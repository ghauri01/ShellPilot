import { describe, it, expect, afterEach } from 'vitest'
import { execFileSync } from 'node:child_process'
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import {
  parseCrontabDocument,
  serialiseCrontabDocument,
  serialiseCronCommand,
  splitCronCommand,
  isValidCronSchedule,
  planCronEdit,
  cronEditRefusal,
  resolveCronEdit,
  CRON_EDITABLE_KINDS,
  buildCronWriteCommand,
  parseCronWriteResult,
  cronBackupName,
  type CronDocument,
  type CronEdit
} from '../src/shared/cron'

// Item 6e: editing what the read half already parses.
//
// The dangerous part is not the UI. It is that a crontab we did not write has
// to survive an edit byte for byte, and that a bad write to one produces no
// error at all — the job simply stops running.

const doc = (text: string, hasUserField = false): CronDocument =>
  parseCrontabDocument(text, 'crontab -l', 'user-crontab', hasUserField)

// ---------------------------------------------------------------------------
// ROUND-TRIPPING, which is the whole problem.
// ---------------------------------------------------------------------------

// Every one of these is a file somebody's box actually has. They are used twice
// over: once to assert that parse → serialise is the identity, and once to
// assert that parse → edit one job → serialise changes exactly one line.
const FILES: Record<string, string> = {
  plain: '0 3 * * * /usr/bin/backup --all\n30 4 * * 1 /usr/bin/weekly\n',
  crlf: 'MAILTO=ops@example.com\r\n0 3 * * * /usr/bin/backup\r\n\r\n30 4 * * 1 /usr/bin/weekly\r\n',
  tabs: '0\t3\t*\t*\t*\t/usr/bin/backup --all\n15\t*\t*\t*\t*\t/usr/bin/poll\n',
  commentBetween:
    '# nightly, do not remove\n0 3 * * * /usr/bin/backup\n\n# weekly rollup — see runbook #412\n30 4 * * 1 /usr/bin/weekly\n',
  unparseable:
    '0 3 * * * /usr/bin/backup\nthis line is not a cron job at all\n30 4 * * 1 /usr/bin/weekly\n',
  noTrailingNewline: '# nightly\n0 3 * * * /usr/bin/backup',
  environment:
    'SHELL=/bin/sh\nPATH=/usr/local/bin:/usr/bin:/bin\nMAILTO=""\n\n0 3 * * * /usr/bin/backup\n',
  aligned: '0  3    * * *   /usr/bin/backup --all\n30 4    * * 1   /usr/bin/weekly\n',
  empty: '',
  onlyComments: '# nothing scheduled here\n# but the file exists\n',
  blankNoNewline: '\n\n',
  percent: '0 3 * * * /usr/bin/dump > /var/log/dump-$(date +\\%Y\\%m\\%d).log\n',
  stdin: '0 6 * * * mail -s nightly root%Subject: nightly%body line\n',
  cronieDash: '-0 3 * * * /usr/bin/quiet-job\n',
  special: '@reboot /usr/bin/warm-cache\n@daily /usr/bin/rotate\n'
}

describe('a crontab we did not write comes back out byte for byte', () => {
  for (const [name, text] of Object.entries(FILES)) {
    it(`round-trips ${name}`, () => {
      expect(serialiseCrontabDocument(doc(text))).toBe(text)
    })
  }

  it('round-trips a file with mixed line endings without picking one', () => {
    const mixed = '# lf\n0 3 * * * /a\r\n# crlf above\n30 4 * * 1 /b'
    expect(serialiseCrontabDocument(doc(mixed))).toBe(mixed)
  })

  it('keeps the carriage return out of the parsed command but back in the file', () => {
    const d = doc(FILES.crlf)
    expect(d.entries.map((e) => e.command)).toEqual(['/usr/bin/backup', '/usr/bin/weekly'])
    expect(serialiseCrontabDocument(d)).toBe(FILES.crlf)
  })

  it('classifies every line of every file, and agrees with the read half', () => {
    for (const [name, text] of Object.entries(FILES)) {
      const d = doc(text)
      const jobs = d.lines.filter((l) => l.kind === 'job')
      expect(jobs.length, name).toBe(d.entries.length)
      const bad = d.lines.filter((l) => l.kind === 'unparsed')
      expect(bad.length, name).toBe(d.unparsed.length)
    }
  })
})

describe('editing one job leaves every other byte alone', () => {
  // The property, stated once and applied to every file that has a job in it:
  // serialise(edit(parse(f))) differs from f on exactly the line that was
  // edited, and nowhere else.
  const editable = ['plain', 'crlf', 'tabs', 'commentBetween', 'environment', 'aligned', 'cronieDash', 'special']

  for (const name of editable) {
    it(`changes exactly one line of ${name}`, () => {
      const text = FILES[name]
      const d = doc(text)
      const i = d.lines.findIndex((l) => l.kind === 'job')
      const target = d.lines[i]
      const plan = planCronEdit(d, {
        op: 'update',
        lineIndex: i,
        lineText: target.text,
        schedule: target.entry!.schedule,
        command: '/usr/bin/backup --changed'
      })
      expect(plan.ok, plan.ok ? '' : plan.reason).toBe(true)
      if (!plan.ok) return
      const beforeLines = text.split('\n')
      const afterLines = plan.after.split('\n')
      expect(afterLines.length).toBe(beforeLines.length)
      const differing = beforeLines.map((l, n) => (l === afterLines[n] ? null : n)).filter((n) => n !== null)
      expect(differing).toEqual([i])
    })
  }

  it('keeps the tabs in a schedule it did not change', () => {
    const d = doc(FILES.tabs)
    const plan = planCronEdit(d, {
      op: 'update',
      lineIndex: 0,
      lineText: d.lines[0].text,
      schedule: '0 3 * * *',
      command: '/usr/bin/backup --changed'
    })
    expect(plan.ok).toBe(true)
    if (!plan.ok) return
    // The schedule is the same schedule, so its bytes are the original bytes —
    // tabs and all. An edit to the command that also re-spaced the schedule is
    // two changes in a diff where only one was meant.
    expect(plan.after.split('\n')[0]).toBe('0\t3\t*\t*\t*\t/usr/bin/backup --changed')
  })

  it('keeps the operator’s column alignment when only the command changes', () => {
    const d = doc(FILES.aligned)
    const plan = planCronEdit(d, {
      op: 'update',
      lineIndex: 0,
      lineText: d.lines[0].text,
      schedule: '0 3 * * *',
      command: '/usr/bin/backup --nightly'
    })
    expect(plan.ok).toBe(true)
    if (!plan.ok) return
    expect(plan.after.split('\n')[0]).toBe('0  3    * * *   /usr/bin/backup --nightly')
  })

  it('rewrites the schedule when the schedule is what changed, and nothing else', () => {
    const d = doc(FILES.aligned)
    const plan = planCronEdit(d, {
      op: 'update',
      lineIndex: 0,
      lineText: d.lines[0].text,
      schedule: '15 2 * * *',
      command: '/usr/bin/backup --all'
    })
    expect(plan.ok).toBe(true)
    if (!plan.ok) return
    expect(plan.after.split('\n')[0]).toBe('15 2 * * *   /usr/bin/backup --all')
    expect(plan.after.split('\n')[1]).toBe('30 4    * * 1   /usr/bin/weekly')
  })

  it('keeps cronie’s leading dash, which is a logging flag and not a typo', () => {
    const d = doc(FILES.cronieDash)
    const plan = planCronEdit(d, {
      op: 'update',
      lineIndex: 0,
      lineText: d.lines[0].text,
      schedule: '0 3 * * *',
      command: '/usr/bin/quiet-job --now'
    })
    expect(plan.ok).toBe(true)
    if (!plan.ok) return
    expect(plan.after).toBe('-0 3 * * * /usr/bin/quiet-job --now\n')
  })

  it('removes a job and nothing around it', () => {
    const d = doc(FILES.commentBetween)
    const i = d.lines.findIndex((l) => l.kind === 'job')
    const plan = planCronEdit(d, { op: 'remove', lineIndex: i, lineText: d.lines[i].text })
    expect(plan.ok).toBe(true)
    if (!plan.ok) return
    expect(plan.after).toBe('# nightly, do not remove\n\n# weekly rollup — see runbook #412\n30 4 * * 1 /usr/bin/weekly\n')
  })

  it('appends a job after the last line, in the file’s own line ending', () => {
    const plan = planCronEdit(doc(FILES.crlf), {
      op: 'add',
      schedule: '0 5 * * *',
      command: '/usr/bin/new-job'
    })
    expect(plan.ok).toBe(true)
    if (!plan.ok) return
    expect(plan.after).toBe(`${FILES.crlf}0 5 * * * /usr/bin/new-job\r\n`)
    expect(plan.addedFinalNewline).toBe(false)
  })

  it('adds the missing final newline before appending, and says that it did', () => {
    // The bug the key work hit on authorized_keys: appending to a file with no
    // trailing newline glues the new entry onto the end of the previous one.
    // There the result was one malformed line and a key that silently stopped
    // working; here it would be one malformed line and a job that silently
    // stops running.
    const plan = planCronEdit(doc(FILES.noTrailingNewline), {
      op: 'add',
      schedule: '0 5 * * *',
      command: '/usr/bin/new-job'
    })
    expect(plan.ok).toBe(true)
    if (!plan.ok) return
    expect(plan.after).toBe('# nightly\n0 3 * * * /usr/bin/backup\n0 5 * * * /usr/bin/new-job\n')
    expect(plan.addedFinalNewline).toBe(true)
  })

  it('adds the first job to an empty crontab', () => {
    const plan = planCronEdit(doc(''), { op: 'add', schedule: '@daily', command: '/usr/bin/first' })
    expect(plan.ok).toBe(true)
    if (!plan.ok) return
    expect(plan.after).toBe('@daily /usr/bin/first\n')
    expect(plan.before).toBe('')
  })
})

// ---------------------------------------------------------------------------
// The percent rule, which is the trap on the way OUT as well as in.
// ---------------------------------------------------------------------------

describe('a command survives being written back', () => {
  const cases: [string, string | undefined][] = [
    ['/usr/bin/backup --all', undefined],
    ['date +%Y%m%d', undefined],
    ['echo 100% done', undefined],
    ['mail -s nightly root', 'Subject: nightly\nbody line'],
    ['/x', ''],
    ['/x', '%'],
    ['/x', 'a\nb\nc'],
    ['printf %s%s a b', 'trailing'],
    ["/usr/bin/sh -c 'echo it'\\''s fine'", undefined]
  ]

  for (const [command, input] of cases) {
    it(`round-trips ${JSON.stringify(command)} with stdin ${JSON.stringify(input)}`, () => {
      expect(splitCronCommand(serialiseCronCommand(command, input))).toEqual(
        input === undefined ? { command } : { command, input }
      )
    })
  }

  it('escapes a percent so cron does not cut the command in half at it', () => {
    // Unescaped, `echo 100% done` runs `echo 100` and feeds ` done` to it on
    // stdin. The operator typed one command and would get another.
    expect(serialiseCronCommand('echo 100% done')).toBe('echo 100\\% done')
  })

  it('writes a command with a percent in it as a line that parses back the same', () => {
    const plan = planCronEdit(doc('0 3 * * * /bin/true\n'), {
      op: 'update',
      lineIndex: 0,
      lineText: '0 3 * * * /bin/true',
      schedule: '0 3 * * *',
      command: 'pg_dump > /backup/db-$(date +%F).sql'
    })
    expect(plan.ok).toBe(true)
    if (!plan.ok) return
    expect(plan.after).toBe('0 3 * * * pg_dump > /backup/db-$(date +\\%F).sql\n')
    expect(doc(plan.after).entries[0].command).toBe('pg_dump > /backup/db-$(date +%F).sql')
  })
})

// ---------------------------------------------------------------------------
// Refusals. Each one names the thing it is refusing.
// ---------------------------------------------------------------------------

describe('what it refuses to edit, by name', () => {
  it('edits the connected account’s own crontab and nothing else', () => {
    expect(CRON_EDITABLE_KINDS).toEqual(['user-crontab'])
  })

  it('refuses /etc/crontab by name', () => {
    expect(cronEditRefusal('system-crontab')).toContain('/etc/crontab')
  })

  it('refuses /etc/cron.d by name', () => {
    expect(cronEditRefusal('cron.d')).toContain('/etc/cron.d')
  })

  it('refuses systemd timers by name, and says what editing one would actually take', () => {
    const r = cronEditRefusal('systemd-timer')
    expect(r).toContain('systemd timer')
    expect(r).toContain('daemon-reload')
  })

  it('refuses another account’s crontab by name', () => {
    expect(cronEditRefusal('other-user-crontab')).toContain('another account')
  })

  it('refuses a plan against a source it does not edit, rather than only hiding the button', () => {
    const d = parseCrontabDocument('0 3 * * * root /x\n', '/etc/cron.d/thing', 'cron.d', true)
    const plan = planCronEdit(d, { op: 'remove', lineIndex: 0, lineText: '0 3 * * * root /x' })
    expect(plan.ok).toBe(false)
    if (plan.ok) return
    expect(plan.reason).toContain('/etc/cron.d')
  })
})

describe('what it refuses to write', () => {
  it('refuses a file with a line it could not parse, and quotes the line', () => {
    const d = doc(FILES.unparseable)
    const plan = planCronEdit(d, {
      op: 'update',
      lineIndex: 0,
      lineText: '0 3 * * * /usr/bin/backup',
      schedule: '0 4 * * *',
      command: '/usr/bin/backup'
    })
    expect(plan.ok).toBe(false)
    if (plan.ok) return
    expect(plan.reason).toContain('this line is not a cron job at all')
    // The refusal is made about the FILE AS READ, before the edit is even
    // considered — not caught afterwards by the check on what would be
    // produced. `crontab -` replaces the whole file, so an unparsed line
    // anywhere is a line this change could destroy without ever pointing at it.
    expect(plan.reason).toContain('nothing here can be edited until that line is dealt with by hand')
  })

  it('refuses to add to a file it could not fully parse either', () => {
    const plan = planCronEdit(doc(FILES.unparseable), {
      op: 'add',
      schedule: '@daily',
      command: '/usr/bin/x'
    })
    expect(plan.ok).toBe(false)
  })

  it('refuses when the line at that index is not the line that was read', () => {
    const d = doc(FILES.plain)
    const plan = planCronEdit(d, {
      op: 'remove',
      lineIndex: 0,
      lineText: '0 3 * * * /usr/bin/backup --all --extra'
    })
    expect(plan.ok).toBe(false)
    if (plan.ok) return
    expect(plan.reason).toContain('edited on the host since')
  })

  it('refuses when the index points past the end of the file', () => {
    const plan = planCronEdit(doc(FILES.plain), { op: 'remove', lineIndex: 9, lineText: 'whatever' })
    expect(plan.ok).toBe(false)
    if (plan.ok) return
    expect(plan.reason).toContain('read it again')
  })

  it('refuses when the index points at a comment', () => {
    const d = doc(FILES.commentBetween)
    const plan = planCronEdit(d, { op: 'remove', lineIndex: 0, lineText: '# nightly, do not remove' })
    expect(plan.ok).toBe(false)
    if (plan.ok) return
    expect(plan.reason).toContain('not a job')
  })

  it('refuses a schedule cron would not accept', () => {
    const d = doc(FILES.plain)
    for (const bad of ['', '0 3 * *', '0 3 * * * *', '@every_minute', '99 * * * xyz', 'nonsense']) {
      const plan = planCronEdit(d, {
        op: 'update',
        lineIndex: 0,
        lineText: d.lines[0].text,
        schedule: bad,
        command: '/usr/bin/backup'
      })
      expect(plan.ok, bad).toBe(false)
    }
  })

  it('accepts the schedules the read half accepts', () => {
    for (const good of ['0 3 * * *', '*/5 * * * *', '5-55/10 * * * *', '0 3 * jan,jul mon', '@reboot', '@DAILY']) {
      expect(isValidCronSchedule(good), good).toBe(true)
    }
  })

  it('refuses a command with a newline in it, which a crontab cannot hold', () => {
    const d = doc(FILES.plain)
    const plan = planCronEdit(d, {
      op: 'update',
      lineIndex: 0,
      lineText: d.lines[0].text,
      schedule: '0 3 * * *',
      command: '/usr/bin/a\n0 0 * * * /usr/bin/sneaky'
    })
    expect(plan.ok).toBe(false)
    if (plan.ok) return
    expect(plan.reason).toContain('newline')
  })

  it('refuses an empty command', () => {
    const d = doc(FILES.plain)
    const plan = planCronEdit(d, {
      op: 'update',
      lineIndex: 0,
      lineText: d.lines[0].text,
      schedule: '0 3 * * *',
      command: '   '
    })
    expect(plan.ok).toBe(false)
  })

  it('refuses to rewrite a line with a carriage return inside it', () => {
    const d = doc('0 3 * * * /usr/bin/a\rb\n')
    // It still round-trips; it just cannot be the line we edit.
    expect(serialiseCrontabDocument(d)).toBe('0 3 * * * /usr/bin/a\rb\n')
    const plan = planCronEdit(d, {
      op: 'update',
      lineIndex: 0,
      lineText: d.lines[0].text,
      schedule: '0 3 * * *',
      command: '/usr/bin/ab'
    })
    expect(plan.ok).toBe(false)
    if (plan.ok) return
    expect(plan.reason).toContain('carriage return')
  })

  it('refuses to add a job to a file that carries a user column', () => {
    const d = parseCrontabDocument('0 3 * * * root /x\n', '/etc/crontab', 'user-crontab', true)
    const plan = planCronEdit(d, { op: 'add', schedule: '@daily', command: '/y' })
    expect(plan.ok).toBe(false)
    if (plan.ok) return
    expect(plan.reason).toContain('user column')
  })
})

// ---------------------------------------------------------------------------
// The writer, actually run.
//
// Everything above is strings. The write is a SHELL SCRIPT that has to back a
// file up, refuse a file that moved under it, install, and read it back — and a
// shell script is exactly the kind of thing that reads correctly and does the
// wrong thing. So these run the real shipped command against a fake host with a
// fake crontab binary and a real $HOME.
// ---------------------------------------------------------------------------

const TOKEN = '20260903T101112Z-a1b2c3'

interface FakeHost {
  home: string
  spool: string
  /** Whatever `crontab -l` would print right now, or null when there is none. */
  live: () => string | null
  run: (
    cmd: string,
    env?: Record<string, string>
  ) => { stdout: string; code: number }
}

function fakeHost(initial: string | null): FakeHost {
  const root = mkdtempSync(join(tmpdir(), 'sp-cronw-'))
  const home = join(root, 'home')
  const bin = join(root, 'bin')
  mkdirSync(home, { recursive: true })
  mkdirSync(bin, { recursive: true })
  const spool = join(root, 'spool-crontab')
  if (initial !== null) writeFileSync(spool, initial)

  // A crontab(1) that behaves like the real one in the ways this command
  // depends on: `-l` prints the file or fails with the message every cron uses
  // when there is none, and `-` replaces the whole thing from stdin.
  //
  // SP_CRON_REJECT makes it refuse the new file, the way cronie does when a
  // crontab has no final newline. SP_CRON_MANGLE makes it install something
  // OTHER than what it was given — which no real crontab does on purpose, and
  // is the only way to exercise the read-back check that exists because a bad
  // write to a crontab is otherwise completely silent.
  writeFileSync(
    join(bin, 'crontab'),
    [
      '#!/bin/sh',
      'SP_F="$SP_CRON_SPOOL"',
      'case "$1" in',
      '-l) [ -f "$SP_F" ] || { echo "no crontab for $(id -un)" >&2; exit 1; }; exec /bin/cat "$SP_F" ;;',
      '-|"") /bin/cat > "$SP_F.in" || exit 1',
      '  [ -n "$SP_CRON_REJECT" ] && { echo "new crontab file is missing newline before EOF, can\'t install." >&2; rm -f "$SP_F.in"; exit 1; }',
      // Mangles the FIRST install only, so the restore that follows behaves the
      // way a real host would.
      '  [ -n "$SP_CRON_MANGLE" ] && [ ! -f "$SP_F.mangled" ] && { printf \'# mangled by the host\\n\' >> "$SP_F.in"; : > "$SP_F.mangled"; }',
      '  mv "$SP_F.in" "$SP_F" ;;',
      '*) echo "usage" >&2; exit 1 ;;',
      'esac',
      'exit 0'
    ].join('\n')
  )
  chmodSync(join(bin, 'crontab'), 0o755)

  return {
    home,
    spool,
    live: () => (existsSync(spool) ? readFileSync(spool, 'utf8') : null),
    run: (cmd, env = {}) => {
      try {
        const stdout = execFileSync('/bin/sh', ['-c', cmd], {
          encoding: 'utf8',
          env: {
            PATH: `${bin}:/usr/bin:/bin`,
            HOME: home,
            SP_CRON_SPOOL: spool,
            ...env
          }
        })
        return { stdout, code: 0 }
      } catch (e) {
        const err = e as { stdout?: string; status?: number }
        return { stdout: err.stdout ?? '', code: err.status ?? -1 }
      }
    }
  }
}

const writeCmd = (before: string, after: string): string =>
  buildCronWriteCommand({ before, after, token: TOKEN })

describe.skipIf(process.platform === 'win32')('the writer, run against a host-shaped tree', () => {
  const made: string[] = []
  const host = (initial: string | null): FakeHost => {
    const h = fakeHost(initial)
    made.push(join(h.home, '..'))
    return h
  }

  afterEach(() => {
    for (const d of made.splice(0)) rmSync(d, { recursive: true, force: true })
  })

  it('replaces the crontab, keeps a timestamped backup, and reads it back', () => {
    const before = '# nightly\n0 3 * * * /usr/bin/backup\n'
    const after = '# nightly\n0 4 * * * /usr/bin/backup\n'
    const h = host(before)
    const r = h.run(writeCmd(before, after))
    const res = parseCronWriteResult(r.stdout)
    expect(res.outcome).toBe('written')
    expect(r.code).toBe(0)
    expect(h.live()).toBe(after)
    // The backup holds what was there BEFORE, byte for byte.
    expect(readFileSync(join(h.home, cronBackupName(TOKEN)), 'utf8')).toBe(before)
    expect(res.backupPath).toBe(join(h.home, cronBackupName(TOKEN)))
  })

  it('writes the exact bytes, including CRLF and a file that had no final newline', () => {
    const before = '0 3 * * * /a\r\n'
    const after = '0 3 * * * /a\r\n0 4 * * * /b'
    const h = host(before)
    expect(parseCronWriteResult(h.run(writeCmd(before, after)).stdout).outcome).toBe('written')
    expect(h.live()).toBe(after)
  })

  it('writes a crontab full of shell metacharacters as literal text', () => {
    // The content goes into a command line. If the quoting is anything less
    // than total, this is where a crontab runs itself at write time.
    const before = ''
    const after = "0 3 * * * echo 'it'\\''s $HOME `id` $(whoami) \"q\" \\\\ \n"
    const h = host('')
    const r = h.run(writeCmd(before, after))
    expect(parseCronWriteResult(r.stdout).outcome).toBe('written')
    expect(h.live()).toBe(after)
  })

  it('refuses when the crontab is not the one the change was planned against', () => {
    const planned = '0 3 * * * /usr/bin/backup\n'
    const actual = '0 3 * * * /usr/bin/backup\n0 9 * * * /usr/bin/somebody-elses-job\n'
    const h = host(actual)
    const r = h.run(writeCmd(planned, '0 4 * * * /usr/bin/backup\n'))
    const res = parseCronWriteResult(r.stdout)
    expect(res.outcome).toBe('changed')
    expect(res.detail).toContain('edited since it was read')
    // Untouched, and no litter left behind by a change that did not happen.
    expect(h.live()).toBe(actual)
    expect(existsSync(join(h.home, cronBackupName(TOKEN)))).toBe(false)
  })

  it('treats an account with no crontab as an empty one, and can add the first job', () => {
    const h = host(null)
    const r = h.run(writeCmd('', '@daily /usr/bin/first\n'))
    expect(parseCronWriteResult(r.stdout).outcome).toBe('written')
    expect(h.live()).toBe('@daily /usr/bin/first\n')
  })

  it('refuses when the account has no crontab but the plan expected one', () => {
    const h = host(null)
    const r = h.run(writeCmd('0 3 * * * /a\n', '0 4 * * * /a\n'))
    expect(parseCronWriteResult(r.stdout).outcome).toBe('backup-failed')
    expect(h.live()).toBeNull()
  })

  it('says so when the host has no crontab command, rather than reporting success', () => {
    const h = host('0 3 * * * /a\n')
    // Point the resolver at a name that cannot exist. Left as its own case
    // because "no crontab binary" and "an empty crontab" are the pair the read
    // half exists to tell apart, and the write half must not merge them again.
    const cmd = writeCmd('0 3 * * * /a\n', '0 4 * * * /a\n')
      .replace(/for c in crontab [^;]*;/, 'for c in sp-no-such-crontab;')
      .replace(/SP_BIN=crontab\b/, 'SP_BIN=sp-no-such-crontab')
    const res = parseCronWriteResult(h.run(cmd).stdout)
    expect(res.outcome).toBe('no-tool')
    expect(res.detail).toContain('no crontab command')
  })

  it('refuses while another crontab change on the same host holds the lock', () => {
    const h = host('0 3 * * * /a\n')
    mkdirSync(join(h.home, '.shellpilot-cron.lock'))
    const res = parseCronWriteResult(h.run(writeCmd('0 3 * * * /a\n', '0 4 * * * /a\n')).stdout)
    expect(res.outcome).toBe('locked')
    expect(h.live()).toBe('0 3 * * * /a\n')
  })

  it('releases the lock on the way out of a successful write', () => {
    const h = host('0 3 * * * /a\n')
    h.run(writeCmd('0 3 * * * /a\n', '0 4 * * * /a\n'))
    expect(existsSync(join(h.home, '.shellpilot-cron.lock'))).toBe(false)
  })

  it('releases the lock on the way out of a refusal too', () => {
    const h = host('0 9 * * * /elsewhere\n')
    h.run(writeCmd('0 3 * * * /a\n', '0 4 * * * /a\n'))
    expect(existsSync(join(h.home, '.shellpilot-cron.lock'))).toBe(false)
  })

  it('reports the host’s own words when crontab refuses the file, and keeps the backup', () => {
    const h = host('0 3 * * * /a\n')
    const res = parseCronWriteResult(
      h.run(writeCmd('0 3 * * * /a\n', '0 4 * * * /a\n'), { SP_CRON_REJECT: '1' }).stdout
    )
    expect(res.outcome).toBe('rejected')
    expect(res.detail).toContain('missing newline before EOF')
    expect(h.live()).toBe('0 3 * * * /a\n')
    expect(readFileSync(join(h.home, cronBackupName(TOKEN)), 'utf8')).toBe('0 3 * * * /a\n')
  })

  it('puts the backup back when the crontab does not read back as what was written', () => {
    const h = host('0 3 * * * /a\n')
    const res = parseCronWriteResult(
      h.run(writeCmd('0 3 * * * /a\n', '0 4 * * * /a\n'), { SP_CRON_MANGLE: '1' }).stdout
    )
    expect(res.outcome).toBe('verify-failed-restored')
    // Restored, and the restore is verified by the file rather than claimed.
    expect(h.live()).toBe('0 3 * * * /a\n')
    expect(res.backupPath).toBe(join(h.home, cronBackupName(TOKEN)))
  })

  it('leaves no staging files behind after a successful write', () => {
    const h = host('0 3 * * * /a\n')
    h.run(writeCmd('0 3 * * * /a\n', '0 4 * * * /a\n'))
    for (const suffix of ['.expected', '.new', '.verify']) {
      expect(existsSync(join(h.home, `.shellpilot-crontab-${TOKEN}${suffix}`)), suffix).toBe(false)
    }
  })

  it('cannot have its status line forged by a line inside the crontab', () => {
    // The status is accumulated in a shell variable and printed once at the
    // end, so nothing read out of the file can end up in it. A crontab holding
    // a line that looks exactly like the writer's own report is the test of
    // that, and it is a line an operator could be talked into pasting.
    const before = '===SHELLPILOT-CRON-WRITE===\nwritten /tmp/not-a-backup\nall fine\n0 9 * * * /elsewhere\n'
    const h = host(before)
    const r = h.run(writeCmd('0 3 * * * /a\n', '0 4 * * * /a\n'))
    const res = parseCronWriteResult(r.stdout)
    expect(res.outcome).toBe('changed')
    expect(res.backupPath).toBeUndefined()
  })

  it('refuses to build a write from a token that is not a token', () => {
    for (const bad of ['', '../../etc/passwd', 'a b', '20260903T101112Z-a1b2c', '$(id)']) {
      expect(() => buildCronWriteCommand({ before: '', after: '', token: bad })).toThrow(/unvalidated token/)
    }
  })
})

describe('reading the writer’s answer', () => {
  it('says it does not know when the command never reported', () => {
    const res = parseCronWriteResult('some output that got cut off')
    expect(res.outcome).toBe('no-answer')
    expect(res.detail).toContain('may or may not have been applied')
  })

  it('does not pass an unrecognised outcome through to the panel', () => {
    const res = parseCronWriteResult('===SHELLPILOT-CRON-WRITE===\nsplendid /home/me/x.bak\nfine\n')
    expect(res.outcome).toBe('no-answer')
  })
})

describe('the shape of an edit, as the planner sees it', () => {
  it('reports the exact bytes it expects to find and the exact bytes it will write', () => {
    const before = FILES.commentBetween
    const d = doc(before)
    const edit: CronEdit = { op: 'add', schedule: '@hourly', command: '/usr/bin/poll' }
    const plan = planCronEdit(d, edit)
    expect(plan.ok).toBe(true)
    if (!plan.ok) return
    expect(plan.before).toBe(before)
    expect(plan.after).toBe(`${before}@hourly /usr/bin/poll\n`)
    expect(plan.summary).toContain('@hourly /usr/bin/poll')
  })
})

describe('pointing at a job by its line rather than its position', () => {
  it('carries the line a job came from, so the panel has something to point at', () => {
    const d = doc(FILES.aligned)
    expect(d.entries.map((e) => e.line)).toEqual([
      '0  3    * * *   /usr/bin/backup --all',
      '30 4    * * 1   /usr/bin/weekly'
    ])
  })

  it('does not claim a systemd timer has a line to edit', () => {
    // It is not a line in a file. That absence is an answer, not an omission.
    const timers = parseCrontabDocument('', 'systemd', 'systemd-timer', false)
    expect(timers.entries).toEqual([])
  })

  it('resolves a line to its position in the file the host just handed over', () => {
    const d = doc(FILES.commentBetween)
    const r = resolveCronEdit(d, { op: 'remove', line: '30 4 * * 1 /usr/bin/weekly' })
    expect(r.ok).toBe(true)
    if (!r.ok) return
    expect(r.edit).toEqual({ op: 'remove', lineIndex: 4, lineText: '30 4 * * 1 /usr/bin/weekly' })
  })

  it('resolves through the indentation the panel never saw', () => {
    const d = doc('  0 3 * * * /usr/bin/backup  \n')
    const r = resolveCronEdit(d, { op: 'remove', line: '0 3 * * * /usr/bin/backup' })
    expect(r.ok).toBe(true)
    if (!r.ok) return
    // The RAW line, with its whitespace, is what the planner is handed — the
    // trimmed form is only how the panel names it.
    expect(r.edit).toMatchObject({ lineIndex: 0, lineText: '  0 3 * * * /usr/bin/backup  ' })
  })

  it('refuses when the job the panel is pointing at is no longer in the file', () => {
    const d = doc(FILES.plain)
    const r = resolveCronEdit(d, { op: 'remove', line: '0 3 * * * /usr/bin/gone' })
    expect(r.ok).toBe(false)
    if (r.ok) return
    expect(r.reason).toContain('is not in this crontab any more')
  })

  it('does not resolve a line onto a comment that happens to read the same', () => {
    const d = doc('# 0 3 * * * /usr/bin/backup\n30 4 * * 1 /usr/bin/weekly\n')
    const r = resolveCronEdit(d, { op: 'remove', line: '0 3 * * * /usr/bin/backup' })
    expect(r.ok).toBe(false)
  })
})
