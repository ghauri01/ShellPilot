import { describe, it, expect, afterEach } from 'vitest'
import { execFileSync } from 'node:child_process'
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import {
  planCronEditOnHost,
  writeCronEdit,
  mintCronToken,
  type CronEditDeps
} from '../src/main/services/cronEdit'
import { CRON_TOKEN_RE, cronBackupName, type CronSourceReport } from '../src/shared/cron'
import { approvalFor, planBroadcast } from '../src/shared/broadcast'

// The main-process half: read, plan, confirm, write, verify.
//
// Two things are being tested here that the string-level tests cannot reach.
// One is the refusals that depend on the HOST's answer rather than on the file.
// The other is that the read command and the write command, run for real, agree
// with each other about what the file is — a read that appends a newline the
// file did not have produces a plan the write then refuses, and it would refuse
// on every host, forever, for a reason nobody could see from either half alone.

const TARGET = { serverId: 'srv-1', serverName: 'db-01', cfg: { host: 'x' } }

const recorded: Parameters<CronEditDeps['recordApproval']>[0][] = []
const deps = (exec: CronEditDeps['exec']): CronEditDeps => ({
  exec,
  recordApproval: (e) => {
    recorded.push(e)
  }
})

// ---------------------------------------------------------------------------
// A host that runs the real commands.
// ---------------------------------------------------------------------------

interface FakeHost {
  home: string
  live: () => string | null
  deps: (over?: Record<string, string>) => CronEditDeps
}

function fakeHost(initial: string | null): FakeHost {
  const root = mkdtempSync(join(tmpdir(), 'sp-cronsvc-'))
  const home = join(root, 'home')
  const bin = join(root, 'bin')
  mkdirSync(home, { recursive: true })
  mkdirSync(bin, { recursive: true })
  const spool = join(root, 'spool-crontab')
  if (initial !== null) writeFileSync(spool, initial)

  writeFileSync(
    join(bin, 'crontab'),
    [
      '#!/bin/sh',
      'SP_F="$SP_CRON_SPOOL"',
      'case "$1" in',
      '-l) [ -f "$SP_F" ] || { echo "no crontab for $(id -un)" >&2; exit 1; }; exec /bin/cat "$SP_F" ;;',
      '-|"") /bin/cat > "$SP_F.in" && mv "$SP_F.in" "$SP_F" ;;',
      '*) echo "usage" >&2; exit 1 ;;',
      'esac',
      'exit 0'
    ].join('\n')
  )
  chmodSync(join(bin, 'crontab'), 0o755)
  made.push(root)

  return {
    home,
    live: () => (existsSync(spool) ? readFileSync(spool, 'utf8') : null),
    deps: (over = {}) =>
      deps(async (_cfg, command) => {
        try {
          const stdout = execFileSync('/bin/sh', ['-c', command], {
            encoding: 'utf8',
            env: { PATH: `${bin}:/usr/bin:/bin`, HOME: home, SP_CRON_SPOOL: spool, ...over }
          })
          return { ok: true, code: 0, stdout }
        } catch (e) {
          const err = e as { stdout?: string; status?: number }
          return { ok: true, code: err.status ?? 1, stdout: err.stdout ?? '' }
        }
      })
  }
}

// A cron write ends up classified `destructive`, because the command it builds
// contains `rm -f` on its own staging files. The reason the classifier gives is
// about the wrong thing; the demand it makes — type RUN — is right for a
// different reason, so it is left alone rather than gamed. Every approval in
// this file is minted the way the panel mints one: from the re-derived plan,
// with whatever phrase that plan actually asks for.
const approve = (
  command: string,
  targets: { serverId: string; serverName: string }[] = [{ serverId: TARGET.serverId, serverName: TARGET.serverName }]
): ReturnType<typeof approvalFor> => {
  const plan = planBroadcast(command, targets)
  return approvalFor({
    surface: 'broadcast',
    commands: [command],
    targets,
    plan,
    phrase: plan.confirmation.kind === 'type-to-confirm' ? plan.confirmation.phrase : null,
    confirmedAt: Date.now()
  })
}

const made: string[] = []
afterEach(() => {
  recorded.splice(0)
  for (const d of made.splice(0)) rmSync(d, { recursive: true, force: true })
})

// ---------------------------------------------------------------------------

describe('naming this change’s backup', () => {
  it('mints a token the writer will accept', () => {
    expect(mintCronToken(new Date(Date.UTC(2026, 8, 3, 10, 11, 12)))).toMatch(/^20260903T101112Z-[0-9a-f]{6}$/)
    expect(mintCronToken()).toMatch(CRON_TOKEN_RE)
  })

  it('does not give two changes in the same second the same backup file', () => {
    // The second one would overwrite the only copy of what the first replaced.
    const at = new Date(Date.UTC(2026, 8, 3, 10, 11, 12))
    const tokens = new Set(Array.from({ length: 50 }, () => mintCronToken(at)))
    expect(tokens.size).toBe(50)
  })
})

describe('planning against a host', () => {
  it('refuses a crontab the read half only partly read, and says which host', async () => {
    const sources: CronSourceReport[] = [
      { id: 'user-crontab', label: 'crontab -l', status: 'partial', detail: 'read 1 of 2 files' }
    ]
    const r = await planCronEditOnHost(
      deps(async () => {
        throw new Error('must not reach the host')
      }),
      TARGET,
      { op: 'add', schedule: '@daily', command: '/x' },
      { sources }
    )
    expect(r.ok).toBe(false)
    expect(r.reason).toContain('db-01')
    expect(r.reason).toContain('partial')
    expect(r.reason).toContain('the part it could not read is the part it would delete')
  })

  it('refuses a crontab the transport had to cut short', async () => {
    // A clipped crontab parses into a document missing its tail, and writing
    // that back deletes every job past the cut — silently.
    const r = await planCronEditOnHost(
      deps(async () => ({ ok: true, code: 0, stdout: 'anything', truncated: true })),
      TARGET,
      { op: 'add', schedule: '@daily', command: '/x' }
    )
    expect(r.ok).toBe(false)
    expect(r.reason).toContain('the part it could not read is the part it would delete')
  })

  it('reports a host it could not reach rather than planning against nothing', async () => {
    const r = await planCronEditOnHost(
      deps(async () => ({ ok: false, code: null, error: 'connection refused' })),
      TARGET,
      { op: 'add', schedule: '@daily', command: '/x' }
    )
    expect(r.ok).toBe(false)
    expect(r.reason).toContain('connection refused')
  })

  it('says when the host has no crontab command at all', async () => {
    const r = await planCronEditOnHost(
      deps(async () => ({
        ok: true,
        code: 0,
        stdout: '===SHELLPILOT-CRON-READ===\nno-tool\n===SHELLPILOT-CRON-BODY===\n'
      })),
      TARGET,
      { op: 'add', schedule: '@daily', command: '/x' }
    )
    expect(r.ok).toBe(false)
    expect(r.reason).toContain('no crontab command')
  })

  it('does not treat a refused read as an empty crontab', async () => {
    const r = await planCronEditOnHost(
      deps(async () => ({
        ok: true,
        code: 0,
        stdout: '===SHELLPILOT-CRON-READ===\nunknown must be run as root\n===SHELLPILOT-CRON-BODY===\n'
      })),
      TARGET,
      { op: 'add', schedule: '@daily', command: '/x' }
    )
    expect(r.ok).toBe(false)
    expect(r.reason).toContain('must be run as root')
  })
})

describe.skipIf(process.platform === 'win32')('plan and write, against a host running the real commands', () => {
  it('reads the crontab byte for byte, including a missing final newline', async () => {
    // The read command exists precisely because the collector's section
    // printing appends a newline. If this regressed, every plan against a file
    // without a trailing newline would be refused by the host's own comparison,
    // on every host, and neither half would look wrong on its own.
    const h = fakeHost('# nightly\n0 3 * * * /usr/bin/backup')
    const r = await planCronEditOnHost(h.deps(), TARGET, {
      op: 'update',
      lineIndex: 1,
      lineText: '0 3 * * * /usr/bin/backup',
      schedule: '0 4 * * *',
      command: '/usr/bin/backup'
    })
    expect(r.ok, r.reason).toBe(true)
    expect(r.before).toBe('# nightly\n0 3 * * * /usr/bin/backup')
    expect(r.after).toBe('# nightly\n0 4 * * * /usr/bin/backup')
  })

  it('plans, is approved, writes, and the host ends up with exactly those bytes', async () => {
    const h = fakeHost('# nightly\n0 3 * * * /usr/bin/backup\n')
    const d = h.deps()
    const plan = await planCronEditOnHost(d, TARGET, {
      op: 'add',
      schedule: '@hourly',
      command: '/usr/bin/poll'
    })
    expect(plan.ok, plan.reason).toBe(true)

    const approval = approve(plan.command!)
    const res = await writeCronEdit(d, TARGET, {
      before: plan.before!,
      after: plan.after!,
      token: plan.token!,
      runId: 'cron-edit-1',
      approval
    })
    expect(res.ok, res.detail).toBe(true)
    expect(res.outcome).toBe('written')
    expect(h.live()).toBe('# nightly\n0 3 * * * /usr/bin/backup\n@hourly /usr/bin/poll\n')
    expect(readFileSync(join(h.home, cronBackupName(plan.token!)), 'utf8')).toBe(
      '# nightly\n0 3 * * * /usr/bin/backup\n'
    )
    expect(recorded.map((e) => e.event)).toEqual(['granted'])
    expect(recorded[0].hosts).toEqual(['db-01'])
  })

  it('adds the first job to an account that has never had a crontab', async () => {
    const h = fakeHost(null)
    const d = h.deps()
    const plan = await planCronEditOnHost(d, TARGET, { op: 'add', schedule: '@daily', command: '/usr/bin/first' })
    expect(plan.ok, plan.reason).toBe(true)
    expect(plan.before).toBe('')
    const res = await writeCronEdit(d, TARGET, {
      before: plan.before!,
      after: plan.after!,
      token: plan.token!,
      runId: 'r',
      approval: approve(plan.command!)
    })
    expect(res.outcome).toBe('written')
    expect(h.live()).toBe('@daily /usr/bin/first\n')
  })
})

describe('the approval, which a cron edit goes through rather than around', () => {
  const noHost = deps(async () => {
    throw new Error('must not reach the host')
  })

  it('refuses to write with no approval record at all, and records the refusal', async () => {
    const res = await writeCronEdit(noHost, TARGET, {
      before: '0 3 * * * /a\n',
      after: '0 4 * * * /a\n',
      token: '20260903T101112Z-abcdef',
      runId: 'r1'
    })
    expect(res.ok).toBe(false)
    expect(res.detail).toContain('never written down')
    expect(recorded.map((e) => e.event)).toEqual(['refused'])
    expect(recorded[0].title).toContain('db-01')
  })

  it('refuses when the bytes changed after the confirmation', async () => {
    // The operator confirmed one file. `verifyApproval` compares the command
    // text, and the command is built from the bytes — so a different `after`
    // is a different command and needs a fresh confirmation.
    const token = '20260903T101112Z-abcdef'
    const target = { serverId: TARGET.serverId, serverName: TARGET.serverName }
    const { buildCronWriteCommand } = await import('../src/shared/cron')
    const approvedCommand = buildCronWriteCommand({ before: '0 3 * * * /a\n', after: '0 4 * * * /a\n', token })
    const approval = approve(approvedCommand, [target])
    const res = await writeCronEdit(noHost, TARGET, {
      before: '0 3 * * * /a\n',
      after: '0 4 * * * /a\n0 5 * * * /sneaky\n',
      token,
      runId: 'r2',
      approval
    })
    expect(res.ok).toBe(false)
    expect(res.detail).toContain('needs a fresh confirmation')
    expect(recorded.map((e) => e.event)).toEqual(['refused'])
  })

  it('refuses a host that was not in the list that was confirmed', async () => {
    const token = '20260903T101112Z-abcdef'
    const { buildCronWriteCommand } = await import('../src/shared/cron')
    const command = buildCronWriteCommand({ before: '', after: '@daily /x\n', token })
    const approval = approve(command, [{ serverId: 'someone-else', serverName: 'web-09' }])
    const res = await writeCronEdit(noHost, TARGET, {
      before: '',
      after: '@daily /x\n',
      token,
      runId: 'r3',
      approval
    })
    expect(res.ok).toBe(false)
    expect(res.detail).toContain('db-01')
  })

  it('never reaches a host with a token that is not a token', async () => {
    const res = await writeCronEdit(noHost, TARGET, {
      before: '',
      after: '@daily /x\n',
      token: '; rm -rf ~',
      runId: 'r4'
    })
    expect(res.ok).toBe(false)
    expect(res.detail).toContain('unvalidated token')
    // Not even recorded as a refused approval: it never got as far as having
    // a command to be approved.
    expect(recorded).toEqual([])
  })
})

describe('a connection that dies mid-write', () => {
  it('says it does not know, rather than reporting a failure it cannot see', async () => {
    const token = '20260903T101112Z-abcdef'
    const { buildCronWriteCommand } = await import('../src/shared/cron')
    const command = buildCronWriteCommand({ before: '', after: '@daily /x\n', token })
    const target = { serverId: TARGET.serverId, serverName: TARGET.serverName }
    const res = await writeCronEdit(
      deps(async () => ({ ok: false, code: null, error: 'connection closed by remote host' })),
      TARGET,
      {
        before: '',
        after: '@daily /x\n',
        token,
        runId: 'r5',
        approval: approve(command, [target])
      }
    )
    expect(res.ok).toBe(false)
    expect(res.outcome).toBe('no-answer')
    // The host's OWN words about why the connection went, not a generic
    // sentence: "the command never reported" and "we never got the answer" are
    // two different situations and the operator is the one who has to tell
    // them apart.
    expect(res.detail).toContain('connection closed by remote host')
    expect(res.detail).toContain('may or may not have been applied')
    // The approval was granted and the record says so. It ran; we just do not
    // know how it ended.
    expect(recorded.map((e) => e.event)).toEqual(['granted'])
  })
})
