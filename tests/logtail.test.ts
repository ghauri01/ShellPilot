import { spawnSync } from 'node:child_process'
import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import {
  LOG_ISSUE_HELP,
  LOG_MARK,
  buildTailCommand,
  diagnoseLogTail,
  filterLogLines,
  logLineMatches,
  parseLogMark,
  validateLogSource,
  validateSince,
  buildLogFileListCommand,
  buildUnitListCommand,
  type LogSource
} from '../src/shared/logtail'
import { SUDO_PROBE } from '../src/shared/docker'

// The remote command is built here and never taken from the user. A tail is a
// read; the moment a caller can pass arbitrary text this becomes "run anything
// on N hosts" with none of the confirmation broadcast has. So the validator is
// the security boundary, and it refuses rather than escapes — escaping is a
// promise about a shell we do not control.

describe('what may be tailed', () => {
  it('accepts an ordinary unit name', () => {
    expect(validateLogSource({ kind: 'unit', target: 'nginx.service' }).ok).toBe(true)
    expect(validateLogSource({ kind: 'unit', target: 'user@1001.service' }).ok).toBe(true)
  })

  it('accepts an absolute log path', () => {
    expect(validateLogSource({ kind: 'file', target: '/var/log/syslog' }).ok).toBe(true)
  })

  it('refuses a unit name carrying a shell break', () => {
    for (const bad of ['a; rm -rf /', 'a && reboot', 'a|tee /etc/x', '$(id)', '`id`', "a'b", 'a"b', 'a b']) {
      expect(validateLogSource({ kind: 'unit', target: bad }).ok, bad).toBe(false)
    }
  })

  it('refuses a path carrying a shell break', () => {
    for (const bad of ['/var/log/x; id', '/var/log/$(id)', '/var/log/a b', '/var/log/`id`', '/var/log/x|y']) {
      expect(validateLogSource({ kind: 'file', target: bad }).ok, bad).toBe(false)
    }
  })

  it('refuses a relative path', () => {
    // It would resolve against whatever directory the exec channel starts in,
    // which is not something the user can reason about.
    expect(validateLogSource({ kind: 'file', target: 'var/log/syslog' }).ok).toBe(false)
  })

  it('refuses traversal', () => {
    expect(validateLogSource({ kind: 'file', target: '/var/log/../../etc/shadow' }).ok).toBe(false)
  })

  it('refuses an empty target with a usable message', () => {
    const r = validateLogSource({ kind: 'unit', target: '   ' })
    expect(r.ok).toBe(false)
    if (!r.ok) expect(r.error).toMatch(/unit name or a log file path/)
  })
})

describe('the command that gets run', () => {
  it('follows a unit with history, so the pane is not empty', () => {
    // The failure being investigated has usually already happened; a tail that
    // only shows new lines answers nothing.
    const cmd = buildTailCommand({ kind: 'unit', target: 'nginx.service' }, 50)
    expect(cmd).toMatch(/journalctl/)
    expect(cmd).toMatch(/-n 50/)
    expect(cmd).toMatch(/-f/)
    expect(cmd).toMatch(/-u nginx\.service/)
  })

  it('uses tail -F, not -f, so a rotated log keeps working', () => {
    // logrotate is the normal case on a log file, and -f silently follows the
    // old inode forever after it runs. The binary is `$SP_BIN` now rather than
    // the bare word, because a non-login ssh shell's PATH is not the one the
    // operator sees when they log in.
    const cmd = buildTailCommand({ kind: 'file', target: '/var/log/syslog' })
    expect(cmd).toMatch(/"\$SP_BIN" -n \d+ -F \/var\/log\/syslog/)
  })

  it('throws rather than building a command from an unvalidated source', () => {
    // A function that quietly returns a broken command is how a validator gets
    // skipped once and then forgotten.
    expect(() => buildTailCommand({ kind: 'unit', target: 'x; reboot' })).toThrow(/refusing/)
    expect(() => buildTailCommand({ kind: 'file', target: '../etc/shadow' })).toThrow(/refusing/)
  })

  it('merges stderr into the stream, so a denied read is visible', () => {
    // Otherwise "permission denied" vanishes and the pane just stays empty,
    // which reads as "this log has nothing in it".
    expect(buildTailCommand({ kind: 'file', target: '/var/log/secure' })).toMatch(/2>&1/)
  })
})

describe('characters a shell would rewrite', () => {
  it('refuses a unit name containing a backslash', () => {
    // The class used to contain `\\`, which reads like an escape of the
    // trailing `-` but is a literal backslash — the one character in the set
    // the shell does not pass through. `-u a\-b` reaches journalctl as `a-b`,
    // so the host follows a unit the user did not name.
    expect(validateLogSource({ kind: 'unit', target: 'a\\-b.service' }).ok).toBe(false)
    expect(validateLogSource({ kind: 'unit', target: 'dev-disk-by\\x2duuid.device' }).ok).toBe(false)
  })

  it('still accepts the unit names people actually type', () => {
    for (const good of ['nginx.service', 'user@1001.service', 'systemd-journald.service', 'my_app.service']) {
      expect(validateLogSource({ kind: 'unit', target: good }).ok, good).toBe(true)
    }
  })
})

// Fan-out and host-key trust.
//
// `metrics.ts` threads allowPrompt through for the background sweep so an
// unattended sample cannot raise a trust-on-first-use dialog. Broadcast and log
// tailing had no way to say the same thing: both called sshExec/sshExecStream,
// which defaulted allowPrompt to true, so a batch across fifteen hosts with
// unknown keys could raise fifteen stacked modals — each blocking its worker.
//
// The user IS present for these, unlike the sweep, which is why this is a
// different argument rather than the same one: a stack of identical dialogs is
// not a decision anyone can reason about, and click-through on the one dialog
// where click-through is how a machine-in-the-middle succeeds is exactly what
// host verification exists to prevent.
describe('what the fan-out paths ask of an unknown host', () => {
  const read = (p: string): string => readFileSync(join(__dirname, '..', p), 'utf8')

  it('refuses to prompt from broadcast, log tailing and cron', () => {
    const main = read('src/main/index.ts')
    // Each fan-out call passes allowPrompt explicitly false.
    expect(main).toMatch(/sshExec\(resolveChainSecrets\(cfg as SshConnectConfig\), command, timeoutMs, false\)/)
    expect(main).toMatch(/sshExecStream\([\s\S]{0,120}handlers,\s*false\s*\)/)
    expect(main).toMatch(/CRON_COLLECT_COMMAND,\s*\n\s*20_000,\s*\n\s*false\s*\n?\s*\)/)
  })

  it('still prompts for docker, which reads one server the user just picked', () => {
    // The distinction is the point: one host, chosen deliberately, is when a
    // fingerprint question can actually be answered.
    const main = read('src/main/index.ts')
    const dockerBlock = main.slice(main.indexOf('const dockerReader'), main.indexOf('ipcMain.handle(\'docker:list\''))
    expect(dockerBlock).toMatch(/sshExec\(resolveChainSecrets\(cfg as SshConnectConfig\), command, timeoutMs\)/)
    expect(dockerBlock).not.toMatch(/timeoutMs,\s*false/)
  })

  it('brings connection setup inside the caller timeout', () => {
    // The timer used to be armed only after acquire() resolved, so TCP connect,
    // every hop and a trust prompt sat outside the timeout the caller asked
    // for. A "30 second" exec could wait indefinitely.
    const ssh = read('src/main/services/ssh.ts')
    expect(ssh).toMatch(/withDeadline\(\s*\n?\s*acquire\(cfg, undefined, allowPrompt\)/)
  })
})

// ---------------------------------------------------------------------------
// Naming a failure is not handling one.
//
// Everything above tests that the command is safe to build. None of it tests
// what happens when the command runs and the host cannot answer — which on a
// real estate is most of the time, and which used to end as an empty pane or a
// line of shell output styled as a log entry.

describe('a host with no journal at all', () => {
  it('checks journalctl exists before deciding anything else', () => {
    // Alpine, most containers, anything pre-systemd. The tail used to emit
    // `sh: journalctl: not found` into the pane as a log line, which reads as
    // the service having said that.
    const cmd = buildTailCommand({ kind: 'unit', target: 'nginx.service' })
    expect(cmd).toMatch(/command -v "\$SP_BIN"/)
    expect(cmd).toContain(`${LOG_MARK}journal=missing`)
  })

  it('looks where a non-login ssh shell does not', () => {
    // PATH over `ssh host cmd` is roughly /usr/bin:/bin. Reusing docker's
    // resolveBinary rather than restating it: a second answer to "where does
    // this host keep its binaries" is a second thing to keep true.
    const cmd = buildTailCommand({ kind: 'unit', target: 'nginx.service' })
    expect(cmd).toContain('/usr/local/bin/journalctl')
    expect(cmd).toContain('/snap/bin/journalctl')
    expect(buildTailCommand({ kind: 'file', target: '/var/log/syslog' })).toContain('/usr/local/bin/tail')
  })

  it('says so instead of tailing when journalctl is absent', () => {
    expect(diagnoseLogTail({ journal: 'missing' }).issue).toBe('no-journal')
    // And the message points at the way out, which is the file mode.
    expect(LOG_ISSUE_HELP['no-journal']).toMatch(/File/)
    expect(LOG_ISSUE_HELP['no-journal']).toMatch(/systemd/)
  })
})

describe('a file that may not be there', () => {
  it('distinguishes the four things a path can be', () => {
    const cmd = buildTailCommand({ kind: 'file', target: '/var/log/secure' })
    expect(cmd).toMatch(/\[ -d \/var\/log\/secure \]/)
    expect(cmd).toMatch(/\[ -r \/var\/log\/secure \]/)
    expect(cmd).toMatch(/\[ -e \/var\/log\/secure \]/)
  })

  it('reports a file inside an unreadable directory as denied, not missing', () => {
    // /var/log/audit is 0700 root on every distribution shipping auditd, so
    // `[ -e audit.log ]` is false there for reasons that have nothing to do
    // with the file existing. "That path does not exist" would send someone
    // looking for a log that is sitting exactly where they think it is.
    const cmd = buildTailCommand({ kind: 'file', target: '/var/log/audit/audit.log' })
    expect(cmd).toMatch(/\[ -d \/var\/log\/audit \] && \[ ! -x \/var\/log\/audit \]; then SP_F=denied/)
  })

  it('says a missing path is being waited for rather than showing nothing', () => {
    // `tail -F` waiting is right when a log is about to be created and is a
    // dead pane otherwise. The two are indistinguishable without this.
    const d = diagnoseLogTail({ file: 'missing' })
    expect(d.issue).toBe('file-missing')
    expect(d.waiting).toBe(true)
    expect(LOG_ISSUE_HELP['file-missing']).toMatch(/waiting|waits/)
  })

  it('names a denied read', () => {
    expect(diagnoseLogTail({ file: 'denied', sudo: '0' }).issue).toBe('file-denied')
    expect(diagnoseLogTail({ file: 'dir' }).issue).toBe('file-is-dir')
    expect(diagnoseLogTail({ file: 'ok' }).issue).toBe('ok')
  })
})

describe('the empty pane journald produces for a unit you may not read', () => {
  // The dangerous case, and the reason any of this exists. journald answers an
  // unauthorised read with SILENCE, not with an error, so the pane looks
  // exactly like a service that has nothing to say.

  it('asks whether any entry came back, and who this account is', () => {
    const cmd = buildTailCommand({ kind: 'unit', target: 'sshd.service' })
    expect(cmd).toContain(`${LOG_MARK}entries=`)
    expect(cmd).toContain(`${LOG_MARK}priv=`)
    // The groups systemd's own tmpfiles ACLs grant read on the journal.
    expect(cmd).toContain("*' systemd-journal '*")
    expect(cmd).toContain("*' adm '*")
    expect(cmd).toContain("*' wheel '*")
  })

  it('drops journalctl furniture so "-- No entries --" is not counted as one', () => {
    // It is printed on stdout and would otherwise make an unreadable journal
    // look like a readable one with a line in it.
    expect(buildTailCommand({ kind: 'unit', target: 'sshd.service' })).toContain("grep -v '^-- '")
  })

  it('calls an empty unprivileged read unreadable, not quiet', () => {
    const d = diagnoseLogTail({ 'unit-load': 'loaded', entries: '0', priv: '0', sudo: '0' })
    expect(d.issue).toBe('journal-unreadable')
    expect(LOG_ISSUE_HELP['journal-unreadable']).toMatch(/does NOT mean the service is quiet/)
  })

  it('calls an empty privileged read quiet, because there it really is', () => {
    const d = diagnoseLogTail({ 'unit-load': 'loaded', entries: '0', priv: '1' })
    expect(d.issue).toBe('unit-quiet')
  })

  it('will not call a unit quiet when only an unprivileged probe found nothing', () => {
    // The probe runs before the escalation, so a root tail may well show
    // entries it could not see. Claiming the unit is quiet there is a lie.
    const d = diagnoseLogTail({ 'unit-load': 'loaded', entries: '0', priv: '0', sudo: '1' })
    expect(d.issue).toBe('ok')
    expect(d.usedSudo).toBe(true)
  })

  it('blames the unit name before it blames permissions', () => {
    // The name is what the user got wrong; a permissions message would send
    // them to fix a host that is fine.
    const d = diagnoseLogTail({ 'unit-load': 'not-found', entries: '0', priv: '0', sudo: '0' })
    expect(d.issue).toBe('unit-not-loaded')
    expect(diagnoseLogTail({ 'unit-load': 'masked', entries: '0', priv: '0' }).issue).toBe('unit-masked')
  })

  it('does not blame the name when systemctl could not be asked', () => {
    // `unknown` is "we could not ask", which is not evidence about the unit.
    expect(diagnoseLogTail({ 'unit-load': 'unknown', entries: '1' }).issue).toBe('ok')
  })

  it('has something to say for every issue it can report', () => {
    for (const [issue, copy] of Object.entries(LOG_ISSUE_HELP)) {
      if (issue === 'ok') continue
      expect(copy.length, issue).toBeGreaterThan(20)
    }
  })
})

describe('becoming root', () => {
  const all = (re: RegExp, s: string): string[] => s.match(re) ?? []

  it('never uses a sudo that could prompt', () => {
    // `sudo -n` fails immediately instead of asking, which is the whole reason
    // probing with it is safe: it cannot hang an exec on a tty that is not
    // there and cannot consume a cached timestamp the user did not intend.
    for (const cmd of [
      buildTailCommand({ kind: 'unit', target: 'nginx.service' }),
      buildTailCommand({ kind: 'file', target: '/var/log/secure' }),
      buildTailCommand({ kind: 'unit', target: 'nginx.service', sudo: 'always' })
    ]) {
      expect(all(/sudo -n/g, cmd).length).toBeGreaterThan(0)
      // Wherever sudo is invoked — anywhere it is followed by an argument —
      // that argument is -n.
      expect(all(/sudo (?!-n)/g, cmd)).toEqual([])
    }
  })

  it('reuses the docker module probe rather than restating it', () => {
    // One definition of "may this account become root without being asked".
    expect(buildTailCommand({ kind: 'unit', target: 'nginx.service' })).toContain(SUDO_PROBE)
  })

  it('only escalates when root would change the answer', () => {
    // A readable journal, or a readable file, is not a thing root fixes, and
    // retrying it would just do the same read again with more privilege.
    expect(buildTailCommand({ kind: 'unit', target: 'nginx.service' })).toContain(
      'if [ "$SP_SA" = 1 ] && [ "$SP_E" = 0 ] && [ "$SP_P" = 0 ]; then SP_SUDO="sudo -n"'
    )
    expect(buildTailCommand({ kind: 'file', target: '/var/log/secure' })).toContain(
      'if [ "$SP_SA" = 1 ] && [ "$SP_F" = denied ]; then SP_SUDO="sudo -n"'
    )
  })

  it('does not even probe for sudo when the caller said never', () => {
    const cmd = buildTailCommand({ kind: 'unit', target: 'nginx.service', sudo: 'never' })
    // Not even the probe: `sudo -n` is harmless, but running it when the answer
    // could not be used is a round trip that buys nothing.
    expect(cmd).not.toContain('sudo -n')
    expect(cmd).not.toContain(SUDO_PROBE)
    // And it still says so, rather than leaving the panel to guess.
    expect(cmd).toContain(`${LOG_MARK}sudo=0`)
    expect(cmd).toContain(`${LOG_MARK}sudo-avail=0`)
  })

  it('reports that root was used, rather than quietly enjoying it', () => {
    expect(buildTailCommand({ kind: 'unit', target: 'nginx.service' })).toContain(`${LOG_MARK}sudo=`)
    expect(diagnoseLogTail({ sudo: '1', file: 'denied' }).usedSudo).toBe(true)
    // A denied file read as root is no longer denied — but that it took root
    // is still the operative fact, which is why it rides separately.
    expect(diagnoseLogTail({ sudo: '1', file: 'denied' }).issue).toBe('ok')
  })

  it('says when root is available but was not used, so a retry can be offered', () => {
    const d = diagnoseLogTail({ file: 'denied', sudo: '0', 'sudo-avail': '1' })
    expect(d.sudoAvailable).toBe(true)
    expect(d.usedSudo).toBe(false)
  })
})

describe('the preflight and the tail on one channel', () => {
  it('runs every check before the tail takes the channel over', () => {
    const cmd = buildTailCommand({ kind: 'unit', target: 'nginx.service' })
    const begin = cmd.indexOf(`${LOG_MARK}begin=1`)
    expect(begin).toBeGreaterThan(0)
    // Every fact is stated before `begin`, and the follow is exec'd after it.
    for (const key of ['journal=present', 'unit-load=', 'entries=', 'priv=', 'sudo=']) {
      expect(cmd.indexOf(`${LOG_MARK}${key}`), key).toBeLessThan(begin)
    }
    expect(cmd.indexOf('-f -u nginx.service')).toBeGreaterThan(begin)
  })

  it('execs the tail, so the process holding the channel is the tail itself', () => {
    // Otherwise the shell sits between the channel and journalctl and closing
    // the channel stops reaching the thing that is actually following.
    expect(buildTailCommand({ kind: 'unit', target: 'nginx.service' })).toMatch(/exec \$SP_SUDO "\$SP_BIN"/)
    expect(buildTailCommand({ kind: 'file', target: '/var/log/syslog' })).toMatch(/exec \$SP_SUDO "\$SP_BIN"/)
  })

  it('reads a marker line and leaves an ordinary line alone', () => {
    expect(parseLogMark(`${LOG_MARK}entries=0`)).toEqual({ key: 'entries', value: '0' })
    expect(parseLogMark('Sep 01 10:00:00 host sshd[1]: Accepted publickey')).toBeNull()
    expect(parseLogMark(`${LOG_MARK}nonsense`)).toBeNull()
    expect(parseLogMark(`${LOG_MARK}=1`)).toBeNull()
  })
})

describe('the two flags people actually type during an incident', () => {
  it('passes -p through to journalctl', () => {
    const cmd = buildTailCommand({ kind: 'unit', target: 'nginx.service', priority: 'err' })
    expect(cmd).toMatch(/-f -u nginx\.service -p err/)
  })

  it('applies them to the emptiness probe too', () => {
    // Otherwise `-p err` on a chatty unit reports entries and then shows an
    // empty pane, which is the exact confusion the probe exists to remove.
    const cmd = buildTailCommand({ kind: 'unit', target: 'nginx.service', priority: 'err', since: '2 hours ago' })
    const probe = cmd.slice(0, cmd.indexOf(`${LOG_MARK}entries=`))
    expect(probe).toContain('-n 1 --output=short-iso -u nginx.service -p err')
    expect(probe).toContain("--since '2 hours ago'")
  })

  it('quotes --since, and only admits values that cannot escape the quotes', () => {
    // The one value here that cannot be a bare word, because journalctl's time
    // grammar has spaces in it. The class carries no quote, backslash, $ or
    // backtick, so single-quoting is safe by construction rather than by care.
    expect(buildTailCommand({ kind: 'unit', target: 'x.service', since: 'yesterday' })).toContain("--since 'yesterday'")
    for (const bad of ["a' ; reboot ; '", 'a$(id)b', 'a`id`b', 'a\\b', 'a"b', 'x'.repeat(60)]) {
      expect(validateSince(bad), bad).toBe(false)
      expect(validateLogSource({ kind: 'unit', target: 'x.service', since: bad }).ok, bad).toBe(false)
      expect(() => buildTailCommand({ kind: 'unit', target: 'x.service', since: bad })).toThrow(/refusing/)
    }
  })

  it('refuses a priority that is not one of journald’s', () => {
    // These arrive over IPC, where the type annotation is a compile-time claim
    // about a structured-clone value and nothing more.
    expect(validateLogSource({ kind: 'unit', target: 'x.service', priority: 'err' }).ok).toBe(true)
    for (const bad of ['err; reboot', 'ERR', '3', '']) {
      expect(validateLogSource({ kind: 'unit', target: 'x.service', priority: bad as never }).ok, bad).toBe(false)
    }
    expect(validateLogSource({ kind: 'unit', target: 'x.service', sudo: 'yes-please' as never }).ok).toBe(false)
  })

  it('leaves journalctl flags off a file tail, which cannot take them', () => {
    const cmd = buildTailCommand({ kind: 'file', target: '/var/log/syslog', priority: 'err', since: 'yesterday' })
    expect(cmd).not.toContain('-p err')
    expect(cmd).not.toContain('--since')
  })

  it('refuses a history count that is not a count', () => {
    // `-n ${lines}` with a string is a command injection, and it is not the
    // caller's job to notice.
    for (const bad of ['5; reboot', 1.5, 0, -1, NaN]) {
      expect(() => buildTailCommand({ kind: 'unit', target: 'x.service' }, bad as never), String(bad)).toThrow(/refusing/)
    }
  })
})

describe('grepping inside the tail', () => {
  const lines = [
    { text: 'nginx: 200 GET /' },
    { text: 'nginx: 500 GET /admin' },
    { text: 'heartbeat ok' },
    { text: 'NGINX: 502 upstream' }
  ]

  it('matches case-insensitively, because nobody types the case a log used', () => {
    expect(filterLogLines(lines, 'nginx').map((l) => l.text)).toHaveLength(3)
  })

  it('takes a regex between slashes', () => {
    expect(filterLogLines(lines, '/5\\d\\d/').map((l) => l.text)).toEqual(['nginx: 500 GET /admin', 'NGINX: 502 upstream'])
  })

  it('excludes with a leading !, which is how a heartbeat gets out of the way', () => {
    expect(filterLogLines(lines, '!heartbeat')).toHaveLength(3)
    expect(filterLogLines(lines, '!/5\\d\\d/')).toHaveLength(2)
  })

  it('does not throw on a half-typed regex', () => {
    // Which is the normal state of an input someone is still typing into. A
    // filter that throws mid-keystroke takes the pane with it.
    expect(() => filterLogLines(lines, '/5\\d\\d')).not.toThrow()
    expect(() => filterLogLines(lines, '/[/')).not.toThrow()
    expect(logLineMatches('a[b', '/[/')).toBe(true)
  })

  it('shows everything when the box is empty', () => {
    expect(filterLogLines(lines, '   ')).toBe(lines)
    expect(logLineMatches('anything', '!')).toBe(true)
  })
})

describe('the commands we build are valid shell', () => {
  // The File picker shipped broken because its command ended `...$'; | sort -u`
  // — a syntax error — and nothing anywhere executed it to find out. Asking the
  // shell itself is the only check that could not agree with the same mistake.
  // `sh -n` parses without running, so this touches no filesystem and no host.
  const parses = (cmd: string): { ok: boolean; err: string } => {
    const r = spawnSync('sh', ['-n'], { input: cmd, encoding: 'utf8' })
    return { ok: r.status === 0, err: (r.stderr || '').trim() }
  }

  it('the log-file listing command parses', () => {
    const r = parses(buildLogFileListCommand())
    expect(r.err).toBe('')
    expect(r.ok).toBe(true)
  })

  it('the unit listing command parses', () => {
    const r = parses(buildUnitListCommand())
    expect(r.err).toBe('')
    expect(r.ok).toBe(true)
  })

  it('every tail command parses, for all three kinds and both sudo modes', () => {
    const sources: LogSource[] = [
      { kind: 'unit', target: 'sp-logger.service' },
      { kind: 'unit', target: 'getty@tty1.service', priority: 'err', since: '2 hours ago' },
      { kind: 'file', target: '/var/log/syslog' },
      { kind: 'container', target: 'sp-db-sp-postgres-1' }
    ]
    for (const s of sources) {
      for (const sudo of ['auto', 'never', 'always'] as const) {
        const r = parses(buildTailCommand({ ...s, sudo }, 50))
        expect(`${s.kind}/${sudo}: ${r.err}`).toBe(`${s.kind}/${sudo}: `)
      }
    }
  })
})
