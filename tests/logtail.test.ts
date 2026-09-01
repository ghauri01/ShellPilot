import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { validateLogSource, buildTailCommand } from '../src/shared/logtail'

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
    // old inode forever after it runs.
    const cmd = buildTailCommand({ kind: 'file', target: '/var/log/syslog' })
    expect(cmd).toMatch(/tail -n \d+ -F \/var\/log\/syslog/)
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
