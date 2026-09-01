import { describe, it, expect } from 'vitest'
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
