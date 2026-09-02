import { describe, it, expect } from 'vitest'
import { buildTailCommand, validateLogSource, diagnoseLogTail, LOG_ISSUE_HELP } from '../src/shared/logtail'

// Following a container's logs, rather than reading 200 static lines.
//
// The point of the preflight is that `docker logs` on a refused socket, on a
// removed container and on a stopped one all produce the same thing — a pane
// with nothing in it — and they need three different sentences. A container
// tail that skipped the preflight would be the only source kind that goes back
// to guessing.

const src = (target: string, over = {}): Parameters<typeof buildTailCommand>[0] =>
  ({ kind: 'container' as const, target, ...over })

describe('what may be tailed', () => {
  it('accepts a container name or id', () => {
    expect(validateLogSource(src('new_system-redis-1')).ok).toBe(true)
    expect(validateLogSource(src('abc123def456')).ok).toBe(true)
  })

  it('refuses anything that could break out of the command', () => {
    for (const bad of ['a; rm -rf /', '$(id)', 'a b', '`id`', '--privileged', '']) {
      expect(validateLogSource(src(bad)).ok, bad).toBe(false)
    }
  })

  it('refuses journald filters rather than ignoring them', () => {
    // `docker logs` has no -p. Silently dropping a filter the user set is how
    // a pane looks unfiltered for no visible reason.
    const r = validateLogSource(src('web', { priority: 'err' }))
    expect(r.ok).toBe(false)
    if (!r.ok) expect(r.error).toMatch(/do not apply to a container/)
  })
})

describe('the command', () => {
  it('follows rather than snapshotting', () => {
    expect(buildTailCommand(src('web'), 50)).toMatch(/logs --tail 50 -f web/)
  })

  it('resolves the binary like every other docker path', () => {
    expect(buildTailCommand(src('web'))).toContain('/usr/local/bin/docker')
  })

  it('preflights existence and state before following', () => {
    // Without this the three failures are one empty pane.
    const cmd = buildTailCommand(src('web'))
    expect(cmd).toMatch(/inspect -f '\{\{\.State\.Running\}\}' web/)
    expect(cmd).toMatch(/SP_C=running/)
    expect(cmd).toMatch(/SP_C=stopped/)
    expect(cmd).toMatch(/SP_C=denied/)
  })

  it('says docker is missing rather than failing silently', () => {
    expect(buildTailCommand(src('web'))).toMatch(/docker=missing/)
  })

  it('re-asks as root after escalating', () => {
    // Otherwise the banner reports a denial the stream below it has already
    // escalated past, and the two contradict each other.
    const cmd = buildTailCommand(src('web'))
    const afterSudo = cmd.slice(cmd.indexOf('SP_SUDO'))
    expect(afterSudo).toMatch(/\$SP_SUDO "\$SP_BIN" inspect/)
  })

  it('throws rather than building from an invalid reference', () => {
    expect(() => buildTailCommand(src('a; reboot'))).toThrow(/refusing/)
  })
})

describe('what the panel says', () => {
  const d = (facts: Record<string, string>) => diagnoseLogTail(facts)

  it('names a refused socket rather than an empty container', () => {
    expect(d({ docker: 'present', container: 'denied' }).issue).toBe('docker-denied')
  })

  it('does not call it denied once root got in', () => {
    expect(d({ docker: 'present', container: 'running', sudo: '1' }).issue).toBe('ok')
  })

  it('tells a removed container from a stopped one', () => {
    expect(d({ docker: 'present', container: 'absent' }).issue).toBe('container-missing')
    expect(d({ docker: 'present', container: 'stopped' }).issue).toBe('container-stopped')
  })

  it('treats a stopped container as waiting, not as a failure', () => {
    // Its logs are the reason you are looking. Styling that red teaches people
    // to ignore red.
    expect(d({ docker: 'present', container: 'stopped' }).waiting).toBe(true)
  })

  it('says docker is absent before it says anything about the container', () => {
    expect(d({ docker: 'missing' }).issue).toBe('no-docker')
  })

  it('has copy for every container issue', () => {
    for (const k of ['no-docker', 'docker-denied', 'container-missing', 'container-stopped'] as const) {
      expect(LOG_ISSUE_HELP[k], k).toBeTruthy()
      expect(LOG_ISSUE_HELP[k].length, k).toBeGreaterThan(30)
    }
  })

  it('does not describe a stopped container as an error', () => {
    expect(LOG_ISSUE_HELP['container-stopped']).toMatch(/history, not a live stream/)
  })
})
