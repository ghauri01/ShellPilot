import { describe, it, expect } from 'vitest'
import { buildTailCommand, validateLogSource, diagnoseLogTail, LOG_ISSUE_HELP } from '../src/shared/logtail'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'

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

// Reported from a real host: the Container tab was given `redis` and both hosts
// answered "Error response from daemon: No such container: redis" — printed
// into the pane as though it were a log line, with no diagnosis at all.
//
// Three separate faults, two of them in this file's preflight.
describe('a container that is not there', () => {
  it('does not stay "denied" after root proves it absent', () => {
    // THE bug. The unprivileged inspect was refused, so SP_C=denied. The
    // re-ask as root had no default branch, so a "No such container" answer
    // left SP_C at denied — and diagnose() saw denied + usedSudo and called the
    // whole thing `ok`. That is why no banner appeared.
    const cmd = buildTailCommand(src('web'))
    const reask = cmd.slice(cmd.indexOf('if [ -n "$SP_SUDO" ]'))
    expect(reask).toMatch(/\*\) SP_C=absent ;;/)
  })

  it('refuses to follow a container that does not exist', () => {
    // `tail -F` waits for a file because a file appearing is a thing that
    // happens. A container id does not materialise, so `docker logs` on it
    // only produces a daemon error dressed as content.
    const cmd = buildTailCommand(src('web'))
    expect(cmd).toMatch(/if \[ "\$SP_C" = absent \]; then .* exit 0; fi/)
    // And it still marks begin, so the tailer settles a diagnosis rather than
    // treating it as a preflight that never finished.
    const guard = cmd.slice(cmd.indexOf('if [ "$SP_C" = absent ]'))
    expect(guard).toMatch(/begin=1/)
  })

  it('diagnoses absent even when root was used', () => {
    expect(diagnoseLogTail({ docker: 'present', container: 'absent', sudo: '1' }).issue).toBe(
      'container-missing'
    )
  })

  it('offers the container names that actually exist', () => {
    // The third fault, and the one that caused the other two to be seen: the
    // Docker panel groups by compose project and shows the SERVICE name
    // (`redis`) while the container is `new_system-redis-1`. Reading one panel
    // and typing into the other is a correct answer to a question nobody meant
    // to ask.
    const panel = readFileSync(
      join(__dirname, '..', 'src/renderer/src/components/monitor/LogTailPanel.tsx'),
      'utf8'
    )
    // A real dropdown now, not a datalist: the browser's own affordance needs
    // the field focused and is a few pixels wide, which is how a name got typed
    // by hand while the list sat unopened.
    expect(panel).toMatch(/lt-picker/)
    expect(panel).toMatch(/docker as[\s\S]{0,200}list\?:/)
    // The same picker serves all three modes rather than one being special.
    expect(panel).toMatch(/kind === 'unit' \? units\.map/)
    expect(panel).toMatch(/: kind === 'container' \? containers : files/)
  })
})

// File mode needed the same treatment: a path typed from memory is how you
// tail something that is not there and then wait for a file that will never
// appear — `tail -F` is patient by design, so the mistake is silent.
describe('offering the log files that exist', () => {
  it('looks where logs actually live', async () => {
    const { buildLogFileListCommand } = await import('../src/shared/logtail')
    const cmd = buildLogFileListCommand()
    for (const d of ['/var/log', '/var/log/nginx', '/var/log/audit']) {
      expect(cmd, d).toContain(d)
    }
  })

  it('excludes rotated and compressed files', () => {
    // Tailing syslog.3.gz is not a thing anyone means to do, and they would
    // otherwise be most of the list on a busy host.
    return import('../src/shared/logtail').then(({ buildLogFileListCommand }) => {
      expect(buildLogFileListCommand()).toMatch(/grep -vE/)
      expect(buildLogFileListCommand()).toMatch(/gz\|xz\|bz2\|zst/)
    })
  })

  it('is bounded, because a picker is not an archive browser', () => {
    return import('../src/shared/logtail').then(({ buildLogFileListCommand }) => {
      expect(buildLogFileListCommand()).toMatch(/-maxdepth 1/)
      expect(buildLogFileListCommand()).toMatch(/head -n 200/)
    })
  })

  it('keeps only absolute paths, decided by shape', async () => {
    const { parseLogFileList } = await import('../src/shared/logtail')
    const out = [
      '/var/log/syslog',
      '/var/log/nginx/access.log',
      "find: '/var/log/private': Permission denied",
      'not/absolute',
      '/var/log/with a space.log'
    ].join('\n')
    // The find complaint is a sentence with spaces and cannot be mistaken for
    // a path — the same shape-not-content rule the other parsers follow.
    expect(parseLogFileList(out)).toEqual(['/var/log/nginx/access.log', '/var/log/syslog'])
  })

  it('deduplicates, since the directories overlap', async () => {
    const { parseLogFileList } = await import('../src/shared/logtail')
    expect(parseLogFileList('/var/log/syslog\n/var/log/syslog\n')).toEqual(['/var/log/syslog'])
  })
})
