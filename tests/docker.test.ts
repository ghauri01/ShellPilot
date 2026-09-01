import { describe, it, expect } from 'vitest'
import {
  parseDockerOutput,
  classifyDockerFailure,
  validateContainerRef,
  buildDockerLogsCommand,
  buildDockerShellCommand,
  DOCKER_LIST_COMMAND,
  DOCKER_SEP
} from '../src/shared/docker'

// `docker` not installed, the daemon not running, and the user not being in the
// docker group are three different problems with three different fixes. A panel
// that says "no containers" for all three is lying about two of them, and that
// is the failure this module is shaped around.

const row = (...f: string[]): string => f.join(DOCKER_SEP)
const output = (version: string, rows: string[]): string =>
  `${version}\n===SHELLPILOT-PS===\n${rows.join('\n')}\n`

describe('reading containers', () => {
  it('parses a container list', () => {
    const out = output('24.0.7', [
      row('abc123def4567890', 'web', 'nginx:latest', 'running', 'Up 3 hours', '0.0.0.0:80->80/tcp', '2026-09-01 10:00:00 +0000 UTC'),
      row('def456abc7890123', 'db', 'postgres:16', 'exited', 'Exited (0) 2 days ago', '', '2026-08-30 09:00:00 +0000 UTC')
    ])
    const r = parseDockerOutput(out, 0)
    expect(r.ok).toBe(true)
    if (!r.ok) return
    expect(r.version).toBe('24.0.7')
    expect(r.containers).toHaveLength(2)
    expect(r.containers[0]).toMatchObject({ name: 'web', image: 'nginx:latest', state: 'running' })
    // The short id is what people read and type.
    expect(r.containers[0].shortId).toBe('abc123def456')
  })

  it('includes stopped containers', () => {
    // A stopped container is usually the one being investigated.
    const r = parseDockerOutput(
      output('24.0.7', [row('a1', 'gone', 'img', 'exited', 'Exited (137) 1 hour ago', '', 'now')]),
      0
    )
    expect(r.ok && r.containers[0].state).toBe('exited')
  })

  it('reports an empty list as success, not as a failure', () => {
    // "docker works and nothing is running" is a real answer.
    const r = parseDockerOutput(output('24.0.7', []), 0)
    expect(r.ok).toBe(true)
    expect(r.ok && r.containers).toEqual([])
  })

  it('survives a ports field containing the separator-adjacent characters', () => {
    const r = parseDockerOutput(
      output('24.0.7', [row('a1', 'web', 'nginx', 'running', 'Up 1 min', '0.0.0.0:80->80/tcp, :::80->80/tcp', 'now')]),
      0
    )
    expect(r.ok && r.containers[0].ports).toBe('0.0.0.0:80->80/tcp, :::80->80/tcp')
  })
})

describe('telling the three failures apart', () => {
  it('knows docker is not installed', () => {
    expect(classifyDockerFailure('bash: docker: command not found', 127)).toBe('not-installed')
  })

  it('knows the daemon is not answering', () => {
    expect(
      classifyDockerFailure('Cannot connect to the Docker daemon at unix:///var/run/docker.sock. Is the docker daemon running?', 1)
    ).toBe('daemon-unreachable')
  })

  it('knows it is a permission problem, not a stopped daemon', () => {
    // Both mention the socket. Checking for the daemon first would send
    // someone to restart a daemon that is already running.
    const msg =
      'Got permission denied while trying to connect to the Docker daemon socket at unix:///var/run/docker.sock'
    expect(classifyDockerFailure(msg, 1)).toBe('permission-denied')
  })

  it('surfaces the failure instead of an empty container list', () => {
    const r = parseDockerOutput('bash: docker: command not found\n', 127)
    expect(r.ok).toBe(false)
    if (r.ok) return
    expect(r.reason).toBe('not-installed')
    expect(r.detail).toMatch(/command not found/)
  })

  it('catches a daemon that died between the version probe and the list', () => {
    const out = output('24.0.7', ['Cannot connect to the Docker daemon at unix:///var/run/docker.sock.'])
    const r = parseDockerOutput(out, 1)
    expect(r.ok).toBe(false)
    expect(!r.ok && r.reason).toBe('daemon-unreachable')
  })

  it('falls back to unknown rather than guessing', () => {
    expect(classifyDockerFailure('something else entirely', 1)).toBe('unknown')
  })
})

describe('commands built from a container reference', () => {
  it('accepts real ids and names', () => {
    expect(validateContainerRef('abc123def456')).toBe(true)
    expect(validateContainerRef('my_app-1.web')).toBe(true)
  })

  it('refuses anything that could break out of the command', () => {
    for (const bad of ['a; rm -rf /', 'a b', '$(id)', '`id`', 'a|b', '../x', '-rf', '']) {
      expect(validateContainerRef(bad), bad).toBe(false)
    }
  })

  it('throws rather than building from an invalid reference', () => {
    expect(() => buildDockerLogsCommand('a; reboot')).toThrow(/refusing/)
    expect(() => buildDockerShellCommand('a; reboot')).toThrow(/refusing/)
  })

  it('bounds log output and can follow', () => {
    expect(buildDockerLogsCommand('web', 50)).toMatch(/--tail 50 web/)
    expect(buildDockerLogsCommand('web', 50, true)).toMatch(/-f/)
  })

  it('falls back to sh when the image has no bash', () => {
    // A minimal image has no bash, and the failure is otherwise a pane that
    // dies instantly with no explanation.
    const cmd = buildDockerShellCommand('web')
    expect(cmd).toMatch(/\/bin\/bash/)
    expect(cmd).toMatch(/\|\|.*\/bin\/sh/)
  })

  it('merges stderr so an error is visible rather than an empty pane', () => {
    expect(buildDockerLogsCommand('web')).toMatch(/2>&1/)
  })
})

describe('the list command', () => {
  it('includes stopped containers and full ids', () => {
    expect(DOCKER_LIST_COMMAND).toMatch(/--all/)
    expect(DOCKER_LIST_COMMAND).toMatch(/--no-trunc/)
  })

  it('is read-only', () => {
    expect(DOCKER_LIST_COMMAND).not.toMatch(/\b(rm|stop|kill|prune|exec|run)\b/)
  })
})
