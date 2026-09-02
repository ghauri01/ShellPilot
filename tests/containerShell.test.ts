import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { buildDockerShellCommand, validateContainerRef } from '../src/shared/docker'

// A shell inside a container.
//
// `docker exec -it` is arbitrary code execution on the host, and docker-group
// membership is root-equivalent on most installs. The button is small and the
// consequence is not, so what is pinned here is the shape of the path rather
// than only the command text.

const read = (p: string): string => readFileSync(join(__dirname, '..', p), 'utf8')

describe('the command', () => {
  it('falls back to sh when the image has no bash', () => {
    // A minimal image has no bash and the failure is otherwise a pane that
    // dies instantly with no explanation.
    const cmd = buildDockerShellCommand('web')
    // Runs the RESOLVED binary now, not a bare `docker` — an ssh non-login
    // shell often cannot see it on PATH.
    expect(cmd).toMatch(/"\$SP_BIN" exec -it web \/bin\/bash/)
    expect(cmd).toMatch(/\|\|.*"\$SP_BIN" exec -it web \/bin\/sh/)
  })

  it('refuses a reference it cannot prove safe rather than escaping it', () => {
    for (const bad of ['a; rm -rf /', '$(id)', 'a b', '`id`', '--privileged']) {
      expect(() => buildDockerShellCommand(bad), bad).toThrow(/refusing/)
    }
  })

  it('accepts what docker actually allows', () => {
    expect(validateContainerRef('my_app-1.web')).toBe(true)
    expect(() => buildDockerShellCommand('my_app-1.web')).not.toThrow()
  })
})

describe('how it reaches a terminal', () => {
  it('is a transport, not a second terminal', () => {
    // The roadmap's point: `docker exec -it` is a PTY over a channel, which is
    // what an SSH login shell already is. A second terminal implementation
    // would be a second place for every bug in the first one.
    const transport = read('src/renderer/src/lib/transport.ts')
    expect(transport).toMatch(/export function containerTransport/)
    // Built from sshTransport rather than reimplementing write/resize/close.
    expect(transport).toMatch(/const base = sshTransport\(server, setServerStatus\)/)
  })

  it('gives a container shell its own session key', () => {
    // Otherwise a shell in a container and a shell on the host are the same
    // session, and one steals the other.
    expect(read('src/renderer/src/lib/transport.ts')).toMatch(
      /key: `container:\$\{server\.id\}:\$\{containerRef\}`/
    )
  })

  it('does not let a container tab satisfy "open this server"', () => {
    // A container shell is also an SSH tab for that server. Without the
    // containerRef check, opening the server would focus a shell inside a
    // container instead of one on the host.
    expect(read('src/renderer/src/store/app.ts')).toMatch(
      /t\.kind === 'ssh' && t\.serverId === serverId && !t\.containerRef/
    )
  })

  it('only builds initialCommand from the validating builder', () => {
    // The field accepts a string; the whole safety of it is that one caller
    // exists and it goes through a builder that throws.
    const transport = read('src/renderer/src/lib/transport.ts')
    expect(transport).toMatch(/initialCommand: buildDockerShellCommand\(containerRef, \{ sudo \}\)/)
    // No other initialCommand producer anywhere in the renderer.
    const uses = transport.match(/initialCommand:/g) ?? []
    expect(uses).toHaveLength(1)
  })
})

describe('what must NOT be able to reach it', () => {
  it('is not exposed to the MCP bridge', () => {
    // An agent gets execute_command gated per server against an access group.
    // A container shell is a different risk with a different consent story,
    // and it would be an accident rather than a decision.
    const mcp = read('src/main/services/mcpServer.ts')
    expect(mcp).not.toMatch(/containerTransport|buildDockerShellCommand|openContainerShell/)
    expect(mcp).not.toMatch(/docker exec/)
  })

  it('has no IPC channel of its own', () => {
    // It reuses ssh:connect. A `docker:shell` channel would be a second way in
    // that the ssh session machinery does not guard.
    const main = read('src/main/index.ts')
    expect(main).not.toMatch(/'docker:shell'/)
  })

  it('keeps initialCommand out of anything an agent can set', () => {
    // The MCP server never constructs an SshConnectConfig for a terminal.
    const mcp = read('src/main/services/mcpServer.ts')
    expect(mcp).not.toMatch(/initialCommand/)
  })
})

// Reported by an operator running 0.9.1 against a real host.
//
// Three failures, one cause: the container shell was wired as if it were the
// host's own shell, and the docker permission decision was made per-feature
// instead of once.
describe('what a failing container shell must not take down', () => {
  it('does not report the HOST as offline', () => {
    // `containerTransport` spreads sshTransport, which reports
    // connecting/online/offline into setServerStatus. A container shell that
    // failed — refused socket, no /bin/sh, wrong image — therefore marked the
    // SERVER offline, the Fleet Monitor stopped sampling a perfectly reachable
    // host, and the only way back was reconnecting a plain SSH session by hand.
    const t = read('src/renderer/src/lib/transport.ts')
    const block = t.slice(t.indexOf('export function containerTransport'))
    expect(block).toMatch(/onLifecycle: undefined/)
  })

  it('carries the listingticket sudo decision into the shell', () => {
    // Listing containers as root and then opening a shell as an account that
    // cannot reach the socket is one feature behaving as two.
    const t = read('src/renderer/src/lib/transport.ts')
    expect(t).toMatch(/buildDockerShellCommand\(containerRef, \{ sudo \}\)/)
    const panel = read('src/renderer/src/components/docker/DockerPanel.tsx')
    expect(panel).toMatch(/openContainerShell\(server\.id, c\.name, usedSudoNow\)/)
  })

  it('remembers the escalation on the tab, not just at click time', () => {
    // The panel that knew may be gone when the session reconnects, and a shell
    // that silently drops the escalation fails in a way that looks like the
    // container died.
    expect(read('src/renderer/src/types.ts')).toMatch(/containerSudo\?: boolean/)
  })
})

describe('the shell command itself', () => {
  it('resolves the binary like every other docker path', async () => {
    const { buildDockerShellCommand } = await import('../src/shared/docker')
    expect(buildDockerShellCommand('web')).toContain('/usr/local/bin/docker')
  })

  it('can run as root, and does not by default', async () => {
    const { buildDockerShellCommand } = await import('../src/shared/docker')
    expect(buildDockerShellCommand('web')).not.toMatch(/sudo/)
    expect(buildDockerShellCommand('web', { sudo: true })).toMatch(/sudo -n "\$SP_BIN" exec -it web/)
  })

  it('still falls back to sh under sudo', async () => {
    const { buildDockerShellCommand } = await import('../src/shared/docker')
    const cmd = buildDockerShellCommand('web', { sudo: true })
    expect(cmd).toMatch(/\/bin\/bash/)
    expect(cmd).toMatch(/\|\|.*\/bin\/sh/)
  })
})

// A container shell that cannot open used to leave a dead pane saying
// "shell exited with 1". True, and useless: the exit code belongs to
// `docker exec`, not to anything the user typed, and the Docker panel
// classifies its failures carefully while the terminal tab did not.
describe('why a container shell ended', () => {
  const src = read('src/renderer/src/lib/transport.ts')
  const fn = src.slice(src.indexOf('function containerCloseReason'), src.indexOf('export function containerTransport'))

  it('names the distroless case rather than printing 127', () => {
    // A scratch or distroless image genuinely has no shell to give, and no
    // amount of retrying changes that.
    expect(fn).toMatch(/case 127:/)
    expect(fn).toMatch(/neither \/bin\/bash nor \/bin\/sh/)
  })

  it('reads exit 1 as the socket refusing this account', () => {
    // The common real cause, and a permission story rather than a container
    // story — the panel escalated for the listing and the exec did not inherit
    // it.
    expect(fn).toMatch(/case 1:/)
    expect(fn).toMatch(/docker socket refusing this account/)
  })

  it('separates the daemon refusing from the image lacking a shell', () => {
    // 125 and 127 send you to completely different places.
    expect(fn).toMatch(/case 125:/)
    expect(fn).toMatch(/daemon refused it/)
  })

  it('falls back to the ordinary SSH reason for anything unclassified', () => {
    // Inventing a container explanation for a signal or an unknown code would
    // be worse than the generic sentence.
    expect(fn).toMatch(/default:\s*\n\s*return sshCloseReason\(info\)/)
    expect(fn).toMatch(/if \(info\.signal\) return sshCloseReason\(info\)/)
  })

  it('is actually used by the container transport', () => {
    // The helper existing is not the feature; the transport overriding onClose
    // is.
    const block = src.slice(src.indexOf('export function containerTransport'))
    expect(block).toMatch(/containerCloseReason\(info, containerRef\)/)
  })
})
