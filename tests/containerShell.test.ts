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
    expect(cmd).toMatch(/docker exec -it web \/bin\/bash/)
    expect(cmd).toMatch(/\|\|.*docker exec -it web \/bin\/sh/)
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
    expect(transport).toMatch(/initialCommand: buildDockerShellCommand\(containerRef\)/)
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
