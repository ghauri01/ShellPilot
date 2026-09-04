import { describe, it, expect, beforeEach } from 'vitest'
import { resolveServerByName, formatAmbiguity } from '../src/main/services/serverResolver'
import { setServerAliases, resetPolicyCacheForTests } from '../src/main/services/policyStore'
import type { CachedServer, CachedWorkspace } from '../src/main/services/mcpDataCache'

const workspaces: CachedWorkspace[] = [
  { id: 'ws-prod', name: 'Production' },
  { id: 'ws-staging', name: 'Staging' }
]

function server(partial: Partial<CachedServer> & { id: string; workspaceId: string; name: string }): CachedServer {
  return {
    host: '10.0.0.1',
    port: 22,
    username: 'root',
    auth: 'key',
    os: 'Linux',
    route: [],
    // Required on `CachedServer`, and `string | null` rather than optional: a
    // server that rides no VPN says so, it does not stay silent. Left out, the
    // spread of `Partial<CachedServer>` made the field `undefined`, which is
    // the one value the type does not admit.
    vpnProfileId: null,
    ...partial
  }
}

describe('server name resolution', () => {
  beforeEach(() => resetPolicyCacheForTests())

  it('resolves an exact name match', () => {
    const servers = [server({ id: 's1', workspaceId: 'ws-prod', name: 'Nginx Server Prod' })]
    const result = resolveServerByName('Nginx Server Prod', servers, workspaces)
    expect(result.type).toBe('found')
    if (result.type === 'found') expect(result.match.server.id).toBe('s1')
  })

  it('is case-insensitive', () => {
    const servers = [server({ id: 's1', workspaceId: 'ws-prod', name: 'Nginx Server Prod' })]
    const result = resolveServerByName('nginx server prod', servers, workspaces)
    expect(result.type).toBe('found')
  })

  it('resolves via a configured alias', () => {
    setServerAliases('s1', ['nginx', 'prod nginx'])
    const servers = [server({ id: 's1', workspaceId: 'ws-prod', name: 'Nginx Server Prod' })]
    const result = resolveServerByName('nginx', servers, workspaces)
    expect(result.type).toBe('found')
    if (result.type === 'found') expect(result.match.server.id).toBe('s1')
  })

  it('never guesses: two equally-good matches are reported as ambiguous', () => {
    const servers = [
      server({ id: 's1', workspaceId: 'ws-prod', name: 'Nginx Server Prod' }),
      server({ id: 's2', workspaceId: 'ws-prod', name: 'Nginx Server Prod 2' })
    ]
    const result = resolveServerByName('nginx', servers, workspaces)
    expect(result.type).toBe('ambiguous')
    if (result.type === 'ambiguous') {
      expect(result.matches).toHaveLength(2)
      const message = formatAmbiguity(result.matches)
      expect(message).toContain('Nginx Server Prod')
      expect(message).toContain('Nginx Server Prod 2')
    }
  })

  it('returns not-found for something that matches nothing', () => {
    const servers = [server({ id: 's1', workspaceId: 'ws-prod', name: 'Nginx Server Prod' })]
    expect(resolveServerByName('mongodb', servers, workspaces).type).toBe('not-found')
  })

  it('workspace isolation: a server outside the caller-supplied list is invisible', () => {
    // The MCP layer only ever passes listCachedServers(session.workspaceId) in,
    // so a server from another workspace is structurally never a candidate —
    // simulated here by only including the Production server in the list.
    const onlyProd = [server({ id: 's1', workspaceId: 'ws-prod', name: 'Nginx Server Prod' })]
    const result = resolveServerByName('Nginx Server Prod', onlyProd, workspaces)
    expect(result.type).toBe('found')
    const empty = resolveServerByName('Staging DB', onlyProd, workspaces)
    expect(empty.type).toBe('not-found')
  })
})
