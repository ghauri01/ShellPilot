import { describe, it, expect, beforeEach } from 'vitest'
import {
  refreshMcpDataCache,
  listCachedServers,
  listCachedWorkspaces,
  getCachedServer,
  serverToSshConfig
} from '../src/main/services/mcpDataCache'

const sampleData = {
  workspaces: [
    { id: 'ws-prod', name: 'Production' },
    { id: 'ws-dev', name: 'Development' }
  ],
  servers: [
    {
      id: 's1',
      workspaceId: 'ws-prod',
      name: 'Nginx Server Prod',
      host: '10.0.0.1',
      port: 22,
      username: 'root',
      auth: 'key',
      os: 'Linux',
      route: [{ host: '10.0.0.254', port: 22, username: 'bastion', auth: 'key', serverId: 'bastion-1' }]
    },
    { id: 's2', workspaceId: 'ws-dev', name: 'Dev Box', host: '10.0.1.1', port: 22, username: 'dev', auth: 'password' }
  ]
}

describe('mcpDataCache', () => {
  beforeEach(() => refreshMcpDataCache(sampleData))

  it('parses workspaces and servers from the persisted blob', () => {
    expect(listCachedWorkspaces()).toHaveLength(2)
    expect(listCachedServers()).toHaveLength(2)
  })

  it('workspace isolation: filtering by workspace hides other workspaces servers', () => {
    const prodServers = listCachedServers('ws-prod')
    expect(prodServers).toHaveLength(1)
    expect(prodServers[0].id).toBe('s1')
    expect(prodServers.some((s) => s.workspaceId === 'ws-dev')).toBe(false)
  })

  it('preserves the jump-server chain for credential resolution', () => {
    const s1 = getCachedServer('s1')!
    expect(s1.route).toHaveLength(1)
    expect(s1.route[0].serverId).toBe('bastion-1')
  })

  it('serverToSshConfig carries the server id and hop chain through', () => {
    const cfg = serverToSshConfig(getCachedServer('s1')!)
    expect(cfg.serverId).toBe('s1')
    expect(cfg.hops).toHaveLength(1)
  })

  it('tolerates a missing or malformed blob without throwing', () => {
    expect(() => refreshMcpDataCache(null)).not.toThrow()
    expect(listCachedServers()).toHaveLength(0)
    expect(() => refreshMcpDataCache({ servers: 'not-an-array' })).not.toThrow()
  })
})
