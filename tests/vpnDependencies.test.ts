import { beforeEach, describe, expect, it, vi } from 'vitest'

// The dependency graph reads the renderer's data blob through the MCP cache.
// Mocking the cache rather than seeding a real blob keeps this test about the
// graph rules — which references count, and which of them block what — instead
// of about JSON parsing, which mcpDataCache.test.ts already covers.
const servers: { id: string; name: string; vpnProfileId: string | null }[] = []
const databases: { id: string; name: string; vpnProfileId: string | null }[] = []
const tunnels: { id: string; name: string; serverId: string | null }[] = []
const vpnIds = new Set<string>()

vi.mock('../src/main/services/mcpDataCache', () => ({
  listCachedServers: () => servers,
  listCachedDatabases: () => databases,
  listCachedTunnels: () => tunnels,
  getCachedVpn: (id: string) => (vpnIds.has(id) ? { id } : null)
}))

const {
  clearAllVpnConsumers,
  hasLiveVpnDependents,
  liveVpnDependents,
  registerVpnConsumer,
  vpnDeleteBlockers,
  vpnDependents,
  vpnForDatabase,
  vpnForServer
} = await import('../src/main/services/vpn/dependencies')

beforeEach(() => {
  servers.length = 0
  databases.length = 0
  tunnels.length = 0
  vpnIds.clear()
  clearAllVpnConsumers()
})

describe('stored references', () => {
  it('finds servers and databases that name the profile', () => {
    servers.push({ id: 's1', name: 'bastion', vpnProfileId: 'v1' })
    servers.push({ id: 's2', name: 'other', vpnProfileId: null })
    databases.push({ id: 'd1', name: 'prod', vpnProfileId: 'v1' })
    databases.push({ id: 'd2', name: 'local', vpnProfileId: 'v2' })

    const deps = vpnDependents('v1')
    expect(deps.map((d) => `${d.kind}:${d.id}`).sort()).toEqual(['database:d1', 'server:s1'])
    expect(deps.every((d) => !d.live)).toBe(true)
  })

  it('follows a tunnel to the VPN of the server it rides', () => {
    // A tunnel names a server, not a VPN, so a naive scan misses it entirely
    // and the confirmation dialog under-reports what it is about to close.
    servers.push({ id: 's1', name: 'bastion', vpnProfileId: 'v1' })
    tunnels.push({ id: 't1', name: 'pg-forward', serverId: 's1' })
    tunnels.push({ id: 't2', name: 'unrelated', serverId: 's9' })

    const deps = vpnDependents('v1')
    expect(deps.filter((d) => d.kind === 'tunnel').map((d) => d.id)).toEqual(['t1'])
  })

  it('reports nothing for a profile with no references', () => {
    servers.push({ id: 's1', name: 'bastion', vpnProfileId: 'v2' })
    expect(vpnDependents('v1')).toEqual([])
  })
})

describe('live consumers', () => {
  it('registers and releases, and the release is idempotent', () => {
    const release = registerVpnConsumer('v1', { kind: 'session', id: 'sess-1', name: 'bastion' })
    expect(hasLiveVpnDependents('v1')).toBe(true)
    expect(liveVpnDependents('v1')).toEqual([
      { kind: 'session', id: 'sess-1', name: 'bastion', live: true }
    ])

    release()
    expect(hasLiveVpnDependents('v1')).toBe(false)
    expect(() => release()).not.toThrow()
    expect(hasLiveVpnDependents('v1')).toBe(false)
  })

  it('deduplicates by kind and id so a re-register does not double count', () => {
    registerVpnConsumer('v1', { kind: 'session', id: 'sess-1', name: 'bastion' })
    registerVpnConsumer('v1', { kind: 'session', id: 'sess-1', name: 'bastion (renamed)' })
    expect(liveVpnDependents('v1')).toHaveLength(1)
    expect(liveVpnDependents('v1')[0].name).toBe('bastion (renamed)')
  })

  it('keeps profiles separate', () => {
    registerVpnConsumer('v1', { kind: 'session', id: 'a', name: 'a' })
    registerVpnConsumer('v2', { kind: 'session', id: 'b', name: 'b' })
    expect(liveVpnDependents('v1')).toHaveLength(1)
    expect(liveVpnDependents('v2')).toHaveLength(1)
  })

  it('lists live consumers alongside stored references', () => {
    servers.push({ id: 's1', name: 'bastion', vpnProfileId: 'v1' })
    registerVpnConsumer('v1', { kind: 'session', id: 'sess-1', name: 'bastion #1' })

    const deps = vpnDependents('v1')
    expect(deps).toHaveLength(2)
    expect(deps.filter((d) => d.live)).toHaveLength(1)
  })
})

describe('delete blockers', () => {
  it('counts stored references but not live sessions', () => {
    // A live session ends by itself. A stored reference would keep pointing at
    // a profile that no longer exists, which is the thing worth blocking on.
    servers.push({ id: 's1', name: 'bastion', vpnProfileId: 'v1' })
    registerVpnConsumer('v1', { kind: 'session', id: 'sess-1', name: 'live one' })

    const blockers = vpnDeleteBlockers('v1')
    expect(blockers).toHaveLength(1)
    expect(blockers[0].kind).toBe('server')
  })
})

describe('resolution for dialling', () => {
  it('returns the profile a server should be dialled through', () => {
    vpnIds.add('v1')
    servers.push({ id: 's1', name: 'bastion', vpnProfileId: 'v1' })
    expect(vpnForServer('s1')).toBe('v1')
  })

  it('returns null for a reference to a deleted profile rather than throwing', () => {
    // A stale reference must not stop the user connecting to the server
    // directly — failing closed here would turn one deleted profile into an
    // unreachable fleet.
    servers.push({ id: 's1', name: 'bastion', vpnProfileId: 'gone' })
    expect(vpnForServer('s1')).toBeNull()
  })

  it('returns null for an unknown server or database', () => {
    expect(vpnForServer('nope')).toBeNull()
    expect(vpnForDatabase('nope')).toBeNull()
  })

  it('resolves databases the same way', () => {
    vpnIds.add('v1')
    databases.push({ id: 'd1', name: 'prod', vpnProfileId: 'v1' })
    expect(vpnForDatabase('d1')).toBe('v1')
  })
})
