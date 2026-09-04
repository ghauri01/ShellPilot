import { beforeEach, describe, expect, it, vi } from 'vitest'
import type { SshConnectConfig } from '../src/shared/ssh'

// Which VPN a connection rides is resolved in main from the saved record, not
// sent by the renderer. That choice is what these tests are about: every call
// site — terminal, SFTP, metrics, the database shell, the MCP tools, the CLI —
// builds its own config object, and resolving centrally is what stops one of
// them silently skipping the tunnel because it was written first.

const servers: { id: string; name: string; vpnProfileId: string | null }[] = []
const databases: { id: string; name: string; vpnProfileId: string | null }[] = []
const vpnIds = new Set<string>()

vi.mock('../src/main/services/mcpDataCache', () => ({
  listCachedServers: () => servers,
  listCachedDatabases: () => databases,
  listCachedTunnels: () => [],
  getCachedVpn: (id: string) => (vpnIds.has(id) ? { id } : null),
  getCachedServer: (id: string) => servers.find((s) => s.id === id) ?? null,
  getCachedDatabase: (id: string) => databases.find((d) => d.id === id) ?? null
}))

const { withVpnTransport, withVpnTransportDb } = await import(
  '../src/main/services/vpn/transport'
)

beforeEach(() => {
  servers.length = 0
  databases.length = 0
  vpnIds.clear()
})

// Typed as the config `withVpnTransport` takes, rather than cast to `never`.
// The cast made the generic resolve to `never`, so every `out.vpnProfileId`,
// `out.serverName`, `out.username` and `out.port` below was read off a type
// with no members — which is what those five errors were, and it also meant
// the fixture itself was never checked against `SshConnectConfig`.
const sshCfg = (
  over: Partial<SshConnectConfig & { serverId: string }> = {}
): SshConnectConfig & { serverId?: string } => ({
  host: 'bastion.internal',
  port: 22,
  username: 'alice',
  auth: 'key',
  sessionId: 's',
  cols: 80,
  rows: 24,
  ...over
})

describe('SSH', () => {
  it('attaches the profile and the server name when the record names one', () => {
    vpnIds.add('v1')
    servers.push({ id: 'srv1', name: 'bastion', vpnProfileId: 'v1' })

    const out = withVpnTransport(sshCfg({ serverId: 'srv1' }))
    expect(out.vpnProfileId).toBe('v1')
    // The name is what the "3 sessions are using this VPN" confirmation shows,
    // so it has to be the one the user recognises rather than a UUID.
    expect(out.serverName).toBe('bastion')
  })

  it('leaves a direct connection untouched, object identity included', () => {
    servers.push({ id: 'srv1', name: 'bastion', vpnProfileId: null })
    const cfg = sshCfg({ serverId: 'srv1' })
    expect(withVpnTransport(cfg)).toBe(cfg)
  })

  it('ignores an ad-hoc connection with no serverId', () => {
    const cfg = sshCfg()
    expect(withVpnTransport(cfg)).toBe(cfg)
  })

  it('treats a reference to a deleted profile as direct', () => {
    // Failing closed here would turn one deleted profile into an unreachable
    // fleet. The connection goes direct and the UI is what flags the dangling
    // reference.
    servers.push({ id: 'srv1', name: 'bastion', vpnProfileId: 'gone' })
    expect(withVpnTransport(sshCfg({ serverId: 'srv1' })).vpnProfileId).toBeUndefined()
  })

  it('preserves every other field it was given', () => {
    vpnIds.add('v1')
    servers.push({ id: 'srv1', name: 'bastion', vpnProfileId: 'v1' })
    const out = withVpnTransport(sshCfg({ serverId: 'srv1', username: 'bob', port: 2222 }))
    expect(out.username).toBe('bob')
    expect(out.port).toBe(2222)
  })
})

describe('databases', () => {
  const dbCfg = (over: Record<string, unknown> = {}): never =>
    ({ id: 'db1', kind: 'postgres', host: 'pg.internal', port: 5432, username: 'app', ...over }) as never

  it('attaches the profile and the connection name', () => {
    vpnIds.add('v1')
    databases.push({ id: 'db1', name: 'prod', vpnProfileId: 'v1' })
    const out = withVpnTransportDb(dbCfg())
    expect(out.vpnProfileId).toBe('v1')
    expect(out.name).toBe('prod')
  })

  it('keeps a name the caller already supplied', () => {
    vpnIds.add('v1')
    databases.push({ id: 'db1', name: 'prod', vpnProfileId: 'v1' })
    expect(withVpnTransportDb(dbCfg({ name: 'from caller' })).name).toBe('from caller')
  })

  it('leaves an unsaved test connection alone', () => {
    // A "Test connection" dialog has no record in the cache. Guessing a VPN
    // for it would be inventing a decision the user has not made.
    const cfg = dbCfg({ id: 'not-saved-yet' })
    expect(withVpnTransportDb(cfg)).toBe(cfg)
  })

  it('treats a reference to a deleted profile as direct', () => {
    databases.push({ id: 'db1', name: 'prod', vpnProfileId: 'gone' })
    expect(withVpnTransportDb(dbCfg()).vpnProfileId).toBeUndefined()
  })

  it('does not confuse a server id with a database id', () => {
    vpnIds.add('v1')
    servers.push({ id: 'db1', name: 'a server that shares an id', vpnProfileId: 'v1' })
    expect(withVpnTransportDb(dbCfg()).vpnProfileId).toBeUndefined()
  })
})
