// The workspace/server list is owned by the renderer's Zustand store; main
// only ever sees it as an opaque JSON blob it persists (see store.ts). The
// MCP bridge runs entirely in main and needs to resolve friendly server
// names without round-tripping through the renderer on every tool call, so
// it keeps a read-only cache of the same file, refreshed whenever the
// renderer calls data:save. Nothing here writes to the file — that stays
// store.ts's job.
import { loadData } from './store'
import type { SshAuth, SshHop } from '../../shared/ssh'
import type { DbKind } from '../../shared/db'
import type { TunnelKind } from '../../shared/tunnel'
import type { VpnKind, VpnMode } from '../../shared/vpn'

export type CachedHop = SshHop & { serverId?: string }

export interface CachedWorkspace {
  id: string
  name: string
}

export interface CachedServer {
  id: string
  workspaceId: string
  name: string
  host: string
  port: number
  username: string
  auth: SshAuth
  os: string
  route: CachedHop[]
  // Reached through this VPN profile when set, which is why the VPN has to be
  // up before the server is dialled and why stopping that VPN has to say what
  // it would cut. Main-internal wiring only: never put this in an MCP tool
  // response, for the same reason CachedVpn omits endpoints — the bridge may
  // say a profile exists, not where anything points.
  vpnProfileId: string | null
}

export interface CachedDatabase {
  id: string
  workspaceId: string
  name: string
  kind: DbKind
  host: string
  port: number
  username: string
  database: string
  ssl: boolean
  uri: boolean
  // Reached through this SSH server when set, exactly as an interactive
  // connection would be.
  sshServerId: string | null
  // As on CachedServer: main-internal, and never returned to an agent.
  vpnProfileId: string | null
}

export interface CachedTunnel {
  id: string
  workspaceId: string
  name: string
  kind: TunnelKind
  serverId: string | null
  listen: string
  target: string
}

// Deliberately narrower than VpnProfile. The MCP bridge is allowed to say a
// profile exists, what engine carries it and how many things it exposes; it is
// never allowed to say WHERE it points. So the endpoint, the peer keys, the
// vault refs and the listener bind addresses are not parsed into this shape at
// all, rather than parsed and then remembered not to print — a field that does
// not exist cannot leak into a tool response by someone adding one more line to
// a template string.
export interface CachedVpn {
  id: string
  workspaceId: string
  name: string
  kind: VpnKind
  // OpenVPN and frp have no userspace mode, so the field is synthesised as
  // 'system' for them rather than left optional at every call site.
  mode: VpnMode
  // Userspace WireGuard only; how many local listeners the profile defines.
  listenerCount: number
  // frp only; how many proxies the profile would publish.
  proxyCount: number
  autoStart: boolean
}

interface DataShape {
  workspaces?: unknown
  servers?: unknown
  databases?: unknown
  tunnels?: unknown
  vpns?: unknown
}

function isSshAuth(v: unknown): v is SshAuth {
  return v === 'password' || v === 'key' || v === 'agent'
}

function parseRoute(raw: unknown): CachedHop[] {
  if (!Array.isArray(raw)) return []
  return raw.filter(isRecord).map((h) => ({
    host: asString(h.host),
    port: asNumber(h.port, 22),
    username: asString(h.username),
    auth: isSshAuth(h.auth) ? h.auth : 'key',
    keyPath: typeof h.keyPath === 'string' ? h.keyPath : undefined,
    // A hop backed by a saved server resolves its own stored credentials by
    // id, same as a direct connection.
    serverId: typeof h.serverId === 'string' ? h.serverId : undefined
  }))
}

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null
}

function asString(v: unknown, fallback = ''): string {
  return typeof v === 'string' ? v : fallback
}

function asNumber(v: unknown, fallback: number): number {
  return typeof v === 'number' ? v : fallback
}

function parseWorkspaces(raw: unknown): CachedWorkspace[] {
  if (!Array.isArray(raw)) return []
  return raw
    .filter(isRecord)
    .filter((w) => typeof w.id === 'string' && typeof w.name === 'string')
    .map((w) => ({ id: w.id as string, name: w.name as string }))
}

function parseServers(raw: unknown): CachedServer[] {
  if (!Array.isArray(raw)) return []
  return raw
    .filter(isRecord)
    .filter((s) => typeof s.id === 'string' && typeof s.workspaceId === 'string')
    .map((s) => ({
      id: s.id as string,
      workspaceId: s.workspaceId as string,
      name: asString(s.name, s.host as string),
      host: asString(s.host),
      port: asNumber(s.port, 22),
      username: asString(s.username),
      auth: isSshAuth(s.auth) ? s.auth : 'key',
      os: asString(s.os, 'Linux'),
      route: parseRoute(s.route),
      vpnProfileId: typeof s.vpnProfileId === 'string' ? s.vpnProfileId : null
    }))
}

function isDbKind(v: unknown): v is DbKind {
  return v === 'postgres' || v === 'mysql' || v === 'mssql' || v === 'mongodb' || v === 'redis'
}

function isTunnelKind(v: unknown): v is TunnelKind {
  return v === 'local' || v === 'remote' || v === 'socks'
}

function parseDatabases(raw: unknown): CachedDatabase[] {
  if (!Array.isArray(raw)) return []
  return raw
    .filter(isRecord)
    .filter((d) => typeof d.id === 'string' && typeof d.workspaceId === 'string')
    .map((d) => ({
      id: d.id as string,
      workspaceId: d.workspaceId as string,
      name: asString(d.name, asString(d.host)),
      kind: isDbKind(d.kind) ? d.kind : 'postgres',
      host: asString(d.host),
      port: asNumber(d.port, 0),
      username: asString(d.username),
      database: asString(d.database),
      ssl: d.ssl === true,
      uri: d.uri === true,
      sshServerId: typeof d.sshServerId === 'string' ? d.sshServerId : null,
      vpnProfileId: typeof d.vpnProfileId === 'string' ? d.vpnProfileId : null
    }))
}

function isVpnKind(v: unknown): v is VpnKind {
  return v === 'wireguard' || v === 'openvpn' || v === 'frp'
}

function parseVpns(raw: unknown): CachedVpn[] {
  if (!Array.isArray(raw)) return []
  return raw
    .filter(isRecord)
    .filter((v) => typeof v.id === 'string' && typeof v.workspaceId === 'string')
    .map((v) => {
      const spec = isRecord(v.spec) ? v.spec : {}
      const kind = isVpnKind(spec.kind) ? spec.kind : 'wireguard'
      return {
        id: v.id as string,
        workspaceId: v.workspaceId as string,
        name: asString(v.name, v.id as string),
        kind,
        // Only WireGuard carries a mode; the other two always touch the real
        // network, so reporting anything but 'system' for them would be wrong.
        mode: kind === 'wireguard' && spec.mode === 'userspace' ? 'userspace' : 'system',
        listenerCount: Array.isArray(spec.listeners) ? spec.listeners.length : 0,
        proxyCount: Array.isArray(spec.proxies) ? spec.proxies.length : 0,
        autoStart: v.autoStart === true
      }
    })
}

function parseTunnels(raw: unknown): CachedTunnel[] {
  if (!Array.isArray(raw)) return []
  return raw
    .filter(isRecord)
    .filter((t) => typeof t.id === 'string' && typeof t.workspaceId === 'string')
    .map((t) => ({
      id: t.id as string,
      workspaceId: t.workspaceId as string,
      name: asString(t.name, t.id as string),
      kind: isTunnelKind(t.kind) ? t.kind : 'local',
      serverId: typeof t.serverId === 'string' ? t.serverId : null,
      listen: asString(t.listen),
      target: asString(t.target)
    }))
}

// Builds the same shape the renderer sends over ssh:connect/sftp:connect for
// this server, so the MCP bridge authenticates through the identical
// jump-host chain and credential resolver as an interactive session. The
// sessionId/cols/rows fields exist only to satisfy sftp.ts/metrics.ts's
// SshConnectConfig parameter type — they have no interactive terminal, so
// there is no real PTY size to report.
export function serverToSshConfig(
  server: CachedServer
): CachedHop & { hops: CachedHop[]; sessionId: string; cols: number; rows: number } {
  return {
    host: server.host,
    port: server.port,
    username: server.username,
    auth: server.auth,
    serverId: server.id,
    hops: server.route,
    sessionId: `mcp:${server.id}`,
    cols: 80,
    rows: 24
  }
}

let workspaces: CachedWorkspace[] = []
let servers: CachedServer[] = []
let databases: CachedDatabase[] = []
let tunnels: CachedTunnel[] = []
let vpns: CachedVpn[] = []

export function refreshMcpDataCache(data?: unknown): void {
  const raw = (data ?? loadData()) as DataShape | null
  workspaces = parseWorkspaces(raw?.workspaces)
  servers = parseServers(raw?.servers)
  databases = parseDatabases(raw?.databases)
  tunnels = parseTunnels(raw?.tunnels)
  vpns = parseVpns(raw?.vpns)
}

// Same scoping rule as servers: a session only ever sees what is inside the
// workspace(s) it was granted, and never a credential.
export function listCachedDatabases(workspaceId?: string | string[]): CachedDatabase[] {
  if (!workspaceId) return databases
  const ids = Array.isArray(workspaceId) ? workspaceId : [workspaceId]
  return databases.filter((d) => ids.includes(d.workspaceId))
}

export function getCachedDatabase(id: string): CachedDatabase | null {
  return databases.find((d) => d.id === id) ?? null
}

export function listCachedTunnels(workspaceId?: string | string[]): CachedTunnel[] {
  if (!workspaceId) return tunnels
  const ids = Array.isArray(workspaceId) ? workspaceId : [workspaceId]
  return tunnels.filter((t) => ids.includes(t.workspaceId))
}

export function getCachedTunnel(id: string): CachedTunnel | null {
  return tunnels.find((t) => t.id === id) ?? null
}

export function listCachedVpns(workspaceId?: string | string[]): CachedVpn[] {
  if (!workspaceId) return vpns
  const ids = Array.isArray(workspaceId) ? workspaceId : [workspaceId]
  return vpns.filter((v) => ids.includes(v.workspaceId))
}

export function getCachedVpn(id: string): CachedVpn | null {
  return vpns.find((v) => v.id === id) ?? null
}

export function listCachedWorkspaces(): CachedWorkspace[] {
  return workspaces
}

export function listCachedServers(workspaceId?: string | string[]): CachedServer[] {
  if (!workspaceId) return servers
  const ids = Array.isArray(workspaceId) ? workspaceId : [workspaceId]
  return servers.filter((s) => ids.includes(s.workspaceId))
}

export function getCachedServer(id: string): CachedServer | null {
  return servers.find((s) => s.id === id) ?? null
}

export function getCachedWorkspace(id: string): CachedWorkspace | null {
  return workspaces.find((w) => w.id === id) ?? null
}
