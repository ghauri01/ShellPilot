// The workspace/server list is owned by the renderer's Zustand store; main
// only ever sees it as an opaque JSON blob it persists (see store.ts). The
// MCP bridge runs entirely in main and needs to resolve friendly server
// names without round-tripping through the renderer on every tool call, so
// it keeps a read-only cache of the same file, refreshed whenever the
// renderer calls data:save. Nothing here writes to the file — that stays
// store.ts's job.
import { loadData } from './store'
import type { SshAuth, SshHop } from '../../shared/ssh'

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
}

interface DataShape {
  workspaces?: unknown
  servers?: unknown
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
      route: parseRoute(s.route)
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

export function refreshMcpDataCache(data?: unknown): void {
  const raw = (data ?? loadData()) as DataShape | null
  workspaces = parseWorkspaces(raw?.workspaces)
  servers = parseServers(raw?.servers)
}

export function listCachedWorkspaces(): CachedWorkspace[] {
  return workspaces
}

export function listCachedServers(workspaceId?: string): CachedServer[] {
  return workspaceId ? servers.filter((s) => s.workspaceId === workspaceId) : servers
}

export function getCachedServer(id: string): CachedServer | null {
  return servers.find((s) => s.id === id) ?? null
}

export function getCachedWorkspace(id: string): CachedWorkspace | null {
  return workspaces.find((w) => w.id === id) ?? null
}
