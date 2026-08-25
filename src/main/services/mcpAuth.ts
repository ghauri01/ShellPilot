import { app } from 'electron'
import { join } from 'node:path'
import { existsSync, readFileSync, writeFileSync, renameSync, unlinkSync } from 'node:fs'
import { randomBytes, createHash, timingSafeEqual } from 'node:crypto'
import type { McpAgentSession, McpGlobalConfig, WorkspaceRef } from '../../shared/mcp'
import { DEFAULT_MCP_PORT } from '../../shared/mcp'

const CONFIG_FILE = join(app.getPath('userData'), 'shellpilot-mcp-config.json')
const CONFIG_TMP = `${CONFIG_FILE}.tmp`
const SESSIONS_FILE = join(app.getPath('userData'), 'shellpilot-mcp-sessions.json')
const SESSIONS_TMP = `${SESSIONS_FILE}.tmp`

function defaultConfig(): McpGlobalConfig {
  return { enabled: false, port: DEFAULT_MCP_PORT, defaultSessionTtlMinutes: 60, approvalTimeoutSeconds: 120 }
}

let config: McpGlobalConfig | null = null

function loadConfig(): McpGlobalConfig {
  if (config) return config
  try {
    if (existsSync(CONFIG_FILE)) {
      const parsed = JSON.parse(readFileSync(CONFIG_FILE, 'utf8')) as Partial<McpGlobalConfig>
      config = { ...defaultConfig(), ...parsed }
      return config
    }
  } catch {
    /* fall through to defaults on a corrupt file */
  }
  config = defaultConfig()
  return config
}

function writeConfig(next: McpGlobalConfig): void {
  config = next
  writeFileSync(CONFIG_TMP, JSON.stringify(next), { mode: 0o600 })
  renameSync(CONFIG_TMP, CONFIG_FILE)
}

export function getMcpConfig(): McpGlobalConfig {
  return loadConfig()
}

export function setMcpConfig(patch: Partial<McpGlobalConfig>): McpGlobalConfig {
  const next = { ...loadConfig(), ...patch }
  writeConfig(next)
  return next
}

// Sessions only ever persist a token hash + preview, never the raw secret, so
// this file carries no more sensitivity than the audit log.
let sessions: McpAgentSession[] | null = null

function loadSessions(): McpAgentSession[] {
  if (sessions) return sessions
  try {
    if (existsSync(SESSIONS_FILE)) {
      const parsed = JSON.parse(readFileSync(SESSIONS_FILE, 'utf8'))
      if (Array.isArray(parsed)) {
        sessions = parsed as McpAgentSession[]
        return sessions
      }
    }
  } catch {
    /* fall through */
  }
  sessions = []
  return sessions
}

function writeSessions(): void {
  writeFileSync(SESSIONS_TMP, JSON.stringify(sessions ?? []), { mode: 0o600 })
  renameSync(SESSIONS_TMP, SESSIONS_FILE)
}

function hashToken(raw: string): string {
  return createHash('sha256').update(raw).digest('hex')
}

function isExpired(session: McpAgentSession): boolean {
  return session.expiresAt !== null && new Date(session.expiresAt).getTime() <= Date.now()
}

export interface CreateSessionInput {
  agentName: string
  workspaces: WorkspaceRef[]
  groupId: string | null
  groupName: string
  ttlMinutes: number | null // null = no expiration
}

export function createSession(input: CreateSessionInput): { session: McpAgentSession; token: string } {
  const raw = randomBytes(32).toString('hex')
  const now = new Date()
  const session: McpAgentSession = {
    id: `sess-${randomBytes(6).toString('hex')}`,
    agentName: input.agentName,
    workspaces: input.workspaces,
    groupId: input.groupId,
    groupName: input.groupName,
    tokenHash: hashToken(raw),
    tokenPreview: raw.slice(-4),
    createdAt: now.toISOString(),
    expiresAt: input.ttlMinutes ? new Date(now.getTime() + input.ttlMinutes * 60_000).toISOString() : null,
    lastActiveAt: now.toISOString(),
    revoked: false
  }
  const list = loadSessions()
  list.push(session)
  writeSessions()
  return { session, token: raw }
}

export function listSessions(): McpAgentSession[] {
  return [...loadSessions()].sort((a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime())
}

export function getSession(id: string): McpAgentSession | null {
  return loadSessions().find((s) => s.id === id) ?? null
}

export function revokeSession(id: string): void {
  const list = loadSessions()
  const session = list.find((s) => s.id === id)
  if (session) session.revoked = true
  writeSessions()
}

export function killAllSessions(): number {
  const list = loadSessions()
  let count = 0
  for (const s of list) {
    if (!s.revoked) {
      s.revoked = true
      count++
    }
  }
  writeSessions()
  return count
}

export type AuthFailureReason = 'missing-token' | 'invalid-token' | 'revoked' | 'expired' | 'ai-disabled'

// Looks up a session by bearer token using a constant-time comparison so
// timing differences between a near-miss and a total mismatch can't leak
// information about valid hashes.
export function authenticate(rawToken: string | null): { session: McpAgentSession } | { error: AuthFailureReason } {
  if (!getMcpConfig().enabled) return { error: 'ai-disabled' }
  if (!rawToken) return { error: 'missing-token' }
  const hash = hashToken(rawToken)
  const hashBuf = Buffer.from(hash, 'hex')

  const match = loadSessions().find((s) => {
    const candidate = Buffer.from(s.tokenHash, 'hex')
    return candidate.length === hashBuf.length && timingSafeEqual(candidate, hashBuf)
  })

  if (!match) return { error: 'invalid-token' }
  if (match.revoked) return { error: 'revoked' }
  if (isExpired(match)) return { error: 'expired' }

  match.lastActiveAt = new Date().toISOString()
  writeSessions()
  return { session: match }
}

export function resetMcpAuthForTests(): void {
  config = null
  sessions = null
  for (const f of [CONFIG_FILE, SESSIONS_FILE]) {
    try {
      if (existsSync(f)) unlinkSync(f)
    } catch {
      /* ignore */
    }
  }
}
