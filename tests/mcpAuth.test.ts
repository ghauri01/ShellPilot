import { describe, it, expect, beforeEach } from 'vitest'
import { writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { app } from 'electron'
import {
  authenticate,
  createSession,
  revokeSession,
  deleteSession,
  killAllSessions,
  listSessions,
  getMcpConfig,
  setMcpConfig,
  resetMcpAuthForTests
} from '../src/main/services/mcpAuth'

function makeSession(ttlMinutes: number | null = 60) {
  return createSession({
    agentName: 'Claude Code',
    workspaces: [{ id: 'ws-1', name: 'Production' }],
    groupId: 'grp-read-only',
    groupName: 'Read Only',
    ttlMinutes
  })
}

describe('MCP authentication', () => {
  beforeEach(() => resetMcpAuthForTests())

  it('is disabled by default', () => {
    const { token } = makeSession()
    const result = authenticate(token)
    expect('error' in result && result.error).toBe('ai-disabled')
  })

  it('accepts a valid token once enabled', () => {
    setMcpConfig({ enabled: true })
    const { token, session } = makeSession()
    const result = authenticate(token)
    expect('session' in result && result.session.id).toBe(session.id)
  })

  it('rejects a missing token', () => {
    setMcpConfig({ enabled: true })
    const result = authenticate(null)
    expect('error' in result && result.error).toBe('missing-token')
  })

  it('rejects an invalid/unrecognized token', () => {
    setMcpConfig({ enabled: true })
    makeSession()
    const result = authenticate('not-a-real-token')
    expect('error' in result && result.error).toBe('invalid-token')
  })

  it('rejects a revoked session', () => {
    setMcpConfig({ enabled: true })
    const { token, session } = makeSession()
    revokeSession(session.id)
    const result = authenticate(token)
    expect('error' in result && result.error).toBe('revoked')
  })

  it('rejects an expired session', () => {
    setMcpConfig({ enabled: true })
    const { token } = makeSession(-1) // already in the past
    const result = authenticate(token)
    expect('error' in result && result.error).toBe('expired')
  })

  it('a session with no TTL never expires', () => {
    setMcpConfig({ enabled: true })
    const { token } = makeSession(null)
    const result = authenticate(token)
    expect('session' in result).toBe(true)
  })

  it('the kill switch revokes every session at once', () => {
    setMcpConfig({ enabled: true })
    const a = makeSession()
    const b = makeSession()
    const revoked = killAllSessions()
    expect(revoked).toBe(2)
    expect('error' in authenticate(a.token) && authenticate(a.token).error).toBe('revoked')
    expect('error' in authenticate(b.token) && authenticate(b.token).error).toBe('revoked')
  })

  it('stores only a token hash, never the raw token', () => {
    setMcpConfig({ enabled: true })
    const { token, session } = makeSession()
    expect(session.tokenHash).not.toBe(token)
    expect(session.tokenHash).toHaveLength(64) // sha256 hex
  })

  it('respects userData for config (portable-mode friendly)', () => {
    const before = getMcpConfig()
    expect(before.port).toBeGreaterThan(0)
    setMcpConfig({ port: 9999 })
    expect(getMcpConfig().port).toBe(9999)
  })

  it('migrates a pre-multi-workspace session record instead of crashing on it', () => {
    // Sessions saved before a session could span several workspaces are
    // { workspaceId, workspaceName } on disk, not { workspaces }. Loading
    // one must not leave `.workspaces` undefined for a renderer to crash on.
    const legacy = [
      {
        id: 'sess-legacy',
        agentName: 'Claude Code',
        workspaceId: 'ws-old',
        workspaceName: 'Old Workspace',
        groupId: 'grp-read-only',
        groupName: 'Read Only',
        tokenHash: 'a'.repeat(64),
        tokenPreview: 'abcd',
        createdAt: new Date().toISOString(),
        expiresAt: null,
        lastActiveAt: new Date().toISOString(),
        revoked: false
      }
    ]
    writeFileSync(join(app.getPath('userData'), 'shellpilot-mcp-sessions.json'), JSON.stringify(legacy))

    const [migrated] = listSessions()
    expect(Array.isArray(migrated.workspaces)).toBe(true)
    expect(migrated.workspaces).toEqual([{ id: 'ws-old', name: 'Old Workspace' }])
  })

  it('deleting a session removes it from the list entirely, unlike revoke', () => {
    setMcpConfig({ enabled: true })
    const { session } = makeSession()
    expect(listSessions().some((s) => s.id === session.id)).toBe(true)

    const result = deleteSession(session.id)

    expect(result).toBe(true)
    expect(listSessions().some((s) => s.id === session.id)).toBe(false)
  })

  it('deleting a still-live session revokes it in effect, not just from the list', () => {
    setMcpConfig({ enabled: true })
    const { token, session } = makeSession()
    expect('session' in authenticate(token)).toBe(true) // live before deletion

    deleteSession(session.id)

    const result = authenticate(token)
    expect('error' in result && result.error).toBe('invalid-token')
  })

  it('deleting an unknown session id is reported, not silently ignored', () => {
    expect(deleteSession('sess-does-not-exist')).toBe(false)
  })
})
