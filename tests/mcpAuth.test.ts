import { describe, it, expect, beforeEach } from 'vitest'
import {
  authenticate,
  createSession,
  revokeSession,
  killAllSessions,
  getMcpConfig,
  setMcpConfig,
  resetMcpAuthForTests
} from '../src/main/services/mcpAuth'

function makeSession(ttlMinutes: number | null = 60) {
  return createSession({
    agentName: 'Claude Code',
    workspaceId: 'ws-1',
    workspaceName: 'Production',
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
})
