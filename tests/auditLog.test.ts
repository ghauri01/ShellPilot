import { describe, it, expect } from 'vitest'
import { recordAudit, listAudit } from '../src/main/services/auditLog'

describe('audit logging', () => {
  it('records agent, session, workspace, server, action, approval and result', () => {
    recordAudit({
      agentName: 'Claude Code',
      sessionId: 'sess-1',
      workspaceId: 'ws-1',
      workspaceName: 'Production',
      serverId: 'srv-1',
      serverName: 'Nginx Server Prod',
      action: 'systemctl restart nginx',
      capability: 'terminal',
      approval: 'approved',
      result: 'success',
      exitCode: 0
    })
    const entries = listAudit(10)
    const entry = entries.find((e) => e.action === 'systemctl restart nginx')
    expect(entry).toBeTruthy()
    expect(entry?.agentName).toBe('Claude Code')
    expect(entry?.workspaceName).toBe('Production')
    expect(entry?.approval).toBe('approved')
    expect(entry?.result).toBe('success')
    expect(entry?.exitCode).toBe(0)
    expect(entry?.id).toBeTruthy()
    expect(entry?.timestamp).toBeTruthy()
  })

  it('never stores a secret value even if the action text carried one', () => {
    recordAudit({
      agentName: 'Claude Code',
      sessionId: 'sess-1',
      workspaceId: 'ws-1',
      workspaceName: 'Production',
      serverId: 'srv-1',
      serverName: 'DB Prod',
      action: 'echo DB_PASSWORD=hunter2',
      capability: 'terminal',
      approval: 'not-required',
      result: 'success'
    })
    const entries = listAudit(10)
    const entry = entries.find((e) => e.action.includes('DB_PASSWORD'))
    expect(entry?.action).not.toContain('hunter2')
  })

  it('newest entries come first', () => {
    recordAudit({
      agentName: 'A',
      sessionId: 's',
      workspaceId: null,
      workspaceName: null,
      serverId: null,
      serverName: null,
      action: 'first',
      capability: null,
      approval: 'not-required',
      result: 'success'
    })
    recordAudit({
      agentName: 'A',
      sessionId: 's',
      workspaceId: null,
      workspaceName: null,
      serverId: null,
      serverName: null,
      action: 'second',
      capability: null,
      approval: 'not-required',
      result: 'success'
    })
    const entries = listAudit(2)
    expect(entries[0].action).toBe('second')
    expect(entries[1].action).toBe('first')
  })
})
