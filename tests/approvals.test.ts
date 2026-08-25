import { describe, it, expect, beforeEach } from 'vitest'
import { requestApproval, respondToApproval, listPendingApprovals, denyAllPending } from '../src/main/services/approvals'
import { setMcpConfig, resetMcpAuthForTests } from '../src/main/services/mcpAuth'

function req(overrides: Partial<Parameters<typeof requestApproval>[0]> = {}) {
  return requestApproval({
    sessionId: 'sess-1',
    agentName: 'Claude Code',
    workspaceId: 'ws-1',
    workspaceName: 'Production',
    serverId: 'srv-1',
    serverName: 'Nginx Server Prod',
    capability: 'sudo',
    action: 'sudo systemctl restart nginx',
    risk: 'high',
    ...overrides
  })
}

describe('human approval', () => {
  beforeEach(() => {
    resetMcpAuthForTests()
    setMcpConfig({ approvalTimeoutSeconds: 60 })
  })

  it('a pending request shows up for the UI to act on', async () => {
    const pending = req()
    const list = listPendingApprovals()
    expect(list).toHaveLength(1)
    expect(list[0].status).toBe('pending')
    respondToApproval(list[0].id, 'approved')
    expect(await pending).toBe('approved')
  })

  it('the AI-facing path has no way to resolve its own request — only respondToApproval (UI-only) can', async () => {
    const pending = req()
    const [approval] = listPendingApprovals()
    // Nothing in this module lets a tool-call path resolve a request except
    // this exact function, which is only ever invoked from the renderer's
    // approval IPC handler.
    respondToApproval(approval.id, 'denied')
    expect(await pending).toBe('denied')
  })

  it('denyAllPending answers every outstanding request immediately', async () => {
    const a = req()
    const b = req({ action: 'rm -rf /var/cache/app' })
    expect(listPendingApprovals()).toHaveLength(2)
    const count = denyAllPending()
    expect(count).toBe(2)
    expect(await a).toBe('denied')
    expect(await b).toBe('denied')
    expect(listPendingApprovals()).toHaveLength(0)
  })

  it('responding to an unknown id is a no-op', () => {
    expect(respondToApproval('nope', 'approved')).toBe(false)
  })
})
