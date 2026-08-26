import { describe, it, expect, beforeAll, afterAll } from 'vitest'
import { Client } from '@modelcontextprotocol/sdk/client/index.js'
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js'

import { refreshMcpDataCache } from '../src/main/services/mcpDataCache'
import { setAssignment, resetPolicyCacheForTests } from '../src/main/services/policyStore'
import { setMcpConfig, createSession, resetMcpAuthForTests } from '../src/main/services/mcpAuth'
import { startMcpServer, stopMcpServer } from '../src/main/services/mcpServer'
import { onApprovalEvent, respondToApproval, listPendingApprovals } from '../src/main/services/approvals'

// An ASK-tier tool call blocks until a human answers it in the app. Before
// this, the agent got no output whatsoever for the whole approval timeout and
// reported the tool as hung. These tests pin the two things that stop that:
// the agent is told an approval is pending, and if nobody answers, the error
// says where the request was waiting instead of just "timed out".
const PORT = 58739

const sampleData = {
  workspaces: [{ id: 'ws-prod', name: 'Production' }],
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
      route: []
    }
  ]
}

let token: string

async function connectedClient(): Promise<Client> {
  const transport = new StreamableHTTPClientTransport(new URL(`http://127.0.0.1:${PORT}/mcp`), {
    requestInit: { headers: { Authorization: `Bearer ${token}` } }
  })
  const client = new Client({ name: 'test-client', version: '1.0.0' })
  await client.connect(transport)
  return client
}

describe('a pending approval is visible to the agent', () => {
  beforeAll(async () => {
    resetMcpAuthForTests()
    resetPolicyCacheForTests()
    refreshMcpDataCache(sampleData)
    // Read & Write puts writeFiles at 'ask' on both layers, so write_file
    // reaches the human-approval path rather than being allowed or denied.
    setAssignment({ level: 'workspace', workspaceId: 'ws-prod' }, 'grp-read-write')
    setMcpConfig({ enabled: true, port: PORT, approvalTimeoutSeconds: 2 })
    token = createSession({
      agentName: 'Test Agent',
      workspaces: [{ id: 'ws-prod', name: 'Production' }],
      groupId: 'grp-read-write',
      groupName: 'Read & Write',
      ttlMinutes: 60
    }).token
    const result = await startMcpServer()
    expect(result.ok).toBe(true)
  })

  afterAll(async () => {
    await stopMcpServer()
  })

  it('sends a progress notification naming the action, instead of going silent', async () => {
    const client = await connectedClient()
    const messages: string[] = []

    // Answer as soon as the notification arrives: that both keeps the test
    // fast and proves the notification is sent *before* the block, not after.
    const off = onApprovalEvent((e) => {
      if (e.type === 'created') setTimeout(() => respondToApproval(e.request.id, 'denied'), 10)
    })

    try {
      await client.callTool(
        { name: 'write_file', arguments: { serverName: 'Nginx Server Prod', path: '/tmp/x', content: 'x' } },
        undefined,
        { onprogress: (p) => { if (p.message) messages.push(p.message) } }
      )
    } finally {
      off()
    }

    expect(messages).toHaveLength(1)
    expect(messages[0]).toContain('Waiting for a human')
    expect(messages[0]).toContain('Nginx Server Prod')
    // The word the user actually used when reporting this.
    expect(messages[0]).toContain('not stuck')
    await client.close()
  })

  it('leaves the request pending until a human answers — the agent cannot self-approve', async () => {
    const client = await connectedClient()
    let sawPending = false
    // Denied rather than approved on purpose: approving would let the tool go
    // on to open a real SSH connection to a host that does not exist, and the
    // point here is the approval gate, not what happens past it.
    const off = onApprovalEvent((e) => {
      if (e.type === 'created') {
        sawPending = listPendingApprovals().some((r) => r.id === e.request.id)
        setTimeout(() => respondToApproval(e.request.id, 'denied'), 10)
      }
    })
    try {
      await client.callTool({
        name: 'write_file',
        arguments: { serverName: 'Nginx Server Prod', path: '/tmp/x', content: 'x' }
      })
    } finally {
      // Unsubscribing in a finally matters: a listener leaked by a failing
      // test auto-answers the *next* test's approval and makes it fail too,
      // which is exactly how this suite first went wrong.
      off()
    }
    expect(sawPending).toBe(true)
    await client.close()
  })

  it('says where the request was waiting when nobody answers it', async () => {
    const client = await connectedClient()
    const result = await client.callTool({
      name: 'write_file',
      arguments: { serverName: 'Nginx Server Prod', path: '/tmp/x', content: 'x' }
    })
    expect(result.isError).toBe(true)
    const text = (result.content as { type: string; text: string }[])[0].text
    expect(text).toContain('ShellPilot window')
    // A timeout the user can act on names the setting that stops it recurring.
    expect(text).toContain('Ask to Allow')
    await client.close()
  }, 10_000)

  it('a denial still reads as a decision, not as a timeout', async () => {
    const client = await connectedClient()
    const off = onApprovalEvent((e) => {
      if (e.type === 'created') setTimeout(() => respondToApproval(e.request.id, 'denied'), 10)
    })
    let result
    try {
      result = await client.callTool({
        name: 'write_file',
        arguments: { serverName: 'Nginx Server Prod', path: '/tmp/x', content: 'x' }
      })
    } finally {
      off()
    }
    const text = (result.content as { type: string; text: string }[])[0].text
    expect(text).toContain('the user rejected')
    expect(text).not.toContain('timed out')
    await client.close()
  })
})
