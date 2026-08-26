import { describe, it, expect, beforeAll, afterAll, beforeEach } from 'vitest'
import { Client } from '@modelcontextprotocol/sdk/client/index.js'
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js'

import { refreshMcpDataCache } from '../src/main/services/mcpDataCache'
import { setAssignment, resetPolicyCacheForTests } from '../src/main/services/policyStore'
import { setMcpConfig, createSession, resetMcpAuthForTests } from '../src/main/services/mcpAuth'
import { startMcpServer, stopMcpServer } from '../src/main/services/mcpServer'
import { onApprovalEvent, respondToApproval } from '../src/main/services/approvals'
import { listAudit } from '../src/main/services/auditLog'
import {
  setAgentServerCreator,
  type AgentServerRequest,
  type AgentServerResult
} from '../src/main/services/agentServerCreate'

const PORT = 58735
const PASSWORD = 'hunter2-do-not-log-me'

const sampleData = {
  workspaces: [{ id: 'ws-prod', name: 'Production' }],
  servers: [
    {
      id: 's1',
      workspaceId: 'ws-prod',
      name: 'Existing Box',
      host: '10.0.0.1',
      port: 22,
      username: 'root',
      auth: 'key',
      os: 'Linux',
      route: []
    }
  ]
}

let received: AgentServerRequest[] = []
let creatorResult: AgentServerResult = { ok: true, serverId: 's-new' }

beforeAll(async () => {
  resetPolicyCacheForTests()
  resetMcpAuthForTests()
  refreshMcpDataCache(sampleData)
  setMcpConfig({ enabled: true, port: PORT, approvalTimeoutSeconds: 5 })
  setAgentServerCreator((req) => {
    received.push(req)
    return Promise.resolve(creatorResult)
  })
  await startMcpServer()
})

afterAll(async () => await stopMcpServer())

beforeEach(() => {
  received = []
  creatorResult = { ok: true, serverId: 's-new' }
})

async function clientFor(groupId: string | null): Promise<Client> {
  const { token } = createSession({
    agentName: 'Test Agent',
    workspaces: [{ id: 'ws-prod', name: 'Production' }],
    groupId,
    groupName: groupId ?? 'No AI Access',
    ttlMinutes: null
  })
  const transport = new StreamableHTTPClientTransport(new URL(`http://127.0.0.1:${PORT}/mcp`), {
    requestInit: { headers: { Authorization: `Bearer ${token}` } }
  })
  const c = new Client({ name: 'add-server-test', version: '1.0.0' })
  await c.connect(transport)
  return c
}

async function call(c: Client, args: Record<string, unknown>): Promise<string> {
  const r = (await c.callTool({ name: 'add_server', arguments: args })) as {
    content: { text: string }[]
  }
  return r.content.map((x) => x.text).join('\n')
}

// Answers the approval dialog the way a user at the keyboard would.
function autoRespond(decision: 'approved' | 'denied'): () => void {
  return onApprovalEvent((e) => {
    if (e.type === 'created') respondToApproval(e.request.id, decision)
  })
}

describe('add_server', () => {
  it('is exposed as a tool', async () => {
    setAssignment({ level: 'workspace', workspaceId: 'ws-prod' }, 'grp-read-write')
    const c = await clientFor('grp-read-write')
    try {
      const { tools } = await c.listTools()
      expect(tools.map((t) => t.name)).toContain('add_server')
    } finally {
      await c.close()
    }
  })

  it('is denied under Read Only, which does not grant manageServers', async () => {
    setAssignment({ level: 'workspace', workspaceId: 'ws-prod' }, 'grp-read-only')
    const c = await clientFor('grp-read-only')
    try {
      expect(await call(c, { name: 'New Box', host: '10.0.0.9' })).toContain('Denied')
      expect(received).toHaveLength(0)
    } finally {
      await c.close()
    }
  })

  it('is denied when the workspace has no access group at all', async () => {
    setAssignment({ level: 'workspace', workspaceId: 'ws-prod' }, null)
    const c = await clientFor('grp-full')
    try {
      expect(await call(c, { name: 'New Box', host: '10.0.0.9' })).toContain('No AI access')
      expect(received).toHaveLength(0)
    } finally {
      await c.close()
    }
  })

  it('creates the server once the user approves', async () => {
    setAssignment({ level: 'workspace', workspaceId: 'ws-prod' }, 'grp-read-write')
    const stop = autoRespond('approved')
    const c = await clientFor('grp-read-write')
    try {
      const out = await call(c, {
        name: 'Staging Web',
        host: '10.0.0.5',
        port: 2222,
        username: 'deploy',
        auth: 'password',
        password: PASSWORD
      })
      expect(out).toContain('Added "Staging Web" to Production')
      expect(received).toHaveLength(1)
      expect(received[0]).toMatchObject({
        workspaceId: 'ws-prod',
        name: 'Staging Web',
        host: '10.0.0.5',
        port: 2222,
        username: 'deploy',
        auth: 'password',
        password: PASSWORD
      })
    } finally {
      stop()
      await c.close()
    }
  })

  it('creates nothing when the user rejects the approval', async () => {
    setAssignment({ level: 'workspace', workspaceId: 'ws-prod' }, 'grp-read-write')
    const stop = autoRespond('denied')
    const c = await clientFor('grp-read-write')
    try {
      expect(await call(c, { name: 'Rejected Box', host: '10.0.0.6' })).toContain('rejected')
      expect(received).toHaveLength(0)
    } finally {
      stop()
      await c.close()
    }
  })

  it('never writes the supplied credential into the audit log', async () => {
    setAssignment({ level: 'workspace', workspaceId: 'ws-prod' }, 'grp-read-write')
    const stop = autoRespond('approved')
    const c = await clientFor('grp-read-write')
    try {
      await call(c, {
        name: 'Audit Check',
        host: '10.0.0.7',
        auth: 'password',
        password: PASSWORD
      })
      const serialised = JSON.stringify(listAudit())
      expect(serialised).toContain('Audit Check')
      expect(serialised).not.toContain(PASSWORD)
    } finally {
      stop()
      await c.close()
    }
  })

  it('refuses a name that already exists, which would shadow the real server', async () => {
    setAssignment({ level: 'workspace', workspaceId: 'ws-prod' }, 'grp-read-write')
    const stop = autoRespond('approved')
    const c = await clientFor('grp-read-write')
    try {
      // Case-insensitive: every other tool resolves servers by name.
      expect(await call(c, { name: 'existing box', host: '10.0.0.8' })).toContain('already exists')
      expect(received).toHaveLength(0)
    } finally {
      stop()
      await c.close()
    }
  })

  it('rejects an auth method with no matching credential', async () => {
    setAssignment({ level: 'workspace', workspaceId: 'ws-prod' }, 'grp-read-write')
    const c = await clientFor('grp-read-write')
    try {
      expect(await call(c, { name: 'No Cred', host: '10.0.0.9', auth: 'password' })).toContain('requires a password')
      expect(await call(c, { name: 'No Cred', host: '10.0.0.9', auth: 'key' })).toContain('requires keyPath')
      expect(received).toHaveLength(0)
    } finally {
      await c.close()
    }
  })

  it('names the session ceiling, not just the group, when that is what refused', async () => {
    // The loop this exists to break: the workspace allows it, the session does
    // not, and the message said only "Read Only: manageServers = deny" — which
    // reads as a settings problem, so you change the setting, retry, and get
    // the identical message back.
    setAssignment({ level: 'workspace', workspaceId: 'ws-prod' }, 'grp-full')
    const c = await clientFor('grp-read-only')
    try {
      const out = await call(c, { name: 'Ceiling Test', host: '10.0.0.11' })
      expect(out).toContain("this AI session's own ceiling")
      expect(out).toContain('Active Sessions')
      expect(out).toContain('Full Access')
      expect(received).toHaveLength(0)
    } finally {
      await c.close()
    }
  })

  it('does not claim a session ceiling when the workspace is what refused', async () => {
    setAssignment({ level: 'workspace', workspaceId: 'ws-prod' }, 'grp-read-only')
    const c = await clientFor('grp-full')
    try {
      const out = await call(c, { name: 'Workspace Test', host: '10.0.0.12' })
      expect(out).toContain('Denied')
      expect(out).not.toContain("this AI session's own ceiling")
    } finally {
      await c.close()
    }
  })

  it('reports a renderer-side failure instead of claiming success', async () => {
    setAssignment({ level: 'workspace', workspaceId: 'ws-prod' }, 'grp-read-write')
    creatorResult = { ok: false, error: 'OS secure storage is unavailable' }
    const stop = autoRespond('approved')
    const c = await clientFor('grp-read-write')
    try {
      const out = await call(c, { name: 'Doomed', host: '10.0.0.10', auth: 'agent' })
      expect(out).toContain('Could not add the server')
      expect(out).toContain('OS secure storage is unavailable')
    } finally {
      stop()
      await c.close()
    }
  })
})
