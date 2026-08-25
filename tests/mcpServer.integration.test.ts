import { describe, it, expect, beforeAll, afterAll } from 'vitest'
import { Client } from '@modelcontextprotocol/sdk/client/index.js'
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js'

import { refreshMcpDataCache } from '../src/main/services/mcpDataCache'
import { setAssignment, resetPolicyCacheForTests } from '../src/main/services/policyStore'
import { setMcpConfig, createSession, resetMcpAuthForTests } from '../src/main/services/mcpAuth'
import { startMcpServer, stopMcpServer } from '../src/main/services/mcpServer'

const PORT = 58732

const sampleData = {
  workspaces: [
    { id: 'ws-prod', name: 'Production' },
    { id: 'ws-dev', name: 'Development' }
  ],
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
    },
    {
      id: 's2',
      workspaceId: 'ws-dev',
      name: 'Dev Box',
      host: '10.0.1.1',
      port: 22,
      username: 'dev',
      auth: 'password',
      os: 'Linux',
      route: []
    }
  ]
}

async function connectedClient(token: string): Promise<Client> {
  const transport = new StreamableHTTPClientTransport(new URL(`http://127.0.0.1:${PORT}/mcp`), {
    requestInit: { headers: { Authorization: `Bearer ${token}` } }
  })
  const client = new Client({ name: 'test-client', version: '1.0.0' })
  await client.connect(transport)
  return client
}

describe('MCP server (integration)', () => {
  let token: string
  let multiWorkspaceToken: string

  beforeAll(async () => {
    resetMcpAuthForTests()
    resetPolicyCacheForTests()
    refreshMcpDataCache(sampleData)
    // Production and Development both default to Read Only for AI.
    setAssignment({ level: 'workspace', workspaceId: 'ws-prod' }, 'grp-read-only')
    setAssignment({ level: 'workspace', workspaceId: 'ws-dev' }, 'grp-read-only')
    setMcpConfig({ enabled: true, port: PORT, approvalTimeoutSeconds: 5 })
    const created = createSession({
      agentName: 'Test Agent',
      workspaces: [{ id: 'ws-prod', name: 'Production' }],
      groupId: 'grp-read-only',
      groupName: 'Read Only',
      ttlMinutes: 60
    })
    token = created.token
    const createdMulti = createSession({
      agentName: 'Multi-workspace Agent',
      workspaces: [
        { id: 'ws-prod', name: 'Production' },
        { id: 'ws-dev', name: 'Development' }
      ],
      groupId: 'grp-read-only',
      groupName: 'Read Only',
      ttlMinutes: 60
    })
    multiWorkspaceToken = createdMulti.token
    const result = await startMcpServer()
    expect(result.ok).toBe(true)
  })

  afterAll(async () => {
    await stopMcpServer()
  })

  it('a valid MCP client can connect and discover tools with friendly names', async () => {
    const client = await connectedClient(token)
    const { tools } = await client.listTools()
    const names = tools.map((t) => t.name)
    expect(names).toEqual(
      expect.arrayContaining([
        'list_workspaces',
        'list_servers',
        'get_server_details',
        'execute_command',
        'read_file',
        'write_file',
        'list_files',
        'get_server_metrics'
      ])
    )
    await client.close()
  })

  it('list_servers returns the friendly name, never raw connection details', async () => {
    const client = await connectedClient(token)
    const result = await client.callTool({ name: 'list_servers', arguments: {} })
    const text = (result.content as { type: string; text: string }[])[0].text
    expect(text).toContain('Nginx Server Prod')
    expect(text).not.toContain('10.0.0.1')
    await client.close()
  })

  it('rejects a request with no/invalid bearer token', async () => {
    const client = await connectedClient('not-a-real-token')
    const result = await client.callTool({ name: 'list_workspaces', arguments: {} })
    expect(result.isError).toBe(true)
    const text = (result.content as { type: string; text: string }[])[0].text
    expect(text.toLowerCase()).toContain('not recognized')
    await client.close()
  })

  it('a Read Only session is denied writing a file without ever reaching SSH', async () => {
    const client = await connectedClient(token)
    const result = await client.callTool({
      name: 'write_file',
      arguments: { serverName: 'Nginx Server Prod', path: '/etc/nginx/nginx.conf', content: 'x' }
    })
    expect(result.isError).toBe(true)
    const text = (result.content as { type: string; text: string }[])[0].text
    expect(text).toContain('Denied')
    await client.close()
  })

  it('an unknown server name is reported, not guessed at', async () => {
    const client = await connectedClient(token)
    const result = await client.callTool({
      name: 'get_server_details',
      arguments: { serverName: 'totally-unknown-host' }
    })
    expect(result.isError).toBe(true)
    await client.close()
  })

  it('a single-workspace session cannot see a server outside its grant', async () => {
    const client = await connectedClient(token)
    const list = await client.callTool({ name: 'list_servers', arguments: {} })
    const listText = (list.content as { type: string; text: string }[])[0].text
    expect(listText).not.toContain('Dev Box')

    const details = await client.callTool({ name: 'get_server_details', arguments: { serverName: 'Dev Box' } })
    expect(details.isError).toBe(true)
    await client.close()
  })

  it('a multi-workspace session sees servers from every workspace it was granted', async () => {
    const client = await connectedClient(multiWorkspaceToken)
    const list = await client.callTool({ name: 'list_servers', arguments: {} })
    const listText = (list.content as { type: string; text: string }[])[0].text
    expect(listText).toContain('Nginx Server Prod')
    expect(listText).toContain('Dev Box')

    const workspaces = await client.callTool({ name: 'list_workspaces', arguments: {} })
    const workspacesText = (workspaces.content as { type: string; text: string }[])[0].text
    expect(workspacesText).toContain('Production')
    expect(workspacesText).toContain('Development')

    const details = await client.callTool({ name: 'get_server_details', arguments: { serverName: 'Dev Box' } })
    const detailsText = (details.content as { type: string; text: string }[])[0].text
    expect(detailsText).toContain('Workspace: Development')
    await client.close()
  })
})
