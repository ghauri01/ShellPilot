import { describe, it, expect, beforeAll, afterAll } from 'vitest'
import { Client } from '@modelcontextprotocol/sdk/client/index.js'
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js'

import { refreshMcpDataCache } from '../src/main/services/mcpDataCache'
import { setAssignment, listGroups, saveGroup, resetPolicyCacheForTests } from '../src/main/services/policyStore'
import { setMcpConfig, createSession, resetMcpAuthForTests } from '../src/main/services/mcpAuth'
import { startMcpServer, stopMcpServer } from '../src/main/services/mcpServer'

// "SFTP download" and "SFTP upload" are switches in the access-group editor.
// They were never read by anything, so turning them off changed nothing — the
// worst kind of permission, because the user believes it took effect.
const PORT = 58737

const sampleData = {
  workspaces: [{ id: 'ws', name: 'W' }],
  servers: [
    { id: 's1', workspaceId: 'ws', name: 'Box', host: '10.0.0.1', port: 22, username: 'root', auth: 'key', os: 'Linux', route: [] }
  ]
}

beforeAll(async () => {
  resetPolicyCacheForTests()
  resetMcpAuthForTests()
  refreshMcpDataCache(sampleData)
  setAssignment({ level: 'workspace', workspaceId: 'ws' }, 'grp-full')
  setMcpConfig({ enabled: true, port: PORT })
  await startMcpServer()
})

afterAll(async () => await stopMcpServer())

async function connect(): Promise<Client> {
  const { token } = createSession({
    agentName: 'SFTP Cap Test',
    workspaces: [{ id: 'ws', name: 'W' }],
    groupId: 'grp-full',
    groupName: 'Full Access',
    ttlMinutes: null
  })
  const transport = new StreamableHTTPClientTransport(new URL(`http://127.0.0.1:${PORT}/mcp`), {
    requestInit: { headers: { Authorization: `Bearer ${token}` } }
  })
  const c = new Client({ name: 'sftp-cap', version: '1.0.0' })
  await c.connect(transport)
  return c
}

async function call(c: Client, name: string, args: Record<string, unknown>): Promise<string> {
  const r = (await c.callTool({ name, arguments: args })) as { content: { text: string }[] }
  return r.content.map((x) => x.text).join('\n')
}

function setCapability(capability: 'sftpDownload' | 'sftpUpload', value: 'allow' | 'deny'): void {
  const full = listGroups().find((g) => g.id === 'grp-full')!
  saveGroup({ ...full, capabilities: { ...full.capabilities, [capability]: value } })
}

describe('sftp transport capabilities are enforced', () => {
  it('denying sftpDownload blocks read_file and list_files', async () => {
    setCapability('sftpDownload', 'deny')
    const c = await connect()
    try {
      // Denied before any connection is attempted, so no SSH server is needed.
      expect(await call(c, 'read_file', { serverName: 'Box', path: '/tmp/x' })).toContain('Denied')
      expect(await call(c, 'list_files', { serverName: 'Box', path: '/tmp' })).toContain('Denied')
    } finally {
      setCapability('sftpDownload', 'allow')
      await c.close()
    }
  })

  it('denying sftpUpload blocks write_file', async () => {
    setCapability('sftpUpload', 'deny')
    const c = await connect()
    try {
      expect(await call(c, 'write_file', { serverName: 'Box', path: '/tmp/x', content: 'hi' })).toContain('Denied')
    } finally {
      setCapability('sftpUpload', 'allow')
      await c.close()
    }
  })

  it('denying sftpUpload does not also block reads', async () => {
    setCapability('sftpUpload', 'deny')
    const c = await connect()
    try {
      // Asserted through get_server_details rather than by calling read_file:
      // a read that policy allows goes on to open a real SFTP connection to a
      // host that does not exist, which fails fast on a developer machine and
      // hangs until the test timeout on a CI runner. The permission table is
      // the thing under test and it needs no transport.
      const details = await call(c, 'get_server_details', { serverName: 'Box' })
      expect(details).toContain('SFTP upload: DENY')
      expect(details).toContain('SFTP download: ALLOW')
      expect(details).toContain('Read files: ALLOW')
    } finally {
      setCapability('sftpUpload', 'allow')
      await c.close()
    }
  })
})
