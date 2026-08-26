import { describe, it, expect, beforeAll, afterAll } from 'vitest'
import { Client } from '@modelcontextprotocol/sdk/client/index.js'
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js'
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js'
import { mkdtempSync, rmSync, readFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import { refreshMcpDataCache, listCachedWorkspaces } from '../src/main/services/mcpDataCache'
import { setAssignment, listAssignments, listGroups, resetPolicyCacheForTests } from '../src/main/services/policyStore'
import { setMcpConfig, createSession, resetMcpAuthForTests } from '../src/main/services/mcpAuth'
import { startMcpServer, stopMcpServer } from '../src/main/services/mcpServer'
import { writeClaudeDesktopConfigTo, writeCodexConfigTo, claudeCodeCommand } from '../src/main/services/clientConfig'

// Exercises exactly what the "Connect Claude Code" / "Connect Claude Desktop"
// buttons do, end to end: gap-fill the workspace assignments, mint a session,
// then reach ShellPilot with the credential each button hands out. Clicking the
// buttons proves a session was created; only this proves the agent on the other
// end can actually see a server, which is the part that silently fails.
const PORT = 58734

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
    }
  ]
}

let dir: string

beforeAll(async () => {
  dir = mkdtempSync(join(tmpdir(), 'shellpilot-connect-'))
  resetPolicyCacheForTests()
  resetMcpAuthForTests()
  refreshMcpDataCache(sampleData)
  setMcpConfig({ enabled: true, port: PORT })
  await startMcpServer()
})

afterAll(async () => {
  await stopMcpServer()
  rmSync(dir, { recursive: true, force: true })
})

// The renderer's connect() loop, extracted so the test drives the same rules the
// button does rather than a paraphrase of them.
function fillAssignmentGaps(groupId: string | null): void {
  const assigned = new Set(
    listAssignments()
      .filter((a) => a.scope.level === 'workspace')
      .map((a) => (a.scope as { workspaceId: string }).workspaceId)
  )
  for (const w of listCachedWorkspaces()) {
    if (!assigned.has(w.id)) setAssignment({ level: 'workspace', workspaceId: w.id }, groupId)
  }
}

function newSession(agentName: string, groupId: string | null, groupName: string): string {
  const { token } = createSession({
    agentName,
    workspaces: listCachedWorkspaces().map((w) => ({ id: w.id, name: w.name })),
    groupId,
    groupName,
    ttlMinutes: null
  })
  return token
}

async function httpClient(token: string): Promise<Client> {
  const transport = new StreamableHTTPClientTransport(new URL(`http://127.0.0.1:${PORT}/mcp`), {
    requestInit: { headers: { Authorization: `Bearer ${token}` } }
  })
  const client = new Client({ name: 'connect-test', version: '1.0.0' })
  await client.connect(transport)
  return client
}

async function callText(client: Client, name: string): Promise<string> {
  const res = (await client.callTool({ name, arguments: {} })) as { content: { type: string; text: string }[] }
  return res.content.map((c) => c.text).join('\n')
}

describe('connect flow', () => {
  it('a session created without any assignment cannot see a server', async () => {
    // The pre-button state: policy seeded, assignments empty. This is the
    // failure the Connect buttons exist to prevent — the agent connects fine
    // and then sees nothing.
    expect(listAssignments()).toHaveLength(0)
    const token = newSession('Unassigned', 'grp-read-only', 'Read Only')
    const client = await httpClient(token)
    try {
      expect(await callText(client, 'list_servers')).not.toContain('Nginx Server Prod')
    } finally {
      await client.close()
    }
  })

  it('fills the assignment gaps and the agent then sees the server', async () => {
    const readOnly = listGroups().find((g) => g.id === 'grp-read-only')!
    fillAssignmentGaps(readOnly.id)

    expect(listAssignments().map((a) => a.groupId)).toEqual([readOnly.id, readOnly.id])

    const token = newSession('Claude Code', readOnly.id, readOnly.name)
    const client = await httpClient(token)
    try {
      expect(await callText(client, 'list_servers')).toContain('Nginx Server Prod')
      expect(await callText(client, 'list_workspaces')).toContain('Production')
    } finally {
      await client.close()
    }
  })

  it('never overwrites a workspace the user has already assigned', () => {
    // A workspace deliberately set to No AI Access must stay that way.
    setAssignment({ level: 'workspace', workspaceId: 'ws-dev' }, null)
    fillAssignmentGaps('grp-full')
    const dev = listAssignments().find(
      (a) => a.scope.level === 'workspace' && (a.scope as { workspaceId: string }).workspaceId === 'ws-dev'
    )
    expect(dev?.groupId).toBeNull()
  })

  it('the Claude Code command carries a token that actually authenticates', async () => {
    const token = newSession('Claude Code', 'grp-read-only', 'Read Only')
    const command = claudeCodeCommand(token, PORT)

    // Pull the token back out of the generated command line, so a quoting or
    // ordering mistake in the string shows up as an auth failure here.
    const bearer = /--header "Authorization: Bearer ([^"]+)"/.exec(command)?.[1]
    expect(bearer).toBe(token)
    const url = /(http:\/\/127\.0\.0\.1:\d+\/mcp)/.exec(command)?.[1]
    expect(url).toBe(`http://127.0.0.1:${PORT}/mcp`)

    const client = await httpClient(bearer!)
    try {
      expect(await callText(client, 'list_servers')).toContain('Nginx Server Prod')
    } finally {
      await client.close()
    }
  })

  it('the Codex config it writes is a usable MCP server', async () => {
    const file = join(dir, 'config.toml')
    const token = newSession('Codex', 'grp-read-only', 'Read Only')
    expect(writeCodexConfigTo(file, token, PORT).ok).toBe(true)

    // Parsed back out of the TOML that was written, so a quoting or escaping
    // mistake in the block shows up here rather than in Codex.
    const toml = readFileSync(file, 'utf8')
    const command = JSON.parse(/^command = (".*")$/m.exec(toml)![1]) as string
    const args = JSON.parse(`[${/^args = \[(.*)\]$/m.exec(toml)![1]}]`) as string[]

    const transport = new StdioClientTransport({
      command,
      args,
      env: { ...(process.env as Record<string, string>), ELECTRON_RUN_AS_NODE: '1' }
    })
    const client = new Client({ name: 'codex-test', version: '1.0.0' })
    await client.connect(transport)
    try {
      expect(await callText(client, 'list_servers')).toContain('Nginx Server Prod')
    } finally {
      await client.close()
    }
  })

  it('the Claude Desktop config it writes is a usable MCP server', async () => {
    const file = join(dir, 'claude_desktop_config.json')
    const token = newSession('Claude Desktop', 'grp-read-only', 'Read Only')
    const result = writeClaudeDesktopConfigTo(file, token, PORT)
    expect(result.ok).toBe(true)

    // Spawn strictly from what was written to disk — nothing hardcoded — so
    // this fails if the entry Claude Desktop would read is wrong in any way.
    const entry = JSON.parse(readFileSync(file, 'utf8')).mcpServers.shellpilot as {
      command: string
      args: string[]
      env: Record<string, string>
    }
    const transport = new StdioClientTransport({
      command: entry.command,
      args: entry.args,
      env: { ...(process.env as Record<string, string>), ...entry.env }
    })
    const client = new Client({ name: 'desktop-test', version: '1.0.0' })
    await client.connect(transport)
    try {
      const { tools } = await client.listTools()
      expect(tools.map((t) => t.name)).toContain('list_servers')
      expect(await callText(client, 'list_servers')).toContain('Nginx Server Prod')
    } finally {
      await client.close()
    }
  })
})
