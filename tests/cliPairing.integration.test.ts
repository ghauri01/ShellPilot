import { describe, it, expect, beforeAll, afterAll } from 'vitest'
import { join } from 'node:path'
import { Client } from '@modelcontextprotocol/sdk/client/index.js'
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js'

import { refreshMcpDataCache } from '../src/main/services/mcpDataCache'
import { setAssignment, resetPolicyCacheForTests } from '../src/main/services/policyStore'
import { setMcpConfig, resetMcpAuthForTests } from '../src/main/services/mcpAuth'
import { startMcpServer, stopMcpServer } from '../src/main/services/mcpServer'
import { onCliPairingEvent, type CliPairingEvent } from '../src/main/services/cliPairing'

// Exercises the whole `shellpilot claude|codex|run` launcher path against the
// real HTTP server: /pair/start never leaks the code (only an in-process
// event, standing in for the app UI, does), /pair/confirm mints a real
// session, and the compiled CLI's `bridge` subcommand relays a genuine MCP
// client's traffic over stdio into that same authenticated HTTP endpoint.
const PORT = 58733

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

async function postJson(path: string, body: unknown): Promise<Record<string, unknown>> {
  const res = await fetch(`http://127.0.0.1:${PORT}${path}`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body)
  })
  return (await res.json()) as Record<string, unknown>
}

describe('CLI pairing (integration)', () => {
  beforeAll(async () => {
    resetMcpAuthForTests()
    resetPolicyCacheForTests()
    refreshMcpDataCache(sampleData)
    setAssignment({ level: 'workspace', workspaceId: 'ws-prod' }, 'grp-read-only')
    setMcpConfig({ enabled: true, port: PORT, approvalTimeoutSeconds: 5 })
    const result = await startMcpServer()
    expect(result.ok).toBe(true)
  })

  afterAll(async () => {
    await stopMcpServer()
  })

  it('/pair/start never returns the code — it only reaches an in-app event', async () => {
    const codes: string[] = []
    const off = onCliPairingEvent((e: CliPairingEvent) => {
      if (e.type === 'created') codes.push(e.request.code)
    })
    const start = await postJson('/pair/start', { agentName: 'Test CLI' })
    off()
    expect(start).not.toHaveProperty('code')
    expect(typeof start.pairingId).toBe('string')
    expect(codes).toHaveLength(1)
    expect(codes[0]).toMatch(/^\d{6}$/)
  })

  it('rejects the wrong code, then accepts the right one and hands back a working token', async () => {
    let code = ''
    const off = onCliPairingEvent((e: CliPairingEvent) => {
      if (e.type === 'created') code = e.request.code
    })
    const start = await postJson('/pair/start', { agentName: 'Test CLI' })
    off()
    const pairingId = start.pairingId as string

    const wrongCode = code === '000000' ? '111111' : '000000'
    const wrong = await postJson('/pair/confirm', { pairingId, code: wrongCode })
    expect(wrong.ok).toBe(false)

    const right = await postJson('/pair/confirm', { pairingId, code })
    expect(right.ok).toBe(true)
    expect(typeof right.token).toBe('string')
    expect(right.port).toBe(PORT)

    // The same code cannot be replayed.
    const replay = await postJson('/pair/confirm', { pairingId, code })
    expect(replay.ok).toBe(false)

    const client = await connectViaBridge(right.token as string)
    const { tools } = await client.listTools()
    expect(tools.map((t) => t.name)).toContain('list_workspaces')
    await client.close()
  })
})

async function connectViaBridge(token: string): Promise<Client> {
  const transport = new StdioClientTransport({
    command: process.execPath,
    args: [join(__dirname, '../out/cli/index.js'), 'bridge', '--token', token, '--port', String(PORT)]
  })
  const client = new Client({ name: 'bridge-test-client', version: '1.0.0' })
  await client.connect(transport)
  return client
}
