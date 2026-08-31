import { describe, it, expect, beforeAll, afterAll } from 'vitest'
import { Client } from '@modelcontextprotocol/sdk/client/index.js'
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js'

import { refreshMcpDataCache } from '../src/main/services/mcpDataCache'
import { setAssignment, resetPolicyCacheForTests } from '../src/main/services/policyStore'
import { setMcpConfig, createSession, resetMcpAuthForTests } from '../src/main/services/mcpAuth'
import { startMcpServer, stopMcpServer } from '../src/main/services/mcpServer'

// What an agent actually sees. Everything asserted here is metadata the model
// reads before deciding which tool to call, so it is worth pinning: a tool that
// silently loses its annotations looks safe-and-unremarkable to a client.
const PORT = 58736

let client: Client
let tools: Awaited<ReturnType<Client['listTools']>>['tools']

beforeAll(async () => {
  resetPolicyCacheForTests()
  resetMcpAuthForTests()
  refreshMcpDataCache({ workspaces: [{ id: 'ws', name: 'W' }], servers: [] })
  setAssignment({ level: 'workspace', workspaceId: 'ws' }, 'grp-full')
  setMcpConfig({ enabled: true, port: PORT })
  await startMcpServer()

  const { token } = createSession({
    agentName: 'Meta Test',
    workspaces: [{ id: 'ws', name: 'W' }],
    groupId: 'grp-full',
    groupName: 'Full Access',
    ttlMinutes: null
  })
  const transport = new StreamableHTTPClientTransport(new URL(`http://127.0.0.1:${PORT}/mcp`), {
    requestInit: { headers: { Authorization: `Bearer ${token}` } }
  })
  client = new Client({ name: 'meta-test', version: '1.0.0' })
  await client.connect(transport)
  tools = (await client.listTools()).tools
})

afterAll(async () => {
  await client?.close()
  await stopMcpServer()
})

const byName = (n: string): (typeof tools)[number] => {
  const t = tools.find((x) => x.name === n)
  if (!t) throw new Error(`tool ${n} not registered`)
  return t
}

describe('server instructions', () => {
  it('reach the client on initialize', () => {
    const instructions = client.getInstructions()
    expect(instructions).toBeTruthy()
    // The three things an agent cannot infer from tool descriptions alone.
    expect(instructions).toContain('list_servers first')
    expect(instructions).toContain('FRIENDLY NAME')
    expect(instructions).toMatch(/never see hostnames/i)
  })

  it('name the unsupported areas so the agent does not shell out to reach them', () => {
    const instructions = client.getInstructions() ?? ''
    for (const missing of ['tunnels', 'port forwarding', 'database']) {
      expect(instructions.toLowerCase()).toContain(missing)
    }
  })
})

describe('tool metadata', () => {
  it('gives every tool a human title', () => {
    const untitled = tools.filter((t) => !t.annotations?.title && !(t as { title?: string }).title)
    expect(untitled.map((t) => t.name)).toEqual([])
  })

  it('documents every single input parameter', () => {
    const undocumented: string[] = []
    for (const t of tools) {
      const props = (t.inputSchema?.properties ?? {}) as Record<string, { description?: string }>
      for (const [param, schema] of Object.entries(props)) {
        if (!schema.description) undocumented.push(`${t.name}.${param}`)
      }
    }
    expect(undocumented).toEqual([])
  })

  it('marks the read-only tools read-only', () => {
    for (const n of ['list_workspaces', 'list_servers', 'get_server_details', 'read_file', 'list_files', 'get_server_metrics', 'list_vpns']) {
      expect(byName(n).annotations?.readOnlyHint, n).toBe(true)
    }
  })

  it('marks the mutating tools as not read-only', () => {
    for (const n of ['execute_command', 'write_file', 'add_server', 'set_vpn']) {
      expect(byName(n).annotations?.readOnlyHint, n).toBe(false)
    }
    expect(byName('execute_command').annotations?.destructiveHint).toBe(true)
    expect(byName('write_file').annotations?.destructiveHint).toBe(true)
  })

  it('claims an open world only for the tools that reach outside ShellPilot', () => {
    // A shell command and a database statement both act on a system whose
    // contents ShellPilot does not model; everything else operates on things
    // it already knows about. A new tool appearing here should be a decision,
    // not a default — hence the exact list.
    const open = tools.filter((t) => t.annotations?.openWorldHint).map((t) => t.name).sort()
    expect(open).toEqual(['execute_command', 'query_database'])
  })

  it('does not let a tunnel tool claim an open world', () => {
    // set_tunnel can only run a tunnel the user already defined, so its effects
    // are fully described by ShellPilot's own configuration.
    expect(byName('set_tunnel').annotations?.openWorldHint).toBeFalsy()
  })

  it('does not let a VPN tool claim an open world either', () => {
    // Same reasoning: set_vpn can only run a profile that already exists.
    expect(byName('set_vpn').annotations?.openWorldHint).toBeFalsy()
    expect(byName('list_vpns').annotations?.openWorldHint).toBeFalsy()
  })

  it('registers no tool that could create or edit a VPN profile', () => {
    // Not an oversight to be filled in later. A profile decides where the
    // user's traffic goes, and there is no version of an agent authoring one
    // that is safe, so the absence is asserted rather than assumed.
    const vpnTools = tools.map((t) => t.name).filter((n) => n.includes('vpn'))
    expect(vpnTools.sort()).toEqual(['list_vpns', 'set_vpn'])
  })

  it('makes set_vpn state what it cannot do', () => {
    const d = byName('set_vpn').description ?? ''
    // The exact promise set_tunnel makes, in the same words.
    expect(d).toContain('only run one the user has already defined')
    expect(d).toMatch(/cannot create a VPN profile or change where one points/i)
    // And the one refusal an agent must not waste a call discovering.
    expect(d).toMatch(/frp/i)
    expect(d).toMatch(/no access group can permit them|refused outright/i)
  })

  it('tells set_vpn that starting always needs approval', () => {
    expect(byName('set_vpn').description ?? '').toMatch(/always requires user approval/i)
  })

  it('says list_vpns will not disclose where a VPN points', () => {
    const d = byName('list_vpns').description ?? ''
    expect(d).toMatch(/endpoints, keys and listener addresses are never included/i)
  })

  it('points every vpnName parameter at list_vpns', () => {
    const withVpnName = tools.filter((t) => 'vpnName' in ((t.inputSchema?.properties ?? {}) as object))
    expect(withVpnName.length).toBe(1)
    for (const t of withVpnName) {
      const props = t.inputSchema.properties as Record<string, { description?: string }>
      expect(props.vpnName.description, t.name).toContain('list_vpns')
    }
  })

  it('steers the shell tool towards its alternatives', () => {
    const d = byName('execute_command').description ?? ''
    for (const alt of ['read_file', 'list_files', 'write_file', 'get_server_metrics']) {
      expect(d, alt).toContain(alt)
    }
  })

  it('tells the specialised tools to say why they are preferable', () => {
    for (const n of ['read_file', 'list_files', 'get_server_metrics']) {
      expect(byName(n).description ?? '', n).toMatch(/prefer this over/i)
    }
  })

  it('points every serverName parameter at list_servers', () => {
    const withServerName = tools.filter((t) => 'serverName' in ((t.inputSchema?.properties ?? {}) as object))
    expect(withServerName.length).toBeGreaterThanOrEqual(6)
    for (const t of withServerName) {
      const props = t.inputSchema.properties as Record<string, { description?: string }>
      expect(props.serverName.description, t.name).toContain('list_servers')
    }
  })
})
