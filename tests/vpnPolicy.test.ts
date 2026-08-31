import { describe, it, expect, beforeEach, beforeAll, afterAll } from 'vitest'
import { Client } from '@modelcontextprotocol/sdk/client/index.js'
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js'
import {
  listGroups,
  saveGroup,
  setAssignment,
  resetPolicyCacheForTests
} from '../src/main/services/policyStore'
import { evaluateVpnControl, isVpnKindRefusedForAi } from '../src/main/services/policyEngine'
import { refreshMcpDataCache } from '../src/main/services/mcpDataCache'
import { setMcpConfig, createSession, resetMcpAuthForTests } from '../src/main/services/mcpAuth'
import { startMcpServer, stopMcpServer } from '../src/main/services/mcpServer'
import { registerVpnManager, resetVpnManagerForTests } from '../src/main/services/vpn/managerApi'
import type { AccessGroup, PermissionValue } from '../src/shared/mcp'
import type { VpnKind } from '../src/shared/vpn'

let readOnly: AccessGroup
let readWrite: AccessGroup
let sudo: AccessGroup
let full: AccessGroup

beforeEach(() => {
  resetPolicyCacheForTests()
  readOnly = listGroups().find((g) => g.id === 'grp-read-only')!
  readWrite = listGroups().find((g) => g.id === 'grp-read-write')!
  sudo = listGroups().find((g) => g.id === 'grp-sudo')!
  full = listGroups().find((g) => g.id === 'grp-full')!
})

const withVpnControl = (g: AccessGroup, value: PermissionValue): AccessGroup => ({
  ...g,
  capabilities: { ...g.capabilities, vpnControl: value }
})

describe('vpnControl on the seeded groups', () => {
  it('denies Read Only and asks on the other three — no group allows outright', () => {
    expect(readOnly.capabilities.vpnControl).toBe('deny')
    expect(readWrite.capabilities.vpnControl).toBe('ask')
    expect(sudo.capabilities.vpnControl).toBe('ask')
    expect(full.capabilities.vpnControl).toBe('ask')
  })
})

describe('every group, action and dependent state', () => {
  // The whole matrix, written out rather than derived, so a change to any one
  // cell has to be made deliberately.
  interface Case {
    label: string
    group: () => AccessGroup
    action: 'start' | 'stop'
    live: boolean
    expect: PermissionValue
  }

  const cases: Case[] = [
    { label: 'Read Only', group: () => readOnly, action: 'start', live: false, expect: 'deny' },
    { label: 'Read Only', group: () => readOnly, action: 'start', live: true, expect: 'deny' },
    { label: 'Read Only', group: () => readOnly, action: 'stop', live: false, expect: 'deny' },
    { label: 'Read Only', group: () => readOnly, action: 'stop', live: true, expect: 'deny' },

    { label: 'Read & Write', group: () => readWrite, action: 'start', live: false, expect: 'ask' },
    { label: 'Read & Write', group: () => readWrite, action: 'start', live: true, expect: 'ask' },
    { label: 'Read & Write', group: () => readWrite, action: 'stop', live: false, expect: 'ask' },
    { label: 'Read & Write', group: () => readWrite, action: 'stop', live: true, expect: 'ask' },

    { label: 'Sudo Access', group: () => sudo, action: 'start', live: false, expect: 'ask' },
    { label: 'Sudo Access', group: () => sudo, action: 'start', live: true, expect: 'ask' },
    { label: 'Sudo Access', group: () => sudo, action: 'stop', live: false, expect: 'ask' },
    { label: 'Sudo Access', group: () => sudo, action: 'stop', live: true, expect: 'ask' },

    { label: 'Full Access', group: () => full, action: 'start', live: false, expect: 'ask' },
    { label: 'Full Access', group: () => full, action: 'start', live: true, expect: 'ask' },
    { label: 'Full Access', group: () => full, action: 'stop', live: false, expect: 'ask' },
    { label: 'Full Access', group: () => full, action: 'stop', live: true, expect: 'ask' },

    // A group the user has explicitly raised to ALLOW. Starting is still ASK;
    // only a stop with nothing live behind it runs silently.
    { label: 'raised to ALLOW', group: () => withVpnControl(full, 'allow'), action: 'start', live: false, expect: 'ask' },
    { label: 'raised to ALLOW', group: () => withVpnControl(full, 'allow'), action: 'start', live: true, expect: 'ask' },
    { label: 'raised to ALLOW', group: () => withVpnControl(full, 'allow'), action: 'stop', live: false, expect: 'allow' },
    { label: 'raised to ALLOW', group: () => withVpnControl(full, 'allow'), action: 'stop', live: true, expect: 'ask' },

    // An explicit DENY beats everything else the group says.
    { label: 'lowered to DENY', group: () => withVpnControl(full, 'deny'), action: 'start', live: false, expect: 'deny' },
    { label: 'lowered to DENY', group: () => withVpnControl(full, 'deny'), action: 'stop', live: false, expect: 'deny' },
    { label: 'lowered to DENY', group: () => withVpnControl(full, 'deny'), action: 'stop', live: true, expect: 'deny' }
  ]

  for (const c of cases) {
    it(`${c.label}: ${c.action} with ${c.live ? 'live' : 'no'} dependents resolves to ${c.expect}`, () => {
      expect(evaluateVpnControl(c.group(), c.action, c.live).decision).toBe(c.expect)
    })
  }

  it('denies every combination when no group is assigned at all', () => {
    for (const action of ['start', 'stop'] as const) {
      for (const live of [false, true]) {
        expect(evaluateVpnControl(null, action, live).decision, `${action}/${live}`).toBe('deny')
      }
    }
  })
})

describe('starting a VPN is never silent', () => {
  it('upgrades ALLOW to ASK on start, because a VPN moves the user\'s traffic', () => {
    const allowed = withVpnControl(full, 'allow')
    const start = evaluateVpnControl(allowed, 'start', false)
    expect(start.decision).toBe('ask')
    expect(start.reason).toMatch(/where your traffic goes/i)
    // The same group, stopping nothing live, is the one case that runs
    // silently — which is what proves the start rule is the clamp and not
    // just the capability showing through.
    expect(evaluateVpnControl(allowed, 'stop', false).decision).toBe('allow')
  })

  it('says why a stop with live dependents needs approval', () => {
    const stop = evaluateVpnControl(withVpnControl(full, 'allow'), 'stop', true)
    expect(stop.decision).toBe('ask')
    expect(stop.reason).toMatch(/close sessions that depend on it/i)
  })
})

describe('frp is refused in code, not by policy', () => {
  it('refuses frp and nothing else', () => {
    const kinds: VpnKind[] = ['wireguard', 'openvpn', 'frp']
    expect(kinds.filter(isVpnKindRefusedForAi)).toEqual(['frp'])
  })

  it('survives an access group set to ALLOW', () => {
    // The point of the whole rule: the most permissive group anyone can build
    // still cannot reach an frp profile, because the refusal is not a
    // permission value. The capability check itself says allow here.
    const allowed = withVpnControl(full, 'allow')
    expect(evaluateVpnControl(allowed, 'stop', false).decision).toBe('allow')
    expect(isVpnKindRefusedForAi('frp')).toBe(true)
  })

  it('is not reachable from any group value', () => {
    for (const value of ['allow', 'ask', 'deny'] as PermissionValue[]) {
      const group = withVpnControl(full, value)
      // Nothing about the group participates in the decision.
      expect(isVpnKindRefusedForAi('frp'), `${group.name}/${value}`).toBe(true)
    }
  })
})

// The unit tests above prove the rule; this proves the wiring. An frp refusal
// that lives only in a pure function nobody calls would pass every test in this
// file and still open a port.
describe('set_vpn against a live bridge', () => {
  const PORT = 58741
  let client: Client
  const started: string[] = []
  const stopped: string[] = []

  // The most permissive configuration anyone could build: Full Access with
  // vpnControl deliberately raised to ALLOW, which is not a value any seed
  // ships. If frp were a permission, this is what would unlock it. Re-applied
  // per test because the file-level beforeEach wipes the policy store.
  const permit = (): void => {
    const permissive = listGroups().find((g) => g.id === 'grp-full')!
    saveGroup({ ...permissive, capabilities: { ...permissive.capabilities, vpnControl: 'allow' } })
    setAssignment({ level: 'workspace', workspaceId: 'ws' }, 'grp-full')
  }

  beforeEach(permit)

  beforeAll(async () => {
    resetPolicyCacheForTests()
    resetMcpAuthForTests()
    resetVpnManagerForTests()
    permit()

    refreshMcpDataCache({
      workspaces: [{ id: 'ws', name: 'W' }],
      servers: [],
      vpns: [
        {
          id: 'vpn-wg',
          workspaceId: 'ws',
          name: 'office',
          autoStart: false,
          spec: { kind: 'wireguard', mode: 'userspace', listeners: [{}, {}] }
        },
        {
          id: 'vpn-frp',
          workspaceId: 'ws',
          name: 'expose-postgres',
          autoStart: false,
          spec: { kind: 'frp', proxies: [{}] }
        }
      ]
    })

    registerVpnManager({
      statusOf: () => null,
      dependentsOf: () => [],
      startVpn: async (id) => {
        started.push(id)
        return { ok: true, listeners: [] }
      },
      stopVpn: async (id) => {
        stopped.push(id)
        return { ok: true }
      }
    })

    setMcpConfig({ enabled: true, port: PORT, approvalTimeoutSeconds: 5 })
    await startMcpServer()
    const { token } = createSession({
      agentName: 'VPN Test',
      workspaces: [{ id: 'ws', name: 'W' }],
      groupId: 'grp-full',
      groupName: 'Full Access',
      ttlMinutes: null
    })
    const transport = new StreamableHTTPClientTransport(new URL(`http://127.0.0.1:${PORT}/mcp`), {
      requestInit: { headers: { Authorization: `Bearer ${token}` } }
    })
    client = new Client({ name: 'vpn-test', version: '1.0.0' })
    await client.connect(transport)
  })

  afterAll(async () => {
    await client?.close()
    await stopMcpServer()
    resetVpnManagerForTests()
  })

  const call = async (args: { vpnName: string; running: boolean }): Promise<string> => {
    const r = (await client.callTool({ name: 'set_vpn', arguments: args })) as {
      content: { text: string }[]
    }
    return r.content.map((c) => c.text).join('\n')
  }

  it('refuses to start an frp profile even with vpnControl set to ALLOW', async () => {
    const out = await call({ vpnName: 'expose-postgres', running: true })
    expect(out).toMatch(/^Denied:/)
    expect(out).toMatch(/reverse proxy \(frp\)/i)
    expect(out).toMatch(/not a permission that can be raised/i)
    expect(started).not.toContain('vpn-frp')
  })

  it('refuses to stop one too — an agent must not touch the exposure either way', async () => {
    const out = await call({ vpnName: 'expose-postgres', running: false })
    expect(out).toMatch(/^Denied:/)
    expect(stopped).not.toContain('vpn-frp')
  })

  it('still runs a WireGuard stop under the same ALLOW, so the refusal is about frp', async () => {
    const out = await call({ vpnName: 'office', running: false })
    expect(out).toContain('Stopped "office"')
    expect(stopped).toContain('vpn-wg')
  })

  it('lists VPNs without naming an endpoint, a key or a bind address', async () => {
    const r = (await client.callTool({ name: 'list_vpns', arguments: {} })) as { content: { text: string }[] }
    const out = r.content.map((c) => c.text).join('\n')
    expect(out).toContain('office')
    expect(out).toContain('expose-postgres')
    expect(out).toContain('wireguard, userspace, 2 listeners')
    expect(out).toContain('frp, 1 proxy')
    // Nothing resembling an address may appear.
    expect(out).not.toMatch(/\d+\.\d+\.\d+\.\d+|:\d{2,5}\b/)
  })
})
