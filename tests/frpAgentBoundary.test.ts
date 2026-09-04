import { describe, expect, it } from 'vitest'
import { existsSync, readFileSync, readdirSync, statSync } from 'node:fs'
import { dirname, join, relative, resolve } from 'node:path'
import ts from 'typescript'
import { isVpnKindRefusedForAi } from '../src/main/services/policyEngine'
import { AI_CAPABILITIES } from '../src/shared/mcp'
import type { VpnKind } from '../src/shared/vpn'

// ===========================================================================
// A ONE-CLICK PUBLISH IS EXACTLY WHAT AN AGENT MUST NOT HAVE
// ===========================================================================
//
// frp is refused to AI agents outright, and has been since it shipped: not
// gated, not asked-for, refused, with no value of `vpnControl` that changes the
// answer (tests/vpnPolicy.test.ts holds that end to end). The reason is in
// set_vpn's own description — an frp proxy makes a port on the USER'S OWN
// MACHINE reachable from the internet.
//
// Roadmap item 2 makes that easier to do. Easier is the entire feature and it
// is also the entire risk: the flow this session added turns "compose an frp
// proxy definition" into "type a number and press a button", and a capability
// is dangerous in proportion to how few steps it takes. So the boundary is
// re-asserted against the new surface rather than assumed to still hold,
// because the thing that would defeat it is not someone registering an
// `expose_port` tool. It is a shared helper.
//
// `src/shared/frpTunnel.ts` is in `src/shared`, which both sides import from
// freely. `frpPublishReadiness` and `buildPublishedProxy` are pure, cheap, and
// exactly what somebody wiring up a "list the user's public URLs" tool would
// reach for. Once that import exists the next diff is a tool that returns
// them, and the one after that is a tool that creates one.
//
// Three layers, the same three the job engine and the local terminal use:
//
//   1. Rule       — the refusal itself, still true for frp and only frp.
//   2. Static     — the transitive import closure of both agent-facing entry
//                   points, so none of this session's modules is reachable.
//   3. Vocabulary — the capability list, so the IDEA cannot be expressed in the
//                   permission model without this test failing first.
//
// If one of them failed: the failure is the feature. Do not weaken it.

const ROOT = resolve(__dirname, '..')

// ---------------------------------------------------------------------------
// 1. Rule
// ---------------------------------------------------------------------------

describe('frp is still refused to agents, whatever this item added', () => {
  it('refuses frp and nothing else', () => {
    const kinds: VpnKind[] = ['wireguard', 'openvpn', 'frp']
    expect(kinds.filter(isVpnKindRefusedForAi)).toEqual(['frp'])
  })

  it('set_vpn still tells the agent why, in words about the user’s machine', () => {
    const mcp = readFileSync(join(ROOT, 'src/main/services/mcpServer.ts'), 'utf8')
    expect(mcp).toContain(
      'Reverse proxies (frp) are refused outright here and no access group can permit them'
    )
  })
})

// ---------------------------------------------------------------------------
// 2. Static
// ---------------------------------------------------------------------------

const ALIASES: [RegExp, string][] = [[/^@\//, 'src/renderer/src/']]

function applyAlias(spec: string): string | null {
  for (const [rx, to] of ALIASES) if (rx.test(spec)) return join(ROOT, spec.replace(rx, to))
  return null
}

function isLocalSpecifier(spec: string): boolean {
  return spec.startsWith('.') || ALIASES.some(([rx]) => rx.test(spec))
}

function tsFilesIn(dir: string): string[] {
  if (!existsSync(dir)) return []
  const out: string[] = []
  for (const entry of readdirSync(dir)) {
    const full = join(dir, entry)
    if (statSync(full).isDirectory()) out.push(...tsFilesIn(full))
    else if (/\.tsx?$/.test(entry)) out.push(full)
  }
  return out
}

function resolveSpecifier(fromFile: string, spec: string): string | null {
  const aliased = applyAlias(spec)
  if (aliased === null && !spec.startsWith('.')) return null
  const literal = aliased ?? join(dirname(fromFile), spec)
  const stripped = literal.replace(/\.[cm]?js$/i, '')
  const candidates = [
    literal,
    `${literal}.ts`,
    `${literal}.tsx`,
    `${stripped}.ts`,
    `${stripped}.tsx`,
    join(literal, 'index.ts'),
    join(literal, 'index.tsx'),
    join(stripped, 'index.ts')
  ]
  for (const candidate of candidates) {
    if (existsSync(candidate) && statSync(candidate).isFile()) return candidate
  }
  return null
}

interface ImportEdge {
  from: string
  spec: string
  to: string | null
}

function importClosure(seeds: string[]): { files: Set<string>; edges: ImportEdge[] } {
  const files = new Set<string>()
  const edges: ImportEdge[] = []
  const queue = [...seeds]
  while (queue.length > 0) {
    const file = queue.pop() as string
    if (files.has(file)) continue
    files.add(file)
    if (!/\.tsx?$/.test(file) || !existsSync(file)) continue
    const source = readFileSync(file, 'utf8')
    // The second and third arguments are what pick up `require()` and
    // `import()`. A regex over `from` clauses would miss `await import('./x')`.
    for (const ref of ts.preProcessFile(source, true, true).importedFiles) {
      const to = resolveSpecifier(file, ref.fileName)
      edges.push({ from: file, spec: ref.fileName, to })
      if (to !== null && !files.has(to)) queue.push(to)
    }
  }
  return { files, edges }
}

const SEED_FILES = [
  join(ROOT, 'src/main/services/mcpServer.ts'),
  ...tsFilesIn(join(ROOT, 'src/cli'))
]

/** Everything roadmap item 2 added, by path. Listed rather than pattern-matched
 *  because the point is that THESE files are unreachable, and a pattern that
 *  quietly stopped matching one of them would take the assertion with it. */
const ITEM_2_MODULES = [
  'src/shared/frpTunnel.ts',
  'src/main/services/vpn/frpSetup.ts',
  'src/renderer/src/components/vpn/FrpPublishDialog.tsx',
  'src/renderer/src/components/vpn/FrpTunnelSetup.tsx',
  'src/renderer/src/components/vpn/FrpManager.tsx'
]

describe('nothing an agent can reach imports the publish flow', () => {
  const { files, edges } = importClosure(SEED_FILES)
  const relFiles = new Set([...files].map((f) => relative(ROOT, f).split('\\').join('/')))

  it('walked a real closure, not an empty one', () => {
    // The guard on the guard. If the walker breaks, the closure collapses and
    // the assertions below pass for the wrong reason.
    const missing = [
      'src/main/services/mcpServer.ts',
      'src/main/services/policyEngine.ts',
      'src/shared/mcp.ts',
      'src/shared/vpn.ts',
      'src/cli/bridge.ts'
    ].filter((f) => !relFiles.has(f))
    expect(
      missing,
      `The import walker did not reach modules that are definitely reachable from the MCP server ` +
        `or the CLI. The closure is broken, so the assertions below are meaningless.\n  ${missing.join('\n  ')}`
    ).toEqual([])
  })

  it('followed every local import it found', () => {
    const unresolved = edges
      .filter((e) => e.to === null && isLocalSpecifier(e.spec))
      .map((e) => `${relative(ROOT, e.from)} -> '${e.spec}'`)
    expect(
      unresolved,
      `A specifier the walker cannot resolve is one the assertion below silently skips.\n  ` +
        `${unresolved.join('\n  ')}`
    ).toEqual([])
  })

  it('has none of the tunnel-publishing modules in the closure', () => {
    const reachable = ITEM_2_MODULES.filter((m) => relFiles.has(m))
    expect(
      reachable,
      `These modules are now reachable from the MCP bridge or the ShellPilot CLI:\n  ` +
        `${reachable.join('\n  ')}\n\n` +
        `frp is refused to agents outright because an frp proxy makes a port on the USER'S OWN ` +
        `machine reachable from the internet. The one-click flow does not change that judgement; ` +
        `it makes it more load-bearing, because the whole feature is that publishing now takes ` +
        `one step instead of ten.\n\n` +
        `The realistic breach is not a new tool. It is somebody importing frpTunnel.ts for its ` +
        `pure helpers - to LIST the user's public URLs, which sounds harmless - and the next diff ` +
        `being a tool that creates one. If a helper genuinely needs to be shared, move the helper, ` +
        `not this assertion.`
    ).toEqual([])
  })

  it('names none of the publish vocabulary in the MCP server', () => {
    // The cheap layer, from dockerOps.test.ts. It cannot be fooled by an alias
    // and it fails in the diff rather than at runtime.
    const mcp = readFileSync(join(ROOT, 'src/main/services/mcpServer.ts'), 'utf8')
    for (const forbidden of [
      'frpPublishReadiness',
      'buildPublishedProxy',
      'publicUrl',
      'publishLabel',
      'describeExposure',
      'publicHostFrom',
      'storeFrpToken',
      'vpn:frpToken',
      'FrpPublicHost'
    ]) {
      expect(mcp.includes(forbidden), `mcpServer.ts names "${forbidden}"`).toBe(false)
    }
  })
})

// ---------------------------------------------------------------------------
// 3. Vocabulary
// ---------------------------------------------------------------------------

describe('the AI permission model has no word for publishing a port', () => {
  it('names reverse proxies in exactly one capability, the one that refuses them', () => {
    expect(AI_CAPABILITIES.length, 'AI_CAPABILITIES is empty — nothing was checked').toBeGreaterThan(
      0
    )
    const rx = /publish|expose|exposure|ingress|reverse.?prox|frp|public.?url/i
    const named = AI_CAPABILITIES.filter((c) => rx.test(c.id) || rx.test(c.label)).map((c) => c.id)
    // `vpnControl` is labelled "VPN & reverse proxies" because it is the
    // setting an operator looks for when they wonder about frp — and the
    // answer it gives them is no. Any SECOND capability matching these words
    // is a new grant, and the natural next step for someone implementing "let
    // the agent put the dev server on the internet".
    expect(
      named,
      `A capability that names publishing has appeared: ${named.join(', ')}. This is where that ` +
        `conversation has to happen rather than in a diff. There is no value of such a ` +
        `capability — not even ASK — that is safe: the approval is for one port, and what it ` +
        `leaves behind is an open door with a name anyone can resolve.`
    ).toEqual(['vpnControl'])
  })

  it('does not offer a power the code refuses', () => {
    // The sentence beside the toggle in Settings. It used to end "and starts or
    // stops them", which reads as a promise that turning this on lets an agent
    // start a reverse proxy. It never has, at any value.
    const vpn = AI_CAPABILITIES.find((c) => c.id === 'vpnControl')
    expect(vpn?.detail).toBe(
      'Lists VPN profiles and reverse proxies, and starts or stops the VPNs. Reverse proxies ' +
        'are never started or stopped by an agent, at any setting.'
    )
  })
})
