import { describe, it, expect, beforeAll, afterAll } from 'vitest'
import { existsSync, readFileSync, readdirSync, statSync } from 'node:fs'
import { dirname, join, relative, resolve } from 'node:path'
import ts from 'typescript'
import { Client } from '@modelcontextprotocol/sdk/client/index.js'
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js'

import { refreshMcpDataCache } from '../src/main/services/mcpDataCache'
import { setAssignment, resetPolicyCacheForTests } from '../src/main/services/policyStore'
import { setMcpConfig, createSession, resetMcpAuthForTests } from '../src/main/services/mcpAuth'
import { startMcpServer, stopMcpServer } from '../src/main/services/mcpServer'
import { AI_CAPABILITIES } from '../src/shared/mcp'

// The local terminal is a shell on the user's own machine, with the user's own
// privileges, reached with no credential and no host key. It is not behind a
// capability and not behind ASK, because there is no setting of either that
// makes it safe to hand to an agent: an agent that can run local commands can
// read the vault file, the policy store and the audit log that are supposed to
// constrain it. Every constraint this app advertises lives on the same disk as
// the shell.
//
// So the rule is not "gate it", it is "it is not there". The three guards below
// are what keep that true when someone later adds "just a read-only one".
//
//   1. Runtime  — the tool list the bridge actually serves.
//   2. Static   — the transitive import closure of both agent-facing entry
//                 points, so the module cannot even be reached, let alone
//                 called.
//   3. Vocabulary — the capability list, so the *idea* cannot be expressed in
//                 the permission model without this test failing first.
//
// If you are here because one of them failed: the failure is the feature. Do
// not weaken the assertion. See docs/plans/local-terminal-plan.md Phase 8 and
// risk R8.

const ROOT = resolve(__dirname, '..')
const PORT = 58742

// ---------------------------------------------------------------------------
// 1. Runtime: what the bridge actually serves
// ---------------------------------------------------------------------------

// Every tool the bridge is allowed to expose. A whitelist, not a pattern match:
// a new tool has to be added here deliberately, in a diff a reviewer sees,
// which is the whole point.
//
// Reconciled against the 15 `server.registerTool(` calls in
// src/main/services/mcpServer.ts.
const ALLOWED_TOOLS = [
  'list_workspaces',
  'list_servers',
  'get_server_details',
  'execute_command',
  'read_file',
  'write_file',
  'list_files',
  'get_server_metrics',
  // Roadmap item C. Reads over SSH on a configured server, like every other
  // tool here, and reaches no shell on this machine. Gated on its own
  // `hostFacts` capability rather than serverMetrics.
  'get_host_facts',
  'list_databases',
  'query_database',
  'list_tunnels',
  'set_tunnel',
  'list_vpns',
  'set_vpn',
  'add_server'
]

// A hint, not the gate. Anything this regex matches is by construction absent
// from ALLOWED_TOOLS, so the whitelist below has already failed by the time
// this one does — it exists only to put the words "local execution" in the
// failure message, so whoever hits it understands what they tripped over
// rather than reaching for the nearest way to make it green.
//
// THE WHITELIST IS THE REAL GATE. Deleting this regex weakens nothing;
// widening ALLOWED_TOOLS weakens everything.
//
// `(^|_)exec($|_)` is anchored on word boundaries so it does not match the
// legitimate `execute_command`, which runs over SSH on a configured server.
const LOCAL_EXECUTION_TOOL = /local|shell|pty|spawn|(^|_)exec($|_)/i

describe('the MCP bridge exposes no local-terminal surface', () => {
  let token: string

  beforeAll(async () => {
    resetMcpAuthForTests()
    resetPolicyCacheForTests()
    refreshMcpDataCache({ workspaces: [{ id: 'ws', name: 'W' }], servers: [] })
    setAssignment({ level: 'workspace', workspaceId: 'ws' }, 'grp-read-only')
    setMcpConfig({ enabled: true, port: PORT, approvalTimeoutSeconds: 5 })
    token = createSession({
      agentName: 'Guard',
      workspaces: [{ id: 'ws', name: 'W' }],
      groupId: 'grp-read-only',
      groupName: 'Read Only',
      ttlMinutes: 60
    }).token
    const started = await startMcpServer()
    expect(started.ok, `MCP server did not start: ${started.error ?? ''}`).toBe(true)
  })

  afterAll(async () => {
    await stopMcpServer()
  })

  it('serves exactly the reviewed tool list, and nothing that runs anything locally', async () => {
    const transport = new StreamableHTTPClientTransport(new URL(`http://127.0.0.1:${PORT}/mcp`), {
      requestInit: { headers: { Authorization: `Bearer ${token}` } }
    })
    const client = new Client({ name: 'local-terminal-guard', version: '1.0.0' })
    await client.connect(transport)
    const { tools } = await client.listTools()
    const names = tools.map((t) => t.name)

    try {
      // Anti-vacuity: if the bridge served nothing — a transport that failed
      // open, an auth change that empties the list — every assertion below
      // passes while proving nothing at all. Assert only that the list is
      // non-empty here; the exact membership is the whitelist's job, so a new
      // tool fails with the whitelist's message rather than an arithmetic one.
      expect(names.length, 'the bridge served no tools — this test proves nothing in that state').toBeGreaterThan(0)

      const unexpected = names.filter((n) => !ALLOWED_TOOLS.includes(n))
      expect(
        unexpected,
        `New MCP tools must be added to ALLOWED_TOOLS in this test, deliberately, in a diff a ` +
          `reviewer sees. If the new tool reaches a shell on this machine, it must not exist at ` +
          `all — see docs/plans/local-terminal-plan.md risk R8.\n  ${unexpected.join(', ')}`
      ).toEqual([])

      const suspicious = names.filter((n) => LOCAL_EXECUTION_TOOL.test(n))
      expect(
        suspicious,
        `These tool names read like a local-execution surface: ${suspicious.join(', ')}. ` +
          `The bridge runs commands on configured SSH servers, never on this machine.`
      ).toEqual([])
    } finally {
      await client.close()
    }
  })
})

// ---------------------------------------------------------------------------
// 2. Static: the transitive import closure
// ---------------------------------------------------------------------------

// The runtime check catches a tool that was registered. This catches the step
// before it — the module becoming *reachable* — and it covers the CLI bridge
// too, which is a second agent-facing surface with no listTools to interrogate.
//
// Two things this deliberately does NOT do, both of which a previous draft did
// and both of which made it useless:
//
//   * It does not regex for `from '...'`. Imports are found with
//     ts.preProcessFile, which returns every specifier — static, `import type`,
//     re-export, `require()`, and `await import('./x')`. That last one is not
//     hypothetical: it is the exact idiom localPty.ts itself uses to load the
//     native binding, so a regex over `from` clauses would miss the single most
//     likely way the module gets pulled in.
//
//   * It does not check a hand-picked list of files. mcpServer.ts imports 17
//     modules directly and many more transitively. The realistic breach is not
//     someone editing mcpServer.ts — it is someone hoisting a shared helper
//     (the plan copies ssh.ts's output coalescer byte-for-byte, and the first
//     review comment on that will be "don't duplicate this") into a module both
//     sides import. localPty enters the graph; mcpServer.ts's own text never
//     changes; a per-file text check sees nothing.
//
// So: seed from the two entry points, resolve relative specifiers the way the
// bundler does, and walk until the graph closes.

const SEED_FILES = [
  join(ROOT, 'src/main/services/mcpServer.ts'),
  // Everything under src/cli is an entry point in its own right: the launcher,
  // the stdio bridge, and the agent-config writers.
  ...tsFilesIn(join(ROOT, 'src/cli'))
]

// The modules that must never appear. Matched on the specifier's basename, so
// './localPty', '../services/localPty.js' and './localPty/index' all hit, plus
// any package whose name contains node-pty regardless of scope.
function isForbiddenSpecifier(spec: string): boolean {
  if (/node-pty/i.test(spec)) return true
  const base = spec.replace(/\.[cm]?[jt]sx?$/i, '').split(/[/\\]/).pop() ?? ''
  return /^(localPty|shellDiscovery)$/i.test(base)
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

// Resolve a relative specifier to a file on disk. Bare specifiers (packages)
// return null and are not walked — but they are still checked against
// isForbiddenSpecifier by the caller, which is how '@lydell/node-pty' is
// caught even though node_modules is never entered.
//
// The `.js` stripping is not optional: src/cli is NodeNext and writes
// './pairing.js' for a file that is './pairing.ts' on disk. A resolver that
// only tried the literal specifier would silently drop the entire CLI graph
// after one hop and then report a clean closure.
function resolveSpecifier(fromFile: string, spec: string): string | null {
  if (!spec.startsWith('.')) return null
  const literal = join(dirname(fromFile), spec)
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
    // (text, readImportFiles, detectJavaScriptImports) — the second and third
    // arguments are what pick up `require()` and `import()` respectively.
    for (const ref of ts.preProcessFile(source, true, true).importedFiles) {
      const to = resolveSpecifier(file, ref.fileName)
      edges.push({ from: file, spec: ref.fileName, to })
      if (to !== null && !files.has(to)) queue.push(to)
    }
  }

  return { files, edges }
}

// Modules known to be reachable from mcpServer.ts / src/cli today. This is the
// guard on the guard: if the walker ever breaks — preProcessFile changing
// shape, resolution silently failing, a seed path going stale after a move —
// the closure collapses and every forbidden-import assertion passes for the
// wrong reason. These anchors turn that silent pass into a loud failure.
const MUST_BE_IN_CLOSURE = [
  'src/main/services/mcpServer.ts',
  'src/main/services/mcpAuth.ts',
  'src/main/services/mcpDataCache.ts',
  'src/main/services/policyEngine.ts',
  'src/main/services/policyStore.ts',
  'src/main/services/agentServerCreate.ts',
  'src/main/services/serverResolver.ts',
  'src/main/services/credentialResolver.ts',
  'src/main/services/approvals.ts',
  'src/main/services/auditLog.ts',
  'src/main/services/secretRedaction.ts',
  'src/main/services/cliPairing.ts',
  'src/main/services/ssh.ts',
  'src/main/services/sftp.ts',
  'src/main/services/db.ts',
  'src/main/services/tunnel.ts',
  'src/main/services/metrics.ts',
  'src/main/services/vpn/managerApi.ts',
  'src/shared/mcp.ts',
  // Reached only through the src/cli seeds — proves that half of the closure
  // is live too, including the `./pairing.js` -> pairing.ts specifier form.
  'src/cli/pairing.ts',
  'src/cli/bridge.ts',
  'src/cli/agents.ts',
  'src/cli/vpn.ts'
]

describe('nothing an agent can reach imports the local terminal', () => {
  const { files, edges } = importClosure(SEED_FILES)
  const relFiles = new Set([...files].map((f) => relative(ROOT, f).split('\\').join('/')))

  it('walked a real closure, not an empty one', () => {
    const missing = MUST_BE_IN_CLOSURE.filter((f) => !relFiles.has(f))
    expect(
      missing,
      `The import walker did not reach modules that are definitely reachable from the MCP server ` +
        `or the CLI. The closure is broken, so its forbidden-import assertions below are ` +
        `meaningless. Fix the walker (or, if a module genuinely moved, update this list) before ` +
        `trusting a green run.\n  ${missing.join('\n  ')}`
    ).toEqual([])
  })

  it('resolves every relative import it finds', () => {
    // An unresolved relative specifier is a hole in the closure: the graph
    // stops there and anything beyond it goes unchecked. Fail on the hole
    // itself rather than on whatever slips through it later.
    const unresolved = edges
      .filter((e) => e.spec.startsWith('.') && e.to === null)
      .map((e) => `${relative(ROOT, e.from)} -> ${e.spec}`)
    expect(
      unresolved,
      `These relative imports could not be resolved to a file, so the walk stopped short of ` +
        `whatever they point at. Teach resolveSpecifier the new form.\n  ${unresolved.join('\n  ')}`
    ).toEqual([])
  })

  it('imports neither the local pty module, the shell discovery module, nor node-pty', () => {
    const offenders = edges
      .filter((e) => isForbiddenSpecifier(e.spec))
      .map((e) => `${relative(ROOT, e.from)} imports '${e.spec}'`)

    expect(
      offenders,
      `A module reachable from the MCP bridge or the ShellPilot CLI now imports the local ` +
        `terminal. This is the thing the local terminal feature exists on the condition of not ` +
        `doing.\n\n${offenders.join('\n')}\n\n` +
        `An AI agent that can run a command on this machine can read the vault file, the policy ` +
        `store and the audit log that are supposed to constrain it — every one of them is a file ` +
        `on this disk. There is no capability value and no ASK prompt that makes this safe, which ` +
        `is why the answer is "not reachable" rather than "gated". If a shared helper was hoisted ` +
        `into a module both sides import, move the helper, not this assertion. See ` +
        `docs/plans/local-terminal-plan.md Phase 8.`
    ).toEqual([])
  })

  it('has no local-terminal module anywhere in the closure', () => {
    // Belt and braces: catches a reach that arrived through a path alias or a
    // re-export chain whose specifier text never says "localPty".
    const offenders = [...relFiles].filter((f) => /(^|\/)(localPty|shellDiscovery)\.tsx?$/i.test(f))
    expect(
      offenders,
      `These local-terminal modules are in the agent-reachable import closure: ${offenders.join(', ')}`
    ).toEqual([])
  })
})

// ---------------------------------------------------------------------------
// 3. Vocabulary: the permission model
// ---------------------------------------------------------------------------

describe('the AI permission model has no word for a local shell', () => {
  // Asserted over the exported array at runtime rather than by regexing the
  // type declaration. A regex over `export type AiCapability = ...` reports
  // "clean" when it fails to match at all, and stops at the first blank line,
  // so a member added under a doc comment falls outside the capture entirely —
  // it passes for two different reasons that both mean "did not look".
  //
  // AI_CAPABILITIES is also the array the UI renders and policyEngine iterates,
  // so a capability that is not in it is not a capability anyone can grant.

  const ALLOWED_CAPABILITIES = [
    'viewServer',
    'terminal',
    'readFiles',
    'writeFiles',
    'sftpDownload',
    'sftpUpload',
    'sshTunnel',
    'databaseAccess',
    'sudo',
    'serverMetrics',
    // Roadmap item C. Reviewed and added deliberately: it is its OWN capability
    // rather than a widening of serverMetrics, because a count of unpatched
    // vulnerabilities is materially different from CPU and memory.
    'hostFacts',
    'manageServers',
    'vpnControl'
  ]

  it('grants no capability naming a local shell', () => {
    expect(AI_CAPABILITIES.length, 'AI_CAPABILITIES is empty — nothing was checked').toBeGreaterThan(0)

    const offenders = AI_CAPABILITIES.filter(
      (c) => /local|shell|pty|spawn|subprocess/i.test(c.id) || /local|shell|pty|spawn|subprocess/i.test(c.label)
    ).map((c) => `${c.id} (${c.label})`)

    expect(
      offenders,
      `A capability that names a local shell has appeared: ${offenders.join(', ')}. Adding one is ` +
        `the natural next step for someone implementing "let the agent run something locally", and ` +
        `this is where that conversation has to happen instead of it landing in a diff.`
    ).toEqual([])
  })

  it('grants exactly the reviewed capability list', () => {
    const unexpected = AI_CAPABILITIES.map((c) => c.id).filter((id) => !ALLOWED_CAPABILITIES.includes(id))
    expect(
      unexpected,
      `New AI capabilities must be added to ALLOWED_CAPABILITIES in this test, deliberately: ` +
        `${unexpected.join(', ')}`
    ).toEqual([])
  })
})
