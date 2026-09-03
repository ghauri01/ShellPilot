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

// ===========================================================================
// WHY A JOB ENGINE IS HUMAN-ONLY, AND WHY THIS IS NOT THE BROADCAST ARGUMENT
// REPEATED
// ===========================================================================
//
// Broadcast is deliberately not agent-reachable: an agent gets
// `execute_command` gated per server against an access group, and a fan-out
// primitive is a different risk with a different consent story. That argument
// is about BLAST RADIUS, and it is a good argument.
//
// A job engine needs a second one, because it is not merely a broadcast that is
// bigger. It is a broadcast that OUTLIVES the thing that was supposed to be
// able to stop it.
//
//   DURABILITY DEFEATS REVOCATION.
//
// The stop-all-AI-access switch is `denyAllPending()`. It works by resolving
// requests that are *pending*: every approval waiting on a human gets a `deny`,
// every session is revoked, and nothing further can be asked for. That is a
// complete answer for every capability the bridge has today, because every one
// of them is a request-response — the agent asks, a human decides, the work
// happens inside that decision's lifetime.
//
// A job is not. A job that is already running on fifteen hosts has nothing
// pending. There is no request to deny, no approval to withdraw, and no session
// whose revocation reaches the ssh channels already open. `denyAllPending()`
// returns cleanly, reports a number, and the estate upgrade keeps going.
//
// So an agent-reachable job engine would be a STANDING CAPABILITY that the
// stop-all-AI-access switch cannot revoke — which is not a weaker version of
// the guarantee the switch advertises, it is the absence of it. The guarantee
// is either true of everything the bridge can reach or it is not a guarantee.
//
// Making it revocable is not a small fix, either: it would mean the kill switch
// reaching into the runner, cancelling live jobs, and — on B2's detached
// backend — reaching onto the remote hosts to stop processes it did not start,
// under whatever credentials happen to still resolve. Every one of those is a
// new, worse power granted in order to constrain the first one.
//
// Hence: not gated, not asked-for, NOT THERE. Three layers, exactly the ones
// the local terminal uses, plus the cheap literal blacklist dockerOps.test.ts
// carries.
//
//   1. Runtime    — the tool list the bridge actually serves.
//   2. Static     — the transitive import closure of both agent-facing entry
//                   points, so the job service cannot even be reached.
//   3. Vocabulary — the capability list, so the *idea* cannot be expressed in
//                   the permission model without this test failing first.
//   4. Literal    — the words themselves, in the files that must not say them.
//
// If you are here because one of them failed: the failure is the feature. Do
// not weaken the assertion.

const ROOT = resolve(__dirname, '..')
const PORT = 58753

const read = (p: string): string => readFileSync(join(ROOT, p), 'utf8')

// ---------------------------------------------------------------------------
// 1. Runtime: what the bridge actually serves
// ---------------------------------------------------------------------------

// Reconciled against tests/localTerminalNotExposed.test.ts's ALLOWED_TOOLS.
// Deliberately duplicated rather than imported: these are two independent
// reviews of the same list, and a shared constant would let one edit satisfy
// both.
const ALLOWED_TOOLS = [
  'list_workspaces',
  'list_servers',
  'get_server_details',
  'execute_command',
  'read_file',
  'write_file',
  'list_files',
  'get_server_metrics',
  'get_host_facts',
  'list_databases',
  'query_database',
  'list_tunnels',
  'set_tunnel',
  'list_vpns',
  'set_vpn',
  'add_server'
]

// A hint, not the gate — the whitelist above has already failed by the time
// this matches. It exists to put the word "job" in the failure message so
// whoever trips it understands what they tripped over.
const JOB_TOOL = /job|batch|broadcast|fan_?out|schedule/i

describe('the MCP bridge exposes no job surface', () => {
  let token: string

  beforeAll(async () => {
    resetMcpAuthForTests()
    resetPolicyCacheForTests()
    refreshMcpDataCache({ workspaces: [{ id: 'ws', name: 'W' }], servers: [] })
    setAssignment({ level: 'workspace', workspaceId: 'ws' }, 'grp-read-only')
    setMcpConfig({ enabled: true, port: PORT, approvalTimeoutSeconds: 5 })
    token = createSession({
      agentName: 'JobGuard',
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

  it('serves exactly the reviewed tool list, and nothing that starts a job', async () => {
    const transport = new StreamableHTTPClientTransport(new URL(`http://127.0.0.1:${PORT}/mcp`), {
      requestInit: { headers: { Authorization: `Bearer ${token}` } }
    })
    const client = new Client({ name: 'jobs-guard', version: '1.0.0' })
    await client.connect(transport)
    const { tools } = await client.listTools()
    const names = tools.map((t) => t.name)

    try {
      // Anti-vacuity: a bridge that served nothing passes every assertion below
      // while proving nothing at all.
      expect(names.length, 'the bridge served no tools — this test proves nothing in that state').toBeGreaterThan(0)

      const unexpected = names.filter((n) => !ALLOWED_TOOLS.includes(n))
      expect(
        unexpected,
        `New MCP tools must be added to ALLOWED_TOOLS in this test, deliberately, in a diff a ` +
          `reviewer sees: ${unexpected.join(', ')}`
      ).toEqual([])

      const suspicious = names.filter((n) => JOB_TOOL.test(n))
      expect(
        suspicious,
        `These tool names read like a job or fan-out surface: ${suspicious.join(', ')}. A job ` +
          `outlives the request that started it, and denyAllPending() can only resolve requests ` +
          `that are PENDING — so a job an agent started is a standing capability the ` +
          `stop-all-AI-access switch cannot revoke.`
      ).toEqual([])
    } finally {
      await client.close()
    }
  })
})

// ---------------------------------------------------------------------------
// 2. Static: the transitive import closure
// ---------------------------------------------------------------------------
//
// The runtime check catches a tool that was registered. This catches the step
// before it — the module becoming REACHABLE — and it covers the CLI bridge too,
// which is a second agent-facing surface with no listTools to interrogate.
//
// The realistic breach is not someone editing mcpServer.ts. It is someone
// hoisting a shared helper into a module both sides import: this runner
// deliberately reuses ssh.ts's output coalescer and logTail.ts's owns() guard,
// and the first review comment on either is "don't duplicate this". If that
// happens, move the helper — not this assertion.

const SEED_FILES = [
  join(ROOT, 'src/main/services/mcpServer.ts'),
  ...tsFilesIn(join(ROOT, 'src/cli'))
]

/** Matched on the specifier's basename, so './jobRunner', '../services/jobRunner.js'
 *  and './jobRunner/index' all hit. */
function isForbiddenSpecifier(spec: string): boolean {
  const base = spec.replace(/\.[cm]?[jt]sx?$/i, '').split(/[/\\]/).pop() ?? ''
  return /^(jobRunner|jobs)$/i.test(base)
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
    // arguments are what pick up `require()` and `import()`. A regex over
    // `from` clauses would miss `await import('./x')`, which is the idiom this
    // codebase already uses for exactly the heavy modules a breach would want.
    for (const ref of ts.preProcessFile(source, true, true).importedFiles) {
      const to = resolveSpecifier(file, ref.fileName)
      edges.push({ from: file, spec: ref.fileName, to })
      if (to !== null && !files.has(to)) queue.push(to)
    }
  }
  return { files, edges }
}

// The guard on the guard. If the walker ever breaks, the closure collapses and
// every forbidden-import assertion passes for the wrong reason.
const MUST_BE_IN_CLOSURE = [
  'src/main/services/mcpServer.ts',
  'src/main/services/policyEngine.ts',
  'src/main/services/approvals.ts',
  'src/main/services/secretRedaction.ts',
  'src/main/services/ssh.ts',
  'src/shared/mcp.ts',
  'src/cli/bridge.ts'
]

describe('nothing an agent can reach imports the job engine', () => {
  const { files, edges } = importClosure(SEED_FILES)
  const relFiles = new Set([...files].map((f) => relative(ROOT, f).split('\\').join('/')))

  it('walked a real closure, not an empty one', () => {
    const missing = MUST_BE_IN_CLOSURE.filter((f) => !relFiles.has(f))
    expect(
      missing,
      `The import walker did not reach modules that are definitely reachable from the MCP server ` +
        `or the CLI. The closure is broken, so the assertions below are meaningless.\n  ${missing.join('\n  ')}`
    ).toEqual([])
  })

  it('imports neither the job runner nor the job vocabulary', () => {
    const offenders = edges
      .filter((e) => isForbiddenSpecifier(e.spec))
      .map((e) => `${relative(ROOT, e.from)} imports '${e.spec}'`)

    expect(
      offenders,
      `A module reachable from the MCP bridge or the ShellPilot CLI now imports the job engine.\n\n` +
        `${offenders.join('\n')}\n\n` +
        `DURABILITY DEFEATS REVOCATION. denyAllPending() — the stop-all-AI-access switch — works ` +
        `by resolving requests that are PENDING. A job already running on fifteen hosts has ` +
        `nothing pending: no request to deny, no approval to withdraw, and no session revocation ` +
        `that reaches the channels already open. The switch would return cleanly, report a ` +
        `number, and the estate upgrade would keep going. That is not a weaker guarantee than ` +
        `the one the switch advertises — it is the absence of it.\n\n` +
        `If a shared helper was hoisted into a module both sides import, move the helper, not ` +
        `this assertion.`
    ).toEqual([])
  })

  it('has no job module anywhere in the closure', () => {
    // Belt and braces: catches a reach that arrived through a path alias or a
    // re-export chain whose specifier text never says "jobRunner".
    const offenders = [...relFiles].filter((f) => /(^|\/)(jobRunner|jobs)\.tsx?$/i.test(f))
    expect(
      offenders,
      `These job modules are in the agent-reachable import closure: ${offenders.join(', ')}`
    ).toEqual([])
  })
})

// ---------------------------------------------------------------------------
// 3. Vocabulary: the permission model
// ---------------------------------------------------------------------------

describe('the AI permission model has no word for a job', () => {
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
    'hostFacts',
    'manageServers',
    'vpnControl'
  ]

  it('grants no capability naming a job or a fan-out', () => {
    expect(AI_CAPABILITIES.length, 'AI_CAPABILITIES is empty — nothing was checked').toBeGreaterThan(0)

    const rx = /job|broadcast|fan.?out|batch|schedul/i
    const offenders = AI_CAPABILITIES.filter((c) => rx.test(c.id) || rx.test(c.label)).map(
      (c) => `${c.id} (${c.label})`
    )

    expect(
      offenders,
      `A capability that names a job has appeared: ${offenders.join(', ')}. Adding one is the ` +
        `natural next step for someone implementing "let the agent kick off the upgrade", and ` +
        `this is where that conversation has to happen instead of it landing in a diff. There is ` +
        `no value of this capability — not even ASK — that makes it safe, because the thing it ` +
        `grants outlives the ask.`
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

// ---------------------------------------------------------------------------
// 4. Literal: the words, in the files that must not say them
// ---------------------------------------------------------------------------
//
// The cheap one, from dockerOps.test.ts. It cannot be fooled by an alias and it
// fails in the diff rather than at runtime, which for a symbol name is most of
// the value.

describe('what must NOT be able to reach this', () => {
  it('the MCP server names nothing from the job engine', () => {
    const mcp = read('src/main/services/mcpServer.ts')
    for (const forbidden of [
      'JobRunner',
      'jobRunner',
      'planJob',
      'JobRunRequest',
      'jobs:run',
      'jobs:cancel',
      'jobs:list',
      'unfinishedJobs',
      'createJob',
      'shared/jobs'
    ]) {
      expect(mcp, forbidden).not.toContain(forbidden)
    }
  })

  it('the job runner is registered only in main, at one place', () => {
    // The single construction site is what makes the model enforceable by
    // reading. A second `new JobRunner(` anywhere would be a second executor
    // with its own idea of what a job may do.
    const main = read('src/main/index.ts')
    expect(main.match(/new JobRunner\(/g) ?? []).toHaveLength(1)
  })

  it('the job runner reaches no agent-facing module', () => {
    // The other direction of the same boundary. The runner may hold the
    // executor and the store; it may not hold the approval plumbing, because a
    // job that could create its own approval request is a job that could
    // answer one.
    const runner = read('src/main/services/jobRunner.ts')
    for (const forbidden of ['mcpServer', 'mcpAuth', 'approvals', 'policyEngine', 'policyStore']) {
      expect(runner, forbidden).not.toContain(forbidden)
    }
  })
})
