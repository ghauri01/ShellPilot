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

// ---------------------------------------------------------------------------
// What counts as the job engine, DERIVED rather than listed
// ---------------------------------------------------------------------------
//
// This used to be a hand-written `/^(jobRunner|jobExec|jobs)$/i` whose own
// docstring said "a file added to the engine goes here" — and then jobDetached
// was added to the engine and did not go here, because a comment is not a
// mechanism. A literal list of engine modules has exactly one failure mode and
// it is the one that matters: it goes stale silently, and the guard keeps
// passing while the thing it guards grows.
//
// So the set is SCANNED from the directory the engine lives in. Two
// consequences, both wanted:
//
//   * A new `src/main/services/job*.ts` is covered by the import assertions the
//     moment it exists, before anyone imports it.
//   * `REVIEWED_JOB_FILES` below is compared against that scan, so a new engine
//     file fails THE DAY IT IS ADDED rather than the day someone wires it up.
//     The fix for that failure is one line and a reviewer reading it — which is
//     the entire point, because "should this be reachable from the bridge?" is
//     a question to answer when the file is written, not when it is imported.
//
// The shared/ half cannot be scanned the same way: `src/shared` is full of
// modules the bridge legitimately uses, so the job-adjacent ones are named. The
// three that matter beyond the runner itself are patch management (it plans and
// approves estate-wide upgrades), the topology graph (it decides what a reboot
// takes down), and the approval log (a job that could write its own approval
// record could launder one). Two of them are reachable through `shared/jobs`
// today by a single TYPE-ONLY import each — the kind a reviewer deletes with
// "inline these three types and drop the dependency", after which patch
// management is freely importable from the bridge and nothing goes red. Named
// directly, that edge no longer carries the guarantee.

const SERVICES_DIR = join(ROOT, 'src/main/services')

/** Basenames of every `job*.ts` in the engine directory, right now. */
function scanJobModules(): string[] {
  return readdirSync(SERVICES_DIR)
    .filter((f) => /^job.*\.tsx?$/i.test(f))
    .map((f) => f.replace(/\.tsx?$/i, ''))
    .sort()
}

/** The engine files a human has looked at. Compared against the scan below. */
const REVIEWED_JOB_FILES = ['jobDetached', 'jobExec', 'jobRunner']

/** Job-adjacent modules outside `src/main/services`, named because that
 *  directory cannot be scanned wholesale. */
const SHARED_JOB_MODULES = ['jobs', 'patch', 'topology', 'broadcast', 'approvalLog']

const JOB_MODULE_NAMES = [...new Set([...scanJobModules(), ...SHARED_JOB_MODULES])]

/** Every module the job engine is made of. Matched on the specifier's basename,
 *  so './jobRunner', '../services/jobRunner.js' and './jobRunner/index' all
 *  hit. */
const JOB_MODULE = new RegExp(`^(${JOB_MODULE_NAMES.join('|')})$`, 'i')

function isForbiddenSpecifier(spec: string): boolean {
  const base = spec.replace(/\.[cm]?[jt]sx?$/i, '').split(/[/\\]/).pop() ?? ''
  return JOB_MODULE.test(base)
}

describe('the job engine is enumerated by scanning, not by memory', () => {
  it('has no engine file nobody reviewed', () => {
    const scanned = scanJobModules()
    // Anti-vacuity first: a scan that found nothing would make every
    // import assertion in this file pass against an empty alternation.
    expect(
      scanned.length,
      `No job*.ts found in ${relative(ROOT, SERVICES_DIR)} — the scan is broken, and JOB_MODULE ` +
        `below is built from it.`
    ).toBeGreaterThan(0)

    const unreviewed = scanned.filter((f) => !REVIEWED_JOB_FILES.includes(f))
    expect(
      unreviewed,
      `New job engine files: ${unreviewed.join(', ')}.\n\n` +
        `This fails on the day the file was ADDED, deliberately, rather than on the day someone ` +
        `imports it from the bridge — because "may an agent reach this?" is a question to answer ` +
        `while writing the file, not while debugging a red build later. The engine is not ` +
        `agent-reachable (see the header: DURABILITY DEFEATS REVOCATION), and every job*.ts here ` +
        `inherits that. Add it to REVIEWED_JOB_FILES in a diff a reviewer sees.`
    ).toEqual([])

    const gone = REVIEWED_JOB_FILES.filter((f) => !scanned.includes(f))
    expect(
      gone,
      `REVIEWED_JOB_FILES names files that no longer exist: ${gone.join(', ')}. A stale entry ` +
        `here is a hole: the list stops describing the directory it is supposed to mirror.`
    ).toEqual([])
  })

  it('covers the whole engine, including the detached executor', () => {
    // The specific miss this replaced: jobDetached — the executor that
    // deliberately OUTLIVES the link, which is the exact property that makes a
    // job unrevocable — was not in the hand-written alternation at all.
    for (const name of ['jobRunner', 'jobExec', 'jobDetached', 'jobs', 'patch', 'topology']) {
      expect(JOB_MODULE.test(name), name).toBe(true)
    }
    // And the walker's specifier form of the same names.
    for (const spec of ['./jobDetached', '../services/jobDetached.js', '../../shared/patch']) {
      expect(isForbiddenSpecifier(spec), spec).toBe(true)
    }
    // Not everything beginning with "job" out in the world: the match is on a
    // basename, so an unrelated module is not swept up by accident.
    expect(isForbiddenSpecifier('./jobsite')).toBe(false)
    expect(isForbiddenSpecifier('node:path')).toBe(false)
  })
})

/**
 * The path aliases the bundler resolves, so the walker resolves them too.
 *
 * Without this, `resolveSpecifier` returned null for anything not starting with
 * '.', which meant an aliased import was not an offender AND not walked — so
 * the belt-and-braces check below, which exists precisely to catch an alias,
 * never saw the module either. Both layers passed for the same wrong reason,
 * silently, while the literal check further down would have failed loudly with
 * ENOENT. A guard whose quiet failure mode is "pass" is not a guard.
 */
const ALIASES: [RegExp, string][] = [[/^@\//, 'src/renderer/src/']]

function applyAlias(spec: string): string | null {
  for (const [rx, to] of ALIASES) if (rx.test(spec)) return join(ROOT, spec.replace(rx, to))
  return null
}

/** A specifier this walker is expected to be able to follow: relative, or one
 *  of the aliases above. Anything else is a package from node_modules. */
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

  it('followed every local import it found, rather than skipping the ones it could not name', () => {
    // The failure mode that makes the two assertions below vacuous: a
    // specifier the walker cannot resolve is not an offender and is not
    // walked, so a rename or a new path alias would defeat BOTH of them
    // without anything going red. An unresolvable local import is therefore a
    // failure of this file, not a shrug.
    const unresolved = edges
      .filter((e) => e.to === null && isLocalSpecifier(e.spec))
      .map((e) => `${relative(ROOT, e.from)} -> '${e.spec}'`)
    expect(
      unresolved,
      `The import walker could not follow these. Teach resolveSpecifier about them — a specifier ` +
        `it cannot resolve is one the forbidden-import assertions below silently skip.\n  ` +
        `${unresolved.join('\n  ')}`
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
    const offenders = [...relFiles].filter((f) =>
      JOB_MODULE.test(f.split('/').pop()?.replace(/\.tsx?$/i, '') ?? '')
    )
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
      'shared/jobs',
      'jobExec',
      'attachedJobExecutor',
      // The detached executor and its factory. Missing here for exactly as long
      // as it was missing from JOB_MODULE above, and it is the half of the
      // engine that keeps running after the link that started it is gone.
      'jobDetached',
      'detachedJobExecutor',
      // Patch management and the topology graph: the two modules that decide
      // what an estate-wide upgrade does and what a reboot takes down.
      'shared/patch',
      'planPatch',
      'shared/topology',
      'buildTopology',
      // The approval record. A caller that can write one can launder consent
      // for work it was never granted.
      'approvalLog',
      'recordJobApproval',
      // The access write half — roadmap item 23. It edits authorized_keys, it
      // is the one write in this app that can lock the operator out of the
      // host they would use to undo it, and it is currently GATED OFF pending
      // the blockers in its plan path. The property that it never reaches the
      // bridge holds today only by construction: nothing imports it, and
      // nothing stops the next person wiring "let the agent rotate the deploy
      // key" through here. An agent getting `execute_command` gated per server
      // is a different consent story from an agent revoking a key across a
      // selection, and the answer to the second is no — not "not yet".
      'planAccessChange',
      'buildRevokeKeyCommand',
      'buildAddKeyCommand',
      'accessDisarmCommand'
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
