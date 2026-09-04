import { describe, it, expect, beforeAll, afterAll } from 'vitest'
import { existsSync, mkdirSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from 'node:fs'
import { dirname, join, relative, resolve } from 'node:path'
import ts from 'typescript'

import { AI_CAPABILITIES } from '../src/shared/mcp'
import { MODULE_FORBIDDEN_IMPORTS } from '../src/shared/modules'

// ===========================================================================
// WHY A RULE ENGINE IS HUMAN-ONLY, AND WHY IT IS NOT THE JOB ARGUMENT REPEATED
// ===========================================================================
//
// tests/jobsNotExposed.test.ts states the rule this inherits:
//
//   DURABILITY DEFEATS REVOCATION.
//
// `denyAllPending()` — the stop-all-AI-access switch — works by resolving
// requests that are PENDING. It is a complete answer for every capability the
// bridge has today because every one of them is a request-response: the agent
// asks, a human decides, the work happens inside that decision's lifetime. A
// job breaks it because a job already running on fifteen hosts has nothing
// pending.
//
// A RULE BREAKS IT HARDER, AND IN A DIFFERENT PLACE.
//
// A job is unrevocable for as long as it runs — minutes, or an hour. A rule is
// unrevocable FOREVER, and specifically it is unrevocable while it is doing
// nothing at all. It is a row in a JSON file holding a `CommandApproval` a
// human signed once. Between firings there is no request, no session, no open
// channel and no process: `denyAllPending()` iterates a list this rule was
// never on, returns cleanly, reports a number, and that night the rule runs
// commands on an estate because a disk crossed 85%.
//
// There is no version of "revoke it too" that is small, either. It would mean
// the kill switch reaching into a file the user owns and deleting authorisation
// a HUMAN gave — because a rule an agent wrote and a rule an operator wrote are
// the same row, by design, since the operator is the one who confirmed it. So
// the switch would either have to distinguish provenance it does not record, or
// delete the operator's own automation on an AI event. Both are worse than the
// thing they fix.
//
// Second, and separate: a rule is a CONSENT-LAUNDERING primitive in a way a job
// is not. A job needs an approval minted at the moment it runs. A rule holds one
// minted once and reused indefinitely — so an agent that could create a rule
// would be manufacturing a durable consent record for work no human will ever
// be asked about again. That is the objection this repository already makes
// about `approvalLog`, with a much longer fuse.
//
// Hence: not gated, not asked-for, NOT THERE. Same layers as the job engine:
//
//   1. Static     — the transitive import closure of both agent-facing entry
//                   points, so the module cannot be reached at all.
//   2. Vocabulary — the capability list, so the idea cannot be expressed in the
//                   permission model without this test failing first.
//   3. Literal    — the words themselves, in the files that must not say them.
//
// The RUNTIME layer — the tool list the bridge actually serves — is asserted in
// tests/jobsNotExposed.test.ts, whose `JOB_TOOL` alternation now includes
// `rule` and whose ALLOWED_TOOLS whitelist fails on anything new regardless.
// One place starts an MCP server; a second copy of that would be two servers
// for one guarantee.
//
// If you are here because one of these failed: the failure is the feature.

const ROOT = resolve(__dirname, '..')
const read = (p: string): string => readFileSync(join(ROOT, p), 'utf8')

/** Both halves of item 27, matched on the specifier's basename so
 *  '../../shared/rules', './rules' and '../services/rules.js' all hit. */
const RULE_MODULE = /^rules$/i

const ALIASES: [RegExp, string][] = [[/^@\//, 'src/renderer/src/']]

function applyAlias(spec: string): string | null {
  for (const [rx, to] of ALIASES) if (rx.test(spec)) return join(ROOT, spec.replace(rx, to))
  return null
}

function isLocalSpecifier(spec: string): boolean {
  return spec.startsWith('.') || ALIASES.some(([rx]) => rx.test(spec))
}

/**
 * Does this path — a specifier or a resolved file — name the rule engine?
 *
 * The directory form is handled explicitly. `./rules/index` and
 * `src/shared/rules/index.ts` have a basename of `index`, so a plain
 * last-segment match reports them clean; turning `rules.ts` into `rules/`
 * during a refactor is the ordinary way a guard like this stops guarding, and
 * it is one line to close.
 */
function isRuleSpecifier(spec: string): boolean {
  const parts = spec.replace(/\.[cm]?[jt]sx?$/i, '').split(/[/\\]/)
  const base = parts.pop() ?? ''
  if (base === 'index') return RULE_MODULE.test(parts.pop() ?? '')
  return RULE_MODULE.test(base)
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
  for (const c of candidates) if (existsSync(c) && statSync(c).isFile()) return c
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
    // (text, readImportFiles, detectJavaScriptImports) — the second and third
    // arguments are what pick up `require()` and `await import()`, which is the
    // idiom this codebase already uses for its heaviest modules.
    for (const ref of ts.preProcessFile(readFileSync(file, 'utf8'), true, true).importedFiles) {
      const to = resolveSpecifier(file, ref.fileName)
      edges.push({ from: file, spec: ref.fileName, to })
      if (to !== null && !files.has(to)) queue.push(to)
    }
  }
  return { files, edges }
}

const SEED_FILES = [join(ROOT, 'src/main/services/mcpServer.ts'), ...tsFilesIn(join(ROOT, 'src/cli'))]

// ---------------------------------------------------------------------------
// The guard on the guard
// ---------------------------------------------------------------------------

describe('the walker this file depends on', () => {
  const DIR = join(ROOT, '.tmp-tests', 'ruleClosure')

  beforeAll(() => {
    mkdirSync(DIR, { recursive: true })
    writeFileSync(join(DIR, 'rules.ts'), 'export const engine = 1\n')
    writeFileSync(join(DIR, 'reexport.ts'), "export * from './rules'\n")
    writeFileSync(
      join(DIR, 'entry.ts'),
      ["export {} from './reexport'", "export const lazy = () => import('./rules')"].join('\n')
    )
  })
  afterAll(() => rmSync(DIR, { recursive: true, force: true }))

  it('finds a rules module reached by a re-export or a dynamic import', () => {
    // Without this, a closure that quietly returned nothing would make every
    // assertion below pass while proving nothing at all — which is worse than
    // no guard, because it reads as one.
    const { files, edges } = importClosure([join(DIR, 'entry.ts')])
    expect([...files].map((f) => relative(DIR, f)).sort()).toEqual([
      'entry.ts',
      'reexport.ts',
      'rules.ts'
    ])
    expect(edges.filter((e) => isRuleSpecifier(e.spec)).map((e) => e.spec)).toEqual([
      './rules',
      './rules'
    ])
  })

  it('matches both halves of the module and nothing that merely rhymes', () => {
    for (const spec of ['./rules', '../../shared/rules', '../services/rules.js', './rules/index']) {
      expect(isRuleSpecifier(spec), spec).toBe(true)
    }
    for (const spec of ['./ruleset', './rulesPanel', 'node:path', '../../shared/jobs']) {
      expect(isRuleSpecifier(spec), spec).toBe(false)
    }
  })
})

// ---------------------------------------------------------------------------
// 1. Static: the transitive import closure
// ---------------------------------------------------------------------------

const MUST_BE_IN_CLOSURE = [
  'src/main/services/mcpServer.ts',
  'src/main/services/policyEngine.ts',
  'src/main/services/approvals.ts',
  'src/shared/mcp.ts',
  'src/cli/bridge.ts'
]

describe('nothing an agent can reach imports the rule engine', () => {
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

  it('followed every local import it found', () => {
    // A specifier the walker cannot resolve is not an offender AND is not
    // walked, so a rename or a new path alias would defeat both assertions
    // below with nothing going red.
    const unresolved = edges
      .filter((e) => e.to === null && isLocalSpecifier(e.spec))
      .map((e) => `${relative(ROOT, e.from)} -> '${e.spec}'`)
    expect(unresolved, `Teach resolveSpecifier about these:\n  ${unresolved.join('\n  ')}`).toEqual([])
  })

  it('imports neither the engine nor the rule vocabulary', () => {
    const offenders = edges
      .filter((e) => isRuleSpecifier(e.spec))
      .map((e) => `${relative(ROOT, e.from)} imports '${e.spec}'`)
    expect(
      offenders,
      `A module reachable from the MCP bridge or the ShellPilot CLI now imports the rule ` +
        `engine.\n\n${offenders.join('\n')}\n\n` +
        `DURABILITY DEFEATS REVOCATION, and a rule is the worst case of it. denyAllPending() ` +
        `resolves requests that are PENDING; a rule between firings has none — no request, no ` +
        `session, no open channel and no process, only a row in a file holding a human's ` +
        `approval record. The switch would return cleanly, report a number, and the rule would ` +
        `run commands on the estate that night anyway.\n\n` +
        `If a shared helper was hoisted into a module both sides import, move the helper, not ` +
        `this assertion.`
    ).toEqual([])
  })

  it('has no rules module anywhere in the closure', () => {
    // Belt and braces: catches a reach that arrived through a path alias or a
    // re-export chain whose specifier text never says "rules".
    const offenders = [...relFiles].filter(isRuleSpecifier)
    expect(offenders, `These rule modules are agent-reachable: ${offenders.join(', ')}`).toEqual([])
  })
})

// ---------------------------------------------------------------------------
// 2. Vocabulary: the permission model
// ---------------------------------------------------------------------------

describe('the AI permission model has no word for a rule', () => {
  it('grants no capability naming a rule, a trigger or an automation', () => {
    expect(AI_CAPABILITIES.length, 'AI_CAPABILITIES is empty — nothing was checked').toBeGreaterThan(0)
    const rx = /\brule|automat|trigger|when.?then/i
    const offenders = AI_CAPABILITIES.filter((c) => rx.test(c.id) || rx.test(c.label)).map(
      (c) => `${c.id} (${c.label})`
    )
    expect(
      offenders,
      `A capability that names a rule has appeared: ${offenders.join(', ')}. "let the agent set ` +
        `up the automation" is the natural next request, and this is where that conversation has ` +
        `to happen instead of it landing in a diff. There is no value of it — not even ASK — ` +
        `that makes it safe, because what it grants is a consent record that outlives every ask ` +
        `and that the kill switch has no way to find.`
    ).toEqual([])
  })
})

// ---------------------------------------------------------------------------
// 3. Literal: the words, in the files that must not say them
// ---------------------------------------------------------------------------

const RULE_SYMBOLS = [
  'RuleEngine',
  'ruleEngine',
  'shared/rules',
  'services/rules',
  'sanitiseRule',
  'ruleMatches',
  'verifyRuleAction',
  'checkRuleLimit',
  'ruleCreationConfirmation',
  'RULE_UNATTENDED_PHRASE',
  'rules:list',
  'rules:create',
  'rules:enable',
  'rules:remove',
  'rules:sweep'
]

describe('what must NOT be able to reach this', () => {
  it('the MCP server names nothing from the rule engine', () => {
    const mcp = read('src/main/services/mcpServer.ts')
    for (const forbidden of RULE_SYMBOLS) expect(mcp, forbidden).not.toContain(forbidden)
  })

  it('the CLI bridge names nothing from the rule engine either', () => {
    // The second agent-facing surface, and the one with no listTools to
    // interrogate at runtime.
    for (const file of tsFilesIn(join(ROOT, 'src/cli'))) {
      const src = readFileSync(file, 'utf8')
      for (const forbidden of RULE_SYMBOLS) {
        expect(src, `${relative(ROOT, file)} / ${forbidden}`).not.toContain(forbidden)
      }
    }
  })

  it('the engine reaches no agent-facing module', () => {
    // The other direction of the same boundary, matching the assertion
    // tests/jobsNotExposed.test.ts makes about the job runner. An engine that
    // could create an approval request is an engine that could answer one.
    const engine = read('src/main/services/rules.ts')
    for (const forbidden of ['mcpServer', 'mcpAuth', 'approvals', 'policyEngine', 'policyStore']) {
      expect(engine, forbidden).not.toContain(forbidden)
    }
  })

  it('the engine holds no credential of its own', () => {
    // Everything it acts with is injected — the job launcher, the webhook, the
    // target resolver. Importing the webhook module directly would pull
    // `services/secrets` in, which is on MODULE_FORBIDDEN_IMPORTS, for the sake
    // of one function call.
    const engine = read('src/main/services/rules.ts')
    const closure = [...importClosure([join(ROOT, 'src/main/services/rules.ts')]).files].map((f) =>
      relative(ROOT, f).split('\\').join('/')
    )
    const violations = closure.filter((f) => MODULE_FORBIDDEN_IMPORTS.some((bad) => f.includes(bad)))
    expect(violations, `the rule engine reaches: ${violations.join(', ')}`).toEqual([])
    for (const forbidden of ['credentialResolver', 'webhookAlerts', 'jobRunner', 'jobDetached']) {
      expect(engine, forbidden).not.toContain(forbidden)
    }
  })
})
