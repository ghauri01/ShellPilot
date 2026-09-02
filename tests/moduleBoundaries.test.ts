import { describe, it, expect, beforeAll, afterAll } from 'vitest'
import { readFileSync, existsSync, mkdirSync, writeFileSync, rmSync } from 'node:fs'
import { dirname, join, relative, resolve } from 'node:path'
import ts from 'typescript'
import {
  MODULES,
  MODULE_FORBIDDEN_IMPORTS,
  MODULE_FORBIDDEN_BRIDGE,
  backfillModules,
  defaultModuleState,
  moduleEnabled
} from '../src/shared/modules'

// Optional first-party modules — plugin system part (a), and only (a).
//
// The rule the roadmap states and this enforces: a module may not read the
// vault, resolve credentials, register an MCP tool without a policy entry, or
// reach the local terminal. Those four are what the security model is made of.
//
// Enforced by walking the real import closure rather than trusting a
// convention, the same way tests/localTerminalNotExposed.test.ts does. A
// convention nobody enforces is not a boundary — it is a comment.

const ROOT = resolve(__dirname, '..')

// The files each module owns. Adding a module means adding its entry points
// here, deliberately, in a diff a reviewer sees.
const MODULE_FILES: Record<string, string[]> = {
  fleetSearch: ['src/renderer/src/lib/fleetSearch.ts', 'src/renderer/src/components/monitor/FleetSearch.tsx'],
  broadcast: [
    'src/shared/broadcast.ts',
    'src/main/services/broadcast.ts',
    'src/renderer/src/components/monitor/BroadcastPanel.tsx'
  ],
  logTail: [
    'src/shared/logtail.ts',
    'src/main/services/logTail.ts',
    'src/renderer/src/components/monitor/LogTailPanel.tsx'
  ],
  cron: ['src/shared/cron.ts', 'src/renderer/src/components/monitor/CronPanel.tsx'],
  docker: ['src/shared/docker.ts', 'src/main/services/docker.ts', 'src/renderer/src/components/docker/DockerPanel.tsx'],
  kubernetes: [
    'src/shared/kubernetes.ts',
    'src/main/services/kubernetes.ts',
    'src/renderer/src/components/kubernetes/KubernetesPanel.tsx'
  ]
}

// Non-relative specifiers the bundler still resolves inside this repo.
// tsconfig.web.json and electron.vite.config.ts both map `@/` at
// src/renderer/src, so `@/store/vault` is a first-party import that does not
// start with a dot. A walker that only follows `.` stops dead at the first
// aliased hop and reports a clean closure for a file that reaches anything.
const ALIASES: Record<string, string> = { '@/': join(ROOT, 'src/renderer/src/') }

function resolveImport(spec: string, from: string, aliases: Record<string, string>): string | null {
  const alias = Object.keys(aliases).find((a) => spec.startsWith(a))
  let base: string
  if (alias) base = resolve(aliases[alias], spec.slice(alias.length))
  else if (spec.startsWith('.')) base = resolve(dirname(from), spec)
  else return null
  for (const c of [base, `${base}.ts`, `${base}.tsx`, join(base, 'index.ts'), join(base, 'index.tsx')]) {
    if (existsSync(c) && !c.endsWith('/')) {
      try {
        if (readFileSync(c, 'utf8') !== undefined) return c
      } catch {
        /* directory */
      }
    }
  }
  return null
}

/**
 * The module specifier this node imports by, whatever syntax it used.
 *
 * `import` and `export ... from` are the obvious two. The others are not
 * decoration: `await import('./x')` is how src/main/services/ssh.ts and db.ts
 * already reach half of what they use, so a walker that ignores it lets a
 * module reach the vault through the one form of import the codebase uses most
 * for exactly the heavy, lazily-loaded things a module would want.
 */
function specifierOf(n: ts.Node): string | null {
  if (
    (ts.isImportDeclaration(n) || ts.isExportDeclaration(n)) &&
    n.moduleSpecifier &&
    ts.isStringLiteral(n.moduleSpecifier)
  ) {
    return n.moduleSpecifier.text
  }
  // `typeof import('./x')` in a type position.
  if (ts.isImportTypeNode(n) && ts.isLiteralTypeNode(n.argument) && ts.isStringLiteral(n.argument.literal)) {
    return n.argument.literal.text
  }
  // `import('./x')` and `require('./x')`.
  if (ts.isCallExpression(n) && n.arguments.length > 0 && ts.isStringLiteral(n.arguments[0])) {
    const callee = n.expression
    if (callee.kind === ts.SyntaxKind.ImportKeyword) return n.arguments[0].text
    if (ts.isIdentifier(callee) && callee.text === 'require') return n.arguments[0].text
  }
  return null
}

/** Every file reachable from `entry` by an import of any kind. */
function closure(entry: string, aliases: Record<string, string> = ALIASES): Set<string> {
  const seen = new Set<string>()
  const queue = [entry]
  while (queue.length) {
    const file = queue.pop()!
    if (seen.has(file) || !existsSync(file)) continue
    seen.add(file)
    const src = ts.createSourceFile(file, readFileSync(file, 'utf8'), ts.ScriptTarget.Latest, true)
    const visit = (n: ts.Node): void => {
      const spec = specifierOf(n)
      if (spec !== null) {
        const r = resolveImport(spec, file, aliases)
        if (r) queue.push(r)
      }
      ts.forEachChild(n, visit)
    }
    visit(src)
  }
  return seen
}

/**
 * Which forbidden `window.shellpilot` namespaces a file actually touches.
 *
 * Read off the syntax tree rather than grepped, so a namespace named in a
 * comment — including the comment in src/shared/modules.ts explaining this
 * rule — is not a violation.
 */
function bridgeUses(file: string): string[] {
  const src = ts.createSourceFile(file, readFileSync(file, 'utf8'), ts.ScriptTarget.Latest, true)
  const hits = new Set<string>()
  const visit = (n: ts.Node): void => {
    if (ts.isPropertyAccessExpression(n) && (MODULE_FORBIDDEN_BRIDGE as readonly string[]).includes(n.name.text)) {
      // `window.shellpilot.vault`, `window.shellpilot?.vault`, `bridge.vault`
      // where bridge was read off the global — the last hop is what names it.
      if (/(^|\W)shellpilot$/.test(n.expression.getText(src).trim())) hits.add(n.name.text)
    }
    ts.forEachChild(n, visit)
  }
  visit(src)
  return [...hits]
}

// The guard guards nothing the walker cannot see, so the walker is tested
// against a fixture in every import form the codebase actually uses. Written
// under .tmp-tests (gitignored, same as tests/vpnBinaries.test.ts) rather than
// into src, so a failure here cannot leave a stray import in shipped code.
describe('the walker itself', () => {
  const DIR = join(ROOT, '.tmp-tests', 'moduleClosure')
  const write = (name: string, body: string): string => {
    const p = join(DIR, name)
    writeFileSync(p, body)
    return p
  }

  beforeAll(() => {
    mkdirSync(DIR, { recursive: true })
    write('dynamic.ts', 'export const a = 1\n')
    write('deep.ts', 'export const b = 2\n')
    write('reexport.ts', "export * from './deep'\n")
    write('aliased.ts', 'export const c = 3\n')
    write('required.ts', 'export const d = 4\n')
    write('typeonly.ts', 'export const e = 5\n')
    write(
      'entry.ts',
      [
        "export { } from './reexport'",
        "export const lazy = () => import('./dynamic')",
        "import '@/aliased'",
        "const r = require('./required')",
        "export type T = typeof import('./typeonly')",
        'export const used = r'
      ].join('\n')
    )
  })
  afterAll(() => rmSync(DIR, { recursive: true, force: true }))

  it('follows every import form, not only the two with a keyword at the front', () => {
    // A closure that misses `await import()` or an aliased specifier reports a
    // clean bill of health for a file that reaches whatever it likes — which is
    // worse than no guard, because it reads as one.
    const found = [...closure(join(DIR, 'entry.ts'), { '@/': `${DIR}/` })].map((f) => relative(DIR, f)).sort()
    expect(found).toEqual([
      'aliased.ts',
      'deep.ts',
      'dynamic.ts',
      'entry.ts',
      'reexport.ts',
      'required.ts',
      'typeonly.ts'
    ])
  })

  it('sees a bridge call and ignores one that is only talked about', () => {
    const offender = write(
      'bridge.ts',
      [
        '// window.shellpilot.secrets is described here and never called.',
        'export const read = () => window.shellpilot?.vault.list()',
        'export const shell = () => window.shellpilot.local.open()'
      ].join('\n')
    )
    expect(bridgeUses(offender).sort()).toEqual(['local', 'vault'])
    expect(bridgeUses(join(DIR, 'dynamic.ts'))).toEqual([])
  })
})

describe('what a module may not reach', () => {
  for (const [id, files] of Object.entries(MODULE_FILES)) {
    it(`${id} cannot reach the vault, credentials, secrets or the local terminal`, () => {
      const reachable = new Set<string>()
      for (const f of files) {
        const abs = join(ROOT, f)
        // A module listed here whose files do not exist yet is a bug in this
        // list, not a pass.
        expect(existsSync(abs), `${f} is listed for ${id} but does not exist`).toBe(true)
        for (const r of closure(abs)) reachable.add(relative(ROOT, r))
      }
      const violations = [...reachable].filter((f) =>
        MODULE_FORBIDDEN_IMPORTS.some((forbidden) => f.includes(forbidden))
      )
      // If you are here because this failed: the failure is the feature. The
      // four things listed are what the security model is made of, and part (a)
      // exists precisely so it does not drift into part (b).
      expect(violations, `${id} reaches: ${violations.join(', ')}`).toEqual([])
    })

    it(`${id} does not reach them through the preload bridge either`, () => {
      // The import closure is blind to a global. `window.shellpilot.vault.list()`
      // returns every entry with its password in it, from a file whose imports
      // are spotless — and the renderer half of every module is exactly where
      // that is easy to write.
      //
      // Scoped to the module's OWN files rather than its closure, deliberately.
      // A module component imports the app store, the app store legitimately
      // drives the local terminal, and a closure-wide check would therefore
      // forbid every module from importing the store every other view uses.
      // The limit is real and worth stating: routing a vault read through a new
      // shared helper would pass this. It would also be a file added to a shared
      // directory in a diff a reviewer sees, which is the case this cannot cover
      // and review can.
      const offenders = files.flatMap((f) => bridgeUses(join(ROOT, f)).map((ns) => `${f} → shellpilot.${ns}`))
      expect(offenders, `${id} reaches: ${offenders.join(', ')}`).toEqual([])
    })
  }

  it('covers every module in the registry', () => {
    // A module with no entry in MODULE_FILES would be silently unchecked,
    // which is the same as having no boundary at all.
    expect(Object.keys(MODULE_FILES).sort()).toEqual(MODULES.map((m) => m.id).sort())
  })
})

describe('turning modules on and off', () => {
  it('treats an absent module as off, never on', () => {
    // The alternative means every upgrade silently enables whatever was added.
    expect(moduleEnabled({}, 'docker')).toBe(false)
    expect(moduleEnabled(undefined, 'docker')).toBe(false)
    expect(moduleEnabled({ docker: false }, 'docker')).toBe(false)
    expect(moduleEnabled({ docker: true }, 'docker')).toBe(true)
  })

  it('gives a fresh install the defaults', () => {
    const fresh = defaultModuleState()
    for (const m of MODULES) expect(fresh[m.id], m.id).toBe(m.defaultEnabled)
  })

  it('leaves new modules OFF on an existing install', () => {
    // An upgrade is not consent. The user has already decided what their app
    // looks like.
    const existing = backfillModules({ cron: true }, false)
    expect(existing.cron).toBe(true)
    for (const m of MODULES.filter((m) => m.id !== 'cron')) {
      expect(existing[m.id], m.id).toBe(false)
    }
  })

  it('never re-enables something the user turned off', () => {
    const state = backfillModules({ cron: false }, true)
    expect(state.cron).toBe(false)
  })

  it('does not mutate the state it was given', () => {
    const before = { cron: true }
    backfillModules(before, false)
    expect(before).toEqual({ cron: true })
  })
})

describe('part (a) has not drifted into part (b)', () => {
  it('has no way to load code from outside the repo', () => {
    // The whole distinction. A registry that can load an arbitrary path is a
    // third-party extension API with a different name, and this app's thesis
    // is that credentials never leave it.
    const src = readFileSync(join(ROOT, 'src/shared/modules.ts'), 'utf8')
    expect(src).not.toMatch(/\brequire\s*\(/)
    expect(src).not.toMatch(/import\s*\(/)
    expect(src).not.toMatch(/readFile|createRequire|vm\.|eval\(/)
  })

  it('declares nothing that fetches on enable without a verification story', () => {
    // Fetching a dependency at runtime is a supply-chain decision, not a
    // packaging one: it needs a pinned version, a checksum and a signature, or
    // it is remote code execution with a friendly button. Nothing does yet, and
    // the first thing that does cannot slip in unnoticed.
    expect(MODULES.filter((m) => m.fetchesOnEnable)).toEqual([])
  })
})
