import { describe, it, expect } from 'vitest'
import { readFileSync, existsSync } from 'node:fs'
import { dirname, join, relative, resolve } from 'node:path'
import ts from 'typescript'
import {
  MODULES,
  MODULE_FORBIDDEN_IMPORTS,
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
  docker: ['src/shared/docker.ts', 'src/main/services/docker.ts', 'src/renderer/src/components/docker/DockerPanel.tsx']
}

function resolveImport(spec: string, from: string): string | null {
  if (!spec.startsWith('.')) return null
  const base = resolve(dirname(from), spec)
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

/** Every file reachable from `entry` by a relative import. */
function closure(entry: string): Set<string> {
  const seen = new Set<string>()
  const queue = [entry]
  while (queue.length) {
    const file = queue.pop()!
    if (seen.has(file) || !existsSync(file)) continue
    seen.add(file)
    const src = ts.createSourceFile(file, readFileSync(file, 'utf8'), ts.ScriptTarget.Latest, true)
    const visit = (n: ts.Node): void => {
      if (
        (ts.isImportDeclaration(n) || ts.isExportDeclaration(n)) &&
        n.moduleSpecifier &&
        ts.isStringLiteral(n.moduleSpecifier)
      ) {
        const r = resolveImport(n.moduleSpecifier.text, file)
        if (r) queue.push(r)
      }
      ts.forEachChild(n, visit)
    }
    visit(src)
  }
  return seen
}

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
