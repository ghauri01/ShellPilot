import { describe, expect, it } from 'vitest'
import { readdirSync, readFileSync, statSync } from 'node:fs'
import { join, relative, resolve } from 'node:path'

// The renderer test harness must not be able to reach the product.
//
// ShellPilot's standing constraint is no external runtime dependencies: what
// ships is Electron, the drivers, and this codebase. Test tooling is explicitly
// exempt from that — but "exempt" only holds while the exemption is enforced,
// and the enforcement is two facts that are easy to break by accident and
// invisible when broken:
//
//  1. jsdom and the testing-library packages sit in devDependencies. Everything
//     downstream depends on it: electron-builder ships `dependencies` into the
//     asar and nothing else, and `npm audit` in CI treats a runtime dependency
//     differently from a dev one. A stray `npm install --save` moves a 50-package
//     tree into the shipped app and nothing else in this suite would notice.
//
//  2. Nothing under src/ imports them. A dev dependency is only dev-only while
//     no production module reaches for it; the moment one does, the renderer
//     bundle carries jsdom and the packaged app fails to resolve it at runtime.
//
// This is a cheap standing check, not a build. It runs in the node environment
// like the rest of the main-process suite.

const ROOT = resolve(__dirname, '..')
const SRC = join(ROOT, 'src')

/** Everything added for item 29. */
const TEST_ONLY = [
  'jsdom',
  '@testing-library/react',
  '@testing-library/dom',
  '@testing-library/user-event'
]

interface Manifest {
  dependencies: Record<string, string>
  devDependencies: Record<string, string>
}

const pkg: Manifest = JSON.parse(readFileSync(join(ROOT, 'package.json'), 'utf8'))

const SKIP_DIRS = new Set(['node_modules', 'out', 'release', 'dist'])

function sourceFiles(dir: string): string[] {
  const out: string[] = []
  for (const entry of readdirSync(dir)) {
    if (SKIP_DIRS.has(entry)) continue
    const full = join(dir, entry)
    if (statSync(full).isDirectory()) out.push(...sourceFiles(full))
    else if (/\.(ts|tsx)$/.test(entry)) out.push(full)
  }
  return out
}

describe('renderer test harness containment', () => {
  it.each(TEST_ONLY)('%s is a dev dependency', (name) => {
    expect(Object.keys(pkg.devDependencies)).toContain(name)
  })

  it('none of them is a runtime dependency', () => {
    const leaked = TEST_ONLY.filter((name) => name in pkg.dependencies)
    expect(
      leaked,
      `These are test-only packages and must never be in "dependencies": electron-builder ships ` +
        `that list into the packaged app.\n\n${leaked.join('\n')}`
    ).toEqual([])
  })

  it('no file under src/ imports them', () => {
    const offenders: string[] = []
    // `from 'jsdom'`, `require('jsdom')`, `import('jsdom')` and subpaths of
    // each. Comments are not excluded: a commented-out import of jsdom in
    // production source is a plan, and this file is the place to argue with it.
    const pattern = new RegExp(
      `['"\`](${TEST_ONLY.map((n) => n.replace(/[/@]/g, '\\$&')).join('|')})(/[^'"\`]*)?['"\`]`
    )

    for (const file of sourceFiles(SRC)) {
      const text = readFileSync(file, 'utf8')
      text.split('\n').forEach((line, i) => {
        if (pattern.test(line)) offenders.push(`${relative(ROOT, file)}:${i + 1}  ${line.trim()}`)
      })
    }

    expect(
      offenders,
      `Production source must not reference the test harness. These packages are absent from a ` +
        `packaged build, so an import here is a runtime failure in the shipped app, not a test ` +
        `problem.\n\n${offenders.join('\n')}`
    ).toEqual([])
  })
})
