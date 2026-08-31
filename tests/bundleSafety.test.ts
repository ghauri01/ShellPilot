import { describe, expect, it } from 'vitest'
import { readdirSync, readFileSync, statSync } from 'node:fs'
import { join, relative, resolve } from 'node:path'

// A source string that ends with the bare word `import` breaks the production
// build, and nothing else catches it.
//
// electron-vite injects its CommonJS shim after the last thing it reads as an
// ESM static import, and it finds those by running a regex over the finished
// bundle *as text* — it does not know which bytes are code and which are
// string contents. So a line like
//
//     '# Directives that can run a program are never carried over; the import',
//     '# report lists everything that was dropped or rejected.'
//
// matches as `import ',\n    '`, the shim is spliced into the middle of the
// array, and `npm run build` dies with "Unterminated string literal" pointing
// at generated code. `tsc` passes. Every unit test passes. Only the packaged
// app is broken, which is the worst place to find out.
//
// The rule is narrow on purpose: the word has to be the last thing before the
// closing quote. `'the import report lists...'` is fine; `'...the import'` is
// not. Rephrase rather than reformat.
//
// electron-vite: dist/chunks/lib-*.js, `ESMStaticImportRe`.

const ROOT = resolve(__dirname, '..')
const SRC = join(ROOT, 'src')
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

// A quoted literal whose final word is `import`, with **whitespace before it**.
//
// The whitespace matters and is not incidental: electron-vite's regex requires
// the word to be preceded by whitespace, a `;`, or the start of input. So
// `bridgeHas(api, 'import')` — where the quote itself precedes the word — is
// harmless and must not be flagged, while `'... the import'` is the real hazard.
// Template literals are included; the regex that misreads them does not care
// which quote character closed the string.
const TRAILING_IMPORT = /(['"`])(?:[^'"`\\\n]|\\.)*\s+import\1/g

describe('bundle safety', () => {
  const files = sourceFiles(SRC)

  it('finds source files to check', () => {
    expect(files.length).toBeGreaterThan(50)
  })

  it('has no string literal ending in the bare word "import"', () => {
    const offenders: string[] = []

    for (const file of files) {
      const text = readFileSync(file, 'utf8')
      const lines = text.split('\n')
      lines.forEach((line, i) => {
        // Skip comments: they are stripped before the shim regex ever runs, so
        // a comment ending in "import" is harmless — and this file's own
        // explanation above would otherwise fail its own rule.
        const trimmed = line.trim()
        if (trimmed.startsWith('//') || trimmed.startsWith('*') || trimmed.startsWith('/*')) return
        TRAILING_IMPORT.lastIndex = 0
        if (TRAILING_IMPORT.test(line)) {
          offenders.push(`${relative(ROOT, file)}:${i + 1}  ${trimmed}`)
        }
      })
    }

    expect(
      offenders,
      `These string literals end with the bare word "import", which makes electron-vite splice its ` +
        `CommonJS shim into the middle of them and breaks "npm run build" with an unterminated ` +
        `string. Rephrase so the word is not last — e.g. "the import report lists ..." instead of ` +
        `"... the import".\n\n${offenders.join('\n')}`
    ).toEqual([])
  })
})
