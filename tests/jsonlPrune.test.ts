import { describe, expect, it, beforeEach, afterEach } from 'vitest'
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync, statSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { pruneJsonl } from '../src/main/services/jsonlPrune'

const DAY = 24 * 60 * 60 * 1000
const NOW = Date.UTC(2026, 8, 4, 12, 0, 0)
const line = (agoDays: number, id: string): string =>
  JSON.stringify({ id, timestamp: new Date(NOW - agoDays * DAY).toISOString() })

// The newest 100 lines survive regardless of age, so a handful of lines is
// never pruned however old they are -- which is the point of that floor, and
// which made the first version of every test below pass without a prune ever
// happening. Each case therefore needs a log longer than the floor.
const FILLER = 140
const recentFiller = (): string[] =>
  Array.from({ length: FILLER }, (_, i) => line(1, `filler-${i}`))

let dir: string
let file: string
beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), 'sp-prune-'))
  file = join(dir, 'log.jsonl')
})
afterEach(() => rmSync(dir, { recursive: true, force: true }))

describe('pruning a log on disk', () => {
  it('removes what is past the horizon and keeps the rest, in order', () => {
    writeFileSync(
      file,
      [line(500, 'old'), line(400, 'older'), ...recentFiller()].join('\n') + '\n'
    )
    expect(pruneJsonl(file, NOW)).toBe(2)
    const left = readFileSync(file, 'utf8').split('\n').filter(Boolean)
    expect(left).toEqual(recentFiller())
  })

  it('does not touch the file at all when nothing is due', () => {
    // A rename a day for no reason is a needless chance to lose a log. The
    // mtime is the observable proof that the common path leaves it alone.
    writeFileSync(file, recentFiller().join('\n') + '\n')
    const before = statSync(file).mtimeMs
    expect(pruneJsonl(file, NOW)).toBeNull()
    expect(statSync(file).mtimeMs).toBe(before)
  })

  it('leaves no temp file behind', () => {
    writeFileSync(file, [line(500, 'old'), ...recentFiller()].join('\n') + '\n')
    expect(pruneJsonl(file, NOW)).toBe(1)
    expect(existsSync(`${file}.pruning`)).toBe(false)
  })

  it('keeps the file readable as JSON lines, with a trailing newline', () => {
    // The next append does `appendFileSync(file, line + '\n')`. If the prune
    // left the file without a trailing newline, that append would glue itself
    // onto the last surviving entry and corrupt both.
    writeFileSync(file, [line(500, 'old'), ...recentFiller()].join('\n') + '\n')
    expect(pruneJsonl(file, NOW)).toBe(1)
    const raw = readFileSync(file, 'utf8')
    expect(raw.endsWith('\n')).toBe(true)
    for (const l of raw.split('\n').filter(Boolean)) expect(() => JSON.parse(l)).not.toThrow()
  })

  it('is a no-op on a file that is not there', () => {
    expect(pruneJsonl(join(dir, 'absent.jsonl'), NOW)).toBeNull()
  })

  it('keeps the mode private after rewriting', () => {
    // These files are 0600 because of what is in them. A prune that recreated
    // them at the default umask would quietly widen every one of them.
    writeFileSync(file, [line(500, 'old'), ...recentFiller()].join('\n') + '\n', { mode: 0o600 })
    expect(pruneJsonl(file, NOW)).toBe(1)
    expect(statSync(file).mode & 0o077).toBe(0)
  })
})
