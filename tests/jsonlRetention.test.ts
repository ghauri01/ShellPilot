import { describe, expect, it } from 'vitest'
import {
  JSONL_RETENTION_DAYS,
  retainedLines,
  timestampOf
} from '../src/shared/jsonlRetention'

const DAY = 24 * 60 * 60 * 1000
const NOW = Date.UTC(2026, 8, 4, 12, 0, 0)
const line = (agoDays: number, id = 'x'): string =>
  JSON.stringify({ id, timestamp: new Date(NOW - agoDays * DAY).toISOString() })

describe('what survives, and what must not be thrown away', () => {
  it('drops what is past the horizon and keeps what is inside it', () => {
    const lines = [line(400), line(370), line(300), line(1)]
    const { kept, dropped } = retainedLines(lines, { now: NOW, minKeep: 0 })
    expect(dropped).toBe(2)
    expect(kept).toEqual([line(300), line(1)])
  })

  it('keeps a line whose timestamp cannot be read', () => {
    // The worst possible reason to destroy an audit record is that we could not
    // understand it. A half-written line from a crash, or one written by a
    // newer build, is evidence -- and deleting it is not a tidy-up, it is the
    // removal of the only trace of whatever produced it.
    const lines = ['{ not json', JSON.stringify({ timestamp: 'not a date' }), line(400)]
    const { kept } = retainedLines(lines, { now: NOW, minKeep: 0 })
    expect(kept).toEqual(['{ not json', JSON.stringify({ timestamp: 'not a date' })])
  })

  it('keeps the newest lines however old they are', () => {
    // A vault used once and then left alone for two years should still be able
    // to say what happened that once, rather than opening on an empty log.
    const lines = [line(900), line(880), line(870)]
    const { kept, dropped } = retainedLines(lines, { now: NOW, minKeep: 2 })
    expect(dropped).toBe(1)
    expect(kept).toEqual([line(880), line(870)])
  })

  it('caps by count as well as age, dropping the oldest', () => {
    // Age alone does not bound a retry loop: an agent can write a great many
    // lines well inside the horizon.
    const lines = [line(5, 'a'), line(4, 'b'), line(3, 'c'), line(2, 'd')]
    const { kept } = retainedLines(lines, { now: NOW, maxLines: 2, minKeep: 0 })
    expect(kept).toEqual([line(3, 'c'), line(2, 'd')])
  })

  it('leaves a log that is entirely inside the horizon alone', () => {
    // The common case, and the one where a bug would be most expensive: this
    // runs at every startup, so anything it gets wrong it gets wrong to
    // everybody's log, every time.
    const lines = [line(10), line(5), line(0)]
    const { kept, dropped } = retainedLines(lines, { now: NOW })
    expect(dropped).toBe(0)
    expect(kept).toEqual(lines)
  })

  it('keeps a line written exactly on the boundary', () => {
    // `>= cutoff`, not `>`. A line is dropped for being OLDER than the horizon,
    // and one that is exactly the horizon is not older than it.
    const { kept } = retainedLines([line(JSONL_RETENTION_DAYS)], { now: NOW, minKeep: 0 })
    expect(kept).toHaveLength(1)
  })
})

describe('reading the timestamp', () => {
  it('reads an ISO string, which is what all three logs write', () => {
    expect(timestampOf(line(0))).toBe(NOW)
  })

  it('returns null rather than NaN for a value it cannot use', () => {
    // NaN compares false against everything, so a NaN leaking into the age
    // comparison would silently drop the line -- the exact outcome rule 1 is
    // there to prevent.
    expect(timestampOf('{"timestamp": 12345}')).toBeNull()
    expect(timestampOf('{"timestamp": "nope"}')).toBeNull()
    expect(timestampOf('nonsense')).toBeNull()
    expect(timestampOf('{}')).toBeNull()
  })
})
