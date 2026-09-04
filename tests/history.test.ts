import { describe, it, expect, beforeEach, afterEach } from 'vitest'
import { existsSync, mkdtempSync, readdirSync, rmSync, statSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import {
  DISABLE_ENV,
  HISTORY_FILE,
  METRICS,
  RETENTION_FULL_DAYS,
  RETENTION_HOURLY_DAYS,
  historyBytes,
  loadHistory,
  resetHistoryModuleForTests,
  steadyStateRows,
  CAPACITY_METRIC_IDS_FOR_TESTS,
  EVENT_QUERIES_FOR_TESTS,
  FACTS_PREFIX_QUERY_FOR_TESTS,
  type HistoryStore
} from '../src/main/services/history'

const HOUR = 3_600_000
const DAY = 86_400_000

let dir: string
// Every store this file opens, so the teardown can settle each one's backup
// before the directory goes. The .bak is taken on a native async task holding
// the source database open; deleting the file out from under it kills the
// worker rather than raising anything JavaScript can catch, which is a flake
// that only appears when the machine is busy enough for the backup to still be
// running at teardown.
const opened: HistoryStore[] = []

beforeEach(() => {
  resetHistoryModuleForTests()
  delete process.env[DISABLE_ENV]
  opened.length = 0
  dir = mkdtempSync(join(tmpdir(), 'shellpilot-history-'))
})

afterEach(async () => {
  await Promise.all(opened.map((s) => s.backupReady.catch(() => false)))
  for (const s of opened) s.close()
  opened.length = 0
  delete process.env[DISABLE_ENV]
  resetHistoryModuleForTests()
  try {
    rmSync(dir, { recursive: true, force: true })
  } catch {
    /* a leftover temp dir is not worth failing a test over */
  }
})

async function open(at = dir): Promise<HistoryStore> {
  const s = await loadHistory(at)
  expect(s).not.toBeNull()
  opened.push(s!)
  return s!
}

describe('open', () => {
  it('creates its own file, never inside shellpilot-data.json', async () => {
    const s = await open()
    expect(s.path).toBe(join(dir, HISTORY_FILE))
    expect(existsSync(s.path)).toBe(true)
    // shellpilot-data.json is the backup payload backup.ts reads into the
    // encrypted export, and it is renderer-owned and rewritten wholesale on a
    // debounce. Observed host data landing there would silently change what a
    // user's exported backup contains.
    expect(existsSync(join(dir, 'shellpilot-data.json'))).toBe(false)
  })

  it('runs in WAL with a busy timeout and NORMAL sync', async () => {
    const s = await open()
    expect(s.journalMode).toBe('wal')
    expect(s.recovery).toBe('none')
    expect(s.sqliteVersion).toMatch(/^3\./)
  })

  it('falls back to TRUNCATE on the Windows portable target', async () => {
    // The portable build keeps data next to the exe, which is routinely a USB
    // stick or a roaming profile. WAL needs shared memory and real file locking
    // and gets neither there — on SMB it is unsupported outright.
    process.env.PORTABLE_EXECUTABLE_DIR = dir
    try {
      const s = await open()
      expect(s.journalMode).toBe('truncate')
      // And it still works, which is the actual requirement.
      s.recordSamples('h1', 1000, { cpu: 5 })
      expect(s.readSeries('h1', 'cpu', 0, 2000)).toEqual([{ ts: 1000, v: 5, res: 'full' }])
    } finally {
      delete process.env.PORTABLE_EXECUTABLE_DIR
    }
  })

  it('takes a .bak through the backup API', async () => {
    // Settled before anything is written, and that ordering is load-bearing
    // everywhere this file asserts the backup SUCCEEDED. `mod.backup` copies on
    // a libuv thread against this same connection, so a write landing while it
    // steps fails the copy outright — measured under a loaded full suite:
    // ERR_SQLITE_ERROR, errcode 0, "not an error". Writing first and awaiting
    // afterwards is therefore a coin toss, not a test.
    const s = await open()
    await expect(s.backupReady).resolves.toBe(true)
    expect(statSync(`${s.path}.bak`).size).toBeGreaterThan(0)
    // Renamed into place, so nothing is left half-written under either name.
    expect(existsSync(`${s.path}.bak.tmp`)).toBe(false)
  })

  it('renames the backup into place rather than writing onto the .bak', async () => {
    // The .bak is the only file the recovery ladder can restore from, and the
    // copy overwrites its destination from the first page. Written directly, a
    // backup that failed or was quit under left it truncated — measured, a
    // zero-byte file — and SQLite reads a zero-length file as a valid EMPTY
    // database, so the next launch "restored" from it and came up with nothing.
    // What lands under the real name must always be a whole database.
    const s = await open()
    await expect(s.backupReady).resolves.toBe(true)
    const { DatabaseSync } = await import('node:sqlite')
    const bak = new DatabaseSync(`${s.path}.bak`)
    try {
      expect(bak.prepare('PRAGMA integrity_check').get()).toEqual({ integrity_check: 'ok' })
      // A complete copy of THIS store, not an empty file that merely parses.
      expect(bak.prepare("SELECT v FROM meta WHERE k = 'schema'").get()).toBeDefined()
    } finally {
      bak.close()
    }
  })

  it('checkpoints the WAL back into the primary even with the backup in flight', async () => {
    // The realistic shutdown. main/index.ts deliberately does not await the
    // backup — nothing about quitting should wait on it — so `before-quit` can
    // and does close the store while that second connection is still open.
    //
    // SQLite checkpoints for you when the closing connection is the LAST one.
    // With the backup still running it is not, so without the explicit
    // checkpoint the close leaves a 4 MB WAL behind (measured) and a primary
    // missing everything in it. The next launch then either replays a sidecar
    // it was never told about or, if the sidecar is lost, silently comes up
    // short — which is precisely the "half a database" case the .bak exists to
    // rescue and would itself have been taken from.
    const s = await open()
    for (let i = 0; i < 3000; i++) s.recordSamples('h1', i * 60_000, { cpu: i % 100 })
    s.close()

    const wal = `${s.path}-wal`
    expect(existsSync(wal) ? statSync(wal).size : 0).toBe(0)
    await s.backupReady.catch(() => false)

    // And the primary is a complete database on its own.
    resetHistoryModuleForTests()
    const again = await open()
    expect(again.recovery).toBe('none')
    expect(again.readSeries('h1', 'cpu', 0, 3000 * 60_000)).toHaveLength(3000)
  })
})

describe('kill switch', () => {
  it('creates no file and returns null', async () => {
    process.env[DISABLE_ENV] = '1'
    const s = await loadHistory(dir)
    expect(s).toBeNull()
    expect(readdirSync(dir)).toEqual([])
  })

  it('leaves the sampler path working, because a null store is a no-op', async () => {
    process.env[DISABLE_ENV] = '1'
    const s = await loadHistory(dir)
    // This is the whole contract: every consumer holds `HistoryStore | null`
    // and the null branch is today's behaviour. Nothing may throw.
    expect(() => s?.recordSamples('h1', 1, { cpu: 1 })).not.toThrow()
    expect(s?.readSeries('h1', 'cpu', 0, 1) ?? []).toEqual([])
  })
})

describe('samples round-trip', () => {
  it('writes and reads a series back over a range', async () => {
    const s = await open()
    for (let i = 0; i < 10; i++) {
      s.recordSamples('web-1', i * 60_000, { cpu: i * 10, memPct: i })
    }
    const all = s.readSeries('web-1', 'cpu', 0, 10 * 60_000)
    expect(all.map((p) => p.v)).toEqual([0, 10, 20, 30, 40, 50, 60, 70, 80, 90])

    // A range is a range: the ends are inclusive and nothing outside it leaks.
    const window = s.readSeries('web-1', 'cpu', 3 * 60_000, 5 * 60_000)
    expect(window).toEqual([
      { ts: 180_000, v: 30, res: 'full' },
      { ts: 240_000, v: 40, res: 'full' },
      { ts: 300_000, v: 50, res: 'full' }
    ])

    // Series do not bleed across hosts or metrics.
    expect(s.readSeries('web-2', 'cpu', 0, 10 * 60_000)).toEqual([])
    expect(s.readSeries('web-1', 'netRx', 0, 10 * 60_000)).toEqual([])
    expect(s.readSeries('web-1', 'memPct', 0, 10 * 60_000).map((p) => p.v)).toEqual([
      0, 1, 2, 3, 4, 5, 6, 7, 8, 9
    ])
  })

  it('stores hosts as small integers, so the id length does not reach the rows', async () => {
    // The 21.9 bytes/row measurement assumes there is nothing in a row but four
    // small values. A server id repeated 86,400 times a day as a string would
    // be most of the file, so this is a size assertion wearing a schema costume:
    // two identical stores, one with a 3-character host id and one with a
    // 64-character one, must come out the same size to within a page.
    const rows = 20_000
    const sizes: number[] = []
    for (const id of ['h1', 'a-deliberately-long-server-identifier-0123456789abcdef-0123456789']) {
      const sub = mkdtempSync(join(dir, 'sz-'))
      resetHistoryModuleForTests()
      const s = await open(sub)
      await s.backupReady
      s.transaction(() => {
        for (let i = 0; i < rows; i++) s.recordSamples(id, i * 60_000, { cpu: i % 100 })
      })
      expect(s.readSeries(id, 'cpu', 0, rows * 60_000)).toHaveLength(rows)
      s.close()
      sizes.push(statSync(s.path).size)
    }
    // 62 extra characters x 20,000 rows would be 1.2 MB if the id were in the
    // row. One page of slack is the whole allowance.
    expect(Math.abs(sizes[0] - sizes[1])).toBeLessThanOrEqual(8192)
  })

  it('ignores unknown metric names rather than guessing an id', async () => {
    const s = await open()
    // A wrong metric id silently corrupts a series forever, which is far worse
    // than dropping a value nobody has defined yet.
    s.recordSamples('h1', 1000, { cpu: 4, bogus: 9 } as never)
    expect(s.readSeries('h1', 'cpu', 0, 2000)).toEqual([{ ts: 1000, v: 4, res: 'full' }])
    expect(s.counts().samples).toBe(1)
  })

  it('drops non-finite values instead of writing NaN into a series', async () => {
    const s = await open()
    s.recordSamples('h1', 1000, { cpu: NaN, memPct: Infinity, diskPct: 50 })
    expect(s.counts().samples).toBe(1)
    expect(s.readSeries('h1', 'diskPct', 0, 2000)).toEqual([{ ts: 1000, v: 50, res: 'full' }])
  })
})

describe('facts', () => {
  it('preserves first_seen and bumps last_seen in place', async () => {
    const s = await open()
    expect(s.upsertFact('web-1', 'unit:nginx.service', 'active/running', 1000)).toBe('created')
    expect(s.upsertFact('web-1', 'unit:nginx.service', 'active/running', 2000)).toBe('unchanged')
    expect(s.upsertFact('web-1', 'unit:nginx.service', 'active/running', 3000)).toBe('unchanged')

    const facts = s.readFacts('web-1')
    expect(facts).toHaveLength(1)
    expect(facts[0]).toEqual({
      key: 'unit:nginx.service',
      value: 'active/running',
      firstSeen: 1000,
      lastSeen: 3000
    })
    // One row for three sweeps. This is the 5x saving: sampled naively, forty
    // units on one host is 28,800 rows a day, none of them different.
    expect(s.counts().facts).toBe(1)
  })

  it('emits an event when a fact appears and when it changes, but not when it repeats', async () => {
    const s = await open()
    s.upsertFact('web-1', 'unit:nginx.service', 'active/running', 1000)
    s.upsertFact('web-1', 'unit:nginx.service', 'active/running', 2000)
    expect(s.upsertFact('web-1', 'unit:nginx.service', 'failed/failed', 3000)).toBe('changed')

    const events = s.readEvents({ hostId: 'web-1' })
    expect(events.map((e) => e.kind)).toEqual(['fact-changed', 'fact-added'])
    expect(events[0].ts).toBe(3000)
    // The event carries both sides. "nginx went from running to failed" is the
    // answer; "nginx is failed" is only half of it.
    expect(events[0].payload).toEqual({
      key: 'unit:nginx.service',
      from: 'active/running',
      to: 'failed/failed'
    })
    // first_seen survives the change: this unit has been here since 1000.
    expect(s.readFacts('web-1')[0]).toMatchObject({ firstSeen: 1000, lastSeen: 3000 })
  })

  it('retires facts that the probe no longer reports, and records that too', async () => {
    const s = await open()
    s.upsertFact('web-1', 'unit:nginx.service', 'active/running', 1000)
    s.upsertFact('web-1', 'unit:old.service', 'active/running', 1000)
    s.upsertFact('web-1', 'hostname', 'web-1.example', 1000)

    const removed = s.retireFacts('web-1', 2000, 'unit:', ['unit:nginx.service'])
    expect(removed).toBe(1)
    expect(s.readFacts('web-1').map((f) => f.key)).toEqual(['hostname', 'unit:nginx.service'])
    expect(s.readEvents({ hostId: 'web-1', kind: 'fact-removed' })[0].payload).toEqual({
      key: 'unit:old.service',
      value: 'active/running'
    })
  })

  it('treats an underscore in a unit name as a character, not a LIKE wildcard', async () => {
    const s = await open()
    // Asserted in BOTH directions on purpose, because each half alone passes
    // against a different bug. Escaping the prefix without an ESCAPE clause
    // matches nothing, so "retires 0" would look correct while the feature was
    // dead; an ESCAPE clause without escaping the prefix matches everything, so
    // "does not retire the neighbour" would be the only thing to catch it.
    s.upsertFact('h1', 'unit:foo_bar', 'active/running', 1000)
    s.upsertFact('h1', 'unit:fooXbar', 'active/running', 1000)
    s.upsertFact('h1', 'unit:other', 'active/running', 1000)
    expect(s.retireFacts('h1', 2000, 'unit:foo_', [])).toBe(1)
    expect(s.readFacts('h1').map((f) => f.key)).toEqual(['unit:fooXbar', 'unit:other'])
  })

  it('returns nothing for a host it has never seen', async () => {
    const s = await open()
    expect(s.readFacts('never-sampled')).toEqual([])
    expect(s.readEvents({ hostId: 'never-sampled' })).toEqual([])
  })
})

describe('events', () => {
  it('filters by host, kind and time, newest first', async () => {
    const s = await open()
    s.recordEvent('host-unreachable', 'a', { error: 'timeout' }, 1000)
    s.recordEvent('host-recovered', 'a', undefined, 2000)
    s.recordEvent('host-unreachable', 'b', { error: 'refused' }, 3000)
    s.recordEvent('retention', null, { dropped: 5 }, 4000)

    expect(s.readEvents().map((e) => e.ts)).toEqual([4000, 3000, 2000, 1000])
    expect(s.readEvents({ hostId: 'a' }).map((e) => e.ts)).toEqual([2000, 1000])
    expect(s.readEvents({ kind: 'host-unreachable' }).map((e) => e.hostId)).toEqual(['b', 'a'])
    expect(s.readEvents({ from: 2000, to: 3000 }).map((e) => e.ts)).toEqual([3000, 2000])
    expect(s.readEvents({ limit: 1 }).map((e) => e.ts)).toEqual([4000])
    // An estate-level event has no host and must survive the round trip as null.
    expect(s.readEvents({ kind: 'retention' })[0]).toMatchObject({
      ts: 4000,
      kind: 'retention',
      hostId: null,
      payload: { dropped: 5 }
    })
    // And every row carries its own position, so an inbox can page from it.
    expect(s.readEvents({ kind: 'retention' })[0].cursor.ts).toBe(4000)
  })

  it('an unknown host filter returns nothing, not everything', async () => {
    const s = await open()
    s.recordEvent('x', 'a', undefined, 1000)
    // Falling back to "no filter" here would be a quiet lie: a caller asking
    // about one host would be handed the whole estate's events.
    expect(s.readEvents({ hostId: 'zzz' })).toEqual([])
  })
})

describe('transactions', () => {
  it('rolls the whole batch back on a throw', async () => {
    const s = await open()
    s.recordSamples('h1', 1000, { cpu: 1 })
    expect(() =>
      s.transaction(() => {
        s.recordSamples('h1', 2000, { cpu: 2 })
        s.recordSamples('h1', 3000, { cpu: 3 })
        throw new Error('sweep blew up')
      })
    ).toThrow('sweep blew up')
    // A crash loses at most one sweep, and loses all of it rather than half.
    expect(s.readSeries('h1', 'cpu', 0, 9999).map((p) => p.ts)).toEqual([1000])
  })

  it('nests without a second BEGIN', async () => {
    const s = await open()
    // SQLite refuses a nested BEGIN, and a caller should not have to know
    // whether it is the outermost one.
    s.transaction(() => {
      s.transaction(() => s.recordSamples('h1', 1000, { cpu: 1 }))
      s.recordSamples('h1', 2000, { cpu: 2 })
    })
    expect(s.readSeries('h1', 'cpu', 0, 9999)).toHaveLength(2)
  })
})

describe('retention', () => {
  it('folds full-resolution rows past the horizon into hourly avg/min/max and drops them', async () => {
    const s = await open()
    const now = 30 * DAY
    const oldHour = now - 10 * DAY // well past the 7-day full-resolution horizon
    const bucket = Math.floor(oldHour / HOUR) * HOUR

    // Ten samples inside one hour, with a known avg/min/max.
    const values = [10, 20, 30, 40, 50, 60, 70, 80, 90, 100]
    s.transaction(() => {
      values.forEach((v, i) => s.recordSamples('h1', bucket + i * 60_000, { cpu: v }))
      // And one recent sample that must survive untouched. It is also what
      // tells the pass that `now` is a plausible time: retention refuses to
      // age out data against a clock far ahead of the newest row it can see.
      s.recordSamples('h1', now - HOUR, { cpu: 7 })
    })
    expect(s.counts().samples).toBe(11)

    const result = s.retain(now)
    expect(result.rolledUp).toBe(10)
    expect(result.hourlyRows).toBe(1)

    // Full resolution past the horizon is gone; inside it, untouched.
    expect(s.counts().samples).toBe(1)
    expect(s.counts().hourly).toBe(1)
    expect(s.readSeries('h1', 'cpu', now - 2 * HOUR, now)).toEqual([
      { ts: now - HOUR, v: 7, res: 'full' }
    ])

    // The hourly bucket carries the right numbers.
    const rolled = s.readSeries('h1', 'cpu', bucket, bucket + HOUR)
    expect(rolled).toEqual([{ ts: bucket, v: 55, res: 'hourly', min: 10, max: 100, n: 10 }])

    // readSeries stitches the two tiers together. A 30-day query must not have
    // a hole where the downsampling starts — that hole is exactly the bug a
    // two-table store invites, and it would read as "the host was off".
    const wide = s.readSeries('h1', 'cpu', 0, now)
    expect(wide.map((p) => p.ts)).toEqual([bucket, now - HOUR])
  })

  it('merges a second roll-up into the same bucket with a weighted average', async () => {
    const s = await open()
    const now = 30 * DAY
    const bucket = Math.floor((now - 10 * DAY) / HOUR) * HOUR

    s.recordSamples('h1', bucket, { cpu: 0 })
    s.recordSamples('h1', bucket + 60_000, { cpu: 0 })
    s.recordSamples('h1', bucket + 120_000, { cpu: 0 })
    // The sample the live sampler would have just written, which is what makes
    // `now` a plausible clock as far as the retention guard is concerned.
    s.recordSamples('h1', now - 60_000, { cpu: 1 })
    s.retain(now)

    // A late-arriving sample for the same hour rolls up on the next pass.
    s.recordSamples('h1', bucket + 180_000, { cpu: 100 })
    s.retain(now)

    // Averaging averages would give 50. Weighted by n it is 25, which is the
    // real mean of [0, 0, 0, 100].
    expect(s.readSeries('h1', 'cpu', bucket, bucket + HOUR)).toEqual([
      { ts: bucket, v: 25, res: 'hourly', min: 0, max: 100, n: 4 }
    ])
  })

  it('drops hourly rows and events past the quarter horizon', async () => {
    const s = await open()
    const ancient = 100 * DAY
    // Roll the ancient sample into the hourly tier while it is still inside the
    // quarter — two passes at two different "now"s, because a sample that is
    // past BOTH horizons is rolled up and dropped by the same pass and would
    // never prove the hourly tier ages out at all.
    s.recordSamples('h1', ancient, { cpu: 1 })
    s.recordEvent('fact-added', 'h1', { key: 'unit:x' }, ancient)
    const soonAfter = ancient + (RETENTION_FULL_DAYS + 1) * DAY
    // Each pass is anchored by a sample at its own "now": a pass whose clock is
    // days ahead of everything in the store is refused, deliberately.
    s.recordSamples('h1', soonAfter, { cpu: 1 })
    s.retain(soonAfter)
    // The anchor is inside the full-resolution window, so it stays a sample.
    expect(s.counts().samples).toBe(1)
    expect(s.counts().hourly).toBe(1)
    expect(s.counts().events).toBe(1)

    // Now walk past the quarter horizon.
    const later = ancient + (RETENTION_HOURLY_DAYS + 1) * DAY
    s.recordEvent('fact-added', 'h1', { key: 'unit:y' }, later - DAY)
    s.recordSamples('h1', later, { cpu: 1 })
    const result = s.retain(later)
    expect(result.hourlyDropped).toBe(1)
    expect(result.eventsDropped).toBe(1)
    // The ancient bucket is gone. The one hourly row left is the anchor sample
    // from the first pass, which has itself just aged past the full-resolution
    // horizon — a store in steady state always has both tiers occupied.
    expect(s.counts().hourly).toBe(1)
    expect(s.readSeries('h1', 'cpu', 0, ancient + HOUR)).toEqual([])
    // The recent event survives; the ancient one does not.
    expect(s.readEvents().map((e) => e.ts)).toEqual([later - DAY])
  })

  it('never ages out a fact', async () => {
    const s = await open()
    const ancient = 100 * DAY
    // first_seen is the answer to "how long has this unit been here", and it is
    // the whole reason facts are a table rather than a snapshot. A retention
    // pass that shortened it would silently rewrite the answer.
    s.upsertFact('h1', 'unit:x', 'active/running', ancient)
    const now = ancient + (RETENTION_HOURLY_DAYS + 10) * DAY
    s.recordSamples('h1', now, { cpu: 1 })
    s.retain(now)
    expect(s.readFacts('h1')).toEqual([
      { key: 'unit:x', value: 'active/running', firstSeen: ancient, lastSeen: ancient }
    ])
  })

  it('holds the documented steady state and does not grow past it', async () => {
    const s = await open()
    // Settled first, before a single row is written: the copy runs against this
    // same connection and a write landing while it steps fails it. See the
    // ordering note on 'takes a .bak through the backup API'.
    await expect(s.backupReady).resolves.toBe(true)
    // The roadmap's reference estate: fifteen hosts, two-minute cadence, eight
    // metrics. 15 * 8 * 30/hour = 3,600 rows an hour, 86,400 a day.
    // Literals, not the implementation's own formula retyped: writing
    // `15 * 8 * 30 * 24 * RETENTION_FULL_DAYS` here asserts that multiplication
    // works, and passes for any horizon anybody later changes.
    const expected = steadyStateRows(15, 120_000)
    expect(expected.samples).toBe(604_800)
    expect(expected.hourly).toBe(239_040)
    expect(RETENTION_FULL_DAYS).toBe(7)
    expect(RETENTION_HOURLY_DAYS).toBe(90)
    expect(METRICS.length).toBe(8)

    // Writing 604,800 rows in a unit test is a minute of CI for a number that
    // scales linearly, so this writes one host for eight days and checks that
    // the pass leaves exactly the arithmetic above predicts for that slice.
    const now = 20 * DAY
    const cadence = 120_000
    const days = 8
    const start = now - days * DAY
    s.transaction(() => {
      for (let t = start; t < now; t += cadence) {
        s.recordSamples('h1', t, {
          cpu: (t / cadence) % 100,
          memPct: 50,
          memUsed: 1,
          diskPct: 2,
          diskUsed: 3,
          netRx: 4,
          netTx: 5,
          uptime: 6
        })
      }
    })
    const written = days * 24 * 30 * METRICS.length
    expect(s.counts().samples).toBe(written)

    s.retain(now)
    const after = s.counts()
    const oneHost = steadyStateRows(1, cadence)
    // Seven days at full resolution, to the row.
    expect(after.samples).toBe(oneHost.samples)
    expect(after.samples).toBe(7 * 24 * 30 * 8)
    // And the eighth day folded into 24 hours x 8 metrics.
    expect(after.hourly).toBe(24 * METRICS.length)

    // A second pass with no new data is a no-op: retention converges rather
    // than eating into the window it is supposed to keep.
    const again = s.retain(now)
    expect(again.rolledUp).toBe(0)
    expect(s.counts().samples).toBe(after.samples)

    // The measured size of one host's steady-state week, and what fifteen
    // extrapolates to. Reported so the headline figure is a number somebody can
    // check rather than one somebody remembered.
    //
    // Measured on the primary AFTER the close checkpoints the WAL back into it.
    // Measuring while a WAL that the retention pass has just inflated is still
    // on disk mixes a transient into a steady-state number.
    //
    // The backup was settled at the top of this test, so the close below is not
    // racing a copy that is still holding this connection open.
    s.close()
    const primary = statSync(s.path).size
    const rows = after.samples + after.hourly
    const perRow = primary / rows
    console.log(
      `[history] 1 host, 7d full + 1d hourly: ${rows} rows, ` +
        `${(primary / 1024 / 1024).toFixed(2)} MB in the primary, ${perRow.toFixed(1)} bytes/row. ` +
        `15-host steady state extrapolates to ${((perRow * steadyStateRows(15, cadence).total) / 1024 / 1024).toFixed(1)} MB, ` +
        `about twice that on disk once the .bak is counted.`
    )
    // The whole retention argument is that 15 hosts fit in tens of megabytes,
    // not hundreds. A band, not a ceiling with 2.3x of slack in it: measured at
    // 19.1 bytes/row in the checkpointed primary (the 25.6 quoted elsewhere was
    // measured with a retention pass's WAL still on disk), so a doubling has to
    // fail here rather than pass with room to spare — and a collapse means rows
    // stopped being written at all.
    expect(perRow).toBeGreaterThan(12)
    expect(perRow).toBeLessThan(30)

    // And what the disk actually gives up. The .bak is a full second copy taken
    // at every clean launch, so the steady state is ~2x the primary — stated
    // here rather than left as a surprise, because this feature's whole
    // justification is that it must not become a cause of disk pressure.
    resetHistoryModuleForTests()
    const relaunched = await open()
    await expect(relaunched.backupReady).resolves.toBe(true)
    expect(statSync(`${relaunched.path}.bak`).size).toBeGreaterThan(primary * 0.9)
    expect(historyBytes(relaunched.path)).toBeGreaterThan(primary * 1.9)
  })
})

describe('corruption recovery', () => {
  it('restores from .bak when the primary is not a database', async () => {
    const first = await open()
    // Awaited, not polled: the .bak holds the source open until it finishes,
    // and closing underneath it leaves the WAL behind — which SQLite would then
    // cheerfully replay over the "corruption" below, so the test would pass
    // while proving nothing.
    await expect(first.backupReady).resolves.toBe(true)
    first.recordSamples('h1', 1000, { cpu: 42 })
    const path = first.path
    first.close()

    // Deliberately corrupt the primary: this is the "losing every server to one
    // bad write happened once" case, translated to a file SQLite must parse.
    writeFileSync(path, 'this is not a database, it is a sentence')
    resetHistoryModuleForTests()

    const second = await open()
    expect(second.recovery).toBe('restored-from-backup')
    // The backup was taken at open, BEFORE the sample, so its contents are the
    // empty schema. What matters is that it opened and is usable.
    expect(() => second.recordSamples('h1', 2000, { cpu: 1 })).not.toThrow()
    expect(second.readSeries('h1', 'cpu', 0, 9999)).toHaveLength(1)
    // The bad file is kept, not deleted: it is the only evidence if this is
    // ever reported.
    expect(readdirSync(dir).some((f) => f.includes('.corrupt-'))).toBe(true)
  })

  it('starts empty when there is no usable backup, and says so', async () => {
    const path = join(dir, HISTORY_FILE)
    writeFileSync(path, 'garbage')
    writeFileSync(`${path}.bak`, 'also garbage')

    const s = await open()
    // Losing samples is survivable. Refusing to launch is not.
    expect(s.recovery).toBe('started-empty')
    s.recordSamples('h1', 1000, { cpu: 3 })
    expect(s.readSeries('h1', 'cpu', 0, 9999)).toEqual([{ ts: 1000, v: 3, res: 'full' }])
  })

  it('does not call a zero-byte .bak a restore', async () => {
    // What a backup that died mid-write leaves behind, from either end: the
    // copy failed because a write raced it, or the app quit while it ran —
    // main/index.ts deliberately does not wait for it. Both used to truncate
    // the .bak in place, because the copy wrote straight onto it.
    //
    // SQLite reads a zero-length file as a valid EMPTY database, so
    // integrity_check answers 'ok' and the ladder cannot tell it from a real
    // backup. It reported 'restored-from-backup', main/index.ts recorded a
    // recovery event saying so, and the user's entire history was gone.
    // Starting empty is survivable; being told it was recovered is what sends
    // someone looking for data that no longer exists.
    const path = join(dir, HISTORY_FILE)
    writeFileSync(path, 'garbage')
    writeFileSync(`${path}.bak`, '')

    const s = await open()
    expect(s.recovery).toBe('started-empty')
    expect(s.readSeries('h1', 'cpu', 0, 9999)).toEqual([])
  })

  it('never throws out of loadHistory, whatever is on disk', async () => {
    // A directory where the file should be is the shape that a naive open
    // would throw on, and loadHistory's entire contract is that it does not.
    const path = join(dir, HISTORY_FILE)
    rmSync(path, { force: true })
    const { mkdirSync } = await import('node:fs')
    mkdirSync(path)
    await expect(loadHistory(dir)).resolves.toBeNull()

    // And a directory that does not exist at all.
    await expect(loadHistory(join(dir, 'nope', 'deeper'))).resolves.toBeNull()
  })
})

describe('a clock that steps forward', () => {
  // Every horizon in retain() is derived from wall-clock `now`. A VM restored
  // from a snapshot, a dual-boot machine with RTC skew or a dead CMOS battery
  // starts the app with Date.now() a year ahead, and index.ts runs a retention
  // pass seconds after launch — typically before NTP has stepped the clock
  // back. One committed transaction later the store is empty, with no error, no
  // log, and nothing on the next launch to say it happened. The .bak is a
  // pre-session snapshot and does not help.
  //
  // Backwards steps are benign: earlier cutoffs delete less. Only forward
  // destroys.
  async function stocked(now: number): Promise<HistoryStore> {
    const s = await open()
    s.transaction(() => {
      for (let t = now - 8 * DAY; t < now; t += 600_000) s.recordSamples('web-1', t, { cpu: 5 })
      s.recordEvent('fact-added', 'web-1', { key: 'unit:nginx.service' }, now - DAY)
    })
    return s
  }

  it('refuses a pass whose now is far ahead of the newest row it can see', async () => {
    const now = 400 * DAY
    const s = await stocked(now)
    const before = s.counts()
    expect(before.samples).toBeGreaterThan(0)

    const result = s.retain(now + 365 * DAY)

    expect(result.skipped).toBe('clock-ahead')
    expect(s.counts()).toEqual(before)
  })

  it('caps how much one pass may delete, even when the clock check passes', async () => {
    // The second line of defence. Once the sampler has written a single row at
    // the bogus time, the newest row IS the bogus now and the clock check has
    // nothing left to notice — so a pass that would drop the entire hourly tier
    // and every event has to refuse on the size of the deletion alone.
    const now = 400 * DAY
    const s = await open()
    s.transaction(() => {
      // 150 hours x 8 metrics = 1,200 hourly rows once folded. All of it well
      // past the seven-day full-resolution horizon, so one pass folds the lot.
      for (let h = 0; h < 150; h++) {
        s.recordSamples('web-1', now - (400 - h) * HOUR, {
          cpu: 1, memPct: 2, memUsed: 3, diskPct: 4, diskUsed: 5, netRx: 6, netTx: 7, uptime: 8
        })
      }
      s.recordSamples('web-1', now, { cpu: 1 })
    })
    s.retain(now)
    expect(s.counts().hourly).toBe(1200)

    const jumped = now + 365 * DAY
    // The row the sampler writes at the bogus time, which is what blinds the
    // clock check: the newest row IS the wrong clock now.
    s.recordSamples('web-1', jumped, { cpu: 1 })
    const result = s.retain(jumped)

    expect(result.skipped).toBe('blast-radius')
    expect(s.counts().hourly).toBe(1200)
  })

  it('cannot be disarmed by the record of its own refusal', async () => {
    // main/index.ts writes a 'retention-skipped' event when a pass refuses, so
    // that a store which quietly stopped ageing out says so about itself. That
    // event is written at the wrong clock's time — so if the guard treated
    // events as evidence of what time it is, the note it made about refusing
    // would be exactly what let the next pass through.
    const now = 400 * DAY
    const s = await stocked(now)
    const jumped = now + 365 * DAY
    expect(s.retain(jumped).skipped).toBe('clock-ahead')

    s.recordEvent('retention-skipped', null, { reason: 'clock-ahead' }, jumped)
    const before = s.counts()
    expect(s.retain(jumped).skipped).toBe('clock-ahead')
    expect(s.counts()).toEqual(before)
  })

  it('still runs a normal pass, and a backwards step is a no-op rather than a refusal', async () => {
    const now = 400 * DAY
    const s = await stocked(now)
    const forward = s.retain(now)
    expect(forward.skipped).toBeUndefined()
    expect(forward.rolledUp).toBeGreaterThan(0)

    // A clock that steps BACK makes every cutoff earlier, so the pass deletes
    // nothing. It must not be reported as refused — nothing was at risk.
    const after = s.counts()
    const backwards = s.retain(now - 30 * DAY)
    expect(backwards.skipped).toBeUndefined()
    expect(backwards.rolledUp).toBe(0)
    expect(s.counts()).toEqual(after)
  })
})

describe('file permissions', () => {
  it('restricts the WAL and shm on the run that creates them, not the one after', async () => {
    // The 0600 on the primary exists because this file holds an inventory of
    // every host, unit and open port in the estate. The WAL holds the same rows
    // — megabytes of them between checkpoints — and is created by the first
    // write, which happens before the chmod on the creating run. Measured on
    // HEAD: db 0600, wal 0644, shm 0644.
    if (process.platform === 'win32') return
    const s = await open()
    // Before the write, so the .bak below is a file that exists rather than an
    // absent one the default in `mode` would wave through: a write racing the
    // copy fails it. See the ordering note on 'takes a .bak through the backup
    // API'.
    await expect(s.backupReady).resolves.toBe(true)
    s.recordSamples('web-1', 1000, { cpu: 1 })
    const mode = (f: string): number => (existsSync(f) ? statSync(f).mode & 0o777 : 0o600)
    expect(mode(s.path)).toBe(0o600)
    expect(mode(`${s.path}-wal`)).toBe(0o600)
    expect(mode(`${s.path}-shm`)).toBe(0o600)
    expect(existsSync(`${s.path}.bak`)).toBe(true)
    expect(mode(`${s.path}.bak`)).toBe(0o600)
  })
})

describe('the event read path', () => {
  it('uses the (host, ts) index instead of scanning the ts index', async () => {
    // `(?1 IS NULL OR e.host = ?1)` is not sargable: SQLite cannot use an index
    // for a comparison that might be "match everything". Measured on HEAD, the
    // shipped statement plans as `SCAN e USING INDEX events_ts` — so
    // events_host_ts is never used by any query in the file (pure write cost)
    // and readEvents({hostId}) walks the whole ts index until it has collected
    // `limit` matches, or the entire table when there are none.
    const s = await open()
    const { DatabaseSync } = await import('node:sqlite')
    const db = new DatabaseSync(s.path)
    try {
      const plan = (sql: string): string =>
        (db.prepare(`EXPLAIN QUERY PLAN ${sql}`).all() as { detail: string }[])
          .map((r) => r.detail)
          .join(' | ')
      const plans = EVENT_QUERIES_FOR_TESTS.map(plan)
      // host+kind, host, kind, neither — the first two must reach the events
      // by host, and none of the four may scan the table itself.
      expect(plans[0]).toContain('events_host_ts')
      expect(plans[1]).toContain('events_host_ts')
      for (const p of plans) expect(p).not.toMatch(/SCAN events\b/)
    } finally {
      db.close()
    }
  })

  it('pages with a cursor rather than only a bigger limit', async () => {
    const s = await open()
    s.transaction(() => {
      for (let i = 1; i <= 10; i++) s.recordEvent('host-unreachable', 'web-1', { i }, i * 1000)
    })
    const first = s.readEvents({ limit: 4 })
    expect(first.map((e) => e.ts)).toEqual([10_000, 9000, 8000, 7000])

    const second = s.readEvents({ limit: 4, cursor: first[first.length - 1].cursor })
    expect(second.map((e) => e.ts)).toEqual([6000, 5000, 4000, 3000])

    const third = s.readEvents({ limit: 4, cursor: second[second.length - 1].cursor })
    expect(third.map((e) => e.ts)).toEqual([2000, 1000])
  })

  it('pages past events that share a timestamp', async () => {
    // Two events in the same millisecond is what a sweep produces. A cursor
    // that is only a timestamp either repeats them forever or skips one.
    const s = await open()
    s.transaction(() => {
      for (let i = 0; i < 6; i++) s.recordEvent('fact-added', 'web-1', { i }, 5000)
    })
    const seen: unknown[] = []
    let cursor = undefined as ReturnType<typeof s.readEvents>[number]['cursor'] | undefined
    for (let page = 0; page < 4; page++) {
      const rows = s.readEvents({ limit: 2, cursor })
      if (rows.length === 0) break
      seen.push(...rows.map((r) => (r.payload as { i: number }).i))
      cursor = rows[rows.length - 1].cursor
    }
    expect(seen.sort()).toEqual([0, 1, 2, 3, 4, 5])
  })
})

describe('the series read path', () => {
  it('carries min, max and the sample count through the hourly tier', async () => {
    // v_min/v_max/n are written on every roll-up and, on HEAD, unreadable:
    // hourlyRead selects v_avg alone, so anything older than a week has no
    // min/max through the interface at all. Capacity forecasting and threshold
    // backtesting are both questions about the max.
    const s = await open()
    const now = 30 * DAY
    const bucket = Math.floor((now - 10 * DAY) / HOUR) * HOUR
    s.transaction(() => {
      ;[10, 20, 30, 40].forEach((v, i) => s.recordSamples('h1', bucket + i * 60_000, { cpu: v }))
      s.recordSamples('h1', now, { cpu: 0 })
    })
    s.retain(now)

    const rolled = s.readSeries('h1', 'cpu', bucket, bucket + HOUR)
    expect(rolled).toEqual([{ ts: bucket, v: 25, res: 'hourly', min: 10, max: 40, n: 4 }])
  })

  it('marks which resolution every point came from', async () => {
    // A 30-day query returns hourly means and two-minute instantaneous
    // readings in one flat array. Without a marker nothing downstream can tell
    // a mean of thirty samples from a single reading.
    const s = await open()
    const now = 30 * DAY
    const old = Math.floor((now - 10 * DAY) / HOUR) * HOUR
    s.recordSamples('h1', old, { cpu: 90 })
    s.recordSamples('h1', now - HOUR, { cpu: 7 })
    s.retain(now)

    const points = s.readSeries('h1', 'cpu', 0, now)
    expect(points.map((p) => p.res)).toEqual(['hourly', 'full'])
    expect(points[1]).toEqual({ ts: now - HOUR, v: 7, res: 'full' })
  })
})

describe('the three capacity series, in one pass', () => {
  it('reads both tiers in one scan each, not one scan per metric', async () => {
    // The measured cost of the alternative is in the note above
    // CAPACITY_METRIC_IDS: three readSeries calls are three separate walks of
    // the same time range, because `samples` is keyed (ts, host, metric) and
    // host and metric are not in the seek. This is the same data, and the
    // metric ids are derived from METRICS rather than typed out — inserting a
    // metric into the middle of that array would otherwise silently read three
    // different series.
    expect(CAPACITY_METRIC_IDS_FOR_TESTS).toBe('1, 2, 4')
    expect(METRICS[0]).toBe('cpu')
    expect(METRICS[1]).toBe('memPct')
    expect(METRICS[3]).toBe('diskPct')

    const s = await open()
    const { DatabaseSync } = await import('node:sqlite')
    const db = new DatabaseSync(s.path)
    try {
      const plan = (sql: string): string =>
        (db.prepare(`EXPLAIN QUERY PLAN ${sql}`).all() as { detail: string }[])
          .map((r) => r.detail)
          .join(' | ')
      const full = plan(
        'SELECT ts, metric, v FROM samples WHERE host = ? AND ts >= ? AND ts <= ? ' +
          'AND metric IN (1, 2, 4) ORDER BY ts'
      )
      // One range seek on the primary key, and no sort afterwards: the key
      // leads with ts, so the rows arrive in the order the caller wants.
      expect(full).toContain('SEARCH samples USING PRIMARY KEY')
      expect(full).not.toContain('TEMP B-TREE')
    } finally {
      db.close()
    }
  })

  // Roadmap item 26 asks one host for cpu, memPct and diskPct over a window.
  // Three readSeries calls answer it and each one is a separate scan of the
  // same time range — see the note above `trendRead` for the plan and the
  // measurement. This is the same data through one scan.

  it('returns the three series a capacity question is about, and only those', async () => {
    const s = await open()
    s.transaction(() => {
      for (let i = 0; i < 5; i++) {
        s.recordSamples('h1', i * 60_000, {
          cpu: 10 + i,
          memPct: 20 + i,
          diskPct: 30 + i,
          netRx: 999,
          uptime: 5
        })
      }
    })
    const trends = s.readTrends('h1', 0, 5 * 60_000)
    expect(Object.keys(trends).sort()).toEqual(['cpu', 'diskPct', 'memPct'])
    expect(trends.cpu.map((p) => p.v)).toEqual([10, 11, 12, 13, 14])
    expect(trends.memPct.map((p) => p.v)).toEqual([20, 21, 22, 23, 24])
    expect(trends.diskPct.map((p) => p.v)).toEqual([30, 31, 32, 33, 34])
    // netRx and uptime were written and are deliberately not here: this read
    // exists to answer one question, not to be a general table dump.
    expect(trends.cpu[0]).toEqual({ ts: 0, v: 10, res: 'full' })
  })

  it('agrees with readSeries point for point, across both tiers', async () => {
    // The two paths must not be able to disagree. If they can, a panel and an
    // alert looking at the same disk can show different numbers, which is the
    // failure isDiskCritical exists to prevent one level up.
    const s = await open()
    const now = 30 * DAY
    const bucket = Math.floor((now - 10 * DAY) / HOUR) * HOUR
    s.transaction(() => {
      ;[10, 20, 30, 40].forEach((v, i) => s.recordSamples('h1', bucket + i * 60_000, { diskPct: v }))
      s.recordSamples('h1', now - HOUR, { diskPct: 77 })
      s.recordSamples('h1', now, { diskPct: 78 })
    })
    s.retain(now)

    const trends = s.readTrends('h1', 0, now)
    expect(trends.diskPct).toEqual(s.readSeries('h1', 'diskPct', 0, now))
    // And it is the stitched answer, hourly mean first with its extremes,
    // then the full-resolution readings.
    expect(trends.diskPct).toEqual([
      { ts: bucket, v: 25, res: 'hourly', min: 10, max: 40, n: 4 },
      { ts: now - HOUR, v: 77, res: 'full' },
      { ts: now, v: 78, res: 'full' }
    ])
  })

  it('reads only the window it was given', async () => {
    const s = await open()
    s.transaction(() => {
      for (let i = 0; i < 10; i++) s.recordSamples('h1', i * 60_000, { diskPct: i })
    })
    expect(s.readTrends('h1', 3 * 60_000, 5 * 60_000).diskPct.map((p) => p.v)).toEqual([3, 4, 5])
  })

  it('answers a host it has never seen with three empty series, not with everything', async () => {
    const s = await open()
    s.recordSamples('h1', 1000, { diskPct: 50 })
    const trends = s.readTrends('h2', 0, 9999)
    expect(trends).toEqual({ cpu: [], memPct: [], diskPct: [] })
  })

  it('does not leak one host samples into another host trends', async () => {
    const s = await open()
    s.transaction(() => {
      for (let i = 0; i < 20; i++) {
        s.recordSamples('web-1', i * 60_000, { diskPct: 10 })
        s.recordSamples('web-2', i * 60_000, { diskPct: 90 })
      }
    })
    // One scan of the time range sees every host in it. The host filter is the
    // only thing standing between web-1's chart and web-2's disk.
    const trends = s.readTrends('web-1', 0, 20 * 60_000)
    expect(new Set(trends.diskPct.map((p) => p.v))).toEqual(new Set([10]))
    expect(trends.diskPct).toHaveLength(20)
  })
})

describe('transaction', () => {
  it('refuses an async callback instead of committing nothing', async () => {
    // `transaction` never awaits: BEGIN, call fn, get back a pending promise,
    // COMMIT, return. Every write inside then lands afterwards in autocommit —
    // one fsync each, the whole reason this method exists gone, with no error
    // and no test failure. Worse, `depth` is back to 0 before the async body
    // runs, so a nested transaction() inside it issues a fresh BEGIN and
    // commits a partial slice.
    const s = await open()
    expect(() =>
      s.transaction((() => Promise.resolve('nope')) as never)
    ).toThrow(/async|promise/i)
    // And the BEGIN it opened is not left dangling: the next transaction works.
    s.transaction(() => s.recordSamples('h1', 1000, { cpu: 1 }))
    expect(s.readSeries('h1', 'cpu', 0, 9999)).toHaveLength(1)
  })
})

describe('a unit in a restart loop', () => {
  it('records the flapping once with a count, not once per sweep', async () => {
    // A unit stuck in a restart loop alternates activating/auto-restart and
    // failed/failed, so upsertFact reports 'changed' on nearly every sweep:
    // ~65,000 events over ninety days for ONE unit, all of them the same fact.
    const s = await open()
    const start = 1_000_000
    s.upsertFact('web-1', 'unit:flap.service', 'activating/auto-restart', start)
    s.transaction(() => {
      for (let i = 1; i <= 100; i++) {
        s.upsertFact(
          'web-1',
          'unit:flap.service',
          i % 2 === 0 ? 'activating/auto-restart' : 'failed/failed',
          start + i * 120_000
        )
      }
    })
    const events = s.readEvents({ hostId: 'web-1' })
    // One 'fact-added' plus a bounded number of coalesced 'fact-changed' rows:
    // the sweep cadence is two minutes, so 100 sweeps is 3h20m of flapping.
    expect(events.filter((e) => e.kind === 'fact-added')).toHaveLength(1)
    const changed = events.filter((e) => e.kind === 'fact-changed')
    expect(changed.length).toBeLessThanOrEqual(5)
    expect(changed.length).toBeGreaterThan(0)
    // And the count is not lost — the event says how many times it flapped.
    expect(
      changed.reduce((n, e) => n + Number((e.payload as { flaps?: number }).flaps ?? 1), 0)
    ).toBe(100)
    // The fact itself still tracks the latest value exactly.
    expect(s.readFacts('web-1')[0].value).toBe('activating/auto-restart')
  })

  it('still records two genuinely separate changes separately', async () => {
    const s = await open()
    s.upsertFact('web-1', 'unit:nginx.service', 'active/running', 1000)
    s.upsertFact('web-1', 'unit:nginx.service', 'failed/failed', 2000)
    // A day later, not a sweep later: this is a different incident.
    s.upsertFact('web-1', 'unit:nginx.service', 'active/running', 2000 + DAY)
    expect(s.readEvents({ hostId: 'web-1', kind: 'fact-changed' })).toHaveLength(2)
  })
})

describe('retiring facts by prefix', () => {
  it('does not retire a key that differs only in case', async () => {
    // SQLite's LIKE is ASCII case-insensitive; retireFacts' own keep-check is
    // case-sensitive. So `PKG:x` matched the `pkg:` sweep, missed the keep set
    // that holds `pkg:x`, and was deleted — the wrong row, silently.
    const s = await open()
    s.upsertFact('h1', 'pkg:openssl', '3.0.2', 1000)
    s.upsertFact('h1', 'PKG:openssl', '3.0.2', 1000)
    expect(s.retireFacts('h1', 2000, 'pkg:', ['pkg:openssl'])).toBe(0)
    expect(s.readFacts('h1').map((f) => f.key)).toEqual(['PKG:openssl', 'pkg:openssl'])
  })

  it('uses the primary key rather than a LIKE that cannot use it', async () => {
    const s = await open()
    const { DatabaseSync } = await import('node:sqlite')
    const db = new DatabaseSync(s.path)
    try {
      const detail = (db.prepare(`EXPLAIN QUERY PLAN ${FACTS_PREFIX_QUERY_FOR_TESTS}`).all() as {
        detail: string
      }[])
        .map((r) => r.detail)
        .join(' | ')
      // The host= half was always index-led; it is the KEY half that LIKE
      // could not use. Measured on the shipped SQL:
      // `SEARCH facts USING PRIMARY KEY (host=?)` — every key that host has.
      expect(detail).toContain('SEARCH facts USING PRIMARY KEY')
      expect(detail).toMatch(/key>\?/)
      expect(detail).not.toMatch(/SCAN facts\b/)
    } finally {
      db.close()
    }
  })
})

describe('writes after close', () => {
  it('says so rather than dropping them in silence', async () => {
    const s = await open()
    await s.backupReady
    s.close()
    const errors: string[] = []
    const original = console.error
    console.error = (...args: unknown[]): void => {
      errors.push(args.map(String).join(' '))
    }
    try {
      s.recordSamples('h1', 1000, { cpu: 1 })
      s.recordEvent('host-unreachable', 'h1', undefined, 1000)
      s.upsertFact('h1', 'k', 'v', 1000)
    } finally {
      console.error = original
    }
    // A sweep that lands after close is the LAST sweep of every session. It is
    // allowed to be dropped; it is not allowed to be dropped quietly.
    expect(errors.join('\n')).toMatch(/closed/i)
  })
})

describe('two samples in the same second', () => {
  it('keeps the later value, deterministically', async () => {
    // Timestamps are snapped to the second, so two sweeps 400 ms apart collide
    // on the primary key. Nothing pinned which value won; ON CONFLICT DO UPDATE
    // means the later write does, and a caller reading a series is entitled to
    // know that rather than discover it.
    const s = await open()
    s.recordSamples('h1', 1000, { cpu: 1 })
    s.recordSamples('h1', 1400, { cpu: 2 })
    expect(s.readSeries('h1', 'cpu', 0, 9999)).toEqual([{ ts: 1000, v: 2, res: 'full' }])
    expect(s.counts().samples).toBe(1)
  })
})

describe('historyBytes', () => {
  it('counts the .bak, because the disk does', async () => {
    // The .bak is a full second copy taken on every clean launch — roughly a
    // doubling at steady state. A size function that omits it reports half of
    // what the user's disk gave up, and it is the function the headline number
    // is computed from.
    //
    // The backup is settled BEFORE the rows go in, not after. It is taken at
    // open on a libuv thread against this same connection, so the transaction
    // below racing it is what failed the copy — two full-suite runs in ten,
    // ERR_SQLITE_ERROR errcode 0, and a .bak truncated to nothing. Nothing
    // about this test is about that race: it needs a .bak on disk and a store
    // with some rows in it, in that order.
    const s = await open()
    await expect(s.backupReady).resolves.toBe(true)
    s.transaction(() => {
      for (let i = 0; i < 5000; i++) s.recordSamples('h1', i * 60_000, { cpu: i % 100 })
    })
    s.close()
    const bak = statSync(`${s.path}.bak`).size
    expect(bak).toBeGreaterThan(0)
    expect(historyBytes(s.path)).toBeGreaterThanOrEqual(statSync(s.path).size + bak)
  })
})

// ===========================================================================
// Which jobs touched one host — roadmap item 28
// ===========================================================================
//
// A runbook's second half is "what was actually run the last three times this
// fired", and the only way to answer it is to ask which jobs ran against one
// host in a window. That is a NAMED read: a host, two bounds and a cap, with
// no way for a caller to say which kind, which state or which order.

describe('jobsForHost', () => {
  const AT = new Date('2026-02-01T00:00:00Z').getTime()

  function seed(s: HistoryStore, id: string, at: number, commands: string[], hosts: string[]): void {
    s.createJob({
      id,
      createdAt: at,
      workspaceId: null,
      title: `job ${id}`,
      kind: 'command',
      spec: { kind: 'command', title: `job ${id}`, steps: commands.map((command) => ({ command })) },
      risk: 'routine',
      confirmation: { kind: 'none' },
      confirmedAt: null,
      approval: null,
      state: 'done',
      targets: hosts.map((h, i) => ({ serverId: h, serverName: h.toUpperCase(), ord: i, state: 'done' as const }))
    })
  }

  it('returns the job together with this host own target row, not another host row', async () => {
    const s = await open()
    seed(s, 'j1', AT, ['journalctl --vacuum-time=2d'], ['a', 'b'])
    s.updateJobTarget('j1', 'a', { outcome: 'ok', exitCode: 0 })
    s.updateJobTarget('j1', 'b', { outcome: 'failed', exitCode: 1, error: 'no space left on device' })

    const forA = s.jobsForHost('a', AT - 1000, AT + 1000)
    expect(forA.length).toBe(1)
    expect(forA[0].job.id).toBe('j1')
    expect(forA[0].job.spec.steps[0].command).toBe('journalctl --vacuum-time=2d')
    expect(forA[0].host.serverId).toBe('a')
    expect(forA[0].host.outcome).toBe('ok')
    expect(forA[0].host.exitCode).toBe(0)

    const forB = s.jobsForHost('b', AT - 1000, AT + 1000)
    expect(forB[0].host.outcome).toBe('failed')
    expect(forB[0].host.error).toBe('no space left on device')
  })

  it('honours both bounds, inclusively', async () => {
    const s = await open()
    seed(s, 'before', AT - 1, ['a'], ['h'])
    seed(s, 'lower', AT, ['b'], ['h'])
    seed(s, 'upper', AT + 100, ['c'], ['h'])
    seed(s, 'after', AT + 101, ['d'], ['h'])
    expect(s.jobsForHost('h', AT, AT + 100).map((r) => r.job.id)).toEqual(['upper', 'lower'])
  })

  it('returns nothing for a host that ran nothing, and for no host at all', async () => {
    const s = await open()
    seed(s, 'j1', AT, ['a'], ['h'])
    expect(s.jobsForHost('other', AT - 1000, AT + 1000)).toEqual([])
    expect(s.jobsForHost('', AT - 1000, AT + 1000)).toEqual([])
  })

  it('is newest first and capped', async () => {
    const s = await open()
    for (let i = 0; i < 5; i++) seed(s, `j${i}`, AT + i * 1000, [`step-${i}`], ['h'])
    expect(s.jobsForHost('h', AT - 1000, AT + 100_000).map((r) => r.job.id)).toEqual([
      'j4',
      'j3',
      'j2',
      'j1',
      'j0'
    ])
    expect(s.jobsForHost('h', AT - 1000, AT + 100_000, 2).map((r) => r.job.id)).toEqual(['j4', 'j3'])
  })

  it('reads the host index rather than scanning a year of targets', async () => {
    // The read a runbook does on every open. job_target's primary key leads
    // with job_id, so without job_target_server this is a full scan of every
    // target row on every host.
    const s = await open()
    seed(s, 'j1', AT, ['a'], ['h'])
    const db = new (await import('node:sqlite')).DatabaseSync(s.path, { readOnly: true })
    const plan = (
      db
        .prepare(
          'EXPLAIN QUERY PLAN SELECT t.job_id AS job_id FROM job_target t JOIN job j ON j.id = t.job_id ' +
            'WHERE t.server_id = ?1 AND j.created_at >= ?2 AND j.created_at <= ?3 ' +
            'ORDER BY j.created_at DESC, j.id DESC LIMIT ?4'
        )
        .all() as { detail?: unknown }[]
    )
      .map((r) => String(r.detail))
      .join(' | ')
    db.close()
    expect(plan).toContain('job_target_server')
    expect(plan).not.toContain('SCAN t')
  })
})
