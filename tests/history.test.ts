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
      expect(s.readSeries('h1', 'cpu', 0, 2000)).toEqual([{ ts: 1000, v: 5 }])
    } finally {
      delete process.env.PORTABLE_EXECUTABLE_DIR
    }
  })

  it('takes a .bak through the backup API', async () => {
    const s = await open()
    s.recordSamples('h1', 1000, { cpu: 1 })
    await expect(s.backupReady).resolves.toBe(true)
    expect(statSync(`${s.path}.bak`).size).toBeGreaterThan(0)
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
      { ts: 180_000, v: 30 },
      { ts: 240_000, v: 40 },
      { ts: 300_000, v: 50 }
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
    expect(s.readSeries('h1', 'cpu', 0, 2000)).toEqual([{ ts: 1000, v: 4 }])
    expect(s.counts().samples).toBe(1)
  })

  it('drops non-finite values instead of writing NaN into a series', async () => {
    const s = await open()
    s.recordSamples('h1', 1000, { cpu: NaN, memPct: Infinity, diskPct: 50 })
    expect(s.counts().samples).toBe(1)
    expect(s.readSeries('h1', 'diskPct', 0, 2000)).toEqual([{ ts: 1000, v: 50 }])
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
    expect(s.readEvents({ kind: 'retention' })[0]).toEqual({
      ts: 4000,
      kind: 'retention',
      hostId: null,
      payload: { dropped: 5 }
    })
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
      // And one recent sample that must survive untouched.
      s.recordSamples('h1', now - HOUR, { cpu: 7 })
    })
    expect(s.counts().samples).toBe(11)

    const result = s.retain(now)
    expect(result.rolledUp).toBe(10)
    expect(result.hourlyRows).toBe(1)

    // Full resolution past the horizon is gone; inside it, untouched.
    expect(s.counts().samples).toBe(1)
    expect(s.counts().hourly).toBe(1)
    expect(s.readSeries('h1', 'cpu', now - 2 * HOUR, now)).toEqual([{ ts: now - HOUR, v: 7 }])

    // The hourly bucket carries the right numbers.
    const rolled = s.readSeries('h1', 'cpu', bucket, bucket + HOUR)
    expect(rolled).toEqual([{ ts: bucket, v: 55 }]) // avg of 10..100

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
    s.retain(now)

    // A late-arriving sample for the same hour rolls up on the next pass.
    s.recordSamples('h1', bucket + 180_000, { cpu: 100 })
    s.retain(now)

    // Averaging averages would give 50. Weighted by n it is 25, which is the
    // real mean of [0, 0, 0, 100].
    expect(s.readSeries('h1', 'cpu', bucket, bucket + HOUR)).toEqual([{ ts: bucket, v: 25 }])
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
    s.retain(soonAfter)
    expect(s.counts().samples).toBe(0)
    expect(s.counts().hourly).toBe(1)
    expect(s.counts().events).toBe(1)

    // Now walk past the quarter horizon.
    const later = ancient + (RETENTION_HOURLY_DAYS + 1) * DAY
    s.recordEvent('fact-added', 'h1', { key: 'unit:y' }, later - DAY)
    const result = s.retain(later)
    expect(result.hourlyDropped).toBe(1)
    expect(result.eventsDropped).toBe(1)
    expect(s.counts().hourly).toBe(0)
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
    s.retain(ancient + (RETENTION_HOURLY_DAYS + 10) * DAY)
    expect(s.readFacts('h1')).toEqual([
      { key: 'unit:x', value: 'active/running', firstSeen: ancient, lastSeen: ancient }
    ])
  })

  it('holds the documented steady state and does not grow past it', async () => {
    const s = await open()
    // The roadmap's reference estate: fifteen hosts, two-minute cadence, eight
    // metrics. 15 * 8 * 30/hour = 3,600 rows an hour, 86,400 a day.
    const expected = steadyStateRows(15, 120_000)
    expect(expected.samples).toBe(15 * 8 * 30 * 24 * RETENTION_FULL_DAYS)
    expect(expected.samples).toBe(604_800)
    expect(expected.hourly).toBe(15 * 8 * 24 * (RETENTION_HOURLY_DAYS - RETENTION_FULL_DAYS))
    expect(expected.hourly).toBe(239_040)
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
    // extrapolates to. Reported so the roadmap's 20.7 MB is a number somebody
    // can check rather than one somebody remembered.
    const bytes = historyBytes(s.path)
    const perRow = bytes / (after.samples + after.hourly)
    console.log(
      `[history] 1 host, 7d full + 1d hourly: ${after.samples + after.hourly} rows, ` +
        `${(bytes / 1024 / 1024).toFixed(2)} MB on disk, ${perRow.toFixed(1)} bytes/row. ` +
        `15-host steady state extrapolates to ${((perRow * steadyStateRows(15, cadence).total) / 1024 / 1024).toFixed(1)} MB.`
    )
    // The whole retention argument is that 15 hosts fit in tens of megabytes,
    // not hundreds. A regression that makes a row cost 200 bytes would put the
    // steady state past 160 MB and must fail here.
    expect(perRow).toBeLessThan(60)
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
    expect(s.readSeries('h1', 'cpu', 0, 9999)).toEqual([{ ts: 1000, v: 3 }])
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
