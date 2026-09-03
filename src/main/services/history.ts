import { app } from 'electron'
import { join } from 'node:path'
import { chmodSync, copyFileSync, existsSync, readdirSync, renameSync, rmSync, statSync } from 'node:fs'

// A durable store for samples, events and facts — roadmap item A.
//
// ----------------------------------------------------------------------------
// Why node:sqlite and not better-sqlite3
// ----------------------------------------------------------------------------
// This app has already paid the native-module bill once. @lydell/node-pty cost
// a lazy loader with a kill switch, two asarUnpack patterns, a files-exclusion
// glob that shipped two unsigned Windows binaries, a force-install in the
// release workflow, a verify script, a three-OS CI job, and library validation
// switched off in the hardened runtime. None of that is hypothetical.
//
// Electron 43.4.1 bundles Node 24.18.1, which ships SQLite as `node:sqlite`
// inside the binary this app already distributes: zero new dependencies, zero
// prebuilds, zero packaging surface, zero signing surface. The trade is a
// dependency risk for a platform-version risk — the SQLite version is whatever
// Electron bundles — and tests/historyCapability.test.ts is the guard for it.
//
// The escape hatch to better-sqlite3 stays open ONLY while the SQL never
// leaves this file. That is why this module exposes named methods and NOT a
// query surface. If a caller can pass SQL in, every later feature grows its own
// and the door closes. Add a method here instead.
//
// ----------------------------------------------------------------------------
// Why services[] and listeners[] are facts, not samples
// ----------------------------------------------------------------------------
// HostMetrics carries `services` and `listeners` and they are re-sampled every
// sweep. A host with forty systemd units stored naively as samples is 28,800
// rows a day for ONE host — five times the entire metric budget for the whole
// estate, none of it changing between sweeps. They are written only when they
// change, and the change is recorded as an event. See upsertFact/retireFacts.
//
// ----------------------------------------------------------------------------
// Why retention ships on day one
// ----------------------------------------------------------------------------
// Measured: the naive schema is 730 MB a year and climbing. Seven days at full
// resolution plus eighty-three days of hourly avg/min/max holds ~16 MB in the
// primary at steady state and never grows — call it ~32 MB on disk, because a
// full .bak is taken at every clean launch and historyBytes counts it. A tool
// that alerts on disk pressure must not become a cause of it, and a store that
// only gains a retention rule after someone complains has already written the
// year of rows.
//
// ----------------------------------------------------------------------------
// Its own file
// ----------------------------------------------------------------------------
// shellpilot-history.db, never inside shellpilot-data.json. That blob is the
// backup payload (backup.ts reads it into the encrypted export), so putting
// observed host data there would silently change what a user's exported backup
// contains. It is also renderer-owned and rewritten wholesale on a debounce.
//
// auditLog.ts and localSessionLog.ts are deliberately NOT migrated. They work,
// they are tested, and they answer a different question.

/** The eight numeric series sampled per host. Ids are the index + 1 and are
 *  stable forever: a new metric APPENDS, it never reorders. */
export const METRICS = [
  'cpu',
  'memPct',
  'memUsed',
  'diskPct',
  'diskUsed',
  'netRx',
  'netTx',
  'uptime'
] as const

export type Metric = (typeof METRICS)[number]

/** Everything else on HostMetrics — memTotal, diskTotal, cores, kernel, the
 *  unit list, the listener list — is a fact, because it does not change between
 *  sweeps. Storing it as a series would be the 5x mistake above. */
export type Facts = Record<string, string>

export interface SeriesPoint {
  ts: number
  v: number
  /** Which tier this point came from. A 30-day query returns hourly means and
   *  two-minute instantaneous readings in one array, and a consumer that cannot
   *  tell them apart is drawing a mean of thirty samples as if it were a
   *  reading. 'full' points carry no min/max; there is nothing to average. */
  res: 'full' | 'hourly'
  /** Hourly only: the extremes inside the bucket, and how many samples are
   *  behind the average. Capacity forecasting and threshold backtesting are
   *  both questions about the max, and the roll-up has always written these —
   *  they were simply not readable. */
  min?: number
  max?: number
  n?: number
}

/** Where a page of events ended, so the next page can start there. Two events
 *  in the same millisecond is what one sweep produces, so a timestamp alone
 *  either repeats a row forever or skips one; the row id breaks the tie. */
export interface EventCursor {
  ts: number
  id: number
}

export interface HistoryEvent {
  ts: number
  kind: string
  hostId: string | null
  payload: unknown
  /** This row's own position, to be handed back as EventFilter.cursor. */
  cursor: EventCursor
}

export interface EventFilter {
  hostId?: string
  kind?: string
  from?: number
  to?: number
  limit?: number
  /** Continue after this row. Events are newest-first, so a cursor means
   *  "strictly older than this one". */
  cursor?: EventCursor
}

export interface HistoryFact {
  key: string
  value: string
  firstSeen: number
  lastSeen: number
}

/** What upsertFact did, so a caller can tell "new" from "changed" from
 *  "same as last sweep" without reading back. */
export type FactOutcome = 'created' | 'changed' | 'unchanged'

export interface RetentionResult {
  /** Full-resolution rows folded into hourly buckets and deleted. */
  rolledUp: number
  /** NEW hourly buckets created. A late sample merged into a bucket that
   *  already existed does not count here — it changes a row rather than adding
   *  one, which is the number the size arithmetic cares about. */
  hourlyRows: number
  /** Hourly rows dropped for being past the horizon. */
  hourlyDropped: number
  /** Events dropped for being past the horizon. */
  eventsDropped: number
  /** Set when the pass refused to run and deleted nothing. See retain(). */
  skipped?: 'clock-ahead' | 'blast-radius'
}

/**
 * The whole store surface. Six named methods plus the retire half of
 * upsertFact, a retention pass and lifecycle. No SQL crosses this boundary in
 * either direction — see the note at the top of the file about why.
 */
export interface HistoryStore {
  recordSamples(hostId: string, at: number, values: Partial<Record<Metric, number>>): void
  readSeries(hostId: string, metric: Metric, from: number, to: number): SeriesPoint[]
  recordEvent(kind: string, hostId: string | null, payload?: unknown, at?: number): void
  readEvents(filter?: EventFilter): HistoryEvent[]
  upsertFact(hostId: string, key: string, value: string, at: number): FactOutcome
  readFacts(hostId: string): HistoryFact[]
  /** The delete half of upsertFact. Without it a decommissioned unit stays a
   *  fact forever and item C would have to grow its own SQL to clean up.
   *  Only ever called when the probe actually ran — `services: null` means
   *  "could not see", which is not the same as "there are none". */
  retireFacts(hostId: string, at: number, prefix: string, keep: Iterable<string>): number
  /** One BEGIN/COMMIT around fn. A sweep writes ~120 rows; without this that
   *  is 120 fsyncs instead of one, and a crash can leave half a sweep.
   *
   *  The intersection in the parameter type is what stops `async () => {}`
   *  compiling. Nothing here awaits, so an async callback would BEGIN, receive
   *  a pending promise, COMMIT an empty transaction and return — every write
   *  inside it landing afterwards in autocommit, one fsync each, with no error
   *  and nothing failing. Worse, `depth` would be back to 0 before the body
   *  ran, so a nested transaction() inside it would issue a fresh BEGIN and
   *  commit a partial slice. It is checked again at runtime, because a JS
   *  caller and a cast both get past the type. */
  transaction<T>(fn: () => T & (T extends PromiseLike<unknown> ? never : unknown)): T
  /** Fold anything older than the full-resolution horizon into hourly
   *  avg/min/max, then drop what is past the hourly horizon. */
  retain(now?: number): RetentionResult
  /** Rows currently held, for the size arithmetic and for tests. */
  counts(): { samples: number; hourly: number; events: number; facts: number }
  close(): void
  readonly path: string
  /** 'wal' normally; 'truncate' on the Windows portable target. */
  readonly journalMode: string
  readonly sqliteVersion: string
  /** Set when the primary was unreadable at open: what we did about it.
   *
   *  main/index.ts both logs this and, when it is not 'none', writes a
   *  'history-recovery' event into the store itself — a console line in a
   *  packaged app is not somewhere a user can look, and "why does this fleet
   *  have no past" is a question the store should be able to answer about
   *  itself. */
  readonly recovery: 'none' | 'restored-from-backup' | 'started-empty'
  /** Resolves when the .bak taken at open has finished, true if it succeeded.
   *  Startup deliberately does not wait on this; it exists so a caller that
   *  genuinely needs the backup on disk — a test, or a future export — can say
   *  so rather than poll for a file that is still being written. */
  readonly backupReady: Promise<boolean>
}

// ---------------------------------------------------------------------------
// Retention policy. Both horizons are documented in ROADMAP item A and the
// arithmetic below is what makes 20-ish MB steady state true rather than hoped.
// ---------------------------------------------------------------------------
const HOUR_MS = 3_600_000
const DAY_MS = 86_400_000
/** Full resolution is kept for this long. */
export const RETENTION_FULL_DAYS = 7
/** Hourly buckets are kept for this long in total, then dropped. */
export const RETENTION_HOURLY_DAYS = 90

// ---------------------------------------------------------------------------
// Two guards on the retention pass, because every horizon above is derived from
// wall-clock `now` and a wrong clock is not a rare machine.
//
// A VM restored from a snapshot, a dual-boot box with RTC skew, or a dead CMOS
// battery starts with Date.now() a year ahead, and main/index.ts runs a pass
// seconds after launch — typically before NTP has stepped the clock back. One
// committed transaction later the store is empty: no error, no log, and nothing
// on the next launch to say it happened. The .bak is a pre-session snapshot and
// does not help. Backwards steps are harmless — earlier cutoffs delete less.
//
// So: refuse a pass whose `now` is far ahead of the newest row the store can
// see, AND refuse one whose deletions would take most of what is there. Both,
// not either: the first is blind once the sampler has written a single row at
// the bogus time, and the second cannot tell a small store from a wrong one.
// ---------------------------------------------------------------------------

/** How far ahead of the newest row `now` may be before a pass is refused. */
export const RETENTION_CLOCK_GRACE_MS = 2 * 86_400_000
/** Below this many hourly+event rows the blast-radius guard does not apply: a
 *  store this small is not the disaster the guard exists for, and a legitimate
 *  first pass on a nearly-empty store routinely clears most of it. */
export const RETENTION_GUARD_MIN_ROWS = 1000
/** Above the floor, one pass may not delete more than this share of the hourly
 *  and event rows. Steady state drops about a ninetieth of the hourly tier a
 *  day; anything near half in one pass is a clock, not a horizon.
 *
 *  The roll-up is deliberately NOT counted here. Folding samples into hourly
 *  buckets is what the pass is FOR, and an app that has not run for a fortnight
 *  legitimately rolls up its whole full-resolution tier on the next launch. */
export const RETENTION_MAX_DROP_FRACTION = 0.5

/**
 * Steady-state row counts for a given estate, so a test can assert the
 * documented number rather than a number somebody typed.
 *
 * The reference estate in the roadmap is fifteen hosts at a two-minute cadence
 * with eight metrics: 15 * 8 * 30/hour = 3,600 rows an hour, 86,400 a day.
 */
export function steadyStateRows(hosts: number, cadenceMs: number): {
  samples: number
  hourly: number
  total: number
} {
  const perHostPerHour = (HOUR_MS / cadenceMs) * METRICS.length
  const samples = Math.round(hosts * perHostPerHour * 24 * RETENTION_FULL_DAYS)
  const hourly = Math.round(
    hosts * METRICS.length * 24 * (RETENTION_HOURLY_DAYS - RETENTION_FULL_DAYS)
  )
  return { samples, hourly, total: samples + hourly }
}

// ---------------------------------------------------------------------------
// Lazy load, exactly the localPty.ts discipline.
//
// node:sqlite is not a native module and cannot fail to dlopen, but the rest of
// the reasoning holds unchanged: an Electron whose bundled Node predates
// node:sqlite, a read-only or full userData directory, a file that will not
// open — none of those may stop ShellPilot from starting. History is the
// feature that fails, not the app. The renderer must render a fleet with no
// history at all, which it does today: nothing reads from here yet.
// ---------------------------------------------------------------------------

/** Kill switch, checked BEFORE the import so setting it genuinely prevents the
 *  module being loaded at all — the same contract as
 *  ELECTRON_DISABLE_LOCAL_TERMINAL. */
export const DISABLE_ENV = 'SHELLPILOT_DISABLE_HISTORY'

export const HISTORY_FILE = 'shellpilot-history.db'

type SqliteRow = Record<string, unknown>
interface Stmt {
  run(...params: unknown[]): { changes: number | bigint; lastInsertRowid: number | bigint }
  get(...params: unknown[]): SqliteRow | undefined
  all(...params: unknown[]): SqliteRow[]
}
interface Db {
  exec(sql: string): void
  prepare(sql: string): Stmt
  close(): void
}
interface SqliteModule {
  DatabaseSync: new (path: string, opts?: Record<string, unknown>) => Db
  StatementSync: unknown
  backup: (source: Db, destination: string, opts?: Record<string, unknown>) => Promise<number>
}

let sqlite: SqliteModule | null = null
let loadError: string | null = null

async function loadSqlite(): Promise<SqliteModule> {
  if (sqlite) return sqlite
  if (loadError) throw new Error(loadError)

  if (process.env[DISABLE_ENV] === '1') {
    loadError =
      `History is disabled on this machine (${DISABLE_ENV}=1). ` +
      `Unset it and restart ShellPilot to record samples. Everything else is unaffected.`
    throw new Error(loadError)
  }

  let raw: unknown
  try {
    raw = await import('node:sqlite')
  } catch (err) {
    // The realistic cause is an Electron whose bundled Node predates
    // node:sqlite (added in 22.5). Deliberately a different message from the
    // shape check below: they have different fixes.
    loadError =
      `History is unavailable on this machine: node:sqlite would not load ` +
      `(${err instanceof Error ? err.message : String(err)}). ShellPilot is otherwise unaffected.`
    throw new Error(loadError)
  }

  const mod = ((raw as { default?: unknown }).default ?? raw) as SqliteModule
  // The one risk this decision carries is that the platform, not a dependency,
  // owns the version. If a future Electron renames or drops any of these three
  // it must fail here with a sentence a bug report can quote, not as an opaque
  // "is not a constructor" at the first sweep.
  if (typeof mod.DatabaseSync !== 'function' || typeof mod.backup !== 'function') {
    loadError =
      `History is unavailable on this machine: node:sqlite loaded but does not export ` +
      `DatabaseSync/backup (got ${typeof mod.DatabaseSync}/${typeof mod.backup}) — the ` +
      `bundled SQLite module's shape is not what ShellPilot expects. ShellPilot is otherwise unaffected.`
    throw new Error(loadError)
  }
  sqlite = mod
  return mod
}

/** Test seam: forget the cached module and any recorded failure. */
export function resetHistoryModuleForTests(): void {
  sqlite = null
  loadError = null
}

const SCHEMA = `
CREATE TABLE IF NOT EXISTS meta (
  k TEXT PRIMARY KEY,
  v TEXT NOT NULL
) WITHOUT ROWID;

-- Hosts and metrics are interned to small integers. The samples table stores
-- the integer, never the string: 'srv-3f9c…' repeated 86,400 times a day is
-- most of the file, and the whole point of the measured 21.9 bytes/row is that
-- there is nothing in a row but four small values.
CREATE TABLE IF NOT EXISTS hosts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  host_key TEXT NOT NULL UNIQUE
);

CREATE TABLE IF NOT EXISTS metric_names (
  id INTEGER PRIMARY KEY,
  name TEXT NOT NULL UNIQUE
);

-- WITHOUT ROWID and PRIMARY KEY(ts, host, metric): the primary key IS the
-- table, so there is no second B-tree to pay for. Measured at 21.9 bytes/row.
-- ts leads because every read is a time range.
CREATE TABLE IF NOT EXISTS samples (
  ts INTEGER NOT NULL,
  host INTEGER NOT NULL,
  metric INTEGER NOT NULL,
  v REAL NOT NULL,
  PRIMARY KEY (ts, host, metric)
) WITHOUT ROWID;

-- The downsampled tier. v_avg/v_min/v_max rather than avg/min/max because the
-- bare names collide with the aggregate functions in the roll-up statement and
-- the resulting SQL is a trap for whoever edits it next. n is the sample count
-- behind the average, so a second roll-up into the same bucket can merge
-- correctly (weighted) instead of averaging averages.
CREATE TABLE IF NOT EXISTS samples_hourly (
  ts INTEGER NOT NULL,
  host INTEGER NOT NULL,
  metric INTEGER NOT NULL,
  v_avg REAL NOT NULL,
  v_min REAL NOT NULL,
  v_max REAL NOT NULL,
  n INTEGER NOT NULL,
  PRIMARY KEY (ts, host, metric)
) WITHOUT ROWID;

-- Alerts raised and resolved, jobs, fact changes, approvals. host is nullable:
-- some events are about the estate, not a host.
CREATE TABLE IF NOT EXISTS events (
  ts INTEGER NOT NULL,
  kind TEXT NOT NULL,
  host INTEGER,
  payload TEXT
);
CREATE INDEX IF NOT EXISTS events_ts ON events (ts);
CREATE INDEX IF NOT EXISTS events_host_ts ON events (host, ts);

-- One row per key, last_seen bumped in place. Shaped for item C (host facts):
-- a fact is a (host, key) with a value and a lifetime, and "when did this
-- first appear" is the question that makes the table worth having.
CREATE TABLE IF NOT EXISTS facts (
  host INTEGER NOT NULL,
  key TEXT NOT NULL,
  value TEXT NOT NULL,
  first_seen INTEGER NOT NULL,
  last_seen INTEGER NOT NULL,
  PRIMARY KEY (host, key)
) WITHOUT ROWID;
`

const SCHEMA_VERSION = '1'

// ---------------------------------------------------------------------------
// The event read path.
//
// `(?1 IS NULL OR e.host = ?1)` looks like one query plan for four filters and
// is: SCAN e USING INDEX events_ts, for all four. A comparison that might mean
// "match everything" is not sargable, so events_host_ts was never used by any
// query in this file — pure write cost — and readEvents({hostId}) walked the
// whole ts index until it had collected `limit` matches, or the entire table
// when there were none. Measured, both plans:
//
//   old  SCAN e USING INDEX events_ts
//   new  SEARCH e USING INDEX events_host_ts (host=? AND ts>? AND ts<?)
//
// So: four fixed WHERE shapes, each prepared twice (with and without a cursor),
// and the caller selects one. Every fragment here is a literal in this file —
// nothing is concatenated from caller input — so the rule that no SQL crosses
// the boundary is untouched, and the index earns its keep.
// ---------------------------------------------------------------------------

/** The four filter shapes, in the order readEvents selects them:
 *  host+kind, host, kind, neither. */
const EVENT_WHERE = [
  'e.host = ?1 AND e.kind = ?2',
  'e.host = ?1',
  'e.kind = ?2',
  '1 = 1'
] as const

/** Wider than any real timestamp, so "no bound" is still a sargable range
 *  rather than a NULL check. These are the ends of the JS Date range. */
const TS_MIN = -8_640_000_000_000_000
const TS_MAX = 8_640_000_000_000_000

function eventQuery(where: string, cursor: boolean): string {
  return (
    'SELECT e.ts AS ts, e.rowid AS id, e.kind AS kind, h.host_key AS host_key, e.payload AS payload ' +
    'FROM events e LEFT JOIN hosts h ON h.id = e.host ' +
    `WHERE ${where} AND e.ts >= ?3 AND e.ts <= ?4` +
    // The cursor's timestamp is also folded into ?4 by the caller, so the range
    // stays sargable and this pair only breaks the tie inside one millisecond.
    (cursor ? ' AND (e.ts < ?6 OR e.rowid < ?7)' : '') +
    ' ORDER BY e.ts DESC, e.rowid DESC LIMIT ?5'
  )
}

/** Read-only, for the query-plan guard in tests/history.test.ts. Exporting the
 *  text of this module's own statements is not a query surface: nothing here
 *  lets a caller pass SQL in, which is the property the better-sqlite3 escape
 *  hatch depends on. */
export const EVENT_QUERIES_FOR_TESTS: readonly string[] = EVENT_WHERE.map((w) => eventQuery(w, false))

/** A prefix sweep as a primary-key range rather than a LIKE.
 *
 *  Two reasons, and the correctness one is the important one. SQLite's LIKE is
 *  ASCII case-insensitive while retireFacts' own keep-check is case-sensitive,
 *  so a `PKG:x` sitting alongside a `pkg:x` matched a `pkg:` sweep, missed the
 *  keep set that holds `pkg:x`, and was deleted — the wrong row, silently. And
 *  the plans, measured: LIKE gives `SEARCH facts USING PRIMARY KEY (host=?)`,
 *  which reads every key that host has, against
 *  `SEARCH facts USING PRIMARY KEY (host=? AND key>? AND key<?)`. A range is
 *  case-sensitive like the keep-check, and needs no escaping. */
const FACTS_PREFIX_QUERY =
  'SELECT key, value FROM facts WHERE host = ? AND key >= ? AND key < ? ORDER BY key'

/** Read-only, for the same query-plan guard. */
export const FACTS_PREFIX_QUERY_FOR_TESTS = FACTS_PREFIX_QUERY

/** The exclusive upper bound of every key starting with `prefix`.
 *
 *  SQLite compares TEXT byte-wise by default and UTF-8 preserves code-point
 *  order, so incrementing the prefix's last code point is greater than every
 *  string that starts with it and less than everything that does not. */
function prefixUpperBound(prefix: string): string {
  const cps = Array.from(prefix)
  const last = cps.length > 0 ? cps[cps.length - 1].codePointAt(0) : undefined
  if (last === undefined || last >= 0x10ffff) return `${prefix}\u{10FFFF}`
  // Skip the surrogate range: a lone surrogate has no valid UTF-8 encoding.
  const next = last + 1 >= 0xd800 && last + 1 <= 0xdfff ? 0xe000 : last + 1
  return cps.slice(0, -1).join('') + String.fromCodePoint(next)
}

/** How long a run of changes to one fact is treated as one flapping incident.
 *
 *  A unit in a restart loop alternates activating/auto-restart and
 *  failed/failed, so every sweep is a change: ~65,000 events over ninety days
 *  for ONE unit, every one of them the same fact saying the same thing. Inside
 *  this window the changes are folded into the event already written, with a
 *  count, so the incident is recorded once and its size is not lost. */
const FLAP_WINDOW_MS = 3_600_000

/**
 * Open the store. NEVER throws: a machine where this will not work gets a null
 * and an app that behaves exactly as it does today.
 */
export async function loadHistory(dir?: string): Promise<HistoryStore | null> {
  try {
    const mod = await loadSqlite()
    const base = dir ?? app.getPath('userData')
    return openStore(mod, join(base, HISTORY_FILE))
  } catch (err) {
    console.error('[history] disabled:', err instanceof Error ? err.message : String(err))
    return null
  }
}

// Written temp-then-rename is the wrong shape for a database, so the crash
// story is store.ts's translated rather than copied: an integrity_check at
// open standing in for "is the JSON parseable", a .bak taken through SQLite's
// own backup API standing in for the copyFileSync, and — when both are gone —
// starting empty and saying so. Losing samples is survivable. Refusing to
// launch is not, which is the one thing store.ts's fallback ladder is really
// protecting against.
function openStore(mod: SqliteModule, path: string): HistoryStore {
  const bak = `${path}.bak`
  let recovery: HistoryStore['recovery'] = 'none'

  // Every open goes through here so the 0600 lands BEFORE the first write.
  // The -wal and -shm are created by that write — inside applyPragmas, long
  // before the old chmod site below the schema — so on the run that CREATES
  // the store they took the default umask and stayed world-readable for the
  // whole session. Measured on that path: db 0600, wal 0644, shm 0644, with
  // the WAL holding megabytes of the same inventory the 0600 is for.
  const open = (p: string): Db => {
    const d = new mod.DatabaseSync(p)
    restrictStore(p)
    return d
  }

  let db = mod.DatabaseSync ? open(path) : null
  if (!db) throw new Error('node:sqlite did not return a database')

  if (!checkIntegrity(db)) {
    db.close()
    // Keep the bad file rather than deleting it: it is the only evidence if
    // someone reports this, and a corrupt db is small next to what it replaced.
    const aside = `${path}.corrupt-${Date.now()}`
    try {
      renameSync(path, aside)
      for (const sidecar of ['-wal', '-shm']) {
        if (existsSync(`${path}${sidecar}`)) rmSync(`${path}${sidecar}`, { force: true })
      }
      console.error(`[history] primary failed integrity_check, moved aside to ${aside}`)
    } catch (err) {
      console.error('[history] could not move the corrupt primary aside:', err)
      try {
        rmSync(path, { force: true })
      } catch {
        /* if it cannot even be removed, the reopen below will fail and we
           surface that instead */
      }
    }

    let restored = false
    if (existsSync(bak)) {
      try {
        copyFileSync(bak, path)
        const retry = open(path)
        if (checkIntegrity(retry)) {
          db = retry
          restored = true
          recovery = 'restored-from-backup'
          console.error('[history] restored from backup')
        } else {
          retry.close()
          rmSync(path, { force: true })
        }
      } catch (err) {
        console.error('[history] backup unreadable too:', err)
        try {
          rmSync(path, { force: true })
        } catch {
          /* fall through to the empty open, which is the last rung */
        }
      }
    }

    if (!restored) {
      // The last rung. An empty store is a real outcome, and main/index.ts
      // both logs it and records a 'history-recovery' event, rather than
      // quietly showing a fleet with no past.
      db = open(path)
      recovery = 'started-empty'
    }
  }

  const journalMode = applyPragmas(db, path)
  db.exec(SCHEMA)
  db.exec(`INSERT INTO meta (k, v) VALUES ('schema', '${SCHEMA_VERSION}')
           ON CONFLICT(k) DO UPDATE SET v = excluded.v`)

  // Seed the metric lookup. Ids come from the METRICS index and never move,
  // so appending a ninth metric later cannot renumber the eight already on disk.
  const seedMetric = db.prepare('INSERT OR IGNORE INTO metric_names (id, name) VALUES (?, ?)')
  for (let i = 0; i < METRICS.length; i++) seedMetric.run(i + 1, METRICS[i])

  // Again, now that the journal mode has created the sidecars.
  restrictStore(path)

  const sqliteVersion = String(
    (db.prepare('SELECT sqlite_version() AS v').get() as { v?: string } | undefined)?.v ?? 'unknown'
  )

  // Take the backup the recovery ladder above depends on, once, at open, and
  // do not block startup on it. This is store.ts's copyFileSync-before-write
  // moved to a point where the file is known good: a backup taken mid-session
  // could capture the corruption it exists to undo.
  const backupReady =
    recovery === 'none'
      ? mod
          .backup(db, bak)
          .then(() => {
            restrictPermissions(bak)
            return true
          })
          .catch((err) => {
            console.error('[history] backup failed (not fatal):', err)
            return false
          })
      : // A store that was just recovered or started empty has nothing worth
        // backing up yet, and overwriting the .bak here would destroy the copy
        // the NEXT failure would have restored from.
        Promise.resolve(false)

  return buildStore(db, { path, journalMode, sqliteVersion, recovery, backupReady })
}

function checkIntegrity(db: Db): boolean {
  try {
    const row = db.prepare('PRAGMA integrity_check').get() as { integrity_check?: string } | undefined
    return row?.integrity_check === 'ok'
  } catch (err) {
    // A file that is not a database at all throws here rather than answering.
    console.error('[history] integrity_check failed:', err instanceof Error ? err.message : err)
    return false
  }
}

/**
 * WAL, NORMAL, and a busy timeout — except on the Windows portable target.
 *
 * The portable build keeps its data next to the exe (electron-builder.yml
 * `portable.unpackDirName`), which is routinely a USB stick or a roaming /
 * network profile. WAL needs shared memory and real file locking and gets
 * neither there: on SMB it is unsupported outright. TRUNCATE is slower and
 * correct, which is the right way round for the one target where the data
 * directory might be unplugged mid-write.
 *
 * The result is read back rather than assumed, so any other environment SQLite
 * refuses WAL in also falls back instead of silently running with whatever it
 * decided to use.
 */
function applyPragmas(db: Db, path: string): string {
  db.exec('PRAGMA busy_timeout = 5000')
  db.exec('PRAGMA synchronous = NORMAL')
  db.exec('PRAGMA foreign_keys = ON')

  // Read the env var directly rather than importing ../portable: that module
  // calls app.setPath at import time, and this one must be importable without
  // an Electron app object. The variable is electron-builder's own contract.
  const portable = !!process.env.PORTABLE_EXECUTABLE_DIR
  if (!portable) {
    try {
      const row = db.prepare('PRAGMA journal_mode = WAL').get() as { journal_mode?: string } | undefined
      const mode = String(row?.journal_mode ?? '').toLowerCase()
      if (mode === 'wal') return 'wal'
      console.error(`[history] WAL refused for ${path} (got "${mode}"), falling back to TRUNCATE`)
    } catch (err) {
      console.error('[history] WAL refused, falling back to TRUNCATE:', err)
    }
  }

  try {
    const row = db.prepare('PRAGMA journal_mode = TRUNCATE').get() as
      | { journal_mode?: string }
      | undefined
    return String(row?.journal_mode ?? 'unknown').toLowerCase()
  } catch {
    // An in-memory database answers 'memory' and refuses both. Not a failure.
    return 'unknown'
  }
}

// 0o600, like the vault, the audit log and store.ts's temp file. This holds an
// inventory of every host, unit and open port in the estate; it is not a file
// other accounts on a shared machine should be able to read.
function restrictPermissions(file: string): void {
  if (process.platform === 'win32') return
  try {
    if (existsSync(file)) chmodSync(file, 0o600)
  } catch {
    /* a permissions failure must not stop the store opening */
  }
}

/** The database and both sidecars. The WAL is not a lesser file: between
 *  checkpoints it holds the same rows, and it is measured in megabytes. */
function restrictStore(path: string): void {
  restrictPermissions(path)
  restrictPermissions(`${path}-wal`)
  restrictPermissions(`${path}-shm`)
}

function buildStore(
  db: Db,
  info: {
    path: string
    journalMode: string
    sqliteVersion: string
    recovery: HistoryStore['recovery']
    backupReady: Promise<boolean>
  }
): HistoryStore {
  // Named prepared statements, all of them, prepared once. Nothing here builds
  // SQL from a caller's string.
  const st = {
    hostId: db.prepare('SELECT id FROM hosts WHERE host_key = ?'),
    hostInsert: db.prepare('INSERT INTO hosts (host_key) VALUES (?) ON CONFLICT(host_key) DO NOTHING'),
    sampleInsert: db.prepare(
      'INSERT INTO samples (ts, host, metric, v) VALUES (?, ?, ?, ?) ' +
        'ON CONFLICT(ts, host, metric) DO UPDATE SET v = excluded.v'
    ),
    seriesRead: db.prepare(
      'SELECT ts, v FROM samples WHERE host = ? AND metric = ? AND ts >= ? AND ts <= ? ORDER BY ts'
    ),
    hourlyRead: db.prepare(
      'SELECT ts, v_avg AS v, v_min AS mn, v_max AS mx, n AS n FROM samples_hourly ' +
        'WHERE host = ? AND metric = ? AND ts >= ? AND ts <= ? ORDER BY ts'
    ),
    eventInsert: db.prepare('INSERT INTO events (ts, kind, host, payload) VALUES (?, ?, ?, ?)'),
    // Rewrites the event a run of flapping is being folded into. See
    // FLAP_WINDOW_MS.
    eventRewrite: db.prepare('UPDATE events SET ts = ?, payload = ? WHERE rowid = ?'),
    // Eight fixed statements — four filter shapes, with and without a cursor —
    // built from literals in this file. See the note above EVENT_WHERE.
    eventRead: EVENT_WHERE.map((w) => db.prepare(eventQuery(w, false))),
    eventReadFrom: EVENT_WHERE.map((w) => db.prepare(eventQuery(w, true))),
    factGet: db.prepare('SELECT value, first_seen FROM facts WHERE host = ? AND key = ?'),
    factInsert: db.prepare(
      'INSERT INTO facts (host, key, value, first_seen, last_seen) VALUES (?, ?, ?, ?, ?)'
    ),
    factTouch: db.prepare('UPDATE facts SET last_seen = ? WHERE host = ? AND key = ?'),
    factChange: db.prepare('UPDATE facts SET value = ?, last_seen = ? WHERE host = ? AND key = ?'),
    factsRead: db.prepare(
      'SELECT key, value, first_seen, last_seen FROM facts WHERE host = ? ORDER BY key'
    ),
    factsByPrefix: db.prepare(FACTS_PREFIX_QUERY),
    // An empty prefix means "every fact for this host", which has no upper
    // bound to compute.
    factsAll: db.prepare('SELECT key, value FROM facts WHERE host = ? ORDER BY key'),
    factDelete: db.prepare('DELETE FROM facts WHERE host = ? AND key = ?'),
    // Retention.
    rollup: db.prepare(
      'INSERT INTO samples_hourly (ts, host, metric, v_avg, v_min, v_max, n) ' +
        'SELECT (ts / 3600000) * 3600000, host, metric, avg(v), min(v), max(v), count(*) ' +
        'FROM samples WHERE ts < ? GROUP BY 1, 2, 3 ' +
        'ON CONFLICT(ts, host, metric) DO UPDATE SET ' +
        // Weighted, so re-running the pass over a partially rolled-up hour does
        // not average an average and quietly bias the result.
        '  v_avg = (samples_hourly.v_avg * samples_hourly.n + excluded.v_avg * excluded.n) ' +
        '          / (samples_hourly.n + excluded.n), ' +
        '  v_min = min(samples_hourly.v_min, excluded.v_min), ' +
        '  v_max = max(samples_hourly.v_max, excluded.v_max), ' +
        '  n = samples_hourly.n + excluded.n'
    ),
    dropFull: db.prepare('DELETE FROM samples WHERE ts < ?'),
    dropHourly: db.prepare('DELETE FROM samples_hourly WHERE ts < ?'),
    dropEvents: db.prepare('DELETE FROM events WHERE ts < ?'),
    countSamples: db.prepare('SELECT count(*) AS n FROM samples'),
    countHourly: db.prepare('SELECT count(*) AS n FROM samples_hourly'),
    countEvents: db.prepare('SELECT count(*) AS n FROM events'),
    countFacts: db.prepare('SELECT count(*) AS n FROM facts'),
    // The retention guards: the newest row this store can see, and how much a
    // pass would actually delete. Both answered before anything is written.
    newestSample: db.prepare('SELECT max(ts) AS n FROM samples'),
    newestHourly: db.prepare('SELECT max(ts) AS n FROM samples_hourly'),
    doomedHourly: db.prepare('SELECT count(*) AS n FROM samples_hourly WHERE ts < ?'),
    doomedEvents: db.prepare('SELECT count(*) AS n FROM events WHERE ts < ?')
  }

  const metricIds = new Map<Metric, number>(METRICS.map((m, i) => [m, i + 1]))
  const hostIds = new Map<string, number>()

  const internHost = (hostId: string): number => {
    const cached = hostIds.get(hostId)
    if (cached !== undefined) return cached
    st.hostInsert.run(hostId)
    const row = st.hostId.get(hostId) as { id?: number } | undefined
    const id = Number(row?.id ?? 0)
    if (id > 0) hostIds.set(hostId, id)
    return id
  }

  const lookupHost = (hostId: string): number | null => {
    const cached = hostIds.get(hostId)
    if (cached !== undefined) return cached
    const row = st.hostId.get(hostId) as { id?: number } | undefined
    if (row?.id === undefined) return null
    hostIds.set(hostId, Number(row.id))
    return Number(row.id)
  }

  const num = (row: SqliteRow | undefined): number => Number((row as { n?: number } | undefined)?.n ?? 0)

  let closed = false
  let depth = 0
  let droppedAfterClose = 0

  /** A write that arrives after close() is dropped — the last sweep of a
   *  session routinely does, because dispose() hands the store back before the
   *  in-flight sweep has finished. It is allowed to be dropped. It is not
   *  allowed to be dropped in silence: that is the difference between a known
   *  cost and a mystery gap at the end of every session. */
  const droppedWrite = (what: string): boolean => {
    if (!closed) return false
    droppedAfterClose++
    // Capped, so a sampler that keeps writing cannot flood the log.
    if (droppedAfterClose <= 3) {
      console.error(
        `[history] ${what} arrived after the store was closed and was dropped` +
          `${droppedAfterClose === 3 ? ' (further drops will not be logged)' : ''}`
      )
    }
    return true
  }

  /** Only ever grows to the number of facts changing inside one window. */
  const flapping = new Map<string, { id: number; since: number; from: string; count: number }>()

  const store: HistoryStore = {
    path: info.path,
    journalMode: info.journalMode,
    sqliteVersion: info.sqliteVersion,
    recovery: info.recovery,
    backupReady: info.backupReady,

    recordSamples(hostId, at, values) {
      if (droppedWrite('a sample')) return
      const host = internHost(hostId)
      // Snapped to the second. Two sweeps cannot then collide on the primary
      // key unless they are genuinely the same instant, and the ts column
      // compresses better than a millisecond stamp nobody reads.
      const ts = Math.floor(at / 1000) * 1000
      for (const [name, v] of Object.entries(values)) {
        const metric = metricIds.get(name as Metric)
        // An unknown metric name is dropped rather than inserted under a
        // guessed id: a wrong id silently corrupts a series forever.
        if (metric === undefined) continue
        if (typeof v !== 'number' || !Number.isFinite(v)) continue
        st.sampleInsert.run(ts, host, metric, v)
      }
    },

    readSeries(hostId, metric, from, to) {
      if (closed) return []
      const host = lookupHost(hostId)
      const m = metricIds.get(metric)
      if (host === null || m === undefined) return []
      const full = st.seriesRead.all(host, m, from, to) as { ts: number; v: number }[]
      // Anything older than the full-resolution horizon lives in the hourly
      // tier. A caller asking for a 30-day range gets one series, not a hole
      // where the downsampling starts — that hole is exactly the bug a
      // two-table store invites. Each point says which tier it came from, and
      // an hourly point carries the min, max and sample count behind its mean:
      // all three are written on every roll-up and were simply not readable.
      const hourly = st.hourlyRead.all(host, m, from, to) as {
        ts: number
        v: number
        mn: number
        mx: number
        n: number
      }[]
      const seen = new Set(full.map((r) => Number(r.ts)))
      const merged: SeriesPoint[] = [
        ...hourly
          .filter((r) => !seen.has(Number(r.ts)))
          .map((r) => ({
            ts: Number(r.ts),
            v: Number(r.v),
            res: 'hourly' as const,
            min: Number(r.mn),
            max: Number(r.mx),
            n: Number(r.n)
          })),
        ...full.map((r) => ({ ts: Number(r.ts), v: Number(r.v), res: 'full' as const }))
      ]
      merged.sort((a, b) => a.ts - b.ts)
      return merged
    },

    recordEvent(kind, hostId, payload, at) {
      if (droppedWrite(`a '${kind}' event`)) return
      const host = hostId === null || hostId === undefined ? null : internHost(hostId)
      let json: string | null = null
      if (payload !== undefined) {
        try {
          json = JSON.stringify(payload)
        } catch {
          // A circular payload is a caller bug, not a reason to lose the event.
          json = null
        }
      }
      st.eventInsert.run(at ?? Date.now(), kind, host, json)
    },

    readEvents(filter = {}) {
      if (closed) return []
      const host = filter.hostId === undefined ? null : lookupHost(filter.hostId)
      // A hostId that was never recorded means "no events for it", not "every
      // event". Returning the whole table there would be a quiet lie.
      if (filter.hostId !== undefined && host === null) return []
      // Which of the four fixed statements answers this filter.
      const byHost = host !== null
      const byKind = filter.kind !== undefined
      const which = byHost && byKind ? 0 : byHost ? 1 : byKind ? 2 : 3
      const limit = Math.max(1, Math.min(10_000, filter.limit ?? 500))
      const to = filter.to ?? TS_MAX
      const from = filter.from ?? TS_MIN
      const cursor = filter.cursor
      const rows = (
        cursor
          ? // The cursor's timestamp narrows the range bound as well as
            // breaking the tie, so paging stays one index seek rather than
            // re-reading everything newer than the cursor each time.
            st.eventReadFrom[which].all(
              host,
              filter.kind ?? null,
              from,
              Math.min(to, cursor.ts),
              limit,
              cursor.ts,
              cursor.id
            )
          : st.eventRead[which].all(host, filter.kind ?? null, from, to, limit)
      ) as {
        ts: number
        id: number
        kind: string
        host_key: string | null
        payload: string | null
      }[]
      return rows.map((r) => ({
        ts: Number(r.ts),
        kind: String(r.kind),
        hostId: r.host_key ?? null,
        payload: r.payload === null ? undefined : safeParse(r.payload),
        cursor: { ts: Number(r.ts), id: Number(r.id) }
      }))
    },

    upsertFact(hostId, key, value, at) {
      if (droppedWrite(`a fact (${key})`)) return 'unchanged'
      const host = internHost(hostId)
      const existing = st.factGet.get(host, key) as
        | { value?: string; first_seen?: number }
        | undefined
      if (existing === undefined) {
        st.factInsert.run(host, key, value, at, at)
        // A new fact is a change. "nginx.service appeared on web-2 at 04:12"
        // is the whole reason facts are not just a snapshot table.
        st.eventInsert.run(at, 'fact-added', host, JSON.stringify({ key, value }))
        return 'created'
      }
      if (existing.value === value) {
        // The common case by far, and the reason this table is 5x cheaper than
        // storing units as samples: nothing is written but a timestamp.
        st.factTouch.run(at, host, key)
        return 'unchanged'
      }
      st.factChange.run(value, at, host, key)

      // A run of changes to one fact inside FLAP_WINDOW_MS is one incident.
      // Without this, a unit stuck in a restart loop writes an event on nearly
      // every sweep — ~65,000 of them over ninety days, all saying the same
      // thing — and the events table stops being readable by a human.
      const flapKey = `${host}\u0000${key}`
      const incident = flapping.get(flapKey)
      if (incident && at >= incident.since && at - incident.since <= FLAP_WINDOW_MS) {
        const count = incident.count + 1
        const rewritten = Number(
          st.eventRewrite.run(
            at,
            JSON.stringify({ key, from: incident.from, to: value, flaps: count }),
            incident.id
          ).changes
        )
        // Zero rows means retention dropped the event under us; fall through
        // and start a new incident rather than losing the record entirely.
        if (rewritten > 0) {
          incident.count = count
          return 'changed'
        }
        flapping.delete(flapKey)
      }

      const id = Number(
        st.eventInsert.run(
          at,
          'fact-changed',
          host,
          JSON.stringify({ key, from: existing.value, to: value })
        ).lastInsertRowid
      )
      // Bounded: entries are only interesting inside the window, so a sweep
      // over a large estate cannot grow this without limit.
      if (flapping.size > 4096) {
        for (const [k, v] of flapping) if (at - v.since > FLAP_WINDOW_MS) flapping.delete(k)
      }
      flapping.set(flapKey, { id, since: at, from: String(existing.value ?? ''), count: 1 })
      return 'changed'
    },

    readFacts(hostId) {
      if (closed) return []
      const host = lookupHost(hostId)
      if (host === null) return []
      const rows = st.factsRead.all(host) as {
        key: string
        value: string
        first_seen: number
        last_seen: number
      }[]
      return rows.map((r) => ({
        key: String(r.key),
        value: String(r.value),
        firstSeen: Number(r.first_seen),
        lastSeen: Number(r.last_seen)
      }))
    },

    retireFacts(hostId, at, prefix, keep) {
      if (droppedWrite('a fact retirement')) return 0
      const host = lookupHost(hostId)
      if (host === null) return 0
      const kept = keep instanceof Set ? keep : new Set(keep)
      const rows = (
        prefix === ''
          ? st.factsAll.all(host)
          : st.factsByPrefix.all(host, prefix, prefixUpperBound(prefix))
      ) as {
        key: string
        value: string
      }[]
      let removed = 0
      for (const r of rows) {
        const key = String(r.key)
        if (kept.has(key)) continue
        st.factDelete.run(host, key)
        st.eventInsert.run(at, 'fact-removed', host, JSON.stringify({ key, value: r.value }))
        removed++
      }
      return removed
    },

    transaction<T>(fn: () => T & (T extends PromiseLike<unknown> ? never : unknown)): T {
      // The type above stops this at compile time; this stops a cast and a
      // plain-JS caller. Nothing here awaits, so an async callback would BEGIN,
      // receive a pending promise, COMMIT nothing, and let every write inside
      // it land afterwards in autocommit — one fsync each, silently, with
      // `depth` already back to 0 so a nested transaction() would issue its own
      // BEGIN and commit a partial slice.
      const sync = (out: T): T => {
        if (out !== null && typeof out === 'object' && typeof (out as { then?: unknown }).then === 'function') {
          throw new Error(
            'history.transaction() was given an async callback. It does not await, so ' +
              'the transaction would commit before any of the writes inside it ran. ' +
              'Collect the awaited work first, then call transaction() with a synchronous callback.'
          )
        }
        return out
      }

      if (closed) return sync(fn())
      // Nested calls join the outer transaction rather than issuing a second
      // BEGIN, which SQLite refuses. A caller should not have to know whether
      // it is the outermost one.
      if (depth > 0) {
        depth++
        try {
          return sync(fn())
        } finally {
          depth--
        }
      }
      db.exec('BEGIN')
      depth = 1
      try {
        const out = sync(fn())
        db.exec('COMMIT')
        return out
      } catch (err) {
        try {
          db.exec('ROLLBACK')
        } catch {
          /* already rolled back by SQLite on some errors */
        }
        throw err
      } finally {
        depth = 0
      }
    },

    retain(now = Date.now()) {
      const nothing: RetentionResult = { rolledUp: 0, hourlyRows: 0, hourlyDropped: 0, eventsDropped: 0 }
      if (closed) return nothing
      const fullCutoff = now - RETENTION_FULL_DAYS * DAY_MS
      const hourlyCutoff = now - RETENTION_HOURLY_DAYS * DAY_MS

      // Guard one: a clock that has stepped forward.
      //
      // main/index.ts runs a pass seconds after launch, which on a VM restored
      // from a snapshot or a machine with a dead CMOS battery is before NTP has
      // corrected anything. Every cutoff above is then a year in the future and
      // one committed transaction empties the store. The newest row the store
      // can see is the only second opinion available about what time it is.
      //
      // Samples and hourly buckets only, NOT events: the caller records a
      // 'retention-skipped' event when this refuses, and an event written at
      // the bogus time would become the newest row and disarm the guard on the
      // very next pass. A guard that its own log entry defeats is not a guard.
      // The second opinion has to come from data somebody else wrote.
      const newest = Math.max(num(st.newestSample.get()), num(st.newestHourly.get()))
      if (newest > 0 && now - newest > RETENTION_CLOCK_GRACE_MS) {
        console.error(
          `[history] retention skipped: the clock says ${new Date(now).toISOString()} but the ` +
            `newest row is ${new Date(newest).toISOString()}. Refusing to age out data against a ` +
            `clock that far ahead. The pass runs normally once new samples land at the current time.`
        )
        return { ...nothing, skipped: 'clock-ahead' }
      }

      // Guard two: a pass that would take most of what is here.
      //
      // Once the sampler has written one row at a bogus time, the newest row IS
      // that time and guard one has nothing left to notice. Only the deletions
      // are counted, not the roll-up: folding samples into hourly buckets is
      // what the pass is for, and an app that has not run for a fortnight
      // legitimately folds its whole full-resolution tier on the next launch.
      //
      // The known cost, deliberately taken: an app that has not been opened for
      // more than a quarter really does have most of its hourly tier past the
      // horizon, and this refuses that pass too. It keeps rows it could have
      // dropped — the safe direction — says so every time, and starts dropping
      // again as new buckets accumulate. Bailing out rather than deleting a
      // capped slice is the same choice: a cap that deletes a little every pass
      // still empties the store against a wrong clock, just over a day.
      const doomed = num(st.doomedHourly.get(hourlyCutoff)) + num(st.doomedEvents.get(hourlyCutoff))
      const base = num(st.countHourly.get()) + num(st.countEvents.get())
      if (base >= RETENTION_GUARD_MIN_ROWS && doomed > base * RETENTION_MAX_DROP_FRACTION) {
        console.error(
          `[history] retention skipped: one pass would drop ${doomed} of ${base} hourly and event ` +
            `rows (over ${Math.round(RETENTION_MAX_DROP_FRACTION * 100)}%). That is a wrong clock, ` +
            `not a horizon — nothing was deleted.`
        )
        return { ...nothing, skipped: 'blast-radius' }
      }

      return store.transaction(() => {
        const before = num(st.countHourly.get())
        st.rollup.run(fullCutoff)
        const after = num(st.countHourly.get())
        // The roll-up must land before the delete, in the same transaction: a
        // crash between them would drop a week of samples that were never
        // written anywhere else.
        const rolledUp = Number(st.dropFull.run(fullCutoff).changes)
        const hourlyDropped = Number(st.dropHourly.run(hourlyCutoff).changes)
        // Events age out on the same horizon. They are the record of what
        // changed, not an audit trail — auditLog.ts is the audit trail and is
        // deliberately untouched by any of this.
        const eventsDropped = Number(st.dropEvents.run(hourlyCutoff).changes)
        return { rolledUp, hourlyRows: after - before, hourlyDropped, eventsDropped }
      })
    },

    counts() {
      if (closed) return { samples: 0, hourly: 0, events: 0, facts: 0 }
      return {
        samples: num(st.countSamples.get()),
        hourly: num(st.countHourly.get()),
        events: num(st.countEvents.get()),
        facts: num(st.countFacts.get())
      }
    },

    close() {
      if (closed) return
      closed = true
      try {
        // Fold the WAL back into the main file before closing.
        //
        // SQLite already does this when the closing connection is the LAST one,
        // which is why this looks redundant and is not. The .bak taken at open
        // is deliberately not awaited — nothing about quitting should wait on
        // it — so `before-quit` routinely closes this store while the backup's
        // own connection is still open. Measured without this line: a 4 MB WAL
        // left on disk and a primary missing everything in it. The next launch
        // then either replays a sidecar nobody accounted for or, if that
        // sidecar was lost, comes up quietly short — the exact "half a
        // database" case the .bak exists to rescue, and which the .bak would
        // itself have been taken from.
        //
        // A crash skips this, which is exactly right: the WAL is then the
        // record of what was in flight and SQLite replays it at the next open.
        const row = db.prepare('PRAGMA wal_checkpoint(TRUNCATE)').get() as
          | { busy?: number; log?: number; checkpointed?: number }
          | undefined
        // exec() threw the answer away. Measured with a real reader holding the
        // database, this blocks for the full busy_timeout — 5,349 ms — returns
        // busy=1, throws nothing, and leaves the whole 4 MB WAL behind. A
        // five-second stall on quit deserves a line saying what it was.
        if (row && Number(row.busy) === 1) {
          console.error(
            `[history] WAL checkpoint on close was blocked by another reader after the busy ` +
              `timeout; ${Number(row.log ?? -1)} pages are still in the WAL and will be replayed ` +
              `at the next launch.`
          )
        }
      } catch {
        /* a database that is already gone, or in TRUNCATE mode, has nothing to
           checkpoint — not a reason to skip the close below */
      }
      try {
        db.close()
      } catch (err) {
        console.error('[history] close failed:', err)
      }
      // Only ever an EMPTY sidecar, and only after the checkpoint above said
      // there is nothing left in it. Removing a WAL with content in it would be
      // deleting the data this whole file exists to keep.
      for (const sidecar of [`${info.path}-wal`, `${info.path}-shm`]) {
        try {
          if (existsSync(sidecar) && statSync(sidecar).size === 0) rmSync(sidecar, { force: true })
        } catch {
          /* a sidecar that will not go away is untidy, never incorrect */
        }
      }
    }
  }

  return store
}

function safeParse(json: string): unknown {
  try {
    return JSON.parse(json)
  } catch {
    return json
  }
}

/** Bytes on disk, for the size arithmetic.
 *
 *  Counts the WAL, because a WAL that has not checkpointed is still space the
 *  user's disk is giving up, and counts the .bak, because a full copy taken at
 *  every clean launch is a second file of very nearly the same size — the
 *  steady state is ~2x the primary, and a function that reported half of what
 *  the disk gave up would be the wrong number in the one feature justified by
 *  "must not become a cause of disk pressure". */
export function historyBytes(path: string): number {
  let total = 0
  for (const f of [path, `${path}-wal`, `${path}-shm`, `${path}.bak`]) {
    try {
      if (existsSync(f)) total += statSync(f).size
    } catch {
      /* a file that vanished between the two calls contributes nothing */
    }
  }
  return total
}

/**
 * Every file the store can leave in `dir`: the database, both journal
 * sidecars, the backup the recovery ladder restores from, and any timestamped
 * copies that ladder moved aside.
 *
 * Exported because backup.ts's "delete all data" and its import both have to
 * remove them, and the list of what the store writes belongs next to the code
 * that writes it — a second copy of these suffixes somewhere else is how the
 * database came to be missing from ALL_DATA_FILES in the first place.
 */
export function historyFiles(dir: string): string[] {
  const base = join(dir, HISTORY_FILE)
  const files = [base, `${base}-wal`, `${base}-shm`, `${base}.bak`]
  try {
    for (const name of readdirSync(dir)) {
      if (name.startsWith(`${HISTORY_FILE}.corrupt-`)) files.push(join(dir, name))
    }
  } catch {
    /* an unreadable directory has nothing for us to delete */
  }
  return files
}

/** Remove all of them. The caller must have closed the store first: unlinking
 *  an open database is EBUSY on Windows. */
export function removeHistoryFiles(dir: string): void {
  for (const f of historyFiles(dir)) rmSync(f, { force: true })
}
