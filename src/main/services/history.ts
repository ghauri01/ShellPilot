import { app } from 'electron'
import { join } from 'node:path'
import { chmodSync, copyFileSync, existsSync, readdirSync, renameSync, rmSync, statSync } from 'node:fs'
import type {
  JobDetachedHandle,
  JobDetail,
  JobHostResult,
  JobHostState,
  JobKind,
  JobOutputLine,
  JobRecord,
  JobSpec,
  JobState
} from '../../shared/jobs'
import { JOB_OUTPUT_RETENTION_DAYS, JOB_RECORD_RETENTION_DAYS, isJobDetachedHandle } from '../../shared/jobs'
import type { BroadcastConfirmation, BroadcastRisk, CommandApproval } from '../../shared/broadcast'
import { isCommandApproval } from '../../shared/broadcast'
import { CAPACITY_METRICS, type CapacityMetric } from '../../shared/capacity'

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

/** What createJob is given. The spec and confirmation are stored as JSON;
 *  everything else is a column. */
export interface NewJob {
  id: string
  createdAt: number
  workspaceId: string | null
  title: string
  kind: JobKind
  spec: JobSpec
  risk: BroadcastRisk
  confirmation: BroadcastConfirmation
  confirmedAt: number | null
  /** B3's approval record. `null` is accepted so a caller that genuinely has
   *  none writes a row that says so, rather than one that lies by omission. */
  approval: CommandApproval | null
  state: JobState
  targets: { serverId: string; serverName: string; ord: number; state: JobHostState }[]
}

/** A partial job transition. Absent keys are left alone; an explicit `null`
 *  clears the column, which is how a cancelled job's `ended_at` is set without
 *  a second method. */
export interface JobPatch {
  state?: JobState
  startedAt?: number | null
  endedAt?: number | null
  cancelledAt?: number | null
}

export interface JobTargetPatch {
  state?: JobHostState
  outcome?: JobHostResult['outcome'] | null
  exitCode?: number | null
  error?: string | null
  startedAt?: number | null
  endedAt?: number | null
  outOffset?: number
  outElided?: number
  /** B2's marker handle. Undefined leaves the column alone; `null` clears it,
   *  which is what a reaped marker does. */
  detached?: JobDetachedHandle | null
}

/**
 * One host's part in one job — roadmap item 28.
 *
 * Two rows rather than a flattened one, because `job` and `job_target` both
 * have a `state`, a `started_at` and an `ended_at`, and every one of those
 * pairs means something different. A flattened row would need six aliases and
 * the first reader to get one wrong would be reading the JOB's outcome and
 * calling it the host's.
 */
export interface JobHostRun {
  job: JobRecord
  host: JobHostResult
}

export interface JobRetentionResult {
  /** job_output rows dropped for being past the output horizon. */
  outputDropped: number
  /** Whole jobs dropped — the job row, its targets and any output left. */
  jobsDropped: number
  /** Set when the JOB-ROW sweep refused to run against a clock the store's own
   *  newest row disagrees with. The output sweep still ran — see jobRetain. */
  skipped?: 'clock-ahead'
}

/**
 * The whole store surface. Six named methods plus the retire half of
 * upsertFact, a retention pass and lifecycle. No SQL crosses this boundary in
 * either direction — see the note at the top of the file about why.
 */
export interface HistoryStore {
  recordSamples(hostId: string, at: number, values: Partial<Record<Metric, number>>): void
  readSeries(hostId: string, metric: Metric, from: number, to: number): SeriesPoint[]
  /** The three series a capacity question is about — cpu, memPct, diskPct —
   *  for one host, over one range, in ONE pass. See the note above
   *  CAPACITY_METRIC_IDS for why that is not the same thing as three
   *  readSeries calls. */
  readTrends(hostId: string, from: number, to: number): Record<CapacityMetric, SeriesPoint[]>
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

  // ---- Jobs (roadmap B1) --------------------------------------------------
  //
  // Named methods, like everything else here. The job runner holds no SQL and
  // cannot pass any in — the escape hatch to better-sqlite3 stays open only
  // while that is true of every caller, and a runner is exactly the kind of
  // stateful thing that grows its own queries if you let it.

  /** Write the job row and its targets. One transaction: a job whose targets
   *  did not land is a job the runner would re-adopt with nothing to run. */
  createJob(job: NewJob): void
  /** Move the job's own state on. Only the fields given are written, so a
   *  transition cannot accidentally blank a timestamp it does not know about. */
  updateJob(jobId: string, patch: JobPatch): void
  /** Move one host's state on, same rule. */
  updateJobTarget(jobId: string, serverId: string, patch: JobTargetPatch): void
  /** Append output for one host, redacted and capped by the CALLER. The store
   *  writes what it is given; see appendJobOutput's note on why the cap is not
   *  applied here. */
  appendJobOutput(jobId: string, serverId: string, lines: JobOutputLine[]): void
  /** Newest first. */
  listJobs(limit?: number): JobRecord[]
  /** The job and every target, in `ord` order. Null if there is no such job. */
  readJob(jobId: string): JobDetail | null
  /** Stored output for one host, in seq order. */
  readJobOutput(jobId: string, serverId: string): JobOutputLine[]
  /**
   * Every job that touched ONE host inside a time range, newest first, with
   * that host's own row beside it — roadmap item 28.
   *
   * A NAMED statement, not a filter surface. It takes a host, two bounds and a
   * cap, and there is deliberately no way to say which kind of job, which state
   * or which order: the store's rule is that no SQL crosses this boundary, and
   * "let the caller narrow it" is the first step of the query surface that rule
   * exists to refuse.
   *
   * The bounds are on `job.created_at`, which is when the job was MINTED. A job
   * created before the range and still running inside it is therefore not
   * returned, and that is the honest reading for what item 28 asks: "what did
   * we run in response to this alert" is about work that STARTED after the
   * alert, and a job already running when it fired was not a response to it.
   */
  jobsForHost(serverId: string, from: number, to: number, limit?: number): JobHostRun[]
  /** Jobs whose rows still say they were running or queued. Read once at
   *  startup: on the attached path every one of them is over and does not know
   *  it. */
  unfinishedJobs(): JobDetail[]
  /** Drop output past its horizon, then whole jobs past theirs. */
  jobRetain(now?: number): JobRetentionResult
  /** Rows currently held, for the size arithmetic and for tests. */
  counts(): {
    samples: number
    hourly: number
    events: number
    facts: number
    jobs: number
    jobOutput: number
  }
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

-- ---------------------------------------------------------------------------
-- Jobs — roadmap item B1.
--
-- Three tables and a deliberate asymmetry between them: the two small ones are
-- kept for a year and the big one for a month. A job row is a title, a spec and
-- five timestamps; the output behind it is up to 256 KB per host. "When did we
-- last upgrade web-2 and did it exit 0" is worth a year of rows and costs
-- almost nothing; the dpkg chatter that answers "what exactly did it say" is
-- worth a month and costs everything. See jobRetain().
--
-- The id is the caller's own job id (a uuid), not an autoincrement: it is minted
-- before the job starts, it is what a progress event names, and it must survive
-- a restart unchanged so a re-adopted job is the SAME job rather than a new row
-- describing it.
--
-- host ids are NOT interned here, unlike samples and facts. A job has a handful
-- of hosts and is written once; interning buys nothing and costs the ability to
-- read a job's targets without a join. The server NAME is stored beside the id
-- for the same reason the broadcast result carries it: a server deleted from
-- the workspace next month must not turn last month's job into a list of uuids.
CREATE TABLE IF NOT EXISTS job (
  id TEXT PRIMARY KEY,
  created_at INTEGER NOT NULL,
  workspace_id TEXT,
  title TEXT NOT NULL,
  kind TEXT NOT NULL,
  spec TEXT NOT NULL,
  risk TEXT NOT NULL,
  confirmation TEXT NOT NULL,
  confirmed_at INTEGER,
  -- B3's approval record, as JSON: the step text and the resolved target list
  -- exactly as the user confirmed them, the risk, the confirmation kind, and
  -- the phrase they actually typed where one was required.
  --
  -- The three columns above are a SUMMARY of it and are kept because a list
  -- renders them; this is what the runner re-checks at launch and at resume.
  -- Storing the commands and targets a SECOND time, next to spec and
  -- job_target, is the point rather than a redundancy: comparing the spec to
  -- itself would always agree, and the whole question is whether the spec has
  -- moved since somebody agreed to it.
  --
  -- One column of JSON rather than three, for the detached column's reason: nothing
  -- queries inside it, it is read whole by one caller and written whole by one.
  -- NULL for a row written before B3 — readable, never resumable.
  approval TEXT,
  state TEXT NOT NULL,
  started_at INTEGER,
  ended_at INTEGER,
  cancelled_at INTEGER
) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS job_created ON job (created_at);
-- The adoption query: every job whose rows still say it was running. Read once
-- at startup, so it is an index on a column with four distinct values purely to
-- keep that read off a full scan of a year of jobs.
CREATE INDEX IF NOT EXISTS job_state ON job (state);

-- One row per host. Field names are BroadcastHostResult's, exactly, so the
-- renderer's existing result type can be pointed at a job without a
-- translation layer — ord and the four columns after it are the ones only a
-- persisted run needs.
CREATE TABLE IF NOT EXISTS job_target (
  job_id TEXT NOT NULL,
  server_id TEXT NOT NULL,
  server_name TEXT NOT NULL,
  ord INTEGER NOT NULL,
  state TEXT NOT NULL,
  outcome TEXT,
  exit_code INTEGER,
  error TEXT,
  started_at INTEGER,
  ended_at INTEGER,
  -- Bytes of output persisted for this host, and bytes dropped from the middle
  -- of it. out_elided is not decoration: without it a long output is
  -- indistinguishable from a short one, which is how a head-only cap turns
  -- "dpkg failed" into "the command produced no error".
  out_offset INTEGER NOT NULL DEFAULT 0,
  out_elided INTEGER NOT NULL DEFAULT 0,
  -- B2's marker handle, as JSON: which directory on the host holds this step's
  -- cmd/pid/out/rc, which instance launched it, and how many bytes of its out
  -- have been read from it. NULL for every attached row, which is how a reader tells
  -- the two apart a month later.
  --
  -- One column of JSON rather than six columns, because nothing queries inside
  -- it: it is read whole by exactly one caller (reclaim()) and written whole by
  -- exactly one (the runner). Six columns would be six migrations the first
  -- time the wrapper grows a field.
  detached TEXT,
  PRIMARY KEY (job_id, server_id)
) WITHOUT ROWID;
-- Item 28's read: which jobs touched ONE host. The primary key leads with
-- job_id, so without this "every job that ran on web-2" is a full scan of a
-- year of targets on every host — which is the read a runbook does on every
-- open, once per alert kind. A WITHOUT ROWID table's index entries carry the
-- primary key rather than a rowid, so this costs the two ids and buys the
-- scan back.
CREATE INDEX IF NOT EXISTS job_target_server ON job_target (server_id);

-- The output itself, in arrival order per host. seq is the runner's own
-- counter, so two chunks in the same millisecond keep their order — the same
-- tie-break the events table needs and for the same reason.
CREATE TABLE IF NOT EXISTS job_output (
  job_id TEXT NOT NULL,
  server_id TEXT NOT NULL,
  seq INTEGER NOT NULL,
  at INTEGER NOT NULL,
  stream TEXT NOT NULL,
  text TEXT NOT NULL,
  PRIMARY KEY (job_id, server_id, seq)
) WITHOUT ROWID;
`

// 2 adds the three job tables. No migration step is needed and none is written:
// every statement in SCHEMA is CREATE ... IF NOT EXISTS, so an existing store
// gains the tables at the next open and keeps every row it had. The number is
// bumped anyway, because the first change that CANNOT be expressed that way
// needs to know which shape it is starting from, and a version that only moves
// when someone remembers is a version nobody can trust.
// 4 is B3's `job.approval`. Bumped even though `migrateJob` below adds the
// column by hand for the same reason 3 was: the number is what the first change
// that CANNOT be expressed as an idempotent ALTER will need in order to know
// which shape it is starting from, and a version that only moves when someone
// remembers is a version nobody can trust.
// 5 adds job_target_server, the index item 28's per-host job read needs. Like
// every table above it, it is an idempotent CREATE ... IF NOT EXISTS, so an
// existing store gains it at the next open and keeps every row it had. The
// number is bumped anyway, for the reason 2, 3 and 4 were.
const SCHEMA_VERSION = '5'

/**
 * The first change that CANNOT be expressed as `CREATE TABLE IF NOT EXISTS`,
 * which is the case SCHEMA_VERSION was bumped for the last time in
 * anticipation of.
 *
 * `job_target.detached` is a new column on a table an existing store already
 * has, and `CREATE TABLE IF NOT EXISTS` does nothing at all for a table that
 * exists. So it is added by hand, guarded by reading the table's own shape
 * rather than by trusting the version — a store restored from a backup taken
 * mid-upgrade can have a version that disagrees with its columns, and
 * `ALTER TABLE` on a column that is already there is an error that would take
 * the whole store down at open.
 *
 * Adding a nullable column to a SQLite table is a metadata-only operation: it
 * does not rewrite a single row, so this costs nothing on a store with a year
 * of jobs in it.
 */
function migrateJobTarget(db: Db): void {
  const cols = db.prepare('PRAGMA table_info(job_target)').all() as { name?: unknown }[]
  if (cols.length === 0) return // the table is about to be created with the column
  if (cols.some((c) => String(c.name) === 'detached')) return
  db.exec('ALTER TABLE job_target ADD COLUMN detached TEXT')
}

/** B3's approval record, added to `job` the same way and for the same reasons.
 *  A store that already has the table keeps every row it had; the new column is
 *  NULL on all of them, which reads as "written before approvals were recorded"
 *  and is exactly what such a row is. */
function migrateJob(db: Db): void {
  const cols = db.prepare('PRAGMA table_info(job)').all() as { name?: unknown }[]
  if (cols.length === 0) return
  if (cols.some((c) => String(c.name) === 'approval')) return
  db.exec('ALTER TABLE job ADD COLUMN approval TEXT')
}

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

// ---------------------------------------------------------------------------
// The sample read path, and the one thing its first consumer found.
//
// `samples` is WITHOUT ROWID with PRIMARY KEY (ts, host, metric): the key IS
// the table, ts leads, and that is right for the write and retention paths —
// every insert appends and every delete is `ts < ?`. It is not right for the
// read that roadmap item 26 actually performs. Measured plan for seriesRead:
//
//   SEARCH samples USING PRIMARY KEY (ts>? AND ts<?)
//
// host and metric are not in the seek. A seven-day read walks every row in the
// range for every host and every metric to return one series: at the roadmap's
// reference estate — fifteen hosts, eight metrics, two-minute cadence — that is
// 604,800 rows scanned for the 5,040 wanted, three times over, once per metric.
// Measured on that store: 19.7 ms per metric, 58.8 ms for the three; at sixty
// hosts, 70 ms and 225 ms. It grows with the fleet, not with the answer.
//
// The obvious fix is an index on (host, metric, ts), and it works — 4.4 ms,
// SEARCH samples USING INDEX (host=? AND metric=? AND ts>? AND ts<?). It was
// measured and REJECTED. On a WITHOUT ROWID table that index is very nearly a
// second copy of the primary key, and it took the reference store from 16.6 MB
// to 23.6 MB and the sixty-host store from 66 MB to 94 MB — 42% on a budget
// this file's header states as ~16 MB at steady state and never growing, for a
// panel a person opens by hand. A partial index over only the three capacity
// metrics does not help either: `metric = ?` is a bound parameter, so SQLite
// cannot prove the partial index applies and does not use it (measured: the
// plan is unchanged).
//
// What is left costs nothing: ask for the three series in ONE scan instead of
// three. 22.7 ms at fifteen hosts, 100 ms at sixty. The metric list below is
// interpolated from METRICS at module load — a literal in this file, like every
// fragment of EVENT_WHERE — and never from a caller. The rule that no SQL
// crosses this boundary is untouched.
// ---------------------------------------------------------------------------

// Type aliases rather than interfaces: an interface has no implicit index
// signature, so `rows as FullRow[]` off node:sqlite's SqliteRow would not
// compile.
type FullRow = { ts: number; v: number }
type HourlyRow = { ts: number; v: number; mn: number; mx: number; n: number }

/**
 * The two tiers, stitched into one series.
 *
 * Anything older than the full-resolution horizon lives in the hourly tier. A
 * caller asking for a 30-day range gets one series, not a hole where the
 * downsampling starts — that hole is exactly the bug a two-table store invites,
 * and it would read as "the host was off". Each point says which tier it came
 * from, and an hourly point carries the min, max and sample count behind its
 * mean: all three are written on every roll-up and were, for a while, simply
 * not readable.
 *
 * The tiers do not overlap in practice — the roll-up deletes what it folds, in
 * the same transaction — with one exception: a sample that arrives late for an
 * hour already rolled up sits in `samples` until the next pass. Where such a
 * row lands exactly on the bucket's own timestamp the full-resolution reading
 * wins, because two points at one instant is the one thing a chart cannot draw.
 */
function mergeTiers(full: FullRow[], hourly: HourlyRow[]): SeriesPoint[] {
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
}

/** The ids of CAPACITY_METRICS, as a SQL list. Ids are the METRICS index + 1
 *  and never move (see METRICS), so this is derived rather than typed out: a
 *  hand-written `IN (1, 2, 4)` would silently read the wrong three series the
 *  first time somebody inserted a metric into the middle of that array. */
const CAPACITY_METRIC_IDS = CAPACITY_METRICS.map((m) => METRICS.indexOf(m) + 1).join(', ')

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
/** The capacity metric ids as they are interpolated into the two trend
 *  statements, so a test can assert the derived list against METRICS rather
 *  than against a number somebody typed. */
export const CAPACITY_METRIC_IDS_FOR_TESTS = CAPACITY_METRIC_IDS

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
    // Size, not just existence. SQLite reads a zero-length file as a perfectly
    // valid EMPTY database, so integrity_check below cannot tell one from a
    // real backup — and a truncated .bak is exactly what a backup that died
    // mid-write used to leave behind (see the copy below, which now renames
    // into place instead). Restoring from it reported 'restored-from-backup'
    // and came up with nothing at all. Losing the history is survivable;
    // saying it was recovered when it was not sends someone looking for data
    // that is gone.
    if (existsSync(bak) && statSync(bak).size > 0) {
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
  // BEFORE the schema, not after: `CREATE TABLE IF NOT EXISTS` does nothing for
  // a table that already exists, so this is the only chance an existing
  // job_target has to gain the column. On a fresh store the table is not there
  // yet and this is a no-op.
  migrateJobTarget(db)
  migrateJob(db)
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
  //
  // Written to a temp file and renamed into place, never straight onto the
  // .bak. The copy overwrites its destination from the very first page, so
  // writing directly meant the only file the ladder above can restore from was
  // destroyed for the whole length of the backup — and a backup that does not
  // finish leaves it destroyed. It does not always finish: the copy runs on a
  // libuv thread against this same connection, so a write landing in the wrong
  // moment fails it (measured: ERR_SQLITE_ERROR and a ZERO-BYTE .bak left on
  // disk), and main/index.ts deliberately quits without waiting for it, which
  // truncates it from the other direction. rename(2) is atomic: the .bak is
  // either the previous good copy or a complete new one, and never half of
  // either.
  const backupTmp = `${bak}.tmp`
  const backupReady =
    recovery === 'none'
      ? (async (): Promise<boolean> => {
          try {
            rmSync(backupTmp, { force: true })
            await mod.backup(db, backupTmp)
            // 0600 before it is visible under its real name, rather than a
            // window with the whole inventory readable under the umask.
            restrictPermissions(backupTmp)
            renameSync(backupTmp, bak)
            return true
          } catch (err) {
            console.error('[history] backup failed (not fatal):', err)
            // Only the attempt goes. Whatever .bak was already there is still
            // whole, and is still what the next failure would restore from.
            try {
              rmSync(backupTmp, { force: true })
              rmSync(`${backupTmp}-journal`, { force: true })
            } catch {
              /* `backupReady` answers true or false and never rejects: callers
                 hold it for the length of the session and an unhandled
                 rejection out of here would be a process-wide event. */
            }
            return false
          }
        })()
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
    // Both tiers, three metrics, one scan each. See the note above
    // CAPACITY_METRIC_IDS.
    trendRead: db.prepare(
      `SELECT ts, metric, v FROM samples WHERE host = ? AND ts >= ? AND ts <= ? ` +
        `AND metric IN (${CAPACITY_METRIC_IDS}) ORDER BY ts`
    ),
    trendHourlyRead: db.prepare(
      `SELECT ts, metric, v_avg AS v, v_min AS mn, v_max AS mx, n AS n FROM samples_hourly ` +
        `WHERE host = ? AND ts >= ? AND ts <= ? ` +
        `AND metric IN (${CAPACITY_METRIC_IDS}) ORDER BY ts`
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
    doomedEvents: db.prepare('SELECT count(*) AS n FROM events WHERE ts < ?'),

    // ---- Jobs -------------------------------------------------------------
    jobInsert: db.prepare(
      'INSERT INTO job (id, created_at, workspace_id, title, kind, spec, risk, confirmation, ' +
        'confirmed_at, approval, state, started_at, ended_at, cancelled_at) ' +
        'VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL, NULL) ' +
        // A re-run under an id that already exists would otherwise throw and
        // lose the run; replacing the row is the only sane reading of "start
        // this job", and the targets below are replaced with it.
        'ON CONFLICT(id) DO UPDATE SET created_at = excluded.created_at, ' +
        '  workspace_id = excluded.workspace_id, title = excluded.title, kind = excluded.kind, ' +
        '  spec = excluded.spec, risk = excluded.risk, confirmation = excluded.confirmation, ' +
        '  confirmed_at = excluded.confirmed_at, approval = excluded.approval, ' +
        '  state = excluded.state, started_at = NULL, ended_at = NULL, cancelled_at = NULL'
    ),
    jobTargetInsert: db.prepare(
      'INSERT INTO job_target (job_id, server_id, server_name, ord, state, outcome, exit_code, ' +
        'error, started_at, ended_at, out_offset, out_elided, detached) ' +
        'VALUES (?, ?, ?, ?, ?, NULL, NULL, NULL, NULL, NULL, 0, 0, NULL) ' +
        'ON CONFLICT(job_id, server_id) DO UPDATE SET server_name = excluded.server_name, ' +
        '  ord = excluded.ord, state = excluded.state, outcome = NULL, exit_code = NULL, ' +
        '  error = NULL, started_at = NULL, ended_at = NULL, out_offset = 0, out_elided = 0, ' +
        // A re-run under the same id starts a new marker, so the old one must
        // not survive on the row: a handle pointing at a directory the previous
        // run reaped would send reclaim() to look for it.
        '  detached = NULL'
    ),
    // A full-row write over values merged in JS, rather than a COALESCE-per-
    // column patch. `null` is a MEANINGFUL value in three of these four columns
    // — "not started", "not ended", "not cancelled" — so COALESCE cannot tell
    // "leave it alone" from "clear it", and a patch language that cannot
    // express clearing is one the cancel path immediately needs to work around.
    // Reading the row first costs one indexed lookup on a table with a handful
    // of rows per job.
    jobUpdate: db.prepare(
      'UPDATE job SET state = ?2, started_at = ?3, ended_at = ?4, cancelled_at = ?5 WHERE id = ?1'
    ),
    jobRead: db.prepare('SELECT * FROM job WHERE id = ?'),
    jobList: db.prepare('SELECT * FROM job ORDER BY created_at DESC, id DESC LIMIT ?'),
    jobUnfinished: db.prepare(
      "SELECT * FROM job WHERE state IN ('queued', 'running') ORDER BY created_at"
    ),
    jobTargetUpdate: db.prepare(
      'UPDATE job_target SET state = ?3, outcome = ?4, exit_code = ?5, error = ?6, ' +
        'started_at = ?7, ended_at = ?8, out_offset = ?9, out_elided = ?10, detached = ?11 ' +
        'WHERE job_id = ?1 AND server_id = ?2'
    ),
    jobTargetRead: db.prepare('SELECT * FROM job_target WHERE job_id = ? ORDER BY ord'),
    jobTargetOne: db.prepare('SELECT * FROM job_target WHERE job_id = ? AND server_id = ?'),
    // Item 28. Ids only: the job row and the host row are then read back
    // through jobRead and jobTargetOne, which already map to JobRecord and
    // JobHostResult. Selecting `j.*, t.*` in one go would collide on state,
    // started_at and ended_at and need six aliases plus a second mapper, for a
    // read bounded at fifty rows.
    jobIdsForHost: db.prepare(
      'SELECT t.job_id AS job_id FROM job_target t JOIN job j ON j.id = t.job_id ' +
        'WHERE t.server_id = ?1 AND j.created_at >= ?2 AND j.created_at <= ?3 ' +
        'ORDER BY j.created_at DESC, j.id DESC LIMIT ?4'
    ),
    jobOutputInsert: db.prepare(
      'INSERT INTO job_output (job_id, server_id, seq, at, stream, text) VALUES (?, ?, ?, ?, ?, ?) ' +
        'ON CONFLICT(job_id, server_id, seq) DO UPDATE SET at = excluded.at, ' +
        '  stream = excluded.stream, text = excluded.text'
    ),
    jobOutputRead: db.prepare(
      'SELECT server_id, seq, at, stream, text FROM job_output WHERE job_id = ? AND server_id = ? ORDER BY seq'
    ),
    // Retention. Output goes on its own, much shorter horizon; the job and
    // target rows outlive it by a factor of twelve.
    jobDropOutput: db.prepare(
      'DELETE FROM job_output WHERE job_id IN (SELECT id FROM job WHERE created_at < ?)'
    ),
    jobDropTargets: db.prepare(
      'DELETE FROM job_target WHERE job_id IN (SELECT id FROM job WHERE created_at < ?)'
    ),
    jobDropJobs: db.prepare('DELETE FROM job WHERE created_at < ?'),
    // Everything belonging to ONE job id, for the re-run path. See createJob.
    jobTargetsClear: db.prepare('DELETE FROM job_target WHERE job_id = ?'),
    jobOutputClear: db.prepare('DELETE FROM job_output WHERE job_id = ?'),
    // The retention guard's second opinion about what time it is. See
    // jobRetain().
    newestJob: db.prepare('SELECT max(created_at) AS n FROM job'),
    countJobs: db.prepare('SELECT count(*) AS n FROM job'),
    countJobOutput: db.prepare('SELECT count(*) AS n FROM job_output')
  }

  const metricIds = new Map<Metric, number>(METRICS.map((m, i) => [m, i + 1]))
  /** The other direction, for the read that selects the metric column rather
   *  than binding it. Only the capacity three: nothing else asks. */
  const metricNames = new Map<number, CapacityMetric>(
    CAPACITY_METRICS.map((m) => [METRICS.indexOf(m) + 1, m])
  )
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
      return mergeTiers(
        st.seriesRead.all(host, m, from, to) as FullRow[],
        st.hourlyRead.all(host, m, from, to) as HourlyRow[]
      )
    },

    readTrends(hostId, from, to) {
      const out = {} as Record<CapacityMetric, SeriesPoint[]>
      const full = {} as Record<CapacityMetric, FullRow[]>
      const hourly = {} as Record<CapacityMetric, HourlyRow[]>
      for (const m of CAPACITY_METRICS) {
        full[m] = []
        hourly[m] = []
        out[m] = []
      }
      if (closed) return out
      const host = lookupHost(hostId)
      // A host the store has never seen has no trends. One scan of a time range
      // sees every host in it, so this filter is the only thing standing
      // between one host's panel and another host's disk.
      if (host === null) return out
      for (const r of st.trendRead.all(host, from, to) as (FullRow & { metric: number })[]) {
        const name = metricNames.get(Number(r.metric))
        if (name !== undefined) full[name].push(r)
      }
      for (const r of st.trendHourlyRead.all(host, from, to) as (HourlyRow & { metric: number })[]) {
        const name = metricNames.get(Number(r.metric))
        if (name !== undefined) hourly[name].push(r)
      }
      for (const m of CAPACITY_METRICS) out[m] = mergeTiers(full[m], hourly[m])
      return out
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

    // ---- Jobs -------------------------------------------------------------

    createJob(job) {
      if (droppedWrite(`job ${job.id}`)) return
      // One transaction. A job row whose targets did not land is a job the
      // runner would re-adopt with nothing to run and no way to say why.
      store.transaction(() => {
        // The id is REPLACED, not merged into, and that has to include the
        // rows hanging off it.
        //
        // The runner only refuses a LIVE id; a finished one is re-runnable and
        // the job row above is replaced wholesale. The targets were upserted
        // per id, so a host in the OLD list and not the new one survived — and
        // a re-run over one host reported the other as `ok`, a host it never
        // contacted. The output was never touched at all, while seq restarts
        // at zero, so the second run's first rows overwrote the first run's by
        // primary key and the rest of the first run's stayed behind: a single
        // host's output read back as the two runs interleaved, in seq order,
        // with nothing marking the seam.
        st.jobTargetsClear.run(job.id)
        st.jobOutputClear.run(job.id)
        st.jobInsert.run(
          job.id,
          job.createdAt,
          job.workspaceId,
          job.title,
          job.kind,
          JSON.stringify(job.spec),
          job.risk,
          JSON.stringify(job.confirmation),
          job.confirmedAt,
          job.approval === null ? null : JSON.stringify(job.approval),
          job.state
        )
        for (const t of job.targets) {
          st.jobTargetInsert.run(job.id, t.serverId, t.serverName, t.ord, t.state)
        }
      })
    },

    updateJob(jobId, patch) {
      if (droppedWrite(`a job transition (${jobId})`)) return
      const row = st.jobRead.get(jobId) as SqliteRow | undefined
      // A transition for a job that is not there is dropped rather than
      // inserted: an UPSERT here would resurrect a job retention just deleted,
      // as a row with no targets and no spec.
      if (row === undefined) return
      const pick = <K extends keyof JobPatch>(key: K, column: string): unknown =>
        key in patch ? (patch[key] ?? null) : (row[column] ?? null)
      st.jobUpdate.run(
        jobId,
        patch.state ?? String(row.state),
        pick('startedAt', 'started_at'),
        pick('endedAt', 'ended_at'),
        pick('cancelledAt', 'cancelled_at')
      )
    },

    updateJobTarget(jobId, serverId, patch) {
      if (droppedWrite(`a job host transition (${jobId}/${serverId})`)) return
      const row = st.jobTargetOne.get(jobId, serverId) as SqliteRow | undefined
      if (row === undefined) return
      const pick = <K extends keyof JobTargetPatch>(key: K, column: string): unknown =>
        key in patch ? (patch[key] ?? null) : (row[column] ?? null)
      st.jobTargetUpdate.run(
        jobId,
        serverId,
        patch.state ?? String(row.state),
        pick('outcome', 'outcome'),
        pick('exitCode', 'exit_code'),
        pick('error', 'error'),
        pick('startedAt', 'started_at'),
        pick('endedAt', 'ended_at'),
        patch.outOffset ?? Number(row.out_offset ?? 0),
        patch.outElided ?? Number(row.out_elided ?? 0),
        // `undefined` leaves the column alone, `null` clears it. The same
        // three-way the four timestamp columns above need, and for the same
        // reason: a reaped marker has to be CLEARABLE, and a patch language
        // that cannot say "clear this" is one the reap path works around.
        'detached' in patch
          ? patch.detached === null || patch.detached === undefined
            ? null
            : JSON.stringify(patch.detached)
          : (row.detached ?? null)
      )
    },

    appendJobOutput(jobId, serverId, lines) {
      if (lines.length === 0) return
      if (droppedWrite(`job output (${jobId}/${serverId})`)) return
      // The head+tail cap and the redaction both happen in the runner, not
      // here, and deliberately so. The cap is a decision about what is worth
      // keeping and needs the whole of a host's output to make; the store sees
      // one chunk at a time and could only ever apply a prefix rule, which is
      // the exact mistake the cap exists to correct. Redaction belongs with the
      // resolved secrets, which are the runner's, not the store's.
      store.transaction(() => {
        for (const l of lines) {
          st.jobOutputInsert.run(jobId, serverId, l.seq, l.at, l.stream, l.text)
        }
      })
    },

    listJobs(limit) {
      if (closed) return []
      const n = Math.max(1, Math.min(1000, limit ?? 100))
      return (st.jobList.all(n) as SqliteRow[]).map(toJobRecord)
    },

    readJob(jobId) {
      if (closed) return null
      const row = st.jobRead.get(jobId) as SqliteRow | undefined
      if (row === undefined) return null
      return {
        ...toJobRecord(row),
        targets: (st.jobTargetRead.all(jobId) as SqliteRow[]).map(toJobTarget)
      }
    },

    readJobOutput(jobId, serverId) {
      if (closed) return []
      return (st.jobOutputRead.all(jobId, serverId) as SqliteRow[]).map((r) => ({
        serverId: String(r.server_id),
        seq: Number(r.seq),
        at: Number(r.at),
        stream: String(r.stream) === 'err' ? ('err' as const) : ('out' as const),
        text: String(r.text)
      }))
    },

    jobsForHost(serverId, from, to, limit) {
      if (closed) return []
      if (typeof serverId !== 'string' || serverId === '') return []
      const n = Math.max(1, Math.min(200, limit ?? 50))
      const out: JobHostRun[] = []
      for (const row of st.jobIdsForHost.all(serverId, from, to, n) as SqliteRow[]) {
        const id = String(row.job_id)
        const job = st.jobRead.get(id) as SqliteRow | undefined
        const host = st.jobTargetOne.get(id, serverId) as SqliteRow | undefined
        // Both or neither. A job row without its target row is a half-deleted
        // retention pass caught mid-sweep, and half of a run is not a run.
        if (job === undefined || host === undefined) continue
        out.push({ job: toJobRecord(job), host: toJobTarget(host) })
      }
      return out
    },

    unfinishedJobs() {
      if (closed) return []
      return (st.jobUnfinished.all() as SqliteRow[]).map((row) => ({
        ...toJobRecord(row),
        targets: (st.jobTargetRead.all(String(row.id)) as SqliteRow[]).map(toJobTarget)
      }))
    },

    jobRetain(now = Date.now()) {
      const nothing: JobRetentionResult = { outputDropped: 0, jobsDropped: 0 }
      if (closed) return nothing
      // THE OUTPUT SWEEP takes no clock guard, and the argument is the one
      // written when these horizons were chosen. A wrong clock aging out
      // samples destroys the only copy of a measurement nobody can retake. A
      // wrong clock aging out job output destroys a record whose SUMMARY — the
      // job and target rows, on a horizon twelve times longer — is still there,
      // and which is regenerable by running the job again. What it costs is a
      // month of chatter, not a year of history.
      //
      // THE JOB-ROW SWEEP takes retain()'s guard, because that argument does
      // not survive being applied to it. It says the loss is bounded BECAUSE
      // the summary outlives the output twelve times over — and this branch is
      // what deletes the summary. A clock more than a year ahead is exactly the
      // snapshot-restore case retain()'s own guard cites, and retain() refuses
      // that very same pass, seconds later, with skipped: 'clock-ahead'. One
      // pass cannot coherently be too dangerous to age out an hourly bucket and
      // safe to delete the change log.
      //
      // Same second opinion, from the same rows plus this table's own: the
      // newest thing anybody wrote. Events are excluded for retain()'s reason —
      // the caller records a skip event, and a row written at the bogus time
      // would disarm the guard on the next pass.
      //
      // The blast-radius guard is still not applied, and that reason is
      // unchanged: a store holding two jobs, one of them old, legitimately
      // drops half of everything on the first pass. That is the normal case,
      // not the alarm.
      const outputCutoff = now - JOB_OUTPUT_RETENTION_DAYS * DAY_MS
      const jobCutoff = now - JOB_RECORD_RETENTION_DAYS * DAY_MS
      const newest = Math.max(
        num(st.newestJob.get()),
        num(st.newestSample.get()),
        num(st.newestHourly.get())
      )
      const clockAhead = newest > 0 && now - newest > RETENTION_CLOCK_GRACE_MS
      if (clockAhead) {
        console.error(
          `[history] job record retention skipped: the clock says ${new Date(now).toISOString()} ` +
            `but the newest row is ${new Date(newest).toISOString()}. Refusing to delete the job ` +
            `change log against a clock that far ahead. Output past its own horizon is still aged out.`
        )
      }
      return store.transaction(() => {
        const outputDropped = Number(st.jobDropOutput.run(outputCutoff).changes)
        if (clockAhead) return { outputDropped, jobsDropped: 0, skipped: 'clock-ahead' as const }
        // Targets before jobs: the target sweep selects by job id from `job`,
        // so deleting the parents first would strand every child row.
        st.jobDropTargets.run(jobCutoff)
        const jobsDropped = Number(st.jobDropJobs.run(jobCutoff).changes)
        return { outputDropped, jobsDropped }
      })
    },

    counts() {
      if (closed) return { samples: 0, hourly: 0, events: 0, facts: 0, jobs: 0, jobOutput: 0 }
      return {
        samples: num(st.countSamples.get()),
        hourly: num(st.countHourly.get()),
        events: num(st.countEvents.get()),
        facts: num(st.countFacts.get()),
        jobs: num(st.countJobs.get()),
        jobOutput: num(st.countJobOutput.get())
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

/** SQLite gives back `null` for a missing INTEGER; the record type says
 *  `number | null` and means it. */
function optNum(v: unknown): number | null {
  return v === null || v === undefined ? null : Number(v)
}

function optStr(v: unknown): string | undefined {
  return v === null || v === undefined ? undefined : String(v)
}

function toJobRecord(r: SqliteRow): JobRecord {
  return {
    id: String(r.id),
    createdAt: Number(r.created_at),
    workspaceId: r.workspace_id === null || r.workspace_id === undefined ? null : String(r.workspace_id),
    title: String(r.title),
    kind: String(r.kind) as JobKind,
    // A spec that will not parse is a row written by a build that is not this
    // one, or a row somebody edited. It becomes an EMPTY spec rather than
    // throwing: a job list that cannot render because one historical row is
    // malformed is a worse failure than one job showing no steps.
    spec: (safeParse(String(r.spec)) as JobSpec | undefined) ?? { kind: 'command', title: '', steps: [] },
    risk: String(r.risk) as BroadcastRisk,
    confirmation: (safeParse(String(r.confirmation)) as BroadcastConfirmation | undefined) ?? {
      kind: 'confirm'
    },
    confirmedAt: optNum(r.confirmed_at),
    // Validated on the way out, not merely parsed, for readHandle's reason: a
    // record that does not check out is a row from another build or one
    // somebody edited, and the runner is about to decide whether to start
    // commands on the strength of it. `null` reads exactly like a pre-B3 row,
    // which cannot be resumed — the safe direction.
    approval: readApproval(r.approval),
    // Read back as whatever the row says, NOT narrowed to the states this
    // build knows. A B2 row saying `detached` must come back saying
    // `detached` — a read that silently maps an unknown state onto a known one
    // is a store lying about its own contents to a build that could have
    // simply displayed the word.
    state: String(r.state) as JobState,
    startedAt: optNum(r.started_at),
    endedAt: optNum(r.ended_at),
    cancelledAt: optNum(r.cancelled_at)
  }
}

function toJobTarget(r: SqliteRow): JobHostResult {
  const startedAt = optNum(r.started_at)
  const endedAt = optNum(r.ended_at)
  return {
    serverId: String(r.server_id),
    serverName: String(r.server_name),
    state: String(r.state) as JobHostState,
    outcome: optStr(r.outcome) as JobHostResult['outcome'],
    exitCode: r.exit_code === null || r.exit_code === undefined ? undefined : Number(r.exit_code),
    error: optStr(r.error),
    // Derived rather than stored: two timestamps and their difference is one
    // fact written twice, and the second copy is the one that goes stale.
    ms: startedAt !== null && endedAt !== null ? endedAt - startedAt : undefined,
    ord: Number(r.ord),
    startedAt: startedAt ?? undefined,
    endedAt: endedAt ?? undefined,
    outOffset: Number(r.out_offset ?? 0),
    outElided: Number(r.out_elided ?? 0),
    truncated: Number(r.out_elided ?? 0) > 0 || undefined,
    // Validated on the way out, not merely parsed. A malformed handle is a row
    // written by a build that is not this one, or one somebody edited, and
    // handing it to reclaim() would send a `rm -rf` at whatever `dir` says.
    // `null` for anything that does not check out, which reads exactly like an
    // attached row — the safe direction.
    detached: readHandle(r.detached)
  }
}

function readApproval(v: unknown): CommandApproval | null {
  if (v === null || v === undefined) return null
  const parsed = safeParse(String(v))
  return isCommandApproval(parsed) ? parsed : null
}

function readHandle(v: unknown): JobDetachedHandle | null {
  if (v === null || v === undefined) return null
  const parsed = safeParse(String(v))
  return isJobDetachedHandle(parsed) ? parsed : null
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
  // `.bak.tmp` is where the backup is written before it is renamed onto the
  // .bak; a process that died under one leaves it, and "delete all data" has
  // to mean all of it.
  const files = [base, `${base}-wal`, `${base}-shm`, `${base}.bak`, `${base}.bak.tmp`]
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
