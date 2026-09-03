/**
 * Database operations — the operator's half of a database connection.
 *
 * `db.ts` can run a query. That is a client. This file is what an operator
 * actually needs from a server they are responsible for: is replication
 * running, is WAL reaching the archive, is anything about to hit transaction-ID
 * wraparound, who is blocking whom, and how big is it all getting.
 *
 * Everything here is PURE. It takes the rows a driver already handed back and
 * turns them into a status, a value and a judgement. No driver imports, no IO,
 * no `await`. That is what makes it testable against captured output from real
 * servers (tests/fixtures/dbops/) rather than against a mock of our own
 * assumptions — and the assumptions this file exists to kill were all found
 * that way, not by reasoning.
 *
 * ---------------------------------------------------------------------------
 * READ-ONLY, AND THAT IS NOT AN OVERSIGHT
 * ---------------------------------------------------------------------------
 *
 * Every statement this feature runs is a SELECT or a SHOW. There is no write,
 * no DDL, and no `KILL`/`pg_terminate_backend`, and there will not be one.
 * Following the refusal `src/shared/docker.ts` writes down for `prune`:
 *
 *  * `KILL <id>` / `pg_terminate_backend(pid)`. The lock panel below names the
 *    session blocking everything else, and the obvious next control is a button
 *    that kills it. It is not going here. Killing a backend rolls back whatever
 *    it was in the middle of, and the panel that offers the button cannot show
 *    what that was — `query` is the CURRENT statement, not the transaction, and
 *    on an unprivileged account it is `<insufficient privilege>` anyway. The
 *    operator would be terminating a transaction whose contents the UI could
 *    not display. If a session must die, that is a job: it goes through the job
 *    engine's approval model (roadmap B1), which records who asked, what was
 *    run and what came back, on a target the operator named.
 *  * `VACUUM` / `ANALYZE` / `OPTIMIZE TABLE`. The wraparound panel is the one
 *    place a "fix it" button is most tempting and most dangerous: a manual
 *    VACUUM FREEZE on a large table is hours of IO on a live server. The panel
 *    exists so the operator can schedule that themselves, in a window they
 *    chose.
 *  * `PURGE BINARY LOGS` / `pg_switch_wal()`. Deleting binlogs is deleting the
 *    only thing standing between a replica that fell behind and a rebuild.
 *  * Anything that resets a counter — `pg_stat_statements_reset()`,
 *    `FLUSH STATUS`. They are writes, they are shared, and a reset erases the
 *    history a colleague is mid-way through reading.
 *
 * ---------------------------------------------------------------------------
 * NOTHING IS INTERPOLATED
 * ---------------------------------------------------------------------------
 *
 * Every query is a frozen constant with `$1`/`?` placeholders, and
 * tests/dbOps.test.ts reads this file's source and fails if one of them grows a
 * `${`. There is no allowlisted-identifier path because no question here needs
 * one: every filter is a value, and a value binds.
 *
 * The two statements that genuinely CANNOT bind are the timeouts —
 * `SET statement_timeout` and `SET SESSION MAX_EXECUTION_TIME` take a literal,
 * not a parameter — so they are built by pgStatementTimeout/mysqlMaxExecutionTime
 * below, which validate an integer and throw on anything else.
 */

// ---------------------------------------------------------------------------
// Status vocabulary
// ---------------------------------------------------------------------------

/**
 * Why a question has the answer it has.
 *
 * The same distinction `src/shared/hostFacts.ts` draws for a host, for the same
 * reason: these views need privileges an application user very often lacks, and
 * "you are not allowed to see this" rendered as an empty table is a lie told in
 * exactly the hour it matters. `pg_stat_replication` needs `pg_monitor`;
 * `SHOW REPLICA STATUS` needs `REPLICATION CLIENT`. Neither absence is a zero.
 */
export type DbAnswerStatus =
  /** Read it. A zero here really is a zero. */
  | 'ok'
  /**
   * Read it, and this account is shown LESS than the whole truth without being
   * told so. MySQL's `information_schema.PROCESSLIST` without the PROCESS
   * privilege silently returns only the caller's own connections — no error, no
   * warning, just a smaller number. Captured, not theorised: see
   * tests/fixtures/dbops/mysql/unprivileged.json.
   */
  | 'partial'
  /** The view exists and this account may not read it. */
  | 'denied'
  /** The feature is not turned on here — archiving off, binary logging off. */
  | 'absent'
  /** The question does not apply to this server's role: replica lag on a
   *  server that is not a replica. */
  | 'not-applicable'
  /** This server version cannot answer at all, whatever the privileges. */
  | 'unsupported'
  /** The statement failed for some other reason; `detail` has the words. */
  | 'error'

export const DB_ANSWER_STATUSES: DbAnswerStatus[] = [
  'ok',
  'partial',
  'denied',
  'absent',
  'not-applicable',
  'unsupported',
  'error'
]

/** One sentence per status, written for the person deciding whether to act on
 *  the number beside it. */
export const DB_ANSWER_HELP: Record<DbAnswerStatus, string> = {
  ok: 'Read successfully. A zero here means zero, not "we could not look".',
  partial:
    'The server answered, but this account is only shown part of the picture and is not told so. Treat the numbers as a floor, never as the total.',
  denied:
    'This exists and the account ShellPilot connected as was not allowed to read it. A more privileged account would see more. This is NOT the same as "there is nothing here".',
  absent: 'The feature this question is about is not enabled on this server, so there is nothing to read.',
  'not-applicable': 'This question does not apply to the role this server is playing.',
  unsupported: 'This server version cannot answer this question at all. Treat it as UNKNOWN, never as zero.',
  error: 'The statement failed. The server’s own words are shown beside it.'
}

/**
 * How worried to be.
 *
 * `unknown` is deliberately NOT `ok`. The whole point of the item is that a
 * number nobody looked at is not a judgement, and a question we could not ask
 * is not a pass.
 */
export type DbVerdictLevel = 'ok' | 'watch' | 'alarm' | 'unknown'

export const DB_VERDICT_RANK: Record<DbVerdictLevel, number> = {
  ok: 0,
  unknown: 1,
  watch: 2,
  alarm: 3
}

export interface DbVerdict {
  level: DbVerdictLevel
  /** A sentence, not a cell. "Replication is 4h 12m behind." */
  headline: string
  /** The mechanics underneath it, when there are any worth printing. */
  because?: string
}

export interface DbAnswer<T> {
  id: DbQuestionId
  status: DbAnswerStatus
  verdict: DbVerdict
  /** The engine's own words when something went wrong. Never paraphrased away. */
  detail?: string
  value?: T
}

// ---------------------------------------------------------------------------
// The questions
// ---------------------------------------------------------------------------

/**
 * Eight per engine, and choosing them was the actual work.
 *
 * The rule applied: a question earns its place if a wrong answer to it takes
 * the database down, loses data, or is the thing the operator will be asked
 * about at 3am. Everything that is merely interesting was cut — buffer/cache
 * ratios on Postgres (unactionable without knowing the workload), index usage
 * (a query-tuning question, not an operations one), per-user connection
 * breakdowns (a report, not an alarm).
 */
export const PG_QUESTIONS = [
  'overview',
  'replication',
  'archiver',
  'autovacuum',
  'connections',
  'locks',
  'sizes',
  'statements'
] as const

export const MYSQL_QUESTIONS = [
  'overview',
  'replication',
  'binlogs',
  'slowlog',
  'connections',
  'processlist',
  'bufferpool',
  'sizes'
] as const

export type PgQuestionId = (typeof PG_QUESTIONS)[number]
export type MysqlQuestionId = (typeof MYSQL_QUESTIONS)[number]
export type DbQuestionId = PgQuestionId | MysqlQuestionId

export const DB_QUESTION_LABEL: Record<DbQuestionId, string> = {
  overview: 'Server',
  replication: 'Replication',
  archiver: 'WAL archiving',
  autovacuum: 'Autovacuum and wraparound',
  connections: 'Connections',
  locks: 'Blocking locks',
  sizes: 'Size and growth',
  statements: 'Statement history',
  binlogs: 'Binary logs',
  slowlog: 'Slow query log',
  processlist: 'Running queries',
  bufferpool: 'InnoDB buffer pool'
}

/** Why this one is on the page. Shown in the UI, so the editorial choice is
 *  visible to the operator rather than only to whoever wrote it. */
export const DB_QUESTION_WHY: Record<DbQuestionId, string> = {
  overview: 'Which server this is, what role it is playing, and how long it has been up.',
  replication:
    'A replica that has stopped is a backup that is not being taken and a read pool serving stale rows. It fails silently.',
  archiver:
    'A climbing failed_count is an outage in slow motion: WAL is not reaching the archive, so point-in-time recovery is already broken and pg_wal is filling the disk.',
  autovacuum:
    'Transaction-ID wraparound is the one that takes a Postgres database down hard, and it announces itself for weeks first as a rising relfrozenxid age.',
  connections: 'Running out of connections refuses every new client at once, including the one you would use to fix it.',
  locks: 'One session holding a lock stalls every session behind it, and none of them look broken on their own.',
  sizes: 'Where the disk went, and which table is taking it.',
  statements: 'Which statements actually cost this server its time.',
  binlogs: 'Binary logs are point-in-time recovery and the only thing a lagging replica can catch up from. They are also a disk that fills.',
  slowlog: 'Whether the server is even recording slow queries. If it is off, the absence of slow queries means nothing.',
  processlist: 'What is running right now, and what has been running far too long.',
  bufferpool: 'A buffer pool that stopped holding the working set turns every read into disk IO.'
}

// ---------------------------------------------------------------------------
// Thresholds
// ---------------------------------------------------------------------------

/**
 * Named, in one place, with the reason. A magic number buried in a comparison
 * is a judgement nobody can argue with.
 */
export const DB_THRESHOLDS = {
  /** Replica lag. A minute is noise on a busy server; an hour is a decision. */
  replicaLagWatchSeconds: 60,
  replicaLagAlarmSeconds: 3600,
  /** Fraction of autovacuum_freeze_max_age. Postgres itself forces an
   *  anti-wraparound vacuum at 1.0; half of that is when a human should be
   *  planning the window rather than discovering it. */
  freezeWatchFraction: 0.5,
  freezeAlarmFraction: 0.9,
  /** Absolute backstop, independent of the setting. Wraparound is at 2^31;
   *  Postgres refuses new transactions at 2^31 - 1e7. */
  freezeAlarmAbsolute: 1_500_000_000,
  /** Fraction of max_connections. */
  connectionsWatchFraction: 0.8,
  connectionsAlarmFraction: 0.9,
  /** An idle-in-transaction session holds back vacuum and keeps its locks. */
  idleInTransactionWatchSeconds: 300,
  idleInTransactionAlarmSeconds: 900,
  /** How long a session may sit behind a lock before it is worth a page. */
  lockWaitWatchSeconds: 10,
  lockWaitAlarmSeconds: 60,
  /** A single running statement. */
  longQueryWatchSeconds: 60,
  longQueryAlarmSeconds: 300,
  /** InnoDB buffer pool hit rate. */
  bufferPoolWatchRate: 0.99,
  bufferPoolAlarmRate: 0.95,
  /**
   * The buffer pool hit rate is meaningless on a server that has just started —
   * every first read is a miss. Measured, not assumed: a Postgres/MySQL pair
   * five minutes old reported a 93.9% hit rate, which would have alarmed for a
   * server doing nothing wrong. Below either of these the verdict is `unknown`.
   */
  bufferPoolMinUptimeSeconds: 3600,
  bufferPoolMinReadRequests: 1_000_000,
  /** A slow log whose threshold is this high records almost nothing. */
  slowLogUselessThresholdSeconds: 10
} as const

/**
 * Where PostgreSQL actually stops.
 *
 * 2^31 minus the 10 million transaction safety margin it keeps for the vacuum
 * that has to get you out. This is the denominator for the sentence "N% of the
 * way to transaction-ID wraparound"; `autovacuum_freeze_max_age` is NOT — that
 * is where autovacuum STARTS, 200 million by default, and 90% of it is 8.5% of
 * the way to wraparound. A busy table cycles that band as normal steady state.
 */
export const PG_WRAPAROUND_XID_LIMIT = 2_147_483_647 - 10_000_000

// ---------------------------------------------------------------------------
// Coercion
// ---------------------------------------------------------------------------

/**
 * A driver value to a number, or null.
 *
 * The single most important function in this file, because of what it REFUSES
 * to do: `num(null)` is `null`. `pg` hands back `bigint` and `numeric` columns
 * as strings; `mysql2` hands `SHOW STATUS` values back as strings and
 * `Seconds_Behind_Source` back as a number or as `null`. A `Number(x) || 0`
 * anywhere on that path turns "the server would not say" into "zero", which is
 * the bug this whole feature exists to not have.
 */
export function num(v: unknown): number | null {
  if (v === null || v === undefined) return null
  if (typeof v === 'number') return Number.isFinite(v) ? v : null
  if (typeof v === 'bigint') return Number(v)
  if (typeof v === 'boolean') return v ? 1 : 0
  if (typeof v === 'string') {
    const t = v.trim()
    if (t === '') return null
    const n = Number(t)
    return Number.isFinite(n) ? n : null
  }
  return null
}

/** A driver value to a string, or null. Empty string stays empty — MySQL uses
 *  `''` for "no error", which is different from "no such column". */
export function str(v: unknown): string | null {
  if (v === null || v === undefined) return null
  if (typeof v === 'string') return v
  if (typeof v === 'number' || typeof v === 'bigint' || typeof v === 'boolean') return String(v)
  return null
}

/** MySQL reports booleans as 0/1, Postgres as true/false, and both drivers
 *  sometimes as the strings 'ON'/'OFF'. */
export function bool(v: unknown): boolean | null {
  if (v === null || v === undefined) return null
  if (typeof v === 'boolean') return v
  const n = num(v)
  if (n !== null && (typeof v === 'number' || typeof v === 'bigint')) return n !== 0
  const s = str(v)?.trim().toLowerCase()
  if (s === undefined || s === null) return null
  if (s === 'on' || s === 'yes' || s === 'true' || s === '1') return true
  if (s === 'off' || s === 'no' || s === 'false' || s === '0') return false
  return null
}

// ---------------------------------------------------------------------------
// Formatting — a duration a person reads, not a float
// ---------------------------------------------------------------------------

export function formatSeconds(s: number | null | undefined): string {
  if (s === null || s === undefined || !Number.isFinite(s)) return 'unknown'
  const n = Math.max(0, Math.round(s))
  if (n < 60) return `${n}s`
  const m = Math.floor(n / 60)
  if (m < 60) return `${m}m ${n % 60}s`
  const h = Math.floor(m / 60)
  if (h < 24) return `${h}h ${m % 60}m`
  return `${Math.floor(h / 24)}d ${h % 24}h`
}

const UNITS = ['B', 'KB', 'MB', 'GB', 'TB', 'PB']

export function formatBytes(b: number | null | undefined): string {
  if (b === null || b === undefined || !Number.isFinite(b)) return 'unknown'
  let n = Math.abs(b)
  let i = 0
  while (n >= 1024 && i < UNITS.length - 1) {
    n /= 1024
    i++
  }
  const sign = b < 0 ? '-' : ''
  return `${sign}${i === 0 ? Math.round(n) : n.toFixed(n < 10 ? 1 : 0)} ${UNITS[i]}`
}

/** A count, grouped. 1500000 -> "1,500,000". */
export function formatCount(n: number | null | undefined): string {
  if (n === null || n === undefined || !Number.isFinite(n)) return 'unknown'
  return Math.round(n).toLocaleString('en-US')
}

// ---------------------------------------------------------------------------
// Failure classification
// ---------------------------------------------------------------------------

export interface DbFailure {
  status: DbAnswerStatus
  detail: string
}

/**
 * A Postgres error to a status.
 *
 * SQLSTATE first, because it is stable across versions and locales; the message
 * text is only consulted when there is no code, which happens for driver-level
 * failures. The three codes that matter:
 *
 *  * 42501 insufficient_privilege — `denied`.
 *  * 42P01 undefined_table and 42883 undefined_function — the object is not
 *    there. For `pg_stat_statements` that is `absent` (an extension nobody
 *    installed), which is a first-class answer, not an error. Captured from a
 *    real database without the extension: SQLSTATE 42P01, "relation
 *    \"pg_stat_statements\" does not exist".
 *  * 55000 object_not_in_prerequisite_state — what `pg_last_wal_receive_lsn()`
 *    raises on a primary ("recovery is not in progress"). That is `not-applicable`:
 *    the question was aimed at the wrong role, not refused.
 */
export function classifyPgFailure(code: string | null | undefined, message: string): DbFailure {
  const detail = (message || '').trim() || 'The statement failed and the server said nothing.'
  const c = (code || '').trim()
  if (c === '42501') return { status: 'denied', detail }
  if (c === '42P01' || c === '42883' || c === '3F000') return { status: 'absent', detail }
  // Checked before the SQLSTATE below because Postgres raises 55000 for two
  // completely different situations: "recovery is not in progress" (the
  // question was aimed at the wrong role) and "pg_stat_statements must be
  // loaded via shared_preload_libraries" (the extension row exists, the
  // library does not). Seen on a standby built by pg_basebackup, which inherits
  // the CREATE EXTENSION and not the postgresql.conf.
  if (/shared_preload_libraries/i.test(detail)) return { status: 'absent', detail }
  if (c === '55000') return { status: 'not-applicable', detail }
  if (c === '42703' || c === '42601') return { status: 'unsupported', detail }
  const m = detail.toLowerCase()
  if (/permission denied|must be superuser|insufficient privilege/.test(m)) return { status: 'denied', detail }
  if (/does not exist/.test(m)) return { status: 'absent', detail }
  return { status: 'error', detail }
}

/**
 * A MySQL/MariaDB error to a status.
 *
 * Every code below was produced by a real server and is in
 * tests/fixtures/dbops/:
 *
 *  * 1227 ER_SPECIFIC_ACCESS_DENIED_ERROR — "you need (at least one of) the
 *    SUPER, REPLICATION CLIENT privilege(s)". What an application user gets for
 *    `SHOW REPLICA STATUS` and `SHOW BINARY LOGS`. `denied`.
 *  * 1381 ER_NO_BINARY_LOGGING — `SHOW BINARY LOGS` on a server with the binlog
 *    off. An ERROR, not an empty list, and it means `absent`.
 *  * 1064 ER_PARSE_ERROR — MariaDB 10.4 on `SHOW REPLICA STATUS`. The statement
 *    does not exist in that dialect, so this is `unsupported` and the caller
 *    falls back to the older spelling. It is emphatically not a failure.
 *  * 1193 ER_UNKNOWN_SYSTEM_VARIABLE — `@@binlog_expire_logs_seconds` on
 *    MariaDB, which spells it `@@expire_logs_days`. `unsupported`, same fallback.
 */
export function classifyMysqlFailure(errno: number | null | undefined, message: string): DbFailure {
  const detail = (message || '').trim() || 'The statement failed and the server said nothing.'
  switch (errno) {
    case 1227:
    case 1045:
    case 1142:
    case 1143:
      return { status: 'denied', detail }
    case 1381:
      return { status: 'absent', detail }
    case 1064:
    case 1193:
    case 1146:
      return { status: 'unsupported', detail }
    default:
      break
  }
  const m = detail.toLowerCase()
  if (/access denied|privilege/.test(m)) return { status: 'denied', detail }
  if (/you have an error in your sql syntax|unknown system variable/.test(m)) return { status: 'unsupported', detail }
  if (/not using binary logging/.test(m)) return { status: 'absent', detail }
  return { status: 'error', detail }
}

// ---------------------------------------------------------------------------
// Statement timeouts — the only two statements that cannot bind a parameter
// ---------------------------------------------------------------------------

/**
 * `SET statement_timeout = 5000`.
 *
 * Postgres will not take a parameter here — `SET statement_timeout = $1` is a
 * syntax error — so this is the one place a value is written into SQL text, and
 * it is the reason this function exists rather than a template literal at the
 * call site. It throws rather than sanitising: a caller passing something that
 * is not a plain positive integer has a bug, and quietly clamping it would hide
 * the bug while still being the shape an injection takes.
 */
export function pgStatementTimeout(ms: number): string {
  return `SET statement_timeout = ${safeMs(ms)}`
}

/** `SET SESSION MAX_EXECUTION_TIME = 5000`. Same constraint, same guard. */
export function mysqlMaxExecutionTime(ms: number): string {
  return `SET SESSION MAX_EXECUTION_TIME = ${safeMs(ms)}`
}

/**
 * `SET SESSION max_statement_time = 8`. MariaDB, which spells it differently
 * AND counts in SECONDS.
 *
 * Not a nicety. MariaDB raises ER_UNKNOWN_SYSTEM_VARIABLE (1193) on
 * MAX_EXECUTION_TIME, so before this existed the collector caught that, shrugged,
 * and ran unbounded — including `sizes`, which stats every file on the server.
 * A best-effort net that is always absent on one of the two supported flavours
 * is not a net. The value is rounded UP to a whole second, because rounding a
 * sub-second budget down to zero means "no limit" in MariaDB.
 */
export function mariadbMaxStatementTime(ms: number): string {
  return `SET SESSION max_statement_time = ${Math.max(1, Math.ceil(safeMs(ms) / 1000))}`
}

/**
 * Every statement this feature sends that is NOT in PG_QUERIES/MYSQL_QUERIES.
 *
 * Enumerated so the read-only assertion in tests/dbOpsRegressions.test.ts can
 * see them. They were the hole: the test that proves nothing here writes
 * iterated the query maps, and these were the only statements the app sends
 * that the assertion never saw.
 */
export const DB_TIMEOUT_STATEMENT_BUILDERS: ((ms: number) => string)[] = [
  pgStatementTimeout,
  mysqlMaxExecutionTime,
  mariadbMaxStatementTime
]

/**
 * Strip credentials and hostnames out of an engine's own error text.
 *
 * `Last_IO_Error` reads, verbatim: `error connecting to master
 * 'replicator@db-eu.internal:3306' - ... Unknown MySQL server host
 * 'db-eu.internal' (-2)`. That sentence is shown on screen AND written into the
 * durable event store, where it becomes a replication username and a source
 * host sitting in a table nobody thinks of as sensitive. The judgement does not
 * need either to be right, so neither is kept.
 */
export function redactDbIdentifiers(text: string): string {
  return text
    .replace(/'[^'@\s]+@[^']*'/g, "'<redacted>'")
    .replace(/\b(host|master|source)\s+'[^']*'/gi, "$1 '<redacted>'")
    .replace(/\buser\s+'[^']*'/gi, "user '<redacted>'")
    .replace(/\b\d{1,3}(?:\.\d{1,3}){3}\b/g, '<redacted>')
}

function safeMs(ms: unknown): number {
  if (typeof ms !== 'number' || !Number.isInteger(ms) || ms <= 0 || ms > 3_600_000) {
    throw new Error(`Refusing to build a timeout statement from ${JSON.stringify(ms)}: expected a positive integer of milliseconds.`)
  }
  return ms
}

// ===========================================================================
// Postgres
// ===========================================================================

export interface PgOverview {
  serverVersion: string
  versionNum: number
  inRecovery: boolean
  maxConnections: number
  /** `superuser_reserved_connections`, and on PostgreSQL 16+ the separate
   *  `reserved_connections`. max_connections is not the ceiling an ordinary
   *  client can reach: these come off it first. */
  superuserReservedConnections: number
  reservedConnections: number
  autovacuumFreezeMaxAge: number
  archiveMode: string
  walLevel: string
  database: string
  username: string
  uptimeSeconds: number | null
}

export interface PgReplica {
  applicationName: string | null
  clientAddr: string | null
  state: string | null
  syncState: string | null
  writeLagSeconds: number | null
  flushLagSeconds: number | null
  replayLagSeconds: number | null
  sentLagBytes: number | null
  replayLagBytes: number | null
  replyAgeSeconds: number | null
  /**
   * The row is there and everything that would answer the question is NULL.
   *
   * Not hypothetical. A role without `pg_monitor` SELECTing pg_stat_replication
   * gets one row per walsender with `application_name` filled in and `state`,
   * `sync_state` and every lag column NULL — no error, no warning. Rendered
   * naively that is "0 bytes behind, streaming", which is the Postgres twin of
   * the Seconds_Behind_Source trap. Captured in
   * tests/fixtures/dbops/postgres/unprivileged.json.
   */
  redacted: boolean
}

export interface PgReplicationPrimary {
  role: 'primary'
  replicas: PgReplica[]
}

export interface PgReplicationStandby {
  role: 'standby'
  receiveLsn: string | null
  replayLsn: string | null
  replayAgeSeconds: number | null
  replayPaused: boolean
  applyLagBytes: number | null
  /**
   * `pg_last_xact_replay_timestamp()` is NULL until this standby replays its
   * first COMMIT. Measured on a freshly built standby that was streaming
   * perfectly. "No timestamp" is therefore NOT "no lag" — it is "no evidence
   * either way", and it is reported as unknown.
   */
  neverReplayed: boolean
}

export type PgReplicationValue = PgReplicationPrimary | PgReplicationStandby

export interface PgArchiver {
  archiveMode: string
  archivedCount: number | null
  lastArchivedWal: string | null
  lastArchivedAgeSeconds: number | null
  failedCount: number | null
  lastFailedWal: string | null
  lastFailedAgeSeconds: number | null
  statsResetAgeSeconds: number | null
}

export interface PgVacuumTable {
  schema: string
  name: string
  /** 'r' ordinary, 'm' materialised view, 't' TOAST. Partitioned parents ('p')
   *  are not asked for: they hold no rows, their relfrozenxid is 0, and
   *  `age()` of a non-normal xid is INT_MAX rather than an error. */
  relkind: string | null
  /** For a TOAST relation, the table it belongs to. `pg_toast.pg_toast_16384`
   *  is not a name anybody can act on. */
  parent: string | null
  xidAge: number | null
  deadTuples: number | null
  liveTuples: number | null
  lastAutovacuumAgeSeconds: number | null
  lastVacuumAgeSeconds: number | null
  lastAutoanalyzeAgeSeconds: number | null
  /** xidAge as a fraction of autovacuum_freeze_max_age. */
  freezeFraction: number | null
}

export interface PgDatabaseAge {
  name: string
  xidAge: number | null
  freezeFraction: number | null
  /** Fraction of the point at which PostgreSQL stops accepting transactions. */
  wraparoundFraction: number | null
}

export interface PgVacuumValue {
  freezeMaxAge: number
  tables: PgVacuumTable[]
  /**
   * `age(datfrozenxid)` per database.
   *
   * pg_class is per-database and wraparound is a property of the CLUSTER, so
   * the table list above can only ever see one database's share of it. A
   * neighbouring database at 1.9 billion takes this one down with it.
   */
  databases: PgDatabaseAge[]
}

export interface PgConnectionState {
  /**
   * NULL is not a state. It is the signature of a backend this role may see and
   * may not read: without pg_read_all_stats, pg_stat_activity returns the row
   * with `state`, `query_start`, `query` and `wait_event*` all NULL and raises
   * nothing. COALESCE-ing it to a word laundered that into a bucket no rule
   * inspects, which made the idle-in-transaction alarm unreachable.
   */
  state: string | null
  n: number
  oldestSeconds: number | null
}

export interface PgConnectionsValue {
  maxConnections: number
  /** `superuser_reserved_connections` (+ PG16 `reserved_connections`). */
  superuserReserved: number
  reserved: number
  /** What an ordinary client can actually reach. */
  usableConnections: number
  states: PgConnectionState[]
  used: number
  /** Backends counted but not readable. See PgConnectionState.state. */
  redactedCount: number
}

export interface PgLock {
  pid: number
  username: string | null
  state: string | null
  /**
   * How long this session has been waiting — or NULL because the role may not
   * read `query_start` for a backend it does not own. `?? 0` turned a two-hour
   * block into "briefly blocked (0s)".
   */
  waitingSeconds: number | null
  /** The row is blocked and this account may not see for how long. */
  redacted: boolean
  blockedBy: number[]
  waitEventType: string | null
  waitEvent: string | null
  query: string | null
}

export interface PgSized {
  schema?: string
  name: string
  totalBytes: number | null
  heapBytes?: number | null
  indexBytes?: number | null
}

export interface PgSizesValue {
  databases: PgSized[]
  tables: PgSized[]
}

export interface PgStatement {
  query: string
  calls: number | null
  totalExecMs: number | null
  meanExecMs: number | null
  rows: number | null
}

export interface PgStatementsValue {
  extensionVersion: string | null
  /** True when EVERY statement's text was redacted. */
  redactedText: boolean
  /**
   * How many statement texts came back as `<insufficient privilege>`.
   *
   * Postgres keeps the timings and hides the text from a role that lacks
   * pg_read_all_stats — but it shows the role its OWN statements, so the usual
   * result is a partly-redacted list rather than a wholly redacted one. Counted
   * rather than flagged, because "3 of 20 shown" and "0 of 20 shown" are
   * different situations and a boolean cannot tell them apart.
   */
  redactedCount: number
  statements: PgStatement[]
}

/** Postgres reports a redacted statement text with this exact literal. */
export const PG_REDACTED_QUERY = '<insufficient privilege>'

// ---- Queries --------------------------------------------------------------
//
// Frozen, parameterised, and asserted free of interpolation by
// tests/dbOps.test.ts. `$1` is always a row limit.

export const PG_QUERIES = Object.freeze({
  overview: `SELECT current_setting('server_version') AS server_version,
       current_setting('server_version_num')::int AS version_num,
       pg_is_in_recovery() AS in_recovery,
       current_setting('max_connections')::int AS max_connections,
       current_setting('superuser_reserved_connections')::int AS superuser_reserved,
       -- PostgreSQL 16 added a second reserve on top of the superuser one. The
       -- missing_ok form of current_setting returns NULL on 15 and below rather
       -- than raising, which is what keeps this query working on both.
       current_setting('reserved_connections', true)::int AS reserved,
       current_setting('autovacuum_freeze_max_age')::bigint AS freeze_max_age,
       current_setting('archive_mode') AS archive_mode,
       current_setting('wal_level') AS wal_level,
       current_database() AS database,
       current_user AS username,
       EXTRACT(EPOCH FROM (now() - pg_postmaster_start_time()))::bigint AS uptime_seconds`,

  replication: `SELECT application_name, host(client_addr) AS client_addr, state, sync_state,
       EXTRACT(EPOCH FROM write_lag) AS write_lag_seconds,
       EXTRACT(EPOCH FROM flush_lag) AS flush_lag_seconds,
       EXTRACT(EPOCH FROM replay_lag) AS replay_lag_seconds,
       pg_wal_lsn_diff(pg_current_wal_lsn(), sent_lsn)::bigint AS sent_lag_bytes,
       pg_wal_lsn_diff(pg_current_wal_lsn(), replay_lsn)::bigint AS replay_lag_bytes,
       EXTRACT(EPOCH FROM (now() - reply_time)) AS reply_age_seconds
  FROM pg_stat_replication ORDER BY application_name`,

  // A standby does not appear in its own pg_stat_replication — that view lists
  // the walsenders a PRIMARY is feeding. Asking a replica how far behind it is
  // means asking it directly, which is this.
  standby: `SELECT pg_last_wal_receive_lsn()::text AS receive_lsn,
       pg_last_wal_replay_lsn()::text AS replay_lsn,
       EXTRACT(EPOCH FROM (now() - pg_last_xact_replay_timestamp())) AS replay_age_seconds,
       pg_is_wal_replay_paused() AS replay_paused,
       pg_wal_lsn_diff(pg_last_wal_receive_lsn(), pg_last_wal_replay_lsn())::bigint AS apply_lag_bytes`,

  archiver: `SELECT archived_count::bigint AS archived_count, last_archived_wal,
       EXTRACT(EPOCH FROM (now() - last_archived_time)) AS last_archived_age_seconds,
       failed_count::bigint AS failed_count, last_failed_wal,
       EXTRACT(EPOCH FROM (now() - last_failed_time)) AS last_failed_age_seconds,
       EXTRACT(EPOCH FROM (now() - stats_reset))::bigint AS stats_reset_age_seconds
  FROM pg_stat_archiver`,

  // pg_class carries relfrozenxid; pg_stat_user_tables carries the vacuum
  // history. The LEFT JOIN is deliberate: a table that autovacuum has never
  // touched has no stats row, and dropping it would hide the table most likely
  // to be the problem.
  //
  // The relkind filter is not a tidiness choice, it is the whole correctness of
  // this question:
  //
  //  * 'p', a PARTITIONED PARENT, is excluded. It holds no rows, so its
  //    relfrozenxid is 0, and `age()` of a non-normal xid returns INT_MAX
  //    rather than raising — 2147483647 against a 200 million
  //    autovacuum_freeze_max_age is 1074%. Any database using declarative
  //    partitioning — which is most databases big enough to care about
  //    wraparound — opened this page to a permanent red alarm, and because the
  //    sort is `ORDER BY age(relfrozenxid) DESC` the storage-less parents took
  //    every one of the LIMIT $1 rows and hid the real worst table behind them.
  //    `NOT (relfrozenxid = '0'::xid)` catches the same thing for any other
  //    storage-less relation. (Negated equality because `xid` is guaranteed the
  //    `=` operator and nothing else.)
  //  * 't', a TOAST relation, is now INCLUDED, and pg_toast is no longer
  //    excluded by namespace. A toast table ages independently of its parent
  //    and is a classic wraparound source; excluding it hid exactly the kind of
  //    table this question exists to find. The join to the owning relation is
  //    so the answer can say `public.documents (TOAST)` rather than
  //    `pg_toast.pg_toast_16384`, which nobody can act on.
  vacuum: `SELECT n.nspname AS schema, c.relname AS name, c.relkind::text AS relkind,
       pn.nspname AS parent_schema, p.relname AS parent_name,
       age(c.relfrozenxid)::bigint AS xid_age,
       COALESCE(s.n_dead_tup, 0)::bigint AS dead_tuples,
       COALESCE(s.n_live_tup, 0)::bigint AS live_tuples,
       EXTRACT(EPOCH FROM (now() - s.last_autovacuum))::bigint AS last_autovacuum_age_seconds,
       EXTRACT(EPOCH FROM (now() - s.last_vacuum))::bigint AS last_vacuum_age_seconds,
       EXTRACT(EPOCH FROM (now() - s.last_autoanalyze))::bigint AS last_autoanalyze_age_seconds
  FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
  LEFT JOIN pg_stat_user_tables s ON s.relid = c.oid
  LEFT JOIN pg_class p ON p.reltoastrelid = c.oid
  LEFT JOIN pg_namespace pn ON pn.oid = p.relnamespace
  WHERE c.relkind IN ('r','m','t')
    AND NOT (c.relfrozenxid = '0'::xid)
    AND n.nspname NOT IN ('pg_catalog','information_schema')
  ORDER BY age(c.relfrozenxid) DESC LIMIT $1`,

  // Wraparound is a CLUSTER property and pg_class is per-database, so the
  // question above can only ever see one database's worth of it. datfrozenxid
  // is the cluster's real position, and it is readable by anybody.
  databaseAges: `SELECT datname AS name, age(datfrozenxid)::bigint AS xid_age
  FROM pg_database ORDER BY 2 DESC`,

  connections: `SELECT state, count(*)::int AS n,
       MAX(EXTRACT(EPOCH FROM (now() - state_change)))::bigint AS oldest_seconds
  FROM pg_stat_activity WHERE backend_type = 'client backend' GROUP BY 1 ORDER BY 2 DESC`,

  locks: `SELECT a.pid, a.usename AS username, a.state,
       EXTRACT(EPOCH FROM (now() - a.query_start))::bigint AS waiting_seconds,
       pg_blocking_pids(a.pid) AS blocked_by, a.wait_event_type, a.wait_event,
       left(a.query, 200) AS query
  FROM pg_stat_activity a
  WHERE cardinality(pg_blocking_pids(a.pid)) > 0 ORDER BY 4 DESC NULLS LAST LIMIT $1`,

  databases: `SELECT datname AS name, pg_database_size(oid)::bigint AS bytes
  FROM pg_database WHERE datallowconn ORDER BY 2 DESC`,

  tables: `SELECT n.nspname AS schema, c.relname AS name,
       pg_total_relation_size(c.oid)::bigint AS total_bytes,
       pg_relation_size(c.oid)::bigint AS heap_bytes,
       pg_indexes_size(c.oid)::bigint AS index_bytes
  FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
  WHERE c.relkind IN ('r','m') AND n.nspname NOT IN ('pg_catalog','information_schema','pg_toast')
  ORDER BY 3 DESC LIMIT $1`,

  // Detect, do not assume. pg_extension is per-database, which is exactly the
  // granularity that matters: the extension can be loaded in one database of a
  // cluster and absent in the next.
  extension: `SELECT extversion FROM pg_extension WHERE extname = 'pg_stat_statements'`,

  // pg_stat_statements 1.8 (Postgres 13) renamed total_time/mean_time to
  // total_exec_time/mean_exec_time. Both spellings ship; the caller tries the
  // modern one and falls back on SQLSTATE 42703.
  statements: `SELECT left(query, 300) AS query, calls::bigint AS calls,
       total_exec_time, mean_exec_time, rows::bigint AS rows
  FROM pg_stat_statements ORDER BY total_exec_time DESC LIMIT $1`,

  statementsLegacy: `SELECT left(query, 300) AS query, calls::bigint AS calls,
       total_time AS total_exec_time, mean_time AS mean_exec_time, rows::bigint AS rows
  FROM pg_stat_statements ORDER BY total_time DESC LIMIT $1`
})

/**
 * The oldest Postgres this feature will speak to.
 *
 * 9.6 for `pg_blocking_pids()`, 10 for `pg_wal_lsn_diff` and the
 * `pg_current_wal_lsn` spelling. 10 is the floor, and versions below it get
 * `unsupported` on the questions that need those rather than a syntax error
 * presented as a database problem.
 */
export const PG_MIN_VERSION_NUM = 100000

type Row = Record<string, unknown>

export function parsePgOverview(row: Row | undefined): PgOverview | null {
  if (!row) return null
  return {
    serverVersion: str(row.server_version) ?? 'unknown',
    versionNum: num(row.version_num) ?? 0,
    inRecovery: bool(row.in_recovery) ?? false,
    maxConnections: num(row.max_connections) ?? 0,
    superuserReservedConnections: num(row.superuser_reserved) ?? 0,
    // NULL on PostgreSQL 15 and below, where the setting does not exist.
    reservedConnections: num(row.reserved) ?? 0,
    autovacuumFreezeMaxAge: num(row.freeze_max_age) ?? 200_000_000,
    archiveMode: str(row.archive_mode) ?? 'unknown',
    walLevel: str(row.wal_level) ?? 'unknown',
    database: str(row.database) ?? '',
    username: str(row.username) ?? '',
    uptimeSeconds: num(row.uptime_seconds)
  }
}

export function parsePgReplicas(rows: Row[]): PgReplica[] {
  return rows.map((r) => {
    const replica: PgReplica = {
      applicationName: str(r.application_name),
      clientAddr: str(r.client_addr),
      state: str(r.state),
      syncState: str(r.sync_state),
      writeLagSeconds: num(r.write_lag_seconds),
      flushLagSeconds: num(r.flush_lag_seconds),
      replayLagSeconds: num(r.replay_lag_seconds),
      sentLagBytes: num(r.sent_lag_bytes),
      replayLagBytes: num(r.replay_lag_bytes),
      replyAgeSeconds: num(r.reply_age_seconds),
      redacted: false
    }
    // `state` NULL with a row present is the signature of a role that may see
    // the walsender exists and nothing about it.
    replica.redacted =
      replica.state === null &&
      replica.replayLagBytes === null &&
      replica.sentLagBytes === null &&
      replica.replayLagSeconds === null
    return replica
  })
}

export function parsePgStandby(row: Row | undefined): PgReplicationStandby | null {
  if (!row) return null
  const age = num(row.replay_age_seconds)
  return {
    role: 'standby',
    receiveLsn: str(row.receive_lsn),
    replayLsn: str(row.replay_lsn),
    replayAgeSeconds: age,
    replayPaused: bool(row.replay_paused) ?? false,
    applyLagBytes: num(row.apply_lag_bytes),
    neverReplayed: age === null
  }
}

export function parsePgArchiver(row: Row | undefined, archiveMode: string): PgArchiver | null {
  if (!row) return null
  return {
    archiveMode,
    archivedCount: num(row.archived_count),
    lastArchivedWal: str(row.last_archived_wal),
    lastArchivedAgeSeconds: num(row.last_archived_age_seconds),
    failedCount: num(row.failed_count),
    lastFailedWal: str(row.last_failed_wal),
    lastFailedAgeSeconds: num(row.last_failed_age_seconds),
    statsResetAgeSeconds: num(row.stats_reset_age_seconds)
  }
}

export function parsePgVacuum(rows: Row[], freezeMaxAge: number, databaseRows: Row[] = []): PgVacuumValue {
  const max = freezeMaxAge > 0 ? freezeMaxAge : 200_000_000
  return {
    freezeMaxAge: max,
    databases: databaseRows.map((r) => {
      const xidAge = num(r.xid_age)
      return {
        name: str(r.name) ?? '',
        xidAge,
        freezeFraction: xidAge === null ? null : xidAge / max,
        wraparoundFraction: xidAge === null ? null : xidAge / PG_WRAPAROUND_XID_LIMIT
      }
    }),
    tables: rows.map((r) => {
      const xidAge = num(r.xid_age)
      const parentSchema = str(r.parent_schema)
      const parentName = str(r.parent_name)
      return {
        schema: str(r.schema) ?? '',
        name: str(r.name) ?? '',
        relkind: str(r.relkind),
        parent: parentName ? `${parentSchema ? `${parentSchema}.` : ''}${parentName}` : null,
        xidAge,
        deadTuples: num(r.dead_tuples),
        liveTuples: num(r.live_tuples),
        lastAutovacuumAgeSeconds: num(r.last_autovacuum_age_seconds),
        lastVacuumAgeSeconds: num(r.last_vacuum_age_seconds),
        lastAutoanalyzeAgeSeconds: num(r.last_autoanalyze_age_seconds),
        freezeFraction: xidAge === null ? null : xidAge / max
      }
    })
  }
}

export function parsePgConnections(
  rows: Row[],
  maxConnections: number,
  reserved: { superuserReserved?: number; reserved?: number } = {}
): PgConnectionsValue {
  const states = rows.map((r) => ({
    state: str(r.state),
    n: num(r.n) ?? 0,
    oldestSeconds: num(r.oldest_seconds)
  }))
  const superuserReserved = reserved.superuserReserved ?? 0
  const alsoReserved = reserved.reserved ?? 0
  return {
    maxConnections,
    superuserReserved,
    reserved: alsoReserved,
    usableConnections: Math.max(0, maxConnections - superuserReserved - alsoReserved),
    states,
    used: states.reduce((a, s) => a + s.n, 0),
    redactedCount: states.filter((s) => s.state === null).reduce((a, s) => a + s.n, 0)
  }
}

export function parsePgLocks(rows: Row[]): PgLock[] {
  return rows.map((r) => ({
    pid: num(r.pid) ?? 0,
    username: str(r.username),
    state: str(r.state),
    waitingSeconds: num(r.waiting_seconds),
    // A blocked backend is by definition `active`, so a NULL state on a row
    // pg_blocking_pids() put here is the redaction, not a quiet session.
    redacted: str(r.state) === null && num(r.waiting_seconds) === null,
    blockedBy: Array.isArray(r.blocked_by) ? r.blocked_by.map((p) => num(p) ?? 0) : [],
    waitEventType: str(r.wait_event_type),
    waitEvent: str(r.wait_event),
    query: str(r.query)
  }))
}

export function parsePgSizes(databases: Row[], tables: Row[]): PgSizesValue {
  return {
    databases: databases.map((r) => ({ name: str(r.name) ?? '', totalBytes: num(r.bytes) })),
    tables: tables.map((r) => ({
      schema: str(r.schema) ?? undefined,
      name: str(r.name) ?? '',
      totalBytes: num(r.total_bytes),
      heapBytes: num(r.heap_bytes),
      indexBytes: num(r.index_bytes)
    }))
  }
}

export function parsePgStatements(rows: Row[], extensionVersion: string | null): PgStatementsValue {
  const statements = rows.map((r) => ({
    query: str(r.query) ?? '',
    calls: num(r.calls),
    totalExecMs: num(r.total_exec_time),
    meanExecMs: num(r.mean_exec_time),
    rows: num(r.rows)
  }))
  const redactedCount = statements.filter((s) => s.query === PG_REDACTED_QUERY).length
  return {
    extensionVersion,
    redactedText: statements.length > 0 && redactedCount === statements.length,
    redactedCount,
    statements
  }
}

// ---- Judgements -----------------------------------------------------------

const T = DB_THRESHOLDS

/**
 * Replication, primary or standby.
 *
 * The ordering is the design. `redacted` is checked BEFORE any lag comparison,
 * because a redacted row's lag columns are all NULL and every comparison
 * against them is false — so a naive "lag > threshold" chain would fall through
 * to `ok` and tell an operator with no monitoring privileges that replication
 * is healthy. Same shape, same reason, as the MySQL rule below.
 */
export function judgePgReplication(v: PgReplicationValue): DbVerdict {
  if (v.role === 'standby') {
    if (v.replayPaused) {
      return {
        level: 'alarm',
        headline: 'WAL replay is PAUSED on this standby.',
        because: 'It is still receiving WAL and is not applying it, so it falls further behind every second and will not be promotable.'
      }
    }

    // BYTES FIRST, and this ordering is not a preference — it is a correction.
    //
    // The obvious measure of standby lag, `now() - pg_last_xact_replay_timestamp()`,
    // is wrong, and it was caught here by running against a real streaming pair
    // rather than by reading about it: a standby that was byte-for-byte current
    // reported nine and a half minutes of "lag", because that timestamp is the
    // commit time of the last transaction it replayed and the PRIMARY had been
    // idle for nine and a half minutes. On a quiet database that number grows
    // without bound while nothing at all is wrong, and it would page somebody
    // every night.
    //
    // The receive/replay LSN difference has no such failure mode: zero means
    // everything received has been applied, whatever the clock says.
    const bytes = v.applyLagBytes
    const age = v.replayAgeSeconds

    if (bytes === 0) {
      return {
        level: 'ok',
        headline: 'This standby has applied every byte of WAL it has received.',
        because:
          age === null
            ? 'pg_last_xact_replay_timestamp() is NULL because no transaction has been replayed since this standby started. That is not lag — the receive and replay positions are identical.'
            : `Its last replayed transaction committed ${formatSeconds(age)} ago, which measures how idle the PRIMARY is rather than how far behind this standby is. The receive and replay positions are identical.`
      }
    }

    if (bytes === null) {
      if (v.neverReplayed) {
        return {
          level: 'unknown',
          headline: 'This standby has not replayed a transaction yet, and its WAL positions could not be read.',
          because:
            'pg_last_xact_replay_timestamp() is NULL. That happens on a standby built moments ago and on one whose primary is idle — it is NOT a lag of zero.'
        }
      }
      const s = age ?? 0
      return {
        level: s >= T.replicaLagAlarmSeconds ? 'alarm' : s >= T.replicaLagWatchSeconds ? 'watch' : 'unknown',
        headline: `This standby last replayed a transaction ${formatSeconds(s)} ago.`,
        because:
          'The WAL byte positions could not be read, so this is a timestamp and not a lag: on an idle primary it grows while the standby is perfectly current. Treat it as a hint.'
      }
    }

    // There IS unapplied WAL, so the replay timestamp finally means something.
    const s = age ?? 0
    const because = `${formatBytes(bytes)} of received WAL is not yet applied.`
    if (s >= T.replicaLagAlarmSeconds) {
      return { level: 'alarm', headline: `This standby is ${formatSeconds(s)} behind its primary.`, because }
    }
    if (s >= T.replicaLagWatchSeconds) {
      return { level: 'watch', headline: `This standby is ${formatSeconds(s)} behind its primary.`, because }
    }
    return { level: 'ok', headline: `This standby is applying WAL, ${formatBytes(bytes)} behind.`, because }
  }

  if (v.replicas.length === 0) {
    return {
      level: 'unknown',
      headline: 'No standby is connected to this server.',
      because:
        'pg_stat_replication is empty. On a server that was never meant to have a replica that is correct; on one that was, it means the replica is gone. ShellPilot cannot tell which, and will not guess.'
    }
  }

  const redacted = v.replicas.filter((r) => r.redacted)
  if (redacted.length === v.replicas.length) {
    return {
      level: 'unknown',
      headline: `Replication state is hidden from this account (${redacted.length} standby connection${redacted.length === 1 ? '' : 's'} visible, no detail).`,
      because:
        'The rows are there and every column that would answer the question came back NULL. Postgres does this rather than raising an error when the role lacks pg_monitor. Grant pg_monitor to read it — do not read this as healthy.'
    }
  }

  // 'backup' is a walsender serving a running pg_basebackup. It is not a
  // standby that stopped, it is a backup being taken, and alarming on it fires
  // every time somebody clones the server.
  const notStreaming = v.replicas.filter(
    (r) => !r.redacted && r.state !== null && r.state !== 'streaming' && r.state !== 'backup'
  )
  if (notStreaming.length > 0) {
    const worst = notStreaming[0]
    return {
      level: 'alarm',
      headline: `Standby ${worst.applicationName ?? worst.clientAddr ?? 'unknown'} is in state "${worst.state}", not streaming.`,
      because: 'A walsender that is catching up, or stopped, is not keeping a replica current.'
    }
  }

  let worstSeconds = 0
  let worstReplica: PgReplica | null = null
  for (const r of v.replicas) {
    const s = r.replayLagSeconds
    if (s !== null && s >= worstSeconds) {
      worstSeconds = s
      worstReplica = r
    }
  }
  const name = worstReplica?.applicationName ?? worstReplica?.clientAddr ?? 'the standby'
  const because =
    worstReplica?.replayLagBytes === null || worstReplica?.replayLagBytes === undefined
      ? undefined
      : `${formatBytes(worstReplica.replayLagBytes)} of WAL sent but not yet replayed.`
  if (worstSeconds >= T.replicaLagAlarmSeconds) {
    return { level: 'alarm', headline: `Replication is ${formatSeconds(worstSeconds)} behind on ${name}.`, because }
  }
  if (worstSeconds >= T.replicaLagWatchSeconds) {
    return { level: 'watch', headline: `Replication is ${formatSeconds(worstSeconds)} behind on ${name}.`, because }
  }
  const n = v.replicas.length
  // SOME redacted, not all. The all-redacted branch above is the easy case; the
  // mixed one fell through it, and every lag comparison against a redacted
  // row's NULLs is false, so two standbys of which one is hidden rendered as
  // "2 standbys streaming" with a verdict of ok.
  if (redacted.length > 0) {
    return {
      level: 'unknown',
      headline: `${redacted.length} of ${n} standby connections are hidden from this account.`,
      because: `The ${n - redacted.length} readable one${n - redacted.length === 1 ? ' is' : 's are'} streaming with a worst replay lag of ${formatSeconds(worstSeconds)}. The rest returned every lag column NULL, which Postgres does instead of raising an error when the role lacks pg_monitor — so this page cannot say whether they are current.`
    }
  }
  return {
    level: 'ok',
    headline: `${n} standby${n === 1 ? '' : 's'} streaming, worst replay lag ${formatSeconds(worstSeconds)}.`,
    because
  }
}

/**
 * WAL archiving.
 *
 * `failed_count` alone is not the signal — a server that failed once a year ago
 * and has archived cleanly since is fine. The signal is whether the LAST thing
 * that happened was a failure, which is what comparing the two ages does. A
 * failure with no successful archive at all is the worst case and the one the
 * captured fixture shows: 28 failures, `last_archived_wal` NULL.
 */
export function judgePgArchiver(a: PgArchiver): DbVerdict {
  if (a.archiveMode !== 'on' && a.archiveMode !== 'always') {
    return {
      level: 'unknown',
      headline: `WAL archiving is off (archive_mode = ${a.archiveMode}).`,
      because:
        'Nothing is being archived, so this server has no point-in-time recovery. That may be deliberate. It is reported rather than judged because ShellPilot cannot know your recovery plan.'
    }
  }
  const failed = a.failedCount ?? 0
  const failedAge = a.lastFailedAgeSeconds
  const archivedAge = a.lastArchivedAgeSeconds
  const failingNow = failed > 0 && (archivedAge === null || (failedAge !== null && failedAge < archivedAge))
  if (failingNow) {
    return {
      level: 'alarm',
      headline: `WAL archiving is FAILING — ${formatCount(failed)} failure${failed === 1 ? '' : 's'}, the last ${formatSeconds(failedAge)} ago.`,
      because:
        `Postgres retains every WAL segment it could not archive, so pg_wal grows until the disk fills and the server stops. ` +
        (a.lastArchivedWal === null
          ? 'Nothing has ever been archived successfully from this server.'
          : `The last segment that did archive was ${a.lastArchivedWal}, ${formatSeconds(archivedAge)} ago.`)
    }
  }
  if (failed > 0) {
    return {
      level: 'watch',
      headline: `Archiving is working now, but has failed ${formatCount(failed)} time${failed === 1 ? '' : 's'} since the counters were reset.`,
      because: `Last failure ${formatSeconds(failedAge)} ago on ${a.lastFailedWal ?? 'an unnamed segment'}; last success ${formatSeconds(archivedAge)} ago.`
    }
  }
  if ((a.archivedCount ?? 0) === 0) {
    return {
      level: 'unknown',
      headline: 'Archiving is enabled and nothing has been archived yet.',
      because: 'No successes and no failures. On a server that has just started that is expected; on a busy one it means WAL is not being handed to the archiver.'
    }
  }
  return {
    level: 'ok',
    headline: `${formatCount(a.archivedCount)} segments archived, none failed. Last success ${formatSeconds(archivedAge)} ago.`
  }
}

/**
 * Autovacuum and transaction-ID wraparound.
 *
 * Two questions in one because they are read from the same place and the second
 * one is what kills you: when `age(relfrozenxid)` reaches roughly 2^31 Postgres
 * stops accepting writes entirely, and the only way out is a vacuum that takes
 * as long as it takes. It is visible for weeks first.
 */
export function judgePgVacuum(v: PgVacuumValue): DbVerdict {
  // The CLUSTER first, because pg_class is per-database and wraparound is not.
  // A neighbouring database at 1.9 billion stops this one too, and nothing in
  // the table list below can see it.
  const worstDb = (v.databases ?? [])
    .filter((d) => d.xidAge !== null)
    .reduce<PgDatabaseAge | null>((a, b) => ((b.xidAge ?? 0) > (a?.xidAge ?? -1) ? b : a), null)
  if (worstDb && (worstDb.xidAge ?? 0) >= T.freezeAlarmAbsolute) {
    return {
      level: 'alarm',
      headline: `Database ${worstDb.name} is ${Math.round((worstDb.wraparoundFraction ?? 0) * 100)}% of the way to transaction-ID wraparound.`,
      because: `age(datfrozenxid) is ${formatCount(worstDb.xidAge)} of the ${formatCount(PG_WRAPAROUND_XID_LIMIT)} at which Postgres refuses writes. This is cluster-wide: it is not visible in this database's pg_class, and every database in the cluster stops together.`
    }
  }

  const withAge = v.tables.filter((t) => t.xidAge !== null)
  if (withAge.length === 0) {
    return { level: 'unknown', headline: 'No table ages could be read.' }
  }
  const worst = withAge.reduce((a, b) => ((b.xidAge ?? 0) > (a.xidAge ?? 0) ? b : a))
  const age = worst.xidAge ?? 0
  const frac = worst.freezeFraction ?? 0
  // A TOAST relation is named pg_toast.pg_toast_16384, which nobody can act on.
  const where = worst.relkind === 't' && worst.parent ? `${worst.parent} (TOAST)` : `${worst.schema}.${worst.name}`
  // The genuine shutdown alarm, measured against the point Postgres actually
  // stops rather than against the point autovacuum starts.
  if (age >= T.freezeAlarmAbsolute) {
    return {
      level: 'alarm',
      headline: `${where} is ${Math.round((age / PG_WRAPAROUND_XID_LIMIT) * 100)}% of the way to transaction-ID wraparound.`,
      because: `age(relfrozenxid) is ${formatCount(age)} of the ${formatCount(PG_WRAPAROUND_XID_LIMIT)} at which Postgres refuses writes. Get a vacuum onto this table in a window you choose rather than one it chooses.`
    }
  }
  if (frac >= T.freezeAlarmFraction) {
    // NOT wraparound. autovacuum_freeze_max_age is where autovacuum STARTS, and
    // saying "90% of the way to wraparound" here overstated it by more than ten
    // times — 180M of 200M is 8.5% of the way to the number that matters.
    return {
      level: 'alarm',
      headline: `${where} is ${Math.round(frac * 100)}% of the way to a forced anti-wraparound vacuum.`,
      because: `age(relfrozenxid) is ${formatCount(age)} against an autovacuum_freeze_max_age of ${formatCount(v.freezeMaxAge)} — ${Math.round((age / PG_WRAPAROUND_XID_LIMIT) * 100)}% of the age at which Postgres refuses writes. At 100% autovacuum forces a freeze whether or not it suits you, and on a large table that is hours of IO.`
    }
  }
  if (frac >= T.freezeWatchFraction) {
    return {
      level: 'watch',
      headline: `${where} is ${Math.round(frac * 100)}% of the way to an anti-wraparound vacuum.`,
      because: `age(relfrozenxid) is ${formatCount(age)} of ${formatCount(v.freezeMaxAge)}. Autovacuum will force a freeze at 100%, and on a large table that is hours of IO.`
    }
  }
  const bloated = v.tables.filter(
    (t) => (t.deadTuples ?? 0) > 100_000 && (t.deadTuples ?? 0) > (t.liveTuples ?? 0) * 0.2
  )
  if (bloated.length > 0) {
    const b = bloated[0]
    return {
      level: 'watch',
      headline: `${b.schema}.${b.name} is carrying ${formatCount(b.deadTuples)} dead rows against ${formatCount(b.liveTuples)} live ones.`,
      because:
        b.lastAutovacuumAgeSeconds === null
          ? 'Autovacuum has never run on this table.'
          : `Last autovacuum ${formatSeconds(b.lastAutovacuumAgeSeconds)} ago, and it is not keeping up.`
    }
  }
  return {
    level: 'ok',
    headline: `Oldest table age is ${Math.round(frac * 100)}% of autovacuum_freeze_max_age (${where}).`,
    because: `${formatCount(age)} of ${formatCount(v.freezeMaxAge)}.`
  }
}

export function judgePgConnections(v: PgConnectionsValue): DbVerdict {
  const idleTx = v.states.find((s) => s.state === 'idle in transaction')
  const idleAborted = v.states.find((s) => s.state === 'idle in transaction (aborted)')
  // The ceiling an ordinary client can reach is max_connections minus what is
  // held back for superusers (and, on PostgreSQL 16+, the second reserve). The
  // old text asserted Postgres "reserves a handful for superusers and nothing
  // else" while dividing by the number that includes them.
  const ceiling = v.usableConnections > 0 ? v.usableConnections : v.maxConnections
  const frac = ceiling > 0 ? v.used / ceiling : 0
  const held = v.superuserReserved + v.reserved
  const shape = `${v.used} of ${v.maxConnections} connections in use`
  const reservedNote = held > 0
    ? ` ${held} of those are reserved (superuser_reserved_connections ${v.superuserReserved}, reserved_connections ${v.reserved}), so the ceiling an ordinary client reaches is ${ceiling}.`
    : ''

  if (ceiling > 0 && frac >= T.connectionsAlarmFraction) {
    return {
      level: 'alarm',
      headline: `${shape} (${Math.round(frac * 100)}%).`,
      because:
        'When max_connections is reached every new client is refused, including the psql session you would use to fix it.' + reservedNote
    }
  }
  const oldestIdleTx = Math.max(idleTx?.oldestSeconds ?? 0, idleAborted?.oldestSeconds ?? 0)
  if (oldestIdleTx >= T.idleInTransactionAlarmSeconds) {
    return {
      level: 'alarm',
      headline: `A session has been idle in transaction for ${formatSeconds(oldestIdleTx)}.`,
      because: 'It holds its locks and pins the oldest snapshot, so vacuum cannot remove any row deleted since it began. This is how a table bloats without anyone writing to it.'
    }
  }
  if (ceiling > 0 && frac >= T.connectionsWatchFraction) {
    return { level: 'watch', headline: `${shape} (${Math.round(frac * 100)}%).` }
  }
  if (oldestIdleTx >= T.idleInTransactionWatchSeconds) {
    return {
      level: 'watch',
      headline: `A session has been idle in transaction for ${formatSeconds(oldestIdleTx)}.`,
      because: 'Idle-in-transaction sessions hold back vacuum for the whole database.'
    }
  }
  // Below every threshold — but if part of the picture came back NULL, this is
  // not a clean bill of health, it is a bill this account could not read. The
  // idle-in-transaction rules above are silently unreachable in this state.
  if (v.redactedCount > 0) {
    return {
      level: 'unknown',
      headline: `${shape} (${Math.round(frac * 100)}%), and ${v.redactedCount} of them cannot be read by this account.`,
      because:
        'Their state, query and query_start all came back NULL. Postgres does that rather than raising an error when the role lacks pg_read_all_stats, so an idle-in-transaction session holding back vacuum for the whole database would be invisible here. Grant pg_monitor (or pg_read_all_stats) to answer this.'
    }
  }
  return { level: 'ok', headline: `${shape} (${Math.round(frac * 100)}%).` }
}

export function judgePgLocks(locks: PgLock[]): DbVerdict {
  if (locks.length === 0) return { level: 'ok', headline: 'Nothing is waiting on a lock.' }
  // `?? 0` here was the bug: a role without pg_read_all_stats gets NULL for
  // query_start on a backend it does not own, so a session blocked for two
  // hours rendered as "briefly blocked (0s)" — a watch instead of an alarm.
  // A wait nobody could time is not a wait of zero.
  const timed = locks.filter((l) => l.waitingSeconds !== null)
  const hidden = locks.length - timed.length
  const worst = timed.length > 0 ? timed.reduce((a, b) => ((b.waitingSeconds ?? 0) > (a.waitingSeconds ?? 0) ? b : a)) : null
  const s = worst?.waitingSeconds ?? null
  const blockers = [...new Set(locks.flatMap((l) => l.blockedBy))]
  const target = worst ?? locks[0]
  const because = `pid ${target.pid} is waiting on ${target.blockedBy.join(', ') || 'another session'}${
    blockers.length > 1 ? `; ${blockers.length} sessions are blocking in total` : ''
  }.`
  if (s !== null && s >= T.lockWaitAlarmSeconds) {
    return { level: 'alarm', headline: `${locks.length} session${locks.length === 1 ? ' has' : 's have'} been blocked for up to ${formatSeconds(s)}.`, because }
  }
  if (hidden > 0) {
    return {
      level: 'unknown',
      headline: `${locks.length} session${locks.length === 1 ? ' is' : 's are'} blocked, and this account cannot see for how long.`,
      because: `query_start came back NULL for ${hidden} of them, which is what Postgres returns instead of an error when the role lacks pg_read_all_stats. The wait could be two seconds or two hours. ${because}`
    }
  }
  if (s !== null && s >= T.lockWaitWatchSeconds) {
    return { level: 'watch', headline: `${locks.length} session${locks.length === 1 ? ' is' : 's are'} blocked, the longest for ${formatSeconds(s)}.`, because }
  }
  return { level: 'watch', headline: `${locks.length} session${locks.length === 1 ? ' is' : 's are'} briefly blocked (${formatSeconds(s ?? 0)}).`, because }
}

export function judgePgSizes(v: PgSizesValue): DbVerdict {
  const total = v.databases.reduce((a, d) => a + (d.totalBytes ?? 0), 0)
  const biggest = v.tables[0]
  return {
    level: 'ok',
    headline: `${formatBytes(total)} across ${v.databases.length} database${v.databases.length === 1 ? '' : 's'}.`,
    because: biggest ? `Largest table: ${biggest.schema ? `${biggest.schema}.` : ''}${biggest.name} at ${formatBytes(biggest.totalBytes)}.` : undefined
  }
}

export function judgePgStatements(v: PgStatementsValue): DbVerdict {
  if (v.redactedText) {
    return {
      level: 'unknown',
      headline: 'pg_stat_statements is installed and this account may not read the statement text.',
      because: `Every query came back as "${PG_REDACTED_QUERY}". The timings beside them are real; the statements they belong to are not shown. pg_read_all_stats or pg_monitor would show them.`
    }
  }
  if (v.statements.length === 0) {
    return { level: 'unknown', headline: 'pg_stat_statements is installed and has recorded nothing yet.' }
  }
  const top = v.statements[0]
  const headline = `${v.statements.length} statements by total time; the top one has cost ${formatSeconds((top.totalExecMs ?? 0) / 1000)} over ${formatCount(top.calls)} calls.`
  if (v.redactedCount > 0) {
    return {
      level: 'unknown',
      headline: `${headline} ${v.redactedCount} of ${v.statements.length} statement texts are hidden from this account.`,
      because: `Postgres shows a role its own statements and replaces the rest with "${PG_REDACTED_QUERY}". The timings are real; the statements they belong to are not all shown. pg_read_all_stats or pg_monitor would show them.`
    }
  }
  return { level: 'ok', headline }
}

// ===========================================================================
// MySQL / MariaDB
// ===========================================================================

export interface MysqlOverview {
  version: string
  versionComment: string
  /** MariaDB and MySQL diverge on statement names, system variables and error
   *  codes; this is read from the version string, not guessed. */
  flavour: 'mysql' | 'mariadb'
  serverId: number | null
  readOnly: boolean | null
  maxConnections: number
  hostname: string | null
  uptimeSeconds: number | null
}

/** Which spelling of the replication vocabulary a row used. */
export type MysqlReplicaVocabulary = 'replica' | 'slave'

export interface MysqlReplicationChannel {
  channel: string
  vocabulary: MysqlReplicaVocabulary
  sourceHost: string | null
  ioState: string | null
  ioRunning: string | null
  sqlRunning: string | null
  /**
   * `Seconds_Behind_Source` / `Seconds_Behind_Master`, VERBATIM.
   *
   * NULL means the server declined to state a lag, which happens whenever the
   * IO thread is not connected — i.e. whenever replication is broken. It does
   * NOT mean zero, and nothing in this file may coerce it. The type is
   * `number | null` for exactly that reason and `num()` preserves the null.
   */
  secondsBehind: number | null
  lastIoErrno: number | null
  lastIoError: string | null
  lastSqlErrno: number | null
  lastSqlError: string | null
  /** A deliberately delayed replica (CHANGE REPLICATION SOURCE ... SOURCE_DELAY).
   *  Its lag is intentional and must not be alarmed on. */
  sqlDelaySeconds: number | null
  autoPosition: boolean | null
  sourceLogFile: string | null
  relayLogSpaceBytes: number | null
}

export interface MysqlBinlogFile {
  name: string
  bytes: number | null
  encrypted: string | null
}

export interface MysqlBinlogsValue {
  logBin: boolean
  /** MySQL 8 spells it binlog_expire_logs_seconds; MariaDB and MySQL 5.7 spell
   *  it expire_logs_days. Whichever answered. */
  expireSeconds: number | null
  expireSource: 'binlog_expire_logs_seconds' | 'expire_logs_days' | null
  files: MysqlBinlogFile[]
  totalBytes: number
}

export interface MysqlSlowLogValue {
  enabled: boolean
  longQueryTimeSeconds: number | null
  file: string | null
  output: string | null
  slowQueries: number | null
  uptimeSeconds: number | null
}

export interface MysqlConnectionsValue {
  maxConnections: number
  threadsConnected: number | null
  threadsRunning: number | null
  maxUsedConnections: number | null
  abortedConnects: number | null
  /** Non-zero means clients have ALREADY been refused for hitting
   *  max_connections. Not a risk — an outage that happened. */
  connectionErrorsMaxConnections: number | null
}

export interface MysqlProcess {
  id: number | null
  user: string | null
  host: string | null
  db: string | null
  command: string | null
  seconds: number | null
  state: string | null
  info: string | null
}

export interface MysqlProcesslistValue {
  processes: MysqlProcess[]
  /** How many rows information_schema.PROCESSLIST returned in total. */
  visible: number | null
  /** What SHOW GLOBAL STATUS says is actually connected. */
  threadsConnected: number | null
}

export interface MysqlBufferPoolValue {
  sizeBytes: number | null
  instances: number | null
  readRequests: number | null
  reads: number | null
  pagesTotal: number | null
  pagesFree: number | null
  pagesDirty: number | null
  uptimeSeconds: number | null
  /** 1 - reads/read_requests, or null when there is nothing to divide. */
  hitRate: number | null
}

export interface MysqlTableSize {
  schema: string
  name: string
  engine: string | null
  rows: number | null
  dataBytes: number | null
  indexBytes: number | null
  freeBytes: number | null
}

export interface MysqlSizesValue {
  tables: MysqlTableSize[]
  totalBytes: number
}

// ---- Queries --------------------------------------------------------------

export const MYSQL_QUERIES = Object.freeze({
  overview: `SELECT VERSION() AS version, @@version_comment AS version_comment, @@server_id AS server_id,
       @@read_only AS read_only, @@max_connections AS max_connections, @@hostname AS hostname`,

  // MySQL 8.0.22 renamed SHOW SLAVE STATUS to SHOW REPLICA STATUS. MariaDB kept
  // the old spelling and did not add the new one until 10.5. So BOTH are tried
  // and neither failing is an error on its own — only both failing is.
  //
  // The subtlety the fixtures caught: MySQL 8.0.46 accepts BOTH statements and
  // answers them with DIFFERENT column names (Replica_IO_Running vs
  // Slave_IO_Running, Seconds_Behind_Source vs Seconds_Behind_Master). The
  // parser therefore reads either vocabulary from whichever row it got, rather
  // than assuming the columns follow the statement it happened to send.
  replicaStatus: 'SHOW REPLICA STATUS',
  // MariaDB's multi-source spelling. `SHOW SLAVE STATUS` there returns ONLY the
  // unnamed default connection, so a MariaDB server replicating from two
  // sources answers it with the one row and says nothing about the other.
  allSlavesStatus: 'SHOW ALL SLAVES STATUS',
  slaveStatus: 'SHOW SLAVE STATUS',

  logBin: 'SELECT @@log_bin AS log_bin',
  binlogExpireSeconds: 'SELECT @@binlog_expire_logs_seconds AS expire_seconds',
  binlogExpireDays: 'SELECT @@expire_logs_days AS expire_days',
  binaryLogs: 'SHOW BINARY LOGS',

  slowSettings: `SELECT @@slow_query_log AS slow_query_log, @@long_query_time AS long_query_time,
       @@slow_query_log_file AS slow_query_log_file, @@log_output AS log_output`,

  // One round trip for every counter any question below needs. SHOW GLOBAL
  // STATUS unfiltered is ~500 rows on MySQL 8 and most of them are noise.
  status: `SHOW GLOBAL STATUS WHERE Variable_name IN
    ('Uptime','Threads_connected','Threads_running','Max_used_connections','Aborted_connects',
     'Connection_errors_max_connections','Slow_queries','Queries',
     'Innodb_buffer_pool_read_requests','Innodb_buffer_pool_reads','Innodb_buffer_pool_pages_total',
     'Innodb_buffer_pool_pages_free','Innodb_buffer_pool_pages_dirty','Innodb_row_lock_waits',
     'Innodb_row_lock_time_avg','Innodb_buffer_pool_wait_free')`,

  bufferPool: `SELECT @@innodb_buffer_pool_size AS bytes, @@innodb_buffer_pool_instances AS instances`,

  processlist: `SELECT ID AS id, USER AS user, HOST AS host, DB AS db, COMMAND AS command,
       TIME AS seconds, STATE AS state, LEFT(INFO, 200) AS info
  FROM information_schema.PROCESSLIST WHERE COMMAND <> 'Sleep' ORDER BY TIME DESC LIMIT ?`,

  // Counted separately from the listing above so "how many can this account
  // see" can be compared with Threads_connected. Without the PROCESS privilege
  // MySQL silently shows only the caller's own connections — no error, a
  // smaller number, and a page that would otherwise say "1 query running" on a
  // server with two hundred.
  processlistCount: 'SELECT COUNT(*) AS n FROM information_schema.PROCESSLIST',

  sizes: `SELECT TABLE_SCHEMA AS \`schema\`, TABLE_NAME AS name, ENGINE AS engine,
       TABLE_ROWS AS table_rows, DATA_LENGTH AS data_bytes, INDEX_LENGTH AS index_bytes,
       DATA_FREE AS free_bytes
  FROM information_schema.TABLES
  WHERE TABLE_SCHEMA NOT IN ('mysql','information_schema','performance_schema','sys')
    AND TABLE_TYPE = 'BASE TABLE'
  ORDER BY (COALESCE(DATA_LENGTH,0) + COALESCE(INDEX_LENGTH,0)) DESC LIMIT ?`
})

/**
 * Read a replication field under either vocabulary.
 *
 * `SHOW SLAVE STATUS` on MySQL 8 returns Slave_IO_Running and
 * Seconds_Behind_Master; `SHOW REPLICA STATUS` on the SAME SERVER returns
 * Replica_IO_Running and Seconds_Behind_Source. Reading by the statement we
 * sent would work until someone reordered the fallback.
 *
 * `in` rather than `!== undefined`: the whole point is to tell a column that is
 * present and NULL from a column that is not present at all.
 */
export function replicaField(row: Row, modern: string, legacy: string): unknown {
  if (modern in row) return row[modern]
  if (legacy in row) return row[legacy]
  return undefined
}

/** Whether a row uses the post-8.0.22 spelling. Recorded so the UI can say
 *  which dialect answered rather than implying one. */
export function replicaVocabulary(row: Row): MysqlReplicaVocabulary {
  return 'Replica_IO_Running' in row || 'Seconds_Behind_Source' in row ? 'replica' : 'slave'
}

export function parseMysqlOverview(row: Row | undefined, uptimeSeconds: number | null): MysqlOverview | null {
  if (!row) return null
  const version = str(row.version) ?? 'unknown'
  const comment = str(row.version_comment) ?? ''
  return {
    version,
    versionComment: comment,
    flavour: /mariadb/i.test(version) || /mariadb/i.test(comment) ? 'mariadb' : 'mysql',
    serverId: num(row.server_id),
    readOnly: bool(row.read_only),
    maxConnections: num(row.max_connections) ?? 0,
    hostname: str(row.hostname),
    uptimeSeconds
  }
}

export function parseMysqlReplication(rows: Row[]): MysqlReplicationChannel[] {
  return rows.map((r) => ({
    // MySQL calls it Channel_Name; MariaDB calls it Connection_name. Reading
    // only the first collapsed every MariaDB multi-source connection into
    // "default", so a server replicating from two places looked like one.
    channel: str(replicaField(r, 'Channel_Name', 'Connection_name')) || 'default',
    vocabulary: replicaVocabulary(r),
    sourceHost: str(replicaField(r, 'Source_Host', 'Master_Host')),
    ioState: str(replicaField(r, 'Replica_IO_State', 'Slave_IO_State')),
    ioRunning: str(replicaField(r, 'Replica_IO_Running', 'Slave_IO_Running')),
    sqlRunning: str(replicaField(r, 'Replica_SQL_Running', 'Slave_SQL_Running')),
    // num() and not Number(): this is the value the whole item is about.
    secondsBehind: num(replicaField(r, 'Seconds_Behind_Source', 'Seconds_Behind_Master')),
    lastIoErrno: num(r.Last_IO_Errno),
    lastIoError: str(r.Last_IO_Error),
    lastSqlErrno: num(r.Last_SQL_Errno),
    lastSqlError: str(r.Last_SQL_Error),
    sqlDelaySeconds: num(r.SQL_Delay),
    autoPosition: bool(r.Auto_Position),
    sourceLogFile: str(replicaField(r, 'Source_Log_File', 'Master_Log_File')),
    relayLogSpaceBytes: num(r.Relay_Log_Space)
  }))
}

export function parseMysqlBinlogs(
  rows: Row[],
  logBin: boolean,
  expire: { seconds: number | null; days: number | null }
): MysqlBinlogsValue {
  const files = rows.map((r) => ({
    name: str(r.Log_name) ?? '',
    bytes: num(r.File_size),
    encrypted: str(r.Encrypted)
  }))
  const seconds = expire.seconds
  const days = expire.days
  return {
    logBin,
    expireSeconds: seconds !== null ? seconds : days !== null ? days * 86_400 : null,
    expireSource: seconds !== null ? 'binlog_expire_logs_seconds' : days !== null ? 'expire_logs_days' : null,
    files,
    totalBytes: files.reduce((a, f) => a + (f.bytes ?? 0), 0)
  }
}

/** SHOW GLOBAL STATUS rows to a map. Both drivers return
 *  `{ Variable_name, Value }`; the values are always strings. */
export function statusMap(rows: Row[]): Record<string, string> {
  const out: Record<string, string> = {}
  for (const r of rows) {
    const k = str(r.Variable_name) ?? str(r.VARIABLE_NAME)
    if (k) out[k] = str(r.Value) ?? str(r.VALUE) ?? ''
  }
  return out
}

export function parseMysqlSlowLog(settings: Row | undefined, status: Record<string, string>): MysqlSlowLogValue {
  return {
    enabled: bool(settings?.slow_query_log) ?? false,
    longQueryTimeSeconds: num(settings?.long_query_time),
    file: str(settings?.slow_query_log_file),
    output: str(settings?.log_output),
    slowQueries: num(status.Slow_queries),
    uptimeSeconds: num(status.Uptime)
  }
}

export function parseMysqlConnections(status: Record<string, string>, maxConnections: number): MysqlConnectionsValue {
  return {
    maxConnections,
    threadsConnected: num(status.Threads_connected),
    threadsRunning: num(status.Threads_running),
    maxUsedConnections: num(status.Max_used_connections),
    abortedConnects: num(status.Aborted_connects),
    connectionErrorsMaxConnections: num(status.Connection_errors_max_connections)
  }
}

export function parseMysqlProcesslist(
  rows: Row[],
  visible: number | null,
  threadsConnected: number | null
): MysqlProcesslistValue {
  return {
    processes: rows.map((r) => ({
      id: num(r.id),
      user: str(r.user),
      host: str(r.host),
      db: str(r.db),
      command: str(r.command),
      seconds: num(r.seconds),
      state: str(r.state),
      info: str(r.info)
    })),
    visible,
    threadsConnected
  }
}

export function parseMysqlBufferPool(status: Record<string, string>, settings: Row | undefined): MysqlBufferPoolValue {
  const requests = num(status.Innodb_buffer_pool_read_requests)
  const reads = num(status.Innodb_buffer_pool_reads)
  return {
    sizeBytes: num(settings?.bytes),
    instances: num(settings?.instances),
    readRequests: requests,
    reads,
    pagesTotal: num(status.Innodb_buffer_pool_pages_total),
    pagesFree: num(status.Innodb_buffer_pool_pages_free),
    pagesDirty: num(status.Innodb_buffer_pool_pages_dirty),
    uptimeSeconds: num(status.Uptime),
    hitRate: requests !== null && reads !== null && requests > 0 ? 1 - reads / requests : null
  }
}

export function parseMysqlSizes(rows: Row[]): MysqlSizesValue {
  const tables = rows.map((r) => ({
    schema: str(r.schema) ?? '',
    name: str(r.name) ?? '',
    engine: str(r.engine),
    rows: num(r.table_rows),
    dataBytes: num(r.data_bytes),
    indexBytes: num(r.index_bytes),
    freeBytes: num(r.free_bytes)
  }))
  return { tables, totalBytes: tables.reduce((a, t) => a + (t.dataBytes ?? 0) + (t.indexBytes ?? 0), 0) }
}

// ---- Judgements -----------------------------------------------------------

/**
 * The most important function in this feature.
 *
 * Four rules, and the ORDER of the first three is the whole thing. Each was
 * derived from output captured off a real MySQL 8.0.46 replica
 * (tests/fixtures/dbops/mysql/), not from the documentation.
 *
 *  1. No channels at all — the server is not a replica. `SHOW REPLICA STATUS`
 *     on a source returns an EMPTY RESULT SET, not an error, so this case has
 *     to be recognised here or it becomes "healthy, zero lag".
 *
 *  2. Either thread not running is an ALARM, regardless of Seconds_Behind.
 *     This rule comes before the seconds check because of a capture that is
 *     worse than the famous NULL: a replica pointed at a host that does not
 *     resolve reported `Replica_IO_Running: No`, `Last_IO_Errno: 2005` — and
 *     `Seconds_Behind_Source: 0`. A genuinely dead replica reporting ZERO
 *     seconds behind. Checking only for NULL would call that healthy.
 *
 *  3. Seconds_Behind NULL is an ALARM, never zero and never "healthy".
 *     `STOP REPLICA IO_THREAD` produces `Seconds_Behind_Source: NULL` with
 *     `Last_IO_Errno: 0` and an EMPTY `Last_IO_Error` — replication stopped
 *     with no error text at all. The NULL is the only signal there is.
 *
 *  4. Only once both threads run and the value is a real number does the
 *     number get compared with a threshold, minus any deliberate SQL_Delay.
 */
export function judgeMysqlReplication(channels: MysqlReplicationChannel[]): DbVerdict {
  if (channels.length === 0) {
    return {
      level: 'unknown',
      headline: 'This server is not replicating from anything.',
      because:
        'SHOW REPLICA STATUS returned no rows, which is what a source (or a standalone server) returns. If this server is supposed to be a replica, that is the finding.'
    }
  }

  // Worst channel wins. A server with four channels where one is dead is a
  // server with a dead channel.
  const verdicts = channels.map(judgeMysqlChannel)
  return verdicts.reduce((a, b) => (DB_VERDICT_RANK[b.level] > DB_VERDICT_RANK[a.level] ? b : a))
}

function channelName(c: MysqlReplicationChannel): string {
  const from = c.sourceHost ? ` from ${c.sourceHost}` : ''
  return c.channel && c.channel !== 'default' ? `Channel "${c.channel}"${from}` : `Replication${from}`
}

export function judgeMysqlChannel(c: MysqlReplicationChannel): DbVerdict {
  const name = channelName(c)
  const ioOk = c.ioRunning === 'Yes'
  const sqlOk = c.sqlRunning === 'Yes'

  if (!ioOk || !sqlOk) {
    const stopped = [!ioOk ? 'IO' : null, !sqlOk ? 'SQL' : null].filter(Boolean).join(' and ')
    // Last_IO_Error reads `error connecting to master 'replicator@db:3306'`.
    // That sentence is shown here AND written into the durable event store.
    const err = redactDbIdentifiers((c.lastIoError || '').trim() || (c.lastSqlError || '').trim())
    return {
      level: 'alarm',
      headline: `${name} is BROKEN — the ${stopped} thread${stopped.includes('and') ? 's are' : ' is'} not running.`,
      because: err
        ? err
        : `The server reported no error (Last_IO_Errno ${c.lastIoErrno ?? 0}, Last_SQL_Errno ${c.lastSqlErrno ?? 0}) — a thread that was stopped deliberately looks exactly like this. Nothing is being replicated either way.` +
          (c.secondsBehind === 0
            ? ' Note that it is still reporting 0 seconds behind, which is not a measurement.'
            : '')
    }
  }

  if (c.secondsBehind === null) {
    return {
      level: 'alarm',
      headline: `${name} is BROKEN — the server would not say how far behind it is.`,
      because:
        'Seconds_Behind_Source is NULL. MySQL returns NULL, not a number, whenever it cannot compute the lag — which in practice means replication is not running. It is NOT zero, and it is not "up to date".'
    }
  }

  // A deliberately delayed replica is meant to be behind by exactly this much.
  const delay = c.sqlDelaySeconds ?? 0
  const effective = Math.max(0, c.secondsBehind - delay)
  const delayNote = delay > 0 ? ` (${formatSeconds(delay)} of that is the configured SQL_Delay)` : ''

  if (effective >= T.replicaLagAlarmSeconds) {
    return {
      level: 'alarm',
      headline: `${name} is ${formatSeconds(c.secondsBehind)} behind${delayNote}.`,
      because: 'Reads from this replica are returning rows from that far in the past, and a failover to it would lose everything since.'
    }
  }
  if (effective >= T.replicaLagWatchSeconds) {
    return { level: 'watch', headline: `${name} is ${formatSeconds(c.secondsBehind)} behind${delayNote}.` }
  }
  return {
    level: 'ok',
    headline: `${name} is running, ${formatSeconds(c.secondsBehind)} behind${delayNote}.`,
    because: c.ioState ? `IO thread: ${c.ioState}` : undefined
  }
}

export function judgeMysqlBinlogs(v: MysqlBinlogsValue): DbVerdict {
  if (!v.logBin) {
    return {
      level: 'unknown',
      headline: 'Binary logging is OFF.',
      because:
        'This server cannot be a replication source and has no point-in-time recovery — a restore can only go back to the last full backup. On a standalone server that may be deliberate.'
    }
  }
  if (v.expireSeconds === 0) {
    return {
      level: 'watch',
      headline: `Binary logs never expire, and there are ${v.files.length} of them using ${formatBytes(v.totalBytes)}.`,
      because: `${v.expireSource} is 0, so nothing removes them and the volume grows until the disk fills. Set an expiry, or purge them from a job with the retention you actually want.`
    }
  }
  const expiryNote =
    v.expireSeconds === null
      ? 'No expiry setting could be read.'
      : `Kept for ${formatSeconds(v.expireSeconds)} (${v.expireSource}).`
  if (v.files.length === 0) {
    return { level: 'unknown', headline: 'Binary logging is on and no log files are listed.', because: expiryNote }
  }
  return {
    level: 'ok',
    headline: `${v.files.length} binary log${v.files.length === 1 ? '' : 's'} using ${formatBytes(v.totalBytes)}.`,
    because: expiryNote
  }
}

export function judgeMysqlSlowLog(v: MysqlSlowLogValue): DbVerdict {
  if (!v.enabled) {
    return {
      level: 'unknown',
      headline: 'The slow query log is OFF.',
      because:
        'Nothing is being recorded, so "no slow queries" here means "no evidence", not "none happened". This is the first question about slow queries and it has to be answered before the second one means anything.'
    }
  }
  if ((v.output ?? '').toUpperCase().includes('NONE')) {
    return {
      level: 'unknown',
      headline: 'The slow query log is enabled and log_output is NONE, so nothing is written anywhere.',
      because: `slow_query_log is ON but log_output is "${v.output}".`
    }
  }
  const t = v.longQueryTimeSeconds
  // SHOW GLOBAL STATUS feeds both of these. When it failed — a denied account,
  // a dropped connection — they are null, and the sentence built from them read
  // "unknown slow queries recorded in unknown of uptime" under a green tick.
  const uncounted = v.slowQueries === null || v.uptimeSeconds === null
  const counted = uncounted
    ? 'SHOW GLOBAL STATUS could not be read, so how much this log has actually recorded is unknown.'
    : `${formatCount(v.slowQueries)} slow quer${v.slowQueries === 1 ? 'y' : 'ies'} recorded in ${formatSeconds(v.uptimeSeconds)} of uptime.`
  if (t !== null && t >= T.slowLogUselessThresholdSeconds) {
    return {
      level: 'watch',
      headline: `The slow query log is on, but long_query_time is ${t}s.`,
      because: `Almost nothing takes that long, so the log will stay near-empty and prove nothing. ${counted}`
    }
  }
  return {
    level: uncounted ? 'unknown' : 'ok',
    headline: `Slow query log on at ${t ?? '?'}s, writing to ${v.output ?? 'FILE'}.`,
    because: `${counted}${v.file ? ` File: ${v.file}` : ''}`
  }
}

export function judgeMysqlConnections(v: MysqlConnectionsValue): DbVerdict {
  const refused = v.connectionErrorsMaxConnections ?? 0
  const used = v.threadsConnected ?? 0
  const frac = v.maxConnections > 0 ? used / v.maxConnections : 0
  const shape = `${used} of ${v.maxConnections} connections in use (${Math.round(frac * 100)}%)`

  if (refused > 0) {
    return {
      level: 'alarm',
      headline: `${formatCount(refused)} connection${refused === 1 ? ' has' : 's have'} already been REFUSED for hitting max_connections.`,
      because: `This is not a risk, it is an outage that has happened: Connection_errors_max_connections is ${formatCount(refused)}. ${shape}; the high-water mark is ${formatCount(v.maxUsedConnections)}.`
    }
  }
  if (v.maxConnections > 0 && frac >= T.connectionsAlarmFraction) {
    return { level: 'alarm', headline: `${shape}.`, because: `High-water mark ${formatCount(v.maxUsedConnections)}.` }
  }
  if (v.maxConnections > 0 && frac >= T.connectionsWatchFraction) {
    return { level: 'watch', headline: `${shape}.`, because: `High-water mark ${formatCount(v.maxUsedConnections)}.` }
  }
  const highWater = v.maxUsedConnections ?? 0
  if (v.maxConnections > 0 && highWater / v.maxConnections >= T.connectionsAlarmFraction) {
    return {
      level: 'watch',
      headline: `${shape}, but ${formatCount(highWater)} were in use at the peak.`,
      because: 'Max_used_connections is a high-water mark since the last restart. It came close once and will again.'
    }
  }
  return { level: 'ok', headline: `${shape}.`, because: `High-water mark ${formatCount(v.maxUsedConnections)}.` }
}

/**
 * Running queries.
 *
 * The partial-visibility check is the point. Without the PROCESS privilege
 * MySQL shows an account ONLY its own connections and says nothing about it, so
 * the count is compared with Threads_connected — which every account can read —
 * and the gap is reported rather than swallowed. Captured: an application user
 * saw 1 row where root saw 3 on the same server at the same moment.
 */
/**
 * The server's own threads, which are not queries anyone is waiting on.
 *
 * Found by running this against a real replica: its applier thread shows up as
 * `system user` in state "Waiting for an event from Coordinator" with a TIME
 * equal to the replica's uptime, so a naive "longest running query" alarmed at
 * eleven minutes on a completely healthy server. The binlog dump thread on a
 * source has the same shape, and so does the event scheduler.
 */
export const MYSQL_INTERNAL_COMMANDS = ['Daemon', 'Binlog Dump', 'Binlog Dump GTID', 'Connect'] as const

export function isClientQuery(p: MysqlProcess): boolean {
  if (p.user === 'system user' || p.user === 'event_scheduler') return false
  return !MYSQL_INTERNAL_COMMANDS.includes((p.command ?? '') as (typeof MYSQL_INTERNAL_COMMANDS)[number])
}

export function judgeMysqlProcesslist(v: MysqlProcesslistValue): DbVerdict {
  const hidden =
    v.visible !== null && v.threadsConnected !== null && v.visible < v.threadsConnected
      ? v.threadsConnected - v.visible
      : 0
  const partialNote = hidden > 0
    ? `This account can see ${v.visible} of ${v.threadsConnected} connections — ${hidden} ${hidden === 1 ? 'is' : 'are'} hidden because it lacks the PROCESS privilege. MySQL does not warn about this.`
    : undefined

  const running = v.processes.filter(isClientQuery)
  const longest = running.reduce<MysqlProcess | null>((a, b) => ((b.seconds ?? 0) > (a?.seconds ?? -1) ? b : a), null)
  const s = longest?.seconds ?? 0

  if (s >= T.longQueryAlarmSeconds) {
    return {
      level: 'alarm',
      headline: `A query has been running for ${formatSeconds(s)}.`,
      because: [`${longest?.user ?? 'unknown'} on ${longest?.db ?? 'no database'}, state "${longest?.state ?? '?'}".`, partialNote]
        .filter(Boolean)
        .join(' ')
    }
  }
  if (s >= T.longQueryWatchSeconds) {
    return {
      level: 'watch',
      headline: `A query has been running for ${formatSeconds(s)}.`,
      because: [`${longest?.user ?? 'unknown'} on ${longest?.db ?? 'no database'}.`, partialNote].filter(Boolean).join(' ')
    }
  }
  if (hidden > 0) {
    return {
      level: 'unknown',
      headline: `${running.length} quer${running.length === 1 ? 'y' : 'ies'} running, but this account cannot see the whole processlist.`,
      because: partialNote
    }
  }
  return { level: 'ok', headline: `${running.length} quer${running.length === 1 ? 'y' : 'ies'} running, longest ${formatSeconds(s)}.` }
}

/**
 * InnoDB buffer pool.
 *
 * The uptime guard exists because the first version of this alarmed on a
 * perfectly healthy server. A MySQL container five minutes old reported 17,345
 * read requests against 1,050 disk reads — a 93.9% hit rate, below the alarm
 * line — purely because every first read of a cold pool is a miss. A ratio over
 * too short a window is not a measurement, and saying so is more useful than a
 * number that is technically correct and operationally wrong.
 */
export function judgeMysqlBufferPool(v: MysqlBufferPoolValue): DbVerdict {
  const size = `Pool ${formatBytes(v.sizeBytes)}${v.instances ? ` across ${v.instances} instance${v.instances === 1 ? '' : 's'}` : ''}.`
  if (v.hitRate === null) {
    return { level: 'unknown', headline: 'The buffer pool has served no reads, so there is no hit rate to report.', because: size }
  }
  const pct = `${(v.hitRate * 100).toFixed(2)}%`
  const tooYoung = (v.uptimeSeconds ?? 0) < T.bufferPoolMinUptimeSeconds
  const tooFew = (v.readRequests ?? 0) < T.bufferPoolMinReadRequests
  // AND, not OR. A million requests is a lot for a busy server and nothing for
  // a quiet one, so a server up a hundred days with half a million reads was
  // `unknown` forever at a 99.98% hit rate — a permanently unanswered question
  // rather than a warm-up guard. Either signal on its own is enough to judge;
  // it takes both to mean the pool is still cold.
  if (tooYoung && tooFew) {
    return {
      level: 'unknown',
      headline: `Buffer pool hit rate is ${pct}, over too small a sample to judge.`,
      because: `${formatCount(v.readRequests)} read requests in ${formatSeconds(v.uptimeSeconds)} of uptime. Every first read of a cold pool is a miss, so this ratio only means something after ${formatSeconds(T.bufferPoolMinUptimeSeconds)} and ${formatCount(T.bufferPoolMinReadRequests)} requests. ${size}`
    }
  }
  const detail = `${formatCount(v.reads)} disk reads out of ${formatCount(v.readRequests)} requests. ${size}`
  if (v.hitRate < T.bufferPoolAlarmRate) {
    return {
      level: 'alarm',
      headline: `Buffer pool hit rate is ${pct} — the working set no longer fits.`,
      because: `${detail} Every miss is a disk read on the query's critical path.`
    }
  }
  if (v.hitRate < T.bufferPoolWatchRate) {
    return { level: 'watch', headline: `Buffer pool hit rate is ${pct}.`, because: detail }
  }
  return { level: 'ok', headline: `Buffer pool hit rate is ${pct}.`, because: detail }
}

export function judgeMysqlSizes(v: MysqlSizesValue): DbVerdict {
  // information_schema.TABLES is filtered by grants, silently — the identical
  // mechanism as PROCESSLIST, and there is no counter to cross-check it
  // against, so it is disclosed instead of guessed at. A 500 GB server read by
  // an account with SELECT on one schema answers "32 KB across 1 table" with no
  // error and no warning.
  const scope =
    ' information_schema.TABLES lists only tables this account has some privilege on, and MySQL does not say when it has filtered the list — treat this as a floor, not a total.'
  if (v.tables.length === 0) {
    return {
      level: 'unknown',
      headline: 'No user tables were listed.',
      because: `That is either an empty server or an account with no privileges on anything.${scope}`
    }
  }
  const biggest = v.tables[0]
  const fragmented = v.tables.filter((t) => (t.freeBytes ?? 0) > 1_000_000_000)
  return {
    level: 'ok',
    headline: `${formatBytes(v.totalBytes)} across ${v.tables.length} table${v.tables.length === 1 ? '' : 's'}.`,
    because:
      `Largest: ${biggest.schema}.${biggest.name} at ${formatBytes((biggest.dataBytes ?? 0) + (biggest.indexBytes ?? 0))}.` +
      (fragmented.length > 0
        ? ` ${fragmented.length} table${fragmented.length === 1 ? ' has' : 's have'} over 1 GB of DATA_FREE — space allocated on disk and not in use.`
        : '') +
      scope
  }
}

// ===========================================================================
// The report
// ===========================================================================

export interface DbOpsReport {
  ok: boolean
  /** Set only when the connection itself failed. Individual questions failing
   *  is normal and is reported per answer. */
  error?: string
  engine: DbOpsEngine
  connectionId: string
  at: number
  elapsedMs: number
  /** In the order they should be read. */
  answers: DbAnswer<unknown>[]
}

export type DbOpsEngine = 'postgres' | 'mysql'

/** Which engines this feature covers. MongoDB and Redis are a later roadmap
 *  item and are deliberately not half-built here. */
export function supportsDbOps(kind: string): kind is DbOpsEngine {
  return kind === 'postgres' || kind === 'mysql'
}

export const DB_OPS_UNSUPPORTED_NOTE =
  'Operational reads are available for PostgreSQL and MySQL/MariaDB. MongoDB and Redis answer completely different questions — replica-set state and oplog window, eviction policy and persistence — and get their own pass rather than a thin imitation of this one.'

/** The worst verdict on the page, which is the one the tab badge shows. */
export function worstVerdict(answers: DbAnswer<unknown>[]): DbVerdictLevel {
  let worst: DbVerdictLevel = 'ok'
  for (const a of answers) {
    if (DB_VERDICT_RANK[a.verdict.level] > DB_VERDICT_RANK[worst]) worst = a.verdict.level
  }
  return worst
}

/**
 * The states worth remembering.
 *
 * Item A's store (src/main/services/history.ts) already has recordEvent, and
 * item 19b will alert off it. This function decides WHAT is worth a row; it
 * does not write one and it does not alert. Two rules:
 *
 *  * Only `alarm` and `watch`. An `ok` every sixty seconds is a log nobody
 *    reads and a table that grows forever.
 *  * `unknown` is excluded even though it is not `ok`, with one exception:
 *    a question that went from answerable to `denied` is itself an event —
 *    someone changed a grant — but ShellPilot cannot see the transition from a
 *    single read, so that belongs to whoever compares two reads, not here.
 */
export function notableDbEvents(report: DbOpsReport): { kind: string; payload: Record<string, unknown> }[] {
  const out: { kind: string; payload: Record<string, unknown> }[] = []
  for (const a of report.answers) {
    if (a.verdict.level !== 'alarm' && a.verdict.level !== 'watch') continue
    out.push({
      kind: `db-${a.verdict.level}`,
      payload: {
        connectionId: report.connectionId,
        engine: report.engine,
        question: a.id,
        status: a.status,
        level: a.verdict.level,
        headline: a.verdict.headline,
        because: a.verdict.because,
        metrics: dbEventMetrics(a)
      }
    })
  }
  return out
}

/**
 * The numbers behind a verdict, for whoever alerts off it.
 *
 * A rule of the shape "alert when lag exceeds N" needs a number. Without this
 * the payload is prose, and the only way to express such a rule is a regular
 * expression over an English sentence — which breaks the first time a headline
 * is reworded. The numbers are cheap to add now and a schema migration to add
 * later.
 *
 * Item 19b does NOT read them, and that is deliberate rather than an oversight
 * to be tidied up: it alerts at the levels this file already decided, because
 * an alert that re-derived a verdict could disagree with the screen item 18
 * renders. These are carried for a rule that does not exist yet.
 *
 * Only finite numbers go in. A metric that is null is omitted rather than
 * written as 0, for the same reason `num()` refuses to: an absent measurement
 * and a measurement of zero are the whole subject of this file.
 */
export function dbEventMetrics(a: DbAnswer<unknown>): Record<string, number> {
  const out: Record<string, number> = {}
  const put = (k: string, n: number | null | undefined): void => {
    if (typeof n === 'number' && Number.isFinite(n)) out[k] = n
  }
  const v = a.value as Record<string, unknown> | undefined
  switch (a.id) {
    case 'replication': {
      if (Array.isArray(v)) {
        // MySQL: worst channel.
        const channels = v as MysqlReplicationChannel[]
        put('channels', channels.length)
        const behind = channels.map((c) => c.secondsBehind).filter((n): n is number => n !== null)
        if (behind.length > 0) put('secondsBehind', Math.max(...behind))
        put('channelsStopped', channels.filter((c) => c.ioRunning !== 'Yes' || c.sqlRunning !== 'Yes').length)
      } else if (v && (v as unknown as PgReplicationValue).role === 'standby') {
        const st = v as unknown as PgReplicationStandby
        put('secondsBehind', st.replayAgeSeconds)
        put('applyLagBytes', st.applyLagBytes)
      } else if (v && (v as unknown as PgReplicationValue).role === 'primary') {
        const replicas = (v as unknown as PgReplicationPrimary).replicas
        put('replicas', replicas.length)
        put('replicasRedacted', replicas.filter((r) => r.redacted).length)
        const lags = replicas.map((r) => r.replayLagSeconds).filter((n): n is number => n !== null)
        if (lags.length > 0) put('secondsBehind', Math.max(...lags))
      }
      break
    }
    case 'archiver': {
      const ar = v as unknown as PgArchiver | undefined
      put('failedCount', ar?.failedCount)
      put('archivedCount', ar?.archivedCount)
      put('lastFailedAgeSeconds', ar?.lastFailedAgeSeconds)
      break
    }
    case 'autovacuum': {
      const va = v as unknown as PgVacuumValue | undefined
      const worst = (va?.tables ?? []).reduce<number | null>((m, t) => (t.xidAge !== null && t.xidAge > (m ?? -1) ? t.xidAge : m), null)
      put('xidAge', worst)
      put('freezeMaxAge', va?.freezeMaxAge)
      if (worst !== null && va) put('freezeFraction', worst / va.freezeMaxAge)
      if (worst !== null) put('wraparoundFraction', worst / PG_WRAPAROUND_XID_LIMIT)
      const db = (va?.databases ?? []).reduce<number | null>((m, d) => (d.xidAge !== null && d.xidAge > (m ?? -1) ? d.xidAge : m), null)
      put('databaseXidAge', db)
      break
    }
    case 'connections': {
      if (v && 'usableConnections' in v) {
        const c = v as unknown as PgConnectionsValue
        put('used', c.used)
        put('maxConnections', c.maxConnections)
        put('usableConnections', c.usableConnections)
        put('redactedCount', c.redactedCount)
        if (c.usableConnections > 0) put('usedFraction', c.used / c.usableConnections)
      } else if (v) {
        const c = v as unknown as MysqlConnectionsValue
        put('used', c.threadsConnected)
        put('maxConnections', c.maxConnections)
        put('refused', c.connectionErrorsMaxConnections)
        put('highWaterMark', c.maxUsedConnections)
        if (c.maxConnections > 0 && c.threadsConnected !== null) put('usedFraction', c.threadsConnected / c.maxConnections)
      }
      break
    }
    case 'locks': {
      const locks = (Array.isArray(v) ? v : []) as PgLock[]
      put('blockedSessions', locks.length)
      const waits = locks.map((l) => l.waitingSeconds).filter((n): n is number => n !== null)
      if (waits.length > 0) put('longestWaitSeconds', Math.max(...waits))
      put('redactedSessions', locks.filter((l) => l.redacted).length)
      break
    }
    case 'sizes': {
      if (v && 'databases' in v) {
        const sz = v as unknown as PgSizesValue
        put('totalBytes', sz.databases.reduce((acc, d) => acc + (d.totalBytes ?? 0), 0))
        put('largestTableBytes', sz.tables[0]?.totalBytes)
      } else if (v) {
        const sz = v as unknown as MysqlSizesValue
        put('totalBytes', sz.totalBytes)
        put('tables', sz.tables.length)
      }
      break
    }
    case 'statements': {
      const st = v as unknown as PgStatementsValue | undefined
      put('statements', st?.statements.length)
      put('redactedCount', st?.redactedCount)
      put('slowestMeanMs', st?.statements[0]?.meanExecMs)
      break
    }
    case 'binlogs': {
      const b = v as unknown as MysqlBinlogsValue | undefined
      put('totalBytes', b?.totalBytes)
      put('files', b?.files.length)
      put('expireSeconds', b?.expireSeconds)
      break
    }
    case 'slowlog': {
      const sl = v as unknown as MysqlSlowLogValue | undefined
      put('slowQueries', sl?.slowQueries)
      put('longQueryTimeSeconds', sl?.longQueryTimeSeconds)
      put('uptimeSeconds', sl?.uptimeSeconds)
      break
    }
    case 'processlist': {
      const pl = v as unknown as MysqlProcesslistValue | undefined
      put('visible', pl?.visible)
      put('threadsConnected', pl?.threadsConnected)
      const running = (pl?.processes ?? []).filter(isClientQuery)
      put('running', running.length)
      const secs = running.map((r) => r.seconds).filter((n): n is number => n !== null)
      if (secs.length > 0) put('longestSeconds', Math.max(...secs))
      break
    }
    case 'bufferpool': {
      const bp = v as unknown as MysqlBufferPoolValue | undefined
      put('hitRate', bp?.hitRate)
      put('readRequests', bp?.readRequests)
      put('reads', bp?.reads)
      put('sizeBytes', bp?.sizeBytes)
      break
    }
    default:
      break
  }
  return out
}

/** A question that could not be asked at all, with the reason kept intact. */
export function unanswered<T>(id: DbQuestionId, failure: DbFailure, headline?: string): DbAnswer<T> {
  return {
    id,
    status: failure.status,
    detail: failure.detail,
    verdict: {
      level: 'unknown',
      headline: headline ?? defaultUnansweredHeadline(id, failure.status),
      because: DB_ANSWER_HELP[failure.status]
    }
  }
}

function defaultUnansweredHeadline(id: DbQuestionId, status: DbAnswerStatus): string {
  const label = DB_QUESTION_LABEL[id]
  switch (status) {
    case 'denied':
      return `${label}: this account is not permitted to read it.`
    case 'absent':
      return `${label}: not enabled on this server.`
    case 'unsupported':
      return `${label}: this server version cannot answer it.`
    case 'not-applicable':
      return `${label}: does not apply to this server.`
    default:
      return `${label}: could not be read.`
  }
}
