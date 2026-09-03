/**
 * Database operations — the main-process collectors.
 *
 * One round trip per question over the connection `db.ts` is already holding.
 * Everything this file does is: send a statement, hand the rows to a pure
 * parser in src/shared/dbOps.ts, and attach the judgement that parser produced.
 * No thresholds live here and no sentences are written here, so every editorial
 * decision is testable without a database.
 *
 * Three rules the shape of this file enforces:
 *
 *  1. **Read-only.** Every statement is a SELECT or a SHOW. The refusal to ship
 *     KILL, VACUUM or PURGE is written down in src/shared/dbOps.ts.
 *
 *  2. **One failing question does not fail the page.** Each collector is
 *     wrapped, and a failure becomes an ANSWER with a status — denied, absent,
 *     unsupported — rather than an exception that takes the other seven with
 *     it. That is the point of the whole item: an application user who can read
 *     four of the eight should see four answers and four honest refusals, not
 *     one error.
 *
 *  3. **Detect, do not assume.** Where a statement exists in one dialect and
 *     not another (SHOW REPLICA STATUS, binlog_expire_logs_seconds,
 *     pg_stat_statements' column names) the fallback is tried and its success
 *     is normal. Only both spellings failing is a finding.
 */

import type { DbConnectConfig } from '../../shared/db'
import {
  DB_QUESTION_LABEL,
  MYSQL_QUERIES,
  PG_MIN_VERSION_NUM,
  PG_QUERIES,
  classifyMysqlFailure,
  classifyPgFailure,
  judgeMysqlBinlogs,
  judgeMysqlBufferPool,
  judgeMysqlConnections,
  judgeMysqlProcesslist,
  judgeMysqlReplication,
  judgeMysqlSizes,
  judgeMysqlSlowLog,
  judgePgArchiver,
  judgePgConnections,
  judgePgLocks,
  judgePgReplication,
  judgePgSizes,
  judgePgStatements,
  judgePgVacuum,
  mysqlMaxExecutionTime,
  num,
  parseMysqlBinlogs,
  parseMysqlBufferPool,
  parseMysqlConnections,
  parseMysqlOverview,
  parseMysqlProcesslist,
  parseMysqlReplication,
  parseMysqlSizes,
  parseMysqlSlowLog,
  parsePgArchiver,
  parsePgConnections,
  parsePgLocks,
  parsePgOverview,
  parsePgReplicas,
  parsePgSizes,
  parsePgStandby,
  parsePgStatements,
  parsePgVacuum,
  pgStatementTimeout,
  statusMap,
  str,
  supportsDbOps,
  unanswered,
  type DbAnswer,
  type DbFailure,
  type DbOpsReport,
  type DbQuestionId,
  type PgOverview,
  type PgReplicationValue
} from '../../shared/dbOps'
import { ensure } from './db'

type Row = Record<string, unknown>

/**
 * How long a single question may take.
 *
 * `pg_total_relation_size` over a catalogue with tens of thousands of relations
 * is not instant, and `information_schema.TABLES` on MySQL can stat every file
 * on the server. Without a timeout one slow question holds the whole panel, and
 * a panel that hangs is one nobody opens.
 */
const STATEMENT_TIMEOUT_MS = 8000

/** Rows per list. Enough to see the shape, small enough that the answer is a
 *  judgement and not a data dump the operator has to scroll. */
const ROW_LIMIT = 20

// ---------------------------------------------------------------------------
// Postgres
// ---------------------------------------------------------------------------

interface PgErr {
  code?: string
  message?: string
}

function pgFailure(err: unknown): DbFailure {
  const e = err as PgErr
  return classifyPgFailure(e?.code, e?.message ?? String(err))
}

async function pgRows(client: any, sql: string, params: unknown[] = []): Promise<Row[]> {
  const res = await client.query(sql, params)
  return (res.rows ?? []) as Row[]
}

async function collectPostgres(client: any): Promise<DbAnswer<unknown>[]> {
  const answers: DbAnswer<unknown>[] = []

  // A per-session timeout. It is set once and applies to everything after it;
  // if the server refuses (a role with no SET privilege is unusual but
  // possible) the reads still run, just unbounded.
  try {
    await client.query(pgStatementTimeout(STATEMENT_TIMEOUT_MS))
  } catch {
    /* not fatal — the questions below are what matter */
  }

  // ---- overview. Everything after it needs max_connections and
  // autovacuum_freeze_max_age, so it is the one question whose failure really
  // does stop the page.
  let overview: PgOverview | null = null
  try {
    overview = parsePgOverview((await pgRows(client, PG_QUERIES.overview))[0])
    answers.push({
      id: 'overview',
      status: 'ok',
      value: overview,
      verdict: {
        level: 'ok',
        headline: `PostgreSQL ${overview?.serverVersion ?? '?'} — ${overview?.inRecovery ? 'STANDBY (in recovery)' : 'primary'}.`,
        because: overview
          ? `Connected as ${overview.username} to ${overview.database}. wal_level=${overview.walLevel}, archive_mode=${overview.archiveMode}, up ${Math.round((overview.uptimeSeconds ?? 0) / 60)} minutes.`
          : undefined
      }
    })
  } catch (err) {
    answers.push(unanswered('overview', pgFailure(err)))
    return answers
  }

  const tooOld = (overview?.versionNum ?? 0) > 0 && (overview?.versionNum ?? 0) < PG_MIN_VERSION_NUM

  // ---- replication. Which question to ask is decided by the server's role,
  // because a standby does NOT appear in its own pg_stat_replication — that
  // view lists what a primary is feeding. Asking the wrong one returns an empty
  // set that looks exactly like "no replicas", which is the trap.
  answers.push(
    await answer('replication', async () => {
      if (tooOld) throw Object.assign(new Error(`PostgreSQL ${overview?.serverVersion} predates pg_wal_lsn_diff.`), { code: '42883' })
      if (overview?.inRecovery) {
        const standby = parsePgStandby((await pgRows(client, PG_QUERIES.standby))[0])
        if (!standby) throw new Error('The standby reported no replay position.')
        return { value: standby as PgReplicationValue, verdict: judgePgReplication(standby) }
      }
      const replicas = parsePgReplicas(await pgRows(client, PG_QUERIES.replication))
      const value: PgReplicationValue = { role: 'primary', replicas }
      const verdict = judgePgReplication(value)
      // A row whose every meaningful column is NULL is a permission answer, not
      // a data answer, and it has to be labelled as one or the page reads as
      // "streaming, no lag".
      const allRedacted = replicas.length > 0 && replicas.every((r) => r.redacted)
      return { value, verdict, status: allRedacted ? ('denied' as const) : undefined }
    }, pgFailure)
  )

  // ---- WAL archiving
  answers.push(
    await answer('archiver', async () => {
      const archiver = parsePgArchiver((await pgRows(client, PG_QUERIES.archiver))[0], overview?.archiveMode ?? 'unknown')
      if (!archiver) throw new Error('pg_stat_archiver returned no row.')
      const verdict = judgePgArchiver(archiver)
      const off = archiver.archiveMode !== 'on' && archiver.archiveMode !== 'always'
      return { value: archiver, verdict, status: off ? ('absent' as const) : undefined }
    }, pgFailure)
  )

  // ---- autovacuum and wraparound
  answers.push(
    await answer('autovacuum', async () => {
      const value = parsePgVacuum(await pgRows(client, PG_QUERIES.vacuum, [ROW_LIMIT]), overview?.autovacuumFreezeMaxAge ?? 200_000_000)
      return { value, verdict: judgePgVacuum(value) }
    }, pgFailure)
  )

  // ---- connections
  answers.push(
    await answer('connections', async () => {
      const value = parsePgConnections(await pgRows(client, PG_QUERIES.connections), overview?.maxConnections ?? 0)
      return { value, verdict: judgePgConnections(value) }
    }, pgFailure)
  )

  // ---- blocking locks
  answers.push(
    await answer('locks', async () => {
      const value = parsePgLocks(await pgRows(client, PG_QUERIES.locks, [ROW_LIMIT]))
      return { value, verdict: judgePgLocks(value) }
    }, pgFailure)
  )

  // ---- sizes
  answers.push(
    await answer('sizes', async () => {
      const value = parsePgSizes(
        await pgRows(client, PG_QUERIES.databases),
        await pgRows(client, PG_QUERIES.tables, [ROW_LIMIT])
      )
      return { value, verdict: judgePgSizes(value) }
    }, pgFailure)
  )

  // ---- pg_stat_statements. An extension, so absent is the common case and a
  // first-class answer rather than an error.
  answers.push(
    await answer('statements', async () => {
      const ext = str((await pgRows(client, PG_QUERIES.extension))[0]?.extversion)
      if (!ext) {
        return {
          value: { extensionVersion: null, redactedText: false, redactedCount: 0, statements: [] },
          status: 'absent' as const,
          verdict: {
            level: 'unknown' as const,
            headline: 'pg_stat_statements is not installed in this database.',
            because:
              'It is an extension, not a built-in view, and it is absent far more often than not. Without it Postgres keeps no per-statement history at all, so there is nothing to show — which is different from there being no slow statements. CREATE EXTENSION pg_stat_statements (it also needs to be in shared_preload_libraries and a restart).'
          }
        }
      }
      let rows: Row[]
      try {
        rows = await pgRows(client, PG_QUERIES.statements, [ROW_LIMIT])
      } catch (err) {
        // Postgres 12 and below, or pg_stat_statements below 1.8: the columns
        // were called total_time/mean_time. SQLSTATE 42703 is "column does not
        // exist" and is the documented signal to use the older spelling.
        if ((err as PgErr)?.code !== '42703') throw err
        rows = await pgRows(client, PG_QUERIES.statementsLegacy, [ROW_LIMIT])
      }
      const value = parsePgStatements(rows, ext)
      const status = value.redactedText ? ('denied' as const) : value.redactedCount > 0 ? ('partial' as const) : undefined
      return { value, verdict: judgePgStatements(value), status }
    }, pgFailure)
  )

  return answers
}

// ---------------------------------------------------------------------------
// MySQL / MariaDB
// ---------------------------------------------------------------------------

interface MyErr {
  errno?: number
  message?: string
}

function mysqlFailure(err: unknown): DbFailure {
  const e = err as MyErr
  return classifyMysqlFailure(e?.errno, e?.message ?? String(err))
}

async function myRows(client: any, sql: string, params: unknown[] = []): Promise<Row[]> {
  const [rows] = await client.query(sql, params)
  return (Array.isArray(rows) ? rows : []) as Row[]
}

async function collectMysql(client: any): Promise<DbAnswer<unknown>[]> {
  const answers: DbAnswer<unknown>[] = []

  try {
    await client.query(mysqlMaxExecutionTime(STATEMENT_TIMEOUT_MS))
  } catch {
    /* MariaDB spells it max_statement_time and takes seconds; not worth a
       second dialect probe for a safety net that is already best-effort. */
  }

  // One SHOW GLOBAL STATUS feeds four of the eight questions.
  let status: Record<string, string> = {}
  let statusFailure: DbFailure | null = null
  try {
    status = statusMap(await myRows(client, MYSQL_QUERIES.status))
  } catch (err) {
    statusFailure = mysqlFailure(err)
  }

  let overview: ReturnType<typeof parseMysqlOverview> = null
  try {
    overview = parseMysqlOverview((await myRows(client, MYSQL_QUERIES.overview))[0], num(status.Uptime))
    answers.push({
      id: 'overview',
      status: 'ok',
      value: overview,
      verdict: {
        level: 'ok',
        headline: `${overview?.flavour === 'mariadb' ? 'MariaDB' : 'MySQL'} ${overview?.version ?? '?'} — ${overview?.readOnly ? 'READ ONLY' : 'writable'}.`,
        because: `server_id ${overview?.serverId ?? '?'}, max_connections ${overview?.maxConnections ?? '?'}${
          overview?.uptimeSeconds ? `, up ${Math.round(overview.uptimeSeconds / 60)} minutes` : ''
        }.`
      }
    })
  } catch (err) {
    answers.push(unanswered('overview', mysqlFailure(err)))
    return answers
  }

  // ---- replication. Both spellings, and neither one failing on its own is a
  // finding: MySQL 8.0.22+ renamed the statement and MariaDB below 10.5 never
  // had the new name. What IS a finding is both failing with the same
  // privilege error, which is what an application user gets.
  answers.push(
    await answer('replication', async () => {
      let rows: Row[]
      let firstFailure: unknown = null
      try {
        rows = await myRows(client, MYSQL_QUERIES.replicaStatus)
      } catch (err) {
        firstFailure = err
        // Fall back regardless of which error it was. A parse error means the
        // dialect is older; a privilege error means the account is weaker, and
        // in that case the second attempt fails the same way and its error is
        // the one reported.
        try {
          rows = await myRows(client, MYSQL_QUERIES.slaveStatus)
        } catch {
          throw firstFailure
        }
      }
      const channels = parseMysqlReplication(rows)
      const verdict = judgeMysqlReplication(channels)
      return { value: channels, verdict, status: channels.length === 0 ? ('not-applicable' as const) : undefined }
    }, mysqlFailure)
  )

  // ---- binary logs
  answers.push(
    await answer('binlogs', async () => {
      const logBin = (await myRows(client, MYSQL_QUERIES.logBin))[0]?.log_bin
      const on = num(logBin) === 1 || String(logBin).toUpperCase() === 'ON'
      let seconds: number | null = null
      let days: number | null = null
      try {
        seconds = num((await myRows(client, MYSQL_QUERIES.binlogExpireSeconds))[0]?.expire_seconds)
      } catch {
        // MariaDB: ER_UNKNOWN_SYSTEM_VARIABLE 1193. It spells it in days.
        try {
          days = num((await myRows(client, MYSQL_QUERIES.binlogExpireDays))[0]?.expire_days)
        } catch {
          /* neither name — report no expiry setting rather than guessing one */
        }
      }
      let files: Row[] = []
      let filesFailure: DbFailure | null = null
      if (on) {
        try {
          files = await myRows(client, MYSQL_QUERIES.binaryLogs)
        } catch (err) {
          filesFailure = mysqlFailure(err)
        }
      }
      const value = parseMysqlBinlogs(files, on, { seconds, days })
      const verdict = judgeMysqlBinlogs(value)
      if (filesFailure) {
        return {
          value,
          status: filesFailure.status,
          detail: filesFailure.detail,
          verdict: {
            level: 'unknown' as const,
            headline:
              filesFailure.status === 'denied'
                ? 'Binary logging is on and this account may not list the log files.'
                : 'Binary logging is on and the log files could not be listed.',
            because: filesFailure.detail
          }
        }
      }
      return { value, verdict, status: on ? undefined : ('absent' as const) }
    }, mysqlFailure)
  )

  // ---- slow query log
  answers.push(
    await answer('slowlog', async () => {
      const settings = (await myRows(client, MYSQL_QUERIES.slowSettings))[0]
      const value = parseMysqlSlowLog(settings, status)
      return { value, verdict: judgeMysqlSlowLog(value), status: value.enabled ? undefined : ('absent' as const) }
    }, mysqlFailure)
  )

  // ---- connections
  answers.push(
    await answer('connections', async () => {
      if (statusFailure) throw Object.assign(new Error(statusFailure.detail), { errno: 0 })
      const value = parseMysqlConnections(status, overview?.maxConnections ?? 0)
      return { value, verdict: judgeMysqlConnections(value) }
    }, mysqlFailure)
  )

  // ---- running queries. The count is read separately so partial visibility
  // can be detected; see judgeMysqlProcesslist.
  answers.push(
    await answer('processlist', async () => {
      const rows = await myRows(client, MYSQL_QUERIES.processlist, [ROW_LIMIT])
      let visible: number | null = null
      try {
        visible = num((await myRows(client, MYSQL_QUERIES.processlistCount))[0]?.n)
      } catch {
        /* the listing above already worked; a failed count only costs the
           partial-visibility check, not the answer */
      }
      const value = parseMysqlProcesslist(rows, visible, num(status.Threads_connected))
      const hidden = visible !== null && value.threadsConnected !== null && visible < value.threadsConnected
      return { value, verdict: judgeMysqlProcesslist(value), status: hidden ? ('partial' as const) : undefined }
    }, mysqlFailure)
  )

  // ---- InnoDB buffer pool
  answers.push(
    await answer('bufferpool', async () => {
      if (statusFailure) throw Object.assign(new Error(statusFailure.detail), { errno: 0 })
      const settings = (await myRows(client, MYSQL_QUERIES.bufferPool))[0]
      const value = parseMysqlBufferPool(status, settings)
      return { value, verdict: judgeMysqlBufferPool(value) }
    }, mysqlFailure)
  )

  // ---- table and index sizes
  answers.push(
    await answer('sizes', async () => {
      const value = parseMysqlSizes(await myRows(client, MYSQL_QUERIES.sizes, [ROW_LIMIT]))
      return { value, verdict: judgeMysqlSizes(value) }
    }, mysqlFailure)
  )

  return answers
}

// ---------------------------------------------------------------------------
// Shared plumbing
// ---------------------------------------------------------------------------

interface Produced<T> {
  value: T
  verdict: DbAnswer<T>['verdict']
  /** Overrides `ok` when the value is real but the account saw less than all
   *  of it — a redacted replication row, a truncated processlist. */
  status?: DbAnswer<T>['status']
  detail?: string
}

/**
 * Run one question. A thrown error becomes a classified ANSWER, never an
 * exception that takes the page down. This is the mechanism behind "a
 * permission-denied answer is not an empty answer".
 */
async function answer<T>(
  id: DbQuestionId,
  run: () => Promise<Produced<T>>,
  classify: (err: unknown) => DbFailure
): Promise<DbAnswer<T>> {
  try {
    const produced = await run()
    return {
      id,
      status: produced.status ?? 'ok',
      value: produced.value,
      detail: produced.detail,
      verdict: produced.verdict
    }
  } catch (err) {
    const failure = classify(err)
    // A denied answer keeps the label AND the engine's own words, so the
    // operator knows which grant to ask for.
    return unanswered<T>(id, failure, deniedHeadline(id, failure))
  }
}

function deniedHeadline(id: DbQuestionId, failure: DbFailure): string | undefined {
  if (failure.status !== 'denied') return undefined
  const label = DB_QUESTION_LABEL[id]
  switch (id) {
    case 'replication':
      return `${label}: not permitted. Reading it needs pg_monitor on PostgreSQL, or REPLICATION CLIENT on MySQL — this is NOT "replication is fine".`
    case 'binlogs':
      return `${label}: not permitted. Listing binary logs needs REPLICATION CLIENT.`
    case 'statements':
      return `${label}: not permitted. Reading other roles' statements needs pg_read_all_stats.`
    default:
      return `${label}: not permitted for this account.`
  }
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

export async function dbOps(cfg: DbConnectConfig): Promise<DbOpsReport> {
  const started = Date.now()
  const base = {
    engine: (cfg.kind === 'postgres' ? 'postgres' : 'mysql') as 'postgres' | 'mysql',
    connectionId: cfg.id,
    at: started,
    answers: [] as DbAnswer<unknown>[]
  }
  if (!supportsDbOps(cfg.kind)) {
    return { ...base, ok: false, error: `Operational reads are not available for ${cfg.kind}.`, elapsedMs: 0 }
  }
  try {
    const conn = await ensure(cfg)
    const answers = cfg.kind === 'postgres' ? await collectPostgres(conn.client) : await collectMysql(conn.client)
    return { ...base, ok: true, answers, elapsedMs: Date.now() - started }
  } catch (err) {
    return {
      ...base,
      ok: false,
      error: err instanceof Error ? err.message : String(err),
      elapsedMs: Date.now() - started
    }
  }
}
