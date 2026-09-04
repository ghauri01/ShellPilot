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
 *  1. **Read-only.** Every statement is a SELECT or a SHOW, plus the session
 *     timeout, which is built by a validating builder in src/shared/dbOps.ts
 *     and enumerated there so the read-only assertion can see it. The refusal
 *     to ship KILL, VACUUM or PURGE is written down in the same file.
 *
 *  1b. **On a connection of its own.** Nothing here runs on the client the
 *     query editor and the shell share. The timeout is a session setting with
 *     no reset, and a question that raises 42501 aborts the transaction it is
 *     inside. See openTransient() in ./db.
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
 *
 *  4. **A fallback that sees less says so.** Two of them here answer a
 *     narrower question than the one that was asked — MySQL's
 *     `information_schema.PROCESSLIST` without the PROCESS privilege, and
 *     MongoDB's `$currentOp` with `allUsers: false`. Both are taken, because half
 *     an answer beats none, and both mark the answer `partial`. Neither is
 *     allowed to render as the whole truth.
 *
 * For MongoDB and Redis the same three rules hold with different mechanics.
 * There is no session to configure, so rule 1b costs nothing and the transient
 * connection is kept anyway: a MongoClient opened here is also an SSH forward
 * opened here, and it has to be closed. The statement bound is `maxTimeMS` on
 * every Mongo command; Redis has no server-side equivalent at all, and the
 * comment on redisCall says so rather than implying one.
 */

import type { DbConnectConfig } from '../../shared/db'
import {
  DB_QUESTION_LABEL,
  MONGO_COMMANDS,
  MYSQL_QUERIES,
  PG_MIN_VERSION_NUM,
  PG_QUERIES,
  REDIS_COMMANDS,
  classifyMongoFailure,
  classifyMysqlFailure,
  classifyPgFailure,
  classifyRedisFailure,
  infoBool,
  judgeMongoAsserts,
  judgeMongoConnections,
  judgeMongoCurrentOp,
  judgeMongoIndexes,
  judgeMongoOplog,
  judgeMongoReplication,
  judgeMongoSizes,
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
  judgeRedisClients,
  judgeRedisCluster,
  judgeRedisKeyspace,
  judgeRedisMemory,
  judgeRedisPersistence,
  judgeRedisReplication,
  judgeRedisSlowlog,
  judgeRedisStats,
  mariadbMaxStatementTime,
  mergeRedisInfo,
  mongoCollStatsCommand,
  mongoCurrentOpCommand,
  mongoIndexStatsCommand,
  mysqlMaxExecutionTime,
  num,
  parseMongoAsserts,
  parseMongoConnections,
  parseMongoCurrentOp,
  parseMongoIndexes,
  parseMongoOplog,
  parseMongoOverview,
  parseMongoReplication,
  parseMongoSizes,
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
  parseRedisClients,
  parseRedisCluster,
  parseRedisConfig,
  parseRedisInfo,
  parseRedisKeyspace,
  parseRedisMemory,
  parseRedisOverview,
  parseRedisPersistence,
  parseRedisReplication,
  parseRedisSlowlog,
  parseRedisStats,
  pgStatementTimeout,
  redisSlowlogGetCommand,
  statusMap,
  str,
  supportsDbOps,
  unanswered,
  type DbAnswer,
  type DbFailure,
  type DbOpsReport,
  type DbQuestionId,
  type DbOpsEngine,
  type PgOverview,
  type PgReplicationValue,
  type RedisInfo
} from '../../shared/dbOps'
import { mongoDbName, openTransient } from './db'

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

  // A per-session timeout on OUR OWN session, which is closed when this
  // function returns. If the server refuses it (a role with no SET privilege is
  // unusual but possible) the reads still run, just unbounded.
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
      // every() for denied, some() for partial. One redacted walsender among
      // two is not a clean read of two, and the old code only had the first
      // test — so a mixed set came back `ok`.
      const redacted = replicas.filter((r) => r.redacted).length
      const status = redacted === 0 ? undefined : redacted === replicas.length ? ('denied' as const) : ('partial' as const)
      return { value, verdict, status }
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
      // Cluster-wide first, and separately: pg_class is per-database, so the
      // table list cannot see a neighbouring database at 1.9 billion. A role
      // that cannot read pg_database still gets the table answer.
      let databaseAges: Row[] = []
      try {
        databaseAges = await pgRows(client, PG_QUERIES.databaseAges)
      } catch {
        /* supplementary — the per-table ages below are the main answer */
      }
      const value = parsePgVacuum(
        await pgRows(client, PG_QUERIES.vacuum, [ROW_LIMIT]),
        overview?.autovacuumFreezeMaxAge ?? 200_000_000,
        databaseAges
      )
      return { value, verdict: judgePgVacuum(value) }
    }, pgFailure)
  )

  // ---- connections
  answers.push(
    await answer('connections', async () => {
      const value = parsePgConnections(await pgRows(client, PG_QUERIES.connections), overview?.maxConnections ?? 0, {
        superuserReserved: overview?.superuserReservedConnections ?? 0,
        reserved: overview?.reservedConnections ?? 0
      })
      // Backends this role may count and may not read. Same species as the
      // walsender case below: rows present, every readable column NULL.
      return { value, verdict: judgePgConnections(value), status: value.redactedCount > 0 ? ('partial' as const) : undefined }
    }, pgFailure)
  )

  // ---- blocking locks
  answers.push(
    await answer('locks', async () => {
      const value = parsePgLocks(await pgRows(client, PG_QUERIES.locks, [ROW_LIMIT]))
      const redacted = value.some((l) => l.redacted)
      return { value, verdict: judgePgLocks(value), status: redacted ? ('partial' as const) : undefined }
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

  // MySQL's spelling first, then MariaDB's. Not optional: MariaDB raises
  // ER_UNKNOWN_SYSTEM_VARIABLE (1193) on MAX_EXECUTION_TIME, so with only the
  // first probe nothing bounded ANY statement on MariaDB — including `sizes`,
  // which stats every file on the server. A best-effort net that is always
  // absent on one of the two supported flavours is not a net.
  try {
    await client.query(mysqlMaxExecutionTime(STATEMENT_TIMEOUT_MS))
  } catch {
    try {
      await client.query(mariadbMaxStatementTime(STATEMENT_TIMEOUT_MS))
    } catch {
      /* neither spelling — the reads still run, just unbounded */
    }
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
        // in that case the later attempts fail the same way and the FIRST
        // error is the one reported.
        //
        // SHOW ALL SLAVES STATUS before SHOW SLAVE STATUS because on MariaDB
        // the plain form returns only the unnamed default connection: a server
        // replicating from two sources answers it with one row and says nothing
        // about the other. On MySQL it is a parse error and costs one round
        // trip on a path that already failed.
        try {
          rows = await myRows(client, MYSQL_QUERIES.allSlavesStatus)
        } catch {
          try {
            rows = await myRows(client, MYSQL_QUERIES.slaveStatus)
          } catch {
            throw firstFailure
          }
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
      // `status` is empty when SHOW GLOBAL STATUS failed, which made
      // Slow_queries and Uptime null — and the sentence built from them read
      // "unknown slow queries recorded in unknown of uptime" under an `ok`.
      // judgeMysqlSlowLog now returns `unknown` for that; the answer carries
      // the reason as well.
      const value = parseMysqlSlowLog(settings, status)
      const verdict = judgeMysqlSlowLog(value)
      if (statusFailure) {
        return { value, verdict, status: statusFailure.status, detail: statusFailure.detail }
      }
      return { value, verdict, status: value.enabled ? undefined : ('absent' as const) }
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
// MongoDB
// ---------------------------------------------------------------------------

interface MongoErr {
  code?: number
  codeName?: string
  message?: string
}

function mongoFailure(err: unknown): DbFailure {
  const e = err as MongoErr
  return classifyMongoFailure(e?.code, e?.codeName, e?.message ?? String(err))
}

/**
 * Send one command, bounded at both ends.
 *
 * `maxTimeMS` is the SERVER's bound and is the one that matters: without it a
 * `$collStats` over a catalogue of ten thousand collections runs to completion
 * on the server whatever the client does. It is the only field this collector
 * adds to a command in MONGO_COMMANDS, and tests/dbOpsRegressions.test.ts
 * asserts that.
 *
 * `timeoutMS` is the driver's client-side bound, so a server that has stopped
 * answering does not hold the panel open either.
 */
async function mongoCommand(client: any, db: string, command: Record<string, unknown>): Promise<Row> {
  return (await client.db(db).command({ ...command, maxTimeMS: STATEMENT_TIMEOUT_MS }, { timeoutMS: STATEMENT_TIMEOUT_MS })) as Row
}

/** The documents out of a cursor-shaped reply. */
function firstBatch(reply: Row | undefined): Row[] {
  const cursor = reply?.cursor as { firstBatch?: Row[] } | undefined
  return cursor?.firstBatch ?? []
}

/**
 * How many collections are asked about individually.
 *
 * Two round trips each — `$collStats` and `$indexStats` — so this is the number
 * that decides whether the page opens in a second or in thirty. Collections
 * beyond it are counted and named as skipped rather than silently dropped,
 * because a `sizes` answer that quietly covers twelve of four hundred
 * collections is the same species of lie as an unprivileged `listDatabases`.
 */
const COLLECTION_LIMIT = 12

async function collectMongo(client: any, dbName: string): Promise<DbAnswer<unknown>[]> {
  const answers: DbAnswer<unknown>[] = []
  const now = Date.now()

  // ---- overview. `hello` needs no privilege at all and is what tells a
  // standalone from a replica-set member and both from a mongos, so it is the
  // one command whose failure really does stop the page. `serverStatus` may
  // well be denied on the same server — captured, in unauthorized.json — and
  // that costs the version and the uptime, not the page.
  let hello: Row | undefined
  let serverStatus: Row | undefined
  let serverStatusFailure: DbFailure | null = null
  try {
    hello = await mongoCommand(client, MONGO_COMMANDS.hello.db, MONGO_COMMANDS.hello.command)
  } catch (err) {
    answers.push(unanswered('overview', mongoFailure(err)))
    return answers
  }
  let buildInfo: Row | undefined
  try {
    buildInfo = await mongoCommand(client, MONGO_COMMANDS.buildInfo.db, MONGO_COMMANDS.buildInfo.command)
  } catch {
    /* supplementary: serverStatus carries the version too */
  }
  try {
    serverStatus = await mongoCommand(client, MONGO_COMMANDS.serverStatus.db, MONGO_COMMANDS.serverStatus.command)
  } catch (err) {
    serverStatusFailure = mongoFailure(err)
  }

  const overview = parseMongoOverview(hello, buildInfo, serverStatus)
  answers.push({
    id: 'overview',
    status: serverStatusFailure ? serverStatusFailure.status : 'ok',
    value: overview,
    detail: serverStatusFailure?.detail,
    verdict: {
      level: overview?.isRouter ? 'unknown' : 'ok',
      headline: overview?.isRouter
        ? `This is a mongos router, not a mongod — MongoDB ${overview.version}.`
        : `MongoDB ${overview?.version ?? '?'} — ${overview?.setName ? `${overview.role} of set ${overview.setName}` : (overview?.role ?? 'unknown role')}.`,
      because: overview?.isRouter
        ? 'Every question below is aimed at a single mongod. Against a router they answer for the router process or for whichever shard it forwarded to, which is not the same fact, so treat this page as out of scope here.'
        : serverStatusFailure
          ? `serverStatus was refused, so the uptime and the counters below are missing. ${serverStatusFailure.detail}`
          : `Up ${Math.round((overview?.uptimeSeconds ?? 0) / 60)} minutes${overview?.memberCount ? `, ${overview.memberCount} members in the set` : ''}.`
    }
  })

  // ---- replica-set health. A standalone raises code 76, which classifies as
  // not-applicable rather than as a failure.
  answers.push(
    await answer('replication', async () => {
      const status = await mongoCommand(client, MONGO_COMMANDS.replSetGetStatus.db, MONGO_COMMANDS.replSetGetStatus.command)
      const value = parseMongoReplication(status)
      return { value, verdict: judgeMongoReplication(value) }
    }, mongoFailure)
  )

  // ---- the oplog window.
  answers.push(
    await answer('oplog', async () => {
      // The find succeeds with an EMPTY BATCH on a server with no oplog, so
      // the stats call is what distinguishes "no oplog" from "an oplog with
      // nothing in it yet". Its failure is not fatal to the answer.
      const first = firstBatch(await mongoCommand(client, MONGO_COMMANDS.oplogFirst.db, MONGO_COMMANDS.oplogFirst.command))
      const last = firstBatch(await mongoCommand(client, MONGO_COMMANDS.oplogLast.db, MONGO_COMMANDS.oplogLast.command))
      let stats: Row | undefined
      try {
        stats = firstBatch(await mongoCommand(client, MONGO_COMMANDS.oplogStats.db, MONGO_COMMANDS.oplogStats.command))[0]
      } catch {
        /* code 26 on a server with no oplog, which `first` already implies */
      }
      const value = parseMongoOplog(first, last, stats, overview?.uptimeSeconds ?? null)
      return {
        value,
        verdict: judgeMongoOplog(value),
        status: value.present ? undefined : ('not-applicable' as const)
      }
    }, mongoFailure)
  )

  // ---- index usage, for the database the operator is pointed at.
  answers.push(
    await answer('indexes', async () => {
      const names = await collectionNames(client, dbName)
      const per: { collection: string; rows: Row[] | null }[] = []
      for (const name of names.used) {
        try {
          per.push({ collection: name, rows: firstBatch(await mongoCommand(client, dbName, mongoIndexStatsCommand(name))) })
        } catch {
          // A `read` role is granted $collStats and refused $indexStats on the
          // same collection. Named as unreadable rather than reported as
          // having no indexes.
          per.push({ collection: name, rows: null })
        }
      }
      const value = parseMongoIndexes(per, now)
      const denied = value.unreadable.length > 0
      return {
        value,
        verdict: judgeMongoIndexes(value),
        status: denied ? (value.indexes.length === 0 ? ('denied' as const) : ('partial' as const)) : names.skipped > 0 ? ('partial' as const) : undefined
      }
    }, mongoFailure)
  )

  // ---- connections
  answers.push(
    await answer('connections', async () => {
      if (serverStatusFailure) throw Object.assign(new Error(serverStatusFailure.detail), { code: 13, codeName: 'Unauthorized' })
      const value = parseMongoConnections(serverStatus)
      return { value, verdict: judgeMongoConnections(value) }
    }, mongoFailure)
  )

  // ---- running operations
  answers.push(
    await answer('currentop', async () => {
      let rows: Row[]
      let ownOpsOnly = false
      try {
        rows = firstBatch(await mongoCommand(client, 'admin', mongoCurrentOpCommand(ROW_LIMIT, true)))
      } catch (err) {
        // Denied for other users' operations. Asking for our own is not a
        // silent downgrade: it is labelled, because the fallback answers "1
        // operation running" on a server running two hundred.
        if (mongoFailure(err).status !== 'denied') throw err
        rows = firstBatch(await mongoCommand(client, 'admin', mongoCurrentOpCommand(ROW_LIMIT, false)))
        ownOpsOnly = true
      }
      const value = parseMongoCurrentOp(rows, ownOpsOnly)
      return { value, verdict: judgeMongoCurrentOp(value), status: ownOpsOnly ? ('partial' as const) : undefined }
    }, mongoFailure)
  )

  // ---- sizes
  answers.push(
    await answer('sizes', async () => {
      const databases = await mongoCommand(client, MONGO_COMMANDS.listDatabases.db, MONGO_COMMANDS.listDatabases.command)
      const names = await collectionNames(client, dbName)
      const collections: { name: string; stats: Row | null }[] = []
      for (const name of names.used) {
        try {
          collections.push({ name, stats: firstBatch(await mongoCommand(client, dbName, mongoCollStatsCommand(name)))[0] ?? null })
        } catch {
          collections.push({ name, stats: null })
        }
      }
      const value = parseMongoSizes(databases, collections)
      const verdict = judgeMongoSizes(value)
      if (names.skipped > 0) {
        return {
          value,
          status: 'partial' as const,
          verdict: {
            ...verdict,
            because: `${verdict.because ?? ''} Only ${names.used.length} of ${names.used.length + names.skipped} collections in ${dbName} were measured — this page reads them one at a time and stops at ${COLLECTION_LIMIT}.`.trim()
          }
        }
      }
      return { value, verdict, status: value.databasesFiltered ? ('partial' as const) : undefined }
    }, mongoFailure)
  )

  // ---- asserts and page faults
  answers.push(
    await answer('asserts', async () => {
      if (serverStatusFailure) throw Object.assign(new Error(serverStatusFailure.detail), { code: 13, codeName: 'Unauthorized' })
      const value = parseMongoAsserts(serverStatus)
      return { value, verdict: judgeMongoAsserts(value) }
    }, mongoFailure)
  )

  return answers
}

/**
 * The collections of one database, capped.
 *
 * Sorted before the cap so the same twelve are read every time — an unsorted
 * cap makes the panel report a different subset on each refresh, which reads as
 * collections appearing and disappearing.
 */
async function collectionNames(client: any, dbName: string): Promise<{ used: string[]; skipped: number }> {
  const rows = firstBatch(await mongoCommand(client, dbName, MONGO_COMMANDS.listCollections.command))
  const names = rows
    .map((r) => str(r.name))
    .filter((n): n is string => n !== null && !n.startsWith('system.'))
    .sort((a, b) => a.localeCompare(b, 'en'))
  return { used: names.slice(0, COLLECTION_LIMIT), skipped: Math.max(0, names.length - COLLECTION_LIMIT) }
}

// ---------------------------------------------------------------------------
// Redis
// ---------------------------------------------------------------------------

function redisFailure(err: unknown): DbFailure {
  return classifyRedisFailure(err instanceof Error ? err.message : String(err))
}

/**
 * Send one command, bounded on OUR side only.
 *
 * There is no server-side equivalent of `maxTimeMS` here, and saying so is the
 * point: Redis runs commands one at a time and cannot be told to give up on
 * one. What this bound buys is that the panel does not hang — the command it
 * was waiting for carries on. That is acceptable because every command in
 * REDIS_COMMANDS is O(1) or bounded by construction, which is the same reason
 * `KEYS` and `SCAN` are refused up in src/shared/dbOps.ts.
 */
async function redisCall(client: any, argv: string[]): Promise<unknown> {
  let timer: ReturnType<typeof setTimeout> | undefined
  try {
    return await Promise.race([
      client.call(argv[0], ...argv.slice(1)),
      new Promise((_, reject) => {
        timer = setTimeout(() => reject(new Error(`${argv.join(' ')} did not answer within ${STATEMENT_TIMEOUT_MS} ms.`)), STATEMENT_TIMEOUT_MS)
      })
    ])
  } finally {
    if (timer) clearTimeout(timer)
  }
}

/** One INFO section, parsed, or the failure that stopped it. */
async function redisSection(client: any, argv: string[]): Promise<{ info: RedisInfo } | { failure: DbFailure }> {
  try {
    const reply = await redisCall(client, argv)
    return { info: parseRedisInfo(typeof reply === 'string' ? reply : '') }
  } catch (err) {
    return { failure: redisFailure(err) }
  }
}

async function collectRedis(client: any): Promise<DbAnswer<unknown>[]> {
  const answers: DbAnswer<unknown>[] = []
  const now = Date.now()

  // ioredis emits 'error' asynchronously as well as rejecting the call that
  // caused it, and an 'error' event with no listener is an uncaught exception
  // in the MAIN process. A monitoring page must not be able to take the app
  // down because a password was rotated. Removed again below.
  const swallow = (): void => {}
  if (typeof client?.on === 'function') client.on('error', swallow)

  try {
    const server = await redisSection(client, REDIS_COMMANDS.infoServer)
    if ('failure' in server) {
      // Every section is one INFO command, so a refusal here is a refusal
      // everywhere. Reported once as an overview that says which grant is
      // missing, rather than as nine identical red boxes.
      answers.push(unanswered('overview', server.failure, redisDeniedHeadline(server.failure)))
      for (const id of ['memory', 'persistence', 'replication', 'slowlog', 'clients', 'keyspace', 'stats', 'cluster'] as const) {
        answers.push(unanswered(id, server.failure))
      }
      return answers
    }

    const clusterSection = await redisSection(client, REDIS_COMMANDS.infoCluster)
    const clusterInfo = 'info' in clusterSection ? clusterSection.info : null
    const overview = parseRedisOverview(mergeRedisInfo(server.info, clusterInfo))
    answers.push({
      id: 'overview',
      status: 'ok',
      value: overview,
      verdict: {
        level: 'ok',
        headline: `Redis ${overview.version} — ${overview.role ?? 'unknown role'}, mode ${overview.mode ?? 'unknown'}.`,
        because: `Up ${Math.round((overview.uptimeSeconds ?? 0) / 60)} minutes on ${overview.os ?? 'an unreported platform'}.`
      }
    })

    // ---- memory. The one question whose answer other questions need.
    const memorySection = await redisSection(client, REDIS_COMMANDS.infoMemory)
    let policy: string | null = null
    answers.push(
      await answer('memory', async () => {
        if ('failure' in memorySection) throw new Error(memorySection.failure.detail)
        const value = parseRedisMemory(memorySection.info)
        policy = value.policy
        return {
          value,
          verdict: judgeRedisMemory(value),
          // A server that did not report maxmemory has answered LESS than the
          // question asks, which is what `partial` is for.
          status: value.maxmemoryReported ? undefined : ('unsupported' as const)
        }
      }, redisFailure)
    )

    answers.push(
      await answer('persistence', async () => {
        const section = await redisSection(client, REDIS_COMMANDS.infoPersistence)
        if ('failure' in section) throw new Error(section.failure.detail)
        const value = parseRedisPersistence(section.info, now)
        return { value, verdict: judgeRedisPersistence(value) }
      }, redisFailure)
    )

    answers.push(
      await answer('replication', async () => {
        const section = await redisSection(client, REDIS_COMMANDS.infoReplication)
        if ('failure' in section) throw new Error(section.failure.detail)
        const value = parseRedisReplication(section.info)
        return { value, verdict: judgeRedisReplication(value) }
      }, redisFailure)
    )

    // ---- the slow log. The threshold is fetched FIRST, because without it an
    // empty log cannot be interpreted and the answer is `unknown` rather than
    // a clean bill of health.
    answers.push(
      await answer('slowlog', async () => {
        let config: Record<string, string> = {}
        let configFailure: DbFailure | null = null
        try {
          config = parseRedisConfig(await redisCall(client, REDIS_COMMANDS.configSlowlog))
        } catch (err) {
          configFailure = redisFailure(err)
        }
        const length = num(await redisCall(client, REDIS_COMMANDS.slowlogLen))
        const rows = await redisCall(client, redisSlowlogGetCommand(ROW_LIMIT))
        const value = parseRedisSlowlog(rows, config, length)
        return {
          value,
          verdict: judgeRedisSlowlog(value),
          status: configFailure ? configFailure.status : undefined,
          detail: configFailure?.detail
        }
      }, redisFailure)
    )

    answers.push(
      await answer('clients', async () => {
        const section = await redisSection(client, REDIS_COMMANDS.infoClients)
        if ('failure' in section) throw new Error(section.failure.detail)
        const value = parseRedisClients(section.info)
        return {
          value,
          verdict: judgeRedisClients(value),
          status: value.maxclientsReported ? undefined : ('unsupported' as const)
        }
      }, redisFailure)
    )

    answers.push(
      await answer('keyspace', async () => {
        const section = await redisSection(client, REDIS_COMMANDS.infoKeyspace)
        if ('failure' in section) throw new Error(section.failure.detail)
        let selected: number | null = null
        try {
          selected = num(await redisCall(client, REDIS_COMMANDS.dbsize))
        } catch {
          /* DBSIZE is the cross-check, not the answer */
        }
        const value = parseRedisKeyspace(section.info, selected)
        return { value, verdict: judgeRedisKeyspace(value, policy) }
      }, redisFailure)
    )

    answers.push(
      await answer('stats', async () => {
        const section = await redisSection(client, REDIS_COMMANDS.infoStats)
        if ('failure' in section) throw new Error(section.failure.detail)
        const value = parseRedisStats(section.info)
        return { value, verdict: judgeRedisStats(value) }
      }, redisFailure)
    )

    answers.push(
      await answer('cluster', async () => {
        if (clusterInfo === null) throw new Error('INFO cluster did not answer.')
        // CLUSTER INFO is only sent when INFO cluster says there is one. On a
        // standalone it raises "ERR This instance has cluster support
        // disabled", which is a fact rather than a failure — but there is no
        // reason to make the server say it.
        let detail: RedisInfo | null = null
        if (infoBool(clusterInfo, 'cluster_enabled') === true) {
          const reply = await redisCall(client, REDIS_COMMANDS.clusterInfo)
          detail = parseRedisInfo(typeof reply === 'string' ? reply : '')
        }
        const value = parseRedisCluster(clusterInfo, detail)
        return { value, verdict: judgeRedisCluster(value), status: value.enabled === false ? ('not-applicable' as const) : undefined }
      }, redisFailure)
    )

    return answers
  } finally {
    if (typeof client?.off === 'function') client.off('error', swallow)
  }
}

function redisDeniedHeadline(failure: DbFailure): string | undefined {
  if (failure.status !== 'denied') return undefined
  return 'Redis refused INFO, so every question on this page is unanswered. Reading it needs an ACL with +info (and +slowlog, +config|get, +dbsize for the rest) — this is NOT "the server has nothing to report".'
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
    engine: cfg.kind as DbOpsEngine,
    connectionId: cfg.id,
    at: started,
    answers: [] as DbAnswer<unknown>[]
  }
  if (!supportsDbOps(cfg.kind)) {
    return { ...base, ok: false, error: `Operational reads are not available for ${cfg.kind}.`, elapsedMs: 0 }
  }
  let conn: Awaited<ReturnType<typeof openTransient>> | null = null
  try {
    // NOT ensure(). See openTransient() in ./db for the two reasons: the
    // session timeout below never resets, and a denied question aborts whatever
    // transaction the operator has open in the query tab.
    conn = await openTransient(cfg)
    const answers =
      cfg.kind === 'postgres'
        ? await collectPostgres(conn.client)
        : cfg.kind === 'mysql'
          ? await collectMysql(conn.client)
          : cfg.kind === 'mongodb'
            ? // The database the operator selected, not : index usage and
              // collection sizes are questions about the data they are looking
              // at. Everything else runs against admin or local.
              await collectMongo(conn.client, mongoDbName(cfg) ?? 'admin')
            : await collectRedis(conn.client)
    return { ...base, ok: true, answers, elapsedMs: Date.now() - started }
  } catch (err) {
    return {
      ...base,
      ok: false,
      error: err instanceof Error ? err.message : String(err),
      elapsedMs: Date.now() - started
    }
  } finally {
    // Always. A leaked connection here is also a leaked SSH or VPN forward.
    if (conn) {
      try {
        await conn.close()
      } catch {
        /* already gone */
      }
    }
  }
}
