import { describe, expect, it } from 'vitest'
import { readFileSync } from 'node:fs'
import { join, resolve } from 'node:path'
import {
  DB_ANSWER_HELP,
  DB_OPS_UNSUPPORTED_NOTE,
  DB_QUESTIONS_BY_ENGINE,
  DB_QUESTION_LABEL,
  DB_THRESHOLDS,
  DB_VERDICT_RANK,
  MYSQL_QUERIES,
  MYSQL_QUESTIONS,
  PG_QUERIES,
  PG_QUESTIONS,
  PG_REDACTED_QUERY,
  bool,
  classifyMysqlFailure,
  classifyPgFailure,
  isClientQuery,
  judgeMysqlBinlogs,
  judgeMysqlBufferPool,
  judgeMysqlChannel,
  judgeMysqlConnections,
  judgeMysqlProcesslist,
  judgeMysqlReplication,
  judgeMysqlSlowLog,
  judgePgArchiver,
  judgePgConnections,
  judgePgLocks,
  judgePgReplication,
  judgePgStatements,
  judgePgVacuum,
  mysqlMaxExecutionTime,
  notableDbEvents,
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
  parsePgReplicas,
  parsePgStandby,
  parsePgStatements,
  parsePgVacuum,
  pgStatementTimeout,
  replicaField,
  replicaVocabulary,
  statusMap,
  supportsDbOps,
  worstVerdict,
  type DbOpsReport,
  type MysqlReplicationChannel
} from '../src/shared/dbOps'

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------
//
// Captured from real servers by the drivers this app ships. See
// tests/fixtures/dbops/README.md for what each file is and where the gaps are.
//
// To regenerate, on a machine with docker:
//
//   docker network create spnet
//   docker run -d --name sp-pg --network spnet -e POSTGRES_PASSWORD=sp -p 55440:5432 \
//     postgres:16 -c wal_level=replica -c max_wal_senders=10 -c hot_standby=on \
//     -c archive_mode=on -c archive_command=/bin/false \
//     -c shared_preload_libraries=pg_stat_statements
//   docker run -d --name sp-my --network spnet -e MYSQL_ROOT_PASSWORD=sp -p 53306:3306 \
//     mysql:8.0 --server-id=1 --log-bin=binlog --gtid-mode=ON \
//     --enforce-gtid-consistency=ON --slow-query-log=ON --long-query-time=1
//   docker run -d --name sp-maria -e MARIADB_ROOT_PASSWORD=sp -p 53308:3306 mariadb:10.4
//
// then a standby via `pg_basebackup -h sp-pg -U repl -D … -R` and a replica via
// `CHANGE REPLICATION SOURCE TO SOURCE_HOST='sp-my' … ; START REPLICA;`, and run
// each statement in PG_QUERIES / MYSQL_QUERIES through `pg` / `mysql2`.

const FIXTURES = resolve(__dirname, 'fixtures/dbops')

interface Captured {
  ok: boolean
  rows?: Record<string, unknown>[]
  code?: string
  errno?: number
  message?: string
}

function capture(engine: 'postgres' | 'mysql', file: string): Record<string, Captured> {
  return JSON.parse(readFileSync(join(FIXTURES, engine, `${file}.json`), 'utf8'))
}

const PG_PRIMARY = capture('postgres', 'primary')
const PG_STANDBY = capture('postgres', 'standby')
const PG_UNPRIV = capture('postgres', 'unprivileged')
const PG_LOCKS = capture('postgres', 'blocking-locks')

const MY_SOURCE = capture('mysql', 'source')
const MY_HEALTHY = capture('mysql', 'replica-healthy')
const MY_IO_STOPPED = capture('mysql', 'replica-io-thread-stopped')
const MY_UNREACHABLE = capture('mysql', 'replica-source-unreachable')
const MY_UNPRIV = capture('mysql', 'unprivileged')
const MARIA = capture('mysql', 'mariadb-10.4')

const rows = (c: Captured): Record<string, unknown>[] => c.rows ?? []
const row = (c: Captured): Record<string, unknown> | undefined => c.rows?.[0]

// ===========================================================================
// The trap this whole item exists for
// ===========================================================================

describe('Seconds_Behind_Source = NULL is BROKEN, never 0 and never healthy', () => {
  // The fixture is not a story about a NULL. It is the actual output of
  // `SHOW REPLICA STATUS` on a MySQL 8.0.46 replica after STOP REPLICA IO_THREAD.
  const captured = row(MY_IO_STOPPED.replicaStatus)!

  it('the captured server really did return null, not 0 and not a string', () => {
    expect(captured.Seconds_Behind_Source).toBeNull()
    expect(captured.Replica_IO_Running).toBe('No')
    // And it said nothing at all about why. The NULL is the whole signal.
    expect(captured.Last_IO_Errno).toBe(0)
    expect(captured.Last_IO_Error).toBe('')
  })

  it('survives parsing as null', () => {
    const [c] = parseMysqlReplication([captured])
    expect(c.secondsBehind).toBeNull()
    // The mutation that would break it. `Number(null)` is 0 and `null ?? 0` is 0;
    // both are the bug, and both would make this assertion pass with `toBe(0)`.
    expect(c.secondsBehind).not.toBe(0)
  })

  it('renders as an alarm that says BROKEN', () => {
    const verdict = judgeMysqlReplication(parseMysqlReplication([captured]))
    expect(verdict.level).toBe('alarm')
    expect(verdict.headline).toMatch(/BROKEN/)
    expect(verdict.headline).not.toMatch(/up to date|healthy|0s behind/)
  })

  /**
   * The fail-first proof, run rather than asserted.
   *
   * `coerced` is exactly what the bug looks like: `secondsBehind ?? 0`. The
   * judgement is then re-run on it, and the assertion is that it comes out
   * DIFFERENT — because if the parser ever coerces, the two calls agree and this
   * test fails. Without the running-thread rule the coerced version says "0s
   * behind" at level ok; with it, the alarm survives the coercion, so the check
   * is aimed at the rule that would be left if someone deleted the null branch.
   */
  it('a null coerced to zero produces a materially different, wrong answer', () => {
    const [real] = parseMysqlReplication([captured])
    const coerced: MysqlReplicationChannel = { ...real, secondsBehind: real.secondsBehind ?? 0 }
    expect(coerced.secondsBehind).toBe(0)

    // Delete the running-thread rule too — i.e. the naive implementation, which
    // only ever looks at the number.
    const naive = judgeMysqlChannel({ ...coerced, ioRunning: 'Yes', sqlRunning: 'Yes' })
    expect(naive.level).toBe('ok')
    expect(naive.headline).toMatch(/0s behind/)

    // What ShellPilot actually says about the same server.
    const real1 = judgeMysqlChannel(real)
    expect(real1.level).toBe('alarm')
    expect(real1.level).not.toBe(naive.level)
  })

  /**
   * The null branch on its own, with both threads reported as running.
   *
   * MySQL will report `Yes`/`Yes` with a NULL lag during the window between the
   * IO thread reconnecting and the applier catching up, so this is not a
   * contrived combination — and it is the case that a coercion would silently
   * turn into "0s behind, ok". This test fails if the null branch is deleted,
   * which is what makes the coercion detectable at all.
   */
  it('is an alarm even when both threads say Yes', () => {
    const [real] = parseMysqlReplication([captured])
    const v = judgeMysqlChannel({ ...real, ioRunning: 'Yes', sqlRunning: 'Yes' })
    expect(v.level).toBe('alarm')
    expect(v.headline).toMatch(/would not say how far behind/)
    expect(v.because).toMatch(/It is NOT zero/)
    // And with a real 0 in the same position, the same code says ok. The value
    // is the only difference, so nothing else can be doing the work.
    expect(judgeMysqlChannel({ ...real, ioRunning: 'Yes', sqlRunning: 'Yes', secondsBehind: 0 }).level).toBe('ok')
  })

  it('says so even when the IO thread stopping is the only evidence', () => {
    const [c] = parseMysqlReplication([captured])
    const v = judgeMysqlChannel(c)
    expect(v.because).toMatch(/no error/i)
  })
})

/**
 * The inverse trap, and the reason the running-thread check runs FIRST.
 *
 * A replica pointed at a host that does not resolve reported
 * `Seconds_Behind_Source: 0`. An implementation that only guarded against NULL
 * would call this healthy at zero lag, which is worse than the bug it was
 * guarding against.
 */
describe('a broken replica that reports 0 seconds behind', () => {
  const captured = row(MY_UNREACHABLE.replicaStatus)!

  it('the captured server really did report zero while disconnected', () => {
    expect(captured.Seconds_Behind_Source).toBe(0)
    expect(captured.Replica_IO_Running).toBe('No')
    expect(captured.Last_IO_Errno).toBe(2005)
  })

  it('is an alarm, and the number is not what decides it', () => {
    const v = judgeMysqlReplication(parseMysqlReplication([captured]))
    expect(v.level).toBe('alarm')
    expect(v.headline).toMatch(/BROKEN/)
    // The engine's own words, kept — minus the identifiers. Last_IO_Error reads
    // `error connecting to master 'repl@nosuchhost.invalid:3306' … Unknown MySQL
    // server host 'nosuchhost.invalid'`, and that sentence is not only rendered,
    // it is written verbatim into the durable event store by notableDbEvents.
    // The judgement does not need a replication username or a source hostname to
    // be right, so neither is kept. See redactDbIdentifiers.
    expect(v.because).toMatch(/Error connecting to source/i)
    expect(v.because).not.toMatch(/nosuchhost\.invalid/)
    expect(v.because).toMatch(/<redacted>/)
  })

  it('a null-only guard would have passed this server as healthy', () => {
    const [c] = parseMysqlReplication([captured])
    // The naive rule: "null means broken, a number means fine".
    const naive = c.secondsBehind === null ? 'alarm' : 'ok'
    expect(naive).toBe('ok')
    expect(judgeMysqlChannel(c).level).toBe('alarm')
  })
})

describe('healthy MySQL replication', () => {
  it('reads as ok with a real lag figure', () => {
    const v = judgeMysqlReplication(parseMysqlReplication(rows(MY_HEALTHY.replicaStatus)))
    expect(v.level).toBe('ok')
    expect(v.headline).toMatch(/running/)
  })

  it('a source is not a replica, and an empty result set says so', () => {
    // Captured: SHOW REPLICA STATUS on a source returns no rows and no error.
    expect(MY_SOURCE.replicaStatus.ok).toBe(true)
    expect(rows(MY_SOURCE.replicaStatus)).toHaveLength(0)
    const v = judgeMysqlReplication(parseMysqlReplication(rows(MY_SOURCE.replicaStatus)))
    expect(v.level).toBe('unknown')
    expect(v.headline).toMatch(/not replicating/)
    expect(v.level).not.toBe('ok')
  })

  it('a deliberately delayed replica is not alarmed on for its own delay', () => {
    const [base] = parseMysqlReplication(rows(MY_HEALTHY.replicaStatus))
    const delayed: MysqlReplicationChannel = { ...base, secondsBehind: 7200, sqlDelaySeconds: 7200 }
    expect(judgeMysqlChannel(delayed).level).toBe('ok')
    // ...but real lag on top of the delay still counts.
    expect(judgeMysqlChannel({ ...delayed, secondsBehind: 7200 + 4000 }).level).toBe('alarm')
  })

  it('reports lag as a duration a person reads', () => {
    const [base] = parseMysqlReplication(rows(MY_HEALTHY.replicaStatus))
    const v = judgeMysqlChannel({ ...base, secondsBehind: 15_120 })
    expect(v.headline).toContain('4h 12m')
  })
})

// ===========================================================================
// Both spellings, because MySQL renamed them and MariaDB did not
// ===========================================================================

describe('SHOW REPLICA STATUS and SHOW SLAVE STATUS', () => {
  it('MySQL 8.0.46 answered both, with different column names', () => {
    // The finding that drove replicaField(): the vocabulary follows the
    // STATEMENT, so reading by the statement we sent would break the moment
    // someone reordered the fallback.
    const modern = row(MY_HEALTHY.replicaStatus)!
    const legacy = row(MY_HEALTHY.slaveStatus)!
    expect('Seconds_Behind_Source' in modern).toBe(true)
    expect('Seconds_Behind_Source' in legacy).toBe(false)
    expect('Seconds_Behind_Master' in legacy).toBe(true)
    expect(replicaVocabulary(modern)).toBe('replica')
    expect(replicaVocabulary(legacy)).toBe('slave')
  })

  it('parses the same server identically under either spelling', () => {
    const [a] = parseMysqlReplication([row(MY_HEALTHY.replicaStatus)!])
    const [b] = parseMysqlReplication([row(MY_HEALTHY.slaveStatus)!])
    expect(b.secondsBehind).toBe(a.secondsBehind)
    expect(b.ioRunning).toBe(a.ioRunning)
    expect(b.sourceHost).toBe(a.sourceHost)
  })

  it('distinguishes a column that is present and NULL from one that is absent', () => {
    expect(replicaField({ Seconds_Behind_Source: null }, 'Seconds_Behind_Source', 'Seconds_Behind_Master')).toBeNull()
    expect(replicaField({}, 'Seconds_Behind_Source', 'Seconds_Behind_Master')).toBeUndefined()
  })

  it('MariaDB 10.4 rejects the new statement, and that is not a failure', () => {
    // Captured: ER_PARSE_ERROR 1064.
    expect(MARIA.replicaStatus.ok).toBe(false)
    expect(MARIA.replicaStatus.errno).toBe(1064)
    expect(classifyMysqlFailure(MARIA.replicaStatus.errno, MARIA.replicaStatus.message!).status).toBe('unsupported')
    // ...and the old one works.
    expect(MARIA.slaveStatus.ok).toBe(true)
  })

  it('MariaDB spells the binlog expiry differently, and that is not a failure either', () => {
    expect(MARIA.binlogExpireSeconds.errno).toBe(1193)
    expect(classifyMysqlFailure(1193, MARIA.binlogExpireSeconds.message!).status).toBe('unsupported')
    const v = parseMysqlBinlogs([], true, { seconds: null, days: num(row(MARIA.binlogExpireDays)!.expire_days) })
    expect(v.expireSource).toBe('expire_logs_days')
    expect(v.expireSeconds).toBe(10 * 86_400)
  })
})

// ===========================================================================
// Permission denied is not an empty answer
// ===========================================================================

describe('permission-denied renders as "not permitted", never as healthy or empty', () => {
  it('MySQL: SHOW REPLICA STATUS without REPLICATION CLIENT', () => {
    expect(MY_UNPRIV.replicaStatus.errno).toBe(1227)
    const f = classifyMysqlFailure(MY_UNPRIV.replicaStatus.errno, MY_UNPRIV.replicaStatus.message!)
    expect(f.status).toBe('denied')
    expect(f.detail).toMatch(/REPLICATION CLIENT/)
    expect(DB_ANSWER_HELP.denied).toMatch(/NOT the same as "there is nothing here"/)
  })

  it('MySQL: SHOW BINARY LOGS without REPLICATION CLIENT', () => {
    expect(classifyMysqlFailure(MY_UNPRIV.binaryLogs.errno, MY_UNPRIV.binaryLogs.message!).status).toBe('denied')
  })

  it('MySQL: binary logging genuinely off is `absent`, not `denied`', () => {
    // Two different situations that both produce no list of binlogs.
    expect(MARIA.binaryLogs.errno).toBe(1381)
    expect(classifyMysqlFailure(1381, MARIA.binaryLogs.message!).status).toBe('absent')
    expect(classifyMysqlFailure(1227, MY_UNPRIV.binaryLogs.message!).status).toBe('denied')
  })

  /**
   * The Postgres twin of the NULL trap, and the one nobody expects: an
   * unprivileged role SELECTing pg_stat_replication gets a ROW back, with every
   * column that answers the question set to NULL, and no error at all.
   */
  it('Postgres: pg_stat_replication returns a row of NULLs rather than an error', () => {
    const captured = row(PG_UNPRIV.replication)!
    expect(PG_UNPRIV.replication.ok).toBe(true)
    expect(captured.application_name).toBe('walreceiver')
    expect(captured.state).toBeNull()
    expect(captured.replay_lag_bytes).toBeNull()

    const [r] = parsePgReplicas([captured])
    expect(r.redacted).toBe(true)

    const v = judgePgReplication({ role: 'primary', replicas: [r] })
    expect(v.level).toBe('unknown')
    expect(v.level).not.toBe('ok')
    expect(v.headline).toMatch(/hidden from this account/)
    expect(v.because).toMatch(/pg_monitor/)
    expect(v.because).toMatch(/do not read this as healthy/i)
  })

  it('Postgres: a redacted row is not mistaken for a healthy one', () => {
    const real = parsePgReplicas(rows(PG_PRIMARY.replication))
    const redacted = parsePgReplicas(rows(PG_UNPRIV.replication))
    expect(real[0].redacted).toBe(false)
    expect(redacted[0].redacted).toBe(true)
    expect(judgePgReplication({ role: 'primary', replicas: real }).level).toBe('ok')
    expect(judgePgReplication({ role: 'primary', replicas: redacted }).level).toBe('unknown')
  })

  it('Postgres: pg_stat_statements redacts the text and keeps the numbers', () => {
    const v = parsePgStatements(rows(PG_UNPRIV.statements), '1.10')
    expect(v.redactedCount).toBe(v.statements.length)
    expect(v.redactedText).toBe(true)
    expect(v.statements[0].query).toBe(PG_REDACTED_QUERY)
    // The timings are real. The numbers are not the problem; the missing text is.
    expect(v.statements[0].totalExecMs).toBeGreaterThan(0)
    const verdict = judgePgStatements(v)
    expect(verdict.level).toBe('unknown')
    expect(verdict.level).not.toBe('ok')
    expect(verdict.headline).toMatch(/may not read the statement text/)
    expect(verdict.because).toMatch(/pg_read_all_stats|pg_monitor/)
  })

  it('Postgres: a PARTLY redacted list is reported as partly redacted', () => {
    // The usual real shape: Postgres shows a role its OWN statements and hides
    // the rest, so most accounts see a mixture rather than a clean refusal.
    const all = parsePgStatements(rows(PG_UNPRIV.statements), '1.10')
    const mixed = parsePgStatements(
      [...rows(PG_UNPRIV.statements).slice(0, 8), ...rows(PG_PRIMARY.statements).slice(0, 2)],
      '1.10'
    )
    expect(all.redactedText).toBe(true)
    expect(mixed.redactedText).toBe(false)
    expect(mixed.redactedCount).toBe(8)
    const verdict = judgePgStatements(mixed)
    expect(verdict.level).toBe('unknown')
    expect(verdict.headline).toMatch(/8 of 10 statement texts are hidden/)
  })

  it('Postgres: insufficient_privilege maps to denied', () => {
    expect(classifyPgFailure('42501', 'permission denied for view pg_stat_replication').status).toBe('denied')
  })

  it('MySQL: the processlist silently shrinks rather than erroring', () => {
    // Captured at the same moment: root saw 3 rows, the app user saw 1, and
    // MySQL said nothing about the difference.
    expect(rows(MY_SOURCE.processlist)).toHaveLength(3)
    expect(rows(MY_UNPRIV.processlist)).toHaveLength(1)
    expect(MY_UNPRIV.processlist.ok).toBe(true)

    const value = parseMysqlProcesslist(rows(MY_UNPRIV.processlist), 1, 2)
    const v = judgeMysqlProcesslist(value)
    expect(v.level).toBe('unknown')
    expect(v.level).not.toBe('ok')
    expect(v.because).toMatch(/PROCESS privilege/)
    expect(v.because).toMatch(/1 is hidden/)
  })

  it('MySQL: a full view of the processlist is not flagged as partial', () => {
    const value = parseMysqlProcesslist(rows(MY_SOURCE.processlist), 3, 3)
    expect(judgeMysqlProcesslist(value).level).toBe('ok')
  })
})

// ===========================================================================
// Postgres: the standby that does not appear in its own view
// ===========================================================================

describe('Postgres replication on a standby', () => {
  it('the standby really is absent from its own pg_stat_replication', () => {
    expect(PG_STANDBY.replication.ok).toBe(true)
    expect(rows(PG_STANDBY.replication)).toHaveLength(0)
    // While its primary sees it perfectly well.
    expect(rows(PG_PRIMARY.replication)).toHaveLength(1)
    expect(row(PG_PRIMARY.replication)!.state).toBe('streaming')
  })

  it('asking the primary question on a standby would report "no replicas"', () => {
    // The trap, made explicit: the wrong question returns an empty set that is
    // indistinguishable from a lost replica.
    const wrong = judgePgReplication({ role: 'primary', replicas: parsePgReplicas(rows(PG_STANDBY.replication)) })
    expect(wrong.headline).toMatch(/No standby is connected/)
  })

  /**
   * The false positive found by running against a real streaming pair.
   *
   * `now() - pg_last_xact_replay_timestamp()` on a fully caught-up standby of an
   * IDLE primary grows without bound: it is the commit time of the last
   * transaction replayed, not a lag. The captured standby was byte-for-byte
   * current and a first draft of this code called it "9m 32s behind".
   */
  it('a caught-up standby of an idle primary is not reported as behind', () => {
    const standby = parsePgStandby(row(PG_STANDBY.standby))!
    expect(standby.applyLagBytes).toBe(0)
    expect(standby.replayAgeSeconds).toBeNull()

    const v = judgePgReplication(standby)
    expect(v.level).toBe('ok')
    expect(v.headline).toMatch(/applied every byte/)

    // Same standby, an hour of idleness later. Still not behind.
    const idle = judgePgReplication({ ...standby, replayAgeSeconds: 3600, neverReplayed: false })
    expect(idle.level).toBe('ok')
    expect(idle.because).toMatch(/how idle the PRIMARY is/)
  })

  it('a standby with unapplied WAL IS reported as behind', () => {
    const standby = parsePgStandby(row(PG_STANDBY.standby))!
    const behind = judgePgReplication({ ...standby, applyLagBytes: 900_000_000, replayAgeSeconds: 15_120, neverReplayed: false })
    expect(behind.level).toBe('alarm')
    expect(behind.headline).toContain('4h 12m')
  })

  it('paused replay is an alarm whatever the numbers say', () => {
    const standby = parsePgStandby(row(PG_STANDBY.standby))!
    const v = judgePgReplication({ ...standby, replayPaused: true })
    expect(v.level).toBe('alarm')
    expect(v.headline).toMatch(/PAUSED/)
  })
})

// ===========================================================================
// Postgres: the other six questions
// ===========================================================================

describe('WAL archiving', () => {
  it('a real archiver outage is an alarm', () => {
    // Captured with archive_command=/bin/false: 28 failures, nothing archived.
    const a = parsePgArchiver(row(PG_PRIMARY.archiver), 'on')!
    expect(a.failedCount).toBe(28)
    expect(a.lastArchivedWal).toBeNull()
    const v = judgePgArchiver(a)
    expect(v.level).toBe('alarm')
    expect(v.headline).toMatch(/FAILING/)
    expect(v.because).toMatch(/pg_wal grows/)
  })

  it('archiving off is reported, not judged', () => {
    const a = parsePgArchiver(row(PG_STANDBY.archiver), 'off')!
    const v = judgePgArchiver(a)
    expect(v.level).toBe('unknown')
    expect(v.headline).toMatch(/archiving is off/)
  })

  it('old failures with recent successes are a watch, not an alarm', () => {
    const a = parsePgArchiver(row(PG_PRIMARY.archiver), 'on')!
    const recovered = { ...a, archivedCount: 900, lastArchivedWal: '0001', lastArchivedAgeSeconds: 30, lastFailedAgeSeconds: 86_400 }
    expect(judgePgArchiver(recovered).level).toBe('watch')
  })

  it('clean archiving is ok', () => {
    const a = parsePgArchiver(row(PG_PRIMARY.archiver), 'on')!
    expect(judgePgArchiver({ ...a, failedCount: 0, archivedCount: 900, lastArchivedAgeSeconds: 12 }).level).toBe('ok')
  })
})

describe('autovacuum and transaction-ID wraparound', () => {
  // The captured ages are 2 and 16 — a real database that has done almost
  // nothing. Producing a real age of a billion needs a billion transactions, so
  // the wraparound arithmetic below is exercised on synthetic ages against the
  // real row shape. Said plainly here rather than implied.
  const real = parsePgVacuum(rows(PG_PRIMARY.vacuum), 200_000_000)

  it('reads the real shape', () => {
    expect(real.tables.map((t) => t.name)).toContain('orders')
    expect(real.tables[0].freezeFraction).toBeLessThan(0.001)
    expect(judgePgVacuum(real).level).toBe('ok')
  })

  it('half of autovacuum_freeze_max_age is a watch', () => {
    const t = { ...real.tables[0], xidAge: 110_000_000, freezeFraction: 110_000_000 / 200_000_000 }
    expect(judgePgVacuum({ ...real, tables: [t] }).level).toBe('watch')
  })

  it('90% is an alarm that names the table and the number', () => {
    const t = { ...real.tables[0], name: 'events', xidAge: 185_000_000, freezeFraction: 0.925 }
    const v = judgePgVacuum({ ...real, tables: [t] })
    expect(v.level).toBe('alarm')
    expect(v.headline).toContain('events')
    expect(v.headline).toMatch(/wraparound/)
    expect(v.because).toMatch(/refuses writes/)
  })

  it('the absolute backstop fires even when freeze_max_age was raised', () => {
    // Someone setting autovacuum_freeze_max_age to 2 billion does not make
    // wraparound go away.
    const t = { ...real.tables[0], xidAge: 1_600_000_000, freezeFraction: 1_600_000_000 / 2_000_000_000 }
    expect(judgePgVacuum({ freezeMaxAge: 2_000_000_000, tables: [t], databases: [] }).level).toBe('alarm')
  })

  it('heavy dead-tuple bloat is a watch even when the freeze age is fine', () => {
    const t = { ...real.tables[0], xidAge: 10, freezeFraction: 0, deadTuples: 4_000_000, liveTuples: 1_000_000 }
    const v = judgePgVacuum({ ...real, tables: [t] })
    expect(v.level).toBe('watch')
    expect(v.headline).toMatch(/dead rows/)
  })

  it('no readable ages is unknown, not ok', () => {
    expect(judgePgVacuum({ freezeMaxAge: 200_000_000, tables: [], databases: [] }).level).toBe('unknown')
  })
})

describe('connections', () => {
  it('reads the real shape, including idle in transaction', () => {
    const v = parsePgConnections(rows(PG_LOCKS.connections), 100)
    expect(v.states.map((s) => s.state)).toContain('idle in transaction')
    expect(v.used).toBe(3)
  })

  it('an idle-in-transaction session is an alarm long before max_connections is', () => {
    const v = parsePgConnections(rows(PG_LOCKS.connections), 100)
    const stale = {
      ...v,
      states: v.states.map((s) => (s.state === 'idle in transaction' ? { ...s, oldestSeconds: 1200 } : s))
    }
    const verdict = judgePgConnections(stale)
    expect(verdict.level).toBe('alarm')
    expect(verdict.because).toMatch(/vacuum cannot remove/)
  })

  it('90% of max_connections is an alarm', () => {
    const v = parsePgConnections([{ state: 'active', n: 95, oldest_seconds: 1 }], 100)
    expect(judgePgConnections(v).level).toBe('alarm')
    expect(judgePgConnections(v).because).toMatch(/refused/)
  })

  it('MySQL: connections that were ALREADY refused are an alarm even at 1% usage', () => {
    const status = statusMap(rows(MY_SOURCE.status))
    const v = parseMysqlConnections({ ...status, Connection_errors_max_connections: '7' }, 151)
    const verdict = judgeMysqlConnections(v)
    expect(verdict.level).toBe('alarm')
    expect(verdict.headline).toMatch(/REFUSED/)
    expect(verdict.because).toMatch(/an outage that has happened/)
  })

  it('MySQL: a healthy server is ok', () => {
    const v = parseMysqlConnections(statusMap(rows(MY_SOURCE.status)), 151)
    expect(judgeMysqlConnections(v).level).toBe('ok')
  })

  it('MySQL: a high-water mark near the limit is a watch even when current usage is low', () => {
    const status = statusMap(rows(MY_SOURCE.status))
    const v = parseMysqlConnections({ ...status, Max_used_connections: '145' }, 151)
    const verdict = judgeMysqlConnections(v)
    expect(verdict.level).toBe('watch')
    expect(verdict.because).toMatch(/high-water mark/i)
  })
})

describe('blocking locks', () => {
  it('reads a real pg_blocking_pids() result', () => {
    const locks = parsePgLocks(rows(PG_LOCKS.locks))
    expect(locks).toHaveLength(1)
    expect(locks[0].blockedBy).toEqual([252])
    expect(locks[0].waitEvent).toBe('transactionid')
  })

  it('nothing blocked is ok', () => {
    expect(judgePgLocks([]).level).toBe('ok')
  })

  it('a long block is an alarm that names the blocker', () => {
    const locks = parsePgLocks(rows(PG_LOCKS.locks))
    const v = judgePgLocks([{ ...locks[0], waitingSeconds: 300 }])
    expect(v.level).toBe('alarm')
    expect(v.because).toMatch(/252/)
  })
})

describe('sizes', () => {
  it('Postgres reads real database and table sizes', () => {
    const v = parseMysqlSizes(rows(MY_SOURCE.sizes))
    expect(v.tables[0].name).toBe('orders')
    expect(v.totalBytes).toBe(32768)
  })
})

// ===========================================================================
// MySQL: the other five questions
// ===========================================================================

describe('binary logs', () => {
  it('reads a real listing and a real expiry setting', () => {
    const v = parseMysqlBinlogs(rows(MY_SOURCE.binaryLogs), true, {
      seconds: num(row(MY_SOURCE.binlogExpireSeconds)!.expire_seconds),
      days: null
    })
    expect(v.files).toHaveLength(3)
    expect(v.totalBytes).toBe(180 + 2_997_942 + 1850)
    expect(v.expireSeconds).toBe(2_592_000)
    expect(judgeMysqlBinlogs(v).level).toBe('ok')
  })

  it('binary logging off is reported as such and not as an empty list', () => {
    const v = parseMysqlBinlogs([], false, { seconds: null, days: 10 })
    const verdict = judgeMysqlBinlogs(v)
    expect(verdict.level).toBe('unknown')
    expect(verdict.headline).toMatch(/OFF/)
    expect(verdict.because).toMatch(/point-in-time recovery/)
  })

  it('logs that never expire are a watch with the disk cost attached', () => {
    const v = parseMysqlBinlogs(rows(MY_SOURCE.binaryLogs), true, { seconds: 0, days: null })
    const verdict = judgeMysqlBinlogs(v)
    expect(verdict.level).toBe('watch')
    expect(verdict.headline).toMatch(/never expire/)
    expect(verdict.headline).toMatch(/2\.9 MB/)
  })
})

describe('the slow query log', () => {
  it('OFF is the first answer, and it is not "no slow queries"', () => {
    // Captured from the replica, where the slow log is off.
    const v = parseMysqlSlowLog(row(MY_HEALTHY.slowSettings), statusMap(rows(MY_HEALTHY.status)))
    expect(v.enabled).toBe(false)
    const verdict = judgeMysqlSlowLog(v)
    expect(verdict.level).toBe('unknown')
    expect(verdict.level).not.toBe('ok')
    expect(verdict.headline).toMatch(/OFF/)
    expect(verdict.because).toMatch(/no evidence/)
  })

  it('ON with a usable threshold is ok', () => {
    const v = parseMysqlSlowLog(row(MY_SOURCE.slowSettings), statusMap(rows(MY_SOURCE.status)))
    expect(v.enabled).toBe(true)
    expect(v.longQueryTimeSeconds).toBe(1)
    expect(judgeMysqlSlowLog(v).level).toBe('ok')
  })

  it('ON with the 10s default records almost nothing, and says so', () => {
    const v = parseMysqlSlowLog(row(MY_SOURCE.slowSettings), statusMap(rows(MY_SOURCE.status)))
    const verdict = judgeMysqlSlowLog({ ...v, longQueryTimeSeconds: 10 })
    expect(verdict.level).toBe('watch')
    expect(verdict.because).toMatch(/prove nothing/)
  })

  it('ON with log_output NONE writes nowhere', () => {
    const v = parseMysqlSlowLog(row(MY_SOURCE.slowSettings), statusMap(rows(MY_SOURCE.status)))
    expect(judgeMysqlSlowLog({ ...v, output: 'NONE' }).level).toBe('unknown')
  })
})

describe('running queries', () => {
  it("the replica's own applier thread is not a long-running query", () => {
    // Found live: the replica's applier shows as `system user` with a TIME equal
    // to the replica's uptime, and a naive "longest query" alarmed at 11 minutes
    // on a healthy server.
    expect(isClientQuery({ id: 1, user: 'system user', host: '', db: null, command: 'Connect', seconds: 669, state: 'Waiting for an event from Coordinator', info: null })).toBe(false)
    expect(isClientQuery({ id: 2, user: 'repl', host: '', db: null, command: 'Binlog Dump GTID', seconds: 900, state: null, info: null })).toBe(false)
    expect(isClientQuery({ id: 3, user: 'app', host: '', db: 'shop', command: 'Query', seconds: 4, state: 'executing', info: 'SELECT 1' })).toBe(true)
  })

  it('a real long-running client query is an alarm', () => {
    const value = parseMysqlProcesslist(
      [{ id: 9, user: 'app', host: 'h', db: 'shop', command: 'Query', seconds: 400, state: 'Sending data', info: 'SELECT ...' }],
      1,
      1
    )
    const v = judgeMysqlProcesslist(value)
    expect(v.level).toBe('alarm')
    expect(v.headline).toMatch(/6m 40s/)
  })

  it('the real source processlist, which is only server threads, is ok', () => {
    const value = parseMysqlProcesslist(rows(MY_SOURCE.processlist), 3, 3)
    expect(judgeMysqlProcesslist(value).level).toBe('ok')
  })
})

describe('the InnoDB buffer pool', () => {
  /**
   * The guard that a real capture forced. A five-minute-old MySQL container
   * reported a 93.9% hit rate — below the alarm line — purely because every
   * first read of a cold pool is a miss.
   */
  it('refuses to judge a hit rate over too small a sample', () => {
    const v = parseMysqlBufferPool(statusMap(rows(MY_SOURCE.status)), row(MY_SOURCE.bufferPool))
    expect(v.hitRate).toBeLessThan(DB_THRESHOLDS.bufferPoolAlarmRate)
    const verdict = judgeMysqlBufferPool(v)
    expect(verdict.level).toBe('unknown')
    expect(verdict.level).not.toBe('alarm')
    expect(verdict.because).toMatch(/cold pool is a miss/)
  })

  it('judges the same ratio once the sample is big enough', () => {
    const v = parseMysqlBufferPool(statusMap(rows(MY_SOURCE.status)), row(MY_SOURCE.bufferPool))
    const settled = { ...v, uptimeSeconds: 86_400, readRequests: 50_000_000, reads: 3_000_000, hitRate: 1 - 3 / 50 }
    expect(judgeMysqlBufferPool(settled).level).toBe('alarm')
    expect(judgeMysqlBufferPool({ ...settled, reads: 1_000_000, hitRate: 0.98 }).level).toBe('watch')
    expect(judgeMysqlBufferPool({ ...settled, reads: 50_000, hitRate: 0.999 }).level).toBe('ok')
  })

  it('no reads at all is unknown, not a perfect score', () => {
    const v = parseMysqlBufferPool({ Innodb_buffer_pool_read_requests: '0', Innodb_buffer_pool_reads: '0' }, undefined)
    expect(v.hitRate).toBeNull()
    expect(judgeMysqlBufferPool(v).level).toBe('unknown')
  })
})

// ===========================================================================
// Coercion, classification, and the rules the file promises
// ===========================================================================

describe('num()', () => {
  it('never turns absence into zero', () => {
    expect(num(null)).toBeNull()
    expect(num(undefined)).toBeNull()
    expect(num('')).toBeNull()
    expect(num('   ')).toBeNull()
    expect(num('not a number')).toBeNull()
    expect(num(NaN)).toBeNull()
  })

  it('reads the driver representations that actually turn up', () => {
    expect(num('17345')).toBe(17_345) // mysql2 SHOW STATUS
    expect(num('200000000')).toBe(200_000_000) // pg bigint
    expect(num('0.000208')).toBeCloseTo(0.000208) // pg interval epoch
    expect(num(0)).toBe(0)
    expect(num(10n)).toBe(10)
  })

  it('0 and null stay different all the way through', () => {
    expect(num(0)).not.toBeNull()
    expect(num(null)).not.toBe(0)
  })
})

describe('bool()', () => {
  it('reads every representation the two engines use', () => {
    expect(bool(true)).toBe(true)
    expect(bool(1)).toBe(true)
    expect(bool(0)).toBe(false)
    expect(bool('ON')).toBe(true)
    expect(bool('off')).toBe(false)
    expect(bool('Yes')).toBe(true)
    expect(bool(null)).toBeNull()
    expect(bool('always')).toBeNull()
  })
})

describe('failure classification', () => {
  it('separates denied, absent, unsupported and unknown', () => {
    expect(classifyPgFailure('42501', 'permission denied').status).toBe('denied')
    expect(classifyPgFailure('42P01', 'relation "pg_stat_statements" does not exist').status).toBe('absent')
    expect(classifyPgFailure('55000', 'recovery is not in progress').status).toBe('not-applicable')
    expect(classifyPgFailure('42703', 'column "total_time" does not exist').status).toBe('unsupported')
    expect(classifyPgFailure('08006', 'connection terminated').status).toBe('error')
  })

  it('an extension registered without its library loaded is absent, not not-applicable', () => {
    // Captured from a standby built by pg_basebackup: it inherits the
    // CREATE EXTENSION and not the postgresql.conf that loads the library.
    // Postgres raises 55000 for this AND for "recovery is not in progress".
    const f = classifyPgFailure('55000', 'pg_stat_statements must be loaded via shared_preload_libraries')
    expect(f.status).toBe('absent')
  })

  it('never loses the engine’s own words', () => {
    const f = classifyMysqlFailure(1227, 'Access denied; you need (at least one of) the SUPER, REPLICATION CLIENT privilege(s) for this operation')
    expect(f.detail).toContain('REPLICATION CLIENT')
  })
})

describe('no query is built by interpolation', () => {
  const source = readFileSync(resolve(__dirname, '../src/shared/dbOps.ts'), 'utf8')

  it('every shipped query is a constant with no template substitution', () => {
    for (const [name, sql] of Object.entries({ ...PG_QUERIES, ...MYSQL_QUERIES })) {
      expect(sql, name).not.toContain('${')
      expect(sql, name).not.toMatch(/'\s*\+|\+\s*'/)
    }
  })

  it('the query blocks in the source contain no interpolation either', () => {
    // Belt and braces: the constants above are the runtime values, this is the
    // text a reviewer reads. A query assembled at module scope would satisfy the
    // first check and fail this one.
    const blocks = source.match(/export const (?:PG|MYSQL)_QUERIES = Object\.freeze\(\{[\s\S]*?\n\}\)/g) ?? []
    expect(blocks).toHaveLength(2)
    for (const b of blocks) expect(b).not.toContain('${')
  })

  it('every query taking input uses a placeholder', () => {
    for (const [name, sql] of Object.entries(PG_QUERIES)) {
      if (/LIMIT\s+\d/.test(sql)) throw new Error(`${name} hard-codes a LIMIT`)
      if (/LIMIT/.test(sql)) expect(sql, name).toContain('$1')
    }
    for (const [name, sql] of Object.entries(MYSQL_QUERIES)) {
      if (/LIMIT/.test(sql)) expect(sql, name).toContain('?')
    }
  })

  it('nothing here writes', () => {
    for (const [name, sql] of Object.entries({ ...PG_QUERIES, ...MYSQL_QUERIES })) {
      expect(sql, name).toMatch(/^\s*(SELECT|SHOW)\b/i)
      expect(sql, name).not.toMatch(/\b(INSERT|UPDATE|DELETE|DROP|TRUNCATE|ALTER|CREATE|GRANT|KILL|VACUUM|ANALYZE|PURGE|RESET|FLUSH)\b/i)
    }
  })

  it('the refusal to ship destructive controls is written down', () => {
    expect(source).toMatch(/pg_terminate_backend/)
    expect(source).toMatch(/VACUUM/)
    expect(source).toMatch(/PURGE BINARY LOGS/)
  })
})

describe('the two statements that cannot bind a parameter', () => {
  it('builds a timeout from an integer', () => {
    expect(pgStatementTimeout(8000)).toBe('SET statement_timeout = 8000')
    expect(mysqlMaxExecutionTime(8000)).toBe('SET SESSION MAX_EXECUTION_TIME = 8000')
  })

  it('throws rather than sanitising anything that is not one', () => {
    for (const bad of ['8000; DROP TABLE users', '8000', 1.5, -1, 0, NaN, Infinity, null, undefined, {}]) {
      expect(() => pgStatementTimeout(bad as number), String(bad)).toThrow(/Refusing to build/)
      expect(() => mysqlMaxExecutionTime(bad as number), String(bad)).toThrow(/Refusing to build/)
    }
  })

  it('refuses an absurd timeout too', () => {
    expect(() => pgStatementTimeout(999_999_999)).toThrow()
  })
})

// ===========================================================================
// Report shape
// ===========================================================================

describe('the report', () => {
  it('covers eight questions per SQL engine', () => {
    expect(PG_QUESTIONS).toHaveLength(8)
    expect(MYSQL_QUESTIONS).toHaveLength(8)
    for (const id of [...PG_QUESTIONS, ...MYSQL_QUESTIONS]) expect(DB_QUESTION_LABEL[id]).toBeTruthy()
  })

  it('covers only the engines it can actually answer for', () => {
    expect(supportsDbOps('postgres')).toBe(true)
    expect(supportsDbOps('mysql')).toBe(true)
    // Added by the MongoDB/Redis pass. They were `false` here deliberately
    // until there were captured fixtures and judgements behind them, rather
    // than a thin imitation of the SQL page — see tests/dbOpsMongoRedis.test.ts.
    expect(supportsDbOps('mongodb')).toBe(true)
    expect(supportsDbOps('redis')).toBe(true)
    // Still out, and the note says why rather than leaving it to be discovered.
    expect(supportsDbOps('mssql')).toBe(false)
    expect(DB_OPS_UNSUPPORTED_NOTE).toMatch(/SQL Server is not covered/)
  })

  it('knows which questions each engine answers', () => {
    for (const [engine, questions] of Object.entries(DB_QUESTIONS_BY_ENGINE)) {
      expect(questions.length, engine).toBeGreaterThanOrEqual(8)
      for (const id of questions) expect(DB_QUESTION_LABEL[id], `${engine}.${id}`).toBeTruthy()
      expect(new Set(questions).size, engine).toBe(questions.length)
    }
  })

  it('ranks unknown above ok, so a question nobody could ask is not a pass', () => {
    expect(DB_VERDICT_RANK.unknown).toBeGreaterThan(DB_VERDICT_RANK.ok)
    expect(DB_VERDICT_RANK.alarm).toBeGreaterThan(DB_VERDICT_RANK.watch)
    expect(worstVerdict([
      { id: 'sizes', status: 'ok', verdict: { level: 'ok', headline: '' } },
      { id: 'replication', status: 'denied', verdict: { level: 'unknown', headline: '' } }
    ])).toBe('unknown')
  })

  it('records notable states as events and stays quiet about the rest', () => {
    const report: DbOpsReport = {
      ok: true,
      engine: 'mysql',
      connectionId: 'db-1',
      at: 1,
      elapsedMs: 2,
      answers: [
        { id: 'replication', status: 'ok', verdict: { level: 'alarm', headline: 'Replication is BROKEN.' } },
        { id: 'binlogs', status: 'ok', verdict: { level: 'watch', headline: 'Binary logs never expire.' } },
        { id: 'sizes', status: 'ok', verdict: { level: 'ok', headline: '32 KB.' } },
        { id: 'slowlog', status: 'absent', verdict: { level: 'unknown', headline: 'The slow query log is OFF.' } }
      ]
    }
    const events = notableDbEvents(report)
    expect(events.map((e) => e.kind)).toEqual(['db-alarm', 'db-watch'])
    expect(events[0].payload).toMatchObject({ connectionId: 'db-1', engine: 'mysql', question: 'replication' })
    // An `ok` every sweep is a table that grows forever, and an `unknown` is not
    // a state change ShellPilot can see from one read.
    expect(events.some((e) => e.payload.question === 'sizes')).toBe(false)
    expect(events.some((e) => e.payload.question === 'slowlog')).toBe(false)
  })

  it('a MySQL overview reads the real version and flavour', () => {
    const my = parseMysqlOverview(row(MY_SOURCE.overview), 900)
    expect(my?.flavour).toBe('mysql')
    expect(my?.maxConnections).toBe(151)
    const maria = parseMysqlOverview(row(MARIA.overview), 600)
    expect(maria?.flavour).toBe('mariadb')
  })
})
