import { describe, expect, it } from 'vitest'
import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import {
  DB_TIMEOUT_STATEMENT_BUILDERS,
  MYSQL_QUERIES,
  PG_QUERIES,
  dbEventMetrics,
  judgeMysqlChannel,
  judgeMysqlSizes,
  judgeMysqlSlowLog,
  judgePgConnections,
  judgePgLocks,
  judgePgReplication,
  judgePgVacuum,
  mariadbMaxStatementTime,
  notableDbEvents,
  parseMysqlReplication,
  parsePgConnections,
  parsePgLocks,
  parsePgReplicas,
  parsePgVacuum,
  redactDbIdentifiers,
  type DbOpsReport
} from '../src/shared/dbOps'

// ===========================================================================
// BLOCKER 1 — a partitioned parent has no storage, and xid_age() on its zero
// relfrozenxid is INT_MAX. Left in the list it is a permanent 1074% alarm that
// also sorts every real table off the end of LIMIT $1.
// ===========================================================================

describe('partitioned parents are not wraparound candidates', () => {
  it('the vacuum query does not ask for relkind p', () => {
    expect(PG_QUERIES.vacuum).not.toMatch(/relkind IN \([^)]*'p'/)
  })

  it('the vacuum query refuses storage-less relations outright', () => {
    // relfrozenxid = 0 is the definition of "this relation has no storage", and
    // age() of a non-normal xid is INT_MAX rather than an error. Written as a
    // negated equality because `xid` is guaranteed only the `=` operator.
    expect(PG_QUERIES.vacuum).toContain("NOT (c.relfrozenxid = '0'::xid)")
  })

  it('toast relations, a classic wraparound source, are no longer excluded', () => {
    expect(PG_QUERIES.vacuum).toMatch(/relkind IN \('r','m','t'\)/)
    expect(PG_QUERIES.vacuum).not.toMatch(/NOT IN \('pg_catalog','information_schema','pg_toast'\)/)
  })

  it('the size query uses the same filter', () => {
    expect(PG_QUERIES.tables).not.toMatch(/relkind IN \([^)]*'p'/)
  })

  it('wraparound is asked cluster-wide as well as per-database', () => {
    // pg_class is per-database; wraparound is a cluster property.
    expect(PG_QUERIES.databaseAges).toMatch(/pg_database/)
    expect(PG_QUERIES.databaseAges).toMatch(/datfrozenxid/)
  })

  it('a database close to wraparound is an alarm even when every table looks fine', () => {
    const v = parsePgVacuum([{ schema: 'public', name: 'orders', xid_age: '12' }], 200_000_000, [
      { name: 'shop', xid_age: '1900000000' }
    ])
    expect(v.databases[0].xidAge).toBe(1_900_000_000)
    const verdict = judgePgVacuum(v)
    expect(verdict.level).toBe('alarm')
    expect(verdict.headline).toMatch(/shop/)
  })
})

// ===========================================================================
// BLOCKER 2 / 4 — the session statements, and the connection they are sent on.
// ===========================================================================

describe('every statement the collector can send is a read or a bounded timeout', () => {
  const collector = readFileSync(resolve(__dirname, '../src/main/services/dbOps.ts'), 'utf8')

  it('the collector sends no SQL of its own — only the frozen maps and the timeout builders', () => {
    // The hole this closes: tests/dbOps.test.ts iterates PG_QUERIES/MYSQL_QUERIES
    // only, and the SET statements were the two statements the app sends that
    // the read-only assertion never saw.
    const literals = collector.match(/\.query\(\s*['"`]/g) ?? []
    expect(literals).toEqual([])
  })

  it('MariaDB gets a timeout too, in the seconds it spells it in', () => {
    expect(mariadbMaxStatementTime(8000)).toBe('SET SESSION max_statement_time = 8')
    expect(() => mariadbMaxStatementTime(0)).toThrow(/Refusing to build/)
  })

  it('every timeout builder is enumerated, so a third one cannot escape the read-only rule', () => {
    expect(DB_TIMEOUT_STATEMENT_BUILDERS.length).toBeGreaterThanOrEqual(3)
    for (const build of DB_TIMEOUT_STATEMENT_BUILDERS) {
      const sql = build(8000)
      expect(sql).toMatch(/^SET (SESSION )?[A-Za-z_]+ = \d+$/)
      expect(sql).not.toMatch(/\b(INSERT|UPDATE|DELETE|DROP|TRUNCATE|ALTER|CREATE|GRANT|KILL|VACUUM|PURGE|BEGIN|COMMIT|ROLLBACK)\b/i)
    }
  })

  it('the collector opens its own connection rather than borrowing the query editor’s', () => {
    expect(collector).toMatch(/openTransient\(cfg\)/)
    // ensure() is the module-cached client the query editor and the shell share.
    expect(collector).not.toMatch(/await ensure\(/)
    expect(collector).not.toMatch(/import \{[^}]*\bensure\b[^}]*\} from '\.\/db'/)
  })
})

// ===========================================================================
// BLOCKER 3 — pg_stat_activity redaction, twice.
// ===========================================================================

describe('a role without pg_read_all_stats sees rows it cannot read', () => {
  it('the connections query does not launder a redacted state into a bucket', () => {
    expect(PG_QUERIES.connections).not.toMatch(/COALESCE\(state/)
  })

  it('redacted backends are counted as redacted, not as a state called "unknown"', () => {
    const v = parsePgConnections(
      [
        { state: null, n: 40, oldest_seconds: '3600' },
        { state: 'active', n: 1, oldest_seconds: '0' }
      ],
      100
    )
    expect(v.redactedCount).toBe(40)
    expect(v.used).toBe(41)
  })

  it('the idle-in-transaction alarm is not silently unreachable — it says it cannot see', () => {
    const v = parsePgConnections(
      [
        { state: null, n: 40, oldest_seconds: '3600' },
        { state: 'active', n: 1, oldest_seconds: '0' }
      ],
      100
    )
    const verdict = judgePgConnections(v)
    expect(verdict.level).not.toBe('ok')
    expect(verdict.level).toBe('unknown')
    expect(verdict.headline).toMatch(/40/)
    expect(verdict.because).toMatch(/pg_read_all_stats/)
  })

  it('a blocked session whose wait cannot be timed is unknown-duration, not 0s', () => {
    const locks = parsePgLocks([
      {
        pid: 41,
        username: 'app',
        state: null,
        waiting_seconds: null,
        blocked_by: [40],
        wait_event_type: null,
        wait_event: null,
        query: null
      }
    ])
    expect(locks[0].redacted).toBe(true)
    const verdict = judgePgLocks(locks)
    expect(verdict.headline).not.toMatch(/\(0s\)/)
    expect(verdict.headline).not.toMatch(/briefly/)
    expect(verdict.level).toBe('unknown')
    expect(verdict.because).toMatch(/pg_read_all_stats/)
  })

  it('a real timed block still outranks the redacted ones', () => {
    const locks = parsePgLocks([
      { pid: 41, username: 'app', state: 'active', waiting_seconds: '7200', blocked_by: [40] },
      { pid: 42, username: 'app', state: null, waiting_seconds: null, blocked_by: [40] }
    ])
    expect(judgePgLocks(locks).level).toBe('alarm')
  })
})

// ===========================================================================
// The cheap, real ones.
// ===========================================================================

describe('partial redaction is not a pass', () => {
  const streaming = {
    application_name: 'standby1',
    client_addr: '10.0.0.2',
    state: 'streaming',
    sync_state: 'async',
    replay_lag_seconds: 0,
    sent_lag_bytes: '0',
    replay_lag_bytes: '0'
  }
  const hidden = { application_name: 'standby2' }

  it('one hidden walsender among two is not "2 standbys streaming"', () => {
    const replicas = parsePgReplicas([streaming, hidden])
    const v = judgePgReplication({ role: 'primary', replicas })
    expect(v.level).not.toBe('ok')
    expect(v.headline).not.toMatch(/2 standbys streaming/)
  })

  it('a walsender serving a base backup is not a fault', () => {
    const replicas = parsePgReplicas([{ ...streaming, state: 'backup' }])
    expect(judgePgReplication({ role: 'primary', replicas }).level).not.toBe('alarm')
  })
})

describe('the slow log cannot be ok when its counters could not be read', () => {
  it('"unknown slow queries recorded in unknown of uptime" is not an ok', () => {
    const v = {
      enabled: true,
      longQueryTimeSeconds: 1,
      file: '/var/log/slow.log',
      output: 'FILE',
      slowQueries: null,
      uptimeSeconds: null
    }
    const verdict = judgeMysqlSlowLog(v)
    expect(verdict.level).toBe('unknown')
    expect(`${verdict.headline} ${verdict.because}`).not.toMatch(/unknown slow quer/)
  })
})

describe('the connection ceiling is not max_connections', () => {
  it('the overview reads both reserved-connection settings', () => {
    expect(PG_QUERIES.overview).toMatch(/superuser_reserved_connections/)
    // PG16 added a second one, and current_setting's missing_ok form is what
    // keeps this query working on 15 and below.
    expect(PG_QUERIES.overview).toMatch(/current_setting\('reserved_connections', true\)/)
  })

  it('the reserved slots come off the ceiling', () => {
    const v = parsePgConnections([{ state: 'active', n: 88, oldest_seconds: '1' }], 100, {
      superuserReserved: 3,
      reserved: 5
    })
    expect(v.usableConnections).toBe(92)
    // 88 of 92 usable is 95%; 88 of 100 is 88% and would not alarm.
    expect(judgePgConnections(v).level).toBe('alarm')
  })
})

describe('MariaDB multi-source replication', () => {
  it('a named MariaDB connection is not collapsed into "default"', () => {
    const [c] = parseMysqlReplication([
      { Connection_name: 'eu', Master_Host: 'db-eu', Slave_IO_Running: 'Yes', Slave_SQL_Running: 'Yes', Seconds_Behind_Master: 0 }
    ])
    expect(c.channel).toBe('eu')
  })

  it('the statement that returns every MariaDB connection is shipped', () => {
    expect(MYSQL_QUERIES.allSlavesStatus).toBe('SHOW ALL SLAVES STATUS')
  })
})

describe('what goes into the durable store', () => {
  const channel = parseMysqlReplication([
    {
      Master_Host: 'db-eu.internal',
      Slave_IO_Running: 'No',
      Slave_SQL_Running: 'Yes',
      Seconds_Behind_Master: null,
      Last_IO_Errno: 2005,
      Last_IO_Error:
        "error connecting to master 'replicator@db-eu.internal:3306' - retry-time: 60 retries: 1 message: Unknown MySQL server host 'db-eu.internal' (-2)"
    }
  ])

  it('the replication username and source host are not written down verbatim', () => {
    const v = judgeMysqlChannel(channel[0])
    expect(v.because).not.toMatch(/replicator@/)
    expect(redactDbIdentifiers("user 'repl'@'10.0.0.9'")).not.toMatch(/10\.0\.0\.9/)
  })

  it('an event carries numbers, so an alert rule does not have to regex English', () => {
    const report: DbOpsReport = {
      ok: true,
      engine: 'postgres',
      connectionId: 'db-1',
      at: 0,
      elapsedMs: 1,
      answers: [
        {
          id: 'connections',
          status: 'ok',
          value: parsePgConnections([{ state: 'active', n: 95, oldest_seconds: '1' }], 100),
          verdict: { level: 'alarm', headline: '95 of 100 connections in use (95%).' }
        }
      ]
    }
    const [event] = notableDbEvents(report)
    expect(event.payload.metrics).toMatchObject({ used: 95, maxConnections: 100 })
  })

  it('every question can be asked for its numbers', () => {
    expect(
      dbEventMetrics({
        id: 'locks',
        status: 'ok',
        value: parsePgLocks([{ pid: 1, waiting_seconds: '90', blocked_by: [2] }]),
        verdict: { level: 'alarm', headline: 'x' }
      })
    ).toMatchObject({ blockedSessions: 1, longestWaitSeconds: 90 })
  })
})

describe('information_schema.TABLES is filtered by grants and does not say so', () => {
  it('the card says the list is only what this account can see', () => {
    const v = judgeMysqlSizes({
      tables: [{ schema: 'shop', name: 'orders', engine: 'InnoDB', rows: 1, dataBytes: 32_768, indexBytes: 0, freeBytes: 0 }],
      totalBytes: 32_768
    })
    expect(v.because).toMatch(/privilege|can see/i)
  })
})
