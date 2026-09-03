import { beforeEach, describe, expect, it, vi } from 'vitest'
import { readFileSync, readdirSync } from 'node:fs'
import { join, resolve } from 'node:path'
import { MYSQL_QUERIES, PG_QUERIES, type DbAnswer, type DbAnswerStatus } from '../src/shared/dbOps'
import type { DbConnectConfig } from '../src/shared/db'

/**
 * The collector, driven by the captured fixtures.
 *
 * src/main/services/dbOps.ts was 532 lines with no test at all, and everything
 * interesting in it is a FALLBACK: the REPLICA→SLAVE retry and its both-failed
 * rethrow, the 42703 legacy pg_stat_statements columns, the
 * binlog_expire_logs_seconds→expire_logs_days retry, statusFailure propagation.
 * The fixtures were already a replay script — every file is
 * `{ queryKey: { ok, rows } | { ok: false, code, errno, message } }` — and
 * mariadb-10.4.json records 1064/1193/1381 for exactly these paths. Nothing
 * drove them. This does.
 */

const openTransient = vi.fn()
vi.mock('../src/main/services/db', () => ({
  openTransient: (cfg: DbConnectConfig) => openTransient(cfg)
}))

const { dbOps } = await import('../src/main/services/dbOps')

const FIXTURES = resolve(__dirname, 'fixtures/dbops')

interface Captured {
  ok: boolean
  rows?: Record<string, unknown>[]
  code?: string
  errno?: number
  message?: string
}
type Replay = Record<string, Captured>

function capture(engine: 'postgres' | 'mysql', file: string): Replay {
  return JSON.parse(readFileSync(join(FIXTURES, engine, `${file}.json`), 'utf8'))
}

/** Which statement is this? Matched by text, so a renamed query key that lost
 *  its fixture shows up here as a missing entry rather than as silence. */
function keyOf(map: Record<string, string>, sql: string): string | null {
  for (const [k, v] of Object.entries(map)) if (v === sql) return k
  return null
}

const SET_STATEMENT = /^SET (SESSION )?[A-Za-z_]+ = \d+$/

function raise(cap: Captured): never {
  throw Object.assign(new Error(cap.message ?? 'failed'), { code: cap.code, errno: cap.errno })
}

/** A `pg` Client that answers only from the capture. */
function pgClient(fx: Replay, sent: string[]): { query: (sql: string, params?: unknown[]) => Promise<unknown> } {
  return {
    query: async (sql: string) => {
      sent.push(sql)
      if (SET_STATEMENT.test(sql)) return { rows: [] }
      const key = keyOf(PG_QUERIES, sql)
      if (!key) throw new Error(`the collector sent a statement that is not in PG_QUERIES:\n${sql}`)
      const cap = fx[key]
      if (!cap) throw Object.assign(new Error(`no captured answer for ${key}`), { code: '42P01' })
      if (!cap.ok) raise(cap)
      return { rows: cap.rows ?? [] }
    }
  }
}

/** A `mysql2` connection: same replay, `[rows]` shape. */
function myClient(fx: Replay, sent: string[]): { query: (sql: string, params?: unknown[]) => Promise<unknown> } {
  return {
    query: async (sql: string) => {
      sent.push(sql)
      if (SET_STATEMENT.test(sql)) return [[]]
      const key = keyOf(MYSQL_QUERIES, sql)
      if (!key) throw new Error(`the collector sent a statement that is not in MYSQL_QUERIES:\n${sql}`)
      const cap = fx[key]
      if (!cap) throw Object.assign(new Error(`no captured answer for ${key}`), { errno: 1146 })
      if (!cap.ok) raise(cap)
      return [cap.rows ?? []]
    }
  }
}

const closed = { count: 0 }

function serve(kind: 'postgres' | 'mysql', fx: Replay, sent: string[] = []): void {
  openTransient.mockImplementation(async () => ({
    kind,
    client: kind === 'postgres' ? pgClient(fx, sent) : myClient(fx, sent),
    close: async () => {
      closed.count++
    }
  }))
}

const PG_CFG: DbConnectConfig = { id: 'db-pg', kind: 'postgres', host: 'h', port: 5432, username: 'ops' }
const MY_CFG: DbConnectConfig = { id: 'db-my', kind: 'mysql', host: 'h', port: 3306, username: 'ops' }

function byId(answers: DbAnswer<unknown>[], id: string): DbAnswer<unknown> {
  const a = answers.find((x) => x.id === id)
  if (!a) throw new Error(`no answer for ${id}: got ${answers.map((x) => x.id).join(', ')}`)
  return a
}

const statusOf = (answers: DbAnswer<unknown>[], id: string): DbAnswerStatus => byId(answers, id).status

beforeEach(() => {
  openTransient.mockReset()
  closed.count = 0
})

// ===========================================================================
// The connection the questions run on
// ===========================================================================

describe('the collector does not borrow the connection the query editor is using', () => {
  it('opens its own and closes it, so no session setting and no failed statement outlives the read', () => {
    // BLOCKER 2 and BLOCKER 4 in one: SET statement_timeout on the shared
    // client survived until db:close, and a question that raised 42501 aborted
    // whatever transaction the operator had open in the query tab.
    const sent: string[] = []
    serve('postgres', capture('postgres', 'primary'), sent)
    return dbOps(PG_CFG).then((report) => {
      expect(report.ok).toBe(true)
      expect(closed.count).toBe(1)
      expect(sent.filter((s) => SET_STATEMENT.test(s))).toEqual(['SET statement_timeout = 8000'])
    })
  })

  it('closes it even when the very first question fails', async () => {
    openTransient.mockImplementation(async () => ({
      kind: 'postgres',
      client: {
        query: async () => {
          throw Object.assign(new Error('permission denied for view pg_stat_activity'), { code: '42501' })
        }
      },
      close: async () => {
        closed.count++
      }
    }))
    const report = await dbOps(PG_CFG)
    expect(report.ok).toBe(true)
    expect(statusOf(report.answers, 'overview')).toBe('denied')
    expect(closed.count).toBe(1)
  })

  it('MariaDB gets a bound on its statements too', async () => {
    const sent: string[] = []
    const fx = capture('mysql', 'mariadb-10.4')
    openTransient.mockImplementation(async () => ({
      kind: 'mysql',
      client: {
        query: async (sql: string, params?: unknown[]) => {
          if (sql === 'SET SESSION MAX_EXECUTION_TIME = 8000') {
            throw Object.assign(new Error('Unknown system variable'), { errno: 1193 })
          }
          return myClient(fx, sent).query(sql, params)
        }
      },
      close: async () => {
        closed.count++
      }
    }))
    await dbOps(MY_CFG)
    // MariaDB spells it max_statement_time and takes seconds. Without the
    // second probe nothing bounds `sizes`, which stats every file on the server.
    expect(sent).toContain('SET SESSION max_statement_time = 8')
  })
})

// ===========================================================================
// The fallbacks nothing drove
// ===========================================================================

describe('PostgreSQL', () => {
  it('answers all eight from the captured primary', async () => {
    serve('postgres', capture('postgres', 'primary'))
    const { answers } = await dbOps(PG_CFG)
    expect(answers.map((a) => a.id)).toEqual([
      'overview',
      'replication',
      'archiver',
      'autovacuum',
      'connections',
      'locks',
      'sizes',
      'statements'
    ])
  })

  it('falls back to total_time when the modern column names raise 42703', async () => {
    const fx = capture('postgres', 'primary')
    // The 42703 is real and so are the rows — this capture is from PG16, where
    // it is the LEGACY spelling that raises "column total_time does not exist".
    // On a pre-13 server the modern spelling raises it instead, which is the
    // branch under test, so the two captured answers are swapped. Nothing is
    // invented: both halves came off the same server.
    expect(fx.statementsLegacy.ok).toBe(false)
    expect(fx.statementsLegacy.code).toBe('42703')
    serve('postgres', { ...fx, statements: fx.statementsLegacy, statementsLegacy: fx.statements })
    const { answers } = await dbOps(PG_CFG)
    // The fallback succeeding is normal, not a finding.
    expect(statusOf(answers, 'statements')).toBe('ok')
  })

  it('asks the standby about itself rather than about walsenders it does not have', async () => {
    serve('postgres', capture('postgres', 'standby'))
    const { answers } = await dbOps(PG_CFG)
    const replication = byId(answers, 'replication')
    expect((replication.value as { role: string }).role).toBe('standby')
  })

  it('a database without the extension is absent, not an error', async () => {
    // Only the two pg_stat_statements statements were run in that database, so
    // the overview comes from the same cluster's primary capture.
    serve('postgres', { ...capture('postgres', 'primary'), ...capture('postgres', 'no-pg-stat-statements') })
    const { answers } = await dbOps(PG_CFG)
    expect(statusOf(answers, 'statements')).toBe('absent')
    expect(byId(answers, 'statements').verdict.level).toBe('unknown')
  })

  it('an unprivileged role gets labelled answers, not empty ones', async () => {
    serve('postgres', capture('postgres', 'unprivileged'))
    const { answers } = await dbOps(PG_CFG)
    // Every walsender row came back with every lag column NULL.
    expect(statusOf(answers, 'replication')).toBe('denied')
    expect(byId(answers, 'replication').verdict.level).toBe('unknown')
    // pg_stat_statements kept the timings and hid every statement text.
    expect(statusOf(answers, 'statements')).toBe('denied')
  })
})

describe('MySQL and MariaDB', () => {
  it('answers all eight from the captured source', async () => {
    serve('mysql', capture('mysql', 'source'))
    const { answers } = await dbOps(MY_CFG)
    expect(answers.map((a) => a.id)).toEqual([
      'overview',
      'replication',
      'binlogs',
      'slowlog',
      'connections',
      'processlist',
      'bufferpool',
      'sizes'
    ])
    // SHOW REPLICA STATUS on a source is an EMPTY RESULT SET, not an error.
    expect(statusOf(answers, 'replication')).toBe('not-applicable')
  })

  it('MariaDB 10.4: 1064 on SHOW REPLICA STATUS is a dialect, not a failure', async () => {
    const fx = capture('mysql', 'mariadb-10.4')
    expect(fx.replicaStatus.errno).toBe(1064)
    expect(fx.slaveStatus.ok).toBe(true)
    serve('mysql', fx)
    const { answers } = await dbOps(MY_CFG)
    expect(byId(answers, 'replication').status).not.toBe('error')
  })

  it('MariaDB 10.4: 1193 falls back to expire_logs_days, and 1381 is absent', async () => {
    const fx = capture('mysql', 'mariadb-10.4')
    expect(fx.binlogExpireSeconds.errno).toBe(1193)
    expect(fx.binaryLogs.errno).toBe(1381)
    serve('mysql', fx)
    const { answers } = await dbOps(MY_CFG)
    expect(statusOf(answers, 'binlogs')).toBe('absent')
  })

  it('both replication spellings failing on privilege reports the FIRST failure', async () => {
    const fx = capture('mysql', 'unprivileged')
    expect(fx.replicaStatus.errno).toBe(1227)
    serve('mysql', fx)
    const { answers } = await dbOps(MY_CFG)
    const replication = byId(answers, 'replication')
    expect(replication.status).toBe('denied')
    expect(replication.detail).toMatch(/REPLICATION CLIENT/)
    expect(replication.verdict.headline).toMatch(/NOT "replication is fine"/)
  })

  it('an unprivileged processlist is partial, never a smaller truth', async () => {
    const fx = capture('mysql', 'unprivileged')
    // The captured session: Threads_connected is 2 and PROCESSLIST returned
    // exactly ONE row, the account's own. `processlistCount` was added to
    // MYSQL_QUERIES after the capture, so it is supplied here rather than
    // pretended to be captured — and 1 is the only value consistent with the
    // rows above it, not a number chosen to make a test pass.
    expect(fx.processlist.rows).toHaveLength(1)
    fx.processlistCount = { ok: true, rows: [{ n: 1 }] }
    serve('mysql', fx)
    const { answers } = await dbOps(MY_CFG)
    expect(statusOf(answers, 'processlist')).toBe('partial')
    expect(byId(answers, 'processlist').verdict.headline).toMatch(/cannot see the whole processlist/)
  })

  it('a missing count costs the partial check and not the answer', async () => {
    // The same file WITHOUT that entry, which is the shipped fallback path:
    // the listing worked, the count did not, and the answer still lands.
    serve('mysql', capture('mysql', 'unprivileged'))
    const { answers } = await dbOps(MY_CFG)
    expect(statusOf(answers, 'processlist')).toBe('ok')
  })

  it('a failed SHOW GLOBAL STATUS is propagated, not rendered as zero counters', async () => {
    const fx = { ...capture('mysql', 'source') }
    fx.status = { ok: false, errno: 1227, message: 'Access denied; you need the PROCESS privilege' }
    serve('mysql', fx)
    const { answers } = await dbOps(MY_CFG)
    expect(statusOf(answers, 'connections')).toBe('denied')
    expect(statusOf(answers, 'bufferpool')).toBe('denied')
    // And the slow log cannot claim "ok" when it cannot count anything.
    expect(byId(answers, 'slowlog').verdict.level).not.toBe('ok')
  })
})

// ===========================================================================
// The fixtures are a replay script, so they have to match the script
// ===========================================================================

describe('every shipped statement has a captured answer', () => {
  /** Captured, but no statement asks for it any more. Kept because deleting a
   *  real capture to satisfy a test is how fixtures start being fiction. */
  const EXTRA = new Set(['superReadOnly', 'q'])
  /** Shipped, and no server was available to capture it. Stated in
   *  tests/fixtures/dbops/README.md rather than invented. */
  const UNCAPTURED = new Set(['processlistCount', 'allSlavesStatus', 'databaseAges'])

  function files(engine: 'postgres' | 'mysql'): string[] {
    return readdirSync(join(FIXTURES, engine)).filter((f) => f.endsWith('.json'))
  }

  for (const engine of ['postgres', 'mysql'] as const) {
    const map = engine === 'postgres' ? PG_QUERIES : MYSQL_QUERIES

    it(`${engine}: no fixture key is an orphan`, () => {
      for (const file of files(engine)) {
        const fx = capture(engine, file.replace(/\.json$/, ''))
        expect(Array.isArray(fx), `${file} is not the documented { key: capture } shape`).toBe(false)
        for (const key of Object.keys(fx)) {
          if (EXTRA.has(key)) continue
          expect(Object.keys(map), `${file} has a key no statement asks for: ${key}`).toContain(key)
        }
      }
    })

    it(`${engine}: every statement is covered by at least one fixture`, () => {
      const seen = new Set<string>()
      for (const file of files(engine)) {
        for (const key of Object.keys(capture(engine, file.replace(/\.json$/, '')))) seen.add(key)
      }
      for (const key of Object.keys(map)) {
        if (UNCAPTURED.has(key)) continue
        expect(seen, `${engine}.${key} has no captured answer anywhere`).toContain(key)
      }
    })
  }

  it('the gaps are stated in the README rather than left to be discovered', () => {
    const readme = readFileSync(join(FIXTURES, 'README.md'), 'utf8')
    for (const key of ['processlistCount', 'allSlavesStatus', 'databaseAges', 'superReadOnly']) {
      expect(readme, `${key} is not accounted for in the README`).toContain(key)
    }
  })
})
