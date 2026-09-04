import { beforeEach, describe, expect, it, vi } from 'vitest'
import { readFileSync, readdirSync } from 'node:fs'
import { join, resolve } from 'node:path'
import {
  MONGO_COMMANDS,
  MONGO_QUESTIONS,
  REDIS_COMMANDS,
  REDIS_QUESTIONS,
  mongoCollStatsCommand,
  mongoCurrentOpCommand,
  mongoIndexStatsCommand,
  redisSlowlogGetCommand,
  type DbAnswer,
  type DbAnswerStatus
} from '../src/shared/dbOps'
import type { DbConnectConfig } from '../src/shared/db'

/**
 * The MongoDB and Redis collectors, driven by the captured fixtures.
 *
 * The same shape as tests/dbOpsCollector.test.ts and for the same reason:
 * everything interesting in a collector is a FALLBACK, and a fallback nothing
 * drives is a fallback nobody has run. The three here are `$currentOp` dropping
 * from allUsers:true to false, `$indexStats` being refused per collection while
 * `$collStats` succeeds, and an INFO refusal collapsing the whole Redis page
 * into one labelled answer instead of nine identical red boxes.
 *
 * A fake driver answers ONLY from the capture, and it matches by comparing the
 * command it was sent against MONGO_COMMANDS / REDIS_COMMANDS. So a collector
 * that invents a command, or renames one out from under its fixture, fails here
 * with the command in the message rather than silently losing coverage.
 */

const openTransient = vi.fn()
// The parameter is declared so the mock has the arity the call site uses.
const mongoDbName = vi.fn((_cfg: DbConnectConfig) => 'shop')
vi.mock('../src/main/services/db', () => ({
  openTransient: (cfg: DbConnectConfig) => openTransient(cfg),
  mongoDbName: (cfg: DbConnectConfig) => mongoDbName(cfg)
}))

const { dbOps } = await import('../src/main/services/dbOps')

const FIXTURES = resolve(__dirname, 'fixtures/dbops')

interface MongoCapture {
  ok: boolean
  result?: Record<string, unknown>
  code?: number
  codeName?: string
  message?: string
}
interface RedisCapture {
  ok: boolean
  reply?: unknown
  message?: string
}

function mongoFixture(file: string): Record<string, MongoCapture> {
  return JSON.parse(readFileSync(join(FIXTURES, 'mongodb', `${file}.json`), 'utf8'))
}
function redisFixture(file: string): Record<string, RedisCapture> {
  return JSON.parse(readFileSync(join(FIXTURES, 'redis', `${file}.json`), 'utf8'))
}

/**
 * Which MONGO_COMMANDS entry this is.
 *
 * `maxTimeMS` is stripped before comparing, because it is the ONE field the
 * collector adds to every command — see mongoCommand() in the service. If it
 * ever adds a second, every command stops matching and every test in this file
 * says which one.
 */
function mongoKeyOf(db: string, command: Record<string, unknown>): string | null {
  const { maxTimeMS: _dropped, ...sent } = command
  const text = JSON.stringify(sent)
  for (const [key, spec] of Object.entries(MONGO_COMMANDS)) {
    if (spec.db !== null && spec.db !== db) continue
    if (JSON.stringify(spec.command) === text) return key
  }
  // The builders, whose parameter is part of the key.
  const coll = typeof sent.aggregate === 'string' ? sent.aggregate : null
  if (coll) {
    if (JSON.stringify(mongoIndexStatsCommand(coll)) === text) return `indexStats:${coll}`
    if (JSON.stringify(mongoCollStatsCommand(coll)) === text) return `collStats:${coll}`
  }
  if (JSON.stringify(mongoCurrentOpCommand(20, true)) === text) return 'currentOp'
  if (JSON.stringify(mongoCurrentOpCommand(20, false)) === text) return 'currentOpOwn'
  return null
}

function redisKeyOf(argv: string[]): string | null {
  const text = JSON.stringify(argv)
  for (const [key, spec] of Object.entries(REDIS_COMMANDS)) if (JSON.stringify(spec) === text) return key
  if (JSON.stringify(redisSlowlogGetCommand(20)) === text) return 'slowlogGet'
  return null
}

function raiseMongo(cap: MongoCapture): never {
  throw Object.assign(new Error(cap.message ?? 'failed'), { code: cap.code, codeName: cap.codeName })
}

const sentCommands: string[] = []
const closed = { count: 0 }

function serveMongo(fx: Record<string, MongoCapture>): void {
  openTransient.mockImplementation(async () => ({
    kind: 'mongodb',
    client: {
      db: (name: string) => ({
        command: async (command: Record<string, unknown>) => {
          const key = mongoKeyOf(name, command)
          if (!key) throw new Error(`the collector sent a command that is not in MONGO_COMMANDS:\n${name}: ${JSON.stringify(command)}`)
          sentCommands.push(key)
          const cap = fx[key]
          if (!cap) throw Object.assign(new Error(`no captured answer for ${key}`), { code: 59, codeName: 'CommandNotFound' })
          if (!cap.ok) raiseMongo(cap)
          return cap.result ?? {}
        }
      })
    },
    close: async () => {
      closed.count++
    }
  }))
}

function serveRedis(fx: Record<string, RedisCapture>): void {
  openTransient.mockImplementation(async () => ({
    kind: 'redis',
    client: {
      on: () => {},
      off: () => {},
      call: async (...argv: string[]) => {
        const key = redisKeyOf(argv)
        if (!key) throw new Error(`the collector sent a command that is not in REDIS_COMMANDS:\n${argv.join(' ')}`)
        sentCommands.push(key)
        const cap = fx[key]
        if (!cap) throw new Error(`ERR unknown command '${argv[0]}'`)
        if (!cap.ok) throw new Error(cap.message ?? 'failed')
        return cap.reply
      }
    },
    close: async () => {
      closed.count++
    }
  }))
}

// `username` is required on `DbConnectConfig` — a collector config with none
// is not one the app can build.
const MONGO_CFG: DbConnectConfig = {
  id: 'db-mongo',
  kind: 'mongodb',
  host: 'h',
  port: 27017,
  username: 'app',
  database: 'shop'
}
const REDIS_CFG: DbConnectConfig = { id: 'db-redis', kind: 'redis', host: 'h', port: 6379, username: 'app' }

function byId(answers: DbAnswer<unknown>[], id: string): DbAnswer<unknown> {
  const a = answers.find((x) => x.id === id)
  if (!a) throw new Error(`no answer for ${id}: got ${answers.map((x) => x.id).join(', ')}`)
  return a
}
const statusOf = (answers: DbAnswer<unknown>[], id: string): DbAnswerStatus => byId(answers, id).status

beforeEach(() => {
  openTransient.mockReset()
  sentCommands.length = 0
  closed.count = 0
})

// ===========================================================================
// MongoDB
// ===========================================================================

describe('the MongoDB collector', () => {
  it('answers all eight from the captured primary, in order', async () => {
    serveMongo(mongoFixture('replica-set-primary'))
    const report = await dbOps(MONGO_CFG)
    expect(report.ok).toBe(true)
    expect(report.engine).toBe('mongodb')
    expect(report.answers.map((a) => a.id)).toEqual([...MONGO_QUESTIONS])
    expect(report.answers.every((a) => a.verdict.headline.length > 0)).toBe(true)
  })

  it('closes the connection it opened, even when the first command fails', async () => {
    // Not a nicety: a MongoClient opened here is also an SSH forward or a VPN
    // route opened here.
    // FAILS FIRST, with the finally-block close removed, as:
    //   expected +0 to be 1 // Object.is equality
    serveMongo(mongoFixture('replica-set-primary'))
    await dbOps(MONGO_CFG)
    expect(closed.count).toBe(1)

    openTransient.mockImplementation(async () => ({
      kind: 'mongodb',
      client: {
        db: () => ({
          command: async () => {
            throw Object.assign(new Error('command hello requires authentication'), { code: 13, codeName: 'Unauthorized' })
          }
        })
      },
      close: async () => {
        closed.count++
      }
    }))
    const report = await dbOps(MONGO_CFG)
    expect(report.ok).toBe(true)
    expect(statusOf(report.answers, 'overview')).toBe('denied')
    expect(closed.count).toBe(2)
  })

  it('bounds every command it sends on the server as well as on itself', async () => {
    // The only field the collector adds. mongoKeyOf strips exactly this one, so
    // if a second ever appears every command in this file stops matching.
    // FAILS FIRST, with maxTimeMS dropped, as:
    //   expected undefined to be 8000 // Object.is equality
    // and what it costs is not hypothetical: without it a $collStats over a
    // large catalogue runs to completion on the server whatever the client
    // does, because the driver's timeoutMS only stops US waiting.
    const seen: Record<string, unknown>[] = []
    openTransient.mockImplementation(async () => ({
      kind: 'mongodb',
      client: {
        db: () => ({
          command: async (c: Record<string, unknown>) => {
            seen.push(c)
            throw Object.assign(new Error('stop'), { code: 13 })
          }
        })
      },
      close: async () => {}
    }))
    await dbOps(MONGO_CFG)
    expect(seen.length).toBeGreaterThan(0)
    for (const c of seen) expect(c.maxTimeMS).toBe(8000)
  })

  it('a standalone gets not-applicable for replication and for the oplog, not an error', async () => {
    serveMongo(mongoFixture('standalone'))
    const { answers } = await dbOps(MONGO_CFG)
    expect(statusOf(answers, 'replication')).toBe('not-applicable')
    expect(byId(answers, 'replication').verdict.level).toBe('unknown')
    // FAILS FIRST, with the not-applicable status removed, as:
    //   expected 'ok' to be 'not-applicable' // Object.is equality
    // which is the whole point: an `ok` here is a green tick on a server that
    // keeps no oplog at all.
    expect(statusOf(answers, 'oplog')).toBe('not-applicable')
    expect(byId(answers, 'oplog').verdict.headline).toBe('This server keeps no oplog.')
    // And the rest of the page still answers.
    expect(statusOf(answers, 'connections')).toBe('ok')
    expect(byId(answers, 'overview').verdict.level).toBe('ok')
  })

  it('a down member takes the whole replication answer to alarm', async () => {
    serveMongo(mongoFixture('secondary-down'))
    const { answers } = await dbOps(MONGO_CFG)
    const replication = byId(answers, 'replication')
    expect(replication.status).toBe('ok')
    expect(replication.verdict.level).toBe('alarm')
    expect(replication.verdict.headline).toContain('sp-mongo2:27017')
  })

  it('drops $currentOp to its own operations when the wide form is refused, and labels it', async () => {
    // The fallback this file exists for. Captured: allUsers:true raises 13 and
    // allUsers:false returns ok:1.
    // FAILS FIRST, with the fallback removed, as:
    //   expected [ 'hello', 'buildInfo', …(9) ] to include 'currentOpOwn'
    serveMongo(mongoFixture('unauthorized'))
    const { answers } = await dbOps(MONGO_CFG)
    expect(sentCommands).toContain('currentOp')
    expect(sentCommands).toContain('currentOpOwn')
    const op = byId(answers, 'currentop')
    expect(op.status).toBe('partial')
    expect(op.verdict.level).toBe('unknown')
    expect(op.verdict.because).toMatch(/never treat it as the whole server/)
  })

  it('keeps the sizes answer when $indexStats is refused on the same collection', async () => {
    serveMongo(mongoFixture('unauthorized'))
    const { answers } = await dbOps(MONGO_CFG)
    // $collStats worked, $indexStats did not — captured, same collection.
    // FAILS FIRST, with the per-collection failure recorded as an empty index
    // list rather than as unreadable, as:
    //   expected 'ok' to be 'denied' // Object.is equality
    // and the page then says "All 0 droppable indexes have been used" about a
    // collection it was refused.
    expect(statusOf(answers, 'indexes')).toBe('denied')
    expect(byId(answers, 'indexes').verdict.because).toMatch(/refused on orders/)
    const sizes = byId(answers, 'sizes')
    expect(sizes.status).toBe('partial')
    expect(sizes.verdict.headline).toMatch(/floor, not a total/)
  })

  it('reports a refused serverStatus once, and does not pretend the counters are zero', async () => {
    serveMongo(mongoFixture('unauthorized'))
    const { answers } = await dbOps(MONGO_CFG)
    expect(statusOf(answers, 'overview')).toBe('denied')
    expect(statusOf(answers, 'connections')).toBe('denied')
    expect(statusOf(answers, 'asserts')).toBe('denied')
    expect(byId(answers, 'connections').verdict.level).toBe('unknown')
    // The overview still lands, because `hello` needs no privilege.
    expect(byId(answers, 'overview').verdict.headline).toMatch(/^MongoDB/)
  })

  it('measures the oplog of a rolling member as a real window and a fresh one as a floor', async () => {
    serveMongo(mongoFixture('oplog-saturated'))
    const rolled = byId((await dbOps(MONGO_CFG)).answers, 'oplog')
    expect(rolled.verdict.level).toBe('alarm')

    sentCommands.length = 0
    serveMongo(mongoFixture('replica-set-primary'))
    const fresh = byId((await dbOps(MONGO_CFG)).answers, 'oplog')
    expect(fresh.verdict.level).toBe('unknown')
    expect(fresh.verdict.because).toMatch(/FLOOR/)
  })

  it('asks about the database the operator selected, not about admin', async () => {
    mongoDbName.mockReturnValueOnce('shop')
    serveMongo(mongoFixture('replica-set-primary'))
    await dbOps(MONGO_CFG)
    expect(sentCommands).toContain('listCollections')
    expect(sentCommands).toContain('indexStats:orders')
    expect(sentCommands).toContain('collStats:customers')
  })
})

// ===========================================================================
// Redis
// ===========================================================================

describe('the Redis collector', () => {
  it('answers all nine from the captured master, in order', async () => {
    serveRedis(redisFixture('master'))
    const report = await dbOps(REDIS_CFG)
    expect(report.ok).toBe(true)
    expect(report.engine).toBe('redis')
    expect(report.answers.map((a) => a.id)).toEqual([...REDIS_QUESTIONS])
  })

  it('does not send CLUSTER INFO to an instance that says it has no cluster', async () => {
    // The command errors there — "ERR This instance has cluster support
    // disabled" — and there is no reason to make the server say it.
    // FAILS FIRST, with the cluster_enabled gate removed, as:
    //   expected [ 'infoServer', 'infoCluster', …(11) ] to not include 'clusterInfo'
    serveRedis(redisFixture('master'))
    const { answers } = await dbOps(REDIS_CFG)
    expect(sentCommands).toContain('infoCluster')
    expect(sentCommands).not.toContain('clusterInfo')
    expect(statusOf(answers, 'cluster')).toBe('not-applicable')
    expect(byId(answers, 'cluster').verdict.level).toBe('ok')
  })

  it('collapses an ACL refusal into nine labelled answers, never nine empty ones', async () => {
    // FAILS FIRST, with the tailored headline removed, as:
    //   expected 'Server: this account is not permitted…' to match
    //   /NOT "the server has nothing to report"/
    // The generic refusal is accurate and useless: it names the question
    // instead of the grant, on a page where all nine say the same thing.
    serveRedis(redisFixture('acl-denied'))
    const { answers } = await dbOps(REDIS_CFG)
    expect(answers.map((a) => a.id)).toEqual([...REDIS_QUESTIONS])
    for (const a of answers) {
      expect(a.status, a.id).toBe('denied')
      expect(a.verdict.level, a.id).toBe('unknown')
      expect(a.value, a.id).toBeUndefined()
    }
    expect(byId(answers, 'overview').verdict.headline).toMatch(/NOT "the server has nothing to report"/)
    expect(byId(answers, 'overview').detail).toContain('NOPERM')
    // One INFO refusal is every INFO refusal: it is one command.
    expect(sentCommands).toEqual(['infoServer'])
  })

  it('reports an absent maxmemory as unsupported rather than as no limit', async () => {
    const fx = redisFixture('master')
    fx.infoMemory = { ok: true, reply: '# Memory\r\nused_memory:2384024\r\n' }
    serveRedis(fx)
    const { answers } = await dbOps(REDIS_CFG)
    expect(statusOf(answers, 'memory')).toBe('unsupported')
    expect(byId(answers, 'memory').verdict.level).toBe('unknown')
  })

  it('reports Redis 5’s missing maxclients as unsupported, and still answers the rest', async () => {
    serveRedis(redisFixture('redis-5'))
    const { answers } = await dbOps(REDIS_CFG)
    expect(statusOf(answers, 'clients')).toBe('unsupported')
    expect(byId(answers, 'clients').verdict.because).toMatch(/did not add it until 6\.0/)
    // Everything else on a Redis 5 answers normally.
    expect(statusOf(answers, 'memory')).toBe('ok')
    expect(statusOf(answers, 'keyspace')).toBe('ok')
    expect(byId(answers, 'keyspace').verdict.headline).toBe('This instance holds no keys.')
  })

  it('fetches the slow-log threshold before the entries, and says so when it cannot', async () => {
    serveRedis(redisFixture('master'))
    const { answers } = await dbOps(REDIS_CFG)
    expect(sentCommands.indexOf('configSlowlog')).toBeLessThan(sentCommands.indexOf('slowlogGet'))
    expect(statusOf(answers, 'slowlog')).toBe('ok')

    sentCommands.length = 0
    const fx = redisFixture('master')
    fx.configSlowlog = { ok: false, message: "NOPERM User app has no permissions to run the 'config|get' command" }
    serveRedis(fx)
    const denied = byId((await dbOps(REDIS_CFG)).answers, 'slowlog')
    expect(denied.status).toBe('denied')
    expect(denied.verdict.level).toBe('unknown')
    expect(denied.verdict.because).toMatch(/means "nothing was slow" at 10 ms/)
  })

  it('alarms on a replica whose master has gone', async () => {
    serveRedis(redisFixture('replica-link-down'))
    const { answers } = await dbOps(REDIS_CFG)
    const replication = byId(answers, 'replication')
    expect(replication.status).toBe('ok')
    expect(replication.verdict.level).toBe('alarm')
    expect(replication.verdict.because).toMatch(/not "zero seconds ago"/)
  })

  it('alarms on a full noeviction instance and passes the policy to the keyspace question', async () => {
    serveRedis(redisFixture('memory-full-noeviction'))
    const { answers } = await dbOps(REDIS_CFG)
    expect(byId(answers, 'memory').verdict.level).toBe('alarm')
    // The keyspace judgement needs the policy the memory question read, which
    // is why the two are not independent.
    expect(byId(answers, 'keyspace').verdict.because).toMatch(/nothing will ever remove them/)
  })

  it('closes the connection it opened', async () => {
    serveRedis(redisFixture('master'))
    await dbOps(REDIS_CFG)
    expect(closed.count).toBe(1)
  })
})

// ===========================================================================
// The fixtures are a replay script, so they have to match the script
// ===========================================================================

describe('every shipped MongoDB and Redis command has a captured answer', () => {
  /** Captured, but no command asks for it any more. */
  const EXTRA = new Set<string>([])
  /**
   * Shipped, and no server was available to capture it. Stated in
   * tests/fixtures/dbops/README.md rather than invented.
   *
   * `clusterInfo` is here in its SUCCESS form only: every instance available
   * had cluster mode off, so what is captured is the refusal
   * "ERR This instance has cluster support disabled" — which is a real capture
   * of a real answer, and is not a capture of a cluster.
   */
  const UNCAPTURED = new Set<string>([])

  function files(engine: 'mongodb' | 'redis'): string[] {
    return readdirSync(join(FIXTURES, engine)).filter((f) => f.endsWith('.json'))
  }

  it('mongodb: no fixture key is an orphan', () => {
    const builderKeys = /^(collStats|indexStats):/
    for (const file of files('mongodb')) {
      const fx = mongoFixture(file.replace(/\.json$/, ''))
      for (const key of Object.keys(fx)) {
        if (EXTRA.has(key) || builderKeys.test(key) || key === 'currentOp' || key === 'currentOpOwn') continue
        expect(Object.keys(MONGO_COMMANDS), `${file} has a key no command asks for: ${key}`).toContain(key)
      }
    }
  })

  it('mongodb: every command is covered by at least one fixture', () => {
    const seen = new Set<string>()
    for (const file of files('mongodb')) for (const key of Object.keys(mongoFixture(file.replace(/\.json$/, '')))) seen.add(key)
    for (const key of Object.keys(MONGO_COMMANDS)) {
      if (UNCAPTURED.has(key)) continue
      expect(seen, `mongodb.${key} has no captured answer anywhere`).toContain(key)
    }
    expect(seen).toContain('currentOp')
    expect(seen).toContain('currentOpOwn')
    expect([...seen].some((k) => k.startsWith('collStats:'))).toBe(true)
    expect([...seen].some((k) => k.startsWith('indexStats:'))).toBe(true)
  })

  it('redis: no fixture key is an orphan', () => {
    for (const file of files('redis')) {
      const fx = redisFixture(file.replace(/\.json$/, ''))
      for (const key of Object.keys(fx)) {
        if (key === 'slowlogGet') continue
        expect(Object.keys(REDIS_COMMANDS), `${file} has a key no command asks for: ${key}`).toContain(key)
      }
    }
  })

  it('redis: every command is covered by at least one fixture', () => {
    const seen = new Set<string>()
    for (const file of files('redis')) for (const key of Object.keys(redisFixture(file.replace(/\.json$/, '')))) seen.add(key)
    for (const key of Object.keys(REDIS_COMMANDS)) {
      expect(seen, `redis.${key} has no captured answer anywhere`).toContain(key)
    }
    expect(seen).toContain('slowlogGet')
  })

  it('the gaps are stated in the README rather than left to be discovered', () => {
    const readme = readFileSync(join(FIXTURES, 'README.md'), 'utf8')
    for (const phrase of ['No sharded cluster', 'No Redis Cluster', 'No Redis Sentinel', 'No AOF-enabled Redis', 'mongodb+srv']) {
      expect(readme, `${phrase} is not accounted for in the README`).toContain(phrase)
    }
  })
})
