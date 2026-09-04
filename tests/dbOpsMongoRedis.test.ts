import { describe, expect, it } from 'vitest'
import { readFileSync } from 'node:fs'
import { join, resolve } from 'node:path'
import {
  DB_THRESHOLDS,
  MONGO_COMMANDS,
  MONGO_COMMAND_BUILDERS,
  MONGO_QUESTIONS,
  REDIS_COMMANDS,
  REDIS_COMMAND_BUILDERS,
  REDIS_QUESTIONS,
  classifyMongoFailure,
  classifyRedisFailure,
  dbEventMetrics,
  infoNum,
  isMongoClientOp,
  judgeMongoAsserts,
  judgeMongoConnections,
  judgeMongoCurrentOp,
  judgeMongoIndexes,
  judgeMongoOplog,
  judgeMongoReplication,
  judgeMongoSizes,
  judgeRedisClients,
  judgeRedisCluster,
  judgeRedisKeyspace,
  judgeRedisMemory,
  judgeRedisPersistence,
  judgeRedisReplication,
  judgeRedisSlowlog,
  judgeRedisStats,
  mongoCollStatsCommand,
  mongoCurrentOpCommand,
  mongoIndexStatsCommand,
  mongoTimestampSeconds,
  parseMongoAsserts,
  parseMongoConnections,
  parseMongoCurrentOp,
  parseMongoIndexes,
  parseMongoOplog,
  parseMongoOverview,
  parseMongoReplication,
  parseMongoSizes,
  parseRedisClients,
  parseRedisCluster,
  parseRedisConfig,
  parseRedisInfo,
  parseRedisKeyspace,
  parseRedisMemory,
  parseRedisPersistence,
  parseRedisReplication,
  parseRedisSlowlog,
  parseRedisStats,
  redactMongoCommandEcho,
  redisSlowlogGetCommand
} from '../src/shared/dbOps'

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------
//
// Captured from real containers by the `mongodb` and `ioredis` drivers this app
// ships. See tests/fixtures/dbops/README.md for what each file holds and, more
// importantly, for the list of what could not be captured.
//
// To regenerate, on a machine with docker:
//
//   docker network create spops
//   docker run -d --name sp-mongo1 --network spops -p 57017:27017 mongo:7 --replSet rs0 --bind_ip_all
//   docker run -d --name sp-mongo2 --network spops -p 57018:27017 mongo:7 --replSet rs0 --bind_ip_all
//   docker run -d --name sp-mongo3 --network spops -p 57022:27017 mongo:7 --replSet rs0 --bind_ip_all
//   docker exec sp-mongo1 mongosh --eval 'rs.initiate({_id:"rs0",members:[
//     {_id:0,host:"sp-mongo1:27017"},{_id:1,host:"sp-mongo2:27017"}]})'
//   docker exec sp-mongo1 mongosh --eval 'rs.add("sp-mongo3:27017")'
//   docker run -d --name sp-mongo-solo --network spops -p 57019:27017 mongo:7 --bind_ip_all
//   docker run -d --name sp-mongo-tight --network spops -p 57020:27017 mongo:7 \
//     --replSet rs1 --bind_ip_all --oplogSize 1        # then write ~200 MB of random
//                                                       # documents until it rolls
//   docker run -d --name sp-mongo-auth --network spops -p 57021:27017 \
//     -e MONGO_INITDB_ROOT_USERNAME=root -e MONGO_INITDB_ROOT_PASSWORD=… mongo:7 --bind_ip_all
//   docker run -d --name sp-redis1 --network spops -p 56379:6379 redis:7 \
//     --maxmemory 64mb --maxmemory-policy allkeys-lru --save '60 1'
//   docker run -d --name sp-redis2 --network spops -p 56380:6379 redis:7 --replicaof sp-redis1 6379
//   docker run -d --name sp-redis5 --network spops -p 56382:6379 redis:5
//   docker run -d --name sp-redis-full --network spops -p 56383:6379 redis:7 \
//     --maxmemory 8mb --maxmemory-policy noeviction --save ''
//
// then `docker pause sp-mongo2` for secondary-down.json and `docker stop sp-redis1`
// for replica-link-down.json, and run every command in MONGO_COMMANDS /
// REDIS_COMMANDS through the drivers — NOT through mongosh or redis-cli, which
// hand back different types.

const FIXTURES = resolve(__dirname, 'fixtures/dbops')

interface MongoCapture {
  ok: boolean
  result?: Record<string, unknown>
  name?: string
  code?: number
  codeName?: string
  message?: string
}
interface RedisCapture {
  ok: boolean
  reply?: unknown
  name?: string
  message?: string
}

function mongo(file: string): Record<string, MongoCapture> {
  return JSON.parse(readFileSync(join(FIXTURES, 'mongodb', `${file}.json`), 'utf8'))
}
function redis(file: string): Record<string, RedisCapture> {
  return JSON.parse(readFileSync(join(FIXTURES, 'redis', `${file}.json`), 'utf8'))
}

/** The documents out of a captured cursor reply. */
function batch(cap: MongoCapture | undefined): Record<string, unknown>[] {
  const cursor = cap?.result?.cursor as { firstBatch?: Record<string, unknown>[] } | undefined
  return cursor?.firstBatch ?? []
}

function info(cap: RedisCapture | undefined): ReturnType<typeof parseRedisInfo> {
  return parseRedisInfo(typeof cap?.reply === 'string' ? cap.reply : '')
}

const PRIMARY = mongo('replica-set-primary')
const DOWN = mongo('secondary-down')
const SOLO = mongo('standalone')
const SATURATED = mongo('oplog-saturated')
const UNAUTH = mongo('unauthorized')

const R_MASTER = redis('master')
const R_REPLICA = redis('replica')
const R_LINK_DOWN = redis('replica-link-down')
const R_FULL = redis('memory-full-noeviction')
const R_ACL = redis('acl-denied')
const R_5 = redis('redis-5')

// ===========================================================================
// MongoDB — a member that is down
// ===========================================================================

describe('a MongoDB member that is not reachable', () => {
  // The captured row, in full, eighteen seconds after `docker pause`:
  //   state 8, stateStr "(not reachable/healthy)", health 0,
  //   optimeDate "1970-01-01T00:00:00.000Z", uptime 0, pingMs 0
  // Three of those five read as excellent.
  const value = parseMongoReplication(DOWN.replSetGetStatus.result)
  const dead = value.members.find((m) => m.state === 8)

  it('is in the fixture as state 8 with health 0 — not as an absence', () => {
    expect(DOWN.replSetGetStatus.ok).toBe(true)
    expect(dead).toBeDefined()
    expect(dead?.health).toBe(0)
    expect(dead?.stateStr).toBe('(not reachable/healthy)')
  })

  it('reports NO lag rather than zero, because its optime is the Unix epoch', () => {
    // FAILS FIRST, against a parser that takes optimeDate at face value, as:
    //   expected 1788487961 to be null // Object.is equality
    // 1970 is a valid Date, so the subtraction succeeds and reports this member
    // as 1,788,487,961 seconds — fifty-six years — behind. Which is the SAFE
    // half of the bug: it is loud. The dangerous half is the next commit, where
    // somebody sees "56y behind" on a dashboard, decides a duration cannot be
    // negative or absurd, and clamps it — and every clamp that starts at zero
    // turns a dead member into "0s behind", which is exactly the
    // Seconds_Behind_Source bug 971c47d fixed for MySQL.
    expect(dead?.lagSeconds).toBe(null)
    expect(dead?.optimeMs).toBe(null)
    expect(dead?.optimeIsEpoch).toBe(true)
  })

  it('does not report a round trip of zero milliseconds for a member that did not answer', () => {
    // pingMs is literally 0 in the capture. It is not a fast member.
    expect(DOWN.replSetGetStatus.result?.members).toBeDefined()
    expect(dead?.pingMs).toBe(null)
    expect(dead?.uptimeSeconds).toBe(null)
  })

  it('alarms on the state before it looks at any time at all', () => {
    const verdict = judgeMongoReplication(value)
    expect(verdict.level).toBe('alarm')
    expect(verdict.headline).toContain('sp-mongo2:27017')
    expect(verdict.headline).toContain('(not reachable/healthy)')
    expect(verdict.because).toMatch(/Unix epoch/)
    // And never the word that would make it look fine.
    expect(verdict.headline).not.toMatch(/\b0s behind\b/)
  })

  it('keeps the two healthy members out of the alarm', () => {
    expect(value.healthyCount).toBe(2)
    expect(value.members).toHaveLength(3)
  })

  it('redacts the host names out of the heartbeat message before it is shown or stored', () => {
    // The raw text is 300 characters and reads `… target:[sp-mongo2:27017]
    // db:admin cmd:{ replSetHeartbeat: "rs0", … from: "sp-mongo1:27017" … }`.
    const raw = (DOWN.replSetGetStatus.result?.members as Record<string, unknown>[])[1].lastHeartbeatMessage as string
    expect(raw).toContain('sp-mongo2:27017')
    expect(dead?.heartbeatMessage).not.toContain('sp-mongo2:27017')
    expect(dead?.heartbeatMessage).toContain('<redacted>')
    expect((dead?.heartbeatMessage ?? '').length).toBeLessThanOrEqual(241)
  })

  it('a healthy set does not alarm', () => {
    // Two members here and three in secondary-down.json: the third was added
    // between the captures, and both files are what the server said at the
    // moment it was asked rather than one edited to match the other.
    const healthy = parseMongoReplication(PRIMARY.replSetGetStatus.result)
    expect(healthy.members).toHaveLength(2)
    expect(healthy.members.map((m) => m.stateStr)).toEqual(['PRIMARY', 'SECONDARY'])
    expect(judgeMongoReplication(healthy).level).toBe('ok')
  })

  it('a set with no primary is an alarm even when every member is reachable', () => {
    const all = parseMongoReplication({
      set: 'rs0',
      members: [
        { _id: 0, name: 'a:27017', state: 2, stateStr: 'SECONDARY', health: 1, optimeDate: '2026-09-04T02:00:00.000Z' },
        { _id: 1, name: 'b:27017', state: 2, stateStr: 'SECONDARY', health: 1, optimeDate: '2026-09-04T02:00:00.000Z' }
      ]
    })
    const v = judgeMongoReplication(all)
    expect(v.level).toBe('alarm')
    expect(v.headline).toBe('This replica set has no PRIMARY.')
  })
})

// ===========================================================================
// MongoDB — a standalone
// ===========================================================================

describe('a standalone mongod', () => {
  it('errors on replSetGetStatus rather than answering emptily', () => {
    expect(SOLO.replSetGetStatus.ok).toBe(false)
    expect(SOLO.replSetGetStatus.code).toBe(76)
    expect(SOLO.replSetGetStatus.codeName).toBe('NoReplicationEnabled')
    expect(SOLO.replSetGetStatus.message).toBe('not running with --replSet')
  })

  it('classifies code 76 as not-applicable — not as an error and not as healthy', () => {
    // FAILS FIRST, against a classifier that only knew 13/26/59, as:
    //   expected 'error' to be 'not-applicable' // Object.is equality
    // Reported as `error` the page shows a red box on a server behaving exactly
    // as configured; reported as `ok` with an empty member list it shows a
    // green tick on a server with no replication at all.
    const f = classifyMongoFailure(SOLO.replSetGetStatus.code, SOLO.replSetGetStatus.codeName, SOLO.replSetGetStatus.message ?? '')
    expect(f.status).toBe('not-applicable')
    expect(f.detail).toBe('not running with --replSet')
  })

  it('has no oplog, and its EMPTY find is not a window of zero', () => {
    // The trap under the trap: `find` on local.oplog.rs succeeds with an empty
    // batch and ok: 1 on a standalone. Only $collStats errors.
    expect(SOLO.oplogFirst.ok).toBe(true)
    expect(batch(SOLO.oplogFirst)).toHaveLength(0)
    expect(SOLO.oplogStats.ok).toBe(false)
    expect(SOLO.oplogStats.code).toBe(26)

    const v = parseMongoOplog(batch(SOLO.oplogFirst), batch(SOLO.oplogLast), undefined, 300)
    expect(v.present).toBe(false)
    expect(v.windowSeconds).toBe(null)
    const verdict = judgeMongoOplog(v)
    expect(verdict.level).toBe('unknown')
    expect(verdict.headline).toBe('This server keeps no oplog.')
    expect(verdict.because).toMatch(/not a window of zero/)
  })

  it('is described as a standalone rather than as a replica-set member', () => {
    const o = parseMongoOverview(SOLO.hello.result, SOLO.buildInfo.result, SOLO.serverStatus.result)
    expect(o?.setName).toBe(null)
    expect(o?.role).toBe('standalone')
    expect(o?.isRouter).toBe(false)
    const p = parseMongoOverview(PRIMARY.hello.result, PRIMARY.buildInfo.result, PRIMARY.serverStatus.result)
    expect(p?.setName).toBe('rs0')
    expect(p?.role).toBe('primary')
    expect(p?.memberCount).toBe(2)
  })
})

// ===========================================================================
// MongoDB — the oplog window
// ===========================================================================

describe('an oplog window that is small', () => {
  const ts = (cap: MongoCapture | undefined): number | null => mongoTimestampSeconds(batch(cap)[0]?.ts)

  it('is 472 seconds on a member up for 493 — and 30 on one up for 478', () => {
    // The two numbers this question exists to tell apart. Both are "small".
    const freshWindow = (ts(PRIMARY.oplogLast) ?? 0) - (ts(PRIMARY.oplogFirst) ?? 0)
    const rolledWindow = (ts(SATURATED.oplogLast) ?? 0) - (ts(SATURATED.oplogFirst) ?? 0)
    expect(freshWindow).toBe(472)
    expect(PRIMARY.serverStatus.result?.uptime).toBe(493)
    expect(rolledWindow).toBe(30)
    expect(SATURATED.serverStatus.result?.uptime).toBe(478)
  })

  it('reads as UNKNOWN when it is small because the member is new', () => {
    // FAILS FIRST, against a judge that compares the window with a threshold
    // and nothing else, as:
    //   expected 'alarm' to be 'unknown' // Object.is equality
    // 472 seconds is under an hour, so a fresh replica set alarms the moment it
    // is created and keeps alarming until it has been up for one — on a server
    // that has discarded nothing and whose window is still growing.
    const v = parseMongoOplog(batch(PRIMARY.oplogFirst), batch(PRIMARY.oplogLast), batch(PRIMARY.oplogStats)[0], 493)
    expect(v.windowSeconds).toBe(472)
    expect(v.neverRolled).toBe(true)
    const verdict = judgeMongoOplog(v)
    expect(verdict.level).toBe('unknown')
    expect(verdict.because).toMatch(/FLOOR and not a measurement/)
  })

  it('reads as ALARM when it is small because the oplog is rolling', () => {
    const v = parseMongoOplog(batch(SATURATED.oplogFirst), batch(SATURATED.oplogLast), batch(SATURATED.oplogStats)[0], 478)
    expect(v.windowSeconds).toBe(30)
    expect(v.neverRolled).toBe(false)
    const verdict = judgeMongoOplog(v)
    expect(verdict.level).toBe('alarm')
    expect(verdict.because).toMatch(/entries are being discarded/)
  })

  it('does not decide it from the storage numbers, which say the opposite', () => {
    // The reason the discriminator is uptime. WiredTiger never shrinks a file
    // it has allocated, so the ROLLING oplog reports 225 MB against a
    // configured maximum of 1 MB — 21000% "full" — while the healthy one
    // reports 0.07%. Any judge built on used-against-configured gets both
    // backwards.
    const rolled = batch(SATURATED.oplogStats)[0].storageStats as Record<string, number>
    const fresh = batch(PRIMARY.oplogStats)[0].storageStats as Record<string, number>
    expect(rolled.storageSize).toBeGreaterThan(rolled.maxSize * 200)
    expect(fresh.storageSize).toBeLessThan(fresh.maxSize * 0.01)
  })

  it('a genuinely long window is ok', () => {
    const v = parseMongoOplog([{ ts: { $timestamp: '7681494973912449025' } }], [{ ts: { $timestamp: '7681920000000000000' } }], undefined, 2_000_000)
    expect(v.windowSeconds).toBeGreaterThan(DB_THRESHOLDS.oplogWindowWatchSeconds)
    expect(judgeMongoOplog(v).level).toBe('ok')
  })
})

describe('a BSON timestamp', () => {
  it('reads the seconds out of the decimal-string form every fixture is in', () => {
    // JSON.stringify of a driver Timestamp is { $timestamp: "<64-bit decimal>" },
    // NOT { $timestamp: { t, i } }. A parser that handled only the live shapes
    // would pass against a running server and be tested against nothing.
    // The literal below is the first oplog entry in replica-set-primary.json,
    // and 1788487419 is 2026-09-04T02:03:39Z, which is when rs.initiate() ran.
    expect(mongoTimestampSeconds({ $timestamp: '7681494973912449025' })).toBe(1788487419)
    expect(mongoTimestampSeconds({ $timestamp: { t: 1788487419, i: 1 } })).toBe(1788487419)
    expect(mongoTimestampSeconds({ t: 1788487419, i: 1 })).toBe(1788487419)
    // The driver's own object: a Long with the seconds in the high word.
    expect(mongoTimestampSeconds({ high: 1788487419, low: 1, unsigned: false })).toBe(1788487419)
  })

  it('is null rather than zero for anything it cannot read', () => {
    for (const bad of [null, undefined, 'later', {}, { $timestamp: 'not a number' }]) {
      expect(mongoTimestampSeconds(bad), JSON.stringify(bad)).toBe(null)
    }
  })
})

// ===========================================================================
// MongoDB — running operations
// ===========================================================================

describe('MongoDB running operations', () => {
  const value = parseMongoCurrentOp(batch(PRIMARY.currentOp), false)

  it('holds a real eleven-second client query and the server’s own threads', () => {
    expect(value.operations.length).toBeGreaterThan(4)
    const client = value.operations.filter(isMongoClientOp)
    expect(client).toHaveLength(1)
    expect(client[0].ns).toBe('shop.orders')
    expect(client[0].secondsRunning).toBe(11)
    expect(client[0].planSummary).toBe('COLLSCAN')
  })

  it('does not count the oplog tail as a long-running operation', () => {
    // FAILS FIRST, with BOTH exclusions removed (the namespace rule and the
    // appName rule each catch it on their own), as:
    //   expected false to be true // Object.is equality
    // The OplogFetcher's getmore on local.oplog.rs is a TAILING cursor and has
    // been running for the member's whole uptime by design, so a long-running
    // -operation alarm that does not exclude it fires on every replica set,
    // forever. The same shape as the MySQL applier-thread false positive fixed
    // in 971c47d.
    const fetcher = value.operations.find((o) => o.appName === 'OplogFetcher')
    expect(fetcher).toBeDefined()
    expect(fetcher?.op).toBe('getmore')
    expect(fetcher?.ns).toBe('local.oplog.rs')
    expect(fetcher?.internal).toBe(true)
    expect(isMongoClientOp(fetcher!)).toBe(false)
  })

  it('does not count the journal flusher, the checkpointer or the noop writer', () => {
    for (const desc of ['JournalFlusher', 'Checkpointer', 'NoopWriter']) {
      const t = value.operations.find((o) => o.desc === desc)
      expect(t, desc).toBeDefined()
      expect(t?.op, desc).toBe('none')
      expect(t?.internal, desc).toBe(true)
    }
  })

  it('does not count this panel’s own read', () => {
    const own = value.operations.find((o) => o.ns === 'admin.$cmd.aggregate')
    expect(own).toBeDefined()
    expect(own?.internal).toBe(true)
  })

  it('says so, rather than reporting a smaller truth, when it can only see its own', () => {
    // Captured: $currentOp with allUsers:true raises 13 and allUsers:false
    // returns ok:1 with one row. The fallback is taken because half an answer
    // beats none, and it is labelled.
    expect(UNAUTH.currentOp.ok).toBe(false)
    expect(UNAUTH.currentOp.code).toBe(13)
    expect(UNAUTH.currentOpOwn.ok).toBe(true)
    const own = parseMongoCurrentOp(batch(UNAUTH.currentOpOwn), true)
    const verdict = judgeMongoCurrentOp(own)
    expect(verdict.level).toBe('unknown')
    expect(verdict.because).toMatch(/refused with allUsers: true/)
    expect(verdict.because).toMatch(/never treat it as the whole server/)
  })

  it('alarms on a client operation that has run too long', () => {
    const v = parseMongoCurrentOp([{ desc: 'conn9', op: 'query', ns: 'shop.orders', secs_running: 900, planSummary: 'COLLSCAN' }], false)
    const verdict = judgeMongoCurrentOp(v)
    expect(verdict.level).toBe('alarm')
    expect(verdict.headline).toContain('shop.orders')
    expect(verdict.because).toMatch(/no control here to kill it/)
  })
})

// ===========================================================================
// MongoDB — index usage
// ===========================================================================

describe('MongoDB index usage', () => {
  const rows = batch(PRIMARY['indexStats:orders'])
  const now = Date.parse('2026-09-04T02:11:00.000Z')

  it('holds one index with real accesses and three with none', () => {
    expect(rows.map((r) => (r.accesses as Record<string, unknown>).ops)).toEqual([500, 0, 0, 0])
  })

  it('refuses to call an index unused while the counters are younger than a week', () => {
    // FAILS FIRST, against a judge with no counter-age gate, as:
    //   expected 'watch' to be 'unknown' // Object.is equality
    // and the sentence it produced was "2 of the 3 droppable indexes have had
    // no reads in 7m 2s", on a server whose $indexStats counters were seven
    // minutes old because it had just been restarted. Every index on every
    // freshly restarted server is "unused".
    const v = parseMongoIndexes([{ collection: 'orders', rows }], now)
    expect(v.counterAgeSeconds).toBeLessThan(DB_THRESHOLDS.indexUnusedMinCounterAgeSeconds)
    const verdict = judgeMongoIndexes(v)
    expect(verdict.level).toBe('unknown')
    expect(verdict.because).toMatch(/counts accesses since the server last started/)
  })

  it('reports them once the counters have been running long enough to mean something', () => {
    const old = rows.map((r) => ({ ...r, accesses: { ...(r.accesses as object), since: '2026-07-01T00:00:00.000Z' } }))
    const v = parseMongoIndexes([{ collection: 'orders', rows: old }], now)
    const verdict = judgeMongoIndexes(v)
    expect(verdict.level).toBe('watch')
    // Two, not three: _id_ is excluded from both sides of the ratio because it
    // cannot be dropped, so counting it is a sentence nobody can act on.
    expect(verdict.headline).toMatch(/^2 of the 3 droppable indexes have had no reads/)
    expect(verdict.because).toMatch(/a counter is not a query plan/)
    // _id_ is never reported: it cannot be dropped.
    expect(verdict.because).not.toContain('orders._id_')
  })

  it('says a collection was refused rather than reporting it as having no indexes', () => {
    // $collStats on `orders` succeeded for this role while $indexStats on the
    // SAME collection was denied. Sizes working proves nothing about indexes.
    expect(UNAUTH['collStats:orders'].ok).toBe(true)
    expect(UNAUTH['indexStats:orders'].ok).toBe(false)
    expect(UNAUTH['indexStats:orders'].code).toBe(13)
    const v = parseMongoIndexes([{ collection: 'orders', rows: null }], now)
    expect(v.unreadable).toEqual(['orders'])
    const verdict = judgeMongoIndexes(v)
    expect(verdict.level).toBe('unknown')
    expect(verdict.because).toMatch(/refused on orders/)
  })
})

// ===========================================================================
// MongoDB — sizes, connections, asserts
// ===========================================================================

describe('MongoDB sizes', () => {
  it('reports a filtered listDatabases as a floor, not a total', () => {
    // FAILS FIRST, against a parser that trusts the list it was given, as:
    //   expected false to be true // Object.is equality
    // and the sentence it produced was "40 KB across 1 database(s)" under an
    // `ok` verdict, for a user on a four-database cluster. listDatabases
    // returns ok:1 with no error and no flag; the only signal available is that
    // admin and local, which every mongod has, are not in the list.
    const v = parseMongoSizes(UNAUTH.listDatabases.result, [{ name: 'orders', stats: batch(UNAUTH['collStats:orders'])[0] }])
    expect(v.databases.map((d) => d.name)).toEqual(['shop'])
    expect(v.databasesFiltered).toBe(true)
    const verdict = judgeMongoSizes(v)
    expect(verdict.level).toBe('unknown')
    expect(verdict.headline).toMatch(/that is a floor, not a total/)
    expect(verdict.because).toMatch(/without admin and without local/)
  })

  it('does not flag a full listDatabases', () => {
    const v = parseMongoSizes(PRIMARY.listDatabases.result, [
      { name: 'orders', stats: batch(PRIMARY['collStats:orders'])[0] },
      { name: 'customers', stats: batch(PRIMARY['collStats:customers'])[0] }
    ])
    expect(v.databases.map((d) => d.name).sort()).toEqual(['admin', 'config', 'local', 'shop'])
    expect(v.databasesFiltered).toBe(false)
    expect(judgeMongoSizes(v).level).toBe('ok')
    // Sorted biggest first, so the panel's first row is the one that matters.
    expect(v.collections[0].name).toBe('orders')
    expect(v.collections[0].documents).toBe(20000)
  })
})

describe('MongoDB connections', () => {
  it('computes the ceiling serverStatus never states', () => {
    const v = parseMongoConnections(PRIMARY.serverStatus.result)
    expect(v.current).toBe(16)
    expect(v.available).toBe(307120)
    expect(v.ceiling).toBe(307136)
    expect(judgeMongoConnections(v).level).toBe('ok')
  })

  it('will not judge a count with no ceiling', () => {
    const v = parseMongoConnections({ connections: { current: 40 } })
    expect(v.ceiling).toBe(null)
    const verdict = judgeMongoConnections(v)
    expect(verdict.level).toBe('unknown')
    expect(verdict.because).toMatch(/current \+ available/)
  })

  it('alarms on refusals that have already happened, at any usage', () => {
    const v = parseMongoConnections({ connections: { current: 3, available: 900, rejected: 12 } })
    const verdict = judgeMongoConnections(v)
    expect(verdict.level).toBe('alarm')
    expect(verdict.headline).toMatch(/^12 connections have already been refused/)
  })
})

describe('MongoDB asserts and page faults', () => {
  it('does not report a page-fault count on a platform that does not report one', () => {
    // serverStatus states the hazard itself: extra_info carries
    // note: "fields vary by platform".
    const present = parseMongoAsserts(PRIMARY.serverStatus.result)
    expect(present.pageFaultsReported).toBe(true)
    expect(present.pageFaults).toBe(0)

    const absent = parseMongoAsserts({ uptime: 100, asserts: { regular: 0, user: 5 }, extra_info: { note: 'fields vary by platform' } })
    expect(absent.pageFaultsReported).toBe(false)
    expect(absent.pageFaults).toBe(null)
    expect(judgeMongoAsserts(absent).because).toMatch(/different from a count of zero/)
    // And the metric is omitted rather than written as 0 for whoever alerts.
    expect(dbEventMetrics({ id: 'asserts', status: 'ok', value: absent, verdict: { level: 'ok', headline: '' } })).not.toHaveProperty('pageFaults')
  })

  it('separates a failed client command from the server catching itself', () => {
    const healthy = parseMongoAsserts(PRIMARY.serverStatus.result)
    expect(healthy.user).toBeGreaterThan(0)
    expect(healthy.regular).toBe(0)
    expect(judgeMongoAsserts(healthy).level).toBe('ok')

    const broken = parseMongoAsserts({ uptime: 3600, asserts: { regular: 4, msg: 0, user: 900 }, extra_info: { page_faults: 0 } })
    const verdict = judgeMongoAsserts(broken)
    expect(verdict.level).toBe('alarm')
    expect(verdict.because).toMatch(/not failed client commands/)
  })
})

// ===========================================================================
// Redis — the ACL wall
// ===========================================================================

describe('a Redis instance this account may not read', () => {
  it('refuses every single command, with no partial data and no empty reply', () => {
    // Twelve in REDIS_COMMANDS plus SLOWLOG GET, which is a builder.
    const keys = Object.keys(R_ACL)
    expect(keys).toHaveLength(13)
    expect(Object.keys(REDIS_COMMANDS)).toHaveLength(12)
    for (const k of keys) expect(R_ACL[k].ok, k).toBe(false)
    expect(R_ACL.infoMemory.message).toBe("NOPERM User app has no permissions to run the 'info' command")
  })

  it('is DENIED and never absent, empty or zero', () => {
    // FAILS FIRST, with the NOPERM branch removed, as:
    //   infoServer: expected 'error' to be 'denied' // Object.is equality
    // Redis errors carry no numeric code at all, so a classifier that falls
    // through to `error` for everything it does not recognise puts a red box
    // saying "the command failed" where the answer is "ask for a grant". Worse
    // is the shape one step before that: parseRedisInfo of a NOPERM string
    // yields {}, every infoNum is null, and the page renders a tidy row of
    // dashes that looks like a server with nothing to report.
    for (const k of Object.keys(R_ACL)) {
      expect(classifyRedisFailure(R_ACL[k].message ?? '').status, k).toBe('denied')
    }
    expect(classifyRedisFailure('WRONGPASS invalid username-password pair or user is disabled').status).toBe('denied')
    expect(classifyRedisFailure('NOAUTH Authentication required.').status).toBe('denied')
  })

  it('keeps the server’s own words, so the operator knows which grant to ask for', () => {
    const f = classifyRedisFailure(R_ACL.slowlogGet.message ?? '')
    expect(f.detail).toContain("'slowlog|get'")
  })

  it('does not mistake a disabled feature for a refusal', () => {
    // Same error prefix (ERR), completely different fact, and identical on 5
    // and 7.
    expect(R_MASTER.clusterInfo.message).toBe('ERR This instance has cluster support disabled')
    expect(R_5.clusterInfo.message).toBe('ERR This instance has cluster support disabled')
    expect(classifyRedisFailure(R_MASTER.clusterInfo.message ?? '').status).toBe('absent')
  })
})

// ===========================================================================
// Redis — memory
// ===========================================================================

describe('Redis maxmemory', () => {
  it('reads 0 as unlimited, because that is what Redis means by it', () => {
    const v = parseRedisMemory(info(R_REPLICA.infoMemory))
    expect(v.maxmemoryReported).toBe(true)
    expect(v.maxmemoryBytes).toBe(0)
    expect(v.policy).toBe('noeviction')
    // Never a fraction of zero: 0/0 is NaN and renders as "NaN%".
    expect(v.usedFraction).toBe(null)
    const verdict = judgeRedisMemory(v)
    expect(verdict.level).toBe('watch')
    expect(verdict.headline).toMatch(/with NO memory limit set/)
    expect(verdict.because).toMatch(/a real answer and not a missing one/)
  })

  it('reads an ABSENT maxmemory as unknown, which is a different thing entirely', () => {
    // FAILS FIRST, against a reader built on `Number(fields.maxmemory) || 0`,
    // as:
    //   expected +0 to be null // Object.is equality
    // which then renders as "with NO memory limit set" — turning "this server
    // did not say" into "somebody decided not to set one". The same sentence on
    // screen, opposite facts.
    const v = parseRedisMemory(parseRedisInfo('# Memory\r\nused_memory:2384024\r\n'))
    expect(v.maxmemoryBytes).toBe(null)
    expect(v.maxmemoryReported).toBe(false)
    expect(v.usedBytes).toBe(2384024)
    const verdict = judgeRedisMemory(v)
    expect(verdict.level).toBe('unknown')
    expect(verdict.because).toMatch(/NOT the same as maxmemory being zero/)
  })

  it('alarms on a full instance under noeviction, because that is a write outage', () => {
    const v = parseRedisMemory(info(R_FULL.infoMemory))
    expect(v.usedBytes).toBe(35956376)
    expect(v.maxmemoryBytes).toBe(8388608)
    expect(v.policy).toBe('noeviction')
    const verdict = judgeRedisMemory(v)
    expect(verdict.level).toBe('alarm')
    expect(verdict.because).toMatch(/OOM command not allowed/)
    expect(verdict.because).toMatch(/reads carry on looking healthy/)
  })

  it('is calm about a master well under an eviction policy', () => {
    const v = parseRedisMemory(info(R_MASTER.infoMemory))
    expect(v.policy).toBe('allkeys-lru')
    expect(v.maxmemoryBytes).toBe(67108864)
    expect(judgeRedisMemory(v).level).toBe('ok')
  })
})

// ===========================================================================
// Redis — replication
// ===========================================================================

describe('Redis replication', () => {
  it('will not call a master with no replicas healthy OR broken, because INFO cannot say', () => {
    const v = parseRedisReplication(info(R_MASTER.infoReplication))
    expect(v.role).toBe('master')
    expect(v.connectedReplicas).toBe(1)

    const alone = parseRedisReplication(parseRedisInfo('# Replication\r\nrole:master\r\nconnected_slaves:0\r\n'))
    const verdict = judgeRedisReplication(alone)
    expect(verdict.level).toBe('unknown')
    expect(verdict.because).toMatch(/A standalone Redis reports exactly this line/)
    expect(verdict.because).toMatch(/does not read a Sentinel/)
  })

  it('parses the slave0 line, which has its own key=value grammar inside one field', () => {
    const v = parseRedisReplication(info(R_MASTER.infoReplication))
    expect(v.replicas).toHaveLength(1)
    expect(v.replicas[0].state).toBe('online')
    expect(v.replicas[0].port).toBe(6379)
    expect(v.replicas[0].lagSeconds).toBe(0)
    expect(judgeRedisReplication(v).level).toBe('ok')
  })

  it('does not report -1 seconds since the last IO as zero seconds since the last IO', () => {
    // FAILS FIRST, against a parser that carries the number through, as:
    //   expected -1 to be null // Object.is equality
    // and with the clamp any reviewer would then ask for — Math.max(0, …)
    // around a duration — the panel says "last heard from 0s ago" on a replica
    // that has heard nothing at all. The Seconds_Behind_Source: 0 trap, in
    // Redis.
    const raw = info(R_LINK_DOWN.infoReplication)
    expect(infoNum(raw, 'master_last_io_seconds_ago')).toBe(-1)

    const v = parseRedisReplication(raw)
    expect(v.masterLinkStatus).toBe('down')
    expect(v.masterLastIoSentinel).toBe(true)
    expect(v.masterLastIoSeconds).toBe(null)
    expect(v.linkDownSeconds).toBe(13)

    const verdict = judgeRedisReplication(v)
    expect(verdict.level).toBe('alarm')
    expect(verdict.headline).toMatch(/^This replica has LOST its master/)
    expect(verdict.because).toMatch(/it is not "zero seconds ago"/)
  })

  it('a healthy replica reports its link and says what it cannot measure', () => {
    const v = parseRedisReplication(info(R_REPLICA.infoReplication))
    expect(v.role).toBe('slave')
    expect(v.masterLinkStatus).toBe('up')
    const verdict = judgeRedisReplication(v)
    expect(verdict.level).toBe('ok')
    expect(verdict.because).toMatch(/only reports its own offset/)
  })
})

// ===========================================================================
// Redis — the slow log
// ===========================================================================

describe('the Redis slow log', () => {
  const config = parseRedisConfig(R_MASTER.configSlowlog.reply)

  it('reads CONFIG GET as a pair list, because the order is not stable across versions', () => {
    // Redis 7 answers [slowlog-max-len, …, slowlog-log-slower-than, …];
    // Redis 5 answers them the other way round. Both captured.
    expect(R_MASTER.configSlowlog.reply).toEqual(['slowlog-max-len', '128', 'slowlog-log-slower-than', '10000'])
    expect(R_5.configSlowlog.reply).toEqual(['slowlog-log-slower-than', '10000', 'slowlog-max-len', '128'])
    expect(config).toEqual({ 'slowlog-max-len': '128', 'slowlog-log-slower-than': '10000' })
    expect(parseRedisConfig(R_5.configSlowlog.reply)).toEqual(config)
  })

  it('reports the slowest real command with its threshold beside it', () => {
    const v = parseRedisSlowlog(R_MASTER.slowlogGet.reply, config, R_MASTER.slowlogLen.reply as number)
    expect(v.thresholdMicroseconds).toBe(10000)
    expect(v.maxLength).toBe(128)
    expect(v.entries).toHaveLength(2)
    expect(v.entries[0].command).toBe('EVAL')
    expect(v.entries[1].command).toBe('KEYS')
    expect(v.entries[0].microseconds).toBe(384144)
    const verdict = judgeRedisSlowlog(v)
    expect(verdict.level).toBe('watch')
    expect(verdict.headline).toMatch(/against a 10 ms threshold/)
  })

  it('does not keep the argument values, which are somebody’s data', () => {
    // The captured EVAL entry's argv[1] is a 90-character Lua script; on a real
    // server it is `SET session:8f2… <token>`. This panel's output is shown AND
    // written into the durable event store.
    const raw = (R_MASTER.slowlogGet.reply as unknown[][])[1]
    expect((raw[3] as string[])[1]).toContain('redis.call')
    const v = parseRedisSlowlog(R_MASTER.slowlogGet.reply, config, 2)
    expect(JSON.stringify(v)).not.toContain('redis.call')
    expect(v.entries[0].argumentCount).toBe(2)
  })

  it('redacts the client address', () => {
    const v = parseRedisSlowlog([[1, 1788488203, 69229, ['KEYS', 'tmp:*'], '192.168.65.1:36134', '']], config, 1)
    expect(v.entries[0].clientAddr).toBe('<redacted>:36134')
  })

  it('refuses to read an empty log as good news when the log is switched off', () => {
    // FAILS FIRST, with the negative-threshold branch removed, as:
    //   expected 'ok' to be 'unknown' // Object.is equality
    // and the headline it produced was "Nothing has taken longer than -1 ms
    // since the log was last reset". A negative threshold disables the log
    // entirely, so an empty log is not evidence of anything at all.
    const off = parseRedisSlowlog([], { 'slowlog-log-slower-than': '-1', 'slowlog-max-len': '128' }, 0)
    const verdict = judgeRedisSlowlog(off)
    expect(verdict.level).toBe('unknown')
    expect(verdict.headline).toMatch(/switched OFF/)
  })

  it('says so when the threshold is 0 and the log is therefore this panel looking at itself', () => {
    // FAILS FIRST, with the zero-threshold branch removed, as:
    //   expected 'ok' to be 'unknown' // Object.is equality
    const noisy = parseRedisSlowlog([], { 'slowlog-log-slower-than': '0' }, 128)
    const verdict = judgeRedisSlowlog(noisy)
    expect(verdict.level).toBe('unknown')
    expect(verdict.because).toMatch(/this panel’s own reads/)
  })

  it('cannot interpret the log at all without the threshold', () => {
    const blind = parseRedisSlowlog([], {}, 0)
    expect(blind.thresholdMicroseconds).toBe(null)
    expect(judgeRedisSlowlog(blind).level).toBe('unknown')
  })
})

// ===========================================================================
// Redis — clients, keyspace, stats, cluster
// ===========================================================================

describe('Redis clients', () => {
  it('has no maxclients at all on Redis 5, and says so rather than inventing a ceiling', () => {
    // FAILS FIRST, against `Number(fields.maxclients) || 0`, as:
    //   expected +0 to be null // Object.is equality
    // which then renders as "1 of 0 clients connected" with an Infinity
    // fraction. The field is genuinely absent from INFO clients before Redis 6;
    // redis-5.json is the evidence rather than the assumption.
    const five = info(R_5.infoClients)
    expect(Object.keys(five.fields)).not.toContain('maxclients')
    const v = parseRedisClients(five)
    expect(v.maxclients).toBe(null)
    expect(v.maxclientsReported).toBe(false)
    expect(v.connected).toBe(1)
    expect(v.usedFraction).toBe(null)
    const verdict = judgeRedisClients(v)
    expect(verdict.level).toBe('unknown')
    expect(verdict.because).toMatch(/did not add it until 6\.0/)
  })

  it('judges against the ceiling when there is one', () => {
    const v = parseRedisClients(info(R_MASTER.infoClients))
    expect(v.maxclients).toBe(10000)
    expect(judgeRedisClients(v).level).toBe('ok')

    const busy = parseRedisClients(parseRedisInfo('# Clients\r\nconnected_clients:9600\r\nmaxclients:10000\r\nblocked_clients:0\r\n'))
    const verdict = judgeRedisClients(busy)
    expect(verdict.level).toBe('alarm')
    expect(verdict.because).toMatch(/rejected_connections/)
  })
})

describe('Redis keyspace', () => {
  it('treats an omitted database as a genuine zero, which is the one place absence is', () => {
    const empty = parseRedisKeyspace(info(R_5.infoKeyspace), 0)
    expect(R_5.infoKeyspace.reply).toBe('# Keyspace\r\n')
    expect(empty.databases).toHaveLength(0)
    expect(empty.totalKeys).toBe(0)
    const verdict = judgeRedisKeyspace(empty, 'noeviction')
    expect(verdict.level).toBe('ok')
    expect(verdict.because).toMatch(/unlike an absent field anywhere else on this page/)
  })

  it('reads the db0 line’s own key=value grammar', () => {
    const v = parseRedisKeyspace(info(R_MASTER.infoKeyspace), R_MASTER.dbsize.reply as number)
    expect(v.databases).toHaveLength(1)
    expect(v.databases[0].name).toBe('db0')
    expect(v.databases[0].keys).toBe(305800)
    expect(v.databases[0].avgTtlMs).toBe(2842971)
    expect(v.databases[0].expires).toBe(800)
    expect(v.selectedDbKeys).toBe(305800)
  })

  it('names the combination that fills an instance: no TTL under noeviction', () => {
    const v = parseRedisKeyspace(parseRedisInfo('# Keyspace\r\ndb0:keys=1000000,expires=0,avg_ttl=0\r\n'), 1000000)
    expect(judgeRedisKeyspace(v, 'allkeys-lru').level).toBe('ok')
    const verdict = judgeRedisKeyspace(v, 'noeviction')
    expect(verdict.level).toBe('watch')
    expect(verdict.because).toMatch(/nothing will ever remove them/)
  })

  it('is unknown when INFO keyspace never arrived, rather than reporting no keys', () => {
    const v = parseRedisKeyspace(parseRedisInfo(''), null)
    expect(v.totalKeys).toBe(null)
    expect(judgeRedisKeyspace(v, null).level).toBe('unknown')
  })
})

describe('Redis stats', () => {
  it('alarms on connections Redis refused, which nothing else on the page records', () => {
    const v = parseRedisStats(parseRedisInfo('# Stats\r\nrejected_connections:41\r\nevicted_keys:0\r\n'))
    const verdict = judgeRedisStats(v)
    expect(verdict.level).toBe('alarm')
    expect(verdict.headline).toMatch(/^41 connections have been REFUSED/)
  })

  it('separates a key that expired from a key that was thrown away', () => {
    const v = parseRedisStats(parseRedisInfo('# Stats\r\nrejected_connections:0\r\nevicted_keys:900\r\nexpired_keys:12\r\n'))
    const verdict = judgeRedisStats(v)
    expect(verdict.level).toBe('watch')
    expect(verdict.because).toMatch(/silent data loss/)
  })

  it('is calm on the captured master', () => {
    const v = parseRedisStats(info(R_MASTER.infoStats))
    expect(v.rejectedConnections).toBe(0)
    expect(v.evictedKeys).toBe(0)
    expect(judgeRedisStats(v).level).toBe('ok')
  })
})

describe('Redis cluster', () => {
  it('is not-a-problem rather than a failure on an instance with cluster mode off', () => {
    const v = parseRedisCluster(info(R_MASTER.infoCluster), null)
    expect(v.enabled).toBe(false)
    const verdict = judgeRedisCluster(v)
    expect(verdict.level).toBe('ok')
    expect(verdict.because).toMatch(/a fact rather than a failure/)
  })

  it('alarms on an incomplete slot map — UNPROVEN, no real cluster was available', () => {
    // Stated rather than implied: every captured instance has
    // cluster_enabled: 0, so this arithmetic has never met a real cluster. See
    // tests/fixtures/dbops/README.md.
    const v = parseRedisCluster(parseRedisInfo('# Cluster\r\ncluster_enabled:1\r\n'), parseRedisInfo('cluster_state:ok\r\ncluster_slots_assigned:10923\r\ncluster_known_nodes:4\r\n'))
    const verdict = judgeRedisCluster(v)
    expect(verdict.level).toBe('alarm')
    expect(verdict.headline).toMatch(/10,923 of 16384 hash slots/)
  })

  it('alarms on a state that is not ok', () => {
    const v = parseRedisCluster(parseRedisInfo('# Cluster\r\ncluster_enabled:1\r\n'), parseRedisInfo('cluster_state:fail\r\ncluster_slots_assigned:16384\r\n'))
    expect(judgeRedisCluster(v).level).toBe('alarm')
  })
})

describe('Redis persistence', () => {
  it('alarms when the last background save failed', () => {
    const v = parseRedisPersistence(parseRedisInfo('# Persistence\r\nloading:0\r\naof_enabled:0\r\nrdb_last_bgsave_status:err\r\nrdb_last_save_time:1788487441\r\n'), 1788487441000)
    const verdict = judgeRedisPersistence(v)
    expect(verdict.level).toBe('alarm')
    expect(verdict.because).toMatch(/no current snapshot on disk/)
  })

  it('says how much a restart would lose when the RDB is stale and changes are pending', () => {
    // Read out of the fixture rather than hard-coded, so a re-recording moves
    // the clock and not the assertion.
    const saved = Number(/rdb_last_save_time:(\d+)/.exec(String(R_MASTER.infoPersistence.reply))![1])
    const v = parseRedisPersistence(info(R_MASTER.infoPersistence), (saved + 90_000) * 1000)
    expect(v.aofEnabled).toBe(false)
    expect(v.rdbLastSaveAgeSeconds).toBe(90_000)
    const stale = { ...v, rdbChangesSinceLastSave: 5000 }
    const verdict = judgeRedisPersistence(stale)
    expect(verdict.level).toBe('alarm')
    expect(verdict.because).toMatch(/exists only in memory/)
  })

  it('is calm on a master that has just saved', () => {
    const saved = Number(/rdb_last_save_time:(\d+)/.exec(String(R_MASTER.infoPersistence.reply))![1])
    const v = parseRedisPersistence(info(R_MASTER.infoPersistence), (saved + 60) * 1000)
    expect(v.rdbChangesSinceLastSave).toBe(0)
    expect(judgeRedisPersistence(v).level).toBe('ok')
  })
})

// ===========================================================================
// The INFO parser itself
// ===========================================================================

describe('parseRedisInfo', () => {
  it('strips the carriage return Redis sends, which no log would show you', () => {
    const parsed = parseRedisInfo('# Memory\r\nmaxmemory_policy:noeviction\r\nmaxmemory:0\r\n')
    expect(parsed.fields.maxmemory_policy).toBe('noeviction')
    expect(parsed.fields.maxmemory_policy).not.toContain('\r')
    expect(parsed.sections).toEqual(['Memory'])
  })

  it('splits on the FIRST colon only, so structured values survive', () => {
    const parsed = parseRedisInfo('# Replication\r\nslave0:ip=172.23.0.6,port=6379,state=online,offset=226642,lag=0\r\nmaster_replid:cc98cf7e07\r\n')
    expect(parsed.fields.slave0).toBe('ip=172.23.0.6,port=6379,state=online,offset=226642,lag=0')
    expect(parsed.fields.master_replid).toBe('cc98cf7e07')
  })

  it('distinguishes a field that is absent from a field that is zero', () => {
    const parsed = parseRedisInfo('# Memory\r\nmaxmemory:0\r\n')
    expect(infoNum(parsed, 'maxmemory')).toBe(0)
    expect(infoNum(parsed, 'maxclients')).toBe(null)
  })

  it('reads every section of a real reply', () => {
    const merged = info(R_MASTER.infoMemory)
    expect(merged.sections).toEqual(['Memory'])
    expect(Object.keys(merged.fields).length).toBeGreaterThan(40)
  })
})

// ===========================================================================
// Read-only, and the commands that take a parameter
// ===========================================================================

describe('nothing here changes the server', () => {
  const source = readFileSync(resolve(__dirname, '../src/shared/dbOps.ts'), 'utf8')

  it('sends no Redis command that writes, kills, flushes or reconfigures', () => {
    const forbidden = /\b(SET|FLUSHDB|FLUSHALL|DEBUG|SHUTDOWN|KILL|RESET|RESETSTAT|BGSAVE|BGREWRITEAOF|REPLICAOF|SLAVEOF|FAILOVER|FORGET|MIGRATE|DEL|EXPIRE|RENAME|SCRIPT|FUNCTION)\b/i
    for (const [name, argv] of Object.entries(REDIS_COMMANDS)) {
      for (const word of argv) expect(word, `${name}: ${argv.join(' ')}`).not.toMatch(forbidden)
    }
    for (const build of REDIS_COMMAND_BUILDERS) {
      for (const word of build()) expect(word).not.toMatch(forbidden)
    }
  })

  it('sends CONFIG GET and never CONFIG SET', () => {
    // CONFIG is one word away from the most destructive thing on the list, so
    // the one place it appears is asserted rather than assumed.
    const configs = Object.values(REDIS_COMMANDS).filter((argv) => argv[0] === 'CONFIG')
    expect(configs).toHaveLength(1)
    expect(configs[0]).toEqual(['CONFIG', 'GET', 'slowlog-*'])
  })

  it('never sends KEYS or SCAN, which are reads and are still an outage', () => {
    for (const argv of Object.values(REDIS_COMMANDS)) {
      expect(argv[0]).not.toBe('KEYS')
      expect(argv[0]).not.toBe('SCAN')
    }
    expect(REDIS_COMMANDS.dbsize).toEqual(['DBSIZE'])
  })

  it('sends no MongoDB command that writes, kills or reconfigures', () => {
    const forbidden = /"(killOp|drop|dropDatabase|dropIndexes|createIndexes|compact|insert|update|delete|findAndModify|replSetStepDown|replSetReconfig|replSetFreeze|fsync|shutdown|renameCollection|create)"/
    for (const [name, spec] of Object.entries(MONGO_COMMANDS)) {
      expect(JSON.stringify(spec.command), name).not.toMatch(forbidden)
    }
    for (const build of MONGO_COMMAND_BUILDERS) {
      expect(JSON.stringify(build())).not.toMatch(forbidden)
    }
  })

  it('runs every fixed MongoDB command against admin or local, never a user database', () => {
    for (const [name, spec] of Object.entries(MONGO_COMMANDS)) {
      if (name === 'listCollections') {
        // The one that follows the operator's selection.
        expect(spec.db).toBe(null)
        continue
      }
      expect(['admin', 'local'], name).toContain(spec.db)
    }
  })

  it('does not ask $currentOp for the command document, which is somebody’s query', () => {
    const projected = mongoCurrentOpCommand(20, true)
    const stage = (projected.pipeline as Record<string, unknown>[])[1].$project as Record<string, number>
    expect(stage).not.toHaveProperty('command')
    expect(stage).not.toHaveProperty('clientMetadata')
    expect(stage).not.toHaveProperty('originatingCommand')
    expect(stage).toHaveProperty('secs_running')
  })

  it('the refusal to ship destructive controls is written down', () => {
    expect(source).toMatch(/killOp/)
    expect(source).toMatch(/CONFIG SET/)
    expect(source).toMatch(/FLUSHDB/)
    expect(source).toMatch(/replSetStepDown/)
    expect(source).toMatch(/`KEYS` and `SCAN`/)
  })
})

describe('the four commands that take a parameter', () => {
  it('builds them from a real collection name', () => {
    expect(mongoCollStatsCommand('orders').aggregate).toBe('orders')
    expect(mongoIndexStatsCommand('orders').aggregate).toBe('orders')
    expect(redisSlowlogGetCommand(20)).toEqual(['SLOWLOG', 'GET', '20'])
    expect((mongoCurrentOpCommand(20, false).pipeline as Record<string, unknown>[])[3]).toEqual({ $limit: 20 })
  })

  it('throws rather than sanitising anything that is not one', () => {
    for (const bad of ['', 'a$b', 'x\0y', 'x'.repeat(201), 42, null, undefined, {}]) {
      expect(() => mongoCollStatsCommand(bad as string), JSON.stringify(bad)).toThrow(/Refusing to build a command/)
      expect(() => mongoIndexStatsCommand(bad as string), JSON.stringify(bad)).toThrow(/Refusing to build a command/)
    }
    for (const bad of [0, -1, 1.5, 1001, NaN, '20', null, undefined]) {
      expect(() => redisSlowlogGetCommand(bad as number), JSON.stringify(bad)).toThrow(/Refusing to build SLOWLOG GET/)
      expect(() => mongoCurrentOpCommand(bad as number, true), JSON.stringify(bad)).toThrow(/Refusing to build a command/)
    }
  })
})

describe('MongoDB error text', () => {
  it('keeps the answer and drops the statement the server echoed back at us', () => {
    // The real message is 200+ characters and re-prints the command we sent,
    // including an lsid UUID, into a durable event store.
    const raw = UNAUTH.replSetGetStatus.message ?? ''
    expect(raw).toContain('lsid')
    const f = classifyMongoFailure(13, 'Unauthorized', raw)
    expect(f.status).toBe('denied')
    expect(f.detail).toBe('not authorized on admin to execute command { replSetGetStatus: … }')
    expect(f.detail).not.toContain('lsid')
  })

  it('leaves a message with no echo alone', () => {
    expect(redactMongoCommandEcho('not running with --replSet')).toBe('not running with --replSet')
  })

  it('classifies the codes that were actually captured', () => {
    expect(classifyMongoFailure(13, 'Unauthorized', 'x').status).toBe('denied')
    expect(classifyMongoFailure(26, 'NamespaceNotFound', 'x').status).toBe('absent')
    expect(classifyMongoFailure(76, 'NoReplicationEnabled', 'x').status).toBe('not-applicable')
    expect(classifyMongoFailure(59, 'CommandNotFound', 'x').status).toBe('unsupported')
    expect(classifyMongoFailure(undefined, undefined, 'something else entirely').status).toBe('error')
  })
})

// ===========================================================================
// The question lists
// ===========================================================================

describe('the questions', () => {
  it('are eight for MongoDB and nine for Redis, with the ninth explained in the source', () => {
    expect(MONGO_QUESTIONS).toHaveLength(8)
    expect(REDIS_QUESTIONS).toHaveLength(9)
    expect(new Set(MONGO_QUESTIONS).size).toBe(8)
    expect(new Set(REDIS_QUESTIONS).size).toBe(9)
  })

  it('carry the numbers a rule would need, and omit the ones nobody measured', () => {
    const oplog = parseMongoOplog(batch(SATURATED.oplogFirst), batch(SATURATED.oplogLast), batch(SATURATED.oplogStats)[0], 478)
    const m = dbEventMetrics({ id: 'oplog', status: 'ok', value: oplog, verdict: { level: 'alarm', headline: '' } })
    expect(m.windowSeconds).toBe(30)
    expect(m.neverRolled).toBe(0)

    // maxmemory omitted when the server never reported one, so a rule of the
    // shape "alert when maxmemory is 0" cannot fire on a server that did not say.
    const blind = parseRedisMemory(parseRedisInfo('# Memory\r\nused_memory:100\r\n'))
    // `status: 'ok'` — the INFO command was READ; `maxmemory` simply was not in
    // what it returned. `unknown` is a member of the verdict's level, not of
    // `DbAnswerStatus`, and the two were being conflated here. `dbEventMetrics`
    // reads only `id` and `value`, so this changes nothing but the claim.
    const mm = dbEventMetrics({ id: 'memory', status: 'ok', value: blind, verdict: { level: 'unknown', headline: '' } })
    expect(mm).not.toHaveProperty('maxmemoryBytes')
    expect(mm.usedBytes).toBe(100)
  })

  it('report a down Redis link as linkUp 0 rather than as a lag nobody measured', () => {
    const v = parseRedisReplication(info(R_LINK_DOWN.infoReplication))
    const m = dbEventMetrics({ id: 'replication', status: 'ok', value: v, verdict: { level: 'alarm', headline: '' } })
    expect(m.linkUp).toBe(0)
    expect(m.linkDownSeconds).toBe(13)
    expect(m).not.toHaveProperty('masterLastIoSeconds')
  })
})
