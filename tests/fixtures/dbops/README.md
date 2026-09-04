# Database operations fixtures (roadmap item 18)

## Provenance

Every file here was **captured from a real server**, running in a container on the
machine that wrote the parser, by the `pg` and `mysql2` drivers this app ships — not
by `psql`/`mysql` and not by hand. That matters: the drivers are what the collector
actually sees, and they are where the types get interesting (`pg` returns `bigint`
and `numeric` as strings, `mysql2` returns `SHOW STATUS` values as strings and
`Seconds_Behind_Source` as a number *or* `null`). A fixture recorded through a CLI
would have lost exactly the distinction the parser exists to preserve.

**Nothing in this directory is reconstructed.** Where a case is not covered, the gap
is stated below rather than filled with an invention — the rule
`tests/fixtures/docker/README.md` sets out, for the same reason: a fixture written
from documentation agrees with whatever the author believed the format was.

Each file is `{ statementKey: { ok, rows } | { ok: false, code, errno, message } }`,
one entry per statement in `PG_QUERIES` / `MYSQL_QUERIES`, **keyed by the query's
own name**. An entry may also carry a `q` field recording the exact text that was
run, where it differed from the shipped constant.

That correspondence is now asserted, in `tests/dbOpsCollector.test.ts`, in both
directions: no fixture key that no statement asks for, and no statement without a
captured answer. Before that assertion existed the keys had drifted
(`binlogEnabled` for `logBin`, `binlogExpire8` for `binlogExpireSeconds`,
`bufferPoolSize` for `bufferPool`) while this file claimed one entry per statement,
so renaming a query silently lost its fixture. The keys were renamed to match; the
captured data is untouched.

`tests/dbOpsCollector.test.ts` replays these files through the real collector in
`src/main/services/dbOps.ts` with a fake driver, which is what finally drives the
fallbacks `mariadb-10.4.json` was captured for.

### PostgreSQL — `postgres:16` (server 16.15, Debian, aarch64)

A primary with `archive_mode=on` and a deliberately failing `archive_command`
(`/bin/false`), `shared_preload_libraries=pg_stat_statements`, and a streaming
standby built from it with `pg_basebackup -R`.

| File | Captured from |
|---|---|
| `primary.json` | The primary, as `postgres` (superuser). Contains a **real streaming `pg_stat_replication` row** from the standby, and a **real archiver outage**: `failed_count: 28`, `last_archived_wal: null`. |
| `standby.json` | The standby, as `postgres`. `pg_stat_replication` is **empty** — a standby does not appear in its own copy of that view — and `pg_last_xact_replay_timestamp()` is **NULL** on a standby that has replayed nothing since it started. |
| `unprivileged.json` | The primary, as a plain `LOGIN` role with no grants. The one that changed the design: `pg_stat_replication` returns a **row per walsender with `state` and every lag column NULL**, and no error. `pg_stat_statements` returns real timings with every `query` replaced by `<insufficient privilege>`. |
| `blocking-locks.json` | The primary, with two sessions genuinely contending on one row: a real `pg_blocking_pids()` result and a real `idle in transaction` state. |
| `no-pg-stat-statements.json` | A database in the same cluster where the extension was never created. `pg_extension` is empty; the view raises SQLSTATE `42P01`. Only those two statements were run there, so a replay of this file takes its `overview` from `primary.json` — the same cluster, a different database. |

### MySQL — `mysql:8.0` (server 8.0.46)

A GTID source with binary logging and the slow log on, and a replica of it.

| File | Captured from |
|---|---|
| `source.json` | The source, as `root`. `SHOW REPLICA STATUS` and `SHOW SLAVE STATUS` both return an **empty result set**, not an error. |
| `replica-healthy.json` | The replica, streaming. Shows that MySQL 8.0.46 answers **both** statements with **different column names** (`Replica_IO_Running` vs `Slave_IO_Running`, `Seconds_Behind_Source` vs `Seconds_Behind_Master`). |
| `replica-io-thread-stopped.json` | After `STOP REPLICA IO_THREAD`. **`Seconds_Behind_Source: null`**, `Replica_IO_Running: "No"`, and `Last_IO_Errno: 0` with an **empty** `Last_IO_Error` — replication broken with no error text at all. |
| `replica-source-unreachable.json` | After pointing the replica at a hostname that does not resolve. **`Seconds_Behind_Source: 0`** with `Replica_IO_Running: "No"` and `Last_IO_Errno: 2005`. A dead replica reporting *zero* seconds behind — the inverse of the NULL trap, and the reason the running-thread check comes first. |
| `unprivileged.json` | The source, as an application user with only `SELECT` on one schema. `SHOW REPLICA STATUS` and `SHOW BINARY LOGS` fail with **errno 1227**; `information_schema.PROCESSLIST` **silently returns only that user's own connections** — one row where `root` saw three, with no error and no warning. |

### MariaDB — `mariadb:10.4` (server 10.4.34)

| File | Captured from |
|---|---|
| `mariadb-10.4.json` | A default MariaDB 10.4. `SHOW REPLICA STATUS` fails with **ER_PARSE_ERROR 1064** (the statement does not exist in this dialect) while `SHOW SLAVE STATUS` works; `@@binlog_expire_logs_seconds` fails with **ER_UNKNOWN_SYSTEM_VARIABLE 1193** while `@@expire_logs_days` works; and `SHOW BINARY LOGS` with the binlog off fails with **ER_NO_BINARY_LOGGING 1381** rather than returning an empty list. |

### MongoDB — `mongo:7` (server 7.0.40, Ubuntu 22.04, aarch64)

A three-member replica set `rs0` (`sp-mongo1`/`sp-mongo2`/`sp-mongo3`), a standalone
`mongod` with no `--replSet`, a single-member set with `--oplogSize 1` written hard
enough to make its oplog roll, and a `--auth` server with a `read`-on-one-database
user. Every capture went through the `mongodb` driver this app ships, over a
`directConnection=true` client so each member answers for **itself** rather than for
whichever node the topology picked.

Each file is `{ commandKey: { ok: true, result } | { ok: false, name, code, codeName, message } }`,
one entry per command in `MONGO_COMMANDS`, plus `currentOp` / `currentOpOwn` from the
`mongoCurrentOpCommand` builder and `collStats:<coll>` / `indexStats:<coll>` from the
per-collection builders.

| File | Captured from |
|---|---|
| `replica-set-primary.json` | The PRIMARY of `rs0`, as an unauthenticated superuser. Holds a **real 11-second client query** (`op: "query"`, `ns: "shop.orders"`, `planSummary: "COLLSCAN"`) sitting alongside the server's own `OplogFetcher` tailing cursor, and **real `$indexStats`**: one index with 500 accesses and three with zero. |
| `replica-set-secondary.json` | The SECONDARY's own view of the same set, at the same moment. |
| `secondary-down.json` | The PRIMARY, 18 seconds after `docker pause sp-mongo2`. **The file this design is built around** — see below. |
| `standalone.json` | A `mongod` started without `--replSet`. `replSetGetStatus` fails with **code 76 `NoReplicationEnabled`**, `find` on `local.oplog.rs` returns an **empty batch with `ok: 1` and no error**, and `$collStats` on it fails with **code 26 `NamespaceNotFound`**. |
| `oplog-saturated.json` | The `--oplogSize 1` member after ~200 MB of incompressible writes. **Uptime 478 s, oplog window 30 s** — an oplog that is genuinely rolling. Its sibling above is uptime 493 s, window 472 s: the same small number, a completely different fact. |
| `unauthorized.json` | The `--auth` server as a user with `read` on one database and nothing else. Seven of thirteen commands fail with **code 13 `Unauthorized`**; the other six succeed and three of those are the trap. |

#### What `secondary-down.json` says, and why the judge is shaped around it

A member that has been unreachable for eighteen seconds reports:

```
state: 8, stateStr: "(not reachable/healthy)", health: 0,
optimeDate: "1970-01-01T00:00:00.000Z", uptime: 0, pingMs: 0
```

Three of those five numbers read as *excellent* to anything that does not check
`health` first. `pingMs: 0` is a perfect round trip. `uptime: 0` is a counter, not an
error. And `optimeDate` is not null and is not the member's last known position — it
is **the Unix epoch**, so lag arithmetic against it produces either fifty-six years
or, after any `Math.max(0, …)`, zero. This is the MySQL `Seconds_Behind_Source: 0`
trap with different field names: the state is checked first and the times second,
and an epoch optime is reported as "the member did not say", never as a measurement.

`lastHeartbeatMessage` on that row carries the full internal heartbeat command
including the source and target host names, so it is redacted before it is shown or
stored.

#### What `unauthorized.json` says

* **`listDatabases` returned exactly one database and `ok: 1`.** No error, no flag.
  The server silently answers with the databases this user is authorized on, so a
  4 GB cluster reports `totalSize: 40960`. This is `information_schema` shrinking
  again; the collector detects it by the absence of `admin` and `local`, which every
  `mongod` has.
* **`$currentOp` with `allUsers: true` is denied, and with `allUsers: false` succeeds.**
  A fallback that quietly drops to `false` reports "1 operation running" on a server
  running two hundred. It is taken, because half an answer beats none, and the answer
  is labelled `partial`.
* **`$collStats` on a collection succeeds while `$indexStats` on the same collection
  is denied.** Sizes working is not evidence that index usage will.

### Redis — `redis:7` (7.4.7) and `redis:5` (5.0.14)

A master with `--maxmemory 64mb --maxmemory-policy allkeys-lru`, a replica of it, an
instance deliberately pushed past a `noeviction` limit, and a Redis 5 for the version
gap. Captured through `ioredis`, the driver this app ships, by `client.call(...)` with
the exact argv in `REDIS_COMMANDS`.

Each file is `{ commandKey: { ok: true, reply } | { ok: false, name, message } }`. Redis
errors carry **no numeric code at all** — the classification is by the leading token of
the message, which is why `NOPERM`, `WRONGPASS` and `ERR This instance has cluster
support disabled` are matched as text.

| File | Captured from |
|---|---|
| `master.json` | The master, with `slowlog-log-slower-than` set to a real 10 000 µs and **two real slow entries**: `KEYS tmp:*` at 69 ms and an `EVAL` at 384 ms. `INFO replication` carries a real `slave0:ip=…,state=online,offset=…,lag=0` line. |
| `replica.json` | The replica, streaming. **`maxmemory:0` with `maxmemory_policy:noeviction`** — the field that is present and genuinely means *unlimited*. |
| `replica-link-down.json` | The same replica 12 seconds after `docker stop` on its master. `master_link_status:down`, `master_link_down_since_seconds:13`, and **`master_last_io_seconds_ago:-1`** — a sentinel, not a measurement, and zero after any clamp. |
| `memory-full-noeviction.json` | An instance at `used_memory:35758744` against `maxmemory:8388608` with `maxmemory-policy:noeviction`. 426 % of its limit, which Redis permits because the write arrived as one script. |
| `acl-denied.json` | The master as an ACL user with `+get +set ~app:*`. **All thirteen commands fail**, each with `NOPERM User app has no permissions to run the '<command>' command`. There is no partial data and no empty reply — the whole page is a refusal. |
| `redis-5.json` | A default `redis:5`. **`maxclients` is absent from `INFO clients` entirely**, `INFO keyspace` is the bare header `# Keyspace\r\n` with no `db0` line, and thirty-seven `INFO stats` fields do not exist. It is the evidence for the rule that an absent field is unknown and never zero. |

`redis-5.json` also records something no amount of reading would have caught:
**`CONFIG GET slowlog-*` returns its pairs in a different order on 5 than on 7**
(`slowlog-log-slower-than` first rather than `slowlog-max-len`). The reply is read as a
flat pair list, never by index.

## The gaps, stated rather than hidden

* **`superReadOnly` is captured and nothing asks for it.** A `SELECT
  @@super_read_only` from an earlier draft of the MySQL overview. It is kept
  rather than deleted — removing a real capture to make a test pass is how
  fixtures start being fiction — and `tests/dbOpsCollector.test.ts` lists it as a
  known extra.
* **Three statements have no captured answer at all**, because no server was
  available to record them and inventing one is not allowed here:
  `processlistCount` (MySQL), `allSlavesStatus` (MariaDB multi-source; the
  containers ran one connection each) and `databaseAges` (PostgreSQL). They are
  named in `UNCAPTURED` in `tests/dbOpsCollector.test.ts` so the coverage
  assertion stays honest about which ones it is not making.
* **No MySQL 5.7 and no MariaDB 10.5–11.x.** 5.7 has neither `SHOW REPLICA STATUS`
  nor `binlog_expire_logs_seconds`, so MariaDB 10.4 exercises the same two fallbacks
  and is a reasonable stand-in — but its error *codes* have not been verified, only
  reasoned about. MariaDB 10.5+ accepts both spellings and is untested here.
* **No PostgreSQL below 16.** `pg_blocking_pids()` (9.6), `pg_wal_lsn_diff` (10) and
  the `total_exec_time` rename (13) are all version-gated in `src/shared/dbOps.ts`
  and none of those gates has been exercised against a server that actually needs
  them. The legacy `pg_stat_statements` column names in particular are covered only
  by the *failure* half: `primary.json` records the real SQLSTATE `42703` that the
  modern query raises when asked for `total_time`.
* **No table near transaction-ID wraparound.** Producing a real `age(relfrozenxid)`
  of a billion needs a billion transactions. The captured ages are 2 and 16; the
  wraparound arithmetic in `judgePgVacuum` is tested against synthetic ages, and the
  test says so.
* **No connection-exhaustion capture.** `Connection_errors_max_connections` is 0 in
  every file here.

### MongoDB and Redis

* **No sharded cluster and no `mongos`.** Every MongoDB capture is against a `mongod`.
  `rs.status()` on a `mongos` is a different shape entirely, `listDatabases` aggregates
  across shards, and none of that is exercised here. A `mongos` is detected from
  `hello().msg === 'isdbgrid'` and reported as out of scope rather than guessed at.
* **No Redis Cluster.** `cluster_enabled` is `0` in every file, so `CLUSTER INFO` is
  captured only in its **refusal** form — `ERR This instance has cluster support
  disabled`, identical on 5 and 7. `cluster_state:ok` / `cluster_state:fail` and the
  slot arithmetic in `judgeRedisCluster` have never met a real cluster, and
  `tests/dbOpsMongoRedis.test.ts` says so at that test.
* **No Redis Sentinel.** Sentinel is what tells you whether an instance is *supposed*
  to have replicas, which is the one thing `INFO replication` cannot say. It is not
  read, and the replication verdict states the limit rather than assuming standalone.
* **No AOF-enabled Redis.** `aof_enabled:0` everywhere, so `aof_last_write_status:err`
  and `aof_rewrites_consecutive_failures` are judged but not captured.
* **No MongoDB with a genuinely large index working set.** `$indexStats` shows real
  zero-access indexes, but on a server whose counters are eight minutes old. The rule
  that an unused index is only *reported* as unused when `accesses.since` is old enough
  to mean something is therefore tested against synthetic `since` values, and the test
  says so.
* **No `mongodb+srv://` capture.** `src/main/services/db.ts` already refuses to tunnel
  one; nothing here proves what the collector does against a real Atlas deployment,
  where `serverStatus` and `local.oplog.rs` are both denied to every user role Atlas
  hands out.
* **No MongoDB below 7.0 and no Redis 6.** The `$currentOp`/`$collStats` projections and
  `maxclients` are the two places a version gate matters, and 5.0.14 stands in for
  "old" at one end only.

## A note on the recording machine, since it bears on trust

`tests/fixtures/docker/README.md` records that a command proxy on the recording host
rewrites some Docker output into token-optimised summaries, which makes a naively
captured fixture **fabricated without anyone deciding to fabricate it**.

Nothing in `mongodb/` or `redis/` can have been affected: every byte came back over a
TCP socket from the `mongodb` and `ioredis` drivers inside a Node process, and no
`docker` output is parsed anywhere in the capture. Docker was used only to *start* the
servers, through the proxy's passthrough form (`rtk proxy docker …`).

The check was run anyway rather than reasoned about. A second capture of
`redis/master.json` and `mongodb/replica-set-primary.json`, taken minutes after the
committed ones, was compared **by structure** — the set of every key path and value
type, values excluded because they move — and both diffs were empty in both directions.

Regenerate with the container recipes in the header comments of `tests/dbOps.test.ts`
(PostgreSQL, MySQL, MariaDB) and `tests/dbOpsMongoRedis.test.ts` (MongoDB, Redis).
