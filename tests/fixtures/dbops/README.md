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

Each file is `{ questionName: { ok, rows } | { ok: false, code, errno, message } }`,
one entry per statement in `PG_QUERIES` / `MYSQL_QUERIES`.

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
| `no-pg-stat-statements.json` | A database in the same cluster where the extension was never created. `pg_extension` is empty; the view raises SQLSTATE `42P01`. |

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

## The gaps, stated rather than hidden

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

Regenerate with the container recipe in `tests/dbOps.test.ts`'s header comment.
