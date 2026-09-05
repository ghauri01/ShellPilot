import type { DbAnswerStatus, DbVerdictLevel } from '../../shared/dbOps'

// SQL Server's operational reads — item 18's last engine.
//
// Every query here was run against a real SQL Server 2022 before it was written
// down, and three of them changed as a result. Reading the T-SQL is not enough
// for this engine, because several of its system views answer "not configured"
// and "configured and empty" with the same rows.

/** The `mssql` package's pool. `any` for the reason the rest of this file's
 *  neighbours are: the driver ships its own types under a CJS default export
 *  that does not survive the ESM interop. */
type MsClient = {
  request: () => { query: (sql: string) => Promise<{ recordset?: unknown[] }> }
}

export async function msRows(client: MsClient, sql: string): Promise<Record<string, unknown>[]> {
  const res = await client.request().query(sql)
  return (res?.recordset ?? []) as Record<string, unknown>[]
}

/**
 * `user connections = 0` means UNLIMITED, not "no connections allowed".
 *
 * Straight out of the live server: a default install reports 0, and a naive
 * `used / max` reads that as either a division by zero or a server at infinite
 * capacity. Both are wrong in the direction that matters — the first crashes
 * the panel, the second reports an alarm on a server that is fine.
 */
export function mssqlConnectionCeiling(configured: number | null): number | null {
  if (configured === null) return null
  return configured === 0 ? null : configured
}

/**
 * Whether an availability-group reading means anything.
 *
 * `sys.dm_hadr_availability_replica_states` returns ZERO ROWS on a server with
 * no availability group. It does not error, and it does not distinguish itself
 * from an AG whose replicas have all disappeared. Confirmed on a real server:
 * the empty list and `IsHadrEnabled = 0` arrive together, and the property is
 * the only thing that separates "not configured" from "configured and gone".
 *
 * Reporting `ok` for zero rows would tell an operator their replication is
 * healthy on a server that has none.
 */
export function mssqlAlwaysOnStatus(
  hadrEnabled: number | null,
  replicaCount: number
): { status: DbAnswerStatus; level: DbVerdictLevel; headline: string } {
  if (hadrEnabled === null) {
    return {
      // `error`, not `absent`. The status vocabulary has no `unknown` -- that
      // is a VERDICT level -- and calling a failed read `absent` would say the
      // feature is not configured when what happened is that we could not look.
      status: 'error',
      level: 'unknown',
      headline: 'Could not read whether AlwaysOn is enabled on this server'
    }
  }
  if (hadrEnabled === 0) {
    return {
      status: 'absent',
      level: 'ok',
      headline: 'AlwaysOn is not enabled on this server'
    }
  }
  if (replicaCount === 0) {
    // Enabled, and no replicas. NOT the same as the line above, and this is the
    // case the whole function exists for.
    return {
      status: 'partial',
      level: 'alarm',
      headline: 'AlwaysOn is enabled but this server reports no replicas at all'
    }
  }
  return { status: 'ok', level: 'ok', headline: `${replicaCount} replica(s) reporting` }
}

/** Databases SQL Server keeps for itself, plus the two that only exist inside
 *  the Linux container image. Confirmed present on a real container and absent
 *  on Windows, so they are filtered by name rather than by any flag. */
export const MSSQL_SYSTEM_DBS = new Set([
  'master',
  'model',
  'msdb',
  'tempdb',
  'model_msdb',
  'model_replicatedmaster'
])

export interface MssqlBackupRow {
  name: string
  recovery: string
  lastFull: string | null
  lastLog: string | null
}

/**
 * What a database's backup history means, in the order an operator cares.
 *
 * NULL from `msdb.dbo.backupset` means NEVER, and never is not "a long time
 * ago" -- it is the state where the restore does not exist. The FULL-recovery
 * case is the one that quietly kills a server: the log is never truncated
 * because nothing has ever backed it up, so it grows until the disk fills, and
 * SQL Server raises nothing until it stops.
 *
 * `tempdb` is excluded by the caller; it is never backed up by design and
 * flagging it would train people to ignore this answer.
 */
export function mssqlBackupVerdict(
  row: MssqlBackupRow,
  now: number,
  fullWarnHours = 48,
  logWarnHours = 6
): { level: DbVerdictLevel; because: string } {
  const full = row.lastFull === null ? null : Date.parse(row.lastFull)
  const log = row.lastLog === null ? null : Date.parse(row.lastLog)
  const needsLog = row.recovery === 'FULL' || row.recovery === 'BULK_LOGGED'

  if (full === null) {
    return { level: 'alarm', because: `${row.name} has never been backed up` }
  }
  if (needsLog && log === null) {
    return {
      level: 'alarm',
      because: `${row.name} is in ${row.recovery} recovery and its log has never been backed up, so the log will grow until the disk fills`
    }
  }
  const fullAgeH = (now - full) / 3_600_000
  if (fullAgeH > fullWarnHours) {
    return {
      level: 'watch',
      because: `${row.name} was last backed up ${Math.floor(fullAgeH)} hours ago`
    }
  }
  if (needsLog && log !== null) {
    const logAgeH = (now - log) / 3_600_000
    if (logAgeH > logWarnHours) {
      return {
        level: 'watch',
        because: `${row.name}'s log was last backed up ${Math.floor(logAgeH)} hours ago`
      }
    }
  }
  return { level: 'ok', because: `${row.name} is backed up` }
}

/** Log fullness. The number that matters is the percentage, not the size: a
 *  2 GB log at 12% is fine and a 200 MB log at 99% is minutes from stopping
 *  the database. */
export function mssqlLogVerdict(usedPercent: number | null): DbVerdictLevel {
  if (usedPercent === null) return 'unknown'
  if (usedPercent >= 90) return 'alarm'
  if (usedPercent >= 75) return 'watch'
  return 'ok'
}

export const MSSQL_QUERIES = {
  overview: `SET NOCOUNT ON; SELECT
      CAST(SERVERPROPERTY('ProductVersion') AS NVARCHAR(64)) AS version,
      CAST(SERVERPROPERTY('Edition') AS NVARCHAR(128)) AS edition,
      CAST(SERVERPROPERTY('IsHadrEnabled') AS INT) AS hadr,
      DATEDIFF(second, sqlserver_start_time, GETDATE()) AS uptime_seconds
    FROM sys.dm_os_sys_info`,
  replicas: `SET NOCOUNT ON; SELECT COUNT(*) AS n FROM sys.dm_hadr_availability_replica_states`,
  backups: `SET NOCOUNT ON; SELECT d.name AS name, d.recovery_model_desc AS recovery,
      CONVERT(NVARCHAR(33), MAX(CASE WHEN b.type = 'D' THEN b.backup_finish_date END), 126) AS lastFull,
      CONVERT(NVARCHAR(33), MAX(CASE WHEN b.type = 'L' THEN b.backup_finish_date END), 126) AS lastLog
    FROM sys.databases d
    LEFT JOIN msdb.dbo.backupset b ON b.database_name = d.name
    GROUP BY d.name, d.recovery_model_desc
    ORDER BY d.name`,
  connections: `SET NOCOUNT ON; SELECT
      (SELECT COUNT(*) FROM sys.dm_exec_sessions WHERE is_user_process = 1) AS sessions,
      (SELECT value_in_use FROM sys.configurations WHERE name = 'user connections') AS ceiling`,
  blocking: `SET NOCOUNT ON; SELECT r.session_id AS blocked, r.blocking_session_id AS blocker,
      r.wait_type AS waitType, r.wait_time AS waitMs, DB_NAME(r.database_id) AS dbName
    FROM sys.dm_exec_requests r WHERE r.blocking_session_id <> 0`,
  sizes: `SET NOCOUNT ON; SELECT DB_NAME(database_id) AS name, type_desc AS kind,
      CAST(SUM(size) * 8 / 1024.0 AS DECIMAL(18,1)) AS mb
    FROM sys.master_files GROUP BY database_id, type_desc ORDER BY 1`
} as const
