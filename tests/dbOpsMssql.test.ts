import { describe, expect, it } from 'vitest'
import {
  MSSQL_SYSTEM_DBS,
  mssqlAlwaysOnStatus,
  mssqlBackupVerdict,
  mssqlConnectionCeiling,
  mssqlLogVerdict
} from '../src/main/services/dbOpsMssql'

// The readings SQL Server gives that mean the opposite of what they look like.
// Each number here was observed on a real SQL Server 2022 before it was written.

describe('the connection ceiling', () => {
  it('reads a configured 0 as unlimited, not as none', () => {
    // Straight off a default install: `user connections` is 0, and 0 means
    // unlimited. `used / 0` is either a crash or a server reported at infinite
    // load, and both are wrong in the direction that shows an alarm on a
    // server that is fine.
    expect(mssqlConnectionCeiling(0)).toBeNull()
    expect(mssqlConnectionCeiling(100)).toBe(100)
    expect(mssqlConnectionCeiling(null)).toBeNull()
  })
})

describe('availability groups, where an empty list is not a healthy one', () => {
  it('says not configured when AlwaysOn is off, and does not call it ok replication', () => {
    // The observed case: a server with no AG returns ZERO ROWS from
    // dm_hadr_availability_replica_states and does not error.
    const r = mssqlAlwaysOnStatus(0, 0)
    expect(r.status).toBe('absent')
    expect(r.headline).toMatch(/not enabled/)
  })

  it('ALARMS when AlwaysOn is on and no replicas report', () => {
    // Same zero rows, opposite meaning. This is the reason the property is
    // read at all: enabled with nothing reporting is replication that has gone.
    const r = mssqlAlwaysOnStatus(1, 0)
    expect(r.level).toBe('alarm')
    expect(r.status).toBe('partial')
  })

  it('is unknown when the property itself could not be read', () => {
    expect(mssqlAlwaysOnStatus(null, 0).level).toBe('unknown')
  })

  it('is ok when replicas actually report', () => {
    expect(mssqlAlwaysOnStatus(1, 3).level).toBe('ok')
  })
})

describe('backups, where NULL means never', () => {
  const NOW = Date.UTC(2026, 8, 5, 12, 0, 0)
  const iso = (hoursAgo: number): string => new Date(NOW - hoursAgo * 3_600_000).toISOString()

  it('alarms on a database that has never been backed up', () => {
    // NULL from msdb.dbo.backupset is never, not long ago. Never is the state
    // where the restore does not exist.
    const v = mssqlBackupVerdict(
      { name: 'payments', recovery: 'FULL', lastFull: null, lastLog: null },
      NOW
    )
    expect(v.level).toBe('alarm')
    expect(v.because).toMatch(/never been backed up/)
  })

  it('alarms on FULL recovery whose log has never been backed up', () => {
    // The quiet killer, and the reason this question exists. The log is never
    // truncated, grows until the disk fills, and SQL Server says nothing until
    // the database stops.
    const v = mssqlBackupVerdict(
      { name: 'orders', recovery: 'FULL', lastFull: iso(1), lastLog: null },
      NOW
    )
    expect(v.level).toBe('alarm')
    expect(v.because).toMatch(/log will grow until the disk fills/)
  })

  it('does not demand a log backup from a SIMPLE database', () => {
    // SIMPLE truncates its own log. Asking for a log backup there would be an
    // alarm nobody can act on, which is how an alarm gets ignored.
    const v = mssqlBackupVerdict(
      { name: 'reporting', recovery: 'SIMPLE', lastFull: iso(1), lastLog: null },
      NOW
    )
    expect(v.level).toBe('ok')
  })

  it('watches a stale full backup rather than alarming', () => {
    const v = mssqlBackupVerdict(
      { name: 'orders', recovery: 'SIMPLE', lastFull: iso(72), lastLog: null },
      NOW
    )
    expect(v.level).toBe('watch')
    expect(v.because).toMatch(/72 hours ago/)
  })

  it('watches a stale log even when the full backup is fresh', () => {
    const v = mssqlBackupVerdict(
      { name: 'orders', recovery: 'FULL', lastFull: iso(1), lastLog: iso(9) },
      NOW
    )
    expect(v.level).toBe('watch')
    expect(v.because).toMatch(/log was last backed up/)
  })
})

describe('log space', () => {
  it('grades on percentage, not size', () => {
    // A 2 GB log at 12% is fine; a 200 MB log at 99% is minutes from stopping
    // the database. The size is the wrong number to alarm on.
    expect(mssqlLogVerdict(12)).toBe('ok')
    expect(mssqlLogVerdict(80)).toBe('watch')
    expect(mssqlLogVerdict(95)).toBe('alarm')
    expect(mssqlLogVerdict(null)).toBe('unknown')
  })
})

describe('which databases are the server’s own', () => {
  it('includes the two that only exist inside the Linux image', () => {
    // Observed on a real container: DBCC SQLPERF(LOGSPACE) lists model_msdb and
    // model_replicatedmaster, which no Windows install has. Reporting them
    // would be noise an operator cannot act on.
    expect(MSSQL_SYSTEM_DBS.has('model_msdb')).toBe(true)
    expect(MSSQL_SYSTEM_DBS.has('model_replicatedmaster')).toBe(true)
    expect(MSSQL_SYSTEM_DBS.has('tempdb')).toBe(true)
    expect(MSSQL_SYSTEM_DBS.has('payments')).toBe(false)
  })
})
