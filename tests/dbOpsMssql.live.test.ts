import { describe, expect, it } from 'vitest'
import {
  MSSQL_QUERIES,
  mssqlAlwaysOnStatus,
  mssqlConnectionCeiling,
  msRows
} from '../src/main/services/dbOpsMssql'

// Against a REAL SQL Server, because this engine answers "not configured" and
// "configured and empty" with the same rows and no fixture can prove which one
// a live server sends.
//
//   docker run -d --rm --name sp-mssql -e ACCEPT_EULA=Y \
//     -e MSSQL_SA_PASSWORD='Sh3llP1lot!test' -p 21433:1433 \
//     mcr.microsoft.com/mssql/server:2022-latest
//
// Skipped when SHELLPILOT_MSSQL_LIVE is unset, so the suite stays runnable
// without Docker — and CI does not silently lose the check, because the whole
// point of the file is what it proves when it DOES run.
const LIVE = process.env.SHELLPILOT_MSSQL_LIVE === '1'

async function connect(): Promise<{ client: never; close: () => Promise<void> }> {
  const mod: Record<string, unknown> = await import('mssql')
  const sql = (mod.default ?? mod) as {
    ConnectionPool: new (c: unknown) => { connect: () => Promise<never>; close: () => Promise<void> }
  }
  const pool = new sql.ConnectionPool({
    server: '127.0.0.1',
    port: 21433,
    user: 'sa',
    password: process.env.SHELLPILOT_MSSQL_PASSWORD ?? 'Sh3llP1lot!test',
    options: { encrypt: false, trustServerCertificate: true }
  })
  const client = await pool.connect()
  return { client, close: () => pool.close() }
}

describe.skipIf(!LIVE)('the queries, run against a real SQL Server', () => {
  it('every query this engine ships actually parses and runs', async () => {
    // The failure this catches is the one reading T-SQL cannot: a view that
    // does not exist on this edition, a column renamed between versions, a
    // GROUP BY the planner rejects.
    const { client, close } = await connect()
    try {
      for (const [name, sql] of Object.entries(MSSQL_QUERIES)) {
        await expect(msRows(client, sql), name).resolves.toBeInstanceOf(Array)
      }
    } finally {
      await close()
    }
  }, 60_000)

  it('reports a server with no availability group as not configured, not as healthy', async () => {
    // The reading that would otherwise be wrong in the reassuring direction.
    const { client, close } = await connect()
    try {
      const overview = (await msRows(client, MSSQL_QUERIES.overview))[0]
      const replicas = Number((await msRows(client, MSSQL_QUERIES.replicas))[0]?.n ?? -1)
      expect(replicas).toBe(0)

      const judged = mssqlAlwaysOnStatus(Number(overview?.hadr ?? 0), replicas)
      expect(judged.status).toBe('absent')
      expect(judged.headline).toMatch(/not enabled/)
    } finally {
      await close()
    }
  }, 60_000)

  it('sees the connection ceiling a default install actually reports', async () => {
    // A default server reports `user connections = 0`, and 0 is unlimited.
    // This test exists because that number looks like a limit of none.
    const { client, close } = await connect()
    try {
      const row = (await msRows(client, MSSQL_QUERIES.connections))[0]
      expect(Number(row?.ceiling)).toBe(0)
      expect(mssqlConnectionCeiling(Number(row?.ceiling))).toBeNull()
    } finally {
      await close()
    }
  }, 60_000)

  it('reports a never-backed-up database as null rather than as an old date', async () => {
    const { client, close } = await connect()
    try {
      const rows = await msRows(client, MSSQL_QUERIES.backups)
      const master = rows.find((r) => r.name === 'master')
      expect(master).toBeTruthy()
      expect(master?.lastFull ?? null).toBeNull()
    } finally {
      await close()
    }
  }, 60_000)
})
