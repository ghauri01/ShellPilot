/* eslint-disable @typescript-eslint/no-explicit-any */
import type { DbConnectConfig, DbInfo, DbKind, DbQueryResult, DbTestResult } from '../../shared/db'

export interface Conn {
  kind: DbKind
  client: any
  close: () => Promise<void>
}

const conns = new Map<string, Conn>()

// Replace the host:port in a connection string, preserving credentials and
// everything after the authority.
function rewriteUriHost(uri: string, host: string, port: number): string {
  const m = /^([a-z][a-z0-9+.-]*:\/\/)([^/?#]*)(.*)$/i.exec(uri)
  if (!m) return uri
  const at = m[2].lastIndexOf('@')
  const creds = at === -1 ? '' : m[2].slice(0, at + 1)
  return `${m[1]}${creds}${host}:${port}${m[3]}`
}

function uriEndpoint(uri: string): { host: string; port: number } | null {
  const m = /^[a-z][a-z0-9+.-]*:\/\/([^/?#]*)/i.exec(uri)
  if (!m) return null
  const authority = m[1].slice(m[1].lastIndexOf('@') + 1)
  const host = authority.split(',')[0] // first host of a replica-set list
  const i = host.lastIndexOf(':')
  if (i === -1) return { host, port: 0 }
  return { host: host.slice(0, i), port: Number(host.slice(i + 1)) || 0 }
}

const DEFAULT_PORT: Record<DbKind, number> = {
  postgres: 5432,
  mysql: 3306,
  mssql: 1433,
  mongodb: 27017,
  redis: 6379
}

// Open the SSH forward (when configured) and hand the driver a config pointed
// at the local end of it.
async function build(cfg: DbConnectConfig): Promise<Conn> {
  if (!cfg.ssh) return buildDriver(cfg)

  if (cfg.uri && /^mongodb\+srv:/i.test(cfg.uri)) {
    throw new Error(
      'mongodb+srv:// resolves several hosts via DNS and cannot be tunnelled. Use the host/port fields, or a plain mongodb:// string.'
    )
  }

  const from = cfg.uri ? uriEndpoint(cfg.uri) : null
  const targetHost = from?.host || cfg.host
  const targetPort = from?.port || cfg.port || DEFAULT_PORT[cfg.kind]
  if (!targetHost) throw new Error('No database host to tunnel to.')

  const { openEphemeralForward } = await import('./tunnel')
  const fwd = await openEphemeralForward(cfg.ssh, targetHost, targetPort)
  try {
    const conn = await buildDriver({
      ...cfg,
      host: '127.0.0.1',
      port: fwd.port,
      uri: cfg.uri ? rewriteUriHost(cfg.uri, '127.0.0.1', fwd.port) : undefined
    })
    const inner = conn.close
    return {
      ...conn,
      close: async () => {
        try {
          await inner()
        } finally {
          fwd.close()
        }
      }
    }
  } catch (err) {
    fwd.close()
    throw err
  }
}

async function buildDriver(cfg: DbConnectConfig): Promise<Conn> {
  const { kind, host, port, username, password, database, ssl, uri } = cfg
  switch (kind) {
    case 'postgres': {
      const { Client } = await import('pg')
      const c = uri
        ? new Client({ connectionString: uri, ssl: ssl ? { rejectUnauthorized: false } : undefined })
        : new Client({ host, port, user: username, password, database: database || undefined, ssl: ssl ? { rejectUnauthorized: false } : undefined })
      await c.connect()
      return { kind, client: c, close: () => c.end() }
    }
    case 'mysql': {
      const mysql = await import('mysql2/promise')
      const c = uri
        ? await mysql.createConnection(uri)
        : await mysql.createConnection({ host, port, user: username, password, database: database || undefined, ssl: ssl ? {} : undefined })
      return { kind, client: c, close: async () => void c.end() }
    }
    case 'mssql': {
      // mssql is CJS with no detectable named exports, so under ESM its API
      // lands on `default`. Without this, `new sql.ConnectionPool()` throws
      // "sql.ConnectionPool is not a constructor".
      const mod: any = await import('mssql')
      const sql: any = mod.default ?? mod
      const pool = uri
        ? await new sql.ConnectionPool(uri).connect()
        : await new sql.ConnectionPool({
            server: host,
            port,
            user: username,
            password,
            database: database || undefined,
            options: { encrypt: ssl ?? true, trustServerCertificate: true }
          }).connect()
      return { kind, client: pool, close: () => pool.close() }
    }
    case 'mongodb': {
      const { MongoClient } = await import('mongodb')
      const auth = username ? `${encodeURIComponent(username)}:${encodeURIComponent(password ?? '')}@` : ''
      const url = uri || `mongodb://${auth}${host}:${port}/${database || 'admin'}`
      const c = new MongoClient(url)
      await c.connect()
      return { kind, client: c, close: () => c.close() }
    }
    case 'redis': {
      const Redis = (await import('ioredis')).default
      const c = uri
        ? new Redis(uri, { lazyConnect: true, maxRetriesPerRequest: 1 })
        : new Redis({ host, port, username: username || undefined, password: password || undefined, lazyConnect: true, maxRetriesPerRequest: 1 })
      await c.connect()
      return { kind, client: c, close: async () => void c.quit() }
    }
  }
}

export async function ensure(cfg: DbConnectConfig): Promise<Conn> {
  const existing = conns.get(cfg.id)
  if (existing) return existing
  const conn = await build(cfg)
  conns.set(cfg.id, conn)
  return conn
}

function msg(err: unknown): string {
  return err instanceof Error ? err.message : String(err)
}

// The MongoDB database to operate on: explicit field wins, else the db in the
// connection string, else the driver default.
export function mongoDbName(cfg: DbConnectConfig): string | undefined {
  if (cfg.database) return cfg.database
  const m = cfg.uri?.match(/mongodb(?:\+srv)?:\/\/[^/]+\/([^?]+)/i)
  return m?.[1] ? decodeURIComponent(m[1]) : undefined
}

export async function dbTest(cfg: DbConnectConfig): Promise<DbTestResult> {
  try {
    const conn = await build(cfg)
    let version = ''
    try {
      if (cfg.kind === 'postgres') version = (await conn.client.query('SELECT version()')).rows[0].version
      else if (cfg.kind === 'mysql') version = (await conn.client.query('SELECT VERSION() v'))[0][0].v
      else if (cfg.kind === 'mssql') version = (await conn.client.request().query('SELECT @@VERSION v')).recordset[0].v
      else if (cfg.kind === 'redis') version = 'Redis ' + (await conn.client.info('server')).match(/redis_version:([^\r\n]+)/)?.[1]
      else if (cfg.kind === 'mongodb') version = 'MongoDB ' + (await conn.client.db().admin().serverInfo()).version
    } catch {
      /* version optional */
    }
    await conn.close()
    return { ok: true, version: (version || '').trim() }
  } catch (err) {
    return { ok: false, error: msg(err) }
  }
}

// Tokenize a redis command line respecting simple quotes.
function tokenize(line: string): string[] {
  const out: string[] = []
  const re = /"([^"]*)"|'([^']*)'|(\S+)/g
  let m: RegExpExecArray | null
  while ((m = re.exec(line))) out.push(m[1] ?? m[2] ?? m[3])
  return out
}

export async function dbQuery(cfg: DbConnectConfig, text: string): Promise<DbQueryResult> {
  const started = Date.now()
  try {
    const conn = await ensure(cfg)
    const elapsed = (): number => Date.now() - started

    if (cfg.kind === 'postgres') {
      const res = await conn.client.query(text)
      const columns = (res.fields ?? []).map((f: any) => f.name)
      const rows = (res.rows ?? []).map((r: any) => columns.map((c: string) => r[c]))
      return { ok: true, kind: columns.length ? 'rows' : 'message', columns, rows, rowCount: res.rowCount, message: `${res.rowCount ?? 0} row(s)`, elapsedMs: elapsed() }
    }
    if (cfg.kind === 'mysql') {
      const [rows, fields] = await conn.client.query(text)
      if (Array.isArray(rows) && fields) {
        const columns = (fields as any[]).map((f) => f.name)
        return { ok: true, kind: 'rows', columns, rows: (rows as any[]).map((r) => columns.map((c) => r[c])), rowCount: (rows as any[]).length, elapsedMs: elapsed() }
      }
      return { ok: true, kind: 'message', message: JSON.stringify(rows), elapsedMs: elapsed() }
    }
    if (cfg.kind === 'mssql') {
      const res = await conn.client.request().query(text)
      const rec = res.recordset
      if (rec && rec.columns) {
        const columns = Object.keys(rec.columns)
        return { ok: true, kind: 'rows', columns, rows: rec.map((r: any) => columns.map((c) => r[c])), rowCount: rec.length, elapsedMs: elapsed() }
      }
      return { ok: true, kind: 'message', message: `${res.rowsAffected?.[0] ?? 0} row(s) affected`, elapsedMs: elapsed() }
    }
    if (cfg.kind === 'mongodb') {
      const command = JSON.parse(text)
      const db = conn.client.db(mongoDbName(cfg))
      const raw = await db.command(command)
      // Unwrap find/aggregate cursors so the user sees their documents directly
      // instead of a { cursor: { firstBatch: [...] } } wrapper.
      const batch = raw?.cursor?.firstBatch
      if (Array.isArray(batch)) {
        return { ok: true, kind: 'json', json: batch, rowCount: batch.length, message: `${batch.length} document(s)`, elapsedMs: elapsed() }
      }
      return { ok: true, kind: 'json', json: raw, elapsedMs: elapsed() }
    }
    // redis
    const args = tokenize(text)
    if (args.length === 0) return { ok: false, error: 'Empty command' }
    const reply = await conn.client.call(args[0], ...args.slice(1))
    return { ok: true, kind: 'value', json: reply, elapsedMs: elapsed() }
  } catch (err) {
    return { ok: false, error: msg(err), elapsedMs: Date.now() - started }
  }
}

export async function dbInfo(cfg: DbConnectConfig): Promise<DbInfo> {
  try {
    const conn = await ensure(cfg)
    if (cfg.kind === 'postgres') {
      const dbs = (await conn.client.query('SELECT datname FROM pg_database WHERE datistemplate=false ORDER BY 1')).rows.map((r: any) => r.datname)
      const tables = (await conn.client.query("SELECT tablename FROM pg_tables WHERE schemaname='public' ORDER BY 1")).rows.map((r: any) => r.tablename)
      return { ok: true, databases: dbs, tables }
    }
    if (cfg.kind === 'mysql') {
      const [dbs] = await conn.client.query('SHOW DATABASES')
      const [tables] = await conn.client.query('SHOW TABLES')
      return { ok: true, databases: (dbs as any[]).map((r) => Object.values(r)[0] as string), tables: (tables as any[]).map((r) => Object.values(r)[0] as string) }
    }
    if (cfg.kind === 'mssql') {
      const dbs = (await conn.client.request().query('SELECT name FROM sys.databases ORDER BY name')).recordset.map((r: any) => r.name)
      const tables = (await conn.client.request().query('SELECT name FROM sys.tables ORDER BY name')).recordset.map((r: any) => r.name)
      return { ok: true, databases: dbs, tables }
    }
    if (cfg.kind === 'mongodb') {
      // A read-only user may lack listDatabases on admin — degrade gracefully
      // and still return the selected database's collections.
      let databases: string[] = []
      try {
        const res = await conn.client.db().admin().listDatabases({ nameOnly: true })
        databases = (res.databases ?? []).map((d: any) => d.name).sort((a: string, b: string) => a.localeCompare(b))
      } catch {
        /* listDatabases not permitted */
      }
      // Never drop the database the user is actually pointed at, even when the
      // server only reported the ones this user is authorized on.
      const current = mongoDbName(cfg)
      if (current && !databases.includes(current)) databases = [current, ...databases]
      let tables: string[] = []
      try {
        tables = (await conn.client.db(mongoDbName(cfg)).listCollections().toArray()).map((c: any) => c.name)
      } catch {
        /* listCollections not permitted for this db */
      }
      return { ok: true, databases, tables }
    }
    // redis
    return { ok: true, databases: [], tables: [] }
  } catch (err) {
    return { ok: false, error: msg(err) }
  }
}

export async function dbClose(id: string): Promise<void> {
  const c = conns.get(id)
  if (!c) return
  try {
    await c.close()
  } catch {
    /* ignore */
  }
  conns.delete(id)
}

export function dbDisposeAll(): void {
  for (const id of [...conns.keys()]) void dbClose(id)
}
