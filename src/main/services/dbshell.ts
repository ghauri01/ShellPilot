import type { DbConnectConfig, DbKind } from '../../shared/db'
import type { DbShellResult } from '../../shared/dbshell'
import { dbClose, dbQuery, ensure, mongoDbName } from './db'
import { parseChain, parseRelaxed, type ChainCall, type HelperFn } from './relaxed-json'

// ----------------------------------------------------------------- utilities

// BSON values cannot cross the IPC boundary intact, so collapse them to the
// printable forms the mongo shell itself uses.
function plain(v: unknown, depth = 0): unknown {
  if (v === null || v === undefined) return v ?? null
  if (depth > 24) return '[nested too deep]'
  if (typeof v !== 'object') return typeof v === 'bigint' ? v.toString() : v
  if (v instanceof Date) return v.toISOString()
  if (v instanceof RegExp) return v.toString()
  if (Buffer.isBuffer(v)) return v.toString('base64')
  if (v instanceof Uint8Array) return Buffer.from(v).toString('base64')
  if (Array.isArray(v)) return v.map((x) => plain(x, depth + 1))

  const bt = (v as any)._bsontype
  if (bt) {
    if (bt === 'Binary') return Buffer.from((v as any).buffer ?? []).toString('base64')
    return String(v)
  }

  const out: Record<string, unknown> = {}
  for (const [k, val] of Object.entries(v as Record<string, unknown>)) out[k] = plain(val, depth + 1)
  return out
}

function sqlLiteral(s: string): string {
  return `'${s.replace(/'/g, "''")}'`
}

const HELP: Record<DbKind, string> = {
  mongodb: `Commands
  show dbs | show collections | show users      list server objects
  use <database>                                switch database
  db.<coll>.find({...}).sort({...}).limit(n)    query documents
  db.<coll>.findOne / countDocuments / distinct
  db.<coll>.insertOne / insertMany / updateOne / updateMany / deleteOne / deleteMany
  db.<coll>.aggregate([...])                    aggregation pipeline
  db.<coll>.indexes() / createIndex({...}) / drop()
  db.runCommand({...})                          raw command
  { "find": "coll", "limit": 5 }                raw command as JSON
Helpers: ObjectId(), ISODate(), NumberLong(), NumberDecimal(), UUID(), /regex/i
Results are capped at 50 documents unless you add .limit(n).`,
  postgres: `Commands
  <SQL>;                     run a statement
  \\l                         list databases
  \\dt                        list tables          \\dv  views    \\di  indexes
  \\d <table>                 describe a table     \\dn  schemas  \\du  roles
  \\c <database>              connect to another database
  \\conninfo                  current connection info`,
  mysql: `Commands
  <SQL>;                     run a statement
  \\l                         list databases       (or SHOW DATABASES)
  \\dt                        list tables          \\du  users
  \\d <table>                 describe a table
  \\c <database>              switch database      (or USE <database>)
  \\conninfo                  current connection info`,
  mssql: `Commands
  <T-SQL>                    run a statement
  \\l                         list databases
  \\dt                        list tables          \\dv  views    \\du  principals
  \\d <table>                 describe a table
  \\c <database>              switch database
  \\conninfo                  current connection info`,
  redis: `Commands
  <REDIS COMMAND>            e.g. GET mykey, KEYS user:*, HGETALL h
  SELECT <n>                 switch keyspace
  INFO server                server information`
}

// ------------------------------------------------------------------- mongodb

async function mongoHelpers(): Promise<HelperFn> {
  const m: any = await import('mongodb')
  return (name, args) => {
    const a0 = args[0]
    switch (name) {
      case 'ObjectId':
      case 'ObjectID':
        return a0 === undefined ? new m.ObjectId() : new m.ObjectId(String(a0))
      case 'ISODate':
      case 'Date':
        return a0 === undefined ? new Date() : new Date(a0 as any)
      case 'NumberLong':
        return m.Long.fromString(String(a0))
      case 'NumberInt':
        return new m.Int32(Number(a0))
      case 'NumberDecimal':
        return m.Decimal128.fromString(String(a0))
      case 'UUID':
        return new m.UUID(String(a0))
      case 'BinData':
        return new m.Binary(Buffer.from(String(args[1] ?? ''), 'base64'), Number(a0))
      case 'Timestamp':
        return new m.Timestamp({ t: Number(a0 ?? 0), i: Number(args[1] ?? 0) })
      case 'MinKey':
        return new m.MinKey()
      case 'MaxKey':
        return new m.MaxKey()
      default:
        throw new Error(`Unsupported helper ${name}()`)
    }
  }
}

const DEFAULT_DOC_LIMIT = 50

// Apply .sort()/.limit()/.skip()/... to a find or aggregate cursor.
async function runCursor(cursor: any, rest: ChainCall[], countFallback: () => Promise<number>): Promise<DbShellResult> {
  let explicitLimit = false
  for (const c of rest) {
    const a0 = c.args[0]
    switch (c.name) {
      case 'sort':
        cursor = cursor.sort(a0 ?? {})
        break
      case 'limit':
        cursor = cursor.limit(Number(a0))
        explicitLimit = true
        break
      case 'skip':
        cursor = cursor.skip(Number(a0))
        break
      case 'project':
      case 'projection':
        cursor = cursor.project(a0 ?? {})
        break
      case 'hint':
        cursor = cursor.hint(a0 as any)
        break
      case 'batchSize':
        cursor = cursor.batchSize(Number(a0))
        break
      case 'maxTimeMS':
        cursor = cursor.maxTimeMS(Number(a0))
        break
      case 'collation':
        cursor = cursor.collation(a0 as any)
        break
      case 'toArray':
      case 'pretty':
        break
      case 'count':
      case 'size':
      case 'itcount': {
        const n = await countFallback()
        return { ok: true, json: n }
      }
      case 'explain': {
        const plan = await cursor.explain()
        return { ok: true, json: plain(plan) }
      }
      default:
        throw new Error(`Unsupported cursor method .${c.name}()`)
    }
  }
  if (!explicitLimit) cursor = cursor.limit(DEFAULT_DOC_LIMIT)
  const docs = await cursor.toArray()
  const capped = !explicitLimit && docs.length === DEFAULT_DOC_LIMIT
  return {
    ok: true,
    json: docs.map((d: unknown) => plain(d)),
    note: `${docs.length} document(s)${capped ? ` — capped at ${DEFAULT_DOC_LIMIT}, add .limit(n) for more` : ''}`
  }
}

async function mongoShow(db: any, client: any, whatRaw: string): Promise<DbShellResult> {
  const what = whatRaw.toLowerCase()
  if (what === 'dbs' || what === 'databases') {
    const res = await client.db().admin().listDatabases()
    const rows = (res.databases ?? []).map((d: any) => [d.name, d.sizeOnDisk == null ? '' : `${(Number(d.sizeOnDisk) / 1048576).toFixed(2)} MiB`])
    return { ok: true, columns: ['name', 'size'], rows, note: `${rows.length} database(s)` }
  }
  if (what === 'collections' || what === 'tables') {
    const names = (await db.listCollections().toArray()).map((c: any) => c.name).sort()
    return { ok: true, text: names.join('\n') || '(none)', note: `${names.length} collection(s)` }
  }
  if (what === 'users') return { ok: true, json: plain(await db.command({ usersInfo: 1 })) }
  if (what === 'roles') return { ok: true, json: plain(await db.command({ rolesInfo: 1 })) }
  if (what === 'profile') return { ok: true, json: plain(await db.command({ profile: -1 })) }
  throw new Error(`Unsupported: show ${whatRaw}`)
}

async function mongoCollection(db: any, name: string, calls: ChainCall[]): Promise<DbShellResult> {
  const coll = db.collection(name)
  const [first, ...rest] = calls
  const a = first.args
  const filter = (a[0] as any) ?? {}

  switch (first.name) {
    case 'find':
      return runCursor(
        coll.find(filter, a[1] ? { projection: a[1] } : undefined),
        rest,
        () => coll.countDocuments(filter)
      )
    case 'aggregate':
      return runCursor(coll.aggregate((a[0] as any[]) ?? [], a[1] as any), rest, async () => {
        const out = await coll.aggregate((a[0] as any[]) ?? []).toArray()
        return out.length
      })
    case 'findOne':
      return { ok: true, json: plain(await coll.findOne(filter, a[1] ? { projection: a[1] } : undefined)) }
    case 'countDocuments':
    case 'count':
      return { ok: true, json: await coll.countDocuments(filter) }
    case 'estimatedDocumentCount':
      return { ok: true, json: await coll.estimatedDocumentCount() }
    case 'distinct':
      return { ok: true, json: plain(await coll.distinct(String(a[0]), (a[1] as any) ?? {})) }
    case 'insertOne':
      return { ok: true, json: plain(await coll.insertOne(a[0] as any)), refreshSchema: true }
    case 'insertMany':
      return { ok: true, json: plain(await coll.insertMany(a[0] as any)), refreshSchema: true }
    case 'updateOne':
      return { ok: true, json: plain(await coll.updateOne(filter, a[1] as any, a[2] as any)) }
    case 'updateMany':
      return { ok: true, json: plain(await coll.updateMany(filter, a[1] as any, a[2] as any)) }
    case 'replaceOne':
      return { ok: true, json: plain(await coll.replaceOne(filter, a[1] as any, a[2] as any)) }
    case 'deleteOne':
      return { ok: true, json: plain(await coll.deleteOne(filter)) }
    case 'deleteMany':
    case 'remove':
      return { ok: true, json: plain(await coll.deleteMany(filter)) }
    case 'findOneAndUpdate':
      return { ok: true, json: plain(await coll.findOneAndUpdate(filter, a[1] as any, a[2] as any)) }
    case 'findOneAndDelete':
      return { ok: true, json: plain(await coll.findOneAndDelete(filter, a[1] as any)) }
    case 'findOneAndReplace':
      return { ok: true, json: plain(await coll.findOneAndReplace(filter, a[1] as any, a[2] as any)) }
    case 'drop':
      return { ok: true, json: await coll.drop(), refreshSchema: true }
    case 'createIndex':
      return { ok: true, json: await coll.createIndex(a[0] as any, a[1] as any) }
    case 'dropIndex':
      return { ok: true, json: plain(await coll.dropIndex(a[0] as any)) }
    case 'indexes':
    case 'getIndexes':
      return { ok: true, json: plain(await coll.indexes()) }
    case 'stats':
      return { ok: true, json: plain(await db.command({ collStats: name })) }
    case 'renameCollection':
      return { ok: true, json: plain(await coll.rename(String(a[0]))), refreshSchema: true }
    default:
      throw new Error(`Unsupported collection method .${first.name}()`)
  }
}

async function mongoShell(cfg: DbConnectConfig, text: string): Promise<DbShellResult> {
  const conn = await ensure(cfg)
  const client = conn.client
  const db = client.db(mongoDbName(cfg))
  const body = text.replace(/;+\s*$/, '')

  const use = /^use\s+([^\s;]+)$/i.exec(body)
  if (use) {
    const name = use[1].replace(/^["']|["']$/g, '')
    return { ok: true, text: `switched to db ${name}`, useDatabase: name, refreshSchema: true }
  }

  const show = /^show\s+(\w+)$/i.exec(body)
  if (show) return mongoShow(db, client, show[1])

  if (body.startsWith('{')) {
    const helper = await mongoHelpers()
    const raw = await db.command(parseRelaxed(body, helper) as any)
    const batch = raw?.cursor?.firstBatch
    if (Array.isArray(batch)) {
      return { ok: true, json: batch.map((d: unknown) => plain(d)), note: `${batch.length} document(s)` }
    }
    return { ok: true, json: plain(raw) }
  }

  if (!/^db\b/.test(body)) {
    throw new Error(`Unknown command. Try "help", "show collections", or db.<collection>.find({})`)
  }

  const helper = await mongoHelpers()
  const { path, calls } = parseChain(body, helper)
  if (path[0] !== 'db') throw new Error('Commands must start with "db."')
  if (calls.length === 0) throw new Error('Expected a method call, e.g. db.users.find({})')

  // db-level methods
  if (path.length === 1) {
    const [first, ...rest] = calls
    if (rest.length) throw new Error(`Cannot chain .${rest[0].name}() onto db.${first.name}()`)
    const a = first.args
    switch (first.name) {
      case 'runCommand':
        return { ok: true, json: plain(await db.command(a[0] as any)) }
      case 'adminCommand':
        return { ok: true, json: plain(await client.db('admin').command(a[0] as any)) }
      case 'getCollectionNames': {
        const names = (await db.listCollections().toArray()).map((c: any) => c.name).sort()
        return { ok: true, json: names }
      }
      case 'getName':
        return { ok: true, text: db.databaseName }
      case 'stats':
        return { ok: true, json: plain(await db.stats()) }
      case 'createCollection':
        await db.createCollection(String(a[0]), a[1] as any)
        return { ok: true, text: `{ ok: 1 }`, refreshSchema: true }
      case 'dropDatabase':
        return { ok: true, json: plain(await db.dropDatabase()), refreshSchema: true }
      case 'getSiblingDB':
        throw new Error(`Use "use ${String(a[0])}" to switch databases`)
      default:
        throw new Error(`Unsupported db method .${first.name}()`)
    }
  }

  return mongoCollection(db, path.slice(1).join('.'), calls)
}

// ----------------------------------------------------------------------- SQL

// Translate a psql-style backslash command into SQL for the given engine.
function metaSql(kind: DbKind, cmd: string, arg: string): string | null {
  const t = arg.trim()
  if (kind === 'postgres') {
    switch (cmd) {
      case 'l':
      case 'list':
        return 'SELECT datname AS name, pg_catalog.pg_get_userbyid(datdba) AS owner, pg_encoding_to_char(encoding) AS encoding FROM pg_database WHERE datistemplate = false ORDER BY 1'
      case 'dt':
        return "SELECT schemaname AS schema, tablename AS name, tableowner AS owner FROM pg_tables WHERE schemaname NOT IN ('pg_catalog','information_schema') ORDER BY 1,2"
      case 'dv':
        return "SELECT schemaname AS schema, viewname AS name FROM pg_views WHERE schemaname NOT IN ('pg_catalog','information_schema') ORDER BY 1,2"
      case 'di':
        return "SELECT schemaname AS schema, indexname AS name, tablename AS table FROM pg_indexes WHERE schemaname NOT IN ('pg_catalog','information_schema') ORDER BY 1,2"
      case 'dn':
        return "SELECT nspname AS name FROM pg_namespace WHERE nspname NOT LIKE 'pg_%' AND nspname <> 'information_schema' ORDER BY 1"
      case 'du':
        return 'SELECT rolname AS name, rolsuper AS superuser, rolcanlogin AS login FROM pg_roles ORDER BY 1'
      case 'df':
        return "SELECT n.nspname AS schema, p.proname AS name FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace WHERE n.nspname NOT IN ('pg_catalog','information_schema') ORDER BY 1,2"
      case 'conninfo':
        return 'SELECT current_database() AS database, current_user AS user, inet_server_addr()::text AS server, version() AS version'
      case 'd':
        if (!t) return metaSql(kind, 'dt', '')
        return `SELECT column_name AS column, data_type AS type, is_nullable AS nullable, column_default AS default FROM information_schema.columns WHERE table_name = ${sqlLiteral(t.replace(/^.*\./, ''))} ORDER BY ordinal_position`
      default:
        return null
    }
  }
  if (kind === 'mysql') {
    switch (cmd) {
      case 'l':
      case 'list':
        return 'SHOW DATABASES'
      case 'dt':
        return 'SHOW FULL TABLES'
      case 'dv':
        return "SELECT table_name AS name FROM information_schema.views WHERE table_schema = DATABASE() ORDER BY 1"
      case 'di':
        return t ? `SHOW INDEX FROM \`${t.replace(/`/g, '')}\`` : null
      case 'du':
        return 'SELECT user AS name, server FROM mysql.user ORDER BY 1'
      case 'conninfo':
        return 'SELECT DATABASE() AS database, USER() AS user, VERSION() AS version'
      case 'd':
        if (!t) return 'SHOW FULL TABLES'
        return `DESCRIBE \`${t.replace(/`/g, '')}\``
      default:
        return null
    }
  }
  if (kind === 'mssql') {
    switch (cmd) {
      case 'l':
      case 'list':
        return 'SELECT name, state_desc AS state FROM sys.databases ORDER BY name'
      case 'dt':
        return 'SELECT s.name AS [schema], t.name AS [name] FROM sys.tables t JOIN sys.schemas s ON s.schema_id = t.schema_id ORDER BY 1,2'
      case 'dv':
        return 'SELECT s.name AS [schema], v.name AS [name] FROM sys.views v JOIN sys.schemas s ON s.schema_id = v.schema_id ORDER BY 1,2'
      case 'di':
        return 'SELECT t.name AS [table], i.name AS [index], i.type_desc AS [type] FROM sys.indexes i JOIN sys.tables t ON t.object_id = i.object_id WHERE i.name IS NOT NULL ORDER BY 1,2'
      case 'du':
        return "SELECT name, type_desc FROM sys.database_principals WHERE type NOT IN ('R') ORDER BY 1"
      case 'conninfo':
        return 'SELECT DB_NAME() AS [database], SUSER_NAME() AS [login], @@VERSION AS [version]'
      case 'd':
        if (!t) return metaSql(kind, 'dt', '')
        return `SELECT COLUMN_NAME AS [column], DATA_TYPE AS [type], IS_NULLABLE AS [nullable], COLUMN_DEFAULT AS [default] FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_NAME = ${sqlLiteral(t.replace(/^.*\./, ''))} ORDER BY ORDINAL_POSITION`
      default:
        return null
    }
  }
  return null
}

async function runSql(cfg: DbConnectConfig, sql: string): Promise<DbShellResult> {
  const r = await dbQuery(cfg, sql)
  if (!r.ok) return { ok: false, error: r.error, elapsedMs: r.elapsedMs }
  if (r.kind === 'rows') {
    return {
      ok: true,
      columns: r.columns,
      rows: r.rows,
      note: `${r.rowCount ?? r.rows?.length ?? 0} row(s)`,
      elapsedMs: r.elapsedMs
    }
  }
  if (r.kind === 'message') return { ok: true, text: r.message, elapsedMs: r.elapsedMs }
  return { ok: true, json: r.json, note: r.message, elapsedMs: r.elapsedMs }
}

async function sqlShell(cfg: DbConnectConfig, text: string): Promise<DbShellResult> {
  const body = text.trim()

  // \c <db> and USE <db> both need a fresh connection so later statements land
  // on the new database.
  const switchTo = /^\\c(?:onnect)?\s+([^\s;]+)$/i.exec(body) ?? /^use\s+([^\s;]+)\s*;?$/i.exec(body)
  if (switchTo) {
    const name = switchTo[1].replace(/^["'`[]|["'`\]]$/g, '')
    await dbClose(cfg.id)
    return { ok: true, text: `You are now connected to database "${name}".`, useDatabase: name, refreshSchema: true }
  }

  if (body.startsWith('\\')) {
    const m = /^\\(\w+)\s*(.*)$/s.exec(body)
    if (!m) throw new Error(`Invalid command: ${body}`)
    const sql = metaSql(cfg.kind, m[1].toLowerCase(), m[2])
    if (!sql) throw new Error(`\\${m[1]}${m[2] ? '' : ' (without an argument)'} is not supported here — type "help" for the list`)
    return runSql(cfg, sql)
  }

  const r = await runSql(cfg, body)
  // DDL changes what the schema sidebar should show.
  if (r.ok && /^\s*(create|drop|alter|truncate|rename)\b/i.test(body)) r.refreshSchema = true
  return r
}

// --------------------------------------------------------------------- redis

async function redisShell(cfg: DbConnectConfig, text: string): Promise<DbShellResult> {
  const r = await dbQuery(cfg, text)
  if (!r.ok) return { ok: false, error: r.error, elapsedMs: r.elapsedMs }
  const v = r.json
  if (v === null || v === undefined) return { ok: true, text: '(nil)', elapsedMs: r.elapsedMs }
  if (typeof v === 'string') return { ok: true, text: v, elapsedMs: r.elapsedMs }
  return { ok: true, json: v, elapsedMs: r.elapsedMs }
}

// ---------------------------------------------------------------- entrypoint

export async function dbShell(cfg: DbConnectConfig, line: string): Promise<DbShellResult> {
  const text = line.trim()
  if (!text) return { ok: true }

  const lower = text.toLowerCase()
  if (lower === 'clear' || lower === 'cls') return { ok: true, clear: true }
  if (lower === 'help' || lower === '?' || lower === '\\?' || lower === '\\h') {
    return { ok: true, text: HELP[cfg.kind] }
  }
  if (lower === 'exit' || lower === 'quit' || lower === '\\q') {
    return { ok: true, text: 'Switch to the Query tab to leave the shell — the connection stays open.' }
  }

  const started = Date.now()
  try {
    let r: DbShellResult
    if (cfg.kind === 'mongodb') r = await mongoShell(cfg, text)
    else if (cfg.kind === 'redis') r = await redisShell(cfg, text)
    else r = await sqlShell(cfg, text)
    return { ...r, elapsedMs: r.elapsedMs ?? Date.now() - started }
  } catch (err) {
    return {
      ok: false,
      error: err instanceof Error ? err.message : String(err),
      elapsedMs: Date.now() - started
    }
  }
}
