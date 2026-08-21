export type DbKind = 'postgres' | 'mysql' | 'mssql' | 'mongodb' | 'redis'

// Optional SSH jump: the driver connects to a local forward instead of the
// database host directly.
export interface DbSshConfig {
  serverId?: string
  host: string
  port: number
  username: string
  auth: 'password' | 'key' | 'agent'
  password?: string
  keyPath?: string
  privateKey?: string
  passphrase?: string
}

export interface DbConnectConfig {
  id: string
  kind: DbKind
  host: string
  port: number
  username: string
  password?: string
  database?: string
  ssl?: boolean
  // Full connection string / URI (e.g. mongodb+srv://user:pass@cluster/db).
  // When present it takes precedence over the discrete host/port/... fields.
  uri?: string
  ssh?: DbSshConfig
}

export interface DbTestResult {
  ok: boolean
  error?: string
  version?: string
}

export type DbResultKind = 'rows' | 'json' | 'value' | 'message'

export interface DbQueryResult {
  ok: boolean
  error?: string
  kind?: DbResultKind
  columns?: string[]
  rows?: unknown[][]
  json?: unknown
  message?: string
  elapsedMs?: number
  rowCount?: number
}

export interface DbInfo {
  ok: boolean
  error?: string
  // A flat list of "schema objects": databases, tables or collections.
  databases?: string[]
  tables?: string[]
}

export const DB_DEFAULT_PORT: Record<DbKind, number> = {
  postgres: 5432,
  mysql: 3306,
  mssql: 1433,
  mongodb: 27017,
  redis: 6379
}

export const DB_LABEL: Record<DbKind, string> = {
  postgres: 'PostgreSQL',
  mysql: 'MySQL',
  mssql: 'SQL Server',
  mongodb: 'MongoDB',
  redis: 'Redis'
}
