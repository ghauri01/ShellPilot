import { useCallback, useEffect, useRef, useState } from 'react'
import {
  Play,
  Plug,
  RefreshCw,
  Table2,
  CheckCircle2,
  AlertTriangle,
  ChevronDown,
  FileCode2,
  TerminalSquare,
  Activity,
  Loader2,
  Pencil,
  Trash2,
  X
} from 'lucide-react'
import { useApp, useWorkspaceServers } from '../../store/app'
import { clsx } from '../../lib/format'
import { useClickOutside } from '../../hooks/useClickOutside'
import { DbShell } from './DbShell'
import { DbOpsPanel } from './DbOpsPanel'
import { toast } from '../../store/toast'
import { KIND_COLOR, KIND_SHORT } from './DatabaseSidebar'
import { sshHopFor } from '../../lib/ssh'
import { withVaultUnlock } from '../../lib/withVaultUnlock'
import { classifyConnectionError, errorText } from '../../lib/connectionError'
import { openDatabaseCreator, openDatabaseEditor } from '../../store/dbEditor'
import { openSettings } from '../../store/nav'
import { supportsDbOps } from '../../../../shared/dbOps'
import type { DatabaseConn, DbKind, Server } from '../../types'
import type { DbConnectConfig, DbInfo, DbQueryResult, DbTestResult } from '../../../../shared/db'

const DEFAULT_QUERY: Record<DbKind, string> = {
  postgres: 'SELECT * FROM information_schema.tables LIMIT 20;',
  mysql: 'SHOW TABLES;',
  mssql: 'SELECT name FROM sys.tables;',
  mongodb: '{ "listCollections": 1 }',
  redis: 'PING'
}
const KIND_LABEL: Record<DbKind, string> = {
  postgres: 'PostgreSQL',
  mysql: 'MySQL',
  mssql: 'SQL Server',
  mongodb: 'MongoDB',
  redis: 'Redis'
}

function cfgOf(db: DatabaseConn, servers: Server[]): DbConnectConfig {
  const jump = db.sshServerId ? servers.find((s) => s.id === db.sshServerId) : undefined
  return {
    id: db.id,
    kind: db.kind,
    host: db.host,
    port: db.port,
    username: db.username,
    database: db.database,
    ssl: db.ssl,
    ssh: jump ? sshHopFor(jump) : undefined
  }
}

// One sentence for a connection failure, picked from what the driver said.
// The driver's own words stay on screen underneath; this is the part that says
// which setting to go and look at.
function connSummary(db: DatabaseConn, jump: Server | undefined, error: string | undefined): string {
  switch (classifyConnectionError(error)) {
    case 'refused':
      return `Nothing is listening on ${db.host}:${db.port}.`
    case 'unreachable':
      return `${db.host} did not answer in time.`
    case 'auth':
      return `${db.host} rejected the username or password.`
    case 'host-key':
      return `${jump ? jump.name : 'The SSH server'} presented a different host key, so the tunnel was refused.`
    case 'key-missing':
      return `${jump ? `${jump.name}'s` : 'The'} private key file is not where the connection says it is.`
    case 'passphrase':
      return `${jump ? `${jump.name}'s` : 'The'} private key needs a passphrase.`
    case 'permission':
      return `${db.username || 'This user'} is not allowed to open ${db.database || 'this database'}.`
    default:
      return `Could not connect to ${db.name}.`
  }
}

export function DatabaseView({ db }: { db: DatabaseConn }): React.JSX.Element {
  const deleteDatabase = useApp((s) => s.deleteDatabase)
  const servers = useWorkspaceServers()
  // The bastion this database is reached through, when it has one. Named in
  // failures so "the key is missing" says whose key.
  const jumpServer = db.sshServerId ? servers.find((s) => s.id === db.sshServerId) : undefined
  const [query, setQuery] = useState(DEFAULT_QUERY[db.kind])
  const [result, setResult] = useState<DbQueryResult | null>(null)
  const [running, setRunning] = useState(false)
  // `message` is the sentence a person reads; `detail` is the driver's own text,
  // kept beside it so nothing is lost when the sentence is the short version.
  const [conn, setConn] = useState<{
    phase: 'idle' | 'connecting' | 'ok' | 'error'
    message?: string
    detail?: string
  }>({ phase: 'idle' })
  const [info, setInfo] = useState<DbInfo | null>(null)
  const [dbName, setDbName] = useState(db.database)
  // Database picker. `typed` is true only while the user is actively typing, so
  // opening the list from the chevron always shows every database rather than
  // just the ones matching the currently selected name.
  const [pickerOpen, setPickerOpen] = useState(false)
  const [typed, setTyped] = useState(false)
  const [mode, setMode] = useState<'query' | 'shell' | 'ops'>('query')
  // Operational reads exist for PostgreSQL and MySQL/MariaDB only. MongoDB and
  // Redis answer completely different questions (replica-set state and oplog
  // window; eviction policy and persistence) and get their own pass rather than
  // a thin imitation of this one, so the tab is absent rather than empty.
  const hasOps = supportsDbOps(db.kind)
  const pickerRef = useRef<HTMLDivElement>(null)
  useClickOutside(pickerRef, () => setPickerOpen(false), pickerOpen)

  const cfgWith = useCallback(
    (dbn: string): DbConnectConfig => ({ ...cfgOf(db, servers), database: dbn }),
    [db, servers]
  )

  // Every call that reaches the database can need a credential the vault holds
  // — its own password, or the bastion's key. Routing them through this means a
  // locked vault produces an unlock dialog and the call finishing, rather than
  // a rejected promise nobody catches.
  const unlocked = useCallback(
    <T,>(run: () => Promise<T>): Promise<T> => withVaultUnlock(`Connecting to ${db.name}`, run),
    [db.name]
  )

  const loadInfo = useCallback(
    async (dbn: string): Promise<DbInfo | undefined> => {
      try {
        const i = await unlocked(async () => window.shellpilot?.db.info(cfgWith(dbn)))
        if (i) setInfo(i)
        return i
      } catch {
        // The connection banner already carries the failure; a second copy of
        // it here would just be the same problem counted twice.
        return undefined
      }
    },
    [cfgWith, unlocked]
  )

  const init = useCallback(
    async (dbn: string): Promise<void> => {
      setConn({ phase: 'connecting' })
      let r: DbTestResult | undefined
      try {
        r = await unlocked(async () => window.shellpilot?.db.test(cfgWith(dbn)))
      } catch (err) {
        const detail = errorText(err)
        setConn({ phase: 'error', message: connSummary(db, jumpServer, detail), detail })
        return
      }
      if (!r?.ok) {
        setConn({ phase: 'error', message: connSummary(db, jumpServer, r?.error), detail: r?.error })
        return
      }
      setConn({ phase: 'ok', message: r.version })
      const i = await loadInfo(dbn)
      // MongoDB connection strings often omit the database (e.g. replica-set
      // URIs), so queries would hit the empty default db. Auto-pick a real
      // database so the user sees their data.
      if (db.kind === 'mongodb' && !dbn && i?.databases?.length) {
        const pick = i.databases.find((d) => !['admin', 'local', 'config'].includes(d)) ?? i.databases[0]
        if (pick) {
          setDbName(pick)
          await loadInfo(pick)
        }
      }
    },
    [cfgWith, loadInfo, unlocked, db, jumpServer]
  )

  useEffect(() => {
    setQuery(DEFAULT_QUERY[db.kind])
    setResult(null)
    setInfo(null)
    setDbName(db.database)
    void init(db.database)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [db.id])

  const test = (): void => void init(dbName)

  const selectDb = (dbn: string): void => {
    setDbName(dbn)
    setTyped(false)
    setResult(null)
    void loadInfo(dbn)
  }

  const allDbs = info?.databases ?? []
  const shownDbs = typed
    ? allDbs.filter((d) => d.toLowerCase().includes(dbName.trim().toLowerCase()))
    : allDbs

  const run = useCallback(async () => {
    if (!query.trim()) return
    setRunning(true)
    let r: DbQueryResult | undefined
    try {
      r = await unlocked(async () => window.shellpilot?.db.query(cfgWith(dbName), query))
    } catch (err) {
      r = { ok: false, error: errorText(err) }
    }
    setResult(r ?? { ok: false, error: 'The database did not answer.' })
    if (r?.ok && conn.phase !== 'ok') setConn({ phase: 'ok' })
    setRunning(false)
  }, [query, conn.phase, cfgWith, dbName, unlocked])

  const onKey = (e: React.KeyboardEvent): void => {
    if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
      e.preventDefault()
      void run()
    }
  }

  const insertTable = (t: string): void => {
    if (db.kind === 'mongodb') setQuery(`{ "find": "${t}", "limit": 20 }`)
    else if (db.kind === 'redis') setQuery(`KEYS *`)
    else setQuery(`SELECT * FROM ${t} LIMIT 100;`)
  }

  return (
    <div className="main">
      <div className="viewbar">
        <span className="mono" style={{ fontWeight: 700, color: KIND_COLOR[db.kind] }}>
          {KIND_LABEL[db.kind]}
        </span>
        <b>{db.name}</b>
        <span className="server-meta mono">
          {db.host}
          {db.port ? `:${db.port}` : ''}
        </span>
        {db.kind === 'mongodb' ? (
          <div ref={pickerRef} style={{ position: 'relative', display: 'flex', alignItems: 'center' }}>
            <input
              className="input"
              style={{ height: 26, width: 170, padding: '0 22px 0 8px' }}
              placeholder="database"
              title="Database (type or pick)"
              value={dbName}
              onFocus={() => setPickerOpen(true)}
              onChange={(e) => {
                setTyped(true)
                setPickerOpen(true)
                setDbName(e.target.value)
              }}
              onBlur={(e) => {
                // Ignore blur caused by clicking an entry in the picker itself —
                // that path commits through selectDb already.
                if (pickerRef.current?.contains(e.relatedTarget as Node)) return
                setPickerOpen(false)
                if (e.target.value !== db.database || typed) selectDb(e.target.value)
              }}
              onKeyDown={(e) => {
                if (e.key === 'Enter') {
                  setPickerOpen(false)
                  selectDb((e.target as HTMLInputElement).value)
                }
              }}
            />
            <button
              className="icon-btn sm"
              title="Show all databases"
              style={{ marginLeft: -22, height: 22, width: 22 }}
              onClick={() => {
                setTyped(false)
                setPickerOpen((o) => !o)
              }}
            >
              <ChevronDown size={13} />
            </button>
            {pickerOpen && (
              <div className="menu" style={{ top: 30, left: 0, minWidth: 190, maxHeight: 300, overflowY: 'auto' }}>
                <div className="menu-label">Databases ({allDbs.length})</div>
                {shownDbs.map((d) => (
                  <button
                    key={d}
                    className="menu-item"
                    onClick={() => {
                      setPickerOpen(false)
                      selectDb(d)
                    }}
                  >
                    <span className="mono">{d}</span>
                  </button>
                ))}
                {shownDbs.length === 0 && (
                  <div className="faint" style={{ padding: '4px 10px 8px', fontSize: 11 }}>
                    {allDbs.length ? 'No match' : 'None listed — the user may lack listDatabases. Type a name.'}
                  </div>
                )}
              </div>
            )}
          </div>
        ) : (
          dbName && <span className="chip">{dbName}</span>
        )}
        <div className="row" style={{ gap: 4, marginLeft: 4 }}>
          <button className={`btn sm${mode === 'query' ? ' primary' : ''}`} onClick={() => setMode('query')}>
            <FileCode2 size={13} /> Query
          </button>
          <button className={`btn sm${mode === 'shell' ? ' primary' : ''}`} onClick={() => setMode('shell')}>
            <TerminalSquare size={13} /> Shell
          </button>
          {hasOps && (
            <button className={`btn sm${mode === 'ops' ? ' primary' : ''}`} onClick={() => setMode('ops')}>
              <Activity size={13} /> Operations
            </button>
          )}
        </div>
        <span className="spacer" />
        {conn.phase === 'connecting' && <Loader2 size={14} className="spin" />}
        {conn.phase === 'ok' && (
          <span className="chip ok" title={conn.message}>
            <CheckCircle2 size={12} /> connected
          </span>
        )}
        {conn.phase === 'error' && (
          <span className="chip danger" title={conn.message}>
            <AlertTriangle size={12} /> error
          </span>
        )}
        <button className="btn sm" onClick={test}>
          <Plug size={13} /> Test
        </button>
        <button
          className="btn sm danger"
          onClick={() => {
            deleteDatabase(db.id)
            void window.shellpilot?.secrets.delete(db.id)
            toast(`${db.name} deleted`)
          }}
        >
          <Trash2 size={13} />
        </button>
      </div>

      {conn.phase === 'error' && (
        <div className="conn-error">
          <AlertTriangle size={14} />
          <div style={{ minWidth: 0 }}>
            <div className="selectable">{conn.message}</div>
            {conn.detail && conn.detail !== conn.message && (
              <div className="mono faint selectable" style={{ fontSize: 11 }}>
                {conn.detail}
              </div>
            )}
          </div>
          <span className="spacer" />
          {/* A host key that no longer matches is not fixed by editing the
              connection — the saved key has to be reviewed and forgotten
              first, so that is the button that gets offered instead. */}
          {classifyConnectionError(conn.detail) === 'host-key' ? (
            <button className="btn sm" onClick={() => openSettings('security')}>
              Review saved keys
            </button>
          ) : (
            <button className="btn sm" onClick={() => openDatabaseEditor(db.id)}>
              <Pencil size={13} /> Edit connection
            </button>
          )}
          <button className="btn sm" onClick={test}>
            Retry
          </button>
        </div>
      )}

      <div style={{ display: 'flex', flex: 1, minHeight: 0 }}>
        <div className="db-schema">
          <div className="sidebar-title" style={{ padding: '10px 12px 6px' }}>
            {db.kind === 'redis' ? 'Keyspace' : db.kind === 'mongodb' ? 'Collections' : 'Tables'}
          </div>
          <div style={{ overflowY: 'auto', flex: 1 }}>
            {conn.phase === 'error' && (
              <div className="faint" style={{ padding: 12, fontSize: 12 }}>Not connected, so nothing can be listed.</div>
            )}
            {(info?.tables ?? []).map((t) => (
              <div key={t} className="tree-row" onClick={() => insertTable(t)}>
                <Table2 size={13} className="faint" />
                <span className="label">{t}</span>
              </div>
            ))}
            {info && (info.tables?.length ?? 0) === 0 && (
              <div className="faint" style={{ padding: 12, fontSize: 12 }}>No objects</div>
            )}
          </div>
        </div>

        <div style={{ display: 'flex', flexDirection: 'column', flex: 1, minWidth: 0 }}>
          {mode === 'ops' && hasOps ? (
            <DbOpsPanel cfg={cfgWith(dbName)} kind={db.kind} />
          ) : mode === 'shell' ? (
            <DbShell
              cfg={cfgWith(dbName)}
              kind={db.kind}
              dbName={dbName}
              onUseDatabase={selectDb}
              onSchemaChanged={() => void loadInfo(dbName)}
            />
          ) : (
            <>
          <div style={{ padding: 12, borderBottom: '1px solid var(--border-subtle)' }}>
            <textarea
              className="textarea"
              style={{ minHeight: 110, width: '100%' }}
              value={query}
              spellCheck={false}
              onChange={(e) => setQuery(e.target.value)}
              onKeyDown={onKey}
              placeholder={
                db.kind === 'redis'
                  ? 'Redis command, e.g. GET mykey'
                  : db.kind === 'mongodb'
                    ? 'MongoDB command as JSON, e.g. { "find": "users", "limit": 10 }'
                    : 'SQL query…'
              }
            />
            <div className="row" style={{ marginTop: 8 }}>
              <button className="btn primary sm" disabled={running} onClick={() => void run()}>
                {running ? <Loader2 size={13} className="spin" /> : <Play size={13} />} Run
                <span className="kbd" style={{ marginLeft: 6 }}>
                  Ctrl ⏎
                </span>
              </button>
              <span className="spacer" />
              {result?.elapsedMs != null && (
                <span className="faint" style={{ fontSize: 11 }}>
                  {result.rowCount != null ? `${result.rowCount} rows · ` : ''}
                  {result.elapsedMs} ms
                </span>
              )}
              <button className="icon-btn sm" title="Refresh schema" onClick={() => void test()}>
                <RefreshCw size={14} />
              </button>
            </div>
          </div>

          <div style={{ flex: 1, minHeight: 0, overflow: 'auto' }}>
            <Results result={result} />
          </div>
            </>
          )}
        </div>
      </div>
    </div>
  )
}

function Results({ result }: { result: DbQueryResult | null }): React.JSX.Element {
  if (!result) {
    return <div className="faint" style={{ padding: 20, fontSize: 13 }}>Run a query to see results.</div>
  }
  if (!result.ok) {
    return (
      <div className="log-line error" style={{ padding: 16, whiteSpace: 'pre-wrap' }}>
        <span className="lvl">ERROR</span>
        <span className="selectable">{result.error}</span>
      </div>
    )
  }
  if (result.kind === 'rows' && result.columns) {
    const rows = (result.rows ?? []).slice(0, 500)
    return (
      <table className="table" style={{ fontSize: 12 }}>
        <thead>
          <tr>
            <th style={{ width: 40 }}>#</th>
            {result.columns.map((c) => (
              <th key={c}>{c}</th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.map((r, i) => (
            <tr key={i}>
              <td className="faint">{i + 1}</td>
              {r.map((v, j) => (
                <td key={j} className="mono selectable">
                  {v === null ? <span className="faint">NULL</span> : String(v)}
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    )
  }
  if (result.kind === 'message') {
    return <div style={{ padding: 16 }}>{result.message}</div>
  }
  // Array of documents (e.g. MongoDB find) → render as a table.
  const j = result.json
  if (Array.isArray(j) && j.length > 0 && j.every((x) => x && typeof x === 'object' && !Array.isArray(x))) {
    const cols = Array.from(new Set(j.flatMap((o) => Object.keys(o as object)))).slice(0, 40)
    const cell = (v: unknown): string =>
      v === null || v === undefined
        ? ''
        : typeof v === 'object'
          ? JSON.stringify(v)
          : String(v)
    return (
      <table className="table" style={{ fontSize: 12 }}>
        <thead>
          <tr>
            <th style={{ width: 40 }}>#</th>
            {cols.map((c) => (
              <th key={c}>{c}</th>
            ))}
          </tr>
        </thead>
        <tbody>
          {(j as Record<string, unknown>[]).slice(0, 500).map((o, i) => (
            <tr key={i}>
              <td className="faint">{i + 1}</td>
              {cols.map((c) => (
                <td key={c} className="mono selectable">
                  {c in o ? cell(o[c]) : <span className="faint">—</span>}
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    )
  }
  return (
    <pre className="selectable" style={{ padding: 16, fontSize: 12, fontFamily: 'var(--font-mono)', whiteSpace: 'pre-wrap' }}>
      {JSON.stringify(result.json ?? result.message ?? null, null, 2)}
    </pre>
  )
}

export function DatabaseWorkspace(): React.JSX.Element {
  const databases = useApp((s) => s.databases)
  const activeId = useApp((s) => s.activeDatabaseId)
  const openIds = useApp((s) => s.openDatabaseIds)
  const setActive = useApp((s) => s.setActiveDatabase)
  const closeDatabase = useApp((s) => s.closeDatabase)

  const open = openIds.map((id) => databases.find((d) => d.id === id)).filter((d): d is DatabaseConn => !!d)
  const active = open.find((d) => d.id === activeId) ?? open[0]

  if (!active) {
    return (
      <div className="main">
        <div className="empty">
          <div className="empty-icon">
            <Table2 size={26} />
          </div>
          <h3>No database selected</h3>
          <p>Add a database connection, then select it to run queries.</p>
          <button className="btn primary" onClick={openDatabaseCreator}>
            <Plug size={15} /> Add Database
          </button>
        </div>
      </div>
    )
  }
  // Every open database stays mounted and is hidden when inactive, so its
  // shell history, results and connection survive switching tabs.
  return (
    <div className="main">
      <div className="tabbar">
        {open.map((d) => (
          <div
            key={d.id}
            className={clsx('tab', d.id === active.id && 'active')}
            onClick={() => setActive(d.id)}
          >
            <span className="mono" style={{ fontSize: 9, fontWeight: 700, color: KIND_COLOR[d.kind] }}>
              {KIND_SHORT[d.kind]}
            </span>
            <span className="title">{d.name}</span>
            <button
              className="close"
              title="Close"
              onClick={(e) => {
                e.stopPropagation()
                closeDatabase(d.id)
              }}
            >
              <X size={12} />
            </button>
          </div>
        ))}
      </div>
      {open.map((d) => (
        <div
          key={d.id}
          style={{ display: d.id === active.id ? 'flex' : 'none', flex: 1, minHeight: 0 }}
        >
          <DatabaseView db={d} />
        </div>
      ))}
    </div>
  )
}
