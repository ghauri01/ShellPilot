import { useCallback, useEffect, useRef, useState } from 'react'
import { AlertTriangle, CheckCircle2, HelpCircle, Loader2, Lock, RefreshCw, ShieldAlert } from 'lucide-react'
import {
  DB_ANSWER_HELP,
  DB_QUESTIONS_BY_ENGINE,
  DB_QUESTION_LABEL,
  DB_QUESTION_WHY,
  formatBytes,
  formatCount,
  formatSeconds,
  worstVerdict,
  type DbAnswer,
  type DbAnswerStatus,
  type DbOpsReport,
  type DbVerdictLevel,
  isMongoClientOp,
  supportsDbOps,
  type DbOpsEngine,
  type MongoCurrentOpValue,
  type MongoIndexesValue,
  type MongoOplogValue,
  type MongoReplicationValue,
  type MongoSizesValue,
  type MysqlBinlogsValue,
  type MysqlProcesslistValue,
  type MysqlReplicationChannel,
  type MysqlSizesValue,
  type PgConnectionsValue,
  type PgLock,
  type PgReplicationValue,
  type PgSizesValue,
  type PgStatementsValue,
  type PgVacuumValue,
  type RedisKeyspaceValue,
  type RedisMemoryValue,
  type RedisReplicationValue,
  type RedisSlowlogValue
} from '../../../../shared/dbOps'
import type { DbConnectConfig, DbKind } from '../../../../shared/db'

/**
 * The operations panel.
 *
 * Eight or nine questions depending on the engine, each rendered as a SENTENCE
 * first and a table second. That ordering is the whole editorial point of
 * roadmap item 18: "replication is 4h 12m behind" is a judgement someone can
 * act on, and a cell containing 15120 in a tab nobody has open is not.
 *
 * The panel has no buttons that change anything. Every control here re-reads.
 * See the refusal at the top of src/shared/dbOps.ts for why there is no "kill
 * this blocking query", no "vacuum this table", no "drop this unused index" and
 * no "raise maxmemory".
 *
 * Four engines now, and the tables below are per engine because the same
 * question id means different rows: `replication` is walsenders on Postgres,
 * channels on MySQL, members on MongoDB and a link on Redis. The engine comes
 * from the REPORT and not from the connection's kind, so a report can never be
 * rendered with the wrong engine's columns.
 */

const LEVEL_ICON: Record<DbVerdictLevel, typeof CheckCircle2> = {
  ok: CheckCircle2,
  watch: AlertTriangle,
  alarm: ShieldAlert,
  unknown: HelpCircle
}

const LEVEL_CLASS: Record<DbVerdictLevel, string> = {
  ok: 'ok',
  watch: 'warn',
  alarm: 'danger',
  unknown: ''
}

/** A status that means "we did not get the whole truth" gets a lock, so it can
 *  never be mistaken at a glance for a clean read. */
const GUARDED: DbAnswerStatus[] = ['denied', 'partial']

function StatusChip({ status }: { status: DbAnswerStatus }): React.JSX.Element | null {
  if (status === 'ok') return null
  return (
    <span className={`chip${GUARDED.includes(status) ? ' warn' : ''}`} title={DB_ANSWER_HELP[status]}>
      {GUARDED.includes(status) && <Lock size={11} />} {status === 'partial' ? 'partial view' : status}
    </span>
  )
}

function Card({ answer, children }: { answer: DbAnswer<unknown>; children?: React.ReactNode }): React.JSX.Element {
  const Icon = LEVEL_ICON[answer.verdict.level]
  return (
    <section
      style={{
        border: '1px solid var(--border-subtle)',
        borderRadius: 6,
        padding: 12,
        marginBottom: 10
      }}
    >
      <div className="row" style={{ gap: 8, alignItems: 'flex-start' }}>
        <Icon size={15} className={LEVEL_CLASS[answer.verdict.level] || undefined} />
        <div style={{ minWidth: 0, flex: 1 }}>
          <div className="row" style={{ gap: 6 }}>
            <strong style={{ fontSize: 12 }}>{DB_QUESTION_LABEL[answer.id]}</strong>
            <StatusChip status={answer.status} />
          </div>
          {/* The judgement, before any number. */}
          <div style={{ fontSize: 13, marginTop: 3 }}>{answer.verdict.headline}</div>
          {answer.verdict.because && (
            <div className="faint" style={{ fontSize: 11, marginTop: 4 }}>
              {answer.verdict.because}
            </div>
          )}
          {answer.detail && (
            <div className="mono faint" style={{ fontSize: 11, marginTop: 4, whiteSpace: 'pre-wrap' }}>
              {answer.detail}
            </div>
          )}
          <div className="faint" style={{ fontSize: 10, marginTop: 6, opacity: 0.7 }}>
            {DB_QUESTION_WHY[answer.id]}
          </div>
          {children}
        </div>
      </div>
    </section>
  )
}

function Table({ columns, rows }: { columns: string[]; rows: (string | number | null)[][] }): React.JSX.Element {
  return (
    <div style={{ overflowX: 'auto', marginTop: 8 }}>
      <table className="table" style={{ fontSize: 11, width: '100%' }}>
        <thead>
          <tr>
            {columns.map((c) => (
              <th key={c} style={{ textAlign: 'left', padding: '2px 8px 2px 0' }}>
                {c}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.map((r, i) => (
            <tr key={i}>
              {r.map((cell, j) => (
                <td key={j} className={j === 0 ? 'mono' : undefined} style={{ padding: '2px 8px 2px 0' }}>
                  {cell === null ? <span className="faint">—</span> : cell}
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

/** The numbers behind each judgement. Deliberately below it, and deliberately
 *  short — a table long enough to scroll is a table nobody reads. */
function Detail({ answer, engine }: { answer: DbAnswer<unknown>; engine: DbOpsEngine }): React.JSX.Element | null {
  if (answer.value === undefined || answer.value === null) return null

  // ---- MongoDB -----------------------------------------------------------

  if (answer.id === 'replication' && engine === 'mongodb') {
    const v = answer.value as MongoReplicationValue
    if (v.members.length === 0) return null
    return (
      <Table
        columns={['member', 'state', 'health', 'behind primary', 'ping']}
        rows={v.members.map((m) => [
          m.name,
          m.stateStr,
          m.health === 1 ? 'up' : 'DOWN',
          // Never a zero here. A member that did not report an optime says so
          // in words; the epoch it actually sends is not a position.
          m.optimeIsEpoch ? 'did not report' : m.lagSeconds === null ? null : formatSeconds(m.lagSeconds),
          // And a round trip that was never made is not 0 ms.
          m.pingMs === null ? null : `${m.pingMs} ms`
        ])}
      />
    )
  }

  if (answer.id === 'oplog') {
    const v = answer.value as MongoOplogValue
    if (!v.present) return null
    return (
      <Table
        columns={['window', 'member uptime', 'has it rolled?', 'entries', 'configured max']}
        rows={[[
          formatSeconds(v.windowSeconds),
          formatSeconds(v.uptimeSeconds),
          // The distinction the question exists for, in the table as well as in
          // the sentence.
          v.neverRolled === null ? null : v.neverRolled ? 'not yet — the window is still growing' : 'yes — this is the real window',
          formatCount(v.count),
          formatBytes(v.maxSizeBytes)
        ]]}
      />
    )
  }

  if (answer.id === 'indexes') {
    const v = answer.value as MongoIndexesValue
    if (v.indexes.length === 0) return null
    return (
      <Table
        columns={['index', 'reads', 'counting since', 'size']}
        rows={v.indexes.slice(0, 8).map((i) => [
          `${i.collection}.${i.name}`,
          formatCount(i.ops),
          // Shown beside every row, because "0 reads" without it is a claim
          // about a window nobody stated.
          i.sinceMs === null ? null : new Date(i.sinceMs).toISOString().replace('T', ' ').slice(0, 16),
          i.sizeBytes === null ? null : formatBytes(i.sizeBytes)
        ])}
      />
    )
  }

  if (answer.id === 'currentop') {
    const v = answer.value as MongoCurrentOpValue
    const client = v.operations.filter(isMongoClientOp)
    if (client.length === 0) return null
    return (
      <Table
        columns={['op', 'namespace', 'running', 'plan', 'waiting for lock']}
        rows={client.slice(0, 8).map((o) => [
          o.op,
          o.ns,
          formatSeconds(o.secondsRunning),
          o.planSummary,
          o.waitingForLock === null ? null : o.waitingForLock ? 'yes' : 'no'
        ])}
      />
    )
  }

  if (answer.id === 'sizes' && engine === 'mongodb') {
    const v = answer.value as MongoSizesValue
    return (
      <>
        {v.databases.length > 0 && (
          <Table
            columns={['database', 'on disk']}
            rows={v.databases.slice(0, 8).map((d) => [d.name, formatBytes(d.sizeOnDiskBytes)])}
          />
        )}
        {v.collections.length > 0 && (
          <Table
            columns={['collection', 'documents', 'data', 'storage', 'indexes']}
            rows={v.collections.slice(0, 8).map((c) => [
              c.name,
              formatCount(c.documents),
              formatBytes(c.dataBytes),
              formatBytes(c.storageBytes),
              formatBytes(c.indexBytes)
            ])}
          />
        )}
      </>
    )
  }

  // ---- Redis -------------------------------------------------------------

  if (answer.id === 'memory') {
    const v = answer.value as RedisMemoryValue
    return (
      <Table
        columns={['used', 'limit', 'policy', 'fragmentation']}
        rows={[[
          formatBytes(v.usedBytes),
          // Three different cells for three different facts, and none of them
          // is a blank a reader would fill in as zero.
          !v.maxmemoryReported ? 'not reported' : v.maxmemoryBytes === 0 ? 'none — unlimited' : formatBytes(v.maxmemoryBytes),
          v.policy,
          v.fragmentationRatio === null ? null : v.fragmentationRatio.toFixed(2)
        ]]}
      />
    )
  }

  if (answer.id === 'replication' && engine === 'redis') {
    const v = answer.value as RedisReplicationValue
    if (v.role === 'slave' || v.role === 'replica') {
      return (
        <Table
          columns={['master', 'link', 'last heard from', 'down for', 'offset']}
          rows={[[
            v.masterHost,
            v.masterLinkStatus,
            // -1 is Redis's sentinel and never reaches this cell as a number.
            v.masterLastIoSentinel ? 'no measurement' : v.masterLastIoSeconds === null ? null : `${formatSeconds(v.masterLastIoSeconds)} ago`,
            v.linkDownSeconds === null ? null : formatSeconds(v.linkDownSeconds),
            formatCount(v.replicaReplOffset)
          ]]}
        />
      )
    }
    if (v.replicas.length === 0) return null
    return (
      <Table
        columns={['replica', 'state', 'offset', 'lag']}
        rows={v.replicas.map((r) => [r.ip ? `${r.ip}:${r.port ?? '?'}` : null, r.state, formatCount(r.offsetBytes), r.lagSeconds === null ? null : formatSeconds(r.lagSeconds)])}
      />
    )
  }

  if (answer.id === 'slowlog' && engine === 'redis') {
    const v = answer.value as RedisSlowlogValue
    if (v.entries.length === 0) return null
    return (
      <Table
        columns={['command', 'arguments', 'took', 'when', 'client']}
        rows={v.entries.slice(0, 8).map((e) => [
          // The command NAME. The argument values are not carried this far —
          // see parseRedisSlowlog for why.
          e.command,
          e.argumentCount,
          e.microseconds === null ? null : `${(e.microseconds / 1000).toFixed(1)} ms`,
          e.atMs === null ? null : new Date(e.atMs).toISOString().replace('T', ' ').slice(0, 19),
          e.clientAddr
        ])}
      />
    )
  }

  if (answer.id === 'keyspace') {
    const v = answer.value as RedisKeyspaceValue
    if (v.databases.length === 0) return null
    return (
      <Table
        columns={['database', 'keys', 'with an expiry', 'never expire']}
        rows={v.databases.map((d) => [
          d.name,
          formatCount(d.keys),
          formatCount(d.expires),
          d.keys === null || d.expires === null ? null : formatCount(d.keys - d.expires)
        ])}
      />
    )
  }


  if (answer.id === 'replication' && engine === 'postgres') {
    const v = answer.value as PgReplicationValue
    if (v.role === 'standby') {
      return (
        <Table
          columns={['receive LSN', 'replay LSN', 'unapplied', 'last replay']}
          rows={[[v.receiveLsn, v.replayLsn, formatBytes(v.applyLagBytes), v.neverReplayed ? null : formatSeconds(v.replayAgeSeconds) + ' ago']]}
        />
      )
    }
    if (v.replicas.length === 0) return null
    return (
      <Table
        columns={['standby', 'client', 'state', 'sync', 'replay lag', 'unreplayed']}
        rows={v.replicas.map((r) => [
          r.applicationName,
          r.clientAddr,
          r.state,
          r.syncState,
          r.replayLagSeconds === null ? null : formatSeconds(r.replayLagSeconds),
          r.replayLagBytes === null ? null : formatBytes(r.replayLagBytes)
        ])}
      />
    )
  }

  if (answer.id === 'replication' && engine === 'mysql') {
    const channels = answer.value as MysqlReplicationChannel[]
    if (channels.length === 0) return null
    return (
      <Table
        columns={['channel', 'source', 'IO', 'SQL', 'behind']}
        rows={channels.map((c) => [
          c.channel,
          c.sourceHost,
          c.ioRunning,
          c.sqlRunning,
          // The one cell in this app that must never say 0 when the server said
          // NULL. It says so in words rather than leaving an empty box.
          c.secondsBehind === null ? 'NULL — broken' : formatSeconds(c.secondsBehind)
        ])}
      />
    )
  }

  if (answer.id === 'autovacuum') {
    const v = answer.value as PgVacuumValue
    const databases = v.databases ?? []
    if (v.tables.length === 0 && databases.length === 0) return null
    return (
      <>
        {databases.length > 0 && (
          <Table
            columns={['database', 'xid age', '% of freeze_max_age', '% to wraparound']}
            rows={databases.slice(0, 8).map((d) => [
              d.name,
              formatCount(d.xidAge),
              d.freezeFraction === null ? null : `${(d.freezeFraction * 100).toFixed(1)}%`,
              d.wraparoundFraction === null ? null : `${(d.wraparoundFraction * 100).toFixed(1)}%`
            ])}
          />
        )}
        {v.tables.length > 0 && (
          <Table
            columns={['table', 'xid age', '% of max', 'dead rows', 'last autovacuum']}
            rows={v.tables.slice(0, 8).map((t) => [
              // pg_toast.pg_toast_16384 is not a name anybody can act on.
              t.relkind === 't' && t.parent ? `${t.parent} (TOAST)` : `${t.schema}.${t.name}`,
              formatCount(t.xidAge),
              t.freezeFraction === null ? null : `${(t.freezeFraction * 100).toFixed(1)}%`,
              formatCount(t.deadTuples),
              t.lastAutovacuumAgeSeconds === null ? null : `${formatSeconds(t.lastAutovacuumAgeSeconds)} ago`
            ])}
          />
        )}
      </>
    )
  }

  if (answer.id === 'connections' && engine === 'postgres') {
    const v = answer.value as PgConnectionsValue
    if (v.states.length === 0) return null
    return (
      <Table
        columns={['state', 'sessions', 'oldest']}
        rows={v.states.map((st) => [
          // NULL is not a state. It is a backend this account may count and may
          // not read, and writing "unknown" in the cell would read as one.
          st.state ?? 'hidden from this account',
          st.n,
          st.oldestSeconds === null ? null : `${formatSeconds(st.oldestSeconds)} ago`
        ])}
      />
    )
  }

  if (answer.id === 'locks') {
    const locks = answer.value as PgLock[]
    if (locks.length === 0) return null
    return (
      <Table
        columns={['pid', 'user', 'waiting', 'blocked by', 'query']}
        rows={locks.map((l) => [
          l.pid,
          l.username,
          // formatSeconds(null) is "unknown", and that is the point: a wait this
          // account may not read is not a wait of zero seconds.
          l.redacted ? 'hidden' : formatSeconds(l.waitingSeconds),
          l.blockedBy.join(', '),
          l.query
        ])}
      />
    )
  }

  if (answer.id === 'sizes' && engine === 'postgres') {
    const v = answer.value as PgSizesValue
    return (
      <Table
        columns={['table', 'total', 'heap', 'indexes']}
        rows={v.tables.slice(0, 8).map((t) => [
          `${t.schema ? `${t.schema}.` : ''}${t.name}`,
          formatBytes(t.totalBytes),
          formatBytes(t.heapBytes),
          formatBytes(t.indexBytes)
        ])}
      />
    )
  }

  if (answer.id === 'sizes' && engine === 'mysql') {
    const v = answer.value as MysqlSizesValue
    return (
      <Table
        columns={['table', 'engine', 'rows', 'data', 'indexes', 'free']}
        rows={v.tables.slice(0, 8).map((t) => [
          `${t.schema}.${t.name}`,
          t.engine,
          formatCount(t.rows),
          formatBytes(t.dataBytes),
          formatBytes(t.indexBytes),
          formatBytes(t.freeBytes)
        ])}
      />
    )
  }

  if (answer.id === 'binlogs') {
    const v = answer.value as MysqlBinlogsValue
    if (v.files.length === 0) return null
    return <Table columns={['file', 'size']} rows={v.files.map((f) => [f.name, formatBytes(f.bytes)])} />
  }

  if (answer.id === 'processlist') {
    const v = answer.value as MysqlProcesslistValue
    if (v.processes.length === 0) return null
    return (
      <Table
        columns={['id', 'user', 'db', 'command', 'time', 'state']}
        rows={v.processes.slice(0, 8).map((p) => [p.id, p.user, p.db, p.command, formatSeconds(p.seconds), p.state])}
      />
    )
  }

  if (answer.id === 'statements') {
    const v = answer.value as PgStatementsValue
    // The empty-list case is the point of the whole question: a missing
    // extension must SAY it is missing, never render as a clean empty table.
    if (v.statements.length === 0) return null
    return (
      <Table
        columns={['statement', 'calls', 'total', 'mean']}
        rows={v.statements.slice(0, 8).map((s) => [
          s.query,
          formatCount(s.calls),
          formatSeconds((s.totalExecMs ?? 0) / 1000),
          `${(s.meanExecMs ?? 0).toFixed(1)} ms`
        ])}
      />
    )
  }

  return null
}

interface Props {
  cfg: DbConnectConfig
  kind: DbKind
  /**
   * The worst verdict on the page, reported upward after every read.
   *
   * worstVerdict() was documented as "the one the tab badge shows" and nothing
   * imported it — the Operations tab was a plain button, so ranking `unknown`
   * above `ok` had no effect on anything anybody could see. The badge is the
   * whole point of that ranking: the panel is only mounted while the tab is
   * open, and the state worth showing is the one on the tab nobody has open.
   */
  onVerdict?: (level: DbVerdictLevel) => void
}

export function DbOpsPanel({ cfg, kind, onVerdict }: Props): React.JSX.Element {
  const [report, setReport] = useState<DbOpsReport | null>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  // Guards against a read for connection A landing after the user moved to B —
  // the cross-server leak tests/dockerPanel.test.tsx exists to prevent.
  const generation = useRef(0)

  const read = useCallback(async () => {
    const mine = ++generation.current
    setLoading(true)
    setError(null)
    try {
      const r = await window.shellpilot?.db?.ops?.(cfg)
      if (mine !== generation.current) return
      if (!r) setError('The preload bridge does not expose operational reads. Restart the app.')
      else if (!r.ok) setError(r.error ?? 'The read failed.')
      else {
        setReport(r)
        onVerdict?.(worstVerdict(r.answers))
      }
    } catch (err) {
      if (mine !== generation.current) return
      setError(err instanceof Error ? err.message : String(err))
    } finally {
      if (mine === generation.current) setLoading(false)
    }
  }, [cfg, onVerdict])

  // A new connection must never show the previous one's answers, not even for
  // the frame before the fresh read lands.
  //
  // `setLoading(false)` is not tidying-up: the in-flight read for the previous
  // connection returns without touching state (its generation is stale), so
  // without this the spinner never clears and the panel is dead until the
  // operator finds the button under it. Caught by a test, not by review.
  useEffect(() => {
    generation.current++
    setReport(null)
    setError(null)
    setLoading(false)
  }, [cfg.id])

  // From the report and not from `kind`, so the tables can never be drawn with
  // another engine's columns while a stale report is still on screen.
  const engine = report?.engine ?? null

  return (
    <div style={{ padding: 12, overflowY: 'auto', flex: 1, minHeight: 0 }}>
      <div className="row" style={{ marginBottom: 10 }}>
        <button className="btn primary sm" disabled={loading} onClick={() => void read()}>
          {loading ? <Loader2 size={13} className="spin" /> : <RefreshCw size={13} />} Read server state
        </button>
        <span className="spacer" />
        {report && (
          <span className="faint" style={{ fontSize: 11 }}>
            {report.answers.length} questions in {report.elapsedMs} ms
          </span>
        )}
      </div>

      <div className="faint" style={{ fontSize: 11, marginBottom: 10 }}>
        Read-only. Every statement here is a SELECT, a SHOW, a MongoDB read command or a Redis
        INFO — nothing on this page changes the server, and there is no control that kills a
        session or an operation, vacuums a table, purges a log, drops an index or sets a config.
      </div>

      {error && (
        <div className="chip danger" style={{ marginBottom: 10 }}>
          <AlertTriangle size={12} /> {error}
        </div>
      )}

      {!report && !loading && !error && (
        <div className="faint" style={{ fontSize: 12 }}>
          Nothing has been read yet.{' '}
          {supportsDbOps(kind) &&
            `${DB_QUESTIONS_BY_ENGINE[kind].length} questions will be asked: ${DB_QUESTIONS_BY_ENGINE[kind]
              .map((id) => DB_QUESTION_LABEL[id].toLowerCase())
              .join(', ')}.`}
        </div>
      )}

      {report && engine &&
        report.answers.map((a) => (
          <Card key={a.id} answer={a}>
            <Detail answer={a} engine={engine} />
          </Card>
        ))}
    </div>
  )
}
