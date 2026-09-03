import { useCallback, useEffect, useRef, useState } from 'react'
import { AlertTriangle, CheckCircle2, HelpCircle, Loader2, Lock, RefreshCw, ShieldAlert } from 'lucide-react'
import {
  DB_ANSWER_HELP,
  DB_QUESTION_LABEL,
  DB_QUESTION_WHY,
  formatBytes,
  formatCount,
  formatSeconds,
  type DbAnswer,
  type DbAnswerStatus,
  type DbOpsReport,
  type DbVerdictLevel,
  type MysqlBinlogsValue,
  type MysqlProcesslistValue,
  type MysqlReplicationChannel,
  type MysqlSizesValue,
  type PgLock,
  type PgReplicationValue,
  type PgSizesValue,
  type PgStatementsValue,
  type PgVacuumValue
} from '../../../../shared/dbOps'
import type { DbConnectConfig, DbKind } from '../../../../shared/db'

/**
 * The operations panel.
 *
 * Eight questions, each rendered as a SENTENCE first and a table second. That
 * ordering is the whole editorial point of roadmap item 18: "replication is 4h
 * 12m behind" is a judgement someone can act on, and a cell containing 15120 in
 * a tab nobody has open is not.
 *
 * The panel has no buttons that change anything. Every control here re-reads.
 * See the refusal at the top of src/shared/dbOps.ts for why there is no "kill
 * this blocking query" and no "vacuum this table".
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
function Detail({ answer, engine }: { answer: DbAnswer<unknown>; engine: 'postgres' | 'mysql' }): React.JSX.Element | null {
  if (answer.value === undefined || answer.value === null) return null

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
    if (v.tables.length === 0) return null
    return (
      <Table
        columns={['table', 'xid age', '% of max', 'dead rows', 'last autovacuum']}
        rows={v.tables.slice(0, 8).map((t) => [
          `${t.schema}.${t.name}`,
          formatCount(t.xidAge),
          t.freezeFraction === null ? null : `${(t.freezeFraction * 100).toFixed(1)}%`,
          formatCount(t.deadTuples),
          t.lastAutovacuumAgeSeconds === null ? null : `${formatSeconds(t.lastAutovacuumAgeSeconds)} ago`
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
          formatSeconds(l.waitingSeconds),
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
}

export function DbOpsPanel({ cfg, kind }: Props): React.JSX.Element {
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
      else setReport(r)
    } catch (err) {
      if (mine !== generation.current) return
      setError(err instanceof Error ? err.message : String(err))
    } finally {
      if (mine === generation.current) setLoading(false)
    }
  }, [cfg])

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

  const engine = kind === 'postgres' ? 'postgres' : 'mysql'

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
        Read-only. Every statement here is a SELECT or a SHOW — nothing on this page changes the
        server, and there is no control that kills a session, vacuums a table or purges a log.
      </div>

      {error && (
        <div className="chip danger" style={{ marginBottom: 10 }}>
          <AlertTriangle size={12} /> {error}
        </div>
      )}

      {!report && !loading && !error && (
        <div className="faint" style={{ fontSize: 12 }}>
          Nothing has been read yet.
        </div>
      )}

      {report?.answers.map((a) => (
        <Card key={a.id} answer={a}>
          <Detail answer={a} engine={engine} />
        </Card>
      ))}
    </div>
  )
}
