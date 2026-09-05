import { useCallback, useState } from 'react'
import { Plus, RefreshCw, ServerCog } from 'lucide-react'
import { clsx } from '../../lib/format'
import { openSettings } from '../../store/nav'
import {
  checkUnitDraft,
  renderUnitFile,
  summariseUserUnits,
  type UnitDraft,
  type UnitRestart,
  type UserUnitsReading
} from '../../../../shared/userUnits'
import type { Server } from '../../types'

// What each server supervises for this account, read from its own systemd.
//
// The panel's job is one sentence, and it is not the unit list: a `--user`
// service stops when the account's last session ends unless that account is
// lingering, so a list of `running` units read over SSH can be a list of things
// that are about to stop. summariseUserUnits() decides that; this renders it
// first and the units underneath.

interface Row {
  serverId: string
  serverName: string
  reading: UserUnitsReading
}

export function ServicesPanel({ servers }: { servers: Server[] }): React.JSX.Element {
  // `null` until read, never `[]`. Rendering an empty list as "nothing is
  // supervised" before asking is the claim this app has been fixing all week.
  const [rows, setRows] = useState<Row[] | null>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  // Which server the form is open against, or null. One at a time on purpose:
  // "install this on all of them" is not a thing to make easy.
  const [writingFor, setWritingFor] = useState<{ id: string; name: string } | null>(null)
  const [draft, setDraft] = useState<UnitDraft>({
    name: '',
    description: '',
    execStart: '',
    restart: 'on-failure'
  })
  const [writeResult, setWriteResult] = useState<{ ok: boolean; text: string } | null>(null)

  const check = checkUnitDraft(draft)

  const install = async (): Promise<void> => {
    const target = servers.find((s) => s.id === writingFor?.id)
    if (!target) return
    const w = (
      window.shellpilot as
        | { services?: { write?: (t: unknown, d: UnitDraft) => Promise<{ ok: boolean; output?: string; error?: string }> } }
        | undefined
    )?.services?.write
    if (typeof w !== 'function') {
      setWriteResult({ ok: false, text: 'This build cannot write units. Restart the app to rebuild it.' })
      return
    }
    // Asked before it happens, and it names the server and the unit, because a
    // file is about to appear on a machine the operator is not looking at.
    if (
      !window.confirm(
        `Install ${draft.name} on ${writingFor?.name}?\n\nIt writes ~/.config/systemd/user/${draft.name} and enables it. It does NOT start it, and any existing unit of that name is backed up first.`
      )
    ) {
      return
    }
    const res = await w({ cfg: target }, draft)
    setWriteResult({ ok: res.ok === true, text: res.output ?? res.error ?? 'No answer.' })
    if (res.ok) {
      setWritingFor(null)
      await read()
    }
  }

  const bridge = (): { collect?: (t: unknown[]) => Promise<Row[]> } | undefined =>
    (window.shellpilot as { services?: { collect?: (t: unknown[]) => Promise<Row[]> } } | undefined)
      ?.services

  const read = useCallback(async (): Promise<void> => {
    const collect = bridge()?.collect
    if (typeof collect !== 'function') {
      setError('This build’s preload does not expose server services yet. Restart the app to rebuild it.')
      setRows([])
      return
    }
    setLoading(true)
    setError(null)
    try {
      const targets = servers.map((s) => ({ serverId: s.id, serverName: s.name, cfg: s }))
      setRows(await collect(targets))
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e))
    } finally {
      setLoading(false)
    }
  }, [servers])

  return (
    <div className="panel-body">
      <div className="panel-head">
        <div>
          <div className="panel-title">
            <ServerCog size={14} /> Server services
          </div>
          <div className="panel-subtitle">
            What each server&rsquo;s own systemd supervises for your account. Read-only — nothing is
            started, stopped or written here, because the server&rsquo;s supervisor is the one that
            is still there when ShellPilot is not.
          </div>
        </div>
        <button className="btn primary" disabled={loading || servers.length === 0} onClick={() => void read()}>
          <RefreshCw size={13} className={clsx(loading && 'spin')} /> {rows ? 'Refresh' : 'Read services'}
        </button>
      </div>

      {error && <div className="panel-note is-alarm">{error}</div>}

      {writingFor && (
        <div className="list-row" style={{ flexDirection: 'column', alignItems: 'stretch', gap: 6 }}>
          <div className="r-title">New service on {writingFor.name}</div>
          <div className="r-sub faint">
            Written to <code>~/.config/systemd/user/</code> and enabled, not started. The server’s
            own systemd owns the restart policy from then on — which is the point: it is there when
            ShellPilot is not.
          </div>
          <input
            className="input"
            placeholder="worker.service"
            aria-label="Unit name"
            value={draft.name}
            onChange={(e) => setDraft({ ...draft, name: e.target.value })}
          />
          <input
            className="input"
            placeholder="What it is, in one line"
            aria-label="Description"
            value={draft.description}
            onChange={(e) => setDraft({ ...draft, description: e.target.value })}
          />
          <input
            className="input mono"
            placeholder="/usr/local/bin/worker --queue main"
            aria-label="ExecStart"
            value={draft.execStart}
            onChange={(e) => setDraft({ ...draft, execStart: e.target.value })}
          />
          <select
            className="input"
            aria-label="Restart policy"
            value={draft.restart}
            onChange={(e) => setDraft({ ...draft, restart: e.target.value as UnitRestart })}
          >
            <option value="on-failure">Restart on failure</option>
            <option value="always">Always restart</option>
            <option value="no">Never restart</option>
          </select>

          {/* The exact bytes, before they are written. A file is about to appear
              on a machine nobody is looking at, and "trust me" is not a preview. */}
          {check.ok ? (
            <pre className="mono" style={{ fontSize: 11, whiteSpace: 'pre-wrap', margin: 0 }}>
              {renderUnitFile(draft)}
            </pre>
          ) : (
            <div className="s-note state-unknown">{check.reason}</div>
          )}

          <div className="row-actions">
            <button className="btn primary" disabled={!check.ok} onClick={() => void install()}>
              Install
            </button>
            <button className="btn" onClick={() => setWritingFor(null)}>
              Cancel
            </button>
          </div>
        </div>
      )}

      {writeResult && (
        <div className={clsx('panel-note', writeResult.ok ? '' : 'is-alarm')}>
          <span className="mono">{writeResult.text}</span>
        </div>
      )}

      {rows === null ? (
        <div className="panel-empty">
          <p className="panel-empty-title">Nothing read yet.</p>
          <p className="panel-empty-body">
            Press <b>Read services</b> to ask each server what it is supervising for you.
          </p>
        </div>
      ) : rows.length === 0 ? (
        <div className="panel-empty">
          <p className="panel-empty-title">No servers to ask.</p>
          <p className="panel-empty-body">
            Add a server to this workspace, or <button className="btn ghost sm" onClick={() => openSettings('modules')}>open Settings</button> to
            check which are in it.
          </p>
        </div>
      ) : (
        rows.map((r) => {
          const s = summariseUserUnits(r.reading)
          const shown = r.reading.units.filter((u) => u.load !== 'not-found')
          return (
            <div key={r.serverId} className="list-row" style={{ flexDirection: 'column', alignItems: 'stretch' }}>
              <div className="r-title">
                {r.serverName}{' '}
                <span className={clsx(s.level === 'ok' ? 'ok' : s.level === 'alarm' ? 'danger' : 'state-unknown')}>
                  · {s.level}
                </span>
              </div>
              {/* The headline first and the list second, deliberately: the list
                  is what people look at and the sentence is what they need. */}
              <div className={clsx('r-sub', s.level === 'alarm' && 'danger')}>{s.headline}</div>
              {r.reading.detail && <div className="r-sub faint mono">{r.reading.detail}</div>}
              <div className="row-actions" style={{ marginTop: 6 }}>
                <button
                  className="btn sm"
                  onClick={() => {
                    setWriteResult(null)
                    setWritingFor({ id: r.serverId, name: r.serverName })
                  }}
                >
                  <Plus size={12} /> New service
                </button>
              </div>
              {shown.length > 0 && (
                <table className="mini-table">
                  <tbody>
                    {shown.map((u) => (
                      <tr key={u.name}>
                        <td>{u.name}</td>
                        <td className={clsx(u.active === 'failed' && 'danger')}>{u.active}</td>
                        <td className="faint">{u.sub}</td>
                        <td className="faint">{u.description}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </div>
          )
        })
      )}
    </div>
  )
}
