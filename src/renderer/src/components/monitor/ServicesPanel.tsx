import { useCallback, useState } from 'react'
import { RefreshCw, ServerCog } from 'lucide-react'
import { clsx } from '../../lib/format'
import { openSettings } from '../../store/nav'
import {
  summariseUserUnits,
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
