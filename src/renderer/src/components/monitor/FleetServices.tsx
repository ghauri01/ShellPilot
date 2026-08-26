import { useMemo, useState } from 'react'
import { ChevronDown, ChevronRight, CircleAlert, Network } from 'lucide-react'
import { useFleet } from '../../store/fleet'
import { clsx } from '../../lib/format'
import type { Server } from '../../types'

// Services and listening ports across the estate.
//
// Reads what the metrics poll already collected, so this opens no connections
// of its own — same arrangement as the capacity totals above it.
export function FleetServices({ servers }: { servers: Server[] }): React.JSX.Element | null {
  const hosts = useFleet((s) => s.hosts)
  const [open, setOpen] = useState<string | null>(null)

  const rows = useMemo(
    () =>
      servers
        .map((s) => ({ server: s, host: hosts[s.id] }))
        .filter((r) => r.host && (r.host.services !== null || r.host.listeners !== null))
        .map((r) => ({
          ...r,
          failed: (r.host.services ?? []).filter((u) => u.active === 'failed' || u.sub === 'failed'),
          running: (r.host.services ?? []).filter((u) => u.sub === 'running'),
          listeners: r.host.listeners ?? []
        })),
    [servers, hosts]
  )

  const totalFailed = rows.reduce((n, r) => n + r.failed.length, 0)

  // Nothing has reported a probe result yet, so there is nothing truthful to
  // say — better than a panel of zeroes that looks like an answer.
  if (rows.length === 0) return null

  return (
    <div className="fleet-services">
      <div className="row" style={{ gap: 8, alignItems: 'center', marginBottom: 8 }}>
        <b>Services and ports</b>
        <span className="server-meta">
          {rows.length} {rows.length === 1 ? 'host' : 'hosts'} reporting
        </span>
        {totalFailed > 0 && (
          <span className="badge danger">
            <CircleAlert size={12} /> {totalFailed} failed
          </span>
        )}
      </div>

      {rows.map(({ server, host, failed, running, listeners }) => {
        const isOpen = open === server.id
        return (
          <div className="list-row" key={server.id} style={{ flexWrap: 'wrap' }}>
            <button className="btn sm ghost" onClick={() => setOpen(isOpen ? null : server.id)}>
              {isOpen ? <ChevronDown size={13} /> : <ChevronRight size={13} />} {server.name}
            </button>
            <span className="spacer" />

            {host.services === null ? (
              // A host without systemd is not a host with no services, and
              // saying "0 services" would be a lie.
              <span className="server-meta">no systemd</span>
            ) : (
              <span className={clsx('server-meta', failed.length > 0 && 'danger')}>
                {failed.length > 0 ? `${failed.length} failed · ` : ''}
                {running.length} running
              </span>
            )}

            <span className="server-meta">
              <Network size={12} />{' '}
              {host.listeners === null
                ? 'no ss or netstat'
                : `${listeners.length} listening${host.listenerSource ? ` (${host.listenerSource})` : ''}`}
            </span>

            {isOpen && (
              <div style={{ width: '100%', marginTop: 8 }}>
                {failed.length > 0 && (
                  <div style={{ marginBottom: 8 }}>
                    <div className="s-desc">
                      <b>Failed units</b>
                    </div>
                    {failed.map((u) => (
                      <div key={u.name} className="s-desc danger">
                        {u.name} — {u.description || u.sub}
                      </div>
                    ))}
                  </div>
                )}

                {listeners.length > 0 && (
                  <table className="mini-table" style={{ width: '100%' }}>
                    <thead>
                      <tr>
                        <th>Port</th>
                        <th>Proto</th>
                        <th>Address</th>
                        <th>Process</th>
                      </tr>
                    </thead>
                    <tbody>
                      {listeners.map((l) => (
                        <tr key={`${l.proto}-${l.address}-${l.port}`}>
                          <td className="mono strong">{l.port}</td>
                          <td className="mono">{l.proto}</td>
                          <td className="mono">{l.address}</td>
                          <td className="mono">
                            {l.process ?? <span className="faint">not visible</span>}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                )}

                {listeners.length > 0 && !listeners.some((l) => l.process) && (
                  <div className="s-desc" style={{ marginTop: 6 }}>
                    Process names need root on most systems, so they are blank when the monitoring
                    account is unprivileged. The ports themselves are still accurate.
                  </div>
                )}
              </div>
            )}
          </div>
        )
      })}
    </div>
  )
}
