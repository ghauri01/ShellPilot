import { useMemo, useState } from 'react'
import { ChevronDown, ChevronRight, CircleAlert, CircleCheck, HardDrive } from 'lucide-react'
import { useFleet } from '../../store/fleet'
import { bytes, clsx } from '../../lib/format'
import type { PortListener } from '../../../../shared/ssh'
import type { HostRow } from './hostHealth'
import {
  coverageLine,
  diskLine,
  failureLine,
  splitListeners,
  summariseFleetHealth
} from './hostHealth'
import type { Server } from '../../types'

// Fleet health.
//
// Reads what the metrics poll already collected, so this opens no connections
// of its own — same arrangement as the capacity totals beside it.
//
// Hosts needing attention get their own region rather than a place at the top
// of one long sorted list. Sorting by health means every row moves whenever
// any host changes state; a labelled region means a host crosses one visible
// boundary and the rows around it stay where they were.

/** Ports, grouped by whether anything off-box can reach them. */
function PortTable({ rows }: { rows: PortListener[] }): React.JSX.Element {
  return (
    <table className="mini-table fh-ports-table">
      <thead>
        <tr>
          <th>Port</th>
          <th>Proto</th>
          <th>Address</th>
          <th>Process</th>
        </tr>
      </thead>
      <tbody>
        {rows.map((l) => (
          <tr key={`${l.proto}-${l.address}-${l.port}`}>
            <td className="mono strong">{l.port}</td>
            <td className="mono">{l.proto}</td>
            <td className="mono">{l.address}</td>
            {/* An em dash rather than "not visible" on every row: the reason is
                said once below the table instead of seventy-five times. */}
            <td className="mono">{l.process ?? <span className="faint">—</span>}</td>
          </tr>
        ))}
      </tbody>
    </table>
  )
}

/** Only ever rendered for a host that has ports to show. */
function HostPorts({
  listeners,
  source
}: {
  listeners: PortListener[]
  source: HostRow['listenerSource']
}): React.JSX.Element {
  const groups = useMemo(() => splitListeners(listeners), [listeners])
  const unnamed = !listeners.some((l) => l.process)
  return (
    <div className="fh-ports">
      {groups.exposed.length > 0 && (
        <>
          <div className="fh-group">
            Reachable from the network <span className="faint">{groups.exposed.length}</span>
          </div>
          <PortTable rows={groups.exposed} />
        </>
      )}
      {groups.loopback.length > 0 && (
        <>
          <div className="fh-group">
            Local only <span className="faint">{groups.loopback.length}</span>
          </div>
          <PortTable rows={groups.loopback} />
        </>
      )}
      {unnamed && source && (
        // Why the Process column is blank. The probe name belongs in a
        // sentence that explains it, not appended to a count as "(ss)".
        <div className="fh-note">
          The ports were read with {source}, which needs root to name the process behind each one.
          The port numbers themselves are accurate.
        </div>
      )}
    </div>
  )
}

function servicesMeta(row: HostRow): string {
  // null is not zero: a host without systemd has not told us that nothing
  // failed, it has told us nothing at all.
  return row.running === null
    ? 'services not visible — no systemd'
    : `${row.running} running`
}

function portsLabel(row: HostRow): string {
  if (row.listeners === null) return 'ports not visible — no ss or netstat'
  if (row.listeners.length === 0) return 'no listening ports'
  return `${row.listeners.length} listening ${row.listeners.length === 1 ? 'port' : 'ports'}`
}

function HostRowView({
  row,
  attention
}: {
  row: HostRow
  attention: boolean
}): React.JSX.Element {
  const [open, setOpen] = useState(false)
  const failed = row.failed ?? []

  // A host with no ports to show gets a statement, not a control. A toggle
  // that opens onto a restatement of its own label is a dead affordance.
  const listeners = row.listeners
  const ports =
    listeners && listeners.length > 0 ? (
      <button className="btn sm ghost fh-ports-toggle" onClick={() => setOpen(!open)}>
        {open ? <ChevronDown size={13} /> : <ChevronRight size={13} />} {portsLabel(row)}
      </button>
    ) : (
      <span className="fh-meta">{portsLabel(row)}</span>
    )

  return (
    <div className={clsx('list-row', 'fh-row', attention && 'attention')}>
      <div className="row fh-line">
        <span className={clsx('status-dot', row.status)} />
        <b className="fh-name">{row.name}</b>
        <span className="spacer" />
        {attention ? (
          <>
            {failed.length > 0 && (
              <span className="chip danger">
                <CircleAlert size={11} /> {failed.length} failed
              </span>
            )}
            {row.diskCritical && (
              <span className="chip warn">
                <HardDrive size={11} /> disk {row.diskPct.toFixed(0)}%
              </span>
            )}
          </>
        ) : (
          <>
            <span className="fh-meta">{servicesMeta(row)}</span>
            {ports}
          </>
        )}
      </div>

      {attention && failed.length > 0 && (
        <ul className="fh-units">
          {failed.map((u) => (
            <li key={u.name}>
              <b>{u.name}</b>
              {u.description ? ` — ${u.description}` : ''}
            </li>
          ))}
        </ul>
      )}

      {attention && row.diskCritical && (
        // The chip on the line above already carries the percentage; repeating
        // it here would spend a line saying nothing new.
        <div className="fh-pressure">
          {bytes(row.diskUsed)} of {bytes(row.diskTotal)} used on the root filesystem.
        </div>
      )}

      {attention && (
        <div className="row fh-line">
          <span className="fh-meta">{servicesMeta(row)}</span>
          <span className="spacer" />
          {ports}
        </div>
      )}

      {open && listeners && <HostPorts listeners={listeners} source={row.listenerSource} />}
    </div>
  )
}

export function FleetHealth({ servers }: { servers: Server[] }): React.JSX.Element | null {
  const hosts = useFleet((s) => s.hosts)
  const [showRest, setShowRest] = useState(false)

  const health = useMemo(() => summariseFleetHealth(servers, hosts), [servers, hosts])

  // Nothing has reported a probe result yet, so there is nothing truthful to
  // say — better than a panel of zeroes that looks like an answer.
  if (health.attention.length === 0 && health.rest.length === 0) return null

  const failures = failureLine(health)
  const disks = diskLine(health)

  return (
    <section className="fleet-health">
      <div className="fh-head">
        <b>Fleet health</b>
        {failures && (
          <span className="chip danger">
            <CircleAlert size={11} /> {failures}
          </span>
        )}
        {disks && (
          <span className="chip warn">
            <HardDrive size={11} /> {disks}
          </span>
        )}
        {!failures && !disks && (
          <span className="chip ok">
            <CircleCheck size={11} /> Nothing needs attention
          </span>
        )}
        <span className="spacer" />
        <span className="fh-meta">{coverageLine(health)}</span>
      </div>

      {health.attention.length > 0 && (
        <div className="fh-list">
          {health.attention.map((row) => (
            <HostRowView key={row.id} row={row} attention />
          ))}
        </div>
      )}

      {health.rest.length > 0 && (
        // The healthy hosts are reference material, so they are one click away
        // rather than thirteen rows of scanning between you and the failures.
        <>
          <button className="btn sm ghost fh-rest-toggle" onClick={() => setShowRest(!showRest)}>
            {showRest ? <ChevronDown size={13} /> : <ChevronRight size={13} />} {health.rest.length}{' '}
            {health.rest.length === 1 ? 'other host' : 'other hosts'}
          </button>
          {showRest && (
            <div className="fh-list">
              {health.rest.map((row) => (
                <HostRowView key={row.id} row={row} attention={false} />
              ))}
            </div>
          )}
        </>
      )}
    </section>
  )
}
