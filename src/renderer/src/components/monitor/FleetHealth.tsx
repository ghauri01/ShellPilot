import { useMemo, useState } from 'react'
import {
  ChevronDown,
  ChevronRight,
  CircleAlert,
  CircleCheck,
  Clock,
  HardDrive,
  Unplug
} from 'lucide-react'
import { useApp } from '../../store/app'
import { useFleet } from '../../store/fleet'
import { openSettings } from '../../store/nav'
import { bytes, clsx, duration } from '../../lib/format'
import type { PortListener } from '../../../../shared/ssh'
// Aliased: the summary type and the component below share a name, and the
// component is the one this module is about.
import type { FleetHealth as FleetSummary, HostRow, UnreachableRow } from './hostHealth'
import {
  coverageLine,
  diskLine,
  failureLine,
  splitListeners,
  summariseFleetHealth,
  unreachableLine
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
  const hasPorts = listeners !== null && listeners.length > 0
  const ports = hasPorts ? (
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

      {/* The same condition the toggle was drawn from. `listeners &&` alone
          let an empty array through — `[]` is truthy — so a host whose last
          service had just stopped rendered the "needs root to name the
          process" note under a heading with no ports above it. */}
      {open && hasPorts && <HostPorts listeners={listeners} source={row.listenerSource} />}
    </div>
  )
}

/**
 * A host the sampler could not ask. Deliberately not a HostRow with a red
 * border: an unreachable host is not a host with a problem on it, it is a host
 * we have no opinion about, and the two must not be read as the same claim.
 */
function UnreachableRowView({ row }: { row: UnreachableRow }): React.JSX.Element {
  const last = row.last
  return (
    <div className="list-row fh-row">
      <div className="row fh-line">
        <span className={clsx('status-dot', row.status)} />
        <b className="fh-name">{row.name}</b>
        <span className="spacer" />
        <span className="chip warn">
          <Unplug size={11} /> could not be checked
        </span>
      </div>

      {/* The sampler's own words. A paraphrase would cost the one detail that
          tells a refused connection apart from a wrong key. */}
      <div className="fh-note">
        {row.error} · last tried {duration(row.at)} ago
      </div>

      {last && (
        // What we knew before it went quiet, labelled as history so nobody
        // reads a stale port count as the state of the host right now.
        <div className="row fh-line">
          <span className="fh-meta">Last good check: {servicesMeta(last)}</span>
          <span className="spacer" />
          <span className="fh-meta">{portsLabel(last)}</span>
        </div>
      )}
    </div>
  )
}

/**
 * The panel before anything has been sampled. An empty section used to render
 * as nothing at all, which reads identically to "this feature does not exist"
 * and to "nothing is wrong" — the two answers a monitor most needs to keep
 * apart. It also happens to be the only place background checking is offered.
 */
function NotYetChecked({
  health,
  sampling
}: {
  health: FleetSummary
  sampling: boolean
}): React.JSX.Element {
  return (
    <section className="fleet-health">
      <div className="fh-head">
        <b>Fleet health</b>
        <span className="chip">
          <Clock size={11} /> Not checked yet
        </span>
        <span className="spacer" />
        {/* The same coverage line the filled panel carries, which here reads
            "0 of 10 servers reporting" — the fact the missing panel used to
            withhold. */}
        <span className="fh-meta">{coverageLine(health)}</span>
      </div>
      {sampling ? (
        <div className="fh-note">
          No host has reported yet. Background checking is on, so this fills in as hosts answer —
          failed services and disks close to full will be listed here.
        </div>
      ) : (
        <>
          <div className="fh-note">
            No host has reported yet. Background checking is off, so a host is only looked at while
            its card is on screen — nothing is watching for failed services or full disks in between.
            Turning it on in Settings → Monitoring sweeps the whole estate on a schedule and fills
            this panel in.
          </div>
          <button className="btn sm ghost" onClick={() => openSettings('monitoring')}>
            Open Monitoring settings
          </button>
        </>
      )}
    </section>
  )
}

export function FleetHealth({ servers }: { servers: Server[] }): React.JSX.Element | null {
  const hosts = useFleet((s) => s.hosts)
  const errors = useFleet((s) => s.errors)
  const sampling = useApp((s) => s.settings.fleetSamplingEnabled)
  const [showRest, setShowRest] = useState(false)

  const health = useMemo(
    () => summariseFleetHealth(servers, hosts, errors),
    [servers, hosts, errors]
  )

  // No servers at all: the monitor already says so in its own empty state, and
  // a health panel about nothing would be a second answer to a question the
  // page has already answered.
  if (health.totalServers === 0) return null

  // Nothing has answered and nothing has failed to answer. This used to render
  // as no panel at all, which told a user with ten servers exactly as much as
  // having no such feature would have.
  if (
    health.attention.length === 0 &&
    health.rest.length === 0 &&
    health.unreachable.length === 0
  ) {
    return <NotYetChecked health={health} sampling={sampling} />
  }

  const failures = failureLine(health)
  const disks = diskLine(health)
  const unreachable = unreachableLine(health)

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
        {unreachable && (
          <span className="chip warn">
            <Unplug size={11} /> {unreachable}
          </span>
        )}
        {/* The all-clear is only true of the hosts that answered, so an
            unreachable host withholds it: "nothing needs attention" beside a
            host nobody could reach is a claim the panel cannot make. */}
        {!failures && !disks && !unreachable && (
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

      {health.unreachable.length > 0 && (
        // Not folded away with the healthy hosts. A host nobody could reach is
        // an open question, and an open question the user has not seen is
        // indistinguishable from a host that is fine.
        <div className="fh-list">
          {health.unreachable.map((row) => (
            <UnreachableRowView key={row.id} row={row} />
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
