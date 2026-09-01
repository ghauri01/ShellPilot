import type { HostMetrics, PortListener, ServiceUnit } from '../../../../shared/ssh'
import type { FleetError } from '../../store/fleet'
import type { Server } from '../../types'

// Turning a fleet of raw metric samples into the answer to one question:
// is anything broken, where, and what is it.
//
// Pure so the ordering and the counting can be pinned by tests — they are the
// part of this screen that a reader trusts without checking.

/** Only the fields the fleet summary needs; keeps the tests free of fixtures. */
export type ServerRef = Pick<Server, 'id' | 'name' | 'status'>

/**
 * Bar colouring for a percentage. Shared with the metric cards so the attention
 * list and the red bar on a card can never disagree about what "too high" is.
 */
export function level(v: number): 'ok' | 'warn' | 'danger' {
  return v > 85 ? 'danger' : v > 65 ? 'warn' : 'ok'
}

/**
 * A disk over this mark is listed as needing attention. Deliberately the same
 * number `level` calls danger, so a host in the list is exactly a host whose
 * disk bar is red further down the page.
 */
export const DISK_DANGER = 85

export interface HostRow {
  id: string
  name: string
  status: Server['status']
  /**
   * Failed units, or null when systemd is not on the host at all. Null is not
   * an empty list: "nothing has failed" and "we cannot see whether anything
   * has failed" are different answers and must never render the same.
   */
  failed: ServiceUnit[] | null
  /** Running unit count, or null for the same reason as `failed`. */
  running: number | null
  /** null when the host has neither ss nor netstat. */
  listeners: PortListener[] | null
  listenerSource: HostMetrics['listenerSource']
  diskPct: number
  diskUsed: number
  diskTotal: number
  diskCritical: boolean
  needsAttention: boolean
}

/**
 * A host the sampler could not ask at all. Its own shape rather than a HostRow
 * with a flag, because it answers a different question: not "is this host
 * healthy" but "we do not know, and here is why".
 */
export interface UnreachableRow {
  id: string
  name: string
  status: Server['status']
  /** What the sampler reported, verbatim — e.g. "Connection refused". */
  error: string
  /** When the failure was recorded. */
  at: number
  /**
   * The last sample taken before the host stopped answering, or null if it has
   * never answered. Kept because a host that was fine ten minutes ago and is
   * unreachable now is worth showing as both — the store deliberately does not
   * discard the metrics when it records the error.
   */
  last: HostRow | null
}

export interface FleetHealth {
  /** Hosts carrying something that stays broken until a person acts on it. */
  attention: HostRow[]
  /** Everything else that reported, in the order the caller supplied. */
  rest: HostRow[]
  /**
   * Hosts the sampler could not reach. They are not in `attention` or `rest`:
   * a stale sample rendered as current is the failure mode this whole
   * distinction exists to prevent.
   */
  unreachable: UnreachableRow[]
  /**
   * Servers we have neither a sample nor an error for — never polled since
   * launch. A server that failed is not silent; it is unreachable, and it has
   * told us something.
   */
  silent: number
  totalServers: number
  failedUnits: number
  failingHosts: number
  diskHosts: number
  /** Reporting hosts whose services probe could not run. */
  blind: number
  /** Reporting hosts whose port probe could not run — neither ss nor netstat. */
  portBlind: number
}

function isFailed(u: ServiceUnit): boolean {
  return u.active === 'failed' || u.sub === 'failed'
}

function toRow(server: ServerRef, host: HostMetrics): HostRow {
  const failed = host.services === null ? null : host.services.filter(isFailed)
  const running = host.services === null ? null : host.services.filter((u) => u.sub === 'running').length
  // A host that reported no disk at all (an unusual df) must not read as 0%
  // full and certainly must not raise an alarm.
  const diskCritical = host.diskTotal > 0 && host.diskPct > DISK_DANGER
  return {
    id: server.id,
    name: server.name,
    status: server.status,
    failed,
    running,
    listeners: host.listeners,
    listenerSource: host.listenerSource,
    diskPct: host.diskPct,
    diskUsed: host.diskUsed,
    diskTotal: host.diskTotal,
    diskCritical,
    needsAttention: (failed?.length ?? 0) > 0 || diskCritical
  }
}

/**
 * Splits the estate into what needs a person and what does not.
 *
 * Only two things qualify as needing attention: a failed unit and a full disk.
 * Both stay broken until someone acts. CPU and memory spikes recover on their
 * own, the cards below already colour them, and the resource-alert
 * notifications already chase them — putting them here would fill the section
 * with things that fix themselves, which is how an alert list stops being read.
 *
 * `errors` is what the sampler could not ask, and it wins over any sample we
 * still hold for that host: the numbers are from before the host went quiet,
 * so showing them as this host's current state would be a lie told in the
 * shape of an answer.
 */
export function summariseFleetHealth(
  servers: ServerRef[],
  hosts: Record<string, HostMetrics>,
  errors: Record<string, FleetError> = {}
): FleetHealth {
  const attention: HostRow[] = []
  const rest: HostRow[] = []
  const unreachable: UnreachableRow[] = []
  let silent = 0
  let failedUnits = 0
  let failingHosts = 0
  let diskHosts = 0
  let blind = 0
  let portBlind = 0

  for (const server of servers) {
    const host = hosts[server.id]
    const failure = errors[server.id]
    if (failure) {
      unreachable.push({
        id: server.id,
        name: server.name,
        status: server.status,
        error: failure.error,
        at: failure.at,
        last: host ? toRow(server, host) : null
      })
      continue
    }
    if (!host) {
      silent++
      continue
    }
    const row = toRow(server, host)
    if (row.failed === null) blind++
    if (row.listeners === null) portBlind++
    if (row.failed && row.failed.length > 0) {
      failedUnits += row.failed.length
      failingHosts++
    }
    if (row.diskCritical) diskHosts++
    ;(row.needsAttention ? attention : rest).push(row)
  }

  // Failed units ahead of disk pressure: a unit that is down is an outage
  // already, a disk that is filling is one that has not happened yet.
  //
  // The number of failures is deliberately not part of the key. A host going
  // from two failures to one has not changed what it needs from you, and rows
  // that reshuffle while you are reading them are their own kind of unusable.
  // Only a change of kind moves a row, and that is an event worth noticing.
  attention.sort(
    (a, b) => rank(b) - rank(a) || a.name.localeCompare(b.name)
  )

  return {
    attention,
    rest,
    unreachable,
    silent,
    totalServers: servers.length,
    failedUnits,
    failingHosts,
    diskHosts,
    blind,
    portBlind
  }
}

function rank(row: HostRow): number {
  return (row.failed?.length ?? 0) > 0 ? 1 : 0
}

export interface ListenerGroups {
  /** Bound to every interface or to a routable address — reachable off-box. */
  exposed: PortListener[]
  /** Bound to loopback — only processes on the host itself can reach these. */
  loopback: PortListener[]
}

/** 127.0.0.0/8 and ::1. `*` means every interface, so it is not loopback. */
export function isLoopback(address: string): boolean {
  return address === '::1' || address === 'localhost' || /^127\./.test(address)
}

/**
 * Groups a port list by whether the outside world can reach it, which is the
 * question a port list is actually opened to answer. Sorted here rather than
 * trusted from the probe, so the grouping does not depend on the main process
 * happening to keep its current order.
 */
export function splitListeners(listeners: PortListener[]): ListenerGroups {
  const byPort = (a: PortListener, b: PortListener): number =>
    a.port - b.port || a.proto.localeCompare(b.proto) || a.address.localeCompare(b.address)
  return {
    exposed: listeners.filter((l) => !isLoopback(l.address)).sort(byPort),
    loopback: listeners.filter((l) => isLoopback(l.address)).sort(byPort)
  }
}

function plural(n: number, one: string, many = `${one}s`): string {
  return n === 1 ? one : many
}

/** "4 failed services on 3 hosts", or null when nothing has failed. */
export function failureLine(h: FleetHealth): string | null {
  if (h.failedUnits === 0) return null
  return `${h.failedUnits} failed ${plural(h.failedUnits, 'service')} on ${h.failingHosts} ${plural(h.failingHosts, 'host')}`
}

/** "2 hosts low on disk", or null when none is. */
export function diskLine(h: FleetHealth): string | null {
  if (h.diskHosts === 0) return null
  return `${h.diskHosts} ${plural(h.diskHosts, 'host')} low on disk`
}

/**
 * "2 hosts could not be checked", or null when every host answered. Its own
 * line rather than a share of the failure count: these hosts are not known to
 * be broken, and counting them as failures would be inventing an outage.
 */
export function unreachableLine(h: FleetHealth): string | null {
  if (h.unreachable.length === 0) return null
  const n = h.unreachable.length
  return `${n} ${plural(n, 'host')} could not be checked`
}

/**
 * What the panel is speaking for. Says how much of the estate it can see, so a
 * clean bill of health is never mistaken for one that covers everything.
 *
 * Each probe gets its own clause because each can fail on its own: a host
 * without systemd still lists its ports, and a host without ss still lists its
 * units. "Cannot list ports" is not "no ports", for the same reason a null
 * listener array is not an empty one.
 */
export function coverageLine(h: FleetHealth): string {
  const reporting = h.attention.length + h.rest.length
  const parts = [
    reporting === h.totalServers
      ? `${reporting} ${plural(reporting, 'server')} reporting`
      : `${reporting} of ${h.totalServers} ${plural(h.totalServers, 'server')} reporting`
  ]
  if (h.blind > 0) parts.push(`${h.blind} cannot list services`)
  if (h.portBlind > 0) parts.push(`${h.portBlind} cannot list ports`)
  return parts.join(' · ')
}
