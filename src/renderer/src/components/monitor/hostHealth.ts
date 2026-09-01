import type { HostMetrics, PortListener, ServiceUnit } from '../../../../shared/ssh'
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

export interface FleetHealth {
  /** Hosts carrying something that stays broken until a person acts on it. */
  attention: HostRow[]
  /** Everything else that reported, in the order the caller supplied. */
  rest: HostRow[]
  /** Servers with no sample at all yet — offline, or not polled since launch. */
  silent: number
  totalServers: number
  failedUnits: number
  failingHosts: number
  diskHosts: number
  /** Reporting hosts whose services probe could not run. */
  blind: number
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
 */
export function summariseFleetHealth(
  servers: ServerRef[],
  hosts: Record<string, HostMetrics>
): FleetHealth {
  const attention: HostRow[] = []
  const rest: HostRow[] = []
  let silent = 0
  let failedUnits = 0
  let failingHosts = 0
  let diskHosts = 0
  let blind = 0

  for (const server of servers) {
    const host = hosts[server.id]
    if (!host) {
      silent++
      continue
    }
    const row = toRow(server, host)
    if (row.failed === null) blind++
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
    silent,
    totalServers: servers.length,
    failedUnits,
    failingHosts,
    diskHosts,
    blind
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
 * What the panel is speaking for. Says how much of the estate it can see, so a
 * clean bill of health is never mistaken for one that covers everything.
 */
export function coverageLine(h: FleetHealth): string {
  const reporting = h.attention.length + h.rest.length
  const parts = [
    reporting === h.totalServers
      ? `${reporting} ${plural(reporting, 'server')} reporting`
      : `${reporting} of ${h.totalServers} servers reporting`
  ]
  if (h.blind > 0) parts.push(`${h.blind} cannot list services`)
  return parts.join(' · ')
}
