import type { HostMetrics } from '../../../shared/ssh'

// Search across everything the fleet sampler already knows.
//
// The monitor collects every systemd unit and every listening socket on every
// host on every sweep, renders the two or three a card has room for, and throws
// the rest away. "Which host is running postgres" and "what is listening on
// 6379 anywhere" are answerable from data already in memory, and were only
// unanswerable because nothing looked.
//
// The hard part is not matching. It is saying honestly what was searched.
// A result list of three, drawn from four hosts out of fifteen, is a lie told
// by omission unless the gap is on screen — and the gaps here are real and
// varied: a host nobody has sampled yet, a container with no systemd, a box
// where the port probe could not run, a host that has gone unreachable since
// its last good sample. Each is a different reason for absence and each is
// reported separately. That is why `coverage` is not optional.

export type FleetMatchKind = 'unit' | 'port' | 'host'

export interface FleetMatch {
  kind: FleetMatchKind
  serverId: string
  serverName: string
  /** When the sample this match came from was taken. */
  at: number
  /** "nginx.service", "tcp/443", or the host's own name. */
  label: string
  /** Unit description, owning process, kernel — whatever identifies it further. */
  detail: string
  /** Short state tag: "failed", "0.0.0.0", "running". */
  badge?: string
  /**
   * The host has failed to answer since this sample was taken, so the row is
   * the last thing known rather than the current truth. Kept and marked rather
   * than dropped: "postgres was on that box ten minutes ago and the box is now
   * unreachable" is more useful than silence, and much more useful than an
   * unmarked row implying it is still there.
   */
  stale?: boolean
}

/**
 * Why a host is not represented in the results.
 *
 * Every field is a list of server names rather than a count, because "3 hosts
 * could not be searched" prompts the question this is supposed to answer.
 */
export interface FleetCoverage {
  /** Hosts with usable data behind this search. */
  searched: string[]
  /** Never sampled — background checking off, or not swept yet. */
  notChecked: string[]
  /** Sampled, but systemd is not present, so no unit can match. */
  noServiceView: string[]
  /** Sampled, but neither ss nor netstat is present, so no port can match. */
  noPortView: string[]
  /** Answered before and is failing now; its rows are marked stale. */
  unreachable: string[]
}

export interface FleetSearchResult {
  matches: FleetMatch[]
  coverage: FleetCoverage
  /** Matches beyond the cap, dropped. Stated rather than silently truncated. */
  truncated: number
}

export interface FleetSearchInput {
  servers: { id: string; name: string }[]
  hosts: Record<string, { host: HostMetrics; at: number }>
  errors: Record<string, { error: string; at: number }>
}

// A fleet-wide substring can match thousands of rows; the list is for reading,
// not for exporting. The remainder is counted and reported — a silent cut would
// let someone conclude a port is not in use anywhere when it was simply past
// the end.
export const FLEET_SEARCH_CAP = 200

const norm = (s: string): string => s.toLowerCase()

/** A query that is only digits is a port number, and should match ports exactly. */
function portQuery(q: string): number | null {
  return /^\d{1,5}$/.test(q) ? Number(q) : null
}

function rank(m: FleetMatch, q: string): number {
  const label = norm(m.label)
  if (label === q) return 0
  if (label.startsWith(q)) return 1
  if (label.includes(q)) return 2
  return 3
}

export function searchFleet(input: FleetSearchInput, rawQuery: string): FleetSearchResult {
  const q = norm(rawQuery.trim())
  const coverage: FleetCoverage = {
    searched: [],
    notChecked: [],
    noServiceView: [],
    noPortView: [],
    unreachable: []
  }
  const matches: FleetMatch[] = []
  if (q === '') return { matches, coverage, truncated: 0 }

  const exactPort = portQuery(q)

  for (const server of input.servers) {
    const entry = input.hosts[server.id]
    if (!entry) {
      coverage.notChecked.push(server.name)
      continue
    }
    const { host, at } = entry
    coverage.searched.push(server.name)

    // An error newer than the sample means the host has stopped answering
    // since. Rows still show, marked.
    const err = input.errors[server.id]
    const stale = err !== undefined && err.at >= at
    if (stale) coverage.unreachable.push(server.name)

    const base = { serverId: server.id, serverName: server.name, at, stale: stale || undefined }

    // The host itself — so "ubuntu" or a hostname finds the box, not just
    // things on it.
    const hostHay = `${server.name} ${host.hostname} ${host.kernel}`
    if (norm(hostHay).includes(q)) {
      matches.push({
        ...base,
        kind: 'host',
        label: server.name,
        detail: `${host.hostname} · ${host.kernel} · ${host.cores} vCPU`,
        badge: stale ? 'unreachable' : undefined
      })
    }

    if (host.services === null) coverage.noServiceView.push(server.name)
    else {
      for (const u of host.services) {
        if (!norm(`${u.name} ${u.description}`).includes(q)) continue
        const failed = u.active === 'failed' || u.sub === 'failed'
        matches.push({
          ...base,
          kind: 'unit',
          label: u.name,
          detail: u.description || `${u.active}/${u.sub}`,
          badge: failed ? 'failed' : u.active
        })
      }
    }

    if (host.listeners === null) coverage.noPortView.push(server.name)
    else {
      for (const l of host.listeners) {
        const hay = `${l.proto} ${l.port} ${l.address} ${l.process ?? ''}`
        const hit = exactPort !== null ? l.port === exactPort : norm(hay).includes(q)
        if (!hit) continue
        matches.push({
          ...base,
          kind: 'port',
          label: `${l.proto}/${l.port}`,
          // An unprivileged probe sees the socket but not its owner. Say so
          // rather than leaving a blank that reads as "nothing owns this".
          detail: l.process
            ? `${l.process}${l.pid ? ` (pid ${l.pid})` : ''}`
            : 'owner not visible at this privilege',
          badge: l.address
        })
      }
    }
  }

  matches.sort(
    (a, b) =>
      rank(a, q) - rank(b, q) ||
      a.serverName.localeCompare(b.serverName) ||
      a.label.localeCompare(b.label)
  )

  const truncated = Math.max(0, matches.length - FLEET_SEARCH_CAP)
  return { matches: matches.slice(0, FLEET_SEARCH_CAP), coverage, truncated }
}

/**
 * One sentence describing what the search could and could not see.
 *
 * Returns null only when every server in the workspace was searched with both
 * probes working — the one case where silence is accurate.
 */
export function coverageSentence(c: FleetCoverage): string | null {
  const parts: string[] = []
  const list = (names: string[]): string =>
    names.length <= 3 ? names.join(', ') : `${names.slice(0, 3).join(', ')} and ${names.length - 3} more`

  if (c.notChecked.length) parts.push(`${list(c.notChecked)} have not been checked yet`)
  if (c.unreachable.length) parts.push(`${list(c.unreachable)} stopped answering since the last sample`)
  if (c.noServiceView.length) parts.push(`no systemd on ${list(c.noServiceView)}`)
  if (c.noPortView.length) parts.push(`no port probe on ${list(c.noPortView)}`)
  if (parts.length === 0) return null

  const n = c.searched.length
  return `Searched ${n} host${n === 1 ? '' : 's'} — ${parts.join('; ')}.`
}
