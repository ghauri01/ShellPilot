import { factSource, type HostFacts } from '../../../shared/hostFacts'
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
  /**
   * Sort position, 0 (exact) to 3 (other), computed against the text that
   * actually matched rather than against `label`.
   *
   * Ranking on the label alone was wrong for every match whose label the query
   * never appears in — a host found by its hostname, a unit found by its
   * description, a port found by its owning process all scored worst-possible
   * and sorted below every incidental substring hit. It is computed once here
   * rather than inside the comparator, which also stops the sort recomputing it
   * O(n log n) times per keystroke.
   */
  score: number
}

/**
 * Why a host is not represented in the results.
 *
 * Every field is a list of server names rather than a count, because "3 hosts
 * could not be searched" prompts the question this is supposed to answer.
 *
 * `noServiceView`, `noPortView` and `noProbes` are disjoint: a host that has
 * neither probe appears once, under `noProbes`, rather than twice under the
 * other two with nothing saying that between them they account for everything
 * that host could have contributed.
 */
export interface FleetCoverage {
  /**
   * Hosts whose units and ports were actually searched.
   *
   * A host with a sample but neither probe is NOT here: its inventory was not
   * searched at all, only its own name, hostname and kernel. Counting it would
   * put a number on the screen that overstates what was looked at, which is the
   * one thing this whole structure exists to prevent.
   */
  searched: string[]
  /** Never sampled — background checking off, or not swept yet. */
  notChecked: string[]
  /** Sampled, but systemd is not present, so no unit can match. */
  noServiceView: string[]
  /** Sampled, but neither ss nor netstat is present, so no port can match. */
  noPortView: string[]
  /** Sampled, but neither probe ran: nothing on the host was searchable. */
  noProbes: string[]
  /** Answered before and is failing now; its rows are marked stale. */
  unreachable: string[]

  // -------------------------------------------------------------------------
  // Host facts — roadmap item C.
  //
  // A second axis, and it needed its own buckets rather than a share of the
  // ones above. `notChecked` is about the two-minute metrics sweep; facts are
  // collected HOURLY, so a host can be sampled forty times and still have no
  // facts, and folding the two together would tell someone their estate had
  // not been checked when it is being checked constantly.
  //
  // The four below are mutually disjoint and, with `notChecked`, complete: a
  // host reaches exactly one of them. The chain is deliberate — a host with no
  // facts cannot also be missing a package manager, because we do not know
  // whether it has one.
  // -------------------------------------------------------------------------

  /** Facts were collected, so distro, package manager and the rest were
   *  searched on this host. The facts counterpart of `searched`. */
  factsSearched: string[]
  /** No facts yet. Normal for a host added within the last hour, and NOT the
   *  same as "this host has no distribution". */
  noFacts: string[]
  /** Facts collected, and none of the six package managers is installed. No
   *  update count of any kind can exist here. */
  noPackageManager: string[]
  /**
   * Facts collected, a package manager is present, and it CANNOT report a
   * security count — Arch and Alpine have no security channel, and dnf cannot
   * answer where the repositories publish no updateinfo.
   *
   * The bucket that justifies the rest of them. Someone searching `security`,
   * seeing three hits and concluding the estate has three security problems is
   * wrong by however many hosts are named here, and nothing else on screen
   * would tell them.
   */
  securityUnsupported: string[]
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
  /**
   * Host facts per server, on their own hourly clock — roadmap item C.
   *
   * REQUIRED rather than optional, and an absent entry means "never collected"
   * rather than "this caller does not do facts". An optional field would let a
   * caller silently opt out of the coverage buckets below, which is exactly the
   * lie-by-omission the coverage structure exists to prevent: the search would
   * report a clean bill of health for an estate it had not looked at half of.
   * Pass `{}` and every host is honestly reported as having no facts.
   */
  facts: Record<string, { facts?: HostFacts; at?: number }>
}

// A fleet-wide substring can match thousands of rows; the list is for reading,
// not for exporting. The remainder is counted and reported — a silent cut would
// let someone conclude a port is not in use anywhere when it was simply past
// the end.
export const FLEET_SEARCH_CAP = 200

const norm = (s: string): string => s.toLowerCase()

/** The highest port number there is. Above it, digits are not a port at all. */
const MAX_PORT = 65535

/**
 * A query that is only digits is a port number, and should match ports exactly.
 *
 * Only a number that could actually be a listening port counts. `99999` is five
 * digits and no port, and `0` is what a kernel prints for "any" rather than
 * anything a process listens on; treating either as an exact port silently
 * returned nothing at all. Both fall through to substring matching instead,
 * where `0` still finds every socket bound to 0.0.0.0 and `99999` finds a
 * process or address that contains it — an honest answer rather than an empty
 * one.
 */
function portQuery(q: string): number | null {
  if (!/^\d{1,5}$/.test(q)) return null
  const n = Number(q)
  return n >= 1 && n <= MAX_PORT ? n : null
}

/** 0 exact, 1 prefix, 2 substring, 3 no match. `term` must already be lowercase. */
function rank(term: string, q: string): number {
  if (term === q) return 0
  if (term.startsWith(q)) return 1
  if (term.includes(q)) return 2
  return 3
}

/** The best rank across every field the row could have matched on. */
function bestRank(terms: string[], q: string): number {
  let best = 3
  for (const t of terms) {
    const r = rank(t, q)
    if (r < best) best = r
    if (best === 0) break
  }
  return best
}

/**
 * A React key that is unique within one result list.
 *
 * `kind:serverId:label` was not: two sockets with the same protocol and port on
 * different addresses (0.0.0.0:443 and ::1:443, or the same port bound per
 * interface) share a label, and duplicate keys make React drop or mis-update
 * rows. The index guarantees uniqueness even for two byte-identical rows, which
 * `netstat` can genuinely produce.
 */
export function matchKey(m: FleetMatch, index: number): string {
  return `${m.kind}:${m.serverId}:${m.label}:${m.badge ?? ''}:${index}`
}

export function searchFleet(input: FleetSearchInput, rawQuery: string): FleetSearchResult {
  const q = norm(rawQuery.trim())
  const coverage: FleetCoverage = {
    searched: [],
    notChecked: [],
    noServiceView: [],
    noPortView: [],
    noProbes: [],
    unreachable: [],
    factsSearched: [],
    noFacts: [],
    noPackageManager: [],
    securityUnsupported: []
  }
  const matches: FleetMatch[] = []
  if (q === '') return { matches, coverage, truncated: 0 }

  const exactPort = portQuery(q)
  // The same server listed twice would be scanned twice: every row duplicated,
  // its name counted twice in the coverage sentence, and two rows sharing a
  // React key. Cheaper to refuse the duplicate than to reason about whether the
  // store can ever produce one.
  const seenServers = new Set<string>()

  for (const server of input.servers) {
    if (seenServers.has(server.id)) continue
    seenServers.add(server.id)

    const entry = input.hosts[server.id]
    if (!entry) {
      // Reported once, here, rather than under `notChecked` AND `noFacts`. The
      // sampler only probes facts after a successful metrics sample, so a host
      // nothing has ever sampled has never had facts collected either, and
      // naming it twice under two gaps says less than naming it once under the
      // gap that explains both.
      coverage.notChecked.push(server.name)
      continue
    }
    const { host, at } = entry

    // An error newer than the sample means the host has stopped answering
    // since. Rows still show, marked.
    //
    // `>=` rather than `>` on purpose: a success DELETES the stored error
    // (store/fleet.ts `report`), so an error being present at all means it was
    // recorded after the last good sample. When the two timestamps tie — same
    // sweep, or two events inside one millisecond — the error is the later of
    // the two and the rows are stale. `>` would silently un-mark exactly that
    // case. The comparison still earns its keep for an error that arrives out
    // of order carrying a timestamp older than a sample already stored.
    const err = input.errors[server.id]
    const stale = err !== undefined && err.at >= at
    if (stale) coverage.unreachable.push(server.name)

    const base = {
      serverId: server.id,
      serverName: server.name,
      at,
      stale: stale || undefined
    }

    // What the host IS, as opposed to what is running on it. Facts are hourly
    // and independent of the sample above, so their absence is its own gap and
    // never a claim about the host.
    const facts = input.facts[server.id]?.facts
    if (!facts) {
      coverage.noFacts.push(server.name)
    } else {
      coverage.factsSearched.push(server.name)
      if (facts.packageManager === null) {
        // No package manager means no update count of any kind, so the security
        // question never arises here — which is why this is `else if` and not a
        // second push. The collector reports `no-tool` rather than `unsupported`
        // for exactly this case; the branch keeps the two buckets disjoint even
        // if a partial or forged set of facts ever says otherwise.
        coverage.noPackageManager.push(server.name)
      } else if (factSource(facts, 'security-updates').status === 'unsupported') {
        coverage.securityUnsupported.push(server.name)
      }
    }

    // The host itself — so "ubuntu", "rocky", "kvm", "apt" or a hostname finds
    // the box, not just things on it.
    //
    // The fact terms are appended to the same `host` match kind rather than
    // given a kind of their own: "which hosts are Ubuntu" is a question about
    // hosts, and a fourth icon in the result list would say it was not.
    const nameTerm = norm(server.name)
    const hostTerm = norm(host.hostname || '')
    const kernelTerm = norm(host.kernel || '')
    // Every allow-listed and free-text fact the host reported about itself.
    // `prettyName` and `cpuModel` are the host's own words and arrive already
    // stripped of control characters and bidi marks by parseHostFacts.
    const factTerms = facts
      ? [
          facts.distroId,
          facts.distroVersion,
          facts.prettyName,
          facts.packageManager,
          facts.virtualisation,
          facts.arch,
          facts.cpuModel
        ]
          .filter((t): t is string => t !== null && t !== '')
          .map(norm)
      : []
    const hostTerms = [nameTerm, hostTerm, kernelTerm, ...factTerms]
    if (hostTerms.some((t) => t.includes(q))) {
      // Distro and package manager earn a place in the detail line for the same
      // reason the kernel already has one: a host found by typing "kvm" that
      // does not say "kvm" anywhere on the row looks like a bug.
      const detail = [
        host.hostname,
        facts?.prettyName ??
          (facts?.distroId
            ? `${facts.distroId}${facts.distroVersion ? ` ${facts.distroVersion}` : ''}`
            : null),
        host.kernel,
        facts?.virtualisation && facts.virtualisation !== 'none' ? facts.virtualisation : null,
        facts?.packageManager,
        `${host.cores} vCPU`
      ]
        .filter((p): p is string => !!p)
        .join(' · ')
      matches.push({
        ...base,
        kind: 'host',
        label: server.name,
        detail,
        badge: stale ? 'unreachable' : undefined,
        // Ranked on whichever term the query hit, so a host found by an exact
        // distro id or hostname sorts above a unit that merely contains the
        // query. Ranking on the label alone put every one of these last.
        score: bestRank(hostTerms, q)
      })
    }

    // A host with neither probe had nothing but its own identity to search.
    // Reported as one gap rather than counted as a searched host with two
    // separate holes in it.
    if (host.services === null && host.listeners === null) {
      coverage.noProbes.push(server.name)
    } else {
      coverage.searched.push(server.name)
      if (host.services === null) coverage.noServiceView.push(server.name)
      if (host.listeners === null) coverage.noPortView.push(server.name)
    }

    if (host.services !== null) {
      for (const u of host.services) {
        const name = norm(u.name)
        const desc = norm(u.description || '')
        if (!name.includes(q) && !desc.includes(q)) continue
        const failed = u.active === 'failed' || u.sub === 'failed'
        matches.push({
          ...base,
          kind: 'unit',
          label: u.name,
          detail: u.description || `${u.active}/${u.sub}`,
          badge: failed ? 'failed' : u.active,
          score: bestRank([name, desc], q)
        })
      }
    }

    if (host.listeners !== null) {
      for (const l of host.listeners) {
        let score: number
        if (exactPort !== null) {
          // The numeric path touches no strings at all. It runs over every
          // socket on every host on every keystroke, and building a haystack
          // it then ignores was the bulk of the work a port query did.
          if (l.port !== exactPort) continue
          score = 0
        } else {
          const proto = norm(l.proto || '')
          const addr = norm(l.address || '')
          const proc = norm(l.process || '')
          const portStr = String(l.port)
          if (!proto.includes(q) && !portStr.includes(q) && !addr.includes(q) && !proc.includes(q)) {
            continue
          }
          score = bestRank([`${proto}/${portStr}`, portStr, proc, addr, proto], q)
        }
        matches.push({
          ...base,
          kind: 'port',
          label: `${l.proto}/${l.port}`,
          // An unprivileged probe sees the socket but not its owner. Say so
          // rather than leaving a blank that reads as "nothing owns this".
          detail: l.process
            ? `${l.process}${l.pid ? ` (pid ${l.pid})` : ''}`
            : 'owner not visible at this privilege',
          badge: l.address,
          score
        })
      }
    }
  }

  matches.sort(
    (a, b) => a.score - b.score || a.serverName.localeCompare(b.serverName) || a.label.localeCompare(b.label)
  )

  const truncated = Math.max(0, matches.length - FLEET_SEARCH_CAP)
  return { matches: matches.slice(0, FLEET_SEARCH_CAP), coverage, truncated }
}

/**
 * One sentence describing what the search could and could not see.
 *
 * The count leads with units and ports rather than with hosts, because that is
 * what the number is true of: a host with no probes contributed nothing but its
 * own name, and calling it "searched" put a reassuring number on screen that
 * the results behind it did not support. Host facts get a second count for the
 * same reason they get their own buckets — they are a different sweep on a
 * different clock, and one number covering both would be true of neither.
 *
 * Every clause names HOSTS rather than counting them. "3 hosts could not be
 * searched" prompts the question this is supposed to answer.
 *
 * Returns null only when every server was searched with both probes working AND
 * every one of them had facts that could answer every question — the one case
 * where silence is accurate. That is a higher bar than it was before facts
 * existed, and deliberately so: an estate with five Arch boxes in it can never
 * clear it, and a search for `security` on that estate must never look complete.
 */
export function coverageSentence(c: FleetCoverage): string | null {
  const parts: string[] = []
  const list = (names: string[]): string =>
    names.length <= 3 ? names.join(', ') : `${names.slice(0, 3).join(', ')} and ${names.length - 3} more`

  if (c.notChecked.length) parts.push(`${list(c.notChecked)} have not been checked yet`)
  if (c.unreachable.length) parts.push(`${list(c.unreachable)} stopped answering since the last sample`)
  if (c.noProbes.length) parts.push(`neither systemd nor a port probe on ${list(c.noProbes)}`)
  if (c.noServiceView.length) parts.push(`no systemd on ${list(c.noServiceView)}`)
  if (c.noPortView.length) parts.push(`no port probe on ${list(c.noPortView)}`)
  // Facts last, and each in its own words. "No facts yet" is a schedule, "no
  // package manager" is a property of the host, and "can never report security
  // updates" is a property of the DISTRIBUTION that no amount of waiting or
  // privilege will change — three different things a reader does three
  // different things about.
  if (c.noFacts.length) parts.push(`no host facts collected yet for ${list(c.noFacts)}`)
  if (c.noPackageManager.length) parts.push(`no package manager on ${list(c.noPackageManager)}`)
  if (c.securityUnsupported.length) {
    parts.push(`${list(c.securityUnsupported)} can never report security updates`)
  }
  if (parts.length === 0) return null

  const n = c.searched.length
  const f = c.factsSearched.length
  return `Units and ports searched on ${n} host${n === 1 ? '' : 's'}, host facts on ${f} — ${parts.join('; ')}.`
}
