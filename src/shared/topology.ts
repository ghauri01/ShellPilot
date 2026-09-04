// What the workspace knows about how hosts depend on each other — and,
// louder, what it does not.
//
// This file exists for one question, asked at the moment a patch run is about
// to restart a machine: WHO ELSE GOES DOWN WITH IT. There is no general answer
// to that. ShellPilot is not a CMDB, it does not read your load balancer, it
// has never seen your replication topology, and a feature that pretended
// otherwise would be worse than one that says nothing — an operator who
// believes a reboot has been checked stops checking it themselves.
//
// So the scope is exactly two facts the workspace genuinely holds:
//
//  1. `Server.route[].serverId` — a saved server used as a JUMP HOST by another
//     saved server. Rebooting it drops every connection that runs through it,
//     including the ones this job is using to watch its own work.
//  2. `DatabaseConn.sshServerId` — a saved database reached through a saved
//     server. Rebooting that server takes the database with it.
//
// Both are things the user typed into this app. Neither is discovered, guessed
// or inferred, and nothing here upgrades a coincidence into a claim.
//
// ---------------------------------------------------------------------------
// THE HOLE IN THE GRAPH, WHICH IS SURFACED AND NOT PAPERED OVER
// ---------------------------------------------------------------------------
// A hop may be a bare host/port/user with NO `serverId` — a bastion that was
// never saved as a server. Such a hop is invisible to a graph keyed on
// `serverId`: two servers can share a bastion it cannot see, and rebooting a
// saved server that happens to be that same machine would be refused by
// nothing.
//
// The honest response is neither to fail open silently nor to refuse every
// reboot in a workspace containing one unmatched hop. It is to COUNT them and
// say so, in the UI, next to the refusals — "N hops could not be matched to
// saved servers, so the checks below cannot see them". `unmatchedHops` is that
// count, `unmatchedHopNote` is that sentence, and `PatchPlan` carries it to the
// panel. See tests/topology.test.ts.
//
// ---------------------------------------------------------------------------
// THE FLOOR UNDER THAT HOLE: THE ADDRESS
// ---------------------------------------------------------------------------
// The hole has a floor, and a graph that ignored it was describing a hole it
// was standing in. A hop is an ADDRESS the user typed. A saved server is an
// ADDRESS the user typed. When the two are the same string, the bastion is not
// invisible — it is sitting in the server list under another name, and the note
// saying "somewhere out there is a hop we cannot see" is the one sentence about
// it that is definitely false.
//
// So `buildTopology` resolves a hop by `serverId` AND by `host:port`, and
// records which way it matched. Two failures that a serverId-only graph could
// not even express:
//
//   1. Server A routes through bare `bastion.example`; that machine is also
//      saved, as server B. A serverId-only graph puts B in a wave, reboots it,
//      and drops A — while the note counts the hop and never names B, which is
//      the one actionable fact.
//   2. `bastion-a` and `bastion-b` are one machine saved twice. X routes via
//      `bastion-a`. `rebootBlockFor(bastion-b)` returns null on a serverId
//      match and takes X down with no refusal.
//
// Both become ordinary jump-host refusals here, and the refusal SAYS the match
// was made by address rather than by a saved reference — a different claim,
// which must not read as the same one. Matching is exact on host (case-folded)
// and port (absent means 22), because those are the two fields a connection
// actually dials; nothing is inferred from a partial name, a DNS lookup, or a
// shared suffix.
//
// What stays unmatched, deliberately: a hop with an address no saved server
// has, and a dangling `serverId` with no usable address beside it. Refusing on
// a host nobody can name is worse than counting it.
//
// THE FALSE POSITIVE THIS ACCEPTS, named rather than discovered later: two
// genuinely different machines can carry the same `host:port` — `10.0.0.5:22`
// on either side of two VPN profiles, say. Address matching will call them one
// machine and refuse a reboot that was in fact fine. That is the direction this
// file errs in everywhere else: a false refusal costs one deliberate run on one
// host, and a false pass costs the bastion mid-upgrade. The refusal names the
// address it matched on and says to correct the host or port if the two are not
// the same box, so the operator can see the reasoning rather than guess at it.

/** A hop as either half of the app spells it: the renderer's `Hop` and main's
 *  `CachedHop` are structurally this, plus fields nothing here reads. */
export interface TopologyHop {
  serverId?: string | null
  host?: string
  port?: number
  username?: string
  label?: string
}

/** A saved server, narrowed to what a dependency graph needs.
 *
 *  `host`/`port` are not decoration: they are how a bare hop is recognised as
 *  this machine, and how two saved records are recognised as one machine. A
 *  server passed without them can still be an edge's TARGET by `serverId`, but
 *  it can never be recognised by address — so callers pass what the workspace
 *  saved rather than trimming the object down. */
export interface TopologyServer {
  id: string
  name: string
  host?: string
  port?: number
  route?: TopologyHop[]
}

/** A saved database, narrowed the same way. */
export interface TopologyDatabase {
  id: string
  name: string
  /** Postgres, MySQL, … — compared, never interpreted. */
  kind?: string
  /** The database NAME on the server, where one was given. */
  database?: string
  /** The saved server this database is reached through, or null for a direct
   *  connection this file can say nothing about. */
  sshServerId?: string | null
}

/** One hop the graph could not resolve to a saved server. */
export interface UnmatchedHop {
  /** The server whose route carries it. */
  serverId: string
  serverName: string
  /** Position in that route, 1-based, so a message can name it. */
  index: number
  /** What the user typed for it, as `user@host:port` where those exist. Never
   *  a credential: only the three fields a connection dialog shows. */
  where: string
}

/** How a hop was tied to the host it depends on. */
export type DependentMatch = 'server-id' | 'address'

/** A server that reaches something else through the host in question. */
export interface Dependent {
  id: string
  name: string
  /** Position of the hop in that server's route, 1-based. */
  hop: number
  /**
   * `server-id` — the hop names this saved server outright.
   * `address` — the hop's `host:port` is the address saved for this server, and
   * that is the ONLY reason the two are tied together. A weaker claim than a
   * saved reference, so it is carried through to the refusal text rather than
   * flattened into one.
   */
  matchedBy: DependentMatch
  /** The `host:port` that made an `address` match, for the sentence. */
  address: string | null
}

/**
 * The comparable form of an address: host case-folded, port defaulted to 22.
 *
 * Exact, and only these two fields. A hop is dialled at a host and a port; a
 * saved server is dialled at a host and a port. Anything looser — a shared
 * domain suffix, a name that merely starts the same, a DNS lookup — would be
 * this file inferring a topology fact, which is the thing its header refuses to
 * do. `null` when there is no host to compare, because an empty string matching
 * an empty string would tie every address-less record to every other.
 */
export function hostAddress(host?: string | null, port?: number | null): string | null {
  const h = (host ?? '').trim().toLowerCase()
  if (h === '') return null
  const p = typeof port === 'number' && Number.isFinite(port) && port > 0 ? Math.floor(port) : 22
  return `${h}:${p}`
}

/** A saved database reached through the host in question. */
export interface DatabaseTenant {
  id: string
  name: string
  kind: string | null
  database: string | null
}

export interface Topology {
  /** Every server id the graph was built from. */
  servers: Map<string, string>
  /** serverId -> the servers that route through it. Never contains an empty
   *  array: a host with no dependents is simply absent. */
  dependents: Map<string, Dependent[]>
  /** serverId -> the saved databases reached through it. */
  databases: Map<string, DatabaseTenant[]>
  /** Every hop that named no saved server, in the order they were found. */
  unmatchedHops: UnmatchedHop[]
}

function hopWhere(h: TopologyHop): string {
  const host = (h.host ?? '').trim()
  const user = (h.username ?? '').trim()
  const port = typeof h.port === 'number' && h.port > 0 && h.port !== 22 ? `:${h.port}` : ''
  if (host === '') return h.label?.trim() || 'an unnamed hop'
  return `${user ? `${user}@` : ''}${host}${port}`
}

/**
 * Build the graph.
 *
 * A hop is resolved TWO ways, and both are things the user typed:
 *
 *  - by `serverId`, the saved reference; and
 *  - by `host:port`, against every saved server's own address — which is what
 *    catches a bare bastion that is also a saved server, and the second saved
 *    record for one machine. See the header. A hop that carries only a
 *    `serverId` borrows that server's address for this step, because that is
 *    how the app builds a route when the operator picks a server from a list.
 *
 * A hop that resolves BOTH ways to the same server is a `server-id` match: the
 * stronger evidence wins, and the refusal does not claim an address match it
 * did not need.
 *
 * A hop whose `serverId` names a server that is NOT in `servers`, and whose
 * address matches nothing either, counts as unmatched rather than as a
 * dependency: the reference is dangling — the server was deleted, or it lives
 * in another workspace this caller cannot see — and treating it as an edge
 * would put a refusal on a host nobody can name. It is reported with the id it
 * pointed at, so the count is never silently short.
 *
 * A route hop pointing at the server that owns the route — by id OR by address
 * — is ignored entirely. It is a configuration mistake rather than a
 * dependency, and reading it as one would make that server permanently
 * unrebootable for being its own bastion. It is not counted as a hole either:
 * it resolved, to the one machine it cannot be a hidden bastion for.
 */
export function buildTopology(
  servers: TopologyServer[],
  databases: TopologyDatabase[] = []
): Topology {
  const known = new Map<string, string>()
  const addressOf = new Map<string, string>()
  const atAddress = new Map<string, string[]>()
  for (const s of servers) {
    known.set(s.id, s.name)
    const addr = hostAddress(s.host, s.port)
    if (addr === null) continue
    addressOf.set(s.id, addr)
    const list = atAddress.get(addr) ?? []
    if (!list.includes(s.id)) list.push(s.id)
    atAddress.set(addr, list)
  }

  const dependents = new Map<string, Dependent[]>()
  const unmatchedHops: UnmatchedHop[] = []

  for (const s of servers) {
    const route = s.route ?? []
    for (let i = 0; i < route.length; i++) {
      const hop = route[i]
      const via = typeof hop.serverId === 'string' && hop.serverId !== '' ? hop.serverId : null
      const addr = hostAddress(hop.host, hop.port) ?? (via === null ? null : addressOf.get(via) ?? null)

      // Every saved server this one hop could be, and how it was recognised.
      const targets = new Map<string, DependentMatch>()
      if (via !== null && known.has(via)) targets.set(via, 'server-id')
      if (addr !== null) {
        for (const id of atAddress.get(addr) ?? []) if (!targets.has(id)) targets.set(id, 'address')
      }

      // Resolved INCLUDES resolving to the route's own owner: that hop is a
      // mistake, not a hole, and reporting it as one would put a warning about
      // an unseen bastion on a workspace whose every hop is accounted for.
      const resolved = targets.size > 0
      targets.delete(s.id)

      if (!resolved) {
        unmatchedHops.push({
          serverId: s.id,
          serverName: s.name,
          index: i + 1,
          where:
            via === null
              ? hopWhere(hop)
              : `${hopWhere(hop)} (saved server ${via}, which is not in this list)`
        })
        continue
      }

      for (const [target, matchedBy] of targets) {
        const list = dependents.get(target) ?? []
        // One server may appear twice in another's route — a mistake, but it
        // must not double-count into "2 servers depend on this". A later
        // `server-id` match UPGRADES an earlier address one, so a route that
        // names a host both ways is reported by the stronger evidence
        // regardless of which hop came first.
        const already = list.find((d) => d.id === s.id)
        if (already === undefined) {
          list.push({
            id: s.id,
            name: s.name,
            hop: i + 1,
            matchedBy,
            address: matchedBy === 'address' ? addr : null
          })
        } else if (already.matchedBy === 'address' && matchedBy === 'server-id') {
          already.matchedBy = 'server-id'
          already.address = null
          already.hop = i + 1
        }
        dependents.set(target, list)
      }
    }
  }

  const dbs = new Map<string, DatabaseTenant[]>()
  for (const d of databases) {
    const via = typeof d.sshServerId === 'string' && d.sshServerId !== '' ? d.sshServerId : null
    if (via === null || !known.has(via)) continue
    const list = dbs.get(via) ?? []
    list.push({
      id: d.id,
      name: d.name,
      kind: d.kind ?? null,
      database: d.database && d.database !== '' ? d.database : null
    })
    dbs.set(via, list)
  }

  for (const list of dependents.values()) list.sort((a, b) => a.name.localeCompare(b.name))
  for (const list of dbs.values()) list.sort((a, b) => a.name.localeCompare(b.name))

  return { servers: known, dependents, databases: dbs, unmatchedHops }
}

/** Does any other saved server reach itself through this one? */
export function isJumpHost(topo: Topology, serverId: string): boolean {
  return (topo.dependents.get(serverId)?.length ?? 0) > 0
}

export function dependentsOf(topo: Topology, serverId: string): Dependent[] {
  return topo.dependents.get(serverId) ?? []
}

export function databasesOn(topo: Topology, serverId: string): DatabaseTenant[] {
  return topo.databases.get(serverId) ?? []
}

/**
 * The sentence the UI must print whenever it shows a reboot check.
 *
 * `null` when every hop resolved, because a line saying "0 hops could not be
 * matched" is noise that trains people to skip the line that matters.
 *
 * A hop resolved BY ADDRESS is not in this count. It is not part of the hole:
 * the machine was found, and the refusal above names it. Counting it here as
 * well would be the note claiming a blind spot in the one case where the graph
 * has just proved it does not have one — which is the fastest way to teach an
 * operator that this line is decoration.
 */
export function unmatchedHopNote(topo: Topology): string | null {
  const n = topo.unmatchedHops.length
  if (n === 0) return null
  const names = [...new Set(topo.unmatchedHops.map((h) => h.serverName))]
  const who = names.length <= 3 ? names.join(', ') : `${names.slice(0, 3).join(', ')} and others`
  return (
    `${n} ${n === 1 ? 'hop is' : 'hops are'} not backed by a saved server (on ${who}), so the ` +
    'reboot checks below cannot see them. Two servers can share a bastion that ShellPilot has ' +
    'never been told about; if one of the servers below is that machine, nothing here will say so.'
  )
}

// ---------------------------------------------------------------------------
// The refusals
// ---------------------------------------------------------------------------

export type RebootBlockKind = 'jump-host' | 'same-wave-database'

export interface RebootBlock {
  kind: RebootBlockKind
  serverId: string
  serverName: string
  /** The whole sentence, ready to print. */
  reason: string
}

/**
 * May this host be restarted?
 *
 * A HARD REFUSAL, not a confirmation, and the difference is the point. A
 * confirmation is a question, and a question asked fifteen times during a
 * staged estate upgrade is answered by reflex. Rebooting the machine every
 * other connection runs through is not a thing to be sure about; it is a thing
 * the run must not contain. The remedy is to take that host out of the target
 * list and do it deliberately, on its own, when the estate is not mid-upgrade.
 *
 * `null` when the host has no saved dependents. That is NOT "this is safe to
 * reboot" — see `unmatchedHopNote`, and see the header of this file.
 */
export function rebootBlockFor(topo: Topology, serverId: string): RebootBlock | null {
  const deps = dependentsOf(topo, serverId)
  if (deps.length === 0) return null
  const name = topo.servers.get(serverId) ?? serverId
  const via = deps.map((d) => d.name).join(', ')

  // An address match is a WEAKER claim than a saved reference and the sentence
  // has to say so, or an operator reading "is the jump host that X connects
  // through" will look for a route entry naming this server and not find one.
  const byAddress = deps.filter((d) => d.matchedBy === 'address')
  const addresses = [...new Set(byAddress.map((d) => d.address).filter((a): a is string => a !== null))]
  const addressNote =
    byAddress.length === 0
      ? ''
      : ` ${byAddress.map((d) => d.name).join(', ')} ${byAddress.length === 1 ? 'names' : 'name'} ` +
        `that hop by the address ${addresses.join(', ')} rather than by a saved-server reference; ` +
        `${name} is the saved server at that address. The same machine reached under two names is ` +
        'exactly the case a serverId-only check cannot see, so it is refused here rather than ' +
        'counted as an unmatched hop. If they are genuinely different machines, correct the server ' +
        'or port on one of them.'

  return {
    kind: 'jump-host',
    serverId,
    serverName: name,
    reason:
      `${name} is the jump host ${deps.length === 1 ? 'that' : 'that'} ${via} ` +
      `${deps.length === 1 ? 'connects' : 'connect'} through. Restarting it drops those ` +
      'connections — including the ones this job is using to watch its own work — so this run ' +
      'will not do it. Reboot it on its own, deliberately, with nothing else in flight.' +
      addressNote
  }
}

/**
 * Two hosts in the SAME wave that carry saved databases sharing an identity.
 *
 * This is the closest an honest implementation gets to "do not reboot both
 * replicas of a database". It cannot know what replicates with what; what it
 * can see is that the user saved `orders` on postgres through `db-a` and
 * `orders` on postgres through `db-b`, and that this wave would restart both at
 * once. That is worth refusing, and it is worth saying exactly what it is based
 * on so nobody mistakes it for replication awareness.
 *
 * Same KIND and same DATABASE NAME. Name alone would collide on every `postgres`
 * default database across unrelated hosts; kind alone would refuse an entire
 * wave of PostgreSQL servers that have nothing to do with each other. A database
 * saved without a name contributes nothing, because there is nothing to match.
 */
export function sameWaveDatabaseBlocks(topo: Topology, waveServerIds: string[]): RebootBlock[] {
  const byKey = new Map<string, { serverId: string; serverName: string; dbName: string }[]>()
  for (const serverId of waveServerIds) {
    for (const db of databasesOn(topo, serverId)) {
      if (db.database === null) continue
      const key = `${db.kind ?? ''} ${db.database.toLowerCase()}`
      const list = byKey.get(key) ?? []
      list.push({
        serverId,
        serverName: topo.servers.get(serverId) ?? serverId,
        dbName: db.database
      })
      byKey.set(key, list)
    }
  }
  const blocks: RebootBlock[] = []
  const seen = new Set<string>()
  for (const list of byKey.values()) {
    const hosts = [...new Map(list.map((l) => [l.serverId, l])).values()]
    if (hosts.length < 2) continue
    const names = hosts.map((h) => h.serverName).join(' and ')
    for (const h of hosts) {
      if (seen.has(h.serverId)) continue
      seen.add(h.serverId)
      blocks.push({
        kind: 'same-wave-database',
        serverId: h.serverId,
        serverName: h.serverName,
        reason:
          `${names} both carry a saved ${list[0].dbName} database, and this wave would restart ` +
          'them together. ShellPilot does not know whether they replicate — it only knows you ' +
          'saved the same database on both — so it will not restart them in the same wave. Put ' +
          'them in different waves.'
      })
    }
  }
  return blocks
}
