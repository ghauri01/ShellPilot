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
// never saved as a server. Such a hop is invisible to this graph: two servers
// can share a bastion that this file cannot see, and rebooting a saved server
// that happens to be that same machine would be refused by nothing.
//
// The honest response is neither to fail open silently nor to refuse every
// reboot in a workspace containing one unmatched hop. It is to COUNT them and
// say so, in the UI, next to the refusals — "N hops could not be matched to
// saved servers, so the checks below cannot see them". `unmatchedHops` is that
// count, `unmatchedHopNote` is that sentence, and `PatchPlan` carries it to the
// panel. See tests/topology.test.ts.

/** A hop as either half of the app spells it: the renderer's `Hop` and main's
 *  `CachedHop` are structurally this, plus fields nothing here reads. */
export interface TopologyHop {
  serverId?: string | null
  host?: string
  port?: number
  username?: string
  label?: string
}

/** A saved server, narrowed to what a dependency graph needs. */
export interface TopologyServer {
  id: string
  name: string
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

/** A server that reaches something else through the host in question. */
export interface Dependent {
  id: string
  name: string
  /** Position of the hop in that server's route, 1-based. */
  hop: number
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
 * A hop whose `serverId` names a server that is NOT in `servers` counts as
 * unmatched, not as a dependency: the reference is dangling — the server was
 * deleted, or it lives in another workspace this caller cannot see — and
 * treating it as an edge would put a refusal on a host nobody can name. It is
 * reported with the id it pointed at, so the count is never silently short.
 *
 * A route hop pointing at the server that owns the route is ignored entirely.
 * It is a configuration mistake rather than a dependency, and reading it as one
 * would make that server permanently unrebootable for being its own bastion.
 */
export function buildTopology(
  servers: TopologyServer[],
  databases: TopologyDatabase[] = []
): Topology {
  const known = new Map<string, string>()
  for (const s of servers) known.set(s.id, s.name)

  const dependents = new Map<string, Dependent[]>()
  const unmatchedHops: UnmatchedHop[] = []

  for (const s of servers) {
    const route = s.route ?? []
    for (let i = 0; i < route.length; i++) {
      const hop = route[i]
      const via = typeof hop.serverId === 'string' && hop.serverId !== '' ? hop.serverId : null
      if (via === null) {
        unmatchedHops.push({
          serverId: s.id,
          serverName: s.name,
          index: i + 1,
          where: hopWhere(hop)
        })
        continue
      }
      if (via === s.id) continue
      if (!known.has(via)) {
        unmatchedHops.push({
          serverId: s.id,
          serverName: s.name,
          index: i + 1,
          where: `${hopWhere(hop)} (saved server ${via}, which is not in this list)`
        })
        continue
      }
      const list = dependents.get(via) ?? []
      // One server may appear twice in another's route — a mistake, but it must
      // not double-count into "2 servers depend on this".
      if (!list.some((d) => d.id === s.id)) list.push({ id: s.id, name: s.name, hop: i + 1 })
      dependents.set(via, list)
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
 */
export function unmatchedHopNote(topo: Topology): string | null {
  const n = topo.unmatchedHops.length
  if (n === 0) return null
  const names = [...new Set(topo.unmatchedHops.map((h) => h.serverName))]
  const who = names.length <= 3 ? names.join(', ') : `${names.slice(0, 3).join(', ')} and others`
  return (
    `${n} ${n === 1 ? 'hop is' : 'hops are'} not backed by a saved server (on ${who}), so the ` +
    'reboot checks below cannot see them. Two servers can share a bastion that ShellPilot has ' +
    'never been told about; if one of the hosts below is that machine, nothing here will say so.'
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
  return {
    kind: 'jump-host',
    serverId,
    serverName: name,
    reason:
      `${name} is the jump host ${deps.length === 1 ? 'that' : 'that'} ${via} ` +
      `${deps.length === 1 ? 'connects' : 'connect'} through. Restarting it drops those ` +
      'connections — including the ones this job is using to watch its own work — so this run ' +
      'will not do it. Reboot it on its own, deliberately, with nothing else in flight.'
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
