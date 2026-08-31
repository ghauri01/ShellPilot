import type { VpnDependent } from '../../../shared/vpn'
import {
  getCachedVpn,
  listCachedDatabases,
  listCachedServers,
  listCachedTunnels
} from '../mcpDataCache'

// What breaks if this VPN goes away.
//
// Two questions are being answered here and they are not the same one:
//
//   * "what is *defined* to use this profile" — servers, databases and tunnels
//     with `vpnProfileId` set. Deleting a profile with any of these strands
//     them, so a delete is blocked until they are detached.
//   * "what is *using it right now*" — live SSH sessions, open database
//     connections and running tunnels that were dialled through it. Stopping a
//     profile with any of these disconnects a human mid-keystroke, so a stop
//     needs a confirmation that names the count.
//
// The second set is registered at dial time rather than derived, because a
// live session outlives the definition it came from: the user can edit a
// server to point somewhere else while a session it opened is still up, and
// the session is still riding the old VPN.

// Live users of a profile, registered by whoever dialled through it. Keyed by
// profile id.
const live = new Map<string, Map<string, VpnDependent>>()

/** Register a live consumer. Returns the release function — call it from the
 *  same place that tears the consumer down, so the two cannot drift. */
export function registerVpnConsumer(
  vpnProfileId: string,
  dep: Omit<VpnDependent, 'live'>
): () => void {
  let m = live.get(vpnProfileId)
  if (!m) {
    m = new Map()
    live.set(vpnProfileId, m)
  }
  const key = `${dep.kind}:${dep.id}`
  m.set(key, { ...dep, live: true })
  return () => {
    const cur = live.get(vpnProfileId)
    if (!cur) return
    cur.delete(key)
    if (cur.size === 0) live.delete(vpnProfileId)
  }
}

/** Everything referencing this profile: stored definitions plus live users. */
export function vpnDependents(vpnProfileId: string): VpnDependent[] {
  const out: VpnDependent[] = []

  for (const s of listCachedServers()) {
    if (s.vpnProfileId === vpnProfileId) {
      out.push({ kind: 'server', id: s.id, name: s.name, live: false })
    }
  }
  for (const d of listCachedDatabases()) {
    if (d.vpnProfileId === vpnProfileId) {
      out.push({ kind: 'database', id: d.id, name: d.name, live: false })
    }
  }
  // A tunnel rides a server, so it inherits that server's VPN rather than
  // naming one itself. Resolving it here means the confirmation dialog can say
  // "and 2 tunnels" instead of leaving the user to work that out.
  const viaServer = new Set(
    listCachedServers()
      .filter((s) => s.vpnProfileId === vpnProfileId)
      .map((s) => s.id)
  )
  for (const t of listCachedTunnels()) {
    if (t.serverId && viaServer.has(t.serverId)) {
      out.push({ kind: 'tunnel', id: t.id, name: t.name, live: false })
    }
  }

  for (const dep of live.get(vpnProfileId)?.values() ?? []) out.push(dep)
  return out
}

/** True when stopping would disconnect something a person is using. */
export function hasLiveVpnDependents(vpnProfileId: string): boolean {
  return (live.get(vpnProfileId)?.size ?? 0) > 0
}

export function liveVpnDependents(vpnProfileId: string): VpnDependent[] {
  return [...(live.get(vpnProfileId)?.values() ?? [])]
}

/** Blocks a profile delete. Returns the stored references only: a live session
 *  will end on its own, but a stored reference would silently point at
 *  nothing. */
export function vpnDeleteBlockers(vpnProfileId: string): VpnDependent[] {
  return vpnDependents(vpnProfileId).filter((d) => !d.live)
}

/** Which profile a server should be dialled through, if any. Returns null for
 *  an unknown or deleted profile rather than throwing: a stale reference must
 *  not stop the user connecting to a server directly. */
export function vpnForServer(serverId: string): string | null {
  const s = listCachedServers().find((x) => x.id === serverId)
  const id = s?.vpnProfileId ?? null
  if (!id) return null
  return getCachedVpn(id) ? id : null
}

export function vpnForDatabase(databaseId: string): string | null {
  const d = listCachedDatabases().find((x) => x.id === databaseId)
  const id = d?.vpnProfileId ?? null
  if (!id) return null
  return getCachedVpn(id) ? id : null
}

/** Drop every live registration for a profile. Called after its transport has
 *  gone down and the consumers have been torn down, so the next start begins
 *  from an empty set rather than inheriting ghosts. */
export function clearVpnConsumers(vpnProfileId: string): void {
  live.delete(vpnProfileId)
}

/** Test seam and quit-path reset. */
export function clearAllVpnConsumers(): void {
  live.clear()
}
