import type { Hop, Server } from '../types'
import type { SshHop } from '../../../shared/ssh'

const asAuth = (a: string): SshHop['auth'] =>
  a === 'password' || a === 'agent' ? a : 'key'

// Jump hops for a server. Every consumer (terminal, SFTP, metrics, tunnels)
// must build these identically: dropping serverId/keyPath makes the hop
// authenticate with nothing, and also changes its connection-pool identity so
// it opens a second connection to the same bastion instead of sharing one.
export function sshHopsFor(server: Server): (SshHop & { serverId?: string })[] {
  return server.route.map((h: Hop) => ({
    host: h.host,
    port: h.port,
    username: h.username,
    auth: asAuth(h.auth),
    serverId: h.serverId ?? undefined,
    keyPath: h.keyPath || undefined
  }))
}

export interface SshHopInfo {
  serverId: string
  host: string
  port: number
  username: string
  auth: 'password' | 'key' | 'agent'
}

// The SSH details the main process needs to open a connection. Credentials are
// deliberately absent — main merges them from the encrypted store by serverId.
export function sshHopFor(server: Server): SshHopInfo {
  return {
    serverId: server.id,
    host: server.host,
    port: server.port,
    username: server.username,
    auth: server.auth === 'password' ? 'password' : server.auth === 'agent' ? 'agent' : 'key'
  }
}
