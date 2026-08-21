import type { SshHop } from './ssh'

export type TunnelKind = 'local' | 'remote' | 'socks'

export interface TunnelConfig {
  id: string
  kind: TunnelKind
  // Where the listener is opened. For `local`/`socks` this is on this machine;
  // for `remote` it is on the SSH server.
  listenHost: string
  listenPort: number
  // Where traffic is delivered. Unused for `socks`, which takes the
  // destination from each SOCKS request.
  targetHost: string
  targetPort: number
}

export interface TunnelSshConfig extends SshHop {
  serverId?: string
  hops?: SshHop[]
}

export type TunnelState = 'starting' | 'active' | 'error' | 'stopped'

export interface TunnelStatus {
  id: string
  state: TunnelState
  error?: string
  // Live count of proxied connections, shown in the UI.
  connections: number
  // Actual bound port — differs from the request when 0 was passed.
  listenPort?: number
}

export interface TunnelResult {
  ok: boolean
  error?: string
  listenPort?: number
}

// "127.0.0.1:5432" -> { host, port }. Accepts a bare port and bracketed IPv6.
export function parseEndpoint(text: string, defaultHost = '127.0.0.1'): { host: string; port: number } {
  const s = text.trim()
  if (/^\d+$/.test(s)) return { host: defaultHost, port: Number(s) }
  const v6 = /^\[(.+)\]:(\d+)$/.exec(s)
  if (v6) return { host: v6[1], port: Number(v6[2]) }
  const i = s.lastIndexOf(':')
  if (i === -1) return { host: s || defaultHost, port: 0 }
  return { host: s.slice(0, i) || defaultHost, port: Number(s.slice(i + 1)) || 0 }
}
