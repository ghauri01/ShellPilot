// Shared SSH types used by main, preload and renderer.

export type SshAuth = 'password' | 'key' | 'agent'

export interface SshHop {
  host: string
  port: number
  username: string
  auth: SshAuth
  password?: string
  keyPath?: string
  privateKey?: string
  passphrase?: string
}

export interface SshConnectConfig extends SshHop {
  sessionId: string
  cols: number
  rows: number
  hops?: SshHop[]
}

export type SshStatusPhase = 'connecting' | 'hop' | 'authenticating' | 'ready' | 'closed' | 'error'

// Why a shell session ended, as far as the far end told us. Everything is
// optional: a connection dropped mid-flight reports nothing at all.
export interface SshCloseInfo {
  // Exit status of the remote shell, when it exited normally.
  code?: number
  // Signal that killed it, e.g. 'HUP' when the server timed the session out.
  signal?: string
}

export interface SshStatus {
  sessionId: string
  phase: SshStatusPhase
  message?: string
  hopIndex?: number
  hopCount?: number
}

export interface SftpEntry {
  name: string
  dir: boolean
  link: boolean
  size: number
  mtime: number
  perms: string
}

export interface SftpResult<T = void> {
  ok: boolean
  error?: string
  data?: T
}

// Emitted while a file transfer runs so the Files view can show progress.
export interface SftpProgress {
  key: string
  name: string
  transferred: number
  total: number
  // 1-based position in the current batch.
  index: number
  count: number
}

export interface SftpUploadSummary {
  uploaded: string[]
  failed: { name: string; error: string }[]
}

export interface HostMetrics {
  cpu: number // percent 0-100
  memPct: number
  memUsed: number // bytes
  memTotal: number
  diskPct: number
  diskUsed: number
  diskTotal: number
  netRx: number // cumulative bytes
  netTx: number
  uptime: number // seconds
  hostname: string
  kernel: string
  cores: number
  // null means the tool is not on the host at all — a container without
  // systemd, or a box with neither ss nor netstat. That is a different thing
  // from an empty list, which means the tool ran and found nothing, and the
  // UI has to be able to tell them apart: "no failed services" and "cannot
  // see services" are not the same answer.
  services: ServiceUnit[] | null
  listeners: PortListener[] | null
  // Which probe produced the listeners, so the UI can say why the process
  // column is empty on a host where only netstat exists and it ran unprivileged.
  listenerSource: 'ss' | 'netstat' | null
}

// A systemd unit, as reported by `systemctl list-units`.
export interface ServiceUnit {
  name: string
  // active | failed | activating | inactive
  active: string
  // running | exited | dead | failed
  sub: string
  description: string
}

// A socket in LISTEN state, from `ss` or `netstat`.
export interface PortListener {
  proto: string
  address: string
  port: number
  // Only present when the probe ran with enough privilege to see the owner;
  // an unprivileged user sees the socket but not whose it is.
  process?: string
  pid?: number
}

export interface MetricsResult {
  ok: boolean
  error?: string
  data?: HostMetrics
}
