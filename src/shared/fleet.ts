import type { HostMetrics, SshConnectConfig } from './ssh'

// Background fleet sampling.
//
// Until this existed, metrics were sampled only by mounted UI: leaving the
// monitor tab unmounted every card and stopped the polling, so the estate's
// state was known only while somebody was looking at it. That made alerting
// impossible rather than merely unbuilt — there was no moment at which a
// failure could be noticed while the person was doing something else.

// One server the sampler should keep an eye on. The config is resolved by the
// renderer the same way it is for a terminal session, so the sampler never
// builds a connection description of its own.
export interface FleetTarget {
  serverId: string
  serverName: string
  // `serverId` rides along inside the config too, because that is how
  // credentialResolver finds the vault entry for a host — the same shape
  // `metrics:sample` already accepts.
  cfg: SshConnectConfig & { serverId?: string }
}

export interface FleetSamplerConfig {
  enabled: boolean
  // Milliseconds between the end of one sweep and the start of the next.
  // Deliberately an interval between sweeps rather than a rate: a slow estate
  // must not queue sweeps faster than they finish, for the same reason the
  // per-server poll chains rather than using setInterval.
  intervalMs: number
  targets: FleetTarget[]
}

export type FleetSampleReason =
  // A scheduled sweep produced this.
  | 'scheduled'
  // The renderer asked for an immediate sweep, e.g. on opening the monitor.
  | 'requested'

export interface FleetSampleEvent {
  serverId: string
  reason: FleetSampleReason
  at: number
  // Exactly one of these is set. An error is kept rather than dropped so the
  // UI can distinguish "this host is unhealthy" from "we could not ask it",
  // which is the same null-is-not-empty distinction HostMetrics makes about
  // its own probes.
  host?: HostMetrics
  error?: string
}

// Why the sampler is not currently running, for a UI that has to explain
// itself rather than silently showing stale numbers.
export type FleetSamplerIdleReason =
  | 'disabled'
  | 'no-targets'
  // Credentials cannot be resolved, so sampling would fail on every target.
  // Degrading to "not sampling" is deliberate: retrying into a locked vault
  // produces an error loop and an audit entry per attempt.
  | 'vault-locked'

export interface FleetSamplerStatus {
  running: boolean
  idleReason?: FleetSamplerIdleReason
  targetCount: number
  // When the last sweep finished, or undefined if none has.
  lastSweepAt?: number
  // How long the last sweep took end to end, which is what tells a user
  // whether their interval is realistic for their estate.
  lastSweepMs?: number
}

// Slower than a focused view by design. The monitor polls a visible server
// every 2s because someone is watching a graph; a background sweep across a
// whole estate is answering "has anything broken", and doing that every couple
// of seconds is fifteen SSH exec channels a minute for a question whose answer
// changes on the order of minutes.
export const FLEET_INTERVAL_DEFAULT_MS = 120_000
export const FLEET_INTERVAL_MIN_MS = 30_000
export const FLEET_INTERVAL_MAX_MS = 3_600_000
