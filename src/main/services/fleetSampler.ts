import type {
  FleetSampleEvent,
  FleetSampleReason,
  FleetSamplerConfig,
  FleetSamplerStatus,
  FleetTarget
} from '../../shared/fleet'
import {
  FLEET_INTERVAL_DEFAULT_MS,
  FLEET_INTERVAL_MAX_MS,
  FLEET_INTERVAL_MIN_MS
} from '../../shared/fleet'

// Samples the estate on a schedule, in main, whether or not anyone is looking.
//
// The renderer used to own this: every ServerMonitorCard ran its own 2s poll
// while mounted, which meant leaving the monitor tab stopped sampling entirely.
// Nothing could notice a failure unless the failure happened to occur while
// somebody was watching the screen that would have shown it.
//
// Two properties are carried over from that renderer loop deliberately, because
// they were right:
//
//   * Polls CHAIN rather than repeat on an interval. A slow link makes an
//     interval queue polls faster than they finish, and every queued poll is
//     another exec channel on the connection a terminal may be typing over.
//     Here the same rule applies a level up: one sweep at a time, and the gap
//     is measured from the END of a sweep.
//   * The sampler never resolves credentials or builds a connection itself. It
//     is handed a resolved config per target, exactly as a terminal session is.
//
// What is new is the failure posture. This runs unattended, so anything that
// would produce an error every interval forever has to stop the loop instead:
// see `vault-locked` below.

type Sampler = (key: string, cfg: FleetTarget['cfg']) => Promise<{ ok: boolean; data?: unknown; error?: string }>

export interface FleetSamplerDeps {
  // metricsSample, injected so the schedule can be tested without SSH.
  sample: Sampler
  emit: (event: FleetSampleEvent) => void
  // Reports whether credentials can currently be resolved at all. When they
  // cannot, sweeping every target would produce one failure per server per
  // interval, forever, plus an audit entry each — so the loop parks instead.
  vaultUnlocked: () => boolean
  now?: () => number
  setTimer?: (fn: () => void, ms: number) => ReturnType<typeof setTimeout>
  clearTimer?: (t: ReturnType<typeof setTimeout>) => void
}

export function clampInterval(ms: number): number {
  // NaN falls back to the DEFAULT, not the minimum. A corrupt or missing
  // setting resolving to "sample as fast as allowed" is the wrong direction to
  // fail in — it maximises load on the estate to recover from a bad number.
  // Infinity is not garbage, it is an extreme, so it clamps like any other.
  if (Number.isNaN(ms)) return FLEET_INTERVAL_DEFAULT_MS
  return Math.min(FLEET_INTERVAL_MAX_MS, Math.max(FLEET_INTERVAL_MIN_MS, Math.round(ms)))
}

// A key distinct from the one a mounted card uses, so a background sweep and a
// focused 2s poll do not evict each other from metricsSample's short cache or
// share an in-flight promise. They are asking the same question at different
// cadences and either may be cancelled independently.
export const fleetKey = (serverId: string): string => `fleet:${serverId}`

export class FleetSampler {
  private cfg: FleetSamplerConfig = { enabled: false, intervalMs: FLEET_INTERVAL_MIN_MS, targets: [] }
  private timer: ReturnType<typeof setTimeout> | null = null
  private sweeping = false
  private disposed = false
  private lastSweepAt: number | undefined
  private lastSweepMs: number | undefined
  // Bumped on every configure() and dispose(). A sweep that was in flight
  // across a reconfigure checks this before scheduling the next one, so a
  // stale sweep cannot resurrect a loop the caller has just stopped.
  private generation = 0

  constructor(private readonly deps: FleetSamplerDeps) {}

  private get now(): number {
    return (this.deps.now ?? Date.now)()
  }

  configure(next: FleetSamplerConfig): void {
    if (this.disposed) return
    this.generation++
    this.cfg = { ...next, intervalMs: clampInterval(next.intervalMs) }
    this.stopTimer()
    if (this.shouldRun()) this.schedule(0)
  }

  private shouldRun(): boolean {
    return this.cfg.enabled && this.cfg.targets.length > 0 && this.deps.vaultUnlocked()
  }

  status(): FleetSamplerStatus {
    const base = {
      targetCount: this.cfg.targets.length,
      lastSweepAt: this.lastSweepAt,
      lastSweepMs: this.lastSweepMs
    }
    if (!this.cfg.enabled) return { running: false, idleReason: 'disabled', ...base }
    if (this.cfg.targets.length === 0) return { running: false, idleReason: 'no-targets', ...base }
    if (!this.deps.vaultUnlocked()) return { running: false, idleReason: 'vault-locked', ...base }
    return { running: true, ...base }
  }

  private stopTimer(): void {
    if (!this.timer) return
    ;(this.deps.clearTimer ?? clearTimeout)(this.timer)
    this.timer = null
  }

  private schedule(delayMs: number): void {
    this.stopTimer()
    const gen = this.generation
    this.timer = (this.deps.setTimer ?? setTimeout)(() => {
      this.timer = null
      if (gen !== this.generation) return
      void this.sweep('scheduled')
    }, delayMs)
  }

  /** Sweep now, out of band. Used when the monitor opens so it is not cold. */
  async sampleNow(): Promise<void> {
    if (!this.cfg.enabled || this.cfg.targets.length === 0) return
    await this.sweep('requested')
  }

  private async sweep(reason: FleetSampleReason): Promise<void> {
    // One sweep at a time. A requested sweep arriving mid-sweep is dropped
    // rather than queued: it would double the load to answer a question the
    // in-flight sweep is already answering.
    if (this.sweeping || this.disposed) return
    const gen = this.generation
    this.sweeping = true
    const started = this.now

    try {
      // Sequential, not Promise.all. Fifteen servers behind two bastions means
      // the parallel version opens fifteen exec channels through two hosts at
      // once, which is a load spike on exactly the machines an operator cannot
      // afford to wobble. A sweep is not latency-sensitive; it is allowed to
      // take a while.
      for (const t of this.cfg.targets) {
        if (gen !== this.generation || this.disposed) return
        // Re-checked inside the loop: an auto-lock partway through a sweep
        // should stop it, not produce a failure for every remaining server.
        if (!this.deps.vaultUnlocked()) break

        try {
          const res = await this.deps.sample(fleetKey(t.serverId), t.cfg)
          if (gen !== this.generation || this.disposed) return
          this.deps.emit(
            res.ok && res.data
              ? { serverId: t.serverId, reason, at: this.now, host: res.data as FleetSampleEvent['host'] }
              : { serverId: t.serverId, reason, at: this.now, error: res.error ?? 'unavailable' }
          )
        } catch (err) {
          // One unreachable host must not end the sweep: the others are the
          // reason it is running.
          this.deps.emit({
            serverId: t.serverId,
            reason,
            at: this.now,
            error: err instanceof Error ? err.message : String(err)
          })
        }
      }
      this.lastSweepAt = this.now
      this.lastSweepMs = this.lastSweepAt - started
    } finally {
      this.sweeping = false
      // Measured from the end of the sweep, so a sweep that takes longer than
      // the interval slows the cadence rather than overlapping with itself.
      if (gen === this.generation && !this.disposed && this.shouldRun()) {
        this.schedule(this.cfg.intervalMs)
      }
    }
  }

  dispose(): void {
    this.disposed = true
    this.generation++
    this.stopTimer()
  }
}
