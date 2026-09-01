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
  // metricsDisconnect. Called for every target the sampler stops watching.
  //
  // metricsSample holds a pooled connection per key and only releases it when
  // this is called, so without it a server dropped from the workspace kept an
  // authenticated master open for good.
  //
  // What this does NOT do, which an earlier version of this comment claimed it
  // did: a server that is still being watched is never released, so its
  // refcount never reaches zero, so release() never arms the idle timer, and
  // `sshMasterIdleMinutes` does not apply to it — a setting whose documented
  // purpose is deciding how often a two-factor code has to be re-entered.
  //
  // Releasing after each pass is not the fix. When the interval is shorter than
  // the retention the next pass re-acquires before the timer fires and nothing
  // changes; when it is longer or equal — a 15-minute interval against the
  // 5-minute retention, say — the connection really is torn down, and the next
  // background pass has to authenticate again with nobody present. On a
  // two-factor server that is an unattended prompt, which is the failure mode
  // allowPrompt exists to avoid. Holding the connection is also better for the
  // estate than reconnecting to fifteen hosts through a bastion on a timer.
  //
  // So the behaviour stays and the silence goes: both settings rows now state
  // it — see settings/connectionRetention.ts.
  release: (key: string) => void
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
  // Set when a scheduled run was refused because a sweep was already going.
  // Without it, that refusal loses the obligation to reschedule and the loop
  // stops for good. See sweep().
  private restartPending = false
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
    const previous = this.cfg.targets.map((t) => t.serverId)
    this.cfg = { ...next, intervalMs: clampInterval(next.intervalMs) }

    // Hand back the connection for anything no longer watched — a server
    // removed from the workspace, or every target when the feature is switched
    // off. Otherwise the pool keeps an authenticated master alive for a host
    // nobody is asking about any more.
    const keep = new Set(next.enabled ? next.targets.map((t) => t.serverId) : [])
    for (const id of previous) if (!keep.has(id)) this.deps.release(fleetKey(id))

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
    // Derived from the loop, not from the config. status() used to say
    // `running: true` whenever the settings said so, which is exactly what let
    // a stalled sampler go unnoticed -- the settings screen affirmed it was
    // fine while nothing had been sampled for hours.
    return { running: this.timer !== null || this.sweeping, ...base }
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
    //
    // But a DROPPED sweep must hand back the obligation to reschedule, or the
    // loop dies silently. The sequence that killed it: configure() bumps the
    // generation and schedules immediately; that timer fires while the old
    // sweep is still running, is refused here, and has already consumed
    // this.timer; the old sweep then reaches its finally, sees a generation
    // mismatch, and declines to reschedule. No timer armed, not sweeping,
    // nothing ever runs again — while status() went on reporting `running`
    // because it reads the config rather than the loop.
    //
    // It took two configure() calls seconds apart, which is what connecting to
    // a single server produces: setServerStatus fires 'connecting' then
    // 'online', each rebuilding the target list.
    if (this.sweeping || this.disposed) {
      if (!this.disposed) this.restartPending = true
      return
    }
    this.restartPending = false
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
      if (!this.disposed && this.shouldRun()) {
        if (gen === this.generation) {
          // Measured from the end of the sweep, so a sweep that takes longer
          // than the interval slows the cadence rather than overlapping.
          this.schedule(this.cfg.intervalMs)
        } else if (this.restartPending) {
          // A reconfigure landed mid-sweep and its immediate run was refused
          // above. Honour it now: the config changed, so start promptly rather
          // than waiting a full interval for state the user just asked for.
          this.restartPending = false
          this.schedule(0)
        }
      }
    }
  }

  dispose(): void {
    this.disposed = true
    this.generation++
    this.stopTimer()
    // Stopping the timer is not enough: the pooled connections outlive it.
    for (const t of this.cfg.targets) this.deps.release(fleetKey(t.serverId))
  }
}
