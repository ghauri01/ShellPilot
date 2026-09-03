import type {
  FleetSampleEvent,
  FleetSampleReason,
  FleetSamplerConfig,
  FleetSamplerStatus,
  FleetTarget
} from '../../shared/fleet'
import type { HostMetrics } from '../../shared/ssh'
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

/**
 * The slice of the durable store this file uses.
 *
 * Declared structurally here rather than imported from history.ts on purpose:
 * a direct import would drag node:sqlite and app.getPath('userData') into every
 * test that constructs a sampler, and there are a lot of them. HistoryStore
 * satisfies this shape, so main/index.ts hands over the real thing and the
 * tests hand over nothing.
 */
export interface HistoryWriter {
  transaction<T>(fn: () => T): T
  recordSamples(hostId: string, at: number, values: Record<string, number>): void
  upsertFact(hostId: string, key: string, value: string, at: number): unknown
  retireFacts(hostId: string, at: number, prefix: string, keep: Iterable<string>): number
  recordEvent(kind: string, hostId: string | null, payload?: unknown, at?: number): void
}

/**
 * The eight numeric series worth keeping per sample.
 *
 * Everything else on HostMetrics is a fact — see metricsToFacts. memTotal,
 * diskTotal, cores and kernel do not change between sweeps, and storing them as
 * series would be paying the metric budget for a constant.
 */
export function metricsToSamples(host: HostMetrics): Record<string, number> {
  return {
    cpu: host.cpu,
    memPct: host.memPct,
    memUsed: host.memUsed,
    diskPct: host.diskPct,
    diskUsed: host.diskUsed,
    netRx: host.netRx,
    netTx: host.netTx,
    uptime: host.uptime
  }
}

/**
 * The parts of a sample that are facts.
 *
 * `services` and `listeners` are the reason this function exists. They are
 * re-sampled every sweep and almost never change; a host with forty units
 * stored as samples is 28,800 rows a day for ONE host, five times the entire
 * metric budget for the estate. As facts they cost one timestamp bump per
 * sweep, and a real change becomes an event.
 *
 * Prefixes are the retirement scope: `unit:` and `port:` are swept against the
 * probe's own output so a decommissioned unit stops being a current fact.
 */
export const UNIT_FACT_PREFIX = 'unit:'
export const PORT_FACT_PREFIX = 'port:'

export function metricsToFacts(host: HostMetrics): Record<string, string> {
  const facts: Record<string, string> = {
    hostname: host.hostname,
    kernel: host.kernel,
    cores: String(host.cores),
    memTotal: String(host.memTotal),
    diskTotal: String(host.diskTotal)
  }
  if (host.listenerSource) facts.listenerSource = host.listenerSource
  // null is not empty. A host with no systemd reports null and must not have
  // its (nonexistent) unit facts recorded OR retired — the monitor already
  // respects that distinction and it has to survive into the store, or history
  // will confidently report that every unit was removed the day the probe broke.
  for (const u of host.services ?? []) {
    facts[`${UNIT_FACT_PREFIX}${u.name}`] = `${u.active}/${u.sub}`
  }
  for (const l of host.listeners ?? []) {
    facts[`${PORT_FACT_PREFIX}${l.proto}/${l.address}:${l.port}`] = l.process ?? ''
  }
  return facts
}

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
  /**
   * The durable store, resolved per sweep rather than captured once.
   *
   * A function and not the store itself because loadHistory() is async and the
   * sampler is constructed at module scope in main/index.ts, long before the
   * database has opened. Returning null is the normal state on a machine where
   * history is disabled or would not open, and every sweep behaves exactly as
   * it does today.
   */
  history?: () => HistoryWriter | null | undefined
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

/**
 * What the sampler last learned about a server, kept so the MCP bridge can
 * answer from it instead of opening a connection of its own.
 *
 * Shaped like the renderer's fleet store on purpose: a success clears the
 * error, and an error KEEPS the last good sample. "This host was fine ten
 * minutes ago and is unreachable now" is two facts and an agent needs both.
 */
export interface FleetCacheEntry {
  /** Last successful sample, if there has ever been one. */
  host?: HostMetrics
  /** When `host` was taken. */
  at?: number
  /** Set when the most recent attempt failed; cleared by a success. */
  error?: string
  errorAt?: number
}

/** One host's contribution to a sweep, held until the whole sweep is written. */
interface PendingWrite {
  serverId: string
  at: number
  host?: HostMetrics
  error?: string
  /** True when this success follows a recorded failure, so the store gets a
   *  'host-recovered' event rather than nothing at all. */
  recovered?: boolean
}

export interface FleetLookup {
  entry: FleetCacheEntry
  /** The configured sweep interval, so a caller can judge what "stale" means. */
  intervalMs: number
}

// The MCP bridge reads the cache through this rather than being handed the
// sampler: startMcpServer() takes no arguments and is called from four places,
// none of which has one. main/index.ts owns the instance and registers it here.
let active: FleetSampler | null = null

export function setActiveFleetSampler(sampler: FleetSampler | null): void {
  active = sampler
}

/** The sampler's own view of a server, or undefined if it has none. */
export function fleetCached(serverId: string): FleetLookup | undefined {
  return active?.lookup(serverId)
}

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
  // Last known state per server. Bounded by the target list: configure() drops
  // entries for anything no longer watched, in the same pass that hands back
  // its connection.
  private samples = new Map<string, FleetCacheEntry>()
  // Last known reachability per server, kept separately from `samples` because
  // that map deliberately KEEPS the last good sample across a failure — so it
  // cannot answer "was this host up on the previous sweep", which is the
  // question that turns a permanent failure into one event instead of one per
  // sweep forever. Bounded by the same target list.
  private reachable = new Map<string, boolean>()

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
    for (const id of previous) {
      if (keep.has(id)) continue
      this.deps.release(fleetKey(id))
      // Drop what we knew about it too. A server removed from the workspace
      // must not keep answering MCP questions from a sample nobody can refresh.
      this.samples.delete(id)
      this.reachable.delete(id)
    }

    this.stopTimer()
    if (this.shouldRun()) this.schedule(0)
  }

  private shouldRun(): boolean {
    return this.cfg.enabled && this.cfg.targets.length > 0 && this.deps.vaultUnlocked()
  }

  /** What this sampler last learned about one server. */
  lookup(serverId: string): FleetLookup | undefined {
    const entry = this.samples.get(serverId)
    return entry ? { entry, intervalMs: this.cfg.intervalMs } : undefined
  }

  /**
   * Re-arm after an external condition changed.
   *
   * `shouldRun()` is only consulted at configure() and at the end of a sweep.
   * A vault that locks mid-sweep fails that check, the loop stops — correctly,
   * since it cannot resolve a credential — and then nothing was telling it the
   * vault had come back. It stayed stopped until the user toggled the setting,
   * which is a workaround the settings pane was literally instructing people to
   * perform: "Turn this off and on again to restart it."
   *
   * That line was honest about the state and wrong about the remedy. Telling a
   * user to power-cycle a feature is an admission that something is not wired,
   * not an instruction worth shipping.
   *
   * Idempotent: a call while sweeping or already scheduled does nothing, so
   * every unlock path can call it without coordinating.
   */
  resume(): void {
    if (this.disposed || this.sweeping || this.timer !== null) return
    if (this.shouldRun()) this.schedule(0)
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

  // A success clears the recorded error; a failure keeps the last good sample.
  private remember(serverId: string, next: FleetCacheEntry): void {
    const previous = this.samples.get(serverId)
    this.samples.set(
      serverId,
      next.host
        ? { host: next.host, at: next.at }
        : { host: previous?.host, at: previous?.at, error: next.error, errorAt: next.errorAt }
    )
  }

  /**
   * Write one sweep to the durable store, in one transaction.
   *
   * Everything here is best-effort by construction. A store that is absent
   * (disabled, or it would not open) or that throws mid-write leaves the
   * sampler, the renderer and the MCP cache exactly as they are today — the
   * history is the feature that degrades, never the sweep.
   */
  private persist(writes: PendingWrite[]): void {
    if (writes.length === 0) return
    const store = this.deps.history?.()
    if (!store) return
    try {
      store.transaction(() => {
        for (const w of writes) {
          if (!w.host) {
            store.recordEvent('host-unreachable', w.serverId, { error: w.error }, w.at)
            continue
          }
          if (w.recovered) store.recordEvent('host-recovered', w.serverId, undefined, w.at)
          store.recordSamples(w.serverId, w.at, metricsToSamples(w.host))

          const facts = metricsToFacts(w.host)
          for (const [key, value] of Object.entries(facts)) {
            store.upsertFact(w.serverId, key, value, w.at)
          }
          // Retire only what the probe could actually see. `services: null`
          // means "no systemd here / the probe failed", which is not the same
          // as "there are no units" — retiring on null would record forty
          // fact-removed events the first time a probe broke.
          if (w.host.services) {
            store.retireFacts(
              w.serverId,
              w.at,
              UNIT_FACT_PREFIX,
              Object.keys(facts).filter((k) => k.startsWith(UNIT_FACT_PREFIX))
            )
          }
          if (w.host.listeners) {
            store.retireFacts(
              w.serverId,
              w.at,
              PORT_FACT_PREFIX,
              Object.keys(facts).filter((k) => k.startsWith(PORT_FACT_PREFIX))
            )
          }
        }
      })
    } catch (err) {
      console.error('[fleet] history write failed (sampling is unaffected):', err)
    }
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
    // Buffered, not written per host: the whole sweep goes into the store in
    // one BEGIN/COMMIT below. Fifteen hosts is ~120 sample rows plus facts, and
    // writing them one statement at a time is 120 fsyncs where one will do —
    // on the same disk this app exists to warn people about filling.
    const writes: PendingWrite[] = []

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
          const at = this.now
          // Read BEFORE remember() overwrites it: reachability is a transition,
          // and an event per sweep for a host that has been down since Tuesday
          // is 720 rows a day saying the same thing.
          const wasReachable = this.reachable.get(t.serverId)
          if (res.ok && res.data) {
            const host = res.data as HostMetrics
            this.remember(t.serverId, { host, at })
            this.reachable.set(t.serverId, true)
            writes.push({ serverId: t.serverId, at, host, recovered: wasReachable === false })
          } else {
            const error = res.error ?? 'unavailable'
            this.remember(t.serverId, { error, errorAt: at })
            this.reachable.set(t.serverId, false)
            if (wasReachable !== false) writes.push({ serverId: t.serverId, at, error })
          }
          this.deps.emit(
            res.ok && res.data
              ? { serverId: t.serverId, reason, at: this.now, host: res.data as FleetSampleEvent['host'] }
              : { serverId: t.serverId, reason, at: this.now, error: res.error ?? 'unavailable' }
          )
        } catch (err) {
          // One unreachable host must not end the sweep: the others are the
          // reason it is running.
          const message = err instanceof Error ? err.message : String(err)
          const at = this.now
          const wasReachable = this.reachable.get(t.serverId)
          this.remember(t.serverId, { error: message, errorAt: at })
          this.reachable.set(t.serverId, false)
          if (wasReachable !== false) writes.push({ serverId: t.serverId, at, error: message })
          this.deps.emit({ serverId: t.serverId, reason, at, error: message })
        }
      }
      this.lastSweepAt = this.now
      this.lastSweepMs = this.lastSweepAt - started
    } finally {
      // In the finally, so a sweep cut short by a reconfigure still persists
      // what it did learn. Inside its own try, because a store that will not
      // write is a degraded feature and never a broken sweep.
      this.persist(writes)
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
    this.samples.clear()
    this.reachable.clear()
    if (active === this) active = null
  }
}
