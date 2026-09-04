import type {
  FleetSampleEvent,
  FleetSampleReason,
  FleetSamplerConfig,
  FleetSamplerStatus,
  FleetTarget
} from '../../shared/fleet'
import type { HostAccess } from '../../shared/access'
import type { HostFacts } from '../../shared/hostFacts'
import type { HostPosture } from '../../shared/posture'
import type { HostDrift } from '../../shared/drift'
import type { HostMetrics } from '../../shared/ssh'
import { ACCESS_FACT_PREFIX, accessKeyPrefix, accessToFacts } from '../../shared/access'
import {
  FLEET_INTERVAL_DEFAULT_MS,
  FLEET_INTERVAL_MAX_MS,
  FLEET_INTERVAL_MIN_MS
} from '../../shared/fleet'
import {
  HOST_FACTS_INTERVAL_MIN_MS,
  HOST_FACTS_INTERVAL_MS,
  HOST_FACT_PREFIX,
  hostFactsToFacts
} from '../../shared/hostFacts'
import { POSTURE_FACT_PREFIX, postureToFacts } from '../../shared/posture'
import { DRIFT_FACT_PREFIX, driftToFacts } from './drift'

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
 * The host-facts probe, injected exactly as `sample` is.
 *
 * Never a direct import of main/services/hostFacts.ts: the sampler's tests
 * construct it with doubles and would otherwise drag ssh2 and a pooled
 * connection into every one of them.
 */
type FactsSampler = (
  key: string,
  cfg: FleetTarget['cfg']
) => Promise<{ ok: boolean; facts?: HostFacts; error?: string }>

/**
 * The key and access probe — roadmap item 23. Injected exactly as `sampleFacts`
 * is, and for the same reason: the sampler's tests must not drag ssh2 and a
 * pooled connection into every one of them.
 *
 * It rides the FACTS cadence rather than owning a timer. Both probes answer
 * questions that change when a person edits a file, not continuously, and a
 * second timer would need its own copy of the vault re-check, the generation
 * guard and disposal — duplicating that reasoning is how it breaks.
 */
type AccessSampler = (
  key: string,
  cfg: FleetTarget['cfg']
) => Promise<{ ok: boolean; access?: HostAccess; error?: string }>

/**
 * The security posture probe — roadmap item 24. Injected exactly as
 * `sampleFacts` and `sampleAccess` are, and for the same reason: the sampler's
 * tests must not drag ssh2 and a pooled connection into every one of them.
 *
 * It rides the FACTS cadence rather than owning a timer, like the other two.
 * A firewall ruleset changes when somebody changes it, not continuously, and a
 * third timer would need its own copy of the vault re-check, the generation
 * guard and disposal — duplicating that reasoning is how it breaks.
 */
type PostureSampler = (
  key: string,
  cfg: FleetTarget['cfg']
) => Promise<{ ok: boolean; posture?: HostPosture; error?: string }>

/**
 * The configuration drift probe — roadmap item 25. Injected exactly as the
 * three above are, and for the same reason.
 *
 * It rides the FACTS cadence too. A watched configuration file changes when
 * somebody changes it, and reading seven of them off every host every two
 * minutes would be a great deal of I/O to watch nothing happen.
 *
 * Takes the host's own name as well as the config, because the `hostnames`
 * normalisation rule cannot substitute a name nobody told it about — and
 * without it every templated file in the estate is unique and the whole
 * comparison is noise. `hostname` is what the metrics probe reported this
 * sweep; `serverName` is what the server is called in ShellPilot.
 */
type DriftSampler = (
  key: string,
  cfg: FleetTarget['cfg'],
  ctx: { hostname?: string; serverName?: string }
) => Promise<{ ok: boolean; drift?: HostDrift; error?: string }>

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
  transaction<T>(fn: () => T & (T extends PromiseLike<unknown> ? never : unknown)): T
  recordSamples(hostId: string, at: number, values: Record<string, number>): void
  upsertFact(hostId: string, key: string, value: string, at: number): unknown
  retireFacts(hostId: string, at: number, prefix: string, keep: Iterable<string>): number
  recordEvent(kind: string, hostId: string | null, payload?: unknown, at?: number): void
  /** Read, because reachability has to survive a restart — see seedReachable.
   *  Optional: this interface is the WRITE slice the sampler needs, and a
   *  double that only records is still a valid one. A writer without it simply
   *  starts each session with no memory of who was down. */
  readEvents?(filter: { hostId?: string; kind?: string; limit?: number }): { ts: number }[]
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
    // A metric that could not be measured is not recorded at all. Writing a
    // zero would put an idle CPU in the series for a sweep where the probe
    // came back with nothing, and a chart cannot tell that apart from a host
    // that was genuinely quiet.
    ...(host.cpu === null ? {} : { cpu: host.cpu }),
    ...(host.memPct === null ? {} : { memPct: host.memPct }),
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
  /**
   * The hourly host-facts probe. Optional: a sampler built without it behaves
   * exactly as it did before facts existed, which is what keeps every existing
   * test valid rather than making them all declare a probe they do not use.
   *
   * It runs INSIDE the metrics sweep, per target, when that target's facts are
   * due — not on a second timer. The sweep already handles the vault re-check,
   * the generation guard and disposal, and a parallel loop would have to
   * re-derive all three. It also only runs after a SUCCESSFUL metrics sample:
   * a host that just refused a metrics channel will refuse this one too, and
   * paying a 45-second timeout to find that out again helps nobody.
   */
  sampleFacts?: FactsSampler
  /**
   * The key and access probe — roadmap item 23. Optional for the same reason
   * `sampleFacts` is: a sampler built without it behaves exactly as it did
   * before, which keeps every existing test valid.
   *
   * Runs in the same place and under the same conditions as the facts probe —
   * inside the sequential sweep, only after a SUCCESSFUL metrics sample, and
   * only when this target's hour is up. It keeps its own due clock so a facts
   * probe that fails does not also postpone this one.
   */
  sampleAccess?: AccessSampler
  /**
   * Whether the key and access probe may run at all, resolved PER SWEEP.
   *
   * The one place in this file where a module toggle gates a channel rather
   * than a panel, and deliberately so. Every other optional module in this app
   * hides its UI while its main-process handlers stay registered — defensible
   * for a handler somebody has to call, and not defensible for a probe that
   * runs by itself on every host every hour and reads other accounts' home
   * directories with `sudo -n`. "We now read everyone's authorized_keys on all
   * of your servers" is a thing a person switches on, not one they discover in
   * a sudo log.
   *
   * A function rather than a flag so a toggle takes effect on the next sweep
   * rather than at the next restart. Absent means the gate is not installed,
   * which is how every existing test keeps working.
   */
  accessEnabled?: () => boolean
  /**
   * The security posture probe — roadmap item 24. Optional for the reason
   * `sampleFacts` and `sampleAccess` are: a sampler built without it behaves
   * exactly as it did before, which keeps every existing test valid rather
   * than making them all declare a probe they do not use.
   *
   * Runs in the same place and under the same conditions as the other two —
   * inside the sequential sweep, only after a SUCCESSFUL metrics sample, and
   * only when this target's hour is up. Its own due clock, so a facts or
   * access probe that keeps failing does not also postpone this one.
   */
  samplePosture?: PostureSampler
  /**
   * Whether the posture probe may run at all, resolved PER SWEEP.
   *
   * The SECOND place in this file where a module toggle gates a channel rather
   * than a panel, and it earns that for a different reason from the access
   * probe's. That one is gated because of what it does on the host — walking
   * /etc/passwd and reading other accounts' files under `sudo -n`. This one is
   * gated because of what it PRODUCES: which port is open on which host, which
   * of them still take passwords over ssh, and which have SELinux switched
   * off. That is a map of how to attack the estate, held in one process's
   * memory and written into the durable store, and building it is a thing a
   * person switches on rather than discovers.
   *
   * A function rather than a flag so a toggle takes effect on the next sweep
   * rather than at the next restart. Absent means the gate is not installed,
   * which is how every existing test keeps working.
   */
  postureEnabled?: () => boolean
  /**
   * The configuration drift probe — roadmap item 25. Optional for the reason
   * the other three are: a sampler built without it behaves exactly as it did
   * before, which keeps every existing test valid.
   *
   * Same place, same conditions, its own due clock.
   */
  sampleDrift?: DriftSampler
  /**
   * Whether the drift probe may run at all, resolved PER SWEEP.
   *
   * The THIRD place in this file where a module toggle gates a channel rather
   * than a panel, and it earns that for the posture probe's reason rather than
   * the access probe's: not what it does on the host — it reads seven
   * world-readable files with no sudo anywhere — but what it PRODUCES.
   *
   * A map of which hosts differ from a known-good configuration is a map of
   * which hosts are behind, and "these three still have PasswordAuthentication
   * where the other twelve do not" is a target list. That is worth having,
   * which is why it exists; it is not worth having without somebody deciding
   * to have it.
   *
   * A function rather than a flag so a toggle takes effect on the next sweep
   * rather than at the next restart. Absent means the gate is not installed,
   * which is how every existing test keeps working.
   */
  driftEnabled?: () => boolean
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

/**
 * The facts cadence, clamped separately from the metrics one.
 *
 * There is no maximum: a user who wants facts once a day is asking for
 * something reasonable about data that changes when somebody runs an upgrade.
 * The minimum exists because the probe is a 45-second-budget round trip that
 * shells out to a package manager, and running it at the metrics cadence would
 * put `dnf check-update` on every host every two minutes.
 */
export function clampFactsInterval(ms: number | undefined): number {
  if (ms === undefined || Number.isNaN(ms)) return HOST_FACTS_INTERVAL_MS
  return Math.max(HOST_FACTS_INTERVAL_MIN_MS, Math.round(ms))
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
  /**
   * The last successful host-facts collection. Kept on the SAME entry as the
   * metrics sample but on its own clock: facts are collected hourly, so
   * `factsAt` is normally much older than `at`, and anything reading them has
   * to say which age it is quoting.
   */
  facts?: HostFacts
  factsAt?: number
  /** Set when the most recent facts probe failed; cleared by a success, and
   *  kept ALONGSIDE the last good facts for the same reason `error` is kept
   *  alongside the last good sample. */
  factsError?: string
  factsErrorAt?: number
  /**
   * The last successful key and access collection — roadmap item 23. Its own
   * clock again, for the reason `factsAt` has one: an inventory read an hour
   * ago is not the same claim as a metrics sample taken two minutes ago, and
   * anything quoting it has to say which age it means.
   */
  access?: HostAccess
  accessAt?: number
  /** Set when the most recent access probe failed; cleared by a success and
   *  kept ALONGSIDE the last good collection. "This host's keys were read an
   *  hour ago and the probe is failing now" is two facts and both matter —
   *  most of all here, where the alternative is an empty key list that reads
   *  as "this host trusts nobody". */
  accessError?: string
  accessErrorAt?: number
  /**
   * The last successful posture collection — roadmap item 24. Its own clock
   * again, for the reason `factsAt` has one: a firewall read an hour ago is
   * not the same claim as a metrics sample taken two minutes ago, and anything
   * quoting it has to say which age it means.
   */
  posture?: HostPosture
  postureAt?: number
  /** Set when the most recent posture probe failed; cleared by a success and
   *  kept ALONGSIDE the last good collection. "This host's firewall was read
   *  an hour ago and the probe is failing now" is two facts and both matter —
   *  most of all here, where the alternative is an empty reading that renders
   *  as a host with no rules. */
  postureError?: string
  postureErrorAt?: number
  /**
   * The last successful configuration drift collection — roadmap item 25. Its
   * own clock again, for the reason `factsAt` has one.
   *
   * This is also where the bounded redacted PREVIEW of each watched file lives,
   * and the only place it ever lives: it is not written to the durable store
   * and does not survive a restart. See the note at the top of
   * services/drift.ts about what is stored and what is only held.
   */
  drift?: HostDrift
  driftAt?: number
  /** Set when the most recent drift probe failed; cleared by a success and
   *  kept ALONGSIDE the last good collection. A host whose files were read an
   *  hour ago and whose probe is failing now has NOT come into line, and the
   *  comparison must not render it as a host that matches. */
  driftError?: string
  driftErrorAt?: number
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
  /** Present only on the sweeps where the facts probe was also due. */
  facts?: HostFacts
  /** Present only on the sweeps where the access probe was also due. */
  access?: HostAccess
  /** Present only on the sweeps where the posture probe was also due. */
  posture?: HostPosture
  /** Present only on the sweeps where the drift probe was also due. */
  drift?: HostDrift
}

export interface FleetLookup {
  entry: FleetCacheEntry
  /** The configured sweep interval, so a caller can judge what "stale" means. */
  intervalMs: number
  /** The facts cadence, which is a different number entirely — quoting the
   *  metrics interval against a facts timestamp would call an hour-old fact
   *  thirty intervals stale when it is exactly on schedule. */
  factsIntervalMs: number
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
  // The sweep currently in flight, so dispose() can hand a caller something to
  // wait on. A sweep persists in its finally, and main/index.ts closes the
  // store right after dispose() returns — without this the last sweep of every
  // session lands after the close and is dropped.
  private inFlight: Promise<void> | null = null
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
  // When each server's host facts are next due, per target and NOT on a timer
  // of its own. The sweep checks this inline; see the note on deps.sampleFacts.
  //
  // A server with no entry is due immediately, which is what makes the first
  // sweep after a restart collect facts rather than waiting an hour for a
  // schedule the process cannot remember. Bounded by the target list, cleared
  // in the same pass as `samples`.
  private factsDueAt = new Map<string, number>()
  // The same, for the key and access probe — roadmap item 23. A SEPARATE map
  // rather than a shared due time: the two probes fail independently, and one
  // clock would let a host whose facts probe keeps timing out postpone its
  // access collection too, so an estate would quietly stop being inventoried
  // for a reason that has nothing to do with keys.
  private accessDueAt = new Map<string, number>()
  // The same again, for the posture probe — roadmap item 24. A THIRD map
  // rather than a shared due time, for the reason the second one exists: the
  // probes fail independently, and one clock would let a host whose access
  // probe keeps timing out postpone its posture collection too.
  private postureDueAt = new Map<string, number>()
  // And a FOURTH, for the configuration drift probe — roadmap item 25. Same
  // reason as the second and the third: the probes fail independently, and one
  // shared clock lets a host whose posture probe keeps timing out postpone its
  // drift collection too.
  private driftDueAt = new Map<string, number>()
  // Servers whose last known reachability has already been looked up in the
  // store. Once per server per process: the in-memory map is the answer after
  // that, and a lookup on every sweep would be two reads per host forever.
  private seeded = new Set<string>()

  constructor(private readonly deps: FleetSamplerDeps) {}

  /**
   * Recover what the last session knew about one server's reachability.
   *
   * `reachable` is in-memory, so without this the sequence "host goes down, app
   * restarts, host is still down" raises host-unreachable a second time — and,
   * because the transition it thinks it saw is undefined->false rather than
   * true->false, never emits the matching host-recovered when the host comes
   * back. An alert that can be raised twice and closed never.
   *
   * Best-effort by construction, like every other use of the store here: a
   * missing or throwing store leaves the map exactly as it was.
   */
  private seedReachable(serverId: string): void {
    if (this.seeded.has(serverId)) return
    this.seeded.add(serverId)
    try {
      const store = this.deps.history?.()
      if (!store) {
        // Not seeded after all — the store may open later in this session.
        this.seeded.delete(serverId)
        return
      }
      if (!store.readEvents) return
      const last = (kind: string): number | undefined =>
        store.readEvents?.({ hostId: serverId, kind, limit: 1 })[0]?.ts
      const down = last('host-unreachable')
      const up = last('host-recovered')
      if (down === undefined) return
      // A recovery newer than the outage means it was up when we last looked;
      // no recovery at all, or an older one, means it was down.
      this.reachable.set(serverId, up !== undefined && up > down)
    } catch (err) {
      console.error('[fleet] could not read last known reachability (not fatal):', err)
    }
  }

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
      this.factsDueAt.delete(id)
      this.accessDueAt.delete(id)
      this.postureDueAt.delete(id)
      this.driftDueAt.delete(id)
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
    return entry
      ? {
          entry,
          intervalMs: this.cfg.intervalMs,
          factsIntervalMs: clampFactsInterval(this.cfg.factsIntervalMs)
        }
      : undefined
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
  //
  // The facts half is carried across UNTOUCHED in both directions. Facts are
  // collected on their own hourly clock, so nearly every metrics sample lands
  // between two collections — rebuilding the entry without them would erase an
  // hour-old fact set thirty times an hour and leave the inventory permanently
  // empty except in the one sweep that had just refreshed it.
  private remember(serverId: string, next: FleetCacheEntry): void {
    const previous = this.samples.get(serverId)
    const facts = {
      facts: previous?.facts,
      factsAt: previous?.factsAt,
      factsError: previous?.factsError,
      factsErrorAt: previous?.factsErrorAt,
      // Carried across for exactly the reason the facts are. An access
      // collection is hourly, so nearly every metrics sample lands between two
      // of them — rebuilding the entry without it would erase the key inventory
      // thirty times an hour and leave the panel reporting "no keys" on a host
      // that trusts a dozen.
      access: previous?.access,
      accessAt: previous?.accessAt,
      accessError: previous?.accessError,
      accessErrorAt: previous?.accessErrorAt,
      // And again for the posture, for exactly the same reason. Rebuilding the
      // entry without it would erase the firewall reading thirty times an hour
      // and leave the panel reporting "not collected" on a host it read
      // perfectly well four minutes ago.
      posture: previous?.posture,
      postureAt: previous?.postureAt,
      postureError: previous?.postureError,
      postureErrorAt: previous?.postureErrorAt,
      // And again for configuration drift — roadmap item 25 — for the same
      // reason a third time. This one carries the bounded redacted PREVIEW of
      // each watched file as well as the hashes, and that preview exists
      // nowhere else: dropping it here would blank the side-by-side view thirty
      // times an hour with no way to get it back short of the next hourly
      // collection.
      drift: previous?.drift,
      driftAt: previous?.driftAt,
      driftError: previous?.driftError,
      driftErrorAt: previous?.driftErrorAt
    }
    this.samples.set(
      serverId,
      next.host
        ? { ...facts, host: next.host, at: next.at }
        : { ...facts, host: previous?.host, at: previous?.at, error: next.error, errorAt: next.errorAt }
    )
  }

  /**
   * Record one host-facts collection, on the entry the metrics sample owns.
   *
   * A success clears the facts error and a failure keeps the last good facts,
   * mirroring `remember` — "this host's inventory was read an hour ago and the
   * probe is failing now" is two facts and both matter.
   */
  private rememberFacts(serverId: string, at: number, facts?: HostFacts, error?: string): void {
    const entry = this.samples.get(serverId) ?? {}
    this.samples.set(
      serverId,
      facts
        ? { ...entry, facts, factsAt: at, factsError: undefined, factsErrorAt: undefined }
        : { ...entry, factsError: error ?? 'unavailable', factsErrorAt: at }
    )
  }

  /**
   * Record one key and access collection, on the entry the metrics sample owns.
   *
   * Mirrors `rememberFacts` exactly, including the part that matters most here:
   * a FAILURE KEEPS THE LAST GOOD COLLECTION. Replacing it with nothing would
   * turn "the probe could not run this hour" into an empty key list, and an
   * empty key list is the one thing this feature must never invent.
   */
  private rememberAccess(serverId: string, at: number, access?: HostAccess, error?: string): void {
    const entry = this.samples.get(serverId) ?? {}
    this.samples.set(
      serverId,
      access
        ? { ...entry, access, accessAt: at, accessError: undefined, accessErrorAt: undefined }
        : { ...entry, accessError: error ?? 'unavailable', accessErrorAt: at }
    )
  }

  /**
   * Record one posture collection, on the entry the metrics sample owns.
   *
   * Mirrors `rememberAccess` exactly, including the part that matters most: a
   * FAILURE KEEPS THE LAST GOOD COLLECTION. Replacing it with nothing would
   * turn "the probe could not run this hour" into a host with no firewall
   * reading, and the panel would then have to decide what that means — which
   * is precisely the decision this item exists to take away from it.
   */
  private rememberPosture(serverId: string, at: number, posture?: HostPosture, error?: string): void {
    const entry = this.samples.get(serverId) ?? {}
    this.samples.set(
      serverId,
      posture
        ? { ...entry, posture, postureAt: at, postureError: undefined, postureErrorAt: undefined }
        : { ...entry, postureError: error ?? 'unavailable', postureErrorAt: at }
    )
  }

  /** What this sampler last collected about one server's security posture, for
   *  the IPC surface the posture view reads — roadmap item 24. Separate from
   *  `accessFor` so a caller that wants the firewall is not handed a key
   *  inventory to ignore. */
  postureFor(serverId: string): {
    posture?: HostPosture
    at?: number
    error?: string
    errorAt?: number
    intervalMs: number
  } {
    const entry = this.samples.get(serverId)
    return {
      posture: entry?.posture,
      at: entry?.postureAt,
      error: entry?.postureError,
      errorAt: entry?.postureErrorAt,
      intervalMs: clampFactsInterval(this.cfg.factsIntervalMs)
    }
  }

  /**
   * Record one configuration drift collection, on the entry the metrics sample
   * owns.
   *
   * Mirrors `rememberPosture` exactly, including the part that matters most: a
   * FAILURE KEEPS THE LAST GOOD COLLECTION. Replacing it with nothing would
   * turn "the probe could not run this hour" into a host with no readings, and
   * a host with no readings is one the comparison reports as uncollected — a
   * softer word than the truth, which is that this host stopped answering while
   * still holding whatever configuration it had.
   */
  private rememberDrift(serverId: string, at: number, drift?: HostDrift, error?: string): void {
    const entry = this.samples.get(serverId) ?? {}
    this.samples.set(
      serverId,
      drift
        ? { ...entry, drift, driftAt: at, driftError: undefined, driftErrorAt: undefined }
        : { ...entry, driftError: error ?? 'unavailable', driftErrorAt: at }
    )
  }

  /** What this sampler last collected about one server's watched configuration
   *  files, for the IPC surface the drift view reads — roadmap item 25.
   *  Separate from `postureFor` so a caller that wants a config comparison is
   *  not handed a firewall reading to ignore. */
  driftFor(serverId: string): {
    drift?: HostDrift
    at?: number
    error?: string
    errorAt?: number
    intervalMs: number
  } {
    const entry = this.samples.get(serverId)
    return {
      drift: entry?.drift,
      at: entry?.driftAt,
      error: entry?.driftError,
      errorAt: entry?.driftErrorAt,
      intervalMs: clampFactsInterval(this.cfg.factsIntervalMs)
    }
  }

  /** What this sampler last collected about who can get into one server, for
   *  the IPC surface the access view reads. Separate from `factsFor` so a
   *  caller that wants keys is not handed an inventory to ignore. */
  accessFor(serverId: string): {
    access?: HostAccess
    at?: number
    error?: string
    errorAt?: number
    intervalMs: number
  } {
    const entry = this.samples.get(serverId)
    return {
      access: entry?.access,
      at: entry?.accessAt,
      error: entry?.accessError,
      errorAt: entry?.accessErrorAt,
      intervalMs: clampFactsInterval(this.cfg.factsIntervalMs)
    }
  }

  /** What this sampler last collected about one server's identity, for the IPC
   *  surface the inventory view reads. Separate from `lookup` so a caller that
   *  wants only facts is not handed a whole metrics sample to ignore. */
  factsFor(serverId: string): {
    facts?: HostFacts
    at?: number
    error?: string
    errorAt?: number
    intervalMs: number
  } {
    const entry = this.samples.get(serverId)
    return {
      facts: entry?.facts,
      at: entry?.factsAt,
      error: entry?.factsError,
      errorAt: entry?.factsErrorAt,
      intervalMs: clampFactsInterval(this.cfg.factsIntervalMs)
    }
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
    try {
      // Inside the try, not above it. persist() is called from the sweep's
      // finally, before `sweeping = false` and before the reschedule — so a
      // resolver that throws (any future provider that can fail) aborts the
      // finally, leaves `sweeping` true forever and stops sampling for good
      // while status() goes on reporting `running`. That is the silent-death
      // mode the long comment in sweep() exists to prevent, through a new door.
      const store = this.deps.history?.()
      if (!store) return
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

          // Host facts, into the SAME store — item A's, not a second one, and
          // never into shellpilot-data.json, which is the encrypted backup
          // payload rather than a place to keep an hourly inventory.
          //
          // Written only on the sweeps where the probe actually ran. `w.facts`
          // absent means "not due this sweep", so retiring here would delete a
          // complete inventory thirty times an hour and record a fact-removed
          // event for each key every time.
          if (w.facts) {
            const hostFacts = hostFactsToFacts(w.facts)
            for (const [key, value] of Object.entries(hostFacts)) {
              store.upsertFact(w.serverId, key, value, w.at)
            }
            // Retired against the probe's own output, so a host that switches
            // package manager — or stops being able to answer something it used
            // to answer — loses the stale key instead of keeping it next to a
            // fresher one. Safe to sweep unconditionally here, unlike units and
            // ports: hostFactsToFacts writes a key for EVERY field, storing the
            // source's status where the value is null, so a failed probe still
            // produces a complete key set rather than an empty one.
            store.retireFacts(w.serverId, w.at, HOST_FACT_PREFIX, Object.keys(hostFacts))
          }

          // Key and access facts — roadmap item 23, into the SAME store.
          //
          // The retirement here is the delicate part, and it is deliberately
          // NOT the unconditional sweep host facts get. `retireFacts` records a
          // fact-removed event for everything it drops, and a fact-removed
          // event on an authorized key reads as "this key was revoked on this
          // host" — which is precisely the audit trail this item exists to
          // produce, and precisely the thing that must never be fabricated.
          //
          // So keys are retired PER ACCOUNT, and only for accounts whose file
          // was actually read this hour. An account that went `denied` because
          // somebody tightened a home directory keeps every key it had, and the
          // status fact next to it says the reading is stale. The alternative —
          // one sweep of the whole `access:` prefix — would report a clean
          // revocation of every key on the host the first time sudo stopped
          // working.
          if (w.access) {
            const accessFacts = accessToFacts(w.access)
            for (const [key, value] of Object.entries(accessFacts)) {
              store.upsertFact(w.serverId, key, value, w.at)
            }
            for (const a of w.access.accounts) {
              if (a.keys === null) continue
              const prefix = accessKeyPrefix(a.user)
              store.retireFacts(
                w.serverId,
                w.at,
                prefix,
                Object.keys(accessFacts).filter((k) => k.startsWith(prefix))
              )
            }
            // The host-level scalars — source statuses, counts, completeness —
            // are written for every collection, so sweeping them is safe in the
            // way the per-account key rows are not. Scoped to the flat keys so
            // it cannot reach a `user:` row.
            store.retireFacts(
              w.serverId,
              w.at,
              `${ACCESS_FACT_PREFIX}source:`,
              Object.keys(accessFacts).filter((k) => k.startsWith(`${ACCESS_FACT_PREFIX}source:`))
            )
          }

          // Security posture — roadmap item 24, into the SAME store.
          //
          // Swept unconditionally, the way host facts are and the way the key
          // rows above deliberately are NOT. The distinction is what the sweep
          // can fabricate: `retireFacts` records a fact-removed event for
          // everything it drops, and on an authorized key that event reads as
          // "this key was revoked", which must never be invented. Nothing here
          // is per-object — every key is a flat scalar, and `postureToFacts`
          // writes ALL of them on every collection, storing the source's status
          // where the value is null. So a failed probe still produces a
          // complete key set, and a sweep against that output can only ever
          // retire a key the shape of the posture genuinely no longer has.
          //
          // Written only on the sweeps where the probe actually ran: `w.posture`
          // absent means "not due this sweep", and sweeping then would delete a
          // complete reading thirty times an hour.
          if (w.posture) {
            const postureFacts = postureToFacts(w.posture)
            for (const [key, value] of Object.entries(postureFacts)) {
              store.upsertFact(w.serverId, key, value, w.at)
            }
            store.retireFacts(w.serverId, w.at, POSTURE_FACT_PREFIX, Object.keys(postureFacts))
          }

          // Configuration drift — roadmap item 25, into the SAME store, and
          // swept unconditionally for exactly the reason posture is: nothing
          // here is per-object. `driftToFacts` writes a status row for EVERY
          // watched file on every collection, including the ones that could not
          // be read, so the key set is complete whatever the probe managed and
          // a sweep against it can only retire a watch the catalogue no longer
          // has.
          //
          // What is written is two hashes, a status and a list of rule ids per
          // file. No content of any kind — see services/drift.ts. `upsertFact`
          // reports 'changed' for a hash that moved, which is what turns a
          // config edit into a fact-changed event without this file storing a
          // single line of anybody's nginx.conf.
          if (w.drift) {
            const driftFacts = driftToFacts(w.drift)
            for (const [key, value] of Object.entries(driftFacts)) {
              store.upsertFact(w.serverId, key, value, w.at)
            }
            store.retireFacts(w.serverId, w.at, DRIFT_FACT_PREFIX, Object.keys(driftFacts))
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
    // Published before the first await so a dispose() arriving mid-sweep has
    // something to hand back to a caller that must not close the store yet.
    let finished = (): void => undefined
    this.inFlight = new Promise<void>((resolve) => (finished = resolve))
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
          if (!this.reachable.has(t.serverId)) this.seedReachable(t.serverId)
          const wasReachable = this.reachable.get(t.serverId)
          // Empty on the ~29 sweeps in 30 where facts were not due. Spread into
          // the emitted event, so a listener sees the field only when there is
          // something to say — an always-present `facts: undefined` would read
          // as "collected, and this host has none".
          let factsEvent: { facts?: HostFacts; factsError?: string } = {}
          if (res.ok && res.data) {
            const host = res.data as HostMetrics
            this.remember(t.serverId, { host, at })
            this.reachable.set(t.serverId, true)
            const write: PendingWrite = {
              serverId: t.serverId,
              at,
              host,
              recovered: wasReachable === false
            }

            // The slow probe, inline in this same sequential loop rather than
            // on a second timer. The sweep already owns the vault re-check, the
            // generation guard and disposal; a parallel facts loop would have to
            // re-derive all three, and duplicating that reasoning is how it
            // breaks.
            //
            // Only after a successful metrics sample, and only when this
            // target's hour is up.
            if (this.deps.sampleFacts && at >= (this.factsDueAt.get(t.serverId) ?? 0)) {
              // Set BEFORE the probe, not after. A probe that throws, times out
              // or is abandoned by a reconfigure must still push the next
              // attempt an hour out — otherwise a host that reliably fails is
              // retried on every sweep with a 45-second budget, which is the
              // whole estate's sweep time spent on one broken box.
              this.factsDueAt.set(t.serverId, at + clampFactsInterval(this.cfg.factsIntervalMs))
              const probe = await this.deps.sampleFacts(fleetKey(t.serverId), t.cfg).catch((err) => ({
                ok: false as const,
                error: err instanceof Error ? err.message : String(err)
              }))
              if (gen !== this.generation || this.disposed) return
              const factsAt = this.now
              if (probe.ok && probe.facts) {
                this.rememberFacts(t.serverId, factsAt, probe.facts)
                write.facts = probe.facts
                factsEvent = { facts: probe.facts }
              } else {
                const error = probe.error ?? 'unavailable'
                this.rememberFacts(t.serverId, factsAt, undefined, error)
                factsEvent = { factsError: error }
              }
            }

            // The key and access probe — roadmap item 23. Same place, same
            // conditions, its own due clock. Sequential after the facts probe
            // rather than beside it: two 45-to-60-second reads opened at once
            // on the same connection is two exec channels on a link a terminal
            // may be typing over, which is the thing this whole loop is shaped
            // to avoid.
            const accessOn = this.deps.accessEnabled?.() ?? true
            if (this.deps.sampleAccess && accessOn && at >= (this.accessDueAt.get(t.serverId) ?? 0)) {
              // Set BEFORE the probe, for the reason the facts one is: a probe
              // that throws or times out must still push the next attempt an
              // hour out, or one broken host eats the whole estate's sweep.
              this.accessDueAt.set(t.serverId, at + clampFactsInterval(this.cfg.factsIntervalMs))
              const probe = await this.deps.sampleAccess(fleetKey(t.serverId), t.cfg).catch((err) => ({
                ok: false as const,
                error: err instanceof Error ? err.message : String(err)
              }))
              if (gen !== this.generation || this.disposed) return
              const accessAt = this.now
              if (probe.ok && probe.access) {
                this.rememberAccess(t.serverId, accessAt, probe.access)
                write.access = probe.access
              } else {
                this.rememberAccess(t.serverId, accessAt, undefined, probe.error ?? 'unavailable')
              }
            }

            // The security posture probe — roadmap item 24. Same place, same
            // conditions, its own due clock, and sequential after the other two
            // rather than beside them: three long reads opened at once on the
            // same connection is three exec channels on a link a terminal may
            // be typing over, which is the thing this whole loop is shaped to
            // avoid.
            const postureOn = this.deps.postureEnabled?.() ?? true
            if (this.deps.samplePosture && postureOn && at >= (this.postureDueAt.get(t.serverId) ?? 0)) {
              // Set BEFORE the probe, for the reason the other two are: a probe
              // that throws or times out must still push the next attempt an
              // hour out, or one broken host eats the whole estate's sweep.
              this.postureDueAt.set(t.serverId, at + clampFactsInterval(this.cfg.factsIntervalMs))
              const probe = await this.deps.samplePosture(fleetKey(t.serverId), t.cfg).catch((err) => ({
                ok: false as const,
                error: err instanceof Error ? err.message : String(err)
              }))
              if (gen !== this.generation || this.disposed) return
              const postureAt = this.now
              if (probe.ok && probe.posture) {
                this.rememberPosture(t.serverId, postureAt, probe.posture)
                write.posture = probe.posture
              } else {
                this.rememberPosture(t.serverId, postureAt, undefined, probe.error ?? 'unavailable')
              }
            }

            // The configuration drift probe — roadmap item 25. Same place, same
            // conditions, its own due clock, and sequential after the other
            // three for the reason they are sequential with each other: four
            // long reads opened at once is four exec channels on a link a
            // terminal may be typing over.
            const driftOn = this.deps.driftEnabled?.() ?? true
            if (this.deps.sampleDrift && driftOn && at >= (this.driftDueAt.get(t.serverId) ?? 0)) {
              // Set BEFORE the probe, for the reason the other three are.
              this.driftDueAt.set(t.serverId, at + clampFactsInterval(this.cfg.factsIntervalMs))
              const probe = await this.deps
                .sampleDrift(fleetKey(t.serverId), t.cfg, {
                  // The host's own name, so the `hostnames` normalisation rule
                  // has something to substitute. Taken from THIS sweep's sample
                  // rather than from the cache, because a host that was renamed
                  // would otherwise be normalised against the name it used to
                  // have and every one of its files would read as drifted.
                  hostname: (res.data as HostMetrics | undefined)?.hostname,
                  serverName: t.serverName
                })
                .catch((err) => ({
                  ok: false as const,
                  error: err instanceof Error ? err.message : String(err)
                }))
              if (gen !== this.generation || this.disposed) return
              const driftAt = this.now
              if (probe.ok && probe.drift) {
                this.rememberDrift(t.serverId, driftAt, probe.drift)
                write.drift = probe.drift
              } else {
                this.rememberDrift(t.serverId, driftAt, undefined, probe.error ?? 'unavailable')
              }
            }
            writes.push(write)
          } else {
            const error = res.error ?? 'unavailable'
            this.remember(t.serverId, { error, errorAt: at })
            this.reachable.set(t.serverId, false)
            if (wasReachable !== false) writes.push({ serverId: t.serverId, at, error })
          }
          this.deps.emit(
            res.ok && res.data
              ? {
                  serverId: t.serverId,
                  reason,
                  at: this.now,
                  host: res.data as FleetSampleEvent['host'],
                  ...factsEvent
                }
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
      this.inFlight = null
      // Last, so anything awaiting dispose() sees a sweep that has finished
      // persisting AND finished deciding whether to reschedule.
      finished()
    }
  }

  /**
   * Stop sampling. The returned promise settles once any in-flight sweep has
   * finished writing what it had already collected.
   *
   * Callers that only want the loop stopped can ignore it, exactly as before.
   * A caller that is about to close the store must await it: dispose() marks
   * the sweep abandoned, but the sweep still persists what it learned in its
   * finally, and a store closed before that lands drops those writes — which is
   * precisely what the comment above historyStore.close() in main/index.ts says
   * must not happen.
   */
  dispose(): Promise<void> {
    this.disposed = true
    this.generation++
    this.stopTimer()
    // Stopping the timer is not enough: the pooled connections outlive it.
    for (const t of this.cfg.targets) this.deps.release(fleetKey(t.serverId))
    this.samples.clear()
    this.reachable.clear()
    this.factsDueAt.clear()
    this.accessDueAt.clear()
    this.postureDueAt.clear()
    this.driftDueAt.clear()
    this.seeded.clear()
    if (active === this) active = null
    return this.inFlight ?? Promise.resolve()
  }
}
