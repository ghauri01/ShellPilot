import { randomUUID } from 'node:crypto'
import { join } from 'node:path'
import type { WebContents } from 'electron'
import type {
  VpnDependent,
  VpnEngineInfo,
  VpnKind,
  VpnLogLine,
  VpnProfile,
  VpnPrompt,
  VpnResult,
  VpnSpec,
  VpnStartResult,
  VpnStats,
  VpnStatus,
  VpnValidation
} from '../../../shared/vpn'
import { isVpnRunning } from '../../../shared/vpn'
import { isVaultLockedError, resolveVpnSecrets } from '../credentialResolver'
import { listCachedVpns } from '../mcpDataCache'
import { redactOutput } from '../secretRedaction'
import { loadData } from '../store'
import {
  clearVpnConsumers,
  hasLiveVpnDependents,
  registerVpnConsumer,
  vpnDependents
} from './dependencies'
import type { ResolvedVpnSecrets, VpnDriverContext } from './driver'
import { driverFor, allDrivers } from './drivers'
import { toVpnResult, VpnError } from './errors'
import { registerVpnManager } from './managerApi'
import { elevatorForPlatform } from './elevation'
import { restoreOrphanedNetstate } from './netstate'
import { createRunDir, disposeRunDir, runIdSegment, sweepRunDirs, vpnRunRoot } from './runDir'
import { elevatedNetContext } from './drivers/wireguard'
import { VpnStatusBus } from './statusBus'
import { Supervisor } from './supervisor'

// The one place that owns running VPNs.
//
// Everything protocol-specific is behind `VpnDriver`; this file owns the parts
// that are the same for all three engines and that are easy to get subtly
// wrong: making sure a start cannot race a stop, that secrets are resolved
// fresh and dropped afterwards, that a status reaching the renderer has been
// coalesced, that a log line has been redacted before it is stored rather than
// before it is shown, and that stopping a transport tears down what was riding
// on it first.

interface Live {
  profile: VpnProfile
  runId: string
  runDir: string
  logs: VpnLogLine[]
  logBytes: number
  releaseConsumers: (() => void)[]
}

const LOG_RING_LINES = 2000
// A line cap alone is not a bound: the supervisor truncates a single line at
// 1 MB, so 2000 lines is a 2 GB ceiling. The supervisor's own LogRing carries a
// byte budget for exactly this reason — two agents each built a ring and only
// one of them read the note.
const LOG_RING_BYTES = 1 << 20

// Where a system-mode tunnel can have made changes worth reverting. macOS is
// absent because system mode is refused there, so there is never a snapshot.
const SYSTEM_MODE_PLATFORMS = new Set<NodeJS.Platform>(['linux', 'win32'])

const live = new Map<string, Live>()
// The final log of the most recent run per profile, kept after the run is torn
// down so a failure can still be read. Replaced on the next start, dropped when
// the profile is forgotten.
const lastLogs = new Map<string, VpnLogLine[]>()
// One serial queue per profile: every start and stop for a given id runs after
// the previous one has settled. See enqueue().
const pending = new Map<string, Promise<unknown>>()
const bus = new VpnStatusBus()
const supervisor = new Supervisor()

let prompter: ((p: VpnPrompt) => Promise<string | null>) | null = null
let started = false

// ------------------------------------------------------------------ profiles

interface DataShape {
  vpns?: unknown
}

/** Profiles come from the renderer's data blob, the same file servers and
 *  tunnels live in. Main reads it and never writes it — a second writer is how
 *  that file gets truncated. */
export function vpnProfiles(): VpnProfile[] {
  const raw = (loadData() as DataShape | null)?.vpns
  if (!Array.isArray(raw)) return []
  const out: VpnProfile[] = []
  for (const item of raw) {
    if (!item || typeof item !== 'object') continue
    const p = item as Partial<VpnProfile>
    // A profile from before this feature existed, or a half-written one, is
    // skipped rather than allowed to throw on every list call.
    if (typeof p.id !== 'string' || !p.spec || typeof p.spec !== 'object') continue
    if (typeof (p.spec as VpnSpec).kind !== 'string') continue
    out.push({
      id: p.id,
      workspaceId: typeof p.workspaceId === 'string' ? p.workspaceId : '',
      name: typeof p.name === 'string' ? p.name : p.id,
      autoStart: p.autoStart === true,
      spec: p.spec as VpnSpec
    })
  }
  return out
}

export function vpnProfile(id: string): VpnProfile | null {
  return vpnProfiles().find((p) => p.id === id) ?? null
}

/** Resolve a profile by its display name, for the MCP bridge and the CLI.
 *  Case-insensitive, and ambiguous names are an error rather than a coin
 *  toss — an agent starting "the other office VPN" is not a recoverable
 *  mistake. */
export function vpnProfileByName(name: string, workspaceIds?: string[]): VpnProfile | null {
  const wanted = name.trim().toLowerCase()
  const matches = vpnProfiles().filter(
    (p) =>
      p.name.trim().toLowerCase() === wanted &&
      (!workspaceIds || workspaceIds.includes(p.workspaceId))
  )
  return matches.length === 1 ? matches[0] : null
}

// -------------------------------------------------------------------- status

export function vpnList(): VpnStatus[] {
  const known = new Map(bus.all().map((s) => [s.id, s]))
  // A profile that has not run in this app session has no status of its own,
  // and reporting nothing at all would leave the UI with an empty list on a
  // fresh launch. Synthesise `stopped`, which is what it is.
  return vpnProfiles().map(
    (p) =>
      known.get(p.id) ?? {
        id: p.id,
        kind: p.spec.kind,
        state: 'stopped' as const,
        restarts: 0
      }
  )
}

export function vpnStatus(id: string): VpnStatus | null {
  return bus.latest(id)
}

export function vpnLogs(id: string, limit = 500): VpnLogLine[] {
  const lines = live.get(id)?.logs ?? lastLogs.get(id) ?? []
  return limit >= lines.length ? [...lines] : lines.slice(-limit)
}

export function vpnAttachRenderer(wc: WebContents): void {
  bus.addTarget(wc)
}

export function vpnDetachRenderer(wc: WebContents): void {
  bus.removeTarget(wc)
}

export function vpnSetCadence(mode: 'active' | 'idle'): void {
  bus.setCadence(mode)
}

export function vpnSubscribeLogs(id: string): void {
  bus.subscribeLogs(id)
}

export function vpnUnsubscribeLogs(id: string): void {
  bus.unsubscribeLogs(id)
}

export function setVpnPrompter(fn: (p: VpnPrompt) => Promise<string | null>): void {
  prompter = fn
}

// ------------------------------------------------------------------ validate

export function vpnValidate(spec: VpnSpec): VpnValidation {
  try {
    return driverFor(spec.kind).validateConfig(spec)
  } catch (e) {
    // validateConfig is documented as pure and non-throwing, but it is called
    // on every keystroke from a form; a bug in it must not take the window
    // down with it.
    return {
      ok: false,
      issues: [
        {
          path: '',
          severity: 'error',
          code: 'validator-failed',
          message: e instanceof Error ? e.message : String(e)
        }
      ]
    }
  }
}

export async function vpnProbe(kind: VpnKind): Promise<VpnEngineInfo> {
  // driverFor returns undefined for a kind that is not in the registry, which
  // only a corrupt profile or a malformed IPC argument can produce — but the
  // resulting TypeError would escape the IPC handler as an unhandled rejection
  // rather than reaching the caller.
  const driver = driverFor(kind)
  if (!driver) {
    return { kind, available: false, bundled: false, reason: `Unknown tunnel type "${kind}".` }
  }
  try {
    return await driver.probe()
  } catch (e) {
    return { kind, available: false, bundled: false, reason: toVpnResult(e).error }
  }
}

// --------------------------------------------------------------------- start

/** Run `fn` after whatever start or stop is already queued for this profile.
 *
 *  E50. Two earlier attempts at this were both subtly wrong in the same way:
 *  they read the in-flight marker, and only then armed their own — with an
 *  `await` in between. An await yields, so a stop arriving immediately after a
 *  start saw nothing to wait for and ran alongside it, leaving two engines
 *  fighting over one listen port.
 *
 *  A queue fixes it by construction: the chain is extended **synchronously**,
 *  before any caller can yield, so ordering does not depend on where the awaits
 *  happen to fall. It also means the "is it already running?" check runs after
 *  the predecessor has finished, which is the only time its answer is true. */
function enqueue<T>(id: string, fn: () => Promise<T>): Promise<T> {
  const prev = pending.get(id) ?? Promise.resolve()
  // A failed predecessor must not cancel what is queued behind it.
  const task = prev.then(fn, fn)
  pending.set(id, task)
  void task.catch(() => undefined).finally(() => {
    if (pending.get(id) === task) pending.delete(id)
  })
  return task
}

export function vpnStart(id: string): Promise<VpnStartResult> {
  return enqueue(id, async () => {
    const current = bus.latest(id)
    if (current && current.state !== 'stopped' && current.state !== 'error') {
      return { ok: true, listeners: current.listeners }
    }

    const profile = vpnProfile(id)
    if (!profile) {
      return { ok: false, error: 'That VPN profile no longer exists.', errorCode: 'config-invalid' }
    }
    return doStart(profile)
  })
}

// E52: two profiles asking for the same local port.
//
// The OS reports EADDRINUSE either way, and a driver turns that into
// `port-in-use` — but "port 1080 is already in use" sends the user hunting
// through their whole machine, when the answer is almost always the other
// ShellPilot profile they left running. A driver cannot say that: it only
// knows its own run. The manager knows all of them, so the check belongs here.
//
// This does not replace the driver's EADDRINUSE handling. Something outside
// ShellPilot can still hold the port, and two starts can still race between
// this check and the bind. It converts the common case from a puzzle into a
// sentence.
function portConflict(profile: VpnProfile): string | null {
  const wanted = new Map<string, number>()
  if (profile.spec.kind === 'wireguard') {
    for (const l of profile.spec.listeners) {
      // Port 0 means "pick one", so it can never collide.
      if (l.bindPort > 0) wanted.set(`${l.bindHost}:${l.bindPort}`, l.bindPort)
    }
  }
  if (wanted.size === 0) return null

  for (const status of bus.all()) {
    if (status.id === profile.id) continue
    if (!isVpnRunning(status.state)) continue
    for (const bound of status.listeners ?? []) {
      const key = `${bound.bindHost}:${bound.bindPort}`
      // A listener on 0.0.0.0 shadows every loopback bind of the same port,
      // and vice versa — comparing only the exact pair would miss the case
      // that actually bites.
      const clashes =
        wanted.has(key) ||
        [...wanted.values()].some(
          (p) =>
            p === bound.bindPort &&
            (bound.bindHost === '0.0.0.0' || bound.bindHost === '::' || wildcardWanted(profile, p))
        )
      if (clashes) {
        const other = vpnProfile(status.id)?.name ?? status.id
        return `Port ${bound.bindPort} is already being used by the VPN profile "${other}".`
      }
    }
  }
  return null
}

function wildcardWanted(profile: VpnProfile, port: number): boolean {
  if (profile.spec.kind !== 'wireguard') return false
  return profile.spec.listeners.some(
    (l) => l.bindPort === port && (l.bindHost === '0.0.0.0' || l.bindHost === '::')
  )
}

async function doStart(profile: VpnProfile): Promise<VpnStartResult> {
  const driver = driverFor(profile.spec.kind)

  const validation = vpnValidate(profile.spec)
  if (!validation.ok) {
    const first = validation.issues.find((i) => i.severity === 'error')
    // The message alone, without the dotted spec path. `proxies[0].
    // acknowledgedExposure` is internal notation and means nothing in a toast;
    // the message it carries is already a full sentence.
    return fail(profile, 'config-invalid', first?.message)
  }

  const clash = portConflict(profile)
  if (clash) return fail(profile, 'port-in-use', clash)

  const runId = `${profile.id}-${randomUUID().slice(0, 8)}`
  let runDir: string
  let secrets: ResolvedVpnSecrets
  try {
    runDir = await createRunDir(runId)
  } catch (e) {
    return fail(profile, 'internal', e instanceof Error ? e.message : undefined)
  }

  try {
    // Resolved fresh at every start and never cached: the vault can be locked
    // between two starts, and holding plaintext in a module map would quietly
    // defeat that.
    secrets = await resolveVpnSecrets(profile)
  } catch (e) {
    await disposeRunDir(runId).catch(() => undefined)
    if (isVaultLockedError(e)) return fail(profile, 'vault-locked')
    return fail(profile, e instanceof VpnError ? e.code : 'internal', describe(e))
  }

  const entry: Live = {
    profile,
    runId,
    runDir,
    logs: [],
    logBytes: 0,
    releaseConsumers: []
  }
  live.set(profile.id, entry)

  // Clear the previous failure explicitly: the emit spread carries `prev`
  // forward, so without this a retry reads "Starting…" beside the error it is
  // retrying.
  emit(profile, { state: 'starting', since: Date.now(), restarts: 0, error: undefined, errorCode: undefined })

  const ctx: VpnDriverContext = {
    runDir,
    secrets,
    emit: (patch) => emit(profile, patch),
    dropped: (reason, errorCode) => {
      // Queued like a stop, so reconciling cannot interleave with a start the
      // user began at the same moment.
      void enqueue(profile.id, () => doDropped(profile, reason, errorCode)).catch(() => undefined)
    },
    log: (line, stream) => appendLog(entry, line, stream, secrets.all),
    askUser: (p) => askUser(profile, p),
    supervisor
  }

  try {
    const result = await driver.start(profile as VpnProfile & { spec: never }, ctx)
    if (!result.ok) {
      await cleanup(profile.id)
      emit(profile, { state: 'error', error: result.error, errorCode: result.errorCode })
      return result
    }
    emit(profile, { state: 'connected', listeners: result.listeners, error: undefined, errorCode: undefined })
    return result
  } catch (e) {
    await cleanup(profile.id)
    const r = toVpnResult(e)
    emit(profile, { state: 'error', error: r.error, errorCode: r.errorCode })
    return r
  }
}

// ---------------------------------------------------------------------- stop

export function vpnStop(id: string, opts?: { force?: boolean }): Promise<VpnResult> {
  return enqueue(id, async () => {
    const profile = live.get(id)?.profile ?? vpnProfile(id)
    if (!profile) {
      // Nothing to stop. Not an error: a caller asking twice should get the
      // same answer both times.
      return { ok: true }
    }
    return doStop(profile, opts)
  })
}

async function doStop(profile: VpnProfile, opts?: { force?: boolean }): Promise<VpnResult> {
  // Dependents die before the transport they ride on, so nothing observes a
  // half-dead network — the same ordering tunnel.ts applies to a dropped SSH
  // client, and the reason quit ordering in index.ts matters too. They are
  // released first regardless of whether the engine then stops cleanly: a
  // session riding a tunnel we are tearing down is finished either way.
  await releaseDependents(profile.id)
  try {
    await driverFor(profile.spec.kind).stop(profile.id, opts)
    // Only now. Emitting `stopped` up front would be more responsive, and it
    // would also be a lie whenever the engine refuses to die — the user would
    // see a stopped tunnel while a process still held the port and, in system
    // mode, still held their routes.
    emit(profile, { state: 'stopped', error: undefined, errorCode: undefined })
    return { ok: true }
  } catch (e) {
    const r = toVpnResult(e)
    emit(profile, { state: 'error', error: r.error, errorCode: r.errorCode })
    return r
  } finally {
    await cleanup(profile.id)
  }
}

/** E18: the tunnel went down on its own. Everything riding it is closed with
 *  an explicit reason — there is no silent fallback to an unprotected path,
 *  because a session that quietly carries on outside the tunnel is worse than
 *  one that stops. */
export function vpnDropped(id: string, reason: string): Promise<void> {
  const profile = live.get(id)?.profile ?? vpnProfile(id)
  if (!profile) return Promise.resolve()
  return enqueue(id, () => doDropped(profile, reason))
}

/** Put manager, driver and supervisor state back to stopped after the engine
 *  went down by itself.
 *
 *  The driver is told to stop even though its process is already gone: its own
 *  bookkeeping is not. OpenVPN in particular keeps the session in its map, so
 *  without this the next start refuses with "This tunnel is already running."
 *  next to a Start button and a dead tunnel — recoverable only by pressing Stop
 *  first, which nothing in the UI suggests. */
async function doDropped(
  profile: VpnProfile,
  reason: string,
  errorCode: VpnStatus['errorCode'] = 'network-unreachable'
): Promise<void> {
  if (!live.has(profile.id)) return
  emit(profile, { state: 'error', error: reason, errorCode })
  await releaseDependents(profile.id)
  try {
    await driverFor(profile.spec.kind).stop(profile.id, { force: true })
  } catch {
    // The engine is already gone; a driver that objects to being told so must
    // not stop the rest of the teardown.
  }
  await cleanup(profile.id)
}

async function releaseDependents(id: string): Promise<void> {
  const entry = live.get(id)
  if (!entry) return
  // Copy first: a release callback may register or remove entries as it runs.
  const releases = [...entry.releaseConsumers]
  entry.releaseConsumers.length = 0
  for (const r of releases) {
    try {
      r()
    } catch {
      // A consumer that fails to tear down must not strand the ones after it.
    }
  }
  clearVpnConsumers(id)
}

async function cleanup(id: string): Promise<void> {
  const entry = live.get(id)
  if (!entry) return
  // Keep the log where the user can still reach it.
  //
  // Every failure path calls cleanup() before emitting the error, and the ring
  // lived on the Live entry — so `vpn:logs` returned [] from the moment the
  // error appeared, while the error itself said "Open the log to see why". The
  // last run's output is exactly what is wanted at that moment.
  if (entry.logs.length > 0) lastLogs.set(id, entry.logs)
  live.delete(id)
  await disposeRunDir(entry.runId).catch(() => undefined)
}

// -------------------------------------------------------------------- reload

export async function vpnReload(id: string): Promise<VpnResult> {
  const profile = vpnProfile(id)
  if (!profile) return { ok: false, error: 'That VPN profile no longer exists.', errorCode: 'config-invalid' }
  const driver = driverFor(profile.spec.kind)
  if (!driver) {
    return { ok: false, error: `Unknown tunnel type "${profile.spec.kind}".`, errorCode: 'config-invalid' }
  }
  if (!driver.reload) {
    // Only frp can apply a changed config without dropping its control
    // connection. For the others, restart is the honest answer.
    const stopped = await vpnStop(id)
    if (!stopped.ok) return stopped
    return vpnStart(id)
  }
  try {
    return await driver.reload(id, profile.spec as never)
  } catch (e) {
    return toVpnResult(e)
  }
}

export async function vpnStats(id: string): Promise<VpnStats | null> {
  const profile = live.get(id)?.profile ?? vpnProfile(id)
  if (!profile) return null
  try {
    return await driverFor(profile.spec.kind).stats(id)
  } catch {
    return null
  }
}

// ---------------------------------------------------------------- dependents

export function vpnDependentsOf(id: string): VpnDependent[] {
  return vpnDependents(id)
}

/** Open a forward into a running tunnel, for SSH and database connections.
 *  The shape matches `openEphemeralForward` in ../tunnel.ts so db.ts can take
 *  either without branching. Registers the caller as a live dependent, so a
 *  stop knows it would disconnect someone. */
export async function vpnOpenForward(
  id: string,
  host: string,
  port: number,
  consumer: Omit<VpnDependent, 'live'>
): Promise<{ port: number; close: () => void }> {
  const profile = vpnProfile(id)
  if (!profile) throw new VpnError('config-invalid', 'That VPN profile no longer exists.')

  const start = await vpnStart(id)
  if (!start.ok) {
    // Surface the VPN's own error rather than letting the caller time out
    // downstream. An unexplained ETIMEDOUT is the worst failure mode this
    // feature has.
    throw new VpnError(start.errorCode ?? 'internal', start.error)
  }

  const driver = driverFor(profile.spec.kind)
  if (!driver.openForward) {
    // System mode already has a route; there is nothing to forward through.
    throw new VpnError('unsupported', 'This profile does not provide local forwards.')
  }

  const fwd = await driver.openForward(id, host, port)
  const release = registerVpnConsumer(id, consumer)
  const entry = live.get(id)
  if (entry) entry.releaseConsumers.push(release)

  let closed = false
  return {
    port: fwd.port,
    close: () => {
      if (closed) return
      closed = true
      release()
      fwd.close()
    }
  }
}

// ------------------------------------------------------------------ lifecycle

/** Called once at app start, before the MCP server. Sweeps anything a previous
 *  run left behind and publishes this module to the MCP bridge. */
export async function vpnInit(): Promise<void> {
  if (started) return
  started = true

  registerVpnManager({
    statusOf: (id) => bus.latest(id),
    dependentsOf: (id) => vpnDependents(id),
    startVpn: (id) => vpnStart(id).catch(toVpnResult),
    stopVpn: (id) => vpnStop(id).catch(toVpnResult)
  })

  // Orphan reaping runs before anything is started, so a stale engine cannot
  // be mistaken for a live one and cannot hold a port the new run wants.
  await supervisor.reapOrphans().catch((e) => console.error('[vpn] orphan reap failed:', e))
  for (const d of allDrivers()) {
    if (d.reap) await d.reap().catch((e) => console.error(`[vpn] ${d.kind} reap failed:`, e))
  }
  // Put the machine's networking back before anything else touches the run
  // directories.
  //
  // This is the only failure in the whole feature that outlives the app: a
  // system-mode WireGuard run killed by a crash or a power loss leaves the
  // resolver pointed at tunnel-only DNS servers, and `netstate.json` in its run
  // directory is the only record of what to undo. `restoreOrphanedNetstate`
  // was written and tested for exactly this and was never called — while
  // `sweepRunDirs([])` deleted every run directory a moment later, destroying
  // the evidence. Order matters: restore, then sweep.
  //
  // The empty `liveRunIds` is correct here and only here: vpnInit runs before
  // any profile starts, so nothing is live yet.
  await restoreOrphanedNetstate({
    liveRunIds: [],
    createContext: (state) => {
      // Reverting routes and DNS needs root, and asking for it at launch, with
      // no visible tunnel to explain why, would be alarming. Only attempt it
      // where elevation can happen without a prompt the user has no context
      // for; otherwise the snapshot stays on disk and the next start retries.
      const elevator = elevatorForPlatform()
      if (!SYSTEM_MODE_PLATFORMS.has(process.platform)) return null
      return elevatedNetContext(
        state.runId,
        join(vpnRunRoot(), runIdSegment(state.runId)),
        elevator,
        'Restore the network settings a VPN left behind'
      )
    }
  }).catch((e) => console.error('[vpn] netstate restore failed:', e))

  await sweepRunDirs([]).catch(() => undefined)

  for (const p of vpnProfiles()) {
    if (!p.autoStart) continue
    // Auto-start is best effort: one profile that cannot come up must not stop
    // the app from finishing its startup.
    void vpnStart(p.id).catch((e) => console.error(`[vpn] autostart ${p.name} failed:`, e))
  }
}

/** Quit path. Raced against a hard timeout by the caller, so it must be safe
 *  to abandon halfway. */
export async function vpnDisposeAll(): Promise<void> {
  const ids = [...live.keys()]
  await Promise.allSettled(ids.map((id) => vpnStop(id, { force: true })))
  for (const d of allDrivers()) {
    if (d.disposeAll) await d.disposeAll().catch(() => undefined)
  }
  await supervisor.stopAll().catch(() => undefined)
  bus.dispose()
  live.clear()
}

/** True when stopping this profile would disconnect a live session, so the UI
 *  and the MCP policy can ask before doing it. */
export function vpnHasLiveDependents(id: string): boolean {
  return hasLiveVpnDependents(id)
}

/** The machine woke up, or its network changed underneath us.
 *
 *  The three engines need three different things here, which is why this is a
 *  nudge rather than a restart:
 *
 *   * WireGuard roams natively — it notices the new path from the next
 *     handshake — so all it needs is for us to resample rather than keep
 *     showing a handshake age that has been frozen since before the lid shut.
 *   * OpenVPN needs a soft restart (`signal SIGUSR1`); left alone it can sit on
 *     a dead socket until its own ping-restart timer fires, which is minutes.
 *   * frp reconnects on its heartbeat, and its health check will catch it.
 *
 *  Deliberately not a stop/start: under elevation that would mean another
 *  password prompt every time a laptop opened, which trains people to approve
 *  prompts without reading them. */
export function vpnHandleWake(): void {
  for (const [id, entry] of live) {
    const driver = driverFor(entry.profile.spec.kind) as {
      softRestart?: (id: string) => boolean
    }
    // A driver that has nothing to do on wake simply does not implement it.
    try {
      driver.softRestart?.(id)
    } catch (e) {
      console.error(`[vpn] wake nudge failed for ${entry.profile.name}:`, e)
    }
    // Resample regardless, so a frozen handshake age does not linger in the UI
    // as though nothing happened.
    void vpnStats(id)
      .then((stats) => {
        if (stats) emit(entry.profile, { stats })
      })
      .catch(() => undefined)
  }
}

/** Names of the profiles the AI bridge may see, scoped to its workspaces. */
export function vpnNamesForWorkspaces(workspaceIds: string[]): string[] {
  return listCachedVpns(workspaceIds).map((v) => v.name)
}

// --------------------------------------------------------------------- utils

function emit(profile: VpnProfile, patch: Partial<VpnStatus>): void {
  const prev = bus.latest(profile.id)
  const next: VpnStatus = {
    id: profile.id,
    kind: profile.spec.kind,
    restarts: 0,
    state: 'stopped',
    ...prev,
    ...patch
  }
  // `since` tracks the last state change, not the last message, so the UI can
  // say "connected for 4 minutes" rather than "connected for 1 second" on
  // every stats tick.
  if (!prev || prev.state !== next.state) next.since = patch.since ?? Date.now()
  bus.publish(next)
}

function fail(profile: VpnProfile, code: VpnStatus['errorCode'], detail?: string): VpnStartResult {
  const r = toVpnResult(new VpnError(code ?? 'internal', detail))
  emit(profile, { state: 'error', error: r.error, errorCode: r.errorCode })
  return r
}

function describe(e: unknown): string | undefined {
  return e instanceof Error ? e.message : undefined
}

function appendLog(
  entry: Live,
  line: string,
  stream: VpnLogLine['stream'],
  knownSecrets: string[]
): void {
  // Redacted before storage, not before display: the ring buffer, the audit
  // log and the IPC event all carry text that has already been through this.
  const text = redactOutput(line, knownSecrets)
  const rec: VpnLogLine = { at: Date.now(), stream, text }
  entry.logs.push(rec)
  entry.logBytes += text.length
  // Oldest out, by lines *and* by bytes. One 4 MB stack trace must not be able
  // to sit in memory just because it is a single line.
  while (
    entry.logs.length > LOG_RING_LINES ||
    (entry.logBytes > LOG_RING_BYTES && entry.logs.length > 1)
  ) {
    const dropped = entry.logs.shift()
    if (dropped) entry.logBytes -= dropped.text.length
  }
  bus.publishLog(entry.profile.id, rec)
}

async function askUser(
  profile: VpnProfile,
  p: Omit<VpnPrompt, 'id' | 'profileId' | 'profileName'>
): Promise<string | null> {
  if (!prompter) return null
  return prompter({
    ...p,
    id: randomUUID(),
    profileId: profile.id,
    profileName: profile.name
  })
}

/** Test seam. */
export function resetVpnManagerState(): void {
  live.clear()
  bus.dispose()
  prompter = null
  started = false
}
