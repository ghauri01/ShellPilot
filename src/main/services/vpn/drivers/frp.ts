import { randomBytes } from 'node:crypto'
import net from 'node:net'
import type {
  FrpProxyStatus,
  FrpSpec,
  VpnBoundListener,
  VpnEngineInfo,
  VpnErrorCode,
  VpnLogLine,
  VpnProfile,
  VpnResult,
  VpnStartResult,
  VpnStats,
  VpnStatus,
  VpnValidation
} from '../../../../shared/vpn'
import { resolveBundled } from '../binaries'
import type { ResolvedVpnSecrets, VpnDriver, VpnDriverContext } from '../driver'
import { describeVpnError, isVpnError, toVpnResult, VpnError } from '../errors'
import type { FrpReadiness } from '../frpAdminApi'
import {
  FrpAdminApi,
  frpErrorFromLine,
  frpReadinessError,
  stripAnsi,
  summariseFrpProxies
} from '../frpAdminApi'
import type { FrpResolvedSecrets } from '../frpConfig'
import { frpEnv, generateFrpToml, validateFrpSpec } from '../frpConfig'
import { writeSecretFile } from '../runDir'
import type { SupervisedSpec, SupervisorExit, SupervisorHandle } from '../supervisor'

// frp is the odd engine out. WireGuard and OpenVPN pull this machine towards a
// network; frp pushes a port of this machine out to whoever can reach the frp
// server. Everything unusual below follows from that inversion:
//
//  * `start()` refuses unless every proxy carries `acknowledgedExposure`. It is
//    a gate, not a preference (E41): a profile with four proxies where three
//    were confirmed does not start.
//  * `openForward` is deliberately absent. frp is an inbound-exposure tool, not
//    a transport, so there is nothing for db.ts to dial through and the manager
//    reports `unsupported` rather than opening something meaningless.
//  * `reload()` exists, and only here. frpc can swap its whole proxy set over a
//    live control connection, so a changed profile does not drop the tunnel.
//  * `stats()` omits rxBytes/txBytes. frp exposes no client-side counters and a
//    zero would read as "no traffic" rather than "not measurable".

const FRPC = 'frpc'
// Fixed: the admin API is our own control channel, not an account, and the
// password beside it is 32 fresh random bytes per run.
const ADMIN_USER = 'shellpilot'
const ADMIN_PASSWORD_BYTES = 32
const CONFIG_FILE = 'frpc.toml'
const POLL_INTERVAL_MS = 200
// Roughly a screen of output: enough to hold the line that explains an exit.
const LOG_SCAN_LINES = 200
// The supervisor puts its own deadline around `readiness()`. Ours has to expire
// first, because ours can say "the frp server rejected this token" and the
// supervisor's can only say "not ready within 30s" (E33, E65).
const READINESS_SLACK_MS = 5_000
// frpc's own wording for a control connection that came up. It is the only
// signal a visitors-only profile gives: visitors register nothing on the
// server, so `/api/status` has nothing to count.
const LOGIN_OK = /login to server success/i

/** Timings and the port picker, gathered so a test can shorten a thirty-second
 *  wait and pin an otherwise random port. Production never writes to this; the
 *  defaults are the plan's numbers (§6.3). */
export const frpTuning = {
  readinessTimeoutMs: 30_000,
  /** A reload is a foreground action, so it waits a shorter time before it
   *  reports what it found and lets `stats()` carry the rest. */
  reloadTimeoutMs: 10_000,
  healthIntervalMs: 15_000,
  gracefulTimeoutMs: 5_000,
  /** How many times a lost race for the admin port is retried before it is
   *  reported as `port-in-use`. */
  adminPortAttempts: 3,
  /** Null means the real picker: bind 127.0.0.1:0, read the port, release it. */
  adminPortPicker: null as null | (() => Promise<number>)
}

/** frpc could not bind the admin port we chose for it. Its own class because
 *  it is the one failure that is worth retrying with a different port rather
 *  than reporting: we released the port before frpc started, so anything on
 *  the machine could have taken it in between. */
class AdminPortTaken extends VpnError {}

/** Exit-time codes that a restart cannot fix. A wrong token retried five times
 *  is five failed logins against the user's account and a `crash-loop` error
 *  that says nothing about the token (E33), so the run is stopped and the
 *  engine's own sentence is what the user sees. */
const TERMINAL_ON_EXIT: ReadonlySet<VpnErrorCode> = new Set<VpnErrorCode>([
  'auth-failed',
  'version-mismatch',
  'config-invalid',
  'config-rejected'
])

interface Run {
  profile: VpnProfile
  spec: FrpSpec
  ctx: VpnDriverContext
  api: FrpAdminApi
  adminPort: number
  adminPassword: string
  /** The names from the spec we generated, never the names in a response. */
  proxyNames: string[]
  handle: SupervisorHandle | null
  status: VpnStatus
  stopping: boolean
  /** True once start() has returned success. After that a terminal exit is a
   *  *drop* the manager must reconcile, not a start that failed. */
  started: boolean
  /** Ends the in-flight `start()` with a better error than the one the
   *  supervisor would eventually produce. A no-op once the start has settled. */
  fail: (e: unknown) => void
  /** Cancels a readiness poll that would otherwise outlive the run it belongs
   *  to and keep dialling a port nothing is listening on. */
  abort: AbortController
  detach: (() => void)[]
}

const runs = new Map<string, Run>()

// ------------------------------------------------------------------ secrets

const PLUGIN_PREFIX = 'plugin:'

/** `ResolvedVpnSecrets` is one flat shape for three engines, so frp's per-proxy
 *  secrets share `proxySecretKeys` with its per-proxy plugin passwords, the
 *  latter under a `plugin:<name>` key (credentialResolver.ts). The OIDC client
 *  secret rides in `password`, the one free single-value slot. This is where
 *  that packing is undone, and it is the only place that knows about it. */
export function frpSecretsFrom(secrets: ResolvedVpnSecrets): FrpResolvedSecrets {
  const pluginPasswords: Record<string, string> = {}
  for (const [key, value] of Object.entries(secrets.proxySecretKeys ?? {})) {
    if (key.startsWith(PLUGIN_PREFIX)) pluginPasswords[key.slice(PLUGIN_PREFIX.length)] = value
  }
  return {
    token: secrets.token,
    oidcClientSecret: secrets.password,
    // Passed whole: a `plugin:<name>` key can never collide with a proxy name,
    // because a proxy name may not contain a colon.
    proxySecretKeys: secrets.proxySecretKeys,
    pluginPasswords
  }
}

// -------------------------------------------------------------------- ports

/** Bind :0, note what the kernel handed out, release it. frpc has no "tell me
 *  the port you chose" channel, so the port has to be decided before it starts
 *  and written into its config — which means letting go of it first. The window
 *  between the release and frpc's own bind is real, and `start()` retries when
 *  something wins it. */
export function reserveAdminPort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const srv = net.createServer()
    srv.once('error', reject)
    srv.listen(0, '127.0.0.1', () => {
      const addr = srv.address()
      const port = typeof addr === 'object' && addr ? addr.port : 0
      srv.close(() => {
        if (port) resolve(port)
        else reject(new VpnError('port-in-use', 'No local port was free for the control channel.'))
      })
    })
  })
}

function pickAdminPort(): Promise<number> {
  return (frpTuning.adminPortPicker ?? reserveAdminPort)()
}

// ------------------------------------------------------------------- status

function publish(run: Run, patch: Partial<VpnStatus>): void {
  run.status = { ...run.status, ...patch }
  run.ctx.emit(patch)
}

function applyProxies(run: Run, proxies: FrpProxyStatus[]): void {
  // A proxy in `start error` is degraded, not error: the control connection is
  // up and the other proxies are carrying traffic. frpc's own wording comes
  // through verbatim — `port already used` already tells the user what to do.
  const summary = summariseFrpProxies(proxies, run.proxyNames)
  publish(run, { state: summary.state, error: summary.error, errorCode: summary.errorCode })
}

/** frp reports no byte counters anywhere in the admin API, so rxBytes/txBytes
 *  are left off rather than reported as zero. The proxy table is the telemetry,
 *  and this cast is where that decision is written down. */
function frpStats(proxies: FrpProxyStatus[]): VpnStats {
  const stats: Omit<VpnStats, 'rxBytes' | 'txBytes'> = { proxies, sampledAt: Date.now() }
  return stats as VpnStats
}

// --------------------------------------------------------------------- logs

/** frpc colours every line and puts the reset at the start of the *next* one,
 *  so nothing may be pattern-matched before it has been stripped. Both streams
 *  are read: frpc writes its warnings and errors to stdout, not stderr. */
function logText(h: SupervisorHandle | null): string[] {
  return (h?.logs(LOG_SCAN_LINES) ?? []).map((l: VpnLogLine) => stripAnsi(l.text))
}

/** The most recent line that classifies, so a run that logged a warning and
 *  then died of something else reports the something else. */
function lastEngineError(lines: string[]): VpnError | null {
  for (let i = lines.length - 1; i >= 0; i--) {
    const err = frpErrorFromLine(lines[i])
    if (err) return err
  }
  return null
}

// ---------------------------------------------------------------- readiness

function sleep(ms: number, signal: AbortSignal): Promise<void> {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      signal.removeEventListener('abort', onAbort)
      resolve()
    }, ms)
    const onAbort = (): void => {
      clearTimeout(timer)
      reject(signal.reason)
    }
    signal.addEventListener('abort', onAbort, { once: true })
  })
}

const NOT_READY: FrpReadiness = {
  ready: false,
  proxies: [],
  failed: [],
  missing: [],
  timedOut: true
}

/** A visitors-only profile has nothing in `/api/status` to count, so the login
 *  line is the only evidence frpc reached frps. Deliberately not `/healthz`:
 *  that goes green as soon as the admin listener is up, which says nothing
 *  about the server. */
async function awaitLogin(run: Run, h: SupervisorHandle): Promise<void> {
  const deadline = Date.now() + frpTuning.readinessTimeoutMs
  for (;;) {
    const lines = logText(h)
    if (lines.some((l) => LOGIN_OK.test(l))) return
    if (Date.now() >= deadline) throw frpReadinessError(NOT_READY, lines)
    await sleep(POLL_INTERVAL_MS, run.abort.signal)
  }
}

async function awaitReady(run: Run, h: SupervisorHandle): Promise<void> {
  try {
    if (run.proxyNames.length === 0) {
      await awaitLogin(run, h)
      publish(run, { state: 'connected', error: undefined, errorCode: undefined })
      return
    }

    // Counted against the *configured* names. frpc answers `200 {}` before it
    // has logged in to frps, so a check that iterates the response passes
    // vacuously and reports a tunnel connected to nothing.
    const readiness = await run.api.waitForReady(run.proxyNames, {
      timeoutMs: frpTuning.readinessTimeoutMs,
      signal: run.abort.signal
    })
    // A readiness timeout with an empty proxy table means frpc never logged in,
    // and the reason is in the log. "The frp server rejected this token" beats
    // "something took too long" every time.
    if (readiness.timedOut) throw frpReadinessError(readiness, logText(h))
    applyProxies(run, readiness.proxies)
  } catch (e) {
    // An engine that never came up is reported now, with the reason, rather
    // than after two minutes of backoff that can only end in `crash-loop`
    // (E54's kill-and-retry still applies to a run that *was* up and dropped;
    // this only short-circuits a start that never reached readiness once).
    run.fail(e)
    throw e
  }
}

// -------------------------------------------------------------------- start

/** Every proxy, every time. Nothing about a partially confirmed profile is
 *  safe to start: the unconfirmed one is exposed exactly as much as the rest. */
function exposureGate(spec: FrpSpec): VpnError | null {
  const unconfirmed = spec.proxies.filter((p) => p.acknowledgedExposure !== true)
  if (unconfirmed.length === 0) return null
  const named = unconfirmed
    .map((p) => `"${p.name}" (${p.localIp}:${p.localPort} reachable from ${spec.serverAddr})`)
    .join(', ')
  return new VpnError('exposure-unacknowledged', `Not confirmed: ${named}.`)
}

/** Visitors bind a real local port, so they are listeners in the sense the rest
 *  of the app means. Proxies are not: what they open is a port on the frp
 *  server, and reporting that here would put a remote address in a field the UI
 *  labels "listening on". `stats().proxies` is where those belong. */
function visitorListeners(spec: FrpSpec): VpnBoundListener[] {
  return spec.visitors.map((v) => ({ kind: v.type, bindHost: v.bindAddr, bindPort: v.bindPort }))
}

function supervisedSpec(
  run: Run,
  enginePath: string,
  sha256: string | undefined,
  configPath: string,
  env: Record<string, string>
): SupervisedSpec {
  return {
    id: run.profile.id,
    command: enginePath,
    // The config path is the only argument. Every secret is in `env`, reached
    // through frp's `{{ .Envs.X }}` templating: /proc/<pid>/cmdline is
    // world-readable and /proc/<pid>/environ is not.
    args: ['-c', configPath],
    env,
    cwd: run.ctx.runDir,
    readiness: (h) => awaitReady(run, h),
    readinessTimeoutMs: frpTuning.readinessTimeoutMs + READINESS_SLACK_MS,
    healthCheck: () => run.api.healthz(),
    healthIntervalMs: frpTuning.healthIntervalMs,
    // Load-bearing on Windows, where a non-console child has no SIGTERM and
    // `process.kill` is a hard TerminateProcess. The control channel is the
    // only chance frpc gets to close its connections politely.
    gracefulStop: () => run.api.stop(),
    gracefulTimeoutMs: frpTuning.gracefulTimeoutMs,
    restart: 'on-failure',
    backoff: { baseMs: 1_000, maxMs: 30_000, jitter: 0.3 },
    crashLoop: { windowMs: 120_000, maxRestarts: 5 },
    logRing: { maxLines: 2_000, maxBytes: 1 << 20 },
    // The admin password is ours rather than the user's, but it is still a
    // credential and frpc echoes its config back on request.
    redact: [...run.ctx.secrets.all, run.adminPassword],
    kind: 'frp',
    profileId: run.profile.id,
    exeSha256: sha256,
    onRestartScheduled: (h) => {
      publish(run, { state: 'reconnecting', restarts: h.restarts })
    }
  }
}

/** Decide, from a child that has just exited, whether this run is over. The
 *  supervisor owns backoff; this only overrides it for the cases where
 *  retrying is worse than stopping. */
function onExit(run: Run, exit: SupervisorExit): void {
  if (run.stopping) return
  const err = lastEngineError(logText(run.handle))

  if (err?.code === 'port-in-use') {
    // The only way an *exit* reports a port conflict is the admin listener: a
    // proxy whose remote port is taken sits in `start error` and keeps running.
    run.fail(new AdminPortTaken('port-in-use', err.detail))
    return
  }
  if (exit.restarting) {
    // A wrong token retried five times is five failed logins against the
    // user's account and a `crash-loop` that says nothing about the token.
    if (err && TERMINAL_ON_EXIT.has(err.code)) run.fail(err)
    return
  }

  // The supervisor has given up. The engine's own last word beats a generic
  // exit code wherever there is one (E65).
  const final =
    (err && TERMINAL_ON_EXIT.has(err.code) ? err : exit.error) ??
    err ??
    new VpnError('internal', `frpc exited with code ${exit.code}.`)
  for (const l of exit.logTail ?? []) run.ctx.log(l.text, l.stream)
  if (run.started) {
    run.ctx.dropped(describeVpnError(final.code, final.detail), final.code)
    return
  }
  publish(run, {
    state: 'error',
    error: describeVpnError(final.code, final.detail),
    errorCode: final.code
  })
  run.fail(final)
}

async function startAttempt(
  run: Run,
  engine: VpnEngineInfo,
  secrets: FrpResolvedSecrets,
  adminPort: number
): Promise<SupervisorHandle> {
  run.adminPort = adminPort
  run.api = new FrpAdminApi({ port: adminPort, user: ADMIN_USER, password: run.adminPassword })

  const toml = generateFrpToml(run.spec, { adminPort, adminUser: ADMIN_USER })
  // On disk, and legitimately so: what this file holds are `{{ .Envs.* }}`
  // templates, not secrets — frpc resolves them from its own environment at
  // load. 0600 regardless, because it still names every port this machine is
  // about to expose and to whom.
  const configPath = await writeSecretFile(run.ctx.runDir, CONFIG_FILE, toml)
  const env = frpEnv(run.spec, secrets, {
    adminPort,
    adminUser: ADMIN_USER,
    adminPassword: run.adminPassword
  })

  const failed = new Promise<never>((_resolve, reject) => {
    run.fail = reject
  })

  const spec = supervisedSpec(run, engine.path ?? FRPC, engine.sha256, configPath, env)
  const pending = run.ctx.supervisor.spawn(spec)
  // The handle exists from the moment `spawn` is called, and log lines start
  // arriving well before readiness: an engine given a bad config has said
  // everything it is going to say within milliseconds.
  const handle = run.ctx.supervisor.get(run.profile.id)
  if (handle) {
    run.handle = handle
    run.detach.push(handle.onLog((l) => run.ctx.log(l.text, l.stream)))
    run.detach.push(handle.onExit((e) => onExit(run, e)))
  }

  const ready = await Promise.race([pending, failed])
  run.handle = ready
  return ready
}

async function start(
  profile: VpnProfile & { spec: FrpSpec },
  ctx: VpnDriverContext
): Promise<VpnStartResult> {
  const gate = exposureGate(profile.spec)
  if (gate) return toVpnResult(gate)

  const engine = await resolveBundled(FRPC)
  const secrets = frpSecretsFrom(ctx.secrets)

  const run: Run = {
    profile,
    spec: profile.spec,
    ctx,
    api: new FrpAdminApi({ port: 0, user: ADMIN_USER, password: '' }),
    adminPort: 0,
    adminPassword: randomBytes(ADMIN_PASSWORD_BYTES).toString('base64url'),
    proxyNames: profile.spec.proxies.map((p) => p.name),
    handle: null,
    status: { id: profile.id, kind: 'frp', state: 'starting', since: Date.now(), restarts: 0 },
    stopping: false,
    started: false,
    fail: () => {},
    abort: new AbortController(),
    detach: []
  }
  runs.set(profile.id, run)

  let last: unknown = null
  for (let attempt = 0; attempt < frpTuning.adminPortAttempts; attempt++) {
    try {
      await startAttempt(run, engine, secrets, await pickAdminPort())
      run.started = true
      return { ok: true, listeners: visitorListeners(profile.spec) }
    } catch (e) {
      last = e
      await discard(run)
      // Only the lost-port race is worth another go. Anything else would be
      // the same failure with a different number in it.
      if (!(e instanceof AdminPortTaken)) break
    }
  }

  runs.delete(profile.id)
  if (last instanceof AdminPortTaken) {
    return toVpnResult(
      new VpnError(
        'port-in-use',
        `The control channel port was taken by something else ${frpTuning.adminPortAttempts} times in a row.`
      )
    )
  }
  return toVpnResult(last)
}

/** Tear down a supervised run without ending the start that owns it: detaches
 *  our listeners, cancels the readiness poll, and clears the supervisor's entry
 *  so the next attempt spawns rather than being handed the dead one back. */
async function discard(run: Run): Promise<void> {
  run.stopping = true
  run.fail = () => {}
  run.abort.abort(new VpnError('internal', 'The tunnel run ended.'))
  for (const off of run.detach.splice(0)) off()
  await run.ctx.supervisor.stop(run.profile.id, { force: true }).catch(() => undefined)
  run.handle = null
  run.stopping = false
  run.abort = new AbortController()
}

// --------------------------------------------------------------------- rest

async function stop(id: string, opts?: { force?: boolean }): Promise<void> {
  const run = runs.get(id)
  if (!run) return
  run.stopping = true
  run.fail = () => {}
  run.abort.abort(new VpnError('internal', 'The tunnel was stopped.'))
  try {
    // Graceful means `POST /api/stop` first, via the supervisor's ladder.
    await run.ctx.supervisor.stop(id, opts)
  } finally {
    // Detached only now: frpc logs its own shutdown on the way out, and those
    // lines belong in the drawer like every other.
    for (const off of run.detach.splice(0)) off()
    runs.delete(id)
  }
}

async function stats(id: string): Promise<VpnStats | null> {
  const run = runs.get(id)
  if (!run) return null
  let proxies: FrpProxyStatus[]
  try {
    proxies = await run.api.status()
  } catch {
    // Between a restart's exit and its next bind there is nothing to ask. That
    // is not a statistic worth an error dialog.
    return null
  }
  applyProxies(run, proxies)
  return frpStats(proxies)
}

async function reload(id: string, spec: FrpSpec): Promise<VpnResult> {
  const run = runs.get(id)
  if (!run) return toVpnResult(new VpnError('internal', 'That tunnel is not running.'))

  const gate = exposureGate(spec)
  if (gate) return toVpnResult(gate)
  const validation = validateFrpSpec(spec)
  if (!validation.ok) {
    const first = validation.issues.find((i) => i.severity === 'error')
    return toVpnResult(
      new VpnError('config-invalid', first ? `${first.path}: ${first.message}` : undefined)
    )
  }

  // The admin port and user are carried over unchanged: they are how we are
  // talking to frpc right now, and a reload that moved them would cut the wire
  // it is travelling on. Secrets cannot change either — the environment is
  // fixed at spawn — so a new token needs a restart, not a reload.
  const toml = generateFrpToml(spec, { adminPort: run.adminPort, adminUser: ADMIN_USER })
  try {
    await run.api.reload(toml)
  } catch (e) {
    return toVpnResult(e)
  }
  await writeSecretFile(run.ctx.runDir, CONFIG_FILE, toml).catch(() => undefined)
  run.spec = spec
  run.proxyNames = spec.proxies.map((p) => p.name)

  // The config is applied either way; this only decides what the card says
  // while the new proxy set comes up.
  const readiness = await run.api
    .waitForReady(run.proxyNames, { timeoutMs: frpTuning.reloadTimeoutMs })
    .catch(() => null)
  if (readiness) applyProxies(run, readiness.proxies)
  return { ok: true }
}

export const frpDriver: VpnDriver<FrpSpec> = {
  kind: 'frp',

  validateConfig(spec: FrpSpec): VpnValidation {
    // Pure and synchronous; called on every keystroke. The confirmations live
    // on the form rather than the spec, so the risky-but-legitimate choices
    // stay errors here until the UI passes the boxes the user ticked.
    return validateFrpSpec(spec)
  },

  async probe(): Promise<VpnEngineInfo> {
    try {
      return await resolveBundled(FRPC)
    } catch (e) {
      // A missing or tampered binary is a state the UI shows, not an exception
      // it has to handle. `resolveBundled` throws so nothing can mistake a
      // tampered binary for an absent one; this is where that turns into text.
      if (!isVpnError(e)) throw e
      return {
        kind: 'frp',
        available: false,
        bundled: true,
        reason: describeVpnError(e.code, e.detail)
      }
    }
  },

  start,
  stop,

  status(id: string): VpnStatus | null {
    return runs.get(id)?.status ?? null
  },

  stats,
  reload,

  // `openForward` is intentionally not implemented. frp exposes a local port to
  // a remote server; it does not carry this machine's traffic anywhere, so
  // there is nothing to forward *into*. The manager reports `unsupported`,
  // which is the truth.

  async reap(): Promise<void> {
    // Nothing engine-specific to sweep. frpc creates no interface, changes no
    // route and holds no lock: an orphan is a process and a run directory, both
    // of which the supervisor's identity-checked reaper already owns. This
    // exists to drop in-process state, which matters when the app is restarted
    // inside one process during development.
    runs.clear()
  },

  async disposeAll(): Promise<void> {
    // Best effort and raced against a quit timeout by the caller, so each stop
    // is allowed to fail without stranding the ones after it.
    await Promise.allSettled([...runs.keys()].map((id) => stop(id)))
    runs.clear()
  }
}
