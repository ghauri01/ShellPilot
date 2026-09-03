import { execFile, spawn as nodeSpawn } from 'node:child_process'
import type { ChildProcess, SpawnOptions } from 'node:child_process'
import { readdir, readFile, unlink, writeFile } from 'node:fs/promises'
import { join } from 'node:path'
import { createInterface } from 'node:readline'
import type { VpnKind, VpnLogLine } from '../../../shared/vpn'
import { redactOutput } from '../secretRedaction'
import { sha256File } from './binaries'
import { VpnError } from './errors'
import { disposeRunDir, runIdSegment, sweepRunDirs, vpnRunRoot } from './runDir'

// Every engine ShellPilot runs is an external process, and every external
// process has the same four failure modes: it never comes up, it comes up and
// dies, it dies over and over, or it outlives us. Drivers do not touch
// `child_process` directly so that backoff, crash-loop detection, bounded log
// capture and orphan reaping apply uniformly rather than three times, subtly
// differently.

const DEFAULT_READINESS_TIMEOUT_MS = 30_000
const DEFAULT_HEALTH_INTERVAL_MS = 15_000
const DEFAULT_GRACEFUL_TIMEOUT_MS = 5_000
// Between SIGTERM and SIGKILL. Deliberately not configurable: a child that has
// ignored SIGTERM for five seconds is not going to honour six.
const TERM_TO_KILL_MS = 5_000
// How long readiness must hold before the backoff exponent is forgotten. A
// tunnel that stayed up for a minute and then dropped is a new incident, not
// the continuation of the last one.
const HEALTHY_RESET_MS = 60_000
// Attached to a crash-loop error. Roughly one screen: enough to contain the
// actual complaint, few enough that the dialog stays readable.
const CRASH_LOG_LINES = 40
// Quitting must not block on a wedged child (E56).
const FINAL_EXIT_WAIT_MS = 4_000
// `ps` reports whole seconds and the pid file is written a moment after the
// spawn, so an exact `>=` on start time would reject our own process about
// half the time.
const START_TIME_TOLERANCE_MS = 2_000
const TRUNCATION_NOTE = '…[truncated]'

export interface SupervisedSpec {
  id: string
  command: string
  args: string[]
  /** Secrets are allowed here (frp reads its token from an env template);
   *  they are never allowed in `args`. */
  env?: Record<string, string>
  cwd: string
  /** Written to the child's stdin, then the pipe is ended. Preferred secret
   *  channel: argv is world-readable through `ps`, and a file has to be
   *  deleted afterwards by someone. */
  stdinPayload?: string
  /** Resolves when the run is up. Rejecting triggers backoff. */
  readiness(h: SupervisorHandle): Promise<void>
  readinessTimeoutMs: number
  healthCheck?(h: SupervisorHandle): Promise<void>
  healthIntervalMs?: number
  /** Ordered graceful stop attempted before any signal. */
  gracefulStop?(h: SupervisorHandle): Promise<void>
  gracefulTimeoutMs?: number
  restart: 'never' | 'on-failure' | 'always'
  backoff: { baseMs: number; maxMs: number; jitter: number }
  crashLoop: { windowMs: number; maxRestarts: number }
  logRing: { maxLines: number; maxBytes: number }
  /** Literal values scrubbed from every captured line before it is stored. */
  redact: string[]

  // --- recorded in the pid file so an orphan can be identified after a crash
  kind?: VpnKind
  profileId?: string
  /** Hash of `command`. Supplied by the driver, which already computed it
   *  while resolving the engine; computed here once per run when absent. */
  exeSha256?: string

  // --- optional notifications, so a driver can move its status without
  // polling. All best-effort: a throwing hook never affects the run.
  onReady?(h: SupervisorHandle): void
  onUnhealthy?(h: SupervisorHandle, cause: unknown): void
  onRestartScheduled?(h: SupervisorHandle, attempt: number, delayMs: number): void
}

export interface SupervisorExit {
  id: string
  code: number | null
  signal: NodeJS.Signals | null
  /** True when a restart has been scheduled. False means this run is over. */
  restarting: boolean
  /** Set when the run ended terminally rather than on its way to a restart. */
  error?: VpnError
  /** The last 40 lines, attached to a terminal exit. A crash loop is never
   *  explicable from the exit code alone. */
  logTail?: VpnLogLine[]
}

export interface SupervisorHandle {
  readonly id: string
  /** The pid of the process running right now, or 0 while between attempts. */
  readonly pid: number
  readonly runDir: string
  readonly restarts: number
  write(s: string): void
  logs(limit?: number): VpnLogLine[]
  onLog(cb: (line: VpnLogLine) => void): () => void
  onExit(cb: (e: SupervisorExit) => void): () => void
  kill(force?: boolean): Promise<void>
}

export type SpawnFn = (
  command: string,
  args: readonly string[],
  options: SpawnOptions
) => ChildProcess

export interface SupervisorOptions {
  /** Where `<runId>.pid` files live. Defaults to `vpnRunRoot()`. */
  runRoot?: string
  platform?: NodeJS.Platform
  spawn?: SpawnFn
  now?: () => number
  /** Injected so the jitter can be pinned in a test. */
  random?: () => number
  /** `process.kill`. Signal 0 is the liveness probe, so this is also how the
   *  reaper asks whether a pid still exists. */
  kill?: (pid: number, signal: number | NodeJS.Signals) => void
  /** Runs a per-OS process-identity probe and returns its stdout. */
  runProbe?: (command: string, args: string[]) => Promise<string>
  reapTermGraceMs?: number
}

/** What is written next to every run so a crash can be cleaned up afterwards.
 *  `exePath` and `startedAtIso` together are the PID-reuse defence: neither is
 *  sufficient alone (E47). */
export interface VpnPidRecord {
  pid: number
  startedAtIso: string
  exePath: string
  exeSha256?: string
  kind?: VpnKind
  profileId?: string
  runId: string
  runDir: string
}

export interface ProcessIdentity {
  exePath: string
  startedAtMs: number
}

/** `delay = min(maxMs, baseMs * 2^n) * (1 ± jitter)`. The jitter is not
 *  decoration: five profiles pointed at the same downed endpoint retry in
 *  lockstep without it, and arrive as a thundering herd the moment it comes
 *  back. */
export function backoffDelay(
  attempt: number,
  backoff: { baseMs: number; maxMs: number; jitter: number },
  random: () => number = Math.random
): number {
  const base = Math.min(backoff.maxMs, backoff.baseMs * 2 ** Math.max(0, attempt))
  const spread = 1 + (random() * 2 - 1) * backoff.jitter
  return Math.max(0, Math.round(base * spread))
}

// A line cap alone is not a bound. One 4 MB stack trace on a single line sits
// inside a 2000-line cap indefinitely, so the byte cap is the real limit and
// the line cap only keeps the drawer scrollable (E58).
class LogRing {
  private lines: VpnLogLine[] = []
  private bytes = 0

  constructor(
    private readonly maxLines: number,
    private readonly maxBytes: number
  ) {}

  push(stream: VpnLogLine['stream'], text: string, at: number): VpnLogLine {
    const budget = Math.max(1, this.maxBytes - Buffer.byteLength(TRUNCATION_NOTE, 'utf8'))
    const buf = Buffer.from(text, 'utf8')
    // Truncated rather than dropped: the head of a line says what happened,
    // and discarding the only line that explains a failure to protect a
    // memory bound trades one bug for a worse one.
    const stored =
      buf.length > budget ? `${buf.subarray(0, budget).toString('utf8')}${TRUNCATION_NOTE}` : text
    const line: VpnLogLine = { at, stream, text: stored }
    this.lines.push(line)
    this.bytes += Buffer.byteLength(line.text, 'utf8')
    while (this.lines.length > 1 && (this.lines.length > this.maxLines || this.bytes > this.maxBytes)) {
      const dropped = this.lines.shift()
      if (!dropped) break
      this.bytes -= Buffer.byteLength(dropped.text, 'utf8')
    }
    return line
  }

  snapshot(limit?: number): VpnLogLine[] {
    if (limit === undefined || limit >= this.lines.length) return [...this.lines]
    return this.lines.slice(this.lines.length - Math.max(0, limit))
  }
}

interface Run {
  spec: SupervisedSpec
  handle: SupervisorHandle
  ring: LogRing
  child: ChildProcess | null
  pid: number
  /** Incremented per launch so a late callback from a dead attempt — a
   *  readiness promise that resolves after the child already exited — cannot
   *  act on the current one. */
  generation: number
  attempt: number
  restarts: number
  exits: number[]
  ready: boolean
  stopping: boolean
  terminal: boolean
  exeSha256?: string
  pidFile: string
  timers: {
    readiness: ReturnType<typeof setTimeout> | null
    healthyReset: ReturnType<typeof setTimeout> | null
    health: ReturnType<typeof setInterval> | null
    backoff: ReturnType<typeof setTimeout> | null
  }
  logListeners: Set<(l: VpnLogLine) => void>
  exitListeners: Set<(e: SupervisorExit) => void>
  exitWaiters: (() => void)[]
  first: { resolve: (h: SupervisorHandle) => void; reject: (e: unknown) => void } | null
}

export class Supervisor {
  private readonly runs = new Map<string, Run>()
  private readonly runRoot: string
  private readonly platform: NodeJS.Platform
  private readonly spawnFn: SpawnFn
  private readonly now: () => number
  private readonly random: () => number
  private readonly killFn: (pid: number, signal: number | NodeJS.Signals) => void
  private readonly runProbe: (command: string, args: string[]) => Promise<string>
  private readonly reapTermGraceMs: number

  constructor(opts: SupervisorOptions = {}) {
    this.runRoot = opts.runRoot ?? vpnRunRoot()
    this.platform = opts.platform ?? process.platform
    this.spawnFn = opts.spawn ?? (nodeSpawn as unknown as SpawnFn)
    this.now = opts.now ?? Date.now
    this.random = opts.random ?? Math.random
    this.killFn = opts.kill ?? ((pid, signal) => process.kill(pid, signal))
    this.runProbe = opts.runProbe ?? defaultRunProbe
    this.reapTermGraceMs = opts.reapTermGraceMs ?? 2_000
  }

  get(id: string): SupervisorHandle | undefined {
    return this.runs.get(id)?.handle
  }

  /** Resolves when the first attempt reaches readiness; rejects if the run
   *  goes terminal before it ever does. Starting the same id twice returns the
   *  live handle rather than spawning a second engine (E51). */
  async spawn(spec: SupervisedSpec): Promise<SupervisorHandle> {
    const existing = this.runs.get(spec.id)
    // A terminal run is a corpse, not a live engine. goTerminal now removes it,
    // so this should be unreachable — it stays because the failure it guards
    // against (reporting "connected" with no process) is silent.
    if (existing && !existing.terminal) return existing.handle
    if (existing) this.runs.delete(spec.id)

    const run: Run = {
      spec,
      handle: null as unknown as SupervisorHandle,
      ring: new LogRing(spec.logRing.maxLines, spec.logRing.maxBytes),
      child: null,
      pid: 0,
      generation: 0,
      attempt: 0,
      restarts: 0,
      exits: [],
      ready: false,
      stopping: false,
      terminal: false,
      exeSha256: spec.exeSha256,
      pidFile: join(this.runRoot, `${runIdSegment(spec.id)}.pid`),
      timers: { readiness: null, healthyReset: null, health: null, backoff: null },
      logListeners: new Set(),
      exitListeners: new Set(),
      exitWaiters: [],
      first: null
    }
    run.handle = this.makeHandle(run)
    this.runs.set(spec.id, run)

    return await new Promise<SupervisorHandle>((resolve, reject) => {
      run.first = { resolve, reject }
      void this.launch(run)
    })
  }

  async stop(id: string, opts?: { force?: boolean }): Promise<void> {
    const run = this.runs.get(id)
    if (!run) return
    run.stopping = true
    this.clearTimers(run)

    const child = run.child
    if (!child || child.exitCode !== null || run.terminal) {
      await this.finish(run)
      return
    }

    const exited = new Promise<void>((resolve) => run.exitWaiters.push(resolve))

    if (!opts?.force) {
      // The control channel first, always. On Windows there is no SIGTERM for
      // a non-console child — `process.kill(pid, 'SIGTERM')` is a hard
      // TerminateProcess — so this is the only chance the engine ever gets to
      // close its interface and put the routes back.
      if (run.spec.gracefulStop) {
        try {
          void Promise.resolve(run.spec.gracefulStop(run.handle)).catch(() => {})
        } catch {
          // A gracefulStop that throws synchronously is still just a failed
          // graceful stop; the signal ladder below handles it.
        }
      }
      if (await this.raceExit(exited, run.spec.gracefulTimeoutMs ?? DEFAULT_GRACEFUL_TIMEOUT_MS)) {
        await this.finish(run)
        return
      }
      this.signal(run, 'SIGTERM')
      if (await this.raceExit(exited, TERM_TO_KILL_MS)) {
        await this.finish(run)
        return
      }
    }

    this.hardKill(run)
    // Never awaited unbounded: quit races this and a wedged child must not be
    // able to hold the app open (E56).
    await this.raceExit(exited, FINAL_EXIT_WAIT_MS)
    await this.finish(run)
  }

  async stopAll(): Promise<void> {
    await Promise.allSettled([...this.runs.keys()].map((id) => this.stop(id)))
  }

  /**
   * Clean up engines left behind by a previous run of the app. Identity is
   * verified before anything is killed: a pid on its own says nothing, because
   * the OS reuses pids and the one we recorded may now belong to the user's
   * editor (E46/E47).
   */
  async reapOrphans(): Promise<void> {
    let entries: string[]
    try {
      entries = await readdir(this.runRoot)
    } catch {
      return
    }

    const live = new Set(this.runs.keys())
    const keepDirs = new Set<string>(live)

    for (const name of entries) {
      if (!name.endsWith('.pid')) continue
      const file = join(this.runRoot, name)
      const record = await this.readPidRecord(file)
      if (!record) {
        await unlink(file).catch(() => {})
        continue
      }
      if (live.has(record.runId)) {
        keepDirs.add(record.runId)
        continue
      }

      if (!this.isAlive(record.pid)) {
        await unlink(file).catch(() => {})
        await disposeRunDir(record.runId, this.runRoot)
        continue
      }

      const identity = await this.probeIdentity(record.pid)
      if (!identity) {
        // The pid is alive but we could not establish whose it is. Killing on
        // a failed probe is exactly the mistake the probe exists to prevent,
        // so the record is left in place and retried next launch, when the pid
        // has most likely gone.
        keepDirs.add(record.runId)
        continue
      }

      if (!identityMatches(record, identity, this.platform)) {
        // Someone else owns this pid now. Our process is long gone, so the
        // record and its directory are stale — but nothing gets signalled.
        await unlink(file).catch(() => {})
        await disposeRunDir(record.runId, this.runRoot)
        continue
      }

      await this.killOrphan(record.pid)
      await unlink(file).catch(() => {})
      await disposeRunDir(record.runId, this.runRoot)
    }

    await sweepRunDirs([...keepDirs], this.runRoot)
  }

  // ------------------------------------------------------------- internals

  private makeHandle(run: Run): SupervisorHandle {
    // Object-literal getters below are not arrow functions, so they get their
    // own `this`. The alias is how they reach the supervisor.
    // eslint-disable-next-line @typescript-eslint/no-this-alias
    const self = this
    return {
      get id(): string {
        return run.spec.id
      },
      get pid(): number {
        return run.pid
      },
      get runDir(): string {
        return run.spec.cwd
      },
      get restarts(): number {
        return run.restarts
      },
      write(s: string): void {
        run.child?.stdin?.write(s)
      },
      logs(limit?: number): VpnLogLine[] {
        return run.ring.snapshot(limit)
      },
      onLog(cb: (line: VpnLogLine) => void): () => void {
        run.logListeners.add(cb)
        return () => run.logListeners.delete(cb)
      },
      onExit(cb: (e: SupervisorExit) => void): () => void {
        run.exitListeners.add(cb)
        return () => run.exitListeners.delete(cb)
      },
      kill(force?: boolean): Promise<void> {
        return self.stop(run.spec.id, { force })
      }
    }
  }

  private async launch(run: Run): Promise<void> {
    if (run.stopping || run.terminal) return
    const spec = run.spec
    const generation = ++run.generation

    let child: ChildProcess
    try {
      child = this.spawnFn(spec.command, spec.args, {
        cwd: spec.cwd,
        env: { ...process.env, ...spec.env },
        // Never `inherit`: everything the engine says has to go through the
        // redactor before it is stored, and nothing may reach the real stdout.
        stdio: ['pipe', 'pipe', 'pipe'],
        windowsHide: true
      })
    } catch (e) {
      this.goTerminal(run, new VpnError('binary-missing', `${spec.command} could not be started.`, { cause: e }))
      return
    }

    run.child = child
    run.pid = child.pid ?? 0

    // Listeners before any await. An engine given a bad config exits in
    // milliseconds, well inside the time it takes to hash the binary and
    // write the pid file, and an exit event that arrives with nothing
    // listening is gone for good — the run would then sit in `starting`
    // until someone pressed Stop.
    this.capture(run, generation, child)
    child.once('error', (err: Error) => {
      // ENOENT arrives here rather than as a throw from spawn().
      this.appendLine(run, 'app', `spawn failed: ${err.message}`)
    })
    child.once('exit', (code: number | null, signal: NodeJS.Signals | null) => {
      void this.onExit(run, generation, code, signal)
    })

    if (spec.stdinPayload !== undefined) {
      // The pipe is ended immediately: engines that read a config from stdin
      // block until EOF, and leaving it open is the classic silent hang.
      child.stdin?.write(spec.stdinPayload)
      child.stdin?.end()
    }

    // Written before this method resolves, so a crash between here and the
    // first status update still leaves something for the reaper to find.
    await this.writePidRecord(run)
    if (generation !== run.generation || run.child !== child) {
      // It exited while the record was being written, and the exit path has
      // already decided what happens next. The record it wrote first is stale,
      // so this one has to go rather than outlive the process it describes.
      await unlink(run.pidFile).catch(() => {})
      return
    }

    const timeoutMs = spec.readinessTimeoutMs || DEFAULT_READINESS_TIMEOUT_MS
    const timeout = new Promise<never>((_resolve, reject) => {
      run.timers.readiness = setTimeout(
        () => reject(new VpnError('handshake-timeout', `${spec.command} was not ready within ${Math.round(timeoutMs / 1000)}s.`)),
        timeoutMs
      )
    })

    try {
      await Promise.race([spec.readiness(run.handle), timeout])
      if (generation !== run.generation) return
      this.onReady(run)
    } catch (e) {
      if (generation !== run.generation) return
      this.clearTimer(run, 'readiness')
      this.appendLine(run, 'app', `not ready: ${e instanceof Error ? e.message : String(e)}`)
      // Killed rather than restarted here: the exit handler is the single
      // place that applies backoff, so a wedged engine takes the same path as
      // one that died on its own (E54).
      //
      // Never while a stop is already in flight, though. A readiness promise
      // does not only time out — it also REJECTS, the moment a driver gives up
      // on the start, and a driver that gives up stops the run in the same
      // turn. `stop()` is then already walking the graceful ladder: the
      // engine's own control channel first (`signal SIGTERM` for openvpn),
      // then a real SIGTERM, then SIGKILL. SIGKILL from here landed on a live,
      // answering engine microseconds after it had been politely asked to
      // exit, so it never acted on the request: the tun interface stayed up
      // and the routes the server pushed stayed installed. On Windows, where
      // `process.kill` is a hard TerminateProcess and the control channel is
      // the only polite mechanism there is, nothing asked it at all.
      //
      // `stop()` ends in this same hardKill if the ladder runs out, so nothing
      // survives by taking longer — it is bounded by gracefulTimeoutMs plus
      // TERM_TO_KILL_MS.
      if (!run.stopping && run.child && run.child.exitCode === null) this.hardKill(run)
    }
  }

  private onReady(run: Run): void {
    this.clearTimer(run, 'readiness')
    run.ready = true
    // The exponent is forgotten only after readiness *holds*. Resetting on
    // reaching readiness would let an engine that comes up and dies after two
    // seconds retry at baseMs forever.
    run.timers.healthyReset = setTimeout(() => {
      run.attempt = 0
    }, HEALTHY_RESET_MS)

    if (run.spec.healthCheck) {
      const every = run.spec.healthIntervalMs ?? DEFAULT_HEALTH_INTERVAL_MS
      run.timers.health = setInterval(() => {
        void this.runHealthCheck(run, run.generation)
      }, every)
    }

    try {
      run.spec.onReady?.(run.handle)
    } catch {
      // A driver's status hook must never take down the run that succeeded.
    }
    if (run.first) {
      run.first.resolve(run.handle)
      run.first = null
    }
  }

  private async runHealthCheck(run: Run, generation: number): Promise<void> {
    if (!run.spec.healthCheck || run.stopping || run.terminal) return
    try {
      await run.spec.healthCheck(run.handle)
    } catch (e) {
      if (generation !== run.generation || run.stopping) return
      this.appendLine(run, 'app', `health check failed: ${e instanceof Error ? e.message : String(e)}`)
      try {
        run.spec.onUnhealthy?.(run.handle, e)
      } catch {
        // As above: a status hook is not allowed to change the outcome.
      }
      // `never` means the user asked us not to interfere; report and leave it.
      if (run.spec.restart === 'never') return
      if (run.child && run.child.exitCode === null) this.hardKill(run)
    }
  }

  private async onExit(
    run: Run,
    generation: number,
    code: number | null,
    signal: NodeJS.Signals | null
  ): Promise<void> {
    if (generation !== run.generation) return
    this.clearTimers(run)
    run.child = null
    run.pid = 0
    run.ready = false
    await unlink(run.pidFile).catch(() => {})

    const waiters = run.exitWaiters.splice(0)
    for (const w of waiters) w()

    if (run.stopping) {
      this.notifyExit(run, { id: run.spec.id, code, signal, restarting: false })
      return
    }

    const at = this.now()
    run.exits = run.exits.filter((t) => at - t < run.spec.crashLoop.windowMs)
    run.exits.push(at)

    if (run.exits.length > run.spec.crashLoop.maxRestarts) {
      const seconds = Math.round(run.spec.crashLoop.windowMs / 1000)
      this.goTerminal(
        run,
        new VpnError('crash-loop', `It exited ${run.exits.length} times in ${seconds} seconds.`),
        code,
        signal
      )
      return
    }

    if (!shouldRestart(run.spec.restart, code, signal)) {
      const detail =
        signal !== null ? `${run.spec.command} was killed by ${signal}.` : `${run.spec.command} exited with code ${code}.`
      this.goTerminal(run, new VpnError('internal', detail), code, signal)
      return
    }

    const delay = backoffDelay(run.attempt, run.spec.backoff, this.random)
    run.attempt++
    run.restarts++
    this.appendLine(run, 'app', `exited (code ${code}, signal ${signal}); restarting in ${delay} ms`)
    try {
      run.spec.onRestartScheduled?.(run.handle, run.attempt, delay)
    } catch {
      // Same reasoning as the other hooks.
    }
    this.notifyExit(run, { id: run.spec.id, code, signal, restarting: true })
    run.timers.backoff = setTimeout(() => {
      run.timers.backoff = null
      void this.launch(run)
    }, delay)
  }

  private goTerminal(
    run: Run,
    error: VpnError,
    code: number | null = null,
    signal: NodeJS.Signals | null = null
  ): void {
    run.terminal = true
    this.clearTimers(run)
    void unlink(run.pidFile).catch(() => {})
    const logTail = run.ring.snapshot(CRASH_LOG_LINES)
    this.notifyExit(run, { id: run.spec.id, code, signal, restarting: false, error, logTail })
    if (run.first) {
      run.first.reject(error)
      run.first = null
    }
    // Drop it. `finish()` used to be the only deleter and only `stop()` calls
    // that, so a crash-looped or cleanly-exited run stayed in the map — and
    // the next spawn() with the same id returned the dead handle immediately,
    // without spawning anything or running readiness. The driver then reported
    // ok, the card went green, and nothing was running. A green light over a
    // tunnel that does not exist is the worst lie this feature can tell.
    this.runs.delete(run.spec.id)
  }

  private notifyExit(run: Run, e: SupervisorExit): void {
    for (const cb of [...run.exitListeners]) {
      try {
        cb(e)
      } catch {
        // One bad listener must not stop the others from being told.
      }
    }
  }

  // Line-oriented from the start. `stdout.on('data')` with string
  // concatenation is the unbounded-growth bug: it keeps whatever the engine
  // wrote in memory until a newline that may never come.
  private capture(run: Run, generation: number, child: ChildProcess): void {
    const attach = (stream: NodeJS.ReadableStream | null, name: 'stdout' | 'stderr'): void => {
      if (!stream) return
      const rl = createInterface({ input: stream, crlfDelay: Infinity })
      rl.on('line', (line: string) => {
        if (generation !== run.generation) return
        this.appendLine(run, name, line)
      })
      rl.on('error', () => rl.close())
      child.once('exit', () => rl.close())
    }
    attach(child.stdout, 'stdout')
    attach(child.stderr, 'stderr')
  }

  private appendLine(run: Run, stream: VpnLogLine['stream'], text: string): void {
    // Redaction happens before storage, not before display: an unredacted
    // value that reaches the ring buffer has already leaked into every
    // consumer of it, including the crash-loop error and the audit log.
    const line = run.ring.push(stream, redactOutput(text, run.spec.redact), this.now())
    for (const cb of [...run.logListeners]) {
      try {
        cb(line)
      } catch {
        // As with exit listeners.
      }
    }
  }

  private signal(run: Run, sig: NodeJS.Signals): void {
    if (!run.pid) return
    try {
      this.killFn(run.pid, sig)
    } catch {
      // ESRCH: it exited between the liveness check and the signal, which is
      // the outcome we wanted anyway.
    }
  }

  private hardKill(run: Run): void {
    if (!run.pid) return
    if (this.platform === 'win32') {
      // `/T` matters: OpenVPN on Windows starts helper processes, and killing
      // only the parent leaves them holding the TAP adapter.
      try {
        this.spawnFn('taskkill', ['/T', '/F', '/PID', String(run.pid)], {
          stdio: 'ignore',
          windowsHide: true
        })
      } catch {
        // Fall through: there is nothing further to try.
      }
      return
    }
    this.signal(run, 'SIGKILL')
  }

  private async raceExit(exited: Promise<void>, ms: number): Promise<boolean> {
    let timer: ReturnType<typeof setTimeout> | null = null
    const timeout = new Promise<false>((resolve) => {
      timer = setTimeout(() => resolve(false), ms)
    })
    const result = await Promise.race([exited.then(() => true), timeout])
    if (timer) clearTimeout(timer)
    return result
  }

  private async finish(run: Run): Promise<void> {
    this.clearTimers(run)
    // Settle a spawn() that is still waiting for readiness.
    //
    // Only onReady() and goTerminal() used to settle `first`, and neither runs
    // on a stop — onExit returns early once `stopping` is set. So stopping a
    // run that was still starting deleted it out from under a promise that
    // could then never settle: the Start button spun forever, the IPC invoke
    // never replied, and the closure kept the resolved plaintext secrets alive
    // for the rest of the process. Stopping during a start is an ordinary
    // double-click, not an exotic case.
    if (run.first) {
      run.first.reject(new VpnError('internal', 'The tunnel was stopped while it was starting.'))
      run.first = null
    }
    this.runs.delete(run.spec.id)
    await unlink(run.pidFile).catch(() => {})
  }

  private clearTimer(run: Run, key: 'readiness' | 'healthyReset' | 'backoff'): void {
    const t = run.timers[key]
    if (t) clearTimeout(t)
    run.timers[key] = null
  }

  private clearTimers(run: Run): void {
    this.clearTimer(run, 'readiness')
    this.clearTimer(run, 'healthyReset')
    this.clearTimer(run, 'backoff')
    if (run.timers.health) clearInterval(run.timers.health)
    run.timers.health = null
  }

  private async writePidRecord(run: Run): Promise<void> {
    if (run.exeSha256 === undefined) {
      // Once per run, not once per restart: a restarting engine re-hashing a
      // 30 MB sidecar every few seconds would be pure waste.
      run.exeSha256 = await sha256File(run.spec.command).catch(() => undefined)
    }
    const record: VpnPidRecord = {
      pid: run.pid,
      startedAtIso: new Date(this.now()).toISOString(),
      exePath: run.spec.command,
      exeSha256: run.exeSha256,
      kind: run.spec.kind,
      profileId: run.spec.profileId,
      runId: run.spec.id,
      runDir: run.spec.cwd
    }
    await writeFile(run.pidFile, JSON.stringify(record), { mode: 0o600 }).catch(() => {})
  }

  private async readPidRecord(file: string): Promise<VpnPidRecord | null> {
    try {
      const rec = JSON.parse(await readFile(file, 'utf8')) as VpnPidRecord
      if (typeof rec.pid !== 'number' || !rec.pid || !rec.exePath || !rec.startedAtIso) return null
      if (!rec.runId) return null
      return rec
    } catch {
      return null
    }
  }

  private isAlive(pid: number): boolean {
    try {
      this.killFn(pid, 0)
      return true
    } catch {
      return false
    }
  }

  private async probeIdentity(pid: number): Promise<ProcessIdentity | null> {
    try {
      if (this.platform === 'linux') {
        const exePath = (await this.runProbe('readlink', ['-f', `/proc/${pid}/exe`])).trim()
        // The `/proc/<pid>` directory's mtime is the moment the process was
        // created, which avoids parsing the clock-tick field of
        // `/proc/<pid>/stat` against the boot time.
        const seconds = Number((await this.runProbe('stat', ['-c', '%Y', `/proc/${pid}`])).trim())
        if (!exePath || !Number.isFinite(seconds)) return null
        return { exePath, startedAtMs: seconds * 1000 }
      }
      if (this.platform === 'darwin') {
        return parseDarwinPs(await this.runProbe('ps', ['-o', 'comm=,lstart=', '-p', String(pid)]))
      }
      if (this.platform === 'win32') {
        return parseWindowsProcess(
          await this.runProbe('powershell.exe', [
            '-NoProfile',
            '-NonInteractive',
            '-Command',
            `Get-CimInstance Win32_Process -Filter "ProcessId=${pid}" | ForEach-Object { $_.ExecutablePath; $_.CreationDate.ToString('o') }`
          ])
        )
      }
    } catch {
      return null
    }
    return null
  }

  private async killOrphan(pid: number): Promise<void> {
    try {
      if (this.platform === 'win32') {
        this.spawnFn('taskkill', ['/T', '/F', '/PID', String(pid)], {
          stdio: 'ignore',
          windowsHide: true
        })
        return
      }
      this.killFn(pid, 'SIGTERM')
    } catch {
      return
    }
    const deadline = this.now() + this.reapTermGraceMs
    while (this.now() < deadline) {
      if (!this.isAlive(pid)) return
      await new Promise((resolve) => setTimeout(resolve, 100))
    }
    if (this.isAlive(pid)) {
      try {
        this.killFn(pid, 'SIGKILL')
      } catch {
        // Nothing left to try; the next launch will look again.
      }
    }
  }
}

function shouldRestart(
  policy: SupervisedSpec['restart'],
  code: number | null,
  signal: NodeJS.Signals | null
): boolean {
  if (policy === 'never') return false
  if (policy === 'always') return true
  return code !== 0 || signal !== null
}

/** `ps -o comm=,lstart=` output. `lstart` is always exactly five fields
 *  ("Wed Aug 27 10:11:12 2025"); whatever precedes them is the path, which may
 *  itself contain spaces. */
export function parseDarwinPs(out: string): ProcessIdentity | null {
  const line = out
    .split(/\r?\n/)
    .map((s) => s.trim())
    .find(Boolean)
  if (!line) return null
  const parts = line.split(/\s+/)
  if (parts.length < 6) return null
  const startedAtMs = Date.parse(parts.slice(-5).join(' '))
  const exePath = parts.slice(0, -5).join(' ')
  if (!exePath || Number.isNaN(startedAtMs)) return null
  return { exePath, startedAtMs }
}

/** Two lines from `Get-CimInstance Win32_Process`: `ExecutablePath` then
 *  `CreationDate` as a round-trip ISO string. */
export function parseWindowsProcess(out: string): ProcessIdentity | null {
  const lines = out
    .split(/\r?\n/)
    .map((s) => s.trim())
    .filter(Boolean)
  if (lines.length < 2) return null
  const startedAtMs = Date.parse(lines[1])
  if (Number.isNaN(startedAtMs)) return null
  return { exePath: lines[0], startedAtMs }
}

/** Both halves must agree. The path alone is defeated by pid reuse against
 *  another copy of the same engine; the start time alone is defeated by any
 *  process that happens to be younger than our record. */
export function identityMatches(
  record: VpnPidRecord,
  identity: ProcessIdentity,
  platform: NodeJS.Platform
): boolean {
  const norm = (p: string): string =>
    platform === 'win32' ? p.replace(/\//g, '\\').toLowerCase() : p
  if (norm(record.exePath) !== norm(identity.exePath)) return false
  const recorded = Date.parse(record.startedAtIso)
  if (Number.isNaN(recorded)) return false
  return identity.startedAtMs >= recorded - START_TIME_TOLERANCE_MS
}

function defaultRunProbe(command: string, args: string[]): Promise<string> {
  return new Promise((resolve, reject) => {
    execFile(
      command,
      args,
      { timeout: 5_000, windowsHide: true, maxBuffer: 1 << 20 },
      (err, stdout) => (err ? reject(err) : resolve(stdout))
    )
  })
}
