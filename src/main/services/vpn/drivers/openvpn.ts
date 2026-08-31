import type {
  OpenVpnSpec,
  VpnEngineInfo,
  VpnErrorCode,
  VpnLogLine,
  VpnProfile,
  VpnStartResult,
  VpnStats,
  VpnStatus,
  VpnValidation,
  VpnValidationIssue
} from '../../../../shared/vpn'
import { resolveSystem } from '../binaries'
import type { VpnDriver, VpnDriverContext } from '../driver'
import type { ElevationProbe, Elevator } from '../elevation'
import { elevationErrorCode, elevatorForPlatform } from '../elevation'
import { VpnError } from '../errors'
import { OpenVpnManagement } from '../openvpnManagement'
import type { OpenVpnManagementEndpoint } from '../openvpnManagement'
import { emitOvpnConfig, ovpnArgs } from '../parsers'
import { writeSecretFile } from '../runDir'
import type { SupervisedSpec } from '../supervisor'

// The OpenVPN driver.
//
// Three rules shape it, and everything below follows from one of them:
//
//  1. **No secret is ever an argument.** Username, password, one-time code and
//     private-key passphrase all travel over the management channel after the
//     process is up. Never `--auth-user-pass <file>`, never `--askpass <file>`,
//     never argv — `ps` is world-readable, and an elevated process's command
//     line is if anything more visible than an ordinary one.
//  2. **We listen; openvpn dials.** `OpenVpnManagement.listen()` runs *before*
//     the spawn and `--management-client` inverts the direction, so there is
//     never a window in which a listening management endpoint sits waiting for
//     whoever reaches it first.
//  3. **A refused credential is never retried.** OpenVPN re-asks immediately
//     after `Verification Failed`, and answering is what locks accounts (E28).
//     `openvpnManagement.ts` refuses to answer; the restart policy here must
//     not undo that by launching a second process with the same secret.

// OpenVPN reconnects internally rather than exiting, so a process-level
// restart buys nothing once it is up — and under elevation it costs another
// password prompt. This is the deadline for the *first* connection only.
const CONNECT_TIMEOUT_MS = 60_000
const GRACEFUL_TIMEOUT_MS = 5_000
const BACKOFF = { baseMs: 1_000, maxMs: 60_000, jitter: 0.3 }
const CRASH_LOOP = { windowMs: 120_000, maxRestarts: 5 }
const LOG_RING = { maxLines: 2_000, maxBytes: 1024 * 1024 }

// Windows has no `/dev/stdin`, so there the config body has to touch a disk.
// It lands 0600 inside the 0700 run directory and goes away with it — but for
// as long as the tunnel is up, a file containing an inline `<key>` block
// exists and anything running as this user can read it. That residual risk is
// stated rather than hidden: every alternative shape (`--auth-user-pass`, a
// config path on a shared command line) is worse, not better.
const CONFIG_FILE_NAME = 'p.ovpn'

// ------------------------------------------------------------------ launcher

/** A running engine, whatever started it. */
export interface OpenVpnProcess {
  /** 0 when the engine is not in our process tree — the macOS security
   *  framework and the Windows Interactive Service both start it elsewhere. */
  readonly pid: number
  stop(force?: boolean): Promise<void>
}

export interface OpenVpnGone {
  code: number | null
  /** The user dismissed the administrator prompt. An answer, not a fault:
   *  `elevation-declined`, and no restart (E04). */
  declined: boolean
  error?: VpnError
}

export interface OpenVpnLaunchOptions {
  spec: SupervisedSpec
  ctx: VpnDriverContext
  /** Shown in the OS prompt, where the OS allows a message. */
  reason: string
  onLine(line: VpnLogLine): void
  onGone(exit: OpenVpnGone): void
  /** Whether the management channel has already been accepted. Once it has,
   *  the listener is closed and a supervisor restart can only fail. */
  isConnected(): boolean
}

/**
 * How the engine process is started.
 *
 * There are two implementations and the split is forced rather than chosen.
 * `Elevator.run()` starts the engine itself — on macOS through the security
 * framework, on Windows through ShellExecute or the OpenVPN Interactive
 * Service — so the engine is not our child there, and the supervisor's model
 * (stdio pipes, signals, pid identity, backoff) does not describe it. The
 * supervised launcher is the other half: a direct child, fully supervised.
 *
 * Everything that carries risk — argv, the config body, the credential
 * exchange, readiness, stats, the stop ladder — sits above this seam and is
 * identical for both.
 */
export interface OpenVpnLauncher {
  /** False when the launcher starts the engine outside our stdio, which is
   *  true of every elevation helper on every platform. `--config /dev/stdin`
   *  is usable only when this is true. */
  readonly carriesStdin: boolean
  probe(): Promise<ElevationProbe>
  launch(opts: OpenVpnLaunchOptions): Promise<OpenVpnProcess>
}

/** Start the engine as our own child, through the supervisor. */
export function supervisedLauncher(): OpenVpnLauncher {
  return {
    carriesStdin: true,
    probe: async (): Promise<ElevationProbe> => ({ available: true, method: 'none' }),
    async launch(o: OpenVpnLaunchOptions): Promise<OpenVpnProcess> {
      // Deliberately not awaited: it resolves on readiness, which is the event
      // `start()` is already waiting for, and rejects when the run goes
      // terminal, which arrives here through `onExit` carrying more detail.
      void o.ctx.supervisor.spawn(o.spec).catch(() => undefined)
      // The supervisor registers the run and spawns the child synchronously
      // before it hands its promise back, so the handle already exists and no
      // exit can have been missed.
      const handle = o.ctx.supervisor.get(o.spec.id)
      if (!handle) throw new VpnError('internal', 'The supervisor did not register the run.')

      handle.onLog((line) => o.onLine(line))
      handle.onExit((e) => {
        if (e.restarting) {
          // A relaunch after the channel was accepted dials an endpoint nobody
          // is listening on. Stop now, so the drop is reported with its real
          // reason instead of `crash-loop` two minutes later.
          if (o.isConnected()) void o.ctx.supervisor.stop(o.spec.id, { force: true })
          return
        }
        o.onGone({ code: e.code, declined: false, error: e.error })
      })

      return {
        get pid(): number {
          return handle.pid
        },
        stop: (force?: boolean) => handle.kill(force)
      }
    }
  }
}

/** Start the engine with administrator rights. OpenVPN has no userspace mode —
 *  `--dev tun` needs CAP_NET_ADMIN or root — so this is the production path on
 *  every platform. */
export function elevatedLauncher(elevator: Elevator = elevatorForPlatform()): OpenVpnLauncher {
  return {
    // Follows the elevator rather than being flatly false. pkexec and sudo
    // fork the engine, so a pipe reaches it and the config never has to touch
    // disk; osascript and ShellExecute start it detached, so it does. The
    // elevator declares which it is, and refuses a stdin payload it cannot
    // carry rather than dropping one.
    carriesStdin: elevator.carriesStdin,
    probe: () => elevator.probe(),
    async launch(o: OpenVpnLaunchOptions): Promise<OpenVpnProcess> {
      const probe = await elevator.probe()
      if (!probe.available) throw new VpnError('unsupported', probe.reason)

      const proc = await elevator.run({
        reason: o.reason,
        command: o.spec.command,
        args: o.spec.args,
        cwd: o.spec.cwd,
        stdin: o.spec.stdinPayload
      })

      // No restart, ever. Every attempt is another password prompt, and a
      // prompt storm trains people to approve without reading.
      void proc.wait().then(
        (exit) => {
          const code: VpnErrorCode | null = exit.declined
            ? 'elevation-declined'
            : elevationErrorCode(elevator.method, exit.code)
          o.onGone({
            code: exit.code,
            declined: exit.declined,
            error: code ? new VpnError(code) : undefined
          })
        },
        (e: unknown) => {
          o.onGone({
            code: null,
            declined: false,
            error: e instanceof VpnError ? e : new VpnError('internal', describe(e))
          })
        }
      )

      return { pid: proc.pid ?? 0, stop: (force?: boolean) => proc.kill(force) }
    }
  }
}

// ------------------------------------------------------------------- session

interface Session {
  id: string
  ctx: VpnDriverContext
  management: OpenVpnManagement
  proc: OpenVpnProcess | null
  status: VpnStatus
  connected: boolean
  stopping: boolean
  /** Resolves when the tunnel is up and rejects on the failure that ended the
   *  attempt. Also the supervisor's readiness gate, so a terminal failure
   *  kills the child instead of leaving it wedged. */
  outcome: Promise<void>
  settle: { resolve(): void; reject(e: unknown): void } | null
  /** The code to report, or null for an outcome that is not an error — a
   *  dismissed credential prompt is the user answering, not a fault. */
  failure: VpnError | null
  failureMessage: string
  connectTimer: ReturnType<typeof setTimeout> | null
}

export interface OpenVpnDriverOptions {
  /** Defaults to `elevatedLauncher()`. */
  launcher?: OpenVpnLauncher
  /** Which file to execute. The default is the allowlisted resolver in
   *  `binaries.ts`, which is where every rule about *where* an engine may come
   *  from lives; this exists so a test can point at a stand-in without any of
   *  those rules being weakened to let it through. */
  resolveEngine?: (spec: OpenVpnSpec) => Promise<VpnEngineInfo>
  platform?: NodeJS.Platform
  connectTimeoutMs?: number
  gracefulTimeoutMs?: number
  backoff?: { baseMs: number; maxMs: number; jitter: number }
  crashLoop?: { windowMs: number; maxRestarts: number }
}

export interface OpenVpnDriver extends VpnDriver<OpenVpnSpec> {
  /** Renegotiate without tearing the tunnel down — what a resume from sleep or
   *  an interface change wants (E20/E21), because a full restart would re-ask
   *  for credentials it does not need. Exposed for the manager to call; nothing
   *  here subscribes to power events, because a driver that reacts to them on
   *  its own is a driver two callers can fight over. False when there is no
   *  live run. */
  softRestart(id: string): boolean
}

export function createOpenVpnDriver(opts: OpenVpnDriverOptions = {}): OpenVpnDriver {
  const sessions = new Map<string, Session>()
  const launcher = opts.launcher ?? elevatedLauncher()
  const platform = opts.platform ?? process.platform
  const connectTimeoutMs = opts.connectTimeoutMs ?? CONNECT_TIMEOUT_MS
  const gracefulTimeoutMs = opts.gracefulTimeoutMs ?? GRACEFUL_TIMEOUT_MS
  const backoff = opts.backoff ?? BACKOFF
  const crashLoop = opts.crashLoop ?? CRASH_LOOP
  const resolveEngine =
    opts.resolveEngine ??
    // `binaryPath` reaches a spec only from the profile form: the importer
    // hard-rejects every path directive in a `.ovpn` file, so its presence
    // here is the user's own confirmed choice and nobody else's (E44).
    ((spec: OpenVpnSpec) =>
      resolveSystem('openvpn', {
        binaryPath: spec.binaryPath,
        confirmed: spec.binaryPath !== undefined
      }))

  function clearConnectTimer(s: Session): void {
    if (s.connectTimer) clearTimeout(s.connectTimer)
    s.connectTimer = null
  }

  /** End the start attempt. `error` is null for an outcome the user chose. */
  function fail(s: Session, error: VpnError | null, message: string): void {
    const settle = s.settle
    // Already decided, or already up: a later problem belongs to a running
    // tunnel and reaches the UI through `emit`, not through the start.
    if (!settle || s.connected) return
    s.settle = null
    s.failure = error
    s.failureMessage = message
    clearConnectTimer(s)
    settle.reject(error ?? new Error(message))
    // Stopped here rather than in `start()`'s catch, because openvpn is at
    // this moment either being re-asked for the credential the server just
    // refused or about to be restarted, and both are what we are preventing.
    void s.proc?.stop().catch(() => undefined)
  }

  function succeed(s: Session): void {
    const settle = s.settle
    if (!settle) return
    s.settle = null
    s.connected = true
    clearConnectTimer(s)
    settle.resolve()
  }

  function onEmit(s: Session, patch: Partial<VpnStatus>): void {
    Object.assign(s.status, patch)
    s.ctx.emit(patch)
    if (s.stopping) return
    if (patch.state === 'connected') {
      succeed(s)
      return
    }
    if (patch.state === 'error') {
      fail(s, new VpnError(patch.errorCode ?? 'internal', patch.error), patch.error ?? '')
      return
    }
    if (patch.state === 'stopped') {
      // `stopped` carrying a code is a refusal — a cancelled one-time code
      // arrives as `auth-otp-required`. `stopped` without one is the user
      // dismissing a prompt, which is an answer rather than an error.
      if (patch.errorCode) fail(s, new VpnError(patch.errorCode, patch.error), patch.error ?? '')
      else fail(s, null, patch.error ?? 'Connecting was cancelled.')
    }
  }

  async function shutdown(s: Session, force?: boolean): Promise<void> {
    s.stopping = true
    clearConnectTimer(s)
    sessions.delete(s.id)
    try {
      await s.proc?.stop(force)
    } finally {
      s.management.close()
    }
  }

  const driver: OpenVpnDriver = {
    kind: 'openvpn',

    validateConfig(spec: OpenVpnSpec): VpnValidation {
      const issues: VpnValidationIssue[] = []
      const error = (path: string, code: string, message: string): void => {
        issues.push({ path, severity: 'error', code, message })
      }
      const warn = (path: string, code: string, message: string): void => {
        issues.push({ path, severity: 'warning', code, message })
      }

      if (!spec.configRef) {
        error('configRef', 'missing-config', 'This profile has no stored configuration.')
      }
      if (spec.authMode !== 'none' && !spec.usernameRef && !spec.passwordRef) {
        // Not fatal: openvpn asks over the management channel and the user can
        // type it. Saying so beats a prompt that arrives unexplained.
        warn(
          'authMode',
          'no-stored-credentials',
          'No username or password is stored, so you will be asked for them each time this connects.'
        )
      }
      if (spec.authMode === 'userpass-otp' && !spec.staticChallenge) {
        warn(
          'staticChallenge',
          'no-challenge-text',
          'The server has not said what to call the one-time code, so the prompt will use its own wording.'
        )
      }
      if (spec.redirectGateway) {
        // A warning, not a block: it is a legitimate choice, but it is not one
        // a downloaded profile gets to make quietly (E13).
        warn(
          'redirectGateway',
          'default-route',
          'While this is connected, all of this machine’s traffic goes through the tunnel.'
        )
      }
      if (spec.binaryPath !== undefined && spec.binaryPath.trim() === '') {
        error('binaryPath', 'empty-path', 'The program path is blank. Clear it to use the installed OpenVPN.')
      }
      if (spec.httpProxy) {
        if (!spec.httpProxy.host.trim()) {
          error('httpProxy.host', 'bad-host', 'The proxy needs a host name.')
        }
        if (!isPort(spec.httpProxy.port)) {
          error('httpProxy.port', 'bad-port', 'The proxy port must be between 1 and 65535.')
        }
      }
      for (const [i, remote] of (spec.remotes ?? []).entries()) {
        if (!remote.host.trim()) {
          error(`remotes[${i}].host`, 'bad-host', 'The server needs a host name.')
        }
        if (!isPort(remote.port)) {
          error(`remotes[${i}].port`, 'bad-port', 'The server port must be between 1 and 65535.')
        }
      }

      return { ok: !issues.some((i) => i.severity === 'error'), issues }
    },

    async probe(): Promise<VpnEngineInfo> {
      try {
        return await resolveSystem('openvpn', {})
      } catch (e) {
        return { kind: 'openvpn', available: false, bundled: false, reason: absentReason(e, platform) }
      }
    },

    async start(
      profile: VpnProfile & { spec: OpenVpnSpec },
      ctx: VpnDriverContext
    ): Promise<VpnStartResult> {
      const spec = profile.spec
      if (sessions.has(profile.id)) throw new VpnError('already-running')

      const body = ctx.secrets.configBody
      if (!body) throw new VpnError('config-invalid', 'This profile has no stored configuration body.')

      const engine = await resolveEngine(spec)
      if (!engine.path) throw new VpnError('binary-missing')

      // The last gate before these bytes reach the engine. The importer
      // produced this body, but it has been through the vault since, and the
      // vault is storage rather than a trust boundary.
      const config = emitOvpnConfig(spec, body)

      let session!: Session
      const management = new OpenVpnManagement(
        {
          emit: (patch) => onEmit(session, patch),
          log: (line, stream) => ctx.log(line, stream),
          askUser: (p) => ctx.askUser(p),
          // Read fresh on every prompt rather than captured once: with
          // `--auth-nocache` a reconnect re-asks, and a re-prompt then is
          // expected behaviour rather than a failure (E30).
          credentials: () => ({
            username: ctx.secrets.username,
            password: ctx.secrets.password,
            keyPassphrase: ctx.secrets.keyPassphrase
          }),
          onClose: () => {
            // Not a failure on its own: openvpn closes the channel on the way
            // out, and the exit that follows carries the reason. Logged
            // because the reverse — a channel that goes away under a process
            // that is still running — leaves the tunnel up with nothing
            // steering it, and that is invisible otherwise.
            if (!session.stopping) ctx.log('the management channel closed', 'app')
          }
        },
        { runDir: ctx.runDir, platform }
      )

      session = {
        id: profile.id,
        ctx,
        management,
        proc: null,
        status: { id: profile.id, kind: 'openvpn', state: 'starting', since: Date.now(), restarts: 0 },
        connected: false,
        stopping: false,
        outcome: Promise.resolve(),
        settle: null,
        failure: null,
        failureMessage: '',
        connectTimer: null
      }
      session.outcome = new Promise<void>((resolve, reject) => {
        session.settle = { resolve, reject }
      })
      // Nothing observes this before `start()` does, and an unobserved
      // rejection must not take the app down.
      session.outcome.catch(() => undefined)
      sessions.set(profile.id, session)

      try {
        // Before the spawn, always: `--management-client` means openvpn dials
        // us, and it cannot dial an endpoint that does not exist yet.
        const endpoint = await management.listen()

        // `/dev/stdin` only when the supervisor's stdin pipe actually reaches
        // the engine. It does not when an elevation helper sits in between,
        // and Windows has no `/dev/stdin` at all.
        const viaStdin = platform !== 'win32' && launcher.carriesStdin
        const configPath = viaStdin
          ? '/dev/stdin'
          : await writeSecretFile(ctx.runDir, CONFIG_FILE_NAME, config)

        // `ovpnArgs` emits `--script-security 0`, the `--pull-filter reject`
        // set, `--management-client --management-query-passwords
        // --management-hold`, `--auth-nocache` and — when `redirectGateway` is
        // false — `--route-nopull` plus the `redirect-gateway` pull-filter. A
        // clean local config is only half the job; the other half is refusing
        // the same directives when a hostile *server* pushes them (E38).
        const args = ovpnArgs(spec, { configPath, management: managementArg(endpoint), verb: 3 })

        const supervised: SupervisedSpec = {
          id: profile.id,
          command: engine.path,
          args,
          cwd: ctx.runDir,
          stdinPayload: viaStdin ? config : undefined,
          readiness: () => session.outcome,
          // The driver owns the connect deadline below so the failure can be
          // named; this is only a backstop for a readiness promise that never
          // settles at all.
          readinessTimeoutMs: connectTimeoutMs + 5_000,
          gracefulStop: async () => {
            // The control channel first. On Windows there is no SIGTERM for a
            // non-console child, so this is the only chance openvpn gets to
            // close its interface and put the routes back.
            session.management.sigterm()
          },
          gracefulTimeoutMs,
          // Restarting is useful in exactly one window: before openvpn has
          // dialled the management channel. There the listener is still open,
          // so a relaunch can connect, and a binary that died on startup gets
          // a second chance.
          //
          // After the channel has been accepted it is useless and actively
          // harmful — accept() closes the listener, so every relaunch dials a
          // dead endpoint and the run marches through five backoffs to
          // `crash-loop`, reporting that instead of why the tunnel actually
          // dropped. The launcher stops the run itself at that point rather
          // than letting the policy grind; see `isConnected` below.
          //
          // Credentials the server refused are still never resent (E28).
          restart: 'on-failure',
          backoff,
          crashLoop,
          logRing: LOG_RING,
          redact: ctx.secrets.all,
          kind: 'openvpn',
          profileId: profile.id,
          exeSha256: engine.sha256,
          onRestartScheduled: (_h, attempt, delayMs) => {
            session.status.restarts = attempt
            ctx.emit({ state: 'reconnecting', since: Date.now(), restarts: attempt })
            ctx.log(`openvpn exited; retrying in ${delayMs} ms`, 'app')
          }
        }

        session.connectTimer = setTimeout(() => {
          fail(
            session,
            new VpnError(
              'handshake-timeout',
              `openvpn did not connect within ${Math.round(connectTimeoutMs / 1000)}s.`
            ),
            ''
          )
        }, connectTimeoutMs)

        session.proc = await launcher.launch({
          spec: supervised,
          ctx,
          reason: `ShellPilot needs administrator rights to bring up the “${profile.name}” VPN tunnel.`,
          onLine: (line) => ctx.log(line.text, line.stream),
          isConnected: () => session.connected,
          onGone: (exit) => {
            if (session.stopping) return
            const code =
              exit.error?.code ??
              (exit.declined ? 'elevation-declined' : management.lastErrorCode()) ??
              'internal'
            const detail = exit.error?.detail ?? exitDetail(exit)
            if (!session.connected) {
              fail(session, new VpnError(code, detail), detail)
              return
            }
            // Connected, and the engine is gone: a drop, not a failed start.
            // Emitting alone left the session in `sessions`, so the next start
            // refused with "This tunnel is already running." beside a Start
            // button and a dead tunnel. `dropped` makes the manager tell this
            // driver to stop, which clears that.
            ctx.dropped(detail, code)
          }
        })

        await session.outcome
      } catch (e) {
        await shutdown(session)
        if (session.failure) throw session.failure
        // A stop the user asked for is not an error, so it carries no code.
        if (session.failureMessage) return { ok: false, error: session.failureMessage }
        throw e
      }

      // No listeners and no `openForward`: OpenVPN is always system-mode, so
      // the tunnel is a real interface with real routes and there is nothing
      // to forward into.
      return { ok: true }
    },

    async stop(id: string, options?: { force?: boolean }): Promise<void> {
      const session = sessions.get(id)
      if (!session) return
      await shutdown(session, options?.force)
    },

    status(id: string): VpnStatus | null {
      const session = sessions.get(id)
      return session ? { ...session.status } : null
    },

    async stats(id: string): Promise<VpnStats | null> {
      // `>BYTECOUNT:` for the counters and the CONNECTED state line for the
      // assigned address. Both are pushed, so this asks openvpn nothing.
      return sessions.get(id)?.management.stats() ?? null
    },

    softRestart(id: string): boolean {
      const session = sessions.get(id)
      if (!session) return false
      session.management.softRestart()
      return true
    },

    async reap(): Promise<void> {
      // Nothing openvpn-specific to do. Process orphans belong to the
      // supervisor, whose `reapOrphans()` the manager runs before this, and
      // the management socket a SIGKILLed run left behind lives inside the run
      // directory that same sweep removes. Implemented rather than omitted so
      // the reasoning sits where someone would go looking for it.
    },

    async disposeAll(): Promise<void> {
      await Promise.allSettled([...sessions.values()].map((s) => shutdown(s)))
    }
  }

  return driver
}

/** The registry imports exactly this name. */
export const openvpnDriver: OpenVpnDriver = createOpenVpnDriver()

// -------------------------------------------------------------------- helpers

function isPort(value: number): boolean {
  return Number.isInteger(value) && value >= 1 && value <= 65535
}

function managementArg(
  endpoint: OpenVpnManagementEndpoint
): { kind: 'unix'; path: string } | { kind: 'tcp'; host: string; port: number } {
  if (endpoint.socketPath) return { kind: 'unix', path: endpoint.socketPath }
  // Windows: `listen()` bound 127.0.0.1:0 and stops listening on the first
  // accept, so the port is reachable for exactly as long as it takes openvpn
  // to dial back.
  return { kind: 'tcp', host: '127.0.0.1', port: endpoint.port ?? 0 }
}

function exitDetail(exit: OpenVpnGone): string {
  if (exit.declined) return 'The administrator prompt was dismissed.'
  return exit.code === null ? 'openvpn stopped.' : `openvpn exited with code ${exit.code}.`
}

function describe(e: unknown): string {
  return e instanceof Error ? e.message : String(e)
}

/** Why OpenVPN is not here, and what to do about it.
 *
 *  ShellPilot never bundles it: OpenVPN is GPL-2.0 and ShellPilot is Apache-2.0
 *  (`THIRD-PARTY-NOTICES.md`), so shipping them together is not a packaging
 *  decision anyone is free to revisit. "Not found" therefore always means
 *  "install it", never "our download failed". */
function absentReason(e: unknown, platform: NodeJS.Platform): string {
  const detail = e instanceof VpnError ? e.message : describe(e)
  return `${detail} ShellPilot does not include OpenVPN, because its licence and ShellPilot's cannot be combined. ${installHint(platform)}`
}

function installHint(platform: NodeJS.Platform): string {
  if (platform === 'win32') {
    // Worth naming twice over: the official package is the only supported
    // route on Windows — there is no PATH search there (E44) — and it installs
    // the Interactive Service, which is what removes the permission prompt on
    // every connect (E05).
    return 'Install OpenVPN from openvpn.net/community-downloads. The official installer also adds the OpenVPN Interactive Service, which lets tunnels connect without a Windows permission prompt each time.'
  }
  if (platform === 'darwin') return 'Install it with Homebrew: brew install openvpn.'
  return 'Install your distribution’s openvpn package, for example apt install openvpn or dnf install openvpn.'
}
