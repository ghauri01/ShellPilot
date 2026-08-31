import { randomBytes } from 'node:crypto'
import { chmod, mkdtemp, rm, writeFile } from 'node:fs/promises'
import { connect, isIP } from 'node:net'
import type { Socket } from 'node:net'
import { tmpdir } from 'node:os'
import { basename, join } from 'node:path'
import { performance } from 'node:perf_hooks'
import type {
  VpnBoundListener,
  VpnEngineInfo,
  VpnListener,
  VpnProfile,
  VpnStartResult,
  VpnState,
  VpnStats,
  VpnStatus,
  VpnValidation,
  VpnValidationIssue,
  WireGuardSpec
} from '../../../../shared/vpn'
import { isCidr, isWireGuardKey, parseVpnEndpoint, WG_HANDSHAKE_STALE_SEC } from '../../../../shared/vpn'
import { resolveBundled } from '../binaries'
import type { VpnDriver, VpnDriverContext } from '../driver'
import type { ElevatedProcess, ElevationExit, Elevator } from '../elevation'
import { elevationErrorCode, elevatorForPlatform } from '../elevation'
import { describeVpnError, isVpnError, toVpnResult, VpnError } from '../errors'
import type { NetApplyContext, NetStateFile } from '../netstate'
import { applyNetState, revertNetState } from '../netstate'
import type { DnsSpec } from '../dns/index'
import type { RouteConflict, RouteManager, RouteSpec } from '../routing/index'
import { claimsDefault, routeManagerFor } from '../routing/index'
import type { SupervisedSpec, SupervisorExit, SupervisorHandle } from '../supervisor'

// WireGuard, in userspace by default, with no administrator rights anywhere in
// the default story.
//
// `shellpilot-netd` runs wireguard-go over gVisor netstack, so the tunnel is
// not an operating-system interface at all: it is a TCP/IP stack living inside
// a child process, exposed to the rest of the app as ordinary loopback
// listeners. Nothing on that path creates a device, changes a route or touches
// the resolver, which is why a user can connect to their company VPN without
// ever seeing an elevation prompt — and why `openForward` can hand db.ts the
// same `{ port, close }` pair `openEphemeralForward` does.
//
// A profile can opt into **system mode**, which is the opposite trade: a real
// TUN interface, real routes and a real resolver change, behind one elevation
// prompt per launch and nothing installed. It is a different device and a
// different transport, not a different protocol — `startSystem` below, and
// `sidecar/netd/privileged.go` on the other side. It is refused on macOS
// (E02), refused for full-tunnel profiles, and it never restarts itself:
// respawning it would mean asking for root again without being asked to.
//
// Three properties are load-bearing and every design choice below follows from
// one of them:
//
//  1. **Keys travel on stdin, never on argv.** `args` is empty — not "almost
//     empty" — because `ps aux` and `Get-CimInstance Win32_Process` are
//     world-readable on every platform this ships to. The NDJSON control
//     channel doubles as the secret channel, so there is nothing to clean up
//     afterwards either: no key ever reaches disk.
//  2. **Up and passing traffic are different facts.** A handshake older than
//     180 s while the process is healthy is `degraded`, never `error`. Telling
//     a user their tunnel is down when it is up-but-idle is how a VPN UI loses
//     trust; telling them it is fine when nothing has crossed it for an hour is
//     how it loses it faster.
//  3. **Time is not monotonic.** The handshake age is computed against a clock
//     that was pinned at start, so a user who fixes their system clock at
//     lunchtime does not get told the last handshake was four thousand seconds
//     in the future (E63).

const NETD = 'shellpilot-netd'

/** Timings and injectable clocks, gathered so a test can shorten a
 *  thirty-second wait and pin the wall clock. Production never writes to this;
 *  the defaults are the plan's numbers (§6.1). */
export const wireguardTuning = {
  /** E22/E27. WireGuard's own rekey attempts give up well inside this, so a
   *  tunnel with nothing to show after 30 s has a reason, not a delay. */
  firstHandshakeTimeoutMs: 30_000,
  handshakePollMs: 500,
  /** The supervisor puts its own deadline around `readiness()`. Ours has to
   *  expire first, because ours can name the endpoint and the peer key and the
   *  supervisor's can only say "not ready within 30s" (E65). */
  readinessSlackMs: 5_000,
  /** A control-channel call that never answers means the sidecar is wedged;
   *  the supervisor's ladder is what fixes that, so this only has to be long
   *  enough that a busy `wg.up` is not mistaken for one. */
  requestTimeoutMs: 20_000,
  healthIntervalMs: 15_000,
  gracefulTimeoutMs: 5_000,
  /** Split so a test can jump the wall clock backwards without touching the
   *  machine's. `monoNow` must be monotonic; `wallNow` need not be. */
  wallNow: (): number => Date.now(),
  monoNow: (): number => performance.now(),
  /** Overridable so the darwin refusal and the conflict gate are testable off
   *  their own platform. */
  platform: null as NodeJS.Platform | null,
  elevator: null as Elevator | null,
  /** The networking half of system mode, injectable for the same reason the
   *  elevator is: a test can then drive the real elevation, the real control
   *  socket and the real `wg.up` without the result depending on — or
   *  rewriting — the route table of whatever machine is running it. */
  routeManager: null as Pick<RouteManager, 'conflicts'> | null,
  applyNet: null as typeof applyNetState | null,
  /** How the sidecar binary is located. Injectable so a test of the elevation
   *  and routing logic does not also depend on a 6 MB Go binary having been
   *  cross-compiled first — which is what made these tests pass locally and
   *  fail on a clean CI runner with `binary-missing`. */
  resolveEngine: null as (() => Promise<VpnEngineInfo>) | null
}

function resolveNetd(): Promise<VpnEngineInfo> {
  return (wireguardTuning.resolveEngine ?? (() => resolveBundled(NETD)))()
}

function platformNow(): NodeJS.Platform {
  return wireguardTuning.platform ?? process.platform
}

// Where the bundled sidecar can actually create a system-mode interface.
//
// Per platform, because the answer turns on things that have nothing to do
// with the Go code:
//
//  - **linux** — open. `shellpilot-netd --privileged` opens `/dev/net/tun`,
//    `pkexec`/`sudo` elevate it for one launch, and `ip` gives the interface
//    its address. Nothing is installed and nothing survives the process.
//  - **win32** — open. UAC elevates for one launch and `netsh` applies the
//    address. Wintun's driver DLL is not bundled today, so a machine without
//    `wintun.dll` gets a refusal from the sidecar that names it, rather than a
//    tunnel that half exists.
//  - **darwin** — closed, and not because of the sidecar (E02). See below.
//
// A platform absent from this map is one nobody has taught the routing and DNS
// managers about, which is a refusal, not a default.
const SIDECAR_HAS_PRIVILEGED_MODE: Partial<Record<NodeJS.Platform, boolean>> = {
  linux: true,
  win32: true,
  darwin: false
}

function sidecarHasPrivilegedMode(platform: NodeJS.Platform): boolean {
  return SIDECAR_HAS_PRIVILEGED_MODE[platform] === true
}

const NO_PRIVILEGED_BUILD =
  'ShellPilot cannot create a system network interface on this platform. Switch this profile to userspace mode.'

// E02. There is no Developer ID for this project, so `SMJobBless` — the only
// supported way to install a privileged helper on macOS — is impossible, and a
// per-launch `osascript` prompt cannot own a persistent utun device. Saying so
// plainly beats an elevation prompt that leads nowhere.
const DARWIN_SYSTEM_MODE =
  'System mode is not available on macOS: ShellPilot has no signed privileged helper, so it cannot create a system network interface. Userspace mode gives the same tunnel through local listeners and needs no administrator rights.'

// --------------------------------------------------------------- wire types

// The half of the sidecar's protocol.go this side consumes. Kept local rather
// than shared: it is a wire contract with one process, and the moment it is
// exported someone will build a UI on it.

interface NetdListenerIn {
  kind: string
  bindHost?: string
  bindPort: number
  targetHost?: string
  targetPort?: number
}

interface NetdListenerOut {
  kind: string
  bindHost: string
  bindPort: number
  targetHost?: string
  targetPort?: number
}

interface NetdUpResult {
  tunnelId: string
  ifaceName?: string
  listeners: NetdListenerOut[]
  assignedIp?: string
}

interface NetdStatsResult {
  tunnelId: string
  rxBytes: number
  txBytes: number
  /** ABSOLUTE unix seconds, not an age. Zero means there has never been one. */
  lastHandshakeUnixSec?: number
  remoteEndpoint?: string
  assignedIp?: string
  peers: number
  sampledAt: number
}

interface NetdForwardOpenResult {
  forwardId: string
  bindHost: string
  listenPort: number
}

interface NetdStateData {
  tunnelId: string
  state: string
  assignedIp?: string
  remoteEndpoint?: string
  errorCode?: string
  error?: string
}

interface NetdLogData {
  level: string
  msg: string
  tunnelId?: string
}

interface NetdResponse {
  id?: string
  ok?: boolean
  result?: unknown
  error?: { code?: string; message?: string }
  event?: string
  data?: unknown
}

// ------------------------------------------------------------------- clocks

/** A wall clock that ignores wall-clock jumps: it is pinned once and advanced
 *  from a monotonic source thereafter. */
export interface MonotonicClock {
  /** Epoch milliseconds as they would have run had nobody touched the clock. */
  nowMs(): number
}

export function createMonotonicClock(
  wallNow: () => number = wireguardTuning.wallNow,
  monoNow: () => number = wireguardTuning.monoNow
): MonotonicClock {
  const wallBase = wallNow()
  const monoBase = monoNow()
  return { nowMs: (): number => wallBase + (monoNow() - monoBase) }
}

/**
 * Age of a handshake in whole seconds, or undefined when there has never been
 * one.
 *
 * E63: the sidecar reports an absolute unix second because it cannot know what
 * the parent's clock has been doing. Measuring against `Date.now()` here would
 * mean a user who corrects a fast clock sees "last handshake in 4000 seconds",
 * and the floor at zero is the second half of the same promise: a negative age
 * is never a fact about the tunnel, only ever a fact about the clock.
 */
export function handshakeAgeSec(
  lastHandshakeUnixSec: number | undefined,
  clock: MonotonicClock
): number | undefined {
  if (!lastHandshakeUnixSec || lastHandshakeUnixSec <= 0) return undefined
  return Math.max(0, Math.floor(clock.nowMs() / 1000 - lastHandshakeUnixSec))
}

/**
 * Up-but-not-passing-traffic versus down. WireGuard rekeys well inside 180 s
 * whenever anything is flowing, so a handshake older than that means the
 * process is fine and the path is not — which is amber, not red, and is the
 * single most useful thing a WireGuard card can show.
 */
export function stateFromHandshakeAge(ageSec: number | undefined): VpnState {
  if (ageSec === undefined) return 'starting'
  return ageSec > WG_HANDSHAKE_STALE_SEC ? 'degraded' : 'connected'
}

// --------------------------------------------------------------- validation

function issue(
  path: string,
  code: string,
  message: string,
  severity: VpnValidationIssue['severity'] = 'error'
): VpnValidationIssue {
  return { path, severity, code, message }
}

const LOOPBACK = new Set(['127.0.0.1', 'localhost', '::1', ''])

function isDefaultPrefix(cidr: string): boolean {
  const t = cidr.trim()
  return t === '0.0.0.0/0' || t === '::/0'
}

/**
 * Pure and synchronous: no I/O, no secrets, no platform. Safe to call from a
 * form on every keystroke, which is the point — a mistyped key caught here is
 * a red field, and the same key caught by the engine is a silent absence of
 * handshakes thirty seconds later.
 */
export function validateWireGuardSpec(spec: WireGuardSpec): VpnValidation {
  const issues: VpnValidationIssue[] = []

  if (!spec.privateKeyRef?.vaultEntryId) {
    issues.push(
      issue('privateKeyRef', 'private-key-missing', 'This profile has no private key stored in the vault.')
    )
  }

  if (!spec.addresses || spec.addresses.length === 0) {
    issues.push(issue('addresses', 'addresses-empty', 'At least one interface address is required.'))
  }
  spec.addresses?.forEach((a, i) => {
    if (!isCidr(a)) {
      issues.push(
        issue(`addresses[${i}]`, 'address-invalid', `"${a}" is not an address with a prefix, e.g. 10.0.0.2/32.`)
      )
    }
  })

  spec.dns?.forEach((d, i) => {
    if (isIP(d.trim()) === 0) {
      issues.push(issue(`dns[${i}]`, 'dns-invalid', `"${d}" is not an IP address.`))
    }
  })

  if (spec.mtu !== undefined) {
    // The same 576-9000 window the sidecar enforces, so the form rejects what
    // the engine would have rejected rather than the two disagreeing.
    if (!Number.isInteger(spec.mtu) || spec.mtu < 576 || spec.mtu > 9000) {
      issues.push(issue('mtu', 'mtu-range', 'MTU must be a whole number between 576 and 9000. 1420 is the usual value.'))
    }
  }

  if (!spec.peers || spec.peers.length === 0) {
    issues.push(issue('peers', 'peers-empty', 'A WireGuard profile needs at least one peer.'))
  }

  const seenKeys = new Map<string, number>()
  spec.peers?.forEach((peer, i) => {
    if (!isWireGuardKey(peer.publicKey ?? '')) {
      issues.push(
        issue(`peers[${i}].publicKey`, 'public-key-invalid', 'A public key is 44 base64 characters ending in "=".')
      )
    } else {
      const first = seenKeys.get(peer.publicKey.trim())
      if (first !== undefined) {
        // Two peers with one key is not a duplicate row to tidy up: the device
        // replaces the first with the second, so one of the two endpoints
        // silently stops being used.
        issues.push(
          issue(
            `peers[${i}].publicKey`,
            'public-key-duplicate',
            `This is the same public key as peer ${first + 1}. Each peer needs its own.`
          )
        )
      } else {
        seenKeys.set(peer.publicKey.trim(), i)
      }
    }

    if (!parseVpnEndpoint(peer.endpoint ?? '')) {
      issues.push(
        issue(`peers[${i}].endpoint`, 'endpoint-invalid', 'An endpoint looks like vpn.example.com:51820 or [2001:db8::1]:51820.')
      )
    }

    if (!peer.allowedIps || peer.allowedIps.length === 0) {
      issues.push(issue(`peers[${i}].allowedIps`, 'allowed-ips-empty', 'At least one allowed IP range is required.'))
    }
    peer.allowedIps?.forEach((a, j) => {
      if (!isCidr(a)) {
        issues.push(
          issue(`peers[${i}].allowedIps[${j}]`, 'allowed-ip-invalid', `"${a}" is not a CIDR range, e.g. 10.0.0.0/24.`)
        )
      }
    })

    if (peer.persistentKeepalive !== undefined) {
      if (!Number.isInteger(peer.persistentKeepalive) || peer.persistentKeepalive < 0 || peer.persistentKeepalive > 65535) {
        issues.push(
          issue(`peers[${i}].persistentKeepalive`, 'keepalive-range', 'Keepalive is a whole number of seconds, 0 to 65535. 25 is the usual value behind NAT.')
        )
      }
    }
  })

  // E17. In userspace mode 0.0.0.0/0 is not a warning about danger — it is a
  // warning about a false belief. The prefix tells the device which peer a
  // packet belongs to and nothing else, because there is no route table in
  // play at all, so a user reading "all traffic" off their config needs to be
  // told plainly that only what they point at the listeners is tunnelled.
  const defaultPeer = spec.peers?.findIndex((p) => (p.allowedIps ?? []).some(isDefaultPrefix)) ?? -1
  if (spec.mode === 'userspace' && defaultPeer >= 0) {
    issues.push(
      issue(
        `peers[${defaultPeer}].allowedIps`,
        'default-route-userspace',
        'This peer accepts all traffic (0.0.0.0/0 or ::/0), but userspace mode changes no system routes: only the connections you send through this profile\'s listeners or forwards go through the tunnel. Everything else on this machine keeps using your normal network.',
        'warning'
      )
    )
  }

  if (spec.mode === 'userspace') {
    const ports = new Map<number, number>()
    spec.listeners?.forEach((l, i) => {
      if (!Number.isInteger(l.bindPort) || l.bindPort < 0 || l.bindPort > 65535) {
        issues.push(issue(`listeners[${i}].bindPort`, 'port-range', 'A port is a whole number from 0 to 65535. 0 picks a free one.'))
      } else if (l.bindPort > 0) {
        const first = ports.get(l.bindPort)
        if (first !== undefined) {
          // Caught here rather than as an EADDRINUSE from our own second
          // listener, which reads as "something else has the port" and sends
          // the user hunting through `lsof` for a process that is us.
          issues.push(
            issue(
              `listeners[${i}].bindPort`,
              'port-duplicate',
              `Port ${l.bindPort} is already used by listener ${first + 1}. Use a different port, or 0 to pick one automatically.`
            )
          )
        } else {
          ports.set(l.bindPort, i)
        }
      }

      if (!LOOPBACK.has((l.bindHost ?? '').trim())) {
        // E25. Legitimate — a VM or a container on the host bridge needs it —
        // so a warning, not an error, but never silent.
        issues.push(
          issue(
            `listeners[${i}].bindHost`,
            'listener-not-loopback',
            `Binding to ${l.bindHost} makes this listener reachable from your local network, not just this machine.`,
            'warning'
          )
        )
      }

      if (l.kind === 'forward') {
        if (!l.targetHost?.trim()) {
          issues.push(issue(`listeners[${i}].targetHost`, 'target-missing', 'A forward needs the address to connect to inside the tunnel.'))
        }
        if (!Number.isInteger(l.targetPort) || l.targetPort < 1 || l.targetPort > 65535) {
          issues.push(issue(`listeners[${i}].targetPort`, 'target-port-range', 'A forward needs a target port from 1 to 65535.'))
        }
      } else if (l.kind !== 'socks5' && l.kind !== 'http') {
        issues.push(issue(`listeners[${i}].kind`, 'listener-kind', `"${(l as VpnListener).kind}" is not a listener ShellPilot can open.`))
      }
    })
  }

  if (spec.mode === 'system' && defaultPeer >= 0) {
    // Refused rather than warned about, and refused here as well as at start,
    // so the form says so before the user has committed to the profile. See
    // FULL_TUNNEL_SYSTEM_MODE: without keeping the peer endpoint outside the
    // tunnel, a full-tunnel system profile routes its own encrypted packets
    // back into itself and takes the machine off the network.
    issues.push(issue(`peers[${defaultPeer}].allowedIps`, 'default-route-system-mode', FULL_TUNNEL_SYSTEM_MODE))
  }

  if (spec.mode === 'system') {
    issues.push(
      issue(
        'mode',
        'system-mode-elevation',
        'System mode creates a real network interface and changes this machine\'s routes and DNS, so it asks for administrator approval every time it starts.',
        'warning'
      )
    )
  }

  return { ok: !issues.some((i) => i.severity === 'error'), issues }
}

// -------------------------------------------------------------------- state

interface Pending {
  resolve(value: unknown): void
  reject(error: unknown): void
  timer: ReturnType<typeof setTimeout>
}

/** How a request line reaches the sidecar, and how that channel is closed.
 *
 *  Userspace mode writes to the supervised child's stdin. System mode writes
 *  to an authenticated unix socket, because an elevated child has no stdio
 *  connected to us on two of the three platforms. `send()` does not care
 *  which; everything above it is the same code. */
interface Transport {
  write(line: string): void
  close(): Promise<void>
}

interface Run {
  profile: VpnProfile & { spec: WireGuardSpec }
  spec: WireGuardSpec
  ctx: VpnDriverContext
  handle: SupervisorHandle | null
  transport: Transport | null
  /** System mode only: the elevated sidecar and everything it needs cleaning
   *  up — the socket, the 0700 control directory, the process itself. */
  privileged: PrivilegedSidecar | null
  status: VpnStatus
  clock: MonotonicClock
  seq: number
  pending: Map<string, Pending>
  listeners: VpnBoundListener[]
  /** Forward ids handed out by the sidecar, so a stop can drop them all. */
  forwards: Set<string>
  stopping: boolean
  /** True once start() has returned success. After that a terminal exit is a
   *  *drop* — the manager has to release dependents and tear the run down —
   *  rather than a start that failed, which start()'s own rejection handles. */
  started: boolean
  /** Ends the in-flight `start()` with a better error than the one the
   *  supervisor would eventually produce. A no-op once the start has settled. */
  fail: (e: unknown) => void
  detach: (() => void)[]
  /** System mode only: what was changed on this machine, and how to undo it. */
  netState: NetStateFile | null
  netCtx: NetApplyContext | null
}

const runs = new Map<string, Run>()

function publish(run: Run, patch: Partial<VpnStatus>): void {
  run.status = { ...run.status, ...patch }
  run.ctx.emit(patch)
}

// ----------------------------------------------------------- control channel

/**
 * One NDJSON request, correlated by id.
 *
 * The request line is the only channel any key ever travels on. `handle.write`
 * puts it on the child's stdin, which the supervisor keeps open for the life of
 * the run — deliberately not `SupervisedSpec.stdinPayload`, which writes once
 * and then ends the pipe, and an ended stdin is exactly how netd is told the
 * parent has died.
 */
function send<T>(run: Run, method: string, params?: unknown): Promise<T> {
  const transport = run.transport
  if (!transport) {
    return Promise.reject(new VpnError('internal', 'The WireGuard sidecar is not running.'))
  }
  const id = String(++run.seq)
  return new Promise<T>((resolve, reject) => {
    const timer = setTimeout(() => {
      run.pending.delete(id)
      reject(new VpnError('internal', `The sidecar did not answer ${method} within ${Math.round(wireguardTuning.requestTimeoutMs / 1000)}s.`))
    }, wireguardTuning.requestTimeoutMs)
    run.pending.set(id, { resolve: resolve as (v: unknown) => void, reject, timer })
    transport.write(`${JSON.stringify({ id, method, params })}\n`)
  })
}

function settleAll(run: Run, error: VpnError): void {
  for (const [, p] of run.pending) {
    clearTimeout(p.timer)
    p.reject(error)
  }
  run.pending.clear()
}

/** Every line the sidecar writes. stdout is protocol; stderr is prose. */
function onLine(run: Run, stream: string, text: string): void {
  if (stream !== 'stdout') {
    run.ctx.log(text, stream === 'stderr' ? 'stderr' : 'app')
    return
  }
  const trimmed = text.trim()
  if (!trimmed) return
  if (!trimmed.startsWith('{')) {
    // Not protocol. Almost certainly a Go runtime message that escaped onto
    // stdout, which is worth showing rather than swallowing.
    run.ctx.log(trimmed, 'stdout')
    return
  }

  let msg: NetdResponse
  try {
    msg = JSON.parse(trimmed) as NetdResponse
  } catch {
    // Never quote the line back at full length in an error: a malformed wg.up
    // echo would carry a private key.
    run.ctx.log('The sidecar wrote a line that is not valid JSON.', 'ctl')
    return
  }

  if (typeof msg.id === 'string') {
    const pending = run.pending.get(msg.id)
    if (!pending) return
    run.pending.delete(msg.id)
    clearTimeout(pending.timer)
    if (msg.ok) pending.resolve(msg.result)
    else pending.reject(wireError(msg.error))
    return
  }

  if (msg.event === 'log') {
    const data = (msg.data ?? {}) as NetdLogData
    if (data.msg) run.ctx.log(`[${data.level ?? 'info'}] ${data.msg}`, 'ctl')
    return
  }
  if (msg.event === 'wg.state') {
    applyState(run, (msg.data ?? {}) as NetdStateData)
    return
  }
  run.ctx.log(trimmed, 'ctl')
}

/** The sidecar's error codes are drawn from `VpnErrorCode` by construction, so
 *  an unrecognised one is a version skew rather than something to guess at. */
function wireError(e: { code?: string; message?: string } | undefined): VpnError {
  const code = e?.code
  const detail = e?.message
  if (code && code in VPN_CODES) return new VpnError(code as VpnError['code'], detail)
  return new VpnError('internal', detail ?? 'The WireGuard sidecar reported an error with no detail.')
}

// The subset protocol.go can emit. Listed rather than cast so a code the
// sidecar grows and this file has not seen becomes `internal` with the
// engine's own sentence attached, instead of a VpnError with a code nothing
// downstream has a message for.
const VPN_CODES: Record<string, true> = {
  'config-invalid': true,
  'port-in-use': true,
  'permission-denied': true,
  'handshake-timeout': true,
  'network-unreachable': true,
  'dns-failure': true,
  'already-running': true,
  unsupported: true,
  internal: true
}

function applyState(run: Run, data: NetdStateData): void {
  if (run.stopping) return
  switch (data.state) {
    case 'connected':
      publish(run, { state: 'connected', error: undefined, errorCode: undefined })
      return
    case 'degraded':
      // Amber. The process is alive and the listeners are open; what has
      // stopped is the far end answering.
      publish(run, {
        state: 'degraded',
        error: describeVpnError('handshake-timeout', staleDetail(run, data.remoteEndpoint)),
        errorCode: 'handshake-timeout'
      })
      return
    case 'stopped':
      publish(run, { state: 'stopped' })
      return
    case 'error': {
      const err =
        data.errorCode === 'handshake-timeout'
          ? handshakeTimeout(run)
          : wireError({ code: data.errorCode, message: data.error })
      publish(run, { state: 'error', error: describeVpnError(err.code, err.detail), errorCode: err.code })
      return
    }
    default:
      return
  }
}

// ------------------------------------------------------------------- errors

/** The peer this profile is trying to reach, from the model. */
function firstPeer(spec: WireGuardSpec): { endpoint: string; publicKey: string } | null {
  const peer = spec.peers?.find((p) => (p.endpoint ?? '').trim() !== '') ?? spec.peers?.[0]
  if (!peer) return null
  return { endpoint: (peer.endpoint ?? '').trim(), publicKey: (peer.publicKey ?? '').trim() }
}

/**
 * E22/E27. Three facts, because a first handshake that never arrives has
 * exactly three common causes and the user cannot tell them apart from the
 * outside: the UDP port is blocked, the network wants them to sign in, or the
 * server does not have this public key.
 *
 * The public key comes from the profile, never from a log line. The redactor
 * cannot tell a public key from a private one — they are the same 32 bytes of
 * base64 — so it blanks both, and a UI that scraped one out of the log drawer
 * would show `[REDACTED]` at the exact moment the user needs to compare it
 * against what their administrator has on file.
 */
function handshakeTimeout(run: Run): VpnError {
  const peer = firstPeer(run.spec)
  const seconds = Math.round(wireguardTuning.firstHandshakeTimeoutMs / 1000)
  if (!peer) return new VpnError('handshake-timeout', `Nothing answered within ${seconds}s.`)
  const port = parseVpnEndpoint(peer.endpoint)?.port
  const parts = [
    `${peer.endpoint} did not complete a handshake within ${seconds}s.`,
    port !== undefined
      ? `WireGuard is UDP: outbound UDP to port ${port} may be blocked here, or this network may need you to sign in first.`
      : 'WireGuard is UDP, which some networks block.'
  ]
  if (peer.publicKey) parts.push(`The server may also not recognise this public key: ${peer.publicKey}`)
  return new VpnError('handshake-timeout', parts.join(' '))
}

function staleDetail(run: Run, endpoint?: string): string {
  const where = endpoint || firstPeer(run.spec)?.endpoint || 'the peer'
  return `Nothing has been heard from ${where} for over ${WG_HANDSHAKE_STALE_SEC}s. The tunnel is still up and its listeners are still open.`
}

// -------------------------------------------------------------------- start

function toListenerIn(l: VpnListener): NetdListenerIn {
  const base: NetdListenerIn = {
    kind: l.kind,
    // Empty means loopback to the sidecar, and loopback is the default an
    // ephemeral proxy should have.
    bindHost: (l.bindHost ?? '').trim() || '127.0.0.1',
    bindPort: l.bindPort
  }
  if (l.kind === 'forward') {
    base.targetHost = l.targetHost
    base.targetPort = l.targetPort
  }
  return base
}

/** E25: the bind host comes back exactly as the sidecar bound it, never
 *  normalised, so a UI showing `0.0.0.0` is showing the truth. */
function toBound(l: NetdListenerOut): VpnBoundListener {
  return {
    kind: l.kind,
    bindHost: l.bindHost,
    bindPort: l.bindPort,
    ...(l.targetHost ? { targetHost: l.targetHost } : {}),
    ...(l.targetPort ? { targetPort: l.targetPort } : {})
  }
}

function upParams(run: Run): Record<string, unknown> {
  const secrets = run.ctx.secrets
  if (!secrets.privateKey) {
    throw new VpnError('config-invalid', 'No private key was available for this profile.')
  }
  return {
    tunnelId: run.profile.id,
    iface: {
      privateKey: secrets.privateKey,
      addresses: run.spec.addresses ?? [],
      dns: run.spec.dns ?? [],
      ...(run.spec.mtu ? { mtu: run.spec.mtu } : {})
    },
    peers: (run.spec.peers ?? []).map((p) => ({
      publicKey: p.publicKey,
      // Keyed by peer public key by the resolver, so a profile with two peers
      // and one preshared key sends it to the peer it belongs to.
      ...(secrets.presharedKeys?.[p.publicKey] ? { presharedKey: secrets.presharedKeys[p.publicKey] } : {}),
      endpoint: p.endpoint,
      allowedIps: p.allowedIps ?? [],
      ...(p.persistentKeepalive ? { persistentKeepalive: p.persistentKeepalive } : {})
    })),
    listeners: (run.spec.listeners ?? []).map(toListenerIn),
    // The device emits a line per worker goroutine at startup, which is
    // ~60 log events racing the responses on the same pipe for every wg.up.
    // "debug" is genuinely useful when a handshake will not complete and
    // genuinely unusable otherwise, so it is not the default and there is no
    // UI for it yet: a support build flips this line.
    logLevel: 'error'
  }
}

const sleep = (ms: number): Promise<void> => new Promise((r) => setTimeout(r, ms))

/**
 * Readiness, in two steps that answer two different questions.
 *
 * `wg.up` answers "are the listeners open" — which is what the caller needs
 * before it can hand a port to db.ts. The handshake poll answers "is anything
 * at the other end" — which is what the user needs before they believe the
 * green dot. Both have to hold before a start is called a success, because a
 * SOCKS proxy that accepts connections and then hangs is worse than one that
 * refused to open.
 */
async function bringUp(run: Run, handle: SupervisorHandle): Promise<void> {
  run.handle = handle
  run.transport = stdinTransport(handle)
  try {
    const up = await send<NetdUpResult>(run, 'wg.up', upParams(run))
    run.listeners = (up.listeners ?? []).map(toBound)
    publish(run, { listeners: run.listeners })

    const exposed = run.listeners.filter((l) => !LOOPBACK.has(l.bindHost))
    for (const l of exposed) {
      // Reported back verbatim so the UI can warn: the sidecar allowed the
      // bind, and pretending it was loopback would hide a LAN-visible proxy.
      run.ctx.log(`${l.kind} is listening on ${l.bindHost}:${l.bindPort}, which is reachable from your local network.`, 'app')
    }

    await awaitHandshake(run)
    publish(run, { state: 'connected', error: undefined, errorCode: undefined })
  } catch (e) {
    // Reported now, with the reason, rather than after two minutes of backoff
    // that can only end in `crash-loop`: a blocked UDP port does not become
    // unblocked by trying five more times.
    run.fail(e)
    throw e
  }
}

async function awaitHandshake(run: Run): Promise<void> {
  const deadline = run.clock.nowMs() + wireguardTuning.firstHandshakeTimeoutMs
  for (;;) {
    const stats = await send<NetdStatsResult>(run, 'wg.stats', { tunnelId: run.profile.id })
    if (handshakeAgeSec(stats.lastHandshakeUnixSec, run.clock) !== undefined) {
      publish(run, { stats: toStats(run, stats) })
      return
    }
    if (run.clock.nowMs() >= deadline) throw handshakeTimeout(run)
    if (run.stopping) throw new VpnError('internal', 'The tunnel was stopped while it was starting.')
    await sleep(wireguardTuning.handshakePollMs)
  }
}

function toStats(run: Run, s: NetdStatsResult): VpnStats {
  const age = handshakeAgeSec(s.lastHandshakeUnixSec, run.clock)
  return {
    rxBytes: s.rxBytes ?? 0,
    txBytes: s.txBytes ?? 0,
    ...(age === undefined ? {} : { lastHandshakeSec: age }),
    ...(s.assignedIp ? { assignedIp: s.assignedIp } : {}),
    ...(s.remoteEndpoint ? { remoteEndpoint: s.remoteEndpoint } : {}),
    // The pinned clock, for the same reason the age uses it: a status card
    // whose "as of" time jumps backwards is a card nobody trusts.
    sampledAt: Math.round(run.clock.nowMs())
  }
}

/** The supervisor's periodic health check. A stale handshake is a *state*, not
 *  a failure: throwing here would have the supervisor kill a tunnel that is
 *  merely idle. Only a control channel that has stopped answering does that. */
async function sampleHealth(run: Run): Promise<void> {
  const stats = await send<NetdStatsResult>(run, 'wg.stats', { tunnelId: run.profile.id })
  const age = handshakeAgeSec(stats.lastHandshakeUnixSec, run.clock)
  const state = stateFromHandshakeAge(age)
  publish(run, {
    state,
    stats: toStats(run, stats),
    error: state === 'degraded' ? describeVpnError('handshake-timeout', staleDetail(run, stats.remoteEndpoint)) : undefined,
    errorCode: state === 'degraded' ? 'handshake-timeout' : undefined
  })
}

function supervisedSpec(run: Run, enginePath: string, sha256: string | undefined): SupervisedSpec {
  return {
    id: run.profile.id,
    command: enginePath,
    // Empty, and it stays empty. Every parameter this engine takes — including
    // the private key and every preshared key — arrives as an NDJSON request
    // on stdin, because `ps aux` on POSIX and Get-CimInstance Win32_Process on
    // Windows show argv to every user on the machine.
    args: [],
    cwd: run.ctx.runDir,
    // Deliberately no `stdinPayload`: that writes once and closes the pipe,
    // and netd treats stdin EOF as "the parent is gone, shut down".
    readiness: (h) => bringUp(run, h),
    readinessTimeoutMs: wireguardTuning.firstHandshakeTimeoutMs + wireguardTuning.readinessSlackMs,
    healthCheck: () => sampleHealth(run),
    healthIntervalMs: wireguardTuning.healthIntervalMs,
    gracefulStop: () => gracefulStop(run),
    gracefulTimeoutMs: wireguardTuning.gracefulTimeoutMs,
    restart: 'on-failure',
    backoff: { baseMs: 1_000, maxMs: 30_000, jitter: 0.3 },
    crashLoop: { windowMs: 120_000, maxRestarts: 5 },
    logRing: { maxLines: 2_000, maxBytes: 1 << 20 },
    redact: run.ctx.secrets.all,
    kind: 'wireguard',
    profileId: run.profile.id,
    exeSha256: sha256,
    onRestartScheduled: (h) => publish(run, { state: 'reconnecting', restarts: h.restarts })
  }
}

function onExit(run: Run, exit: SupervisorExit): void {
  // Whatever was in flight is never going to be answered now.
  settleAll(run, exit.error ?? new VpnError('internal', 'The WireGuard sidecar exited.'))
  run.forwards.clear()
  if (run.stopping) return
  if (exit.restarting) return

  const err = exit.error ?? new VpnError('internal', `The WireGuard sidecar exited with code ${exit.code}.`)
  // The last thing the engine said, kept where the user can read it: the crash
  // dialog tells them to open the log, and the supervisor computes this tail
  // for exactly that purpose.
  for (const l of exit.logTail ?? []) run.ctx.log(l.text, l.stream)
  if (run.started) {
    // Already connected, so this is a drop rather than a failed start. The
    // manager releases dependents and tears the run down; it emits the error
    // itself, so do not also publish one.
    run.ctx.dropped(describeVpnError(err.code, err.detail), err.code)
    return
  }
  publish(run, { state: 'error', error: describeVpnError(err.code, err.detail), errorCode: err.code })
  run.fail(err)
}

async function gracefulStop(run: Run): Promise<void> {
  // `wg.down` first so the listeners are closed and every relay has ended
  // before the process goes: the caller is entitled to assume the ports are
  // free once a stop returns. Then `shutdown`, which is load-bearing on
  // Windows, where a non-console child has no SIGTERM at all and
  // `process.kill` is a hard TerminateProcess.
  await send(run, 'wg.down', { tunnelId: run.profile.id }).catch(() => undefined)
  await send(run, 'shutdown').catch(() => undefined)
}

/**
 * System mode, in the order that keeps every refusal cheap.
 *
 * `applySystemNetworking` owns the sequence — platform gate, elevation probe,
 * conflict check, *then* the device, then the snapshot and the change. The
 * device step is this function's callback, so a prefix another VPN already
 * owns is refused before a single elevation prompt appears, and the routes and
 * the resolver are addressed to the interface name the kernel actually chose.
 *
 * There is no supervisor here and no restart ladder. The sidecar is started by
 * an elevation helper, not by us, so we cannot respawn it without asking the
 * user for administrator rights again — and silently re-prompting for root is
 * not a thing an app should do. A dropped system-mode tunnel is reported and
 * left for the user to restart.
 */
async function startSystem(run: Run): Promise<void> {
  const platform = platformNow()
  const engine = await resolveNetd()
  if (!engine.path) {
    // The userspace path tolerates a bare name and lets the OS resolve it.
    // This one must not: `pkexec shellpilot-netd` resolved through an
    // inherited PATH is a root process chosen by whoever got a directory onto
    // that PATH first.
    throw new VpnError(
      'internal',
      'The WireGuard sidecar could not be located on disk, and system mode will not ask for administrator rights for a binary it cannot name.'
    )
  }
  const enginePath = engine.path
  const elevator = wireguardTuning.elevator ?? elevatorForPlatform(platform)
  // The run directory's own name is the run id: the manager derives one from
  // the other, and the netstate record has to be findable by the startup
  // restore pass under exactly that name.
  const runId = basename(run.ctx.runDir)

  const failed = new Promise<never>((_resolve, reject) => {
    run.fail = reject
  })

  const applied = applySystemNetworking(run.profile, run.ctx, runId, {
    platform,
    elevator,
    ...(wireguardTuning.routeManager ? { routeManager: wireguardTuning.routeManager } : {}),
    ...(wireguardTuning.applyNet ? { applyNet: wireguardTuning.applyNet } : {}),
    bringUpInterface: async (planned) => {
      const sidecar = await launchPrivilegedSidecar(
        run,
        enginePath,
        planned,
        elevator,
        `ShellPilot needs administrator rights to create a network interface for "${run.profile.name}".`
      )
      run.privileged = sidecar
      const up = await send<NetdUpResult>(run, 'wg.up', {
        ...upParams(run),
        ifaceName: planned,
        // Meaningless with a real interface: the route table carries the
        // traffic. The sidecar refuses them rather than dropping them, and
        // this makes sure it never has to.
        listeners: []
      })
      sidecar.ifaceName = (up.ifaceName ?? '').trim()
      sidecar.assignedIp = up.assignedIp
      if (!sidecar.ifaceName) {
        throw new VpnError(
          'internal',
          'The WireGuard sidecar created an interface but did not say what it is called, so nothing can be routed through it.'
        )
      }
      return sidecar.ifaceName
    }
  })

  const result = await Promise.race([applied, failed])
  run.netState = result.state
  run.netCtx = result.ctx
  run.ctx.log(`Routing through ${result.state.interfaceName}.`, 'app')

  // Only now, with routes and DNS in place, is a handshake something to wait
  // for: until the routes exist there may be no path to the peer at all.
  await Promise.race([awaitHandshake(run), failed])
  publish(run, { state: 'connected', error: undefined, errorCode: undefined })
}

async function start(
  profile: VpnProfile & { spec: WireGuardSpec },
  ctx: VpnDriverContext
): Promise<VpnStartResult> {
  const run: Run = {
    profile,
    spec: profile.spec,
    ctx,
    handle: null,
    transport: null,
    privileged: null,
    status: { id: profile.id, kind: 'wireguard', state: 'starting', since: Date.now(), restarts: 0 },
    clock: createMonotonicClock(),
    seq: 0,
    pending: new Map(),
    listeners: [],
    forwards: new Set(),
    stopping: false,
    started: false,
    fail: () => {},
    detach: [],
    netState: null,
    netCtx: null
  }

  try {
    if (profile.spec.mode === 'system') {
      // Refused before anything is elevated and before any snapshot is taken:
      // prompting for administrator rights we cannot use would be worse than
      // saying no.
      guardSystemMode(platformNow())
      runs.set(profile.id, run)
      await startSystem(run)
      run.started = true
      return { ok: true, listeners: [] }
    }
    const engine = await resolveNetd()
    runs.set(profile.id, run)

    const spec = supervisedSpec(run, engine.path ?? NETD, engine.sha256)
    const failed = new Promise<never>((_resolve, reject) => {
      run.fail = reject
    })
    const pending = ctx.supervisor.spawn(spec)
    // The handle exists from the moment `spawn` is called, and the sidecar's
    // first lines arrive well before readiness. Attaching after would lose the
    // response to our own `wg.up`.
    const handle = ctx.supervisor.get(profile.id)
    if (!handle) throw new VpnError('internal', 'The supervisor did not register the run.')
    run.handle = handle
    run.detach.push(handle.onLog((l) => onLine(run, l.stream, l.text)))
    run.detach.push(handle.onExit((e) => onExit(run, e)))

    await Promise.race([pending, failed])
    run.started = true
    return { ok: true, listeners: run.listeners }
  } catch (e) {
    await teardown(run, { force: true })
    runs.delete(profile.id)
    return toVpnResult(e)
  }
}

/** Detach, stop the child, and put back anything system mode changed. */
async function teardown(run: Run, opts?: { force?: boolean }): Promise<void> {
  run.stopping = true
  run.fail = () => {}
  try {
    // The log listener stays attached across the stop, and that is load-
    // bearing: it is the only reader of the control channel, so detaching it
    // first would leave `wg.down` waiting for an answer that has already
    // arrived and been dropped — a graceful stop that takes a request timeout
    // and then escalates to a signal for no reason.
    if (run.privileged) {
      // No supervisor involved: this child belongs to an elevation helper, not
      // to us. Its own stop() says `wg.down` and `shutdown` first, then closes
      // the socket, which is what makes the sidecar exit and take the tunnel
      // interface — and every route bound to it — with it.
      await run.privileged.stop(opts).catch(() => undefined)
      run.privileged = null
    } else {
      await run.ctx.supervisor.stop(run.profile.id, opts).catch(() => undefined)
    }
    run.transport = null
  } finally {
    for (const off of run.detach.splice(0)) off()
    settleAll(run, new VpnError('internal', 'The tunnel was stopped.'))
    if (run.netState && run.netCtx) {
      // Reverted here as well as by the startup pass, because a clean stop
      // should not leave a user's resolver pointing into a tunnel that no
      // longer exists until they next open the app.
      await revertNetState(run.netState, run.netCtx).catch((e: unknown) => {
        run.ctx.log(`Could not put the system network settings back: ${describe(e)}`, 'app')
      })
      run.netState = null
    }
  }
}

async function stop(id: string, opts?: { force?: boolean }): Promise<void> {
  const run = runs.get(id)
  if (!run) return
  try {
    await teardown(run, opts)
  } finally {
    runs.delete(id)
  }
}

// ------------------------------------------------------------------ forwards

/**
 * An ephemeral loopback listener that relays into the tunnel. Deliberately the
 * same `{ port, close }` shape `openEphemeralForward` returns, so `db.ts` and
 * `ssh.ts` consume a VPN forward and an SSH forward without branching — which
 * is the whole reason SSH-over-VPN and DB-over-VPN cost nothing to add.
 */
async function openForward(
  id: string,
  host: string,
  port: number
): Promise<{ port: number; close: () => void }> {
  const run = runs.get(id)
  if (!run || !run.transport) throw new VpnError('internal', 'That VPN profile is not running.')
  if (run.spec.mode !== 'userspace') {
    throw new VpnError('unsupported', 'System mode routes this traffic already, so there is nothing to forward through.')
  }

  const res = await send<NetdForwardOpenResult>(run, 'wg.forward.open', {
    tunnelId: id,
    host,
    port
  })
  run.forwards.add(res.forwardId)

  let closed = false
  return {
    port: res.listenPort,
    close: (): void => {
      if (closed) return
      closed = true
      run.forwards.delete(res.forwardId)
      // Fire and forget: a forward whose tunnel already went down is not an
      // error, and the caller closing it is often the thing that happens on
      // the way out of a failed connection.
      void send(run, 'wg.forward.close', { forwardId: res.forwardId }).catch(() => undefined)
    }
  }
}

// ------------------------------------------------- privileged control channel

/** The supervised child's stdin. `handle.write` keeps the pipe open for the
 *  life of the run — deliberately not `SupervisedSpec.stdinPayload`, which
 *  writes once and then ends the pipe, and an ended stdin is exactly how netd
 *  is told the parent has died. */
function stdinTransport(handle: SupervisorHandle): Transport {
  return {
    write: (line) => handle.write(line),
    close: async () => {}
  }
}

export interface PrivilegedSidecar {
  transport: Transport
  /** The name the KERNEL gave the interface, as the sidecar reports it. Not
   *  the name that was asked for: on macOS they are never the same, and on
   *  Linux and Windows they can differ. */
  ifaceName: string
  assignedIp?: string
  stop(opts?: { force?: boolean }): Promise<void>
}

/** How long to wait for the elevated sidecar to appear on its socket. Long,
 *  because the clock includes a human reading a UAC or polkit dialog. */
const ELEVATED_CONNECT_TIMEOUT_MS = 120_000
const ELEVATED_CONNECT_POLL_MS = 150

/** Exit codes privileged.go uses before it can say anything on the socket.
 *  They are all we get: no elevation helper on any platform hands us the
 *  elevated child's stderr. */
const NETD_EXIT = {
  badArguments: 2,
  setupRefused: 3,
  authFailed: 4
} as const

/**
 * Start `shellpilot-netd --privileged` behind one elevation prompt and
 * authenticate to it.
 *
 * The nonce is 32 random bytes written as hex into a 0600 file inside a 0700
 * directory, and only the *path* goes on the command line: argv is readable by
 * every account on the machine through `ps aux` and
 * `Get-CimInstance Win32_Process`. The sidecar deletes the file the moment it
 * reads it.
 *
 * §6.1 describes the nonce as travelling "over the already-elevated channel".
 * That channel only exists on Linux — `Elevator.carriesStdin` is false for
 * `osascript` and for Windows' ShellExecute route — so a file the elevated
 * process can read and unlink is the one mechanism that behaves identically on
 * both platforms system mode is open on.
 */
async function launchPrivilegedSidecar(
  run: Run,
  enginePath: string,
  requestedIface: string,
  elevator: Elevator,
  reason: string
): Promise<PrivilegedSidecar> {
  // The socket lives in a fresh 0700 temp directory rather than in the run
  // directory: a unix socket path is capped at ~104 bytes by the kernel, and
  // the run directory sits under `userData`, which on a real machine is
  // already most of that budget. `mkdtemp` creates the directory atomically
  // with 0700, so there is no window where it is world-writable.
  const controlDir = await mkdtemp(join(tmpdir(), 'shellpilot-netd-'))
  await chmod(controlDir, 0o700).catch(() => {})
  const socketPath = join(controlDir, 'c.sock')
  if (socketPath.length > 100) {
    // A unix socket path is capped at 104 bytes on macOS and 108 on Linux, and
    // the failure is an "invalid argument" from bind(2) that surfaces here two
    // minutes later as "never opened its control socket". Said plainly
    // instead, before anything is elevated.
    await rm(controlDir, { recursive: true, force: true }).catch(() => {})
    throw new VpnError(
      'internal',
      `The temporary directory path on this machine is too long for a control socket (${socketPath.length} of about 100 characters). Set TMPDIR to something shorter, or use userspace mode.`
    )
  }
  const noncePath = join(controlDir, 'nonce')
  const nonce = randomBytes(32).toString('hex')
  await writeFile(noncePath, nonce, { mode: 0o600 })
  await chmod(noncePath, 0o600).catch(() => {})

  const cleanupDir = async (): Promise<void> => {
    await rm(controlDir, { recursive: true, force: true }).catch(() => {})
  }

  let proc: ElevatedProcess
  try {
    proc = await elevator.run({
      reason,
      command: enginePath,
      // No secret is on this command line and none ever will be: the private
      // key travels as an `wg.up` request over the authenticated socket.
      args: ['--privileged', '--socket', socketPath, '--nonce-file', noncePath],
      cwd: run.ctx.runDir
    })
  } catch (e) {
    await cleanupDir()
    throw e
  }

  let exit: ElevationExit | null = null
  // Not awaited: on Linux the elevated process is a real child, so `wait()`
  // only resolves when the tunnel ends. It is watched so a declined prompt or
  // an immediate refusal is reported as itself rather than as a connect
  // timeout two minutes later.
  void proc.wait().then((e) => {
    exit = e
  })

  const deadline = wireguardTuning.monoNow() + ELEVATED_CONNECT_TIMEOUT_MS
  let socket: Socket | null = null
  for (;;) {
    if (exit) {
      await cleanupDir()
      throw privilegedExitError(elevator, exit)
    }
    socket = await tryConnect(socketPath)
    if (socket) break
    if (wireguardTuning.monoNow() >= deadline) {
      await proc.kill(true).catch(() => undefined)
      await cleanupDir()
      throw new VpnError(
        'internal',
        'The elevated WireGuard helper never opened its control socket. Nothing was changed on this machine.'
      )
    }
    if (run.stopping) {
      await proc.kill(true).catch(() => undefined)
      await cleanupDir()
      throw new VpnError('internal', 'The tunnel was stopped while it was starting.')
    }
    await sleep(ELEVATED_CONNECT_POLL_MS)
  }

  const live = socket
  const transport: Transport = {
    write: (line) => {
      live.write(line)
    },
    close: async () => {
      await new Promise<void>((resolve) => {
        live.end(() => resolve())
        // A socket whose peer has already gone never fires the callback.
        setTimeout(resolve, 1_000).unref?.()
      })
      live.destroy()
    }
  }

  // Attached before authenticating: the auth response is an ordinary NDJSON
  // response and `send()` is what correlates it.
  const mute = attachSocketReader(run, live)
  run.transport = transport

  try {
    await send(run, 'auth', { nonce })
  } catch (e) {
    // Muted first. A sidecar that refuses the nonce answers and then hangs up,
    // and the hang-up would otherwise race the answer — reporting "the helper
    // stopped" instead of the reason it stopped.
    mute()
    await transport.close().catch(() => undefined)
    await proc.kill(true).catch(() => undefined)
    await cleanupDir()
    run.transport = null
    // The sidecar answers `permission-denied` and exits without saying which
    // part was wrong, which is correct of it and unhelpful here, so this says
    // what it means for the user.
    throw isVpnError(e) && e.code === 'permission-denied'
      ? new VpnError(
          'permission-denied',
          'The elevated WireGuard helper refused this connection. Stop the tunnel and try again.'
        )
      : e
  }

  const sidecar: PrivilegedSidecar = {
    transport,
    ifaceName: '',
    stop: async (opts?: { force?: boolean }) => {
      if (!opts?.force) {
        // Closing the tunnel destroys the TUN device, and a device that goes
        // away takes every route bound to it with it — so this is what makes
        // the kernel finish the cleanup even if the revert below cannot.
        await send(run, 'wg.down', { tunnelId: run.profile.id }).catch(() => undefined)
        await send(run, 'shutdown').catch(() => undefined)
      }
      await transport.close().catch(() => undefined)
      // The sidecar exits when its one connection ends; the kill is the
      // backstop for a wedged one.
      await proc.kill(true).catch(() => undefined)
      await cleanupDir()
    }
  }
  return sidecar
}

/** One connect attempt. A socket that is not there yet is the normal state
 *  while the user is still looking at the elevation prompt, so it resolves
 *  null rather than throwing. */
function tryConnect(path: string): Promise<Socket | null> {
  return new Promise((resolve) => {
    const sock = connect(path)
    const done = (value: Socket | null): void => {
      sock.removeAllListeners('connect')
      sock.removeAllListeners('error')
      if (!value) sock.destroy()
      resolve(value)
    }
    sock.once('connect', () => done(sock))
    sock.once('error', () => done(null))
  })
}

/** Split the socket stream into NDJSON lines and feed them to the same reader
 *  the supervised child's stdout uses. Returns a `mute` that stops it
 *  reporting, for the paths that already have a better answer than "the socket
 *  closed". */
function attachSocketReader(run: Run, sock: Socket): () => void {
  let buffered = ''
  const onData = (chunk: Buffer): void => {
    buffered += chunk.toString('utf8')
    for (;;) {
      const nl = buffered.indexOf('\n')
      if (nl < 0) break
      const line = buffered.slice(0, nl)
      buffered = buffered.slice(nl + 1)
      if (line.trim()) onLine(run, 'stdout', line)
    }
    // A peer that stops sending newlines must not be able to grow this
    // without bound.
    if (buffered.length > 1 << 20) buffered = ''
  }
  let muted = false
  sock.on('data', onData)
  sock.once('close', () => {
    if (run.stopping || muted) return
    // The elevated helper is gone and nothing will answer again. Reported
    // rather than left to a request timeout, which would take 20s per call.
    const err = new VpnError('internal', 'The elevated WireGuard helper stopped.')
    settleAll(run, err)
    publish(run, { state: 'error', error: describeVpnError(err.code, err.detail), errorCode: err.code })
    run.fail(err)
  })
  const mute = (): void => {
    muted = true
    sock.off('data', onData)
  }
  run.detach.push(mute)
  return mute
}

/** What an elevated sidecar that exited before saying anything means. */
function privilegedExitError(elevator: Elevator, exit: ElevationExit): VpnError {
  if (exit.declined) return new VpnError('elevation-declined')
  const mapped = elevationErrorCode(elevator.method, exit.code)
  if (mapped === 'elevation-declined') return new VpnError('elevation-declined')
  if (mapped) return new VpnError(mapped, 'Administrator rights were not available for this launch.')
  switch (exit.code) {
    case NETD_EXIT.setupRefused:
      return new VpnError(
        'permission-denied',
        'The elevated WireGuard helper could not start. It refuses to run without administrator rights, and it cannot create a tunnel device on this machine.'
      )
    case NETD_EXIT.authFailed:
      return new VpnError(
        'permission-denied',
        'The elevated WireGuard helper rejected ShellPilot\'s connection. Stop the tunnel and try again.'
      )
    case NETD_EXIT.badArguments:
      return new VpnError(
        'internal',
        'The bundled WireGuard sidecar does not understand system mode. This build is incomplete.'
      )
    default:
      return new VpnError('internal', `The elevated WireGuard helper exited with code ${exit.code}.`)
  }
}

// -------------------------------------------------------------- system mode

/** Refuse system mode where it cannot work, before anything is elevated and
 *  before any snapshot is taken. Returns normally where it can. */
function guardSystemMode(platform: NodeJS.Platform): void {
  // E02 first, because it is the specific reason and the generic one would
  // otherwise swallow it: there is no Developer ID for this project, so
  // `SMJobBless` is impossible and a per-launch `osascript` prompt cannot
  // carry the control channel either.
  if (platform === 'darwin') throw new VpnError('unsupported', DARWIN_SYSTEM_MODE)
  if (!sidecarHasPrivilegedMode(platform)) throw new VpnError('unsupported', NO_PRIVILEGED_BUILD)
}

// A full-tunnel profile needs the connection to the peer itself kept OUT of
// the tunnel — otherwise the encrypted packets carrying the tunnel match the
// route they created and loop. Real clients solve it with a firewall mark and
// a policy-routing rule (`wg-quick`) or a host route to the server via the old
// gateway. ShellPilot does neither yet, and bringing a full tunnel up without
// it would take the machine off the network until the profile is stopped.
//
// So it is refused, by name, rather than attempted. Split-tunnel system mode —
// the common corporate case — is unaffected.
const FULL_TUNNEL_SYSTEM_MODE =
  'This profile routes all traffic (0.0.0.0/0 or ::/0), which system mode cannot do safely yet: ShellPilot cannot keep the connection to the VPN server itself outside the tunnel, so bringing it up would take this machine off the network. Use userspace mode, or list only the ranges you need in AllowedIPs.'

/** The routes a system-mode tunnel would claim: one per distinct allowed
 *  prefix, all pointed at the tunnel interface. */
export function systemRoutes(spec: WireGuardSpec, interfaceName: string): RouteSpec[] {
  const seen = new Set<string>()
  const routes: RouteSpec[] = []
  for (const peer of spec.peers ?? []) {
    for (const raw of peer.allowedIps ?? []) {
      const destination = raw.trim()
      if (!destination || seen.has(destination)) continue
      seen.add(destination)
      routes.push({ destination, interfaceName })
    }
  }
  return routes
}

/** Interface names are not free-form: Linux caps them at 15 characters and
 *  Windows shows them to the user in `ncpa.cpl`. */
export function systemInterfaceName(profileId: string, platform: NodeJS.Platform): string {
  const short = profileId.replace(/[^A-Za-z0-9]/g, '').slice(0, 8) || 'wg'
  if (platform === 'win32') return `ShellPilot ${short}`
  return `wg-${short}`.slice(0, 15)
}

/**
 * The elevation seam, as an ordinary `NetApplyContext`.
 *
 * `supportsStdin` is false and says so out loud: no elevation helper on any
 * platform can hand a stdin payload to the elevated child — macOS puts the
 * whole command line inside `osascript`'s own argv, and Windows' ShellExecute
 * has no pipe at all. A DNS backend that needs stdin (macOS `scutil`) must
 * therefore report `unsupported` rather than run a command that silently does
 * nothing and reports success.
 */
export function elevatedNetContext(
  runId: string,
  runDir: string,
  elevator: Elevator,
  reason: string
): NetApplyContext {
  return {
    runId,
    runDir,
    supportsStdin: false,
    async runPrivileged(cmd: string, args: string[], opts?: { stdin?: string }) {
      if (opts?.stdin !== undefined) {
        throw new VpnError(
          'unsupported',
          'This change needs to send data to an administrator command over stdin, which no elevation prompt can carry.'
        )
      }
      const proc = await elevator.run({ reason, command: cmd, args, cwd: runDir })
      const exit = await proc.wait()
      // A dismissed prompt is the user answering the question, not a fault,
      // and never a reason to try again on their behalf (E04).
      if (exit.declined) throw new VpnError('elevation-declined')
      return { code: exit.code ?? -1, stdout: '', stderr: '' }
    }
  }
}

export interface SystemNetworkingResult {
  state: NetStateFile
  ctx: NetApplyContext
  warnings: RouteConflict[]
}

/**
 * Everything system mode does to this machine, in the only order that is safe:
 * refuse what cannot work, ask for rights once, look for conflicts, bring the
 * interface up, snapshot, and only then change anything.
 *
 * The conflict check happens **before** the interface exists, which is the
 * whole reason `bringUpInterface` is a callback rather than something the
 * caller does first. A prefix another VPN already owns is a refusal, and a
 * refusal that arrives after an elevation prompt and a live tunnel device is a
 * refusal that has already cost the user something.
 *
 * `bringUpInterface` returns the name the KERNEL chose. Everything downstream
 * — every route, the resolver change, the snapshot that reverts them — is
 * addressed to that name and never to the name that was asked for. On macOS
 * the two are never the same (the kernel allocates the utun number), and
 * guessing `utun4` is how system mode ends up routing nothing.
 *
 * Snapshotting happens inside `applyNetState`, before the first route is
 * written and after nothing — a snapshot taken after the change records the
 * change as the original state, which is how a "restore" ends up restoring the
 * broken configuration. The record it writes is what makes `kill -9`
 * survivable: `restoreOrphanedNetstate` finds it on the next launch and puts
 * the routes and the resolver back even though the process that changed them
 * is long gone.
 */
export async function applySystemNetworking(
  profile: VpnProfile & { spec: WireGuardSpec },
  ctx: VpnDriverContext,
  runId: string,
  deps: {
    platform?: NodeJS.Platform
    elevator?: Elevator
    routeManager?: Pick<RouteManager, 'conflicts'>
    /** Injectable only so a test can assert what this asks for without
     *  rewriting the host's route table to find out. */
    applyNet?: typeof applyNetState
    netStateRoot?: string
    /** Creates the tunnel device and answers with the interface name the
     *  kernel actually gave it. Called after the conflict check and before
     *  anything is snapshotted or applied. Absent — as it is in every test
     *  that only cares about the networking half — means "assume the planned
     *  name", which is exactly what the old, device-less code did. */
    bringUpInterface?: (planned: string) => Promise<string>
  } = {}
): Promise<SystemNetworkingResult> {
  const platform = deps.platform ?? platformNow()
  if (platform === 'darwin') throw new VpnError('unsupported', DARWIN_SYSTEM_MODE)

  const elevator = deps.elevator ?? wireguardTuning.elevator ?? elevatorForPlatform(platform)
  const probe = await elevator.probe()
  if (!probe.available) throw new VpnError('unsupported', probe.reason)

  const planned = systemInterfaceName(profile.id, platform)
  const plannedRoutes = systemRoutes(profile.spec, planned)
  if (claimsDefault(plannedRoutes, 'inet') || claimsDefault(plannedRoutes, 'inet6')) {
    throw new VpnError('unsupported', FULL_TUNNEL_SYSTEM_MODE)
  }

  const conflicts = await (deps.routeManager ?? routeManagerFor(platform)).conflicts(plannedRoutes)
  const claimed = conflicts.filter((c) => c.kind === 'prefix-claimed')
  if (claimed.length > 0) {
    // Refused rather than applied. Two VPNs claiming one prefix is a coin toss
    // decided by metric order, and the loser is whichever the user needed.
    throw new VpnError('interface-conflict', claimed.map((c) => c.message).join(' '))
  }
  const warnings = conflicts.filter((c) => c.kind === 'ipv6-leak')
  for (const w of warnings) {
    // A warning, not a refusal: a v4-only tunnel is a legitimate thing to run,
    // and refusing it would stop people using profiles that work fine.
    ctx.log(w.message, 'app')
  }

  // Only now, with the conflicts cleared, is a device created — and with it,
  // on the real path, the elevation prompt.
  const interfaceName = deps.bringUpInterface ? (await deps.bringUpInterface(planned)).trim() : planned
  if (!interfaceName) {
    throw new VpnError('internal', 'The WireGuard sidecar did not report an interface name.')
  }
  // Recomputed against the real name rather than patched: `plannedRoutes` was
  // only ever a question for the conflict check.
  const routes = systemRoutes(profile.spec, interfaceName)

  const netCtx = elevatedNetContext(
    runId,
    ctx.runDir,
    elevator,
    `ShellPilot needs administrator rights to route "${profile.name}" through a system network interface.`
  )

  const dns: DnsSpec | undefined =
    (profile.spec.dns ?? []).length > 0
      ? { servers: profile.spec.dns, searchDomains: [], interfaceName }
      : undefined

  const apply = deps.applyNet ?? applyNetState
  const state = await apply({ interfaceName, routes, dns }, netCtx, { platform, root: deps.netStateRoot })
  return { state, ctx: netCtx, warnings }
}

// --------------------------------------------------------------------- misc

function describe(e: unknown): string {
  if (isVpnError(e)) return describeVpnError(e.code, e.detail)
  return e instanceof Error ? e.message : String(e)
}

/** `--version` answers with one line of JSON on stdout, because stdout is
 *  protocol-only for this binary and a bare version string would be the one
 *  exception. The manifest usually carries the version already; this is the
 *  fallback, and it is what keeps `{"version":"0.4.4",…}` out of the UI. */
export function parseNetdVersion(raw: string | undefined): string | undefined {
  if (!raw) return undefined
  const t = raw.trim()
  if (!t.startsWith('{')) return t
  try {
    const parsed = JSON.parse(t) as { version?: unknown; buildSha?: unknown }
    if (typeof parsed.version !== 'string') return undefined
    return typeof parsed.buildSha === 'string' && parsed.buildSha !== 'unknown'
      ? `${parsed.version} (${parsed.buildSha})`
      : parsed.version
  } catch {
    return undefined
  }
}

export const wireguardDriver: VpnDriver<WireGuardSpec> = {
  kind: 'wireguard',

  validateConfig(spec: WireGuardSpec): VpnValidation {
    return validateWireGuardSpec(spec)
  },

  async probe(): Promise<VpnEngineInfo> {
    try {
      const info = await resolveBundled(NETD)
      return { ...info, version: parseNetdVersion(info.version) }
    } catch (e) {
      // A missing or tampered binary is a state the UI shows, not an exception
      // it has to handle. `resolveBundled` throws so nothing can mistake a
      // tampered binary for an absent one; this is where that turns into text.
      if (!isVpnError(e)) throw e
      return {
        kind: 'wireguard',
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

  async stats(id: string): Promise<VpnStats | null> {
    const run = runs.get(id)
    if (!run || !run.transport || run.stopping) return null
    let raw: NetdStatsResult
    try {
      raw = await send<NetdStatsResult>(run, 'wg.stats', { tunnelId: id })
    } catch {
      // Between a restart's exit and its next `wg.up` there is nothing to ask.
      // That is not a statistic worth an error dialog.
      return null
    }
    const stats = toStats(run, raw)
    const state = stateFromHandshakeAge(stats.lastHandshakeSec)
    publish(run, {
      state,
      stats,
      error: state === 'degraded' ? describeVpnError('handshake-timeout', staleDetail(run, raw.remoteEndpoint)) : undefined,
      errorCode: state === 'degraded' ? 'handshake-timeout' : undefined
    })
    return stats
  },

  openForward,

  // `reload` is intentionally absent. Changing a peer or an address means a
  // new device: netd's wg.up replaces rather than merges, so the manager's
  // stop-then-start is both what would happen anyway and the honest way to
  // show it in the UI.

  async reap(): Promise<void> {
    // Nothing engine-specific to sweep in userspace mode: netd creates no
    // interface and changes no route, so an orphan is a process and a run
    // directory, both of which the supervisor's identity-checked reaper
    // already owns — and a netd whose parent died sees stdin EOF and exits on
    // its own.
    //
    // Nothing to sweep in system mode either, and for the same reason wearing
    // different clothes: an elevated netd serves exactly one connection and
    // exits when it ends, so a `kill -9` of the app closes the socket, the
    // sidecar exits, the TUN device goes away and every route bound to it goes
    // with it. What can outlive that is the resolver change, which is
    // `restoreOrphanedNetstate`'s job and runs from the manager before any
    // driver starts. This exists to drop in-process state, which matters when
    // the app restarts inside one process during development.
    runs.clear()
  },

  async disposeAll(): Promise<void> {
    // Best effort and raced against a quit timeout by the caller, so each stop
    // is allowed to fail without stranding the ones after it.
    await Promise.allSettled([...runs.keys()].map((id) => stop(id)))
    runs.clear()
  }
}
