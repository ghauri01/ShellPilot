import type {
  VpnEngineInfo,
  VpnErrorCode,
  VpnKind,
  VpnProfile,
  VpnPrompt,
  VpnResult,
  VpnSpec,
  VpnStartResult,
  VpnStats,
  VpnStatus,
  VpnValidation
} from '../../../shared/vpn'
import type { Supervisor } from './supervisor'

// Plaintext, resolved from the vault immediately before a start and dropped
// when it ends. Main-process only: never logged, never emitted over IPC, never
// placed in argv.
export interface ResolvedVpnSecrets {
  privateKey?: string
  // Keyed by peer public key.
  presharedKeys?: Record<string, string>
  username?: string
  password?: string
  keyPassphrase?: string
  token?: string
  // The whole sanitised .ovpn body.
  configBody?: string
  // Keyed by proxy name.
  proxySecretKeys?: Record<string, string>
  // Every literal above, flattened, for the log redactor. Populated by the
  // resolver so each driver does not have to remember to build it.
  all: string[]
}

export interface VpnDriverContext {
  // A 0700 scratch directory unique to this run, swept at startup and removed
  // on stop.
  runDir: string
  secrets: ResolvedVpnSecrets
  // Coalesced and change-detected by the manager before it reaches IPC.
  emit(patch: Partial<VpnStatus>): void
  // Already through redactOutput(); goes to the bounded ring buffer.
  log(line: string, stream: 'stdout' | 'stderr' | 'ctl' | 'app'): void
  // The engine went down on its own — a crash loop, a terminal exit, a control
  // channel that closed while connected.
  //
  // This exists because `emit({state:'error'})` is not enough and every driver
  // assumed it was. Emitting only updates the status bus: the manager still
  // holds the Live entry, its run directory, its resolved plaintext secrets,
  // and every SSH/DB registration for sessions whose forwards are already
  // gone — so `hasLiveVpnDependents` then lies to the stop confirmation and to
  // the MCP policy check. Call this instead of, not as well as, emitting the
  // error; the manager emits it.
  dropped(reason: string, errorCode?: VpnErrorCode): void
  // Resolves to null when the user cancels, which is a normal outcome and not
  // an error.
  askUser(p: Omit<VpnPrompt, 'id' | 'profileId' | 'profileName'>): Promise<string | null>
  // Drivers never touch child_process directly; everything goes through here
  // so backoff, crash-loop detection, log capture and orphan reaping apply
  // uniformly.
  supervisor: Supervisor
}

export interface VpnDriver<S extends VpnSpec = VpnSpec> {
  readonly kind: VpnKind

  /** Pure and synchronous: no I/O, no secrets. Safe to call from a form on
   *  every keystroke. */
  validateConfig(spec: S): VpnValidation

  /** Locate and integrity-check the engine. Cached for the app run. Never
   *  spawns a profile. */
  probe(): Promise<VpnEngineInfo>

  start(profile: VpnProfile & { spec: S }, ctx: VpnDriverContext): Promise<VpnStartResult>

  /** Graceful by default: control channel first, then signals. `force` skips
   *  straight to a kill. */
  stop(id: string, opts?: { force?: boolean }): Promise<void>

  status(id: string): VpnStatus | null

  stats(id: string): Promise<VpnStats | null>

  /** Apply a changed spec without dropping the connection. frp only today.
   *  Absent means the manager does a stop then a start. */
  reload?(id: string, spec: S): Promise<VpnResult>

  /** Userspace mode only: an ephemeral 127.0.0.1 listener forwarding into the
   *  tunnel. The shape is deliberately identical to `openEphemeralForward` in
   *  ../tunnel.ts so db.ts can consume either without branching. */
  openForward?(id: string, host: string, port: number): Promise<{ port: number; close: () => void }>

  /** Called once at app start, before any profile runs: sweep this engine's
   *  orphans from a previous run. */
  reap?(): Promise<void>

  /** Called on app quit. Best-effort, raced against a hard timeout. */
  disposeAll?(): Promise<void>
}
