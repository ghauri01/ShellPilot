// Live log tailing across hosts.
//
// The Fleet Monitor now says a unit failed. This is "why", which is always the
// next question and currently costs opening a terminal, remembering the unit
// name, and typing journalctl — per host.
//
// Two decisions shape the rest:
//
// 1. The remote command is BUILT here, never taken from the user. A tail is a
//    read, and the moment a caller can pass arbitrary text the feature becomes
//    "run anything on N hosts" with none of the confirmation broadcast has.
//    Unit names and paths are validated against the shapes systemd and POSIX
//    actually permit, and anything else is refused rather than escaped —
//    escaping is a promise about a shell we do not control.
// 2. Lines carry their host. An interleaved stream where you cannot tell which
//    machine said what is worse than four separate tails, because it looks
//    authoritative.

export type LogSourceKind = 'unit' | 'file'

export interface LogSource {
  kind: LogSourceKind
  /** Unit name (`nginx.service`) or absolute path (`/var/log/syslog`). */
  target: string
}

export interface LogLine {
  tailId: string
  serverId: string
  serverName: string
  /** Monotonic per host, so the UI can key rows without hashing content. */
  seq: number
  text: string
  /** stderr from the remote command — a missing file, a denied read. */
  isError?: boolean
  at: number
}

export interface LogTailState {
  tailId: string
  serverId: string
  serverName: string
  state: 'starting' | 'streaming' | 'ended' | 'failed'
  error?: string
}

/** How many lines the renderer keeps per tail before dropping the oldest. */
export const LOG_RING = 2_000
/** Lines from a single host per second before we start dropping, with a notice. */
export const LOG_RATE_PER_SEC = 500

// systemd unit names: alphanumerics and `-_.\@:` plus an optional suffix. This
// is deliberately the permissive-but-bounded set rather than a full grammar —
// what matters is that nothing here can end a shell word.
const UNIT_RE = /^[A-Za-z0-9@._:\\-]{1,128}$/
// Absolute paths only, no shell metacharacters, no traversal. A relative path
// would resolve against whatever directory the exec channel happens to start
// in, which is not a thing the user can reason about.
const PATH_RE = /^\/[A-Za-z0-9/._@:+-]{1,255}$/

export function validateLogSource(source: LogSource): { ok: true } | { ok: false; error: string } {
  const t = source.target.trim()
  if (t === '') return { ok: false, error: 'Give a unit name or a log file path.' }
  if (source.kind === 'unit') {
    if (!UNIT_RE.test(t)) {
      return { ok: false, error: 'That is not a unit name. Letters, digits and - _ . @ : only.' }
    }
    return { ok: true }
  }
  if (!t.startsWith('/')) return { ok: false, error: 'Use an absolute path, starting with /.' }
  if (t.includes('..')) return { ok: false, error: 'Paths with .. are refused.' }
  if (!PATH_RE.test(t)) return { ok: false, error: 'That path contains characters this will not pass to a shell.' }
  return { ok: true }
}

/**
 * The remote command for a source.
 *
 * Never interpolates unvalidated text: callers must run `validateLogSource`
 * first, and `buildTailCommand` throws rather than producing a command from
 * input it has not checked. A function that quietly returns a broken command
 * is how a validator gets skipped once and forgotten.
 *
 * `journalctl` gets `--no-pager -n` so the first screen is history rather than
 * an empty pane that only fills when something new happens — the failure being
 * investigated has usually already happened.
 */
export function buildTailCommand(source: LogSource, historyLines = 200): string {
  const v = validateLogSource(source)
  if (!v.ok) throw new Error(`refusing to build a command from an invalid source: ${v.error}`)
  const t = source.target.trim()
  if (source.kind === 'unit') {
    return `journalctl --no-pager --output=short-iso -n ${historyLines} -f -u ${t} 2>&1`
  }
  // -F rather than -f: a rotated file is the normal case on a log, and -f
  // silently follows the old inode forever after logrotate runs.
  return `tail -n ${historyLines} -F ${t} 2>&1`
}
