// Supervised local processes — roadmap item 1, the LOCAL half.
//
// "Run, watch, restart and read the logs of a long-lived process": a dev
// server, a worker, a one-off script that should not die when the terminal
// does. The vocabulary lives here, in `shared`, because the renderer has to
// name the same things main does.
//
// ===========================================================================
// ALMOST NONE OF THE HARD PART IS HERE, AND THAT IS THE POINT
// ===========================================================================
//
// The engine is `src/main/services/vpn/supervisor.ts`, which was written to
// keep VPN engines alive and already implements the whole of pm2's core:
// exponential backoff with jitter, crash-loop detection over a rolling window,
// restart policies, readiness probes, optional periodic health checks, a
// bounded log ring, pid records that survive an app restart, and orphan
// reaping on launch. `SupervisedSpec` is a description of a CHILD PROCESS that
// happened to be used for tunnels.
//
// So this item is a lift. What is new is a persistent list, a UI, and the
// judgement written down below about what such a list may and may not do.
//
// ===========================================================================
// THE REMOTE HALF IS NOT HERE, AND IT IS NOT "NOT YET"
// ===========================================================================
//
// Stated the way `src/shared/docker.ts` states its refusal to ship `prune`,
// because the shape is the same: a named absence with a falsifiable reason and
// a description of what would have to be true instead.
//
//   * RUNNING A SUPERVISED PROCESS ON A REMOTE HOST, in every spelling — an
//     agent-side runner over an SSH channel this app holds open, a `screen`
//     or `tmux` session it reattaches to, a nohup'd child whose pid it
//     remembers.
//
//     The supervisor spawns LOCALLY. Everything above — the pid record, the
//     identity probe, the reaper, the log ring fed from stdout — is a
//     statement about processes on this machine. Making it remote is not a
//     matter of swapping `spawn` for `ssh`, because the guarantees would not
//     survive the swap: a restart policy is a promise to be there when the
//     child dies, and this app is not there when the laptop lid closes.
//
//     The objection is falsifiable rather than a preference: **shipping "we
//     run your process over an SSH channel we hold open" is a promise about
//     reliability the current transport does not make.** The transport
//     reconnects for interactive work and for polling; it does not guarantee
//     continuity across a suspend, a network change or a VPN flap, and every
//     one of those is a moment at which a supervised remote process would
//     either be silently unsupervised or silently restarted twice.
//
//     There are two honest answers and this file implements neither:
//
//       1. TRANSLATE, do not supervise — write a `systemd --user` unit or a
//          launchd plist on the host and let the host's own supervisor own the
//          restart policy. The host is there when we are not. This is the one
//          worth doing, and it is a different feature: what ShellPilot would
//          ship is a unit-file editor and a `systemctl --user` reader, not a
//          supervisor.
//       2. An agent-side runner. A real design, and a real decision about
//          shipping a binary onto other people's servers.
//
//     What a future remote half must NOT do is hold a channel open, and the
//     reason it must not is now stronger than when the roadmap was written:
//     THE JOB ENGINE ALREADY SOLVED DETACHED REMOTE EXECUTION for one-shot
//     work. `src/shared/jobs.ts` and `src/main/services/jobDetached.ts` run a
//     step on a host in a way that survives the link that started it and is
//     re-adopted afterwards from a durable record. A remote supervisor should
//     be built on that — a detached runner plus a record to adopt — rather
//     than on a socket somebody hopes stays up. Building the socket version
//     first would mean two mechanisms for the same problem, one of which
//     already works.
//
//   * AUTO-START ON LAUNCH. pm2 has `resurrect` and this deliberately does
//     not. What survives a restart is the LIST; what does not is anything
//     running. A stored command is arbitrary local code execution, and an app
//     that runs one before a human has looked at the screen is an app whose
//     start-up is defined by a file. Starting is a button, every time.
//
//     This is also what keeps the list honest as a piece of data: nothing in
//     it executes by existing.
//
// ===========================================================================
// WHERE THE LIST LIVES, AND WHY NOT WITH EVERYTHING ELSE
// ===========================================================================
//
// Not in `shellpilot-data.json`. That file is the renderer-owned blob — the
// workspaces, servers, folders and tunnels the renderer edits and hands back
// to main as one snapshot — and it is also the export/backup payload. A
// process definition is a command line that will be executed on this machine.
// Two things follow, and both point the same way:
//
//   * A COMMAND THAT RUNS ON THIS MACHINE DOES NOT BELONG IN AN EXPORTED
//     BACKUP. Restoring a backup would then be "and also here are some
//     programs to run", from a file that gets mailed around.
//   * MAIN OWNS IT, NOT THE RENDERER. The renderer never sends the list back;
//     it sends one edit at a time and main re-narrows every field.
//
// It gets its own file beside the vault and the rule file, written
// temp-then-rename at 0600 — see `readProcessFile` / `writeProcessFile` in
// `src/main/services/processes.ts`.
//
// ===========================================================================
// AN AGENT CANNOT REACH ANY OF THIS
// ===========================================================================
//
// Same argument as the job engine's, one notch sharper. DURABILITY DEFEATS
// REVOCATION: `denyAllPending()` — the stop-all-AI-access switch — works by
// resolving requests that are PENDING, and a supervised process has nothing
// pending. It is a child of this app with a restart policy, so denying every
// outstanding approval and revoking every session leaves it running AND leaves
// the supervisor ready to start it again when it exits. There is no request to
// deny and no channel whose closure reaches it.
//
// It is also strictly more powerful than a job: a job runs a command on a
// remote host under a credential that could be rotated, and this runs a
// command on the machine the vault is on. See `tests/jobsNotExposed.test.ts`,
// which holds it out of the bridge by import closure, by vocabulary and by
// literal symbol name.

// --------------------------------------------------------------------- caps

/** How many processes one install may hold. Not a resource limit — it is a cap
 *  on how much arbitrary local code execution one JSON file can describe. */
export const MAX_PROCESSES = 50

/** The supervisor's log ring, sized for this consumer.
 *
 *  A crash-looping process is a log FLOOD, and both halves matter: the line cap
 *  keeps the drawer scrollable and the byte cap is the actual bound, because one
 *  4 MB stack trace sits happily inside a 2000-line cap. */
export const PROCESS_LOG_RING = { maxLines: 2_000, maxBytes: 1 << 20 } as const

/** The most lines one `logs()` call may return, whatever the caller asks for.
 *
 *  The ring is bounded, so this is not what stops main growing — it is what
 *  stops a crash loop being repainted a megabyte at a time in the renderer. */
export const PROCESS_LOG_PAGE = 500

/** Backoff between restarts. Jittered for the reason the supervisor jitters
 *  everything: several processes pointed at the same dead port would otherwise
 *  retry in lockstep. */
export const PROCESS_BACKOFF = { baseMs: 1_000, maxMs: 60_000, jitter: 0.3 } as const

/** Six exits in a minute is a process that is not going to start. Stopping and
 *  saying so beats respawning it until someone notices the fan. */
export const PROCESS_CRASH_LOOP = { windowMs: 60_000, maxRestarts: 6 } as const

export const PROCESS_NAME_MAX = 60
export const PROCESS_ARG_MAX = 4_000
export const PROCESS_ARGS_MAX = 64
export const PROCESS_ENV_MAX = 64
export const PROCESS_ENV_KEY_MAX = 128
export const PROCESS_ENV_VALUE_MAX = 4_000
export const PROCESS_READY_PATTERN_MAX = 200
export const PROCESS_READY_TIMEOUT_MIN_MS = 1_000
export const PROCESS_READY_TIMEOUT_MAX_MS = 600_000

// ------------------------------------------------------------------- shapes

export type ProcessRestartPolicy = 'never' | 'on-failure' | 'always'

/**
 * When a run counts as up.
 *
 * `spawned` is honest about what it knows: the child exists. `log` waits for a
 * line, which is how every dev server announces itself.
 *
 * `pattern` is a SUBSTRING, never a regular expression, and that is a security
 * decision rather than a simplification. A user-supplied regex evaluated
 * against every line a process writes is a ReDoS primitive with an attacker —
 * or an accident — on both ends of it: the pattern comes from a text box and
 * the input is unbounded output from a program. `String.includes` cannot
 * backtrack.
 */
export type ProcessReadiness =
  | { kind: 'spawned' }
  | { kind: 'log'; pattern: string; timeoutMs: number }

/**
 * One environment variable.
 *
 * A literal, or a reference to a vault entry resolved at start time and never
 * stored. The split is the same one `CredProxyRule` makes and for the same
 * reason: the value is fetched when it is needed, lives as long as the spawn,
 * and nothing here holds a copy of it after the vault re-locks.
 *
 * A literal whose KEY looks like a secret is refused — see
 * `PROCESS_SECRET_KEY_RX`. There is no setting that allows it.
 */
export type ProcessEnvVar =
  | { key: string; kind: 'literal'; value: string }
  | { key: string; kind: 'vault'; vaultEntryId: string; slot: ProcessEnvSlot; fieldKey?: string }

/** Which slot of a vault entry holds the value. Mirrors `CredProxySlot`. */
export type ProcessEnvSlot = 'password' | 'privateKey' | 'username' | 'field'

/** A process as it is stored. */
export interface ManagedProcess {
  id: string
  name: string
  command: string
  /** Never a secret. `ps` is world-readable, so a value put here is a value
   *  published to every account on this machine — which is why there is no
   *  vault reference in this list and never will be. Secrets go in `env`. */
  args: string[]
  cwd: string
  env: ProcessEnvVar[]
  restart: ProcessRestartPolicy
  readiness: ProcessReadiness
  createdAt: string
}

/**
 * A process as the RENDERER sees it.
 *
 * `env` carries keys and where each value comes from. It never carries a
 * value, literal or resolved — not to be shown, not to be edited, not to
 * round-trip through an IPC message. Editing a value is "replace this one",
 * which needs no read.
 */
export interface ManagedProcessView {
  id: string
  name: string
  command: string
  args: string[]
  cwd: string
  env: ProcessEnvKeyView[]
  restart: ProcessRestartPolicy
  readiness: ProcessReadiness
  createdAt: string
}

export interface ProcessEnvKeyView {
  key: string
  source: 'literal' | 'vault'
  /** Present for a vault reference, so the panel can say which entry. Never
   *  the value in it. */
  vaultEntryId?: string
  slot?: ProcessEnvSlot
  fieldKey?: string
}

export type ProcessState =
  | 'stopped'
  | 'starting'
  | 'running'
  /** The crash-loop detector tripped. Not 'stopped': the difference between
   *  "you stopped it" and "it would not stay up" is the whole message. */
  | 'crash-looped'
  /** It exited terminally, or it never started. */
  | 'failed'

export interface ProcessStatus {
  id: string
  state: ProcessState
  /** The pid running right now, or 0 between attempts and when stopped. */
  pid: number
  restarts: number
  startedAt?: number
  /** Why it is not running, in a sentence a person can act on. Already
   *  translated out of the supervisor's VPN prose. */
  error?: string
  lastExitCode?: number | null
  lastExitSignal?: string | null
}

/** Structurally the supervisor's `SupervisedLogLine`. Redeclared rather than
 *  imported because `shared` may not reach into `main`. */
export interface ProcessLogLine {
  at: number
  stream: 'stdout' | 'stderr' | 'ctl' | 'app'
  text: string
}

/** The file, as it is written. Versioned because it holds command lines that
 *  will be executed, and those have to keep meaning what they meant. */
export interface ProcessesFile {
  v: 1
  processes: unknown[]
}

/** What the renderer sends to create or replace one. No `id` and no
 *  `createdAt`: main mints both. */
export interface ProcessDraft {
  name: string
  command: string
  args: string[]
  cwd: string
  env: ProcessEnvVar[]
  restart: ProcessRestartPolicy
  readiness: ProcessReadiness
}

// -------------------------------------------------------------- the refusals

/**
 * Environment variable names that may not hold a literal.
 *
 * Deliberately the same vocabulary as the first rule in
 * `services/secretRedaction.ts`, so a value this refuses to store is a value
 * that would have been scrubbed out of the logs anyway. Matching the name
 * rather than the value is the only check available before the value exists,
 * and it catches the case that actually happens: somebody pastes a token into
 * the box labelled `DATABASE_PASSWORD`.
 *
 * The point is not that a clever name defeats it. The point is that the
 * ordinary path — the one a person takes without thinking about it — ends at
 * the vault rather than at a JSON file, and that the alternative is one click
 * away rather than a feature request.
 */
export const PROCESS_SECRET_KEY_RX =
  /(PASSWORD|PASSWD|PASSPHRASE|SECRET|TOKEN|API_?KEY|PRIVATE_?KEY|CREDENTIAL|ACCESS_?KEY)/i

export const PROCESS_SECRET_LITERAL_REFUSAL =
  'That looks like a secret, so it cannot be stored as a plain value. Add it to the vault and ' +
  'reference the entry instead — the value is then read when the process starts and never ' +
  'written to disk here.'

/**
 * The supervisor's error codes, in this feature's words.
 *
 * The supervisor throws `VpnError`, whose prose says "tunnel" — "The tunnel
 * program kept exiting, so it was stopped." Showing that for a dev server is a
 * bug report nobody can act on, and broadening the VPN messages so they no
 * longer say "tunnel" would make every VPN failure vaguer to make one
 * non-VPN failure clearer. So it is translated on the way out, here, where the
 * renderer can see the mapping.
 */
export const PROCESS_FAILURE_MESSAGE: Record<string, string> = {
  'binary-missing': 'That program could not be found, so nothing was started.',
  'handshake-timeout': 'It started but never became ready, so it was stopped.',
  'crash-loop': 'It kept exiting, so it was stopped rather than restarted again.',
  internal: 'It stopped unexpectedly.'
}

export function processFailureMessage(code: string | undefined, detail?: string): string {
  const base = (code && PROCESS_FAILURE_MESSAGE[code]) || PROCESS_FAILURE_MESSAGE.internal
  return detail ? `${base} ${detail}` : base
}

// ---------------------------------------------------------------- narrowing

const str = (v: unknown): string => (typeof v === 'string' ? v : '')
const trimmed = (v: unknown, max: number): string => str(v).trim().slice(0, max)

function sanitiseEnvVar(raw: unknown): ProcessEnvVar | null {
  if (!raw || typeof raw !== 'object') return null
  const r = raw as Record<string, unknown>
  const key = trimmed(r.key, PROCESS_ENV_KEY_MAX)
  // POSIX names, plus the leading-digit rule. A key that needs a quote is a key
  // that would be passed to a shell somewhere, and nothing here has a shell.
  if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(key)) return null
  if (r.kind === 'vault') {
    const vaultEntryId = trimmed(r.vaultEntryId, 200)
    const slot = r.slot
    if (!vaultEntryId) return null
    if (slot !== 'password' && slot !== 'privateKey' && slot !== 'username' && slot !== 'field') {
      return null
    }
    const fieldKey = trimmed(r.fieldKey, PROCESS_ENV_KEY_MAX)
    if (slot === 'field' && !fieldKey) return null
    return slot === 'field'
      ? { key, kind: 'vault', vaultEntryId, slot, fieldKey }
      : { key, kind: 'vault', vaultEntryId, slot }
  }
  if (r.kind !== 'literal') return null
  // The refusal, applied on the way IN as well as at creation: a file edited by
  // hand is exactly as hostile as an IPC message.
  if (PROCESS_SECRET_KEY_RX.test(key)) return null
  return { key, kind: 'literal', value: str(r.value).slice(0, PROCESS_ENV_VALUE_MAX) }
}

function sanitiseReadiness(raw: unknown): ProcessReadiness | null {
  if (!raw || typeof raw !== 'object') return null
  const r = raw as Record<string, unknown>
  if (r.kind === 'spawned') return { kind: 'spawned' }
  if (r.kind !== 'log') return null
  const pattern = trimmed(r.pattern, PROCESS_READY_PATTERN_MAX)
  if (!pattern) return null
  const raw2 = typeof r.timeoutMs === 'number' && Number.isFinite(r.timeoutMs) ? r.timeoutMs : 0
  const timeoutMs = Math.min(
    PROCESS_READY_TIMEOUT_MAX_MS,
    Math.max(PROCESS_READY_TIMEOUT_MIN_MS, Math.round(raw2))
  )
  return { kind: 'log', pattern, timeoutMs }
}

/** One stored process, narrowed from whatever was on disk or on the wire.
 *  Returns null rather than throwing: a row that will not narrow is a row that
 *  is dropped, and dropping one must not lose the other forty-nine. */
export function sanitiseProcess(raw: unknown): ManagedProcess | null {
  if (!raw || typeof raw !== 'object') return null
  const r = raw as Record<string, unknown>
  const id = trimmed(r.id, 200)
  const name = trimmed(r.name, PROCESS_NAME_MAX)
  const command = trimmed(r.command, PROCESS_ARG_MAX)
  const cwd = trimmed(r.cwd, PROCESS_ARG_MAX)
  if (!id || !name || !command || !cwd) return null

  const args = (Array.isArray(r.args) ? r.args : [])
    .slice(0, PROCESS_ARGS_MAX)
    .filter((a): a is string => typeof a === 'string')
    .map((a) => a.slice(0, PROCESS_ARG_MAX))

  // Last-writer-wins on a duplicate key, because that is what actually
  // happens downstream: the list becomes a Record before it reaches `spawn`,
  // and the later entry overwrites the earlier one. Keeping both here would
  // leave which one applies up to an object spread three files away, and
  // showing the user the one that does NOT apply is worse than dropping it.
  const byKey = new Map<string, ProcessEnvVar>()
  for (const e of (Array.isArray(r.env) ? r.env : []).slice(0, PROCESS_ENV_MAX)) {
    const v = sanitiseEnvVar(e)
    if (v) byKey.set(v.key, v)
  }
  const env: ProcessEnvVar[] = [...byKey.values()]

  const readiness = sanitiseReadiness(r.readiness) ?? { kind: 'spawned' }
  const restart =
    r.restart === 'always' || r.restart === 'never' || r.restart === 'on-failure'
      ? r.restart
      : 'on-failure'
  const createdAt = trimmed(r.createdAt, 40) || new Date(0).toISOString()

  return { id, name, command, args, cwd, env, restart, readiness, createdAt }
}

export function sanitiseProcesses(raw: unknown): ManagedProcess[] {
  const list = raw && typeof raw === 'object' ? (raw as Record<string, unknown>).processes : null
  if (!Array.isArray(list)) return []
  const out: ManagedProcess[] = []
  const ids = new Set<string>()
  for (const row of list) {
    const p = sanitiseProcess(row)
    if (!p || ids.has(p.id)) continue
    ids.add(p.id)
    out.push(p)
    if (out.length >= MAX_PROCESSES) break
  }
  return out
}

/** What is wrong with a draft, or null. One sentence, said to the user. */
export function processDraftProblem(draft: ProcessDraft | null | undefined): string | null {
  if (!draft || typeof draft !== 'object') return 'That is not a process.'
  if (!str(draft.name).trim()) return 'Give it a name.'
  if (!str(draft.command).trim()) return 'Give it a command to run.'
  if (!str(draft.cwd).trim()) return 'Give it a working directory.'
  if (!Array.isArray(draft.args)) return 'Arguments must be a list.'
  if (draft.args.length > PROCESS_ARGS_MAX) return `That is more than ${PROCESS_ARGS_MAX} arguments.`
  if (!Array.isArray(draft.env)) return 'Environment must be a list.'
  if (draft.env.length > PROCESS_ENV_MAX) return `That is more than ${PROCESS_ENV_MAX} variables.`
  for (const e of draft.env) {
    const key = str((e as { key?: unknown })?.key).trim()
    if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(key)) {
      return `${key || 'That'} is not a usable environment variable name.`
    }
    if ((e as { kind?: unknown })?.kind === 'literal' && PROCESS_SECRET_KEY_RX.test(key)) {
      return `${key}: ${PROCESS_SECRET_LITERAL_REFUSAL}`
    }
  }
  if (!sanitiseReadiness(draft.readiness)) return 'That readiness check is not valid.'
  return null
}

/** The wire view: keys and sources, never a value. */
export function toProcessView(p: ManagedProcess): ManagedProcessView {
  return {
    id: p.id,
    name: p.name,
    command: p.command,
    args: [...p.args],
    cwd: p.cwd,
    env: p.env.map((e) =>
      e.kind === 'vault'
        ? {
            key: e.key,
            source: 'vault' as const,
            vaultEntryId: e.vaultEntryId,
            slot: e.slot,
            ...(e.fieldKey ? { fieldKey: e.fieldKey } : {})
          }
        : { key: e.key, source: 'literal' as const }
    ),
    restart: p.restart,
    readiness: p.readiness,
    createdAt: p.createdAt
  }
}

// ------------------------------------------------------------------- bridge

/**
 * What the renderer may ask for.
 *
 * There is no `logs` subscription and no status event, deliberately. A
 * crash-looping process writes as fast as the OS will let it, and a push
 * channel would repaint the renderer at that rate — the ring is bounded but a
 * stream out of it is not. The panel POLLS, so the cost of a process that has
 * lost its mind is one bounded page per poll interval, whatever it is doing.
 *
 * There is also no `create`-with-values read-back: `list` returns
 * `ManagedProcessView`, which has no environment values in it at all.
 */
export interface ProcessesBridge {
  list(): Promise<ManagedProcessView[]>
  status(): Promise<ProcessStatus[]>
  create(draft: ProcessDraft): Promise<ManagedProcessView | null>
  remove(id: string): Promise<boolean>
  start(id: string): Promise<ProcessStatus | null>
  stop(id: string): Promise<ProcessStatus | null>
  restart(id: string): Promise<ProcessStatus | null>
  logs(id: string, limit?: number): Promise<ProcessLogLine[]>
}
