import { existsSync, readFileSync, renameSync, writeFileSync } from 'node:fs'
import {
  MAX_PROCESSES,
  PROCESS_BACKOFF,
  PROCESS_CRASH_LOOP,
  PROCESS_LOG_PAGE,
  PROCESS_LOG_RING,
  processDraftProblem,
  processFailureMessage,
  sanitiseProcess,
  sanitiseProcesses,
  toProcessView
} from '../../shared/processes'
import type {
  ManagedProcess,
  ManagedProcessView,
  ProcessDraft,
  ProcessEnvVar,
  ProcessLogLine,
  ProcessState,
  ProcessStatus,
  ProcessesFile
} from '../../shared/processes'
import { Supervisor } from './vpn/supervisor'
import type { SupervisedSpec, SupervisorExit, SupervisorHandle } from './vpn/supervisor'

// The main-process half of roadmap item 1 — pm2-style supervision of the
// user's own long-lived local processes.
//
// The whole of the hard part is `Supervisor`, which was written for VPN and
// does not know what a tunnel is: backoff with jitter, crash-loop detection,
// restart policies, readiness probes, a bounded log ring, pid records that
// survive a crash, and orphan reaping on launch. This file is the LIST, the
// TRANSLATION and the REFUSALS. See src/shared/processes.ts for the reasoning
// behind each of them, including why there is no remote half and no
// auto-start.
//
// ---------------------------------------------------------------------------
// EVERYTHING IS INJECTED, INCLUDING THE VAULT
// ---------------------------------------------------------------------------
//
// Same discipline as `CredProxy` and `RuleEngine`, and for the same second
// reason: this module must not import `services/vault` or `services/secrets`.
// It is the one module in the app that starts a program on the machine the
// vault is on, and giving it the key as well would put the whole security
// model inside one class. It is handed a `resolveSecret` that returns a value
// or a reason, and it can do nothing its host did not give it.
//
// It does not import `electron` either: paths come in as strings, so nothing
// here has to reach for `app` and nothing here is unreachable from a test.
//
// ---------------------------------------------------------------------------
// A SUPERVISED PROCESS IS NEVER REACHABLE BY AN AGENT
// ---------------------------------------------------------------------------
//
// DURABILITY DEFEATS REVOCATION, and this is the sharpest case of it in the
// repo. `denyAllPending()` — the stop-all-AI-access switch — resolves requests
// that are PENDING. A running supervised process has nothing pending: no
// approval to withdraw, no session whose revocation reaches it, and a restart
// policy that will start it AGAIN when it exits. Denying every pending request
// returns cleanly, reports a number, and the process keeps running.
//
// Held out of the bridge three ways by tests/jobsNotExposed.test.ts: import
// closure, capability vocabulary, and the literal symbol names below.

/** What a vault lookup produced. A discriminated result rather than a thrown
 *  `VaultLockedError`, so this module never imports the resolver that defines
 *  it — main/index.ts does the mapping. Mirrors `CredentialResolution`. */
export type ProcessSecretResolution =
  | { ok: true; value: string }
  | { ok: false; reason: 'vault-locked' | 'credential-missing' }

export interface ProcessServiceDeps {
  now(): number
  newId(): string
  /** The process file, as it is on disk. Narrowed again by `sanitiseProcesses`
   *  regardless of what this returns. */
  read(): unknown
  write(file: ProcessesFile): void
  /** Resolves one `env` entry's vault reference to plaintext, AT START TIME.
   *  Never cached: the value lives as long as one spawn and no longer, so
   *  nothing here holds a copy after the vault re-locks. */
  resolveSecret(ref: {
    vaultEntryId: string
    slot: string
    fieldKey?: string
  }): ProcessSecretResolution
  /**
   * The supervisor to run children through.
   *
   * Injected so a test can drive it with a fake clock and a fake spawn, and —
   * more importantly — so the caller is the one that decides its `runRoot`.
   * That is not a convenience: `reapOrphans()` claims every `*.pid` file under
   * its root, and claiming means SIGTERM then SIGKILL. A supervisor sharing
   * the VPN root would reap the user's live tunnel on launch. See rule 1 at
   * the top of vpn/supervisor.ts.
   */
  supervisor: Supervisor
}

interface Runtime {
  state: ProcessState
  restarts: number
  startedAt?: number
  error?: string
  lastExitCode?: number | null
  lastExitSignal?: string | null
  /** Held so the last logs of a stopped run survive until the next start —
   *  the supervisor drops the handle the moment a run goes terminal, and the
   *  lines that say WHY it failed are the ones a person wants after it has. */
  tail: ProcessLogLine[]
}

const emptyFile = (): ProcessesFile => ({ v: 1, processes: [] })

export class ProcessService {
  private readonly deps: ProcessServiceDeps
  private processes: ManagedProcess[]
  private readonly runtime = new Map<string, Runtime>()

  constructor(deps: ProcessServiceDeps) {
    this.deps = deps
    this.processes = sanitiseProcesses(deps.read())
  }

  // ------------------------------------------------------------------- list

  list(): ManagedProcessView[] {
    return this.processes.map(toProcessView)
  }

  status(): ProcessStatus[] {
    return this.processes.map((p) => this.statusOf(p.id))
  }

  create(draft: ProcessDraft): ManagedProcessView | null {
    const problem = processDraftProblem(draft)
    if (problem) throw new Error(problem)
    if (this.processes.length >= MAX_PROCESSES) {
      throw new Error(`That is already ${MAX_PROCESSES} processes, which is the limit.`)
    }
    // Narrowed by the same function that narrows the file, so a field the
    // renderer invents is dropped rather than stored.
    const p = sanitiseProcess({
      ...draft,
      id: this.deps.newId(),
      createdAt: new Date(this.deps.now()).toISOString()
    })
    if (!p) throw new Error('That is not a process.')
    this.processes = [...this.processes, p]
    this.save()
    return toProcessView(p)
  }

  /** Removing a process stops it first. A definition deleted out from under a
   *  running child would leave a supervised orphan with nothing in the list
   *  that could ever stop it again. */
  async remove(id: string): Promise<boolean> {
    const before = this.processes.length
    await this.stop(id).catch(() => undefined)
    this.processes = this.processes.filter((p) => p.id !== id)
    this.runtime.delete(id)
    if (this.processes.length === before) return false
    this.save()
    return true
  }

  // ---------------------------------------------------------------- control

  async start(id: string): Promise<ProcessStatus | null> {
    const p = this.processes.find((x) => x.id === id)
    if (!p) return null
    if (this.deps.supervisor.get(this.runId(id))) return this.statusOf(id)

    // Resolved here and nowhere else. The values exist as locals for the
    // length of this call, go into the spec's `env` and its `redact` list, and
    // are never written to the process file, never logged and never returned.
    let env: Record<string, string>
    let secrets: string[]
    try {
      const resolved = this.resolveEnv(p.env)
      env = resolved.env
      secrets = resolved.secrets
    } catch (e) {
      const message = e instanceof Error ? e.message : String(e)
      this.setRuntime(id, { state: 'failed', error: message })
      return this.statusOf(id)
    }

    this.setRuntime(id, { state: 'starting', error: undefined, startedAt: this.deps.now() })

    // The exit listener is attached BEFORE the first await. `spawn()` puts the
    // run in the supervisor's map synchronously and only then waits for
    // readiness, so the handle is already there — and a process given a bad
    // argument exits in milliseconds, well inside that wait. An exit event
    // that arrives with nothing listening is gone for good, and the row would
    // sit on `starting` until somebody pressed Stop.
    const started = this.deps.supervisor.spawn(this.specFor(p, env, secrets))
    this.observe(id)

    try {
      await started
      const rt = this.runtime.get(id)
      // A run that reached readiness and then died before this line lands is
      // already `failed`; do not paint it green on the way past.
      if (rt && rt.state === 'starting') this.setRuntime(id, { state: 'running' })
    } catch (e) {
      this.recordFailure(id, e)
    }
    return this.statusOf(id)
  }

  async stop(id: string): Promise<ProcessStatus | null> {
    const p = this.processes.find((x) => x.id === id)
    if (!p) return null
    this.captureTail(id)
    await this.deps.supervisor.stop(this.runId(id))
    this.setRuntime(id, { state: 'stopped', error: undefined, restarts: 0 })
    return this.statusOf(id)
  }

  async restart(id: string): Promise<ProcessStatus | null> {
    const p = this.processes.find((x) => x.id === id)
    if (!p) return null
    await this.stop(id)
    return await this.start(id)
  }

  /** Stop everything, for app quit. Bounded by the supervisor's own ladder. */
  async stopAll(): Promise<void> {
    await Promise.allSettled(this.processes.map((p) => this.stop(p.id)))
  }

  /**
   * Clean up children left behind by a previous run of the app.
   *
   * Straight through to the supervisor, which verifies identity — exe path AND
   * start time — before it signals anything, because a pid on its own says
   * nothing: the OS reuses them and the one recorded may now belong to the
   * user's editor.
   *
   * This is the only thing this service does at launch. Nothing is STARTED —
   * see the auto-start refusal in shared/processes.ts.
   */
  async reapOrphans(): Promise<void> {
    await this.deps.supervisor.reapOrphans()
  }

  // ------------------------------------------------------------------- logs

  /**
   * The last lines, capped.
   *
   * Capped twice on purpose. The ring is bounded, so main cannot grow; this
   * bounds what crosses to the renderer, so a process that has lost its mind
   * costs one bounded page per poll rather than a megabyte per repaint.
   */
  logs(id: string, limit?: number): ProcessLogLine[] {
    const want = Math.min(PROCESS_LOG_PAGE, Math.max(1, Math.floor(limit ?? PROCESS_LOG_PAGE)))
    const handle = this.deps.supervisor.get(this.runId(id))
    if (handle) return handle.logs(want)
    // A terminal run has already been dropped by the supervisor. The lines
    // that explain WHY are the ones a person opens the drawer for.
    return (this.runtime.get(id)?.tail ?? []).slice(-want)
  }

  // -------------------------------------------------------------- internals

  private runId(id: string): string {
    // Namespaced, so a process id can never collide with a VPN run id even if
    // the two ever shared a root by mistake.
    return `proc-${id}`
  }

  private statusOf(id: string): ProcessStatus {
    const rt = this.runtime.get(id)
    const handle = this.deps.supervisor.get(this.runId(id))
    return {
      id,
      state: rt?.state ?? 'stopped',
      pid: handle?.pid ?? 0,
      restarts: handle?.restarts ?? rt?.restarts ?? 0,
      ...(rt?.startedAt !== undefined ? { startedAt: rt.startedAt } : {}),
      ...(rt?.error !== undefined ? { error: rt.error } : {}),
      ...(rt?.lastExitCode !== undefined ? { lastExitCode: rt.lastExitCode } : {}),
      ...(rt?.lastExitSignal !== undefined ? { lastExitSignal: rt.lastExitSignal } : {})
    }
  }

  private setRuntime(id: string, patch: Partial<Runtime>): void {
    const prev = this.runtime.get(id) ?? { state: 'stopped' as ProcessState, restarts: 0, tail: [] }
    this.runtime.set(id, { ...prev, ...patch })
  }

  private captureTail(id: string): void {
    const handle = this.deps.supervisor.get(this.runId(id))
    if (handle) this.setRuntime(id, { tail: handle.logs(PROCESS_LOG_PAGE) })
  }

  private recordFailure(id: string, e: unknown): void {
    const code = (e as { code?: string })?.code
    const detail = (e as { detail?: string })?.detail
    this.setRuntime(id, {
      state: code === 'crash-loop' ? 'crash-looped' : 'failed',
      error: processFailureMessage(code, detail)
    })
  }

  /**
   * Vault references to values, once, at start time.
   *
   * Throws with a sentence rather than starting a process with the variable
   * missing. "It started and immediately failed to connect to the database" is
   * a worse answer than "the vault is locked", and a half-populated
   * environment is the kind of failure people debug for an hour.
   */
  private resolveEnv(vars: ProcessEnvVar[]): { env: Record<string, string>; secrets: string[] } {
    const env: Record<string, string> = {}
    const secrets: string[] = []
    for (const v of vars) {
      if (v.kind === 'literal') {
        env[v.key] = v.value
        continue
      }
      const got = this.deps.resolveSecret({
        vaultEntryId: v.vaultEntryId,
        slot: v.slot,
        ...(v.fieldKey ? { fieldKey: v.fieldKey } : {})
      })
      if (!got.ok) {
        throw new Error(
          got.reason === 'vault-locked'
            ? `The vault is locked, so ${v.key} could not be read. Unlock it and start this again.`
            : `The vault entry for ${v.key} is missing, so this was not started.`
        )
      }
      env[v.key] = got.value
      // Every resolved value goes to the supervisor's redactor, which scrubs
      // BEFORE a line reaches the ring. A process that echoes its own
      // environment on start-up is not exotic; it is what half of them do.
      if (got.value) secrets.push(got.value)
    }
    return { env, secrets }
  }

  private specFor(
    p: ManagedProcess,
    env: Record<string, string>,
    secrets: string[]
  ): SupervisedSpec {
    const readiness = p.readiness
    return {
      id: this.runId(p.id),
      // "The process was stopped while it was starting", not "The tunnel …".
      noun: 'process',
      command: p.command,
      args: p.args,
      cwd: p.cwd,
      env,
      readiness:
        readiness.kind === 'spawned'
          ? // The child exists. Honest about what it knows rather than
            // pretending to have checked something.
            async (): Promise<void> => {}
          : (h: SupervisorHandle): Promise<void> => waitForLine(h, readiness.pattern),
      readinessTimeoutMs: readiness.kind === 'log' ? readiness.timeoutMs : 1_000,
      // Zero, on purpose. The supervisor's ladder is: gracefulStop (a control
      // channel), then SIGTERM, then SIGKILL. A user process has no control
      // channel — SIGTERM *is* the polite stop, and it is what `kill` and
      // `systemctl stop` send. Leaving the graceful rung at its default would
      // mean five seconds of waiting for a channel that does not exist before
      // the process was so much as asked to stop.
      gracefulTimeoutMs: 0,
      restart: p.restart,
      backoff: { ...PROCESS_BACKOFF },
      crashLoop: { ...PROCESS_CRASH_LOOP },
      logRing: { ...PROCESS_LOG_RING },
      redact: secrets,
      onReady: () => this.setRuntime(p.id, { state: 'running', error: undefined }),
      onRestartScheduled: (h) => this.setRuntime(p.id, { restarts: h.restarts }),
      onUnhealthy: () => this.setRuntime(p.id, { state: 'starting' })
    }
  }

  private save(): void {
    this.deps.write({ v: 1, processes: this.processes })
  }

  /** Attach exit bookkeeping to the live handle, so the panel's poll can say
   *  why something stopped rather than only that it is not running. */
  private observe(id: string): void {
    const handle = this.deps.supervisor.get(this.runId(id))
    if (!handle) return
    handle.onExit((e: SupervisorExit) => {
      // A restart in flight is not a stop. Painting it red between attempts
      // makes a healthy restart policy look like a broken process.
      if (e.restarting) {
        this.setRuntime(id, { restarts: handle.restarts, lastExitCode: e.code })
        return
      }
      if (e.logTail) this.setRuntime(id, { tail: [...e.logTail] })
      const rt = this.runtime.get(id)
      if (e.error) {
        this.recordFailure(id, e.error)
      } else if (rt?.state !== 'stopped') {
        this.setRuntime(id, { state: 'failed' })
      }
      this.setRuntime(id, { lastExitCode: e.code, lastExitSignal: e.signal })
    })
  }
}

/** Resolve when a line CONTAINS `pattern`. A substring, never a regex — see
 *  `ProcessReadiness`. Lines already in the ring count: a process that printed
 *  its banner before this listener attached is ready, not pending. */
function waitForLine(handle: SupervisorHandle, pattern: string): Promise<void> {
  return new Promise<void>((resolve) => {
    if (handle.logs().some((l) => l.text.includes(pattern))) {
      resolve()
      return
    }
    const off = handle.onLog((line) => {
      if (!line.text.includes(pattern)) return
      off()
      resolve()
    })
  })
}

// --------------------------------------------------------------------- io
//
// Paths in, no `electron` import — the same arrangement credProxy.ts uses, and
// what keeps this module out of the reach of anything that would have to
// import the app object to use it.

/** The process file as it is on disk, or an empty one.
 *
 *  A corrupt file reads as empty rather than throwing. The alternative is an
 *  app that will not finish starting because a JSON file lost a brace, and
 *  `sanitiseProcesses` already treats the contents as hostile. */
export function readProcessFile(path: string): unknown {
  try {
    if (existsSync(path)) return JSON.parse(readFileSync(path, 'utf8'))
  } catch (err) {
    console.error('[processes] file unreadable, starting empty:', err)
  }
  return emptyFile()
}

/**
 * Written temp-then-rename at 0600, like the vault, the rule file and
 * store.ts.
 *
 * Its own file, deliberately NOT `shellpilot-data.json`. That blob is
 * renderer-owned and is also the backup/export payload, and a command line
 * that will be executed on this machine does not belong in a file that gets
 * mailed around. The reasoning is written out at the top of
 * src/shared/processes.ts.
 */
export function writeProcessFile(path: string, file: ProcessesFile): void {
  try {
    writeFileSync(`${path}.tmp`, JSON.stringify(file), { mode: 0o600 })
    renameSync(`${path}.tmp`, path)
  } catch (err) {
    console.error('[processes] save failed:', err)
  }
}
