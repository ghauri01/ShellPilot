import type { JobPatch, JobTargetPatch, NewJob } from './history'
import type {
  JobDetachedHandle,
  JobDetail,
  JobHostOutcome,
  JobHostResult,
  JobHostState,
  JobOutput,
  JobOutputLine,
  JobProgress,
  JobRecord,
  JobRunRequest,
  JobSpec
} from '../../shared/jobs'
import {
  JOB_ABANDONED_ERROR,
  isJobDetachedHandle,
  JOB_CLASSIFY_BYTES,
  JOB_CONCURRENCY,
  JOB_OUTPUT_HEAD,
  JOB_OUTPUT_RATE_PER_SEC,
  JOB_OUTPUT_TAIL,
  JOB_REDACT_BLOCK_CARRY,
  JOB_REDACT_LINE_CARRY,
  JOB_STALL_GRACE_MS,
  JOB_STEP_TIMEOUT_MS,
  classifyJobResult,
  elisionNotice,
  planJob,
  stepFailureNote,
  stepNotice
} from '../../shared/jobs'
import { redactOutput } from './secretRedaction'

// Runs a job — roadmap item B1.
//
// Started from broadcast.ts and keeps what is proven there: the bounded worker
// pool, the stall guard whose timer covers the connect that sshExec's own
// timeout does not, the cancel checked both at dequeue and at entry, and the
// terminal event in a `finally` with an identity check so disposal cannot drop
// another run's event.
//
// Four things are new, and each of them is here because a job is not a
// broadcast that happens to be slower.
//
//  1. THE EXECUTOR IS AN INJECTED STRATEGY, from the first line. B1 runs on the
//     attached path and B2 replaces it with a detached launch against a marker
//     directory. Everything in this file — the vocabulary, the store, the
//     registry, the lifecycle — is true of both. If the transport were reached
//     for directly, B2 would be a rewrite rather than a swap, and the whole
//     reason B1 exists as a separate item would be lost.
//
//  2. THE `owns()` GUARD, taken from logTail.ts. Broadcast has one await per
//     host and could get away with an entry check; a job has several — the
//     store write, the exec, the output flush, the terminal write — and a
//     second run under the same id, or a dispose, can land in any of them.
//     Registration happens up front; every post-await step asks whether this
//     invocation still owns the id before it writes or emits.
//
//  3. OUTPUT IS COALESCED PER TICK, like ssh.ts's interactive terminal, and NOT
//     per line like logTail. `apt` writes a progress line per package; one IPC
//     message each is a flood the renderer does not survive, and the user's
//     conclusion is "ShellPilot froze". The per-host rate limit counts what it
//     dropped and says so on the next event — logTail's model, because a gap
//     nobody mentions reads as "the upgrade hung".
//
//  4. EVERY TRANSITION IS PERSISTED. That is what "durable" means in B1, and
//     it is the whole of what it means: the row survives, the process does not.
//     A job that was running when the app stopped is `abandoned`, and adopt()
//     writes that down at the next launch rather than leaving a row that says
//     `running` about a command the kernel SIGHUP'd hours ago.
//
// What this file does NOT do is claim to survive a dropped connection. See the
// header of shared/jobs.ts: on the attached path a dying socket is SIGHUP, and
// apt and dpkg do not ignore it. Saying otherwise would be worse than not
// offering the feature.
//
// Not agent-reachable, and the argument is not broadcast's repeated. See
// tests/jobsNotExposed.test.ts.

/** What an executor is handed. */
export interface JobExecRequest {
  cfg: unknown
  command: string
  timeoutMs: number
  /** Which job and host this is, so a detached executor can name a marker
   *  directory that a different ShellPilot can find from the row alone. */
  jobId: string
  serverId: string
  serverName: string
  /** 1-based step within the job. Part of the marker name, because `out`, `pid`
   *  and `rc` describe one process and two steps sharing them would make the
   *  byte cursor mean two different things. */
  step: number
  /**
   * A marker this host already has: watch it rather than launching anything.
   *
   * The reclaim path, and it is the SAME call as a fresh launch on purpose. A
   * reclaim that went through its own entry point would be a code path
   * exercised only in the failure people report.
   */
  resume?: JobDetachedHandle
  /**
   * Something the executor has learned that must be on disk NOW, before it goes
   * back to waiting.
   *
   * The whole claim of a detached job is that an instance which never saw it
   * start can pick it up, and that claim is only as good as the row. A handle
   * held in memory until the executor returns is a handle that does not exist
   * for the one event it is for.
   */
  onState?: (u: JobExecUpdate) => void
  /**
   * False once this run no longer owns the host — the window closed, or a
   * second run took the id.
   *
   * An attached executor does not need it: its channel dies with the process.
   * A detached one polls a host that is still working, and without this it
   * would poll forever into a runner that stopped listening.
   */
  alive?: () => boolean
  /**
   * Output as it arrives.
   *
   * An executor with no streaming may call this once when the command is over;
   * the runner does not care and does not ask. That is deliberate — it is the
   * seam B2's marker-file poller resumes through, reading from a byte offset,
   * without this file learning what a marker file is.
   */
  onOutput: (stream: 'out' | 'err', text: string) => void
}

export interface JobExecResult {
  ok: boolean
  code?: number | null
  stdout?: string
  stderr?: string
  error?: string
  /**
   * The executor dropped output of its own accord.
   *
   * A LIVE hint only. It has no column, and it must not get one: the fact a
   * reader needs a month later is HOW MUCH went, which is what `out_elided`
   * already holds. An executor that drops bytes therefore reports `elided`
   * below, the runner folds it into the host's elision count, and truncation
   * survives a restart as a number rather than as a flag that was emitted once
   * and thrown away.
   */
  truncated?: boolean
  /** Bytes the EXECUTOR dropped, folded into the host's `out_elided`. See
   *  `truncated`. */
  elided?: number
  /**
   * The state this host ends in, when `ok`/`failed` cannot express it.
   *
   * B2's `orphaned` is the case: the marker survived, the pid did not, and no
   * exit status was ever written. That is neither a success nor a failure of
   * the command — it is the absence of an answer — and calling it `failed`
   * would report a verdict nobody reached.
   */
  finalState?: JobHostState
  /** The outcome to record, when the executor knows something the classifier
   *  cannot re-derive from an exit code and two streams. */
  finalOutcome?: JobHostOutcome
  /**
   * The marker to leave on the row, or null to clear it.
   *
   * Set when the executor is handing a still-running command back — a disposed
   * run, or a foreign marker it may read but not reap — so the row keeps what
   * the next instance needs to find it.
   */
  detachedHandle?: JobDetachedHandle | null
  /**
   * The executor merged stderr into stdout, so classify from one stream.
   *
   * A detached wrapper redirects `2>&1` to keep the two in ORDER, which on a
   * package operation is the difference between a readable log and two shuffled
   * halves. The runner therefore classifies from the merged tail rather than
   * from an stderr buffer that is empty by construction — without this, every
   * failing detached command would come back `nonzero` and `missing-command`
   * would be unreachable.
   */
  mergedOutput?: boolean
}

/** What an executor tells the runner mid-flight. Everything here is persisted
 *  the moment it arrives; see JobExecRequest.onState. */
export interface JobExecUpdate {
  state?: JobHostState
  /** Undefined leaves the row's handle alone; null clears it. */
  detached?: JobDetachedHandle | null
  /** This host fell back to the attached path, and why. */
  degraded?: string
  /** A note about the CURRENT state — "the vault is locked, polling is
   *  paused" — not a terminal error. */
  error?: string
}

export type JobExecutor = (req: JobExecRequest) => Promise<JobExecResult>

/**
 * The slice of the store a runner may touch.
 *
 * Structural rather than `HistoryStore`, so nothing here can reach the metric
 * or fact surface — and so a test can hand in a fake without an Electron app
 * object. No SQL crosses it in either direction; see the note at the top of
 * history.ts about why that is the condition the store's escape hatch depends
 * on.
 */
export interface JobStore {
  createJob(job: NewJob): void
  updateJob(jobId: string, patch: JobPatch): void
  updateJobTarget(jobId: string, serverId: string, patch: JobTargetPatch): void
  appendJobOutput(jobId: string, serverId: string, lines: JobOutputLine[]): void
  listJobs(limit?: number): JobRecord[]
  readJob(jobId: string): JobDetail | null
  readJobOutput(jobId: string, serverId: string): JobOutputLine[]
  unfinishedJobs(): JobDetail[]
  recordEvent(kind: string, hostId: string | null, payload?: unknown, at?: number): void
}

export interface JobRunnerDeps {
  exec: JobExecutor
  store: JobStore
  emit: (progress: JobProgress) => void
  emitOutput: (output: JobOutput) => void
  now?: () => number
  /**
   * Secret values resolved for this host, blanked out of its output before it
   * is written down. Same contract as recordAudit's: the pattern rules in
   * secretRedaction.ts always apply; this adds the values ShellPilot already
   * holds for the servers involved.
   */
  knownSecrets?: (cfg: unknown) => string[]
  /**
   * How a coalescing flush is scheduled. Defaults to a zero-delay timer, which
   * is ssh.ts's batching window. Injectable so tests can drive it rather than
   * sleep on it — a suite that synchronises on `setTimeout(5)` gets flakier as
   * the state machine grows, and this one is going to grow.
   */
  schedule?: (fn: () => void) => void
  /** Overridable for tests; see JOB_STALL_GRACE_MS. */
  stallGraceMs?: number
}

interface RunState {
  cancelled: boolean
  /**
   * Set by disposeAll(): the app is going away underneath this run.
   *
   * Distinct from `cancelled`, and the distinction is the whole of BLOCKER 1.
   * A cancelled job ENDED — somebody stopped it and the row says so. A disposed
   * job did not end; nothing decided anything, the window went. Writing
   * `cancelled` + endedAt for it makes the row terminal, and a terminal row is
   * one `unfinishedJobs()` can never select again — so the host that was
   * mid-command stays `running` forever and `abandoned` becomes unreachable on
   * the one path that produces it. The rows are left open for adopt() instead.
   */
  disposed: boolean
}

/** Per-host output bookkeeping. Lives for the length of one host's run. */
interface HostOutput {
  /** Rows already written. Also the next seq to use. */
  seq: number
  /** Bytes persisted so far. Becomes out_offset. */
  bytes: number
  /** Bytes dropped from the middle. Becomes out_elided. */
  elided: number
  /** Bytes of head written. Once this passes JOB_OUTPUT_HEAD, chunks go to the
   *  tail ring instead of straight to the store. */
  headBytes: number
  /** The last JOB_OUTPUT_TAIL bytes, held until the host finishes. */
  tail: JobOutputLine[]
  tailBytes: number
  /** Coalescing buffer for the renderer, one entry per stream run. */
  pending: { stream: 'out' | 'err'; text: string }[]
  scheduled: boolean
  /** Rate-limit window for renderer events. */
  windowStart: number
  inWindow: number
  dropped: number
  /** Bytes held back per stream so a secret split across two chunks is redacted
   *  as one string. See JOB_REDACT_LINE_CARRY. */
  carry: { out: string; err: string }
  /** The tail of each stream, kept only to classify the result. See
   *  JOB_CLASSIFY_BYTES. */
  clsOut: string
  clsErr: string
}

export class JobRunner {
  /**
   * Runs keyed by job id. A second run under a live id is refused rather than
   * silently joined: cancel names one id, every progress event carries one id,
   * and the first to finish would delete the other's entry — leaving a live job
   * that cannot be cancelled and a Stop button that does nothing.
   */
  private active = new Map<string, RunState>()

  /** Reclaimed jobs still running, so a caller can wait for one without the
   *  startup path having to. See reclaim(). */
  private settling = new Map<string, Promise<void>>()

  constructor(private readonly deps: JobRunnerDeps) {}

  private get now(): number {
    return (this.deps.now ?? Date.now)()
  }

  private schedule(fn: () => void): void {
    if (this.deps.schedule) {
      this.deps.schedule(fn)
      return
    }
    const t = setTimeout(fn, 0)
    // A flush is not a reason to hold the process open at quit.
    if (typeof t.unref === 'function') t.unref()
  }

  isRunning(jobId: string): boolean {
    return this.active.has(jobId)
  }

  list(limit?: number): JobRecord[] {
    return this.deps.store.listJobs(limit)
  }

  get(jobId: string): JobDetail | null {
    return this.deps.store.readJob(jobId)
  }

  outputFor(jobId: string, serverId: string): JobOutputLine[] {
    return this.deps.store.readJobOutput(jobId, serverId)
  }

  /**
   * Stop a job.
   *
   * Hosts already executing are left to finish, exactly as broadcast leaves
   * them: killing a command mid-write is how a half-applied change happens, and
   * a half-applied change is worse than one that completed. Hosts not yet
   * started are recorded `skipped`, so the target list stays complete rather
   * than simply ending early.
   *
   * Persisted immediately, before any host notices. A cancel the store does not
   * know about is a cancel that a restart undoes.
   */
  cancel(jobId: string): boolean {
    const run = this.active.get(jobId)
    if (!run) return false
    if (run.cancelled) return true
    run.cancelled = true
    const at = this.now
    this.deps.store.updateJob(jobId, { cancelledAt: at })
    const job = this.deps.store.readJob(jobId)
    if (job) this.deps.emit({ jobId, job, cancelled: true })
    return true
  }

  /**
   * Reject an executor that never settles.
   *
   * Copied from broadcast, comment and all, because the reason is unchanged:
   * `sshExec`'s own timer starts only once the connection is up, so connection
   * setup is not covered by it at all. An exec that never resolves used to
   * leave the worker awaiting forever — no result for that host, no terminal
   * event for any of them, and a Stop button that cannot help because cancel
   * deliberately leaves a running host alone.
   */
  private stallGuard<T>(p: Promise<T>, ms: number, message: string): Promise<T> {
    let timer: ReturnType<typeof setTimeout> | undefined
    const guard = new Promise<never>((_resolve, reject) => {
      timer = setTimeout(() => reject(new Error(message)), ms)
      if (typeof timer.unref === 'function') timer.unref()
    })
    // Promise.race attaches its own handlers to `p`, so an exec that settles
    // after the guard fired is not an unhandled rejection.
    return Promise.race([p, guard]).finally(() => clearTimeout(timer))
  }

  /**
   * Close out jobs whose rows still say they were running.
   *
   * Read at startup, from rows alone: this instance never saw them run and does
   * not need to have. On the attached path there is nothing to reconnect to —
   * the channel died with the process that held it and the remote command was
   * sent SIGHUP — so the honest thing, and the only thing, is to write down
   * that it was abandoned and say what that may have left behind.
   *
   * This is the method B2 replaces rather than extends: with a marker directory
   * the same rows are reclaimable, and the states are `detached`/`orphaned`
   * rather than `abandoned`. The lifecycle around it does not change, which is
   * the point of building it now.
   */
  adopt(): JobDetail[] {
    const at = this.now
    const adopted: JobDetail[] = []
    for (const job of this.deps.store.unfinishedJobs()) {
      // A job this process is currently running is not an orphan. adopt() is a
      // startup call, but a caller that runs it twice must not wreck a live
      // run's rows.
      if (this.active.has(job.id)) continue
      // A job with a detached marker on any host is NOT closed here. There is a
      // command running on that machine right now and a directory recording
      // where; writing `abandoned` over it would be this build telling a lie
      // about a process it can still reach. Left open for reclaim(), which is
      // called immediately after this and picks it up from the rows alone.
      if (job.targets.some((t) => reclaimable(t))) continue
      for (const t of job.targets) {
        if (t.state === 'running') {
          this.deps.store.updateJobTarget(job.id, t.serverId, {
            state: 'failed',
            outcome: 'abandoned',
            error: JOB_ABANDONED_ERROR,
            endedAt: at
          })
        } else if (t.state === 'pending' || t.state === 'waiting') {
          // `cancelled`, whose label is "not run" — NOT `abandoned`.
          //
          // `abandoned` is defined one line above and in shared/jobs.ts as
          // "ShellPilot stopped while this host was RUNNING": the channel went
          // and the remote process was sent SIGHUP. Nothing ever touched this
          // host, so there is no channel and no SIGHUP, and filing it under
          // `abandoned` inflates every summary with hosts that were never at
          // risk. It is also what classifyJobResult answers for the same row —
          // the error text below deliberately does not match its ABANDONED
          // regex — and a stored outcome that disagrees with a re-derivation
          // over the same row means the answer depends on which of the two a
          // reader happened to use. markSkipped writes `cancelled` for exactly
          // this situation already.
          this.deps.store.updateJobTarget(job.id, t.serverId, {
            state: 'skipped',
            outcome: 'cancelled',
            error: 'ShellPilot stopped before this host was reached.',
            endedAt: at
          })
        }
      }
      this.deps.store.updateJob(job.id, { state: 'abandoned', endedAt: at })
      this.deps.store.recordEvent('job-abandoned', null, { jobId: job.id, title: job.title }, at)
      const closed = this.deps.store.readJob(job.id)
      if (closed) {
        adopted.push(closed)
        this.deps.emit({ jobId: job.id, job: closed, done: true })
      }
    }
    return adopted
  }

  /**
   * Pick up detached jobs from a previous run of this app.
   *
   * FROM THE ROWS ALONE. This instance never saw these jobs start, has no
   * memory of the dialog that authorised them and no channel to any of them —
   * it has a marker directory, a byte offset and a step number, which between
   * them are everything the poller needs. That is the whole claim B2 makes and
   * it is why the handle is written to the row before the first poll rather
   * than held in memory.
   *
   * TWO DELIBERATE REFUSALS.
   *
   *  1. HOSTS THAT WERE NEVER REACHED ARE NOT STARTED. A job whose first three
   *     hosts are detached and whose remaining twelve are `pending` resumes
   *     three and closes twelve as "not run". Launching them would be running
   *     a destructive command on twelve machines on the strength of a
   *     confirmation this process never saw a human give — `BroadcastPlan`
   *     never reaches main, and main deliberately does not re-derive it. That
   *     is B3's item, and quietly acting as though it were already done would
   *     make B3 a correction rather than an addition.
   *  2. A HOST WHOSE SERVER IS GONE IS NOT GUESSED AT. If the workspace no
   *     longer has that server there is no way to connect, and the row says so
   *     rather than sitting at `detached` forever.
   *
   * SYNCHRONOUS, and it returns the rows it has taken over rather than the rows
   * it has finished. A reclaimed upgrade can have forty minutes left to run; a
   * startup path that awaited it would hold the app's boot open for the
   * duration. `whenSettled` is how a caller waits for one on purpose.
   */
  reclaim(deps: {
    /** The connection config for a server id, or null if it is no longer in the
     *  workspace. */
    cfgFor: (serverId: string) => unknown | null
  }): JobDetail[] {
    const store = this.deps.store
    const out: JobDetail[] = []
    for (const job of store.unfinishedJobs()) {
      if (this.active.has(job.id)) continue
      const resumable = job.targets.filter((t) => reclaimable(t))
      if (resumable.length === 0) continue

      const state: RunState = { cancelled: false, disposed: false }
      this.active.set(job.id, state)
      const owns = (): boolean => this.active.get(job.id) === state

      // Everything that was NOT launched is closed before anything is resumed,
      // so the job's own row is honest for the whole of the time it takes.
      const at = this.now
      for (const t of job.targets) {
        if (reclaimable(t)) continue
        if (t.state === 'running') {
          store.updateJobTarget(job.id, t.serverId, {
            state: 'failed',
            outcome: 'abandoned',
            error: JOB_ABANDONED_ERROR,
            endedAt: at
          })
        } else if (t.state === 'pending' || t.state === 'waiting') {
          store.updateJobTarget(job.id, t.serverId, {
            state: 'skipped',
            outcome: 'cancelled',
            error:
              'ShellPilot stopped before this host was reached. It was not started at the next ' +
              'launch, because the confirmation the job was authorised with does not survive a ' +
              'restart yet.',
            endedAt: at
          })
        }
      }
      store.recordEvent(
        'job-reclaimed',
        null,
        { jobId: job.id, title: job.title, hosts: resumable.length },
        at
      )
      this.emitJob(job.id)

      const req: JobRunRequest = {
        jobId: job.id,
        workspaceId: job.workspaceId,
        spec: job.spec,
        confirmedAt: job.confirmedAt ?? undefined,
        targets: resumable.map((t) => ({
          serverId: t.serverId,
          serverName: t.serverName,
          cfg: deps.cfgFor(t.serverId)
        }))
      }
      const queue = [...resumable]

      const workers = Array.from(
        { length: Math.min(job.spec.concurrency ?? JOB_CONCURRENCY, Math.max(queue.length, 1)) },
        async () => {
          for (;;) {
            if (!owns()) return
            const next = queue.shift()
            if (!next) return
            const handle = next.detached
            const target = req.targets.find((t) => t.serverId === next.serverId)
            if (!isJobDetachedHandle(handle) || target === undefined) continue
            if (target.cfg === null || target.cfg === undefined) {
              store.updateJobTarget(job.id, next.serverId, {
                state: 'orphaned',
                outcome: 'orphaned',
                error:
                  'This host is no longer in the workspace, so its job cannot be followed. Its ' +
                  `marker directory is still on the machine at ${handle.dir} and holds the ` +
                  'output and exit status.',
                endedAt: this.now
              })
              this.emitHost(job.id, {
                serverId: next.serverId,
                serverName: next.serverName,
                state: 'orphaned',
                outcome: 'orphaned'
              })
              continue
            }
            await this.runOne(req, target, state, owns, {
              handle,
              startedAt: next.startedAt,
              outOffset: next.outOffset,
              outElided: next.outElided,
              // Continue the output rather than overwriting it: seq is the
              // primary key of job_output, so restarting at zero would write
              // this instance's first chunk over the last one from before the
              // restart.
              outSeq: store.readJobOutput(job.id, next.serverId).length
            })
          }
        }
      )

      const settled = (async () => {
        try {
          await Promise.all(workers)
        } finally {
          const stillOurs = this.active.get(job.id) === state
          if (stillOurs) {
            this.active.delete(job.id)
            const endedAt = this.now
            store.updateJob(job.id, { state: state.cancelled ? 'cancelled' : 'done', endedAt })
            store.recordEvent('job-ended', null, { jobId: job.id, reclaimed: true }, endedAt)
            const final = store.readJob(job.id)
            this.deps.emit({ jobId: job.id, job: final ?? undefined, done: true })
          }
          this.settling.delete(job.id)
        }
      })()
      // Held so nothing is an unhandled rejection and so whenSettled() has
      // something to hand back. A reclaim that threw would otherwise be
      // invisible: the rows would sit at `detached` and the only evidence would
      // be in a console nobody in a packaged app can read.
      this.settling.set(job.id, settled)
      void settled.catch(() => {
        /* the row is closed in the finally above; nothing else to do */
      })

      const taken = store.readJob(job.id)
      if (taken) out.push(taken)
    }
    return out
  }

  /** Resolves when a reclaimed job has finished. Undefined for a job that is
   *  not being reclaimed. */
  whenSettled(jobId: string): Promise<void> | undefined {
    return this.settling.get(jobId)
  }

  /**
   * Write down something the executor learned mid-flight, and say so.
   *
   * Persisted the moment it arrives rather than at the end of the host's run,
   * because the events this carries are exactly the ones whose value is that
   * they survive this process: a marker directory that is not on disk before
   * the first poll is a running command nobody can reclaim.
   *
   * Guarded by `owns` like every other post-await write. A detached executor
   * polls a host for as long as the command runs, which can be past a dispose
   * and past a second run claiming the id.
   */
  private applyUpdate(
    jobId: string,
    serverId: string,
    serverName: string,
    u: JobExecUpdate,
    owns: () => boolean
  ): void {
    if (!owns()) return
    const patch: JobTargetPatch = {}
    if (u.state !== undefined) patch.state = u.state
    if (u.detached !== undefined) patch.detached = u.detached
    // A NOTE, not a verdict. `error` on a live row is how "the vault is locked,
    // so this host is not being polled" reaches a reader; the terminal write at
    // the end of runOne overwrites it either way.
    if (u.error !== undefined) patch.error = u.error
    this.deps.store.updateJobTarget(jobId, serverId, patch)
    const host: JobHostResult = { serverId, serverName, state: u.state ?? 'running' }
    if (u.detached !== undefined) host.detached = u.detached
    if (u.error !== undefined) host.error = u.error
    // Carried on the event as well as written to the row: the row is what the
    // next launch reads, and the event is what tells the person watching that
    // this host has fallen back to the attached path and will not survive the
    // lid closing. Neither substitutes for the other.
    if (u.degraded !== undefined) host.degraded = u.degraded
    this.emitHost(jobId, host)
  }

  /**
   * Run a job to completion.
   *
   * The row exists before the first host is touched, and so does every target
   * row. That ordering is the feature, not an implementation detail: it is why
   * a job read back after a restart knows which hosts it was aimed at, and why
   * adopt() can say "host b was never reached" rather than only "host a died".
   * A runner that wrote rows as it went would have nothing to say about the
   * hosts it had not got to.
   */
  async run(req: JobRunRequest): Promise<JobDetail> {
    if (this.active.has(req.jobId)) {
      throw new Error(`a job with id ${req.jobId} is already running`)
    }
    const state: RunState = { cancelled: false, disposed: false }
    this.active.set(req.jobId, state)
    // Identity, not `has(jobId)`. Everything after an await asks this before it
    // writes or emits — see the header.
    const owns = (): boolean => this.active.get(req.jobId) === state

    const store = this.deps.store
    const createdAt = this.now
    const plan = planJob(req.spec, req.targets)

    store.createJob({
      id: req.jobId,
      createdAt,
      workspaceId: req.workspaceId ?? null,
      title: req.spec.title,
      kind: req.spec.kind,
      spec: req.spec,
      risk: plan.risk,
      // Recorded as it was demanded rather than re-derived on read. B3 turns
      // this into a full approval record; persisting the demand now means a job
      // read back after a restart can say what standard it was held to.
      confirmation: plan.confirmation,
      confirmedAt: req.confirmedAt ?? null,
      state: 'queued',
      targets: req.targets.map((t, i) => ({
        serverId: t.serverId,
        serverName: t.serverName,
        ord: i,
        state: 'pending' as const
      }))
    })

    store.updateJob(req.jobId, { state: 'running', startedAt: createdAt })
    store.recordEvent(
      'job-started',
      null,
      { jobId: req.jobId, title: req.spec.title, risk: plan.risk, hosts: req.targets.length },
      createdAt
    )
    this.emitJob(req.jobId)

    const queue = [...req.targets]
    const workers = Array.from(
      { length: Math.min(req.spec.concurrency ?? JOB_CONCURRENCY, Math.max(queue.length, 1)) },
      async () => {
        for (;;) {
          if (!owns()) return
          const next = queue.shift()
          if (!next) return
          // Checked at DEQUEUE as well as at entry to runOne, and both are
          // load-bearing. A cancel landing while an earlier host was still
          // running has to stop this one before anything opens a channel; a
          // cancel landing inside runOne's own first await has to stop it
          // there. One check covers one of those two windows, and the window it
          // misses is as wide as a host's runtime.
          if (state.cancelled) {
            this.markSkipped(req.jobId, next)
            continue
          }
          await this.runOne(req, next, state, owns)
        }
      }
    )

    try {
      await Promise.all(workers)
    } finally {
      // Only if this run still owns the entry. disposeAll clears the map, and a
      // deletion that does not check identity would drop somebody else's live
      // run out of reach of cancel.
      const stillOurs = this.active.get(req.jobId) === state
      if (stillOurs) this.active.delete(req.jobId)
      const endedAt = this.now
      if (!stillOurs) {
        // This run no longer owns the id: either disposeAll() took the map
        // apart under it, or — the map having been cleared — a later run
        // claimed the id. NOTHING TERMINAL MAY BE WRITTEN HERE, and both cases
        // want that for different reasons.
        //
        // Disposed: the run did not end, the app went. Writing `cancelled` +
        // endedAt makes the row terminal, unfinishedJobs() selects on
        // queued/running, and the row drops out of adoption's reach forever —
        // while the host that was mid-exec is left saying `running` about a
        // command the kernel SIGHUP'd. That pairing (a job that looks finished
        // over a target that looks running) is unreadable, it is what the
        // comment in main/index.ts's before-quit handler promises adopt() will
        // clean up, and it made `abandoned` — the headline of B1 — unreachable
        // on the ordinary path. Closing the window on macOS was enough to hit
        // it. Left `running`, adopt() closes it at the next launch, which is
        // the truth about what the attached path just did.
        //
        // Superseded: the rows belong to the other run now, and a stale write
        // would overwrite its state with this one's.
        if (state.disposed) {
          store.recordEvent('job-disposed', null, { jobId: req.jobId, title: req.spec.title }, endedAt)
        }
      } else {
        // The state a job ends in is a fact about the run, not about its hosts:
        // a cancelled job with twelve successful hosts is still a cancelled job,
        // and calling it `done` would lose the only reason the last three never
        // ran.
        store.updateJob(req.jobId, {
          state: state.cancelled ? 'cancelled' : 'done',
          endedAt
        })
        store.recordEvent(
          'job-ended',
          null,
          { jobId: req.jobId, cancelled: state.cancelled || undefined },
          endedAt
        )
        // A terminal event always fires — on cancel, and on an empty target list
        // — so nothing waits forever for a job that has already stopped.
        const final = store.readJob(req.jobId)
        this.deps.emit({
          jobId: req.jobId,
          job: final ?? undefined,
          done: true,
          cancelled: state.cancelled || undefined
        })
      }
    }

    return store.readJob(req.jobId) as JobDetail
  }

  private emitJob(jobId: string): void {
    const job = this.deps.store.readJob(jobId)
    if (job) this.deps.emit({ jobId, job })
  }

  private emitHost(jobId: string, host: JobHostResult): void {
    this.deps.emit({ jobId, host })
  }

  /**
   * A host the cancel reached before the job did.
   *
   * Reported rather than dropped, so the target list stays complete: "three
   * hosts never ran" is the answer someone needs afterwards, and an absent row
   * reads as "we forgot about them". One writer, called from both cancel
   * checks, so the two can never disagree about what a skipped host looks like.
   */
  private markSkipped(jobId: string, target: { serverId: string; serverName: string }): void {
    this.deps.store.updateJobTarget(jobId, target.serverId, {
      state: 'skipped',
      outcome: 'cancelled',
      endedAt: this.now
    })
    this.emitHost(jobId, {
      serverId: target.serverId,
      serverName: target.serverName,
      state: 'skipped',
      outcome: 'cancelled'
    })
  }

  private async runOne(
    req: JobRunRequest,
    target: JobRunRequest['targets'][number],
    state: RunState,
    owns: () => boolean,
    /** Set when this host is being RECLAIMED: there is a command already
     *  running on it and a marker directory recording where. See reclaim(). */
    resume?: {
      handle: JobDetachedHandle
      startedAt?: number
      outOffset?: number
      outElided?: number
      outSeq?: number
    }
  ): Promise<void> {
    const store = this.deps.store
    const { serverId, serverName } = target

    if (state.cancelled) {
      this.markSkipped(req.jobId, target)
      return
    }

    const startedAt = resume?.startedAt ?? this.now
    // A reclaimed host keeps the state its row already carries: it is
    // `detached`, it has been since before this process existed, and writing
    // `running` over it would claim this instance has a channel to something it
    // has not polled yet.
    if (resume === undefined) {
      store.updateJobTarget(req.jobId, serverId, { state: 'running', startedAt })
      this.emitHost(req.jobId, { serverId, serverName, state: 'running', startedAt })
    }

    // A reclaimed host CONTINUES its output rather than starting it again. seq
    // is the primary key of job_output, so restarting at 0 would overwrite what
    // was written before the restart; out_offset is what the row already says
    // this host produced, and resetting it to zero would tell a reader the
    // upgrade printed nothing for its first forty minutes.
    const out: HostOutput = {
      seq: resume?.outSeq ?? 0,
      bytes: resume?.outOffset ?? 0,
      elided: resume?.outElided ?? 0,
      // The head budget is per HOST, not per process. A reclaimed host that
      // reset this would be allowed a second 64 KB head, which is how a job
      // restarted three times quietly stores four times its cap.
      headBytes: Math.min(resume?.outOffset ?? 0, JOB_OUTPUT_HEAD),
      tail: [],
      tailBytes: 0,
      pending: [],
      scheduled: false,
      windowStart: startedAt,
      inWindow: 0,
      dropped: 0,
      carry: { out: '', err: '' },
      clsOut: '',
      clsErr: ''
    }
    const secrets = this.deps.knownSecrets?.(target.cfg) ?? []

    let result: JobExecResult | null = null
    let failure: string | null = null
    /** The marker this host currently carries, mirrored here so the dispose
     *  branch below can tell a detached host from an attached one without
     *  reading the row back. */
    let handle: JobDetachedHandle | null = resume?.handle ?? null
    /** Which step produced `result`, 1-based, and what it was. */
    let stepIndex = 0
    let stepCommand = ''
    const totalSteps = req.spec.steps.length

    // Steps run in order and stop at the first one that does not exit zero —
    // `a && b` semantics, because that is what a person typing them means. A
    // job whose second step ran after its first failed is a job that did
    // something nobody asked for. B1 ships one step; the loop is here because
    // the spec type carries a list and quietly running only the first would be
    // a lie told by the type.
    // A reclaimed host rejoins at the step its marker names, and the steps
    // BEFORE it are not re-run. Re-running them would be the worst possible
    // reading of "resume": step 1 of an upgrade has already happened on that
    // machine, and doing it twice because ShellPilot restarted is ShellPilot
    // causing the damage it exists to avoid.
    const resumeAt = resume?.handle.step ?? 1
    for (const step of req.spec.steps) {
      if (!owns()) break
      stepIndex++
      if (stepIndex < resumeAt) continue
      stepCommand = step.command
      // A boundary row, in the stream, in order. Without it a three-step job is
      // one wall of text and "which step printed this" has no answer — and the
      // head budget is per host, so a chatty first step eats it and the marker
      // is the only surviving evidence the later steps ran at all.
      if (totalSteps > 1) {
        this.pushOutput(
          req.jobId,
          serverId,
          out,
          'err',
          stepNotice(stepIndex, totalSteps, step.command),
          secrets,
          owns
        )
      }
      const timeoutMs = step.timeoutMs ?? JOB_STEP_TIMEOUT_MS
      try {
        const r = await this.stallGuard(
          this.deps.exec({
            cfg: target.cfg,
            command: step.command,
            timeoutMs,
            jobId: req.jobId,
            serverId,
            serverName,
            step: stepIndex,
            // Only the step the marker names is resumed. A three-step job
            // reclaimed at step 2 launches step 3 normally.
            resume: stepIndex === resumeAt ? resume?.handle : undefined,
            alive: owns,
            onState: (u) => {
              if (u.detached !== undefined) handle = u.detached
              this.applyUpdate(req.jobId, serverId, serverName, u, owns)
            },
            onOutput: (stream, text) => this.pushOutput(req.jobId, serverId, out, stream, text, secrets, owns)
          }),
          timeoutMs + (this.deps.stallGraceMs ?? JOB_STALL_GRACE_MS),
          `${serverName} never answered — giving up so the rest of the job can finish`
        )
        result = r
        // An executor that returns the whole output instead of streaming it —
        // the attached `sshExec` does exactly this — still has to reach the
        // store and the pane. Handed over here rather than inside the executor
        // so a streaming backend and a batch one produce the same rows.
        if (r.stdout) this.pushOutput(req.jobId, serverId, out, 'out', r.stdout, secrets, owns)
        if (r.stderr) this.pushOutput(req.jobId, serverId, out, 'err', r.stderr, secrets, owns)
        // An executor that capped its own buffer says how much it lost, and
        // the count is folded into the host's elision total. That is where
        // truncation is PERSISTED: `truncated` has no column and does not need
        // one, because out_elided already answers the question a reader has a
        // month later — how much went — and a flag that is emitted live and
        // thrown away turns "dpkg failed" back into "the command produced no
        // error" at the next restart.
        out.elided += r.elided ?? 0
        if (!r.ok || (r.code ?? 0) !== 0) break
      } catch (e) {
        // One unreachable host must not end the job — the others are the reason
        // it was started.
        failure = e instanceof Error ? e.message : String(e)
        break
      }
    }

    // Whatever the rate limiter, the redaction carry and the tail buffer are
    // still holding is the last thing anyone gets to see. Flushed BEFORE the
    // terminal state is written, so a reader that stops at "this host is done"
    // has all of it. The carry goes first: it holds a partial last line that
    // the tail has not been offered yet.
    this.pushOutput(req.jobId, serverId, out, 'out', '', secrets, owns, true)
    this.pushOutput(req.jobId, serverId, out, 'err', '', secrets, owns, true)
    this.flushPending(req.jobId, serverId, out, owns)
    this.flushTail(req.jobId, serverId, out, owns)

    if (!owns()) {
      // Disposed mid-command. This run's result is being dropped on the floor,
      // so the row must not be left saying `running` — that is the half of
      // BLOCKER 1 the job row cannot express on its own. Written as exactly
      // what adopt() would write for it, so the in-process close and the
      // next-launch one cannot disagree. Guarded on `disposed` rather than on
      // `!owns()`: if a LATER run took this id, these rows are its rows now.
      if (state.disposed) {
        if (handle !== null) {
          // A DETACHED host is not abandoned, and this is the whole of what B2
          // buys. The command is running in its own session with no controlling
          // terminal; the window going away reaches nothing. The row keeps
          // saying `detached` with its marker, the offsets are brought up to
          // date, and reclaim() picks it up at the next launch and carries on
          // reading from the byte it had got to.
          store.updateJobTarget(req.jobId, serverId, {
            detached: handle,
            outOffset: out.bytes,
            outElided: out.elided
          })
        } else {
          store.updateJobTarget(req.jobId, serverId, {
            state: 'failed',
            outcome: 'abandoned',
            error: JOB_ABANDONED_ERROR,
            endedAt: this.now,
            outOffset: out.bytes,
            outElided: out.elided
          })
        }
      }
      return
    }

    const endedAt = this.now
    // A step that did not exit zero puts its own number on the row. `result` is
    // overwritten per step, so without this the row carries an exit code with
    // no subject: nothing says which of three commands produced it and nothing
    // says the ones after it never ran.
    const stepNote =
      totalSteps > 1 && failure === null && result !== null && (!result.ok || (result.code ?? 0) !== 0)
        ? stepFailureNote(stepIndex, totalSteps, stepCommand, result.code)
        : null
    // Redacted like every other byte that leaves this host, and for the same
    // reason: a transport error routinely carries the connection string it
    // failed on, and it lands in the same row of the same file on disk as the
    // output that WAS scrubbed. The rules are pattern-only here — the resolved
    // secrets are applied too, via `secrets`.
    const scrub = (text: string | undefined | null): string | undefined =>
      text === undefined || text === null || text === '' ? undefined : redactOutput(text, secrets)
    const host: JobHostResult =
      failure !== null
        ? {
            serverId,
            serverName,
            state: 'failed',
            error: scrub(failure),
            startedAt,
            endedAt,
            ms: endedAt - startedAt
          }
        : {
            serverId,
            serverName,
            // A non-zero exit is a result, not an error — broadcast's rule,
            // unchanged. `grep` finding nothing exits 1, and calling that a
            // failure would make half the useful commands look broken.
            //
            // `finalState` overrides it, and only an executor can know when it
            // applies: `orphaned` is neither a success nor a failure of the
            // command, it is the absence of an answer, and deriving it from an
            // exit code that was never written is not possible from here.
            state: result?.finalState ?? (result?.ok ? 'ok' : 'failed'),
            exitCode: result?.code ?? undefined,
            error: scrub([result?.error, stepNote].filter((x) => x).join(' ')),
            startedAt,
            endedAt,
            ms: endedAt - startedAt
          }
    host.outOffset = out.bytes
    host.outElided = out.elided
    host.truncated = out.elided > 0 || result?.truncated || undefined
    // Classified from the UNCAPPED streams, for the reason broadcast gives:
    // the shell's "command not found" is the last thing on stderr, and a host
    // that printed 20k of warnings first would have had it cut off before
    // anyone could read it.
    //
    // `clsOut`/`clsErr` are the fallback, and they are what makes a STREAMING
    // executor classifiable at all: it hands its output to the runner as it
    // arrives and returns nothing, so `result.stdout` is empty and every
    // failing command would classify as `nonzero` — no `missing-command`, no
    // `permission-denied`. A batch executor still wins, because it has the
    // whole of both streams and the buffers only hold the tail.
    //
    // `mergedOutput` is the detached path's: its wrapper redirects stderr into
    // stdout to keep the two in order, so `clsErr` is empty by construction and
    // the classifier is pointed at the merged tail instead. Without that, every
    // failing detached command would come back `nonzero` and `missing-command`
    // would be a category nothing could ever reach.
    host.outcome =
      result?.finalOutcome ??
      classifyJobResult({
        ...host,
        stdout: result?.stdout || out.clsOut,
        stderr: result?.stderr || (result?.mergedOutput ? out.clsOut : out.clsErr)
      }) ??
      undefined
    // `undefined` leaves the row's marker alone; `null` clears it. A finished
    // detached step clears it because the directory has been reaped and a
    // handle pointing at nothing would send the next reclaim looking for it.
    if (result?.detachedHandle !== undefined) handle = result.detachedHandle
    host.detached = handle

    store.updateJobTarget(req.jobId, serverId, {
      state: host.state,
      outcome: host.outcome ?? null,
      exitCode: host.exitCode ?? null,
      error: host.error ?? null,
      endedAt,
      outOffset: out.bytes,
      outElided: out.elided,
      detached: handle
    })
    this.emitHost(req.jobId, host)
  }

  // ------------------------------------------------------------- output

  /**
   * One chunk of a host's output: redacted, persisted under the head+tail
   * policy, and queued for the renderer.
   *
   * Redaction happens HERE, before anything is written or sent, exactly as
   * recordAudit does it. A secret that reaches the store is a secret in a file
   * on disk that outlives the session, and a redaction applied on read is one
   * `SELECT` away from being skipped.
   */
  private pushOutput(
    jobId: string,
    serverId: string,
    out: HostOutput,
    stream: 'out' | 'err',
    raw: string,
    secrets: string[],
    owns: () => boolean,
    /** The host is finished: emit what is being held back rather than waiting
     *  for a boundary that is never coming. */
    final = false
  ): void {
    // A superseded or disposed run must not write rows or paint a pane: an
    // executor's channel can still deliver buffered data after the run that
    // owned it has gone.
    if (!owns()) return

    // REDACTION IS APPLIED ACROSS THE CHUNK SEAM, not within one chunk.
    //
    // The order was already right — redact, then split for the head/tail — but
    // each chunk was redacted alone, and a socket boundary does not respect a
    // regex. `DB_PASSWORD=` ending one chunk and `hunter2` starting the next
    // matches no rule, and both halves are persisted verbatim. So the trailing
    // PARTIAL LINE is held back and prepended to whatever comes next: every
    // pattern rule but one is single-line, and holding only a partial line
    // costs nothing for output that ends in a newline, which is nearly all of
    // it.
    const buffered = out.carry[stream] + raw
    let ready = buffered
    let held = ''
    if (!final) {
      // `\r` as well as `\n`: a progress bar redrawing in place ends each
      // redraw with one, and holding those would leave the pane blank through
      // the download half of an upgrade.
      const nl = Math.max(buffered.lastIndexOf('\n'), buffered.lastIndexOf('\r'))
      const cut = nl >= 0 ? nl + 1 : 0
      ready = buffered.slice(0, cut)
      held = buffered.slice(cut)
      // Output that ends at neither — a prompt waiting on input — must not be
      // held for the whole run. Bounded, then released.
      if (Buffer.byteLength(held, 'utf8') > JOB_REDACT_LINE_CARRY) {
        ready = buffered
        held = ''
      } else {
        // The PEM rule is the one that spans lines, and the one whose failure
        // costs a private key rather than a password. Hold from an
        // unterminated BEGIN so the block is matched whole.
        const begin = ready.lastIndexOf('-----BEGIN ')
        if (begin >= 0 && ready.indexOf('-----END ', begin) < 0) {
          const block = ready.slice(begin) + held
          // Capped: a BEGIN with no END behind it must not buffer the host's
          // entire output waiting for one.
          if (Buffer.byteLength(block, 'utf8') <= JOB_REDACT_BLOCK_CARRY) {
            held = block
            ready = ready.slice(0, begin)
          }
        }
      }
    }
    out.carry[stream] = held
    if (ready === '') return

    const text = redactOutput(ready, secrets)
    const at = this.now

    // The tail of each stream, for classifyJobResult. See JOB_CLASSIFY_BYTES.
    if (stream === 'out') out.clsOut = keepTail(out.clsOut + text, JOB_CLASSIFY_BYTES)
    else out.clsErr = keepTail(out.clsErr + text, JOB_CLASSIFY_BYTES)

    // The cap is applied WITHIN a chunk, not between chunks, and that is not a
    // refinement — it is the difference between working and not. The attached
    // executor has no stream: it hands the whole of a host's output over in one
    // piece at the end. A cap that only compared whole chunks against the head
    // budget would see one chunk, find the head empty, and write all five
    // megabytes of it — the exact unbounded write the budget exists to prevent,
    // on the one code path B1 actually ships.
    let rest = text
    if (out.headBytes < JOB_OUTPUT_HEAD) {
      const [head, overflow] = splitAtBytes(rest, JOB_OUTPUT_HEAD - out.headBytes)
      if (head !== '') {
        // The head is written straight through. Durability where it is
        // cheapest: if the app dies mid-run, what survives is the beginning of
        // the output, which is what says which command was running and on what.
        const n = Buffer.byteLength(head, 'utf8')
        out.headBytes += n
        out.bytes += n
        this.deps.store.appendJobOutput(jobId, serverId, [
          { serverId, seq: out.seq++, at, stream, text: head }
        ])
      }
      rest = overflow
    }

    if (rest !== '') {
      // Past the head, output goes into a ring holding the last
      // JOB_OUTPUT_TAIL bytes, and what falls out of it is COUNTED. The middle
      // of an apt run is download progress: the least informative bytes in the
      // file and by far the most of them. The end is where the answer is.
      let bytes = Buffer.byteLength(rest, 'utf8')
      if (bytes > JOB_OUTPUT_TAIL) {
        // One chunk bigger than the whole tail budget — again, the batch
        // executor's normal case. Keep its last JOB_OUTPUT_TAIL bytes.
        const [gone, kept] = splitAtBytes(rest, bytes - JOB_OUTPUT_TAIL)
        out.elided += Buffer.byteLength(gone, 'utf8')
        rest = kept
        bytes = Buffer.byteLength(rest, 'utf8')
      }
      out.tail.push({ serverId, seq: -1, at, stream, text: rest })
      out.tailBytes += bytes
      while (out.tailBytes > JOB_OUTPUT_TAIL && out.tail.length > 1) {
        const dropped = out.tail.shift() as JobOutputLine
        const n = Buffer.byteLength(dropped.text, 'utf8')
        out.tailBytes -= n
        out.elided += n
      }
    }

    // The renderer gets ALL of it, uncapped. The cap is a storage policy — what
    // is worth keeping on disk for a month — and not a decision about what a
    // person watching the job right now is allowed to see. The rate limiter
    // below is what protects the pane.
    out.pending.push({ stream, text })
    if (!out.scheduled) {
      out.scheduled = true
      this.schedule(() => this.flushPending(jobId, serverId, out, owns))
    }
  }

  /**
   * Send one tick's worth of output to the renderer.
   *
   * Coalesced, not per line: a job emitting apt output one message per line is
   * an IPC flood, and the flood is indistinguishable from a freeze. Consecutive
   * chunks on the same stream are joined; a switch between stdout and stderr
   * starts a new message, because merging them would lose which one said what
   * and that is the only question an error is read for.
   */
  private flushPending(jobId: string, serverId: string, out: HostOutput, owns: () => boolean): void {
    out.scheduled = false
    if (!owns()) {
      out.pending = []
      return
    }
    const batches: { stream: 'out' | 'err'; text: string }[] = []
    for (const p of out.pending) {
      const last = batches[batches.length - 1]
      if (last && last.stream === p.stream) last.text += p.text
      else batches.push({ stream: p.stream, text: p.text })
    }
    out.pending = []

    const at = this.now
    if (at - out.windowStart >= 1000) {
      out.windowStart = at
      out.inWindow = 0
    }
    for (const b of batches) {
      if (out.inWindow >= JOB_OUTPUT_RATE_PER_SEC) {
        // Counted, never silently discarded. The count rides on the next event
        // that does go out, and on the flush at the end of the host's run, so
        // the last window's drops have somewhere to go — the gap logTail's
        // counter exists to explain.
        out.dropped++
        continue
      }
      out.inWindow++
      const event: JobOutput = { jobId, serverId, at, stream: b.stream, text: b.text }
      if (out.dropped > 0) {
        event.dropped = out.dropped
        out.dropped = 0
      }
      this.deps.emitOutput(event)
    }
    this.announceDrops(jobId, serverId, out)
  }

  /**
   * Say what the rate limiter threw away, when nothing else will.
   *
   * The count normally rides on the next event that does go out. A window that
   * dropped EVERYTHING it was offered — and the last window of a host that then
   * stops producing output — has no such event, and that is exactly the case
   * the counter exists for: a gap nobody mentions is how someone concludes the
   * upgrade hung. So it goes out on its own, with empty text, which a reader
   * renders as the notice and not as a line the host printed.
   */
  private announceDrops(jobId: string, serverId: string, out: HostOutput): void {
    if (out.dropped === 0) return
    const dropped = out.dropped
    out.dropped = 0
    this.deps.emitOutput({ jobId, serverId, at: this.now, stream: 'err', text: '', dropped })
  }

  /**
   * Write the tail, with a notice where the middle used to be.
   *
   * The elision is a ROW, not a flag on a row: a reader scrolling a host's
   * output has to see the gap where it is, in order, rather than be told
   * somewhere else that one exists. `out_elided` on the target row is the
   * machine-readable half of the same fact.
   */
  private flushTail(jobId: string, serverId: string, out: HostOutput, owns: () => boolean): void {
    // Guarded like flushPending, which the file header already claims of every
    // post-await step. Without it a disposed run wrote the whole tail ring —
    // rows appearing under a target the same pass then declined to update, so
    // the output said one thing and out_offset said the host had produced
    // nothing.
    if (!owns()) {
      out.tail = []
      out.tailBytes = 0
      return
    }
    if (out.tail.length === 0) return
    const rows: JobOutputLine[] = []
    if (out.elided > 0) {
      const notice = elisionNotice(out.elided)
      rows.push({ serverId, seq: out.seq++, at: this.now, stream: 'err', text: notice })
      out.bytes += Buffer.byteLength(notice, 'utf8')
    }
    for (const l of out.tail) {
      rows.push({ ...l, seq: out.seq++ })
      out.bytes += Buffer.byteLength(l.text, 'utf8')
    }
    out.tail = []
    out.tailBytes = 0
    this.deps.store.appendJobOutput(jobId, serverId, rows)
  }

  /**
   * Stops every in-flight job. Called when the window goes and at quit.
   *
   * Queued hosts do not start. Hosts already executing are left alone, exactly
   * as cancel() leaves them, and their rows are NOT closed as though the run
   * had finished — see RunState.disposed. What this leaves behind is a job row
   * still saying `running` with a target row saying the same, which is
   * precisely what adopt() reads at the next launch and closes as `abandoned`.
   */
  disposeAll(): void {
    for (const run of this.active.values()) {
      run.cancelled = true
      run.disposed = true
    }
    this.active.clear()
  }
}

/**
 * Split `text` so the first piece is at most `budget` BYTES, never mid-code-point.
 *
 * Bytes rather than characters, because the budget is a disk budget and a
 * character is between one and four of them — a cap counted in UTF-16 units
 * would be a cap that means something different depending on the host's locale.
 *
 * The back-up loop is what keeps a split off the middle of a code point. UTF-8
 * continuation bytes are `10xxxxxx`, so walking back while the byte AT the cut
 * is one lands on the start of a character. Without it, a boundary landing
 * inside a multi-byte sequence produces a replacement character on BOTH sides
 * of the seam — visible corruption in output someone is reading to find out
 * what went wrong.
 */
/** The last `budget` bytes of `text`, never splitting a code point. */
function keepTail(text: string, budget: number): string {
  if (Buffer.byteLength(text, 'utf8') <= budget) return text
  return splitAtBytes(text, Buffer.byteLength(text, 'utf8') - budget)[1]
}

/**
 * Is this row a detached step somebody can pick up?
 *
 * BOTH halves are required. A handle without a live state is a finished host
 * whose marker was left behind for a foreign instance — re-watching it would
 * poll a directory this build may not reap. A live state without a handle is
 * B1's attached row, which adopt() closes as `abandoned` because that is what
 * really happened to it.
 */
function reclaimable(t: JobHostResult): boolean {
  return isJobDetachedHandle(t.detached) && (t.state === 'detached' || t.state === 'rebooting')
}

export function splitAtBytes(text: string, budget: number): [string, string] {
  if (budget <= 0) return ['', text]
  const buf = Buffer.from(text, 'utf8')
  if (buf.length <= budget) return [text, '']
  let cut = budget
  while (cut > 0 && (buf[cut] & 0xc0) === 0x80) cut--
  return [buf.subarray(0, cut).toString('utf8'), buf.subarray(cut).toString('utf8')]
}

/** Re-exported so main/index.ts and the tests name one thing. */
export type { JobSpec }
