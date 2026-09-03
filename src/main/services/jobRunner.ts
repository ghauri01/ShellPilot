import type { JobPatch, JobTargetPatch, NewJob } from './history'
import type {
  JobDetail,
  JobHostResult,
  JobOutput,
  JobOutputLine,
  JobProgress,
  JobRecord,
  JobRunRequest,
  JobSpec
} from '../../shared/jobs'
import {
  JOB_ABANDONED_ERROR,
  JOB_CONCURRENCY,
  JOB_OUTPUT_HEAD,
  JOB_OUTPUT_RATE_PER_SEC,
  JOB_OUTPUT_TAIL,
  JOB_STALL_GRACE_MS,
  JOB_STEP_TIMEOUT_MS,
  classifyJobResult,
  elisionNotice,
  planJob
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
  truncated?: boolean
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
}

export class JobRunner {
  /**
   * Runs keyed by job id. A second run under a live id is refused rather than
   * silently joined: cancel names one id, every progress event carries one id,
   * and the first to finish would delete the other's entry — leaving a live job
   * that cannot be cancelled and a Stop button that does nothing.
   */
  private active = new Map<string, RunState>()

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
      for (const t of job.targets) {
        if (t.state === 'running') {
          this.deps.store.updateJobTarget(job.id, t.serverId, {
            state: 'failed',
            outcome: 'abandoned',
            error: JOB_ABANDONED_ERROR,
            endedAt: at
          })
        } else if (t.state === 'pending' || t.state === 'waiting') {
          this.deps.store.updateJobTarget(job.id, t.serverId, {
            state: 'skipped',
            outcome: 'abandoned',
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
    const state: RunState = { cancelled: false }
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
      if (this.active.get(req.jobId) === state) this.active.delete(req.jobId)
      const endedAt = this.now
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
    owns: () => boolean
  ): Promise<void> {
    const store = this.deps.store
    const { serverId, serverName } = target

    if (state.cancelled) {
      this.markSkipped(req.jobId, target)
      return
    }

    const startedAt = this.now
    store.updateJobTarget(req.jobId, serverId, { state: 'running', startedAt })
    this.emitHost(req.jobId, { serverId, serverName, state: 'running', startedAt })

    const out: HostOutput = {
      seq: 0,
      bytes: 0,
      elided: 0,
      headBytes: 0,
      tail: [],
      tailBytes: 0,
      pending: [],
      scheduled: false,
      windowStart: startedAt,
      inWindow: 0,
      dropped: 0
    }
    const secrets = this.deps.knownSecrets?.(target.cfg) ?? []

    let result: JobExecResult | null = null
    let failure: string | null = null

    // Steps run in order and stop at the first one that does not exit zero —
    // `a && b` semantics, because that is what a person typing them means. A
    // job whose second step ran after its first failed is a job that did
    // something nobody asked for. B1 ships one step; the loop is here because
    // the spec type carries a list and quietly running only the first would be
    // a lie told by the type.
    for (const step of req.spec.steps) {
      if (!owns()) break
      const timeoutMs = step.timeoutMs ?? JOB_STEP_TIMEOUT_MS
      try {
        const r = await this.stallGuard(
          this.deps.exec({
            cfg: target.cfg,
            command: step.command,
            timeoutMs,
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
        if (!r.ok || (r.code ?? 0) !== 0) break
      } catch (e) {
        // One unreachable host must not end the job — the others are the reason
        // it was started.
        failure = e instanceof Error ? e.message : String(e)
        break
      }
    }

    // Whatever the rate limiter and the tail buffer are still holding is the
    // last thing anyone gets to see. Flushed BEFORE the terminal state is
    // written, so a reader that stops at "this host is done" has all of it.
    this.flushPending(req.jobId, serverId, out, owns)
    this.flushTail(req.jobId, serverId, out)

    if (!owns()) return

    const endedAt = this.now
    const host: JobHostResult =
      failure !== null
        ? {
            serverId,
            serverName,
            state: 'failed',
            error: failure,
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
            state: result?.ok ? 'ok' : 'failed',
            exitCode: result?.code ?? undefined,
            error: result?.error,
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
    host.outcome =
      classifyJobResult({
        ...host,
        stdout: result?.stdout ?? '',
        stderr: result?.stderr ?? ''
      }) ?? undefined

    store.updateJobTarget(req.jobId, serverId, {
      state: host.state,
      outcome: host.outcome ?? null,
      exitCode: host.exitCode ?? null,
      error: host.error ?? null,
      endedAt,
      outOffset: out.bytes,
      outElided: out.elided
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
    owns: () => boolean
  ): void {
    // A superseded or disposed run must not write rows or paint a pane: an
    // executor's channel can still deliver buffered data after the run that
    // owned it has gone.
    if (!owns() || raw === '') return
    const text = redactOutput(raw, secrets)
    const at = this.now

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
  private flushTail(jobId: string, serverId: string, out: HostOutput): void {
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

  /** Cancels every in-flight job. Called on shutdown. */
  disposeAll(): void {
    for (const run of this.active.values()) run.cancelled = true
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
