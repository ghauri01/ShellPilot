import type {
  BroadcastHostResult,
  BroadcastProgress,
  BroadcastRequest
} from '../../shared/broadcast'
import {
  BROADCAST_CONCURRENCY,
  BROADCAST_OUTPUT_CAP,
  BROADCAST_STALL_GRACE_MS,
  BROADCAST_TIMEOUT_MS
} from '../../shared/broadcast'

// Runs one command across many servers.
//
// The approval model lives in shared/broadcast.ts and was settled first; this
// file is the easy half, and its job is to not undermine that model. Three
// things it must get right:
//
//  1. Cancel means hosts that have not started never start. A broadcast you
//     cannot stop is precisely the failure the confirmation exists to prevent,
//     so a cancel that only stops "eventually" would give the model away.
//  2. Bounded concurrency, for the same reason the fleet sweep is sequential:
//     fifteen hosts behind two bastions is fifteen exec channels through two
//     machines an operator cannot afford to wobble. Three at a time.
//  3. Per-host results, always. One host failing must not end the run, and
//     merged output loses which machine said what — the only question anyone
//     asks afterwards.

export type Executor = (
  cfg: unknown,
  command: string,
  timeoutMs: number
) => Promise<{ ok: boolean; code?: number | null; stdout?: string; stderr?: string; error?: string; truncated?: boolean }>

export interface BroadcastDeps {
  exec: Executor
  emit: (progress: BroadcastProgress) => void
  now?: () => number
  /** Overridable for tests; see BROADCAST_STALL_GRACE_MS. */
  stallGraceMs?: number
}

function cap(text: string | undefined): { text: string; truncated: boolean } {
  const s = text ?? ''
  return s.length > BROADCAST_OUTPUT_CAP
    ? { text: s.slice(0, BROADCAST_OUTPUT_CAP), truncated: true }
    : { text: s, truncated: false }
}

export class BroadcastRunner {
  // Runs keyed by id so a cancel can name which one it means. A second run
  // starting does not invalidate the first: they are independent, and silently
  // cancelling one because another began would lose results the user is
  // watching.
  private active = new Map<string, { cancelled: boolean }>()

  constructor(private readonly deps: BroadcastDeps) {}

  private get now(): number {
    return (this.deps.now ?? Date.now)()
  }

  /** True while the given run is still executing. */
  isRunning(runId: string): boolean {
    return this.active.has(runId)
  }

  /**
   * Stop a run. Hosts already executing are left to finish — killing a command
   * mid-write is how you get a half-applied change, which is worse than the
   * command completing. Hosts not yet started are reported `skipped` so the
   * result list stays complete rather than simply ending early.
   */
  cancel(runId: string): boolean {
    const run = this.active.get(runId)
    if (!run) return false
    run.cancelled = true
    return true
  }

  /**
   * Reject an executor that never settles.
   *
   * The per-host timeout belongs to `sshExec`, and its timer starts only once
   * the connection is up — so connection setup is not covered by it at all. An
   * exec that never resolves used to leave the worker awaiting forever: no
   * result for that host, no terminal event for any of them, `active` never
   * cleared, and a Stop button that cannot help because cancel deliberately
   * leaves a running host alone. Whatever else is true, the run must end.
   */
  private stallGuard<T>(p: Promise<T>, ms: number, message: string): Promise<T> {
    let timer: ReturnType<typeof setTimeout> | undefined
    const guard = new Promise<never>((_resolve, reject) => {
      timer = setTimeout(() => reject(new Error(message)), ms)
      // The run is over as far as the user is concerned; do not hold the
      // process open waiting to say so.
      if (typeof timer.unref === 'function') timer.unref()
    })
    // Promise.race attaches its own handlers to `p`, so an exec that settles
    // after the guard fired is not an unhandled rejection.
    return Promise.race([p, guard]).finally(() => clearTimeout(timer))
  }

  async run(req: BroadcastRequest): Promise<BroadcastHostResult[]> {
    const timeoutMs = req.timeoutMs ?? BROADCAST_TIMEOUT_MS
    // Two runs under one id is not a second broadcast, it is one broadcast the
    // user can no longer address: cancel names a single id, progress events
    // carry a single id, and the first run to finish would delete the other's
    // entry — leaving a live run that cannot be cancelled and a Stop button
    // that silently does nothing.
    if (this.active.has(req.runId)) {
      throw new Error(`a broadcast with id ${req.runId} is already running`)
    }
    const state = { cancelled: false }
    this.active.set(req.runId, state)

    const results: BroadcastHostResult[] = []
    const queue = [...req.targets]

    const runOne = async (t: BroadcastRequest['targets'][number]): Promise<void> => {
      // Checked again here rather than only at dequeue: a cancel landing while
      // an earlier host was still running must stop this one before it opens a
      // channel.
      if (state.cancelled) {
        const skipped: BroadcastHostResult = {
          serverId: t.serverId,
          serverName: t.serverName,
          state: 'skipped'
        }
        results.push(skipped)
        this.deps.emit({ runId: req.runId, host: skipped, cancelled: true })
        return
      }

      const started = this.now
      this.deps.emit({
        runId: req.runId,
        host: { serverId: t.serverId, serverName: t.serverName, state: 'running' }
      })

      let host: BroadcastHostResult
      try {
        const r = await this.stallGuard(
          this.deps.exec(t.cfg, req.command, timeoutMs),
          timeoutMs + (this.deps.stallGraceMs ?? BROADCAST_STALL_GRACE_MS),
          `${t.serverName} never answered — giving up so the rest of the run can finish`
        )
        const out = cap(r.stdout)
        const err = cap(r.stderr)
        host = {
          serverId: t.serverId,
          serverName: t.serverName,
          // A non-zero exit is a result, not an error: `grep` finding nothing
          // exits 1, and calling that a failure would make half the useful
          // commands look broken. Only an unreachable host or a timeout is a
          // failure.
          state: r.ok ? 'ok' : 'failed',
          exitCode: r.code ?? undefined,
          stdout: out.text,
          stderr: err.text,
          error: r.error,
          ms: this.now - started,
          truncated: out.truncated || err.truncated || r.truncated || undefined
        }
      } catch (e) {
        // One unreachable host must not end the run — the others are the
        // reason it was started.
        host = {
          serverId: t.serverId,
          serverName: t.serverName,
          state: 'failed',
          error: e instanceof Error ? e.message : String(e),
          ms: this.now - started
        }
      }
      results.push(host)
      this.deps.emit({ runId: req.runId, host })
    }

    // A small pool rather than Promise.all over everything.
    const workers = Array.from({ length: Math.min(BROADCAST_CONCURRENCY, queue.length) }, async () => {
      for (;;) {
        const next = queue.shift()
        if (!next) return
        await runOne(next)
      }
    })

    try {
      await Promise.all(workers)
    } finally {
      // Only if this run still owns the entry. disposeAll clears the map, and a
      // deletion that does not check identity would drop somebody else's live
      // run out of reach of cancel.
      if (this.active.get(req.runId) === state) this.active.delete(req.runId)
      // A terminal event always fires, including on cancel and on an empty
      // target list, so the renderer never waits forever for a run that has
      // already stopped.
      this.deps.emit({
        runId: req.runId,
        host: { serverId: '', serverName: '', state: 'pending' },
        done: true,
        cancelled: state.cancelled || undefined
      })
    }
    return results
  }

  /** Cancels every in-flight run. Called on shutdown. */
  disposeAll(): void {
    for (const run of this.active.values()) run.cancelled = true
    this.active.clear()
  }
}
