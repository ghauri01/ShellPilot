import type { LogLine, LogSource, LogTailState } from '../../shared/logtail'
import { LOG_LINE_CAP, LOG_RATE_PER_SEC, buildTailCommand, validateLogSource } from '../../shared/logtail'

// Streams a following log from one or more hosts.
//
// Unlike sshExec this never completes on its own — `journalctl -f` runs until
// killed — so everything here is about ending cleanly. A tail that keeps a
// channel open after the user closed the pane is a connection leak that looks
// like nothing, and fifteen of them is an estate wondering why its sshd is
// busy.
//
// Rate limiting is per host and deliberate. A misconfigured service can emit
// tens of thousands of lines a second; without a cap that becomes an IPC flood
// that wedges the renderer, and the user's conclusion is "ShellPilot froze"
// rather than "that service is screaming".

export type StreamExec = (
  cfg: unknown,
  command: string,
  handlers: {
    onStdout: (chunk: string) => void
    onStderr: (chunk: string) => void
    onClose: (code: number | null) => void
    onError: (message: string) => void
  }
) => Promise<() => void>

export interface LogTailDeps {
  execStream: StreamExec
  emitLine: (line: LogLine) => void
  emitState: (state: LogTailState) => void
  now?: () => number
}

interface Active {
  stop: () => void
  /** Emits anything the rate limiter is still holding, before the tail ends. */
  flush: () => void
  serverId: string
}

export class LogTailer {
  private active = new Map<string, Active[]>()

  constructor(private readonly deps: LogTailDeps) {}

  private get now(): number {
    return (this.deps.now ?? Date.now)()
  }

  isActive(tailId: string): boolean {
    return this.active.has(tailId)
  }

  async start(
    tailId: string,
    source: LogSource,
    targets: { serverId: string; serverName: string; cfg: unknown }[]
  ): Promise<{ ok: boolean; error?: string }> {
    // Validated here as well as in the renderer. The renderer is where the
    // message is useful, but main is where the command is actually built, and
    // a boundary that trusts its caller to have checked is one refactor away
    // from not being checked at all.
    const v = validateLogSource(source)
    if (!v.ok) return { ok: false, error: v.error }

    // Starting a tail that is already running would silently double every line.
    if (this.active.has(tailId)) this.stop(tailId)

    const command = buildTailCommand(source)
    const running: Active[] = []
    this.active.set(tailId, running)
    // Identity, not `has(tailId)`: opening a channel is awaited per host, so a
    // second start under the same id can land while this one is still in that
    // await. Everything after an await therefore asks whether this invocation
    // is still the one that owns the id. Without it the superseded start would
    // go on opening channels, push their stop handles onto an array nobody
    // holds any more — a channel per host that no stop() can ever reach — and
    // emit its lines under the live tailId, which is the doubled stream the
    // restart-guard above exists to prevent.
    const owns = (): boolean => this.active.get(tailId) === running

    for (const t of targets) {
      if (!owns()) break
      this.deps.emitState({ tailId, serverId: t.serverId, serverName: t.serverName, state: 'starting' })

      let seq = 0
      let windowStart = this.now
      let inWindow = 0
      let dropped = 0
      // Partial lines are normal: a chunk boundary lands mid-line constantly,
      // and emitting the halves separately makes a log unreadable in exactly
      // the moments it matters.
      let carry = ''

      const notice = (text: string, at: number): void =>
        this.deps.emitLine({
          tailId,
          serverId: t.serverId,
          serverName: t.serverName,
          seq: seq++,
          text,
          isError: true,
          at
        })

      // The drop count is only reported when a *later* line arrives to close
      // the window, so the last window's count had nowhere to go: a host that
      // screams and then stops — or that is stopped by the user — left the pane
      // showing exactly LOG_RATE_PER_SEC lines and no explanation, which is the
      // silent gap this counter exists to avoid.
      const flushDrops = (): void => {
        if (dropped === 0) return
        notice(`— ${dropped} lines dropped, this host is logging faster than the pane can show —`, this.now)
        dropped = 0
      }

      const push = (text: string, isError: boolean): void => {
        // A superseded or stopped tail must not paint the pane: its channel may
        // still deliver buffered data after stop() has been called.
        if (!owns()) return
        const now = this.now
        if (now - windowStart >= 1000) {
          flushDrops()
          windowStart = now
          inWindow = 0
        }
        if (inWindow >= LOG_RATE_PER_SEC) {
          // Counted and reported at the end of the window rather than silently
          // discarded: a gap nobody mentions is how someone concludes a service
          // stopped logging.
          dropped++
          return
        }
        inWindow++
        this.deps.emitLine({
          tailId,
          serverId: t.serverId,
          serverName: t.serverName,
          seq: seq++,
          text,
          isError: isError || undefined,
          at: now
        })
      }

      // Nothing guarantees a newline ever arrives, so a line longer than the
      // cap is emitted in pieces rather than buffered: the buffer is memory in
      // main sized by whatever the remote host feels like sending.
      const pushCapped = (text: string, isError: boolean): void => {
        if (text.length <= LOG_LINE_CAP) {
          push(text, isError)
          return
        }
        for (let i = 0; i < text.length; i += LOG_LINE_CAP) push(text.slice(i, i + LOG_LINE_CAP), isError)
      }

      const feed = (chunk: string, isError: boolean): void => {
        const parts = (carry + chunk).split('\n')
        carry = parts.pop() ?? ''
        for (const line of parts) pushCapped(line.replace(/\r$/, ''), isError)
        while (carry.length > LOG_LINE_CAP) {
          push(carry.slice(0, LOG_LINE_CAP), isError)
          carry = carry.slice(LOG_LINE_CAP)
        }
      }

      try {
        const stop = await this.deps.execStream(t.cfg, command, {
          onStdout: (c) => feed(c, false),
          onStderr: (c) => feed(c, true),
          onClose: () => {
            if (carry !== '') {
              pushCapped(carry, false)
              carry = ''
            }
            flushDrops()
            // A channel belonging to a superseded start closing must not report
            // "ended" for a host the current tail is streaming from.
            if (owns()) {
              this.deps.emitState({ tailId, serverId: t.serverId, serverName: t.serverName, state: 'ended' })
            }
          },
          onError: (message) => {
            if (!owns()) return
            this.deps.emitState({ tailId, serverId: t.serverId, serverName: t.serverName, state: 'failed', error: message })
          }
        })
        if (!owns()) {
          // Superseded while this channel was opening. Close it here — nothing
          // else holds the handle — and stop before touching the newer run's
          // state.
          try {
            stop()
          } catch {
            /* already gone */
          }
          return { ok: false, error: 'This tail was restarted while it was starting.' }
        }
        running.push({ stop, flush: flushDrops, serverId: t.serverId })
        this.deps.emitState({ tailId, serverId: t.serverId, serverName: t.serverName, state: 'streaming' })
      } catch (e) {
        if (!owns()) return { ok: false, error: 'This tail was restarted while it was starting.' }
        // One host refusing must not stop the others — comparing a failing host
        // against a working one is most of why this reads several at once.
        this.deps.emitState({
          tailId,
          serverId: t.serverId,
          serverName: t.serverName,
          state: 'failed',
          error: e instanceof Error ? e.message : String(e)
        })
      }
    }

    if (!owns()) return { ok: false, error: 'This tail was restarted while it was starting.' }
    if (running.length === 0) {
      this.active.delete(tailId)
      return { ok: false, error: 'No host accepted the tail.' }
    }
    return { ok: true }
  }

  stop(tailId: string): void {
    const running = this.active.get(tailId)
    if (!running) return
    for (const r of running) {
      // Before the channel goes, and before the id is forgotten: whatever the
      // rate limiter is still holding is the last thing the user gets to see,
      // and losing it turns a throttled burst into an unexplained gap.
      try {
        r.flush()
      } catch {
        /* a flush must never keep a channel open */
      }
      try {
        r.stop()
      } catch {
        // A channel that is already gone is the expected case on shutdown, and
        // one throwing must not strand the rest still open.
      }
    }
    this.active.delete(tailId)
  }

  disposeAll(): void {
    for (const id of [...this.active.keys()]) this.stop(id)
  }
}
