import type { LogDiagnosis, LogLine, LogSource, LogTailState, UnitChoice } from '../../shared/logtail'
import {
  LOG_LINE_CAP,
  LOG_PAUSE_BUFFER,
  LOG_RATE_PER_SEC,
  buildTailCommand,
  buildUnitListCommand,
  diagnoseLogTail,
  parseUnitList,
  parseLogMark,
  validateLogSource
} from '../../shared/logtail'

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
//
// Two things arrive on the same channel: the preflight's facts, and then the
// log. They are told apart by ORDER — see LOG_MARK — and the facts are turned
// into a diagnosis that rides on the host's STATE rather than being written
// into the stream. A tail is long-lived, and a notice written once as a log
// line ("reading as root") has scrolled away within the second.

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
  /** Emits anything still held — throttled drops and the paused buffer alike. */
  flush: () => void
  /** Emits the paused buffer only. */
  drain: () => void
  serverId: string
}

export class LogTailer {
  private active = new Map<string, Active[]>()
  /**
   * Tails whose stream is held rather than stopped.
   *
   * Separate from `active` because a paused tail is still a running tail: the
   * channel is open, the remote command is still following, and Stop still
   * means Stop. Conflating them is how "pause" becomes "lose the buffer", which
   * is the thing pause exists to avoid.
   */
  private paused = new Set<string>()

  constructor(private readonly deps: LogTailDeps) {}

  private get now(): number {
    return (this.deps.now ?? Date.now)()
  }

  isActive(tailId: string): boolean {
    return this.active.has(tailId)
  }

  isPaused(tailId: string): boolean {
    return this.paused.has(tailId)
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
    // It also clears any hold, which is what keeps a restart from being a
    // resume: a new stream arriving into the old one's pause would sit there
    // empty with nothing on screen to say why.
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

      let seq = 0
      let windowStart = this.now
      let inWindow = 0
      let dropped = 0
      // Partial lines are normal: a chunk boundary lands mid-line constantly,
      // and emitting the halves separately makes a log unreadable in exactly
      // the moments it matters.
      let carry = ''
      // What the preflight said, and whether it is over. Only lines before
      // `begin` may be read as facts; the tail is not exec'd until `begin` has
      // been printed, so nothing a remote log says can ever be in a position to
      // claim, for instance, that it was read as root.
      const facts: Record<string, string> = {}
      let preflightDone = false
      let diagnosis: LogDiagnosis | undefined
      let held: LogLine[] = []
      let heldDropped = 0

      // Every state for this host carries the diagnosis once there is one. The
      // preflight's facts can land before execStream has even resolved, so an
      // emit that only attached the diagnosis at the moment it was computed
      // would be overwritten a moment later by the plain `streaming` below —
      // and the panel, which keeps the last state per host, would lose it.
      const emit = (state: LogTailState['state'], extra: Partial<LogTailState> = {}): void =>
        this.deps.emitState({
          tailId,
          serverId: t.serverId,
          serverName: t.serverName,
          state,
          ...(diagnosis ? { diagnosis } : {}),
          ...(this.paused.has(tailId) ? { paused: true } : {}),
          ...extra
        })

      emit('starting')

      // Settling it only computes; announcing it is the caller's business,
      // because the state it belongs on differs — `streaming` when the
      // preflight handed over to the tail, `ended` when it never got that far.
      const settleDiagnosis = (): void => {
        if (diagnosis) return
        diagnosis = diagnoseLogTail(facts)
      }

      const send = (line: LogLine): void => this.deps.emitLine(line)

      const notice = (text: string, at: number): void =>
        send({
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

      // Everything the pause held, in the order the host said it. The overflow
      // count is reported for the same reason the rate limiter reports its own:
      // a gap nobody mentions is how someone concludes a service went quiet.
      const drain = (): void => {
        if (held.length === 0 && heldDropped === 0) return
        const buffered = held
        held = []
        for (const l of buffered) send(l)
        if (heldDropped > 0) {
          const n = heldDropped
          heldDropped = 0
          notice(`— ${n} lines dropped while paused, the pane holds ${LOG_PAUSE_BUFFER} —`, this.now)
        }
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
        const line: LogLine = {
          tailId,
          serverId: t.serverId,
          serverName: t.serverName,
          seq: seq++,
          text,
          isError: isError || undefined,
          at: now
        }
        // Held, not dropped. The channel stays open while paused — that is the
        // whole difference from Stop — so the lines have to go somewhere, and
        // the oldest go first once the buffer is full: during an incident the
        // newest lines are the ones being waited for.
        //
        // The rate limiter above still applies while paused, which is not an
        // oversight: resume emits the whole buffer in one go, so the burst it
        // has to survive is the same IPC burst the limiter exists for. Both
        // caps report what they discarded, so neither produces a silent gap.
        if (this.paused.has(tailId)) {
          held.push(line)
          while (held.length > LOG_PAUSE_BUFFER) {
            held.shift()
            heldDropped++
          }
          return
        }
        send(line)
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

      // A preflight fact rather than a log line, or null. Only consulted before
      // `begin`: after it, a line that looks like a marker is content and is
      // shown as content.
      const takeMark = (line: string): boolean => {
        if (preflightDone) return false
        const m = parseLogMark(line)
        if (!m) return false
        if (m.key === 'begin') {
          preflightDone = true
          settleDiagnosis()
          if (owns()) emit('streaming')
          return true
        }
        facts[m.key] = m.value
        return true
      }

      const feed = (chunk: string, isError: boolean): void => {
        const parts = (carry + chunk).split('\n')
        carry = parts.pop() ?? ''
        for (const raw of parts) {
          const line = raw.replace(/\r$/, '')
          if (takeMark(line)) continue
          pushCapped(line, isError)
        }
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
              if (!takeMark(carry)) pushCapped(carry, false)
              carry = ''
            }
            flushDrops()
            drain()
            // A preflight that refused — no journalctl on the host — never
            // reaches `begin`, so the diagnosis has to be settled here too.
            // Otherwise the one case the preflight exists to catch is the one
            // case it says nothing about.
            settleDiagnosis()
            // A channel belonging to a superseded start closing must not report
            // "ended" for a host the current tail is streaming from.
            if (owns()) emit('ended')
          },
          onError: (message) => {
            if (!owns()) return
            emit('failed', { error: message })
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
        running.push({
          stop,
          flush: () => {
            flushDrops()
            drain()
          },
          drain,
          serverId: t.serverId
        })
        emit('streaming')
      } catch (e) {
        if (!owns()) return { ok: false, error: 'This tail was restarted while it was starting.' }
        // One host refusing must not stop the others — comparing a failing host
        // against a working one is most of why this reads several at once.
        emit('failed', { error: e instanceof Error ? e.message : String(e) })
      }
    }

    if (!owns()) return { ok: false, error: 'This tail was restarted while it was starting.' }
    if (running.length === 0) {
      this.active.delete(tailId)
      this.paused.delete(tailId)
      return { ok: false, error: 'No host accepted the tail.' }
    }
    return { ok: true }
  }

  /**
   * Hold the stream without touching the channel.
   *
   * Stop is the other thing, and conflating them is what this fixes: reading a
   * burst used to mean pressing Stop, which killed `journalctl -f` on every
   * host, discarded the pane and made Tail the only way back — a second
   * connection, a second history fetch, and whatever the host said in between
   * gone. Here the remote command keeps running and its lines are held.
   */
  pause(tailId: string): boolean {
    if (!this.active.has(tailId)) return false
    this.paused.add(tailId)
    return true
  }

  resume(tailId: string): boolean {
    if (!this.paused.delete(tailId)) return false
    const running = this.active.get(tailId)
    if (!running) return false
    for (const r of running) {
      try {
        r.drain()
      } catch {
        /* one host's buffer must not strand another's */
      }
    }
    return true
  }

  /**
   * The units on a host, for the unit picker.
   *
   * Uses the plain exec, not the streaming one: this is a question with an
   * answer, not a follow.
   */
  async listUnits(
    exec: (cfg: unknown, command: string, timeoutMs: number) => Promise<{ ok: boolean; stdout?: string; stderr?: string; error?: string }>,
    cfg: unknown
  ): Promise<{ ok: boolean; units: UnitChoice[]; error?: string }> {
    try {
      const r = await exec(cfg, buildUnitListCommand(), 15_000)
      if (!r.ok) return { ok: false, units: [], error: r.error ?? 'could not reach the host' }
      const out = `${r.stdout ?? ''}${r.stderr ?? ''}`
      const units = parseUnitList(out)
      // No units parsed AND something that reads like a shell complaint means
      // no systemd here — distinct from a host with genuinely no services.
      if (units.length === 0 && /not found|no such file/i.test(out)) {
        return { ok: false, units: [], error: 'systemd is not available on this host.' }
      }
      return { ok: true, units }
    } catch (e) {
      return { ok: false, units: [], error: e instanceof Error ? e.message : String(e) }
    }
  }

  stop(tailId: string): void {
    const running = this.active.get(tailId)
    // The hold is cleared before the flush, so what the pause was holding is
    // emitted rather than filed straight back into the buffer it came from.
    this.paused.delete(tailId)
    if (!running) return
    for (const r of running) {
      // Before the channel goes, and before the id is forgotten: whatever the
      // rate limiter or the pause is still holding is the last thing the user
      // gets to see, and losing it turns a throttled burst — or a deliberate
      // pause — into an unexplained gap.
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
