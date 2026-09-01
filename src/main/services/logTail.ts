import type { LogLine, LogSource, LogTailState } from '../../shared/logtail'
import { LOG_RATE_PER_SEC, buildTailCommand, validateLogSource } from '../../shared/logtail'

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

    for (const t of targets) {
      this.deps.emitState({ tailId, serverId: t.serverId, serverName: t.serverName, state: 'starting' })

      let seq = 0
      let windowStart = this.now
      let inWindow = 0
      let dropped = 0
      // Partial lines are normal: a chunk boundary lands mid-line constantly,
      // and emitting the halves separately makes a log unreadable in exactly
      // the moments it matters.
      let carry = ''

      const push = (text: string, isError: boolean): void => {
        const now = this.now
        if (now - windowStart >= 1000) {
          if (dropped > 0) {
            this.deps.emitLine({
              tailId,
              serverId: t.serverId,
              serverName: t.serverName,
              seq: seq++,
              text: `— ${dropped} lines dropped, this host is logging faster than the pane can show —`,
              isError: true,
              at: now
            })
          }
          windowStart = now
          inWindow = 0
          dropped = 0
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

      const feed = (chunk: string, isError: boolean): void => {
        const parts = (carry + chunk).split('\n')
        carry = parts.pop() ?? ''
        for (const line of parts) push(line.replace(/\r$/, ''), isError)
      }

      try {
        const stop = await this.deps.execStream(t.cfg, command, {
          onStdout: (c) => feed(c, false),
          onStderr: (c) => feed(c, true),
          onClose: () => {
            if (carry !== '') {
              push(carry, false)
              carry = ''
            }
            this.deps.emitState({ tailId, serverId: t.serverId, serverName: t.serverName, state: 'ended' })
          },
          onError: (message) =>
            this.deps.emitState({ tailId, serverId: t.serverId, serverName: t.serverName, state: 'failed', error: message })
        })
        running.push({ stop, serverId: t.serverId })
        this.deps.emitState({ tailId, serverId: t.serverId, serverName: t.serverName, state: 'streaming' })
      } catch (e) {
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
