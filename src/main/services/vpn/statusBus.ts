import type { WebContents } from 'electron'
import type { VpnLogLine, VpnStatus } from '../../../shared/vpn'

// Status and log delivery to the renderer, with the back-pressure the plan
// requires.
//
// A VPN emits far more than a UI can use: WireGuard stats are polled, OpenVPN
// pushes a >BYTECOUNT: every few seconds per profile, and frp's proxy table is
// re-read on every poll. Forwarding all of it is how an idle window ends up
// doing constant IPC and constant React work for numbers nobody is looking at.
//
// Three rules, and the third is the one that is easy to get wrong:
//
//   1. Coalesce. At most one status message per profile per interval, and only
//      when the payload actually differs from the last one sent.
//   2. State transitions bypass the throttle. A user pressing Stop must not
//      wait a second to see the UI move — throttling a *transition* is the
//      difference between "responsive" and "did my click register?".
//   3. Logs are pull, not push. Lines stop at the ring buffer unless a
//      renderer has the drawer open, tracked by refcount.

// One second while the window is focused. WireGuard rekeys every 120s or so
// and OpenVPN's finest bytecount granularity is 1s, so sampling faster buys
// nothing.
export const STATUS_INTERVAL_ACTIVE_MS = 1000
// Backgrounded window: still live, but nobody is watching a byte counter.
export const STATUS_INTERVAL_IDLE_MS = 10_000

interface Entry {
  last: VpnStatus | null
  lastSentAt: number
  // Set when a payload was suppressed by the throttle and still needs sending.
  pending: VpnStatus | null
  timer: NodeJS.Timeout | null
}

export interface StatusBusOptions {
  now?: () => number
  setTimer?: (fn: () => void, ms: number) => NodeJS.Timeout
  clearTimer?: (t: NodeJS.Timeout) => void
}

export class VpnStatusBus {
  private readonly entries = new Map<string, Entry>()
  private readonly logSubscribers = new Map<string, number>()
  private targets = new Set<WebContents>()
  private intervalMs = STATUS_INTERVAL_ACTIVE_MS
  private readonly now: () => number
  private readonly setTimer: (fn: () => void, ms: number) => NodeJS.Timeout
  private readonly clearTimer: (t: NodeJS.Timeout) => void

  constructor(opts: StatusBusOptions = {}) {
    this.now = opts.now ?? (() => Date.now())
    this.setTimer = opts.setTimer ?? ((fn, ms) => setTimeout(fn, ms))
    this.clearTimer = opts.clearTimer ?? ((t) => clearTimeout(t))
  }

  /** Renderers that should receive events. A VPN started by an AI agent has no
   *  renderer that asked for it, which is not a reason to refuse to start one —
   *  the same reasoning as tunnel.ts's emit(). */
  addTarget(wc: WebContents): void {
    this.targets.add(wc)
  }

  removeTarget(wc: WebContents): void {
    this.targets.delete(wc)
  }

  /** Focused windows get the fast cadence; a hidden or blurred one does not
   *  need per-second byte counts. */
  setCadence(mode: 'active' | 'idle'): void {
    this.intervalMs = mode === 'active' ? STATUS_INTERVAL_ACTIVE_MS : STATUS_INTERVAL_IDLE_MS
  }

  get cadenceMs(): number {
    return this.intervalMs
  }

  /** The last status published for a profile, or null. Synchronous, and used
   *  by the MCP bridge, so it must never throw. */
  latest(id: string): VpnStatus | null {
    return this.entries.get(id)?.last ?? null
  }

  all(): VpnStatus[] {
    const out: VpnStatus[] = []
    for (const e of this.entries.values()) if (e.last) out.push(e.last)
    return out
  }

  publish(status: VpnStatus): void {
    const e = this.entryFor(status.id)

    // Nothing changed: not a message. This is what stops a 1 Hz poll of a
    // connected-and-idle tunnel from becoming 1 Hz of IPC.
    if (e.last && sameStatus(e.last, status)) return

    // A state change is news. Send it now, whatever the throttle says, and
    // reset the window so the next stats update is not immediately due.
    const transition = !e.last || e.last.state !== status.state
    const elapsed = this.now() - e.lastSentAt

    if (transition || elapsed >= this.intervalMs) {
      this.send(e, status)
      return
    }

    // Throttled: remember the newest payload and make sure it goes out at the
    // end of the window. Overwriting `pending` is deliberate — an intermediate
    // byte count nobody saw is not worth delivering late.
    e.pending = status
    if (!e.timer) {
      e.timer = this.setTimer(() => {
        e.timer = null
        const p = e.pending
        e.pending = null
        if (p) this.send(e, p)
      }, this.intervalMs - elapsed)
    }
  }

  /** Drop a profile's state, e.g. after it is deleted. */
  forget(id: string): void {
    const e = this.entries.get(id)
    if (e?.timer) this.clearTimer(e.timer)
    this.entries.delete(id)
    this.logSubscribers.delete(id)
  }

  // ------------------------------------------------------------------ logs

  subscribeLogs(id: string): void {
    this.logSubscribers.set(id, (this.logSubscribers.get(id) ?? 0) + 1)
  }

  unsubscribeLogs(id: string): void {
    const n = (this.logSubscribers.get(id) ?? 0) - 1
    if (n > 0) this.logSubscribers.set(id, n)
    else this.logSubscribers.delete(id)
  }

  hasLogSubscribers(id: string): boolean {
    return (this.logSubscribers.get(id) ?? 0) > 0
  }

  /** Lines are always written to the driver's ring buffer by the supervisor;
   *  this only decides whether to also push them at a renderer. With the drawer
   *  closed they are still there to be pulled with vpn:logs. */
  publishLog(id: string, line: VpnLogLine): void {
    if (!this.hasLogSubscribers(id)) return
    this.emit(`vpn:log:${id}`, line)
  }

  /** Called on app quit and by tests. */
  dispose(): void {
    for (const e of this.entries.values()) if (e.timer) this.clearTimer(e.timer)
    this.entries.clear()
    this.logSubscribers.clear()
    this.targets = new Set()
  }

  // --------------------------------------------------------------- private

  private entryFor(id: string): Entry {
    let e = this.entries.get(id)
    if (!e) {
      // lastSentAt starts at -Infinity so the very first status for a profile
      // is never throttled, even if it arrives inside the first interval of
      // the app's life.
      e = { last: null, lastSentAt: Number.NEGATIVE_INFINITY, pending: null, timer: null }
      this.entries.set(id, e)
    }
    return e
  }

  private send(e: Entry, status: VpnStatus): void {
    e.last = status
    e.lastSentAt = this.now()
    this.emit(`vpn:status:${status.id}`, status)
  }

  private emit(channel: string, payload: unknown): void {
    for (const wc of this.targets) {
      // A destroyed WebContents is the ordinary case on window close, not an
      // error worth logging on every tick.
      if (wc.isDestroyed()) {
        this.targets.delete(wc)
        continue
      }
      wc.send(channel, payload)
    }
  }
}

/** Structural equality over the fields the UI renders.
 *
 *  `stats.sampledAt` is deliberately excluded: it changes on every poll by
 *  definition, so including it would make every status differ from the last
 *  and defeat the whole comparison. */
export function sameStatus(a: VpnStatus, b: VpnStatus): boolean {
  if (
    a.state !== b.state ||
    a.error !== b.error ||
    a.errorCode !== b.errorCode ||
    a.restarts !== b.restarts ||
    a.since !== b.since
  ) {
    return false
  }
  if (!sameListeners(a.listeners, b.listeners)) return false
  return sameStats(a.stats, b.stats)
}

function sameListeners(a: VpnStatus['listeners'], b: VpnStatus['listeners']): boolean {
  if (a === b) return true
  if (!a || !b || a.length !== b.length) return false
  return a.every((x, i) => {
    const y = b[i]
    return (
      x.kind === y.kind &&
      x.bindHost === y.bindHost &&
      x.bindPort === y.bindPort &&
      x.targetHost === y.targetHost &&
      x.targetPort === y.targetPort
    )
  })
}

function sameStats(a: VpnStatus['stats'], b: VpnStatus['stats']): boolean {
  if (a === b) return true
  if (!a || !b) return false
  if (
    a.rxBytes !== b.rxBytes ||
    a.txBytes !== b.txBytes ||
    a.assignedIp !== b.assignedIp ||
    a.remoteEndpoint !== b.remoteEndpoint ||
    a.latencyMs !== b.latencyMs
  ) {
    return false
  }
  // The handshake age is recomputed on every sample and drifts by a second at
  // a time even when nothing has happened. Comparing it exactly would emit a
  // message per second for a healthy idle tunnel — which is the exact traffic
  // this class exists to remove. Bucket it instead: what the UI shows is
  // "12s ago" and, more importantly, which side of the 180s staleness line it
  // falls on, and neither of those changes between 12.0 and 12.9.
  if (handshakeBucket(a.lastHandshakeSec) !== handshakeBucket(b.lastHandshakeSec)) return false
  return sameProxies(a.proxies, b.proxies)
}

/** Buckets that match what the UI can actually distinguish: exact for the
 *  first ten seconds, then five-second steps, then coarse. Crossing the
 *  staleness threshold always lands in a new bucket. */
export function handshakeBucket(sec: number | undefined): number | undefined {
  if (sec === undefined) return undefined
  if (sec < 0) return 0
  if (sec < 10) return sec
  if (sec < 180) return 10 + Math.floor((sec - 10) / 5) * 5
  return 180 + Math.floor((sec - 180) / 30) * 30
}

function sameProxies(
  a: NonNullable<VpnStatus['stats']>['proxies'],
  b: NonNullable<VpnStatus['stats']>['proxies']
): boolean {
  if (a === b) return true
  if (!a || !b || a.length !== b.length) return false
  return a.every((x, i) => {
    const y = b[i]
    return (
      x.name === y.name &&
      x.type === y.type &&
      x.status === y.status &&
      x.err === y.err &&
      x.localAddr === y.localAddr &&
      x.remoteAddr === y.remoteAddr
    )
  })
}
