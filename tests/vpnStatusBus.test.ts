import { beforeEach, describe, expect, it, vi } from 'vitest'
import type { WebContents } from 'electron'
import type { VpnStatus } from '../src/shared/vpn'
import {
  STATUS_INTERVAL_ACTIVE_MS,
  STATUS_INTERVAL_IDLE_MS,
  VpnStatusBus,
  handshakeBucket,
  sameStatus
} from '../src/main/services/vpn/statusBus'

// A controllable clock and timer queue. Real timers here would make every
// throttling assertion a race, and vitest's fake timers do not help with the
// clock the bus reads for its own window arithmetic.
class Clock {
  t = 1_000_000
  private readonly queued: { at: number; fn: () => void; id: NodeJS.Timeout }[] = []
  private next = 1

  now = (): number => this.t

  setTimer = (fn: () => void, ms: number): NodeJS.Timeout => {
    const id = this.next++ as unknown as NodeJS.Timeout
    this.queued.push({ at: this.t + ms, fn, id })
    return id
  }

  clearTimer = (id: NodeJS.Timeout): void => {
    const i = this.queued.findIndex((q) => q.id === id)
    if (i >= 0) this.queued.splice(i, 1)
  }

  advance(ms: number): void {
    const target = this.t + ms
    for (;;) {
      const due = this.queued
        .filter((q) => q.at <= target)
        .sort((a, b) => a.at - b.at)
        .shift()
      if (!due) break
      this.queued.splice(this.queued.indexOf(due), 1)
      this.t = due.at
      due.fn()
    }
    this.t = target
  }

  get pending(): number {
    return this.queued.length
  }
}

function fakeWc(): WebContents & { sent: { ch: string; payload: unknown }[] } {
  const sent: { ch: string; payload: unknown }[] = []
  return {
    sent,
    isDestroyed: () => false,
    send: (ch: string, payload: unknown) => sent.push({ ch, payload })
  } as unknown as WebContents & { sent: { ch: string; payload: unknown }[] }
}

function status(over: Partial<VpnStatus> = {}): VpnStatus {
  return {
    id: 'v1',
    kind: 'wireguard',
    state: 'connected',
    restarts: 0,
    ...over
  }
}

let clock: Clock
let bus: VpnStatusBus
let wc: ReturnType<typeof fakeWc>

beforeEach(() => {
  clock = new Clock()
  bus = new VpnStatusBus({ now: clock.now, setTimer: clock.setTimer, clearTimer: clock.clearTimer })
  wc = fakeWc()
  bus.addTarget(wc)
})

const statuses = (): VpnStatus[] =>
  wc.sent.filter((s) => s.ch.startsWith('vpn:status:')).map((s) => s.payload as VpnStatus)

describe('coalescing', () => {
  it('sends the first status immediately, however early it arrives', () => {
    bus.publish(status({ state: 'starting' }))
    expect(statuses()).toHaveLength(1)
  })

  it('does not send an unchanged status at all', () => {
    bus.publish(status())
    clock.advance(STATUS_INTERVAL_ACTIVE_MS * 5)
    bus.publish(status())
    bus.publish(status())
    expect(statuses()).toHaveLength(1)
  })

  it('ignores stats.sampledAt, which changes on every poll by definition', () => {
    const s = status({ stats: { rxBytes: 1, txBytes: 2, sampledAt: 1 } })
    bus.publish(s)
    clock.advance(STATUS_INTERVAL_ACTIVE_MS * 3)
    bus.publish(status({ stats: { rxBytes: 1, txBytes: 2, sampledAt: 999 } }))
    expect(statuses()).toHaveLength(1)
  })

  it('throttles a stats change to one message per interval', () => {
    bus.publish(status({ stats: { rxBytes: 0, txBytes: 0, sampledAt: 1 } }))
    expect(statuses()).toHaveLength(1)

    // Three updates inside one window collapse to a single delayed send.
    clock.advance(100)
    bus.publish(status({ stats: { rxBytes: 10, txBytes: 0, sampledAt: 2 } }))
    clock.advance(100)
    bus.publish(status({ stats: { rxBytes: 20, txBytes: 0, sampledAt: 3 } }))
    clock.advance(100)
    bus.publish(status({ stats: { rxBytes: 30, txBytes: 0, sampledAt: 4 } }))
    expect(statuses()).toHaveLength(1)

    clock.advance(STATUS_INTERVAL_ACTIVE_MS)
    const sent = statuses()
    expect(sent).toHaveLength(2)
    // The newest value wins; the intermediate ones nobody saw are dropped
    // rather than delivered late.
    expect(sent[1].stats?.rxBytes).toBe(30)
  })

  it('lets a state transition bypass the throttle', () => {
    bus.publish(status({ state: 'connected', stats: { rxBytes: 0, txBytes: 0, sampledAt: 1 } }))
    clock.advance(50)
    bus.publish(status({ state: 'connected', stats: { rxBytes: 5, txBytes: 0, sampledAt: 2 } }))
    expect(statuses()).toHaveLength(1)

    // A user pressing Stop must not wait out the window.
    clock.advance(10)
    bus.publish(status({ state: 'stopped' }))
    const sent = statuses()
    expect(sent).toHaveLength(2)
    expect(sent[1].state).toBe('stopped')
  })

  it('keeps profiles independent', () => {
    bus.publish(status({ id: 'v1' }))
    bus.publish(status({ id: 'v2', kind: 'frp' }))
    expect(wc.sent.map((s) => s.ch)).toEqual(['vpn:status:v1', 'vpn:status:v2'])
  })
})

describe('cadence', () => {
  it('backs off to the idle interval when the window is not focused', () => {
    bus.setCadence('idle')
    expect(bus.cadenceMs).toBe(STATUS_INTERVAL_IDLE_MS)

    bus.publish(status({ stats: { rxBytes: 0, txBytes: 0, sampledAt: 1 } }))
    clock.advance(STATUS_INTERVAL_ACTIVE_MS * 2)
    bus.publish(status({ stats: { rxBytes: 9, txBytes: 0, sampledAt: 2 } }))
    // Still inside the idle window, so nothing more has gone out yet.
    expect(statuses()).toHaveLength(1)

    clock.advance(STATUS_INTERVAL_IDLE_MS)
    expect(statuses()).toHaveLength(2)
  })
})

describe('handshake bucketing', () => {
  it('is exact for the first ten seconds', () => {
    expect(handshakeBucket(0)).toBe(0)
    expect(handshakeBucket(9)).toBe(9)
  })

  it('coarsens after ten seconds so an idle tunnel stops emitting', () => {
    expect(handshakeBucket(10)).toBe(handshakeBucket(14))
    expect(handshakeBucket(10)).not.toBe(handshakeBucket(15))
  })

  it('always changes bucket across the 180s staleness line', () => {
    expect(handshakeBucket(179)).not.toBe(handshakeBucket(180))
  })

  it('never reports a negative age, so a clock change cannot render one', () => {
    expect(handshakeBucket(-5)).toBe(0)
  })

  it('leaves "never handshaked" distinguishable from "handshaked at 0s"', () => {
    expect(handshakeBucket(undefined)).toBeUndefined()
    expect(handshakeBucket(0)).toBe(0)
  })

  it('suppresses a one-second drift on a healthy idle tunnel', () => {
    bus.publish(status({ stats: { rxBytes: 1, txBytes: 1, lastHandshakeSec: 60, sampledAt: 1 } }))
    clock.advance(STATUS_INTERVAL_ACTIVE_MS * 3)
    bus.publish(status({ stats: { rxBytes: 1, txBytes: 1, lastHandshakeSec: 61, sampledAt: 2 } }))
    expect(statuses()).toHaveLength(1)
  })

  it('still reports the tunnel going stale', () => {
    bus.publish(status({ stats: { rxBytes: 1, txBytes: 1, lastHandshakeSec: 170, sampledAt: 1 } }))
    clock.advance(STATUS_INTERVAL_ACTIVE_MS * 3)
    bus.publish(status({ stats: { rxBytes: 1, txBytes: 1, lastHandshakeSec: 200, sampledAt: 2 } }))
    expect(statuses()).toHaveLength(2)
  })
})

describe('logs are pull, not push', () => {
  const line = { at: 1, stream: 'stdout' as const, text: 'hello' }

  it('drops log lines when nobody has the drawer open', () => {
    bus.publishLog('v1', line)
    expect(wc.sent.filter((s) => s.ch === 'vpn:log:v1')).toHaveLength(0)
  })

  it('delivers while subscribed', () => {
    bus.subscribeLogs('v1')
    bus.publishLog('v1', line)
    expect(wc.sent.filter((s) => s.ch === 'vpn:log:v1')).toHaveLength(1)
  })

  it('refcounts, so one of two drawers closing does not silence the other', () => {
    bus.subscribeLogs('v1')
    bus.subscribeLogs('v1')
    bus.unsubscribeLogs('v1')
    expect(bus.hasLogSubscribers('v1')).toBe(true)
    bus.unsubscribeLogs('v1')
    expect(bus.hasLogSubscribers('v1')).toBe(false)
  })

  it('does not underflow on an extra unsubscribe', () => {
    bus.unsubscribeLogs('v1')
    bus.subscribeLogs('v1')
    expect(bus.hasLogSubscribers('v1')).toBe(true)
  })
})

describe('targets', () => {
  it('prunes a destroyed WebContents instead of throwing on every tick', () => {
    const dead = fakeWc()
    ;(dead as unknown as { isDestroyed: () => boolean }).isDestroyed = () => true
    bus.addTarget(dead)
    bus.publish(status())
    expect(dead.sent).toHaveLength(0)
    expect(wc.sent).toHaveLength(1)
  })

  it('still tracks state with no renderer attached, for the MCP bridge', () => {
    const headless = new VpnStatusBus({ now: clock.now, setTimer: clock.setTimer })
    headless.publish(status({ state: 'connected' }))
    expect(headless.latest('v1')?.state).toBe('connected')
    expect(headless.all()).toHaveLength(1)
  })
})

describe('lifecycle', () => {
  it('forget clears state and cancels a pending send', () => {
    bus.publish(status({ stats: { rxBytes: 0, txBytes: 0, sampledAt: 1 } }))
    clock.advance(10)
    bus.publish(status({ stats: { rxBytes: 5, txBytes: 0, sampledAt: 2 } }))
    expect(clock.pending).toBe(1)

    bus.forget('v1')
    expect(clock.pending).toBe(0)
    expect(bus.latest('v1')).toBeNull()

    clock.advance(STATUS_INTERVAL_ACTIVE_MS * 2)
    expect(statuses()).toHaveLength(1)
  })

  it('dispose cancels every timer', () => {
    bus.publish(status({ id: 'a', stats: { rxBytes: 0, txBytes: 0, sampledAt: 1 } }))
    bus.publish(status({ id: 'b', stats: { rxBytes: 0, txBytes: 0, sampledAt: 1 } }))
    clock.advance(10)
    bus.publish(status({ id: 'a', stats: { rxBytes: 1, txBytes: 0, sampledAt: 2 } }))
    bus.publish(status({ id: 'b', stats: { rxBytes: 1, txBytes: 0, sampledAt: 2 } }))
    expect(clock.pending).toBe(2)
    bus.dispose()
    expect(clock.pending).toBe(0)
  })
})

describe('sameStatus', () => {
  it('notices an error appearing even when the state is unchanged', () => {
    const a = status({ state: 'degraded' })
    const b = status({ state: 'degraded', error: 'no handshake', errorCode: 'handshake-timeout' })
    expect(sameStatus(a, b)).toBe(false)
  })

  it('notices a listener being rebound', () => {
    const a = status({ listeners: [{ kind: 'socks5', bindHost: '127.0.0.1', bindPort: 1080 }] })
    const b = status({ listeners: [{ kind: 'socks5', bindHost: '127.0.0.1', bindPort: 1081 }] })
    expect(sameStatus(a, b)).toBe(false)
  })

  it('notices an frp proxy changing status', () => {
    const mk = (s: string): VpnStatus =>
      status({
        kind: 'frp',
        stats: {
          rxBytes: 0,
          txBytes: 0,
          sampledAt: 1,
          proxies: [{ name: 'pg', type: 'tcp', status: s }]
        }
      })
    expect(sameStatus(mk('running'), mk('start error'))).toBe(false)
    expect(sameStatus(mk('running'), mk('running'))).toBe(true)
  })

  it('notices a restart', () => {
    expect(sameStatus(status({ restarts: 0 }), status({ restarts: 1 }))).toBe(false)
  })
})

describe('vitest sanity', () => {
  it('uses no real timers', () => {
    const spy = vi.spyOn(globalThis, 'setTimeout')
    bus.publish(status({ stats: { rxBytes: 0, txBytes: 0, sampledAt: 1 } }))
    clock.advance(10)
    bus.publish(status({ stats: { rxBytes: 1, txBytes: 0, sampledAt: 2 } }))
    expect(spy).not.toHaveBeenCalled()
    spy.mockRestore()
  })
})
