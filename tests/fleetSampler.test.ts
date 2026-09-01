import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { FleetSampler, clampInterval, fleetKey } from '../src/main/services/fleetSampler'
import type { FleetSampleEvent, FleetTarget } from '../src/shared/fleet'
import {
  FLEET_INTERVAL_DEFAULT_MS,
  FLEET_INTERVAL_MAX_MS,
  FLEET_INTERVAL_MIN_MS
} from '../src/shared/fleet'

// The sampler runs unattended, which is the whole point and also the whole
// risk: every failure mode here is one that repeats forever without anyone
// watching. The tests below are mostly about it stopping when it should.

const target = (id: string): FleetTarget => ({
  serverId: id,
  serverName: `srv-${id}`,
  cfg: { host: 'h', port: 22, username: 'u' } as FleetTarget['cfg']
})

interface Harness {
  sampler: FleetSampler
  events: FleetSampleEvent[]
  calls: string[]
  released: string[]
  setUnlocked: (v: boolean) => void
  /** Make the next sample (only the next) report a failure. */
  failNext: (error: string) => void
  resolveAll: () => void
}

function harness(over: { slow?: boolean } = {}): Harness {
  const events: FleetSampleEvent[] = []
  const calls: string[] = []
  const released: string[] = []
  let unlocked = true
  let failWith: string | null = null
  const pending: (() => void)[] = []

  const sampler = new FleetSampler({
    sample: async (key) => {
      calls.push(key)
      if (over.slow) await new Promise<void>((r) => pending.push(r))
      if (failWith !== null) {
        const error = failWith
        failWith = null
        return { ok: false, error }
      }
      return { ok: true, data: { hostname: key } }
    },
    release: (k) => released.push(k),
    emit: (e) => events.push(e),
    vaultUnlocked: () => unlocked
  })

  return {
    sampler,
    events,
    calls,
    released,
    setUnlocked: (v) => {
      unlocked = v
    },
    failNext: (error) => {
      failWith = error
    },
    resolveAll: () => {
      while (pending.length) pending.shift()!()
    }
  }
}

beforeEach(() => {
  vi.useFakeTimers()
})
afterEach(() => {
  vi.useRealTimers()
})

describe('interval clamping', () => {
  it('refuses a cadence that would hammer the estate', () => {
    // A 2s sweep across fifteen servers is fifteen exec channels every two
    // seconds, through the bastions those servers sit behind, to answer a
    // question whose answer changes on the order of minutes.
    expect(clampInterval(2_000)).toBe(FLEET_INTERVAL_MIN_MS)
    expect(clampInterval(0)).toBe(FLEET_INTERVAL_MIN_MS)
    expect(clampInterval(-1)).toBe(FLEET_INTERVAL_MIN_MS)
  })

  it('refuses a cadence so slow the data is meaningless', () => {
    expect(clampInterval(Number.MAX_SAFE_INTEGER)).toBe(FLEET_INTERVAL_MAX_MS)
  })

  it('falls back to the default on garbage, not to the fastest cadence', () => {
    // The direction matters. A corrupt setting resolving to the minimum means
    // a bad number maximises load on the estate, which is the wrong way to
    // fail. Infinity is an extreme rather than garbage, so it clamps normally.
    expect(clampInterval(Number.NaN)).toBe(FLEET_INTERVAL_DEFAULT_MS)
    expect(clampInterval(Number.POSITIVE_INFINITY)).toBe(FLEET_INTERVAL_MAX_MS)
    expect(clampInterval(Number.NEGATIVE_INFINITY)).toBe(FLEET_INTERVAL_MIN_MS)
  })

  it('keeps a sensible value as given', () => {
    expect(clampInterval(120_000)).toBe(120_000)
  })
})

describe('sampling key', () => {
  it('does not collide with the key a focused monitor card uses', () => {
    // Both ask the same question at different cadences through the same
    // metricsSample cache. Sharing a key would let a 2s foreground poll and a
    // 2min background sweep evict or dedupe each other.
    expect(fleetKey('abc')).toBe('fleet:abc')
    expect(fleetKey('abc')).not.toBe('abc')
    expect(fleetKey('abc')).not.toBe('mcp:abc')
  })
})

describe('running and not running', () => {
  it('does nothing until configured', async () => {
    const h = harness()
    await vi.advanceTimersByTimeAsync(10 * FLEET_INTERVAL_MIN_MS)
    expect(h.calls).toEqual([])
    expect(h.sampler.status().running).toBe(false)
  })

  it('sweeps immediately on configure rather than waiting a full interval', async () => {
    // Otherwise enabling the feature appears to do nothing for two minutes.
    const h = harness()
    h.sampler.configure({ enabled: true, intervalMs: 60_000, targets: [target('a')] })
    await vi.advanceTimersByTimeAsync(0)
    expect(h.calls).toEqual(['fleet:a'])
  })

  it('parks when disabled, and says why', async () => {
    const h = harness()
    h.sampler.configure({ enabled: false, intervalMs: 60_000, targets: [target('a')] })
    await vi.advanceTimersByTimeAsync(5 * FLEET_INTERVAL_MIN_MS)
    expect(h.calls).toEqual([])
    expect(h.sampler.status()).toMatchObject({ running: false, idleReason: 'disabled' })
  })

  it('parks with no targets, and says why', async () => {
    const h = harness()
    h.sampler.configure({ enabled: true, intervalMs: 60_000, targets: [] })
    await vi.advanceTimersByTimeAsync(5 * FLEET_INTERVAL_MIN_MS)
    expect(h.calls).toEqual([])
    expect(h.sampler.status()).toMatchObject({ running: false, idleReason: 'no-targets' })
  })

  it('parks while the vault is locked instead of failing every server forever', async () => {
    // The failure mode this prevents: credentials cannot resolve, so every
    // target errors, every interval, indefinitely -- with an audit entry each.
    const h = harness()
    h.setUnlocked(false)
    h.sampler.configure({ enabled: true, intervalMs: 60_000, targets: [target('a'), target('b')] })
    await vi.advanceTimersByTimeAsync(10 * 60_000)
    expect(h.calls).toEqual([])
    expect(h.sampler.status()).toMatchObject({ running: false, idleReason: 'vault-locked' })
  })

  it('resumes when the vault is unlocked and it is reconfigured', async () => {
    const h = harness()
    h.setUnlocked(false)
    h.sampler.configure({ enabled: true, intervalMs: 60_000, targets: [target('a')] })
    await vi.advanceTimersByTimeAsync(60_000)
    expect(h.calls).toEqual([])

    h.setUnlocked(true)
    h.sampler.configure({ enabled: true, intervalMs: 60_000, targets: [target('a')] })
    await vi.advanceTimersByTimeAsync(0)
    expect(h.calls).toEqual(['fleet:a'])
  })

  it('stops mid-sweep when the vault auto-locks', async () => {
    // Auto-lock partway through a sweep must stop it, not produce a failure
    // for every remaining server. Needs a sample that can be held open, or the
    // whole sweep finishes before the lock can land and the test proves
    // nothing — which is exactly what the first version of it did.
    const h = harness({ slow: true })
    h.sampler.configure({
      enabled: true,
      intervalMs: 60_000,
      targets: [target('a'), target('b'), target('c')]
    })
    await vi.advanceTimersByTimeAsync(0)
    expect(h.calls).toEqual(['fleet:a'])

    // Let the first land, then lock before the loop reaches the second.
    h.setUnlocked(false)
    h.resolveAll()
    await vi.advanceTimersByTimeAsync(0)

    expect(h.calls).toEqual(['fleet:a'])
    expect(h.events).toHaveLength(1)
    expect(h.events[0]).toMatchObject({ serverId: 'a' })
    // b and c produce no entries at all — not errors, not stale successes.
    expect(h.events.some((e) => e.error)).toBe(false)
    h.sampler.dispose()
  })
})

describe('sweep behaviour', () => {
  it('visits every target once per sweep', async () => {
    const h = harness()
    h.sampler.configure({
      enabled: true,
      intervalMs: 60_000,
      targets: [target('a'), target('b'), target('c')]
    })
    await vi.advanceTimersByTimeAsync(0)
    expect(h.calls).toEqual(['fleet:a', 'fleet:b', 'fleet:c'])
    expect(h.events.map((e) => e.serverId)).toEqual(['a', 'b', 'c'])
  })

  it('keeps sweeping on the interval', async () => {
    const h = harness()
    h.sampler.configure({ enabled: true, intervalMs: 60_000, targets: [target('a')] })
    await vi.advanceTimersByTimeAsync(0)
    expect(h.calls).toHaveLength(1)
    await vi.advanceTimersByTimeAsync(60_000)
    expect(h.calls).toHaveLength(2)
    await vi.advanceTimersByTimeAsync(60_000)
    expect(h.calls).toHaveLength(3)
  })

  it('reports an unreachable host and carries on to the rest', async () => {
    // One dead server is not a reason to stop asking about the other fourteen.
    const events: FleetSampleEvent[] = []
    const sampler = new FleetSampler({
      sample: async (key) => {
        if (key === 'fleet:b') throw new Error('connect ETIMEDOUT')
        return { ok: true, data: { hostname: key } }
      },
      release: () => {},
      emit: (e) => events.push(e),
      vaultUnlocked: () => true
    })
    sampler.configure({
      enabled: true,
      intervalMs: 60_000,
      targets: [target('a'), target('b'), target('c')]
    })
    await vi.advanceTimersByTimeAsync(0)

    expect(events.map((e) => e.serverId)).toEqual(['a', 'b', 'c'])
    expect(events[1].error).toContain('ETIMEDOUT')
    expect(events[1].host).toBeUndefined()
    // An error is emitted rather than swallowed, so the UI can say "could not
    // ask" rather than showing a stale number as if it were current.
    expect(events[0].host).toBeDefined()
    expect(events[2].host).toBeDefined()
    sampler.dispose()
  })

  it('carries a failed result through as an error, not as a gap', async () => {
    const events: FleetSampleEvent[] = []
    const sampler = new FleetSampler({
      sample: async () => ({ ok: false, error: 'permission denied' }),
      release: () => {},
      emit: (e) => events.push(e),
      vaultUnlocked: () => true
    })
    sampler.configure({ enabled: true, intervalMs: 60_000, targets: [target('a')] })
    await vi.advanceTimersByTimeAsync(0)
    expect(events[0]).toMatchObject({ serverId: 'a', error: 'permission denied' })
    sampler.dispose()
  })
})

describe('never overlapping itself', () => {
  it('measures the gap from the end of a sweep, not the start', async () => {
    // A sweep slower than the interval must slow the cadence rather than
    // stack up. Fifteen servers on a slow link can easily exceed the gap.
    const h = harness({ slow: true })
    h.sampler.configure({ enabled: true, intervalMs: 60_000, targets: [target('a')] })
    await vi.advanceTimersByTimeAsync(0)
    expect(h.calls).toHaveLength(1)

    // Interval elapses while the first sample is still outstanding.
    await vi.advanceTimersByTimeAsync(120_000)
    expect(h.calls).toHaveLength(1)

    h.resolveAll()
    await vi.advanceTimersByTimeAsync(0)
    // Still one: the next is scheduled an interval after this one finished.
    expect(h.calls).toHaveLength(1)
    await vi.advanceTimersByTimeAsync(60_000)
    expect(h.calls).toHaveLength(2)
    h.sampler.dispose()
  })

  it('drops a requested sweep that arrives while one is running', async () => {
    // Queuing it would double the load to answer a question already in flight.
    const h = harness({ slow: true })
    h.sampler.configure({ enabled: true, intervalMs: 60_000, targets: [target('a')] })
    await vi.advanceTimersByTimeAsync(0)
    expect(h.calls).toHaveLength(1)

    void h.sampler.sampleNow()
    await vi.advanceTimersByTimeAsync(0)
    expect(h.calls).toHaveLength(1)
    h.resolveAll()
    h.sampler.dispose()
  })
})

describe('reconfiguration and teardown', () => {
  it('does not let a sweep in flight resurrect a loop that was stopped', async () => {
    // The race this closes: reconfigure to disabled while a sweep is running,
    // and the sweep's own finally-block schedules the next one.
    const h = harness({ slow: true })
    h.sampler.configure({ enabled: true, intervalMs: 60_000, targets: [target('a')] })
    await vi.advanceTimersByTimeAsync(0)

    h.sampler.configure({ enabled: false, intervalMs: 60_000, targets: [target('a')] })
    h.resolveAll()
    await vi.advanceTimersByTimeAsync(10 * 60_000)

    expect(h.calls).toHaveLength(1)
    expect(h.sampler.status().running).toBe(false)
  })

  it('keeps running when a reconfigure lands mid-sweep', async () => {
    // The defect this exists for: configure() bumps the generation and
    // schedules immediately; that run is refused because a sweep is in flight
    // and has already consumed the timer; the old sweep's finally then declines
    // to reschedule because the generation moved. Net: no timer, not sweeping,
    // dead forever -- while status() still said `running`.
    //
    // The trigger is ordinary. Connecting to one server fires setServerStatus
    // 'connecting' then 'online', rebuilding the target list twice seconds
    // apart, so opening a single SSH session killed background monitoring for
    // the rest of the session.
    //
    // The sibling test below asserts only that the superseded sweep emits
    // nothing, which a permanently dead sampler also satisfies. This one
    // asserts the loop survives.
    const h = harness({ slow: true })
    h.sampler.configure({ enabled: true, intervalMs: 60_000, targets: [target('a')] })
    await vi.advanceTimersByTimeAsync(0)
    expect(h.calls).toEqual(['fleet:a'])

    h.sampler.configure({ enabled: true, intervalMs: 60_000, targets: [target('b')] })
    // Order is the whole reproduction. The reconfigure's immediate run must
    // fire while the first sweep is STILL in flight, so it is refused and
    // consumes the timer. Resolving the sample first lets the old sweep finish
    // and reschedule normally, which is why an earlier version of this test
    // passed against the bug.
    await vi.advanceTimersByTimeAsync(0)
    h.resolveAll()
    await vi.advanceTimersByTimeAsync(0)

    // The new configuration is sampled promptly -- the user just asked for it.
    expect(h.calls).toContain('fleet:b')
    expect(h.sampler.status().running).toBe(true)

    // And the loop keeps going rather than stopping after that one run.
    h.resolveAll()
    await vi.advanceTimersByTimeAsync(60_000)
    h.resolveAll()
    await vi.advanceTimersByTimeAsync(0)
    expect(h.calls.filter((c) => c === 'fleet:b').length).toBeGreaterThanOrEqual(2)
    h.sampler.dispose()
  })

  it('reports not-running when the loop has actually stopped', async () => {
    // status() derived `running` from the config, so a stalled sampler was
    // reported healthy and the settings screen affirmed it.
    const h = harness()
    h.sampler.configure({ enabled: true, intervalMs: 60_000, targets: [target('a')] })
    await vi.advanceTimersByTimeAsync(0)
    expect(h.sampler.status().running).toBe(true)
    h.sampler.dispose()
    expect(h.sampler.status().running).toBe(false)
  })

  it('emits nothing for a sweep superseded by a reconfigure', async () => {
    const h = harness({ slow: true })
    h.sampler.configure({ enabled: true, intervalMs: 60_000, targets: [target('a')] })
    await vi.advanceTimersByTimeAsync(0)
    h.sampler.configure({ enabled: true, intervalMs: 60_000, targets: [target('z')] })
    h.resolveAll()
    await vi.advanceTimersByTimeAsync(0)
    // The 'a' result belonged to a configuration that no longer exists.
    expect(h.events.some((e) => e.serverId === 'a')).toBe(false)
    h.sampler.dispose()
  })

  it('stops for good once disposed', async () => {
    const h = harness()
    h.sampler.configure({ enabled: true, intervalMs: 60_000, targets: [target('a')] })
    await vi.advanceTimersByTimeAsync(0)
    const before = h.calls.length
    h.sampler.dispose()
    await vi.advanceTimersByTimeAsync(10 * 60_000)
    expect(h.calls).toHaveLength(before)
    // And configure() after dispose does not bring it back.
    h.sampler.configure({ enabled: true, intervalMs: 60_000, targets: [target('a')] })
    await vi.advanceTimersByTimeAsync(10 * 60_000)
    expect(h.calls).toHaveLength(before)
  })
})

describe('status', () => {
  it('reports how long the last sweep took, so a cadence can be judged', async () => {
    const h = harness()
    h.sampler.configure({ enabled: true, intervalMs: 60_000, targets: [target('a')] })
    await vi.advanceTimersByTimeAsync(0)
    const s = h.sampler.status()
    expect(s.running).toBe(true)
    expect(s.targetCount).toBe(1)
    expect(s.lastSweepAt).toBeTypeOf('number')
    expect(s.lastSweepMs).toBeTypeOf('number')
    h.sampler.dispose()
  })
})

// Child effects run before parent effects in React, and FleetMonitor is a child
// of the tree FleetWatcher sits at the root of. So on a cold start with the
// monitor as the opening view, sampleNow() reaches main BEFORE configure() does
// and finds no targets. What saves it is configure() scheduling at zero — but
// that is a property of a different method, held by nothing, and the panel goes
// blank for a whole interval if it ever stops being true.
describe('the monitor asking for a sweep before it has been configured', () => {
  it('still sweeps promptly, because configure schedules immediately', async () => {
    const h = harness()
    await h.sampler.sampleNow() // no targets yet: nothing to do
    expect(h.calls).toEqual([])

    h.sampler.configure({ enabled: true, intervalMs: 60_000, targets: [target('a')] })
    await vi.advanceTimersByTimeAsync(0)
    // Not "eventually" — at zero delay. A first sweep an interval later is the
    // failure this covers, and an interval can be an hour.
    expect(h.calls).toEqual([fleetKey('a')])
  })

  it('reports no-targets rather than running while it waits', () => {
    const h = harness()
    expect(h.sampler.status()).toMatchObject({ running: false, idleReason: 'disabled' })
  })
})

// The sampler is already asking every server these questions on a schedule.
// get_server_metrics used to ignore that entirely and open its own connection
// under an `mcp:` key — a third authenticated session per server, and an agent
// quoting numbers that disagreed with the monitor on screen. What is pinned
// here is the cache the bridge reads, because a cache is exactly where an
// agent starts answering "what is failing right now" from stale data.
describe('what the sampler remembers for the MCP bridge', () => {
  it('knows nothing about a server it has never swept', () => {
    const h = harness()
    expect(h.sampler.lookup('a')).toBeUndefined()
  })

  it('remembers a successful sample, with when it was taken', async () => {
    const h = harness()
    h.sampler.configure({ enabled: true, intervalMs: 60_000, targets: [target('a')] })
    await vi.advanceTimersByTimeAsync(0)
    const found = h.sampler.lookup('a')
    expect(found?.entry.host).toMatchObject({ hostname: fleetKey('a') })
    expect(found?.entry.at).toBe(Date.now())
    // The interval comes with it: "stale" means nothing without knowing how
    // often this is supposed to refresh.
    expect(found?.intervalMs).toBe(60_000)
  })

  it('keeps the last good sample when a later sweep fails', async () => {
    const h = harness()
    h.sampler.configure({ enabled: true, intervalMs: 60_000, targets: [target('a')] })
    await vi.advanceTimersByTimeAsync(0)
    const goodAt = h.sampler.lookup('a')?.entry.at

    h.failNext('host unreachable')
    await vi.advanceTimersByTimeAsync(60_000)

    const found = h.sampler.lookup('a')
    // Both facts survive. "It was fine a minute ago" and "it is not answering
    // now" are different answers and an agent needs each of them.
    expect(found?.entry.host).toBeTruthy()
    expect(found?.entry.at).toBe(goodAt)
    expect(found?.entry.error).toBe('host unreachable')
  })

  it('clears the error once the host answers again', async () => {
    const h = harness()
    h.sampler.configure({ enabled: true, intervalMs: 60_000, targets: [target('a')] })
    await vi.advanceTimersByTimeAsync(0)
    h.failNext('boom')
    await vi.advanceTimersByTimeAsync(60_000)
    expect(h.sampler.lookup('a')?.entry.error).toBe('boom')

    await vi.advanceTimersByTimeAsync(60_000)
    expect(h.sampler.lookup('a')?.entry.error).toBeUndefined()
  })

  it('forgets a server dropped from the workspace', async () => {
    const h = harness()
    h.sampler.configure({ enabled: true, intervalMs: 60_000, targets: [target('a'), target('b')] })
    await vi.advanceTimersByTimeAsync(0)
    expect(h.sampler.lookup('a')).toBeTruthy()

    h.sampler.configure({ enabled: true, intervalMs: 60_000, targets: [target('b')] })
    // Otherwise a removed server keeps answering MCP questions from a sample
    // nothing can ever refresh.
    expect(h.sampler.lookup('a')).toBeUndefined()
    expect(h.sampler.lookup('b')).toBeTruthy()
  })

  it('forgets everything on dispose', async () => {
    const h = harness()
    h.sampler.configure({ enabled: true, intervalMs: 60_000, targets: [target('a')] })
    await vi.advanceTimersByTimeAsync(0)
    h.sampler.dispose()
    expect(h.sampler.lookup('a')).toBeUndefined()
  })
})
