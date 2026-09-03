import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { FleetSampler, clampFactsInterval } from '../src/main/services/fleetSampler'
import type { FleetSampleEvent, FleetTarget } from '../src/shared/fleet'
import { HOST_FACTS_INTERVAL_MIN_MS, HOST_FACTS_INTERVAL_MS, parseHostFacts } from '../src/shared/hostFacts'
import type { HostFacts } from '../src/shared/hostFacts'

// The slow half of the sweep — roadmap item C's sampler integration.
//
// Everything here is about CADENCE and about what survives between
// collections, because those are the two things that are invisible until they
// are wrong: a facts probe that runs every sweep puts `dnf check-update` on
// every host every two minutes, and a facts set that does not survive a
// metrics-only sweep leaves the inventory empty except in the one sweep out of
// thirty that had just refreshed it.

const target = (id: string): FleetTarget => ({
  serverId: id,
  serverName: `srv-${id}`,
  cfg: { host: 'h', port: 22, username: 'u' } as FleetTarget['cfg']
})

const facts = (pm: string): HostFacts =>
  parseHostFacts(['V pkg ' + pm, '===SHELLPILOT-FACTS===', 'package-manager ok -'].join('\n'))

interface Store {
  upserts: { host: string; key: string; value: string; at: number }[]
  retired: { host: string; prefix: string; keep: string[] }[]
}

interface Harness {
  sampler: FleetSampler
  events: FleetSampleEvent[]
  /** Every key the facts probe was asked for, in order. */
  factCalls: string[]
  metricCalls: string[]
  store: Store
  failMetrics: (error: string | null) => void
  failFacts: (error: string | null) => void
  throwFacts: (on: boolean) => void
}

function harness(over: { withFacts?: boolean; factsIntervalMs?: number } = {}): Harness {
  const events: FleetSampleEvent[] = []
  const factCalls: string[] = []
  const metricCalls: string[] = []
  const store: Store = { upserts: [], retired: [] }
  let metricsError: string | null = null
  let factsError: string | null = null
  let factsThrows = false
  const pm = 'apt'

  const sampler = new FleetSampler({
    sample: async (key) => {
      metricCalls.push(key)
      if (metricsError !== null) return { ok: false, error: metricsError }
      return { ok: true, data: { hostname: key, services: null, listeners: null } }
    },
    ...(over.withFacts === false
      ? {}
      : {
          sampleFacts: async (key) => {
            factCalls.push(key)
            if (factsThrows) throw new Error('probe exploded')
            if (factsError !== null) return { ok: false, error: factsError }
            return { ok: true, facts: facts(pm) }
          }
        }),
    release: () => undefined,
    emit: (e) => events.push(e),
    vaultUnlocked: () => true,
    history: () => ({
      transaction: <T,>(fn: () => T): T => fn(),
      recordSamples: () => undefined,
      upsertFact: (host, key, value, at) => {
        store.upserts.push({ host, key, value, at })
        return 'created'
      },
      retireFacts: (host, _at, prefix, keep) => {
        store.retired.push({ host, prefix, keep: [...keep] })
        return 0
      },
      recordEvent: () => undefined
    })
  })

  // Two-minute metrics cadence against an hourly facts cadence — the real
  // ratio, so "one sweep in thirty" is what the tests actually exercise.
  sampler.configure({
    enabled: true,
    intervalMs: 120_000,
    factsIntervalMs: over.factsIntervalMs,
    targets: [target('a')]
  })

  return {
    sampler,
    events,
    factCalls,
    metricCalls,
    store,
    failMetrics: (e) => {
      metricsError = e
    },
    failFacts: (e) => {
      factsError = e
    },
    throwFacts: (on) => {
      factsThrows = on
    }
  }
}

beforeEach(() => {
  vi.useFakeTimers()
})
afterEach(() => {
  vi.useRealTimers()
})

describe('the facts cadence', () => {
  it('refuses a cadence that would shell out to a package manager every sweep', () => {
    // The probe runs `dnf check-update` on a 45-second budget. At the metrics
    // cadence that is every host, every two minutes, forever.
    expect(clampFactsInterval(2_000)).toBe(HOST_FACTS_INTERVAL_MIN_MS)
    expect(clampFactsInterval(0)).toBe(HOST_FACTS_INTERVAL_MIN_MS)
  })

  it('defaults to hourly when nothing is configured', () => {
    // A config written before facts existed has no field for them, and must not
    // resolve to "as often as allowed".
    expect(clampFactsInterval(undefined)).toBe(HOST_FACTS_INTERVAL_MS)
    expect(clampFactsInterval(Number.NaN)).toBe(HOST_FACTS_INTERVAL_MS)
  })

  it('has no maximum: once a day is a reasonable thing to want', () => {
    expect(clampFactsInterval(24 * 60 * 60 * 1000)).toBe(24 * 60 * 60 * 1000)
  })

  it('collects on the first sweep rather than an hour after start-up', async () => {
    // The due map is in memory, so a restart has no schedule to remember. A
    // host with no entry is due immediately — otherwise every restart leaves
    // the inventory blank for an hour.
    const h = harness()
    await vi.advanceTimersByTimeAsync(0)
    expect(h.factCalls).toEqual(['fleet:a'])
  })

  it('does not collect again on the next twenty-nine sweeps', async () => {
    const h = harness()
    await vi.advanceTimersByTimeAsync(0)
    await vi.advanceTimersByTimeAsync(29 * 120_000)
    expect(h.metricCalls.length).toBeGreaterThan(20)
    expect(h.factCalls).toEqual(['fleet:a'])
  })

  it('collects again once the hour is up', async () => {
    const h = harness()
    await vi.advanceTimersByTimeAsync(0)
    await vi.advanceTimersByTimeAsync(HOST_FACTS_INTERVAL_MS + 120_000)
    expect(h.factCalls).toEqual(['fleet:a', 'fleet:a'])
  })

  it('adds no timer of its own', async () => {
    // The sweep already owns the vault re-check, the generation guard and
    // disposal. A second timer would have to re-derive all three, and
    // duplicating that reasoning is how it breaks. Stopping the sweep must stop
    // the facts probe, with nothing else to remember.
    const h = harness()
    await vi.advanceTimersByTimeAsync(0)
    h.sampler.configure({ enabled: false, intervalMs: 120_000, targets: [target('a')] })
    await vi.advanceTimersByTimeAsync(10 * HOST_FACTS_INTERVAL_MS)
    expect(h.factCalls).toEqual(['fleet:a'])
  })

  it('does not probe a host that just failed its metrics sample', async () => {
    // A host that refused a metrics channel will refuse this one too, and
    // paying a 45-second timeout to find that out again costs the rest of the
    // estate its place in the sweep.
    const h = harness()
    h.failMetrics('connect ECONNREFUSED')
    await vi.advanceTimersByTimeAsync(0)
    expect(h.metricCalls).toEqual(['fleet:a'])
    expect(h.factCalls).toEqual([])
  })

  it('pushes the next attempt out even when the probe throws', async () => {
    // A host that reliably fails must not be retried on every sweep with a
    // 45-second budget — that is the whole estate's sweep time spent on one
    // broken box.
    //
    // What this asserts is the OUTCOME (one attempt per interval regardless of
    // how the probe ended), not the placement of the assignment. The `.catch()`
    // around the probe means before-and-after are equivalent for a throw; the
    // assignment is still made first because the generation guard between them
    // can return early, and that path has no test here.
    const h = harness()
    h.throwFacts(true)
    await vi.advanceTimersByTimeAsync(0)
    expect(h.factCalls).toEqual(['fleet:a'])
    await vi.advanceTimersByTimeAsync(10 * 120_000)
    expect(h.factCalls).toEqual(['fleet:a'])
  })

  it('works exactly as before when no facts probe is injected', async () => {
    // Optional by design: every existing sampler test builds deps without one.
    const h = harness({ withFacts: false })
    await vi.advanceTimersByTimeAsync(0)
    await vi.advanceTimersByTimeAsync(5 * 120_000)
    expect(h.factCalls).toEqual([])
    expect(h.metricCalls.length).toBeGreaterThan(1)
    expect(h.sampler.factsFor('a').facts).toBeUndefined()
  })
})

describe('what the cache keeps between collections', () => {
  it('keeps facts across the twenty-nine metrics-only sweeps that follow', async () => {
    // The bug this is here for: remember() rebuilds the cache entry on every
    // metrics sample. Rebuilding it without the facts half erases an hour-old
    // inventory thirty times an hour.
    const h = harness()
    await vi.advanceTimersByTimeAsync(0)
    expect(h.sampler.factsFor('a').facts?.packageManager).toBe('apt')
    await vi.advanceTimersByTimeAsync(10 * 120_000)
    expect(h.sampler.factsFor('a').facts?.packageManager).toBe('apt')
  })

  it('keeps facts across a metrics failure too', async () => {
    // "This host's inventory was read an hour ago and it is unreachable now" is
    // two facts and an operator needs both.
    const h = harness()
    await vi.advanceTimersByTimeAsync(0)
    h.failMetrics('host went away')
    await vi.advanceTimersByTimeAsync(3 * 120_000)
    expect(h.sampler.factsFor('a').facts?.packageManager).toBe('apt')
    expect(h.sampler.lookup('a')?.entry.error).toBe('host went away')
  })

  it('keeps the last good facts when the probe itself starts failing', async () => {
    const h = harness({ factsIntervalMs: HOST_FACTS_INTERVAL_MIN_MS })
    await vi.advanceTimersByTimeAsync(0)
    h.failFacts('sudo: a password is required')
    await vi.advanceTimersByTimeAsync(HOST_FACTS_INTERVAL_MIN_MS + 120_000)
    const got = h.sampler.factsFor('a')
    expect(got.facts?.packageManager).toBe('apt')
    expect(got.error).toBe('sudo: a password is required')
    // The timestamps are separate, so a reader can say "read an hour ago,
    // failing since twenty minutes ago" rather than picking one.
    expect(got.errorAt).toBeGreaterThan(got.at ?? 0)
  })

  it('clears the facts error on the next success', async () => {
    const h = harness({ factsIntervalMs: HOST_FACTS_INTERVAL_MIN_MS })
    h.failFacts('temporarily broken')
    await vi.advanceTimersByTimeAsync(0)
    expect(h.sampler.factsFor('a').error).toBe('temporarily broken')
    h.failFacts(null)
    await vi.advanceTimersByTimeAsync(HOST_FACTS_INTERVAL_MIN_MS + 120_000)
    expect(h.sampler.factsFor('a').error).toBeUndefined()
    expect(h.sampler.factsFor('a').facts).toBeDefined()
  })

  it('forgets a server dropped from the workspace', async () => {
    // A removed server must not keep answering from a set nobody can refresh.
    const h = harness()
    await vi.advanceTimersByTimeAsync(0)
    h.sampler.configure({ enabled: true, intervalMs: 120_000, targets: [] })
    expect(h.sampler.factsFor('a').facts).toBeUndefined()
  })

  it('quotes the facts cadence, not the metrics one', async () => {
    // An hour-old fact judged against a two-minute interval is thirty intervals
    // stale when it is exactly on schedule.
    const h = harness()
    await vi.advanceTimersByTimeAsync(0)
    expect(h.sampler.lookup('a')?.intervalMs).toBe(120_000)
    expect(h.sampler.lookup('a')?.factsIntervalMs).toBe(HOST_FACTS_INTERVAL_MS)
  })
})

describe('what the renderer is told', () => {
  it('carries facts only on the sweep that collected them', async () => {
    // Absence means "not collected on this sweep", never "this host has none".
    const h = harness()
    await vi.advanceTimersByTimeAsync(0)
    expect(h.events[0].facts?.packageManager).toBe('apt')
    await vi.advanceTimersByTimeAsync(3 * 120_000)
    expect(h.events.length).toBeGreaterThan(1)
    for (const e of h.events.slice(1)) expect(e.facts).toBeUndefined()
  })

  it('reports a facts failure separately from a metrics failure', async () => {
    const h = harness()
    h.failFacts('the host answered but returned no usable facts')
    await vi.advanceTimersByTimeAsync(0)
    // The metrics half succeeded; only the facts half did not.
    expect(h.events[0].host).toBeDefined()
    expect(h.events[0].error).toBeUndefined()
    expect(h.events[0].factsError).toBe('the host answered but returned no usable facts')
  })
})

describe('what reaches the durable store', () => {
  it('writes host facts under their own prefix, into item A’s store', async () => {
    const h = harness()
    await vi.advanceTimersByTimeAsync(0)
    const keys = h.store.upserts.filter((u) => u.key.startsWith('host:')).map((u) => u.key)
    expect(keys).toContain('host:packageManager')
    expect(keys).toContain('host:securityUpdates')
    expect(keys).toContain('host:source:security-updates')
    // Every host fact is written under one prefix so retirement has a scope.
    expect(h.store.retired.some((r) => r.prefix === 'host:')).toBe(true)
  })

  it('stores the STATUS where a value is null, not a zero', async () => {
    const h = harness()
    await vi.advanceTimersByTimeAsync(0)
    const sec = h.store.upserts.find((u) => u.key === 'host:securityUpdates')
    // The fixture's collection never reported a security count. It must not
    // land in history as 0.
    expect(sec?.value).toBe('unknown')
  })

  it('does not retire host facts on a sweep that did not collect them', async () => {
    // Retiring against an empty set would delete the whole inventory thirty
    // times an hour and record a fact-removed event for every key each time.
    const h = harness()
    await vi.advanceTimersByTimeAsync(0)
    const after = h.store.retired.filter((r) => r.prefix === 'host:').length
    await vi.advanceTimersByTimeAsync(10 * 120_000)
    expect(h.store.retired.filter((r) => r.prefix === 'host:').length).toBe(after)
  })

  it('writes nothing to the store when the probe failed', async () => {
    const h = harness()
    h.failFacts('unreachable: connect ECONNREFUSED')
    await vi.advanceTimersByTimeAsync(0)
    expect(h.store.upserts.some((u) => u.key.startsWith('host:'))).toBe(false)
    expect(h.store.retired.some((r) => r.prefix === 'host:')).toBe(false)
  })
})
