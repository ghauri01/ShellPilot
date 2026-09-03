import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import {
  FleetSampler,
  PORT_FACT_PREFIX,
  UNIT_FACT_PREFIX,
  metricsToFacts,
  metricsToSamples,
  type HistoryWriter
} from '../src/main/services/fleetSampler'
import type { FleetTarget } from '../src/shared/fleet'
import type { HostMetrics } from '../src/shared/ssh'
import { loadHistory, resetHistoryModuleForTests, type HistoryStore } from '../src/main/services/history'

// The store is only worth having if something real writes to it. The repo's own
// pre-release review named "main-process work the renderer never calls" as the
// failure pattern that produced most of its findings, and a durable store with
// no producer is the same shape of mistake one level down.
//
// So these tests are about the sampler's sweep actually landing in the database,
// and about every way that could go wrong being survivable.

const target = (id: string): FleetTarget => ({
  serverId: id,
  serverName: `srv-${id}`,
  cfg: { host: 'h', port: 22, username: 'u' } as FleetTarget['cfg']
})

const metrics = (over: Partial<HostMetrics> = {}): HostMetrics => ({
  cpu: 12,
  memPct: 34,
  memUsed: 1024,
  memTotal: 4096,
  diskPct: 56,
  diskUsed: 500,
  diskTotal: 1000,
  netRx: 7,
  netTx: 8,
  uptime: 9000,
  hostname: 'web-1.example',
  kernel: '6.1.0',
  cores: 4,
  services: [{ name: 'nginx.service', active: 'active', sub: 'running', description: 'nginx' }],
  listeners: [{ proto: 'tcp', address: '0.0.0.0', port: 443, process: 'nginx' }],
  listenerSource: 'ss',
  ...over
})

describe('mapping a sample onto the schema', () => {
  it('keeps exactly the eight numeric series', () => {
    const s = metricsToSamples(metrics())
    expect(Object.keys(s).sort()).toEqual(
      ['cpu', 'diskPct', 'diskUsed', 'memPct', 'memUsed', 'netRx', 'netTx', 'uptime'].sort()
    )
    expect(s.cpu).toBe(12)
    expect(s.uptime).toBe(9000)
  })

  it('routes the constants to facts rather than paying the metric budget for them', () => {
    const f = metricsToFacts(metrics())
    // memTotal, diskTotal and cores do not change between sweeps. Stored as
    // series they would be three more rows every two minutes, forever, all
    // identical.
    expect(f.memTotal).toBe('4096')
    expect(f.diskTotal).toBe('1000')
    expect(f.cores).toBe('4')
    expect(f.kernel).toBe('6.1.0')
    expect(f.hostname).toBe('web-1.example')
    expect(f.listenerSource).toBe('ss')
    expect(metricsToSamples(metrics())).not.toHaveProperty('memTotal')
  })

  it('turns units and ports into facts, which is the 5x saving', () => {
    const f = metricsToFacts(metrics())
    expect(f[`${UNIT_FACT_PREFIX}nginx.service`]).toBe('active/running')
    expect(f[`${PORT_FACT_PREFIX}tcp/0.0.0.0:443`]).toBe('nginx')
  })

  it('produces no unit or port facts when the probe could not see them', () => {
    // null is not empty. A container without systemd reports null, and
    // recording that as "this host has no units" is a different claim.
    const f = metricsToFacts(metrics({ services: null, listeners: null, listenerSource: null }))
    expect(Object.keys(f).filter((k) => k.startsWith(UNIT_FACT_PREFIX))).toEqual([])
    expect(Object.keys(f).filter((k) => k.startsWith(PORT_FACT_PREFIX))).toEqual([])
    expect(f).not.toHaveProperty('listenerSource')
  })
})

describe('a sweep against a real store', () => {
  let dir: string
  let store: HistoryStore

  beforeEach(async () => {
    vi.useFakeTimers()
    resetHistoryModuleForTests()
    dir = mkdtempSync(join(tmpdir(), 'shellpilot-fleethist-'))
    store = (await loadHistory(dir))!
    expect(store).not.toBeNull()
  })

  afterEach(() => {
    store?.close()
    vi.useRealTimers()
    resetHistoryModuleForTests()
    try {
      rmSync(dir, { recursive: true, force: true })
    } catch {
      /* a leftover temp dir is not worth failing a test over */
    }
  })

  function sampler(sample: (key: string) => { ok: boolean; data?: unknown; error?: string }): FleetSampler {
    return new FleetSampler({
      sample: async (key) => sample(key),
      release: () => undefined,
      emit: () => undefined,
      vaultUnlocked: () => true,
      history: () => store,
      now: () => 1_700_000_000_000
    })
  }

  it('lands samples and facts in the database', async () => {
    const s = sampler(() => ({ ok: true, data: metrics() }))
    s.configure({ enabled: true, intervalMs: 120_000, targets: [target('a')] })
    await vi.advanceTimersByTimeAsync(0)
    s.dispose()

    expect(store.readSeries('a', 'cpu', 0, Infinity)).toEqual([{ ts: 1_700_000_000_000, v: 12 }])
    expect(store.readSeries('a', 'diskPct', 0, Infinity)[0].v).toBe(56)
    expect(store.counts().samples).toBe(8)

    const facts = store.readFacts('a')
    expect(facts.map((f) => f.key)).toContain(`${UNIT_FACT_PREFIX}nginx.service`)
    expect(facts.map((f) => f.key)).toContain(`${PORT_FACT_PREFIX}tcp/0.0.0.0:443`)
    // A first sighting is a change, and every one of them is an event.
    expect(store.readEvents({ hostId: 'a', kind: 'fact-added' })).toHaveLength(facts.length)
  })

  it('writes facts once and only re-writes what changed', async () => {
    let unit = 'running'
    const s = sampler(() => ({
      ok: true,
      data: metrics({
        services: [{ name: 'nginx.service', active: 'active', sub: unit, description: 'nginx' }]
      })
    }))
    s.configure({ enabled: true, intervalMs: 120_000, targets: [target('a')] })
    await vi.advanceTimersByTimeAsync(0)
    const afterFirst = store.counts()

    // Three more sweeps with nothing changed.
    for (let i = 0; i < 3; i++) await vi.advanceTimersByTimeAsync(120_000)
    // Samples share a timestamp because `now` is frozen, so the count is
    // unchanged; what matters is that facts did not multiply.
    expect(store.counts().facts).toBe(afterFirst.facts)
    expect(store.counts().events).toBe(afterFirst.events)

    unit = 'dead'
    await vi.advanceTimersByTimeAsync(120_000)
    s.dispose()
    const changed = store.readEvents({ hostId: 'a', kind: 'fact-changed' })
    expect(changed).toHaveLength(1)
    expect(changed[0].payload).toEqual({
      key: `${UNIT_FACT_PREFIX}nginx.service`,
      from: 'active/running',
      to: 'active/dead'
    })
  })

  it('retires a unit that went away, but never on a null probe', async () => {
    let services: HostMetrics['services'] = [
      { name: 'nginx.service', active: 'active', sub: 'running', description: '' },
      { name: 'old.service', active: 'active', sub: 'running', description: '' }
    ]
    const s = sampler(() => ({ ok: true, data: metrics({ services }) }))
    s.configure({ enabled: true, intervalMs: 120_000, targets: [target('a')] })
    await vi.advanceTimersByTimeAsync(0)
    expect(store.readFacts('a').filter((f) => f.key.startsWith(UNIT_FACT_PREFIX))).toHaveLength(2)

    // The probe breaks. Retiring here would record two fact-removed events and
    // then two fact-added events the moment it came back — a fabricated history
    // of units being uninstalled and reinstalled.
    services = null
    await vi.advanceTimersByTimeAsync(120_000)
    expect(store.readFacts('a').filter((f) => f.key.startsWith(UNIT_FACT_PREFIX))).toHaveLength(2)
    expect(store.readEvents({ hostId: 'a', kind: 'fact-removed' })).toHaveLength(0)

    // The probe comes back and the unit really is gone.
    services = [{ name: 'nginx.service', active: 'active', sub: 'running', description: '' }]
    await vi.advanceTimersByTimeAsync(120_000)
    s.dispose()
    expect(store.readFacts('a').filter((f) => f.key.startsWith(UNIT_FACT_PREFIX))).toHaveLength(1)
    expect(store.readEvents({ hostId: 'a', kind: 'fact-removed' })[0].payload).toMatchObject({
      key: `${UNIT_FACT_PREFIX}old.service`
    })
  })

  it('records an unreachable host once, not once per sweep', async () => {
    let ok = true
    const s = sampler(() => (ok ? { ok: true, data: metrics() } : { ok: false, error: 'timeout' }))
    s.configure({ enabled: true, intervalMs: 120_000, targets: [target('a')] })
    await vi.advanceTimersByTimeAsync(0)

    ok = false
    // Five sweeps down. Without the transition check that is 720 identical rows
    // a day for a host that has been down since Tuesday.
    for (let i = 0; i < 5; i++) await vi.advanceTimersByTimeAsync(120_000)
    expect(store.readEvents({ hostId: 'a', kind: 'host-unreachable' })).toHaveLength(1)
    expect(store.readEvents({ hostId: 'a', kind: 'host-unreachable' })[0].payload).toEqual({
      error: 'timeout'
    })

    ok = true
    await vi.advanceTimersByTimeAsync(120_000)
    s.dispose()
    expect(store.readEvents({ hostId: 'a', kind: 'host-recovered' })).toHaveLength(1)
  })
})

describe('the store never breaks a sweep', () => {
  beforeEach(() => vi.useFakeTimers())
  afterEach(() => vi.useRealTimers())

  function run(history: (() => HistoryWriter | null) | undefined): Promise<string[]> {
    const calls: string[] = []
    const s = new FleetSampler({
      sample: async (key) => {
        calls.push(key)
        return { ok: true, data: metrics() }
      },
      release: () => undefined,
      emit: () => undefined,
      vaultUnlocked: () => true,
      history,
      now: () => 1000
    })
    s.configure({ enabled: true, intervalMs: 120_000, targets: [target('a'), target('b')] })
    return vi
      .advanceTimersByTimeAsync(0)
      .then(() => vi.advanceTimersByTimeAsync(120_000))
      .then(() => {
        s.dispose()
        return calls
      })
  }

  it('sweeps normally with no store injected at all', async () => {
    // The default. Every existing test constructs the sampler without one, and
    // the app must behave exactly as it did before this feature existed.
    expect(await run(undefined)).toEqual(['fleet:a', 'fleet:b', 'fleet:a', 'fleet:b'])
  })

  it('sweeps normally while the store is still opening', async () => {
    // loadHistory() is async and the sampler is built at module scope, so null
    // is the real state for the first moments of every launch.
    expect(await run(() => null)).toEqual(['fleet:a', 'fleet:b', 'fleet:a', 'fleet:b'])
  })

  it('sweeps normally when every write throws', async () => {
    const angry: HistoryWriter = {
      transaction: () => {
        throw new Error('disk is full')
      },
      recordSamples: () => undefined,
      upsertFact: () => undefined,
      retireFacts: () => 0,
      recordEvent: () => undefined
    }
    // A store that cannot write is a degraded feature. It is never a broken
    // sweep, an unhandled rejection, or a loop that stops rescheduling.
    expect(await run(() => angry)).toEqual(['fleet:a', 'fleet:b', 'fleet:a', 'fleet:b'])
  })

  it('writes one transaction per sweep, not one per host', async () => {
    let transactions = 0
    let samples = 0
    const counter: HistoryWriter = {
      transaction: (fn) => {
        transactions++
        return fn()
      },
      recordSamples: () => {
        samples++
      },
      upsertFact: () => undefined,
      retireFacts: () => 0,
      recordEvent: () => undefined
    }
    await run(() => counter)
    // Two sweeps, two hosts each. One BEGIN/COMMIT per sweep is the difference
    // between one fsync and 120 of them, on the same disk this app exists to
    // warn people about filling.
    expect(transactions).toBe(2)
    expect(samples).toBe(4)
  })
})
