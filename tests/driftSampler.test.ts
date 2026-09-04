import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { FleetSampler } from '../src/main/services/fleetSampler'
import type { FleetTarget } from '../src/shared/fleet'
import type { HostDrift } from '../src/shared/drift'

// Configuration drift in the sweep — roadmap item 25.
//
// Three things are invisible until they are wrong, and all three are here: the
// module toggle gating the CHANNEL rather than the tab, the host's own name
// reaching the normaliser, and a failed collection keeping the last good one
// instead of erasing it.

const target = (id: string, name = `srv-${id}`): FleetTarget => ({
  serverId: id,
  serverName: name,
  cfg: { host: 'h', port: 22, username: 'u' } as FleetTarget['cfg']
})

const drift = (at = 1): HostDrift => ({
  at,
  readings: [{ watchId: 'timezone', status: 'ok', hash: 'h', normalisedHash: 'n' }]
})

interface Harness {
  sampler: FleetSampler
  calls: { key: string; ctx: { hostname?: string; serverName?: string } }[]
  upserts: { host: string; key: string; value: string }[]
  retired: { host: string; prefix: string; keep: string[] }[]
  setEnabled: (on: boolean) => void
  failDrift: (error: string | null) => void
}

function harness(over: { enabledGate?: boolean; hostname?: string } = {}): Harness {
  const calls: Harness['calls'] = []
  const upserts: Harness['upserts'] = []
  const retired: Harness['retired'] = []
  let enabled = true
  let error: string | null = null

  const sampler = new FleetSampler({
    sample: async (key) => ({
      ok: true,
      data: { hostname: over.hostname ?? `${key}.example.internal`, services: null, listeners: null }
    }),
    ...(over.enabledGate === false ? {} : { driftEnabled: () => enabled }),
    sampleDrift: async (key, _cfg, ctx) => {
      calls.push({ key, ctx })
      if (error !== null) return { ok: false, error }
      return { ok: true, drift: drift() }
    },
    release: () => undefined,
    emit: () => undefined,
    vaultUnlocked: () => true,
    history: () => ({
      transaction: <T,>(fn: () => T): T => fn(),
      recordSamples: () => undefined,
      // Filtered to this feature's prefix. The sweep writes the metrics facts
      // too, and a test that asserted over everything would be asserting on
      // somebody else's rows.
      upsertFact: (host, key, value) => {
        if (key.startsWith('drift:')) upserts.push({ host, key, value })
        return 'created'
      },
      retireFacts: (host, _at, prefix, keep) => {
        if (prefix === 'drift:') retired.push({ host, prefix, keep: [...keep] })
        return 0
      },
      recordEvent: () => undefined
    })
  })

  sampler.configure({
    enabled: true,
    intervalMs: 120_000,
    targets: [target('a', 'web-01')]
  })

  return {
    sampler,
    calls,
    upserts,
    retired,
    setEnabled: (on) => {
      enabled = on
    },
    failDrift: (e) => {
      error = e
    }
  }
}

beforeEach(() => {
  vi.useFakeTimers()
})
afterEach(() => {
  vi.useRealTimers()
})

describe('the drift probe in the sweep', () => {
  it('does not open a channel at all while the module is off', async () => {
    // The toggle gates the COLLECTION, not the tab. A version that hid the
    // panel while the sweep kept reading seven files off every host every hour
    // would be exactly the thing the module registry exists to make a person
    // decide about.
    const h = harness()
    h.setEnabled(false)
    await h.sampler.sampleNow()
    expect(h.calls).toEqual([])
    expect(h.upserts).toEqual([])
  })

  it('starts collecting on the next sweep after the toggle goes on', async () => {
    // A function rather than a captured flag, so switching it on does not need
    // a restart.
    const h = harness()
    h.setEnabled(false)
    await h.sampler.sampleNow()
    h.setEnabled(true)
    await h.sampler.sampleNow()
    expect(h.calls).toHaveLength(1)
  })

  it('hands the probe the host name from this sweep, so the hostname rule has one', async () => {
    // Without it, every templated file in the estate is unique and the whole
    // comparison is noise. Taken from THIS sweep's sample rather than a cached
    // one: a renamed host normalised against the name it used to have reads as
    // having drifted in every file it owns.
    const h = harness({ hostname: 'web-01.example.internal' })
    await h.sampler.sampleNow()
    expect(h.calls[0].ctx).toEqual({
      hostname: 'web-01.example.internal',
      serverName: 'web-01'
    })
  })

  it('writes two hashes and a status, and nothing that could be file content', async () => {
    const h = harness()
    await h.sampler.sampleNow()
    expect(h.upserts.map((u) => u.key)).toEqual([
      'drift:timezone:status',
      'drift:timezone:hash',
      'drift:timezone:normalised'
    ])
    expect(h.retired).toEqual([
      {
        host: 'a',
        prefix: 'drift:',
        keep: ['drift:timezone:status', 'drift:timezone:hash', 'drift:timezone:normalised']
      }
    ])
  })

  it('writes nothing on a sweep where the probe was not due', async () => {
    // Sweeping the prefix on a sweep with no collection would retire a complete
    // reading thirty times an hour.
    const h = harness()
    await h.sampler.sampleNow()
    const after = h.upserts.length
    await h.sampler.sampleNow()
    expect(h.calls).toHaveLength(1)
    expect(h.upserts).toHaveLength(after)
    expect(h.retired).toHaveLength(1)
  })

  it('keeps the last good collection when the probe fails', async () => {
    // A host whose files were read an hour ago and whose probe is failing now
    // has NOT come into line. Replacing the readings with nothing would render
    // it as a host nobody has collected, which is a softer word than the truth.
    const h = harness()
    await h.sampler.sampleNow()
    expect(h.sampler.driftFor('a').drift?.readings[0].hash).toBe('h')

    h.failDrift('connect ETIMEDOUT')
    // Push the due clock past the hour so the probe runs again.
    vi.setSystemTime(Date.now() + 3_600_001)
    await h.sampler.sampleNow()

    const view = h.sampler.driftFor('a')
    expect(view.drift?.readings[0].hash).toBe('h')
    expect(view.error).toBe('connect ETIMEDOUT')
  })

  it('survives the twenty-nine metrics sweeps between two collections', async () => {
    // The bug this found on the way in: `remember` rebuilds the cache entry on
    // every metrics sample and carries the hourly collections across by hand.
    // Adding a fourth one without adding it to that list erases it thirty times
    // an hour, and the panel reports "not collected" on a host whose files were
    // read four minutes ago.
    //
    // Fail-first, before `drift` was added to the carried set in `remember`:
    //   AssertionError: expected undefined to be 'h' // Object.is equality
    const h = harness()
    await h.sampler.sampleNow()
    // A second sweep, with the drift probe not due — a plain metrics sample.
    await h.sampler.sampleNow()
    expect(h.calls).toHaveLength(1)
    expect(h.sampler.driftFor('a').drift?.readings[0].hash).toBe('h')
  })

  it('forgets a server dropped from the workspace', async () => {
    // A server removed must not keep answering from a collection nobody can
    // refresh.
    const h = harness()
    await h.sampler.sampleNow()
    h.sampler.configure({ enabled: true, intervalMs: 120_000, targets: [] })
    expect(h.sampler.driftFor('a').drift).toBeUndefined()
  })

  it('runs with no drift probe injected at all, exactly as it did before', async () => {
    const sampler = new FleetSampler({
      sample: async () => ({ ok: true, data: { hostname: 'h', services: null, listeners: null } }),
      release: () => undefined,
      emit: () => undefined,
      vaultUnlocked: () => true
    })
    sampler.configure({ enabled: true, intervalMs: 120_000, targets: [target('a')] })
    await sampler.sampleNow()
    expect(sampler.driftFor('a').drift).toBeUndefined()
  })
})
