import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { createHash } from 'node:crypto'
import { FleetSampler } from '../src/main/services/fleetSampler'
import type { FleetTarget } from '../src/shared/fleet'
import {
  ACCESS_FACT_PREFIX,
  ACCESS_STATUS_MARKER,
  accessKeyPrefix,
  parseAccessCollection,
  type HostAccess,
  type Sha256
} from '../src/shared/access'
import { HOST_FACTS_INTERVAL_MS } from '../src/shared/hostFacts'

// The key and access probe's place in the sweep — roadmap item 23.
//
// Everything here is about CADENCE and about what survives between
// collections, because those are the two things that are invisible until they
// are wrong. Two failures are specific to this probe and neither has an
// equivalent in the facts one:
//
//  * An access collection that does not survive a metrics-only sweep leaves
//    the panel reporting "no keys" on a host that trusts a dozen, twenty-nine
//    sweeps out of thirty.
//  * Retiring key facts for an account that could not be read this hour records
//    a fact-removed event per key — which reads as "these keys were revoked on
//    this host". That is the audit trail this item exists to produce, and
//    fabricating it is worse than producing none.

const sha256: Sha256 = (data) => new Uint8Array(createHash('sha256').update(data).digest())
const ED25519 = 'AAAAC3NzaC1lZDI1NTE5AAAAIJp0kFqDkGDMEnCH7mFY3sBRb+tSVEyKvJhLhZ+SHDdw'
const ED25519_FP = 'SHA256:wVlk8sEGn2qqP1yFjdkoYGu+eWPmKJ/koiL8zATTjxI'

const target = (id: string): FleetTarget => ({
  serverId: id,
  serverName: `srv-${id}`,
  cfg: { host: 'h', port: 22, username: 'u' } as FleetTarget['cfg']
})

const OK_STATUS = [
  'accounts ok -',
  'sshd-config ok - /etc/ssh/sshd_config',
  'account-status ok -',
  'sudoers ok -',
  'last-login ok - lastlog'
]

function collected(body: string[]): HostAccess {
  return parseAccessCollection([...body, ACCESS_STATUS_MARKER, ...OK_STATUS].join('\n'), {
    sha256,
    now: 1_800_000_000_000
  })
}

/** Both accounts read. */
const bothRead = (): HostAccess =>
  collected([
    'U 1 keys ok -',
    'U 1 name ops',
    `K 1 1 60 ssh-ed25519 ${ED25519} ops@laptop`,
    'U 2 keys ok -',
    'U 2 name deploy'
  ])

/** `ops` read, `deploy` closed to us this hour — the case the retirement rule
 *  exists for. */
const deployDenied = (): HostAccess =>
  collected([
    'U 1 keys ok -',
    'U 1 name ops',
    `K 1 1 60 ssh-ed25519 ${ED25519} ops@laptop`,
    'U 2 keys denied -',
    'U 2 name deploy'
  ])

interface Store {
  upserts: { host: string; key: string; value: string }[]
  retired: { host: string; prefix: string; keep: string[] }[]
}

interface Harness {
  sampler: FleetSampler
  accessCalls: string[]
  factCalls: string[]
  store: Store
  setAccess: (a: HostAccess | null) => void
  failAccess: (error: string | null) => void
  failFacts: (error: string | null) => void
  setEnabled: (on: boolean) => void
}

function harness(over: { withAccess?: boolean; gated?: boolean } = {}): Harness {
  const accessCalls: string[] = []
  const factCalls: string[] = []
  const store: Store = { upserts: [], retired: [] }
  let access: HostAccess | null = bothRead()
  let accessError: string | null = null
  let factsError: string | null = null
  let enabled = true

  const sampler = new FleetSampler({
    sample: async (key) => ({ ok: true, data: { hostname: key, services: null, listeners: null } }),
    sampleFacts: async (key) => {
      factCalls.push(key)
      if (factsError !== null) return { ok: false, error: factsError }
      return { ok: true, facts: { sources: [], collectedAt: 1 } as never }
    },
    ...(over.withAccess === false
      ? {}
      : {
          sampleAccess: async (key) => {
            accessCalls.push(key)
            if (accessError !== null) return { ok: false, error: accessError }
            return { ok: true, access: access ?? undefined }
          }
        }),
    ...(over.gated ? { accessEnabled: (): boolean => enabled } : {}),
    release: () => undefined,
    emit: () => undefined,
    vaultUnlocked: () => true,
    history: () => ({
      transaction: <T,>(fn: () => T): T => fn(),
      recordSamples: () => undefined,
      upsertFact: (host, key, value) => {
        store.upserts.push({ host, key, value })
        return 'created'
      },
      retireFacts: (host, _at, prefix, keep) => {
        store.retired.push({ host, prefix, keep: [...keep] })
        return 0
      },
      recordEvent: () => undefined
    })
  })

  // The real ratio: a two-minute metrics cadence against an hourly slow one.
  sampler.configure({ enabled: true, intervalMs: 120_000, targets: [target('a')] })

  return {
    sampler,
    accessCalls,
    factCalls,
    store,
    setAccess: (a) => {
      access = a
    },
    failAccess: (e) => {
      accessError = e
    },
    failFacts: (e) => {
      factsError = e
    },
    setEnabled: (on) => {
      enabled = on
    }
  }
}

beforeEach(() => {
  vi.useFakeTimers()
})
afterEach(() => {
  vi.useRealTimers()
})

describe('the cadence', () => {
  it('collects on the first sweep rather than an hour after start-up', async () => {
    const h = harness()
    await vi.advanceTimersByTimeAsync(0)
    expect(h.accessCalls).toEqual(['fleet:a'])
  })

  it('does not read every home directory on the host every two minutes', async () => {
    const h = harness()
    await vi.advanceTimersByTimeAsync(0)
    await vi.advanceTimersByTimeAsync(29 * 120_000)
    expect(h.accessCalls).toEqual(['fleet:a'])
  })

  it('collects again once the hour is up', async () => {
    const h = harness()
    await vi.advanceTimersByTimeAsync(0)
    await vi.advanceTimersByTimeAsync(HOST_FACTS_INTERVAL_MS + 120_000)
    expect(h.accessCalls).toEqual(['fleet:a', 'fleet:a'])
  })

  it('adds no timer of its own — stopping the sweep stops it', async () => {
    const h = harness()
    await vi.advanceTimersByTimeAsync(0)
    h.sampler.configure({ enabled: false, intervalMs: 120_000, targets: [target('a')] })
    await vi.advanceTimersByTimeAsync(10 * HOST_FACTS_INTERVAL_MS)
    expect(h.accessCalls).toEqual(['fleet:a'])
  })

  it('keeps its own due clock, so a broken facts probe cannot postpone it', async () => {
    // Sharing one clock would let a host whose facts probe keeps failing stop
    // being inventoried for keys — an estate quietly going unaudited for a
    // reason that has nothing to do with keys.
    const h = harness()
    h.failFacts('facts exploded')
    await vi.advanceTimersByTimeAsync(0)
    expect(h.factCalls).toEqual(['fleet:a'])
    expect(h.accessCalls).toEqual(['fleet:a'])
    await vi.advanceTimersByTimeAsync(HOST_FACTS_INTERVAL_MS + 120_000)
    expect(h.accessCalls).toEqual(['fleet:a', 'fleet:a'])
  })

  it('pushes the next attempt out even when the probe failed', async () => {
    // Otherwise a host that reliably refuses is retried every sweep on a
    // 60-second budget, which is the whole estate's sweep time spent on one box.
    const h = harness()
    h.failAccess('denied')
    await vi.advanceTimersByTimeAsync(0)
    await vi.advanceTimersByTimeAsync(29 * 120_000)
    expect(h.accessCalls).toEqual(['fleet:a'])
  })

  it('does nothing at all when no probe was injected', async () => {
    const h = harness({ withAccess: false })
    await vi.advanceTimersByTimeAsync(0)
    expect(h.accessCalls).toEqual([])
    expect(h.store.retired.filter((r) => r.prefix.startsWith(ACCESS_FACT_PREFIX))).toEqual([])
  })
})

describe('the module gate', () => {
  it('never runs the probe while the module is off', async () => {
    // The one place a module toggle gates a channel rather than a panel. The
    // probe walks /etc/passwd on every host and, where passwordless sudo
    // exists, `sudo -n cat`s other accounts' authorized_keys — one line in that
    // host's sudo log per account per hour. Not a thing to discover after
    // the fact.
    const h = harness({ gated: true })
    h.setEnabled(false)
    await vi.advanceTimersByTimeAsync(0)
    await vi.advanceTimersByTimeAsync(10 * HOST_FACTS_INTERVAL_MS)
    expect(h.accessCalls).toEqual([])
  })

  it('starts collecting on the next sweep after it is switched on', async () => {
    // Resolved per sweep, not captured at construction: a toggle has to take
    // effect without a restart.
    const h = harness({ gated: true })
    h.setEnabled(false)
    await vi.advanceTimersByTimeAsync(0)
    expect(h.accessCalls).toEqual([])
    h.setEnabled(true)
    await vi.advanceTimersByTimeAsync(120_000)
    expect(h.accessCalls).toEqual(['fleet:a'])
  })
})

describe('what survives between collections', () => {
  it('keeps the collection through the twenty-nine metrics-only sweeps', async () => {
    // Rebuilding the cache entry without it would erase the key inventory
    // thirty times an hour and leave the panel reporting "no keys" on a host
    // that trusts a dozen.
    const h = harness()
    await vi.advanceTimersByTimeAsync(0)
    await vi.advanceTimersByTimeAsync(10 * 120_000)
    const got = h.sampler.accessFor('a')
    expect(got.access?.accounts.map((a) => a.user)).toEqual(['ops', 'deploy'])
    expect(got.at).toBeDefined()
  })

  it('keeps the last good collection when a later probe fails', async () => {
    // "This host's keys were read an hour ago and the probe is failing now" is
    // two facts. Replacing the first with nothing turns a failure into an
    // empty key list, which is the one thing this feature must never invent.
    const h = harness()
    await vi.advanceTimersByTimeAsync(0)
    h.failAccess('denied: sudo is no longer available')
    await vi.advanceTimersByTimeAsync(HOST_FACTS_INTERVAL_MS + 120_000)
    const got = h.sampler.accessFor('a')
    expect(got.access?.accounts).toHaveLength(2)
    expect(got.error).toBe('denied: sudo is no longer available')
    expect(got.errorAt).toBeDefined()
  })

  it('clears the error once a collection succeeds again', async () => {
    const h = harness()
    h.failAccess('denied')
    await vi.advanceTimersByTimeAsync(0)
    expect(h.sampler.accessFor('a').error).toBe('denied')
    h.failAccess(null)
    await vi.advanceTimersByTimeAsync(HOST_FACTS_INTERVAL_MS + 120_000)
    expect(h.sampler.accessFor('a').error).toBeUndefined()
    expect(h.sampler.accessFor('a').access?.accounts).toHaveLength(2)
  })

  it('reports nothing for a server it has never collected', async () => {
    const h = harness()
    expect(h.sampler.accessFor('nobody')).toMatchObject({ access: undefined, error: undefined })
  })
})

describe('what reaches the durable store', () => {
  const keysOf = (h: Harness): string[] =>
    h.store.upserts.filter((u) => u.key.startsWith(ACCESS_FACT_PREFIX)).map((u) => u.key)

  it('writes the key rows and the completeness of the collection', async () => {
    const h = harness()
    await vi.advanceTimersByTimeAsync(0)
    expect(keysOf(h)).toContain(`${accessKeyPrefix('ops')}${ED25519_FP}`)
    expect(h.store.upserts).toContainEqual({
      host: 'a',
      key: `${ACCESS_FACT_PREFIX}complete`,
      value: 'true'
    })
  })

  it('retires an account’s keys only for accounts it actually read', async () => {
    // THE rule. `retireFacts` records a fact-removed event for everything it
    // drops, and on an authorized key that reads as a revocation. An account
    // that went `denied` because somebody tightened a home directory must keep
    // every key row it had.
    const h = harness()
    h.setAccess(deployDenied())
    await vi.advanceTimersByTimeAsync(0)
    const prefixes = h.store.retired.map((r) => r.prefix)
    expect(prefixes).toContain(accessKeyPrefix('ops'))
    expect(prefixes).not.toContain(accessKeyPrefix('deploy'))
  })

  it('never sweeps the whole access prefix, which would revoke everything', async () => {
    // One `retireFacts(host, at, 'access:', …)` would drop every key row on the
    // host the first time sudo stopped working, and record a clean revocation
    // of all of them.
    const h = harness()
    await vi.advanceTimersByTimeAsync(0)
    expect(h.store.retired.map((r) => r.prefix)).not.toContain(ACCESS_FACT_PREFIX)
  })

  it('writes no key row at all for an account it could not read', async () => {
    const h = harness()
    h.setAccess(deployDenied())
    await vi.advanceTimersByTimeAsync(0)
    expect(keysOf(h).filter((k) => k.startsWith(accessKeyPrefix('deploy')))).toEqual([])
    expect(h.store.upserts).toContainEqual({
      host: 'a',
      key: `${ACCESS_FACT_PREFIX}user:deploy:keys`,
      value: 'denied'
    })
  })

  it('writes nothing on the sweeps where the probe was not due', async () => {
    // Otherwise a complete inventory is re-retired thirty times an hour.
    const h = harness()
    await vi.advanceTimersByTimeAsync(0)
    const after = h.store.upserts.length
    await vi.advanceTimersByTimeAsync(10 * 120_000)
    expect(h.store.upserts.filter((u) => u.key.startsWith(ACCESS_FACT_PREFIX)).length).toBe(
      keysOf(h).length
    )
    expect(h.store.upserts.length).toBeGreaterThanOrEqual(after)
    // Exactly one retirement per read account plus the host-level source sweep,
    // and only from the ONE sweep the probe was due on. Ten metrics-only sweeps
    // later there must be no more of them: each extra pass would re-retire a
    // complete inventory it had not re-read.
    expect(h.store.retired.filter((r) => r.prefix.startsWith(ACCESS_FACT_PREFIX)).map((r) => r.prefix)).toEqual([
      accessKeyPrefix('ops'),
      accessKeyPrefix('deploy'),
      `${ACCESS_FACT_PREFIX}source:`
    ])
  })
})
