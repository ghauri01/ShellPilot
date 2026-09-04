import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { FleetSampler } from '../src/main/services/fleetSampler'
import type { FleetTarget } from '../src/shared/fleet'
import { HOST_FACTS_INTERVAL_MS } from '../src/shared/hostFacts'
import { POSTURE_FACT_PREFIX, POSTURE_STATUS_MARKER, parsePosture } from '../src/shared/posture'
import type { HostPosture } from '../src/shared/posture'
import { PostureReader, firewallRulesGranted } from '../src/main/services/posture'
import type { AccessGroup, AiCapabilityPolicy, PermissionValue } from '../src/shared/mcp'

// The security posture probe's place in the sweep — roadmap item 24.
//
// Everything here is about CADENCE, about the module gate, and about what
// survives between collections, because those are the things that are
// invisible until they are wrong. Two of them are specific to this probe:
//
//  * A posture collection that does not survive a metrics-only sweep leaves
//    the panel reporting "never collected" on a host whose firewall was read
//    four minutes ago, twenty-nine sweeps out of thirty.
//  * The probe is GATED on the module, not merely hidden behind it. Every
//    other optional module in this app leaves its main-process handlers
//    registered and hides a UI; this one and item 23's are the exceptions, and
//    they are exceptions for different reasons — that one for what it does on
//    the host, this one for what it produces.

const NOW = 1_800_000_000_000

const target = (id: string): FleetTarget => ({
  serverId: id,
  serverName: `srv-${id}`,
  cfg: { host: 'h', port: 22, username: 'u' } as FleetTarget['cfg']
})

/** A collection where ufw answered. */
const read = (): HostPosture =>
  parsePosture(
    [
      'V fw-tool ufw',
      'V fw-active active',
      'V fw-rules 4',
      'V fw-backend-status ok',
      'V fw-backend nftables',
      'V fw-backend-rules 9',
      POSTURE_STATUS_MARKER,
      'firewall ok - ufw status verbose',
      'mandatory-access absent - neither is installed',
      'sshd-hardening denied - /etc/ssh cannot be entered',
      'failed-logins denied - needs root'
    ].join('\n'),
    NOW
  )

interface Store {
  upserts: { host: string; key: string; value: string }[]
  retired: { host: string; prefix: string; keep: string[] }[]
}

interface Harness {
  sampler: FleetSampler
  postureCalls: string[]
  factCalls: string[]
  store: Store
  failPosture: (error: string | null) => void
  throwPosture: (on: boolean) => void
  failFacts: (error: string | null) => void
  setEnabled: (on: boolean) => void
}

function harness(over: { withPosture?: boolean; gated?: boolean } = {}): Harness {
  const postureCalls: string[] = []
  const factCalls: string[] = []
  const store: Store = { upserts: [], retired: [] }
  let postureError: string | null = null
  let postureThrows = false
  let factsError: string | null = null
  let enabled = true

  const sampler = new FleetSampler({
    sample: async (key) => ({ ok: true, data: { hostname: key, services: null, listeners: null } }),
    sampleFacts: async (key) => {
      factCalls.push(key)
      if (factsError !== null) return { ok: false, error: factsError }
      return { ok: true, facts: { sources: [], collectedAt: 1 } as never }
    },
    ...(over.withPosture === false
      ? {}
      : {
          samplePosture: async (key) => {
            postureCalls.push(key)
            if (postureThrows) throw new Error('probe exploded')
            if (postureError !== null) return { ok: false, error: postureError }
            return { ok: true, posture: read() }
          }
        }),
    ...(over.gated ? { postureEnabled: (): boolean => enabled } : {}),
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
    postureCalls,
    factCalls,
    store,
    failPosture: (e) => {
      postureError = e
    },
    throwPosture: (on) => {
      postureThrows = on
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
    expect(h.postureCalls).toEqual(['fleet:a'])
  })

  it('does not fork sshd and read the ruleset on every host every two minutes', async () => {
    const h = harness()
    await vi.advanceTimersByTimeAsync(0)
    await vi.advanceTimersByTimeAsync(29 * 120_000)
    expect(h.postureCalls).toEqual(['fleet:a'])
  })

  it('collects again once the hour is up', async () => {
    const h = harness()
    await vi.advanceTimersByTimeAsync(0)
    await vi.advanceTimersByTimeAsync(HOST_FACTS_INTERVAL_MS + 120_000)
    expect(h.postureCalls).toEqual(['fleet:a', 'fleet:a'])
  })

  it('adds no timer of its own — stopping the sweep stops it', async () => {
    const h = harness()
    await vi.advanceTimersByTimeAsync(0)
    h.sampler.configure({ enabled: false, intervalMs: 120_000, targets: [target('a')] })
    await vi.advanceTimersByTimeAsync(10 * HOST_FACTS_INTERVAL_MS)
    expect(h.postureCalls).toEqual(['fleet:a'])
  })

  it('keeps its own due clock, so a broken facts probe cannot postpone it', async () => {
    // Sharing one clock would let a host whose facts probe keeps failing stop
    // being checked for its firewall — an estate quietly going unreviewed for
    // a reason that has nothing to do with security posture.
    const h = harness()
    h.failFacts('facts exploded')
    await vi.advanceTimersByTimeAsync(0)
    expect(h.factCalls).toEqual(['fleet:a'])
    expect(h.postureCalls).toEqual(['fleet:a'])
    await vi.advanceTimersByTimeAsync(HOST_FACTS_INTERVAL_MS + 120_000)
    expect(h.postureCalls).toEqual(['fleet:a', 'fleet:a'])
  })

  it('pushes the next attempt out even when the probe threw', async () => {
    // Otherwise a host that reliably fails is retried on every sweep with a
    // 45-second budget, which is the whole estate's sweep time spent on one
    // broken box.
    const h = harness()
    h.throwPosture(true)
    await vi.advanceTimersByTimeAsync(0)
    await vi.advanceTimersByTimeAsync(29 * 120_000)
    expect(h.postureCalls).toEqual(['fleet:a'])
    expect(h.sampler.postureFor('a').error).toContain('probe exploded')
  })

  it('does nothing at all when no probe was injected', async () => {
    const h = harness({ withPosture: false })
    await vi.advanceTimersByTimeAsync(0)
    expect(h.postureCalls).toEqual([])
    expect(h.store.retired.filter((r) => r.prefix === POSTURE_FACT_PREFIX)).toEqual([])
  })
})

describe('the module gate', () => {
  it('never runs the probe while the module is off', async () => {
    // Gated on the CHANNEL rather than the panel, and for a reason that is not
    // item 23's. That probe is gated for what it does on the host; this one is
    // gated for what it PRODUCES — a fleet-wide table of which host has no
    // firewall and still takes passwords over ssh is a map of how to attack the
    // estate, and assembling one is a thing a person switches on.
    const h = harness({ gated: true })
    h.setEnabled(false)
    await vi.advanceTimersByTimeAsync(0)
    await vi.advanceTimersByTimeAsync(10 * HOST_FACTS_INTERVAL_MS)
    expect(h.postureCalls).toEqual([])
    // And the metrics half is untouched: turning this off does not stop the
    // monitor.
    expect(h.factCalls.length).toBeGreaterThan(0)
  })

  it('starts collecting on the next sweep once it is switched on, not at the next restart', async () => {
    const h = harness({ gated: true })
    h.setEnabled(false)
    await vi.advanceTimersByTimeAsync(0)
    expect(h.postureCalls).toEqual([])
    h.setEnabled(true)
    await vi.advanceTimersByTimeAsync(120_000)
    expect(h.postureCalls).toEqual(['fleet:a'])
  })
})

describe('what survives between collections', () => {
  it('keeps the reading across the twenty-nine metrics-only sweeps', async () => {
    // Without this the panel reports "never collected" on a host whose
    // firewall was read four minutes ago, which is the same lie as reporting
    // no rules.
    const h = harness()
    await vi.advanceTimersByTimeAsync(0)
    expect(h.sampler.postureFor('a').posture?.firewall?.rules).toBe(4)
    const firstAt = h.sampler.postureFor('a').at
    await vi.advanceTimersByTimeAsync(29 * 120_000)
    expect(h.sampler.postureFor('a').posture?.firewall?.rules).toBe(4)
    // And the timestamp is the one the COLLECTION was taken at, not the last
    // metrics sweep's. A posture stamped with a two-minute-old time is a
    // reading that claims to be fresher than it is.
    expect(h.sampler.postureFor('a').at).toBe(firstAt)
  })

  it('keeps the last good reading ALONGSIDE a failure rather than replacing it', async () => {
    // "This host's firewall was read an hour ago and the probe is failing now"
    // is two facts and both matter. Replacing the reading with nothing would
    // turn a probe failure into a host with no firewall reading, and the panel
    // would then have to decide what that means.
    const h = harness()
    await vi.advanceTimersByTimeAsync(0)
    h.failPosture('denied')
    await vi.advanceTimersByTimeAsync(HOST_FACTS_INTERVAL_MS + 120_000)
    const held = h.sampler.postureFor('a')
    expect(held.posture?.firewall?.rules).toBe(4)
    expect(held.error).toBe('denied')
  })

  it('clears the failure when a later collection succeeds', async () => {
    const h = harness()
    h.failPosture('denied')
    await vi.advanceTimersByTimeAsync(0)
    expect(h.sampler.postureFor('a').error).toBe('denied')
    h.failPosture(null)
    await vi.advanceTimersByTimeAsync(HOST_FACTS_INTERVAL_MS + 120_000)
    expect(h.sampler.postureFor('a').error).toBeUndefined()
    expect(h.sampler.postureFor('a').posture?.firewall?.rules).toBe(4)
  })

  it('quotes the slow interval, not the metrics one', async () => {
    // A caller judging staleness against 120_000 would call an hour-old
    // posture thirty intervals stale when it is exactly on schedule.
    const h = harness()
    await vi.advanceTimersByTimeAsync(0)
    expect(h.sampler.postureFor('a').intervalMs).toBe(HOST_FACTS_INTERVAL_MS)
  })

  it('has nothing to say about a server it has never sampled', async () => {
    const h = harness()
    await vi.advanceTimersByTimeAsync(0)
    expect(h.sampler.postureFor('never-seen')).toEqual({
      posture: undefined,
      at: undefined,
      error: undefined,
      errorAt: undefined,
      intervalMs: HOST_FACTS_INTERVAL_MS
    })
  })
})

describe('what reaches the durable store', () => {
  it('writes every posture key, including the ones that are a status', async () => {
    const h = harness()
    await vi.advanceTimersByTimeAsync(0)
    const written = new Map(
      h.store.upserts.filter((u) => u.key.startsWith(POSTURE_FACT_PREFIX)).map((u) => [u.key, u.value])
    )
    expect(written.get(`${POSTURE_FACT_PREFIX}firewallTool`)).toBe('ufw')
    expect(written.get(`${POSTURE_FACT_PREFIX}firewallRules`)).toBe('4')
    // The sshd probe was refused. Its keys carry the STATUS, never a value and
    // never nothing — so a report written six months from now can still tell
    // "this host permitted root logins" from "nobody was allowed to look".
    expect(written.get(`${POSTURE_FACT_PREFIX}sshd:permitrootlogin`)).toBe('denied')
    expect(written.get(`${POSTURE_FACT_PREFIX}source:sshd-hardening`)).toBe('denied')
    expect(written.get(`${POSTURE_FACT_PREFIX}source:mandatory-access`)).toBe('absent')
  })

  it('retires only against a collection that actually ran', async () => {
    // `w.posture` absent means "not due this sweep". Sweeping the prefix then
    // would delete a complete reading twenty-nine times an hour and record a
    // fact-removed event for every key each time.
    const h = harness()
    await vi.advanceTimersByTimeAsync(0)
    const first = h.store.retired.filter((r) => r.prefix === POSTURE_FACT_PREFIX).length
    expect(first).toBe(1)
    await vi.advanceTimersByTimeAsync(29 * 120_000)
    expect(h.store.retired.filter((r) => r.prefix === POSTURE_FACT_PREFIX).length).toBe(first)
  })

  it('writes nothing under the posture prefix when the probe failed', async () => {
    // A failed probe must not retire anything either: a fact-removed event on
    // `posture:firewallRules` reads as "this host's rules were removed".
    const h = harness()
    h.failPosture('denied')
    await vi.advanceTimersByTimeAsync(0)
    expect(h.store.upserts.filter((u) => u.key.startsWith(POSTURE_FACT_PREFIX))).toEqual([])
    expect(h.store.retired.filter((r) => r.prefix === POSTURE_FACT_PREFIX)).toEqual([])
  })
})

// ---------------------------------------------------------------------------
// The reader's failure classification
// ---------------------------------------------------------------------------

describe('the reader tells three failures apart', () => {
  const reader = (
    r: { ok: boolean; stdout?: string; stderr?: string; error?: string },
    sent?: (cmd: string) => void
  ): PostureReader =>
    new PostureReader({
      exec: async (_cfg, command) => {
        sent?.(command)
        return r
      },
      now: () => NOW
    })

  it('calls a transport failure unreachable and infers NOTHING about the host', async () => {
    // The single most important line in src/main/services/posture.ts.
    // "No firewall rules, sshd not hardened" for a connection that never opened
    // is a fabricated security finding.
    const p = await reader({ ok: false, error: 'connect ETIMEDOUT' }).read({})
    expect(p).toEqual({ ok: false, reason: 'unreachable', detail: 'connect ETIMEDOUT' })
  })

  it('calls output with no status block no-output rather than a host with four unknowns', async () => {
    const p = await reader({ ok: true, stdout: 'V fw-tool ufw\n', stderr: 'sh: bad substitution' }).read({})
    expect(p).toMatchObject({ ok: false, reason: 'no-output', detail: 'sh: bad substitution' })
  })

  it('calls a successful collection successful even when every probe was refused', async () => {
    // A collection whose every source says `denied` is not a failure — it is
    // the feature, and the panel needs it to say so per source.
    const out = [
      POSTURE_STATUS_MARKER,
      'firewall denied - needs root',
      'mandatory-access denied - unreadable',
      'sshd-hardening denied - cannot enter /etc/ssh',
      'failed-logins denied - needs root',
      'oom-kills denied - the journal needs root',
      'certificates denied - /etc/letsencrypt would not be entered'
    ].join('\n')
    const p = await reader({ ok: true, stdout: out }).read({})
    expect(p.ok).toBe(true)
    if (!p.ok) throw new Error('unreachable')
    expect(p.posture.sources.map((s) => s.status)).toEqual([
      'denied',
      'denied',
      'denied',
      'denied',
      'denied',
      'denied'
    ])
    expect(p.posture.firewall).toBeNull()
    expect(p.posture.collectedAt).toBe(NOW)
  })

  it('passes the sudo option through to the command it sends', async () => {
    let sent = ''
    await reader({ ok: true, stdout: POSTURE_STATUS_MARKER }, (c) => (sent = c)).read({}, { sudo: false })
    expect(sent).not.toMatch(/\bsudo\b/)
  })

  it('does not merge stderr into the record region', async () => {
    // A `V `-prefixed line from a noisy shell profile would be read as a
    // firewall value if stderr were folded in.
    const p = await reader({
      ok: true,
      stdout: [POSTURE_STATUS_MARKER, 'firewall unsupported - nothing installed'].join('\n'),
      stderr: 'V fw-tool ufw\nV fw-rules 99'
    }).read({})
    expect(p.ok).toBe(true)
    if (!p.ok) throw new Error('unreachable')
    expect(p.posture.firewall).toBeNull()
  })
})

// ---------------------------------------------------------------------------
// Who may have the rule lines — roadmap item 31
// ---------------------------------------------------------------------------
//
// The decision itself, kept out of main/index.ts so it can be asserted rather
// than reviewed. What main adds around it is the group resolution the MCP
// bridge already does: the assignment on the server, else the one on its
// workspace.

const capabilities = (firewallRules: PermissionValue): AiCapabilityPolicy =>
  ({ firewallRules }) as unknown as AiCapabilityPolicy

const withRules = (firewallRules: PermissionValue): AccessGroup => ({
  id: 'g',
  name: 'G',
  builtIn: false,
  capabilities: capabilities(firewallRules),
  filePolicies: []
})

describe('firewallRulesGranted', () => {
  it('collects only on allow, because an hourly sweep has nobody to ask', () => {
    expect(firewallRulesGranted(withRules('allow'))).toBe(true)
    // 'ask' is not a maybe here. There is no screen and no human in a
    // background sweep, so treating it as a yes invents a consent and raising
    // a prompt queues an approval against work nobody started.
    expect(firewallRulesGranted(withRules('ask'))).toBe(false)
    expect(firewallRulesGranted(withRules('deny'))).toBe(false)
  })

  it('fails closed on a server with no group, and on a group that predates it', () => {
    // No assignment at all is "No AI Access", which is the strictest answer
    // the policy layer has and must not become the loosest one here.
    expect(firewallRulesGranted(null)).toBe(false)
    // A group saved before the capability existed has no key for it.
    // `backfillCapabilities` fills it in at deny on load; this is what happens
    // in the window before it does, and in any test or caller that skips it.
    const stale = withRules('allow')
    delete (stale.capabilities as Partial<AiCapabilityPolicy>).firewallRules
    expect(firewallRulesGranted(stale)).toBe(false)
  })

  it('reads nothing but the capability, so no other grant can widen it', () => {
    // A group that may do everything else on a server still may not have this
    // unless it says so. serverMetrics is the one that would have been widened
    // if this had ridden in on something broader, which is the 0.8.0 finding.
    const permissive = {
      id: 'g',
      name: 'G',
      builtIn: false,
      capabilities: {
        terminal: 'allow',
        sudo: 'allow',
        serverMetrics: 'allow',
        hostFacts: 'allow',
        firewallRules: 'deny'
      } as unknown as AiCapabilityPolicy,
      filePolicies: []
    }
    expect(firewallRulesGranted(permissive)).toBe(false)
  })
})
