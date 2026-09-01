import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import { validateWebhookUrl } from '../src/shared/webhook'
import type { AlertPayload } from '../src/shared/webhook'

// This is the first outbound call ShellPilot makes to an endpoint a user
// chooses, so the tests here are mostly about what must NOT happen: a
// credential on the wire in clear, and infrastructure detail in a payload.

describe('webhook URL validation', () => {
  it('accepts https', () => {
    const r = validateWebhookUrl('https://hooks.slack.com/services/T/B/xxx')
    expect(r.ok).toBe(true)
  })

  it('refuses plain http to a remote host', () => {
    // The URL is a bearer credential -- anyone holding a Slack webhook can
    // post as you -- so http would put it on the wire in clear.
    const r = validateWebhookUrl('http://example.com/hook')
    expect(r.ok).toBe(false)
    if (!r.ok) expect(r.error).toMatch(/https/i)
  })

  it('allows http to loopback, where nothing transits a network', () => {
    // A self-hosted receiver on the same machine is a real setup and blocking
    // it would push people to a worse workaround.
    for (const u of ['http://localhost:9000/hook', 'http://127.0.0.1:9000/hook']) {
      expect(validateWebhookUrl(u).ok, u).toBe(true)
    }
  })

  it('refuses schemes that are not http(s) at all', () => {
    for (const u of ['file:///etc/passwd', 'ftp://example.com/x', 'javascript:alert(1)']) {
      expect(validateWebhookUrl(u).ok, u).toBe(false)
    }
  })

  it('refuses nonsense rather than passing it through to fetch', () => {
    // Caught while someone is looking at settings, not during an incident.
    for (const u of ['', '   ', 'not a url', 'hooks.slack.com/x']) {
      expect(validateWebhookUrl(u).ok, JSON.stringify(u)).toBe(false)
    }
  })

  it('tolerates surrounding whitespace from a paste', () => {
    expect(validateWebhookUrl('  https://example.com/hook  ').ok).toBe(true)
  })
})

describe('payload sanitising — what actually leaves the machine', () => {
  // Replaces an earlier version of these tests that asserted on an object
  // literal the test file itself wrote. Those passed because the author had not
  // typed the word "host"; they would have passed unchanged if the code started
  // shipping journal output. These drive the real sanitiser instead.

  it('rebuilds from a whitelist, dropping anything it was not asked for', async () => {
    // The renderer can put anything on this IPC -- AlertPayload constrains its
    // source, not the runtime object -- so main must not forward what it got.
    const { sanitisePayload } = await import('../src/main/services/webhookAlerts')
    const out = sanitisePayload({
      source: 'not-shellpilot',
      event: 'raised',
      kind: 'cpu',
      server: 'box',
      summary: 'CPU high',
      version: '0.8.0',
      at: '1999-01-01T00:00:00.000Z',
      host: '10.0.0.5',
      username: 'root',
      password: 'hunter2',
      privateKey: '-----BEGIN OPENSSH PRIVATE KEY-----',
      logs: 'Sep 1 12:00:00 sshd: Accepted password for root'
    })
    expect(out).not.toBeNull()
    expect(Object.keys(out!).sort()).toEqual(
      ['at', 'event', 'kind', 'server', 'source', 'summary', 'version'].sort()
    )
    expect(JSON.stringify(out)).not.toMatch(/hunter2|PRIVATE KEY|10\.0\.0\.5|sshd/)
  })

  it('forces source and timestamp rather than trusting them', async () => {
    const { sanitisePayload } = await import('../src/main/services/webhookAlerts')
    const out = sanitisePayload({ event: 'raised', kind: 'cpu', at: 'whenever', source: 'spoofed' })
    expect(out!.source).toBe('shellpilot')
    expect(() => new Date(out!.at).toISOString()).not.toThrow()
  })

  it('rejects a payload whose event or kind is not one of ours', async () => {
    const { sanitisePayload } = await import('../src/main/services/webhookAlerts')
    expect(sanitisePayload({ event: 'exfil', kind: 'cpu' })).toBeNull()
    expect(sanitisePayload({ event: 'raised', kind: 'whatever' })).toBeNull()
    expect(sanitisePayload(null)).toBeNull()
    expect(sanitisePayload('a string')).toBeNull()
  })

  it('caps text, so an unbounded string cannot become an exfil channel', async () => {
    // The rate limiter caps request COUNT, not body size. Without this, 30
    // POSTs a minute of unbounded strings is whatever bandwidth you want.
    const { sanitisePayload } = await import('../src/main/services/webhookAlerts')
    const out = sanitisePayload({
      event: 'raised',
      kind: 'cpu',
      server: 'x'.repeat(10_000),
      summary: 'y'.repeat(10_000)
    })
    expect(out!.server.length).toBeLessThanOrEqual(200)
    expect(out!.summary.length).toBeLessThanOrEqual(200)
  })

  it('strips a hostile unit name instead of posting it', async () => {
    // Unit names come off a machine that may be compromised. `<!channel>`
    // contains no whitespace, so it survives parseServices -- and would ping an
    // entire Slack workspace on a loop, from an integration the user trusts.
    const { sanitisePayload } = await import('../src/main/services/webhookAlerts')
    const out = sanitisePayload({
      event: 'raised',
      kind: 'unit-failed',
      server: 'box',
      summary: 'failed',
      units: ['<!channel>.service', 'https://evil.example/x.service', 'nginx.service']
    })
    // `<`, `>` and `/` are gone, so neither a Slack control sequence nor a
    // clickable link survives. The colon stays because systemd unit names may
    // contain one, which is why the result still reads oddly -- but it is inert.
    expect(out!.units).toEqual(['channel.service', 'https:evil.examplex.service', 'nginx.service'])
    expect(JSON.stringify(out)).not.toMatch(/[<>]/)
    expect(JSON.stringify(out)).not.toMatch(/\/\//)
  })

  it('caps the number and length of unit names', async () => {
    const { sanitisePayload } = await import('../src/main/services/webhookAlerts')
    const out = sanitisePayload({
      event: 'raised',
      kind: 'unit-failed',
      units: Array.from({ length: 500 }, (_, i) => `u${i}.service`).concat(['z'.repeat(9999)])
    })
    expect(out!.units!.length).toBeLessThanOrEqual(20)
    for (const u of out!.units!) expect(u.length).toBeLessThanOrEqual(128)
  })

  it('coerces numbers and drops ones that are not', async () => {
    const { sanitisePayload } = await import('../src/main/services/webhookAlerts')
    const out = sanitisePayload({
      event: 'raised', kind: 'cpu', value: '91', threshold: Number.NaN, minutes: {}
    })
    expect(out!.value).toBe(91)
    expect(out!.threshold).toBeUndefined()
    expect(out!.minutes).toBeUndefined()
  })
})

// ---- Delivery policy ----
//
// Imported here rather than exercised by hand because these are the behaviours
// that only show up during an incident: a flapping unit, a revoked hook, an
// endpoint having a bad minute. Getting them wrong is either a silent gap or a
// thousand POSTs.
describe('delivery policy', () => {
  const realFetch = globalThis.fetch

  beforeEach(async () => {
    const m = await import('../src/main/services/webhookAlerts')
    m.webhookResetForTests()
    m.webhookSetUrl('https://example.com/hook')
    m.webhookConfigure({ enabled: true, notifyOnResolved: true })
  })

  afterEach(() => {
    globalThis.fetch = realFetch
    vi.useRealTimers()
  })

  const sample = (): AlertPayload => ({
    source: 'shellpilot',
    version: '0.8.0',
    event: 'raised',
    kind: 'cpu',
    server: 'box',
    summary: 'box: CPU at 95%',
    at: new Date().toISOString()
  })

  it('does not retry a 4xx, because it will be wrong again', async () => {
    // A revoked Slack hook returns 403 forever. Retrying only delays the truth
    // and triples the noise.
    let calls = 0
    globalThis.fetch = (async () => {
      calls++
      return new Response('no', { status: 403 })
    }) as typeof fetch

    const { webhookTest } = await import('../src/main/services/webhookAlerts')
    const r = await webhookTest()
    expect(r.ok).toBe(false)
    expect(r.status).toBe(403)
    expect(calls).toBe(1)
  })

  it('retries a 5xx, because it may not be wrong next time', async () => {
    let calls = 0
    globalThis.fetch = (async () => {
      calls++
      return calls < 3 ? new Response('', { status: 503 }) : new Response('ok', { status: 200 })
    }) as typeof fetch

    const { webhookTest } = await import('../src/main/services/webhookAlerts')
    const r = await webhookTest()
    expect(r.ok).toBe(true)
    expect(calls).toBe(3)
  }, 20_000)

  it('retries 429 rather than treating it as a permanent refusal', async () => {
    let calls = 0
    globalThis.fetch = (async () => {
      calls++
      return calls === 1 ? new Response('', { status: 429 }) : new Response('ok', { status: 200 })
    }) as typeof fetch

    const { webhookTest } = await import('../src/main/services/webhookAlerts')
    expect((await webhookTest()).ok).toBe(true)
    expect(calls).toBe(2)
  }, 20_000)

  it('gives up rather than retrying forever', async () => {
    let calls = 0
    globalThis.fetch = (async () => {
      calls++
      throw new Error('ECONNREFUSED')
    }) as typeof fetch

    const { webhookTest } = await import('../src/main/services/webhookAlerts')
    const r = await webhookTest()
    expect(r.ok).toBe(false)
    expect(r.error).toContain('ECONNREFUSED')
    expect(calls).toBe(3)
  }, 20_000)

  it('drops past the rate limit instead of sending a thousand posts', async () => {
    // The backstop. The per-alert repeat window upstream handles the normal
    // case; this is what stops a bug in that logic becoming an outage of
    // somebody's Slack channel.
    let calls = 0
    globalThis.fetch = (async () => {
      calls++
      return new Response('ok', { status: 200 })
    }) as typeof fetch

    const m = await import('../src/main/services/webhookAlerts')
    for (let i = 0; i < 50; i++) m.webhookNotify(sample())
    await new Promise((r) => setTimeout(r, 50))

    expect(calls).toBeLessThanOrEqual(30)
    expect(m.webhookDeliveryStatus().dropped).toBeGreaterThan(0)
  })

  it('sends nothing while disabled, even with a URL set', async () => {
    let calls = 0
    globalThis.fetch = (async () => {
      calls++
      return new Response('ok', { status: 200 })
    }) as typeof fetch

    const m = await import('../src/main/services/webhookAlerts')
    m.webhookConfigure({ enabled: false, notifyOnResolved: true })
    m.webhookNotify(sample())
    await new Promise((r) => setTimeout(r, 20))
    expect(calls).toBe(0)
  })

  it('honours the resolved-message opt-out without affecting raises', async () => {
    const seen: string[] = []
    globalThis.fetch = (async (_u: string, init: RequestInit) => {
      seen.push(JSON.parse(String(init.body)).event)
      return new Response('ok', { status: 200 })
    }) as unknown as typeof fetch

    const m = await import('../src/main/services/webhookAlerts')
    m.webhookConfigure({ enabled: true, notifyOnResolved: false })
    m.webhookNotify({ ...sample(), event: 'resolved' })
    m.webhookNotify(sample())
    await new Promise((r) => setTimeout(r, 50))
    expect(seen).toEqual(['raised'])
  })
})

// Removing the URL from a webhook that is already switched on. The pane cannot
// switch it on without a URL, so this is the only way into the state — and it
// was reachable, silent, and reported as healthy: the switch still read ON, the
// alerts went nowhere, and delivery() had nothing to say about it.
describe('a webhook whose URL is taken away', () => {
  beforeEach(async () => {
    const m = await import('../src/main/services/webhookAlerts')
    m.webhookResetForTests()
    m.webhookSetUrl('https://example.com/hook')
    m.webhookConfigure({ enabled: true, notifyOnResolved: true })
  })

  it('turns itself off rather than staying on with nowhere to send', async () => {
    const m = await import('../src/main/services/webhookAlerts')
    expect(m.webhookStatus().enabled).toBe(true)
    m.webhookSetUrl('')
    expect(m.webhookStatus()).toMatchObject({ enabled: false, hasUrl: false })
  })

  it('says why, if an alert ever reaches the send path without a URL', async () => {
    const m = await import('../src/main/services/webhookAlerts')
    m.webhookSetUrl('')
    // Back on without a URL: only reachable if some future caller configures
    // around the pane, which is exactly when a silent discard costs the most.
    m.webhookConfigure({ enabled: true, notifyOnResolved: true })
    const calls: string[] = []
    globalThis.fetch = (async (u: string) => {
      calls.push(String(u))
      return new Response('', { status: 200 })
    }) as unknown as typeof fetch
    m.webhookNotify({
      source: 'shellpilot',
      version: '0.8.0',
      event: 'raised',
      kind: 'cpu',
      server: 'box',
      summary: 'box: CPU at 95%',
      at: new Date().toISOString()
    })
    expect(calls).toEqual([])
    expect(m.webhookDeliveryStatus().lastError).toMatch(/no webhook url/i)
  })
})
