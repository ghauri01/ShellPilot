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

describe('what a payload is allowed to contain', () => {
  // The load-bearing decision in this feature. Every field is a constant, a
  // number, or a name the user typed. Nothing is passed through from a
  // command, a log line or a file -- which is the only reason this can be sent
  // to a third party without running it past secretRedaction first.
  const payload: AlertPayload = {
    source: 'shellpilot',
    version: '0.8.0',
    event: 'raised',
    kind: 'unit-failed',
    server: 'Prod Code 1',
    summary: '2 units failed on Prod Code 1',
    at: new Date().toISOString(),
    units: ['postfix@-.service', 'uwsgi.service']
  }

  it('carries no host, IP, username or port', () => {
    // docs/AI-SECURITY.md makes "an agent never receives a real host, IP or
    // username" a property of the product. A webhook is an easier way to leak
    // an estate's addressing than the MCP bridge ever was, so the same rule
    // holds here. The friendly name is what a person needs to act on.
    const json = JSON.stringify(payload)
    for (const banned of ['host', 'ip', 'username', 'port', 'password', 'key']) {
      expect(Object.keys(payload)).not.toContain(banned)
    }
    expect(json).not.toMatch(/\b\d{1,3}(\.\d{1,3}){3}\b/)
  })

  it('carries unit names but not descriptions or output', () => {
    // A name is enough to act on. Everything past the name is text the host
    // chose rather than text we did.
    expect(payload.units).toEqual(['postfix@-.service', 'uwsgi.service'])
    expect(Object.keys(payload)).not.toContain('description')
    expect(Object.keys(payload)).not.toContain('output')
    expect(Object.keys(payload)).not.toContain('log')
  })

  it('has a fixed key set, so a future field is a deliberate decision', () => {
    // If this fails because someone added a field, that is the point: the
    // question "can this leave the machine" should be asked out loud.
    expect(Object.keys(payload).sort()).toEqual(
      ['at', 'event', 'kind', 'server', 'source', 'summary', 'units', 'version'].sort()
    )
  })

  it('identifies itself so a shared endpoint can tell who posted', () => {
    expect(payload.source).toBe('shellpilot')
    expect(payload.version).toBeTruthy()
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
