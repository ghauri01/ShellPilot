import { describe, it, expect, afterEach } from 'vitest'
import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http'
import { AddressInfo } from 'node:net'
import { CredProxy, isLoopbackAddress, redactThenCap } from '../src/main/services/credProxy'
import type { CredProxyDeps, CredProxyFile } from '../src/main/services/credProxy'
import { CRED_PROXY_TOKEN_HEADER } from '../src/shared/credproxy'
import type { CredProxyCall, CredProxyRule } from '../src/shared/credproxy'

// ===========================================================================
// A REAL node:http UPSTREAM, NOT A DOUBLE
// ===========================================================================
//
// Same choice the S3 work made, for the same reason: a stub agrees with
// whatever the code under test believes about the wire. The three things a
// double would have accepted here, and this file does not:
//
//   * that a header set on a `Headers` object arrives under the name it was
//     set with (case, and the token header we must NOT forward);
//   * that `redirect: 'manual'` means what it says, rather than undici having
//     followed the hop before we ever saw a status;
//   * that a refusal happens BEFORE any socket is opened — which is only
//     observable if there is a real server on the other end that could have
//     recorded a request and did not.
//
// Every assertion below is a literal or an observed behaviour. There is no
// place where the expectation is computed by the function under test.

// A value shaped like a real key, distinctive enough that a substring search
// over a response, a header dump or an audit row is a sound leak test.
const SECRET = 'sk-live-51NEVERLEAKME-8f3a2b7c9d1e4f60'
const TOKEN = 'cpx_5f4d3c2b1a09876543210fedcba98765'

interface Hit {
  method: string
  url: string
  headers: Record<string, string | string[] | undefined>
  body: string
}

interface Upstream {
  origin: string
  port: number
  hits: Hit[]
  close(): Promise<void>
}

/** A real HTTP server that records what it was sent. It never echoes a header
 *  back in its response body — an echoing upstream would make "the credential
 *  is not in the response" untestable, and the property under test is that the
 *  PROXY does not put it there. */
async function upstream(
  respond: (req: IncomingMessage, res: ServerResponse, hit: Hit) => void = (_r, res) => {
    res.writeHead(200, { 'content-type': 'text/plain' })
    res.end('upstream-ok')
  }
): Promise<Upstream> {
  const hits: Hit[] = []
  const server: Server = createServer((req, res) => {
    const chunks: Buffer[] = []
    req.on('data', (c: Buffer) => chunks.push(c))
    req.on('end', () => {
      const hit: Hit = {
        method: req.method ?? '',
        url: req.url ?? '',
        headers: { ...req.headers },
        body: Buffer.concat(chunks).toString('utf8')
      }
      hits.push(hit)
      respond(req, res, hit)
    })
  })
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', () => resolve()))
  const port = (server.address() as AddressInfo).port
  return {
    origin: `http://127.0.0.1:${port}`,
    port,
    hits,
    close: () =>
      new Promise<void>((resolve) => {
        server.closeAllConnections?.()
        server.close(() => resolve())
      })
  }
}

interface Harness {
  proxy: CredProxy
  audit: CredProxyCall[]
  written(): CredProxyFile | null
  base(): string
}

const cleanups: (() => Promise<void>)[] = []

afterEach(async () => {
  for (const c of cleanups.splice(0).reverse()) await c()
})

async function harness(rules: CredProxyRule[], over: Partial<CredProxyDeps> = {}): Promise<Harness> {
  const audit: CredProxyCall[] = []
  let file: CredProxyFile | null = null
  let n = 0
  const deps: CredProxyDeps = {
    now: () => Date.now(),
    newId: () => `id-${++n}`,
    read: () => ({ v: 1, enabled: false, port: 0, rules }),
    write: (f) => {
      file = f
    },
    resolveCredential: () => ({ ok: true, value: SECRET }),
    clientToken: () => TOKEN,
    recordCall: (c) => audit.push(c),
    ...over
  }
  const proxy = new CredProxy(deps, 0)
  const started = await proxy.start(0)
  expect(started.ok, started.error ?? '').toBe(true)
  cleanups.push(() => proxy.stop())
  return {
    proxy,
    audit,
    written: () => file,
    base: () => `http://127.0.0.1:${proxy.boundPort()}`
  }
}

const rule = (over: Partial<CredProxyRule>): CredProxyRule => ({
  id: 'r1',
  name: 'Example API',
  origin: 'http://127.0.0.1:1',
  credential: { vaultEntryId: 'v1', slot: 'password' },
  injection: { kind: 'bearer' },
  enabled: true,
  createdAt: '2026-01-01T00:00:00.000Z',
  ...over
})

/** Every byte a caller can see, as one string, for a leak search. */
async function seenByCaller(res: Response): Promise<string> {
  const headers: string[] = []
  res.headers.forEach((v, k) => headers.push(`${k}: ${v}`))
  return `HTTP ${res.status}\n${headers.join('\n')}\n\n${await res.text()}`
}

const call = (h: Harness, path: string, init: RequestInit = {}): Promise<Response> =>
  fetch(`${h.base()}/${path}`, {
    redirect: 'manual',
    ...init,
    headers: { [CRED_PROXY_TOKEN_HEADER]: TOKEN, ...(init.headers ?? {}) }
  })

// ---------------------------------------------------------------------------

describe('the proxy injects at the boundary and the caller never holds the key', () => {
  it('forwards with a bearer token the caller never sent and never sees', async () => {
    const up = await upstream()
    cleanups.push(up.close)
    const h = await harness([rule({ origin: up.origin, injection: { kind: 'bearer' } })])

    const res = await call(h, `${up.origin}/v1/things?limit=5`)

    expect(res.status).toBe(200)
    expect(await res.clone().text()).toBe('upstream-ok')

    // The upstream got the credential.
    expect(up.hits).toHaveLength(1)
    expect(up.hits[0].headers.authorization).toBe(`Bearer ${SECRET}`)
    expect(up.hits[0].url).toBe('/v1/things?limit=5')

    // The caller got none of it.
    expect(await seenByCaller(res)).not.toContain(SECRET)
    expect(res.headers.get('x-shellpilot-proxy')).toBe('forwarded')
  })

  it('injects into a named header', async () => {
    const up = await upstream()
    cleanups.push(up.close)
    const h = await harness([
      rule({ origin: up.origin, injection: { kind: 'header', name: 'X-Api-Key' } })
    ])

    const res = await call(h, `${up.origin}/v1/x`)

    expect(res.status).toBe(200)
    expect(up.hits[0].headers['x-api-key']).toBe(SECRET)
    expect(up.hits[0].headers.authorization).toBeUndefined()
    expect(await seenByCaller(res)).not.toContain(SECRET)
  })

  it('injects into a query parameter, and keeps it out of the audit path', async () => {
    const up = await upstream()
    cleanups.push(up.close)
    const h = await harness([
      rule({ origin: up.origin, injection: { kind: 'query', name: 'api_key' } })
    ])

    await call(h, `${up.origin}/v1/x?page=2`)

    expect(up.hits[0].url).toBe(`/v1/x?page=2&api_key=${SECRET}`)
    // The audit keeps the path and drops the query string, because THIS rule
    // kind is what puts a credential in one.
    expect(h.audit[0].path).toBe('/v1/x')
    expect(JSON.stringify(h.audit)).not.toContain(SECRET)
  })

  it('injects basic auth as the username the rule names', async () => {
    const up = await upstream()
    cleanups.push(up.close)
    const h = await harness([rule({ origin: up.origin, injection: { kind: 'basic', name: 'svc' } })])

    await call(h, `${up.origin}/v1/x`)

    expect(up.hits[0].headers.authorization).toBe(
      `Basic ${Buffer.from(`svc:${SECRET}`, 'utf8').toString('base64')}`
    )
  })

  it('forwards a POST body and the caller’s own headers unchanged', async () => {
    const up = await upstream()
    cleanups.push(up.close)
    const h = await harness([rule({ origin: up.origin })])

    await call(h, `${up.origin}/v1/x`, {
      method: 'POST',
      body: '{"hello":"world"}',
      headers: { 'content-type': 'application/json', 'x-request-id': 'abc123' }
    })

    expect(up.hits[0].method).toBe('POST')
    expect(up.hits[0].body).toBe('{"hello":"world"}')
    expect(up.hits[0].headers['x-request-id']).toBe('abc123')
  })

  // The proxy's own shared secret is a credential too. Forwarding it would
  // hand every upstream a token that unlocks every OTHER rule.
  it('never forwards its own client token to the upstream', async () => {
    const up = await upstream()
    cleanups.push(up.close)
    const h = await harness([rule({ origin: up.origin })])

    await call(h, `${up.origin}/v1/x`)

    expect(up.hits[0].headers[CRED_PROXY_TOKEN_HEADER]).toBeUndefined()
    expect(JSON.stringify(up.hits[0].headers)).not.toContain(TOKEN)
  })
})

describe('the proxy refuses to be an open relay', () => {
  it('refuses a destination no rule covers, without opening a socket to it', async () => {
    const covered = await upstream()
    const uncovered = await upstream()
    cleanups.push(covered.close, uncovered.close)
    const h = await harness([rule({ origin: covered.origin })])

    const res = await call(h, `${uncovered.origin}/v1/x`)

    expect(res.status).toBe(403)
    const body = (await res.json()) as { error: string; message: string }
    expect(body.error).toBe('no-rule')
    expect(body.message).toBe(
      'No rule covers that destination, so nothing was sent. This proxy never forwards a request ' +
        'it has no rule for — not without the credential, not at all.'
    )
    // Not "forwarded without a credential". Not contacted.
    expect(uncovered.hits).toEqual([])
    expect(covered.hits).toEqual([])
    expect(h.audit[0].outcome).toBe('no-rule')
  })

  // The near-miss, end to end and against two real servers: the rule names one
  // origin, the caller names a host that differs from it by one character.
  it('refuses a near-miss hostname rather than matching it', async () => {
    const real = await upstream()
    cleanups.push(real.close)
    const h = await harness([rule({ origin: `http://127.0.0.1:${real.port}` })])

    // Same machine, same port, a name that merely CONTAINS the rule's host.
    const res = await call(h, `http://127.0.0.1.evil.tld:${real.port}/v1/x`)

    expect(res.status).toBe(403)
    expect(((await res.json()) as { error: string }).error).toBe('no-rule')
    expect(real.hits).toEqual([])
  })

  it('refuses a different name for the very same socket', async () => {
    const real = await upstream()
    cleanups.push(real.close)
    const h = await harness([rule({ origin: `http://127.0.0.1:${real.port}` })])

    // `localhost` resolves to the same listener. It is still not the origin a
    // human wrote into the rule, and a proxy that decides two names are one
    // host has started doing DNS on behalf of an authorisation decision.
    const res = await call(h, `http://localhost:${real.port}/v1/x`)

    expect(res.status).toBe(403)
    expect(real.hits).toEqual([])
  })

  it('refuses a rule that is switched off', async () => {
    const up = await upstream()
    cleanups.push(up.close)
    const h = await harness([rule({ origin: up.origin, enabled: false })])

    const res = await call(h, `${up.origin}/v1/x`)

    expect(res.status).toBe(403)
    expect(((await res.json()) as { error: string }).error).toBe('rule-disabled')
    expect(up.hits).toEqual([])
  })

  it('refuses a bare path, which is a client pointed at us wrongly', async () => {
    const h = await harness([])
    const res = await call(h, 'v1/things')
    expect(res.status).toBe(400)
    expect(((await res.json()) as { error: string }).error).toBe('not-a-target')
  })
})

describe('a caller on loopback is not automatically trusted', () => {
  it('refuses a request with no client token, and contacts nothing', async () => {
    const up = await upstream()
    cleanups.push(up.close)
    const h = await harness([rule({ origin: up.origin })])

    const res = await fetch(`${h.base()}/${up.origin}/v1/x`, { redirect: 'manual' })

    expect(res.status).toBe(401)
    const body = (await res.json()) as { error: string; message: string }
    expect(body.error).toBe('unauthenticated')
    expect(body.message).toContain('x-shellpilot-proxy-token')
    expect(up.hits).toEqual([])
  })

  it('refuses a wrong token', async () => {
    const up = await upstream()
    cleanups.push(up.close)
    const h = await harness([rule({ origin: up.origin })])

    const res = await fetch(`${h.base()}/${up.origin}/v1/x`, {
      redirect: 'manual',
      headers: { [CRED_PROXY_TOKEN_HEADER]: 'cpx_wrong' }
    })

    expect(res.status).toBe(401)
    expect(up.hits).toEqual([])
  })

  // Authentication happens BEFORE routing on purpose: a local process with no
  // token must not be able to enumerate which APIs have rules by watching a
  // 401 turn into a 403.
  it('answers 401 for a covered and an uncovered destination alike, when the token is missing', async () => {
    const covered = await upstream()
    cleanups.push(covered.close)
    const h = await harness([rule({ origin: covered.origin })])

    const a = await fetch(`${h.base()}/${covered.origin}/v1/x`, { redirect: 'manual' })
    const b = await fetch(`${h.base()}/http://127.0.0.1:9/v1/x`, { redirect: 'manual' })

    expect(a.status).toBe(401)
    expect(b.status).toBe(401)
    expect(((await a.json()) as { error: string }).error).toBe('unauthenticated')
    expect(((await b.json()) as { error: string }).error).toBe('unauthenticated')
  })

  it('refuses everything when no token has been minted at all', async () => {
    const up = await upstream()
    cleanups.push(up.close)
    const h = await harness([rule({ origin: up.origin })], { clientToken: () => null })

    const res = await call(h, `${up.origin}/v1/x`)

    expect(res.status).toBe(401)
    expect(up.hits).toEqual([])
  })

  it('knows which peer addresses are this machine', () => {
    expect(isLoopbackAddress('127.0.0.1')).toBe(true)
    expect(isLoopbackAddress('127.0.0.53')).toBe(true)
    expect(isLoopbackAddress('::1')).toBe(true)
    expect(isLoopbackAddress('::ffff:127.0.0.1')).toBe(true)
    expect(isLoopbackAddress('192.168.1.10')).toBe(false)
    expect(isLoopbackAddress('::ffff:192.168.1.10')).toBe(false)
    expect(isLoopbackAddress('10.0.0.1')).toBe(false)
    expect(isLoopbackAddress(undefined)).toBe(false)
  })
})

describe('a redirect to another origin does not carry the credential', () => {
  it('does not follow the hop, and the second host is never contacted', async () => {
    const thief = await upstream()
    cleanups.push(thief.close)
    const api = await upstream((_req, res) => {
      res.writeHead(302, { location: `${thief.origin}/stolen` })
      res.end()
    })
    cleanups.push(api.close)
    const h = await harness([
      rule({ origin: api.origin, injection: { kind: 'header', name: 'X-Api-Key' } })
    ])

    const res = await call(h, `${api.origin}/v1/x`)

    expect(res.status).toBe(302)
    expect(res.headers.get('x-shellpilot-proxy')).toBe('redirect-not-followed')
    // The credential was injected exactly once, to the origin in the rule.
    expect(api.hits).toHaveLength(1)
    expect(api.hits[0].headers['x-api-key']).toBe(SECRET)
    // And the other host heard nothing at all.
    expect(thief.hits).toEqual([])
  })

  // The same hop, with a naive caller that DOES follow redirects — which is
  // every HTTP client's default. It reaches the thief directly, because the
  // Location header is honest, and it arrives with nothing: the caller never
  // held the credential, so it has none to resend.
  it('leaves a following caller with nothing to leak', async () => {
    const thief = await upstream()
    cleanups.push(thief.close)
    const api = await upstream((_req, res) => {
      res.writeHead(302, { location: `${thief.origin}/stolen` })
      res.end()
    })
    cleanups.push(api.close)
    const h = await harness([
      rule({ origin: api.origin, injection: { kind: 'header', name: 'X-Api-Key' } })
    ])

    const res = await fetch(`${h.base()}/${api.origin}/v1/x`, {
      redirect: 'follow',
      headers: { [CRED_PROXY_TOKEN_HEADER]: TOKEN }
    })

    expect(res.status).toBe(200)
    expect(thief.hits).toHaveLength(1)
    expect(thief.hits[0].url).toBe('/stolen')
    expect(thief.hits[0].headers['x-api-key']).toBeUndefined()
    expect(thief.hits[0].headers.authorization).toBeUndefined()
    expect(JSON.stringify(thief.hits[0].headers)).not.toContain(SECRET)
  })

  it('records the refused hop by origin, and says the credential was not resent', async () => {
    const thief = await upstream()
    cleanups.push(thief.close)
    const api = await upstream((_req, res) => {
      res.writeHead(307, { location: `${thief.origin}/stolen?token=abc` })
      res.end()
    })
    cleanups.push(api.close)
    const h = await harness([rule({ origin: api.origin })])

    await call(h, `${api.origin}/v1/x`)

    expect(h.audit[0].outcome).toBe('forwarded')
    expect(h.audit[0].status).toBe(307)
    expect(h.audit[0].detail).toBe(
      `Upstream redirected to ${thief.origin}; not followed, credential not resent.`
    )
    // The origin, never the redirect's path or its query string.
    expect(h.audit[0].detail).not.toContain('token=abc')
  })

  it('passes a same-origin redirect back to the caller rather than following it either', async () => {
    let n = 0
    const api = await upstream((_req, res) => {
      if (n++ === 0) {
        res.writeHead(302, { location: '/v1/moved' })
        res.end()
        return
      }
      res.writeHead(200)
      res.end('should-not-be-reached-by-the-proxy')
    })
    cleanups.push(api.close)
    const h = await harness([rule({ origin: api.origin })])

    const res = await call(h, `${api.origin}/v1/x`)

    expect(res.status).toBe(302)
    expect(res.headers.get('location')).toBe('/v1/moved')
    // One request, not two: even a same-origin hop is a credentialed request
    // re-issued on the strength of a header the upstream wrote.
    expect(api.hits).toHaveLength(1)
    // Same-origin is not a leak, so it is not flagged as one.
    expect(res.headers.get('x-shellpilot-proxy')).toBe('forwarded')
  })
})

describe('a locked vault parks rather than forwarding bare', () => {
  it('sends nothing, says why, and does not blame the far end', async () => {
    const up = await upstream()
    cleanups.push(up.close)
    const h = await harness([rule({ origin: up.origin })], {
      resolveCredential: () => ({ ok: false, reason: 'vault-locked' })
    })

    const res = await call(h, `${up.origin}/v1/x`)

    expect(res.status).toBe(409)
    const body = (await res.json()) as { error: string; message: string }
    expect(body.error).toBe('vault-locked')
    expect(body.message).toBe(
      'The vault is locked, so the credential for that rule could not be read. The request was ' +
        'parked, not sent — an unauthenticated request would have failed at the far end and looked ' +
        'like a permissions problem there.'
    )
    // The thing that would have been worst: a request going out unauthenticated.
    expect(up.hits).toEqual([])
  })

  it('reports a parked state rather than an error per request', async () => {
    const up = await upstream()
    cleanups.push(up.close)
    const h = await harness([rule({ origin: up.origin })], {
      resolveCredential: () => ({ ok: false, reason: 'vault-locked' })
    })

    await call(h, `${up.origin}/a`)
    await call(h, `${up.origin}/b`)
    await call(h, `${up.origin}/c`)

    const parked = h.proxy.status().parked
    expect(parked?.reason).toBe('vault-locked')
    expect(parked?.calls).toBe(3)
    expect(typeof parked?.since).toBe('string')
  })

  it('clears the parked state as soon as a call resolves again', async () => {
    const up = await upstream()
    cleanups.push(up.close)
    let locked = true
    const h = await harness([rule({ origin: up.origin })], {
      resolveCredential: () =>
        locked ? { ok: false, reason: 'vault-locked' } : { ok: true, value: SECRET }
    })

    await call(h, `${up.origin}/a`)
    expect(h.proxy.status().parked?.reason).toBe('vault-locked')

    locked = false
    await call(h, `${up.origin}/b`)
    expect(h.proxy.status().parked).toBeUndefined()
    expect(up.hits).toHaveLength(1)
  })

  it('parks the same way when the vault entry has simply gone', async () => {
    const up = await upstream()
    cleanups.push(up.close)
    const h = await harness([rule({ origin: up.origin })], {
      resolveCredential: () => ({ ok: false, reason: 'credential-missing' })
    })

    const res = await call(h, `${up.origin}/v1/x`)

    expect(res.status).toBe(409)
    expect(((await res.json()) as { error: string }).error).toBe('credential-missing')
    expect(up.hits).toEqual([])
  })
})

describe('the audit says what happened and never what the credential is', () => {
  it('records the destination, the rule, the outcome and a duration', async () => {
    const up = await upstream()
    cleanups.push(up.close)
    const h = await harness([rule({ origin: up.origin, id: 'rule-7', name: 'Billing API' })])

    await call(h, `${up.origin}/v1/invoices?since=2026-01-01`, { method: 'DELETE' })

    const row = h.audit[0]
    expect(row.method).toBe('DELETE')
    expect(row.origin).toBe(up.origin)
    expect(row.path).toBe('/v1/invoices')
    expect(row.ruleId).toBe('rule-7')
    expect(row.ruleName).toBe('Billing API')
    expect(row.outcome).toBe('forwarded')
    expect(row.status).toBe(200)
    expect(typeof row.ms).toBe('number')
  })

  it('records no query string, no body and no headers', async () => {
    const up = await upstream()
    cleanups.push(up.close)
    const h = await harness([rule({ origin: up.origin })])

    await call(h, `${up.origin}/v1/x?customer=acme&secret_in_query=hunter2`, {
      method: 'POST',
      body: 'a-body-nobody-should-log'
    })

    const dump = JSON.stringify(h.audit)
    expect(dump).not.toContain('secret_in_query')
    expect(dump).not.toContain('hunter2')
    expect(dump).not.toContain('a-body-nobody-should-log')
    expect(dump).not.toContain(SECRET)
  })

  it('records a refusal too, so a rule that never fires is visible', async () => {
    const up = await upstream()
    cleanups.push(up.close)
    const h = await harness([rule({ origin: up.origin })])

    await call(h, 'http://127.0.0.1:9/v1/x')

    expect(h.audit[0].outcome).toBe('no-rule')
    expect(h.audit[0].origin).toBe('http://127.0.0.1:9')
    expect(h.audit[0].ruleId).toBeNull()
  })

  it('keeps the credential out of an upstream failure message', async () => {
    // Nothing is listening on this port, so the fetch fails and the error text
    // is whatever undici says — which is exactly the text nobody reviews.
    const dead = await upstream()
    const port = dead.port
    await dead.close()
    const h = await harness([rule({ origin: `http://127.0.0.1:${port}` })])

    const res = await call(h, `http://127.0.0.1:${port}/v1/x`)

    expect(res.status).toBe(502)
    expect(h.audit[0].outcome).toBe('upstream-failed')
    expect(JSON.stringify(h.audit)).not.toContain(SECRET)
  })

  it('shows recent calls newest first', async () => {
    const up = await upstream()
    cleanups.push(up.close)
    const h = await harness([rule({ origin: up.origin })])

    await call(h, `${up.origin}/first`)
    await call(h, `${up.origin}/second`)

    expect(h.proxy.calls().map((c) => c.path)).toEqual(['/second', '/first'])
  })
})

describe('redactThenCap redacts before it truncates', () => {
  // The exact bug found in the change log this week: capping first cuts the
  // END marker off a PEM block, the pattern then matches nothing, and the key
  // ships as prose.
  it('redacts a PEM block that would be cut in half by the cap', () => {
    const pem =
      '-----BEGIN RSA PRIVATE KEY-----\n' +
      `${'MIIEowIBAAKCAQEAx7Vk9pQ2mN3rT8sL0wYzB4cD5eF6gH7iJ8kL9mN0oP1qR2sT'.repeat(6)}\n` +
      '-----END RSA PRIVATE KEY-----'
    const line = `upstream said: ${pem}`

    const out = redactThenCap(line, [], 120)

    expect(out).not.toContain('MIIEowIBAAKCAQEA')
    expect(out).toContain('[REDACTED]')
    expect(out.length).toBeLessThanOrEqual(121)
  })

  it('blanks a known secret that sits past the cap', () => {
    const line = `${'x'.repeat(300)} ${SECRET}`
    const out = redactThenCap(line, [SECRET], 400)
    expect(out).not.toContain(SECRET)
    expect(out).toContain('[REDACTED]')
  })

  it('leaves a short clean string exactly as it was', () => {
    expect(redactThenCap('connection refused', [])).toBe('connection refused')
  })
})

describe('the listener is loopback and the rule file is what persists', () => {
  it('binds 127.0.0.1, never a wildcard address', async () => {
    const h = await harness([])
    expect(h.proxy.status().address).toBe(`127.0.0.1:${h.proxy.boundPort()}`)
    expect(h.proxy.status().listening).toBe(true)
  })

  it('writes the port it actually bound, so the panel does not show 0', async () => {
    const h = await harness([])
    expect(h.written()?.port).toBe(h.proxy.boundPort())
    expect(h.written()?.enabled).toBe(true)
  })

  it('stops listening when disabled, and remembers that', async () => {
    const up = await upstream()
    cleanups.push(up.close)
    const h = await harness([rule({ origin: up.origin })])
    const port = h.proxy.boundPort()

    await h.proxy.disable()

    expect(h.proxy.status().listening).toBe(false)
    expect(h.written()?.enabled).toBe(false)
    await expect(fetch(`http://127.0.0.1:${port}/${up.origin}/x`)).rejects.toThrow()
  })
})

describe('saving a rule', () => {
  it('stores the sanitised form, not the draft', async () => {
    const h = await harness([])
    const saved = h.proxy.saveRule({
      name: 'Example',
      origin: 'HTTPS://API.Example.com/v1/ignored',
      credential: { vaultEntryId: 'v1', slot: 'password' },
      injection: { kind: 'header', name: 'X-Api-Key' }
    })
    expect(saved.ok).toBe(true)
    if (!saved.ok) return
    expect(saved.rule.origin).toBe('https://api.example.com')
    expect(saved.rule.id).toBe('id-1')
    expect(h.proxy.rules().map((r) => r.origin)).toEqual(['https://api.example.com'])
  })

  it('refuses a second rule for the same origin, and says which one already covers it', async () => {
    const h = await harness([
      rule({ id: 'a', name: 'First', origin: 'https://api.example.com' })
    ])
    const res = h.proxy.saveRule({
      name: 'Second',
      origin: 'https://api.example.com:443',
      credential: { vaultEntryId: 'v2', slot: 'password' },
      injection: { kind: 'bearer' }
    })
    expect(res.ok).toBe(false)
    if (res.ok) return
    expect(res.error).toBe(
      '"First" already covers https://api.example.com. One origin, one rule — two would be an ' +
        'ambiguity about which credential leaves this machine.'
    )
  })

  it('names the specific problem with an injection rather than a generic refusal', async () => {
    const h = await harness([])
    const res = h.proxy.saveRule({
      name: 'Bad',
      origin: 'https://api.example.com',
      credential: { vaultEntryId: 'v1', slot: 'password' },
      injection: { kind: 'header', name: 'Host' }
    })
    expect(res.ok).toBe(false)
    if (res.ok) return
    expect(res.error).toBe('"Host" cannot carry a credential.')
  })

  it('removes a rule and stops honouring it', async () => {
    const up = await upstream()
    cleanups.push(up.close)
    const h = await harness([rule({ id: 'gone', origin: up.origin })])

    expect(h.proxy.removeRule('gone')).toEqual({ ok: true })
    const res = await call(h, `${up.origin}/v1/x`)

    expect(res.status).toBe(403)
    expect(up.hits).toEqual([])
    expect(h.written()?.rules).toEqual([])
  })
})
