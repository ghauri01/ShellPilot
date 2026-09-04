import { describe, it, expect } from 'vitest'
import {
  CRED_PROXY_TOKEN_HEADER,
  HOP_BY_HOP_HEADERS,
  UNINJECTABLE_HEADERS,
  credProxyBaseUrl,
  describeInjection,
  matchRule,
  normaliseOrigin,
  parseProxyTarget,
  sanitiseRule,
  sanitiseRules,
  validateInjection
} from '../src/shared/credproxy'
import type { CredProxyRule } from '../src/shared/credproxy'

// The matching model, on its own, with no listener and no vault.
//
// Everything here is a literal. There is no helper that derives the expected
// origin by calling normaliseOrigin, because a test that computes its
// expectation with the function under test agrees with that function's bugs.

const rule = (over: Partial<CredProxyRule> = {}): CredProxyRule => ({
  id: 'r1',
  name: 'Example',
  origin: 'https://api.example.com',
  credential: { vaultEntryId: 'v1', slot: 'password' },
  injection: { kind: 'bearer' },
  enabled: true,
  createdAt: '2026-01-01T00:00:00.000Z',
  ...over
})

describe('normaliseOrigin', () => {
  it('keeps a plain https origin as it is', () => {
    expect(normaliseOrigin('https://api.example.com')).toBe('https://api.example.com')
  })

  it('drops the path, query and fragment', () => {
    expect(normaliseOrigin('https://api.example.com/v1/things?a=1#x')).toBe('https://api.example.com')
  })

  it('lowercases the host and the scheme', () => {
    expect(normaliseOrigin('HTTPS://API.Example.COM/x')).toBe('https://api.example.com')
  })

  it('drops the default port but keeps an explicit non-default one', () => {
    expect(normaliseOrigin('https://api.example.com:443')).toBe('https://api.example.com')
    expect(normaliseOrigin('http://api.example.com:80')).toBe('http://api.example.com')
    expect(normaliseOrigin('https://api.example.com:8443')).toBe('https://api.example.com:8443')
  })

  it('drops a single trailing dot, because that is the same host', () => {
    expect(normaliseOrigin('https://api.example.com./v1')).toBe('https://api.example.com')
  })

  it('drops userinfo rather than carrying it into a comparison', () => {
    expect(normaliseOrigin('https://someone:hunter2@api.example.com/x')).toBe('https://api.example.com')
  })

  it('refuses anything that is not http or https', () => {
    expect(normaliseOrigin('file:///etc/passwd')).toBeNull()
    expect(normaliseOrigin('ftp://api.example.com')).toBeNull()
    expect(normaliseOrigin('javascript:alert(1)')).toBeNull()
  })

  it('refuses input that is not a URL at all', () => {
    expect(normaliseOrigin('api.example.com')).toBeNull()
    expect(normaliseOrigin('')).toBeNull()
    expect(normaliseOrigin('   ')).toBeNull()
  })
})

describe('matchRule matches an origin exactly, and near misses do not match', () => {
  const rules = [rule()]

  it('matches the origin it was written for', () => {
    expect(matchRule(rules, 'https://api.example.com')?.id).toBe('r1')
    expect(matchRule(rules, 'https://api.example.com:443')?.id).toBe('r1')
  })

  // THE ONE THAT MATTERS. Every suffix, prefix or `includes` formulation of
  // this match hands the key to whoever registered the second domain.
  it('does not match a hostname that merely starts with the rule host', () => {
    expect(matchRule(rules, 'https://api.example.com.evil.tld')).toBeNull()
  })

  it('does not match a hostname that merely ends with the rule host', () => {
    expect(matchRule(rules, 'https://evil-api.example.com')).toBeNull()
    expect(matchRule(rules, 'https://notapi.example.com')).toBeNull()
  })

  it('does not match a subdomain of the rule host', () => {
    expect(matchRule(rules, 'https://staging.api.example.com')).toBeNull()
  })

  it('does not match the parent domain', () => {
    expect(matchRule(rules, 'https://example.com')).toBeNull()
  })

  it('does not match the same host over a different scheme', () => {
    expect(matchRule(rules, 'http://api.example.com')).toBeNull()
  })

  it('does not match the same host on a different port', () => {
    expect(matchRule(rules, 'https://api.example.com:8443')).toBeNull()
  })

  it('does not match when the host is only in the path or the fragment', () => {
    expect(matchRule(rules, 'https://evil.tld/api.example.com')).toBeNull()
    expect(matchRule(rules, 'https://evil.tld#api.example.com')).toBeNull()
  })

  it('does not match when the rule host is smuggled into userinfo', () => {
    expect(matchRule(rules, 'https://api.example.com@evil.tld/v1')).toBeNull()
  })

  it('returns null rather than a rule when there are no rules at all', () => {
    expect(matchRule([], 'https://api.example.com')).toBeNull()
  })
})

describe('parseProxyTarget', () => {
  it('reads the upstream URL out of the request target', () => {
    const r = parseProxyTarget('/https://api.example.com/v1/things?limit=5')
    expect(r.ok).toBe(true)
    if (!r.ok) return
    expect(r.target.url.href).toBe('https://api.example.com/v1/things?limit=5')
    expect(r.target.origin).toBe('https://api.example.com')
  })

  // Several HTTP clients collapse `//` inside a path before the request goes
  // out, which turns the documented form into this one. Without this the
  // feature works with curl and with nothing else.
  it('accepts the collapsed single-slash form real clients produce', () => {
    const r = parseProxyTarget('/https:/api.example.com/v1/things')
    expect(r.ok).toBe(true)
    if (!r.ok) return
    expect(r.target.url.href).toBe('https://api.example.com/v1/things')
    expect(r.target.origin).toBe('https://api.example.com')
  })

  it('refuses a bare path, which is what a misconfigured client sends', () => {
    const r = parseProxyTarget('/v1/things')
    expect(r).toEqual({ ok: false, reason: 'not-a-target' })
  })

  it('refuses the root path', () => {
    expect(parseProxyTarget('/')).toEqual({ ok: false, reason: 'not-a-target' })
  })

  it('refuses a target that does not start with a slash', () => {
    expect(parseProxyTarget('https://api.example.com/v1')).toEqual({
      ok: false,
      reason: 'not-a-target'
    })
  })

  it('refuses a scheme that is not http or https', () => {
    expect(parseProxyTarget('/file:///etc/passwd')).toEqual({
      ok: false,
      reason: 'unsupported-scheme'
    })
    expect(parseProxyTarget('/ftp://api.example.com/x')).toEqual({
      ok: false,
      reason: 'unsupported-scheme'
    })
  })
})

describe('validateInjection', () => {
  it('accepts a bearer rule with no name', () => {
    expect(validateInjection({ kind: 'bearer' })).toEqual({ ok: true })
  })

  it('accepts an ordinary API-key header', () => {
    expect(validateInjection({ kind: 'header', name: 'X-Api-Key' })).toEqual({ ok: true })
  })

  it('refuses a header rule with no name', () => {
    const r = validateInjection({ kind: 'header', name: '' })
    expect(r.ok).toBe(false)
    if (r.ok) return
    expect(r.error).toBe('This rule needs a header name.')
  })

  it('refuses a header name with a colon or a newline in it', () => {
    expect(validateInjection({ kind: 'header', name: 'X-Api-Key: x' }).ok).toBe(false)
    expect(validateInjection({ kind: 'header', name: 'X-Api\r\nHost' }).ok).toBe(false)
  })

  // Injecting the credential under the proxy's own token header would put OUR
  // shared secret on the wire to a third party.
  it('refuses to inject a credential into the proxy token header', () => {
    const r = validateInjection({ kind: 'header', name: 'X-ShellPilot-Proxy-Token' })
    expect(r.ok).toBe(false)
    if (r.ok) return
    expect(r.error).toBe('"X-ShellPilot-Proxy-Token" cannot carry a credential.')
  })

  it('refuses to inject into Host or Content-Length', () => {
    expect(validateInjection({ kind: 'header', name: 'Host' }).ok).toBe(false)
    expect(validateInjection({ kind: 'header', name: 'content-length' }).ok).toBe(false)
  })

  it('refuses a basic-auth username carrying a colon', () => {
    const r = validateInjection({ kind: 'basic', name: 'user:pass' })
    expect(r.ok).toBe(false)
    if (r.ok) return
    expect(r.error).toBe('A basic-auth username cannot contain a colon or whitespace.')
  })
})

describe('the header lists name the proxy token', () => {
  // Both lists, for two different reasons — an injected credential must never
  // be given that name, and an inbound token must never be forwarded upstream.
  it('never lets a rule inject into it', () => {
    expect(UNINJECTABLE_HEADERS).toContain('x-shellpilot-proxy-token')
  })

  it('never forwards it to the upstream', () => {
    expect(HOP_BY_HOP_HEADERS).toContain('x-shellpilot-proxy-token')
  })

  it('is the header the caller actually sends', () => {
    expect(CRED_PROXY_TOKEN_HEADER).toBe('x-shellpilot-proxy-token')
  })
})

describe('sanitiseRule', () => {
  it('rebuilds a well-formed rule', () => {
    const r = sanitiseRule({
      id: 'r1',
      name: 'Example',
      origin: 'https://api.example.com/v1/ignored',
      credential: { vaultEntryId: 'v1', slot: 'password' },
      injection: { kind: 'header', name: 'X-Api-Key' },
      enabled: true,
      createdAt: '2026-01-01T00:00:00.000Z'
    })
    expect(r).toEqual({
      id: 'r1',
      name: 'Example',
      origin: 'https://api.example.com',
      credential: { vaultEntryId: 'v1', slot: 'password' },
      injection: { kind: 'header', name: 'X-Api-Key' },
      enabled: true,
      createdAt: '2026-01-01T00:00:00.000Z'
    })
  })

  it('drops a rule whose origin is not a URL', () => {
    expect(sanitiseRule({ ...rule(), origin: 'api.example.com' })).toBeNull()
  })

  it('drops a rule with no vault entry behind it', () => {
    expect(sanitiseRule({ ...rule(), credential: { vaultEntryId: '', slot: 'password' } })).toBeNull()
  })

  it('drops a rule whose injection would not validate', () => {
    expect(sanitiseRule({ ...rule(), injection: { kind: 'header', name: 'Host' } })).toBeNull()
  })

  it('drops a rule naming an injection kind that does not exist', () => {
    expect(sanitiseRule({ ...rule(), injection: { kind: 'cookie', name: 'k' } })).toBeNull()
  })

  it('drops a field-slot rule that names no field', () => {
    expect(
      sanitiseRule({ ...rule(), credential: { vaultEntryId: 'v1', slot: 'field', fieldKey: '' } })
    ).toBeNull()
  })

  it('treats a missing enabled flag as on, and only an explicit false as off', () => {
    const on = sanitiseRule({ ...rule(), enabled: undefined })
    expect(on?.enabled).toBe(true)
    const off = sanitiseRule({ ...rule(), enabled: false })
    expect(off?.enabled).toBe(false)
  })

  it('falls back to the origin for a rule with no name', () => {
    expect(sanitiseRule({ ...rule(), name: '   ' })?.name).toBe('https://api.example.com')
  })
})

describe('sanitiseRules', () => {
  it('keeps the good rules and drops the bad ones', () => {
    const out = sanitiseRules([
      rule({ id: 'a', origin: 'https://a.example.com' }),
      { nonsense: true },
      rule({ id: 'b', origin: 'https://b.example.com' })
    ])
    expect(out.map((r) => r.id)).toEqual(['a', 'b'])
  })

  // Two rules for one origin is an ambiguity about which credential leaves the
  // machine, not a merge to resolve at request time.
  it('collapses a duplicate origin to the first rule', () => {
    const out = sanitiseRules([
      rule({ id: 'a', origin: 'https://api.example.com', name: 'first' }),
      rule({ id: 'b', origin: 'https://API.example.com:443', name: 'second' })
    ])
    expect(out).toHaveLength(1)
    expect(out[0].id).toBe('a')
  })

  it('collapses a duplicate id', () => {
    const out = sanitiseRules([
      rule({ id: 'a', origin: 'https://a.example.com' }),
      rule({ id: 'a', origin: 'https://b.example.com' })
    ])
    expect(out.map((r) => r.origin)).toEqual(['https://a.example.com'])
  })

  it('returns nothing for something that is not an array', () => {
    expect(sanitiseRules({ rules: [] })).toEqual([])
    expect(sanitiseRules(null)).toEqual([])
  })
})

describe('descriptions never name the secret', () => {
  it('says how the credential goes out, not what it is', () => {
    expect(describeInjection({ kind: 'bearer' })).toBe('Authorization: Bearer')
    expect(describeInjection({ kind: 'header', name: 'X-Api-Key' })).toBe('header X-Api-Key')
    expect(describeInjection({ kind: 'query', name: 'api_key' })).toBe('query parameter api_key')
    expect(describeInjection({ kind: 'basic', name: 'svc' })).toBe('basic auth as svc')
  })
})

describe('credProxyBaseUrl', () => {
  it('is the loopback address, never a wildcard one', () => {
    expect(credProxyBaseUrl(5178, 'https://api.example.com')).toBe(
      'http://127.0.0.1:5178/https://api.example.com'
    )
  })
})
