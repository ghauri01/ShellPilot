import { describe, expect, it } from 'vitest'
import {
  credProxyTokenState,
  credProxyTokenUsable,
  type CredProxyToken
} from '../src/shared/credproxy'

const NOW = Date.UTC(2026, 8, 5, 12, 0, 0)
const token = (over: Partial<CredProxyToken> = {}): CredProxyToken => ({
  id: 't1',
  name: 'nightly backup script',
  createdAt: new Date(NOW - 86_400_000).toISOString(),
  expiresAt: null,
  revokedAt: null,
  lastUsedAt: null,
  ...over
})

describe('whether a token may be used', () => {
  it('is usable when it has no end date and nobody took it away', () => {
    expect(credProxyTokenUsable(token(), NOW)).toBe(true)
  })

  it('stops at the moment it expires, not after a grace period', () => {
    const at = new Date(NOW).toISOString()
    expect(credProxyTokenState(token({ expiresAt: at }), NOW)).toBe('expired')
    expect(credProxyTokenState(token({ expiresAt: at }), NOW - 1)).toBe('active')
  })

  it('says revoked rather than expired when it is both', () => {
    // A token revoked before its end date is revoked. Calling it expired sends
    // someone to change a date when what actually happened is that it was taken
    // away, and they would hand the same script a fresh one.
    const t = token({
      expiresAt: new Date(NOW - 1000).toISOString(),
      revokedAt: new Date(NOW - 5000).toISOString()
    })
    expect(credProxyTokenState(t, NOW)).toBe('revoked')
  })

  it('treats an expiry it cannot read as expired, never as forever', () => {
    // The failure that matters. A corrupt or half-written record must not read
    // as "no expiry set" -- that turns a broken file into a permanent
    // credential. The safe reading of a date we cannot parse is the one that
    // stops.
    for (const bad of ['', 'soon', 'not-a-date', '2026-13-45']) {
      expect(credProxyTokenState(token({ expiresAt: bad }), NOW)).toBe('expired')
      expect(credProxyTokenUsable(token({ expiresAt: bad }), NOW)).toBe(false)
    }
  })

  it('does not become usable again by the clock going backwards', () => {
    // Revocation is not a function of time.
    const t = token({ revokedAt: new Date(NOW).toISOString() })
    expect(credProxyTokenUsable(t, NOW - 10 * 86_400_000)).toBe(false)
  })
})

// ---------------------------------------------------------------------------

import { migrateLegacyToken, credProxyTokenSecretId } from '../src/main/services/credProxy'

describe('promoting the single token that existed before', () => {
  const file = { v: 1 as const, enabled: true, port: 5178, rules: [] }

  it('keeps the old secret id, so a script that holds the token keeps working', () => {
    // The whole point. An upgrade that quietly invalidates a live credential
    // is an outage dressed as a migration -- every script pointed at the proxy
    // would start failing at once, for a change nobody asked for.
    const out = migrateLegacyToken(file, true, '2026-09-05T00:00:00.000Z')
    expect(out.tokens).toHaveLength(1)
    expect(credProxyTokenSecretId(out.tokens![0].id)).toBe('credproxy.client.token')
  })

  it('does not invent a token on an install that never minted one', () => {
    const out = migrateLegacyToken(file, false, '2026-09-05T00:00:00.000Z')
    expect(out.tokens).toEqual([])
  })

  it('runs once, however many times it is called', () => {
    // It runs on every read, so it has to be idempotent or the list grows a
    // duplicate every time the panel opens.
    let out = migrateLegacyToken(file, true, '2026-09-05T00:00:00.000Z')
    out = migrateLegacyToken(out, true, '2026-09-06T00:00:00.000Z')
    out = migrateLegacyToken(out, true, '2026-09-07T00:00:00.000Z')
    expect(out.tokens).toHaveLength(1)
  })

  it('names it so the operator can tell what it is', () => {
    // A list of tokens nobody can account for is a list nobody revokes from.
    const out = migrateLegacyToken(file, true, '2026-09-05T00:00:00.000Z')
    expect(out.tokens![0].name).toMatch(/Original token/)
    expect(out.tokens![0].revokedAt).toBeNull()
  })

  it('gives new tokens their own secret id, not the legacy one', () => {
    expect(credProxyTokenSecretId('abc123')).toBe('credproxy.token.abc123')
  })
})
