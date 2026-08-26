import { describe, it, expect } from 'vitest'
import { createHash, createHmac, randomBytes } from 'node:crypto'

import {
  parseKnownHosts,
  canonicalHostname,
  entryMatchesHost,
  lookupInKnownHosts
} from '../src/main/services/opensshKnownHosts'

const fingerprint = (key: Buffer): string =>
  `SHA256:${createHash('sha256').update(key).digest('base64').replace(/=+$/, '')}`

const KEY_A = Buffer.from('ssh-rsa-key-material-a')
const KEY_B = Buffer.from('ssh-rsa-key-material-b')
const b64 = (b: Buffer): string => b.toString('base64')

function hashHost(name: string): string {
  const salt = randomBytes(20)
  const hash = createHmac('sha1', salt).update(name).digest('base64')
  return `|1|${salt.toString('base64')}|${hash}`
}

describe('OpenSSH known_hosts parsing', () => {
  it('skips comments, blank lines and truncated entries', () => {
    const entries = parseKnownHosts(
      ['# a comment', '', '   ', 'not-enough-fields', `example.com ssh-rsa ${b64(KEY_A)}`].join('\n')
    )
    expect(entries).toHaveLength(1)
    expect(entries[0].patterns).toEqual(['example.com'])
    expect(entries[0].keyType).toBe('ssh-rsa')
    expect(entries[0].key.equals(KEY_A)).toBe(true)
  })

  it('reads @revoked and @cert-authority markers, and drops unknown ones', () => {
    const entries = parseKnownHosts(
      [
        `@revoked example.com ssh-rsa ${b64(KEY_A)}`,
        `@cert-authority *.example.com ssh-rsa ${b64(KEY_B)}`,
        `@some-future-marker example.com ssh-rsa ${b64(KEY_A)}`
      ].join('\n')
    )
    expect(entries.map((e) => e.marker)).toEqual(['revoked', 'cert-authority'])
  })

  it('accepts a trailing comment after the key', () => {
    const entries = parseKnownHosts(`example.com ssh-ed25519 ${b64(KEY_A)} zeeshan@laptop`)
    expect(entries).toHaveLength(1)
    expect(entries[0].key.equals(KEY_A)).toBe(true)
  })
})

describe('host name canonicalisation', () => {
  // Getting this wrong is the whole bug: a host trusted on a non-default port
  // is stored as "[host]:port", so looking it up by bare host finds nothing.
  it('brackets the host only when the port is not 22', () => {
    expect(canonicalHostname('13.251.230.58', 22000)).toBe('[13.251.230.58]:22000')
    expect(canonicalHostname('example.com', 22)).toBe('example.com')
    expect(canonicalHostname('example.com', 0)).toBe('example.com')
  })
})

describe('host pattern matching', () => {
  const entryFor = (hosts: string): ReturnType<typeof parseKnownHosts>[number] =>
    parseKnownHosts(`${hosts} ssh-rsa ${b64(KEY_A)}`)[0]

  it('matches a plain host and a comma-separated list', () => {
    expect(entryMatchesHost(entryFor('example.com'), 'example.com')).toBe(true)
    expect(entryMatchesHost(entryFor('a.com,b.com,c.com'), 'b.com')).toBe(true)
    expect(entryMatchesHost(entryFor('a.com,b.com'), 'z.com')).toBe(false)
  })

  it('matches a non-default port only in bracketed form', () => {
    const entry = entryFor('[13.251.230.58]:22000')
    expect(entryMatchesHost(entry, '[13.251.230.58]:22000')).toBe(true)
    expect(entryMatchesHost(entry, '13.251.230.58')).toBe(false)
  })

  it('supports * and ? wildcards', () => {
    expect(entryMatchesHost(entryFor('*.example.com'), 'web1.example.com')).toBe(true)
    expect(entryMatchesHost(entryFor('*.example.com'), 'example.com')).toBe(false)
    expect(entryMatchesHost(entryFor('web?.example.com'), 'web1.example.com')).toBe(true)
    expect(entryMatchesHost(entryFor('web?.example.com'), 'web12.example.com')).toBe(false)
  })

  it('lets a negation override a wildcard match', () => {
    expect(entryMatchesHost(entryFor('*.example.com,!secret.example.com'), 'secret.example.com')).toBe(false)
    expect(entryMatchesHost(entryFor('*.example.com,!secret.example.com'), 'web.example.com')).toBe(true)
  })

  it('does not let a wildcard pattern escape a dot boundary it did not ask for', () => {
    // "*" is a glob, not a regex — a literal dot in the pattern must stay literal.
    expect(entryMatchesHost(entryFor('web1.example.com'), 'web1XexampleXcom')).toBe(false)
  })

  it('matches hashed (HashKnownHosts) entries', () => {
    const entry = parseKnownHosts(`${hashHost('[13.251.230.58]:22000')} ssh-rsa ${b64(KEY_A)}`)[0]
    expect(entry.hashed).not.toBeNull()
    expect(entryMatchesHost(entry, '[13.251.230.58]:22000')).toBe(true)
    expect(entryMatchesHost(entry, '[13.251.230.58]:22')).toBe(false)
  })
})

describe('looking a presented key up in known_hosts', () => {
  const look = (text: string, host: string, port: number, key: Buffer): ReturnType<typeof lookupInKnownHosts> =>
    lookupInKnownHosts(parseKnownHosts(text), host, port, fingerprint, fingerprint(key))

  it('recognises the exact key OpenSSH already trusts, on a non-default port', () => {
    const result = look(`[13.251.230.58]:22000 ssh-rsa ${b64(KEY_A)}`, '13.251.230.58', 22000, KEY_A)
    expect(result).toEqual({ trusted: true, knownUnderAnotherKey: false, revoked: false })
  })

  it('reports a host known under a different key rather than calling it trusted', () => {
    const result = look(`example.com ssh-rsa ${b64(KEY_A)}`, 'example.com', 22, KEY_B)
    expect(result.trusted).toBe(false)
    expect(result.knownUnderAnotherKey).toBe(true)
  })

  it('still recognises the right key when the host has several', () => {
    // A host normally has one line per key type; matching must not be
    // defeated by the other types sitting alongside it.
    const text = [`example.com ssh-rsa ${b64(KEY_A)}`, `example.com ssh-ed25519 ${b64(KEY_B)}`].join('\n')
    const result = look(text, 'example.com', 22, KEY_B)
    expect(result.trusted).toBe(true)
  })

  it('reports revocation for the revoked key', () => {
    const result = look(`@revoked example.com ssh-rsa ${b64(KEY_A)}`, 'example.com', 22, KEY_A)
    expect(result.revoked).toBe(true)
    expect(result.trusted).toBe(false)
  })

  it('does not treat a CA entry as trust for a host key', () => {
    // A @cert-authority line authorises certificates; it says nothing about
    // whether this raw host key is legitimate.
    const result = look(`@cert-authority *.example.com ssh-rsa ${b64(KEY_A)}`, 'web.example.com', 22, KEY_A)
    expect(result.trusted).toBe(false)
    expect(result.knownUnderAnotherKey).toBe(false)
  })

  it('finds nothing for a host that is genuinely absent', () => {
    const result = look(`other.com ssh-rsa ${b64(KEY_A)}`, 'example.com', 22, KEY_A)
    expect(result).toEqual({ trusted: false, knownUnderAnotherKey: false, revoked: false })
  })
})
