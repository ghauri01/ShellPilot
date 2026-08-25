import { describe, it, expect } from 'vitest'
import { redactOutput, redactKnownSecrets, redactPatterns } from '../src/main/services/secretRedaction'

describe('secret redaction', () => {
  it('redacts a known secret value verbatim', () => {
    const out = redactKnownSecrets('the password is hunter2 today', ['hunter2'])
    expect(out).not.toContain('hunter2')
    expect(out).toContain('[REDACTED]')
  })

  it('redacts KEY=value style env assignments', () => {
    const out = redactPatterns('DB_PASSWORD=abc123\nOTHER=fine')
    expect(out).toContain('DB_PASSWORD=[REDACTED]')
    expect(out).toContain('OTHER=fine')
  })

  it('redacts a full PEM private key block', () => {
    const pem = '-----BEGIN OPENSSH PRIVATE KEY-----\nabcdef\n-----END OPENSSH PRIVATE KEY-----'
    const out = redactPatterns(`before\n${pem}\nafter`)
    expect(out).not.toContain('abcdef')
    expect(out).toContain('before')
    expect(out).toContain('after')
  })

  it('redacts a bearer token', () => {
    const out = redactPatterns('Authorization: Bearer abcd1234efgh5678')
    expect(out).not.toContain('abcd1234efgh5678')
  })

  it('redacts a password embedded in a connection URI', () => {
    const out = redactPatterns('postgres://admin:s3cret@db.internal:5432/app')
    expect(out).not.toContain('s3cret')
    expect(out).toContain('admin')
    expect(out).toContain('db.internal')
  })

  it('leaves ordinary output untouched', () => {
    const text = 'total 12\ndrwxr-xr-x 2 root root 4096 Jan 1 00:00 var'
    expect(redactOutput(text)).toBe(text)
  })

  it('never logs the actual secret when both layers are combined', () => {
    const out = redactOutput('DB_PASSWORD=hunter2', ['hunter2'])
    expect(out).not.toContain('hunter2')
  })
})
