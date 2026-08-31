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

// VPN engine output (E57). A key printed by wireguard-go, openvpn or frpc goes
// through this before it reaches the ring buffer, the audit log or an AI agent.
describe('VPN engine output', () => {
  it('redacts a WireGuard base64 key', () => {
    const out = redactPatterns('peer: yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=')
    expect(out).not.toContain('yAnz5TF')
    expect(out).toContain('[REDACTED]')
  })

  it('redacts a public key too, because nothing in the text says which it is', () => {
    // The deliberate trade: a redacted public key costs a support ticket, a
    // leaked private key costs the tunnel. The UI shows public keys from the
    // profile model, never scraped back out of a log.
    const out = redactPatterns('public_key xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg= endpoint')
    expect(out).not.toContain('xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=')
    expect(out).toContain('endpoint')
  })

  it('redacts the hex key form wireguard-go speaks on its UAPI socket', () => {
    const hex = 'a'.repeat(64)
    const out = redactPatterns(`private_key=${hex}\npreshared_key=${hex}\nfwmark=0`)
    expect(out).not.toContain(hex)
    expect(out).toContain('preshared_key=[REDACTED]')
    expect(out).toContain('fwmark=0')
  })

  it('redacts an OpenVPN static-challenge response, which carries the password', () => {
    const out = redactPatterns('sending SCRV1:aHVudGVyMg==:MTIzNDU2 to server')
    expect(out).not.toContain('aHVudGVyMg==')
    expect(out).toContain('sending')
    expect(out).toContain('to server')
  })

  it('redacts an frp token assignment whatever the value looks like', () => {
    const out = redactPatterns(
      'serverAddr = "vpn.example.com"\nauth.token = "s3cr3t-token"\n  secretKey = bare-value\n'
    )
    expect(out).not.toContain('s3cr3t-token')
    expect(out).not.toContain('bare-value')
    expect(out).toContain('vpn.example.com')
  })

  it('redacts the OpenVPN management password command it echoes back', () => {
    const out = redactPatterns('MANAGEMENT: CMD \'password "Auth" "hunter2"\'')
    expect(out).not.toContain('hunter2')
    expect(out).toContain('password "Auth" "[REDACTED]"')
  })

  it('does not eat ordinary base64-looking output', () => {
    // The key rules have to be narrow enough that a log full of hashes, digests
    // and encoded blobs stays readable, or people turn the log drawer off.
    const text = [
      'SGVsbG8gd29ybGQsIHRoaXMgaXMgb3JkaW5hcnkgb3V0cHV0IHRoYXQgaGFwcGVucyB0byBiZSBiYXNlNjQgZW5jb2RlZC4=',
      'dGhpcyBpcyBub3QgYSBrZXk=',
      'sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
      'allowed_ips=10.0.0.0/24 latest_handshake=1735689600'
    ].join('\n')
    expect(redactOutput(text)).toBe(text)
  })

  it('blanks every resolved literal handed to it, not just the recognisable ones', () => {
    // What ResolvedVpnSecrets.all is for: an frp token has no shape at all, so
    // only knowing the value catches it.
    const out = redactOutput('login to server failed: token=abc-123-not-a-shape', [
      'abc-123-not-a-shape'
    ])
    expect(out).not.toContain('abc-123-not-a-shape')
  })
})
