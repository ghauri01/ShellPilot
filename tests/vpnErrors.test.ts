import { describe, expect, it } from 'vitest'
import type { VpnErrorCode } from '../src/shared/vpn'
import {
  VPN_ERROR_HINT,
  VPN_ERROR_MESSAGE,
  VpnError,
  classifyEngineLine,
  describeVpnError,
  isVpnError,
  toVpnResult
} from '../src/main/services/vpn/errors'

// The list the app is allowed to produce. Kept here rather than derived from
// the maps under test, so a code added to the union with no message fails
// here instead of reaching a user as "undefined".
const ALL_CODES: VpnErrorCode[] = [
  'binary-missing',
  'binary-untrusted',
  'config-invalid',
  'config-rejected',
  'auth-failed',
  'auth-otp-required',
  'tls-handshake-failed',
  'cert-expired',
  'handshake-timeout',
  'dns-failure',
  'port-in-use',
  'permission-denied',
  'elevation-declined',
  'network-unreachable',
  'server-rejected',
  'crash-loop',
  'vault-locked',
  'proxy-required',
  'version-mismatch',
  'interface-conflict',
  'already-running',
  'clock-skew',
  'exposure-unacknowledged',
  'unsupported',
  'internal'
]

describe('message coverage', () => {
  it('every code has a message', () => {
    for (const c of ALL_CODES) {
      expect(VPN_ERROR_MESSAGE[c], `missing message for ${c}`).toBeTruthy()
    }
  })

  it('every code has a hint entry, even if deliberately empty', () => {
    for (const c of ALL_CODES) {
      expect(VPN_ERROR_HINT[c], `missing hint for ${c}`).toBeDefined()
    }
  })

  it('has no message or hint for a code that is not in the union', () => {
    expect(Object.keys(VPN_ERROR_MESSAGE).sort()).toEqual([...ALL_CODES].sort())
    expect(Object.keys(VPN_ERROR_HINT).sort()).toEqual([...ALL_CODES].sort())
  })

  it('writes messages as sentences, not enum names', () => {
    for (const c of ALL_CODES) {
      const m = VPN_ERROR_MESSAGE[c]
      expect(m, c).toMatch(/^[A-Z]/)
      expect(m, c).toMatch(/[.!]$/)
      // A message that just restates the code teaches the user nothing.
      expect(m.toLowerCase(), c).not.toContain(c)
    }
  })
})

describe('describeVpnError', () => {
  it('reads as what happened, then what to do', () => {
    const text = describeVpnError('port-in-use', 'Port 1080 on 127.0.0.1.')
    expect(text).toBe(
      'The local port is already in use. Port 1080 on 127.0.0.1. Choose another port, or leave it as 0 to pick one automatically.'
    )
  })

  it('omits an empty hint rather than leaving a double space', () => {
    const text = describeVpnError('already-running')
    expect(text).toBe('This tunnel is already running.')
    expect(text).not.toMatch(/ {2}/)
  })
})

describe('VpnError', () => {
  it('carries the code and the detail', () => {
    const e = new VpnError('handshake-timeout', 'vpn.example.com:51820')
    expect(isVpnError(e)).toBe(true)
    expect(e.code).toBe('handshake-timeout')
    expect(e.detail).toBe('vpn.example.com:51820')
    expect(e.message).toContain('vpn.example.com:51820')
  })

  it('preserves the cause', () => {
    const cause = new Error('ECONNREFUSED')
    const e = new VpnError('server-rejected', undefined, { cause })
    expect(e.cause).toBe(cause)
  })
})

describe('toVpnResult', () => {
  it('turns a VpnError into the full user-facing text plus its code', () => {
    const r = toVpnResult(new VpnError('vault-locked'))
    expect(r.ok).toBe(false)
    expect(r.errorCode).toBe('vault-locked')
    expect(r.error).toContain('Unlock the vault')
  })

  it('falls back to internal for an unknown throw', () => {
    expect(toVpnResult(new Error('boom'))).toEqual({
      ok: false,
      error: 'boom',
      errorCode: 'internal'
    })
  })

  it('handles a thrown non-Error', () => {
    const r = toVpnResult('just a string')
    expect(r.errorCode).toBe('internal')
    expect(r.error).toBe('just a string')
  })

  it('never returns an empty message', () => {
    expect(toVpnResult(new Error('')).error).toBeTruthy()
    expect(toVpnResult(undefined).error).toBeTruthy()
  })
})

describe('classifyEngineLine', () => {
  const cases: [string, VpnErrorCode][] = [
    ['AUTH_FAILED', 'auth-failed'],
    ["Verification Failed: 'Auth'", 'auth-failed'],
    ['VERIFY ERROR: depth=0, error=certificate has expired', 'cert-expired'],
    ['TLS key negotiation failed to occur within 60 seconds', 'tls-handshake-failed'],
    ['RESOLVE: Cannot resolve server address: vpn.example.com', 'dns-failure'],
    ['Network is unreachable', 'network-unreachable'],
    ['ERROR: Cannot ioctl TUNSETIFF tun0: Operation not permitted', 'permission-denied'],
    ['bind(): Address already in use', 'port-in-use'],
    ['authentication failed', 'auth-failed'],
    ['proxy name pg already exists', 'interface-conflict'],
    ['login to server failed: i/o timeout', 'server-rejected'],
    ['port already used', 'port-in-use'],
    ['failed to parse private key', 'config-invalid']
  ]

  for (const [line, code] of cases) {
    it(`maps ${JSON.stringify(line.slice(0, 40))} to ${code}`, () => {
      expect(classifyEngineLine(line)).toBe(code)
    })
  }

  it('separates a not-yet-valid certificate from an expired one', () => {
    // Both arrive as VERIFY ERROR and look alike, but they send the user to
    // different people: one needs a new certificate, the other needs their
    // clock fixed.
    expect(classifyEngineLine('VERIFY ERROR: certificate is not yet valid')).toBe('clock-skew')
    expect(classifyEngineLine('VERIFY ERROR: certificate has expired')).toBe('cert-expired')
  })

  it('returns null rather than guessing on an ordinary log line', () => {
    expect(classifyEngineLine('Initialization Sequence Completed')).toBeNull()
    expect(classifyEngineLine('')).toBeNull()
    expect(classifyEngineLine('start proxy success')).toBeNull()
  })

  it('only returns codes that have messages', () => {
    for (const [line] of cases) {
      const code = classifyEngineLine(line)
      expect(code && VPN_ERROR_MESSAGE[code]).toBeTruthy()
    }
  })
})
