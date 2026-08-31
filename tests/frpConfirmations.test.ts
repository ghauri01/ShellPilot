import { describe, expect, it } from 'vitest'
import type { FrpSpec } from '../src/shared/vpn'
import { validateFrpSpec } from '../src/main/services/vpn/frpConfig'

// Four legitimate frp configurations used to be permanently unsavable.
//
// `validateFrpSpec` raises a blocking error for each of them unless a
// confirmation is passed — and nothing ever passed one. The IPC handler called
// `validateFrpSpec(spec)`, the form had no control that could set a
// confirmation, and the default was `{}`. So turning off "Encrypt the control
// connection with TLS" made the profile unsavable forever, with "1 problem to
// fix" as the only explanation and no field to fix it on.
//
// The fix stores the confirmations on the spec, which is what makes validation
// give the *same* answer in the form and at start time. A confirmation held
// only in the form's local state would have let Save succeed and then made
// Start refuse forever, which is a worse bug than the one being fixed.

function frp(over: Partial<FrpSpec> = {}): FrpSpec {
  return {
    kind: 'frp',
    serverAddr: 'frp.example.com',
    serverPort: 7000,
    auth: { method: 'token', tokenRef: { vaultEntryId: 'v1', field: 'token' } },
    transport: { protocol: 'tcp', tlsEnable: true },
    proxies: [],
    visitors: [],
    ...over
  }
}

const errorCodes = (spec: FrpSpec): string[] =>
  validateFrpSpec(spec).issues.filter((i) => i.severity === 'error').map((i) => i.code)

const proxy = (over: Record<string, unknown> = {}): never =>
  ({
    name: 'postgres',
    type: 'tcp',
    localIp: '127.0.0.1',
    localPort: 5432,
    remotePort: 15432,
    acknowledgedExposure: true,
    ...over
  }) as never

describe('a confirmation stored on the spec unblocks validation', () => {
  it('plaintext transport', () => {
    const off = frp({ transport: { protocol: 'tcp', tlsEnable: false } })
    expect(errorCodes(off)).toContain('tls-disabled')

    const confirmed = frp({
      transport: { protocol: 'tcp', tlsEnable: false },
      confirmations: { allowPlaintextTransport: true }
    })
    expect(errorCodes(confirmed)).not.toContain('tls-disabled')
    expect(validateFrpSpec(confirmed).ok).toBe(true)
  })

  it('a non-loopback local address', () => {
    const lan = frp({ proxies: [proxy({ localIp: '192.168.1.50' })] })
    expect(errorCodes(lan)).toContain('local-ip-not-loopback')

    const confirmed = frp({
      proxies: [proxy({ localIp: '192.168.1.50' })],
      confirmations: { allowNonLoopbackLocalIp: true }
    })
    expect(errorCodes(confirmed)).not.toContain('local-ip-not-loopback')
  })

  it('a proxy plugin', () => {
    const withPlugin = frp({ proxies: [proxy({ plugin: { name: 'socks5' } })] })
    const codes = errorCodes(withPlugin)
    expect(codes.length).toBeGreaterThan(0)

    const confirmed = frp({
      proxies: [proxy({ plugin: { name: 'socks5' } })],
      confirmations: { allowProxyPlugins: true }
    })
    expect(errorCodes(confirmed).length).toBeLessThan(codes.length)
  })
})

describe('an explicit argument still wins over the spec', () => {
  it('so the form can preview a confirmation before storing it', () => {
    const off = frp({ transport: { protocol: 'tcp', tlsEnable: false } })
    expect(errorCodes(off)).toContain('tls-disabled')
    const previewed = validateFrpSpec(off, { allowPlaintextTransport: true })
    expect(previewed.issues.filter((i) => i.severity === 'error').map((i) => i.code)).not.toContain(
      'tls-disabled'
    )
  })
})

describe('confirmations do not weaken the per-proxy exposure gate', () => {
  it('acknowledgedExposure is still required', () => {
    // The four confirmations are profile-wide. Whether one specific port
    // becomes reachable is a different question, asked once per proxy, and no
    // profile-level tick may answer it.
    const spec = frp({
      proxies: [proxy({ acknowledgedExposure: false })],
      confirmations: {
        allowPlaintextTransport: true,
        allowNonLoopbackLocalIp: true,
        allowProxyPlugins: true,
        allowNonLoopbackBindAddr: true
      }
    })
    expect(validateFrpSpec(spec).ok).toBe(false)
  })
})
