import { describe, it, expect } from 'vitest'
import {
  degradedReason,
  frpSummary,
  proxyCount
} from '../src/renderer/src/components/vpn/VpnStatusCard'
import type { FrpSpec, VpnStatus } from '../src/shared/vpn'

// The sentences the VPN pane and the VPN sidebar put in front of the user.
// They are covered here rather than through the components because there is no
// DOM in this suite — and because the defects these cover were all in the
// strings rather than in the rendering.

const spec = (over: Partial<FrpSpec> = {}): FrpSpec => ({
  kind: 'frp',
  serverAddr: 'frp.example.com',
  serverPort: 7000,
  auth: { method: 'token' },
  transport: { protocol: 'tcp', tlsEnable: true },
  proxies: [],
  visitors: [],
  ...over
})

const proxy = (name: string): FrpSpec['proxies'][number] => ({
  name,
  type: 'tcp',
  localIp: '127.0.0.1',
  localPort: 8080
})

const status = (over: Partial<VpnStatus> = {}): VpnStatus => ({
  id: 'vpn-1',
  kind: 'frp',
  state: 'connected',
  restarts: 0,
  ...over
})

describe('counting proxies', () => {
  it('says "1 proxy", not "1 proxies"', () => {
    expect(proxyCount(1)).toBe('1 proxy')
  })

  it('pluralises everything else', () => {
    expect(proxyCount(0)).toBe('0 proxies')
    expect(proxyCount(3)).toBe('3 proxies')
  })
})

describe('summarising an frp client', () => {
  it('names the server it dials and what it carries', () => {
    expect(frpSummary(spec({ proxies: [proxy('web')] }))).toBe('frp.example.com:7000 · 1 proxy')
  })

  it('does not render a bare port for a profile with no server address', () => {
    // ":7000 · 0 proxies" reads as a field the app failed to load rather than
    // one nobody has filled in yet.
    const s = frpSummary(spec({ serverAddr: '' }))
    expect(s).toBe('no server yet · 0 proxies')
    expect(s.startsWith(':')).toBe(false)
  })
})

describe('explaining an amber profile', () => {
  it('explains a reconnecting profile of any kind', () => {
    expect(degradedReason('frp', status({ state: 'reconnecting' }))).toBe(
      'Lost the connection to the server; retrying.'
    )
    expect(degradedReason('wireguard', status({ state: 'reconnecting' }))).toBe(
      'Lost the connection to the server; retrying.'
    )
  })

  it('points a degraded frp client at the proxy table', () => {
    // This one used to render as a bare amber chip with nothing beside it.
    expect(degradedReason('frp', status({ state: 'degraded' }))).toContain('proxy failed to start')
  })

  it('still explains a WireGuard tunnel with a stale handshake', () => {
    const reason = degradedReason(
      'wireguard',
      status({ kind: 'wireguard', state: 'connected', stats: { rxBytes: 0, txBytes: 0 } })
    )
    expect(reason).toContain('nothing is crossing it')
  })
})
