import { describe, expect, it } from 'vitest'
import {
  buildPublishedProxy,
  delegationRecord,
  describeExposure,
  frpPublishReadiness,
  isDelegatableDomain,
  publicHostFrom,
  publicUrl,
  publishLabel,
  toLabel,
  tunnelHostProfile
} from '../src/shared/frpTunnel'
import type { FrpPublicHost, FrpSpec, VpnProfile } from '../src/shared/vpn'
import { validateFrpSpec } from '../src/main/services/vpn/frpConfig'

// The arithmetic behind "give me a public URL for localhost:3000".
//
// The defect class this whole file is aimed at is a URL that looks like ngrok's
// and is not: an address ShellPilot composed for itself, shown with a Copy
// button, that resolves to nothing because nobody ever created a DNS record.
// So the assertions below are mostly about what does NOT come out — no URL
// without a domain, no ticked exposure box, no scheme invented on the user's
// behalf.

const host = (over: Partial<FrpPublicHost> = {}): FrpPublicHost => ({
  baseDomain: 'tunnel.example.com',
  scheme: 'https',
  confirmedAt: 1_700_000_000_000,
  ...over
})

const spec = (over: Partial<FrpSpec> = {}): FrpSpec => ({
  kind: 'frp',
  serverAddr: 'frp.example.com',
  serverPort: 7000,
  auth: { method: 'token', tokenRef: { vaultEntryId: 'v1', field: 'token' } },
  transport: { protocol: 'tcp', tlsEnable: true },
  proxies: [],
  visitors: [],
  ...over
})

const profile = (over: Partial<FrpSpec> = {}, name = 'Tunnel server'): VpnProfile => ({
  id: 'vpn-1',
  workspaceId: 'ws-1',
  name,
  autoStart: false,
  spec: spec(over)
})

describe('there is no public URL without a domain the operator owns', () => {
  it('refuses, and names what the operator has to own', () => {
    const readiness = frpPublishReadiness([])
    expect(readiness.ready).toBe(false)
    if (readiness.ready) throw new Error('unreachable')
    expect(readiness.gaps.map((g) => g.code)).toEqual(['no-host'])
    expect(readiness.gaps[0].message).toBe(
      'A public URL needs an frp server you control, with a domain pointed at it. ' +
        'Set that up once and this stops being a question.'
    )
  })

  it('carries no address at all in the refusal', () => {
    // The failure mode is not "the URL is wrong", it is "there is a URL". An
    // address assembled out of the frp server's own hostname would look
    // entirely plausible and would resolve to nothing.
    const withServerButNoDomain: VpnProfile = {
      ...profile(),
      spec: spec({ publicHost: { baseDomain: '', scheme: 'https', confirmedAt: 1 } })
    }
    const readiness = frpPublishReadiness([withServerButNoDomain])
    // Asserted on the whole result rather than on a named field, and before
    // `ready`, so a fabricated address is legible in the failure message
    // itself rather than reported as a boolean that came out wrong.
    expect(JSON.stringify(readiness)).not.toContain('://')
    expect(JSON.stringify(readiness)).not.toContain('frp.example.com')
    expect(readiness.ready).toBe(false)
  })

  it('refuses a server that has a domain but nowhere for it to resolve to', () => {
    const noServer = {
      ...profile({ serverAddr: '', publicHost: host() }),
      name: 'Tunnel server'
    }
    const readiness = frpPublishReadiness([noServer])
    expect(readiness.ready).toBe(false)
    if (readiness.ready) throw new Error('unreachable')
    expect(readiness.gaps.map((g) => g.code)).toEqual(['no-server'])
    expect(readiness.gaps[0].message).toBe(
      '"Tunnel server" has no frp server address, so there is nothing for that name to resolve to.'
    )
  })

  it('an unconfirmed public server is not a server', () => {
    // A profile could carry a half-filled `publicHost` from a future edit path.
    // Only the operator's confirmation makes it usable, so `confirmedAt: 0`
    // sends the user back to the setup rather than into a publish.
    const unconfirmed = profile({ publicHost: host({ confirmedAt: 0 }) })
    expect(tunnelHostProfile([unconfirmed])).toBe(null)
    expect(frpPublishReadiness([unconfirmed]).ready).toBe(false)
  })
})

describe('once the domain exists, the URL is derived from it', () => {
  it('is ready, and points at the operator’s own domain', () => {
    const readiness = frpPublishReadiness([profile({ publicHost: host() })])
    expect(readiness.ready).toBe(true)
    if (!readiness.ready) throw new Error('unreachable')
    expect(readiness.target.host.baseDomain).toBe('tunnel.example.com')
    expect(publicUrl(readiness.target.host, 'port-3000')).toBe(
      'https://port-3000.tunnel.example.com'
    )
  })

  it('carries a non-default port and leaves out a default one', () => {
    expect(publicUrl(host({ scheme: 'http', port: 8080 }), 'api')).toBe(
      'http://api.tunnel.example.com:8080'
    )
    expect(publicUrl(host({ scheme: 'http', port: 80 }), 'api')).toBe('http://api.tunnel.example.com')
    expect(publicUrl(host({ scheme: 'https', port: 443 }), 'api')).toBe(
      'https://api.tunnel.example.com'
    )
  })

  it('skips the frp profiles that are not tunnel servers', () => {
    const plain = { ...profile({}, 'Imported frpc'), id: 'vpn-plain' }
    const configured = { ...profile({ publicHost: host() }, 'Tunnel server'), id: 'vpn-host' }
    expect(tunnelHostProfile([plain, configured])?.id).toBe('vpn-host')
  })
})

describe('naming a published service', () => {
  it('falls back to the port when nothing was typed', () => {
    expect(publishLabel('', 3000, [])).toBe('port-3000')
  })

  it('slugifies what was typed', () => {
    expect(toLabel('My Staging API')).toBe('my-staging-api')
    expect(toLabel('  --Weird__name!!  ')).toBe('weird-name')
  })

  it('does not reuse a label another proxy already has', () => {
    // Two proxies with the same name is an frp error and two identical URLs is
    // a user-facing one; the label is both, so it is de-duplicated once.
    expect(publishLabel('api', 3000, ['api'])).toBe('api-2')
    expect(publishLabel('api', 3000, ['api', 'api-2'])).toBe('api-3')
  })
})

describe('the proxy a one-click publish builds', () => {
  it('does not tick the exposure box', () => {
    // The gate `FrpProxy.acknowledgedExposure` exists precisely so that
    // publishing a local port cannot be a side effect of a click that was
    // about something else. A builder that pre-ticked it would route around
    // the gate while leaving it in the type.
    const p = buildPublishedProxy('api', 3000)
    expect(p.acknowledgedExposure).toBe(false)
  })

  it('is an http proxy on loopback, routed by the label', () => {
    const p = buildPublishedProxy('api', 3000)
    expect(p.type).toBe('http')
    expect(p.localIp).toBe('127.0.0.1')
    expect(p.localPort).toBe(3000)
    expect(p.subdomain).toBe('api')
    expect(p.name).toBe('api')
  })

  it('is refused by the real validator until the box is ticked, and passes after', () => {
    // Binds the builder to the engine's own rules rather than to a second
    // opinion about them: this is the same validateFrpSpec that runs at start.
    const built = buildPublishedProxy('api', 3000)
    const before = validateFrpSpec(spec({ proxies: [built], publicHost: host() }))
    expect(before.ok).toBe(false)
    expect(before.issues.map((i) => i.code)).toContain('exposure-unacknowledged')

    const after = validateFrpSpec(
      spec({ proxies: [{ ...built, acknowledgedExposure: true }], publicHost: host() })
    )
    expect(after.issues.filter((i) => i.severity === 'error')).toEqual([])
    expect(after.ok).toBe(true)
  })
})

describe('what the user is shown before anything is published', () => {
  const exposure = describeExposure({
    host: host(),
    label: 'api',
    localPort: 3000,
    serverAddr: 'frp.example.com',
    serverPort: 7000
  })

  it('names the exact local address and the exact public one', () => {
    expect(exposure.local).toBe('127.0.0.1:3000')
    expect(exposure.url).toBe('https://api.tunnel.example.com')
    expect(exposure.sentence).toBe(
      'Anything answering on 127.0.0.1:3000 on this machine becomes reachable at https://api.tunnel.example.com.'
    )
  })

  it('says who can reach it', () => {
    expect(exposure.audience).toBe(
      'Anyone who has that address can reach it. Nothing asks them for a password first.'
    )
  })

  it('names the route rather than implying ShellPilot serves it', () => {
    expect(exposure.route).toBe(
      'Traffic arrives through frp.example.com:7000, the frp server you set up.'
    )
  })
})

describe('writing down what the setup learned', () => {
  it('stamps the confirmation and normalises the domain', () => {
    const h = publicHostFrom({ baseDomain: '  *.Tunnel.Example.com. ', scheme: 'https', now: 42 })
    expect(h.baseDomain).toBe('tunnel.example.com')
    expect(h.confirmedAt).toBe(42)
  })

  it('drops a port that is the scheme’s own default', () => {
    expect(publicHostFrom({ baseDomain: 'a.example.com', scheme: 'https', port: 443, now: 1 }).port).toBe(
      undefined
    )
    expect(publicHostFrom({ baseDomain: 'a.example.com', scheme: 'http', port: 8080, now: 1 }).port).toBe(
      8080
    )
  })

  it('spells out the one DNS record the operator has to create', () => {
    expect(delegationRecord('tunnel.example.com', 'frp.example.com')).toBe(
      '*.tunnel.example.com  →  frp.example.com'
    )
    expect(delegationRecord('*.tunnel.example.com', 'frp.example.com')).toBe(
      '*.tunnel.example.com  →  frp.example.com'
    )
  })

  it('checks the shape of a domain and nothing more', () => {
    expect(isDelegatableDomain('tunnel.example.com')).toBe(true)
    expect(isDelegatableDomain('*.tunnel.example.com')).toBe(true)
    expect(isDelegatableDomain('localhost')).toBe(false)
    expect(isDelegatableDomain('not a domain')).toBe(false)
    expect(isDelegatableDomain('')).toBe(false)
  })
})
