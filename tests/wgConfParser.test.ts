import { describe, it, expect } from 'vitest'
import { existsSync, readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { join } from 'node:path'
import { parseWgConf, WG_REJECT_RULES } from '../src/main/services/vpn/parsers/wgConf'
import type { VpnImportResultInternal, WireGuardSpec } from '../src/shared/vpn'

// A wg-quick .conf is executable content: PreUp/PostUp/PreDown/PostDown are
// shell commands run as root. These assert the parser treats the file as
// hostile input and produces a typed model, never a passthrough.

const DIR = fileURLToPath(new URL('./fixtures/wgconf', import.meta.url))

const load = (name: string): string => readFileSync(join(DIR, name), 'utf8')
const parse = (name: string, hostHasIpv6 = false): VpnImportResultInternal =>
  parseWgConf(load(name), { hostHasIpv6 })
const wg = (r: VpnImportResultInternal): WireGuardSpec => r.spec as WireGuardSpec

describe('wg-quick shell hooks are a whole-import failure', () => {
  // The allowlist and its fixtures must not drift apart, so the table is the
  // exported rule list rather than a copy of it.
  it.each(WG_REJECT_RULES.map((r) => [r.id, r] as const))('rejects %s', (id, rule) => {
    const file = `reject-${id}.conf`
    expect(existsSync(join(DIR, file)), `missing fixture ${file}`).toBe(true)

    const result = parse(file)
    expect(result.ok).toBe(false)
    expect(result.errorCode).toBe('config-rejected')
    expect(result.spec).toBeUndefined()
    expect(result.secrets).toBeUndefined()

    // The offending line is quoted, so the user can see what they were sent.
    const offending = load(file)
      .split('\n')
      .find((l) => l.toLowerCase().startsWith(rule.key))
    expect(result.error).toContain(offending?.trim())

    const entry = result.stripped.find((s) => s.severity === 'rejected')
    expect(entry).toBeDefined()
    expect(entry?.directive).toBe(rule.key)
    expect(entry?.reason).toBe(rule.reason)
  })

  it('never reports a rejection as an empty strip list', () => {
    for (const rule of WG_REJECT_RULES) {
      expect(parse(`reject-${rule.id}.conf`).stripped.length).toBeGreaterThan(0)
    }
  })
})

describe('a plain profile', () => {
  it('produces a userspace spec with the key held apart from it', () => {
    const r = parse('ok-minimal.conf')
    expect(r.ok).toBe(true)
    const spec = wg(r)
    expect(spec.kind).toBe('wireguard')
    expect(spec.mode).toBe('userspace')
    expect(spec.addresses).toEqual(['10.0.0.2/32'])
    expect(spec.peers).toHaveLength(1)
    expect(spec.peers[0].endpoint).toBe('vpn.example.com:51820')
    expect(spec.peers[0].allowedIps).toEqual(['10.0.0.0/24'])
    expect(r.name).toBe('vpn.example.com')

    // The private key travels in `secrets`, never on the spec: profiles are
    // persisted as plain JSON.
    expect(r.secrets?.privateKey).toBeTruthy()
    expect(JSON.stringify(spec)).not.toContain(r.secrets?.privateKey as string)
    expect(spec.privateKeyRef.field).toBe('privateKey')
    expect(spec.privateKeyRef.vaultEntryId).toBe('')
  })

  it('carries addresses, DNS, MTU, preshared keys and keepalive', () => {
    const r = parse('ok-full.conf')
    expect(r.ok).toBe(true)
    const spec = wg(r)
    expect(spec.addresses).toEqual(['10.0.0.2/32', 'fd00::2/128'])
    expect(spec.dns).toEqual(['10.0.0.1', 'fd00::1', 'corp.example.com'])
    expect(spec.mtu).toBe(1420)
    expect(spec.peers[0].persistentKeepalive).toBe(25)

    const pub = spec.peers[0].publicKey
    expect(spec.peers[0].presharedKeyRef).toEqual({
      vaultEntryId: '',
      field: 'presharedKey',
      fieldKey: pub
    })
    expect(r.secrets?.presharedKeys?.[pub]).toBeTruthy()
    expect(JSON.stringify(spec)).not.toContain(r.secrets?.presharedKeys?.[pub] as string)
  })

  it('reads more than one [Peer], including an IPv6 endpoint', () => {
    const spec = wg(parse('ok-multipeer.conf'))
    expect(spec.peers).toHaveLength(2)
    expect(spec.peers[1].endpoint).toBe('[2001:db8::1]:51820')
    // `PersistentKeepalive = off` is zero, and zero means absent.
    expect(spec.peers[1].persistentKeepalive).toBeUndefined()
  })

  it('survives CRLF, trailing whitespace, comments and a bare address', () => {
    const r = parse('ok-crlf.conf')
    expect(r.ok).toBe(true)
    const spec = wg(r)
    // `Address = 10.0.0.2` with no prefix means /32, as wg-quick reads it.
    expect(spec.addresses).toEqual(['10.0.0.2/32'])
    expect(spec.peers[0].endpoint).toBe('vpn.example.com:51820')
  })
})

describe('what is reported rather than swallowed', () => {
  it('names every setting it understands but cannot model', () => {
    const r = parse('edge-unmodelled.conf')
    expect(r.ok).toBe(true)
    const dropped = r.stripped.map((s) => s.directive)
    expect(dropped).toContain('listenport')
    expect(dropped).toContain('table')
    expect(dropped).toContain('saveconfig')
    expect(dropped).toContain('fwmark')
    for (const s of r.stripped) {
      expect(s.severity).toBe('removed')
      expect(s.reason.length).toBeGreaterThan(0)
    }
    // The report survives onto the spec so the UI can show it again later.
    expect(wg(r).strippedDirectives).toEqual(r.stripped)
  })

  it('warns on a duplicate key and keeps the last value', () => {
    const r = parse('edge-duplicate-keys.conf')
    expect(r.ok).toBe(true)
    expect(wg(r).addresses).toEqual(['10.0.0.2/32'])
    expect(wg(r).peers[0].endpoint).toBe('vpn.example.com:51820')
    expect(r.warnings.join(' ')).toContain('set more than once')
    expect(r.warnings.join(' ')).toContain('10.0.0.9/32')
  })
})

describe('warnings the user needs before connecting', () => {
  it('says so when a v4-only profile runs on a v6 server (E16)', () => {
    expect(parse('ok-minimal.conf', true).warnings).toContain(
      'This profile does not carry IPv6. IPv6 traffic will bypass it.'
    )
    // A dual-stack profile has nothing to warn about.
    expect(parse('ok-full.conf', true).warnings.join(' ')).not.toContain('does not carry IPv6')
  })

  it('explains that 0.0.0.0/0 does not mean "all traffic" in userspace mode (E17)', () => {
    expect(parse('ok-full.conf').warnings.join(' ')).toContain('changes no system routes')
    expect(parse('ok-minimal.conf').warnings.join(' ')).not.toContain('changes no system routes')
  })
})

describe('malformed files', () => {
  it.each([
    ['bad-missing-interface.conf', 'no [Interface]'],
    ['bad-no-peer.conf', 'no [Peer]'],
    ['bad-base64.conf', 'base64'],
    ['bad-endpoint.conf', 'host:port'],
    ['bad-no-endpoint.conf', 'no Endpoint']
  ])('%s fails with config-invalid', (file, needle) => {
    const r = parse(file)
    expect(r.ok).toBe(false)
    expect(r.errorCode).toBe('config-invalid')
    expect(r.error).toContain(needle)
  })

  it('refuses a setting that appears before any section', () => {
    const r = parseWgConf('PrivateKey = x\n', { hostHasIpv6: false })
    expect(r.ok).toBe(false)
    expect(r.errorCode).toBe('config-invalid')
  })

  it('refuses a second [Interface]', () => {
    const r = parseWgConf('[Interface]\n[Interface]\n', { hostHasIpv6: false })
    expect(r.ok).toBe(false)
    expect(r.error).toContain('second [Interface]')
  })
})
