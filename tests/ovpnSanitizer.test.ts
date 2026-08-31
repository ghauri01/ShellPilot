import { describe, it, expect, beforeAll, afterAll } from 'vitest'
import { existsSync, mkdtempSync, mkdirSync, readFileSync, rmSync, symlinkSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { fileURLToPath } from 'node:url'
import { join } from 'node:path'
import {
  emitOvpnConfig,
  escapeOvpnValue,
  OVPN_PULL_FILTER_REJECTS,
  OVPN_REJECT_RULES,
  ovpnArgs,
  ovpnRejectRuleFor,
  parseOvpn
} from '../src/main/services/vpn/parsers/ovpn'
import type { OpenVpnSpec, VpnImportResultInternal } from '../src/shared/vpn'

// A .ovpn file is executable content. Everything here is a statement about what
// the sanitizer refuses, what it drops, and what the config *we generate*
// contains — never about passing the user's bytes through.

const DIR = fileURLToPath(new URL('./fixtures/ovpn', import.meta.url))

const load = (name: string): string => readFileSync(join(DIR, name), 'utf8')
const parse = (name: string, hostHasIpv6 = false): VpnImportResultInternal =>
  parseOvpn(load(name), DIR, { hostHasIpv6 })
const ovpn = (r: VpnImportResultInternal): OpenVpnSpec => r.spec as OpenVpnSpec
const body = (r: VpnImportResultInternal): string => r.secrets?.configBody ?? ''

describe('the hard-reject list', () => {
  // The list and its fixtures must not drift apart, so the table is the
  // exported rule list itself.
  it.each(OVPN_REJECT_RULES.map((r) => [r.id, r] as const))('has a fixture for %s and fails the whole import', (id, rule) => {
    const file = `reject-${id}.ovpn`
    expect(existsSync(join(DIR, file)), `missing fixture ${file}`).toBe(true)

    const result = parse(file)
    expect(result.ok, `${file} was not rejected`).toBe(false)
    expect(result.errorCode).toBe('config-rejected')
    // A rejected import yields nothing usable: no spec, and no key material.
    expect(result.spec).toBeUndefined()
    expect(result.secrets).toBeUndefined()
    // The offending line is quoted so the user learns what they were handed.
    expect(result.error).toMatch(/Line \d+: /)
    expect(result.error).toContain(rule.reason)

    const entry = result.stripped.find((s) => s.severity === 'rejected')
    expect(entry, `${file} reported no rejected directive`).toBeDefined()
    expect(entry?.reason).toBe(rule.reason)
  })

  it('never reports a rejection with an empty strip list', () => {
    for (const rule of OVPN_REJECT_RULES) {
      expect(parse(`reject-${rule.id}.ovpn`).stripped.length).toBeGreaterThan(0)
    }
  })

  it('matches on the normalised name, so casing and `--` are not a way past it', () => {
    expect(ovpnRejectRuleFor('--UP')?.id).toBe('up')
    expect(ovpnRejectRuleFor('Script-Security')?.id).toBe('script-security')
    for (const file of ['hostile-double-dash.ovpn', 'hostile-uppercase.ovpn']) {
      const r = parse(file)
      expect(r.ok, file).toBe(false)
      expect(r.errorCode).toBe('config-rejected')
    }
  })

  it('catches the whole management family by prefix', () => {
    expect(ovpnRejectRuleFor('management-external-key')?.id).toBe('management')
    expect(ovpnRejectRuleFor('management-client-auth')?.id).toBe('management')
    expect(parse('hostile-management-external-key.ovpn').errorCode).toBe('config-rejected')
  })

  it('rejects the file-writing variants as well as the base directive', () => {
    expect(parse('hostile-log-append.ovpn').errorCode).toBe('config-rejected')
    expect(parse('hostile-status-version.ovpn').errorCode).toBe('config-rejected')
  })

  it('does not let a split certificate block hide a directive between halves', () => {
    // `</ca>` closes the block, so anything after it is parsed as a directive
    // rather than swallowed as key material.
    const r = parse('hostile-forged-close-tag.ovpn')
    expect(r.ok).toBe(false)
    expect(r.stripped.find((s) => s.severity === 'rejected')?.directive).toBe('up')
  })
})

describe('path traversal (E37)', () => {
  it('refuses an absolute path', () => {
    const r = parse('hostile-path-absolute.ovpn')
    expect(r.ok).toBe(false)
    expect(r.errorCode).toBe('config-rejected')
    expect(r.stripped.find((s) => s.severity === 'rejected')?.directive).toBe('ca')
  })

  it('refuses `..`, at the start or buried mid-path', () => {
    expect(parse('reject-path-escape.ovpn').errorCode).toBe('config-rejected')
    expect(parse('hostile-path-nested-traversal.ovpn').errorCode).toBe('config-rejected')
  })

  it('refuses a symlink that leaves the import folder', () => {
    const tmp = mkdtempSync(join(tmpdir(), 'shellpilot-ovpn-'))
    try {
      const base = join(tmp, 'profile')
      mkdirSync(base)
      writeFileSync(join(tmp, 'outside.crt'), '-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n')
      // The path in the config has no `..` in it at all — only realpath knows.
      symlinkSync(join(tmp, 'outside.crt'), join(base, 'ca.crt'))
      const r = parseOvpn('client\ndev tun\nremote vpn.example.com 1194\nca ca.crt\n', base, {
        hostHasIpv6: false
      })
      expect(r.ok).toBe(false)
      expect(r.errorCode).toBe('config-rejected')
      expect(r.error).toContain('outside the folder')
    } finally {
      rmSync(tmp, { recursive: true, force: true })
    }
  })

  it('refuses a path form at all when there is no import folder to contain it', () => {
    const r = parseOvpn('client\ndev tun\nremote vpn.example.com 1194\nca ca.crt\n', undefined, {
      hostHasIpv6: false
    })
    expect(r.ok).toBe(false)
    expect(r.errorCode).toBe('config-rejected')
  })

  it('reads key material that stays inside the folder, and inlines it', () => {
    const r = parse('ok-pathform.ovpn')
    expect(r.ok).toBe(true)
    const config = body(r)
    for (const tag of ['ca', 'cert', 'key', 'tls-auth']) {
      expect(config).toContain(`<${tag}>`)
      expect(config).toContain(`</${tag}>`)
    }
    // The emitted config never names a path.
    expect(config).not.toContain('certs/')
    // `tls-auth <file> <direction>` carries the direction across.
    expect(config).toContain('key-direction 1')
  })

  it('fails clearly when a contained file simply is not there', () => {
    const r = parse('bad-missing-file.ovpn')
    expect(r.ok).toBe(false)
    expect(r.errorCode).toBe('config-invalid')
    expect(r.error).toContain('was not found')
  })
})

describe('quote and escape safety', () => {
  it('rejects a value carrying a quote, however it was written', () => {
    expect(parse('reject-quote-injection.ovpn').errorCode).toBe('config-rejected')
    const r = parseOvpn('client\ndev tun\nremote a.example.com 1194\ncipher "AES\\\\256"\n', DIR, {
      hostHasIpv6: false
    })
    expect(r.ok).toBe(false)
    expect(r.error).toContain('backslash')
  })

  it('quotes on the way out only what needs it', () => {
    expect(escapeOvpnValue('AES-256-GCM')).toBe('AES-256-GCM')
    expect(escapeOvpnValue('C=GB, CN=server')).toBe('"C=GB, CN=server"')
    expect(escapeOvpnValue('')).toBe('""')
  })

  it('round-trips a quoted value through the generated config unchanged', () => {
    const config = body(parse('ok-full-inline.ovpn'))
    expect(config).toContain('verify-x509-name "C=GB, O=Example, CN=server" subject')
    expect(config).toContain('static-challenge "Enter your 6-digit code" 1')
  })
})

describe('a benign profile passes through cleanly', () => {
  it('re-emits a minimal config we generated', () => {
    const r = parse('ok-minimal.ovpn')
    expect(r.ok).toBe(true)
    const config = body(r)
    expect(config.startsWith('# Generated by ShellPilot')).toBe(true)
    for (const line of ['client', 'dev tun', 'proto udp', 'remote vpn.example.com 1194', 'nobind', 'verb 3']) {
      expect(config).toContain(line)
    }
    expect(ovpn(r).authMode).toBe('none')
    expect(ovpn(r).remotes).toEqual([{ host: 'vpn.example.com', port: 1194, proto: 'udp' }])
    expect(r.name).toBe('vpn.example.com')
    // The config body is a secret, not part of the persisted profile.
    expect(JSON.stringify(r.spec)).not.toContain('BEGIN CERTIFICATE')
    expect(ovpn(r).configRef).toEqual({ vaultEntryId: '', field: 'configBody' })
  })

  it('handles CRLF, trailing whitespace and both comment characters', () => {
    const r = parse('ok-crlf.ovpn')
    expect(r.ok).toBe(true)
    expect(body(r)).toContain('remote vpn.example.com 1194')
    expect(body(r)).not.toContain('\r')
  })

  it('accepts `ca [inline]` beside a real inline block', () => {
    const r = parse('ok-inline-marker.ovpn')
    expect(r.ok).toBe(true)
    expect(body(r)).toContain('<ca>')
  })

  it('accepts a pkcs12-only profile', () => {
    const r = parse('ok-pkcs12.ovpn')
    expect(r.ok).toBe(true)
    expect(body(r)).toContain('<pkcs12>')
  })

  it('carries proxy settings but only in their keyword form', () => {
    const config = body(parse('ok-proxied.ovpn'))
    expect(config).toContain('http-proxy corp-proxy.example.com 3128 auto basic')
    expect(config).toContain('socks-proxy socks.example.com 1080 auto')
  })
})

describe('a full real-world profile', () => {
  const r = parse('ok-full-inline.ovpn')
  const config = body(r)
  const dropped = (name: string): string | undefined =>
    r.stripped.find((s) => s.directive === name && s.severity === 'removed')?.reason

  it('imports', () => {
    expect(r.ok).toBe(true)
    expect(r.stripped.every((s) => s.severity === 'removed')).toBe(true)
  })

  it('clamps a hostile log level (E59)', () => {
    expect(config).toContain('verb 4')
    expect(config).not.toContain('verb 11')
    expect(dropped('verb')).toContain('clamped to 4')
  })

  it('drops compression, and says why', () => {
    expect(config).not.toContain('comp-lzo')
    expect(dropped('comp-lzo')).toContain('VORACLE')
  })

  it('drops the noise flags', () => {
    for (const name of ['mute', 'nice', 'fast-io']) expect(dropped(name)).toBeTruthy()
  })

  it('reports anything it does not recognise instead of swallowing it', () => {
    expect(dropped('nonsense-directive')).toBe('Not a setting ShellPilot carries over.')
    expect(config).not.toContain('nonsense-directive')
  })

  it('leaves redirect-gateway out of the body and off on the spec (E13)', () => {
    expect(config).not.toContain('redirect-gateway')
    expect(ovpn(r).redirectGateway).toBe(false)
    expect(dropped('redirect-gateway')).toContain('stays off until you turn it on')
    expect(r.warnings.join(' ')).toContain('all of your traffic through the VPN')
  })

  it('reads the auth mode and the static challenge off the file', () => {
    expect(ovpn(r).authMode).toBe('userpass-otp')
    expect(ovpn(r).staticChallenge).toEqual({ text: 'Enter your 6-digit code', echo: true })
  })

  it('keeps every remote, in order', () => {
    expect(ovpn(r).remotes).toEqual([
      { host: 'uk-london.vpn.example.com', port: 1194, proto: 'udp' },
      { host: 'uk-manchester.vpn.example.com', port: 1194, proto: 'udp' }
    ])
  })

  it('extracts every inline block into the config body once', () => {
    for (const tag of ['ca', 'cert', 'key', 'tls-auth']) {
      expect(config.split(`<${tag}>`).length - 1).toBe(1)
      expect(config.split(`</${tag}>`).length - 1).toBe(1)
    }
    expect(config).toContain('key-direction 1')
    expect(config.split('key-direction').length - 1).toBe(1)
  })

  it('carries only the allowlisted setenv names', () => {
    expect(config).toContain('setenv FORWARD_COMPATIBLE 1')
    expect(config).toContain('setenv UV_PLATFORM shellpilot')
  })

  it('gives every stripped entry a directive and a reason', () => {
    expect(r.stripped.length).toBeGreaterThan(0)
    for (const s of r.stripped) {
      expect(s.directive).toBeTruthy()
      expect(s.reason.length).toBeGreaterThan(0)
    }
    // Persisted, so the warning can be shown again later.
    expect(ovpn(r).strippedDirectives).toEqual(r.stripped)
  })
})

describe('import warnings', () => {
  it('warns about a v4-only profile on a v6 host (E16)', () => {
    expect(parse('ok-minimal.ovpn', true).warnings).toContain(
      'This profile does not carry IPv6. IPv6 traffic will bypass it.'
    )
    expect(parse('ok-ipv6.ovpn', true).warnings.join(' ')).not.toContain('does not carry IPv6')
    expect(parse('ok-minimal.ovpn', false).warnings.join(' ')).not.toContain('does not carry IPv6')
  })

  it('warns about TCP-over-TCP (E62)', () => {
    expect(parse('ok-tcp.ovpn').warnings).toContain(
      'TCP mode is slower and can stall under loss. Use UDP unless the network blocks it.'
    )
    expect(parse('ok-minimal.ovpn').warnings.join(' ')).not.toContain('TCP mode is slower')
  })

  it('warns that an encrypted private key needs a passphrase', () => {
    expect(parse('ok-encrypted-key.ovpn').warnings.join(' ')).toContain('passphrase')
  })
})

describe('files that are not hostile, just unusable', () => {
  it.each([
    ['bad-no-ca.ovpn', 'config-invalid'],
    ['bad-no-remote.ovpn', 'config-invalid'],
    ['bad-unclosed-block.ovpn', 'config-invalid'],
    ['bad-tap.ovpn', 'unsupported']
  ])('%s fails with %s', (file, code) => {
    const r = parse(file)
    expect(r.ok).toBe(false)
    expect(r.errorCode).toBe(code)
  })
})

// ---------------------------------------------------------------- emission

const specFor = (redirectGateway: boolean): OpenVpnSpec => ({
  kind: 'openvpn',
  configRef: { vaultEntryId: 'v1', field: 'configBody' },
  authMode: 'none',
  redirectGateway
})

describe('emitOvpnConfig', () => {
  it('adds redirect-gateway only when the profile turns it on', () => {
    const config = body(parse('ok-minimal.ovpn'))
    expect(emitOvpnConfig(specFor(false), config)).not.toContain('redirect-gateway')
    expect(emitOvpnConfig(specFor(true), config)).toContain('redirect-gateway def1')
  })

  it('re-checks the body, so a tampered vault entry never reaches openvpn', () => {
    const config = `${body(parse('ok-minimal.ovpn'))}up /tmp/pwn.sh\n`
    expect(() => emitOvpnConfig(specFor(false), config)).toThrowError(/runs a program/)
  })

  it('accepts every config the sanitizer produced', () => {
    for (const file of ['ok-minimal.ovpn', 'ok-full-inline.ovpn', 'ok-pathform.ovpn', 'ok-pkcs12.ovpn']) {
      const r = parse(file)
      expect(() => emitOvpnConfig(specFor(false), body(r)), file).not.toThrow()
    }
  })
})

describe('ovpnArgs', () => {
  const argsFor = (redirectGateway: boolean): string[] =>
    ovpnArgs(specFor(redirectGateway), {
      configPath: '/dev/stdin',
      management: { kind: 'unix', path: '/run/mgmt.sock' }
    })

  const pullFilters = (args: string[]): string[][] => {
    const out: string[][] = []
    for (let i = 0; i < args.length; i++) {
      if (args[i] === '--pull-filter') out.push([args[i + 1], args[i + 2]])
    }
    return out
  }

  it('always refuses the pushed equivalents of the reject list (E38)', () => {
    const args = argsFor(false)
    for (const f of OVPN_PULL_FILTER_REJECTS) {
      expect(pullFilters(args)).toContainEqual(['reject', f])
    }
    expect(args).toContain('--script-security')
    expect(args[args.indexOf('--script-security') + 1]).toBe('0')
    expect(args).toContain('--auth-nocache')
  })

  it('makes split tunnelling a fact rather than a claim (E13)', () => {
    const off = argsFor(false)
    expect(pullFilters(off)).toContainEqual(['ignore', 'redirect-gateway'])
    expect(off).toContain('--route-nopull')

    const on = argsFor(true)
    expect(pullFilters(on)).not.toContainEqual(['ignore', 'redirect-gateway'])
    expect(on).not.toContain('--route-nopull')
    // The reject list is unconditional either way.
    for (const f of OVPN_PULL_FILTER_REJECTS) expect(pullFilters(on)).toContainEqual(['reject', f])
  })

  it('has openvpn dial us, on a socket or a loopback port', () => {
    const unix = argsFor(false)
    expect(unix.join(' ')).toContain('--management /run/mgmt.sock unix')
    expect(unix).toContain('--management-client')
    expect(unix).toContain('--management-query-passwords')
    expect(unix).toContain('--management-hold')

    const tcp = ovpnArgs(specFor(false), {
      configPath: 'C:\\run\\p.ovpn',
      management: { kind: 'tcp', host: '127.0.0.1', port: 51234 }
    })
    expect(tcp.join(' ')).toContain('--management 127.0.0.1 51234')
    expect(tcp).toContain('--management-client')
  })

  it('clamps the log level it asks for', () => {
    const loud = ovpnArgs(specFor(false), {
      configPath: '/dev/stdin',
      management: { kind: 'unix', path: '/run/mgmt.sock' },
      verb: 11
    })
    expect(loud[loud.indexOf('--verb') + 1]).toBe('4')
    const quiet = ovpnArgs(specFor(false), {
      configPath: '/dev/stdin',
      management: { kind: 'unix', path: '/run/mgmt.sock' },
      verb: 0
    })
    expect(quiet[quiet.indexOf('--verb') + 1]).toBe('1')
  })
})

// Guard against a fixture directory that quietly empties out.
describe('fixture coverage', () => {
  let files: string[] = []
  beforeAll(async () => {
    const { readdirSync } = await import('node:fs')
    files = readdirSync(DIR).filter((f) => f.endsWith('.ovpn'))
  })
  afterAll(() => {
    files = []
  })

  it('has a fixture per reject rule plus benign controls', () => {
    expect(files.filter((f) => f.startsWith('reject-')).length).toBe(OVPN_REJECT_RULES.length)
    expect(files.filter((f) => f.startsWith('ok-')).length).toBeGreaterThanOrEqual(8)
    expect(files.length).toBeGreaterThanOrEqual(20)
  })
})
