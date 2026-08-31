import { describe, it, expect } from 'vitest'
import { existsSync, readdirSync, readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { join } from 'node:path'
import {
  FRP_REJECT_RULES,
  isLegacyIni,
  parseFrpConfig,
  parseTomlSubset
} from '../src/main/services/vpn/parsers/frpImport'
import type { FrpSpec, VpnImportResultInternal } from '../src/shared/vpn'

// frp inverts the rest of the app's threat model: every proxy makes a local
// port reachable from the frp server. These assert the import stays timid —
// loopback, TLS on, no filesystem-reaching plugins, and nothing acknowledged
// on the user's behalf.

const DIR = fileURLToPath(new URL('./fixtures/frp', import.meta.url))

const parse = (name: string): VpnImportResultInternal => parseFrpConfig(readFileSync(join(DIR, name), 'utf8'))
const frp = (r: VpnImportResultInternal): FrpSpec => r.spec as FrpSpec

describe('the plugins that are not offered (E40)', () => {
  it.each(FRP_REJECT_RULES.map((r) => [r.id, r] as const))('has a fixture for %s and fails the whole import', (id, rule) => {
    const file = ['toml', 'ini'].map((ext) => `reject-${id}.${ext}`).find((f) => existsSync(join(DIR, f)))
    expect(file, `missing fixture reject-${id}.(toml|ini)`).toBeDefined()

    const r = parse(file as string)
    expect(r.ok).toBe(false)
    expect(r.errorCode).toBe('config-rejected')
    expect(r.spec).toBeUndefined()
    expect(r.secrets).toBeUndefined()
    expect(r.error).toContain(rule.reason)

    const entry = r.stripped.find((s) => s.severity === 'rejected')
    expect(entry).toBeDefined()
    expect(entry?.reason).toBe(rule.reason)
  })

  it('refuses unix_domain_socket in the legacy INI too, not just the TOML', () => {
    const r = parse('reject-plugin-unix-domain-socket.ini')
    expect(r.ok).toBe(false)
    expect(r.error).toContain('docker.sock')
  })

  it('refuses an unsupported plugin rather than dropping it', () => {
    // Dropping the plugin would silently change what the proxy exposes.
    const r = parse('reject-plugin-unsupported.toml')
    expect(r.errorCode).toBe('config-rejected')
    expect(r.error).toContain('https2http')
  })
})

describe('exposure is never acknowledged on the user’s behalf (E41)', () => {
  it('imports every proxy unacknowledged', () => {
    for (const file of ['ok-minimal.toml', 'ok-full.toml', 'ok-legacy.ini', 'ok-legacy-plugin.ini']) {
      const spec = frp(parse(file))
      expect(spec.proxies.length, file).toBeGreaterThan(0)
      for (const p of spec.proxies) expect(p.acknowledgedExposure, `${file}/${p.name}`).toBe(false)
    }
  })

  it('says what the exposure is, naming the server', () => {
    expect(parse('ok-minimal.toml').warnings.join(' ')).toContain(
      'makes a port on this machine reachable from frp.example.com'
    )
  })
})

describe('localIp', () => {
  it('is loopback when the file did not say otherwise', () => {
    const spec = frp(parse('ok-minimal.toml'))
    expect(spec.proxies[0].localIp).toBe('127.0.0.1')
    expect(parse('ok-minimal.toml').warnings.join(' ')).not.toContain('rather than 127.0.0.1')
  })

  it('keeps an explicit value but flags it for confirmation', () => {
    const r = parse('edge-nonloopback.toml')
    expect(frp(r).proxies[0].localIp).toBe('0.0.0.0')
    expect(r.warnings.join(' ')).toContain('listens on 0.0.0.0 rather than 127.0.0.1')
    expect(r.warnings.join(' ')).toContain('Confirm')
  })
})

describe('TLS to the frp server', () => {
  it('defaults on', () => {
    expect(frp(parse('ok-minimal.toml')).transport.tlsEnable).toBe(true)
  })

  it('is left off only when the file asked, and says so', () => {
    const r = parse('edge-tls-off.toml')
    expect(frp(r).transport.tlsEnable).toBe(false)
    expect(r.warnings.join(' ')).toContain('turns off TLS')
  })
})

describe('a v1 TOML profile', () => {
  const r = parse('ok-full.toml')
  const spec = frp(r)

  it('reads the server, transport and every proxy', () => {
    expect(r.ok).toBe(true)
    expect(spec.serverAddr).toBe('frp.example.com')
    expect(spec.serverPort).toBe(7000)
    expect(spec.transport).toEqual({
      protocol: 'quic',
      tlsEnable: true,
      poolCount: 5,
      heartbeatIntervalSec: 30,
      proxyUrl: 'http://corp-proxy:3128'
    })
    expect(spec.proxies.map((p) => p.name)).toEqual(['postgres', 'site', 'secret-ssh', 'socks'])
    expect(spec.proxies[0]).toMatchObject({ type: 'tcp', localPort: 5432, remotePort: 15432 })
    expect(spec.proxies[1].customDomains).toEqual(['site.example.com', 'www.example.com'])
  })

  it('holds the token and every per-proxy secret apart from the spec', () => {
    expect(r.secrets?.token).toBe('s3cr3t-token')
    expect(spec.auth.tokenRef).toEqual({ vaultEntryId: '', field: 'token' })
    expect(r.secrets?.proxySecretKeys?.['secret-ssh']).toBe('peer-shared-secret')
    expect(r.secrets?.proxySecretKeys?.['plugin:socks']).toBe('hunter2')
    const json = JSON.stringify(spec)
    expect(json).not.toContain('s3cr3t-token')
    expect(json).not.toContain('peer-shared-secret')
    expect(json).not.toContain('hunter2')
  })

  it('carries the socks5 plugin and names what it does', () => {
    expect(spec.proxies[3].plugin).toEqual({
      name: 'socks5',
      username: 'bob',
      passwordRef: { vaultEntryId: '', field: 'proxySecretKey', fieldKey: 'plugin:socks' }
    })
    expect(r.warnings.join(' ')).toContain('runs a SOCKS5 proxy')
  })

  it('reads visitors', () => {
    expect(spec.visitors).toEqual([
      {
        name: 'secret-ssh-visitor',
        type: 'stcp',
        serverName: 'secret-ssh',
        bindAddr: '127.0.0.1',
        bindPort: 6000,
        secretKeyRef: { vaultEntryId: '', field: 'proxySecretKey', fieldKey: 'secret-ssh-visitor' }
      }
    ])
  })

  it('reports the settings it generates itself rather than honouring', () => {
    const dropped = r.stripped.map((s) => s.directive)
    expect(dropped).toContain('log')
    expect(dropped).toContain('webServer')
    for (const s of r.stripped) {
      expect(s.severity).toBe('removed')
      expect(s.reason.length).toBeGreaterThan(0)
    }
    expect(spec.strippedDirectives).toEqual(r.stripped)
  })

  it('reads OIDC authentication', () => {
    const oidc = parse('ok-oidc.toml')
    expect(frp(oidc).auth.method).toBe('oidc')
    expect(frp(oidc).auth.oidc).toMatchObject({
      clientId: 'shellpilot',
      audience: 'frp',
      tokenEndpointUrl: 'https://idp.example.com/token'
    })
    expect(oidc.secrets?.password).toBe('oidc-secret')
    expect(JSON.stringify(frp(oidc))).not.toContain('oidc-secret')
  })
})

describe('the legacy INI converter', () => {
  it('is chosen by the [common] section', () => {
    expect(isLegacyIni(readFileSync(join(DIR, 'ok-legacy.ini'), 'utf8'))).toBe(true)
    expect(isLegacyIni(readFileSync(join(DIR, 'ok-full.toml'), 'utf8'))).toBe(false)
  })

  it('converts a v0 file into the v1 model', () => {
    const r = parse('ok-legacy.ini')
    const spec = frp(r)
    expect(r.ok).toBe(true)
    expect(spec.serverAddr).toBe('frp.example.com')
    expect(spec.transport.protocol).toBe('kcp')
    expect(spec.transport.poolCount).toBe(5)
    expect(spec.transport.heartbeatIntervalSec).toBe(30)
    expect(spec.proxies.map((p) => p.name)).toEqual(['ssh', 'web', 'secret_ssh'])
    expect(spec.proxies[1].customDomains).toEqual(['web.example.com', 'www.example.com'])
    expect(r.warnings.join(' ')).toContain('legacy frp INI file')
  })

  it('turns TLS on when the old file never mentioned it', () => {
    const r = parse('ok-legacy.ini')
    expect(frp(r).transport.tlsEnable).toBe(true)
    expect(r.warnings.join(' ')).toContain('did not set tls_enable')
  })

  it('tells a visitor section apart by its role', () => {
    const spec = frp(parse('ok-legacy.ini'))
    expect(spec.visitors.map((v) => v.name)).toEqual(['secret_ssh_visitor'])
    expect(spec.visitors[0].serverName).toBe('secret_ssh')
    expect(spec.proxies.some((p) => p.name === 'secret_ssh_visitor')).toBe(false)
  })

  it('drops the admin API and log settings it generates itself', () => {
    const dropped = parse('ok-legacy.ini').stripped.map((s) => s.directive)
    expect(dropped).toContain('[common] admin_addr')
    expect(dropped).toContain('[common] admin_port')
    expect(dropped).toContain('[common] log_file')
  })

  it('carries a plugin proxy with no local port behind it', () => {
    const spec = frp(parse('ok-legacy-plugin.ini'))
    expect(spec.proxies[0].localPort).toBe(0)
    expect(spec.proxies[0].plugin?.name).toBe('socks5')
    expect(spec.proxies[0].plugin?.username).toBe('bob')
  })
})

describe('files that cannot be run', () => {
  it.each([
    ['bad-no-server.toml', 'frp server address'],
    ['bad-proxy-type.toml', 'carrier-pigeon']
  ])('%s fails with config-invalid', (file, needle) => {
    const r = parse(file)
    expect(r.ok).toBe(false)
    expect(r.errorCode).toBe('config-invalid')
    expect(r.error).toContain(needle)
  })

  it('refuses a file with nothing to run', () => {
    const r = parseFrpConfig('serverAddr = "frp.example.com"\nserverPort = 7000\n')
    expect(r.ok).toBe(false)
    expect(r.error).toContain('no proxies or visitors')
  })
})

// The TOML reader is ours, so it gets its own tests rather than being trusted
// through the importer alone.
describe('the TOML subset reader', () => {
  it('reads tables, dotted keys, arrays of tables and sub-tables', () => {
    const t = parseTomlSubset(
      [
        'a = 1',
        'b.c = "two"',
        '[d]',
        'e = true',
        '[[f]]',
        'name = "one"',
        '[f.g]',
        'deep = 3',
        '[[f]]',
        'name = "two"'
      ].join('\n')
    )
    expect(t).toEqual({
      a: 1,
      b: { c: 'two' },
      d: { e: true },
      f: [{ name: 'one', g: { deep: 3 } }, { name: 'two' }]
    })
  })

  it('reads arrays that span lines, and inline tables', () => {
    const t = parseTomlSubset(['x = [\n  "a",\n  "b",\n]', 'y = { p = 1, q = "r" }'].join('\n'))
    expect(t.x).toEqual(['a', 'b'])
    expect(t.y).toEqual({ p: 1, q: 'r' })
  })

  it('ignores a # inside a string but not outside one', () => {
    const t = parseTomlSubset('a = "not # a comment"  # but this is\nb = 2\n')
    expect(t.a).toBe('not # a comment')
    expect(t.b).toBe(2)
  })

  it('reads escapes and literal strings', () => {
    const t = parseTomlSubset('a = "line\\nbreak"\nb = \'raw\\nvalue\'\n')
    expect(t.a).toBe('line\nbreak')
    expect(t.b).toBe('raw\\nvalue')
  })

  it('fails rather than guessing', () => {
    expect(() => parseTomlSubset('a = \n')).toThrow()
    expect(() => parseTomlSubset('a = "unterminated\n')).toThrow()
    expect(() => parseTomlSubset('a\n')).toThrow()
  })
})

describe('fixture coverage', () => {
  it('has a fixture per reject rule plus benign controls', () => {
    const files = readdirSync(DIR)
    expect(files.filter((f) => f.startsWith('reject-')).length).toBeGreaterThanOrEqual(FRP_REJECT_RULES.length)
    expect(files.filter((f) => f.startsWith('ok-')).length).toBeGreaterThanOrEqual(4)
    expect(files.length).toBeGreaterThanOrEqual(8)
  })
})
