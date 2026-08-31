import { describe, it, expect } from 'vitest'

import type { FrpProxy, FrpSpec, VpnSecretRef } from '../src/shared/vpn'
import {
  FRP_ENV_ADMIN,
  FRP_ENV_TOKEN,
  frpEnv,
  generateFrpToml,
  isSafeTomlString,
  validateFrpSpec
} from '../src/main/services/vpn/frpConfig'
import { VpnError } from '../src/main/services/vpn/errors'

const ref = (fieldKey?: string): VpnSecretRef => ({
  vaultEntryId: 'vault-entry-1',
  field: fieldKey ? 'proxySecretKey' : 'token',
  ...(fieldKey ? { fieldKey } : {})
})

const RUN = { adminPort: 41731, adminUser: 'shellpilot' }
const RUN_SECRETS = { ...RUN, adminPassword: 'admin-pw-3f9c' }

function proxy(over: Partial<FrpProxy> = {}): FrpProxy {
  return {
    name: 'postgres',
    type: 'tcp',
    localIp: '127.0.0.1',
    localPort: 5432,
    remotePort: 15432,
    acknowledgedExposure: true,
    ...over
  }
}

function spec(over: Partial<FrpSpec> = {}): FrpSpec {
  return {
    kind: 'frp',
    serverAddr: 'frp.example.com',
    serverPort: 7000,
    auth: { method: 'token', tokenRef: ref() },
    transport: { protocol: 'tcp', tlsEnable: true, poolCount: 1, heartbeatIntervalSec: 30 },
    proxies: [proxy()],
    visitors: [],
    ...over
  }
}

const REALISTIC: FrpSpec = spec({
  proxies: [
    proxy(),
    proxy({
      name: 'secret-ssh',
      type: 'stcp',
      localPort: 22,
      remotePort: undefined,
      secretKeyRef: ref('secret-ssh')
    }),
    proxy({
      name: 'egress',
      type: 'tcp',
      localPort: 1080,
      remotePort: 16080,
      plugin: { name: 'socks5', username: 'sp', passwordRef: ref('egress-pw') }
    })
  ],
  visitors: [
    {
      name: 'ssh-visitor',
      type: 'stcp',
      serverName: 'secret-ssh',
      secretKeyRef: ref('ssh-visitor'),
      bindAddr: '127.0.0.1',
      bindPort: 9022
    }
  ]
})

describe('generateFrpToml', () => {
  it('emits the whole config for a realistic profile', () => {
    expect(generateFrpToml(REALISTIC, RUN)).toBe(
      `serverAddr = "frp.example.com"
serverPort = 7000

auth.method = "token"
auth.token  = "{{ .Envs.SP_FRP_TOKEN }}"

transport.tls.enable        = true
transport.protocol          = "tcp"
transport.poolCount         = 1
transport.heartbeatInterval = 30

webServer.addr     = "127.0.0.1"
webServer.port     = 41731
webServer.user     = "shellpilot"
webServer.password = "{{ .Envs.SP_FRP_ADMIN }}"

log.to    = "console"
log.level = "info"

[[proxies]]
name       = "postgres"
type       = "tcp"
localIP    = "127.0.0.1"
localPort  = 5432
remotePort = 15432

[[proxies]]
name      = "secret-ssh"
type      = "stcp"
localIP   = "127.0.0.1"
localPort = 22
secretKey = "{{ .Envs.SP_FRP_SECRET_1 }}"

[[proxies]]
name       = "egress"
type       = "tcp"
localIP    = "127.0.0.1"
localPort  = 1080
remotePort = 16080

[proxies.plugin]
type     = "socks5"
username = "sp"
password = "{{ .Envs.SP_FRP_PLUGIN_PW_2 }}"

[[visitors]]
name       = "ssh-visitor"
type       = "stcp"
serverName = "secret-ssh"
secretKey  = "{{ .Envs.SP_FRP_VISITOR_SECRET_0 }}"
bindAddr   = "127.0.0.1"
bindPort   = 9022
`
    )
  })

  it('emits TOML, never the legacy INI frp deprecated at v0.52.0', () => {
    const toml = generateFrpToml(REALISTIC, RUN)
    expect(toml).not.toContain('[common]')
    expect(toml).not.toContain('server_addr')
    expect(toml).not.toContain('server_port')
    expect(toml).not.toContain('local_port')
    expect(toml).not.toContain('remote_port')
    expect(toml).not.toContain('admin_addr')
    expect(toml).not.toContain('tls_enable')
    // Every proxy is an array-of-tables entry, not an INI `[name]` section.
    expect(toml).not.toMatch(/^\[postgres\]$/m)
    expect(toml.match(/^\[\[proxies\]\]$/gm)).toHaveLength(3)
  })

  it('carries the corporate proxy URL when one is set', () => {
    const toml = generateFrpToml(
      spec({
        transport: {
          protocol: 'tcp',
          tlsEnable: true,
          proxyUrl: 'http://corp-proxy.example.com:3128'
        }
      }),
      RUN
    )
    expect(toml).toContain('transport.proxyURL          = "http://corp-proxy.example.com:3128"')
    // Defaults are still emitted explicitly rather than left to frp.
    expect(toml).toContain('transport.poolCount         = 1')
    expect(toml).toContain('transport.heartbeatInterval = 30')
  })

  it('omits auth.token entirely when no token is configured', () => {
    const toml = generateFrpToml(spec({ auth: { method: 'token' } }), RUN)
    expect(toml).toContain('auth.method = "token"')
    expect(toml).not.toContain('auth.token')
  })

  it('emits the OIDC block with the secret behind an env template', () => {
    const toml = generateFrpToml(
      spec({
        auth: {
          method: 'oidc',
          oidc: {
            clientId: 'shellpilot',
            clientSecretRef: ref(),
            audience: 'frps',
            tokenEndpointUrl: 'https://idp.example.com/token'
          }
        }
      }),
      RUN
    )
    expect(toml).toContain('auth.oidc.clientID')
    expect(toml).toContain('auth.oidc.clientSecret')
    expect(toml).toContain('"{{ .Envs.SP_FRP_OIDC_SECRET }}"')
    expect(toml).toContain('auth.oidc.tokenEndpointURL')
  })
})

describe('frpEnv', () => {
  it('carries every secret, and the TOML carries none of them', () => {
    const secrets = {
      token: 'tok_live_9d2f',
      proxySecretKeys: { 'secret-ssh': 'stcp-secret-aaa', 'ssh-visitor': 'stcp-secret-aaa' },
      pluginPasswords: { egress: 'socks-pw-bbb' }
    }
    const env = frpEnv(REALISTIC, secrets, RUN_SECRETS)

    expect(env).toEqual({
      SP_FRP_ADMIN: 'admin-pw-3f9c',
      SP_FRP_TOKEN: 'tok_live_9d2f',
      SP_FRP_SECRET_1: 'stcp-secret-aaa',
      SP_FRP_PLUGIN_PW_2: 'socks-pw-bbb',
      SP_FRP_VISITOR_SECRET_0: 'stcp-secret-aaa'
    })

    const toml = generateFrpToml(REALISTIC, RUN)
    for (const secret of Object.values(env)) expect(toml).not.toContain(secret)
    // What the file holds instead is the template that reads them back.
    expect(toml).toContain(`{{ .Envs.${FRP_ENV_TOKEN} }}`)
    expect(toml).toContain(`{{ .Envs.${FRP_ENV_ADMIN} }}`)
  })

  it('always carries the admin password, even with no other secrets', () => {
    expect(frpEnv(spec({ auth: { method: 'token' } }), {}, RUN_SECRETS)).toEqual({
      SP_FRP_ADMIN: 'admin-pw-3f9c'
    })
  })
})

// ------------------------------------------------------------- validation

const codes = (s: FrpSpec, confirm = {}): string[] =>
  validateFrpSpec(s, confirm).issues.map((i) => i.code)

describe('validateFrpSpec', () => {
  it('accepts a realistic profile once the plugin is confirmed', () => {
    const v = validateFrpSpec(REALISTIC, { allowProxyPlugins: true })
    expect(v.issues.filter((i) => i.severity === 'error')).toEqual([])
    expect(v.ok).toBe(true)
  })

  it('refuses to start unless every proxy acknowledges its exposure', () => {
    const s = spec({
      proxies: [proxy(), proxy({ name: 'redis', localPort: 6379, remotePort: 16379, acknowledgedExposure: false })]
    })
    const v = validateFrpSpec(s)
    expect(v.ok).toBe(false)
    const issue = v.issues.find((i) => i.code === 'exposure-unacknowledged')
    expect(issue?.path).toBe('proxies[1].acknowledgedExposure')
    expect(issue?.severity).toBe('error')
    // The message names the port and says what "exposure" means.
    expect(issue?.message).toContain('127.0.0.1:6379')
  })

  it('never offers unix_domain_socket or static_file', () => {
    for (const name of ['unix_domain_socket', 'static_file']) {
      const s = spec({
        proxies: [proxy({ plugin: { name } as FrpProxy['plugin'] })]
      })
      const v = validateFrpSpec(s, { allowProxyPlugins: true })
      expect(v.ok).toBe(false)
      expect(v.issues.map((i) => i.code)).toContain('plugin-not-offered')
    }
  })

  it('requires an explicit confirmation for the socks5 and http_proxy plugins', () => {
    for (const name of ['socks5', 'http_proxy'] as const) {
      const s = spec({ proxies: [proxy({ plugin: { name } })] })
      expect(codes(s)).toContain('plugin-unconfirmed')
      expect(validateFrpSpec(s, { allowProxyPlugins: true }).ok).toBe(true)
    }
  })

  it('treats a non-loopback localIp as an error until it is confirmed', () => {
    const s = spec({ proxies: [proxy({ localIp: '0.0.0.0' })] })
    expect(codes(s)).toContain('local-ip-not-loopback')
    expect(validateFrpSpec(s, { allowNonLoopbackLocalIp: true }).ok).toBe(true)
  })

  it('treats disabled TLS as an error until it is confirmed', () => {
    const s = spec({ transport: { protocol: 'tcp', tlsEnable: false } })
    expect(codes(s)).toContain('tls-disabled')
    expect(validateFrpSpec(s, { allowPlaintextTransport: true }).ok).toBe(true)
  })

  it('rejects duplicate proxy names and duplicate remote ports', () => {
    const dupName = spec({ proxies: [proxy(), proxy({ remotePort: 15433 })] })
    expect(codes(dupName)).toContain('proxy-name-duplicate')

    const dupPort = spec({ proxies: [proxy(), proxy({ name: 'mysql', localPort: 3306 })] })
    const issue = validateFrpSpec(dupPort).issues.find((i) => i.code === 'remote-port-duplicate')
    expect(issue?.message).toContain('15432')
    expect(issue?.message).toContain('postgres')
  })

  it('holds proxy names to frp’s charset', () => {
    for (const name of ['has space', '-leading-dash', 'semi;colon', 'sl/ash', '']) {
      const s = spec({ proxies: [proxy({ name })] })
      expect(validateFrpSpec(s).ok).toBe(false)
    }
    for (const name of ['postgres', 'db.prod_1', 'a-b-c']) {
      expect(validateFrpSpec(spec({ proxies: [proxy({ name })] })).ok).toBe(true)
    }
  })

  it('requires a remote port for tcp and udp, and a domain for http and https', () => {
    expect(codes(spec({ proxies: [proxy({ remotePort: undefined })] }))).toContain(
      'remote-port-missing'
    )
    expect(
      codes(spec({ proxies: [proxy({ type: 'http', remotePort: undefined })] }))
    ).toContain('domain-missing')
    expect(
      validateFrpSpec(
        spec({
          proxies: [proxy({ type: 'http', remotePort: undefined, subdomain: 'app' })]
        })
      ).ok
    ).toBe(true)
  })

  it('requires a shared secret for stcp, sudp, xtcp and for visitors', () => {
    expect(
      codes(spec({ proxies: [proxy({ type: 'stcp', remotePort: undefined })] }))
    ).toContain('secret-key-missing')
    expect(
      codes(
        spec({
          visitors: [
            {
              name: 'v1',
              type: 'stcp',
              serverName: 'secret-ssh',
              bindAddr: '127.0.0.1',
              bindPort: 9022
            }
          ]
        })
      )
    ).toContain('secret-key-missing')
  })

  it('refuses a visitor whose name collides with a proxy, because they share one secret record', () => {
    const s = spec({
      visitors: [
        {
          name: 'postgres',
          type: 'stcp',
          serverName: 'secret-ssh',
          secretKeyRef: ref('postgres'),
          bindAddr: '127.0.0.1',
          bindPort: 9022
        }
      ]
    })
    expect(codes(s)).toContain('visitor-name-collides-with-proxy')
  })

  it('flags a visitor bound off loopback until it is confirmed', () => {
    const s = spec({
      visitors: [
        {
          name: 'v1',
          type: 'stcp',
          serverName: 'secret-ssh',
          secretKeyRef: ref('v1'),
          bindAddr: '0.0.0.0',
          bindPort: 9022
        }
      ]
    })
    expect(codes(s)).toContain('bind-addr-not-loopback')
    expect(validateFrpSpec(s, { allowNonLoopbackBindAddr: true }).ok).toBe(true)
  })

  it('checks the server address, port, transport and timings', () => {
    expect(codes(spec({ serverAddr: '   ' }))).toContain('server-addr-missing')
    expect(codes(spec({ serverPort: 0 }))).toContain('server-port-invalid')
    expect(codes(spec({ serverPort: 70000 }))).toContain('server-port-invalid')
    expect(
      codes(spec({ transport: { protocol: 'gopher' as 'tcp', tlsEnable: true } }))
    ).toContain('transport-protocol-invalid')
    expect(
      codes(spec({ transport: { protocol: 'tcp', tlsEnable: true, poolCount: 5000 } }))
    ).toContain('pool-count-invalid')
    expect(
      codes(spec({ transport: { protocol: 'tcp', tlsEnable: true, heartbeatIntervalSec: 0 } }))
    ).toContain('heartbeat-invalid')
    expect(
      codes(
        spec({ transport: { protocol: 'tcp', tlsEnable: true, proxyUrl: 'corp-proxy:3128' } })
      )
    ).toContain('proxy-url-invalid')
    expect(
      validateFrpSpec(
        spec({ transport: { protocol: 'tcp', tlsEnable: true, proxyUrl: 'socks5://p:1080' } })
      ).ok
    ).toBe(true)
  })

  it('warns rather than errors when a token profile has no token', () => {
    const v = validateFrpSpec(spec({ auth: { method: 'token' } }))
    expect(v.ok).toBe(true)
    expect(v.issues.find((i) => i.code === 'auth-token-missing')?.severity).toBe('warning')
  })
})

// -------------------------------------------------------- TOML injection

describe('TOML injection', () => {
  // Each of these is an attempt to end the string and start writing keys of
  // the attacker's choosing, or to make frp expand a template we own.
  const HOSTILE = [
    'postgres"\nremotePort = 22\nname = "x',
    'postgres"',
    'back\\slash',
    'line\nbreak',
    'carriage\rreturn',
    'null byte',
    'tab\tseparated',
    'delchar',
    '{{ .Envs.SP_FRP_TOKEN }}',
    'a{{ .Envs.SP_FRP_ADMIN }}b'
  ]

  it('isSafeTomlString rejects every one of them, and accepts ordinary values', () => {
    for (const s of HOSTILE) expect(isSafeTomlString(s)).toBe(false)
    for (const s of ['postgres', 'frp.example.com', '*.apps.example.com', 'a-b_c.1']) {
      expect(isSafeTomlString(s)).toBe(true)
    }
  })

  it('validation rejects them rather than escaping them', () => {
    for (const name of HOSTILE) {
      const v = validateFrpSpec(spec({ proxies: [proxy({ name })] }))
      expect(v.ok).toBe(false)
      expect(v.issues.map((i) => i.code)).toContain('toml-unsafe-string')
    }
  })

  it('rejects them in every free-text field, not just names', () => {
    const hostile = 'evil"\nremotePort = 22'
    expect(codes(spec({ serverAddr: hostile }))).toContain('toml-unsafe-string')
    expect(codes(spec({ proxies: [proxy({ customDomains: [hostile] })] }))).toContain(
      'toml-unsafe-string'
    )
    expect(codes(spec({ proxies: [proxy({ subdomain: hostile })] }))).toContain(
      'toml-unsafe-string'
    )
    expect(codes(spec({ proxies: [proxy({ localIp: hostile })] }))).toContain(
      'toml-unsafe-string'
    )
    expect(
      codes(
        spec({
          visitors: [
            {
              name: 'v1',
              type: 'stcp',
              serverName: hostile,
              secretKeyRef: ref('v1'),
              bindAddr: '127.0.0.1',
              bindPort: 9022
            }
          ]
        })
      )
    ).toContain('toml-unsafe-string')
  })

  it('the generator throws rather than emitting an escaped value, even if validation was skipped', () => {
    for (const name of HOSTILE) {
      const s = spec({ proxies: [proxy({ name })] })
      let thrown: unknown
      try {
        generateFrpToml(s, RUN)
      } catch (e) {
        thrown = e
      }
      expect(thrown).toBeInstanceOf(VpnError)
      expect((thrown as VpnError).code).toBe('config-invalid')
    }
  })
})
