import { describe, it, expect, beforeEach, vi } from 'vitest'
import { redactOutput } from '../src/main/services/secretRedaction'
import type { VaultEntry } from '../src/shared/vault'
import type { FrpSpec, OpenVpnSpec, VpnProfile, VpnSpec, WireGuardSpec } from '../src/shared/vpn'

// A VPN profile is persisted as plain JSON, so every secret it needs lives in
// the vault and the profile carries only refs. These cover the two directions
// of that: an import putting material in, and a start pulling it back out.
//
// The properties worth breaking a build over are that a locked vault fails
// instead of degrading (E34), that nothing is cached past the call, and that
// every resolved literal reaches the log redactor (E57).

let vaultEntries: VaultEntry[] = []
let vaultUnlocked = true
let vaultExists = true

const getSecret = vi.fn<(id: string) => string | null>(() => null)

vi.mock('../src/main/services/secrets', () => ({
  getSecret: (id: string) => getSecret(id),
  setSecret: () => undefined
}))

vi.mock('../src/main/services/vault', () => ({
  vaultStatus: () => ({
    exists: vaultExists,
    unlocked: vaultUnlocked,
    entryCount: vaultEntries.length
  }),
  vaultList: () =>
    vaultUnlocked ? { ok: true, entries: vaultEntries } : { ok: false, error: 'Vault is locked.' },
  vaultSave: (entries: VaultEntry[]) => {
    if (!vaultUnlocked) return { ok: false, error: 'Vault is locked.' }
    vaultEntries = entries
    return { ok: true }
  }
}))

const { resolveVpnSecrets, VaultLockedError, isVaultLockedError } = await import(
  '../src/main/services/credentialResolver'
)
const { stageImportedSecrets, deleteVpnSecrets } = await import(
  '../src/main/services/vpn/vaultBridge'
)

// Real-shaped material: a 44-char base64 WireGuard key, so the redaction
// assertions exercise the same values the pattern rules see in a log.
const WG_PRIVATE = 'yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk='
const PEER_PUBLIC = 'xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg='
const PEER_PSK = 'FpCyhws9cxwWoV4xELtfJvjJN+zQVRPISllRWgeopVE='
const OVPN_BODY = '<ca>\nMIIB\n</ca>\n<key>\nPRIVATE-MATERIAL\n</key>\nremote vpn.example.com 1194'
const FRP_TOKEN = 'frp-token-9f2c'
const PROXY_SECRET = 'stcp-secret-a1'

const entry = (patch: Partial<VaultEntry>): VaultEntry => ({
  id: 'v1',
  name: 'Office VPN',
  kind: 'vpn',
  workspaceId: 'w1',
  url: '',
  username: '',
  password: '',
  notes: '',
  tags: ['vpn'],
  fields: [],
  createdAt: '',
  updatedAt: '',
  ...patch
})

const profile = (spec: VpnSpec): VpnProfile => ({
  id: 'p1',
  workspaceId: 'w1',
  name: 'Office VPN',
  autoStart: false,
  spec
})

const wireguard = (vaultEntryId = 'v1'): WireGuardSpec => ({
  kind: 'wireguard',
  mode: 'userspace',
  privateKeyRef: { vaultEntryId, field: 'privateKey' },
  addresses: ['10.0.0.2/32'],
  dns: ['10.0.0.1'],
  peers: [
    {
      publicKey: PEER_PUBLIC,
      presharedKeyRef: {
        vaultEntryId,
        field: 'presharedKey',
        fieldKey: `presharedKey:${PEER_PUBLIC}`
      },
      endpoint: 'vpn.example.com:51820',
      allowedIps: ['0.0.0.0/0']
    }
  ],
  listeners: []
})

const openvpn = (vaultEntryId = 'v1'): OpenVpnSpec => ({
  kind: 'openvpn',
  configRef: { vaultEntryId, field: 'configBody' },
  authMode: 'userpass',
  usernameRef: { vaultEntryId, field: 'username' },
  passwordRef: { vaultEntryId, field: 'password' },
  keyPassphraseRef: { vaultEntryId, field: 'keyPassphrase', fieldKey: 'keyPassphrase' },
  redirectGateway: false
})

const frp = (vaultEntryId = 'v1'): FrpSpec => ({
  kind: 'frp',
  serverAddr: 'frp.example.com',
  serverPort: 7000,
  auth: { method: 'token', tokenRef: { vaultEntryId, field: 'token' } },
  transport: { protocol: 'tcp', tlsEnable: true },
  proxies: [
    {
      name: 'ssh',
      type: 'stcp',
      localIp: '127.0.0.1',
      localPort: 22,
      secretKeyRef: {
        vaultEntryId,
        field: 'proxySecretKey',
        fieldKey: 'proxySecretKey:ssh'
      },
      acknowledgedExposure: true
    }
  ],
  visitors: []
})

beforeEach(() => {
  vaultEntries = []
  vaultUnlocked = true
  vaultExists = true
  getSecret.mockClear()
})

describe('resolving a WireGuard profile', () => {
  it('reads the private key from the key slot and each preshared key from a field', () => {
    vaultEntries = [
      entry({
        privateKey: WG_PRIVATE,
        fields: [
          { id: 'f1', key: `presharedKey:${PEER_PUBLIC}`, value: PEER_PSK, secret: true }
        ]
      })
    ]
    return expect(resolveVpnSecrets(profile(wireguard()))).resolves.toMatchObject({
      privateKey: WG_PRIVATE,
      presharedKeys: { [PEER_PUBLIC]: PEER_PSK }
    })
  })

  it('keys preshared material by peer public key, so a two-peer profile still works', async () => {
    const secondPub = 'TrMvSoP4jYQlY6RIzBgbssQqY3vxI2Pi+y71lOWWXX0='
    const secondPsk = 'aGVsbG8gd29ybGQgdGhpcyBpcyBhIHByZXNoYXJlZCA='
    const spec = wireguard()
    spec.peers.push({
      publicKey: secondPub,
      presharedKeyRef: {
        vaultEntryId: 'v1',
        field: 'presharedKey',
        fieldKey: `presharedKey:${secondPub}`
      },
      endpoint: 'other.example.com:51820',
      allowedIps: ['10.1.0.0/16']
    })
    vaultEntries = [
      entry({
        privateKey: WG_PRIVATE,
        fields: [
          { id: 'f1', key: `presharedKey:${PEER_PUBLIC}`, value: PEER_PSK, secret: true },
          { id: 'f2', key: `presharedKey:${secondPub}`, value: secondPsk, secret: true }
        ]
      })
    ]

    const resolved = await resolveVpnSecrets(profile(spec))
    expect(resolved.presharedKeys).toEqual({ [PEER_PUBLIC]: PEER_PSK, [secondPub]: secondPsk })
  })
})

describe('resolving an OpenVPN profile', () => {
  it('reads the config body, the account and the passphrase from their own places', async () => {
    vaultEntries = [
      entry({
        privateKey: OVPN_BODY,
        username: 'vpnuser',
        password: 'hunter2',
        fields: [{ id: 'f1', key: 'keyPassphrase', value: 'phrase', secret: true }]
      })
    ]

    const resolved = await resolveVpnSecrets(profile(openvpn()))
    expect(resolved.configBody).toBe(OVPN_BODY)
    expect(resolved.username).toBe('vpnuser')
    expect(resolved.password).toBe('hunter2')
    expect(resolved.keyPassphrase).toBe('phrase')
    // The body is key material, so it goes in the same slot a WireGuard key
    // would: there is no second key column on a vault entry.
    expect(vaultEntries[0].privateKey).toBe(OVPN_BODY)
  })
})

describe('resolving an frp profile', () => {
  it('reads the token from the password slot and per-proxy secrets from fields', async () => {
    const spec = frp()
    spec.proxies[0].plugin = {
      name: 'socks5',
      username: 'bob',
      passwordRef: { vaultEntryId: 'v1', field: 'password', fieldKey: 'pluginPassword:ssh' }
    }
    spec.visitors.push({
      name: 'ssh-visitor',
      type: 'stcp',
      serverName: 'ssh',
      secretKeyRef: {
        vaultEntryId: 'v1',
        field: 'proxySecretKey',
        fieldKey: 'proxySecretKey:ssh-visitor'
      },
      bindAddr: '127.0.0.1',
      bindPort: 6000
    })
    vaultEntries = [
      entry({
        password: FRP_TOKEN,
        fields: [
          { id: 'f1', key: 'proxySecretKey:ssh', value: PROXY_SECRET, secret: true },
          { id: 'f2', key: 'pluginPassword:ssh', value: 'plugin-pw', secret: true },
          { id: 'f3', key: 'proxySecretKey:ssh-visitor', value: 'visitor-secret', secret: true }
        ]
      })
    ]

    const resolved = await resolveVpnSecrets(profile(spec))
    expect(resolved.token).toBe(FRP_TOKEN)
    expect(resolved.proxySecretKeys).toEqual({
      ssh: PROXY_SECRET,
      'plugin:ssh': 'plugin-pw',
      'ssh-visitor': 'visitor-secret'
    })
  })

  it('never opens the vault for a profile that references nothing', async () => {
    // An frp profile with no token and no secret proxies must not raise an
    // unlock prompt just by being started.
    vaultUnlocked = false
    const spec = frp()
    spec.auth = { method: 'token' }
    spec.proxies[0].secretKeyRef = undefined

    await expect(resolveVpnSecrets(profile(spec))).resolves.toEqual({ all: [] })
  })
})

describe('a locked vault stops the start (E34)', () => {
  it('rejects with VaultLockedError so the unlock prompt is what the user sees', async () => {
    vaultUnlocked = false
    vaultEntries = [entry({ privateKey: WG_PRIVATE })]

    await expect(resolveVpnSecrets(profile(wireguard()))).rejects.toThrow(VaultLockedError)
    await expect(resolveVpnSecrets(profile(wireguard()))).rejects.toThrow(/vault is locked/i)
  })

  it('carries the marker the renderer recognises across IPC', async () => {
    vaultUnlocked = false
    const err = await resolveVpnSecrets(profile(wireguard())).catch((e: unknown) => e)
    expect(isVaultLockedError(err)).toBe(true)
    expect(String(err)).toContain('SHELLPILOT_VAULT_LOCKED')
  })

  it('has no fallback: it never reaches for the OS keychain instead', async () => {
    // Starting a tunnel with a stale copy of a key the user has since rotated is
    // worse than a clear failure, so there is deliberately no second source.
    getSecret.mockReturnValue(JSON.stringify({ privateKey: 'STALE-KEYCHAIN-COPY' }))
    vaultUnlocked = false

    await expect(resolveVpnSecrets(profile(wireguard()))).rejects.toThrow(VaultLockedError)
    expect(getSecret).not.toHaveBeenCalled()
  })

  it('fails the same way after a successful resolve, because nothing is cached', async () => {
    // A module-level cache of resolved plaintext would survive the vault
    // re-locking, which would quietly undo the auto-lock.
    vaultEntries = [entry({ privateKey: WG_PRIVATE })]
    const spec = wireguard()
    spec.peers[0].presharedKeyRef = undefined
    expect((await resolveVpnSecrets(profile(spec))).privateKey).toBe(WG_PRIVATE)

    vaultUnlocked = false
    await expect(resolveVpnSecrets(profile(spec))).rejects.toThrow(VaultLockedError)
  })

  it('refuses to stage an import or delete an entry while locked', async () => {
    vaultUnlocked = false
    await expect(stageImportedSecrets('n', 'w1', 'wireguard', { privateKey: WG_PRIVATE })).rejects.toThrow(
      VaultLockedError
    )
    await expect(deleteVpnSecrets('v1')).rejects.toThrow(VaultLockedError)
  })

  it('reports a missing vault entry rather than starting without a key', async () => {
    vaultEntries = []
    await expect(resolveVpnSecrets(profile(wireguard('gone')))).rejects.toThrow(/no longer in the vault/i)
  })
})

describe('every resolved literal reaches the log redactor (E57)', () => {
  it('flattens each kind of secret into all[]', async () => {
    vaultEntries = [
      entry({
        privateKey: WG_PRIVATE,
        fields: [{ id: 'f1', key: `presharedKey:${PEER_PUBLIC}`, value: PEER_PSK, secret: true }]
      })
    ]
    const resolved = await resolveVpnSecrets(profile(wireguard()))
    expect(resolved.all).toContain(WG_PRIVATE)
    expect(resolved.all).toContain(PEER_PSK)
    // The peer's public key is not a secret and is not in here; it is shown in
    // the UI from the profile model.
    expect(resolved.all).not.toContain(PEER_PUBLIC)
  })

  it('blanks every one of them out of a log line', async () => {
    vaultEntries = [
      entry({
        privateKey: OVPN_BODY,
        username: 'vpnuser',
        password: 'hunter2',
        fields: [{ id: 'f1', key: 'keyPassphrase', value: 'phrase-not-shaped-like-a-secret', secret: true }]
      })
    ]
    const resolved = await resolveVpnSecrets(profile(openvpn()))
    const line = 'AUTH: user=vpnuser pass=hunter2 pp=phrase-not-shaped-like-a-secret'

    const redacted = redactOutput(line, resolved.all)
    for (const literal of resolved.all) expect(redacted).not.toContain(literal)
  })

  it('orders longest first, so a short secret cannot leave a longer one in fragments', async () => {
    vaultEntries = [entry({ privateKey: 'abc-token', password: 'abc-token-longer-value' })]
    const spec = openvpn()
    spec.usernameRef = undefined
    spec.keyPassphraseRef = undefined

    const resolved = await resolveVpnSecrets(profile(spec))
    expect(redactOutput('value: abc-token-longer-value', resolved.all)).not.toContain('longer')
  })
})

describe('staging an import into the vault', () => {
  it('round-trips WireGuard material through refs back to the same plaintext', async () => {
    const staged = await stageImportedSecrets('Office WireGuard', 'w1', 'wireguard', {
      privateKey: WG_PRIVATE,
      presharedKeys: { [PEER_PUBLIC]: PEER_PSK }
    })

    const spec: WireGuardSpec = {
      ...wireguard(staged.vaultEntryId),
      privateKeyRef: staged.refs.privateKey!,
      peers: [
        {
          publicKey: PEER_PUBLIC,
          presharedKeyRef: staged.refs.presharedKeys?.[PEER_PUBLIC],
          endpoint: 'vpn.example.com:51820',
          allowedIps: ['0.0.0.0/0']
        }
      ]
    }

    const resolved = await resolveVpnSecrets(profile(spec))
    expect(resolved.privateKey).toBe(WG_PRIVATE)
    expect(resolved.presharedKeys).toEqual({ [PEER_PUBLIC]: PEER_PSK })
  })

  it('round-trips an OpenVPN import, config body included', async () => {
    const staged = await stageImportedSecrets('Corp OpenVPN', 'w1', 'openvpn', {
      configBody: OVPN_BODY,
      username: 'vpnuser',
      password: 'hunter2',
      keyPassphrase: 'phrase'
    })

    const spec: OpenVpnSpec = {
      ...openvpn(staged.vaultEntryId),
      configRef: staged.refs.configBody!,
      usernameRef: staged.refs.username,
      passwordRef: staged.refs.password,
      keyPassphraseRef: staged.refs.keyPassphrase
    }

    await expect(resolveVpnSecrets(profile(spec))).resolves.toMatchObject({
      configBody: OVPN_BODY,
      username: 'vpnuser',
      password: 'hunter2',
      keyPassphrase: 'phrase'
    })
  })

  it('round-trips an frp import', async () => {
    const staged = await stageImportedSecrets('Home frp', 'w1', 'frp', {
      token: FRP_TOKEN,
      proxySecretKeys: { ssh: PROXY_SECRET }
    })

    const spec: FrpSpec = { ...frp(staged.vaultEntryId) }
    spec.auth = { method: 'token', tokenRef: staged.refs.token }
    spec.proxies[0].secretKeyRef = staged.refs.proxySecretKeys?.ssh

    await expect(resolveVpnSecrets(profile(spec))).resolves.toMatchObject({
      token: FRP_TOKEN,
      proxySecretKeys: { ssh: PROXY_SECRET }
    })
  })

  it('creates one vpn-kind entry and leaves existing entries alone', async () => {
    vaultEntries = [entry({ id: 'existing', kind: 'login', password: 'unrelated' })]
    const staged = await stageImportedSecrets('Office WireGuard', 'w1', 'wireguard', {
      privateKey: WG_PRIVATE
    })

    expect(vaultEntries).toHaveLength(2)
    const created = vaultEntries.find((e) => e.id === staged.vaultEntryId)!
    expect(created.kind).toBe('vpn')
    expect(created.name).toBe('Office WireGuard')
    expect(created.workspaceId).toBe('w1')
    expect(created.tags).toContain('wireguard')
    expect(vaultEntries[0].password).toBe('unrelated')
  })

  it('falls back to a named field when two values want the same slot', async () => {
    // frp is the case that can produce both a token and an OIDC client secret;
    // the ref records where the loser actually went, so resolution still finds
    // it without a second convention to remember.
    const staged = await stageImportedSecrets('Both', 'w1', 'frp', {
      password: 'oidc-client-secret',
      token: FRP_TOKEN
    })

    expect(staged.refs.password?.fieldKey).toBeUndefined()
    expect(staged.refs.token?.fieldKey).toBe('token')
    const created = vaultEntries[0]
    expect(created.password).toBe('oidc-client-secret')
    expect(created.fields.map((f) => f.key)).toEqual(['token'])
  })

  it('hands back refs and a profile with no plaintext anywhere in them', async () => {
    // The renderer receives this. Walking the serialised form is the assertion
    // that matters: a secret smuggled onto a profile would be written to
    // store.ts's plain JSON on the next save.
    const staged = await stageImportedSecrets('Office WireGuard', 'w1', 'wireguard', {
      privateKey: WG_PRIVATE,
      presharedKeys: { [PEER_PUBLIC]: PEER_PSK },
      username: 'vpnuser',
      password: 'hunter2',
      keyPassphrase: 'pkcs8-unlock-word',
      token: FRP_TOKEN,
      configBody: OVPN_BODY,
      proxySecretKeys: { ssh: PROXY_SECRET }
    })

    const spec: WireGuardSpec = {
      ...wireguard(staged.vaultEntryId),
      privateKeyRef: staged.refs.privateKey!,
      peers: [
        {
          publicKey: PEER_PUBLIC,
          presharedKeyRef: staged.refs.presharedKeys?.[PEER_PUBLIC],
          endpoint: 'vpn.example.com:51820',
          allowedIps: ['0.0.0.0/0']
        }
      ]
    }

    const serialised = JSON.stringify({ refs: staged.refs, profile: profile(spec) })
    for (const literal of [
      WG_PRIVATE,
      PEER_PSK,
      'hunter2',
      'pkcs8-unlock-word',
      FRP_TOKEN,
      PROXY_SECRET,
      'PRIVATE-MATERIAL'
    ]) {
      expect(serialised).not.toContain(literal)
    }
    // The peer's public key is on the profile, which is how the UI can show it
    // without unlocking the vault.
    expect(serialised).toContain(PEER_PUBLIC)
  })
})

describe('deleting a profile takes its credentials with it', () => {
  it('removes only the entry the profile owned', async () => {
    const staged = await stageImportedSecrets('Office WireGuard', 'w1', 'wireguard', {
      privateKey: WG_PRIVATE
    })
    vaultEntries = [...vaultEntries, entry({ id: 'other', kind: 'login' })]

    await deleteVpnSecrets(staged.vaultEntryId)
    expect(vaultEntries.map((e) => e.id)).toEqual(['other'])
  })

  it('treats an already-missing entry as done, so a profile is never undeletable', async () => {
    vaultEntries = [entry({ id: 'other', kind: 'login' })]
    await expect(deleteVpnSecrets('never-existed')).resolves.toBeUndefined()
    expect(vaultEntries).toHaveLength(1)
  })
})
