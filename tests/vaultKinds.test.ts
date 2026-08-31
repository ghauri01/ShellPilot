import { describe, it, expect } from 'vitest'
import {
  VAULT_KIND_LABEL,
  VAULT_KIND_FIELDS as KIND_FIELDS,
  hiddenFieldsFor,
  vaultMatches,
  type VaultEntry
} from '../src/shared/vault'

// entry.kind used to be read in exactly one place — the type picker's own
// value — so choosing a kind changed an icon in the sidebar and nothing else:
// a Note asked for a password, and an API key had nowhere obvious to put the
// key. These assert against the real map the view renders from, not a copy.

const entry = (patch: Partial<VaultEntry> = {}): VaultEntry => ({
  id: 'e1',
  name: 'Thing',
  kind: 'login',
  url: 'https://example.com',
  username: 'bob',
  password: 's3cret',
  notes: '',
  tags: [],
  fields: [],
  createdAt: '2026-01-01T00:00:00.000Z',
  updatedAt: '2026-01-01T00:00:00.000Z',
  ...patch
})

describe('what each vault kind shows', () => {
  it('covers every kind the picker offers', () => {
    expect(Object.keys(KIND_FIELDS).sort()).toEqual(Object.keys(VAULT_KIND_LABEL).sort())
  })

  it('gives a login all three credential fields', () => {
    expect(KIND_FIELDS.login).toEqual({ url: true, username: true, secret: 'password' })
  })

  it('does not ask a note for a password or a URL', () => {
    expect(KIND_FIELDS.note).toEqual({ url: false, username: false, secret: null })
  })

  it('labels the secret on an API key as a key, not a password', () => {
    expect(KIND_FIELDS.key.secret).toBe('key')
    expect(KIND_FIELDS.key.username).toBe(false)
  })

  it('gives a bookmark a URL and nothing secret', () => {
    expect(KIND_FIELDS.url).toEqual({ url: true, username: false, secret: null })
  })

  it('would notice a kind added to one map but not the other', () => {
    // The coverage assertion above is only worth having if it actually fails on
    // a half-done addition, which is how the `vpn` kind was added: label, field
    // map and this test in one go.
    const halfAdded = { ...VAULT_KIND_LABEL, wireguardish: 'Half added' }
    expect(Object.keys(KIND_FIELDS).sort()).not.toEqual(Object.keys(halfAdded).sort())
  })

  it('gives a VPN profile a username, a password and a key slot', () => {
    // privateKey carries the WireGuard key or the sanitised .ovpn body, password
    // carries the auth password or the frp token, username the OpenVPN account.
    expect(KIND_FIELDS.vpn).toEqual({ url: true, username: true, secret: 'password', keys: true })
    expect(VAULT_KIND_LABEL.vpn).toBe('VPN profile')
  })

  it('shows a different field set for at least two kinds', () => {
    // The bug in one assertion: if every kind rendered the same thing, the
    // picker would be decorative.
    const shapes = new Set(Object.values(KIND_FIELDS).map((f) => JSON.stringify(f)))
    expect(shapes.size).toBeGreaterThan(1)
  })
})

describe('switching kind is not destructive', () => {
  it('keeps a value that the new kind does not display', () => {
    // Only the rendering is conditional; the record is untouched.
    const asNote = { ...entry(), kind: 'note' as const }
    expect(asNote.password).toBe('s3cret')
    expect(asNote.username).toBe('bob')
    expect(asNote.url).toBe('https://example.com')
  })

  it('leaves a hidden value searchable, so it cannot be silently lost', () => {
    const asNote = { ...entry(), kind: 'note' as const }
    expect(vaultMatches(asNote, 'bob')).toBe(true)
    expect(vaultMatches(asNote, 'example.com')).toBe(true)
  })

  it('never puts a secret into the search haystack', () => {
    // Reading the password back out through search would be a leak, whatever
    // the kind.
    expect(vaultMatches(entry(), 's3cret')).toBe(false)
  })

  it('detects which stored values a kind hides, so the UI can say so', () => {
    expect(hiddenFieldsFor({ ...entry(), kind: 'note' })).toEqual(['URL', 'username', 'password'])
  })

  it('reports nothing hidden when the kind shows everything that is set', () => {
    expect(hiddenFieldsFor(entry())).toEqual([])
  })

  it('flags a stored private key that the current kind does not show', () => {
    expect(hiddenFieldsFor({ ...entry(), kind: 'login', privateKey: 'PEM' })).toContain('private key')
  })

  it('never puts private key material into the search haystack', () => {
    const k = { ...entry(), kind: 'sshkey' as const, privateKey: 'PRIVATE-MATERIAL', publicKey: 'ssh-ed25519 AAAA deploy@box' }
    expect(vaultMatches(k, 'PRIVATE-MATERIAL')).toBe(false)
    // The public half is not a secret and carries the key comment, which is
    // the useful thing to search an SSH key by.
    expect(vaultMatches(k, 'deploy@box')).toBe(true)
  })
})

describe('a VPN profile in the vault', () => {
  const vpnEntry = (): VaultEntry => ({
    ...entry(),
    id: 'v-wg',
    name: 'Office WireGuard',
    kind: 'vpn',
    url: '',
    username: '',
    password: '',
    privateKey: 'gI6EdUSYvn8ugXOt8QQD6Yc+JyiZxIhp3GInSWRfWGE=',
    tags: ['vpn', 'wireguard'],
    fields: [
      { id: 'f1', key: 'presharedKey:PUBKEY', value: 'PRESHARED-MATERIAL', secret: true }
    ]
  })

  it('holds key material rather than a path to it, so it travels with a backup', () => {
    // The whole reason a WireGuard key lives here and not in the OS keychain: a
    // keychain entry is machine-local and no encrypted backup can carry it.
    expect(vpnEntry().privateKey).toBeTruthy()
    expect(hiddenFieldsFor(vpnEntry())).toEqual([])
  })

  it('never puts VPN key material into the search haystack', () => {
    const e = vpnEntry()
    expect(vaultMatches(e, 'gI6EdUSYvn8ugXOt8QQD6Yc')).toBe(false)
    expect(vaultMatches(e, 'PRESHARED-MATERIAL')).toBe(false)
    // The custom field's key names which peer it belongs to and is not secret,
    // which is what makes an entry with six preshared keys navigable.
    expect(vaultMatches(e, 'presharedKey:PUBKEY')).toBe(true)
    expect(vaultMatches(e, 'Office WireGuard')).toBe(true)
  })
})
