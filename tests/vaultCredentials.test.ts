import { describe, it, expect, beforeEach, vi, afterEach } from 'vitest'
import type { SshHop } from '../src/shared/ssh'
import type { VaultEntry } from '../src/shared/vault'

// The vault used to be a password manager sitting beside the SSH client with
// no connection to it: server credentials lived in the OS keychain, and a
// private key lived in neither — just a path to plaintext on disk that did not
// travel with an encrypted backup. These cover the wiring that closes that.

const secrets = new Map<string, string>()
let vaultEntries: VaultEntry[] = []
let vaultUnlocked = true
let vaultExists = true

vi.mock('../src/main/services/secrets', () => ({
  getSecret: (id: string) => secrets.get(id) ?? null,
  setSecret: (id: string, v: string) => void secrets.set(id, v)
}))

vi.mock('../src/main/services/vault', () => ({
  vaultStatus: () => ({ exists: vaultExists, unlocked: vaultUnlocked, entryCount: vaultEntries.length }),
  vaultList: () => ({ ok: true, entries: vaultEntries })
}))

const { resolveSecrets, credentialSourceFor, knownSecretValuesForServer, VaultLockedError } = await import(
  '../src/main/services/credentialResolver'
)

const entry = (patch: Partial<VaultEntry>): VaultEntry => ({
  id: 'v1',
  name: 'Prod key',
  kind: 'sshkey',
  url: '',
  username: 'deploy',
  password: '',
  notes: '',
  tags: [],
  fields: [],
  createdAt: '',
  updatedAt: '',
  ...patch
})

// `SshHop` itself, not a five-field literal type. The literal had no
// `password`, `privateKey`, `keyPath` or `passphrase` on it — the four fields
// every assertion below reads off the RESULT — so `resolveSecrets<T>` returned
// that same narrow T and each `cfg.privateKey` was a property access the
// compiler had no member for. It is also why three call sites carried
// `as never`: the cast was standing in for the type this helper should have
// had all along.
const hop = (): SshHop & { serverId: string } => ({
  host: '10.0.0.1',
  port: 22,
  username: 'root',
  auth: 'key',
  serverId: 's1'
})

beforeEach(() => {
  secrets.clear()
  vaultEntries = []
  vaultUnlocked = true
  vaultExists = true
})
afterEach(() => vi.restoreAllMocks())

describe('resolving a credential from the vault', () => {
  it('supplies key material and its passphrase from the referenced entry', () => {
    vaultEntries = [entry({ privateKey: '-----BEGIN OPENSSH PRIVATE KEY-----\nabc\n', password: 'phrase' })]
    secrets.set('s1', JSON.stringify({ vaultEntryId: 'v1' }))

    const cfg = resolveSecrets(hop())
    expect(cfg.privateKey).toContain('BEGIN OPENSSH PRIVATE KEY')
    expect(cfg.passphrase).toBe('phrase')
  })

  it('supplies a password from a login entry', () => {
    vaultEntries = [entry({ id: 'v2', kind: 'login', privateKey: undefined, password: 'hunter2' })]
    secrets.set('s1', JSON.stringify({ vaultEntryId: 'v2' }))

    expect(resolveSecrets({ ...hop(), auth: 'password' }).password).toBe('hunter2')
  })

  it('fails clearly when the vault is locked instead of silently trying nothing', () => {
    // ssh2 reports every auth problem as "All configured authentication methods
    // failed", so an unhelpful failure here is indistinguishable from a wrong
    // password.
    vaultUnlocked = false
    secrets.set('s1', JSON.stringify({ vaultEntryId: 'v1' }))
    expect(() => resolveSecrets(hop())).toThrow(VaultLockedError)
    expect(() => resolveSecrets(hop())).toThrow(/vault is locked/i)
  })

  it('does not fall back to a stale keychain copy when the vault is locked', () => {
    // Authenticating with an old credential the user has since rotated in the
    // vault is worse than refusing to connect.
    vaultUnlocked = false
    secrets.set('s1', JSON.stringify({ vaultEntryId: 'v1', password: 'old-and-rotated' }))
    expect(() => resolveSecrets({ ...hop(), auth: 'password' })).toThrow(VaultLockedError)
  })

  it('leaves a server saved before the vault held credentials working unchanged', () => {
    secrets.set('s1', JSON.stringify({ keyPath: '/home/me/.ssh/id_ed25519', passphrase: 'p' }))
    const cfg = resolveSecrets(hop())
    expect(cfg.keyPath).toBe('/home/me/.ssh/id_ed25519')
    expect(cfg.passphrase).toBe('p')
  })

  it('never overrides a credential the caller supplied inline', () => {
    vaultEntries = [entry({ privateKey: 'FROM-VAULT' })]
    secrets.set('s1', JSON.stringify({ vaultEntryId: 'v1' }))
    expect(resolveSecrets({ ...hop(), privateKey: 'INLINE' }).privateKey).toBe('INLINE')
  })
})

describe('reporting where a credential lives', () => {
  it('distinguishes vault, keychain and nothing at all', () => {
    secrets.set('a', JSON.stringify({ vaultEntryId: 'v1' }))
    secrets.set('b', JSON.stringify({ password: 'x' }))
    secrets.set('c', JSON.stringify({}))
    expect(credentialSourceFor('a')).toEqual({ source: 'vault', vaultEntryId: 'v1' })
    expect(credentialSourceFor('b').source).toBe('keychain')
    expect(credentialSourceFor('c').source).toBe('none')
    expect(credentialSourceFor('missing').source).toBe('none')
  })
})

describe('redaction covers vault-backed credentials', () => {
  it('redacts a vault passphrase and private key from agent-visible output', () => {
    // A credential must not leak through command output just because it moved
    // from the keychain into the vault.
    vaultEntries = [entry({ privateKey: 'PRIVATE-MATERIAL', password: 'phrase' })]
    secrets.set('s1', JSON.stringify({ vaultEntryId: 'v1' }))
    const values = knownSecretValuesForServer('s1')
    expect(values).toContain('PRIVATE-MATERIAL')
    expect(values).toContain('phrase')
  })

  it('returns nothing rather than throwing when the vault is locked', () => {
    vaultUnlocked = false
    secrets.set('s1', JSON.stringify({ vaultEntryId: 'v1' }))
    expect(knownSecretValuesForServer('s1')).toEqual([])
  })
})
