// A free-form key/value pair on a vault entry. `secret` fields are masked in
// the UI until revealed.
export interface VaultField {
  id: string
  key: string
  value: string
  secret: boolean
}

export type VaultKind = 'login' | 'url' | 'key' | 'sshkey' | 'note'

export interface VaultEntry {
  id: string
  name: string
  kind: VaultKind
  url: string
  username: string
  // Doubles as the key passphrase on an `sshkey` entry. One secret slot, whose
  // label changes with the kind, rather than a second column that is null on
  // every other kind.
  password: string
  // PEM material for an `sshkey` entry. Optional because every other kind
  // leaves them empty, and absent on entries written before this existed.
  //
  // The private key is stored here rather than referenced by path: a path is
  // the one credential ShellPilot never actually held — not in the OS keychain,
  // not in the encrypted vault, just a filename pointing at plaintext on disk,
  // which also does not travel with an encrypted backup.
  privateKey?: string
  publicKey?: string
  notes: string
  tags: string[]
  fields: VaultField[]
  createdAt: string
  updatedAt: string
}

export interface VaultStatus {
  // Whether a vault file exists yet — false means the user still has to choose
  // a master password.
  exists: boolean
  unlocked: boolean
  entryCount: number
}

export interface VaultResult {
  ok: boolean
  error?: string
}

export interface VaultListResult extends VaultResult {
  entries?: VaultEntry[]
}

export const VAULT_KIND_LABEL: Record<VaultKind, string> = {
  login: 'Login',
  url: 'URL',
  key: 'API key',
  sshkey: 'SSH key',
  note: 'Note'
}

// Matches an entry against a search query across every stored field, so the
// user can find things by value (a hostname, a username) not just by title.
export function vaultMatches(e: VaultEntry, query: string): boolean {
  const q = query.trim().toLowerCase()
  if (!q) return true
  const hay = [
    e.name,
    e.url,
    e.username,
    e.notes,
    // The public half is not a secret and is the useful thing to search by —
    // it carries the key's comment, which is usually user@host. The private
    // key and the passphrase are never in here, same as every other secret.
    e.publicKey,
    ...e.tags,
    ...e.fields.flatMap((f) => [f.key, f.secret ? '' : f.value])
  ]
  return hay.some((h) => h?.toLowerCase().includes(q))
}

export type VaultSecretSlot = 'password' | 'key' | 'passphrase'

export interface VaultKindFields {
  url: boolean
  username: boolean
  secret: VaultSecretSlot | null
  keys?: boolean
}

// Which built-in fields each kind shows. Lives here rather than in the view so
// the tests exercise the real map: when this started as a copy inside the test
// file, adding a kind left the copy behind and the coverage assertion was the
// only thing that noticed.
//
// Name, tags, custom fields and notes are on every kind and are not listed.
export const VAULT_KIND_FIELDS: Record<VaultKind, VaultKindFields> = {
  login: { url: true, username: true, secret: 'password' },
  url: { url: true, username: false, secret: null },
  key: { url: true, username: false, secret: 'key' },
  // username is the account the key logs in as, worth keeping beside the key
  // rather than only on each server that uses it.
  sshkey: { url: false, username: true, secret: 'passphrase', keys: true },
  note: { url: false, username: false, secret: null }
}

export const VAULT_SECRET_LABEL: Record<VaultSecretSlot, string> = {
  password: 'Password',
  key: 'API key',
  passphrase: 'Passphrase'
}

// Values an entry is holding that its current kind does not display. Stored and
// searchable, but invisible — which is its own trap, so the UI says so.
export function hiddenFieldsFor(e: VaultEntry): string[] {
  const shown = VAULT_KIND_FIELDS[e.kind] ?? VAULT_KIND_FIELDS.login
  return [
    !shown.url && e.url ? 'URL' : null,
    !shown.username && e.username ? 'username' : null,
    !shown.secret && e.password ? 'password' : null,
    !shown.keys && e.privateKey ? 'private key' : null
  ].filter((v): v is string => v !== null)
}
