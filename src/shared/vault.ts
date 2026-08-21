// A free-form key/value pair on a vault entry. `secret` fields are masked in
// the UI until revealed.
export interface VaultField {
  id: string
  key: string
  value: string
  secret: boolean
}

export type VaultKind = 'login' | 'url' | 'key' | 'note'

export interface VaultEntry {
  id: string
  name: string
  kind: VaultKind
  url: string
  username: string
  password: string
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
    ...e.tags,
    ...e.fields.flatMap((f) => [f.key, f.secret ? '' : f.value])
  ]
  return hay.some((h) => h?.toLowerCase().includes(q))
}
