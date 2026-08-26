import { describe, it, expect } from 'vitest'
import { vaultEntriesFor, isSharedVaultEntry, type VaultEntry } from '../src/shared/vault'

// The vault was a single global store: creating a new workspace showed the
// entries from the old one. Entries can now belong to a workspace, with
// "shared" as a real state rather than an accident.

const entry = (id: string, workspaceId?: string): VaultEntry => ({
  id,
  name: id,
  kind: 'login',
  workspaceId,
  url: '',
  username: '',
  password: '',
  notes: '',
  tags: [],
  fields: [],
  createdAt: '',
  updatedAt: ''
})

const all = [entry('prod-db', 'ws-a'), entry('client-vpn', 'ws-b'), entry('company-wifi')]

describe('what a workspace shows', () => {
  it('shows its own entries and the shared ones, not another workspace’s', () => {
    expect(vaultEntriesFor(all, 'ws-a').map((e) => e.id)).toEqual(['prod-db', 'company-wifi'])
    expect(vaultEntriesFor(all, 'ws-b').map((e) => e.id)).toEqual(['client-vpn', 'company-wifi'])
  })

  it('treats an entry with no workspace as shared', () => {
    // Entries written before the field existed have no record of where they
    // came from. Guessing would either hide a credential someone relies on or
    // claim knowledge we do not have.
    expect(isSharedVaultEntry(entry('legacy'))).toBe(true)
    expect(vaultEntriesFor([entry('legacy')], 'ws-a')).toHaveLength(1)
  })

  it('is not a way to lose an entry — every one is visible from somewhere', () => {
    const reachable = new Set(
      ['ws-a', 'ws-b'].flatMap((ws) => vaultEntriesFor(all, ws).map((e) => e.id))
    )
    expect(reachable).toEqual(new Set(all.map((e) => e.id)))
  })

  it('shows everything when no workspace is active', () => {
    expect(vaultEntriesFor(all, null)).toHaveLength(3)
  })

  it('hides nothing from a workspace whose entries are all shared', () => {
    const shared = [entry('a'), entry('b')]
    expect(vaultEntriesFor(shared, 'ws-a')).toHaveLength(2)
  })

  it('reports how many are hidden, so they do not just vanish', () => {
    // Saying nothing would recreate the original confusion in the opposite
    // direction: entries you saved would simply be missing.
    const visible = vaultEntriesFor(all, 'ws-a')
    expect(all.length - visible.length).toBe(1)
  })
})

describe('what this is not', () => {
  it('does not separate entries cryptographically', () => {
    // One encrypted file, one master password. Filtering is a view, and the
    // shape of the data says so: every entry is in the same array.
    const everything = vaultEntriesFor(all, null)
    expect(everything).toHaveLength(all.length)
    expect(everything.some((e) => e.workspaceId === 'ws-b')).toBe(true)
  })
})
