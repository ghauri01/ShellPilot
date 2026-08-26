import { create } from 'zustand'
import type { VaultEntry, VaultField, VaultKind } from '../../../shared/vault'

let seq = 0
const uid = (p: string): string => `${p}-${Date.now().toString(36)}-${seq++}`

export function newEntry(kind: VaultKind = 'login'): VaultEntry {
  const now = new Date().toISOString()
  return {
    id: uid('v'),
    name: 'New entry',
    kind,
    url: '',
    username: '',
    password: '',
    notes: '',
    tags: [],
    fields: [],
    createdAt: now,
    updatedAt: now
  }
}

export function newField(): VaultField {
  return { id: uid('f'), key: '', value: '', secret: false }
}

interface VaultState {
  exists: boolean
  unlocked: boolean
  entries: VaultEntry[]
  selectedId: string | null
  query: string
  error: string | null
  busy: boolean

  refresh: () => Promise<void>
  create: (password: string) => Promise<boolean>
  unlock: (password: string) => Promise<boolean>
  lock: () => Promise<void>
  changePassword: (current: string, next: string) => Promise<boolean>
  destroy: () => Promise<boolean>

  select: (id: string | null) => void
  setQuery: (q: string) => void
  addEntry: (kind?: VaultKind) => Promise<void>
  // Creates a fully-populated entry and hands back its id, so a caller that
  // needs to reference the new entry — saving a server's credential into the
  // vault — does not have to guess which one it just made.
  createEntry: (kind: VaultKind, patch: Partial<VaultEntry>) => Promise<string | null>
  updateEntry: (id: string, patch: Partial<VaultEntry>) => Promise<void>
  deleteEntry: (id: string) => Promise<void>
  clearError: () => void
}

// Entries only ever live here while the vault is unlocked; locking drops them.
export const useVault = create<VaultState>((set, get) => ({
  exists: false,
  unlocked: false,
  entries: [],
  selectedId: null,
  query: '',
  error: null,
  busy: false,

  refresh: async () => {
    const st = await window.shellpilot?.vault.status()
    if (!st) return
    set({ exists: st.exists, unlocked: st.unlocked })
    if (st.unlocked) {
      const r = await window.shellpilot?.vault.list()
      if (r?.ok && r.entries) set({ entries: r.entries })
    }
  },

  create: async (password) => {
    set({ busy: true, error: null })
    const r = await window.shellpilot?.vault.create(password)
    set({ busy: false })
    if (!r?.ok) {
      set({ error: r?.error ?? 'Could not create the vault.' })
      return false
    }
    set({ exists: true, unlocked: true, entries: [] })
    return true
  },

  unlock: async (password) => {
    set({ busy: true, error: null })
    const r = await window.shellpilot?.vault.unlock(password)
    set({ busy: false })
    if (!r?.ok) {
      set({ error: r?.error ?? 'Could not unlock the vault.' })
      return false
    }
    set({ unlocked: true })
    await get().refresh()
    return true
  },

  lock: async () => {
    await window.shellpilot?.vault.lock()
    set({ unlocked: false, entries: [], selectedId: null, query: '', error: null })
  },

  changePassword: async (current, next) => {
    set({ busy: true, error: null })
    const r = await window.shellpilot?.vault.changePassword(current, next)
    set({ busy: false })
    if (!r?.ok) {
      set({ error: r?.error ?? 'Could not change the password.' })
      return false
    }
    return true
  },

  destroy: async () => {
    const r = await window.shellpilot?.vault.destroy()
    if (!r?.ok) {
      set({ error: r?.error ?? 'Could not delete the vault.' })
      return false
    }
    set({ exists: false, unlocked: false, entries: [], selectedId: null })
    return true
  },

  select: (id) => set({ selectedId: id }),
  setQuery: (q) => set({ query: q }),

  addEntry: async (kind = 'login') => {
    const e = newEntry(kind)
    const entries = [...get().entries, e]
    set({ entries, selectedId: e.id })
    await persist(entries, set)
  },

  createEntry: async (kind, patch) => {
    const e = { ...newEntry(kind), ...patch }
    const entries = [...get().entries, e]
    set({ entries })
    await persist(entries, set)
    // persist() surfaces a failure through `error`; a caller must not be told
    // an id that was never written to disk.
    return get().error ? null : e.id
  },

  updateEntry: async (id, patch) => {
    const entries = get().entries.map((e) =>
      e.id === id ? { ...e, ...patch, updatedAt: new Date().toISOString() } : e
    )
    set({ entries })
    await persist(entries, set)
  },

  deleteEntry: async (id) => {
    const entries = get().entries.filter((e) => e.id !== id)
    set({ entries, selectedId: get().selectedId === id ? null : get().selectedId })
    await persist(entries, set)
  },

  clearError: () => set({ error: null })
}))

async function persist(
  entries: VaultEntry[],
  set: (partial: Partial<VaultState>) => void
): Promise<void> {
  const r = await window.shellpilot?.vault.save(entries)
  if (!r?.ok) set({ error: r?.error ?? 'Could not save the vault.' })
}
