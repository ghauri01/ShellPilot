import { create } from 'zustand'
import { useApp } from './app'
import type { VaultEntry, VaultField, VaultKind } from '../../../shared/vault'

let seq = 0
const uid = (p: string): string => `${p}-${Date.now().toString(36)}-${seq++}`

// A new entry belongs to the workspace it was made in. That is the behaviour
// people expect from a workspace, and the alternative — defaulting to shared —
// silently reproduces the problem this exists to fix.
export function newEntry(kind: VaultKind = 'login', workspaceId?: string): VaultEntry {
  const now = new Date().toISOString()
  return {
    id: uid('v'),
    name: 'New entry',
    kind,
    workspaceId,
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
  /**
   * Whether a vault file is there -- `null` until the main process has said.
   *
   * NOT a boolean, and the third state is the whole point. `status()` reaches
   * safeStorage, which on macOS can block on a keychain prompt for as long as
   * the user takes to answer it. While that was pending this was `false`, and
   * `false` renders the CREATE screen: a user with a vault full of credentials
   * was shown "Create vault" and two empty password fields, which reads as
   * "your vault is gone". Nobody knows yet is not the same as there isn't one.
   */
  exists: boolean | null
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
  // Biometric unlock. `bioKind` is what to call it on this platform, so the
  // UI never says "Touch ID" on a machine that does not have one.
  bioAvailable: boolean
  bioKind: string
  bioReason: string | null
  bioEnabled: boolean
  refreshBiometrics: () => Promise<void>
  unlockWithBiometrics: () => Promise<boolean>
  bioScope: 'session' | 'persistent' | null
  setBiometrics: (on: boolean, scope?: 'session' | 'persistent') => Promise<boolean>
}

// Entries only ever live here while the vault is unlocked; locking drops them.
export const useVault = create<VaultState>((set, get) => ({
  exists: null,
  unlocked: false,
  entries: [],
  selectedId: null,
  query: '',
  error: null,
  busy: false,
  bioAvailable: false,
  bioKind: 'none',
  bioReason: null,
  bioEnabled: false,
  bioScope: null,

  refreshBiometrics: async () => {
    const v = window.shellpilot?.vault
    if (typeof v?.bioSupport !== 'function') return
    const [support, enabled, scope] = await Promise.all([
      v.bioSupport(),
      v.bioEnabled(),
      typeof v.bioScope === 'function' ? v.bioScope() : Promise.resolve(null)
    ])
    set({
      bioAvailable: !!support?.available,
      bioKind: support?.kind ?? 'none',
      bioReason: support?.reason ?? null,
      bioEnabled: !!enabled,
      bioScope: scope ?? null
    })
  },

  unlockWithBiometrics: async () => {
    const v = window.shellpilot?.vault
    if (typeof v?.bioUnlock !== 'function') return false
    set({ busy: true, error: null })
    const r = await v.bioUnlock()
    set({ busy: false })
    if (!r?.ok) {
      // A cancelled prompt should not shout; the password field is right
      // there and is the expected fallback.
      set({ error: r?.error ?? 'Biometric unlock failed.' })
      await get().refreshBiometrics()
      return false
    }
    set({ unlocked: true })
    await get().refresh()
    return true
  },

  setBiometrics: async (on, scope = 'session') => {
    const v = window.shellpilot?.vault
    if (typeof v?.bioEnable !== 'function') return false
    const r = on ? await v.bioEnable(scope) : await v.bioDisable()
    await get().refreshBiometrics()
    if (!r?.ok) set({ error: r?.error ?? 'Could not change biometric unlock.' })
    return !!r?.ok
  },

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
    const e = newEntry(kind, useApp.getState().activeWorkspaceId)
    const entries = [...get().entries, e]
    set({ entries, selectedId: e.id })
    await persist(entries, set)
  },

  createEntry: async (kind, patch) => {
    const e = { ...newEntry(kind, useApp.getState().activeWorkspaceId), ...patch }
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
