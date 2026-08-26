import { create } from 'zustand'

// A single place anything can ask "the vault needs to be open for this" and be
// answered by the user, rather than each caller inventing its own dialog — or,
// as before, the operation simply failing with advice the user then has to act
// on manually and retry by hand.

interface VaultPromptState {
  open: boolean
  reason: string
  resolve: ((unlocked: boolean) => void) | null
  request: (reason: string) => Promise<boolean>
  finish: (unlocked: boolean) => void
}

export const useVaultPrompt = create<VaultPromptState>((set, get) => ({
  open: false,
  reason: '',
  resolve: null,

  request: (reason) =>
    new Promise<boolean>((resolve) => {
      // A second request while one is already open joins the first rather than
      // stacking dialogs: connecting to three servers at once should ask once.
      const existing = get().resolve
      set({
        open: true,
        reason,
        resolve: (unlocked) => {
          existing?.(unlocked)
          resolve(unlocked)
        }
      })
    }),

  finish: (unlocked) => {
    get().resolve?.(unlocked)
    set({ open: false, resolve: null, reason: '' })
  }
}))
