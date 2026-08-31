import { create } from 'zustand'

export type ToastKind = 'info' | 'ok' | 'error'

/** The thing to do about it.
 *
 *  A message that tells someone to go and do something, without giving them a
 *  way to do it, has handed them a research task. "Unlock the vault and try
 *  again" means: find the vault, work out what a vault is, unlock it, come back,
 *  and remember what you were doing. The button removes all of that. */
export interface ToastAction {
  label: string
  run: () => void
}

export interface Toast {
  id: number
  kind: ToastKind
  message: string
  action?: ToastAction
  /** Errors and anything with an action stay until dismissed. A message worth
   *  acting on that disappears after three seconds is worse than no message:
   *  the user knows something went wrong and has no way to find out what. */
  sticky: boolean
}

let tid = 0

// Long enough to read a sentence, short enough not to sit in the way. Only
// applies to transient confirmations now.
const AUTO_DISMISS_MS = 3200

interface ToastState {
  toasts: Toast[]
  push: (message: string, kind?: ToastKind, action?: ToastAction) => void
  dismiss: (id: number) => void
  clear: () => void
}

export const useToasts = create<ToastState>((set) => ({
  toasts: [],
  push: (message, kind = 'info', action) => {
    const id = ++tid
    const sticky = kind === 'error' || action !== undefined
    set((s) => {
      // Collapse an identical message rather than stacking it. A failing
      // reconnect can emit the same sentence repeatedly, and three copies of
      // one problem reads as three problems.
      const withoutDuplicate = s.toasts.filter((t) => t.message !== message)
      return { toasts: [...withoutDuplicate, { id, kind, message, action, sticky }] }
    })
    if (!sticky) {
      setTimeout(() => set((s) => ({ toasts: s.toasts.filter((t) => t.id !== id) })), AUTO_DISMISS_MS)
    }
  },
  dismiss: (id) => set((s) => ({ toasts: s.toasts.filter((t) => t.id !== id) })),
  clear: () => set({ toasts: [] })
}))

/**
 * Show a message.
 *
 * Pass an `action` whenever the message asks the user to do something — which
 * is nearly always, for an error. `toast('Unlock the vault and try again')` is
 * a dead end; `toast('...', 'error', { label: 'Unlock vault', run: unlock })`
 * is a fix.
 */
export const toast = (message: string, kind?: ToastKind, action?: ToastAction): void =>
  useToasts.getState().push(message, kind, action)
