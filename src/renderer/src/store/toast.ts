import { create } from 'zustand'

export type ToastKind = 'info' | 'ok' | 'error'
export interface Toast {
  id: number
  kind: ToastKind
  message: string
}

let tid = 0

interface ToastState {
  toasts: Toast[]
  push: (message: string, kind?: ToastKind) => void
  dismiss: (id: number) => void
}

export const useToasts = create<ToastState>((set) => ({
  toasts: [],
  push: (message, kind = 'info') => {
    const id = ++tid
    set((s) => ({ toasts: [...s.toasts, { id, kind, message }] }))
    setTimeout(() => set((s) => ({ toasts: s.toasts.filter((t) => t.id !== id) })), 3200)
  },
  dismiss: (id) => set((s) => ({ toasts: s.toasts.filter((t) => t.id !== id) }))
}))

export const toast = (message: string, kind?: ToastKind): void =>
  useToasts.getState().push(message, kind)
