import { create } from 'zustand'

// Whether the walkthrough has been seen. A UI preference, so it lives with the
// UI rather than in the workspace data file — it is about this installation,
// not about the servers in it, and it should not travel in an encrypted backup.
const SEEN_KEY = 'shellpilot.onboarding.seen'

interface OnboardingState {
  open: boolean
  step: number
  start: () => void
  next: () => void
  back: () => void
  goTo: (i: number) => void
  finish: () => void
  // Opens on a first run and never again on its own; Settings can always
  // reopen it.
  openIfFirstRun: () => void
}

export const useOnboarding = create<OnboardingState>((set, get) => ({
  open: false,
  step: 0,

  start: () => set({ open: true, step: 0 }),
  next: () => set({ step: get().step + 1 }),
  back: () => set({ step: Math.max(0, get().step - 1) }),
  goTo: (i) => set({ step: Math.max(0, i) }),

  finish: () => {
    // Written on finish AND on skip: someone who dismissed it has decided, and
    // showing it again on next launch would be nagging.
    try {
      localStorage.setItem(SEEN_KEY, '1')
    } catch {
      /* private mode or a wiped profile: worst case it offers once more */
    }
    set({ open: false, step: 0 })
  },

  openIfFirstRun: () => {
    let seen = false
    try {
      seen = localStorage.getItem(SEEN_KEY) === '1'
    } catch {
      seen = false
    }
    if (!seen) set({ open: true, step: 0 })
  }
}))
