import { describe, it, expect, beforeEach, vi } from 'vitest'
import { useOnboarding } from '../src/renderer/src/store/onboarding'
import { TOUR_STEPS } from '../src/renderer/src/components/onboarding/tourSteps'

const store = new Map<string, string>()

beforeEach(() => {
  store.clear()
  vi.stubGlobal('localStorage', {
    getItem: (k: string) => store.get(k) ?? null,
    setItem: (k: string, v: string) => void store.set(k, v),
    removeItem: (k: string) => void store.delete(k)
  })
  useOnboarding.setState({ open: false, step: 0 })
})

describe('when the walkthrough appears', () => {
  it('opens on a first run', () => {
    useOnboarding.getState().openIfFirstRun()
    expect(useOnboarding.getState().open).toBe(true)
  })

  it('does not reappear once it has been finished', () => {
    useOnboarding.getState().openIfFirstRun()
    useOnboarding.getState().finish()
    useOnboarding.setState({ open: false })

    useOnboarding.getState().openIfFirstRun()
    expect(useOnboarding.getState().open).toBe(false)
  })

  it('does not reappear after being skipped either', () => {
    // Skip goes through finish(): someone who dismissed it has decided, and
    // showing it again next launch would be nagging.
    useOnboarding.getState().start()
    useOnboarding.getState().finish()
    useOnboarding.getState().openIfFirstRun()
    expect(useOnboarding.getState().open).toBe(false)
  })

  it('can always be reopened deliberately, even after being dismissed', () => {
    useOnboarding.getState().finish()
    useOnboarding.getState().start()
    expect(useOnboarding.getState().open).toBe(true)
    expect(useOnboarding.getState().step).toBe(0)
  })

  it('still opens when localStorage is unavailable rather than throwing', () => {
    // A wiped profile or a locked-down environment must not crash the app on
    // launch; offering the tour once more is the harmless failure.
    vi.stubGlobal('localStorage', {
      getItem: () => {
        throw new Error('denied')
      },
      setItem: () => {
        throw new Error('denied')
      }
    })
    expect(() => useOnboarding.getState().openIfFirstRun()).not.toThrow()
    expect(useOnboarding.getState().open).toBe(true)
    expect(() => useOnboarding.getState().finish()).not.toThrow()
  })
})

describe('moving through it', () => {
  it('advances and goes back', () => {
    const s = useOnboarding.getState()
    s.start()
    s.next()
    expect(useOnboarding.getState().step).toBe(1)
    useOnboarding.getState().back()
    expect(useOnboarding.getState().step).toBe(0)
  })

  it('cannot go back past the first step', () => {
    useOnboarding.getState().start()
    useOnboarding.getState().back()
    expect(useOnboarding.getState().step).toBe(0)
  })

  it('resets to the start when reopened', () => {
    useOnboarding.getState().start()
    useOnboarding.getState().goTo(4)
    useOnboarding.getState().finish()
    useOnboarding.getState().start()
    expect(useOnboarding.getState().step).toBe(0)
  })
})

describe('the steps themselves', () => {
  it('covers the features a new user would otherwise find by accident', () => {
    const ids = TOUR_STEPS.map((s) => s.id)
    for (const required of ['workspaces', 'connections', 'vault', 'monitor', 'tunnels', 'ai']) {
      expect(ids, required).toContain(required)
    }
  })

  it('stays short enough that people finish it', () => {
    // A tour people skip teaches nothing.
    expect(TOUR_STEPS.length).toBeLessThanOrEqual(9)
  })

  it('has unique ids, since they key the progress dots', () => {
    expect(new Set(TOUR_STEPS.map((s) => s.id)).size).toBe(TOUR_STEPS.length)
  })

  it('gives every step something to read', () => {
    for (const s of TOUR_STEPS) {
      expect(s.title.length, s.id).toBeGreaterThan(0)
      expect(s.body.length, s.id).toBeGreaterThan(40)
    }
  })

  it('only points at views that exist', () => {
    const views = ['connections', 'databases', 'tunnels', 'monitor', 'vault', 'ai']
    for (const s of TOUR_STEPS) {
      if (s.view) expect(views, s.id).toContain(s.view)
    }
  })
})
