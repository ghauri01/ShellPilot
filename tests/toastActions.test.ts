import { beforeEach, describe, expect, it, vi } from 'vitest'
import { toast, useToasts } from '../src/renderer/src/store/toast'

// The toast store is the whole reason an error can offer a way out.
//
// It used to take a string and delete itself after 3.2 seconds, so a message
// could only ever describe a problem. "Unlock the vault and try again" left the
// reader to work out what a vault is, find it, unlock it, come back, and
// remember what they had been doing. These tests pin the three properties that
// stop that happening again: an action survives to the view, an actionable or
// failed message does not disappear while it is being read, and one problem
// reads as one problem.
//
// A plain zustand store, so it runs in the node environment the rest of the
// suite uses — no DOM required.

beforeEach(() => {
  useToasts.getState().clear()
  vi.useRealTimers()
})

describe('actions', () => {
  it('carries the action through to the view', () => {
    const run = vi.fn()
    toast('The vault is locked.', 'error', { label: 'Unlock vault', run })

    const [t] = useToasts.getState().toasts
    expect(t.action?.label).toBe('Unlock vault')
    t.action?.run()
    expect(run).toHaveBeenCalledOnce()
  })

  it('makes an informational message sticky once it has something to do', () => {
    toast('Imported. Confirm what each proxy exposes.', 'info', {
      label: 'Open profile',
      run: () => undefined
    })
    expect(useToasts.getState().toasts[0].sticky).toBe(true)
  })
})

describe('lifetime', () => {
  it('keeps errors until they are dismissed', () => {
    vi.useFakeTimers()
    toast('No response from the server.', 'error')
    vi.advanceTimersByTime(60_000)
    expect(useToasts.getState().toasts).toHaveLength(1)
  })

  it('still lets a plain confirmation go away by itself', () => {
    vi.useFakeTimers()
    toast('office saved', 'ok')
    expect(useToasts.getState().toasts).toHaveLength(1)
    vi.advanceTimersByTime(5_000)
    expect(useToasts.getState().toasts).toHaveLength(0)
  })

  it('dismisses on request', () => {
    toast('No response from the server.', 'error')
    const { id } = useToasts.getState().toasts[0]
    useToasts.getState().dismiss(id)
    expect(useToasts.getState().toasts).toHaveLength(0)
  })
})

describe('duplicates', () => {
  it('collapses an identical message rather than stacking it', () => {
    // A reconnect loop emits the same sentence repeatedly. Three copies of one
    // problem reads as three problems.
    toast('Lost the connection to the server.', 'error')
    toast('Lost the connection to the server.', 'error')
    toast('Lost the connection to the server.', 'error')
    expect(useToasts.getState().toasts).toHaveLength(1)
  })

  it('keeps the newest action when a message repeats', () => {
    const stale = vi.fn()
    const fresh = vi.fn()
    toast('The vault is locked.', 'error', { label: 'Unlock', run: stale })
    toast('The vault is locked.', 'error', { label: 'Unlock', run: fresh })

    const [t] = useToasts.getState().toasts
    t.action?.run()
    expect(fresh).toHaveBeenCalledOnce()
    expect(stale).not.toHaveBeenCalled()
  })

  it('does not collapse two genuinely different problems', () => {
    toast('No response from the server.', 'error')
    toast('The local port is already in use.', 'error')
    expect(useToasts.getState().toasts).toHaveLength(2)
  })
})
