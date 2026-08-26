import { describe, it, expect, vi, afterEach } from 'vitest'
import { bridgeOn, bridgeHas } from '../src/renderer/src/lib/bridge'

afterEach(() => vi.restoreAllMocks())

describe('bridgeOn', () => {
  it('subscribes and returns the unsubscribe callback', () => {
    const off = vi.fn()
    const register = vi.fn().mockReturnValue(off)
    const cb = vi.fn()

    const result = bridgeOn('ns.onThing', register, cb)
    expect(register).toHaveBeenCalledWith(cb)
    result()
    expect(off).toHaveBeenCalled()
  })

  it('degrades to a no-op when the preload method is missing', () => {
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {})
    // The dev-time failure: renderer newer than preload. This must not throw —
    // it used to take the whole window down through the error boundary.
    expect(() => bridgeOn('ns.onMissing', undefined, vi.fn())()).not.toThrow()
    expect(warn).toHaveBeenCalledOnce()
  })

  it('warns once, not on every component that hits it', () => {
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {})
    bridgeOn('a', undefined, vi.fn())
    bridgeOn('b', undefined, vi.fn())
    bridgeOn('c', undefined, vi.fn())
    expect(warn.mock.calls.length).toBeLessThanOrEqual(1)
  })
})

describe('bridgeHas', () => {
  it('reports whether a namespace exposes a callable method', () => {
    expect(bridgeHas({ go: () => {} }, 'go')).toBe(true)
    expect(bridgeHas({ go: 'not a function' }, 'go')).toBe(false)
    expect(bridgeHas({}, 'go')).toBe(false)
    expect(bridgeHas(undefined, 'go')).toBe(false)
  })
})
