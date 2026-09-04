// @vitest-environment jsdom
import { describe, expect, it } from 'vitest'
import { stubBridge } from './setup/renderer'
import { initPersistence } from '../src/renderer/src/store/persist'
import { useApp } from '../src/renderer/src/store/app'

// Whether the app has READ its saved servers yet, which is not the same
// question as whether it has any.
//
// Panels hold their "no servers" line until this is set, so the flag failing to
// arrive is not a cosmetic bug: it is a screen that says "Reading your
// servers…" until somebody closes the app. The panel tests set the flag by
// hand and therefore cannot catch that — a mutation deleting the line that
// signals it left all seventeen of them green.
//
// So these drive the real function, and the cases that matter are the unhappy
// ones. A load that throws and a build with no data bridge are both DEFINITE
// answers: nothing is coming later, and pretending otherwise trades a wrong
// claim for a spinner that never stops.

describe('signalling that the saved data has been read', () => {
  it('is false before anything runs', () => {
    expect(useApp.getState().hydrated).toBe(false)
  })

  it('is set after a normal load', async () => {
    stubBridge({
      data: { load: async () => null, save: async () => undefined },
      workspaceLock: { ids: async () => [] },
      vault: { setAutoLock: async () => undefined },
      ssh: { setPoolIdle: async () => undefined },
      jobs: { setDetached: async () => undefined }
    } as never)
    await initPersistence()
    expect(useApp.getState().hydrated).toBe(true)
  })

  it('is set when there is no data bridge at all to load from', async () => {
    // The capability is missing from this build. Nothing will ever arrive, so
    // waiting for it is waiting forever.
    stubBridge({})
    await initPersistence()
    expect(useApp.getState().hydrated).toBe(true)
  })

  it('is set even when the load throws', async () => {
    // A corrupt or unreadable data file. The servers are not coming, and the
    // panels must be allowed to say what they know rather than spin.
    stubBridge({
      data: {
        load: async () => {
          throw new Error('data file is unreadable')
        },
        save: async () => undefined
      }
    } as never)
    await expect(initPersistence()).rejects.toThrow('unreadable')
    expect(useApp.getState().hydrated).toBe(true)
  })
})
