import { describe, expect, it } from 'vitest'
import {
  AUTOSTART_UNSUPPORTED_REASON,
  autoStartRequest,
  autoStartSupported,
  hiddenLaunchSupported
} from '../src/shared/autostart'

// Starting with the machine, and the two ways this could quietly lie.
//
// The whole feature is one Electron call. What is worth testing is not the
// call but the platform rules around it, because both failure modes are silent:
// a switch that stores nothing, and a switch that stores something the OS
// ignores. Neither shows an error; both leave a user believing their fleet is
// being watched from login when it is not.

describe('which platforms can do this at all', () => {
  it('is macOS and Windows, and explicitly not Linux', () => {
    expect(autoStartSupported('darwin')).toBe(true)
    expect(autoStartSupported('win32')).toBe(true)
    // Electron's setLoginItemSettings is a no-op here. Accepting the setting
    // anyway would be a switch that stores nothing and reports success.
    expect(autoStartSupported('linux')).toBe(false)
  })

  it('says why rather than showing an inert switch', () => {
    expect(AUTOSTART_UNSUPPORTED_REASON).toMatch(/Linux/)
    expect(AUTOSTART_UNSUPPORTED_REASON).toMatch(/startup applications/)
  })
})

describe('a hidden launch', () => {
  it('is macOS only, because Windows accepts the flag and ignores it', () => {
    expect(hiddenLaunchSupported('darwin')).toBe(true)
    expect(hiddenLaunchSupported('win32')).toBe(false)
    expect(hiddenLaunchSupported('linux')).toBe(false)
  })

  it('is dropped rather than passed through on a platform that ignores it', () => {
    // The failure this prevents: the user turns on "start in the background" on
    // Windows, we pass it to Electron, Electron ignores it, and the switch sits
    // there on for a behaviour that never happens.
    expect(autoStartRequest('win32', { openAtLogin: true, openAsHidden: true })).toEqual({
      openAtLogin: true,
      openAsHidden: false
    })
    expect(autoStartRequest('darwin', { openAtLogin: true, openAsHidden: true })).toEqual({
      openAtLogin: true,
      openAsHidden: true
    })
  })

  it('does not smuggle a truthy non-boolean through as enabled', () => {
    const sneaky = { openAtLogin: 'yes', openAsHidden: 1 } as unknown as {
      openAtLogin: boolean
      openAsHidden: boolean
    }
    expect(autoStartRequest('darwin', sneaky)).toEqual({
      openAtLogin: false,
      openAsHidden: false
    })
  })
})
