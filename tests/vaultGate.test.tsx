// @vitest-environment jsdom
import { describe, expect, it, vi } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import { stubBridge } from './setup/renderer'
import { VaultView } from '../src/renderer/src/components/vault/VaultView'
import { useVault } from '../src/renderer/src/store/vault'
import { useApp } from '../src/renderer/src/store/app'

// The vault gate, and the two things it got wrong in front of a real user.
//
// Both are about the same mistake in opposite directions: deciding something
// before the answer has arrived, and refusing to act after the user has plainly
// asked. Neither is visible to a test that only checks the unlocked browser.

/** A bridge whose `vault.status()` never settles, which is what a keychain
 *  prompt actually does to it: safeStorage blocks for as long as the person
 *  takes to answer, and on this machine that was long enough to screenshot. */
function pendingStatusBridge(): void {
  stubBridge({
    vault: {
      status: () => new Promise(() => {}),
      list: async () => ({ ok: true, entries: [] }),
      bioSupport: async () => ({ available: false, kind: 'none' }),
      bioEnabled: async () => false,
      bioScope: async () => null
    }
  } as never)
}

describe('before the main process has answered', () => {
  it('does not tell someone with a vault that they have none', async () => {
    // The reported bug, exactly. `exists` began as `false`, so for the whole
    // time the keychain prompt was up the screen offered to CREATE a vault --
    // two empty password fields, to a user whose vault was full of credentials.
    // "Nobody has said yet" is not "there isn't one".
    pendingStatusBridge()
    render(<VaultView />)

    await waitFor(() => expect(screen.getByText(/Opening the vault/i)).toBeTruthy())
    expect(screen.queryByText(/Create vault/i)).toBeNull()
    expect(screen.queryByPlaceholderText(/Confirm master password/i)).toBeNull()
  })

  it('offers to create one once main says there is none', async () => {
    // The other half: the unknown state must not be a permanent hiding place.
    stubBridge({
      vault: {
        status: async () => ({ exists: false, unlocked: false }),
        list: async () => ({ ok: true, entries: [] }),
        bioSupport: async () => ({ available: false, kind: 'none' }),
        bioEnabled: async () => false,
        bioScope: async () => null
      }
    } as never)
    render(<VaultView />)
    await waitFor(() => expect(screen.getByText(/Create vault/i)).toBeTruthy())
  })
})

describe('asking for Touch ID when the vault screen opens locked', () => {
  function lockedWithBiometrics(unlockSpy: () => Promise<void>): void {
    stubBridge({
      vault: {
        status: async () => ({ exists: true, unlocked: false }),
        list: async () => ({ ok: true, entries: [] }),
        bioSupport: async () => ({ available: true, kind: 'touch-id' }),
        bioEnabled: async () => true,
        bioScope: async () => 'persistent'
      }
    } as never)
    useVault.setState({ unlockWithBiometrics: unlockSpy as never })
  }

  it('raises the prompt without waiting for a click', async () => {
    const spy = vi.fn(async () => {})
    lockedWithBiometrics(spy)
    useApp.setState((s) => ({ settings: { ...s.settings, vaultAutoBiometricPrompt: true } }))

    render(<VaultView />)
    await waitFor(() => expect(spy).toHaveBeenCalled())
  })

  it('asks once and not again, so cancelling does not reopen the sheet', async () => {
    // promptTouchID rejects on cancel and the store turns that into a failed
    // result rather than a throw, leaving the vault locked. Without the guard
    // the effect sees the same still-locked state and prompts again: a sheet
    // the user cannot get out of by cancelling it.
    //
    // Re-rendering alone does NOT test this, and the first version of this test
    // did exactly that and passed with the guard deleted. The effect's deps do
    // not change on a plain re-render, so React never re-runs it and the guard
    // is never reached. What re-runs it in life is `busy` going true and back
    // to false around the attempt, so the spy does that here.
    // The flip happens on the FIRST attempt only. Without that bound, removing
    // the guard does not fail this test -- it hangs it: every prompt re-runs the
    // effect, which prompts again, forever. A test that hangs on a regression is
    // barely better than one that passes on it, so the second call is allowed to
    // happen and then counted.
    let flips = 0
    const spy = vi.fn(async () => {
      if (flips > 0) return
      flips += 1
      useVault.setState({ busy: true })
      await Promise.resolve()
      useVault.setState({ busy: false })
    })
    lockedWithBiometrics(spy)
    useApp.setState((s) => ({ settings: { ...s.settings, vaultAutoBiometricPrompt: true } }))

    render(<VaultView />)
    await waitFor(() => expect(spy).toHaveBeenCalledTimes(1))
    // Let every effect the busy flip scheduled actually run.
    await waitFor(() => expect(useVault.getState().busy).toBe(false))
    expect(spy).toHaveBeenCalledTimes(1)
  })

  it('stays quiet when the setting is off', async () => {
    const spy = vi.fn(async () => {})
    lockedWithBiometrics(spy)
    useApp.setState((s) => ({ settings: { ...s.settings, vaultAutoBiometricPrompt: false } }))

    render(<VaultView />)
    await waitFor(() => expect(screen.getByText(/Vault locked/i)).toBeTruthy())
    expect(spy).not.toHaveBeenCalled()
  })

  it('stays quiet when biometrics are not set up, however the setting reads', async () => {
    // The setting defaults on, so this is the common case: it must be inert
    // rather than raising a prompt for a key that does not exist.
    const spy = vi.fn(async () => {})
    stubBridge({
      vault: {
        status: async () => ({ exists: true, unlocked: false }),
        list: async () => ({ ok: true, entries: [] }),
        bioSupport: async () => ({ available: true, kind: 'touch-id' }),
        bioEnabled: async () => false,
        bioScope: async () => null
      }
    } as never)
    useVault.setState({ unlockWithBiometrics: spy as never })
    useApp.setState((s) => ({ settings: { ...s.settings, vaultAutoBiometricPrompt: true } }))

    render(<VaultView />)
    await waitFor(() => expect(screen.getByText(/Vault locked/i)).toBeTruthy())
    expect(spy).not.toHaveBeenCalled()
  })
})
