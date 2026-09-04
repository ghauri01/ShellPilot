import { describe, it, expect, beforeEach, vi } from 'vitest'
import type { Mock } from 'vitest'
import { useVaultPrompt } from '../src/renderer/src/store/vaultPrompt'
import { isVaultLocked, withVaultUnlock } from '../src/renderer/src/lib/withVaultUnlock'
import { VaultLockedError, VAULT_LOCKED } from '../src/main/services/credentialResolver'

// A locked vault used to fail the operation with advice the user then had to
// go and act on somewhere else before starting over. These cover asking in
// place and carrying on.

// Electron rewrites a rejected IPC handler's error, so the class does not
// survive the trip to the renderer — only the message does.
const asIpcError = (e: Error): Error =>
  new Error(`Error invoking remote method 'ssh:connect': ${e.message}`)

beforeEach(() => {
  useVaultPrompt.setState({ open: false, reason: '', resolve: null })
})

describe('recognising the failure across the IPC boundary', () => {
  it('matches the marker after Electron has rewrapped the error', () => {
    expect(isVaultLocked(asIpcError(new VaultLockedError()))).toBe(true)
  })

  it('does not match an ordinary connection failure', () => {
    expect(isVaultLocked(new Error('All configured authentication methods failed'))).toBe(false)
    expect(isVaultLocked(new Error('ECONNREFUSED'))).toBe(false)
  })

  it('keeps the class and the token in step', () => {
    // If one is renamed without the other, the prompt silently stops opening.
    expect(new VaultLockedError().message).toContain(VAULT_LOCKED)
  })
})

describe('recognising the failure as a resolved result, not a rejection', () => {
  // The VPN paths do not throw when the vault is shut. They resolve with
  // `{ ok: false, errorCode: 'vault-locked' }`, because an IPC handler that
  // rejects loses its structure on the way to the renderer. A helper that only
  // inspected rejections therefore did nothing for them, which is exactly how
  // "unlock the vault and try again" survived as a dead end in the VPN
  // surfaces after it had been fixed everywhere else.
  it('matches an errorCode on a resolved result', () => {
    expect(isVaultLocked({ ok: false, errorCode: 'vault-locked' })).toBe(true)
  })

  it('matches the same code under `code`', () => {
    expect(isVaultLocked({ ok: false, code: 'vault-locked' })).toBe(true)
  })

  it('matches the marker carried on an `error` string', () => {
    expect(isVaultLocked({ ok: false, error: `something: ${VAULT_LOCKED}` })).toBe(true)
  })

  it('does not match a result that merely failed', () => {
    expect(isVaultLocked({ ok: false, errorCode: 'handshake-timeout' })).toBe(false)
    expect(isVaultLocked({ ok: true })).toBe(false)
  })

  it('does not match nothing at all', () => {
    expect(isVaultLocked(null)).toBe(false)
    expect(isVaultLocked(undefined)).toBe(false)
  })

  it('retries a resolved failure once the vault is open', async () => {
    let calls = 0
    const run = async (): Promise<{ ok: boolean; errorCode?: string }> => {
      calls++
      return calls === 1 ? { ok: false, errorCode: 'vault-locked' } : { ok: true }
    }
    const done = withVaultUnlock('Starting office', run)
    await Promise.resolve()
    useVaultPrompt.getState().finish(true)

    await expect(done).resolves.toEqual({ ok: true })
    expect(calls).toBe(2)
  })

  it('hands back the original result when the user cancels', async () => {
    let calls = 0
    const locked = { ok: false, errorCode: 'vault-locked' }
    const done = withVaultUnlock('Starting office', async () => {
      calls++
      return locked
    })
    await Promise.resolve()
    useVaultPrompt.getState().finish(false)

    // The original result, unchanged — not a throw, and not a second attempt
    // the user did not ask for.
    await expect(done).resolves.toBe(locked)
    expect(calls).toBe(1)
  })

  it('does not prompt for a resolved failure that is not about the vault', async () => {
    const done = withVaultUnlock('Starting office', async () => ({
      ok: false,
      errorCode: 'handshake-timeout'
    }))
    await expect(done).resolves.toEqual({ ok: false, errorCode: 'handshake-timeout' })
    expect(useVaultPrompt.getState().open).toBe(false)
  })

  it('is not tripped up by an empty object', () => {
    // A result that carries no code and no text at all must not be read as a
    // locked vault, or every shapeless failure would open the dialog.
    expect(isVaultLocked({})).toBe(false)
  })

  it('matches the marker carried on a `message` field', () => {
    // A plain object stringifies to "[object Object]", so both fields the two
    // shapes put text in have to be read directly.
    expect(isVaultLocked({ message: `something: ${VAULT_LOCKED}` })).toBe(true)
  })

  it('retries a resolved failure once, not forever', async () => {
    // Still locked after a successful unlock means the cause is something
    // else; a second dialog would be one the user cannot get rid of.
    let calls = 0
    const locked = { ok: false, errorCode: 'vault-locked' }
    const done = withVaultUnlock('Starting office', async () => {
      calls++
      return locked
    })
    await Promise.resolve()
    useVaultPrompt.getState().finish(true)

    await expect(done).resolves.toBe(locked)
    expect(calls).toBe(2)
  })
})

describe('asking and retrying', () => {
  it('does not prompt when the operation succeeds', async () => {
    const run = vi.fn().mockResolvedValue('connected')
    expect(await withVaultUnlock('Connecting', run)).toBe('connected')
    expect(useVaultPrompt.getState().open).toBe(false)
    expect(run).toHaveBeenCalledTimes(1)
  })

  it('retries once after the user unlocks', async () => {
    const run = vi
      .fn()
      .mockRejectedValueOnce(asIpcError(new VaultLockedError()))
      .mockResolvedValueOnce('connected')

    const promise = withVaultUnlock('Connecting to Prod', run)
    await vi.waitFor(() => expect(useVaultPrompt.getState().open).toBe(true))
    expect(useVaultPrompt.getState().reason).toBe('Connecting to Prod')

    useVaultPrompt.getState().finish(true)
    expect(await promise).toBe('connected')
    expect(run).toHaveBeenCalledTimes(2)
  })

  it('gives up with the original error when the user cancels', async () => {
    const run = vi.fn().mockRejectedValue(asIpcError(new VaultLockedError()))
    const promise = withVaultUnlock('Connecting', run)
    await vi.waitFor(() => expect(useVaultPrompt.getState().open).toBe(true))
    useVaultPrompt.getState().finish(false)

    await expect(promise).rejects.toThrow(VAULT_LOCKED)
    expect(run).toHaveBeenCalledTimes(1)
  })

  it('retries once, not forever', async () => {
    // If it still fails after a successful unlock the cause is something else,
    // and asking again would be a dialog the user cannot dismiss.
    const run = vi.fn().mockRejectedValue(asIpcError(new VaultLockedError()))
    const promise = withVaultUnlock('Connecting', run)
    await vi.waitFor(() => expect(useVaultPrompt.getState().open).toBe(true))
    useVaultPrompt.getState().finish(true)

    await expect(promise).rejects.toThrow()
    expect(run).toHaveBeenCalledTimes(2)
  })

  it('never prompts for an unrelated failure', async () => {
    const run = vi.fn().mockRejectedValue(new Error('ECONNREFUSED'))
    await expect(withVaultUnlock('Connecting', run)).rejects.toThrow('ECONNREFUSED')
    expect(useVaultPrompt.getState().open).toBe(false)
    expect(run).toHaveBeenCalledTimes(1)
  })
})

describe('several operations at once', () => {
  it('asks once and answers all of them', async () => {
    // Opening three tabs against vault-backed servers should not stack three
    // identical dialogs.
    // `ReturnType<typeof vi.fn>` is the un-parameterised `Mock`, whose call
    // signature is `Procedure | Constructable` — not something `withVaultUnlock`
    // can accept. Naming the signature the mock stands for is what lets the
    // three of them be passed to it.
    const make = (): Mock<() => Promise<unknown>> =>
      vi
        .fn<() => Promise<unknown>>()
        .mockRejectedValueOnce(asIpcError(new VaultLockedError()))
        .mockResolvedValueOnce('ok')
    const runs = [make(), make(), make()]
    const all = Promise.all(runs.map((r) => withVaultUnlock('Connecting', r)))

    await vi.waitFor(() => expect(useVaultPrompt.getState().open).toBe(true))
    useVaultPrompt.getState().finish(true)

    expect(await all).toEqual(['ok', 'ok', 'ok'])
    for (const r of runs) expect(r).toHaveBeenCalledTimes(2)
  })
})
