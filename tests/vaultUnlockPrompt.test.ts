import { describe, it, expect, beforeEach, vi } from 'vitest'
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
    const make = (): ReturnType<typeof vi.fn> =>
      vi.fn().mockRejectedValueOnce(asIpcError(new VaultLockedError())).mockResolvedValueOnce('ok')
    const runs = [make(), make(), make()]
    const all = Promise.all(runs.map((r) => withVaultUnlock('Connecting', r)))

    await vi.waitFor(() => expect(useVaultPrompt.getState().open).toBe(true))
    useVaultPrompt.getState().finish(true)

    expect(await all).toEqual(['ok', 'ok', 'ok'])
    for (const r of runs) expect(r).toHaveBeenCalledTimes(2)
  })
})
