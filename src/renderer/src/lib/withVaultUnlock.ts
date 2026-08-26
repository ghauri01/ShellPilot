import { useVaultPrompt } from '../store/vaultPrompt'

// Matches the marker credentialResolver.ts puts in the message. Electron
// rewrites a rejected IPC handler's error, so the class does not survive but
// the token does.
const VAULT_LOCKED = 'SHELLPILOT_VAULT_LOCKED'

export function isVaultLocked(err: unknown): boolean {
  return err instanceof Error ? err.message.includes(VAULT_LOCKED) : String(err).includes(VAULT_LOCKED)
}

/**
 * Runs an operation that may need a vault credential. If it fails only because
 * the vault is locked, asks the user to unlock and runs it once more.
 *
 * Retrying once, not looping: if it fails again after a successful unlock the
 * cause is something else, and asking a second time would just be a dialog the
 * user cannot get rid of.
 */
export async function withVaultUnlock<T>(reason: string, run: () => Promise<T>): Promise<T> {
  try {
    return await run()
  } catch (err) {
    if (!isVaultLocked(err)) throw err
    const unlocked = await useVaultPrompt.getState().request(reason)
    if (!unlocked) throw err
    return await run()
  }
}
