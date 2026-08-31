import { useVaultPrompt } from '../store/vaultPrompt'

// Matches the marker credentialResolver.ts puts in the message. Electron
// rewrites a rejected IPC handler's error, so the class does not survive but
// the token does.
const VAULT_LOCKED = 'SHELLPILOT_VAULT_LOCKED'

/** The same condition, spelled as a code on a result object rather than thrown.
 *  Mirrors the `'vault-locked'` member of VpnErrorCode in shared/vpn.ts. */
const VAULT_LOCKED_CODE = 'vault-locked'

const hasMarker = (v: unknown): boolean => typeof v === 'string' && v.includes(VAULT_LOCKED)

/**
 * True when this failure is "the vault is locked" and nothing else.
 *
 * A locked vault reaches the renderer in two shapes, and both mean exactly the
 * same thing to the person looking at the screen:
 *
 *  - a rejection whose message still carries the marker (SSH, SFTP, database);
 *  - a *resolved* result carrying `errorCode: 'vault-locked'` (VPN start, VPN
 *    import), because those paths report failure rather than throwing.
 *
 * Recognising only the first meant every caller on the second shape had to
 * hand-roll the prompt, or — more often — silently did nothing and left the
 * user reading advice with no way to act on it.
 */
export function isVaultLocked(err: unknown): boolean {
  if (err === null || err === undefined) return false
  if (typeof err === 'object') {
    // `errorCode` is the shared result shape; `code` is what a VpnError carries
    // when one survives structured-cloning intact.
    const o = err as { errorCode?: unknown; code?: unknown; message?: unknown; error?: unknown }
    if (o.errorCode === VAULT_LOCKED_CODE || o.code === VAULT_LOCKED_CODE) return true
    // An Error stringifies usefully, a plain object does not ("[object
    // Object]"), so read the two fields either shape puts the text in.
    return hasMarker(o.message) || hasMarker(o.error)
  }
  return hasMarker(String(err))
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
    const result = await run()
    // A resolved-but-failed result is the same situation as a rejection here,
    // so it gets the same offer rather than being returned as a dead end.
    if (!isVaultLocked(result)) return result
    const unlocked = await useVaultPrompt.getState().request(reason)
    return unlocked ? await run() : result
  } catch (err) {
    if (!isVaultLocked(err)) throw err
    const unlocked = await useVaultPrompt.getState().request(reason)
    if (!unlocked) throw err
    return await run()
  }
}
