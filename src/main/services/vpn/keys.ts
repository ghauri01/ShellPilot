// Minting a WireGuard keypair, and storing one. Two operations, deliberately
// not one.
//
// ShellPilot mints key material in exactly one place, and this is it. The split
// below is the whole design: `mintKeypair` makes a pair and touches nothing,
// `storeKeypair` is the only thing here that writes to the vault. The profile
// form generates through the first and, if and only if the user presses Save,
// stores through the second.
//
// It used to be a single operation that did both, and the cost was an orphan:
// open the profile dialog, press "Generate keypair", press Cancel, and a vault
// entry stayed behind that no profile referenced. The user had asked for a key
// and then said no.
//
// This could equally have been one function with a `store: boolean`. It is not,
// because a boolean deciding whether a secret is persisted is a boolean that
// eventually gets passed wrong, and it fails silently in both directions — pass
// it when you meant to store and the key is lost, omit it and the orphan is
// back. Two names, no argument to get wrong.

import type { VpnKeygenResult, VpnMintResult } from '../../../shared/vpn'
import { isVaultLockedError } from '../credentialResolver'
import { wireguardDriver } from './drivers/wireguard'
import { toVpnResult } from './errors'
import { deleteVpnSecrets, stageImportedSecrets } from './vaultBridge'

export interface StoreKeypairRequest {
  /** Names the vault entry, so key material stays recognisable from the vault
   *  UI on its own — exactly as an imported profile's entry is. */
  profileName: string
  workspaceId: string
  /** The key to store. Minted here a moment ago, or pasted by the user; by this
   *  point the difference no longer matters. */
  privateKey: string
  /** The entry this profile pointed at before, released once the new one is
   *  safely written. */
  replaces?: string
}

/**
 * A fresh keypair, stored nowhere.
 *
 * The private key crosses IPC to the renderer, which is not new — the caller
 * has always been able to reveal and copy the key it just made — but nothing
 * persists it. If the form is cancelled the pair is garbage collected with the
 * component and no trace of it exists.
 */
export async function mintKeypair(): Promise<VpnMintResult> {
  try {
    const pair = await wireguardDriver.keygen()
    if (!pair.privateKey) {
      return { ok: false, error: 'No private key was generated.', errorCode: 'internal' }
    }
    return { ok: true, privateKey: pair.privateKey, publicKey: pair.publicKey }
  } catch (e) {
    return toVpnResult(e)
  }
}

/**
 * Store a keypair and hand back the ref the profile should carry.
 *
 * Goes through `stageImportedSecrets`, the same function an imported `.conf`
 * stores through, so there is exactly one road into the vault for a WireGuard
 * private key rather than a second one that has to be kept in step.
 *
 * The public key is derived rather than accepted from the caller. Trusting a
 * public half sent alongside a private one would let a mismatched pair be
 * stored and displayed as if it were real, and that is the worst failure
 * available here: the profile saves, the key looks right on screen, the user
 * authorises it on their server, and the handshake silently never completes.
 */
export async function storeKeypair(req: StoreKeypairRequest): Promise<VpnKeygenResult> {
  try {
    const privateKey = req.privateKey.trim()
    if (!privateKey) {
      return { ok: false, error: 'No private key was supplied.', errorCode: 'internal' }
    }
    const pair = await wireguardDriver.keygen({ publicKeyFor: privateKey })
    const name = req.profileName.trim() || 'WireGuard'
    const staged = await stageImportedSecrets(name, req.workspaceId, 'wireguard', { privateKey })
    // Only once the replacement is safely written. Releasing first would lose
    // the old key to a vault write that then failed.
    if (req.replaces && req.replaces !== staged.vaultEntryId) {
      await deleteVpnSecrets(req.replaces).catch(() => undefined)
    }
    return {
      ok: true,
      // Returned so the user can reveal and copy the key they just made.
      // Nothing persists it: the profile carries the ref below instead.
      privateKey,
      publicKey: pair.publicKey,
      privateKeyRef: staged.refs.privateKey,
      vaultEntryId: staged.vaultEntryId
    }
  } catch (e) {
    if (isVaultLockedError(e)) {
      return {
        ok: false,
        error: 'Unlock the vault before saving this key — this is where it will be stored.',
        errorCode: 'vault-locked'
      }
    }
    return toVpnResult(e)
  }
}
