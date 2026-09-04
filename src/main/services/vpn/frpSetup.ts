// Storing the one credential the guided tunnel setup collects.
//
// The guided setup asks for three things exactly once: the frp server, the
// domain the operator pointed at it, and the server's token. Two of those are
// plain JSON and go on the profile. The third is a secret, and a secret on a
// profile is a secret in `store.ts`'s plain-JSON blob — so it takes the same
// road every other piece of VPN key material takes, `stageImportedSecrets`,
// and the profile gets a ref.
//
// Before this existed the frp form's own answer was a sentence: "Token — add
// one to this profile's vault entry before starting." That is a correct
// instruction and a terrible one to meet in the middle of a flow whose entire
// promise is that the setup happens once. A setup that ends by telling the
// user to go and finish it somewhere else has not happened once; it has
// happened once and a half.
//
// Deliberately not a general "write an frp secret" channel. Proxy secret keys,
// plugin passwords and OIDC client secrets are not here: each of those belongs
// to a proxy the full editor owns, and one channel that can write any of them
// is one channel that has to be reasoned about for all of them.

import type { FrpTokenResult } from '../../../shared/vpn'
import { isVaultLockedError } from '../credentialResolver'
import { toVpnResult } from './errors'
import { deleteVpnSecrets, stageImportedSecrets } from './vaultBridge'

export interface StoreFrpTokenRequest {
  /** Names the vault entry, so the credential stays recognisable from the
   *  vault UI alone — exactly as an imported profile's entry is. */
  profileName: string
  workspaceId: string
  /** The frp server's `auth.token`, as the operator pasted it. */
  token: string
  /** The entry this profile pointed at before, released only once the
   *  replacement is safely written. */
  replaces?: string
}

/**
 * Put an frp server token in the vault and hand back the ref the profile
 * carries.
 *
 * Returns a result rather than throwing, because every VPN channel does and
 * because the one failure that matters here — a locked vault — is a thing the
 * renderer can fix and retry rather than an error to report.
 */
export async function storeFrpToken(req: StoreFrpTokenRequest): Promise<FrpTokenResult> {
  try {
    const token = req.token.trim()
    if (!token) {
      return { ok: false, error: 'No token was supplied.', errorCode: 'internal' }
    }
    const name = req.profileName.trim() || 'frp'
    const staged = await stageImportedSecrets(name, req.workspaceId, 'frp', { token })
    if (!staged.refs.token) {
      return { ok: false, error: 'The token was not stored.', errorCode: 'internal' }
    }
    // Only once the replacement is safely written. Releasing first would lose
    // the old token to a vault write that then failed.
    if (req.replaces && req.replaces !== staged.vaultEntryId) {
      await deleteVpnSecrets(req.replaces).catch(() => undefined)
    }
    return { ok: true, tokenRef: staged.refs.token, vaultEntryId: staged.vaultEntryId }
  } catch (e) {
    if (isVaultLockedError(e)) {
      return {
        ok: false,
        error: 'Unlock the vault before saving this token — this is where it will be stored.',
        errorCode: 'vault-locked'
      }
    }
    return toVpnResult(e)
  }
}
