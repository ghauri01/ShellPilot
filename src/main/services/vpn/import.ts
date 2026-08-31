import type {
  FrpSpec,
  OpenVpnSpec,
  VpnImportResult,
  VpnKind,
  VpnSecretRef,
  VpnSpec,
  WireGuardSpec
} from '../../../shared/vpn'
import { isVaultLockedError } from '../credentialResolver'
import { toVpnResult, VpnError } from './errors'
import { parseVpnConfig } from './parsers'
import { deleteVpnSecrets as dropVpnSecrets, stageImportedSecrets } from './vaultBridge'
import type { StagedVpnSecretRefs } from './vaultBridge'

// The import handler: the boundary a hostile file has to cross.
//
// Two calls, deliberately split:
//
//   vpnImport()       parses and reports. Nothing is stored, nothing is
//                     started. The renderer gets a spec and — always — the
//                     full list of what was dropped or rejected, so the user
//                     sees it BEFORE deciding to keep the profile.
//   vpnCommitImport() re-parses the same text, puts the key material in the
//                     vault, and returns a spec whose refs point at it.
//
// It re-parses rather than caching the first parse, and that is on purpose.
// Caching would mean holding a private key in a module-level map between two
// IPC calls, for as long as the user leaves the dialog open — and the parse is
// pure and cheap, so the only thing caching would buy is that risk.

/** Parse and report. Never stores anything, never returns key material. */
export function vpnImport(kind: VpnKind, text: string, baseDir?: string): VpnImportResult {
  try {
    const parsed = parseVpnConfig(kind, text, { baseDir })
    // Drop `secrets` on the floor: the internal type carries it, the wire type
    // does not, and this is the one place the two meet.
    const { secrets: _secrets, ...wire } = parsed
    return wire
  } catch (e) {
    const r = toVpnResult(e)
    return { ok: false, error: r.error, errorCode: r.errorCode, stripped: [], warnings: [] }
  }
}

export interface VpnCommitResult {
  ok: boolean
  error?: string
  errorCode?: VpnImportResult['errorCode']
  spec?: VpnSpec
  vaultEntryId?: string
}

/** Store the credentials and return a spec that points at them. */
export async function vpnCommitImport(
  name: string,
  workspaceId: string,
  kind: VpnKind,
  text: string,
  baseDir?: string
): Promise<VpnCommitResult> {
  try {
    const parsed = parseVpnConfig(kind, text, { baseDir })
    if (!parsed.ok || !parsed.spec) {
      return {
        ok: false,
        error: parsed.error ?? 'This configuration could not be imported.',
        errorCode: parsed.errorCode ?? 'config-rejected'
      }
    }

    const staged = await stageImportedSecrets(name, workspaceId, kind, parsed.secrets ?? {})
    const spec = applyRefs(parsed.spec, staged.refs)
    return { ok: true, spec, vaultEntryId: staged.vaultEntryId }
  } catch (e) {
    if (isVaultLockedError(e)) {
      return {
        ok: false,
        error: 'Unlock the vault before importing a VPN profile — its key material is stored there.',
        errorCode: 'vault-locked'
      }
    }
    const r = toVpnResult(e)
    return { ok: false, error: r.error, errorCode: r.errorCode }
  }
}

/** Release the vault entry behind a deleted profile, so its key material does
 *  not linger with nothing in the UI pointing at it. */
export async function vpnDeleteSecrets(vaultEntryId: string): Promise<void> {
  if (!vaultEntryId) return
  await dropVpnSecrets(vaultEntryId)
}

// Parsers cannot invent a vault id, so every ref they produce carries an empty
// one. This walks the spec and fills them in from what staging actually wrote —
// including the fallback cases, where a value did not fit its preferred slot
// and staging recorded a named field instead.
function applyRefs(spec: VpnSpec, refs: StagedVpnSecretRefs): VpnSpec {
  switch (spec.kind) {
    case 'wireguard':
      return applyWireGuardRefs(spec, refs)
    case 'openvpn':
      return applyOpenVpnRefs(spec, refs)
    case 'frp':
      return applyFrpRefs(spec, refs)
  }
}

function applyWireGuardRefs(spec: WireGuardSpec, refs: StagedVpnSecretRefs): WireGuardSpec {
  return {
    ...spec,
    privateKeyRef: require(refs.privateKey, 'private key'),
    peers: spec.peers.map((p) => {
      // A peer only gets a preshared-key ref if the file actually carried one;
      // an absent PSK is normal, not a missing credential.
      const psk = refs.presharedKeys?.[p.publicKey]
      return psk ? { ...p, presharedKeyRef: psk } : { ...p, presharedKeyRef: undefined }
    })
  }
}

function applyOpenVpnRefs(spec: OpenVpnSpec, refs: StagedVpnSecretRefs): OpenVpnSpec {
  return {
    ...spec,
    configRef: require(refs.configBody, 'configuration'),
    usernameRef: refs.username,
    passwordRef: refs.password,
    keyPassphraseRef: refs.keyPassphrase
  }
}

function applyFrpRefs(spec: FrpSpec, refs: StagedVpnSecretRefs): FrpSpec {
  return {
    ...spec,
    auth: {
      ...spec.auth,
      tokenRef: refs.token,
      oidc: spec.auth.oidc ? { ...spec.auth.oidc, clientSecretRef: refs.password } : undefined
    },
    proxies: spec.proxies.map((p) => ({
      ...p,
      secretKeyRef: refs.proxySecretKeys?.[p.name],
      plugin: p.plugin
        ? { ...p.plugin, passwordRef: refs.proxySecretKeys?.[`plugin:${p.name}`] }
        : undefined
    })),
    visitors: spec.visitors.map((v) => ({
      ...v,
      secretKeyRef: refs.proxySecretKeys?.[v.name]
    }))
  }
}

// A ref the spec cannot work without. Failing here rather than storing a
// profile with an empty vault id means the error names the missing credential,
// instead of turning up later as an unexplained failure to start.
function require(ref: VpnSecretRef | undefined, what: string): VpnSecretRef {
  if (!ref) throw new VpnError('config-invalid', `The imported profile has no ${what}.`)
  return ref
}
