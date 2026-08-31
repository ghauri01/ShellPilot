import { randomUUID } from 'node:crypto'
import { VaultLockedError, VPN_VAULT_SLOT } from '../credentialResolver'
import { vaultList, vaultSave, vaultStatus } from '../vault'
import { VpnError } from './errors'
import type { VaultEntry, VaultField } from '../../../shared/vault'
import type { ImportedSecrets, VpnKind, VpnSecretField, VpnSecretRef } from '../../../shared/vpn'

// The one place key material crosses from an import into storage.
//
// An import parses a `.conf` / `.ovpn` in the main process and hands the
// material here; what goes back to the renderer is a set of refs. The renderer
// therefore never holds a private key, which is what lets the profile itself be
// persisted by store.ts as plain JSON — there is nothing secret on it to
// persist.

// Refs for whatever the import actually produced, shaped like ImportedSecrets so
// the caller can copy each one straight onto the matching field of its spec.
export interface StagedVpnSecretRefs {
  privateKey?: VpnSecretRef
  // Keyed by peer public key, matching WireGuardPeer.publicKey.
  presharedKeys?: Record<string, VpnSecretRef>
  username?: VpnSecretRef
  password?: VpnSecretRef
  keyPassphrase?: VpnSecretRef
  token?: VpnSecretRef
  configBody?: VpnSecretRef
  // Keyed by proxy name, matching FrpProxy.name.
  proxySecretKeys?: Record<string, VpnSecretRef>
}

export interface StagedVpnSecrets {
  vaultEntryId: string
  refs: StagedVpnSecretRefs
}

const VPN_SUBJECT = 'this VPN profile authenticates with a vault credential'

function requireUnlocked(): VaultEntry[] {
  const status = vaultStatus()
  if (!status.exists || !status.unlocked) throw new VaultLockedError(VPN_SUBJECT)
  const list = vaultList()
  // vaultList fails only when the vault is locked, which the check above
  // already covers. Reporting it the same way keeps one story rather than two.
  if (!list.ok || !list.entries) throw new VaultLockedError(VPN_SUBJECT)
  return list.entries
}

// Assembles one `vpn` entry, deciding where each value goes.
//
// Built-in slots are preferred because they are what the vault UI renders.
// Anything with no free slot falls back to a custom field, and the ref records
// that decision so resolution never has to guess where a value ended up.
class VpnEntryBuilder {
  private readonly fields: VaultField[] = []
  private readonly slots: { privateKey?: string; password?: string; username?: string } = {}

  constructor(private readonly vaultEntryId: string) {}

  place(field: VpnSecretField, value: string, key?: string): VpnSecretRef {
    const slot = VPN_VAULT_SLOT[field]
    if (slot && !key && this.slots[slot] === undefined) {
      this.slots[slot] = value
      return { vaultEntryId: this.vaultEntryId, field }
    }
    this.fields.push({ id: randomUUID(), key: key ?? field, value, secret: true })
    return { vaultEntryId: this.vaultEntryId, field, fieldKey: key ?? field }
  }

  build(name: string, workspaceId: string, kind: VpnKind): VaultEntry {
    const now = new Date().toISOString()
    return {
      id: this.vaultEntryId,
      name,
      kind: 'vpn',
      workspaceId,
      url: '',
      username: this.slots.username ?? '',
      password: this.slots.password ?? '',
      privateKey: this.slots.privateKey,
      notes: '',
      // Which engine this belongs to, so an entry orphaned by a profile deleted
      // some other way is still recognisable for what it is.
      tags: ['vpn', kind],
      fields: this.fields,
      createdAt: now,
      updatedAt: now
    }
  }
}

/** Moves imported key material into a new `vpn` vault entry and returns the
 *  refs that go on the profile. Nothing secret comes back, so the result is
 *  safe to hand to the renderer. */
export async function stageImportedSecrets(
  name: string,
  workspaceId: string,
  kind: VpnKind,
  secrets: ImportedSecrets
): Promise<StagedVpnSecrets> {
  const entries = requireUnlocked()
  const vaultEntryId = randomUUID()
  const builder = new VpnEntryBuilder(vaultEntryId)
  const refs: StagedVpnSecretRefs = {}

  // Order matters only where two fields compete for one slot: a WireGuard
  // private key and an OpenVPN config body never arrive together, but if they
  // did, the first one placed keeps the slot and the second takes a field.
  if (secrets.privateKey) refs.privateKey = builder.place('privateKey', secrets.privateKey)
  if (secrets.configBody) refs.configBody = builder.place('configBody', secrets.configBody)
  if (secrets.username) refs.username = builder.place('username', secrets.username)
  if (secrets.password) refs.password = builder.place('password', secrets.password)
  if (secrets.token) refs.token = builder.place('token', secrets.token)
  if (secrets.keyPassphrase) {
    refs.keyPassphrase = builder.place('keyPassphrase', secrets.keyPassphrase)
  }
  for (const [publicKey, value] of Object.entries(secrets.presharedKeys ?? {})) {
    if (!value) continue
    refs.presharedKeys = {
      ...refs.presharedKeys,
      [publicKey]: builder.place('presharedKey', value, `presharedKey:${publicKey}`)
    }
  }
  for (const [proxyName, value] of Object.entries(secrets.proxySecretKeys ?? {})) {
    if (!value) continue
    refs.proxySecretKeys = {
      ...refs.proxySecretKeys,
      [proxyName]: builder.place('proxySecretKey', value, `proxySecretKey:${proxyName}`)
    }
  }

  const saved = vaultSave([...entries, builder.build(name, workspaceId, kind)])
  if (!saved.ok) throw new VpnError('internal', saved.error)
  return { vaultEntryId, refs }
}

/** Removes the vault entry a deleted profile owned.
 *
 *  An entry that is already gone is not an error: a profile whose credentials
 *  were deleted by hand must still be deletable, and refusing would leave the
 *  user with a profile they cannot get rid of. */
export async function deleteVpnSecrets(vaultEntryId: string): Promise<void> {
  const entries = requireUnlocked()
  const remaining = entries.filter((e) => e.id !== vaultEntryId)
  if (remaining.length === entries.length) return
  const saved = vaultSave(remaining)
  if (!saved.ok) throw new VpnError('internal', saved.error)
}
