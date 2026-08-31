import { getSecret } from './secrets'
import { vaultList, vaultStatus } from './vault'
import { VpnError } from './vpn/errors'
import type { SshHop } from '../../shared/ssh'
import type { VaultEntry } from '../../shared/vault'
import type { VpnProfile, VpnSecretField, VpnSecretRef, VpnSpec } from '../../shared/vpn'
import type { ResolvedVpnSecrets } from './vpn/driver'

export interface SecretBlob {
  // A reference to a vault entry, which is where a credential belongs: one
  // record, reusable across every server that authenticates with it, changed
  // in one place when it rotates. The fields below remain for servers saved
  // before the vault held credentials, and for anyone who would rather not
  // keep one.
  vaultEntryId?: string
  password?: string
  keyPath?: string
  passphrase?: string
  // Saved answer to a single keyboard-interactive prompt (a static second
  // password). One-time codes are never stored.
  kbAnswer?: string
}

export type CredentialSource = 'vault' | 'keychain' | 'inline' | 'none'

// Why a connection has no usable credential, when it names a vault entry it
// cannot read. Surfaced so the failure says "unlock the vault" rather than
// ssh2's "All configured authentication methods failed".
// A marker the renderer can recognise across the IPC boundary. Electron
// serialises a rejected handler into a plain Error whose message is prefixed
// with "Error invoking remote method ...", so the class and its name do not
// survive the trip — a stable token inside the message does.
export const VAULT_LOCKED = 'SHELLPILOT_VAULT_LOCKED'

export class VaultLockedError extends Error {
  // The subject is a parameter only so a VPN profile does not have to describe
  // itself as a server. The default is what every existing caller produces.
  constructor(subject = 'this server authenticates with a vault credential') {
    super(`${VAULT_LOCKED}: ${subject}, and the vault is locked.`)
    this.name = 'VaultLockedError'
  }
}

/** Recognises the locked-vault failure across a module boundary, so a caller
 *  can map it onto its own error vocabulary (the VPN layer turns it into
 *  `vault-locked`) instead of reporting it as an internal fault. */
export function isVaultLockedError(e: unknown): e is VaultLockedError {
  return e instanceof VaultLockedError || (e instanceof Error && e.message.includes(VAULT_LOCKED))
}

function vaultEntry(id: string): VaultEntry | null {
  const status = vaultStatus()
  if (!status.exists || !status.unlocked) throw new VaultLockedError()
  return vaultList().entries?.find((e) => e.id === id) ?? null
}

// Copies a vault entry's material onto a connection. The entry is the single
// source of truth: a key stored as material travels with an encrypted backup
// and works on another machine, which a keyPath pointing at local plaintext
// never did.
function applyVaultEntry<T extends SshHop>(cfg: T, entry: VaultEntry): void {
  if (entry.privateKey) {
    cfg.privateKey = cfg.privateKey ?? entry.privateKey
    cfg.passphrase = cfg.passphrase ?? (entry.password || undefined)
  } else if (entry.password) {
    cfg.password = cfg.password ?? entry.password
  }
}

// Merges stored credentials (never exposed outside main) unless the caller
// already supplied inline secrets. Shared by the IPC handlers in
// main/index.ts and the MCP bridge — the AI-facing path authenticates SSH
// exactly the same way a human-driven terminal/SFTP session does, so there is
// only one place that ever reads a server's stored secret.
export function resolveSecrets<T extends SshHop & { serverId?: string }>(cfg: T): T {
  if (cfg.serverId && !cfg.password && !cfg.privateKey && !cfg.keyPath) {
    const raw = getSecret(cfg.serverId)
    if (raw) {
      let blob: SecretBlob | null = null
      try {
        blob = JSON.parse(raw) as SecretBlob
      } catch {
        /* a corrupt blob is the same as no stored credential */
      }
      if (blob) {
        // A vault reference wins: it is the record the user maintains. A
        // VaultLockedError deliberately propagates rather than falling through
        // to the legacy fields — quietly authenticating with a stale copy of a
        // credential the user has since changed in the vault is worse than a
        // clear failure.
        if (blob.vaultEntryId) {
          const entry = vaultEntry(blob.vaultEntryId)
          if (entry) applyVaultEntry(cfg, entry)
        }
        cfg.password = cfg.password ?? blob.password
        cfg.keyPath = cfg.keyPath ?? blob.keyPath
        cfg.passphrase = cfg.passphrase ?? blob.passphrase
      }
    }
  }
  return cfg
}

// Which store a server's credential actually comes from, for the UI to show
// without ever reading the credential itself.
export function credentialSourceFor(serverId: string): { source: CredentialSource; vaultEntryId?: string } {
  const raw = getSecret(serverId)
  if (!raw) return { source: 'none' }
  try {
    const blob = JSON.parse(raw) as SecretBlob
    if (blob.vaultEntryId) return { source: 'vault', vaultEntryId: blob.vaultEntryId }
    if (blob.password || blob.keyPath || blob.passphrase) return { source: 'keychain' }
    return { source: 'none' }
  } catch {
    return { source: 'none' }
  }
}

// Every jump hop authenticates independently, so each one needs its own
// credentials resolved — not just the final target.
export function resolveChainSecrets<T extends SshHop & { serverId?: string; hops?: SshHop[] }>(cfg: T): T {
  const resolved = resolveSecrets(cfg)
  if (Array.isArray(resolved.hops)) {
    resolved.hops = resolved.hops.map((h) => resolveSecrets({ ...h } as SshHop & { serverId?: string }))
  }
  return resolved
}

// Raw secret values known for a server, used only to redact them out of
// command/file output returned to an AI agent — never returned to a caller
// directly.
export function knownSecretValuesForServer(serverId: string): string[] {
  const raw = getSecret(serverId)
  if (!raw) return []
  try {
    const blob = JSON.parse(raw) as SecretBlob
    const values = [blob.password, blob.passphrase, blob.kbAnswer]
    // A vault-backed credential must be redacted from agent-visible output for
    // exactly the same reason a keychain one is.
    if (blob.vaultEntryId) {
      try {
        const entry = vaultEntry(blob.vaultEntryId)
        if (entry) values.push(entry.password, entry.privateKey)
      } catch {
        /* locked: nothing to redact, because nothing could be resolved either */
      }
    }
    return values.filter((v): v is string => !!v)
  } catch {
    return []
  }
}


// A database's stored credential, resolved the same way a server's is: keyed
// by id in the OS keychain, read only in main, never returned to a caller.
// The jump host's own credentials live in that same store under the server id.
export function resolveDbSecrets<T extends { id: string; password?: string; uri?: string; ssh?: unknown }>(
  cfg: T
): T {
  if (!cfg.password && !cfg.uri) {
    const raw = getSecret(cfg.id)
    if (raw) {
      try {
        const b = JSON.parse(raw) as { password?: string; uri?: string }
        cfg.password = b.password
        cfg.uri = b.uri
      } catch {
        cfg.password = raw // legacy plain-password secret
      }
    }
  }
  if (cfg.ssh) {
    cfg.ssh = resolveChainSecrets({ ...(cfg.ssh as SshHop & { serverId?: string }) }) as T['ssh']
  }
  return cfg
}

// ---------------------------------------------------------------------- VPN

// Which built-in slot of a `vpn` vault entry a given secret field lives in.
// `null` means the field has no built-in slot and is always carried in
// `fields[]`, keyed by the ref's `fieldKey`. VAULT_KIND_FIELDS in
// shared/vault.ts documents the layout from the entry's side.
export const VPN_VAULT_SLOT: Record<VpnSecretField, 'privateKey' | 'password' | 'username' | null> = {
  privateKey: 'privateKey',
  // The sanitised .ovpn body has the client key inlined in it, so it is key
  // material and belongs in the slot that holds key material.
  configBody: 'privateKey',
  password: 'password',
  token: 'password',
  username: 'username',
  keyPassphrase: null,
  presharedKey: null,
  proxySecretKey: null
}

function vpnVaultEntries(): Map<string, VaultEntry> {
  const status = vaultStatus()
  if (!status.exists || !status.unlocked) {
    throw new VaultLockedError('this VPN profile authenticates with a vault credential')
  }
  const byId = new Map<string, VaultEntry>()
  for (const e of vaultList().entries ?? []) byId.set(e.id, e)
  return byId
}

function readVpnRef(ref: VpnSecretRef, entries: Map<string, VaultEntry>): string {
  const entry = entries.get(ref.vaultEntryId)
  if (!entry) {
    throw new VpnError(
      'config-invalid',
      `Its stored ${ref.field} is no longer in the vault. Import the profile again.`
    )
  }
  // A named custom field wins over the built-in slot. Staging falls back to a
  // custom field whenever the slot it wanted was already taken, and the ref is
  // the only record of where the value actually went.
  const slot = ref.fieldKey ? null : VPN_VAULT_SLOT[ref.field]
  const value = slot
    ? entry[slot]
    : entry.fields.find((f) => f.key === (ref.fieldKey ?? ref.field))?.value
  if (!value) {
    throw new VpnError(
      'config-invalid',
      `The vault entry "${entry.name}" has no ${ref.field} in it any more.`
    )
  }
  return value
}

// Every literal, longest first, for the log redactor.
//
// Longest first because redactKnownSecrets replaces in order: if a short secret
// happens to be a substring of a longer one, blanking the short one first
// leaves recognisable fragments of the long one behind.
//
// The username is in here even though it is not itself a secret — the contract
// on ResolvedVpnSecrets says every literal, and an account name disclosed to an
// AI agent through a log line is still a disclosure. The cost is that a log
// showing the username shows [REDACTED] instead; the profile model still has it
// for the UI.
function flattenVpnSecrets(s: ResolvedVpnSecrets): string[] {
  const seen = new Set<string>()
  const add = (v: string | undefined): void => {
    if (v) seen.add(v)
  }
  add(s.privateKey)
  add(s.username)
  add(s.password)
  add(s.keyPassphrase)
  add(s.token)
  // The config body is one large literal that no single log line will contain,
  // but a driver echoing the whole thing back is exactly the accident this is
  // here to catch. The key material inlined in it is also covered by the PEM
  // pattern rule in secretRedaction.ts.
  add(s.configBody)
  for (const v of Object.values(s.presharedKeys ?? {})) add(v)
  for (const v of Object.values(s.proxySecretKeys ?? {})) add(v)
  return [...seen].sort((a, b) => b.length - a.length)
}

function resolveVpnSpec(spec: VpnSpec, read: (ref: VpnSecretRef) => string): ResolvedVpnSecrets {
  const out: ResolvedVpnSecrets = { all: [] }
  if (spec.kind === 'wireguard') {
    out.privateKey = read(spec.privateKeyRef)
    for (const peer of spec.peers) {
      if (!peer.presharedKeyRef) continue
      out.presharedKeys = { ...out.presharedKeys, [peer.publicKey]: read(peer.presharedKeyRef) }
    }
  } else if (spec.kind === 'openvpn') {
    out.configBody = read(spec.configRef)
    if (spec.usernameRef) out.username = read(spec.usernameRef)
    if (spec.passwordRef) out.password = read(spec.passwordRef)
    if (spec.keyPassphraseRef) out.keyPassphrase = read(spec.keyPassphraseRef)
  } else {
    if (spec.auth.tokenRef) out.token = read(spec.auth.tokenRef)
    // ResolvedVpnSecrets has one free single-value slot left and frp has one
    // more single-value secret, so the OIDC client secret takes `password`.
    // `auth.method` is either token or oidc, never both, so nothing collides.
    if (spec.auth.oidc?.clientSecretRef) out.password = read(spec.auth.oidc.clientSecretRef)
    for (const p of spec.proxies) {
      if (p.secretKeyRef) {
        out.proxySecretKeys = { ...out.proxySecretKeys, [p.name]: read(p.secretKeyRef) }
      }
      // A plugin password is per-proxy too, so it rides in the same map under a
      // prefixed key rather than fighting for the one `password` slot.
      if (p.plugin?.passwordRef) {
        out.proxySecretKeys = {
          ...out.proxySecretKeys,
          [`plugin:${p.name}`]: read(p.plugin.passwordRef)
        }
      }
    }
    for (const v of spec.visitors) {
      if (!v.secretKeyRef) continue
      out.proxySecretKeys = { ...out.proxySecretKeys, [v.name]: read(v.secretKeyRef) }
    }
  }
  out.all = flattenVpnSecrets(out)
  return out
}

/** Resolves every secret a VPN profile references into plaintext, immediately
 *  before a start.
 *
 *  Returned, never cached: the plaintext lives as long as the caller's
 *  `VpnDriverContext` and no longer, so nothing here keeps a copy of a key
 *  after the vault re-locks.
 *
 *  Throws `VaultLockedError` when the vault is locked, which is what makes the
 *  renderer's existing `withVaultUnlock` flow prompt. There is deliberately no
 *  fallback to an unencrypted source: starting a tunnel with a stale copy of a
 *  key the user has since rotated is worse than a clear failure, the same
 *  reasoning `resolveSecrets` above applies to SSH. */
export async function resolveVpnSecrets(profile: VpnProfile): Promise<ResolvedVpnSecrets> {
  // Opened on first use so a profile that references nothing — an frp profile
  // with no token and no secret proxies — never raises an unlock prompt.
  let entries: Map<string, VaultEntry> | null = null
  return resolveVpnSpec(profile.spec, (ref) => {
    entries ??= vpnVaultEntries()
    return readVpnRef(ref, entries)
  })
}
