import { getSecret } from './secrets'
import { vaultList, vaultStatus } from './vault'
import type { SshHop } from '../../shared/ssh'
import type { VaultEntry } from '../../shared/vault'

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
  constructor() {
    super(
      `${VAULT_LOCKED}: this server authenticates with a vault credential, and the vault is locked.`
    )
    this.name = 'VaultLockedError'
  }
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
