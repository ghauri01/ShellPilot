import { getSecret } from './secrets'
import type { SshHop } from '../../shared/ssh'

export interface SecretBlob {
  password?: string
  keyPath?: string
  passphrase?: string
  // Saved answer to a single keyboard-interactive prompt (a static second
  // password). One-time codes are never stored.
  kbAnswer?: string
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
      try {
        const blob = JSON.parse(raw) as SecretBlob
        cfg.password = cfg.password ?? blob.password
        cfg.keyPath = cfg.keyPath ?? blob.keyPath
        cfg.passphrase = cfg.passphrase ?? blob.passphrase
      } catch {
        /* ignore */
      }
    }
  }
  return cfg
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
    return [blob.password, blob.passphrase, blob.kbAnswer].filter((v): v is string => !!v)
  } catch {
    return []
  }
}
