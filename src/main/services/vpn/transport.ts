import type { DbConnectConfig } from '../../../shared/db'
import type { SshConnectConfig } from '../../../shared/ssh'
import { getCachedDatabase, getCachedServer } from '../mcpDataCache'
import { vpnForDatabase, vpnForServer } from './dependencies'

// Which VPN a connection rides, resolved in main from the saved record rather
// than sent by the renderer.
//
// The renderer could pass it, but then every caller would have to remember to —
// the terminal, SFTP, the metrics sampler, the database shell, the MCP tools
// and the CLI all build their own config objects. Resolving it here from the
// same cache that already resolves server names means a connection cannot
// accidentally skip its VPN because one call site was written before the
// feature existed.
//
// A reference to a deleted profile resolves to nothing rather than failing:
// `vpnForServer` already checks the profile still exists, because one deleted
// profile must not make a fleet unreachable.

export function withVpnTransport<T extends SshConnectConfig & { serverId?: string }>(
  cfg: T
): T & { vpnProfileId?: string; serverName?: string } {
  if (!cfg.serverId) return cfg
  const vpnProfileId = vpnForServer(cfg.serverId)
  if (!vpnProfileId) return cfg
  return { ...cfg, vpnProfileId, serverName: getCachedServer(cfg.serverId)?.name }
}

export function withVpnTransportDb(cfg: DbConnectConfig): DbConnectConfig {
  // A test dialog and a saved connection are the same shape, but only a saved
  // one has an id in the cache — an unsaved "Test connection" has nothing to
  // look up, and asking it to pick a VPN it has not been assigned yet would be
  // guessing.
  const vpnProfileId = vpnForDatabase(cfg.id)
  if (!vpnProfileId) return cfg
  return { ...cfg, vpnProfileId, name: cfg.name ?? getCachedDatabase(cfg.id)?.name }
}
