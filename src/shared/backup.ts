// Contents of a backup bundle, before encryption.
export interface BackupPayload {
  version: 1
  createdAt: string
  app: string // ShellPilot version that wrote the bundle
  // Non-secret application state (workspaces, folders, servers, databases…).
  data: unknown | null
  // Credentials, unsealed from the OS keychain. Only ever exists inside the
  // encrypted envelope or in memory.
  secrets: Record<string, string>
  // Already password-encrypted by the vault itself; carried verbatim.
  vault: unknown | null
  // Per-workspace password verifiers.
  workspaceLocks: unknown | null
  // Trusted SSH host keys.
  knownHosts: unknown | null
}

export interface BackupSummary {
  createdAt: string
  app: string
  servers: number
  databases: number
  workspaces: number
  secrets: number
  hasVault: boolean
}

export interface BackupResult {
  ok: boolean
  error?: string
  // Set when the user completes a save/open dialog.
  path?: string
  cancelled?: boolean
  summary?: BackupSummary
}
