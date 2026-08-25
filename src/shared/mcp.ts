// Shared AI/MCP types used by main, preload and renderer.
//
// This is the vocabulary of the security boundary described in the project
// brief: an AI agent talks to the MCP bridge, the bridge resolves an Access
// Group for the target server, and every capability that group grants is one
// of ALLOW / ASK / DENY rather than a blanket yes/no.

export type PermissionValue = 'allow' | 'ask' | 'deny'

export type AiCapability =
  | 'viewServer'
  | 'terminal'
  | 'readFiles'
  | 'writeFiles'
  | 'sftpDownload'
  | 'sftpUpload'
  | 'sshTunnel'
  | 'databaseAccess'
  | 'sudo'
  | 'serverMetrics'

export const AI_CAPABILITIES: { id: AiCapability; label: string }[] = [
  { id: 'viewServer', label: 'View server' },
  { id: 'terminal', label: 'Execute terminal commands' },
  { id: 'readFiles', label: 'Read files' },
  { id: 'writeFiles', label: 'Write files' },
  { id: 'sftpDownload', label: 'SFTP download' },
  { id: 'sftpUpload', label: 'SFTP upload' },
  { id: 'sshTunnel', label: 'SSH tunnels' },
  { id: 'databaseAccess', label: 'Database access' },
  { id: 'sudo', label: 'Sudo / privilege escalation' },
  { id: 'serverMetrics', label: 'Server metrics' }
]

export type AiCapabilityPolicy = Record<AiCapability, PermissionValue>

// A path-scoped override. The most specific matching pattern (longest string)
// wins over a shorter one; anything not matched falls back to the group's
// blanket readFiles/writeFiles capability.
export interface FilePathRule {
  id: string
  pattern: string
  read?: PermissionValue
  write?: PermissionValue
}

export interface AccessGroup {
  id: string
  name: string
  // The four seeded groups cannot be deleted (so assignments referencing them
  // never dangle) but every field on them, including capabilities, is
  // editable — there is no hard-coded three-tier permission model.
  builtIn: boolean
  capabilities: AiCapabilityPolicy
  filePolicies: FilePathRule[]
}

export type PolicyScope =
  | { level: 'workspace'; workspaceId: string }
  | { level: 'server'; serverId: string }

// null groupId means "No AI Access" for that scope. More specific scope
// (server) overrides less specific (workspace); a server with no assignment
// at all inherits its workspace's assignment; a workspace with no assignment
// at all defaults to No AI Access.
export interface PolicyAssignment {
  id: string
  scope: PolicyScope
  groupId: string | null
}

export interface ServerAiMeta {
  serverId: string
  aliases: string[]
}

export interface McpGlobalConfig {
  enabled: boolean
  port: number
  defaultSessionTtlMinutes: number
  approvalTimeoutSeconds: number
}

// Each agent connects with its own bearer token: the session — not one
// shared secret for the whole app — so Claude Code and Codex can be pointed
// at different workspaces/access groups at the same time, each individually
// revocable. The raw token is shown to the user once, at creation, and only
// its SHA-256 hash plus a display preview are ever persisted.
export interface McpAgentSession {
  id: string
  agentName: string
  workspaceId: string
  workspaceName: string
  groupId: string | null
  groupName: string
  tokenHash: string
  tokenPreview: string
  createdAt: string
  expiresAt: string | null
  lastActiveAt: string
  revoked: boolean
}

export interface ApprovalRequest {
  id: string
  sessionId: string
  agentName: string
  workspaceId: string
  workspaceName: string
  serverId: string
  serverName: string
  capability: AiCapability
  action: string
  risk: 'low' | 'medium' | 'high'
  createdAt: string
  status: 'pending' | 'approved' | 'denied' | 'timeout'
  resolvedAt?: string
}

export type AuditApproval = 'not-required' | 'approved' | 'denied' | 'timeout'
export type AuditResult = 'success' | 'error' | 'denied'

export interface AuditEntry {
  id: string
  timestamp: string
  agentName: string
  sessionId: string
  workspaceId: string | null
  workspaceName: string | null
  serverId: string | null
  serverName: string | null
  action: string
  capability: AiCapability | null
  approval: AuditApproval
  result: AuditResult
  exitCode?: number
  error?: string
}

export interface PolicyState {
  version: 1
  groups: AccessGroup[]
  assignments: PolicyAssignment[]
  serverMeta: ServerAiMeta[]
}

export const DEFAULT_MCP_PORT = 5177

// A short-lived code shown only inside ShellPilot (never returned to the CLI
// that requested it) so the `shellpilot claude|codex|run` launcher can bootstrap
// a session without a human pasting a token/URL by hand.
export interface CliPairingRequest {
  id: string
  code: string
  agentName: string
  createdAt: string
  expiresAt: string
}
