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
  | 'hostFacts'
  | 'firewallRules'
  | 'manageServers'
  | 'vpnControl'

// `detail` is the consent surface, and it is not decoration. A user reading this
// grid is deciding what an agent may do, and the only thing they have to decide
// on is the label. When a label understates its grant, consent was given for
// something narrower than what was taken — which is what happened to Server
// metrics: it meant CPU and memory when the user granted it, and it now also
// returns a service and port inventory of the host. Nobody was asked again.
//
// So a `detail` that merely restates its label is a bug. Each one below names
// what an agent can actually obtain, and any tool added under an existing
// capability has to be reflected here in the same change.
export const AI_CAPABILITIES: { id: AiCapability; label: string; detail: string }[] = [
  {
    id: 'viewServer',
    label: 'View server',
    detail:
      'Lets an agent see that this server exists and read the permissions it has on it. Hostnames, usernames and keys are never disclosed.'
  },
  {
    id: 'terminal',
    label: 'Execute terminal commands',
    detail:
      'Runs shell commands over SSH. Unrestricted privilege-escalation shells (sudo -i, su, sudo bash) are refused whatever this is set to.'
  },
  {
    id: 'readFiles',
    label: 'Read files',
    detail: 'Reads file contents and lists directories. The path rules below can widen or narrow this per path.'
  },
  {
    id: 'writeFiles',
    label: 'Write files',
    detail: 'Creates and overwrites files. The path rules below can widen or narrow this per path.'
  },
  {
    id: 'sftpDownload',
    label: 'SFTP download',
    detail:
      'The transport underneath reading. Applied on top of the path rules, so denying it blocks every path regardless of what they say.'
  },
  {
    id: 'sftpUpload',
    label: 'SFTP upload',
    detail: 'The transport underneath writing. Denying it blocks every path regardless of what the rules say.'
  },
  {
    id: 'sshTunnel',
    label: 'SSH tunnels',
    detail: 'Lists tunnels, and opens or closes a forward between this machine and a port on the server.'
  },
  {
    id: 'databaseAccess',
    label: 'Database access',
    detail: 'Lists databases and runs queries against them through the server.'
  },
  {
    id: 'sudo',
    label: 'Sudo / privilege escalation',
    detail:
      'Commands beginning with sudo, checked on top of Execute terminal commands. Path rules still apply — sudo does not waive them.'
  },
  {
    id: 'serverMetrics',
    label: 'Server metrics, services & ports',
    detail:
      'CPU, memory, disk and uptime — and also every failed systemd unit and every listening port with the process that owns it. That is a service and port inventory of the host, not only its capacity.'
  },
  // Its own capability, NOT a widening of Server metrics, and that was decided
  // rather than defaulted. "How many unpatched security updates, and which
  // distribution and kernel" is a vulnerability report about the host and is
  // arguably the most attacker-useful thing this bridge can return —
  // materially different from CPU and memory. The 0.8.0 finding recorded above
  // was exactly a consent that had drifted wider than its grid text, and the
  // standard it set is that the grid must describe what is actually taken. A
  // new capability backfills to DENY for every existing group, which is the
  // correct default here.
  {
    id: 'hostFacts',
    label: 'Host inventory & pending security updates',
    detail:
      'Distribution and version, CPU model, architecture, virtualisation type, package manager, how many updates are pending, how many of those are SECURITY updates, and whether the host is waiting on a reboot. That is a patch-status report: it tells an agent which of your hosts are unpatched and against what.'
  },
  // Its own capability again, and this one is not reachable by an agent AT ALL
  // — which is why the detail says so rather than leaving a reader to assume
  // the grid's usual meaning. Roadmap item 31 settled that deliberately: a
  // firewall rule list is a map of how to attack the host, and an agent that
  // could read one could exfiltrate it. tests/jobsNotExposed.test.ts holds the
  // property, by name, in the MCP bridge's own closure.
  //
  // What this line grants is COLLECTION. Item 24's posture probe reads firewall
  // scalars — tool, active, default policy, rule count — on every host once an
  // hour; the rule LINES are read only where this says allow, and the probe is
  // built without the commands that would list them everywhere else. So the
  // grid is the consent surface for a human-only feature, which is unusual and
  // is the point: this is the one thing in the posture read that turns counts
  // and fixed vocabulary into addresses and ports.
  //
  // 'ask' collects nothing. The sweep is unattended and hourly, with nobody at
  // the screen to answer, so anything short of 'allow' means do not read them.
  {
    id: 'firewallRules',
    label: 'Firewall rules: the addresses and ports this host accepts',
    detail:
      'The rule lines themselves, as ufw, firewalld, nft or iptables print them — every address, port and protocol named in them, capped and stripped of control characters on the host. That is an inventory of what this host is exposed on and to whom, which is the thing an attacker would otherwise have to scan for. No agent can read it whatever this is set to: it is not behind any MCP tool. Setting it to allow lets ShellPilot COLLECT the rules for this server, for a person to read in Security posture; anything else and they are never asked for.'
  },
  {
    id: 'manageServers',
    label: 'Add servers to the workspace',
    detail: 'Adds a new server to the workspace. It does not grant any access to the server it adds.'
  },
  {
    id: 'vpnControl',
    label: 'VPN & reverse proxies',
    // Says what it grants and what it does not. It used to say "and starts
    // or stops them", which promised something no value of this setting
    // delivers: an frp reverse proxy makes a port on the user's own machine
    // reachable from the internet, so set_vpn refuses one outright and no
    // access group can permit it. A permission UI that offers a power the
    // code refuses is how an operator ends up believing they granted less
    // than they did, or more.
    detail:
      'Lists VPN profiles and reverse proxies, and starts or stops the VPNs. Reverse proxies ' +
      'are never started or stopped by an agent, at any setting.'
  }
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

export interface WorkspaceRef {
  id: string
  name: string
}

// Each agent connects with its own bearer token: the session — not one
// shared secret for the whole app — so Claude Code and Codex can be pointed
// at different workspaces/access groups at the same time, each individually
// revocable. The raw token is shown to the user once, at creation, and only
// its SHA-256 hash plus a display preview are ever persisted.
//
// A session can be granted several workspaces at once (chosen explicitly at
// creation, never "all workspaces including future ones") — every tool that
// lists or resolves a server filters against this exact set, so a workspace
// left out is invisible to the session, not merely denied.
export interface McpAgentSession {
  id: string
  agentName: string
  workspaces: WorkspaceRef[]
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
  // Highest seeded-file-policy generation this file has been brought up to.
  // Absent on every file written before the generation counter existed, which
  // is what lets a new deny rule reach existing installs exactly once without
  // resurrecting rules the user deliberately deleted. See policyStore.
  filePolicyGeneration?: number
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
