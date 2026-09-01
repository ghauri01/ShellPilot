export type UUID = string

export type WorkspaceColor =
  | 'green'
  | 'purple'
  | 'blue'
  | 'orange'
  | 'red'
  | 'cyan'
  | 'pink'

export interface Workspace {
  id: UUID
  name: string
  color: WorkspaceColor
  hidden: boolean
  locked: boolean
  hasPassword: boolean
}

export type ServerStatus = 'online' | 'idle' | 'offline' | 'connecting'
export type AuthMethod = 'password' | 'key' | 'agent' | 'certificate'

export interface Hop {
  id: UUID
  label: string
  host: string
  port: number
  username: string
  auth: AuthMethod
  // Populated from a saved server; its stored credentials are then used for
  // this hop instead of anything held here.
  serverId?: UUID | null
  // Private key for this hop when it is not backed by a saved server.
  keyPath?: string
}

export interface Server {
  id: UUID
  workspaceId: UUID
  folderId: UUID | null
  name: string
  host: string
  port: number
  username: string
  auth: AuthMethod
  status: ServerStatus
  tags: string[]
  favorite: boolean
  os: string
  route: Hop[]
  // Reach this server through a VPN profile when set. The VPN is the outer
  // transport: the route hops above are dialled *through* it, not beside it.
  // Main resolves this from the saved record rather than trusting a caller to
  // pass it, and a reference to a deleted profile means "connect directly"
  // rather than "fail" — one deleted profile must not strand a fleet.
  vpnProfileId: UUID | null
  demo?: boolean
}

export type FolderKind = 'server' | 'database'

export interface Folder {
  id: UUID
  workspaceId: UUID
  name: string
  parentId: UUID | null
  // Connections and databases keep separate folder trees, so a "Staging"
  // folder for servers does not appear in the database sidebar.
  kind: FolderKind
}

// A section in the Fleet Monitor. Groups are a monitoring-only arrangement:
// they are independent of connection folders, so a server can sit under
// "Staging" in the sidebar and under "Databases" on the monitor wall.
export interface MonitorGroup {
  id: UUID
  workspaceId: UUID
  name: string
  collapsed: boolean
  // Cards in this group, in display order.
  serverIds: UUID[]
  // The bucket every unplaced server falls into. One per workspace; it cannot
  // be renamed, deleted or dragged, and always sorts last.
  system?: boolean
}

// The VPN domain lives in src/shared/vpn.ts, shared with main and preload, and
// is re-exported here rather than restated. What used to sit at this spot was a
// renderer-only mock (`rx`/`tx`/`connectedSince`, kinds `pritunl`/`easyconnect`)
// that nothing read; a second definition of the same record is how a renderer
// and a main process end up disagreeing about it.
export type {
  FrpProxy,
  FrpProxyStatus,
  FrpProxyType,
  FrpSpec,
  FrpVisitor,
  OpenVpnAuthMode,
  OpenVpnSpec,
  StrippedDirective,
  VpnBoundListener,
  VpnDependent,
  VpnEngineInfo,
  VpnErrorCode,
  VpnImportResult,
  VpnKind,
  VpnListener,
  VpnLogLine,
  VpnMode,
  VpnProfile,
  VpnPrompt,
  VpnSecretRef,
  VpnSpec,
  VpnState,
  VpnStats,
  VpnStatus,
  VpnValidation,
  VpnValidationIssue,
  WireGuardPeer,
  WireGuardSpec
} from '../../shared/vpn'

export type TunnelKind = 'local' | 'remote' | 'socks'
export interface Tunnel {
  id: UUID
  workspaceId: UUID
  name: string
  kind: TunnelKind
  status: 'active' | 'inactive'
  // SSH server the tunnel is carried over.
  serverId: UUID | null
  listen: string
  target: string
}

export type DbKind = 'postgres' | 'mysql' | 'mssql' | 'mongodb' | 'redis'
export interface DatabaseConn {
  id: UUID
  workspaceId: UUID
  name: string
  kind: DbKind
  host: string
  port: number
  username: string
  database: string
  ssl: boolean
  uri: boolean // true when the connection is defined by a full connection string
  folderId: UUID | null
  // Reach the database through this SSH server (a bastion) when set.
  sshServerId: UUID | null
  // Reach the database through a VPN profile when set. Independent of the
  // bastion above and composable with it: with both, the VPN carries the
  // *bastion*, and the database is reached from there as it always was.
  vpnProfileId: UUID | null
}

export type PanelView = 'terminal' | 'monitor' | 'files'
export type ActivityView = 'connections' | 'databases' | 'tunnels' | 'monitor' | 'vault' | 'ai' | 'settings'

interface TabBase {
  id: UUID
  // Tabs belong to the workspace they were opened in, so switching workspaces
  // does not show another workspace's sessions.
  workspaceId: UUID
  title: string
  view: PanelView
}

// A tab backed by a saved server. `serverId` is non-null here on purpose: it
// was typed `UUID | null` while every consumer assumed non-null, which is how
// "Session unavailable" became reachable for reasons other than a deleted
// server.
export interface SshTab extends TabBase {
  kind: 'ssh'
  serverId: UUID
}

// A tab backed by a shell on this machine. It has no server, and deliberately
// does not synthesize one: `servers` is persisted (store/persist.ts:16) and
// mirrored into the MCP data cache by `data:save`, so a fake row there would
// make the local terminal an MCP-addressable target without anyone
// registering a tool for it.
export interface LocalTab extends TabBase {
  kind: 'local'
  // A LocalShell.id from src/shared/local.ts. Opaque — a readable prefix plus
  // a digest of the shell's path ('darwin-zsh-b663616e'). Resolve it against
  // the discovered list; never parse it.
  shellId: string
  // Where the shell was started, when the user asked for somewhere specific.
  cwd?: string
  // Only 'terminal' is meaningful; Monitor and Files are SSH-only views.
  view: 'terminal'
}

export type Tab = SshTab | LocalTab
