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

export type VpnKind = 'wireguard' | 'openvpn' | 'pritunl' | 'easyconnect'
export type VpnStatus = 'connected' | 'disconnected' | 'connecting' | 'error'

export interface VpnProfile {
  id: UUID
  workspaceId: UUID
  name: string
  kind: VpnKind
  status: VpnStatus
  endpoint: string
  localIp: string
  address: string
  rx: number
  tx: number
  connectedSince: number | null
}

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
}

export type PanelView = 'terminal' | 'monitor' | 'files'
export type ActivityView = 'connections' | 'databases' | 'tunnels' | 'monitor' | 'vault' | 'settings'

export interface Tab {
  id: UUID
  // Tabs belong to the workspace they were opened in, so switching workspaces
  // does not show another workspace's sessions.
  workspaceId: UUID
  serverId: UUID | null
  title: string
  view: PanelView
}
