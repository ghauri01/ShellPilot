import type { ActivityView } from '../../types'

export interface TourStep {
  id: string
  title: string
  body: string
  // Which view to switch to while this step shows, so the feature is on screen
  // behind the card rather than merely described.
  view?: ActivityView
  // A concrete thing to try, where there is one worth naming.
  action?: string
}

// Deliberately short. A tour people skip teaches nothing, so each step has to
// earn its place by covering something you would otherwise find by accident:
// that workspaces exist at all, that credentials belong in the vault rather
// than on each server, that an AI agent never sees them.
export const TOUR_STEPS: TourStep[] = [
  {
    id: 'welcome',
    title: 'Welcome to ShellPilot',
    body: 'An SSH terminal, SFTP browser, server monitor, tunnel manager, database client and encrypted vault in one window. This takes about a minute, and Settings can reopen it any time.'
  },
  {
    id: 'workspaces',
    title: 'Workspaces keep clients and environments apart',
    body: 'Servers, databases and tunnels each belong to a workspace — switch with the picker in the title bar, and password-protect a workspace to keep one client’s infrastructure out of sight. The vault is the exception: it is shared across every workspace, so a credential you save is visible from all of them.',
    action: 'Try the workspace picker at the top left.'
  },
  {
    id: 'connections',
    title: 'Connections, and jump hosts that chain',
    body: 'Add a server once and reuse it everywhere. Each can route through unlimited jump hosts, each with its own credentials. Existing hosts import straight from your ~/.ssh/config.',
    view: 'connections',
    action: 'Add a server, or import your SSH config.'
  },
  {
    id: 'vault',
    title: 'The vault is where credentials live',
    body: 'Passwords, SSH keys and API keys, encrypted with AES-256-GCM under a master password. One vault for the whole app, not one per workspace — a server in any workspace can reference the same entry, so rotating a credential is one edit instead of a hunt. On a Mac with Touch ID you can unlock with a fingerprint.',
    view: 'vault',
    action: 'Create your vault and add a credential.'
  },
  {
    id: 'monitor',
    title: 'Monitoring, including what is broken',
    body: 'Live CPU, memory, disk and network per server, totalled across the fleet. Failed systemd units and listening ports come back on the same poll, so you can see what a host exposes and what has fallen over without opening a shell.',
    view: 'monitor'
  },
  {
    id: 'tunnels',
    title: 'Tunnels, and databases behind a bastion',
    body: 'Local and remote port forwards plus a SOCKS5 proxy. The database client speaks PostgreSQL, MySQL, SQL Server, MongoDB and Redis, and can reach a database that is only routable from inside the network.',
    view: 'tunnels'
  },
  {
    id: 'ai',
    title: 'AI agents, without handing over credentials',
    body: 'Claude Code, Claude Desktop and Codex can run commands and read files through ShellPilot, but never see a password, key, hostname or username. You choose per capability what is allowed, asked about or refused, and every action lands in the audit log.',
    view: 'ai',
    action: 'AI & MCP → Overview → Connect, when you want it.'
  },
  {
    id: 'done',
    title: 'That is the tour',
    body: 'Cmd/Ctrl+K opens the command palette, which reaches everything here. Shortcuts are rebindable in Settings, and this walkthrough is there too if you want it again.'
  }
]
