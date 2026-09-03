import { create } from 'zustand'
import { useShallow } from 'zustand/react/shallow'
import { FLEET_INTERVAL_DEFAULT_MS } from '../../../shared/fleet'
import { defaultModuleState, type ModuleState } from '../../../shared/modules'
import { forgetServer } from './serverCleanup'
import type {
  ActivityView,
  MonitorGroup,
  PanelView,
  Server,
  Tab,
  LocalTab,
  UUID,
  Workspace,
  Folder,
  FolderKind,
  VpnProfile,
  VpnSpec,
  VpnStatus,
  Tunnel,
  DatabaseConn
} from '../types'
import type { LocalShell } from '../../../shared/local'
import { bridgeHas } from '../lib/bridge'

// Clean default: a single empty workspace. No sample servers/VPNs/tunnels.
const DEFAULT_WORKSPACE: Workspace = {
  id: 'ws-default',
  name: 'Personal',
  color: 'cyan',
  hidden: false,
  locked: false,
  hasPassword: false
}

let seq = 0
const uid = (p: string): string => `${p}-${Date.now().toString(36)}-${seq++}`

export type ThemeMode = 'dark' | 'light' | 'system'

// The axis a tab's panes are laid out along. 'v' puts the next pane to the
// right, 'h' puts it underneath — the same two letters `toggleSplit` has always
// taken, so the shortcuts and the viewbar buttons keep their contract.
export type SplitDirection = 'h' | 'v'

// What a pane is connected to. A pane, not a tab, is what owns a session, so a
// tab can hold a remote shell beside a local one — which is the whole reason to
// split rather than open a second tab.
export type PaneTarget =
  | { kind: 'ssh'; serverId: string }
  | { kind: 'local'; shellId: string; cwd?: string }

export interface Pane {
  // Minted by the store when the pane is created and never derived during
  // render. `tabSession`/`tabCwd` are keyed by it, and a lazily synthesized id
  // would change every render — writing each session under a key that no longer
  // exists on the next one, which is how SFTP cwd-follow would break for
  // *unsplit* tabs that work today. It is also the React key of the pane's
  // subtree, so an unstable one tears down xterm and its scrollback.
  id: string
  target: PaneTarget
}

export interface TabPanes {
  // A flat, ordered list laid out along one axis. Not a tree: tmux's nested
  // splits are a much larger surface and nothing in the brief needs them.
  direction: SplitDirection
  panes: Pane[]
  // Always one of `panes`. The active pane is what SFTP follows and what a new
  // split clones, so it is maintained rather than derived.
  activePaneId: string
}

// Past four the terminals are too narrow to read and every one of them holds a
// live process. Overflow is a no-op in the store rather than a toast or a
// throw: the button that would exceed it renders disabled, so the cap is stated
// in the UI before it is enforced here, and a hotkey that hits it does nothing
// rather than opening a dialog over the terminal you are typing into.
export const MAX_PANES = 4

export interface AppSettings {
  // Set whenever stored data changes and cleared on a successful export, so
  // the UI can warn that the last backup no longer reflects reality.
  backupDirty: boolean
  lastBackupAt: string | null
  // Whether Ctrl/Cmd+1…9 counts hidden workspaces when numbering. Off means
  // hidden workspaces are skipped and cannot be reached by shortcut.
  switchHiddenWorkspaces: boolean
  // Minutes an authenticated SSH connection is kept alive after its last
  // session closes. 0 = close at once, -1 = keep until the app exits.
  sshMasterIdleMinutes: number
  // Minutes of vault inactivity before it locks itself. 0 = never. A vault that
  // never locks makes every other protection on it optional, so the default is
  // deliberately short rather than off.
  vaultAutoLockMinutes: number
  // Terminal font size in pixels, adjusted with Ctrl +/- and Ctrl+wheel.
  terminalFontSize: number
  // Host metrics docked under the terminal.
  showMonitorStrip: boolean
  // The master switch for ALL alerting: CPU/memory thresholds, failed systemd
  // units, and webhook delivery. Named `resourceAlerts` before unit alerts and
  // webhooks existed; the name is kept so saved settings still load, but the
  // UI calls it "Alerts" and says what it covers.
  resourceAlertsEnabled: boolean
  resourceAlertThreshold: number
  /**
   * Per-host overrides of the CPU/memory threshold, by server id.
   *
   * An estate is not uniform: a build box at 95% is working and a database at
   * 95% is in trouble, and one number for both means either the build box
   * cries wolf every afternoon or the database says nothing until it is too
   * late. Absent means "use the global", which is what every install has today.
   *
   * Deliberately only CPU and memory. Disk, inodes and load are fixed at
   * DISK_DANGER, INODE_DANGER and LOAD_DANGER because those are the numbers
   * other screens colour a bar at and list a host under — an alert that fired
   * at a different number from the screen it sends you to is worse than no
   * alert, which is the argument the disk alert shipped with.
   */
  resourceAlertThresholds: Record<string, number>
  // Sample every server in the workspace on a schedule from the main process,
  // so the estate is watched when the monitor is not on screen. Off by default:
  // it maintains connections to the whole estate whether or not anyone is
  // looking, which is a reasonable thing to want and not a reasonable thing to
  // start doing to someone without asking.
  fleetSamplingEnabled: boolean
  fleetSamplingIntervalMs: number
  // Optional first-party modules. Absent reads as OFF, and an upgrade never
  // switches a new one on for an existing install — see backfillModules.
  modules: ModuleState
  // Webhook delivery. These live in settings rather than in the webhook
  // service because settings are persisted and the service is not: an earlier
  // version held `enabled` in a module-level variable, so every restart
  // silently switched off a feature whose entire job is noticing failures
  // while you are not looking. The URL itself stays in safeStorage — it is a
  // credential and does not belong in a settings file or a backup.
  webhookAlertsEnabled: boolean
  webhookNotifyOnResolved: boolean
  // Tightens row heights and paddings across the app.
  compactDensity: boolean
  // Command used to open remote files. Empty means the OS default handler.
  externalEditorCommand: string
  // Double-clicking a file opens it externally rather than in the inline editor.
  openFilesExternally: boolean
  // Whether shells on this machine can be opened at all: the `+` menu, the
  // palette group and the New Local Terminal shortcut all read it.
  //
  // Defaults to `true`, and must stay that way. Settings are persisted
  // wholesale (store/persist.ts save()) and merged saved-over-default here
  // (`replaceAll`), so a `false` that ever shipped as the default would be
  // written to every install's data file and permanently outrank a later
  // change — the trap `shortcuts` documents a few lines above. Main keeps its
  // own copy of this flag (main/services/localGate.ts) and treats *absence* as
  // enabled for the same reason; the two must agree, so only an explicit user
  // toggle may ever persist `false`.
  localTerminalEnabled: boolean
  // Whether a job may detach from its channel and run on under a marker
  // directory (roadmap B2). Absence reads as ENABLED, in both the store and
  // main, for localTerminalEnabled's reason a few lines above: a `false` that
  // ever shipped as a default would be written into every install's data file
  // and outrank a later change. Off yields B1's behaviour — nothing whatsoever
  // is written to a host, and a job that was running when ShellPilot stopped is
  // abandoned, which for a package operation means dpkg took a SIGHUP.
  jobsDetached: boolean
  // Keyboard shortcut overrides, command id -> canonical combo ("Ctrl+Shift+P").
  // Only commands the user actually rebound are stored, so later releases can
  // change a default and have it reach existing installs. An empty string is a
  // deliberate unbind, which is why it is stored rather than deleted.
  shortcuts: Record<string, string>
}

export const DEFAULT_SETTINGS: AppSettings = {
  backupDirty: false,
  lastBackupAt: null,
  switchHiddenWorkspaces: false,
  sshMasterIdleMinutes: 15,
  vaultAutoLockMinutes: 15,
  terminalFontSize: 13,
  showMonitorStrip: true,
  resourceAlertsEnabled: true,
  resourceAlertThreshold: 80,
  resourceAlertThresholds: {},
  fleetSamplingEnabled: false,
  fleetSamplingIntervalMs: FLEET_INTERVAL_DEFAULT_MS,
  modules: defaultModuleState(),
  webhookAlertsEnabled: false,
  webhookNotifyOnResolved: true,
  compactDensity: false,
  externalEditorCommand: 'code',
  openFilesExternally: false,
  localTerminalEnabled: true,
  jobsDetached: true,
  shortcuts: {}
}
export type ModalKind = 'add-server' | 'workspaces' | 'route-editor' | 'add-database' | 'import-ssh' | null

/** Which of the three destinations the Tunnels & VPN view is showing. */
export type TunnelsTab = 'tunnels' | 'vpn' | 'frp'

// What openTab takes: a Tab minus the fields the store mints, with the
// workspace optional.
//
// Written distributively (`T extends Tab ? … : never`) because `Omit` is NOT
// distributive: `Omit<Tab, 'id' | 'workspaceId'>` over a union collapses to the
// keys the members share, which drops both `serverId` and `shellId` and leaves
// a shape no tab can be built from.
type NewTab<T extends Tab = Tab> = T extends Tab
  ? Omit<T, 'id' | 'workspaceId'> & { workspaceId?: UUID }
  : never

interface AppState {
  // data
  workspaces: Workspace[]
  folders: Folder[]
  servers: Server[]
  vpns: VpnProfile[]
  // Live status per profile id, straight off `vpn:status:<id>`. Kept beside the
  // profiles rather than on them, and deliberately outside the persisted slice:
  // a profile is a saved definition that belongs in a backup, a status is a
  // reading that ticks once a second. Merging the two would make every
  // handshake sample look like an edit and mark the backup out of date.
  vpnStatuses: Record<string, VpnStatus>
  tunnels: Tunnel[]
  databases: DatabaseConn[]

  // navigation
  activeWorkspaceId: string
  activity: ActivityView
  // Which destination the Tunnels & VPN view stands on. Session-only, like
  // `activity` itself and for the same reason: persist.ts saves the data a
  // backup needs, and where someone happened to be looking is not that.
  tunnelsTab: TunnelsTab
  sidebarWidth: number
  sidebarCollapsed: boolean

  // tabs
  tabs: Tab[]
  activeTabId: string | null
  // Terminal session id + working directory (for SFTP <-> terminal sync),
  // keyed by **pane** id, not tab id. A tab can hold up to MAX_PANES live
  // terminals and each has its own session and its own cwd; keying by tab meant
  // the second pane's OSC-7 cwd and session id went nowhere.
  //
  // Every entry is owned by a pane in `panes`, and `dropTabs`/`closePane` are
  // the only things that remove one — see the note on `dropTabs`.
  tabSession: Record<string, string>
  tabCwd: Record<string, string>
  // Pane layout per tab, keyed by tab id. Lives here rather than in the panel so
  // the split shortcut can reach it; not persisted, since a live session is not
  // something a backup can restore. Every tab the store creates gets an entry
  // with exactly one pane, so `panes[tab.id]` is present for the tab's lifetime.
  panes: Record<string, TabPanes>

  // Shells discovered on this machine, as main reported them. Never persisted:
  // it describes the machine the app is running on right now, so restoring it
  // from a backup taken elsewhere would offer shells that are not installed.
  // Main owns the cache; this is the renderer's copy of the last answer, shared
  // by the shell menu, the palette and openLocalById so they cannot disagree
  // about which shells exist.
  localShells: LocalShell[]

  // overlays
  modal: ModalKind
  routeEditorServerId: string | null
  // Server being edited in the add/edit modal; null means "adding new".
  editServerId: string | null
  paletteOpen: boolean
  theme: ThemeMode
  settings: AppSettings
  // Workspace ids unlocked during this session. Never persisted — locking is
  // re-applied on every app start.
  unlockedWorkspaces: string[]
  // Workspace awaiting a password before it can be activated.
  pendingWorkspaceId: string | null

  // selectors
  activeDatabaseId: string | null
  // Databases opened as tabs, in the order they were opened.
  openDatabaseIds: string[]
  monitorGroups: MonitorGroup[]

  // The active workspace id, resolved against the workspaces that exist.
  activeId: () => string
  activeWorkspace: () => Workspace
  workspaceDatabases: () => DatabaseConn[]
  workspaceServers: () => Server[]
  workspaceFolders: (kind?: FolderKind) => Folder[]
  workspaceVpns: () => VpnProfile[]
  workspaceTunnels: () => Tunnel[]
  // Non-system groups in display order, then the Ungrouped bucket last.
  workspaceMonitorGroups: () => MonitorGroup[]
  activeTab: () => Tab | null
  workspaceTabs: () => Tab[]

  // actions
  setWorkspace: (id: string) => void
  setActivity: (v: ActivityView) => void
  setTunnelsTab: (v: TunnelsTab) => void
  setSidebarWidth: (w: number) => void
  toggleSidebar: () => void
  openServer: (serverId: string, view?: PanelView) => void
  /** A shell inside a container on that server. See the implementation. */
  openContainerShell: (serverId: string, containerRef: string, sudo?: boolean) => void
  newSession: (serverId: string) => void
  // A shell on this machine, in a new tab. Never focuses an existing one: a
  // second local shell is a second shell, never the same one.
  openLocal: (shell: LocalShell, cwd?: string) => void
  // The same, resolved against `localShells`. Synchronous on purpose — the
  // hotkey RUNNERS entries are `(s) => boolean` and cannot await a lookup.
  // Unknown ids are a no-op rather than a fallback to the default shell:
  // silently spawning a different shell than the one asked for is how a
  // shellId stops meaning anything.
  openLocalById: (shellId: string, cwd?: string) => void
  // Refreshes `localShells` from main. Safe to call before the preload bridge
  // grows its `local` namespace — it no-ops rather than throwing. `refresh`
  // makes main re-enumerate rather than answer from its cache, which is what
  // the menu's Rescan entry is for.
  refreshLocalShells: (refresh?: boolean) => Promise<void>
  openTab: (tab: NewTab) => void
  closeTab: (id: string) => void
  duplicateTab: (id: string) => void
  closeOtherTabs: (id: string) => void
  closeTabsToLeft: (id: string) => void
  closeTabsToRight: (id: string) => void
  closeAllTabs: () => void
  setActiveTab: (id: string) => void
  cycleTab: (dir: 1 | -1) => void
  setTabView: (id: string, view: PanelView) => void
  // Both take a **pane** id. Named for the tab because that is what they were
  // keyed by before panes existed and every caller passes whatever it was given
  // as `tabId`; the terminal hook receives a pane id there now.
  setTabSession: (paneId: string, sessionId: string | null) => void
  setTabCwd: (paneId: string, path: string) => void
  // Adds a pane to a tab, defaulting to the same target the active pane has.
  // A no-op at MAX_PANES, and a no-op for a tab that does not exist.
  splitPane: (tabId: string, dir: SplitDirection, target?: PaneTarget) => void
  // Removes one pane and its session/cwd entries. A no-op on the last pane of a
  // tab: a tab with no panes is not representable, and making a pane-level
  // action close the tab means the small × inside a pane can take the whole tab
  // with it. Closing the last pane is closing the tab, which the tab's own × and
  // Ctrl+W already do.
  closePane: (tabId: string, paneId: string) => void
  setActivePane: (tabId: string, paneId: string) => void
  // The pre-pane split contract, kept so the two viewbar buttons and Ctrl+\ need
  // no new concepts. See the implementation for the full truth table.
  toggleSplit: (tabId: string, dir: SplitDirection) => void
  setModal: (m: ModalKind) => void
  openRouteEditor: (serverId: string) => void
  openServerEditor: (serverId: string) => void
  togglePalette: (open?: boolean) => void
  setTheme: (t: ThemeMode) => void
  setSettings: (patch: Partial<AppSettings>) => void
  setShortcut: (commandId: string, combo: string | null) => void
  resetShortcuts: () => void
  zoomTerminal: (delta: number | 'reset') => void
  isWorkspaceAccessible: (id: string) => boolean
  unlockWorkspace: (id: string) => void
  cancelWorkspaceUnlock: () => void
  lockWorkspace: (id: string) => void
  setWorkspaceProtected: (id: string, hasPassword: boolean) => void
  syncWorkspaceLocks: (lockedIds: string[]) => void
  toggleWorkspaceHidden: (id: string) => void
  addWorkspace: (name: string, color: Workspace['color']) => string
  deleteWorkspace: (id: string) => void
  toggleFavorite: (serverId: string) => void
  addServer: (input: Partial<Server> & { name: string; host: string }) => string
  setServerStatus: (serverId: string, status: Server['status']) => void
  updateServer: (id: string, patch: Partial<Omit<Server, 'id' | 'workspaceId'>>) => void
  deleteServer: (id: string) => void
  addDatabase: (input: Omit<DatabaseConn, 'id' | 'workspaceId'>) => string
  deleteDatabase: (id: string) => void
  setActiveDatabase: (id: string | null) => void
  openDatabase: (id: string) => void
  closeDatabase: (id: string) => void
  addFolder: (name: string, parentId?: string | null, kind?: FolderKind) => string
  renameFolder: (id: string, name: string) => void
  deleteFolder: (id: string) => void
  moveServerToFolder: (serverId: string, folderId: string | null) => void
  moveDatabaseToFolder: (databaseId: string, folderId: string | null) => void
  addMonitorGroup: (name: string) => string
  renameMonitorGroup: (id: string, name: string) => void
  deleteMonitorGroup: (id: string) => void
  toggleMonitorGroup: (id: string) => void
  // Places a card at an index inside a group, removing it from wherever it was.
  moveMonitorCard: (serverId: string, groupId: string, index: number) => void
  moveMonitorGroup: (id: string, toIndex: number) => void
  // Creates the Ungrouped bucket and files any server that is not on the wall
  // yet. Writes nothing when the layout is already correct.
  syncMonitorLayout: () => void
  addTunnel: (input: Omit<Tunnel, 'id' | 'workspaceId' | 'status'>) => string
  deleteTunnel: (id: string) => void
  setTunnelStatus: (id: string, status: Tunnel['status']) => void
  setVpnProfiles: (profiles: VpnProfile[]) => void
  upsertVpnProfile: (profile: VpnProfile) => void
  removeVpnProfile: (id: string) => void
  setVpnStatus: (id: string, status: VpnStatus) => void
  replaceAll: (
    data: Partial<
      Pick<
        AppState,
        | 'workspaces'
        | 'folders'
        | 'servers'
        | 'vpns'
        | 'tunnels'
        | 'databases'
        | 'settings'
        | 'activeWorkspaceId'
        | 'monitorGroups'
      >
    >
  ) => void
}

type TabSlice = Pick<AppState, 'tabs' | 'activeTabId' | 'tabSession' | 'tabCwd' | 'panes'>
type PaneSlice = Pick<AppState, 'tabSession' | 'tabCwd' | 'panes'>

// Everything a set of departing tabs owned: their layout, and the session and
// cwd of every pane inside it.
//
// It is a separate function because `dropTabs` is not the only way a tab is
// removed — `deleteWorkspace` and `deleteServer` both filter `s.tabs` directly,
// and both left their per-tab state behind long before panes existed. Nothing
// ever prunes these maps otherwise, so a missed call is a leak that lasts as
// long as the app runs, and one this cheap to route through one place.
function prunePaneState(s: PaneSlice, doomed: Set<string>): PaneSlice {
  if (doomed.size === 0) return { tabSession: s.tabSession, tabCwd: s.tabCwd, panes: s.panes }
  const tabSession = { ...s.tabSession }
  const tabCwd = { ...s.tabCwd }
  const panes = { ...s.panes }
  for (const id of doomed) {
    // Reached through `panes[id]`, never by the tab id: the entries are keyed by
    // **pane** id, so `delete tabSession[id]` — the form this had while a tab
    // held exactly one session — matches nothing and strands one entry per pane
    // per closed tab.
    for (const p of panes[id]?.panes ?? []) {
      delete tabSession[p.id]
      delete tabCwd[p.id]
    }
    delete panes[id]
  }
  return { tabSession, tabCwd, panes }
}

// Removes a set of tabs and picks the next active one: the nearest surviving
// neighbour in the same workspace, searching right first — the behaviour every
// tabbed editor has.
//
// The session/cwd entries deleted here are keyed by **pane** id, so they have to
// be reached through `panes[tabId]` rather than by the tab id. Deleting
// `tabSession[tabId]` (which is what this did while both were tab-keyed) now
// matches nothing and strands one entry per pane per closed tab, forever, in a
// map that is never otherwise pruned.
function dropTabs(s: TabSlice, doomed: Set<string>): TabSlice {
  const tabs = s.tabs.filter((t) => !doomed.has(t.id))
  const { tabSession, tabCwd, panes } = prunePaneState(s, doomed)
  let activeTabId = s.activeTabId
  if (activeTabId && doomed.has(activeTabId)) {
    const idx = s.tabs.findIndex((t) => t.id === activeTabId)
    const ws = s.tabs[idx]?.workspaceId
    const survives = (t: Tab): boolean => !doomed.has(t.id) && t.workspaceId === ws
    activeTabId =
      s.tabs.slice(idx + 1).find(survives)?.id ??
      [...s.tabs.slice(0, idx)].reverse().find(survives)?.id ??
      null
  }
  return { tabs, activeTabId, tabSession, tabCwd, panes }
}

// The pane every tab starts with: one, on the tab's own target.
//
// Minted here — inside the action that creates the tab — rather than
// synthesized by the grid during render. A render-time id is a different id
// every render, and `tabSession`/`tabCwd` are keyed by it.
function initialPanes(tab: Tab): TabPanes {
  const target: PaneTarget =
    tab.kind === 'local'
      ? { kind: 'local', shellId: tab.shellId, cwd: tab.cwd }
      : { kind: 'ssh', serverId: tab.serverId }
  const pane: Pane = { id: uid('pane'), target }
  return { direction: 'v', panes: [pane], activePaneId: pane.id }
}

// The direction the tab is *currently* split in, or null when it holds a single
// pane. This is what the viewbar's two toggle buttons highlight on, and it
// replaces reading `tabSplit[id]`: with one pane there is no split to show, even
// though `TabPanes.direction` always holds a letter.
export function splitDirectionOf(
  panes: Record<string, TabPanes>,
  tabId: string | null | undefined
): SplitDirection | null {
  const tp = tabId ? panes[tabId] : undefined
  return tp && tp.panes.length > 1 ? tp.direction : null
}

// Tabs of the workspace that sit before/after the given one, as shown in the
// tab bar — positions are taken from the workspace's own ordering, since the
// tabs array interleaves every workspace.
function sideTabs(all: Tab[], id: string, side: 'left' | 'right'): Set<string> {
  const src = all.find((t) => t.id === id)
  if (!src) return new Set()
  const mine = all.filter((t) => t.workspaceId === src.workspaceId)
  const idx = mine.findIndex((t) => t.id === id)
  const slice = side === 'left' ? mine.slice(0, idx) : mine.slice(idx + 1)
  return new Set(slice.map((t) => t.id))
}

// Repeat sessions are numbered "name", "name (2)", "name (3)". Counting is
// per-target, and the target is a server for an SSH tab and a shell for a local
// one — a single `t.serverId === serverId` comparison across both would compare
// `undefined === null`, never match, and title every local tab identically.
function sessionTitle(tabs: Tab[], match: (t: Tab) => boolean, name: string): string {
  const count = tabs.filter(match).length
  return count ? `${name} (${count + 1})` : name
}

// Tabs on the same target as `src`, for the numbering above. Kept beside
// sessionTitle so the two halves of "what counts as the same session" cannot
// drift apart.
function sameTarget(src: Tab): (t: Tab) => boolean {
  return src.kind === 'local'
    ? (t) => t.kind === 'local' && t.shellId === src.shellId
    : (t) => t.kind === 'ssh' && t.serverId === src.serverId
}

// The copy duplicateTab inserts. Built per kind rather than by spreading `src`
// and patching: the discriminant and its kind-specific fields have to travel
// together, and a spread that loses one produces a tab the union cannot
// describe.
function duplicateOf(tabs: Tab[], servers: Server[], src: Tab, id: UUID): Tab {
  if (src.kind === 'local') {
    return {
      id,
      kind: 'local',
      workspaceId: src.workspaceId,
      shellId: src.shellId,
      cwd: src.cwd,
      title: sessionTitle(tabs, sameTarget(src), src.title.replace(/ \(\d+\)$/, '')),
      view: 'terminal'
    }
  }
  const server = servers.find((sv) => sv.id === src.serverId)
  const base = server?.name ?? src.title.replace(/ \(\d+\)$/, '')
  return {
    id,
    kind: 'ssh',
    workspaceId: src.workspaceId,
    serverId: src.serverId,
    title: sessionTitle(tabs, sameTarget(src), base),
    view: src.view
  }
}

// The id every list filters against. An id that matches no workspace — a save
// written before the active workspace was stored, or one naming a workspace
// that has since been deleted — resolves to the first workspace instead of
// filtering every list down to nothing.
function resolveWorkspaceId(workspaces: Workspace[], wanted: string): string {
  return workspaces.some((w) => w.id === wanted) ? wanted : workspaces[0]?.id ?? wanted
}

// Every vault entry a profile points at. A profile is plain JSON in the saved
// blob and never holds key material itself, so deleting one has to tell main
// which vault entries it just made unreachable.
function vpnVaultEntryIds(spec: VpnSpec): string[] {
  const ids = new Set<string>()
  const take = (ref: { vaultEntryId: string } | undefined): void => {
    if (ref) ids.add(ref.vaultEntryId)
  }
  if (spec.kind === 'wireguard') {
    take(spec.privateKeyRef)
    spec.peers.forEach((p) => take(p.presharedKeyRef))
  } else if (spec.kind === 'openvpn') {
    take(spec.configRef)
    take(spec.usernameRef)
    take(spec.passwordRef)
    take(spec.keyPassphraseRef)
  } else {
    take(spec.auth.tokenRef)
    take(spec.auth.oidc?.clientSecretRef)
    spec.proxies.forEach((p) => {
      take(p.secretKeyRef)
      take(p.plugin?.passwordRef)
    })
    spec.visitors.forEach((v) => take(v.secretKeyRef))
  }
  return [...ids]
}

// Releases the vault entries a set of doomed profiles owned. Fire-and-forget:
// the profile is already gone from the slice, and a failed release leaves an
// unreferenced entry rather than a broken UI.
function releaseVpnSecrets(profiles: VpnProfile[]): void {
  // `typeof window` rather than `window?.` — a bare reference to an undeclared
  // global is a ReferenceError, not undefined, so the optional chain below does
  // not help outside a browser. The store is exercised by the test suite under
  // `environment: 'node'`, where every deleteWorkspace/removeVpnProfile call
  // used to throw here before reaching the state it was asserting on.
  if (typeof window === 'undefined') return
  if (!bridgeHas(window.shellpilot?.vpn as Record<string, unknown> | undefined, 'deleteSecrets')) return
  for (const p of profiles) {
    for (const entryId of vpnVaultEntryIds(p.spec)) {
      void window.shellpilot?.vpn.deleteSecrets(entryId)
    }
  }
}

// Clears `vpnProfileId` on every row pointing at a profile that is going away.
// Main already reads a dangling reference as "connect directly" rather than
// failing, so a leftover pointer breaks nothing — but it is a lie the saved
// blob keeps telling, and it resurfaces as a "(missing profile)" row in every
// form that reads it. Returns the array unchanged when nothing pointed at a
// doomed profile, so persist.ts's reference comparison does not report a
// backup as stale over a delete that touched none of these.
function detachVpn<T extends { vpnProfileId: string | null }>(
  rows: T[],
  doomed: Set<string>
): T[] {
  const hit = (r: T): boolean => !!r.vpnProfileId && doomed.has(r.vpnProfileId)
  return rows.some(hit) ? rows.map((r) => (hit(r) ? { ...r, vpnProfileId: null } : r)) : rows
}

export const useApp = create<AppState>((set, get) => ({
  workspaces: [DEFAULT_WORKSPACE],
  folders: [],
  monitorGroups: [],
  servers: [],
  vpns: [],
  vpnStatuses: {},
  tunnels: [],
  databases: [],

  activeDatabaseId: null,
  openDatabaseIds: [],
  activeWorkspaceId: DEFAULT_WORKSPACE.id,
  activity: 'connections',
  tunnelsTab: 'tunnels',
  sidebarWidth: 280,
  sidebarCollapsed: false,

  tabs: [],
  activeTabId: null,
  tabSession: {},
  tabCwd: {},
  panes: {},
  localShells: [],

  modal: null,
  routeEditorServerId: null,
  editServerId: null,
  paletteOpen: false,
  theme: 'dark',
  settings: DEFAULT_SETTINGS,
  unlockedWorkspaces: [],
  pendingWorkspaceId: null,

  // activeWorkspace() always fell back to the first workspace while the filters
  // below used the raw id, so a stale id showed a workspace in the header with
  // nothing under it. Both sides resolve the id the same way now.
  // The workspace* getters below filter, so each call returns a new array.
  // Never call one straight from a component as useApp((s) => s.workspaceX()):
  // useSyncExternalStore compares snapshots with Object.is, a fresh array never
  // matches, and the component re-renders itself to death (React error #185).
  // Use the useWorkspaceX hooks at the bottom of this file — they wrap the same
  // getters in useShallow. Getters returning an existing element (activeTab,
  // activeWorkspace) are stable and safe either way.
  activeId: () => resolveWorkspaceId(get().workspaces, get().activeWorkspaceId),

  activeWorkspace: () =>
    get().workspaces.find((w) => w.id === get().activeId()) ?? get().workspaces[0],
  workspaceDatabases: () => get().databases.filter((d) => d.workspaceId === get().activeId()),
  workspaceServers: () => get().servers.filter((s) => s.workspaceId === get().activeId()),
  workspaceFolders: (kind: FolderKind = 'server') =>
    get().folders.filter((f) => f.workspaceId === get().activeId() && (f.kind ?? 'server') === kind),
  workspaceVpns: () => get().vpns.filter((v) => v.workspaceId === get().activeId()),
  workspaceTunnels: () => get().tunnels.filter((t) => t.workspaceId === get().activeId()),
  workspaceMonitorGroups: () => {
    const mine = get().monitorGroups.filter((g) => g.workspaceId === get().activeId())
    // Ungrouped is where unplaced cards land, so it belongs at the bottom of
    // the wall whatever order the real groups are in.
    return [...mine.filter((g) => !g.system), ...mine.filter((g) => g.system)]
  },
  activeTab: () => get().tabs.find((t) => t.id === get().activeTabId) ?? null,
  workspaceTabs: () => get().tabs.filter((t) => t.workspaceId === get().activeId()),

  // Gated here rather than at the call sites so the switcher, the Ctrl+N
  // shortcut and the manager all go through the same check.
  setWorkspace: (id) => {
    if (!get().isWorkspaceAccessible(id)) {
      set({ pendingWorkspaceId: id })
      return
    }
    const mine = get().tabs.filter((t) => t.workspaceId === id)
    set({
      activeWorkspaceId: id,
      pendingWorkspaceId: null,
      // Sessions in other workspaces stay open; only the visible set changes.
      activeTabId: mine.some((t) => t.id === get().activeTabId)
        ? get().activeTabId
        : mine[0]?.id ?? null
    })
  },

  isWorkspaceAccessible: (id) => {
    const s = get()
    const w = s.workspaces.find((x) => x.id === id)
    if (!w?.hasPassword) return true
    return s.unlockedWorkspaces.includes(id)
  },

  unlockWorkspace: (id) =>
    set((s) => ({
      unlockedWorkspaces: s.unlockedWorkspaces.includes(id)
        ? s.unlockedWorkspaces
        : [...s.unlockedWorkspaces, id],
      activeWorkspaceId: id,
      pendingWorkspaceId: null
    })),

  cancelWorkspaceUnlock: () => set({ pendingWorkspaceId: null }),

  lockWorkspace: (id) =>
    set((s) => {
      const unlockedWorkspaces = s.unlockedWorkspaces.filter((x) => x !== id)
      if (s.activeWorkspaceId !== id) return { unlockedWorkspaces }
      // Locking the workspace you are standing in: move to the first one that
      // is still reachable, else force the unlock prompt.
      const fallback = s.workspaces.find(
        (w) => w.id !== id && (!w.hasPassword || unlockedWorkspaces.includes(w.id))
      )
      return fallback
        ? { unlockedWorkspaces, activeWorkspaceId: fallback.id }
        : { unlockedWorkspaces, pendingWorkspaceId: id }
    }),

  setWorkspaceProtected: (id, hasPassword) =>
    set((s) => ({
      workspaces: s.workspaces.map((w) =>
        w.id === id ? { ...w, hasPassword, locked: hasPassword } : w
      ),
      // Setting a password leaves it unlocked for the current session;
      // removing one drops it from the set entirely.
      unlockedWorkspaces: hasPassword
        ? [...new Set([...s.unlockedWorkspaces, id])]
        : s.unlockedWorkspaces.filter((x) => x !== id)
    })),

  // The lock file in the main process is the source of truth for which
  // workspaces have a password; reconcile the persisted flags against it.
  syncWorkspaceLocks: (lockedIds) =>
    set((s) => ({
      workspaces: s.workspaces.map((w) => {
        const has = lockedIds.includes(w.id)
        return w.hasPassword === has && w.locked === has ? w : { ...w, hasPassword: has, locked: has }
      })
    })),
  setActivity: (v) => set({ activity: v }),
  setTunnelsTab: (v) => set({ tunnelsTab: v }),
  setSidebarWidth: (w) => set({ sidebarWidth: Math.max(200, Math.min(480, w)) }),
  toggleSidebar: () => set((s) => ({ sidebarCollapsed: !s.sidebarCollapsed })),

  // Focus an existing tab for this server (switching its view), or open one.
  // A server maps to a single tab whose view is switched in place, so the
  // terminal session survives Terminal <-> Monitor <-> Files navigation.
  // A shell inside a container, in its own tab.
  //
  // Focuses an existing tab for the same container rather than opening a
  // second: two shells in one container is occasionally wanted and always
  // confusing to arrive at by accident, and the Docker panel's button is one
  // click from a list that redraws.
  //
  // The tab is an SSH tab with a containerRef. What actually runs is built by
  // buildDockerShellCommand, which validates the reference and throws rather
  // than escaping it — the ref is never taken as free text.
  openContainerShell: (serverId, containerRef, sudo = false) => {
    const server = get().servers.find((s) => s.id === serverId)
    if (!server) return
    const existing = get().tabs.find(
      (t) => t.kind === 'ssh' && t.serverId === serverId && t.containerRef === containerRef
    )
    if (existing) {
      set({ activeTabId: existing.id })
      return
    }
    const tab: Tab = {
      id: uid('tab'),
      kind: 'ssh',
      workspaceId: server.workspaceId,
      serverId,
      containerRef,
      containerSudo: sudo || undefined,
      title: containerRef,
      // Monitor and Files read the host, not the container. Offering them here
      // would show the host's disk usage under a container's name.
      view: 'terminal'
    }
    set((s) => ({ tabs: [...s.tabs, tab], activeTabId: tab.id, activity: 'connections' }))
  },

  openServer: (serverId, view = 'terminal') => {
    const server = get().servers.find((s) => s.id === serverId)
    if (!server) return
    // `!t.containerRef` matters: a container shell is also an SSH tab for this
    // server, and without it "open this server" would focus a shell inside a
    // container instead of one on the host.
    const existing = get().tabs.find(
      (t) => t.kind === 'ssh' && t.serverId === serverId && !t.containerRef
    )
    if (existing) {
      set((s) => ({
        activeTabId: existing.id,
        // Re-narrowed inside the map: `view` is a PanelView and only an SSH tab
        // can hold Monitor or Files.
        tabs: s.tabs.map((t) => (t.id === existing.id && t.kind === 'ssh' ? { ...t, view } : t))
      }))
      return
    }
    const tab: Tab = {
      id: uid('tab'),
      kind: 'ssh',
      workspaceId: server.workspaceId,
      serverId,
      title: server.name,
      view
    }
    set((s) => ({
      tabs: [...s.tabs, tab],
      activeTabId: tab.id,
      panes: { ...s.panes, [tab.id]: initialPanes(tab) }
    }))
  },

  // Always open an additional session tab for a server (multiple terminals).
  newSession: (serverId) => {
    const server = get().servers.find((s) => s.id === serverId)
    if (!server) return
    const tab: Tab = {
      id: uid('tab'),
      kind: 'ssh',
      workspaceId: server.workspaceId,
      serverId,
      title: sessionTitle(get().tabs, (t) => t.kind === 'ssh' && t.serverId === serverId, server.name),
      view: 'terminal'
    }
    set((s) => ({
      tabs: [...s.tabs, tab],
      activeTabId: tab.id,
      panes: { ...s.panes, [tab.id]: initialPanes(tab) }
    }))
  },

  // A shell on this machine. Nothing is written to `servers` here, and that is
  // the entire point of the union: `servers` is persisted and mirrored into the
  // MCP data cache, so a synthesized row would hand an agent a target that no
  // tool ever declared.
  openLocal: (shell, cwd) => {
    const tab: LocalTab = {
      id: uid('tab'),
      kind: 'local',
      workspaceId: get().activeId(),
      shellId: shell.id,
      cwd,
      title: sessionTitle(
        get().tabs,
        (t) => t.kind === 'local' && t.shellId === shell.id,
        shell.label
      ),
      view: 'terminal'
    }
    set((s) => ({
      tabs: [...s.tabs, tab],
      activeTabId: tab.id,
      panes: { ...s.panes, [tab.id]: initialPanes(tab) }
    }))
  },

  openLocalById: (shellId, cwd) => {
    // Shell ids are opaque ('darwin-zsh-b663616e' — a readable prefix plus a
    // digest of the path), so this is an exact lookup and never a parse.
    const shell = get().localShells.find((sh) => sh.id === shellId)
    if (!shell) return
    get().openLocal(shell, cwd)
  },

  refreshLocalShells: async (refresh) => {
    // Guarded twice on purpose. `typeof window` covers the store being driven
    // outside a browser (the test suite runs under `environment: 'node'`), and
    // `bridgeHas` covers the dev-server case the whole module exists for: the
    // renderer hot-reloads while the process keeps the preload bundle it booted
    // with, so a method added in this session is undefined for the rest of it.
    // A missing shell list is an empty menu, never a thrown effect.
    if (typeof window === 'undefined') return
    const ns = window.shellpilot?.local
    if (!ns || !bridgeHas(ns as Record<string, unknown> | undefined, 'shells')) return
    const shells = await ns.shells(refresh)
    set({ localShells: Array.isArray(shells) ? shells : [] })
  },

  // Opens a second session on the same target, next to the original, keeping
  // its view and working directory. The session itself is not shared: an SSH
  // tab dials its own shell over the pooled connection, and a local tab spawns
  // its own pty.
  duplicateTab: (id) =>
    set((s) => {
      const src = s.tabs.find((t) => t.id === id)
      if (!src) return {}
      const tab = duplicateOf(s.tabs, s.servers, src, uid('tab'))
      const idx = s.tabs.findIndex((t) => t.id === id)

      // The layout is copied pane for pane — duplicating a split tab that came
      // back as a single pane would be a surprise — but every pane gets a fresh
      // id, because a pane id keys a live session and the copy is a new one.
      //
      // The cwd copy travels with it. It used to read `tabCwd[id]`, which was
      // the tab's own key; once sessions moved to pane ids that lookup silently
      // matched nothing and the duplicate stopped inheriting the remote
      // directory, contradicting this action's own promise.
      const srcPanes = s.panes[id]
      const tabCwd = { ...s.tabCwd }
      let panes = s.panes
      if (srcPanes) {
        const copies = srcPanes.panes.map((p) => {
          const copy: Pane = { id: uid('pane'), target: p.target }
          const cwd = s.tabCwd[p.id]
          if (cwd) tabCwd[copy.id] = cwd
          return { from: p.id, copy }
        })
        panes = {
          ...s.panes,
          [tab.id]: {
            direction: srcPanes.direction,
            panes: copies.map((c) => c.copy),
            activePaneId:
              copies.find((c) => c.from === srcPanes.activePaneId)?.copy.id ?? copies[0].copy.id
          }
        }
      } else {
        panes = { ...s.panes, [tab.id]: initialPanes(tab) }
      }

      return {
        tabs: [...s.tabs.slice(0, idx + 1), tab, ...s.tabs.slice(idx + 1)],
        activeTabId: tab.id,
        tabCwd,
        panes
      }
    }),

  openTab: (tab) => {
    const workspaceId = tab.workspaceId ?? get().activeWorkspaceId
    const id = uid('tab')
    // Narrowed before the spread, not after: spreading the union directly
    // produces an object TypeScript cannot match to either member, because the
    // discriminant is widened away along with everything keyed off it.
    const t: Tab = tab.kind === 'ssh' ? { ...tab, workspaceId, id } : { ...tab, workspaceId, id }
    set((s) => ({
      tabs: [...s.tabs, t],
      activeTabId: t.id,
      panes: { ...s.panes, [t.id]: initialPanes(t) }
    }))
  },

  closeTab: (id) => set((s) => dropTabs(s, new Set([id]))),

  // The bulk closes only ever touch the workspace the tab belongs to — tabs in
  // other workspaces are not on screen and their sessions must survive.
  closeOtherTabs: (id) =>
    set((s) => {
      const src = s.tabs.find((t) => t.id === id)
      if (!src) return {}
      const doomed = s.tabs.filter((t) => t.workspaceId === src.workspaceId && t.id !== id)
      return { ...dropTabs(s, new Set(doomed.map((t) => t.id))), activeTabId: id }
    }),

  closeTabsToLeft: (id) => set((s) => dropTabs(s, sideTabs(s.tabs, id, 'left'))),
  closeTabsToRight: (id) => set((s) => dropTabs(s, sideTabs(s.tabs, id, 'right'))),

  closeAllTabs: () =>
    set((s) =>
      dropTabs(s, new Set(s.tabs.filter((t) => t.workspaceId === s.activeWorkspaceId).map((t) => t.id)))
    ),

  setActiveTab: (id) => set({ activeTabId: id }),

  cycleTab: (dir) =>
    set((s) => {
      const mine = s.tabs.filter((t) => t.workspaceId === s.activeWorkspaceId)
      if (mine.length === 0) return {}
      const idx = mine.findIndex((t) => t.id === s.activeTabId)
      const next = (idx + dir + mine.length) % mine.length
      return { activeTabId: mine[next].id }
    }),

  // Monitor and Files are SSH-only views, so this is a no-op on a local tab
  // rather than a state the UI has no way to render. It used to be reachable
  // from the open-files shortcut, which would have blanked the pane with no
  // way back.
  setTabView: (id, view) =>
    set((s) => ({
      tabs: s.tabs.map((t) => (t.id === id && t.kind === 'ssh' ? { ...t, view } : t))
    })),

  setTabSession: (tabId, sessionId) =>
    set((s) => {
      const next = { ...s.tabSession }
      if (sessionId) next[tabId] = sessionId
      else delete next[tabId]
      return { tabSession: next }
    }),

  setTabCwd: (paneId, path) => set((s) => ({ tabCwd: { ...s.tabCwd, [paneId]: path } })),

  splitPane: (tabId, dir, target) =>
    set((s) => {
      const tp = s.panes[tabId]
      if (!tp || tp.panes.length >= MAX_PANES) return {}
      const source = tp.panes.find((p) => p.id === tp.activePaneId) ?? tp.panes[0]
      const pane: Pane = { id: uid('pane'), target: target ?? source.target }
      // Inserted after the pane it was split from, not appended: splitting the
      // left pane of three should put the new one next to it.
      const at = tp.panes.findIndex((p) => p.id === source.id) + 1
      return {
        panes: {
          ...s.panes,
          [tabId]: {
            direction: dir,
            panes: [...tp.panes.slice(0, at), pane, ...tp.panes.slice(at)],
            activePaneId: pane.id
          }
        }
      }
    }),

  closePane: (tabId, paneId) =>
    set((s) => {
      const tp = s.panes[tabId]
      if (!tp || tp.panes.length < 2) return {}
      const idx = tp.panes.findIndex((p) => p.id === paneId)
      if (idx === -1) return {}
      const remaining = tp.panes.filter((p) => p.id !== paneId)
      const tabSession = { ...s.tabSession }
      const tabCwd = { ...s.tabCwd }
      delete tabSession[paneId]
      delete tabCwd[paneId]
      return {
        tabSession,
        tabCwd,
        panes: {
          ...s.panes,
          [tabId]: {
            ...tp,
            panes: remaining,
            // Focus moves to the neighbour on the right, then the left — the
            // same rule dropTabs uses for tabs.
            activePaneId:
              tp.activePaneId === paneId
                ? (remaining[idx] ?? remaining[idx - 1]).id
                : tp.activePaneId
          }
        }
      }
    }),

  setActivePane: (tabId, paneId) =>
    set((s) => {
      const tp = s.panes[tabId]
      if (!tp || tp.activePaneId === paneId || !tp.panes.some((p) => p.id === paneId)) return {}
      return { panes: { ...s.panes, [tabId]: { ...tp, activePaneId: paneId } } }
    }),

  // The shim the two viewbar buttons and Ctrl+\ / Ctrl+Shift+\ still call.
  //
  //  | panes | current dir | toggleSplit(dir) | result                        |
  //  |-------|-------------|------------------|-------------------------------|
  //  | 0/none| —           | either           | no-op (no such tab)           |
  //  | 1     | any         | 'v'              | split → 2 panes, direction 'v'|
  //  | 1     | any         | 'h'              | split → 2 panes, direction 'h'|
  //  | 2     | same as dir | dir              | collapse to the ACTIVE pane   |
  //  | 2     | other       | dir              | re-orient, still 2 panes      |
  //  | 3–4   | same as dir | dir              | no-op                         |
  //  | 3–4   | other       | dir              | re-orient, panes unchanged    |
  //  | 4     | other       | dir              | re-orient (adds no pane, so   |
  //  |       |             |                  | the cap does not apply)       |
  //
  // Two decisions worth stating. **Collapse keeps the active pane, not the
  // first**: pressing the button that un-splits should leave you in the terminal
  // you were typing in. And **collapse only applies at exactly two panes** —
  // the count the pre-pane model could ever be in, which is what this shim
  // exists to reproduce. With three or four live shells the same keystroke
  // would kill two or three of them with no confirmation and no undo, so it
  // does nothing instead and the panes are closed one at a time.
  // Written as a plain body rather than a `set` updater because the split case
  // delegates to `splitPane`, and calling one action's `set` from inside
  // another's updater applies both but discards the first's result from the
  // reference the outer merge is built on.
  toggleSplit: (tabId, dir) => {
    const tp = get().panes[tabId]
    if (!tp) return
    if (tp.panes.length === 1) {
      get().splitPane(tabId, dir)
      return
    }
    if (tp.direction !== dir) {
      set((s) => ({ panes: { ...s.panes, [tabId]: { ...tp, direction: dir } } }))
      return
    }
    if (tp.panes.length > 2) return
    const kept = tp.panes.find((p) => p.id === tp.activePaneId) ?? tp.panes[0]
    set((s) => {
      const tabSession = { ...s.tabSession }
      const tabCwd = { ...s.tabCwd }
      for (const p of tp.panes) {
        if (p.id === kept.id) continue
        delete tabSession[p.id]
        delete tabCwd[p.id]
      }
      return {
        tabSession,
        tabCwd,
        panes: { ...s.panes, [tabId]: { ...tp, panes: [kept], activePaneId: kept.id } }
      }
    })
  },

  setModal: (m) => set({ modal: m, editServerId: null }),
  openServerEditor: (serverId) => set({ editServerId: serverId, modal: 'add-server' }),

  openRouteEditor: (serverId) => set({ modal: 'route-editor', routeEditorServerId: serverId }),
  togglePalette: (open) => set((s) => ({ paletteOpen: open ?? !s.paletteOpen })),
  setTheme: (t) => set({ theme: t }),

  setSettings: (patch) => set((s) => ({ settings: { ...s.settings, ...patch } })),

  // combo === null restores the built-in default by dropping the override;
  // an empty string is kept, because that is how a command is left unbound.
  setShortcut: (commandId, combo) =>
    set((s) => {
      const shortcuts = { ...s.settings.shortcuts }
      if (combo === null) delete shortcuts[commandId]
      else shortcuts[commandId] = combo
      return { settings: { ...s.settings, shortcuts } }
    }),

  resetShortcuts: () => set((s) => ({ settings: { ...s.settings, shortcuts: {} } })),

  // Clamped so the terminal can never be zoomed into unusability.
  zoomTerminal: (delta) =>
    set((s) => ({
      settings: {
        ...s.settings,
        terminalFontSize:
          delta === 'reset'
            ? DEFAULT_SETTINGS.terminalFontSize
            : Math.max(8, Math.min(32, s.settings.terminalFontSize + delta))
      }
    })),

  toggleWorkspaceHidden: (id) =>
    set((s) => ({
      workspaces: s.workspaces.map((w) => (w.id === id ? { ...w, hidden: !w.hidden } : w))
    })),

  addWorkspace: (name, color) => {
    const id = uid('ws')
    set((s) => ({
      workspaces: [
        ...s.workspaces,
        { id, name, color, hidden: false, locked: false, hasPassword: false }
      ]
    }))
    return id
  },

  // Removes the workspace and everything scoped to it. Refuses the last one,
  // since the app always needs somewhere to put connections.
  deleteWorkspace: (id) =>
    set((s) => {
      if (s.workspaces.length <= 1) return {}
      const remaining = s.workspaces.filter((w) => w.id !== id)
      const doomedServers = new Set(s.servers.filter((v) => v.workspaceId === id).map((v) => v.id))
      // Profiles are workspace-scoped, so in practice only this workspace's own
      // records name them — but a record that survives the cascade must not
      // keep pointing at one that did not.
      const doomedVpns = new Set(s.vpns.filter((v) => v.workspaceId === id).map((v) => v.id))
      // The profiles go with the workspace, but their vault entries do not go by
      // themselves — release them for the same reason removeVpnProfile does.
      releaseVpnSecrets(s.vpns.filter((v) => v.workspaceId === id))
      // Tabs go with their workspace whatever backs them — a local tab has no
      // server to cascade from, so filtering on doomedServers alone would leave
      // it stranded in a workspace that no longer exists, unreachable from the
      // tab bar and still holding a live pty.
      const keptTabs = s.tabs.filter(
        (t) => t.workspaceId !== id && (t.kind !== 'ssh' || !doomedServers.has(t.serverId))
      )
      const kept = new Set(keptTabs.map((t) => t.id))
      return {
        ...prunePaneState(s, new Set(s.tabs.filter((t) => !kept.has(t.id)).map((t) => t.id))),
        workspaces: remaining,
        folders: s.folders.filter((f) => f.workspaceId !== id),
        servers: detachVpn(s.servers.filter((v) => v.workspaceId !== id), doomedVpns),
        monitorGroups: s.monitorGroups.filter((g) => g.workspaceId !== id),
        databases: detachVpn(s.databases.filter((d) => d.workspaceId !== id), doomedVpns),
        vpns: s.vpns.filter((v) => v.workspaceId !== id),
        tunnels: s.tunnels.filter((t) => t.workspaceId !== id),
        tabs: keptTabs,
        // Asked of the surviving list rather than of the doomed one: the old
        // form only cleared the active tab when a *server* took it, so an
        // active tab removed for any other reason left activeTabId dangling.
        activeTabId: keptTabs.some((t) => t.id === s.activeTabId) ? s.activeTabId : null,
        activeWorkspaceId: s.activeWorkspaceId === id ? remaining[0].id : s.activeWorkspaceId,
        unlockedWorkspaces: s.unlockedWorkspaces.filter((w) => w !== id)
      }
    }),

  toggleFavorite: (serverId) =>
    set((s) => ({
      servers: s.servers.map((sv) =>
        sv.id === serverId ? { ...sv, favorite: !sv.favorite } : sv
      )
    })),

  addServer: (input) => {
    const id = uid('s')
    set((s) => ({
      servers: [
        ...s.servers,
        {
          id,
          // Normally the workspace you are looking at, but an agent-initiated
          // add names the workspace its session is scoped to, which is not
          // necessarily the one on screen.
          workspaceId: input.workspaceId ?? s.activeWorkspaceId,
          folderId: input.folderId ?? null,
          name: input.name,
          host: input.host,
          port: input.port ?? 22,
          username: input.username ?? 'root',
          auth: input.auth ?? 'key',
          status: 'offline',
          tags: input.tags ?? [],
          favorite: false,
          os: input.os ?? 'Linux',
          route: input.route ?? [],
          // Direct by default. A server that silently rode a VPN nobody chose
          // would be a surprising thing to inherit from a bulk import.
          vpnProfileId: input.vpnProfileId ?? null,
          demo: false
        }
      ]
    }))
    return id
  },

  updateServer: (id, patch) =>
    set((s) => ({ servers: s.servers.map((sv) => (sv.id === id ? { ...sv, ...patch } : sv)) })),

  deleteServer: (id) => {
    // Forget everything keyed by this server before dropping it.
    //
    // All three of these were written with docstrings describing exactly this
    // and then never called. The consequences were real: an active CPU alert
    // kept counting in the status bar under the name of a server that no longer
    // existed, its last metrics stayed in the fleet totals, and its failed-unit
    // set persisted — so deleting and re-adding a server suppressed the first
    // genuine failure as "not fresh", which is the precise thing
    // clearUnitAlerts promised to prevent.
    forgetServer(id)
    set((s) => {
      // Close any tabs pointing at the server that no longer exists. Local tabs
      // are not among them: they have no server, so deleting one cannot orphan
      // them and they keep running.
      const keptTabs = s.tabs.filter((t) => t.kind !== 'ssh' || t.serverId !== id)
      const kept = new Set(keptTabs.map((t) => t.id))
      return {
        ...prunePaneState(s, new Set(s.tabs.filter((t) => !kept.has(t.id)).map((t) => t.id))),
        servers: s.servers.filter((sv) => sv.id !== id),
        tabs: keptTabs,
        activeTabId: keptTabs.some((t) => t.id === s.activeTabId) ? s.activeTabId : null
      }
    })
  },

  setServerStatus: (serverId, status) =>
    set((s) => ({
      servers: s.servers.map((sv) => (sv.id === serverId ? { ...sv, status } : sv))
    })),

  addDatabase: (input) => {
    const id = uid('db')
    set((s) => ({
      databases: [
        ...s.databases,
        { ...input, vpnProfileId: input.vpnProfileId ?? null, id, workspaceId: s.activeWorkspaceId }
      ],
      activeDatabaseId: id,
      openDatabaseIds: [...s.openDatabaseIds, id]
    }))
    return id
  },

  deleteDatabase: (id) =>
    set((s) => ({
      databases: s.databases.filter((d) => d.id !== id),
      openDatabaseIds: s.openDatabaseIds.filter((d) => d !== id),
      activeDatabaseId: s.activeDatabaseId === id ? null : s.activeDatabaseId
    })),

  setActiveDatabase: (id) => set({ activeDatabaseId: id }),

  openDatabase: (id) =>
    set((s) => ({
      activeDatabaseId: id,
      openDatabaseIds: s.openDatabaseIds.includes(id) ? s.openDatabaseIds : [...s.openDatabaseIds, id]
    })),

  closeDatabase: (id) =>
    set((s) => {
      const open = s.openDatabaseIds.filter((d) => d !== id)
      const idx = s.openDatabaseIds.indexOf(id)
      return {
        openDatabaseIds: open,
        activeDatabaseId:
          s.activeDatabaseId === id ? open[idx] ?? open[idx - 1] ?? open[0] ?? null : s.activeDatabaseId
      }
    }),

  addFolder: (name, parentId = null, kind = 'server') => {
    const id = uid('f')
    set((s) => ({
      folders: [...s.folders, { id, workspaceId: s.activeWorkspaceId, name, parentId, kind }]
    }))
    return id
  },

  renameFolder: (id, name) =>
    set((s) => ({ folders: s.folders.map((f) => (f.id === id ? { ...f, name } : f)) })),

  deleteFolder: (id) =>
    set((s) => ({
      // Detach children to root rather than deleting servers/databases/subfolders.
      folders: s.folders.filter((f) => f.id !== id).map((f) => (f.parentId === id ? { ...f, parentId: null } : f)),
      servers: s.servers.map((sv) => (sv.folderId === id ? { ...sv, folderId: null } : sv)),
      databases: s.databases.map((d) => (d.folderId === id ? { ...d, folderId: null } : d))
    })),

  moveServerToFolder: (serverId, folderId) =>
    set((s) => ({
      servers: s.servers.map((sv) => (sv.id === serverId ? { ...sv, folderId } : sv))
    })),

  addTunnel: (input) => {
    const id = uid('tun')
    set((s) => ({
      tunnels: [...s.tunnels, { ...input, id, workspaceId: s.activeWorkspaceId, status: 'inactive' }]
    }))
    return id
  },

  deleteTunnel: (id) => set((s) => ({ tunnels: s.tunnels.filter((t) => t.id !== id) })),

  // A live tunnel re-emits its status on every connection open and close, so
  // this is called constantly with a status that has not moved. Writing it
  // anyway would still allocate a fresh tunnel object, and anything selecting
  // the list by identity would read that as a change — so bail out when
  // nothing actually differs. Returning the state object unchanged makes it a
  // true no-op: zustand skips notifying subscribers at all.
  setTunnelStatus: (id, status) =>
    set((s) =>
      s.tunnels.some((t) => t.id === id && t.status !== status)
        ? { tunnels: s.tunnels.map((t) => (t.id === id ? { ...t, status } : t)) }
        : s
    ),

  setVpnProfiles: (profiles) => set({ vpns: profiles }),

  upsertVpnProfile: (profile) =>
    set((s) => ({
      vpns: s.vpns.some((v) => v.id === profile.id)
        ? s.vpns.map((v) => (v.id === profile.id ? profile : v))
        : [...s.vpns, profile]
    })),

  removeVpnProfile: (id) =>
    set((s) => {
      const doomed = s.vpns.find((v) => v.id === id)
      // The profile is just JSON in the saved blob, but its key material is in
      // the vault and nothing else points at it once this row is gone.
      if (doomed) releaseVpnSecrets([doomed])
      // The live status goes too; leaving it behind would keep a deleted
      // profile "connected" for anything reading the map by id.
      const { [id]: _gone, ...vpnStatuses } = s.vpnStatuses
      // Detached in the same action as the delete, so the saved blob is never
      // written with a pointer to a profile that no longer exists.
      const doomedIds = new Set([id])
      return {
        vpns: s.vpns.filter((v) => v.id !== id),
        servers: detachVpn(s.servers, doomedIds),
        databases: detachVpn(s.databases, doomedIds),
        vpnStatuses
      }
    }),

  // Called on every coalesced status tick, so it has to be a true no-op when
  // nothing moved — same reasoning as setTunnelStatus above. Comparing the
  // sample timestamp is enough: main only re-emits when the payload differs.
  setVpnStatus: (id, status) =>
    set((s) => {
      const prev = s.vpnStatuses[id]
      if (
        prev &&
        prev.state === status.state &&
        prev.restarts === status.restarts &&
        prev.error === status.error &&
        prev.stats?.sampledAt === status.stats?.sampledAt
      ) {
        return s
      }
      return { vpnStatuses: { ...s.vpnStatuses, [id]: status } }
    }),

  moveDatabaseToFolder: (databaseId, folderId) =>
    set((s) => ({
      databases: s.databases.map((d) => (d.id === databaseId ? { ...d, folderId } : d))
    })),

  addMonitorGroup: (name) => {
    const id = uid('mg')
    set((s) => ({
      monitorGroups: [
        ...s.monitorGroups,
        { id, workspaceId: s.activeId(), name, collapsed: false, serverIds: [] }
      ]
    }))
    return id
  },

  renameMonitorGroup: (id, name) =>
    set((s) => ({
      monitorGroups: s.monitorGroups.map((g) => (g.id === id && !g.system ? { ...g, name } : g))
    })),

  deleteMonitorGroup: (id) =>
    set((s) => {
      const doomed = s.monitorGroups.find((g) => g.id === id)
      if (!doomed || doomed.system) return {}
      // The cards are not deleted with the group. They become unplaced, and
      // syncMonitorLayout files them back under Ungrouped.
      return { monitorGroups: s.monitorGroups.filter((g) => g.id !== id) }
    }),

  toggleMonitorGroup: (id) =>
    set((s) => ({
      monitorGroups: s.monitorGroups.map((g) => (g.id === id ? { ...g, collapsed: !g.collapsed } : g))
    })),

  moveMonitorCard: (serverId, groupId, index) =>
    set((s) => {
      const ws = s.activeId()
      let insertAt = index
      const stripped = s.monitorGroups.map((g) => {
        if (g.workspaceId !== ws || !g.serverIds.includes(serverId)) return g
        // Dropping further along the group it already sits in: pulling the card
        // out first shifts every later slot down by one.
        if (g.id === groupId && g.serverIds.indexOf(serverId) < insertAt) insertAt--
        return { ...g, serverIds: g.serverIds.filter((id) => id !== serverId) }
      })
      return {
        monitorGroups: stripped.map((g) => {
          if (g.id !== groupId) return g
          const next = [...g.serverIds]
          next.splice(Math.max(0, Math.min(insertAt, next.length)), 0, serverId)
          return { ...g, serverIds: next }
        })
      }
    }),

  moveMonitorGroup: (id, toIndex) =>
    set((s) => {
      const ws = s.activeId()
      // Ungrouped is pinned to the bottom, so only the real groups reorder.
      const mine = s.monitorGroups.filter((g) => g.workspaceId === ws && !g.system)
      const from = mine.findIndex((g) => g.id === id)
      if (from === -1) return {}
      const next = [...mine]
      const [moved] = next.splice(from, 1)
      next.splice(Math.max(0, Math.min(toIndex, next.length)), 0, moved)
      // Refill this workspace's slots in the new order, leaving every other
      // workspace's groups exactly where they were in the flat array.
      const queue = [...next]
      return {
        monitorGroups: s.monitorGroups.map((g) =>
          g.workspaceId === ws && !g.system ? (queue.shift() as MonitorGroup) : g
        )
      }
    }),

  syncMonitorLayout: () =>
    set((s) => {
      const ws = s.activeId()
      const live = new Set(s.servers.filter((sv) => sv.workspaceId === ws).map((sv) => sv.id))
      const system = s.monitorGroups.find((g) => g.workspaceId === ws && g.system)

      const seen = new Set<string>()
      let changed = false
      const pruned = s.monitorGroups.map((g) => {
        if (g.workspaceId !== ws) return g
        const kept = g.serverIds.filter((id) => {
          // Drops servers that were deleted or moved to another workspace, and
          // keeps only the first placement if one ever ended up in two groups.
          if (!live.has(id) || seen.has(id)) return false
          seen.add(id)
          return true
        })
        if (kept.length === g.serverIds.length) return g
        changed = true
        return { ...g, serverIds: kept }
      })

      const unplaced = [...live].filter((id) => !seen.has(id))

      if (!system) {
        return {
          monitorGroups: [
            ...pruned,
            {
              id: uid('mg'),
              workspaceId: ws,
              name: 'Ungrouped',
              collapsed: false,
              serverIds: unplaced,
              system: true
            }
          ]
        }
      }
      // Nothing to file and nothing stale: return no change at all, so this
      // cannot loop with the effect that calls it or dirty the save file.
      if (unplaced.length === 0) return changed ? { monitorGroups: pruned } : {}
      return {
        monitorGroups: pruned.map((g) =>
          g.id === system.id ? { ...g, serverIds: [...g.serverIds, ...unplaced] } : g
        )
      }
    }),

  // Older saves predate folder kinds and database folders — normalise on load
  // so existing folders stay with connections and databases start at root.
  replaceAll: (data) =>
    set((s) => ({
      ...s,
      ...data,
      // The saved active workspace is restored here rather than left at the
      // seed default, and pinned to a workspace that actually exists.
      activeWorkspaceId: resolveWorkspaceId(
        data.workspaces ?? s.workspaces,
        data.activeWorkspaceId ?? s.activeWorkspaceId
      ),
      folders: (data.folders ?? s.folders).map((f) => ({ ...f, kind: f.kind ?? 'server' })),
      // Saves written before a server could name a VPN have no such key at all.
      // Normalising on load rather than defaulting at every read keeps
      // "null means direct" the one representation the rest of the app sees.
      servers: (data.servers ?? s.servers).map((sv) => ({
        ...sv,
        vpnProfileId: sv.vpnProfileId ?? null
      })),
      databases: (data.databases ?? s.databases).map((d) => ({
        ...d,
        folderId: d.folderId ?? null,
        sshServerId: d.sshServerId ?? null,
        vpnProfileId: d.vpnProfileId ?? null
      })),
      // Saves written before the VPN domain was real hold the old mock shape at
      // this key — a record with `kind`/`rx`/`tx` and no `spec` at all. Dropping
      // anything without a spec is cheaper than a migration and cannot leave a
      // half-typed profile in a list every start/stop path dereferences.
      vpns: (data.vpns ?? s.vpns).filter((v) => !!v && !!v.spec),
      // Merge over defaults so a preference added in a later version is not
      // left undefined when an older save is loaded.
      // Nothing is forwarding yet at launch, whatever the last save said.
      tunnels: (data.tunnels ?? s.tunnels).map((t) => ({
        ...t,
        status: 'inactive' as const,
        serverId: t.serverId ?? null
      })),
      settings: { ...DEFAULT_SETTINGS, ...(data.settings ?? {}) }
    }))
}))

// Derived collection hooks. These selectors return freshly-filtered arrays, so
// they MUST be wrapped in useShallow — otherwise zustand's strict-equality
// check sees a new reference every render and loops forever (React #185).
export const useWorkspaceServers = () => useApp(useShallow((s) => s.workspaceServers()))
export const useWorkspaceFolders = (kind: FolderKind = 'server') =>
  useApp(useShallow((s) => s.workspaceFolders(kind)))
export const useWorkspaceVpns = () => useApp(useShallow((s) => s.workspaceVpns()))
export const useWorkspaceTunnels = () => useApp(useShallow((s) => s.workspaceTunnels()))
export const useWorkspaceDatabases = () => useApp(useShallow((s) => s.workspaceDatabases()))
export const useWorkspaceTabs = () => useApp(useShallow((s) => s.workspaceTabs()))
export const useWorkspaceMonitorGroups = () =>
  useApp(useShallow((s) => s.workspaceMonitorGroups()))
