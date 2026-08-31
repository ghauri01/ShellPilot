import { create } from 'zustand'
import { useShallow } from 'zustand/react/shallow'
import type {
  ActivityView,
  MonitorGroup,
  PanelView,
  Server,
  Tab,
  Workspace,
  Folder,
  FolderKind,
  VpnProfile,
  VpnSpec,
  VpnStatus,
  Tunnel,
  DatabaseConn
} from '../types'
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

// Terminal split direction for a tab. 'v' puts the second pane to the right,
// 'h' puts it underneath; null is a single pane.
export type TabSplit = 'h' | 'v' | null

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
  // Warn when a host's CPU or memory stays at or above the threshold.
  resourceAlertsEnabled: boolean
  resourceAlertThreshold: number
  // Tightens row heights and paddings across the app.
  compactDensity: boolean
  // Command used to open remote files. Empty means the OS default handler.
  externalEditorCommand: string
  // Double-clicking a file opens it externally rather than in the inline editor.
  openFilesExternally: boolean
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
  compactDensity: false,
  externalEditorCommand: 'code',
  openFilesExternally: false,
  shortcuts: {}
}
export type ModalKind = 'add-server' | 'workspaces' | 'route-editor' | 'add-database' | 'import-ssh' | null

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
  sidebarWidth: number
  sidebarCollapsed: boolean

  // tabs
  tabs: Tab[]
  activeTabId: string | null
  // per-tab terminal session id + working directory (for SFTP <-> terminal sync)
  tabSession: Record<string, string>
  tabCwd: Record<string, string>
  // Split layout per tab. Lives here rather than in the panel so the split
  // shortcut can reach it; not persisted, since a split is a view state that
  // belongs to a live session.
  tabSplit: Record<string, TabSplit>

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
  setSidebarWidth: (w: number) => void
  toggleSidebar: () => void
  openServer: (serverId: string, view?: PanelView) => void
  newSession: (serverId: string) => void
  openTab: (tab: Omit<Tab, 'id' | 'workspaceId'> & { workspaceId?: string }) => void
  closeTab: (id: string) => void
  duplicateTab: (id: string) => void
  closeOtherTabs: (id: string) => void
  closeTabsToLeft: (id: string) => void
  closeTabsToRight: (id: string) => void
  closeAllTabs: () => void
  setActiveTab: (id: string) => void
  cycleTab: (dir: 1 | -1) => void
  setTabView: (id: string, view: PanelView) => void
  setTabSession: (tabId: string, sessionId: string | null) => void
  setTabCwd: (tabId: string, path: string) => void
  toggleSplit: (tabId: string, dir: Exclude<TabSplit, null>) => void
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

type TabSlice = Pick<AppState, 'tabs' | 'activeTabId' | 'tabSession' | 'tabCwd' | 'tabSplit'>

// Removes a set of tabs and picks the next active one: the nearest surviving
// neighbour in the same workspace, searching right first — the behaviour every
// tabbed editor has. Per-tab session/cwd/split entries are dropped with them.
function dropTabs(s: TabSlice, doomed: Set<string>): TabSlice {
  const tabs = s.tabs.filter((t) => !doomed.has(t.id))
  const tabSession = { ...s.tabSession }
  const tabCwd = { ...s.tabCwd }
  const tabSplit = { ...s.tabSplit }
  for (const id of doomed) {
    delete tabSession[id]
    delete tabCwd[id]
    delete tabSplit[id]
  }
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
  return { tabs, activeTabId, tabSession, tabCwd, tabSplit }
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

// Sessions for the same server are numbered "name", "name (2)", "name (3)".
function sessionTitle(tabs: Tab[], serverId: string | null, name: string): string {
  const count = tabs.filter((t) => t.serverId === serverId).length
  return count ? `${name} (${count + 1})` : name
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
  sidebarWidth: 280,
  sidebarCollapsed: false,

  tabs: [],
  activeTabId: null,
  tabSession: {},
  tabCwd: {},
  tabSplit: {},

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
  setSidebarWidth: (w) => set({ sidebarWidth: Math.max(200, Math.min(480, w)) }),
  toggleSidebar: () => set((s) => ({ sidebarCollapsed: !s.sidebarCollapsed })),

  // Focus an existing tab for this server (switching its view), or open one.
  // A server maps to a single tab whose view is switched in place, so the
  // terminal session survives Terminal <-> Monitor <-> Files navigation.
  openServer: (serverId, view = 'terminal') => {
    const server = get().servers.find((s) => s.id === serverId)
    if (!server) return
    const existing = get().tabs.find((t) => t.serverId === serverId)
    if (existing) {
      set((s) => ({
        activeTabId: existing.id,
        tabs: s.tabs.map((t) => (t.id === existing.id ? { ...t, view } : t))
      }))
      return
    }
    const tab: Tab = {
      id: uid('tab'),
      workspaceId: server.workspaceId,
      serverId,
      title: server.name,
      view
    }
    set((s) => ({ tabs: [...s.tabs, tab], activeTabId: tab.id }))
  },

  // Always open an additional session tab for a server (multiple terminals).
  newSession: (serverId) => {
    const server = get().servers.find((s) => s.id === serverId)
    if (!server) return
    const tab: Tab = {
      id: uid('tab'),
      workspaceId: server.workspaceId,
      serverId,
      title: sessionTitle(get().tabs, serverId, server.name),
      view: 'terminal'
    }
    set((s) => ({ tabs: [...s.tabs, tab], activeTabId: tab.id }))
  },

  // Opens a second session on the same server, next to the original, keeping
  // its view and remote directory. The SSH session itself is not shared: the
  // new tab dials its own shell over the pooled connection.
  duplicateTab: (id) =>
    set((s) => {
      const src = s.tabs.find((t) => t.id === id)
      if (!src) return {}
      const server = s.servers.find((sv) => sv.id === src.serverId)
      const base = server?.name ?? src.title.replace(/ \(\d+\)$/, '')
      const tab: Tab = {
        id: uid('tab'),
        workspaceId: src.workspaceId,
        serverId: src.serverId,
        title: sessionTitle(s.tabs, src.serverId, base),
        view: src.view
      }
      const idx = s.tabs.findIndex((t) => t.id === id)
      const cwd = s.tabCwd[id]
      return {
        tabs: [...s.tabs.slice(0, idx + 1), tab, ...s.tabs.slice(idx + 1)],
        activeTabId: tab.id,
        tabCwd: cwd ? { ...s.tabCwd, [tab.id]: cwd } : s.tabCwd
      }
    }),

  openTab: (tab) => {
    const t: Tab = { ...tab, workspaceId: tab.workspaceId ?? get().activeWorkspaceId, id: uid('tab') }
    set((s) => ({ tabs: [...s.tabs, t], activeTabId: t.id }))
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

  setTabView: (id, view) =>
    set((s) => ({ tabs: s.tabs.map((t) => (t.id === id ? { ...t, view } : t)) })),

  setTabSession: (tabId, sessionId) =>
    set((s) => {
      const next = { ...s.tabSession }
      if (sessionId) next[tabId] = sessionId
      else delete next[tabId]
      return { tabSession: next }
    }),

  setTabCwd: (tabId, path) => set((s) => ({ tabCwd: { ...s.tabCwd, [tabId]: path } })),

  // Pressing the same direction again collapses back to a single pane, which
  // is what the split buttons in the tab bar have always done.
  toggleSplit: (tabId, dir) =>
    set((s) => ({
      tabSplit: { ...s.tabSplit, [tabId]: s.tabSplit[tabId] === dir ? null : dir }
    })),

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
      return {
        workspaces: remaining,
        folders: s.folders.filter((f) => f.workspaceId !== id),
        servers: detachVpn(s.servers.filter((v) => v.workspaceId !== id), doomedVpns),
        monitorGroups: s.monitorGroups.filter((g) => g.workspaceId !== id),
        databases: detachVpn(s.databases.filter((d) => d.workspaceId !== id), doomedVpns),
        vpns: s.vpns.filter((v) => v.workspaceId !== id),
        tunnels: s.tunnels.filter((t) => t.workspaceId !== id),
        tabs: s.tabs.filter((t) => !t.serverId || !doomedServers.has(t.serverId)),
        activeTabId: s.tabs.find((t) => t.id === s.activeTabId && t.serverId && doomedServers.has(t.serverId))
          ? null
          : s.activeTabId,
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

  deleteServer: (id) =>
    set((s) => ({
      servers: s.servers.filter((sv) => sv.id !== id),
      // Close any tabs pointing at the server that no longer exists.
      tabs: s.tabs.filter((t) => t.serverId !== id),
      activeTabId: s.tabs.find((t) => t.id === s.activeTabId)?.serverId === id ? null : s.activeTabId
    })),

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
