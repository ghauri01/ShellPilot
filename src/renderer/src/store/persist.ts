import { useApp } from './app'
import { backfillModules, type ModuleState } from '../../../shared/modules'
import type { Server, MonitorGroup } from '../types'

// Bump when the seed/shape changes in a way that should discard older on-disk
// data (e.g. removing the original sample/dummy dataset).
const SEED_VERSION = 2

interface Persisted {
  version?: number
  workspaces: unknown
  monitorGroups?: unknown
  // Absent in saves written before this was stored; the store falls back to
  // the first workspace when it is missing or names a deleted workspace.
  activeWorkspaceId?: unknown
  folders: unknown
  servers: unknown
  vpns: unknown
  tunnels: unknown
  databases: unknown
  settings: unknown
}

let timer: ReturnType<typeof setTimeout> | null = null

// Connecting to a server flips Server.status (online/offline/connecting)
// dozens of times a session, and collapsing a Fleet Monitor group flips
// MonitorGroup.collapsed — both change the array's reference, but neither is
// something a backup needs to capture. Comparing without them is what keeps
// "Backup out of date" meaning what it says: your servers, workspaces, vault
// or connections changed, not that you opened a terminal or collapsed a
// panel.
function serversWithoutStatus(servers: Server[]): Omit<Server, 'status'>[] {
  return servers.map(({ status: _status, ...rest }) => rest)
}
function monitorGroupsWithoutCollapsed(groups: MonitorGroup[]): Omit<MonitorGroup, 'collapsed'>[] {
  return groups.map(({ collapsed: _collapsed, ...rest }) => rest)
}

export async function initPersistence(): Promise<void> {
  const bridge = window.shellpilot
  if (!bridge?.data) return

  const saved = await bridge.data.load<Persisted>()
  if (saved && saved.version === SEED_VERSION && Array.isArray(saved.servers)) {
    // Read what was actually SAVED, before replaceAll runs. replaceAll merges
    // `{ ...DEFAULT_SETTINGS, ...data.settings }`, and DEFAULT_SETTINGS carries
    // defaultModuleState() — so after it, every module key is present and
    // backfillModules, which only fills ABSENT keys, has nothing left to do.
    // The saved object is the only thing that still knows this install predates
    // the module.
    //
    // Getting this wrong switched three modules on for every existing install
    // on upgrade, which is the exact thing backfillModules was written to
    // prevent. The unit test passed throughout because it exercised the
    // function with a partial object rather than the real call site.
    const savedModules = (saved as { settings?: { modules?: ModuleState } }).settings?.modules
    useApp.getState().replaceAll(saved as never)
    // An upgrade is not consent: the user has already decided what their app
    // looks like. A fresh install gets the defaults instead, from
    // defaultModuleState() in DEFAULT_SETTINGS.
    useApp.getState().setSettings({ modules: backfillModules(savedModules, false) })
  } else {
    // No data, or data written by an older (dummy-seeded) version — start clean
    // and overwrite it with the current empty seed.
    void save()
  }

  // The main-process lock file decides which workspaces are password
  // protected, so reconcile the freshly-loaded flags against it.
  const lockedIds = await window.shellpilot?.workspaceLock.ids()
  if (lockedIds) {
    useApp.getState().syncWorkspaceLocks(lockedIds)
    // activeWorkspaceId is not restored through setWorkspace, so a protected
    // workspace would otherwise open unchallenged on launch.
    const st = useApp.getState()
    if (!st.isWorkspaceAccessible(st.activeWorkspaceId)) st.lockWorkspace(st.activeWorkspaceId)
  }

  // Main owns the vault's idle timer, same as the connection pool below.
  void window.shellpilot?.vault?.setAutoLock?.(useApp.getState().settings.vaultAutoLockMinutes)

  // Main owns the connection pool, so mirror the retention policy into it.
  void window.shellpilot?.ssh.setPoolIdle(useApp.getState().settings.sshMasterIdleMinutes)

  useApp.subscribe((state, prev) => {
    if (state.settings.sshMasterIdleMinutes !== prev.settings.sshMasterIdleMinutes) {
      void window.shellpilot?.ssh.setPoolIdle(state.settings.sshMasterIdleMinutes)
    }
    if (state.settings.vaultAutoLockMinutes !== prev.settings.vaultAutoLockMinutes) {
      void window.shellpilot?.vault?.setAutoLock?.(state.settings.vaultAutoLockMinutes)
    }
    const serversRefChanged = state.servers !== prev.servers
    const monitorGroupsRefChanged = state.monitorGroups !== prev.monitorGroups

    // Reference changes drive the save-to-disk timer below — status and
    // collapsed are still worth persisting across restarts, just not worth
    // telling the user their backup is stale over.
    const dataChanged =
      state.workspaces !== prev.workspaces ||
      state.folders !== prev.folders ||
      monitorGroupsRefChanged ||
      serversRefChanged ||
      state.vpns !== prev.vpns ||
      state.tunnels !== prev.tunnels ||
      state.databases !== prev.databases

    const serversContentChanged =
      serversRefChanged &&
      JSON.stringify(serversWithoutStatus(state.servers)) !== JSON.stringify(serversWithoutStatus(prev.servers))
    const monitorGroupsContentChanged =
      monitorGroupsRefChanged &&
      JSON.stringify(monitorGroupsWithoutCollapsed(state.monitorGroups)) !==
        JSON.stringify(monitorGroupsWithoutCollapsed(prev.monitorGroups))

    const backupRelevantChanged =
      state.workspaces !== prev.workspaces ||
      state.folders !== prev.folders ||
      monitorGroupsContentChanged ||
      serversContentChanged ||
      state.vpns !== prev.vpns ||
      state.tunnels !== prev.tunnels ||
      state.databases !== prev.databases

    // Any change to stored data invalidates the last backup. Guarded on the
    // current flag so this cannot loop: writing settings re-enters with
    // backupRelevantChanged false.
    if (backupRelevantChanged && !state.settings.backupDirty) {
      useApp.getState().setSettings({ backupDirty: true })
    }

    // Which workspace is open is remembered across restarts, but it is not a
    // change to the stored data, so it neither marks the backup stale nor is
    // checked above.
    const activeChanged = state.activeWorkspaceId !== prev.activeWorkspaceId

    if (dataChanged || activeChanged || state.settings !== prev.settings) {
      if (timer) clearTimeout(timer)
      timer = setTimeout(save, 400)
    }
  })
}

function save(): Promise<void> {
  const s = useApp.getState()
  return (
    window.shellpilot?.data.save({
      version: SEED_VERSION,
      workspaces: s.workspaces,
      activeWorkspaceId: s.activeWorkspaceId,
      monitorGroups: s.monitorGroups,
      folders: s.folders,
      servers: s.servers,
      vpns: s.vpns,
      tunnels: s.tunnels,
      databases: s.databases,
      settings: s.settings
    }) ?? Promise.resolve()
  )
}
