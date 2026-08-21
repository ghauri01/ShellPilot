import { useApp } from './app'

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

export async function initPersistence(): Promise<void> {
  const bridge = window.shellpilot
  if (!bridge?.data) return

  const saved = await bridge.data.load<Persisted>()
  if (saved && saved.version === SEED_VERSION && Array.isArray(saved.servers)) {
    useApp.getState().replaceAll(saved as never)
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

  // Main owns the connection pool, so mirror the retention policy into it.
  void window.shellpilot?.ssh.setPoolIdle(useApp.getState().settings.sshMasterIdleMinutes)

  useApp.subscribe((state, prev) => {
    if (state.settings.sshMasterIdleMinutes !== prev.settings.sshMasterIdleMinutes) {
      void window.shellpilot?.ssh.setPoolIdle(state.settings.sshMasterIdleMinutes)
    }
    const dataChanged =
      state.workspaces !== prev.workspaces ||
      state.folders !== prev.folders ||
      state.monitorGroups !== prev.monitorGroups ||
      state.servers !== prev.servers ||
      state.vpns !== prev.vpns ||
      state.tunnels !== prev.tunnels ||
      state.databases !== prev.databases

    // Any change to stored data invalidates the last backup. Guarded on the
    // current flag so this cannot loop: writing settings re-enters with
    // dataChanged false.
    if (dataChanged && !state.settings.backupDirty) {
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
