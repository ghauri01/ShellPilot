import { create } from 'zustand'
import { useApp } from './app'
import type { ModuleId } from '../../../shared/modules'

// Which page of AI & MCP, and which page of Settings, is open. Both used to be
// local `useState` inside their panel, which meant nothing outside the panel
// could point at anything inside it — so a message about an access group, the
// bridge or an update could only *name* the place and leave the user to find
// it. Holding the section here is what lets a button do the walking.

export type AiSection = 'overview' | 'agents' | 'groups' | 'sessions' | 'approvals' | 'audit' | 'security'

export type SettingsSection =
  | 'general'
  | 'appearance'
  | 'terminal'
  | 'connections'
  | 'ssh'
  | 'security'
  | 'sftp'
  | 'monitoring'
  | 'modules'
  | 'editor'
  | 'shortcuts'
  | 'backup'
  | 'notifications'
  | 'advanced'

/** Which panel of the Fleet Monitor is showing. `overview` and `alerts` are
 *  fixed; the rest are whichever optional modules are enabled. */
export type MonitorTab = 'overview' | 'alerts' | ModuleId

interface NavState {
  aiSection: AiSection
  /** An access group the Access Groups page should open on, set by whoever
   *  sent the user there. Cleared as soon as it has been honoured, so coming
   *  back later does not silently re-select a group the user has moved on from. */
  aiGroupId: string | null
  settingsSection: SettingsSection
  /**
   * Held here rather than in FleetMonitor's own useState, for exactly the
   * reason at the top of this file: the status-bar alert chip is a pointer at
   * the inbox, and a pointer that can only open the page and not the tab is a
   * chip that says "it is in here somewhere". The panels still stay mounted —
   * this moves which one is visible, not whether it exists.
   */
  monitorTab: MonitorTab
  setAiSection: (s: AiSection) => void
  setSettingsSection: (s: SettingsSection) => void
  setMonitorTab: (t: MonitorTab) => void
  clearAiGroup: () => void
}

export const useNav = create<NavState>((set) => ({
  aiSection: 'overview',
  aiGroupId: null,
  settingsSection: 'appearance',
  monitorTab: 'overview',
  setAiSection: (s) => set({ aiSection: s, aiGroupId: null }),
  setSettingsSection: (s) => set({ settingsSection: s }),
  setMonitorTab: (t) => set({ monitorTab: t }),
  clearAiGroup: () => set({ aiGroupId: null })
}))

/** Open a page of AI & MCP, optionally on a particular access group. */
export function openAi(section: AiSection, groupId?: string | null): void {
  useNav.setState({ aiSection: section, aiGroupId: groupId ?? null })
  useApp.getState().setActivity('ai')
}

/** Open the Fleet Monitor on a particular panel. */
export function openMonitor(tab: MonitorTab): void {
  useNav.setState({ monitorTab: tab })
  useApp.getState().setActivity('monitor')
}

/** Open a page of Settings. */
export function openSettings(section: SettingsSection): void {
  useNav.setState({ settingsSection: section })
  useApp.getState().setActivity('settings')
}
