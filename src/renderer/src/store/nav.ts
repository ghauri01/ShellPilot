import { create } from 'zustand'
import { useApp } from './app'

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

interface NavState {
  aiSection: AiSection
  /** An access group the Access Groups page should open on, set by whoever
   *  sent the user there. Cleared as soon as it has been honoured, so coming
   *  back later does not silently re-select a group the user has moved on from. */
  aiGroupId: string | null
  settingsSection: SettingsSection
  setAiSection: (s: AiSection) => void
  setSettingsSection: (s: SettingsSection) => void
  clearAiGroup: () => void
}

export const useNav = create<NavState>((set) => ({
  aiSection: 'overview',
  aiGroupId: null,
  settingsSection: 'appearance',
  setAiSection: (s) => set({ aiSection: s, aiGroupId: null }),
  setSettingsSection: (s) => set({ settingsSection: s }),
  clearAiGroup: () => set({ aiGroupId: null })
}))

/** Open a page of AI & MCP, optionally on a particular access group. */
export function openAi(section: AiSection, groupId?: string | null): void {
  useNav.setState({ aiSection: section, aiGroupId: groupId ?? null })
  useApp.getState().setActivity('ai')
}

/** Open a page of Settings. */
export function openSettings(section: SettingsSection): void {
  useNav.setState({ settingsSection: section })
  useApp.getState().setActivity('settings')
}
