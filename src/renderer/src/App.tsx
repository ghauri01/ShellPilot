import { useEffect } from 'react'
import { useApp } from './store/app'
import { clsx } from './lib/format'
import { initPersistence } from './store/persist'
import { useHotkeys } from './hooks/useHotkeys'
import { TitleBar } from './components/layout/TitleBar'
import { ActivityBar } from './components/layout/ActivityBar'
import { Sidebar } from './components/layout/Sidebar'
import { StatusBar } from './components/layout/StatusBar'
import { WorkspacePanel } from './components/panel/WorkspacePanel'
import { FleetMonitor } from './components/monitor/FleetMonitor'
import { TunnelManager } from './components/tunnels/TunnelManager'
import { VpnManager } from './components/vpn/VpnManager'
import { DatabaseWorkspace } from './components/databases/DatabaseView'
import { AddDatabaseModal } from './components/databases/AddDatabaseModal'
import { Settings } from './components/settings/Settings'
import { VaultView } from './components/vault/VaultView'
import { AiPanel } from './components/ai/AiPanel'
import { ApprovalWatcher } from './components/ai/ApprovalWatcher'
import { AgentServerWatcher } from './components/ai/AgentServerWatcher'
import { VaultUnlockModal } from './components/vault/VaultUnlockModal'
import { OnboardingTour } from './components/onboarding/OnboardingTour'
import { CliPairingBanner } from './components/ai/CliPairingBanner'
import { CommandPalette } from './components/palette/CommandPalette'
import { AddServerModal } from './components/connections/AddServerModal'
import { RouteEditor } from './components/connections/RouteEditor'
import { SshConfigImport } from './components/connections/SshConfigImport'
import { SshPrompt } from './components/connections/SshPrompt'
import { VpnPromptModal } from './components/vpn/VpnPromptModal'
import { WorkspaceManager } from './components/workspace/WorkspaceManager'
import { WorkspaceUnlock } from './components/workspace/WorkspaceUnlock'
import { Toasts } from './components/common/Toasts'

// The connections panel stays mounted whatever the active view is: unmounting
// it would tear down every live terminal, so switching to Databases and back
// would drop running processes. Other views are cheap and mount on demand.
function MainArea(): React.JSX.Element {
  const activity = useApp((s) => s.activity)
  const onConnections = activity === 'connections'

  return (
    <>
      <div className={clsx('main-host', !onConnections && 'hidden')} aria-hidden={!onConnections}>
        <WorkspacePanel />
      </div>
      {activity === 'monitor' && <FleetMonitor />}
      {activity === 'databases' && <DatabaseWorkspace />}
      {/* One view, three sections: SSH tunnels, VPN and frp reverse proxies.
          They are all "make a remote thing reachable from here", and splitting
          them across two activity icons would only make the user guess which
          one holds the thing they set up yesterday. */}
      {activity === 'tunnels' && (
        <div className="main">
          <TunnelManager />
          <VpnManager />
        </div>
      )}
      {activity === 'vault' && <VaultView />}
      {activity === 'ai' && <AiPanel />}
      {activity === 'settings' && <Settings />}
    </>
  )
}

export default function App(): React.JSX.Element {
  useHotkeys()
  const theme = useApp((s) => s.theme)
  const modal = useApp((s) => s.modal)
  const paletteOpen = useApp((s) => s.paletteOpen)

  useEffect(() => {
    void initPersistence()
  }, [])

  // Density is a root attribute so it can tighten every surface from CSS
  // rather than threading a prop through every component.
  const compact = useApp((s) => s.settings.compactDensity)
  useEffect(() => {
    document.documentElement.toggleAttribute('data-compact', compact)
  }, [compact])

  useEffect(() => {
    const apply = (mode: string): void => {
      const dark =
        mode === 'dark' ||
        (mode === 'system' && window.matchMedia('(prefers-color-scheme: dark)').matches)
      document.documentElement.setAttribute('data-theme', dark ? 'dark' : 'light')
    }
    apply(theme)
    window.shellpilot?.theme.set(theme as 'dark' | 'light' | 'system')
  }, [theme])

  return (
    <div className="app">
      <TitleBar />
      <div className="app-body">
        <ActivityBar />
        <Sidebar />
        <MainArea />
      </div>
      <StatusBar />

      {paletteOpen && <CommandPalette />}
      {modal === 'add-server' && <AddServerModal />}
      {modal === 'route-editor' && <RouteEditor />}
      {modal === 'workspaces' && <WorkspaceManager />}
      {modal === 'add-database' && <AddDatabaseModal />}
      {modal === 'import-ssh' && <SshConfigImport />}
      {/* Not a `modal` kind: the unlock prompt can appear over any view. */}
      <WorkspaceUnlock />
      {/* Can appear during any connection attempt, including SFTP and metrics. */}
      <SshPrompt />
      {/* Global, like SshPrompt: a VPN started from the Tunnels view can ask for
          an OTP long after the user has moved on to a terminal. */}
      <VpnPromptModal />
      {/* Surfaces an AI approval request no matter which tab is active. */}
      <ApprovalWatcher />
      <AgentServerWatcher />
      <VaultUnlockModal />
      <OnboardingTour />
      <CliPairingBanner />
      <Toasts />
    </div>
  )
}
