import { GitBranch, Wifi, Bell, Cpu, AlertTriangle } from 'lucide-react'
import { useApp } from '../../store/app'
import { useAlerts } from '../../store/alerts'
import { colorVar } from './WorkspaceSwitcher'
import { UpdateIndicator } from './UpdateIndicator'

export function StatusBar(): React.JSX.Element {
  const ws = useApp((s) => s.activeWorkspace())
  const tabs = useApp((s) => s.tabs)
  const backupDirty = useApp((s) => s.settings.backupDirty)
  const alerts = useAlerts((s) => s.active)
  const setActivity = useApp((s) => s.setActivity)

  return (
    <div className="statusbar">
      <div className="item">
        <span className="ws-dot" style={{ background: colorVar[ws.color], color: colorVar[ws.color] }} />
        <span>{ws.name}</span>
      </div>
      <div className="item">
        <GitBranch size={12} />
        <span>
          {tabs.length} session{tabs.length === 1 ? '' : 's'}
        </span>
      </div>
      <div className="spacer" />
      {/* Rendered in the status bar rather than as a floating overlay, so an
          alert can never cover terminal output. */}
      {Object.values(alerts).length > 0 && (
        <div
          className="item resource-alert"
          title={Object.values(alerts)
            .map((a) => `${a.serverName}: ${a.kind === 'cpu' ? 'CPU' : 'Memory'} ${a.value.toFixed(0)}%`)
            .join('\n')}
        >
          <AlertTriangle size={12} />
          <span>
            {Object.values(alerts).length} alert{Object.values(alerts).length === 1 ? '' : 's'}
          </span>
        </div>
      )}
      {backupDirty && (
        <button
          className="item backup-warn"
          title="Stored connections have changed since the last export. Click to open Backup & Restore."
          onClick={() => setActivity('settings')}
        >
          <AlertTriangle size={12} />
          <span>Backup out of date</span>
        </button>
      )}
      <UpdateIndicator />
      <div className="item metric">
        <Cpu size={12} />
        <span>
          local <b>ok</b>
        </span>
      </div>
      <div className="item">
        <Wifi size={12} />
        <span>Online</span>
      </div>
      <div className="item">
        <Bell size={12} />
      </div>
    </div>
  )
}
