import { GitBranch, Wifi, Bell, Cpu, AlertTriangle } from 'lucide-react'
import { useApp } from '../../store/app'
import { LABEL, chipValue, useAlerts } from '../../store/alerts'
import { useFleetStatus, samplerWarning } from '../../store/fleetStatus'
import { openSettings } from '../../store/nav'
import { colorVar } from './WorkspaceSwitcher'
import { UpdateIndicator } from './UpdateIndicator'

export function StatusBar(): React.JSX.Element {
  const ws = useApp((s) => s.activeWorkspace())
  const tabs = useApp((s) => s.tabs)
  const backupDirty = useApp((s) => s.settings.backupDirty)
  const alerts = useAlerts((s) => s.active)
  const setActivity = useApp((s) => s.setActivity)
  // Whether the thing that raises those alerts is actually running. An alert
  // count of zero means nothing if nobody is checking.
  const samplerStatus = useFleetStatus((s) => s.status)
  const samplingEnabled = useApp((s) => s.settings.fleetSamplingEnabled)
  const warning = samplerWarning(samplerStatus, samplingEnabled)

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
        // A button, not a div. It sits beside the backup warning, which is the
        // same shape and does navigate — one of the two being inert made the
        // bar teach that a chip here may or may not be worth clicking. The
        // tooltip names the hosts; the click takes you to where they are.
        <button
          className="item resource-alert"
          title={`${Object.values(alerts)
            // The store's own labels and the store's own units, not a ternary
            // and not a hard-coded percent sign here. A third kind made that
            // ternary label every disk alert "Memory", and a hard-coded `%`
            // showed a load average of 3.2 per core as "3%" — a wrong number
            // rather than an ugly one.
            .map((a) => `${a.serverName}: ${LABEL[a.kind]}${chipValue(a)}${a.detail ? ` — ${a.detail}` : ''}`)
            .join('\n')}\n\nClick to open the Fleet Monitor.`}
          onClick={() => setActivity('monitor')}
        >
          <AlertTriangle size={12} />
          <span>
            {Object.values(alerts).length} alert{Object.values(alerts).length === 1 ? '' : 's'}
          </span>
        </button>
      )}
      {/* Sits before the backup warning because it is worse: a stale export
          costs you a restore, background checking being silently stopped costs
          you the incident. Deliberately shown even when the alert count is
          zero — that zero is precisely what is not trustworthy while this is
          up. */}
      {warning && (
        <button className="item resource-alert" title={warning.detail} onClick={() => openSettings('monitoring')}>
          <AlertTriangle size={12} />
          <span>{warning.label}</span>
        </button>
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
