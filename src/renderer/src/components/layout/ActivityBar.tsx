import { Server, Database, Network, Activity, KeyRound, Bot, Settings, PanelLeft } from 'lucide-react'
import { useApp } from '../../store/app'
import { clsx } from '../../lib/format'
import type { ActivityView } from '../../types'

const items: { id: ActivityView; icon: React.ReactNode; label: string }[] = [
  { id: 'connections', icon: <Server size={20} />, label: 'Connections' },
  { id: 'databases', icon: <Database size={20} />, label: 'Databases' },
  { id: 'tunnels', icon: <Network size={20} />, label: 'Tunnels & VPN' },
  { id: 'monitor', icon: <Activity size={20} />, label: 'Monitoring' },
  { id: 'vault', icon: <KeyRound size={20} />, label: 'Vault' },
  { id: 'ai', icon: <Bot size={20} />, label: 'AI & MCP' }
]

export function ActivityBar(): React.JSX.Element {
  const activity = useApp((s) => s.activity)
  const setActivity = useApp((s) => s.setActivity)
  const toggleSidebar = useApp((s) => s.toggleSidebar)
  const backupDirty = useApp((s) => s.settings.backupDirty)

  return (
    <div className="activitybar">
      <button className="activity-btn" title="Toggle sidebar" onClick={toggleSidebar}>
        <PanelLeft size={20} />
      </button>
      <div style={{ height: 8 }} />
      {items.map((it) => (
        <button
          key={it.id}
          className={clsx('activity-btn', activity === it.id && 'active')}
          title={it.label}
          onClick={() => setActivity(it.id)}
        >
          {it.icon}
        </button>
      ))}
      <div className="activity-spacer" />
      <button
        className={clsx('activity-btn', activity === 'settings' && 'active')}
        title={backupDirty ? 'Settings — backup out of date' : 'Settings'}
        onClick={() => setActivity('settings')}
      >
        <Settings size={20} />
        {backupDirty && <span className="activity-badge" />}
      </button>
    </div>
  )
}
