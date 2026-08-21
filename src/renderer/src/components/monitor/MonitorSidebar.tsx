import { Activity } from 'lucide-react'
import { useApp, useWorkspaceServers } from '../../store/app'
import { clsx } from '../../lib/format'

export function MonitorSidebar(): React.JSX.Element {
  const servers = useWorkspaceServers()
  const openServer = useApp((s) => s.openServer)
  return (
    <div className="tree-section">
      <div className="tree-section-label">
        <Activity size={11} /> Servers <span className="count">{servers.length}</span>
      </div>
      {servers.map((s) => (
        <div key={s.id} className="tree-row" onClick={() => openServer(s.id, 'monitor')}>
          <span className={clsx('status-dot', s.status)} />
          <span className="label">{s.name}</span>
        </div>
      ))}
    </div>
  )
}
