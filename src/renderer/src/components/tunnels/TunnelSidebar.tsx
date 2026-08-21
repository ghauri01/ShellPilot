import { Network } from 'lucide-react'
import { useWorkspaceTunnels } from '../../store/app'
import { clsx } from '../../lib/format'

export function TunnelSidebar(): React.JSX.Element {
  const tunnels = useWorkspaceTunnels()
  return (
    <div className="tree-section">
      <div className="tree-section-label">
        <Network size={11} /> Tunnels <span className="count">{tunnels.length}</span>
      </div>
      {tunnels.map((t) => (
        <div key={t.id} className="tree-row" title={`${t.listen} → ${t.target}`}>
          <span className={clsx('status-dot', t.status === 'active' ? 'online' : 'offline')} />
          <span className="label">{t.name}</span>
          <span className="spacer" />
          <span className="faint" style={{ fontSize: 10, textTransform: 'uppercase' }}>
            {t.kind}
          </span>
        </div>
      ))}
    </div>
  )
}
