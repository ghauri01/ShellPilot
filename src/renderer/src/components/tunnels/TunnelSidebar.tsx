import { Network } from 'lucide-react'
import { useApp, useWorkspaceTunnels } from '../../store/app'
import { clsx } from '../../lib/format'

export function TunnelSidebar(): React.JSX.Element {
  const tunnels = useWorkspaceTunnels()
  // The tabs in the main pane are the navigation; this only marks which of the
  // three sections is the one on screen, so the sidebar is not silently
  // describing a list the user cannot currently see.
  const current = useApp((s) => s.tunnelsTab) === 'tunnels'
  return (
    <div className="tree-section">
      <div className={clsx('tree-section-label', current && 'active')}>
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
