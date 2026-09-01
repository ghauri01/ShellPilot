import { Globe, Network, Share2 } from 'lucide-react'
import { useApp, useWorkspaceTunnels, useWorkspaceVpns } from '../../store/app'
import type { TunnelsTab } from '../../store/app'
import { clsx } from '../../lib/format'
import { TunnelManager } from './TunnelManager'
import { VpnManager } from '../vpn/VpnManager'
import { FrpManager } from '../vpn/FrpManager'

/**
 * SSH tunnels, VPN and frp reverse proxies, behind one activity icon.
 *
 * They are all "make a remote thing reachable from here", and splitting them
 * across two activity icons would only make the user guess which one holds the
 * thing they set up yesterday — so this stays one destination. What changed is
 * how the three are reached inside it: they used to be sections of a single
 * unbounded scrolling column, which put VPN at the fold and frp entirely below
 * it, so a user with no tunnels saw one empty state and no sign the other two
 * existed. A segment names all three and their counts at the top of the view,
 * and the same `.viewbar`/`.segment` the terminal's Terminal/Monitor/Files
 * switcher uses — one idiom in the app for "what is this panel showing".
 */
export function TunnelsView(): React.JSX.Element {
  const tab = useApp((s) => s.tunnelsTab)
  const setTab = useApp((s) => s.setTunnelsTab)
  const tunnels = useWorkspaceTunnels()
  const vpns = useWorkspaceVpns()

  const tabs: { id: TunnelsTab; label: string; icon: React.ReactNode; count: number }[] = [
    { id: 'tunnels', label: 'Tunnels', icon: <Network size={14} />, count: tunnels.length },
    {
      id: 'vpn',
      label: 'VPN',
      icon: <Globe size={14} />,
      count: vpns.filter((p) => p.spec.kind !== 'frp').length
    },
    {
      id: 'frp',
      label: 'Reverse proxies',
      icon: <Share2 size={14} />,
      count: vpns.filter((p) => p.spec.kind === 'frp').length
    }
  ]

  return (
    <div className="main">
      <div className="viewbar">
        <div className="segment">
          {tabs.map((t) => (
            <button
              key={t.id}
              className={clsx('seg-btn', tab === t.id && 'active')}
              onClick={() => setTab(t.id)}
            >
              {t.icon} {t.label} <span className="count">{t.count}</span>
            </button>
          ))}
        </div>
      </div>

      {tab === 'tunnels' && <TunnelManager />}
      {tab === 'vpn' && <VpnManager />}
      {tab === 'frp' && <FrpManager />}
    </div>
  )
}
