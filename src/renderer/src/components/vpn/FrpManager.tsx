import { Plus, Share2 } from 'lucide-react'
import { EmptyState } from '../common/EmptyState'
import { useApp, useWorkspaceVpns } from '../../store/app'
import type { VpnProfile } from '../../types'
import { useVpnProfiles } from './useVpnProfiles'

function blankFrpProfile(workspaceId: string): VpnProfile {
  return {
    id: `vpn-${crypto.randomUUID()}`,
    workspaceId,
    name: 'New frp client',
    autoStart: false,
    // No proxies: a fresh client connects and exposes nothing, which is the
    // only safe thing an empty form can mean here.
    spec: {
      kind: 'frp',
      serverAddr: '',
      serverPort: 7000,
      auth: { method: 'token' },
      transport: { protocol: 'tcp', tlsEnable: true },
      proxies: [],
      visitors: []
    }
  }
}

/** frp reverse proxies. Same engine plumbing as `VpnManager` — see
 *  `useVpnProfiles` — but the reverse direction: a VPN brings you onto a remote
 *  network, an frp client publishes something here onto a remote one. */
export function FrpManager(): React.JSX.Element {
  const profiles = useWorkspaceVpns().filter((p) => p.spec.kind === 'frp')
  const { row, dialogs, importProfile, editProfile } = useVpnProfiles()

  const newClient = (): void => editProfile(blankFrpProfile(useApp.getState().activeId()))

  return (
    <div className="content">
      <div className="content-header">
        <div>
          <h1>Reverse proxies (frp)</h1>
          <div className="sub">Publish a local service through an frp server</div>
        </div>
        <div className="spacer" />
        <button className="btn sm" onClick={() => importProfile('frp')}>
          <Plus size={14} /> Import frpc config
        </button>
        <button className="btn sm" onClick={newClient}>
          <Share2 size={14} /> New frp client
        </button>
      </div>

      {profiles.length === 0 ? (
        <EmptyState
          icon={<Share2 size={26} />}
          title="No reverse proxies"
          message="An frp client makes a service on this machine reachable through a server you control."
          action={
            <button className="btn primary" onClick={newClient}>
              <Share2 size={15} /> New frp client
            </button>
          }
        />
      ) : (
        <div className="col" style={{ gap: 8, paddingBottom: 16 }}>
          {profiles.map(row)}
        </div>
      )}

      {dialogs}
    </div>
  )
}
