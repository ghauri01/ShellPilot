import { useState } from 'react'
import { Copy, Globe, Plus, Share2 } from 'lucide-react'
import { EmptyState } from '../common/EmptyState'
import { useApp, useWorkspaceVpns } from '../../store/app'
import { toast } from '../../store/toast'
import type { VpnProfile } from '../../types'
import { frpPublishReadiness, publicUrl, type FrpSetupGap } from '../../../../shared/frpTunnel'
import { useVpnProfiles } from './useVpnProfiles'
import { FrpPublishDialog } from './FrpPublishDialog'
import { FrpTunnelSetup } from './FrpTunnelSetup'

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

  // The one-click flow. `port` is a string rather than a number so an empty box
  // is empty rather than 0, and so "3000abc" is rejected instead of silently
  // becoming 3000.
  const [port, setPort] = useState('')
  const [gaps, setGaps] = useState<FrpSetupGap[] | null>(null)
  const [publishing, setPublishing] = useState<{ port: number } | null>(null)
  const [settingUp, setSettingUp] = useState(false)

  const readiness = frpPublishReadiness(profiles)
  const wanted = /^\d+$/.test(port.trim()) ? Number(port.trim()) : 0
  const portOk = wanted > 0 && wanted < 65536

  const newClient = (): void => editProfile(blankFrpProfile(useApp.getState().activeId()))

  /**
   * The click.
   *
   * It produces a URL or it produces an explanation, and there is no third
   * outcome — `frpPublishReadiness` has no state that yields half of one. The
   * explanation is deliberately not the setup dialog opening by itself: being
   * dropped into a five-field form is a worse answer to "why did nothing
   * happen" than a sentence saying what is missing, with the form one click
   * further on.
   */
  const publish = (): void => {
    if (!portOk) {
      toast('Enter the port your service is listening on.', 'error')
      return
    }
    if (!readiness.ready) {
      setGaps(readiness.gaps)
      return
    }
    setGaps(null)
    setPublishing({ port: wanted })
  }

  // Everything already published through the tunnel host, with the address it
  // is at. The point of the feature is the URL, so it has to be gettable again
  // afterwards without opening the proxy editor and reassembling it by hand.
  const published =
    readiness.ready && readiness.target.spec.proxies.length > 0
      ? readiness.target.spec.proxies
          .filter((p) => p.subdomain)
          .map((p) => ({
            name: p.name,
            local: `${p.localIp}:${p.localPort}`,
            url: publicUrl(readiness.target.host, p.subdomain as string)
          }))
      : []

  const copy = (url: string): void => {
    window.shellpilot?.clipboard.write(url)
    toast('Address copied', 'ok')
  }

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

      <div className="hop-card" style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
        <div className="row" style={{ gap: 8, alignItems: 'center' }}>
          <span style={{ fontSize: 13 }}>Publish localhost:</span>
          <input
            className="input"
            style={{ width: 92 }}
            placeholder="3000"
            aria-label="Local port"
            value={port}
            onChange={(e) => setPort(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === 'Enter') publish()
            }}
          />
          <button className="btn primary sm" onClick={publish}>
            <Globe size={14} /> Get a public URL
          </button>
          <span className="grow" />
        </div>

        {/* What is missing, rather than a URL that would not have worked. */}
        {gaps && (
          <div className="col" style={{ gap: 6 }}>
            {gaps.map((g) => (
              <span key={g.code} style={{ fontSize: 12, color: 'var(--warn)' }}>
                {g.message}
              </span>
            ))}
            <div className="row">
              <button className="btn sm" onClick={() => setSettingUp(true)}>
                Set up a tunnel host
              </button>
            </div>
          </div>
        )}

        {published.length > 0 && (
          <div className="col" style={{ gap: 4 }}>
            {published.map((p) => (
              <div key={p.name} className="row" style={{ gap: 8, alignItems: 'center' }}>
                <span style={{ fontSize: 12 }}>{p.url}</span>
                <span className="muted" style={{ fontSize: 12 }}>
                  → {p.local}
                </span>
                <span className="grow" />
                <button
                  className="icon-btn sm"
                  title={`Copy ${p.url}`}
                  aria-label={`Copy ${p.url}`}
                  onClick={() => copy(p.url)}
                >
                  <Copy size={13} />
                </button>
              </div>
            ))}
          </div>
        )}
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

      {settingUp && (
        <FrpTunnelSetup
          workspaceId={useApp.getState().activeId()}
          // Promote the profile the user already has rather than adding a
          // second one beside it: two frp clients dialling the same server is
          // a confusing thing to end a setup with.
          existing={profiles.length === 1 ? profiles[0] : null}
          onClose={() => setSettingUp(false)}
          onDone={() => {
            setSettingUp(false)
            setGaps(null)
            // Carry straight on into the publish the user originally asked
            // for. The setup was an interruption, not the task.
            if (portOk) setPublishing({ port: wanted })
          }}
        />
      )}

      {publishing && readiness.ready && (
        <FrpPublishDialog
          target={readiness.target}
          localPort={publishing.port}
          onClose={() => setPublishing(null)}
        />
      )}

      {dialogs}
    </div>
  )
}
