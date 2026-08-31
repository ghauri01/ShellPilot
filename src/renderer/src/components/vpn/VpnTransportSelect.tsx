import { useEffect } from 'react'
import { AlertTriangle } from 'lucide-react'
import { useApp, useWorkspaceVpns } from '../../store/app'
import { bridgeHas } from '../../lib/bridge'
import type { UUID, VpnKind } from '../../types'
import { HealthChip, vpnHealth } from './VpnStatusCard'

// Which VPN profile a saved connection is dialled through. `null` is a direct
// connection and is what everything defaults to.
//
// Shared by the server form and the database form because the decision is the
// same one in both places, and because the two failure modes worth getting
// right — a profile that is stopped, and a profile that has been deleted — are
// easy to get right once and tedious to get right twice.

const KIND_LABEL: Record<VpnKind, string> = {
  wireguard: 'WireGuard',
  openvpn: 'OpenVPN',
  frp: 'frp'
}

interface VpnTransportSelectProps {
  /** The saved profile id, or null for a direct connection. */
  value: UUID | null
  onChange: (value: UUID | null) => void
  /** One line under the field saying how this composes with whatever else the
   *  form already routes through. The ordering is not guessable, so each form
   *  spells out its own. */
  hint: React.ReactNode
}

export function VpnTransportSelect({
  value,
  onChange,
  hint
}: VpnTransportSelectProps): React.JSX.Element {
  const profiles = useWorkspaceVpns()
  const vpnStatuses = useApp((s) => s.vpnStatuses)
  const setVpnStatus = useApp((s) => s.setVpnStatus)

  // frp is an inbound-exposure tool: it publishes a local port on a remote
  // server. Nothing dials *out* through it, so listing it here — even greyed —
  // would suggest a thing it cannot do.
  const usable = profiles.filter((p) => p.spec.kind !== 'frp')

  // The status map is only filled while the VPN pane is mounted, and this form
  // can be opened without ever going there. Without this reconcile the chip
  // would confidently say "Stopped" about a tunnel that is up.
  useEffect(() => {
    if (!bridgeHas(window.shellpilot?.vpn as Record<string, unknown> | undefined, 'list')) return
    void window.shellpilot?.vpn.list().then((list) => {
      list?.forEach((st) => setVpnStatus(st.id, st))
    })
  }, [setVpnStatus])

  const selected = value ? usable.find((p) => p.id === value) : undefined
  // A saved reference to a profile that is no longer here. Main resolves this
  // to "connect directly" rather than failing, so it is a stale pointer to tidy
  // up — not a broken connection, and the wording must not imply otherwise.
  const missing = !!value && !selected
  const health = vpnHealth(selected ? vpnStatuses[selected.id] : undefined)

  return (
    <div className="field">
      <label className="field-label">Reach through (optional)</label>
      <div className="row" style={{ gap: 8 }}>
        <select
          className="input grow"
          value={value ?? ''}
          onChange={(e) => onChange(e.target.value || null)}
        >
          <option value="">Direct — no VPN</option>
          {usable.map((p) => (
            <option key={p.id} value={p.id}>
              via {p.name} ({KIND_LABEL[p.spec.kind]})
            </option>
          ))}
          {/* Kept selectable so the field shows what is actually stored. Picking
              "Direct" is how it is cleared. */}
          {missing && <option value={value ?? ''}>(missing profile)</option>}
        </select>
        {selected && <HealthChip health={health} />}
      </div>

      {missing ? (
        <div className="row" style={{ gap: 6, color: 'var(--warn)', fontSize: 11, marginTop: 6 }}>
          <AlertTriangle size={12} />
          <span>
            The VPN profile this was saved against no longer exists, so this connection is being
            made directly. Choose one above, or leave it — picking <em>Direct</em> clears the
            reference.
          </span>
        </div>
      ) : selected && health === 'off' ? (
        // Not a warning: connecting starts the profile. Saying so beats leaving
        // the user to wonder whether they have to go and press Start first.
        <span className="field-hint">
          {selected.name} is stopped. Connecting through it starts it first and waits for the
          tunnel, so the failure you see is the VPN&apos;s, not a connect timeout.
        </span>
      ) : null}

      {usable.length === 0 && !missing ? (
        <span className="field-hint">
          No WireGuard or OpenVPN profiles in this workspace yet — import one in the Tunnels view.
          (frp is an inbound reverse proxy, so it is never a transport.)
        </span>
      ) : (
        <span className="field-hint">{hint}</span>
      )}
    </div>
  )
}
