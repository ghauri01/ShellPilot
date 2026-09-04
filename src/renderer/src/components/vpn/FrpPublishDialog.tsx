import { useState } from 'react'
import { Globe } from 'lucide-react'
import { Modal } from '../common/Modal'
import { useApp } from '../../store/app'
import { toast } from '../../store/toast'
import { clsx } from '../../lib/format'
import { bridgeHas } from '../../lib/bridge'
import { withVaultUnlock } from '../../lib/withVaultUnlock'
import {
  buildPublishedProxy,
  describeExposure,
  publicUrl,
  publishLabel,
  toLabel,
  type FrpPublishTarget
} from '../../../../shared/frpTunnel'
import { isVpnRunning } from '../../../../shared/vpn'
import type { FrpSpec } from '../../../../shared/vpn'
import { headline } from './useVpnProfiles'

/**
 * The last thing between a typed port number and a port on the internet.
 *
 * Two facts have to be on screen before the button works, and they are the two
 * a one-click flow is most likely to get wrong:
 *
 *   WHICH PORT. The flow takes a number out of a box. 3000 and 3306 are one
 *   keystroke apart, and one of them is a database. So the local address is
 *   written out in full — not "this port", the actual `127.0.0.1:3306`.
 *
 *   WHERE IT APPEARS. Not "publicly", not "on the internet": the exact URL, and
 *   the frp server the traffic crosses to get here.
 *
 * The switch below sets `FrpProxy.acknowledgedExposure`, which is the gate the
 * engine already enforces — `start()` refuses a proxy without it. This dialog
 * satisfies that gate rather than routing around it: `buildPublishedProxy`
 * cannot tick it, and the tick that goes onto the proxy is the one the user
 * operated, with these sentences beside it.
 */

interface FrpPublishDialogProps {
  target: FrpPublishTarget
  /** The port the user typed. Already validated as a port by the caller. */
  localPort: number
  onClose: () => void
}

export function FrpPublishDialog({
  target,
  localPort,
  onClose
}: FrpPublishDialogProps): React.JSX.Element {
  const upsertVpnProfile = useApp((s) => s.upsertVpnProfile)
  const status = useApp((s) => s.vpnStatuses[target.profile.id])

  const taken = target.spec.proxies.map((p) => p.name)
  const [label, setLabel] = useState(() => publishLabel('', localPort, taken))
  const [acknowledged, setAcknowledged] = useState(false)
  const [busy, setBusy] = useState(false)

  const clean = toLabel(label)
  const collides = clean !== '' && taken.some((t) => t.toLowerCase() === clean)
  const nameOk = clean !== '' && !collides

  const exposure = describeExposure({
    host: target.host,
    label: clean || '…',
    localPort,
    serverAddr: target.spec.serverAddr,
    serverPort: target.spec.serverPort
  })

  const publish = async (): Promise<void> => {
    if (!acknowledged || !nameOk || busy) return
    setBusy(true)
    try {
      const proxy = { ...buildPublishedProxy(clean, localPort), acknowledgedExposure: true }
      const spec: FrpSpec = { ...target.spec, proxies: [...target.spec.proxies, proxy] }
      upsertVpnProfile({ ...target.profile, spec })

      const url = publicUrl(target.host, clean)
      const running = status ? isVpnRunning(status.state) : false
      const vpn = window.shellpilot?.vpn as Record<string, unknown> | undefined
      const method = running ? 'reload' : 'start'
      if (!bridgeHas(vpn, method)) {
        // Saved, not started. Saying so beats a success toast for something
        // that did not happen.
        toast(`Added to ${target.profile.name}. Press Start on it to publish.`, 'info')
        onClose()
        return
      }

      const result = await withVaultUnlock(`Publishing ${exposure.local}`, () =>
        running
          ? window.shellpilot!.vpn.reload(target.profile.id)
          : window.shellpilot!.vpn.start(target.profile.id)
      )
      if (result && result.ok === false) {
        // The proxy stays on the profile. It is valid and confirmed; what
        // failed is the engine, and the row's own Start button is now the
        // shortest way to try again.
        toast(headline(result.error ?? 'The frp client failed to start.'), 'error')
      } else {
        toast(`Published at ${url}`, 'ok')
      }
      onClose()
    } finally {
      setBusy(false)
    }
  }

  return (
    <Modal
      title="Publish a local port"
      subtitle={target.profile.name}
      onClose={onClose}
      footer={
        <>
          <span className="grow" />
          <button className="btn" onClick={onClose}>
            Cancel
          </button>
          <button
            className="btn primary"
            disabled={!acknowledged || !nameOk || busy}
            onClick={() => void publish()}
          >
            <Globe size={14} /> Publish
          </button>
        </>
      }
    >
      <div className="col" style={{ gap: 14 }}>
        <label className="field">
          <span className="field-label">Name</span>
          <input
            className="input"
            value={label}
            onChange={(e) => setLabel(e.target.value)}
            aria-label="Name"
          />
          {collides && (
            <span className="field-hint" style={{ color: 'var(--danger)' }}>
              “{clean}” is already published from this profile.
            </span>
          )}
          {!collides && clean === '' && (
            <span className="field-hint" style={{ color: 'var(--danger)' }}>
              Give it a name — it becomes the first label of the address.
            </span>
          )}
        </label>

        {/* Both ends, spelled out, before anything happens. */}
        <div className="hop-card" style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
          <span style={{ fontSize: 13 }}>{exposure.sentence}</span>
          <span className="muted" style={{ fontSize: 12 }}>
            {exposure.audience}
          </span>
          <span className="muted" style={{ fontSize: 12 }}>
            {exposure.route}
          </span>
        </div>

        {/* The engine's gate, asked here rather than deep in the proxy editor,
            because this is where the click that publishes actually is. */}
        <label className="row" style={{ gap: 8, alignItems: 'flex-start' }}>
          <span
            className={clsx('switch', acknowledged && 'on')}
            style={{ marginTop: 1 }}
            role="switch"
            tabIndex={0}
            aria-checked={acknowledged}
            aria-label={exposure.sentence}
            onClick={() => setAcknowledged(!acknowledged)}
            onKeyDown={(e) => {
              if (e.key === ' ' || e.key === 'Enter') {
                e.preventDefault()
                setAcknowledged(!acknowledged)
              }
            }}
          />
          <span style={{ fontSize: 12, color: acknowledged ? 'var(--text-muted)' : 'var(--warn)' }}>
            I want {exposure.local} reachable at {exposure.url}.
          </span>
        </label>
      </div>
    </Modal>
  )
}
