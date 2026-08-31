import { useState } from 'react'
import { AlertTriangle, Monitor, Server as ServerIcon, CheckCircle2, PlayCircle } from 'lucide-react'
import { Modal } from '../common/Modal'
import { useApp } from '../../store/app'
import { RouteHops } from './RouteHops'
import { toast } from '../../store/toast'
import { sshHopsFor } from '../../lib/ssh'
import { withVaultUnlock } from '../../lib/withVaultUnlock'
import { classifyConnectionError, errorText } from '../../lib/connectionError'
import { openSettings } from '../../store/nav'
import type { Hop } from '../../types'

export function RouteEditor(): React.JSX.Element {
  const setModal = useApp((s) => s.setModal)
  const serverId = useApp((s) => s.routeEditorServerId)
  const server = useApp((s) => s.servers.find((sv) => sv.id === serverId))
  const updateServer = useApp((s) => s.updateServer)

  const [hops, setHops] = useState<Hop[]>(server?.route ?? [])
  const [testing, setTesting] = useState(false)
  const [result, setResult] = useState<{ ok: boolean; message: string; detail?: string } | null>(null)

  // A real end-to-end dial, not an animation.
  //
  // This used to tick each hop on a timer and then announce "Route reachable
  // end to end" whatever the truth was. A test that always passes is worse
  // than no test: it is the one message a user would actually trust. Opening
  // the SFTP channel builds the whole chain — every hop authenticates on the
  // way — and the throwaway key is closed again straight after, so nothing is
  // left holding a connection.
  const testAll = async (): Promise<void> => {
    if (!server) return
    setTesting(true)
    setResult(null)
    const probeKey = `route-test-${server.id}`
    let failure: string | undefined
    try {
      const r = await withVaultUnlock(`Testing the route to ${server.name}`, async () =>
        window.shellpilot?.sftp.connect(probeKey, {
          sessionId: probeKey,
          serverId: server.id,
          host: server.host,
          port: server.port,
          username: server.username,
          auth: server.auth === 'password' || server.auth === 'agent' ? server.auth : 'key',
          cols: 80,
          rows: 24,
          hops: sshHopsFor({ ...server, route: hops })
        })
      )
      if (!r?.ok) failure = r?.error ?? 'The connection did not open.'
    } catch (err) {
      failure = errorText(err)
    }
    void window.shellpilot?.sftp.disconnect(probeKey)
    setTesting(false)
    if (!failure) {
      setResult({
        ok: true,
        message: hops.length
          ? `Reached ${server.name} through ${hops.length} hop${hops.length === 1 ? '' : 's'}.`
          : `Reached ${server.name} directly.`
      })
      return
    }
    setResult({
      ok: false,
      message: `The route did not come up. ${hops.length ? 'A hop below, or the target itself, refused the connection.' : 'The target refused the connection.'}`,
      detail: failure
    })
  }

  return (
    <Modal
      title="Connection Route"
      subtitle={server ? `Jump path to ${server.name}` : 'Jump path'}
      onClose={() => setModal(null)}
      size="lg"
      footer={
        <>
          <button className="btn" disabled={testing || !serverId} onClick={() => void testAll()}>
            <PlayCircle size={14} /> {testing ? 'Testing…' : 'Test route'}
          </button>
          <span className="spacer" />
          <button className="btn" onClick={() => setModal(null)}>
            Cancel
          </button>
          <button
            className="btn primary"
            disabled={!serverId}
            onClick={() => {
              if (!serverId) return
              updateServer(serverId, { route: hops })
              toast('Route saved', 'ok')
              setModal(null)
            }}
          >
            Save route
          </button>
        </>
      }
    >
      {result && (
        <div className="row" style={{ gap: 8, marginBottom: 12, alignItems: 'flex-start' }}>
          {result.ok ? (
            <CheckCircle2 size={14} style={{ color: 'var(--ok)', flex: 'none', marginTop: 2 }} />
          ) : (
            <AlertTriangle size={14} style={{ color: 'var(--danger)', flex: 'none', marginTop: 2 }} />
          )}
          <div style={{ minWidth: 0 }}>
            <div className="selectable" style={{ fontSize: 12 }}>
              {result.message}
            </div>
            {result.detail && (
              <div className="mono faint selectable" style={{ fontSize: 11 }}>
                {result.detail}
              </div>
            )}
          </div>
          <span className="spacer" />
          {/* The only route failure that is fixed somewhere else: a key that no
              longer matches has to be reviewed and forgotten before any hop on
              this path will connect again. */}
          {classifyConnectionError(result.detail) === 'host-key' && (
            <button className="btn sm" onClick={() => openSettings('security')}>
              Review saved keys
            </button>
          )}
        </div>
      )}

      <div className="route">
        <div className="route-node">
          <span className="r-icon">
            <Monitor size={16} />
          </span>
          <div className="r-body">
            <div className="r-name">Local machine</div>
            <div className="r-host">this device</div>
          </div>
          <CheckCircle2 size={16} style={{ color: 'var(--ok)' }} />
        </div>

        <div className="route-connector">
          <span className="line" />
        </div>

        {/* Same editor the add/edit server dialog uses. */}
        <RouteHops hops={hops} onChange={setHops} excludeServerId={serverId} />

        <div className="route-connector">
          <span className="line" />
        </div>
        <div className="route-node endpoint">
          <span className="r-icon" style={{ color: 'var(--accent)' }}>
            <ServerIcon size={16} />
          </span>
          <div className="r-body">
            <div className="r-name">{server?.name ?? 'Target server'}</div>
            <div className="r-host">
              {server?.host}:{server?.port}
            </div>
          </div>
        </div>
      </div>
    </Modal>
  )
}
