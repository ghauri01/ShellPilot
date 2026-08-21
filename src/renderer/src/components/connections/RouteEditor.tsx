import { useState } from 'react'
import { Monitor, Server as ServerIcon, CheckCircle2, PlayCircle } from 'lucide-react'
import { Modal } from '../common/Modal'
import { useApp } from '../../store/app'
import { RouteHops } from './RouteHops'
import { toast } from '../../store/toast'
import type { Hop } from '../../types'

export function RouteEditor(): React.JSX.Element {
  const setModal = useApp((s) => s.setModal)
  const serverId = useApp((s) => s.routeEditorServerId)
  const server = useApp((s) => s.servers.find((sv) => sv.id === serverId))
  const updateServer = useApp((s) => s.updateServer)

  const [hops, setHops] = useState<Hop[]>(server?.route ?? [])
  const [testing, setTesting] = useState(false)
  const [, setTested] = useState<Set<string>>(new Set())




  const testAll = (): void => {
    setTesting(true)
    setTested(new Set())
    const ids = hops.map((h) => h.id)
    ids.forEach((id, i) =>
      setTimeout(() => {
        setTested((s) => new Set([...s, id]))
        if (i === ids.length - 1) {
          setTesting(false)
          toast('Route reachable end to end', 'ok')
        }
      }, (i + 1) * 500)
    )
  }

  return (
    <Modal
      title="Connection Route"
      subtitle={server ? `Jump path to ${server.name}` : 'Jump path'}
      onClose={() => setModal(null)}
      size="lg"
      footer={
        <>
          <button className="btn" disabled={testing || hops.length === 0} onClick={testAll}>
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
