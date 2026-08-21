import { ArrowDown, ArrowUp, KeyRound, Plus, Shield, Trash2 } from 'lucide-react'
import { useWorkspaceServers } from '../../store/app'
import type { Hop } from '../../types'

let hopSeq = 0

interface Props {
  hops: Hop[]
  onChange: (hops: Hop[]) => void
  // The server being configured, so it cannot be its own jump host.
  excludeServerId?: string | null
}

// Shared jump-route editor. Used both inside the add/edit server dialog and by
// the standalone route editor, so the two can never drift apart.
export function RouteHops({ hops, onChange, excludeServerId }: Props): React.JSX.Element {
  const servers = useWorkspaceServers()

  const add = (): void =>
    onChange([
      ...hops,
      {
        id: `nh-${hopSeq++}`,
        label: `Jump ${hops.length + 1}`,
        host: '',
        port: 22,
        username: '',
        auth: 'key',
        serverId: null
      }
    ])

  const remove = (id: string): void => onChange(hops.filter((h) => h.id !== id))

  const move = (i: number, dir: -1 | 1): void => {
    const j = i + dir
    if (j < 0 || j >= hops.length) return
    const next = [...hops]
    ;[next[i], next[j]] = [next[j], next[i]]
    onChange(next)
  }

  const patch = (id: string, k: keyof Hop, v: string | number): void =>
    onChange(hops.map((h) => (h.id === id ? { ...h, [k]: v } : h)))

  // Linking a hop to a saved server is what lets main reuse that server's
  // stored credentials for the hop.
  const useSaved = (id: string, pickedId: string): void => {
    const src = servers.find((s) => s.id === pickedId)
    onChange(
      hops.map((h) =>
        h.id !== id
          ? h
          : src
            ? {
                ...h,
                serverId: src.id,
                label: src.name,
                host: src.host,
                port: src.port,
                username: src.username,
                auth: src.auth,
                keyPath: undefined
              }
            : { ...h, serverId: null }
      )
    )
  }

  const pickKey = async (id: string): Promise<void> => {
    const p = await window.shellpilot?.dialog.openKey()
    if (p) onChange(hops.map((h) => (h.id === id ? { ...h, keyPath: p, auth: 'key', serverId: null } : h)))
  }

  return (
    <div className="field">
      <div className="row" style={{ marginBottom: 6 }}>
        <label className="field-label" style={{ margin: 0 }}>
          Jump hosts {hops.length > 0 && `(${hops.length})`}
        </label>
        <span className="spacer" />
        <button className="btn sm" onClick={add}>
          <Plus size={13} /> Add jump host
        </button>
      </div>

      {hops.length === 0 && (
        <span className="field-hint">
          Connects directly. Add a jump host to reach a server that is only routable from a bastion.
        </span>
      )}

      {hops.map((h, i) => (
        <div key={h.id} className="hop-card">
          <div className="row" style={{ gap: 6 }}>
            <Shield size={14} style={{ color: 'var(--warn)' }} />
            <span className="faint" style={{ fontSize: 11 }}>
              Hop {i + 1}
            </span>
            <span className="spacer" />
            <button className="icon-btn sm" title="Move up" onClick={() => move(i, -1)}>
              <ArrowUp size={13} />
            </button>
            <button className="icon-btn sm" title="Move down" onClick={() => move(i, 1)}>
              <ArrowDown size={13} />
            </button>
            <button className="icon-btn sm" title="Remove" onClick={() => remove(h.id)}>
              <Trash2 size={13} />
            </button>
          </div>

          <select
            className="input"
            value={h.serverId ?? ''}
            onChange={(e) => useSaved(h.id, e.target.value)}
            title="Reuse a saved server, including its stored credentials"
          >
            <option value="">Custom host — set details below</option>
            {servers
              .filter((s) => s.id !== excludeServerId)
              .map((s) => (
                <option key={s.id} value={s.id}>
                  Use saved: {s.name} ({s.username}@{s.host})
                </option>
              ))}
          </select>

          <div className="input-group">
            <input
              className="input"
              style={{ flex: '0 0 30%' }}
              placeholder="label"
              value={h.label}
              onChange={(e) => patch(h.id, 'label', e.target.value)}
            />
            <input
              className="input"
              placeholder="host"
              value={h.host}
              disabled={!!h.serverId}
              onChange={(e) => patch(h.id, 'host', e.target.value)}
            />
            <input
              className="input"
              style={{ flex: '0 0 76px' }}
              placeholder="port"
              value={h.port}
              disabled={!!h.serverId}
              onChange={(e) => patch(h.id, 'port', Number(e.target.value) || 22)}
            />
            <input
              className="input"
              style={{ flex: '0 0 24%' }}
              placeholder="user"
              value={h.username}
              disabled={!!h.serverId}
              onChange={(e) => patch(h.id, 'username', e.target.value)}
            />
          </div>

          <div className="input-group">
            <input
              className="input"
              placeholder={h.serverId ? 'using the saved server’s credentials' : 'private key file'}
              value={h.serverId ? '' : h.keyPath ?? ''}
              disabled={!!h.serverId}
              onChange={(e) => patch(h.id, 'keyPath', e.target.value)}
            />
            <button
              className="btn"
              style={{ flex: '0 0 auto' }}
              disabled={!!h.serverId}
              onClick={() => void pickKey(h.id)}
            >
              <KeyRound size={13} /> Browse
            </button>
          </div>
        </div>
      ))}
    </div>
  )
}
