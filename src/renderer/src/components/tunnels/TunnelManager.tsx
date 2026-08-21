import { useCallback, useEffect, useState } from 'react'
import { Network, Plus, Power, ArrowRight, Trash2, Loader2 } from 'lucide-react'
import { useApp, useWorkspaceServers, useWorkspaceTunnels } from '../../store/app'
import { EmptyState } from '../common/EmptyState'
import { Modal } from '../common/Modal'
import { clsx } from '../../lib/format'
import { toast } from '../../store/toast'
import { parseEndpoint } from '../../../../shared/tunnel'
import type { TunnelStatus } from '../../../../shared/tunnel'
import { sshHopFor } from '../../lib/ssh'
import type { Tunnel, TunnelKind } from '../../types'

const kindLabel: Record<TunnelKind, string> = {
  local: 'Local forward',
  remote: 'Remote forward',
  socks: 'SOCKS5 proxy'
}

export function TunnelManager(): React.JSX.Element {
  const tunnels = useWorkspaceTunnels()
  const servers = useWorkspaceServers()
  const deleteTunnel = useApp((s) => s.deleteTunnel)
  const setTunnelStatus = useApp((s) => s.setTunnelStatus)
  const [creating, setCreating] = useState(false)
  const [live, setLive] = useState<Record<string, TunnelStatus>>({})
  const [busy, setBusy] = useState<Record<string, boolean>>({})

  // Subscribe to status for every tunnel in the workspace.
  //
  // Keyed on the ids rather than the tunnel objects. A status write replaces
  // the object it touches, so depending on the list itself would tear down and
  // rebuild every subscription each time a status arrived — and a busy tunnel
  // reports one per connection. The name is resolved when an error actually
  // fires, which keeps renames out of this dependency too.
  const tunnelIds = tunnels.map((t) => t.id).join(',')
  useEffect(() => {
    const ids = tunnelIds ? tunnelIds.split(',') : []
    const offs = ids.map((id) =>
      window.shellpilot?.tunnel.onStatus(id, (s) => {
        setLive((m) => ({ ...m, [id]: s }))
        setTunnelStatus(id, s.state === 'active' ? 'active' : 'inactive')
        if (s.state === 'error' && s.error) {
          const name = useApp.getState().tunnels.find((t) => t.id === id)?.name ?? 'Tunnel'
          toast(`${name}: ${s.error}`, 'error')
        }
      })
    )
    return () => offs.forEach((off) => off?.())
  }, [tunnelIds, setTunnelStatus])

  // Reconcile with what is actually running (e.g. after a view remount).
  useEffect(() => {
    void window.shellpilot?.tunnel.list().then((list) => {
      if (!list) return
      setLive(Object.fromEntries(list.map((s) => [s.id, s])))
      list.forEach((s) => setTunnelStatus(s.id, s.state === 'active' ? 'active' : 'inactive'))
    })
  }, [setTunnelStatus])

  const toggle = useCallback(
    async (t: Tunnel) => {
      const running = live[t.id]?.state === 'active'
      setBusy((b) => ({ ...b, [t.id]: true }))
      if (running) {
        await window.shellpilot?.tunnel.stop(t.id)
        toast(`${t.name} stopped`)
      } else {
        const server = servers.find((s) => s.id === t.serverId)
        if (!server) {
          toast('This tunnel has no SSH server selected', 'error')
          setBusy((b) => ({ ...b, [t.id]: false }))
          return
        }
        const listen = parseEndpoint(t.listen)
        const target = t.kind === 'socks' ? { host: '', port: 0 } : parseEndpoint(t.target)
        const r = await window.shellpilot?.tunnel.start(
          {
            id: t.id,
            kind: t.kind,
            listenHost: listen.host,
            listenPort: listen.port,
            targetHost: target.host,
            targetPort: target.port
          },
          sshHopFor(server)
        )
        if (r?.ok) toast(`${t.name} listening on ${listen.host}:${r.listenPort}`, 'ok')
        else toast(r?.error ?? 'Could not start the tunnel', 'error')
      }
      setBusy((b) => ({ ...b, [t.id]: false }))
    },
    [live, servers]
  )

  const header = (
    <div className="content-header">
      <div>
        <h1>SSH Tunnels</h1>
        <div className="sub">Local &amp; remote port forwarding and SOCKS5 proxies</div>
      </div>
      <div className="spacer" />
      <button className="btn primary" onClick={() => setCreating(true)}>
        <Plus size={15} /> Create tunnel
      </button>
    </div>
  )

  if (tunnels.length === 0) {
    return (
      <div className="panel-body">
        <EmptyState
          icon={<Network size={26} />}
          title="No tunnels"
          message="Create a secure SSH tunnel to forward a local or remote port through a server."
          action={
            <button className="btn primary" onClick={() => setCreating(true)}>
              <Plus size={15} /> Create tunnel
            </button>
          }
        />
        {creating && <TunnelForm onClose={() => setCreating(false)} />}
      </div>
    )
  }

  return (
    <div className="content">
      {header}

      {tunnels.map((t) => {
        const st = live[t.id]
        const on = st?.state === 'active'
        const server = servers.find((s) => s.id === t.serverId)
        return (
          <div key={t.id} className="list-row">
            <span className={clsx('status-dot', on ? 'online' : st?.state === 'error' ? 'error' : 'offline')} />
            <div>
              <div className="r-title">{t.name}</div>
              <div className="r-sub">
                {kindLabel[t.kind]}
                {server ? ` · via ${server.name}` : ' · no server'}
                {on && st.connections > 0 ? ` · ${st.connections} open` : ''}
              </div>
            </div>
            <span className="spacer" />
            <div className="r-stat mono" style={{ alignItems: 'center' }}>
              <span>{t.listen}</span>
              {t.kind !== 'socks' && (
                <>
                  <ArrowRight size={13} />
                  <span>{t.target}</span>
                </>
              )}
            </div>
            <button
              className={clsx('btn sm', on ? 'danger' : 'primary')}
              disabled={busy[t.id]}
              onClick={() => void toggle(t)}
            >
              {busy[t.id] ? <Loader2 size={13} className="spin" /> : <Power size={13} />}
              {on ? 'Stop' : 'Start'}
            </button>
            <button
              className="icon-btn sm"
              title="Delete tunnel"
              onClick={() => {
                void window.shellpilot?.tunnel.stop(t.id)
                deleteTunnel(t.id)
                toast(`${t.name} deleted`)
              }}
            >
              <Trash2 size={14} />
            </button>
          </div>
        )
      })}

      {creating && <TunnelForm onClose={() => setCreating(false)} />}
    </div>
  )
}

function TunnelForm({ onClose }: { onClose: () => void }): React.JSX.Element {
  const servers = useWorkspaceServers()
  const addTunnel = useApp((s) => s.addTunnel)

  const [name, setName] = useState('')
  const [kind, setKind] = useState<TunnelKind>('local')
  const [serverId, setServerId] = useState(servers[0]?.id ?? '')
  const [listen, setListen] = useState('127.0.0.1:8080')
  const [target, setTarget] = useState('localhost:80')

  const socks = kind === 'socks'
  const valid = name.trim() && serverId && parseEndpoint(listen).port > 0 && (socks || parseEndpoint(target).port > 0)

  const save = (): void => {
    if (!valid) return
    addTunnel({ name: name.trim(), kind, serverId, listen: listen.trim(), target: socks ? '' : target.trim() })
    toast(`${name.trim()} created — press Start to open it`, 'ok')
    onClose()
  }

  return (
    <Modal title="Create tunnel" subtitle="Forward a port over an SSH connection" onClose={onClose}>
      <div className="card" style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
        <input
          className="input"
          placeholder="Tunnel name"
          autoFocus
          value={name}
          onChange={(e) => setName(e.target.value)}
        />

        <div className="row" style={{ gap: 6 }}>
          {(['local', 'remote', 'socks'] as TunnelKind[]).map((k) => (
            <button
              key={k}
              className={clsx('btn sm', kind === k && 'primary')}
              onClick={() => {
                setKind(k)
                if (k === 'socks') setListen('127.0.0.1:1080')
              }}
            >
              {kindLabel[k]}
            </button>
          ))}
        </div>

        <label className="field">
          <span className="field-label">SSH server</span>
          <select className="input" value={serverId} onChange={(e) => setServerId(e.target.value)}>
            {servers.length === 0 && <option value="">No servers in this workspace</option>}
            {servers.map((s) => (
              <option key={s.id} value={s.id}>
                {s.name} ({s.username}@{s.host})
              </option>
            ))}
          </select>
        </label>

        <label className="field">
          <span className="field-label">{kind === 'remote' ? 'Listen on server' : 'Listen locally'}</span>
          <input className="input" value={listen} onChange={(e) => setListen(e.target.value)} placeholder="127.0.0.1:8080" />
        </label>

        {!socks && (
          <label className="field">
            <span className="field-label">
              {kind === 'remote' ? 'Forward to (from this machine)' : 'Forward to (from the server)'}
            </span>
            <input className="input" value={target} onChange={(e) => setTarget(e.target.value)} placeholder="localhost:80" />
          </label>
        )}

        <div className="faint" style={{ fontSize: 11 }}>
          {kind === 'local' && 'Connections to the local port are carried over SSH and opened from the server.'}
          {kind === 'remote' && 'The server listens and forwards connections back to this machine.'}
          {kind === 'socks' && 'Point a browser or CLI at this port to route traffic through the server.'}
        </div>

        <div className="row" style={{ gap: 8 }}>
          <span className="spacer" />
          <button className="btn sm" onClick={onClose}>
            Cancel
          </button>
          <button className="btn primary sm" disabled={!valid} onClick={save}>
            <Plus size={14} /> Create
          </button>
        </div>
      </div>
    </Modal>
  )
}
