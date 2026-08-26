import { useState, useEffect } from 'react'
import { KeyRound, Lock, UserCheck, FileBadge, FolderOpen, ChevronRight } from 'lucide-react'
import { Modal } from '../common/Modal'
import { useApp } from '../../store/app'
import { RouteHops } from './RouteHops'
import { toast } from '../../store/toast'
import { clsx } from '../../lib/format'
import type { AuthMethod, Hop } from '../../types'

const AUTH: { id: AuthMethod; label: string; icon: React.ReactNode }[] = [
  { id: 'password', label: 'Password', icon: <Lock size={16} /> },
  { id: 'key', label: 'Private Key', icon: <KeyRound size={16} /> },
  { id: 'agent', label: 'SSH Agent', icon: <UserCheck size={16} /> },
  { id: 'certificate', label: 'Certificate', icon: <FileBadge size={16} /> }
]

export function AddServerModal(): React.JSX.Element {
  const setModal = useApp((s) => s.setModal)
  const addServer = useApp((s) => s.addServer)
  const updateServer = useApp((s) => s.updateServer)
  const openServer = useApp((s) => s.openServer)
  // Set when the modal was opened to edit an existing server.
  const editId = useApp((s) => s.editServerId)
  const existing = useApp((s) => s.servers.find((sv) => sv.id === s.editServerId))

  const [name, setName] = useState(existing?.name ?? '')
  const [host, setHost] = useState(existing?.host ?? '')
  const [port, setPort] = useState(String(existing?.port ?? 22))
  const [username, setUsername] = useState(existing?.username ?? 'root')
  const [auth, setAuth] = useState<AuthMethod>(existing?.auth ?? 'key')
  const [keyPath, setKeyPath] = useState('')
  const [foundKeys, setFoundKeys] = useState<
    { path: string; fileName: string; algorithm: string | null; encrypted: boolean }[]
  >([])
  const [hops, setHops] = useState<Hop[]>(existing?.route ?? [])
  const [passphrase, setPassphrase] = useState('')
  const [password, setPassword] = useState('')
  const [advanced, setAdvanced] = useState(false)
  const [keepAlive, setKeepAlive] = useState(true)
  const [compression, setCompression] = useState(false)
  const [hostKeyCheck, setHostKeyCheck] = useState(true)
  const [timeout, setTimeoutV] = useState('15')
  const [env, setEnv] = useState('')

  const valid = name.trim() && host.trim()

  const pickKey = async (): Promise<void> => {
    const p = await window.shellpilot?.dialog.openKey()
    if (p) setKeyPath(p)
  }

  // ~/.ssh is hidden and OpenSSH keys have no extension, so the file picker is
  // a bad first experience. Offer what is already there; nothing is selected
  // until the user clicks it.
  useEffect(() => {
    if (auth !== 'key' || foundKeys.length > 0) return
    void window.shellpilot?.ssh.defaultKeys().then((k) => setFoundKeys(k ?? []))
  }, [auth, foundKeys.length])

  const save = async (): Promise<void> => {
    if (!valid) return
    const fields = {
      name: name.trim(),
      host: host.trim(),
      port: Number(port) || 22,
      username: username.trim() || 'root',
      auth,
      route: hops
    }
    const id = editId ? (updateServer(editId, fields), editId) : addServer(fields)

    // Credentials live in OS secure storage, keyed by server id. On an edit,
    // blank fields mean "leave what is already stored alone".
    const secret =
      auth === 'password'
        ? { password }
        : auth === 'key'
          ? { keyPath: keyPath.trim() || undefined, passphrase: passphrase || undefined }
          : null
    if (secret && (secret.password || secret.keyPath)) {
      const ok = await window.shellpilot?.secrets.set(id, JSON.stringify(secret))
      if (ok === false) toast('OS secure storage unavailable — credentials not saved', 'error')
    }

    toast(`${fields.name} ${editId ? 'updated' : 'added'}`, 'ok')
    setModal(null)
    if (!editId) openServer(id, 'terminal')
  }

  return (
    <Modal
      title={editId ? 'Edit Server' : 'Add Server'}
      subtitle={editId ? 'Change this connection profile' : 'Create a new SSH connection profile'}
      onClose={() => setModal(null)}
      footer={
        <>
          <span className="spacer" />
          <button className="btn" onClick={() => setModal(null)}>
            Cancel
          </button>
          <button className="btn primary" disabled={!valid} onClick={save}>
            {editId ? 'Save Changes' : 'Add Server'}
          </button>
        </>
      }
    >
      <div className="field">
        <label className="field-label">Connection Name</label>
        <input
          className="input"
          placeholder="Production API"
          value={name}
          onChange={(e) => setName(e.target.value)}
          autoFocus
        />
      </div>

      <div className="field-row">
        <div className="field" style={{ gridColumn: 'span 1' }}>
          <label className="field-label">Host / IP</label>
          <input className="input" placeholder="10.20.0.10" value={host} onChange={(e) => setHost(e.target.value)} />
        </div>
        <div className="field-row" style={{ gridColumn: 'span 1' }}>
          <div className="field">
            <label className="field-label">Port</label>
            <input className="input" value={port} onChange={(e) => setPort(e.target.value)} />
          </div>
          <div className="field">
            <label className="field-label">Username</label>
            <input className="input" value={username} onChange={(e) => setUsername(e.target.value)} />
          </div>
        </div>
      </div>

      <div className="field">
        <label className="field-label">Authentication</label>
        <div className="radio-cards">
          {AUTH.map((a) => (
            <button
              key={a.id}
              className={clsx('radio-card', auth === a.id && 'active')}
              onClick={() => setAuth(a.id)}
            >
              {a.icon}
              {a.label}
            </button>
          ))}
        </div>
      </div>

      {auth === 'key' && (
        <div className="field">
          <label className="field-label">Private key</label>
          <div className="input-group">
            <input
              className="input"
              placeholder="~/.ssh/id_ed25519"
              value={keyPath}
              onChange={(e) => setKeyPath(e.target.value)}
            />
            <button className="btn" onClick={pickKey}>
              <FolderOpen size={14} /> Browse
            </button>
          </div>
          {foundKeys.length > 0 && (
            <div className="field-hint" style={{ marginTop: 6 }}>
              <span>Found in ~/.ssh:</span>
              <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap', marginTop: 4 }}>
                {foundKeys.map((k) => (
                  <button
                    key={k.path}
                    className={clsx('btn', 'sm', keyPath === k.path && 'active')}
                    onClick={() => setKeyPath(k.path)}
                    title={k.path}
                  >
                    <KeyRound size={12} /> {k.fileName}
                    {k.algorithm ? ` (${k.algorithm})` : ''}
                    {k.encrypted ? ' \u00b7 passphrase' : ''}
                  </button>
                ))}
              </div>
            </div>
          )}
          <span className="field-hint">Key path and passphrase are stored in OS secure storage, never in plaintext.</span>
          <input
            className="input"
            type="password"
            placeholder="Key passphrase (optional)"
            value={passphrase}
            onChange={(e) => setPassphrase(e.target.value)}
            style={{ marginTop: 8 }}
          />
        </div>
      )}

      {auth === 'password' && (
        <div className="field">
          <label className="field-label">Password</label>
          <input
            className="input"
            type="password"
            placeholder="••••••••••"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
          />
          <span className="field-hint">Encrypted with the OS keychain.</span>
        </div>
      )}

      <RouteHops hops={hops} onChange={setHops} excludeServerId={editId} />

      <div className="disclosure">
        <button className="disclosure-head" onClick={() => setAdvanced((v) => !v)}>
          <ChevronRight size={14} className={clsx('chev', advanced && 'open')} style={{ transition: 'transform .12s', transform: advanced ? 'rotate(90deg)' : undefined }} />
          Advanced options
        </button>
        {advanced && (
          <div className="disclosure-body">
            <div className="field-row">
              <div className="field">
                <label className="field-label">Connection timeout (s)</label>
                <input className="input" value={timeout} onChange={(e) => setTimeoutV(e.target.value)} />
              </div>
              <div className="field">
                <label className="field-label">Environment variables</label>
                <input className="input" placeholder="TERM=xterm-256color" value={env} onChange={(e) => setEnv(e.target.value)} />
              </div>
            </div>
            <label className="row" style={{ justifyContent: 'space-between' }}>
              <span className="s-title">Keep-alive</span>
              <span className={clsx('switch', keepAlive && 'on')} onClick={() => setKeepAlive((v) => !v)} />
            </label>
            <label className="row" style={{ justifyContent: 'space-between' }}>
              <span className="s-title">Compression</span>
              <span className={clsx('switch', compression && 'on')} onClick={() => setCompression((v) => !v)} />
            </label>
            <label className="row" style={{ justifyContent: 'space-between' }}>
              <span className="s-title">Strict host key verification</span>
              <span className={clsx('switch', hostKeyCheck && 'on')} onClick={() => setHostKeyCheck((v) => !v)} />
            </label>
          </div>
        )}
      </div>
    </Modal>
  )
}
