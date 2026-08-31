import { useEffect, useState } from 'react'
import { Database } from 'lucide-react'
import { Modal } from '../common/Modal'
import { useApp, useWorkspaceServers } from '../../store/app'
import { toast } from '../../store/toast'
import { clsx } from '../../lib/format'
import { KIND_COLOR } from './DatabaseSidebar'
import { VpnTransportSelect } from '../vpn/VpnTransportSelect'
import { saveDatabaseEdit, useDbEditor } from '../../store/dbEditor'
import type { DbKind, UUID } from '../../types'

const KINDS: { id: DbKind; label: string; port: number }[] = [
  { id: 'postgres', label: 'PostgreSQL', port: 5432 },
  { id: 'mysql', label: 'MySQL', port: 3306 },
  { id: 'mssql', label: 'SQL Server', port: 1433 },
  { id: 'mongodb', label: 'MongoDB', port: 27017 },
  { id: 'redis', label: 'Redis', port: 6379 }
]

export function AddDatabaseModal(): React.JSX.Element {
  const setModal = useApp((s) => s.setModal)
  const addDatabase = useApp((s) => s.addDatabase)
  const servers = useWorkspaceServers()
  // Set when the dialog was opened to correct an existing connection.
  const editId = useDbEditor((s) => s.editId)
  const existing = useApp((s) => s.databases.find((d) => d.id === editId))

  const [kind, setKind] = useState<DbKind>(existing?.kind ?? 'postgres')
  const [mode, setMode] = useState<'fields' | 'uri'>(existing?.uri ? 'uri' : 'fields')
  const [name, setName] = useState(existing?.name ?? '')
  const [host, setHost] = useState(existing?.host ?? 'localhost')
  const [port, setPort] = useState(String(existing?.port ?? 5432))
  const [username, setUsername] = useState(existing?.username ?? '')
  const [password, setPassword] = useState('')
  const [database, setDatabase] = useState(existing?.database ?? '')
  const [ssl, setSsl] = useState(existing?.ssl ?? false)
  const [uri, setUri] = useState('')
  const [sshServerId, setSshServerId] = useState(existing?.sshServerId ?? '')
  const [vpnProfileId, setVpnProfileId] = useState<UUID | null>(existing?.vpnProfileId ?? null)

  // Whoever opened the dialog owns the target; leaving it set would make the
  // next plain "Add database" open on the connection edited before it.
  useEffect(() => () => useDbEditor.setState({ editId: null }), [])

  const pickKind = (k: DbKind): void => {
    setKind(k)
    setPort(String(KINDS.find((x) => x.id === k)?.port ?? 5432))
  }

  const useUri = mode === 'uri'
  // An edit starts with the stored credential already in the keychain, so an
  // empty password field means "leave it alone" rather than "there isn't one".
  const valid = name.trim() && (useUri ? uri.trim() || !!editId : host.trim())

  // Retryable on purpose: an OS keychain that is unavailable is usually a
  // login keyring the user has not unlocked yet, and that is fixed outside
  // this app and then works.
  const storeSecret = async (
    id: string,
    secret: { uri: string } | { password: string },
    label: string
  ): Promise<void> => {
    const ok = await window.shellpilot?.secrets.set(id, JSON.stringify(secret))
    if (ok !== false) return
    toast(`${label} was saved, but this device would not store its password.`, 'error', {
      label: 'Try again',
      run: () => void storeSecret(id, secret, label)
    })
  }

  const save = async (): Promise<void> => {
    if (!valid) return
    const displayHost = useUri ? uri.match(/@([^/:?,]+)/)?.[1] ?? uri.replace(/^\w+(\+\w+)?:\/\//, '').split(/[/:?]/)[0] : host.trim()
    const fields = {
      name: name.trim(),
      kind,
      host: displayHost || existing?.host || '',
      port: Number(port) || KINDS.find((x) => x.id === kind)!.port,
      username: useUri ? '' : username.trim(),
      database: database.trim(),
      ssl,
      uri: useUri,
      folderId: existing?.folderId ?? null,
      sshServerId: sshServerId || null,
      vpnProfileId
    }
    const id = editId ? (saveDatabaseEdit(editId, fields), editId) : addDatabase(fields)
    const secret = useUri ? (uri.trim() ? { uri: uri.trim() } : null) : password ? { password } : null
    if (secret) await storeSecret(id, secret, fields.name)
    toast(`${fields.name} ${editId ? 'updated' : 'added'}`, 'ok')
    setModal(null)
  }

  const uriPlaceholder: Record<DbKind, string> = {
    postgres: 'postgresql://user:pass@host:5432/dbname',
    mysql: 'mysql://user:pass@host:3306/dbname',
    mssql: 'Server=host,1433;Database=db;User Id=user;Password=pass;Encrypt=true',
    mongodb: 'mongodb+srv://user:pass@cluster.mongodb.net/dbname',
    redis: 'redis://:pass@host:6379/0'
  }

  return (
    <Modal
      title={editId ? 'Edit Database' : 'Add Database'}
      subtitle={editId ? `Change how ShellPilot reaches ${existing?.name ?? 'this database'}` : 'Create a database connection profile'}
      onClose={() => setModal(null)}
      footer={
        <>
          <span className="spacer" />
          <button className="btn" onClick={() => setModal(null)}>
            Cancel
          </button>
          <button className="btn primary" disabled={!valid} onClick={save}>
            {editId ? 'Save Changes' : 'Add Database'}
          </button>
        </>
      }
    >
      <div className="field">
        <label className="field-label">Engine</label>
        <div className="radio-cards" style={{ gridTemplateColumns: 'repeat(5, 1fr)' }}>
          {KINDS.map((k) => (
            <button
              key={k.id}
              className={clsx('radio-card', kind === k.id && 'active')}
              onClick={() => pickKind(k.id)}
            >
              <Database size={16} style={{ color: KIND_COLOR[k.id] }} />
              {k.label}
            </button>
          ))}
        </div>
      </div>

      <div className="row" style={{ gap: 8 }}>
        <div className="field grow">
          <label className="field-label">Connection Name</label>
          <input className="input" placeholder="Production DB" value={name} onChange={(e) => setName(e.target.value)} autoFocus />
        </div>
        <div className="field">
          <label className="field-label">Method</label>
          <div className="segment">
            <button className={clsx('seg-btn', !useUri && 'active')} onClick={() => setMode('fields')}>
              Fields
            </button>
            <button className={clsx('seg-btn', useUri && 'active')} onClick={() => setMode('uri')}>
              Connection string
            </button>
          </div>
        </div>
      </div>

      {useUri ? (
        <>
          <div className="field">
            <label className="field-label">Connection string / URI</label>
            <textarea
              className="textarea"
              style={{ minHeight: 60 }}
              placeholder={editId ? 'Leave blank to keep the saved connection string' : uriPlaceholder[kind]}
              value={uri}
              onChange={(e) => setUri(e.target.value)}
            />
          </div>
          {kind === 'mongodb' && (
            <div className="field">
              <label className="field-label">Database (optional — overrides the URI default)</label>
              <input className="input" placeholder="from URI" value={database} onChange={(e) => setDatabase(e.target.value)} />
            </div>
          )}
        </>
      ) : (
        <>
          <div className="field-row">
            <div className="field" style={{ gridColumn: 'span 1' }}>
              <label className="field-label">Host / IP</label>
              <input className="input" value={host} onChange={(e) => setHost(e.target.value)} />
            </div>
            <div className="field">
              <label className="field-label">Port</label>
              <input className="input" value={port} onChange={(e) => setPort(e.target.value)} />
            </div>
          </div>

          <div className="field-row">
            <div className="field">
              <label className="field-label">Username</label>
              <input className="input" value={username} onChange={(e) => setUsername(e.target.value)} />
            </div>
            <div className="field">
              <label className="field-label">Password</label>
              <input
                className="input"
                type="password"
                placeholder={editId ? 'Unchanged' : '••••••••'}
                value={password}
                onChange={(e) => setPassword(e.target.value)}
              />
            </div>
          </div>

          <div className="field-row">
            <div className="field">
              <label className="field-label">{kind === 'redis' ? 'Database (index)' : 'Database'}</label>
              <input
                className="input"
                placeholder={kind === 'mongodb' ? 'admin' : kind === 'redis' ? '0' : 'postgres'}
                value={database}
                onChange={(e) => setDatabase(e.target.value)}
              />
            </div>
            <div className="field">
              <label className="field-label">TLS / SSL</label>
              <label className="row" style={{ height: 34, gap: 10 }}>
                <span className={clsx('switch', ssl && 'on')} onClick={() => setSsl((v) => !v)} />
                <span className="muted">{ssl ? 'Enabled' : 'Disabled'}</span>
              </label>
            </div>
          </div>
        </>
      )}

      <div className="field">
        <label className="field-label">SSH tunnel (optional)</label>
        <select className="input" value={sshServerId} onChange={(e) => setSshServerId(e.target.value)}>
          <option value="">Connect directly</option>
          {servers.map((s) => (
            <option key={s.id} value={s.id}>
              via {s.name} ({s.username}@{s.host})
            </option>
          ))}
        </select>
        <span className="field-hint">
          Reaches a database that is only routable from the bastion. The host and port above are
          resolved on the server, not on this machine.
          {kind === 'mongodb' && ' mongodb+srv:// strings cannot be tunnelled — use host/port.'}
        </span>
      </div>

      <VpnTransportSelect
        value={vpnProfileId}
        onChange={setVpnProfileId}
        hint={
          sshServerId
            ? 'Both are set, so the VPN goes on the outside: the SSH server above is reached through the VPN, and the database is reached from there exactly as it would be without one.'
            : 'Independent of the SSH tunnel above, and stackable with it: set both and the VPN carries the SSH server, which then reaches the database.'
        }
      />

      <span className="field-hint">Credentials are stored in OS secure storage, never in plaintext.</span>
    </Modal>
  )
}
