import { useState, useEffect } from 'react'
import { KeyRound, Lock, UserCheck, FileBadge, FolderOpen, ChevronRight } from 'lucide-react'
import { Modal } from '../common/Modal'
import { useApp } from '../../store/app'
import { RouteHops } from './RouteHops'
import { toast } from '../../store/toast'
import { clsx } from '../../lib/format'
import { useVault } from '../../store/vault'
import { VpnTransportSelect } from '../vpn/VpnTransportSelect'
import type { AuthMethod, Hop, UUID } from '../../types'

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
  // '' means "enter a new one"; anything else is a vault entry id.
  const [vaultEntryId, setVaultEntryId] = useState('')
  const [saveToVault, setSaveToVault] = useState(true)
  const [foundKeys, setFoundKeys] = useState<
    { path: string; fileName: string; algorithm: string | null; encrypted: boolean }[]
  >([])
  const [hops, setHops] = useState<Hop[]>(existing?.route ?? [])
  const [vpnProfileId, setVpnProfileId] = useState<UUID | null>(existing?.vpnProfileId ?? null)
  const [passphrase, setPassphrase] = useState('')
  const [password, setPassword] = useState('')
  const [advanced, setAdvanced] = useState(false)
  const [keepAlive, setKeepAlive] = useState(true)
  const [compression, setCompression] = useState(false)
  const [hostKeyCheck, setHostKeyCheck] = useState(true)
  const [timeout, setTimeoutV] = useState('15')
  const [env, setEnv] = useState('')

  const vaultUnlocked = useVault((s) => s.unlocked)
  const vaultEntries = useVault((s) => s.entries)
  const createVaultEntry = useVault((s) => s.createEntry)

  // A credential is only offered for the method it can actually satisfy: a
  // password entry cannot authenticate a key connection, and vice versa.
  const usableEntries = vaultEntries.filter((e) =>
    auth === 'key' ? !!e.privateKey : auth === 'password' ? !!e.password && !e.privateKey : false
  )
  const usingVault = vaultUnlocked && vaultEntryId !== ''

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
      route: hops,
      vpnProfileId
    }
    const id = editId ? (updateServer(editId, fields), editId) : addServer(fields)

    // What gets stored against the server is a reference wherever possible.
    // A credential in the vault is one record — reusable across every server
    // that uses it, and changed in one place when it rotates — whereas a copy
    // per server is what makes rotation a hunt.
    let secret: Record<string, string | undefined> | null = null

    if (usingVault) {
      secret = { vaultEntryId }
    } else if (auth === 'password' && password) {
      secret = saveToVault && vaultUnlocked ? null : { password }
      if (!secret) {
        const entryId = await createVaultEntry('login', {
          name: `${fields.name} (${fields.username})`,
          username: fields.username,
          password,
          tags: ['server']
        })
        // Falling back to the keychain beats losing the credential the user
        // just typed because the vault write failed.
        secret = entryId ? { vaultEntryId: entryId } : { password }
        if (!entryId) toast('Could not save to the vault — kept in OS secure storage', 'error')
      }
    } else if (auth === 'key' && keyPath.trim()) {
      secret = { keyPath: keyPath.trim(), passphrase: passphrase || undefined }
    }

    if (secret) {
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

      {auth !== 'agent' && vaultUnlocked && usableEntries.length > 0 && (
        <div className="field">
          <label className="field-label">Credential</label>
          <select className="input" value={vaultEntryId} onChange={(e) => setVaultEntryId(e.target.value)}>
            <option value="">Enter a new one…</option>
            {usableEntries.map((e) => (
              <option key={e.id} value={e.id}>
                {e.name}
                {e.username ? ` — ${e.username}` : ''}
              </option>
            ))}
          </select>
          <span className="field-hint">
            {usingVault
              ? 'This server will reference the vault entry. Change the credential there and every server using it follows.'
              : 'Reuse a credential you have already saved, or type a new one below.'}
          </span>
        </div>
      )}

      {auth !== 'agent' && vaultUnlocked && usableEntries.length === 0 && (
        <div className="field">
          <span className="field-hint">
            No saved {auth === 'key' ? 'SSH key' : 'login'} in the vault yet — type one below and it
            will be saved there.
          </span>
        </div>
      )}

      {auth === 'key' && !usingVault && (
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

      {auth === 'password' && !usingVault && (
        <div className="field">
          <label className="field-label">Password</label>
          <input
            className="input"
            type="password"
            placeholder="••••••••••"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
          />
          {vaultUnlocked ? (
            <label className="field-hint row" style={{ gap: 6, cursor: 'pointer', marginTop: 6 }}>
              <input type="checkbox" checked={saveToVault} onChange={(e) => setSaveToVault(e.target.checked)} />
              Save this to the vault as a reusable credential
            </label>
          ) : (
            <span className="field-hint">
              Encrypted with the OS keychain. Unlock the vault first to save it as a reusable
              credential instead.
            </span>
          )}
        </div>
      )}

      <VpnTransportSelect
        value={vpnProfileId}
        onChange={setVpnProfileId}
        hint="The VPN is the outer transport: any jump hosts below are dialled through it, and so is everything that rides this server — terminals, SFTP, metrics and its SSH tunnels."
      />

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
