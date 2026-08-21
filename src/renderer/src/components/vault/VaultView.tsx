import { useEffect, useState } from 'react'
import { Copy, Eye, EyeOff, KeyRound, Lock, Plus, ShieldCheck, Trash2, Unlock } from 'lucide-react'
import { useVault, newField } from '../../store/vault'
import { toast } from '../../store/toast'
import { VAULT_KIND_LABEL, type VaultEntry, type VaultKind } from '../../../../shared/vault'

const KINDS: VaultKind[] = ['login', 'url', 'key', 'note']

function copy(label: string, value: string): void {
  if (!value) return
  window.shellpilot?.clipboard.write(value)
  toast(`${label} copied`)
}

export function VaultView(): React.JSX.Element {
  const exists = useVault((s) => s.exists)
  const unlocked = useVault((s) => s.unlocked)
  const refresh = useVault((s) => s.refresh)

  useEffect(() => {
    void refresh()
  }, [refresh])

  if (!exists) return <VaultGate mode="create" />
  if (!unlocked) return <VaultGate mode="unlock" />
  return <VaultBrowser />
}

// Create-master-password and unlock share a layout; only the copy and the
// action differ.
function VaultGate({ mode }: { mode: 'create' | 'unlock' }): React.JSX.Element {
  const create = useVault((s) => s.create)
  const unlock = useVault((s) => s.unlock)
  const error = useVault((s) => s.error)
  const clearError = useVault((s) => s.clearError)
  const busy = useVault((s) => s.busy)

  const [password, setPassword] = useState('')
  const [confirm, setConfirm] = useState('')
  const [show, setShow] = useState(false)

  const creating = mode === 'create'
  const mismatch = creating && confirm.length > 0 && password !== confirm
  const canSubmit = password.length >= (creating ? 8 : 1) && !mismatch && (!creating || confirm.length > 0)

  const submit = async (): Promise<void> => {
    if (!canSubmit || busy) return
    const ok = creating ? await create(password) : await unlock(password)
    if (ok) {
      setPassword('')
      setConfirm('')
      toast(creating ? 'Vault created' : 'Vault unlocked')
    }
  }

  return (
    <div className="main vault-gate">
      <div className="vault-gate-card">
        <div className="vault-gate-icon">{creating ? <ShieldCheck size={26} /> : <Lock size={26} />}</div>
        <h2>{creating ? 'Create your vault' : 'Vault locked'}</h2>
        <p className="faint">
          {creating
            ? 'Pick a master password. It encrypts everything in the vault and is never stored — if you lose it, the contents cannot be recovered.'
            : 'Enter your master password to decrypt the vault for this session.'}
        </p>

        <div className="row" style={{ gap: 6, marginTop: 4 }}>
          <input
            className="input"
            type={show ? 'text' : 'password'}
            autoFocus
            style={{ flex: 1 }}
            placeholder={creating ? 'Master password (min 8 characters)' : 'Master password'}
            value={password}
            onChange={(e) => {
              clearError()
              setPassword(e.target.value)
            }}
            onKeyDown={(e) => e.key === 'Enter' && void submit()}
          />
          <button className="icon-btn" title={show ? 'Hide' : 'Show'} onClick={() => setShow((v) => !v)}>
            {show ? <EyeOff size={16} /> : <Eye size={16} />}
          </button>
        </div>

        {creating && (
          <input
            className="input"
            type={show ? 'text' : 'password'}
            style={{ width: '100%', marginTop: 6 }}
            placeholder="Confirm master password"
            value={confirm}
            onChange={(e) => setConfirm(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && void submit()}
          />
        )}

        {mismatch && <div className="vault-error">Passwords do not match.</div>}
        {error && <div className="vault-error">{error}</div>}

        <button
          className="btn primary"
          style={{ width: '100%', marginTop: 10, justifyContent: 'center' }}
          disabled={!canSubmit || busy}
          onClick={() => void submit()}
        >
          {creating ? <ShieldCheck size={15} /> : <Unlock size={15} />}
          {creating ? 'Create vault' : 'Unlock'}
        </button>
      </div>
    </div>
  )
}

function VaultBrowser(): React.JSX.Element {
  const entries = useVault((s) => s.entries)
  const selectedId = useVault((s) => s.selectedId)
  const lock = useVault((s) => s.lock)
  const addEntry = useVault((s) => s.addEntry)
  const error = useVault((s) => s.error)
  const [changing, setChanging] = useState(false)

  const entry = entries.find((e) => e.id === selectedId) ?? null

  return (
    <div className="main">
      <div className="viewbar">
        <KeyRound size={14} style={{ color: 'var(--accent)' }} />
        <b>Vault</b>
        <span className="server-meta">{entries.length} entries</span>
        <span className="spacer" />
        <button className="btn sm" onClick={() => setChanging((v) => !v)}>
          Change password
        </button>
        <button className="btn sm" onClick={() => void addEntry()}>
          <Plus size={13} /> New entry
        </button>
        <button className="btn sm" onClick={() => void lock()}>
          <Lock size={13} /> Lock
        </button>
      </div>

      {error && <div className="vault-error" style={{ margin: 12 }}>{error}</div>}
      {changing && <ChangePassword onDone={() => setChanging(false)} />}

      {entry ? (
        <EntryEditor entry={entry} />
      ) : (
        <div className="faint" style={{ padding: 24, fontSize: 13 }}>
          Select an entry, or create one with <b>New entry</b>.
        </div>
      )}
    </div>
  )
}

function ChangePassword({ onDone }: { onDone: () => void }): React.JSX.Element {
  const changePassword = useVault((s) => s.changePassword)
  const busy = useVault((s) => s.busy)
  const [current, setCurrent] = useState('')
  const [next, setNext] = useState('')

  return (
    <div className="vault-panel">
      <div className="row" style={{ gap: 6 }}>
        <input
          className="input"
          type="password"
          placeholder="Current password"
          value={current}
          onChange={(e) => setCurrent(e.target.value)}
        />
        <input
          className="input"
          type="password"
          placeholder="New password (min 8)"
          value={next}
          onChange={(e) => setNext(e.target.value)}
        />
        <button
          className="btn primary sm"
          disabled={busy || !current || next.length < 8}
          onClick={async () => {
            if (await changePassword(current, next)) {
              toast('Master password changed')
              onDone()
            }
          }}
        >
          Save
        </button>
        <button className="btn sm" onClick={onDone}>
          Cancel
        </button>
      </div>
    </div>
  )
}

function EntryEditor({ entry }: { entry: VaultEntry }): React.JSX.Element {
  const update = useVault((s) => s.updateEntry)
  const remove = useVault((s) => s.deleteEntry)
  const [revealed, setRevealed] = useState<Record<string, boolean>>({})

  const set = (patch: Partial<VaultEntry>): void => void update(entry.id, patch)
  const toggle = (id: string): void => setRevealed((r) => ({ ...r, [id]: !r[id] }))

  const setField = (id: string, patch: Partial<(typeof entry.fields)[number]>): void =>
    set({ fields: entry.fields.map((f) => (f.id === id ? { ...f, ...patch } : f)) })

  return (
    <div className="vault-editor">
      <div className="row" style={{ gap: 8 }}>
        <input
          className="input"
          style={{ flex: 1, fontWeight: 600 }}
          value={entry.name}
          placeholder="Entry name"
          onChange={(e) => set({ name: e.target.value })}
        />
        <select className="input" value={entry.kind} onChange={(e) => set({ kind: e.target.value as VaultKind })}>
          {KINDS.map((k) => (
            <option key={k} value={k}>
              {VAULT_KIND_LABEL[k]}
            </option>
          ))}
        </select>
        <button
          className="btn sm danger"
          onClick={() => {
            remove(entry.id)
            toast(`${entry.name} deleted`)
          }}
        >
          <Trash2 size={13} />
        </button>
      </div>

      <Row label="URL" value={entry.url} onChange={(v) => set({ url: v })} placeholder="https://…" />
      <Row label="Username" value={entry.username} onChange={(v) => set({ username: v })} />
      <Row
        label="Password"
        value={entry.password}
        onChange={(v) => set({ password: v })}
        secret
        revealed={!!revealed.__pw}
        onReveal={() => toggle('__pw')}
      />
      <Row
        label="Tags"
        value={entry.tags.join(', ')}
        onChange={(v) => set({ tags: v.split(',').map((t) => t.trim()).filter(Boolean) })}
        placeholder="prod, aws"
      />

      <div className="vault-section-title">
        Custom fields
        <button className="btn sm" onClick={() => set({ fields: [...entry.fields, newField()] })}>
          <Plus size={13} /> Add field
        </button>
      </div>

      {entry.fields.map((f) => (
        <div className="row" key={f.id} style={{ gap: 6 }}>
          <input
            className="input"
            style={{ width: 170 }}
            placeholder="key"
            value={f.key}
            onChange={(e) => setField(f.id, { key: e.target.value })}
          />
          <input
            className="input"
            style={{ flex: 1 }}
            placeholder="value"
            type={f.secret && !revealed[f.id] ? 'password' : 'text'}
            value={f.value}
            onChange={(e) => setField(f.id, { value: e.target.value })}
          />
          <button
            className="icon-btn sm"
            title={f.secret ? 'Marked secret' : 'Mark as secret'}
            onClick={() => setField(f.id, { secret: !f.secret })}
          >
            {f.secret ? <Lock size={14} /> : <Unlock size={14} />}
          </button>
          {f.secret && (
            <button className="icon-btn sm" title="Reveal" onClick={() => toggle(f.id)}>
              {revealed[f.id] ? <EyeOff size={14} /> : <Eye size={14} />}
            </button>
          )}
          <button className="icon-btn sm" title="Copy value" onClick={() => copy(f.key || 'Value', f.value)}>
            <Copy size={14} />
          </button>
          <button
            className="icon-btn sm"
            title="Remove field"
            onClick={() => set({ fields: entry.fields.filter((x) => x.id !== f.id) })}
          >
            <Trash2 size={14} />
          </button>
        </div>
      ))}

      <div className="vault-section-title">Notes</div>
      <textarea
        className="textarea"
        style={{ width: '100%', minHeight: 90 }}
        value={entry.notes}
        spellCheck={false}
        onChange={(e) => set({ notes: e.target.value })}
      />

      <div className="faint" style={{ fontSize: 11 }}>
        Updated {new Date(entry.updatedAt).toLocaleString()}
      </div>
    </div>
  )
}

function Row({
  label,
  value,
  onChange,
  placeholder,
  secret,
  revealed,
  onReveal
}: {
  label: string
  value: string
  onChange: (v: string) => void
  placeholder?: string
  secret?: boolean
  revealed?: boolean
  onReveal?: () => void
}): React.JSX.Element {
  return (
    <div className="row" style={{ gap: 6 }}>
      <span className="vault-label">{label}</span>
      <input
        className="input"
        style={{ flex: 1 }}
        type={secret && !revealed ? 'password' : 'text'}
        placeholder={placeholder}
        value={value}
        onChange={(e) => onChange(e.target.value)}
      />
      {secret && (
        <button className="icon-btn sm" title="Reveal" onClick={onReveal}>
          {revealed ? <EyeOff size={14} /> : <Eye size={14} />}
        </button>
      )}
      <button className="icon-btn sm" title={`Copy ${label.toLowerCase()}`} onClick={() => copy(label, value)}>
        <Copy size={14} />
      </button>
    </div>
  )
}
