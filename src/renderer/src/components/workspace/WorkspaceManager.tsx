import { useState } from 'react'
import { EyeOff, Eye, Copy, Download, Trash2, Plus, Lock, LockOpen, Check } from 'lucide-react'
import { Modal } from '../common/Modal'
import { useApp } from '../../store/app'
import { toast } from '../../store/toast'
import { colorVar } from '../layout/WorkspaceSwitcher'
import { clsx } from '../../lib/format'
import type { WorkspaceColor } from '../../types'

const COLORS: WorkspaceColor[] = ['green', 'purple', 'blue', 'orange', 'red', 'cyan', 'pink']

export function WorkspaceManager(): React.JSX.Element {
  const setModal = useApp((s) => s.setModal)
  const workspaces = useApp((s) => s.workspaces)
  const toggleHidden = useApp((s) => s.toggleWorkspaceHidden)
  const addWorkspace = useApp((s) => s.addWorkspace)
  const setWorkspaceProtected = useApp((s) => s.setWorkspaceProtected)
  const lockWorkspace = useApp((s) => s.lockWorkspace)
  const unlockedWorkspaces = useApp((s) => s.unlockedWorkspaces)
  const deleteWorkspace = useApp((s) => s.deleteWorkspace)
  // Confirming a delete: holds the workspace id awaiting confirmation.
  const [confirming, setConfirming] = useState<string | null>(null)

  const [name, setName] = useState('')
  const [color, setColor] = useState<WorkspaceColor>('cyan')
  const [withPassword, setWithPassword] = useState(false)
  const [newPassword, setNewPassword] = useState('')
  // Workspace id whose password form is open.
  const [editing, setEditing] = useState<string | null>(null)

  const active = workspaces.filter((w) => !w.hidden)
  const hidden = workspaces.filter((w) => w.hidden)

  const create = async (): Promise<void> => {
    if (!name.trim()) return
    if (withPassword && newPassword.length < 6) {
      toast('Password must be at least 6 characters', 'error')
      return
    }
    const id = addWorkspace(name.trim(), color)
    if (withPassword) {
      const r = await window.shellpilot?.workspaceLock.set(id, newPassword)
      if (r?.ok) setWorkspaceProtected(id, true)
      else toast(r?.error ?? 'Could not set the password', 'error')
    }
    toast(`Workspace "${name.trim()}" created`, 'ok')
    setName('')
    setNewPassword('')
    setWithPassword(false)
  }

  const Row = ({
    id,
    wname,
    wcolor,
    isHidden,
    hasPassword
  }: {
    id: string
    wname: string
    wcolor: WorkspaceColor
    isHidden: boolean
    hasPassword: boolean
  }): React.JSX.Element => (
    <>
      <div className="list-row" style={{ padding: '10px 14px' }}>
        <span className="ws-dot" style={{ background: colorVar[wcolor], color: colorVar[wcolor] }} />
        <span className="r-title">{wname}</span>
        {hasPassword && (
          <span
            className="row"
            title={unlockedWorkspaces.includes(id) ? 'Protected — unlocked this session' : 'Protected — locked'}
          >
            <Lock size={13} className="faint" />
          </span>
        )}
        <span className="spacer" />
        {hasPassword && unlockedWorkspaces.includes(id) && (
          <button
            className="icon-btn sm"
            title="Lock now"
            onClick={() => {
              lockWorkspace(id)
              toast(`${wname} locked`)
            }}
          >
            <LockOpen size={14} />
          </button>
        )}
        <button
          className="icon-btn sm"
          title={hasPassword ? 'Change or remove password' : 'Set password'}
          onClick={() => setEditing(editing === id ? null : id)}
        >
          <Lock size={14} />
        </button>
        <button className="icon-btn sm" title="Duplicate" onClick={() => toast('Duplicated (mock)')}>
          <Copy size={14} />
        </button>
        <button className="icon-btn sm" title="Export" onClick={() => toast('Exported workspace.json')}>
          <Download size={14} />
        </button>
        <button
          className="icon-btn sm"
          title={isHidden ? 'Restore' : 'Hide'}
          onClick={() => {
            toggleHidden(id)
            toast(isHidden ? `${wname} restored` : `${wname} hidden`)
          }}
        >
          {isHidden ? <Eye size={14} /> : <EyeOff size={14} />}
        </button>
        <button
          className="icon-btn sm"
          title={workspaces.length <= 1 ? 'The last workspace cannot be deleted' : 'Delete'}
          disabled={workspaces.length <= 1}
          onClick={() => setConfirming(id)}
        >
          <Trash2 size={14} />
        </button>
      </div>
      {confirming === id && (
        <div className="vault-panel">
          <div className="row" style={{ gap: 8 }}>
            <span style={{ color: 'var(--danger)', fontSize: 12 }}>
              Delete <b>{wname}</b> and everything in it — servers, databases, tunnels and folders?
              This cannot be undone.
            </span>
            <span className="spacer" />
            <button className="btn sm" onClick={() => setConfirming(null)}>
              Cancel
            </button>
            <button
              className="btn sm danger"
              onClick={async () => {
                // Drop stored credentials for the servers and databases that
                // are about to disappear, so no orphan secrets are left.
                const doomed = [
                  ...useApp.getState().servers.filter((sv) => sv.workspaceId === id),
                  ...useApp.getState().databases.filter((d) => d.workspaceId === id)
                ]
                deleteWorkspace(id)
                await Promise.all(doomed.map((d) => window.shellpilot?.secrets.delete(d.id)))
                await window.shellpilot?.workspaceLock.delete(id)
                setConfirming(null)
                toast(`${wname} deleted`)
              }}
            >
              Delete workspace
            </button>
          </div>
        </div>
      )}
      {editing === id && (
        <PasswordForm
          id={id}
          wname={wname}
          hasPassword={hasPassword}
          onDone={() => setEditing(null)}
        />
      )}
    </>
  )

  return (
    <Modal
      title="Manage Workspaces"
      subtitle="Organize servers, credentials and settings into isolated spaces"
      onClose={() => setModal(null)}
      size="lg"
    >
      <div className="card" style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
        <div className="sidebar-title">New workspace</div>
        <div className="input-group">
          <input
            className="input grow"
            placeholder="Workspace name"
            value={name}
            onChange={(e) => setName(e.target.value)}
          />
          <button className="btn primary" onClick={() => void create()} disabled={!name.trim()}>
            <Plus size={14} /> Create
          </button>
        </div>
        <div className="row" style={{ gap: 8 }}>
          {COLORS.map((c) => (
            <button
              key={c}
              onClick={() => setColor(c)}
              className="row"
              style={{
                width: 24,
                height: 24,
                borderRadius: 6,
                background: colorVar[c],
                justifyContent: 'center',
                boxShadow: color === c ? '0 0 0 2px var(--bg-card), 0 0 0 4px var(--accent)' : undefined
              }}
            >
              {color === c && <Check size={13} color="#000" />}
            </button>
          ))}
          <span className="spacer" />
          <label className="row" style={{ gap: 8 }}>
            <span className="muted">Password protect</span>
            <span className={clsx('switch', withPassword && 'on')} onClick={() => setWithPassword((v) => !v)} />
          </label>
        </div>
        {withPassword && (
          <input
            className="input"
            type="password"
            placeholder="Workspace password (min 6 characters)"
            value={newPassword}
            onChange={(e) => setNewPassword(e.target.value)}
          />
        )}
      </div>

      <div>
        <div className="sidebar-title" style={{ margin: '4px 0 8px' }}>
          Active ({active.length})
        </div>
        {active.map((w) => (
          <Row key={w.id} id={w.id} wname={w.name} wcolor={w.color} isHidden={false} hasPassword={w.hasPassword} />
        ))}
      </div>

      {hidden.length > 0 && (
        <div>
          <div className="sidebar-title" style={{ margin: '4px 0 8px' }}>
            Hidden ({hidden.length})
          </div>
          {hidden.map((w) => (
            <Row key={w.id} id={w.id} wname={w.name} wcolor={w.color} isHidden hasPassword={w.hasPassword} />
          ))}
        </div>
      )}
    </Modal>
  )
}

function PasswordForm({
  id,
  wname,
  hasPassword,
  onDone
}: {
  id: string
  wname: string
  hasPassword: boolean
  onDone: () => void
}): React.JSX.Element {
  const setWorkspaceProtected = useApp((s) => s.setWorkspaceProtected)
  const [current, setCurrent] = useState('')
  const [next, setNext] = useState('')
  const [busy, setBusy] = useState(false)

  const save = async (): Promise<void> => {
    if (next.length < 6 || busy) return
    setBusy(true)
    const r = await window.shellpilot?.workspaceLock.set(id, next, current)
    setBusy(false)
    if (!r?.ok) {
      toast(r?.error ?? 'Could not set the password', 'error')
      return
    }
    setWorkspaceProtected(id, true)
    toast(hasPassword ? `Password changed for ${wname}` : `${wname} is now password protected`)
    onDone()
  }

  const clear = async (): Promise<void> => {
    setBusy(true)
    const r = await window.shellpilot?.workspaceLock.remove(id, current)
    setBusy(false)
    if (!r?.ok) {
      toast(r?.error ?? 'Could not remove the password', 'error')
      return
    }
    setWorkspaceProtected(id, false)
    toast(`Password removed from ${wname}`)
    onDone()
  }

  return (
    <div className="vault-panel" style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
      <div className="row" style={{ gap: 6 }}>
        {hasPassword && (
          <input
            className="input grow"
            type="password"
            placeholder="Current password"
            value={current}
            onChange={(e) => setCurrent(e.target.value)}
          />
        )}
        <input
          className="input grow"
          type="password"
          placeholder={hasPassword ? 'New password (min 6)' : 'Password (min 6)'}
          value={next}
          onChange={(e) => setNext(e.target.value)}
          onKeyDown={(e) => e.key === 'Enter' && void save()}
        />
        <button className="btn primary sm" disabled={busy || next.length < 6} onClick={() => void save()}>
          {hasPassword ? 'Change' : 'Set'}
        </button>
        {hasPassword && (
          <button className="btn sm danger" disabled={busy || !current} onClick={() => void clear()}>
            Remove
          </button>
        )}
        <button className="btn sm" onClick={onDone}>
          Cancel
        </button>
      </div>
      <div className="faint" style={{ fontSize: 11 }}>
        Gates access to this workspace in the app. It does not encrypt its servers on disk — use the
        Vault for secrets that must be encrypted at rest.
      </div>
    </div>
  )
}
