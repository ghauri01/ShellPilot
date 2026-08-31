import { useRef, useState } from 'react'
import { EyeOff, Eye, Trash2, Plus, Lock, LockOpen, Check } from 'lucide-react'
import { Modal } from '../common/Modal'
import { useApp } from '../../store/app'
import { toast } from '../../store/toast'
import { colorVar } from '../layout/WorkspaceSwitcher'
import { clsx } from '../../lib/format'
import type { WorkspaceColor } from '../../types'

const COLORS: WorkspaceColor[] = ['green', 'purple', 'blue', 'orange', 'red', 'cyan', 'pink']

// Matches what the main process enforces in wslock.ts. Kept in step so the
// form can refuse a short password itself instead of round-tripping to be told.
const MIN_WS_PASSWORD = 6

export function WorkspaceManager(): React.JSX.Element {
  const setModal = useApp((s) => s.setModal)
  const workspaces = useApp((s) => s.workspaces)
  const toggleHidden = useApp((s) => s.toggleWorkspaceHidden)
  const addWorkspace = useApp((s) => s.addWorkspace)
  const setWorkspaceProtected = useApp((s) => s.setWorkspaceProtected)
  const lockWorkspace = useApp((s) => s.lockWorkspace)
  const setWorkspace = useApp((s) => s.setWorkspace)
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

  // Checked by the form rather than announced afterwards: a rule the form can
  // enforce before the click is not an error, and an error toast for one is a
  // telling-off with nothing to act on.
  const passwordTooShort = withPassword && newPassword.length > 0 && newPassword.length < MIN_WS_PASSWORD
  const canCreate = name.trim().length > 0 && (!withPassword || newPassword.length >= MIN_WS_PASSWORD)

  const create = async (): Promise<void> => {
    const wname = name.trim()
    if (!canCreate) return
    const id = addWorkspace(wname, color)
    const clearForm = (): void => {
      setName('')
      setNewPassword('')
      setWithPassword(false)
    }
    if (withPassword) {
      const r = await window.shellpilot?.workspaceLock.set(id, newPassword)
      if (!r?.ok) {
        // The workspace itself was created, so "could not set the password"
        // alone would leave someone believing a workspace is protected when it
        // is wide open. Say what exists now, and open the form that finishes
        // the job.
        clearForm()
        toast(
          `"${wname}" was created, but without a password: ${r?.error ?? 'it could not be saved.'} Anyone using this app can open it.`,
          'error',
          { label: 'Set password', run: () => setEditing(id) }
        )
        return
      }
      setWorkspaceProtected(id, true)
    }
    clearForm()
    toast(`Workspace "${wname}" created`, 'ok')
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
            title={
              unlockedWorkspaces.includes(id)
                ? 'Password protected — open until you lock it or quit'
                : 'Password protected — asks for the password to open'
            }
          >
            <Lock size={13} className="faint" />
          </span>
        )}
        <span className="spacer" />
        {hasPassword &&
          (unlockedWorkspaces.includes(id) ? (
            <button
              className="icon-btn sm"
              title={`Lock ${wname} again now`}
              onClick={() => {
                lockWorkspace(id)
                toast(`${wname} locked`)
              }}
            >
              <LockOpen size={14} />
            </button>
          ) : (
            // Reporting "locked" and leaving it there is the whole complaint.
            // setWorkspace routes through the same gate as the switcher, so
            // this opens the unlock dialog — with the manager out of the way so
            // there is only one thing on screen asking for something.
            <button
              className="btn sm"
              title={`Enter the password for ${wname} and open it`}
              onClick={() => {
                setModal(null)
                setWorkspace(id)
              }}
            >
              <Lock size={13} /> Unlock
            </button>
          ))}
        <button
          className="icon-btn sm"
          title={hasPassword ? 'Change or remove password' : 'Set password'}
          onClick={() => setEditing(editing === id ? null : id)}
        >
          <Lock size={14} />
        </button>
        {/* No Duplicate or Export here: both only ever announced work that
            never happened ("Exported workspace.json"), and a message describing
            an imaginary file is worse than no button. Settings → Backup is the
            export that exists. */}
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
          <button
            className="btn primary"
            onClick={() => void create()}
            disabled={!canCreate}
            title={
              canCreate
                ? 'Create this workspace'
                : withPassword && name.trim()
                  ? `Enter a password of at least ${MIN_WS_PASSWORD} characters first`
                  : 'Give the workspace a name first'
            }
          >
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
          <>
            <input
              className="input"
              type="password"
              placeholder={`Workspace password (min ${MIN_WS_PASSWORD} characters)`}
              value={newPassword}
              onChange={(e) => setNewPassword(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && void create()}
            />
            {passwordTooShort && (
              <div className="s-desc" style={{ color: 'var(--danger)' }}>
                Use at least {MIN_WS_PASSWORD} characters.
              </div>
            )}
            <div className="faint" style={{ fontSize: 11 }}>
              Hides this workspace behind a password inside ShellPilot. It is not your vault master
              password, and it does not encrypt anything on disk.
            </div>
          </>
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
  // Shown in the form rather than thrown at the corner of the screen: every
  // failure here is "one of these two fields is wrong", and the fields are here.
  const [error, setError] = useState<string | null>(null)
  const currentRef = useRef<HTMLInputElement>(null)

  const canSave = !busy && next.length >= MIN_WS_PASSWORD && (!hasPassword || current.length > 0)

  // Only the current password can be wrong in a way the user can correct on the
  // spot, so that is where the cursor goes back to.
  const blame = (message: string): void => {
    setError(message)
    if (hasPassword) {
      currentRef.current?.select()
      currentRef.current?.focus()
    }
  }

  const save = async (): Promise<void> => {
    if (!canSave) return
    setBusy(true)
    const r = await window.shellpilot?.workspaceLock.set(id, next, current)
    setBusy(false)
    if (!r?.ok) {
      blame(r?.error ?? 'That password could not be saved. Try again.')
      return
    }
    setWorkspaceProtected(id, true)
    toast(hasPassword ? `Password changed for ${wname}` : `${wname} is now password protected`, 'ok')
    onDone()
  }

  const clear = async (): Promise<void> => {
    if (busy || !current) return
    setBusy(true)
    const r = await window.shellpilot?.workspaceLock.remove(id, current)
    setBusy(false)
    if (!r?.ok) {
      blame(r?.error ?? 'The password could not be removed. Try again.')
      return
    }
    setWorkspaceProtected(id, false)
    toast(`${wname} no longer asks for a password`, 'ok')
    onDone()
  }

  return (
    <div className="vault-panel" style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
      <div className="row" style={{ gap: 6 }}>
        {hasPassword && (
          <input
            className="input grow"
            ref={currentRef}
            type="password"
            autoFocus
            placeholder="Current password"
            value={current}
            onChange={(e) => {
              setError(null)
              setCurrent(e.target.value)
            }}
            onKeyDown={(e) => e.key === 'Enter' && void save()}
          />
        )}
        <input
          className="input grow"
          type="password"
          placeholder={
            hasPassword
              ? `New password (min ${MIN_WS_PASSWORD})`
              : `Password (min ${MIN_WS_PASSWORD})`
          }
          value={next}
          onChange={(e) => {
            setError(null)
            setNext(e.target.value)
          }}
          onKeyDown={(e) => e.key === 'Enter' && void save()}
        />
        <button
          className="btn primary sm"
          disabled={!canSave}
          title={
            canSave
              ? undefined
              : hasPassword && !current
                ? 'Enter the current password first'
                : `New password must be at least ${MIN_WS_PASSWORD} characters`
          }
          onClick={() => void save()}
        >
          {hasPassword ? 'Change' : 'Set'}
        </button>
        {hasPassword && (
          <button
            className="btn sm danger"
            disabled={busy || !current}
            title={current ? `Stop asking for a password on ${wname}` : 'Enter the current password first'}
            onClick={() => void clear()}
          >
            Remove
          </button>
        )}
        <button className="btn sm" onClick={onDone}>
          Cancel
        </button>
      </div>
      {error && <div className="vault-error">{error}</div>}
      <div className="faint" style={{ fontSize: 11 }}>
        This password hides the workspace inside ShellPilot. It does not encrypt anything on disk,
        and it is not your vault master password — for secrets that must be encrypted at rest, put
        them in the Vault in the left sidebar.
      </div>
    </div>
  )
}
