import { useRef, useState } from 'react'
import { Eye, EyeOff, Lock, Unlock } from 'lucide-react'
import { Modal } from '../common/Modal'
import { useApp } from '../../store/app'
import { toast } from '../../store/toast'

// Shown whenever something tries to activate a password-protected workspace
// that has not been unlocked yet this session.
export function WorkspaceUnlock(): React.JSX.Element | null {
  const pendingId = useApp((s) => s.pendingWorkspaceId)
  const workspaces = useApp((s) => s.workspaces)
  const unlockWorkspace = useApp((s) => s.unlockWorkspace)
  const cancel = useApp((s) => s.cancelWorkspaceUnlock)
  const setModal = useApp((s) => s.setModal)

  const [password, setPassword] = useState('')
  const [show, setShow] = useState(false)
  const [failed, setFailed] = useState(false)
  const [busy, setBusy] = useState(false)
  const passwordRef = useRef<HTMLInputElement>(null)

  const ws = workspaces.find((w) => w.id === pendingId)
  if (!pendingId || !ws) return null

  const close = (): void => {
    setPassword('')
    setFailed(false)
    cancel()
  }

  // The one destination that can actually do something about a workspace
  // password — change it, remove it, or delete the workspace. Offered only
  // after an attempt has failed, because until then the field is the answer.
  const manage = (): void => {
    close()
    setModal('workspaces')
  }

  const submit = async (): Promise<void> => {
    if (!password || busy) return
    setBusy(true)
    const ok = await window.shellpilot?.workspaceLock.verify(pendingId, password)
    setBusy(false)
    if (!ok) {
      setFailed(true)
      // Keep the attempt in the field and selected: the next keystroke
      // replaces it, and the cursor never leaves the only place this is fixed.
      passwordRef.current?.select()
      passwordRef.current?.focus()
      return
    }
    unlockWorkspace(pendingId)
    setPassword('')
    setFailed(false)
    toast(`${ws.name} unlocked`)
  }

  return (
    <Modal
      title={`${ws.name} is locked`}
      subtitle="Enter the workspace password to open it"
      onClose={close}
    >
      <div className="card" style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
        <div className="row" style={{ gap: 8, alignItems: 'flex-start' }}>
          <Lock size={18} className="faint" style={{ marginTop: 2, flexShrink: 0 }} />
          <span className="muted" style={{ fontSize: 12 }}>
            Someone set a password on this workspace, so its servers, databases and tunnels stay out
            of sight until it is entered. Your other workspaces are unaffected.
          </span>
        </div>
        <div className="row" style={{ gap: 6 }}>
          <input
            className="input grow"
            ref={passwordRef}
            type={show ? 'text' : 'password'}
            autoFocus
            placeholder="Workspace password"
            value={password}
            onChange={(e) => {
              setFailed(false)
              setPassword(e.target.value)
            }}
            onKeyDown={(e) => e.key === 'Enter' && void submit()}
          />
          <button className="icon-btn" title={show ? 'Hide' : 'Show'} onClick={() => setShow((v) => !v)}>
            {show ? <EyeOff size={16} /> : <Eye size={16} />}
          </button>
        </div>
        {failed && (
          <>
            <div className="vault-error">That is not the password for {ws.name}.</div>
            {/* No reset exists, so say so rather than let someone hunt for one —
                and name the confusion this trips over most often. */}
            <span className="muted" style={{ fontSize: 12 }}>
              Workspace passwords are case sensitive, and this is not your vault master password.
              Nothing here can reset one: to change or remove it, or to delete the workspace
              entirely, open Manage Workspaces.
            </span>
          </>
        )}
        <div className="row" style={{ gap: 8 }}>
          {failed && (
            <button className="btn sm" onClick={manage}>
              Manage workspaces
            </button>
          )}
          <span className="spacer" />
          <button className="btn sm" onClick={close}>
            Cancel
          </button>
          <button className="btn primary sm" disabled={!password || busy} onClick={() => void submit()}>
            <Unlock size={14} /> Unlock
          </button>
        </div>
      </div>
    </Modal>
  )
}
