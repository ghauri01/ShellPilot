import { useState } from 'react'
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

  const [password, setPassword] = useState('')
  const [show, setShow] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)

  const ws = workspaces.find((w) => w.id === pendingId)
  if (!pendingId || !ws) return null

  const close = (): void => {
    setPassword('')
    setError(null)
    cancel()
  }

  const submit = async (): Promise<void> => {
    if (!password || busy) return
    setBusy(true)
    const ok = await window.shellpilot?.workspaceLock.verify(pendingId, password)
    setBusy(false)
    if (!ok) {
      setError('Incorrect password.')
      setPassword('')
      return
    }
    unlockWorkspace(pendingId)
    setPassword('')
    setError(null)
    toast(`${ws.name} unlocked`)
  }

  return (
    <Modal
      title={`${ws.name} is locked`}
      subtitle="Enter the workspace password to open it"
      onClose={close}
    >
      <div className="card" style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
        <div className="row" style={{ gap: 8 }}>
          <Lock size={18} className="faint" />
          <span className="muted" style={{ fontSize: 12 }}>
            This workspace is password protected.
          </span>
        </div>
        <div className="row" style={{ gap: 6 }}>
          <input
            className="input grow"
            type={show ? 'text' : 'password'}
            autoFocus
            placeholder="Workspace password"
            value={password}
            onChange={(e) => {
              setError(null)
              setPassword(e.target.value)
            }}
            onKeyDown={(e) => e.key === 'Enter' && void submit()}
          />
          <button className="icon-btn" title={show ? 'Hide' : 'Show'} onClick={() => setShow((v) => !v)}>
            {show ? <EyeOff size={16} /> : <Eye size={16} />}
          </button>
        </div>
        {error && <div className="vault-error">{error}</div>}
        <div className="row" style={{ gap: 8 }}>
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
