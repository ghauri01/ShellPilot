import { useEffect, useState } from 'react'
import { Eye, EyeOff, Fingerprint, Lock } from 'lucide-react'
import { Modal } from '../common/Modal'
import { useVault } from '../../store/vault'
import { useVaultPrompt } from '../../store/vaultPrompt'

const BIO_LABEL: Record<string, string> = {
  'touch-id': 'Touch ID',
  'windows-hello': 'Windows Hello'
}

// Mounted once at the app root. Something needed a vault credential and the
// vault was locked — so ask, here, and let the caller carry on, instead of
// failing with instructions the user has to go and follow somewhere else
// before starting over.
export function VaultUnlockModal(): React.JSX.Element | null {
  const open = useVaultPrompt((s) => s.open)
  const reason = useVaultPrompt((s) => s.reason)
  const finish = useVaultPrompt((s) => s.finish)

  const unlock = useVault((s) => s.unlock)
  const busy = useVault((s) => s.busy)
  const error = useVault((s) => s.error)
  const clearError = useVault((s) => s.clearError)
  const exists = useVault((s) => s.exists)
  const bioAvailable = useVault((s) => s.bioAvailable)
  const bioEnabled = useVault((s) => s.bioEnabled)
  const bioKind = useVault((s) => s.bioKind)
  const refreshBiometrics = useVault((s) => s.refreshBiometrics)
  const unlockWithBiometrics = useVault((s) => s.unlockWithBiometrics)

  const [password, setPassword] = useState('')
  const [show, setShow] = useState(false)
  const canUseBio = bioAvailable && bioEnabled

  useEffect(() => {
    if (open) void refreshBiometrics()
  }, [open, refreshBiometrics])

  // Same as the main gate: go straight to the prompt rather than to a button
  // that opens a prompt.
  useEffect(() => {
    if (!open || !canUseBio) return
    void unlockWithBiometrics().then((ok) => ok && finish(true))
  }, [open, canUseBio, unlockWithBiometrics, finish])

  if (!open) return null

  const submit = async (): Promise<void> => {
    if (!password || busy) return
    if (await unlock(password)) {
      setPassword('')
      finish(true)
    }
  }

  return (
    <Modal
      title="Vault locked"
      subtitle={reason}
      onClose={() => {
        setPassword('')
        finish(false)
      }}
    >
      <div className="row" style={{ gap: 10, alignItems: 'flex-start', marginBottom: 12 }}>
        <Lock size={18} style={{ color: 'var(--accent)', marginTop: 2 }} />
        <div className="s-desc">
          {exists
            ? 'This credential is stored in your vault. Unlock it to continue — it stays unlocked for the rest of this session.'
            : 'There is no vault on this machine yet, so this credential cannot be read.'}
        </div>
      </div>

      {canUseBio && (
        <button
          className="btn primary"
          style={{ width: '100%', marginBottom: 10 }}
          disabled={busy}
          onClick={() => void unlockWithBiometrics().then((ok) => ok && finish(true))}
        >
          <Fingerprint size={15} /> Unlock with {BIO_LABEL[bioKind] ?? 'biometrics'}
        </button>
      )}

      <div className="row" style={{ gap: 6 }}>
        <input
          className="input"
          style={{ flex: 1 }}
          type={show ? 'text' : 'password'}
          autoFocus
          placeholder="Master password"
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

      {error && <div className="vault-error" style={{ marginTop: 8 }}>{error}</div>}

      <div className="row" style={{ gap: 8, marginTop: 14 }}>
        <button className="btn sm primary" disabled={!password || busy} onClick={() => void submit()}>
          Unlock and continue
        </button>
        <button
          className="btn sm"
          onClick={() => {
            setPassword('')
            finish(false)
          }}
        >
          Cancel
        </button>
      </div>
    </Modal>
  )
}
