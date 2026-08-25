import { useEffect, useState } from 'react'
import { Modal } from '../common/Modal'
import type { CliPairingRequest } from '../../../../shared/mcp'

// Mounted once at the app root, like ApprovalWatcher: the `shellpilot
// claude|codex|run` CLI launcher can pair from any tab the user happens to
// be on. The code shown here is never sent back over the wire to whichever
// local process asked for it — only display it and let the user type it into
// their own terminal proves they can see both.
export function CliPairingBanner(): React.JSX.Element | null {
  const [request, setRequest] = useState<CliPairingRequest | null>(null)
  const [secondsLeft, setSecondsLeft] = useState(0)

  useEffect(() => {
    const off = window.shellpilot?.aiMcp.onPairingEvent((e) => {
      if (e.type === 'created') setRequest(e.request)
      else setRequest((r) => (r && r.id === e.request.id ? null : r))
    })
    return () => off?.()
  }, [])

  useEffect(() => {
    if (!request) return
    const tick = (): void =>
      setSecondsLeft(Math.max(0, Math.round((new Date(request.expiresAt).getTime() - Date.now()) / 1000)))
    tick()
    const t = setInterval(tick, 500)
    return () => clearInterval(t)
  }, [request])

  if (!request) return null

  const cancel = async (): Promise<void> => {
    await window.shellpilot?.aiMcp.cancelPairing(request.id)
    setRequest(null)
  }

  return (
    <Modal title="A CLI wants to connect" onClose={cancel}>
      <div className="setting-row">
        <div className="s-info">
          <div className="s-title">Agent</div>
          <div className="s-desc">{request.agentName}</div>
        </div>
      </div>
      <div className="setting-row">
        <div className="s-info">
          <div className="s-title">Type this code into the terminal that asked for it</div>
          <div className="s-title mono" style={{ fontSize: 28, letterSpacing: 6, marginTop: 6 }}>
            {request.code}
          </div>
          <div className="s-desc" style={{ marginTop: 6 }}>
            Expires in {secondsLeft}s. If you did not run a ShellPilot CLI command, click Cancel.
          </div>
        </div>
      </div>
      <div className="setting-row" style={{ marginTop: 12 }}>
        <button className="btn danger" onClick={cancel}>
          Cancel
        </button>
      </div>
    </Modal>
  )
}
