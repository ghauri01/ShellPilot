import { useEffect, useState } from 'react'
import { RefreshCw, Download, CheckCircle2, ExternalLink, AlertTriangle, Loader2 } from 'lucide-react'
import type { UpdaterStatus } from '../../../../shared/updater'

export function UpdatePanel(): React.JSX.Element {
  const [version, setVersion] = useState<string | null>(null)
  const [status, setStatus] = useState<UpdaterStatus>({ state: 'idle' })

  useEffect(() => {
    void window.shellpilot?.getVersion().then(setVersion)
    void window.shellpilot?.updater.status().then(setStatus)
    const off = window.shellpilot?.updater.onStatus(setStatus)
    return () => off?.()
  }, [])

  const checking = status.state === 'checking'

  return (
    <div className="settings-section">
      <h2>About &amp; Updates</h2>
      <div className="setting-row">
        <div className="s-info">
          <div className="s-title">ShellPilot {version ? `v${version}` : ''}</div>
          <div className="s-desc">
            {status.state === 'idle' && 'Checks automatically on launch.'}
            {status.state === 'checking' && 'Checking for updates…'}
            {status.state === 'not-available' && "You're on the latest version."}
            {status.state === 'available' && `v${status.version} found — starting download…`}
            {status.state === 'downloading' && `Downloading update… ${status.percent}%`}
            {status.state === 'downloaded' && `v${status.version} is ready to install.`}
            {status.state === 'manual' && `v${status.version} is available.`}
            {status.state === 'error' && `Could not check for updates: ${status.message}`}
          </div>
        </div>
        <button className="btn sm" disabled={checking} onClick={() => void window.shellpilot?.updater.check()}>
          {checking ? <Loader2 size={13} className="spin" /> : <RefreshCw size={13} />}
          Check for updates
        </button>
      </div>

      {status.state === 'downloaded' && (
        <div className="backup-banner ok">
          <CheckCircle2 size={16} />
          <div style={{ flex: 1 }}>
            <div className="s-title">Update ready</div>
            <div className="s-desc">ShellPilot will restart to finish installing v{status.version}.</div>
          </div>
          <button className="btn sm primary" onClick={() => void window.shellpilot?.updater.install()}>
            Restart &amp; update
          </button>
        </div>
      )}

      {status.state === 'manual' && (
        <div className="backup-banner warn">
          <AlertTriangle size={16} />
          <div style={{ flex: 1 }}>
            <div className="s-title">v{status.version} is available</div>
            <div className="s-desc">
              macOS builds here are not notarized, so ShellPilot cannot safely replace itself
              automatically — download the new version and open it the same way as the first
              install.
            </div>
          </div>
          <button className="btn sm" onClick={() => void window.shellpilot?.updater.openReleasePage()}>
            <ExternalLink size={13} /> Download
          </button>
        </div>
      )}

      {status.state === 'error' && (
        <div className="backup-banner warn">
          <AlertTriangle size={16} />
          <div style={{ flex: 1 }}>
            <div className="s-title">Update check failed</div>
            <div className="s-desc">
              {status.message} — you can always grab the latest release directly.
            </div>
          </div>
          <button className="btn sm" onClick={() => void window.shellpilot?.updater.openReleasePage()}>
            <Download size={13} /> Releases page
          </button>
        </div>
      )}
    </div>
  )
}
