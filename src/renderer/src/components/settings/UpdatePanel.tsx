import { useState } from 'react'
import {
  RefreshCw,
  Download,
  CheckCircle2,
  ExternalLink,
  AlertTriangle,
  Loader2,
  BellOff
} from 'lucide-react'
import { useUpdater } from '../../store/updater'
import { Modal } from '../common/Modal'
import { clsx } from '../../lib/format'
import {
  channelOfVersion,
  type CheckIntervalHours,
  type UpdateChannel,
  type UpdaterCapabilities
} from '../../../../shared/updater'

// Marks an offered build as a prerelease. Being on the beta channel does not
// answer "what am I about to install": beta cascades, so the newest thing on
// offer there is often an ordinary stable release.
function OfferedTag({ version }: { version: string }): React.JSX.Element | null {
  return channelOfVersion(version) === 'beta' ? <span className="build-tag">beta</span> : null
}

// The same switch Settings uses. Duplicated rather than imported because that
// one is a private helper of a page this panel is only a guest on, and because
// this one has to be able to sit there disabled with a reason attached — a
// toggle the platform cannot honour has to look unavailable, not just fail
// silently when pressed.
function SettingSwitch({
  label,
  desc,
  checked,
  disabled,
  onChange
}: {
  label: string
  desc: string
  checked: boolean
  disabled?: boolean
  onChange: (v: boolean) => void
}): React.JSX.Element {
  return (
    <div className="setting-row">
      <div className="s-info">
        <div className="s-title">{label}</div>
        <div className="s-desc">{desc}</div>
      </div>
      <span
        className={clsx('switch', checked && !disabled && 'on', disabled && 'disabled')}
        onClick={() => !disabled && onChange(!checked)}
      />
    </div>
  )
}

// An age, not a wall-clock time: "12 minutes ago" answers "is this stale"
// without the user working out what time it is now. A clock that has moved
// backwards since the check would otherwise print a negative age, which reads
// as a bug, so anything in the future is simply "just now".
function checkedAgo(iso: string | null): string {
  if (!iso) return 'Not checked yet.'
  const at = Date.parse(iso)
  if (Number.isNaN(at)) return 'Not checked yet.'
  const mins = Math.floor(Math.max(0, Date.now() - at) / 60000)
  if (mins < 1) return 'Last checked just now.'
  if (mins < 60) return `Last checked ${mins} minute${mins === 1 ? '' : 's'} ago.`
  const hours = Math.floor(mins / 60)
  if (hours < 24) return `Last checked ${hours} hour${hours === 1 ? '' : 's'} ago.`
  const days = Math.floor(hours / 24)
  return `Last checked ${days} day${days === 1 ? '' : 's'} ago.`
}

// Why this build cannot replace itself. Taken from the capabilities the main
// process sent, never from anything the renderer can sniff for itself — the
// renderer has no business re-deriving a rule that decides whether an installer
// will run.
function noSelfInstallReason(caps: UpdaterCapabilities): string {
  if (caps.platform === 'darwin') {
    return 'macOS builds here are not notarized, so ShellPilot cannot safely replace itself automatically — download the new version and open it the same way as the first install.'
  }
  if (caps.isPortable) {
    return 'This is the portable build, which runs from wherever you put it — ShellPilot cannot replace its own executable, so download the new version and swap it in.'
  }
  return 'This build cannot install updates itself — download the new version from the releases page.'
}

export function UpdatePanel(): React.JSX.Element {
  const status = useUpdater((s) => s.status)
  const prefs = useUpdater((s) => s.prefs)
  const caps = useUpdater((s) => s.capabilities)
  const dismissedVersion = useUpdater((s) => s.dismissedVersion)
  const check = useUpdater((s) => s.check)
  const download = useUpdater((s) => s.download)
  const install = useUpdater((s) => s.install)
  const setPrefs = useUpdater((s) => s.setPrefs)
  const dismiss = useUpdater((s) => s.dismiss)
  const undismiss = useUpdater((s) => s.undismiss)

  // Two confirmations, both for things the user cannot take back on their own:
  // a restart that ends every open session, and a channel change that can move
  // the app down a version.
  const [confirmRestart, setConfirmRestart] = useState(false)
  const [confirmDowngrade, setConfirmDowngrade] = useState(false)

  const checking = status.state === 'checking'
  // Assume the app cannot install itself until told otherwise. Offering a
  // restart that silently does nothing is worse than the half-second the
  // capabilities call takes to arrive.
  const canAutoInstall = caps?.canAutoInstall ?? false

  const selectChannel = (channel: UpdateChannel): void => {
    if (channel === prefs.channel) return
    // Leaving beta while actually running a beta build means the next update is
    // very likely to be an older version than the one on screen. Nobody expects
    // an update to go backwards, so it gets said out loud first.
    if (channel === 'stable' && caps?.runningChannel === 'beta') {
      setConfirmDowngrade(true)
      return
    }
    setPrefs({ channel })
  }

  return (
    <div className="settings-section">
      <h2>About &amp; Updates</h2>
      <div className="setting-row">
        <div className="s-info">
          <div className="s-title">
            ShellPilot {caps ? `v${caps.currentVersion}` : ''}
            {caps?.runningChannel === 'beta' && <span className="build-tag">beta</span>}
          </div>
          <div className="s-desc">
            {status.state === 'idle' && checkedAgo(prefs.lastCheckedAt)}
            {status.state === 'checking' && 'Checking for updates…'}
            {status.state === 'not-available' && `You're on the latest version. ${checkedAgo(prefs.lastCheckedAt)}`}
            {status.state === 'available' &&
              (prefs.autoDownload ? `v${status.version} found — starting download…` : `v${status.version} is available.`)}
            {status.state === 'downloading' && `Downloading update… ${Math.round(status.percent)}%`}
            {status.state === 'downloaded' && `v${status.version} is ready to install.`}
            {status.state === 'manual' && `v${status.version} is available.`}
            {status.state === 'error' && `Could not check for updates: ${status.message}`}
          </div>
        </div>
        <div className="row" style={{ gap: 6 }}>
          {status.state === 'available' && !prefs.autoDownload && (
            <button className="btn sm primary" onClick={download}>
              <Download size={13} /> Download
            </button>
          )}
          <button className="btn sm" disabled={checking} onClick={check}>
            {checking ? <Loader2 size={13} className="spin" /> : <RefreshCw size={13} />}
            Check for updates
          </button>
        </div>
      </div>

      {status.state === 'downloaded' && (
        <div className="backup-banner ok">
          <CheckCircle2 size={16} />
          <div style={{ flex: 1 }}>
            <div className="s-title">
              Update ready <OfferedTag version={status.version} />
            </div>
            <div className="s-desc">
              {canAutoInstall
                ? `ShellPilot will restart to finish installing v${status.version}.`
                : `v${status.version} has been downloaded, but this build cannot install it itself.`}
            </div>
          </div>
          {canAutoInstall ? (
            <button className="btn sm primary" onClick={() => setConfirmRestart(true)}>
              Restart &amp; update
            </button>
          ) : (
            <button className="btn sm" onClick={() => void window.shellpilot?.updater.openReleasePage()}>
              <ExternalLink size={13} /> Releases page
            </button>
          )}
        </div>
      )}

      {status.state === 'manual' && caps && (
        <div className="backup-banner warn">
          <AlertTriangle size={16} />
          <div style={{ flex: 1 }}>
            <div className="s-title">
              v{status.version} is available <OfferedTag version={status.version} />
            </div>
            <div className="s-desc">{noSelfInstallReason(caps)}</div>
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
            <div className="s-desc">{status.message} — you can always grab the latest release directly.</div>
          </div>
          <button className="btn sm" onClick={() => void window.shellpilot?.updater.openReleasePage()}>
            <Download size={13} /> Releases page
          </button>
        </div>
      )}

      <div className="backup-h">Update channel</div>
      <div className="setting-row">
        <div className="s-info">
          <div className="s-title">Channel</div>
          <div className="s-desc">
            Stable is the released build. Beta gets new features earlier, and gets their bugs earlier
            too — it is the build that has not been through as many hands yet.
          </div>
        </div>
        <select
          className="input"
          style={{ maxWidth: 160 }}
          value={prefs.channel}
          onChange={(e) => selectChannel(e.target.value as UpdateChannel)}
        >
          <option value="stable">Stable</option>
          <option value="beta">Beta</option>
        </select>
      </div>

      <div className="backup-h">Automatic updates</div>
      <SettingSwitch
        label="Check for updates automatically"
        desc="Off means ShellPilot only looks when you press Check for updates."
        checked={prefs.autoCheck}
        onChange={(autoCheck) => setPrefs({ autoCheck })}
      />
      <div className="setting-row">
        <div className="s-info">
          <div className="s-title">How often to check</div>
          <div className="s-desc">
            Every check happens at launch as well. A longer interval only affects an app that stays
            open for days.
          </div>
        </div>
        <select
          className="input"
          style={{ maxWidth: 180 }}
          disabled={!prefs.autoCheck}
          value={prefs.checkIntervalHours}
          onChange={(e) =>
            setPrefs({ checkIntervalHours: Number(e.target.value) as CheckIntervalHours })
          }
        >
          <option value={0}>Only at launch</option>
          <option value={6}>Every 6 hours</option>
          <option value={24}>Every 24 hours</option>
        </select>
      </div>
      <SettingSwitch
        label="Download updates automatically"
        desc="Fetch the update in the background as soon as one is found. Off means you are told first and press Download yourself."
        checked={prefs.autoDownload}
        onChange={(autoDownload) => setPrefs({ autoDownload })}
      />
      <SettingSwitch
        label="Install on quit"
        desc={
          canAutoInstall
            ? 'Apply a downloaded update the next time you close ShellPilot, instead of waiting for you to restart it now.'
            : caps
              ? `Unavailable on this build. ${noSelfInstallReason(caps)}`
              : 'Unavailable until ShellPilot knows what this build can install.'
        }
        checked={prefs.autoInstallOnQuit}
        disabled={!canAutoInstall}
        onChange={(autoInstallOnQuit) => setPrefs({ autoInstallOnQuit })}
      />

      {dismissedVersion !== null ? (
        <div className="setting-row">
          <div className="s-info">
            <div className="s-title">Ignoring v{dismissedVersion}</div>
            <div className="s-desc">
              The status bar stays quiet about this version. A newer one brings the indicator back on
              its own.
            </div>
          </div>
          <button className="btn sm" onClick={undismiss}>
            Stop ignoring
          </button>
        </div>
      ) : (
        (status.state === 'available' || status.state === 'downloaded' || status.state === 'manual') && (
          <div className="setting-row">
            <div className="s-info">
              <div className="s-title">Not now</div>
              <div className="s-desc">
                Hide the status-bar indicator for v{status.version}. Updates stay on, and the next
                version will say so.
              </div>
            </div>
            <button className="btn sm" onClick={dismiss}>
              <BellOff size={13} /> Ignore this version
            </button>
          </div>
        )
      )}

      {confirmRestart && (
        <Modal
          title="Restart to finish updating?"
          subtitle="ShellPilot closes and reopens on the new version."
          onClose={() => setConfirmRestart(false)}
          footer={
            <>
              <span className="spacer" />
              <button className="btn" onClick={() => setConfirmRestart(false)}>
                Not now
              </button>
              <button className="btn primary" onClick={install}>
                Restart &amp; update
              </button>
            </>
          }
        >
          <p>
            Every open SSH session, tunnel and file transfer ends when the app closes. Anything
            running on a server keeps running there, but ShellPilot will not be watching it.
          </p>
        </Modal>
      )}

      {confirmDowngrade && (
        <Modal
          title="Switch to the stable channel?"
          subtitle={caps ? `You are running v${caps.currentVersion}, a beta build.` : undefined}
          onClose={() => setConfirmDowngrade(false)}
          footer={
            <>
              <span className="spacer" />
              <button className="btn" onClick={() => setConfirmDowngrade(false)}>
                Stay on beta
              </button>
              <button
                className="btn primary"
                onClick={() => {
                  setPrefs({ channel: 'stable' })
                  setConfirmDowngrade(false)
                }}
              >
                Switch to stable
              </button>
            </>
          }
        >
          <p>
            The newest stable release is probably older than the beta you are on. ShellPilot will
            offer it as an update and installing it moves this app <b>down</b> a version, taking the
            beta-only features with it.
          </p>
          <p>Nothing changes until you install that update, and you can switch back to beta first.</p>
        </Modal>
      )}
    </div>
  )
}
