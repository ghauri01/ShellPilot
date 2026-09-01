import { app, shell } from 'electron'
// electron-updater is CommonJS, and it is externalized rather than bundled
// (external deps resolve through real Node ESM/CJS interop, not esbuild's
// bundle-time shim) — Node's cjs-module-lexer cannot statically see
// `autoUpdater` as a named export of this particular module, even though the
// package itself does expose it. The default-import form sidesteps that
// entirely; see electron-updater's own docs for this exact caveat.
import electronUpdater from 'electron-updater'
import { isPortable } from '../portable'
import { channelOfVersion } from '../../shared/updater'
import type { UpdatePrefs, UpdaterCapabilities, UpdaterStatus } from '../../shared/updater'
import { channelConfig } from './updaterChannel'
import { getUpdatePrefs, setUpdatePrefs } from './updatePrefs'

const { autoUpdater } = electronUpdater

// electron-builder's `publish: provider: github` config (electron-builder.yml)
// bakes an app-update.yml into the packaged resources at build time, which is
// all electron-updater needs to know where to check — nothing to configure
// here beyond the event wiring below.

const RELEASES_URL = 'https://github.com/ghauri01/ShellPilot/releases/latest'

// Windows (NSIS) and Linux (AppImage) builds can safely self-replace with
// electron-updater's default flow. Two builds cannot.
//
// macOS: there is no Apple Developer ID here, only an ad-hoc signature (see
// electron-builder.yml's `mac.identity` comment) — Squirrel.Mac's apply step
// needs a real signature to trust a silent replace. A certificate alone would
// not be enough either: Squirrel.Mac downloads a zip, and MacUpdater.js picks
// its artifact with findFile(files, "zip", ["pkg", "dmg"]), while `mac.target`
// here is dmg-only. Shipping mac auto-update means a certificate AND a zip
// target, not just the certificate.
//
// Windows portable: the .exe unpacks itself to a temp dir and runs from there,
// and electron-updater has no story for replacing an executable that is
// currently running out of its own extraction. PORTABLE_EXECUTABLE_DIR is how
// that target announces itself, which is what src/main/portable.ts keys off.
//
// Both cases still check and then point at the release page for a manual
// download — the same experience a signed app's updater falls back to anyway
// when a signature check fails.
const CAN_AUTO_INSTALL = process.platform !== 'darwin' && !isPortable

let status: UpdaterStatus = { state: 'idle' }
const listeners = new Set<(s: UpdaterStatus) => void>()

function setStatus(next: UpdaterStatus): void {
  status = next
  for (const cb of listeners) cb(next)
}

export function getUpdaterStatus(): UpdaterStatus {
  return status
}

export function onUpdaterStatus(cb: (s: UpdaterStatus) => void): () => void {
  listeners.add(cb)
  return () => listeners.delete(cb)
}

export function getCapabilities(): UpdaterCapabilities {
  const currentVersion = app.getVersion()
  return {
    canAutoInstall: CAN_AUTO_INSTALL,
    isPortable,
    platform: process.platform,
    currentVersion,
    runningChannel: channelOfVersion(currentVersion)
  }
}

// Without this, electron-updater silently no-ops checkForUpdates() whenever
// !app.isPackaged — logging a warning and resolving as if nothing were wrong,
// which from the UI looked identical to "you're already up to date" no
// matter what was actually published. dev-app-update.yml (repo root) mirrors
// electron-builder.yml's publish config so `npm run dev` exercises the exact
// same GitHub-releases check a packaged build does, not a stub.
if (!app.isPackaged) autoUpdater.forceDevUpdateConfig = true

// Push the current prefs into autoUpdater. Called before every check rather
// than only on change, because electron-updater keeps this state on a
// long-lived singleton and there is no way to ask it what it currently
// believes — cheap to re-assert, expensive to get wrong.
function applyPrefs(prefs: UpdatePrefs): void {
  autoUpdater.autoDownload = prefs.autoDownload && CAN_AUTO_INSTALL
  // A platform that cannot self-install has nothing to install on quit, and
  // letting electron-updater try would mean a quit that hangs on a replace it
  // can never complete.
  autoUpdater.autoInstallOnAppQuit = prefs.autoInstallOnQuit && CAN_AUTO_INSTALL

  const cfg = channelConfig(prefs.channel)
  autoUpdater.allowPrerelease = cfg.allowPrerelease
  // Only assign a real channel name. Setting `channel` to null or '' throws
  // ERR_UPDATER_INVALID_CHANNEL, so the stable channel is expressed by leaving
  // the setter alone entirely and letting /releases/latest do the work.
  if (cfg.channel !== null) autoUpdater.channel = cfg.channel
  // Last, and explicitly, because the `channel` setter above force-sets
  // allowDowngrade = true as a side effect (AppUpdater.js:44). Assigning it
  // before the channel — or not at all — leaves a stable-channel user
  // silently able to downgrade.
  autoUpdater.allowDowngrade = cfg.allowDowngrade
}

// Safe defaults for the window between module load and the first applyPrefs:
// nothing downloads or installs itself until the stored prefs have actually
// said so.
autoUpdater.autoDownload = false
autoUpdater.autoInstallOnAppQuit = false

autoUpdater.on('checking-for-update', () => setStatus({ state: 'checking' }))
autoUpdater.on('update-not-available', () => setStatus({ state: 'not-available' }))
autoUpdater.on('error', (err) => setStatus({ state: 'error', message: err.message }))
autoUpdater.on('download-progress', (p) => setStatus({ state: 'downloading', percent: Math.round(p.percent) }))
autoUpdater.on('update-downloaded', (info) =>
  setStatus({ state: 'downloaded', version: info.version, channel: channelOfVersion(info.version) })
)
autoUpdater.on('update-available', (info) => {
  const channel = channelOfVersion(info.version)
  if (!CAN_AUTO_INSTALL) {
    setStatus({ state: 'manual', version: info.version, channel })
    return
  }
  setStatus({ state: 'available', version: info.version, channel })
  // Started here rather than left to autoUpdater.autoDownload, so the renderer
  // always sees 'available' before 'downloading' — the framework kicks its own
  // auto-download off after this emit returns, and a user watching the status
  // bar should see what was found before it starts pulling it. Calling it
  // twice is harmless: downloadUpdate() hands back the in-flight promise when
  // one already exists (AppUpdater.js:442).
  if (getUpdatePrefs().autoDownload) void autoUpdater.downloadUpdate()
})

export async function checkForUpdates(): Promise<void> {
  applyPrefs(getUpdatePrefs())
  try {
    await autoUpdater.checkForUpdates()
  } catch (err) {
    setStatus({ state: 'error', message: err instanceof Error ? err.message : String(err) })
  } finally {
    // Stamped on failure too. The UI's "last checked" line answers "is this
    // thing running at all", and a network blip that left the timestamp at its
    // old value read as a broken updater rather than a failed check.
    setUpdatePrefs({ lastCheckedAt: new Date().toISOString() })
  }
}

// Only reachable with autoDownload off: the user was shown 'available' and
// pressed Download. Errors surface through the 'error' event that
// electron-updater emits, same as an auto-started download.
export async function downloadUpdate(): Promise<void> {
  if (!CAN_AUTO_INSTALL) return
  try {
    await autoUpdater.downloadUpdate()
  } catch (err) {
    setStatus({ state: 'error', message: err instanceof Error ? err.message : String(err) })
  }
}

let timer: NodeJS.Timeout | null = null

// Re-entrant on purpose: a prefs change calls this again to pick up a new
// interval, and without clearing first each change would leave its old timer
// running, so the app would end up checking on every interval it had ever been
// set to.
export function startAutoCheck(): void {
  if (timer) {
    clearInterval(timer)
    timer = null
  }
  const prefs = getUpdatePrefs()
  if (!prefs.autoCheck) return
  void checkForUpdates()
  if (prefs.checkIntervalHours > 0) {
    timer = setInterval(() => void checkForUpdates(), prefs.checkIntervalHours * 60 * 60 * 1000)
    // A pending timer is a reason for Node to stay alive. On Linux, where
    // closing the last window quits, an armed 24-hour interval would otherwise
    // be the one handle keeping a windowless process from exiting.
    timer.unref()
  }
}

export function getPrefs(): UpdatePrefs {
  return getUpdatePrefs()
}

export function setPrefs(patch: Partial<UpdatePrefs>): UpdatePrefs {
  const before = getUpdatePrefs()
  const next = setUpdatePrefs(patch)
  applyPrefs(next)
  // Both of these change what the *next* check does, so neither is visible
  // until one happens. Switching channel is the case users notice: they pick
  // beta expecting to be offered a beta, and waiting up to six hours to find
  // out looks like the setting did nothing.
  if (next.channel !== before.channel) void checkForUpdates()
  else if (next.autoCheck !== before.autoCheck || next.checkIntervalHours !== before.checkIntervalHours) {
    startAutoCheck()
  }
  return next
}

// Only meaningful once state is 'downloaded', and only where the platform can
// self-install — the renderer gates the button on both, this is the
// belt-and-braces backend check for anything that calls it regardless.
export function installUpdate(): void {
  if (!CAN_AUTO_INSTALL) return
  autoUpdater.quitAndInstall()
}

export function openReleasePage(): void {
  void shell.openExternal(RELEASES_URL)
}
