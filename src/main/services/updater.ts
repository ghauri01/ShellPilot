import { app, shell } from 'electron'
import { autoUpdater } from 'electron-updater'
import type { UpdaterStatus } from '../../shared/updater'

// electron-builder's `publish: provider: github` config (electron-builder.yml)
// bakes an app-update.yml into the packaged resources at build time, which is
// all electron-updater needs to know where to check — nothing to configure
// here beyond the event wiring below.

const RELEASES_URL = 'https://github.com/ghauri01/ShellPilot/releases/latest'

// Windows (NSIS) and Linux (AppImage) builds can safely self-replace with
// electron-updater's default flow. macOS cannot: there is no Apple Developer
// ID here, only an ad-hoc signature (see electron-builder.yml's `mac.identity`
// comment) — Squirrel.Mac's apply step needs a real signature to trust a
// silent replace, so on macOS this only ever checks and points at the
// release page for a manual download, the same experience a signed app's
// updater falls back to anyway if a signature check fails.
const CAN_AUTO_INSTALL = process.platform !== 'darwin'

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

autoUpdater.autoDownload = false
autoUpdater.autoInstallOnAppQuit = false

autoUpdater.on('checking-for-update', () => setStatus({ state: 'checking' }))
autoUpdater.on('update-not-available', () => setStatus({ state: 'not-available' }))
autoUpdater.on('error', (err) => setStatus({ state: 'error', message: err.message }))
autoUpdater.on('download-progress', (p) => setStatus({ state: 'downloading', percent: Math.round(p.percent) }))
autoUpdater.on('update-downloaded', (info) => setStatus({ state: 'downloaded', version: info.version }))
autoUpdater.on('update-available', (info) => {
  if (CAN_AUTO_INSTALL) {
    setStatus({ state: 'available', version: info.version })
    void autoUpdater.downloadUpdate()
  } else {
    setStatus({ state: 'manual', version: info.version })
  }
})

// No-op in dev: there is no packaged app-update.yml to read outside a real
// build, and checking would only ever fail with a confusing error.
export async function checkForUpdates(): Promise<void> {
  if (!app.isPackaged) {
    setStatus({ state: 'not-available' })
    return
  }
  try {
    await autoUpdater.checkForUpdates()
  } catch (err) {
    setStatus({ state: 'error', message: err instanceof Error ? err.message : String(err) })
  }
}

// Only meaningful once state is 'downloaded', and only on Windows/Linux —
// the renderer gates the button on both, this is the belt-and-braces backend
// check for anything that calls it regardless.
export function installUpdate(): void {
  if (!CAN_AUTO_INSTALL) return
  autoUpdater.quitAndInstall()
}

export function openReleasePage(): void {
  void shell.openExternal(RELEASES_URL)
}
