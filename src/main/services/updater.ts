import { app, shell } from 'electron'
// electron-updater is CommonJS, and it is externalized rather than bundled
// (external deps resolve through real Node ESM/CJS interop, not esbuild's
// bundle-time shim) — Node's cjs-module-lexer cannot statically see
// `autoUpdater` as a named export of this particular module, even though the
// package itself does expose it. The default-import form sidesteps that
// entirely; see electron-updater's own docs for this exact caveat.
import electronUpdater from 'electron-updater'
import type { UpdaterStatus } from '../../shared/updater'

const { autoUpdater } = electronUpdater

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

// Without this, electron-updater silently no-ops checkForUpdates() whenever
// !app.isPackaged — logging a warning and resolving as if nothing were wrong,
// which from the UI looked identical to "you're already up to date" no
// matter what was actually published. dev-app-update.yml (repo root) mirrors
// electron-builder.yml's publish config so `npm run dev` exercises the exact
// same GitHub-releases check a packaged build does, not a stub.
if (!app.isPackaged) autoUpdater.forceDevUpdateConfig = true

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

export async function checkForUpdates(): Promise<void> {
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
