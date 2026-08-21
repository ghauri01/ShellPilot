// Must come first: redirects userData for portable builds before any
// service module resolves its file paths.
import './portable'
import { app, shell, BrowserWindow, ipcMain, nativeTheme, dialog, session, Menu, Notification } from 'electron'
import { join } from 'node:path'
import { readFileSync, existsSync } from 'node:fs'
import { readFile, writeFile } from 'node:fs/promises'
import {
  sshConnect,
  sshWrite,
  sshResize,
  sshClose,
  sshDisposeAll,
  setSshPrompter,
  setPoolIdle,
  poolList,
  poolClose
} from './services/ssh'
import type { KeyboardRequest } from './services/ssh'
import {
  sftpConnect,
  sftpList,
  sftpRead,
  sftpWrite,
  sftpMkdir,
  sftpRename,
  sftpDelete,
  sftpUpload,
  sftpDisconnect,
  sftpDisposeAll
} from './services/sftp'
import { metricsSample, metricsDisconnect, metricsDisposeAll } from './services/metrics'
import { dbTest, dbQuery, dbInfo, dbClose, dbDisposeAll } from './services/db'
import { dbShell } from './services/dbshell'
import type { DbConnectConfig } from '../shared/db'
import { setSecret, getSecret, deleteSecret, secretsAvailable } from './services/secrets'
import {
  vaultStatus,
  vaultCreate,
  vaultUnlock,
  vaultLock,
  vaultList,
  vaultSave,
  vaultChangePassword,
  vaultDestroy,
  vaultDispose
} from './services/vault'
import type { VaultEntry } from '../shared/vault'
import { wsLockIds, wsLockSet, wsLockVerify, wsLockRemove, wsLockDelete } from './services/wslock'
import { tunnelStart, tunnelStop, tunnelList, tunnelDisposeAll } from './services/tunnel'
import type { TunnelConfig, TunnelSshConfig } from '../shared/tunnel'
import { knownHostList, knownHostForget } from './services/knownhosts'
import { externalEditOpen, externalEditStop, externalEditDisposeAll } from './services/extedit'
import { backupExport, backupImport, backupInspect, relaunchApp } from './services/backup'
import { parseSshConfig } from '../shared/sshconfig'
import { loadData, saveData } from './services/store'
import type { SshConnectConfig, SshHop } from '../shared/ssh'

const isDev = !app.isPackaged

// Windows shows the AppUserModelID as the heading on every notification, and
// Electron's default is "electron.app.<name>". Setting it to the installer's
// appId makes Windows resolve it to the Start-menu shortcut, so notifications
// are headed "ShellPilot". Must be set before any notification is shown.
if (process.platform === 'win32') app.setAppUserModelId('com.shellpilot.app')

let mainWindow: BrowserWindow | null = null

// WSL has a broken GPU + sandbox/zygote stack: the GPU and network service
// crash on launch, which leaves the window black because the renderer can
// never paint (or, in dev, load the Vite server). Detect WSL and fall back to
// software rendering with the sandbox disabled. On real Linux the sandbox and
// hardware acceleration stay on.
function isWSL(): boolean {
  if (process.platform !== 'linux') return false
  if (process.env.WSL_DISTRO_NAME || process.env.WSL_INTEROP) return true
  try {
    return /microsoft/i.test(readFileSync('/proc/version', 'utf8'))
  } catch {
    return false
  }
}

if (isWSL()) {
  app.disableHardwareAcceleration()
  app.commandLine.appendSwitch('no-sandbox')
  app.commandLine.appendSwitch('disable-gpu')
  app.commandLine.appendSwitch('disable-dev-shm-usage')
}

// Content-Security-Policy applied via response headers.
// Dev needs inline/eval for the Vite dev server + React fast-refresh; prod is strict.
function installCsp(): void {
  const policy = isDev
    ? "default-src 'self' 'unsafe-inline' 'unsafe-eval' data: blob: ws: http://localhost:* http://127.0.0.1:*"
    : "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self' data:; connect-src 'self'"
  session.defaultSession.webRequest.onHeadersReceived((details, cb) => {
    cb({
      responseHeaders: {
        ...details.responseHeaders,
        'Content-Security-Policy': [policy]
      }
    })
  })
}

// Taskbar/window icon. Packaged builds also get platform icons from build/
// via electron-builder; this covers dev and the Linux window manager.
function appIcon(): string | undefined {
  const p = join(__dirname, '../../resources/icon.png')
  return existsSync(p) ? p : undefined
}

function createWindow(): void {
  mainWindow = new BrowserWindow({
    width: 1440,
    height: 900,
    minWidth: 1024,
    minHeight: 640,
    show: false,
    backgroundColor: '#0d1017',
    icon: appIcon(),
    titleBarStyle: process.platform === 'darwin' ? 'hiddenInset' : 'hidden',
    frame: process.platform === 'darwin',
    trafficLightPosition: { x: 16, y: 16 },
    webPreferences: {
      preload: join(__dirname, '../preload/index.mjs'),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: false
    }
  })

  mainWindow.on('ready-to-show', () => mainWindow?.show())

  // F5 would reload and destroy every open terminal. Ctrl+R is deliberately
  // NOT blocked here: preventDefault stops the key reaching the page at all,
  // and the shell needs it for reverse history search. Removing the reload
  // role from the menu is what stops Ctrl+R reloading.
  mainWindow.webContents.on('before-input-event', (event, input) => {
    if (input.type === 'keyDown' && input.key === 'F5') event.preventDefault()
  })

  if (isDev) {
    mainWindow.webContents.on('console-message', (_e, level, message, line, source) => {
      console.log(`[renderer:${level}] ${message} (${source}:${line})`)
    })
    mainWindow.webContents.on('render-process-gone', (_e, d) =>
      console.log('[renderer gone]', d.reason)
    )
    mainWindow.webContents.on('did-fail-load', (_e, code, desc) =>
      console.log('[did-fail-load]', code, desc)
    )
  }

  mainWindow.webContents.setWindowOpenHandler((details) => {
    shell.openExternal(details.url)
    return { action: 'deny' }
  })

  // Emit maximize state so the renderer titlebar can update its control.
  const emitMax = () => mainWindow?.webContents.send('window:maximized', mainWindow.isMaximized())
  mainWindow.on('maximize', emitMax)
  mainWindow.on('unmaximize', emitMax)

  if (isDev && process.env['ELECTRON_RENDERER_URL']) {
    mainWindow.loadURL(process.env['ELECTRON_RENDERER_URL'])
  } else {
    mainWindow.loadFile(join(__dirname, '../renderer/index.html'))
  }
}

// ---- Narrow, validated IPC surface -----------------------------------------

ipcMain.handle('window:control', (_e, action: unknown) => {
  if (!mainWindow) return
  switch (action) {
    case 'minimize':
      mainWindow.minimize()
      break
    case 'toggle-maximize':
      mainWindow.isMaximized() ? mainWindow.unmaximize() : mainWindow.maximize()
      break
    case 'close':
      mainWindow.close()
      break
    default:
      // ignore unknown actions
      break
  }
})

ipcMain.handle('window:isMaximized', () => mainWindow?.isMaximized() ?? false)

ipcMain.handle('app:platform', () => process.platform)

ipcMain.handle('theme:set', (_e, mode: unknown) => {
  if (mode === 'dark' || mode === 'light' || mode === 'system') {
    nativeTheme.themeSource = mode
  }
  return nativeTheme.shouldUseDarkColors
})

ipcMain.handle('dialog:openKey', async () => {
  if (!mainWindow) return null
  const result = await dialog.showOpenDialog(mainWindow, {
    title: 'Select private key',
    properties: ['openFile', 'showHiddenFiles'],
    // All files first: OpenSSH keys usually have no extension at all
    // (id_ed25519, or any bare filename), and an extension filter hides them.
    filters: [
      { name: 'All files', extensions: ['*'] },
      { name: 'Private keys', extensions: ['pem', 'key', 'ppk'] }
    ]
  })
  return result.canceled ? null : result.filePaths[0] ?? null
})

// Save/open a small JSON document the renderer owns (keyboard shortcuts
// today). The renderer serialises it — main only picks the path and moves the
// bytes, so it needs no knowledge of the shape.
ipcMain.handle('dialog:saveJson', async (_e, suggestedName: string, contents: string) => {
  if (!mainWindow) return false
  const chosen = await dialog.showSaveDialog(mainWindow, {
    title: 'Export',
    defaultPath: suggestedName,
    filters: [{ name: 'JSON', extensions: ['json'] }]
  })
  if (chosen.canceled || !chosen.filePath) return false
  await writeFile(chosen.filePath, contents, 'utf8')
  return true
})

ipcMain.handle('dialog:openJson', async () => {
  if (!mainWindow) return null
  const chosen = await dialog.showOpenDialog(mainWindow, {
    title: 'Import',
    properties: ['openFile'],
    filters: [{ name: 'JSON', extensions: ['json'] }]
  })
  const path = chosen.canceled ? null : chosen.filePaths[0] ?? null
  if (!path) return null
  // A file the user picked by hand can be anything; the renderer validates the
  // contents, so a read failure is the only thing handled here.
  try {
    return await readFile(path, 'utf8')
  } catch {
    return null
  }
})

ipcMain.handle('dialog:openUpload', async () => {
  if (!mainWindow) return null
  const result = await dialog.showOpenDialog(mainWindow, {
    title: 'Select files to upload',
    buttonLabel: 'Upload',
    properties: ['openFile', 'multiSelections', 'showHiddenFiles']
  })
  return result.canceled ? null : result.filePaths
})

// ---- SSH ----

// Multi-factor challenges are answered by the user, so the request is relayed
// to the renderer and the reply awaited here.
let promptSeq = 0
const pendingPrompts = new Map<string, (answers: string[]) => void>()

ipcMain.on(
  'ssh:prompt-reply',
  (_e, id: string, answers: string[], remember?: boolean, serverId?: string) => {
    const resolve = pendingPrompts.get(id)
    if (!resolve) return
    pendingPrompts.delete(id)
    // Only a single answer is worth storing; multi-prompt challenges are
    // per-attempt by nature.
    if (remember && serverId && answers.length === 1) {
      const raw = getSecret(serverId)
      const blob: SecretBlob = raw ? (JSON.parse(raw) as SecretBlob) : {}
      blob.kbAnswer = answers[0]
      setSecret(serverId, JSON.stringify(blob))
    }
    resolve(answers)
  }
)

setSshPrompter((req: KeyboardRequest) => {
  // A previously saved answer skips the dialog entirely.
  if (req.serverId && req.prompts.length === 1) {
    const raw = getSecret(req.serverId)
    if (raw) {
      try {
        const blob = JSON.parse(raw) as SecretBlob
        if (blob.kbAnswer) return Promise.resolve([blob.kbAnswer])
      } catch {
        /* fall through to prompting */
      }
    }
  }
  const target = mainWindow
  if (!target || target.isDestroyed()) return Promise.resolve([])
  const id = `kb-${promptSeq++}`
  return new Promise<string[]>((resolve) => {
    pendingPrompts.set(id, resolve)
    target.webContents.send('ssh:prompt', { id, ...req })
    // Never leave a connection hanging on an unanswered dialog.
    setTimeout(() => {
      if (pendingPrompts.delete(id)) resolve([])
    }, 120000)
  })
})

interface SecretBlob {
  password?: string
  keyPath?: string
  passphrase?: string
  // Saved answer to a single keyboard-interactive prompt (a static second
  // password). One-time codes are never stored — the UI does not offer it.
  kbAnswer?: string
}

// Merge stored credentials (never sent to the renderer) unless the renderer
// supplied inline secrets (e.g. from a one-time password prompt).
function resolveSecrets<T extends SshHop & { serverId?: string }>(cfg: T): T {
  if (cfg.serverId && !cfg.password && !cfg.privateKey && !cfg.keyPath) {
    const raw = getSecret(cfg.serverId)
    if (raw) {
      try {
        const blob = JSON.parse(raw) as SecretBlob
        cfg.password = cfg.password ?? blob.password
        cfg.keyPath = cfg.keyPath ?? blob.keyPath
        cfg.passphrase = cfg.passphrase ?? blob.passphrase
      } catch {
        /* ignore */
      }
    }
  }
  return cfg
}

// Every jump hop authenticates independently, so each one needs its own
// credentials resolved — not just the final target.
function resolveChainSecrets<T extends SshHop & { serverId?: string; hops?: SshHop[] }>(cfg: T): T {
  const resolved = resolveSecrets(cfg)
  if (Array.isArray(resolved.hops)) {
    resolved.hops = resolved.hops.map((h) => resolveSecrets({ ...h } as SshHop & { serverId?: string }))
  }
  return resolved
}

ipcMain.handle('ssh:connect', (e, cfg: SshConnectConfig & { serverId?: string }) =>
  sshConnect(e.sender, resolveChainSecrets(cfg))
)
ipcMain.handle('ssh:pool-list', () => poolList())
ipcMain.handle('ssh:pool-close', (_e, key: string) => poolClose(key))
ipcMain.handle('ssh:pool-idle', (_e, minutes: number) => setPoolIdle(minutes))
ipcMain.on('ssh:write', (_e, id: string, data: string) => sshWrite(id, data))
ipcMain.on('ssh:resize', (_e, id: string, cols: number, rows: number) => sshResize(id, cols, rows))
ipcMain.on('ssh:close', (_e, id: string) => sshClose(id))

// ---- SFTP ----
ipcMain.handle('sftp:connect', (_e, key: string, cfg: SshConnectConfig & { serverId?: string }) =>
  sftpConnect(key, resolveChainSecrets(cfg))
)
ipcMain.handle('sftp:list', (_e, key: string, path: string) => sftpList(key, path))
ipcMain.handle('sftp:read', (_e, key: string, path: string) => sftpRead(key, path))
ipcMain.handle('sftp:write', (_e, key: string, path: string, content: string) =>
  sftpWrite(key, path, content)
)
ipcMain.handle('sftp:mkdir', (_e, key: string, path: string) => sftpMkdir(key, path))
ipcMain.handle('sftp:rename', (_e, key: string, from: string, to: string) => sftpRename(key, from, to))
ipcMain.handle('sftp:delete', (_e, key: string, path: string, dir: boolean) => sftpDelete(key, path, dir))
ipcMain.handle('sftp:upload', (e, key: string, localPaths: string[], remoteDir: string) =>
  sftpUpload(e.sender, key, localPaths, remoteDir)
)
ipcMain.handle('sftp:disconnect', (_e, key: string) => sftpDisconnect(key))
ipcMain.handle('sftp:edit-external', (e, key: string, path: string, command: string) =>
  externalEditOpen(e.sender, key, path, command)
)
ipcMain.handle('sftp:edit-external-stop', (_e, path: string) => externalEditStop(path))

// ---- Metrics ----
ipcMain.handle('metrics:sample', (_e, key: string, cfg: SshConnectConfig & { serverId?: string }) =>
  metricsSample(key, resolveChainSecrets(cfg))
)
ipcMain.handle('metrics:disconnect', (_e, key: string) => metricsDisconnect(key))

// ---- Databases ----
function withDbSecret(cfg: DbConnectConfig): DbConnectConfig {
  if (!cfg.password && !cfg.uri) {
    const raw = getSecret(cfg.id)
    if (raw) {
      try {
        const b = JSON.parse(raw) as { password?: string; uri?: string }
        cfg.password = b.password
        cfg.uri = b.uri
      } catch {
        cfg.password = raw // legacy plain-password secret
      }
    }
  }
  // The jump host's own credentials live in the same encrypted store, keyed by
  // the server id.
  if (cfg.ssh) cfg.ssh = resolveChainSecrets({ ...cfg.ssh })
  return cfg
}
ipcMain.handle('db:test', (_e, cfg: DbConnectConfig) => dbTest(withDbSecret(cfg)))
ipcMain.handle('db:query', (_e, cfg: DbConnectConfig, text: string) => dbQuery(withDbSecret(cfg), text))
ipcMain.handle('db:info', (_e, cfg: DbConnectConfig) => dbInfo(withDbSecret(cfg)))
ipcMain.handle('db:shell', (_e, cfg: DbConnectConfig, line: string) => dbShell(withDbSecret(cfg), line))
ipcMain.handle('db:close', (_e, id: string) => dbClose(id))

// ---- SSH config import ----
ipcMain.handle('sshconfig:read', () => {
  const home = app.getPath('home')
  const path = join(home, '.ssh', 'config')
  try {
    // Expand ~ here so the renderer never has to guess the home directory.
    const hosts = parseSshConfig(readFileSync(path, 'utf8')).map((h) =>
      h.identityFile?.startsWith('~')
        ? { ...h, identityFile: join(home, h.identityFile.slice(1)) }
        : h
    )
    return { ok: true, path, hosts }
  } catch (err) {
    const e = err as NodeJS.ErrnoException
    return {
      ok: false,
      path,
      error: e.code === 'ENOENT' ? `No SSH config found at ${path}` : e.message
    }
  }
})

// ---- Notifications ----
// Native OS notifications: they render outside the window, so they can never
// cover the terminal, and the OS handles stacking and dismissal.
ipcMain.handle('notify:show', (_e, title: string, body: string) => {
  if (!Notification.isSupported()) return false
  const n = new Notification({ title, body, silent: true, icon: appIcon() })
  n.on('click', () => {
    if (mainWindow && !mainWindow.isDestroyed()) {
      if (mainWindow.isMinimized()) mainWindow.restore()
      mainWindow.focus()
    }
  })
  n.show()
  return true
})

// ---- Backup ----
ipcMain.handle('backup:export', (_e, password: string) => backupExport(password))
ipcMain.handle('backup:inspect', (_e, password: string, path?: string) => backupInspect(password, path))
ipcMain.handle('backup:import', (_e, password: string, path: string) => backupImport(password, path))
ipcMain.handle('backup:relaunch', () => relaunchApp())

// ---- Known hosts ----
ipcMain.handle('knownhosts:list', () => knownHostList())
ipcMain.handle('knownhosts:forget', (_e, id: string) => knownHostForget(id))

// ---- Tunnels ----
ipcMain.handle('tunnel:start', (e, cfg: TunnelConfig, ssh: TunnelSshConfig) =>
  tunnelStart(e.sender, cfg, resolveChainSecrets(ssh))
)
ipcMain.handle('tunnel:stop', (_e, id: string) => tunnelStop(id))
ipcMain.handle('tunnel:list', () => tunnelList())

// ---- Vault ----
ipcMain.handle('vault:status', () => vaultStatus())
ipcMain.handle('vault:create', (_e, password: string) => vaultCreate(password))
ipcMain.handle('vault:unlock', (_e, password: string) => vaultUnlock(password))
ipcMain.handle('vault:lock', () => vaultLock())
ipcMain.handle('vault:list', () => vaultList())
ipcMain.handle('vault:save', (_e, entries: VaultEntry[]) => vaultSave(entries))
ipcMain.handle('vault:change-password', (_e, current: string, next: string) =>
  vaultChangePassword(current, next)
)
ipcMain.handle('vault:destroy', () => vaultDestroy())

// ---- Workspace locks ----
ipcMain.handle('wslock:ids', () => wsLockIds())
ipcMain.handle('wslock:verify', (_e, id: string, password: string) => wsLockVerify(id, password))
ipcMain.handle('wslock:set', (_e, id: string, password: string, current?: string) =>
  wsLockSet(id, password, current)
)
ipcMain.handle('wslock:remove', (_e, id: string, current: string) => wsLockRemove(id, current))
ipcMain.handle('wslock:delete', (_e, id: string) => wsLockDelete(id))

// ---- Secrets ----
ipcMain.handle('secrets:available', () => secretsAvailable())
ipcMain.handle('secrets:set', (_e, id: string, value: string) => setSecret(id, value))
ipcMain.handle('secrets:delete', (_e, id: string) => deleteSecret(id))

// ---- Data persistence ----
ipcMain.handle('data:load', () => loadData())
ipcMain.handle('data:save', (_e, data: unknown) => saveData(data))

app.on('before-quit', () => {
  sshDisposeAll()
  sftpDisposeAll()
  metricsDisposeAll()
  dbDisposeAll()
  tunnelDisposeAll()
  externalEditDisposeAll()
  vaultDispose()
})

// Safety net: never let a stray async error (e.g. a failed child_process
// spawn) crash the main process with a fatal dialog.
process.on('uncaughtException', (err) => console.error('[uncaughtException]', err))
process.on('unhandledRejection', (reason) => console.error('[unhandledRejection]', reason))

// The window is frameless, so no menu bar is drawn — but an application menu
// still has to exist for the clipboard accelerators (Ctrl/Cmd+C, V, X, A) to
// reach focused inputs. Without it, copy and paste silently do nothing.
function installMenu(): void {
  const isMac = process.platform === 'darwin'
  const menu = Menu.buildFromTemplate([
    ...(isMac ? [{ role: 'appMenu' as const }] : []),
    {
      label: 'Edit',
      submenu: [
        { role: 'undo' as const },
        { role: 'redo' as const },
        { type: 'separator' as const },
        { role: 'cut' as const },
        { role: 'copy' as const },
        { role: 'paste' as const },
        { role: 'pasteAndMatchStyle' as const },
        { role: 'delete' as const },
        { role: 'selectAll' as const }
      ]
    },
    {
      label: 'View',
      submenu: [
        // No 'reload' role. Its Ctrl+R accelerator is swallowed app-wide and
        // shells bind Ctrl+R to reverse history search — losing that, and
        // having every open terminal torn down by an accidental reload, is far
        // worse than not having a reload menu item.
        { role: 'toggleDevTools' as const, accelerator: 'F12' },
        { type: 'separator' as const },
        // No zoom roles: Ctrl +/-/0 resize the terminal font instead, and the
        // menu accelerators would otherwise zoom the whole UI at the same time.
        { role: 'togglefullscreen' as const }
      ]
    },
    // No 'Window' submenu. Its two roles carry CmdOrCtrl+M and CmdOrCtrl+W
    // accelerators, which the menu consumes before the renderer sees them —
    // that swallowed Close Tab and Open Fleet Monitor. The frameless title bar
    // already provides minimize/close buttons, and Alt+F4 still works.
  ])
  if (isMac) Menu.setApplicationMenu(menu)
  else {
    // Keep the accelerators, keep the bar hidden.
    Menu.setApplicationMenu(menu)
    BrowserWindow.getAllWindows().forEach((w) => w.setMenuBarVisibility(false))
  }
}

// A second instance would share the same data files and silently clobber the
// first one's state — last writer wins. Focus the existing window instead.
if (!app.requestSingleInstanceLock()) {
  app.quit()
} else {
  app.on('second-instance', () => {
    if (!mainWindow || mainWindow.isDestroyed()) return
    if (mainWindow.isMinimized()) mainWindow.restore()
    mainWindow.focus()
  })
}

app.whenReady().then(() => {
  installCsp()
  createWindow()
  installMenu()
  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow()
  })
})

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') app.quit()
})
