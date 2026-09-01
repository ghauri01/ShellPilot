// Must come first: redirects userData for portable builds before any
// service module resolves its file paths.
import './portable'
import { app, shell, BrowserWindow, ipcMain, nativeTheme, dialog, session, Menu, Notification, powerMonitor } from 'electron'
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
import {
  setVpnPrompter,
  vpnAttachRenderer,
  vpnDependentsOf,
  vpnDetachRenderer,
  vpnDisposeAll,
  vpnInit,
  vpnList,
  vpnLogs,
  vpnProbe,
  vpnProfiles,
  vpnReload,
  vpnSetCadence,
  vpnStart,
  vpnStop,
  vpnSubscribeLogs,
  vpnUnsubscribeLogs,
  vpnValidate,
  vpnHandleWake
} from './services/vpn/manager'
import { vpnCommitImport, vpnDeleteSecrets, vpnImport } from './services/vpn/import'
import { wireguardDriver } from './services/vpn/drivers/wireguard'
import { mintKeypair, storeKeypair } from './services/vpn/keys'
import { toVpnResult } from './services/vpn/errors'
import { withVpnTransport, withVpnTransportDb } from './services/vpn/transport'
import type { VpnKeygenResult, VpnKind, VpnMintResult, VpnPublicKeyResult, VpnSpec } from '../shared/vpn'
import { externalEditOpen, externalEditStop, externalEditDisposeAll } from './services/extedit'
import { backupExport, backupImport, backupInspect, deleteAllData, relaunchApp } from './services/backup'
import {
  checkForUpdates,
  getUpdaterStatus,
  onUpdaterStatus,
  installUpdate,
  openReleasePage,
  getCapabilities as getUpdaterCapabilities,
  getPrefs as getUpdaterPrefs,
  setPrefs as setUpdaterPrefs,
  downloadUpdate,
  startAutoCheck
} from './services/updater'
import type { UpdatePrefs } from '../shared/updater'
import { parseSshConfig } from '../shared/sshconfig'
import { loadData, saveData } from './services/store'
import type { SshConnectConfig } from '../shared/ssh'
import { resolveDbSecrets, resolveChainSecrets, type SecretBlob } from './services/credentialResolver'
import { refreshMcpDataCache, listCachedWorkspaces, listCachedServers } from './services/mcpDataCache'
import {
  listGroups,
  createGroup,
  saveGroup,
  deleteGroup,
  listAssignments,
  setAssignment,
  removeAssignment,
  listServerMeta,
  setServerAliases
} from './services/policyStore'
import type { AccessGroup, ApprovalRequest, McpGlobalConfig, PolicyAssignment } from '../shared/mcp'
import {
  getMcpConfig,
  setMcpConfig,
  createSession,
  listSessions,
  revokeSession,
  deleteSession,
  killAllSessions,
  setSessionGroup,
  type CreateSessionInput
} from './services/mcpAuth'
import { listPendingApprovals, respondToApproval, onApprovalEvent, denyAllPending } from './services/approvals'
import { onCliPairingEvent, cancelCliPairing } from './services/cliPairing'
import { claudeCodeCommand, writeClaudeDesktopConfig, writeCodexConfig } from './services/clientConfig'
import { setAgentServerCreator, type AgentServerRequest, type AgentServerResult } from './services/agentServerCreate'
import { listDefaultKeys, sshDir } from './services/sshKeys'
import { setVaultAutoLock } from './services/vault'
import {
  biometricSupport,
  biometricEnabled,
  biometricScope,
  enableBiometricUnlock,
  disableBiometricUnlock,
  forgetSessionKey,
  biometricUnlock
} from './services/biometrics'
import { listAudit } from './services/auditLog'
import { startMcpServer, stopMcpServer, mcpServerStatus, explainSessionAccess } from './services/mcpServer'

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

  // VPN status is polled, and nobody reads a byte counter on a window they
  // cannot see. Backing off while hidden is most of the idle cost of this
  // feature; resuming on focus samples immediately so the numbers are current
  // by the time the user has looked at them.
  const active = (): void => vpnSetCadence('active')
  const idle = (): void => vpnSetCadence('idle')
  mainWindow.on('focus', active)
  mainWindow.on('show', active)
  mainWindow.on('blur', idle)
  mainWindow.on('hide', idle)
  vpnAttachRenderer(mainWindow.webContents)
  mainWindow.on('closed', () => {
    // The WebContents is already gone here, so the bus would prune it on its
    // next send anyway; doing it now keeps a closed window from being counted
    // as a live target in the meantime.
    vpnSetCadence('idle')
  })
  mainWindow.webContents.on('destroyed', () => {
    if (mainWindow) vpnDetachRenderer(mainWindow.webContents)
  })

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
ipcMain.handle('app:version', () => app.getVersion())

ipcMain.handle('theme:set', (_e, mode: unknown) => {
  if (mode === 'dark' || mode === 'light' || mode === 'system') {
    nativeTheme.themeSource = mode
  }
  return nativeTheme.shouldUseDarkColors
})

ipcMain.handle('ssh:defaultKeys', () => listDefaultKeys())

ipcMain.handle('dialog:openKey', async () => {
  if (!mainWindow) return null
  const result = await dialog.showOpenDialog(mainWindow, {
    title: 'Select private key',
    // ~/.ssh is where keys actually live and the picker will not show a hidden
    // folder unless it opens there, so landing anywhere else means the user
    // has to type the path they came here to avoid typing.
    defaultPath: sshDir(),
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


ipcMain.handle('ssh:connect', (e, cfg: SshConnectConfig & { serverId?: string }) =>
  sshConnect(e.sender, withVpnTransport(resolveChainSecrets(cfg)))
)
ipcMain.handle('ssh:pool-list', () => poolList())
ipcMain.handle('ssh:pool-close', (_e, key: string) => poolClose(key))
ipcMain.handle('ssh:pool-idle', (_e, minutes: number) => setPoolIdle(minutes))
ipcMain.on('ssh:write', (_e, id: string, data: string) => sshWrite(id, data))
ipcMain.on('ssh:resize', (_e, id: string, cols: number, rows: number) => sshResize(id, cols, rows))
ipcMain.on('ssh:close', (_e, id: string) => sshClose(id))

// ---- SFTP ----
ipcMain.handle('sftp:connect', (_e, key: string, cfg: SshConnectConfig & { serverId?: string }) =>
  sftpConnect(key, withVpnTransport(resolveChainSecrets(cfg)))
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
// withVpnTransportDb resolves the profile from the saved record, so a
// connection cannot skip its VPN just because one call site predates the
// feature.
ipcMain.handle('db:test', (_e, cfg: DbConnectConfig) => dbTest(withVpnTransportDb(resolveDbSecrets(cfg))))
ipcMain.handle('db:query', (_e, cfg: DbConnectConfig, text: string) =>
  dbQuery(withVpnTransportDb(resolveDbSecrets(cfg)), text)
)
ipcMain.handle('db:info', (_e, cfg: DbConnectConfig) => dbInfo(withVpnTransportDb(resolveDbSecrets(cfg))))
ipcMain.handle('db:shell', (_e, cfg: DbConnectConfig, line: string) =>
  dbShell(withVpnTransportDb(resolveDbSecrets(cfg)), line)
)
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

// An approval blocks an AI agent until the user answers it, and the dialog it
// renders lives inside the window. If ShellPilot is not in front, nothing tells
// the user anything is waiting — the agent simply appears to hang for the
// whole timeout, which is exactly how it was reported.
function notifyApprovalPending(request: ApprovalRequest): void {
  if (mainWindow && !mainWindow.isDestroyed()) {
    // Bounces the dock icon on macOS, flashes the taskbar on Windows. Left as
    // 'informational' rather than 'critical': the request expires on its own,
    // so it does not warrant a bouncing icon that will not stop.
    app.dock?.bounce('informational')
    mainWindow.flashFrame(true)
  }
  if (!Notification.isSupported()) return
  const n = new Notification({
    title: `${request.agentName} needs approval`,
    body: `${request.action}\non ${request.serverName}`,
    icon: appIcon()
  })
  n.on('click', () => {
    if (mainWindow && !mainWindow.isDestroyed()) {
      if (mainWindow.isMinimized()) mainWindow.restore()
      mainWindow.show()
      mainWindow.focus()
    }
  })
  n.show()
}

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
ipcMain.handle('backup:deleteAll', () => deleteAllData())
ipcMain.handle('backup:relaunch', () => relaunchApp())

// ---- Updater ----
ipcMain.handle('updater:check', () => checkForUpdates())
ipcMain.handle('updater:status', () => getUpdaterStatus())
ipcMain.handle('updater:install', () => installUpdate())
ipcMain.handle('updater:openReleasePage', () => openReleasePage())
ipcMain.handle('updater:download', () => downloadUpdate())
ipcMain.handle('updater:getPrefs', () => getUpdaterPrefs())
ipcMain.handle('updater:setPrefs', (_e, patch: Partial<UpdatePrefs>) => setUpdaterPrefs(patch))
ipcMain.handle('updater:capabilities', () => getUpdaterCapabilities())
onUpdaterStatus((s) => {
  if (mainWindow && !mainWindow.isDestroyed()) mainWindow.webContents.send('updater:status-event', s)
})

// ---- Known hosts ----
ipcMain.handle('knownhosts:list', () => knownHostList())
ipcMain.handle('knownhosts:forget', (_e, id: string) => knownHostForget(id))

// ---- Tunnels ----
ipcMain.handle('tunnel:start', (e, cfg: TunnelConfig, ssh: TunnelSshConfig) =>
  tunnelStart(e.sender, cfg, resolveChainSecrets(ssh))
)
ipcMain.handle('tunnel:stop', (_e, id: string) => tunnelStop(id))
ipcMain.handle('tunnel:list', () => tunnelList())

// ---- VPN ----
ipcMain.handle('vpn:list', () => vpnList())
ipcMain.handle('vpn:profiles', () => vpnProfiles())
ipcMain.handle('vpn:start', (e, id: string) => {
  vpnAttachRenderer(e.sender)
  return vpnStart(id)
})
ipcMain.handle('vpn:stop', (_e, id: string, force?: boolean) => vpnStop(id, { force }))
ipcMain.handle('vpn:reload', (_e, id: string) => vpnReload(id))
ipcMain.handle('vpn:validate', (_e, spec: VpnSpec) => vpnValidate(spec))
ipcMain.handle('vpn:probe', (_e, kind: VpnKind) => vpnProbe(kind))
// Returns a spec plus the stripped-directive report, and nothing else: the
// key material stays in main until the user commits the import.
ipcMain.handle('vpn:import', (_e, kind: VpnKind, text: string, baseDir?: string) =>
  vpnImport(kind, text, baseDir)
)
ipcMain.handle(
  'vpn:commitImport',
  (_e, name: string, workspaceId: string, kind: VpnKind, text: string, baseDir?: string) =>
    vpnCommitImport(name, workspaceId, kind, text, baseDir)
)
ipcMain.handle('vpn:deleteSecrets', (_e, vaultEntryId: string) => vpnDeleteSecrets(vaultEntryId))
// Two channels, because they do two different things to the vault.
//
// `wireguardKeygen` writes; `wireguardMint` does not. The profile form
// generates through the mint channel and holds the pair, then stores through
// the other one only if the user presses Save — so cancelling a dialog after
// pressing "Generate keypair" no longer leaves an entry behind that no profile
// references. Both bodies live in services/vpn/keys.ts, where the reasoning and
// the tests for that split are.
ipcMain.handle('vpn:wireguardMint', (): Promise<VpnMintResult> => mintKeypair())
ipcMain.handle(
  'vpn:wireguardKeygen',
  (
    _e,
    req: { profileName: string; workspaceId: string; privateKey: string; replaces?: string }
  ): Promise<VpnKeygenResult> => storeKeypair(req)
)
// `wg pubkey`, and nothing else: no vault write, no side effect, safe to call
// while the user is still typing. It exists because a private key is useless
// until you can tell your server which public key to authorise.
ipcMain.handle(
  'vpn:wireguardPublicKey',
  async (_e, privateKey: string): Promise<VpnPublicKeyResult> => {
    try {
      const pair = await wireguardDriver.keygen({ publicKeyFor: privateKey })
      return { ok: true, publicKey: pair.publicKey }
    } catch (e) {
      return toVpnResult(e)
    }
  }
)
ipcMain.handle('vpn:logs', (_e, id: string, limit?: number) => vpnLogs(id, limit))
ipcMain.handle('vpn:dependents', (_e, id: string) => vpnDependentsOf(id))
// Log lines stop at the ring buffer unless a drawer is open. Refcounted, so
// two windows watching the same profile do not silence each other.
ipcMain.on('vpn:log-subscribe', (e, id: string) => {
  vpnAttachRenderer(e.sender)
  vpnSubscribeLogs(id)
})
ipcMain.on('vpn:log-unsubscribe', (_e, id: string) => vpnUnsubscribeLogs(id))

// One-time codes and password re-prompts, mirroring the SSH prompter above.
const pendingVpnPrompts = new Map<string, (value: string | null) => void>()
ipcMain.on('vpn:prompt-reply', (_e, id: string, value: string | null) => {
  const resolve = pendingVpnPrompts.get(id)
  if (!resolve) return
  pendingVpnPrompts.delete(id)
  resolve(value)
})
setVpnPrompter((req) => {
  const target = mainWindow
  // No window means nobody can answer. Returning null is the same outcome as
  // the user dismissing the dialog, which the drivers already handle; the
  // alternative is a connection that hangs forever with no explanation.
  if (!target || target.isDestroyed()) return Promise.resolve(null)
  return new Promise<string | null>((resolve) => {
    pendingVpnPrompts.set(req.id, resolve)
    target.webContents.send('vpn:prompt', req)
    // A one-time code the user walked away from must not pin a connection
    // open indefinitely.
    setTimeout(() => {
      if (pendingVpnPrompts.delete(req.id)) resolve(null)
    }, 120000)
  })
})

// ---- Vault ----
ipcMain.handle('vault:status', () => vaultStatus())
ipcMain.handle('vault:create', (_e, password: string) => vaultCreate(password))
ipcMain.handle('vault:unlock', (_e, password: string) => vaultUnlock(password))
// Auto-lock needs the renderer told, or the UI keeps showing an unlocked vault
// it can no longer read. The biometric session key goes with it.
setVaultAutoLock(15, () => {
  forgetSessionKey()
  if (mainWindow && !mainWindow.isDestroyed()) mainWindow.webContents.send('vault:auto-locked')
})

ipcMain.handle('vault:lock', () => {
  // A session-scoped biometric key must not outlive the unlocked state, or
  // "lock" would not mean locked.
  forgetSessionKey()
  return vaultLock()
})
ipcMain.handle('vault:list', () => vaultList())
ipcMain.handle('vault:save', (_e, entries: VaultEntry[]) => vaultSave(entries))
// The stored biometric key was derived from the old password and cannot open
// the re-encrypted vault, so it is cleared here rather than left to fail on
// the next unlock. The renderer re-reads bio-enabled after this and tells the
// user to set it up again.
ipcMain.handle('vault:change-password', async (_e, current: string, next: string) => {
  const result = await vaultChangePassword(current, next)
  if (result.ok) disableBiometricUnlock()
  return result
})
ipcMain.handle('vault:destroy', () => {
  // A stored biometric key opens a vault that no longer exists; leaving it
  // behind is dead material on disk.
  disableBiometricUnlock()
  return vaultDestroy()
})

// ---- Vault: biometric unlock ----
ipcMain.handle('vault:bio-support', () => biometricSupport())
ipcMain.handle('vault:bio-enabled', () => biometricEnabled())
ipcMain.handle('vault:bio-enable', (_e, scope: 'session' | 'persistent' = 'session') =>
  enableBiometricUnlock(scope)
)
ipcMain.handle('vault:bio-scope', () => biometricScope())
ipcMain.handle('vault:set-auto-lock', (_e, minutes: number) => setVaultAutoLock(minutes))
ipcMain.handle('vault:bio-disable', () => disableBiometricUnlock())
ipcMain.handle('vault:bio-unlock', () => biometricUnlock())

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
ipcMain.handle('data:save', (_e, data: unknown) => {
  saveData(data)
  // The MCP bridge resolves friendly server/workspace names from this same
  // file (see mcpDataCache.ts) rather than round-tripping through the
  // renderer on every tool call, so its cache is refreshed right after the
  // write that would otherwise make it stale.
  refreshMcpDataCache(data)
})

// ---- AI & MCP: access groups ----
ipcMain.handle('aiPolicy:listGroups', () => listGroups())
ipcMain.handle('aiPolicy:createGroup', (_e, name: string) => createGroup(name))
ipcMain.handle('aiPolicy:saveGroup', (_e, group: AccessGroup) => saveGroup(group))
ipcMain.handle('aiPolicy:deleteGroup', (_e, id: string) => deleteGroup(id))
ipcMain.handle('aiPolicy:listAssignments', () => listAssignments())
ipcMain.handle('aiPolicy:setAssignment', (_e, scope: PolicyAssignment['scope'], groupId: string | null) =>
  setAssignment(scope, groupId)
)
ipcMain.handle('aiPolicy:removeAssignment', (_e, id: string) => removeAssignment(id))
ipcMain.handle('aiPolicy:listServerMeta', () => listServerMeta())
ipcMain.handle('aiPolicy:setServerAliases', (_e, serverId: string, aliases: string[]) =>
  setServerAliases(serverId, aliases)
)

// ---- AI & MCP: server/workspace directory (read-only view for the UI) ----
ipcMain.handle('aiPolicy:listWorkspaces', () => listCachedWorkspaces())
ipcMain.handle('aiPolicy:listServers', (_e, workspaceId?: string) => listCachedServers(workspaceId))

// ---- AI & MCP: global config + server lifecycle ----
ipcMain.handle('aiMcp:getConfig', () => getMcpConfig())
ipcMain.handle('aiMcp:setConfig', async (_e, patch: Partial<McpGlobalConfig>) => {
  const next = setMcpConfig(patch)
  if (next.enabled && mcpServerStatus().running === false) {
    const result = await startMcpServer()
    if (!result.ok) return { config: next, error: result.error }
  } else if (!next.enabled) {
    await stopMcpServer()
  }
  return { config: next }
})
ipcMain.handle('aiMcp:status', () => mcpServerStatus())

// ---- AI & MCP: agent sessions ----
ipcMain.handle('aiMcp:createSession', (_e, input: CreateSessionInput) => createSession(input))
ipcMain.handle('aiMcp:listSessions', () => listSessions())
ipcMain.handle('aiMcp:revokeSession', (_e, id: string) => revokeSession(id))
ipcMain.handle('aiMcp:deleteSession', (_e, id: string) => deleteSession(id))
ipcMain.handle('aiMcp:setSessionGroup', (_e, id: string, groupId: string | null, groupName: string) =>
  setSessionGroup(id, groupId, groupName)
)
ipcMain.handle('aiMcp:explainAccess', (_e, sessionId: string, serverId: string | null) =>
  explainSessionAccess(sessionId, serverId)
)
ipcMain.handle('aiMcp:killAllSessions', () => {
  const count = killAllSessions()
  const denied = denyAllPending()
  return { revoked: count, denied }
})

// ---- AI & MCP: approvals ----
ipcMain.handle('aiMcp:listApprovals', () => listPendingApprovals())
ipcMain.handle('aiMcp:respondApproval', (_e, id: string, decision: 'approved' | 'denied') =>
  respondToApproval(id, decision)
)
onApprovalEvent((e) => {
  if (mainWindow && !mainWindow.isDestroyed()) mainWindow.webContents.send('ai:approval-event', e)
  if (e.type === 'created') notifyApprovalPending(e.request)
  // Stop the taskbar flashing once the thing it was flashing about is answered.
  if (e.type === 'resolved' && mainWindow && !mainWindow.isDestroyed()) mainWindow.flashFrame(false)
})

// ---- AI & MCP: agent-initiated server creation (the add_server tool) ----
// Same request/reply shape as ssh:prompt above: the renderer owns the
// connection list, so main hands it the work and waits for the answer.
let createSeq = 0
const pendingServerCreates = new Map<string, (result: AgentServerResult) => void>()

ipcMain.on('aiMcp:create-server-reply', (_e, id: string, result: AgentServerResult) => {
  const resolve = pendingServerCreates.get(id)
  if (!resolve) return
  pendingServerCreates.delete(id)
  resolve(result)
})

setAgentServerCreator((req: AgentServerRequest) => {
  const target = mainWindow
  if (!target || target.isDestroyed()) {
    return Promise.resolve({ ok: false, error: 'The ShellPilot window is closed.' })
  }
  const id = `mkserver-${createSeq++}`
  return new Promise<AgentServerResult>((resolve) => {
    pendingServerCreates.set(id, resolve)
    target.webContents.send('aiMcp:create-server', { id, request: req })
    // The agent is blocked on this call; never leave it hanging on a renderer
    // that failed to answer.
    setTimeout(() => {
      if (pendingServerCreates.delete(id)) resolve({ ok: false, error: 'Timed out adding the server.' })
    }, 30000)
  })
})

// ---- AI & MCP: one-click client wiring (AI & MCP -> Overview -> Connect) ----
ipcMain.handle('aiMcp:claudeCodeCommand', (_e, token: string, port: number) => claudeCodeCommand(token, port))
ipcMain.handle('aiMcp:writeClaudeDesktopConfig', (_e, token: string, port: number) =>
  writeClaudeDesktopConfig(token, port)
)
ipcMain.handle('aiMcp:writeCodexConfig', (_e, token: string, port: number) => writeCodexConfig(token, port))

// ---- AI & MCP: CLI pairing (the `shellpilot claude|codex|run` launcher) ----
ipcMain.handle('aiMcp:cancelPairing', (_e, id: string) => cancelCliPairing(id))
onCliPairingEvent((e) => {
  if (mainWindow && !mainWindow.isDestroyed()) mainWindow.webContents.send('ai:pairing-event', e)
})

// ---- AI & MCP: audit log ----
ipcMain.handle('aiMcp:listAudit', (_e, limit?: number) => listAudit(limit))

// Teardown became asynchronous when VPN engines arrived: they are separate
// processes and killing them is not instantaneous. The order below is the
// point — every consumer dies before the transport it was riding, so nothing
// observes a half-dead network on the way out.
//
// The re-entry guard exists because preventDefault + app.exit() means this
// handler fires twice on some platforms, and running the dispose functions
// twice is at best noisy.
let teardownStarted = false
app.on('before-quit', (e) => {
  if (teardownStarted) {
    // Still prevent the default. Without this, the second fire (Cmd+Q twice,
    // or the platforms where this handler runs twice by itself) quits
    // immediately while the first invocation's vpnDisposeAll is still inside
    // its 4s window — so engines die by process death instead of by the
    // graceful ladder, and a system-mode tunnel never puts the routes and DNS
    // back. The single app.exit(0) below is what ends the process.
    e.preventDefault()
    return
  }
  teardownStarted = true
  e.preventDefault()

  sshDisposeAll()
  sftpDisposeAll()
  metricsDisposeAll()
  dbDisposeAll()
  tunnelDisposeAll()
  externalEditDisposeAll()
  vaultDispose()
  void stopMcpServer()

  // Dependents are down; now the transports. Hard-capped, because a wedged
  // child must never be able to hold the app open — an orphan is reaped on the
  // next launch, an app that will not quit is a support ticket.
  const cap = new Promise<void>((resolve) => setTimeout(resolve, 4000))
  void Promise.race([vpnDisposeAll().catch(() => undefined), cap]).finally(() => app.exit(0))
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
  // Primed once at launch so the MCP bridge can resolve server/workspace
  // names even before the renderer's first data:save call.
  refreshMcpDataCache()
  // Before the MCP server: the bridge asks the manager what is running, and a
  // bridge that answered "nothing" because the manager had not booted would be
  // lying about the state of the user's network. This also reaps any engine a
  // previous run left behind, before anything tries to claim its ports.
  // A laptop that has been asleep comes back on a different path, and
  // sometimes a different network entirely. WireGuard roams by itself but its
  // reported handshake age is stale until we resample; OpenVPN can sit on a
  // dead socket for minutes waiting for its own ping-restart. Nudging both is
  // cheaper than either.
  powerMonitor.on('resume', () => vpnHandleWake())
  powerMonitor.on('unlock-screen', () => vpnHandleWake())

  void vpnInit()
    .catch((e) => console.error('[vpn] init failed:', e))
    .finally(() => {
      if (!getMcpConfig().enabled) return
      void startMcpServer().then((r) => {
        if (!r.ok) console.error('[mcp] failed to start on launch:', r.error)
      })
    })
  // Quiet by design: this only ever pushes a status event the renderer can
  // choose to surface (or not) — it never interrupts anything on its own.
  // The launch check and the recurring one are the same decision, made from
  // the stored prefs, so both live behind startAutoCheck rather than a bare
  // check here plus a timer somewhere else.
  startAutoCheck()
  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow()
  })
})

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') app.quit()
})
