import { contextBridge, ipcRenderer, clipboard, webUtils } from 'electron'
import type { IpcRendererEvent } from 'electron'
import type {
  SshConnectConfig,
  SshStatus,
  SftpEntry,
  SftpProgress,
  SftpResult,
  SftpUploadSummary,
  MetricsResult,
  SshCloseInfo
} from '../shared/ssh'

export interface SshPromptRequest {
  id: string
  host: string
  username: string
  serverId?: string
  name: string
  instructions: string
  prompts: { prompt: string; echo: boolean }[]
}
import type { DbConnectConfig, DbInfo, DbQueryResult, DbTestResult } from '../shared/db'
import type { DbShellResult } from '../shared/dbshell'
import type { VaultEntry, VaultListResult, VaultResult, VaultStatus } from '../shared/vault'
import type { TunnelConfig, TunnelResult, TunnelSshConfig, TunnelStatus } from '../shared/tunnel'
import type { KnownHost } from '../main/services/knownhosts'
import type { SshConfigHost } from '../shared/sshconfig'
import type { BackupResult } from '../shared/backup'
import type { UpdaterStatus } from '../shared/updater'
import type {
  AccessGroup,
  PolicyAssignment,
  ServerAiMeta,
  McpGlobalConfig,
  McpAgentSession,
  ApprovalRequest,
  AuditEntry,
  CliPairingRequest
} from '../shared/mcp'

type WindowAction = 'minimize' | 'toggle-maximize' | 'close'
type ThemeMode = 'dark' | 'light' | 'system'

const api = {
  platform: (): Promise<NodeJS.Platform> => ipcRenderer.invoke('app:platform'),
  getVersion: (): Promise<string> => ipcRenderer.invoke('app:version'),
  window: {
    control: (action: WindowAction): Promise<void> =>
      ipcRenderer.invoke('window:control', action),
    isMaximized: (): Promise<boolean> => ipcRenderer.invoke('window:isMaximized'),
    onMaximizedChange: (cb: (maximized: boolean) => void): (() => void) => {
      const handler = (_e: unknown, value: boolean): void => cb(value)
      ipcRenderer.on('window:maximized', handler)
      return () => ipcRenderer.removeListener('window:maximized', handler)
    }
  },
  theme: {
    set: (mode: ThemeMode): Promise<boolean> => ipcRenderer.invoke('theme:set', mode)
  },
  dialog: {
    openKey: (): Promise<string | null> => ipcRenderer.invoke('dialog:openKey'),
    openUpload: (): Promise<string[] | null> => ipcRenderer.invoke('dialog:openUpload'),
    saveJson: (suggestedName: string, contents: string): Promise<boolean> =>
      ipcRenderer.invoke('dialog:saveJson', suggestedName, contents),
    openJson: (): Promise<string | null> => ipcRenderer.invoke('dialog:openJson')
  },
  clipboard: {
    read: (): string => clipboard.readText(),
    write: (text: string): void => clipboard.writeText(text)
  },
  ssh: {
    connect: (cfg: SshConnectConfig & { serverId?: string }): Promise<void> =>
      ipcRenderer.invoke('ssh:connect', cfg),
    write: (id: string, data: string): void => ipcRenderer.send('ssh:write', id, data),
    resize: (id: string, cols: number, rows: number): void =>
      ipcRenderer.send('ssh:resize', id, cols, rows),
    close: (id: string): void => ipcRenderer.send('ssh:close', id),
    onData: (id: string, cb: (data: string) => void): (() => void) => {
      const ch = `ssh:data:${id}`
      const h = (_e: IpcRendererEvent, d: string): void => cb(d)
      ipcRenderer.on(ch, h)
      return () => ipcRenderer.removeListener(ch, h)
    },
    onStatus: (id: string, cb: (s: SshStatus) => void): (() => void) => {
      const ch = `ssh:status:${id}`
      const h = (_e: IpcRendererEvent, s: SshStatus): void => cb(s)
      ipcRenderer.on(ch, h)
      return () => ipcRenderer.removeListener(ch, h)
    },
    onPrompt: (cb: (req: SshPromptRequest) => void): (() => void) => {
      const h = (_e: IpcRendererEvent, req: SshPromptRequest): void => cb(req)
      ipcRenderer.on('ssh:prompt', h)
      return () => ipcRenderer.removeListener('ssh:prompt', h)
    },
    poolList: (): Promise<{ key: string; host: string; username: string; sessions: number }[]> =>
      ipcRenderer.invoke('ssh:pool-list'),
    poolClose: (key: string): Promise<void> => ipcRenderer.invoke('ssh:pool-close', key),
    defaultKeys: (): Promise<
      { path: string; fileName: string; algorithm: string | null; encrypted: boolean }[]
    > => ipcRenderer.invoke('ssh:defaultKeys'),
    setPoolIdle: (minutes: number): Promise<void> => ipcRenderer.invoke('ssh:pool-idle', minutes),
    replyPrompt: (id: string, answers: string[], remember?: boolean, serverId?: string): void =>
      ipcRenderer.send('ssh:prompt-reply', id, answers, remember, serverId),
    onClose: (id: string, cb: (info: SshCloseInfo) => void): (() => void) => {
      const ch = `ssh:close:${id}`
      const h = (_e: IpcRendererEvent, info: SshCloseInfo): void => cb(info ?? {})
      ipcRenderer.on(ch, h)
      return () => ipcRenderer.removeListener(ch, h)
    }
  },
  sftp: {
    connect: (key: string, cfg: SshConnectConfig & { serverId?: string }): Promise<SftpResult<{ home: string }>> =>
      ipcRenderer.invoke('sftp:connect', key, cfg),
    list: (key: string, path: string): Promise<SftpResult<SftpEntry[]>> =>
      ipcRenderer.invoke('sftp:list', key, path),
    read: (key: string, path: string): Promise<SftpResult<string>> =>
      ipcRenderer.invoke('sftp:read', key, path),
    write: (key: string, path: string, content: string): Promise<SftpResult> =>
      ipcRenderer.invoke('sftp:write', key, path, content),
    mkdir: (key: string, path: string): Promise<SftpResult> => ipcRenderer.invoke('sftp:mkdir', key, path),
    rename: (key: string, from: string, to: string): Promise<SftpResult> =>
      ipcRenderer.invoke('sftp:rename', key, from, to),
    remove: (key: string, path: string, dir: boolean): Promise<SftpResult> =>
      ipcRenderer.invoke('sftp:delete', key, path, dir),
    upload: (key: string, localPaths: string[], remoteDir: string): Promise<SftpResult<SftpUploadSummary>> =>
      ipcRenderer.invoke('sftp:upload', key, localPaths, remoteDir),
    // Dropped files only carry a path via webUtils; File.path was removed in
    // Electron 32.
    pathFor: (file: File): string => webUtils.getPathForFile(file),
    onProgress: (cb: (p: SftpProgress) => void): (() => void) => {
      const h = (_e: IpcRendererEvent, p: SftpProgress): void => cb(p)
      ipcRenderer.on('sftp:progress', h)
      return () => ipcRenderer.removeListener('sftp:progress', h)
    },
    disconnect: (key: string): Promise<void> => ipcRenderer.invoke('sftp:disconnect', key),
    editExternal: (
      key: string,
      path: string,
      command: string
    ): Promise<{ ok: boolean; error?: string; localPath?: string }> =>
      ipcRenderer.invoke('sftp:edit-external', key, path, command),
    stopExternal: (path: string): Promise<void> =>
      ipcRenderer.invoke('sftp:edit-external-stop', path),
    onExternalSaved: (
      cb: (r: { remotePath: string; ok: boolean; error?: string }) => void
    ): (() => void) => {
      const h = (_e: IpcRendererEvent, r: { remotePath: string; ok: boolean; error?: string }): void =>
        cb(r)
      ipcRenderer.on('sftp:external-saved', h)
      return () => ipcRenderer.removeListener('sftp:external-saved', h)
    }
  },
  metrics: {
    sample: (key: string, cfg: SshConnectConfig & { serverId?: string }): Promise<MetricsResult> =>
      ipcRenderer.invoke('metrics:sample', key, cfg),
    disconnect: (key: string): Promise<void> => ipcRenderer.invoke('metrics:disconnect', key)
  },
  db: {
    test: (cfg: DbConnectConfig): Promise<DbTestResult> => ipcRenderer.invoke('db:test', cfg),
    query: (cfg: DbConnectConfig, text: string): Promise<DbQueryResult> =>
      ipcRenderer.invoke('db:query', cfg, text),
    info: (cfg: DbConnectConfig): Promise<DbInfo> => ipcRenderer.invoke('db:info', cfg),
    shell: (cfg: DbConnectConfig, line: string): Promise<DbShellResult> =>
      ipcRenderer.invoke('db:shell', cfg, line),
    close: (id: string): Promise<void> => ipcRenderer.invoke('db:close', id)
  },
  notify: {
    show: (title: string, body: string): Promise<boolean> =>
      ipcRenderer.invoke('notify:show', title, body)
  },
  backup: {
    export: (password: string): Promise<BackupResult> => ipcRenderer.invoke('backup:export', password),
    inspect: (password: string, path?: string): Promise<BackupResult> =>
      ipcRenderer.invoke('backup:inspect', password, path),
    import: (password: string, path: string): Promise<BackupResult> =>
      ipcRenderer.invoke('backup:import', password, path),
    deleteAll: (): Promise<BackupResult> => ipcRenderer.invoke('backup:deleteAll'),
    relaunch: (): Promise<void> => ipcRenderer.invoke('backup:relaunch')
  },
  updater: {
    check: (): Promise<void> => ipcRenderer.invoke('updater:check'),
    status: (): Promise<UpdaterStatus> => ipcRenderer.invoke('updater:status'),
    install: (): Promise<void> => ipcRenderer.invoke('updater:install'),
    openReleasePage: (): Promise<void> => ipcRenderer.invoke('updater:openReleasePage'),
    onStatus: (cb: (s: UpdaterStatus) => void): (() => void) => {
      const h = (_e: IpcRendererEvent, s: UpdaterStatus): void => cb(s)
      ipcRenderer.on('updater:status-event', h)
      return () => ipcRenderer.removeListener('updater:status-event', h)
    }
  },
  sshConfig: {
    read: (): Promise<{ ok: boolean; path: string; hosts?: SshConfigHost[]; error?: string }> =>
      ipcRenderer.invoke('sshconfig:read')
  },
  knownHosts: {
    list: (): Promise<KnownHost[]> => ipcRenderer.invoke('knownhosts:list'),
    forget: (id: string): Promise<void> => ipcRenderer.invoke('knownhosts:forget', id)
  },
  tunnel: {
    start: (cfg: TunnelConfig, ssh: TunnelSshConfig): Promise<TunnelResult> =>
      ipcRenderer.invoke('tunnel:start', cfg, ssh),
    stop: (id: string): Promise<void> => ipcRenderer.invoke('tunnel:stop', id),
    list: (): Promise<TunnelStatus[]> => ipcRenderer.invoke('tunnel:list'),
    onStatus: (id: string, cb: (s: TunnelStatus) => void): (() => void) => {
      const ch = `tunnel:status:${id}`
      const h = (_e: IpcRendererEvent, s: TunnelStatus): void => cb(s)
      ipcRenderer.on(ch, h)
      return () => ipcRenderer.removeListener(ch, h)
    }
  },
  vault: {
    status: (): Promise<VaultStatus> => ipcRenderer.invoke('vault:status'),
    create: (password: string): Promise<VaultResult> => ipcRenderer.invoke('vault:create', password),
    unlock: (password: string): Promise<VaultResult> => ipcRenderer.invoke('vault:unlock', password),
    lock: (): Promise<VaultResult> => ipcRenderer.invoke('vault:lock'),
    list: (): Promise<VaultListResult> => ipcRenderer.invoke('vault:list'),
    save: (entries: VaultEntry[]): Promise<VaultResult> => ipcRenderer.invoke('vault:save', entries),
    changePassword: (current: string, next: string): Promise<VaultResult> =>
      ipcRenderer.invoke('vault:change-password', current, next),
    destroy: (): Promise<VaultResult> => ipcRenderer.invoke('vault:destroy'),
    bioSupport: (): Promise<{ available: boolean; kind: string; reason?: string }> =>
      ipcRenderer.invoke('vault:bio-support'),
    bioEnabled: (): Promise<boolean> => ipcRenderer.invoke('vault:bio-enabled'),
    bioEnable: (scope: 'session' | 'persistent' = 'session'): Promise<VaultResult> =>
      ipcRenderer.invoke('vault:bio-enable', scope),
    bioScope: (): Promise<'session' | 'persistent' | null> => ipcRenderer.invoke('vault:bio-scope'),
    setAutoLock: (minutes: number): Promise<void> => ipcRenderer.invoke('vault:set-auto-lock', minutes),
    onAutoLocked: (cb: () => void): (() => void) => {
      const h = (): void => cb()
      ipcRenderer.on('vault:auto-locked', h)
      return () => ipcRenderer.removeListener('vault:auto-locked', h)
    },
    bioDisable: (): Promise<VaultResult> => ipcRenderer.invoke('vault:bio-disable'),
    bioUnlock: (): Promise<VaultResult> => ipcRenderer.invoke('vault:bio-unlock')
  },
  workspaceLock: {
    ids: (): Promise<string[]> => ipcRenderer.invoke('wslock:ids'),
    verify: (id: string, password: string): Promise<boolean> =>
      ipcRenderer.invoke('wslock:verify', id, password),
    set: (id: string, password: string, current?: string): Promise<{ ok: boolean; error?: string }> =>
      ipcRenderer.invoke('wslock:set', id, password, current),
    remove: (id: string, current: string): Promise<{ ok: boolean; error?: string }> =>
      ipcRenderer.invoke('wslock:remove', id, current),
    delete: (id: string): Promise<void> => ipcRenderer.invoke('wslock:delete', id)
  },
  secrets: {
    available: (): Promise<boolean> => ipcRenderer.invoke('secrets:available'),
    set: (id: string, value: string): Promise<boolean> => ipcRenderer.invoke('secrets:set', id, value),
    delete: (id: string): Promise<void> => ipcRenderer.invoke('secrets:delete', id)
  },
  data: {
    load: <T>(): Promise<T | null> => ipcRenderer.invoke('data:load'),
    save: (data: unknown): Promise<void> => ipcRenderer.invoke('data:save', data)
  },
  aiPolicy: {
    listGroups: (): Promise<AccessGroup[]> => ipcRenderer.invoke('aiPolicy:listGroups'),
    createGroup: (name: string): Promise<AccessGroup> => ipcRenderer.invoke('aiPolicy:createGroup', name),
    saveGroup: (group: AccessGroup): Promise<AccessGroup> => ipcRenderer.invoke('aiPolicy:saveGroup', group),
    deleteGroup: (id: string): Promise<{ ok: boolean; error?: string }> =>
      ipcRenderer.invoke('aiPolicy:deleteGroup', id),
    listAssignments: (): Promise<PolicyAssignment[]> => ipcRenderer.invoke('aiPolicy:listAssignments'),
    setAssignment: (scope: PolicyAssignment['scope'], groupId: string | null): Promise<PolicyAssignment> =>
      ipcRenderer.invoke('aiPolicy:setAssignment', scope, groupId),
    removeAssignment: (id: string): Promise<void> => ipcRenderer.invoke('aiPolicy:removeAssignment', id),
    listServerMeta: (): Promise<ServerAiMeta[]> => ipcRenderer.invoke('aiPolicy:listServerMeta'),
    setServerAliases: (serverId: string, aliases: string[]): Promise<ServerAiMeta> =>
      ipcRenderer.invoke('aiPolicy:setServerAliases', serverId, aliases),
    listWorkspaces: (): Promise<{ id: string; name: string }[]> => ipcRenderer.invoke('aiPolicy:listWorkspaces'),
    listServers: (workspaceId?: string): Promise<{ id: string; workspaceId: string; name: string }[]> =>
      ipcRenderer.invoke('aiPolicy:listServers', workspaceId)
  },
  aiMcp: {
    getConfig: (): Promise<McpGlobalConfig> => ipcRenderer.invoke('aiMcp:getConfig'),
    setConfig: (
      patch: Partial<McpGlobalConfig>
    ): Promise<{ config: McpGlobalConfig; error?: string }> => ipcRenderer.invoke('aiMcp:setConfig', patch),
    status: (): Promise<{ running: boolean; port: number | null }> => ipcRenderer.invoke('aiMcp:status'),
    createSession: (input: {
      agentName: string
      workspaces: { id: string; name: string }[]
      groupId: string | null
      groupName: string
      ttlMinutes: number | null
    }): Promise<{ session: McpAgentSession; token: string }> => ipcRenderer.invoke('aiMcp:createSession', input),
    listSessions: (): Promise<McpAgentSession[]> => ipcRenderer.invoke('aiMcp:listSessions'),
    revokeSession: (id: string): Promise<void> => ipcRenderer.invoke('aiMcp:revokeSession', id),
    deleteSession: (id: string): Promise<boolean> => ipcRenderer.invoke('aiMcp:deleteSession', id),
    setSessionGroup: (id: string, groupId: string | null, groupName: string): Promise<McpAgentSession | null> =>
      ipcRenderer.invoke('aiMcp:setSessionGroup', id, groupId, groupName),
    explainAccess: (
      sessionId: string,
      serverId: string | null
    ): Promise<
      {
        capability: string
        label: string
        decision: 'allow' | 'ask' | 'deny'
        reason: string
        fromScope: 'allow' | 'ask' | 'deny'
        fromSession: 'allow' | 'ask' | 'deny' | null
        decidedBy: 'scope' | 'session' | 'both'
      }[] | null
    > => ipcRenderer.invoke('aiMcp:explainAccess', sessionId, serverId),
    killAllSessions: (): Promise<{ revoked: number; denied: number }> =>
      ipcRenderer.invoke('aiMcp:killAllSessions'),
    listApprovals: (): Promise<ApprovalRequest[]> => ipcRenderer.invoke('aiMcp:listApprovals'),
    respondApproval: (id: string, decision: 'approved' | 'denied'): Promise<boolean> =>
      ipcRenderer.invoke('aiMcp:respondApproval', id, decision),
    listAudit: (limit?: number): Promise<AuditEntry[]> => ipcRenderer.invoke('aiMcp:listAudit', limit),
    onApprovalEvent: (
      cb: (e: { type: 'created' | 'resolved'; request: ApprovalRequest }) => void
    ): (() => void) => {
      const h = (_e: IpcRendererEvent, ev: { type: 'created' | 'resolved'; request: ApprovalRequest }): void => cb(ev)
      ipcRenderer.on('ai:approval-event', h)
      return () => ipcRenderer.removeListener('ai:approval-event', h)
    },
    claudeCodeCommand: (token: string, port: number): Promise<string> =>
      ipcRenderer.invoke('aiMcp:claudeCodeCommand', token, port),
    writeClaudeDesktopConfig: (
      token: string,
      port: number
    ): Promise<{ ok: boolean; path: string; backedUpTo?: string; error?: string }> =>
      ipcRenderer.invoke('aiMcp:writeClaudeDesktopConfig', token, port),
    writeCodexConfig: (
      token: string,
      port: number
    ): Promise<{ ok: boolean; path: string; backedUpTo?: string; error?: string }> =>
      ipcRenderer.invoke('aiMcp:writeCodexConfig', token, port),
    onCreateServerRequest: (
      cb: (e: { id: string; request: Record<string, unknown> }) => void
    ): (() => void) => {
      const h = (_e: IpcRendererEvent, ev: { id: string; request: Record<string, unknown> }): void => cb(ev)
      ipcRenderer.on('aiMcp:create-server', h)
      return () => ipcRenderer.removeListener('aiMcp:create-server', h)
    },
    replyCreateServer: (id: string, result: { ok: boolean; serverId?: string; error?: string }): void =>
      ipcRenderer.send('aiMcp:create-server-reply', id, result),
    cancelPairing: (id: string): Promise<void> => ipcRenderer.invoke('aiMcp:cancelPairing', id),
    onPairingEvent: (
      cb: (e: { type: 'created' | 'resolved' | 'expired'; request: CliPairingRequest }) => void
    ): (() => void) => {
      const h = (
        _e: IpcRendererEvent,
        ev: { type: 'created' | 'resolved' | 'expired'; request: CliPairingRequest }
      ): void => cb(ev)
      ipcRenderer.on('ai:pairing-event', h)
      return () => ipcRenderer.removeListener('ai:pairing-event', h)
    }
  }
}

contextBridge.exposeInMainWorld('shellpilot', api)

export type ShellPilotApi = typeof api
