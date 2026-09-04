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
import type {
  AccessChangePreview,
  AccessRunRequest,
  AccessRunResult,
  HostAccess
} from '../shared/access'
import type { HostFacts } from '../shared/hostFacts'
import type { HostPosture } from '../shared/posture'
import type { FleetSampleEvent, FleetSamplerConfig, FleetSamplerStatus } from '../shared/fleet'
import type { BroadcastHostResult, BroadcastProgress, BroadcastRequest } from '../shared/broadcast'
import type {
  JobDetail,
  JobHostCapabilityReport,
  JobOutput,
  JobProgress,
  JobRecord,
  JobRunRequest,
  JobsBridge
} from '../shared/jobs'
import type { LogLine, LogSource, LogTailState, UnitChoice } from '../shared/logtail'
import type { CronEntry, CronSourceReport } from '../shared/cron'
import type { CapacityBridge, CapacityReport } from '../shared/capacity'
import type { HostDrift } from '../shared/drift'
import type { RuleDraftWire, RuleView, RulesBridge } from '../shared/rules'
import type { ChangeLogBridge, ChangeLogFilter, ChangeLogPage } from '../shared/changelog'
import type { RunbookNote, RunbookView, RunbooksBridge } from '../shared/runbooks'
import type { StoreAlertKind } from '../shared/webhook'
import type {
  DockerAction,
  DockerActionResult,
  DockerBridge,
  DockerDiskDetailProbe,
  DockerDiskProbe,
  DockerInspectProbe,
  DockerLogsOptions,
  DockerProbe,
  DockerStatsProbe
} from '../shared/docker'
import type {
  ComposeBridge,
  ComposeConfigProbe,
  ComposeEnvProbe,
  ComposeImageWriteRequest,
  ComposeImageWriteResult,
  ComposeListProbe,
  ComposeProjectRef
} from '../shared/compose'
import type {
  K8sDiagnosis,
  K8sOverview,
  K8sProbe,
  K8sRolloutResult,
  K8sRolloutTarget,
  K8sUsage
} from '../shared/kubernetes'
import type {
  AlertPayload,
  StoredAlertEvent,
  StoredAlertRow,
  StoredDbAlertRow,
  WebhookConfig,
  WebhookDeliveryStatus,
  WebhookTestResult
} from '../shared/webhook'
import type { CredProxyCall, CredProxyRule, CredProxyStatus } from '../shared/credproxy'
import type {
  LocalCloseInfo,
  LocalConnectConfig,
  LocalShell,
  LocalStatus
} from '../shared/local'

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
import type { DbOpsReport } from '../shared/dbOps'
import type { VaultEntry, VaultListResult, VaultResult, VaultStatus } from '../shared/vault'
import type { TunnelConfig, TunnelResult, TunnelSshConfig, TunnelStatus } from '../shared/tunnel'
import type {
  VpnDependent,
  VpnEngineInfo,
  VpnImportResult,
  VpnKeygenResult,
  VpnMintResult,
  VpnKind,
  VpnLogLine,
  VpnProfile,
  VpnPrompt,
  VpnPublicKeyResult,
  VpnResult,
  VpnSpec,
  VpnStartResult,
  VpnStatus,
  VpnValidation
} from '../shared/vpn'
import type { KnownHost } from '../main/services/knownhosts'
import type { SshConfigHost } from '../shared/sshconfig'
import type {
  BackupDestination,
  BackupResult,
  BackupRunReport,
  BackupTargetsFile,
  DumpEngine,
  DumpRunReport,
  RemoteListResult
} from '../shared/backup'
import type { UpdatePrefs, UpdaterCapabilities, UpdaterStatus } from '../shared/updater'
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

// Declared out here rather than inline in `api` so it can carry the JobsBridge
// annotation. See the comment at `jobs:` below for why the annotation is the
// point.
const jobsBridge: JobsBridge = {
  list: (limit?: number): Promise<JobRecord[]> => ipcRenderer.invoke('jobs:list', limit),
  get: (jobId: string): Promise<JobDetail | null> => ipcRenderer.invoke('jobs:get', jobId),
  // The request carries a `CommandApproval` — B3. It is not decoration and the
  // preload does not check it: main re-derives `planJob` over this very spec
  // and target list and refuses the run if the record disagrees, so a caller
  // that forges or omits one gets a sentence back rather than a job. Verifying
  // it here as well would be a second copy of the rule in the one place that
  // has no more information than the sender.
  run: (req: JobRunRequest): Promise<JobDetail> => ipcRenderer.invoke('jobs:run', req),
  cancel: (jobId: string): Promise<boolean> => ipcRenderer.invoke('jobs:cancel', jobId),
  // Pushed from the renderer's settings the way ssh.setPoolIdle is, because
  // that is where the switch the user flicks lives. Main holds the value and
  // the detached executor reads it per LAUNCH, so turning it off never
  // interferes with a job already running — and a job being reclaimed after a
  // restart is followed to its end either way, because there is a real process
  // on that host whatever this switch now says.
  setDetached: (enabled: boolean): Promise<void> =>
    ipcRenderer.invoke('jobs:setDetached', enabled),
  capabilities: (): Promise<JobHostCapabilityReport[]> => ipcRenderer.invoke('jobs:capabilities'),
  onProgress: (fn: (p: JobProgress) => void): (() => void) => {
    const h = (_e: IpcRendererEvent, p: JobProgress): void => fn(p)
    ipcRenderer.on('jobs:progress', h)
    return () => ipcRenderer.removeListener('jobs:progress', h)
  },
  // A separate channel from progress, not a variant of it. Output is high
  // volume and coalesced per tick; job and host transitions are rare and must
  // never be dropped behind a burst of apt chatter. One channel would make the
  // state machine share a queue with the noise.
  onOutput: (fn: (o: JobOutput) => void): (() => void) => {
    const h = (_e: IpcRendererEvent, o: JobOutput): void => fn(o)
    ipcRenderer.on('jobs:output', h)
    return () => ipcRenderer.removeListener('jobs:output', h)
  }
}

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
  // Mirrors `ssh` above, channel for channel, but a separate namespace rather
  // than one with a `kind` discriminator: the two take different configs, and a
  // union the renderer has to narrow at every call site is how a local session
  // ends up in a code path that tries to dial it.
  //
  // Nothing here is reachable from the MCP bridge or the CLI, deliberately.
  // tests/localTerminalNotExposed.test.ts is what keeps that true.
  local: {
    shells: (refresh?: boolean): Promise<LocalShell[]> =>
      ipcRenderer.invoke('local:shells', refresh),
    connect: (cfg: LocalConnectConfig): Promise<void> => ipcRenderer.invoke('local:connect', cfg),
    write: (id: string, data: string): void => ipcRenderer.send('local:write', id, data),
    // Reports how many UTF-16 code units the terminal has actually parsed, which
    // is what lets main stop reading the pty when the renderer falls behind.
    // Code units, not bytes: main counts the same unit on the way out, and
    // mixing the two accrues a deficit that never repays and wedges the session.
    ack: (id: string, units: number): void => ipcRenderer.send('local:ack', id, units),
    resize: (id: string, cols: number, rows: number): void =>
      ipcRenderer.send('local:resize', id, cols, rows),
    close: (id: string): void => ipcRenderer.send('local:close', id),
    onData: (id: string, cb: (data: string) => void): (() => void) => {
      const ch = `local:data:${id}`
      const h = (_e: IpcRendererEvent, d: string): void => cb(d)
      ipcRenderer.on(ch, h)
      return () => ipcRenderer.removeListener(ch, h)
    },
    onStatus: (id: string, cb: (s: LocalStatus) => void): (() => void) => {
      const ch = `local:status:${id}`
      const h = (_e: IpcRendererEvent, s: LocalStatus): void => cb(s)
      ipcRenderer.on(ch, h)
      return () => ipcRenderer.removeListener(ch, h)
    },
    onClose: (id: string, cb: (info: LocalCloseInfo) => void): (() => void) => {
      const ch = `local:close:${id}`
      const h = (_e: IpcRendererEvent, info: LocalCloseInfo): void => cb(info ?? {})
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
  // Outbound alert delivery. The URL never comes back across this bridge —
  // `status()` reports only whether one is set, because it is a bearer
  // credential and the renderer has no use for its value.
  webhook: {
    status: (): Promise<WebhookConfig> => ipcRenderer.invoke('webhook:status'),
    delivery: (): Promise<WebhookDeliveryStatus> => ipcRenderer.invoke('webhook:delivery'),
    configure: (cfg: { enabled: boolean; notifyOnResolved: boolean }): Promise<WebhookConfig> =>
      ipcRenderer.invoke('webhook:configure', cfg),
    setUrl: (url: string): Promise<{ ok: boolean; error?: string }> =>
      ipcRenderer.invoke('webhook:set-url', url),
    test: (): Promise<WebhookTestResult> => ipcRenderer.invoke('webhook:test'),
    notify: (payload: AlertPayload): Promise<void> => ipcRenderer.invoke('webhook:notify', payload)
  },
  // The API credential proxy — roadmap item 7.
  //
  // The one credential in this bridge that deliberately travels TOWARDS the
  // renderer is `token()`. Every other secret in this app stays in main, and
  // the webhook URL a few lines above is the model: there is no getter for it
  // because the user never needs to see it. This one is different in kind —
  // it is the string the user pastes into their own script, so a token that
  // never leaves main is a proxy nobody can call. It is not an API key; it is
  // what a caller presents INSTEAD of one, and the panel says so out loud.
  //
  // The API keys themselves never appear here, in either direction. A rule
  // carries a vault entry id, and the value behind it is read in main at
  // request time and injected onto the wire.
  credproxy: {
    status: (): Promise<CredProxyStatus> => ipcRenderer.invoke('credproxy:status'),
    rules: (): Promise<CredProxyRule[]> => ipcRenderer.invoke('credproxy:rules'),
    calls: (limit?: number): Promise<CredProxyCall[]> => ipcRenderer.invoke('credproxy:calls', limit),
    saveRule: (
      draft: unknown
    ): Promise<{ ok: true; rule: CredProxyRule } | { ok: false; error: string }> =>
      ipcRenderer.invoke('credproxy:save-rule', draft),
    removeRule: (id: string): Promise<{ ok: boolean }> =>
      ipcRenderer.invoke('credproxy:remove-rule', id),
    start: (port?: number): Promise<{ ok: boolean; error?: string; status: CredProxyStatus }> =>
      ipcRenderer.invoke('credproxy:start', port),
    stop: (): Promise<CredProxyStatus> => ipcRenderer.invoke('credproxy:stop'),
    token: (): Promise<{ ok: boolean; token?: string; error?: string }> =>
      ipcRenderer.invoke('credproxy:token'),
    rotateToken: (): Promise<{ ok: boolean; token?: string; error?: string }> =>
      ipcRenderer.invoke('credproxy:rotate-token')
  },
  // The durable side of alerting — roadmap item 19b.
  //
  // Two methods, both named. `record` writes one raise or resolve; `history`
  // reads the log newest-first. There is no filter or query argument on
  // purpose: the history store's rule is that no SQL crosses its boundary, and
  // a general read surface here would be the first step to losing it.
  alerts: {
    record: (event: StoredAlertEvent, at?: number): Promise<boolean> =>
      ipcRenderer.invoke('alerts:record', event, at),
    history: (limit?: number): Promise<StoredAlertRow[]> => ipcRenderer.invoke('alerts:history', limit),
    // Item 18's database verdicts, which item 19b alerts on and does not
    // recompute. A separate named read rather than a filter argument on
    // `history`: the store's rule is named statements only, and "let the caller
    // say which kind" is the first step of the query surface that rule exists
    // to refuse.
    dbEvents: (limit?: number): Promise<StoredDbAlertRow[]> =>
      ipcRenderer.invoke('alerts:db-events', limit)
  },
  // Roadmap item 26. One method, taking a host and a window and nothing else,
  // for the same reason `alerts` above has no filter argument: a general read
  // surface here is the first step to losing the history store's rule that no
  // SQL crosses its boundary. `satisfies CapacityBridge` so a channel added to
  // the contract and forgotten here is a compile error rather than a method the
  // panel calls at runtime and finds undefined.
  capacity: {
    trends: (hostId: string, windowDays: number): Promise<CapacityReport | null> =>
      ipcRenderer.invoke('capacity:trends', hostId, windowDays)
  } satisfies CapacityBridge,
  // Roadmap item 27. Four channels and deliberately no fifth: there is no
  // `run` and no `test`, because a button that fired a rule on demand would be
  // a way to run a pinned job without the dialog that pins it.
  //
  // `create` carries a `CommandApproval` the panel minted with
  // `jobApprovalFor`, exactly as `jobs.run` does, and the preload does not
  // check it for the same reason: main re-derives `planJob` over that very spec
  // and target list — at creation AND at every firing — so a caller that forges
  // or omits one gets a refusal rather than a rule. Verifying here as well
  // would be a second copy of the rule in the one place with no more
  // information than the sender.
  //
  // `satisfies RulesBridge` so a channel added to the contract and forgotten
  // here is a compile error rather than a method the panel calls at runtime and
  // finds undefined.
  rules: {
    list: (): Promise<RuleView[]> => ipcRenderer.invoke('rules:list'),
    create: (draft: RuleDraftWire): Promise<RuleView | null> =>
      ipcRenderer.invoke('rules:create', draft),
    setEnabled: (id: string, enabled: boolean): Promise<boolean> =>
      ipcRenderer.invoke('rules:enable', id, enabled),
    remove: (id: string): Promise<boolean> => ipcRenderer.invoke('rules:remove', id)
  } satisfies RulesBridge,
  // Roadmap item 14. One method, taking a filter and returning a page, for the
  // reason `capacity` above has one: the merge, the ordering, the redaction and
  // the per-source budget all live in main, and what crosses is the ANSWER.
  //
  // There is no write beside it and there will not be one: this is a reader
  // over four append-only records, and a change log that can be edited is not
  // a change log. `satisfies ChangeLogBridge` so a method added to the contract
  // and forgotten here is a compile error rather than something the panel finds
  // undefined at runtime.
  changelog: {
    read: (filter?: ChangeLogFilter): Promise<ChangeLogPage> =>
      ipcRenderer.invoke('changelog:read', filter)
  } satisfies ChangeLogBridge,
  // Roadmap item 28. Two channels, and the third one people ask for is the
  // point of the item: there is no `run`, because a button that repeats what
  // we did last time is how an outage gets repeated deliberately. The commands
  // this returns were the right answer to a DIFFERENT incident; running one is
  // a job, with a plan and an approval, started the ordinary way.
  //
  // `read` takes a kind and a host and nothing else — no filter, no range, no
  // ordering — for the reason `alerts` and `capacity` above take none: the
  // history store's rule is named statements only, and "let the caller narrow
  // it" is the first step of the query surface that rule exists to refuse.
  runbooks: {
    read: (kind: StoreAlertKind, hostId: string | null): Promise<RunbookView> =>
      ipcRenderer.invoke('runbook:read', kind, hostId),
    saveNote: (
      kind: StoreAlertKind,
      hostId: string | null,
      text: string
    ): Promise<{ ok: boolean; note: RunbookNote | null }> =>
      ipcRenderer.invoke('runbook:save-note', kind, hostId, text)
  } satisfies RunbooksBridge,
  k8s: {
    read: (cfg: unknown, context?: string, namespace?: string): Promise<K8sProbe> =>
      ipcRenderer.invoke('k8s:read', cfg, context, namespace),
    logs: (
      cfg: unknown,
      namespace: string,
      pod: string,
      lines: number,
      context?: string
    ): Promise<{ ok: boolean; output: string; error?: string }> =>
      ipcRenderer.invoke('k8s:logs', cfg, namespace, pod, lines, context),
    // Deliberately no `previous` argument on `logs`. An unwired handler would
    // ignore the extra parameter and return CURRENT logs under a "previous"
    // label, which is worse than not offering it. Previous-container logs reach
    // the panel only through `diagnose`, where the section marker comes from
    // the command itself.
    diagnose: (
      cfg: unknown,
      namespace: string,
      pod: string,
      context?: string,
      previousLines?: number
    ): Promise<K8sDiagnosis> =>
      ipcRenderer.invoke('k8s:diagnose', cfg, namespace, pod, context, previousLines),
    overview: (cfg: unknown, context?: string, namespace?: string): Promise<K8sOverview> =>
      ipcRenderer.invoke('k8s:overview', cfg, context, namespace),
    usage: (cfg: unknown, context?: string, namespace?: string): Promise<K8sUsage> =>
      ipcRenderer.invoke('k8s:usage', cfg, context, namespace),
    rolloutRestart: (
      cfg: unknown,
      target: K8sRolloutTarget,
      confirmed: boolean
    ): Promise<K8sRolloutResult> =>
      ipcRenderer.invoke('k8s:rollout-restart', cfg, target, confirmed)
  },
  // `satisfies DockerBridge` so a channel added to the contract and forgotten
  // here is a compile error rather than a method the panel calls at runtime and
  // finds undefined.
  docker: {
    list: (cfg: unknown, opts?: { sudo?: boolean; autoSudo?: boolean }): Promise<DockerProbe> =>
      ipcRenderer.invoke('docker:list', cfg, opts),
    canSudo: (cfg: unknown): Promise<boolean> => ipcRenderer.invoke('docker:can-sudo', cfg),
    logs: (
      cfg: unknown,
      ref: string,
      lines: number,
      opts?: DockerLogsOptions
    ): Promise<{ ok: boolean; output: string; error?: string }> =>
      ipcRenderer.invoke('docker:logs', cfg, ref, lines, opts),
    disk: (cfg: unknown, opts?: { sudo?: boolean; autoSudo?: boolean }): Promise<DockerDiskProbe> =>
      ipcRenderer.invoke('docker:disk', cfg, opts),
    diskDetail: (
      cfg: unknown,
      opts?: { sudo?: boolean; autoSudo?: boolean }
    ): Promise<DockerDiskDetailProbe> => ipcRenderer.invoke('docker:disk-detail', cfg, opts),
    inspect: (
      cfg: unknown,
      ref: string,
      opts?: { sudo?: boolean; autoSudo?: boolean }
    ): Promise<DockerInspectProbe> => ipcRenderer.invoke('docker:inspect', cfg, ref, opts),
    stats: (
      cfg: unknown,
      refs: string[],
      opts?: { sudo?: boolean; autoSudo?: boolean }
    ): Promise<DockerStatsProbe> => ipcRenderer.invoke('docker:stats', cfg, refs, opts),
    act: (
      cfg: unknown,
      action: DockerAction,
      refs: string[],
      opts?: { sudo?: boolean; timeoutSec?: number }
    ): Promise<DockerActionResult> => ipcRenderer.invoke('docker:act', cfg, action, refs, opts)
  } satisfies DockerBridge,
  // The file half. `satisfies ComposeBridge` for the same reason as above: a
  // channel added to the contract and forgotten here becomes a compile error
  // rather than a method the panel calls and finds undefined.
  //
  // There is no `down`, no `rm` and no `stop` on this bridge, and no channel
  // that returns the contents of an env file. `pull` and `up -d` are absent on
  // purpose too: they are jobs, and they reach the host through the jobs bridge
  // so they inherit its approval record rather than growing a second one.
  compose: {
    list: (
      cfg: unknown,
      opts?: { sudo?: boolean; autoSudo?: boolean; search?: boolean }
    ): Promise<ComposeListProbe> => ipcRenderer.invoke('compose:list', cfg, opts),
    config: (
      cfg: unknown,
      project: ComposeProjectRef,
      opts?: { sudo?: boolean; autoSudo?: boolean }
    ): Promise<ComposeConfigProbe> => ipcRenderer.invoke('compose:config', cfg, project, opts),
    envNames: (
      cfg: unknown,
      paths: string[],
      opts?: { sudo?: boolean; autoSudo?: boolean }
    ): Promise<ComposeEnvProbe> => ipcRenderer.invoke('compose:env-names', cfg, paths, opts),
    readFile: (
      cfg: unknown,
      path: string,
      opts?: { sudo?: boolean }
    ): Promise<{ ok: boolean; text?: string; error?: string }> =>
      ipcRenderer.invoke('compose:read-file', cfg, path, opts),
    writeImageTag: (
      cfg: unknown,
      req: ComposeImageWriteRequest,
      opts?: { sudo?: boolean }
    ): Promise<ComposeImageWriteResult> =>
      ipcRenderer.invoke('compose:write-image-tag', cfg, req, opts)
  } satisfies ComposeBridge,
  cron: {
    collect: (
      targets: { serverId: string; serverName: string; cfg: unknown }[]
    ): Promise<
      {
        serverId: string
        serverName: string
        entries: CronEntry[]
        unparsed: number
        sources?: CronSourceReport[]
        error?: string
      }[]
    > => ipcRenderer.invoke('cron:collect', targets),
    // Kept beside `collect` rather than in a namespace of its own, because the
    // panel checks for these at runtime: a main process that has not been
    // taught the channels answers nothing, and an edit button that does nothing
    // is worse than no edit button.
    planEdit: (
      target: { serverId: string; serverName: string; cfg: unknown },
      edit: unknown,
      opts?: unknown
    ): Promise<unknown> => ipcRenderer.invoke('cron:plan-edit', target, edit, opts),
    write: (
      target: { serverId: string; serverName: string; cfg: unknown },
      req: { before: string; after: string; token: string; runId: string; approval?: unknown }
    ): Promise<unknown> => ipcRenderer.invoke('cron:write-edit', target, req)
  },
  logtail: {
    start: (
      tailId: string,
      source: LogSource,
      targets: { serverId: string; serverName: string; cfg: unknown }[]
    ): Promise<{ ok: boolean; error?: string }> => ipcRenderer.invoke('logtail:start', tailId, source, targets),
    stop: (tailId: string): Promise<boolean> => ipcRenderer.invoke('logtail:stop', tailId),
    units: (cfg: unknown): Promise<{ ok: boolean; units: UnitChoice[]; error?: string }> =>
      ipcRenderer.invoke('logtail:units', cfg),
    logfiles: (cfg: unknown): Promise<{ ok: boolean; files: string[]; error?: string }> =>
      ipcRenderer.invoke('logtail:logfiles', cfg),
    pause: (tailId: string): Promise<boolean> => ipcRenderer.invoke('logtail:pause', tailId),
    resume: (tailId: string): Promise<boolean> => ipcRenderer.invoke('logtail:resume', tailId),
    onLine: (fn: (l: LogLine) => void): (() => void) => {
      const h = (_e: unknown, l: LogLine): void => fn(l)
      ipcRenderer.on('logtail:line', h)
      return () => ipcRenderer.removeListener('logtail:line', h)
    },
    onState: (fn: (s: LogTailState) => void): (() => void) => {
      const h = (_e: unknown, s: LogTailState): void => fn(s)
      ipcRenderer.on('logtail:state', h)
      return () => ipcRenderer.removeListener('logtail:state', h)
    }
  },
  broadcast: {
    run: (req: BroadcastRequest): Promise<BroadcastHostResult[]> => ipcRenderer.invoke('broadcast:run', req),
    cancel: (runId: string): Promise<boolean> => ipcRenderer.invoke('broadcast:cancel', runId),
    onProgress: (fn: (p: BroadcastProgress) => void): (() => void) => {
      const h = (_e: unknown, p: BroadcastProgress): void => fn(p)
      ipcRenderer.on('broadcast:progress', h)
      return () => ipcRenderer.removeListener('broadcast:progress', h)
    }
  },
  // Roadmap item B1. A broadcast that outlives its panel: the row is in the
  // store before the first host is touched, so closing the window loses the
  // view and not the record.
  //
  // Annotated against JobsBridge rather than left to `typeof api` to infer.
  // Main and the preload are two halves of one interface and nothing else
  // checks that they agree: a handler added in one and forgotten in the other
  // is `undefined is not a function` the first time someone presses the button,
  // in a packaged app, with no stack worth reading. With the annotation it is a
  // compile error in both directions — a missing method fails to satisfy the
  // interface, an extra one is an excess property.
  jobs: jobsBridge,
  // Background sampling of the whole estate, scheduled in main so it continues
  // when the monitor is not on screen. `metrics` above is the foreground path:
  // one server, fast cadence, driven by a mounted card.
  fleet: {
    configure: (cfg: FleetSamplerConfig): Promise<FleetSamplerStatus> =>
      ipcRenderer.invoke('fleet:configure', cfg),
    status: (): Promise<FleetSamplerStatus> => ipcRenderer.invoke('fleet:status'),
    sampleNow: (): Promise<FleetSamplerStatus> => ipcRenderer.invoke('fleet:sample-now'),
    // Host facts as the sampler last collected them — roadmap item C. Read-only
    // and never a trigger: `at` is when the collection happened and is normally
    // much older than a metrics sample, because facts are collected hourly.
    // `error` is set independently of the metrics error, since a host can
    // answer a metrics sample perfectly and still refuse this probe.
    facts: (
      serverId: string
    ): Promise<{ facts?: HostFacts; at?: number; error?: string; errorAt?: number; intervalMs: number }> =>
      ipcRenderer.invoke('fleet:facts', serverId),
    // Who can get into a server, as the sampler last collected it — roadmap
    // item 23. Read-only and never a trigger, exactly like `facts`.
    //
    // `access` absent with no `error` means the probe has not run for this
    // server yet. That is a THIRD state, distinct from both "collected, and it
    // trusts no keys" and "the collection failed", and the panel has to keep it
    // distinct — a host nobody has looked at is not a host with no keys.
    access: (
      serverId: string
    ): Promise<{ access?: HostAccess; at?: number; error?: string; errorAt?: number; intervalMs: number }> =>
      ipcRenderer.invoke('fleet:access', serverId),
    // A server's security posture, as the sampler last collected it — roadmap
    // item 24. Read-only and never a trigger, exactly like `facts` and
    // `access`, and with the same third state: `posture` absent with no `error`
    // means the probe has not run for this server yet. A host nobody has looked
    // at is not a host with no firewall, and the panel keeps the two apart.
    //
    // There is no write beside this and there is not going to be one casually.
    // src/shared/posture.ts states the refusal in full: every button this
    // panel could grow — `ufw enable`, `setenforce`, an sshd_config edit — can
    // lock the operator out of the host they would use to undo it, with none
    // of the dead-man's switch that earns `accessRun` its place above.
    posture: (
      serverId: string
    ): Promise<{ posture?: HostPosture; at?: number; error?: string; errorAt?: number; intervalMs: number }> =>
      ipcRenderer.invoke('fleet:posture', serverId),
    // A server's watched configuration files, as the sampler last collected
    // them — roadmap item 25. Read-only and never a trigger, exactly like
    // `facts`, `access` and `posture`, and with the same third state: `drift`
    // absent with no `error` means the probe has not run for this server yet.
    // A host nobody has looked at is not a host whose configuration matches
    // everybody else's, and the comparison keeps the two apart.
    //
    // Each reading carries two hashes and a BOUNDED, ALREADY-REDACTED preview.
    // The preview lives in the sampler's memory and nowhere else — it is not in
    // the durable store and does not survive a restart.
    //
    // There is no write beside this and there is not going to be one.
    // src/shared/drift.ts states the refusal in full: bringing a host into line
    // is a job, and it goes through the plan and the approval a job carries.
    // This panel could not decide which side is right in any case — a host that
    // was fixed first and a host that drifted look identical from here.
    drift: (
      serverId: string
    ): Promise<{ drift?: HostDrift; at?: number; error?: string; errorAt?: number; intervalMs: number }> =>
      ipcRenderer.invoke('fleet:drift', serverId),
    // Changing who can get in — roadmap item 23, the write half.
    //
    // TWO CALLS AND NOT ONE, on purpose. `accessPlan` asks main what a change
    // would do and what it refuses to do; `accessRun` carries back the command
    // text the operator was shown, and main will not touch a host unless that
    // matches what it derives for itself. A single "revoke this key" call would
    // have nothing to compare, which is precisely the state broadcast was in
    // before B3.
    //
    // `accessRun` is a WRITE and the only one on this bridge that edits an
    // authorized_keys file. It stages behind the host's own rollback and
    // confirms over a session that authenticated afterwards; a host that never
    // gets that confirmation puts its previous file back by itself. The three
    // outcomes it can report are not two — see AccessCommitOutcome.
    accessPlan: (
      req: Omit<AccessRunRequest, 'token' | 'confirmedCommand'>
    ): Promise<AccessChangePreview> => ipcRenderer.invoke('access:plan', req),
    accessRun: (req: AccessRunRequest): Promise<AccessRunResult> =>
      ipcRenderer.invoke('access:run', req),
    onSample: (cb: (event: FleetSampleEvent) => void): (() => void) => {
      const h = (_e: IpcRendererEvent, event: FleetSampleEvent): void => cb(event)
      ipcRenderer.on('fleet:sample', h)
      return () => ipcRenderer.removeListener('fleet:sample', h)
    }
  },
  db: {
    test: (cfg: DbConnectConfig): Promise<DbTestResult> => ipcRenderer.invoke('db:test', cfg),
    query: (cfg: DbConnectConfig, text: string): Promise<DbQueryResult> =>
      ipcRenderer.invoke('db:query', cfg, text),
    info: (cfg: DbConnectConfig): Promise<DbInfo> => ipcRenderer.invoke('db:info', cfg),
    shell: (cfg: DbConnectConfig, line: string): Promise<DbShellResult> =>
      ipcRenderer.invoke('db:shell', cfg, line),
    close: (id: string): Promise<void> => ipcRenderer.invoke('db:close', id),
    // Read-only operational answers for PostgreSQL and MySQL/MariaDB. There is
    // no write counterpart and there is not meant to be one.
    ops: (cfg: DbConnectConfig): Promise<DbOpsReport> => ipcRenderer.invoke('db:ops', cfg)
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
    relaunch: (): Promise<void> => ipcRenderer.invoke('backup:relaunch'),
    // Destinations. Note what is NOT here: no credential, in either direction.
    // An SFTP destination names a saved server and an S3 one names a vault
    // entry, and main resolves both — so the renderer can configure where the
    // vault gets uploaded without ever holding the key to the place it lands.
    destinations: (): Promise<BackupTargetsFile> => ipcRenderer.invoke('backup:destinations'),
    saveDestinations: (destinations: BackupDestination[]): Promise<BackupTargetsFile> =>
      ipcRenderer.invoke('backup:saveDestinations', destinations),
    runDestination: (id: string, password: string): Promise<BackupRunReport> =>
      ipcRenderer.invoke('backup:runDestination', id, password),
    listRemote: (id: string): Promise<RemoteListResult> => ipcRenderer.invoke('backup:listRemote', id),
    inspectRemote: (id: string, name: string, password: string): Promise<BackupResult> =>
      ipcRenderer.invoke('backup:inspectRemote', id, name, password),
    discardStaged: (path: string): Promise<void> => ipcRenderer.invoke('backup:discardStaged', path),
    chooseDirectory: (): Promise<string | null> => ipcRenderer.invoke('backup:chooseDirectory'),
    dumpableDatabases: (): Promise<{ id: string; name: string; engine: DumpEngine }[]> =>
      ipcRenderer.invoke('backup:dumpableDatabases'),
    dumpDatabase: (destinationId: string, databaseId: string): Promise<DumpRunReport> =>
      ipcRenderer.invoke('backup:dumpDatabase', destinationId, databaseId)
  },
  updater: {
    check: (): Promise<void> => ipcRenderer.invoke('updater:check'),
    status: (): Promise<UpdaterStatus> => ipcRenderer.invoke('updater:status'),
    install: (): Promise<void> => ipcRenderer.invoke('updater:install'),
    openReleasePage: (): Promise<void> => ipcRenderer.invoke('updater:openReleasePage'),
    download: (): Promise<void> => ipcRenderer.invoke('updater:download'),
    getPrefs: (): Promise<UpdatePrefs> => ipcRenderer.invoke('updater:getPrefs'),
    setPrefs: (patch: Partial<UpdatePrefs>): Promise<UpdatePrefs> =>
      ipcRenderer.invoke('updater:setPrefs', patch),
    capabilities: (): Promise<UpdaterCapabilities> => ipcRenderer.invoke('updater:capabilities'),
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
  vpn: {
    list: (): Promise<VpnStatus[]> => ipcRenderer.invoke('vpn:list'),
    start: (id: string): Promise<VpnStartResult> => ipcRenderer.invoke('vpn:start', id),
    // Returns the result rather than discarding it: a stop can fail (an engine
    // that will not exit), and a caller that cannot see that will cheerfully
    // report "stopped" over the top of an error.
    stop: (id: string, force = false): Promise<VpnResult> =>
      ipcRenderer.invoke('vpn:stop', id, force),
    reload: (id: string): Promise<VpnResult> => ipcRenderer.invoke('vpn:reload', id),
    validate: (spec: VpnSpec): Promise<VpnValidation> => ipcRenderer.invoke('vpn:validate', spec),
    probe: (kind: VpnKind): Promise<VpnEngineInfo> => ipcRenderer.invoke('vpn:probe', kind),
    // Returns vault refs, never key material: the main-process handler stores
    // the secrets and hands back pointers.
    import: (kind: VpnKind, text: string, baseDir?: string): Promise<VpnImportResult> =>
      ipcRenderer.invoke('vpn:import', kind, text, baseDir),
    // The profile's secrets, staged into the vault. Called once when a profile
    // is created from an import.
    commitImport: (
      profileName: string,
      workspaceId: string,
      kind: VpnKind,
      text: string,
      baseDir?: string
    ): Promise<{ ok: boolean; error?: string; spec?: VpnSpec; vaultEntryId?: string }> =>
      ipcRenderer.invoke('vpn:commitImport', profileName, workspaceId, kind, text, baseDir),
    logs: (id: string, limit?: number): Promise<VpnLogLine[]> =>
      ipcRenderer.invoke('vpn:logs', id, limit),
    dependents: (id: string): Promise<VpnDependent[]> => ipcRenderer.invoke('vpn:dependents', id),
    // A WireGuard keypair, stored the same way an imported one is: the main
    // handler puts the private key in the vault and hands back a ref. The key
    // itself comes back too, so the user can reveal and copy the one they just
    // made — nothing persists it, and `privateKeyRef` is the only part that
    // goes on the profile.
    //
    // Store a key in the vault and hand back the ref the profile carries.
    //
    // `privateKey` is required: this channel no longer mints. Minting moved to
    // `wireguardMint` below so that generating a key and cancelling the form
    // leaves nothing behind, which means every call here is a deliberate write.
    // `replaces` is the entry this profile pointed at before, released once the
    // new one is safely written.
    wireguardKeygen: (req: {
      profileName: string
      workspaceId: string
      privateKey: string
      replaces?: string
    }): Promise<VpnKeygenResult> => ipcRenderer.invoke('vpn:wireguardKeygen', req),
    // Mint a keypair and store nothing. Separate from `wireguardKeygen` above
    // because that one writes to the vault: the form generates through this,
    // holds the pair, and stages it through the other only on Save — so
    // cancelling a dialog leaves no entry behind.
    wireguardMint: (): Promise<VpnMintResult> => ipcRenderer.invoke('vpn:wireguardMint'),
    // `wg pubkey`. No vault write and no side effect, so it is safe to call
    // while the user is still typing a key in.
    wireguardPublicKey: (privateKey: string): Promise<VpnPublicKeyResult> =>
      ipcRenderer.invoke('vpn:wireguardPublicKey', privateKey),
    // Called when a profile is deleted. The profile itself lives in the
    // renderer's data blob, but its key material lives in the vault and would
    // otherwise be orphaned there with no UI pointing at it.
    deleteSecrets: (vaultEntryId: string): Promise<void> =>
      ipcRenderer.invoke('vpn:deleteSecrets', vaultEntryId),
    // Read-only. Profiles are persisted by the renderer as part of the ordinary
    // `data:save` blob, exactly like servers and tunnels — a second writer for
    // the same JSON file is how that file gets corrupted. This exists so main,
    // the MCP tools and the CLI all read the same list the UI shows, without
    // each re-deriving it.
    profiles: (): Promise<VpnProfile[]> => ipcRenderer.invoke('vpn:profiles'),
    onStatus: (id: string, cb: (s: VpnStatus) => void): (() => void) => {
      const ch = `vpn:status:${id}`
      const h = (_e: IpcRendererEvent, s: VpnStatus): void => cb(s)
      ipcRenderer.on(ch, h)
      return () => ipcRenderer.removeListener(ch, h)
    },
    // Log lines only stream while someone is subscribed; otherwise they stop
    // at the ring buffer in main and the drawer pulls them with logs().
    onLog: (id: string, cb: (l: VpnLogLine) => void): (() => void) => {
      const ch = `vpn:log:${id}`
      const h = (_e: IpcRendererEvent, l: VpnLogLine): void => cb(l)
      ipcRenderer.on(ch, h)
      ipcRenderer.send('vpn:log-subscribe', id)
      return () => {
        ipcRenderer.removeListener(ch, h)
        ipcRenderer.send('vpn:log-unsubscribe', id)
      }
    },
    onPrompt: (cb: (p: VpnPrompt) => void): (() => void) => {
      const h = (_e: IpcRendererEvent, p: VpnPrompt): void => cb(p)
      ipcRenderer.on('vpn:prompt', h)
      return () => ipcRenderer.removeListener('vpn:prompt', h)
    },
    replyPrompt: (id: string, value: string | null): void =>
      ipcRenderer.send('vpn:prompt-reply', id, value)
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
