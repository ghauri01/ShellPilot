import { createServer, type Server as HttpServer, type IncomingMessage, type ServerResponse } from 'node:http'
import { randomUUID } from 'node:crypto'
import { z } from 'zod'
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js'
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js'
import { isInitializeRequest } from '@modelcontextprotocol/sdk/types.js'
import type { CallToolResult } from '@modelcontextprotocol/sdk/types.js'

import { authenticate, getMcpConfig, type AuthFailureReason } from './mcpAuth'
import { startCliPairing, confirmCliPairing } from './cliPairing'
import { listCachedServers, listCachedWorkspaces, getCachedWorkspace, getCachedServer, serverToSshConfig } from './mcpDataCache'
import { resolveServerByName, formatAmbiguity, type ServerMatch } from './serverResolver'
import {
  resolveGroupId,
  evaluateCapability,
  evaluateCommand,
  evaluateFilePath,
  mostRestrictive,
  type Decision
} from './policyEngine'
import { getGroup, listAssignments } from './policyStore'
import { requestApproval } from './approvals'
import { recordAudit } from './auditLog'
import { redactOutput } from './secretRedaction'
import { knownSecretValuesForServer, resolveChainSecrets } from './credentialResolver'
import { sshExec } from './ssh'
import { sftpConnect, sftpList, sftpRead, sftpWrite, sftpDisconnect } from './sftp'
import { metricsSample } from './metrics'
import { AI_CAPABILITIES } from '../../shared/mcp'
import type { AccessGroup, AiCapability, McpAgentSession } from '../../shared/mcp'

function text(s: string): CallToolResult {
  return { content: [{ type: 'text', text: s }] }
}

function errorText(s: string): CallToolResult {
  return { content: [{ type: 'text', text: s }], isError: true }
}

const AUTH_MESSAGES: Record<AuthFailureReason, string> = {
  'ai-disabled': 'AI & MCP access is currently disabled in ShellPilot.',
  'missing-token': 'No bearer token was supplied. Configure this agent with the token from AI & MCP > Agents.',
  'invalid-token': 'This token is not recognized. It may have been regenerated — reconnect with the current one.',
  revoked: 'This session has been revoked from ShellPilot. Ask the user to create a new one.',
  expired: 'This session has expired. Ask the user to create a new one.'
}

interface RequestInfoLike {
  headers: Record<string, string | string[] | undefined>
}

function bearerFrom(headers: RequestInfoLike['headers']): string | null {
  const raw = headers['authorization'] ?? headers['Authorization']
  const value = Array.isArray(raw) ? raw[0] : raw
  if (!value) return null
  const m = /^Bearer\s+(.+)$/i.exec(value.trim())
  return m ? m[1] : null
}

interface ExtraLike {
  requestInfo?: RequestInfoLike
}

function authenticateExtra(extra: ExtraLike): { session: McpAgentSession } | { error: AuthFailureReason } {
  const token = extra.requestInfo ? bearerFrom(extra.requestInfo.headers) : null
  return authenticate(token)
}

function resolveServerOrError(
  session: McpAgentSession,
  serverName: string
): { match: ServerMatch } | { error: CallToolResult } {
  const servers = listCachedServers(session.workspaces.map((w) => w.id))
  const workspaces = listCachedWorkspaces()
  const result = resolveServerByName(serverName, servers, workspaces)
  if (result.type === 'not-found') {
    const names = session.workspaces.map((w) => getCachedWorkspace(w.id)?.name ?? w.name).join(', ')
    const label = session.workspaces.length > 1 ? `workspaces "${names}"` : `workspace "${names}"`
    return { error: errorText(`No server matching "${serverName}" was found in ${label}.`) }
  }
  if (result.type === 'ambiguous') {
    return { error: errorText(formatAmbiguity(result.matches)) }
  }
  return { match: result.match }
}

// The server/workspace assignment (Phase 4) decides which group governs a
// given server; the session's own group (chosen when it was created) is a
// ceiling on top of that. Every check below evaluates both sides and takes
// whichever is more restrictive — a session can never do more than either
// side allows. The group lookup is keyed on the server's OWN workspace, not
// the session's — a session can now span several workspaces, so the two are
// no longer interchangeable.
function serverGroupFor(serverId: string): AccessGroup | null {
  const server = getCachedServer(serverId)
  if (!server) return null
  const groupId = resolveGroupId(listAssignments(), serverId, server.workspaceId)
  return groupId ? getGroup(groupId) : null
}

function sessionGroupFor(session: McpAgentSession): AccessGroup | null {
  return session.groupId ? getGroup(session.groupId) : null
}

function effectiveCapability(session: McpAgentSession, serverId: string, capability: AiCapability): Decision {
  const serverGroup = serverGroupFor(serverId)
  if (!serverGroup) return { decision: 'deny', reason: 'No AI access is assigned to this server.' }
  const sessionGroup = sessionGroupFor(session)
  const fromServer = evaluateCapability(serverGroup, capability)
  if (!sessionGroup) return fromServer
  return mostRestrictive(fromServer, evaluateCapability(sessionGroup, capability))
}

function effectiveCommand(session: McpAgentSession, serverId: string, command: string): Decision {
  const serverGroup = serverGroupFor(serverId)
  if (!serverGroup) return { decision: 'deny', reason: 'No AI access is assigned to this server.' }
  const sessionGroup = sessionGroupFor(session)
  const fromServer = evaluateCommand(serverGroup, command)
  if (!sessionGroup) return fromServer
  return mostRestrictive(fromServer, evaluateCommand(sessionGroup, command))
}

function effectiveFilePath(session: McpAgentSession, serverId: string, path: string, mode: 'read' | 'write'): Decision {
  const serverGroup = serverGroupFor(serverId)
  if (!serverGroup) return { decision: 'deny', reason: 'No AI access is assigned to this server.' }
  const sessionGroup = sessionGroupFor(session)
  const fromServer = evaluateFilePath(serverGroup, path, mode)
  if (!sessionGroup) return fromServer
  return mostRestrictive(fromServer, evaluateFilePath(sessionGroup, path, mode))
}

interface AuditContext {
  session: McpAgentSession
  // The specific server's own workspace, not the session's — a session can
  // span several workspaces now, so only the resolved server's workspace is
  // correct for an audit entry about acting on it.
  workspaceId: string | null
  workspaceName: string | null
  serverId: string | null
  serverName: string | null
  action: string
  capability: AiCapability | null
}

async function gate(
  ctx: AuditContext,
  check: { decision: 'allow' | 'ask' | 'deny'; reason: string },
  risk: 'low' | 'medium' | 'high'
): Promise<{ ok: true } | { ok: false; result: CallToolResult }> {
  if (check.decision === 'deny') {
    recordAudit({
      agentName: ctx.session.agentName,
      sessionId: ctx.session.id,
      workspaceId: ctx.workspaceId,
      workspaceName: ctx.workspaceName,
      serverId: ctx.serverId,
      serverName: ctx.serverName,
      action: ctx.action,
      capability: ctx.capability,
      approval: 'not-required',
      result: 'denied',
      error: check.reason
    })
    return { ok: false, result: errorText(`Denied: ${check.reason}`) }
  }

  if (check.decision === 'ask') {
    if (!ctx.serverId || !ctx.serverName || !ctx.capability || !ctx.workspaceId || !ctx.workspaceName) {
      return { ok: false, result: errorText('Denied: this action requires approval but has no server context.') }
    }
    const decision = await requestApproval({
      sessionId: ctx.session.id,
      agentName: ctx.session.agentName,
      workspaceId: ctx.workspaceId,
      workspaceName: ctx.workspaceName,
      serverId: ctx.serverId,
      serverName: ctx.serverName,
      capability: ctx.capability,
      action: ctx.action,
      risk
    })
    if (decision !== 'approved') {
      recordAudit({
        agentName: ctx.session.agentName,
        sessionId: ctx.session.id,
        workspaceId: ctx.workspaceId,
        workspaceName: ctx.workspaceName,
        serverId: ctx.serverId,
        serverName: ctx.serverName,
        action: ctx.action,
        capability: ctx.capability,
        approval: decision,
        result: 'denied'
      })
      return {
        ok: false,
        result: errorText(
          decision === 'timeout'
            ? 'Denied: approval request timed out waiting for the user.'
            : 'Denied: the user rejected this action.'
        )
      }
    }
  }

  return { ok: true }
}

function auditSuccess(ctx: AuditContext, approval: 'not-required' | 'approved', extra: { exitCode?: number } = {}): void {
  recordAudit({
    agentName: ctx.session.agentName,
    sessionId: ctx.session.id,
    workspaceId: ctx.workspaceId,
    workspaceName: ctx.workspaceName,
    serverId: ctx.serverId,
    serverName: ctx.serverName,
    action: ctx.action,
    capability: ctx.capability,
    approval,
    result: 'success',
    exitCode: extra.exitCode
  })
}

function buildServer(): McpServer {
  const server = new McpServer({ name: 'shellpilot', version: '1.0.0' })

  server.registerTool(
    'list_workspaces',
    {
      description:
        "Lists the workspace(s) this AI session is scoped to. This never reveals a workspace outside the session's grant."
    },
    async (extra) => {
      const auth = authenticateExtra(extra)
      if ('error' in auth) return errorText(AUTH_MESSAGES[auth.error])
      const names = auth.session.workspaces.map((w) => getCachedWorkspace(w.id)?.name ?? w.name)
      return text(names.length ? `Workspaces:\n${names.join('\n')}` : 'No workspace is available for this session.')
    }
  )

  server.registerTool(
    'list_servers',
    { description: 'Lists the servers this AI session is allowed to see, by friendly name, grouped by workspace.' },
    async (extra) => {
      const auth = authenticateExtra(extra)
      if ('error' in auth) return errorText(AUTH_MESSAGES[auth.error])
      const { session } = auth
      const workspaceIds = session.workspaces.map((w) => w.id)
      const workspaceNames = session.workspaces.map((w) => getCachedWorkspace(w.id)?.name ?? w.name)
      const servers = listCachedServers(workspaceIds).filter(
        (s) => effectiveCapability(session, s.id, 'viewServer').decision !== 'deny'
      )
      const header = `Workspace${workspaceNames.length > 1 ? 's' : ''}:\n${workspaceNames.join(', ')}`
      if (servers.length === 0) {
        return text(`${header}\n\nNo servers are available to AI access in this session's workspace(s).`)
      }
      if (workspaceNames.length === 1) {
        const lines = servers.map((s) => `- ${s.name}`)
        return text(`${header}\n\nServers:\n${lines.join('\n')}`)
      }
      const byWorkspace = new Map<string, string[]>()
      for (const s of servers) {
        const wsName = getCachedWorkspace(s.workspaceId)?.name ?? s.workspaceId
        byWorkspace.set(wsName, [...(byWorkspace.get(wsName) ?? []), s.name])
      }
      const groups = [...byWorkspace.entries()].map(
        ([wsName, names]) => `${wsName}:\n${names.map((n) => `- ${n}`).join('\n')}`
      )
      return text(`${header}\n\nServers:\n${groups.join('\n\n')}`)
    }
  )

  server.registerTool(
    'get_server_details',
    {
      description: 'Gets details about one server by its friendly name (or alias). Never returns credentials.',
      inputSchema: { serverName: z.string().describe('The server name or alias, e.g. "Nginx Server Prod" or "nginx"') }
    },
    async ({ serverName }, extra) => {
      const auth = authenticateExtra(extra)
      if ('error' in auth) return errorText(AUTH_MESSAGES[auth.error])
      const resolved = resolveServerOrError(auth.session, serverName)
      if ('error' in resolved) return resolved.error
      const { server: s, workspace } = resolved.match
      const view = effectiveCapability(auth.session, s.id, 'viewServer')
      if (view.decision !== 'allow') return errorText(`Denied: ${view.reason}`)
      const serverGroup = serverGroupFor(s.id)
      const caps = AI_CAPABILITIES.map(
        ({ id, label }) => `- ${label}: ${effectiveCapability(auth.session, s.id, id).decision.toUpperCase()}`
      ).join('\n')
      return text(
        [
          `Workspace: ${workspace.name}`,
          `Server: ${s.name}`,
          `OS: ${s.os}`,
          `Access group: ${serverGroup?.name ?? 'No AI Access'}`,
          `Effective permissions for this session:\n${caps}`
        ].join('\n')
      )
    }
  )

  server.registerTool(
    'execute_command',
    {
      description:
        'Runs a single non-interactive command on a server over SSH and returns stdout/stderr/exit code. May require user approval depending on the access group.',
      inputSchema: {
        serverName: z.string().describe('The server name or alias'),
        command: z.string().describe('The shell command to run')
      }
    },
    async ({ serverName, command }, extra) => {
      const auth = authenticateExtra(extra)
      if ('error' in auth) return errorText(AUTH_MESSAGES[auth.error])
      const resolved = resolveServerOrError(auth.session, serverName)
      if ('error' in resolved) return resolved.error
      const { server: s, workspace } = resolved.match
      const check = effectiveCommand(auth.session, s.id, command)
      const ctx: AuditContext = {
        session: auth.session,
        workspaceId: workspace.id,
        workspaceName: workspace.name,
        serverId: s.id,
        serverName: s.name,
        action: command,
        capability: 'terminal'
      }
      const risk = check.decision === 'deny' ? 'high' : /sudo\b/.test(command) ? 'high' : 'medium'
      const gated = await gate(ctx, check, risk)
      if (!gated.ok) return gated.result

      const secrets = knownSecretValuesForServer(s.id)
      const cfg = resolveChainSecrets(serverToSshConfig(s))
      const result = await sshExec(cfg, command)
      if (!result.ok) {
        recordAudit({
          agentName: auth.session.agentName,
          sessionId: auth.session.id,
          workspaceId: workspace.id,
          workspaceName: workspace.name,
          serverId: s.id,
          serverName: s.name,
          action: command,
          capability: 'terminal',
          approval: check.decision === 'ask' ? 'approved' : 'not-required',
          result: 'error',
          error: result.error
        })
        return errorText(`Command failed: ${result.error ?? 'unknown error'}`)
      }
      auditSuccess(ctx, check.decision === 'ask' ? 'approved' : 'not-required', { exitCode: result.code ?? undefined })
      const stdout = redactOutput(result.stdout, secrets)
      const stderr = redactOutput(result.stderr, secrets)
      const truncNote = result.truncated ? '\n[output truncated]' : ''
      return text(`exit code: ${result.code}\n\nstdout:\n${stdout}\n\nstderr:\n${stderr}${truncNote}`)
    }
  )

  server.registerTool(
    'read_file',
    {
      description: 'Reads a text file from a server over SFTP.',
      inputSchema: { serverName: z.string(), path: z.string().describe('Absolute remote path') }
    },
    async ({ serverName, path }, extra) => {
      const auth = authenticateExtra(extra)
      if ('error' in auth) return errorText(AUTH_MESSAGES[auth.error])
      const resolved = resolveServerOrError(auth.session, serverName)
      if ('error' in resolved) return resolved.error
      const { server: s, workspace } = resolved.match
      const check = effectiveFilePath(auth.session, s.id, path, 'read')
      const ctx: AuditContext = {
        session: auth.session,
        workspaceId: workspace.id,
        workspaceName: workspace.name,
        serverId: s.id,
        serverName: s.name,
        action: `read ${path}`,
        capability: 'readFiles'
      }
      const gated = await gate(ctx, check, 'low')
      if (!gated.ok) return gated.result

      const secrets = knownSecretValuesForServer(s.id)
      const cfg = resolveChainSecrets(serverToSshConfig(s))
      const key = `mcp:${s.id}`
      const conn = await sftpConnect(key, cfg)
      if (!conn.ok) return errorText(`Could not connect: ${conn.error}`)
      const result = await sftpRead(key, path)
      sftpDisconnect(key)
      if (!result.ok) {
        recordAudit({ ...auditBase(ctx), approval: check.decision === 'ask' ? 'approved' : 'not-required', result: 'error', error: result.error })
        return errorText(`Read failed: ${result.error}`)
      }
      auditSuccess(ctx, check.decision === 'ask' ? 'approved' : 'not-required')
      return text(redactOutput(result.data ?? '', secrets))
    }
  )

  server.registerTool(
    'write_file',
    {
      description: 'Writes a text file to a server over SFTP, overwriting it if it exists.',
      inputSchema: { serverName: z.string(), path: z.string().describe('Absolute remote path'), content: z.string() }
    },
    async ({ serverName, path, content }, extra) => {
      const auth = authenticateExtra(extra)
      if ('error' in auth) return errorText(AUTH_MESSAGES[auth.error])
      const resolved = resolveServerOrError(auth.session, serverName)
      if ('error' in resolved) return resolved.error
      const { server: s, workspace } = resolved.match
      const check = effectiveFilePath(auth.session, s.id, path, 'write')
      const ctx: AuditContext = {
        session: auth.session,
        workspaceId: workspace.id,
        workspaceName: workspace.name,
        serverId: s.id,
        serverName: s.name,
        action: `write ${path} (${content.length} bytes)`,
        capability: 'writeFiles'
      }
      const gated = await gate(ctx, check, 'medium')
      if (!gated.ok) return gated.result

      const cfg = resolveChainSecrets(serverToSshConfig(s))
      const key = `mcp:${s.id}`
      const conn = await sftpConnect(key, cfg)
      if (!conn.ok) return errorText(`Could not connect: ${conn.error}`)
      const result = await sftpWrite(key, path, content)
      sftpDisconnect(key)
      if (!result.ok) {
        recordAudit({ ...auditBase(ctx), approval: check.decision === 'ask' ? 'approved' : 'not-required', result: 'error', error: result.error })
        return errorText(`Write failed: ${result.error}`)
      }
      auditSuccess(ctx, check.decision === 'ask' ? 'approved' : 'not-required')
      return text(`Wrote ${content.length} bytes to ${path}.`)
    }
  )

  server.registerTool(
    'list_files',
    {
      description: 'Lists the contents of a directory on a server over SFTP.',
      inputSchema: { serverName: z.string(), path: z.string().describe('Absolute remote directory path') }
    },
    async ({ serverName, path }, extra) => {
      const auth = authenticateExtra(extra)
      if ('error' in auth) return errorText(AUTH_MESSAGES[auth.error])
      const resolved = resolveServerOrError(auth.session, serverName)
      if ('error' in resolved) return resolved.error
      const { server: s, workspace } = resolved.match
      const check = effectiveFilePath(auth.session, s.id, path, 'read')
      const ctx: AuditContext = {
        session: auth.session,
        workspaceId: workspace.id,
        workspaceName: workspace.name,
        serverId: s.id,
        serverName: s.name,
        action: `list ${path}`,
        capability: 'readFiles'
      }
      const gated = await gate(ctx, check, 'low')
      if (!gated.ok) return gated.result

      const cfg = resolveChainSecrets(serverToSshConfig(s))
      const key = `mcp:${s.id}`
      const conn = await sftpConnect(key, cfg)
      if (!conn.ok) return errorText(`Could not connect: ${conn.error}`)
      const result = await sftpList(key, path)
      sftpDisconnect(key)
      if (!result.ok) {
        recordAudit({ ...auditBase(ctx), approval: check.decision === 'ask' ? 'approved' : 'not-required', result: 'error', error: result.error })
        return errorText(`List failed: ${result.error}`)
      }
      auditSuccess(ctx, check.decision === 'ask' ? 'approved' : 'not-required')
      const lines = (result.data ?? []).map((e) => `${e.dir ? 'd' : '-'} ${e.perms} ${String(e.size).padStart(10)} ${e.name}`)
      return text(lines.length ? lines.join('\n') : '(empty directory)')
    }
  )

  server.registerTool(
    'get_server_metrics',
    { description: 'Gets live CPU/memory/disk/uptime metrics for a server.', inputSchema: { serverName: z.string() } },
    async ({ serverName }, extra) => {
      const auth = authenticateExtra(extra)
      if ('error' in auth) return errorText(AUTH_MESSAGES[auth.error])
      const resolved = resolveServerOrError(auth.session, serverName)
      if ('error' in resolved) return resolved.error
      const { server: s, workspace } = resolved.match
      const check = effectiveCapability(auth.session, s.id, 'serverMetrics')
      const ctx: AuditContext = {
        session: auth.session,
        workspaceId: workspace.id,
        workspaceName: workspace.name,
        serverId: s.id,
        serverName: s.name,
        action: 'get_server_metrics',
        capability: 'serverMetrics'
      }
      const gated = await gate(ctx, check, 'low')
      if (!gated.ok) return gated.result

      const cfg = resolveChainSecrets(serverToSshConfig(s))
      const result = await metricsSample(`mcp:${s.id}`, cfg)
      if (!result.ok || !result.data) {
        recordAudit({ ...auditBase(ctx), approval: 'not-required', result: 'error', error: result.error })
        return errorText(`Could not sample metrics: ${result.error ?? 'unknown error'}`)
      }
      auditSuccess(ctx, 'not-required')
      const m = result.data
      return text(
        [
          `Host: ${m.hostname} (${m.kernel})`,
          `CPU: ${m.cpu.toFixed(1)}%`,
          `Memory: ${m.memPct.toFixed(1)}% (${m.memUsed}/${m.memTotal} bytes)`,
          `Disk: ${m.diskPct.toFixed(1)}% (${m.diskUsed}/${m.diskTotal} bytes)`,
          `Uptime: ${Math.round(m.uptime / 3600)}h`
        ].join('\n')
      )
    }
  )

  return server
}

function auditBase(ctx: AuditContext): {
  agentName: string
  sessionId: string
  workspaceId: string | null
  workspaceName: string | null
  serverId: string | null
  serverName: string | null
  action: string
  capability: AiCapability | null
} {
  return {
    agentName: ctx.session.agentName,
    sessionId: ctx.session.id,
    workspaceId: ctx.workspaceId,
    workspaceName: ctx.workspaceName,
    serverId: ctx.serverId,
    serverName: ctx.serverName,
    action: ctx.action,
    capability: ctx.capability
  }
}

let httpServer: HttpServer | null = null
const transports = new Map<string, StreamableHTTPServerTransport>()

function readBody(req: IncomingMessage): Promise<unknown> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = []
    req.on('data', (c: Buffer) => chunks.push(c))
    req.on('end', () => {
      const raw = Buffer.concat(chunks).toString('utf8')
      if (!raw) return resolve(undefined)
      try {
        resolve(JSON.parse(raw))
      } catch (err) {
        reject(err)
      }
    })
    req.on('error', reject)
  })
}

async function handlePairStart(req: IncomingMessage, res: ServerResponse): Promise<void> {
  if (!getMcpConfig().enabled) {
    res.writeHead(403, { 'content-type': 'application/json' })
    res.end(JSON.stringify({ error: 'AI & MCP access is currently disabled in ShellPilot.' }))
    return
  }
  try {
    const body = (await readBody(req)) as { agentName?: string } | undefined
    const agentName = typeof body?.agentName === 'string' && body.agentName.trim() ? body.agentName.trim() : 'CLI agent'
    const { pairingId, expiresInSeconds } = startCliPairing(agentName)
    res.writeHead(200, { 'content-type': 'application/json' })
    res.end(JSON.stringify({ pairingId, expiresInSeconds }))
  } catch {
    res.writeHead(400, { 'content-type': 'application/json' })
    res.end(JSON.stringify({ error: 'Invalid request' }))
  }
}

async function handlePairConfirm(req: IncomingMessage, res: ServerResponse): Promise<void> {
  try {
    const body = (await readBody(req)) as { pairingId?: string; code?: string } | undefined
    if (!body?.pairingId || !body?.code) {
      res.writeHead(400, { 'content-type': 'application/json' })
      res.end(JSON.stringify({ ok: false, error: 'Missing pairingId or code' }))
      return
    }
    const result = confirmCliPairing(body.pairingId, body.code)
    res.writeHead(200, { 'content-type': 'application/json' })
    res.end(JSON.stringify(result.ok ? { ok: true, token: result.token, port: getMcpConfig().port } : result))
  } catch {
    res.writeHead(400, { 'content-type': 'application/json' })
    res.end(JSON.stringify({ ok: false, error: 'Invalid request' }))
  }
}

export function mcpServerStatus(): { running: boolean; port: number | null } {
  return { running: httpServer !== null, port: httpServer ? getMcpConfig().port : null }
}

export async function startMcpServer(): Promise<{ ok: boolean; error?: string }> {
  if (httpServer) return { ok: true }
  const config = getMcpConfig()

  return new Promise((resolve) => {
    const server = createServer((req, res) => {
      void (async () => {
        if (!req.url) {
          res.writeHead(404).end()
          return
        }

        if (req.method === 'POST' && req.url === '/pair/start') return handlePairStart(req, res)
        if (req.method === 'POST' && req.url === '/pair/confirm') return handlePairConfirm(req, res)

        if (!req.url.startsWith('/mcp')) {
          res.writeHead(404).end()
          return
        }

        try {
          const sessionId = req.headers['mcp-session-id'] as string | undefined
          let transport = sessionId ? transports.get(sessionId) : undefined

          if (!transport) {
            const body = req.method === 'POST' ? await readBody(req) : undefined
            if (req.method === 'POST' && isInitializeRequest(body)) {
              transport = new StreamableHTTPServerTransport({
                sessionIdGenerator: () => randomUUID(),
                onsessioninitialized: (sid) => {
                  if (transport) transports.set(sid, transport)
                }
              })
              transport.onclose = () => {
                if (transport?.sessionId) transports.delete(transport.sessionId)
              }
              const mcp = buildServer()
              await mcp.connect(transport)
              await transport.handleRequest(req, res, body)
              return
            }
            res.writeHead(400, { 'content-type': 'application/json' })
            res.end(JSON.stringify({ error: 'No valid MCP session. Send an initialize request first.' }))
            return
          }

          await transport.handleRequest(req, res)
        } catch (err) {
          console.error('[mcp] request handling failed:', err)
          if (!res.headersSent) res.writeHead(500).end()
        }
      })()
    })

    server.on('error', (err) => {
      console.error('[mcp] server error:', err)
      httpServer = null
      resolve({ ok: false, error: err.message })
    })

    // 127.0.0.1 only — this must never be reachable from outside the machine.
    server.listen(config.port, '127.0.0.1', () => {
      httpServer = server
      resolve({ ok: true })
    })
  })
}

export async function stopMcpServer(): Promise<void> {
  for (const transport of transports.values()) {
    try {
      await transport.close()
    } catch {
      /* ignore */
    }
  }
  transports.clear()
  const server = httpServer
  httpServer = null
  if (!server) return
  await new Promise<void>((resolve) => server.close(() => resolve()))
}
