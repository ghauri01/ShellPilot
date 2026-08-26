import { createServer, type Server as HttpServer, type IncomingMessage, type ServerResponse } from 'node:http'
import { randomUUID } from 'node:crypto'
import { z } from 'zod'
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js'
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js'
import { isInitializeRequest } from '@modelcontextprotocol/sdk/types.js'
import type { CallToolResult } from '@modelcontextprotocol/sdk/types.js'

import { authenticate, getSession, getMcpConfig, type AuthFailureReason } from './mcpAuth'
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
import { createServerForAgent } from './agentServerCreate'
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

// Creating a session in ShellPilot does not reconfigure the client: the token
// lives in the client's own config file, so a new session leaves the old,
// dead token exactly where it was. "Ask the user to create a new one" was
// therefore advice that does not work on its own — it is the half of the fix
// that is easy to do and does nothing, and following it produces the identical
// error. Say the other half.
const RE_REGISTER =
  'Creating a session in ShellPilot is not enough on its own — the token lives in this ' +
  "client's own configuration, so it must be pointed at the new one. In ShellPilot, use " +
  'AI & MCP > Overview > Connect, which issues a session and gives back the exact command or ' +
  'config entry to apply, then reconnect this client.'

const AUTH_MESSAGES: Record<AuthFailureReason, string> = {
  'ai-disabled': 'AI & MCP access is currently disabled in ShellPilot. Enable it under AI & MCP > Security.',
  'missing-token': 'No bearer token was supplied. Configure this agent with the token from AI & MCP > Agents.',
  'invalid-token': `This token is not recognized by ShellPilot. ${RE_REGISTER}`,
  revoked: `This session has been revoked in ShellPilot. ${RE_REGISTER}`,
  expired: `This session has expired. ${RE_REGISTER}`
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

// Combine the scope's decision with the session's ceiling, and when the ceiling
// is what refused, say so.
//
// Both sides report only a group name, so "Denied: Read Only: manageServers =
// deny" is indistinguishable whether it came from the workspace assignment or
// from the session. The two are changed in different places and only one of
// them can be changed at all once a client is connected: a session copies its
// group in at creation and never re-reads it, so editing access groups in
// Settings cannot affect a connection that already exists. Without that spelt
// out the obvious move is to go and change the setting, retry, and get the same
// message back.
function withCeiling(scope: Decision, session: Decision | null, scopeLabel: string): Decision {
  if (!session) return scope
  const winner = mostRestrictive(scope, session)
  // mostRestrictive prefers its first argument on a tie, so this is only the
  // session when the session is strictly the narrower of the two.
  if (winner !== session) return winner
  return {
    decision: session.decision,
    reason:
      `${session.reason} — that is this AI session's own ceiling, fixed when the session was ` +
      `created, while ${scopeLabel} allows it. Changing access groups in Settings cannot affect a ` +
      `connection that already exists. Revoke this session under AI & MCP -> Active Sessions, ` +
      `create a new one with a higher access group, and reconnect the client.`
  }
}

function effectiveCapability(session: McpAgentSession, serverId: string, capability: AiCapability): Decision {
  const serverGroup = serverGroupFor(serverId)
  if (!serverGroup) return { decision: 'deny', reason: 'No AI access is assigned to this server.' }
  const sessionGroup = sessionGroupFor(session)
  return withCeiling(
    evaluateCapability(serverGroup, capability),
    sessionGroup ? evaluateCapability(sessionGroup, capability) : null,
    `the server's own access group ("${serverGroup.name}")`
  )
}

// add_server acts on a workspace, not on a server that exists yet, so the
// per-server override layer has nothing to look at. Resolve the workspace's own
// assignment instead and keep the session group as the same ceiling it is
// everywhere else.
function effectiveWorkspaceCapability(
  session: McpAgentSession,
  workspaceId: string,
  capability: AiCapability
): Decision {
  const groupId = resolveGroupId(listAssignments(), '', workspaceId)
  const workspaceGroup = groupId ? getGroup(groupId) : null
  if (!workspaceGroup) return { decision: 'deny', reason: 'No AI access is assigned to this workspace.' }
  const sessionGroup = sessionGroupFor(session)
  return withCeiling(
    evaluateCapability(workspaceGroup, capability),
    sessionGroup ? evaluateCapability(sessionGroup, capability) : null,
    `the workspace's access group ("${workspaceGroup.name}")`
  )
}

function effectiveCommand(session: McpAgentSession, serverId: string, command: string): Decision {
  const serverGroup = serverGroupFor(serverId)
  if (!serverGroup) return { decision: 'deny', reason: 'No AI access is assigned to this server.' }
  const sessionGroup = sessionGroupFor(session)
  return withCeiling(
    evaluateCommand(serverGroup, command),
    sessionGroup ? evaluateCommand(sessionGroup, command) : null,
    `the server's own access group ("${serverGroup.name}")`
  )
}

// read_file, list_files and write_file are the SFTP transport, so the transport
// capability applies on top of the path rules. It never was consulted, which
// left "SFTP download"/"SFTP upload" in the access-group editor as switches that
// changed nothing — a permission that is displayed but not enforced is worse
// than one that does not exist, because the user believes they have set it.
function effectiveFilePath(session: McpAgentSession, serverId: string, path: string, mode: 'read' | 'write'): Decision {
  const serverGroup = serverGroupFor(serverId)
  if (!serverGroup) return { decision: 'deny', reason: 'No AI access is assigned to this server.' }
  const transport: AiCapability = mode === 'read' ? 'sftpDownload' : 'sftpUpload'
  const sessionGroup = sessionGroupFor(session)

  const forGroup = (g: AccessGroup): Decision =>
    mostRestrictive(evaluateFilePath(g, path, mode), evaluateCapability(g, transport))

  return withCeiling(
    forGroup(serverGroup),
    sessionGroup ? forGroup(sessionGroup) : null,
    `the server's own access group ("${serverGroup.name}")`
  )
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

// Sent to the client on initialize and, in most clients, placed in the model's
// system prompt. Without it an agent has to infer the addressing scheme from
// eight one-line descriptions, and the thing it infers is "this is a shell" —
// which is how you get `cat` where read_file belongs.
const INSTRUCTIONS = `ShellPilot is a gateway to SSH servers the user has already configured.

Addressing
- Servers are identified by FRIENDLY NAME or alias, never by hostname, IP or connection string.
- Call list_servers first. The names it returns are the only valid serverName values.
- You never see hostnames, IP addresses, usernames, passwords or keys, and cannot ask for them.
  ShellPilot resolves the name and authenticates on your behalf.

Choosing a tool
- Prefer the specific tool over execute_command: read_file over \`cat\`, list_files over \`ls\`,
  get_server_metrics over \`top\`/\`free\`/\`df\`. They state their intent exactly, so the user's
  path rules apply precisely rather than being inferred from a command string, and they are
  less likely to need an approval prompt.
- Use execute_command for work that genuinely needs a shell.

Permissions
- Every call is checked against an access group. A call may return "Denied", or block while the
  user approves it. Both are normal; do not retry a denied call in a different form, and do not
  try to work around a path rule by expressing the same access as a shell command.
- Some capabilities may be denied entirely for this session. get_server_details lists the
  effective permissions for a given server.

Not available
- No SSH tunnels, port forwarding, database queries, or file upload/download beyond
  read_file/write_file. Do not attempt these through execute_command; say they are unsupported.`

function buildServer(): McpServer {
  const server = new McpServer({ name: 'shellpilot', version: '1.0.0' }, { instructions: INSTRUCTIONS })

  server.registerTool(
    'list_workspaces',
    {
      title: 'List workspaces',
      description:
        "Lists the workspace(s) this AI session is scoped to. A workspace is a group of servers. " +
        "This never reveals a workspace outside the session's grant. Useful when a tool asks which " +
        'workspace to act on; otherwise start with list_servers.',
      annotations: { readOnlyHint: true, idempotentHint: true, openWorldHint: false }
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
    {
      title: 'List servers',
      description:
        'Lists the servers this session may use, by friendly name, grouped by workspace. CALL THIS FIRST: ' +
        'every other tool addresses a server by one of these names, and no other identifier — not a hostname, ' +
        'an IP or a connection string — will resolve. A server the user has not granted AI access to does not ' +
        'appear here.',
      annotations: { readOnlyHint: true, idempotentHint: true, openWorldHint: false }
    },
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
      title: 'Get server details',
      description:
        'Gets the OS, access group and the effective permissions this session has on one server. ' +
        'Call this when you are unsure whether an action will be allowed, blocked for approval, or denied — ' +
        'it is cheaper than attempting the action and being refused. Never returns credentials, hostnames or usernames.',
      inputSchema: {
        serverName: z
          .string()
          .describe('Friendly name or alias exactly as returned by list_servers, e.g. "Nginx Server Prod" or "nginx"')
      },
      annotations: { readOnlyHint: true, idempotentHint: true, openWorldHint: false }
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
      title: 'Run a shell command',
      description:
        'Runs a single non-interactive command over SSH and returns stdout, stderr and the exit code. ' +
        'Use this only for work the purpose-built tools do not cover. Prefer read_file over `cat`, ' +
        'list_files over `ls`, write_file over a redirect, and get_server_metrics over `top`/`free`/`df`: ' +
        'those state their intent exactly, so the path rules apply precisely instead of being inferred from ' +
        'a command string, and they are less likely to require approval. Interactive commands, shells and ' +
        'privilege-escalation shells (sudo -i, su, sudo bash) are always refused. May block while the user approves it.',
      inputSchema: {
        serverName: z.string().describe('Friendly name or alias exactly as returned by list_servers'),
        command: z
          .string()
          .describe('A single non-interactive shell command. Not a script, not an interactive program.')
      },
      annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: true }
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
      title: 'Read a file',
      description:
        'Reads a text file from a server over SFTP. Prefer this over running `cat` through execute_command: ' +
        "the path is checked against the user's per-path rules directly rather than being parsed out of a " +
        'command line. Text only — this is not a way to fetch binaries.',
      inputSchema: {
        serverName: z.string().describe('Friendly name or alias exactly as returned by list_servers'),
        path: z.string().describe('Absolute remote path, e.g. /var/log/nginx/error.log')
      },
      annotations: { readOnlyHint: true, idempotentHint: true, openWorldHint: false }
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
      title: 'Write a file',
      description:
        'Writes a text file over SFTP, replacing it entirely if it exists. There is no append mode — read the ' +
        'file first and write back the full contents. Prefer this over a shell redirect: the path is checked ' +
        'against the per-path rules directly. Often requires approval.',
      inputSchema: {
        serverName: z.string().describe('Friendly name or alias exactly as returned by list_servers'),
        path: z.string().describe('Absolute remote path, e.g. /etc/nginx/conf.d/site.conf'),
        content: z.string().describe('The complete new contents of the file. Replaces whatever is there.')
      },
      annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: true, openWorldHint: false }
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
      title: 'List a directory',
      description:
        'Lists the contents of a directory over SFTP, with sizes and types. Prefer this over running `ls` ' +
        'through execute_command — it returns structured output and is checked against the per-path rules directly.',
      inputSchema: {
        serverName: z.string().describe('Friendly name or alias exactly as returned by list_servers'),
        path: z.string().describe('Absolute remote directory path, e.g. /var/www')
      },
      annotations: { readOnlyHint: true, idempotentHint: true, openWorldHint: false }
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
    {
      title: 'Get server metrics',
      description:
        'Samples live CPU, memory, disk and uptime for a server and returns them as structured values. ' +
        'Prefer this over `top`, `free`, `df` or `uptime` through execute_command — it needs no shell access ' +
        'and returns numbers rather than text to parse.',
      inputSchema: { serverName: z.string().describe('Friendly name or alias exactly as returned by list_servers') },
      annotations: { readOnlyHint: true, idempotentHint: false, openWorldHint: false }
    },
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

  server.registerTool(
    'add_server',
    {
      title: 'Add a server',
      annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: false },
      description:
        'Adds a new SSH connection to a workspace in ShellPilot, so later calls can address it by name. ' +
        'Use only when the user asks for a server to be added; it changes their saved configuration. ' +
        'Requires the manageServers capability and, ' +
        'unless the access group allows it outright, explicit approval from the user. Credentials are written ' +
        "straight to the operating system's secure storage and are never readable back through this bridge.",
      inputSchema: {
        name: z.string().describe('Friendly name for the connection, e.g. "Web Server Staging". Must be unique.'),
        host: z.string().describe('Hostname or IP address'),
        workspaceName: z
          .string()
          .optional()
          .describe('Which workspace to add it to. Optional when the session covers exactly one.'),
        port: z.number().int().min(1).max(65535).optional().describe('SSH port, default 22'),
        username: z.string().optional().describe('SSH username, default "root"'),
        auth: z
          .enum(['password', 'key', 'agent'])
          .optional()
          .describe('Authentication method, default "agent" (use the running SSH agent, no credential stored)'),
        password: z.string().optional().describe('Password, when auth is "password"'),
        keyPath: z.string().optional().describe('Absolute path to a private key file, when auth is "key"'),
        passphrase: z.string().optional().describe('Passphrase for the private key, if it has one'),
        os: z.string().optional().describe('Operating system label, default "Linux"')
      }
    },
    async (args, extra) => {
      const auth = authenticateExtra(extra)
      if ('error' in auth) return errorText(AUTH_MESSAGES[auth.error])
      const { session } = auth

      const scoped = session.workspaces.map((w) => ({ ...w, name: getCachedWorkspace(w.id)?.name ?? w.name }))
      const workspace = args.workspaceName
        ? scoped.find((w) => w.name.toLowerCase() === args.workspaceName!.trim().toLowerCase())
        : scoped.length === 1
          ? scoped[0]
          : undefined
      if (!workspace) {
        return errorText(
          args.workspaceName
            ? `No workspace named "${args.workspaceName}" is available to this session.`
            : `This session covers several workspaces — pass workspaceName. Available: ${scoped
                .map((w) => w.name)
                .join(', ')}`
        )
      }

      const name = args.name.trim()
      if (!name) return errorText('A server name is required.')
      // Every other tool addresses servers by friendly name, so a duplicate
      // would make an existing server unreachable through this bridge.
      if (listCachedServers([workspace.id]).some((s) => s.name.toLowerCase() === name.toLowerCase())) {
        return errorText(`A server named "${name}" already exists in ${workspace.name}.`)
      }

      const method = args.auth ?? 'agent'
      if (method === 'password' && !args.password) return errorText('auth "password" requires a password.')
      if (method === 'key' && !args.keyPath) return errorText('auth "key" requires keyPath.')

      const port = args.port ?? 22
      const username = args.username?.trim() || 'root'
      const ctx: AuditContext = {
        session,
        workspaceId: workspace.id,
        workspaceName: workspace.name,
        // No server exists yet, so there is no id to record. The name is what
        // the audit entry and the approval dialog are about.
        serverId: 'pending-new-server',
        serverName: name,
        // Deliberately describes the credential without reproducing it: this
        // string is persisted to the audit log and shown in a dialog.
        action: `Add server "${name}" (${username}@${args.host}:${port}, auth: ${method}${
          method === 'agent' ? '' : ', credential supplied by the agent'
        })`,
        capability: 'manageServers'
      }

      const check = effectiveWorkspaceCapability(session, workspace.id, 'manageServers')
      const gated = await gate(ctx, check, 'high')
      if (!gated.ok) return gated.result

      const result = await createServerForAgent({
        workspaceId: workspace.id,
        name,
        host: args.host.trim(),
        port,
        username,
        auth: method,
        password: args.password,
        keyPath: args.keyPath,
        passphrase: args.passphrase,
        os: args.os
      })
      if (!result.ok) {
        recordAudit({
          ...auditBase(ctx),
          approval: check.decision === 'ask' ? 'approved' : 'not-required',
          result: 'error',
          error: result.error ?? 'unknown error'
        })
        return errorText(`Could not add the server: ${result.error ?? 'unknown error'}`)
      }

      auditSuccess(ctx, check.decision === 'ask' ? 'approved' : 'not-required')
      return text(
        `Added "${name}" to ${workspace.name}. Refer to it by that name in other tools. ` +
          `Its credential is in the OS keychain and cannot be read back through this bridge.`
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

export interface CapabilityExplanation {
  capability: AiCapability
  label: string
  decision: 'allow' | 'ask' | 'deny'
  reason: string
  fromScope: 'allow' | 'ask' | 'deny'
  fromSession: 'allow' | 'ask' | 'deny' | null
  decidedBy: 'scope' | 'session' | 'both'
}

// The same functions the tools call, so the UI cannot drift from what is
// actually enforced. A permissions screen that computes its own answer is
// worse than no permissions screen, because it will eventually disagree with
// reality and be believed.
export function explainSessionAccess(sessionId: string, serverId: string | null): CapabilityExplanation[] | null {
  const session = getSession(sessionId)
  if (!session) return null

  const sessionGroup = sessionGroupFor(session)
  const scopeGroup = serverId
    ? serverGroupFor(serverId)
    : (() => {
        const first = session.workspaces[0]
        if (!first) return null
        const groupId = resolveGroupId(listAssignments(), '', first.id)
        return groupId ? getGroup(groupId) : null
      })()

  return AI_CAPABILITIES.map(({ id, label }) => {
    const scope = scopeGroup
      ? evaluateCapability(scopeGroup, id)
      : { decision: 'deny' as const, reason: 'No access group is assigned.' }
    const sess = sessionGroup ? evaluateCapability(sessionGroup, id) : null
    const combined = serverId
      ? effectiveCapability(session, serverId, id)
      : withCeiling(scope, sess, 'the workspace')
    return {
      capability: id,
      label,
      decision: combined.decision,
      reason: combined.reason,
      fromScope: scope.decision,
      fromSession: sess ? sess.decision : null,
      decidedBy:
        !sess || sess.decision === scope.decision ? 'both' : combined.decision === sess.decision ? 'session' : 'scope'
    }
  })
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
