import { EventEmitter } from 'node:events'
import { randomBytes } from 'node:crypto'
import type { ApprovalRequest } from '../../shared/mcp'
import { getMcpConfig } from './mcpAuth'

// Human-in-the-loop gate for ASK-tier actions. The only way to resolve a
// pending request is respond(), called from the IPC handler the renderer's
// approval dialog uses — the MCP/HTTP surface never reaches this function,
// so an AI agent has no path to approve its own request.
const emitter = new EventEmitter()
const pending = new Map<string, { request: ApprovalRequest; resolve: (v: 'approved' | 'denied' | 'timeout') => void; timer: ReturnType<typeof setTimeout> }>()

export type ApprovalEvent =
  | { type: 'created'; request: ApprovalRequest }
  | { type: 'resolved'; request: ApprovalRequest }

export function onApprovalEvent(cb: (e: ApprovalEvent) => void): () => void {
  emitter.on('event', cb)
  return () => emitter.off('event', cb)
}

export interface CreateApprovalInput {
  sessionId: string
  agentName: string
  workspaceId: string
  workspaceName: string
  serverId: string
  serverName: string
  capability: ApprovalRequest['capability']
  action: string
  risk: ApprovalRequest['risk']
}

export function requestApproval(input: CreateApprovalInput): Promise<'approved' | 'denied' | 'timeout'> {
  const request: ApprovalRequest = {
    id: `appr-${randomBytes(6).toString('hex')}`,
    createdAt: new Date().toISOString(),
    status: 'pending',
    ...input
  }

  return new Promise((resolve) => {
    const timeoutMs = getMcpConfig().approvalTimeoutSeconds * 1000
    const timer = setTimeout(() => {
      finish(request.id, 'timeout')
    }, timeoutMs)

    pending.set(request.id, { request, resolve, timer })
    emitter.emit('event', { type: 'created', request } satisfies ApprovalEvent)
  })
}

function finish(id: string, decision: 'approved' | 'denied' | 'timeout'): void {
  const entry = pending.get(id)
  if (!entry) return
  clearTimeout(entry.timer)
  pending.delete(id)
  entry.request.status = decision
  entry.request.resolvedAt = new Date().toISOString()
  entry.resolve(decision)
  emitter.emit('event', { type: 'resolved', request: entry.request } satisfies ApprovalEvent)
}

// Called only from the renderer's approval dialog via IPC — never from the
// MCP tool-call path.
export function respondToApproval(id: string, decision: 'approved' | 'denied'): boolean {
  if (!pending.has(id)) return false
  finish(id, decision)
  return true
}

export function listPendingApprovals(): ApprovalRequest[] {
  return [...pending.values()].map((e) => e.request)
}

// Used by the global "STOP ALL AI ACCESS" kill switch: every outstanding
// question is answered "denied" immediately rather than left to time out.
export function denyAllPending(): number {
  const ids = [...pending.keys()]
  for (const id of ids) finish(id, 'denied')
  return ids.length
}
