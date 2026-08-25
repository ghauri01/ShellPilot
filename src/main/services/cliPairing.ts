import { EventEmitter } from 'node:events'
import { randomBytes, randomInt } from 'node:crypto'
import type { CliPairingRequest } from '../../shared/mcp'
import { listCachedWorkspaces } from './mcpDataCache'
import { listGroups } from './policyStore'
import { createSession } from './mcpAuth'

// Bootstraps a session for the `shellpilot claude|codex|run` CLI launcher
// without weakening the existing consent model: the code is only ever shown
// inside ShellPilot itself (never returned to whichever local process called
// /pair/start), so completing a pairing proves the human at the keyboard can
// see both the app window and the terminal — the same property a TV-app or
// `gh auth login` device code gets from a physically separate screen.
const TTL_MINUTES = 480
const CODE_TTL_MS = 60_000
const MAX_ATTEMPTS = 5

interface PendingPairing {
  code: string
  agentName: string
  createdAt: number
  expiresAt: number
  attempts: number
  timer: ReturnType<typeof setTimeout>
}

const pending = new Map<string, PendingPairing>()
const emitter = new EventEmitter()

export type CliPairingEvent =
  | { type: 'created'; request: CliPairingRequest }
  | { type: 'resolved'; request: CliPairingRequest }
  | { type: 'expired'; request: CliPairingRequest }

export function onCliPairingEvent(cb: (e: CliPairingEvent) => void): () => void {
  emitter.on('event', cb)
  return () => emitter.off('event', cb)
}

function toRequest(id: string, p: PendingPairing): CliPairingRequest {
  return {
    id,
    code: p.code,
    agentName: p.agentName,
    createdAt: new Date(p.createdAt).toISOString(),
    expiresAt: new Date(p.expiresAt).toISOString()
  }
}

function genCode(): string {
  return String(randomInt(0, 1_000_000)).padStart(6, '0')
}

export function startCliPairing(agentName: string): { pairingId: string; expiresInSeconds: number } {
  const id = `pair-${randomBytes(6).toString('hex')}`
  const now = Date.now()
  const timer = setTimeout(() => expirePairing(id), CODE_TTL_MS)
  const p: PendingPairing = { code: genCode(), agentName, createdAt: now, expiresAt: now + CODE_TTL_MS, attempts: 0, timer }
  pending.set(id, p)
  emitter.emit('event', { type: 'created', request: toRequest(id, p) } satisfies CliPairingEvent)
  return { pairingId: id, expiresInSeconds: CODE_TTL_MS / 1000 }
}

function expirePairing(id: string): void {
  const p = pending.get(id)
  if (!p) return
  clearTimeout(p.timer)
  pending.delete(id)
  emitter.emit('event', { type: 'expired', request: toRequest(id, p) } satisfies CliPairingEvent)
}

// Lets the user dismiss a pairing they did not request, from the app itself.
export function cancelCliPairing(id: string): void {
  expirePairing(id)
}

export function confirmCliPairing(
  id: string,
  code: string
): { ok: true; token: string; expiresAt: string | null } | { ok: false; error: string } {
  const p = pending.get(id)
  if (!p) return { ok: false, error: 'This pairing request was not found. Run the command again.' }
  if (Date.now() > p.expiresAt) {
    expirePairing(id)
    return { ok: false, error: 'This pairing code has expired. Run the command again.' }
  }
  p.attempts++
  if (p.attempts > MAX_ATTEMPTS) {
    expirePairing(id)
    return { ok: false, error: 'Too many incorrect attempts. Run the command again.' }
  }
  if (code.trim() !== p.code) {
    return { ok: false, error: 'Incorrect code.' }
  }

  clearTimeout(p.timer)
  pending.delete(id)
  emitter.emit('event', { type: 'resolved', request: toRequest(id, p) } satisfies CliPairingEvent)

  const workspace = listCachedWorkspaces()[0]
  if (!workspace) return { ok: false, error: 'No workspace exists in ShellPilot yet — create one first.' }
  const group = listGroups()[0]

  const { session, token } = createSession({
    agentName: p.agentName,
    workspaceId: workspace.id,
    workspaceName: workspace.name,
    groupId: group?.id ?? null,
    groupName: group?.name ?? 'No AI Access',
    ttlMinutes: TTL_MINUTES
  })

  return { ok: true, token, expiresAt: session.expiresAt }
}
