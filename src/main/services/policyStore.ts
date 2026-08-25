import { app } from 'electron'
import { join } from 'node:path'
import { existsSync, readFileSync, writeFileSync, renameSync, unlinkSync } from 'node:fs'
import { randomBytes } from 'node:crypto'
import type { AccessGroup, PolicyAssignment, PolicyState, ServerAiMeta } from '../../shared/mcp'

// Access groups, server/workspace assignments and AI aliases. Same
// temp-then-rename write pattern as store.ts/vault.ts/knownhosts.ts. No
// secrets live in this file — credentials never enter the AI policy layer.
const FILE = join(app.getPath('userData'), 'shellpilot-ai-policy.json')
const TMP = `${FILE}.tmp`

const uid = (p: string): string => `${p}-${randomBytes(6).toString('hex')}`

function allowAll(overrides: Partial<AccessGroup['capabilities']> = {}): AccessGroup['capabilities'] {
  return {
    viewServer: 'allow',
    terminal: 'allow',
    readFiles: 'allow',
    writeFiles: 'allow',
    sftpDownload: 'allow',
    sftpUpload: 'allow',
    sshTunnel: 'allow',
    databaseAccess: 'allow',
    sudo: 'allow',
    serverMetrics: 'allow',
    ...overrides
  }
}

// Seeded onto every default group. Users can edit or delete these — they are
// ordinary data, not a hard-coded exception — but a fresh install starts with
// the sensitive paths the brief calls out already locked down.
function defaultFilePolicies(): AccessGroup['filePolicies'] {
  return [
    { id: uid('fp'), pattern: '/etc/shadow', read: 'deny', write: 'deny' },
    { id: uid('fp'), pattern: '/etc/gshadow', read: 'deny', write: 'deny' },
    { id: uid('fp'), pattern: '/root/.ssh/**', read: 'deny', write: 'deny' },
    { id: uid('fp'), pattern: '/home/*/.ssh/**', read: 'deny', write: 'deny' },
    { id: uid('fp'), pattern: '/etc/nginx/**', write: 'ask' },
    { id: uid('fp'), pattern: '/var/www/**', write: 'ask' }
  ]
}

function defaultGroups(): AccessGroup[] {
  return [
    {
      id: 'grp-read-only',
      name: 'Read Only',
      builtIn: true,
      capabilities: allowAll({
        writeFiles: 'deny',
        sftpUpload: 'deny',
        sshTunnel: 'deny',
        sudo: 'deny'
      }),
      filePolicies: defaultFilePolicies()
    },
    {
      id: 'grp-read-write',
      name: 'Read & Write',
      builtIn: true,
      capabilities: allowAll({
        writeFiles: 'ask',
        sftpUpload: 'ask',
        sshTunnel: 'ask',
        sudo: 'deny'
      }),
      filePolicies: defaultFilePolicies()
    },
    {
      id: 'grp-sudo',
      name: 'Sudo Access',
      builtIn: true,
      capabilities: allowAll({
        writeFiles: 'ask',
        sftpUpload: 'ask',
        sshTunnel: 'ask',
        sudo: 'ask'
      }),
      filePolicies: defaultFilePolicies()
    },
    {
      id: 'grp-full',
      name: 'Full Access',
      builtIn: true,
      // Even "Full Access" keeps sudo at ASK by default: the brief is explicit
      // that root access must never be granted silently. The user can raise
      // this to 'allow' themselves, which is then an explicit choice, not a
      // default.
      capabilities: allowAll({ sudo: 'ask' }),
      filePolicies: defaultFilePolicies()
    }
  ]
}

function seed(): PolicyState {
  return { version: 1, groups: defaultGroups(), assignments: [], serverMeta: [] }
}

function read(): PolicyState {
  try {
    if (existsSync(FILE)) {
      const parsed = JSON.parse(readFileSync(FILE, 'utf8')) as PolicyState
      if (parsed && Array.isArray(parsed.groups)) return parsed
    }
  } catch {
    /* fall through to a fresh seed rather than crash on a corrupt file */
  }
  return seed()
}

function write(state: PolicyState): void {
  writeFileSync(TMP, JSON.stringify(state), { mode: 0o600 })
  renameSync(TMP, FILE)
}

let cache: PolicyState | null = null

function load(): PolicyState {
  if (!cache) cache = read()
  return cache
}

export function getPolicyState(): PolicyState {
  return load()
}

export function listGroups(): AccessGroup[] {
  return load().groups
}

export function getGroup(id: string): AccessGroup | null {
  return load().groups.find((g) => g.id === id) ?? null
}

export function saveGroup(group: AccessGroup): AccessGroup {
  const state = load()
  const idx = state.groups.findIndex((g) => g.id === group.id)
  if (idx === -1) state.groups.push(group)
  else state.groups[idx] = group
  write(state)
  return group
}

export function createGroup(name: string): AccessGroup {
  const group: AccessGroup = {
    id: uid('grp'),
    name,
    builtIn: false,
    capabilities: allowAll({
      terminal: 'ask',
      writeFiles: 'deny',
      sftpUpload: 'deny',
      sshTunnel: 'deny',
      databaseAccess: 'ask',
      sudo: 'deny'
    }),
    filePolicies: defaultFilePolicies()
  }
  return saveGroup(group)
}

export function deleteGroup(id: string): { ok: boolean; error?: string } {
  const state = load()
  const group = state.groups.find((g) => g.id === id)
  if (!group) return { ok: true }
  if (group.builtIn) return { ok: false, error: 'Built-in access groups cannot be deleted.' }
  state.groups = state.groups.filter((g) => g.id !== id)
  // Anything assigned to the deleted group falls back to No AI Access rather
  // than pointing at a group that no longer exists.
  state.assignments = state.assignments.map((a) => (a.groupId === id ? { ...a, groupId: null } : a))
  write(state)
  return { ok: true }
}

export function listAssignments(): PolicyAssignment[] {
  return load().assignments
}

// One assignment per scope: setting a workspace/server assignment replaces
// whatever was there, it does not accumulate duplicates that could be
// evaluated in an undefined order.
export function setAssignment(scope: PolicyAssignment['scope'], groupId: string | null): PolicyAssignment {
  const state = load()
  const matches = (a: PolicyAssignment): boolean =>
    a.scope.level === scope.level &&
    (scope.level === 'workspace'
      ? a.scope.level === 'workspace' && a.scope.workspaceId === scope.workspaceId
      : a.scope.level === 'server' && a.scope.serverId === scope.serverId)
  const existing = state.assignments.find(matches)
  if (existing) {
    existing.groupId = groupId
    write(state)
    return existing
  }
  const assignment: PolicyAssignment = { id: uid('asn'), scope, groupId }
  state.assignments.push(assignment)
  write(state)
  return assignment
}

export function removeAssignment(id: string): void {
  const state = load()
  state.assignments = state.assignments.filter((a) => a.id !== id)
  write(state)
}

export function getServerMeta(serverId: string): ServerAiMeta {
  return load().serverMeta.find((m) => m.serverId === serverId) ?? { serverId, aliases: [] }
}

export function listServerMeta(): ServerAiMeta[] {
  return load().serverMeta
}

export function setServerAliases(serverId: string, aliases: string[]): ServerAiMeta {
  const state = load()
  const cleaned = [...new Set(aliases.map((a) => a.trim().toLowerCase()).filter(Boolean))]
  const idx = state.serverMeta.findIndex((m) => m.serverId === serverId)
  const meta: ServerAiMeta = { serverId, aliases: cleaned }
  if (idx === -1) state.serverMeta.push(meta)
  else state.serverMeta[idx] = meta
  write(state)
  return meta
}

// Test-only: wipe both the in-memory cache and the on-disk file so the next
// access starts from a fresh seed rather than a previous test's state.
export function resetPolicyCacheForTests(): void {
  cache = null
  try {
    if (existsSync(FILE)) unlinkSync(FILE)
  } catch {
    /* ignore */
  }
}
