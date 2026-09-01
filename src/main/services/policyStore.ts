import { app } from 'electron'
import { join } from 'node:path'
import { existsSync, readFileSync, writeFileSync, renameSync, unlinkSync } from 'node:fs'
import { randomBytes } from 'node:crypto'
import { AI_CAPABILITIES } from '../../shared/mcp'
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
    // Not 'allow', despite the name. Every other capability here is an action
    // performed ON a server the user already added; this one edits ShellPilot's
    // own connection list and stores a credential. Groups that predate it never
    // had that power, and a helper called allowAll should not be what silently
    // hands it to them — each group opts in below.
    manageServers: 'deny',
    // Same reasoning, one step further out: this one decides which network the
    // user's later SSH and database sessions travel over, and an frp profile
    // makes a local port reachable from the public internet. A group that never
    // saw the capability cannot be assumed to have wanted it, so nothing here
    // is granted by the helper — each group opts in below, and none of them
    // opts in at 'allow'.
    vpnControl: 'deny',
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
    // macOS puts home directories under /Users, not /home, so the rule above
    // matched nothing at all on a Mac target — while the UI listed it as
    // configured. Three of the four built-in groups allow readFiles outright,
    // so this was the whole of the protection on SSH keys there.
    { id: uid('fp'), pattern: '/Users/*/.ssh/**', read: 'deny', write: 'deny' },
    // Windows. Patterns are matched separator- and case-insensitively (see
    // evaluateFilePath), so one entry per shape covers `C:\Users\me\.ssh`,
    // `c:/users/me/.ssh` and everything between. Any drive, not just C:.
    { id: uid('fp'), pattern: '?:/Users/*/.ssh/**', read: 'deny', write: 'deny' },
    // The Windows analogue of /etc/shadow: the OS credential stores, not the
    // whole of AppData. AppData is mostly ordinary application state — logs,
    // caches, settings an agent may legitimately need — and a blanket deny
    // there produces refusals a user cannot explain, which is how a rule ends
    // up deleted along with the ones that mattered.
    //
    // Crypto and Protect hold DPAPI master keys and RSA private keys; take
    // those and every safeStorage secret on the machine decrypts. Credentials
    // is the Credential Manager blob store.
    { id: uid('fp'), pattern: '?:/Users/*/AppData/Roaming/Microsoft/Crypto/**', read: 'deny', write: 'deny' },
    { id: uid('fp'), pattern: '?:/Users/*/AppData/Roaming/Microsoft/Protect/**', read: 'deny', write: 'deny' },
    { id: uid('fp'), pattern: '?:/Users/*/AppData/Local/Microsoft/Credentials/**', read: 'deny', write: 'deny' },
    { id: uid('fp'), pattern: '?:/Users/*/AppData/Roaming/Microsoft/Credentials/**', read: 'deny', write: 'deny' },
    // Shell history is a credential store in practice — tokens pasted into a
    // command line live here in plaintext. Same reasoning would apply to
    // ~/.bash_history on POSIX; that is a separate rule, not this one.
    {
      id: uid('fp'),
      pattern: '?:/Users/*/AppData/Roaming/Microsoft/Windows/PowerShell/PSReadLine/**',
      read: 'deny',
      write: 'deny'
    },
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
        sudo: 'deny',
        manageServers: 'ask',
        vpnControl: 'ask'
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
        sudo: 'ask',
        manageServers: 'ask',
        vpnControl: 'ask'
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
      capabilities: allowAll({ sudo: 'ask', manageServers: 'ask', vpnControl: 'ask' }),
      filePolicies: defaultFilePolicies()
    }
  ]
}

function seed(): PolicyState {
  // Stamped at the latest generation: defaultFilePolicies() already contains
  // every seeded pattern, so a fresh install has nothing to backfill.
  return {
    version: 1,
    groups: defaultGroups(),
    assignments: [],
    serverMeta: [],
    filePolicyGeneration: LATEST_FILE_POLICY_GENERATION
  }
}

// A capability added in a later version is simply absent from a policy file
// written before it existed, and an absent capability evaluates as DENY. That
// is the right default for an unknown permission, but it also means an upgraded
// install silently behaves differently from a fresh one — the feature is off,
// nothing in the UI says why, and toggling something else does not fix it.
//
// So backfill on load. Built-in groups get whatever a fresh seed would have
// given them, which is the setting the user would see on a new install; custom
// groups get DENY, because there is no intent on record for a capability their
// author never saw.
function backfillCapabilities(state: PolicyState): PolicyState {
  const seeded = new Map(defaultGroups().map((g) => [g.id, g.capabilities]))
  for (const group of state.groups) {
    const fresh = seeded.get(group.id)
    for (const { id } of AI_CAPABILITIES) {
      if (group.capabilities[id] === undefined) {
        group.capabilities[id] = fresh?.[id] ?? 'deny'
      }
    }
  }
  return state
}

// Seeded file-policy generations. Each entry is the set of patterns introduced
// at that generation; a file records the highest one it has been brought up to.
//
// Why a generation counter rather than "add any missing seed": the seeds are
// ordinary data and the user is free to delete them. Re-adding every absent
// default on load would silently resurrect a rule they removed on purpose.
// Keying on a generation means each new rule is offered exactly once, to the
// installs that predate it, and a later deletion sticks.
const FILE_POLICY_GENERATIONS: { generation: number; patterns: AccessGroup['filePolicies'] }[] = [
  {
    // Home directories on macOS (/Users, not /home) and Windows. Until this
    // generation the only home-dir rule was /home/*/.ssh/**, so on a Mac or
    // Windows target it matched nothing and three of the four built-in groups
    // allow readFiles outright — private keys were readable through the policy
    // layer on every install made before this shipped, not only new ones.
    generation: 1,
    patterns: [
      { id: '', pattern: '/Users/*/.ssh/**', read: 'deny', write: 'deny' },
      { id: '', pattern: '?:/Users/*/.ssh/**', read: 'deny', write: 'deny' },
      // Windows credential stores specifically, not all of AppData. See
      // defaultFilePolicies for why the blanket was the wrong shape.
      { id: '', pattern: '?:/Users/*/AppData/Roaming/Microsoft/Crypto/**', read: 'deny', write: 'deny' },
      { id: '', pattern: '?:/Users/*/AppData/Roaming/Microsoft/Protect/**', read: 'deny', write: 'deny' },
      { id: '', pattern: '?:/Users/*/AppData/Local/Microsoft/Credentials/**', read: 'deny', write: 'deny' },
      { id: '', pattern: '?:/Users/*/AppData/Roaming/Microsoft/Credentials/**', read: 'deny', write: 'deny' },
      {
        id: '',
        pattern: '?:/Users/*/AppData/Roaming/Microsoft/Windows/PowerShell/PSReadLine/**',
        read: 'deny',
        write: 'deny'
      }
    ]
  }
]

const LATEST_FILE_POLICY_GENERATION = FILE_POLICY_GENERATIONS.at(-1)?.generation ?? 0

// Applies to BUILT-IN groups only. A custom group is the author's own list and
// nothing here has standing to add to it.
export function migrateForTests(state: PolicyState): PolicyState {
  return backfillFilePolicies(state)
}

function backfillFilePolicies(state: PolicyState): PolicyState {
  const from = state.filePolicyGeneration ?? 0
  if (from >= LATEST_FILE_POLICY_GENERATION) return state

  for (const { generation, patterns } of FILE_POLICY_GENERATIONS) {
    if (generation <= from) continue
    for (const group of state.groups) {
      if (!group.builtIn) continue
      for (const rule of patterns) {
        // A user who already wrote this exact pattern keeps their own values.
        if (group.filePolicies.some((p) => p.pattern === rule.pattern)) continue
        group.filePolicies.push({ ...rule, id: uid('fp') })
      }
    }
  }
  state.filePolicyGeneration = LATEST_FILE_POLICY_GENERATION
  return state
}

function read(): PolicyState {
  try {
    if (existsSync(FILE)) {
      const parsed = JSON.parse(readFileSync(FILE, 'utf8')) as PolicyState
      if (parsed && Array.isArray(parsed.groups)) {
        return backfillFilePolicies(backfillCapabilities(parsed))
      }
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
