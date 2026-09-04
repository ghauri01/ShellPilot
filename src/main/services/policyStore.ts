import { app } from 'electron'
import { join } from 'node:path'
import { existsSync, readFileSync, writeFileSync, renameSync, unlinkSync } from 'node:fs'
import { randomBytes } from 'node:crypto'
import { AI_CAPABILITIES } from '../../shared/mcp'
import type {
  AccessGroup,
  PermissionValue,
  PolicyAssignment,
  PolicyState,
  ServerAiMeta
} from '../../shared/mcp'

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
    // Denied on every seeded group, and NONE of them opts in below — the only
    // capability here of which that is true.
    //
    // It returns how many unpatched security updates a host is carrying and
    // against which distribution, which is a vulnerability report rather than a
    // health check, and the roadmap settled it explicitly: a new capability
    // backfills to DENY for every existing group. Seeding it at 'ask' on the
    // three permissive groups would have made the backfill hand it to upgraded
    // installs at 'ask' rather than 'deny', because backfillCapabilities gives
    // a built-in group whatever a fresh install would have given it.
    //
    // The cost is that a fresh install must switch it on deliberately, which is
    // the same posture the optional modules ship with and is the intended one
    // for the most attacker-useful thing the bridge can return.
    hostFacts: 'deny',
    // Denied on every seeded group too, and nothing below opts in — the second
    // capability of which that is true, for hostFacts' reason one step further
    // along. This one is the firewall RULE LIST: the addresses and ports the
    // host accepts traffic on, which is the map an attacker would otherwise
    // have to scan for. Roadmap item 31 settled it the same way item C settled
    // hostFacts: a new capability backfills to DENY for every existing group,
    // and seeding it at 'ask' on the permissive groups would hand upgraded
    // installs an 'ask' instead.
    //
    // 'ask' would be meaningless here in a way it is not for the others. What
    // this gates is an unattended hourly collection with nobody at the screen,
    // so there is no prompt an 'ask' could raise; only 'allow' collects.
    firewallRules: 'deny',
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
    // POSIX shell and REPL history, the counterpart to the PSReadLine rule
    // above. Same reasoning: a token pasted onto a command line is in the
    // history file in plaintext, and `.psql_history` / `.mysql_history` hold
    // connection strings with passwords in them — which matters here more than
    // most places, because ShellPilot is also a database client.
    //
    // `.*_history` is one rule per home root instead of a dozen literals: the
    // leading dot is matched literally and `*` stays inside the filename, so it
    // covers .bash_history, .zsh_history, .sh_history, .python_history,
    // .node_repl_history, .psql_history, .mysql_history, .rediscli_history and
    // .sqlite_history without listing each one and without reaching outside the
    // home directory.
    ...['/root', '/home/*', '/Users/*', '?:/Users/*'].flatMap((home) => [
      { id: uid('fp'), pattern: `${home}/.*_history`, read: 'deny' as const, write: 'deny' as const },
      // fish keeps its history somewhere else entirely.
      {
        id: uid('fp'),
        pattern: `${home}/.local/share/fish/fish_history`,
        read: 'deny' as const,
        write: 'deny' as const
      }
    ]),
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

// Seeded file-policy generations. Each entry is what changed at that
// generation; a file records the highest one it has been brought up to.
//
// Why a generation counter rather than "add any missing seed": the seeds are
// ordinary data and the user is free to delete them. Re-adding every absent
// default on load would silently resurrect a rule they removed on purpose.
// Keying on a generation means each change is offered exactly once, to the
// installs that predate it, and a later deletion sticks.
//
// `retire` is the counterpart, for a rule that shipped and then turned out to
// be the wrong shape — the blanket AppData deny was one, before it was
// corrected pre-release. A retired entry is removed ONLY where it still holds
// the exact values it was seeded with. The moment a user has edited one, that
// edit is intent on record and outranks anything here; the rule stays and they
// can delete it themselves. Retiring is therefore never destructive of a
// decision someone actually made.
interface FilePolicyGeneration {
  generation: number
  patterns?: AccessGroup['filePolicies']
  retire?: { pattern: string; read?: PermissionValue; write?: PermissionValue }[]
}

const FILE_POLICY_GENERATIONS: FilePolicyGeneration[] = [
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
      },
      // POSIX shell and REPL history — see defaultFilePolicies for why one
      // `.*_history` pattern per home root rather than a list of literals.
      ...['/root', '/home/*', '/Users/*', '?:/Users/*'].flatMap((home) => [
        { id: '', pattern: `${home}/.*_history`, read: 'deny' as const, write: 'deny' as const },
        {
          id: '',
          pattern: `${home}/.local/share/fish/fish_history`,
          read: 'deny' as const,
          write: 'deny' as const
        }
      ])
    ]
  }
]

const LATEST_FILE_POLICY_GENERATION = FILE_POLICY_GENERATIONS.at(-1)?.generation ?? 0

// Applies to BUILT-IN groups only. A custom group is the author's own list and
// nothing here has standing to add to it.
// `generations` is injectable so a test can exercise the migration mechanism
// itself — retire, replace, no-op-when-already-past — without inventing a fake
// generation in the shipped list to do it.
export function migrateForTests(
  state: PolicyState,
  generations: FilePolicyGeneration[] = FILE_POLICY_GENERATIONS
): PolicyState {
  return backfillFilePolicies(state, generations)
}

function backfillFilePolicies(
  state: PolicyState,
  generations: FilePolicyGeneration[] = FILE_POLICY_GENERATIONS
): PolicyState {
  const latest = generations.at(-1)?.generation ?? 0
  const from = state.filePolicyGeneration ?? 0
  if (from >= latest) return state

  for (const { generation, patterns, retire } of generations) {
    if (generation <= from) continue
    for (const group of state.groups) {
      if (!group.builtIn) continue

      // Retire before adding, so a generation can replace a rule with a
      // narrower one in a single step without the two fighting over ordering.
      for (const dead of retire ?? []) {
        group.filePolicies = group.filePolicies.filter(
          (p) => !(p.pattern === dead.pattern && p.read === dead.read && p.write === dead.write)
        )
      }

      for (const rule of patterns ?? []) {
        // A user who already wrote this exact pattern keeps their own values.
        if (group.filePolicies.some((p) => p.pattern === rule.pattern)) continue
        group.filePolicies.push({ ...rule, id: uid('fp') })
      }
    }
  }
  state.filePolicyGeneration = latest
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
