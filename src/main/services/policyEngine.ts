import type { AccessGroup, AiCapability, PermissionValue, PolicyAssignment } from '../../shared/mcp'
import type { VpnKind } from '../../shared/vpn'

export interface Decision {
  decision: PermissionValue
  reason: string
}

// Server-specific assignment overrides the workspace default; a workspace
// with no assignment at all defaults to No AI Access (null groupId).
export function resolveGroupId(
  assignments: PolicyAssignment[],
  serverId: string,
  workspaceId: string
): string | null {
  const serverOverride = assignments.find((a) => a.scope.level === 'server' && a.scope.serverId === serverId)
  if (serverOverride) return serverOverride.groupId

  const workspaceDefault = assignments.find(
    (a) => a.scope.level === 'workspace' && a.scope.workspaceId === workspaceId
  )
  if (workspaceDefault) return workspaceDefault.groupId

  return null
}

export function evaluateCapability(group: AccessGroup | null, capability: AiCapability): Decision {
  if (!group) return { decision: 'deny', reason: 'No AI access is assigned to this server.' }
  // A group saved before this capability existed has no entry for it. Falling
  // through with `undefined` would read as neither 'deny' nor 'ask' at the call
  // sites and quietly behave like ALLOW, so an upgrade would silently widen
  // what every existing group permits. Absent means denied.
  const value = group.capabilities[capability] ?? 'deny'
  return { decision: value, reason: `${group.name}: ${capability} = ${value}` }
}

const RANK: Record<PermissionValue, number> = { deny: 0, ask: 1, allow: 2 }

// The session's own access group (chosen when the user created the session)
// is a ceiling: a per-server/workspace assignment can only narrow what that
// session is allowed to do, never widen it. Whichever side is more
// restrictive wins.
export function mostRestrictive(a: Decision, b: Decision): Decision {
  return RANK[a.decision] <= RANK[b.decision] ? a : b
}

// Commands that hand the AI an interactive/unrestricted shell as root. These
// are always denied — never ASK, never ALLOW, regardless of access group —
// because approving one is indistinguishable from granting an unrestricted
// root shell, which the brief says must never happen even implicitly.
const UNRESTRICTED_SHELL_PATTERNS = [
  /^sudo\s+-i\b/,
  /^sudo\s+su\b/,
  /^sudo\s+-s\b/,
  /^sudo\s+(?:(?:\/usr)?\/bin\/)?(?:ba|z|da)?sh\b/,
  /^sudo\s+su\s+-/,
  /^su\s+-?\s*$/,
  /^su\s+-\s*\w*$/
]

export interface CommandClassification {
  isSudo: boolean
  isUnrestrictedShell: boolean
}

export function classifyCommand(command: string): CommandClassification {
  const trimmed = command.trim()
  const isSudo = /^sudo\b/.test(trimmed) || /^doas\b/.test(trimmed)
  const isUnrestrictedShell = UNRESTRICTED_SHELL_PATTERNS.some((rx) => rx.test(trimmed))
  return { isSudo, isUnrestrictedShell }
}


// Absolute paths a command will read or write, as far as that can be told from
// a command line.
//
// The point is that `execute_command "cat /etc/shadow"` and
// `read_file /etc/shadow` must not disagree. Path rules only ever applied to
// the SFTP tools, so the seeded /etc/shadow and /root/.ssh/** denies were
// bypassed by the tool an agent reaches for first.
//
// This is deliberately best-effort and deliberately narrow:
//
//   * Only ABSOLUTE paths are considered. A relative operand cannot be matched
//     against a pattern like "/etc/shadow" without knowing the remote working
//     directory, and treating every bare word as a path would put a file
//     decision in front of commands that touch no files at all.
//   * Only well-known file-reading and file-writing commands are inspected.
//     Guessing at arbitrary binaries would produce noise, not safety.
//
// So `cd /root/.ssh && cat id_rsa` still gets through, and always will while
// commands are strings. It closes the direct, obvious form — which is the form
// a model actually emits — and it never widens anything: the result is folded
// in with mostRestrictive.
const READ_COMMANDS = new Set([
  'cat', 'bat', 'head', 'tail', 'less', 'more', 'nl', 'tac', 'rev', 'strings', 'xxd', 'od', 'hexdump',
  'base64', 'md5sum', 'sha1sum', 'sha256sum', 'sha512sum', 'cksum', 'wc', 'cut', 'sort', 'uniq',
  'grep', 'egrep', 'fgrep', 'rgrep', 'awk', 'diff', 'cmp', 'file', 'stat', 'readlink', 'realpath'
])

const WRITE_COMMANDS = new Set([
  'tee', 'truncate', 'shred', 'rm', 'unlink', 'install', 'ln', 'touch', 'mkdir', 'rmdir',
  'chmod', 'chown', 'chgrp', 'dd'
])

// Read their source operands and write their last one.
const COPY_COMMANDS = new Set(['cp', 'mv', 'rsync', 'scp'])

// Wrappers whose own flags precede the command that matters.
const PREFIXES = new Set(['sudo', 'doas', 'command', 'env', 'nohup', 'time', 'nice', 'ionice', 'stdbuf'])

// Short flags on those wrappers that consume the next token, so `sudo -u root
// cat /etc/shadow` does not stop at "root" and conclude the command was `root`.
const PREFIX_VALUE_FLAGS: Record<string, Set<string>> = {
  sudo: new Set(['-u', '-g', '-C', '-D', '-h', '-p', '-r', '-t', '-U', '-R']),
  doas: new Set(['-u', '-C']),
  env: new Set(['-u', '-C', '-S']),
  nice: new Set(['-n']),
  ionice: new Set(['-c', '-n', '-p']),
  stdbuf: new Set(['-i', '-o', '-e'])
}

export interface PathAccess {
  path: string
  mode: 'read' | 'write'
}

// Splits on the shell operators that start a new command, respecting quotes so
// a separator inside an argument is not treated as one.
function splitSegments(command: string): string[] {
  const out: string[] = []
  let current = ''
  let quote: string | null = null
  for (let i = 0; i < command.length; i++) {
    const c = command[i]
    if (quote) {
      if (c === quote) quote = null
      current += c
      continue
    }
    if (c === '"' || c === "'") {
      quote = c
      current += c
      continue
    }
    const two = command.slice(i, i + 2)
    if (two === '&&' || two === '||') {
      out.push(current)
      current = ''
      i++
      continue
    }
    if (c === ';' || c === '|' || c === '\n') {
      out.push(current)
      current = ''
      continue
    }
    current += c
  }
  out.push(current)
  return out.filter((s) => s.trim())
}

function tokenize(segment: string): string[] {
  const tokens: string[] = []
  let current = ''
  let quote: string | null = null
  for (const c of segment) {
    if (quote) {
      if (c === quote) quote = null
      else current += c
      continue
    }
    if (c === '"' || c === "'") {
      quote = c
      continue
    }
    if (/\s/.test(c)) {
      if (current) tokens.push(current)
      current = ''
      continue
    }
    current += c
  }
  if (current) tokens.push(current)
  return tokens
}

const isAbsolute = (t: string): boolean => t.startsWith('/')

export function extractPathAccesses(command: string): PathAccess[] {
  const found: PathAccess[] = []

  for (const segment of splitSegments(command)) {
    // Redirections bind to the segment, not to any particular argv entry, and
    // `> /etc/passwd` is a write however harmless the command in front of it.
    for (const m of segment.matchAll(/(\d?>>?|<)\s*("[^"]*"|'[^']*'|\S+)/g)) {
      const target = m[2].replace(/^["']|["']$/g, '')
      if (isAbsolute(target)) found.push({ path: target, mode: m[1].includes('>') ? 'write' : 'read' })
    }

    let tokens = tokenize(segment.replace(/(\d?>>?|<)\s*("[^"]*"|'[^']*'|\S+)/g, ' '))
    while (tokens.length && PREFIXES.has(tokens[0].split('/').pop() ?? '')) {
      const wrapper = tokens[0].split('/').pop() ?? ''
      const valueFlags = PREFIX_VALUE_FLAGS[wrapper] ?? new Set<string>()
      tokens = tokens.slice(1)
      while (tokens.length && tokens[0].startsWith('-')) {
        const takesValue = valueFlags.has(tokens[0])
        tokens = tokens.slice(takesValue ? 2 : 1)
      }
      // `env FOO=bar cmd` and `sudo FOO=bar cmd`
      while (tokens.length && /^[A-Za-z_][A-Za-z0-9_]*=/.test(tokens[0])) tokens = tokens.slice(1)
    }
    if (tokens.length === 0) continue

    const name = tokens[0].split('/').pop() ?? ''
    const operands = tokens.slice(1).filter((t) => !t.startsWith('-'))

    if (COPY_COMMANDS.has(name)) {
      // Last operand is the destination; everything before it is a source.
      operands.forEach((t, i) => {
        if (!isAbsolute(t)) return
        found.push({ path: t, mode: i === operands.length - 1 && operands.length > 1 ? 'write' : 'read' })
      })
      continue
    }

    // `sed -i` edits in place; without it the operands are only read.
    const mode: 'read' | 'write' | null =
      name === 'sed' || name === 'perl'
        ? tokens.some((t) => /^-\w*i/.test(t))
          ? 'write'
          : 'read'
        : READ_COMMANDS.has(name)
          ? 'read'
          : WRITE_COMMANDS.has(name)
            ? 'write'
            : null
    if (!mode) continue

    // grep/awk/sed take a pattern or script before their file operands, but a
    // pattern is not an absolute path, so filtering on that is enough.
    for (const t of operands) {
      if (isAbsolute(t)) found.push({ path: t, mode })
      // dd if=/x of=/y
      const kv = /^(if|of)=(.+)$/.exec(t)
      if (kv && isAbsolute(kv[2])) found.push({ path: kv[2], mode: kv[1] === 'of' ? 'write' : 'read' })
    }
  }

  return found
}

export function evaluateCommand(group: AccessGroup | null, command: string): Decision {
  if (!group) return { decision: 'deny', reason: 'No AI access is assigned to this server.' }

  const terminal = evaluateCapability(group, 'terminal')
  if (terminal.decision === 'deny') return { decision: 'deny', reason: 'Terminal access is denied for this access group.' }

  const { isSudo, isUnrestrictedShell } = classifyCommand(command)
  if (isUnrestrictedShell) {
    return {
      decision: 'deny',
      reason: 'Unrestricted privilege-escalation shells (sudo -i, su, sudo bash, ...) are always blocked.'
    }
  }

  // Both branches fall through to the path check below rather than returning:
  // `sudo cat /etc/shadow` under a group with sudo=allow must still be refused
  // by the /etc/shadow rule, not waved through because sudo was permitted.
  let base: Decision
  if (isSudo) {
    const sudo = evaluateCapability(group, 'sudo')
    if (sudo.decision === 'deny') return { decision: 'deny', reason: 'Sudo is denied for this access group.' }
    base =
      sudo.decision === 'ask'
        ? { decision: 'ask', reason: 'Sudo commands require approval.' }
        : { decision: 'allow', reason: 'Sudo allowed by access group.' }
  } else {
    base =
      terminal.decision === 'ask'
        ? { decision: 'ask', reason: 'Terminal commands require approval for this access group.' }
        : { decision: 'allow', reason: 'Allowed by access group.' }
  }

  // A path rule can only narrow the command decision, never widen it.
  return extractPathAccesses(command).reduce<Decision>(
    (acc, { path, mode }) => mostRestrictive(acc, evaluateFilePath(group, path, mode)),
    base
  )
}

// Minimal glob support: `**` crosses path segments, `*` stays within one,
// `?` matches a single character. Good enough for policy patterns like
// "/etc/nginx/**" without pulling in a dependency.
export function globToRegExp(glob: string): RegExp {
  let pattern = glob.replace(/[.+^${}()|[\]\\]/g, '\\$&')
  const DOUBLESTAR = ' DOUBLESTAR '
  pattern = pattern.replace(/\*\*/g, DOUBLESTAR)
  pattern = pattern.replace(/\*/g, '[^/]*')
  pattern = pattern.split(`${DOUBLESTAR}/`).join('(?:.*/)?')
  pattern = pattern.split(DOUBLESTAR).join('.*')
  pattern = pattern.replace(/\?/g, '[^/]')
  return new RegExp(`^${pattern}$`)
}

export function evaluateFilePath(
  group: AccessGroup | null,
  path: string,
  mode: 'read' | 'write'
): Decision {
  if (!group) return { decision: 'deny', reason: 'No AI access is assigned to this server.' }

  const capability: AiCapability = mode === 'read' ? 'readFiles' : 'writeFiles'
  const blanket = evaluateCapability(group, capability)

  const matches = group.filePolicies
    .filter((rule) => globToRegExp(rule.pattern).test(path))
    .filter((rule) => (mode === 'read' ? rule.read : rule.write) !== undefined)
    .sort((a, b) => b.pattern.length - a.pattern.length)

  const best = matches[0]
  if (best) {
    const value = (mode === 'read' ? best.read : best.write) as PermissionValue
    return { decision: value, reason: `Path rule "${best.pattern}" (${mode}) = ${value}` }
  }

  if (blanket.decision === 'deny') {
    return { decision: 'deny', reason: `${mode === 'read' ? 'Reading' : 'Writing'} files is denied for this access group.` }
  }
  return blanket
}


// Database statements, classified the way commands already are.
//
// databaseAccess defaults to ALLOW in every built-in group, because until now
// nothing was gated on it. Shipping a query tool that simply honoured that
// would hand a Full Access agent a silent DROP TABLE, so this follows the rule
// the codebase already applies to sudo: the dangerous form is never granted
// silently, whatever the group says.
//
// Reads are governed by databaseAccess alone. Anything that writes is also
// bounded by writeFiles — a group whose whole point is that it cannot change
// anything should not be able to change a row either — and can never resolve
// better than ASK.
export type StatementKind = 'read' | 'mutating' | 'destructive'

const DESTRUCTIVE = /^(drop|truncate|alter|create|rename|grant|revoke|flushall|flushdb|shutdown)\b/
const MUTATING =
  /^(insert|update|delete|replace|merge|upsert|copy|load|call|do|set|del|unlink|expire|rpush|lpush|sadd|hset|incr|decr|append|getset|move|migrate|restore|persist)\b/
const READ = /^(select|show|explain|describe|desc|with|values|table|analyze|get|mget|keys|scan|type|ttl|exists|llen|lrange|smembers|hget|hgetall|zrange|info|dbsize|find|aggregate|count|distinct|list)\b/

// Strips leading comments and parenthesised prefixes so the verb is the first
// thing tested, and splits on ; so a read cannot smuggle a write behind one.
function statements(sql: string): string[] {
  return sql
    .replace(/\/\*[\s\S]*?\*\//g, ' ')
    .replace(/--[^\n]*/g, ' ')
    .split(';')
    .map((s) => s.trim().replace(/^\(+/, '').trim().toLowerCase())
    .filter(Boolean)
}

// Mongo shell statements lead with the collection, not the verb —
// db.users.find({}) — so the leading-verb tests never see the operation.
const MONGO = /^db\.(?:getcollection\(['"]?[\w.$-]+['"]?\)|[\w.$-]+)\.(\w+)\s*\(/
const MONGO_READ = new Set([
  'find', 'findone', 'aggregate', 'count', 'countdocuments', 'estimateddocumentcount',
  'distinct', 'getindexes', 'stats', 'explain', 'watch'
])
const MONGO_DESTRUCTIVE = new Set(['drop', 'dropindex', 'dropindexes', 'renamecollection'])

function classifyMongo(s: string): StatementKind | null {
  if (/^db\.dropdatabase\s*\(/.test(s)) return 'destructive'
  const m = MONGO.exec(s)
  if (!m) return null
  const method = m[1].toLowerCase()
  if (MONGO_DESTRUCTIVE.has(method)) return 'destructive'
  return MONGO_READ.has(method) ? 'read' : 'mutating'
}

export function classifyStatement(sql: string): StatementKind {
  let worst: StatementKind = 'read'
  for (const s of statements(sql)) {
    const mongo = classifyMongo(s)
    if (mongo === 'destructive') return 'destructive'
    if (mongo === 'mutating') {
      worst = 'mutating'
      continue
    }
    if (mongo === 'read') continue

    if (DESTRUCTIVE.test(s)) return 'destructive'
    if (MUTATING.test(s)) worst = 'mutating'
    // An unrecognised verb is treated as mutating rather than read. There are
    // far too many dialects to enumerate, and guessing "harmless" is the
    // expensive direction to be wrong in.
    else if (!READ.test(s)) worst = worst === 'read' ? 'mutating' : worst
  }
  return worst
}

export function evaluateDatabaseStatement(group: AccessGroup | null, sql: string): Decision {
  if (!group) return { decision: 'deny', reason: 'No AI access is assigned to this workspace.' }

  const access = evaluateCapability(group, 'databaseAccess')
  if (access.decision === 'deny') return { decision: 'deny', reason: 'Database access is denied for this access group.' }

  const kind = classifyStatement(sql)
  if (kind === 'read') return access

  const write = evaluateCapability(group, 'writeFiles')
  if (write.decision === 'deny') {
    return {
      decision: 'deny',
      reason: `This statement ${kind === 'destructive' ? 'changes schema or permissions' : 'modifies data'}, and this access group cannot write.`
    }
  }
  const combined = mostRestrictive(access, write)
  // Never silently: a write or a DDL always surfaces an approval prompt.
  return combined.decision === 'allow'
    ? { decision: 'ask', reason: `Statements that ${kind === 'destructive' ? 'change schema or permissions' : 'modify data'} always require approval.` }
    : combined
}

// Opening a tunnel binds a listener on the user's own machine, so it gets the
// same treatment: bounded by sshTunnel and never granted silently.
export function evaluateTunnelOpen(group: AccessGroup | null): Decision {
  if (!group) return { decision: 'deny', reason: 'No AI access is assigned to this workspace.' }
  const tunnel = evaluateCapability(group, 'sshTunnel')
  if (tunnel.decision === 'deny') return { decision: 'deny', reason: 'SSH tunnels are denied for this access group.' }
  return tunnel.decision === 'allow'
    ? { decision: 'ask', reason: 'Opening a tunnel binds a port on your machine and always requires approval.' }
    : tunnel
}

// VPN kinds an AI agent may never run, whatever access group governs it.
//
// The same treatment as UNRESTRICTED_SHELL_PATTERNS above, for the same reason.
// Every frp proxy makes a port on the user's own machine reachable from the frp
// server, which is to say from the public internet. An approval prompt would
// not help: "Start VPN office" is indistinguishable, to the person clicking it,
// from consent to publish a port. So it is not expressed as a permission an
// administrator could raise to 'allow' — it is refused here, in code, and the
// user opens an frp profile themselves in ShellPilot or it does not open.
const AI_REFUSED_VPN_KINDS: ReadonlySet<VpnKind> = new Set<VpnKind>(['frp'])

export function isVpnKindRefusedForAi(kind: VpnKind): boolean {
  return AI_REFUSED_VPN_KINDS.has(kind)
}

// Starting a VPN is a bigger act than opening a tunnel: a tunnel binds one
// port, a VPN changes which network everything downstream of it travels over.
// So it is never silent — not even for a group that says 'allow' — and a stop
// that would cut live sessions surfaces that fact before it happens.
export function evaluateVpnControl(
  group: AccessGroup | null,
  action: 'start' | 'stop',
  hasLiveDependents: boolean
): Decision {
  if (!group) return { decision: 'deny', reason: 'No AI access is assigned to this workspace.' }
  const cap = evaluateCapability(group, 'vpnControl')
  if (cap.decision === 'deny') return { decision: 'deny', reason: 'VPN control is denied for this access group.' }
  if (action === 'start') {
    return cap.decision === 'allow'
      ? { decision: 'ask', reason: 'Starting a VPN changes where your traffic goes and always requires approval.' }
      : cap
  }
  if (hasLiveDependents && cap.decision === 'allow') {
    return { decision: 'ask', reason: 'Stopping this VPN will close sessions that depend on it.' }
  }
  return cap
}
