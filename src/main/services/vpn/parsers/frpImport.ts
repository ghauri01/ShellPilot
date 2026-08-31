import type {
  FrpOidc,
  FrpProxy,
  FrpProxyType,
  FrpSpec,
  FrpVisitor,
  StrippedDirective,
  VpnImportResultInternal
} from '../../../../shared/vpn'
import { VpnError } from '../errors'
import { PENDING_VAULT_ENTRY } from './wgConf'

// frp client import: v1 TOML and the legacy v0 INI, both into a typed FrpSpec.
// The INI path is the one-click converter the plan calls for — we emit TOML
// only, so a v0 file is read here and never handed to frpc.
//
// frp inverts the rest of the app's threat model. Every proxy makes a local
// port reachable *from the frp server*, so the import is deliberately timid:
// localIp defaults to loopback, TLS defaults on, the two filesystem-reaching
// plugins are refused outright, and `acknowledgedExposure` always arrives
// false so the user has to tick each proxy themselves (E41).

export interface FrpRejectRule {
  /** Stable id. A fixture named `reject-<id>.toml` or `reject-<id>.ini` must
   *  exist under `tests/fixtures/frp/`; a meta-test asserts it. */
  id: string
  reason: string
}

export const FRP_REJECT_RULES: readonly FrpRejectRule[] = [
  {
    id: 'plugin-unix-domain-socket',
    reason:
      'The unix_domain_socket plugin exposes a local socket to the frp server. Pointed at docker.sock it is root-equivalent remote code execution, so ShellPilot does not offer it.'
  },
  {
    id: 'plugin-static-file',
    reason: 'The static_file plugin serves a directory to the frp server, which is a file-disclosure primitive.'
  },
  {
    id: 'plugin-unsupported',
    reason:
      'ShellPilot only runs the socks5 and http_proxy plugins. Dropping an unsupported one would silently change what this proxy exposes.'
  }
]

const REJECTED_PLUGINS: Record<string, string> = {
  unix_domain_socket: 'plugin-unix-domain-socket',
  static_file: 'plugin-static-file'
}

const SUPPORTED_PLUGINS = new Set(['socks5', 'http_proxy'])

const PROXY_TYPES = new Set<FrpProxyType>(['tcp', 'udp', 'http', 'https', 'stcp', 'sudp', 'xtcp', 'tcpmux'])
const VISITOR_TYPES = new Set(['stcp', 'sudp', 'xtcp'])
const TRANSPORTS = new Set(['tcp', 'kcp', 'quic', 'websocket', 'wss'])

const LOOPBACK = /^(127(\.\d{1,3}){3}|::1|localhost)$/i

// ------------------------------------------------------------- TOML subset

export type TomlValue = string | number | boolean | TomlValue[] | TomlTable
export interface TomlTable {
  [key: string]: TomlValue
}

function tomlFail(lineNo: number, why: string): never {
  throw new VpnError('config-invalid', `Line ${lineNo}: ${why}`)
}

/** Cut a `#` comment, but only when it is outside a string. */
function stripTomlComment(line: string): string {
  let quote: string | null = null
  for (let i = 0; i < line.length; i++) {
    const c = line[i]
    if (quote) {
      if (c === '\\' && quote === '"') i++
      else if (c === quote) quote = null
      continue
    }
    if (c === '"' || c === "'") quote = c
    else if (c === '#') return line.slice(0, i)
  }
  return line
}

/** Bracket and brace depth outside strings, so a multi-line array or inline
 *  table can be joined into one logical line before it is parsed. */
function depthOf(line: string): number {
  let quote: string | null = null
  let depth = 0
  for (let i = 0; i < line.length; i++) {
    const c = line[i]
    if (quote) {
      if (c === '\\' && quote === '"') i++
      else if (c === quote) quote = null
      continue
    }
    if (c === '"' || c === "'") quote = c
    else if (c === '[' || c === '{') depth++
    else if (c === ']' || c === '}') depth--
  }
  return depth
}

function skipWs(s: string, i: number): number {
  while (i < s.length && /\s/.test(s[i])) i++
  return i
}

function parseTomlString(s: string, i: number, lineNo: number): [string, number] {
  const q = s[i]
  i++
  let out = ''
  while (i < s.length) {
    const c = s[i]
    if (c === q) return [out, i + 1]
    if (c === '\\' && q === '"') {
      const n = s[i + 1]
      if (n === 'n') out += '\n'
      else if (n === 't') out += '\t'
      else if (n === 'r') out += '\r'
      else if (n === 'b') out += '\b'
      else if (n === 'f') out += '\f'
      else if (n === 'u') {
        out += String.fromCharCode(parseInt(s.slice(i + 2, i + 6), 16))
        i += 6
        continue
      } else out += n
      i += 2
      continue
    }
    out += c
    i++
  }
  tomlFail(lineNo, 'unterminated string.')
}

function parseTomlValue(s: string, i: number, lineNo: number): [TomlValue, number] {
  i = skipWs(s, i)
  if (i >= s.length) tomlFail(lineNo, 'a key with no value.')
  const c = s[i]

  if (c === '"' || c === "'") return parseTomlString(s, i, lineNo)

  if (c === '[') {
    const arr: TomlValue[] = []
    i = skipWs(s, i + 1)
    while (i < s.length && s[i] !== ']') {
      const [v, next] = parseTomlValue(s, i, lineNo)
      arr.push(v)
      i = skipWs(s, next)
      if (s[i] === ',') i = skipWs(s, i + 1)
    }
    if (s[i] !== ']') tomlFail(lineNo, 'unterminated array.')
    return [arr, i + 1]
  }

  if (c === '{') {
    const table: TomlTable = {}
    i = skipWs(s, i + 1)
    while (i < s.length && s[i] !== '}') {
      const [path, next] = parseTomlKeyPath(s, i, lineNo)
      let j = skipWs(s, next)
      if (s[j] !== '=') tomlFail(lineNo, 'expected `=` inside an inline table.')
      const [v, after] = parseTomlValue(s, j + 1, lineNo)
      setPath(table, path, v, lineNo)
      j = skipWs(s, after)
      if (s[j] === ',') j = skipWs(s, j + 1)
      i = j
    }
    if (s[i] !== '}') tomlFail(lineNo, 'unterminated inline table.')
    return [table, i + 1]
  }

  let j = i
  while (j < s.length && !/[,\]}\s]/.test(s[j])) j++
  const raw = s.slice(i, j)
  if (raw === 'true') return [true, j]
  if (raw === 'false') return [false, j]
  const num = Number(raw.replace(/_/g, ''))
  if (raw !== '' && Number.isFinite(num)) return [num, j]
  tomlFail(lineNo, `"${raw}" is not a value this importer understands.`)
}

function parseTomlKeyPath(s: string, i: number, lineNo: number): [string[], number] {
  const path: string[] = []
  for (;;) {
    i = skipWs(s, i)
    if (s[i] === '"' || s[i] === "'") {
      const [key, next] = parseTomlString(s, i, lineNo)
      path.push(key)
      i = next
    } else {
      let j = i
      while (j < s.length && /[A-Za-z0-9_-]/.test(s[j])) j++
      if (j === i) tomlFail(lineNo, 'expected a key.')
      path.push(s.slice(i, j))
      i = j
    }
    const k = skipWs(s, i)
    if (s[k] === '.') {
      i = k + 1
      continue
    }
    return [path, i]
  }
}

/** Walk to the table `path` names, creating tables as needed. A segment whose
 *  current value is an array of tables resolves to that array's last element,
 *  which is what makes `[proxies.plugin]` after `[[proxies]]` work. */
function walk(root: TomlTable, path: string[], lineNo: number): TomlTable {
  let cur = root
  for (const seg of path) {
    let next = cur[seg]
    if (next === undefined) {
      next = {}
      cur[seg] = next
    }
    if (Array.isArray(next)) {
      const last = next[next.length - 1]
      if (typeof last !== 'object' || Array.isArray(last)) tomlFail(lineNo, `"${seg}" is not a table.`)
      cur = last as TomlTable
      continue
    }
    if (typeof next !== 'object') tomlFail(lineNo, `"${seg}" is not a table.`)
    cur = next as TomlTable
  }
  return cur
}

function setPath(table: TomlTable, path: string[], value: TomlValue, lineNo: number): void {
  const parent = walk(table, path.slice(0, -1), lineNo)
  parent[path[path.length - 1]] = value
}

/** A deliberately small TOML reader: tables, arrays of tables, dotted keys,
 *  strings, numbers, booleans, arrays and inline tables. That is everything an
 *  frpc.toml uses, and writing it is cheaper than adding a dependency to an app
 *  that ships no TOML anywhere else. */
export function parseTomlSubset(text: string): TomlTable {
  const root: TomlTable = {}
  let current = root
  const lines = text.split(/\r?\n/)

  for (let i = 0; i < lines.length; i++) {
    let line = stripTomlComment(lines[i]).trim()
    const lineNo = i + 1
    if (!line) continue

    // Join a value that spans lines.
    let guard = 0
    while (depthOf(line) > 0 && i + 1 < lines.length && guard++ < 1000) {
      i++
      line += ` ${stripTomlComment(lines[i]).trim()}`
    }

    if (line.startsWith('[[')) {
      const end = line.lastIndexOf(']]')
      if (end === -1) tomlFail(lineNo, 'unterminated table header.')
      const [path] = parseTomlKeyPath(line.slice(2, end), 0, lineNo)
      const parent = walk(root, path.slice(0, -1), lineNo)
      const key = path[path.length - 1]
      const existing = parent[key]
      const arr = Array.isArray(existing) ? existing : []
      if (!Array.isArray(existing)) parent[key] = arr
      const table: TomlTable = {}
      arr.push(table)
      current = table
      continue
    }

    if (line.startsWith('[')) {
      const end = line.lastIndexOf(']')
      if (end === -1) tomlFail(lineNo, 'unterminated table header.')
      const [path] = parseTomlKeyPath(line.slice(1, end), 0, lineNo)
      current = walk(root, path, lineNo)
      continue
    }

    const [path, afterKey] = parseTomlKeyPath(line, 0, lineNo)
    const eq = skipWs(line, afterKey)
    if (line[eq] !== '=') tomlFail(lineNo, 'expected `key = value`.')
    const [value] = parseTomlValue(line, eq + 1, lineNo)
    setPath(current, path, value, lineNo)
  }
  return root
}

// -------------------------------------------------------------- legacy INI

/** frp v0 `frpc.ini`. Values are unquoted, and every section other than
 *  `[common]` is a proxy or a visitor named by the section header. */
function parseLegacyIni(text: string): Map<string, Map<string, string>> {
  const sections = new Map<string, Map<string, string>>()
  let current = 'common'
  sections.set(current, new Map())

  const lines = text.split(/\r?\n/)
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i].trim()
    if (!line || line.startsWith('#') || line.startsWith(';')) continue
    const header = /^\[([^\]]+)\]$/.exec(line)
    if (header) {
      current = header[1].trim()
      if (!sections.has(current)) sections.set(current, new Map())
      continue
    }
    const eq = line.indexOf('=')
    if (eq === -1) throw new VpnError('config-invalid', `Line ${i + 1}: ${line} — expected \`key = value\`.`)
    const key = line.slice(0, eq).trim().toLowerCase()
    let value = line.slice(eq + 1).trim()
    if (value.length > 1 && ((value.startsWith('"') && value.endsWith('"')) || (value.startsWith("'") && value.endsWith("'")))) {
      value = value.slice(1, -1)
    }
    sections.get(current)?.set(key, value)
  }
  return sections
}

// ------------------------------------------------------------------ import

interface Ctx {
  stripped: StrippedDirective[]
  warnings: string[]
  secretKeys: Record<string, string>
}

function drop(ctx: Ctx, directive: string, reason: string): void {
  ctx.stripped.push({ directive, reason, severity: 'removed' })
}

function reject(ctx: Ctx, id: string, directive: string): never {
  const rule = FRP_REJECT_RULES.find((r) => r.id === id)
  if (!rule) throw new VpnError('internal', `no reject rule "${id}"`)
  ctx.stripped.push({ directive, reason: rule.reason, severity: 'rejected' })
  throw new VpnError('config-rejected', `${directive} — ${rule.reason}`)
}

export function parseFrpConfig(text: string): VpnImportResultInternal {
  const ctx: Ctx = { stripped: [], warnings: [], secretKeys: {} }
  try {
    // A file exported on Windows often starts with a BOM.
    const body = text.replace(/^\uFEFF/, '')
    return isLegacyIni(body) ? fromIni(body, ctx) : fromToml(body, ctx)
  } catch (e) {
    if (e instanceof VpnError) {
      return {
        ok: false,
        error: e.message,
        errorCode: e.code,
        stripped: ctx.stripped,
        warnings: ctx.warnings
      }
    }
    throw e
  }
}

/** A v0 file always has a `[common]` section; a v1 file never does. */
export function isLegacyIni(text: string): boolean {
  return /^[ \t]*\[common\][ \t]*$/im.test(text)
}

// ------------------------------------------------------------------ shared

function requireHost(value: string, what: string): string {
  const v = value.trim()
  if (!v || !/^[A-Za-z0-9._:-]{1,253}$/.test(v)) {
    throw new VpnError('config-invalid', `"${value}" is not a valid ${what}.`)
  }
  return v
}

/** `min` is 0 for a plugin proxy's local port: a plugin *is* the service, so
 *  there is no local port behind it and frp writes 0 or omits it. */
function requirePort(value: unknown, what: string, min = 1): number {
  const n = typeof value === 'number' ? value : Number(String(value ?? '').trim())
  if (!Number.isInteger(n) || n < min || n > 65535) {
    throw new VpnError('config-invalid', `"${String(value)}" is not a valid ${what}.`)
  }
  return n
}

function requireName(value: string): string {
  const v = value.trim()
  if (!v || !/^[A-Za-z0-9._-]{1,64}$/.test(v)) {
    throw new VpnError('config-invalid', `"${value}" is not a usable proxy name.`)
  }
  return v
}

/** Every proxy is an exposure decision, so the flag the driver gates on always
 *  arrives false and the user has to tick it per proxy (E41). */
function newProxy(name: string, type: FrpProxyType, localPort: number, localIp: string): FrpProxy {
  return { name, type, localIp, localPort, acknowledgedExposure: false }
}

function noteLocalIp(ctx: Ctx, name: string, ip: string): void {
  if (LOOPBACK.test(ip)) return
  ctx.warnings.push(
    `Proxy "${name}" listens on ${ip} rather than 127.0.0.1, so it can also forward traffic that reaches this machine on your local network. Confirm that is what you want before starting it.`
  )
}

function notePlugin(ctx: Ctx, name: string, plugin: string): void {
  const what =
    plugin === 'socks5'
      ? 'a SOCKS5 proxy, so anything that reaches it can open connections from this machine to anywhere'
      : 'an HTTP proxy, so anything that reaches it can make HTTP requests from this machine'
  ctx.warnings.push(`Proxy "${name}" runs ${what}. Confirm that before starting it.`)
}

function checkPlugin(ctx: Ctx, name: string, plugin: string): 'socks5' | 'http_proxy' {
  const p = plugin.trim()
  const rejectId = REJECTED_PLUGINS[p]
  if (rejectId) reject(ctx, rejectId, `[${name}] plugin = "${p}"`)
  if (!SUPPORTED_PLUGINS.has(p)) reject(ctx, 'plugin-unsupported', `[${name}] plugin = "${p}"`)
  notePlugin(ctx, name, p)
  return p as 'socks5' | 'http_proxy'
}

function finish(
  ctx: Ctx,
  spec: FrpSpec,
  secrets: { token?: string; password?: string }
): VpnImportResultInternal {
  if (spec.proxies.length === 0 && spec.visitors.length === 0) {
    throw new VpnError('config-invalid', 'This file defines no proxies or visitors, so there is nothing to run.')
  }
  spec.strippedDirectives = ctx.stripped
  if (spec.proxies.length > 0) {
    ctx.warnings.push(
      `Each proxy makes a port on this machine reachable from ${spec.serverAddr}. None of them will start until you confirm that, one by one.`
    )
  }
  const out: VpnImportResultInternal = {
    ok: true,
    spec,
    name: spec.serverAddr,
    stripped: ctx.stripped,
    warnings: ctx.warnings
  }
  const secretKeys = Object.keys(ctx.secretKeys).length > 0 ? { proxySecretKeys: ctx.secretKeys } : {}
  if (secrets.token !== undefined || secrets.password !== undefined || Object.keys(secretKeys).length > 0) {
    out.secrets = { ...secrets, ...secretKeys }
  }
  return out
}

// -------------------------------------------------------------------- TOML

function str(v: TomlValue | undefined): string | undefined {
  return typeof v === 'string' ? v : undefined
}

function asTable(v: TomlValue | undefined): TomlTable | undefined {
  return v && typeof v === 'object' && !Array.isArray(v) ? (v as TomlTable) : undefined
}

function asTableArray(v: TomlValue | undefined): TomlTable[] {
  if (!Array.isArray(v)) return []
  return v.filter((e): e is TomlTable => typeof e === 'object' && !Array.isArray(e))
}

const TOML_TOP_LEVEL_KNOWN = new Set(['serverAddr', 'serverPort', 'auth', 'transport', 'proxies', 'visitors'])

const TOML_PROXY_KNOWN = new Set([
  'name',
  'type',
  'localIP',
  'localIp',
  'localPort',
  'remotePort',
  'customDomains',
  'subdomain',
  'secretKey',
  'plugin'
])

const TOML_VISITOR_KNOWN = new Set(['name', 'type', 'serverName', 'secretKey', 'bindAddr', 'bindPort'])

function fromToml(text: string, ctx: Ctx): VpnImportResultInternal {
  const root = parseTomlSubset(text)

  const serverAddr = requireHost(str(root.serverAddr) ?? '', 'frp server address')
  const serverPort = requirePort(root.serverPort ?? 7000, 'frp server port')

  for (const key of Object.keys(root)) {
    if (TOML_TOP_LEVEL_KNOWN.has(key)) continue
    drop(ctx, key, 'ShellPilot generates the log, web-server and process settings itself.')
  }

  const authTable = asTable(root.auth) ?? {}
  const transport = asTable(root.transport) ?? {}
  const tls = asTable(transport.tls)

  const spec: FrpSpec = {
    kind: 'frp',
    serverAddr,
    serverPort,
    auth: { method: 'token' },
    transport: { protocol: 'tcp', tlsEnable: true },
    proxies: [],
    visitors: []
  }
  const secrets: { token?: string; password?: string } = {}

  const method = str(authTable.method) ?? 'token'
  if (method === 'oidc') {
    const oidcTable = asTable(authTable.oidc) ?? {}
    const oidc: FrpOidc = {
      clientId: str(oidcTable.clientID) ?? str(oidcTable.clientId) ?? '',
      tokenEndpointUrl: str(oidcTable.tokenEndpointURL) ?? str(oidcTable.tokenEndpointUrl) ?? ''
    }
    if (!oidc.clientId || !oidc.tokenEndpointUrl) {
      throw new VpnError('config-invalid', 'OIDC authentication needs a client id and a token endpoint.')
    }
    if (str(oidcTable.audience)) oidc.audience = str(oidcTable.audience)
    if (str(oidcTable.scope)) oidc.scope = str(oidcTable.scope)
    const clientSecret = str(oidcTable.clientSecret)
    if (clientSecret) {
      secrets.password = clientSecret
      oidc.clientSecretRef = { vaultEntryId: PENDING_VAULT_ENTRY, field: 'password' }
    }
    spec.auth = { method: 'oidc', oidc }
  } else if (method !== 'token') {
    throw new VpnError('config-invalid', `"${method}" is not an authentication method frp offers.`)
  } else {
    const token = str(authTable.token)
    if (token) {
      secrets.token = token
      spec.auth.tokenRef = { vaultEntryId: PENDING_VAULT_ENTRY, field: 'token' }
    }
  }

  const protocol = str(transport.protocol) ?? 'tcp'
  if (!TRANSPORTS.has(protocol)) throw new VpnError('config-invalid', `"${protocol}" is not an frp transport.`)
  spec.transport.protocol = protocol as FrpSpec['transport']['protocol']

  if (tls && typeof tls.enable === 'boolean') {
    spec.transport.tlsEnable = tls.enable
    if (!tls.enable) {
      ctx.warnings.push(
        'This file turns off TLS between frpc and the frp server. ShellPilot leaves it off only because the file asked; turning it back on is safer.'
      )
    }
  }
  const proxyUrl = str(transport.proxyURL) ?? str(transport.proxyUrl)
  if (proxyUrl) spec.transport.proxyUrl = proxyUrl
  if (typeof transport.poolCount === 'number') spec.transport.poolCount = transport.poolCount
  if (typeof transport.heartbeatInterval === 'number') {
    spec.transport.heartbeatIntervalSec = transport.heartbeatInterval
  }

  for (const p of asTableArray(root.proxies)) {
    const name = requireName(str(p.name) ?? '')
    const type = (str(p.type) ?? '') as FrpProxyType
    if (!PROXY_TYPES.has(type)) throw new VpnError('config-invalid', `Proxy "${name}" has type "${str(p.type) ?? ''}".`)
    // The plugin is settled first: a rejected plugin must fail the import as a
    // rejection, not as whatever the rest of the entry happens to trip over.
    const plugin = asTable(p.plugin)
    const pluginName = plugin ? checkPlugin(ctx, name, str(plugin.type) ?? '') : undefined

    // Loopback unless the file explicitly asked for something else.
    const localIp = str(p.localIP) ?? str(p.localIp) ?? '127.0.0.1'
    const proxy = newProxy(
      name,
      type,
      requirePort(p.localPort ?? (plugin ? 0 : undefined), `local port for proxy "${name}"`, plugin ? 0 : 1),
      requireHost(localIp, 'local address')
    )
    noteLocalIp(ctx, name, proxy.localIp)
    if (p.remotePort !== undefined) proxy.remotePort = requirePort(p.remotePort, `remote port for proxy "${name}"`)
    const domains = Array.isArray(p.customDomains) ? p.customDomains.filter((d): d is string => typeof d === 'string') : []
    if (domains.length > 0) proxy.customDomains = domains.map((d) => requireHost(d, 'custom domain'))
    if (str(p.subdomain)) proxy.subdomain = requireHost(str(p.subdomain) as string, 'subdomain')

    const secretKey = str(p.secretKey)
    if (secretKey) {
      ctx.secretKeys[name] = secretKey
      proxy.secretKeyRef = { vaultEntryId: PENDING_VAULT_ENTRY, field: 'proxySecretKey', fieldKey: name }
    }

    if (plugin && pluginName) {
      proxy.plugin = { name: pluginName }
      if (str(plugin.username)) proxy.plugin.username = str(plugin.username)
      const password = str(plugin.password)
      if (password) {
        ctx.secretKeys[`plugin:${name}`] = password
        proxy.plugin.passwordRef = {
          vaultEntryId: PENDING_VAULT_ENTRY,
          field: 'proxySecretKey',
          fieldKey: `plugin:${name}`
        }
      }
    }

    for (const key of Object.keys(p)) {
      if (TOML_PROXY_KNOWN.has(key)) continue
      drop(ctx, `[${name}] ${key}`, 'Not a proxy setting ShellPilot carries over.')
    }
    spec.proxies.push(proxy)
  }

  for (const v of asTableArray(root.visitors)) {
    for (const key of Object.keys(v)) {
      if (TOML_VISITOR_KNOWN.has(key)) continue
      drop(ctx, `[${str(v.name) ?? '?'}] ${key}`, 'Not a visitor setting ShellPilot carries over.')
    }
    spec.visitors.push(visitorFrom(ctx, {
      name: str(v.name) ?? '',
      type: str(v.type) ?? '',
      serverName: str(v.serverName) ?? '',
      secretKey: str(v.secretKey),
      bindAddr: str(v.bindAddr),
      bindPort: v.bindPort
    }))
  }

  return finish(ctx, spec, secrets)
}

function visitorFrom(
  ctx: Ctx,
  raw: { name: string; type: string; serverName: string; secretKey?: string; bindAddr?: string; bindPort?: unknown }
): FrpVisitor {
  const name = requireName(raw.name)
  if (!VISITOR_TYPES.has(raw.type)) {
    throw new VpnError('config-invalid', `Visitor "${name}" has type "${raw.type}", which is not stcp, sudp or xtcp.`)
  }
  const visitor: FrpVisitor = {
    name,
    type: raw.type as FrpVisitor['type'],
    serverName: requireName(raw.serverName),
    bindAddr: requireHost(raw.bindAddr ?? '127.0.0.1', 'bind address'),
    bindPort: requirePort(raw.bindPort, `bind port for visitor "${name}"`)
  }
  if (!LOOPBACK.test(visitor.bindAddr)) {
    ctx.warnings.push(
      `Visitor "${name}" listens on ${visitor.bindAddr} rather than 127.0.0.1, so other machines on your network can use it.`
    )
  }
  if (raw.secretKey) {
    ctx.secretKeys[name] = raw.secretKey
    visitor.secretKeyRef = { vaultEntryId: PENDING_VAULT_ENTRY, field: 'proxySecretKey', fieldKey: name }
  }
  return visitor
}

// --------------------------------------------------------------------- INI

const INI_COMMON_KNOWN = new Set([
  'server_addr',
  'server_port',
  'token',
  'authentication_method',
  'oidc_client_id',
  'oidc_client_secret',
  'oidc_audience',
  'oidc_scope',
  'oidc_token_endpoint_url',
  'tls_enable',
  'protocol',
  'pool_count',
  'heartbeat_interval',
  'http_proxy'
])

const INI_PROXY_KNOWN = new Set([
  'type',
  'local_ip',
  'local_port',
  'remote_port',
  'custom_domains',
  'subdomain',
  'sk',
  'role',
  'server_name',
  'bind_addr',
  'bind_port',
  'plugin',
  'plugin_user',
  'plugin_passwd',
  'plugin_http_user',
  'plugin_http_passwd'
])

function iniBool(v: string | undefined): boolean | undefined {
  if (v === undefined) return undefined
  const t = v.trim().toLowerCase()
  if (t === 'true' || t === '1') return true
  if (t === 'false' || t === '0') return false
  return undefined
}

function fromIni(text: string, ctx: Ctx): VpnImportResultInternal {
  const sections = parseLegacyIni(text)
  const common = sections.get('common') ?? new Map<string, string>()

  ctx.warnings.push(
    'This is a legacy frp INI file. ShellPilot has converted it to the v1 model; check the proxies below before starting anything.'
  )

  const serverAddr = requireHost(common.get('server_addr') ?? '', 'frp server address')
  const serverPort = requirePort(common.get('server_port') ?? 7000, 'frp server port')

  const spec: FrpSpec = {
    kind: 'frp',
    serverAddr,
    serverPort,
    auth: { method: 'token' },
    transport: { protocol: 'tcp', tlsEnable: true },
    proxies: [],
    visitors: []
  }
  const secrets: { token?: string; password?: string } = {}

  const method = (common.get('authentication_method') ?? 'token').toLowerCase()
  if (method === 'oidc') {
    const oidc: FrpOidc = {
      clientId: common.get('oidc_client_id') ?? '',
      tokenEndpointUrl: common.get('oidc_token_endpoint_url') ?? ''
    }
    if (!oidc.clientId || !oidc.tokenEndpointUrl) {
      throw new VpnError('config-invalid', 'OIDC authentication needs a client id and a token endpoint.')
    }
    const audience = common.get('oidc_audience')
    const scope = common.get('oidc_scope')
    if (audience) oidc.audience = audience
    if (scope) oidc.scope = scope
    const clientSecret = common.get('oidc_client_secret')
    if (clientSecret) {
      secrets.password = clientSecret
      oidc.clientSecretRef = { vaultEntryId: PENDING_VAULT_ENTRY, field: 'password' }
    }
    spec.auth = { method: 'oidc', oidc }
  } else if (method !== 'token') {
    throw new VpnError('config-invalid', `"${method}" is not an authentication method frp offers.`)
  } else {
    const token = common.get('token')
    if (token) {
      secrets.token = token
      spec.auth.tokenRef = { vaultEntryId: PENDING_VAULT_ENTRY, field: 'token' }
    }
  }

  const protocol = (common.get('protocol') ?? 'tcp').toLowerCase()
  if (!TRANSPORTS.has(protocol)) throw new VpnError('config-invalid', `"${protocol}" is not an frp transport.`)
  spec.transport.protocol = protocol as FrpSpec['transport']['protocol']

  const tlsEnable = iniBool(common.get('tls_enable'))
  if (tlsEnable === undefined) {
    // v0 defaulted this off; v1 defaults it on, and so do we.
    ctx.warnings.push('The original file did not set tls_enable. ShellPilot has turned TLS on.')
  } else {
    spec.transport.tlsEnable = tlsEnable
    if (!tlsEnable) {
      ctx.warnings.push(
        'This file turns off TLS between frpc and the frp server. ShellPilot leaves it off only because the file asked; turning it back on is safer.'
      )
    }
  }
  const httpProxy = common.get('http_proxy')
  if (httpProxy) spec.transport.proxyUrl = httpProxy
  const pool = common.get('pool_count')
  if (pool && /^\d+$/.test(pool)) spec.transport.poolCount = Number(pool)
  const heartbeat = common.get('heartbeat_interval')
  if (heartbeat && /^\d+$/.test(heartbeat)) spec.transport.heartbeatIntervalSec = Number(heartbeat)

  for (const [key] of common) {
    if (INI_COMMON_KNOWN.has(key)) continue
    drop(ctx, `[common] ${key}`, 'ShellPilot generates the log, admin-API and process settings itself.')
  }

  for (const [section, values] of sections) {
    if (section === 'common') continue
    const name = requireName(section)

    if ((values.get('role') ?? '').toLowerCase() === 'visitor') {
      spec.visitors.push(
        visitorFrom(ctx, {
          name,
          type: (values.get('type') ?? '').toLowerCase(),
          serverName: values.get('server_name') ?? '',
          secretKey: values.get('sk'),
          bindAddr: values.get('bind_addr'),
          bindPort: values.get('bind_port')
        })
      )
      for (const [key] of values) {
        if (INI_PROXY_KNOWN.has(key)) continue
        drop(ctx, `[${name}] ${key}`, 'Not a setting ShellPilot carries over.')
      }
      continue
    }

    const type = (values.get('type') ?? '').toLowerCase() as FrpProxyType
    if (!PROXY_TYPES.has(type)) {
      throw new VpnError('config-invalid', `Proxy "${name}" has type "${values.get('type') ?? ''}".`)
    }
    // Settled first, so a rejected plugin fails the import as a rejection
    // rather than as whatever the rest of the section happens to trip over.
    const plugin = values.get('plugin')
    const pluginName = plugin ? checkPlugin(ctx, name, plugin) : undefined

    const localIp = values.get('local_ip') ?? '127.0.0.1'
    const proxy = newProxy(
      name,
      type,
      requirePort(values.get('local_port') ?? (plugin ? 0 : undefined), `local port for proxy "${name}"`, plugin ? 0 : 1),
      requireHost(localIp, 'local address')
    )
    noteLocalIp(ctx, name, proxy.localIp)
    const remotePort = values.get('remote_port')
    if (remotePort) proxy.remotePort = requirePort(remotePort, `remote port for proxy "${name}"`)
    const domains = (values.get('custom_domains') ?? '')
      .split(',')
      .map((d) => d.trim())
      .filter(Boolean)
    if (domains.length > 0) proxy.customDomains = domains.map((d) => requireHost(d, 'custom domain'))
    const subdomain = values.get('subdomain')
    if (subdomain) proxy.subdomain = requireHost(subdomain, 'subdomain')

    const sk = values.get('sk')
    if (sk) {
      ctx.secretKeys[name] = sk
      proxy.secretKeyRef = { vaultEntryId: PENDING_VAULT_ENTRY, field: 'proxySecretKey', fieldKey: name }
    }

    if (plugin && pluginName) {
      proxy.plugin = { name: pluginName }
      const user = values.get('plugin_user') ?? values.get('plugin_http_user')
      if (user) proxy.plugin.username = user
      const password = values.get('plugin_passwd') ?? values.get('plugin_http_passwd')
      if (password) {
        ctx.secretKeys[`plugin:${name}`] = password
        proxy.plugin.passwordRef = {
          vaultEntryId: PENDING_VAULT_ENTRY,
          field: 'proxySecretKey',
          fieldKey: `plugin:${name}`
        }
      }
    }

    for (const [key] of values) {
      if (INI_PROXY_KNOWN.has(key)) continue
      drop(ctx, `[${name}] ${key}`, 'Not a setting ShellPilot carries over.')
    }

    spec.proxies.push(proxy)
  }

  return finish(ctx, spec, secrets)
}
