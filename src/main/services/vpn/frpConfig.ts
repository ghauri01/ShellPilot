import type {
  FrpProxy,
  FrpSpec,
  FrpVisitor,
  VpnValidation,
  VpnValidationIssue
} from '../../../shared/vpn'
import { VpnError } from './errors'

// frpc configuration is *generated*, never passed through. A user-pasted
// frpc.toml is executable-ish content: `plugin = "unix_domain_socket"` pointed
// at /var/run/docker.sock is root-equivalent RCE reachable from whoever runs
// the frp server. So the typed FrpSpec is the only input, and everything this
// file emits comes from fields we understand.
//
// TOML only. INI was deprecated at frp v0.52.0 and every feature added since
// is TOML/YAML/JSON-only; we pin against v0.71.0.

// ------------------------------------------------------------------ env

// Secrets travel in the child's environment, not argv. On Linux
// /proc/<pid>/environ is 0400 owner-only while /proc/<pid>/cmdline is
// world-readable, so any local user can read argv of any process. That makes
// env strictly better than argv here — not perfect (a debugger attached as the
// same user still sees it, and some `ps` implementations can be configured to
// show environment), but it removes the whole class of over-the-shoulder and
// unprivileged-local-user leaks. frp's own Go-template syntax,
// `{{ .Envs.NAME }}`, is what lets the generated TOML reference them.
export const FRP_ENV_TOKEN = 'SP_FRP_TOKEN'
export const FRP_ENV_ADMIN = 'SP_FRP_ADMIN'
export const FRP_ENV_OIDC_SECRET = 'SP_FRP_OIDC_SECRET'

export function frpProxySecretEnv(index: number): string {
  return `SP_FRP_SECRET_${index}`
}

export function frpVisitorSecretEnv(index: number): string {
  return `SP_FRP_VISITOR_SECRET_${index}`
}

export function frpPluginPasswordEnv(index: number): string {
  return `SP_FRP_PLUGIN_PW_${index}`
}

/** A quoted TOML value holding one of our own env templates. Deliberately not
 *  routed through `quote()`: that rejects `{{`, which is exactly right for
 *  anything the user typed and exactly wrong for the templates we write
 *  ourselves. The name always comes from a constant in this file. */
function envTemplate(name: string): string {
  return `"{{ .Envs.${name} }}"`
}

// ---------------------------------------------------------------- inputs

/** Per-run admin-API identity. The port is bound by us and released before
 *  frpc starts, the user is fixed, the password is 32 random bytes. */
export interface FrpRun {
  adminPort: number
  adminUser: string
}

export interface FrpRunSecrets extends FrpRun {
  adminPassword: string
}

/** Plaintext, resolved from the vault immediately before a start. Structurally
 *  a subset of ResolvedVpnSecrets so the driver can hand its bundle straight
 *  in. Records are keyed by proxy / visitor name. */
export interface FrpResolvedSecrets {
  token?: string
  oidcClientSecret?: string
  proxySecretKeys?: Record<string, string>
  pluginPasswords?: Record<string, string>
}

/** Confirmations the user ticked in the form. These are not preferences: each
 *  one corresponds to a validation error that stays an error until the user
 *  has read what it means. */
export interface FrpConfirmations {
  /** `localIP` other than 127.0.0.1 — the proxy then reaches something that is
   *  not this machine's loopback (E25). */
  allowNonLoopbackLocalIp?: boolean
  /** `transport.tls.enable = false`. */
  allowPlaintextTransport?: boolean
  /** socks5 / http_proxy plugins: the proxy becomes a general-purpose egress
   *  path out of this machine rather than a single port. */
  allowProxyPlugins?: boolean
  /** A visitor listening on something other than loopback (E25). */
  allowNonLoopbackBindAddr?: boolean
}

// ------------------------------------------------------------- escaping

// TOML basic strings can express `"` and newlines via backslash escapes, and
// it would be easy to escape-and-hope. We reject instead. A proxy name or a
// custom domain that contains a quote, a newline or a control character is not
// a value that got mangled in transit — something put it there, and the only
// safe reading of "postgres\"\nremotePort = 22" is an attempt to inject a key
// into a config we are supposed to own. Escaping it would produce a valid
// config containing an attacker-chosen *value*; rejecting it produces no
// config at all, which is the outcome we want.
//
// `{{` is rejected for the same reason one level up: frp expands Go templates
// over every string in the file, so a value containing `{{ .Envs.SP_FRP_TOKEN }}`
// would read a secret back out into a field the remote server can see.
const TEMPLATE_OPEN = '{{'

export function isSafeTomlString(value: string): boolean {
  if (value.includes('"') || value.includes('\\')) return false
  if (value.includes(TEMPLATE_OPEN)) return false
  for (let i = 0; i < value.length; i++) {
    const c = value.charCodeAt(i)
    // C0 controls (newline, CR, tab, NUL, ...) and DEL. TOML can escape some
    // of these; we do not want any of them in a value we generated.
    if (c < 0x20 || c === 0x7f) return false
  }
  return true
}

function quote(value: string): string {
  if (!isSafeTomlString(value)) {
    throw new VpnError(
      'config-invalid',
      `The value ${JSON.stringify(value)} cannot be written to a config file.`
    )
  }
  return `"${value}"`
}

function quoteList(values: string[]): string {
  return `[${values.map(quote).join(', ')}]`
}

// ------------------------------------------------------------ emission

type Row = [key: string, value: string]

// The `=` signs are aligned per block. Alignment is not decoration here: the
// generated file is shown to the user in the profile's "Generated config" pane
// and is the thing they compare against the docs when a server operator asks
// what their client is sending.
function block(rows: Row[]): string {
  const width = rows.reduce((w, [k]) => Math.max(w, k.length), 0)
  return rows.map(([k, v]) => `${k.padEnd(width)} = ${v}`).join('\n')
}

const PROXY_TYPES_WITH_SECRET = new Set(['stcp', 'sudp', 'xtcp'])

function proxyBlock(proxy: FrpProxy, index: number): string {
  const rows: Row[] = [
    ['name', quote(proxy.name)],
    ['type', quote(proxy.type)],
    ['localIP', quote(proxy.localIp)],
    ['localPort', String(proxy.localPort)]
  ]
  if (proxy.remotePort !== undefined) rows.push(['remotePort', String(proxy.remotePort)])
  if (proxy.customDomains?.length) rows.push(['customDomains', quoteList(proxy.customDomains)])
  if (proxy.subdomain) rows.push(['subdomain', quote(proxy.subdomain)])
  if (PROXY_TYPES_WITH_SECRET.has(proxy.type) && proxy.secretKeyRef) {
    rows.push(['secretKey', envTemplate(frpProxySecretEnv(index))])
  }

  const parts = ['[[proxies]]', block(rows)]
  if (proxy.plugin) {
    const pluginRows: Row[] = [['type', quote(proxy.plugin.name)]]
    if (proxy.plugin.username) pluginRows.push(['username', quote(proxy.plugin.username)])
    if (proxy.plugin.passwordRef) {
      pluginRows.push(['password', envTemplate(frpPluginPasswordEnv(index))])
    }
    parts.push('', '[proxies.plugin]', block(pluginRows))
  }
  return parts.join('\n')
}

function visitorBlock(visitor: FrpVisitor, index: number): string {
  const rows: Row[] = [
    ['name', quote(visitor.name)],
    ['type', quote(visitor.type)],
    ['serverName', quote(visitor.serverName)]
  ]
  if (visitor.secretKeyRef) {
    rows.push(['secretKey', envTemplate(frpVisitorSecretEnv(index))])
  }
  rows.push(['bindAddr', quote(visitor.bindAddr)], ['bindPort', String(visitor.bindPort)])
  return ['[[visitors]]', block(rows)].join('\n')
}

/** The whole frpc.toml, generated from the typed model. Throws
 *  `VpnError('config-invalid')` rather than emitting a file containing a value
 *  it could not safely quote — `validateFrpSpec` should have caught it first,
 *  and this is the backstop that makes "never escape, always reject" true even
 *  if a caller skips validation. */
export function generateFrpToml(spec: FrpSpec, run: FrpRun): string {
  const sections: string[] = []

  sections.push(
    block([
      ['serverAddr', quote(spec.serverAddr)],
      ['serverPort', String(spec.serverPort)]
    ])
  )

  const auth: Row[] = [['auth.method', quote(spec.auth.method)]]
  if (spec.auth.method === 'token') {
    // Only reference the env var when a secret actually backs it: frp expands
    // the template eagerly and an unset variable becomes an empty token, which
    // fails against frps with a confusing "authentication failed" rather than
    // the honest "you have not set a token".
    if (spec.auth.tokenRef) auth.push(['auth.token', envTemplate(FRP_ENV_TOKEN)])
  } else if (spec.auth.oidc) {
    const o = spec.auth.oidc
    auth.push(['auth.oidc.clientID', quote(o.clientId)])
    if (o.clientSecretRef) {
      auth.push(['auth.oidc.clientSecret', envTemplate(FRP_ENV_OIDC_SECRET)])
    }
    if (o.audience) auth.push(['auth.oidc.audience', quote(o.audience)])
    if (o.scope) auth.push(['auth.oidc.scope', quote(o.scope)])
    auth.push(['auth.oidc.tokenEndpointURL', quote(o.tokenEndpointUrl)])
  }
  sections.push(block(auth))

  const transport: Row[] = [
    ['transport.tls.enable', spec.transport.tlsEnable ? 'true' : 'false'],
    ['transport.protocol', quote(spec.transport.protocol)],
    ['transport.poolCount', String(spec.transport.poolCount ?? 1)],
    ['transport.heartbeatInterval', String(spec.transport.heartbeatIntervalSec ?? 30)]
  ]
  // E61: a corporate HTTP/SOCKS proxy is the only way out of some networks.
  if (spec.transport.proxyUrl) {
    transport.push(['transport.proxyURL', quote(spec.transport.proxyUrl)])
  }
  sections.push(block(transport))

  // The admin API is our control channel: readiness, per-proxy status, hot
  // reload and graceful stop all go through it. 127.0.0.1 only, and the
  // password is a per-run value that never touches disk in cleartext.
  sections.push(
    block([
      ['webServer.addr', quote('127.0.0.1')],
      ['webServer.port', String(run.adminPort)],
      ['webServer.user', quote(run.adminUser)],
      ['webServer.password', envTemplate(FRP_ENV_ADMIN)]
    ])
  )

  // Console, never a file: the supervisor captures stdout through the redactor
  // and into a bounded ring buffer. A `log.to` path would write unredacted
  // text somewhere nothing sweeps.
  sections.push(
    block([
      ['log.to', quote('console')],
      ['log.level', quote('info')]
    ])
  )

  for (const [i, proxy] of spec.proxies.entries()) sections.push(proxyBlock(proxy, i))
  for (const [i, visitor] of spec.visitors.entries()) sections.push(visitorBlock(visitor, i))

  return `${sections.join('\n\n')}\n`
}

/** The environment the generated TOML's `{{ .Envs.* }}` references resolve
 *  against. Every value here is a secret; the map is built immediately before
 *  spawn and dropped when the run ends. */
export function frpEnv(
  spec: FrpSpec,
  secrets: FrpResolvedSecrets,
  run: FrpRunSecrets
): Record<string, string> {
  const env: Record<string, string> = { [FRP_ENV_ADMIN]: run.adminPassword }

  if (spec.auth.method === 'token' && spec.auth.tokenRef && secrets.token !== undefined) {
    env[FRP_ENV_TOKEN] = secrets.token
  }
  if (spec.auth.method === 'oidc' && spec.auth.oidc?.clientSecretRef) {
    if (secrets.oidcClientSecret !== undefined) {
      env[FRP_ENV_OIDC_SECRET] = secrets.oidcClientSecret
    }
  }

  for (const [i, proxy] of spec.proxies.entries()) {
    if (PROXY_TYPES_WITH_SECRET.has(proxy.type) && proxy.secretKeyRef) {
      const key = secrets.proxySecretKeys?.[proxy.name]
      if (key !== undefined) env[frpProxySecretEnv(i)] = key
    }
    if (proxy.plugin?.passwordRef) {
      const pw = secrets.pluginPasswords?.[proxy.name]
      if (pw !== undefined) env[frpPluginPasswordEnv(i)] = pw
    }
  }

  for (const [i, visitor] of spec.visitors.entries()) {
    if (visitor.secretKeyRef) {
      // Visitors share the proxy-secret record, keyed by name. That is why
      // validation refuses a visitor whose name collides with a proxy's.
      const key = secrets.proxySecretKeys?.[visitor.name]
      if (key !== undefined) env[frpVisitorSecretEnv(i)] = key
    }
  }

  return env
}

// ---------------------------------------------------------- validation

// frp builds the server-side identity as `<user>.<name>`, so a name is part of
// a routing key rather than a label. Keep it to what frp itself accepts and
// what cannot be mistaken for structure.
const PROXY_NAME = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/
// Hostname or literal IP, including bracketed v6. Full validation is the
// engine's job; this only has to reject things that are not addresses.
const HOSTISH = /^[A-Za-z0-9._:[\]-]+$/
const DOMAIN = /^[A-Za-z0-9*._-]+$/
const PROXY_URL = /^(https?|socks5|ntlm):\/\/[^\s]+$/
const TRANSPORT_PROTOCOLS = new Set(['tcp', 'kcp', 'quic', 'websocket', 'wss'])
const PROXY_TYPES = new Set(['tcp', 'udp', 'http', 'https', 'stcp', 'sudp', 'xtcp', 'tcpmux'])
const VISITOR_TYPES = new Set(['stcp', 'sudp', 'xtcp'])
// E40: `unix_domain_socket` aimed at /var/run/docker.sock is root-equivalent
// RCE reachable from the frp server, and `static_file` is a directory-exposure
// primitive. Neither is offered in v1, and a raw-TOML import that names one is
// rejected rather than downgraded.
const ALLOWED_PLUGINS = new Set(['socks5', 'http_proxy'])
const REQUIRES_REMOTE_PORT = new Set(['tcp', 'udp'])
const REQUIRES_DOMAIN = new Set(['http', 'https'])

function isPort(n: unknown): boolean {
  return typeof n === 'number' && Number.isInteger(n) && n >= 1 && n <= 65535
}

class Issues {
  readonly list: VpnValidationIssue[] = []

  error(path: string, code: string, message: string): void {
    this.list.push({ path, severity: 'error', code, message })
  }

  warn(path: string, code: string, message: string): void {
    this.list.push({ path, severity: 'warning', code, message })
  }

  /** Every free-text field goes through here before any other rule looks at
   *  it. Returns false when the value cannot be written at all, so the caller
   *  can skip the shape checks that would only add noise. */
  text(path: string, value: string): boolean {
    if (isSafeTomlString(value)) return true
    this.error(
      path,
      'toml-unsafe-string',
      'This contains a quote, a backslash, a line break or a template marker, which cannot appear in a config file.'
    )
    return false
  }
}

function validateProxy(p: FrpProxy, i: number, issues: Issues, confirm: FrpConfirmations): void {
  const at = `proxies[${i}]`

  if (issues.text(`${at}.name`, p.name) && !PROXY_NAME.test(p.name)) {
    issues.error(
      `${at}.name`,
      'proxy-name-invalid',
      'A proxy name may use letters, digits, dot, dash and underscore, and must start with a letter or digit.'
    )
  }

  if (!PROXY_TYPES.has(p.type)) {
    issues.error(`${at}.type`, 'proxy-type-invalid', `"${p.type}" is not an frp proxy type.`)
  }

  if (issues.text(`${at}.localIp`, p.localIp)) {
    if (!HOSTISH.test(p.localIp)) {
      issues.error(`${at}.localIp`, 'local-ip-invalid', 'This is not an address.')
    } else if (p.localIp !== '127.0.0.1' && !confirm.allowNonLoopbackLocalIp) {
      // E25. Confirming is the point: the checkbox has to say which machine
      // the frp server will be able to reach, not "advanced".
      issues.error(
        `${at}.localIp`,
        'local-ip-not-loopback',
        `This proxy forwards to ${p.localIp}, which is not this machine's loopback. Confirm that you want ${p.localIp}:${p.localPort} reachable from the frp server.`
      )
    }
  }

  if (!isPort(p.localPort)) {
    issues.error(`${at}.localPort`, 'local-port-invalid', 'Enter a port between 1 and 65535.')
  }

  if (p.remotePort !== undefined && !isPort(p.remotePort)) {
    issues.error(`${at}.remotePort`, 'remote-port-invalid', 'Enter a port between 1 and 65535.')
  } else if (p.remotePort === undefined && REQUIRES_REMOTE_PORT.has(p.type)) {
    issues.error(
      `${at}.remotePort`,
      'remote-port-missing',
      `A ${p.type} proxy needs the port to open on the frp server.`
    )
  }

  for (const [j, d] of (p.customDomains ?? []).entries()) {
    if (issues.text(`${at}.customDomains[${j}]`, d) && !DOMAIN.test(d)) {
      issues.error(`${at}.customDomains[${j}]`, 'domain-invalid', 'This is not a domain name.')
    }
  }
  if (p.subdomain && issues.text(`${at}.subdomain`, p.subdomain) && !DOMAIN.test(p.subdomain)) {
    issues.error(`${at}.subdomain`, 'domain-invalid', 'This is not a subdomain.')
  }
  if (REQUIRES_DOMAIN.has(p.type) && !p.customDomains?.length && !p.subdomain) {
    issues.error(
      `${at}.customDomains`,
      'domain-missing',
      `A ${p.type} proxy needs a custom domain or a subdomain for the server to route by.`
    )
  }

  if (PROXY_TYPES_WITH_SECRET.has(p.type) && !p.secretKeyRef) {
    issues.error(
      `${at}.secretKeyRef`,
      'secret-key-missing',
      `A ${p.type} proxy is reached with a shared secret, so one is required.`
    )
  }

  if (p.plugin) {
    const name: string = p.plugin.name
    if (!ALLOWED_PLUGINS.has(name)) {
      issues.error(
        `${at}.plugin.name`,
        'plugin-not-offered',
        `The "${name}" plugin is not offered. unix_domain_socket can expose a socket such as the Docker daemon, and static_file exposes a directory; neither can be made safe with a checkbox.`
      )
    } else if (!confirm.allowProxyPlugins) {
      issues.error(
        `${at}.plugin.name`,
        'plugin-unconfirmed',
        `The "${name}" plugin turns this proxy into a general-purpose route out of this machine, not a single port. Confirm that this is what you want.`
      )
    }
    if (p.plugin.username) issues.text(`${at}.plugin.username`, p.plugin.username)
  }

  // E41. This is the gate, and it is per proxy: a profile with four proxies
  // where three were confirmed is not startable. `start()` refuses.
  if (p.acknowledgedExposure !== true) {
    issues.error(
      `${at}.acknowledgedExposure`,
      'exposure-unacknowledged',
      `Confirm that this makes ${p.localIp}:${p.localPort} reachable from the frp server.`
    )
  }
}

function validateVisitor(
  v: FrpVisitor,
  i: number,
  issues: Issues,
  confirm: FrpConfirmations
): void {
  const at = `visitors[${i}]`

  if (issues.text(`${at}.name`, v.name) && !PROXY_NAME.test(v.name)) {
    issues.error(
      `${at}.name`,
      'visitor-name-invalid',
      'A visitor name may use letters, digits, dot, dash and underscore, and must start with a letter or digit.'
    )
  }
  if (!VISITOR_TYPES.has(v.type)) {
    issues.error(`${at}.type`, 'visitor-type-invalid', `"${v.type}" is not a visitor type.`)
  }
  if (issues.text(`${at}.serverName`, v.serverName) && !PROXY_NAME.test(v.serverName)) {
    issues.error(
      `${at}.serverName`,
      'visitor-server-name-invalid',
      'This must be the name of the proxy on the other side.'
    )
  }
  if (!v.secretKeyRef) {
    issues.error(
      `${at}.secretKeyRef`,
      'secret-key-missing',
      'A visitor is authorised by a shared secret, so one is required.'
    )
  }
  if (issues.text(`${at}.bindAddr`, v.bindAddr)) {
    if (!HOSTISH.test(v.bindAddr)) {
      issues.error(`${at}.bindAddr`, 'bind-addr-invalid', 'This is not an address.')
    } else if (v.bindAddr !== '127.0.0.1' && !confirm.allowNonLoopbackBindAddr) {
      // E25 again, in the other direction: this listener is what other
      // machines on the LAN would be able to reach.
      issues.error(
        `${at}.bindAddr`,
        'bind-addr-not-loopback',
        `Listening on ${v.bindAddr} makes this reachable from the local network. Confirm that this is what you want.`
      )
    }
  }
  if (!isPort(v.bindPort)) {
    issues.error(`${at}.bindPort`, 'bind-port-invalid', 'Enter a port between 1 and 65535.')
  }
}

/** Pure and synchronous: safe to call on every keystroke. `confirm` carries
 *  the boxes the user has ticked; without them the risky-but-legitimate
 *  choices stay errors rather than becoming warnings nobody reads. */
export function validateFrpSpec(spec: FrpSpec, confirm?: FrpConfirmations): VpnValidation {
  // Falling back to the spec's own confirmations is what makes validation give
  // the same answer in the form and at start time. Without it a profile could
  // be saved and then never started.
  const confirmed: FrpConfirmations = confirm ?? spec.confirmations ?? {}
  const issues = new Issues()

  if (!spec.serverAddr.trim()) {
    issues.error('serverAddr', 'server-addr-missing', 'Enter the frp server address.')
  } else if (issues.text('serverAddr', spec.serverAddr) && !HOSTISH.test(spec.serverAddr)) {
    issues.error('serverAddr', 'server-addr-invalid', 'This is not a host name or address.')
  }
  if (!isPort(spec.serverPort)) {
    issues.error('serverPort', 'server-port-invalid', 'Enter a port between 1 and 65535.')
  }

  if (spec.auth.method === 'token') {
    if (!spec.auth.tokenRef) {
      issues.warn(
        'auth.tokenRef',
        'auth-token-missing',
        'No token is set. This only works if the frp server was configured without one.'
      )
    }
  } else if (spec.auth.method === 'oidc') {
    const o = spec.auth.oidc
    if (!o) {
      issues.error('auth.oidc', 'oidc-incomplete', 'OIDC is selected but not configured.')
    } else {
      if (!o.clientId.trim()) {
        issues.error('auth.oidc.clientId', 'oidc-incomplete', 'Enter the OIDC client ID.')
      } else issues.text('auth.oidc.clientId', o.clientId)
      if (!o.tokenEndpointUrl.trim()) {
        issues.error(
          'auth.oidc.tokenEndpointUrl',
          'oidc-incomplete',
          'Enter the OIDC token endpoint.'
        )
      } else issues.text('auth.oidc.tokenEndpointUrl', o.tokenEndpointUrl)
      if (o.audience) issues.text('auth.oidc.audience', o.audience)
      if (o.scope) issues.text('auth.oidc.scope', o.scope)
    }
  } else {
    issues.error('auth.method', 'auth-method-invalid', 'Choose token or OIDC.')
  }

  if (!TRANSPORT_PROTOCOLS.has(spec.transport.protocol)) {
    issues.error(
      'transport.protocol',
      'transport-protocol-invalid',
      `"${spec.transport.protocol}" is not an frp transport.`
    )
  }
  if (!spec.transport.tlsEnable && !confirmed.allowPlaintextTransport) {
    issues.error(
      'transport.tlsEnable',
      'tls-disabled',
      'Without TLS the control connection to the frp server is readable by anything on the path. Confirm that you want it off.'
    )
  }
  if (spec.transport.proxyUrl !== undefined) {
    if (
      issues.text('transport.proxyUrl', spec.transport.proxyUrl) &&
      !PROXY_URL.test(spec.transport.proxyUrl)
    ) {
      issues.error(
        'transport.proxyUrl',
        'proxy-url-invalid',
        'Use http://, https://, socks5:// or ntlm:// followed by host:port.'
      )
    }
  }
  const pool = spec.transport.poolCount
  if (pool !== undefined && (!Number.isInteger(pool) || pool < 0 || pool > 100)) {
    issues.error('transport.poolCount', 'pool-count-invalid', 'Enter a number between 0 and 100.')
  }
  const beat = spec.transport.heartbeatIntervalSec
  if (beat !== undefined && (!Number.isInteger(beat) || beat < 1 || beat > 3600)) {
    issues.error(
      'transport.heartbeatIntervalSec',
      'heartbeat-invalid',
      'Enter a number of seconds between 1 and 3600.'
    )
  }

  if (spec.proxies.length === 0 && spec.visitors.length === 0) {
    issues.warn('proxies', 'no-proxies', 'This profile does not forward anything yet.')
  }

  const proxyNames = new Set<string>()
  const remotePorts = new Map<number, number>()
  for (const [i, p] of spec.proxies.entries()) {
    validateProxy(p, i, issues, confirmed)
    if (proxyNames.has(p.name)) {
      issues.error(
        `proxies[${i}].name`,
        'proxy-name-duplicate',
        `Another proxy is already called "${p.name}".`
      )
    }
    proxyNames.add(p.name)
    if (p.remotePort !== undefined) {
      const first = remotePorts.get(p.remotePort)
      if (first !== undefined) {
        issues.error(
          `proxies[${i}].remotePort`,
          'remote-port-duplicate',
          `Port ${p.remotePort} on the frp server is already used by "${spec.proxies[first].name}".`
        )
      } else remotePorts.set(p.remotePort, i)
    }
  }

  const visitorNames = new Set<string>()
  const bindPorts = new Map<number, number>()
  for (const [i, v] of spec.visitors.entries()) {
    validateVisitor(v, i, issues, confirmed)
    if (visitorNames.has(v.name)) {
      issues.error(
        `visitors[${i}].name`,
        'visitor-name-duplicate',
        `Another visitor is already called "${v.name}".`
      )
    } else if (proxyNames.has(v.name)) {
      // Proxy and visitor secrets share one vault-keyed record, so a collision
      // would silently hand one entry's secret to the other.
      issues.error(
        `visitors[${i}].name`,
        'visitor-name-collides-with-proxy',
        `A proxy is already called "${v.name}". Give the visitor a different name.`
      )
    }
    visitorNames.add(v.name)
    if (isPort(v.bindPort)) {
      const first = bindPorts.get(v.bindPort)
      if (first !== undefined) {
        issues.error(
          `visitors[${i}].bindPort`,
          'bind-port-duplicate',
          `Port ${v.bindPort} is already used by "${spec.visitors[first].name}".`
        )
      } else bindPorts.set(v.bindPort, i)
    }
  }

  return { ok: !issues.list.some((x) => x.severity === 'error'), issues: issues.list }
}
