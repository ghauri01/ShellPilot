import { readFileSync, realpathSync, statSync } from 'node:fs'
import { isAbsolute, resolve, sep } from 'node:path'
import type {
  OpenVpnAuthMode,
  OpenVpnSpec,
  StrippedDirective,
  VpnImportResultInternal
} from '../../../../shared/vpn'
import { VpnError } from '../errors'
import { hostHasIpv6, PENDING_VAULT_ENTRY } from './wgConf'

// The OpenVPN config sanitizer.
//
// A `.ovpn` file is executable content. `up`, `down`, `route-up`, `ipchange`,
// `tls-verify`, `client-connect`, `learn-address`, `auth-user-pass-verify` and
// `plugin` all run programs, and `up` runs *before* any server is contacted —
// so an attacker who can hand you a file needs no server at all. This is a
// documented RCE class (Tenable, Claroty Team82).
//
// The governing rule: **we never hand the user's file to openvpn.** Every line
// is parsed into a typed model and a config *we* generated is re-emitted.
// Three tiers:
//
//   ALLOWED        re-emitted, after its value is validated
//   DROPPED        not emitted, reported in `stripped` as `removed`
//   HARD-REJECTED  the whole import fails, reported as `rejected`
//
// Hard reject rather than silent strip is deliberate. The profile author
// intended those side effects, so a "connected" tunnel without them is not the
// thing the user asked for — and a silent strip teaches the user nothing about
// having been handed a config that tried to run a program.

const MAX_MATERIAL_BYTES = 512 * 1024
const MAX_CONFIG_LINES = 20000

// ---------------------------------------------------------------- rejects

export interface OvpnRejectRule {
  /** Stable id. `tests/fixtures/ovpn/reject-<id>.ovpn` must exist — a meta-test
   *  asserts it, so the reject list and its fixtures cannot drift apart. */
  id: string
  /** Directive names matched exactly, after `--` is stripped and lowercased. */
  directives?: readonly string[]
  /** Directive-name prefix, for the `management*` family. */
  prefix?: string
  reason: string
}

export const OVPN_REJECT_RULES: readonly OvpnRejectRule[] = [
  // --- runs a program ---
  { id: 'up', directives: ['up'], reason: 'up runs a program, and it runs before any server is contacted.' },
  { id: 'down', directives: ['down'], reason: 'down runs a program when the tunnel closes.' },
  {
    id: 'up-restart',
    directives: ['up-restart'],
    reason: 'up-restart re-runs the up program on every restart.'
  },
  { id: 'route-up', directives: ['route-up'], reason: 'route-up runs a program once routes are added.' },
  {
    id: 'route-pre-down',
    directives: ['route-pre-down'],
    reason: 'route-pre-down runs a program before routes are removed.'
  },
  {
    id: 'ipchange',
    directives: ['ipchange'],
    reason: 'ipchange runs a program whenever the remote address changes.'
  },
  {
    id: 'tls-verify',
    directives: ['tls-verify'],
    reason: 'tls-verify runs a program during the TLS handshake.'
  },
  {
    id: 'tls-export-cert',
    directives: ['tls-export-cert'],
    reason: 'tls-export-cert writes peer certificates into a directory the config author chose.'
  },
  { id: 'client-connect', directives: ['client-connect'], reason: 'client-connect runs a program on connect.' },
  {
    id: 'client-disconnect',
    directives: ['client-disconnect'],
    reason: 'client-disconnect runs a program on disconnect.'
  },
  {
    id: 'learn-address',
    directives: ['learn-address'],
    reason: 'learn-address runs a program for every address the tunnel learns.'
  },
  {
    id: 'auth-user-pass-verify',
    directives: ['auth-user-pass-verify'],
    reason: 'auth-user-pass-verify runs a program and hands it credentials.'
  },
  { id: 'plugin', directives: ['plugin'], reason: 'plugin loads a shared library into the OpenVPN process.' },
  {
    id: 'script-security',
    directives: ['script-security'],
    reason: 'script-security is what enables every one of the script directives. ShellPilot always sets it to 0.'
  },

  // --- arbitrary read, write or process control ---
  {
    id: 'config',
    directives: ['config'],
    reason: 'config includes another file, which would smuggle unreviewed directives past this check.'
  },
  { id: 'chroot', directives: ['chroot'], reason: 'chroot changes the process root directory.' },
  { id: 'cd', directives: ['cd'], reason: 'cd changes the working directory, which re-points every relative path.' },
  { id: 'tmp-dir', directives: ['tmp-dir'], reason: 'tmp-dir chooses where OpenVPN writes temporary files.' },
  { id: 'daemon', directives: ['daemon'], reason: 'daemon detaches the process from ShellPilot’s supervision.' },
  { id: 'askpass', directives: ['askpass'], reason: 'askpass reads a passphrase from a file on disk.' },
  { id: 'writepid', directives: ['writepid'], reason: 'writepid writes to a path of the config author’s choosing.' },
  {
    id: 'log',
    directives: ['log', 'log-append'],
    reason: 'log and log-append write to an arbitrary path, and would take the output away from the log drawer.'
  },
  {
    id: 'status',
    directives: ['status', 'status-version'],
    reason: 'status writes a status file to a path of the config author’s choosing.'
  },
  {
    id: 'management',
    prefix: 'management',
    reason:
      'The management interface is how ShellPilot drives OpenVPN. A config that sets its own would hand control of the process to whoever wrote the file.'
  },

  // --- routing ---
  {
    id: 'ifconfig-noexec',
    directives: ['ifconfig-noexec'],
    reason: 'ifconfig-noexec suppresses the interface setup ShellPilot relies on.'
  },
  { id: 'route-method-exe', reason: 'route-method exe adds routes by running an external program.' },

  // --- environment ---
  {
    id: 'setenv',
    reason:
      'setenv puts an arbitrary value into the process environment, where a later directive or a pushed option can pick it up.'
  },

  // --- credentials and key material read from disk ---
  {
    id: 'auth-user-pass-file',
    reason:
      'auth-user-pass with a file name reads credentials from disk and sends them to the server. ShellPilot supplies credentials over the management channel instead.'
  },
  {
    id: 'http-proxy-authfile',
    reason: 'http-proxy with an authentication file reads that file from disk and sends its contents to the proxy.'
  },
  {
    id: 'socks-proxy-authfile',
    reason: 'socks-proxy with an authentication file reads that file from disk and sends its contents to the proxy.'
  },
  {
    id: 'path-escape',
    reason: 'This certificate or key path points outside the folder the profile was imported from.'
  },

  // --- shape of the file itself ---
  {
    id: 'inline-unknown',
    reason: 'Only certificate and key blocks may be inline. Any other block could carry unreviewed directives.'
  },
  {
    id: 'quote-injection',
    reason:
      'A quote, backslash or control character in a value could break out of the generated config or out of a management-interface command.'
  }
]

const REJECT_BY_DIRECTIVE = new Map<string, OvpnRejectRule>()
const REJECT_PREFIXES: OvpnRejectRule[] = []
for (const rule of OVPN_REJECT_RULES) {
  for (const d of rule.directives ?? []) REJECT_BY_DIRECTIVE.set(d, rule)
  if (rule.prefix) REJECT_PREFIXES.push(rule)
}

function normaliseDirective(name: string): string {
  return name.replace(/^-{1,2}/, '').toLowerCase()
}

function ruleById(id: string): OvpnRejectRule {
  const r = OVPN_REJECT_RULES.find((x) => x.id === id)
  if (!r) throw new VpnError('internal', `no reject rule "${id}"`)
  return r
}

/** The rule that forbids `name`, or null. Matching runs on the normalised name
 *  — leading `--` stripped, lowercased — so neither casing nor the `--` form
 *  can be used to slip a script directive past the check. */
export function ovpnRejectRuleFor(name: string): OvpnRejectRule | null {
  const n = normaliseDirective(name)
  const exact = REJECT_BY_DIRECTIVE.get(n)
  if (exact) return exact
  for (const rule of REJECT_PREFIXES) if (n.startsWith(rule.prefix as string)) return rule
  return null
}

// ------------------------------------------------------------- allowlists

const FLAGS = new Set([
  'client',
  'nobind',
  'persist-key',
  'persist-tun',
  'remote-random',
  'float',
  'tls-client',
  'route-nopull',
  'ping-timer-rem'
])

// name -> [min, max]
const INTS: Record<string, [number, number]> = {
  'reneg-sec': [0, 604800],
  ping: [0, 3600],
  'ping-restart': [0, 3600],
  'tun-mtu': [576, 9000],
  fragment: [0, 9000],
  sndbuf: [0, 16777216],
  rcvbuf: [0, 16777216],
  'key-direction': [0, 1]
}

const PROTOS = new Set(['udp', 'udp4', 'udp6', 'tcp', 'tcp4', 'tcp6', 'tcp-client'])
const TOPOLOGIES = new Set(['subnet', 'net30', 'p2p'])
const X509_TYPES = new Set(['name', 'name-prefix', 'subject'])
const DHCP_OPTIONS = new Set(['DNS', 'DOMAIN', 'DOMAIN-SEARCH'])
const REDIRECT_FLAGS = new Set([
  'def1',
  'local',
  'autolocal',
  'bypass-dhcp',
  'bypass-dns',
  'block-local',
  'ipv6',
  '!ipv4'
])
const ROUTE_KEYWORDS = new Set(['vpn_gateway', 'net_gateway', 'remote_host', 'default'])
const PROXY_AUTH_KEYWORDS = new Set(['auto', 'auto-nct'])
const PROXY_AUTH_METHODS = new Set(['basic', 'ntlm', 'ntlm2', 'none'])

/** The only blocks allowed inline, and the only directives allowed to name a
 *  file. Everything here ends up inside the re-emitted config as a block. */
const INLINE_TAGS = ['ca', 'cert', 'key', 'tls-auth', 'tls-crypt', 'tls-crypt-v2', 'dh', 'pkcs12'] as const
const INLINE_TAG_SET: ReadonlySet<string> = new Set<string>(INLINE_TAGS)

// Dropped with a report rather than rejected: nothing an attacker reaches
// through, but carrying them over would be wrong.
const DROP_REASONS: Record<string, string> = {
  'comp-lzo': 'Compression inside a VPN is a plaintext-recovery vector (VORACLE), so ShellPilot never enables it.',
  compress: 'Compression inside a VPN is a plaintext-recovery vector (VORACLE), so ShellPilot never enables it.',
  'comp-noadapt': 'Compression inside a VPN is a plaintext-recovery vector (VORACLE), so ShellPilot never enables it.',
  mute: 'ShellPilot keeps the whole engine output in the log drawer rather than muting part of it.',
  'mute-replay-warnings': 'ShellPilot keeps the whole engine output in the log drawer rather than muting part of it.',
  nice: 'Process priority is ShellPilot’s to decide.',
  'fast-io': 'A tuning flag with no effect on how this profile connects.'
}

const SETENV_NAMES = new Set(['FORWARD_COMPATIBLE', 'CLIENT_CERT'])
const SETENV_UV = /^UV_[A-Z0-9_]{1,32}$/
const SETENV_VALUE = /^[A-Za-z0-9._:-]{0,64}$/

// ------------------------------------------------------------ pull-filters

/** Always emitted. A clean local config is only half the job — a hostile
 *  *server* can push these (E38). */
export const OVPN_PULL_FILTER_REJECTS: readonly string[] = [
  'script-security',
  'up ',
  'down ',
  'route-method',
  'setenv opt '
]

// ------------------------------------------------------------------ parse

interface Ctx {
  stripped: StrippedDirective[]
  warnings: string[]
  out: string[]
  inline: Map<string, string>
  remotes: { host: string; port: number; proto: string }[]
  baseDir?: string
  globalProto?: string
  authUserPass: boolean
  staticChallenge?: { text: string; echo: boolean }
  redirectGatewayRequested: boolean
  keyDirection?: string
  carriesIpv6: boolean
  usesTcp: boolean
}

function drop(ctx: Ctx, directive: string, reason: string): void {
  ctx.stripped.push({ directive, reason, severity: 'removed' })
}

function reject(ctx: Ctx, rule: OvpnRejectRule, lineNo: number, raw: string, directive?: string): never {
  ctx.stripped.push({ directive: directive ?? rule.id, reason: rule.reason, severity: 'rejected' })
  throw new VpnError('config-rejected', `Line ${lineNo}: ${raw.trim()} — ${rule.reason}`)
}

function invalid(lineNo: number, raw: string, why: string): never {
  throw new VpnError('config-invalid', `Line ${lineNo}: ${raw.trim()} — ${why}`)
}

function unsupported(lineNo: number, raw: string, why: string): never {
  throw new VpnError('unsupported', `Line ${lineNo}: ${raw.trim()} — ${why}`)
}

/** Anything that could end a value early, start a directive of its own, or
 *  break out of a `"`-quoted management-interface command. No directive in the
 *  allowed set has a legitimate use for one, so a value carrying any of them
 *  fails the import rather than being quietly escaped away. */
// eslint-disable-next-line no-control-regex -- rejecting them is the point
const DANGEROUS = /["\\\r\n\x00-\x1f\x7f]/

function checkSafe(ctx: Ctx, tokens: string[], lineNo: number, raw: string): void {
  for (const t of tokens) {
    if (DANGEROUS.test(t)) reject(ctx, ruleById('quote-injection'), lineNo, raw, normaliseDirective(tokens[0]))
  }
}

/** OpenVPN's own tokenizer: whitespace-separated, `"` and `'` quoting, and
 *  `\\`/`\"` escapes inside double quotes. Escapes are resolved here, so
 *  `verify-x509-name "a\"b"` is seen as a value containing a quote and hits
 *  `checkSafe` instead of being written back out as an escape we trust. */
function tokenize(line: string, lineNo: number, raw: string): string[] {
  const tokens: string[] = []
  let i = 0
  while (i < line.length) {
    while (i < line.length && /\s/.test(line[i])) i++
    if (i >= line.length) break
    const q = line[i]
    if (q === '"' || q === "'") {
      i++
      let v = ''
      let closed = false
      while (i < line.length) {
        const c = line[i]
        if (c === '\\' && q === '"' && (line[i + 1] === '\\' || line[i + 1] === '"')) {
          v += line[i + 1]
          i += 2
          continue
        }
        if (c === q) {
          closed = true
          i++
          break
        }
        v += c
        i++
      }
      if (!closed) invalid(lineNo, raw, 'unterminated quote.')
      tokens.push(v)
    } else {
      let v = ''
      while (i < line.length && !/\s/.test(line[i])) {
        v += line[i]
        i++
      }
      tokens.push(v)
    }
  }
  return tokens
}

/** Quote on the way out only when the value needs it. Everything reaching here
 *  has been proved free of quotes, backslashes and control characters, so this
 *  cannot produce a line that reparses into something else. */
export function escapeOvpnValue(v: string): string {
  if (v === '') return '""'
  return /\s/.test(v) ? `"${v}"` : v
}

function emit(ctx: Ctx, name: string, ...values: string[]): void {
  ctx.out.push([name, ...values.map(escapeOvpnValue)].join(' '))
}

function intIn(v: string, lo: number, hi: number): number | null {
  if (!/^\d+$/.test(v)) return null
  const n = Number(v)
  return n >= lo && n <= hi ? n : null
}

const HOSTISH = /^[A-Za-z0-9._:-]{1,253}$/
const IPISH = /^[0-9A-Fa-f.:/]{1,49}$/
const CIPHERISH = /^[A-Za-z0-9:+_!.@-]{1,512}$/

// -------------------------------------------------------- file containment

function tryRealpath(p: string): string | null {
  try {
    return realpathSync(p)
  } catch {
    return null
  }
}

/** Read a file named by a path-form directive, but only from inside the folder
 *  the profile was imported from. Absolute paths, `..` and symlinks that leave
 *  the folder are all rejected (E37): no file outside the import folder is ever
 *  read, so `ca /etc/shadow` cannot turn an import into an exfiltration. */
function readContained(ctx: Ctx, p: string, lineNo: number, raw: string, directive: string): Buffer {
  const escape = ruleById('path-escape')
  const base = ctx.baseDir
  if (!base) reject(ctx, escape, lineNo, raw, directive)
  if (isAbsolute(p) || p.startsWith('/') || /^[A-Za-z]:/.test(p) || p.startsWith('\\\\')) {
    reject(ctx, escape, lineNo, raw, directive)
  }
  if (p.split(/[\\/]/).some((seg) => seg === '..')) reject(ctx, escape, lineNo, raw, directive)

  const root = tryRealpath(base)
  if (!root) reject(ctx, escape, lineNo, raw, directive)
  const target = tryRealpath(resolve(root, p))
  if (!target) invalid(lineNo, raw, `the file "${p}" was not found next to the profile.`)

  const prefix = root.endsWith(sep) ? root : root + sep
  if (!target.startsWith(prefix)) reject(ctx, escape, lineNo, raw, directive)

  const st = statSync(target)
  if (!st.isFile()) invalid(lineNo, raw, `"${p}" is not a file.`)
  if (st.size > MAX_MATERIAL_BYTES) invalid(lineNo, raw, `"${p}" is larger than 512 KB.`)
  return readFileSync(target)
}

// eslint-disable-next-line no-control-regex -- rejecting them is the point
const MATERIAL_CONTROL = /[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/

/** Certificate and key blocks are PEM or base64. Neither contains `<` or `>`,
 *  and forbidding them is what stops a forged `</ca>` inside the block from
 *  closing it early and having the rest of the block parsed as directives. */
function checkMaterial(body: string, lineNo: number, raw: string, tag: string): string {
  if (body.length > MAX_MATERIAL_BYTES) invalid(lineNo, raw, `the <${tag}> block is larger than 512 KB.`)
  for (const line of body.split('\n')) {
    const l = line.replace(/\r$/, '')
    if (l.includes('<') || l.includes('>')) {
      invalid(lineNo, raw, `the <${tag}> block contains "<" or ">", which no certificate or key does.`)
    }
    if (MATERIAL_CONTROL.test(l)) invalid(lineNo, raw, `the <${tag}> block contains control characters.`)
  }
  return `${body.replace(/\r\n/g, '\n').replace(/\s*$/, '')}\n`
}

// -------------------------------------------------------------- the parser

export interface OvpnParseOptions {
  /** Overridable so the E16 warning is testable without a real v6 stack. */
  hostHasIpv6?: boolean
}

export function parseOvpn(text: string, baseDir?: string, opts: OvpnParseOptions = {}): VpnImportResultInternal {
  const ctx: Ctx = {
    stripped: [],
    warnings: [],
    out: [],
    inline: new Map(),
    remotes: [],
    baseDir,
    authUserPass: false,
    redirectGatewayRequested: false,
    carriesIpv6: false,
    usesTcp: false
  }
  try {
    return build(text, ctx, opts)
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

function build(text: string, ctx: Ctx, opts: OvpnParseOptions): VpnImportResultInternal {
  // A file exported on Windows often starts with a BOM; without this the first
  // directive would be seen as an unknown one and silently dropped.
  const lines = text.replace(/^\uFEFF/, '').split(/\r?\n/)
  if (lines.length > MAX_CONFIG_LINES) {
    throw new VpnError('config-invalid', `This file has more than ${MAX_CONFIG_LINES} lines.`)
  }

  let openTag: string | null = null
  let openTagLine = 0
  let openTagRaw = ''
  let buf: string[] = []

  for (let i = 0; i < lines.length; i++) {
    const raw = lines[i]
    const lineNo = i + 1
    const line = raw.trim()

    if (openTag) {
      if (line === `</${openTag}>`) {
        const body = checkMaterial(buf.join('\n'), openTagLine, openTagRaw, openTag)
        if (ctx.inline.has(openTag)) {
          ctx.warnings.push(`<${openTag}> appears more than once; the last block is the one used.`)
        }
        ctx.inline.set(openTag, body)
        openTag = null
        buf = []
        continue
      }
      buf.push(raw)
      continue
    }

    if (!line) continue
    if (line.startsWith('#') || line.startsWith(';')) continue

    const tag = /^<(\/?)([A-Za-z0-9_-]+)>$/.exec(line)
    if (tag) {
      if (tag[1]) invalid(lineNo, raw, `a closing </${tag[2]}> with no opening tag.`)
      const name = tag[2].toLowerCase()
      if (!INLINE_TAG_SET.has(name)) reject(ctx, ruleById('inline-unknown'), lineNo, raw, name)
      openTag = name
      openTagLine = lineNo
      openTagRaw = raw
      continue
    }

    const tokens = tokenize(line, lineNo, raw)
    if (tokens.length > 0) directive(ctx, tokens, lineNo, raw)
  }

  if (openTag) {
    throw new VpnError('config-invalid', `The <${openTag}> block opened on line ${openTagLine} is never closed.`)
  }
  return finish(ctx, opts)
}

function directive(ctx: Ctx, tokens: string[], lineNo: number, raw: string): void {
  const name = normaliseDirective(tokens[0])
  const args = tokens.slice(1)

  // Reject first, before the value is even looked at.
  const rule = ovpnRejectRuleFor(name)
  if (rule) reject(ctx, rule, lineNo, raw, name)

  // Everything that survives is either emitted or dropped. Checking here rather
  // than at emission means a quote in a value we were going to drop anyway is
  // still treated as what it almost certainly is: an attempt at injection.
  checkSafe(ctx, tokens, lineNo, raw)

  if (FLAGS.has(name)) {
    if (args.length > 0) return drop(ctx, name, `Takes no value, but was given "${args.join(' ')}".`)
    return emit(ctx, name)
  }

  const range = INTS[name]
  if (range) {
    const n = args.length === 1 ? intIn(args[0], range[0], range[1]) : null
    if (n === null) return drop(ctx, name, `Expected a number between ${range[0]} and ${range[1]}.`)
    // key-direction is emitted once at the end, next to the key it belongs to.
    if (name === 'key-direction') ctx.keyDirection = String(n)
    else emit(ctx, name, String(n))
    return
  }

  if (name in DROP_REASONS) return drop(ctx, name, DROP_REASONS[name])

  switch (name) {
    case 'dev': {
      if (!/^u?tun\d*$/.test((args[0] ?? '').toLowerCase())) {
        unsupported(lineNo, raw, 'ShellPilot only runs routed (tun) OpenVPN profiles.')
      }
      // The device name is ours to pick; carrying `tun7` over would only invite
      // a collision with another profile (E53).
      return emit(ctx, 'dev', 'tun')
    }

    case 'dev-type': {
      if ((args[0] ?? '').toLowerCase() !== 'tun') {
        unsupported(lineNo, raw, 'ShellPilot only runs routed (tun) OpenVPN profiles.')
      }
      return emit(ctx, 'dev-type', 'tun')
    }

    case 'proto': {
      const v = (args[0] ?? '').toLowerCase()
      if (args.length !== 1 || !PROTOS.has(v)) {
        return drop(ctx, name, `"${args.join(' ')}" is not a protocol OpenVPN accepts.`)
      }
      ctx.globalProto = v
      if (v.startsWith('tcp')) ctx.usesTcp = true
      if (v.endsWith('6')) ctx.carriesIpv6 = true
      return emit(ctx, name, v)
    }

    case 'remote': {
      const host = args[0] ?? ''
      if (!HOSTISH.test(host)) return drop(ctx, name, `"${host}" is not a host name or address.`)
      const port = args.length > 1 ? intIn(args[1], 1, 65535) : 1194
      if (port === null) return drop(ctx, name, `"${args[1]}" is not a port.`)
      let proto = ctx.globalProto ?? 'udp'
      if (args.length > 2) {
        const p = args[2].toLowerCase()
        if (!PROTOS.has(p)) return drop(ctx, name, `"${args[2]}" is not a protocol OpenVPN accepts.`)
        proto = p
      }
      if (proto.startsWith('tcp')) ctx.usesTcp = true
      if (proto.endsWith('6') || host.includes(':')) ctx.carriesIpv6 = true
      ctx.remotes.push({ host, port, proto })
      if (args.length > 2) emit(ctx, name, host, String(port), proto)
      else emit(ctx, name, host, String(port))
      return
    }

    case 'resolv-retry': {
      const v = (args[0] ?? '').toLowerCase()
      if (v === 'infinite') return emit(ctx, name, 'infinite')
      const n = intIn(v, 0, 86400)
      if (n === null) return drop(ctx, name, 'Expected a number of seconds, or "infinite".')
      return emit(ctx, name, String(n))
    }

    case 'remote-cert-tls': {
      if (args.length !== 1 || args[0].toLowerCase() !== 'server') {
        return drop(ctx, name, 'A client profile may only require the peer to present a server certificate.')
      }
      return emit(ctx, name, 'server')
    }

    case 'verify-x509-name': {
      const value = args[0] ?? ''
      if (!value || value.length > 256) return drop(ctx, name, 'Expected a certificate name to match.')
      if (args.length > 2) return drop(ctx, name, 'Expected at most a name and a match type.')
      if (args.length === 2) {
        const type = args[1].toLowerCase()
        if (!X509_TYPES.has(type)) return drop(ctx, name, `"${args[1]}" is not a match type.`)
        return emit(ctx, name, value, type)
      }
      return emit(ctx, name, value)
    }

    case 'cipher':
    case 'data-ciphers':
    case 'data-ciphers-fallback':
    case 'auth':
    case 'tls-cipher':
    case 'tls-groups': {
      if (args.length !== 1 || !CIPHERISH.test(args[0])) {
        return drop(ctx, name, `"${args.join(' ')}" is not an algorithm list OpenVPN accepts.`)
      }
      return emit(ctx, name, args[0])
    }

    case 'tls-version-min': {
      const v = (args[0] ?? '').toLowerCase()
      if (!/^1\.[0-3]$/.test(v)) return drop(ctx, name, 'Expected a TLS version such as 1.2.')
      if (args.length === 2) {
        if (args[1].toLowerCase() !== 'or-highest') {
          return drop(ctx, name, `"${args[1]}" is not a modifier this directive accepts.`)
        }
        return emit(ctx, name, v, 'or-highest')
      }
      return emit(ctx, name, v)
    }

    case 'mssfix': {
      const n = intIn(args[0] ?? '', 0, 9000)
      if (n === null) return drop(ctx, name, 'Expected a number.')
      if (args.length === 2) {
        const mod = args[1].toLowerCase()
        if (mod !== 'mtu' && mod !== 'fixed') {
          return drop(ctx, name, `"${args[1]}" is not a modifier this directive accepts.`)
        }
        return emit(ctx, name, String(n), mod)
      }
      return emit(ctx, name, String(n))
    }

    case 'explicit-exit-notify': {
      if (args.length === 0) return emit(ctx, name)
      const n = intIn(args[0], 0, 2)
      if (n === null) return drop(ctx, name, 'Expected 0, 1 or 2.')
      return emit(ctx, name, String(n))
    }

    case 'auth-retry': {
      if (args.length !== 1 || args[0].toLowerCase() !== 'nointeract') {
        return drop(ctx, name, 'ShellPilot always runs OpenVPN non-interactively, so only "nointeract" is carried over.')
      }
      return emit(ctx, name, 'nointeract')
    }

    case 'auth-user-pass': {
      // The file form reads credentials from disk. Ours arrive over the
      // management channel and never touch the filesystem.
      if (args.length > 0) reject(ctx, ruleById('auth-user-pass-file'), lineNo, raw, name)
      ctx.authUserPass = true
      return emit(ctx, name)
    }

    case 'static-challenge': {
      const text = args[0] ?? ''
      const echo = args[1] ?? '0'
      if (!text || text.length > 256) return drop(ctx, name, 'Expected a challenge prompt.')
      if (echo !== '0' && echo !== '1') return drop(ctx, name, 'The echo flag must be 0 or 1.')
      ctx.staticChallenge = { text, echo: echo === '1' }
      return emit(ctx, name, text, echo)
    }

    case 'redirect-gateway': {
      for (const f of args) {
        if (!REDIRECT_FLAGS.has(f.toLowerCase())) {
          return drop(ctx, name, `"${f}" is not a flag this directive accepts.`)
        }
      }
      // Never written into the body. `emitOvpnConfig` adds it back only when the
      // user has turned redirectGateway on for the profile (E13).
      ctx.redirectGatewayRequested = true
      return drop(
        ctx,
        name,
        'Sending all of your traffic through the VPN stays off until you turn it on for this profile. ShellPilot does not hijack the default route because a downloaded file asked it to.'
      )
    }

    case 'route': {
      if (args.length === 0 || args.length > 4) return drop(ctx, name, 'Expected between one and four values.')
      for (const a of args) {
        if (ROUTE_KEYWORDS.has(a.toLowerCase())) continue
        if (IPISH.test(a)) continue
        return drop(ctx, name, `"${a}" is not an address, netmask, gateway or metric.`)
      }
      return emit(ctx, name, ...args)
    }

    case 'dhcp-option': {
      const opt = (args[0] ?? '').toUpperCase()
      if (!DHCP_OPTIONS.has(opt)) {
        return drop(ctx, name, `Only DNS, DOMAIN and DOMAIN-SEARCH are carried over; "${args[0] ?? ''}" is not.`)
      }
      const value = args[1] ?? ''
      if (!HOSTISH.test(value)) return drop(ctx, name, `"${value}" is not a server or domain name.`)
      return emit(ctx, name, opt, value)
    }

    case 'topology': {
      const v = (args[0] ?? '').toLowerCase()
      if (!TOPOLOGIES.has(v)) return drop(ctx, name, `"${args[0] ?? ''}" is not a topology.`)
      return emit(ctx, name, v)
    }

    case 'http-proxy':
    case 'socks-proxy': {
      const host = args[0] ?? ''
      const port = intIn(args[1] ?? '', 1, 65535)
      if (!HOSTISH.test(host) || port === null) return drop(ctx, name, 'Expected a proxy host and port.')
      const extra: string[] = []
      if (args.length > 2) {
        const third = args[2].toLowerCase()
        // Anything that is not one of the two keywords is the name of an
        // authentication file: a read-a-file-and-send-it primitive, the same
        // class as askpass.
        if (!PROXY_AUTH_KEYWORDS.has(third)) {
          const id = name === 'http-proxy' ? 'http-proxy-authfile' : 'socks-proxy-authfile'
          reject(ctx, ruleById(id), lineNo, raw, name)
        }
        extra.push(third)
        if (args.length > 3) {
          const method = args[3].toLowerCase()
          if (!PROXY_AUTH_METHODS.has(method)) return drop(ctx, name, `"${args[3]}" is not an authentication method.`)
          extra.push(method)
        }
      }
      return emit(ctx, name, host, String(port), ...extra)
    }

    case 'setenv': {
      const key = args[0] ?? ''
      const value = args[1] ?? ''
      const allowed = args.length <= 2 && (SETENV_NAMES.has(key) || SETENV_UV.test(key)) && SETENV_VALUE.test(value)
      if (!allowed) reject(ctx, ruleById('setenv'), lineNo, raw, name)
      return emit(ctx, name, key, value)
    }

    case 'route-method': {
      if ((args[0] ?? '').toLowerCase() === 'exe') reject(ctx, ruleById('route-method-exe'), lineNo, raw, name)
      return drop(ctx, name, 'ShellPilot decides how routes are applied.')
    }

    case 'verb': {
      // E59: a hostile `verb 11` is a log-flood denial of service against the
      // ring buffer and, eventually, the disk behind it.
      const n = args.length === 1 ? intIn(args[0], 0, 11) : null
      if (n === null) return drop(ctx, name, 'Expected a number between 0 and 11.')
      if (n > 4) {
        drop(ctx, name, `Log level ${n} floods the log, so it was clamped to 4.`)
        return emit(ctx, name, '4')
      }
      return emit(ctx, name, String(n))
    }

    case 'ca':
    case 'cert':
    case 'key':
    case 'tls-auth':
    case 'tls-crypt':
    case 'tls-crypt-v2':
    case 'dh':
    case 'pkcs12': {
      const p = args[0] ?? ''
      if (!p) return drop(ctx, name, 'Expected a file name.')
      // Some exporters write both `ca [inline]` and a <ca> block.
      if (p === '[inline]') return
      const bytes = readContained(ctx, p, lineNo, raw, name)
      const body =
        name === 'pkcs12'
          ? `${bytes.toString('base64').replace(/(.{64})/g, '$1\n')}\n`
          : checkMaterial(bytes.toString('utf8'), lineNo, raw, name)
      ctx.inline.set(name, body)
      if (name === 'tls-auth' && args.length > 1) {
        const d = intIn(args[1], 0, 1)
        if (d === null) return drop(ctx, name, 'The key direction must be 0 or 1.')
        ctx.keyDirection = String(d)
      }
      return
    }

    default:
      return drop(ctx, name, 'Not a setting ShellPilot carries over.')
  }
}

function finish(ctx: Ctx, opts: OvpnParseOptions): VpnImportResultInternal {
  if (!ctx.inline.has('ca') && !ctx.inline.has('pkcs12')) {
    throw new VpnError(
      'config-invalid',
      'This profile carries no certificate authority, so the server’s identity could not be checked.'
    )
  }
  if (ctx.remotes.length === 0) {
    throw new VpnError('config-invalid', 'This profile has no remote, so there is no server to connect to.')
  }

  // Do not end any of these lines with the bare word "import" before the
  // closing quote. electron-vite injects its CommonJS shim after the last
  // thing its regex reads as an ESM static import, and that regex scans the
  // whole bundle as text: `... the import',\n '# report ...` matches as
  // `import ',\n    '`, so the shim lands in the middle of this array and the
  // production build dies with "Unterminated string literal" in a file that
  // typechecks perfectly. Rephrase rather than reformat if you touch this.
  const body: string[] = [
    '# Generated by ShellPilot from an imported OpenVPN profile.',
    '# Directives that can run a program are never carried over.',
    '# The import report lists everything that was dropped or rejected.'
  ]
  body.push(...ctx.out)
  if (ctx.keyDirection !== undefined) body.push(`key-direction ${ctx.keyDirection}`)
  for (const tag of INLINE_TAGS) {
    const content = ctx.inline.get(tag)
    if (!content) continue
    body.push(`<${tag}>`, content.replace(/\n$/, ''), `</${tag}>`)
  }
  const configBody = `${body.join('\n')}\n`

  const authMode: OpenVpnAuthMode = !ctx.authUserPass
    ? 'none'
    : ctx.staticChallenge
      ? 'userpass-otp'
      : 'userpass'

  if (!ctx.carriesIpv6 && (opts.hostHasIpv6 ?? hostHasIpv6())) {
    // E16.
    ctx.warnings.push('This profile does not carry IPv6. IPv6 traffic will bypass it.')
  }
  if (ctx.usesTcp) {
    // E62.
    ctx.warnings.push('TCP mode is slower and can stall under loss. Use UDP unless the network blocks it.')
  }
  if (ctx.redirectGatewayRequested) {
    ctx.warnings.push(
      'This profile asks to send all of your traffic through the VPN. That stays off until you turn it on for this profile.'
    )
  }
  if (authMode !== 'none') {
    ctx.warnings.push('This profile signs in with a username and password, which you will need to add to the profile.')
  }
  const key = ctx.inline.get('key')
  if (key && /ENCRYPTED/.test(key)) {
    ctx.warnings.push('The private key in this profile is encrypted, so you will need its passphrase to connect.')
  }

  const spec: OpenVpnSpec = {
    kind: 'openvpn',
    configRef: { vaultEntryId: PENDING_VAULT_ENTRY, field: 'configBody' },
    authMode,
    // E13. Never true at import: a downloaded file does not get to decide that
    // all of the user's traffic moves.
    redirectGateway: false,
    strippedDirectives: ctx.stripped,
    remotes: ctx.remotes
  }
  if (ctx.staticChallenge) spec.staticChallenge = ctx.staticChallenge

  return {
    ok: true,
    spec,
    name: ctx.remotes[0].host,
    stripped: ctx.stripped,
    warnings: ctx.warnings,
    secrets: { configBody }
  }
}

// ------------------------------------------------------------------- emit

/** The final on-disk / on-stdin body. `configBody` is the sanitized config the
 *  parser produced and the vault stored; the only thing added here is the
 *  spec-level gate on `redirect-gateway`, which is a user decision rather than
 *  a property of the imported file.
 *
 *  The body is re-checked on the way out. It should always be one we wrote, so
 *  a hit means the vault was tampered with or some future code path stored an
 *  unsanitized body — either way, not something to hand to openvpn. */
export function emitOvpnConfig(spec: OpenVpnSpec, configBody: string): string {
  let inTag: string | null = null
  const lines = configBody.split(/\r?\n/)
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i].trim()
    if (inTag) {
      if (line === `</${inTag}>`) inTag = null
      continue
    }
    const tag = /^<(\/?)([A-Za-z0-9_-]+)>$/.exec(line)
    if (tag) {
      const name = tag[2].toLowerCase()
      if (tag[1] || !INLINE_TAG_SET.has(name)) {
        throw new VpnError('config-rejected', `Line ${i + 1}: ${line} — ${ruleById('inline-unknown').reason}`)
      }
      inTag = name
      continue
    }
    if (!line || line.startsWith('#') || line.startsWith(';')) continue

    const tokens = tokenize(line, i + 1, lines[i])
    const rule = ovpnRejectRuleFor(tokens[0])
    if (rule) throw new VpnError('config-rejected', `Line ${i + 1}: ${line} — ${rule.reason}`)
    for (const t of tokens) {
      if (DANGEROUS.test(t)) {
        throw new VpnError('config-rejected', `Line ${i + 1}: ${line} — ${ruleById('quote-injection').reason}`)
      }
    }
  }

  const out = configBody.endsWith('\n') ? configBody : `${configBody}\n`
  // `def1` installs two /1 routes instead of replacing the default route, so
  // the original default survives and comes back cleanly on disconnect.
  return spec.redirectGateway ? `${out}redirect-gateway def1\n` : out
}

// ------------------------------------------------------------------- argv

export interface OvpnArgOptions {
  /** `/dev/stdin` on POSIX; the 0600 file inside the 0700 run directory on
   *  Windows, which has no `/dev/stdin`. */
  configPath: string
  /** `--management-client` inverts the direction — openvpn dials us — so there
   *  is never a window where a listening management port sits unauthenticated. */
  management: { kind: 'unix'; path: string } | { kind: 'tcp'; host: string; port: number }
  /** Clamped to 1..4, for the same reason the parser clamps `verb` (E59). */
  verb?: number
}

export function ovpnArgs(spec: OpenVpnSpec, opts: OvpnArgOptions): string[] {
  const args = ['--config', opts.configPath]

  if (opts.management.kind === 'unix') args.push('--management', opts.management.path, 'unix')
  else args.push('--management', opts.management.host, String(opts.management.port))
  args.push('--management-client', '--management-query-passwords', '--management-hold')

  // A clean local config is only half the job. The second half is refusing the
  // same directives when a hostile *server* pushes them (E38).
  args.push('--script-security', '0')
  for (const f of OVPN_PULL_FILTER_REJECTS) args.push('--pull-filter', 'reject', f)

  if (!spec.redirectGateway) {
    // E13 + E38: without both of these a pushed `redirect-gateway` still moves
    // every route, and "split tunnel" would be a claim rather than a fact.
    args.push('--pull-filter', 'ignore', 'redirect-gateway')
    args.push('--route-nopull')
  }

  // Credentials come back over the management channel on every reconnect
  // instead of sitting in the process for the life of the tunnel.
  args.push('--auth-nocache')
  args.push('--verb', String(Math.min(4, Math.max(1, Math.trunc(opts.verb ?? 3)))))
  return args
}
