import { networkInterfaces } from 'node:os'
import type {
  StrippedDirective,
  VpnImportResultInternal,
  VpnSecretRef,
  WireGuardPeer,
  WireGuardSpec
} from '../../../../shared/vpn'
import { isCidr, isWireGuardKey, parseVpnEndpoint } from '../../../../shared/vpn'
import { VpnError } from '../errors'

// wg-quick `.conf` import.
//
// A `.conf` is executable content in exactly the way a `.ovpn` is: wg-quick
// runs PreUp/PostUp/PreDown/PostDown as root shell commands before and after
// the interface comes up. So the same rule applies — the file is parsed into a
// typed WireGuardSpec and the engine is configured from the model. The user's
// bytes never reach an engine.

/** Placeholder for `VpnSecretRef.vaultEntryId`. A parser has no vault access
 *  and must not invent an id: the import handler puts the plaintext from
 *  `VpnImportResultInternal.secrets` into the vault and rewrites every ref. */
export const PENDING_VAULT_ENTRY = ''

export interface WgParseOptions {
  /** Overridable so the E16 warning is testable without a real v6 stack. */
  hostHasIpv6?: boolean
}

/** True when this machine has a routable IPv6 address. Used for E16: a v4-only
 *  tunnel on a v6-capable host silently leaks every AAAA connection. */
export function hostHasIpv6(): boolean {
  const ifaces = networkInterfaces()
  for (const list of Object.values(ifaces)) {
    for (const a of list ?? []) {
      if (a.family !== 'IPv6') continue
      if (a.internal) continue
      // Link-local is not connectivity; it exists on every interface.
      if (a.address.toLowerCase().startsWith('fe80')) continue
      return true
    }
  }
  return false
}

// PreUp/PostUp/PreDown/PostDown are the whole reason this file exists. Kept as
// a table so the meta-test can assert each has a hostile fixture (E39).
export interface WgRejectRule {
  id: string
  key: string
  reason: string
}

export const WG_REJECT_RULES: readonly WgRejectRule[] = [
  { id: 'preup', key: 'preup', reason: 'PreUp runs a shell command as root before the interface comes up.' },
  { id: 'postup', key: 'postup', reason: 'PostUp runs a shell command as root once the interface is up.' },
  { id: 'predown', key: 'predown', reason: 'PreDown runs a shell command as root before the interface goes down.' },
  { id: 'postdown', key: 'postdown', reason: 'PostDown runs a shell command as root after the interface goes down.' }
]

const REJECT_BY_KEY = new Map(WG_REJECT_RULES.map((r) => [r.key, r]))

// Modelled by WireGuardSpec, so these are carried across.
const IFACE_MODELLED = new Set(['privatekey', 'address', 'dns', 'mtu'])
const PEER_MODELLED = new Set([
  'publickey',
  'presharedkey',
  'endpoint',
  'allowedips',
  'persistentkeepalive'
])

// Understood, not hostile, but WireGuardSpec has nowhere to put them: the
// userspace stack picks its own source port and never touches a route table.
// Reported rather than swallowed so the import report stays complete.
const IFACE_UNMODELLED: Record<string, string> = {
  listenport: 'The userspace stack binds its own source port, so a fixed ListenPort has no effect.',
  table: 'Table only means something to wg-quick, which manages system routes. ShellPilot does not.'
}

interface Ctx {
  stripped: StrippedDirective[]
  warnings: string[]
}

function drop(ctx: Ctx, directive: string, reason: string): void {
  ctx.stripped.push({ directive, reason, severity: 'removed' })
}

function reject(ctx: Ctx, directive: string, reason: string, lineNo: number, raw: string): never {
  ctx.stripped.push({ directive, reason, severity: 'rejected' })
  throw new VpnError('config-rejected', `Line ${lineNo}: ${raw.trim()} — ${reason}`)
}

function invalid(lineNo: number, raw: string, why: string): never {
  throw new VpnError('config-invalid', `Line ${lineNo}: ${raw.trim()} — ${why}`)
}

/** Everything after the first `#` or `;` is a comment. Neither character can
 *  appear in a key, a base64 key, an endpoint or a CIDR, so this is safe. */
function stripComment(line: string): string {
  const h = line.indexOf('#')
  const s = line.indexOf(';')
  const i = h === -1 ? s : s === -1 ? h : Math.min(h, s)
  return i === -1 ? line : line.slice(0, i)
}

function splitList(v: string): string[] {
  return v
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean)
}

/** `10.0.0.2` means `10.0.0.2/32`; wg-quick accepts the bare form. */
function normaliseCidr(v: string): string {
  if (v.includes('/')) return v
  return v.includes(':') ? `${v}/128` : `${v}/32`
}

function intIn(v: string, lo: number, hi: number): number | null {
  if (!/^\d+$/.test(v)) return null
  const n = Number(v)
  return n >= lo && n <= hi ? n : null
}

interface Section {
  name: 'interface' | 'peer'
  values: Map<string, { value: string; line: number; raw: string }>
}

export function parseWgConf(text: string, opts: WgParseOptions = {}): VpnImportResultInternal {
  const ctx: Ctx = { stripped: [], warnings: [] }
  try {
    return build(text, opts, ctx)
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

function build(text: string, opts: WgParseOptions, ctx: Ctx): VpnImportResultInternal {
  const sections: Section[] = []
  // A file exported on Windows often starts with a BOM; without this the first
  // section header would not match and the whole import would fail on line 1.
  const lines = text.replace(/^\uFEFF/, '').split(/\r?\n/)

  for (let i = 0; i < lines.length; i++) {
    const raw = lines[i]
    const lineNo = i + 1
    const line = stripComment(raw).trim()
    if (!line) continue

    const header = /^\[\s*([A-Za-z]+)\s*\]$/.exec(line)
    if (header) {
      const name = header[1].toLowerCase()
      if (name !== 'interface' && name !== 'peer') {
        invalid(lineNo, raw, `unknown section [${header[1]}].`)
      }
      if (name === 'interface' && sections.some((s) => s.name === 'interface')) {
        invalid(lineNo, raw, 'a second [Interface] section.')
      }
      sections.push({ name, values: new Map() })
      continue
    }

    const eq = line.indexOf('=')
    if (eq === -1) invalid(lineNo, raw, 'expected `Key = value`.')
    const key = line.slice(0, eq).trim().toLowerCase()
    const value = line.slice(eq + 1).trim()
    if (!key) invalid(lineNo, raw, 'missing key.')

    const hook = REJECT_BY_KEY.get(key)
    if (hook) reject(ctx, key, hook.reason, lineNo, raw)

    const section = sections[sections.length - 1]
    if (!section) invalid(lineNo, raw, 'a setting before any [Interface] section.')

    // Last wins, matching wg-quick, but a duplicate is nearly always a merge
    // accident and the value that lost is worth naming.
    const prev = section.values.get(key)
    if (prev) {
      ctx.warnings.push(
        `Line ${lineNo}: ${key} is set more than once in [${section.name === 'interface' ? 'Interface' : 'Peer'}]; the last value wins ("${value}" replaces "${prev.value}").`
      )
    }
    section.values.set(key, { value, line: lineNo, raw })
  }

  const iface = sections.find((s) => s.name === 'interface')
  if (!iface) throw new VpnError('config-invalid', 'This file has no [Interface] section.')
  const peerSections = sections.filter((s) => s.name === 'peer')
  if (peerSections.length === 0) {
    throw new VpnError('config-invalid', 'This file has no [Peer] section, so there is nothing to connect to.')
  }

  // ---------------------------------------------------------- [Interface]

  const privateKeyEntry = iface.values.get('privatekey')
  if (!privateKeyEntry) throw new VpnError('config-invalid', '[Interface] has no PrivateKey.')
  if (!isWireGuardKey(privateKeyEntry.value)) {
    invalid(privateKeyEntry.line, privateKeyEntry.raw, 'PrivateKey is not a 44-character base64 WireGuard key.')
  }
  const privateKey = privateKeyEntry.value.trim()

  const addresses: string[] = []
  const addrEntry = iface.values.get('address')
  if (addrEntry) {
    for (const a of splitList(addrEntry.value)) {
      const cidr = normaliseCidr(a)
      if (!isCidr(cidr)) invalid(addrEntry.line, addrEntry.raw, `"${a}" is not an address with a prefix length.`)
      addresses.push(cidr)
    }
  }
  if (addresses.length === 0) throw new VpnError('config-invalid', '[Interface] has no Address.')

  const dns: string[] = []
  const dnsEntry = iface.values.get('dns')
  if (dnsEntry) {
    for (const d of splitList(dnsEntry.value)) {
      // wg-quick allows search domains here too, so this only has to reject
      // anything that could not be a host: whitespace or shell punctuation.
      if (!/^[A-Za-z0-9._:%-]+$/.test(d)) {
        invalid(dnsEntry.line, dnsEntry.raw, `"${d}" is not a valid DNS server or search domain.`)
      }
      dns.push(d)
    }
  }

  let mtu: number | undefined
  const mtuEntry = iface.values.get('mtu')
  if (mtuEntry) {
    const n = intIn(mtuEntry.value, 576, 9000)
    if (n === null) invalid(mtuEntry.line, mtuEntry.raw, 'MTU must be between 576 and 9000.')
    mtu = n
  }

  for (const [key, entry] of iface.values) {
    if (IFACE_MODELLED.has(key)) continue
    const known = IFACE_UNMODELLED[key]
    if (known) {
      drop(ctx, key, known)
      continue
    }
    drop(ctx, key, `Not a setting ShellPilot understands (value "${entry.value}").`)
  }

  // --------------------------------------------------------------- [Peer]

  const peers: WireGuardPeer[] = []
  const presharedKeys: Record<string, string> = {}

  for (const section of peerSections) {
    const pubEntry = section.values.get('publickey')
    if (!pubEntry) throw new VpnError('config-invalid', 'A [Peer] section has no PublicKey.')
    if (!isWireGuardKey(pubEntry.value)) {
      invalid(pubEntry.line, pubEntry.raw, 'PublicKey is not a 44-character base64 WireGuard key.')
    }
    const publicKey = pubEntry.value.trim()

    const endpointEntry = section.values.get('endpoint')
    if (!endpointEntry) {
      throw new VpnError(
        'config-invalid',
        `The [Peer] with public key ${publicKey} has no Endpoint, so there is no address to dial.`
      )
    }
    if (!parseVpnEndpoint(endpointEntry.value)) {
      invalid(endpointEntry.line, endpointEntry.raw, 'Endpoint must be host:port or [v6]:port.')
    }
    const endpoint = endpointEntry.value.trim()

    const allowedEntry = section.values.get('allowedips')
    if (!allowedEntry) {
      throw new VpnError(
        'config-invalid',
        `The [Peer] with public key ${publicKey} has no AllowedIPs, so no traffic would be routed to it.`
      )
    }
    const allowedIps: string[] = []
    for (const a of splitList(allowedEntry.value)) {
      const cidr = normaliseCidr(a)
      if (!isCidr(cidr)) invalid(allowedEntry.line, allowedEntry.raw, `"${a}" is not a CIDR range.`)
      allowedIps.push(cidr)
    }
    if (allowedIps.length === 0) invalid(allowedEntry.line, allowedEntry.raw, 'AllowedIPs is empty.')

    const peer: WireGuardPeer = { publicKey, endpoint, allowedIps }

    const pskEntry = section.values.get('presharedkey')
    if (pskEntry) {
      if (!isWireGuardKey(pskEntry.value)) {
        invalid(pskEntry.line, pskEntry.raw, 'PresharedKey is not a 44-character base64 WireGuard key.')
      }
      presharedKeys[publicKey] = pskEntry.value.trim()
      const ref: VpnSecretRef = {
        vaultEntryId: PENDING_VAULT_ENTRY,
        field: 'presharedKey',
        fieldKey: publicKey
      }
      peer.presharedKeyRef = ref
    }

    const kaEntry = section.values.get('persistentkeepalive')
    if (kaEntry) {
      const v = kaEntry.value.trim().toLowerCase()
      const n = v === 'off' ? 0 : intIn(v, 0, 65535)
      if (n === null) invalid(kaEntry.line, kaEntry.raw, 'PersistentKeepalive must be a number of seconds, or "off".')
      if (n > 0) peer.persistentKeepalive = n
    }

    for (const [key, entry] of section.values) {
      if (PEER_MODELLED.has(key)) continue
      drop(ctx, key, `Not a [Peer] setting ShellPilot understands (value "${entry.value}").`)
    }

    peers.push(peer)
  }

  // ------------------------------------------------------------ warnings

  const anyDefaultV4 = peers.some((p) => p.allowedIps.includes('0.0.0.0/0'))
  const carriesV6 =
    peers.some((p) => p.allowedIps.some((a) => a.includes(':'))) || addresses.some((a) => a.includes(':'))
  const v6Host = opts.hostHasIpv6 ?? hostHasIpv6()
  if (!carriesV6 && v6Host) {
    // E16.
    ctx.warnings.push('This profile does not carry IPv6. IPv6 traffic will bypass it.')
  }
  if (anyDefaultV4) {
    // E17: 0.0.0.0/0 reads like "everything goes through the VPN", and in
    // userspace mode it does not. Saying so at import beats a support ticket.
    ctx.warnings.push(
      'AllowedIPs includes 0.0.0.0/0. In userspace mode ShellPilot changes no system routes, so only the connections you send through this tunnel’s local listeners use it.'
    )
  }

  const spec: WireGuardSpec = {
    kind: 'wireguard',
    mode: 'userspace',
    privateKeyRef: { vaultEntryId: PENDING_VAULT_ENTRY, field: 'privateKey' },
    addresses,
    dns,
    peers,
    listeners: [],
    strippedDirectives: ctx.stripped
  }
  if (mtu !== undefined) spec.mtu = mtu

  const secrets = {
    privateKey,
    ...(Object.keys(presharedKeys).length > 0 ? { presharedKeys } : {})
  }

  const first = parseVpnEndpoint(peers[0].endpoint)
  return {
    ok: true,
    spec,
    name: first ? first.host : undefined,
    stripped: ctx.stripped,
    warnings: ctx.warnings,
    secrets
  }
}
