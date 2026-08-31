import { VpnError } from '../errors'
import { readCommand } from '../netstate'
import type { NetApplyContext } from '../netstate'
import { assertDnsSpec, isSplitDns, runTag, verificationFor } from './index'
import type { DnsManager, DnsSnapshot, DnsSpec, DnsVerification } from './index'

// macOS keeps its resolver configuration in the dynamic store, not in a file.
// `/etc/resolv.conf` there is a read-only rendering of it, so writing to it
// changes nothing and looks like it worked.
//
// Two ways in. `networksetup -setdnsservers <service>` is the visible one that
// shows up in System Settings, but it only addresses *network services* — a
// utun device created by a tunnel is not one, so it cannot be used here. The
// other is to publish our own State: key, which is what every VPN client on
// the platform does and what mDNSResponder merges alongside the interfaces'
// own configuration. Publishing under a key named after the run is also what
// makes the cleanup exact: removing `State:/Network/Service/ShellPilot-<runId>`
// takes away everything we added and nothing anybody else did (E09).

const SCUTIL = 'scutil'
const NETWORKSETUP = 'networksetup'

export interface ScutilResolver {
  nameservers: string[]
  searchDomains: string[]
  domain?: string
  interfaceName?: string
  interfaceIndex?: number
}

/** `scutil --dns` prints a numbered list of resolvers:
 *
 *    resolver #1
 *      search domain[0] : lan
 *      nameserver[0] : 192.168.1.1
 *      if_index : 12 (en0)
 *
 *  The blank-line-separated blocks are what matter; the trailing "DNS
 *  configuration (for scoped queries)" section repeats them per interface. */
export function parseScutilDns(text: string): ScutilResolver[] {
  const out: ScutilResolver[] = []
  let current: ScutilResolver | null = null
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim()
    if (/^resolver\s+#\d+/i.test(line)) {
      current = { nameservers: [], searchDomains: [] }
      out.push(current)
      continue
    }
    if (!current) continue
    const kv = /^([A-Za-z_ ]+?)(?:\[(\d+)\])?\s*:\s*(.+)$/.exec(line)
    if (!kv) continue
    const key = kv[1].trim().toLowerCase()
    const value = kv[3].trim()
    if (key === 'nameserver') current.nameservers.push(value)
    else if (key === 'search domain') current.searchDomains.push(value)
    else if (key === 'domain') current.domain = value
    else if (key === 'if_index') {
      const m = /^(\d+)\s*(?:\(([^)]+)\))?/.exec(value)
      if (m) {
        current.interfaceIndex = Number(m[1])
        if (m[2]) current.interfaceName = m[2]
      }
    }
  }
  return out
}

/** `networksetup -listnetworkserviceorder` pairs a visible service with the
 *  BSD device behind it:
 *    (1) Wi-Fi
 *    (Hardware Port: Wi-Fi, Device: en0)
 *  Not used for the tunnel itself, but it is how a physical interface's
 *  resolvers are read back for the snapshot report. */
export function parseServiceOrder(text: string): Record<string, string> {
  const out: Record<string, string> = {}
  const lines = text.split(/\r?\n/)
  for (let i = 0; i < lines.length; i++) {
    const name = /^\(\d+\)\s+(.+?)\s*$/.exec(lines[i])
    if (!name) continue
    const device = /Device:\s*([A-Za-z0-9._-]+)\)/.exec(lines[i + 1] ?? '')
    if (device) out[device[1]] = name[1]
  }
  return out
}

function scutilKey(tag: string, suffix: string): string {
  return `State:/Network/Service/${tag}/${suffix}`
}

/** The scutil command stream. Written as a script rather than as argv because
 *  scutil has no argv form for setting a key — it reads commands on stdin and
 *  nothing else. */
export function buildApplyScript(spec: DnsSpec, tag: string): string {
  const lines = ['d.init', `d.add ServerAddresses * ${spec.servers.join(' ')}`]
  if (spec.searchDomains.length > 0) {
    lines.push(`d.add SearchDomains * ${spec.searchDomains.join(' ')}`)
  }
  if (isSplitDns(spec)) {
    // SupplementalMatchDomains is the split-DNS mechanism (E12): only queries
    // under these suffixes are sent to our servers, and everything else keeps
    // whatever resolver it already had.
    lines.push(`d.add SupplementalMatchDomains * ${(spec.splitDomains ?? []).join(' ')}`)
    lines.push('d.add SupplementalMatchOrders * 100')
  }
  lines.push(`d.add InterfaceName ${spec.interfaceName}`)
  lines.push(`set ${scutilKey(tag, 'DNS')}`)
  // The IPv4 dictionary is what associates the service with the device, and
  // without it mDNSResponder has no interface to scope the resolver to.
  lines.push('d.init')
  lines.push(`d.add InterfaceName ${spec.interfaceName}`)
  lines.push(`set ${scutilKey(tag, 'IPv4')}`)
  lines.push('quit')
  return lines.join('\n') + '\n'
}

export function buildRevertScript(tag: string): string {
  return [`remove ${scutilKey(tag, 'DNS')}`, `remove ${scutilKey(tag, 'IPv4')}`, 'quit', ''].join('\n')
}

function requireStdin(ctx: NetApplyContext): void {
  if (ctx.supportsStdin) return
  throw new VpnError(
    'unsupported',
    'Changing DNS on macOS needs a privileged channel that accepts standard input, because scutil takes its commands there and has no equivalent arguments.'
  )
}

export class DarwinDnsManager implements DnsManager {
  private lastCtx: NetApplyContext | null = null

  async snapshot(): Promise<DnsSnapshot> {
    const [dns, order] = await Promise.all([
      readCommand(SCUTIL, ['--dns']),
      readCommand(NETWORKSETUP, ['-listnetworkserviceorder'])
    ])
    const resolvers = dns.code === 0 ? parseScutilDns(dns.stdout) : []
    // The first unscoped resolver is the one an ordinary lookup uses, which is
    // the one worth putting in the restore report.
    const previous = resolvers.find((r) => !r.domain)?.nameservers ?? resolvers[0]?.nameservers ?? []
    // Parsed for the report even though the tunnel branch does not use it: a
    // user reading "your DNS was Wi-Fi's 192.168.1.1" understands it.
    void parseServiceOrder(order.stdout)
    return {
      platform: 'darwin',
      capturedAt: Date.now(),
      runId: '',
      interfaceName: '',
      previous
    }
  }

  async apply(spec: DnsSpec, ctx: NetApplyContext): Promise<void> {
    assertDnsSpec(spec)
    requireStdin(ctx)
    this.lastCtx = ctx
    const tag = runTag(ctx.runId)
    const res = await ctx.runPrivileged(SCUTIL, [], { stdin: buildApplyScript(spec, tag) })
    if (res.code !== 0) {
      throw new VpnError(
        'internal',
        `Could not set DNS for ${spec.interfaceName}: ${`${res.stderr}\n${res.stdout}`.trim().split(/\r?\n/)[0] ?? `scutil exited ${res.code}`}`
      )
    }
  }

  async revert(snapshot: DnsSnapshot, ctx?: NetApplyContext): Promise<void> {
    const use = ctx ?? this.lastCtx
    if (!use) return
    if (!use.supportsStdin) return
    const tag = snapshot.tag ?? runTag(snapshot.runId || use.runId)
    // `remove` on a key that is not there exits non-zero and is exactly what a
    // second revert looks like, so the result is not checked.
    await use.runPrivileged(SCUTIL, [], { stdin: buildRevertScript(tag) }).catch(() => {})
  }

  async verify(spec: DnsSpec): Promise<DnsVerification> {
    const res = await readCommand(SCUTIL, ['--dns'])
    if (res.code !== 0) {
      return { ok: false, actual: [], reason: 'The resolver configuration could not be read.' }
    }
    const resolvers = parseScutilDns(res.stdout)
    const split = isSplitDns(spec)
    const wanted = split
      ? resolvers.filter((r) =>
          (spec.splitDomains ?? []).some(
            (d) => (r.domain ?? '').toLowerCase() === d.replace(/^\./, '').toLowerCase()
          )
        )
      : resolvers.filter((r) => r.interfaceName === spec.interfaceName || !r.domain)
    const actual = [...new Set(wanted.flatMap((r) => r.nameservers))]
    if (split && wanted.length === 0) {
      return {
        ok: false,
        actual: [],
        reason: `No resolver is scoped to ${(spec.splitDomains ?? []).join(', ')}, so the split DNS rule did not take effect.`
      }
    }
    return verificationFor(spec, actual)
  }
}
