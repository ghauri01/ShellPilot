import { VpnError } from '../errors'
import type { NetApplyContext } from '../netstate'
import { DarwinDnsManager } from './darwin'
import { LinuxDnsManager } from './linux'
import { Win32DnsManager } from './win32'

// System-mode DNS. Userspace mode resolves inside the netstack and has nothing
// system-wide to change, so none of this is reached there (E08).
//
// Two things make DNS harder than routing. It is the change that persists
// longest after a crash — an NRPT rule and a rewritten /etc/resolv.conf both
// survive a reboot — and it is the change most likely to fail silently, since
// every one of these commands exits 0 whether or not the resolver actually
// picked the change up. Hence `verify()`.

export interface DnsSpec {
  servers: string[]
  searchDomains: string[]
  interfaceName: string
  /** Split DNS (E12): only these suffixes resolve through the tunnel and
   *  everything else keeps using the resolver it was already using. Absent or
   *  empty means the tunnel takes every query. */
  splitDomains?: string[]
}

export interface DnsSnapshot {
  platform: NodeJS.Platform
  capturedAt: number
  /** Stamped by `netstate.ts`, not by `snapshot()`: the run id arrives with
   *  the apply context, and the snapshot is taken before that. */
  runId: string
  interfaceName: string
  /** The resolvers in force before anything changed. Shown in the restore
   *  report and used by `verify()` to tell "changed" from "unchanged". */
  previous: string[]
  /** darwin: the scutil service key we own. win32: the NRPT rule tag. */
  tag?: string
  /** linux, and only on the resolv.conf branch. */
  resolvConf?: { content: string; symlinkTarget: string | null }
  /** linux: which branch was taken, recorded so a revert takes the same one
   *  even if systemd-resolved was started or stopped while we were up. */
  backend?: 'resolvectl' | 'resolv.conf'
  planned?: DnsSpec
}

export interface DnsVerification {
  ok: boolean
  actual: string[]
  reason?: string
}

export interface DnsManager {
  snapshot(): Promise<DnsSnapshot>
  apply(spec: DnsSpec, ctx: NetApplyContext): Promise<void>
  /** `ctx` falls back to the one the last `apply` used. The startup restore
   *  pass has no such call behind it and always passes one explicitly. */
  revert(snapshot: DnsSnapshot, ctx?: NetApplyContext): Promise<void>
  /** Re-read the resolver configuration and report what it actually is. A DNS
   *  change that did not apply looks exactly like one that did, right up until
   *  every query goes to the old server. */
  verify(spec: DnsSpec): Promise<DnsVerification>
}

export function dnsManagerFor(platform: NodeJS.Platform = process.platform): DnsManager {
  switch (platform) {
    case 'darwin':
      return new DarwinDnsManager()
    case 'win32':
      return new Win32DnsManager()
    case 'linux':
      return new LinuxDnsManager()
    default:
      throw new VpnError('unsupported', `System-mode DNS is not implemented for ${platform}.`)
  }
}

// ------------------------------------------------------------------ helpers
// Function declarations rather than consts: the platform modules import these
// while this module imports their classes, and only declarations are
// initialised early enough for that cycle to be safe.

/** Every run's changes are tagged with this so a sweep can find exactly ours
 *  and never someone else's (E10). */
export function runTag(runId: string): string {
  return `ShellPilot-${runId.replace(/[^A-Za-z0-9._-]/g, '_')}`
}

const IPV4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/
// Deliberately loose on the address itself and strict on the alphabet: this is
// a gate on what can be interpolated into a command line, not a parser.
const IPV6 = /^[0-9a-fA-F:]+(?:%[0-9A-Za-z._-]+)?$/
const DOMAIN = /^\.?(?:[A-Za-z0-9_](?:[A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?\.)*[A-Za-z0-9_](?:[A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?\.?$/

export function isDnsServer(s: string): boolean {
  const t = s.trim()
  if (!t) return false
  const m4 = IPV4.exec(t)
  if (m4) return [m4[1], m4[2], m4[3], m4[4]].every((o) => Number(o) <= 255)
  return t.includes(':') && IPV6.test(t)
}

export function isDomainName(s: string): boolean {
  const t = s.trim()
  if (!t || t.length > 253) return false
  if (t === '.') return true
  return DOMAIN.test(t)
}

/** Anything that reaches a command line is checked first. These values come
 *  from an imported `.ovpn` or `.conf` that a third party wrote, so treating
 *  them as trusted is exactly the mistake that turns a config file into a
 *  command. */
export function assertDnsSpec(spec: DnsSpec): void {
  for (const s of spec.servers) {
    if (!isDnsServer(s)) throw new VpnError('config-invalid', `${JSON.stringify(s)} is not a DNS server address.`)
  }
  for (const d of [...spec.searchDomains, ...(spec.splitDomains ?? [])]) {
    if (!isDomainName(d)) throw new VpnError('config-invalid', `${JSON.stringify(d)} is not a domain name.`)
  }
  if (!/^[A-Za-z0-9._: -]{1,64}$/.test(spec.interfaceName)) {
    throw new VpnError('config-invalid', `${JSON.stringify(spec.interfaceName)} is not an interface name.`)
  }
}

export function isSplitDns(spec: DnsSpec): boolean {
  return Array.isArray(spec.splitDomains) && spec.splitDomains.length > 0
}

/** The servers a spec asked for, compared against what the resolver actually
 *  reports. Order is not required — resolvers reorder freely — but every
 *  requested server has to be there. */
export function verificationFor(spec: DnsSpec, actual: string[]): DnsVerification {
  const have = new Set(actual.map((s) => s.trim().toLowerCase()))
  const missing = spec.servers.filter((s) => !have.has(s.trim().toLowerCase()))
  if (missing.length === 0) return { ok: true, actual }
  return {
    ok: false,
    actual,
    reason:
      actual.length === 0
        ? 'The resolver reports no servers for this interface, so the DNS change did not take effect.'
        : `The resolver is using ${actual.join(', ')} and not ${missing.join(', ')}, so the DNS change did not take effect.`
  }
}
