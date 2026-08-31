import { VpnError } from '../errors'
import { readCommand } from '../netstate'
import type { NetApplyContext } from '../netstate'
import { assertDnsSpec, isSplitDns, runTag, verificationFor } from './index'
import type { DnsManager, DnsSnapshot, DnsSpec, DnsVerification } from './index'

// The Name Resolution Policy Table is Windows' split-DNS mechanism, and it is
// the right one to use here: a rule names a namespace and the servers that
// namespace resolves through, so `*.corp` going down the tunnel while
// everything else keeps its existing resolver needs no interface surgery at
// all (E12). A namespace of "." is the whole tree, which is how a full-tunnel
// profile is expressed.
//
// NRPT rules are machine-wide and persist across reboots. That is precisely
// why every rule carries `ShellPilot-<runId>` in its comment and display name:
// the sweep removes rules matching exactly that tag, so a crashed run is
// cleaned up and a rule some other product or a domain policy created is left
// completely alone (E10).

const POWERSHELL = 'powershell.exe'
const PS_ARGS = ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-Command']

/** PowerShell single-quoted string: the only metacharacter inside one is the
 *  quote itself. Values are also shape-checked by `assertDnsSpec` before they
 *  get here, so this is the second of two gates rather than the only one. */
export function psQuote(value: string): string {
  return `'${value.replace(/'/g, "''")}'`
}

function psList(values: string[]): string {
  return `@(${values.map(psQuote).join(',')})`
}

/** A namespace as NRPT wants it: a leading dot means "this suffix and
 *  everything under it", and "." means every name. */
export function nrptNamespaces(spec: DnsSpec): string[] {
  if (!isSplitDns(spec)) return ['.']
  return (spec.splitDomains ?? []).map((d) => {
    const t = d.trim().replace(/\.$/, '')
    return t.startsWith('.') ? t : `.${t}`
  })
}

export function buildAddScript(spec: DnsSpec, tag: string): string {
  const servers = psList(spec.servers)
  const parts = ['$ErrorActionPreference=' + psQuote('Stop')]
  for (const ns of nrptNamespaces(spec)) {
    parts.push(
      `Add-DnsClientNrptRule -Namespace ${psQuote(ns)} -NameServers ${servers} -Comment ${psQuote(tag)} -DisplayName ${psQuote(tag)}`
    )
  }
  return parts.join('; ')
}

/** Tag-scoped, and scoped by equality rather than by prefix: a run id is not
 *  allowed to match another run id by being a prefix of it. */
export function buildRemoveScript(tag: string): string {
  return [
    '$ErrorActionPreference=' + psQuote('SilentlyContinue'),
    `Get-DnsClientNrptRule | Where-Object { $_.Comment -eq ${psQuote(tag)} } | ForEach-Object { Remove-DnsClientNrptRule -Name $_.Name -Force }`
  ].join('; ')
}

export function buildQueryScript(tag: string): string {
  return [
    '$ErrorActionPreference=' + psQuote('SilentlyContinue'),
    `Get-DnsClientNrptRule | Where-Object { $_.Comment -eq ${psQuote(tag)} } | Select-Object Namespace,NameServers | ConvertTo-Json -Compress -Depth 3`
  ].join('; ')
}

export interface NrptRule {
  namespace: string
  nameServers: string[]
}

/** `ConvertTo-Json` emits a bare object for a single result and an array for
 *  several, and omits the property entirely when there are none. All three
 *  shapes have to parse to the same thing. */
export function parseNrptJson(text: string): NrptRule[] {
  const trimmed = text.trim()
  if (!trimmed) return []
  let raw: unknown
  try {
    raw = JSON.parse(trimmed)
  } catch {
    return []
  }
  const items = Array.isArray(raw) ? raw : [raw]
  const out: NrptRule[] = []
  for (const item of items) {
    if (!item || typeof item !== 'object') continue
    const o = item as Record<string, unknown>
    const ns = o.Namespace
    const servers = o.NameServers
    out.push({
      namespace: Array.isArray(ns) ? String(ns[0] ?? '') : String(ns ?? ''),
      nameServers: Array.isArray(servers)
        ? servers.map((s) => String(s))
        : typeof servers === 'string' && servers
          ? [servers]
          : []
    })
  }
  return out
}

export class Win32DnsManager implements DnsManager {
  private lastCtx: NetApplyContext | null = null

  async snapshot(): Promise<DnsSnapshot> {
    // There is nothing to restore on this platform — an NRPT rule is added,
    // not a setting overwritten — so the snapshot's job is to record the tag
    // that identifies our rules and to prove none already carry it.
    const res = await readCommand(POWERSHELL, [
      ...PS_ARGS,
      "Get-DnsClientNrptRule | Select-Object Namespace,NameServers | ConvertTo-Json -Compress -Depth 3"
    ])
    const existing = res.code === 0 ? parseNrptJson(res.stdout) : []
    return {
      platform: 'win32',
      capturedAt: Date.now(),
      runId: '',
      interfaceName: '',
      previous: [...new Set(existing.flatMap((r) => r.nameServers))]
    }
  }

  async apply(spec: DnsSpec, ctx: NetApplyContext): Promise<void> {
    assertDnsSpec(spec)
    this.lastCtx = ctx
    const tag = runTag(ctx.runId)
    const res = await ctx.runPrivileged(POWERSHELL, [...PS_ARGS, buildAddScript(spec, tag)])
    if (res.code !== 0) {
      const first = `${res.stderr}\n${res.stdout}`.trim().split(/\r?\n/)[0]
      throw new VpnError(
        'internal',
        `Could not add the DNS rule for ${spec.interfaceName}: ${first || `powershell exited ${res.code}`}`
      )
    }
  }

  async revert(snapshot: DnsSnapshot, ctx?: NetApplyContext): Promise<void> {
    const use = ctx ?? this.lastCtx
    if (!use) return
    const tag = snapshot.tag ?? runTag(snapshot.runId || use.runId)
    // Removing rules that are already gone matches nothing and exits 0, which
    // is what makes a second revert harmless.
    await use.runPrivileged(POWERSHELL, [...PS_ARGS, buildRemoveScript(tag)]).catch(() => {})
  }

  async verify(spec: DnsSpec): Promise<DnsVerification> {
    // Verified against our own rules rather than against the machine's
    // resolvers: NRPT does not change what `Get-DnsClientServerAddress`
    // reports, so reading that would report failure on a working tunnel.
    const tag = runTag(this.lastCtx?.runId ?? '')
    const res = await readCommand(POWERSHELL, [...PS_ARGS, buildQueryScript(tag)])
    if (res.code !== 0) {
      return { ok: false, actual: [], reason: 'The name resolution policy table could not be read.' }
    }
    const rules = parseNrptJson(res.stdout)
    if (rules.length === 0) {
      return {
        ok: false,
        actual: [],
        reason: `No name resolution rule tagged ${tag} is present, so the DNS change did not take effect.`
      }
    }
    const wanted = new Set(nrptNamespaces(spec).map((n) => n.toLowerCase()))
    const have = new Set(rules.map((r) => r.namespace.trim().toLowerCase()))
    const missing = [...wanted].filter((n) => !have.has(n))
    const actual = [...new Set(rules.flatMap((r) => r.nameServers))]
    if (missing.length > 0) {
      return {
        ok: false,
        actual,
        reason: `No rule covers ${missing.join(', ')}, so those names still resolve outside the tunnel.`
      }
    }
    return verificationFor(spec, actual)
  }
}
