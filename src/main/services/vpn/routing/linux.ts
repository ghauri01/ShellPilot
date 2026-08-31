import { classifyEngineLine, VpnError } from '../errors'
import { readCommand } from '../netstate'
import type { NetApplyContext } from '../netstate'
import {
  detectIpv6Leak,
  detectPrefixConflicts,
  expandDefaultRoutes,
  familyOf,
  normalizeCidr,
  sameDestinationOtherInterface
} from './index'
import type { RouteConflict, RouteEntry, RouteManager, RouteSnapshot, RouteSpec } from './index'

// iproute2 only. `route(8)` from net-tools is absent by default on every
// current distribution, cannot express IPv6 properly, and its output is
// classful in the same way macOS's netstat is. `ip route` prints one route per
// line in a stable `key value` grammar that survives locale changes, which is
// the property that matters when the output is being parsed rather than read.

const IP = 'ip'

/** One `ip route show` line:
 *    default via 192.168.1.1 dev eth0 proto dhcp src 192.168.1.50 metric 100
 *    10.8.0.0/24 dev wg0 proto kernel scope link src 10.8.0.2
 *  The destination is always first; everything after it is a keyword pair, so
 *  scanning for the keywords is safe even when new ones appear. */
export function parseIpRoute(text: string, family: 'inet' | 'inet6'): RouteEntry[] {
  const out: RouteEntry[] = []
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim()
    if (!line) continue
    // Continuation lines of a multipath route (`nexthop via ...`) describe the
    // route above, not a new one.
    if (line.startsWith('nexthop')) continue
    const tok = line.split(/\s+/)
    const destination = normalizeCidr(tok[0], family)
    if (!destination) continue
    const entry: RouteEntry = { destination, family }
    for (let i = 1; i < tok.length - 1; i++) {
      if (tok[i] === 'via') entry.gateway = tok[i + 1]
      else if (tok[i] === 'dev') entry.interfaceName = tok[i + 1]
      else if (tok[i] === 'metric') {
        const n = Number(tok[i + 1])
        if (Number.isFinite(n)) entry.metric = n
      }
    }
    out.push(entry)
  }
  return out
}

async function showRoutes(family: 'inet' | 'inet6', selector: string[] = []): Promise<RouteEntry[]> {
  const res = await readCommand(IP, [family === 'inet6' ? '-6' : '-4', 'route', 'show', ...selector])
  if (res.code !== 0) return []
  return parseIpRoute(res.stdout, family)
}

function familyFlag(destination: string): string {
  return familyOf(destination) === 'inet6' ? '-6' : '-4'
}

function replaceArgs(r: RouteSpec): string[] {
  // `replace` rather than `add`: it is the same operation when the route is
  // absent and idempotent when a retry finds it already there.
  const args = [familyFlag(r.destination), 'route', 'replace', r.destination]
  if (r.gateway) args.push('via', r.gateway)
  args.push('dev', r.interfaceName)
  if (r.metric !== undefined) args.push('metric', String(r.metric))
  return args
}

function deleteArgs(r: RouteSpec): string[] {
  const args = [familyFlag(r.destination), 'route', 'del', r.destination]
  if (r.gateway) args.push('via', r.gateway)
  args.push('dev', r.interfaceName)
  if (r.metric !== undefined) args.push('metric', String(r.metric))
  return args
}

export class LinuxRouteManager implements RouteManager {
  private lastCtx: NetApplyContext | null = null

  async snapshot(): Promise<RouteSnapshot> {
    const [v4, v6] = await Promise.all([
      showRoutes('inet', ['default']),
      showRoutes('inet6', ['default'])
    ])
    return {
      platform: 'linux',
      capturedAt: Date.now(),
      defaults: [...v4, ...v6],
      planned: []
    }
  }

  async apply(routes: RouteSpec[], ctx: NetApplyContext): Promise<void> {
    this.lastCtx = ctx
    for (const r of expandDefaultRoutes(routes)) {
      const res = await ctx.runPrivileged(IP, replaceArgs(r))
      if (res.code === 0) continue
      const text = `${res.stderr}\n${res.stdout}`
      throw new VpnError(
        classifyEngineLine(text) ?? 'internal',
        `Could not add route ${r.destination} on ${r.interfaceName}: ${text.trim().split(/\r?\n/)[0] ?? `ip exited ${res.code}`}`
      )
    }
  }

  async revert(snapshot: RouteSnapshot, ctx?: NetApplyContext): Promise<void> {
    const use = ctx ?? this.lastCtx
    if (!use) return
    for (const r of expandDefaultRoutes(snapshot.planned).reverse()) {
      // `RTNETLINK answers: No such process` is what a route that has already
      // gone looks like, and it is the expected outcome of a second revert.
      await use.runPrivileged(IP, deleteArgs(r)).catch(() => {})
    }
    await this.restoreDefaults(snapshot, use)
  }

  private async restoreDefaults(snapshot: RouteSnapshot, ctx: NetApplyContext): Promise<void> {
    for (const d of snapshot.defaults) {
      if (!d.gateway || !d.interfaceName) continue
      if (normalizeCidr(d.destination, d.family) !== (d.family === 'inet6' ? '::/0' : '0.0.0.0/0')) continue
      const current = await showRoutes(d.family, ['default'])
      if (current.length > 0) continue
      const args = [d.family === 'inet6' ? '-6' : '-4', 'route', 'replace', 'default', 'via', d.gateway, 'dev', d.interfaceName]
      if (d.metric !== undefined) args.push('metric', String(d.metric))
      await ctx.runPrivileged(IP, args).catch(() => {})
    }
  }

  async conflicts(routes: RouteSpec[]): Promise<RouteConflict[]> {
    const [v4, v6] = await Promise.all([showRoutes('inet'), showRoutes('inet6')])
    const table = [...v4, ...v6]
    const out = detectPrefixConflicts(routes, table, sameDestinationOtherInterface)
    const defaults = table.filter(
      (e) => normalizeCidr(e.destination, e.family) === (e.family === 'inet6' ? '::/0' : '0.0.0.0/0')
    )
    const leak = detectIpv6Leak(routes, defaults)
    if (leak) out.push(leak)
    return out
  }
}
