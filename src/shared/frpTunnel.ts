// "Give me a public URL for localhost:3000" — the part of it that is arithmetic
// rather than pixels.
//
// ================= WHY THIS IS NOT NGROK, AND SAYS SO =================
//
// ngrok's whole trick is that ngrok owns the endpoint. You run one command and
// a name you have never seen before resolves, because the company behind it
// operates the DNS zone and the TLS terminator on the other end of your tunnel.
//
// frp owns nothing. It is a client and a server binary; the server is on a host
// somebody rented, under a domain somebody registered, and neither of those
// somebodies is ShellPilot. So the pleasant one-click flow is only honest if
// the "somebody" step happens once, explicitly, and is written down — which is
// `FrpPublicHost` on the profile — and is then never mentioned again.
//
// The failure this file is shaped to prevent is a URL that looks like magic and
// is not: an address composed out of the frp server's own hostname, shown with
// a Copy button, that resolves to nothing because no DNS record was ever
// created. That is strictly worse than the form it replaced, because the form
// at least never claimed to have finished. Hence: every URL here is derived
// from a domain the operator supplied, and when there is no such domain the
// answer is a list of gaps and NO URL AT ALL. `frpPublishReadiness` has no
// third state on purpose.

import type { FrpProxy, FrpPublicHost, FrpSpec, VpnProfile } from './vpn'

// ------------------------------------------------------------------ readiness

export type FrpSetupGapCode = 'no-host' | 'no-domain' | 'no-server'

export interface FrpSetupGap {
  code: FrpSetupGapCode
  /** Actionable, and about the user's own infrastructure rather than ours. */
  message: string
}

export interface FrpPublishTarget {
  profile: VpnProfile
  spec: FrpSpec
  host: FrpPublicHost
}

export type FrpPublishReadiness =
  | { ready: true; target: FrpPublishTarget }
  | { ready: false; gaps: FrpSetupGap[] }

/** The frp profile a workspace publishes through: the first one carrying a
 *  confirmed public host.
 *
 *  First rather than newest, and by list order rather than by name, because the
 *  list order is what the user sees in the pane — "it used the one at the top"
 *  is an explanation; "it used the most recently edited one" is a surprise. */
export function tunnelHostProfile(profiles: VpnProfile[]): VpnProfile | null {
  return (
    profiles.find(
      (p) => p.spec.kind === 'frp' && (p.spec.publicHost?.confirmedAt ?? 0) > 0
    ) ?? null
  )
}

/**
 * Whether one click can produce a working public URL, and if not, why not.
 *
 * The `ready: false` branch deliberately carries no URL and no host. A caller
 * cannot accidentally render half an answer, because there is no half-answer in
 * the type.
 */
export function frpPublishReadiness(profiles: VpnProfile[]): FrpPublishReadiness {
  const profile = tunnelHostProfile(profiles)
  if (!profile || profile.spec.kind !== 'frp') {
    return {
      ready: false,
      gaps: [
        {
          code: 'no-host',
          message:
            'A public URL needs an frp server you control, with a domain pointed at it. ' +
            'Set that up once and this stops being a question.'
        }
      ]
    }
  }

  const spec = profile.spec
  const host = spec.publicHost
  const gaps: FrpSetupGap[] = []
  if (!host || !host.baseDomain.trim()) {
    gaps.push({
      code: 'no-domain',
      message: `"${profile.name}" has no domain. frp routes a public name to this machine, but the name has to be one you own and have pointed at the server.`
    })
  }
  if (!spec.serverAddr.trim()) {
    gaps.push({
      code: 'no-server',
      message: `"${profile.name}" has no frp server address, so there is nothing for that name to resolve to.`
    })
  }
  if (gaps.length > 0 || !host) return { ready: false, gaps }
  return { ready: true, target: { profile, spec, host } }
}

// ----------------------------------------------------------------------- URLs

/** The port a URL of this scheme leaves out. */
export function defaultPortFor(scheme: FrpPublicHost['scheme']): number {
  return scheme === 'https' ? 443 : 80
}

/**
 * The address a published service appears at.
 *
 * Composed from the operator's own domain and nothing else. There is no
 * fallback that substitutes the frp server's hostname when the domain is
 * missing: callers reach this only through a `ready: true` readiness, and an
 * empty `baseDomain` here would produce `https://api.` rather than something
 * that quietly looks plausible.
 */
export function publicUrl(host: FrpPublicHost, label: string): string {
  const port = host.port && host.port !== defaultPortFor(host.scheme) ? `:${host.port}` : ''
  return `${host.scheme}://${label}.${host.baseDomain}${port}`
}

// --------------------------------------------------------------------- labels

/** Longest DNS label. Also inside frp's own 64-char proxy-name limit. */
const MAX_LABEL = 63

/** A DNS label, from whatever the user typed.
 *
 *  Lowercased, because DNS is case-insensitive and `API.example.com` printed
 *  next to `api.example.com` reads as two different addresses. */
export function toLabel(input: string): string {
  const slug = input
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9-]+/g, '-')
    .replace(/-+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, MAX_LABEL)
    .replace(/-+$/g, '')
  return slug
}

/**
 * A label for this publish, unique among the ones already on the profile.
 *
 * The label is also the frp proxy name, deliberately: two names for one thing
 * would let a URL and the row that produced it drift apart, and frp's own
 * uniqueness rule for proxy names is then the same rule as the URL's.
 */
export function publishLabel(desired: string, localPort: number, taken: string[]): string {
  const base = toLabel(desired) || toLabel(`port-${localPort}`)
  const used = new Set(taken.map((t) => t.toLowerCase()))
  if (!used.has(base)) return base
  for (let n = 2; n < 1000; n++) {
    const candidate = `${base.slice(0, MAX_LABEL - String(n).length - 1)}-${n}`
    if (!used.has(candidate)) return candidate
  }
  return base
}

// -------------------------------------------------------------------- exposure

/**
 * The proxy a publish creates.
 *
 * `acknowledgedExposure: false`, always. This function cannot tick that box —
 * see `FrpProxy` in shared/vpn.ts, where it is documented as a gate rather than
 * a preference. A one-click flow that set it here would be a one-click flow
 * that answered "do you understand this port is now on the internet?" on the
 * user's behalf, which is the exact question the click is too fast to have
 * asked. The dialog sets it, from a control the user operated.
 *
 * `type: 'http'` and `localIp: '127.0.0.1'`, both fixed. http is the only frp
 * proxy type that is routed by name, which is the entire point of having a
 * domain; loopback is the only address this flow can honestly describe, since
 * it is the one place a port number alone identifies a service on the operator's
 * own machine. Anything else is the full proxy editor's job.
 */
export function buildPublishedProxy(label: string, localPort: number): FrpProxy {
  return {
    name: label,
    type: 'http',
    localIp: '127.0.0.1',
    localPort,
    subdomain: label,
    acknowledgedExposure: false
  }
}

export interface FrpExposure {
  /** `127.0.0.1:3000` — what is about to be published. */
  local: string
  /** The address it appears at. */
  url: string
  /** What actually happens, in one sentence, with both ends named. */
  sentence: string
  /** Who can reach it. Separate because it is the part users assume wrongly. */
  audience: string
  /** The route, so "reachable from where" has a concrete answer. */
  route: string
}

/**
 * Exactly what is about to become reachable, and to whom.
 *
 * Both ends are named literally. "Publish this port" tells the operator nothing
 * they had not already assumed, and the assumption they get wrong is which port
 * — the flow takes a number typed into a box, and 3000 and 3306 are one
 * keystroke apart. So the sentence carries the address, the URL, and no verbs
 * that could be read as a promise about availability.
 */
export function describeExposure(input: {
  host: FrpPublicHost
  label: string
  localPort: number
  serverAddr: string
  serverPort: number
}): FrpExposure {
  const local = `127.0.0.1:${input.localPort}`
  const url = publicUrl(input.host, input.label)
  return {
    local,
    url,
    sentence: `Anything answering on ${local} on this machine becomes reachable at ${url}.`,
    audience: 'Anyone who has that address can reach it. Nothing asks them for a password first.',
    route: `Traffic arrives through ${input.serverAddr}:${input.serverPort}, the frp server you set up.`
  }
}

// ------------------------------------------------------------------ the record

/** What the guided setup writes onto the profile once, and the reason the
 *  guided setup is over. `confirmedAt` is stamped here rather than by the
 *  caller so there is one definition of "the operator has answered this". */
export function publicHostFrom(input: {
  baseDomain: string
  scheme: FrpPublicHost['scheme']
  port?: number
  now?: number
}): FrpPublicHost {
  const port = input.port && input.port !== defaultPortFor(input.scheme) ? input.port : undefined
  return {
    baseDomain: input.baseDomain.trim().replace(/^\*\./, '').replace(/^\.+|\.+$/g, '').toLowerCase(),
    scheme: input.scheme,
    ...(port ? { port } : {}),
    confirmedAt: input.now ?? Date.now()
  }
}

/** The DNS record the operator has to create, spelled out so it can be copied
 *  rather than reconstructed from prose. One line, one time. */
export function delegationRecord(baseDomain: string, serverAddr: string): string {
  const domain = baseDomain.trim().replace(/^\*\./, '') || '<your domain>'
  return `*.${domain}  →  ${serverAddr.trim() || '<your frp server>'}`
}

/** A domain that could plausibly be delegated. Deliberately shape-only: this
 *  cannot know whether the record exists, and pretending to check would be the
 *  same lie in a different place. */
export function isDelegatableDomain(value: string): boolean {
  const d = value.trim().replace(/^\*\./, '')
  if (d.length === 0 || d.length > 253) return false
  if (!d.includes('.')) return false
  return d.split('.').every((part) => /^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$/.test(part))
}
