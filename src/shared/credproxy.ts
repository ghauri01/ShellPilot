// The API credential proxy — roadmap item 7, vocabulary half.
//
// ===========================================================================
// THE DESIGN DECISION, AND WHY IT IS NOT REOPENED HERE
// ===========================================================================
//
// A process — a script, a dev server, an AI agent — makes an authenticated
// call to a third-party API without ever holding the key. There are two ways
// to build that, and the roadmap picks one:
//
//   * INTERCEPTION. Transparent to the caller, and it requires putting a local
//     certificate authority into the machine's trust store so we can terminate
//     TLS we were never given.
//   * REWRITE. The caller opts in by pointing its base URL at us.
//
// This is the rewrite, and the reason is one sentence: a tool whose pitch is
// "your secrets never leave" should not ship a CA into the user's trust store.
// Nothing here installs a certificate, nothing here terminates anyone else's
// TLS, and a caller that has not been reconfigured is not affected in any way.
//
// ===========================================================================
// WHAT A CALLER SENDS
// ===========================================================================
//
// The listener speaks plain HTTP on loopback, and the request target is the
// absolute upstream URL after the leading slash:
//
//     GET http://127.0.0.1:5178/https://api.example.com/v1/things?limit=5
//
// which is the shape a base-URL rewrite naturally produces: point an SDK at
// `http://127.0.0.1:5178/https://api.example.com` and it appends its own path.
//
// `parseProxyTarget` also accepts the single-slash form (`/https:/api...`)
// because a number of HTTP clients collapse `//` inside a path before the
// request goes out. That is not a permissiveness we wanted; it is the
// difference between the feature working with real clients and not.
//
// ===========================================================================
// MATCHING IS EXACT, ON THE ORIGIN, AND THAT IS THE WHOLE SAFETY PROPERTY
// ===========================================================================
//
// A rule pins ONE origin, normalised, and matching is `===` against the
// normalised origin of the resolved upstream URL. Not a suffix test, not a
// hostname `includes`, not a wildcard.
//
// The bug this shape exists to make unwriteable: a rule for `api.example.com`
// matching `api.example.com.evil.tld`, which every substring or endsWith
// formulation does, and which hands the user's key to whoever registered the
// second domain. `endsWith('.example.com')` has the same hole one level up
// (`notexample.com` fails, but `evil.example.com.attacker.tld` is a different
// shape of the same mistake) and there is no version of prefix/suffix matching
// that is worth the review it would need. Exact origin equality needs none.
//
// There is deliberately no default rule and no wildcard rule. An unmatched
// destination is a refusal with a reason — see REFUSAL_REASONS. A proxy that
// forwards what it does not recognise is an open relay, and one sitting on
// loopback with a credential attached is an open relay that pays.

/** The header a caller proves itself with. See CRED_PROXY_TOKEN_NOTE. */
export const CRED_PROXY_TOKEN_HEADER = 'x-shellpilot-proxy-token'

/** Loopback only, and 5178 rather than 5177 — 5177 is the MCP bridge. */
export const DEFAULT_CRED_PROXY_PORT = 5178

/** What the panel must say out loud next to the token, because a token whose
 *  power the holder has not been told is a token they will paste into a chat
 *  window. */
export const CRED_PROXY_TOKEN_NOTE =
  'Anything holding this token can spend your API budget through every rule below. ' +
  'It is not a password for you — it is the key a script or an agent presents instead of the ' +
  'credential itself. Treat it like the API key it stands in for, and rotate it when you would ' +
  'have rotated that.'

/** Why loopback alone is not an authorisation. */
export const CRED_PROXY_LOOPBACK_NOTE =
  'Every process on this machine can reach a loopback port, so being local is not a ' +
  'permission. The token is what separates your script from anything else running as you.'

// --------------------------------------------------------------------- rules

export type CredProxyInjectionKind = 'header' | 'bearer' | 'query' | 'basic'

export interface CredProxyInjection {
  kind: CredProxyInjectionKind
  /** Header name for `header`, query parameter name for `query`, username for
   *  `basic`. Ignored by `bearer`, which is always `Authorization: Bearer …`. */
  name?: string
}

/** Which slot of a vault entry holds the key. `field` reads a named custom
 *  field, which is where an entry that carries several keys keeps them. */
export type CredProxySlot = 'password' | 'privateKey' | 'username' | 'field'

export interface CredProxyCredentialRef {
  vaultEntryId: string
  slot: CredProxySlot
  /** Required when `slot` is `field`. */
  fieldKey?: string
}

export interface CredProxyRule {
  id: string
  name: string
  /** A normalised origin — `scheme://host[:port]`, never a path. */
  origin: string
  credential: CredProxyCredentialRef
  injection: CredProxyInjection
  enabled: boolean
  createdAt: string
}

// ------------------------------------------------------------------ refusals

export type CredProxyOutcome =
  | 'forwarded'
  | 'not-a-target'
  | 'unsupported-scheme'
  | 'no-rule'
  | 'rule-disabled'
  | 'unauthenticated'
  /** The presented value matched a real token that is past its end date, or
   *  that was revoked. Distinct from `unauthenticated` ON PURPOSE, and only
   *  reachable AFTER the value matched: somebody who does not hold a token
   *  still learns nothing, and somebody who does gets told why their script
   *  stopped at 3am rather than being sent to check for a typo. */
  | 'token-expired'
  | 'token-revoked'
  | 'not-loopback'
  | 'vault-locked'
  | 'credential-missing'
  | 'upstream-failed'

/** The sentence a caller gets back, and the one the panel shows. Every refusal
 *  says WHY: a proxy that answers an unmatched destination with a generic 403
 *  sends the operator to the far end's permissions page, which is the wrong
 *  building. */
export const REFUSAL_REASONS: Record<Exclude<CredProxyOutcome, 'forwarded'>, string> = {
  'not-a-target':
    'The request path is not an absolute upstream URL. Point your client at ' +
    'http://127.0.0.1:<port>/https://api.example.com and let it append its own path.',
  'unsupported-scheme': 'Only http:// and https:// upstreams are proxied.',
  'no-rule':
    'No rule covers that destination, so nothing was sent. This proxy never forwards a request ' +
    'it has no rule for — not without the credential, not at all.',
  'rule-disabled': 'A rule covers that destination but it is switched off.',
  'token-expired':
    'That token has passed its end date. Nothing was sent. Create a new token in ShellPilot’s ' +
    'API credential proxy panel — the old one is not extended, deliberately.',
  'token-revoked':
    'That token was revoked. Nothing was sent, and it will not start working again. If this is ' +
    'a script that should still run, give it a token of its own.',
  unauthenticated:
    'Missing or wrong client token. Copy the token from ShellPilot’s API credential proxy ' +
    `settings and send it as ${CRED_PROXY_TOKEN_HEADER}.`,
  'not-loopback': 'This proxy accepts connections from this machine only.',
  'vault-locked':
    'The vault is locked, so the credential for that rule could not be read. The request was ' +
    'parked, not sent — an unauthenticated request would have failed at the far end and looked ' +
    'like a permissions problem there.',
  'credential-missing':
    'The rule points at a vault entry or field that no longer holds anything. Nothing was sent.',
  'upstream-failed': 'The upstream could not be reached.'
}

/** Status codes. `vault-locked` is 409 rather than 401/403: nothing is wrong
 *  with the caller or the rule, the machine is in a state the user resolves. */
export const REFUSAL_STATUS: Record<Exclude<CredProxyOutcome, 'forwarded'>, number> = {
  'not-a-target': 400,
  'unsupported-scheme': 400,
  'no-rule': 403,
  'rule-disabled': 403,
  unauthenticated: 401,
  // 401, not 403. The caller held a real token and the fix is a new one, which
  // is an authentication problem — 403 would say the token was fine and the
  // destination was not, and send them to the rules list instead.
  'token-expired': 401,
  'token-revoked': 401,
  'not-loopback': 403,
  'vault-locked': 409,
  'credential-missing': 409,
  'upstream-failed': 502
}

// ------------------------------------------------------------------- parsing

/** Normalises an origin for storage and comparison, or null when the input is
 *  not one.
 *
 *  Everything here exists so that `===` is a sound comparison afterwards:
 *  lowercase scheme and host, default port dropped, path/query/fragment and
 *  userinfo discarded, and a single trailing dot removed from the hostname —
 *  `api.example.com.` is the same host as `api.example.com`, and treating them
 *  as different would refuse a destination the user really did configure. */
export function normaliseOrigin(raw: string): string | null {
  const text = String(raw ?? '').trim()
  if (text === '') return null
  let u: URL
  try {
    u = new URL(text)
  } catch {
    return null
  }
  if (u.protocol !== 'https:' && u.protocol !== 'http:') return null
  // `hostname` is already lowercased and IPv6 is already bracketed by URL.
  const host = u.hostname.replace(/\.$/, '')
  if (host === '') return null
  // `u.port` is '' when the port is the scheme default, which is the drop we
  // want; an explicit :443 on https therefore compares equal to none.
  return `${u.protocol}//${host}${u.port ? `:${u.port}` : ''}`
}

export interface ProxyTarget {
  url: URL
  /** The normalised origin, the thing a rule is matched on. */
  origin: string
}

/** Turns a raw request target into the upstream URL it names.
 *
 *  Returns an outcome rather than throwing, because every failure here is a
 *  refusal the caller is owed a reason for. */
export function parseProxyTarget(
  requestTarget: string
): { ok: true; target: ProxyTarget } | { ok: false; reason: 'not-a-target' | 'unsupported-scheme' } {
  const raw = String(requestTarget ?? '')
  if (!raw.startsWith('/')) return { ok: false, reason: 'not-a-target' }
  let rest = raw.slice(1)
  // Clients that collapse `//` inside a path — several do, before the request
  // is ever written to the socket — turn `/https://host/x` into `/https:/host/x`.
  // Restoring the pair here is what makes a base-URL rewrite work with real
  // SDKs instead of only with curl.
  rest = rest.replace(/^(https?):\/(?!\/)/i, '$1://')
  let url: URL
  try {
    url = new URL(rest)
  } catch {
    return { ok: false, reason: 'not-a-target' }
  }
  if (url.protocol !== 'https:' && url.protocol !== 'http:') {
    return { ok: false, reason: 'unsupported-scheme' }
  }
  const origin = normaliseOrigin(url.origin)
  if (origin === null) return { ok: false, reason: 'not-a-target' }
  return { ok: true, target: { url, origin } }
}

/**
 * The rule for an origin, or null.
 *
 * Exact equality on the normalised origin. Read the header of this file before
 * changing it to anything that involves a suffix.
 */
export function matchRule(rules: CredProxyRule[], origin: string): CredProxyRule | null {
  const want = normaliseOrigin(origin)
  if (want === null) return null
  return rules.find((r) => r.origin === want) ?? null
}

// -------------------------------------------------------------- sanitisation

const HEADER_NAME = /^[A-Za-z0-9!#$%&'*+.^_`|~-]+$/

/** Headers a rule may not inject into.
 *
 *  `host`, `content-length` and the hop-by-hop set would corrupt the forward.
 *  The proxy's own token header is here for a different reason: injecting the
 *  credential under that name would put OUR shared secret on the wire to a
 *  third party, which is the exact accident this whole feature exists to
 *  prevent. */
export const UNINJECTABLE_HEADERS = [
  'host',
  'content-length',
  'connection',
  'keep-alive',
  'transfer-encoding',
  'te',
  'trailer',
  'upgrade',
  'proxy-authorization',
  'proxy-connection',
  CRED_PROXY_TOKEN_HEADER
]

/** Headers never copied from the caller's request to the upstream, or back.
 *
 *  The token header is in here as well as in UNINJECTABLE_HEADERS, and it is
 *  the entry that matters most: without it, every proxied call would carry the
 *  proxy's own client token to a third-party API in a header they log. */
export const HOP_BY_HOP_HEADERS = [
  'connection',
  'keep-alive',
  'proxy-authenticate',
  'proxy-authorization',
  'proxy-connection',
  'te',
  'trailer',
  'transfer-encoding',
  'upgrade',
  'host',
  'content-length',
  CRED_PROXY_TOKEN_HEADER
]

export function validateInjection(inj: CredProxyInjection): { ok: true } | { ok: false; error: string } {
  if (inj.kind === 'bearer') return { ok: true }
  const name = (inj.name ?? '').trim()
  if (name === '') {
    const what =
      inj.kind === 'header' ? 'a header name' : inj.kind === 'query' ? 'a parameter name' : 'a username'
    return { ok: false, error: `This rule needs ${what}.` }
  }
  if (inj.kind === 'header') {
    if (!HEADER_NAME.test(name)) return { ok: false, error: `"${name}" is not a valid header name.` }
    if (UNINJECTABLE_HEADERS.includes(name.toLowerCase())) {
      return { ok: false, error: `"${name}" cannot carry a credential.` }
    }
  }
  if (inj.kind === 'basic' && /[:\s]/.test(name)) {
    return { ok: false, error: 'A basic-auth username cannot contain a colon or whitespace.' }
  }
  return { ok: true }
}

/** How the panel and the audit row describe a rule, without naming the secret. */
export function describeInjection(inj: CredProxyInjection): string {
  switch (inj.kind) {
    case 'bearer':
      return 'Authorization: Bearer'
    case 'header':
      return `header ${inj.name}`
    case 'query':
      return `query parameter ${inj.name}`
    case 'basic':
      return `basic auth as ${inj.name}`
  }
}

const str = (v: unknown): string => (typeof v === 'string' ? v : '')

const INJECTION_KINDS: CredProxyInjectionKind[] = ['header', 'bearer', 'query', 'basic']
const SLOTS: CredProxySlot[] = ['password', 'privateKey', 'username', 'field']

/** Rebuilds one rule field by field from whatever was on disk or came across
 *  the IPC bridge. A rule decides where a credential is sent, so nothing is
 *  passed through structurally — `sanitiseRules` is what stands between a
 *  hand-edited JSON file and a key going somewhere nobody chose. */
export function sanitiseRule(raw: unknown): CredProxyRule | null {
  if (typeof raw !== 'object' || raw === null) return null
  const r = raw as Record<string, unknown>
  const id = str(r.id).trim()
  if (id === '') return null
  const origin = normaliseOrigin(str(r.origin))
  if (origin === null) return null

  const cred = (typeof r.credential === 'object' && r.credential !== null ? r.credential : {}) as Record<
    string,
    unknown
  >
  const vaultEntryId = str(cred.vaultEntryId).trim()
  if (vaultEntryId === '') return null
  const slot = SLOTS.find((s) => s === cred.slot) ?? 'password'
  const fieldKey = str(cred.fieldKey).trim()
  if (slot === 'field' && fieldKey === '') return null

  const injRaw = (typeof r.injection === 'object' && r.injection !== null ? r.injection : {}) as Record<
    string,
    unknown
  >
  const kind = INJECTION_KINDS.find((k) => k === injRaw.kind)
  if (!kind) return null
  const injection: CredProxyInjection = { kind }
  if (kind !== 'bearer') injection.name = str(injRaw.name).trim().slice(0, 128)
  if (!validateInjection(injection).ok) return null

  return {
    id: id.slice(0, 64),
    name: (str(r.name).trim() || origin).slice(0, 80),
    origin,
    credential: slot === 'field' ? { vaultEntryId, slot, fieldKey } : { vaultEntryId, slot },
    injection,
    // Absent means enabled: a rule written before this field existed is one the
    // user created on purpose. Only an explicit `false` switches it off.
    enabled: r.enabled !== false,
    createdAt: str(r.createdAt) || new Date(0).toISOString()
  }
}

/** Every rule that survives sanitisation, with duplicate origins collapsed.
 *
 *  Two rules for one origin is not a merge conflict to resolve at request
 *  time — it is an ambiguity about which credential leaves the machine, and
 *  the first one wins deterministically rather than whichever `find` reached
 *  first after an unrelated reordering. */
export function sanitiseRules(raw: unknown): CredProxyRule[] {
  if (!Array.isArray(raw)) return []
  const out: CredProxyRule[] = []
  const seenOrigins = new Set<string>()
  const seenIds = new Set<string>()
  for (const item of raw) {
    const rule = sanitiseRule(item)
    if (!rule) continue
    if (seenIds.has(rule.id) || seenOrigins.has(rule.origin)) continue
    seenIds.add(rule.id)
    seenOrigins.add(rule.origin)
    out.push(rule)
  }
  return out
}

// --------------------------------------------------------------- audit rows

/** One call, as the audit records it.
 *
 *  What is here: the destination origin, the method, the path with its QUERY
 *  STRING REMOVED, which rule matched, the outcome, the status and the
 *  duration.
 *
 *  What is deliberately NOT here, and why:
 *    * the request or response BODY — the roadmap says so, and a body is where
 *      a second credential lives when an API takes one in a form field;
 *    * the QUERY STRING — a `query` rule puts the key in it, and an API that
 *      takes a key in a query parameter is exactly the API whose callers put
 *      other things there too;
 *    * request and response HEADERS — the injected one is the credential, and
 *      keeping "all except that one" is a whitelist nobody maintains. */
export interface CredProxyCall {
  id: string
  at: string
  method: string
  origin: string
  /** Path only. Never the query string. */
  path: string
  ruleId: string | null
  ruleName: string | null
  outcome: CredProxyOutcome
  /** Upstream status, when there was an upstream response. */
  status?: number
  ms: number
  /** A refusal or upstream error, already redacted. */
  detail?: string
}

export interface CredProxyStatus {
  enabled: boolean
  port: number
  /** Whether the listener is actually accepting connections right now. */
  listening: boolean
  /** The address it is bound to, so the panel can state loopback as a fact
   *  rather than as a promise. */
  address: string | null
  /** Whether a client token exists. The token's VALUE is fetched separately
   *  and deliberately — see credProxy.ts. */
  hasToken: boolean
  ruleCount: number
  error?: string
  /** Set when a call could not be made because the credential could not be
   *  read — the vault is locked, or the entry is gone.
   *
   *  It is a STATE, not a per-request error, because that is the difference
   *  between an operator seeing "the vault is locked, 14 calls parked since
   *  09:12" once and seeing fourteen unrelated-looking failures. Cleared by
   *  the next call that resolves. */
  parked?: { reason: 'vault-locked' | 'credential-missing'; since: string; calls: number }
}

/** The base URL a caller points at, built once so the panel and the docs
 *  cannot disagree about the shape. */
export function credProxyBaseUrl(port: number, upstreamOrigin: string): string {
  return `http://127.0.0.1:${port}/${upstreamOrigin}`
}

// ------------------------------------------------------------------- tokens
//
// PER-AGENT TOKENS, replacing the single shared one.
//
// The proxy shipped with one static token, minted once and valid until somebody
// thought to rotate it. That is the shape every secrets product eventually
// regrets: it names nobody, expires never, and revoking it stops every caller
// at once — so in practice it never gets revoked, because the person who would
// do it cannot tell what they would break.
//
// A token now belongs to a caller, says who, and can be given an end date. The
// point is not cryptography, it is BLAST RADIUS: when one script's token leaks,
// the answer should be revoking that script, not every script.
//
// Values stay in the OS keychain via the secrets store, keyed by token id,
// exactly where the single token already lived. They are not put in the rules
// file and not hashed: hashing would buy nothing here, because the file never
// held the value in the first place, and it would cost the ability to re-copy a
// token — which on a single-user desktop turns a small mistake into a rotation.

export interface CredProxyToken {
  id: string
  /** What this token is for, in the operator's words. Required, because a list
   *  of tokens nobody can tell apart is a list nobody will ever revoke from. */
  name: string
  createdAt: string
  /** ISO date, or null for a token that does not expire. Null is allowed and
   *  is not the default the UI offers. */
  expiresAt: string | null
  /** Set when revoked. The record is KEPT rather than deleted, so the call log
   *  can still say which token made a call last week. */
  revokedAt: string | null
  /** Updated on every accepted call. What makes an unused token safe to
   *  revoke, and the only reason anyone ever does. */
  lastUsedAt: string | null
}

export type CredProxyTokenState = 'active' | 'expired' | 'revoked'

/**
 * Whether a token may be used, right now.
 *
 * Revocation beats expiry: a token revoked before it expired is revoked, and
 * saying "expired" about it would send someone to change the date rather than
 * to notice it was taken away.
 */
export function credProxyTokenState(t: CredProxyToken, now: number): CredProxyTokenState {
  if (t.revokedAt !== null) return 'revoked'
  if (t.expiresAt === null) return 'active'
  const at = Date.parse(t.expiresAt)
  // An unparseable expiry is treated as EXPIRED, not as "no expiry". A date we
  // cannot read is not permission to keep going: the safe reading of a broken
  // record is the one that stops.
  if (!Number.isFinite(at)) return 'expired'
  return now >= at ? 'expired' : 'active'
}

export function credProxyTokenUsable(t: CredProxyToken, now: number): boolean {
  return credProxyTokenState(t, now) === 'active'
}

/** Why a presented token was refused, for the call log and the panel. */
export const CRED_PROXY_TOKEN_STATE_NOTE: Record<CredProxyTokenState, string> = {
  active: 'Usable.',
  expired: 'Past its end date. Create a new token rather than extending this one.',
  revoked: 'Revoked. It is kept here so the call log can still name it.'
}
