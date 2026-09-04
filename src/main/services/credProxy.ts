import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http'
import { timingSafeEqual } from 'node:crypto'
import {
  CRED_PROXY_TOKEN_HEADER,
  HOP_BY_HOP_HEADERS,
  REFUSAL_REASONS,
  REFUSAL_STATUS,
  matchRule,
  parseProxyTarget,
  sanitiseRule,
  sanitiseRules,
  validateInjection
} from '../../shared/credproxy'
import type {
  CredProxyCall,
  CredProxyCredentialRef,
  CredProxyOutcome,
  CredProxyRule,
  CredProxyStatus
} from '../../shared/credproxy'
import { redactOutput } from './secretRedaction'

// The API credential proxy — roadmap item 7, main-process half.
//
// The vocabulary and the matching model are in src/shared/credproxy.ts, and
// the header of that file carries the design argument. This file is the part
// that touches the world: a loopback listener, a rule file, an audit ring, and
// the one place a resolved API key exists in memory.
//
// ---------------------------------------------------------------------------
// NOT AGENT-REACHABLE, IN EITHER DIRECTION, AND THE ARGUMENT IS THE JOB
// ENGINE'S ONE TURN FURTHER
// ---------------------------------------------------------------------------
//
// tests/jobsNotExposed.test.ts states it as DURABILITY DEFEATS REVOCATION:
// `denyAllPending()` — the stop-all-AI-access switch — works by resolving
// requests that are PENDING, so a capability that outlives the request that
// created it is one the switch cannot revoke.
//
// This module is that, twice over, and the two halves are different powers:
//
//   * An agent that could DEFINE A RULE would be choosing a destination for
//     one of the user's credentials. The rule is a row in a JSON file holding
//     a standing authorisation; it has nothing pending at any moment, so
//     revoking every session, denying every outstanding approval and stopping
//     the bridge entirely leaves it exactly where it is, pointed wherever it
//     was pointed. That is the rule engine's objection (item 27) with a
//     credential attached to it.
//
//   * An agent that could CALL THE PROXY would be spending the user's API
//     budget on someone else's meter, under a credential it never held and
//     therefore cannot be shown to have used. The audit here records the
//     calls; it does not record who asked for them, because on loopback there
//     is no such thing as a caller identity beyond the token.
//
// So: no MCP tool, no capability, no import from anything the bridge or the
// CLI can reach. See tests/jobsNotExposed.test.ts, which fails on the symbol
// names as well as on the import closure.
//
// ---------------------------------------------------------------------------
// EVERYTHING IS INJECTED, INCLUDING THE VAULT
// ---------------------------------------------------------------------------
//
// Same discipline as RuleEngine, and for the same second reason: this module
// must not import `services/vault` or `services/secrets`, because that would
// put the OS keychain and the master key inside the reach of the one module in
// this app that talks to third-party hosts. It is handed a `resolveCredential`
// that returns a value or a reason, and it can do nothing its host did not
// give it.

/** What a credential lookup produced. A discriminated result rather than a
 *  thrown `VaultLockedError`, so this module never has to import the resolver
 *  that defines it. main/index.ts does the mapping. */
export type CredentialResolution =
  | { ok: true; value: string }
  | { ok: false; reason: 'vault-locked' | 'credential-missing' }

/** The file, as it is written. Versioned because it holds routing decisions
 *  about where credentials go, and those have to keep meaning what they meant. */
export interface CredProxyFile {
  v: 1
  enabled: boolean
  port: number
  rules: unknown[]
}

export interface CredProxyDeps {
  now(): number
  newId(): string
  read(): unknown
  write(file: CredProxyFile): void
  /** Resolves one rule's credential to plaintext, at request time. Never
   *  cached here: the value lives as long as one request and no longer, so
   *  nothing in this module holds a copy of a key after the vault re-locks. */
  resolveCredential(ref: CredProxyCredentialRef): CredentialResolution
  /** The client token a caller must present, or null when none is minted. */
  clientToken(): string | null
  /** Durable audit. Called once per call, refusals included. */
  recordCall(call: CredProxyCall): void
  /** Injected so a test can point the proxy at a real `node:http` upstream
   *  without reaching the network. Defaults to the global fetch. */
  fetch?: typeof globalThis.fetch
}

/** A request body larger than this is refused rather than buffered. An API
 *  call is not a file upload, and an unbounded buffer on a loopback port any
 *  local process can reach is a memory-exhaustion primitive. */
const MAX_BODY_BYTES = 16 * 1024 * 1024

/** Long enough for a slow API, short enough that a hung upstream does not pin
 *  a socket for the life of the app. */
const UPSTREAM_TIMEOUT_MS = 60_000

/** How many calls the panel can show. The durable log is `recordCall`. */
const RING = 200

/** A refusal or error string, as it is stored.
 *
 * REDACT FIRST, THEN CAP — never the other way round.
 *
 * This ordering is the whole function. Capping first can cut the END marker
 * off a PEM block, after which the private-key pattern in secretRedaction.ts
 * matches nothing at all and the body is stored as prose. That exact bug was
 * found in the change log this week; it is written here as code rather than as
 * a comment somewhere because the two lines look interchangeable and are not.
 */
export function redactThenCap(text: string, secrets: string[], max = 400): string {
  const clean = redactOutput(String(text ?? ''), secrets)
  return clean.length <= max ? clean : `${clean.slice(0, max)}…`
}

/** Constant-time string comparison that also survives a length mismatch —
 *  `timingSafeEqual` throws on one, and a thrown comparison is a comparison
 *  that returned nothing. */
function tokenEquals(a: string, b: string): boolean {
  const ba = Buffer.from(a, 'utf8')
  const bb = Buffer.from(b, 'utf8')
  if (ba.length !== bb.length) {
    // Still compare something of equal length, so the failure path does not
    // become a length oracle for the token.
    timingSafeEqual(ba, ba)
    return false
  }
  return timingSafeEqual(ba, bb)
}

/** Whether a socket's peer address is this machine.
 *
 *  The listener already binds 127.0.0.1, so this should never fire. It is here
 *  because "bound to loopback" is a property of one line of setup code that a
 *  future edit could change to 0.0.0.0 for a plausible-sounding reason, and
 *  the refusal should not depend on remembering why that line is what it is. */
export function isLoopbackAddress(addr: string | undefined): boolean {
  if (!addr) return false
  const a = addr.startsWith('::ffff:') ? addr.slice(7) : addr
  if (a === '::1') return true
  return /^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(a)
}

const emptyFile = (): CredProxyFile => ({ v: 1, enabled: false, port: 0, rules: [] })

export class CredProxy {
  private readonly deps: CredProxyDeps
  private file: CredProxyFile
  private ruleCache: CredProxyRule[]
  private server: Server | null = null
  private ring: CredProxyCall[] = []
  private lastError: string | undefined
  private parked: CredProxyStatus['parked']

  constructor(deps: CredProxyDeps, defaultPort: number) {
    this.deps = deps
    const raw = deps.read()
    const r = (typeof raw === 'object' && raw !== null ? raw : {}) as Record<string, unknown>
    const port = Number(r.port)
    this.file = {
      v: 1,
      enabled: r.enabled === true,
      port: Number.isInteger(port) && port > 0 && port < 65536 ? port : defaultPort,
      rules: Array.isArray(r.rules) ? r.rules : []
    }
    this.ruleCache = sanitiseRules(this.file.rules)
  }

  // ------------------------------------------------------------------ rules

  rules(): CredProxyRule[] {
    return this.ruleCache.map((r) => ({ ...r }))
  }

  private persist(): void {
    this.file.rules = this.ruleCache
    this.deps.write(this.file)
  }

  /** Adds or replaces a rule. Returns the stored form, which is the sanitised
   *  one — the caller never gets to assume its draft survived unchanged. */
  saveRule(draft: unknown): { ok: true; rule: CredProxyRule } | { ok: false; error: string } {
    const d = (typeof draft === 'object' && draft !== null ? draft : {}) as Record<string, unknown>
    const withId: Record<string, unknown> = {
      ...d,
      id: typeof d.id === 'string' && d.id !== '' ? d.id : this.deps.newId()
    }
    if (typeof withId.createdAt !== 'string' || withId.createdAt === '') {
      withId.createdAt = new Date(this.deps.now()).toISOString()
    }
    // The specific error first, so the panel can say what is wrong rather than
    // "that rule is not valid" for six different reasons.
    const inj = (typeof d.injection === 'object' && d.injection !== null ? d.injection : {}) as {
      kind?: unknown
      name?: unknown
    }
    if (typeof inj.kind === 'string') {
      const v = validateInjection({
        kind: inj.kind as never,
        name: typeof inj.name === 'string' ? inj.name : ''
      })
      if (!v.ok) return { ok: false, error: v.error }
    }
    const rule = sanitiseRule(withId)
    if (!rule) {
      return {
        ok: false,
        error: 'That rule needs a name, an https:// destination, a vault entry and a way to send it.'
      }
    }
    const clash = this.ruleCache.find((r) => r.origin === rule.origin && r.id !== rule.id)
    if (clash) {
      return {
        ok: false,
        error: `"${clash.name}" already covers ${rule.origin}. One origin, one rule — two would be an ambiguity about which credential leaves this machine.`
      }
    }
    const at = this.ruleCache.findIndex((r) => r.id === rule.id)
    if (at >= 0) this.ruleCache[at] = rule
    else this.ruleCache.push(rule)
    this.persist()
    return { ok: true, rule }
  }

  removeRule(id: string): { ok: boolean } {
    const before = this.ruleCache.length
    this.ruleCache = this.ruleCache.filter((r) => r.id !== id)
    if (this.ruleCache.length !== before) this.persist()
    return { ok: this.ruleCache.length !== before }
  }

  // ----------------------------------------------------------------- status

  status(): CredProxyStatus {
    const addr = this.server?.address()
    return {
      enabled: this.file.enabled,
      port: this.file.port,
      listening: this.server !== null && this.server.listening,
      address: addr && typeof addr === 'object' ? `${addr.address}:${addr.port}` : null,
      hasToken: this.deps.clientToken() !== null,
      ruleCount: this.ruleCache.length,
      ...(this.lastError ? { error: this.lastError } : {}),
      ...(this.parked ? { parked: this.parked } : {})
    }
  }

  calls(limit = RING): CredProxyCall[] {
    return this.ring.slice(0, Math.max(0, Math.min(limit, RING)))
  }

  // -------------------------------------------------------------- lifecycle

  /** Binds the listener. Loopback only, and that is not a configuration. */
  async start(port?: number): Promise<{ ok: boolean; error?: string }> {
    if (port !== undefined) {
      // 0 is legal and means "ask the OS for a free one" — what the tests use,
      // and what a user never types. The bound port is written back below, so
      // the panel and the next launch both see the real number rather than 0.
      if (!Number.isInteger(port) || port < 0 || port > 65535) {
        return { ok: false, error: `${port} is not a port.` }
      }
      this.file.port = port
    }
    await this.stop()
    this.lastError = undefined
    const server = createServer((req, res) => {
      void this.handle(req, res)
    })
    // A local process that opens a socket and says nothing must not be able to
    // hold one open indefinitely.
    server.headersTimeout = 30_000
    server.requestTimeout = UPSTREAM_TIMEOUT_MS
    const result = await new Promise<{ ok: boolean; error?: string }>((resolve) => {
      const onError = (err: Error): void => {
        server.removeListener('error', onError)
        resolve({ ok: false, error: err.message })
      }
      server.once('error', onError)
      // 127.0.0.1, never 0.0.0.0 and never a configurable host. A proxy that
      // holds API credentials and listens on a LAN interface is a credential
      // server for the network it is on.
      server.listen(this.file.port, '127.0.0.1', () => {
        server.removeListener('error', onError)
        resolve({ ok: true })
      })
    })
    if (!result.ok) {
      this.lastError = result.error
      try {
        server.close()
      } catch {
        /* it never bound */
      }
      return result
    }
    this.server = server
    this.file.enabled = true
    const bound = server.address()
    if (bound && typeof bound === 'object') this.file.port = bound.port
    this.persist()
    return { ok: true }
  }

  async stop(): Promise<void> {
    const server = this.server
    this.server = null
    if (!server) return
    await new Promise<void>((resolve) => {
      server.close(() => resolve())
      // An idle keep-alive connection would otherwise hold `close` open until
      // it times out, which turns "turn the proxy off" into a 60-second wait.
      server.closeIdleConnections?.()
    })
  }

  /** Turns it off and remembers that, so it does not come back on next launch. */
  async disable(): Promise<void> {
    await this.stop()
    this.file.enabled = false
    this.persist()
  }

  boundPort(): number | null {
    const addr = this.server?.address()
    return addr && typeof addr === 'object' ? addr.port : null
  }

  // ------------------------------------------------------------- the request

  private record(call: CredProxyCall): void {
    this.ring.unshift(call)
    if (this.ring.length > RING) this.ring.length = RING
    try {
      this.deps.recordCall(call)
    } catch (err) {
      console.error('[credproxy] failed to record a call:', err)
    }
  }

  /** Refuses, with the reason, and never by forwarding. */
  private refuse(
    res: ServerResponse,
    reason: Exclude<CredProxyOutcome, 'forwarded'>,
    started: number,
    ctx: { method: string; origin: string; path: string; rule?: CredProxyRule; detail?: string }
  ): void {
    const body = JSON.stringify({
      error: reason,
      message: REFUSAL_REASONS[reason],
      proxy: 'shellpilot-credential-proxy'
    })
    res.writeHead(REFUSAL_STATUS[reason], {
      'content-type': 'application/json',
      'content-length': Buffer.byteLength(body),
      // So a caller that gets an unexpected 403 knows which hop produced it,
      // rather than reading it as the far end's answer.
      'x-shellpilot-proxy': 'refused'
    })
    res.end(body)
    this.record({
      id: this.deps.newId(),
      at: new Date(this.deps.now()).toISOString(),
      method: ctx.method,
      origin: ctx.origin,
      path: ctx.path,
      ruleId: ctx.rule?.id ?? null,
      ruleName: ctx.rule?.name ?? null,
      outcome: reason,
      ms: this.deps.now() - started,
      ...(ctx.detail ? { detail: ctx.detail } : {})
    })
  }

  async handle(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const started = this.deps.now()
    const method = (req.method ?? 'GET').toUpperCase()
    // Nothing is known about the destination yet, and the audit row still has
    // to say something true.
    const unknownCtx = { method, origin: '', path: '' }

    if (!isLoopbackAddress(req.socket.remoteAddress ?? undefined)) {
      this.refuse(res, 'not-loopback', started, unknownCtx)
      return
    }

    // AUTHENTICATION BEFORE ROUTING, deliberately. A caller with no token
    // learns nothing about which destinations have rules — not even by the
    // difference between a 401 and a 403.
    const expected = this.deps.clientToken()
    const raw = req.headers[CRED_PROXY_TOKEN_HEADER]
    const presented = Array.isArray(raw) ? (raw[0] ?? '') : (raw ?? '')
    if (expected === null || presented === '' || !tokenEquals(presented, expected)) {
      this.refuse(res, 'unauthenticated', started, unknownCtx)
      return
    }

    const parsed = parseProxyTarget(req.url ?? '')
    if (!parsed.ok) {
      this.refuse(res, parsed.reason, started, unknownCtx)
      return
    }
    const { url, origin } = parsed.target
    // The path WITHOUT its query string, everywhere it is recorded. A `query`
    // rule puts the credential in that query string.
    const ctx = { method, origin, path: url.pathname }

    const rule = matchRule(this.ruleCache, origin)
    if (!rule) {
      this.refuse(res, 'no-rule', started, ctx)
      return
    }
    if (!rule.enabled) {
      this.refuse(res, 'rule-disabled', started, { ...ctx, rule })
      return
    }

    const resolved = this.deps.resolveCredential(rule.credential)
    if (!resolved.ok) {
      // Parked, not forwarded. A request that silently went out unauthenticated
      // would fail at the far end and look like a permissions problem there,
      // which sends whoever is debugging it to the wrong building.
      this.parked = {
        reason: resolved.reason,
        since: this.parked?.reason === resolved.reason ? this.parked.since : new Date(started).toISOString(),
        calls: (this.parked?.reason === resolved.reason ? this.parked.calls : 0) + 1
      }
      this.refuse(res, resolved.reason, started, { ...ctx, rule })
      return
    }
    const secret = resolved.value
    this.parked = undefined

    // An ArrayBuffer rather than the Buffer readBody produced: `BodyInit` in
    // this project's lib resolves to a BufferSource whose ArrayBufferView arm
    // no longer accepts a generic `Uint8Array<ArrayBufferLike>`, and a copy
    // into a plain ArrayBuffer is the honest way past that rather than a cast
    // that would also silence a real mistake here later.
    let body: ArrayBuffer | undefined
    if (method !== 'GET' && method !== 'HEAD') {
      try {
        body = toArrayBuffer(await readBody(req, MAX_BODY_BYTES))
      } catch {
        this.refuse(res, 'upstream-failed', started, {
          ...ctx,
          rule,
          detail: 'The request body was larger than this proxy will buffer.'
        })
        return
      }
    }

    const outbound = new URL(url.href)
    const headers = new Headers()
    for (const [name, value] of Object.entries(req.headers)) {
      if (value === undefined) continue
      if (HOP_BY_HOP_HEADERS.includes(name.toLowerCase())) continue
      headers.set(name, Array.isArray(value) ? value.join(', ') : value)
    }

    // ---- the injection, and the only place the secret is used --------------
    switch (rule.injection.kind) {
      case 'bearer':
        headers.set('authorization', `Bearer ${secret}`)
        break
      case 'basic':
        headers.set(
          'authorization',
          `Basic ${Buffer.from(`${rule.injection.name ?? ''}:${secret}`, 'utf8').toString('base64')}`
        )
        break
      case 'header':
        headers.set(rule.injection.name ?? '', secret)
        break
      case 'query':
        outbound.searchParams.set(rule.injection.name ?? '', secret)
        break
    }

    const doFetch = this.deps.fetch ?? globalThis.fetch
    let upstream: Response
    try {
      upstream = await doFetch(outbound, {
        method,
        headers,
        body,
        // ---------------------------------------------------------------
        // REDIRECTS ARE NOT FOLLOWED. AT ALL. NOT EVEN SAME-ORIGIN.
        // ---------------------------------------------------------------
        //
        // This is the classic leak in a credential proxy, and it is worth
        // stating the reasoning rather than the setting.
        //
        // Node's fetch follows redirects by default. undici strips the
        // `Authorization` header when a redirect crosses an origin — but it
        // does NOT strip a custom header you set yourself, which is exactly
        // what a `header` rule injects. So on the default setting, an upstream
        // that answers 302 to https://evil.tld gets `X-Api-Key` delivered to
        // it by us, with no rule covering that origin and nothing in this file
        // consulted a second time.
        //
        // "Follow it only when the target origin matches the rule" was the
        // other candidate and it is still wrong: it re-issues a CREDENTIALED
        // request on the strength of a `Location` header the upstream wrote,
        // which makes the destination partly the upstream's decision. The
        // credential is injected exactly once, to the origin a human wrote
        // into a rule, and if that host wants the caller somewhere else the
        // caller can decide — without our key, because it never had it.
        redirect: 'manual',
        signal: AbortSignal.timeout(UPSTREAM_TIMEOUT_MS)
      })
    } catch (err) {
      const detail = redactThenCap(err instanceof Error ? err.message : String(err), [secret])
      this.refuse(res, 'upstream-failed', started, { ...ctx, rule, detail })
      return
    }

    const outHeaders: Record<string, string | string[]> = {}
    upstream.headers.forEach((value, name) => {
      if (HOP_BY_HOP_HEADERS.includes(name.toLowerCase())) return
      // `set-cookie` is the one header that legitimately repeats; Headers
      // gives it back joined, and getSetCookie splits it properly again.
      if (name.toLowerCase() === 'set-cookie') return
      outHeaders[name] = value
    })
    const cookies = upstream.headers.getSetCookie?.() ?? []
    if (cookies.length > 0) outHeaders['set-cookie'] = cookies
    outHeaders['x-shellpilot-proxy'] = 'forwarded'

    let detail: string | undefined
    if (upstream.status >= 300 && upstream.status < 400) {
      const location = upstream.headers.get('location')
      const to = location ? safeOrigin(location, origin) : null
      if (to !== null && to !== origin) {
        // The caller may follow this itself. It will not be carrying our
        // credential when it does, because it never had one.
        outHeaders['x-shellpilot-proxy'] = 'redirect-not-followed'
        detail = redactThenCap(`Upstream redirected to ${to}; not followed, credential not resent.`, [
          secret
        ])
      }
    }

    const payload = Buffer.from(await upstream.arrayBuffer())
    res.writeHead(upstream.status, outHeaders)
    res.end(payload)

    this.record({
      id: this.deps.newId(),
      at: new Date(started).toISOString(),
      method,
      origin,
      path: url.pathname,
      ruleId: rule.id,
      ruleName: rule.name,
      outcome: 'forwarded',
      status: upstream.status,
      ms: this.deps.now() - started,
      ...(detail ? { detail } : {})
    })
  }
}

/** The origin a `Location` header points at, resolved against the request's
 *  own origin so a relative redirect reads as same-origin. Null when it is not
 *  a URL at all. */
function safeOrigin(location: string, base: string): string | null {
  try {
    const u = new URL(location, base)
    return u.origin
  } catch {
    return null
  }
}

function toArrayBuffer(buf: Buffer): ArrayBuffer {
  const out = new ArrayBuffer(buf.byteLength)
  new Uint8Array(out).set(buf)
  return out
}

function readBody(req: IncomingMessage, max: number): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = []
    let size = 0
    req.on('data', (c: Buffer) => {
      size += c.length
      if (size > max) {
        reject(new Error('body too large'))
        req.destroy()
        return
      }
      chunks.push(c)
    })
    req.on('end', () => resolve(Buffer.concat(chunks)))
    req.on('error', reject)
  })
}

export { emptyFile as emptyCredProxyFile }
