import http from 'node:http'
import type { FrpProxyStatus, VpnErrorCode, VpnState } from '../../../shared/vpn'
import { VpnError, classifyEngineLine } from './errors'

// frpc's admin API is a real, documented control channel, so we use it instead
// of scraping stdout. Endpoints verified against frp's `client/api_router.go`:
//
//   GET  /healthz                   liveness, used as the supervisor healthCheck
//   GET  /api/status                per-proxy state
//   GET  /api/config                the active config
//   PUT  /api/config                replace it
//   GET  /api/reload                apply the replacement, in place
//   POST /api/stop                  graceful shutdown, used as gracefulStop
//   GET  /api/proxy/{name}/config   per-proxy detail
//
// Bound to 127.0.0.1 only — there is no host option here on purpose, so no
// caller can point this client at anything but the child we started.
//
// Verified against frpc 0.71.0 on darwin/arm64, not inferred from the docs:
//
//   * `/healthz` takes NO credentials; `/api/*` returns 401 without them. The
//     two are therefore not interchangeable — a green /healthz says the
//     process is alive, and says nothing at all about whether it reached frps.
//   * `/api/status` answers `200 {}` — an empty *object* — before the client
//     has logged in to frps. `{}` is the not-connected-to-anything state, and
//     `summariseReadiness` treats it as such by counting against the
//     configured proxy names rather than iterating whatever came back.
//   * `/api/config` returns the config text with `{{ .Envs.X }}` still
//     unexpanded, so the admin API never discloses a secret. That cuts both
//     ways: `reload()` must PUT templates too, never resolved values.
//   * frpc logs to stdout (including `[W]`/`[E]`), wrapped in ANSI colour, and
//     the reset sequence lands at the *start of the next line*. Everything
//     that pattern-matches engine output goes through `stripAnsi` first.

// frp exposes no client-side byte counters at all: there is no equivalent of
// WireGuard's rx_bytes/tx_bytes anywhere in the admin API. So VpnStats for frp
// omits rxBytes/txBytes rather than reporting zeroes or a made-up figure — the
// proxy table below *is* the telemetry, and it is the more useful of the two.

const ADMIN_HOST = '127.0.0.1'
const DEFAULT_TIMEOUT_MS = 5_000
// Big enough for a status payload with a few hundred proxies, small enough
// that a wedged or hostile responder cannot make us buffer a heap.
const DEFAULT_MAX_BODY_BYTES = 1024 * 1024
const DEFAULT_READY_TIMEOUT_MS = 30_000
const DEFAULT_POLL_INTERVAL_MS = 400

export const FRP_STATUS_RUNNING = 'running'
export const FRP_STATUS_START_ERROR = 'start error'

export interface FrpAdminOptions {
  port: number
  user: string
  password: string
  /** Per request, covering connect, response and body. */
  timeoutMs?: number
  maxBodyBytes?: number
}

export interface FrpReadyOptions {
  timeoutMs?: number
  intervalMs?: number
  signal?: AbortSignal
}

export interface FrpReadiness {
  /** Every expected proxy reported `running`. */
  ready: boolean
  proxies: FrpProxyStatus[]
  /** Proxies frpc could not start, with `err` exactly as frpc worded it. */
  failed: FrpProxyStatus[]
  /** Expected names the admin API never mentioned. */
  missing: string[]
  timedOut: boolean
}

interface RawResponse {
  status: number
  body: string
}

// The shape frpc actually returns from /api/status: an object keyed by proxy
// type, each holding an array. Fields are snake_case on the wire.
interface WireProxy {
  name?: unknown
  type?: unknown
  status?: unknown
  err?: unknown
  local_addr?: unknown
  remote_addr?: unknown
  plugin?: unknown
}

function str(v: unknown): string | undefined {
  return typeof v === 'string' && v.length > 0 ? v : undefined
}

export class FrpAdminApi {
  private readonly port: number
  private readonly authHeader: string
  private readonly timeoutMs: number
  private readonly maxBodyBytes: number

  constructor(opts: FrpAdminOptions) {
    this.port = opts.port
    const basic = Buffer.from(`${opts.user}:${opts.password}`, 'utf8').toString('base64')
    this.authHeader = `Basic ${basic}`
    this.timeoutMs = opts.timeoutMs ?? DEFAULT_TIMEOUT_MS
    this.maxBodyBytes = opts.maxBodyBytes ?? DEFAULT_MAX_BODY_BYTES
  }

  get origin(): string {
    return `http://${ADMIN_HOST}:${this.port}`
  }

  private send(method: string, path: string, body?: string): Promise<RawResponse> {
    return new Promise<RawResponse>((resolve, reject) => {
      const payload = body === undefined ? undefined : Buffer.from(body, 'utf8')
      const req = http.request(
        {
          host: ADMIN_HOST,
          port: this.port,
          path,
          method,
          // No pooling: this is a low-rate control channel, and a pooled socket
          // outliving the child it belonged to is a source of confusing
          // ECONNRESETs after a restart.
          agent: false,
          timeout: this.timeoutMs,
          headers: {
            authorization: this.authHeader,
            ...(payload ? { 'content-type': 'text/plain', 'content-length': payload.length } : {})
          }
        },
        (res) => {
          const chunks: Buffer[] = []
          let total = 0
          res.on('data', (chunk: Buffer) => {
            total += chunk.length
            if (total > this.maxBodyBytes) {
              res.destroy()
              req.destroy()
              reject(
                new VpnError(
                  'internal',
                  `The tunnel program sent more than ${this.maxBodyBytes} bytes in reply to ${method} ${path}.`
                )
              )
              return
            }
            chunks.push(chunk)
          })
          res.on('end', () => {
            resolve({ status: res.statusCode ?? 0, body: Buffer.concat(chunks).toString('utf8') })
          })
          res.on('error', reject)
        }
      )
      req.on('timeout', () => {
        req.destroy(
          new VpnError(
            'internal',
            `The tunnel program did not answer ${method} ${path} on ${ADMIN_HOST}:${this.port} within ${this.timeoutMs} ms.`
          )
        )
      })
      req.on('error', reject)
      if (payload) req.write(payload)
      req.end()
    })
  }

  private async call(method: string, path: string, body?: string): Promise<RawResponse> {
    let res: RawResponse
    try {
      res = await this.send(method, path, body)
    } catch (e) {
      throw asAdminError(e, `${ADMIN_HOST}:${this.port}`)
    }
    if (res.status === 401 || res.status === 403) {
      // Our own child rejecting our own per-run credentials means either a bug
      // or that something else is listening on the port we expected frpc on.
      // Either way it is not the user's password and must not read as one.
      throw new VpnError(
        'permission-denied',
        `The tunnel program's control channel on ${ADMIN_HOST}:${this.port} rejected ShellPilot's credentials.`
      )
    }
    if (res.status >= 300 && res.status < 400) {
      // Redirects are never followed: the whole security story of this client
      // is that it only ever talks to 127.0.0.1, and a Location header is
      // exactly how that would stop being true.
      throw new VpnError(
        'internal',
        `The tunnel program's control channel answered ${method} ${path} with a redirect (${res.status}), which is not followed.`
      )
    }
    if (res.status < 200 || res.status >= 300) {
      const detail = stripAnsi(res.body).trim().slice(0, 300)
      throw new VpnError(
        classifyEngineLine(detail) ?? 'internal',
        `The tunnel program's control channel answered ${method} ${path} with ${res.status}${detail ? `: ${detail}` : '.'}`
      )
    }
    return res
  }

  /** Liveness, and only liveness. frp serves `/healthz` without credentials,
   *  and it goes green as soon as the admin listener is up — before, and
   *  independently of, any connection to frps. Readiness is `waitForReady`. */
  async healthz(): Promise<void> {
    await this.call('GET', '/healthz')
  }

  async status(): Promise<FrpProxyStatus[]> {
    const res = await this.call('GET', '/api/status')
    return parseFrpStatus(res.body)
  }

  /** The active config, verbatim — `{{ .Envs.X }}` comes back unexpanded, so
   *  this never discloses the token or the admin password. */
  async getConfig(): Promise<string> {
    const res = await this.call('GET', '/api/config')
    return res.body
  }

  /** Replace the stored config. Pass the *generated* TOML, templates intact:
   *  substituting resolved secrets here would write them into frpc's
   *  in-memory config and back out of `GET /api/config`. */
  async putConfig(toml: string): Promise<void> {
    await this.call('PUT', '/api/config', toml)
  }

  /** Apply whatever `PUT /api/config` last stored. */
  async applyReload(): Promise<void> {
    await this.call('GET', '/api/reload')
  }

  /** Replace the config and apply it without dropping the control connection
   *  to frps. frp is the only engine that can do this; WireGuard and OpenVPN
   *  do a stop then a start. */
  async reload(toml: string): Promise<void> {
    await this.putConfig(toml)
    await this.applyReload()
  }

  async proxyConfig(name: string): Promise<Record<string, unknown>> {
    if (name.includes('/') || name.includes('?') || name.includes('#')) {
      throw new VpnError('config-invalid', `"${name}" is not a proxy name.`)
    }
    const res = await this.call('GET', `/api/proxy/${encodeURIComponent(name)}/config`)
    const parsed: unknown = JSON.parse(res.body)
    return typeof parsed === 'object' && parsed !== null ? (parsed as Record<string, unknown>) : {}
  }

  /** Graceful shutdown, used as the supervisor's `gracefulStop`. This is
   *  load-bearing on Windows, where there is no SIGTERM for a non-console
   *  child and the control channel is the only polite way to stop frpc. */
  async stop(): Promise<void> {
    try {
      await this.call('POST', '/api/stop')
    } catch (e) {
      // frpc answers and then exits, so the socket often dies mid-reply. A
      // connection torn down by a process that is doing exactly what we asked
      // is a success, not a failure.
      if (!isDisconnect(e)) throw e
    }
  }

  /** Poll until every *configured* proxy reports `running`, or the timeout.
   *
   *  `expected` must be the names from the spec we generated, never the names
   *  in the response. Before frpc has logged in to frps, `/api/status` answers
   *  `200 {}`, so a readiness check that iterates the response passes
   *  vacuously and reports a tunnel that is connected to nothing. Counting
   *  against the configured names is what makes an empty body mean "not
   *  ready" instead of "all done".
   *
   *  A proxy that reached `start error` is terminal enough to stop waiting on:
   *  frpc's own error text (`port already used`, `proxy name already exists`)
   *  is more useful now than thirty seconds from now. */
  async waitForReady(expected: string[], opts: FrpReadyOptions = {}): Promise<FrpReadiness> {
    const timeoutMs = opts.timeoutMs ?? DEFAULT_READY_TIMEOUT_MS
    const intervalMs = opts.intervalMs ?? DEFAULT_POLL_INTERVAL_MS
    const deadline = Date.now() + timeoutMs
    let last: FrpProxyStatus[] = []

    for (;;) {
      opts.signal?.throwIfAborted()
      try {
        last = await this.status()
      } catch (e) {
        // Not yet listening is the normal first second of a run; a real
        // failure surfaces via the deadline below or via the process exiting.
        if (!isDisconnect(e)) throw e
      }

      const summary = summariseReadiness(last, expected)
      if (summary.ready || summary.failed.length > 0) return { ...summary, timedOut: false }
      if (Date.now() >= deadline) return { ...summary, timedOut: true }
      await delay(Math.min(intervalMs, Math.max(0, deadline - Date.now())), opts.signal)
    }
  }
}

// ------------------------------------------------------------- parsing

/** `/api/status` is an object keyed by proxy type; flatten it and normalise
 *  the snake_case wire names onto FrpProxyStatus. */
export function parseFrpStatus(body: string): FrpProxyStatus[] {
  let parsed: unknown
  try {
    parsed = JSON.parse(body)
  } catch {
    throw new VpnError('internal', 'The tunnel program sent a status reply that is not JSON.')
  }
  if (typeof parsed !== 'object' || parsed === null) return []

  const out: FrpProxyStatus[] = []
  for (const [group, value] of Object.entries(parsed as Record<string, unknown>)) {
    if (!Array.isArray(value)) continue
    for (const entry of value) {
      if (typeof entry !== 'object' || entry === null) continue
      const w = entry as WireProxy
      const name = str(w.name)
      if (!name) continue
      out.push({
        name,
        // The group key is the proxy type; `type` is present in current frp
        // but falling back to the key costs nothing and survives version skew.
        type: str(w.type) ?? group,
        status: str(w.status) ?? 'unknown',
        err: str(w.err),
        localAddr: str(w.local_addr),
        remoteAddr: str(w.remote_addr)
      })
    }
  }
  return out
}

function summariseReadiness(
  proxies: FrpProxyStatus[],
  expected: string[]
): Omit<FrpReadiness, 'timedOut'> {
  const byName = new Map(proxies.map((p) => [p.name, p]))
  const missing: string[] = []
  const failed: FrpProxyStatus[] = []
  let running = 0

  for (const name of expected) {
    const p = byName.get(name)
    if (!p) {
      missing.push(name)
      continue
    }
    if (p.status === FRP_STATUS_RUNNING) running++
    else if (p.status === FRP_STATUS_START_ERROR) failed.push(p)
  }

  // `expected.length > 0` is load-bearing: an empty configured set can never
  // be "all running", and neither can an empty `/api/status` body.
  const ready = expected.length > 0 && missing.length === 0 && running === expected.length
  return { ready, proxies, failed, missing }
}

// -------------------------------------------------------------- mapping

export interface FrpStateSummary {
  state: VpnState
  error?: string
  errorCode?: VpnErrorCode
}

/** Turn the proxy table into the card's state. A proxy in `start error` is
 *  `degraded` rather than `error`: the control connection to frps is up and
 *  the other proxies are carrying traffic, so up-but-not-all-working is the
 *  honest reading — and it is the single most useful distinction this UI can
 *  draw. frpc's own wording is surfaced verbatim, because `port already used`
 *  and `proxy name already exists` already tell the user what to do and any
 *  rewrite of ours would tell them less. */
export function summariseFrpProxies(
  proxies: FrpProxyStatus[],
  expected: string[]
): FrpStateSummary {
  const summary = summariseReadiness(proxies, expected)

  if (summary.failed.length > 0) {
    const first = summary.failed[0]
    const err = first.err ?? 'it could not be started'
    const more = summary.failed.length > 1 ? ` (and ${summary.failed.length - 1} more)` : ''
    return {
      state: 'degraded',
      error: `Proxy "${first.name}": ${err}${more}`,
      errorCode: classifyEngineLine(err) ?? undefined
    }
  }
  if (summary.ready) return { state: 'connected' }
  return { state: 'starting' }
}

/** frpc wraps every log line in ANSI colour, and puts the reset sequence at
 *  the *start of the next line* rather than the end of its own. So a line as
 *  read by `readline` typically begins with `\x1b[0m\x1b[1;34m` — which means
 *  a `/^.../` rule in the error table would never match, and a stored log line
 *  would carry escape codes into the UI. Strip first, always. */
export function stripAnsi(text: string): string {
  // CSI sequences: ESC [ params intermediates final. Enough for frp's SGR
  // colours without pulling in a dependency.
  return text.replace(/\u001b\[[0-9;?]*[ -\/]*[@-~]/g, '')
}

/** Map a line of frpc output to a code. frp's login failures are the version
 *  skew tell: frps reports an incompatible client as a failed login, so
 *  `version mismatch` has to beat the generic `login to server failed` — which
 *  is exactly the order `classifyEngineLine` applies (E33, version skew).
 *
 *  Note frpc writes its warnings and errors to *stdout*, not stderr, so the
 *  caller must feed both streams through here. */
export function frpErrorFromLine(line: string): VpnError | null {
  const clean = stripAnsi(line).trim()
  const code = classifyEngineLine(clean)
  return code ? new VpnError(code, clean) : null
}

/** What to report when `waitForReady` gave up. A readiness timeout with an
 *  empty proxy table is not a generic timeout: it means frpc never logged in
 *  to frps, and the cause is in the engine log. `recentLines` is the tail of
 *  the run's captured output (both streams); the first line that classifies
 *  wins, so a token mismatch surfaces as `auth-failed` and a skewed frps as
 *  `version-mismatch` rather than as "something took too long". */
export function frpReadinessError(readiness: FrpReadiness, recentLines: string[] = []): VpnError {
  for (let i = recentLines.length - 1; i >= 0; i--) {
    const err = frpErrorFromLine(recentLines[i])
    if (err) return err
  }
  if (readiness.proxies.length === 0) {
    return new VpnError(
      'server-rejected',
      'The frp server did not accept a connection, so no proxy was ever registered.'
    )
  }
  const stuck = readiness.missing.join(', ')
  return new VpnError(
    'handshake-timeout',
    stuck ? `These proxies never started: ${stuck}.` : 'Not every proxy started.'
  )
}

// --------------------------------------------------------------- helpers

const DISCONNECT_CODES = new Set(['ECONNRESET', 'ECONNREFUSED', 'EPIPE', 'ENOTFOUND', 'ECONNABORTED'])

/** The control channel is not answering. Its own class because the first
 *  second of a run and the last moment of a graceful stop both look exactly
 *  like this, and neither is a failure — while the same condition an hour into
 *  a run is one. Only the caller knows which it is. */
class AdminUnavailable extends VpnError {}

function isDisconnect(e: unknown): boolean {
  if (e instanceof AdminUnavailable) return true
  const code = (e as NodeJS.ErrnoException | undefined)?.code
  if (code && DISCONNECT_CODES.has(code)) return true
  return e instanceof Error && /socket hang up/i.test(e.message)
}

function asAdminError(e: unknown, where: string): unknown {
  if (e instanceof VpnError) return e
  if (isDisconnect(e)) {
    return new AdminUnavailable('internal', `Nothing is answering on ${where}.`)
  }
  return e
}

function delay(ms: number, signal?: AbortSignal): Promise<void> {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      signal?.removeEventListener('abort', onAbort)
      resolve()
    }, ms)
    const onAbort = (): void => {
      clearTimeout(timer)
      reject(signal?.reason)
    }
    signal?.addEventListener('abort', onAbort, { once: true })
  })
}
