import { app } from 'electron'
import { setSecret, getSecret, deleteSecret } from './secrets'
import { validateWebhookUrl } from '../../shared/webhook'
import type {
  AlertPayload,
  WebhookConfig,
  WebhookDeliveryStatus,
  WebhookTestResult
} from '../../shared/webhook'

// Delivers alerts to a user-configured HTTPS endpoint.
//
// Lives in main for two reasons. The renderer's CSP is `connect-src 'self'`,
// so it cannot make this call at all — and should not: keeping delivery here
// means the webhook URL never has to cross into the renderer, so a compromised
// renderer cannot read the credential or aim it somewhere else.
//
// A generic JSON POST rather than a Slack integration. Slack, Discord, Teams
// and most alerting systems accept an incoming webhook, so one honest
// implementation covers them; a Slack-shaped one would be wrong for everything
// else and would still be a webhook underneath.

const SECRET_ID = 'webhook.alert.url'

// A single alert is small and the endpoint is usually nearby. Ten seconds is
// long enough for a slow relay and short enough that a hung endpoint cannot
// pile up deliveries behind it.
const TIMEOUT_MS = 10_000

// Retries cover a dropped connection or a momentary 5xx, not a wrong URL.
const MAX_ATTEMPTS = 3
const RETRY_DELAYS_MS = [1_000, 4_000]

// A ceiling, not a cadence. Fifteen hosts failing at once is fifteen messages
// worth sending; a flapping unit on a loop is not, and the per-alert repeat
// window upstream already handles the common case. This is the backstop that
// keeps a bug in that logic from turning into a thousand POSTs.
const RATE_LIMIT = 30
const RATE_WINDOW_MS = 60_000

let enabled = false
let notifyOnResolved = true
let sentTimes: number[] = []
const status: WebhookDeliveryStatus = { dropped: 0 }

export function webhookConfigure(cfg: { enabled: boolean; notifyOnResolved: boolean }): WebhookConfig {
  enabled = cfg.enabled
  notifyOnResolved = cfg.notifyOnResolved
  return webhookStatus()
}

export function webhookStatus(): WebhookConfig {
  return { enabled, hasUrl: getSecret(SECRET_ID) !== null, notifyOnResolved }
}

export function webhookDeliveryStatus(): WebhookDeliveryStatus {
  return { ...status }
}

/** Stores the URL, or clears it when given an empty string. */
export function webhookSetUrl(raw: string): { ok: boolean; error?: string } {
  if (raw.trim() === '') {
    deleteSecret(SECRET_ID)
    // Clearing the URL turns the feature off, rather than leaving `enabled`
    // true with nothing to send to. The settings pane cannot switch it on
    // without a URL, so it had no way back to this state on its own — but
    // removing a URL from an already-enabled webhook reached it, and the pane
    // then showed the switch ON while every alert was dropped on the floor.
    enabled = false
    return { ok: true }
  }
  const v = validateWebhookUrl(raw)
  if (!v.ok) return { ok: false, error: v.error }
  return setSecret(SECRET_ID, v.url)
    ? { ok: true }
    : { ok: false, error: 'Could not store the URL — OS encryption is unavailable.' }
}

function allowedByRateLimit(now: number): boolean {
  sentTimes = sentTimes.filter((t) => now - t < RATE_WINDOW_MS)
  if (sentTimes.length >= RATE_LIMIT) {
    status.dropped++
    return false
  }
  sentTimes.push(now)
  return true
}

// Everything that crosses the IPC boundary is rebuilt here, field by field.
//
// AlertPayload is a TypeScript type, which means it constrains the renderer's
// source and nothing at runtime: `webhook:notify` receives a deserialised
// object and used to hand it straight to JSON.stringify. That gave anything
// running in the renderer an arbitrary-JSON-to-arbitrary-URL primitive from
// the main process — a hole straight through the CSP that is the only reason a
// renderer compromise is survivable at all.
//
// It also bounds host-controlled text. `units` are systemd unit names scraped
// from a machine that may itself be compromised; a unit named `<!channel>`
// posts a workspace-wide ping into someone's incident channel on a loop, from
// an integration they trust.
const LITERAL = {
  event: ['raised', 'resolved'],
  kind: ['cpu', 'memory', 'unit-failed']
} as const

const MAX_TEXT = 200
const MAX_UNITS = 20
const MAX_UNIT_NAME = 128

const text = (v: unknown, max = MAX_TEXT): string =>
  typeof v === 'string' ? v.slice(0, max) : ''

const num = (v: unknown): number | undefined => {
  const n = Number(v)
  return Number.isFinite(n) ? n : undefined
}

export function sanitisePayload(raw: unknown): AlertPayload | null {
  if (typeof raw !== 'object' || raw === null) return null
  const r = raw as Record<string, unknown>

  const event = LITERAL.event.find((e) => e === r.event)
  const kind = LITERAL.kind.find((k) => k === r.kind)
  if (!event || !kind) return null

  const out: AlertPayload = {
    source: 'shellpilot',
    version: text(r.version, 32),
    event,
    kind,
    server: text(r.server),
    summary: text(r.summary),
    at: new Date().toISOString()
  }

  const value = num(r.value)
  const threshold = num(r.threshold)
  const minutes = num(r.minutes)
  if (value !== undefined) out.value = value
  if (threshold !== undefined) out.threshold = threshold
  if (minutes !== undefined) out.minutes = minutes

  if (Array.isArray(r.units)) {
    out.units = r.units
      .slice(0, MAX_UNITS)
      // A unit name is [A-Za-z0-9._@:-] plus the `\x2d` escapes systemd uses.
      // Anything else is not a unit name, whatever the host claims.
      .map((u) => text(u, MAX_UNIT_NAME).replace(/[^A-Za-z0-9._@:\-\\]/g, ''))
      // `@` has to stay in the class for template units (`getty@tty1.service`),
      // but a name that STARTS with it is not one. systemd agrees: it loads
      // `getty@tty1.service` and rejects `@everyone.service` as "neither a
      // valid invocation ID nor unit name" — the prefix before `@` cannot be
      // empty. So dropping a leading `@` costs no real unit name.
      //
      // What it buys is the other half of the threat above. `<!channel>` is
      // Slack's mass ping and the character class already removes it; Discord's
      // is the literal text `@everyone`, which is all name characters and
      // survived. Same attack — a unit name on a host we do not trust becoming
      // a mass ping in a channel that trusts this integration — so it gets the
      // same answer.
      .map((u) => u.replace(/^@+/, ''))
      .filter((u) => u.length > 0)
  }
  return out
}

async function post(url: string, payload: AlertPayload): Promise<WebhookTestResult> {
  let lastError = 'unknown error'

  for (let attempt = 0; attempt < MAX_ATTEMPTS; attempt++) {
    const ac = new AbortController()
    const timer = setTimeout(() => ac.abort(), TIMEOUT_MS)
    try {
      const res = await fetch(url, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify(payload),
        // Do NOT follow redirects.
        //
        // validateWebhookUrl runs once, on the string the user typed. With
        // redirects followed, the ENDPOINT then chooses where the request
        // actually lands — a 308 to http://10.0.0.5/ puts this payload on a
        // cleartext hop to an internal host, from a process sitting inside the
        // user's network and possibly behind a VPN the app itself raised. That
        // makes both the https rule and the loopback-only-http rule advisory.
        //
        // Every real receiver — Slack, Discord, Teams, PagerDuty, Alertmanager
        // — answers 2xx directly. None needs a redirect.
        redirect: 'manual',
        signal: ac.signal
      })
      // A 3xx here is `redirect: 'manual'` refusing to follow, not success.
      if (res.status >= 300 && res.status < 400) {
        return {
          ok: false,
          status: res.status,
          error: `The endpoint redirected (HTTP ${res.status}). Point the webhook at its final URL — redirects are not followed, because the destination could be an internal or cleartext host.`
        }
      }
      // Deliberate: the response body is never read. That is what keeps a
      // hostile or mistyped endpoint from becoming a read primitive into the
      // user's network. Do not "improve" this by surfacing the body.
      if (res.ok) return { ok: true, status: res.status }

      // 4xx means the request is wrong and will be wrong again — a revoked
      // Slack hook, a bad path. Retrying it just delays the truth. 408 and 429
      // are the exceptions: both mean "later", not "no".
      const retryable = res.status >= 500 || res.status === 429 || res.status === 408
      lastError = `HTTP ${res.status}`
      if (!retryable) return { ok: false, status: res.status, error: lastError }
    } catch (err) {
      lastError = err instanceof Error ? err.message : String(err)
    } finally {
      clearTimeout(timer)
    }

    const delay = RETRY_DELAYS_MS[attempt]
    if (delay !== undefined) await new Promise((r) => setTimeout(r, delay))
  }
  return { ok: false, error: lastError }
}

/**
 * Fire-and-forget. Never awaited by a caller on the alert path: a slow endpoint
 * must not hold up the desktop notification, the status-bar chip, or the next
 * sample. Failures are recorded on `status` rather than thrown at a caller that
 * has nothing useful to do with them.
 */
export function webhookNotify(raw: unknown): void {
  if (!enabled) return
  // Rebuilt from a whitelist, never forwarded as received. See sanitisePayload.
  const payload = sanitisePayload(raw)
  if (!payload) return
  if (payload.event === 'resolved' && !notifyOnResolved) return
  const url = getSecret(SECRET_ID)
  if (!url) {
    // webhookSetUrl disables the feature when the URL is cleared, so this is
    // unreachable through the UI. It is still recorded rather than returned
    // silently: the one thing an alerting path must never do is discard
    // without saying so, and if some path ever does reach here the settings
    // pane says why instead of showing a healthy, empty panel.
    status.lastError = 'No webhook URL is set, so the alert was not sent.'
    return
  }
  if (!allowedByRateLimit(Date.now())) return

  void post(url, payload).then((r) => {
    if (r.ok) {
      status.lastSentAt = Date.now()
      status.lastError = undefined
    } else {
      status.lastError = r.error
    }
  })
}

/** Sends a sample payload and reports what happened, for the settings screen. */
export async function webhookTest(): Promise<WebhookTestResult> {
  const url = getSecret(SECRET_ID)
  if (!url) return { ok: false, error: 'No webhook URL is set.' }
  return post(url, {
    source: 'shellpilot',
    version: app.getVersion(),
    event: 'raised',
    kind: 'cpu',
    server: 'Test server',
    summary: 'Test alert from ShellPilot. Nothing is wrong.',
    at: new Date().toISOString(),
    value: 91,
    threshold: 80
  })
}

export function webhookResetForTests(): void {
  enabled = false
  notifyOnResolved = true
  sentTimes = []
  status.dropped = 0
  status.lastError = undefined
  status.lastSentAt = undefined
}
