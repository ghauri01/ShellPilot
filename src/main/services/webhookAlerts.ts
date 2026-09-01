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
        signal: ac.signal
      })
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
export function webhookNotify(payload: AlertPayload): void {
  if (!enabled) return
  if (payload.event === 'resolved' && !notifyOnResolved) return
  const url = getSecret(SECRET_ID)
  if (!url) return
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
