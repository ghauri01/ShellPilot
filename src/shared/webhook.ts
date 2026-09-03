// Outbound alert delivery.
//
// This is the first outbound network call ShellPilot makes to an endpoint the
// user chooses, which makes the payload a security decision rather than a
// formatting one. An alert naming a host and a unit is useful; an alert
// carrying a log line carries whatever was in that log line to a third-party
// API, and secretRedaction.ts exists because that is easy to get wrong.
//
// So the payload is a fixed, whitelisted shape. Nothing is passed through from
// a command, a log, or a file — every field below is either a constant, a
// number, or a name the user typed themselves.

export type AlertEvent = 'raised' | 'resolved'

/**
 * Every kind that may leave the machine, as a value rather than only a type.
 *
 * The main-process sanitiser rebuilds the payload from a whitelist, and that
 * whitelist used to be a second, hand-written copy of this list. A kind added
 * here and not there was dropped in main with nothing recorded — the alert did
 * not arrive and the settings pane still showed a healthy webhook. One array,
 * consumed by both, is the only version of this that cannot drift.
 */
export const ALERT_KINDS = ['cpu', 'memory', 'disk', 'unit-failed'] as const
export type AlertKind = (typeof ALERT_KINDS)[number]

export interface AlertPayload {
  // Lets a shared endpoint tell ShellPilot's posts from anything else's.
  source: 'shellpilot'
  version: string
  event: AlertEvent
  kind: AlertKind
  // The FRIENDLY name, never the host or IP.
  //
  // Not squeamishness: docs/AI-SECURITY.md makes "an agent never receives a
  // real host, IP or username" a property of the product, and a webhook is a
  // far easier way to leak an estate's addressing than the MCP bridge ever
  // was. The friendly name is what a person needs to act, and it is a name
  // they chose.
  server: string
  // One line, safe to render anywhere. Built from the fields below, never
  // from remote output.
  summary: string
  at: string
  // Present for cpu and memory.
  value?: number
  threshold?: number
  // How long it has been in this state, when known.
  minutes?: number
  // Present for unit-failed: systemd unit NAMES only.
  //
  // Not descriptions, and not journal output. A name is enough to act on, and
  // everything past the name is text the host chose rather than text we did.
  units?: string[]
}

export interface WebhookConfig {
  enabled: boolean
  // Stored via safeStorage, never in settings: a webhook URL is a bearer
  // credential — anyone holding a Slack one can post as you — so it belongs
  // with the other secrets and not in a JSON file or a backup blob.
  hasUrl: boolean
  // Send the "back to normal" message too. On by default: an alert with no
  // resolution leaves the reader to work out whether it is still happening.
  notifyOnResolved: boolean
}

export interface WebhookTestResult {
  ok: boolean
  status?: number
  error?: string
}

export interface WebhookDeliveryStatus {
  // Deliveries dropped by the rate limiter since launch. Surfaced rather than
  // hidden: an alerting path that silently discards is worse than one that
  // does not exist, because it is trusted.
  dropped: number
  lastError?: string
  lastSentAt?: number
}

// A URL is rejected outright rather than tried and failed, so a typo is caught
// while someone is looking at the settings rather than during an incident.
export function validateWebhookUrl(raw: string): { ok: true; url: string } | { ok: false; error: string } {
  let u: URL
  try {
    u = new URL(raw.trim())
  } catch {
    return { ok: false, error: 'That is not a valid URL.' }
  }
  const loopback = u.hostname === 'localhost' || u.hostname === '127.0.0.1' || u.hostname === '::1'
  if (u.protocol === 'https:') return { ok: true, url: u.toString() }
  // Plain http is allowed only to loopback, where nothing transits a network.
  // Everywhere else it would put a bearer credential on the wire in clear, and
  // this URL is a bearer credential.
  if (u.protocol === 'http:' && loopback) return { ok: true, url: u.toString() }
  if (u.protocol === 'http:') {
    return { ok: false, error: 'Use https. The webhook URL is a credential and http would send it in clear.' }
  }
  return { ok: false, error: `Unsupported scheme "${u.protocol.replace(':', '')}". Use https.` }
}
