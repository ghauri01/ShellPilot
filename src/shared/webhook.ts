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
export const ALERT_KINDS = [
  'cpu',
  'memory',
  'disk',
  'unit-failed',
  'inode',
  'load',
  'host-unreachable',
  'job-failed',
  'tunnel-down',
  'db-alarm',
  'db-watch'
] as const
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
  // Set on the one raise that trips flap damping — see store/alerts.ts.
  //
  // The endpoint needs this more than the desktop does. A person who stops
  // getting notifications about a host still has the app in front of them; an
  // endpoint that stops receiving has no way to tell a damped alert from a
  // ShellPilot that died, and "we went quiet on purpose, here is when we will
  // speak again" is the difference between a working integration and a silent
  // one.
  damped?: boolean
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

// ---------------------------------------------------------------------------
// The durable side of an alert.
//
// Everything the alert store remembered used to be a module-level Map in the
// renderer, so it died with the window. The visible cost was a chronically full
// disk: its repeat window is six hours, but the window was empty at every
// launch, so the same 91% announced itself once per app start forever — and the
// first thing a person does about an alert they cannot action is mute the
// feature.
//
// So the raise/resolve decisions are written to the history store (item A) and
// read back at startup. These types are here rather than beside the store
// because BOTH processes need them: the renderer decides and the main process
// writes, and the row is rebuilt from a whitelist on the way in exactly like
// the webhook payload is. A row that reaches the inbox is rendered, and prose
// assembled on a host we do not control has no business being rendered.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// The kinds as the ALERT STORE names them, which is not quite the wire's list.
//
// `ram` is `memory` on the wire — a name chosen before the webhook existed and
// not worth a migration — and `unit-failed` has no store entry because failed
// units are tracked as a SET of unit names rather than a threshold crossing.
// The mapping between the two lives in store/alerts.ts as a total Record, so a
// kind added to one list and not the other is a type error rather than an alert
// that posts under the wrong name.
//
// They are three lists rather than one because the kinds do not behave alike,
// and the store has a different code path for each shape. STORE_ALERT_KINDS is
// their concatenation and stays the single list every whitelist consumes.
// ---------------------------------------------------------------------------

/** Kinds that are a number against a line. Hysteresis, escalation and a
 *  recovery margin all mean something for these and nothing for the rest. */
export const NUMERIC_ALERT_KINDS = ['cpu', 'ram', 'disk', 'inode', 'load'] as const
export type NumericAlertKind = (typeof NUMERIC_ALERT_KINDS)[number]

/**
 * Kinds that are a state rather than a reading.
 *
 * Split from the numeric ones rather than folded in with a synthetic value of
 * 1, because every per-kind table the numeric path owns — recovery margin,
 * escalation step, the unit a number is printed in — would then have to hold an
 * answer for a question the kind does not ask, and "1 per core" is not an
 * answer, it is a placeholder that reads as a measurement.
 */
export const STATE_ALERT_KINDS = ['host-unreachable', 'job-failed', 'tunnel-down'] as const
export type StateAlertKind = (typeof STATE_ALERT_KINDS)[number]

/**
 * Kinds that are neither: something happened, once.
 *
 * Item 18's database verdicts. `notableDbEvents` records `alarm` and `watch`
 * and deliberately does NOT record `ok` — an ok every sixty seconds is a log
 * nobody reads and a table that grows forever — so there is no row anywhere
 * that could tell us a database recovered. A kind that cannot observe its own
 * recovery must not pretend to hold a condition: it raises, it is recorded, and
 * it never carries a status-bar chip that only a restart could clear.
 */
export const EVENT_ALERT_KINDS = ['db-alarm', 'db-watch'] as const
export type EventAlertKind = (typeof EVENT_ALERT_KINDS)[number]

export const STORE_ALERT_KINDS = [
  ...NUMERIC_ALERT_KINDS,
  ...STATE_ALERT_KINDS,
  ...EVENT_ALERT_KINDS
] as const
export type StoreAlertKind = (typeof STORE_ALERT_KINDS)[number]

/** The history-store event kind every alert row is written under. One kind, so
 *  the whole log is one `readEvents({ kind })` — a named statement, not a new
 *  query surface. The `event` field below discriminates. */
export const ALERT_HISTORY_KIND = 'alert'

/**
 * What a stored row records, which is one more thing than the wire carries.
 *
 * `stood-down` is not an all-clear and is never posted anywhere: it is the row
 * written when alerting is switched OFF while something was outstanding. It has
 * to be distinguishable from a resolve, because the two mean opposite things to
 * whoever reads the log back — a resolve leaves the repeat window standing (a
 * re-cross seconds later must not read as news), and a stand-down ends the
 * conversation entirely, so the next crossing speaks at once.
 */
export type StoredAlertEventName = AlertEvent | 'stood-down'

export const STORED_ALERT_EVENTS = ['raised', 'resolved', 'stood-down'] as const

export interface StoredAlertEvent {
  event: StoredAlertEventName
  kind: StoreAlertKind
  /** The server's id, so the row can be filtered per host. */
  serverId: string
  /** The FRIENDLY name, for the same reason AlertPayload carries it. */
  serverName: string
  value?: number
  threshold?: number
  /**
   * What the alert is ABOUT, when the kind has no number to say it with.
   *
   * A tunnel's name, a job step, the database question that went into alarm.
   * The numeric kinds say what they are about with `value` and `threshold`; a
   * state or event kind that carried neither would reach the inbox as "Job
   * failed" against a host and nothing else, which is a row nobody can act on.
   *
   * Scrubbed on the way in exactly like `serverName`, and for a stronger
   * reason: `serverName` is a name the user typed, while a database question id
   * and a job step name are ours but pass through a report. Neither is remote
   * output today and neither is allowed to become it.
   */
  detail?: string
}

/** A row as it comes back out, with the store's own timestamp. */
export interface StoredAlertRow extends StoredAlertEvent {
  at: number
}

const MAX_NAME = 200

/**
 * Rebuild a row from a whitelist, or refuse it.
 *
 * Same shape and same reasoning as `sanitisePayload` in webhookAlerts.ts: an
 * unknown `kind` or `event` is dropped rather than stored, because the inbox
 * renders these and a row is only as trustworthy as the narrowest thing that
 * produced it.
 */
export function sanitiseStoredAlert(raw: unknown): StoredAlertEvent | null {
  if (typeof raw !== 'object' || raw === null) return null
  const r = raw as Record<string, unknown>
  const event = STORED_ALERT_EVENTS.find((e) => e === r.event)
  const kind = STORE_ALERT_KINDS.find((k) => k === r.kind)
  if (!event || !kind) return null
  if (typeof r.serverId !== 'string' || r.serverId === '') return null
  const out: StoredAlertEvent = {
    event,
    kind,
    serverId: r.serverId.slice(0, MAX_NAME),
    serverName: typeof r.serverName === 'string' ? r.serverName.slice(0, MAX_NAME) : ''
  }
  // A value of 0 is a real reading and must survive; only a non-finite one is
  // dropped. `undefined` here means "this kind has no number", which is not the
  // same as zero — the rule the whole of 19a is built on.
  if (typeof r.value === 'number' && Number.isFinite(r.value)) out.value = r.value
  if (typeof r.threshold === 'number' && Number.isFinite(r.threshold)) out.threshold = r.threshold
  // Same character class the store scrubs a name to, applied again here. The
  // store is the only writer today; the whitelist is what makes that a fact
  // about the DATA rather than a fact about the current call sites.
  if (typeof r.detail === 'string') {
    const detail = r.detail.slice(0, MAX_NAME).replace(/[^A-Za-z0-9 ._@:-]/g, '').trim()
    if (detail !== '') out.detail = detail
  }
  return out
}
