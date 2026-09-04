import type { ApprovalVerdict, BroadcastConfirmation, CommandApproval, JobPlan, JobSpec, JobTargetRef } from './jobs'
import { planJob, verifyJobApproval } from './jobs'
import { ALERT_KINDS, STORE_ALERT_KINDS, STORED_ALERT_EVENTS } from './webhook'
import type { AlertKind, StoreAlertKind, StoredAlertRow } from './webhook'

// The rule engine — roadmap item 27.
//
// "When this alert fires, run that job, then call that webhook."
//
// THREE CLAUSES AND NO MORE: on event, matching filter, run action, with a rate
// limit. The roadmap is explicit that anything past that is someone else's
// product, so there is no expression language here, no branching, no loops, no
// variables and no way for one rule to start another. Every field below is
// either a value from a closed list or a number, and the whole of `ruleMatches`
// is four comparisons. If a future requirement cannot be written with those
// four, the answer is a second rule, not a fifth clause.
//
// ===========================================================================
// THE DANGEROUS PART IS NOT THE MATCHING
// ===========================================================================
//
// A rule that runs a job is a STANDING AUTHORISATION to run commands on hosts,
// created once and fired unattended forever. Every other execution path in this
// app is authorised per run, by a human, at the moment of running: `planJob`
// sizes the confirmation by risk and blast radius, `jobApprovalFor` mints a
// record at the instant the dialog is answered, and `verifyJobApproval`
// re-derives that plan and compares it at launch AND again at resume.
//
// The decision, written out because it is the whole of what makes this
// shippable:
//
//   A RULE MAY ONLY RUN THE JOB THAT WAS APPROVED WHEN THE RULE WAS WRITTEN —
//   THAT SPEC, THOSE HOSTS — AND ANY DRIFT REFUSES.
//
// Concretely: a job rule carries a `CommandApproval` minted by
// `jobApprovalFor` over a FIXED spec and a FIXED target list, at the moment a
// human satisfied the dialog. Every firing re-runs `verifyJobApproval` against
// that same stored pair. Nothing about the triggering event reaches the job:
// the event decides WHETHER, never WHERE and never WHAT. There is no
// substitution, no template, and no "run it on the host the alert names" —
// because a rule whose target list is chosen by an event has a blast radius
// that is only knowable at 3am, and the property this item has to keep is that
//
//   THE BLAST RADIUS OF A RULE IS KNOWABLE WHEN IT IS WRITTEN.
//
// The three drifts `verifyJobApproval` already catches are exactly the three
// that a standing authorisation suffers from, and it catches them for free:
//
//   * THE COMMAND WAS EDITED. Editing a rule's steps under its stored approval
//     is the whole attack, and the record holds the step text.
//   * A TARGET WAS ADDED. Consent was given for a radius; a rule that quietly
//     grows one is the accident the model exists to prevent. (A SHRUNK list is
//     allowed by `verifyApproval` — but only while the re-derived confirmation
//     still matches, so a rule that lost hosts until it needed a weaker
//     confirmation than the human gave still refuses.)
//   * THE CLASSIFIER GOT STRICTER. This is the one that matters most here and
//     nowhere else. A job runs minutes after it was approved; a rule can fire
//     for the first time a year and four releases later. `assessCommand` is
//     deliberately tightened over time — `sudo -n reboot` used to read
//     `elevated` and now reads `destructive` — and a rule minted under the old
//     reading must not keep running under the new one on a confirmation nobody
//     would give today.
//
// The two options not taken, and why:
//
//   * A FIXED ALLOW-LIST OF SAFE SHAPES ("restart a unit", "clear a log"). It
//     sounds safer and is not: it means a second risk model beside
//     `assessCommand`, written by whoever adds the fifth shape, and the first
//     argument about whether `systemctl restart` of a database is a safe shape
//     is an argument this app already knows how to answer with a confirmation
//     dialog. A second copy of a safety rule is a second thing to drift.
//   * STAGE A JOB A HUMAN STILL CONFIRMS. Honest, and not automation — the
//     roadmap item is "when this alert fires, run that job", and a feature that
//     answers it with a notification is a feature that was not built. It is
//     also strictly worse than the alert inbox that already exists.
//
// What is given up by pinning the targets is real and should be said plainly:
// "when ANY host's disk fills, clean that host up" cannot be written as one
// rule. It is written as one rule per host, and the list of rules is then
// literally the list of machines this app may touch unattended. That is the
// trade, and it is the right way round.
//
// ===========================================================================
// NOT AGENT-REACHABLE. EVER.
// ===========================================================================
//
// The job engine is not reachable from the MCP bridge because DURABILITY
// DEFEATS REVOCATION (see the header of shared/jobs.ts). A rule is the same
// argument raised one further: `denyAllPending()` resolves requests that are
// PENDING, and a rule sitting in a file with a year-old approval on it has
// nothing pending even when it is not running. Revoking every session, denying
// every outstanding approval and shutting the bridge down leaves the rule
// exactly where it was, and it fires at 3am regardless.
//
// So a rule is not gated, not asked-for, NOT THERE. See
// tests/rulesNotExposed.test.ts and tests/jobsNotExposed.test.ts.

// ---------------------------------------------------------------------------
// Clause one: on event
// ---------------------------------------------------------------------------

/**
 * The history-store kinds a rule may watch, DERIVED rather than listed.
 *
 * Events come from item A's store, and the ones a rule may act on are the alert
 * rows 19b writes — one history kind, `ALERT_HISTORY_KIND`, discriminated by
 * the `event` field on the payload. They are read back, never recomputed: a
 * rule that re-derived "is this disk critical" would be a second opinion able
 * to disagree with the inbox the operator is looking at, which is the mistake
 * the disk alert was careful not to make about `isDiskCritical`.
 *
 * Deliberately NOT "any history kind". The store also carries
 * `retention-skipped`, `job-gate`, `history-recovery` and a dozen other
 * bookkeeping strings that are internal names rather than a published
 * vocabulary; a rule keyed on one of those changes meaning the day somebody
 * renames a debug string, and nothing would go red. Every kind a rule can watch
 * is one the operator can already see in the alert inbox.
 *
 * The list is the INTERSECTION of the store's kinds and the wire's kinds, and
 * that is why `ram` is absent. The store calls it `ram`, the wire calls it
 * `memory`, and the map between the two is a private const inside
 * `src/renderer/src/store/alerts.ts`. Writing a second copy of that map here to
 * gain one kind would be a second thing to drift — the exact mistake
 * `ALERT_KINDS` was published as a value to end. So the list is computed from
 * the two published arrays, memory rules wait for the map to be published
 * alongside them, and until then this constant says out loud what is missing
 * instead of a whitelist quietly saying no to its own product.
 */
export type RuleAlertKind = StoreAlertKind & AlertKind

const isRuleAlertKind = (k: StoreAlertKind): k is RuleAlertKind =>
  (ALERT_KINDS as readonly string[]).includes(k)

export const RULE_ALERT_KINDS: readonly RuleAlertKind[] = STORE_ALERT_KINDS.filter(isRuleAlertKind)

/**
 * A rule's trigger kind is also its wire kind — by TYPE, not by promise.
 *
 * `RuleAlertKind` is the intersection of the two published unions, so this
 * function needs no cast and adding a kind to one list and not the other cannot
 * produce a rule that posts under a name the sanitiser drops. That is the whole
 * reason the intersection is taken at the type level as well as at runtime.
 */
export function ruleWireKind(kind: RuleAlertKind): AlertKind {
  return kind
}

/**
 * Which stored alert events a rule may trigger on.
 *
 * `raised` and `resolved` only. `snoozed`, `acknowledged` and `stood-down` are
 * decisions a human made ABOUT an alert, and a rule that ran a job because
 * somebody pressed snooze would be automation triggered by the act of asking
 * for quiet.
 */
export const RULE_TRIGGER_EVENTS = ['raised', 'resolved'] as const
export type RuleTriggerEvent = (typeof RULE_TRIGGER_EVENTS)[number]

export interface RuleTrigger {
  kind: RuleAlertKind
  event: RuleTriggerEvent
}

// ---------------------------------------------------------------------------
// Clause two: matching filter
// ---------------------------------------------------------------------------

/**
 * Two fields, and that is the whole filter.
 *
 * `serverId` absent means any host. `minValue` absent means the reading is not
 * looked at — and a row that HAS no reading never satisfies a `minValue`,
 * because a missing measurement is not a zero. That is the rule the whole of
 * 19a is built on and it is not weakened here to make a state kind filterable
 * by a number it does not have.
 */
export interface RuleFilter {
  serverId?: string
  minValue?: number
}

// ---------------------------------------------------------------------------
// Clause three: run action
// ---------------------------------------------------------------------------

/**
 * Run a job — the pinned one, and only it.
 *
 * `spec` and `targets` are stored beside the `approval` that covers them rather
 * than looked up by id, so there is no second place a rule's blast radius can
 * be edited from. See the header for why the event contributes nothing here.
 */
export interface RuleJobAction {
  type: 'job'
  spec: JobSpec
  targets: JobTargetRef[]
  /** Minted by `jobApprovalFor` at the moment the human satisfied the dialog. */
  approval: CommandApproval
}

/** Post to the configured webhook and stop. No credential of its own: delivery
 *  is `webhookAlerts.ts`'s, whitelisted and rate-limited exactly as an alert
 *  is. */
export interface RuleNotifyAction {
  type: 'notify'
}

export type RuleAction = RuleJobAction | RuleNotifyAction

export const RULE_ACTION_TYPES = ['job', 'notify'] as const

// ---------------------------------------------------------------------------
// The rate limit
// ---------------------------------------------------------------------------

/**
 * A sliding window, per rule.
 *
 * Not decoration and not a backstop: it is the difference between a rule and an
 * outage. 19b learned this the expensive way and wrote it down — "a disk alert
 * that fires forty times overnight gets the whole feature muted" — and a rule
 * is worse than an alert in the same situation, because the forty things it
 * does are forty commands on a host rather than forty lines in a channel. A
 * unit in a restart loop produces a `job-failed` raise per sweep; a rule that
 * restarted it each time would be a restart loop with the app's name on it.
 *
 * Deliberately a WINDOW rather than a cooldown between firings. A cooldown of
 * ten minutes still allows six firings an hour forever; a window says how many
 * times this rule may act, full stop, and it is the number an operator can
 * reason about at the moment they write the rule.
 */
export interface RuleLimit {
  /** Most firings allowed inside `windowMs`. At least 1. */
  maxFirings: number
  windowMs: number
}

/**
 * Once an hour.
 *
 * The default is the conservative one on purpose. Somebody writing their first
 * rule is not thinking about the flapping case — that is the whole reason this
 * clause is mandatory rather than optional — so the value they get without
 * choosing is the one that cannot produce a storm, and widening it is a
 * decision they make with the consequence in front of them.
 */
export const RULE_LIMIT_DEFAULT: RuleLimit = { maxFirings: 1, windowMs: 3_600_000 }

/** A window shorter than this is not a rate limit, it is a formality. */
export const RULE_LIMIT_MIN_WINDOW_MS = 60_000
export const RULE_LIMIT_MAX_WINDOW_MS = 7 * 86_400_000
/** A ceiling on the ceiling. Sixty firings inside one window is already past
 *  anything a person is supervising. */
export const RULE_LIMIT_MAX_FIRINGS = 60

export function clampRuleLimit(raw: Partial<RuleLimit> | undefined): RuleLimit {
  const maxFirings = Number(raw?.maxFirings)
  const windowMs = Number(raw?.windowMs)
  return {
    maxFirings: Number.isFinite(maxFirings)
      ? Math.max(1, Math.min(RULE_LIMIT_MAX_FIRINGS, Math.floor(maxFirings)))
      : RULE_LIMIT_DEFAULT.maxFirings,
    windowMs: Number.isFinite(windowMs)
      ? Math.max(RULE_LIMIT_MIN_WINDOW_MS, Math.min(RULE_LIMIT_MAX_WINDOW_MS, Math.floor(windowMs)))
      : RULE_LIMIT_DEFAULT.windowMs
  }
}

export interface RuleLimitVerdict {
  allowed: boolean
  /** The firing timestamps still inside the window, with `at` appended when it
   *  was allowed. The caller persists this and hands it back next time. */
  fired: number[]
  /** When the window next has room, for a panel that has to explain a
   *  suppression rather than merely perform one. Null when allowed. */
  nextAllowedAt: number | null
}

/**
 * Pure, and given its clock rather than reading one.
 *
 * Everything that decides whether a command runs on somebody's estate is
 * testable without a timer, for the reason three flaky tests in this repo
 * turned out to be real production bugs.
 */
export function checkRuleLimit(
  fired: readonly number[],
  at: number,
  limit: RuleLimit
): RuleLimitVerdict {
  // A firing timestamp in the FUTURE is kept rather than discarded. It means
  // the clock moved backwards, and dropping it would let a rule fire its whole
  // window's worth again the moment somebody's NTP corrected a drifting host.
  const recent = fired.filter((t) => at - t < limit.windowMs).sort((a, b) => a - b)
  if (recent.length >= limit.maxFirings) {
    // The oldest firing in the window is the one whose expiry makes room.
    return { allowed: false, fired: recent, nextAllowedAt: recent[0] + limit.windowMs }
  }
  return { allowed: true, fired: [...recent, at], nextAllowedAt: null }
}

// ---------------------------------------------------------------------------
// The rule
// ---------------------------------------------------------------------------

export interface Rule {
  id: string
  /** What the user called it. Shown on screen and in the notification; never
   *  parsed. */
  name: string
  enabled: boolean
  trigger: RuleTrigger
  filter: RuleFilter
  action: RuleAction
  limit: RuleLimit
  /**
   * The moment this rule became live, and the reason a rule cannot fire on the
   * backlog.
   *
   * Set when the rule is created and RESET every time it is enabled. Both
   * halves matter. Without the first, a rule written this afternoon would fire
   * on last month's alerts the first time the engine swept. Without the second,
   * switching a rule off for a fortnight and back on would replay the fortnight
   * — which is the opposite of what "off" meant to the person who pressed it,
   * and would make disabling a rule the most dangerous button on the panel.
   */
  armedAt: number
}

/** Why a rule stopped being able to act, kept beside it so the panel can say
 *  so rather than showing a rule that looks armed and is not. */
export interface RuleStatus {
  ruleId: string
  /** Firing timestamps inside the current window. */
  fired: number[]
  lastFiredAt?: number
  /** How many matching events this rule declined to act on because of the rate
   *  limit. Counted and shown, never silently dropped — see
   *  `WebhookDeliveryStatus.dropped` for the same argument. */
  suppressed: number
  /** The refusal from the last time the approval did not verify. Present means
   *  the rule is refusing every firing until it is confirmed again. */
  refusal?: string
  refusedAt?: number
}

// ---------------------------------------------------------------------------
// Matching — the whole of clause one and two, in four comparisons
// ---------------------------------------------------------------------------

/**
 * Does this stored alert row fire this rule?
 *
 * `at > armedAt` is STRICT. A rule is answerable for what happens after it was
 * written, and the store puts two events in the same millisecond routinely, so
 * the boundary has to fall on one side deliberately rather than by accident.
 */
export function ruleMatches(rule: Rule, row: StoredAlertRow): boolean {
  if (!rule.enabled) return false
  if (!(row.at > rule.armedAt)) return false
  if (row.kind !== rule.trigger.kind) return false
  if (row.event !== rule.trigger.event) return false
  if (rule.filter.serverId !== undefined && row.serverId !== rule.filter.serverId) return false
  if (rule.filter.minValue !== undefined) {
    // A row with no reading never satisfies a threshold. `undefined` is "this
    // kind has no number", which is not zero.
    if (typeof row.value !== 'number') return false
    if (row.value < rule.filter.minValue) return false
  }
  return true
}

// ---------------------------------------------------------------------------
// The authorisation
// ---------------------------------------------------------------------------

/**
 * The plan a job rule was written against — risk, confirmation, blast radius.
 *
 * Re-derived rather than stored, which is the point: this is what the panel
 * prints when the rule is written AND what the engine compares against when it
 * fires, so the two can never be different numbers.
 */
export function ruleJobPlan(pinned: { spec: JobSpec; targets: JobTargetRef[] }): JobPlan {
  return planJob(pinned.spec, pinned.targets)
}

/**
 * Is this rule still authorised to run what it says it runs?
 *
 * A non-job action is always ok — a notification carries no authority, so there
 * is nothing to verify and pretending otherwise would put a meaningless verdict
 * in front of a reader who then stops reading them.
 */
export function verifyRuleAction(rule: Rule): ApprovalVerdict {
  if (rule.action.type !== 'job') return { ok: true }
  return verifyJobApproval(rule.action.approval, rule.action.spec, rule.action.targets)
}

/**
 * What a human must do to create a job rule, and it is not what `planJob` says.
 *
 * `planJob` sizes a confirmation for ONE run that a person is watching. A rule
 * is a different thing being agreed to: the same commands, on the same hosts,
 * an unbounded number of times, while nobody is looking. An ordinary command on
 * two hosts needs no confirmation at all as a job; as a standing authorisation
 * it needs somebody to have noticed what they were agreeing to.
 *
 * So the creation gate is ALWAYS type-to-confirm, with its own word. The word
 * is `UNATTENDED` rather than the job path's `RUN` deliberately — it is the
 * fact about this dialog that is not true of the other one, and a person typing
 * it has read it.
 *
 * This is a gate on WRITING the rule and is emphatically NOT folded into the
 * stored `CommandApproval`: that record has to keep verifying against a fresh
 * `planJob` at every firing, and a record carrying an escalated confirmation
 * would disagree with its own re-derivation and refuse forever.
 */
export const RULE_UNATTENDED_PHRASE = 'UNATTENDED'

export function ruleCreationConfirmation(type: RuleAction['type']): BroadcastConfirmation {
  if (type !== 'job') return { kind: 'confirm' }
  return { kind: 'type-to-confirm', phrase: RULE_UNATTENDED_PHRASE }
}

// ---------------------------------------------------------------------------
// The notification a rule sends
// ---------------------------------------------------------------------------

/**
 * What the endpoint is told when a rule acts, and why it is not the alert
 * again.
 *
 * 19b already posts every raise and resolve. Re-posting the row that fired a
 * rule would be the same message twice and would teach people to filter it. The
 * thing nothing else says is THAT THE AUTOMATION RAN — so `summary` names the
 * rule and what it did, while `kind`, `server`, `value` and `threshold` are
 * carried from the row so an endpoint can still route it.
 *
 * Built as a plain object and handed to `webhookNotify`, which rebuilds it from
 * its own whitelist. Nothing here is trusted on the way out: this function's
 * job is to say the right thing, and `sanitisePayload`'s is to make sure only a
 * fixed shape ever leaves the machine. Both, not either.
 */
export interface RuleNotice {
  event: 'raised'
  kind: AlertKind
  server: string
  summary: string
  value?: number
  threshold?: number
}

/** What the rule did, in the words the notification uses. */
export type RuleOutcome = 'notified' | 'job-started' | 'job-refused'

const OUTCOME_WORDS: Record<RuleOutcome, string> = {
  notified: 'matched',
  'job-started': 'started',
  'job-refused': 'refused to start'
}

export function ruleNotice(rule: Rule, row: StoredAlertRow, outcome: RuleOutcome): RuleNotice {
  const what =
    rule.action.type === 'job'
      ? `${OUTCOME_WORDS[outcome]} the job "${rule.action.spec.title}" on ${rule.action.targets.length} server(s)`
      : OUTCOME_WORDS[outcome]
  const notice: RuleNotice = {
    event: 'raised',
    kind: ruleWireKind(rule.trigger.kind),
    server: row.serverName,
    // Our words, the rule's name and the job's title — all typed by the user —
    // plus a kind from a closed list. No remote output reaches this string, for
    // the reason written at the top of shared/webhook.ts.
    summary: `ShellPilot rule "${rule.name}" ${what} after a ${rule.trigger.kind} alert ${rule.trigger.event}.`
  }
  if (typeof row.value === 'number') notice.value = row.value
  if (typeof row.threshold === 'number') notice.threshold = row.threshold
  return notice
}

// ---------------------------------------------------------------------------
// Reading a rule back off disk
// ---------------------------------------------------------------------------

const MAX_NAME = 120
const MAX_RULES = 200

/**
 * Rebuild a rule from a whitelist, or refuse it.
 *
 * The rules file is not a trusted input — the same argument `updatePrefs.ts`
 * makes about its own, and a stronger one, because these fields decide what
 * runs on somebody's servers. It survives downgrades, hand edits and
 * half-written upgrades. Every field is narrowed back to something the rest of
 * the code has a branch for, rather than trusted because the file parsed.
 *
 * The approval is NOT rebuilt field by field here: `verifyJobApproval` is the
 * one thing that decides whether a record is usable, `isCommandApproval` is its
 * gate, and a second narrowing pass in this file would be a second opinion
 * about what a valid approval looks like. It is carried through as it was read
 * and refused at the moment it is used.
 */
export function sanitiseRule(raw: unknown): Rule | null {
  if (typeof raw !== 'object' || raw === null) return null
  const r = raw as Record<string, unknown>
  if (typeof r.id !== 'string' || r.id === '') return null

  const trig = typeof r.trigger === 'object' && r.trigger !== null ? (r.trigger as Record<string, unknown>) : null
  const kind = RULE_ALERT_KINDS.find((k) => k === trig?.kind)
  const event = RULE_TRIGGER_EVENTS.find((e) => e === trig?.event)
  if (!kind || !event) return null
  // Cross-check against the stored-event vocabulary too. RULE_TRIGGER_EVENTS is
  // a subset of it by intent, and a divergence would mean a rule triggering on
  // a name no row is ever written under — a rule that looks armed and is inert.
  if (!(STORED_ALERT_EVENTS as readonly string[]).includes(event)) return null

  const act = typeof r.action === 'object' && r.action !== null ? (r.action as Record<string, unknown>) : null
  let action: RuleAction
  if (act?.type === 'job') {
    if (typeof act.spec !== 'object' || act.spec === null) return null
    if (!Array.isArray(act.targets) || act.targets.length === 0) return null
    const spec = act.spec as JobSpec
    if (!Array.isArray(spec.steps) || spec.steps.length === 0) return null
    if (spec.steps.some((s) => typeof s?.command !== 'string' || s.command === '')) return null
    const targets: JobTargetRef[] = []
    for (const t of act.targets as Record<string, unknown>[]) {
      if (typeof t?.serverId !== 'string' || t.serverId === '') return null
      targets.push({
        serverId: t.serverId,
        serverName: typeof t.serverName === 'string' ? t.serverName.slice(0, MAX_NAME) : '',
        ...(typeof t.cohort === 'string' ? { cohort: t.cohort } : {})
      })
    }
    action = { type: 'job', spec, targets, approval: act.approval as CommandApproval }
  } else if (act?.type === 'notify') {
    action = { type: 'notify' }
  } else {
    return null
  }

  const filterRaw =
    typeof r.filter === 'object' && r.filter !== null ? (r.filter as Record<string, unknown>) : {}
  const filter: RuleFilter = {}
  if (typeof filterRaw.serverId === 'string' && filterRaw.serverId !== '') {
    filter.serverId = filterRaw.serverId.slice(0, MAX_NAME)
  }
  if (typeof filterRaw.minValue === 'number' && Number.isFinite(filterRaw.minValue)) {
    filter.minValue = filterRaw.minValue
  }

  const armedAt = typeof r.armedAt === 'number' && Number.isFinite(r.armedAt) ? r.armedAt : 0
  return {
    id: r.id.slice(0, MAX_NAME),
    name: typeof r.name === 'string' ? r.name.slice(0, MAX_NAME) : '',
    // Absent reads as OFF, exactly as an absent module does. A rules file from
    // a half-written upgrade must not arm anything by omission.
    enabled: r.enabled === true,
    trigger: { kind, event },
    filter,
    action,
    limit: clampRuleLimit(r.limit as Partial<RuleLimit> | undefined),
    armedAt
  }
}

/** The whole file, narrowed. A rule that does not survive is dropped and the
 *  rest are kept: one corrupt entry must not disarm the other nine. */
export function sanitiseRules(raw: unknown): Rule[] {
  if (!Array.isArray(raw)) return []
  const out: Rule[] = []
  const seen = new Set<string>()
  for (const entry of raw.slice(0, MAX_RULES)) {
    const rule = sanitiseRule(entry)
    if (!rule || seen.has(rule.id)) continue
    seen.add(rule.id)
    out.push(rule)
  }
  return out
}

export const RULES_FILE = 'shellpilot-rules.json'

// ---------------------------------------------------------------------------
// What crosses the IPC boundary
// ---------------------------------------------------------------------------

export interface RuleVerdict {
  ok: boolean
  reason?: string
}

/** A rule as the panel sees it: the rule, its ledger, and a FRESHLY re-derived
 *  verdict on its authority. The verdict is not stored — a panel showing a
 *  cached "armed" against a record that has since drifted is the one thing this
 *  screen must never do. */
export interface RuleView extends Rule {
  status: RuleStatus
  verdict: RuleVerdict
}

/** What the panel sends to create one. No `id`, no `armedAt` and no `enabled`:
 *  a caller that could set those could arm a rule into the past, which is the
 *  one thing a rule must never be. Main fills all three. */
export interface RuleDraftWire {
  name: string
  trigger: RuleTrigger
  filter?: RuleFilter
  limit?: Partial<RuleLimit>
  action: RuleAction
}

/**
 * The four channels, annotated in both halves so main and the preload cannot
 * disagree — the argument written at `jobs:` in src/preload/index.ts.
 *
 * There is deliberately no `run` and no `test`. A button that fires a rule on
 * demand would be a way to run a pinned job without the dialog that pins it,
 * which is the whole authorisation model with a shortcut through it.
 */
export interface RulesBridge {
  list(): Promise<RuleView[]>
  create(draft: RuleDraftWire): Promise<RuleView | null>
  setEnabled(id: string, enabled: boolean): Promise<boolean>
  remove(id: string): Promise<boolean>
}

/**
 * How old an alert row may be and still fire a rule.
 *
 * A product rule first and a bound second, and it is worth having both ways
 * round in mind.
 *
 * The product rule: a rule does not act on an alert from six hours ago. By then
 * the condition has been dealt with or it has not, and either way running a
 * command about it NOW is worse than not — the operator has moved on, the host
 * may be mid-repair, and the automation would be arguing with a person. This is
 * the same instinct behind `armedAt`, applied to the engine rather than to the
 * rule.
 *
 * The bound: `readEvents` returns newest-first and pages backwards, so
 * "everything since the watermark" after a fortnight offline is unbounded work
 * with no way to start from the oldest end. Anchoring the older end to a fixed
 * window is what makes the read finite without inventing a forward cursor the
 * store does not have.
 */
export const RULE_STALE_EVENT_MS = 3_600_000

/**
 * The ceiling on one sweep's read, and it is a ceiling rather than the bound.
 *
 * `RULE_STALE_EVENT_MS` is the bound; this is what stops a pathological hour —
 * an estate raising two thousand alerts in sixty minutes — being loaded whole.
 * If it is reached the OLDEST rows inside the window are the ones that fall
 * out, and the engine writes `rule-suppressed`'s sibling row saying so, because
 * an automation path that discards without saying so is worse than one that
 * does not exist.
 */
export const RULE_SWEEP_MAX_EVENTS = 2000

/** One page of the alert log. Small enough that a quiet estate reads one page
 *  and stops; large enough that a busy hour is a handful of seeks. */
export const RULE_SWEEP_PAGE = 200

/** How often the engine sweeps. Alerts are written when they happen and a rule
 *  is not a real-time system: a minute is well inside every repeat window in
 *  store/alerts.ts and costs one indexed read. */
export const RULE_SWEEP_INTERVAL_MS = 60_000

/** The history-store kinds the engine writes. Named here so the panel and the
 *  tests read the same strings the engine writes. */
export const RULE_EVENT_FIRED = 'rule-fired'
export const RULE_EVENT_SUPPRESSED = 'rule-suppressed'
export const RULE_EVENT_REFUSED = 'rule-refused'
/** Written when a sweep hit RULE_SWEEP_MAX_EVENTS and rows inside the window
 *  went unread. Rare, and the one thing a rule engine must never do quietly. */
export const RULE_EVENT_SKIPPED = 'rule-events-skipped'
