import type { EventCursor, EventFilter, HistoryEvent } from './history'
import type { CommandApproval, JobSpec } from '../../shared/jobs'
import { ALERT_HISTORY_KIND, sanitiseStoredAlert } from '../../shared/webhook'
import type { StoredAlertRow } from '../../shared/webhook'
import {
  RULE_EVENT_FIRED,
  RULE_EVENT_REFUSED,
  RULE_EVENT_SKIPPED,
  RULE_EVENT_SUPPRESSED,
  RULE_SWEEP_INTERVAL_MS,
  RULE_SWEEP_MAX_EVENTS,
  RULE_SWEEP_PAGE,
  RULE_STALE_EVENT_MS,
  checkRuleLimit,
  clampRuleLimit,
  ruleMatches,
  ruleNotice,
  sanitiseRules,
  verifyRuleAction
} from '../../shared/rules'
import type { Rule, RuleDraftWire, RuleStatus, RuleView } from '../../shared/rules'

// The rule engine — roadmap item 27, main-process half.
//
// The vocabulary, the authorisation decision and the reasoning behind both are
// in src/shared/rules.ts. This file is the part that touches the world, and it
// holds exactly three things: a JSON file, a watermark into the alert log, and
// a per-rule rate-limit ledger.
//
// ---------------------------------------------------------------------------
// Everything is injected, including the clock
// ---------------------------------------------------------------------------
//
// Same discipline as JobRunner and LogTailer, and for a stronger reason here.
// This engine decides whether commands run on somebody's estate while nobody is
// watching, so every test of it has to be able to say "at this instant, with
// this log, exactly this happened" — with no timer, no sleep and no real
// executor. The engine therefore holds no ssh, no credential resolver, no
// webhook URL and no job executor: it is handed `runJob`, `notify` and
// `resolveTarget` and can do nothing its host did not give it.
//
// It also keeps this module's import closure small enough to be checkable. The
// webhook module imports `services/secrets`, which is on
// MODULE_FORBIDDEN_IMPORTS; importing it here to send a notification would put
// the OS keychain inside a module's reach for the sake of one function call.
//
// ---------------------------------------------------------------------------
// Not agent-reachable, and not for the broadcast reason
// ---------------------------------------------------------------------------
//
// DURABILITY DEFEATS REVOCATION, one turn further than shared/jobs.ts states
// it. `denyAllPending()` resolves requests that are PENDING; a rule at rest has
// nothing pending even between firings, so revoking every session and denying
// every outstanding approval leaves it exactly where it was and it fires at 3am
// anyway. See tests/rulesNotExposed.test.ts.

/** The half of the history store this engine may see. Reads and one write
 *  kind — deliberately not the whole `HistoryStore`, so nothing here can grow
 *  a job row or a metric sample. */
export interface RuleEventStore {
  readEvents(filter?: EventFilter): HistoryEvent[]
  recordEvent(kind: string, hostId: string | null, payload?: unknown, at?: number): void
}

/** What a rule's pinned job becomes when it is actually launched. Structurally
 *  `JobRunRequest`, restated rather than imported so this module does not pull
 *  the job runner in to name a type. */
export interface RuleJobLaunch {
  jobId: string
  spec: JobSpec
  approval: CommandApproval
  targets: { serverId: string; serverName: string; cohort?: string; cfg: unknown }[]
}

/** The file, as it is written. Versioned because it holds an approval record
 *  that has to keep meaning what it meant. */
export interface RulesFile {
  v: 1
  watermark: EventCursor | null
  rules: unknown[]
  status: unknown[]
}

export interface RuleEngineDeps {
  /** Null on a machine where the history store would not open. A rule engine
   *  with no event log is inert, and says so, rather than pretending. */
  store: RuleEventStore | null
  now(): number
  read(): unknown
  write(file: RulesFile): void
  /** `webhookNotify`. Fire-and-forget and sanitised by the callee. */
  notify(raw: unknown): void
  /** The SSH config for a pinned target, or null when that server is gone. */
  resolveTarget(serverId: string): unknown | null
  runJob(launch: RuleJobLaunch): Promise<unknown>
  newId(): string
  /** The app version stamped into a notification, so a shared endpoint can tell
   *  which build posted. A function rather than a string because main reads it
   *  from Electron and this engine is constructed before that matters. */
  version(): string
}

export interface RuleSweepResult {
  /** Alert rows this sweep looked at. */
  read: number
  fired: number
  suppressed: number
  refused: number
  /** Rows inside the window the read could not reach. Never silent. */
  skipped: number
}

const emptyStatus = (ruleId: string): RuleStatus => ({ ruleId, fired: [], suppressed: 0 })

function sanitiseStatus(raw: unknown): RuleStatus | null {
  if (typeof raw !== 'object' || raw === null) return null
  const r = raw as Record<string, unknown>
  if (typeof r.ruleId !== 'string' || r.ruleId === '') return null
  const out: RuleStatus = {
    ruleId: r.ruleId,
    fired: Array.isArray(r.fired) ? r.fired.filter((t): t is number => typeof t === 'number' && Number.isFinite(t)) : [],
    suppressed: typeof r.suppressed === 'number' && Number.isFinite(r.suppressed) ? Math.max(0, Math.floor(r.suppressed)) : 0
  }
  if (typeof r.lastFiredAt === 'number' && Number.isFinite(r.lastFiredAt)) out.lastFiredAt = r.lastFiredAt
  if (typeof r.refusal === 'string' && r.refusal !== '') out.refusal = r.refusal
  if (typeof r.refusedAt === 'number' && Number.isFinite(r.refusedAt)) out.refusedAt = r.refusedAt
  return out
}

function sanitiseWatermark(raw: unknown): EventCursor | null {
  if (typeof raw !== 'object' || raw === null) return null
  const r = raw as Record<string, unknown>
  if (typeof r.ts !== 'number' || !Number.isFinite(r.ts)) return null
  if (typeof r.id !== 'number' || !Number.isFinite(r.id)) return null
  return { ts: r.ts, id: r.id }
}

export class RuleEngine {
  private rules: Rule[] = []
  private status = new Map<string, RuleStatus>()
  private watermark: EventCursor | null = null
  private timer: ReturnType<typeof setInterval> | null = null
  private loaded = false
  /** One sweep at a time. A sweep awaits `runJob`, and a second one entering
   *  while the first is between "read the log" and "advance the watermark"
   *  would see the same rows again and fire twice on one event — the exact
   *  property this whole file is supposed to have. */
  private sweeping: Promise<RuleSweepResult> | null = null

  constructor(private deps: RuleEngineDeps) {}

  private load(): void {
    if (this.loaded) return
    this.loaded = true
    const raw = this.deps.read()
    const file = typeof raw === 'object' && raw !== null ? (raw as Record<string, unknown>) : {}
    this.rules = sanitiseRules(file.rules)
    this.watermark = sanitiseWatermark(file.watermark)
    const kept = new Set(this.rules.map((r) => r.id))
    this.status = new Map()
    if (Array.isArray(file.status)) {
      for (const s of file.status) {
        const parsed = sanitiseStatus(s)
        // A status row for a rule that is gone is dropped rather than kept:
        // resurrecting a deleted rule's id would hand the new rule the old
        // one's spent rate limit.
        if (parsed && kept.has(parsed.ruleId)) this.status.set(parsed.ruleId, parsed)
      }
    }
    for (const r of this.rules) if (!this.status.has(r.id)) this.status.set(r.id, emptyStatus(r.id))
  }

  private persist(): void {
    this.deps.write({
      v: 1,
      watermark: this.watermark,
      rules: this.rules,
      status: [...this.status.values()]
    })
  }

  private statusFor(id: string): RuleStatus {
    let s = this.status.get(id)
    if (!s) {
      s = emptyStatus(id)
      this.status.set(id, s)
    }
    return s
  }

  list(): RuleView[] {
    this.load()
    return this.rules.map((rule) => {
      const verdict = verifyRuleAction(rule)
      return {
        ...rule,
        status: { ...this.statusFor(rule.id), fired: [...this.statusFor(rule.id).fired] },
        verdict: verdict.ok ? { ok: true } : { ok: false, reason: verdict.reason }
      }
    })
  }

  /**
   * Write a rule.
   *
   * `armedAt` is the CURRENT time and is not taken from the caller. A rule that
   * could be created already armed into the past would fire on the backlog the
   * moment it was written, which is the one thing a rule must never do.
   */
  create(draft: RuleDraftWire): RuleView | null {
    this.load()
    const rule: Rule = {
      id: this.deps.newId(),
      name: draft.name.slice(0, 120),
      // Created ENABLED, and armed from now. The alternative — created off,
      // switched on afterwards — is the same two presses with a state in
      // between where the panel shows a rule that is not doing anything and
      // does not say why.
      enabled: true,
      trigger: draft.trigger,
      filter: draft.filter ?? {},
      action: draft.action,
      limit: clampRuleLimit(draft.limit),
      armedAt: this.deps.now()
    }
    // Round-tripped through the same whitelist the file is read back through,
    // so a rule that could not survive a restart cannot be created either.
    const [checked] = sanitiseRules([rule])
    if (!checked) return null
    // The watermark has to exist before the first rule does. Without it the
    // first sweep would set it to "now" AFTER this rule armed, and the events
    // in between would be read by nothing.
    if (this.watermark === null) this.watermark = { ts: this.deps.now(), id: 0 }
    this.rules.push(checked)
    this.status.set(checked.id, emptyStatus(checked.id))
    this.persist()
    return this.list().find((r) => r.id === checked.id) ?? null
  }

  /**
   * Turn a rule on or off.
   *
   * Enabling RE-ARMS it. Off means off: a rule switched off for a fortnight and
   * back on must not replay the fortnight, or disabling a rule becomes the most
   * dangerous button on the panel. Disabling deliberately leaves the rate-limit
   * ledger alone — a rule toggled off and on again has not earned a fresh
   * window.
   */
  setEnabled(id: string, enabled: boolean): boolean {
    this.load()
    const rule = this.rules.find((r) => r.id === id)
    if (!rule) return false
    rule.enabled = enabled
    if (enabled) rule.armedAt = this.deps.now()
    this.persist()
    return true
  }

  remove(id: string): boolean {
    this.load()
    const before = this.rules.length
    this.rules = this.rules.filter((r) => r.id !== id)
    if (this.rules.length === before) return false
    this.status.delete(id)
    this.persist()
    return true
  }

  start(): void {
    this.load()
    if (this.timer !== null) return
    this.timer = setInterval(() => {
      void this.sweep()
    }, RULE_SWEEP_INTERVAL_MS)
    // Never hold the process open for a rule sweep.
    this.timer.unref?.()
  }

  stop(): void {
    if (this.timer !== null) clearInterval(this.timer)
    this.timer = null
  }

  sweep(): Promise<RuleSweepResult> {
    if (this.sweeping !== null) return this.sweeping
    const run = this.runSweep().finally(() => {
      this.sweeping = null
    })
    this.sweeping = run
    return run
  }

  /**
   * Read what is new in the alert log and act on it.
   *
   * The read is bounded on BOTH ends and neither bound is arbitrary:
   *
   *  * The watermark is where the last sweep got to, so an event is acted on
   *    once and not once per read. It advances to the newest row this sweep
   *    actually looked at, and only after the acting is done.
   *  * `RULE_STALE_EVENT_MS` is the older end. A rule does not act on an alert
   *    from six hours ago — the condition has been dealt with or it has not,
   *    and either way running a command about it now is worse than not. It also
   *    makes catch-up after a long shutdown finite, which is what lets a
   *    newest-first cursor be paged to exhaustion here at all.
   */
  private async runSweep(): Promise<RuleSweepResult> {
    this.load()
    const result: RuleSweepResult = { read: 0, fired: 0, suppressed: 0, refused: 0, skipped: 0 }
    const store = this.deps.store
    if (!store) return result
    const now = this.deps.now()

    if (this.watermark === null) {
      // First sweep on this machine: start here, act on nothing behind us.
      this.watermark = { ts: now, id: 0 }
      this.persist()
      return result
    }

    const from = Math.max(this.watermark.ts, now - RULE_STALE_EVENT_MS)
    const rows: { row: StoredAlertRow; cursor: EventCursor }[] = []
    let cursor: EventCursor | undefined
    let exhausted = false
    while (rows.length < RULE_SWEEP_MAX_EVENTS) {
      const page = store.readEvents({ kind: ALERT_HISTORY_KIND, from, limit: RULE_SWEEP_PAGE, cursor })
      for (const e of page) {
        // Newer than the watermark, with the row id breaking a same-millisecond
        // tie exactly as EventCursor was written to do.
        const fresh =
          e.ts > this.watermark.ts || (e.ts === this.watermark.ts && e.cursor.id > this.watermark.id)
        if (!fresh) continue
        const row = sanitiseStoredAlert(e.payload)
        // A row that does not survive the whitelist is not a partial alert to
        // act on. It is counted as read so the watermark still passes it.
        if (row) rows.push({ row: { ...row, at: e.ts }, cursor: e.cursor })
      }
      if (page.length < RULE_SWEEP_PAGE) {
        exhausted = true
        break
      }
      cursor = page[page.length - 1].cursor
    }

    if (rows.length === 0) {
      if (exhausted) {
        // Nothing new, but the window has moved: advancing here is what stops
        // a quiet estate re-reading the same hour of log on every sweep.
        this.watermark = { ts: Math.max(this.watermark.ts, from), id: this.watermark.id }
        this.persist()
      }
      return result
    }

    // Read newest-first; acted on oldest-first, because a raise followed by a
    // resolve must not be seen the other way round.
    rows.sort((a, b) => a.cursor.ts - b.cursor.ts || a.cursor.id - b.cursor.id)
    result.read = rows.length

    if (!exhausted) {
      // The cap was reached inside the window, so rows older than the oldest
      // one here were never looked at. Said out loud rather than dropped: an
      // automation path that discards without saying so is worse than one that
      // does not exist, because it is trusted.
      result.skipped = 1
      store.recordEvent(
        RULE_EVENT_SKIPPED,
        null,
        { from, oldestRead: rows[0].cursor.ts, read: rows.length, cap: RULE_SWEEP_MAX_EVENTS },
        now
      )
    }

    const suppressedThisSweep = new Map<string, number>()
    for (const { row } of rows) {
      for (const rule of this.rules) {
        if (!ruleMatches(rule, row)) continue
        const outcome = await this.fire(rule, row, now)
        if (outcome === 'fired') result.fired++
        else if (outcome === 'refused') result.refused++
        else {
          result.suppressed++
          suppressedThisSweep.set(rule.id, (suppressedThisSweep.get(rule.id) ?? 0) + 1)
        }
      }
    }

    // One row per rule per sweep rather than one per suppression. A unit in a
    // restart loop produces a raise every few seconds; a suppression row for
    // each would put the flapping back into the store this feature was
    // supposed to keep it out of. The COUNT is what an operator asks about.
    for (const [ruleId, count] of suppressedThisSweep) {
      const rule = this.rules.find((r) => r.id === ruleId)
      store.recordEvent(RULE_EVENT_SUPPRESSED, null, { ruleId, name: rule?.name ?? '', count }, now)
    }

    const newest = rows[rows.length - 1].cursor
    this.watermark = { ts: newest.ts, id: newest.id }
    this.persist()
    return result
  }

  private async fire(rule: Rule, row: StoredAlertRow, now: number): Promise<'fired' | 'refused' | 'suppressed'> {
    const status = this.statusFor(rule.id)

    // THE RATE LIMIT IS CHECKED FIRST, before the approval, and that ordering
    // is deliberate. A rule whose approval has drifted still matches every
    // event from a flapping source; checking authority first would turn a
    // broken rule into two hundred notifications an hour. The limit governs how
    // often this rule may ACT AT ALL, and complaining is acting.
    //
    // The clock is `now` and not the event's timestamp. A backlog of forty
    // matching rows swept in one instant is forty actions on the estate in one
    // instant however old the rows are, so the limit has to be measured in wall
    // clock, which is the thing the estate experiences.
    const verdict = checkRuleLimit(status.fired, now, rule.limit)
    if (!verdict.allowed) {
      status.suppressed++
      status.fired = verdict.fired
      return 'suppressed'
    }
    status.fired = verdict.fired
    status.lastFiredAt = now

    const authorised = verifyRuleAction(rule)
    if (!authorised.ok) {
      status.refusal = authorised.reason
      status.refusedAt = now
      this.deps.store?.recordEvent(
        RULE_EVENT_REFUSED,
        null,
        { ruleId: rule.id, name: rule.name, reason: authorised.reason },
        now
      )
      this.deps.notify(this.payload(rule, row, 'job-refused'))
      return 'refused'
    }

    if (rule.action.type === 'notify') {
      status.refusal = undefined
      status.refusedAt = undefined
      this.deps.store?.recordEvent(
        RULE_EVENT_FIRED,
        row.serverId,
        { ruleId: rule.id, name: rule.name, action: 'notify', kind: row.kind, event: row.event },
        now
      )
      this.deps.notify(this.payload(rule, row, 'notified'))
      return 'fired'
    }

    // A pinned target whose server no longer exists REFUSES THE WHOLE RULE
    // rather than running on the rest. `verifyApproval` would accept a shrunk
    // list, and for a job being resumed that is right — every survivor was in
    // the list a human confirmed. It is not right here: a rule is a standing
    // authorisation whose whole claim is that its blast radius was knowable
    // when it was written, and "these three of the five, because two were
    // deleted from the workspace at some point" is not that shape.
    const targets: RuleJobLaunch['targets'] = []
    const missing: string[] = []
    for (const t of rule.action.targets) {
      const cfg = this.deps.resolveTarget(t.serverId)
      if (cfg === null) missing.push(t.serverName || t.serverId)
      else targets.push({ serverId: t.serverId, serverName: t.serverName, cohort: t.cohort, cfg })
    }
    if (missing.length > 0) {
      const reason =
        `${missing.join(', ')} ${missing.length === 1 ? 'is' : 'are'} no longer in this workspace. A ` +
        `rule runs on the server list it was confirmed against or it does not run.`
      status.refusal = reason
      status.refusedAt = now
      this.deps.store?.recordEvent(
        RULE_EVENT_REFUSED,
        null,
        { ruleId: rule.id, name: rule.name, reason },
        now
      )
      this.deps.notify(this.payload(rule, row, 'job-refused'))
      return 'refused'
    }

    try {
      await this.deps.runJob({
        jobId: this.deps.newId(),
        spec: rule.action.spec,
        // The record minted when the rule was written, handed over unchanged.
        // Main re-derives planJob over this very spec and target list and
        // refuses if the record disagrees — the same door every other job goes
        // through, taken for the same reason.
        approval: rule.action.approval,
        targets
      })
    } catch (err) {
      const reason = err instanceof Error ? err.message : String(err)
      status.refusal = reason
      status.refusedAt = now
      this.deps.store?.recordEvent(
        RULE_EVENT_REFUSED,
        null,
        { ruleId: rule.id, name: rule.name, reason },
        now
      )
      this.deps.notify(this.payload(rule, row, 'job-refused'))
      return 'refused'
    }

    status.refusal = undefined
    status.refusedAt = undefined
    this.deps.store?.recordEvent(
      RULE_EVENT_FIRED,
      row.serverId,
      {
        ruleId: rule.id,
        name: rule.name,
        action: 'job',
        title: rule.action.spec.title,
        hosts: targets.length,
        kind: row.kind,
        event: row.event
      },
      now
    )
    this.deps.notify(this.payload(rule, row, 'job-started'))
    return 'fired'
  }

  private payload(
    rule: Rule,
    row: StoredAlertRow,
    outcome: 'notified' | 'job-started' | 'job-refused'
  ): Record<string, unknown> {
    return { source: 'shellpilot', version: this.deps.version(), ...ruleNotice(rule, row, outcome) }
  }
}
