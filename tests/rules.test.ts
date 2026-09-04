import { describe, expect, it } from 'vitest'
import type { ApprovalVerdict } from '../src/shared/broadcast'
import {
  RULE_ALERT_KINDS,
  RULE_LIMIT_DEFAULT,
  RULE_LIMIT_MAX_FIRINGS,
  RULE_LIMIT_MAX_WINDOW_MS,
  RULE_LIMIT_MIN_WINDOW_MS,
  RULE_TRIGGER_EVENTS,
  RULE_UNATTENDED_PHRASE,
  checkRuleLimit,
  clampRuleLimit,
  ruleCreationConfirmation,
  ruleJobPlan,
  ruleMatches,
  ruleNotice,
  ruleWireKind,
  sanitiseRule,
  sanitiseRules,
  verifyRuleAction,
  type Rule,
  type RuleJobAction
} from '../src/shared/rules'
import { jobApprovalFor } from '../src/shared/jobs'
import type { JobSpec, JobTargetRef } from '../src/shared/jobs'
import { sanitisePayload } from '../src/main/services/webhookAlerts'
import type { StoredAlertRow } from '../src/shared/webhook'

// The vocabulary half of roadmap item 27.
//
// Everything here is a literal. A rule engine's failure mode is not a crash —
// it is a rule that looks armed and does nothing, or one that looks pinned and
// runs something else — so an assertion derived from the same constant the code
// reads would agree with the bug.

const T0 = 1_700_000_000_000
const HOUR = 3_600_000

const TARGETS: JobTargetRef[] = [
  { serverId: 'srv-a', serverName: 'alpha' },
  { serverId: 'srv-b', serverName: 'bravo' }
]

const SPEC: JobSpec = {
  kind: 'command',
  title: 'clear the journal',
  steps: [{ command: 'journalctl --vacuum-size=200M' }]
}

function jobAction(over: { spec?: JobSpec; targets?: JobTargetRef[] } = {}): RuleJobAction {
  const spec = over.spec ?? SPEC
  const targets = over.targets ?? TARGETS
  return {
    type: 'job',
    spec,
    targets,
    // Minted over the spec and targets the rule was WRITTEN with, which is the
    // whole of the authorisation decision.
    approval: jobApprovalFor(SPEC, TARGETS, { phrase: null, confirmedAt: T0 })
  }
}

function rule(over: Partial<Rule> = {}): Rule {
  return {
    id: 'rule-1',
    name: 'vacuum the journal',
    enabled: true,
    trigger: { kind: 'disk', event: 'raised' },
    filter: {},
    action: { type: 'notify' },
    limit: { maxFirings: 1, windowMs: HOUR },
    armedAt: T0,
    ...over
  }
}

function row(over: Partial<StoredAlertRow> = {}): StoredAlertRow {
  return {
    at: T0 + 1000,
    event: 'raised',
    kind: 'disk',
    serverId: 'srv-a',
    serverName: 'alpha',
    value: 91,
    threshold: 85,
    ...over
  }
}

describe('what a rule may watch', () => {
  it('watches exactly the alert kinds that survive the outbound whitelist', () => {
    // A literal, not `STORE_ALERT_KINDS.filter(...)` repeated. `ram` is absent
    // on purpose: the store calls it `ram`, the wire calls it `memory`, and the
    // map between them is private to the renderer's alert store. This list is
    // what says that out loud instead of a rule quietly posting under a name
    // the sanitiser drops.
    expect([...RULE_ALERT_KINDS]).toEqual([
      'cpu',
      'disk',
      'inode',
      'load',
      'cert-expiry',
      'host-unreachable',
      'job-failed',
      'tunnel-down',
      'oom-kill',
      'db-alarm',
      'db-watch'
    ])
  })

  it('has no kind the outbound sanitiser would silently drop', () => {
    // The property the list above exists for, checked against the thing that
    // actually decides. A kind that did not survive here would produce a rule
    // whose notification never arrives, from a settings pane reporting a
    // healthy webhook — which is the exact failure webhookAlerts.ts calls
    // "a whitelist that quietly says no to its own product".
    for (const kind of RULE_ALERT_KINDS) {
      const payload = sanitisePayload({
        source: 'shellpilot',
        version: '1.0.0',
        event: 'raised',
        kind: ruleWireKind(kind),
        server: 'alpha',
        summary: 'x'
      })
      expect(payload, kind).not.toBeNull()
      expect(payload?.kind).toBe(kind)
    }
  })

  it('triggers on what an alert did and never on what a person decided about it', () => {
    // `snoozed` and `acknowledged` are in the stored-event vocabulary and are
    // deliberately not here: a job that ran because somebody pressed snooze is
    // automation triggered by a request for quiet.
    expect([...RULE_TRIGGER_EVENTS]).toEqual(['raised', 'resolved'])
  })
})

describe('matching an event', () => {
  it('fires on a row that matches the trigger', () => {
    expect(ruleMatches(rule(), row())).toBe(true)
  })

  it('does not fire on the backlog that existed before it was armed', () => {
    // The rule was written at T0. An alert raised a minute earlier is not
    // something it is answerable for, and replaying it would mean writing a
    // rule ran a job about a condition that had already been dealt with.
    expect(ruleMatches(rule({ armedAt: T0 }), row({ at: T0 - 60_000 }))).toBe(false)
    // Strict, and on purpose: the store writes several events in one
    // millisecond routinely, so the boundary falls on one side deliberately.
    expect(ruleMatches(rule({ armedAt: T0 }), row({ at: T0 }))).toBe(false)
    expect(ruleMatches(rule({ armedAt: T0 }), row({ at: T0 + 1 }))).toBe(true)
  })

  it('ignores another kind and the other half of the same kind', () => {
    expect(ruleMatches(rule(), row({ kind: 'cpu' }))).toBe(false)
    expect(ruleMatches(rule(), row({ event: 'resolved' }))).toBe(false)
    expect(ruleMatches(rule({ trigger: { kind: 'disk', event: 'resolved' } }), row({ event: 'resolved' }))).toBe(true)
  })

  it('ignores a decision somebody made about an alert', () => {
    expect(ruleMatches(rule(), row({ event: 'snoozed' }))).toBe(false)
    expect(ruleMatches(rule(), row({ event: 'acknowledged' }))).toBe(false)
    expect(ruleMatches(rule(), row({ event: 'stood-down' }))).toBe(false)
  })

  it('narrows to one server when the filter names one', () => {
    const r = rule({ filter: { serverId: 'srv-a' } })
    expect(ruleMatches(r, row({ serverId: 'srv-a' }))).toBe(true)
    expect(ruleMatches(r, row({ serverId: 'srv-b' }))).toBe(false)
  })

  it('treats a missing reading as no reading rather than as zero', () => {
    // The rule the whole of 19a runs on. A `host-unreachable` row carries no
    // number, and a rule filtering above 50 must not match it because
    // `undefined` compared as 0 is below the line.
    const r = rule({ trigger: { kind: 'host-unreachable', event: 'raised' }, filter: { minValue: 50 } })
    expect(ruleMatches(r, row({ kind: 'host-unreachable', value: undefined }))).toBe(false)
    // And at a line of zero, which is where "absent coerced to a number" stops
    // being invisible: `undefined` read as 0 clears a line of 0, so a rule
    // written to fire on anything at all would fire on rows that carry no
    // measurement whatsoever.
    const anyReading = rule({
      trigger: { kind: 'host-unreachable', event: 'raised' },
      filter: { minValue: 0 }
    })
    expect(ruleMatches(anyReading, row({ kind: 'host-unreachable', value: undefined }))).toBe(false)
    // And a real zero is a real reading, not a missing one.
    const cpu = rule({ trigger: { kind: 'cpu', event: 'raised' }, filter: { minValue: 0 } })
    expect(ruleMatches(cpu, row({ kind: 'cpu', value: 0 }))).toBe(true)
  })

  it('fires at the line and not below it', () => {
    const r = rule({ filter: { minValue: 90 } })
    expect(ruleMatches(r, row({ value: 89.9 }))).toBe(false)
    expect(ruleMatches(r, row({ value: 90 }))).toBe(true)
  })

  it('is inert when disabled, whatever else matches', () => {
    expect(ruleMatches(rule({ enabled: false }), row())).toBe(false)
  })
})

describe('the rate limit', () => {
  it('allows the first firing and refuses the second inside the window', () => {
    const first = checkRuleLimit([], T0, { maxFirings: 1, windowMs: HOUR })
    expect(first.allowed).toBe(true)
    expect(first.fired).toEqual([T0])
    expect(first.nextAllowedAt).toBeNull()

    const second = checkRuleLimit(first.fired, T0 + 1000, { maxFirings: 1, windowMs: HOUR })
    expect(second.allowed).toBe(false)
    // The panel has to say WHEN, not merely that it declined.
    expect(second.nextAllowedAt).toBe(T0 + HOUR)
  })

  it('lets the window slide rather than resetting it', () => {
    const limit = { maxFirings: 2, windowMs: HOUR }
    const a = checkRuleLimit([], T0, limit)
    const b = checkRuleLimit(a.fired, T0 + 10 * 60_000, limit)
    expect(b.allowed).toBe(true)
    const c = checkRuleLimit(b.fired, T0 + 20 * 60_000, limit)
    expect(c.allowed).toBe(false)
    expect(c.nextAllowedAt).toBe(T0 + HOUR)
    // The first firing has now aged out; the second has not.
    const d = checkRuleLimit(c.fired, T0 + HOUR, limit)
    expect(d.allowed).toBe(true)
    expect(d.fired).toEqual([T0 + 10 * 60_000, T0 + HOUR])
  })

  it('keeps a firing recorded in the future rather than discarding it', () => {
    // A clock correction that moves time backwards must not hand a rule its
    // whole window over again. Keeping the row is the conservative reading.
    const v = checkRuleLimit([T0 + HOUR], T0, { maxFirings: 1, windowMs: HOUR })
    expect(v.allowed).toBe(false)
    expect(v.fired).toEqual([T0 + HOUR])
  })

  it('holds under a flapping source', () => {
    // 240 raises in an hour — one every fifteen seconds, which is what a unit
    // in a restart loop produces against a sampler. One firing is what the
    // operator asked for and 240 is an outage with this app's name on it.
    const limit = { maxFirings: 1, windowMs: HOUR }
    let fired: number[] = []
    let allowed = 0
    for (let i = 0; i < 240; i++) {
      const v = checkRuleLimit(fired, T0 + i * 15_000, limit)
      fired = v.fired
      if (v.allowed) allowed++
    }
    expect(allowed).toBe(1)
  })

  it('defaults to once an hour', () => {
    expect(RULE_LIMIT_DEFAULT).toEqual({ maxFirings: 1, windowMs: 3_600_000 })
  })

  it('narrows a hand-edited limit back to something with a branch behind it', () => {
    expect(clampRuleLimit({ maxFirings: 0, windowMs: 1 })).toEqual({
      maxFirings: 1,
      windowMs: RULE_LIMIT_MIN_WINDOW_MS
    })
    expect(clampRuleLimit({ maxFirings: 10_000, windowMs: 10 ** 12 })).toEqual({
      maxFirings: RULE_LIMIT_MAX_FIRINGS,
      windowMs: RULE_LIMIT_MAX_WINDOW_MS
    })
    expect(clampRuleLimit(undefined)).toEqual(RULE_LIMIT_DEFAULT)
    expect(clampRuleLimit({ maxFirings: Number.NaN, windowMs: Number.NaN })).toEqual(RULE_LIMIT_DEFAULT)
  })
})

/**
 * The reason a verdict refuses, failing the test if it did not refuse.
 *
 * `ApprovalVerdict` is `{ ok: true } | { ok: false; reason: string }`, and
 * `expect(verdict.ok).toBe(false)` narrows nothing for the compiler — so every
 * `verdict.reason` below was a property access on a union whose `ok: true` arm
 * has no such member. Going through here narrows it properly, and an
 * unexpectedly-approved verdict now fails by saying so rather than by
 * comparing `undefined` against a sentence.
 */
function refusal(verdict: ApprovalVerdict): string {
  if (verdict.ok) throw new Error('expected this to be refused, but the verdict was ok')
  return verdict.reason
}

describe('what a rule is authorised to run', () => {
  it('verifies a rule whose job is what was approved', () => {
    expect(verifyRuleAction(rule({ action: jobAction() }))).toEqual({ ok: true })
  })

  it('refuses a rule whose command was edited under its stored approval', () => {
    const drifted = jobAction({
      spec: { ...SPEC, steps: [{ command: 'rm -rf /var/log' }] }
    })
    const reason = refusal(verifyRuleAction(rule({ action: drifted })))
    expect(reason).toContain('An edited command needs a fresh confirmation.')
  })

  it('refuses a rule that grew a server after it was written', () => {
    const grown = jobAction({
      targets: [...TARGETS, { serverId: 'srv-c', serverName: 'charlie' }]
    })
    const reason = refusal(verifyRuleAction(rule({ action: grown })))
    expect(reason).toContain('charlie')
    expect(reason).toContain('runs on nobody’s approval')
  })

  it('refuses a rule with no usable record at all', () => {
    const forged = { type: 'job', spec: SPEC, targets: TARGETS, approval: { v: 1 } } as unknown as RuleJobAction
    const reason = refusal(verifyRuleAction(rule({ action: forged })))
    expect(reason).toContain('no usable approval record came with this run')
  })

  it('has nothing to verify for a notification', () => {
    expect(verifyRuleAction(rule())).toEqual({ ok: true })
  })

  it('states the blast radius from the pinned target list', () => {
    // Knowable when the rule is written, which is the property the whole
    // authorisation decision exists to keep.
    const plan = ruleJobPlan(jobAction())
    expect(plan.blastRadius).toBe(2)
    expect(plan.totalHosts).toBe(2)
    expect(plan.risk).toBe('ordinary')
  })

  it('always demands a typed word to create a job rule', () => {
    // `planJob` asks for one click here — an ordinary command on two hosts. A
    // standing authorisation is a different thing being agreed to, so the
    // creation gate is stricter than the run gate for the same job.
    expect(ruleJobPlan(jobAction()).confirmation).toEqual({ kind: 'confirm' })
    expect(ruleCreationConfirmation('job')).toEqual({
      kind: 'type-to-confirm',
      phrase: 'UNATTENDED'
    })
    expect(RULE_UNATTENDED_PHRASE).toBe('UNATTENDED')
    expect(ruleCreationConfirmation('notify')).toEqual({ kind: 'confirm' })
  })
})

describe('what the endpoint is told', () => {
  it('says the automation ran rather than repeating the alert', () => {
    const notice = ruleNotice(rule({ action: jobAction() }), row(), 'job-started')
    expect(notice.summary).toBe(
      'ShellPilot rule "vacuum the journal" started the job "clear the journal" on 2 server(s) after a disk alert raised.'
    )
    expect(notice.kind).toBe('disk')
    expect(notice.server).toBe('alpha')
    expect(notice.value).toBe(91)
    expect(notice.threshold).toBe(85)
  })

  it('says so when the rule refused instead of running', () => {
    const notice = ruleNotice(rule({ action: jobAction() }), row(), 'job-refused')
    expect(notice.summary).toContain('refused to start the job "clear the journal"')
  })

  it('survives the outbound whitelist unchanged', () => {
    const notice = ruleNotice(rule({ action: jobAction() }), row(), 'job-started')
    const sent = sanitisePayload({ source: 'shellpilot', version: '1.2.3', ...notice })
    expect(sent).not.toBeNull()
    expect(sent?.summary).toBe(notice.summary)
    expect(sent?.kind).toBe('disk')
  })

  it('carries no reading for a kind that has none', () => {
    const notice = ruleNotice(
      rule({ trigger: { kind: 'host-unreachable', event: 'raised' } }),
      row({ kind: 'host-unreachable', value: undefined, threshold: undefined }),
      'notified'
    )
    expect(notice.value).toBeUndefined()
    expect(notice.threshold).toBeUndefined()
  })
})

describe('reading a rules file back', () => {
  const stored = (over: Record<string, unknown> = {}): Record<string, unknown> => ({
    id: 'r1',
    name: 'n',
    enabled: true,
    trigger: { kind: 'disk', event: 'raised' },
    filter: {},
    action: { type: 'notify' },
    limit: { maxFirings: 1, windowMs: HOUR },
    armedAt: T0,
    ...over
  })

  it('reads back a rule it wrote', () => {
    expect(sanitiseRule(stored())).toEqual(rule({ id: 'r1', name: 'n' }))
  })

  it('treats an absent enabled flag as off', () => {
    // Absent reads as OFF, exactly as an absent module does. A rules file from
    // a half-written upgrade must not arm anything by omission.
    expect(sanitiseRule(stored({ enabled: undefined }))?.enabled).toBe(false)
    expect(sanitiseRule(stored({ enabled: 'yes' }))?.enabled).toBe(false)
    expect(sanitiseRule(stored({ enabled: 1 }))?.enabled).toBe(false)
  })

  it('refuses a kind or an event nothing produces', () => {
    expect(sanitiseRule(stored({ trigger: { kind: 'ram', event: 'raised' } }))).toBeNull()
    expect(sanitiseRule(stored({ trigger: { kind: 'disk', event: 'snoozed' } }))).toBeNull()
    expect(sanitiseRule(stored({ trigger: { kind: 'anything', event: 'raised' } }))).toBeNull()
  })

  it('refuses an action it has no branch for', () => {
    expect(sanitiseRule(stored({ action: { type: 'shell', command: 'rm -rf /' } }))).toBeNull()
    expect(sanitiseRule(stored({ action: { type: 'job', spec: SPEC, targets: [] } }))).toBeNull()
    expect(
      sanitiseRule(stored({ action: { type: 'job', spec: { ...SPEC, steps: [] }, targets: TARGETS } }))
    ).toBeNull()
  })

  it('keeps the other rules when one entry is corrupt', () => {
    const rules = sanitiseRules([stored({ id: 'a' }), { id: 'broken' }, stored({ id: 'b' })])
    expect(rules.map((r) => r.id)).toEqual(['a', 'b'])
  })

  it('keeps the first of two rules sharing an id', () => {
    // Two rules with one id is a file that was hand-edited or half-written, and
    // the status a rule carries is keyed on that id — two of them would share
    // one rate limit and one would fire on the other's budget.
    const rules = sanitiseRules([stored({ id: 'a', name: 'first' }), stored({ id: 'a', name: 'second' })])
    expect(rules.map((r) => r.name)).toEqual(['first'])
  })

  it('narrows an out-of-range limit rather than trusting the file', () => {
    expect(sanitiseRule(stored({ limit: { maxFirings: 99_999, windowMs: 5 } }))?.limit).toEqual({
      maxFirings: RULE_LIMIT_MAX_FIRINGS,
      windowMs: RULE_LIMIT_MIN_WINDOW_MS
    })
  })

  it('reads a rules file that is not an array as no rules', () => {
    expect(sanitiseRules(null)).toEqual([])
    expect(sanitiseRules({ rules: [stored()] })).toEqual([])
  })
})
