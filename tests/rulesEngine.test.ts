import { describe, expect, it } from 'vitest'
import { RuleEngine } from '../src/main/services/rules'
import type { RuleEngineDeps, RuleJobLaunch, RulesFile } from '../src/main/services/rules'
import type { RuleDraftWire as RuleDraft } from '../src/shared/rules'
import type { EventFilter, HistoryEvent } from '../src/main/services/history'
import { ALERT_HISTORY_KIND } from '../src/shared/webhook'
import type { StoredAlertEvent } from '../src/shared/webhook'
import { jobApprovalFor } from '../src/shared/jobs'
import type { JobSpec, JobTargetRef } from '../src/shared/jobs'
import {
  RULE_EVENT_FIRED,
  RULE_EVENT_REFUSED,
  RULE_EVENT_SKIPPED,
  RULE_EVENT_SUPPRESSED,
  RULE_STALE_EVENT_MS,
  RULE_SWEEP_MAX_EVENTS
} from '../src/shared/rules'

// The engine half of roadmap item 27.
//
// Deterministic to the millisecond: the clock, the log, the job launcher, the
// webhook and the file are all handed in, and nothing here sleeps. Three flaky
// tests found in this repo turned out to be three real production bugs, and an
// engine that decides whether commands run unattended is the last place to
// accept a timing-dependent pass.

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

/** A fake alert log with the real store's ordering and cursor semantics:
 *  newest-first, `from` inclusive, and a cursor meaning "strictly older". */
function alertLog() {
  const rows: { ts: number; id: number; payload: StoredAlertEvent; kind: string }[] = []
  const written: { kind: string; hostId: string | null; payload: unknown; at?: number }[] = []
  let nextId = 1
  return {
    written,
    raise(over: Partial<StoredAlertEvent> & { at: number }): void {
      const { at, ...rest } = over
      rows.push({
        ts: at,
        id: nextId++,
        kind: ALERT_HISTORY_KIND,
        payload: {
          event: 'raised',
          kind: 'disk',
          serverId: 'srv-a',
          serverName: 'alpha',
          value: 91,
          threshold: 85,
          ...rest
        }
      })
    },
    /** A row that is not an alert at all, to prove the engine reads the alert
     *  kind rather than everything. */
    junk(at: number): void {
      rows.push({ ts: at, id: nextId++, kind: 'retention-skipped', payload: {} as StoredAlertEvent })
    },
    store: {
      readEvents(filter: EventFilter = {}): HistoryEvent[] {
        const from = filter.from ?? -Infinity
        const to = filter.to ?? Infinity
        const limit = filter.limit ?? 500
        return rows
          .filter((r) => {
            if (filter.kind !== undefined && r.kind !== filter.kind) return false
            if (r.ts < from || r.ts > to) return false
            const c = filter.cursor
            if (c && !(r.ts < c.ts || r.id < c.id)) return false
            return true
          })
          .sort((a, b) => b.ts - a.ts || b.id - a.id)
          .slice(0, limit)
          .map((r) => ({
            ts: r.ts,
            kind: r.kind,
            hostId: r.payload.serverId ?? null,
            payload: r.payload,
            cursor: { ts: r.ts, id: r.id }
          }))
      },
      recordEvent(kind: string, hostId: string | null, payload?: unknown, at?: number): void {
        written.push({ kind, hostId, payload, at })
      }
    }
  }
}

function harness(over: Partial<RuleEngineDeps> & { missingServers?: string[] } = {}) {
  const log = alertLog()
  const launched: RuleJobLaunch[] = []
  const notified: Record<string, unknown>[] = []
  let file: RulesFile | null = null
  let clock = T0
  let ids = 0
  let refuseJobWith: string | null = null

  const deps: RuleEngineDeps = {
    store: log.store,
    now: () => clock,
    read: () => file,
    write: (f) => {
      // Round-tripped through JSON, because that is what the real file does and
      // a Map or an undefined that only survives in memory is a restart bug
      // nobody sees until a restart.
      file = JSON.parse(JSON.stringify(f)) as RulesFile
    },
    notify: (raw) => notified.push(raw as Record<string, unknown>),
    resolveTarget: (id) => (over.missingServers?.includes(id) ? null : { serverId: id, host: `${id}.internal` }),
    runJob: async (launch) => {
      if (refuseJobWith !== null) throw new Error(refuseJobWith)
      launched.push(launch)
      return {}
    },
    newId: () => `id-${++ids}`,
    version: () => '9.9.9',
    ...over
  }

  return {
    log,
    launched,
    notified,
    deps,
    engine: new RuleEngine(deps),
    tick: (ms: number) => {
      clock += ms
    },
    at: () => clock,
    refuseJob: (reason: string | null) => {
      refuseJobWith = reason
    },
    /** Reopen from the file exactly as a restart would. */
    restart: () => new RuleEngine(deps),
    file: () => file
  }
}

const notifyRule = (over: Partial<RuleDraft> = {}): RuleDraft => ({
  name: 'tell me about the disk',
  trigger: { kind: 'disk', event: 'raised' },
  action: { type: 'notify' },
  limit: { maxFirings: 1, windowMs: HOUR },
  ...over
})

const jobRule = (over: { spec?: JobSpec; targets?: JobTargetRef[] } = {}): RuleDraft => ({
  name: 'vacuum the journal',
  trigger: { kind: 'disk', event: 'raised' },
  limit: { maxFirings: 1, windowMs: HOUR },
  action: {
    type: 'job',
    spec: over.spec ?? SPEC,
    targets: over.targets ?? TARGETS,
    // The record is minted over the ORIGINAL pair. `over` is how a test makes
    // the live pair drift away from it.
    approval: jobApprovalFor(SPEC, TARGETS, { phrase: null, confirmedAt: T0 })
  }
})

describe('firing once per event', () => {
  it('fires once for one matching event, however often it is read', async () => {
    const h = harness()
    h.engine.create(notifyRule())
    h.tick(1000)
    h.log.raise({ at: h.at() })
    h.tick(1000)

    expect(await h.engine.sweep()).toMatchObject({ read: 1, fired: 1, suppressed: 0 })
    // Swept again with the same log. A watermark that did not advance would
    // fire again here — and it would keep firing every sweep forever, which is
    // the failure this whole design is arranged around.
    expect(await h.engine.sweep()).toMatchObject({ read: 0, fired: 0 })
    expect(await h.engine.sweep()).toMatchObject({ read: 0, fired: 0 })
    expect(h.notified).toHaveLength(1)
  })

  it('does not fire again after a restart', async () => {
    // The watermark is in the file, not in memory. Without that, every launch
    // replays the last hour of alerts — which is exactly the bug 19b's durable
    // half exists to end, arriving through a different door.
    const h = harness()
    h.engine.create(notifyRule())
    h.tick(1000)
    h.log.raise({ at: h.at() })
    h.tick(1000)
    expect(await h.engine.sweep()).toMatchObject({ fired: 1 })

    const reopened = h.restart()
    expect(await reopened.sweep()).toMatchObject({ read: 0, fired: 0 })
    expect(h.notified).toHaveLength(1)
  })

  it('acts on two events in one millisecond, and neither twice', async () => {
    // The store writes several rows per sweep and `EventCursor` carries a row
    // id for exactly this. A watermark keyed on the timestamp alone either
    // repeats one of these forever or steps over the other.
    const h = harness()
    h.engine.create(notifyRule({ limit: { maxFirings: 10, windowMs: HOUR } }))
    h.tick(1000)
    h.log.raise({ at: h.at(), serverId: 'srv-a' })
    h.log.raise({ at: h.at(), serverId: 'srv-b' })
    h.tick(1000)
    expect(await h.engine.sweep()).toMatchObject({ read: 2, fired: 2 })
    expect(await h.engine.sweep()).toMatchObject({ read: 0, fired: 0 })
  })

  it('reads the alert log and not the rest of the store', async () => {
    const h = harness()
    h.engine.create(notifyRule())
    h.tick(1000)
    h.log.junk(h.at())
    h.tick(1000)
    expect(await h.engine.sweep()).toMatchObject({ read: 0, fired: 0 })
  })

  it('never fires on what happened before the rule was written', async () => {
    const h = harness()
    h.log.raise({ at: h.at() - 60_000 })
    h.engine.create(notifyRule())
    h.tick(1000)
    expect(await h.engine.sweep()).toMatchObject({ fired: 0 })
    expect(h.notified).toEqual([])
  })

  it('never acts on an alert that has gone stale', async () => {
    // The engine was off for two hours. The disk alert from ninety minutes ago
    // has been dealt with or it has not; running a command about it now is
    // arguing with whoever dealt with it.
    const h = harness()
    h.engine.create(notifyRule())
    h.tick(1000)
    h.log.raise({ at: h.at() })
    h.tick(RULE_STALE_EVENT_MS + 60_000)
    expect(await h.engine.sweep()).toMatchObject({ read: 0, fired: 0 })
  })

  it('acts on the oldest event first', async () => {
    // A raise followed by a resolve seen the other way round would leave a
    // rule acting on a condition that had already cleared.
    const h = harness()
    h.engine.create(notifyRule({ limit: { maxFirings: 5, windowMs: HOUR } }))
    h.tick(1000)
    h.log.raise({ at: h.at(), serverName: 'first' })
    h.tick(1000)
    h.log.raise({ at: h.at(), serverName: 'second' })
    h.tick(1000)
    await h.engine.sweep()
    expect(h.notified.map((n) => n.server)).toEqual(['first', 'second'])
  })
})

describe('the rate limit under a flapping source', () => {
  it('acts once for a unit that raises every fifteen seconds for an hour', async () => {
    // 240 raises. One action is what the operator asked for; 240 is an outage
    // with this app's name on it, and 19b already paid for that lesson once.
    const h = harness()
    h.engine.create(notifyRule({ limit: { maxFirings: 1, windowMs: HOUR } }))
    for (let i = 0; i < 240; i++) {
      h.tick(15_000)
      h.log.raise({ at: h.at() })
      await h.engine.sweep()
    }
    expect(h.notified).toHaveLength(1)
  })

  it('collapses a backlog swept in one instant to a single action', async () => {
    // Forty rows arriving between sweeps are forty actions on the estate in
    // one instant if the limit is measured against each row's own timestamp.
    // It is measured in wall clock, which is what the estate experiences.
    const h = harness()
    h.engine.create(notifyRule({ limit: { maxFirings: 1, windowMs: HOUR } }))
    for (let i = 0; i < 40; i++) {
      h.tick(60_000)
      h.log.raise({ at: h.at() })
    }
    h.tick(1000)
    const result = await h.engine.sweep()
    expect(result.read).toBe(40)
    expect(result.fired).toBe(1)
    expect(result.suppressed).toBe(39)
    expect(h.notified).toHaveLength(1)
  })

  it('counts what it suppressed and writes it down once per sweep', async () => {
    const h = harness()
    h.engine.create(notifyRule({ limit: { maxFirings: 1, windowMs: HOUR } }))
    for (let i = 0; i < 5; i++) {
      h.tick(1000)
      h.log.raise({ at: h.at() })
    }
    h.tick(1000)
    await h.engine.sweep()

    const suppressed = h.log.written.filter((w) => w.kind === RULE_EVENT_SUPPRESSED)
    // One row carrying the count, not four rows re-creating the flapping in
    // the store this feature exists to keep it out of.
    expect(suppressed).toHaveLength(1)
    expect(suppressed[0].payload).toMatchObject({ count: 4, name: 'tell me about the disk' })
    expect(h.engine.list()[0].status.suppressed).toBe(4)
  })

  it('holds the rate limit across a restart', async () => {
    // A ledger that lived in memory would hand every rule its whole window back
    // on every launch, and a crash loop would then be an action loop.
    const h = harness()
    h.engine.create(notifyRule({ limit: { maxFirings: 1, windowMs: HOUR } }))
    h.tick(1000)
    h.log.raise({ at: h.at() })
    h.tick(1000)
    expect(await h.engine.sweep()).toMatchObject({ fired: 1 })

    h.tick(60_000)
    h.log.raise({ at: h.at() })
    h.tick(1000)
    const reopened = h.restart()
    expect(await reopened.sweep()).toMatchObject({ fired: 0, suppressed: 1 })
    expect(h.notified).toHaveLength(1)
  })

  it('lets the window slide so a rule is not muted forever', async () => {
    const h = harness()
    h.engine.create(notifyRule({ limit: { maxFirings: 1, windowMs: HOUR } }))
    h.tick(1000)
    h.log.raise({ at: h.at() })
    h.tick(1000)
    await h.engine.sweep()

    h.tick(HOUR)
    h.log.raise({ at: h.at() })
    h.tick(1000)
    expect(await h.engine.sweep()).toMatchObject({ fired: 1 })
    expect(h.notified).toHaveLength(2)
  })
})

describe('running the pinned job', () => {
  it('launches the spec and the targets it was written with', async () => {
    const h = harness()
    h.engine.create(jobRule())
    h.tick(1000)
    h.log.raise({ at: h.at() })
    h.tick(1000)
    expect(await h.engine.sweep()).toMatchObject({ fired: 1 })

    expect(h.launched).toHaveLength(1)
    expect(h.launched[0].spec.steps.map((s) => s.command)).toEqual([
      'journalctl --vacuum-size=200M'
    ])
    expect(h.launched[0].targets.map((t) => t.serverId)).toEqual(['srv-a', 'srv-b'])
    // The record minted at rule-creation, handed over unchanged.
    expect(h.launched[0].approval.commands).toEqual(['journalctl --vacuum-size=200M'])
    expect(h.launched[0].approval.confirmedAt).toBe(T0)
  })

  it('takes nothing from the event that fired it', async () => {
    // The event decides WHETHER, never WHERE. A disk alert on a host that is
    // not in the pinned list must not add that host to the run.
    const h = harness()
    h.engine.create(jobRule())
    h.tick(1000)
    h.log.raise({ at: h.at(), serverId: 'srv-zulu', serverName: 'zulu' })
    h.tick(1000)
    await h.engine.sweep()
    expect(h.launched[0].targets.map((t) => t.serverId)).toEqual(['srv-a', 'srv-b'])
  })

  it('tells the endpoint that the automation ran', async () => {
    const h = harness()
    h.engine.create(jobRule())
    h.tick(1000)
    h.log.raise({ at: h.at() })
    h.tick(1000)
    await h.engine.sweep()
    expect(h.notified[0]).toMatchObject({
      source: 'shellpilot',
      version: '9.9.9',
      kind: 'disk',
      summary:
        'ShellPilot rule "vacuum the journal" started the job "clear the journal" on 2 server(s) after a disk alert raised.'
    })
  })

  it('writes down that it fired', async () => {
    const h = harness()
    h.engine.create(jobRule())
    h.tick(1000)
    h.log.raise({ at: h.at() })
    h.tick(1000)
    await h.engine.sweep()
    const fired = h.log.written.filter((w) => w.kind === RULE_EVENT_FIRED)
    expect(fired).toHaveLength(1)
    expect(fired[0].payload).toMatchObject({ action: 'job', title: 'clear the journal', hosts: 2 })
  })
})

describe('a rule whose job has drifted', () => {
  it('refuses rather than running something else', async () => {
    const h = harness()
    // The rule's spec says one thing; its stored approval covers another. This
    // is what a hand-edited rules file, or a future edit path that forgot to
    // re-confirm, actually looks like on disk.
    h.engine.create(jobRule({ spec: { ...SPEC, steps: [{ command: 'rm -rf /var/log' }] } }))
    h.tick(1000)
    h.log.raise({ at: h.at() })
    h.tick(1000)

    expect(await h.engine.sweep()).toMatchObject({ refused: 1, fired: 0 })
    expect(h.launched).toEqual([])
    const refused = h.log.written.filter((w) => w.kind === RULE_EVENT_REFUSED)
    expect(refused).toHaveLength(1)
    expect((refused[0].payload as { reason: string }).reason).toContain(
      'An edited command needs a fresh confirmation.'
    )
  })

  it('refuses a rule that grew a server', async () => {
    const h = harness()
    h.engine.create(jobRule({ targets: [...TARGETS, { serverId: 'srv-c', serverName: 'charlie' }] }))
    h.tick(1000)
    h.log.raise({ at: h.at() })
    h.tick(1000)
    expect(await h.engine.sweep()).toMatchObject({ refused: 1 })
    expect(h.launched).toEqual([])
    expect(h.engine.list()[0].status.refusal).toContain('charlie')
  })

  it('refuses rather than running on the servers that are left', async () => {
    // A shrunk list is what `verifyApproval` allows for a RESUME, and that is
    // right there — every survivor was in the list a human confirmed. It is
    // wrong here: a rule's claim is that its blast radius was knowable when it
    // was written, and "these three of the five" is not that shape.
    const h = harness({ missingServers: ['srv-b'] })
    h.engine.create(jobRule())
    h.tick(1000)
    h.log.raise({ at: h.at() })
    h.tick(1000)
    expect(await h.engine.sweep()).toMatchObject({ refused: 1, fired: 0 })
    expect(h.launched).toEqual([])
    expect(h.engine.list()[0].status.refusal).toBe(
      'bravo is no longer in this workspace. A rule runs on the server list it was confirmed against or it does not run.'
    )
  })

  it('says so on the panel before it has ever fired', async () => {
    // A refusal discovered only at 3am is a refusal nobody reads. The verdict
    // is re-derived on every list(), so a rule that cannot run reads as one.
    const h = harness()
    h.engine.create(jobRule({ spec: { ...SPEC, steps: [{ command: 'rm -rf /var/log' }] } }))
    const view = h.engine.list()[0]
    expect(view.verdict.ok).toBe(false)
    expect(view.verdict.reason).toContain('An edited command needs a fresh confirmation.')
  })

  it('carries main’s own refusal back to the panel', async () => {
    // The engine is not the last gate: `jobs:run` re-derives planJob over the
    // same spec and target list and can refuse for a reason this side does not
    // know, such as item 17's reboot-ordering block.
    const h = harness()
    h.engine.create(jobRule())
    h.refuseJob('This job was not started: rebooting gateway would cut three servers.')
    h.tick(1000)
    h.log.raise({ at: h.at() })
    h.tick(1000)
    expect(await h.engine.sweep()).toMatchObject({ refused: 1 })
    expect(h.engine.list()[0].status.refusal).toContain('would cut three servers')
  })

  it('a refusal costs the rule a slot in its window', async () => {
    // Otherwise a broken rule is unrate-limited: it matches every event from a
    // flapping source and complains about each one.
    const h = harness()
    h.engine.create(jobRule({ spec: { ...SPEC, steps: [{ command: 'rm -rf /var/log' }] } }))
    for (let i = 0; i < 5; i++) {
      h.tick(1000)
      h.log.raise({ at: h.at() })
    }
    h.tick(1000)
    const r = await h.engine.sweep()
    expect(r.refused).toBe(1)
    expect(r.suppressed).toBe(4)
    expect(h.notified).toHaveLength(1)
  })
})

describe('a disabled rule', () => {
  it('is inert rather than merely hidden', async () => {
    const h = harness()
    const created = h.engine.create(jobRule())!
    expect(h.engine.setEnabled(created.id, false)).toBe(true)
    h.tick(1000)
    h.log.raise({ at: h.at() })
    h.tick(1000)

    const r = await h.engine.sweep()
    // The event was READ — the engine swept normally — and nothing happened.
    expect(r.read).toBe(1)
    expect(r).toMatchObject({ fired: 0, refused: 0, suppressed: 0 })
    expect(h.launched).toEqual([])
    expect(h.notified).toEqual([])
    // And it spent nothing: a disabled rule must not quietly consume its own
    // rate limit, or re-enabling it would find the window already full.
    expect(h.engine.list()[0].status.fired).toEqual([])
    expect(h.engine.list()[0].status.suppressed).toBe(0)
  })

  it('stays inert across a restart', async () => {
    const h = harness()
    const created = h.engine.create(jobRule())!
    h.engine.setEnabled(created.id, false)
    h.tick(1000)
    h.log.raise({ at: h.at() })
    h.tick(1000)

    const reopened = h.restart()
    expect(reopened.list()[0].enabled).toBe(false)
    expect(await reopened.sweep()).toMatchObject({ fired: 0 })
    expect(h.launched).toEqual([])
  })

  it('does not replay what happened while it was off', async () => {
    // Off means off. If enabling replayed the gap, disabling a rule would be
    // the most dangerous button on the panel.
    // Deliberately NO sweep while the rule is off. That is the case that
    // matters: the app was closed for a fortnight, the alerts piled up, and the
    // watermark is still where it was. If re-arming did not move with the
    // switch, enabling would run the job about a fortnight-old condition.
    const h = harness()
    const created = h.engine.create(jobRule())!
    h.engine.setEnabled(created.id, false)
    h.tick(1000)
    h.log.raise({ at: h.at() })
    h.tick(1000)

    h.engine.setEnabled(created.id, true)
    h.tick(1000)
    expect(await h.engine.sweep()).toMatchObject({ read: 1, fired: 0 })
    expect(h.launched).toEqual([])

    // But it is genuinely live again for what happens next.
    h.log.raise({ at: h.at() })
    h.tick(1000)
    expect(await h.engine.sweep()).toMatchObject({ fired: 1 })
  })

  it('keeps the rate limit it had spent when it was switched off', async () => {
    // A rule toggled off and on again has not earned a fresh window; if it had,
    // the toggle would be a way to defeat the rate limit twice a minute.
    const h = harness()
    const created = h.engine.create(notifyRule({ limit: { maxFirings: 1, windowMs: HOUR } }))!
    h.tick(1000)
    h.log.raise({ at: h.at() })
    h.tick(1000)
    expect(await h.engine.sweep()).toMatchObject({ fired: 1 })

    h.engine.setEnabled(created.id, false)
    h.engine.setEnabled(created.id, true)
    h.tick(60_000)
    h.log.raise({ at: h.at() })
    h.tick(1000)
    expect(await h.engine.sweep()).toMatchObject({ fired: 0, suppressed: 1 })
    expect(h.notified).toHaveLength(1)
  })

  it('is removed cleanly, ledger and all', async () => {
    const h = harness()
    const created = h.engine.create(notifyRule())!
    h.tick(1000)
    h.log.raise({ at: h.at() })
    h.tick(1000)
    await h.engine.sweep()
    expect(h.engine.remove(created.id)).toBe(true)
    expect(h.engine.list()).toEqual([])
    expect(h.engine.remove(created.id)).toBe(false)

    h.log.raise({ at: h.at() })
    h.tick(1000)
    expect(await h.engine.sweep()).toMatchObject({ fired: 0 })
  })
})

describe('the engine with nothing under it', () => {
  it('is inert without a history store rather than pretending', async () => {
    const h = harness({ store: null })
    h.engine.create(notifyRule())
    expect(await h.engine.sweep()).toEqual({ read: 0, fired: 0, suppressed: 0, refused: 0, skipped: 0 })
  })

  it('drops a hand-edited rule that could not survive a restart', () => {
    const h = harness()
    // A rules file someone edited by hand, with a trigger nothing writes.
    const broken = { ...notifyRule(), trigger: { kind: 'ram', event: 'raised' } } as unknown as RuleDraft
    expect(h.engine.create(broken)).toBeNull()
    expect(h.engine.list()).toEqual([])
  })

  it('says out loud when a sweep could not reach the whole window', async () => {
    const h = harness()
    h.engine.create(notifyRule())
    h.tick(1000)
    for (let i = 0; i <= RULE_SWEEP_MAX_EVENTS; i++) {
      h.tick(1)
      h.log.raise({ at: h.at() })
    }
    h.tick(1000)
    const r = await h.engine.sweep()
    expect(r.skipped).toBe(1)
    expect(h.log.written.filter((w) => w.kind === RULE_EVENT_SKIPPED)).toHaveLength(1)
  })
})
