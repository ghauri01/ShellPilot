import { describe, it, expect, beforeAll, beforeEach, afterEach, vi } from 'vitest'
import type { StoredAlertEvent, StoredAlertRow } from '../src/shared/webhook'

// Roadmap item 19b: snooze and acknowledge.
//
// The roadmap lists them beside hysteresis and flap suppression, and they are
// the half of the list that belongs to the reader rather than to the algorithm.
// Damping decides that a SIGNAL has stopped tracking anything; these are how a
// person says the same thing about an alert the signal is reporting perfectly
// well. Both are durable, because the first thing somebody does about an app
// that is annoying them is restart it.

const shown: { title: string; body: string }[] = []
const posted: Record<string, unknown>[] = []
const recorded: { event: StoredAlertEvent; at: number | undefined }[] = []

type Alerts = typeof import('../src/renderer/src/store/alerts')
type AppStore = typeof import('../src/renderer/src/store/app')

let alerts: Alerts
let app: AppStore

beforeAll(async () => {
  ;(globalThis as { window?: unknown }).window = {
    shellpilot: {
      getVersion: () => Promise.resolve('9.9.9'),
      notify: {
        show: (title: string, body: string) => {
          shown.push({ title, body })
        }
      },
      webhook: {
        notify: (p: Record<string, unknown>) => {
          posted.push(p)
        }
      },
      alerts: {
        record: (event: StoredAlertEvent, at?: number) => {
          recorded.push({ event, at })
          return Promise.resolve(true)
        },
        history: () => Promise.resolve([] as StoredAlertRow[])
      }
    }
  }
  alerts = await import('../src/renderer/src/store/alerts')
  app = await import('../src/renderer/src/store/app')
})

const raises = (): Record<string, unknown>[] => posted.filter((p) => p.event === 'raised')
const resolves = (): Record<string, unknown>[] => posted.filter((p) => p.event === 'resolved')
const chip = (): Alerts['useAlerts'] extends never ? never : ReturnType<
  Alerts['useAlerts']['getState']
>['active'][string] => alerts.useAlerts.getState().active['s1:disk']

const MINUTE = 60_000
const HOUR = 60 * MINUTE
const T0 = new Date('2026-01-01T00:00:00Z').getTime()

/** One sample. Disk raises strictly above 85 and clears at 80 or below. */
function sample(disk: number | null): void {
  alerts.checkResourceAlerts('s1', 'web-1', { cpu: 0, ram: 0, disk, inode: null, load: null })
}

function loggedRows(): StoredAlertRow[] {
  return recorded.map((r) => ({ ...r.event, at: r.at ?? 0 })).sort((a, b) => b.at - a.at)
}

function restart(rows: StoredAlertRow[]): void {
  alerts.resetAlertsForTests()
  app.useApp.getState().setSettings({ resourceAlertsEnabled: true, resourceAlertThreshold: 80 })
  alerts.applyStoredAlerts(rows)
}

beforeEach(() => {
  shown.length = 0
  posted.length = 0
  recorded.length = 0
  alerts.resetAlertsForTests()
  app.useApp.getState().setSettings({ resourceAlertsEnabled: true, resourceAlertThreshold: 80 })
  vi.useFakeTimers()
  vi.setSystemTime(T0)
})

afterEach(() => {
  vi.useRealTimers()
})

describe('snooze', () => {
  it('stops the repeat and keeps the chip, because the condition has not changed', () => {
    sample(91)
    expect(raises()).toHaveLength(1)
    alerts.snoozeAlert('s1', 'disk', 8 * HOUR)
    // The chip is still there and now says why it has gone quiet.
    expect(chip()).toBeDefined()
    expect(chip().snoozedUntil).toBe(T0 + 8 * HOUR)

    // Six hours later the ordinary repeat window would have fired.
    vi.setSystemTime(T0 + 7 * HOUR)
    sample(91)
    expect(raises()).toHaveLength(1)
  })

  it('speaks again when the snooze runs out', () => {
    sample(91)
    alerts.snoozeAlert('s1', 'disk', HOUR)
    vi.setSystemTime(T0 + 30 * MINUTE)
    sample(91)
    expect(raises()).toHaveLength(1)
    // An hour and a repeat window later.
    vi.setSystemTime(T0 + 7 * HOUR)
    sample(91)
    expect(raises()).toHaveLength(2)
  })

  it('still escalates, because monotone movement is not what was snoozed', () => {
    sample(86)
    expect(raises()).toHaveLength(1)
    alerts.snoozeAlert('s1', 'disk', 8 * HOUR)
    vi.setSystemTime(T0 + MINUTE)
    sample(88)
    expect(raises()).toHaveLength(1)
    // Five points worse than the figure last announced. Someone who snoozed a
    // disk at 86% did not snooze it at 96%.
    vi.setSystemTime(T0 + 2 * MINUTE)
    sample(96)
    expect(raises()).toHaveLength(2)
    expect(raises()[1].value).toBe(96)
  })

  it('holds the all-clear too, and lets it out when the snooze ends', () => {
    sample(91)
    alerts.snoozeAlert('s1', 'disk', HOUR)
    vi.setSystemTime(T0 + MINUTE)
    sample(40)
    // Half of an alert's noise is all-clears. A snooze that let them through
    // would be half a snooze.
    expect(resolves()).toHaveLength(0)
    // The outstanding alarm is left standing, so the endpoint's view when the
    // snooze ends is whichever of a repeat or an all-clear is then true.
    vi.setSystemTime(T0 + 2 * HOUR)
    sample(40)
    expect(resolves()).toHaveLength(1)
  })

  it('survives a restart', () => {
    sample(91)
    alerts.snoozeAlert('s1', 'disk', 8 * HOUR)
    const rows = loggedRows()
    restart(rows)
    posted.length = 0
    vi.setSystemTime(T0 + 7 * HOUR)
    sample(91)
    expect(raises()).toHaveLength(0)
    expect(chip()).toBeDefined()
  })

  it('ends early when asked, and says so on the wire’s next opportunity', () => {
    sample(91)
    alerts.snoozeAlert('s1', 'disk', 8 * HOUR)
    expect(chip().snoozedUntil).toBe(T0 + 8 * HOUR)
    vi.setSystemTime(T0 + MINUTE)
    alerts.unsnoozeAlert('s1', 'disk')
    expect(chip().snoozedUntil).toBeUndefined()
    vi.setSystemTime(T0 + 7 * HOUR)
    sample(91)
    expect(raises()).toHaveLength(2)
  })

  it('is not extended by anything the estate does', () => {
    // A crossing while DAMPED refreshes the damp to six hours. A crossing while
    // snoozed must not, or a thirty-minute snooze becomes a six-hour one and
    // the app has decided how long the user meant.
    sample(91)
    alerts.snoozeAlert('s1', 'disk', 30 * MINUTE)
    for (let i = 1; i <= 3; i++) {
      vi.setSystemTime(T0 + i * 5 * MINUTE)
      sample(60)
      vi.setSystemTime(T0 + i * 5 * MINUTE + MINUTE)
      sample(91)
    }
    expect(raises()).toHaveLength(1)
    // Thirty minutes and a repeat window later, it speaks — it was not extended.
    vi.setSystemTime(T0 + 7 * HOUR)
    sample(91)
    expect(raises()).toHaveLength(2)
  })
})

describe('acknowledge', () => {
  it('takes the chip and stays quiet for as long as the condition lasts', () => {
    sample(91)
    expect(raises()).toHaveLength(1)
    alerts.acknowledgeAlert('s1', 'disk')
    expect(chip()).toBeUndefined()

    // A full day later, still full, still nothing said and still no chip. This
    // is the difference from a snooze: cleaning a disk takes as long as it
    // takes, and an acknowledgement on a clock would start shouting in the
    // middle of the work it acknowledged.
    for (const h of [7, 14, 21, 28]) {
      vi.setSystemTime(T0 + h * HOUR)
      sample(91)
    }
    expect(raises()).toHaveLength(1)
    expect(chip()).toBeUndefined()
  })

  it('still posts the all-clear, so the endpoint is not left holding an alarm', () => {
    sample(91)
    alerts.acknowledgeAlert('s1', 'disk')
    vi.setSystemTime(T0 + 3 * HOUR)
    sample(40)
    expect(resolves()).toHaveLength(1)
    expect(resolves()[0].summary).toContain('back to 85% or below')
  })

  it('ends with the condition, so the next crossing is heard', () => {
    sample(91)
    alerts.acknowledgeAlert('s1', 'disk')
    vi.setSystemTime(T0 + 3 * HOUR)
    sample(40)
    posted.length = 0
    vi.setSystemTime(T0 + 4 * HOUR)
    sample(91)
    expect(raises()).toHaveLength(1)
    expect(alerts.useAlerts.getState().active['s1:disk']).toBeDefined()
  })

  it('survives a restart', () => {
    sample(91)
    alerts.acknowledgeAlert('s1', 'disk')
    restart(loggedRows())
    posted.length = 0
    vi.setSystemTime(T0 + 7 * HOUR)
    sample(91)
    expect(raises()).toHaveLength(0)
    expect(alerts.useAlerts.getState().active['s1:disk']).toBeUndefined()
  })

  it('works on a kind that has no number', () => {
    alerts.checkStateAlert('t1', 'office-db', 'tunnel-down', true)
    expect(raises()).toHaveLength(1)
    alerts.acknowledgeAlert('t1', 'tunnel-down')
    expect(alerts.useAlerts.getState().active['t1:tunnel-down']).toBeUndefined()
    // Still down, sweep after sweep, and now silent.
    for (let i = 1; i <= 5; i++) {
      vi.setSystemTime(T0 + i * HOUR)
      alerts.checkStateAlert('t1', 'office-db', 'tunnel-down', true)
    }
    expect(raises()).toHaveLength(1)
    expect(alerts.useAlerts.getState().active['t1:tunnel-down']).toBeUndefined()
  })

  it('ends when the tunnel comes back, so the NEXT failure is heard', () => {
    // The condition ending is what ends an acknowledgement, and for a state
    // kind that is the tunnel coming up rather than a number falling. The
    // reader acknowledged this outage; they did not acknowledge the next one.
    alerts.checkStateAlert('t1', 'office-db', 'tunnel-down', true)
    alerts.acknowledgeAlert('t1', 'tunnel-down')
    vi.setSystemTime(T0 + HOUR)
    alerts.checkStateAlert('t1', 'office-db', 'tunnel-down', false)
    posted.length = 0
    vi.setSystemTime(T0 + 2 * HOUR)
    alerts.checkStateAlert('t1', 'office-db', 'tunnel-down', true)
    expect(raises()).toHaveLength(1)
    expect(alerts.useAlerts.getState().active['t1:tunnel-down']).toBeDefined()
  })

  it('replaces a snooze rather than layering over it', () => {
    sample(91)
    alerts.snoozeAlert('s1', 'disk', HOUR)
    vi.setSystemTime(T0 + MINUTE)
    alerts.acknowledgeAlert('s1', 'disk')
    // Long after the snooze would have run out.
    vi.setSystemTime(T0 + 12 * HOUR)
    sample(91)
    expect(raises()).toHaveLength(1)
  })

  it('leaves no snooze behind, so the next crossing after it ends is heard', () => {
    // Acknowledging while snoozed must clear the snooze, not sit on top of it.
    // Otherwise the acknowledgement ends with its condition — correctly — and a
    // stale eight-hour snooze nobody can see goes on silencing the next one.
    sample(91)
    alerts.snoozeAlert('s1', 'disk', 8 * HOUR)
    vi.setSystemTime(T0 + MINUTE)
    alerts.acknowledgeAlert('s1', 'disk')
    vi.setSystemTime(T0 + HOUR)
    sample(40)
    posted.length = 0
    vi.setSystemTime(T0 + 2 * HOUR)
    sample(91)
    expect(raises()).toHaveLength(1)
  })

  it('leaves no snooze behind ACROSS A RESTART either', () => {
    // The same rule, put through the one thing a person does when an app is
    // annoying them. The live mutators are mutually exclusive; the replay
    // branches only ever ADDED, so a restart resurrected the snooze the
    // acknowledgement had replaced — and then `isQuiet` held the all-clear
    // back, leaving the endpoint with an alarm nothing will ever close.
    sample(91)
    alerts.snoozeAlert('s1', 'disk', 8 * HOUR)
    vi.setSystemTime(T0 + MINUTE)
    alerts.acknowledgeAlert('s1', 'disk')

    restart(loggedRows())
    posted.length = 0
    // The disk is cleaned an hour later, which is what ends an acknowledgement.
    vi.setSystemTime(T0 + HOUR)
    sample(40)
    expect(resolves()).toHaveLength(1)
  })

  it('is replaced by a snooze, which has an end the acknowledgement did not', () => {
    // The other direction. Snoozing something already acknowledged is a person
    // narrowing an open-ended silence to a period, and the period has to win.
    sample(91)
    vi.setSystemTime(T0 + MINUTE)
    alerts.acknowledgeAlert('s1', 'disk')
    vi.setSystemTime(T0 + 2 * MINUTE)
    alerts.snoozeAlert('s1', 'disk', HOUR)
    expect(alerts.useAlerts.getState().active['s1:disk']).toBeUndefined()
    // An hour and a repeat window later it speaks, which it never would have
    // done under the acknowledgement it replaced.
    vi.setSystemTime(T0 + 7 * HOUR)
    sample(91)
    expect(raises()).toHaveLength(2)
  })

  it('is replaced by a snooze ACROSS A RESTART too', () => {
    // The mirror of the case above, and the worse half of it: a stale
    // acknowledgement outlives the snooze that replaced it, and an
    // acknowledgement only ends when the condition does. Twelve hours later,
    // on a 91% disk, that is silence with no chip and nothing to un-silence.
    sample(91)
    vi.setSystemTime(T0 + MINUTE)
    alerts.acknowledgeAlert('s1', 'disk')
    vi.setSystemTime(T0 + 2 * MINUTE)
    alerts.snoozeAlert('s1', 'disk', HOUR)

    restart(loggedRows())
    posted.length = 0
    vi.setSystemTime(T0 + 12 * HOUR)
    sample(91)
    expect(raises()).toHaveLength(1)
    expect(alerts.useAlerts.getState().active['s1:disk']).toBeDefined()
  })

  it('is undone by switching alerting off and on, like everything else', () => {
    sample(91)
    alerts.acknowledgeAlert('s1', 'disk')
    app.useApp.getState().setSettings({ resourceAlertsEnabled: false })
    app.useApp.getState().setSettings({ resourceAlertsEnabled: true })
    posted.length = 0
    vi.setSystemTime(T0 + MINUTE)
    sample(91)
    expect(raises()).toHaveLength(1)
  })
})

describe('what goes in the log', () => {
  it('records a snooze with the moment it ends, not a duration', () => {
    sample(91)
    alerts.snoozeAlert('s1', 'disk', 8 * HOUR)
    const row = recorded.find((r) => r.event.event === 'snoozed')
    expect(row).toBeDefined()
    expect(row?.event.until).toBe(T0 + 8 * HOUR)
    expect(row?.event.kind).toBe('disk')
    expect(row?.event.serverName).toBe('web-1')
  })

  it('records an acknowledgement with no expiry, because it has none', () => {
    sample(91)
    alerts.acknowledgeAlert('s1', 'disk')
    const row = recorded.find((r) => r.event.event === 'acknowledged')
    expect(row).toBeDefined()
    expect(row?.event.until).toBeUndefined()
  })
})
