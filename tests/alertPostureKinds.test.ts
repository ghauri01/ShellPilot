import { describe, it, expect, beforeAll, beforeEach, afterEach, vi } from 'vitest'
import type { StoredAlertEvent, StoredAlertRow } from '../src/shared/webhook'
import { NUMERIC_ALERT_KINDS, STATE_ALERT_KINDS } from '../src/shared/webhook'
import { COVERAGE_SOURCE, alertCoverageLines } from '../src/renderer/src/components/settings/alertCoverage'

// The two kinds roadmap item 19b deferred, on the alert bus.
//
// They do not take the same shape, and saying which is which is half the item:
//
//   cert-expiry  NUMERIC. Days remaining is a number against a line, with a
//                real recovery (a renewal takes it from 3 to 89) and real
//                monotone movement (30 → 21 → 14 → 7). It is the first numeric
//                kind whose number runs DOWNWARDS, so what these cases are
//                really pinning is that the recovery margin, the escalation
//                step and the recovery test were all inverted together rather
//                than one of the three being left pointing the old way.
//
//   oom-kill     STATE. It holds a condition — "this host has killed a process
//                for memory inside the window" — which can be observed to
//                become false when the journal's fixed window rolls past the
//                last kill. That observable resolve is exactly what an event
//                kind cannot have, and it is why this is not one.

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
const chips = (): string[] => alerts.useAlerts.getState().list().map((a) => a.kind).sort()

const DAY = 24 * 60 * 60 * 1000
const T0 = new Date('2026-01-01T00:00:00Z').getTime()

/** One posture sweep's certificate answer for web-1. */
const cert = (days: number | null): void => alerts.checkCertificateAlert('s1', 'web-1', days)
/** One posture sweep's OOM answer for web-1. */
const oom = (bad: boolean | null, detail = ''): void =>
  alerts.checkStateAlert('s1', 'web-1', 'oom-kill', bad, detail)

beforeEach(() => {
  shown.length = 0
  posted.length = 0
  recorded.length = 0
  alerts.resetAlertsForTests()
  app.useApp.getState().setSettings({ resourceAlertsEnabled: true, resourceAlertThreshold: 90 })
  vi.useFakeTimers()
  vi.setSystemTime(T0)
})

afterEach(() => {
  vi.useRealTimers()
})

// ---------------------------------------------------------------------------
// Which kind is which
// ---------------------------------------------------------------------------

describe('the two kinds take the shapes the item says they take', () => {
  it('files certificate expiry with the numbers and OOM kills with the states', () => {
    expect(NUMERIC_ALERT_KINDS).toContain('cert-expiry')
    expect(NUMERIC_ALERT_KINDS).not.toContain('oom-kill')
    expect(STATE_ALERT_KINDS).toContain('oom-kill')
    expect(STATE_ALERT_KINDS).not.toContain('cert-expiry')
  })
})

// ---------------------------------------------------------------------------
// cert-expiry: a number that runs the other way
// ---------------------------------------------------------------------------

describe('a certificate running out', () => {
  it('says nothing at thirty-one days and speaks at thirty', () => {
    cert(31)
    expect(raises()).toHaveLength(0)
    expect(chips()).toEqual([])

    cert(30)
    expect(raises()).toHaveLength(1)
    expect(chips()).toEqual(['cert-expiry'])
    expect(shown[0].title).toBe('web-1: Certificate 30 days from expiry')
  })

  it('reads differently once it has ACTUALLY expired', () => {
    // The number goes negative, and "at -3 days" is not a sentence anybody
    // should have to decode at three in the morning. An expired certificate is
    // an outage in progress; one expiring in three days is not.
    cert(-3)
    expect(shown[0].title).toBe('web-1: Certificate 3 days PAST expiry')
    expect(raises()[0].summary).toBe(
      'web-1: The soonest certificate on this host 3 days PAST expiry (threshold 30 days)'
    )
  })

  it('says "expiring today" rather than "0 days from expiry"', () => {
    cert(0)
    expect(shown[0].title).toBe('web-1: Certificate expiring today')
  })

  it('announces the day it actually expires, without waiting out the daily window', () => {
    // The step rule alone does not carry this. ESCALATE_BY is seven days, so
    // one-day-left to one-day-past is a two-day move and would have been left
    // to the next repeat — up to a day after the certificate stopped working,
    // which is the one moment this kind exists for.
    //
    // Zero is a boundary for a downward kind rather than another number on the
    // scale: on one side the service works and on the other it does not, so
    // crossing it is a change of kind, not of degree.
    cert(1)
    expect(raises()).toHaveLength(1)

    cert(-1)
    expect(raises()).toHaveLength(2)
    expect(shown[1].title).toBe('web-1: Certificate 1 days PAST expiry')
  })

  it('does not treat every step below the line as a crossing', () => {
    // The negative here is the paired assertion: without it the rule above
    // could be "always escalate for a downward kind", which would announce a
    // certificate every single day of the month before it expires.
    cert(20)
    expect(raises()).toHaveLength(1)

    cert(18)
    expect(raises()).toHaveLength(1)
  })

  it('escalates when it gets a week worse, without waiting out the daily window', () => {
    // Monotone movement towards an outage is the one shape a flap never has,
    // and a fortnight of silence between 29 days and 8 is how a certificate
    // expires under an alerting system that was technically working.
    cert(29)
    expect(raises()).toHaveLength(1)

    vi.setSystemTime(T0 + 60 * 60 * 1000)
    cert(22)
    expect(raises()).toHaveLength(2)
    expect(shown[1].title).toBe('web-1: Certificate 22 days from expiry')
  })

  it('does not escalate for a day passing, which is what the window is for', () => {
    cert(29)
    vi.setSystemTime(T0 + 60 * 60 * 1000)
    cert(28)
    vi.setSystemTime(T0 + 2 * 60 * 60 * 1000)
    cert(27)
    expect(raises()).toHaveLength(1)
  })

  it('repeats once a day while it stays true', () => {
    cert(20)
    expect(raises()).toHaveLength(1)
    vi.setSystemTime(T0 + DAY - 1000)
    cert(20)
    expect(raises()).toHaveLength(1)
    vi.setSystemTime(T0 + DAY)
    cert(20)
    expect(raises()).toHaveLength(2)
  })

  it('posts the all-clear when it is renewed', () => {
    cert(20)
    vi.setSystemTime(T0 + DAY)
    cert(89)
    expect(resolves()).toHaveLength(1)
    expect(resolves()[0].summary).toBe(
      'web-1: The soonest certificate on this host renewed and back above 30 days'
    )
    expect(chips()).toEqual([])
  })

  it('does not treat stepping just off the line as a renewal for the purpose of speaking again', () => {
    // The recovery margin, inverted. Thirty-one days is off the line and is
    // not a renewal — nothing renews a certificate to thirty-one days — so a
    // reading back under the line has not made a round trip through recovery
    // and does not earn a fresh raise.
    cert(25)
    expect(raises()).toHaveLength(1)
    vi.setSystemTime(T0 + 60 * 60 * 1000)
    cert(31)
    expect(chips()).toEqual([])
    vi.setSystemTime(T0 + 2 * 60 * 60 * 1000)
    cert(25)
    expect(raises()).toHaveLength(1)

    // A real renewal, past the margin, IS a round trip — and the next expiry
    // months later is heard at once rather than waiting out a window.
    vi.setSystemTime(T0 + 3 * 60 * 60 * 1000)
    cert(89)
    vi.setSystemTime(T0 + 4 * 60 * 60 * 1000)
    cert(25)
    expect(raises()).toHaveLength(2)
  })

  it('never raises, resolves or reads as healthy when nothing could be dated', () => {
    // null covers a refused /etc/letsencrypt, a certificate that would not
    // parse, and a host that genuinely has none. All three must be silent
    // rather than fine.
    cert(null)
    expect(raises()).toHaveLength(0)
    expect(chips()).toEqual([])

    cert(12)
    expect(raises()).toHaveLength(1)

    // And a later sweep that could not read them is NOT a renewal.
    vi.setSystemTime(T0 + DAY)
    cert(null)
    expect(resolves()).toHaveLength(0)
    expect(chips()).toEqual(['cert-expiry'])
  })

  it('puts days on the chip, not a percentage', () => {
    cert(12)
    const chip = alerts.useAlerts.getState().list()[0]
    expect(alerts.chipValue(chip)).toBe(' 12d left')
  })

  it('writes the raise to the durable log under its own kind', () => {
    cert(12)
    expect(recorded.map((r) => `${r.event.kind}:${r.event.event}`)).toEqual(['cert-expiry:raised'])
    expect(recorded[0].event.threshold).toBe(30)
    expect(recorded[0].event.value).toBe(12)
  })
})

// ---------------------------------------------------------------------------
// oom-kill: a state with an observable resolve
// ---------------------------------------------------------------------------

describe('a host killing processes for memory', () => {
  it('speaks once on the crossing and says what was killed', () => {
    oom(true, '3 killed across 2 processes')
    expect(raises()).toHaveLength(1)
    expect(raises()[0].summary).toBe(
      'web-1 has killed a process for memory (3 killed across 2 processes)'
    )
    expect(chips()).toEqual(['oom-kill'])
  })

  it('does not repeat while it is still true, because there is nothing to add', () => {
    oom(true, '3 killed across 2 processes')
    for (let h = 1; h <= 8; h++) {
      vi.setSystemTime(T0 + h * 60 * 60 * 1000)
      oom(true, '3 killed across 2 processes')
    }
    expect(raises()).toHaveLength(1)
  })

  it('posts the all-clear when the window rolls past the last kill', () => {
    // This is the observation that makes it a state kind rather than an event
    // one: the journal is asked for a fixed window, so a day later it answers
    // zero and the condition really has become false.
    oom(true, '1 killed across 1 process')
    vi.setSystemTime(T0 + DAY)
    oom(false)
    expect(resolves()).toHaveLength(1)
    expect(resolves()[0].summary).toBe('web-1 has recorded no further OOM kill for a day')
    expect(chips()).toEqual([])
  })

  it('never raises, resolves or reads as healthy when the kernel log could not be read', () => {
    // The line this kind was deferred over. A restricted dmesg, a root-only
    // journal and a ring-buffer zero all arrive here as null.
    oom(null)
    expect(raises()).toHaveLength(0)
    expect(chips()).toEqual([])

    oom(true, '2 killed across 1 process')
    expect(raises()).toHaveLength(1)

    // And the next sweep failing to read the journal is NOT a recovery.
    vi.setSystemTime(T0 + DAY)
    oom(null)
    expect(resolves()).toHaveLength(0)
    expect(chips()).toEqual(['oom-kill'])
  })

  it('carries no number, because it has none', () => {
    oom(true, '2 killed across 1 process')
    const chip = alerts.useAlerts.getState().list()[0]
    expect(chip.value).toBeNull()
    expect(alerts.chipValue(chip)).toBe('')
    expect(recorded[0].event.value).toBeUndefined()
    expect(recorded[0].event.threshold).toBeUndefined()
  })

  it('is heard again after a second occurrence, once the first has resolved', () => {
    oom(true, '1 killed across 1 process')
    vi.setSystemTime(T0 + DAY)
    oom(false)
    vi.setSystemTime(T0 + 2 * DAY)
    oom(true, '4 killed across 1 process')
    expect(raises()).toHaveLength(2)
    expect(raises()[1].summary).toBe('web-1 has killed a process for memory (4 killed across 1 process)')
  })
})

// ---------------------------------------------------------------------------
// What the coverage row is allowed to claim about them
// ---------------------------------------------------------------------------

describe('coverage stays honest about where these two come from', () => {
  it('does not file them under the sampler, the app root or read-on-demand', () => {
    expect(COVERAGE_SOURCE['oom-kill']).toBe('posture-sweep')
    expect(COVERAGE_SOURCE['cert-expiry']).toBe('posture-sweep')
  })

  it('names the SECOND switch the other three sources do not have', () => {
    const row = alertCoverageLines(true, true).find((l) => l.source === 'posture-sweep')
    expect(row, 'no posture-sweep row — this assertion checked nothing').toBeDefined()
    expect(row?.kinds.sort()).toEqual(['cert-expiry', 'oom-kill'])
    expect(row?.text).toContain('Security posture module')
    // And it must not borrow the sampler's promise, which is the sentence this
    // whole file exists to keep honest.
    expect(row?.text).toContain('not even while a monitor is on screen')
  })

  it('leaves the sampler row speaking only for the kinds the sampler produces', () => {
    const sampler = alertCoverageLines(true, true).find((l) => l.source === 'sampler')
    expect(sampler?.kinds).not.toContain('oom-kill')
    expect(sampler?.kinds).not.toContain('cert-expiry')
  })
})
