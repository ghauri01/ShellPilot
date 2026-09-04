import { describe, it, expect, beforeAll, beforeEach, afterEach, vi } from 'vitest'
import type { StoredAlertEvent, StoredAlertRow } from '../src/shared/webhook'

// Roadmap item 19b, stage 2.
//
// RECOVER_MARGIN already stops an alert oscillating on the noise in a single
// reading: a resolve only registers five points below the line. Nothing stopped
// a host that crosses CLEANLY and repeatedly — all the way down through the
// recovery margin and back over the line, over and over. Every one of those is
// a new incident by every rule 19a wrote, and the roadmap is literal about
// where that ends: "a disk alert that fires forty times overnight gets the
// whole feature muted, which is worse than not shipping it."

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

const MINUTE = 60_000
const HOUR = 60 * MINUTE

function sample(disk: number | null): void {
  alerts.checkResourceAlerts('s1', 'web-1', { cpu: 0, ram: 0, disk, inode: null, load: null })
}

/**
 * One clean crossing: over the line, then all the way below the recovery
 * margin. `disk` clears at 80 (DISK_DANGER 85 less RECOVER_MARGIN 5), so 60 is
 * unambiguously recovered.
 */
function crossOnce(at: number, high = 91): void {
  vi.setSystemTime(at)
  sample(high)
  vi.setSystemTime(at + MINUTE)
  sample(60)
}

beforeEach(() => {
  shown.length = 0
  posted.length = 0
  recorded.length = 0
  alerts.resetAlertsForTests()
  app.useApp.getState().setSettings({ resourceAlertsEnabled: true, resourceAlertThreshold: 80 })
  vi.useFakeTimers()
  vi.setSystemTime(new Date('2026-01-01T00:00:00Z'))
})

afterEach(() => {
  vi.useRealTimers()
})

const T0 = Date.parse('2026-01-01T00:00:00Z')

describe('a server that crosses cleanly and repeatedly', () => {
  it('is not the reason for forty messages overnight', () => {
    // Forty crossings spread over twelve hours, which is what "overnight" is.
    for (let i = 0; i < 40; i++) crossOnce(T0 + i * 18 * MINUTE)
    // Five are said and the rest are not. The number is exact rather than a
    // bound, because a bound would still pass if damping fired on the first
    // crossing and said nothing at all — which is the same failure seen from
    // the other side.
    expect(raises().length).toBe(5)
    expect(raises().map((p) => p.value)).toEqual([91, 91, 91, 91, 91])
  })

  it('says the first five and then goes quiet', () => {
    for (let i = 0; i < 5; i++) crossOnce(T0 + i * 5 * MINUTE)
    expect(raises().length).toBe(5)
    // The sixth and seventh crossings.
    crossOnce(T0 + 30 * MINUTE)
    crossOnce(T0 + 35 * MINUTE)
    expect(raises().length).toBe(5)
  })

  it('damps the all-clears too, which are half of a flap’s noise', () => {
    for (let i = 0; i < 5; i++) crossOnce(T0 + i * 5 * MINUTE)
    // Four, not five: the damp trips ON the fifth raise, so that crossing's own
    // recovery is already inside it.
    expect(resolves().length).toBe(4)
    crossOnce(T0 + 30 * MINUTE)
    crossOnce(T0 + 35 * MINUTE)
    expect(resolves().length).toBe(4)
  })

  it('speaks again once it has gone six hours without crossing', () => {
    for (let i = 0; i < 5; i++) crossOnce(T0 + i * 5 * MINUTE)
    // Two more crossings while damped. Each one refreshes the damp, which is
    // what makes forty overnight into five rather than into ten.
    crossOnce(T0 + HOUR)
    crossOnce(T0 + 2 * HOUR)
    expect(raises().length).toBe(5)
    // Five hours after the last crossing is not yet enough.
    crossOnce(T0 + 7 * HOUR)
    expect(raises().length).toBe(5)
    // Six clear hours after that one is.
    crossOnce(T0 + 13 * HOUR + MINUTE)
    expect(raises().length).toBe(6)
    expect(raises()[5].value).toBe(91)
  })

  it('says out loud that it is going quiet, and tells the endpoint too', () => {
    for (let i = 0; i < 5; i++) crossOnce(T0 + i * 5 * MINUTE)
    const last = shown[shown.length - 1]
    expect(last.body).toContain('crossed the line 5 times in 6 hours')
    expect(last.body).toContain('until it has gone 6 hours without crossing again')
    expect(last.body).toContain('Alerts tab still lists every crossing')
    const damped = raises().filter((p) => p.damped === true)
    expect(damped.length).toBe(1)
    expect(damped[0].value).toBe(91)
  })
})

describe('what damping must not touch', () => {
  it('leaves the chip following the condition', () => {
    for (let i = 0; i < 8; i++) crossOnce(T0 + i * 5 * MINUTE)
    // Damped, and still over the line right now.
    vi.setSystemTime(T0 + 45 * MINUTE)
    sample(93)
    expect(alerts.useAlerts.getState().list().map((a) => a.kind)).toEqual(['disk'])
    vi.setSystemTime(T0 + 46 * MINUTE)
    sample(60)
    expect(alerts.useAlerts.getState().list()).toEqual([])
  })

  it('records every crossing in the durable log, including the damped ones', () => {
    for (let i = 0; i < 8; i++) crossOnce(T0 + i * 5 * MINUTE)
    // Five raises spoken and recorded; the three damped crossings are not
    // spoken. The log is what the inbox reads, and the chip is what the status
    // bar reads — this asserts the log still carries the spoken five.
    expect(recorded.filter((r) => r.event.event === 'raised').length).toBe(5)
    expect(recorded.filter((r) => r.event.event === 'resolved').length).toBe(4)
  })

  it('still escalates through a damp when the value gets materially worse', () => {
    for (let i = 0; i < 5; i++) crossOnce(T0 + i * 5 * MINUTE, 86)
    expect(raises().length).toBe(5)
    // Damped. A disk that then climbs from the 86 last announced to 96 is
    // monotone movement, which is the one shape a flap never has.
    vi.setSystemTime(T0 + 40 * MINUTE)
    sample(96)
    expect(raises().length).toBe(6)
    expect(raises()[5].value).toBe(96)
  })

  it('does not damp a sustained alert that never recovers', () => {
    // The defect this rule had to avoid: CPU repeats every sixty seconds, so
    // counting REPEATS rather than crossings would damp a genuinely pegged
    // processor after five minutes. Ten minutes of a disk over the line, at its
    // own six-hour window, is one message either way — so this is checked on
    // CPU, where the window is a minute and ten repeats are expected.
    for (let i = 0; i < 10; i++) {
      vi.setSystemTime(T0 + i * 2 * MINUTE)
      alerts.checkResourceAlerts('s2', 'db-1', { cpu: 95, ram: 0, disk: null, inode: null, load: null })
    }
    const cpu = raises().filter((p) => p.kind === 'cpu')
    expect(cpu.length).toBe(10)
    expect(cpu.every((p) => p.damped === undefined)).toBe(true)
  })

  it('damps one server+kind without silencing another server', () => {
    for (let i = 0; i < 8; i++) crossOnce(T0 + i * 5 * MINUTE)
    vi.setSystemTime(T0 + 45 * MINUTE)
    alerts.checkResourceAlerts('s2', 'db-1', { cpu: 0, ram: 0, disk: 93, inode: null, load: null })
    const other = raises().filter((p) => p.server === 'db-1')
    expect(other.length).toBe(1)
    expect(other[0].kind).toBe('disk')
  })
})

describe('the damp survives a restart', () => {
  it('does not hand a flapping server a clean slate at every launch', () => {
    for (let i = 0; i < 4; i++) crossOnce(T0 + i * 5 * MINUTE)
    expect(raises().length).toBe(4)
    // The restart happens with the host recovered, which is the case that would
    // otherwise hand it a clean slate.
    const log: StoredAlertRow[] = recorded
      .map((r, i) => ({ ...r.event, at: r.at ?? 0, i }))
      .sort((a, b) => b.at - a.at || b.i - a.i)
      .map(({ i: _i, ...row }) => row)

    posted.length = 0
    alerts.resetAlertsForTests()
    alerts.applyStoredAlerts(log)
    // The fifth crossing, after the restart, still trips the damp.
    crossOnce(T0 + 25 * MINUTE)
    expect(raises().length).toBe(1)
    expect(raises()[0].damped).toBe(true)
    crossOnce(T0 + 35 * MINUTE)
    expect(raises().length).toBe(1)
  })
})
