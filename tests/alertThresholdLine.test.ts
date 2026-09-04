import { describe, it, expect, beforeAll, beforeEach, afterEach, vi } from 'vitest'
import type { StoredAlertEvent, StoredAlertRow } from '../src/shared/webhook'

// Roadmap item 19b: the number in the box has to be the number it fires at.
//
// CPU and memory were compared against `threshold - RECOVER_MARGIN`, so a host
// alerted five points below its line. With a single global 80 that was one
// wrong sentence nobody had chosen. With a per-host text box the user types the
// number, is told it fires there, and it fired five points lower: a threshold of
// 50 raised at 45, with `threshold: 50` on the wire, a summary reading "CPU at
// 45% (threshold 50%)" and a desktop body reading "CPU has been at or above 50%"
// — at 45. At THRESHOLD_MIN, the real line was below the minimum the UI claims
// to enforce.
//
// The recovery margin survives where it belongs: on the decision to SPEAK
// again. `lastNotifiedValue` is only dropped once the value is five points
// below the line, so a host stepping back over it does not earn a fresh raise.

const shown: { title: string; body: string }[] = []
const posted: Record<string, unknown>[] = []

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
        record: () => Promise.resolve(true),
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
const T0 = new Date('2026-01-01T00:00:00Z').getTime()

const sample = (cpu: number): void =>
  alerts.checkResourceAlerts('s1', 'web-1', { cpu, ram: null, disk: null, inode: null, load: null })

beforeEach(() => {
  shown.length = 0
  posted.length = 0
  alerts.resetAlertsForTests()
  app.useApp.getState().setSettings({
    resourceAlertsEnabled: true,
    resourceAlertThreshold: 80,
    resourceAlertThresholds: { s1: 50 }
  })
  vi.useFakeTimers()
  vi.setSystemTime(T0)
})

afterEach(() => {
  vi.useRealTimers()
})

// A silenced `record` is enough here: what is on trial is the line, not the log.
void ({} as StoredAlertEvent)

describe('a server held to a line its owner typed', () => {
  it('says nothing five points below the number in the box', () => {
    // The reproduction. A per-host threshold of 50 and a CPU of 45.
    sample(45)
    expect(raises()).toHaveLength(0)
    expect(shown).toHaveLength(0)
    expect(alerts.useAlerts.getState().active['s1:cpu']).toBeUndefined()
  })

  it('raises at the number in the box, and says that number', () => {
    sample(50)
    expect(raises()).toHaveLength(1)
    expect(raises()[0].value).toBe(50)
    expect(raises()[0].threshold).toBe(50)
    expect(raises()[0].summary).toBe('web-1: CPU at 50% (threshold 50%)')
    // And the desktop body, which is the sentence that was wrong by five
    // points on a number the user chose.
    expect(shown[0].body).toContain('CPU has been at or above 50%')
    expect(shown[0].title).toBe('web-1: CPU at 50%')
  })

  it('keeps the chip only while the reading is over that line', () => {
    sample(60)
    expect(alerts.useAlerts.getState().active['s1:cpu']).toBeDefined()
    vi.setSystemTime(T0 + MINUTE)
    // 48 is under the line and inside the old five-point dead band, which is
    // where a chip used to be stranded: on display, pointing at a screen that
    // said the host was fine.
    sample(48)
    expect(alerts.useAlerts.getState().active['s1:cpu']).toBeUndefined()
    expect(resolves()).toHaveLength(1)
    expect(resolves()[0].summary).toBe('web-1: CPU back below 50%')
  })

  it('does not let a server sitting on the line earn a fresh raise on every step', () => {
    // The recovery margin has not gone anywhere; it governs the talking. 48 is
    // off the line but not five points below it, so stepping back over does
    // not read as a new incident and MIN_GAP still has to elapse.
    sample(60)
    expect(raises()).toHaveLength(1)
    for (let i = 1; i <= 10; i++) {
      vi.setSystemTime(T0 + i * 2000)
      sample(48)
      vi.setSystemTime(T0 + i * 2000 + 1000)
      sample(52)
    }
    expect(raises()).toHaveLength(1)
  })

  it('holds the workspace default to its own number too', () => {
    app.useApp.getState().setSettings({ resourceAlertThresholds: {} })
    sample(76)
    expect(raises()).toHaveLength(0)
    sample(80)
    expect(raises()).toHaveLength(1)
    expect(raises()[0].threshold).toBe(80)
  })
})
