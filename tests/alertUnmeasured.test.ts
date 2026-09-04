import { describe, it, expect, beforeAll, beforeEach, afterEach, vi } from 'vitest'
import type { StoredAlertEvent, StoredAlertRow } from '../src/shared/webhook'

// Roadmap item 19b: "not measured" reaching the alert path as a number.
//
// checkResourceAlerts' own docblock says "There is no branch that turns one
// into a zero on the way in." That is true of the function and was false of the
// pipeline it sits at the end of: metrics.ts turned an absent __CPU__ section
// into 0 and an absent MemTotal into 0%, and ResourceSample typed both as a
// bare number, so there was no null for a caller to pass even if it had one.
//
// The consequence is not a cosmetic zero. It is two `resolved` webhooks for
// alerts that are still true, a chip that vanishes, a `conditionHeld` that
// clears, and a genuine re-cross that then counts as a fresh clean crossing
// towards a flap damp — the estate goes quiet about a pegged host because a
// probe failed.

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
const chips = (): string[] =>
  alerts.useAlerts
    .getState()
    .list()
    .map((a) => a.kind)
    .sort()

const MINUTE = 60_000
const T0 = new Date('2026-01-01T00:00:00Z').getTime()

/** One sample. Only cpu and ram vary; everything else is honestly absent. */
function sample(cpu: number | null, ram: number | null): void {
  alerts.checkResourceAlerts('s1', 'web-1', { cpu, ram, disk: null, inode: null, load: null })
}

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

describe('a CPU and a memory reading that could not be taken', () => {
  it('does not post an all-clear for a server that is still pegged', () => {
    sample(95, 95)
    expect(raises()).toHaveLength(2)
    expect(chips()).toEqual(['cpu', 'ram'])

    // The next sweep reached the host but the probe came back with nothing —
    // no procfs, no grep, a compound exec cut off mid-stream. That is not a
    // host that recovered.
    vi.setSystemTime(T0 + MINUTE)
    sample(null, null)
    expect(resolves()).toHaveLength(0)
    expect(chips()).toEqual(['cpu', 'ram'])
  })

  it('does not let the genuine re-cross count as a fresh crossing', () => {
    // The second cost, and the quieter one. A false resolve clears
    // conditionHeld, so the next real sample is a clean crossing towards the
    // five that trip a flap damp — and a host whose probe is flaky gets damped
    // for being pegged.
    sample(95, 95)
    for (let i = 1; i <= 6; i++) {
      vi.setSystemTime(T0 + i * 2 * MINUTE)
      sample(null, null)
      vi.setSystemTime(T0 + i * 2 * MINUTE + MINUTE)
      sample(95, 95)
    }
    // Every raise after the first is the ordinary repeat, and none of them is
    // damped: nothing crossed anything.
    expect(raises().every((p) => p.damped === undefined)).toBe(true)
    expect(resolves()).toHaveLength(0)
  })

  it('still resolves on a real reading below the line', () => {
    // Paired with the negatives above, so they cannot pass by the whole path
    // going silent.
    sample(95, 95)
    vi.setSystemTime(T0 + MINUTE)
    sample(10, 10)
    expect(resolves()).toHaveLength(2)
    expect(chips()).toEqual([])
  })

  it('raises on one metric while the other is unmeasurable', () => {
    // Null is per metric, not per sample. A host whose memory could not be
    // read is still a host whose CPU is pegged.
    sample(95, null)
    expect(raises()).toHaveLength(1)
    expect(chips()).toEqual(['cpu'])
  })
})
