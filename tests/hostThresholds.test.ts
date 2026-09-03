import { describe, it, expect, beforeAll, beforeEach, afterEach, vi } from 'vitest'
import type { StoredAlertEvent, StoredAlertRow } from '../src/shared/webhook'

// Roadmap item 19b: per-host thresholds.
//
// An estate is not uniform. A build box at 95% is working and a database at 95%
// is in trouble, and one number for both means either the build box cries wolf
// every afternoon or the database says nothing until it is too late — and the
// first of those is how the whole feature gets muted, which is the outcome the
// roadmap says would be worse than not shipping it.

const posted: Record<string, unknown>[] = []

type Alerts = typeof import('../src/renderer/src/store/alerts')
type AppStore = typeof import('../src/renderer/src/store/app')

let alerts: Alerts
let app: AppStore

beforeAll(async () => {
  ;(globalThis as { window?: unknown }).window = {
    shellpilot: {
      getVersion: () => Promise.resolve('9.9.9'),
      notify: { show: () => {} },
      webhook: {
        notify: (p: Record<string, unknown>) => {
          posted.push(p)
        }
      },
      alerts: {
        record: (_e: StoredAlertEvent) => Promise.resolve(true),
        history: () => Promise.resolve([] as StoredAlertRow[])
      }
    }
  }
  alerts = await import('../src/renderer/src/store/alerts')
  app = await import('../src/renderer/src/store/app')
})

const raises = (): Record<string, unknown>[] => posted.filter((p) => p.event === 'raised')

beforeEach(() => {
  posted.length = 0
  alerts.resetAlertsForTests()
  app.useApp.getState().setSettings({
    resourceAlertsEnabled: true,
    resourceAlertThreshold: 80,
    resourceAlertThresholds: {}
  })
  vi.useFakeTimers()
  vi.setSystemTime(new Date('2026-01-01T00:00:00Z'))
})

afterEach(() => {
  vi.useRealTimers()
})

describe('which line a host is held to', () => {
  it('uses the workspace default when there is no override', () => {
    expect(alerts.hostThreshold(80, {}, 's1')).toBe(80)
    expect(alerts.hostThreshold(80, undefined, 's1')).toBe(80)
  })

  it('uses the override when there is one', () => {
    expect(alerts.hostThreshold(80, { s1: 95 }, 's1')).toBe(95)
    // And only for that host.
    expect(alerts.hostThreshold(80, { s1: 95 }, 's2')).toBe(80)
  })

  it('clamps a value that would switch the host off while the switch says on', () => {
    // 0 makes the clear line max(0, -5), which no reading is below, so the
    // alert raises on every sample forever. 100 can never be reached.
    expect(alerts.hostThreshold(80, { s1: 0 }, 's1')).toBe(alerts.THRESHOLD_MIN)
    expect(alerts.hostThreshold(80, { s1: 100 }, 's1')).toBe(alerts.THRESHOLD_MAX)
    expect(alerts.hostThreshold(80, { s1: -40 }, 's1')).toBe(alerts.THRESHOLD_MIN)
  })

  it('falls back to the default for a value that is not a number', () => {
    // A hand-edited settings file or an old backup. NaN would make every
    // comparison false and silence the host completely, which is the one
    // failure a threshold must not have.
    expect(alerts.hostThreshold(80, { s1: NaN }, 's1')).toBe(80)
    expect(alerts.hostThreshold(80, { s1: Infinity }, 's1')).toBe(80)
    expect(alerts.hostThreshold(80, { s1: 'lots' as unknown as number }, 's1')).toBe(80)
  })
})

describe('the line a sample is actually judged against', () => {
  const sample = (id: string, name: string, cpu: number): void =>
    alerts.checkResourceAlerts(id, name, { cpu, ram: 0, disk: null, inode: null, load: null })

  it('holds two hosts to two different lines in the same sweep', () => {
    app.useApp.getState().setSettings({ resourceAlertThresholds: { build: 95 } })
    // 88% on both.
    //
    // CPU and memory are over at the threshold itself — the number in the box,
    // which is the whole point of a per-host line somebody types. So the
    // database's line is 80 and the build box's is 95, and 88 is over one and
    // under the other. The five-point recovery margin is still there; it
    // decides when a later crossing counts as a new incident, not where the
    // line is. See checkResourceAlerts.
    sample('db', 'orders-primary', 88)
    sample('build', 'ci-runner', 88)
    expect(raises()).toHaveLength(1)
    expect(raises()[0].server).toBe('orders-primary')
    expect(raises()[0].threshold).toBe(80)
  })

  it('puts the host’s own number in the sentence a person reads', () => {
    app.useApp.getState().setSettings({ resourceAlertThresholds: { build: 95 } })
    sample('build', 'ci-runner', 97)
    expect(raises()).toHaveLength(1)
    expect(raises()[0].threshold).toBe(95)
    expect(raises()[0].summary).toContain('threshold 95%')
    // Not the workspace default, which would be an alert explaining itself with
    // a number it did not use.
    expect(raises()[0].summary).not.toContain('threshold 80%')
  })

  it('recovers against the host’s own line, not the default', () => {
    app.useApp.getState().setSettings({ resourceAlertThresholds: { build: 95 } })
    sample('build', 'ci-runner', 97)
    expect(raises()).toHaveLength(1)
    // 88 is over the workspace default of 80 and under this host's line of 95.
    // The chip has to follow the host's line, not the default's.
    sample('build', 'ci-runner', 88)
    expect(alerts.useAlerts.getState().active['build:cpu']).toBeUndefined()
  })

  it('applies a clamped override rather than the raw one', () => {
    app.useApp.getState().setSettings({ resourceAlertThresholds: { s1: 0 } })
    // Nothing at all is happening on this host.
    sample('s1', 'web-1', 5)
    // A raw 0 would raise here, forever. The clamp is what stops it.
    expect(raises()).toHaveLength(0)
  })
})

describe('an override does not outlive its server', () => {
  it('is dropped when the server is forgotten', async () => {
    const cleanup = await import('../src/renderer/src/store/serverCleanup')
    app.useApp.getState().setSettings({ resourceAlertThresholds: { s1: 95, s2: 90 } })
    cleanup.forgetServer('s1')
    expect(app.useApp.getState().settings.resourceAlertThresholds).toEqual({ s2: 90 })
  })
})
