import { describe, it, expect, beforeAll, beforeEach, afterEach, vi } from 'vitest'
import { parseMetricsForTests } from '../src/main/services/metrics'
import type { StoredAlertEvent, StoredAlertRow } from '../src/shared/webhook'

// Roadmap item 19b, stage 3: the two kinds the roadmap names first.
//
// Inode exhaustion is the one that is invisible from every screen the app has.
// A filesystem can be 40% full and completely unwritable because it has run out
// of inodes — a mail spool, a build cache, a badly configured session directory
// — and `df -k`, which is what every bar and every disk alert reads, shows
// nothing wrong at all.
//
// Load is the other half of what "the machine is busy" means. CPU percent says
// how much of the processor is being used; load says how long the queue for it
// is, including the tasks stuck in uninterruptible I/O that CPU percent cannot
// see at all.
//
// Both carry 19a's rule, and it is the reason each of them can report null: a
// metric that could not be measured is not zero. `df -i` is absent on some
// busybox userlands, and btrfs and zfs have no fixed inode table and honestly
// report none; a container without /proc has no load average. Zero for either
// would be an empty filesystem and a perfectly idle machine.

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
        record: (_e: StoredAlertEvent) => Promise.resolve(true),
        history: () => Promise.resolve([] as StoredAlertRow[])
      }
    }
  }
  alerts = await import('../src/renderer/src/store/alerts')
  app = await import('../src/renderer/src/store/app')
})

const raises = (): Record<string, unknown>[] => posted.filter((p) => p.event === 'raised')
const resolves = (): Record<string, unknown>[] => posted.filter((p) => p.event === 'resolved')
const chips = (): string[] => alerts.useAlerts.getState().list().map((a) => a.kind)

function sample(over: { inode?: number | null; load?: number | null }): void {
  alerts.checkResourceAlerts('s1', 'web-1', {
    cpu: 0,
    ram: 0,
    disk: null,
    inode: over.inode === undefined ? null : over.inode,
    load: over.load === undefined ? null : over.load
  })
}

const MINUTE = 60_000

beforeEach(() => {
  shown.length = 0
  posted.length = 0
  alerts.resetAlertsForTests()
  app.useApp.getState().setSettings({ resourceAlertsEnabled: true, resourceAlertThreshold: 80 })
  vi.useFakeTimers()
  vi.setSystemTime(new Date('2026-01-01T00:00:00Z'))
})

afterEach(() => {
  vi.useRealTimers()
})

describe('inode exhaustion', () => {
  it('raises above 85% and says which filesystem it looked at', () => {
    sample({ inode: 92.5 })
    expect(raises().length).toBe(1)
    expect(raises()[0].kind).toBe('inode')
    expect(raises()[0].value).toBe(92.5)
    expect(raises()[0].threshold).toBe(85)
    expect(raises()[0].summary).toBe('web-1: Root filesystem inodes at 92.5% (threshold 85%)')
    expect(shown[0].title).toBe('web-1: Inodes at 92.5%')
    expect(chips()).toEqual(['inode'])
  })

  it('says nothing at exactly 85, the same as disk', () => {
    sample({ inode: 85 })
    expect(raises().length).toBe(0)
    expect(chips()).toEqual([])
  })

  it('resolves once it is back to 85% or below', () => {
    sample({ inode: 92 })
    vi.advanceTimersByTime(MINUTE)
    sample({ inode: 60 })
    expect(resolves().length).toBe(1)
    expect(resolves()[0].kind).toBe('inode')
    expect(resolves()[0].summary).toBe('web-1: Root filesystem inodes back to 85% or below')
    expect(chips()).toEqual([])
  })

  it('is a separate alert from blocks, on a filesystem with room to spare', () => {
    // The whole reason this kind exists: 12% of the blocks used, no inodes left.
    alerts.checkResourceAlerts('s1', 'web-1', {
      cpu: 0,
      ram: 0,
      disk: 12,
      inode: 99,
      load: null
    })
    expect(raises().map((p) => p.kind)).toEqual(['inode'])
    expect(chips()).toEqual(['inode'])
  })
})

describe('load average', () => {
  it('raises at two runnable threads per core and reports per-core, not percent', () => {
    sample({ load: 3.2 })
    expect(raises().length).toBe(1)
    expect(raises()[0].kind).toBe('load')
    expect(raises()[0].value).toBe(3.2)
    expect(raises()[0].threshold).toBe(2)
    expect(raises()[0].summary).toBe('web-1: Load average at 3.2 per core (threshold 2 per core)')
    expect(shown[0].title).toBe('web-1: Load at 3.2 per core')
    expect(shown[0].body).toBe('Load average has been at or above 2 per core.')
  })

  it('recovers, and says so in per-core terms', () => {
    // Not a proof of the per-kind recovery margin — with load's one-minute
    // repeat window that margin is not observable from out here, and pretending
    // otherwise would be a test that passes against the bug it names. It is a
    // proof that the sentence a person reads is in the unit the number is in.
    sample({ load: 3 })
    expect(raises().length).toBe(1)
    vi.advanceTimersByTime(MINUTE)
    sample({ load: 1.2 })
    expect(resolves().length).toBe(1)
    expect(resolves()[0].summary).toBe('web-1: Load average back below 2 per core')
    expect(chips()).toEqual([])
  })

  it('withdraws the chip and posts the all-clear at the same moment', () => {
    // 1a4cfaa's invariant, checked on a new kind: hysteresis governs the
    // escalation memory only. The chip follows the condition, and the all-clear
    // goes with it — a chip that lingered while the endpoint had been told the
    // host recovered is the contradiction that fix was written to end.
    sample({ load: 3 })
    expect(chips()).toEqual(['load'])
    vi.advanceTimersByTime(MINUTE)
    sample({ load: 1.8 })
    expect(chips()).toEqual([])
    expect(resolves().length).toBe(1)
    expect(resolves()[0].value).toBe(1.8)
  })
})

describe('a metric that could not be measured', () => {
  it('never raises', () => {
    sample({ inode: null, load: null })
    expect(posted.length).toBe(0)
    expect(shown.length).toBe(0)
    expect(chips()).toEqual([])
  })

  it('never resolves an alert that is already up', () => {
    sample({ inode: 95, load: 4 })
    expect(raises().length).toBe(2)
    vi.advanceTimersByTime(MINUTE)
    // The next sweep could not read either one. That is not good news.
    sample({ inode: null, load: null })
    expect(resolves().length).toBe(0)
    expect(chips().sort()).toEqual(['inode', 'load'])
  })

  it('never reads as healthy: an unmeasurable inode table is not an empty one', () => {
    // The shape of the bug this rule exists to prevent. A btrfs host reports
    // an inode total of zero; dividing gives 0%, and 0% is "loads of room".
    const parsed = parseMetricsForTests(
      ['__INODE__', '/dev/sda1 0 0 0 - /', '__LOAD__', ''].join('\n')
    )
    expect(parsed.inodePct).toBeNull()
    expect(parsed.load1).toBeNull()
  })
})

describe('the probe', () => {
  it('reads df -iP and /proc/loadavg', () => {
    const parsed = parseMetricsForTests(
      [
        '__INODE__',
        '/dev/sda1       655360  622592   32768   95% /',
        '__LOAD__',
        '4.15 3.90 3.44 5/812 20194'
      ].join('\n')
    )
    expect(parsed.inodePct).toBeCloseTo(95, 1)
    expect(parsed.load1).toBe(4.15)
  })

  it('reports null when the server answered neither question', () => {
    const parsed = parseMetricsForTests('__INODE__\n__LOAD__\n')
    expect(parsed.inodePct).toBeNull()
    expect(parsed.load1).toBeNull()
  })
})
