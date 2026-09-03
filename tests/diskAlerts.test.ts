import { describe, it, expect, beforeAll, beforeEach, afterEach, vi } from 'vitest'
import { DISK_DANGER, isDiskCritical } from '../src/renderer/src/components/monitor/hostHealth'

// A filling disk is the one alert condition that does not fix itself. It was
// already computed and already rendered — the Fleet Monitor lists the host and
// paints the bar red — but it was not an AlertKind, so it reached nobody who
// was not already looking at the screen that showed it.
//
// store/alerts.ts had no test coverage at all before this file, and could not
// be imported under `environment: 'node'`: it reads `window.shellpilot` at
// module scope to stamp the app version into outbound payloads, and a bare
// `window` is a ReferenceError rather than undefined. So the stub goes in
// first and the module is pulled in dynamically afterwards. Everything else it
// imports only touches `window` inside a function, which is why stubbing this
// much is enough.

interface Shown {
  title: string
  body: string
}

const shown: Shown[] = []
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
      }
    }
  }
  alerts = await import('../src/renderer/src/store/alerts')
  app = await import('../src/renderer/src/store/app')
})

const raises = (): Record<string, unknown>[] => posted.filter((p) => p.event === 'raised')
const resolves = (): Record<string, unknown>[] => posted.filter((p) => p.event === 'resolved')
const chips = (): string[] => alerts.useAlerts.getState().list().map((a) => a.kind)

/** One sample from one host. CPU and memory sit at 0 so only disk can speak. */
function sample(disk: number | null): void {
  alerts.checkResourceAlerts('s1', 'web-1', 0, 0, disk)
}

const MINUTE = 60_000
const HOUR = 60 * MINUTE

beforeEach(() => {
  shown.length = 0
  posted.length = 0
  // Both maps, the failed-unit history and the store outlive a single test, so
  // without this the results depend on the order the file happens to run in.
  alerts.resetAlertsForTests()
  app.useApp.getState().setSettings({ resourceAlertsEnabled: true, resourceAlertThreshold: 80 })
  // checkResourceAlerts reads Date.now() itself, so the clock has to be ours.
  vi.useFakeTimers()
  vi.setSystemTime(new Date('2026-01-01T00:00:00Z'))
})

afterEach(() => {
  vi.useRealTimers()
})

describe('one disk predicate, two paths', () => {
  it('says nothing at exactly 85.000, which is what the Fleet Monitor says', () => {
    // The disagreement this fixes: hostHealth asked `> 85` while the alert
    // store raised at `>= threshold`. At exactly 85.000 the notification fired,
    // the attention list stayed empty and the bar stayed amber — a notification
    // pointing at a screen that contradicts it.
    expect(isDiskCritical(85, 100_000_000)).toBe(false)
    expect(DISK_DANGER).toBe(85)

    sample(85)
    expect(posted).toEqual([])
    expect(shown).toEqual([])
    expect(chips()).toEqual([])
  })

  it('speaks the moment the disk is genuinely over the line', () => {
    sample(85.4)
    expect(raises().length).toBe(1)
    expect(chips()).toEqual(['disk'])
  })

  it('ignores a host that reported no disk at all', () => {
    // `df` returning nothing is not an empty disk. isDiskCritical is the only
    // place that distinction is made, for both callers.
    expect(isDiskCritical(99, 0)).toBe(false)
    expect(isDiskCritical(99, 1)).toBe(true)
  })
})

describe('what a disk alert actually says', () => {
  it('posts kind "disk", naming the root filesystem it actually probed', () => {
    sample(91)

    const post = raises()[0]
    // The literal that catches the `kind === 'cpu' ? 'cpu' : 'memory'` ternary
    // this replaced. A call count would have passed with every disk alert
    // arriving in Slack labelled "memory".
    expect(post.kind).toBe('disk')
    expect(post.event).toBe('raised')
    expect(post.server).toBe('web-1')
    expect(post.summary).toBe('web-1: Root filesystem at 91% (threshold 85%)')
    expect(post.value).toBe(91)
    expect(post.threshold).toBe(85)
    // `df -kP /` is the whole probe, so the alert may not imply it looked at
    // any other filesystem.
    expect(String(post.summary)).toMatch(/root filesystem/i)

    expect(shown).toEqual([
      { title: 'web-1: Disk at 91%', body: 'Root filesystem has been at or above 85%.' }
    ])
  })

  it('still calls memory memory, and CPU CPU', () => {
    alerts.checkResourceAlerts('s2', 'web-2', 95, 96, null)
    expect(raises().map((p) => p.kind).sort()).toEqual(['cpu', 'memory'])
    expect(raises().find((p) => p.kind === 'memory')?.summary).toBe(
      'web-2: Memory at 96% (threshold 80%)'
    )
  })
})

describe('how often a disk alert repeats', () => {
  it('repeats every six hours, not every minute', () => {
    // A disk does not empty itself. A minute-long window is ~10,000 messages a
    // week for one host nobody can fix before Monday, and the only thing that
    // survives that is the mute button.
    sample(91)
    expect(raises().length).toBe(1)

    vi.advanceTimersByTime(5 * HOUR + 59 * MINUTE)
    sample(91)
    expect(raises().length).toBe(1)

    vi.advanceTimersByTime(2 * MINUTE)
    sample(91)
    expect(raises().length).toBe(2)
  })

  it('leaves CPU and memory on the one-minute window', () => {
    alerts.checkResourceAlerts('s2', 'web-2', 95, 10, null)
    expect(raises().length).toBe(1)
    vi.advanceTimersByTime(61_000)
    alerts.checkResourceAlerts('s2', 'web-2', 95, 10, null)
    expect(raises().length).toBe(2)
  })

  it('escalates a worsening disk without waiting out the window', () => {
    sample(86)
    expect(raises().length).toBe(1)

    // A climb of a point or two is the same news. Compared against the value we
    // last SENT, not the previous sample, so 86 → 88 → 90 does not escalate on
    // every one.
    vi.advanceTimersByTime(MINUTE)
    sample(88)
    vi.advanceTimersByTime(MINUTE)
    sample(90)
    expect(raises().length).toBe(1)

    vi.advanceTimersByTime(MINUTE)
    sample(91)
    expect(raises().length).toBe(2)
    expect(raises()[1].value).toBe(91)

    // And 93 is now measured against 91, not against 86.
    vi.advanceTimersByTime(MINUTE)
    sample(93)
    expect(raises().length).toBe(2)
  })
})

describe('a disk that fills, empties and fills again', () => {
  it('announces the second filling immediately rather than waiting six hours', () => {
    // The hole a six-hour window opens: the repeat clock is deliberately NOT
    // reset on recovery, which is safe at sixty seconds and silences a genuine
    // second incident at six hours.
    sample(96)
    expect(raises().length).toBe(1)

    vi.advanceTimersByTime(HOUR)
    sample(40)
    expect(resolves().length).toBe(1)
    expect(chips()).toEqual([])

    vi.advanceTimersByTime(HOUR)
    sample(92)
    expect(raises().length).toBe(2)
    expect(raises()[1].value).toBe(92)
    expect(raises()[1].kind).toBe('disk')
  })

  it('does not re-announce a disk oscillating around the line', () => {
    // Why the re-raise above is safe without an extra guard: a resolve only
    // registers below `threshold - RECOVER_MARGIN`, so a host bouncing between
    // 81 and 86 never resolves at all and never gets to re-raise. Flap
    // protection is the clear line, not the repeat window.
    sample(86)
    for (const v of [82, 86, 84, 86, 81, 86]) {
      vi.advanceTimersByTime(2_000)
      sample(v)
    }
    expect(raises().length).toBe(1)
    expect(resolves()).toEqual([])
    // And the chip stays up throughout, because the host never recovered.
    expect(chips()).toEqual(['disk'])
  })

  it('never sends more all-clears than alarms', () => {
    // A resolve for something nobody was told about is a message about
    // nothing. Before the escalation memory, an oscillator that crossed the
    // clear line sent one "raised" and an all-clear on every fall.
    for (const v of [86, 79, 86, 79, 86, 79]) {
      vi.advanceTimersByTime(2_000)
      sample(v)
    }
    expect(raises().length).toBe(3)
    expect(resolves().length).toBe(3)
    expect(resolves()[0].kind).toBe('disk')
    expect(resolves()[0].summary).toBe('web-1: Root filesystem back below 85%')
  })
})

describe('a disk nobody could measure', () => {
  it('raises nothing on its own', () => {
    sample(null)
    expect(posted).toEqual([])
    expect(chips()).toEqual([])
  })

  it('does NOT post an all-clear for a host that is still alerting', () => {
    // metrics.ts yields diskPct 0 when the df probe fails. Passing that would
    // post "back below 85%" for a host that may well still be full — a false
    // all-clear manufactured out of a measurement failure.
    sample(96)
    expect(raises().length).toBe(1)

    vi.advanceTimersByTime(2_000)
    sample(null)
    expect(resolves()).toEqual([])
    expect(chips()).toEqual(['disk'])

    // A real zero, on the other hand, is a recovery.
    vi.advanceTimersByTime(2_000)
    sample(0)
    expect(resolves().length).toBe(1)
    expect(chips()).toEqual([])
  })
})

describe('housekeeping', () => {
  it('takes the chips down when alerts are switched off', () => {
    // checkResourceAlerts returns before evaluate while the setting is false,
    // so nothing on the sampling path can clear what is already up. A disk
    // chip would sit in the status bar until restart, pointing at a feature
    // that is no longer running.
    sample(96)
    expect(chips()).toEqual(['disk'])

    app.useApp.getState().setSettings({ resourceAlertsEnabled: false })
    expect(chips()).toEqual([])

    // And nothing new is raised while it is off.
    vi.advanceTimersByTime(7 * HOUR)
    sample(99)
    expect(raises().length).toBe(1)
  })
})
