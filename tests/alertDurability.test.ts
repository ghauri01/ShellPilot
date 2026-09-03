import { describe, it, expect, beforeAll, beforeEach, afterEach, vi } from 'vitest'
import { ALERT_KINDS, sanitiseStoredAlert, STORE_ALERT_KINDS } from '../src/shared/webhook'
import type { StoredAlertEvent, StoredAlertRow } from '../src/shared/webhook'

// Roadmap item 19b, stage 1: the alert store's memory had to survive a restart.
//
// Everything it remembered was a module-level Map in the renderer. For CPU that
// is a sixty-second window and nobody notices. For disk the window is six hours
// and the condition does not fix itself, so a host that has been at 91% for a
// month re-announced the same 91% at every launch — and the roadmap names
// exactly that as the thing that gets the whole feature muted.
//
// A restart cannot be run in a test, so it is simulated the only way that is
// honest: drop everything the module holds (`resetAlertsForTests`, which is
// precisely "the renderer went away"), then replay the durable log through
// `applyStoredAlerts` the way `hydrateAlerts` does at startup.

interface Shown {
  title: string
  body: string
}

const shown: Shown[] = []
const posted: Record<string, unknown>[] = []
/** What the renderer asked main to write down. */
const recorded: { event: StoredAlertEvent; at: number | undefined }[] = []
/** What the startup read will hand back. */
let stored: StoredAlertRow[] = []

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
        history: () => Promise.resolve(stored)
      }
    }
  }
  alerts = await import('../src/renderer/src/store/alerts')
  app = await import('../src/renderer/src/store/app')
})

const raises = (): Record<string, unknown>[] => posted.filter((p) => p.event === 'raised')
const DISK_THRESHOLD = 85
const HOUR = 60 * 60 * 1000

/** One disk sample. CPU and memory sit at 0 so only disk can speak. */
function sample(disk: number | null): void {
  alerts.checkResourceAlerts('s1', 'web-1', { cpu: 0, ram: 0, disk, inode: null, load: null })
}

beforeEach(() => {
  shown.length = 0
  posted.length = 0
  recorded.length = 0
  stored = []
  alerts.resetAlertsForTests()
  app.useApp.getState().setSettings({ resourceAlertsEnabled: true, resourceAlertThreshold: 80 })
  vi.useFakeTimers()
  vi.setSystemTime(new Date('2026-01-01T00:00:00Z'))
})

afterEach(() => {
  vi.useRealTimers()
})

/** Everything the renderer holds goes away; the log does not. */
function restart(): void {
  alerts.resetAlertsForTests()
  alerts.applyStoredAlerts(stored)
}

/** Rows as the store returns them: newest first.
 *
 *  Ties are broken by insertion order reversed, because that is what
 *  `ORDER BY e.ts DESC, e.rowid DESC` does — and two alert rows in the same
 *  millisecond is not exotic, it is what a raise followed immediately by a
 *  stand-down produces. */
function log(): StoredAlertRow[] {
  return recorded
    .map((r, i) => ({ ...r.event, at: r.at ?? 0, i }))
    .sort((a, b) => b.at - a.at || b.i - a.i)
    .map(({ i: _i, ...row }) => row)
}

describe('a raise is written down', () => {
  it('records the raise with the value and threshold that were announced', () => {
    sample(91.4)
    expect(recorded.length).toBe(1)
    expect(recorded[0].event.event).toBe('raised')
    expect(recorded[0].event.kind).toBe('disk')
    expect(recorded[0].event.serverId).toBe('s1')
    expect(recorded[0].event.serverName).toBe('web-1')
    expect(recorded[0].event.value).toBe(91.4)
    expect(recorded[0].event.threshold).toBe(DISK_THRESHOLD)
    expect(recorded[0].at).toBe(Date.parse('2026-01-01T00:00:00Z'))
  })

  it('records the resolve, and only once', () => {
    sample(91)
    vi.advanceTimersByTime(HOUR)
    sample(40)
    sample(41)
    const resolves = recorded.filter((r) => r.event.event === 'resolved')
    expect(resolves.length).toBe(1)
    expect(resolves[0].event.kind).toBe('disk')
    expect(resolves[0].event.value).toBe(40)
  })
})

describe('suppression survives a restart', () => {
  it('does not re-announce a chronically full disk on every launch', () => {
    // The defect, in the shape it actually appears: a disk raised, and the app
    // relaunched twice inside the six-hour window.
    sample(91)
    expect(raises().length).toBe(1)
    stored = log()

    posted.length = 0
    vi.advanceTimersByTime(HOUR)
    restart()
    sample(91)
    expect(raises().length).toBe(0)

    vi.advanceTimersByTime(HOUR)
    restart()
    sample(91)
    expect(raises().length).toBe(0)
  })

  it('still repeats once the window it remembered has actually expired', () => {
    // Paired with the test above so that one cannot pass by nothing ever firing.
    sample(91)
    stored = log()
    posted.length = 0
    vi.advanceTimersByTime(7 * HOUR)
    restart()
    sample(91)
    expect(raises().length).toBe(1)
    expect(raises()[0].value).toBe(91)
  })

  it('still escalates across a restart when the disk gets materially worse', () => {
    sample(86)
    stored = log()
    posted.length = 0
    vi.advanceTimersByTime(HOUR)
    restart()
    sample(96)
    expect(raises().length).toBe(1)
    expect(raises()[0].value).toBe(96)
  })

  it('posts the all-clear for an alarm raised before the restart', () => {
    sample(91)
    stored = log()
    posted.length = 0
    vi.advanceTimersByTime(HOUR)
    restart()
    sample(40)
    const resolves = posted.filter((p) => p.event === 'resolved')
    expect(resolves.length).toBe(1)
    expect(resolves[0].kind).toBe('disk')
    expect(resolves[0].server).toBe('web-1')
  })
})

describe('switching alerting off ends the conversation durably', () => {
  it('writes a stand-down, not an all-clear, and does not post one', () => {
    sample(91)
    posted.length = 0
    app.useApp.getState().setSettings({ resourceAlertsEnabled: false })
    const stand = recorded.filter((r) => r.event.event === 'stood-down')
    expect(stand.length).toBe(1)
    expect(stand[0].event.kind).toBe('disk')
    expect(recorded.filter((r) => r.event.event === 'resolved').length).toBe(0)
    expect(posted.length).toBe(0)
  })

  it('does not let a restart resurrect the window the user just ended', () => {
    sample(91)
    app.useApp.getState().setSettings({ resourceAlertsEnabled: false })
    stored = log()
    posted.length = 0
    restart()
    app.useApp.getState().setSettings({ resourceAlertsEnabled: true })
    sample(91)
    expect(raises().length).toBe(1)
  })
})

describe('nothing is said before the log has been read', () => {
  it('shows the chip but stays silent until hydration settles', async () => {
    stored = []
    const done = alerts.hydrateAlerts()
    sample(91)
    expect(posted.length).toBe(0)
    expect(shown.length).toBe(0)
    expect(alerts.useAlerts.getState().list().map((a) => a.kind)).toEqual(['disk'])
    await done
    sample(91)
    expect(raises().length).toBe(1)
  })
})

describe('the row is rebuilt from a whitelist', () => {
  it('keeps a value of zero, which is a reading, and drops one that is not a number', () => {
    const zero = sanitiseStoredAlert({
      event: 'raised',
      kind: 'disk',
      serverId: 's1',
      serverName: 'web-1',
      value: 0,
      threshold: 85
    })
    expect(zero?.value).toBe(0)
    const bad = sanitiseStoredAlert({
      event: 'raised',
      kind: 'disk',
      serverId: 's1',
      serverName: 'web-1',
      value: 'lots'
    })
    expect(bad).not.toBeNull()
    expect(bad?.value).toBeUndefined()
  })

  it('refuses a kind it does not know rather than storing a partial row', () => {
    expect(sanitiseStoredAlert({ event: 'raised', kind: 'weather', serverId: 's1', serverName: 'x' })).toBeNull()
    expect(sanitiseStoredAlert({ event: 'shrugged', kind: 'disk', serverId: 's1', serverName: 'x' })).toBeNull()
    expect(sanitiseStoredAlert({ event: 'raised', kind: 'disk', serverName: 'x' })).toBeNull()
  })

  it('names every kind the store measures, and spells memory the store’s way', () => {
    // A literal, updated deliberately when a kind is added, because the list is
    // consumed as a whitelist: a kind present in the type and absent here is a
    // row main refuses to store, and a kind here that nothing produces is a
    // value the inbox can render and nobody can explain.
    expect([...STORE_ALERT_KINDS]).toEqual([
      'cpu',
      'ram',
      'disk',
      'inode',
      'load',
      'host-unreachable',
      'job-failed',
      'tunnel-down',
      'db-alarm',
      'db-watch'
    ])
  })

  // The half of the claim above that the literal alone does not make. The list
  // was updated for item 19b's new kinds, and an update that only re-typed the
  // new spelling would have quietly lost the reason the assertion existed.
  it('keeps the store’s spelling of memory apart from the wire’s', () => {
    expect([...STORE_ALERT_KINDS]).toContain('ram')
    expect([...STORE_ALERT_KINDS]).not.toContain('memory')
    expect([...ALERT_KINDS]).toContain('memory')
    expect([...ALERT_KINDS]).not.toContain('ram')
    // `unit-failed` goes out on the wire and has no store entry, because failed
    // units are a set of names rather than a crossing.
    expect([...ALERT_KINDS]).toContain('unit-failed')
    expect([...STORE_ALERT_KINDS]).not.toContain('unit-failed')
  })

  it('carries a scrubbed detail, and refuses one that is only punctuation', () => {
    const row = sanitiseStoredAlert({
      event: 'raised',
      kind: 'job-failed',
      serverId: 's1',
      serverName: 'web-1',
      detail: 'restart <!channel> nginx'
    })
    expect(row?.detail).toBe('restart channel nginx')
    const empty = sanitiseStoredAlert({
      event: 'raised',
      kind: 'job-failed',
      serverId: 's1',
      serverName: 'web-1',
      detail: '<<>>'
    })
    expect(empty).not.toBeNull()
    expect(empty?.detail).toBeUndefined()
  })
})
