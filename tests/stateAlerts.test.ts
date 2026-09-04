import { describe, it, expect, beforeAll, beforeEach, afterEach, vi } from 'vitest'
import type { StoredAlertEvent, StoredAlertRow } from '../src/shared/webhook'

// Roadmap item 19b, stage 3: the kinds that are not a number against a line.
//
// A host that will not answer, a job step that failed, a tunnel in error, and
// item 18's database verdicts. None of them has a reading, so none of them can
// use the threshold path — but every one of them can flap, can be outstanding
// across a restart, and can be un-measurable, and those three are the whole of
// what 19a and the first two stages of 19b built.

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
const chips = (): ReturnType<Alerts['useAlerts']['getState']>['active'] =>
  alerts.useAlerts.getState().active

const MINUTE = 60_000
const HOUR = 60 * MINUTE
const T0 = new Date('2026-01-01T00:00:00Z').getTime()

/** The rows the durable log would hold, newest first, as alerts:history returns
 *  them. Built from what the store actually recorded, so a restart replays the
 *  real log rather than a hand-written idea of it. */
function loggedRows(): StoredAlertRow[] {
  return recorded
    .map((r) => ({ ...r.event, at: r.at ?? 0 }))
    .sort((a, b) => b.at - a.at)
}

/** A restart, simulated the only honest way available: everything the module
 *  holds in memory is dropped, and the durable log is replayed into it. */
function restart(rows: StoredAlertRow[]): void {
  alerts.resetAlertsForTests()
  app.useApp.getState().setSettings({ resourceAlertsEnabled: true })
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

describe('a kind that is a state rather than a reading', () => {
  it('raises once for a server that stops answering, and clears when it answers', () => {
    alerts.checkStateAlert('s1', 'web-1', 'host-unreachable', true)
    expect(raises()).toHaveLength(1)
    expect(raises()[0].summary).toBe('web-1 did not answer the last check')
    expect(raises()[0].kind).toBe('host-unreachable')
    expect(chips()['s1:host-unreachable'].value).toBeNull()

    // Still not answering on the next four sweeps. A state has nothing to add.
    for (let i = 1; i <= 4; i++) {
      vi.setSystemTime(T0 + i * MINUTE)
      alerts.checkStateAlert('s1', 'web-1', 'host-unreachable', true)
    }
    expect(raises()).toHaveLength(1)

    vi.setSystemTime(T0 + 5 * MINUTE)
    alerts.checkStateAlert('s1', 'web-1', 'host-unreachable', false)
    expect(resolves()).toHaveLength(1)
    expect(resolves()[0].summary).toBe('web-1 is answering again')
    expect(chips()['s1:host-unreachable']).toBeUndefined()
  })

  it('names the job step and the tunnel in the words a person reads', () => {
    alerts.checkStateAlert('j1', 'nightly-backup', 'job-failed', true, 'restart nginx')
    alerts.checkStateAlert('t1', 'office-vpn', 'tunnel-down', true)
    const summaries = raises().map((p) => p.summary)
    expect(summaries).toContain('nightly-backup failed a job step (restart nginx)')
    expect(summaries).toContain('Tunnel office-vpn is in error')
    expect(shown.map((s) => s.title)).toContain('nightly-backup: Job failed')
    expect(shown.map((s) => s.title)).toContain('office-vpn: Tunnel down')
  })

  it('scrubs a name before it reaches a Slack summary', () => {
    alerts.checkStateAlert('t1', '<!channel>', 'tunnel-down', true, '@everyone')
    expect(raises()).toHaveLength(1)
    const summary = raises()[0].summary as string
    expect(summary).toContain('channel')
    expect(summary).not.toContain('<!channel>')
    expect(summary).not.toContain('@everyone')
  })

  it('posts no all-clear for an alarm the endpoint was never told about', () => {
    // Never bad, so nothing outstanding. A "resolved" here is a message about
    // nothing, and 1a4cfaa is the commit that made that gate load-bearing.
    alerts.checkStateAlert('s1', 'web-1', 'host-unreachable', false)
    expect(posted).toHaveLength(0)
    expect(recorded).toHaveLength(0)
  })

  it('carries the detail into the durable row, so the inbox has something to show', () => {
    alerts.checkStateAlert('j1', 'nightly-backup', 'job-failed', true, 'restart nginx')
    const row = recorded.find((r) => r.event.kind === 'job-failed')
    expect(row).toBeDefined()
    expect(row?.event.detail).toBe('restart nginx')
    expect(row?.event.event).toBe('raised')
  })
})

describe('a state that could not be measured', () => {
  it('neither raises, nor resolves, nor reads as healthy', () => {
    // Nothing known yet: no chip, nothing said.
    alerts.checkStateAlert('t1', 'office-vpn', 'tunnel-down', null)
    expect(posted).toHaveLength(0)
    expect(chips()['t1:tunnel-down']).toBeUndefined()

    // Now it is genuinely down.
    vi.setSystemTime(T0 + MINUTE)
    alerts.checkStateAlert('t1', 'office-vpn', 'tunnel-down', true)
    expect(raises()).toHaveLength(1)

    // And now the tunnel list cannot be read at all. This must not be an
    // all-clear: "we could not ask" is not "it is carrying traffic again".
    vi.setSystemTime(T0 + 2 * MINUTE)
    alerts.checkStateAlert('t1', 'office-vpn', 'tunnel-down', null)
    expect(resolves()).toHaveLength(0)
    // And the chip stays up, still saying the last thing that was true.
    expect(chips()['t1:tunnel-down']).toBeDefined()
    expect(chips()['t1:tunnel-down'].kind).toBe('tunnel-down')
  })

  it('shows no number on a chip that has no number to show', () => {
    alerts.checkStateAlert('s1', 'web-1', 'host-unreachable', true)
    const chip = chips()['s1:host-unreachable']
    expect(chip.value).toBeNull()
    // The status bar renders this. A state kind reads as its label alone; a "0"
    // or a "1 per core" here would be a measurement nobody took.
    expect(alerts.chipValue(chip)).toBe('')
    alerts.checkResourceAlerts('s2', 'web-2', { cpu: 99, ram: 0, disk: null, inode: null, load: null })
    expect(alerts.chipValue(chips()['s2:cpu'])).toBe(' 99%')
  })
})

describe('a state that survives a restart', () => {
  it('does not re-announce a server that was unreachable when the app closed', () => {
    alerts.checkStateAlert('s1', 'web-1', 'host-unreachable', true)
    expect(raises()).toHaveLength(1)
    const rows = loggedRows()
    expect(rows).toHaveLength(1)

    restart(rows)
    posted.length = 0
    shown.length = 0
    // Same host, same state, one sweep after launch.
    vi.setSystemTime(T0 + 10 * MINUTE)
    alerts.checkStateAlert('s1', 'web-1', 'host-unreachable', true)
    expect(raises()).toHaveLength(0)
    expect(shown).toHaveLength(0)
    // But the chip is back, because the chip states what is true now.
    expect(chips()['s1:host-unreachable']).toBeDefined()
  })

  it('posts the all-clear for an alarm raised before the restart', () => {
    alerts.checkStateAlert('s1', 'web-1', 'host-unreachable', true)
    restart(loggedRows())
    posted.length = 0
    vi.setSystemTime(T0 + 10 * MINUTE)
    alerts.checkStateAlert('s1', 'web-1', 'host-unreachable', false)
    expect(resolves()).toHaveLength(1)
    expect(resolves()[0].summary).toBe('web-1 is answering again')
  })
})

describe('a state whose resolve never arrives', () => {
  // The one shape a state kind cannot recover from on its own. It speaks only
  // on a crossing, `conditionHeld` is durable and is seeded from every raised
  // row, and there is no repeat and no escalation — so a raise whose resolve
  // never comes poisons that key permanently and swallows the NEXT occurrence
  // rather than merely repeating the last one.
  //
  // Both producers are reachable. `tunnelStop` deletes the tunnel from the map
  // and `tunnel.list()` is what the poll diffs against, so stopping a tunnel
  // while it is in error — or quitting the app, which calls tunnelDisposeAll —
  // makes it vanish with no `false` ever passed. And a job failure is resolved
  // only by a later `ok` on the same host, which never comes for a job that is
  // never re-run there.

  it('hears the next tunnel failure after the tunnel vanished from the list', () => {
    alerts.checkStateAlert('t1', 'office-vpn', 'tunnel-down', true)
    expect(raises()).toHaveLength(1)

    // The tunnel is stopped while in error. It is gone from tunnel.list(), so
    // the ten-second poll stops mentioning it entirely — no `false`, no null,
    // nothing. Two days pass.
    posted.length = 0
    vi.setSystemTime(T0 + 48 * HOUR)
    // Started again under the same id, and it fails again. That is news.
    alerts.checkStateAlert('t1', 'office-vpn', 'tunnel-down', true)
    expect(raises()).toHaveLength(1)
    expect(chips()['t1:tunnel-down']).toBeDefined()
  })

  it('hears the next job failure on a server whose failed job was never re-run', () => {
    alerts.checkStateAlert('s1', 'web-1', 'job-failed', true, 'nightly upgrade')
    expect(raises()).toHaveLength(1)

    const rows = loggedRows()
    restart(rows)
    posted.length = 0
    // A month later, a different job fails on the same host.
    vi.setSystemTime(T0 + 30 * 24 * HOUR)
    alerts.checkStateAlert('s1', 'web-1', 'job-failed', true, 'database backup')
    expect(raises()).toHaveLength(1)
    expect(raises()[0].summary).toBe('web-1 failed a job step (database backup)')
  })

  it('still says nothing extra about a condition it is being told about', () => {
    // Paired with the two above so they cannot pass by the hold being dropped
    // altogether. A tunnel that is polled every ten seconds is corroborated
    // every ten seconds, and stays one alert however long it is down.
    alerts.checkStateAlert('t1', 'office-vpn', 'tunnel-down', true)
    for (let i = 1; i <= 24 * 60 * 6; i++) {
      vi.setSystemTime(T0 + i * 10_000)
      alerts.checkStateAlert('t1', 'office-vpn', 'tunnel-down', true)
    }
    expect(raises()).toHaveLength(1)
  })

  it('does not re-announce an unreachable server across an ordinary restart', () => {
    // The hold has to survive what it was built to survive. A host that was
    // unreachable when the app closed and is unreachable when it opens has not
    // crossed anything, and the sampler corroborates it every couple of
    // minutes.
    alerts.checkStateAlert('s1', 'web-1', 'host-unreachable', true)
    const rows = loggedRows()
    restart(rows)
    posted.length = 0
    vi.setSystemTime(T0 + 2 * MINUTE)
    alerts.checkStateAlert('s1', 'web-1', 'host-unreachable', true)
    expect(raises()).toHaveLength(0)
  })
})

describe('a state that flaps', () => {
  /** One clean crossing: down, then back up. */
  function flap(at: number): void {
    vi.setSystemTime(at)
    alerts.checkStateAlert('t1', 'office-vpn', 'tunnel-down', true)
    vi.setSystemTime(at + MINUTE)
    alerts.checkStateAlert('t1', 'office-vpn', 'tunnel-down', false)
  }

  it('says so on the fifth crossing and then goes quiet', () => {
    for (let i = 0; i < 5; i++) flap(T0 + i * 10 * MINUTE)
    expect(raises()).toHaveLength(5)
    const fifth = raises()[4]
    expect(fifth.damped).toBe(true)
    // Announced, never silent — the person about to mute the feature is the one
    // who needs to know it has gone quiet on purpose.
    const body = shown[shown.length - 1].body
    expect(body).toContain('5 times in 6 hours')
    expect(body).toContain('Alerts tab')

    // Four more crossings after the damp trips, and nothing more is said.
    for (let i = 5; i < 9; i++) flap(T0 + i * 10 * MINUTE)
    expect(raises()).toHaveLength(5)
    // Including the all-clears: half of a flap's noise is all-clears.
    expect(resolves()).toHaveLength(4)
  })

  it('stays quiet until it has gone six hours without crossing', () => {
    for (let i = 0; i < 5; i++) flap(T0 + i * 10 * MINUTE)
    posted.length = 0
    // A crossing five hours in refreshes the damp rather than ending it.
    flap(T0 + 5 * HOUR)
    expect(raises()).toHaveLength(0)
    // Six hours after THAT crossing, not after the trip.
    flap(T0 + 5 * HOUR + 6 * HOUR + MINUTE)
    expect(raises()).toHaveLength(1)
  })

  it('carries the damp across a restart', () => {
    for (let i = 0; i < 5; i++) flap(T0 + i * 10 * MINUTE)
    expect(raises()).toHaveLength(5)
    const rows = loggedRows()
    restart(rows)
    posted.length = 0
    // One hour after the trip, still inside the six hours of quiet.
    flap(T0 + HOUR)
    expect(raises()).toHaveLength(0)
  })
})

describe('an occurrence that has no recovery to observe', () => {
  it('announces a database alarm and never leaves a chip behind', () => {
    alerts.noteAlertEvent('c1', 'orders-primary', 'db-alarm', 'replication', T0)
    expect(raises()).toHaveLength(1)
    expect(raises()[0].summary).toBe('orders-primary: replication is in alarm')
    expect(raises()[0].kind).toBe('db-alarm')
    // No chip. Nothing in the store can ever say a database recovered, so a chip
    // here would be permanent and only a restart could clear it.
    expect(chips()['c1:db-alarm']).toBeUndefined()
    expect(alerts.useAlerts.getState().list()).toHaveLength(0)
  })

  it('announces the same row once however many polls return it', () => {
    for (let i = 0; i < 4; i++) {
      vi.setSystemTime(T0 + i * MINUTE)
      alerts.noteAlertEvent('c1', 'orders-primary', 'db-alarm', 'replication', T0)
    }
    expect(raises()).toHaveLength(1)
    // A genuinely new occurrence of the same question is a new row, and speaks.
    alerts.noteAlertEvent('c1', 'orders-primary', 'db-alarm', 'replication', T0 + 5 * MINUTE)
    expect(raises()).toHaveLength(2)
  })

  it('keeps watch and alarm apart, and each question apart', () => {
    alerts.noteAlertEvent('c1', 'orders-primary', 'db-watch', 'autovacuum', T0)
    alerts.noteAlertEvent('c1', 'orders-primary', 'db-alarm', 'autovacuum', T0)
    expect(raises()).toHaveLength(2)
    expect(raises().map((p) => p.summary)).toEqual([
      'orders-primary: autovacuum is worth watching',
      'orders-primary: autovacuum is in alarm'
    ])
  })

  it('does not replay a night of alarms into the notification centre at launch', () => {
    for (let i = 0; i < 3; i++) {
      alerts.noteAlertEvent('c1', 'orders-primary', 'db-alarm', 'replication', T0 + i * HOUR)
    }
    expect(raises()).toHaveLength(3)
    const rows = loggedRows()
    expect(rows).toHaveLength(3)

    restart(rows)
    posted.length = 0
    shown.length = 0
    // The poller offers the same three rows again after the restart.
    for (let i = 0; i < 3; i++) {
      alerts.noteAlertEvent('c1', 'orders-primary', 'db-alarm', 'replication', T0 + i * HOUR)
    }
    expect(raises()).toHaveLength(0)
    expect(shown).toHaveLength(0)
  })

  it('damps a database re-reporting the same alarm, across a restart', () => {
    for (let i = 0; i < 5; i++) {
      alerts.noteAlertEvent('c1', 'orders-primary', 'db-alarm', 'replication', T0 + i * MINUTE)
    }
    expect(raises()).toHaveLength(5)
    expect(raises()[4].damped).toBe(true)

    const rows = loggedRows()
    restart(rows)
    posted.length = 0
    // A sixth occurrence an hour later, still inside the six hours of quiet.
    alerts.noteAlertEvent('c1', 'orders-primary', 'db-alarm', 'replication', T0 + HOUR)
    expect(raises()).toHaveLength(0)
  })

  it('damps one question without silencing the rest of the database', () => {
    // db:ops writes a fresh history row stamped Date.now() on EVERY read, and
    // the Databases page has a manual Refresh button, so five presses against
    // one standing replication alarm are five distinct occurrences by the
    // dedupe key. The damp key was connectionId:kind — per connection and
    // level, not per question — so the fifth press announced "this has
    // happened 5 times in 6 hours" about something that happened once and was
    // read five times, and then silenced every OTHER question on that database
    // for six hours.
    for (let i = 0; i < 5; i++) {
      alerts.noteAlertEvent('c1', 'orders-primary', 'db-alarm', 'replication', T0 + i * MINUTE)
    }
    expect(raises()).toHaveLength(5)
    expect(raises()[4].damped).toBe(true)

    posted.length = 0
    shown.length = 0
    // A different question goes into alarm on the same database, at the same
    // level. Nobody damped this one.
    alerts.noteAlertEvent('c1', 'orders-primary', 'db-alarm', 'autovacuum', T0 + 6 * MINUTE)
    expect(raises()).toHaveLength(1)
    expect(raises()[0].summary).toBe('orders-primary: autovacuum is in alarm')
  })

  it('carries a per-question damp across a restart, and no further', () => {
    for (let i = 0; i < 5; i++) {
      alerts.noteAlertEvent('c1', 'orders-primary', 'db-alarm', 'replication', T0 + i * MINUTE)
    }
    restart(loggedRows())
    posted.length = 0
    // Still damped an hour later — the replay has to reach the same arithmetic
    // as the live path, on the same key.
    alerts.noteAlertEvent('c1', 'orders-primary', 'db-alarm', 'replication', T0 + HOUR)
    expect(raises()).toHaveLength(0)
    // And still not damped for anything else on that database.
    alerts.noteAlertEvent('c1', 'orders-primary', 'db-alarm', 'autovacuum', T0 + HOUR)
    expect(raises()).toHaveLength(1)
  })

  it('says nothing until the durable log has been read back', async () => {
    alerts.resetAlertsForTests()
    // A history read that never settles, which is the window hydration covers.
    let release: (rows: StoredAlertRow[]) => void = () => {}
    const pending = new Promise<StoredAlertRow[]>((r) => {
      release = r
    })
    const w = (globalThis as { window: { shellpilot: { alerts: { history: unknown } } } }).window
    const original = w.shellpilot.alerts.history
    w.shellpilot.alerts.history = () => pending
    const done = alerts.hydrateAlerts()

    alerts.noteAlertEvent('c1', 'orders-primary', 'db-alarm', 'replication', T0)
    expect(raises()).toHaveLength(0)

    release([])
    await done
    w.shellpilot.alerts.history = original

    // Not dropped: the next poll offers the same row and it is announced.
    alerts.noteAlertEvent('c1', 'orders-primary', 'db-alarm', 'replication', T0)
    expect(raises()).toHaveLength(1)
  })
})

describe('the switch still governs all of it', () => {
  it('says nothing for any of the new kinds while alerts are off', () => {
    app.useApp.getState().setSettings({ resourceAlertsEnabled: false })
    alerts.checkStateAlert('s1', 'web-1', 'host-unreachable', true)
    alerts.noteAlertEvent('c1', 'orders-primary', 'db-alarm', 'replication', T0)
    expect(posted).toHaveLength(0)
    expect(shown).toHaveLength(0)
    expect(recorded).toHaveLength(0)
    expect(alerts.useAlerts.getState().list()).toHaveLength(0)
  })
})
