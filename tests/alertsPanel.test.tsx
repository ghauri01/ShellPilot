// @vitest-environment jsdom
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { stubBridge } from './setup/renderer'
import { AlertsPanel, rowSubject } from '../src/renderer/src/components/monitor/AlertsPanel'
import { StatusBar } from '../src/renderer/src/components/layout/StatusBar'
import { useAlerts, resetAlertsForTests } from '../src/renderer/src/store/alerts'
import { useApp } from '../src/renderer/src/store/app'
import { useNav } from '../src/renderer/src/store/nav'
import { useFleetStatus } from '../src/renderer/src/store/fleetStatus'
import type { StoredAlertRow } from '../src/shared/webhook'

// The inbox — roadmap item 19b.
//
// "An alert inbox with a history rather than transient toasts", and the reason
// the roadmap gives for wanting one: "a disk alert that fires forty times
// overnight gets the whole feature muted, which is worse than not shipping it."
// Damping stops the forty. This is what makes the damping affordable, because a
// feature that goes quiet on purpose needs somewhere the quiet parts are still
// written down.

const T0 = new Date('2026-01-01T12:00:00Z').getTime()

let historyRows: StoredAlertRow[]
let historyFails: boolean
/** The durable write behind Acknowledge and Snooze. A spy rather than a stub
 *  so the redesign can be held to reaching the LOG and not merely the in-memory
 *  chip: a card whose primary button only mutated the store would look right,
 *  survive every assertion about the store, and lose the acknowledgement on the
 *  next launch. */
let recorded: ReturnType<typeof vi.fn>

function install(): void {
  stubBridge({
    getVersion: () => Promise.resolve('9.9.9'),
    notify: { show: () => {} },
    alerts: {
      record: recorded,
      history: () =>
        historyFails ? Promise.reject(new Error('database is locked')) : Promise.resolve(historyRows)
    }
  })
}

beforeEach(() => {
  historyRows = []
  historyFails = false
  recorded = vi.fn(() => Promise.resolve(true))
  install()
  resetAlertsForTests()
  useFleetStatus.getState().setStatus(null)
  useApp.getState().setSettings({ resourceAlertsEnabled: true, fleetSamplingEnabled: false })
  vi.useFakeTimers({ shouldAdvanceTime: true })
  vi.setSystemTime(T0)
})

afterEach(() => {
  vi.useRealTimers()
})

describe('the history the chip cannot show', () => {
  it('lists events that are over, which no chip and no toast still holds', async () => {
    // Nothing is outstanding. The status-bar chip is therefore absent, and a
    // toast for any of this was gone the moment it was dismissed.
    historyRows = [
      { event: 'resolved', kind: 'disk', serverId: 's1', serverName: 'web-1', value: 78, threshold: 85, at: T0 - 60_000 },
      { event: 'raised', kind: 'disk', serverId: 's1', serverName: 'web-1', value: 91, threshold: 85, at: T0 - 3 * 60_000 },
      { event: 'raised', kind: 'tunnel-down', serverId: 't1', serverName: 'office-db', at: T0 - 4 * 60_000 }
    ]
    render(<AlertsPanel />)
    await waitFor(() => expect(screen.getByText('Nothing is outstanding right now.')).toBeTruthy())

    // Present before ordered: an absent string passes an index comparison.
    const body = document.body.textContent ?? ''
    expect(body).toContain('Cleared')
    expect(body).toContain('Raised')
    expect(body).toContain('Tunnel down')
    expect(body).toContain('91 of 85')
    expect(body).toContain('78 of 85')
    expect(screen.getAllByText('web-1').length).toBeGreaterThan(0)
    expect(screen.getAllByText('office-db').length).toBeGreaterThan(0)
  })

  it('shows an outstanding alert with no number as its label alone', async () => {
    useAlerts.setState({
      active: {
        's1:host-unreachable': {
          serverId: 's1',
          serverName: 'web-1',
          kind: 'host-unreachable',
          value: null,
          since: T0 - 30 * 60_000
        }
      }
    })
    render(<AlertsPanel />)
    await waitFor(() => expect(screen.getAllByText('Unreachable').length).toBeGreaterThan(0))
    // Scoped to the row, not to the page: the thresholds section below names
    // percentages of its own, and a body-wide assertion would be passing on
    // whatever text happened to be absent rather than on this row's contents.
    //
    // Found by BEING an outstanding card rather than by being the only
    // 'Unreachable' on the page: item 28's runbook picker names every alert
    // kind in an <option>, so the label is no longer unique and a getByText
    // would throw on the ambiguity rather than assert anything about this row.
    //
    // Addressed by its testid rather than by `closest('tr')`, which is what
    // this line used when Outstanding was a table. The assertions below are
    // unchanged; only the way the card is located is.
    const row = screen.getByTestId('outstanding-alert').textContent ?? ''
    expect(row).toContain('web-1')
    expect(row).toContain('since 30 min ago')
    // A state kind has no reading. A "0" here would be a measurement nobody
    // took, which is the rule the whole item runs on.
    expect(row).not.toMatch(/\d\s*%/)
  })

  it('says the log could not be read rather than showing an empty history', async () => {
    historyFails = true
    render(<AlertsPanel />)
    await waitFor(() =>
      expect(screen.getByText(/could not be read/)).toBeTruthy()
    )
    expect(screen.queryByText('No alert has been recorded yet.')).toBeNull()
  })

  it('distinguishes an empty log from an unread one', async () => {
    historyRows = []
    render(<AlertsPanel />)
    await waitFor(() => expect(screen.getByText('No alert has been recorded yet.')).toBeTruthy())
    expect(screen.queryByText(/could not be read/)).toBeNull()
  })

  it('re-reads the log when something is raised, rather than sitting a step behind', async () => {
    render(<AlertsPanel />)
    await waitFor(() => expect(screen.getByText('No alert has been recorded yet.')).toBeTruthy())
    historyRows = [
      { event: 'raised', kind: 'cpu', serverId: 's1', serverName: 'web-1', value: 95, threshold: 80, at: T0 }
    ]
    useAlerts.setState({
      active: {
        's1:cpu': { serverId: 's1', serverName: 'web-1', kind: 'cpu', value: 95, since: T0 }
      }
    })
    await waitFor(() => expect(document.body.textContent).toContain('95 of 80'))
  })

  it('names a stand-down as itself, not as an all-clear', async () => {
    historyRows = [
      { event: 'stood-down', kind: 'disk', serverId: 's1', serverName: 'web-1', value: 91, threshold: 85, at: T0 }
    ]
    render(<AlertsPanel />)
    await waitFor(() => expect(screen.getByText('Stood down')).toBeTruthy())
    expect(screen.queryByText('Cleared')).toBeNull()
  })
})

describe('the per-host threshold box', () => {
  const server = {
    id: 's1',
    workspaceId: 'ws-default',
    folderId: null,
    name: 'web-1',
    host: 'example.test',
    port: 22,
    username: 'root',
    auth: 'key' as const,
    status: 'offline' as const,
    tags: [],
    favorite: false,
    os: 'Linux',
    route: [],
    vpnProfileId: null
  }

  it('never stores a number the app will not honour', async () => {
    // Typing "8" on the way to "85" used to persist an 8. hostThreshold clamps
    // on read, so the app behaved correctly — but the settings blob, and every
    // backup taken from it, held a threshold no reading can be below, for
    // whoever opens one later to draw the wrong conclusion from.
    useApp.setState({ servers: [server] })
    useApp.getState().setSettings({ resourceAlertThresholds: {} })
    render(<AlertsPanel />)
    const box = await screen.findByLabelText('CPU and memory threshold for web-1')
    const user = userEvent.setup({ advanceTimers: vi.advanceTimersByTime })

    await user.type(box, '8')
    // Nothing out of range reaches the store, and the box still shows what is
    // being typed — clamping the keystroke would snap it to 50 and "85" could
    // never be typed at all.
    expect(useApp.getState().settings.resourceAlertThresholds.s1).toBeUndefined()
    expect((box as HTMLInputElement).value).toBe('8')

    await user.type(box, '5')
    expect(useApp.getState().settings.resourceAlertThresholds.s1).toBe(85)
  })

  it('clamps what is left in the box when the field is left', async () => {
    useApp.setState({ servers: [server] })
    useApp.getState().setSettings({ resourceAlertThresholds: {} })
    render(<AlertsPanel />)
    const box = await screen.findByLabelText('CPU and memory threshold for web-1')
    const user = userEvent.setup({ advanceTimers: vi.advanceTimersByTime })
    await user.type(box, '8')
    await user.tab()
    expect(useApp.getState().settings.resourceAlertThresholds.s1).toBe(50)
  })

  it('says the number it will actually alert at', async () => {
    // The row used to print the workspace default's wording for an overridden
    // host, and the alert then fired five points below whatever it printed.
    useApp.setState({ servers: [server] })
    useApp.getState().setSettings({ resourceAlertThreshold: 80, resourceAlertThresholds: { s1: 90 } })
    render(<AlertsPanel />)
    await waitFor(() => expect(screen.getByText('alerts at 90%')).toBeTruthy())
  })
})

describe('what a row is allowed to say it was about', () => {
  it('prefers the detail, falls back to the numbers, and invents nothing', () => {
    const base = { event: 'raised' as const, serverId: 's1', serverName: 'web-1', at: T0 }
    expect(rowSubject({ ...base, kind: 'job-failed', detail: 'nightly upgrade' })).toBe('nightly upgrade')
    expect(rowSubject({ ...base, kind: 'disk', value: 91, threshold: 85 })).toBe('91 of 85')
    expect(rowSubject({ ...base, kind: 'disk', value: 91 })).toBe('91')
    // Neither. Not a zero, not a dash that reads as one — nothing.
    expect(rowSubject({ ...base, kind: 'host-unreachable' })).toBe('')
  })
})

describe('coverage honesty, per kind, because the kinds do not share a source', () => {
  it('repeats the settings screen’s sentence rather than a cheerier one', async () => {
    // Background checking off. This line speaks for the sampler-borne kinds —
    // the five readings and host-unreachable — and for nothing else.
    useApp.getState().setSettings({ fleetSamplingEnabled: false })
    render(<AlertsPanel />)
    await waitFor(() =>
      expect(screen.getByText(/only fire while you are already looking/)).toBeTruthy()
    )
    expect(document.body.textContent).not.toContain('wherever you are')
  })

  it('does not claim coverage from the switch while the sampler is not looping', async () => {
    useApp.getState().setSettings({ fleetSamplingEnabled: true })
    useFleetStatus.getState().setStatus({ running: false } as never)
    render(<AlertsPanel />)
    await waitFor(() => expect(screen.getByText(/switched on but not running/)).toBeTruthy())
    expect(document.body.textContent).not.toContain('wherever you are')
  })

  it('says so when it is genuinely running', async () => {
    useApp.getState().setSettings({ fleetSamplingEnabled: true })
    useFleetStatus.getState().setStatus({ running: true } as never)
    render(<AlertsPanel />)
    await waitFor(() => expect(screen.getByText(/wherever you are/)).toBeTruthy())
  })

  it('does not let the sampler’s sentence speak for kinds it does not produce', async () => {
    // The claim that was false. Of the five kinds item 19b added, exactly one
    // — host-unreachable — is sampler-borne. job-failed rides jobs.onProgress
    // and tunnel-down a ten-second poll, both mounted at the app root and both
    // independent of fleetSamplingEnabled; db-alarm and db-watch are not
    // produced in the background at all.
    useApp.getState().setSettings({ fleetSamplingEnabled: true })
    useFleetStatus.getState().setStatus({ running: true } as never)
    render(<AlertsPanel />)
    await waitFor(() => expect(screen.getByText(/wherever you are/)).toBeTruthy())

    // The sampler's line names the kinds it actually speaks for, and does not
    // name the other four.
    const sampler = screen.getByTestId('alert-coverage-sampler').textContent ?? ''
    expect(sampler).toContain('Unreachable')
    expect(sampler).toContain('CPU')
    expect(sampler).not.toContain('Job failed')
    expect(sampler).not.toContain('Database alarm')
  })

  it('says plainly that a database verdict is only produced when the page is read', async () => {
    // The one that must never read as covered, in either sampler state.
    for (const running of [true, false]) {
      useApp.getState().setSettings({ fleetSamplingEnabled: running })
      useFleetStatus.getState().setStatus({ running } as never)
      const view = render(<AlertsPanel />)
      await waitFor(() =>
        expect(screen.getByText(/opened the Databases page and read it/)).toBeTruthy()
      )
      const db = screen.getByTestId('alert-coverage-read-on-demand').textContent ?? ''
      expect(db).toContain('Database alarm')
      expect(db).toContain('Database watch')
      expect(db).not.toMatch(/wherever you are/)
      view.unmount()
    }
  })

  it('says job failures and tunnels are watched whatever the sampler is doing', async () => {
    useApp.getState().setSettings({ fleetSamplingEnabled: false })
    useFleetStatus.getState().setStatus({ running: false } as never)
    render(<AlertsPanel />)
    const line = (await screen.findByTestId('alert-coverage-app-root')).textContent ?? ''
    expect(line).toContain('watched from the moment the app starts')
    expect(line).toContain('Job failed')
    expect(line).toContain('Tunnel down')
  })

  it('says plainly when alerts themselves are switched off', async () => {
    useApp.getState().setSettings({ resourceAlertsEnabled: false })
    render(<AlertsPanel />)
    await waitFor(() =>
      expect(screen.getByText(/switched off, so nothing new will be added/)).toBeTruthy()
    )
  })
})

describe('what the inbox lets a person do', () => {
  function outstanding(): void {
    useAlerts.setState({
      active: {
        's1:disk': { serverId: 's1', serverName: 'web-1', kind: 'disk', value: 91, since: T0 }
      }
    })
  }

  it('snoozes for a period and says until when, keeping the chip', async () => {
    outstanding()
    render(<AlertsPanel />)
    await userEvent.click(screen.getByRole('button', { name: '8 hours' }))
    // The chip stays: the condition has not changed, and a status bar that
    // disagreed with this screen is what 1a4cfaa was written to end.
    expect(useAlerts.getState().active['s1:disk']).toBeDefined()
    // A range, not an equality: userEvent runs under fake timers that advance
    // real time, so the click lands a few milliseconds after T0. Eight hours
    // from WHEN IT WAS CLICKED is the claim, and that is what this checks.
    const until = useAlerts.getState().active['s1:disk'].snoozedUntil ?? 0
    expect(until).toBeGreaterThanOrEqual(T0 + 8 * 60 * 60_000)
    expect(until).toBeLessThan(T0 + 8 * 60 * 60_000 + 60_000)
    await waitFor(() => expect(screen.getByText(/snoozed until/)).toBeTruthy())
    // And a way back out of it, on the same row.
    expect(screen.getByRole('button', { name: 'Wake' })).toBeTruthy()
  })

  it('wakes a snoozed alert again', async () => {
    outstanding()
    render(<AlertsPanel />)
    await userEvent.click(screen.getByRole('button', { name: '1 hour' }))
    await userEvent.click(screen.getByRole('button', { name: 'Wake' }))
    expect(useAlerts.getState().active['s1:disk'].snoozedUntil).toBeUndefined()
    await waitFor(() => expect(screen.getByRole('button', { name: '1 hour' })).toBeTruthy())
  })

  it('acknowledges, which takes the alert out of the outstanding list entirely', async () => {
    outstanding()
    render(<AlertsPanel />)
    await userEvent.click(screen.getByRole('button', { name: 'Acknowledge' }))
    expect(useAlerts.getState().active['s1:disk']).toBeUndefined()
    await waitFor(() =>
      expect(screen.getByText('Nothing is outstanding right now.')).toBeTruthy()
    )
  })

  it('shows a snooze and an acknowledgement in the history as themselves', async () => {
    historyRows = [
      { event: 'acknowledged', kind: 'disk', serverId: 's1', serverName: 'web-1', at: T0 - 60_000 },
      { event: 'snoozed', kind: 'cpu', serverId: 's1', serverName: 'web-1', until: T0 + 60_000, at: T0 - 120_000 }
    ]
    render(<AlertsPanel />)
    await waitFor(() => expect(screen.getByText('Acknowledged')).toBeTruthy())
    expect(screen.getByText('Snoozed')).toBeTruthy()
    // Neither is an all-clear, and the log is the only place that difference
    // can be seen.
    expect(screen.queryByText('Cleared')).toBeNull()
  })
})

describe('the chip is a pointer at the inbox', () => {
  it('opens the Fleet Monitor on the Alerts tab, not on whatever was last open', async () => {
    useNav.setState({ monitorTab: 'overview' })
    useApp.setState({ activity: 'terminal' } as never)
    useAlerts.setState({
      active: {
        's1:disk': { serverId: 's1', serverName: 'web-1', kind: 'disk', value: 91, since: T0 }
      }
    })
    render(<StatusBar />)
    const chip = screen.getByRole('button', { name: /1 alert/ })
    await userEvent.click(chip)
    expect(useNav.getState().monitorTab).toBe('alerts')
    expect(useApp.getState().activity).toBe('monitor')
  })

  it('names the host and the reading in its tooltip', () => {
    useAlerts.setState({
      active: {
        's1:disk': { serverId: 's1', serverName: 'web-1', kind: 'disk', value: 91, since: T0 },
        't1:tunnel-down': {
          serverId: 't1',
          serverName: 'office-db',
          kind: 'tunnel-down',
          value: null,
          since: T0
        }
      }
    })
    render(<StatusBar />)
    const title = screen.getByRole('button', { name: /2 alerts/ }).getAttribute('title') ?? ''
    expect(title).toContain('web-1: Disk 91%')
    // No number for a kind that has none, and no percent sign borrowed from
    // the kind beside it.
    expect(title).toContain('office-db: Tunnel down')
    expect(title).not.toContain('office-db: Tunnel down 0')
    expect(title).toContain('Click to open the alert inbox.')
  })
})

// ===========================================================================
// The layout, as behaviour.
//
// The complaint this covers, verbatim: "alerts page is weird UX, i can't
// figure out anything in this mountain of text." Everything the page said was
// true and stayed true; the problem was that the one outstanding alert was the
// seventh thing on the screen, one dim line tall, with its five controls
// rendered as five identical grey buttons.
//
// These are written as assertions about ORDER, WEIGHT and DISCLOSURE rather
// than about wording, because those three are what went wrong and they are the
// three a later edit can undo without any single line looking incorrect. A
// paragraph moved back above the alerts, an `Acknowledge` that goes back to
// `btn ghost`, a `<details>` that gains a default `open` — each is a one-word
// diff, and each one puts the mountain back.
// ===========================================================================

describe('the alert is the page', () => {
  function outstanding(): void {
    useAlerts.setState({
      active: {
        's1:disk': { serverId: 's1', serverName: 'web-1', kind: 'disk', value: 91, since: T0 }
      }
    })
  }

  it('puts the outstanding alerts above the explanation rather than under it', async () => {
    outstanding()
    render(<AlertsPanel />)
    const card = await screen.findByTestId('outstanding-alert')
    // Every explanatory block, in the order a person meets them. All four used
    // to be above the alert.
    for (const id of ['alerts-how-it-works', 'alerts-runbook', 'alerts-thresholds']) {
      const fold = screen.getByTestId(id)
      expect(
        card.compareDocumentPosition(fold) & Node.DOCUMENT_POSITION_FOLLOWING,
        `${id} renders before the outstanding alert`
      ).toBeTruthy()
    }
  })

  it('gives each outstanding alert a card of its own, longest-standing first', async () => {
    // Oldest first, which is the order the store has always sorted in. Asserted
    // here because the cards make it visible: whichever is worst-established
    // leads the page.
    useAlerts.setState({
      active: {
        's1:disk': { serverId: 's1', serverName: 'web-1', kind: 'disk', value: 91, since: T0 - 60_000 },
        's2:cpu': { serverId: 's2', serverName: 'db-1', kind: 'cpu', value: 97, since: T0 - 9 * 60 * 60_000 }
      }
    })
    render(<AlertsPanel />)
    const cards = await screen.findAllByTestId('outstanding-alert')
    expect(cards).toHaveLength(2)
    expect(cards[0].textContent).toContain('db-1')
    expect(cards[1].textContent).toContain('web-1')
    // The card carries the whole alert, so nothing about it has to be looked
    // up in a second place: what, where, the reading, and how long.
    expect(cards[0].textContent).toContain('CPU')
    expect(cards[0].textContent).toContain('97')
    expect(cards[0].textContent).toContain('since 9 h ago')
  })

  it('makes Acknowledge the one primary control and the snoozes secondary', async () => {
    // The specific thing that was wrong: 1 hour / 8 hours / 24 hours /
    // Acknowledge / Runbook were five `btn ghost sm` in one table cell, so the
    // action with a consequence looked exactly like the four that mostly do
    // not have one.
    outstanding()
    render(<AlertsPanel />)
    const ack = await screen.findByRole('button', { name: 'Acknowledge' })
    expect(ack.classList.contains('primary')).toBe(true)
    for (const label of ['1 hour', '8 hours', '24 hours', 'Runbook']) {
      expect(
        screen.getByRole('button', { name: label }).classList.contains('primary'),
        `${label} is competing with Acknowledge`
      ).toBe(false)
    }
    // And the three durations are one grouped control rather than three peers
    // scattered along the row.
    const group = screen.getByRole('button', { name: '8 hours' }).parentElement
    expect(group?.className).toContain('alert-snooze-group')
    expect(group?.querySelectorAll('button')).toHaveLength(3)
  })

  it('records an acknowledgement in the durable log, not only on the chip', async () => {
    outstanding()
    render(<AlertsPanel />)
    await userEvent.click(await screen.findByRole('button', { name: 'Acknowledge' }))
    const call = recorded.mock.calls.find((c) => (c[0] as { event: string }).event === 'acknowledged')
    expect(call, 'Acknowledge wrote nothing to the alert log').toBeTruthy()
    expect(call?.[0]).toMatchObject({ event: 'acknowledged', kind: 'disk', serverId: 's1', serverName: 'web-1' })
  })

  it('records a snooze with the moment it runs until', async () => {
    outstanding()
    render(<AlertsPanel />)
    await userEvent.click(await screen.findByRole('button', { name: '8 hours' }))
    const call = recorded.mock.calls.find((c) => (c[0] as { event: string }).event === 'snoozed')
    expect(call, 'Snooze wrote nothing to the alert log').toBeTruthy()
    const payload = call?.[0] as { until: number; serverId: string; kind: string }
    expect(payload.serverId).toBe('s1')
    expect(payload.kind).toBe('disk')
    expect(payload.until).toBeGreaterThanOrEqual(T0 + 8 * 60 * 60_000)
    expect(payload.until).toBeLessThan(T0 + 8 * 60 * 60_000 + 60_000)
  })
})

describe('the explanation, kept but folded', () => {
  it('is collapsed on arrival, so somebody who knows never scrolls past it', async () => {
    render(<AlertsPanel />)
    const fold = (await screen.findByTestId('alerts-how-it-works')) as HTMLDetailsElement
    expect(fold.open).toBe(false)
    // Folded, NOT deleted. Every sentence is still there, and each one states
    // a semantic a sysadmin needs — which is why this is a disclosure and not
    // a cut.
    expect(fold.textContent).toContain('opened the Databases page and read it')
    expect(fold.textContent).toContain('Security posture module is on for this workspace')
    expect(fold.textContent).toContain('occurrences rather than conditions')
  })

  it('opens when it is asked for', async () => {
    render(<AlertsPanel />)
    const fold = (await screen.findByTestId('alerts-how-it-works')) as HTMLDetailsElement
    // The affordance has to be a real <summary>. It is the only child of a
    // <details> that can open it, by mouse or by keyboard, and prose sealed
    // behind a styled <div> that merely looks like a disclosure head is prose
    // nobody can reach at all — strictly worse than the wall it replaced.
    const summary = fold.querySelector('summary')
    expect(summary, 'the fold has no <summary>, so nothing can open it').toBeTruthy()
    expect(summary?.textContent).toContain('How alerting works')
    await userEvent.click(screen.getByText(/How alerting works/))
    expect(fold.open).toBe(true)
  })

  it('leaves the coverage verdict outside the fold, because it is a warning', async () => {
    // The one thing that must not be folded away. "An alert can only fire
    // while you are already looking at the host" is not an explanation of how
    // the feature works, it is a statement that the feature is not watching —
    // and a warning behind a chevron is a warning nobody reads.
    useApp.getState().setSettings({ fleetSamplingEnabled: false })
    useFleetStatus.getState().setStatus({ running: false } as never)
    render(<AlertsPanel />)
    const verdict = await screen.findByText('Foreground only')
    expect(screen.getByTestId('alerts-how-it-works').contains(verdict)).toBe(false)
    // And it is read from whether the sampler is LOOPING, never from the
    // switch — the rule alertCoverage.ts exists to keep.
    useFleetStatus.getState().setStatus({ running: true } as never)
    useApp.getState().setSettings({ fleetSamplingEnabled: true })
    await waitFor(() => expect(screen.getByText('Background checks on')).toBeTruthy())
  })

  it('files per-host thresholds behind their own fold, out of the alert flow', async () => {
    // Configuration, not an alert. It used to sit between the outstanding list
    // and the history, with a paragraph of justification attached.
    useApp.setState({
      servers: [
        {
          id: 's1',
          workspaceId: 'ws-default',
          folderId: null,
          name: 'web-1',
          host: 'example.test',
          port: 22,
          username: 'root',
          auth: 'key' as const,
          status: 'offline' as const,
          tags: [],
          favorite: false,
          os: 'Linux',
          route: [],
          vpnProfileId: null
        }
      ]
    })
    render(<AlertsPanel />)
    const fold = (await screen.findByTestId('alerts-thresholds')) as HTMLDetailsElement
    expect(fold.open).toBe(false)
    // Folded, and still whole: the box and the paragraph explaining why disk,
    // inodes and load are not settable per host are both in there.
    expect(fold.contains(screen.getByLabelText('CPU and memory threshold for web-1'))).toBe(true)
    expect(fold.textContent).toContain('deliberately not settable per host')
  })
})

describe('the quiet state', () => {
  it('answers an empty inbox with a settled state rather than an absence', async () => {
    render(<AlertsPanel />)
    await waitFor(() => expect(screen.getByText('Nothing is outstanding right now.')).toBeTruthy())
    // Not a bare grey half-line. "Everything is fine" and "nothing loaded"
    // look identical when the answer is one faint sentence, and on an alerts
    // page that is the more expensive of the two to get wrong — so the settled
    // state says where the things that DID happen went.
    expect(screen.getByText(/Anything that has been raised and cleared is in the history/)).toBeTruthy()
    expect(screen.queryAllByTestId('outstanding-alert')).toHaveLength(0)
  })
})
