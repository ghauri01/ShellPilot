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

function install(): void {
  stubBridge({
    getVersion: () => Promise.resolve('9.9.9'),
    notify: { show: () => {} },
    alerts: {
      record: () => Promise.resolve(true),
      history: () =>
        historyFails ? Promise.reject(new Error('database is locked')) : Promise.resolve(historyRows)
    }
  })
}

beforeEach(() => {
  historyRows = []
  historyFails = false
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
    await waitFor(() => expect(screen.getByText('Unreachable')).toBeTruthy())
    expect(document.body.textContent).toContain('since 30 min ago')
    // A state kind has no reading. A "0" here would be a measurement nobody
    // took, which is the rule the whole item runs on.
    expect(document.body.textContent).not.toContain('0%')
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

describe('coverage honesty, which the new kinds inherit', () => {
  it('repeats the settings screen’s sentence rather than a cheerier one', async () => {
    // Background checking off. Every kind this item added is raised from the
    // same sampler, so every one of them is foreground-only here.
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

  it('says plainly when alerts themselves are switched off', async () => {
    useApp.getState().setSettings({ resourceAlertsEnabled: false })
    render(<AlertsPanel />)
    await waitFor(() =>
      expect(screen.getByText(/switched off, so nothing new will be added/)).toBeTruthy()
    )
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
