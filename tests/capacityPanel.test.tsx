// @vitest-environment jsdom
import { describe, expect, it } from 'vitest'
import { act, render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { stubBridge } from './setup/renderer'
import { CapacityPanel } from '../src/renderer/src/components/monitor/CapacityPanel'
import {
  CAPACITY_THRESHOLDS,
  buildCapacityReport,
  type CapacityReport,
  type TrendPoint
} from '../src/shared/capacity'
import type { Server } from '../src/renderer/src/types'

// The panel half of roadmap item 26, rendered rather than read.
//
// These assert what an operator sees, because the failures this item is about
// are all things that LOOK fine: a forecast with no window behind it, one line
// drawn through two resolutions, a straight line across two days when the host
// was unreachable. Every one of those renders without an error.

const MIN = 60_000
const HOUR = 3_600_000
const DAY = 86_400_000
const T0 = 1_700_000_000_000

function server(id: string, name: string): Server {
  return {
    id,
    workspaceId: 'ws-default',
    folderId: null,
    name,
    host: `${id}.example.internal`,
    port: 22,
    username: 'ops',
    auth: 'key',
    status: 'online',
    tags: [],
    favorite: false,
    os: 'linux',
    route: [],
    vpnProfileId: null
  }
}

const ALPHA = server('srv-alpha', 'alpha')
const BRAVO = server('srv-bravo', 'bravo')

function points(
  end: number,
  count: number,
  step: number,
  res: 'full' | 'hourly',
  value: (i: number) => number
): TrendPoint[] {
  const start = end - (count - 1) * step
  return Array.from({ length: count }, (_, i) => ({ ts: start + i * step, v: value(i), res }))
}

function report(diskPct: TrendPoint[], windowDays = 7, hostId = 'srv-alpha'): CapacityReport {
  return buildCapacityReport(
    hostId,
    { cpu: [], memPct: [], diskPct },
    {
      now: T0,
      from: T0 - windowDays * DAY,
      to: T0,
      thresholds: CAPACITY_THRESHOLDS,
      fullResolutionDays: 7,
      retainedDays: 90
    }
  )
}

/** Six days of hourly means, 64.5% climbing a point and a half a day. 64.5 +
 *  17 * 1.5 = 90, so the crossing is eleven days after the end of the run. */
const FILLING = points(T0, 145, HOUR, 'hourly', (i) => 64.5 + (i / 24) * 1.5)

// No fake clock, deliberately. Every number on screen comes from the report,
// which is built at the fixed T0 above — the crossing date, the window, the
// rate. A panel that needed the wall clock to render a stored forecast would
// be reading something the report did not say.

describe('a disk that is filling', () => {
  it('says when it fills AND how much data that came from', async () => {
    // The sentence this whole item exists for. The second half is not
    // decoration: without it the reader cannot tell an eleven-day forecast
    // from six days of data apart from one from ninety minutes.
    stubBridge({ capacity: { trends: () => Promise.resolve(report(FILLING)) } })
    render(<CapacityPanel servers={[ALPHA]} />)
    await waitFor(() =>
      expect(screen.getByText(/Reaches 90% in 11 days/)).toBeTruthy()
    )
    expect(screen.getByText(/from 6 days of data/)).toBeTruthy()
    expect(screen.getByText(/\+1\.5 points a day/)).toBeTruthy()
    expect(screen.getByText('high confidence')).toBeTruthy()
  })

  it('shows the reading the forecast starts from', async () => {
    stubBridge({ capacity: { trends: () => Promise.resolve(report(FILLING)) } })
    render(<CapacityPanel servers={[ALPHA]} />)
    // 64.5 + 6 * 1.5 = 73.5.
    await waitFor(() => expect(screen.getByText(/73\.5%/)).toBeTruthy())
  })
})

describe('a forecast the data cannot support', () => {
  it('says which rule refused, not just that there is no number', async () => {
    // Two hours old. Sixty-one samples is plenty of samples; two hours is not
    // a rate, and a panel that only said "not enough data" leaves the operator
    // unable to tell whether to come back in an hour or never.
    const young = points(T0, 61, 2 * MIN, 'full', (i) => 50 + i * 0.1)
    stubBridge({ capacity: { trends: () => Promise.resolve(report(young, 1)) } })
    render(<CapacityPanel servers={[ALPHA]} />)
    await waitFor(() => expect(screen.getByText(/Only 2 hours of unbroken data/)).toBeTruthy())
    expect(screen.getByText(/at least 6 hours/)).toBeTruthy()
    expect(screen.queryByText(/Reaches 90%/)).toBeNull()
  })

  it('refuses a step change and says it was one step', async () => {
    const step = points(T0, 145, HOUR, 'hourly', (i) => (i < 72 ? 50 : 70))
    stubBridge({ capacity: { trends: () => Promise.resolve(report(step)) } })
    render(<CapacityPanel servers={[ALPHA]} />)
    await waitFor(() => expect(screen.getByText(/is one step, not a trend/)).toBeTruthy())
    expect(screen.queryByText(/Reaches 90%/)).toBeNull()
  })

  it('says nothing rather than a date for a flat disk', async () => {
    const flat = points(T0, 145, HOUR, 'hourly', () => 50)
    stubBridge({ capacity: { trends: () => Promise.resolve(report(flat)) } })
    render(<CapacityPanel servers={[ALPHA]} />)
    await waitFor(() => expect(screen.getByText(/Flat over 6 days/)).toBeTruthy())
    // The specific thing a slope of zero produces if nothing stops it.
    expect(screen.queryByText(/Infinity/)).toBeNull()
    expect(screen.queryByText(/NaN/)).toBeNull()
  })
})

describe('a server that was unreachable', () => {
  const before = points(T0 - 2 * DAY - 12 * HOUR, 73, HOUR, 'hourly', (i) => 40 + i * 0.4)
  const after = points(T0, 13, HOUR, 'hourly', () => 80)

  it('breaks the line rather than drawing through the silence', async () => {
    stubBridge({ capacity: { trends: () => Promise.resolve(report([...before, ...after])) } })
    const { container } = render(<CapacityPanel servers={[ALPHA]} />)
    await waitFor(() => expect(screen.getByText(/No samples for 2 days/)).toBeTruthy())
    // Two paths in the disk chart, not one drawn across the gap. A single path
    // would climb 40 to 80 through two days that were never measured.
    const disk = screen.getByLabelText(/^Disk over the last/)
    expect(disk.querySelectorAll('path[stroke="currentColor"]').length).toBe(2)
    expect(container.querySelectorAll('[data-testid="segment-hourly"]').length).toBe(2)
  })

  it('does not forecast from the climb on the far side of the outage', async () => {
    stubBridge({ capacity: { trends: () => Promise.resolve(report([...before, ...after])) } })
    render(<CapacityPanel servers={[ALPHA]} />)
    await waitFor(() => expect(screen.getByText(/Flat over 12 hours/)).toBeTruthy())
    expect(screen.queryByText(/Reaches 90%/)).toBeNull()
  })
})

describe('the boundary between the two stored resolutions', () => {
  const mixed = [
    ...points(T0 - 120 * MIN, 48, HOUR, 'hourly', (i) => 60 + i * 0.02),
    ...points(T0, 60, 2 * MIN, 'full', (i) => 61 + i * 0.001)
  ]

  it('says which part of the line is means and which is readings', async () => {
    stubBridge({ capacity: { trends: () => Promise.resolve(report(mixed, 30)) } })
    const { container } = render(<CapacityPanel servers={[ALPHA]} />)
    await waitFor(() =>
      expect(screen.getByText(/hourly means\. After: individual readings/)).toBeTruthy()
    )
    expect(container.querySelectorAll('[data-testid="resolution-boundary"]').length).toBe(1)
    // And the two halves are drawn as their own segments, so a reader can see
    // the change without reading the caption.
    expect(container.querySelectorAll('[data-testid="segment-hourly"]').length).toBe(1)
    expect(container.querySelectorAll('[data-testid="segment-full"]').length).toBe(1)
  })

  it('draws no boundary rule when the window holds only one resolution', async () => {
    stubBridge({ capacity: { trends: () => Promise.resolve(report(FILLING)) } })
    const { container } = render(<CapacityPanel servers={[ALPHA]} />)
    await waitFor(() => expect(screen.getByText(/Reaches 90%/)).toBeTruthy())
    // A rule drawn here would mark a change of measurement that did not happen.
    expect(container.querySelectorAll('[data-testid="resolution-boundary"]').length).toBe(0)
    // The caption still says what the single resolution IS — an unlabelled
    // line is the same problem as a mislabelled one.
    expect(screen.getByText('hourly means.')).toBeTruthy()
  })

  it('states the store retention, from the report rather than from a literal', async () => {
    stubBridge({ capacity: { trends: () => Promise.resolve(report(FILLING)) } })
    render(<CapacityPanel servers={[ALPHA]} />)
    await waitFor(() =>
      expect(
        screen.getByText(/keeps 7 days of individual readings and 90 days of hourly means/)
      ).toBeTruthy()
    )
  })
})

describe('reading for the wrong server', () => {
  it('does not land one server trends under another server heading', async () => {
    // The DockerPanel defect, in a place where it would be worse: a disk
    // forecast is a number an operator acts on, and there is nothing on screen
    // that would reveal it belonged to a different machine.
    let resolveAlpha: (r: CapacityReport) => void = () => {}
    const alphaPending = new Promise<CapacityReport>((r) => {
      resolveAlpha = r
    })
    stubBridge({
      capacity: {
        trends: (hostId: string) =>
          hostId === 'srv-alpha'
            ? alphaPending
            : Promise.resolve(report(points(T0, 145, HOUR, 'hourly', () => 12), 7, 'srv-bravo'))
      }
    })
    const user = userEvent.setup()
    render(<CapacityPanel servers={[ALPHA, BRAVO]} />)
    await user.selectOptions(screen.getByLabelText('Server'), 'srv-bravo')
    await waitFor(() => expect(screen.getByText(/12\.0%/)).toBeTruthy())

    // Alpha's read, still in flight when the operator moved on, now lands.
    // Flushed through React inside act, so this asserts on the DOM AFTER the
    // late resolution has had every chance to overwrite it — the assertion is
    // worthless if it runs before the stale write would have landed.
    await act(async () => {
      resolveAlpha(report(FILLING))
      await Promise.resolve()
    })
    // Bravo is still what is on screen, and alpha's forecast is not.
    expect(screen.getByText(/12\.0%/)).toBeTruthy()
    expect(screen.queryByText(/Reaches 90% in 11 days/)).toBeNull()
    expect(screen.queryByText(/73\.5%/)).toBeNull()
  })
})

describe('when there is nothing to show', () => {
  it('says the preload has no capacity channel rather than throwing', () => {
    stubBridge({})
    render(<CapacityPanel servers={[ALPHA]} />)
    expect(screen.getByText(/does not expose capacity trends yet/)).toBeTruthy()
  })

  it('says history is empty rather than drawing an empty chart', async () => {
    stubBridge({ capacity: { trends: () => Promise.resolve(null) } })
    render(<CapacityPanel servers={[ALPHA]} />)
    await waitFor(() => expect(screen.getByText(/No stored history/)).toBeTruthy())
  })

  it('reports a failed read instead of an empty panel', async () => {
    stubBridge({ capacity: { trends: () => Promise.reject(new Error('nope')) } })
    render(<CapacityPanel servers={[ALPHA]} />)
    await waitFor(() => expect(screen.getByText(/Could not read the history store/)).toBeTruthy())
  })
})
