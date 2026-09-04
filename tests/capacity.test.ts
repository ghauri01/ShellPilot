import { describe, it, expect } from 'vitest'
import {
  CAPACITY_METRICS,
  CAPACITY_THRESHOLDS,
  FORECAST_MIN_POINTS,
  buildCapacityReport,
  downsample,
  forecast,
  resolutionBoundary,
  runs,
  segments,
  type CapacityMetric,
  type TrendPoint
} from '../src/shared/capacity'
import { METRICS, type Metric, type SeriesPoint } from '../src/main/services/history'

const MIN = 60_000
const HOUR = 3_600_000
const DAY = 86_400_000

// A fixed instant, so every expected number below is a literal a reader can
// check by hand rather than something recomputed from Date.now().
const T0 = 1_700_000_000_000

/** `count` points ending at `end`, spaced `step` apart, value from the index. */
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

describe('the metrics a capacity question is asked about', () => {
  it('names three of item A metrics and nothing invented', () => {
    expect(CAPACITY_METRICS).toEqual(['cpu', 'memPct', 'diskPct'])
    // Every one of them is a real series the sampler writes. A name that
    // drifted from METRICS would read as an empty chart forever, with nothing
    // on screen to say the metric does not exist.
    for (const m of CAPACITY_METRICS) expect(METRICS).toContain(m)
    // And the compile-time half of the same statement, in both directions:
    // main hands the store real SeriesPoints to this module's TrendPoint, and
    // asks the store for these names as Metrics.
    const asMetrics: readonly Metric[] = CAPACITY_METRICS
    expect(asMetrics.length).toBe(3)
    const fromStore: SeriesPoint = { ts: 1, v: 2, res: 'hourly', min: 1, max: 3, n: 4 }
    const asTrendPoint: TrendPoint = fromStore
    expect(asTrendPoint.n).toBe(4)
  })

  it('forecasts a disk and a memory, and refuses to forecast a cpu', () => {
    // A CPU at 100% is busy, not full. Offering "your cpu fills in 4 days"
    // would be the feature saying something it cannot mean.
    expect(CAPACITY_THRESHOLDS.diskPct).toBe(90)
    expect(CAPACITY_THRESHOLDS.memPct).toBe(90)
    expect(CAPACITY_THRESHOLDS.cpu).toBeUndefined()
  })
})

describe('a step change is not a trend', () => {
  it('refuses a disk that jumped once and has been flat since', () => {
    // Three days at 50%, somebody untars a release, three days at 70%. A least
    // squares fit through that has a slope of about 3 points a day and will
    // happily say the disk fills next week. Nothing is filling: it is a step.
    const flatThenStep = points(T0, 145, HOUR, 'hourly', (i) => (i < 72 ? 50 : 70))
    const f = forecast(flatThenStep, 90, T0)
    expect(f.ok).toBe(false)
    expect(f.ok === false && f.reason).toBe('step-change')
    // And it says which window it looked at, so the refusal is checkable.
    expect(f.from).toBe(T0 - 144 * HOUR)
    expect(f.to).toBe(T0)
    expect(f.points).toBe(145)
  })

  it('still catches a step that lands mid-hour and is smeared over two buckets', () => {
    // The hourly tier averages within the hour, so an instantaneous jump at
    // 03:30 arrives as two half-steps rather than one. A rule that only looked
    // at single consecutive differences would let this through.
    const smeared = points(T0, 145, HOUR, 'hourly', (i) => (i < 72 ? 50 : i === 72 ? 60 : 70))
    const f = forecast(smeared, 90, T0)
    expect(f.ok === false && f.reason).toBe('step-change')
  })
})

describe('a gap is not a flat line', () => {
  it('splits the series where the server stopped answering', () => {
    const before = points(T0 - 2 * DAY - 12 * HOUR, 73, HOUR, 'hourly', (i) => 40 + i * 0.4)
    const after = points(T0, 13, HOUR, 'hourly', () => 80)
    const both = [...before, ...after]
    expect(runs(both).map((r) => r.length)).toEqual([73, 13])
  })

  it('forecasts from the latest run only, never across the silence', () => {
    // Three days climbing 40 -> 68.8, then two days unreachable, then half a
    // day flat at 80. Fitting the whole array gives a steep rise that nothing
    // observed: the climb ended before the outage and the 40 -> 80 step across
    // it is an artefact of the host being absent, not a measurement.
    const before = points(T0 - 2 * DAY - 12 * HOUR, 73, HOUR, 'hourly', (i) => 40 + i * 0.4)
    const after = points(T0, 13, HOUR, 'hourly', () => 80)
    const f = forecast([...before, ...after], 90, T0)
    expect(f.ok).toBe(false)
    // Flat, because the run it is entitled to use is flat.
    expect(f.ok === false && f.reason).toBe('flat')
    // Drawn from the twelve hours after the outage, not the five days on disk.
    expect(f.from).toBe(T0 - 12 * HOUR)
    expect(f.to).toBe(T0)
    expect(f.points).toBe(13)
  })

  it('leaves the silence in the drawn line as a hole, not a segment boundary to bridge', () => {
    const before = points(T0 - 2 * DAY - 12 * HOUR, 73, HOUR, 'hourly', (i) => 40 + i * 0.4)
    const after = points(T0, 13, HOUR, 'hourly', () => 80)
    const drawn = segments([...before, ...after])
    expect(drawn.length).toBe(2)
    expect(drawn[0].gapBefore).toBe(0)
    expect(drawn[1].gapBefore).toBe(2 * DAY)
    // Nothing was manufactured inside the silence.
    const inGap = drawn
      .flatMap((s) => s.points)
      .filter((p) => p.ts > T0 - 2 * DAY - 12 * HOUR && p.ts < T0 - 12 * HOUR)
    expect(inGap).toEqual([])
  })

  it('does not call every interval a gap on a fleet sampled every ten minutes', () => {
    // The gap rule is derived from the series own spacing. Pinned to a
    // two-minute cadence constant it would shatter a ten-minute fleet into one
    // run per sample and refuse every forecast on the estate.
    const slow = points(T0, 60, 10 * MIN, 'full', (i) => 50 + i * 0.01)
    expect(runs(slow).length).toBe(1)
  })
})

describe('a series too young to have a rate', () => {
  it('refuses two hours of samples and says the window was too short', () => {
    // Sixty-one points is plenty of points. It is still two hours, and a disk
    // that gained a percent during one backup has not told you anything about
    // next week.
    const young = points(T0, 61, 2 * MIN, 'full', (i) => 50 + i * 0.1)
    expect(young.length).toBeGreaterThan(FORECAST_MIN_POINTS)
    const f = forecast(young, 90, T0)
    expect(f.ok).toBe(false)
    expect(f.ok === false && f.reason).toBe('window-too-short')
    expect(f.to - f.from).toBe(2 * HOUR)
    expect(f.points).toBe(61)
  })

  it('refuses a handful of points even when they span days', () => {
    const sparse = points(T0, 6, 12 * HOUR, 'hourly', (i) => 50 + i * 2)
    const f = forecast(sparse, 90, T0)
    expect(f.ok === false && f.reason).toBe('too-few-points')
    expect(f.points).toBe(6)
  })

  it('refuses a series that stopped reporting, rather than extrapolating a dead server', () => {
    const stopped = points(T0 - 2 * DAY, 145, HOUR, 'hourly', (i) => 60 + i * 0.1)
    const f = forecast(stopped, 90, T0)
    expect(f.ok === false && f.reason).toBe('stale')
    expect(f.to).toBe(T0 - 2 * DAY)
  })
})

describe('a flat disk', () => {
  it('forecasts nothing rather than a date thirty thousand years out', () => {
    // The failure this exists to prevent is arithmetic, not judgement: a slope
    // of zero divides into infinity and renders as "fills in Infinity days" or
    // as a date in the year 33000, both of which look like a working feature.
    const flat = points(T0, 73, HOUR, 'hourly', () => 50)
    const f = forecast(flat, 90, T0)
    expect(f.ok).toBe(false)
    expect(f.ok === false && f.reason).toBe('flat')
    expect('days' in f).toBe(false)
    expect('at' in f).toBe(false)
  })

  it('calls a disk that is emptying falling, not filling', () => {
    const shrinking = points(T0, 73, HOUR, 'hourly', (i) => 70 - i * 0.1)
    const f = forecast(shrinking, 90, T0)
    expect(f.ok === false && f.reason).toBe('falling')
  })

  it('says nothing about a disk that is already over the threshold', () => {
    const over = points(T0, 73, HOUR, 'hourly', (i) => 88 + i * 0.05)
    const f = forecast(over, 90, T0)
    expect(f.ok === false && f.reason).toBe('already-past')
  })

  it('refuses a memory series that swings between sweeps', () => {
    // Real memory bounces twenty points in four minutes. There is a slope
    // through it and it means nothing.
    const bouncing = points(T0, 200, 2 * MIN, 'full', (i) => 50 + (i % 7) * 6 + i * 0.02)
    const f = forecast(bouncing, 90, T0)
    expect(f.ok === false && f.reason).toBe('noisy')
  })
})

describe('a disk that is genuinely filling', () => {
  // Six days of hourly means, 64.5% rising a point and a half a day, with a
  // small repeating wobble so the fit is not artificially perfect. 64.5 + 17 *
  // 1.5 = 90, so the crossing is seventeen days after the run started and the
  // run ended today: eleven days from now.
  const filling = points(T0, 145, HOUR, 'hourly', (i) => 64.5 + (i / 24) * 1.5 + ((i % 5) - 2) * 0.05)

  it('says eleven days', () => {
    const f = forecast(filling, 90, T0)
    expect(f.ok).toBe(true)
    if (!f.ok) throw new Error('expected a forecast')
    expect(f.days).toBeCloseTo(11, 0)
    expect(f.at).toBeCloseTo(T0 + 11 * DAY, -7)
    expect(f.perDay).toBeCloseTo(1.5, 2)
    expect(f.threshold).toBe(90)
  })

  it('states the window it was drawn from, not only the conclusion', () => {
    // "Fills in 11 days" is not an honest sentence on its own. "Fills in 11
    // days, from 6 days of data" is, and the difference is these three fields.
    const f = forecast(filling, 90, T0)
    if (!f.ok) throw new Error('expected a forecast')
    expect(f.from).toBe(T0 - 144 * HOUR)
    expect(f.to).toBe(T0)
    expect(f.points).toBe(145)
    expect(f.to - f.from).toBe(6 * DAY)
    expect(f.res).toBe('hourly')
    expect(f.confidence).toBe('high')
  })

  it('drops to a lower confidence on a shorter run of the same slope', () => {
    // Same rate, eight hours of it. The date is the same arithmetic; the claim
    // behind it is much weaker, and the label has to say so.
    const short = points(T0, 9, HOUR, 'hourly', (i) => 64.5 + (i / 24) * 1.5)
    const f = forecast([...points(T0 - 9 * HOUR, 4, HOUR, 'hourly', () => 64.4), ...short], 90, T0)
    if (!f.ok) throw new Error('expected a forecast')
    expect(f.confidence).toBe('low')
  })
})

describe('the boundary between item A two tiers', () => {
  // Item A keeps seven days at full resolution and eighty-three days of hourly
  // means, so any window longer than a week crosses the boundary. It is
  // routine. The line either says which half is which or it is presenting a
  // mean of thirty readings as a measurement.
  const older = points(T0 - 120 * MIN, 48, HOUR, 'hourly', (i) => 60 + i * 0.02)
  const recent = points(T0, 60, 2 * MIN, 'full', (i) => 61 + i * 0.001)
  const mixed = [...older, ...recent]

  it('reports where full resolution begins', () => {
    expect(resolutionBoundary(mixed)).toBe(recent[0].ts)
  })

  it('reports no boundary when the window holds only one tier', () => {
    expect(resolutionBoundary(older)).toBeNull()
    expect(resolutionBoundary(recent)).toBeNull()
    expect(resolutionBoundary([])).toBeNull()
  })

  it('draws the two tiers as separate segments with no silence between them', () => {
    const drawn = segments(mixed)
    expect(drawn.map((s) => s.res)).toEqual(['hourly', 'full'])
    // Zero, and that is the point: the measurement changed, the clock did not
    // skip. A chart that broke the line here would report an outage that never
    // happened, every time a window longer than a week is opened.
    expect(drawn[1].gapBefore).toBe(0)
  })

  it('tells a forecast which kind of data it used', () => {
    // The run spans the boundary, so the fit saw both an average of thirty
    // readings and single readings. Reporting that as 'full' would present the
    // whole line as measurements.
    const f = forecast(mixed, 90, T0)
    if (!f.ok) throw new Error(`expected a forecast, got ${f.reason}`)
    expect(f.res).toBe('mixed')
    expect(f.from).toBe(mixed[0].ts)
    expect(f.points).toBe(108)
  })
})

describe('downsampling', () => {
  it('keeps the extremes rather than averaging a spike away', () => {
    // On a disk it is the peak that matters. A bucket that reported only its
    // mean would have removed the only interesting thing in the window.
    const segment = {
      res: 'hourly' as const,
      gapBefore: 0,
      points: [
        { ts: T0, v: 10, res: 'hourly' as const, min: 5, max: 40, n: 30 },
        { ts: T0 + HOUR, v: 12, res: 'hourly' as const, min: 8, max: 90, n: 30 }
      ]
    }
    const out = downsample(segment, 6 * HOUR)
    expect(out.points).toEqual([{ ts: T0, v: 11, res: 'hourly', min: 5, max: 90, n: 60 }])
  })

  it('weights the mean by the readings behind each bucket', () => {
    const segment = {
      res: 'hourly' as const,
      gapBefore: 0,
      points: [
        { ts: T0, v: 0, res: 'hourly' as const, min: 0, max: 0, n: 30 },
        { ts: T0 + HOUR, v: 60, res: 'hourly' as const, min: 60, max: 60, n: 10 }
      ]
    }
    // The straight mean is 30. Forty readings averaging (30*0 + 10*60)/40 is
    // 15, which is what those forty machines actually reported.
    expect(downsample(segment, 6 * HOUR).points[0].v).toBe(15)
  })

  it('does not invent a spread for a single instantaneous reading', () => {
    const segment = {
      res: 'full' as const,
      gapBefore: 0,
      points: [{ ts: T0, v: 42, res: 'full' as const }]
    }
    expect(downsample(segment, HOUR).points).toEqual([{ ts: T0, v: 42, res: 'full' }])
  })

  it('never merges across a gap, because buckets are taken inside a segment', () => {
    const before = points(T0 - 2 * DAY - 12 * HOUR, 73, HOUR, 'hourly', () => 40)
    const after = points(T0, 13, HOUR, 'hourly', () => 80)
    const drawn = segments([...before, ...after]).map((s) => downsample(s, 7 * DAY))
    // One bucket each, and emphatically not one bucket of 60 spanning both
    // sides of the outage.
    expect(drawn.length).toBe(2)
    expect(drawn[0].points.map((p) => p.v)).toEqual([40])
    expect(drawn[1].points.map((p) => p.v)).toEqual([80])
  })
})

describe('the report main hands the panel', () => {
  const series: Partial<Record<CapacityMetric, TrendPoint[]>> = {
    cpu: points(T0, 145, HOUR, 'hourly', (i) => 20 + (i % 9)),
    memPct: points(T0, 145, HOUR, 'hourly', () => 44),
    diskPct: points(T0, 145, HOUR, 'hourly', (i) => 64.5 + (i / 24) * 1.5)
  }
  const report = buildCapacityReport('srv-alpha', series, {
    now: T0,
    from: T0 - 7 * DAY,
    to: T0,
    thresholds: CAPACITY_THRESHOLDS,
    fullResolutionDays: 7,
    retainedDays: 90
  })

  it('answers with a conclusion per metric, not with the samples', () => {
    expect(report.hostId).toBe('srv-alpha')
    expect(report.trends.map((t) => t.metric)).toEqual(['cpu', 'memPct', 'diskPct'])
    const disk = report.trends[2]
    expect(disk.read).toBe(145)
    if (!disk.forecast?.ok) throw new Error('expected a disk forecast')
    expect(disk.forecast.days).toBeCloseTo(11, 0)
  })

  it('carries the store retention horizons rather than making the panel guess', () => {
    // The renderer cannot import a main-process constant, and a panel with "7
    // days" typed into it goes on saying that after the policy changes.
    expect(report.fullResolutionDays).toBe(7)
    expect(report.retainedDays).toBe(90)
  })

  it('gives cpu a line and no forecast', () => {
    expect(report.trends[0].forecast).toBeNull()
    expect(report.trends[0].segments.length).toBe(1)
  })

  it('sends a drawable number of points, not seven thousand samples', () => {
    const drawn = report.trends[2].segments.reduce((n, s) => n + s.points.length, 0)
    expect(report.trends[2].read).toBe(145)
    expect(drawn).toBeLessThanOrEqual(145)
    expect(drawn).toBeGreaterThan(0)
  })

  it('reports the range seen including the hourly tier own extremes', () => {
    const spiky: Partial<Record<CapacityMetric, TrendPoint[]>> = {
      diskPct: [
        { ts: T0 - HOUR, v: 50, res: 'hourly', min: 20, max: 99, n: 30 },
        { ts: T0, v: 51, res: 'full' }
      ]
    }
    const r = buildCapacityReport('srv-alpha', spiky, {
      now: T0,
      from: T0 - DAY,
      to: T0,
      thresholds: CAPACITY_THRESHOLDS,
      fullResolutionDays: 7,
      retainedDays: 90
    })
    // 99 was reached inside that hour. A panel that only read the mean would
    // report a quiet 51% for a disk that touched 99.
    expect(r.trends[2].high).toBe(99)
    expect(r.trends[2].low).toBe(20)
  })

  it('reports nothing at all for a server with no history, without throwing', () => {
    const r = buildCapacityReport('srv-new', {}, {
      now: T0,
      from: T0 - DAY,
      to: T0,
      thresholds: CAPACITY_THRESHOLDS,
      fullResolutionDays: 7,
      retainedDays: 90
    })
    expect(r.trends.map((t) => t.read)).toEqual([0, 0, 0])
    expect(r.trends[2].latest).toBeNull()
    expect(r.trends[2].forecast).toEqual({ ok: false, reason: 'no-data', from: 0, to: 0, points: 0 })
  })
})
