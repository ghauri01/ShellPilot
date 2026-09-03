// Capacity trends and the one sentence they exist to produce — roadmap item 26.
//
//     "This disk fills in eleven days."
//
// ----------------------------------------------------------------------------
// What this is, and what it deliberately is not
// ----------------------------------------------------------------------------
// Item A shipped a durable store. This is its first user-visible consumer, and
// the roadmap is explicit that it is "a query and a chart, not a subsystem".
// The rule that keeps it that way is that NOTHING is stored here. Every number
// below is derived, on demand, from samples the fleet sampler already wrote.
// A capacity feature that starts keeping its own rollups, its own thresholds
// per host and its own evaluation timer has become the metrics warehouse the
// roadmap says not to build, and it will lose to Prometheus.
//
// ----------------------------------------------------------------------------
// Why the refusals are the feature
// ----------------------------------------------------------------------------
// A least-squares fit will cheerfully report that a disk fills in three days
// because somebody untarred a release into /var once. It will report a
// crossing date from ninety minutes of data. It will draw a straight line
// through two days when the host was unreachable and call the slope a trend.
// Each of those is worse than saying nothing, because an operator who acts on
// one and finds nothing wrong stops reading the next one.
//
// So `forecast` returns a REFUSAL with a reason far more often than it returns
// a date, and every refusal names which rule stopped it. The thresholds are
// exported constants rather than literals inside the function so a test can
// state the number it is testing and a reader can see the whole policy in one
// place.
//
// ----------------------------------------------------------------------------
// Percentages only
// ----------------------------------------------------------------------------
// cpu, memPct and diskPct — three of item A's eight series, all of them 0-100.
// diskUsed and memUsed are bytes and would need per-host totals to mean
// anything, and "fills in eleven days" is a question about the percentage
// anyway. Restricting the input domain is what lets FLAT_RISE_PCT below be a
// number rather than a per-metric configuration table.
//
// ----------------------------------------------------------------------------
// No imports
// ----------------------------------------------------------------------------
// This file imports nothing, from anywhere. `TrendPoint` is structurally the
// history store's `SeriesPoint` and the assignability is asserted in
// tests/capacity.test.ts, because shared/ may not reach into src/main. Main
// passes real SeriesPoints in; the renderer receives the report over IPC.

/** The three series a capacity question is asked about. A subset of item A's
 *  METRICS, by name, checked against it where main wires the two together. */
export const CAPACITY_METRICS = ['cpu', 'memPct', 'diskPct'] as const

export type CapacityMetric = (typeof CAPACITY_METRICS)[number]

/** One sample as the history store returns it. Structurally `SeriesPoint`. */
export interface TrendPoint {
  ts: number
  v: number
  /** Which tier it came from. 'hourly' is a mean of `n` readings; 'full' is one
   *  instantaneous reading. A consumer that cannot tell them apart is drawing a
   *  mean of thirty samples as if it were a measurement. */
  res: 'full' | 'hourly'
  min?: number
  max?: number
  n?: number
}

/**
 * A contiguous run of points at ONE resolution, ready to draw as one line.
 *
 * The two reasons a series breaks into more than one of these are the two
 * things a chart must not smooth over:
 *
 *  - a GAP. A host that was unreachable for two days has no samples for two
 *    days. Drawing a straight line across that invents a trend that nothing
 *    observed. `gapBefore` is how long the silence was, in ms.
 *  - a RESOLUTION CHANGE. Item A keeps seven days at full resolution and
 *    eighty-three days of hourly means, so any window longer than a week
 *    crosses that boundary. It is routine, not an anomaly, and the two halves
 *    of the line are not the same kind of measurement.
 */
export interface TrendSegment {
  res: 'full' | 'hourly'
  points: TrendPoint[]
  /** Silence before this segment, in ms. 0 when it merely follows a resolution
   *  change with no missing time — the line continues, its meaning changes. */
  gapBefore: number
}

/** Why `forecast` declined to give a number. One per host per metric, and the
 *  UI shows it in place of a date; see refusalText in the renderer's lib. */
export type RefusalReason =
  /** Nothing in the window at all. */
  | 'no-data'
  /** The newest sample is too old to extrapolate from — the host stopped
   *  reporting, and a forecast from a dead series is a forecast about the past. */
  | 'stale'
  | 'too-few-points'
  /** The run is real but too short a slice of time to have a rate. */
  | 'window-too-short'
  /** Already at or over the threshold. There is nothing to predict. */
  | 'already-past'
  /** The line does not move enough over its own window to call it a trend. */
  | 'flat'
  /** It is going down. */
  | 'falling'
  /** The points scatter too far from the fit for the fit to mean anything. */
  | 'noisy'
  /** The rise is one jump, not a trend. Someone untarred something. */
  | 'step-change'
  /** A real rate, but the crossing is past the horizon this feature will
   *  state — beyond which "the rate holds" is not a claim worth making. */
  | 'beyond-horizon'

export interface ForecastRefused {
  ok: false
  reason: RefusalReason
  /** The run the refusal is about, so the UI can say "two hours of data"
   *  rather than only "too short". Both zero when there was nothing at all. */
  from: number
  to: number
  points: number
}

export interface ForecastMade {
  ok: true
  /** When the fitted line reaches `threshold`. */
  at: number
  /** Days from `now` to `at`. */
  days: number
  threshold: number
  /** Percentage points per day. */
  perDay: number
  /** How well the line fits, 0..1, and the label derived from it. */
  r2: number
  confidence: 'low' | 'medium' | 'high'
  /**
   * The window the forecast was DRAWN FROM, not the window that was queried.
   *
   * "Fills in 11 days" is not an honest sentence. "Fills in 11 days, from 6
   * days of data" is, and the difference is entirely in these three fields,
   * which is why they are not optional.
   */
  from: number
  to: number
  points: number
  /** Whether the fit saw instantaneous readings, hourly means, or both. */
  res: 'full' | 'hourly' | 'mixed'
}

export type Forecast = ForecastMade | ForecastRefused

/** One metric's answer: a line to draw and, where a threshold was asked for,
 *  a forecast or a refusal. */
export interface Trend {
  metric: CapacityMetric
  /** Ready to draw. Downsampled; see `downsample`. */
  segments: TrendSegment[]
  /** How many points were actually read, before downsampling. The chart is a
   *  summary of this many measurements and says so. */
  read: number
  /** The newest reading in the window, undownsampled. */
  latest: TrendPoint | null
  /** The lowest and highest value seen anywhere in the window, taking the
   *  hourly tier's own min/max into account rather than only its mean. */
  low: number | null
  high: number | null
  /** Where the full-resolution tier begins, when the window contains both
   *  tiers. Null when the whole window is one resolution — there is no
   *  boundary to draw, and drawing one anyway would be a lie. */
  resolutionBoundary: number | null
  /** Null when no threshold was asked for (cpu). */
  forecast: Forecast | null
}

export interface CapacityReport {
  hostId: string
  /** The window that was asked for. */
  from: number
  to: number
  /** When it was computed. Every "in N days" below is relative to this. */
  now: number
  /** Item A's retention horizons, carried rather than duplicated: the renderer
   *  cannot import a main-process constant, and a panel that hard-coded "7
   *  days" would keep saying it after the policy changed. */
  fullResolutionDays: number
  retainedDays: number
  trends: Trend[]
}

// ---------------------------------------------------------------------------
// The policy. Every number here is a refusal boundary; see the file header for
// why they are the point of the feature rather than an obstacle to it.
// ---------------------------------------------------------------------------

const MINUTE_MS = 60_000
const HOUR_MS = 3_600_000
const DAY_MS = 86_400_000

/** Below this many points in the run, no forecast. Twelve is two hourly means
 *  short of half a day, or twenty-four minutes of full-resolution samples: few
 *  enough to be reachable, many enough that one bad reading cannot set the
 *  slope. */
export const FORECAST_MIN_POINTS = 12

/** And below this much elapsed time, no forecast however many points there
 *  are. Six hours, because the daily cycle of a working machine — a backup, a
 *  build, a log rotation — is longer than any shorter window, and a rate
 *  measured inside one phase of it is a rate for that phase only. This is what
 *  refuses a fleet that was first connected two hours ago. */
export const FORECAST_MIN_WINDOW_MS = 6 * HOUR_MS

/** Newer than this, or the series is stale and nothing is extrapolated from
 *  it. Six hours of silence from a host that samples every two minutes is not
 *  a quiet patch; it is a host that stopped answering. */
export const FORECAST_MAX_STALE_MS = 6 * HOUR_MS

/** The fitted line must move at least this many percentage points across its
 *  own window, in either direction, to be a trend at all. Below it the answer
 *  is 'flat' — which is the honest answer, and specifically NOT the infinity
 *  that dividing by a slope of zero produces. */
export const FORECAST_FLAT_RISE_PCT = 0.5

/** Coefficient of determination below which the fit is not describing the
 *  data. A memory series that swings twenty points between sweeps has a slope;
 *  it does not have a trend. */
export const FORECAST_MIN_R2 = 0.5

/** If a single jump — measured across at most two consecutive intervals, so
 *  that a step smeared over an hourly bucket boundary still counts as one —
 *  accounts for this share of the whole fitted rise, the rise is that jump and
 *  not a trend. This is the untarred release. */
export const FORECAST_STEP_SHARE = 0.6
const STEP_SPAN_POINTS = 2

/** Crossings further out than this are not stated. At three months the claim
 *  "the current rate holds" is doing all the work and the arithmetic is doing
 *  none, and the store itself only remembers ninety days. */
export const FORECAST_HORIZON_DAYS = 90

/** A gap is this many times the run's own typical spacing. Derived from the
 *  data rather than from a cadence constant: the sampler's interval is a user
 *  setting, and a threshold pinned to two minutes would call every interval a
 *  gap on a fleet sampled every ten. */
export const GAP_FACTOR = 3

/** Fallbacks for the typical spacing when there are too few intervals to take
 *  a median of. */
const NOMINAL_SPACING: Record<'full' | 'hourly', number> = {
  full: 2 * MINUTE_MS,
  hourly: HOUR_MS
}

/** Chart points per trend, across all its segments. A 90-day window holds
 *  about seven thousand samples per metric; a line drawn at eight hundred
 *  pixels cannot show them and sending them to the renderer to be averaged
 *  into invisibility is the warehouse habit in miniature. */
export const CHART_MAX_POINTS = 400

// ---------------------------------------------------------------------------

function median(xs: number[]): number {
  if (xs.length === 0) return 0
  const s = [...xs].sort((a, b) => a - b)
  const mid = s.length >> 1
  return s.length % 2 === 1 ? s[mid] : (s[mid - 1] + s[mid]) / 2
}

/**
 * The typical spacing between consecutive points, per resolution.
 *
 * Taken from the points themselves so that a fleet sampled every ten minutes
 * is not read as a fleet with a gap between every pair of samples.
 */
function spacing(points: TrendPoint[]): Record<'full' | 'hourly', number> {
  const gaps: Record<'full' | 'hourly', number[]> = { full: [], hourly: [] }
  for (let i = 1; i < points.length; i++) {
    const a = points[i - 1]
    const b = points[i]
    if (a.res !== b.res) continue
    const d = b.ts - a.ts
    if (d > 0) gaps[a.res].push(d)
  }
  return {
    full: gaps.full.length >= 3 ? median(gaps.full) : NOMINAL_SPACING.full,
    hourly: gaps.hourly.length >= 3 ? median(gaps.hourly) : NOMINAL_SPACING.hourly
  }
}

/**
 * Split into runs of points with no missing time between them.
 *
 * This is the whole of "a gap is not a flat line". Everything downstream —
 * the fit, the chart, the window a forecast states — operates on a run, so
 * there is no path by which two days of silence can become a slope.
 *
 * A run may change resolution partway through: the boundary between item A's
 * two tiers is a change of measurement, not a break in time, and a run that
 * split there would report a shorter window than the store actually holds.
 */
export function runs(points: TrendPoint[]): TrendPoint[][] {
  if (points.length === 0) return []
  const typical = spacing(points)
  const out: TrendPoint[][] = [[points[0]]]
  for (let i = 1; i < points.length; i++) {
    const a = points[i - 1]
    const b = points[i]
    // The coarser of the two ends decides. Crossing from an hourly mean into
    // full resolution, an hour of daylight between them is normal.
    const expected = Math.max(typical[a.res], typical[b.res])
    if (b.ts - a.ts > GAP_FACTOR * expected) out.push([b])
    else out[out.length - 1].push(b)
  }
  return out
}

/** Runs, split further wherever the resolution changes, each carrying how much
 *  silence preceded it. This is what a chart draws. */
export function segments(points: TrendPoint[]): TrendSegment[] {
  const out: TrendSegment[] = []
  let previousEnd: number | null = null
  for (const run of runs(points)) {
    let gapBefore = previousEnd === null ? 0 : run[0].ts - previousEnd
    for (const p of run) {
      const last = out[out.length - 1]
      if (last && last.res === p.res && last.points[last.points.length - 1].ts <= p.ts && gapBefore === 0) {
        last.points.push(p)
        continue
      }
      out.push({ res: p.res, points: [p], gapBefore })
      // Only the first segment of a run inherits the run's gap; a resolution
      // change inside a run is continuous in time.
      gapBefore = 0
    }
    previousEnd = run[run.length - 1].ts
  }
  return out
}

/**
 * Fewer points, same shape.
 *
 * Buckets are taken inside a segment, never across one, so a bucket can never
 * straddle a gap or mix a mean of thirty readings with an instantaneous one.
 * The bucket keeps the extremes as well as the mean: on a disk it is the peak
 * that matters, and a chart that averages a spike away has removed the only
 * interesting thing in the window.
 */
export function downsample(segment: TrendSegment, bucketMs: number): TrendSegment {
  if (bucketMs <= 0 || segment.points.length === 0) return segment
  const out: TrendPoint[] = []
  let bucket = -1
  let acc: TrendPoint[] = []
  const flush = (): void => {
    if (acc.length === 0) return
    let sum = 0
    let weight = 0
    let lo = Infinity
    let hi = -Infinity
    for (const p of acc) {
      const n = p.n && p.n > 0 ? p.n : 1
      sum += p.v * n
      weight += n
      lo = Math.min(lo, p.min ?? p.v)
      hi = Math.max(hi, p.max ?? p.v)
    }
    const point: TrendPoint = { ts: acc[0].ts, v: sum / weight, res: acc[0].res }
    // Only where it says something the mean does not. A single full-resolution
    // reading that survived a bucket alone has no spread and must not pretend
    // to one.
    if (hi > lo) {
      point.min = lo
      point.max = hi
    }
    if (weight > acc.length || acc[0].n !== undefined) point.n = weight
    out.push(point)
    acc = []
  }
  for (const p of segment.points) {
    const b = Math.floor(p.ts / bucketMs)
    if (b !== bucket) {
      flush()
      bucket = b
    }
    acc.push(p)
  }
  flush()
  return { res: segment.res, points: out, gapBefore: segment.gapBefore }
}

/** Least squares, with x measured from the first point so that millisecond
 *  timestamps near 1.7e12 do not eat the precision of the sums. */
function fit(points: TrendPoint[]): { slope: number; intercept: number; r2: number; x0: number } {
  const x0 = points[0].ts
  const n = points.length
  let sx = 0
  let sy = 0
  for (const p of points) {
    sx += p.ts - x0
    sy += p.v
  }
  const mx = sx / n
  const my = sy / n
  let sxy = 0
  let sxx = 0
  for (const p of points) {
    const dx = p.ts - x0 - mx
    sxy += dx * (p.v - my)
    sxx += dx * dx
  }
  const slope = sxx === 0 ? 0 : sxy / sxx
  const intercept = my - slope * mx
  let ssRes = 0
  let ssTot = 0
  for (const p of points) {
    const predicted = intercept + slope * (p.ts - x0)
    ssRes += (p.v - predicted) ** 2
    ssTot += (p.v - my) ** 2
  }
  // A series with no variance at all is fitted perfectly by a flat line. It is
  // caught by the flat rule below long before r2 is consulted; NaN here would
  // make every comparison false and let it through.
  const r2 = ssTot === 0 ? 1 : 1 - ssRes / ssTot
  return { slope, intercept, r2, x0 }
}

/** The largest rise across one or two consecutive intervals. Two, because a
 *  step that lands mid-hour is split across two hourly means and would
 *  otherwise read as two ordinary changes. */
function largestJump(points: TrendPoint[]): number {
  let max = 0
  for (let i = 0; i < points.length; i++) {
    for (let k = 1; k <= STEP_SPAN_POINTS && i + k < points.length; k++) {
      const d = points[i + k].v - points[i].v
      if (d > max) max = d
    }
  }
  return max
}

function resolutionOf(points: TrendPoint[]): 'full' | 'hourly' | 'mixed' {
  let full = false
  let hourly = false
  for (const p of points) {
    if (p.res === 'full') full = true
    else hourly = true
    if (full && hourly) return 'mixed'
  }
  return full ? 'full' : 'hourly'
}

/**
 * When this series crosses `threshold`, or why that question has no answer.
 *
 * Fitted on the MOST RECENT contiguous run only. Older runs describe a machine
 * on the other side of an outage or a reinstall, and stitching them together
 * is precisely the invented trend this function exists to refuse.
 */
export function forecast(points: TrendPoint[], threshold: number, now: number): Forecast {
  if (points.length === 0) return { ok: false, reason: 'no-data', from: 0, to: 0, points: 0 }
  const all = runs(points)
  const run = all[all.length - 1]
  const from = run[0].ts
  const to = run[run.length - 1].ts
  const refuse = (reason: RefusalReason): ForecastRefused => ({
    ok: false,
    reason,
    from,
    to,
    points: run.length
  })

  if (now - to > FORECAST_MAX_STALE_MS) return refuse('stale')
  if (run.length < FORECAST_MIN_POINTS) return refuse('too-few-points')
  const span = to - from
  if (span < FORECAST_MIN_WINDOW_MS) return refuse('window-too-short')
  if (run[run.length - 1].v >= threshold) return refuse('already-past')

  const { slope, intercept, r2, x0 } = fit(run)
  const rise = slope * span
  if (rise <= -FORECAST_FLAT_RISE_PCT) return refuse('falling')
  if (rise < FORECAST_FLAT_RISE_PCT) return refuse('flat')
  if (r2 < FORECAST_MIN_R2) return refuse('noisy')
  if (largestJump(run) >= FORECAST_STEP_SHARE * rise) return refuse('step-change')

  // slope > 0 here: `rise` is slope * span with both positive.
  const at = x0 + (threshold - intercept) / slope
  const days = Math.max(0, (at - now) / DAY_MS)
  if (days > FORECAST_HORIZON_DAYS) return refuse('beyond-horizon')

  const spanDays = span / DAY_MS
  const confidence =
    r2 >= 0.9 && spanDays >= 3 ? 'high' : r2 >= 0.7 && spanDays >= 1 ? 'medium' : 'low'
  return {
    ok: true,
    at,
    days,
    threshold,
    perDay: slope * DAY_MS,
    r2,
    confidence,
    from,
    to,
    points: run.length,
    res: resolutionOf(run)
  }
}

/** Where the full-resolution tier starts, when the window holds both tiers.
 *  Null when it holds only one: there is no boundary to draw. */
export function resolutionBoundary(points: TrendPoint[]): number | null {
  let sawHourly = false
  for (const p of points) {
    if (p.res === 'hourly') sawHourly = true
    else if (sawHourly) return p.ts
  }
  return null
}

export interface ReportOptions {
  now: number
  from: number
  to: number
  /** Per metric. A metric with no threshold gets a line and no forecast, which
   *  is the right answer for cpu: a CPU does not fill up. */
  thresholds: Partial<Record<CapacityMetric, number>>
  fullResolutionDays: number
  retainedDays: number
  maxPoints?: number
}

/**
 * The whole answer for one host, from series the caller has already read.
 *
 * Takes points rather than a store handle so that it is pure: main reads,
 * this decides, and the report crosses IPC as an answer rather than as a
 * table of samples.
 */
export function buildCapacityReport(
  hostId: string,
  series: Partial<Record<CapacityMetric, TrendPoint[]>>,
  opts: ReportOptions
): CapacityReport {
  const maxPoints = Math.max(2, opts.maxPoints ?? CHART_MAX_POINTS)
  const trends: Trend[] = CAPACITY_METRICS.map((metric) => {
    const points = series[metric] ?? []
    const threshold = opts.thresholds[metric]
    const segs = segments(points)
    // One bucket size for the whole trend, so the two sides of a resolution
    // boundary stay comparable to the eye.
    const bucketMs = Math.max(1, Math.ceil((opts.to - opts.from) / maxPoints))
    let low: number | null = null
    let high: number | null = null
    for (const p of points) {
      const lo = p.min ?? p.v
      const hi = p.max ?? p.v
      low = low === null ? lo : Math.min(low, lo)
      high = high === null ? hi : Math.max(high, hi)
    }
    return {
      metric,
      segments: segs.map((s) => downsample(s, bucketMs)),
      read: points.length,
      latest: points.length === 0 ? null : points[points.length - 1],
      low,
      high,
      resolutionBoundary: resolutionBoundary(points),
      forecast: threshold === undefined ? null : forecast(points, threshold, opts.now)
    }
  })
  return {
    hostId,
    from: opts.from,
    to: opts.to,
    now: opts.now,
    fullResolutionDays: opts.fullResolutionDays,
    retainedDays: opts.retainedDays,
    trends
  }
}

/**
 * The default thresholds a capacity question is asked against.
 *
 * 90% for both, and deliberately NOT the 85% `hostHealth.DISK_DANGER` uses.
 * That number answers "is this host in trouble now" and turns a bar red; this
 * one answers "when will it be", and forecasting the moment a warning appears
 * would make the panel say "fills in 3 days" about a host that has three days
 * until it goes amber, not until it goes wrong. cpu has none: a CPU at 100%
 * is busy, not full.
 */
export const CAPACITY_THRESHOLDS: Partial<Record<CapacityMetric, number>> = {
  diskPct: 90,
  memPct: 90
}

/**
 * What the preload must expose for the panel to work.
 *
 * Declared here, and the preload annotated with it, so the two halves can land
 * in separate diffs and type-check against one contract — the same arrangement
 * as DockerBridge. The renderer treats it as Partial: a build where the
 * preload half has not landed must show a panel that says so rather than throw
 * `undefined is not a function`.
 */
export interface CapacityBridge {
  trends(hostId: string, windowDays: number): Promise<CapacityReport | null>
}

/** The windows the panel offers. A day, a week (exactly the full-resolution
 *  horizon), a month and the whole of what item A retains. */
export const CAPACITY_WINDOWS = [1, 7, 30, 90] as const
