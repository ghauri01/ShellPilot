import {
  FORECAST_HORIZON_DAYS,
  FORECAST_MIN_POINTS,
  FORECAST_MIN_WINDOW_MS,
  type CapacityMetric,
  type Forecast,
  type Trend,
  type TrendSegment
} from '../../../shared/capacity'

// Turning a capacity report into words and a shape — roadmap item 26.
//
// The arithmetic is all in src/shared/capacity.ts, where main can run it too.
// What is here is presentation, and it has one job beyond looking right: it
// must not be able to say more than the report does.
//
// That is a real risk and not a stylistic one. Every sentence below either
// carries the window the number came from or is a refusal that names its
// reason. "Fills in 11 days" rendered on its own is the failure the whole item
// is written against — an operator reads it, plans around it, finds the disk at
// the same 74% a fortnight later and never trusts the panel again. The window
// is what lets them judge it: eleven days from six days of data is worth acting
// on, eleven days from seven hours is not.

const MINUTE_MS = 60_000
const HOUR_MS = 3_600_000
const DAY_MS = 86_400_000

export const METRIC_LABEL: Record<CapacityMetric, string> = {
  cpu: 'CPU',
  memPct: 'Memory',
  diskPct: 'Disk'
}

/**
 * A span of time in the coarsest unit that does not lie about it.
 *
 * Rounded, and deliberately never to more than one decimal: "5.7 days of data"
 * suggests a precision the sampler does not have, and "137 hours" makes a
 * reader do arithmetic to find out it is under a week.
 */
export function span(ms: number): string {
  const abs = Math.abs(ms)
  if (abs < 90 * MINUTE_MS) {
    const m = Math.max(1, Math.round(abs / MINUTE_MS))
    return `${m} minute${m === 1 ? '' : 's'}`
  }
  if (abs < 2 * DAY_MS) {
    const h = Math.round(abs / HOUR_MS)
    return `${h} hour${h === 1 ? '' : 's'}`
  }
  const d = abs / DAY_MS
  const rounded = d < 10 ? Math.round(d * 10) / 10 : Math.round(d)
  return `${rounded} day${rounded === 1 ? '' : 's'}`
}

/** A date a person can read, in their own locale. Day and month only: the year
 *  is never in doubt at a ninety-day horizon and it crowds the line. */
export function shortDate(ts: number): string {
  return new Date(ts).toLocaleDateString(undefined, { day: 'numeric', month: 'short' })
}

/**
 * Why there is no number, in words, including how much data the refusal is
 * about.
 *
 * A bare "not enough data" is the same dead end as no message at all: the
 * operator cannot tell whether to come back in an hour or whether this host
 * will never produce a forecast. Every branch here says what would change it.
 */
export function refusalText(
  f: Forecast & { ok: false },
  metric: CapacityMetric,
  threshold: number
): string {
  const held = f.points === 0 ? '' : span(f.to - f.from)
  const label = METRIC_LABEL[metric].toLowerCase()
  switch (f.reason) {
    case 'no-data':
      return 'No samples in this window yet.'
    case 'stale':
      return `No samples for ${span(Date.now() - f.to)}. Nothing to forecast from until this server reports again.`
    case 'too-few-points':
      return `Only ${f.points} sample${f.points === 1 ? '' : 's'} since the last break in the data; ${FORECAST_MIN_POINTS} are needed.`
    case 'window-too-short':
      return `Only ${held} of unbroken data. A rate needs at least ${span(FORECAST_MIN_WINDOW_MS)}, so that one backup or one build is not the whole trend.`
    case 'already-past':
      return `Already at or over ${threshold}%. There is nothing left to predict.`
    case 'flat':
      return `Flat over ${held} — no measurable trend to project.`
    case 'falling':
      return `Falling over ${held}, not filling.`
    case 'noisy':
      return `This ${label} moves too much between samples for a trend line to mean anything.`
    case 'step-change':
      return `The rise over ${held} is one step, not a trend — something was written once. A forecast from it would be about that event, not about the ${label}.`
    case 'beyond-horizon':
      return `More than ${FORECAST_HORIZON_DAYS} days out at this rate, which is further ahead than this will guess.`
  }
}

/**
 * The sentence. The whole item is this sentence being true.
 *
 * Both halves are mandatory: what it concludes, and the window it concluded it
 * from. There is no formatting option that drops the second half.
 */
export function forecastText(f: Forecast, metric: CapacityMetric, threshold: number): string {
  if (!f.ok) return refusalText(f, metric, threshold)
  const when = f.days < 1 ? 'within a day' : `in ${span(f.days * DAY_MS)}`
  return `Reaches ${f.threshold}% ${when} — ${shortDate(f.at)} — from ${span(f.to - f.from)} of data.`
}

/** The rate, spelled out, so the reader can sanity-check the projection
 *  against what they know about the host. */
export function rateText(f: Forecast): string {
  if (!f.ok) return ''
  const perDay = Math.round(f.perDay * 100) / 100
  return `${perDay > 0 ? '+' : ''}${perDay} points a day`
}

/** What the confidence label is FOR. Shown as a title, so the word is never on
 *  screen without the thing it is a judgement about. */
export const CONFIDENCE_HELP: Record<'low' | 'medium' | 'high', string> = {
  high: 'The points sit close to the line and there are several days of them.',
  medium: 'The line fits reasonably, over at least a day.',
  low: 'A short run, or a loose fit. Treat the date as a hint, not a plan.'
}

/** How the two tiers of item A's store are described on screen. The store's
 *  own words for them are 'full' and 'hourly', which mean nothing to a reader
 *  looking at a line. */
export const RES_LABEL: Record<'full' | 'hourly', string> = {
  full: 'individual readings',
  hourly: 'hourly means'
}

export interface Box {
  width: number
  height: number
}

export interface DrawnSegment {
  res: 'full' | 'hourly'
  /** The mean line. */
  line: string
  /** min..max as a closed area, where the tier has extremes to show. Empty for
   *  a run of single readings, which have no spread. */
  band: string
  gapBefore: number
  /** x of this segment's first point, for labelling the silence before it. */
  x0: number
}

export interface Drawing {
  segments: DrawnSegment[]
  /** x of the moment full resolution begins, or null when the window holds
   *  only one tier. */
  boundaryX: number | null
  /** y of the forecast threshold, or null when this metric has none. */
  thresholdY: number | null
}

/**
 * Geometry for one trend.
 *
 * The y axis is fixed at 0-100 rather than fitted to the data, and that is a
 * decision rather than laziness. A disk moving 64% to 74% on an axis zoomed to
 * 64-74 is a dramatic climb; the same line against 0-100 is what it actually
 * is, and the 90% threshold stays on screen where the forecast can be read
 * against it. Auto-scaling a percentage is how a chart lies without a single
 * wrong number in it.
 *
 * Each segment becomes its OWN path. Two segments are never joined, so a gap
 * in the data is a gap in the line and a change of resolution is a change of
 * line, both without any drawing code deciding to bridge them.
 */
export function draw(trend: Trend, from: number, to: number, box: Box, threshold: number | null): Drawing {
  const width = Math.max(1, box.width)
  const height = Math.max(1, box.height)
  const range = Math.max(1, to - from)
  const x = (ts: number): number => ((ts - from) / range) * width
  const y = (v: number): number => height - (Math.max(0, Math.min(100, v)) / 100) * height
  const round = (n: number): number => Math.round(n * 100) / 100

  const segments = trend.segments
    .filter((s: TrendSegment) => s.points.length > 0)
    .map((s) => {
      const line = s.points.map((p, i) => `${i === 0 ? 'M' : 'L'}${round(x(p.ts))} ${round(y(p.v))}`).join(' ')
      const hasSpread = s.points.some((p) => p.min !== undefined && p.max !== undefined && p.max > p.min)
      const band = hasSpread
        ? [
            ...s.points.map((p, i) => `${i === 0 ? 'M' : 'L'}${round(x(p.ts))} ${round(y(p.max ?? p.v))}`),
            ...[...s.points].reverse().map((p) => `L${round(x(p.ts))} ${round(y(p.min ?? p.v))}`),
            'Z'
          ].join(' ')
        : ''
      return { res: s.res, line, band, gapBefore: s.gapBefore, x0: round(x(s.points[0].ts)) }
    })

  return {
    segments,
    boundaryX: trend.resolutionBoundary === null ? null : round(x(trend.resolutionBoundary)),
    thresholdY: threshold === null ? null : round(y(threshold))
  }
}
