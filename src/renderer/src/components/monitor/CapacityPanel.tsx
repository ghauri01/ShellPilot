import { useEffect, useRef, useState } from 'react'
import { AlertTriangle, RefreshCw, TrendingUp } from 'lucide-react'
import { openSettings } from '../../store/nav'
import { clsx } from '../../lib/format'
import {
  CAPACITY_THRESHOLDS,
  CAPACITY_WINDOWS,
  type CapacityBridge,
  type CapacityReport,
  type Trend
} from '../../../../shared/capacity'
import {
  CONFIDENCE_HELP,
  METRIC_LABEL,
  RES_LABEL,
  draw,
  forecastText,
  rateText,
  shortDate,
  span
} from '../../lib/capacity'
import type { Server } from '../../types'

// "This disk fills in eleven days." — roadmap item 26.
//
// The first thing on screen that reads from item A's store. Everything here is
// derived on demand from samples the fleet sampler already writes; this panel
// stores nothing, schedules nothing and evaluates nothing in the background.
// That is what keeps item 26 the "query and a chart" the roadmap describes
// rather than the metrics warehouse it warns against.
//
// Three things this must never do, all of which a naive version does by
// default:
//
//  1. State a forecast without the window it came from. See forecastText: the
//     window is not an optional suffix.
//  2. Draw one line through two resolutions. The store keeps seven days at
//     full resolution and eighty-three days of hourly means, so a 30-day
//     window is half means of thirty readings and half single readings. Each
//     segment is drawn separately and the boundary is labelled.
//  3. Draw across a gap. A host unreachable for two days has no samples for two
//     days, and a line joined across that shows a trend nothing measured. The
//     silence is a hole in the line, and it is labelled too.

const CHART = { width: 640, height: 96 }

function bridge(): Partial<CapacityBridge> | undefined {
  return (window.shellpilot as unknown as { capacity?: Partial<CapacityBridge> } | undefined)?.capacity
}

function tone(v: number): string {
  return v > 85 ? 'danger' : v > 65 ? 'warn' : ''
}

/**
 * One metric: the line, the boundary, the silences, and the sentence.
 *
 * The chart is deliberately plain. A capacity panel earns its place by being
 * believed, and every extra flourish is another thing that can imply a
 * measurement that was not taken.
 */
function TrendRow({
  trend,
  report
}: {
  trend: Trend
  report: CapacityReport
}): React.JSX.Element {
  const threshold = CAPACITY_THRESHOLDS[trend.metric] ?? null
  const drawing = draw(trend, report.from, report.to, CHART, threshold)
  const latest = trend.latest
  const label = METRIC_LABEL[trend.metric]
  const gaps = drawing.segments.filter((s) => s.gapBefore > 0)

  return (
    <div className="col" style={{ gap: 6, marginTop: 14 }}>
      <div className="row" style={{ justifyContent: 'space-between', alignItems: 'baseline' }}>
        <b>{label}</b>
        {latest === null ? (
          <span className="faint" style={{ fontSize: 11 }}>
            no samples
          </span>
        ) : (
          <span className={clsx('mono', tone(latest.v))}>
            {latest.v.toFixed(1)}%
            {trend.high !== null && trend.low !== null && (
              <span className="faint">
                {' '}
                · {trend.low.toFixed(0)}–{trend.high.toFixed(0)}% over the window
              </span>
            )}
          </span>
        )}
      </div>

      <svg
        role="img"
        aria-label={`${label} over the last ${span(report.to - report.from)}`}
        viewBox={`0 0 ${CHART.width} ${CHART.height}`}
        preserveAspectRatio="none"
        style={{ width: '100%', height: CHART.height, display: 'block' }}
      >
        {/* The threshold the forecast is about, drawn where the line has to
            reach rather than described only in the sentence. */}
        {drawing.thresholdY !== null && (
          <line
            x1={0}
            x2={CHART.width}
            y1={drawing.thresholdY}
            y2={drawing.thresholdY}
            stroke="currentColor"
            strokeWidth={1}
            strokeDasharray="2 4"
            opacity={0.35}
          />
        )}
        {/* Where the store's two tiers meet. Routine — any window longer than
            a week crosses it — so it is a quiet rule, not an alarm. */}
        {drawing.boundaryX !== null && (
          <line
            data-testid="resolution-boundary"
            x1={drawing.boundaryX}
            x2={drawing.boundaryX}
            y1={0}
            y2={CHART.height}
            stroke="currentColor"
            strokeWidth={1}
            strokeDasharray="1 3"
            opacity={0.5}
          />
        )}
        {drawing.segments.map((s, i) => (
          <g key={i} data-testid={`segment-${s.res}`}>
            {/* The spread inside each hourly bucket. On a disk it is the peak
                that matters and a mean can hide one entirely. */}
            {s.band !== '' && <path d={s.band} fill="currentColor" opacity={0.15} stroke="none" />}
            <path
              d={s.line}
              fill="none"
              stroke="currentColor"
              strokeWidth={1.5}
              // Means are drawn dashed and readings solid, so the two halves of
              // a long window are distinguishable at a glance and not only in
              // the legend below.
              strokeDasharray={s.res === 'hourly' ? '3 2' : undefined}
              opacity={0.9}
            />
          </g>
        ))}
      </svg>

      <div className="row faint" style={{ fontSize: 11, gap: 10, flexWrap: 'wrap' }}>
        {drawing.boundaryX !== null && (
          <span>
            Before {shortDate(trend.resolutionBoundary ?? report.from)}: {RES_LABEL.hourly}. After:{' '}
            {RES_LABEL.full}.
          </span>
        )}
        {drawing.boundaryX === null && trend.segments.length > 0 && (
          <span>{RES_LABEL[trend.segments[0].res]}.</span>
        )}
        <span>{trend.read} samples.</span>
      </div>

      {gaps.map((s, i) => (
        <div key={i} className="state-unknown" style={{ fontSize: 11 }}>
          <AlertTriangle size={11} /> No samples for {span(s.gapBefore)}. The line is broken there
          rather than joined — nothing was measured across it.
        </div>
      ))}

      {trend.forecast !== null && threshold !== null && (
        <div
          className={clsx('panel-note', trend.forecast.ok ? '' : 'faint')}
          style={{ marginTop: 2 }}
        >
          {forecastText(trend.forecast, trend.metric, threshold)}
          {trend.forecast.ok && (
            <>
              {' '}
              <span className="faint">{rateText(trend.forecast)}.</span>{' '}
              <span className="mono" title={CONFIDENCE_HELP[trend.forecast.confidence]}>
                {trend.forecast.confidence} confidence
              </span>
            </>
          )}
        </div>
      )}
    </div>
  )
}

export function CapacityPanel({ servers }: { servers: Server[] }): React.JSX.Element {
  const [serverId, setServerId] = useState<string>(servers[0]?.id ?? '')
  const [days, setDays] = useState<number>(7)
  const [report, setReport] = useState<CapacityReport | null>(null)
  const [loading, setLoading] = useState(false)
  const [failed, setFailed] = useState(false)
  /** Bumped by Refresh. A re-read of the SAME server and window has to be a
   *  new dependency or the effect does not run, and the button would spin
   *  once and then quietly do nothing forever. */
  const [nonce, setNonce] = useState(0)
  /** Which read the UI is showing. A read still in flight when the operator
   *  changes server or window must not land under the new heading — that is
   *  one host's disk presented as another's, and there is nothing on screen
   *  that would give it away. */
  const generation = useRef(0)

  const selected = servers.find((s) => s.id === serverId) ?? null
  const trends = bridge()?.trends

  useEffect(() => {
    if (typeof trends !== 'function' || serverId === '') return
    const mine = ++generation.current
    setLoading(true)
    setFailed(false)
    void trends(serverId, days)
      .then((r) => {
        if (generation.current !== mine) return
        setReport(r)
        setFailed(false)
      })
      .catch(() => {
        if (generation.current !== mine) return
        setReport(null)
        setFailed(true)
      })
      .finally(() => {
        if (generation.current === mine) setLoading(false)
      })
  }, [trends, serverId, days, nonce])

  const refresh = (): void => setNonce((n) => n + 1)

  return (
    <div className="bc-panel">
      <div className="panel-head">
        <span className="panel-head-icon">
          <TrendingUp size={14} />
        </span>
        <h2 className="ui-section-title">Capacity trends</h2>
        <p className="ui-note panel-head-purpose">
          How one server&rsquo;s CPU, memory and disk have moved over time, drawn from samples the
          fleet sampler already writes. Nothing extra is measured for this panel.
        </p>
        <div className="panel-head-actions">
        <select
          className="input"
          style={{ maxWidth: 200 }}
          aria-label="Server"
          value={serverId}
          onChange={(e) => setServerId(e.target.value)}
        >
          {servers.map((s) => (
            <option key={s.id} value={s.id}>
              {s.name}
            </option>
          ))}
        </select>
        <select
          className="input"
          style={{ maxWidth: 130 }}
          aria-label="Window"
          value={days}
          onChange={(e) => setDays(Number(e.target.value))}
        >
          {CAPACITY_WINDOWS.map((d) => (
            <option key={d} value={d}>
              {d === 1 ? 'Last 24 hours' : `Last ${d} days`}
            </option>
          ))}
        </select>
        <button
          className="btn primary"
          disabled={loading || typeof trends !== 'function' || serverId === ''}
          onClick={refresh}
        >
          <RefreshCw size={13} className={clsx(loading && 'spin')} /> Refresh
        </button>
        </div>
      </div>

      {typeof trends !== 'function' ? (
        <div className="panel-note is-alarm">
          This build’s preload does not expose capacity trends yet. Restart the app to rebuild it.
        </div>
      ) : servers.length === 0 ? (
        <div className="panel-empty">
          <p className="panel-empty-title">No servers to chart.</p>
          <p className="panel-empty-body">
            Add a server to this workspace and its samples start accumulating here.
          </p>
        </div>
      ) : failed ? (
        <div className="panel-note is-alarm">Could not read the history store.</div>
      ) : report === null ? (
        loading ? (
          <div className="panel-note">Reading…</div>
        ) : (
          <div className="panel-empty">
            <p className="panel-empty-title">No stored history.</p>
            <p className="panel-empty-body">
              Trends come from the fleet sampler’s own samples, so this fills in once sampling has
              been running. Turn background checking on and leave it for an hour.
            </p>
            <div className="panel-empty-actions">
              <button className="btn ghost sm" onClick={() => openSettings('monitoring')}>
                Open Monitoring settings
              </button>
            </div>
          </div>
        )
      ) : (
        <>
          <div className="panel-note">
            {selected?.name ?? serverId} over the last {span(report.to - report.from)}, from the
            samples the fleet sampler already writes. Nothing is measured for this panel.
          </div>
          {report.trends.map((t) => (
            <TrendRow key={t.metric} trend={t} report={report} />
          ))}
          <div className="faint" style={{ fontSize: 11, marginTop: 12 }}>
            The store keeps {report.fullResolutionDays} days of {RES_LABEL.full} and{' '}
            {report.retainedDays} days of {RES_LABEL.hourly}. Older than that is gone, which is why
            a longer window is not always more line.
          </div>
        </>
      )}
    </div>
  )
}
