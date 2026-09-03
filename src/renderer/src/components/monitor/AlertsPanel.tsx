import { useCallback, useEffect, useMemo, useState } from 'react'
import { AlertTriangle, RefreshCw } from 'lucide-react'
import { useApp, useWorkspaceServers } from '../../store/app'
import { useFleetStatus } from '../../store/fleetStatus'
import {
  LABEL,
  SNOOZE_CHOICES,
  THRESHOLD_MAX,
  THRESHOLD_MIN,
  hostThreshold,
  acknowledgeAlert,
  chipValue,
  snoozeAlert,
  unsnoozeAlert,
  useAlerts
} from '../../store/alerts'
import { alertCoverageText } from '../settings/alertCoverage'
import { openSettings } from '../../store/nav'
import { clsx } from '../../lib/format'
import type { StoredAlertRow } from '../../../../shared/webhook'

// The alert inbox — roadmap item 19b.
//
// The roadmap asks for "an alert inbox with a history rather than transient
// toasts", and names the reason: "a disk alert that fires forty times overnight
// gets the whole feature muted, which is worse than not shipping it." Flap
// damping is what stops the forty; this is what makes the damping affordable.
// A feature that goes quiet on purpose has to have somewhere the quiet parts
// are still written down, or "we damped it" is indistinguishable from "we lost
// it" — which is the same objection the `damped: true` flag on the webhook
// answers for an endpoint.
//
// Everything here is READ from the durable log the store already writes. There
// is no second source of truth, no in-memory list of "recent alerts" that a
// restart empties, and no computation: a row is rendered as it was recorded,
// having been whitelisted twice on the way — once when the renderer decided it
// and once by main on the way back out.

/** How much of the log to show. The same 500 the store hydrates from, so the
 *  inbox and the suppression state are looking at the same rows — a history
 *  that showed less than the thing deciding whether to speak would be a screen
 *  you could not use to explain the silence. */
const LIMIT = 500

/** How each recorded event reads in a list. `stood-down` is the one that is not
 *  self-explanatory, and it is the one that most needs saying: it is what gets
 *  written when alerting is switched off with something outstanding, and it is
 *  deliberately not an all-clear. */
const EVENT_WORD: Record<StoredAlertRow['event'], string> = {
  raised: 'Raised',
  resolved: 'Cleared',
  'stood-down': 'Stood down',
  snoozed: 'Snoozed',
  acknowledged: 'Acknowledged'
}

const EVENT_CLASS: Record<StoredAlertRow['event'], string> = {
  raised: 'warn',
  resolved: 'ok',
  'stood-down': 'faint',
  snoozed: 'faint',
  acknowledged: 'faint'
}

/**
 * A row's own words for what it was about.
 *
 * The numeric kinds have a value and a threshold; the rest have a detail. A row
 * with neither says nothing rather than inventing a zero — the rule the whole
 * item runs on, at the last surface that could break it.
 */
export function rowSubject(row: StoredAlertRow): string {
  if (row.detail) return row.detail
  if (row.value === undefined) return ''
  return row.threshold === undefined ? String(row.value) : `${row.value} of ${row.threshold}`
}

function when(at: number, now: number): string {
  const mins = Math.floor((now - at) / 60_000)
  if (mins < 1) return 'just now'
  if (mins < 60) return `${mins} min ago`
  const hours = Math.floor(mins / 60)
  if (hours < 24) return `${hours} h ago`
  return new Date(at).toLocaleString()
}

export function AlertsPanel(): React.JSX.Element {
  const active = useAlerts((s) => s.active)
  const samplerStatus = useFleetStatus((s) => s.status)
  const samplingEnabled = useApp((s) => s.settings.fleetSamplingEnabled)
  const alertsEnabled = useApp((s) => s.settings.resourceAlertsEnabled)
  const globalThreshold = useApp((s) => s.settings.resourceAlertThreshold)
  const perHost = useApp((s) => s.settings.resourceAlertThresholds)
  const servers = useWorkspaceServers()
  // What is in each threshold box while it is being typed in, which is not the
  // same thing as what is stored. See commitThreshold.
  const [draft, setDraft] = useState<Record<string, string>>({})
  const [rows, setRows] = useState<StoredAlertRow[] | null>(null)
  const [reading, setReading] = useState(false)
  const [failed, setFailed] = useState(false)

  const read = useCallback(() => {
    const history = window.shellpilot?.alerts?.history
    if (!history) {
      setFailed(true)
      return
    }
    setReading(true)
    void Promise.resolve(history(LIMIT))
      .then((r) => {
        setRows(Array.isArray(r) ? r : [])
        setFailed(false)
      })
      // An unreadable log is said out loud rather than rendered as an empty
      // history. "Nothing has happened" and "we could not look" are the two
      // things this whole item refuses to conflate.
      .catch(() => setFailed(true))
      .then(() => setReading(false))
  }, [])

  // Re-read whenever something is raised or cleared, so the list does not sit
  // one incident behind the chip pointing at it.
  const activeCount = Object.keys(active).length
  useEffect(() => {
    read()
  }, [read, activeCount])

  // A blank box removes the override rather than storing a zero — an empty
  // field means "no opinion", and a 0 stored here would be a threshold no
  // reading can be below, which is alerting switched off for that host while
  // the switch still says it is on.
  //
  // Nothing outside the range is ever STORED. It used to persist the raw typed
  // value and rely on hostThreshold to clamp on read, so typing "8" on the way
  // to "85" wrote an 8 — a number the app will never honour, sitting in the
  // settings blob and in every backup taken from it for somebody to read later
  // and draw the wrong conclusion from.
  //
  // Clamping on each keystroke would be worse than the bug: "8" would snap to
  // 50 and "85" could never be typed at all. So the box keeps a draft of what
  // is being typed, the store only hears a value that is already inside the
  // range, and leaving the field commits whatever is there, clamped. Reading
  // still clamps too — a hand-edited settings file and an old backup are not
  // typing.
  const commitThreshold = (serverId: string, raw: string): void => {
    const next = { ...perHost }
    const n = Number(raw)
    if (raw.trim() === '' || !Number.isFinite(n)) delete next[serverId]
    else next[serverId] = Math.min(THRESHOLD_MAX, Math.max(THRESHOLD_MIN, n))
    useApp.getState().setSettings({ resourceAlertThresholds: next })
  }

  const typeThreshold = (serverId: string, raw: string): void => {
    setDraft((d) => ({ ...d, [serverId]: raw }))
    const n = Number(raw)
    if (raw.trim() === '') commitThreshold(serverId, '')
    else if (Number.isFinite(n) && n >= THRESHOLD_MIN && n <= THRESHOLD_MAX) {
      commitThreshold(serverId, raw)
    }
  }

  const blurThreshold = (serverId: string): void => {
    const raw = draft[serverId]
    if (raw !== undefined) commitThreshold(serverId, raw)
    setDraft((d) => {
      const next = { ...d }
      delete next[serverId]
      return next
    })
  }

  const now = Date.now()
  const outstanding = useMemo(
    () => Object.values(active).sort((a, b) => a.since - b.since),
    [active]
  )

  return (
    <div className="bc-panel">
      <div className="row" style={{ gap: 8, alignItems: 'center' }}>
        <AlertTriangle size={14} className="faint" />
        <b className="grow">Alerts</b>
        <button className="btn ghost sm" onClick={read} disabled={reading}>
          <RefreshCw size={12} /> Refresh
        </button>
      </div>

      {/* The same sentence the settings screen shows, from the same function.
          Not a paraphrase: alertCoverage.ts exists because this claim was once
          made from the SWITCH rather than from whether the sampler is actually
          looping, and a second copy of the wording here is how that comes back.
          Every kind added by this item inherits it, because every kind added by
          this item is raised from the same sampler. */}
      <div className="s-desc">{alertCoverageText(samplerStatus?.running, samplingEnabled)}</div>
      {!alertsEnabled && (
        <div className="s-desc warn">
          Resource alerts are switched off, so nothing new will be added below.{' '}
          <button className="btn ghost sm" onClick={() => openSettings('monitoring')}>
            Monitoring settings
          </button>
        </div>
      )}

      <div className="s-title" style={{ marginTop: 12 }}>
        Outstanding
      </div>
      {/* Said here rather than left as an absence somebody has to notice.
          Outstanding is built from the status-bar chips, and a database verdict
          deliberately holds none: notableDbEvents records alarm and watch and
          never records ok, so nothing in the store can say a database
          recovered, and a chip that could never come down would point at a
          screen that disagreed with it. They are in the history below, and
          there is nothing to snooze because nothing repeats. */}
      <div className="s-desc">
        Database verdicts are not listed here and cannot be snoozed: they are
        occurrences rather than conditions, so there is no repeat to stop. Every one is in the
        history below.
      </div>
      {outstanding.length === 0 ? (
        <div className="faint" style={{ fontSize: 12 }}>
          Nothing is outstanding right now.
        </div>
      ) : (
        <table className="mini-table">
          <tbody>
            {outstanding.map((a) => (
              <tr key={`${a.serverId}:${a.kind}`}>
                <td className={a.snoozedUntil && a.snoozedUntil > now ? 'faint' : 'warn'}>
                  {LABEL[a.kind]}
                </td>
                <td>{a.serverName}</td>
                <td>
                  {chipValue(a).trim()}
                  {a.detail ? ` ${a.detail}` : ''}
                </td>
                <td className="faint">since {when(a.since, now)}</td>
                <td>
                  {/* Said out loud rather than shown as absence. A snoozed alert
                      that simply looked normal would leave a person wondering
                      why it had gone quiet, which is the failure mode damping
                      already had to answer for. */}
                  {a.snoozedUntil && a.snoozedUntil > now ? (
                    <>
                      <span className="faint">
                        snoozed until {new Date(a.snoozedUntil).toLocaleTimeString()}
                      </span>{' '}
                      <button
                        className="btn ghost sm"
                        onClick={() => unsnoozeAlert(a.serverId, a.kind)}
                      >
                        Wake
                      </button>
                    </>
                  ) : (
                    SNOOZE_CHOICES.map((c) => (
                      <button
                        key={c.ms}
                        className="btn ghost sm"
                        title={`Say nothing about this for ${c.label}. The chip stays, because the condition has not changed.`}
                        onClick={() => snoozeAlert(a.serverId, a.kind, c.ms)}
                      >
                        {c.label}
                      </button>
                    ))
                  )}{' '}
                  <button
                    className="btn ghost sm"
                    title="You have seen it and are dealing with it. The chip goes and nothing more is said until the condition itself clears — however long that takes."
                    onClick={() => acknowledgeAlert(a.serverId, a.kind)}
                  >
                    Acknowledge
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}

      <div className="s-title" style={{ marginTop: 12 }}>
        Per-host thresholds
      </div>
      <div className="s-desc">
        The CPU and memory line for one host, where the estate is not uniform — a build box at 95%
        is working and a database at 95% is in trouble. Blank uses the workspace default of{' '}
        {globalThreshold}%. Disk, inodes and load are deliberately not settable per host: they are
        the numbers the Fleet Monitor colours a bar at and lists a host under, and an alert firing
        at a different number from the screen it sends you to is worse than no alert.
      </div>
      <table className="mini-table">
        <tbody>
          {servers.map((srv) => {
            const override = perHost[srv.id]
            return (
              <tr key={srv.id}>
                <td>{srv.name}</td>
                <td>
                  <input
                    className="input"
                    style={{ width: 72 }}
                    type="number"
                    min={THRESHOLD_MIN}
                    max={THRESHOLD_MAX}
                    placeholder={String(globalThreshold)}
                    value={draft[srv.id] ?? (override === undefined ? '' : String(override))}
                    aria-label={`CPU and memory threshold for ${srv.name}`}
                    onChange={(e) => typeThreshold(srv.id, e.target.value)}
                    onBlur={() => blurThreshold(srv.id)}
                  />
                </td>
                <td className="faint">
                  {override === undefined
                    ? `using the default, ${globalThreshold}%`
                    : `alerts at ${hostThreshold(globalThreshold, perHost, srv.id)}%`}
                </td>
              </tr>
            )
          })}
        </tbody>
      </table>
      {servers.length === 0 && (
        <div className="faint" style={{ fontSize: 12 }}>
          This workspace has no servers.
        </div>
      )}

      <div className="s-title" style={{ marginTop: 12 }}>
        History
      </div>
      {failed ? (
        <div className="warn" style={{ fontSize: 12 }}>
          The alert log could not be read, so this history is not the history — it is nothing at
          all. Anything raised while it is unreadable is still delivered.
        </div>
      ) : rows === null ? (
        <div className="faint" style={{ fontSize: 12 }}>
          Reading the alert log…
        </div>
      ) : rows.length === 0 ? (
        <div className="faint" style={{ fontSize: 12 }}>
          No alert has been recorded yet.
        </div>
      ) : (
        <table className="mini-table">
          <tbody>
            {rows.map((row, i) => (
              <tr key={`${row.at}:${row.serverId}:${row.kind}:${i}`}>
                <td className={clsx(EVENT_CLASS[row.event])}>{EVENT_WORD[row.event]}</td>
                <td>{LABEL[row.kind]}</td>
                <td>{row.serverName || row.serverId}</td>
                <td className="faint">{rowSubject(row)}</td>
                <td className="faint">{when(row.at, now)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      {rows !== null && rows.length >= LIMIT && (
        <div className="faint" style={{ fontSize: 11, marginTop: 4 }}>
          Showing the most recent {LIMIT}. Older events are kept for as long as the history store
          keeps anything, and are not shown here.
        </div>
      )}
    </div>
  )
}
