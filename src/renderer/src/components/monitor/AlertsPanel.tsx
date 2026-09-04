import { useCallback, useEffect, useMemo, useState } from 'react'
import { AlertTriangle, BookOpen, CheckCircle2, ChevronRight, RefreshCw, SlidersHorizontal } from 'lucide-react'
import { useApp, useWorkspaceServers } from '../../store/app'
import { useFleetStatus } from '../../store/fleetStatus'
import {
  LABEL,
  RUNBOOK_BRIDGE_MISSING,
  SNOOZE_CHOICES,
  THRESHOLD_MAX,
  THRESHOLD_MIN,
  hostThreshold,
  acknowledgeAlert,
  chipValue,
  readRunbook,
  saveRunbookNote,
  snoozeAlert,
  unsnoozeAlert,
  useAlerts,
  type ActiveAlert
} from '../../store/alerts'
import { alertCoverage, alertCoverageLines, type AlertCoverage } from '../settings/alertCoverage'
import { openSettings } from '../../store/nav'
import { clsx } from '../../lib/format'
import type { StoredAlertRow, StoreAlertKind } from '../../../../shared/webhook'
import { STORE_ALERT_KINDS } from '../../../../shared/webhook'
import {
  RUNBOOK_HOST_REPORTED_NOTE,
  RUNBOOK_NEVER_FIRED,
  RUNBOOK_NOTHING_RUN,
  RUNBOOK_NO_HOST,
  RUNBOOK_NO_RUN_NOTE,
  runbookUnavailableSentence,
  type RunbookView
} from '../../../../shared/runbooks'

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
//
// ---------------------------------------------------------------------------
// On the LAYOUT, which was rebuilt without changing a single one of the above
// claims or any of the semantics below them.
//
// The screen this replaces put five accurate paragraphs above the thing the
// screen is for. Reading top to bottom you met: which alert kinds are polled by
// what and when (four paragraphs), why a database verdict cannot be snoozed, a
// runbook editor, an explainer about what "What was run" means, a per-host
// threshold table, and a paragraph justifying why disk, inodes and load are not
// per-host. The single outstanding alert sat in the middle of that, one line
// tall, and its five controls — three snooze durations, Acknowledge, Runbook —
// were five identical `btn ghost sm` in a table cell, so the thing you had to
// do did not look different from the four things you probably did not.
//
// Three rules came out of that, and they are the whole of the change:
//
//   1. The outstanding alerts are the page. They lead it, one card each, at a
//      size and weight nothing else on the screen competes with, and the
//      primary action on a card is the only filled button in the section.
//   2. The prose is kept, in full, wording untouched — behind a disclosure. It
//      explains real semantics a sysadmin needs (a database verdict exists only
//      because somebody opened the Databases page; OOM and certificate reads
//      need the posture module on) and deleting it would be a lie by omission.
//      But somebody who already knows must never scroll past it, so it is one
//      `<summary>` line and a chevron. What CANNOT be folded away is the
//      coverage VERDICT — "you are only covered while looking at a screen" is a
//      warning, not an explanation — so that stays in the header as a chip,
//      read from alertCoverage() rather than restated, which is the rule
//      alertCoverage.ts exists to enforce.
//   3. Hierarchy through type. `.s-title` and `.s-desc` are defined in
//      global.css only under `.setting-row`, so on this panel they styled
//      nothing at all: every heading, every explanatory paragraph and every
//      table cell rendered at the same 13px body weight. That is the mechanical
//      cause of "this mountain of text" and no amount of reordering fixes it
//      alone. The `.alerts` block appended to global.css gives this panel a
//      real title/heading/body/secondary scale.
//
// Nothing about when an alert fires, what it is worth, or what a snooze does
// changed here. This file reads the same store and calls the same four actions
// it did before.
// ---------------------------------------------------------------------------

/** The page size the read asks for, and the most rows this list renders.
 *
 *  These were the same number for a reason that no longer holds: the inbox and
 *  the suppression state had to be looking at the same rows, or the history
 *  could not explain the silence. Hydration is now bounded by TIME rather than
 *  by a row count — a cap drops the oldest rows, and the oldest rows are the
 *  chronic alerts — so `alerts:history` may hand back more than this, and the
 *  suppression state is right to use all of it. The list still stops here,
 *  because five thousand table rows is not a screen anybody reads, and the note
 *  under it says so. */
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
 * The coverage verdict, in the four words that fit in a chip.
 *
 * Derived from `alertCoverage()` rather than from `fleetSamplingEnabled`, which
 * is the single rule alertCoverage.ts was written to enforce: a screen may
 * describe a capability from whether it is RUNNING, never from the switch that
 * requests it. The long sentences behind the disclosure come from the same
 * function, so the chip and the paragraph cannot drift apart.
 *
 * The chip is the one piece of the explanatory block that is NOT folded away,
 * because it is not an explanation. "An alert can only fire while you are
 * already looking at the host" is a warning about what this screen will fail to
 * tell you, and a warning behind a chevron is a warning nobody reads.
 */
const COVERAGE_CHIP: Record<AlertCoverage, { label: string; tone: string }> = {
  running: { label: 'Background checks on', tone: 'ok' },
  'requested-not-running': { label: 'Checks not running', tone: 'warn' },
  'foreground-only': { label: 'Foreground only', tone: 'warn' }
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

/**
 * One runbook — roadmap item 28.
 *
 * Two halves on one screen, and they are kept visibly apart because they have
 * different authors. The note is OPERATOR-WRITTEN, so it is not
 * attacker-controlled; the failure text under a remembered command is
 * HOST-REPORTED, and it is. `hostReportedBlock` in mcpServer.ts makes that
 * distinction for a model deciding whether a line is an instruction; this makes
 * it for a person at 3am deciding whether a line is advice.
 *
 * There is no control in here that runs anything, and that is the item rather
 * than an omission from it. See RUNBOOK_NO_RUN_NOTE, which is rendered right
 * next to the commands so the person who wants the button is told why there
 * is not one.
 */
function RunbookBody({
  kind,
  hostId,
  hostName
}: {
  kind: StoreAlertKind
  hostId: string | null
  hostName: string
}): React.JSX.Element {
  const [view, setView] = useState<RunbookView | null | 'unreachable'>(null)
  const [draft, setDraft] = useState<string | null>(null)
  const [saveFailed, setSaveFailed] = useState(false)

  const load = useCallback(() => {
    setView(null)
    setDraft(null)
    void readRunbook(kind, hostId).then((v) => setView(v ?? 'unreachable'))
  }, [kind, hostId])

  useEffect(() => {
    load()
  }, [load])

  if (view === 'unreachable') {
    return (
      <div className="s-desc warn" data-testid="runbook-unreachable">
        {RUNBOOK_BRIDGE_MISSING}
      </div>
    )
  }
  if (view === null) {
    return <div className="alerts-quiet-line">Reading the runbook…</div>
  }

  // The note being edited is the one for the CURRENT selection: a host note
  // when a host is chosen, the fleet note otherwise. The other one is shown
  // beside it, read-only, rather than merged into it — two people wrote them
  // about two different scopes.
  const owned = hostId === null ? view.kindNote : view.hostNote
  const text = draft ?? owned?.text ?? ''
  const scope = hostId === null ? `every server` : hostName

  const commit = (): void => {
    void saveRunbookNote(kind, hostId, text).then((r) => {
      setSaveFailed(!r.ok)
      if (r.ok) load()
    })
  }

  return (
    <>
      {view.notesUnreadable && (
        <div className="s-desc warn" data-testid="runbook-notes-unreadable">
          The runbook notes file could not be read, so nothing below is your note — it is nothing
          at all. Saving now would overwrite whatever is in that file.
        </div>
      )}

      <div className="s-desc" data-testid="runbook-note-provenance">
        Your note for {LABEL[kind]} on {scope}. This is text you wrote; nothing on a server can
        change it.
      </div>
      <textarea
        className="input"
        rows={4}
        style={{ width: '100%', fontFamily: 'inherit' }}
        aria-label={`Runbook note for ${LABEL[kind]} on ${scope}`}
        value={text}
        onChange={(e) => setDraft(e.target.value)}
        onBlur={commit}
      />
      {saveFailed && (
        <div className="s-desc warn" data-testid="runbook-save-failed">
          That note was not saved, so it is not there. It is still in the box above — copy it
          somewhere before you leave this screen.
        </div>
      )}
      {hostId !== null && view.kindNote && (
        <div className="s-desc" data-testid="runbook-kind-note">
          <b>Every server, for {LABEL[kind]}:</b> {view.kindNote.text}
        </div>
      )}

      <div className="alerts-subhead">What was run</div>
      <div className="s-desc" data-testid="runbook-no-run">
        {RUNBOOK_NO_RUN_NOTE}
      </div>
      <RunbookRecallBody view={view} />
    </>
  )
}

/** The half nobody typed. Four sentences and a list, and which sentence it is
 *  is the whole point — see the five statuses in shared/runbooks.ts. */
function RunbookRecallBody({ view }: { view: RunbookView }): React.JSX.Element {
  const r = view.recall
  if (r.status === 'no-host') {
    return (
      <div className="alerts-quiet-line" data-testid="runbook-no-host">
        {RUNBOOK_NO_HOST}
      </div>
    )
  }
  if (r.status === 'unavailable') {
    return (
      <div className="s-desc warn" data-testid="runbook-unavailable">
        {runbookUnavailableSentence(r.reason)}
      </div>
    )
  }
  if (r.status === 'never-fired') {
    return (
      <div className="alerts-quiet-line" data-testid="runbook-never-fired">
        {RUNBOOK_NEVER_FIRED}
      </div>
    )
  }
  if (r.status === 'nothing-run') {
    return (
      <div className="alerts-quiet-line" data-testid="runbook-nothing-run">
        {RUNBOOK_NOTHING_RUN}
      </div>
    )
  }

  return (
    <div data-testid="runbook-commands">
      {r.occurrences.map((occ) => (
        <div key={occ.at} style={{ marginTop: 8 }}>
          <div className="alerts-meta">
            Raised {new Date(occ.at).toLocaleString()}
            {occ.resolvedAt === null ? '' : `, cleared ${new Date(occ.resolvedAt).toLocaleString()}`}
          </div>
          {occ.jobs.length === 0 ? (
            <div className="alerts-quiet-line">Nothing ran during this one.</div>
          ) : (
            occ.jobs.map((j) => (
              <div key={j.id}>
                <div className="alerts-meta">{j.title}</div>
                <table className="mini-table">
                  <tbody>
                    {j.commands.map((c, i) => (
                      <tr key={`${j.id}:${i}`}>
                        <td style={{ fontFamily: 'monospace', fontSize: 11 }}>{c.text}</td>
                        <td className={c.outcome === 'failed' ? 'warn' : 'faint'}>{c.outcome}</td>
                        <td className="faint">
                          {/* The one string on this screen a host wrote. Marked
                              as such rather than set beside the note in the
                              same voice — the note is yours and this is not. */}
                          {c.hostReported ? (
                            <span data-testid="runbook-host-reported">
                              <b>{RUNBOOK_HOST_REPORTED_NOTE}</b> {c.hostReported}
                            </span>
                          ) : null}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ))
          )}
          {occ.elided > 0 && (
            <div className="alerts-meta">
              {occ.elided} further step{occ.elided === 1 ? '' : 's'} in this incident are not
              listed. They are in the job itself.
            </div>
          )}
        </div>
      ))}
    </div>
  )
}

/**
 * One outstanding alert.
 *
 * A card rather than a table row, because the content is not tabular: it is a
 * headline (what, and where), a subordinate line (the reading, and how long),
 * and a set of controls of two very different weights. Laying that out in five
 * `<td>` forced all five into one visual rank, which is exactly the complaint.
 *
 * The weighting of the controls is the point of the card:
 *
 *   Acknowledge  is the primary, filled. It is what a person on this screen
 *                has usually come to do, and it says "I have seen it" — the
 *                one action with a consequence for what you will be told next.
 *   Runbook      is a navigation, not an action. Ghost.
 *   Snooze       is three choices, and they were three of the five identical
 *                buttons that made the row unreadable. Grouped into one labelled
 *                segmented control, at the smallest type on the card, so they
 *                read as ONE secondary control with three settings rather than
 *                as three peers of Acknowledge.
 *
 * Every title text, every action and every string is the one that was on the
 * row before. Nothing here decides anything; it calls the same store actions.
 */
function OutstandingCard({
  a,
  now,
  onRunbook
}: {
  a: ActiveAlert
  now: number
  onRunbook: () => void
}): React.JSX.Element {
  const snoozedUntil = a.snoozedUntil
  const snoozed = snoozedUntil !== undefined && snoozedUntil > now
  // The reading, in the unit the reading is actually in — and nothing at all
  // for a kind that is a state rather than a number. A "0" here would be a
  // measurement nobody took, which is the rule the whole item runs on.
  const reading = `${chipValue(a).trim()}${a.detail ? ` ${a.detail}` : ''}`.trim()

  return (
    <li className={clsx('alert-card', snoozed && 'snoozed')} data-testid="outstanding-alert">
      <div className="alert-card-head">
        <span className="alert-kind">{LABEL[a.kind]}</span>
        <span className="alert-host">{a.serverName}</span>
        {reading !== '' && <span className="alert-reading">{reading}</span>}
        <span className="alert-since">since {when(a.since, now)}</span>
      </div>

      {/* Said out loud rather than shown as absence. A snoozed alert that
          simply looked normal would leave a person wondering why it had gone
          quiet, which is the failure mode damping already had to answer for. */}
      {snoozed && (
        <div className="alert-snoozed-note">
          Silenced: snoozed until {new Date(snoozedUntil).toLocaleTimeString()}. The condition has
          not changed, so the status-bar chip stays up.
        </div>
      )}

      <div className="alert-actions">
        <button
          className="btn primary sm"
          title="You have seen it and are dealing with it. The chip goes and nothing more is said until the condition itself clears — however long that takes."
          onClick={() => acknowledgeAlert(a.serverId, a.kind)}
        >
          Acknowledge
        </button>
        <button
          className="btn ghost sm"
          title="Your note for this alert, and what was actually run the last three times it fired on this server."
          onClick={onRunbook}
        >
          Runbook
        </button>

        <div className="alert-snooze">
          {snoozed ? (
            <button className="btn ghost sm" onClick={() => unsnoozeAlert(a.serverId, a.kind)}>
              Wake
            </button>
          ) : (
            <>
              <span className="alert-snooze-label">Snooze for</span>
              <span className="alert-snooze-group">
                {SNOOZE_CHOICES.map((c) => (
                  <button
                    key={c.ms}
                    className="btn ghost sm"
                    title={`Say nothing about this for ${c.label}. The chip stays, because the condition has not changed.`}
                    onClick={() => snoozeAlert(a.serverId, a.kind, c.ms)}
                  >
                    {c.label}
                  </button>
                ))}
              </span>
            </>
          )}
        </div>
      </div>
    </li>
  )
}

export function AlertsPanel(): React.JSX.Element {
  const active = useAlerts((s) => s.active)
  const samplerStatus = useFleetStatus((s) => s.status)
  const samplingEnabled = useApp((s) => s.settings.fleetSamplingEnabled)
  const alertsEnabled = useApp((s) => s.settings.resourceAlertsEnabled)
  const globalThreshold = useApp((s) => s.settings.resourceAlertThreshold)
  const perHost = useApp((s) => s.settings.resourceAlertThresholds)
  const servers = useWorkspaceServers()
  const hydrated = useApp((st) => st.hydrated)
  // What is in each threshold box while it is being typed in, which is not the
  // same thing as what is stored. See commitThreshold.
  const [draft, setDraft] = useState<Record<string, string>>({})
  const [rows, setRows] = useState<StoredAlertRow[] | null>(null)
  const [reading, setReading] = useState(false)
  const [failed, setFailed] = useState(false)
  // Which runbook is open. A kind on its own is the fleet-wide note; a kind
  // and a host is an incident. Held here rather than in the section so the
  // Runbook button on an outstanding row can point at that row's own pair.
  const [runbook, setRunbook] = useState<{ kind: StoreAlertKind; hostId: string | null }>({
    kind: 'disk',
    hostId: null
  })
  // Whether the runbook disclosure is unfolded. Controlled rather than left to
  // the browser because the Runbook button on a card has to be able to open it
  // — a button that silently changed the contents of a section folded shut
  // three screens down would look like a button that does nothing.
  const [runbookOpen, setRunbookOpen] = useState(false)

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
  // Oldest first, unchanged: the longest-standing problem leads. Whether an
  // alert is snoozed deliberately does NOT reorder it — a snooze silences the
  // notification, and moving the row as well would be this screen agreeing to
  // forget something the store still holds.
  const outstanding = useMemo(
    () => Object.values(active).sort((a, b) => a.since - b.since),
    [active]
  )
  const coverage = alertCoverage(samplerStatus?.running, samplingEnabled)
  const chip = COVERAGE_CHIP[coverage]
  const openRunbookFor = (kind: StoreAlertKind, hostId: string): void => {
    setRunbook({ kind, hostId })
    setRunbookOpen(true)
  }

  return (
    <div className="bc-panel alerts">
      {/* ---------------------------------------------------------------
          The header. A title, a one-line count, and the coverage verdict —
          nothing that needs reading twice. Everything that used to be here
          instead is under "How alerting works" below, in full.
          --------------------------------------------------------------- */}
      <div className="alerts-head">
        <AlertTriangle size={16} className={outstanding.length > 0 ? 'warn' : 'faint'} />
        <div className="grow">
          <div className="alerts-title">Alerts</div>
          <div className="alerts-sub">
            {outstanding.length === 0
              ? 'Nothing outstanding.'
              : `${outstanding.length} outstanding.`}{' '}
            {rows === null ? '' : `${rows.length} recorded.`}
          </div>
        </div>
        <span className={clsx('chip', chip.tone)} title={alertCoverageLines(samplerStatus?.running, samplingEnabled)[0].text}>
          {chip.label}
        </span>
        <button className="btn ghost sm" onClick={read} disabled={reading}>
          <RefreshCw size={12} /> Refresh
        </button>
      </div>

      {/* Not folded away with the rest of the prose, and not for symmetry: this
          one is a live state with a control attached, and the state is "the
          feature you are looking at is off". */}
      {!alertsEnabled && (
        <div className="alerts-banner">
          <span className="grow">
            Resource alerts are switched off, so nothing new will be added below.
          </span>
          <button className="btn ghost sm" onClick={() => openSettings('monitoring')}>
            Monitoring settings
          </button>
        </div>
      )}

      {/* ---------------------------------------------------------------
          Outstanding. The page.
          --------------------------------------------------------------- */}
      <div className="alerts-section-head">
        <span className="alerts-heading">Outstanding</span>
        {outstanding.length > 0 && <span className="chip warn">{outstanding.length}</span>}
      </div>

      {outstanding.length === 0 ? (
        // A settled state, said as one. The screen that showed a grey
        // half-sentence here made "everything is fine" look like "nothing
        // loaded", which on an alerts page is the more expensive of the two to
        // get wrong.
        <div className="alerts-quiet">
          <CheckCircle2 size={18} className="ok" />
          <div>
            <div className="alerts-quiet-title">Nothing is outstanding right now.</div>
            <div className="alerts-quiet-sub">
              Anything that has been raised and cleared is in the history below.
            </div>
          </div>
        </div>
      ) : (
        <ul className="alert-list">
          {outstanding.map((a) => (
            <OutstandingCard
              key={`${a.serverId}:${a.kind}`}
              a={a}
              now={now}
              onRunbook={() => openRunbookFor(a.kind, a.serverId)}
            />
          ))}
        </ul>
      )}

      {/* ---------------------------------------------------------------
          How alerting works. Every paragraph that used to lead this screen,
          verbatim, one chevron away.
          --------------------------------------------------------------- */}
      <details className="disclosure alerts-fold" data-testid="alerts-how-it-works">
        <summary className="disclosure-head">
          <ChevronRight size={14} className="chev" />
          How alerting works — where each kind comes from, and what a snooze does
        </summary>
        <div className="disclosure-body">
          {/* Coverage, per kind, because the kinds are not produced by the same
              thing. The first line is the settings screen's own sentence from the
              same function — not a paraphrase, because alertCoverage.ts exists
              because that claim was once made from the SWITCH rather than from
              whether the sampler is actually looping, and a second copy of the
              wording here is how that comes back.

              The lines after it are the correction. Of the five kinds this item
              added, only host-unreachable rides the sampler: job-failed rides
              jobs.onProgress, tunnel-down a ten-second poll, and db-alarm and
              db-watch exist only because a person opened the Databases page. A
              panel that showed the sampler's sentence alone claimed background
              coverage for two kinds that have none at all. */}
          {alertCoverageLines(samplerStatus?.running, samplingEnabled).map((line) => (
            <div className="s-desc" key={line.source} data-testid={`alert-coverage-${line.source}`}>
              <b>{line.kinds.map((k) => LABEL[k]).join(', ')}.</b> {line.text}
            </div>
          ))}

          {/* Said here rather than left as an absence somebody has to notice.
              Outstanding is built from the status-bar chips, and a database verdict
              deliberately holds none: notableDbEvents records alarm and watch and
              never records ok, so nothing in the store can say a database
              recovered, and a chip that could never come down would point at a
              screen that disagreed with it. They are in the history below, and
              there is nothing to snooze because nothing repeats. */}
          <div className="s-desc">
            <b>Database verdicts are not listed under Outstanding and cannot be snoozed:</b> they
            are occurrences rather than conditions, so there is no repeat to stop. Every one is in
            the history below.
          </div>

          {/* The two actions on a card, in the words their own tooltips use.
              Written down once here so the buttons themselves do not have to
              carry an explanation each. */}
          <div className="s-desc">
            <b>Snoozing</b> stops this app talking about one host-and-kind for a while and leaves
            the status-bar chip up, because the condition has not changed.{' '}
            <b>Acknowledging</b> takes it out of Outstanding entirely and says nothing more until
            the condition itself clears, however long that takes.
          </div>
        </div>
      </details>

      {/* ---------------------------------------------------------------
          Runbook — roadmap item 28. The note is the small half; the list under
          it is what was actually run the last three times this fired, read out
          of the job history rather than typed by anybody — which is why it
          cannot go stale. Everything else about documentation belongs in a wiki
          that this app should link to rather than become.
          --------------------------------------------------------------- */}
      <details
        className="disclosure alerts-fold"
        data-testid="alerts-runbook"
        open={runbookOpen}
        onToggle={(e) => setRunbookOpen((e.currentTarget as HTMLDetailsElement).open)}
      >
        <summary className="disclosure-head">
          <ChevronRight size={14} className="chev" />
          <BookOpen size={13} />
          Runbook — your note, and what was run the last three times
        </summary>
        <div className="disclosure-body">
          <div className="row" style={{ gap: 8, alignItems: 'center' }}>
            <select
              className="input"
              aria-label="Runbook alert kind"
              value={runbook.kind}
              onChange={(e) =>
                setRunbook((r) => ({ ...r, kind: e.target.value as StoreAlertKind }))
              }
            >
              {STORE_ALERT_KINDS.map((k) => (
                <option key={k} value={k}>
                  {LABEL[k]}
                </option>
              ))}
            </select>
            <select
              className="input"
              aria-label="Runbook server"
              value={runbook.hostId ?? ''}
              onChange={(e) => setRunbook((r) => ({ ...r, hostId: e.target.value || null }))}
            >
              <option value="">Every server</option>
              {servers.map((srv) => (
                <option key={srv.id} value={srv.id}>
                  {srv.name}
                </option>
              ))}
            </select>
          </div>
          <RunbookBody
            key={`${runbook.kind}:${runbook.hostId ?? ''}`}
            kind={runbook.kind}
            hostId={runbook.hostId}
            hostName={servers.find((sv) => sv.id === runbook.hostId)?.name ?? runbook.hostId ?? ''}
          />
        </div>
      </details>

      {/* ---------------------------------------------------------------
          Per-host thresholds. Configuration, not an alert — so it is not in
          the alert flow any more. Folded, because a fleet is configured once
          and read every day.
          --------------------------------------------------------------- */}
      <details className="disclosure alerts-fold" data-testid="alerts-thresholds">
        <summary className="disclosure-head">
          <ChevronRight size={14} className="chev" />
          <SlidersHorizontal size={13} />
          Per-server thresholds — CPU and memory, where the estate is not uniform
        </summary>
        <div className="disclosure-body">
          <div className="s-desc">
            The CPU and memory line for one server, where the estate is not uniform — a build box at
            95% is working and a database at 95% is in trouble. Blank uses the workspace default of{' '}
            {globalThreshold}%. Disk, inodes and load are deliberately not settable per server: they
            are the numbers the Fleet Monitor colours a bar at and lists a server under, and an alert
            firing at a different number from the screen it sends you to is worse than no alert.
          </div>
          {servers.length === 0 && !hydrated ? (
            // Same reason as the capacity panel: saved servers arrive from an
            // await, so an empty list at launch is "not read yet", not "none".
            // Only the empty branch waits -- a list with something in it needs
            // no confirmation.
            <div className="alerts-quiet-line">Reading your servers…</div>
          ) : servers.length === 0 ? (
            <div className="alerts-quiet-line">This workspace has no servers.</div>
          ) : (
            <table className="mini-table">
              <tbody>
                {servers.map((srv) => {
                  const override = perHost[srv.id]
                  return (
                    <tr key={srv.id}>
                      <td className="strong">{srv.name}</td>
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
          )}
        </div>
      </details>

      {/* ---------------------------------------------------------------
          History. The durable half — the reason this panel exists at all —
          so it stays on the page rather than behind a chevron.
          --------------------------------------------------------------- */}
      <div className="alerts-section-head">
        <span className="alerts-heading">History</span>
      </div>
      {failed ? (
        <div className="alerts-banner">
          The alert log could not be read, so this history is not the history — it is nothing at
          all. Anything raised while it is unreadable is still delivered.
        </div>
      ) : rows === null ? (
        <div className="alerts-quiet-line">Reading the alert log…</div>
      ) : rows.length === 0 ? (
        <div className="alerts-quiet-line">No alert has been recorded yet.</div>
      ) : (
        <table className="mini-table alerts-history">
          <tbody>
            {rows.slice(0, LIMIT).map((row, i) => (
              <tr key={`${row.at}:${row.serverId}:${row.kind}:${i}`}>
                <td className={clsx('alerts-event', EVENT_CLASS[row.event])}>
                  {EVENT_WORD[row.event]}
                </td>
                <td className="strong">{LABEL[row.kind]}</td>
                <td>{row.serverName || row.serverId}</td>
                <td className="faint">{rowSubject(row)}</td>
                <td className="faint">{when(row.at, now)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      {rows !== null && rows.length > LIMIT && (
        <div className="alerts-meta" style={{ marginTop: 4 }}>
          Showing the most recent {LIMIT} of {rows.length} read back. Older events are kept for as
          long as the history store keeps anything, and are not shown here — but they are still
          read, which is what keeps a months-old alert from announcing itself again at every
          launch.
        </div>
      )}
    </div>
  )
}
