import { app } from 'electron'
import { join } from 'node:path'
import { existsSync, readFileSync, renameSync, unlinkSync, writeFileSync } from 'node:fs'
import {
  RUNBOOK_LOOKBACK_DAYS,
  RUNBOOK_OCCURRENCES,
  buildRunbookRecall,
  isRunbookKind,
  runbookJobWindow,
  runbookKey,
  sanitiseRunbookNote,
  type RunbookAlertRow,
  type RunbookJobRow,
  type RunbookNote,
  type RunbookOutcome,
  type RunbookRecall,
  type RunbookView
} from '../../shared/runbooks'
import { ALERT_HISTORY_KIND, sanitiseStoredAlert, type StoreAlertKind } from '../../shared/webhook'
import type { JobHostOutcome } from '../../shared/jobs'
import { DISABLE_ENV, type HistoryStore } from './history'
import { redactOutput } from './secretRedaction'

// Runbooks attached to alerts — roadmap item 28, the main-process half.
//
// ---------------------------------------------------------------------------
// WHERE THE NOTES LIVE, AND WHY NOT IN THE HISTORY STORE
// ---------------------------------------------------------------------------
// The obvious place is the durable store: it is already open, it already holds
// the alert events these notes hang off, and it already has a table shaped like
// a key and a value. It is the wrong place, for one reason that settles it.
//
//   THE HISTORY STORE HAS RETENTION AND A NOTE MUST NOT.
//
// Events are dropped on a horizon per kind — a quarter for most of them, and
// item 32's 400 days is still not never — and facts are retired when the probe
// stops seeing them. Both are correct for a MEASUREMENT — nobody can retake it, and
// nobody needs the one from March — and both are catastrophic for a sentence a
// person wrote at 3am about what to check first. A note that quietly disappears
// after a quiet quarter is worse than no notes feature at all, because the
// operator wrote it believing it would be there.
//
// Nor does it belong in the renderer's zustand blob (store.ts), which is where
// every other user-facing setting lives. That blob is the workspace: servers,
// folders, tunnels, thresholds. A runbook note is not configuration — it is
// small operator-authored content, and it must be readable by main so a future
// export or a future alert payload can carry it without asking a window that
// may not be open. So it gets its own small file, written and read entirely in
// main, exactly as `updatePrefs.ts` argues for its own.
//
// The file is a plain JSON array with temp-then-rename at 0600, the shape
// store.ts, vault.ts, policyStore.ts and updatePrefs.ts all use. No .bak: a
// note is a few sentences a person can retype, and the extra write per save is
// not worth it — the same trade updatePrefs makes and store.ts declines.
//
// ---------------------------------------------------------------------------
// WHAT THE JOB-HISTORY HALF CAN AND CANNOT ANSWER
// ---------------------------------------------------------------------------
// CAN: which jobs a person started against this host between the alert being
// raised and it clearing, what those jobs' steps were, and how each ended on
// that host.
//
// CANNOT, and must not be read as claiming:
//
//  * THAT THE JOB FIXED IT. Nothing here establishes causation. The alert
//    cleared and a job ran; a log rotation on a cron timer may have been what
//    actually did it. The panel says "what was run", never "what fixed it".
//  * WORK DONE OUTSIDE THE JOB ENGINE. An operator who opened a terminal tab
//    and typed `rm` is invisible here — that is a local shell, and the change
//    log is where those rows live. This half sees jobs and nothing else.
//  * ANYTHING OLDER THAN THE ALERT HORIZON. This used to be the shorter of two
//    horizons and it was a defect: job rows were kept for a year and alert
//    events for ninety days, so a job from ten months ago was still on disk and
//    unreachable from here because the raise that would have anchored it was
//    gone. Roadmap item 32 made retention a policy per kind and gave the alert
//    kind 400 days — longer than the job rows it anchors — so the anchor is no
//    longer the short side. Past 400 days there is genuinely nothing to join,
//    and RUNBOOK_NEVER_FIRED says so rather than leaving it as an absence.
//  * A HOST THE ALERT DID NOT NAME. Every read is per host, because the same
//    alert on two machines was two incidents with two answers.

const NOTES_FILE = 'shellpilot-runbooks.json'

/** The stored shape. Versioned from the first write, so the first change that
 *  cannot be expressed by ignoring an unknown field has a number to branch on. */
interface NotesFile {
  v: number
  notes: RunbookNote[]
}

const NOTES_VERSION = 1

export interface RunbookDeps {
  /** The durable store, or null when history is disabled or not yet open. */
  history: () => HistoryStore | null
  /** Where the notes file lives. Defaults to userData. */
  dir?: string
  now?: () => number
}

function notesPath(deps: RunbookDeps): string {
  return join(deps.dir ?? app.getPath('userData'), NOTES_FILE)
}

/** What a read of the notes file produced. `unreadable` is NOT the same as an
 *  empty list, and the view carries both so the panel can say which. */
interface NotesRead {
  notes: Map<string, RunbookNote>
  unreadable: boolean
}

function readNotes(deps: RunbookDeps): NotesRead {
  const path = notesPath(deps)
  const empty: NotesRead = { notes: new Map(), unreadable: false }
  if (!existsSync(path)) return empty
  let parsed: unknown
  try {
    parsed = JSON.parse(readFileSync(path, 'utf8'))
  } catch (err) {
    // A file that EXISTS and will not parse is a different claim from no file.
    // Returning an empty map for it would tell an operator nobody has written
    // a runbook, when what happened is that theirs cannot be read.
    console.error('[runbooks] notes file unreadable:', err)
    return { notes: new Map(), unreadable: true }
  }
  const rows =
    parsed !== null && typeof parsed === 'object' && Array.isArray((parsed as NotesFile).notes)
      ? (parsed as NotesFile).notes
      : null
  if (rows === null) return { notes: new Map(), unreadable: true }

  const notes = new Map<string, RunbookNote>()
  for (const raw of rows) {
    // A notes file is not a trusted input. It survives downgrades, hand edits
    // and restored backups, so every field is narrowed back to something the
    // rest of the code has a branch for rather than trusted because it parsed.
    if (raw === null || typeof raw !== 'object') continue
    const r = raw as Partial<RunbookNote>
    if (!isRunbookKind(r.kind)) continue
    const hostId = typeof r.hostId === 'string' && r.hostId !== '' ? r.hostId : null
    const text = sanitiseRunbookNote(r.text)
    if (text === '') continue
    const updatedAt = typeof r.updatedAt === 'number' && Number.isFinite(r.updatedAt) ? r.updatedAt : 0
    notes.set(runbookKey(r.kind, hostId), { kind: r.kind, hostId, text, updatedAt })
  }
  return { notes, unreadable: false }
}

function writeNotes(deps: RunbookDeps, notes: Map<string, RunbookNote>): boolean {
  const path = notesPath(deps)
  const tmp = `${path}.tmp`
  const body: NotesFile = { v: NOTES_VERSION, notes: [...notes.values()] }
  try {
    writeFileSync(tmp, JSON.stringify(body), { mode: 0o600 })
    renameSync(tmp, path)
    return true
  } catch (err) {
    console.error('[runbooks] note save failed:', err)
    return false
  }
}

/**
 * Write, replace or remove one note.
 *
 * An empty text REMOVES the note rather than storing a blank one. A stored
 * empty string would render as "there is a runbook here" with nothing in it,
 * which is the same lie an empty history is when the log could not be read.
 *
 * Returns the note as stored, `null` when it was removed, and throws nothing:
 * a failed write is reported by the boolean on the result so the caller can
 * tell the operator their note did not land rather than showing it back to
 * them from memory.
 */
export function saveRunbookNote(
  deps: RunbookDeps,
  kind: StoreAlertKind,
  hostId: string | null,
  rawText: unknown
): { ok: boolean; note: RunbookNote | null } {
  const { notes } = readNotes(deps)
  const key = runbookKey(kind, hostId)
  const text = sanitiseRunbookNote(rawText)
  if (text === '') {
    notes.delete(key)
    return { ok: writeNotes(deps, notes), note: null }
  }
  const note: RunbookNote = {
    kind,
    hostId,
    text,
    updatedAt: (deps.now ?? Date.now)()
  }
  notes.set(key, note)
  return { ok: writeNotes(deps, notes), note }
}

/** Test-only, the convention resetUpdatePrefsCacheForTests follows: drop the
 *  file so the next read starts from nothing. */
export function removeRunbookNotesForTests(deps: RunbookDeps): void {
  try {
    const p = notesPath(deps)
    if (existsSync(p)) unlinkSync(p)
  } catch {
    /* ignore */
  }
}

// ---------------------------------------------------------------------------
// The half nobody types
// ---------------------------------------------------------------------------

/**
 * How the job ended ON THIS HOST, in our own vocabulary.
 *
 * Derived from the stored outcome and exit code, never from a sentence the
 * host wrote. `unknown` is a real answer and is not folded into `failed`: a
 * job the app lost track of — abandoned, orphaned — did not necessarily fail,
 * and calling it a failure is the same invention as a zero for an unmeasured
 * reading.
 */
/**
 * A job's per-host outcome, reduced to the three words a runbook needs.
 *
 * TAKEN AS `JobHostOutcome`, NOT AS `string`, AND THAT IS THE POINT. This
 * branched on `'failed'` — which has never been a member of that union — so
 * `nonzero`, `missing-command`, `permission-denied`, `unreachable`, `abandoned`
 * and `orphaned` all fell through to `unknown`. A command that exited non-zero
 * is the commonest failure there is, and the runbook reported it as "we cannot
 * say". A test agreed, because its fixture seeded the same value that does not
 * exist; both were wrong in the same direction, so the test passed.
 *
 * The map below is exhaustive over the union by type rather than by reading, so
 * a new outcome added to the job engine fails to compile here instead of
 * quietly joining `unknown`.
 */
const OUTCOME_MEANS: Record<JobHostOutcome, RunbookOutcome> = {
  ok: 'succeeded',
  nonzero: 'failed',
  'missing-command': 'failed',
  'permission-denied': 'failed',
  timeout: 'failed',
  unreachable: 'failed',
  unhealthy: 'failed',
  orphaned: 'failed',
  abandoned: 'unknown',
  cancelled: 'unknown'
}

function outcomeOf(
  outcome: JobHostOutcome | undefined,
  exitCode: number | undefined
): RunbookOutcome {
  // `abandoned` and `cancelled` are `unknown` rather than `failed` on purpose:
  // neither says the command failed. One stopped because ShellPilot did, the
  // other never ran. Calling either a failure would put a red mark against a
  // host that did nothing wrong — the same reasoning that gave `abandoned` its
  // own name in the job engine rather than reusing `unreachable`.
  if (outcome !== undefined) return OUTCOME_MEANS[outcome] ?? 'unknown'
  if (typeof exitCode === 'number') return exitCode === 0 ? 'succeeded' : 'failed'
  return 'unknown'
}

/** Why the store could not answer. The env var is what `loadHistory` itself
 *  branches on, so "switched off" here means the same thing it means there —
 *  rather than being inferred from a null the disk could also have caused. */
function unavailableReason(): 'store-disabled' | 'store-unreadable' {
  return process.env[DISABLE_ENV] === '1' ? 'store-disabled' : 'store-unreadable'
}

/**
 * What was run the last three times this alert fired on this host.
 *
 * Reads through TWO named statements — `readEvents` for the raises and
 * `jobsForHost` for the work — and passes both to the pure builder in
 * shared/runbooks.ts along with the redactor. No SQL is assembled here and
 * none crosses the store's boundary; see the note at the top of history.ts.
 */
export function readRunbookRecall(
  deps: RunbookDeps,
  kind: StoreAlertKind,
  hostId: string | null
): RunbookRecall {
  if (hostId === null || hostId === '') return { status: 'no-host' }
  const store = deps.history()
  if (!store) return { status: 'unavailable', reason: unavailableReason() }

  const now = (deps.now ?? Date.now)()
  const from = now - RUNBOOK_LOOKBACK_DAYS * 86_400_000

  let alerts: RunbookAlertRow[]
  let jobs: RunbookJobRow[]
  try {
    alerts = []
    // Bounded by RUNBOOK_OCCURRENCES rather than by the page: three raises is
    // the whole answer, but a chatty kind interleaves snoozes and
    // acknowledgements between them, so the read asks for enough rows that
    // three RAISES are inside it rather than three rows.
    for (const row of store.readEvents({
      kind: ALERT_HISTORY_KIND,
      hostId,
      from,
      to: now,
      limit: 40 * RUNBOOK_OCCURRENCES
    })) {
      const event = sanitiseStoredAlert(row.payload)
      if (!event || event.kind !== kind) continue
      if (event.event === 'raised') alerts.push({ at: row.ts, raised: true })
      // A stand-down closes the window as a resolve does. It is NOT an
      // all-clear — see StoredAlertEventName — but it does end the incident
      // from this read's point of view: alerting was switched off, so what
      // happened afterwards was not a response to an alert nobody was seeing.
      else if (event.event === 'resolved' || event.event === 'stood-down') {
        alerts.push({ at: row.ts, raised: false })
      }
    }

    // Bounded by the OCCURRENCES, not by the lookback. The cap below is 200
    // jobs newest-first, and over a 400-day lookback those are all from the
    // last fortnight on a busy host — the job that answered a raise from the
    // spring would fall off the end and the recall would say nothing was run.
    // See runbookJobWindow, which derives the span from the same three raises
    // buildRunbookRecall will report.
    const window = runbookJobWindow(alerts)
    jobs = (window === null
      ? []
      : store.jobsForHost(hostId, Math.max(from, window.from), Math.min(now, window.to), 200)
    ).map((run) => ({
      id: run.job.id,
      title: run.job.title,
      // When it STARTED on this host, falling back to when the row was minted.
      // A job queued behind two waves may have been created before the alert
      // and reached this host after it, and the second of those is the moment
      // that makes it a response.
      at: run.host.startedAt ?? run.job.createdAt,
      commands: run.job.spec.steps.map((s) => s.command),
      outcome: outcomeOf(run.host.outcome, run.host.exitCode),
      ...(run.host.error ? { error: run.host.error } : {})
    }))
  } catch (err) {
    // A store that is open and then throws mid-read is unreadable, not empty.
    // This is the fifth time this codebase has had to say that out loud.
    console.error('[runbooks] history read failed:', err)
    return { status: 'unavailable', reason: 'store-unreadable' }
  }

  return buildRunbookRecall({
    alerts,
    jobs,
    // Pattern redaction only: the resolved passwords `redactKnownSecrets` also
    // takes belong to a live operation and this is a read of rows written
    // months ago, whose credentials this process may not hold and must not
    // resolve in order to render a list. The patterns are what catch a secret
    // TYPED INTO a command, which is the case that matters here.
    redact: (text) => redactOutput(text, [])
  })
}

/** One runbook: the note a person wrote, the note for the kind across the
 *  fleet, and what was actually run. */
export function readRunbook(
  deps: RunbookDeps,
  kind: StoreAlertKind,
  hostId: string | null
): RunbookView {
  const { notes, unreadable } = readNotes(deps)
  return {
    kind,
    hostId,
    hostNote: hostId === null ? null : (notes.get(runbookKey(kind, hostId)) ?? null),
    kindNote: notes.get(runbookKey(kind, null)) ?? null,
    notesUnreadable: unreadable,
    recall: readRunbookRecall(deps, kind, hostId)
  }
}
