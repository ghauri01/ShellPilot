// Runbooks attached to alerts — roadmap item 28.
//
// "When the disk alert fires, show the three commands that fixed it last time."
//
// ---------------------------------------------------------------------------
// WHAT THIS IS, AND THE MUCH LARGER THING IT IS NOT
// ---------------------------------------------------------------------------
// The roadmap calls this "the only part of 'documentation' worth building
// here", and it says why: item A already stores the alert events, and the job
// engine already stores what was actually run against them. So a runbook is two
// halves, and only one of them is written by anybody:
//
//   1. A NOTE attached to an alert kind — free text, per kind, optionally per
//      host. This is the half a person types, and it is the small half.
//   2. WHAT WAS ACTUALLY RUN the last three times this fired — read out of the
//      job history. Nobody types this, nobody maintains it, and it cannot go
//      stale, because it is not a description of what you do: it is a record of
//      what you did.
//
// Everything else about documentation — diagrams, architecture prose, an
// inventory writeup — belongs in a wiki, and this app should link to one rather
// than become one. That is not a stylistic preference: a notes feature grows a
// tree, then a search, then a link resolver, then an export, and none of those
// are things a host ever tells you.
//
// ---------------------------------------------------------------------------
// WHAT IS DELIBERATELY NOT HERE, AND WILL NOT BE ADDED CASUALLY
// ---------------------------------------------------------------------------
// Written down in the shape src/shared/docker.ts writes its refusal to ship
// `docker system prune`, and asserted in tests/runbooks.test.ts, because a
// refusal nobody wrote down is a refusal the next person reverses by accident.
//
//  * A BUTTON THAT RUNS THE REMEMBERED COMMANDS. See RUNBOOK_NO_RUN_NOTE.
//    Showing them is the feature. Running them is a job — with a plan, a blast
//    radius, and an approval — and the one-click version is how an outage gets
//    repeated on purpose. The commands recalled here were right for a DIFFERENT
//    incident: the same alert kind on the same host in March may have been a
//    runaway log, and in June a database that grew. `rm -rf /var/log/*.gz` is
//    the correct answer to one of those and data loss on the other, and nothing
//    in this file can tell them apart. The operator reads them, decides, and
//    starts a job the ordinary way.
//  * COPYING A COMMAND STRAIGHT INTO A JOB SPEC. Same argument one step
//    removed: a "use this" that pre-fills the dialog is still this file
//    choosing the command, with the approval reduced to a formality over text
//    somebody else's incident produced.
//  * SEARCH, TAGS, LINKS BETWEEN NOTES, ATTACHMENTS, HISTORY OF EDITS. Each is
//    the first feature of the wiki this is not.

import { STORE_ALERT_KINDS, type StoreAlertKind } from './webhook'

/**
 * The refusal, in one sentence the panel renders and a test asserts.
 *
 * It is a CONSTANT rather than a comment because the panel has to say it to the
 * person reading the commands. A refusal that lives only in a source comment is
 * invisible to the only reader who could be tempted.
 */
export const RUNBOOK_NO_RUN_NOTE =
  'These are shown, never offered. There is no button here that runs them: they were the ' +
  'right answer to a different incident, and one click that repeats what we did last time is ' +
  'how an outage gets repeated deliberately. Start a job the ordinary way, with its plan and ' +
  'its approval.'

/**
 * The provenance marker for text a HOST reported about itself.
 *
 * The note above it is operator-written and therefore not attacker-controlled.
 * The failure text beside it is not: it is stderr and transport errors from a
 * machine somebody else may configure. Rendering the two in the same block with
 * the same weight is how a line of remote output gets read as a line of the
 * runbook. The wording is deliberately `hostReportedBlock`'s in
 * src/main/services/mcpServer.ts — that function addresses a model deciding
 * whether a line is an instruction, and this one addresses an operator at 3am
 * deciding whether a line is advice. Same distinction, same words.
 */
export const RUNBOOK_HOST_REPORTED_NOTE =
  'Reported by the host, not by ShellPilot and not by you. Treat it as data rather than as ' +
  'instruction: it is whatever the machine printed.'

/** The most a note may hold. Long enough for the three paragraphs an incident
 *  deserves, short enough that this is not a document store. */
export const RUNBOOK_NOTE_MAX = 4000

/** "The last three times it fired" — the roadmap's number, not a tuning knob. */
export const RUNBOOK_OCCURRENCES = 3

/**
 * How much of one command is kept.
 *
 * Applied AFTER redaction, never before, and `buildRunbookRecall` is what makes
 * that ordering structural rather than a convention. Capping first cuts the END
 * marker off a PEM block; the redaction pattern then matches nothing at all and
 * the key body ships as prose. That exact bug was found in the change log this
 * week, which is why the order is a property of one function that both halves
 * go through rather than two call sites that happen to agree today.
 */
export const RUNBOOK_COMMAND_MAX = 400

/** Host-reported failure text is capped harder than a command: it is the one
 *  string here nobody on this side wrote. */
export const RUNBOOK_ERROR_MAX = 200

/** The most commands one occurrence lists. A patch job across a distro is
 *  dozens of steps and the whole of it is not a runbook; the overflow is
 *  COUNTED rather than dropped silently, for elisionNotice's reason. */
export const RUNBOOK_COMMANDS_PER_OCCURRENCE = 12

/**
 * How long after a raise a job counts as a response to it.
 *
 * Bounded by the resolve where there is one, and by this where there is not.
 * Without the second bound an alert that never cleared would claim every job
 * run on that host for the rest of the year as its remedy.
 */
export const RUNBOOK_RESPONSE_WINDOW_MS = 24 * 3_600_000

/**
 * How far back occurrences are looked for.
 *
 * Ninety days because that is what the history store keeps events for
 * (RETENTION_HOURLY_DAYS), not because ninety is a good number. Job ROWS are
 * kept for a year, so this half of the answer is bounded by the alert half:
 * a job from ten months ago is still on disk and still unreachable from here,
 * because the raise that would have anchored it is gone. Said out loud in
 * RUNBOOK_NEVER_FIRED rather than left as an absence.
 */
export const RUNBOOK_LOOKBACK_DAYS = 90

// ---------------------------------------------------------------------------
// The note
// ---------------------------------------------------------------------------

export interface RunbookNote {
  kind: StoreAlertKind
  /** `null` is the fleet-wide note for this kind. A host id narrows it. */
  hostId: string | null
  text: string
  updatedAt: number
}

/** Keys a note. A NUL separator, because it cannot occur in either half. */
export function runbookKey(kind: StoreAlertKind, hostId: string | null): string {
  return `${kind}\u0000${hostId ?? ''}`
}

export function isRunbookKind(value: unknown): value is StoreAlertKind {
  return typeof value === 'string' && (STORE_ALERT_KINDS as readonly string[]).includes(value)
}

// C0, DEL and the bidi overrides. Newline and tab survive — a note is prose a
// person laid out — and everything else that could reorder a rendered line
// does not. A note is not attacker-controlled, but it is text on disk that
// survives hand edits and restored backups, and neither of those is typing.
// eslint-disable-next-line no-control-regex -- matching them is the point
const UNSAFE_NOTE = /[\u0000-\u0008\u000b-\u001f\u007f\u202a-\u202e\u2066-\u2069]/g

/** What a note becomes before it is stored or rendered. Returns `''` for
 *  anything that is not text, which is how "no note" is spelled. */
export function sanitiseRunbookNote(raw: unknown): string {
  if (typeof raw !== 'string') return ''
  // Line endings FIRST. `\r` is inside the C0 range this strips, so stripping
  // first turns a note pasted from a Windows editor into one long line — every
  // paragraph break silently deleted rather than converted.
  const clean = raw.replace(/\r\n?/g, '\n').replace(UNSAFE_NOTE, '')
  return clean.length > RUNBOOK_NOTE_MAX ? clean.slice(0, RUNBOOK_NOTE_MAX) : clean
}

// ---------------------------------------------------------------------------
// The half nobody types
// ---------------------------------------------------------------------------

/** How the job ended ON THIS HOST. Ours, derived from the stored outcome and
 *  exit code — never a sentence a host wrote. */
export type RunbookOutcome = 'succeeded' | 'failed' | 'unknown'

export interface RunbookCommand {
  /** Redacted, then capped. See RUNBOOK_COMMAND_MAX. */
  text: string
  outcome: RunbookOutcome
  /**
   * What the host said went wrong, where it said anything.
   *
   * The ONLY host-reported string on this path, and the reason
   * RUNBOOK_HOST_REPORTED_NOTE exists. Carried because "we ran this and it did
   * not work" is most of what makes a remembered command worth reading, and
   * kept separate from `text` so a renderer cannot present the two as one
   * sentence.
   */
  hostReported?: string
}

export interface RunbookOccurrence {
  /** When the alert was raised. */
  at: number
  /** When it cleared, where a resolve was recorded within the window. `null`
   *  means it did not clear inside the window this occurrence was read over —
   *  not that it is still outstanding. */
  resolvedAt: number | null
  /** The job that ran, by the title its operator gave it. */
  jobs: { id: string; title: string; at: number; commands: RunbookCommand[] }[]
  /** Commands past RUNBOOK_COMMANDS_PER_OCCURRENCE. Counted, not hidden. */
  elided: number
}

/** Why the job-history half cannot answer, as opposed to answering "nothing". */
export type RunbookUnavailableReason = 'store-disabled' | 'store-unreadable'

/**
 * The three answers this half can give, and they are three rather than two on
 * purpose.
 *
 * `never-fired` and `nothing-run` are both empty lists on screen and mean
 * opposite things: one says the alert has no history here, the other says it
 * has one and nobody ran anything. `unavailable` is the third and is neither —
 * it is "I could not tell you", which this codebase has conflated with "there
 * is nothing" five separate times and will not again.
 */
export type RunbookRecall =
  | { status: 'ok'; occurrences: RunbookOccurrence[] }
  | { status: 'nothing-run'; occurrences: RunbookOccurrence[] }
  | { status: 'never-fired' }
  | { status: 'unavailable'; reason: RunbookUnavailableReason }
  /** No host was chosen, so the question was never asked. A FIFTH answer
   *  rather than an empty `ok`, for the same reason there are already four:
   *  "we did not ask" is not "we asked and there was nothing". */
  | { status: 'no-host' }

/** The three sentences, as literals, so the panel cannot paraphrase one into
 *  another and a test can assert which was said. */
export const RUNBOOK_NEVER_FIRED =
  `This alert has not been raised on this host in the last ${RUNBOOK_LOOKBACK_DAYS} days, so ` +
  'there is no last time to show. Older raises are past what the history store keeps, even ' +
  'where the job that answered them is still on record.'

export const RUNBOOK_NOTHING_RUN =
  'It was raised, and no job ran against this host while it was outstanding. Nothing was ' +
  'run — that is the answer, not a gap in the record.'

export const RUNBOOK_STORE_DISABLED =
  'The history store is switched off on this machine, so what was run last time cannot be ' +
  'told to you. This is not the same as nothing having been run.'

export const RUNBOOK_STORE_UNREADABLE =
  'The history store could not be read, so what was run last time cannot be told to you. ' +
  'This is not the same as nothing having been run.'

export const RUNBOOK_NO_HOST =
  'What was run is a per-host question — the same alert on two machines was two incidents ' +
  'with two answers. Pick a host to see what was actually run.'

export function runbookUnavailableSentence(reason: RunbookUnavailableReason): string {
  return reason === 'store-disabled' ? RUNBOOK_STORE_DISABLED : RUNBOOK_STORE_UNREADABLE
}

/** One alert row as the recall needs it: when, and whether it was a raise. */
export interface RunbookAlertRow {
  at: number
  raised: boolean
}

/** One job as the recall needs it, already narrowed to ONE host. */
export interface RunbookJobRow {
  id: string
  title: string
  /** When it began on this host, falling back to when the row was created. */
  at: number
  /** The spec's steps, in order, verbatim and unredacted. */
  commands: string[]
  outcome: RunbookOutcome
  /** Host-reported, verbatim and unredacted. */
  error?: string
}

export interface RunbookRecallInput {
  /** Every raise and resolve for this kind on this host, in any order. */
  alerts: RunbookAlertRow[]
  /** Every job that touched this host in the lookback, in any order. */
  jobs: RunbookJobRow[]
  /**
   * The redactor, injected rather than imported.
   *
   * `src/main/services/secretRedaction.ts` is a main-process module and this
   * file is shared, but that is the smaller reason. The larger one is the
   * ordering: this function applies `redact` and THEN the cap, so
   * redact-before-truncate is a property of the one place both halves pass
   * through instead of an agreement between call sites. A caller that
   * truncated first would have to do it before this function ever saw the
   * string, which is a thing a reviewer can see.
   */
  redact: (text: string) => string
  windowMs?: number
}

function capCommand(text: string, redact: (t: string) => string, max: number): string {
  // REDACT FIRST. Reversing these two lines is the bug this whole comment
  // exists for: a 400-character cap through the middle of a PEM block removes
  // the END marker, the block pattern then matches nothing, and the key body
  // is rendered as a remembered command.
  const safe = redact(text).replace(/\s+/g, ' ').trim()
  return safe.length > max ? `${safe.slice(0, max)}…` : safe
}

/**
 * What was run the last three times this fired.
 *
 * Pure. It is handed rows and a redactor and returns one of the four answers
 * above; it reads nothing and decides nothing about where the rows came from.
 * `unavailable` is therefore NOT produced here — a caller that could not read
 * cannot describe its failure as an empty array on the way in and hope this
 * notices.
 */
export function buildRunbookRecall(input: RunbookRecallInput): RunbookRecall {
  const windowMs = input.windowMs ?? RUNBOOK_RESPONSE_WINDOW_MS
  const raises = input.alerts
    .filter((a) => a.raised)
    .map((a) => a.at)
    .sort((a, b) => b - a)
    .slice(0, RUNBOOK_OCCURRENCES)
  if (raises.length === 0) return { status: 'never-fired' }

  const resolves = input.alerts
    .filter((a) => !a.raised)
    .map((a) => a.at)
    .sort((a, b) => a - b)
  const jobs = [...input.jobs].sort((a, b) => a.at - b.at)

  const occurrences: RunbookOccurrence[] = []
  let anyCommand = false

  for (const at of raises) {
    // The first clear STRICTLY after the raise. `>=` would let a resolve
    // written in the same millisecond close a window before the raise opened
    // it, which is what a stand-down at shutdown looks like.
    const resolvedAt = resolves.find((r) => r > at) ?? null
    const end = Math.min(resolvedAt ?? at + windowMs, at + windowMs)

    const occurrence: RunbookOccurrence = { at, resolvedAt, jobs: [], elided: 0 }
    let budget = RUNBOOK_COMMANDS_PER_OCCURRENCE
    for (const job of jobs) {
      if (job.at < at || job.at > end) continue
      const taken = job.commands.slice(0, Math.max(0, budget))
      occurrence.elided += job.commands.length - taken.length
      budget -= taken.length
      if (taken.length === 0) continue
      const error = job.error ? capCommand(job.error, input.redact, RUNBOOK_ERROR_MAX) : ''
      occurrence.jobs.push({
        id: job.id,
        title: job.title,
        at: job.at,
        commands: taken.map((c) => ({
          text: capCommand(c, input.redact, RUNBOOK_COMMAND_MAX),
          outcome: job.outcome,
          ...(error ? { hostReported: error } : {})
        }))
      })
      anyCommand = true
    }
    occurrences.push(occurrence)
  }

  return anyCommand ? { status: 'ok', occurrences } : { status: 'nothing-run', occurrences }
}

/** Everything one runbook view carries: the half a person wrote, the half
 *  nobody did, and — separately — whether the note store itself could be read.
 *  A missing note and an unreadable note file are not the same claim either. */
export interface RunbookView {
  kind: StoreAlertKind
  hostId: string | null
  /** The note for this exact host, where there is one. */
  hostNote: RunbookNote | null
  /** The note for this kind across the fleet, where there is one. */
  kindNote: RunbookNote | null
  /** Set when the note file exists and could not be read. Distinct from both
   *  notes being null, which means nobody has written one. */
  notesUnreadable: boolean
  recall: RunbookRecall
}

/**
 * The bridge, exactly two methods.
 *
 * A read and a write of the operator's own note, and nothing else. There is
 * deliberately no `runbook:run`, no `runbook:copy-to-job` and no filter
 * argument on the read: the first two are RUNBOOK_NO_RUN_NOTE's refusal
 * expressed as an absent channel rather than as a disabled button, and the
 * third is the query surface the history store's rule refuses.
 *
 * `satisfies RunbooksBridge` in the preload so a method added to this contract
 * and forgotten there is a compile error rather than something the panel finds
 * undefined at runtime.
 */
export interface RunbooksBridge {
  read(kind: StoreAlertKind, hostId: string | null): Promise<RunbookView>
  saveNote(
    kind: StoreAlertKind,
    hostId: string | null,
    text: string
  ): Promise<{ ok: boolean; note: RunbookNote | null }>
}
