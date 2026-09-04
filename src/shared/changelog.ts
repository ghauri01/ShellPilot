// "What did I change on Tuesday." — roadmap item 14.
//
// One time-ordered view over four append-only records that until now never met.
// It is a READER and nothing else: no fifth store, no migration, no new writer.
// The four keep answering the questions they were built for, and this file is
// the vocabulary the merge is expressed in.
//
// ---------------------------------------------------------------------------
// WHY A VIEW AND NOT A FIFTH LOG
// ---------------------------------------------------------------------------
// The obvious build is a `changeLog.ts` beside the other three that everything
// calls. It was rejected for the reason approvalLog.ts is a third file rather
// than a second: each of the four exists because it answers a DIFFERENT
// question, and `shellpilot-ai-audit.jsonl` in particular derives its whole
// value from the sentence in docs/AI-SECURITY.md that says `recordAudit` is
// called from mcpServer.ts and nowhere else. A reader can trust every row in
// that file to be an agent's. Copying its rows into a fifth file would produce
// a second, staler answer to a question that already has a good one; adding a
// caller to it would break the sentence outright. So: read all four, merge,
// order, and say what could not be read.
//
// ---------------------------------------------------------------------------
// METADATA, NEVER CONTENT
// ---------------------------------------------------------------------------
// The roadmap is explicit and the reasoning survives restating. Full terminal
// output is enormous, it is full of secrets no redaction pass reliably catches,
// and a log of everything a person's shell printed is a more attractive target
// than most of what it was meant to protect. `localSessionLog.ts` already says
// exactly this at the top of itself.
//
// So a ChangeLogEntry carries commands and targets and never carries output.
// `detail` holds command text, host names and exit statuses — the things an
// operator needs to recognise a row a year later — and nothing that a host
// printed back. Item 20 made the stronger version of this argument about `.env`
// values and chose "the text never crosses" over "the text is redacted"; the
// reader follows that here by not asking the sources for output at all, rather
// than asking and then filtering. Job output lives in the history store under
// its own retention and this view does not read it.
//
// ---------------------------------------------------------------------------
// HONEST ABOUT COVERAGE
// ---------------------------------------------------------------------------
// A timeline that silently omits a source reads as "nothing happened", which is
// the worst thing a record of what you did can say. Every source therefore
// reports a ChangeLogCoverage row whether it succeeded or not, and the panel
// shows them above the timeline rather than beside it. The language is
// deliberately the shape of `alertCoverage.ts`: name what the source covers,
// then say what state it is in — never describe a capability from the switch
// that requests it.

export const CHANGELOG_SOURCES = ['local-shell', 'approvals', 'agent-audit', 'history'] as const
export type ChangeLogSource = (typeof CHANGELOG_SOURCES)[number]

/**
 * Who did it.
 *
 * Three and not two, which is a deliberate departure from "human vs agent".
 * A host that went unreachable at 03:00 and the retention pass that refused to
 * run against a wrong clock were nobody's doing, and filing them under `human`
 * would make "show me what I did" a lie in exactly the direction this feature
 * exists to prevent. Filtering to `human` therefore excludes them, and the
 * timeline says so rather than quietly dropping them.
 */
export type ChangeLogActor = 'human' | 'agent' | 'system'

export const CHANGELOG_KINDS = ['shell', 'approval', 'agent-action', 'job', 'host', 'store'] as const
export type ChangeLogKind = (typeof CHANGELOG_KINDS)[number]

export interface ChangeLogEntry {
  /** Unique within a page. Derived from the source row's own id, so the same
   *  row read twice is the same entry rather than a new one. */
  id: string
  source: ChangeLogSource
  /** Epoch milliseconds. The JSONL sources store ISO strings and the history
   *  store stores numbers; both are normalised here so one comparison orders
   *  the merged list. */
  ts: number
  actor: ChangeLogActor
  kind: ChangeLogKind
  /** One line. Metadata only. */
  summary: string
  /** Commands, targets and exit statuses — never output. Already redacted by
   *  whichever writer produced the row, and redacted again by the reader for
   *  the sources whose writers do not. */
  detail: string[]
  /** The server this is about, where the source knows an id. Null is common
   *  and means "not attributed to one host", not "the local machine". */
  hostId: string | null
  /** Display names, because a year later a uuid is not a host. A job or a
   *  broadcast has several; a local shell has none. */
  hosts: string[]
}

// ---------------------------------------------------------------------------
// Ordering
// ---------------------------------------------------------------------------

/** Fixed, so two rows sharing a millisecond order the same way on every read.
 *  The numbers themselves mean nothing beyond being distinct and stable. */
const SOURCE_RANK: Record<ChangeLogSource, number> = {
  'local-shell': 0,
  approvals: 1,
  'agent-audit': 2,
  history: 3
}

/**
 * Newest first, with every tie broken.
 *
 * A merge of four independent files produces same-millisecond collisions
 * routinely — a job approval and the job event it caused are written
 * microseconds apart and round to the same ISO millisecond. Sorting on `ts`
 * alone leaves those two in whatever order the source arrays happened to be
 * concatenated in, so the page reorders itself between reads for no reason a
 * user can see. `source` then `id` makes the order TOTAL rather than merely
 * stable: it does not depend on input order at all.
 */
export function compareChangeLogEntries(a: ChangeLogEntry, b: ChangeLogEntry): number {
  if (a.ts !== b.ts) return b.ts - a.ts
  if (a.source !== b.source) return SOURCE_RANK[a.source] - SOURCE_RANK[b.source]
  return a.id < b.id ? -1 : a.id > b.id ? 1 : 0
}

// ---------------------------------------------------------------------------
// Filters
// ---------------------------------------------------------------------------

export interface ChangeLogFilter {
  /** Inclusive epoch ms. */
  from?: number
  /** Inclusive epoch ms. */
  to?: number
  /** Server ids OR display names — the sources disagree about which they
   *  keep, and an operator picking a host from a list should not have to care
   *  which of the four wrote the row. */
  hosts?: string[]
  actors?: ChangeLogActor[]
  kinds?: ChangeLogKind[]
  limit?: number
}

/** Rows returned for one page. A view that wants more asks for an older
 *  window, rather than for a bigger number. */
export const CHANGELOG_PAGE_LIMIT = 200

/** Rows any ONE source may contribute before the merge. Four sources at this
 *  cap is the most that is ever parsed for a page, which is the bound the
 *  roadmap's "do not read an unbounded number of rows" asks for. */
export const CHANGELOG_SOURCE_LIMIT = 500

/**
 * Bytes read from the tail of a JSONL source.
 *
 * The three JSONL files grow without bound today — none of them has a
 * retention pass, unlike the history store. Reading one whole into a string to
 * keep its last 500 lines is what the existing readers do, and it is fine at
 * a megabyte and not fine at a gigabyte. This view reads the LAST window of
 * each file instead, and reports the bytes it did not read rather than
 * pretending the file starts there.
 */
export const CHANGELOG_TAIL_BYTES = 512 * 1024

/** The longest a single free-text field may be once it reaches the view.
 *  Redaction happens BEFORE this cap, never after: truncating first can cut a
 *  `KEY=value` in half and leave the value looking like ordinary prose. */
export const CHANGELOG_FIELD_MAX = 200

function hostMatches(entry: ChangeLogEntry, hosts: string[]): boolean {
  if (entry.hostId !== null && hosts.includes(entry.hostId)) return true
  return entry.hosts.some((h) => hosts.includes(h))
}

export function matchesChangeLogFilter(entry: ChangeLogEntry, filter: ChangeLogFilter): boolean {
  if (filter.from !== undefined && entry.ts < filter.from) return false
  if (filter.to !== undefined && entry.ts > filter.to) return false
  if (filter.actors && filter.actors.length > 0 && !filter.actors.includes(entry.actor)) return false
  if (filter.kinds && filter.kinds.length > 0 && !filter.kinds.includes(entry.kind)) return false
  if (filter.hosts && filter.hosts.length > 0 && !hostMatches(entry, filter.hosts)) return false
  return true
}

/**
 * Filter, order and cut one page.
 *
 * Pure, and separate from the reading, so the ordering rule above can be
 * argued with in a test that does not touch a filesystem.
 */
export function mergeChangeLog(
  entries: ChangeLogEntry[],
  filter: ChangeLogFilter = {}
): ChangeLogEntry[] {
  const limit = filter.limit ?? CHANGELOG_PAGE_LIMIT
  return entries
    .filter((e) => matchesChangeLogFilter(e, filter))
    .sort(compareChangeLogEntries)
    .slice(0, Math.max(0, limit))
}

// ---------------------------------------------------------------------------
// Coverage
// ---------------------------------------------------------------------------

export type ChangeLogSourceState =
  /** Read in full, within the window asked for. */
  | 'read'
  /** The switch is off. Nothing was opened. */
  | 'off'
  /** No such file, or the durable store is not open. Not the same as empty. */
  | 'absent'
  /** It exists and could not be read. */
  | 'unreadable'
  /** Read, but the window did not reach the start of the record. */
  | 'truncated'
  /** Read, but at least one line would not parse and was skipped. */
  | 'partial'

export interface ChangeLogCoverage {
  source: ChangeLogSource
  state: ChangeLogSourceState
  /** Rows this source actually contributed to the merged list, after the
   *  filter. Zero with state `read` genuinely means nothing happened. */
  entries: number
  /** Lines skipped for being unparseable, where that is known. */
  skipped?: number
  /** Bytes of older record the tail window did not reach. */
  bytesUnread?: number
  /** Rows the per-source cap dropped from inside the window that WAS read.
   *  Separate from `bytesUnread` because they are different cuts: one is the
   *  file window, the other is the row budget, and a source can hit both. */
  rowsDropped?: number
  /** The error, for `unreadable`. Redacted like everything else. */
  error?: string
}

/** What each source is a record OF. Shown whatever state it is in, because
 *  "history: unreadable" without this sentence does not tell an operator what
 *  they are missing. */
export const CHANGELOG_SOURCE_LABEL: Record<ChangeLogSource, string> = {
  'local-shell': 'Shells on this machine',
  approvals: 'What you confirmed',
  'agent-audit': 'What an agent did',
  history: 'Alerts, jobs and the store'
}

export const CHANGELOG_SOURCE_SCOPE: Record<ChangeLogSource, string> = {
  'local-shell':
    'which shells started and how they exited — never keystrokes, and never what a shell printed.',
  approvals:
    'what a human was asked before a job or a broadcast ran, and what they answered, with the commands as they were confirmed.',
  'agent-audit':
    'what an agent did through the MCP bridge. This is the one source here that is not yours, and it is shown so the timeline is not missing the half you did not do.',
  history:
    'alerts raised and resolved, jobs, and what the durable store did about its own retention. Job output is deliberately not read.'
}

const STATE_COPY: Record<ChangeLogSourceState, string> = {
  read: 'Read in full for this window.',
  off: 'Not read: the change log is switched off, so this source was not opened.',
  absent:
    'Nothing to read yet — this record does not exist on this machine. That is not the same as a quiet week, and it is shown rather than left as an empty stretch of timeline.',
  unreadable: 'Could NOT be read, so anything it holds is missing from the timeline below.',
  truncated:
    'Only the most recent part was read. Older entries exist and are NOT in the timeline below.',
  partial:
    'Read, except for lines that would not parse. Those were skipped; everything either side of them is here.'
}

/**
 * The sentence a coverage row shows.
 *
 * Built from the row rather than chosen by the panel, for the reason
 * `alertCoverage.ts` exists: a second copy of this wording next to the switch
 * is how a screen ends up describing a capability from the setting that
 * requests it instead of from what actually happened.
 */
export function changeLogCoverageText(row: ChangeLogCoverage): string {
  const parts = [`${CHANGELOG_SOURCE_LABEL[row.source]} — ${CHANGELOG_SOURCE_SCOPE[row.source]}`]
  parts.push(STATE_COPY[row.state])
  if (row.state === 'unreadable' && row.error) parts.push(row.error)
  if (row.skipped !== undefined && row.skipped > 0) {
    parts.push(`${row.skipped} unreadable ${row.skipped === 1 ? 'line was' : 'lines were'} skipped.`)
  }
  if (row.bytesUnread !== undefined && row.bytesUnread > 0) {
    parts.push(`${row.bytesUnread} older bytes were not read.`)
  }
  if (row.rowsDropped !== undefined && row.rowsDropped > 0) {
    parts.push(
      `${row.rowsDropped} older ${row.rowsDropped === 1 ? 'entry was' : 'entries were'} past this page's budget for one source.`
    )
  }
  return parts.join(' ')
}

/**
 * What the switch does and does not turn off.
 *
 * Stated because the switch governs a VIEW over records that four other things
 * write for their own reasons, and a person who turns it off is entitled to
 * know they have not stopped any of them. Turning off the recording of an
 * agent's actions, of local shells, or of approvals would break the guarantees
 * those three exist to provide, so this switch deliberately cannot.
 */
export const CHANGELOG_SWITCH_ON =
  'The change log reads four records that already exist and merges them into one timeline. ' +
  'It stores nothing of its own and writes nothing.'

export const CHANGELOG_SWITCH_OFF =
  'The change log is off, so nothing is read and no timeline is assembled. ' +
  'This does NOT stop anything being recorded: the agent audit log, the local session log, ' +
  'the approval log and the durable store all go on writing exactly as before, because each ' +
  'is relied on by something other than this view. Switching this off removes the timeline, ' +
  'not the records behind it.'

// ---------------------------------------------------------------------------
// The page, and the bridge that carries it
// ---------------------------------------------------------------------------

export interface ChangeLogPage {
  /** Whether the switch was on when this was read. False means `entries` is
   *  empty because nothing was opened — not because nothing happened. */
  enabled: boolean
  entries: ChangeLogEntry[]
  /** One row per source, always all four, whatever state each is in. */
  coverage: ChangeLogCoverage[]
  /** Set when a host filter was applied and rows attributed to no host were
   *  therefore hidden. Jobs, approvals and store events are frequently in that
   *  position, and dropping them silently is how a filtered timeline claims a
   *  quiet afternoon. */
  hostFilterHidUnattributed?: number
  /** The oldest entry returned, so a view can ask for the window before it
   *  rather than for a bigger limit. Null when the page is empty. */
  oldest: number | null
  /** True when the page was cut at `limit` and older entries matched. */
  more: boolean
}

/** The preload surface, defined here so the panel and the handler cannot
 *  disagree about it. */
export interface ChangeLogBridge {
  read(filter?: ChangeLogFilter): Promise<ChangeLogPage>
}
