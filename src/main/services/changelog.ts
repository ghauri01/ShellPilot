import { app } from 'electron'
import { join } from 'node:path'
import { existsSync, openSync, readSync, closeSync, fstatSync } from 'node:fs'
import type { AuditEntry } from '../../shared/mcp'
import type { JobApprovalEntry } from '../../shared/jobs'
import type { LocalSessionEntry } from './localSessionLog'
import {
  CHANGELOG_FIELD_MAX,
  CHANGELOG_PAGE_LIMIT,
  CHANGELOG_SOURCES,
  CHANGELOG_SOURCE_LIMIT,
  CHANGELOG_TAIL_BYTES,
  compareChangeLogEntries,
  matchesChangeLogFilter,
  type ChangeLogCoverage,
  type ChangeLogEntry,
  type ChangeLogFilter,
  type ChangeLogPage,
  type ChangeLogSource
} from '../../shared/changelog'
import { redactOutput } from './secretRedaction'

// The reader half of roadmap item 14. src/shared/changelog.ts argues the shape;
// this file does the reading, and only the reading.
//
// FOUR SOURCES, NO FIFTH. Nothing here appends, rotates, migrates or copies.
// Every row below already exists on disk because something else wrote it for
// its own reasons, and this merges them for one page and forgets them.
//
// ---------------------------------------------------------------------------
// WHY THIS PARSES THE JSONL FILES ITSELF RATHER THAN CALLING listAudit()
// ---------------------------------------------------------------------------
// Two reasons, and the second is the one that decided it.
//
// FIRST, volume. `listAudit`, `listLocalSessions` and `listJobApprovals` all
// read the WHOLE file into a string and then keep its last 500 lines. Those
// three files have no retention pass — unlike the history store, which has two
// — so they grow for the life of the install. That is fine at a megabyte and
// is not fine later, and "do not read an unbounded number of rows to render a
// page" is a requirement of this item. This reads the last CHANGELOG_TAIL_BYTES
// of each instead.
//
// SECOND, honesty. All three existing readers skip a corrupt line and say
// nothing — correct for their own callers, who want the rest of the file, and
// insufficient here, where a skipped line is a hole in a timeline somebody is
// using to reconstruct an incident. The same skipping behaviour is preserved
// exactly (one bad line never costs the rest of the file); what is added is
// that the count comes back.
//
// The cost is a second place that knows these filenames. tests/changelog.test.ts
// asserts each literal against the source module that owns it, so the drift is
// caught rather than hoped against.

export const AUDIT_FILE = 'shellpilot-ai-audit.jsonl'
export const LOCAL_SESSION_FILE = 'shellpilot-local-sessions.jsonl'
export const APPROVAL_FILE = 'shellpilot-job-approvals.jsonl'

/** What a tail read produced. `null` from a TailReader means no such file,
 *  which is a different answer from an empty one. */
export interface TailRead {
  text: string
  /** Bytes before the window, i.e. the part of the record not read. */
  bytesUnread: number
}

export type TailReader = (path: string, maxBytes: number) => TailRead | null

/**
 * The slice of the durable store this view needs.
 *
 * Structural rather than `HistoryStore`, so nothing here depends on the store's
 * whole surface — and so a test can hand over four events without opening
 * sqlite. `readEvents` is the only method: job OUTPUT is reachable from the
 * store and is deliberately not asked for.
 */
export interface ChangeLogHistoryReader {
  readEvents(filter?: {
    from?: number
    to?: number
    limit?: number
    hostId?: string
  }): {
    ts: number
    kind: string
    hostId: string | null
    payload: unknown
    cursor: { ts: number; id: number }
  }[]
}

export interface ChangeLogDeps {
  /**
   * Whether the change log may read ANYTHING.
   *
   * Checked before a path is built, not after rows are gathered: the switch
   * governs the read, so an off switch must mean no file was opened rather
   * than a tab that is hidden. See the test that hands over a reader which
   * throws on call.
   */
  enabled: () => boolean
  /** Where the three JSONL files live. Defaults to userData. */
  dir?: string
  /** The durable store, or null when history is disabled or not yet open. */
  history: () => ChangeLogHistoryReader | null
  /** Server id -> display name, so a row can name a host rather than a uuid. */
  hostName?: (hostId: string) => string | null
  tail?: TailReader
}

// ---------------------------------------------------------------------------
// Reading
// ---------------------------------------------------------------------------

/**
 * The last `maxBytes` of a file, with the partial first line dropped.
 *
 * The window almost certainly starts mid-line and may start mid-UTF-8-sequence.
 * Both are handled by the same move: when the window did not start at byte 0,
 * everything up to and including the first newline is discarded. That is our
 * own cut rather than a corrupt record, so it is NOT counted as a skipped line
 * — miscounting it would put a permanent "1 line skipped" on every large file.
 */
export function tailFile(path: string, maxBytes: number): TailRead | null {
  if (!existsSync(path)) return null
  const fd = openSync(path, 'r')
  try {
    const size = fstatSync(fd).size
    const start = Math.max(0, size - maxBytes)
    const len = size - start
    const buf = Buffer.alloc(len)
    if (len > 0) readSync(fd, buf, 0, len, start)
    let text = buf.toString('utf8')
    if (start > 0) {
      const nl = text.indexOf('\n')
      text = nl === -1 ? '' : text.slice(nl + 1)
    }
    return { text, bytesUnread: start }
  } finally {
    closeSync(fd)
  }
}

/** JSON lines, oldest first, with the count of lines that would not parse.
 *  One bad line costs that line and nothing else — the behaviour all three
 *  existing readers already have, kept deliberately. */
function parseLines<T>(text: string): { rows: T[]; skipped: number } {
  const rows: T[] = []
  let skipped = 0
  for (const line of text.split('\n')) {
    if (!line.trim()) continue
    try {
      rows.push(JSON.parse(line) as T)
    } catch {
      skipped += 1
    }
  }
  return { rows, skipped }
}

/** Redact, THEN cap. The other order can cut a `KEY=value` in half and leave
 *  the value on screen looking like ordinary prose. */
function field(text: unknown): string {
  if (typeof text !== 'string') return ''
  const clean = redactOutput(text)
  return clean.length > CHANGELOG_FIELD_MAX ? `${clean.slice(0, CHANGELOG_FIELD_MAX)}…` : clean
}

function at(iso: unknown): number | null {
  if (typeof iso !== 'string') return null
  const ms = Date.parse(iso)
  return Number.isFinite(ms) ? ms : null
}

// ---------------------------------------------------------------------------
// Mapping each source into the one vocabulary
// ---------------------------------------------------------------------------

function fromLocalSessions(rows: LocalSessionEntry[]): ChangeLogEntry[] {
  const out: ChangeLogEntry[] = []
  for (const r of rows) {
    const ts = at(r?.timestamp)
    if (ts === null || typeof r.id !== 'string') continue
    const label = field(r.shellLabel) || 'a shell'
    const detail: string[] = []
    if (r.shellPath) detail.push(field(r.shellPath))
    if (r.cwd) detail.push(`in ${field(r.cwd)}`)
    if (typeof r.pid === 'number') detail.push(`pid ${r.pid}`)
    if (typeof r.exitCode === 'number') detail.push(`exit ${r.exitCode}`)
    if (typeof r.signal === 'number') detail.push(`signal ${r.signal}`)
    if (r.error) detail.push(field(r.error))
    const verb =
      r.event === 'started' ? 'started' : r.event === 'exited' ? 'exited' : 'would not start'
    out.push({
      id: `local:${r.id}`,
      source: 'local-shell',
      ts,
      actor: 'human',
      kind: 'shell',
      summary: `${label} ${verb} on this machine`,
      detail,
      hostId: null,
      hosts: []
    })
  }
  return out
}

function fromApprovals(rows: JobApprovalEntry[]): ChangeLogEntry[] {
  const out: ChangeLogEntry[] = []
  for (const r of rows) {
    const ts = at(r?.timestamp)
    if (ts === null || typeof r.id !== 'string') continue
    const hosts = Array.isArray(r.hosts) ? r.hosts.map((h) => field(h)).filter(Boolean) : []
    const detail = Array.isArray(r.commands) ? r.commands.map((c) => field(c)).filter(Boolean) : []
    if (r.reason) detail.push(field(r.reason))
    out.push({
      id: `approval:${r.id}`,
      source: 'approvals',
      ts,
      actor: 'human',
      kind: 'approval',
      summary: `${r.surface === 'broadcast' ? 'Broadcast' : 'Job'} ${field(r.event) || 'recorded'} — ${field(r.title) || 'untitled'}`,
      detail,
      hostId: null,
      hosts
    })
  }
  return out
}

function fromAudit(rows: AuditEntry[]): ChangeLogEntry[] {
  const out: ChangeLogEntry[] = []
  for (const r of rows) {
    const ts = at(r?.timestamp)
    if (ts === null || typeof r.id !== 'string') continue
    const detail: string[] = []
    // `action` is the command, already redacted by recordAudit at write time.
    // It is redacted again here rather than trusted: this reader is the thing
    // that puts it on a screen, and a row written by an older build went
    // through an older pattern list.
    if (r.action) detail.push(field(r.action))
    if (r.capability) detail.push(field(r.capability))
    detail.push(`approval: ${field(r.approval) || 'unknown'}`)
    detail.push(`result: ${field(r.result) || 'unknown'}`)
    if (typeof r.exitCode === 'number') detail.push(`exit ${r.exitCode}`)
    if (r.error) detail.push(field(r.error))
    out.push({
      id: `audit:${r.id}`,
      source: 'agent-audit',
      ts,
      actor: 'agent',
      kind: 'agent-action',
      summary: `${field(r.agentName) || 'An agent'} ran a ${field(r.capability) || 'bridge'} call`,
      detail,
      hostId: typeof r.serverId === 'string' ? r.serverId : null,
      hosts: r.serverName ? [field(r.serverName)] : []
    })
  }
  return out
}

/**
 * A history event's payload is `unknown` and is written by half a dozen call
 * sites. Only these keys are ever read, and only as scalars.
 *
 * Deliberately a whitelist rather than a stringify of the object. A payload
 * shape added next month reaches this view as its kind and its host and
 * nothing else, which is the failure direction that cannot leak.
 */
const PAYLOAD_KEYS = ['title', 'reason', 'error', 'jobId', 'wave', 'recovery'] as const

const EVENT_ACTOR: Record<string, 'human' | 'system'> = {
  'job-abandoned': 'human',
  'job-disposed': 'human',
  'job-ended': 'human',
  'job-gate': 'human'
}

const EVENT_KIND: Record<string, ChangeLogEntry['kind']> = {
  'job-abandoned': 'job',
  'job-disposed': 'job',
  'job-ended': 'job',
  'job-gate': 'job',
  'host-unreachable': 'host',
  'host-recovered': 'host',
  'history-recovery': 'store',
  'retention-skipped': 'store',
  'job-retention-skipped': 'store'
}

function fromHistory(
  rows: ReturnType<ChangeLogHistoryReader['readEvents']>,
  hostName: (id: string) => string | null
): ChangeLogEntry[] {
  const out: ChangeLogEntry[] = []
  for (const r of rows) {
    if (typeof r?.ts !== 'number' || typeof r.kind !== 'string') continue
    const detail: string[] = []
    const payload = r.payload
    if (payload && typeof payload === 'object') {
      for (const key of PAYLOAD_KEYS) {
        const v = (payload as Record<string, unknown>)[key]
        if (typeof v === 'string' && v) detail.push(`${key}: ${field(v)}`)
        else if (typeof v === 'number') detail.push(`${key}: ${v}`)
      }
    }
    const name = r.hostId ? hostName(r.hostId) : null
    out.push({
      id: `history:${r.cursor.id}`,
      source: 'history',
      ts: r.ts,
      // Unmapped kinds are `system`: a kind this build has never heard of was
      // not demonstrably a person's doing, and guessing `human` would put a row
      // nobody produced under "what I did".
      actor: EVENT_ACTOR[r.kind] ?? 'system',
      kind: EVENT_KIND[r.kind] ?? 'store',
      summary: r.kind,
      detail,
      hostId: r.hostId ?? null,
      hosts: name ? [field(name)] : []
    })
  }
  return out
}

// ---------------------------------------------------------------------------
// The read
// ---------------------------------------------------------------------------

interface SourceResult {
  entries: ChangeLogEntry[]
  coverage: ChangeLogCoverage
}

function offPage(): ChangeLogPage {
  return {
    enabled: false,
    entries: [],
    coverage: CHANGELOG_SOURCES.map((source) => ({ source, state: 'off' as const, entries: 0 })),
    oldest: null,
    more: false
  }
}

function readJsonlSource<T>(
  source: ChangeLogSource,
  path: string,
  tail: TailReader,
  map: (rows: T[]) => ChangeLogEntry[]
): SourceResult {
  let read: TailRead | null
  try {
    read = tail(path, CHANGELOG_TAIL_BYTES)
  } catch (err) {
    return {
      entries: [],
      // The message can name a path and, on some platforms, an errno string.
      // Redacted like every other free text that reaches this view.
      coverage: { source, state: 'unreadable', entries: 0, error: field(String(err)) }
    }
  }
  if (read === null) return { entries: [], coverage: { source, state: 'absent', entries: 0 } }

  const { rows, skipped } = parseLines<T>(read.text)
  const kept = rows.slice(-CHANGELOG_SOURCE_LIMIT)
  const rowsDropped = rows.length - kept.length
  const truncated = read.bytesUnread > 0 || rowsDropped > 0
  return {
    entries: map(kept),
    coverage: {
      source,
      state: truncated ? 'truncated' : skipped > 0 ? 'partial' : 'read',
      entries: 0,
      ...(skipped > 0 ? { skipped } : {}),
      ...(read.bytesUnread > 0 ? { bytesUnread: read.bytesUnread } : {}),
      ...(rowsDropped > 0 ? { rowsDropped } : {})
    }
  }
}

function readHistorySource(deps: ChangeLogDeps, filter: ChangeLogFilter): SourceResult {
  let store: ChangeLogHistoryReader | null
  try {
    store = deps.history()
  } catch (err) {
    return { entries: [], coverage: { source: 'history', state: 'unreadable', entries: 0, error: field(String(err)) } }
  }
  if (!store) return { entries: [], coverage: { source: 'history', state: 'absent', entries: 0 } }

  try {
    // Bounded by the same per-source cap the files get, and pushed DOWN into
    // the query rather than applied after: the store indexes on (ts, id) and
    // reading a year of events to show a day of them is the unbounded read
    // this item was told not to do.
    const rows = store.readEvents({
      limit: CHANGELOG_SOURCE_LIMIT,
      ...(filter.from === undefined ? {} : { from: filter.from }),
      ...(filter.to === undefined ? {} : { to: filter.to })
    })
    const name = deps.hostName ?? (() => null)
    return {
      entries: fromHistory(rows, name),
      coverage: {
        source: 'history',
        // Exactly `limit` rows back means the store had at least one more.
        state: rows.length >= CHANGELOG_SOURCE_LIMIT ? 'truncated' : 'read',
        entries: 0
      }
    }
  } catch (err) {
    return { entries: [], coverage: { source: 'history', state: 'unreadable', entries: 0, error: field(String(err)) } }
  }
}

/**
 * One page of the merged timeline.
 *
 * Never throws for a source it could not read: a source that fails becomes a
 * coverage row saying so, and the other three still render. A timeline that
 * refuses to draw because one file has the wrong permissions is a timeline
 * nobody can use during the incident it exists for.
 */
export function readChangeLog(deps: ChangeLogDeps, filter: ChangeLogFilter = {}): ChangeLogPage {
  if (!deps.enabled()) return offPage()

  const dir = deps.dir ?? app.getPath('userData')
  const tail = deps.tail ?? tailFile

  const sources: SourceResult[] = [
    readJsonlSource<LocalSessionEntry>('local-shell', join(dir, LOCAL_SESSION_FILE), tail, fromLocalSessions),
    readJsonlSource<JobApprovalEntry>('approvals', join(dir, APPROVAL_FILE), tail, fromApprovals),
    readJsonlSource<AuditEntry>('agent-audit', join(dir, AUDIT_FILE), tail, fromAudit),
    readHistorySource(deps, filter)
  ]

  const limit = filter.limit ?? CHANGELOG_PAGE_LIMIT
  const bySource = new Map<ChangeLogSource, ChangeLogEntry[]>()
  let hidUnattributed = 0
  const matched: ChangeLogEntry[] = []
  for (const s of sources) {
    for (const e of s.entries) {
      if (!matchesChangeLogFilter(e, filter)) {
        // A host filter hiding a row that names no host is the one exclusion
        // worth counting: jobs, approvals and store events are routinely
        // unattributed, and dropping them without a word is how a filtered
        // page claims a quiet afternoon.
        if (
          filter.hosts &&
          filter.hosts.length > 0 &&
          e.hostId === null &&
          e.hosts.length === 0 &&
          matchesChangeLogFilter(e, { ...filter, hosts: undefined })
        ) {
          hidUnattributed += 1
        }
        continue
      }
      matched.push(e)
    }
  }
  matched.sort(compareChangeLogEntries)
  const entries = matched.slice(0, Math.max(0, limit))
  for (const e of entries) {
    const list = bySource.get(e.source) ?? []
    list.push(e)
    bySource.set(e.source, list)
  }

  return {
    enabled: true,
    entries,
    coverage: sources.map((s) => ({
      ...s.coverage,
      entries: bySource.get(s.coverage.source)?.length ?? 0
    })),
    ...(hidUnattributed > 0 ? { hostFilterHidUnattributed: hidUnattributed } : {}),
    oldest: entries.length > 0 ? entries[entries.length - 1].ts : null,
    more: matched.length > entries.length
  }
}
