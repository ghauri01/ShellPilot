import {
  FACT_STATUS_HELP,
  factSource,
  type FactSourceId,
  type FactStatus,
  type HostFacts
} from '../../../shared/hostFacts'
import type { HostMetrics } from '../../../shared/ssh'
import { bytes } from './format'

// The estate inventory: every host, what it is, and what it needs.
//
// The table is the easy half. The hard half — and the entire reason this file
// exists rather than the panel formatting values inline — is that EVERY cell
// can be empty for a different reason, and those reasons must never collapse
// into a dash or a zero.
//
// `src/shared/hostFacts.ts` goes to considerable trouble to keep them apart on
// the way in: `unsupported` is a first-class status distinct from both 0 and
// not-checked, `denied` is distinct from `no-tool` is distinct from `absent`,
// and `stale-metadata` qualifies a number rather than replacing it. All of that
// is thrown away the moment a renderer writes `{facts.securityUpdates ?? '—'}`.
// So no component in this app formats a fact. It asks for a cell, and a cell
// carries either a value or a NAMED reason there is none.
//
// The distinction that matters most, stated once so it is not re-litigated per
// column: a user must be able to tell "this host has no security updates" from
// "this host cannot tell you whether it has security updates". The first is
// `0`. The second is `unsupported` and is rendered as words, never as a
// number, never as a dash, and never in the same visual register as a count.

// ---------------------------------------------------------------------------
// Gaps
// ---------------------------------------------------------------------------

/**
 * Why a cell has no value.
 *
 * The `FactStatus` values minus `ok` — those come off the collector and are
 * about a probe that ran — plus three this side owns, because they are about a
 * collection that did not happen at all:
 *
 *  - `not-collected`: the hourly facts probe has never produced an answer for
 *    this host. A server added ten minutes ago genuinely has none. This is not
 *    a failure and must not be dressed as one.
 *  - `probe-failed`: it ran and it failed. Different from the above, and
 *    different from the metrics error: a host can answer a metrics sample
 *    perfectly and still refuse this probe.
 *  - `not-sampled`: kernel and total RAM are NOT collected by the facts probe.
 *    They are on `HostMetrics` already and hostFacts.ts deliberately declines
 *    to collect them twice. A host with facts but no metrics sample therefore
 *    has a distro and no kernel, which is a real state and needs its own word.
 */
export type CellGap =
  | Exclude<FactStatus, 'ok'>
  | 'not-collected'
  | 'probe-failed'
  | 'not-sampled'

/**
 * What a gap is called in a table cell.
 *
 * Every one of these is a phrase rather than a symbol, on purpose. A dash is
 * read as "nothing", and "nothing" is the one meaning none of these has.
 * `unsupported` gets the least symbol-like phrasing of the lot because it is
 * the status a reader will not have seen before and the one most likely to be
 * mistaken for zero.
 */
export const GAP_LABEL: Record<CellGap, string> = {
  absent: 'not on this server',
  denied: 'not permitted',
  'no-tool': 'no tool for it',
  'stale-metadata': 'from a stale cache',
  unsupported: 'cannot be answered',
  unknown: 'unknown',
  'not-collected': 'not collected yet',
  'probe-failed': 'collection failed',
  'not-sampled': 'not sampled yet'
}

/** The sentence behind the phrase, shown on hover. The six that come off the
 *  collector reuse its own help strings rather than paraphrasing them. */
export const GAP_HELP: Record<CellGap, string> = {
  absent: FACT_STATUS_HELP.absent,
  denied: FACT_STATUS_HELP.denied,
  'no-tool': FACT_STATUS_HELP['no-tool'],
  'stale-metadata': FACT_STATUS_HELP['stale-metadata'],
  unsupported: FACT_STATUS_HELP.unsupported,
  unknown: FACT_STATUS_HELP.unknown,
  'not-collected':
    'Host facts have not been collected for this server yet. They are collected about once an hour, on the same background sweep as metrics, so a server added recently will not have any until that sweep reaches it.',
  'probe-failed':
    'The facts probe ran on this server and did not complete. A server can answer a metrics sample perfectly and still refuse this one, so this is reported separately from the server being reachable.',
  'not-sampled':
    'This value comes from the metrics sweep rather than the hourly facts probe, and this server has not been sampled yet.'
}

/**
 * The gaps a reader must not skim past.
 *
 * `unsupported` is here because reading it as zero is the failure the whole
 * item exists to prevent. `denied` is here because it is the one gap a person
 * can act on — a different account would see more.
 */
export function gapIsLoud(gap: CellGap): boolean {
  return gap === 'unsupported' || gap === 'denied'
}

// ---------------------------------------------------------------------------
// Cells
// ---------------------------------------------------------------------------

export interface InventoryCell {
  /** What to print. For a gap this is `GAP_LABEL[gap]` — never a dash, never
   *  an empty string, and never a number. */
  text: string
  /** null when `text` is a real value. */
  gap: CellGap | null
  /** The tooltip. For a gap: why, in the collector's own words where it had
   *  any. For a value: the extra precision a table cell has no room for. */
  help: string
  /**
   * The value is present and was read correctly, and the package cache behind
   * it has not been refreshed recently — so the number may be a confident lie.
   *
   * A separate flag rather than a gap, because that is what it is: the count is
   * still the best answer available and hiding it would be worse. It is
   * rendered NEXT TO the number it undermines rather than in a distant column,
   * for the obvious reason.
   */
  staleMetadata?: boolean
  /**
   * Sort key, or null when there is nothing to sort on.
   *
   * A gap is ALWAYS null here, including for `pendingUpdates`. Sorting an
   * unknown as 0 would put "we could not count the updates on this host" at
   * the top of an ascending sort, in among the hosts that genuinely have none
   * — which is the same lie as printing it as 0, told by position instead of
   * by text. See `compareRows`.
   */
  sort: number | string | null
}

const value = (text: string, sort: number | string, help = ''): InventoryCell => ({
  text,
  gap: null,
  help,
  sort
})

const missing = (gap: CellGap, detail?: string): InventoryCell => ({
  text: GAP_LABEL[gap],
  gap,
  // The collector's own words come first when it had any: "updateinfo returned
  // nothing while updates are pending" tells an operator far more than the
  // generic sentence, and the generic sentence is still there behind it.
  help: detail ? `${detail}. ${GAP_HELP[gap]}` : GAP_HELP[gap],
  sort: null
})

// ---------------------------------------------------------------------------
// Ages — two of them, and they are not the same thing
// ---------------------------------------------------------------------------

/**
 * A compact age, for a column that has to fit thirteen of its kind.
 *
 * `lib/format.ts`'s `duration()` is not reused here: it tops out at hours, so
 * package metadata refreshed forty days ago renders as "960h 0m". Forty days is
 * exactly the case this column exists to make obvious.
 */
export function compactAge(fromMs: number, now = Date.now()): string {
  const s = Math.max(0, Math.floor((now - fromMs) / 1000))
  if (s < 60) return `${s}s`
  const m = Math.floor(s / 60)
  if (m < 60) return `${m}m`
  const h = Math.floor(m / 60)
  if (h < 48) return `${h}h`
  return `${Math.floor(h / 24)}d`
}

/**
 * The honest rendering of both axes in one sentence, for a tooltip and for the
 * row summary.
 *
 * "collected 5 minutes ago, from metadata 40 days old" is the whole point:
 * merging the two into one age would let a fresh collection vouch for a stale
 * cache, which is precisely how "0 pending updates" becomes a lie.
 */
export function agesSentence(
  collectedAt: number | null,
  metadataAt: number | null,
  now = Date.now()
): string {
  const collected =
    collectedAt === null ? 'never collected' : `collected ${compactAge(collectedAt, now)} ago`
  const metadata =
    metadataAt === null
      ? 'and the age of the package metadata behind the counts is not known'
      : `from package metadata ${compactAge(metadataAt, now)} old`
  return `${collected}, ${metadata}`
}

// ---------------------------------------------------------------------------
// Columns
// ---------------------------------------------------------------------------

export type InventoryColumnId =
  | 'host'
  | 'distro'
  | 'kernel'
  | 'arch'
  | 'cpu'
  | 'ram'
  | 'virt'
  | 'pkg'
  | 'pending'
  | 'security'
  | 'reboot'
  | 'factsAge'
  | 'metadataAge'

export interface InventoryColumn {
  id: InventoryColumnId
  label: string
  /**
   * Shown without asking.
   *
   * Thirteen columns across fifteen hosts is not a table anyone reads, so the
   * split is by QUESTION rather than by width: what a host NEEDS is on screen,
   * what a host IS goes behind a disclosure. Package manager stays in the
   * default set despite being an "is" — it is the explanation for most of the
   * `cannot be answered` cells in the security column, and hiding the reason
   * while showing the gap is how a reader concludes the app is broken.
   */
  primary: boolean
  /** Right-aligned: counts and ages are read by comparing them down a column. */
  numeric?: boolean
  /** Column header tooltip, where the header alone understates it. */
  help?: string
}

export const INVENTORY_COLUMNS: InventoryColumn[] = [
  { id: 'host', label: 'Host', primary: true },
  { id: 'distro', label: 'Distribution', primary: true },
  { id: 'pkg', label: 'Packages', primary: true, help: 'The package manager this server uses.' },
  {
    id: 'pending',
    label: 'Updates',
    primary: true,
    numeric: true,
    help: 'Updates the local package cache knows about. ShellPilot never refreshes that cache — refreshing is a network operation and on some package managers it can break the server — so read this next to the metadata age.'
  },
  {
    id: 'security',
    label: 'Security',
    primary: true,
    numeric: true,
    help: 'Security updates specifically, where the distribution publishes them. Arch and Alpine have no security channel at all, and dnf cannot answer where the repositories omit updateinfo — those servers say so rather than reporting zero.'
  },
  { id: 'reboot', label: 'Reboot', primary: true },
  {
    id: 'factsAge',
    label: 'Collected',
    primary: true,
    numeric: true,
    help: 'How long ago these facts were collected. Facts are collected about once an hour, not on the two-minute metrics cadence.'
  },
  {
    id: 'metadataAge',
    label: 'Metadata',
    primary: true,
    numeric: true,
    help: 'How old the package cache behind the update counts is. This is a SECOND age and not the one above it: freshly collected counts read out of a forty-day-old cache are forty days out of date.'
  },
  { id: 'kernel', label: 'Kernel', primary: false },
  { id: 'arch', label: 'Arch', primary: false },
  { id: 'cpu', label: 'CPU', primary: false },
  { id: 'ram', label: 'RAM', primary: false, numeric: true },
  { id: 'virt', label: 'Virtualisation', primary: false }
]

// ---------------------------------------------------------------------------
// Rows
// ---------------------------------------------------------------------------

/** One server as the panel receives it: facts on their own clock, metrics on
 *  theirs, and either may be absent independently of the other. */
export interface InventoryInput {
  serverId: string
  serverName: string
  facts: HostFacts | null
  factsAt: number | null
  /** The facts probe ran and failed. Independent of the metrics error. */
  factsError: string | null
  metrics: HostMetrics | null
}

export interface InventoryRow {
  serverId: string
  serverName: string
  /** The host's own name for itself, when a metrics sweep has produced one. */
  hostname: string | null
  /** Both ages in one sentence, for the row's own tooltip. */
  ages: string
  cells: Record<InventoryColumnId, InventoryCell>
}

/** Bare metal is a real answer and `none` is a confusing way to print it. */
function virtText(v: string): string {
  return v === 'none' ? 'bare metal' : v
}

export function buildRow(input: InventoryInput, now = Date.now()): InventoryRow {
  const { facts, metrics } = input

  // The gap every facts-derived cell falls back to when there are no facts at
  // all. "Never ran" and "ran and failed" are different sentences and an
  // operator does different things about them.
  const noFacts: CellGap = input.factsError !== null ? 'probe-failed' : 'not-collected'
  const noFactsDetail = input.factsError ?? undefined

  /** The status the collector gave one source, or the whole-collection gap. */
  const from = (id: FactSourceId): { gap: CellGap; detail?: string } => {
    if (!facts) return { gap: noFacts, detail: noFactsDetail }
    const s = factSource(facts, id)
    // `ok` with a null value should be impossible — parseHostFacts downgrades
    // exactly that case to `unknown` — but a cell has to render something, and
    // `unknown` is the honest something.
    return { gap: s.status === 'ok' ? 'unknown' : s.status, detail: s.detail }
  }

  const factCell = (
    id: FactSourceId,
    v: string | number | null,
    text?: string,
    sort?: number | string
  ): InventoryCell => {
    if (v === null || v === '') {
      const { gap, detail } = from(id)
      return missing(gap, detail)
    }
    return value(text ?? String(v), sort ?? (typeof v === 'number' ? v : String(v).toLowerCase()))
  }

  // The package metadata's own status, which QUALIFIES the two counts rather
  // than replacing them. A stale cache does not stop `12 pending` being the
  // best answer available; it stops it being a current one.
  const metaStatus = facts ? factSource(facts, 'package-metadata').status : null
  const staleCounts = metaStatus === 'stale-metadata'
  const withStale = (c: InventoryCell): InventoryCell =>
    staleCounts && c.gap === null
      ? {
          ...c,
          staleMetadata: true,
          help: `${c.help ? `${c.help} ` : ''}${FACT_STATUS_HELP['stale-metadata']}`.trim()
        }
      : c

  const distro = ((): InventoryCell => {
    if (!facts) return missing(noFacts, noFactsDetail)
    const pretty = facts.prettyName
    const composed =
      facts.distroId === null
        ? null
        : `${facts.distroId}${facts.distroVersion ? ` ${facts.distroVersion}` : ''}`
    const text = pretty ?? composed
    if (text === null) {
      const { gap, detail } = from('os-release')
      return missing(gap, detail)
    }
    // Sorted on the allow-listed id where there is one, so `Ubuntu 24.04 LTS`
    // and `ubuntu` land together rather than under U and u.
    return value(text, facts.distroId ?? text.toLowerCase(), composed && pretty ? composed : '')
  })()

  const cells: Record<InventoryColumnId, InventoryCell> = {
    host: value(input.serverName, input.serverName.toLowerCase()),
    distro,
    // Kernel and RAM are on HostMetrics deliberately — hostFacts.ts declines to
    // collect them a second time — so their gap is about the METRICS sweep.
    kernel: metrics?.kernel
      ? value(metrics.kernel, metrics.kernel.toLowerCase())
      : missing('not-sampled'),
    arch: factCell('architecture', facts?.arch ?? null),
    cpu: factCell('cpu', facts?.cpuModel ?? null),
    ram:
      metrics && metrics.memTotal > 0
        ? value(bytes(metrics.memTotal), metrics.memTotal)
        : missing('not-sampled'),
    virt: factCell(
      'virtualisation',
      facts?.virtualisation ?? null,
      facts?.virtualisation ? virtText(facts.virtualisation) : undefined,
      facts?.virtualisation ?? undefined
    ),
    pkg: factCell('package-manager', facts?.packageManager ?? null),
    pending: withStale(factCell('updates', facts?.pendingUpdates ?? null)),
    security: withStale(factCell('security-updates', facts?.securityUpdates ?? null)),
    reboot: ((): InventoryCell => {
      if (!facts || facts.rebootRequired === null) {
        const { gap, detail } = from('reboot-required')
        return missing(gap, detail)
      }
      return facts.rebootRequired
        ? // Sorted so "yes" comes first ascending: the hosts owed a reboot are
          // the reason anyone sorts this column.
          value('yes', 0, facts.rebootReason ? `Waiting on: ${facts.rebootReason}` : '')
        : value('no', 1)
    })(),
    factsAge:
      input.factsAt === null
        ? missing(noFacts, noFactsDetail)
        : // Sorted on the AGE, not the timestamp, so ascending is "freshest
          // first" in both the numbers and the words.
          value(compactAge(input.factsAt, now), now - input.factsAt, new Date(input.factsAt).toLocaleString()),
    metadataAge: ((): InventoryCell => {
      if (!facts || facts.metadataAt === null) {
        const { gap, detail } = from('package-metadata')
        return missing(gap, detail)
      }
      const c = value(
        compactAge(facts.metadataAt, now),
        now - facts.metadataAt,
        new Date(facts.metadataAt).toLocaleString()
      )
      return staleCounts ? { ...c, staleMetadata: true, help: `${c.help}. ${FACT_STATUS_HELP['stale-metadata']}` } : c
    })()
  }

  return {
    serverId: input.serverId,
    serverName: input.serverName,
    hostname: metrics?.hostname || null,
    ages: agesSentence(input.factsAt, facts?.metadataAt ?? null, now),
    cells
  }
}

// ---------------------------------------------------------------------------
// Sorting
// ---------------------------------------------------------------------------

export type SortDirection = 'asc' | 'desc'

/**
 * Order two rows by one column.
 *
 * The decision worth stating: **a cell with no value sorts LAST in both
 * directions.** Not first, not as zero, not as the empty string.
 *
 * Sorting a gap as 0 is the same lie as printing it as 0, told by position
 * instead of by text — "we could not count the updates here" would sit at the
 * top of an ascending sort among the hosts that genuinely have none, which is
 * exactly the confusion this whole item exists to prevent. Sorting it first
 * descending is no better: it would top the "who needs patching most" list with
 * hosts nobody has an answer for.
 *
 * Last in both directions means a gap never occupies a position that implies a
 * magnitude. Reversing the sort reverses the hosts that HAVE answers and leaves
 * the ones that do not where they were, which is the honest behaviour: their
 * position carries no information, and it should not appear to.
 */
export function compareRows(
  a: InventoryRow,
  b: InventoryRow,
  column: InventoryColumnId,
  direction: SortDirection
): number {
  const av = a.cells[column].sort
  const bv = b.cells[column].sort
  if (av === null || bv === null) {
    if (av === null && bv === null) return a.serverName.localeCompare(b.serverName)
    // Not negated by `direction`. That is the whole point.
    return av === null ? 1 : -1
  }
  const c =
    typeof av === 'number' && typeof bv === 'number' ? av - bv : String(av).localeCompare(String(bv))
  // Name as the tiebreak, so the order of two hosts with the same value does
  // not move around under them as unrelated data updates.
  return (direction === 'asc' ? c : -c) || a.serverName.localeCompare(b.serverName)
}

export function sortRows(
  rows: InventoryRow[],
  column: InventoryColumnId,
  direction: SortDirection
): InventoryRow[] {
  return [...rows].sort((a, b) => compareRows(a, b, column, direction))
}

// ---------------------------------------------------------------------------
// The estate summary
// ---------------------------------------------------------------------------

/**
 * What the table adds up to, with the gaps counted rather than skipped.
 *
 * `securityUnanswerable` is not a rounding error in `securityTotal` — it is the
 * number that makes `securityTotal` readable at all. "31 security updates
 * across the estate" is a different claim when five hosts could never have
 * contributed to it, and the second number is the only thing that says so.
 */
export interface InventorySummary {
  hosts: number
  withFacts: number
  pendingTotal: number
  /** Hosts whose pending count could not be read at all. */
  pendingUnknown: number
  securityTotal: number
  /** Hosts that CAN NEVER report a security count. Never folded into a zero. */
  securityUnanswerable: number
  /** Hosts whose security count failed for some other reason. */
  securityUnknown: number
  rebootsOwed: number
  staleMetadata: number
}

export function summarise(rows: InventoryRow[]): InventorySummary {
  const s: InventorySummary = {
    hosts: rows.length,
    withFacts: 0,
    pendingTotal: 0,
    pendingUnknown: 0,
    securityTotal: 0,
    securityUnanswerable: 0,
    securityUnknown: 0,
    rebootsOwed: 0,
    staleMetadata: 0
  }
  for (const r of rows) {
    if (r.cells.factsAge.gap === null) s.withFacts++
    const p = r.cells.pending
    if (p.gap === null) s.pendingTotal += Number(p.sort)
    else s.pendingUnknown++
    const sec = r.cells.security
    if (sec.gap === null) s.securityTotal += Number(sec.sort)
    else if (sec.gap === 'unsupported') s.securityUnanswerable++
    else s.securityUnknown++
    if (r.cells.reboot.gap === null && r.cells.reboot.text === 'yes') s.rebootsOwed++
    if (p.staleMetadata || sec.staleMetadata) s.staleMetadata++
  }
  return s
}
