// What is scheduled across the estate.
//
// Read-only, deliberately and for a while. Cron is a format with more traps
// than it looks, and every one of them is a silent misread rather than an
// error: a system crontab has a user field that a user crontab does not, so
// parsing one as the other attributes `root` to the wrong command and shifts
// the whole command left by a word. Writing on top of a parser that has not
// been proven against real files is how a scheduler eats a job.
//
// So this parses, labels what it could not parse, and never claims more than
// it knows. `description: null` means "this is a valid schedule I will not
// pretend to describe" — better than a confident sentence about the wrong time.

// `resolveBinary` and `SUDO_PROBE` are the Docker module's, deliberately not
// re-derived here. Both encode a fact about the environment rather than
// anything about Docker — that `ssh host cmd` gets a non-login PATH of roughly
// /usr/bin:/bin, and that `sudo -n` is the only escalation that cannot prompt —
// and a second copy of either is a second thing to drift.
import { SUDO_PROBE, resolveBinary } from './docker'

export type CronSourceKind =
  | 'user-crontab'
  | 'system-crontab'
  | 'cron.d'
  | 'systemd-timer'
  /**
   * Another account's crontab, read out of the spool directory.
   *
   * A sysadmin asking "what is scheduled on this box" means root's crontab at
   * least as much as their own, and `crontab -l` cannot answer that: it reads
   * exactly one account's file. The spool is normally root-only, so this source
   * exists or does not depending on whether root can be reached without a
   * password — which is why its status is reported rather than its absence
   * being quietly folded into "nothing scheduled".
   */
  | 'other-user-crontab'

export interface CronEntry {
  kind: CronSourceKind
  /** The file or unit this came from. */
  origin: string
  /** The schedule as written, with runs of whitespace collapsed to one space. */
  schedule: string
  /** Plain English, or null when we decline to guess. */
  description: string | null
  /** Who it runs as. null when the format does not say. */
  user: string | null
  /**
   * What cron actually runs, byte for byte: internal spacing preserved and
   * `\%` unescaped to `%`, which is what the shell will see.
   */
  command: string
  /**
   * Text after the first unescaped `%`, which cron feeds to the command on
   * stdin rather than running. Absent when the command has none.
   */
  input?: string
  /** systemd timers only. */
  nextRun?: string
  lastRun?: string
  /**
   * The line this came from, `\r` stripped and trimmed, exactly as the parser
   * saw it.
   *
   * Absent on a systemd timer, which is not a line in a file and has nothing to
   * point at — and that absence is the edit half's answer to "can this be
   * changed" as much as the source kind is.
   *
   * It exists because a job's IDENTITY has to survive a round trip through the
   * renderer and back. An index into a list does not: the list on screen was
   * read minutes ago and the file may have moved under it, and an index that
   * still resolves against a changed file resolves to the wrong job silently.
   */
  line?: string
}

export interface CronParseResult {
  entries: CronEntry[]
  /** Lines that looked like jobs but did not parse, kept verbatim. */
  unparsed: { origin: string; line: string }[]
}

// ---- Did we actually read it? -----------------------------------------
//
// The bug this fixes, found on a real host: `crontab -l 2>/dev/null || true`
// and `cat /etc/crontab 2>/dev/null || true` produce EXACTLY the same output —
// nothing — whether the file was empty, absent, unreadable, or the binary was
// not installed at all. Four different answers, one rendering: "Nothing
// scheduled."
//
// Three of those four are lies, and the worst is the third. /etc/cron.d is
// commonly root-only, so an operator looking at a fully loaded box is shown an
// empty schedule and has no reason to doubt it. A monitor that cannot tell
// "there is nothing here" from "I was not allowed to look" is worse than no
// monitor, because it is trusted.
//
// So every source now reports what happened to it, and the panel says how much
// of the picture it actually has.

/** The five places a scheduled job can live, each read independently. */
export type CronSourceId =
  | 'user-crontab'
  | 'system-crontab'
  | 'cron.d'
  | 'other-crontabs'
  | 'systemd-timers'

export type CronSourceStatus =
  /** Read it. An empty result here really does mean nothing is scheduled. */
  | 'ok'
  /** Some of it was read and some was refused — cron.d with mixed modes. */
  | 'partial'
  /** It is genuinely not on this host: no /etc/crontab, no crontab for this user. */
  | 'absent'
  /** It exists and this user may not read it. Root did not help, or was not available. */
  | 'denied'
  /** The tool that reads it is not installed, or systemd is not running here. */
  | 'no-tool'
  /** Something else happened, or the collector never reported on this source. */
  | 'unknown'

export interface CronSourceReport {
  id: CronSourceId
  /** What to call it on screen. */
  label: string
  status: CronSourceStatus
  /** Read as root after the unprivileged attempt was refused. Never silent. */
  usedSudo?: boolean
  /** The collector's own words, when it had any. */
  detail?: string
}

/** A collection, plus how much of it we were actually allowed to see. */
export interface CronCollection extends CronParseResult {
  sources: CronSourceReport[]
}

export const CRON_SOURCE_LABEL: Record<CronSourceId, string> = {
  'user-crontab': 'crontab -l',
  'system-crontab': '/etc/crontab',
  'cron.d': '/etc/cron.d',
  'other-crontabs': 'other users’ crontabs',
  'systemd-timers': 'systemd timers'
}

/**
 * What a status means for the completeness of the list.
 *
 * `no-tool` and `absent` are complete answers: a host with no systemd has no
 * systemd timers, and that is a fact rather than a gap. `denied`, `partial` and
 * `unknown` are gaps, and the panel must say so.
 */
export const CRON_STATUS_HELP: Record<CronSourceStatus, string> = {
  ok: 'read in full',
  partial: 'only partly readable — some files were refused',
  absent: 'not present on this server',
  denied: 'exists, but this account may not read it (and root was not available without a password)',
  'no-tool': 'nothing here can schedule a job — the tool that would read it is not installed or not running',
  unknown: 'the collector did not report on this source'
}

const CRON_SOURCE_IDS: CronSourceId[] = [
  'user-crontab',
  'system-crontab',
  'cron.d',
  'other-crontabs',
  'systemd-timers'
]

const CRON_STATUSES: CronSourceStatus[] = ['ok', 'partial', 'absent', 'denied', 'no-tool', 'unknown']

/**
 * How much of a host's schedule this collection actually represents.
 *
 * `answered` deliberately counts `absent` and `no-tool`: those are answers, not
 * gaps. Counting them as failures would make every minimal container look
 * half-read and train people to ignore the number — the same "cries wolf"
 * failure the broadcast risk classifier is built to avoid.
 */
export function summariseCronSources(sources: CronSourceReport[]): {
  total: number
  answered: number
  incomplete: CronSourceReport[]
  usedSudo: boolean
} {
  const incomplete = sources.filter(
    (s) => s.status === 'denied' || s.status === 'partial' || s.status === 'unknown'
  )
  return {
    total: sources.length,
    answered: sources.length - incomplete.length,
    incomplete,
    usedSudo: sources.some((s) => s.usedSudo)
  }
}

const DOW = ['Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday']
const MONTHS = ['January', 'February', 'March', 'April', 'May', 'June', 'July', 'August', 'September', 'October', 'November', 'December']

// The three-letter names cron accepts, in the two fields that accept them.
// Cron compares them case-insensitively, so `JAN`, `Jan` and `jan` are one
// thing, as are `MON`, `Mon` and `mon`.
const MONTH_ABBR = ['jan', 'feb', 'mar', 'apr', 'may', 'jun', 'jul', 'aug', 'sep', 'oct', 'nov', 'dec']
const DOW_ABBR = ['sun', 'mon', 'tue', 'wed', 'thu', 'fri', 'sat']

const SPECIALS: Record<string, string> = {
  '@reboot': 'at boot',
  '@yearly': 'once a year, at midnight on 1 January',
  '@annually': 'once a year, at midnight on 1 January',
  '@monthly': 'at midnight on the 1st of each month',
  '@weekly': 'at midnight on Sunday',
  '@daily': 'at midnight every day',
  '@midnight': 'at midnight every day',
  '@hourly': 'at the top of every hour'
}

/**
 * An environment assignment, not a job.
 *
 * `MAILTO=""` and `PATH=/usr/bin` are legal crontab lines that carry no
 * schedule. Parsing them as jobs is the mistake that produces a "job" whose
 * command is empty and whose schedule is nonsense.
 */
function isAssignment(line: string): boolean {
  return /^[A-Za-z_][A-Za-z0-9_]*\s*=/.test(line)
}

// ---- Field validation --------------------------------------------------
//
// A field is a comma-separated list of items, each `*`, a number, a range or a
// name, optionally followed by `/step`. Minute, hour and day-of-month are
// numeric only; month and day-of-week also take names.
//
// Deliberately a split-and-test rather than one regex over the whole field.
// The regex this replaces —
//   /^(\*|\d+)([-,\/]\d+)*(,\d+([-\/]\d+)?)*$/
// — had two adjacent stars that could both match `,N`, so a *failing* field
// cost O(n²) backtracking: a 20k-character first word took 6.5 seconds on this
// machine. The parser runs that against the first five words of every line of
// every file it reads, most of which are not cron at all. Splitting on `,`
// first makes the work linear and each item's regex unambiguous.
const NUMERIC_ITEM = /^(?:\*|\d{1,4}(?:-\d{1,4})?)(?:\/\d{1,4})?$/
const NAMED_ITEM = /^(?:\*|(?:\d{1,4}|[A-Za-z]{3})(?:-(?:\d{1,4}|[A-Za-z]{3}))?)(?:\/\d{1,4})?$/

const namesValid = (item: string, abbr: string[]): boolean =>
  item
    .split('/')[0]
    .split('-')
    .every((part) => part === '*' || /^\d+$/.test(part) || abbr.includes(part.toLowerCase()))

const isNumericField = (field: string): boolean =>
  field !== '' && field.split(',').every((i) => NUMERIC_ITEM.test(i))

const isNamedField = (field: string, abbr: string[]): boolean =>
  field !== '' && field.split(',').every((i) => NAMED_ITEM.test(i) && namesValid(i, abbr))

const isCronFieldSet = (f: string[]): boolean =>
  f.length === 5 &&
  isNumericField(f[0]) &&
  isNumericField(f[1]) &&
  isNumericField(f[2]) &&
  isNamedField(f[3], MONTH_ABBR) &&
  isNamedField(f[4], DOW_ABBR)

// ---- Describing a schedule --------------------------------------------

interface Unit {
  /** How a single value reads: "minute 5", "on Monday". */
  one: string
  /** How a step reads: "every 5 minutes". */
  many: string
  names?: string[]
  abbr?: string[]
}

function label(v: string, u: Unit): string {
  if (!u.names) return v
  if (u.abbr) {
    const i = u.abbr.indexOf(v.toLowerCase())
    if (i !== -1) return u.names[i] ?? v
  }
  const n = Number(v)
  if (!Number.isInteger(n)) return v
  // Cron months are 1-based (1 = January); days of the week are 0-based on
  // Sunday, with 7 accepted as Sunday too.
  return u.names === MONTHS ? (MONTHS[n - 1] ?? v) : (u.names[n % u.names.length] ?? v)
}

/** One comma-separated item, or null if we will not describe it. */
function describeItem(item: string, u: Unit): string | null {
  const [range, step, ...extraSteps] = item.split('/')
  if (extraSteps.length > 0) return null
  const known = (v: string): boolean => /^\d+$/.test(v) || (u.abbr?.includes(v.toLowerCase()) ?? false)

  if (range === '*') return step ? `every ${step} ${u.many}` : null
  const [from, to, ...extra] = range.split('-')
  if (extra.length > 0) return null
  if (!known(from) || (to !== undefined && !known(to))) return null
  if (to === undefined) {
    // `N/S` means "from N to the end of the field, every S", and the end of the
    // field depends which field it is. Declining beats guessing.
    return step ? null : `${u.one} ${label(from, u)}`
  }
  return step
    ? `every ${step} ${u.many} from ${label(from, u)} to ${label(to, u)}`
    : `${u.one} ${label(from, u)} to ${label(to, u)}`
}

function describeField(value: string, u: Unit): string | null {
  const items = value.split(',')
  const bare = (v: string): boolean => /^\d+$/.test(v) || (u.abbr?.includes(v.toLowerCase()) ?? false)

  // `0,15,30,45` is one list of values, not four separate clauses. Naming the
  // unit once reads as the crontab does; repeating it gives "minute 0, minute
  // 15, minute 30, minute 45".
  if (items.every(bare)) return `${u.one} ${items.map((v) => label(v, u)).join(', ')}`

  const parts: string[] = []
  for (const item of items) {
    const d = describeItem(item, u)
    if (d === null) return null
    parts.push(d)
  }
  return parts.join(', ')
}

/**
 * Plain English for a five-field schedule, or null.
 *
 * Returns null generously. A wrong description of when a job runs is worse
 * than none — someone reads "every day at 3am", does not check, and the job
 * has been running every minute for a month.
 */
export function describeSchedule(schedule: string): string | null {
  const s = schedule.trim()
  if (s.startsWith('@')) return SPECIALS[s.toLowerCase()] ?? null

  const f = s.split(/\s+/)
  if (f.length !== 5) return null
  const [min, hour, dom, mon, dow] = f

  // The common, unambiguous shapes get a real sentence; anything else falls
  // through to the field-by-field walk, and then to null.
  if (/^\d+$/.test(min) && /^\d+$/.test(hour) && dom === '*' && mon === '*' && dow === '*') {
    return `at ${hour.padStart(2, '0')}:${min.padStart(2, '0')} every day`
  }
  if (/^\d+$/.test(min) && /^\d+$/.test(hour) && dom === '*' && mon === '*' && /^\d$/.test(dow)) {
    return `at ${hour.padStart(2, '0')}:${min.padStart(2, '0')} every ${DOW[Number(dow) % 7]}`
  }
  const everyMin = min.match(/^\*\/(\d+)$/)
  if (everyMin && hour === '*' && dom === '*' && mon === '*' && dow === '*') {
    return `every ${everyMin[1]} minutes`
  }
  if (min === '*' && hour === '*' && dom === '*' && mon === '*' && dow === '*') return 'every minute'
  if (/^\d+$/.test(min) && hour === '*' && dom === '*' && mon === '*' && dow === '*') {
    return `at ${min} minutes past every hour`
  }
  if (/^\d+$/.test(min) && /^\d+$/.test(hour) && /^\d+$/.test(dom) && mon === '*' && dow === '*') {
    return `at ${hour.padStart(2, '0')}:${min.padStart(2, '0')} on day ${dom} of each month`
  }

  // Every non-* field must be describable. The earlier version described the
  // fields it understood and silently skipped the one it did not, so
  // `0 0 1-7 * 1#2` came back as "minute 0, hour 0, day 1 to 7" — a confident
  // sentence omitting the part that decides when it actually runs.
  const fields: [string, Unit][] = [
    [min, { one: 'minute', many: 'minutes' }],
    [hour, { one: 'hour', many: 'hours' }],
    [dom, { one: 'day', many: 'days' }],
    [mon, { one: 'month', many: 'months', names: MONTHS, abbr: MONTH_ABBR }],
    [dow, { one: 'on', many: 'days of the week', names: DOW, abbr: DOW_ABBR }]
  ]
  const parts: string[] = []
  for (const [value, u] of fields) {
    if (value === '*') continue
    const d = describeField(value, u)
    if (d === null) return null
    parts.push(d)
  }
  return parts.length ? parts.join(', ') : null
}

// ---- Commands, and the percent rule -----------------------------------

/**
 * Split a crontab command at the percent sign.
 *
 * This is the trap nobody remembers. In a crontab an unescaped `%` is *not*
 * part of the command: cron replaces it with a newline, and everything from the
 * first one onwards is fed to the command on stdin instead of being run. `\%`
 * is a literal percent.
 *
 * `date +\%Y\%m\%d` is in a large fraction of real crontabs, and reporting it
 * verbatim shows a command that is not the one that runs. It is worse the other
 * way round: `mail -s nightly root%Subject: x%body` reads as one long command,
 * when cron runs only `mail -s nightly root`.
 */
export function splitCronCommand(raw: string): { command: string; input?: string } {
  const unescapeInto = (from: number, newlines: boolean): { text: string; stoppedAt: number } => {
    let text = ''
    let i = from
    for (; i < raw.length; i++) {
      if (raw[i] === '\\' && raw[i + 1] === '%') {
        text += '%'
        i++
        continue
      }
      if (raw[i] === '%') {
        if (!newlines) break
        text += '\n'
        continue
      }
      text += raw[i]
    }
    return { text, stoppedAt: i }
  }

  const head = unescapeInto(0, false)
  if (head.stoppedAt >= raw.length) return { command: head.text }
  return { command: head.text, input: unescapeInto(head.stoppedAt + 1, true).text }
}

/** Tokens plus their offsets, so the command can be sliced out of the original
 *  line with its own spacing intact rather than rebuilt from a join. */
function tokenize(line: string): { text: string; start: number }[] {
  const out: { text: string; start: number }[] = []
  const re = /\S+/g
  for (let m = re.exec(line); m !== null; m = re.exec(line)) {
    out.push({ text: m[0], start: m.index })
  }
  return out
}

/**
 * How a job line is laid out, in the bytes the file actually has.
 *
 * Every whitespace run is kept as its own field rather than collapsed, because
 * the edit half rebuilds a line out of these and "our idea of tidy" is a diff
 * nobody can review. Debian's /etc/crontab separates its fields with tabs; a
 * hand-maintained crontab is usually aligned into columns. Both survive an edit
 * to a neighbouring part of the same line.
 */
interface CronLineLayout {
  /** cronie's syslog-suppressing `-`, present or not. */
  dash: string
  /** The schedule exactly as written, tabs and all. */
  scheduleRaw: string
  /** The whitespace between the schedule and whatever comes next. */
  gap: string
  /** The user column, on the files that have one. */
  user: string | null
  /** The whitespace after the user column. Empty when there is no user. */
  userGap: string
  /** Everything after that, byte for byte — command, percent rule and all. */
  rest: string
}

/**
 * Split one already-cleaned crontab line into its parts, or refuse.
 *
 * `null` means "this is not a job", which is the same judgement the read half
 * has always made — it is now made in exactly one place, so that the write half
 * cannot disagree with the read half about what a line is. A disagreement there
 * is a file we would rewrite around a line we misread.
 */
function layoutJobLine(line: string, hasUserField: boolean): CronLineLayout | null {
  // cronie lets a job be prefixed with `-` to suppress its syslog line. It is
  // a logging flag, not part of the schedule, and cronie is the cron on every
  // Red Hat derivative — so a `-` line is a real job, not a broken one.
  const dash = line.startsWith('-') ? '-' : ''
  const body = line.slice(dash.length)

  let scheduleRaw: string
  let gap: string
  let rest: string
  if (body.startsWith('@')) {
    const m = body.match(/^(@\S+)(\s+)(.*)$/)
    // An unknown `@word` is not a schedule any cron accepts — vixie and
    // cronie implement exactly the eight in SPECIALS — so the job never runs.
    // Listing `@every_minute` as scheduled is the same lie as dropping it.
    if (!m || !(m[1].toLowerCase() in SPECIALS)) return null
    scheduleRaw = m[1]
    gap = m[2]
    rest = m[3]
  } else {
    const tok = tokenize(body)
    if (tok.length < (hasUserField ? 7 : 6) || !isCronFieldSet(tok.slice(0, 5).map((t) => t.text))) {
      return null
    }
    const endOfFive = tok[4].start + tok[4].text.length
    scheduleRaw = body.slice(0, endOfFive)
    gap = body.slice(endOfFive, tok[5].start)
    // Sliced, not joined. Debian's /etc/crontab separates its fields with
    // tabs and real commands contain runs of whitespace — `run-parts` lines,
    // quoted arguments, aligned `&&` chains. `f.slice(5).join(' ')` collapsed
    // all of it and printed a command that is not the one on disk.
    rest = body.slice(tok[5].start)
  }

  let user: string | null = null
  let userGap = ''
  if (hasUserField) {
    const m = rest.match(/^(\S+)(\s+)(.*)$/)
    if (!m) return null
    user = m[1]
    userGap = m[2]
    rest = m[3]
  }

  // Note what is *not* done here: a trailing `# comment` is left in the
  // command, because cron leaves it there too. `#` starts a comment only at
  // the beginning of a line, so `0 3 * * * /x # nightly` runs a shell command
  // ending in `# nightly` — stripping it would show a command that is not the
  // one that runs.
  if (splitCronCommand(rest).command.trim() === '') return null
  return { dash, scheduleRaw, gap, user, userGap, rest }
}

/** The layout's schedule with runs of whitespace collapsed, as `CronEntry` wants it. */
const collapse = (s: string): string => s.trim().split(/\s+/).join(' ')

function entryFromLayout(
  l: CronLineLayout,
  origin: string,
  kind: CronSourceKind
): CronEntry {
  const schedule = collapse(l.scheduleRaw)
  const { command, input } = splitCronCommand(l.rest)
  return {
    kind,
    origin,
    schedule,
    description: describeSchedule(schedule),
    user: l.user,
    command,
    ...(input === undefined ? {} : { input })
  }
}

/**
 * Parse a crontab file.
 *
 * `hasUserField` is the whole difficulty. /etc/crontab and /etc/cron.d put a
 * user between the schedule and the command; a user's own crontab does not.
 * Guessing wrong does not error — it silently reports the first word of the
 * command as the user and drops it from the command, which is a plausible
 * looking lie. The caller knows which file it read, so the caller says.
 *
 * A thin wrapper over `parseCrontabDocument` since the edit half arrived: two
 * parsers over one format is two parsers to disagree, and the disagreement
 * would be invisible until a write went out around a line one of them misread.
 */
export function parseCrontab(
  text: string,
  origin: string,
  kind: CronSourceKind,
  hasUserField: boolean
): CronParseResult {
  const { entries, unparsed } = parseCrontabDocument(text, origin, kind, hasUserField)
  return { entries, unparsed }
}

// ---- systemd timers ----------------------------------------------------

const TIMER_DAY = /^[A-Za-z]{3}$/
const TIMER_DATE = /^\d{4}-\d{2}-\d{2}$/
const TIMER_TIME = /^\d{2}:\d{2}:\d{2}$/
// `UTC`, `CEST`, `+0530`. Deliberately upper-case-only and never digit-led, so
// it cannot swallow the first token of the LEFT column, which is always lower
// case (`5h`, `week`, `left`) or a placeholder.
const TIMER_ZONE = /^([A-Z]{2,5}|[+-]\d{2}:?\d{0,2})$/
const TIMER_ABSENT = /^(n\/a|-|\*)$/

/** The NEXT and LAST columns, read out of the tokens before the unit name. */
function timerDates(prefix: string[]): { next?: string; last?: string } {
  const found: string[] = []
  for (let i = 0; i < prefix.length; i++) {
    if (!TIMER_DATE.test(prefix[i])) continue
    const parts: string[] = []
    if (i > 0 && TIMER_DAY.test(prefix[i - 1])) parts.push(prefix[i - 1])
    parts.push(prefix[i])
    if (TIMER_TIME.test(prefix[i + 1] ?? '')) {
      parts.push(prefix[i + 1])
      if (TIMER_ZONE.test(prefix[i + 2] ?? '')) parts.push(prefix[i + 2])
    }
    found.push(parts.join(' '))
  }
  if (found.length >= 2) return { next: found[0], last: found[1] }
  if (found.length === 1) {
    // One date, two columns that could hold it. A row whose first token is a
    // placeholder has no next elapse, so the date must be LAST; otherwise the
    // date is NEXT and it is LAST that is missing.
    return TIMER_ABSENT.test(prefix[0] ?? '') ? { last: found[0] } : { next: found[0] }
  }
  return {}
}

/**
 * Parse `systemctl list-timers --all --no-pager`.
 *
 * The columns are NEXT, LEFT, LAST, PASSED, UNIT, ACTIVATES, and both the dates
 * and the durations contain spaces, so neither counting fields nor splitting on
 * runs of whitespace works.
 *
 * Splitting on `\s{2,}` — which is what this used to do — looks right, because
 * systemd pads its columns. It isn't: the *widest* cell in a column is followed
 * by exactly one space. So the moment any timer on the host is a week out,
 *
 *     Tue 2026-09-08 06:00:00 UTC  1 week 2 days left Mon 2026-09-01 ...
 *
 * LEFT runs straight into LAST on a single space, the columns shift by one, and
 * `lastRun` comes back as `18h ago` — the PASSED column. A plausible looking
 * string in the wrong field is the worst kind of wrong.
 *
 * So this anchors on shapes instead: the unit token ends in `.timer`, and a
 * date is recognisable as `Day YYYY-MM-DD HH:MM:SS TZ` wherever it happens to
 * sit. Absent values are `n/a` on older systemd and `-` since v250, which is
 * most of what `--all` adds.
 */
export function parseSystemdTimers(text: string): CronParseResult {
  const entries: CronEntry[] = []
  const unparsed: { origin: string; line: string }[] = []

  for (const raw of text.split('\n')) {
    const line = raw.replace(/\r/g, '').trim()
    if (line === '') continue
    if (/^(NEXT|UNIT|LEFT)\b/.test(line)) continue
    if (/timers listed/.test(line) || /^Pass --all/.test(line)) continue

    const tokens = line.split(/\s+/)
    const ti = tokens.findIndex((t) => t.endsWith('.timer'))
    const activates = ti === -1 ? '' : tokens.slice(ti + 1).join(' ')
    if (ti === -1 || activates === '') {
      // A timer line we cannot split is reported rather than dropped: a
      // silently missing timer is a scheduled job nobody knows about.
      if (line.includes('.timer')) unparsed.push({ origin: 'systemd', line })
      continue
    }

    const { next, last } = timerDates(tokens.slice(0, ti))
    entries.push({
      kind: 'systemd-timer',
      origin: tokens[ti],
      schedule: 'systemd timer',
      description: null,
      user: null,
      command: activates,
      nextRun: next,
      lastRun: last
    })
  }
  return { entries, unparsed }
}

// ---- Collecting ---------------------------------------------------------

/**
 * Where per-user crontabs live, most specific first.
 *
 * Debian and Ubuntu use the `crontabs` subdirectory; Red Hat derivatives, Arch
 * and SUSE put the files straight into /var/spool/cron. Both exist on Debian —
 * /var/spool/cron is the parent — so the order matters: picking the parent
 * would find no files and report an empty spool on a host full of them.
 */
const SPOOL_DIRS = ['/var/spool/cron/crontabs', '/var/spool/cron']

export interface CronCollectOptions {
  /**
   * Retry an unreadable source as root. On by default.
   *
   * Safe on by default for exactly the reason the Docker reader gives: the
   * retry is `sudo -n`, which NEVER prompts. It either works, because this
   * account already has passwordless sudo — a decision made on that host, by
   * whoever set it up, not one taken here — or it fails instantly. It cannot
   * hang an exec waiting for a tty that is not there.
   *
   * Worth retrying at all because /etc/cron.d and the crontab spool are
   * commonly root-only, so without it the honest answer on a hardened host is
   * "denied" for half the sources — correct, but useless when root was one
   * `sudo -n` away.
   *
   * Every source that used it says so, and the panel shows it. Reading files as
   * root silently would be the wrong trade even when it is the only way to get
   * an answer.
   */
  sudo?: boolean
}

/**
 * The command that collects everything, in one round trip.
 *
 * Each section is fenced with a marker so the parser knows which file each
 * block came from — and therefore whether it has a user field.
 *
 * The important change from the first version: every read now says what
 * happened to it, in a `===SHELLPILOT-STATUS===` block at the end. Before, a
 * missing `crontab` binary, an unreadable /etc/crontab and an empty crontab
 * were all "no output", and the panel rendered all three as "Nothing
 * scheduled." Two of those three were lies, and on a host whose /etc/cron.d is
 * root-only — which is normal — it was lying about the busiest file on the box.
 *
 * The status block is accumulated in a shell variable and printed at the end
 * rather than interleaved, so that nothing read out of a *file* can end up in
 * it. A crontab containing a line that looks like a status line cannot forge
 * one.
 *
 * Failure is still contained per source. There is no `set -e`, every read is
 * inside a conditional or ends in `|| true`, and the script's last command is a
 * `printf` — so a host with no /etc/cron.d, no systemd and no crontab binary
 * still returns every other section and exits 0.
 */
export function buildCronCollectCommand(opts: CronCollectOptions = {}): string {
  const sudo = opts.sudo !== false
  // Omitted entirely rather than left in place behind `[ "$SP_SUDO" = 1 ]`.
  // A dead branch would never run, but "this command contains no sudo at all"
  // is a property somebody can check by reading it, and a runtime guard is
  // not.
  const ifSudo = (...lines: string[]): string[] => (sudo ? lines : [])
  // The same probe the Docker reader uses, for the same reason: `sudo -n`
  // never prompts, so asking whether root is available cannot hang and cannot
  // consume a cached sudo timestamp interactively. Asked ONCE, up front, rather
  // than per file — a `sudo -n` that fails is a sudoers violation, and on a
  // host where this account has no sudo at all, one per file would mail root a
  // small pile of them on every refresh.
  const probe = sudo
    ? `SP_SUDO=0\n[ "$(${SUDO_PROBE})" = SP_SUDO_OK ] && SP_SUDO=1`
    : 'SP_SUDO=0'

  return [
    // A literal newline in a variable, so statuses can be accumulated one per
    // line. `$(printf ...)` cannot be used for this: command substitution
    // strips trailing newlines, which is the entire content here.
    "SP_NL='\n'",
    'SP_STATUS=""',
    'sp_note() { SP_STATUS="$SP_STATUS$*$SP_NL"; }',
    probe,

    // `ssh host cmd` runs a NON-LOGIN shell, so PATH is roughly /usr/bin:/bin.
    // `crontab` is nearly always in /usr/bin, but a busybox or minimal image
    // may not have it at all — and "no crontab binary" and "an empty crontab"
    // produced identical output before this.
    resolveBinary('crontab'),
    'SP_CRONTAB=""',
    'command -v "$SP_BIN" >/dev/null 2>&1 && SP_CRONTAB="$SP_BIN"',
    resolveBinary('systemctl'),
    'SP_SYSTEMCTL=""',
    'command -v "$SP_BIN" >/dev/null 2>&1 && SP_SYSTEMCTL="$SP_BIN"',

    'echo "===SHELLPILOT-USER==="',
    'if [ -z "$SP_CRONTAB" ]; then',
    'sp_note user-crontab no-tool - "this server has no crontab command"',
    'elif SP_OUT=$("$SP_CRONTAB" -l 2>/dev/null); then',
    `printf '%s\\n' "$SP_OUT"`,
    'sp_note user-crontab ok -',
    'else',
    // Non-zero from `crontab -l` is overwhelmingly "no crontab for <user>",
    // which is `absent` and completely normal. Anything else is not, and
    // saying which is the whole point of this block.
    'SP_ERR=$("$SP_CRONTAB" -l 2>&1 >/dev/null || true)',
    'case "$SP_ERR" in',
    '*"no crontab for"*) sp_note user-crontab absent - ;;',
    `*) sp_note user-crontab unknown - "$(printf '%s' "$SP_ERR" | tr '\\n' ' ')" ;;`,
    'esac',
    'fi',

    'echo "===SHELLPILOT-SYSTEM==="',
    'if [ ! -e /etc/crontab ]; then',
    'sp_note system-crontab absent -',
    'elif [ -r /etc/crontab ] && cat /etc/crontab 2>/dev/null; then',
    'sp_note system-crontab ok -',
    ...ifSudo(
      'elif [ "$SP_SUDO" = 1 ] && sudo -n cat /etc/crontab 2>/dev/null; then',
      'sp_note system-crontab ok root'
    ),
    'else',
    'sp_note system-crontab denied -',
    'fi',

    'echo "===SHELLPILOT-CROND==="',
    'SP_OK=0',
    'SP_DENIED=0',
    'SP_USED=-',
    'if [ ! -d /etc/cron.d ]; then',
    'sp_note cron.d absent -',
    'elif [ -r /etc/cron.d ] && [ -x /etc/cron.d ]; then',
    'for f in /etc/cron.d/*; do',
    '[ -f "$f" ] || continue',
    // Captured into a variable and re-printed with exactly one trailing
    // newline, rather than `cat` straight to stdout. Plenty of packaged
    // /etc/cron.d files ship without a final newline, and `cat a` followed by
    // the marker for b glues them: a's last job grows a `#FILE:/etc/cron.d/b`
    // tail on its command, and every job in b gets filed under a — where
    // nobody looking at b will ever find it.
    'if SP_TXT=$(cat "$f" 2>/dev/null); then',
    `printf '#FILE:%s\\n%s\\n' "$f" "$SP_TXT"`,
    'SP_OK=$((SP_OK+1))',
    ...ifSudo(
      'elif [ "$SP_SUDO" = 1 ] && SP_TXT=$(sudo -n cat "$f" 2>/dev/null); then',
      `printf '#FILE:%s\\n%s\\n' "$f" "$SP_TXT"`,
      'SP_OK=$((SP_OK+1))',
      'SP_USED=root'
    ),
    'else',
    'SP_DENIED=$((SP_DENIED+1))',
    'fi',
    'done',
    // Counted, so "read 3 of 5 files" can be said out loud. A directory where
    // one file is 0600 root is the case that used to silently vanish.
    'if [ "$SP_DENIED" -gt 0 ] && [ "$SP_OK" -gt 0 ]; then',
    'sp_note cron.d partial "$SP_USED" "read $SP_OK of $((SP_OK+SP_DENIED)) files"',
    'elif [ "$SP_DENIED" -gt 0 ]; then',
    'sp_note cron.d denied - "$SP_DENIED file(s) could not be read"',
    'else',
    'sp_note cron.d ok "$SP_USED"',
    'fi',
    // The directory itself unreadable. The glob above would have expanded to
    // the literal pattern, matched nothing, and reported an empty cron.d.
    ...ifSudo(
      `elif [ "$SP_SUDO" = 1 ] && SP_TXT=$(sudo -n sh -c 'for f in /etc/cron.d/*; do [ -f "$f" ] || continue; SP_T=$(cat "$f"); printf "#FILE:%s\\n%s\\n" "$f" "$SP_T"; done' 2>/dev/null); then`,
      `printf '%s\\n' "$SP_TXT"`,
      'sp_note cron.d ok root "the directory is readable only by root"'
    ),
    'else',
    'sp_note cron.d denied - "the directory is readable only by root"',
    'fi',

    // Other accounts' crontabs. `crontab -l` reads exactly one account's file,
    // and it is not usually the interesting one: root's is.
    'echo "===SHELLPILOT-SPOOL==="',
    `SP_ME=$(id -un 2>/dev/null || echo "")`,
    // Emitted so the parser can drop our own file rather than listing every
    // job in `crontab -l` a second time under a different heading.
    `printf '#SELF:%s\\n' "$SP_ME"`,
    'SP_OK=0',
    'SP_DENIED=0',
    'SP_USED=-',
    'SP_DIR=""',
    `for d in ${SPOOL_DIRS.join(' ')}; do`,
    '[ -d "$d" ] || continue',
    'SP_DIR="$d"',
    'break',
    'done',
    'if [ -z "$SP_DIR" ]; then',
    'sp_note other-crontabs absent - "no per-user crontab spool on this server"',
    'elif [ -r "$SP_DIR" ] && [ -x "$SP_DIR" ]; then',
    'for f in "$SP_DIR"/*; do',
    '[ -f "$f" ] || continue',
    'if SP_TXT=$(cat "$f" 2>/dev/null); then',
    `printf '#FILE:%s\\n%s\\n' "$f" "$SP_TXT"`,
    'SP_OK=$((SP_OK+1))',
    ...ifSudo(
      'elif [ "$SP_SUDO" = 1 ] && SP_TXT=$(sudo -n cat "$f" 2>/dev/null); then',
      `printf '#FILE:%s\\n%s\\n' "$f" "$SP_TXT"`,
      'SP_OK=$((SP_OK+1))',
      'SP_USED=root'
    ),
    'else',
    'SP_DENIED=$((SP_DENIED+1))',
    'fi',
    'done',
    'if [ "$SP_DENIED" -gt 0 ] && [ "$SP_OK" -gt 0 ]; then',
    'sp_note other-crontabs partial "$SP_USED" "read $SP_OK of $((SP_OK+SP_DENIED)) crontabs"',
    'elif [ "$SP_DENIED" -gt 0 ]; then',
    'sp_note other-crontabs denied - "$SP_DENIED crontab(s) could not be read"',
    'else',
    'sp_note other-crontabs ok "$SP_USED"',
    'fi',
    // The normal case on Debian: the spool is mode 1730 root:crontab, so an
    // ordinary account cannot even list it. Without root there is genuinely
    // nothing to report here, and `denied` says so rather than implying root
    // has no jobs.
    // The spool directory is passed as an ARGUMENT, not interpolated: inside
    // the single-quoted script the outer shell's `$SP_DIR` would stay literal
    // and the inner shell's would be unset, so the loop would read nothing and
    // this branch would silently report success over an empty result.
    ...ifSudo(
      `elif [ "$SP_SUDO" = 1 ] && SP_TXT=$(sudo -n sh -c 'for f in "$1"/*; do [ -f "$f" ] || continue; SP_T=$(cat "$f"); printf "#FILE:%s\\n%s\\n" "$f" "$SP_T"; done' sh "$SP_DIR" 2>/dev/null); then`,
      `printf '%s\\n' "$SP_TXT"`,
      'sp_note other-crontabs ok root "the spool is readable only by root"'
    ),
    'else',
    'sp_note other-crontabs denied - "the spool is readable only by root"',
    'fi',

    'echo "===SHELLPILOT-TIMERS==="',
    'if [ -z "$SP_SYSTEMCTL" ]; then',
    'sp_note systemd-timers no-tool - "this server has no systemctl"',
    'elif SP_TXT=$("$SP_SYSTEMCTL" list-timers --all --no-pager 2>&1); then',
    `printf '%s\\n' "$SP_TXT"`,
    'sp_note systemd-timers ok -',
    'else',
    // systemctl installed but PID 1 is not systemd — every Docker image built
    // FROM a distro base, and most LXC containers. Reported as `no-tool`
    // because the conclusion is the same and it is not a gap in the reading:
    // there are no systemd timers here to miss.
    'case "$SP_TXT" in',
    '*"not been booted"*|*"Failed to connect"*|*"Failed to get D-Bus"*|*"Refusing to operate"*)',
    'sp_note systemd-timers no-tool - "systemctl is installed but systemd is not running here" ;;',
    `*) sp_note systemd-timers unknown - "$(printf '%s' "$SP_TXT" | tr '\\n' ' ')" ;;`,
    'esac',
    'fi',

    'echo "===SHELLPILOT-STATUS==="',
    `printf '%s' "$SP_STATUS"`
  ].join('\n')
}

/**
 * The default collection: everything, with a passwordless-root retry.
 *
 * Kept as a constant because the caller has no decision to make here — the
 * retry cannot prompt, and the alternative is reporting `denied` for sources
 * that were one `sudo -n` away.
 */
export const CRON_COLLECT_COMMAND = buildCronCollectCommand()

/**
 * One `<id> <status> <root|-> <detail...>` line from the status block.
 *
 * The third column says who did the reading. It is spelled `root` rather than
 * `sudo` so that the one rule worth grepping the whole command for — that every
 * escalation in it is `sudo -n`, which cannot prompt — has no false positives
 * to argue with.
 */
function parseStatusLine(line: string): CronSourceReport | null {
  const [id, status, readBy, ...rest] = line.trim().split(/\s+/)
  if (!CRON_SOURCE_IDS.includes(id as CronSourceId)) return null
  const detail = rest.join(' ').replace(/^"|"$/g, '').trim()
  return {
    id: id as CronSourceId,
    label: CRON_SOURCE_LABEL[id as CronSourceId],
    // An unrecognised status is reported as unknown rather than passed
    // through: the panel switches on this, and a value outside the union
    // would render as nothing at all.
    status: CRON_STATUSES.includes(status as CronSourceStatus) ? (status as CronSourceStatus) : 'unknown',
    ...(readBy === 'root' ? { usedSudo: true } : {}),
    ...(detail === '' || detail === '-' ? {} : { detail })
  }
}

/**
 * Split the collector's output and parse each section with the right rules.
 *
 * Sources the status block did not mention come back as `unknown` rather than
 * being left out of the list. The output is capped by the transport, so a host
 * with an enormous cron.d can lose the tail — including the status block — and
 * a list that quietly shrank to four sources would read as complete.
 */
export function parseCronCollection(output: string): CronCollection {
  const section = (name: string): string => {
    // `\r?` because a transport that hands back CRLF would otherwise miss every
    // marker and report an entirely empty estate — a host with nothing
    // scheduled and a host we failed to read look identical from here.
    const m = output.match(new RegExp(`===SHELLPILOT-${name}===\\r?\\n([\\s\\S]*?)(?====SHELLPILOT-|$)`))
    return m ? m[1] : ''
  }

  const entries: CronEntry[] = []
  const unparsed: { origin: string; line: string }[] = []
  const take = (r: CronParseResult): void => {
    entries.push(...r.entries)
    unparsed.push(...r.unparsed)
  }

  const reported = new Map<CronSourceId, CronSourceReport>()
  for (const line of section('STATUS').split('\n')) {
    if (line.trim() === '') continue
    const s = parseStatusLine(line)
    if (s) reported.set(s.id, s)
  }
  const sources: CronSourceReport[] = CRON_SOURCE_IDS.map(
    (id) =>
      reported.get(id) ?? {
        id,
        label: CRON_SOURCE_LABEL[id],
        status: 'unknown' as const,
        detail: 'the collector did not report on this source'
      }
  )

  take(parseCrontab(section('USER'), 'crontab -l', 'user-crontab', false))
  take(parseCrontab(section('SYSTEM'), '/etc/crontab', 'system-crontab', true))

  // Many files in one blob, fenced by #FILE: markers the collector wrote.
  // Attributing an entry to the wrong file makes it unfindable.
  const byFile = (
    text: string,
    fallback: string,
    kind: CronSourceKind,
    hasUserField: boolean,
    userFromFile = false,
    skip?: string
  ): void => {
    let current = fallback
    let buffer: string[] = []
    const flush = (): void => {
      const owner = current.slice(current.lastIndexOf('/') + 1)
      if (buffer.length && !(skip !== undefined && skip !== '' && owner === skip)) {
        const r = parseCrontab(buffer.join('\n'), current, kind, hasUserField)
        // A spool file has no user column — the FILENAME is the user. Reading
        // one as a system crontab would take the first word of every command
        // and report it as the account, which is a plausible-looking lie.
        take(userFromFile ? { ...r, entries: r.entries.map((e) => ({ ...e, user: owner })) } : r)
      }
      buffer = []
    }
    for (const line of text.split('\n')) {
      const m = line.replace(/\r/g, '').match(/^#FILE:(.*)$/)
      if (m) {
        flush()
        current = m[1].trim()
      } else buffer.push(line)
    }
    flush()
  }

  byFile(section('CROND'), '/etc/cron.d', 'cron.d', true)

  // Our own spool file, if we could read it, is the same jobs `crontab -l`
  // already returned. Listed twice it looks like the job is scheduled twice.
  // Only skipped when the user crontab was actually read — if that source came
  // back `no-tool`, the spool copy is the only copy there is.
  const spool = section('SPOOL')
  const self = spool.match(/^#SELF:(.*)$/m)?.[1].trim() ?? ''
  const userRead = reported.get('user-crontab')?.status === 'ok'
  byFile(
    spool.replace(/^#SELF:.*$/m, ''),
    'crontab spool',
    'other-user-crontab',
    false,
    true,
    userRead ? self : undefined
  )

  take(parseSystemdTimers(section('TIMERS')))
  return { entries, unparsed, sources }
}

// ===========================================================================
// EDITING — roadmap item 6e
// ===========================================================================
//
// Read-only shipped first so the parser could be proven before anything wrote,
// and that sequencing paid: two silent misreads turned up in those tests — a
// six-word English sentence parsed as a job, and a schedule described by the
// fields it understood while skipping the one that decided when the job ran.
//
// What that leaves is a narrower problem than it looks, and a harder one.
//
// ROUND-TRIPPING A FILE WE DID NOT WRITE IS THE WHOLE PROBLEM. Comments, blank
// lines, MAILTO=, PATH=, SHELL=, syntax this parser does not know, and the
// operator's own column alignment all have to come out the other side byte for
// byte. A crontab rewritten into our idea of tidy produces a diff nobody can
// review, on a file that decides what runs unattended.
//
// So the model here is a DOCUMENT, not a list of jobs: every line of the file
// is kept exactly as written, along with its own line terminator, and an edit
// replaces one line and nothing else. `serialiseCrontabDocument` of an
// untouched document is the input, byte for byte, including CRLF, including a
// missing final newline.
//
// AND A BAD WRITE IS A SILENT OUTAGE. The job stops running and nothing says
// so — no error, no log line, nothing to notice until the backup that did not
// happen is needed. Which is why the rules below are refusals rather than
// best-effort:
//
//   - never write a file we could not fully parse. One unparsed line and the
//     whole file is off limits, because that line is the one we are most likely
//     to be wrong about the position of.
//   - never write a source the read half reported `partial`. Half a file is not
//     a file.
//   - never write a source we do not fully support. Named refusals only; a
//     partial capability that looks total is worse than a narrow one that says
//     so.
//   - never write a line we cannot parse back into exactly what was asked for.

/** What a line in a crontab is, as far as this parser is concerned. */
export type CronDocLineKind = 'blank' | 'comment' | 'assignment' | 'job' | 'unparsed'

export interface CronDocLine {
  kind: CronDocLineKind
  /** The line exactly as written, without its terminator. */
  text: string
  /**
   * The terminator exactly as written: `\n`, `\r\n`, or `''` on a final line
   * that has none. Carried per line rather than per file because a file with
   * mixed endings is a real thing and normalising it would be a diff.
   */
  eol: string
  /** The job this line produced, on `job` lines only. */
  entry?: CronEntry
}

export interface CronDocument extends CronParseResult {
  origin: string
  kind: CronSourceKind
  hasUserField: boolean
  lines: CronDocLine[]
}

/**
 * Split text into lines that remember their own terminator.
 *
 * `text.split('\n')` cannot be used for this and the difference is the point:
 * it loses whether the file ended in a newline, and it turns every CRLF into a
 * line with a stray `\r` on the end that a naive join then writes back in the
 * wrong place. Here `join('')` of `text + eol` is the input exactly.
 */
function splitKeepingEol(text: string): { text: string; eol: string }[] {
  const out: { text: string; eol: string }[] = []
  let i = 0
  while (i < text.length) {
    const j = text.indexOf('\n', i)
    if (j === -1) {
      out.push({ text: text.slice(i), eol: '' })
      break
    }
    const raw = text.slice(i, j)
    if (raw.endsWith('\r')) out.push({ text: raw.slice(0, -1), eol: '\r\n' })
    else out.push({ text: raw, eol: '\n' })
    i = j + 1
  }
  return out
}

/**
 * Parse a crontab into a document that can be written back unchanged.
 *
 * The classification is the read half's, unchanged and not re-implemented —
 * `parseCrontab` is now a wrapper over this. Two parsers over one format is two
 * parsers to disagree.
 */
export function parseCrontabDocument(
  text: string,
  origin: string,
  kind: CronSourceKind,
  hasUserField: boolean
): CronDocument {
  const lines: CronDocLine[] = []
  const entries: CronEntry[] = []
  const unparsed: { origin: string; line: string }[] = []

  for (const { text: raw, eol } of splitKeepingEol(text)) {
    // `\r` is stripped explicitly rather than left to trim(), because the
    // command is sliced out of this string afterwards and a carriage return
    // sitting inside it would ride along into the reported command.
    const line = raw.replace(/\r/g, '').trim()
    if (line === '') {
      lines.push({ kind: 'blank', text: raw, eol })
      continue
    }
    if (line.startsWith('#')) {
      lines.push({ kind: 'comment', text: raw, eol })
      continue
    }
    if (isAssignment(line)) {
      lines.push({ kind: 'assignment', text: raw, eol })
      continue
    }
    const layout = layoutJobLine(line, hasUserField)
    if (!layout) {
      unparsed.push({ origin, line })
      lines.push({ kind: 'unparsed', text: raw, eol })
      continue
    }
    const entry = { ...entryFromLayout(layout, origin, kind), line }
    entries.push(entry)
    lines.push({ kind: 'job', text: raw, eol, entry })
  }
  return { origin, kind, hasUserField, lines, entries, unparsed }
}

/** The document's bytes. Of an untouched document, the bytes it was parsed from. */
export function serialiseCrontabDocument(doc: CronDocument): string {
  return doc.lines.map((l) => `${l.text}${l.eol}`).join('')
}

// ---- Writing a command back out ----------------------------------------

/**
 * Turn a command (and its stdin, if any) back into the bytes a crontab holds.
 *
 * The exact inverse of `splitCronCommand`, and it has to be: an unescaped `%`
 * in a crontab is NOT a percent sign — cron cuts the line there, runs the left
 * half, and feeds the right half to it on stdin, with each further `%` becoming
 * a newline. So a command the operator typed with a literal `%` in it must go
 * to disk as `\%`, or the second half of their command silently stops being a
 * command at all.
 *
 * `splitCronCommand(serialiseCronCommand(c, i))` is `{ command: c, input: i }`
 * for every c and i, which is asserted as a property rather than on examples.
 */
export function serialiseCronCommand(command: string, input?: string): string {
  const esc = (s: string): string => s.replace(/%/g, '\\%')
  if (input === undefined) return esc(command)
  return `${esc(command)}%${input.split('\n').map(esc).join('%')}`
}

/** Is this a schedule the read half would accept? The write half asks the same question. */
export function isValidCronSchedule(schedule: string): boolean {
  const s = schedule.trim()
  if (s === '') return false
  if (s.startsWith('@')) return s.toLowerCase() in SPECIALS
  const f = s.split(/\s+/)
  return isCronFieldSet(f)
}

// ---- Which sources we will write, and which we refuse by name ------------

/**
 * Why we will not edit each source, or `null` where we will.
 *
 * ONE source is supported, deliberately. The alternative — an edit button that
 * works on user crontabs and quietly does something less complete everywhere
 * else — is the failure the roadmap names: a partial capability that looks
 * total. Each refusal below names the source and the actual reason, so the
 * answer to "why can't I edit this one" is on screen rather than in a commit
 * message.
 */
const CRON_EDIT_REFUSAL: Record<CronSourceKind, string | null> = {
  'user-crontab': null,
  'system-crontab':
    '/etc/crontab is root-owned and is rewritten by the distribution’s own packages. ShellPilot does not edit it: a write here needs root, and a root-owned file that a package manager also writes is not a file to round-trip from a laptop.',
  'cron.d':
    '/etc/cron.d files are root-owned and mostly belong to packages, which replace them wholesale on upgrade. ShellPilot does not edit them.',
  'systemd-timer':
    'a systemd timer is two unit files and a systemctl daemon-reload, not a line in a file. ShellPilot reads timers and does not edit them — doing it properly is its own piece of work, and doing it improperly leaves a unit that no longer matches what systemd has loaded.',
  'other-user-crontab':
    'another account’s crontab can only be written as that account or as root. ShellPilot edits only the crontab of the account it is connected as.'
}

/** `null` when this source can be edited, or the sentence saying why not. */
export function cronEditRefusal(kind: CronSourceKind): string | null {
  return CRON_EDIT_REFUSAL[kind]
}

/** The kinds `cronEditRefusal` lets through, for a panel that wants to say so up front. */
export const CRON_EDITABLE_KINDS: CronSourceKind[] = (
  Object.keys(CRON_EDIT_REFUSAL) as CronSourceKind[]
).filter((k) => CRON_EDIT_REFUSAL[k] === null)

// ---- Planning one edit --------------------------------------------------

/**
 * One change to one line.
 *
 * `update` and `remove` carry BOTH the line's index and the line's exact text.
 * The index alone is not an identity: the collection the operator is looking at
 * was read seconds or minutes ago, and a crontab that has been edited on the
 * host since then can have the same number of lines with a different job on the
 * one being pointed at. The text is what makes "this is still the line you
 * meant" answerable, and the answer is a refusal rather than a guess.
 */
export type CronEdit =
  | { op: 'add'; schedule: string; command: string; input?: string }
  | { op: 'update'; lineIndex: number; lineText: string; schedule: string; command: string; input?: string }
  | { op: 'remove'; lineIndex: number; lineText: string }

export type CronEditPlan =
  | {
      ok: true
      /** The bytes we expect `crontab -l` to be returning right now. */
      before: string
      /** The bytes to install. */
      after: string
      /** One line for the confirmation dialog and the approval record. */
      summary: string
      /** True when a missing final newline had to be added to append a job. */
      addedFinalNewline: boolean
    }
  | { ok: false; reason: string }

/** The `\n` or `\r\n` this file mostly uses, for a line we are adding to it. */
function dominantEol(lines: CronDocLine[]): string {
  const crlf = lines.filter((l) => l.eol === '\r\n').length
  const lf = lines.filter((l) => l.eol === '\n').length
  return crlf > lf ? '\r\n' : '\n'
}

/**
 * Rebuild one job line around a new schedule and a new command.
 *
 * Only the parts that actually changed are rebuilt. If the schedule is the same
 * schedule, its original bytes are reused — tabs, column alignment and all —
 * and the same for the command. That is not tidiness for its own sake: an edit
 * to a job's command that also silently re-spaced its schedule is two changes
 * in the diff, and the reviewer has to work out which one we meant.
 */
function rewriteJobLine(
  layout: CronLineLayout,
  scheduleRaw: string,
  rest: string
): string {
  const schedule = collapse(layout.scheduleRaw) === collapse(scheduleRaw) ? layout.scheduleRaw : scheduleRaw
  const body = layout.rest === rest ? layout.rest : rest
  const user = layout.user === null ? '' : `${layout.user}${layout.userGap}`
  return `${layout.dash}${schedule}${layout.gap}${user}${body}`
}

const refuse = (reason: string): CronEditPlan => ({ ok: false, reason })

/**
 * Work out the exact bytes an edit would install, or refuse and say why.
 *
 * Nothing here talks to a host. The plan is pure, so the refusals are testable
 * without one and the same plan can be shown to the operator, recorded in the
 * approval, and handed to the writer — three uses of one answer rather than
 * three chances to compute it differently.
 */
export function planCronEdit(doc: CronDocument, edit: CronEdit): CronEditPlan {
  const refusal = cronEditRefusal(doc.kind)
  if (refusal !== null) return refuse(refusal)

  // RULE: never write a file we could not fully parse. The unparsed line is
  // precisely the line whose meaning we are least sure of, and an edit
  // elsewhere in the file still rewrites the whole crontab through
  // `crontab -` — so a line we misread is a line we could destroy without ever
  // having pointed at it.
  if (doc.unparsed.length > 0) {
    const first = doc.unparsed[0].line
    return refuse(
      `this crontab has ${doc.unparsed.length} line${doc.unparsed.length === 1 ? '' : 's'} ShellPilot could not parse, starting with \`${first.length > 60 ? `${first.slice(0, 57)}…` : first}\`. Writing a whole file back around a line we did not understand is how a schedule quietly stops running, so nothing here can be edited until that line is dealt with by hand.`
    )
  }

  const lines = doc.lines.map((l) => ({ ...l }))
  let addedFinalNewline = false
  let summary: string

  if (edit.op === 'add') {
    const built = buildJobLine(edit.schedule, edit.command, edit.input, doc.hasUserField)
    if (!built.ok) return refuse(built.reason)
    const eol = dominantEol(lines)
    const last = lines[lines.length - 1]
    // Appending to a file with no final newline glues the new job onto the end
    // of the last one — the exact bug the key work hit with authorized_keys,
    // where the result is one malformed line and the job that was already there
    // silently stops. The newline is added deliberately and reported, rather
    // than being a byte that appears in the diff with no explanation.
    if (last !== undefined && last.eol === '') {
      last.eol = eol
      addedFinalNewline = true
    }
    lines.push({ kind: 'job', text: built.text, eol })
    summary = `add \`${built.text}\``
  } else {
    const target = lines[edit.lineIndex]
    if (target === undefined) {
      return refuse(
        `this crontab has ${lines.length} line${lines.length === 1 ? '' : 's'} and the job being changed was line ${edit.lineIndex + 1}. It has been edited on the server since it was read; read it again.`
      )
    }
    if (target.kind !== 'job') {
      return refuse(
        `line ${edit.lineIndex + 1} of this crontab is not a job any more. It has been edited on the server since it was read; read it again.`
      )
    }
    if (target.text !== edit.lineText) {
      return refuse(
        `line ${edit.lineIndex + 1} of this crontab now reads \`${target.text.trim()}\` and was \`${edit.lineText.trim()}\` when it was read. It has been edited on the server since; read it again.`
      )
    }
    // A line carrying a bare `\r` in the middle cannot be rebuilt without
    // deciding where the carriage return belongs, and there is no right answer
    // to that. It round-trips untouched; it just cannot be the line we edit.
    if (target.text.includes('\r')) {
      return refuse(
        `line ${edit.lineIndex + 1} contains a carriage return inside the line itself. ShellPilot will not rewrite it, because there is no way to put that character back where it was.`
      )
    }
    if (edit.op === 'remove') {
      lines.splice(edit.lineIndex, 1)
      summary = `remove \`${target.text.trim()}\``
    } else {
      const clean = target.text.trim()
      const layout = layoutJobLine(clean, doc.hasUserField)
      // Cannot happen — the line was classified `job` by the same function —
      // but a `!` here would be a claim rather than a check, on the path that
      // rewrites a file.
      if (!layout) return refuse(`line ${edit.lineIndex + 1} no longer parses as a job.`)
      const built = buildJobLine(edit.schedule, edit.command, edit.input, doc.hasUserField)
      if (!built.ok) return refuse(built.reason)
      const lead = target.text.slice(0, target.text.length - target.text.trimStart().length)
      const trail = target.text.slice(target.text.trimEnd().length)
      const rewritten = rewriteJobLine(layout, edit.schedule.trim(), serialiseCronCommand(edit.command, edit.input))
      target.text = `${lead}${rewritten}${trail}`
      summary = `change \`${clean}\` to \`${rewritten}\``
    }
  }

  const after = serialiseCrontabDocument({ ...doc, lines })

  // THE LAST CHECK, and the one that makes the rest safe to believe: parse what
  // we are about to write, and require that it says what we meant. A rebuilt
  // line that parses as something else — or as nothing — never reaches a host.
  const reparsed = parseCrontabDocument(after, doc.origin, doc.kind, doc.hasUserField)
  if (reparsed.unparsed.length > 0) {
    return refuse(
      `the file this change would produce has a line ShellPilot cannot parse back (\`${reparsed.unparsed[0].line}\`), so it was not written.`
    )
  }
  const expected = edit.op === 'remove' ? doc.entries.length - 1 : edit.op === 'add' ? doc.entries.length + 1 : doc.entries.length
  if (reparsed.entries.length !== expected) {
    return refuse(
      `the file this change would produce has ${reparsed.entries.length} job(s) and ${expected} were expected, so it was not written.`
    )
  }
  if (edit.op !== 'remove') {
    const want = { schedule: collapse(edit.schedule), command: edit.command, input: edit.input }
    const got = reparsed.lines.find(
      (l, i) => l.kind === 'job' && (edit.op === 'add' ? i === lines.length - 1 : i === edit.lineIndex)
    )?.entry
    if (
      !got ||
      got.schedule !== want.schedule ||
      got.command !== want.command ||
      got.input !== want.input
    ) {
      return refuse(
        'the line this change would produce does not read back as the job that was asked for, so it was not written.'
      )
    }
  }

  return { ok: true, before: serialiseCrontabDocument(doc), after, summary, addedFinalNewline }
}

/** Build one job line from scratch, or say why it is not a job. */
function buildJobLine(
  schedule: string,
  command: string,
  input: string | undefined,
  hasUserField: boolean
): { ok: true; text: string } | { ok: false; reason: string } {
  const s = schedule.trim()
  if (!isValidCronSchedule(s)) {
    return {
      ok: false,
      reason: `\`${s}\` is not a schedule cron accepts. Five fields, or one of ${Object.keys(SPECIALS).join(', ')}.`
    }
  }
  // A crontab is a line-oriented format with no continuation and no escape for
  // a newline. A command containing one is not a command cron can run; it is
  // two lines, the second of which is whatever the first half of the command
  // happened to leave behind.
  if (/[\r\n]/.test(command) || (input !== undefined && /\r/.test(input))) {
    return { ok: false, reason: 'a crontab line cannot contain a newline or a carriage return.' }
  }
  if (command.trim() === '') return { ok: false, reason: 'a job needs a command to run.' }
  const rest = serialiseCronCommand(command, input)
  // The user column is not synthesised. A file that has one is a file we refuse
  // to edit anyway; this is the check that keeps the two facts consistent
  // rather than relying on them being consistent.
  if (hasUserField) {
    return { ok: false, reason: 'ShellPilot does not add jobs to files that carry a user column.' }
  }
  return { ok: true, text: `${s} ${rest}` }
}

// ---- Writing it to the host ---------------------------------------------

/**
 * Names the backup and the three staging files, on the host, in $HOME.
 *
 * Timestamped first so `ls` sorts them in the order they happened, and so an
 * operator finding one in a shell six weeks later can tell when it was taken
 * without reading its contents. Validated before it is interpolated into a
 * command that replaces a crontab — the value comes from this process today,
 * and a value that reaches a command like that is checked where it is used and
 * not where it happens to be produced.
 */
export const CRON_TOKEN_RE = /^[0-9]{8}T[0-9]{6}Z-[0-9a-f]{6}$/

/** Where the backup lands, relative to $HOME. The panel shows this path. */
export function cronBackupName(token: string): string {
  if (!CRON_TOKEN_RE.test(token)) throw new Error('refusing to name a crontab backup from an unvalidated token')
  return `.shellpilot-crontab-${token}.bak`
}

/**
 * A shell single-quoted literal holding exactly these bytes.
 *
 * `'\''` is the only escape a POSIX single-quoted string has, and with it the
 * quoting is total: no expansion, no substitution, no backslash processing, and
 * embedded newlines are themselves. A crontab is arbitrary text written by
 * somebody else and it goes into a command line, so this is the one place the
 * quoting has to be exactly right rather than nearly right.
 */
function shellLiteral(s: string): string {
  return `'${s.replaceAll("'", `'\\''`)}'`
}

export interface CronWriteRequest {
  /** The bytes `crontab -l` must still be returning, or nothing is written. */
  before: string
  /** The bytes to install. */
  after: string
  token: string
}

/**
 * The command that replaces a user crontab, and proves it did.
 *
 * `crontab -` replaces the WHOLE file — there is no line editing and no partial
 * write — so the shape is read, compare, back up, install, read back:
 *
 *  1. Refuse if the host's crontab is not byte-for-byte the file this change
 *     was planned against. Someone else's edit, or our own stale collection,
 *     and the plan's line numbers are about a different file.
 *  2. Back the crontab up to a timestamped file in $HOME, and STOP if that did
 *     not land. The same rule the key work follows, for the same reason: a
 *     backup an operator can find in a shell is worth more than any rollback
 *     this process could promise, and it is the only thing that survives this
 *     process dying mid-change.
 *  3. Install.
 *  4. Read it back with `crontab -l` and compare. A write that has not been
 *     read back is a write that has not been made — a crontab is the one file
 *     where being wrong produces no error at all, just a job that stops
 *     running. On a mismatch the backup goes straight back in.
 *
 * As everywhere else in this file there is no `set -e`; unlike the read half,
 * every step is chained so that a failure stops the next one. A read that fails
 * can still leave a useful collection. A write whose backup failed must not
 * reach the part that replaces the file.
 *
 * The outcome is accumulated in a shell variable and printed once, after a
 * marker, at the end — the discipline the collector uses. Here it matters for a
 * second reason: `crontab` prints the operator's own file back at them in some
 * of its error messages, and a status line assembled from that output could
 * otherwise be forged by a line inside their crontab.
 */
export function buildCronWriteCommand(o: CronWriteRequest): string {
  if (!CRON_TOKEN_RE.test(o.token)) {
    throw new Error('refusing to build a crontab write from an unvalidated token')
  }
  const bak = cronBackupName(o.token)
  const stem = `.shellpilot-crontab-${o.token}`
  return [
    'LC_ALL=C',
    'export LC_ALL',
    // 077 so the staging copies of the crontab are not world-readable while
    // they exist. A crontab routinely holds paths, hostnames and the odd token.
    'umask 077',
    'SP_OUT=""',
    // Printed ONCE, at the end, from a variable — see the doc comment.
    `sp_end() { printf '===SHELLPILOT-CRON-WRITE===\\n%s %s\\n%s\\n' "$1" "$2" "$SP_OUT"; exit "$3"; }`,
    `sp_say() { SP_OUT="$(printf '%s' "$*" | tr '\\r\\n' '  ')"; }`,

    resolveBinary('crontab'),
    'SP_CRONTAB=""',
    'command -v "$SP_BIN" >/dev/null 2>&1 && SP_CRONTAB="$SP_BIN"',
    '[ -n "$SP_CRONTAB" ] || { sp_say "this server has no crontab command"; sp_end no-tool - 3; }',
    // `cmp` is what proves both the backup and the read-back. Without it there
    // is no verification, and a write with no verification is not one this
    // command is willing to make.
    'command -v cmp >/dev/null 2>&1 || { sp_say "this server has no cmp, so the write could not be verified"; sp_end no-cmp - 3; }',
    '[ -n "$HOME" ] && [ -d "$HOME" ] && [ -w "$HOME" ] || { sp_say "this account has no writable home directory, so no backup could be kept"; sp_end no-home - 3; }',

    `SP_B="$HOME/${bak}"`,
    `SP_E="$HOME/${stem}.expected"`,
    `SP_T="$HOME/${stem}.new"`,
    `SP_V="$HOME/${stem}.verify"`,
    'SP_LOCK="$HOME/.shellpilot-cron.lock"',
    // One change at a time, for the reason the key work gives: two edits a
    // second apart both read the same file, and the second one's "install"
    // silently discards the first one's. `mkdir` is atomic everywhere.
    // The two failures are not the same failure: the directory already existing
    // is another change in flight, anything else is a home this account cannot
    // write, and they have different fixes.
    'mkdir "$SP_LOCK" 2>/dev/null || { [ -d "$SP_LOCK" ] && { sp_say "another crontab change is running on this server right now"; sp_end locked - 6; }; sp_say "a lock could not be created in the home directory"; sp_end locked - 3; }',
    `trap 'rmdir "$SP_LOCK" 2>/dev/null' EXIT INT TERM HUP`,

    // ---- 1. Is this still the file the change was planned against? --------
    //
    // The backup IS the comparison. `crontab -l` is run once, into the backup
    // file, and that file is compared with what we expected — so the bytes we
    // saved are the bytes we checked, with no second read in between for the
    // file to change under.
    `printf '%s' ${shellLiteral(o.before)} > "$SP_E" || { rm -f "$SP_E"; sp_say "the crontab this change was planned against could not be staged"; sp_end stage-failed - 3; }`,
    // Not `|| true`. A `crontab -l` that fails on an account that HAS a crontab
    // is a refusal, and treating it as an empty crontab would let the next step
    // compare nothing against nothing on a file we never read.
    '"$SP_CRONTAB" -l > "$SP_B" 2>/dev/null',
    'SP_RC=$?',
    // An account with no crontab at all: `crontab -l` exits non-zero and prints
    // nothing, which IS the empty file. Distinguished from a real read failure
    // by whether the plan expected an empty file — and if it did not, the
    // comparison below refuses anyway.
    '[ "$SP_RC" = 0 ] || [ ! -s "$SP_E" ] || { rm -f "$SP_E" "$SP_B"; sp_say "this account’s crontab could not be read back to be backed up"; sp_end backup-failed - 3; }',
    'cmp -s "$SP_B" "$SP_E" || { rm -f "$SP_E" "$SP_B"; sp_say "the crontab on this server is not the one this change was planned against — it has been edited since it was read, so nothing was changed"; sp_end changed - 4; }',
    // Belt and braces on the backup itself. `cmp` above proves it matches what
    // we expected, which on a non-empty crontab already proves it landed; this
    // catches the one case that does not — an empty expected file, where a
    // failed `cp` and a correct empty backup are the same zero bytes.
    `[ -f "$SP_B" ] || { rm -f "$SP_E"; sp_say "the backup did not land, so nothing was changed"; sp_end backup-failed - 3; }`,
    'chmod 600 "$SP_B" 2>/dev/null || true',

    // ---- 2. Install --------------------------------------------------------
    `printf '%s' ${shellLiteral(o.after)} > "$SP_T" || { rm -f "$SP_E" "$SP_T"; sp_say "the new crontab could not be staged, so nothing was changed"; sp_end stage-failed - 3; }`,
    // From here on the backup STAYS, whatever happens. Past this line the
    // crontab may have been replaced, and a backup deleted on the way out of a
    // failure is the one an operator needs.
    'rm -f "$SP_E"',
    // `crontab -` and not `crontab "$SP_T"`: `-` is the spelling every cron
    // implementation supports for "read the new crontab from stdin", and it
    // does not depend on the file being readable by whatever the crontab binary
    // drops privileges to.
    'if SP_MSG=$("$SP_CRONTAB" - < "$SP_T" 2>&1); then',
    ':',
    'else',
    'rm -f "$SP_T"',
    'sp_say "the server’s crontab command refused the new file: $SP_MSG"',
    'sp_end rejected "$SP_B" 4',
    'fi',

    // ---- 3. Read it back ---------------------------------------------------
    //
    // The whole reason this command exists in this shape. cron reports nothing
    // when a job stops existing, so the only evidence a write worked is the
    // file coming back the way it went in.
    '"$SP_CRONTAB" -l > "$SP_V" 2>/dev/null',
    'if cmp -s "$SP_V" "$SP_T"; then',
    'rm -f "$SP_T" "$SP_V"',
    'sp_say "the crontab was replaced and read back identical"',
    'sp_end written "$SP_B" 0',
    'fi',
    // It did not come back the way it went in. Put the backup back, and say
    // whether that worked — "we tried to undo it" and "it is undone" are two
    // different facts and only one of them is a reason to stop worrying.
    'if "$SP_CRONTAB" - < "$SP_B" >/dev/null 2>&1; then',
    'rm -f "$SP_T" "$SP_V"',
    'sp_say "the crontab did not read back as what was written, so the backup was put back"',
    'sp_end verify-failed-restored "$SP_B" 5',
    'fi',
    'rm -f "$SP_T" "$SP_V"',
    'sp_say "the crontab did not read back as what was written AND the backup could not be put back. The previous crontab is in the backup file; restore it by hand"',
    'sp_end verify-failed-unrestored "$SP_B" 5'
  ].join('\n')
}

/** Every way `buildCronWriteCommand` can end. `written` is the only one that changed anything as asked. */
export type CronWriteOutcome =
  | 'written'
  | 'no-tool'
  | 'no-cmp'
  | 'no-home'
  | 'locked'
  | 'stage-failed'
  | 'backup-failed'
  | 'changed'
  | 'rejected'
  | 'verify-failed-restored'
  | 'verify-failed-unrestored'
  /** The command did not reach its own last line: killed, timed out, cut off. */
  | 'no-answer'

export interface CronWriteResult {
  outcome: CronWriteOutcome
  /** Full path of the backup on the host, when one was taken. */
  backupPath?: string
  detail: string
}

const CRON_WRITE_OUTCOMES: CronWriteOutcome[] = [
  'written',
  'no-tool',
  'no-cmp',
  'no-home',
  'locked',
  'stage-failed',
  'backup-failed',
  'changed',
  'rejected',
  'verify-failed-restored',
  'verify-failed-unrestored'
]

/**
 * Read the writer's one status line.
 *
 * Output with no marker in it is `no-answer` rather than anything hopeful. A
 * command that was killed between installing and reporting has left a host in
 * an unknown state, and the only honest thing to say is that we do not know —
 * "assume it failed" and "assume it worked" are both guesses, and one of them
 * tells an operator their job is running when it is not.
 */
export function parseCronWriteResult(stdout: string): CronWriteResult {
  const m = stdout.match(/===SHELLPILOT-CRON-WRITE===\r?\n([^\n]*)\r?\n([\s\S]*)$/)
  if (!m) {
    return {
      outcome: 'no-answer',
      detail:
        'the server did not report what happened to this change. It may or may not have been applied — read the crontab again before doing anything else.'
    }
  }
  const [outcome, backup] = m[1].trim().split(/\s+/)
  const detail = m[2].trim()
  return {
    outcome: CRON_WRITE_OUTCOMES.includes(outcome as CronWriteOutcome) ? (outcome as CronWriteOutcome) : 'no-answer',
    ...(backup === undefined || backup === '-' ? {} : { backupPath: backup }),
    detail
  }
}

// ---- Reading the one file we are willing to write -----------------------

/**
 * `crontab -l`, byte for byte, plus what happened.
 *
 * A separate command from the collector, deliberately, and the difference is
 * the point. The collector reads five sources into one blob and its sections
 * are re-printed through `printf '%s\n'`, which is fine for a list of jobs and
 * useless here: it appends a newline a file may not have had, and an edit
 * planned against bytes that are not the file's bytes is an edit the host will
 * refuse — or worse, one it will accept while writing back a file that gained a
 * byte nobody asked for.
 *
 * THE STATUS COMES FIRST and the body last, which is the opposite of the
 * collector and is required rather than stylistic. The body has to be the last
 * thing on stdout for its trailing bytes to survive; and a status printed after
 * it could be forged by a line inside the operator's own crontab. Putting the
 * status first gets both: nothing that comes out of the file is ever read as
 * status, and the file's last byte is the command's last byte.
 */
export function buildCronReadCommand(): string {
  return [
    'LC_ALL=C',
    'export LC_ALL',
    resolveBinary('crontab'),
    'SP_CRONTAB=""',
    'command -v "$SP_BIN" >/dev/null 2>&1 && SP_CRONTAB="$SP_BIN"',
    `printf '===SHELLPILOT-CRON-READ===\\n'`,
    'if [ -z "$SP_CRONTAB" ]; then',
    `printf 'no-tool\\n'`,
    'elif "$SP_CRONTAB" -l >/dev/null 2>&1; then',
    `printf 'ok\\n'`,
    'else',
    // Non-zero from `crontab -l` is overwhelmingly "no crontab for <user>",
    // which is an EMPTY crontab and completely normal — it is what an account
    // that has never scheduled anything looks like, and the first job anybody
    // adds is added to it. Anything else is a refusal and must not be planned
    // against as though the file were empty.
    'SP_ERR=$("$SP_CRONTAB" -l 2>&1 >/dev/null || true)',
    'case "$SP_ERR" in',
    `*"no crontab for"*) printf 'absent\\n' ;;`,
    `*) printf 'unknown %s\\n' "$(printf '%s' "$SP_ERR" | tr '\\r\\n' '  ')" ;;`,
    'esac',
    'fi',
    `printf '===SHELLPILOT-CRON-BODY===\\n'`,
    // Last, and unquoted by any printf, so the file's own trailing bytes are
    // the command's trailing bytes.
    '[ -n "$SP_CRONTAB" ] && "$SP_CRONTAB" -l 2>/dev/null',
    'exit 0'
  ].join('\n')
}

export interface CronReadResult {
  status: 'ok' | 'absent' | 'no-tool' | 'unknown'
  /** The crontab, byte for byte. Empty on `absent`, which IS an empty crontab. */
  text: string
  detail?: string
}

/** Split `buildCronReadCommand`'s output. Anything unrecognised is `unknown`. */
export function parseCronRead(output: string): CronReadResult {
  const m = output.match(/===SHELLPILOT-CRON-READ===\n([^\n]*)\n===SHELLPILOT-CRON-BODY===\n([\s\S]*)$/)
  if (!m) {
    return {
      status: 'unknown',
      text: '',
      detail: 'the server did not answer with a crontab at all, so nothing was read.'
    }
  }
  const [word, ...rest] = m[1].trim().split(/\s+/)
  const detail = rest.join(' ').trim()
  const status =
    word === 'ok' || word === 'absent' || word === 'no-tool' ? word : ('unknown' as const)
  return {
    status,
    text: status === 'ok' ? m[2] : '',
    ...(detail === '' ? {} : { detail })
  }
}

// ---- What crosses the wire ----------------------------------------------

/**
 * An edit as the PANEL asks for it: by the line's own text, never by position.
 *
 * The panel's list was read minutes ago. An index into it still resolves
 * against a file that has since changed — to the wrong job, silently — whereas
 * a line that is no longer in the file is a question with an obvious answer.
 * `resolveCronEdit` turns one of these into the positional form the planner
 * takes, against the document that was just read from the host, or refuses.
 */
export type CronEditRequest =
  | { op: 'add'; schedule: string; command: string; input?: string }
  | { op: 'update'; line: string; schedule: string; command: string; input?: string }
  | { op: 'remove'; line: string }

/** Find the line the panel meant in the file the host just handed over. */
export function resolveCronEdit(
  doc: CronDocument,
  req: CronEditRequest
): { ok: true; edit: CronEdit } | { ok: false; reason: string } {
  if (req.op === 'add') return { ok: true, edit: req }
  const index = doc.lines.findIndex(
    (l) => l.kind === 'job' && l.text.replace(/\r/g, '').trim() === req.line
  )
  if (index === -1) {
    return {
      ok: false,
      reason: `\`${req.line}\` is not in this crontab any more. It has been edited on the server since it was read; read it again.`
    }
  }
  const lineText = doc.lines[index].text
  return {
    ok: true,
    edit:
      req.op === 'remove'
        ? { op: 'remove', lineIndex: index, lineText }
        : {
            op: 'update',
            lineIndex: index,
            lineText,
            schedule: req.schedule,
            command: req.command,
            ...(req.input === undefined ? {} : { input: req.input })
          }
  }
}

export interface CronEditTargetRef {
  serverId: string
  serverName: string
  cfg: unknown
}

/** What `cron:plan-edit` answers with. Every field but `ok` is absent on a refusal. */
export interface CronEditPlanReply {
  ok: boolean
  reason?: string
  before?: string
  after?: string
  summary?: string
  addedFinalNewline?: boolean
  token?: string
  command?: string
}

export interface CronWriteReply extends CronWriteResult {
  ok: boolean
  serverId: string
  serverName: string
}

/**
 * The two channels an edit needs, named so the panel, the preload and main all
 * agree on one shape — the way the compose module's bridge already does.
 *
 * The panel checks for these at runtime rather than assuming them, for the same
 * reason it treats `sources` as optional: a main process that has not been
 * taught the channels answers nothing, and an edit button that does nothing is
 * worse than no edit button.
 */
export interface CronEditBridge {
  planEdit: (
    target: CronEditTargetRef,
    edit: CronEditRequest,
    opts?: { sources?: CronSourceReport[] }
  ) => Promise<CronEditPlanReply>
  write: (
    target: CronEditTargetRef,
    req: { before: string; after: string; token: string; runId: string; approval?: unknown }
  ) => Promise<CronWriteReply>
}
