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
  absent: 'not present on this host',
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
 * Parse a crontab file.
 *
 * `hasUserField` is the whole difficulty. /etc/crontab and /etc/cron.d put a
 * user between the schedule and the command; a user's own crontab does not.
 * Guessing wrong does not error — it silently reports the first word of the
 * command as the user and drops it from the command, which is a plausible
 * looking lie. The caller knows which file it read, so the caller says.
 */
export function parseCrontab(
  text: string,
  origin: string,
  kind: CronSourceKind,
  hasUserField: boolean
): CronParseResult {
  const entries: CronEntry[] = []
  const unparsed: { origin: string; line: string }[] = []

  for (const raw of text.split('\n')) {
    // `\r` is stripped explicitly rather than left to trim(), because the
    // command is sliced out of this string afterwards and a carriage return
    // sitting inside it would ride along into the reported command.
    const line = raw.replace(/\r/g, '').trim()
    if (line === '' || line.startsWith('#')) continue
    if (isAssignment(line)) continue

    // cronie lets a job be prefixed with `-` to suppress its syslog line. It is
    // a logging flag, not part of the schedule, and cronie is the cron on every
    // Red Hat derivative — so a `-` line is a real job, not a broken one.
    const body = line.startsWith('-') ? line.slice(1) : line

    let schedule: string
    let rest: string
    if (body.startsWith('@')) {
      const m = body.match(/^(@\S+)\s+(.*)$/)
      // An unknown `@word` is not a schedule any cron accepts — vixie and
      // cronie implement exactly the eight in SPECIALS — so the job never runs.
      // Listing `@every_minute` as scheduled is the same lie as dropping it.
      if (!m || !(m[1].toLowerCase() in SPECIALS)) {
        unparsed.push({ origin, line })
        continue
      }
      schedule = m[1]
      rest = m[2]
    } else {
      const tok = tokenize(body)
      if (tok.length < (hasUserField ? 7 : 6) || !isCronFieldSet(tok.slice(0, 5).map((t) => t.text))) {
        unparsed.push({ origin, line })
        continue
      }
      schedule = tok
        .slice(0, 5)
        .map((t) => t.text)
        .join(' ')
      // Sliced, not joined. Debian's /etc/crontab separates its fields with
      // tabs and real commands contain runs of whitespace — `run-parts` lines,
      // quoted arguments, aligned `&&` chains. `f.slice(5).join(' ')` collapsed
      // all of it and printed a command that is not the one on disk.
      rest = body.slice(tok[5].start)
    }

    let user: string | null = null
    if (hasUserField) {
      const m = rest.match(/^(\S+)\s+(.*)$/)
      if (!m) {
        unparsed.push({ origin, line })
        continue
      }
      user = m[1]
      rest = m[2]
    }

    // Note what is *not* done here: a trailing `# comment` is left in the
    // command, because cron leaves it there too. `#` starts a comment only at
    // the beginning of a line, so `0 3 * * * /x # nightly` runs a shell command
    // ending in `# nightly` — stripping it would show a command that is not the
    // one that runs.
    const { command, input } = splitCronCommand(rest)
    if (command.trim() === '') {
      unparsed.push({ origin, line })
      continue
    }
    entries.push({
      kind,
      origin,
      schedule,
      description: describeSchedule(schedule),
      user,
      command,
      ...(input === undefined ? {} : { input })
    })
  }
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
    'sp_note user-crontab no-tool - "this host has no crontab command"',
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
    'sp_note other-crontabs absent - "no per-user crontab spool on this host"',
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
    'sp_note systemd-timers no-tool - "this host has no systemctl"',
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
