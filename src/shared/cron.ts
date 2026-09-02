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

export type CronSourceKind = 'user-crontab' | 'system-crontab' | 'cron.d' | 'systemd-timer'

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

/**
 * The command that collects everything, in one round trip.
 *
 * Each section is fenced with a marker so the parser knows which file each
 * block came from — and therefore whether it has a user field. Failures are
 * swallowed per section (`2>/dev/null || true`) because a host with no
 * /etc/cron.d, or a user with no crontab, is the normal case and must not fail
 * the whole collection.
 */
export const CRON_COLLECT_COMMAND = [
  'echo "===SHELLPILOT-USER==="',
  'crontab -l 2>/dev/null || true',
  'echo "===SHELLPILOT-SYSTEM==="',
  'cat /etc/crontab 2>/dev/null || true',
  'echo "===SHELLPILOT-CROND==="',
  // The trailing `printf` is load-bearing. Plenty of /etc/cron.d files ship
  // without a final newline, and `cat a` followed by the marker for b then
  // glues them together: a's last job grows a `#FILE:/etc/cron.d/b` tail on its
  // command, and every job in b gets filed under a. Both are silent, and the
  // second makes a job unfindable by the file it actually lives in.
  '{ for f in /etc/cron.d/*; do [ -f "$f" ] || continue; printf "#FILE:%s\\n" "$f"; cat "$f"; printf "\\n"; done; } 2>/dev/null || true',
  'echo "===SHELLPILOT-TIMERS==="',
  'systemctl list-timers --all --no-pager 2>/dev/null || true'
].join('; ')

/** Split the collector's output and parse each section with the right rules. */
export function parseCronCollection(output: string): CronParseResult {
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

  take(parseCrontab(section('USER'), 'crontab -l', 'user-crontab', false))
  take(parseCrontab(section('SYSTEM'), '/etc/crontab', 'system-crontab', true))

  // cron.d is many files in one blob, fenced by #FILE: markers the collector
  // wrote. Attributing an entry to the wrong file makes it unfindable.
  const crond = section('CROND')
  let current = '/etc/cron.d'
  let buffer: string[] = []
  const flush = (): void => {
    if (buffer.length) take(parseCrontab(buffer.join('\n'), current, 'cron.d', true))
    buffer = []
  }
  for (const line of crond.split('\n')) {
    const m = line.replace(/\r/g, '').match(/^#FILE:(.*)$/)
    if (m) {
      flush()
      current = m[1].trim()
    } else buffer.push(line)
  }
  flush()

  take(parseSystemdTimers(section('TIMERS')))
  return { entries, unparsed }
}
