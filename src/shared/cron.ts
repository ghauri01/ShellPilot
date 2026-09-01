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
  /** The schedule exactly as written. */
  schedule: string
  /** Plain English, or null when we decline to guess. */
  description: string | null
  /** Who it runs as. null when the format does not say. */
  user: string | null
  command: string
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

// Minute, hour and day-of-month are numeric only. Month and day-of-week also
// accept the three-letter names cron allows. The looser "letters anywhere"
// version of this parsed `this is not a crontab line` as a job with the
// schedule "this is not a crontab" — six words is all it takes.
const NUMERIC_FIELD = /^(\*|\d+)([-,/]\d+)*(,\d+([-/]\d+)?)*$|^\*\/\d+$/
const NAMED_FIELD = /^(\*|\d+|[A-Za-z]{3})([-,/](\d+|[A-Za-z]{3}))*$|^\*\/\d+$/

const isNumericFieldSet = (f: string[]): boolean =>
  f.length === 5 &&
  NUMERIC_FIELD.test(f[0]) &&
  NUMERIC_FIELD.test(f[1]) &&
  NUMERIC_FIELD.test(f[2]) &&
  NAMED_FIELD.test(f[3]) &&
  NAMED_FIELD.test(f[4])

function describeField(value: string, unit: string, names?: string[]): string | null {
  if (value === '*') return null
  const named = (v: string): string => {
    const n = Number(v)
    return names && Number.isInteger(n) && names[n % names.length] ? names[n % names.length] : v
  }
  if (/^\*\/(\d+)$/.test(value)) return `every ${RegExp.$1} ${unit}`
  if (/^\d+$/.test(value)) return `${unit} ${named(value)}`
  if (/^[\d,]+$/.test(value)) return `${unit} ${value.split(',').map(named).join(', ')}`
  if (/^(\d+)-(\d+)$/.test(value)) return `${unit} ${named(RegExp.$1)} to ${named(RegExp.$2)}`
  return null
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
  // through to null rather than being approximated.
  if (/^\d+$/.test(min) && /^\d+$/.test(hour) && dom === '*' && mon === '*' && dow === '*') {
    return `at ${hour.padStart(2, '0')}:${min.padStart(2, '0')} every day`
  }
  if (/^\d+$/.test(min) && /^\d+$/.test(hour) && dom === '*' && mon === '*' && /^\d$/.test(dow)) {
    return `at ${hour.padStart(2, '0')}:${min.padStart(2, '0')} every ${DOW[Number(dow) % 7]}`
  }
  if (/^\*\/(\d+)$/.test(min) && hour === '*' && dom === '*' && mon === '*' && dow === '*') {
    return `every ${RegExp.$1} minutes`
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
  const fields: [string, string, string[]?][] = [
    [min, 'minute'],
    [hour, 'hour'],
    [dom, 'day'],
    [mon, 'month', ['', ...MONTHS]],
    [dow, 'on', DOW]
  ]
  const parts: string[] = []
  for (const [value, unit, names] of fields) {
    if (value === '*') continue
    const d = describeField(value, unit, names)
    if (d === null) return null
    parts.push(d)
  }
  return parts.length ? parts.join(', ') : null
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
    const line = raw.trim()
    if (line === '' || line.startsWith('#')) continue
    if (isAssignment(line)) continue

    let schedule: string
    let rest: string
    if (line.startsWith('@')) {
      const m = line.match(/^(@\S+)\s+(.*)$/)
      if (!m) {
        unparsed.push({ origin, line })
        continue
      }
      schedule = m[1]
      rest = m[2]
    } else {
      const f = line.split(/\s+/)
      if (f.length < (hasUserField ? 7 : 6) || !isNumericFieldSet(f.slice(0, 5))) {
        unparsed.push({ origin, line })
        continue
      }
      schedule = f.slice(0, 5).join(' ')
      rest = f.slice(5).join(' ')
    }

    let user: string | null = null
    let command = rest
    if (hasUserField) {
      const m = rest.match(/^(\S+)\s+(.*)$/)
      if (!m) {
        unparsed.push({ origin, line })
        continue
      }
      user = m[1]
      command = m[2]
    }
    if (command.trim() === '') {
      unparsed.push({ origin, line })
      continue
    }
    entries.push({ kind, origin, schedule, description: describeSchedule(schedule), user, command })
  }
  return { entries, unparsed }
}

/**
 * Parse `systemctl list-timers --all --no-pager`.
 *
 * Columns are whitespace-aligned and the date fields themselves contain
 * spaces, so this anchors on the UNIT column (which always ends in `.timer`)
 * rather than counting fields — counting breaks the moment a locale writes a
 * date differently.
 */
export function parseSystemdTimers(text: string): CronParseResult {
  const entries: CronEntry[] = []
  const unparsed: { origin: string; line: string }[] = []

  for (const raw of text.split('\n')) {
    const line = raw.trim()
    if (line === '' || /^(NEXT|UNIT)\b/.test(line) || /timers listed/.test(line)) continue

    const m = line.match(/^(.*?)\s+(\S+\.timer)\s+(\S+\.\w+)\s*$/)
    if (!m) {
      // A timer line we cannot split is reported rather than dropped: a
      // silently missing timer is a scheduled job nobody knows about.
      if (line.includes('.timer')) unparsed.push({ origin: 'systemd', line })
      continue
    }
    const [, dates, timer, activates] = m
    // NEXT and LEFT, then LAST and PASSED. "n/a" appears for a timer that has
    // never run or has no next elapse.
    const cols = dates.split(/\s{2,}/).map((c) => c.trim()).filter(Boolean)
    entries.push({
      kind: 'systemd-timer',
      origin: timer,
      schedule: 'systemd timer',
      description: null,
      user: null,
      command: activates,
      nextRun: cols[0] && cols[0] !== 'n/a' ? cols[0] : undefined,
      lastRun: cols[2] && cols[2] !== 'n/a' ? cols[2] : undefined
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
  '{ for f in /etc/cron.d/*; do [ -f "$f" ] && echo "#FILE:$f" && cat "$f"; done; } 2>/dev/null || true',
  'echo "===SHELLPILOT-TIMERS==="',
  'systemctl list-timers --all --no-pager 2>/dev/null || true'
].join('; ')

/** Split the collector's output and parse each section with the right rules. */
export function parseCronCollection(output: string): CronParseResult {
  const section = (name: string): string => {
    const m = output.match(new RegExp(`===SHELLPILOT-${name}===\\n([\\s\\S]*?)(?====SHELLPILOT-|$)`))
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
    const m = line.match(/^#FILE:(.*)$/)
    if (m) {
      flush()
      current = m[1].trim()
    } else buffer.push(line)
  }
  flush()

  take(parseSystemdTimers(section('TIMERS')))
  return { entries, unparsed }
}
