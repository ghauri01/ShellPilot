// Live log tailing across hosts.
//
// The Fleet Monitor now says a unit failed. This is "why", which is always the
// next question and currently costs opening a terminal, remembering the unit
// name, and typing journalctl — per host.
//
// Two decisions shape the rest:
//
// 1. The remote command is BUILT here, never taken from the user. A tail is a
//    read, and the moment a caller can pass arbitrary text the feature becomes
//    "run anything on N hosts" with none of the confirmation broadcast has.
//    Unit names and paths are validated against the shapes systemd and POSIX
//    actually permit, and anything else is refused rather than escaped —
//    escaping is a promise about a shell we do not control.
// 2. Lines carry their host. An interleaved stream where you cannot tell which
//    machine said what is worse than four separate tails, because it looks
//    authoritative.

// `resolveBinary` and `SUDO_PROBE` are docker's, reused rather than restated.
// A second definition of "where does this host keep its binaries" or "may this
// account become root" is a second thing to keep in step with reality, and the
// answers do not differ by feature.
import { SUDO_PROBE, resolveBinary, validateContainerRef } from './docker'

export type LogSourceKind = 'unit' | 'file' | 'container'

/** journald's severities, lowest number first. `-p err` means err and worse. */
export const LOG_PRIORITIES = ['emerg', 'alert', 'crit', 'err', 'warning', 'notice', 'info', 'debug'] as const
export type LogPriority = (typeof LOG_PRIORITIES)[number]

/**
 * Whether this read may become root.
 *
 * `auto` is docker's discipline: `sudo -n` only, and only when the preflight
 * has established that root would actually change the answer.
 */
export type LogSudoMode = 'auto' | 'never' | 'always'

export interface LogSource {
  kind: LogSourceKind
  /** Unit name (`nginx.service`) or absolute path (`/var/log/syslog`). */
  target: string
  /** journalctl `-p`. Unit sources only; `tail` has no notion of severity. */
  priority?: LogPriority
  /** journalctl `--since`. Unit sources only. */
  since?: string
  /** Default `auto`. See LogSudoMode. */
  sudo?: LogSudoMode
}

export interface LogLine {
  tailId: string
  serverId: string
  serverName: string
  /** Monotonic per host, so the UI can key rows without hashing content. */
  seq: number
  text: string
  /** stderr from the remote command — a missing file, a denied read. */
  isError?: boolean
  at: number
}

export interface LogTailState {
  tailId: string
  serverId: string
  serverName: string
  state: 'starting' | 'streaming' | 'ended' | 'failed'
  error?: string
  /**
   * What the preflight established about this host, once it has run.
   *
   * On the STATE rather than in the stream on purpose. A tail is long-lived:
   * "reading as root" written once as a log line scrolls out of the pane in a
   * second, and after that a root tail is indistinguishable from an ordinary
   * one. Carried here it can be shown for the tail's whole life.
   */
  diagnosis?: LogDiagnosis
  /** The stream is held in main; the channel is still open. */
  paused?: boolean
}

/** How many lines the renderer keeps per tail before dropping the oldest. */
export const LOG_RING = 2_000
/** Lines from a single host per second before we start dropping, with a notice. */
export const LOG_RATE_PER_SEC = 500
/**
 * Longest single line kept, in characters.
 *
 * A "line" is whatever arrives before a newline, and nothing guarantees one
 * ever does: a log file that turns out to be binary, a process writing a
 * progress bar with carriage returns, a JSON blob per event. Without a cap the
 * partial-line buffer is an unbounded allocation in main driven entirely by
 * what a remote host chooses to send, and a single line big enough to matter is
 * an IPC message big enough to stall the renderer. Anything longer is split
 * across several lines rather than dropped — a truncated log is a log that lies
 * about what the host said.
 */
export const LOG_LINE_CAP = 16_384
/**
 * Lines held in main while a tail is paused, before the oldest are dropped.
 *
 * Pausing must not tear the channel down — that is the whole point of it, and
 * Stop already exists for the other thing — so the lines the host keeps sending
 * have to go somewhere. Unbounded, that somewhere is memory in main sized by a
 * remote host's mood, which is the failure `LOG_LINE_CAP` already exists to
 * avoid. Bounded at the renderer's ring, because a line the pane could never
 * have shown is not worth holding, and the drops are reported on resume for the
 * same reason the rate limiter reports its own: an unexplained gap is how
 * someone concludes a service stopped logging.
 */
export const LOG_PAUSE_BUFFER = LOG_RING

// systemd unit names: alphanumerics and `-_.@:` plus an optional suffix. This
// is deliberately the permissive-but-bounded set rather than a full grammar —
// what matters is that nothing here can end a shell word.
//
// No backslash. It used to be in the class (as `\\`, which reads like an escape
// of the trailing `-` but is a literal backslash) and it was the one character
// here that the shell does not pass through: `-u a\-b` reaches journalctl as
// `a-b`, so the host would follow a unit the user did not name. systemd does
// escape `-` as `\x2d` in device and mount unit names, but those are not things
// anyone follows, and the honest answer for them would be to quote the word
// rather than to let a shell rewrite it silently.
const UNIT_RE = /^[A-Za-z0-9@._:-]{1,128}$/
// Absolute paths only, no shell metacharacters, no traversal. A relative path
// would resolve against whatever directory the exec channel happens to start
// in, which is not a thing the user can reason about.
const PATH_RE = /^\/[A-Za-z0-9/._@:+-]{1,255}$/

export function validateLogSource(source: LogSource): { ok: true } | { ok: false; error: string } {
  const t = source.target.trim()
  if (t === '') return { ok: false, error: 'Give a unit name or a log file path.' }
  // Every one of these reaches main through IPC, where the type annotations are
  // a compile-time claim about a structured-clone value and nothing more. They
  // are all interpolated into a shell command, so they are all checked here —
  // the same rule the target has always followed.
  if (source.sudo !== undefined && !['auto', 'never', 'always'].includes(source.sudo)) {
    return { ok: false, error: 'Unrecognised sudo mode.' }
  }
  if (source.priority !== undefined && !validatePriority(source.priority)) {
    return { ok: false, error: `Priority must be one of ${LOG_PRIORITIES.join(', ')}.` }
  }
  if (source.since !== undefined && source.since.trim() !== '' && !validateSince(source.since)) {
    return {
      ok: false,
      error: 'That is not a time journalctl will take. Try "2 hours ago", "yesterday" or "2024-01-01 09:30".'
    }
  }
  // A container reference is validated by docker's own rule rather than a
  // second copy of it here — the two drifting apart is how one of them starts
  // accepting something the other refuses.
  if (source.kind === 'container') {
    if (!validateContainerRef(t)) {
      return { ok: false, error: 'That is not a container name or id.' }
    }
    if (source.priority || (source.since && source.since.trim() !== '')) {
      // Both are journalctl flags. `docker logs` has --since but not -p, and
      // silently ignoring a filter the user set is how a pane looks unfiltered
      // for no visible reason.
      return { ok: false, error: 'Priority and since are journald filters and do not apply to a container.' }
    }
    return { ok: true }
  }

  if (source.kind === 'unit') {
    if (!UNIT_RE.test(t)) {
      return { ok: false, error: 'That is not a unit name. Letters, digits and - _ . @ : only.' }
    }
    return { ok: true }
  }
  if (!t.startsWith('/')) return { ok: false, error: 'Use an absolute path, starting with /.' }
  if (t.includes('..')) return { ok: false, error: 'Paths with .. are refused.' }
  if (!PATH_RE.test(t)) return { ok: false, error: 'That path contains characters this will not pass to a shell.' }
  return { ok: true }
}

// ---------------------------------------------------------------------------
// Naming a failure is not handling one.
//
// The builder above used to produce a command and the tailer streamed whatever
// came back. That is enough when a tail works and actively misleading when it
// does not, because every way a tail fails on a real estate ends as either an
// empty pane or a line of shell output sitting where a log line should be:
//
//  * `journalctl` does not exist — Alpine, most containers, anything
//    pre-systemd. The pane showed `sh: journalctl: not found` styled as log
//    content, which reads as the service having said that.
//  * The file does not exist. `tail -F` waits for it forever, which is right
//    when you are watching for a log about to be created and is otherwise a
//    person staring at a dead pane. The two look identical.
//  * journald answers a read of a unit this account may not see with EMPTY, not
//    with an error. This is the dangerous one: the pane reads as "that service
//    is quiet" when the truth is "you are not allowed to see what it said".
//  * /var/log/secure and /var/log/audit/audit.log are root-only.
//
// So the tail is preceded by a preflight in the same shell, which states the
// facts it can establish and then execs the tail. The facts come back as marker
// lines the tailer strips out; the JUDGEMENT is made here, in a pure function,
// for the same reason docker's classification lives in shared/.

/**
 * Prefix for a preflight fact line.
 *
 * U+0001 for the reason `DOCKER_SEP` uses it: no log line contains it by
 * accident, it survives an ssh2 exec channel (no line discipline to rewrite
 * control bytes) and it survives JSON IPC. The trailing U+0001 makes the prefix
 * a shape rather than a word, so a log that prints `SPLOG` cannot collide.
 *
 * Forgery is prevented by ORDER, not by the bytes. Markers are only honoured
 * before `begin`, and the only thing that has run at that point is the
 * preflight — the tail is not exec'd until `begin` has been printed. So no
 * remote log line can ever be in a position to claim it was read as root.
 */
export const LOG_MARK = '\u0001SPLOG\u0001'

/** A preflight fact line, or null for an ordinary log line. */
export function parseLogMark(line: string): { key: string; value: string } | null {
  if (!line.startsWith(LOG_MARK)) return null
  const rest = line.slice(LOG_MARK.length)
  const eq = rest.indexOf('=')
  if (eq <= 0) return null
  return { key: rest.slice(0, eq), value: rest.slice(eq + 1) }
}

/**
 * What the preflight found, as a judgement rather than a pile of facts.
 *
 * `unit-quiet` and `journal-unreadable` produce the SAME empty pane, and are
 * the whole reason this type exists: one means the service said nothing, the
 * other means this account cannot be told what it said.
 */
export type LogTailIssue =
  | 'ok'
  | 'no-journal'
  | 'no-tail'
  | 'unit-not-loaded'
  | 'unit-masked'
  | 'journal-unreadable'
  | 'unit-quiet'
  | 'file-missing'
  | 'file-denied'
  | 'file-is-dir'
  | 'no-docker'
  | 'docker-denied'
  | 'container-missing'
  | 'container-stopped'

export interface LogDiagnosis {
  issue: LogTailIssue
  /** Root was used for this tail. True for its whole life, not for a moment. */
  usedSudo: boolean
  /** Passwordless sudo exists here, so "retry as root" is worth offering. */
  sudoAvailable: boolean
  /** Running, but with nothing to show yet — and possibly never. */
  waiting: boolean
}

export const LOG_ISSUE_HELP: Record<LogTailIssue, string> = {
  ok: '',
  'no-journal':
    'No journalctl on this server, so it is not running systemd — Alpine, a container, or a pre-systemd distribution. Switch to File and give a path such as /var/log/messages.',
  'no-tail': 'No tail on the PATH an SSH session gets, which is unusual enough to be worth checking by hand.',
  'unit-not-loaded':
    'systemd does not know this unit. Check the name: journalctl will follow a unit that does not exist and show you nothing at all.',
  'unit-masked': 'This unit is masked, so it cannot run and will not be logging.',
  'journal-unreadable':
    'The journal returned nothing for this unit and this account is not root, nor in systemd-journal, adm or wheel. An empty pane here does NOT mean the service is quiet — it means you are not being shown what it said.',
  'unit-quiet': 'The unit exists and its journal is readable, so it genuinely has not logged anything in this window.',
  'file-missing':
    'That path does not exist yet. tail -F keeps waiting and picks the file up the moment it appears — right when you are watching for a log about to be written, and an empty pane forever otherwise.',
  'file-denied':
    'That file exists but this account cannot read it. /var/log/secure and /var/log/audit/audit.log are root-only on most servers.',
  'file-is-dir': 'That path is a directory, not a file.',
  'no-docker':
    'No docker on this server. Looked on PATH and in the usual install directories — if it lives somewhere else, a symlink into /usr/local/bin is the usual fix.',
  'docker-denied':
    'This account cannot reach the docker socket, so it cannot read container logs. Adding it to the docker group grants root-equivalent access on most installs, which is a decision worth making deliberately.',
  'container-missing':
    'No container with that name or id on this server. It may have been removed, or the name may belong to a different server.',
  'container-stopped':
    'That container is not running. Its logs are still readable — this is history, not a live stream, and nothing new will arrive until it starts again.'
}

/** Groups systemd's own tmpfiles ACLs grant read on the journal. */
const JOURNAL_GROUPS = ['systemd-journal', 'adm', 'wheel']

/**
 * Turn preflight facts into the one thing the panel should say.
 *
 * Pure, and deliberately not clever: the ORDER is the design. A unit systemd
 * does not know is reported as such even when the journal is also unreadable,
 * because the name is what the user got wrong and a permissions message would
 * send them to fix a host that is fine.
 */
export function diagnoseLogTail(facts: Record<string, string>): LogDiagnosis {
  const usedSudo = facts.sudo === '1'
  const sudoAvailable = facts['sudo-avail'] === '1'
  const base = { usedSudo, sudoAvailable }

  if (facts.journal === 'missing') return { ...base, issue: 'no-journal', waiting: false }
  if (facts.tailbin === 'missing') return { ...base, issue: 'no-tail', waiting: false }

  if (facts.docker === 'missing') return { ...base, issue: 'no-docker', waiting: false }
  if (facts.container !== undefined) {
    // Denial first: a socket this account cannot reach cannot tell us whether
    // the container exists, so "missing" there would be a guess dressed as a
    // fact. Root getting us in means the read is no longer denied, which is
    // what `usedSudo` already carries.
    if (facts.container === 'denied' && !usedSudo) {
      return { ...base, issue: 'docker-denied', waiting: false }
    }
    if (facts.container === 'absent') return { ...base, issue: 'container-missing', waiting: false }
    // Not an error, and not styled as one: a stopped container's logs are the
    // reason you are looking, and `docker logs -f` on one is history that
    // simply will not grow.
    if (facts.container === 'stopped') return { ...base, issue: 'container-stopped', waiting: true }
    return { ...base, issue: 'ok', waiting: false }
  }

  if (facts.file !== undefined) {
    if (facts.file === 'dir') return { ...base, issue: 'file-is-dir', waiting: false }
    if (facts.file === 'missing') return { ...base, issue: 'file-missing', waiting: true }
    // Root got us in, so the read is no longer denied — but that it took root
    // is the part the operator has to keep in view, which `usedSudo` carries.
    if (facts.file === 'denied' && !usedSudo) return { ...base, issue: 'file-denied', waiting: false }
    return { ...base, issue: 'ok', waiting: false }
  }

  const load = facts['unit-load']
  if (load === 'masked') return { ...base, issue: 'unit-masked', waiting: false }
  // `unknown` means systemctl could not be asked at all, which is not evidence
  // the unit name is wrong. Only systemd's own answer is.
  if (load === 'not-found') return { ...base, issue: 'unit-not-loaded', waiting: false }

  if (facts.entries === '0') {
    // The probe ran unprivileged, so an escalated tail may show entries it
    // could not see. Calling the unit quiet there would be a lie.
    if (usedSudo) return { ...base, issue: 'ok', waiting: false }
    if (facts.priv === '0') return { ...base, issue: 'journal-unreadable', waiting: true }
    return { ...base, issue: 'unit-quiet', waiting: true }
  }
  return { ...base, issue: 'ok', waiting: false }
}

/**
 * What `--since` may contain.
 *
 * journalctl's time grammar needs spaces (`2 hours ago`, `yesterday`,
 * `2024-01-01 09:30:00`), so unlike every other value in this module it cannot
 * be passed as a bare word and has to be quoted. Quoting is a promise about a
 * shell, which this module otherwise refuses to make — so the promise is made
 * defensible by the character class instead. It admits no quote, no backslash,
 * no `$` and no backtick, which is every construct that means anything inside
 * single quotes; a value that passes cannot end the word it is placed in. Safe
 * by construction rather than by care.
 */
const SINCE_RE = /^[A-Za-z0-9 :,._+-]{1,48}$/

export function validateSince(v: string): boolean {
  return SINCE_RE.test(v.trim())
}

export function validatePriority(v: string): v is LogPriority {
  return (LOG_PRIORITIES as readonly string[]).includes(v)
}

/**
 * Match one line against the pane's filter.
 *
 * Client-side on the ring on purpose: filtering remotely would mean restarting
 * the stream on every keystroke and losing the buffer, which is the opposite of
 * what someone narrowing down an incident wants.
 *
 * Three forms, because they are the three already in a sysadmin's fingers:
 * plain text is a case-insensitive substring, `/re/` is a regular expression,
 * and a leading `!` inverts it (grep -v, which is how a heartbeat gets out of
 * the way).
 *
 * Never throws. A half-typed regex is the normal state of an input someone is
 * still typing into, and a filter that throws mid-keystroke takes the pane with
 * it — so an unparseable expression is matched literally instead.
 */
export function logLineMatches(text: string, query: string): boolean {
  const q = query.trim()
  if (q === '') return true
  const negate = q.startsWith('!')
  const body = negate ? q.slice(1).trim() : q
  if (body === '') return true
  const asRegex = body.length >= 2 && body.startsWith('/') && body.endsWith('/') ? body.slice(1, -1) : null
  let hit: boolean
  if (asRegex !== null) {
    try {
      hit = new RegExp(asRegex, 'i').test(text)
    } catch {
      // The inner text rather than the whole `/.../`: the slashes were the
      // user's way of saying "this is a pattern", not part of what they are
      // looking for, and matching them literally finds nothing at all.
      hit = text.toLowerCase().includes(asRegex.toLowerCase())
    }
  } else {
    hit = text.toLowerCase().includes(body.toLowerCase())
  }
  return negate ? !hit : hit
}

export function filterLogLines<T extends { text: string }>(lines: T[], query: string): T[] {
  if (query.trim() === '') return lines
  return lines.filter((l) => logLineMatches(l.text, query))
}

/**
 * The number of history lines, made safe to interpolate.
 *
 * Same reasoning as docker's `validTailCount`: this is exported machinery, and
 * refusing rubbish here rather than trusting the caller is the rule every other
 * builder in this module already follows.
 */
function validHistory(lines: unknown): number {
  if (typeof lines !== 'number' || !Number.isInteger(lines) || lines < 1 || lines > 100_000) {
    throw new Error('refusing to build a command from an invalid history line count')
  }
  return lines
}

const mark = (kv: string): string => `printf '%s\\n' '${LOG_MARK}${kv}'`
const markVar = (key: string, shellVar: string): string => `printf '%s%s\\n' '${LOG_MARK}${key}=' "$${shellVar}"`

/**
 * The block that decides whether this read becomes root, and says so.
 *
 * The decision is made in the shell rather than in a second round trip because
 * a tail is a long-lived stream: restarting one to escalate would drop the
 * channel, re-emit the history and lose whatever the pane had. Docker can
 * afford a retry; this cannot.
 *
 * The discipline is docker's regardless — `SUDO_PROBE` verbatim, so there is
 * exactly one definition of "can this account become root without a prompt" —
 * and `cond` is the "only when it would help" half: root is not asked for when
 * the unprivileged read already worked.
 */
function sudoBlock(mode: LogSudoMode, cond: string): string {
  if (mode === 'never') return [`SP_SUDO=""`, mark('sudo-avail=0'), mark('sudo=0')].join('; ')
  return [
    `SP_SUDO=""`,
    `SP_SA=0`,
    `case "$(${SUDO_PROBE})" in *SP_SUDO_OK*) SP_SA=1 ;; esac`,
    markVar('sudo-avail', 'SP_SA'),
    `if [ "$SP_SA" = 1 ] && ${mode === 'always' ? 'true' : cond}; then SP_SUDO="sudo -n"; fi`,
    `SP_US=0`,
    `[ -n "$SP_SUDO" ] && SP_US=1`,
    markVar('sudo', 'SP_US')
  ].join('; ')
}

/**
 * The remote command for a source: a preflight, then the tail itself.
 *
 * Never interpolates unvalidated text: callers must run `validateLogSource`
 * first, and `buildTailCommand` throws rather than producing a command from
 * input it has not checked. A function that quietly returns a broken command
 * is how a validator gets skipped once and forgotten.
 *
 * `journalctl` gets `--no-pager -n` so the first screen is history rather than
 * an empty pane that only fills when something new happens — the failure being
 * investigated has usually already happened.
 *
 * Why the preflight is in the SAME command rather than a round trip of its own:
 * a separate probe answers a question about a moment that has passed by the
 * time the tail opens its own channel, and it doubles the connection setup on
 * every host in the fan-out. Here the facts and the stream come from one shell
 * on one channel, and the last thing the preflight does is `exec` — so the
 * process holding the channel is journalctl itself, exactly as before.
 */
export function buildTailCommand(source: LogSource, historyLines = 200): string {
  const v = validateLogSource(source)
  if (!v.ok) throw new Error(`refusing to build a command from an invalid source: ${v.error}`)
  const t = source.target.trim()
  const n = validHistory(historyLines)
  const sudo = source.sudo ?? 'auto'

  if (source.kind === 'unit') {
    // Severity and time window: the two flags people actually reach for during
    // an incident. Both are applied to the history probe as well as the tail,
    // so "is this unit's journal empty" answers the question the user asked
    // rather than a broader one — otherwise `-p err` on a chatty unit would
    // report entries and then show an empty pane.
    const p = source.priority ? ` -p ${source.priority}` : ''
    const since = source.since && source.since.trim() !== '' ? ` --since '${source.since.trim()}'` : ''
    return [
      // A non-login ssh shell's PATH is roughly /usr/bin:/bin. journalctl is
      // normally in /usr/bin, but a host with /usr merged oddly, or a
      // container, is exactly where this feature gets used.
      resolveBinary('journalctl'),
      `if command -v "$SP_BIN" >/dev/null 2>&1; then ${mark('journal=present')}`,
      // `--value` needs systemd 230+; the sed form works on every version.
      `SP_LOAD=$(systemctl show -p LoadState ${t} 2>/dev/null | sed 's/^LoadState=//')`,
      `[ -z "$SP_LOAD" ] && SP_LOAD=unknown`,
      markVar('unit-load', 'SP_LOAD'),
      // LoadState only. ActiveState was collected here too and nothing read it:
      // whether the unit is running is what the Fleet Monitor the user came
      // from already shows, and a fact gathered for nobody is a round trip
      // spent to make a diagnosis look thorough.
      // Does this account get to see ANY entry for this unit? journald answers
      // an unauthorised read with silence, not an error, so the only way to tell
      // "quiet" from "not allowed" is to ask for one line and notice nothing
      // came back. `grep -v '^-- '` drops journalctl's own furniture
      // ("-- No entries --", "-- Journal begins at ... --"), which is printed
      // on stdout and would otherwise read as an entry.
      `SP_E=0`,
      `[ -n "$("$SP_BIN" --no-pager -q -n 1 --output=short-iso -u ${t}${p}${since} 2>/dev/null | grep -v '^-- ' | head -n 1)" ] && SP_E=1`,
      markVar('entries', 'SP_E'),
      // Who may read the system journal: root, and the groups systemd's own
      // tmpfiles ACLs grant — systemd-journal, plus adm and wheel on the
      // distributions that add them. This is the fact that turns an empty pane
      // from "quiet service" into "you are not being shown this".
      `SP_P=0`,
      `[ "$(id -u 2>/dev/null)" = 0 ] && SP_P=1`,
      `case " $(id -nG 2>/dev/null) " in ${JOURNAL_GROUPS.map((g) => `*' ${g} '*`).join('|')}) SP_P=1 ;; esac`,
      markVar('priv', 'SP_P'),
      sudoBlock(sudo, `[ "$SP_E" = 0 ] && [ "$SP_P" = 0 ]`),
      mark('begin=1'),
      `exec $SP_SUDO "$SP_BIN" --no-pager --output=short-iso -n ${n} -f -u ${t}${p}${since} 2>&1`,
      `else ${mark('journal=missing')}; fi`
    ].join('; ')
  }

  if (source.kind === 'container') {
    // The same preflight discipline the other two kinds get, for the same
    // reason: `docker logs` on a refused socket, a removed container and a
    // stopped one all produce a dead pane, and they need three different
    // sentences.
    //
    // `docker inspect -f {{.State.Running}}` answers existence and state in
    // one call. Its stderr is captured rather than dropped so a socket refusal
    // is distinguishable from a container that is simply not there.
    return [
      resolveBinary('docker'),
      `if command -v "$SP_BIN" >/dev/null 2>&1; then ${mark('docker=present')}`,
      `SP_INSPECT=$("$SP_BIN" inspect -f '{{.State.Running}}' ${t} 2>&1)`,
      `SP_C=absent`,
      `case "$SP_INSPECT" in true) SP_C=running ;; false) SP_C=stopped ;; ` +
        `*'permission denied'*|*'Got permission denied'*) SP_C=denied ;; esac`,
      markVar('container', 'SP_C'),
      sudoBlock(sudo, `[ "$SP_C" = denied ]`),
      // Re-ask as root, or the panel reports a denial it has just escalated
      // past and the stream that follows contradicts the banner above it.
      // The re-ask needs a default. Without one, a container that does not exist
      // stayed `denied` from the unprivileged attempt, the diagnosis saw
      // denied+usedSudo and called it `ok`, and `docker logs` then printed
      // "No such container" straight into the pane as if it were a log line.
      // Reported from a real host: the panel showed a compose service name,
      // that name is not the container's, and the tail said nothing useful.
      `if [ -n "$SP_SUDO" ]; then SP_INSPECT=$($SP_SUDO "$SP_BIN" inspect -f '{{.State.Running}}' ${t} 2>&1); ` +
        `case "$SP_INSPECT" in true) SP_C=running ;; false) SP_C=stopped ;; *) SP_C=absent ;; esac; ` +
        `${markVar('container', 'SP_C')}; fi`,
      // Do not follow a container that is not there. `tail -F` waits for a file
      // because a file appearing is a thing that happens; a container id does
      // not materialise, so running `docker logs` on it only produces a daemon
      // error dressed as content.
      `if [ "$SP_C" = absent ]; then ${mark('begin=1')}; exit 0; fi`,
      mark('begin=1'),
      `exec $SP_SUDO "$SP_BIN" logs --tail ${n} -f ${t} 2>&1`,
      `else ${mark('docker=missing')}; fi`
    ].join('; ')
  }

  // The parent directory, so a file inside a directory this account cannot even
  // traverse is reported as denied rather than missing. /var/log/audit is 0700
  // root on every distribution that ships auditd, so `[ -e audit.log ]` is
  // false there for reasons that have nothing to do with the file existing —
  // and "that path does not exist" would send someone to look for a log that is
  // sitting right where they think it is.
  const parent = t.slice(0, t.lastIndexOf('/')) || '/'
  return [
    resolveBinary('tail'),
    `if command -v "$SP_BIN" >/dev/null 2>&1; then SP_F=missing`,
    `if [ -d ${t} ]; then SP_F=dir; elif [ -r ${t} ]; then SP_F=ok; elif [ -e ${t} ]; then SP_F=denied; elif [ -d ${parent} ] && [ ! -x ${parent} ]; then SP_F=denied; fi`,
    markVar('file', 'SP_F'),
    sudoBlock(sudo, `[ "$SP_F" = denied ]`),
    mark('begin=1'),
    // -F rather than -f: a rotated file is the normal case on a log, and -f
    // silently follows the old inode forever after logrotate runs. It is also
    // why a missing file is followed rather than refused — the file appearing
    // is a thing that happens.
    `exec $SP_SUDO "$SP_BIN" -n ${n} -F ${t} 2>&1`,
    `else ${mark('tailbin=missing')}; fi`
  ].join('; ')
}

/**
 * List the units on a host, so the unit field can be chosen rather than typed.
 *
 * Typing a unit name from memory is how you get "systemd does not know this
 * unit" — which the panel now says, but not making the mistake beats explaining
 * it. `list-units --all` includes loaded-but-inactive units, which is most of
 * what you want to tail: a service that just died is exactly the one being
 * investigated.
 *
 * `--no-legend --plain` so there is no header, no bullet column and no
 * "N loaded units listed" footer to strip.
 */
export function buildUnitListCommand(): string {
  return [
    resolveBinary('systemctl'),
    // --no-pager, or systemctl pipes into less and the exec never returns.
    `"$SP_BIN" list-units --type=service --all --no-legend --plain --no-pager 2>&1`
  ].join('; ')
}

export interface UnitChoice {
  name: string
  /** loaded | not-found | masked — a not-found unit cannot be tailed. */
  load: string
  active: string
  sub: string
  description: string
}

/**
 * Parse `systemctl list-units --plain --no-legend`.
 *
 * Rejects by SHAPE, not content: a unit named `error-reporter.service` is an
 * ordinary thing to have, and matching an error word against data lines is the
 * bug that ate a namespace list in the Kubernetes module.
 */
export function parseUnitList(output: string): UnitChoice[] {
  const units: UnitChoice[] = []
  for (const raw of output.split('\n')) {
    const line = raw.trim()
    if (line === '') continue
    const f = line.split(/\s+/)
    // UNIT LOAD ACTIVE SUB DESCRIPTION… — a real row has at least four columns
    // and its first ends in .service.
    if (f.length < 4 || !/\.service$/.test(f[0])) continue
    units.push({
      name: f[0],
      load: f[1],
      active: f[2],
      sub: f[3],
      description: f.slice(4).join(' ')
    })
  }
  return units.sort((a, b) => a.name.localeCompare(b.name))
}

/**
 * Log files on a host, so File mode is pickable rather than remembered.
 *
 * Bounded deliberately: `/var/log` on a busy host has thousands of rotated
 * files, and an autocomplete is not an archive browser. Depth 2 covers the
 * directories that matter (nginx/, apache2/, audit/) without walking a year of
 * gzipped history, and the rotated suffixes are excluded because tailing
 * `syslog.3.gz` is not a thing anyone means to do.
 *
 * `-readable` is not POSIX find, so readability is tested per file instead —
 * a file this account cannot open is worth OFFERING, because the tail's own
 * preflight will then say it is denied and offer root, which is a better
 * answer than the file being invisible.
 */
export function buildLogFileListCommand(): string {
  // The loop is statements joined by `;`; the filters are a PIPELINE off the
  // end of it. Those are different joins, so they are written differently.
  //
  // This was one array joined with '; ' and then repaired by
  // `.replace('; |', ' |')` — which takes a string, so it fixed only the FIRST
  // of the two, and every command this ever built ended `...$'; | sort -u`.
  // That is a shell syntax error, so the File picker returned nothing on every
  // host it has ever run against. Nothing said so: the renderer swallows the
  // failure and the button simply stays disabled, with a tooltip blaming the
  // absence on no server being selected.
  const scan = [
    'for d in /var/log /var/log/nginx /var/log/apache2 /var/log/httpd /var/log/audit',
    'do [ -d "$d" ] || continue',
    // -maxdepth 1 per directory rather than one deep walk: it keeps the output
    // bounded per directory instead of letting one noisy tree fill the budget.
    'find "$d" -maxdepth 1 -type f 2>/dev/null',
    'done'
  ].join('; ')
  // Rotated and compressed files are noise in a picker.
  return `${scan} | grep -vE '\\.(gz|xz|bz2|zst|[0-9]+)$' | sort -u | head -n 200`
}

/** Absolute paths only, and nothing that could not be tailed. */
export function parseLogFileList(output: string): string[] {
  const seen = new Set<string>()
  for (const raw of output.split('\n')) {
    const line = raw.trim()
    // Decided by SHAPE: an absolute path with no whitespace and no shell
    // metacharacter. A `find: ... Permission denied` line on stderr is a
    // sentence with spaces and cannot be mistaken for one.
    if (!line.startsWith('/') || /\s/.test(line)) continue
    if (!PATH_RE.test(line)) continue
    seen.add(line)
  }
  return [...seen].sort()
}
