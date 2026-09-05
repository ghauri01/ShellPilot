// What the SERVER supervises for this account — `systemd --user`.
//
// This is item 1's named successor, and the argument for it is written at the
// top of ./processes.ts: supervising a remote process over an SSH channel we
// hold open is a reliability promise this transport does not make, because the
// app is not there when the laptop lid closes. The honest version is to
// TRANSLATE — let the server's own supervisor own the restart policy, and read
// back what it is doing. The server is there when we are not.
//
// The read half only. Nothing here writes a unit file.
//
// ===========================================================================
// THE ONE FACT THIS EXISTS TO REPORT
// ===========================================================================
//
// A `--user` service runs for as long as the user has a session, and STOPS
// WHEN THE LAST ONE ENDS — unless that account is lingering. Observed on RHEL
// 9.8 with systemd 252, which is the case that matters:
//
//   * `su - ops` opens a session, so logind creates /run/user/1000, starts a
//     user manager, and `systemctl --user list-units` answers normally. A
//     service started that way reads as `active running`.
//   * The same account, checked from outside that session:
//         Failed to get user: User ID 1001 is not logged in or lingering
//   * With `loginctl enable-linger`:
//         Linger=yes
//
// So a panel that lists units over SSH and stops there tells an operator their
// service is running, when what it is actually looking at is a service that
// will be killed the moment the connection closes. That is the same failure
// shape as item 23's KillUserProcesses: the reading is true and the conclusion
// is wrong, and only the second question separates them.

import { resolveBinary } from './docker'

export const USER_UNIT_MARKERS = {
  linger: '===SHELLPILOT-LINGER===',
  units: '===SHELLPILOT-USERUNITS==='
} as const

/**
 * How well this account's user manager could be read.
 *
 * The same vocabulary the access and posture collectors use, for the same
 * reason: "no services" and "could not ask" are different facts with different
 * fixes, and a reader that returns an empty list for both is lying about one.
 */
export type UserUnitsStatus =
  | 'ok'
  /** systemctl is not installed. */
  | 'no-tool'
  /** systemctl is there and PID 1 is not systemd — every container built from
   *  a distro image, and the reason this is not folded into `no-tool`. */
  | 'unsupported'
  /** The user bus could not be reached. Almost always the linger case below,
   *  and the message is kept so an operator can tell. */
  | 'no-bus'
  | 'denied'
  | 'unknown'

export type LingerState = 'lingering' | 'not-lingering' | 'unknown'

export interface UserUnit {
  name: string
  /** `loaded`, `not-found`, `masked`. */
  load: string
  /** `active`, `inactive`, `failed`, `activating`. */
  active: string
  /** `running`, `dead`, `exited`, `failed`. */
  sub: string
  description: string
}

export interface UserUnitsReading {
  status: UserUnitsStatus
  linger: LingerState
  units: UserUnit[]
  /** The server's own words when something went wrong. Never paraphrased. */
  detail?: string
}

/**
 * `loginctl show-user NAME -p Linger`.
 *
 * It does NOT print `Linger=no` for an account with no session. It fails:
 *
 *     Failed to get user: User ID 1001 is not logged in or lingering
 *
 * which is the answer, not an error — the account is not lingering. Reading
 * that failure as `unknown` would drop the warning in exactly the case the
 * warning is for, because an account nobody is logged into is precisely where
 * a service quietly is not running.
 */
export function parseLinger(text: string | undefined): LingerState {
  const s = (text ?? '').trim()
  if (s === '') return 'unknown'
  if (/^Linger=yes$/im.test(s)) return 'lingering'
  if (/^Linger=no$/im.test(s)) return 'not-lingering'
  if (/not logged in or lingering/i.test(s)) return 'not-lingering'
  return 'unknown'
}

/** Failures the user bus gives, which are not "no units". */
const NO_BUS = [
  /Failed to connect to bus/i,
  /No medium found/i,
  /Could not activate remote peer/i,
  /Refusing to operate without a bus/i
]

const NOT_SYSTEMD = [
  /System has not been booted with systemd/i,
  /Failed to get D-Bus connection/i,
  /Running in chroot/i
]

/**
 * One `systemctl --user list-units --plain --no-legend` row.
 *
 * Five columns, whitespace separated, DESCRIPTION last and containing spaces —
 * so the split is bounded at four and the remainder is the description. A
 * greedy split loses every description with a space in it, which is all of
 * them.
 *
 * A failed unit is prefixed with a marker glyph in some systemd versions and
 * indented in others; both are stripped before the name is read.
 */
export function parseUserUnitRow(line: string): UserUnit | null {
  const cleaned = line.replace(/^[\s●✘*x]+/u, '')
  if (cleaned === '') return null
  const parts = cleaned.split(/\s+/)
  if (parts.length < 4) return null
  const [name, load, active, sub] = parts
  if (!name.endsWith('.service')) return null
  return {
    name,
    load,
    active,
    sub,
    description: parts.slice(4).join(' ')
  }
}

export function parseUserUnits(output: string, exitCode: number | null): UserUnitsReading {
  const text = output ?? ''
  const lingerPart = text.split(USER_UNIT_MARKERS.linger)[1]?.split(USER_UNIT_MARKERS.units)[0] ?? ''
  const unitsPart = text.split(USER_UNIT_MARKERS.units)[1] ?? ''
  const linger = parseLinger(lingerPart)

  if (/no systemctl/i.test(text) || /command not found/i.test(unitsPart)) {
    return { status: 'no-tool', linger, units: [], detail: 'This server has no systemctl.' }
  }
  if (NOT_SYSTEMD.some((re) => re.test(unitsPart))) {
    return {
      status: 'unsupported',
      linger,
      units: [],
      detail: unitsPart.trim().split('\n')[0]
    }
  }
  if (NO_BUS.some((re) => re.test(unitsPart))) {
    return {
      status: 'no-bus',
      linger,
      units: [],
      detail: unitsPart.trim().split('\n')[0]
    }
  }
  if (/permission denied|access denied/i.test(unitsPart)) {
    return { status: 'denied', linger, units: [], detail: unitsPart.trim().split('\n')[0] }
  }

  const units = unitsPart
    .split('\n')
    .map(parseUserUnitRow)
    .filter((u): u is UserUnit => u !== null)

  if (units.length === 0 && exitCode !== 0 && unitsPart.trim() !== '') {
    return { status: 'unknown', linger, units: [], detail: unitsPart.trim().split('\n')[0] }
  }
  return { status: 'ok', linger, units }
}

/**
 * The sentence the panel leads with.
 *
 * Running units plus a non-lingering account is the case worth interrupting
 * somebody for, and it is stated as what will HAPPEN rather than as a
 * configuration fact: "linger is disabled" is true and means nothing to most
 * people, and "these stop when you log out" is the same fact and is actionable.
 */
export function summariseUserUnits(r: UserUnitsReading): {
  level: 'ok' | 'watch' | 'alarm' | 'unknown'
  headline: string
} {
  if (r.status === 'no-tool' || r.status === 'unsupported') {
    return { level: 'unknown', headline: r.detail ?? 'This server does not run systemd.' }
  }
  if (r.status === 'no-bus') {
    return {
      level: 'unknown',
      headline:
        'Could not reach this account’s user manager. That usually means the account is not lingering and has no open session — run `loginctl enable-linger` on the server for it to supervise anything while you are away.'
    }
  }
  if (r.status === 'denied') return { level: 'unknown', headline: 'Not allowed to read the user manager.' }
  if (r.status === 'unknown') return { level: 'unknown', headline: r.detail ?? 'No answer.' }

  const failed = r.units.filter((u) => u.active === 'failed')
  const running = r.units.filter((u) => u.sub === 'running')

  if (r.linger === 'not-lingering' && running.length > 0) {
    return {
      level: 'alarm',
      headline: `${running.length} service(s) are running, but this account is not lingering — they stop when your last session ends. Run \`loginctl enable-linger\` on the server to keep them.`
    }
  }
  if (failed.length > 0) {
    return { level: 'alarm', headline: `${failed.length} user service(s) have failed` }
  }
  if (running.length === 0) {
    return { level: 'ok', headline: 'No user services are running' }
  }
  return {
    level: 'ok',
    headline: `${running.length} user service(s) running, supervised by the server`
  }
}

/**
 * One round trip: is this account lingering, and what does its manager run.
 *
 * `XDG_RUNTIME_DIR` is set explicitly. A non-login `ssh host cmd` frequently
 * has none, and without it `systemctl --user` cannot find the bus even when a
 * manager is running — which is a failure of the ENVIRONMENT we handed it, not
 * a fact about the server, and reporting it as one would be our bug shown as
 * theirs. `id -u` rather than a literal, because the account is whoever
 * ShellPilot connected as.
 *
 * `|| true` after each read: a missing loginctl must not take the units with
 * it, and the marker layout is what tells the two halves apart afterwards.
 * Read-only throughout — no `start`, no `enable`, no `daemon-reload`.
 */
export function buildUserUnitsCommand(): string {
  return [
    resolveBinary('systemctl'),
    '[ -z "$SP_BIN" ] && echo "no systemctl" >&2',
    `SP_LOGINCTL=""; for c in loginctl /usr/bin/loginctl /bin/loginctl; do ` +
      `command -v "$c" >/dev/null 2>&1 && SP_LOGINCTL="$c" && break; done`,
    `echo "${USER_UNIT_MARKERS.linger}"`,
    '[ -n "$SP_LOGINCTL" ] && "$SP_LOGINCTL" show-user "$(id -un)" -p Linger 2>&1 || true',
    `echo "${USER_UNIT_MARKERS.units}"`,
    'XDG_RUNTIME_DIR="${XDG_RUNTIME_DIR:-/run/user/$(id -u)}" ' +
      '"$SP_BIN" --user list-units --type=service --all --no-legend --plain --no-pager 2>&1 || true'
  ].join('; ')
}

// ---------------------------------------------------------------------------
// The editor
// ---------------------------------------------------------------------------
//
// Writing a `systemd --user` unit is item 1's other half, and it inherits the
// finding that came out of item 23 on the same afternoon: a `--user` unit on a
// server with `KillUserProcesses=yes` and no linger is a unit that stops the
// moment you disconnect. Measured, not assumed. So this refuses to install one
// rather than writing a service that will not be there.

/** Unit names systemd will accept and a shell will not reinterpret. */
const UNIT_NAME_RE = /^[A-Za-z0-9][A-Za-z0-9_.@-]{0,62}\.service$/

/**
 * An ExecStart this is willing to write.
 *
 * ABSOLUTE PATH, and no shell metacharacters. systemd does not run ExecStart
 * through a shell — `ExecStart=/bin/sh -c "..."` is how people get one — so a
 * `;` in here does not become a second command the way it would in a job step.
 * It is refused anyway, because the difference between "systemd will not
 * interpret this" and "nothing downstream will ever interpret this" is one
 * refactor, and this string is written to a file on somebody's server.
 */
const EXEC_START_RE = /^\/[^\s;|&`$()<>\n]*(?: [^\s;|&`$()<>\n]+)*$/

export type UnitRestart = 'no' | 'on-failure' | 'always'

export interface UnitDraft {
  name: string
  description: string
  execStart: string
  restart: UnitRestart
  workingDirectory?: string
}

export type UnitDraftRefusal =
  | { ok: true }
  | { ok: false; reason: string }

/**
 * Whether this draft may be written at all.
 *
 * Every refusal names the field and what would happen, because "invalid unit"
 * sends somebody to read systemd's manual about a rule this app invented.
 */
export function checkUnitDraft(d: UnitDraft): UnitDraftRefusal {
  if (!UNIT_NAME_RE.test(d.name)) {
    return {
      ok: false,
      reason:
        'The unit name must look like `worker.service` — letters, digits, dot, dash, underscore or @, and it has to end in .service.'
    }
  }
  if (!EXEC_START_RE.test(d.execStart)) {
    return {
      ok: false,
      reason:
        'ExecStart has to be an absolute path with plain arguments. systemd does not run it through a shell, so a pipe or a semicolon here would not do what it looks like it does.'
    }
  }
  if (d.description.includes('\n')) {
    return { ok: false, reason: 'The description has to be one line.' }
  }
  if (d.workingDirectory !== undefined && !d.workingDirectory.startsWith('/')) {
    return { ok: false, reason: 'The working directory has to be an absolute path.' }
  }
  return { ok: true }
}

/** The unit file itself. Deterministic, so a diff of two of these is readable. */
export function renderUnitFile(d: UnitDraft): string {
  const lines = [
    '# Written by ShellPilot. Edit here or on the server; ShellPilot reads it back either way.',
    '[Unit]',
    `Description=${d.description}`,
    '',
    '[Service]',
    `ExecStart=${d.execStart}`,
    `Restart=${d.restart}`
  ]
  if (d.workingDirectory !== undefined) lines.push(`WorkingDirectory=${d.workingDirectory}`)
  lines.push('', '[Install]', 'WantedBy=default.target', '')
  return lines.join('\n')
}

/**
 * Install a unit, or refuse.
 *
 * THE PRECONDITION IS THE SAME ONE ITEM 23 LEARNED THE HARD WAY, and it is
 * checked here for the same reason. On a server whose logind has
 * `KillUserProcesses=yes`, a `--user` service belonging to an account that is
 * not lingering stops the moment the last session ends. Installing one there
 * and reporting success would hand somebody a service that is not running by
 * the time they close the terminal — measured on RHEL 9.8, systemd 252, over a
 * real session that was then closed.
 *
 * The existing file is backed up first, with `cp -p`, into a name carrying the
 * token. Same rule as the key write: a backup the operator can find in a shell
 * is worth more than any rollback this app can offer.
 *
 * No `--now`. The unit is written and enabled; STARTING it is a separate act,
 * because writing a file and executing a command are different decisions and
 * this returns the command that does the second one.
 */
export function buildUnitWriteCommand(d: UnitDraft, token: string): string {
  const check = checkUnitDraft(d)
  if (!check.ok) throw new Error(`refusing to write a unit: ${check.reason}`)
  if (!/^[A-Za-z0-9]{4,32}$/.test(token)) {
    throw new Error('refusing to write a unit with an unvalidated token')
  }
  const body = renderUnitFile(d)
  return [
    resolveBinary('systemctl'),
    '[ -z "$SP_BIN" ] && { echo "this server has no systemctl" >&2; exit 2; }',
    'SP_LINGER=no',
    'command -v loginctl >/dev/null 2>&1 && loginctl show-user "$(id -un)" -p Linger 2>/dev/null | grep -q "^Linger=yes$" && SP_LINGER=yes',
    'SP_KILL=no',
    'command -v busctl >/dev/null 2>&1 && busctl get-property org.freedesktop.login1 /org/freedesktop/login1 org.freedesktop.login1.Manager KillUserProcesses 2>/dev/null | grep -q "true" && SP_KILL=yes',
    // Refuse, rather than install a service that stops when the session does.
    '[ "$SP_KILL" = yes ] && [ "$SP_LINGER" = no ] && { echo "this server stops a user’s processes when their last session ends (logind KillUserProcesses=yes) and this account is not lingering, so this service would stop the moment you disconnect; nothing was written. Run: loginctl enable-linger $(id -un)" >&2; exit 6; }',
    'SP_DIR="$HOME/.config/systemd/user"',
    'mkdir -p "$SP_DIR" || { echo "could not create $SP_DIR" >&2; exit 3; }',
    `SP_UNIT="$SP_DIR/${d.name}"`,
    `SP_BAK="$SP_UNIT.shellpilot-${token}.bak"`,
    // Only when one is already there: a backup of nothing is a confusing file
    // to find later.
    '[ -f "$SP_UNIT" ] && { cp -p "$SP_UNIT" "$SP_BAK" || { echo "the existing unit could not be backed up, so nothing was written" >&2; exit 4; }; }',
    `SP_TMP="$SP_UNIT.shellpilot-${token}.tmp"`,
    // BASE64, NOT A HEREDOC, and the difference was found by running it.
    //
    // Every fragment here is joined with '; ', which puts the next command on
    // the same logical line as the heredoc's terminator — so `<<'EOF'` never
    // finds its EOF, bash warns "here-document delimited by end-of-file", and
    // the unit file is never written. The command still exits 0. A test
    // asserting "the command contains a heredoc" passes on that.
    //
    // Encoded content has no terminator to lose and no quoting to get wrong,
    // and `base64 -d` is in coreutils and busybox alike.
    `printf %s ${Buffer.from(body, 'utf8').toString('base64')} | base64 -d > "$SP_TMP" || { echo "the unit body could not be written" >&2; exit 5; }`,
    // Renamed into place, so a reader never sees half a unit file.
    'mv "$SP_TMP" "$SP_UNIT" || { rm -f "$SP_TMP"; echo "the unit could not be written" >&2; exit 5; }',
    'XDG_RUNTIME_DIR="${XDG_RUNTIME_DIR:-/run/user/$(id -u)}" "$SP_BIN" --user daemon-reload 2>&1',
    `XDG_RUNTIME_DIR="\${XDG_RUNTIME_DIR:-/run/user/$(id -u)}" "$SP_BIN" --user enable ${d.name} 2>&1`,
    `echo "WROTE: $SP_UNIT"`
  ].join('; ')
}
