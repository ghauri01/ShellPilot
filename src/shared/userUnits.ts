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
