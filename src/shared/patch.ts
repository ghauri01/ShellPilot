import {
  FACT_STATUS_HELP,
  factSource,
  type FactStatus,
  type HostFacts,
  type PackageManager
} from './hostFacts'
import type { JobSpec, JobStep, JobTargetRef } from './jobs'
import {
  buildTopology,
  dependentsOf,
  rebootBlockFor,
  sameWaveDatabaseBlocks,
  unmatchedHopNote,
  type RebootBlock,
  type Topology,
  type TopologyDatabase,
  type TopologyServer
} from './topology'

// Patch and update management — roadmap item 17.
//
// The most common recurring task in the job this app is named for, and the
// first thing in ShellPilot that does it. Everything it stands on already
// exists: item C collects the counts (shared/hostFacts.ts), B1/B2 make a job
// durable and detached, B3 makes its approval a record, and B4's staging lives
// here rather than being paid for twice.
//
// ===========================================================================
// WHAT THIS WILL NOT DO: DECIDE WHETHER TO PATCH
// ===========================================================================
//
// docker.ts keeps a list of the things it refuses to ship and why. This is
// item 17's entry on that list, and it is the single most important paragraph
// in the file.
//
// There is no schedule here, no "patch everything nightly", no auto-apply and
// no policy engine. Reporting that twelve hosts have security updates and
// letting a person choose is honest. AUTO-PATCHING AN ESTATE FROM A DESKTOP APP
// IS A PROMISE ABOUT UNATTENDED CORRECTNESS THIS APP CANNOT KEEP, and the
// reasons are specific rather than squeamish:
//
//  * The app is not running. It is a desktop application on a laptop that gets
//    closed. A scheduler whose trigger depends on someone having the window
//    open is not a schedule, it is a coincidence, and the estate it silently
//    skips is the one whose owner is on holiday.
//  * Nobody is there when it goes wrong. `dpkg` asks about a modified conffile
//    and waits forever; a kernel upgrade wants a reboot the app cannot decide
//    to take; a mirror serves a half-published repository. Each of those needs
//    a person, and an unattended run's only options are to hang or to guess.
//  * It cannot know what the host does. ShellPilot has never seen your load
//    balancer, your replication topology or your maintenance window. See
//    shared/topology.ts for the full version of that argument; the short form
//    is that the two facts it genuinely holds are not enough to schedule
//    against, and pretending otherwise is worse than saying so.
//  * The distributions already ship the honest version of this. `unattended-
//    upgrades` and `dnf-automatic` run on the host, survive the laptop being
//    shut, and are configured by people who know what that host does. A
//    desktop app reimplementing them badly, over SSH, is not an improvement.
//
// So: this module reports, plans, stages and — when a human confirms a specific
// target list at a specific moment — applies. It never decides.
export const PATCH_NO_AUTOMATION_NOTE =
  'ShellPilot does not patch on a schedule and will not add one. It is a desktop app that gets ' +
  'closed, it cannot answer a dpkg conffile prompt, and it does not know what your servers do. ' +
  'Reporting what is pending and letting you choose is the honest version of this; for genuinely ' +
  'unattended patching use unattended-upgrades or dnf-automatic on the server itself.'

// ===========================================================================
// THE HONESTY REQUIREMENT THIS INHERITS FROM ITEM C
// ===========================================================================
//
// Security-update counts DO NOT EXIST on every distribution. Never on pacman or
// apk — neither has a security channel to count. On dnf and yum only where the
// repositories publish `updateinfo`, and where they do not, dnf returns zero
// rows, which is indistinguishable from "no security updates".
//
// So this feature promises "security updates WHERE THE DISTRIBUTION PUBLISHES
// THEM", never "security updates". A host that cannot answer is excluded from
// every total and from every all-clear, and is never treated as a zero. The
// vocabulary is `lib/inventory.ts`'s, deliberately: `unsupported` renders as
// "cannot be answered", never as a dash and never as a number.
export const PATCH_SECURITY_SCOPE_NOTE =
  'Security counts cover the servers whose distribution publishes them. Arch and Alpine have no ' +
  'security channel at all, and dnf cannot answer where the repositories omit updateinfo — those ' +
  'servers are excluded from the totals below rather than counted as zero.'

// ---------------------------------------------------------------------------
// Package managers
// ---------------------------------------------------------------------------

/**
 * What a patch run can be asked to install.
 *
 * `security` is not offered on every manager, and the ones that cannot do it
 * say so rather than quietly widening to `all`. Installing more than the
 * operator asked for is the one failure mode a patch tool must not have.
 */
export type PatchScope = 'all' | 'security'

export interface PatchCommand {
  ok: true
  command: string
  /** What it actually does, in one line, for the confirmation dialog. */
  detail: string
}

export interface PatchCommandRefusal {
  ok: false
  reason: string
}

/**
 * The upgrade command for one manager.
 *
 * Rules, all four of which are the same ones cron.ts and docker.ts follow:
 *
 *  1. NON-INTERACTIVE OR NOTHING. A detached job has no tty and no stdin
 *     (JOB_SUDO_NOTE). `DEBIAN_FRONTEND=noninteractive` and the dpkg
 *     conffile options are not a convenience: without them apt stops at the
 *     first modified config file and waits for a person who is not there, and
 *     the job times out with the package system half-configured.
 *  2. `--force-confold` KEEPS YOUR CONFIG. The other choice, `--force-confnew`,
 *     overwrites a file an operator edited on purpose. Keeping the old file can
 *     leave a service on stale defaults; overwriting it can leave a service
 *     with no configuration at all. The first is recoverable by reading a
 *     `.dpkg-dist` file, the second is not.
 *  3. NO CACHE REFRESH IS IMPLIED. `apt-get update` IS included here, and only
 *     here, because applying updates from a cache the host has not refreshed
 *     installs yesterday's answer — that is different from the INVENTORY path,
 *     which deliberately never refreshes because a read must not mutate. An
 *     apply is not a read.
 *  4. NO `dist-upgrade` / `full-upgrade`. Those remove packages to satisfy
 *     dependencies. A patch run that can uninstall things is not a patch run.
 *     `apt-get upgrade` never removes; the packages it holds back are reported
 *     in the output, and holding one back is the safe direction.
 */
export function patchCommandFor(
  manager: PackageManager,
  scope: PatchScope,
  o: { sudo?: boolean } = {}
): PatchCommand | PatchCommandRefusal {
  const sudo = o.sudo === false ? '' : 'sudo -n '
  switch (manager) {
    case 'apt':
      if (scope === 'security') {
        // Deliberate refusal rather than a clever pin expression. The usual
        // recipes filter `apt list --upgradable` for `-security` and feed the
        // names back to `apt-get install`, which quietly installs whatever
        // dependencies those names drag in — a wider set than the operator
        // asked for, presented as the narrower one.
        return {
          ok: false,
          reason:
            'apt has no single command that installs only security updates. Every recipe that ' +
            'claims to filters a package list and then installs its dependencies too, which is ' +
            'a wider change than the one you asked for. Run the full upgrade, or use ' +
            'unattended-upgrades on the server, which is built for exactly this.'
        }
      }
      return {
        ok: true,
        command:
          `${sudo}env DEBIAN_FRONTEND=noninteractive apt-get update && ` +
          `${sudo}env DEBIAN_FRONTEND=noninteractive apt-get -y ` +
          '-o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold upgrade',
        detail:
          'apt-get update, then apt-get upgrade with the non-interactive frontend and your ' +
          'existing config files kept. Never dist-upgrade: nothing is removed.'
      }
    case 'dnf':
    case 'yum': {
      const bin = manager
      if (scope === 'security') {
        return {
          ok: true,
          command: `${sudo}${bin} -y --security upgrade`,
          detail:
            `${bin} --security upgrade. On a server whose repositories publish no updateinfo this ` +
            'installs nothing and says so — which is why the count for such a server reads "cannot ' +
            'be answered" rather than 0.'
        }
      }
      return {
        ok: true,
        command: `${sudo}${bin} -y upgrade`,
        detail: `${bin} upgrade. Nothing is removed and no obsoletes are processed.`
      }
    }
    case 'zypper':
      if (scope === 'security') {
        return {
          ok: true,
          command: `${sudo}zypper --non-interactive patch --category security`,
          detail:
            'zypper patch --category security. SUSE models patches as first-class objects, so ' +
            'this really is the security subset rather than a filtered package list.'
        }
      }
      return {
        ok: true,
        command: `${sudo}zypper --non-interactive update`,
        detail: 'zypper update. Nothing is removed; use zypper dup by hand for a distribution jump.'
      }
    case 'pacman':
      if (scope === 'security') {
        return {
          ok: false,
          reason:
            'Arch has no security channel, so there is no security-only upgrade to run. This is ' +
            'the same fact the inventory reports as "cannot be answered" for this server: it is ' +
            'not a permission problem and not a missing tool.'
        }
      }
      return {
        ok: true,
        command: `${sudo}pacman -Syu --noconfirm`,
        detail:
          'pacman -Syu. Arch is a rolling release, so this is a full system upgrade by ' +
          'definition — there is no smaller thing to ask for.'
      }
    case 'apk':
      if (scope === 'security') {
        return {
          ok: false,
          reason:
            'Alpine tracks security fixes per package rather than as a channel, so apk has no ' +
            'security-only upgrade. The inventory reports this server as "cannot be answered" for ' +
            'the same reason.'
        }
      }
      return {
        ok: true,
        command: `${sudo}apk upgrade`,
        detail: 'apk upgrade against the repositories already configured on the server.'
      }
  }
}

// ---------------------------------------------------------------------------
// Reboot, and why it is not a command
// ---------------------------------------------------------------------------

/**
 * The line the reboot step prints before it restarts the machine.
 *
 * A boot id read BEFORE the reboot and compared with the one read after is the
 * only evidence available from here that the machine actually restarted. The
 * alternative — "the process vanished and the host came back" — is
 * indistinguishable from the OOM killer taking the wrapper on a host that never
 * went down, which is precisely the `orphaned` case B2 named and refused to
 * paper over.
 */
export const REBOOT_BOOT_ID_MARK = 'shellpilot-boot-id='

/**
 * Issue the restart.
 *
 * `sleep 2` before it, and the reason is not cosmetic: the wrapper's `out` file
 * has to be flushed and readable before the machine goes, or the boot id we are
 * about to compare against is never written down. Two seconds is far longer
 * than a write to an already-open descriptor needs and far shorter than
 * anything an operator would notice.
 *
 * `systemctl reboot` where systemd is present, `shutdown -r now` otherwise, and
 * the fallthrough is deliberate rather than a preference: `shutdown -r` on a
 * systemd host is a shim that calls systemctl anyway, while `systemctl` on a
 * host without systemd is a missing command and the step would fail having done
 * nothing — which is the safe failure, but a needless one.
 */
export function buildRebootStep(o: { sudo?: boolean } = {}): string {
  const sudo = o.sudo === false ? '' : 'sudo -n '
  return [
    `printf '%s%s\\n' '${REBOOT_BOOT_ID_MARK}' "$(cat /proc/sys/kernel/random/boot_id 2>/dev/null || echo unknown)";`,
    'sync;',
    'sleep 2;',
    `if command -v systemctl >/dev/null 2>&1; then ${sudo}systemctl reboot; else ${sudo}shutdown -r now; fi`
  ].join(' ')
}

/** The boot id a reboot step recorded, or null if it never got that far. */
export function parseRebootBootId(output: string): string | null {
  const lines = output.split('\n')
  for (let i = lines.length - 1; i >= 0; i--) {
    const at = lines[i].indexOf(REBOOT_BOOT_ID_MARK)
    if (at < 0) continue
    const v = lines[i].slice(at + REBOOT_BOOT_ID_MARK.length).trim()
    return v === '' ? null : v
  }
  return null
}

/**
 * Ask a host that has just answered again whether it really restarted, and
 * whether it came back in one piece.
 *
 * Three questions in one round trip, because the expensive part is the trip:
 * the boot id (did it restart), `systemctl is-system-running` (did it come back
 * degraded), and the failed unit list (what specifically). A host without
 * systemd answers `unit-state=` and `failed=`, which reads as "cannot tell",
 * not as "nothing failed" — the null-is-not-empty rule hostHealth.ts states.
 */
export function buildRebootVerify(): string {
  return [
    "echo 'shellpilot-postboot/1';",
    'echo "boot-id=$(cat /proc/sys/kernel/random/boot_id 2>/dev/null)";',
    'echo "uptime=$(cut -d. -f1 /proc/uptime 2>/dev/null)";',
    'if command -v systemctl >/dev/null 2>&1; then',
    '  echo "unit-state=$(systemctl is-system-running 2>/dev/null)";',
    '  echo "failed=$(systemctl list-units --state=failed --no-legend --plain 2>/dev/null | awk \'{print $1}\' | tr \'\\n\' \' \')";',
    'else echo "unit-state="; echo "failed="; fi'
  ].join(' ')
}

export interface RebootVerification {
  /** The host answered this probe at all. */
  answered: boolean
  bootId: string | null
  uptimeSeconds: number | null
  /** `running`, `degraded`, `starting`, … or null where there is no systemd. */
  unitState: string | null
  /** Failed unit names, or null where systemd could not be asked. NOT `[]`. */
  failed: string[] | null
}

export function parseRebootVerify(stdout: string): RebootVerification {
  if (!stdout.includes('shellpilot-postboot/1')) {
    return { answered: false, bootId: null, uptimeSeconds: null, unitState: null, failed: null }
  }
  const fields = new Map<string, string>()
  for (const line of stdout.split('\n')) {
    const eq = line.indexOf('=')
    if (eq <= 0) continue
    const key = line.slice(0, eq).trim()
    if (!/^[a-z-]+$/.test(key)) continue
    fields.set(key, line.slice(eq + 1).replace(/\r$/, '').trim())
  }
  const bootId = fields.get('boot-id') || null
  const uptimeRaw = fields.get('uptime') ?? ''
  const unitState = fields.get('unit-state') || null
  const failedRaw = fields.get('failed')
  return {
    answered: true,
    bootId,
    uptimeSeconds: /^\d+$/.test(uptimeRaw) ? Number(uptimeRaw) : null,
    unitState,
    // An ABSENT `failed` line and an EMPTY one are the same thing here — the
    // host has no systemd and said so — while a host with systemd and nothing
    // broken emits the key with a space in it. `unitState` is what separates
    // the two, so the split is driven off that rather than off the string.
    failed:
      unitState === null
        ? null
        : (failedRaw ?? '')
            .split(/\s+/)
            .map((s) => s.trim())
            .filter((s) => s !== '')
  }
}

export type RebootVerdictKind = 'rebooted' | 'not-rebooted' | 'degraded' | 'unverifiable'

export interface RebootVerdict {
  kind: RebootVerdictKind
  /** True only for `rebooted`: it restarted and came back clean. */
  ok: boolean
  reason: string
}

/**
 * Did it come back, and did it come back healthy?
 *
 * `unverifiable` is a first-class answer for item C's reason. A host with no
 * readable `/proc/sys/kernel/random/boot_id` — a BSD, a container, a kernel
 * built without it — cannot prove it restarted, and reporting that as success
 * would be inventing the evidence. It is not a failure either: the operator can
 * see the uptime and decide.
 */
export function verifyReboot(
  before: string | null,
  after: RebootVerification
): RebootVerdict {
  if (!after.answered) {
    return {
      kind: 'unverifiable',
      ok: false,
      reason: 'The server answered again but the post-reboot check produced nothing this build understands.'
    }
  }
  if (before === null || before === 'unknown' || after.bootId === null) {
    const up = after.uptimeSeconds
    return {
      kind: 'unverifiable',
      ok: false,
      reason:
        'The server is answering again, but it does not expose a boot id, so ShellPilot cannot ' +
        'prove it actually restarted rather than merely dropping the connection' +
        (up === null ? '.' : ` — its uptime is ${up}s, which is the only evidence available.`)
    }
  }
  if (before === after.bootId) {
    return {
      kind: 'not-rebooted',
      ok: false,
      reason:
        'The server is answering and its boot id has not changed, so it never restarted. The ' +
        'reboot command was issued and something refused or swallowed it.'
    }
  }
  if (after.failed !== null && after.failed.length > 0) {
    return {
      kind: 'degraded',
      ok: false,
      reason:
        `The server restarted and came back with ${after.failed.length} failed ` +
        `${after.failed.length === 1 ? 'unit' : 'units'}: ${after.failed.join(', ')}.`
    }
  }
  if (after.unitState !== null && after.unitState !== 'running' && after.unitState !== 'starting') {
    return {
      kind: 'degraded',
      ok: false,
      reason: `The server restarted and systemd reports the system as "${after.unitState}".`
    }
  }
  return {
    kind: 'rebooted',
    ok: true,
    reason:
      after.unitState === null
        ? 'The server restarted (its boot id changed). It has no systemd, so nothing here can say ' +
          'whether its services came back.'
        : 'The server restarted and came back with no failed units.'
  }
}

/** What a host's row says when its reboot step is still waiting for it. */
export const JOB_REBOOTING_NOTE =
  'The reboot has been issued and the server has stopped answering, which is what was expected. ' +
  'ShellPilot is polling until it comes back and will then check that it really restarted and ' +
  'that nothing failed on the way up. This is not "unreachable": nothing is wrong yet.'

// ---------------------------------------------------------------------------
// The view: every host, what it needs
// ---------------------------------------------------------------------------

/**
 * Why a count is missing.
 *
 * `lib/inventory.ts`'s `CellGap`, restated here because shared/ may not import
 * from the renderer — and kept to exactly the same words, because the two
 * screens sit next to each other and a user who learns "cannot be answered" in
 * one must not meet a different phrase for the same fact in the other.
 * tests/patch.test.ts pins the overlap.
 */
export type PatchGap = Exclude<FactStatus, 'ok'> | 'not-collected' | 'probe-failed'

export const PATCH_GAP_LABEL: Record<PatchGap, string> = {
  absent: 'not on this server',
  denied: 'not permitted',
  'no-tool': 'no tool for it',
  'stale-metadata': 'from a stale cache',
  unsupported: 'cannot be answered',
  unknown: 'unknown',
  'not-collected': 'not collected yet',
  'probe-failed': 'collection failed'
}

/** A number, or a named reason there is none. Never a dash and never a zero. */
export interface PatchCount {
  value: number | null
  gap: PatchGap | null
  help: string
  /** The count is real and the cache behind it is not fresh. */
  staleMetadata?: boolean
}

export interface PatchHostInput {
  serverId: string
  serverName: string
  facts: HostFacts | null
  factsAt: number | null
  factsError: string | null
}

export interface PatchHostRow {
  serverId: string
  serverName: string
  packageManager: PackageManager | null
  pending: PatchCount
  security: PatchCount
  /** null is "we cannot see whether a reboot is owed", never "no". */
  rebootRequired: boolean | null
  rebootReason: string | null
  rebootGap: PatchGap | null
  factsAt: number | null
  metadataAt: number | null
  /** True when this host can never report a security count. Drives the
   *  exclusion from every total and from "all clear". */
  securityUnanswerable: boolean
  /**
   * Whether this host has something to install — in THREE states, because two
   * is the bug.
   *
   *  `yes`     — a count came back above zero, or a reboot is owed.
   *  `no`      — every question was asked and answered, and the answer was
   *              nothing.
   *  `unknown` — at least one question this host could not answer. NOT "no".
   *
   * A boolean has no room for "cannot say", so it spends it as "no", and a
   * screen that selects "everything with work" then silently omits exactly the
   * hosts nobody can vouch for. It is the same null-is-not-zero rule the rest
   * of this file follows; `summarisePatch` has always followed it, and this
   * field used to contradict the summary printed beside it.
   */
  hasWork: PatchWorkState
}

/** @see PatchHostRow.hasWork */
export type PatchWorkState = 'yes' | 'no' | 'unknown'

function gapHelp(gap: PatchGap, detail?: string): string {
  const base =
    gap === 'not-collected'
      ? 'Host facts have not been collected for this server yet. They are collected about once an hour.'
      : gap === 'probe-failed'
        ? 'The facts probe ran on this server and did not complete.'
        : FACT_STATUS_HELP[gap]
  return detail ? `${detail}. ${base}` : base
}

export function buildPatchRow(input: PatchHostInput): PatchHostRow {
  const { facts } = input
  const whole: PatchGap = input.factsError !== null ? 'probe-failed' : 'not-collected'
  const wholeDetail = input.factsError ?? undefined

  const count = (id: 'updates' | 'security-updates', v: number | null): PatchCount => {
    if (!facts) return { value: null, gap: whole, help: gapHelp(whole, wholeDetail) }
    if (v === null) {
      const s = factSource(facts, id)
      const gap: PatchGap = s.status === 'ok' ? 'unknown' : s.status
      return { value: null, gap, help: gapHelp(gap, s.detail) }
    }
    return { value: v, gap: null, help: '' }
  }

  const stale = facts ? factSource(facts, 'package-metadata').status === 'stale-metadata' : false
  const withStale = (c: PatchCount): PatchCount =>
    stale && c.gap === null
      ? { ...c, staleMetadata: true, help: FACT_STATUS_HELP['stale-metadata'] }
      : c

  const pending = withStale(count('updates', facts?.pendingUpdates ?? null))
  const security = withStale(count('security-updates', facts?.securityUpdates ?? null))

  let rebootGap: PatchGap | null = null
  if (!facts) rebootGap = whole
  else if (facts.rebootRequired === null) {
    const s = factSource(facts, 'reboot-required')
    rebootGap = s.status === 'ok' ? 'unknown' : s.status
  }

  // "Cannot answer" is decided from the STATUS the collector gave, not from the
  // package manager's name. A dnf host whose repositories do publish
  // updateinfo answers perfectly well, and a table that greyed it out because
  // dnf is "maybe" would be inventing a gap the host does not have.
  const securityUnanswerable = security.gap === 'unsupported'

  // `yes` wins over `unknown`: a host with 4 pending updates and an unreadable
  // security count plainly has work, and burying it in "unknown" would lose a
  // fact that was actually established. `unknown` is for a host where nothing
  // positive was established AND something could not be asked.
  const somethingToDo =
    (pending.value ?? 0) > 0 || (security.value ?? 0) > 0 || facts?.rebootRequired === true
  const unanswered = pending.gap !== null || security.gap !== null || rebootGap !== null
  const hasWork: PatchWorkState = somethingToDo ? 'yes' : unanswered ? 'unknown' : 'no'

  return {
    serverId: input.serverId,
    serverName: input.serverName,
    packageManager: facts?.packageManager ?? null,
    pending,
    security,
    rebootRequired: facts?.rebootRequired ?? null,
    rebootReason: facts?.rebootReason ?? null,
    rebootGap,
    factsAt: input.factsAt,
    metadataAt: facts?.metadataAt ?? null,
    securityUnanswerable,
    hasWork
  }
}

export interface PatchSummary {
  hosts: number
  withFacts: number
  pendingTotal: number
  /** Hosts whose pending count could not be read at all. */
  pendingUnknown: number
  securityTotal: number
  /** Hosts that can NEVER report a security count. Never folded into a zero. */
  securityUnanswerable: number
  /** Hosts whose security count failed for some other reason. */
  securityUnknown: number
  rebootsOwed: number
  /** Hosts where "is a reboot owed" has no answer. */
  rebootUnknown: number
  staleMetadata: number
  /**
   * Every host answered, and every answer was zero.
   *
   * FALSE whenever a single host could not answer, and that is the whole point
   * of the field existing rather than the panel comparing totals to zero. "0
   * security updates across the estate" is a different claim when five hosts
   * could never have contributed to it, and an all-clear that counted them as
   * clear is exactly the lie item C was built to prevent.
   */
  allClear: boolean
  /** Why it is not all clear, or what the all-clear covers. Always present. */
  allClearNote: string
}

export function summarisePatch(rows: PatchHostRow[]): PatchSummary {
  const s: PatchSummary = {
    hosts: rows.length,
    withFacts: 0,
    pendingTotal: 0,
    pendingUnknown: 0,
    securityTotal: 0,
    securityUnanswerable: 0,
    securityUnknown: 0,
    rebootsOwed: 0,
    rebootUnknown: 0,
    staleMetadata: 0,
    allClear: false,
    allClearNote: ''
  }
  for (const r of rows) {
    if (r.factsAt !== null) s.withFacts++
    if (r.pending.gap === null) s.pendingTotal += r.pending.value ?? 0
    else s.pendingUnknown++
    if (r.security.gap === null) s.securityTotal += r.security.value ?? 0
    else if (r.security.gap === 'unsupported') s.securityUnanswerable++
    else s.securityUnknown++
    if (r.rebootGap !== null) s.rebootUnknown++
    else if (r.rebootRequired === true) s.rebootsOwed++
    if (r.pending.staleMetadata || r.security.staleMetadata) s.staleMetadata++
  }

  const unanswered = s.pendingUnknown + s.securityUnanswerable + s.securityUnknown + s.rebootUnknown
  const nothingPending = s.pendingTotal === 0 && s.securityTotal === 0 && s.rebootsOwed === 0
  s.allClear = rows.length > 0 && nothingPending && unanswered === 0

  if (rows.length === 0) {
    s.allClearNote = 'No servers in this workspace.'
  } else if (s.allClear) {
    s.allClearNote = 'Every server answered, and every server is up to date.'
  } else if (nothingPending) {
    const parts: string[] = []
    if (s.securityUnanswerable > 0) {
      parts.push(
        `${s.securityUnanswerable} ${s.securityUnanswerable === 1 ? 'server cannot' : 'servers cannot'} ` +
          'report a security count at all'
      )
    }
    if (s.securityUnknown > 0) parts.push(`${s.securityUnknown} security ${s.securityUnknown === 1 ? 'count' : 'counts'} could not be read`)
    if (s.pendingUnknown > 0) parts.push(`${s.pendingUnknown} update ${s.pendingUnknown === 1 ? 'count' : 'counts'} could not be read`)
    if (s.rebootUnknown > 0) parts.push(`${s.rebootUnknown} ${s.rebootUnknown === 1 ? 'host' : 'hosts'} cannot say whether a reboot is owed`)
    // NOT "all clear". The counts that came back are zero and the ones that did
    // not are not zero — they are absent, and an estate is not clear because
    // the hosts that could answer had nothing to say.
    s.allClearNote =
      `Nothing is pending on the servers that answered, but ${parts.join(', ')}. That is not an ` +
      'all-clear: those servers are unknown, not clean.'
  } else {
    const bits: string[] = []
    if (s.securityTotal > 0) bits.push(`${s.securityTotal} security`)
    if (s.pendingTotal > 0) bits.push(`${s.pendingTotal} pending`)
    if (s.rebootsOwed > 0) bits.push(`${s.rebootsOwed} awaiting a reboot`)
    s.allClearNote = `${bits.join(', ')}. ${PATCH_SECURITY_SCOPE_NOTE}`
  }
  return s
}

// ---------------------------------------------------------------------------
// Staging
// ---------------------------------------------------------------------------

/** Wave names are `wave-1`, `wave-2`, … — the value that lands in
 *  `JobTargetRef.cohort` and therefore in the approval record. */
export function waveName(index: number): string {
  return `wave-${index + 1}`
}

export interface PatchWave {
  name: string
  hosts: { serverId: string; serverName: string }[]
}

/**
 * Split the selected hosts into waves of at most `size`.
 *
 * The ORDER IS THE CALLER'S, unchanged. A clever ordering — least loaded first,
 * jump hosts last — would be a claim about the estate this app cannot support,
 * and it would silently move a host the operator had deliberately put first.
 *
 * `size` of 0 or less means one wave containing everything, which is what
 * "apply to all at once" is, spelled as a wave so the rest of the machinery has
 * nothing to special-case.
 */
export function planWaves(
  hosts: { serverId: string; serverName: string }[],
  size: number
): PatchWave[] {
  if (hosts.length === 0) return []
  const n = size > 0 ? Math.floor(size) : hosts.length
  const waves: PatchWave[] = []
  for (let i = 0; i < hosts.length; i += n) {
    waves.push({ name: waveName(waves.length), hosts: hosts.slice(i, i + n) })
  }
  return waves
}

export function wavesToTargets(waves: PatchWave[]): JobTargetRef[] {
  return waves.flatMap((w) =>
    w.hosts.map((h) => ({ serverId: h.serverId, serverName: h.serverName, cohort: w.name }))
  )
}

// ---------------------------------------------------------------------------
// The plan
// ---------------------------------------------------------------------------

export interface PatchPlanRequest {
  scope: PatchScope
  /** Selected hosts, in the order the operator put them. */
  hosts: { serverId: string; serverName: string; packageManager: PackageManager | null }[]
  waveSize: number
  /** Restart the hosts that say they need one, after the upgrade. */
  reboot: boolean
  /** Hold between waves until the estate looks healthy. */
  healthGate: boolean
  /** Which hosts actually report a reboot as owed. Only these get a reboot
   *  step; a host with nothing to restart for is not restarted. */
  rebootWanted?: (serverId: string) => boolean
  sudo?: boolean
  servers: TopologyServer[]
  databases?: TopologyDatabase[]
}

export interface PatchPlanHost {
  serverId: string
  serverName: string
  wave: string
  packageManager: PackageManager | null
  /** null when this host is excluded — see `excluded`. */
  command: string | null
  /** True when this host's plan includes a restart. */
  reboot: boolean
  /** Why this host is not in the run. */
  excluded: string | null
}

export interface PatchPlan {
  /** One job per distinct command, because a JobSpec has one step list for
   *  every host in it. See `jobs` below. */
  jobs: PatchJobPlan[]
  hosts: PatchPlanHost[]
  /** Hard refusals. A plan with any of these cannot be run as it stands. */
  blocks: RebootBlock[];
  /** The topology hole, in words, or null when every hop resolved. */
  unmatchedNote: string | null
  topology: Topology
  /** Hosts left out and why, for the panel to list rather than silently drop. */
  excluded: { serverId: string; serverName: string; reason: string }[]
}

export interface PatchJobPlan {
  /** `apt`, `dnf`, … — one job per manager, because one JobSpec is one command. */
  packageManager: PackageManager
  spec: JobSpec
  targets: JobTargetRef[]
  /** The upgrade command's own explanation, for the dialog. */
  detail: string
}

/**
 * Turn a selection into something runnable, or into the reasons it is not.
 *
 * ONE JOB PER PACKAGE MANAGER, and it is not an implementation detail. A
 * `JobSpec` carries one list of steps that every target runs; an estate with
 * Debian and Rocky in it cannot be one job without the spec lying about what
 * ran where — and `verifyApproval` compares the step text, so a spec whose
 * command was substituted per host could not be checked against the record at
 * all. Splitting by manager keeps every job honestly describable by its own
 * step list, and the panel confirms them together.
 *
 * REBOOT IS A SEPARATE STEP, never appended to the upgrade command. It is the
 * step that has to be recognised as one that restarts the machine
 * (`restartsTheMachine`), the step whose disconnect is expected, and the step
 * the health gate is asked about afterwards. Folding it into the upgrade would
 * make every one of those invisible.
 */
export function planPatch(req: PatchPlanRequest): PatchPlan {
  const topology = buildTopology(req.servers, req.databases ?? [])
  const waves = planWaves(
    req.hosts.map((h) => ({ serverId: h.serverId, serverName: h.serverName })),
    req.waveSize
  )
  const waveOf = new Map<string, string>()
  for (const w of waves) for (const h of w.hosts) waveOf.set(h.serverId, w.name)

  const excluded: PatchPlan['excluded'] = []
  const hosts: PatchPlanHost[] = []
  const blocks: RebootBlock[] = []
  const wants = req.rebootWanted ?? ((): boolean => true)

  // Same-wave database co-tenancy is a property of a WAVE, so it is asked once
  // per wave rather than once per host.
  if (req.reboot) {
    for (const w of waves) {
      const rebooting = w.hosts.filter((h) => wants(h.serverId)).map((h) => h.serverId)
      blocks.push(...sameWaveDatabaseBlocks(topology, rebooting))
    }
  }

  for (const h of req.hosts) {
    const wave = waveOf.get(h.serverId) ?? waveName(0)
    const reboot = req.reboot && wants(h.serverId)
    if (reboot) {
      const block = rebootBlockFor(topology, h.serverId)
      if (block !== null) blocks.push(block)
    }
    if (h.packageManager === null) {
      const reason =
        'ShellPilot has not identified a package manager on this server, so it cannot know what ' +
        'command would update it. Nothing is guessed.'
      excluded.push({ serverId: h.serverId, serverName: h.serverName, reason })
      hosts.push({
        serverId: h.serverId,
        serverName: h.serverName,
        wave,
        packageManager: null,
        command: null,
        reboot: false,
        excluded: reason
      })
      continue
    }
    const cmd = patchCommandFor(h.packageManager, req.scope, { sudo: req.sudo })
    if (!cmd.ok) {
      excluded.push({ serverId: h.serverId, serverName: h.serverName, reason: cmd.reason })
      hosts.push({
        serverId: h.serverId,
        serverName: h.serverName,
        wave,
        packageManager: h.packageManager,
        command: null,
        reboot: false,
        excluded: cmd.reason
      })
      continue
    }
    hosts.push({
      serverId: h.serverId,
      serverName: h.serverName,
      wave,
      packageManager: h.packageManager,
      command: cmd.command,
      reboot,
      excluded: null
    })
  }

  // A wave with a reboot and one without cannot share a spec, because the step
  // list IS the spec. So the split key is manager + whether this host reboots.
  const byKey = new Map<string, PatchPlanHost[]>()
  for (const h of hosts) {
    if (h.excluded !== null || h.packageManager === null) continue
    const key = `${h.packageManager}|${h.reboot ? 'reboot' : 'no-reboot'}`
    const list = byKey.get(key) ?? []
    list.push(h)
    byKey.set(key, list)
  }

  const jobs: PatchJobPlan[] = []
  for (const [key, list] of byKey) {
    const manager = list[0].packageManager as PackageManager
    const cmd = patchCommandFor(manager, req.scope, { sudo: req.sudo })
    if (!cmd.ok) continue
    const doesReboot = key.endsWith('|reboot')
    const steps: JobStep[] = [{ command: cmd.command }]
    if (doesReboot) steps.push({ command: buildRebootStep({ sudo: req.sudo }), reboot: true })
    jobs.push({
      packageManager: manager,
      detail: cmd.detail,
      spec: {
        kind: 'patch',
        title:
          `${req.scope === 'security' ? 'Security updates' : 'Updates'} · ${manager}` +
          (doesReboot ? ' · with reboot' : ''),
        steps,
        gate: req.healthGate ? 'health' : 'none'
      },
      targets: list.map((h) => ({
        serverId: h.serverId,
        serverName: h.serverName,
        cohort: h.wave
      }))
    })
  }

  // Deduped by host: a host can be both a jump host and a same-wave database
  // tenant, and two refusals for one machine read as two machines.
  const seen = new Set<string>()
  const uniqueBlocks = blocks.filter((b) => {
    const k = `${b.kind}:${b.serverId}`
    if (seen.has(k)) return false
    seen.add(k)
    return true
  })

  return {
    jobs,
    hosts,
    blocks: uniqueBlocks,
    unmatchedNote: unmatchedHopNote(topology),
    topology,
    excluded
  }
}

/** Does this plan carry a refusal that must stop the run? */
export function planIsBlocked(plan: PatchPlan): boolean {
  return plan.blocks.length > 0
}

/** Every dependent name across a plan's refusals, for a one-line summary. */
export function blockSummary(plan: PatchPlan): string | null {
  if (plan.blocks.length === 0) return null
  const jump = plan.blocks.filter((b) => b.kind === 'jump-host')
  const db = plan.blocks.filter((b) => b.kind === 'same-wave-database')
  const parts: string[] = []
  if (jump.length > 0) {
    parts.push(
      `${jump.map((b) => b.serverName).join(', ')} ${jump.length === 1 ? 'is a jump host' : 'are jump hosts'} ` +
        `for ${[...new Set(jump.flatMap((b) => dependentsOf(plan.topology, b.serverId).map((d) => d.name)))].join(', ')}`
    )
  }
  if (db.length > 0) {
    parts.push(`${[...new Set(db.map((b) => b.serverName))].join(', ')} would restart together with a shared database`)
  }
  return `This run will not restart ${parts.join('; ')}.`
}

// ---------------------------------------------------------------------------
// The health gate between waves
// ---------------------------------------------------------------------------

/** One host as the gate sees it. Shaped from whatever the caller's sampler
 *  holds, so the gate itself has no idea where health comes from. */
export interface GateHost {
  serverId: string
  serverName: string
  /** When the most recent health observation for this host was taken, or null
   *  if there has never been one. */
  sampledAt: number | null
  /** The sampler could not reach it at the last attempt. */
  unreachable: boolean
  unreachableError: string | null
  /**
   * Failed unit names, or null when systemd could not be asked. NOT `[]` —
   * hostHealth.ts's rule, and it decides a different outcome here.
   */
  failedUnits: string[] | null
}

export type GateVerdict =
  | {
      ok: true
      /** Hosts that answered but could not report unit state. Reported, never
       *  counted as healthy and never counted as broken. */
      unverified: string[]
      note: string
    }
  | {
      ok: false
      kind: 'stale' | 'unhealthy'
      reason: string
      hosts: string[]
    }

/**
 * May the next wave start?
 *
 * Two ways to say no, and the first one is the one an implementation gets
 * wrong:
 *
 *  1. STALE. A health sample taken BEFORE this wave ran cannot say anything
 *     about what this wave did. A gate that accepted one would pass every time,
 *     instantly, on data from before the upgrade — which is worse than no gate,
 *     because it looks like one. So every host in the finished wave must have
 *     an observation newer than the moment its work ended, and a gate with none
 *     WAITS (the runner retries) rather than deciding.
 *  2. UNHEALTHY. The host is unreachable, or it has failed units. Both stay
 *     broken until a person acts, which is `summariseFleetHealth`'s own
 *     definition of needing attention.
 *
 * A host whose unit state cannot be read at all is `unverified`: reported by
 * name, not blocking. Blocking on it would make a host without systemd
 * permanently unpatchable in a staged run, and the honest thing about a
 * permanent property of a machine is to say it every time rather than to stop.
 */
export function evaluateGate(
  hosts: GateHost[],
  o: { since: number }
): GateVerdict {
  const stale = hosts.filter((h) => h.sampledAt === null || h.sampledAt < o.since)
  if (stale.length > 0) {
    return {
      ok: false,
      kind: 'stale',
      hosts: stale.map((h) => h.serverName),
      reason:
        `No health check newer than this wave for ${stale.map((h) => h.serverName).join(', ')}. ` +
        'A sample taken before the wave ran cannot say what the wave did, so the gate is waiting ' +
        'for a fresh one rather than passing on stale data.'
    }
  }
  const down = hosts.filter((h) => h.unreachable)
  const failing = hosts.filter((h) => !h.unreachable && (h.failedUnits?.length ?? 0) > 0)
  if (down.length > 0 || failing.length > 0) {
    const parts: string[] = []
    if (down.length > 0) {
      parts.push(
        `${down.map((h) => `${h.serverName} (${h.unreachableError ?? 'unreachable'})`).join(', ')} ` +
          `${down.length === 1 ? 'is' : 'are'} not answering`
      )
    }
    if (failing.length > 0) {
      parts.push(
        failing
          .map((h) => `${h.serverName} has ${h.failedUnits!.length} failed ${h.failedUnits!.length === 1 ? 'unit' : 'units'} (${h.failedUnits!.join(', ')})`)
          .join('; ')
      )
    }
    return {
      ok: false,
      kind: 'unhealthy',
      hosts: [...down, ...failing].map((h) => h.serverName),
      reason: `${parts.join('; ')}. The remaining waves were not started.`
    }
  }
  const unverified = hosts.filter((h) => h.failedUnits === null).map((h) => h.serverName)
  return {
    ok: true,
    unverified,
    note:
      unverified.length === 0
        ? `All ${hosts.length} ${hosts.length === 1 ? 'host' : 'hosts'} in this wave answered with no failed units.`
        : `${hosts.length - unverified.length} of ${hosts.length} servers answered with no failed units; ` +
          `${unverified.join(', ')} cannot report unit state at all, so nothing here vouches for ${unverified.length === 1 ? 'it' : 'them'}.`
  }
}

/**
 * How long a wave gate waits for a fresh health observation before giving up.
 *
 * The fleet sampler's default cadence is two minutes, so a gate that gave up
 * sooner would time out on a perfectly healthy estate every time. Five minutes
 * is two sweeps plus slack, and the failure at the end of it is a HALT rather
 * than a pass: a run that could not verify a wave does not start the next one.
 */
export const GATE_WAIT_MS = 5 * 60 * 1000

/** How often the gate re-asks while it waits. */
export const GATE_POLL_MS = 5_000

/**
 * The name of the setting that produces the health observations the gate reads.
 *
 * Spelled once, here, and quoted verbatim in the timeout message and on the
 * patch screen, so the words an operator is told to look for are the words on
 * the switch. Two paraphrases of one setting is how a person concludes there
 * are two settings.
 */
export const GATE_SAMPLER_SETTING = 'Check servers in the background'

/** Where that switch is, in the words the app uses for the place. */
export const GATE_SAMPLER_NOTE =
  `The health data this gate reads comes from the fleet sampler — ${GATE_SAMPLER_SETTING}, ` +
  'under Settings → Monitoring. With that switch off nothing ever samples the estate, so no ' +
  'observation is ever newer than the wave and the gate can only ever time out.'

/**
 * What the row says when the gate never got a fresh answer in time.
 *
 * It NAMES THE SAMPLER. The overwhelmingly likely cause of this message is not
 * a slow estate, it is that background checking is off — it is off by default —
 * in which case there has never been a health observation of any kind and the
 * gate was doomed from the moment the run started. Reporting "there was still
 * no health check newer than it" without saying what produces one turns a
 * two-click fix into a support question, and leaves the operator staring at a
 * halted run and a wave of hosts marked "not run".
 */
export function gateTimeoutReason(wave: string, detail: string): string {
  return (
    `${wave} finished, and ${Math.round(GATE_WAIT_MS / 60000)} minutes later there was still no ` +
    `health check newer than it. ${detail} Rather than roll on against data from before the ` +
    `wave, the run stopped here. ${GATE_SAMPLER_NOTE}`
  )
}
