import { Fragment, useCallback, useEffect, useMemo, useState } from 'react'
import { RefreshCw, ShieldAlert, ShieldQuestion } from 'lucide-react'
import { bridgeHas } from '../../lib/bridge'
import { clsx, duration } from '../../lib/format'
import {
  CERT_EXPIRY_DAYS,
  OOM_WINDOW_HOURS,
  POSTURE_SOURCE_IDS,
  POSTURE_STATUS_HELP,
  SSHD_DIRECTIVES,
  isCertificateExpiringSoon,
  oomWindowIsStated,
  postureSource,
  securityUpdateReading,
  soonestCertificateExpiry,
  summarisePosture,
  type HostPosture,
  type PostureStatus,
  type SshdReading
} from '../../../../shared/posture'
import { FACT_STATUS_HELP, type HostFacts } from '../../../../shared/hostFacts'
import type { Server } from '../../types'

// Security posture — roadmap item 24, renderer half.
//
// The question is "which of my hosts is exposed", and the whole design follows
// from the fact that the answer has THREE parts and not two: the hosts that are
// fine, the hosts that are not, and the hosts nobody could check. The third
// list is the one every other tool leaves out, and leaving it out is what turns
// a security review into a reassuring fiction.
//
// So there is NO CELL in this panel that renders an unread host as a zero, a
// dash, a blank or a tick. Every gap prints the reason in words, with the
// status's own sentence on hover. The one rule that governs every line below:
//
//   A CHECK THAT COULD NOT RUN IS NOT A CHECK THAT PASSED.
//
// src/shared/posture.ts goes to real trouble to keep `denied`, `absent`,
// `no-tool`, `unsupported`, `partial` and "never collected" apart on the way
// in. All of it is thrown away by one `?? '—'` in a renderer, which is exactly
// what tests/posturePanel.test.tsx exists to notice.
//
// It reads through the preload bridge directly rather than through the fleet
// store, and pulls rather than subscribes, for the reason AccessPanel gives:
// `fleet.posture()` is a read of what the background sweep already holds and
// never triggers a probe. There is exactly one thing deciding how often every
// host gets asked for its firewall ruleset, and it is the sampler.
//
// There are no buttons here that change anything, and that is deliberate
// rather than unfinished — src/shared/posture.ts states the refusal in full.
// `ufw enable`, `setenforce` and an sshd_config edit can each lock the operator
// out of the host they would use to undo them, with none of the staged write,
// independent re-authentication and automatic revert that earn the key-change
// button in AccessPanel its place.

/** What one server's collection looks like from here, including the two states
 *  that are not a collection: never run, and failed. */
interface Entry {
  posture?: HostPosture
  at?: number
  error?: string
  errorAt?: number
}

/** One cell: either a value, or the reason there is not one. Never both, and
 *  never neither. */
interface Cell {
  text: string
  /** Null means this is a real value. Anything else is a gap, and `text` is
   *  the words for it. */
  gap: PostureStatus | 'never' | null
  help: string
  /** Louder than the rest: something was read and it is bad. */
  bad?: boolean
}

/** `denied` and `unknown` are the two an operator can usually do something
 *  about, so they are the ones drawn loudly. `absent`, `no-tool` and
 *  `unsupported` are facts about the host rather than gaps in the reading. */
const loudGap = (gap: Cell['gap']): boolean => gap === 'denied' || gap === 'unknown' || gap === 'never'

const gapWords: Record<PostureStatus, string> = {
  ok: 'read',
  partial: 'partly read',
  absent: 'not on this host',
  denied: 'not permitted',
  'no-tool': 'no tool for it',
  unsupported: 'cannot be answered',
  unknown: 'unknown'
}

function gapCell(status: PostureStatus, detail?: string): Cell {
  return {
    text: gapWords[status],
    gap: status,
    help: detail ? `${POSTURE_STATUS_HELP[status]} — ${detail}` : POSTURE_STATUS_HELP[status]
  }
}

const NEVER: Cell = {
  text: 'not collected',
  gap: 'never',
  help: 'The background sweep has not read this host yet. That is not a finding about the host — it is the absence of one. Press Check now, and make sure background checking is on in Settings.'
}

function firewallCell(posture: HostPosture): Cell {
  const s = postureSource(posture, 'firewall')
  const fw = posture.firewall
  if (fw === null || s.status === 'denied' || s.status === 'unknown') return gapCell(s.status, s.detail)

  const tool = fw.tool ?? 'the kernel filter'
  // The number of rules is the finding, and it only means anything when it was
  // actually read. `rules: null` next to `active: true` is a partial reading —
  // ufw.conf says the thing is switched on and says nothing about what it lets
  // through — and it must not render as a firewall with no rules.
  const rules = fw.rules ?? fw.backend.rules
  if (fw.active === false && (fw.backend.rules ?? 0) === 0 && fw.backend.status === 'ok') {
    return {
      text: `${tool} inactive, no kernel rules`,
      gap: null,
      bad: true,
      help: `${tool} is switched off and the kernel filter tables were read and are empty. Both halves were checked; this host is not filtering.`
    }
  }
  if (rules === null) {
    return {
      text: fw.active === true ? `${tool} on, rules not read` : `${tool}, nothing read`,
      gap: s.status === 'ok' ? 'partial' : s.status,
      help: `${POSTURE_STATUS_HELP[s.status === 'ok' ? 'partial' : s.status]}${s.detail ? ` — ${s.detail}` : ''}`
    }
  }
  const words = `${tool} · ${rules} rule${rules === 1 ? '' : 's'}${fw.policyIn ? ` · in ${fw.policyIn}` : ''}`
  return {
    text: words,
    gap: null,
    bad: rules === 0,
    help:
      rules === 0
        ? `${tool} was read and lists no rules at all. This is a reading, not a gap.`
        : `Read from ${tool}.${fw.backend.tool && fw.backend.tool !== fw.tool ? ` The kernel tables underneath (${fw.backend.tool}) hold ${fw.backend.rules ?? 'an unread number of'} rules.` : ''}`
  }
}

function macCell(posture: HostPosture): Cell {
  const s = postureSource(posture, 'mandatory-access')
  const mac = posture.mandatoryAccess
  if (s.status === 'absent') {
    return {
      text: 'none installed',
      gap: null,
      help: 'Neither SELinux nor AppArmor is on this host, and that was checked rather than assumed. Plenty of estates run this way deliberately.'
    }
  }
  if (mac === null || s.status === 'denied' || s.status === 'unknown') return gapCell(s.status, s.detail)

  if (mac.system === 'selinux') {
    if (mac.mode === null) return gapCell(s.status === 'ok' ? 'unknown' : s.status, s.detail)
    const drift =
      mac.bootMode !== null && mac.bootMode !== mac.mode
        ? ` · reverts to ${mac.bootMode} at reboot`
        : ''
    return {
      text: `SELinux ${mac.mode}${drift}`,
      gap: null,
      bad: mac.mode !== 'enforcing',
      help:
        drift === ''
          ? `SELinux is ${mac.mode}.`
          : `SELinux is ${mac.mode} right now, and /etc/selinux/config says ${mac.bootMode}. The running mode and the boot-time setting disagree, so this host changes behaviour at its next reboot.`
    }
  }
  // AppArmor has no global mode. "Enforcing" here means enabled with nothing in
  // complain mode, and a profile list that was refused is UNKNOWN rather than
  // enforcing — complain-mode profiles are exactly what the refused list would
  // have shown.
  if (mac.enabled !== true) {
    return mac.enabled === false
      ? { text: 'AppArmor disabled', gap: null, bad: true, help: 'The AppArmor module is present and switched off.' }
      : gapCell(s.status === 'ok' ? 'unknown' : s.status, s.detail)
  }
  if (mac.profiles === null) {
    return {
      text: 'AppArmor on, profiles not read',
      gap: 'partial',
      help: `${POSTURE_STATUS_HELP.partial} AppArmor is enabled and its profile list needs root here, so how many profiles merely complain is unknown — and a complaining profile enforces nothing.`
    }
  }
  return {
    text: `AppArmor · ${mac.profiles} profile${mac.profiles === 1 ? '' : 's'}${mac.complain ? `, ${mac.complain} complaining` : ''}`,
    gap: null,
    bad: (mac.complain ?? 0) > 0,
    help: `${mac.profiles} profiles are loaded and ${mac.complain ?? 0} of them are in complain mode, which logs rather than blocks.`
  }
}

function sshdCell(posture: HostPosture): Cell {
  const s = postureSource(posture, 'sshd-hardening')
  const sshd = posture.sshd
  if (sshd === null) return gapCell(s.status, s.detail)
  const weak = sshd.readings.filter((r) => r.verdict === 'weak')
  const unread = sshd.readings.filter((r) => r.verdict === 'unknown')
  if (weak.length > 0) {
    return {
      text: `${weak.length} weak · ${weak.map((r) => r.directive).join(', ')}`,
      gap: null,
      bad: true,
      help: weak.map((r) => `${r.directive}: ${r.detail}`).join(' ')
    }
  }
  // NO WEAK DIRECTIVES IS NOT "HARDENED" WHEN MOST OF THEM WERE NOT READ. This
  // is the single most important branch in the file: a host whose sshd_config
  // could not be read has zero weak directives and zero good ones, and the
  // naive summary of that is a clean bill of health.
  if (unread.length === sshd.readings.length) return gapCell(s.status === 'ok' ? 'unknown' : s.status, s.detail)
  const suffix = unread.length > 0 ? `, ${unread.length} not read` : ''
  return {
    text: `nothing weak${suffix}`,
    gap: unread.length > 0 ? 'partial' : null,
    help:
      unread.length > 0
        ? `${sshd.readings.length - unread.length} of ${sshd.readings.length} directives were read and none of them is weak. The other ${unread.length} were not read at all${sshd.effective ? '' : ' — this reading came from configuration files rather than from sshd itself, so a directive nobody wrote down is decided by a compiled-in default this probe cannot see. Passwordless sudo lets `sshd -T` answer exactly.'}`
        : 'Every directive in the baseline was read from sshd’s effective configuration and none of them is weak.'
  }
}

function failedCell(posture: HostPosture): Cell {
  const s = postureSource(posture, 'failed-logins')
  const fl = posture.failedLogins
  if (fl === null || fl.count === null) return gapCell(s.status, s.detail)
  return {
    text: `${fl.count}${fl.users !== null ? ` · ${fl.users} name${fl.users === 1 ? '' : 's'}` : ''}`,
    gap: null,
    bad: fl.count > 100,
    help: `${fl.count} failed attempts${fl.users === null ? '' : ` naming ${fl.users} distinct accounts`}, from ${fl.tool === 'lastb' ? 'lastb' : 'the journal'}${fl.window ? ` (${fl.window})` : ''}.`
  }
}


function oomCell(posture: HostPosture): Cell {
  const s = postureSource(posture, 'oom-kills')
  const k = posture.oomKills
  if (k === null || k.count === null) return gapCell(s.status, s.detail)
  if (k.count > 0) {
    const procs =
      k.processes === null ? '' : ` · ${k.processes} name${k.processes === 1 ? '' : 's'}`
    return {
      text: `${k.count} killed${procs}`,
      gap: null,
      bad: true,
      help: `The kernel reaped ${k.count} process${k.count === 1 ? '' : 'es'} for memory${
        k.processes === null ? '' : `, under ${k.processes} distinct name${k.processes === 1 ? '' : 's'}`
      }, read from ${k.window ?? 'the kernel log'}. Counts only: a process name is a string the process chose for itself.`
    }
  }
  // ZERO, AND THE WINDOW DECIDES WHETHER THAT IS A FINDING. Only the journal
  // is asked for a period of time; a ring buffer holds as much as it holds, so
  // a zero out of it is not a statement about a day and must not be drawn like
  // one. This is the single branch item 19b deferred this kind over.
  if (oomWindowIsStated(k.source)) {
    return {
      text: `none in ${OOM_WINDOW_HOURS}h`,
      gap: null,
      help: `The kernel journal was asked for the last ${OOM_WINDOW_HOURS} hours and holds no OOM kill. This is a reading over a stated window, not a gap.`
    }
  }
  return {
    text: 'none seen · window unbounded',
    gap: 'partial',
    help: `${POSTURE_STATUS_HELP.partial} This was read from ${k.window ?? 'a source with no stated window'}, which is not a period of time — it holds as much as it holds. Nothing was found in it, and that is NOT a report of no OOM kills in the last day. Passwordless sudo lets journalctl -k answer over a real window.`
  }
}

function certCell(posture: HostPosture): Cell {
  const s = postureSource(posture, 'certificates')
  const inv = posture.certificates
  if (inv === null) return gapCell(s.status, s.detail)
  const days = soonestCertificateExpiry(inv)
  const unread = inv.certificates.filter((c) => c.problem !== null).length
  const bound = `Searched ${inv.bound.roots.join(', ')} to ${inv.bound.maxDepth} levels, at most ${inv.bound.maxFiles} files, without crossing filesystems.`

  if (days === null) {
    // NOTHING WAS DATED, and the three reasons are not the same finding.
    if (inv.unreadableRoots > 0) {
      return {
        text: `${inv.unreadableRoots} director${inv.unreadableRoots === 1 ? 'y' : 'ies'} refused`,
        gap: s.status === 'ok' ? 'denied' : s.status,
        help: `A certificate directory that could not be entered is NOT a directory with no certificates. /etc/letsencrypt is 0700 root on most hosts, so this usually closes with passwordless sudo. ${bound}`
      }
    }
    if (unread > 0) {
      return {
        text: `${unread} could not be read`,
        gap: 'partial',
        help: `${unread} file${unread === 1 ? ' was' : 's were'} found and could not be dated — unreadable, not a certificate, or DER this build will not parse. A certificate that could not be parsed is not a certificate that is valid. ${bound}`
      }
    }
    return {
      text: s.status === 'absent' ? 'no certificate directories' : 'none found',
      gap: null,
      help:
        s.status === 'absent'
          ? `None of the directories ShellPilot looks in exists on this host, and that was checked rather than assumed. ${bound}`
          : `Every directory was read and holds no certificate. This is a reading, not a gap — and it is not the same as "this host is fine", because nothing here has an expiry to be near. ${bound}`
    }
  }

  // Something WAS dated, and something else may still be missing. The suffix is
  // not decoration: "45 days" beside a silently skipped /etc/letsencrypt is
  // worse than no number at all.
  const missing = inv.unreadableRoots + unread + (inv.truncated ? 1 : 0)
  const suffix = missing > 0 ? ` · ${missing} not read` : ''
  return {
    text: days < 0 ? `EXPIRED ${-days}d ago${suffix}` : `${days}d left${suffix}`,
    gap: null,
    bad: isCertificateExpiringSoon(days),
    help:
      (days < 0
        ? `The soonest certificate on this host expired ${-days} days ago. This is an outage in progress, not a warning.`
        : `The soonest certificate on this host has ${days} days left${isCertificateExpiringSoon(days) ? `, which is inside the ${CERT_EXPIRY_DAYS}-day line certbot itself renews at — the renewal that should have run has not` : ''}.`) +
      (missing > 0
        ? ` ${missing} other thing${missing === 1 ? '' : 's'} could not be read, so this number may not be the worst one on the host.`
        : '') +
      ` ${bound}`
  }
}

/** The security update count, TAKEN FROM ITEM C. Not recomputed here and not
 *  recomputed anywhere: the distribution's own answer is better than anything
 *  this app would derive, and `unsupported` has to survive all the way to the
 *  screen or an Arch host reads as clean during a CVE week. */
function updatesCell(facts: HostFacts | null): Cell {
  const r = securityUpdateReading(facts)
  if (r.count === null) {
    return {
      text: r.status === 'unsupported' ? 'cannot be answered' : gapWords[r.status === 'stale-metadata' ? 'ok' : r.status],
      gap: r.status === 'stale-metadata' ? null : (r.status as PostureStatus),
      help: `${FACT_STATUS_HELP[r.status]}${r.detail ? ` — ${r.detail}` : ''}`
    }
  }
  return {
    text: String(r.count),
    gap: null,
    bad: r.count > 0,
    help:
      r.count === 0
        ? 'The package manager was asked and reports no pending security updates. Collected by the Inventory probe, not recomputed here.'
        : `${r.count} pending security updates, as this host's own package manager counts them. Collected by the Inventory probe.`
  }
}

function CellView({ cell, host, col }: { cell: Cell; host: string; col: string }): React.JSX.Element {
  return (
    <td data-host={host} data-col={col}>
      {cell.gap === null ? (
        <span className={clsx(cell.bad && 'warn')} title={cell.help}>
          {cell.text}
        </span>
      ) : (
        // Never a dash, never a zero, never a tick. The words are the feature.
        <span className={clsx('inv-na', loudGap(cell.gap) && 'loud')} title={cell.help}>
          {cell.text}
        </span>
      )}
    </td>
  )
}

function DirectiveRow({ r }: { r: SshdReading }): React.JSX.Element {
  return (
    <div className="row" style={{ gap: 8, alignItems: 'baseline' }} data-directive={r.directive}>
      <span className="mono" style={{ minWidth: 190 }}>
        {r.directive}
      </span>
      {r.value === null ? (
        <span className={clsx('inv-na', r.verdict === 'unknown' && 'loud')} title={r.detail}>
          {r.ambiguous ? 'set twice, differently' : 'not read'}
        </span>
      ) : (
        <span className={clsx('mono', r.verdict === 'weak' && 'warn')} title={r.detail}>
          {r.value}
        </span>
      )}
      <span className="faint" style={{ fontSize: 11 }}>
        {r.detail}
      </span>
    </div>
  )
}

const COLUMNS: { id: string; label: string; help: string }[] = [
  { id: 'firewall', label: 'Firewall', help: 'Which firewall is active and how many rules it lists. Both the front end and the kernel tables underneath are read, because "ufw is inactive" is not "nothing is filtering".' },
  { id: 'mac', label: 'SELinux / AppArmor', help: 'Whether mandatory access control is enforcing. A host with neither is a finding, not a gap — and it is shown differently from a host that could not be asked.' },
  { id: 'sshd', label: 'sshd', help: 'Seven directives against a hardening baseline. A directive that could not be read is never counted as passing.' },
  { id: 'failed', label: 'Failed logins', help: 'How many failed attempts the host recorded and how many distinct account names they tried. Counts only: every field on a failed-login record is text an attacker chose.' },
  { id: 'updates', label: 'Security updates', help: 'Pending security updates as the host’s own package manager counts them. Collected by the Inventory probe and shown here unchanged — ShellPilot computes nothing from a CVE feed.' },
  { id: 'oom', label: 'OOM kills', help: 'Processes the kernel reaped for memory in the last 24 hours. Only the journal can be asked for a window — a count read from dmesg or kern.log is real, and a ZERO read from either is not a statement about a day and is not drawn as one.' },
  { id: 'certs', label: 'Certificates', help: 'Days left on the soonest certificate in a bounded set of named directories on this host. Not a TLS scanner: nothing is fetched over the network, the distribution trust store is deliberately not searched, and a directory that could not be entered is never rendered as a host with no certificates.' }
]

export function PosturePanel({
  servers,
  onOpen
}: {
  servers: Server[]
  onOpen?: (serverId: string) => void
}): React.JSX.Element {
  const [entries, setEntries] = useState<Record<string, Entry>>({})
  const [facts, setFacts] = useState<Record<string, HostFacts | null>>({})
  const [busy, setBusy] = useState(false)
  const [open, setOpen] = useState<string | null>(null)

  const load = useCallback(async (): Promise<void> => {
    const fleet = window.shellpilot?.fleet as Record<string, unknown> | undefined
    if (!bridgeHas(fleet, 'posture')) return
    const nextEntries: Record<string, Entry> = {}
    const nextFacts: Record<string, HostFacts | null> = {}
    await Promise.all(
      servers.map(async (s) => {
        const r = await window.shellpilot?.fleet?.posture(s.id)
        if (r) nextEntries[s.id] = { posture: r.posture, at: r.at, error: r.error, errorAt: r.errorAt }
        // Item C's collection, read alongside. The security update count is
        // ITS answer, and this panel shows it rather than deriving one.
        if (bridgeHas(fleet, 'facts')) {
          const f = await window.shellpilot?.fleet?.facts(s.id)
          nextFacts[s.id] = f?.facts ?? null
        }
      })
    )
    setEntries(nextEntries)
    setFacts(nextFacts)
  }, [servers])

  useEffect(() => {
    void load()
  }, [load])

  const refresh = async (): Promise<void> => {
    setBusy(true)
    try {
      // A sweep first, so a server added since the last one is collected rather
      // than reported as never checked, then a read of what main now holds.
      if (bridgeHas(window.shellpilot?.fleet as Record<string, unknown> | undefined, 'sampleNow')) {
        await window.shellpilot?.fleet?.sampleNow()
      }
      await load()
    } finally {
      setBusy(false)
    }
  }

  const rows = useMemo(
    () =>
      servers.map((s) => {
        const e = entries[s.id]
        const posture = e?.posture ?? null
        return {
          serverId: s.id,
          serverName: s.name,
          posture,
          at: e?.at,
          // An error only explains an ABSENCE. With a posture in hand the last
          // good collection is what the row shows, with its own age on it, and
          // the failure is reported above the table rather than by blanking a
          // host we still know things about.
          error: posture ? null : (e?.error ?? null),
          cells: posture
            ? {
                firewall: firewallCell(posture),
                mac: macCell(posture),
                sshd: sshdCell(posture),
                failed: failedCell(posture),
                updates: updatesCell(facts[s.id] ?? null),
                oom: oomCell(posture),
                certs: certCell(posture)
              }
            : {
                firewall: NEVER,
                mac: NEVER,
                sshd: NEVER,
                failed: NEVER,
                updates: updatesCell(facts[s.id] ?? null),
                oom: NEVER,
                certs: NEVER
              }
        }
      }),
    [servers, entries, facts]
  )

  const summary = useMemo(() => summarisePosture(rows.map((r) => ({ posture: r.posture }))), [rows])
  const failed = rows.filter((r): r is typeof r & { error: string } => typeof r.error === 'string')

  return (
    <div className="bc-panel">
      <div className="row" style={{ gap: 8, alignItems: 'center' }}>
        <ShieldAlert size={14} className="faint" />
        <b className="grow">Security posture</b>
        <button
          className="btn"
          disabled={busy || servers.length === 0}
          onClick={() => void refresh()}
          title="Sweeps the estate now and re-reads what has already been collected. Posture is re-collected at most once an hour per host. Nothing is changed by this: no firewall is enabled, no SELinux mode is set and no configuration is written."
        >
          <RefreshCw size={13} className={clsx(busy && 'spin')} /> Check now
        </button>
      </div>

      {summary.collected === 0 ? (
        <div className="s-desc">
          <b>No security posture has been collected yet.</b> ShellPilot reads it about once an hour,
          on the same background sweep as the inventory — so a server added in the last hour, or an
          estate where this has just been switched on, will not have any yet. Press{' '}
          <b>Check now</b> to sweep immediately, and make sure background checking is on in
          Settings. Nothing is changed by the probe: firewalls are read, never enabled; SELinux
          modes are read, never set; and no configuration file is written.
        </div>
      ) : (
        <>
          <div className="row wrap muted" style={{ fontSize: 11, marginTop: 8, gap: 12 }}>
            <span>
              {summary.hosts} host{summary.hosts === 1 ? '' : 's'} · posture for {summary.collected}
            </span>
            {/* Every count here has its gap beside it. A security roll-up drawn
                over only the hosts that answered is the exact shape of
                reassuring fiction this panel exists to avoid. */}
            <span>
              {summary.firewallActive} filtering
              {summary.firewallInactive > 0 && <span className="warn"> · {summary.firewallInactive} not</span>}
              {summary.firewallUnknown > 0 && (
                <span className="warn"> · {summary.firewallUnknown} could not be read</span>
              )}
            </span>
            <span>
              {summary.macEnforcing} enforcing
              {summary.macAbsent > 0 && <span> · {summary.macAbsent} with none installed</span>}
              {summary.macUnknown > 0 && <span className="warn"> · {summary.macUnknown} unknown</span>}
            </span>
            <span>
              {summary.sshdWeak > 0 && <span className="warn">{summary.sshdWeak} with a weak sshd setting</span>}
              {summary.sshdWeak === 0 && <span>no weak sshd settings found</span>}
              {summary.sshdUnknown > 0 && (
                <span className="warn"> · {summary.sshdUnknown} sshd config could not be read</span>
              )}
            </span>
            {/* Both of these carry their gap, for the reason every count above
                does: a roll-up drawn over the hosts that answered is the
                reassuring fiction this panel exists to avoid. `oomUnknown`
                counts every host answered by a ring buffer as well as every
                host that refused, because neither can support a "none". */}
            <span>
              {summary.oomKilling > 0 ? (
                <span className="warn">{summary.oomKilling} killing processes for memory</span>
              ) : (
                <span>no OOM kills seen</span>
              )}
              {summary.oomUnknown > 0 && (
                <span className="warn"> · {summary.oomUnknown} kernel log could not be read over a stated window</span>
              )}
            </span>
            <span>
              {summary.certExpired > 0 && (
                <span className="warn">{summary.certExpired} with an EXPIRED certificate</span>
              )}
              {summary.certExpired === 0 && summary.certExpiringSoon === 0 && (
                <span>no certificate inside {CERT_EXPIRY_DAYS} days</span>
              )}
              {summary.certExpiringSoon > 0 && (
                <span className="warn">
                  {summary.certExpired > 0 ? ' · ' : ''}
                  {summary.certExpiringSoon} expiring within {CERT_EXPIRY_DAYS} days
                </span>
              )}
              {summary.certUnknown > 0 && (
                <span className="warn"> · {summary.certUnknown} could not be fully read</span>
              )}
            </span>
          </div>

          {(summary.firewallUnknown > 0 || summary.sshdUnknown > 0) && (
            <div className="s-desc warn">
              <ShieldQuestion size={12} /> {summary.firewallUnknown + summary.sshdUnknown} check
              {summary.firewallUnknown + summary.sshdUnknown === 1 ? '' : 's'} across this estate could
              not run, and a check that could not run is not a check that passed. Those hosts are not
              in the counts above and they are not clear — most of these close with passwordless
              sudo for the account ShellPilot connects as, which lets the probe read a ruleset and
              ask sshd for its effective configuration. Nothing about that grants any write.
            </div>
          )}

          {failed.map((f) => (
            <div key={f.serverId} className="s-desc danger">
              {f.serverName}: the posture probe failed — {f.error}
            </div>
          ))}

          <div className="inv-scroll">
            <table className="table inv-table">
              <thead>
                <tr>
                  <th>Host</th>
                  {COLUMNS.map((c) => (
                    <th key={c.id} title={c.help}>
                      {c.label}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {rows.map((r) => (
                  // The Fragment carries the key: a bare `<>` inside a map
                  // gives React nothing to reconcile the two rows against, and
                  // the expanded sshd detail below is the second row.
                  <Fragment key={r.serverId}>
                    <tr
                      title={r.at === undefined ? 'Never collected.' : `Read ${duration(r.at)} ago.`}
                    >
                      <td data-host={r.serverName} data-col="host">
                        {onOpen ? (
                          <button className="inv-host" onClick={() => onOpen(r.serverId)} title={`Open ${r.serverName}`}>
                            {r.serverName}
                          </button>
                        ) : (
                          <span>{r.serverName}</span>
                        )}
                        {r.posture?.sshd && (
                          <button
                            className="btn ghost sm"
                            style={{ marginLeft: 6 }}
                            onClick={() => setOpen((o) => (o === r.serverId ? null : r.serverId))}
                            title="Show every directive in the hardening baseline, including the ones that could not be read."
                          >
                            {open === r.serverId ? 'Hide sshd' : 'sshd'}
                          </button>
                        )}
                      </td>
                      {COLUMNS.map((c) => (
                        <CellView
                          key={c.id}
                          cell={r.cells[c.id as keyof typeof r.cells]}
                          host={r.serverName}
                          col={c.id}
                        />
                      ))}
                    </tr>
                    {open === r.serverId && r.posture?.sshd && (
                      <tr>
                        <td colSpan={COLUMNS.length + 1}>
                          <div className="s-desc" data-sshd-detail={r.serverName}>
                            {r.posture.sshd.effective ? (
                              <b>Read from sshd&rsquo;s own effective configuration.</b>
                            ) : (
                              <b>
                                Read from configuration files, not from sshd. A directive nobody
                                wrote down is decided by a compiled-in default this probe cannot
                                see, so it is shown as unread rather than guessed.
                              </b>
                            )}
                            {r.posture.sshd.matchBlocks !== null && r.posture.sshd.matchBlocks > 0 && (
                              <div className="warn" style={{ marginTop: 4 }}>
                                This configuration has {r.posture.sshd.matchBlocks} conditional{' '}
                                <span className="mono">Match</span> block
                                {r.posture.sshd.matchBlocks === 1 ? '' : 's'}. The values below are
                                the global ones; a connection matching one of those blocks gets
                                different answers.
                              </div>
                            )}
                            <div style={{ marginTop: 6 }}>
                              {SSHD_DIRECTIVES.map((d) => {
                                const reading = r.posture?.sshd?.readings.find((x) => x.directive === d)
                                return reading ? <DirectiveRow key={d} r={reading} /> : null
                              })}
                            </div>
                          </div>
                        </td>
                      </tr>
                    )}
                  </Fragment>
                ))}
              </tbody>
            </table>
          </div>

          {/* The per-source detail, for the person whose next question is
              "why couldn't it read that". A status word with nothing behind it
              sends people to the wrong machine. */}
          {rows
            .filter((r) => r.posture !== null)
            .flatMap((r) =>
              POSTURE_SOURCE_IDS
                .map((id) => ({ row: r, s: postureSource(r.posture as HostPosture, id) }))
                .filter(({ s }) => s.status === 'denied' && s.detail)
                .map(({ row, s }) => (
                  <div key={`${row.serverId}-${s.id}`} className="faint" style={{ fontSize: 11, marginTop: 4 }}>
                    {row.serverName} · {s.label}: {s.detail}
                  </div>
                ))
            )}
        </>
      )}
    </div>
  )
}
