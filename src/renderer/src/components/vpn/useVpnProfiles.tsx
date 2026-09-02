import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { AlertTriangle, ChevronRight, Loader2, Pencil, Power, ScrollText, Trash2 } from 'lucide-react'
import { Modal } from '../common/Modal'
import { useApp, useWorkspaceVpns } from '../../store/app'
import { toast, type ToastAction } from '../../store/toast'
import { bytes, clsx } from '../../lib/format'
import { bridgeHas } from '../../lib/bridge'
import { withVaultUnlock } from '../../lib/withVaultUnlock'
import { isVpnRunning } from '../../../../shared/vpn'
import { userSuppliesEngine } from '../../../../shared/vpnEngines'
import type {
  FrpProxy,
  VpnDependent,
  VpnEngineInfo,
  VpnErrorCode,
  VpnKind,
  VpnProfile,
  VpnResult,
  VpnStartResult
} from '../../types'
import {
  HealthChip,
  HealthDot,
  VpnStatusCard,
  frpSummary,
  handshakeLabel,
  vpnHealth
} from './VpnStatusCard'
import { VpnImportModal } from './VpnImportModal'
import { VpnProfileForm, type VpnFormFocus } from './VpnProfileForm'
import { VpnLogDrawer } from './VpnLogDrawer'

const KIND_LABEL: Record<VpnKind, string> = {
  wireguard: 'WireGuard',
  openvpn: 'OpenVPN',
  frp: 'frp'
}

/** The proxies whose exposure the user has not ticked. Start refuses while this
 *  is non-empty — the gate lives in main, but the reason belongs on screen. */
function ungatedProxies(profile: VpnProfile): FrpProxy[] {
  return profile.spec.kind === 'frp'
    ? profile.spec.proxies.filter((p) => !p.acknowledgedExposure)
    : []
}

function subtitle(profile: VpnProfile): string {
  const spec = profile.spec
  if (spec.kind === 'wireguard') {
    const peer = spec.peers[0]
    const mode = spec.mode === 'userspace' ? 'userspace' : 'system'
    return `WireGuard · ${mode}${peer?.endpoint ? ` · ${peer.endpoint}` : ''}`
  }
  if (spec.kind === 'openvpn') {
    const r = spec.remotes?.[0]
    return `OpenVPN${r ? ` · ${r.host}:${r.port}` : ''}`
  }
  return `frp · ${frpSummary(spec)}`
}

/** What the vault loses along with the profile. Naming it is the point: "its
 *  secrets are deleted" does not tell a WireGuard user that the private key
 *  they never wrote down anywhere else is about to stop existing. */
function vaultLoss(profile: VpnProfile): string {
  const kind = profile.spec.kind
  if (kind === 'wireguard') return 'its private key and any preshared keys'
  if (kind === 'openvpn') {
    return 'its stored configuration — including any inline certificates and keys — and its saved credentials'
  }
  return 'its server token and any proxy secret keys'
}

const OPENVPN_DOWNLOAD = 'https://openvpn.net/community-downloads/'

/** Open a page in the user's browser.
 *
 *  `setWindowOpenHandler` in main/index.ts turns every `window.open` into
 *  `shell.openExternal` and denies the window, so this is the route that is
 *  already wired — no new preload method involved. */
function openExternal(url: string): void {
  window.open(url, '_blank', 'noopener,noreferrer')
}

/** The generic sentence `internal` carries. Matched, not guessed: it is the one
 *  message in VPN_ERROR_MESSAGE that describes nothing. */
const INTERNAL_PREFIX = 'Something went wrong inside ShellPilot.'

/** The first sentence of a message from main.
 *
 *  Every VPN failure is composed as message + detail + hint (see
 *  services/vpn/errors.ts) and only the first of the three says what happened.
 *  The hint is advice, and the advice is a button now; the detail is
 *  diagnostics — the paths an engine was looked for in — which belong under
 *  Details, read by someone who wants them rather than at someone who does
 *  not.
 *
 *  Except for `internal`, whose first sentence says nothing at all. OpenVPN
 *  failing because its management socket path was too long produced the toast
 *  "Something went wrong inside ShellPilot." and an empty log drawer — a
 *  message with no fact in it, in front of the one detail that explained the
 *  failure. When the sentence is that one, the detail IS the headline. */
export function headline(text: string): string {
  const trimmed = text.trim()
  if (trimmed.startsWith(INTERNAL_PREFIX)) {
    const rest = trimmed.slice(INTERNAL_PREFIX.length).trim()
    if (rest !== '') return headline(rest)
  }
  const end = trimmed.indexOf('. ')
  return end === -1 ? trimmed : trimmed.slice(0, end + 1)
}

/** What each remedy actually does, supplied by the component that can do it. */
interface Remedies {
  /** Open this profile's form, optionally standing on the field at fault. */
  profile: (focus?: VpnFormFocus) => void
  log: () => void
  /** Start it again. Also the vault route: `start` prompts for an unlock and
   *  retries on its own, so "unlock" and "try again" are the same call. */
  start: () => void
  vault: () => void
}

/** The one control that ends this failure, or undefined when no control would.
 *
 *  A button that does not actually help is worse than no button: it costs a
 *  click to find out it was useless, and it teaches the user to stop pressing
 *  the next one. So `cert-expired` gets nothing — a new certificate comes from
 *  whoever issued it — and neither does `clock-skew`, `network-unreachable` or
 *  a bundled engine that failed its checksum, all of which are fixed outside
 *  this window. */
function remedyFor(
  code: VpnErrorCode | undefined,
  kind: VpnKind,
  platform: NodeJS.Platform | null,
  r: Remedies
): ToastAction | undefined {
  switch (code) {
    // Not "go and unlock the vault, then come back": `start` asks for the
    // unlock and retries by itself, so this button finishes the job the user
    // originally pressed.
    case 'vault-locked':
      return { label: 'Unlock vault', run: r.start }
    // WireGuard and frp always ship inside ShellPilot, and OpenVPN does too
    // everywhere except Windows — so on every other combination a missing
    // engine is a damaged install, which no button in this window can repair.
    // Offering a download page there would send the reader off to install
    // something they already have.
    case 'binary-missing':
      return kind === 'openvpn' && userSuppliesEngine('openvpn', platform)
        ? { label: 'Install OpenVPN', run: () => openExternal(OPENVPN_DOWNLOAD) }
        : undefined
    case 'exposure-unacknowledged':
      return { label: 'Open profile', run: () => r.profile('proxies') }
    case 'config-invalid':
    case 'config-rejected':
    case 'dns-failure':
    case 'handshake-timeout':
    case 'interface-conflict':
    case 'port-in-use':
    case 'proxy-required':
    case 'server-rejected':
      return { label: 'Open profile', run: () => r.profile() }
    // Credentials are never in the profile — they are in the vault, handed to
    // the engine over its management socket — so the profile form is the wrong
    // room to send someone whose password was rejected.
    case 'auth-failed':
      return { label: 'Open vault', run: r.vault }
    case 'elevation-declined':
    case 'permission-denied':
      return { label: 'Try again', run: r.start }
    case 'crash-loop':
    case 'internal':
    case 'tls-handshake-failed':
      return { label: 'Show log', run: r.log }
    default:
      return undefined
  }
}

/** True when the status stream has already toasted this failure.
 *
 *  The subscription below toasts every error a status carries, and start/stop
 *  used to toast the returned error as well — so a single refused start said
 *  the same sentence twice. The stream is the one that always fires, so it
 *  keeps the message and the call sites only speak when it did not. */
function errorSpoken(id: string): boolean {
  return useApp.getState().vpnStatuses[id]?.state === 'error'
}

// `.tab .title` in global.css is these same three lines. `.list-row .r-title`
// never got them, and neither did the wrapper's min-width, so a long endpoint
// in the subtitle pushed Start off the right edge of the row.
const ELLIPSIS: React.CSSProperties = {
  overflow: 'hidden',
  textOverflow: 'ellipsis',
  whiteSpace: 'nowrap'
}

/** Everything a profile list needs, minus the words around it. */
export interface VpnProfiles {
  /** One profile as a row: status, controls and whatever is blocking it. */
  row: (profile: VpnProfile) => React.JSX.Element
  /** Every dialog the rows can open. Render it once, anywhere in the view. */
  dialogs: React.JSX.Element
  /** Open the importer for a kind of config file. */
  importProfile: (kind: VpnKind) => void
  /** Open the profile form — on a stored profile, or on a fresh blank one. */
  editProfile: (profile: VpnProfile) => void
}

/**
 * The machinery behind a list of VPN profiles: status, start/stop, failure
 * reporting, and the dialogs all of that opens.
 *
 * VPN and frp are two destinations in the UI but one subsystem underneath —
 * same IPC surface, same vault interaction, same failure vocabulary — so the
 * behaviour lives here once and `VpnManager` and `FrpManager` only decide which
 * profiles to show and what to call them. Duplicating any of it would mean two
 * places to fix the next time a start can fail in a new way.
 */
export function useVpnProfiles(): VpnProfiles {
  const profiles = useWorkspaceVpns()
  const vpnStatuses = useApp((s) => s.vpnStatuses)
  const setVpnStatus = useApp((s) => s.setVpnStatus)
  const removeVpnProfile = useApp((s) => s.removeVpnProfile)
  const setActivity = useApp((s) => s.setActivity)

  const [busy, setBusy] = useState<Record<string, boolean>>({})
  const [expanded, setExpanded] = useState<string | null>(null)
  const [importing, setImporting] = useState<VpnKind | null>(null)
  // Carries where to stand as well as what to edit: a failure that knows the
  // port is taken can open the form on the port.
  const [editing, setEditing] = useState<{ profile: VpnProfile; focus?: VpnFormFocus } | null>(null)
  const [logsFor, setLogsFor] = useState<VpnProfile | null>(null)
  const [confirmStop, setConfirmStop] = useState<{
    profile: VpnProfile
    dependents: VpnDependent[]
  } | null>(null)
  const [confirmDelete, setConfirmDelete] = useState<{
    profile: VpnProfile
    dependents: VpnDependent[]
    attached: { id: string; kind: string; name: string }[]
  } | null>(null)
  const [engines, setEngines] = useState<Partial<Record<VpnKind, VpnEngineInfo>>>({})
  // Feeds `userSuppliesEngine`, which decides whether a missing engine is the
  // user's to install or a damaged install of ours. Null until the round trip
  // lands, and that shared helper treats null as "not the user's".
  const [platform, setPlatform] = useState<NodeJS.Platform | null>(null)
  useEffect(() => {
    let live = true
    void window.shellpilot?.platform().then((p) => {
      if (live) setPlatform(p)
    })
    return () => {
      live = false
    }
  }, [])

  // `start` reports its failures through `report`, and several of `report`'s
  // buttons start. They genuinely refer to each other, so one of the two is
  // read through a ref — which is also what lets the status subscription below
  // stay keyed on the profile ids alone.
  const reportRef = useRef<(id: string, error: string, code?: VpnErrorCode) => void>(() => {})

  // Starts the user pulled the plug on. A cancelled start still resolves with a
  // failure, and reporting that as one is how cancelling would earn a red toast
  // on top of the one the Cancel button already produced.
  const cancelledStarts = useRef<Set<string>>(new Set())

  // Subscribe to status for every profile in the workspace — including the ones
  // the visible tab is not listing. The sidebar shows a health dot for all
  // three sections at once, so narrowing this to the current tab's profiles is
  // exactly how the other two would go stale the moment you switched.
  //
  // Keyed on the ids rather than the profile objects, for the same reason
  // TunnelManager.tsx:36-51 is: a status arrives up to once a second per
  // profile, and depending on the list itself would tear down and rebuild every
  // subscription on each one. The name is resolved when an error actually
  // fires, which keeps renames out of this dependency too.
  const vpnIds = profiles.map((p) => p.id).join(',')
  useEffect(() => {
    const ids = vpnIds ? vpnIds.split(',') : []
    if (!bridgeHas(window.shellpilot?.vpn as Record<string, unknown> | undefined, 'onStatus')) return
    const offs = ids.map((id) =>
      window.shellpilot?.vpn.onStatus(id, (s) => {
        setVpnStatus(id, s)
        if (s.state === 'error' && s.error) reportRef.current(id, s.error, s.errorCode)
      })
    )
    return () => offs.forEach((off) => off?.())
  }, [vpnIds, setVpnStatus])

  // Reconcile with what is actually running. This view unmounts whenever the
  // user switches activity, and a tunnel started before that is still up.
  useEffect(() => {
    if (!bridgeHas(window.shellpilot?.vpn as Record<string, unknown> | undefined, 'list')) return
    void window.shellpilot?.vpn.list().then((list) => {
      if (!list) return
      list.forEach((s) => setVpnStatus(s.id, s))
    })
  }, [setVpnStatus])

  // Probe once per kind actually in use. A missing OpenVPN binary is the kind of
  // thing that should be visible before Start is pressed, not after.
  const kinds = useMemo(() => [...new Set(profiles.map((p) => p.spec.kind))].join(','), [profiles])
  useEffect(() => {
    if (!kinds) return
    if (!bridgeHas(window.shellpilot?.vpn as Record<string, unknown> | undefined, 'probe')) return
    let live = true
    for (const k of kinds.split(',') as VpnKind[]) {
      void window.shellpilot?.vpn.probe(k).then((info) => {
        if (live && info) setEngines((e) => ({ ...e, [k]: info }))
      })
    }
    return () => {
      live = false
    }
  }, [kinds])

  const start = useCallback(async (p: VpnProfile): Promise<void> => {
    setBusy((b) => ({ ...b, [p.id]: true }))
    // docs/VPN.md promises that starting against a locked vault asks to unlock
    // it. The vault reports that as a code on a *resolved* result rather than as
    // a rejection, which withVaultUnlock now recognises too — so this is the
    // same one-shot prompt-and-retry every other surface in the app gets, from
    // one definition of what "locked" looks like. Declining hands back the
    // failed result rather than throwing, which is what the tail below expects.
    //
    // withVaultUnlock rethrows anything that is not a lock error, and the IPC
    // itself can reject. Without the finally, setBusy(false) was skipped: the
    // row kept its spinner forever, and because status.state was never
    // 'starting' the Cancel button was not offered either — leaving a profile
    // that could be neither started nor stopped until the component unmounted.
    let r: VpnStartResult | undefined
    try {
      r = await withVaultUnlock(`Starting ${p.name}`, () =>
        Promise.resolve(window.shellpilot?.vpn.start(p.id))
      )
    } catch (err) {
      // Same suppression the resolved-failure tail below applies: Cancel and
      // the status stream have each already said what happened.
      const wasCancelled = cancelledStarts.current.delete(p.id)
      if (!wasCancelled && !errorSpoken(p.id)) {
        reportRef.current(p.id, err instanceof Error ? err.message : String(err))
      }
      return
    } finally {
      setBusy((b) => ({ ...b, [p.id]: false }))
    }
    const cancelled = cancelledStarts.current.delete(p.id)
    if (r?.ok) {
      const first = r.listeners?.[0]
      toast(
        first ? `${p.name} up — listening on ${first.bindHost}:${first.bindPort}` : `${p.name} up`,
        'ok'
      )
      return
    }
    // Cancel has already said what happened, and so has the status stream when
    // it carried the error. Either way this failure is spoken for.
    if (cancelled || errorSpoken(p.id)) return
    reportRef.current(p.id, r?.error ?? 'This tunnel could not be started.', r?.errorCode)
  }, [])

  // The single place a VPN failure becomes something on screen — the status
  // stream, start and stop all come through here, so one failure cannot get two
  // different phrasings depending on which of them noticed it first. One line
  // and one button: the rest of what main said stays under the row, behind
  // Details, and in the log.
  const report = (id: string, error: string, code?: VpnErrorCode): void => {
    const p = useApp.getState().vpns.find((v) => v.id === id)
    const action = p
      ? remedyFor(code, p.spec.kind, platform, {
          profile: (focus) => setEditing({ profile: p, focus }),
          log: () => setLogsFor(p),
          start: () => void start(p),
          vault: () => setActivity('vault')
        })
      : undefined
    toast(`${p?.name ?? 'VPN'}: ${headline(error)}`, 'error', action)
  }
  reportRef.current = report

  const stop = useCallback(async (p: VpnProfile, cancelling = false): Promise<void> => {
    setBusy((b) => ({ ...b, [p.id]: true }))
    // Same reason as start: a rejected stop used to strand the row on its
    // spinner with no way back.
    let r: VpnResult | undefined
    try {
      r = await window.shellpilot?.vpn.stop(p.id)
    } catch (err) {
      if (!errorSpoken(p.id)) {
        reportRef.current(p.id, err instanceof Error ? err.message : String(err))
      }
      return
    } finally {
      setBusy((b) => ({ ...b, [p.id]: false }))
    }
    if (r?.ok) {
      toast(cancelling ? `${p.name} — connection attempt cancelled` : `${p.name} stopped`)
      return
    }
    // An engine that refuses to die used to produce a red dot, an error toast
    // and "X stopped", all at once, because the old preload signature threw the
    // result away. It reports one now, so this can say what actually happened.
    if (errorSpoken(p.id)) return
    reportRef.current(
      p.id,
      r?.error ?? `This tunnel could not be ${cancelling ? 'cancelled' : 'stopped'}.`,
      r?.errorCode
    )
  }, [])

  // A start can sit in TLS negotiation, an elevation prompt or an OTP
  // round-trip for the better part of a minute. vpnStop already serialises
  // against an in-flight start, so the way out is the control that is already
  // there rather than a disabled spinner and the Force Quit menu.
  const cancel = useCallback(
    async (p: VpnProfile): Promise<void> => {
      cancelledStarts.current.add(p.id)
      await stop(p, true)
    },
    [stop]
  )

  const requestStop = useCallback(
    async (p: VpnProfile) => {
      // Ask before pulling the transport out from under anything riding on it.
      // A stored definition can be restarted; a live session cannot, which is
      // what makes this destructive rather than merely inconvenient.
      const ns = window.shellpilot?.vpn as Record<string, unknown> | undefined
      const deps = bridgeHas(ns, 'dependents') ? await window.shellpilot?.vpn.dependents(p.id) : []
      const live = (deps ?? []).filter((d) => d.live)
      if (live.length > 0) {
        setConfirmStop({ profile: p, dependents: live })
        return
      }
      await stop(p)
    },
    [stop]
  )

  const toggle = useCallback(
    async (p: VpnProfile) => {
      const state = vpnStatuses[p.id]?.state
      if (state && isVpnRunning(state)) {
        await requestStop(p)
        return
      }
      await start(p)
    },
    [vpnStatuses, requestStop, start]
  )

  // Deleting a profile deletes its key material from the vault, closes whatever
  // is riding on it and rewrites every saved connection that named it. All
  // three used to happen on one click of a trash icon, and the only account of
  // any of it was a toast after the fact. Everything the dialog needs is
  // gathered before the delete, because the same store action detaches them.
  const requestRemove = useCallback(async (p: VpnProfile): Promise<void> => {
    const ns = window.shellpilot?.vpn as Record<string, unknown> | undefined
    const deps = bridgeHas(ns, 'dependents') ? await window.shellpilot?.vpn.dependents(p.id) : []
    const st = useApp.getState()
    const attached = [
      ...st.servers
        .filter((sv) => sv.vpnProfileId === p.id)
        .map((sv) => ({ id: sv.id, kind: 'server', name: sv.name })),
      ...st.databases
        .filter((d) => d.vpnProfileId === p.id)
        .map((d) => ({ id: d.id, kind: 'database', name: d.name }))
    ]
    setConfirmDelete({ profile: p, dependents: (deps ?? []).filter((d) => d.live), attached })
  }, [])

  const remove = useCallback(
    async (p: VpnProfile): Promise<void> => {
      // The stop result was discarded, and it does report {ok: false} when the
      // engine will not die. Deleting anyway dropped the profile, its status and
      // its vault key material while the tunnel kept its routes — under a
      // "deleted" toast, with nothing left on screen able to stop it. So a
      // failed stop cancels the delete instead: the profile is still there, and
      // so is the Stop button.
      let r: VpnResult | undefined
      try {
        r = await window.shellpilot?.vpn.stop(p.id)
      } catch (err) {
        r = { ok: false, error: err instanceof Error ? err.message : String(err) }
      }
      if (r && !r.ok) {
        reportRef.current(
          p.id,
          r.error ?? `${p.name} is still running and could not be stopped, so it was not deleted.`,
          r.errorCode
        )
        return
      }
      removeVpnProfile(p.id)
      toast(`${p.name} deleted`)
    },
    [removeVpnProfile]
  )

  const row = (p: VpnProfile): React.JSX.Element => {
    const status = vpnStatuses[p.id]
    const health = vpnHealth(status)
    const running = !!status && isVpnRunning(status.state)
    const ungated = ungatedProxies(p)
    const engine = engines[p.spec.kind]
    const open = expanded === p.id
    const gated = !running && ungated.length > 0
    const engineMissing = engine?.available === false
    // main explains where it looked, what to install and why it will not look
    // anywhere else. All true, none of it needed before the user has decided
    // what to do — so the row shows the first sentence and the buttons, and
    // keeps the rest one click away.
    const engineProblem = headline(
      engine?.reason ?? `${KIND_LABEL[p.spec.kind]} is not available on this machine.`
    )
    const sub = subtitle(p)
    // Mid-start, and slow enough to be worth escaping from.
    const cancellable =
      !!busy[p.id] && (status?.state === 'starting' || status?.state === 'authenticating')

    return (
      <div key={p.id} className="col" style={{ gap: 0 }}>
        <div className="list-row">
          <HealthDot health={health} />
          <button
            className="row"
            // The card behind this row is the reason to look at the pane at
            // all, and it used to be a bare cursor:pointer div — no chevron, no
            // hover, no way to reach it from the keyboard.
            style={{ gap: 8, minWidth: 0, flex: '0 1 auto', textAlign: 'left' }}
            aria-expanded={open}
            title={open ? 'Hide details' : 'Show assigned IP, endpoint and listeners'}
            onClick={() => setExpanded(open ? null : p.id)}
          >
            <ChevronRight
              size={14}
              className={clsx('chev', open && 'open')}
              style={{
                flex: 'none',
                color: 'var(--text-faint)',
                transition: 'transform .12s',
                transform: open ? 'rotate(90deg)' : undefined
              }}
            />
            <div style={{ minWidth: 0 }}>
              <div className="r-title" style={ELLIPSIS} title={p.name}>
                {p.name}
              </div>
              <div className="r-sub" style={ELLIPSIS} title={sub}>
                {sub}
              </div>
            </div>
          </button>
          <span className="spacer" />
          <div className="r-stat mono" style={{ alignItems: 'center' }}>
            {p.spec.kind === 'wireguard' && running && (
              <span>{handshakeLabel(status?.stats?.lastHandshakeSec)}</span>
            )}
            {running && status?.stats && (
              <span>
                ↓ {bytes(status.stats.rxBytes)} ↑ {bytes(status.stats.txBytes)}
              </span>
            )}
          </div>
          <HealthChip health={health} />
          <button
            className={clsx('btn sm', running || cancellable ? 'danger' : 'primary')}
            disabled={(busy[p.id] && !cancellable) || gated || (!running && engineMissing)}
            title={
              cancellable
                ? 'Stop waiting and tear the connection attempt down'
                : gated
                  ? 'Confirm what each proxy exposes before starting'
                  : engineMissing
                    ? engineProblem
                    : undefined
            }
            onClick={() => void (cancellable ? cancel(p) : toggle(p))}
          >
            {busy[p.id] ? <Loader2 size={13} className="spin" /> : <Power size={13} />}
            {cancellable ? 'Cancel' : running ? 'Stop' : 'Start'}
          </button>
          <button
            className="icon-btn sm"
            title="Edit profile"
            onClick={() => setEditing({ profile: p })}
          >
            <Pencil size={14} />
          </button>
          <button className="icon-btn sm" title="Show log" onClick={() => setLogsFor(p)}>
            <ScrollText size={14} />
          </button>
          <button
            className="icon-btn sm"
            title="Delete profile"
            onClick={() => void requestRemove(p)}
          >
            <Trash2 size={14} />
          </button>
        </div>

        {engineMissing && (
          <div className="col" style={{ gap: 6, padding: '6px 16px' }}>
            <div className="row" style={{ gap: 6, color: 'var(--danger)', fontSize: 11 }}>
              <AlertTriangle size={12} style={{ flexShrink: 0 }} />
              <span className="grow">{engineProblem}</span>
              {/* "Set the path" holds everywhere OpenVPN is involved: pointing
                  at a copy you installed yourself is a valid answer whether or
                  not we ship one. "Install OpenVPN" does not — see
                  `userSuppliesEngine`. WireGuard and frp get neither; both
                  always ship with ShellPilot. */}
              {p.spec.kind === 'openvpn' && (
                <>
                  {userSuppliesEngine('openvpn', platform) && (
                    <button
                      className="btn sm primary"
                      onClick={() => openExternal(OPENVPN_DOWNLOAD)}
                    >
                      Install OpenVPN
                    </button>
                  )}
                  <button
                    className="btn sm"
                    onClick={() => setEditing({ profile: p, focus: 'binaryPath' })}
                  >
                    Set the path
                  </button>
                </>
              )}
            </div>
            {engine?.reason && engine.reason !== engineProblem && (
              <details className="disclosure">
                <summary className="disclosure-head">Details</summary>
                <div className="disclosure-body">
                  <span className="faint" style={{ fontSize: 11 }}>
                    {engine.reason}
                  </span>
                </div>
              </details>
            )}
          </div>
        )}

        {gated && (
          // Naming the proxies is the point. "Acknowledge exposure to continue"
          // just sends the user hunting for the checkbox they missed — and so,
          // very nearly, did the sentence that used to describe the journey to
          // it instead of offering the button.
          <div
            className="row"
            style={{ gap: 6, padding: '6px 16px', color: 'var(--warn)', fontSize: 11 }}
          >
            <AlertTriangle size={12} style={{ flexShrink: 0 }} />
            <span className="grow">
              Confirm what {ungated.map((x) => x.name).join(', ')}{' '}
              {ungated.length === 1 ? 'exposes' : 'expose'} before starting.
            </span>
            <button
              className="btn sm primary"
              onClick={() => setEditing({ profile: p, focus: 'proxies' })}
            >
              {ungated.length === 1 ? 'Confirm it' : 'Confirm them'}
            </button>
          </div>
        )}

        {open && (
          <div style={{ padding: '8px 0 0' }}>
            <VpnStatusCard profile={p} status={status} />
          </div>
        )}
      </div>
    )
  }

  const dialogs = (
    <>
      {importing && <VpnImportModal kind={importing} onClose={() => setImporting(null)} />}
      {editing && (
        <VpnProfileForm
          profile={editing.profile}
          focus={editing.focus}
          onClose={() => setEditing(null)}
        />
      )}
      {logsFor && (
        <VpnLogDrawer
          profileId={logsFor.id}
          profileName={logsFor.name}
          onClose={() => setLogsFor(null)}
        />
      )}
      {confirmStop && (
        <Modal
          title="Stop this VPN?"
          subtitle={confirmStop.profile.name}
          onClose={() => setConfirmStop(null)}
        >
          <div className="card" style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
            <div className="row" style={{ gap: 8, color: 'var(--warn)' }}>
              <AlertTriangle size={16} />
              <span style={{ fontSize: 13 }}>
                {confirmStop.dependents.length}{' '}
                {confirmStop.dependents.length === 1 ? 'session is' : 'sessions are'} using this VPN.
              </span>
            </div>
            <div className="col" style={{ gap: 2 }}>
              {confirmStop.dependents.map((d) => (
                <span key={`${d.kind}-${d.id}`} className="muted" style={{ fontSize: 12 }}>
                  {d.name} <span className="faint">({d.kind})</span>
                </span>
              ))}
            </div>
            <span className="faint" style={{ fontSize: 11 }}>
              They are closed first, then the tunnel — nothing is left talking to a network that is
              no longer there.
            </span>
            <div className="row" style={{ gap: 8 }}>
              <span className="grow" />
              <button className="btn sm" onClick={() => setConfirmStop(null)}>
                Keep it running
              </button>
              <button
                className="btn danger sm"
                onClick={() => {
                  const p = confirmStop.profile
                  setConfirmStop(null)
                  void stop(p)
                }}
              >
                Stop anyway
              </button>
            </div>
          </div>
        </Modal>
      )}
      {confirmDelete && (
        <Modal
          title="Delete this VPN profile?"
          subtitle={confirmDelete.profile.name}
          onClose={() => setConfirmDelete(null)}
        >
          <div className="card" style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
            <div className="row" style={{ gap: 8, color: 'var(--danger)' }}>
              <AlertTriangle size={16} />
              <span style={{ fontSize: 13 }}>
                Deleting {confirmDelete.profile.name} deletes {vaultLoss(confirmDelete.profile)}{' '}
                from the vault. That key material cannot be recovered — if it is not saved anywhere
                else, this profile cannot be recreated.
              </span>
            </div>

            {confirmDelete.dependents.length > 0 && (
              <div className="col" style={{ gap: 2 }}>
                <span className="field-label">
                  {confirmDelete.dependents.length}{' '}
                  {confirmDelete.dependents.length === 1 ? 'live session is' : 'live sessions are'}{' '}
                  using it, and will be closed
                </span>
                {confirmDelete.dependents.map((d) => (
                  <span key={`${d.kind}-${d.id}`} className="muted" style={{ fontSize: 12 }}>
                    {d.name} <span className="faint">({d.kind})</span>
                  </span>
                ))}
              </div>
            )}

            {confirmDelete.attached.length > 0 && (
              // Rewriting a saved connection on the user's behalf is the right
              // thing to do here; doing it silently is not, and afterwards is
              // too late to object.
              <div className="col" style={{ gap: 2 }}>
                <span className="field-label">
                  {confirmDelete.attached.length}{' '}
                  {confirmDelete.attached.length === 1 ? 'connection' : 'connections'} will be
                  detached and will connect directly from now on
                </span>
                {confirmDelete.attached.map((a) => (
                  <span key={`${a.kind}-${a.id}`} className="muted" style={{ fontSize: 12 }}>
                    {a.name} <span className="faint">({a.kind})</span>
                  </span>
                ))}
              </div>
            )}

            <span className="faint" style={{ fontSize: 11 }}>
              The profile itself is only stored here — nothing on the far side of the tunnel
              changes.
            </span>
            <div className="row" style={{ gap: 8 }}>
              <span className="grow" />
              <button className="btn sm" onClick={() => setConfirmDelete(null)}>
                Keep it
              </button>
              <button
                className="btn danger sm"
                onClick={() => {
                  const p = confirmDelete.profile
                  setConfirmDelete(null)
                  void remove(p)
                }}
              >
                <Trash2 size={14} /> Delete profile and key material
              </button>
            </div>
          </div>
        </Modal>
      )}
    </>
  )

  return {
    row,
    dialogs,
    importProfile: setImporting,
    editProfile: (profile) => setEditing({ profile })
  }
}
