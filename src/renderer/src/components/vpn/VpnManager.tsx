import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import {
  AlertTriangle,
  ChevronRight,
  Globe,
  Loader2,
  Pencil,
  Plus,
  Power,
  ScrollText,
  Share2,
  Trash2
} from 'lucide-react'
import { EmptyState } from '../common/EmptyState'
import { Modal } from '../common/Modal'
import { useApp, useWorkspaceVpns } from '../../store/app'
import { useVaultPrompt } from '../../store/vaultPrompt'
import { toast } from '../../store/toast'
import { bytes, clsx } from '../../lib/format'
import { bridgeHas } from '../../lib/bridge'
import { isVpnRunning } from '../../../../shared/vpn'
import type { FrpProxy, VpnDependent, VpnEngineInfo, VpnKind, VpnProfile } from '../../types'
import {
  HealthChip,
  HealthDot,
  VpnStatusCard,
  frpSummary,
  handshakeLabel,
  vpnHealth
} from './VpnStatusCard'
import { VpnImportModal } from './VpnImportModal'
import { VpnProfileForm } from './VpnProfileForm'
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

function blankFrpProfile(workspaceId: string): VpnProfile {
  return {
    id: `vpn-${crypto.randomUUID()}`,
    workspaceId,
    name: 'New frp client',
    autoStart: false,
    // No proxies: a fresh client connects and exposes nothing, which is the
    // only safe thing an empty form can mean here.
    spec: {
      kind: 'frp',
      serverAddr: '',
      serverPort: 7000,
      auth: { method: 'token' },
      transport: { protocol: 'tcp', tlsEnable: true },
      proxies: [],
      visitors: []
    }
  }
}

export function VpnManager(): React.JSX.Element {
  const profiles = useWorkspaceVpns()
  const vpnStatuses = useApp((s) => s.vpnStatuses)
  const setVpnStatus = useApp((s) => s.setVpnStatus)
  const removeVpnProfile = useApp((s) => s.removeVpnProfile)

  const [busy, setBusy] = useState<Record<string, boolean>>({})
  const [expanded, setExpanded] = useState<string | null>(null)
  const [importing, setImporting] = useState<VpnKind | null>(null)
  const [editing, setEditing] = useState<VpnProfile | null>(null)
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

  // Starts the user pulled the plug on. A cancelled start still resolves with a
  // failure, and reporting that as one is how cancelling would earn a red toast
  // on top of the one the Cancel button already produced.
  const cancelledStarts = useRef<Set<string>>(new Set())

  // Subscribe to status for every profile in the workspace.
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
        if (s.state === 'error' && s.error) {
          const name = useApp.getState().vpns.find((p) => p.id === id)?.name ?? 'VPN'
          toast(`${name}: ${s.error}`, 'error')
        }
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
    let r = await window.shellpilot?.vpn.start(p.id)
    // docs/VPN.md promises that starting against a locked vault asks to unlock
    // it. The vault reports this as a code on a resolved result rather than as
    // the thrown marker withVaultUnlock watches for, so the check is on the
    // code — and the retry happens once, for the reason that helper only
    // retries once: a second failure is no longer about the vault.
    if (r?.errorCode === 'vault-locked') {
      const unlocked = await useVaultPrompt.getState().request(`Starting ${p.name}`)
      if (unlocked) r = await window.shellpilot?.vpn.start(p.id)
    }
    setBusy((b) => ({ ...b, [p.id]: false }))
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
    toast(r?.error ?? `Could not start ${p.name}`, 'error')
  }, [])

  const stop = useCallback(async (p: VpnProfile, cancelling = false): Promise<void> => {
    setBusy((b) => ({ ...b, [p.id]: true }))
    const r = await window.shellpilot?.vpn.stop(p.id)
    setBusy((b) => ({ ...b, [p.id]: false }))
    if (r?.ok) {
      toast(cancelling ? `${p.name} — connection attempt cancelled` : `${p.name} stopped`)
      return
    }
    // An engine that refuses to die used to produce a red dot, an error toast
    // and "X stopped", all at once, because the old preload signature threw the
    // result away. It reports one now, so this can say what actually happened.
    if (errorSpoken(p.id)) return
    toast(r?.error ?? `Could not ${cancelling ? 'cancel' : 'stop'} ${p.name}`, 'error')
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
      await window.shellpilot?.vpn.stop(p.id)
      removeVpnProfile(p.id)
      toast(`${p.name} deleted`)
    },
    [removeVpnProfile]
  )

  const vpnProfiles = profiles.filter((p) => p.spec.kind !== 'frp')
  const frpProfiles = profiles.filter((p) => p.spec.kind === 'frp')

  const row = (p: VpnProfile): React.JSX.Element => {
    const status = vpnStatuses[p.id]
    const health = vpnHealth(status)
    const running = !!status && isVpnRunning(status.state)
    const ungated = ungatedProxies(p)
    const engine = engines[p.spec.kind]
    const open = expanded === p.id
    const gated = !running && ungated.length > 0
    const engineMissing = engine?.available === false
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
                    ? engine?.reason
                    : undefined
            }
            onClick={() => void (cancellable ? cancel(p) : toggle(p))}
          >
            {busy[p.id] ? <Loader2 size={13} className="spin" /> : <Power size={13} />}
            {cancellable ? 'Cancel' : running ? 'Stop' : 'Start'}
          </button>
          <button className="icon-btn sm" title="Edit profile" onClick={() => setEditing(p)}>
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
          <div className="row" style={{ gap: 6, padding: '6px 16px', color: 'var(--danger)', fontSize: 11 }}>
            <AlertTriangle size={12} />
            <span>{engine?.reason ?? `${KIND_LABEL[p.spec.kind]} is not available on this machine.`}</span>
          </div>
        )}

        {gated && (
          // Naming the proxies is the point. "Acknowledge exposure to continue"
          // just sends the user hunting for the checkbox they missed.
          <div className="row" style={{ gap: 6, padding: '6px 16px', color: 'var(--warn)', fontSize: 11 }}>
            <AlertTriangle size={12} />
            <span>
              Confirm what {ungated.map((x) => x.name).join(', ')}{' '}
              {ungated.length === 1 ? 'exposes' : 'expose'} before starting — open the profile and
              tick the box on {ungated.length === 1 ? 'that proxy' : 'each of those proxies'}.
            </span>
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

  return (
    <div
      className="content"
      // Sized to its content rather than splitting the view down the middle:
      // the SSH tunnel list above keeps the remaining space, and this pane
      // scrolls on its own once it grows past a bit over half the height.
      style={{ flex: '0 1 auto', maxHeight: '58%', borderTop: '1px solid var(--border)' }}
    >
      <div className="content-header">
        <div>
          <h1>VPN</h1>
          <div className="sub">WireGuard and OpenVPN tunnels</div>
        </div>
        <div className="spacer" />
        <button className="btn sm" onClick={() => setImporting('wireguard')}>
          <Plus size={14} /> Import WireGuard
        </button>
        <button className="btn sm" onClick={() => setImporting('openvpn')}>
          <Plus size={14} /> Import OpenVPN
        </button>
      </div>

      {vpnProfiles.length === 0 ? (
        <EmptyState
          icon={<Globe size={26} />}
          title="No VPN profiles"
          message="Import a WireGuard .conf or an OpenVPN .ovpn to carry servers, databases and tunnels over a VPN."
          action={
            <button className="btn primary" onClick={() => setImporting('wireguard')}>
              <Plus size={15} /> Import WireGuard
            </button>
          }
        />
      ) : (
        <div className="col" style={{ gap: 8, paddingBottom: 16 }}>
          {vpnProfiles.map(row)}
        </div>
      )}

      <div className="content-header">
        <div>
          <h1>Reverse proxies (frp)</h1>
          <div className="sub">Publish a local service through an frp server</div>
        </div>
        <div className="spacer" />
        <button className="btn sm" onClick={() => setImporting('frp')}>
          <Plus size={14} /> Import frpc config
        </button>
        <button
          className="btn sm"
          onClick={() => setEditing(blankFrpProfile(useApp.getState().activeId()))}
        >
          <Share2 size={14} /> New frp client
        </button>
      </div>

      {frpProfiles.length === 0 ? (
        <EmptyState
          icon={<Share2 size={26} />}
          title="No reverse proxies"
          message="An frp client makes a service on this machine reachable through a server you control."
          action={
            <button
              className="btn primary"
              onClick={() => setEditing(blankFrpProfile(useApp.getState().activeId()))}
            >
              <Share2 size={15} /> New frp client
            </button>
          }
        />
      ) : (
        <div className="col" style={{ gap: 8 }}>
          {frpProfiles.map(row)}
        </div>
      )}

      {importing && <VpnImportModal kind={importing} onClose={() => setImporting(null)} />}
      {editing && <VpnProfileForm profile={editing} onClose={() => setEditing(null)} />}
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
    </div>
  )
}
