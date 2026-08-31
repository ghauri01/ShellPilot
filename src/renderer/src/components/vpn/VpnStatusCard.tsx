import { AlertTriangle } from 'lucide-react'
import { WG_HANDSHAKE_STALE_SEC } from '../../../../shared/vpn'
import type {
  FrpProxyStatus,
  FrpSpec,
  VpnBoundListener,
  VpnKind,
  VpnProfile,
  VpnStatus
} from '../../types'
import { bytes, clsx } from '../../lib/format'

// How healthy a profile is, as the UI cares about it. Deliberately coarser than
// VpnState in one place and finer in another: `reconnecting` and `degraded`
// both mean "up, not carrying traffic", and `connected` splits in two because a
// WireGuard peer can be connected with a handshake that stopped happening.
export type VpnHealth = 'off' | 'connecting' | 'ok' | 'degraded' | 'error'

// E63: the sidecar reports an age, but a system clock jump (sleep/wake, an NTP
// step) can still produce a negative one. An age is never negative, and
// "handshake -4s ago" reads as a bug in the client rather than a clock event.
function clampAge(sec: number): number {
  return Math.max(0, Math.round(sec))
}

/** True while the handshake is fresh enough that traffic is actually moving. */
export function isHandshakeFresh(lastHandshakeSec: number | undefined): boolean {
  if (lastHandshakeSec === undefined) return false
  return clampAge(lastHandshakeSec) < WG_HANDSHAKE_STALE_SEC
}

/** "handshake 12s ago" — relative, never a wall-clock timestamp. A timestamp
 *  makes the reader do the subtraction, and the subtraction is the whole
 *  question being asked. */
export function handshakeLabel(lastHandshakeSec: number | undefined): string {
  if (lastHandshakeSec === undefined) return 'no handshake yet'
  const age = clampAge(lastHandshakeSec)
  if (age < 60) return `handshake ${age}s ago`
  if (age < 3600) return `handshake ${Math.floor(age / 60)}m ${age % 60}s ago`
  return `handshake ${Math.floor(age / 3600)}h ${Math.floor((age % 3600) / 60)}m ago`
}

/** "1 proxy", "3 proxies". Lives here because the pane and the sidebar both
 *  say it, and the sidebar used to say "1 proxies". */
export function proxyCount(n: number): string {
  return `${n} ${n === 1 ? 'proxy' : 'proxies'}`
}

/** The one-line description of an frp client: where it dials and how much it
 *  carries. A profile with no server address yet says so — ":7000 · 0 proxies"
 *  reads as a field the app failed to load rather than one nobody has filled
 *  in. */
export function frpSummary(spec: FrpSpec): string {
  const server = spec.serverAddr ? `${spec.serverAddr}:${spec.serverPort}` : 'no server yet'
  return `${server} · ${proxyCount(spec.proxies.length)}`
}

/** Why a profile is amber, in a sentence. Every degraded state had one except
 *  the two frp ones, which showed a chip and left the user to guess. */
export function degradedReason(kind: VpnKind, status: VpnStatus | undefined): string {
  if (status?.state === 'reconnecting') return 'Lost the connection to the server; retrying.'
  if (status?.state === 'degraded') {
    if (kind === 'frp') {
      return 'Connected to the server, but at least one proxy failed to start — see the table below.'
    }
    return 'The connection is up but is not carrying traffic.'
  }
  // Connected, with a WireGuard handshake old enough that nothing is crossing.
  return `The tunnel is up but nothing is crossing it — the last handshake is older than ${WG_HANDSHAKE_STALE_SEC}s. Check that UDP to the peer endpoint is not being blocked.`
}

export function vpnHealth(status: VpnStatus | undefined): VpnHealth {
  if (!status || status.state === 'stopped') return 'off'
  if (status.state === 'error') return 'error'
  if (status.state === 'degraded' || status.state === 'reconnecting') return 'degraded'
  if (status.state === 'starting' || status.state === 'authenticating') return 'connecting'
  // Connected, which for WireGuard is not the same as working: the interface is
  // up and the peer is configured, but if the handshake has gone stale nothing
  // is crossing it. Amber, not red — down and up-but-silent call for different
  // reactions, and almost no WireGuard UI tells them apart.
  if (status.kind === 'wireguard' && !isHandshakeFresh(status.stats?.lastHandshakeSec)) {
    return 'degraded'
  }
  return 'ok'
}

const HEALTH_LABEL: Record<VpnHealth, string> = {
  off: 'Stopped',
  connecting: 'Connecting',
  ok: 'Connected',
  degraded: 'Degraded',
  error: 'Error'
}

const HEALTH_CHIP: Record<VpnHealth, string> = {
  off: '',
  connecting: 'info',
  ok: 'ok',
  degraded: 'warn',
  error: 'danger'
}

// `.status-dot` ships online/idle/offline/connecting; amber is `idle`, which is
// exactly the shade `degraded` wants. There is no red variant, so error paints
// itself from the same tokens the danger chip uses.
const HEALTH_DOT: Record<VpnHealth, string> = {
  off: 'offline',
  connecting: 'connecting',
  ok: 'online',
  degraded: 'idle',
  error: 'offline'
}

export function HealthDot({ health }: { health: VpnHealth }): React.JSX.Element {
  return (
    <span
      className={clsx('status-dot', HEALTH_DOT[health])}
      style={
        health === 'error'
          ? { background: 'var(--danger)', boxShadow: '0 0 0 3px var(--danger-soft)' }
          : undefined
      }
    />
  )
}

export function HealthChip({ health }: { health: VpnHealth }): React.JSX.Element {
  return <span className={clsx('chip', HEALTH_CHIP[health])}>{HEALTH_LABEL[health]}</span>
}

/** E25. A listener on anything but the loopback is reachable by every other
 *  machine on the network, which is a different product than the one the user
 *  thinks they configured. */
export function isLoopbackBind(host: string): boolean {
  const h = host.trim().toLowerCase()
  return h === '' || h === '127.0.0.1' || h === '::1' || h === '[::1]' || h === 'localhost'
}

export function BindWarning({ host, what }: { host: string; what: string }): React.JSX.Element | null {
  if (isLoopbackBind(host)) return null
  return (
    <div className="row" style={{ gap: 6, color: 'var(--warn)', fontSize: 11 }}>
      <AlertTriangle size={12} />
      <span>
        Bound to {host} — {what} is reachable from every machine on your network, not just this
        one. Use 127.0.0.1 unless you meant to share it.
      </span>
    </div>
  )
}

function listenerLabel(l: VpnBoundListener): string {
  if (l.kind === 'forward' && l.targetHost) {
    return `${l.bindHost}:${l.bindPort} → ${l.targetHost}:${l.targetPort}`
  }
  return `${l.bindHost}:${l.bindPort}`
}

function Item({ k, v }: { k: string; v: string }): React.JSX.Element {
  return (
    <div className="info-item">
      <span className="k">{k}</span>
      <span className="v">{v}</span>
    </div>
  )
}

interface VpnStatusCardProps {
  profile: VpnProfile
  status: VpnStatus | undefined
}

export function VpnStatusCard({ profile, status }: VpnStatusCardProps): React.JSX.Element {
  const health = vpnHealth(status)
  const stats = status?.stats
  const listeners = status?.listeners ?? []
  const proxies: FrpProxyStatus[] = stats?.proxies ?? []

  return (
    <div className="card" style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
      {status?.error && (
        // The code is for a bug report, not for reading: it was the only
        // machine token on an otherwise written-out card. It stays reachable on
        // hover, and the log drawer has it in full.
        <div
          className="conn-error"
          style={{ borderRadius: 'var(--r-sm)', border: 'none' }}
          title={status.errorCode ? `Error code: ${status.errorCode}` : undefined}
        >
          <AlertTriangle size={13} />
          <span>{status.error}</span>
        </div>
      )}

      <div className="info-grid">
        <Item k="State" v={HEALTH_LABEL[health]} />
        {profile.spec.kind === 'wireguard' && (
          <Item k="Handshake" v={handshakeLabel(stats?.lastHandshakeSec)} />
        )}
        {stats && <Item k="Received" v={bytes(stats.rxBytes)} />}
        {stats && <Item k="Sent" v={bytes(stats.txBytes)} />}
        {stats?.assignedIp && <Item k="Assigned IP" v={stats.assignedIp} />}
        {stats?.remoteEndpoint && <Item k="Endpoint" v={stats.remoteEndpoint} />}
        {stats?.latencyMs !== undefined && (
          <Item k="Latency" v={`${Math.round(stats.latencyMs)} ms`} />
        )}
        {status && status.restarts > 0 && <Item k="Restarts" v={String(status.restarts)} />}
      </div>

      {health === 'degraded' && (
        // Every kind, not just WireGuard: an frp client whose proxies failed
        // used to get the amber chip and no sentence at all.
        <div className="row" style={{ gap: 6, color: 'var(--warn)', fontSize: 12 }}>
          <AlertTriangle size={13} />
          <span>{degradedReason(profile.spec.kind, status)}</span>
        </div>
      )}

      {listeners.length > 0 && (
        <div className="col" style={{ gap: 6 }}>
          <span className="field-label">Local listeners</span>
          {listeners.map((l, i) => (
            <div key={`${l.bindHost}:${l.bindPort}-${i}`} className="col" style={{ gap: 4 }}>
              <div className="row" style={{ gap: 8 }}>
                <span className="chip">{l.kind}</span>
                <span className="mono" style={{ fontSize: 12 }}>
                  {listenerLabel(l)}
                </span>
              </div>
              <BindWarning host={l.bindHost} what="this listener" />
            </div>
          ))}
        </div>
      )}

      {profile.spec.kind === 'frp' && (
        <div className="col" style={{ gap: 6 }}>
          <span className="field-label">Proxies</span>
          {proxies.length === 0 ? (
            // frp publishes no client-side byte counters, so this table is the
            // telemetry. Saying so beats showing invented rx/tx numbers.
            <span className="faint" style={{ fontSize: 11 }}>
              No proxy status yet. frp reports per-proxy state rather than traffic counters.
            </span>
          ) : (
            <table className="mini-table">
              <thead>
                <tr>
                  <th>Proxy</th>
                  <th>Type</th>
                  <th>Status</th>
                  <th>Local</th>
                  <th>Remote</th>
                </tr>
              </thead>
              <tbody>
                {proxies.map((p) => (
                  <tr key={p.name}>
                    <td className="strong">{p.name}</td>
                    <td>{p.type}</td>
                    <td style={p.err ? { color: 'var(--danger)' } : undefined}>
                      {p.err ? `${p.status} — ${p.err}` : p.status}
                    </td>
                    <td className="mono">{p.localAddr ?? '—'}</td>
                    <td className="mono">{p.remoteAddr ?? '—'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      )}
    </div>
  )
}
