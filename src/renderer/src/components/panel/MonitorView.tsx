import { Cpu, MemoryStick, HardDrive, ArrowDown, ArrowUp, Loader2, AlertTriangle } from 'lucide-react'
import { useServerMetrics } from '../../hooks/useServerMetrics'
import { Sparkline } from '../common/Sparkline'
import { rate, bytes, clsx } from '../../lib/format'
import type { Server } from '../../types'

function level(v: number): string {
  return v > 85 ? 'danger' : v > 65 ? 'warn' : 'ok'
}

function uptimeLabel(sec: number): string {
  const d = Math.floor(sec / 86400)
  const h = Math.floor((sec % 86400) / 3600)
  const m = Math.floor((sec % 3600) / 60)
  return `${d}d ${h}h ${m}m`
}

export function MonitorView({
  server,
  visible = true
}: {
  server: Server
  // The pane stays mounted once opened, so polling must follow visibility or
  // it keeps sampling over the shell's SSH connection in the background.
  visible?: boolean
}): React.JSX.Element {
  const m = useServerMetrics(server, visible && server.status !== 'offline')
  const real = server.demo === false

  const info: [string, string][] = m.host
    ? [
        ['Hostname', m.host.hostname],
        ['OS', server.os],
        ['Kernel', m.host.kernel],
        ['Uptime', uptimeLabel(m.host.uptime)],
        ['CPU cores', `${m.host.cores} vCPU`],
        ['Memory', bytes(m.host.memTotal)],
        ['Disk', bytes(m.host.diskTotal)],
        ['Used memory', `${bytes(m.host.memUsed)} (${m.host.memPct.toFixed(0)}%)`],
        ['Used disk', `${bytes(m.host.diskUsed)} (${m.host.diskPct.toFixed(0)}%)`],
        ['Host / IP', server.host]
      ]
    : [
        ['Hostname', server.name.toLowerCase().replace(/\s+/g, '-')],
        ['OS', server.os],
        ['Kernel', '6.5.0-generic'],
        ['Uptime', '—'],
        ['CPU cores', '8 vCPU'],
        ['Memory', '16 GB'],
        ['Disk', '320 GB SSD'],
        ['Public IP', server.host],
        ['Private IP', '—'],
        ['Latency', '—']
      ]

  const Metric = ({
    label,
    icon,
    value,
    history
  }: {
    label: string
    icon: React.ReactNode
    value: number
    history: number[]
  }): React.JSX.Element => (
    <div className="metric-card">
      <div className="m-head">
        <span className="row">
          {icon} {label}
        </span>
      </div>
      <div className="m-value">
        {value.toFixed(0)}
        <small>%</small>
      </div>
      <div className={clsx('bar', level(value))}>
        <span style={{ width: `${value}%` }} />
      </div>
      <Sparkline data={history} max={100} height={40} color={`var(--${level(value)})`} />
    </div>
  )

  if (real && m.loading) {
    return (
      <div className="content">
        <div className="empty" style={{ height: 260 }}>
          <Loader2 size={22} className="spin" />
          <p>Collecting live metrics from {server.host}…</p>
        </div>
      </div>
    )
  }

  if (real && m.error) {
    return (
      <div className="content">
        <div className="empty" style={{ height: 260 }}>
          <div className="empty-icon" style={{ color: 'var(--danger)' }}>
            <AlertTriangle size={22} />
          </div>
          <h3>Metrics unavailable</h3>
          <p className="mono">{m.error}</p>
        </div>
      </div>
    )
  }

  return (
    <div className="content">
      {real && (
        <div className="row" style={{ marginBottom: 12 }}>
          <span className="chip ok">live</span>
          <span className="muted" style={{ fontSize: 12 }}>
            polling every 2s over SSH
          </span>
        </div>
      )}
      <div className="monitor" style={{ marginBottom: 16 }}>
        <Metric label="CPU" icon={<Cpu size={13} />} value={m.cpu} history={m.cpuHistory} />
        <Metric label="Memory" icon={<MemoryStick size={13} />} value={m.ram} history={m.ramHistory} />
        <Metric label="Disk" icon={<HardDrive size={13} />} value={m.disk} history={m.diskHistory} />
        <div className="metric-card">
          <div className="m-head">
            <span>Network</span>
          </div>
          <div className="row" style={{ justifyContent: 'space-between' }}>
            <div className="col" style={{ gap: 2 }}>
              <span className="muted" style={{ fontSize: 11 }}>
                <ArrowDown size={11} /> Download
              </span>
              <b className="mono">{rate(m.rx)}</b>
            </div>
            <div className="col" style={{ gap: 2 }}>
              <span className="muted" style={{ fontSize: 11 }}>
                <ArrowUp size={11} /> Upload
              </span>
              <b className="mono">{rate(m.tx)}</b>
            </div>
          </div>
          <Sparkline data={m.rxHistory} color="var(--info)" height={40} />
        </div>
      </div>

      <div className="card">
        <div className="sidebar-title" style={{ marginBottom: 12 }}>
          System information
        </div>
        <div className="info-grid">
          {info.map(([k, v]) => (
            <div className="info-item" key={k}>
              <span className="k">{k}</span>
              <span className="v selectable">{v}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}
