import { Activity, ChevronDown, ChevronUp, Cpu, HardDrive, MemoryStick, Wifi } from 'lucide-react'
import { useApp } from '../../store/app'
import { useServerMetrics } from '../../hooks/useServerMetrics'
import { Sparkline } from '../common/Sparkline'
import { clsx } from '../../lib/format'
import type { Server } from '../../types'

function rate(bytesPerSec: number): string {
  if (bytesPerSec >= 1048576) return `${(bytesPerSec / 1048576).toFixed(1)} MB/s`
  if (bytesPerSec >= 1024) return `${(bytesPerSec / 1024).toFixed(1)} KB/s`
  return `${Math.round(bytesPerSec)} B/s`
}

// Severity colouring so a struggling host is obvious without reading numbers.
function tone(pct: number): string {
  if (pct >= 90) return 'var(--danger)'
  if (pct >= 75) return 'var(--warn)'
  return 'var(--ok)'
}

// Live host metrics docked under the terminal, so they can be watched while
// working instead of switching away to a separate view.
export function MonitorStrip({
  server,
  visible
}: {
  server: Server
  visible: boolean
}): React.JSX.Element {
  const open = useApp((s) => s.settings.showMonitorStrip)
  const setSettings = useApp((s) => s.setSettings)
  // Sampling runs commands over the same SSH connection the shell uses, so it
  // only polls for the tab actually on screen — never hidden tabs or tabs in
  // other workspaces.
  const m = useServerMetrics(server, open && visible && server.status !== 'offline')

  const toggle = (): void => setSettings({ showMonitorStrip: !open })

  if (!open) {
    return (
      <button className="monitor-strip collapsed" onClick={toggle} title="Show host metrics">
        <Activity size={13} />
        <span>Monitor</span>
        <span className="spacer" />
        <ChevronUp size={14} />
      </button>
    )
  }

  const stat = (
    icon: React.ReactNode,
    label: string,
    pct: number,
    history: number[]
  ): React.JSX.Element => (
    <div className="ms-stat">
      <div className="ms-head">
        {icon}
        <span className="ms-label">{label}</span>
        <span className="ms-value" style={{ color: tone(pct) }}>
          {pct.toFixed(0)}%
        </span>
      </div>
      <div className="ms-bar">
        <span style={{ width: `${Math.min(100, pct)}%`, background: tone(pct) }} />
      </div>
      <Sparkline data={history} color={tone(pct)} height={14} />
    </div>
  )

  return (
    <div className="monitor-strip">
      <div className="ms-title">
        <Activity size={13} />
        <span>Monitor</span>
        {m.error ? (
          <span className="ms-err">{m.error}</span>
        ) : (
          <span className="faint" style={{ fontSize: 10 }}>
            {m.loading ? 'sampling…' : 'live · every 2s'}
          </span>
        )}
        <span className="spacer" />
        {m.host && (
          <span className="faint mono" style={{ fontSize: 10 }}>
            {m.host.hostname} · {m.host.cores} vCPU
          </span>
        )}
        <button className="icon-btn xs" onClick={toggle} title="Hide host metrics">
          <ChevronDown size={14} />
        </button>
      </div>

      <div className="ms-grid">
        {stat(<Cpu size={12} className="faint" />, 'CPU', m.cpu, m.cpuHistory)}
        {stat(<MemoryStick size={12} className="faint" />, 'Memory', m.ram, m.ramHistory)}
        {stat(<HardDrive size={12} className="faint" />, 'Disk', m.disk, m.diskHistory)}
        <div className="ms-stat">
          <div className="ms-head">
            <Wifi size={12} className="faint" />
            <span className="ms-label">Network</span>
          </div>
          <div className={clsx('ms-net mono')}>
            <span>↓ {rate(m.rx)}</span>
            <span>↑ {rate(m.tx)}</span>
          </div>
          <Sparkline data={m.rxHistory} color="var(--accent)" height={14} />
        </div>
      </div>
    </div>
  )
}
