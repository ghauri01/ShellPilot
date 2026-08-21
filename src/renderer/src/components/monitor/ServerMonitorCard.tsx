import { Cpu, MemoryStick, HardDrive, ArrowDown, ArrowUp } from 'lucide-react'
import { useServerMetrics } from '../../hooks/useServerMetrics'
import { Sparkline } from '../common/Sparkline'
import { bytes, rate, clsx } from '../../lib/format'
import type { Server } from '../../types'

function level(v: number): string {
  return v > 85 ? 'danger' : v > 65 ? 'warn' : 'ok'
}

export function ServerMonitorCard({
  server,
  onOpen
}: {
  server: Server
  onOpen: () => void
}): React.JSX.Element {
  const m = useServerMetrics(server, server.status !== 'offline')
  const off = server.status === 'offline'

  return (
    <div className="metric-card" style={{ cursor: 'pointer' }} onClick={onOpen}>
      <div className="m-head">
        <div className="row">
          <span className={clsx('status-dot', server.status)} />
          <b style={{ color: 'var(--text)' }}>{server.name}</b>
        </div>
        <span className="mono faint" style={{ fontSize: 11 }}>
          {server.host}
        </span>
      </div>

      {off ? (
        <div className="faint" style={{ padding: '18px 0', textAlign: 'center' }}>
          Offline
        </div>
      ) : (
        <>
          <div className="row" style={{ gap: 16 }}>
            <div className="grow col" style={{ gap: 4 }}>
              <div className="row muted" style={{ fontSize: 11, justifyContent: 'space-between' }}>
                <span>
                  <Cpu size={11} /> CPU
                </span>
                <b style={{ color: 'var(--text)' }}>
                  {m.cpu.toFixed(0)}%
                  {m.host ? <span className="faint"> · {m.host.cores} vCPU</span> : null}
                </b>
              </div>
              <div className={clsx('bar', level(m.cpu))}>
                <span style={{ width: `${m.cpu}%` }} />
              </div>
            </div>
            <div className="grow col" style={{ gap: 4 }}>
              <div className="row muted" style={{ fontSize: 11, justifyContent: 'space-between' }}>
                <span>
                  <MemoryStick size={11} /> RAM
                </span>
                <b style={{ color: 'var(--text)' }}>
                  {m.host ? `${bytes(m.host.memUsed)} / ${bytes(m.host.memTotal)}` : `${m.ram.toFixed(0)}%`}
                </b>
              </div>
              <div className={clsx('bar', level(m.ram))}>
                <span style={{ width: `${m.ram}%` }} />
              </div>
            </div>
          </div>

          <Sparkline data={m.cpuHistory} max={100} height={36} />

          {m.host && (
            <div className="row muted" style={{ fontSize: 11, justifyContent: 'space-between' }}>
              <span>
                <HardDrive size={11} /> Disk
              </span>
              <b style={{ color: 'var(--text)' }}>
                {bytes(m.host.diskUsed)} / {bytes(m.host.diskTotal)}
                <span className="faint"> ({m.disk.toFixed(0)}%)</span>
              </b>
            </div>
          )}

          <div className="row muted" style={{ fontSize: 11, justifyContent: 'space-between' }}>
            <span>
              <ArrowDown size={11} /> {rate(m.rx)}
            </span>
            <span>
              <ArrowUp size={11} /> {rate(m.tx)}
            </span>
          </div>
        </>
      )}
    </div>
  )
}
