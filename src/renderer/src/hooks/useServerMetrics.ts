import { useEffect, useRef, useState } from 'react'
import type { Server } from '../types'
import { sshHopsFor } from '../lib/ssh'
import { checkResourceAlerts } from '../store/alerts'
import { useFleet } from '../store/fleet'
import type {HostMetrics, SshAuth} from '../../../shared/ssh'

export interface LiveMetrics {
  cpu: number
  ram: number
  disk: number
  rx: number // bytes/sec
  tx: number
  cpuHistory: number[]
  ramHistory: number[]
  diskHistory: number[]
  rxHistory: number[]
  txHistory: number[]
  host: HostMetrics | null
  error: string | null
  loading: boolean
}

const LEN = 40
const push = (arr: number[], v: number): number[] => [...arr.slice(1), v]
const asAuth = (a: string): SshAuth => (a === 'password' || a === 'agent' ? a : 'key')

function seed(id: string): number {
  let h = 0
  for (let i = 0; i < id.length; i++) h = (h * 31 + id.charCodeAt(i)) % 100
  return h
}

function initial(server: Server): LiveMetrics {
  const real = server.demo === false
  const b = seed(server.id)
  const cpu = real ? 0 : 20 + (b % 40)
  const ram = real ? 0 : 45 + (b % 30)
  const disk = real ? 0 : 60 + (b % 25)
  return {
    cpu,
    ram,
    disk,
    rx: 0,
    tx: 0,
    cpuHistory: Array(LEN).fill(cpu),
    ramHistory: Array(LEN).fill(ram),
    diskHistory: Array(LEN).fill(disk),
    rxHistory: Array(LEN).fill(0),
    txHistory: Array(LEN).fill(0),
    host: null,
    error: null,
    loading: real
  }
}

function walk(prev: number, min: number, max: number, step: number): number {
  return Math.max(min, Math.min(max, prev + (Math.random() - 0.5) * step))
}

// Live metrics for a server. Real servers are polled over SSH every 2s;
// demo servers use a smooth random walk so the UI still animates.
export function useServerMetrics(server: Server, active: boolean): LiveMetrics {
  const real = server.demo === false
  const ref = useRef<LiveMetrics>(initial(server))
  const net = useRef<{ rx: number; tx: number; t: number } | null>(null)
  const [, tick] = useState(0)

  useEffect(() => {
    if (!active) return
    let alive = true

    if (real) {
      const cfg = {
        sessionId: `metrics-${server.id}`,
        serverId: server.id,
        host: server.host,
        port: server.port,
        username: server.username,
        auth: asAuth(server.auth),
        cols: 80,
        rows: 24,
        hops: sshHopsFor(server)
      }
      const poll = async (): Promise<void> => {
        const res = await window.shellpilot?.metrics.sample(server.id, cfg)
        if (!alive) return
        const s = ref.current
        if (res?.ok && res.data) {
          const d = res.data
          let rx = 0
          let tx = 0
          const now = Date.now()
          if (net.current) {
            const dt = (now - net.current.t) / 1000
            if (dt > 0) {
              rx = Math.max(0, (d.netRx - net.current.rx) / dt)
              tx = Math.max(0, (d.netTx - net.current.tx) / dt)
            }
          }
          net.current = { rx: d.netRx, tx: d.netTx, t: now }
          ref.current = {
            cpu: d.cpu,
            ram: d.memPct,
            disk: d.diskPct,
            rx,
            tx,
            cpuHistory: push(s.cpuHistory, d.cpu),
            ramHistory: push(s.ramHistory, d.memPct),
            diskHistory: push(s.diskHistory, d.diskPct),
            rxHistory: push(s.rxHistory, rx),
            txHistory: push(s.txHistory, tx),
            host: d,
            error: null,
            loading: false
          }
          // Evaluated from samples that are already being collected, so
          // alerting never adds SSH load of its own.
          // A disk of null rather than 0 when df reported nothing: see
          // checkResourceAlerts. 0 would read as an empty disk and clear a
          // real alert.
          checkResourceAlerts(server.id, server.name, {
            cpu: d.cpu,
            ram: d.memPct,
            disk: d.diskTotal > 0 ? d.diskPct : null,
            // Both already null when the host could not answer; passing them
            // through unchanged is the point. `?? null` covers a sample taken
            // by an older build of main, where the fields do not exist at all —
            // which is "not measured", not "fine".
            inode: d.inodePct ?? null,
            load: d.load1 === null || d.load1 === undefined ? null : d.load1 / Math.max(1, d.cores)
          })
          // Publish capacity so the Fleet Monitor can total the estate without
          // sampling anything itself.
          useFleet.getState().report(server.id, d)
        } else {
          ref.current = { ...s, error: res?.error ?? 'unavailable', loading: false }
        }
        tick((n) => n + 1)
      }
      // Chained rather than on a fixed interval: when a link is slow, an
      // interval queues polls faster than they finish, and each queued poll is
      // another exec channel on the same connection the terminal types over.
      // Waiting for one to land before scheduling the next keeps at most one
      // outstanding.
      let timer: ReturnType<typeof setTimeout> | null = null
      const loop = async (): Promise<void> => {
        await poll()
        if (!alive) return
        timer = setTimeout(() => void loop(), 2000)
      }
      void loop()
      return () => {
        alive = false
        if (timer) clearTimeout(timer)
      }
    }

    // Demo random walk.
    const iv = setInterval(() => {
      const s = ref.current
      const cpu = walk(s.cpu, 3, 96, 14)
      const ram = walk(s.ram, 30, 92, 5)
      const disk = walk(s.disk, s.disk - 0.1, 95, 0.3)
      const rx = walk(s.rx || 2_000_000, 200_000, 9_000_000, 2_000_000)
      const tx = walk(s.tx || 600_000, 80_000, 3_000_000, 800_000)
      ref.current = {
        ...s,
        cpu,
        ram,
        disk,
        rx,
        tx,
        cpuHistory: push(s.cpuHistory, cpu),
        ramHistory: push(s.ramHistory, ram),
        diskHistory: push(s.diskHistory, disk),
        rxHistory: push(s.rxHistory, rx),
        txHistory: push(s.txHistory, tx)
      }
      tick((n) => n + 1)
    }, 1000)
    return () => {
      alive = false
      clearInterval(iv)
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [active, real, server.id])

  return ref.current
}
