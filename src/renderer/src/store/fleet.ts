import { create } from 'zustand'
import type { HostMetrics } from '../../../shared/ssh'

// Latest reported capacity per server, published by the metrics hook so the
// Fleet Monitor can total the estate without opening connections of its own.
// Every value here came from a sample some other component already paid for.

interface FleetState {
  hosts: Record<string, HostMetrics>
  report: (serverId: string, host: HostMetrics) => void
  forget: (serverId: string) => void
}

export const useFleet = create<FleetState>((set) => ({
  hosts: {},
  report: (serverId, host) => set((s) => ({ hosts: { ...s.hosts, [serverId]: host } })),
  forget: (serverId) =>
    set((s) => {
      const hosts = { ...s.hosts }
      delete hosts[serverId]
      return { hosts }
    })
}))

export interface FleetTotals {
  // Servers that have actually reported, which is what the totals cover.
  reporting: number
  cores: number
  memTotal: number
  memUsed: number
  diskTotal: number
  diskUsed: number
}

// Totals across the given servers. Only servers that have reported contribute,
// so the figures are honest rather than partially guessed.
export function fleetTotals(serverIds: string[], hosts: Record<string, HostMetrics>): FleetTotals {
  const t: FleetTotals = {
    reporting: 0,
    cores: 0,
    memTotal: 0,
    memUsed: 0,
    diskTotal: 0,
    diskUsed: 0
  }
  for (const id of serverIds) {
    const h = hosts[id]
    if (!h) continue
    t.reporting++
    t.cores += h.cores || 0
    t.memTotal += h.memTotal || 0
    t.memUsed += h.memUsed || 0
    t.diskTotal += h.diskTotal || 0
    t.diskUsed += h.diskUsed || 0
  }
  return t
}
