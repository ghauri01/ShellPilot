import { create } from 'zustand'
import type { HostMetrics } from '../../../shared/ssh'
import { onServerForgotten } from './serverCleanup'

// Latest reported capacity per server. Published by the foreground metrics hook
// and by the background fleet sampler, so the Fleet Monitor can total the
// estate without opening connections of its own.

// A server that could not be reached. Kept beside the successes rather than
// dropped, because "this host is unhealthy" and "we could not ask this host"
// are different answers and only one of them means the host is fine. The
// sampler carries the error all the way to the renderer; discarding it there
// was the whole point of the distinction being lost.
export interface FleetError {
  error: string
  at: number
}

// A sample and when it was taken. The timestamp is not decoration: fleet-wide
// search answers "where is postgres" from the last sweep, and an answer with no
// age on it is indistinguishable from a live one. A host that went unreachable
// nine minutes ago still has rows here, and they are only safe to show because
// the age travels with them.
export interface FleetSample {
  host: HostMetrics
  at: number
}

interface FleetState {
  hosts: Record<string, HostMetrics>
  samples: Record<string, FleetSample>
  errors: Record<string, FleetError>
  report: (serverId: string, host: HostMetrics, at?: number) => void
  reportError: (serverId: string, error: string, at: number) => void
  forget: (serverId: string) => void
}

export const useFleet = create<FleetState>((set) => ({
  hosts: {},
  samples: {},
  errors: {},
  // A success clears any recorded failure: the host answered.
  report: (serverId, host, at = Date.now()) =>
    set((s) => {
      const errors = { ...s.errors }
      delete errors[serverId]
      return {
        hosts: { ...s.hosts, [serverId]: host },
        samples: { ...s.samples, [serverId]: { host, at } },
        errors
      }
    }),
  // The last good sample is deliberately KEPT alongside the error. A host that
  // was fine ten minutes ago and is now unreachable is worth showing as both,
  // and dropping the metrics would make the monitor forget what it knew.
  reportError: (serverId, error, at) =>
    set((s) => ({ errors: { ...s.errors, [serverId]: { error, at } } })),
  forget: (serverId) =>
    set((s) => {
      const hosts = { ...s.hosts }
      const samples = { ...s.samples }
      const errors = { ...s.errors }
      delete hosts[serverId]
      delete samples[serverId]
      delete errors[serverId]
      return { hosts, samples, errors }
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

onServerForgotten((serverId) => useFleet.getState().forget(serverId))
