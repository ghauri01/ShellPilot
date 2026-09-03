import { create } from 'zustand'
import type { HostFacts } from '../../../shared/hostFacts'
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

/**
 * What a host IS, on its own clock — roadmap item C.
 *
 * Kept beside the metrics samples rather than inside them because the two have
 * different cadences and either can be absent while the other is present.
 * Facts are collected hourly; a host sampled forty times in the last hour has
 * one facts entry, and a host added ten minutes ago has none at all.
 *
 * `facts` and `error` are BOTH optional and both may be set at once, for the
 * same reason `samples` and `errors` coexist above: a probe that fails does not
 * unlearn what the last successful one found, and the last good facts with a
 * failure beside them is a more useful thing to show than either alone.
 *
 * An absent entry means "never collected", and nothing else. It is not zero
 * updates, not an unsupported distribution and not a failure — it is the
 * collection not having happened yet, which on an hourly cadence is a normal
 * state for a server somebody added five minutes ago.
 */
export interface FleetFacts {
  facts?: HostFacts
  /** When the collection that produced `facts` ran. */
  at?: number
  error?: string
  errorAt?: number
}

interface FleetState {
  hosts: Record<string, HostMetrics>
  samples: Record<string, FleetSample>
  errors: Record<string, FleetError>
  /** Keyed by server id. Absent means never collected — see FleetFacts. */
  facts: Record<string, FleetFacts>
  report: (serverId: string, host: HostMetrics, at?: number) => void
  reportError: (serverId: string, error: string, at: number) => void
  reportFacts: (serverId: string, facts: HostFacts, at: number) => void
  reportFactsError: (serverId: string, error: string, at: number) => void
  forget: (serverId: string) => void
}

export const useFleet = create<FleetState>((set) => ({
  hosts: {},
  samples: {},
  errors: {},
  facts: {},
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
  // A successful collection clears the recorded failure and replaces the facts.
  // Unlike a metrics sample it does NOT arrive on every sweep, so nothing here
  // may clear facts it was not given: an event with no facts on it means "not
  // collected on this sweep", never "this host has no facts".
  reportFacts: (serverId, facts, at) =>
    set((s) => ({ facts: { ...s.facts, [serverId]: { facts, at } } })),
  // The last good facts are KEPT beside the error, the same way the last good
  // sample is. A host that stopped answering the facts probe an hour ago is
  // still, as far as anyone knows, the distribution it was then — and saying so
  // with an age on it beats forgetting.
  reportFactsError: (serverId, error, at) =>
    set((s) => ({ facts: { ...s.facts, [serverId]: { ...s.facts[serverId], error, errorAt: at } } })),
  forget: (serverId) =>
    set((s) => {
      const hosts = { ...s.hosts }
      const samples = { ...s.samples }
      const errors = { ...s.errors }
      const facts = { ...s.facts }
      delete hosts[serverId]
      delete samples[serverId]
      delete errors[serverId]
      delete facts[serverId]
      return { hosts, samples, errors, facts }
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
