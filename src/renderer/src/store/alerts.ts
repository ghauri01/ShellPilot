import { create } from 'zustand'
import { useApp } from './app'

// Resource alerts.
//
// Deliberately unobtrusive: a native OS notification (which renders outside the
// window and so can never cover the terminal) plus a status-bar chip, which
// sits in the layout flow rather than floating over anything. Nothing steals
// focus and nothing has to be dismissed before work continues.
//
// Sampling is not driven from here — alerts are evaluated from metrics that are
// already being collected, so enabling them never adds SSH load.

export type AlertKind = 'cpu' | 'ram'

export interface ActiveAlert {
  serverId: string
  serverName: string
  kind: AlertKind
  value: number
  since: number
}

interface AlertState {
  active: Record<string, ActiveAlert>
  list: () => ActiveAlert[]
  clearServer: (serverId: string) => void
}

const key = (serverId: string, kind: AlertKind): string => `${serverId}:${kind}`

export const useAlerts = create<AlertState>((set, get) => ({
  active: {},
  list: () => Object.values(get().active),
  clearServer: (serverId) =>
    set((s) => ({
      active: Object.fromEntries(Object.entries(s.active).filter(([, a]) => a.serverId !== serverId))
    }))
}))

// Repeat interval while a host stays over the threshold.
const REPEAT_MS = 60_000

// Last notification time per server+metric, so a sustained problem repeats once
// a minute instead of on every 2s sample.
const lastNotified = new Map<string, number>()

const LABEL: Record<AlertKind, string> = { cpu: 'CPU', ram: 'Memory' }

function evaluate(
  serverId: string,
  serverName: string,
  kind: AlertKind,
  value: number,
  threshold: number,
  now: number
): void {
  const k = key(serverId, kind)

  if (value < threshold) {
    // Recovered: drop the alert and allow an immediate notification if it
    // crosses again later.
    if (useAlerts.getState().active[k]) {
      useAlerts.setState((s) => {
        const active = { ...s.active }
        delete active[k]
        return { active }
      })
    }
    lastNotified.delete(k)
    return
  }

  const existing = useAlerts.getState().active[k]
  useAlerts.setState((s) => ({
    active: {
      ...s.active,
      [k]: { serverId, serverName, kind, value, since: existing?.since ?? now }
    }
  }))

  const last = lastNotified.get(k) ?? 0
  if (now - last < REPEAT_MS) return
  lastNotified.set(k, now)

  const mins = existing ? Math.round((now - existing.since) / 60000) : 0
  const forHow = mins >= 1 ? ` for ${mins} min` : ''
  void window.shellpilot?.notify.show(
    `${serverName}: ${LABEL[kind]} at ${value.toFixed(0)}%`,
    `${LABEL[kind]} has been at or above ${threshold}%${forHow}.`
  )
}

// Called from the metrics hook on each sample.
export function checkResourceAlerts(
  serverId: string,
  serverName: string,
  cpu: number,
  ram: number
): void {
  const { resourceAlertsEnabled, resourceAlertThreshold } = useApp.getState().settings
  if (!resourceAlertsEnabled) return
  const now = Date.now()
  evaluate(serverId, serverName, 'cpu', cpu, resourceAlertThreshold, now)
  evaluate(serverId, serverName, 'ram', ram, resourceAlertThreshold, now)
}
