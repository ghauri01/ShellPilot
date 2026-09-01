import { create } from 'zustand'
import { useApp } from './app'

// Stamped into every outbound payload so a shared endpoint can tell which
// version posted. Read once: app.getVersion() is an IPC round trip and this is
// on the alert path.
let APP_VERSION = '0.0.0'
void window.shellpilot?.getVersion?.().then((v) => {
  APP_VERSION = v
})

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
      // Only on an actual transition, so a host sitting comfortably below the
      // threshold does not post "resolved" on every sample. An alert with no
      // resolution leaves the reader to work out whether it is still
      // happening, which is why this is worth sending at all.
      void window.shellpilot?.webhook?.notify({
        source: 'shellpilot',
        version: APP_VERSION,
        event: 'resolved',
        kind: kind === 'cpu' ? 'cpu' : 'memory',
        server: serverName,
        summary: `${serverName}: ${LABEL[kind]} back below ${threshold}%`,
        at: new Date(now).toISOString(),
        value: Math.round(value),
        threshold
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
  // Same repeat window as the desktop notification, so the endpoint sees the
  // same cadence a person does rather than one message per sample.
  void window.shellpilot?.webhook?.notify({
    source: 'shellpilot',
    version: APP_VERSION,
    event: 'raised',
    kind: kind === 'cpu' ? 'cpu' : 'memory',
    server: serverName,
    summary: `${serverName}: ${LABEL[kind]} at ${value.toFixed(0)}% (threshold ${threshold}%)`,
    at: new Date(now).toISOString(),
    value: Math.round(value),
    threshold,
    ...(mins >= 1 ? { minutes: mins } : {})
  })
}

// Failed systemd units, per server.
//
// The reason this feature exists: the reference case was four failed units
// found by opening the app and looking. CPU and memory thresholds never would
// have caught it — a failed unit does not move a graph.
//
// Alerts fire on a TRANSITION into failure, so a unit that has been down for a
// week does not re-announce itself every sweep. Resolution fires when the set
// empties, which is the "it is fixed" message that makes the first one worth
// reading.
const failedUnits = new Map<string, Set<string>>()

export function checkUnitAlerts(serverId: string, serverName: string, units: string[] | null): void {
  // null is "we could not see systemd", not "nothing is failing" — the same
  // distinction HostMetrics is careful about. Treating it as an empty set
  // would post a resolution for a host nobody could ask.
  if (units === null) return
  if (!useApp.getState().settings.resourceAlertsEnabled) return

  const now = Date.now()
  const previous = failedUnits.get(serverId) ?? new Set<string>()
  const current = new Set(units)
  const fresh = units.filter((u) => !previous.has(u))

  if (current.size === 0) failedUnits.delete(serverId)
  else failedUnits.set(serverId, current)

  if (fresh.length > 0) {
    const what = fresh.length === 1 ? fresh[0] : `${fresh.length} units`
    void window.shellpilot?.notify.show(
      `${serverName}: ${what} failed`,
      fresh.join(', ')
    )
    void window.shellpilot?.webhook?.notify({
      source: 'shellpilot',
      version: APP_VERSION,
      event: 'raised',
      kind: 'unit-failed',
      server: serverName,
      summary: `${serverName}: ${what} failed`,
      at: new Date(now).toISOString(),
      units: fresh
    })
    return
  }

  if (previous.size > 0 && current.size === 0) {
    void window.shellpilot?.webhook?.notify({
      source: 'shellpilot',
      version: APP_VERSION,
      event: 'resolved',
      kind: 'unit-failed',
      server: serverName,
      summary: `${serverName}: all previously failed units are running again`,
      at: new Date(now).toISOString(),
      units: [...previous]
    })
  }
}

/** Forgets a server's failure history, so removing and re-adding it does not
 *  suppress the first alert. */
export function clearUnitAlerts(serverId: string): void {
  failedUnits.delete(serverId)
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
