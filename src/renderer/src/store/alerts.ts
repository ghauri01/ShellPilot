import { create } from 'zustand'
import { useApp } from './app'
import { onServerForgotten } from './serverCleanup'
import { DISK_DANGER, isDiskCritical } from '../components/monitor/hostHealth'
import type { AlertKind as WebhookAlertKind } from '../../../shared/webhook'

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

export type AlertKind = 'cpu' | 'ram' | 'disk'

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

// Repeat interval while a host stays over the line, per kind.
//
// Not one number, because the three conditions do not behave alike. CPU and
// memory spike and recover, so a minute is a live readout of something that is
// still moving. A disk does not empty itself: the same minute would be 60
// notifications an hour and about 10,000 a week for one host that nobody can
// fix before Monday, and the only thing that survives that is the mute button.
// Six hours is roughly "twice a working day" — often enough that a filling disk
// is not forgotten, rare enough to still be read. Escalation (see evaluate)
// covers the case where six hours is too long to wait.
const REPEAT: Record<AlertKind, number> = {
  cpu: 60_000,
  ram: 60_000,
  disk: 6 * 60 * 60 * 1000
}

// How far below the threshold a value must fall to count as recovered. Without
// it, a host sitting at the line flaps between raised and resolved on every
// sample. See evaluate().
const RECOVER_MARGIN = 5

// A rise of this many points since the last thing we said re-opens the repeat
// window. See evaluate() for why a six-hour window needs it.
const ESCALATE_BY = 5

/** Below this, a value counts as recovered rather than merely lower. */
const clearLine = (threshold: number): number => Math.max(0, threshold - RECOVER_MARGIN)

// Last notification time per server+metric, so a sustained problem repeats on
// its kind's window instead of on every 2s sample.
const lastNotified = new Map<string, number>()

// The value we last said out loud, per server+metric. Deleted on a real
// resolve, which is what lets a genuine re-raise speak immediately instead of
// waiting out a window it did not earn. See evaluate().
const lastNotifiedValue = new Map<string, number>()

/** Short, for the status-bar chip and the notification title. */
export const LABEL: Record<AlertKind, string> = { cpu: 'CPU', ram: 'Memory', disk: 'Disk' }

// What the number is measuring, for the sentences a person reads. Disk says
// "root filesystem" and means it: metrics.ts probes `df -kP /` and nothing
// else, so a host with a full /var and a roomy / raises nothing here, and an
// alert that said "disk" would be claiming to have looked at more than it did.
const SUBJECT: Record<AlertKind, string> = {
  cpu: 'CPU',
  ram: 'Memory',
  disk: 'Root filesystem'
}

// The wire name for each kind. A Record rather than a ternary, so adding a kind
// is a type error here instead of a metric quietly posting as 'memory'.
const WEBHOOK_KIND: Record<AlertKind, WebhookAlertKind> = {
  cpu: 'cpu',
  ram: 'memory',
  disk: 'disk'
}

function evaluate(
  serverId: string,
  serverName: string,
  kind: AlertKind,
  value: number,
  threshold: number,
  now: number,
  /**
   * Whether this sample is over the line for this kind. Passed in rather than
   * compared here, because the comparison is not the same for every kind and
   * having two of them written down in two files is what put the disk alert
   * and the Fleet Monitor's attention list a hair's breadth out of agreement.
   * Disk passes hostHealth's isDiskCritical; CPU and memory pass the
   * comparison this function has always used.
   */
  over: boolean
): void {
  const k = key(serverId, kind)

  // Hysteresis. Clearing at exactly the threshold means a host hovering around
  // it crosses repeatedly, and each crossing used to reset the repeat window —
  // so at the foreground 2s cadence that is a desktop notification every few
  // seconds and roughly thirty webhooks a minute, which is exactly the delivery
  // rate limit. The alerting path then starts dropping real alerts to keep up
  // with its own noise. A value has to fall meaningfully below the line before
  // it counts as recovered.
  const clearAt = clearLine(threshold)

  if (!over && value < clearAt) {
    // Recovered: drop the alert and allow an immediate notification if it
    // crosses again later.
    if (useAlerts.getState().active[k]) {
      useAlerts.setState((s) => {
        const active = { ...s.active }
        delete active[k]
        return { active }
      })
      // Whether we ever said this host had a problem. A "resolved" for an alert
      // nobody was told about is a message about nothing — and with a six-hour
      // disk window a host oscillating around the line would send a stream of
      // all-clears against a single raise.
      const announced = lastNotifiedValue.has(k)
      // Only the escalation memory is cleared, and only here — on a real
      // resolve rather than on every below-threshold sample. That is what makes
      // a later re-raise a new event rather than a continuation.
      lastNotifiedValue.delete(k)
      if (announced) {
        // Only on an actual transition, so a host sitting comfortably below the
        // threshold does not post "resolved" on every sample. An alert with no
        // resolution leaves the reader to work out whether it is still
        // happening, which is why this is worth sending at all.
        void window.shellpilot?.webhook?.notify({
          source: 'shellpilot',
          version: APP_VERSION,
          event: 'resolved',
          kind: WEBHOOK_KIND[kind],
          server: serverName,
          summary: `${serverName}: ${SUBJECT[kind]} back below ${threshold}%`,
          at: new Date(now).toISOString(),
          value: Math.round(value),
          threshold
        })
      }
    }
    // `lastNotified` is NOT cleared. Deleting it here let the next crossing
    // notify immediately, which is the other half of the flapping problem:
    // hysteresis stops the oscillation, and keeping the window stops a genuine
    // re-cross seconds later from arriving as if nothing had been said. It
    // expires on its own.
    return
  }

  // Between the line and the clear line, on the way down: keep the chip, say
  // nothing new. Raising here would mean a disk at exactly DISK_DANGER alerting
  // while the Fleet Monitor lists it as fine.
  if (!over) return

  const existing = useAlerts.getState().active[k]
  useAlerts.setState((s) => ({
    active: {
      ...s.active,
      [k]: { serverId, serverName, kind, value, since: existing?.since ?? now }
    }
  }))

  // Three ways a sample earns a notification, and all three are needed once a
  // window can be six hours long:
  //
  //  - Nothing outstanding. Either the first crossing ever, or the first since
  //    a real recovery. `clearAt` is what makes the second safe to trust: a
  //    resolve only registers below `threshold - RECOVER_MARGIN`, so a value
  //    back over the line after one is a round trip through recovery, not flap.
  //  - It got materially worse. A disk at 96% is not the 86% we last mentioned,
  //    and waiting out the rest of a six-hour window to say so is how a full
  //    disk becomes an outage. Comparing against the last value we SENT, not
  //    the previous sample, is what keeps 86 → 88 → 90 from escalating on
  //    every one.
  //  - The window has expired, which is the ordinary "still going" repeat.
  const last = lastNotified.get(k) ?? 0
  const said = lastNotifiedValue.get(k)
  const reRaised = said === undefined
  const worsened = said !== undefined && value >= said + ESCALATE_BY
  const due = now - last >= REPEAT[kind]
  if (!reRaised && !worsened && !due) return
  lastNotified.set(k, now)
  lastNotifiedValue.set(k, value)

  const mins = existing ? Math.round((now - existing.since) / 60000) : 0
  const forHow = mins >= 1 ? ` for ${mins} min` : ''
  void window.shellpilot?.notify.show(
    `${serverName}: ${LABEL[kind]} at ${value.toFixed(0)}%`,
    `${SUBJECT[kind]} has been at or above ${threshold}%${forHow}.`
  )
  // Same repeat window as the desktop notification, so the endpoint sees the
  // same cadence a person does rather than one message per sample.
  void window.shellpilot?.webhook?.notify({
    source: 'shellpilot',
    version: APP_VERSION,
    event: 'raised',
    kind: WEBHOOK_KIND[kind],
    server: serverName,
    summary: `${serverName}: ${SUBJECT[kind]} at ${value.toFixed(0)}% (threshold ${threshold}%)`,
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
  // Scrub at the source, not just in the outbound payload.
  //
  // The main-process sanitiser strips `units`, but `summary` and the desktop
  // notification title are BUILT from a unit name — and Slack renders
  // `summary`. So a unit named `<!channel>` on a compromised host still pinged
  // an entire workspace, on a loop, through the one field nobody had filtered.
  // One scrubbed value feeding all three is the only version of this that
  // cannot drift apart again.
  const clean = (u: string): string => u.slice(0, 128).replace(/[^A-Za-z0-9._@:\-\\]/g, '')
  const previous = failedUnits.get(serverId) ?? new Set<string>()
  const current = new Set(units.map(clean).filter(Boolean))
  const fresh = [...current].filter((u) => !previous.has(u))

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

// Registered rather than called from deleteServer, to keep app.ts from having
// to import this module back and make init order matter.
onServerForgotten((serverId) => {
  clearUnitAlerts(serverId)
  useAlerts.getState().clearServer(serverId)
  // The repeat window and the escalation memory too: otherwise a re-added
  // server inherits a suppression it never earned.
  for (const k of [...lastNotified.keys()]) {
    if (k.startsWith(`${serverId}:`)) lastNotified.delete(k)
  }
  for (const k of [...lastNotifiedValue.keys()]) {
    if (k.startsWith(`${serverId}:`)) lastNotifiedValue.delete(k)
  }
})

// Switching alerts off has to take the chips with it.
//
// checkResourceAlerts returns before evaluate when the setting is false, so
// nothing on the sampling path can ever clear what is already up. A CPU chip
// survived that until the next restart; a disk chip, whose repeat window is six
// hours and which does not recover on its own, would sit in the status bar
// pointing at a feature the user has just switched off.
useApp.subscribe((s, prev) => {
  if (prev.settings.resourceAlertsEnabled && !s.settings.resourceAlertsEnabled) {
    useAlerts.setState({ active: {} })
  }
})

/**
 * Called from the metrics hook on each sample.
 *
 * `disk` is null when the host reported no disk at all — `df` failing yields a
 * diskPct of 0, and 0 here would post a "back below 85%" all-clear for a host
 * that may well still be full. A measurement failure must never be able to
 * manufacture good news, so null skips the disk evaluation entirely rather than
 * resolving it.
 */
export function checkResourceAlerts(
  serverId: string,
  serverName: string,
  cpu: number,
  ram: number,
  disk: number | null
): void {
  const { resourceAlertsEnabled, resourceAlertThreshold } = useApp.getState().settings
  if (!resourceAlertsEnabled) return
  const now = Date.now()
  const line = clearLine(resourceAlertThreshold)
  evaluate(serverId, serverName, 'cpu', cpu, resourceAlertThreshold, now, cpu >= line)
  evaluate(serverId, serverName, 'ram', ram, resourceAlertThreshold, now, ram >= line)
  // Fixed at DISK_DANGER rather than the configurable threshold: this is the
  // number the Fleet Monitor colours a bar red at and lists a host under, and
  // an alert that fired at a different number from the screen it sends you to
  // is worse than no alert. isDiskCritical is that number's only comparison.
  if (disk !== null) {
    evaluate(serverId, serverName, 'disk', disk, DISK_DANGER, now, isDiskCritical(disk))
  }
}

/**
 * Drops everything this module remembers between samples.
 *
 * For tests only. The maps and the store are module state that outlives a
 * single test, and a repeat window or a chip left over from the previous case
 * makes the next one depend on the order the file happens to run in.
 */
export function resetAlertsForTests(): void {
  lastNotified.clear()
  lastNotifiedValue.clear()
  failedUnits.clear()
  useAlerts.setState({ active: {} })
}
