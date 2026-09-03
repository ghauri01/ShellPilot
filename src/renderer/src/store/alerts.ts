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

// The floor under every reason to speak, per kind. Nothing may notify faster
// than this, whatever justification it has.
//
// The re-raise and escalation bypasses were written for disk and are correct
// for disk: a filesystem takes hours or days to make a round trip through the
// five-point recovery margin, so a value back over the line really is a second
// incident. A CPU makes that trip in one 2-second sample. Sharing the code
// without scoping the bypasses turned a flapping CPU into fifteen desktop
// notifications and thirty webhooks a minute — exactly RATE_LIMIT in
// webhookAlerts.ts, past which genuine alerts are dropped to keep up with the
// noise. Disk sits at zero because its own bypasses are the feature, and every
// case its tests pin depends on them firing immediately.
const MIN_GAP: Record<AlertKind, number> = {
  cpu: 60_000,
  ram: 60_000,
  disk: 0
}

/** Below this, a value counts as recovered rather than merely lower. */
const clearLine = (threshold: number): number => Math.max(0, threshold - RECOVER_MARGIN)

// Last notification time per server+metric, so a sustained problem repeats on
// its kind's window instead of on every 2s sample.
const lastNotified = new Map<string, number>()

// The value we last said out loud, per server+metric. Deleted on a real
// recovery — meaningfully below the line, not merely off it — which is what
// lets a genuine re-raise speak immediately instead of waiting out a window it
// did not earn. See evaluate().
const lastNotifiedValue = new Map<string, number>()

// Server+metric pairs we have raised and not yet cleared. Its own set rather
// than being read off one of the maps above, because the two questions came
// apart once the chip stopped being tied to hysteresis: the chip tracks the
// condition, `lastNotifiedValue` tracks recovery, and this tracks whether the
// endpoint is currently holding an alarm from us. A "resolved" for something
// nobody was told about is a message about nothing, and a host crossing the
// line repeatedly without earning a new raise must not post an all-clear on
// every crossing.
const announced = new Set<string>()

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

// How each kind's line reads in a sentence, because the kinds do not compare
// alike. Disk raises STRICTLY above DISK_DANGER — "at or above 85%" was a
// claim the code does not implement — and correspondingly clears at 85 itself.
// CPU and memory raise at or above their line.
const OVER_WORD: Record<AlertKind, string> = {
  cpu: 'at or above',
  ram: 'at or above',
  disk: 'above'
}
const backBelow: Record<AlertKind, (threshold: number) => string> = {
  cpu: (t) => `back below ${t}%`,
  ram: (t) => `back below ${t}%`,
  disk: (t) => `back to ${t}% or below`
}

// One decimal at most, trailing zero dropped. Rounding to whole points made a
// disk raise at 85.4 arrive as `value: 85, threshold: 85` — indistinguishable
// at the endpoint from exactly 85, which does not fire at all. Whole numbers
// still print as whole numbers, so nothing that was "91%" becomes "91.0%".
const fmt = (v: number): number => Number(v.toFixed(1))

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

  if (!over) {
    // The chip tracks `over` and nothing else, so it can never say something
    // the screen it navigates to denies. Hysteresis belongs to the decision to
    // SPEAK, not to what is on display: holding the chip until `clearAt`
    // stranded every disk in 80–85% — a permanent "Disk 90%" button opening a
    // Fleet Monitor with an empty attention list and an amber bar, which is
    // exactly where a half-cleaned disk sits.
    if (useAlerts.getState().active[k]) {
      useAlerts.setState((s) => {
        const active = { ...s.active }
        delete active[k]
        return { active }
      })
    }

    // The all-clear, once, and only if the endpoint is holding an alarm from
    // us. Without this gate a host crossing the line repeatedly without ever
    // earning a new raise posts a "resolved" on each crossing — a stream of
    // all-clears against a single alarm.
    if (announced.delete(k)) {
      void window.shellpilot?.webhook?.notify({
        source: 'shellpilot',
        version: APP_VERSION,
        event: 'resolved',
        kind: WEBHOOK_KIND[kind],
        server: serverName,
        summary: `${serverName}: ${SUBJECT[kind]} ${backBelow[kind](threshold)}`,
        at: new Date(now).toISOString(),
        value: fmt(value),
        threshold
      })
    }

    // The escalation memory is what makes a later crossing a NEW incident
    // rather than a continuation, so it survives until the value is
    // meaningfully below the line — not merely off it. That is the whole flap
    // defence for a disk oscillating 82/86: the chip follows each crossing,
    // the talking does not.
    if (value < clearAt) lastNotifiedValue.delete(k)

    // `lastNotified` is NOT cleared. Deleting it here let the next crossing
    // notify immediately, which is the other half of the flapping problem:
    // hysteresis stops the oscillation, and keeping the window stops a genuine
    // re-cross seconds later from arriving as if nothing had been said. It
    // expires on its own.
    return
  }

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
  //
  // MIN_GAP is under all three. The first two are disk's bypasses — a disk
  // takes hours to make a round trip through the recovery margin or to climb
  // five points, so they cannot fire often. A CPU does both in one 2-second
  // sample, and without a floor the shared code turned a flapping CPU into a
  // notification per sample.
  const last = lastNotified.get(k) ?? 0
  const said = lastNotifiedValue.get(k)
  const reRaised = said === undefined
  const worsened = said !== undefined && value >= said + ESCALATE_BY
  const due = now - last >= REPEAT[kind]
  if (!reRaised && !worsened && !due) return
  if (now - last < MIN_GAP[kind]) return
  lastNotified.set(k, now)
  lastNotifiedValue.set(k, value)
  announced.add(k)

  const mins = existing ? Math.round((now - existing.since) / 60000) : 0
  const forHow = mins >= 1 ? ` for ${mins} min` : ''
  void window.shellpilot?.notify.show(
    `${serverName}: ${LABEL[kind]} at ${fmt(value)}%`,
    `${SUBJECT[kind]} has been ${OVER_WORD[kind]} ${threshold}%${forHow}.`
  )
  // Same repeat window as the desktop notification, so the endpoint sees the
  // same cadence a person does rather than one message per sample.
  void window.shellpilot?.webhook?.notify({
    source: 'shellpilot',
    version: APP_VERSION,
    event: 'raised',
    kind: WEBHOOK_KIND[kind],
    server: serverName,
    summary: `${serverName}: ${SUBJECT[kind]} at ${fmt(value)}% (threshold ${threshold}%)`,
    at: new Date(now).toISOString(),
    value: fmt(value),
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
  for (const k of [...announced]) {
    if (k.startsWith(`${serverId}:`)) announced.delete(k)
  }
})

// Switching alerts off has to take the chips with it.
//
// checkResourceAlerts returns before evaluate when the setting is false, so
// nothing on the sampling path can ever clear what is already up. A CPU chip
// survived that until the next restart; a disk chip, whose repeat window is six
// hours and which does not recover on its own, would sit in the status bar
// pointing at a feature the user has just switched off.
// It also has to take the memory with it. Clearing only the chips left the
// repeat window, the escalation memory and the outstanding-alarm set running
// across the gap, so switching alerts off and straight back on re-raised the
// chip in silence — no notification, no webhook, and for a disk another six
// hours on a clock that had started before the toggle. Everything this module
// remembers is about a conversation that has just been ended.
useApp.subscribe((s, prev) => {
  if (prev.settings.resourceAlertsEnabled && !s.settings.resourceAlertsEnabled) {
    useAlerts.setState({ active: {} })
    lastNotified.clear()
    lastNotifiedValue.clear()
    announced.clear()
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
  // `line` is the CLEAR line, not the threshold, and CPU and memory are over
  // when they reach it. That is load-bearing and easy to mistake for a bug:
  // because `over` and `clearAt` are then the same number, "over" and "not yet
  // recovered" are the same condition, and the chip and the notification state
  // cannot come apart. Raising this to `>= resourceAlertThreshold` would open
  // a five-point band for CPU where the chip is down but the alert memory is
  // still held — the dead band that stranded disk chips at 82%. If you change
  // it, the `!over` branch in evaluate has to grow the disk case's handling.
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
  announced.clear()
  failedUnits.clear()
  useAlerts.setState({ active: {} })
}
