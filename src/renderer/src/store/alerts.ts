import { create } from 'zustand'
import { useApp } from './app'
import { onServerForgotten } from './serverCleanup'
import { DISK_DANGER, isDiskCritical } from '../components/monitor/hostHealth'
import { EVENT_ALERT_KINDS } from '../../../shared/webhook'
import type {
  AlertKind as WebhookAlertKind,
  EventAlertKind,
  NumericAlertKind,
  StateAlertKind,
  StoreAlertKind,
  StoredAlertEvent,
  StoredAlertRow
} from '../../../shared/webhook'

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

/** The store's kinds. Defined in shared/webhook.ts because the main process
 *  rebuilds a durable row from the same list. */
export type AlertKind = StoreAlertKind

export interface ActiveAlert {
  serverId: string
  serverName: string
  kind: AlertKind
  /** Null for a kind that is a state rather than a reading. Not zero: this is
   *  the same rule the whole item runs on, applied to the chip. */
  value: number | null
  since: number
  /** A short, already-scrubbed phrase for the tooltip and the inbox. Built from
   *  our words and names the user typed, never from remote output. */
  detail?: string
  /** When a snooze on this server+kind ends, if one is running. On the chip so
   *  the inbox can say so — the chip STAYS up during a snooze, because the
   *  condition is still true and a chip that vanished would put the status bar
   *  and the Fleet Monitor back into the disagreement 1a4cfaa ended. */
  snoozedUntil?: number
}

interface AlertState {
  active: Record<string, ActiveAlert>
  list: () => ActiveAlert[]
  clearServer: (serverId: string) => void
}

const key = (serverId: string, kind: AlertKind): string => `${serverId}:${kind}`

/** How a chip's number reads, in the unit that number is actually in. State
 *  kinds have no number at all — a chip that printed one would be inventing a
 *  measurement — so they read as their label alone. */
export function chipValue(a: ActiveAlert): string {
  if (a.value === null) return ''
  const n = Number.isInteger(a.value) ? String(a.value) : a.value.toFixed(1)
  return ` ${n}${UNIT[a.kind as NumericAlertKind] ?? ''}`
}

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
const REPEAT: Record<NumericAlertKind, number> = {
  cpu: 60_000,
  ram: 60_000,
  disk: 6 * 60 * 60 * 1000,
  // Inodes behave like disk and for the same reason: a filesystem does not
  // grow its own inode table back, so the six-hour argument transfers whole.
  inode: 6 * 60 * 60 * 1000,
  // Load moves like CPU because it largely IS CPU, plus uninterruptible I/O.
  load: 60_000
}

// How far below the threshold a value must fall to count as recovered. Without
// it, a host sitting at the line flaps between raised and resolved on every
// sample. See evaluate().
//
// Per kind, because five is five PERCENT for everything measured in percent and
// is nonsense for a load average: a threshold of 2 per core less a margin of 5
// is a clear line below zero, which no reading can ever reach, so a load alert
// would raise once and never resolve. Half a runnable thread per core is the
// same proportion of the line that five points is for a percentage.
const RECOVER_MARGIN: Record<NumericAlertKind, number> = {
  cpu: 5,
  ram: 5,
  disk: 5,
  inode: 5,
  load: 0.5
}

// A rise of this much since the last thing we said re-opens the repeat window.
// See evaluate() for why a six-hour window needs it.
const ESCALATE_BY: Record<NumericAlertKind, number> = {
  cpu: 5,
  ram: 5,
  disk: 5,
  inode: 5,
  // A whole extra runnable thread per core, which on a load average is the
  // same size of step five points is on a percentage.
  load: 1
}

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
const MIN_GAP: Record<NumericAlertKind, number> = {
  cpu: 60_000,
  ram: 60_000,
  disk: 0,
  // Zero for the same reason disk is zero: the re-raise and escalation
  // bypasses are the feature for a condition that does not fix itself, and an
  // inode table does not empty itself either.
  inode: 0,
  load: 60_000
}

/** Below this, a value counts as recovered rather than merely lower. */
const clearLine = (kind: NumericAlertKind, threshold: number): number =>
  Math.max(0, threshold - RECOVER_MARGIN[kind])

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
const announced = new Map<string, { serverId: string; serverName: string; kind: AlertKind }>()

// ---------------------------------------------------------------------------
// The durable half.
//
// The three maps above are the whole memory of this feature and they died with
// the renderer. Cheap to overlook for CPU, whose window is sixty seconds; not
// cheap for disk, whose window is six hours and whose condition does not fix
// itself. A host that has been at 91% for a month re-announced the same 91% on
// every app launch, forever, and the only thing a person can do about an alert
// they cannot action is mute the feature — which the roadmap names as the
// failure that would make shipping this worse than not shipping it.
//
// So every raise and resolve is written to the history store and the maps are
// rebuilt from it at startup. What is durable and what is not was decided one
// question at a time:
//
//   lastNotified       DURABLE. It is the repeat window, and the whole point.
//   lastNotifiedValue  DURABLE. Without it a restart makes every outstanding
//                      alert look like a first crossing (`said === undefined`
//                      is the re-raise bypass) and announce immediately.
//   announced          DURABLE. Otherwise a restart followed by a recovery
//                      posts no all-clear for an alarm the endpoint is holding.
//   raiseTimes         DURABLE (stage 2's flap counter — see damping below).
//   active (the chip)  IN MEMORY, deliberately. It states what is true NOW, and
//                      what was true before a restart is not that. It is
//                      rebuilt by the first sample, one interval later.
//   failedUnits        IN MEMORY, deliberately. It is a diff against the last
//                      sweep's unit set, and a set from before a restart would
//                      make every unit that failed while the app was closed
//                      look like it failed at launch. Announcing it once at
//                      startup is the correct behaviour and is what happens.
// ---------------------------------------------------------------------------

/** How many rows the startup read asks for. Two hundred crossings is far more
 *  than a healthy estate produces in the ninety days the store keeps events,
 *  and small enough that the read is not something to think about. */
const HISTORY_LIMIT = 500

/**
 * Whether the durable state has been read back yet.
 *
 * Starts TRUE, and only `hydrateAlerts()` sets it false. A module that gated on
 * hydration by default would be silent in every context that never calls it —
 * every existing test, and any window that loads before the bridge — which is
 * the failure this whole item is about, inverted.
 */
let hydrated = true
let hydrating: Promise<void> | null = null

// ---------------------------------------------------------------------------
// Flap damping.
//
// RECOVER_MARGIN handles a host sitting ON the line: a resolve only registers
// five points below it, so an alert cannot oscillate on the noise in a single
// reading. Nothing handled a host that crosses CLEANLY and repeatedly — down
// through the whole recovery margin and back over the line, over and over. Each
// of those crossings is, correctly, a new incident by every rule 19a wrote, and
// forty of them overnight is the outcome the roadmap says would be worse than
// not shipping the feature at all, because the only defence left to the reader
// is the mute button.
//
// THE RULE. Five clean crossings of one server+kind within six hours means the
// signal is oscillating rather than reporting. The fifth says so out loud and is
// the last thing said about that server+kind until it has gone six hours
// without crossing the line again.
//
// Why it is written that way, one clause at a time:
//
//  * Only CLEAN CROSSINGS count — a sample where the condition became true
//    having been false. The "still going" repeats do not, and that distinction
//    is load-bearing rather than tidy: CPU's repeat window is sixty seconds, so
//    counting repeats would damp a genuinely pegged processor after five
//    minutes. Flapping is defined as crossing repeatedly, so crossings are
//    literally what is counted.
//  * A crossing is read off the CONDITION, not off whether we spoke. Reading it
//    off the notification state would stop the counter the moment damping began
//    — a damped host would look like it had settled — and the whole rule needs
//    to keep watching a host it has stopped talking about.
//  * FIVE, because a crossing is already expensive to earn: a full round trip
//    through the five-point recovery margin plus the kind's MIN_GAP floor. Four
//    in six hours is a host having a bad afternoon; five is a signal that has
//    stopped tracking anything a person can act on.
//  * QUIET UNTIL SIX HOURS WITHOUT A CROSSING, rather than a fixed six hours
//    from the trip. A fixed period is a metronome: forty crossings overnight
//    become one burst of five every six hours, which is ten messages rather
//    than forty and still nothing anybody wants. Refreshing on each crossing
//    makes the damp end when the flapping ends, which is the honest condition,
//    and turns forty overnight into five.
//
// The cost, stated rather than hidden: a host that crosses five times and then
// settles into a genuinely sustained problem is silent for six hours. It keeps
// its status-bar chip, every crossing is in the inbox, and escalation still
// speaks — a value five points worse than the figure last announced is monotone
// movement, which is the one shape a flap never has. That is the trade the
// roadmap asks for, in the direction it asks for it.
// ---------------------------------------------------------------------------

const FLAP_WINDOW_MS = 6 * 60 * 60 * 1000
const FLAP_CROSSINGS = 5
const FLAP_DAMP_MS = 6 * 60 * 60 * 1000

/** Clean-crossing timestamps per server+kind, oldest first. Bounded by
 *  FLAP_WINDOW_MS, and emptied when a damp trips. */
const raiseTimes = new Map<string, number[]>()

/** When each damped server+kind may speak again. Refreshed by every crossing
 *  that happens while it is damped. */
const dampedUntil = new Map<string, number>()

// ---------------------------------------------------------------------------
// The two things a person can do about an alert, and why they are not one
// thing with a duration.
//
// SNOOZE is a period. "Not for the next eight hours" — the condition is still
// true, the reader knows, and they will look again after. The chip stays up
// because the condition has not changed and a chip that disappeared would put
// the status bar back into disagreement with the screen it links to.
//
// ACKNOWLEDGE is not a period, and giving it one is the mistake this pair is
// split to avoid. "I have seen this and I am dealing with it" lasts exactly as
// long as the condition does — a disk being cleaned takes as long as it takes,
// and an acknowledgement that expired after eight hours would start shouting
// again in the middle of the work it was acknowledging. So it ends when the
// condition ends, and the chip goes with it: the person has taken the alert,
// and a status bar still counting it is counting their own inbox back at them.
//
// Both are DURABLE, for the same reason the repeat window is. A snooze that
// died with the renderer would be undone by a restart, which is the one thing
// somebody does when an app is annoying them.
//
// Both are kept apart from `dampedUntil` rather than folded into it, even
// though the suppression they want is identical, because the refresh is not:
// a crossing that happens while DAMPED extends the damp to six hours, and a
// thirty-minute snooze that silently became six hours because the host crossed
// once more would be the app deciding how long the user meant.
// ---------------------------------------------------------------------------

/** When each snoozed server+kind may speak again. Set by the user, never
 *  refreshed by anything the estate does. */
const snoozedUntil = new Map<string, number>()

/** Server+kinds the user has said they have seen. Cleared when the condition
 *  clears, not on a clock. */
const acknowledged = new Set<string>()

/**
 * Whether the condition was true on the last sample, per server+kind.
 *
 * The crossing detector, and deliberately not the status-bar chip even though
 * the two move together: the chip is in-memory on purpose, so at startup it
 * says nothing held, and a chronically full disk would look like it crossed
 * afresh at every launch. This set is seeded from the durable outstanding
 * alarms instead, so a disk that was full when the app closed and is full when
 * it opens has not crossed anything.
 */
const conditionHeld = new Set<string>()

/**
 * Occurrences already announced, as `serverId:kind:detail:at`.
 *
 * The event kinds have no condition to hold and no resolve to wait for, so the
 * only thing that can stop the same occurrence being announced twice is knowing
 * it has been announced. It is seeded from the durable log during hydration, so
 * a restart does not replay a night of database alarms into the notification
 * centre — which is the exact failure the durable half of this feature was
 * written to end, in a different kind.
 */
const seenEvents = new Set<string>()

const eventDedupeKey = (id: string, kind: AlertKind, detail: string, at: number): string =>
  `${id}:${kind}:${detail}:${at}`

/** Whether a kind is one of the "something happened, once" kinds. Read off the
 *  shared list rather than a second literal, so a kind added there cannot be
 *  quietly left behind here. */
const isEventKind = (k: AlertKind): boolean => (EVENT_ALERT_KINDS as readonly string[]).includes(k)

function record(
  kind: AlertKind,
  event: StoredAlertEvent['event'],
  a: {
    serverId: string
    serverName: string
    value?: number
    threshold?: number
    detail?: string
    until?: number
    at: number
  }
): void {
  void window.shellpilot?.alerts?.record?.(
    {
      event,
      kind,
      serverId: a.serverId,
      serverName: a.serverName,
      ...(a.value === undefined ? {} : { value: fmt(a.value) }),
      ...(a.threshold === undefined ? {} : { threshold: a.threshold }),
      // Written only when there is one. An empty string in the row would be a
      // detail the inbox renders as a blank parenthesis rather than an absent
      // one, and absent is what it is.
      ...(a.detail ? { detail: a.detail } : {}),
      ...(a.until === undefined ? {} : { until: a.until })
    },
    a.at
  )
}

/**
 * Rebuild the maps from the log.
 *
 * A chronological REPLAY rather than a latest-row-wins scan, because two of the
 * five things being rebuilt are not latest-wins facts. The flap counter is a
 * count of clean crossings over a window, and whether a crossing was clean
 * depends on what preceded it — so the rows have to be walked in the order they
 * happened, applying exactly the transitions evaluate() applies. Rows arrive
 * newest-first; reversing preserves the store's tie-break inside one
 * millisecond, which a raise followed immediately by a stand-down produces.
 *
 * Exported for the restart tests, which are the only way to prove any of this
 * without relaunching an app.
 */
export function applyStoredAlerts(rows: readonly StoredAlertRow[]): void {
  for (const row of [...rows].reverse()) {
    const k = key(row.serverId, row.kind)
    if (isEventKind(row.kind)) {
      // An event kind holds no condition and never writes a resolve, so every
      // raise in the log is a separate occurrence rather than the start of one
      // that is still running. Walking these down the branch below would mark
      // the first one outstanding forever and then read every later one as a
      // "still going" repeat — so the flap counter that exists to damp a
      // database re-reporting the same alarm on every poll would never get past
      // one, and damping would be the one piece of this that a restart undid.
      //
      // This mirrors noteAlertEvent exactly, including the refresh: a
      // occurrence arriving while damped extends the quiet rather than being
      // counted towards a new damp.
      seenEvents.add(eventDedupeKey(row.serverId, row.kind, row.detail ?? '', row.at))
      if (isSnoozed(k, row.at) || acknowledged.has(k)) continue
      if (isDamped(k, row.at)) dampedUntil.set(k, row.at + FLAP_DAMP_MS)
      else noteCrossing(k, row.at)
      continue
    }
    if (row.event === 'raised') {
      // A crossing is CLEAN when nothing was outstanding — the same test
      // evaluate() calls `reRaised`, and for the same reason: a "still going"
      // repeat is not a crossing, and counting repeats would damp a sustained
      // alert rather than a flapping one.
      if (!conditionHeld.has(k)) noteCrossing(k, row.at)
      conditionHeld.add(k)
      lastNotified.set(k, row.at)
      // `undefined` here is the re-raise bypass, so a raise whose value did not
      // survive the whitelist must NOT land as "nothing outstanding" — it would
      // announce immediately on the next sample, which is the restart noise
      // this function exists to stop. A raise we cannot put a number to still
      // counts as outstanding, at the value the threshold implies.
      lastNotifiedValue.set(k, row.value ?? row.threshold ?? 0)
      announced.set(k, { serverId: row.serverId, serverName: row.serverName, kind: row.kind })
    } else if (row.event === 'snoozed') {
      // Absolute, so it means what it meant when it was set. An expired one is
      // simply over — isSnoozed drops it lazily on the first read.
      if (row.until !== undefined) snoozedUntil.set(k, row.until)
    } else if (row.event === 'acknowledged') {
      acknowledged.add(k)
    } else if (row.event === 'stood-down') {
      // Alerting was switched off with this outstanding. Nothing is owed and
      // nothing is suppressed: the next crossing is a new conversation, which
      // is what the in-session toggle already does.
      lastNotified.delete(k)
      lastNotifiedValue.delete(k)
      announced.delete(k)
      conditionHeld.delete(k)
      raiseTimes.delete(k)
      dampedUntil.delete(k)
      snoozedUntil.delete(k)
      acknowledged.delete(k)
    } else {
      // A resolve leaves the repeat window in place and clears the escalation
      // memory — exactly what evaluate()'s `!over` branch does, for the reason
      // written there: a genuine re-cross seconds later must not arrive as if
      // nothing had been said.
      lastNotified.set(k, row.at)
      lastNotifiedValue.delete(k)
      announced.delete(k)
      conditionHeld.delete(k)
      // An acknowledgement lasts as long as its condition, and this row is the
      // condition ending. A snooze is a period the user chose and outlives the
      // thing it was about — otherwise a disk that cleared five minutes into an
      // eight-hour snooze would be free to shout again for the other seven.
      acknowledged.delete(k)
    }
  }
}

/**
 * Count one clean crossing. Returns true if this is the one that trips the damp.
 *
 * The list is trimmed to the window on the way in, so a host that oscillates
 * for a week does not accumulate a week of timestamps, and emptied on a trip,
 * so the six hours of quiet are counted from the trip rather than from whatever
 * happened to still be in the list.
 */
function noteCrossing(k: string, now: number): boolean {
  const times = (raiseTimes.get(k) ?? []).filter((t) => now - t < FLAP_WINDOW_MS)
  times.push(now)
  if (times.length < FLAP_CROSSINGS) {
    raiseTimes.set(k, times)
    return false
  }
  raiseTimes.delete(k)
  dampedUntil.set(k, now + FLAP_DAMP_MS)
  return true
}

/** Whether this server+kind is currently damped. Expiry is lazy: a damp read
 *  back from a log three days old is simply over. */
function isDamped(k: string, now: number): boolean {
  const until = dampedUntil.get(k)
  if (until === undefined) return false
  if (now >= until) {
    dampedUntil.delete(k)
    return false
  }
  return true
}

/** Whether the user has snoozed this server+kind. Same lazy expiry, same
 *  reason. */
function isSnoozed(k: string, now: number): boolean {
  const until = snoozedUntil.get(k)
  if (until === undefined) return false
  if (now >= until) {
    snoozedUntil.delete(k)
    return false
  }
  return true
}

/**
 * Whether anything at all should be said about this server+kind.
 *
 * One predicate over the three reasons for silence, so a code path cannot check
 * two of them and miss the third. Every "should we speak" gate calls this; the
 * only places that ask about damping specifically are the two that REFRESH a
 * damp, because a snooze and an acknowledgement must not be extended by
 * anything the estate does.
 */
function isQuiet(k: string, now: number): boolean {
  return isDamped(k, now) || isSnoozed(k, now) || acknowledged.has(k)
}

export function hydrateAlerts(): Promise<void> {
  if (hydrating) return hydrating
  const read = window.shellpilot?.alerts?.history
  if (!read) return Promise.resolve()
  hydrated = false
  hydrating = Promise.resolve(read(HISTORY_LIMIT))
    .then((rows) => {
      if (Array.isArray(rows)) applyStoredAlerts(rows)
    })
    .catch(() => {
      // Nothing to say. An unreadable log is a reason to behave as if there
      // were none, not a reason to stop alerting.
    })
    .then(() => {
      hydrated = true
    })
  return hydrating
}

/** Short, for the status-bar chip and the notification title. */
export const LABEL: Record<AlertKind, string> = {
  cpu: 'CPU',
  ram: 'Memory',
  disk: 'Disk',
  inode: 'Inodes',
  load: 'Load',
  'host-unreachable': 'Unreachable',
  'job-failed': 'Job failed',
  'tunnel-down': 'Tunnel down',
  'db-alarm': 'Database alarm',
  'db-watch': 'Database watch'
}

// What the number is measuring, for the sentences a person reads. Disk says
// "root filesystem" and means it: metrics.ts probes `df -kP /` and nothing
// else, so a host with a full /var and a roomy / raises nothing here, and an
// alert that said "disk" would be claiming to have looked at more than it did.
const SUBJECT: Record<NumericAlertKind, string> = {
  cpu: 'CPU',
  ram: 'Memory',
  disk: 'Root filesystem',
  // Same probe, same caveat: `df -iP /` and nothing else, so a host that has
  // exhausted the inodes on /var and has room on / raises nothing here.
  inode: 'Root filesystem inodes',
  load: 'Load average'
}

// How each kind's line reads in a sentence, because the kinds do not compare
// alike. Disk raises STRICTLY above DISK_DANGER — "at or above 85%" was a
// claim the code does not implement — and correspondingly clears at 85 itself.
// CPU and memory raise at or above their line.
const OVER_WORD: Record<NumericAlertKind, string> = {
  cpu: 'at or above',
  ram: 'at or above',
  disk: 'above',
  inode: 'above',
  load: 'at or above'
}
const backBelow: Record<NumericAlertKind, (threshold: number) => string> = {
  cpu: (t) => `back below ${t}%`,
  ram: (t) => `back below ${t}%`,
  disk: (t) => `back to ${t}% or below`,
  inode: (t) => `back to ${t}% or below`,
  load: (t) => `back below ${t} per core`
}

// The unit each kind's number is in. Not everything alerting measures is a
// percentage, and a load average printed as "3%" is a wrong number rather than
// an ugly one — which is what the status-bar chip showed before this existed.
export const UNIT: Record<NumericAlertKind, string> = {
  cpu: '%',
  ram: '%',
  disk: '%',
  inode: '%',
  load: ' per core'
}

// One decimal at most, trailing zero dropped. Rounding to whole points made a
// disk raise at 85.4 arrive as `value: 85, threshold: 85` — indistinguishable
// at the endpoint from exactly 85, which does not fire at all. Whole numbers
// still print as whole numbers, so nothing that was "91%" becomes "91.0%".
const fmt = (v: number): number => Number(v.toFixed(1))

// The wire name for each kind. A Record rather than a ternary, so adding a kind
// is a type error here instead of a metric quietly posting as 'memory'.
const WEBHOOK_KIND: Record<StoreAlertKind, WebhookAlertKind> = {
  cpu: 'cpu',
  ram: 'memory',
  disk: 'disk',
  inode: 'inode',
  load: 'load',
  'host-unreachable': 'host-unreachable',
  'job-failed': 'job-failed',
  'tunnel-down': 'tunnel-down',
  'db-alarm': 'db-alarm',
  'db-watch': 'db-watch'
}

function evaluate(
  serverId: string,
  serverName: string,
  kind: NumericAlertKind,
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

  // Hysteresis, and it applies to the TALKING only. Treating a host that has
  // merely stepped back over the line as recovered means it re-raises on the
  // next sample, and at the foreground 2s cadence that is a desktop
  // notification every few seconds and roughly thirty webhooks a minute —
  // exactly the delivery rate limit, past which the path starts dropping real
  // alerts to keep up with its own noise. So the escalation memory survives
  // until the value is meaningfully below the line. The CHIP does not use this
  // number: see the `!over` branch for why holding it here was a bug.
  const clearAt = clearLine(kind, threshold)

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

    // Nothing is said until the durable log has been read back. A resolve
    // decided against an empty `announced` is a resolve for an alarm we cannot
    // yet know whether we hold. One sample later the answer is on hand.
    if (!hydrated) return

    conditionHeld.delete(k)

    // An acknowledgement ends with the condition it was about, and it is
    // cleared HERE — before the quiet gate — so the all-clear still goes out.
    // The person acknowledged the alert on their own screen; an endpoint left
    // holding an alarm that nothing will ever close is a different lie from the
    // one acknowledging was meant to stop.
    acknowledged.delete(k)

    // Damped, snoozed: the crossing is real, the chip has already followed it, and the
    // durable log records it. What is suppressed is the talking, and that has
    // to include the all-clear — half of a flap's noise is all-clears. The
    // outstanding alarm and the escalation memory are left standing on purpose,
    // so the endpoint's view is one raise, then silence, then whichever of a
    // repeat or an all-clear is true when the damp ends.
    if (isQuiet(k, now)) return

    // The all-clear, once, and only if the endpoint is holding an alarm from
    // us. Without this gate a host crossing the line repeatedly without ever
    // earning a new raise posts a "resolved" on each crossing — a stream of
    // all-clears against a single alarm.
    if (announced.delete(k)) {
      record(kind, 'resolved', { serverId, serverName, value, threshold, at: now })
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
  // An acknowledged alert keeps NO chip. The person has taken it, and a status
  // bar still counting it is counting their own inbox back at them. Everything
  // else about the condition goes on: the crossing counter, the durable log,
  // and the all-clear when it finally clears.
  if (!acknowledged.has(k)) {
    useAlerts.setState((s) => ({
      active: {
        ...s.active,
        [k]: {
          serverId,
          serverName,
          kind,
          value,
          since: existing?.since ?? now,
          ...(snoozedUntil.has(k) ? { snoozedUntil: snoozedUntil.get(k) } : {})
        }
      }
    }))
  }

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
  // Same gate as the resolve above, and the same reasoning: the repeat window
  // that decides this is on disk and has not been read yet. The chip is already
  // up, which is the part that must not wait.
  if (!hydrated) return

  // The crossing counter, which runs whether or not anything is said. See the
  // damping rule above for why it is read off the condition rather than off the
  // notification state: a damped host that is still flapping has to go on
  // looking like a damped host that is still flapping.
  //
  // Refreshing an existing damp happens HERE, before any of the gates below,
  // because a damped host that goes on crossing has to keep the damp alive
  // even though nothing is said about it. Counting the crossing towards a NEW
  // damp waits until we know we are actually going to speak — a crossing
  // swallowed by MIN_GAP was never announced, and a rule that counted it could
  // trip a damp whose own announcement nobody ever saw.
  const crossing = !conditionHeld.has(k)
  if (crossing) {
    conditionHeld.add(k)
    if (isDamped(k, now)) dampedUntil.set(k, now + FLAP_DAMP_MS)
  }

  const last = lastNotified.get(k) ?? 0
  const said = lastNotifiedValue.get(k)
  const reRaised = said === undefined
  const worsened = said !== undefined && value >= said + ESCALATE_BY[kind]
  const due = now - last >= REPEAT[kind]
  if (!reRaised && !worsened && !due) return
  if (now - last < MIN_GAP[kind]) return
  // Escalation is the one thing a damp does not stop. A value five points worse
  // than the figure last announced is monotone movement, and monotone movement
  // is the one shape a flap never has.
  if (!worsened && isQuiet(k, now)) return
  // The crossing that trips the damp is still announced — that message is what
  // tells a person the feature has gone quiet on purpose.
  const tripped = crossing && noteCrossing(k, now)
  lastNotified.set(k, now)
  lastNotifiedValue.set(k, value)
  announced.set(k, { serverId, serverName, kind })
  record(kind, 'raised', { serverId, serverName, value, threshold, at: now })

  const mins = existing ? Math.round((now - existing.since) / 60000) : 0
  const forHow = mins >= 1 ? ` for ${mins} min` : ''
  // Damping is announced, never silent. A feature that quietly stops talking is
  // indistinguishable from one that has broken, and the person who needs to
  // know an alert is being damped is exactly the person about to mute it.
  const dampHours = Math.round(FLAP_DAMP_MS / 3_600_000)
  const quiet = tripped
    ? ` This has crossed the line ${FLAP_CROSSINGS} times in ${dampHours} hours, so nothing further ` +
      `will be said about it until it has gone ${dampHours} hours without crossing again. ` +
      `The Alerts tab still lists every crossing.`
    : ''
  void window.shellpilot?.notify.show(
    `${serverName}: ${LABEL[kind]} at ${fmt(value)}${UNIT[kind]}`,
    `${SUBJECT[kind]} has been ${OVER_WORD[kind]} ${threshold}${UNIT[kind]}${forHow}.${quiet}`
  )
  // Same repeat window as the desktop notification, so the endpoint sees the
  // same cadence a person does rather than one message per sample.
  void window.shellpilot?.webhook?.notify({
    source: 'shellpilot',
    version: APP_VERSION,
    event: 'raised',
    kind: WEBHOOK_KIND[kind],
    server: serverName,
    summary:
      `${serverName}: ${SUBJECT[kind]} at ${fmt(value)}${UNIT[kind]} ` +
      `(threshold ${threshold}${UNIT[kind]})`,
    at: new Date(now).toISOString(),
    value: fmt(value),
    threshold,
    ...(mins >= 1 ? { minutes: mins } : {}),
    // The endpoint has to be told too, and for a stronger reason than the
    // desktop does: an endpoint that stops receiving has no way to tell "damped"
    // from "ShellPilot died".
    ...(tripped ? { damped: true } : {})
  })
}

// ---------------------------------------------------------------------------
// Kinds that are a state, not a reading.
//
// A host that will not answer, a job step that failed, a tunnel sitting in
// error. None of them has a number, a threshold, a recovery margin or an
// escalation step, and inventing a value of 1 so they could share the numeric
// path would put "1 per core" in a person's notification. They do share
// everything that matters: the chip, the repeat window, the outstanding-alarm
// pairing that stops an all-clear for something nobody was told about, the
// durable log, and flap damping — a tunnel that flaps is exactly as tiring as a
// disk that does.
//
// The words are per kind and are built here, from our own sentences and from
// names the user typed. Nothing a host, a job or a database said reaches them:
// AlertPayload.summary is rendered by Slack, and secretRedaction.ts exists
// because remote text in an outbound field is easy to get wrong.
// ---------------------------------------------------------------------------

const STATE_WORDS: Record<
  StateAlertKind,
  { raised: (name: string, detail: string) => string; resolved: (name: string) => string }
> = {
  'host-unreachable': {
    raised: (name) => `${name} did not answer the last check`,
    resolved: (name) => `${name} is answering again`
  },
  'job-failed': {
    raised: (name, detail) => `${name} failed a job step${detail ? ` (${detail})` : ''}`,
    resolved: (name) => `${name} has completed a job step since`
  },
  'tunnel-down': {
    raised: (name) => `Tunnel ${name} is in error`,
    resolved: (name) => `Tunnel ${name} is carrying traffic again`
  }
}

const EVENT_WORDS: Record<EventAlertKind, (name: string, detail: string) => string> = {
  'db-alarm': (name, detail) => `${name}: ${detail} is in alarm`,
  'db-watch': (name, detail) => `${name}: ${detail} is worth watching`
}

// The same character class systemd unit names get, and for the same reason: a
// `<!channel>` in a name that reaches `summary` is a mass ping in a workspace
// that trusts this integration. Spaces are allowed because these are names the
// user typed, and a job called "Upgrade the estate" should read as one.
const cleanName = (v: string): string =>
  v.slice(0, 128).replace(/[^A-Za-z0-9 ._@:-]/g, '').replace(/^@+/, '').trim()

/**
 * One state signal.
 *
 * `bad` is `boolean | null`, and the null is the whole point: a tunnel list
 * that could not be read, a sweep that did not run, a job whose outcome is not
 * in yet. Null raises nothing, resolves nothing, and leaves the chip exactly
 * where it is — it is not "fine", it is "not asked".
 */
export function checkStateAlert(
  id: string,
  name: string,
  kind: StateAlertKind,
  bad: boolean | null,
  detail = ''
): void {
  if (bad === null) return
  if (!useApp.getState().settings.resourceAlertsEnabled) return
  const now = Date.now()
  const k = key(id, kind)
  const who = cleanName(name) || 'A server'
  const what = cleanName(detail)

  if (!bad) {
    if (useAlerts.getState().active[k]) {
      useAlerts.setState((s) => {
        const active = { ...s.active }
        delete active[k]
        return { active }
      })
    }
    if (!hydrated) return
    conditionHeld.delete(k)
    // An acknowledgement ends with the condition it was about, and it is
    // cleared HERE — before the quiet gate — so the all-clear still goes out.
    // The person acknowledged the alert on their own screen; an endpoint left
    // holding an alarm that nothing will ever close is a different lie from the
    // one acknowledging was meant to stop.
    acknowledged.delete(k)
    if (isQuiet(k, now)) return
    if (announced.delete(k)) {
      lastNotified.set(k, now)
      void window.shellpilot?.webhook?.notify({
        source: 'shellpilot',
        version: APP_VERSION,
        event: 'resolved',
        kind: WEBHOOK_KIND[kind],
        server: who,
        summary: STATE_WORDS[kind].resolved(who),
        at: new Date(now).toISOString()
      })
      record(kind, 'resolved', { serverId: id, serverName: who, at: now })
    }
    return
  }

  const existing = useAlerts.getState().active[k]
  if (!acknowledged.has(k)) {
    useAlerts.setState((s) => ({
      active: {
        ...s.active,
        [k]: {
          serverId: id,
          serverName: who,
          kind,
          value: null,
          since: existing?.since ?? now,
          detail: what,
          ...(snoozedUntil.has(k) ? { snoozedUntil: snoozedUntil.get(k) } : {})
        }
      }
    }))
  }
  if (!hydrated) return

  const crossing = !conditionHeld.has(k)
  if (crossing) {
    conditionHeld.add(k)
    if (isDamped(k, now)) dampedUntil.set(k, now + FLAP_DAMP_MS)
  }

  // A state kind has no "still going" repeat and no escalation: there is
  // nothing to say a second time about a host that is still not answering that
  // the first message did not already say, and no number that could get worse.
  // So it speaks once per transition and then holds its peace until it
  // resolves — which is stricter than the numeric path, deliberately.
  if (!crossing) return
  if (isQuiet(k, now)) return
  const tripped = noteCrossing(k, now)
  lastNotified.set(k, now)
  // `lastNotifiedValue` is deliberately NOT written. It is the escalation
  // memory — "the figure we last said out loud" — and a state kind has no
  // figure. A 1 here would be a number nothing reads, put there so the two
  // paths look alike; the paths are not alike, which is why they are two.
  announced.set(k, { serverId: id, serverName: who, kind })

  const dampHours = Math.round(FLAP_DAMP_MS / 3_600_000)
  const quiet = tripped
    ? ` This has happened ${FLAP_CROSSINGS} times in ${dampHours} hours, so nothing further will ` +
      `be said about it until it has gone ${dampHours} hours without happening again. ` +
      `The Alerts tab still lists every one.`
    : ''
  const summary = STATE_WORDS[kind].raised(who, what)
  void window.shellpilot?.notify.show(`${who}: ${LABEL[kind]}`, `${summary}.${quiet}`)
  void window.shellpilot?.webhook?.notify({
    source: 'shellpilot',
    version: APP_VERSION,
    event: 'raised',
    kind: WEBHOOK_KIND[kind],
    server: who,
    summary,
    at: new Date(now).toISOString(),
    ...(tripped ? { damped: true } : {})
  })
  record(kind, 'raised', { serverId: id, serverName: who, detail: what, at: now })
}

/**
 * Something happened, once. Item 18's database verdicts.
 *
 * `notableDbEvents` records `alarm` and `watch` and deliberately does not
 * record `ok`, so nothing in the store can ever say a database recovered. A
 * kind that cannot observe its own recovery must not hold a status-bar chip:
 * the chip would be permanent, it would point at a Fleet Monitor that disagreed
 * with it, and that exact contradiction is what 1a4cfaa was written to end.
 *
 * So this raises, is recorded, and is done. The inbox is where it lives
 * afterwards, which is what an inbox is for.
 *
 * `at` is the store's own timestamp for the row, and is what makes this
 * idempotent: the same row seen by two polls is announced once.
 */
export function noteAlertEvent(
  id: string,
  name: string,
  kind: EventAlertKind,
  detail: string,
  at: number
): void {
  if (!useApp.getState().settings.resourceAlertsEnabled) return
  const who = cleanName(name) || 'A database'
  const what = cleanName(detail)
  // Keyed on the SCRUBBED detail and on the store's own timestamp, because
  // those are the two fields the durable row carries — and the durable row is
  // what seeds this set at hydration. Keying on the raw detail here would make
  // the seed miss every row whose detail the scrubber changed, and the first
  // launch after a night of alarms would replay all of them.
  const dedupe = eventDedupeKey(id, kind, what, at)
  if (seenEvents.has(dedupe)) return
  const k = key(id, kind)
  if (!hydrated) {
    // Not marked seen — so the next poll offers it again once the log has been
    // read. Announcing before hydration is exactly what the damping and repeat
    // state on disk exist to prevent.
    return
  }
  seenEvents.add(dedupe)
  // A snooze is the user's own period and nothing the estate does may extend
  // it, so it returns before the damp refresh below rather than through it.
  if (isSnoozed(k, at) || acknowledged.has(k)) return
  // The occurrence's OWN time drives damping, not the wall clock at the moment
  // we happened to read it. That is what makes the live path and the hydration
  // replay above the same arithmetic on the same rows, rather than two versions
  // that agree until a poll runs late.
  if (isDamped(k, at)) {
    dampedUntil.set(k, at + FLAP_DAMP_MS)
    return
  }
  const tripped = noteCrossing(k, at)
  const summary = EVENT_WORDS[kind](who, what)
  const dampHours = Math.round(FLAP_DAMP_MS / 3_600_000)
  void window.shellpilot?.notify.show(
    `${who}: ${LABEL[kind]}`,
    `${summary}.` +
      (tripped
        ? ` This has happened ${FLAP_CROSSINGS} times in ${dampHours} hours, so nothing further ` +
          `will be said about it until it has gone ${dampHours} hours without happening again. ` +
          `The Alerts tab still lists every one.`
        : '')
  )
  void window.shellpilot?.webhook?.notify({
    source: 'shellpilot',
    version: APP_VERSION,
    event: 'raised',
    kind: WEBHOOK_KIND[kind],
    server: who,
    summary,
    at: new Date(at).toISOString(),
    ...(tripped ? { damped: true } : {})
  })
  record(kind, 'raised', { serverId: id, serverName: who, detail: what, at })
}

// ---------------------------------------------------------------------------
// What a person can do about an alert, from the inbox.
// ---------------------------------------------------------------------------

/** The durations the inbox offers. An hour is "I am on it", eight hours is
 *  "not during this shift", a day is "not until tomorrow". Longer than a day is
 *  what acknowledging is for. */
export const SNOOZE_CHOICES: readonly { label: string; ms: number }[] = [
  { label: '1 hour', ms: 60 * 60 * 1000 },
  { label: '8 hours', ms: 8 * 60 * 60 * 1000 },
  { label: '24 hours', ms: 24 * 60 * 60 * 1000 }
]

/**
 * Stop talking about this server+kind for a while.
 *
 * The chip stays up, and that is the point of the pair rather than an
 * oversight: the condition has not changed, and a snooze that cleared the chip
 * would put the status bar back into disagreement with the screen it links to —
 * the contradiction 1a4cfaa was written to end.
 *
 * Escalation still speaks, exactly as it does under flap damping, and for the
 * same reason: a value five points worse than the figure last announced is
 * monotone movement, and someone who snoozed a disk at 86% did not snooze it at
 * 96%.
 */
export function snoozeAlert(serverId: string, kind: AlertKind, ms: number): void {
  const k = key(serverId, kind)
  const until = Date.now() + Math.max(0, ms)
  snoozedUntil.set(k, until)
  // Acknowledging and snoozing are alternatives, not layers. Choosing one
  // replaces the other rather than stacking a period on top of something that
  // has none.
  acknowledged.delete(k)
  const a = useAlerts.getState().active[k]
  if (a) useAlerts.setState((s) => ({ active: { ...s.active, [k]: { ...a, snoozedUntil: until } } }))
  record(kind, 'snoozed', {
    serverId,
    serverName: a?.serverName ?? '',
    detail: a?.detail,
    until,
    at: Date.now()
  })
}

/** End a snooze early. Written to the log as a zero-length snooze rather than
 *  as a new event name: "quiet until then" with a `then` in the past is exactly
 *  what this means, and it replays correctly without teaching the reader a
 *  fifth verb. */
export function unsnoozeAlert(serverId: string, kind: AlertKind): void {
  const k = key(serverId, kind)
  snoozedUntil.delete(k)
  const a = useAlerts.getState().active[k]
  if (a) {
    const next = { ...a }
    delete next.snoozedUntil
    useAlerts.setState((s) => ({ active: { ...s.active, [k]: next } }))
  }
  const at = Date.now()
  record(kind, 'snoozed', { serverId, serverName: a?.serverName ?? '', detail: a?.detail, until: at, at })
}

/**
 * "I have seen this and I am dealing with it."
 *
 * Not a snooze with a long duration. An acknowledgement lasts exactly as long
 * as the condition does — cleaning a disk takes as long as it takes, and an
 * acknowledgement that expired on a clock would start shouting again in the
 * middle of the work it acknowledged. The chip goes, because the person has
 * taken the alert; the condition is still tracked, the log still records it,
 * and the endpoint still gets its all-clear when it really clears.
 */
export function acknowledgeAlert(serverId: string, kind: AlertKind): void {
  const k = key(serverId, kind)
  acknowledged.add(k)
  snoozedUntil.delete(k)
  const a = useAlerts.getState().active[k]
  useAlerts.setState((s) => {
    const active = { ...s.active }
    delete active[k]
    return { active }
  })
  record(kind, 'acknowledged', {
    serverId,
    serverName: a?.serverName ?? '',
    detail: a?.detail,
    at: Date.now()
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
  for (const k of [...announced.keys()]) {
    if (k.startsWith(`${serverId}:`)) announced.delete(k)
  }
  for (const k of [...raiseTimes.keys()]) {
    if (k.startsWith(`${serverId}:`)) raiseTimes.delete(k)
  }
  for (const k of [...dampedUntil.keys()]) {
    if (k.startsWith(`${serverId}:`)) dampedUntil.delete(k)
  }
  for (const k of [...snoozedUntil.keys()]) {
    if (k.startsWith(`${serverId}:`)) snoozedUntil.delete(k)
  }
  for (const k of [...acknowledged]) {
    if (k.startsWith(`${serverId}:`)) acknowledged.delete(k)
  }
  for (const k of [...conditionHeld]) {
    if (k.startsWith(`${serverId}:`)) conditionHeld.delete(k)
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
    // The durable log has to hear about it too, or the clear below is undone by
    // the next launch: a restart would rehydrate a repeat window from a
    // conversation the user ended, and the disk case would be six hours of
    // silence earned by switching the feature off. `stood-down` is written
    // rather than `resolved` precisely because it is not an all-clear — nothing
    // is posted anywhere, and the reader can tell the two apart.
    const at = Date.now()
    for (const a of announced.values()) {
      record(a.kind, 'stood-down', { serverId: a.serverId, serverName: a.serverName, at })
    }
    lastNotified.clear()
    lastNotifiedValue.clear()
    announced.clear()
    raiseTimes.clear()
    dampedUntil.clear()
    conditionHeld.clear()
    // The snoozes and acknowledgements too. They are decisions about a
    // conversation the user has just ended, and a snooze surviving the switch
    // would silence the first alert after it is turned back on.
    snoozedUntil.clear()
    acknowledged.clear()
  }
})

/**
 * One host's sample, as the alert path needs it.
 *
 * An object with every field REQUIRED rather than five positional numbers, and
 * that is a correctness decision rather than a style one. 1a4cfaa records the
 * bug: the disk predicate defaulted its "was this measured" argument, so the
 * guard could be lost by forgetting a parameter. An optional field here would
 * mean a caller that forgets `inode` silently disables inode alerting for its
 * whole path, with both sides compiling. Every field is required, and `null` is
 * how a caller says a thing could not be measured.
 */
export interface ResourceSample {
  cpu: number
  ram: number
  /** Null when df reported no filesystem at all. A failed probe yields a
   *  diskPct of 0, and 0 here would read as an empty disk and post an
   *  all-clear for a host that may well still be full. */
  disk: number | null
  /** Null when inode accounting is unavailable — busybox without `df -i`, or
   *  btrfs and zfs, which have no fixed inode table and honestly report none.
   *  Zero would be an empty filesystem. */
  inode: number | null
  /** One-minute load average PER CORE, or null when /proc/loadavg could not be
   *  read. Zero would be a perfectly idle machine. */
  load: number | null
}

// Inodes get their own line rather than sharing the configurable resource
// threshold, on the same argument disk uses: it is a different question with a
// different consequence. 85% of blocks is "getting full"; 85% of inodes on a
// host that makes small files is often an hour from unwritable, and the number
// is not one a person tunes alongside a CPU percentage.
export const INODE_DANGER = 85

/** Strictly above, exactly like isDiskCritical, so the two filesystem alerts
 *  cannot disagree about what "at the line" means. */
export function isInodeCritical(pct: number): boolean {
  return pct > INODE_DANGER
}

// Per CORE, so the number means the same thing on a 2-core VPS and a 64-core
// box. Two is the classic "there is a queue": one runnable thread per core is
// full utilisation, two is twice as much work as there is machine.
export const LOAD_DANGER = 2

/**
 * Called from the metrics hook and from the fleet sampler on each sample.
 *
 * Every `null` here means "not measured", and a null is neither raised nor
 * resolved nor read as healthy — the rule the whole of 19a is built on. There
 * is no branch that turns one into a zero on the way in.
 */
export function checkResourceAlerts(serverId: string, serverName: string, s: ResourceSample): void {
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
  const line = clearLine('cpu', resourceAlertThreshold)
  evaluate(serverId, serverName, 'cpu', s.cpu, resourceAlertThreshold, now, s.cpu >= line)
  evaluate(serverId, serverName, 'ram', s.ram, resourceAlertThreshold, now, s.ram >= line)
  // Fixed at DISK_DANGER rather than the configurable threshold: this is the
  // number the Fleet Monitor colours a bar red at and lists a host under, and
  // an alert that fired at a different number from the screen it sends you to
  // is worse than no alert. isDiskCritical is that number's only comparison.
  if (s.disk !== null) {
    evaluate(serverId, serverName, 'disk', s.disk, DISK_DANGER, now, isDiskCritical(s.disk))
  }
  if (s.inode !== null) {
    evaluate(serverId, serverName, 'inode', s.inode, INODE_DANGER, now, isInodeCritical(s.inode))
  }
  if (s.load !== null) {
    evaluate(serverId, serverName, 'load', s.load, LOAD_DANGER, now, s.load >= LOAD_DANGER)
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
  raiseTimes.clear()
  dampedUntil.clear()
  snoozedUntil.clear()
  acknowledged.clear()
  conditionHeld.clear()
  seenEvents.clear()
  failedUnits.clear()
  hydrated = true
  hydrating = null
  useAlerts.setState({ active: {} })
}
