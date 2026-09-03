import type { StoreAlertKind } from '../../../../shared/webhook'

// What the alert-threshold row is allowed to claim about coverage.
//
// This exists because the row got it wrong in the way that matters. It branched
// on `fleetSamplingEnabled` — the switch position — and said "Background checks
// are on, so alerts fire wherever you are in the app" while the sampler was
// paused on a locked vault and had never completed a single pass. A centimetre
// below, the sampler's own line correctly said checking was paused. The screen
// contradicted itself, and the half a user is more likely to read was the
// reassuring half.
//
// The rule the three cases encode: a settings screen may describe a capability
// only from whether it is running, never from the setting that requests it.
// "Switched on" and "working" are different facts and the gap between them is
// exactly where someone concludes they are covered when they are not.

export type AlertCoverage = 'running' | 'requested-not-running' | 'foreground-only'

export function alertCoverage(
  /** Whether the sampler is actually looping. Null while status is unknown. */
  running: boolean | undefined,
  /** Whether the user has asked for background checking. */
  enabled: boolean
): AlertCoverage {
  if (running) return 'running'
  // Enabled but not looping: paused on a locked vault, no targets, or stalled.
  // The sampler's own line states which; this row must not paper over it.
  if (enabled) return 'requested-not-running'
  return 'foreground-only'
}

const COPY: Record<AlertCoverage, string> = {
  running: 'Background checks are running, so alerts fire wherever you are in the app.',
  'requested-not-running':
    'Background checks are switched on but not running right now — see the reason below. ' +
    'Until they are, a host is only sampled while its monitor is on screen.',
  'foreground-only':
    'Without background checks below, a host is only sampled while its monitor is on screen — ' +
    'so an alert can only fire while you are already looking at it.'
}

export function alertCoverageText(running: boolean | undefined, enabled: boolean): string {
  return COPY[alertCoverage(running, enabled)]
}

// ---------------------------------------------------------------------------
// Coverage is per KIND, because the kinds are not produced by the same thing.
//
// The sentence above describes the fleet sampler, and for a long time that was
// all there was to describe. Item 19b added four kinds and only ONE of them —
// `host-unreachable` — rides the sampler. Rendering the sampler's sentence over
// a panel that lists all ten claimed coverage the other four do not have, which
// is precisely the shape this file was written to prevent, one level up.
//
// Where each signal actually comes from, checked against the code that emits
// it (FleetWatcher.tsx, which mounts all of them at the app root):
//
//   sampler         cpu, ram, disk, inode, load, host-unreachable.
//                   fleet.onSample, or the foreground monitor's own 2s poll
//                   when a card is on screen. The three-state sentence above
//                   is exactly right for these.
//   app-root        job-failed rides jobs.onProgress, tunnel-down a ten-second
//                   tunnel.list() poll. Both are subscribed at the app root and
//                   neither reads fleetSamplingEnabled, so both work whether or
//                   not background checking is on — better coverage than the
//                   sampler sentence claims, and still not the same claim.
//   read-on-demand  db-alarm and db-watch exist only because `db:ops` ran, and
//                   `db:ops` runs when a person opens the Databases page and
//                   reads it. Nothing produces them in the background at all.
//                   This is the one that must never be described as "alerts
//                   fire wherever you are in the app".
// ---------------------------------------------------------------------------

export type AlertCoverageSource = 'sampler' | 'app-root' | 'read-on-demand'

/** A Record rather than a lookup with a default, so a kind added to
 *  StoreAlertKind is a type error here instead of silently inheriting whatever
 *  claim the sampler happens to be making. */
export const COVERAGE_SOURCE: Record<StoreAlertKind, AlertCoverageSource> = {
  cpu: 'sampler',
  ram: 'sampler',
  disk: 'sampler',
  inode: 'sampler',
  load: 'sampler',
  'host-unreachable': 'sampler',
  'job-failed': 'app-root',
  'tunnel-down': 'app-root',
  'db-alarm': 'read-on-demand',
  'db-watch': 'read-on-demand'
}

const KINDS_BY_SOURCE = (src: AlertCoverageSource): StoreAlertKind[] =>
  (Object.keys(COVERAGE_SOURCE) as StoreAlertKind[]).filter((k) => COVERAGE_SOURCE[k] === src)

const NON_SAMPLER_COPY: Record<Exclude<AlertCoverageSource, 'sampler'>, string> = {
  'app-root':
    'Job failures and tunnels are watched from the moment the app starts, whether or not ' +
    'background checks are on: a job reports its own steps, and tunnels are polled every ten ' +
    'seconds.',
  'read-on-demand':
    'Database verdicts are the exception, and it is not a small one: they exist only because ' +
    'somebody opened the Databases page and read it. Nothing produces them in the background, ' +
    'so a database that goes into alarm overnight is not noticed until it is next read.'
}

/** The sentences a screen listing every kind has to show, in the order they
 *  should be read. The first is the sampler's, unchanged; the rest say which
 *  kinds it does not speak for. */
export function alertCoverageLines(
  running: boolean | undefined,
  enabled: boolean
): { source: AlertCoverageSource; kinds: StoreAlertKind[]; text: string }[] {
  return [
    { source: 'sampler', kinds: KINDS_BY_SOURCE('sampler'), text: alertCoverageText(running, enabled) },
    { source: 'app-root', kinds: KINDS_BY_SOURCE('app-root'), text: NON_SAMPLER_COPY['app-root'] },
    {
      source: 'read-on-demand',
      kinds: KINDS_BY_SOURCE('read-on-demand'),
      text: NON_SAMPLER_COPY['read-on-demand']
    }
  ]
}
