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
