import { create } from 'zustand'
import type { FleetSamplerStatus } from '../../../shared/fleet'

// The sampler's real state, app-wide.
//
// This exists because background checking could stop and nothing would say so
// anywhere a person was looking. The vault auto-locks, the sampler pauses,
// every alert the app can raise stops being raised — and the only surface that
// mentioned it was one line in Settings → Monitoring, a pane an operator has no
// reason to open on a normal day. Found by running it: the switch was on, the
// sampler had been paused for an unknown length of time, and a failed unit sat
// undelivered the whole while.
//
// That is the exact failure the monitor exists to prevent, reintroduced at the
// point where it costs the most: silence from a monitoring tool is indis-
// tinguishable from good news.

interface FleetStatusState {
  status: FleetSamplerStatus | null
  setStatus: (s: FleetSamplerStatus | null) => void
}

export const useFleetStatus = create<FleetStatusState>((set) => ({
  status: null,
  setStatus: (status) => set({ status })
}))

export type SamplerWarningKind = 'vault-locked' | 'no-targets' | 'stalled'

export interface SamplerWarning {
  kind: SamplerWarningKind
  /** Status-bar chip label. Short enough not to crowd the bar. */
  label: string
  /** Tooltip. Says what has stopped, not just what the state is called. */
  detail: string
}

const WARNINGS: Record<SamplerWarningKind, Omit<SamplerWarning, 'kind'>> = {
  'vault-locked': {
    label: 'Checks paused',
    detail:
      'Background checking is paused because the vault is locked, so no alerts can be raised. ' +
      'Unlock the vault to resume.\n\nClick to open Monitoring settings.'
  },
  'no-targets': {
    label: 'Nothing checked',
    detail:
      'Background checking is on, but this workspace has no servers that can be sampled, ' +
      'so no alerts can be raised.\n\nClick to open Monitoring settings.'
  },
  stalled: {
    label: 'Checks stopped',
    detail:
      'Background checking is switched on but nothing is scheduled, so no alerts can be raised. ' +
      'Turn it off and on again to restart it.\n\nClick to open Monitoring settings.'
  }
}

/**
 * Whether the status bar should be warning, and about what.
 *
 * Pure so the rule can be tested without a DOM — and the rule is the whole
 * feature, so it is the part that has to be right.
 *
 * Two silences are deliberate. Background checking switched OFF is a choice,
 * not a fault, and warning about it would train people to ignore the chip.
 * Unknown status is also silent: `status` is null until the first poll returns,
 * and a chip that flashes a warning on every launch is worse than no chip.
 */
export function samplerWarning(
  status: FleetSamplerStatus | null,
  enabled: boolean
): SamplerWarning | null {
  if (!enabled || !status) return null
  if (status.idleReason === 'disabled') return null
  if (status.idleReason === 'vault-locked') return { kind: 'vault-locked', ...WARNINGS['vault-locked'] }
  if (status.idleReason === 'no-targets') return { kind: 'no-targets', ...WARNINGS['no-targets'] }
  // Enabled, targets present, vault open, and still not looping.
  if (!status.running) return { kind: 'stalled', ...WARNINGS.stalled }
  return null
}
