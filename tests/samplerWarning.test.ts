import { describe, it, expect } from 'vitest'
import { samplerWarning } from '../src/renderer/src/store/fleetStatus'
import type { FleetSamplerStatus } from '../src/shared/fleet'

// Found by running the app against a real estate, not by reading it. Background
// checking was switched on, the vault had auto-locked, the sampler had been
// paused for an unknown length of time, and a failed systemd unit sat
// undelivered the whole while. `fleet.status()` was called from exactly one
// file — the Settings pane — so the only surface that said so was a screen an
// operator has no reason to open on a normal day.
//
// Silence from a monitoring tool is indistinguishable from good news, which is
// what makes this worse than it sounds: the status bar showed zero alerts, and
// that zero was true and meaningless at the same time.

const status = (over: Partial<FleetSamplerStatus> = {}): FleetSamplerStatus => ({
  running: true,
  targetCount: 2,
  ...over
})

describe('when the status bar warns that nothing is being checked', () => {
  it('says nothing while checking is actually running', () => {
    expect(samplerWarning(status(), true)).toBeNull()
  })

  it('warns when the vault has locked, which is the case that prompted this', () => {
    const w = samplerWarning(status({ running: false, idleReason: 'vault-locked' }), true)
    expect(w?.kind).toBe('vault-locked')
    // The tooltip has to say what STOPPED, not just name the state. "Vault
    // locked" alone does not tell anyone their alerting is off.
    expect(w?.detail).toMatch(/no alerts can be raised/i)
  })

  it('warns when it is on but nothing is scheduled', () => {
    expect(samplerWarning(status({ running: false }), true)?.kind).toBe('stalled')
  })

  it('warns when there is nothing to check', () => {
    const w = samplerWarning(status({ running: false, idleReason: 'no-targets', targetCount: 0 }), true)
    expect(w?.kind).toBe('no-targets')
  })

  it('stays silent when the user has switched checking off', () => {
    // A choice, not a fault. Warning about it would train people to ignore the
    // chip, and then it is not there for the vault-locked case either.
    expect(samplerWarning(status({ running: false, idleReason: 'disabled' }), false)).toBeNull()
    expect(samplerWarning(status({ running: false }), false)).toBeNull()
  })

  it('stays silent before the first poll has returned', () => {
    // Status is null until then. A chip that flashes a warning on every launch
    // is worse than no chip.
    expect(samplerWarning(null, true)).toBeNull()
  })

  it('lets an idle reason win over a running flag that contradicts it', () => {
    // The sampler never emits both: idleReason is only set on the paths that
    // return running:false. If a contradictory status ever arrives over IPC,
    // this resolves it toward warning on purpose. The premise of the whole
    // feature is that silence from a monitoring tool reads as good news, so a
    // false chip costs a glance and a false silence costs the incident.
    expect(samplerWarning(status({ running: true, idleReason: 'vault-locked' }), true)?.kind).toBe(
      'vault-locked'
    )
    // 'disabled' is the exception: it means the user switched it off, and that
    // is never worth a chip whatever else the status claims.
    expect(samplerWarning(status({ running: true, idleReason: 'disabled' }), true)).toBeNull()
  })

  it('says nothing on a clean running status', () => {
    expect(samplerWarning(status({ running: true }), true)).toBeNull()
  })

  it('gives every warning a label short enough for the bar', () => {
    for (const s of [
      status({ running: false, idleReason: 'vault-locked' }),
      status({ running: false, idleReason: 'no-targets' }),
      status({ running: false })
    ]) {
      const w = samplerWarning(s, true)
      expect(w).not.toBeNull()
      expect(w!.label.length).toBeLessThanOrEqual(20)
      expect(w!.detail).toMatch(/Click to open Monitoring settings/)
    }
  })
})
