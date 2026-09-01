import { describe, it, expect } from 'vitest'
import { alertCoverage, alertCoverageText } from '../src/renderer/src/components/settings/alertCoverage'

// Found by running the feature against a real estate rather than by reading it.
// The switch was on, the sampler was paused on a locked vault and had never
// completed a pass, and this row said "Background checks are on, so alerts fire
// wherever you are in the app." The sampler's own line, a centimetre below,
// correctly said checking was paused. The screen contradicted itself and the
// reassuring half is the one a user is more likely to read.
describe('what the threshold row may claim', () => {
  it('claims full coverage only when the sampler is actually looping', () => {
    expect(alertCoverage(true, true)).toBe('running')
    expect(alertCoverageText(true, true)).toMatch(/wherever you are/)
  })

  it('does not claim coverage from the switch alone', () => {
    // The exact defect: enabled, not running. This must not read as covered.
    expect(alertCoverage(false, true)).toBe('requested-not-running')
    expect(alertCoverageText(false, true)).not.toMatch(/wherever you are/)
  })

  it('says plainly that it is on but not running, and points at the reason', () => {
    // Paired with the negative above, so this cannot pass by the text vanishing.
    const text = alertCoverageText(false, true)
    expect(text).toMatch(/switched on but not running/i)
    expect(text).toMatch(/see the reason below/i)
    expect(text).toMatch(/only sampled while its monitor is on screen/i)
  })

  it('treats unknown status as not running', () => {
    // Status is undefined until the first poll returns. Assuming coverage
    // during that window is the same lie, briefly.
    expect(alertCoverage(undefined, true)).toBe('requested-not-running')
  })

  it('explains foreground-only sampling when background checking is off', () => {
    expect(alertCoverage(false, false)).toBe('foreground-only')
    expect(alertCoverageText(false, false)).toMatch(/only fire while you are already looking/i)
  })

  it('never says "wherever you are" unless the sampler is running', () => {
    for (const enabled of [true, false]) {
      for (const running of [false, undefined]) {
        expect(alertCoverageText(running, enabled), `${running}/${enabled}`).not.toMatch(
          /wherever you are/
        )
      }
    }
  })
})
