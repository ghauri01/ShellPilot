import { describe, it, expect } from 'vitest'
import {
  intervalLabel,
  retentionOverrideNotice
} from '../src/renderer/src/components/settings/connectionRetention'

// "Keep authenticated connection" says how often a two-factor code is
// requested. Background checking makes that untrue for every watched server:
// the pool arms a connection's idle timer only when its reference count reaches
// zero, and a server being sampled never gets there. The behaviour is
// defensible; the silence was not, so what is pinned here is that the row says
// so — and that it only says so when it is actually true.

describe('the retention setting being overridden', () => {
  it('says nothing while background checking is off', () => {
    // A warning that is always on screen is furniture, and stops being read
    // by the time it matters.
    expect(retentionOverrideNotice(false, 120_000)).toBeNull()
  })

  it('warns as soon as background checking is on', () => {
    const notice = retentionOverrideNotice(true, 120_000)
    expect(notice).not.toBeNull()
    expect(notice).toMatch(/does not apply/i)
  })

  it('names two-factor codes, which is what the setting actually controls', () => {
    // Saying "the connection stays open" is true and useless: it does not tell
    // the reader that the thing they set this for has stopped happening.
    expect(retentionOverrideNotice(true, 120_000)).toMatch(/two-factor/i)
  })

  it('rules out Immediately by name, since that is the starkest contradiction', () => {
    // Someone who chose the most cautious option is the person most harmed by
    // this being vague, and most likely to assume a warning is about the
    // longer settings.
    expect(retentionOverrideNotice(true, 60_000)).toMatch(/Immediately/)
  })

  it('tells the reader the actual cadence rather than a vague "regularly"', () => {
    expect(retentionOverrideNotice(true, 300_000)).toMatch(/every 5 minutes/)
    expect(retentionOverrideNotice(true, 900_000)).toMatch(/every 15 minutes/)
  })

  it('reads correctly at a one-minute interval', () => {
    // "every 1 minutes" is the kind of thing that makes a reader trust the
    // rest of the sentence less.
    const notice = retentionOverrideNotice(true, 60_000)
    expect(notice).toMatch(/every minute\b/)
    expect(notice).not.toMatch(/every 1 minute/)
  })
})

describe('intervalLabel', () => {
  it('uses seconds below a minute, since the floor is 30s', () => {
    expect(intervalLabel(30_000)).toBe('30 seconds')
  })

  it('pluralises minutes correctly', () => {
    expect(intervalLabel(60_000)).toBe('minute')
    expect(intervalLabel(120_000)).toBe('2 minutes')
  })
})
