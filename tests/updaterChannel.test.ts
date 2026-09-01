import { describe, it, expect } from 'vitest'
import { channelConfig } from '../src/main/services/updaterChannel'
import { channelOfVersion, isUpdatePending } from '../src/shared/updater'
import type { UpdaterStatus } from '../src/shared/updater'

describe('what each release channel asks electron-updater for', () => {
  it('never offers a prerelease to someone on stable', () => {
    // This is the highest-consequence assertion in the file. Stable is the
    // default, so it is where every user who never opened update settings
    // lives. If allowPrerelease ever flips true here, the entire install base
    // starts being offered beta builds on their next launch, silently, with
    // nothing in the UI saying anything changed.
    const cfg = channelConfig('stable')
    expect(cfg.allowPrerelease).toBe(false)

    // Leaving the channel null is what sends GitHubProvider through
    // GET /releases/latest, and GitHub itself defines that as the newest
    // release not marked prerelease. Naming any channel here instead would
    // switch the provider over to resolving a channel file, changing which
    // releases a stable user can see at all.
    expect(cfg.channel).toBeNull()
  })

  it('does not let a stable user be walked backwards onto an older build', () => {
    // electron-updater's `channel` setter force-sets allowDowngrade as a side
    // effect, so this value is easy to lose by accident further downstream.
    // Asserting it here pins the intent: stable only ever moves forwards.
    expect(channelConfig('stable').allowDowngrade).toBe(false)
  })

  it('puts a beta user on the literal built-in channel named beta', () => {
    const cfg = channelConfig('beta')
    expect(cfg.allowPrerelease).toBe(true)

    // The exact string is the point, and a check for merely "some channel is
    // set" would sail straight past the bug it guards. GitHubProvider only
    // ever offers a CUSTOM channel its own releases, so a made-up name like
    // 'insiders' would strand that user: they would be offered insider builds
    // and never a stable build again, with no way back short of reinstalling.
    // 'beta' is one of the built-in identifiers that cascades, which is what
    // makes a beta user eligible for betas and stables both.
    expect(cfg.channel).toBe('beta')
  })

  it('allows the downgrade that coming off beta actually looks like', () => {
    // Leaving beta is the normal path, and to semver it reads as going
    // backwards: 0.7.0-beta.3 -> 0.6.2. Without this the newer stable release
    // is refused outright and nothing is reported, so the user simply sits on
    // a stale beta wondering why updates stopped.
    expect(channelConfig('beta').allowDowngrade).toBe(true)
  })
})

describe('working out which channel a version came from', () => {
  it('reads a plain release version as stable', () => {
    for (const version of ['0.6.2', '1.0.0', '10.20.30']) {
      expect(channelOfVersion(version), version).toBe('stable')
    }
  })

  it('reads anything carrying a prerelease component as beta', () => {
    // Not just the ones we tag today: whatever prerelease word ends up in a
    // tag, the running build must still be recognised as a beta build, or the
    // downgrade warning in Settings never appears for the people who need it.
    for (const version of ['0.7.0-beta.1', '0.7.0-beta.3', '1.0.0-rc.1', '0.7.0-alpha.0']) {
      expect(channelOfVersion(version), version).toBe('beta')
    }
  })

  it('is not fooled by build metadata into calling a stable release a beta', () => {
    // '+' metadata is not a prerelease under semver, and a stable build that
    // reported itself as beta would show a downgrade warning to someone who
    // had never opted into anything.
    expect(channelOfVersion('1.0.0+20240101')).toBe('stable')
  })
})

describe('deciding whether the status bar indicator should draw attention', () => {
  // Every state the updater can report, and whether it counts as an update
  // waiting on the user. Typing this as a Record over the union's `state`
  // means adding a new state to UpdaterStatus does not typecheck until someone
  // has decided here what it means. That is the failure being guarded: a state
  // gets added, quietly falls through to "not pending", and a downloaded
  // update sits there with the indicator never lighting up.
  const pending: Record<UpdaterStatus['state'], boolean> = {
    idle: false,
    checking: false,
    available: true,
    'not-available': false,
    downloading: true,
    downloaded: true,
    error: false,
    manual: true
  }

  const example: Record<UpdaterStatus['state'], UpdaterStatus> = {
    idle: { state: 'idle' },
    checking: { state: 'checking' },
    available: { state: 'available', version: '0.7.0', channel: 'stable' },
    'not-available': { state: 'not-available' },
    downloading: { state: 'downloading', percent: 42, version: '0.7.0' },
    downloaded: { state: 'downloaded', version: '0.7.0', channel: 'stable' },
    error: { state: 'error', message: 'getaddrinfo ENOTFOUND github.com' },
    manual: { state: 'manual', version: '0.7.0', channel: 'beta' }
  }

  const states = Object.keys(pending) as UpdaterStatus['state'][]

  it('lights up for every state where something is genuinely waiting', () => {
    // `manual` is in here deliberately. On macOS and the Windows portable
    // build there is nothing to install automatically, but a newer version
    // still exists and the user still needs telling.
    for (const state of states.filter((s) => pending[s])) {
      expect(isUpdatePending(example[state]), state).toBe(true)
    }
  })

  it('stays quiet for the states where there is nothing for the user to do', () => {
    // An error in particular must not light the indicator up: a machine that
    // is offline would otherwise nag on every check interval forever.
    for (const state of states.filter((s) => !pending[s])) {
      expect(isUpdatePending(example[state]), state).toBe(false)
    }
  })
})
