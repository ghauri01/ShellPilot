import type { UpdateChannel } from '../../shared/updater'

// The channel -> electron-updater knobs mapping lives in its own module, with
// no electron and no electron-updater import, so the rules below can be
// asserted directly. updater.ts cannot: importing it constructs the real
// autoUpdater and touches app.getPath at module scope.

export interface ChannelConfig {
  allowPrerelease: boolean
  channel: string | null
  allowDowngrade: boolean
}

// `stable` deliberately leaves `channel` null. With allowPrerelease=false and
// no channel set, GitHubProvider resolves through GET /releases/latest, and
// GitHub defines that endpoint as the newest release not marked prerelease —
// so the provider never has to be told what "stable" means.
//
// `beta` sets allowDowngrade because coming back down is the normal path off
// this channel: a beta user offered the next stable sees 0.7.0-beta.3 ->
// 0.6.2, which is a semver downgrade and would be refused outright otherwise.
//
// The assignment ORDER in the caller matters and is not cosmetic. electron-
// updater's `channel` setter force-sets allowDowngrade = true as a side effect
// (AppUpdater.js:44), so anything that assigns channel after allowDowngrade
// silently re-enables downgrades on the stable channel. allowDowngrade must
// always be written explicitly, and always last.
export function channelConfig(channel: UpdateChannel): ChannelConfig {
  if (channel === 'beta') {
    return { allowPrerelease: true, channel: 'beta', allowDowngrade: true }
  }
  return { allowPrerelease: false, channel: null, allowDowngrade: false }
}
