// The update contract, shared by main (updater.ts + updatePrefs.ts, the only
// things that produce these), the preload bridge, and the renderer (the
// Settings panel and the always-visible status-bar indicator).

// Only two channels, deliberately. `stable` maps to electron-updater's
// allowPrerelease=false, which resolves through GitHub's /releases/latest —
// and GitHub defines that as the newest release NOT marked prerelease. So a
// release with no prerelease component in its tag is a stable release by
// definition, with nothing to configure.
//
// `beta` maps to electron-updater's built-in `beta` channel identifier rather
// than a custom name. That is not cosmetic: GitHubProvider only offers a
// custom channel's own releases, so a user on a made-up channel name would
// never be offered a stable build again. `beta` cascades — a beta user is
// offered betas AND stables, whichever is newer.
export type UpdateChannel = 'stable' | 'beta'

// 0 means "only when the app starts". Anything else is additionally re-checked
// on that interval while the app stays open.
export type CheckIntervalHours = 0 | 6 | 24

export interface UpdatePrefs {
  // Master switch for every automatic check. Off means the app only ever
  // checks when the user presses the button.
  autoCheck: boolean
  checkIntervalHours: CheckIntervalHours
  // Download in the background as soon as one is found. Off means the user
  // presses Download themselves after being told.
  autoDownload: boolean
  // Apply a downloaded update on quit instead of waiting for an explicit
  // restart. Ignored where the platform cannot self-install at all.
  autoInstallOnQuit: boolean
  channel: UpdateChannel
  // ISO timestamp of the last completed check, successful or not.
  lastCheckedAt: string | null
}

export const DEFAULT_UPDATE_PREFS: UpdatePrefs = {
  autoCheck: true,
  checkIntervalHours: 6,
  autoDownload: true,
  autoInstallOnQuit: false,
  channel: 'stable',
  lastCheckedAt: null
}

// What this particular build can actually do, decided in main and sent to the
// renderer so the UI never has to re-derive platform rules of its own.
export interface UpdaterCapabilities {
  // False on macOS (ad-hoc signed, and the mac target is dmg-only while
  // Squirrel.Mac needs a zip) and on the Windows portable build (electron-
  // updater cannot replace a portable exe). Those platforms check and then
  // point at the release page.
  canAutoInstall: boolean
  isPortable: boolean
  // Null only when the renderer could not get an answer out of main and fell
  // back to app:version to keep the running version on screen. Consumers must
  // treat null as "unknown platform" and use generic wording, never as a
  // default platform — a fabricated value here would put macOS-specific
  // instructions in front of a Windows user.
  platform: NodeJS.Platform | null
  currentVersion: string
  // Channel implied by the running build's own version — 0.7.0-beta.1 is a
  // beta build. Used to warn when the selected channel would mean a downgrade.
  runningChannel: UpdateChannel
}

export type UpdaterStatus =
  | { state: 'idle' }
  | { state: 'checking' }
  | { state: 'available'; version: string; channel: UpdateChannel }
  | { state: 'not-available' }
  | { state: 'downloading'; percent: number; version?: string }
  | { state: 'downloaded'; version: string; channel: UpdateChannel }
  | { state: 'error'; message: string }
  // A newer version exists but will not be downloaded automatically, because
  // this platform cannot self-install (see UpdaterCapabilities.canAutoInstall).
  | { state: 'manual'; version: string; channel: UpdateChannel }

// The one place that decides whether the always-visible indicator should draw
// attention to itself. Shared so the status bar and the Settings panel can
// never disagree about whether an update is waiting.
export function isUpdatePending(status: UpdaterStatus): boolean {
  return status.state === 'available' || status.state === 'downloading' ||
    status.state === 'downloaded' || status.state === 'manual'
}

// Version -> channel, without pulling in semver: everything before the first
// '-' is the release part, and any prerelease component means a beta build.
export function channelOfVersion(version: string): UpdateChannel {
  return /-/.test(version) ? 'beta' : 'stable'
}
