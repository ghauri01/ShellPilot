/**
 * Starting with the machine, which is the difference between a monitor and a
 * thing you remember to open.
 *
 * Electron implements `setLoginItemSettings` on macOS and Windows and NOT on
 * Linux, where autostart is a `.desktop` file in `~/.config/autostart` whose
 * contents depend on the packaging format. Rather than write a file that is
 * wrong for three of the four ways this app can be installed, the capability
 * reports itself unsupported there and the UI says so instead of showing a
 * switch that silently does nothing -- the same rule the biometrics code
 * follows for Windows Hello.
 */
export interface AutoStartSettings {
  /** Launch when the user logs in. */
  openAtLogin: boolean
  /**
   * Launch without showing a window. macOS only -- Electron ignores it on
   * Windows, so the UI must not promise it there.
   *
   * This is the setting that makes autostart worth having: background checks
   * run from the app root, so a hidden launch is a fleet that is being watched
   * from login rather than from whenever somebody remembers to open the app.
   */
  openAsHidden: boolean
}

export interface AutoStartState extends AutoStartSettings {
  /** False on Linux. The UI shows the reason rather than an inert control. */
  supported: boolean
  /** Whether `openAsHidden` means anything on this platform. */
  hiddenSupported: boolean
  reason?: string
}

/** Whether Electron can register a login item at all on this platform. */
export function autoStartSupported(platform: NodeJS.Platform): boolean {
  return platform === 'darwin' || platform === 'win32'
}

/**
 * Whether a hidden launch means anything here.
 *
 * Electron accepts `openAsHidden` on Windows and does nothing with it, so a
 * switch there would be a promise the OS never keeps. macOS only.
 */
export function hiddenLaunchSupported(platform: NodeJS.Platform): boolean {
  return platform === 'darwin'
}

export const AUTOSTART_UNSUPPORTED_REASON =
  'Electron cannot register a login item on Linux. Add ShellPilot to your desktop environment\u2019s startup applications instead.'

/**
 * What to hand Electron, given what the user asked for and where they are.
 *
 * Separated from the IPC handler so the platform rules can be tested without a
 * running app: the failure worth catching is asking for a hidden launch on a
 * platform that ignores the flag and then REPORTING it back as set, which would
 * show the user a switch that stays on and does nothing.
 */
export function autoStartRequest(
  platform: NodeJS.Platform,
  wanted: AutoStartSettings
): AutoStartSettings {
  return {
    openAtLogin: wanted.openAtLogin === true,
    openAsHidden: hiddenLaunchSupported(platform) && wanted.openAsHidden === true
  }
}
