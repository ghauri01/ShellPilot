import type { VpnErrorCode } from '../../../../shared/vpn'
import { VpnError } from '../errors'
import { createDarwinElevator, resetDarwinProbe } from './darwin'
import { createLinuxElevator, resetLinuxProbe, PKEXEC_DISMISSED, PKEXEC_NOT_FOUND } from './linux'
import { createWin32Elevator, resetWin32Probe, ERROR_CANCELLED } from './win32'

// Asking for administrator rights, once, for the duration of one launch.
//
// Three rules shape everything here, and all three come from the plan (§6.2,
// §7 item 3):
//
//  1. Elevation is a per-launch permission, never an install. No setuid
//     binary, no launchd helper, no systemd unit, no setcap. Uninstalling
//     ShellPilot must leave nothing behind that can still become root.
//  2. Declining is a first-class outcome. A user who dismisses the prompt has
//     answered the question, so it surfaces as `elevation-declined` with a
//     "Try again" affordance, never as a crash and never as a restart loop.
//  3. This module deliberately has no secret parameter. The argv of an
//     elevated process is, if anything, more visible than an ordinary one
//     (`ps aux`, `Get-CimInstance Win32_Process`, and on macOS the whole
//     command line is inside osascript's own argv). Passwords, keys and OTPs
//     travel over the engine's control channel — OpenVPN's management socket,
//     netd's stdin — after the process is up, never through here.

export type ElevationMethod =
  | 'openvpn-interactive-service'
  | 'uac'
  | 'osascript'
  | 'pkexec'
  | 'sudo'
  | 'none'

export interface ElevationRequest {
  // What the user is being asked to approve, in their words. Shown in the OS
  // prompt where the OS allows a message.
  reason: string
  command: string
  args: string[]
  cwd?: string
  // Visible in the helper's argv on every platform that supports it at all, so
  // non-secret values only. Windows rejects this outright: ShellExecute-based
  // elevation cannot pass an environment to the elevated child, and dropping
  // it silently would be worse than saying so.
  env?: Record<string, string>
  // Written to the elevated command's stdin, which is then closed.
  //
  // This is the one channel here that can carry something sensitive, and only
  // on the routes where the elevated process is genuinely a child of ours —
  // `Elevator.carriesStdin` says which. It exists because the alternative for
  // an OpenVPN config (inline certificates and all) is a file on disk, and on
  // Linux `pkexec` can forward a pipe so there need not be one.
  //
  // An elevator that cannot carry it **rejects the request** rather than
  // dropping it. A config that silently never arrived would leave openvpn
  // waiting on an empty stdin, which is a far worse failure than being told up
  // front to use a file.
  stdin?: string
}

export interface ElevationExit {
  // The elevated command's exit status where we can know it, otherwise the
  // helper's. Null when the command never ran — a declined prompt has no exit
  // code to report, and inventing one would make a decline look like a crash.
  code: number | null
  declined: boolean
}

export interface ElevatedProcess {
  pid: number | null
  // Resolves with the exit code. Never rejects for a declined prompt — that is
  // a normal outcome, surfaced as elevation-declined.
  wait(): Promise<ElevationExit>
  kill(force?: boolean): Promise<void>
}

export interface ElevationProbe {
  available: boolean
  method: string
  // Why it is unavailable, or which route was chosen and what would improve
  // it. Written for the user, not for a log.
  reason?: string
}

export interface Elevator {
  readonly method: ElevationMethod
  // Cheap, cached: is elevation even possible here, and by what route?
  probe(): Promise<ElevationProbe>
  run(req: ElevationRequest): Promise<ElevatedProcess>
  // Whether `ElevationRequest.stdin` actually reaches the elevated command.
  //
  // Only true where the elevated process is a real child of ours. `pkexec` and
  // `sudo` fork it, so a pipe survives. `osascript` hands the command to the
  // macOS security framework, which starts it detached — nothing we write is
  // connected to it. `Start-Process -Verb RunAs` goes through ShellExecute,
  // which has no stdin to redirect.
  //
  // Declared rather than sniffed, and honoured by refusing the request when
  // false, because the failure mode of getting this wrong is an engine sitting
  // on an empty pipe with no error anywhere.
  readonly carriesStdin: boolean
}

export function elevatorForPlatform(platform: NodeJS.Platform = process.platform): Elevator {
  if (platform === 'win32') return createWin32Elevator()
  if (platform === 'darwin') return createDarwinElevator()
  if (platform === 'linux') return createLinuxElevator()
  return createUnsupportedElevator(platform)
}

// Probe results are cached for the app run: they answer "is pkexec installed",
// which does not change while ShellPilot is open, and a start button that
// stats the filesystem on every render is a waste. Tests need the caches gone
// between cases, so the reset is public.
export function resetElevationProbeCache(): void {
  resetWin32Probe()
  resetDarwinProbe()
  resetLinuxProbe()
}

// The helper's exit status, read as a ShellPilot error code.
//
// This is separate from `wait()` because `wait()` reports what happened and
// this reports what it means: 127 from pkexec is "polkit vanished between the
// probe and the launch", which is `unsupported`, not a failed connection.
// Returns null when the exit says nothing about elevation, so the caller keeps
// whatever code it already had rather than guessing.
export function elevationErrorCode(
  method: ElevationMethod,
  code: number | null
): VpnErrorCode | null {
  if (code === null || code === 0) return null
  switch (method) {
    case 'uac':
      return code === ERROR_CANCELLED ? 'elevation-declined' : null
    case 'pkexec':
      if (code === PKEXEC_DISMISSED) return 'elevation-declined'
      if (code === PKEXEC_NOT_FOUND) return 'unsupported'
      return null
    // sudo exits 1 both when authentication fails and when the command itself
    // fails, so its exit status alone cannot tell them apart. The Linux
    // elevator classifies a sudo decline from stderr instead.
    default:
      return null
  }
}

function createUnsupportedElevator(platform: NodeJS.Platform): Elevator {
  const probe: ElevationProbe = {
    available: false,
    method: 'none',
    reason: `ShellPilot cannot request administrator rights on ${platform}. Use a userspace WireGuard profile, which needs none.`
  }
  return {
    method: 'none',
    carriesStdin: false,
    probe: async () => probe,
    run: async () => {
      throw new VpnError('unsupported', probe.reason)
    }
  }
}
