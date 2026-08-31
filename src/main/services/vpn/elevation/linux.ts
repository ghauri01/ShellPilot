import { spawn } from 'node:child_process'
import { existsSync } from 'node:fs'
import type { ChildProcess } from 'node:child_process'
import { VpnError } from '../errors'
import type {
  ElevatedProcess,
  ElevationExit,
  ElevationProbe,
  ElevationRequest,
  Elevator
} from './index'

// Linux elevation is pkexec first, then sudo with a graphical askpass, then
// an honest "no".
//
// NOT setcap, and NOT a systemd unit. Both are installs: `setcap
// cap_net_admin+ep` on a bundled binary permanently grants that capability to
// a file the user can later be tricked into running, and a unit file survives
// uninstall. Elevation here is a permission for one launch and it expires with
// the process.

/** The tunnel device. Absent inside most containers and on some hardened
 *  kernels, and its absence is not something elevation can fix (E06). */
export const TUN_DEVICE = '/dev/net/tun'

/** pkexec: authorisation could not be obtained — the user dismissed the polkit
 *  dialog or is not permitted. A decline, not a failure. */
export const PKEXEC_DISMISSED = 126

/** pkexec: the program could not be found or executed. */
export const PKEXEC_NOT_FOUND = 127

// Fixed, absolute candidates followed by PATH. Unlike Windows, a PATH search
// is acceptable here — but the well-known locations are tried first so a
// prepended directory cannot shadow the real pkexec.
const PKEXEC_PATHS = ['/usr/bin/pkexec', '/bin/pkexec', '/usr/local/bin/pkexec']
const SUDO_PATHS = ['/usr/bin/sudo', '/bin/sudo', '/usr/local/bin/sudo']
const ENV_PATHS = ['/usr/bin/env', '/bin/env']

// Graphical password helpers, in the order a desktop is likely to have them.
// A terminal askpass is deliberately not on this list: ShellPilot has no
// terminal to prompt in, so a text prompt would hang the connect forever.
const ASKPASS_PATHS = [
  '/usr/bin/ssh-askpass',
  '/usr/bin/ksshaskpass',
  '/usr/bin/lxqt-openssh-askpass',
  '/usr/libexec/openssh/ssh-askpass',
  '/usr/lib/openssh/gnome-ssh-askpass',
  '/usr/lib/ssh/x11-ssh-askpass'
]

const STDERR_CAP = 8 * 1024

// Everything sudo says when it did not get a usable password. sudo exits 1 for
// both "authentication failed" and "the command failed", so the text is the
// only way to tell a decline from a real error.
const SUDO_DECLINED = /askpass|a (terminal|password) is required|Sorry, try again|authentication failure|incorrect password attempt/i

export interface Resolved {
  probe: ElevationProbe
  helper: string | null
  method: 'pkexec' | 'sudo' | 'none'
  askpass: string | null
}

let cached: Resolved | null = null

export function resetLinuxProbe(): void {
  cached = null
}

export function createLinuxElevator(): Elevator {
  return {
    // pkexec until a probe says otherwise: it is what a desktop Linux has, and
    // naming the fallback before probing would misreport the common case.
    get method(): 'pkexec' | 'sudo' | 'none' {
      return cached ? cached.method : 'pkexec'
    },
    // Both helpers fork the elevated command, so a pipe we open survives into
    // it. This is what lets an OpenVPN config reach `--config /dev/stdin`
    // instead of being written to a file first.
    carriesStdin: true,
    probe: async () => resolveRoute().probe,
    run: runLinux
  }
}

function firstExisting(paths: string[]): string | null {
  for (const p of paths) if (existsSync(p)) return p
  return null
}

/** SUDO_ASKPASS wins if the user set it — that is the documented way to point
 *  sudo at a helper, and second-guessing it would be rude. */
function resolveAskpass(): string | null {
  const configured = process.env.SUDO_ASKPASS
  if (configured && existsSync(configured)) return configured
  return firstExisting(ASKPASS_PATHS)
}

function resolveRoute(): Resolved {
  if (cached) return cached

  const pkexec = firstExisting(PKEXEC_PATHS)
  if (pkexec) {
    cached = {
      probe: { available: true, method: 'pkexec' },
      helper: pkexec,
      method: 'pkexec',
      askpass: null
    }
    return cached
  }

  const sudo = firstExisting(SUDO_PATHS)
  const askpass = sudo ? resolveAskpass() : null
  if (sudo && askpass) {
    cached = {
      probe: {
        available: true,
        method: 'sudo',
        reason: `polkit is not installed, so ShellPilot will ask for your password through ${askpass}.`
      },
      helper: sudo,
      method: 'sudo',
      askpass
    }
    return cached
  }

  cached = {
    probe: {
      available: false,
      method: 'none',
      reason: sudo
        ? 'sudo is installed but there is no graphical password prompt for it. Install polkit (which provides pkexec) or an askpass helper such as ssh-askpass, or point SUDO_ASKPASS at one. A userspace WireGuard profile needs no administrator rights at all.'
        : 'Neither pkexec nor sudo is installed, so ShellPilot cannot ask for administrator rights. Install polkit (which provides pkexec), or use a userspace WireGuard profile, which needs none.'
    },
    helper: null,
    method: 'none',
    askpass: null
  }
  return cached
}

/** The argv the helper is launched with. Exported so tests can assert that no
 *  value ever lands somewhere `ps` can read it. */
export function buildHelperArgs(r: Resolved, req: ElevationRequest): string[] {
  const args: string[] = []
  if (r.method === 'sudo') args.push('-A')
  const env = Object.entries(req.env ?? {})
  if (env.length > 0) {
    const envBin = firstExisting(ENV_PATHS)
    if (!envBin) {
      throw new VpnError('unsupported', 'env is missing, so the request cannot be run.')
    }
    args.push(envBin, ...env.map(([name, value]) => `${name}=${value}`))
  }
  // `--` so an option-looking command path is never read as an option of the
  // helper itself.
  if (r.method === 'sudo') args.push('--')
  args.push(req.command, ...req.args)
  return args
}

async function runLinux(req: ElevationRequest): Promise<ElevatedProcess> {
  // Checked on every run rather than cached with the probe: a container can be
  // given the device between one connect and the next, and the answer here is
  // about the machine's ability to carry a tunnel at all, not about polkit.
  if (!existsSync(TUN_DEVICE)) {
    throw new VpnError(
      'permission-denied',
      `${TUN_DEVICE} does not exist, so no tunnel interface can be created on this machine. Containers and some hardened kernels leave it out. A userspace WireGuard profile works without it.`
    )
  }

  const r = resolveRoute()
  if (!r.probe.available || !r.helper) throw new VpnError('unsupported', r.probe.reason)

  const env = { ...process.env }
  if (r.method === 'sudo' && r.askpass) env.SUDO_ASKPASS = r.askpass

  // pkexec and sudo both fork the elevated command, so a pipe reaches it. That
  // is what lets an OpenVPN config with inline certificates go to
  // `--config /dev/stdin` rather than being written to disk first.
  const wantsStdin = req.stdin !== undefined
  const child = spawn(r.helper, buildHelperArgs(r, req), {
    cwd: req.cwd,
    env,
    stdio: [wantsStdin ? 'pipe' : 'ignore', 'pipe', 'pipe']
  })

  if (wantsStdin) {
    // Closed straight after writing: openvpn reads the config until EOF, so a
    // pipe left open is a hang rather than a slow start.
    child.stdin?.on('error', () => {
      // The child exiting before the write lands is an ordinary race — the
      // exit itself is what the caller is told about, not an EPIPE here.
    })
    child.stdin?.end(req.stdin)
  }

  return adopt(child, r.method)
}

function adopt(child: ChildProcess, method: 'pkexec' | 'sudo' | 'none'): ElevatedProcess {
  let stderr = ''
  child.stderr?.on('data', (chunk: Buffer | string) => {
    if (stderr.length < STDERR_CAP) stderr += String(chunk)
  })

  let settled: Promise<ElevationExit> | null = null
  const wait = (): Promise<ElevationExit> => {
    if (settled) return settled
    settled = new Promise<ElevationExit>((resolve, reject) => {
      child.once('error', (cause) => {
        reject(new VpnError('unsupported', 'The elevation helper could not be run.', { cause }))
      })
      // 'close' so stderr is complete before a sudo exit is classified.
      child.once('close', (code: number | null) => {
        resolve(classifyExit(method, code, stderr))
      })
    })
    return settled
  }

  return {
    pid: child.pid ?? null,
    wait,
    // pkexec and sudo both forward a terminating signal to the command they
    // started, which is the only reason this reaches the privileged process at
    // all. A wedged engine still has to be stopped over its control channel.
    kill: async (force?: boolean) => {
      child.kill(force ? 'SIGKILL' : 'SIGTERM')
    }
  }
}

export function classifyExit(
  method: 'pkexec' | 'sudo' | 'none',
  code: number | null,
  stderr: string
): ElevationExit {
  if (code === null || code === 0) return { code, declined: false }
  if (method === 'pkexec' && code === PKEXEC_DISMISSED) return { code: null, declined: true }
  // 127 stays a plain non-zero exit here; elevationErrorCode() reads it as
  // `unsupported`, because "pkexec is gone" is not something the user declined.
  if (method === 'sudo' && SUDO_DECLINED.test(stderr)) return { code: null, declined: true }
  return { code, declined: false }
}
