import { spawn } from 'node:child_process'
import { existsSync } from 'node:fs'
import net from 'node:net'
import { basename } from 'node:path'
import type { ChildProcess } from 'node:child_process'
import { VpnError } from '../errors'
import type {
  ElevatedProcess,
  ElevationExit,
  ElevationProbe,
  ElevationRequest,
  Elevator
} from './index'

// Windows has two routes to a privileged tunnel, and they are not equal.
//
//  1. The OpenVPN Interactive Service. Installed by the standard OpenVPN MSI,
//     it already runs as SYSTEM and launches openvpn on behalf of an ordinary
//     user over a named pipe. No UAC prompt at all. This is what OpenVPN-GUI
//     itself uses, so it is the supported path rather than a clever trick.
//  2. Start-Process -Verb RunAs. One UAC prompt per connect, every connect.
//
// Prefer (1), fall back to (2), and tell the user that installing the MSI
// removes the prompt (E05).
//
// There is no PATH search anywhere in this file. PATH and CWD lookup on
// Windows is the textbook binary-hijack primitive, and an elevated hijack is
// the worst kind: every executable named here is an absolute path.

export const INTERACTIVE_SERVICE_PIPE = '\\\\.\\pipe\\openvpn\\service'

/** ERROR_CANCELLED. What ShellExecute reports when the user dismisses the UAC
 *  prompt, and what the launcher script below re-raises as its own exit code.
 *  A decline is an answer, not a crash: no restart, no backoff, offer "Try
 *  again" (E04). */
export const ERROR_CANCELLED = 1223

// The service answers with one short message; anything larger is not a reply
// we understand.
const REPLY_CAP = 8 * 1024
const PIPE_TIMEOUT_MS = 5_000

// Liveness polling for a process the service started for us. It is not our
// child, so there is no 'exit' event to wait on.
const PID_POLL_MS = 1_000

let cached: ElevationProbe | null = null

export function resetWin32Probe(): void {
  cached = null
}

/** Absolute path to powershell.exe. Resolved from %SystemRoot% rather than
 *  PATH — see the note at the top of the file. */
export function powershellPath(): string {
  const root = process.env.SystemRoot || 'C:\\Windows'
  return `${root}\\System32\\WindowsPowerShell\\v1.0\\powershell.exe`
}

/** Quote one argument the way CommandLineToArgvW will unquote it.
 *
 *  Start-Process takes the whole command line as a single string, so each
 *  argument is quoted here instead of being handed to PowerShell as an array —
 *  PowerShell's own array joining quotes inconsistently between versions, and
 *  "inconsistently" on an elevated command line means an injection. */
export function quoteWindowsArg(value: string): string {
  if (value.length > 0 && !/[\s"]/.test(value)) return value
  let out = '"'
  let slashes = 0
  for (const ch of value) {
    if (ch === '\\') {
      slashes++
      continue
    }
    if (ch === '"') {
      // Every backslash run immediately before a quote is doubled, then the
      // quote itself is escaped.
      out += '\\'.repeat(slashes * 2 + 1) + '"'
      slashes = 0
      continue
    }
    out += '\\'.repeat(slashes) + ch
    slashes = 0
  }
  return `${out}${'\\'.repeat(slashes * 2)}"`
}

/** PowerShell single-quoted literal: the only metacharacter inside one is the
 *  quote, which doubles. */
export function powershellLiteral(value: string): string {
  return `'${value.split("'").join("''")}'`
}

/** The launcher script.
 *
 *  It exists to turn a dismissed UAC prompt into an exit code we can read.
 *  Start-Process throws a Win32Exception on cancel, whose NativeErrorCode is
 *  ERROR_CANCELLED; without the catch, PowerShell would exit 1 and a decline
 *  would be indistinguishable from the engine failing to start. */
export function buildRunAsScript(req: ElevationRequest): string {
  const start = [
    'Start-Process',
    '-FilePath',
    powershellLiteral(req.command),
    '-Verb',
    'RunAs',
    '-PassThru',
    '-WindowStyle',
    'Hidden'
  ]
  if (req.args.length > 0) {
    start.push('-ArgumentList', powershellLiteral(req.args.map(quoteWindowsArg).join(' ')))
  }
  if (req.cwd) start.push('-WorkingDirectory', powershellLiteral(req.cwd))
  return [
    "$ErrorActionPreference='Stop'",
    `try { $p = ${start.join(' ')} } catch [System.ComponentModel.Win32Exception] { exit $_.Exception.NativeErrorCode }`,
    '$p.WaitForExit()',
    'exit $p.ExitCode'
  ].join('; ')
}

/** The interactive service's request message: three UTF-16LE, NUL-terminated
 *  strings — working directory, openvpn options, stdin. */
export function encodeInteractiveServiceMessage(
  workingDir: string,
  options: string,
  stdin: string
): Buffer {
  return Buffer.from(`${workingDir}\0${options}\0${stdin}\0`, 'utf16le')
}

export interface InteractiveServiceReply {
  // 0 on success.
  error: number
  // "Process ID" on success, otherwise the failing function's name.
  label: string
  pid: number | null
  message: string
}

/** Parse the service's reply: a UTF-16LE three-line string, `0x%08x\n<label>\n
 *  <detail>`, where the detail is the new process id when the error is 0. */
export function parseInteractiveServiceReply(buf: Buffer): InteractiveServiceReply | null {
  const text = buf.toString('utf16le').replace(/\0+$/, '')
  const [head, label = '', detail = ''] = text.split('\n')
  if (head === undefined) return null
  const error = Number.parseInt(head.trim(), 16)
  if (!Number.isFinite(error)) return null
  const pid = error === 0 ? Number.parseInt(detail.trim(), 10) : Number.NaN
  return {
    error,
    label: label.trim(),
    pid: Number.isFinite(pid) && pid > 0 ? pid : null,
    message: detail.trim()
  }
}

export function createWin32Elevator(): Elevator {
  return {
    // Which route this is depends on whether the MSI is installed, so the
    // method follows the probe once one has run and names the fallback before
    // that.
    get method(): 'openvpn-interactive-service' | 'uac' | 'none' {
      if (!cached) return 'uac'
      return cached.method as 'openvpn-interactive-service' | 'uac' | 'none'
    },
    // ShellExecute (Start-Process -Verb RunAs) has no stdin to redirect, and
    // the Interactive Service's message does carry a stdin field but the
    // service, not us, decides what runs — so neither route can promise it.
    carriesStdin: false,
    probe: probeWin32,
    run: runWin32
  }
}

async function probeWin32(): Promise<ElevationProbe> {
  if (cached) return cached
  if (existsSync(INTERACTIVE_SERVICE_PIPE)) {
    cached = {
      available: true,
      method: 'openvpn-interactive-service',
      reason: 'The OpenVPN Interactive Service is running, so OpenVPN can start without a prompt.'
    }
  } else if (existsSync(powershellPath())) {
    cached = {
      available: true,
      method: 'uac',
      reason:
        'Windows will ask for permission each time this connects. Installing OpenVPN from its official installer adds a service that removes the prompt.'
    }
  } else {
    cached = {
      available: false,
      method: 'none',
      reason: `${powershellPath()} is missing, so ShellPilot cannot ask Windows for administrator rights.`
    }
  }
  return cached
}

async function runWin32(req: ElevationRequest): Promise<ElevatedProcess> {
  const probe = await probeWin32()
  if (!probe.available) throw new VpnError('unsupported', probe.reason)

  // ShellExecute starts the elevated process from the AppInfo service rather
  // than forking this one, so it inherits nothing we set here. Silently
  // dropping the caller's environment would be worse than refusing it.
  if (req.env && Object.keys(req.env).length > 0) {
    throw new VpnError(
      'unsupported',
      'Windows cannot pass environment variables to a program started with administrator rights.'
    )
  }

  if (probe.method === 'openvpn-interactive-service' && isOpenVpnCommand(req.command)) {
    const viaService = await tryInteractiveService(req)
    // A refusal from the service is expected rather than exceptional — it
    // validates the options itself and rejects anything outside its own config
    // directories — so fall through to UAC exactly as OpenVPN-GUI does.
    if (viaService) return viaService
  }

  return runViaUac(req)
}

function isOpenVpnCommand(command: string): boolean {
  const name = basename(command).toLowerCase()
  return name === 'openvpn.exe' || name === 'openvpn'
}

function runViaUac(req: ElevationRequest): ElevatedProcess {
  if (req.stdin !== undefined) {
    // Refused, not dropped. This route starts the elevated command detached
    // from us, so a write here would go nowhere and the engine would sit on an
    // empty pipe with no error anywhere — much worse than being told to use a
    // file. See `Elevator.carriesStdin`.
    throw new VpnError(
      'unsupported',
      'Administrator elevation on this platform cannot pass data on standard input.'
    )
  }

  const child = spawn(
    powershellPath(),
    ['-NoProfile', '-NonInteractive', '-Command', buildRunAsScript(req)],
    { stdio: ['ignore', 'pipe', 'pipe'], windowsHide: true }
  )
  return adoptLauncher(child)
}

function adoptLauncher(child: ChildProcess): ElevatedProcess {
  let settled: Promise<ElevationExit> | null = null
  const wait = (): Promise<ElevationExit> => {
    if (settled) return settled
    settled = new Promise<ElevationExit>((resolve, reject) => {
      child.once('error', (cause) => {
        reject(new VpnError('unsupported', `${powershellPath()} could not be run.`, { cause }))
      })
      child.once('close', (code: number | null) => {
        if (code === ERROR_CANCELLED) return resolve({ code: null, declined: true })
        resolve({ code, declined: false })
      })
    })
    return settled
  }

  return {
    // The launcher's pid, not the elevated process's: the elevated process is
    // started by the AppInfo service and is not in our process tree.
    pid: child.pid ?? null,
    wait,
    kill: async (force?: boolean) => {
      await taskkill(child.pid ?? null, force ?? false)
    }
  }
}

async function tryInteractiveService(req: ElevationRequest): Promise<ElevatedProcess | null> {
  // The service always runs the openvpn.exe from its own installation and
  // takes only the option string, so req.command selects the route and is not
  // itself executed. stdin is empty by design: this module never carries a
  // secret (see index.ts).
  const message = encodeInteractiveServiceMessage(
    req.cwd ?? '',
    req.args.map(quoteWindowsArg).join(' '),
    ''
  )
  const reply = await exchange(message)
  if (!reply) return null
  const parsed = parseInteractiveServiceReply(reply)
  if (!parsed || parsed.error !== 0 || parsed.pid === null) return null
  return adoptForeignPid(parsed.pid)
}

function exchange(message: Buffer): Promise<Buffer | null> {
  return new Promise((resolve) => {
    const socket = net.createConnection({ path: INTERACTIVE_SERVICE_PIPE })
    const chunks: Buffer[] = []
    let size = 0
    let done = false
    const finish = (value: Buffer | null): void => {
      if (done) return
      done = true
      clearTimeout(timer)
      socket.destroy()
      resolve(value)
    }
    const timer = setTimeout(() => finish(null), PIPE_TIMEOUT_MS)
    socket.on('error', () => finish(null))
    socket.on('connect', () => socket.write(message))
    socket.on('data', (chunk: Buffer) => {
      chunks.push(chunk)
      size += chunk.length
      // One write from the service is one message; anything past the cap is
      // not a reply we know how to read.
      finish(Buffer.concat(chunks, Math.min(size, REPLY_CAP)))
    })
    socket.on('close', () => finish(chunks.length > 0 ? Buffer.concat(chunks) : null))
  })
}

// A process the service started for us. It is not our child and it runs as
// SYSTEM, so all we can observe is whether the pid is still there, and all we
// can report on exit is that it ended. The exit code is genuinely unavailable
// through this route — the service's reply carries a pid and nothing else.
function adoptForeignPid(pid: number): ElevatedProcess {
  let stopped = false
  let settled: Promise<ElevationExit> | null = null
  const wait = (): Promise<ElevationExit> => {
    if (settled) return settled
    settled = new Promise<ElevationExit>((resolve) => {
      const tick = (): void => {
        if (stopped || !pidAlive(pid)) return resolve({ code: null, declined: false })
        setTimeout(tick, PID_POLL_MS).unref()
      }
      tick()
    })
    return settled
  }
  return {
    pid,
    wait,
    kill: async (force?: boolean) => {
      stopped = true
      await taskkill(pid, force ?? false)
    }
  }
}

function pidAlive(pid: number): boolean {
  try {
    process.kill(pid, 0)
    return true
  } catch (e) {
    // EPERM means the process exists and we are not allowed to signal it,
    // which is the normal answer for something running as SYSTEM.
    return (e as NodeJS.ErrnoException).code === 'EPERM'
  }
}

// Windows has no SIGTERM for a non-console child, and an unelevated taskkill
// cannot touch a SYSTEM process, so this is best-effort: the engine driver
// stops the tunnel over its control channel (OpenVPN's management interface)
// and this only cleans up the launcher.
function taskkill(pid: number | null, force: boolean): Promise<void> {
  if (pid === null) return Promise.resolve()
  const root = process.env.SystemRoot || 'C:\\Windows'
  const args = ['/PID', String(pid), '/T']
  if (force) args.push('/F')
  return new Promise((resolve) => {
    const child = spawn(`${root}\\System32\\taskkill.exe`, args, { stdio: 'ignore' })
    child.once('error', () => resolve())
    child.once('close', () => resolve())
  })
}
