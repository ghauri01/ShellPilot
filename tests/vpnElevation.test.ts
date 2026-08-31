import { describe, it, expect, beforeEach, vi } from 'vitest'
import { EventEmitter } from 'node:events'
import { PassThrough } from 'node:stream'

// The elevation modules only touch the filesystem (does pkexec exist? is the
// OpenVPN service pipe there?) and child_process (launch the helper), so those
// two are the whole seam. Platform selection is driven by passing a platform
// to elevatorForPlatform rather than by writing to process.platform, so every
// platform's behaviour is exercised on whatever machine runs the suite.
const hoisted = vi.hoisted(() => ({
  files: new Set<string>(),
  existsCalls: 0,
  spawns: [] as { command: string; args: string[]; options: Record<string, unknown>; child: unknown }[],
  makeChild: null as null | (() => unknown)
}))

vi.mock('node:fs', () => {
  const existsSync = (p: unknown): boolean => {
    hoisted.existsCalls++
    return hoisted.files.has(String(p))
  }
  return { existsSync, default: { existsSync } }
})

vi.mock('node:child_process', () => {
  const spawn = (command: string, args: string[], options: Record<string, unknown>): unknown => {
    const child = hoisted.makeChild?.()
    hoisted.spawns.push({ command, args, options, child })
    return child
  }
  return { spawn, default: { spawn } }
})

import { elevatorForPlatform, elevationErrorCode, resetElevationProbeCache } from '../src/main/services/vpn/elevation/index'
import type { ElevationRequest } from '../src/main/services/vpn/elevation/index'
import { appleScriptQuote, buildOsascriptArgs, parseOsascriptFailure, posixQuote } from '../src/main/services/vpn/elevation/darwin'
import {
  buildRunAsScript,
  INTERACTIVE_SERVICE_PIPE,
  parseInteractiveServiceReply,
  powershellLiteral,
  powershellPath,
  quoteWindowsArg
} from '../src/main/services/vpn/elevation/win32'
import { TUN_DEVICE } from '../src/main/services/vpn/elevation/linux'

class FakeChild extends EventEmitter {
  static nextPid = 9000
  readonly pid = FakeChild.nextPid++
  readonly stdout = new PassThrough()
  readonly stderr = new PassThrough()
  readonly signals: string[] = []

  kill(signal?: NodeJS.Signals): boolean {
    this.signals.push(signal ?? 'SIGTERM')
    return true
  }

  exit(code: number | null): void {
    this.emit('exit', code, null)
    this.emit('close', code, null)
  }
}

hoisted.makeChild = () => new FakeChild()

interface SpawnRecord {
  command: string
  args: string[]
  options: Record<string, unknown>
  child: FakeChild
}

function lastSpawn(): SpawnRecord {
  const rec = hoisted.spawns[hoisted.spawns.length - 1]
  expect(rec).toBeDefined()
  return rec as SpawnRecord
}

// Lets the PassThrough deliver what a test wrote to stderr before the child is
// told to exit, so the classifier sees the same text a real run would.
const flush = async (times = 4): Promise<void> => {
  for (let i = 0; i < times; i++) await new Promise((resolve) => setImmediate(resolve))
}

const req = (over: Partial<ElevationRequest> = {}): ElevationRequest => ({
  reason: 'Connect the Office VPN',
  command: '/usr/sbin/openvpn',
  args: ['--config', '/run/p.ovpn'],
  ...over
})

const WINDOWS_POWERSHELL = powershellPath()

beforeEach(() => {
  hoisted.files.clear()
  hoisted.existsCalls = 0
  hoisted.spawns.length = 0
  resetElevationProbeCache()
})

describe('windows', () => {
  it('prefers the OpenVPN Interactive Service when its pipe is present', async () => {
    hoisted.files.add(INTERACTIVE_SERVICE_PIPE)
    hoisted.files.add(WINDOWS_POWERSHELL)

    const probe = await elevatorForPlatform('win32').probe()

    expect(probe.available).toBe(true)
    expect(probe.method).toBe('openvpn-interactive-service')
  })

  it('falls back to UAC when the service pipe is absent', async () => {
    hoisted.files.add(WINDOWS_POWERSHELL)

    const elevator = elevatorForPlatform('win32')
    const probe = await elevator.probe()

    expect(probe.available).toBe(true)
    expect(probe.method).toBe('uac')
    // E05: the user can make the prompt go away, and should be told how.
    expect(probe.reason).toMatch(/OpenVPN/)
    expect(elevator.method).toBe('uac')
  })

  it('launches powershell by absolute path, never through PATH', async () => {
    hoisted.files.add(WINDOWS_POWERSHELL)

    await elevatorForPlatform('win32').run(req({ command: 'C:\\Program Files\\OpenVPN\\bin\\openvpn.exe' }))

    const rec = lastSpawn()
    expect(rec.command).toBe(WINDOWS_POWERSHELL)
    expect(rec.command.startsWith('C:\\')).toBe(true)
    expect(rec.args.slice(0, 3)).toEqual(['-NoProfile', '-NonInteractive', '-Command'])
    expect(rec.args[3]).toContain('-Verb RunAs')
  })

  it('reads exit code 1223 as a declined prompt rather than a crash', async () => {
    hoisted.files.add(WINDOWS_POWERSHELL)

    const proc = await elevatorForPlatform('win32').run(req())
    const waiting = proc.wait()
    lastSpawn().child.exit(1223)

    // E04: no exit code to report because the command never ran, and no
    // restart — the user answered the question.
    expect(await waiting).toEqual({ code: null, declined: true })
  })

  it('leaves an ordinary non-zero exit alone', async () => {
    hoisted.files.add(WINDOWS_POWERSHELL)

    const proc = await elevatorForPlatform('win32').run(req())
    const waiting = proc.wait()
    lastSpawn().child.exit(3)

    expect(await waiting).toEqual({ code: 3, declined: false })
  })

  it('refuses an environment it cannot actually deliver', async () => {
    hoisted.files.add(WINDOWS_POWERSHELL)

    await expect(elevatorForPlatform('win32').run(req({ env: { SP_TOKEN: 'x' } }))).rejects.toMatchObject({
      code: 'unsupported'
    })
  })

  it('reports nothing available when powershell is missing', async () => {
    const probe = await elevatorForPlatform('win32').probe()
    expect(probe).toMatchObject({ available: false, method: 'none' })
    expect(probe.reason).toContain('powershell.exe')
  })

  it('parses the interactive service reply', () => {
    const ok = Buffer.from('0x00000000\nProcess ID\n4821', 'utf16le')
    expect(parseInteractiveServiceReply(ok)).toEqual({
      error: 0,
      label: 'Process ID',
      pid: 4821,
      message: '4821'
    })

    const failed = Buffer.from('0x00000005\nCreateProcess\nAccess is denied.', 'utf16le')
    expect(parseInteractiveServiceReply(failed)).toMatchObject({ error: 5, pid: null })
  })
})

describe('windows argument quoting', () => {
  const cases: [string, string][] = [
    ['plain', 'plain'],
    ['has space', '"has space"'],
    ['a"b', '"a\\"b"'],
    ['C:\\dir\\file.ovpn', 'C:\\dir\\file.ovpn'],
    ['C:\\my dir\\', '"C:\\my dir\\\\"'],
    ['', '""']
  ]
  for (const [input, expected] of cases) {
    it(`quotes ${JSON.stringify(input)}`, () => {
      expect(quoteWindowsArg(input)).toBe(expected)
    })
  }

  it('doubles the quote in a PowerShell literal', () => {
    expect(powershellLiteral("C:\\it's\\openvpn.exe")).toBe("'C:\\it''s\\openvpn.exe'")
  })

  it('catches the cancel exception so a decline has an exit code', () => {
    const script = buildRunAsScript(req({ command: 'C:\\OpenVPN\\openvpn.exe' }))
    expect(script).toContain('System.ComponentModel.Win32Exception')
    expect(script).toContain('exit $_.Exception.NativeErrorCode')
    expect(script).toContain('-Verb RunAs')
  })
})

describe('macos', () => {
  beforeEach(() => {
    hoisted.files.add('/usr/bin/osascript')
    hoisted.files.add(TUN_DEVICE)
  })

  it('builds exactly the osascript command, quoting spaces and quotes', () => {
    const args = buildOsascriptArgs({
      reason: 'Connect the Office VPN',
      command: '/Applications/My App/openvpn',
      args: ['--config', "/Users/a b/it's.ovpn"],
      cwd: '/Users/a b'
    })

    expect(args[0]).toBe('-e')
    expect(args[1]).toBe(
      `do shell script "cd '/Users/a b' && exec '/Applications/My App/openvpn' '--config' '/Users/a b/it'\\\\''s.ovpn'" with administrator privileges`
    )
  })

  it('keeps a newline inside the AppleScript literal', () => {
    const args = buildOsascriptArgs(req({ args: ['--config', 'a\nb'] }))
    expect(args[1]).not.toContain('\n')
    expect(args[1]).toContain('a\\nb')
  })

  it('reads AppleScript error -128 as a declined prompt', async () => {
    const proc = await elevatorForPlatform('darwin').run(req())
    const waiting = proc.wait()
    const rec = lastSpawn()
    rec.child.stderr.write('execution error: User canceled. (-128)\n')
    await flush()
    rec.child.exit(1)

    expect(await waiting).toEqual({ code: null, declined: true })
  })

  it('reports the command exit status carried in the AppleScript error', async () => {
    const proc = await elevatorForPlatform('darwin').run(req())
    const waiting = proc.wait()
    const rec = lastSpawn()
    rec.child.stderr.write('execution error: Options error: cannot open config (2)\n')
    await flush()
    rec.child.exit(1)

    expect(await waiting).toEqual({ code: 2, declined: false })
  })

  it('resolves cleanly on success', async () => {
    const proc = await elevatorForPlatform('darwin').run(req())
    const waiting = proc.wait()
    lastSpawn().child.exit(0)

    expect(await waiting).toEqual({ code: 0, declined: false })
  })

  it('classifies stderr directly', () => {
    expect(parseOsascriptFailure('… (-128)')).toEqual({ code: null, declined: true })
    expect(parseOsascriptFailure('User cancelled.')).toEqual({ code: null, declined: true })
    expect(parseOsascriptFailure('boom (7)')).toEqual({ code: 7, declined: false })
    expect(parseOsascriptFailure('nothing useful')).toEqual({ code: null, declined: false })
  })

  it('refuses an environment variable name it cannot quote', () => {
    expect(() => buildOsascriptArgs(req({ env: { 'X=;rm -rf /': 'y' } }))).toThrowError(
      /environment variable name/
    )
  })
})

describe('posix shell quoting', () => {
  // Table-driven because this is the injection boundary on macOS: everything
  // here ends up inside `do shell script`, which is /bin/sh.
  const cases: [string, string][] = [
    ['plain', "'plain'"],
    ['has space', "'has space'"],
    ["it's", "'it'\\''s'"],
    ['say "hi"', `'say "hi"'`],
    ['back\\slash', "'back\\slash'"],
    ['$(id)', "'$(id)'"],
    ['`id`', "'`id`'"],
    ['a; rm -rf /', "'a; rm -rf /'"],
    ['line\nbreak', "'line\nbreak'"],
    ['', "''"]
  ]
  for (const [input, expected] of cases) {
    it(`quotes ${JSON.stringify(input)}`, () => {
      expect(posixQuote(input)).toBe(expected)
    })
  }

  it('escapes a backslash and a quote for AppleScript', () => {
    expect(appleScriptQuote('a\\b"c')).toBe('"a\\\\b\\"c"')
  })
})

describe('linux', () => {
  it('chooses pkexec when it is installed', async () => {
    hoisted.files.add(TUN_DEVICE)
    hoisted.files.add('/usr/bin/pkexec')

    const elevator = elevatorForPlatform('linux')
    expect(await elevator.probe()).toMatchObject({ available: true, method: 'pkexec' })
    expect(elevator.method).toBe('pkexec')

    await elevator.run(req())
    const rec = lastSpawn()
    expect(rec.command).toBe('/usr/bin/pkexec')
    expect(rec.args).toEqual(['/usr/sbin/openvpn', '--config', '/run/p.ovpn'])
  })

  it('falls back to sudo with a graphical askpass', async () => {
    hoisted.files.add(TUN_DEVICE)
    hoisted.files.add('/usr/bin/sudo')
    hoisted.files.add('/usr/bin/ssh-askpass')

    const elevator = elevatorForPlatform('linux')
    const probe = await elevator.probe()
    expect(probe).toMatchObject({ available: true, method: 'sudo' })
    expect(probe.reason).toContain('/usr/bin/ssh-askpass')

    await elevator.run(req())
    const rec = lastSpawn()
    expect(rec.command).toBe('/usr/bin/sudo')
    expect(rec.args).toEqual(['-A', '--', '/usr/sbin/openvpn', '--config', '/run/p.ovpn'])
    expect((rec.options.env as Record<string, string>).SUDO_ASKPASS).toBe('/usr/bin/ssh-askpass')
  })

  it('reports why elevation is impossible when there is no helper', async () => {
    hoisted.files.add(TUN_DEVICE)

    const probe = await elevatorForPlatform('linux').probe()

    expect(probe.available).toBe(false)
    expect(probe.method).toBe('none')
    expect(probe.reason).toContain('pkexec')
    expect(probe.reason).toContain('WireGuard')
  })

  it('says sudo needs a password prompt when only sudo is installed', async () => {
    hoisted.files.add(TUN_DEVICE)
    hoisted.files.add('/usr/bin/sudo')

    const probe = await elevatorForPlatform('linux').probe()

    expect(probe.available).toBe(false)
    expect(probe.reason).toContain('askpass')
  })

  it('reads pkexec exit 126 as a dismissed dialog', async () => {
    hoisted.files.add(TUN_DEVICE)
    hoisted.files.add('/usr/bin/pkexec')

    const proc = await elevatorForPlatform('linux').run(req())
    const waiting = proc.wait()
    lastSpawn().child.exit(126)

    expect(await waiting).toEqual({ code: null, declined: true })
  })

  it('reads pkexec exit 127 as unsupported, not as a decline', async () => {
    hoisted.files.add(TUN_DEVICE)
    hoisted.files.add('/usr/bin/pkexec')

    const proc = await elevatorForPlatform('linux').run(req())
    const waiting = proc.wait()
    lastSpawn().child.exit(127)

    expect(await waiting).toEqual({ code: 127, declined: false })
    expect(elevationErrorCode('pkexec', 127)).toBe('unsupported')
  })

  it('reads a cancelled sudo askpass as a decline', async () => {
    hoisted.files.add(TUN_DEVICE)
    hoisted.files.add('/usr/bin/sudo')
    hoisted.files.add('/usr/bin/ssh-askpass')

    const proc = await elevatorForPlatform('linux').run(req())
    const waiting = proc.wait()
    const rec = lastSpawn()
    rec.child.stderr.write('sudo: no password was provided\nsudo: a password is required\n')
    await flush()
    rec.child.exit(1)

    expect(await waiting).toEqual({ code: null, declined: true })
  })

  it('leaves an ordinary sudo failure alone', async () => {
    hoisted.files.add(TUN_DEVICE)
    hoisted.files.add('/usr/bin/sudo')
    hoisted.files.add('/usr/bin/ssh-askpass')

    const proc = await elevatorForPlatform('linux').run(req())
    const waiting = proc.wait()
    const rec = lastSpawn()
    rec.child.stderr.write('Options error: unrecognized option\n')
    await flush()
    rec.child.exit(1)

    expect(await waiting).toEqual({ code: 1, declined: false })
  })

  it('names /dev/net/tun when the device is missing (E06)', async () => {
    hoisted.files.add('/usr/bin/pkexec')

    const attempt = elevatorForPlatform('linux').run(req())

    await expect(attempt).rejects.toMatchObject({ name: 'VpnError', code: 'permission-denied' })
    await expect(attempt).rejects.toThrowError(/\/dev\/net\/tun/)
    await expect(attempt).rejects.toThrowError(/userspace WireGuard/)
    expect(hoisted.spawns).toHaveLength(0)
  })
})

describe('dispatch and caching', () => {
  it('refuses platforms it has no route for', async () => {
    const elevator = elevatorForPlatform('freebsd')

    expect(elevator.method).toBe('none')
    expect(await elevator.probe()).toMatchObject({ available: false })
    await expect(elevator.run(req())).rejects.toMatchObject({ code: 'unsupported' })
  })

  it('caches the probe for the app run and resets on demand', async () => {
    hoisted.files.add(TUN_DEVICE)
    hoisted.files.add('/usr/bin/pkexec')

    await elevatorForPlatform('linux').probe()
    const afterFirst = hoisted.existsCalls
    await elevatorForPlatform('linux').probe()
    expect(hoisted.existsCalls).toBe(afterFirst)

    resetElevationProbeCache()
    await elevatorForPlatform('linux').probe()
    expect(hoisted.existsCalls).toBeGreaterThan(afterFirst)
  })

  it('maps helper exit codes to error codes', () => {
    expect(elevationErrorCode('uac', 1223)).toBe('elevation-declined')
    expect(elevationErrorCode('uac', 3)).toBeNull()
    expect(elevationErrorCode('pkexec', 126)).toBe('elevation-declined')
    expect(elevationErrorCode('pkexec', 127)).toBe('unsupported')
    expect(elevationErrorCode('pkexec', 0)).toBeNull()
    // sudo exits 1 for a failed password and for a failed command alike, so
    // its status alone is never read as a decline.
    expect(elevationErrorCode('sudo', 1)).toBeNull()
  })
})
