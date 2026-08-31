import { beforeEach, describe, expect, it, vi } from 'vitest'
import { EventEmitter } from 'node:events'
import { PassThrough } from 'node:stream'

// An OpenVPN config carries inline certificates and, on a profile with a
// passphrase-less key, the private key itself. Writing it to disk is a real
// cost — so where the OS lets an elevated process inherit a pipe, it should
// not be written at all.
//
// Only pkexec and sudo fork the command, so only Linux can do this. macOS
// hands the command to the security framework and Windows goes through
// ShellExecute; on both, a write would land nowhere. That is why the answer is
// a declared flag and a refusal, not a best-effort write: an engine sitting on
// an empty pipe reports nothing at all, which is far worse than being told to
// use a file.

const hoisted = vi.hoisted(() => ({
  files: new Set<string>(),
  spawns: [] as { command: string; args: string[]; options: Record<string, unknown>; child: FakeChild }[],
  make: null as null | (() => FakeChild)
}))

vi.mock('node:fs', () => {
  const existsSync = (p: unknown): boolean => hoisted.files.has(String(p))
  return { existsSync, default: { existsSync } }
})

vi.mock('node:child_process', () => {
  const spawn = (command: string, args: string[], options: Record<string, unknown>): unknown => {
    const child = hoisted.make?.() as FakeChild
    hoisted.spawns.push({ command, args, options, child })
    return child
  }
  return { spawn, default: { spawn } }
})

class FakeStdin extends PassThrough {
  written: string[] = []
  ended = false
  override end(chunk?: unknown): this {
    if (typeof chunk === 'string') this.written.push(chunk)
    this.ended = true
    return this
  }
}

class FakeChild extends EventEmitter {
  static nextPid = 7000
  readonly pid = FakeChild.nextPid++
  readonly stdin = new FakeStdin()
  readonly stdout = new PassThrough()
  readonly stderr = new PassThrough()
  kill(): boolean {
    return true
  }
}

const { elevatorForPlatform, resetElevationProbeCache } = await import(
  '../src/main/services/vpn/elevation/index'
)
const { TUN_DEVICE } = await import('../src/main/services/vpn/elevation/linux')

const CONFIG = 'client\nremote vpn.example.com 1194\n<ca>\nSECRET-MATERIAL\n</ca>\n'

const req = (over: Record<string, unknown> = {}): never =>
  ({
    reason: 'Start the office VPN',
    command: '/usr/sbin/openvpn',
    args: ['--config', '/dev/stdin'],
    ...over
  }) as never

beforeEach(() => {
  hoisted.files.clear()
  hoisted.spawns.length = 0
  hoisted.make = () => new FakeChild()
  resetElevationProbeCache()
})

describe('Linux carries stdin', () => {
  beforeEach(() => {
    hoisted.files.add('/usr/bin/pkexec')
    hoisted.files.add(TUN_DEVICE)
  })

  it('declares that it can', () => {
    expect(elevatorForPlatform('linux').carriesStdin).toBe(true)
  })

  it('opens a pipe and writes the payload, then closes it', async () => {
    await elevatorForPlatform('linux').run(req({ stdin: CONFIG }))

    const spawned = hoisted.spawns.at(-1)
    expect((spawned?.options.stdio as string[])[0]).toBe('pipe')
    expect(spawned?.child.stdin.written).toEqual([CONFIG])
    // openvpn reads its config to EOF, so a pipe left open is a hang rather
    // than a slow start.
    expect(spawned?.child.stdin.ended).toBe(true)
  })

  it('leaves stdin closed when there is no payload', async () => {
    await elevatorForPlatform('linux').run(req())
    expect((hoisted.spawns.at(-1)?.options.stdio as string[])[0]).toBe('ignore')
  })

  it('never puts the payload in argv', async () => {
    await elevatorForPlatform('linux').run(req({ stdin: CONFIG }))
    const argv = JSON.stringify(hoisted.spawns.at(-1)?.args)
    expect(argv).not.toContain('SECRET-MATERIAL')
  })

  it('does not fail the launch when the child dies before the write lands', async () => {
    const proc = await elevatorForPlatform('linux').run(req({ stdin: CONFIG }))
    const child = hoisted.spawns.at(-1)?.child as FakeChild
    // An EPIPE here is an ordinary race; the exit is what the caller is told
    // about.
    expect(() => child.stdin.emit('error', new Error('EPIPE'))).not.toThrow()
    expect(proc.pid).toBe(child.pid)
  })
})

describe('platforms that cannot carry it refuse rather than drop it', () => {
  it('macOS declares false and rejects a payload', async () => {
    hoisted.files.add('/usr/bin/osascript')
    const elevator = elevatorForPlatform('darwin')
    expect(elevator.carriesStdin).toBe(false)

    await expect(elevator.run(req({ stdin: CONFIG }))).rejects.toMatchObject({
      code: 'unsupported'
    })
    // Nothing was launched, so there is no process sitting on an empty pipe.
    expect(hoisted.spawns).toHaveLength(0)
  })

  it('macOS still launches normally without a payload', async () => {
    hoisted.files.add('/usr/bin/osascript')
    await elevatorForPlatform('darwin').run(req())
    expect(hoisted.spawns).toHaveLength(1)
  })

  it('Windows declares false and rejects a payload', async () => {
    hoisted.files.add('C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe')
    const elevator = elevatorForPlatform('win32')
    expect(elevator.carriesStdin).toBe(false)

    await expect(elevator.run(req({ stdin: CONFIG }))).rejects.toMatchObject({
      code: 'unsupported'
    })
    expect(hoisted.spawns).toHaveLength(0)
  })

  it('an unsupported platform declares false', () => {
    expect(elevatorForPlatform('freebsd').carriesStdin).toBe(false)
  })
})
