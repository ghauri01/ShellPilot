import { describe, it, expect, beforeEach, afterEach } from 'vitest'
import { existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { Supervisor, identityMatches, parseDarwinPs, parseWindowsProcess } from '../src/main/services/vpn/supervisor'
import type { VpnPidRecord } from '../src/main/services/vpn/supervisor'

// Reaping is the one operation in this layer that signals a process nobody in
// this app started, so every test here is really the same question: did it
// prove whose process that is before it killed it?

const EXE = '/opt/shellpilot/resources/bin/shellpilot-netd'
const DAYS = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat']
const MONTHS = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec']

/** The `lstart` column of `ps`, which is where the start time comes from on
 *  macOS. Whole seconds, always five whitespace-separated fields. */
function lstart(d: Date): string {
  const pad = (n: number): string => String(n).padStart(2, '0')
  return `${DAYS[d.getDay()]} ${MONTHS[d.getMonth()]} ${pad(d.getDate())} ${pad(d.getHours())}:${pad(
    d.getMinutes()
  )}:${pad(d.getSeconds())} ${d.getFullYear()}`
}

let root: string
let signals: [number, number | NodeJS.Signals][]
let alive: Set<number>
let probes: string[]

const terminating = (): [number, number | NodeJS.Signals][] => signals.filter(([, s]) => s !== 0)

function writeRun(runId: string, record: Partial<VpnPidRecord>): void {
  mkdirSync(join(root, runId), { recursive: true })
  const full: VpnPidRecord = {
    pid: 1234,
    startedAtIso: new Date().toISOString(),
    exePath: EXE,
    kind: 'wireguard',
    profileId: 'profile-1',
    runId,
    runDir: join(root, runId),
    ...record
  }
  writeFileSync(join(root, `${runId}.pid`), JSON.stringify(full))
}

function makeSupervisor(probe: (command: string, args: string[]) => string): Supervisor {
  return new Supervisor({
    runRoot: root,
    platform: 'darwin',
    reapTermGraceMs: 50,
    kill: (pid, signal) => {
      signals.push([pid, signal])
      if (signal === 0 && !alive.has(pid)) throw new Error('ESRCH')
      // A process that honours SIGTERM stops being alive, so the reaper never
      // needs to escalate.
      if (signal === 'SIGTERM' || signal === 'SIGKILL') alive.delete(pid)
    },
    runProbe: async (command, args) => {
      probes.push(command)
      return probe(command, args)
    }
  })
}

beforeEach(() => {
  root = mkdtempSync(join(tmpdir(), 'sp-reap-'))
  signals = []
  alive = new Set()
  probes = []
})
afterEach(() => rmSync(root, { recursive: true, force: true }))

describe('orphan reaping', () => {
  it('deletes the record of a pid that is gone without signalling anything', async () => {
    writeRun('gone', { pid: 9001 })
    const sup = makeSupervisor(() => {
      throw new Error('the probe must not run for a dead pid')
    })

    await sup.reapOrphans()

    expect(existsSync(join(root, 'gone.pid'))).toBe(false)
    expect(existsSync(join(root, 'gone'))).toBe(false)
    expect(terminating()).toEqual([])
    expect(probes).toEqual([])
  })

  it('leaves a reused pid alone when the executable no longer matches', async () => {
    // The pid is live, but it belongs to whatever the OS handed it to next.
    writeRun('reused', { pid: 9002 })
    alive.add(9002)
    const sup = makeSupervisor(() => `/usr/bin/vim ${lstart(new Date())}`)

    await sup.reapOrphans()

    expect(terminating()).toEqual([])
    // The record is still stale — our process is long gone — so it goes, but
    // nothing was signalled to make that true.
    expect(existsSync(join(root, 'reused.pid'))).toBe(false)
  })

  it('leaves a pid alone when it started before the run we recorded', async () => {
    // Same executable, but it predates our record, so it is somebody else's
    // copy of the engine and not the one we lost.
    const started = new Date()
    writeRun('older', { pid: 9003, startedAtIso: started.toISOString() })
    alive.add(9003)
    const older = new Date(started.getTime() - 3_600_000)
    const sup = makeSupervisor(() => `${EXE} ${lstart(older)}`)

    await sup.reapOrphans()

    expect(terminating()).toEqual([])
  })

  it('kills only when the path and the start time both agree', async () => {
    const started = new Date()
    writeRun('ours', { pid: 9004, startedAtIso: started.toISOString() })
    alive.add(9004)
    const sup = makeSupervisor(() => `${EXE} ${lstart(started)}`)

    await sup.reapOrphans()

    expect(terminating()).toEqual([[9004, 'SIGTERM']])
    expect(existsSync(join(root, 'ours.pid'))).toBe(false)
    expect(existsSync(join(root, 'ours'))).toBe(false)
  })

  it('keeps a live pid it could not identify rather than guessing', async () => {
    writeRun('opaque', { pid: 9005 })
    alive.add(9005)
    const sup = makeSupervisor(() => '')

    await sup.reapOrphans()

    expect(terminating()).toEqual([])
    // Retried next launch, by which time the pid has almost certainly gone.
    expect(existsSync(join(root, 'opaque.pid'))).toBe(true)
    expect(existsSync(join(root, 'opaque'))).toBe(true)
  })

  it('reads the executable and start time from /proc on Linux', async () => {
    const started = new Date()
    writeRun('linux', { pid: 9006, startedAtIso: started.toISOString() })
    alive.add(9006)
    const seen: string[] = []
    const sup = new Supervisor({
      runRoot: root,
      platform: 'linux',
      reapTermGraceMs: 50,
      kill: (pid, signal) => {
        signals.push([pid, signal])
        if (signal === 0 && !alive.has(pid)) throw new Error('ESRCH')
        if (signal === 'SIGTERM') alive.delete(pid)
      },
      runProbe: async (command, args) => {
        seen.push(`${command} ${args.join(' ')}`)
        if (command === 'readlink') return `${EXE}\n`
        return `${Math.floor(started.getTime() / 1000)}\n`
      }
    })

    await sup.reapOrphans()

    expect(seen).toEqual(['readlink -f /proc/9006/exe', 'stat -c %Y /proc/9006'])
    expect(terminating()).toEqual([[9006, 'SIGTERM']])
  })

  it('sweeps a run directory with no run behind it', async () => {
    mkdirSync(join(root, 'ghost'), { recursive: true })
    const sup = makeSupervisor(() => '')

    await sup.reapOrphans()

    expect(existsSync(join(root, 'ghost'))).toBe(false)
  })

  it('discards a pid file it cannot parse', async () => {
    writeFileSync(join(root, 'broken.pid'), 'not json')
    const sup = makeSupervisor(() => '')

    await sup.reapOrphans()

    expect(existsSync(join(root, 'broken.pid'))).toBe(false)
    expect(terminating()).toEqual([])
  })
})

describe('process identity parsing', () => {
  it('splits a ps line whose executable path contains spaces', () => {
    const id = parseDarwinPs('/Applications/My App/bin/netd Wed Aug 27 10:11:12 2025\n')
    expect(id?.exePath).toBe('/Applications/My App/bin/netd')
    expect(id?.startedAtMs).toBe(Date.parse('Wed Aug 27 10:11:12 2025'))
  })

  it('reads ExecutablePath and CreationDate from Win32_Process output', () => {
    const id = parseWindowsProcess('C:\\Program Files\\OpenVPN\\bin\\openvpn.exe\r\n2025-08-27T10:11:12.0000000+00:00\r\n')
    expect(id?.exePath).toBe('C:\\Program Files\\OpenVPN\\bin\\openvpn.exe')
    expect(id?.startedAtMs).toBe(Date.parse('2025-08-27T10:11:12.0000000+00:00'))
  })

  it('compares Windows paths without regard to case or slash direction', () => {
    const record: VpnPidRecord = {
      pid: 1,
      startedAtIso: '2025-08-27T10:00:00.000Z',
      exePath: 'C:\\Program Files\\OpenVPN\\bin\\openvpn.exe',
      runId: 'r',
      runDir: 'd'
    }
    expect(
      identityMatches(
        record,
        { exePath: 'c:/program files/openvpn/bin/OpenVPN.exe', startedAtMs: Date.parse('2025-08-27T10:00:01Z') },
        'win32'
      )
    ).toBe(true)
  })

  it('tolerates the sub-second truncation of ps but not a real mismatch', () => {
    const record: VpnPidRecord = {
      pid: 1,
      startedAtIso: '2025-08-27T10:00:00.900Z',
      exePath: EXE,
      runId: 'r',
      runDir: 'd'
    }
    // ps rounded down to the second; still our process.
    expect(
      identityMatches(record, { exePath: EXE, startedAtMs: Date.parse('2025-08-27T10:00:00Z') }, 'darwin')
    ).toBe(true)
    // An hour early is not rounding.
    expect(
      identityMatches(record, { exePath: EXE, startedAtMs: Date.parse('2025-08-27T09:00:00Z') }, 'darwin')
    ).toBe(false)
  })
})
