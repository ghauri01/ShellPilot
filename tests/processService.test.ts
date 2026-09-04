import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import { EventEmitter } from 'node:events'
import { existsSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { PassThrough } from 'node:stream'
import type { ChildProcess } from 'node:child_process'
import {
  ProcessService,
  readProcessFile,
  writeProcessFile
} from '../src/main/services/processes'
import type { ProcessSecretResolution, ProcessServiceDeps } from '../src/main/services/processes'
import { Supervisor } from '../src/main/services/vpn/supervisor'
import type { ProcessDraft, ProcessesFile } from '../src/shared/processes'

// Same harness shape as tests/vpnSupervisor.test.ts: an injected clock, an
// injected spawn, no real timers and no sleeps.

class FakeChild extends EventEmitter {
  static nextPid = 7000
  readonly pid = FakeChild.nextPid++
  exitCode: number | null = null
  stdin = new PassThrough()
  stdout = new PassThrough()
  stderr = new PassThrough()

  exit(code: number | null, signal: NodeJS.Signals | null = null): void {
    this.exitCode = code
    this.emit('exit', code, signal)
  }

  say(text: string): void {
    this.stdout.write(`${text}\n`)
  }
}

const flush = async (times = 30): Promise<void> => {
  for (let i = 0; i < times; i++) await new Promise((resolve) => setImmediate(resolve))
}

// Wall-clock budget rather than a turn count, and `performance.now()` rather
// than `Date.now()` — `Date` is faked below, so a Date deadline would never
// advance and this would hang instead of failing. Same reasoning as the
// supervisor suite; do not "simplify" it back.
const waitFor = async (fn: () => boolean, budgetMs = 10_000): Promise<void> => {
  const deadline = performance.now() + budgetMs
  for (;;) {
    if (fn()) return
    if (performance.now() > deadline) break
    await new Promise((resolve) => setImmediate(resolve))
  }
  throw new Error('condition never became true')
}

// `stop()` walks a TIMED ladder — the graceful rung, then SIGTERM, then five
// seconds to SIGKILL — so the fake clock has to move for it to get down it.
// Awaiting the promise on its own under frozen timers is a hang, not a wait.
const withClock = async <T>(p: Promise<T>): Promise<T> => {
  let settled = false
  const tracked = p.then(
    (v) => {
      settled = true
      return v
    },
    (e) => {
      settled = true
      throw e
    }
  )
  for (let i = 0; i < 40 && !settled; i++) {
    await vi.advanceTimersByTimeAsync(1_000)
    await flush()
  }
  return await tracked
}

// Advancing a fake clock only does something if the timer already exists, and
// the backoff timer is armed after a real `fs` unlink in the exit path. A
// single jump bets that the unlink won that race; when it loses, the delay is
// consumed against nothing and the relaunch never comes. Step and re-check
// instead — the same fix tests/vpnSupervisor.test.ts documents.
const advanceUntil = async (fn: () => boolean, stepMs = 1_000, steps = 80): Promise<void> => {
  for (let i = 0; i < steps; i++) {
    if (fn()) return
    await vi.advanceTimersByTimeAsync(stepMs)
    await flush()
  }
  if (!fn()) throw new Error('condition never became true while advancing the clock')
}

let root: string
let file: string
let spawns: { command: string; args: readonly string[]; env: Record<string, string>; child: FakeChild }[]
let signals: [number, number | NodeJS.Signals][]

const draft = (over: Partial<ProcessDraft> = {}): ProcessDraft => ({
  name: 'API',
  command: '/usr/local/bin/node',
  args: ['server.js'],
  cwd: '/srv/api',
  env: [],
  restart: 'on-failure',
  readiness: { kind: 'spawned' },
  ...over
})

function makeService(
  over: Partial<ProcessServiceDeps> = {},
  supervisorOver: { runRoot?: string } = {}
): { service: ProcessService; supervisor: Supervisor; written: ProcessesFile[] } {
  const written: ProcessesFile[] = []
  const supervisor = new Supervisor({
    runRoot: supervisorOver.runRoot ?? root,
    platform: 'linux',
    random: () => 0.5,
    spawn: (command, args, options) => {
      const child = new FakeChild()
      spawns.push({
        command,
        args,
        env: (options.env ?? {}) as Record<string, string>,
        child
      })
      return child as unknown as ChildProcess
    },
    kill: (pid, signal) => {
      if (signal === 0) return
      signals.push([pid, signal])
      spawns.at(-1)?.child.exit(null, signal as NodeJS.Signals)
    }
  })
  let n = 0
  const service = new ProcessService({
    now: () => Date.now(),
    newId: () => `id-${++n}`,
    read: () => readProcessFile(file),
    write: (f) => {
      written.push(f)
      writeProcessFile(file, f)
    },
    resolveSecret: () => ({ ok: false, reason: 'credential-missing' }),
    supervisor,
    ...over
  })
  return { service, supervisor, written }
}

beforeEach(() => {
  root = mkdtempSync(join(tmpdir(), 'sp-proc-'))
  file = join(root, 'shellpilot-processes.json')
  spawns = []
  signals = []
  vi.useFakeTimers({
    toFake: ['setTimeout', 'clearTimeout', 'setInterval', 'clearInterval', 'Date']
  })
})
afterEach(() => {
  vi.useRealTimers()
  rmSync(root, { recursive: true, force: true })
})

describe('the list survives a restart of the app', () => {
  it('reads back what a previous instance wrote, from its own file', async () => {
    const first = makeService()
    first.service.create(draft({ name: 'API', command: '/usr/bin/node', args: ['api.js'] }))
    first.service.create(draft({ name: 'Worker', command: '/usr/bin/node', args: ['worker.js'] }))

    // A whole new service over the same path — the app, restarted.
    const second = makeService()
    expect(second.service.list().map((p) => [p.name, p.command, p.args])).toEqual([
      ['API', '/usr/bin/node', ['api.js']],
      ['Worker', '/usr/bin/node', ['worker.js']]
    ])
  })

  it('writes the list to its own file at 0600, not to the renderer blob', async () => {
    // The renderer blob (shellpilot-data.json) is also the backup/export
    // payload. A command line that will be executed on this machine does not
    // belong in a file that gets mailed around.
    const { service } = makeService()
    service.create(draft())

    expect(existsSync(file)).toBe(true)
    expect(existsSync(join(root, 'shellpilot-data.json'))).toBe(false)
    expect(statSync(file).mode & 0o777).toBe(0o600)
    expect(JSON.parse(readFileSync(file, 'utf8'))).toMatchObject({ v: 1 })
  })

  it('does not start anything on the way back up', async () => {
    // pm2 resurrects; this does not. Constructing the service and reaping
    // orphans is the whole of what happens at launch.
    const first = makeService()
    first.service.create(draft())

    const second = makeService()
    await second.service.reapOrphans()
    await flush()

    expect(spawns).toEqual([])
    expect(second.service.status().map((s) => s.state)).toEqual(['stopped'])
  })

  it('reads a corrupt file as an empty list rather than refusing to start', async () => {
    writeFileSync(file, '{ this is not json')
    const { service } = makeService()
    expect(service.list()).toEqual([])
  })
})

describe('a stored env secret is never rendered and never logged', () => {
  const secretDraft = draft({
    name: 'API',
    env: [{ key: 'DB_URL', kind: 'vault', vaultEntryId: 'v-1', slot: 'password' }],
    readiness: { kind: 'spawned' }
  })

  it('resolves it into the child environment and nowhere else', async () => {
    const resolveSecret = vi.fn(
      (): ProcessSecretResolution => ({ ok: true, value: 'postgres://u:s3cr3t@db/app' })
    )
    const { service } = makeService({ resolveSecret })
    const created = service.create(secretDraft)
    await service.start(created!.id)
    await waitFor(() => spawns.length === 1)

    // In the child's environment...
    expect(spawns[0].env.DB_URL).toBe('postgres://u:s3cr3t@db/app')

    // ...and in none of the three places it could leak from.
    expect(JSON.stringify(service.list())).not.toContain('s3cr3t')
    expect(JSON.stringify(service.status())).not.toContain('s3cr3t')
    expect(readFileSync(file, 'utf8')).not.toContain('s3cr3t')
  })

  it('scrubs it out of the log ring when the process echoes its own environment', async () => {
    // Not exotic. Half of them print their config on start-up.
    //
    // The value is deliberately SHAPELESS — not a connection URI, not a PEM
    // block, not `SOMETHING_TOKEN=…`. secretRedaction's pattern rules catch
    // all of those on their own, so a secret-shaped fixture would let this
    // test pass with the resolved values never handed to the redactor at all.
    // What is under test is that they ARE handed over: `spec.redact`.
    const { service } = makeService({
      resolveSecret: () => ({ ok: true, value: 'wolf-antler-9931' })
    })
    const created = service.create(secretDraft)
    await service.start(created!.id)
    await waitFor(() => spawns.length === 1)

    spawns[0].child.say('connected; credential wolf-antler-9931 accepted')
    await waitFor(() => service.logs(created!.id).length > 0)

    const text = service.logs(created!.id).map((l) => l.text).join('\n')
    expect(text).not.toContain('wolf-antler-9931')
    expect(text).toContain('[REDACTED]')
  })

  it('refuses to start at all when the vault is locked, rather than starting it half-configured', async () => {
    // "It started and then could not reach the database" is a worse answer
    // than "the vault is locked", and a half-populated environment is the kind
    // of failure people debug for an hour.
    const { service } = makeService({
      resolveSecret: () => ({ ok: false, reason: 'vault-locked' })
    })
    const created = service.create(secretDraft)
    const status = await service.start(created!.id)

    expect(spawns).toEqual([])
    expect(status?.state).toBe('failed')
    expect(status?.error).toBe(
      'The vault is locked, so DB_URL could not be read. Unlock it and start this again.'
    )
  })
})

describe('a crash loop trips the detector rather than restarting forever', () => {
  it('stops after the seventh exit in the window and says so without saying "tunnel"', async () => {
    const { service } = makeService()
    const created = service.create(draft({ restart: 'always' }))
    await service.start(created!.id)
    await waitFor(() => spawns.length === 1)

    // PROCESS_CRASH_LOOP allows 6 restarts inside a 5 minute window. Exit
    // seven times: the seventh is the one over the line.
    //
    // random() is pinned to 0.5, so the jitter factor is exactly 1 and the
    // delays are the raw curve: 1s, 2s, 4s, 8s, 16s, then the 30s ceiling.
    // They add up to 61 seconds, which is why the window is five minutes and
    // not one — at a one minute window the oldest exit falls out before the
    // seventh arrives and the detector can never fire at all.
    for (let i = 0; i < 6; i++) {
      const n = spawns.length
      spawns[n - 1].child.exit(1)
      await advanceUntil(() => spawns.length === n + 1)
      expect(spawns.length, `restart ${i + 1}`).toBe(n + 1)
    }
    spawns[6].child.exit(1)
    await flush()

    // Seven attempts, and then it gave up — not an eighth.
    expect(spawns).toHaveLength(7)
    const status = service.status()[0]
    expect(status.state).toBe('crash-looped')
    expect(status.error).toBe(
      'It kept exiting, so it was stopped rather than restarted again. It exited 7 times in 300 seconds.'
    )
  })

  it('does not paint a restart in flight as a failure', async () => {
    // A healthy restart policy doing its job must not look like a broken
    // process, or the state is noise.
    const { service } = makeService()
    const created = service.create(draft({ restart: 'always' }))
    await service.start(created!.id)
    await waitFor(() => spawns.length === 1)

    spawns[0].child.exit(1)
    await flush()
    expect(service.status()[0].state).not.toBe('failed')

    await vi.advanceTimersByTimeAsync(1_000)
    await waitFor(() => spawns.length === 2)
    await waitFor(() => service.status()[0].state === 'running')
  })

  it('keeps the log ring bounded while it loops', async () => {
    const { service } = makeService()
    const created = service.create(draft({ restart: 'always' }))
    await service.start(created!.id)
    await waitFor(() => spawns.length === 1)

    for (let i = 0; i < 3_000; i++) spawns[0].child.say(`line ${i}`)
    await waitFor(() => service.logs(created!.id, 5_000).length > 0)

    // Two caps, and both matter: the ring holds 2000 lines, and one page to
    // the renderer is 500 however many are asked for.
    expect(service.logs(created!.id, 5_000).length).toBeLessThanOrEqual(500)
    expect(service.logs(created!.id).length).toBeLessThanOrEqual(500)
  })
})

describe('an orphan from a previous run is reaped', () => {
  it('kills a child this app left behind, once its identity is confirmed', async () => {
    // A pid record written by a previous run of the app, for a pid that is
    // still alive and whose exe path and start time both match. Both halves
    // have to match: the path alone is defeated by pid reuse against another
    // copy of the same program, and the start time alone by anything younger
    // than the record.
    const startedAtMs = 1_700_000_000_000
    writeFileSync(
      join(root, 'proc-id-1.pid'),
      JSON.stringify({
        pid: 8321,
        startedAtIso: new Date(startedAtMs).toISOString(),
        exePath: '/usr/local/bin/node',
        runId: 'proc-id-1',
        runDir: '/srv/api'
      })
    )

    const killed: [number, number | NodeJS.Signals][] = []
    const supervisor = new Supervisor({
      runRoot: root,
      platform: 'linux',
      kill: (pid, signal) => {
        if (signal !== 0) killed.push([pid, signal])
      },
      runProbe: async (command) =>
        command === 'readlink' ? '/usr/local/bin/node\n' : `${startedAtMs / 1000}\n`,
      reapTermGraceMs: 0,
      spawn: () => new FakeChild() as unknown as ChildProcess
    })
    const { service } = makeService({}, {})
    // Same file, a supervisor with the probe wired up.
    const svc = new ProcessService({
      now: () => Date.now(),
      newId: () => 'id-1',
      read: () => readProcessFile(file),
      write: (f) => writeProcessFile(file, f),
      resolveSecret: () => ({ ok: false, reason: 'credential-missing' }),
      supervisor
    })
    void service

    await svc.reapOrphans()

    expect(killed).toEqual([
      [8321, 'SIGTERM'],
      [8321, 'SIGKILL']
    ])
    expect(existsSync(join(root, 'proc-id-1.pid'))).toBe(false)
  })

  it('leaves a pid that now belongs to somebody else completely alone', async () => {
    // The mistake the identity probe exists to prevent. The OS reuses pids,
    // and the one recorded may now be the user's editor.
    const startedAtMs = 1_700_000_000_000
    writeFileSync(
      join(root, 'proc-id-1.pid'),
      JSON.stringify({
        pid: 8321,
        startedAtIso: new Date(startedAtMs).toISOString(),
        exePath: '/usr/local/bin/node',
        runId: 'proc-id-1',
        runDir: '/srv/api'
      })
    )

    const killed: [number, number | NodeJS.Signals][] = []
    const supervisor = new Supervisor({
      runRoot: root,
      platform: 'linux',
      kill: (pid, signal) => {
        if (signal !== 0) killed.push([pid, signal])
      },
      runProbe: async (command) =>
        command === 'readlink' ? '/Applications/Emacs.app/Contents/MacOS/Emacs\n' : `${startedAtMs / 1000}\n`,
      reapTermGraceMs: 0,
      spawn: () => new FakeChild() as unknown as ChildProcess
    })
    const svc = new ProcessService({
      now: () => Date.now(),
      newId: () => 'id-1',
      read: () => readProcessFile(file),
      write: (f) => writeProcessFile(file, f),
      resolveSecret: () => ({ ok: false, reason: 'credential-missing' }),
      supervisor
    })

    await svc.reapOrphans()

    expect(killed).toEqual([])
  })
})

describe('start, stop, restart and what the panel is shown', () => {
  it('waits for the readiness line before it calls the process running', async () => {
    const { service } = makeService()
    const created = service.create(
      draft({ readiness: { kind: 'log', pattern: 'listening on', timeoutMs: 10_000 } })
    )
    const started = service.start(created!.id)
    await waitFor(() => spawns.length === 1)

    expect(service.status()[0].state).toBe('starting')
    spawns[0].child.say('booting')
    await flush()
    expect(service.status()[0].state).toBe('starting')

    spawns[0].child.say('listening on http://127.0.0.1:3000')
    await started
    expect(service.status()[0].state).toBe('running')
    expect(service.status()[0].pid).toBe(spawns[0].child.pid)
  })

  it('starting twice does not start a second copy', async () => {
    const { service } = makeService()
    const created = service.create(draft())
    await service.start(created!.id)
    await waitFor(() => spawns.length === 1)
    await service.start(created!.id)
    await flush()
    expect(spawns).toHaveLength(1)
  })

  it('stops a running process and reports it stopped, not failed', async () => {
    const { service } = makeService()
    const created = service.create(draft({ restart: 'always' }))
    await service.start(created!.id)
    await waitFor(() => spawns.length === 1)

    const status = await withClock(service.stop(created!.id))
    expect(status?.state).toBe('stopped')
    expect(status?.pid).toBe(0)
    // And a restart policy of `always` must not bring it back after a stop.
    await vi.advanceTimersByTimeAsync(60_000)
    await flush()
    expect(spawns).toHaveLength(1)
  })

  it('keeps the last lines after the run is over, so the drawer still says why', async () => {
    const { service } = makeService()
    const created = service.create(draft({ restart: 'never' }))
    await service.start(created!.id)
    await waitFor(() => spawns.length === 1)
    spawns[0].child.say('Error: EADDRINUSE 3000')
    await waitFor(() => service.logs(created!.id).length > 0)

    await withClock(service.stop(created!.id))
    await flush()

    expect(service.logs(created!.id).map((l) => l.text)).toContain('Error: EADDRINUSE 3000')
  })

  it('stops a process before deleting it, so nothing is left supervised with no row', async () => {
    const { service } = makeService()
    const created = service.create(draft({ restart: 'always' }))
    await service.start(created!.id)
    await waitFor(() => spawns.length === 1)
    const pid = spawns[0].child.pid

    expect(await withClock(service.remove(created!.id))).toBe(true)
    expect(signals.some(([p]) => p === pid)).toBe(true)
    expect(service.list()).toEqual([])
    // And nothing restarts it, because the supervisor no longer holds it.
    await vi.advanceTimersByTimeAsync(60_000)
    await flush()
    expect(spawns).toHaveLength(1)
  })

  it('refuses a draft with a secret-shaped literal rather than storing it', async () => {
    const { service } = makeService()
    expect(() =>
      service.create(draft({ env: [{ key: 'API_TOKEN', kind: 'literal', value: 'ghp_x' }] }))
    ).toThrow(/vault/)
    expect(service.list()).toEqual([])
    expect(existsSync(file)).toBe(false)
  })
})
