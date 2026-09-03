import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import { EventEmitter } from 'node:events'
import { createHash } from 'node:crypto'
import { existsSync, mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { PassThrough } from 'node:stream'
import { fileURLToPath } from 'node:url'
import type { ChildProcess, SpawnOptions } from 'node:child_process'
import { Supervisor, backoffDelay } from '../src/main/services/vpn/supervisor'
import type { SupervisedSpec, SupervisorHandle } from '../src/main/services/vpn/supervisor'

const FIXTURE = fileURLToPath(new URL('./fixtures/fake-child.mjs', import.meta.url))

// A stand-in for ChildProcess that the test drives directly, so the timing
// assertions below depend only on the fake clock and never on how fast a real
// process happens to start.
class FakeChild extends EventEmitter {
  static nextPid = 4000
  readonly pid = FakeChild.nextPid++
  exitCode: number | null = null
  stdin = new PassThrough()
  stdout = new PassThrough()
  stderr = new PassThrough()

  exit(code: number | null, signal: NodeJS.Signals | null = null): void {
    this.exitCode = code
    this.emit('exit', code, signal)
  }
}

interface Spawned {
  command: string
  args: readonly string[]
  options: SpawnOptions
  child: FakeChild
  at: number
}

// Yields to the real event loop. Fake timers here deliberately do not cover
// setImmediate, so this still drains pipe and fs callbacks while the clock is
// frozen.
const flush = async (times = 30): Promise<void> => {
  for (let i = 0; i < times; i++) await new Promise((resolve) => setImmediate(resolve))
}

// Real fs and pipe callbacks still complete while the clock is frozen, but not
// on a predictable number of turns, so conditions are waited on rather than
// counted.
//
// The budget is wall-clock rather than a turn count, and that distinction is
// the whole fix. A turn count measures how many times *this* loop got
// scheduled, which has no fixed relationship to how long a real `fs` or pipe
// callback takes to land — so on a loaded machine the budget ran out while the
// I/O was still perfectly healthy. It failed in CI on the run that prompted
// this, having proved nothing about the code under test.
//
// `performance.now()`, not `Date.now()`. `Date` is in this file's `toFake` list
// (see the beforeEach below), so a `Date.now()` deadline would never advance
// and this loop would spin until the test runner killed the worker — trading a
// fast red test for a hung one, which is worse than the flake. `performance` is
// not faked. Do not "simplify" this back to `Date`.
const WAIT_BUDGET_MS = 10_000
const waitFor = async (fn: () => boolean, budgetMs = WAIT_BUDGET_MS): Promise<void> => {
  const deadline = performance.now() + budgetMs
  for (;;) {
    if (fn()) return
    if (performance.now() > deadline) break
    await new Promise((resolve) => setImmediate(resolve))
  }
  throw new Error('condition never became true')
}

// Advancing a fake clock only does something if the timer already exists, and
// several timers here are armed after a real `fs` callback. A single jump bets
// that the callback won that race; when it lost, the delay was consumed against
// nothing, no relaunch came, and the next `waitFor` died ten seconds later
// having proved nothing. This steps the clock and re-checks instead, so a timer
// armed slightly late is still caught.
const advanceUntil = async (
  fn: () => boolean,
  stepMs: number,
  steps = 20
): Promise<void> => {
  for (let i = 0; i < steps; i++) {
    if (fn()) return
    await vi.advanceTimersByTimeAsync(stepMs)
    await flush()
  }
  if (!fn()) throw new Error('condition never became true while advancing the clock')
}

let root: string

function baseSpec(over: Partial<SupervisedSpec> = {}): SupervisedSpec {
  return {
    id: 'run-1',
    command: '/opt/shellpilot/engine',
    args: ['--config', 'stdin'],
    cwd: root,
    readiness: async () => {},
    readinessTimeoutMs: 30_000,
    restart: 'always',
    backoff: { baseMs: 1_000, maxMs: 60_000, jitter: 0.3 },
    crashLoop: { windowMs: 120_000, maxRestarts: 5 },
    logRing: { maxLines: 2_000, maxBytes: 1 << 20 },
    redact: [],
    ...over
  }
}

beforeEach(() => {
  root = mkdtempSync(join(tmpdir(), 'sp-sup-'))
})
afterEach(() => {
  vi.useRealTimers()
  rmSync(root, { recursive: true, force: true })
})

describe('backoff', () => {
  const backoff = { baseMs: 1_000, maxMs: 60_000, jitter: 0.3 }

  it('doubles per attempt and clamps at maxMs', () => {
    // random() === 0.5 puts the jitter factor at exactly 1, which is the only
    // way to assert the underlying curve rather than a range.
    const mid = (): number => 0.5
    expect([0, 1, 2, 3, 4].map((n) => backoffDelay(n, backoff, mid))).toEqual([
      1_000, 2_000, 4_000, 8_000, 16_000
    ])
    expect(backoffDelay(20, backoff, mid)).toBe(60_000)
  })

  it('keeps every sample inside 1 ± jitter and does not return a constant', () => {
    const samples = Array.from({ length: 500 }, () => backoffDelay(3, backoff))
    for (const s of samples) {
      expect(s).toBeGreaterThanOrEqual(Math.round(8_000 * 0.7))
      expect(s).toBeLessThanOrEqual(Math.round(8_000 * 1.3))
    }
    // Five profiles pointed at one downed endpoint must not retry in lockstep.
    expect(new Set(samples).size).toBeGreaterThan(50)
  })
})

describe('supervisor lifecycle', () => {
  let spawns: Spawned[]
  let signals: [number, number | NodeJS.Signals][]
  let sup: Supervisor

  const make = (over: Partial<SupervisedSpec> = {}, platform: NodeJS.Platform = 'darwin') => {
    const spec = baseSpec(over)
    sup = new Supervisor({
      runRoot: root,
      platform,
      random: () => 0.5,
      spawn: (command, args, options) => {
        const child = new FakeChild()
        spawns.push({ command, args, options, child, at: Date.now() })
        return child as unknown as ChildProcess
      },
      kill: (pid, signal) => {
        signals.push([pid, signal])
      }
    })
    return spec
  }

  beforeEach(() => {
    spawns = []
    signals = []
    vi.useFakeTimers({
      toFake: ['setTimeout', 'clearTimeout', 'setInterval', 'clearInterval', 'Date']
    })
  })

  it('backs off exponentially between restarts', async () => {
    // Wait for the supervisor to say it armed the timer; never count turns to
    // guess that it has.
    //
    // handleExit does `await unlink(run.pidFile)` — real fs I/O — before it
    // arms the backoff timer, and how many event-loop turns that takes is a
    // property of the machine, not of the supervisor. This test used to
    // `flush()` a fixed 30 turns and then advance the clock. On a loaded runner
    // the unlink had not landed yet, so the clock moved to 999 BEFORE the timer
    // existed; the timer was then armed at ~999 and fired ~1000ms after that,
    // and `spawns[1].at - start` came out near 2000 instead of 1000. Roughly
    // one full-suite run in two, and never in isolation — the shape of every
    // timing flake, and the same one the sibling test below already documents.
    //
    // onRestartScheduled fires on the line above the setTimeout, so it is the
    // exact moment the timer is armed, and it carries the delay. That makes the
    // backoff curve assertable directly instead of inferred from Date
    // arithmetic across an await that may or may not have completed.
    const scheduled: number[] = []
    const spec = make({
      onRestartScheduled: (_handle, _attempt, delay) => {
        scheduled.push(delay)
      }
    })
    const handle = await sup.spawn(spec)
    expect(handle.pid).toBe(spawns[0].child.pid)

    // random() is pinned to 0.5 in make(), so the jitter factor is exactly 1
    // and these are the raw curve: 1s, 2s, 4s.
    for (const [attempt, delay] of [1_000, 2_000, 4_000].entries()) {
      spawns[attempt].child.exit(1)
      await waitFor(() => scheduled.length === attempt + 1)
      expect(scheduled[attempt]).toBe(delay)

      // Nothing relaunches before the delay is up...
      await vi.advanceTimersByTimeAsync(delay - 1)
      await flush()
      expect(spawns).toHaveLength(attempt + 1)

      // ...and something does once it is.
      await vi.advanceTimersByTimeAsync(1)
      await waitFor(() => spawns.length === attempt + 2)
    }
  })

  it('forgets the exponent once readiness has held for 60s', async () => {
    // Count readiness rather than assuming a fixed number of event-loop turns
    // reaches it. The 60s healthy-reset timer is only armed once the relaunch
    // is ready, and `flush()`'s fixed 30 turns were enough on an idle machine
    // and not enough on a loaded CI runner — so this test failed intermittently
    // while testing nothing about the supervisor.
    let ready = 0
    // The exit handler unlinks the pid file — real fs — before it arms the
    // backoff timer, and `flush()` counts microtask turns, which has no fixed
    // relationship to how long that takes. Advancing the clock first meant the
    // timer was armed at the already-advanced time and its delay was never
    // consumed. onRestartScheduled fires on the line the timer is armed, so
    // waiting on it removes the guess entirely.
    const armed: number[] = []
    const spec = make({
      onReady: () => { ready++ },
      onRestartScheduled: (_h, _a, delay) => armed.push(delay)
    })
    await sup.spawn(spec)
    await waitFor(() => ready === 1)

    // One failure, so the next delay would be 2s if the exponent survived.
    spawns[0].child.exit(1)
    await waitFor(() => armed.length === 1)
    await vi.advanceTimersByTimeAsync(1_000)
    await waitFor(() => spawns.length === 2)
    // The relaunch must reach readiness before the clock moves, or the 60s
    // timer this test is about would not exist yet when it is advanced past.
    await waitFor(() => ready === 2)

    await vi.advanceTimersByTimeAsync(60_000)
    await flush()

    const before = Date.now()
    spawns[1].child.exit(1)
    // Same reason, and it matters more here: this test asserts the delay is
    // exactly 1000ms by stepping 999 then 1, which only means anything if the
    // timer already exists when the first step happens.
    await waitFor(() => armed.length === 2)
    await vi.advanceTimersByTimeAsync(999)
    await flush()
    expect(spawns).toHaveLength(2)
    await vi.advanceTimersByTimeAsync(1)
    await waitFor(() => spawns.length === 3)
    expect(spawns[2].at - before).toBe(1_000)
  })

  it('goes terminal after more than maxRestarts exits inside the window', async () => {
    const armed: number[] = []
    const spec = make({
      backoff: { baseMs: 10, maxMs: 10, jitter: 0 },
      crashLoop: { windowMs: 120_000, maxRestarts: 5 },
      onRestartScheduled: (_h, _a, delay) => armed.push(delay)
    })
    const handle = await sup.spawn(spec)

    const exits: Parameters<Parameters<SupervisorHandle['onExit']>[0]>[0][] = []
    handle.onExit((e) => exits.push(e))

    // Sixty lines of engine output, so the tail attached to the terminal error
    // has more than enough to be trimmed to forty.
    for (let i = 0; i < 60; i++) spawns[0].child.stdout.write(`engine line ${i}\n`)
    await flush()

    for (let i = 0; i < 6; i++) {
      // Wait for the relaunch to exist rather than assuming a fixed number of
      // event-loop turns produced it. `flush()` was enough on an idle machine
      // and not on a loaded one, where `spawns[i]` was still undefined and the
      // test died on a property access instead of testing the crash loop.
      await waitFor(() => spawns.length > i)
      spawns[i].child.exit(2)
      // Advancing the clock before the retry timer exists means its 20ms is
      // never consumed, so no relaunch comes and the next pass dies on the
      // waitFor budget ten seconds later. The exit handler unlinks the pid
      // file — real fs — before arming that timer, and flush() counts a fixed
      // number of microtask turns, which is not a measure of how long that
      // takes. This is what failed CI on the 0.8.1 tag.
      //
      // The sixth exit is the terminal one and arms nothing, so waiting on
      // `armed` alone would hang on the last pass.
      await waitFor(() => armed.length > i || exits.some((e) => !e.restarting))
      await vi.advanceTimersByTimeAsync(20)
      await flush()
    }

    expect(spawns).toHaveLength(6)
    const terminal = exits.at(-1)
    expect(terminal?.restarting).toBe(false)
    expect(terminal?.error?.code).toBe('crash-loop')
    expect(terminal?.logTail).toHaveLength(40)

    // And it stays stopped: no seventh attempt, ever.
    await vi.advanceTimersByTimeAsync(600_000)
    await flush()
    expect(spawns).toHaveLength(6)
  })

  it('stops in order: gracefulStop, then SIGTERM, then SIGKILL', async () => {
    const order: string[] = []
    const spec = make({
      gracefulTimeoutMs: 5_000,
      gracefulStop: async () => {
        order.push('graceful')
      }
    })
    await sup.spawn(spec)
    const child = spawns[0].child

    const stopped = sup.stop(spec.id)
    await flush()
    // The control channel is tried before anything is signalled — on Windows
    // it is the only chance the engine gets to tidy up.
    expect(order).toEqual(['graceful'])
    expect(signals).toHaveLength(0)

    await vi.advanceTimersByTimeAsync(5_000)
    await flush()
    expect(signals.map((s) => s[1])).toEqual(['SIGTERM'])

    await vi.advanceTimersByTimeAsync(5_000)
    await flush()
    expect(signals.map((s) => s[1])).toEqual(['SIGTERM', 'SIGKILL'])

    child.exit(null, 'SIGKILL')
    await flush()
    await stopped
    expect(sup.get(spec.id)).toBeUndefined()
  })

  it('skips straight to the kill when forced', async () => {
    const order: string[] = []
    const spec = make({
      gracefulStop: async () => {
        order.push('graceful')
      }
    })
    await sup.spawn(spec)
    const stopped = sup.stop(spec.id, { force: true })
    await flush()
    expect(order).toEqual([])
    expect(signals.map((s) => s[1])).toEqual(['SIGKILL'])
    spawns[0].child.exit(null, 'SIGKILL')
    await flush()
    await stopped
  })

  it('uses taskkill /T /F on win32, where a non-console child has no SIGTERM', async () => {
    const spec = make({}, 'win32')
    await sup.spawn(spec)
    const stopped = sup.stop(spec.id, { force: true })
    await flush()
    const kill = spawns.find((s) => s.command === 'taskkill')
    expect(kill?.args).toEqual(['/T', '/F', '/PID', String(spawns[0].child.pid)])
    spawns[0].child.exit(null, 'SIGKILL')
    await flush()
    await stopped
  })

  it('kills and retries when readiness never arrives', async () => {
    const armed: number[] = []
    const spec = make({
      restart: 'on-failure',
      readiness: () => new Promise<void>(() => {}),
      readinessTimeoutMs: 30_000,
      backoff: { baseMs: 1_000, maxMs: 1_000, jitter: 0 },
      // See the backoff-window test: waiting a fixed number of turns for the
      // pid-file unlink before advancing the clock is what made this the one
      // test in the file that still failed under full-suite load.
      onRestartScheduled: (_h, _a, delay) => armed.push(delay)
    })
    // Never resolves until a run is ready, so it is deliberately not awaited.
    void sup.spawn(spec).catch(() => {})
    // The pid file lands before the readiness clock starts, so its appearance
    // is the signal that this attempt is fully wired up.
    await waitFor(() => existsSync(join(root, 'run-1.pid')))
    await flush()
    expect(spawns).toHaveLength(1)

    // Nothing observable marks the instant the readiness clock is armed, so the
    // clock is stepped rather than jumped once and hoped over.
    await advanceUntil(() => signals.length > 0, 30_000)
    expect(signals.map((s) => s[1])).toEqual(['SIGKILL'])

    spawns[0].child.exit(null, 'SIGKILL')
    await waitFor(() => armed.length === 1)
    await vi.advanceTimersByTimeAsync(armed[0])
    await waitFor(() => spawns.length === 2)
  })

  it('leaves a stop that is already under way to do the killing', async () => {
    // A readiness promise does not only time out — it REJECTS, the moment a
    // driver gives up on a start, and a driver that gives up stops the run in
    // the same turn. So the readiness catch and the stop ladder ran over each
    // other and the catch won: SIGKILL landed on a live, answering engine
    // microseconds after `stop()` had asked it, over its own control channel,
    // to exit and put the routes back. It never acted on the request — the tun
    // interface stayed up and the pushed routes stayed installed, which is the
    // one thing the control channel exists to prevent. On Windows, where
    // process.kill is a hard TerminateProcess, that channel is the only polite
    // mechanism there is.
    //
    // Seen from the other end in tests/vpnOpenvpnDriver.test.ts: the OpenVPN
    // stub died of SIGKILL on every run of the dismissed-prompt case, and lost
    // the acknowledgement it was in the middle of writing whenever the machine
    // was loaded enough for the kill to win.
    let giveUp!: (e: Error) => void
    const asked: string[] = []
    const spec = make({
      restart: 'on-failure',
      readiness: () =>
        new Promise<void>((_resolve, reject) => {
          giveUp = reject
        }),
      gracefulStop: async () => {
        asked.push('control channel')
      },
      gracefulTimeoutMs: 5_000
    })
    void sup.spawn(spec).catch(() => {})
    // readiness() is called after the pid record is written, so waiting for the
    // spawn alone would not prove the promise this test rejects exists yet.
    await waitFor(() => Boolean(giveUp))

    // Exactly the shape a driver produces: give up, then stop, in one turn.
    giveUp(new Error('the one-time code prompt was cancelled'))
    const stopped = sup.stop(spec.id)
    await flush()

    expect(asked).toEqual(['control channel'])
    expect(signals).toEqual([])

    // And it exits because it was asked to, not because it was killed.
    spawns[0].child.exit(0)
    await stopped
    expect(signals).toEqual([])
  })

  it('bounds the ring by bytes, so one huge line cannot defeat the line cap', async () => {
    const spec = make({ logRing: { maxLines: 2_000, maxBytes: 1_024 } })
    const handle = await sup.spawn(spec)

    spawns[0].child.stdout.write(`${'H'.repeat(4 * 1024 * 1024)}\n`)
    await flush(12)

    const lines = handle.logs()
    const bytes = lines.reduce((n, l) => n + Buffer.byteLength(l.text, 'utf8'), 0)
    expect(lines.length).toBeGreaterThan(0)
    expect(bytes).toBeLessThanOrEqual(1_024)
    expect(lines.at(-1)?.text).toContain('truncated')
  })

  it('redacts before the line is stored, not before it is displayed', async () => {
    const secret = 'wg-private-key-material'
    const spec = make({ redact: [secret] })
    const handle = await sup.spawn(spec)

    spawns[0].child.stderr.write(`peer configured with ${secret} ok\n`)
    await flush()

    const text = handle.logs().map((l) => l.text).join('\n')
    expect(text).not.toContain(secret)
    expect(text).toContain('[REDACTED]')
  })
})

// The properties above are about timing, so they are driven by a fake clock
// and a fake child. These are about what actually crosses the process
// boundary, so they use a real one.
describe('supervisor against a real child process', () => {
  const readyOnLine =
    (needle: string) =>
    (h: SupervisorHandle): Promise<void> =>
      new Promise((resolve) => {
        if (h.logs().some((l) => l.text.includes(needle))) return resolve()
        const off = h.onLog((l) => {
          if (!l.text.includes(needle)) return
          off()
          resolve()
        })
      })

  it('delivers the secret on stdin and never puts it in argv', async () => {
    const secret = 'super-secret-wireguard-key='
    const sup = new Supervisor({ runRoot: root })
    const spec: SupervisedSpec = {
      id: 'real-1',
      command: process.execPath,
      args: [FIXTURE, '--print-argv', '--read-stdin', '--ready-after=0', '--stay'],
      cwd: root,
      stdinPayload: secret,
      readiness: readyOnLine('READY'),
      readinessTimeoutMs: 10_000,
      restart: 'never',
      backoff: { baseMs: 100, maxMs: 100, jitter: 0 },
      crashLoop: { windowMs: 120_000, maxRestarts: 5 },
      logRing: { maxLines: 500, maxBytes: 1 << 20 },
      redact: [secret]
    }

    const handle = await sup.spawn(spec)
    const text = handle.logs().map((l) => l.text).join('\n')

    // The engine only ever sees the secret through the pipe.
    expect(JSON.stringify(spec.args)).not.toContain(secret)
    const argvLine = handle.logs().find((l) => l.text.startsWith('ARGV '))
    expect(argvLine).toBeDefined()
    expect(argvLine?.text).not.toContain(secret)

    // Proved by hash rather than by echoing it back, so the assertion does not
    // itself put the secret in the log it is checking.
    const sha = createHash('sha256').update(secret).digest('hex')
    expect(text).toContain(`STDIN-SHA256 ${sha}`)
    expect(text).toContain(`STDIN-LEN ${Buffer.byteLength(secret)}`)
    expect(text).not.toContain(secret)

    await sup.stop(spec.id, { force: true })
  })

  it('captures real stdout and stderr separately, line by line', async () => {
    const sup = new Supervisor({ runRoot: root })
    const spec: SupervisedSpec = {
      id: 'real-2',
      command: process.execPath,
      args: [
        FIXTURE,
        '--print=hello from stdout',
        '--stderr=hello from stderr',
        '--ready-after=0',
        '--stay'
      ],
      cwd: root,
      readiness: readyOnLine('READY'),
      readinessTimeoutMs: 10_000,
      restart: 'never',
      backoff: { baseMs: 100, maxMs: 100, jitter: 0 },
      crashLoop: { windowMs: 120_000, maxRestarts: 5 },
      logRing: { maxLines: 500, maxBytes: 1 << 20 },
      redact: []
    }

    const handle = await sup.spawn(spec)
    const lines = handle.logs()
    expect(lines.some((l) => l.stream === 'stdout' && l.text === 'hello from stdout')).toBe(true)
    expect(lines.some((l) => l.stream === 'stderr' && l.text === 'hello from stderr')).toBe(true)

    await sup.stop(spec.id, { force: true })
  })

  it('holds the byte cap against a real 4 MB single line', async () => {
    const sup = new Supervisor({ runRoot: root })
    const spec: SupervisedSpec = {
      id: 'real-2b',
      command: process.execPath,
      args: [FIXTURE, '--huge-line=4000000', '--stay'],
      cwd: root,
      // Not keyed off a log line: the 4 MB line this test is about would
      // evict the readiness marker from the ring before it could be seen.
      readiness: async () => {},
      readinessTimeoutMs: 10_000,
      restart: 'never',
      backoff: { baseMs: 100, maxMs: 100, jitter: 0 },
      crashLoop: { windowMs: 120_000, maxRestarts: 5 },
      // A line cap of 500 would happily hold 4 MB; the byte cap is the bound.
      logRing: { maxLines: 500, maxBytes: 65_536 },
      redact: []
    }

    const handle = await sup.spawn(spec)
    await waitFor(() => handle.logs().some((l) => l.text.startsWith('HHH')))

    const lines = handle.logs()
    expect(lines.reduce((n, l) => n + Buffer.byteLength(l.text, 'utf8'), 0)).toBeLessThanOrEqual(
      65_536
    )
    const huge = lines.find((l) => l.text.startsWith('HHH'))
    expect(huge?.text.endsWith('[truncated]')).toBe(true)
    expect(Buffer.byteLength(huge?.text ?? '', 'utf8')).toBeLessThanOrEqual(65_536)

    await sup.stop(spec.id, { force: true })
  })

  it('stops a child that ignores SIGTERM by escalating to SIGKILL', async () => {
    const sup = new Supervisor({ runRoot: root })
    const order: string[] = []
    const spec: SupervisedSpec = {
      id: 'real-3',
      command: process.execPath,
      args: [FIXTURE, '--ignore-sigterm', '--ready-after=0', '--stay'],
      cwd: root,
      readiness: readyOnLine('READY'),
      readinessTimeoutMs: 10_000,
      gracefulTimeoutMs: 50,
      gracefulStop: async () => {
        order.push('graceful')
      },
      restart: 'never',
      backoff: { baseMs: 100, maxMs: 100, jitter: 0 },
      crashLoop: { windowMs: 120_000, maxRestarts: 5 },
      logRing: { maxLines: 500, maxBytes: 1 << 20 },
      redact: []
    }

    const handle = await sup.spawn(spec)
    const exits: { signal: NodeJS.Signals | null }[] = []
    handle.onExit((e) => exits.push({ signal: e.signal }))

    await sup.stop(spec.id)
    expect(order).toEqual(['graceful'])
    expect(exits.at(-1)?.signal).toBe('SIGKILL')
  }, 20_000)
})
