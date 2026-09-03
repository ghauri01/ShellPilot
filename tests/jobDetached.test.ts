import { describe, it, expect, beforeEach, afterEach } from 'vitest'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import {
  DISABLE_ENV,
  loadHistory,
  resetHistoryModuleForTests,
  type HistoryStore
} from '../src/main/services/history'
import { JobRunner, type JobExecResult, type JobExecutor } from '../src/main/services/jobRunner'
import { detachedJobExecutor, type JobRunResult } from '../src/main/services/jobDetached'
import { assessCommand } from '../src/shared/broadcast'
import type { JobHostCapabilityReport, JobOutput, JobProgress, JobSpec } from '../src/shared/jobs'
import {
  JOB_CMD_PREFIX,
  JOB_LAUNCH_GRACE_MS,
  JOB_RECONNECT_BASE_MS,
  JOB_RECONNECT_GLOBAL_MAX,
  JOB_RECONNECT_MAX_MS,
  buildJobPoll,
  buildJobProbe,
  isJobDetachedHandle,
  nextRetryDelay,
  restartsTheMachine
} from '../src/shared/jobs'

// B2: a job that outlives the connection that started it.
//
// ---------------------------------------------------------------------------
// THE FAKE HOST IS DRIVEN BY THE BUILDERS, NOT BY A SCRIPT OF ITS OWN
// ---------------------------------------------------------------------------
// `FakeHost.run()` takes the command string `shared/jobs.ts` produced and
// PARSES it: the verb and marker directory out of JOB_CMD_PREFIX, the instance
// id and the command out of the launch wrapper, the offset and window out of
// the poll. It then answers in the exact format the parsers in that file read
// back.
//
// That is the whole point of the arrangement. A fake with its own idea of what
// a marker directory looks like would go on passing after somebody changed the
// wrapper, and the tests below would be checking a simulation of last week's
// design. This one fails loudly instead: rename a file, move a header line or
// change the prefix, and the fake stops recognising its own protocol.
//
// ---------------------------------------------------------------------------
// NO SLEEPS. ANYWHERE.
// ---------------------------------------------------------------------------
// logTailer.test.ts's deferredHarness, extended: the executor's `sleep` is
// injected and every wait is HELD until the test releases it by hand, so
// "this host has not been polled yet" is an assertion rather than a hope. This
// session found three flaky tests and all three were real production bugs; a
// suite that synchronises on setTimeout(5) is one that gets flakier as the
// state machine grows, and this state machine grows again in B3 and B4.
//
// ---------------------------------------------------------------------------
// WHAT THIS FILE CANNOT TEST, SAID PLAINLY
// ---------------------------------------------------------------------------
// Everything below runs against a fake host, so it proves that the WRAPPERS ARE
// BUILT AND READ CORRECTLY and that the state machine over them is right. It
// cannot prove anything about a real sshd or a real kernel. Specifically:
//
//  1. WHETHER A REAL sshd KILLS A setsid CHILD when the exec channel closes.
//     This is the single assumption the whole item rests on. It depends on the
//     server's SIGHUP behaviour and on all three standard streams being
//     redirected away from the channel — the fake cannot observe either.
//  2. WHETHER $HOME IS WRITABLE, or on an autofs mount that is not there at
//     boot, or full. The probe's three-candidate fallback is exercised here by
//     making the fake answer differently; that the fallback ORDER is the right
//     one for a real estate is a judgement, not a test.
//  3. WHETHER `setsid` EXECS OR FORKS on a given shell, which decides whether
//     `$!` would have been the right pid. The wrapper writes its own `$$`
//     precisely so this does not matter, and that is the argument, not a proof.
//  4. WHETHER `ps -o args=` IS AVAILABLE AND SHOWS THE MARKER DIRECTORY on
//     every distribution. The `pidcheck=weak` path exists for the hosts where
//     it is not.
//  5. WHETHER A MARKER SURVIVES A REBOOT under /var/tmp on a distribution with
//     an aggressive tmpfiles.d policy.
//
// THE MANUAL MATRIX, to be run once per release against a real host:
//
//   | Host                        | Check                                     |
//   |-----------------------------|-------------------------------------------|
//   | Debian 12 / OpenSSH default | launch, close the laptop lid mid-`sleep`, |
//   |                             | reopen: job still running, output resumes |
//   | Ubuntu 24.04 + unattended-  | `apt full-upgrade` detached, drop the     |
//   | upgrades                    | link at 60s: no dpkg interruption, rc     |
//   |                             | arrives on reconnect                      |
//   | Alpine (busybox, no setsid) | probe reports launcher=nohup; job runs;   |
//   |                             | UI names the host as degraded if neither  |
//   | RHEL 9 with SELinux         | marker created under ~/.local/state, no    |
//   |                             | AVC denial in `ausearch`                  |
//   | Read-only $HOME image       | falls through to /var/tmp/shellpilot-$uid |
//   | Any host, then `reboot`     | state reads `rebooting`, not unreachable; |
//   |                             | after boot the marker is gone or orphaned |
//   | Two ShellPilots, one host   | the second reads output and rc, refuses   |
//   |                             | to reap, reports `foreign`                |

const DAY = 86_400_000

// --------------------------------------------------------------- the fake host

interface Marker {
  cmd: string
  instance: string
  /** Null until the wrapper has "written" its pid — the launch window. */
  pid: number | null
  pgid: number | null
  out: Buffer
  rc: number | null
  /** False once the process is gone, however it went. */
  alive: boolean
}

interface FakeOpts {
  root?: string | null
  launcher?: 'setsid' | 'nohup' | 'none'
  base64?: boolean
  /** No usable `ps`, so `alive` can only be decided by kill -0. */
  weakPidCheck?: boolean
  /** The probe answers with something this build does not understand. */
  probeGarbage?: boolean
}

/**
 * A host with a virtual marker directory, driven by the real builders.
 *
 * Test verbs: `write`, `exit`, `kill`, `disconnect`, `reconnect`, `steal`.
 */
class FakeHost {
  readonly dirs = new Map<string, Marker>()
  readonly commands: string[] = []
  /** What each signal actually did, in order. */
  readonly signals: string[] = []
  connected = true
  private nextPid = 4000

  constructor(private readonly opts: FakeOpts = {}) {}

  /** The single seam. Everything the executor does to a host goes through it. */
  run = async (_cfg: unknown, command: string, _timeoutMs: number): Promise<JobRunResult> => {
    this.commands.push(command)
    if (!this.connected) {
      return { ok: false, code: null, stdout: '', stderr: '', error: 'Timed out after 30000ms connecting' }
    }
    const m = JOB_CMD_PREFIX.exec(command)
    if (!m) {
      throw new Error(
        `the fake host does not recognise this command, which means shared/jobs.ts changed its ` +
          `wrapper and this fake is now simulating a protocol nothing speaks:\n${command.slice(0, 200)}`
      )
    }
    const verb = m[1]
    const dir = m[2] === 'auto' ? '' : unquote(m[2])
    switch (verb) {
      case 'probe':
        return this.probe()
      case 'launch':
        return this.launch(dir, command)
      case 'poll':
        return this.poll(dir, command)
      case 'signal':
        return this.signal(dir)
      case 'reap':
        return this.reap(dir)
      default:
        throw new Error(`unknown verb ${verb}`)
    }
  }

  // -- verbs -----------------------------------------------------------------

  private probe(): JobRunResult {
    if (this.opts.probeGarbage) return ok('sh: 1: Syntax error: word unexpected\n')
    const root = this.opts.root === undefined ? '/var/tmp/shellpilot-1000/jobs' : this.opts.root
    return ok(
      [
        'shellpilot-probe/1',
        `launcher=${this.opts.launcher ?? 'setsid'}`,
        `base64=${this.opts.base64 === false ? 'no' : 'yes'}`,
        'uid=1000',
        `root=${root ?? ''}`,
        ''
      ].join('\n')
    )
  }

  private launch(dir: string, command: string): JobRunResult {
    // Parsed out of the real wrapper, so a change to how the instance is
    // recorded, or to the heredoc, breaks this rather than being simulated.
    const instance = /printf '%s\\n' '([^']+)' > "\$SP_JOB_DIR\/instance"/.exec(command)?.[1]
    const eof = /<<'(SPJOB_[A-Za-z0-9_]+_EOF)'/.exec(command)?.[1]
    expect(instance, 'the launch wrapper no longer records an instance id').toBeTruthy()
    expect(eof, 'the launch wrapper no longer writes the command through a heredoc').toBeTruthy()
    const body = command.slice(command.indexOf(`<<'${eof}'`) + `<<'${eof}'`.length + 1)
    const cmd = body.slice(0, body.indexOf(`\n${eof}`))
    expect(command, 'the launch must redirect all three streams or the channel cannot close').toContain(
      '</dev/null >/dev/null 2>&1 &'
    )
    this.dirs.set(dir, {
      cmd,
      instance: instance as string,
      pid: null,
      pgid: null,
      out: Buffer.alloc(0),
      rc: null,
      alive: true
    })
    // The wrapper's own first act, simulated: it writes its pid, and under
    // setsid it is a session leader so pgid === pid.
    const pid = this.nextPid++
    const marker = this.dirs.get(dir) as Marker
    marker.pid = pid
    marker.pgid = (this.opts.launcher ?? 'setsid') === 'setsid' ? pid : 3000
    return ok('shellpilot-launch/1\nerror=\n')
  }

  private poll(dir: string, command: string): JobRunResult {
    const off = Number(/SP_JOB_OFF=(\d+);/.exec(command)?.[1] ?? -1)
    const max = Number(/SP_JOB_MAX=(\d+);/.exec(command)?.[1] ?? -1)
    expect(off, 'the poll no longer carries an offset').toBeGreaterThanOrEqual(0)
    expect(max, 'the poll no longer carries a window size').toBeGreaterThan(0)
    const b64 = command.includes('| base64 |')
    const marker = this.dirs.get(dir)
    if (!marker) return ok('shellpilot-poll/1\nmarker=missing\nbody/1\n')

    const size = marker.out.length
    const sent = Math.max(0, Math.min(size - off, max))
    const slice = marker.out.subarray(off, off + sent)
    const head = [
      'shellpilot-poll/1',
      'marker=present',
      `instance=${marker.instance}`,
      `pid=${marker.pid ?? ''}`,
      `pgid=${marker.pgid ?? ''}`,
      // rc is read BEFORE the output on the real host, and the fake keeps that
      // order so a test that reorders them here would be testing a poll that
      // could report `finished` with output still to come.
      `rc=${marker.rc ?? ''}`,
      `alive=${marker.alive && marker.pid !== null ? 'yes' : 'no'}`,
      `pidcheck=${this.opts.weakPidCheck ? 'weak' : 'strong'}`,
      `size=${size}`,
      `sent=${sent}`,
      'body/1'
    ].join('\n')
    return ok(`${head}\n${b64 ? slice.toString('base64') : slice.toString('utf8')}`)
  }

  private signal(dir: string): JobRunResult {
    const marker = this.dirs.get(dir)
    if (!marker || marker.pid === null) {
      this.signals.push('none')
      return ok('shellpilot-signal/1\nsignalled=none\n')
    }
    marker.alive = false
    // The rule the builder encodes: the group only goes when the wrapper leads
    // it, which under setsid it does and under nohup it does not.
    const outcome = marker.pid === marker.pgid ? 'group' : 'process'
    this.signals.push(outcome)
    return ok(`shellpilot-signal/1\nsignalled=${outcome}\n`)
  }

  private reap(dir: string): JobRunResult {
    this.dirs.delete(dir)
    return ok('shellpilot-reap/1\nreaped=yes\n')
  }

  // -- test verbs ------------------------------------------------------------

  /** The command produced output. */
  write(dir: string, text: string): void {
    const m = this.marker(dir)
    m.out = Buffer.concat([m.out, Buffer.from(text, 'utf8')])
  }

  /** The command finished and the wrapper recorded its status. */
  exit(dir: string, rc: number): void {
    const m = this.marker(dir)
    m.rc = rc
    m.alive = false
  }

  /** The wrapper died without recording anything: OOM, kill -9, or the host
   *  going down under it. */
  kill(dir: string): void {
    this.marker(dir).alive = false
  }

  /** A different ShellPilot launched this. */
  steal(dir: string, instance: string): void {
    this.marker(dir).instance = instance
  }

  disconnect(): void {
    this.connected = false
  }

  reconnect(): void {
    this.connected = true
  }

  /** The one marker directory, when there is only one. */
  get dir(): string {
    const keys = [...this.dirs.keys()]
    expect(keys, 'expected exactly one marker directory').toHaveLength(1)
    return keys[0]
  }

  marker(dir: string): Marker {
    const m = this.dirs.get(dir)
    if (!m) throw new Error(`no marker directory at ${dir}`)
    return m
  }

  countVerb(verb: string): number {
    return this.commands.filter((c) => c.startsWith(`SP_JOB_VERB=${verb};`)).length
  }
}

function ok(stdout: string): JobRunResult {
  return { ok: true, code: 0, stdout, stderr: '' }
}

function unquote(q: string): string {
  return q.slice(1, -1).split(`'\\''`).join("'")
}

// ------------------------------------------------------------------- harness

/**
 * An executor whose every wait is held until the test lets it go.
 *
 * `pending` is the load-bearing half: `expect(h.pending).toBe(0)` is how "this
 * host has NOT been polled" is asserted, rather than "the poll count did not go
 * up yet", which a racing implementation could satisfy by being slow.
 */
function harness(host: FakeHost, over: Partial<Parameters<typeof detachedJobExecutor>[0]> = {}) {
  const waits: (() => void)[] = []
  const waited: number[] = []
  const attachedCalls: string[] = []
  const caps: JobHostCapabilityReport[] = []
  let clock = 1_000

  const attached: JobExecutor = async (req) => {
    attachedCalls.push(req.command)
    req.onOutput('out', 'attached output\n')
    return { ok: true, code: 0 }
  }

  const exec = detachedJobExecutor({
    run: host.run,
    instanceId: 'sp-me',
    attached,
    enabled: () => true,
    now: () => clock,
    sleep: (ms) =>
      new Promise<void>((resolve) => {
        waited.push(ms)
        waits.push(resolve)
      }),
    // Mid-window, so the equal-jitter arithmetic is exact and asserted rather
    // than sampled.
    random: () => 0.5,
    onCapability: (r) => caps.push(r),
    pollMs: 3_000,
    pollBytes: 64,
    ...over
  })

  const flush = async (): Promise<void> => {
    for (let i = 0; i < 50; i++) await Promise.resolve()
  }

  return {
    exec,
    caps,
    attachedCalls,
    waited,
    get pending(): number {
      return waits.length
    },
    advance: (ms: number) => {
      clock += ms
    },
    /** Release the next held wait and let everything it unblocks run. */
    tick: async (): Promise<void> => {
      const next = waits.shift()
      expect(next, 'nothing was waiting — the poller is not where the test thinks it is').toBeDefined()
      ;(next as () => void)()
      await flush()
    },
    flush
  }
}

function request(over: Record<string, unknown> = {}) {
  const output: string[] = []
  const states: { state?: string; degraded?: string; detached?: unknown; error?: string }[] = []
  let alive = true
  return {
    output,
    states,
    stop: () => {
      alive = false
    },
    req: {
      cfg: { id: 'a' },
      command: 'apt full-upgrade -y',
      timeoutMs: 900_000,
      jobId: 'job1',
      serverId: 'a',
      serverName: 'web-1',
      step: 1,
      alive: () => alive,
      onState: (u: never) => states.push(u),
      onOutput: (_s: 'out' | 'err', t: string) => output.push(t),
      ...over
    }
  }
}

// =========================================================================
// The launch, and exactly what it puts on the host
// =========================================================================

describe('what a detached launch writes to a host', () => {
  it('creates one directory with five files, and nothing that runs afterwards', async () => {
    const host = new FakeHost()
    const h = harness(host)
    const { req } = request()
    const p = h.exec(req)
    await h.flush()

    expect(host.dirs.size).toBe(1)
    const launch = host.commands.find((c) => c.startsWith('SP_JOB_VERB=launch;')) as string
    // The five files, named. If a sixth appears this assertion is where the
    // decision to write it gets made, rather than in a diff nobody read.
    for (const f of ['/cmd', '/instance', '/pid', '/pgid', '/out', '/rc']) {
      expect(launch, `the wrapper should still write ${f}`).toContain(f)
    }
    // And nothing that outlives the command.
    for (const forbidden of ['crontab', 'systemctl', 'systemd-run', 'apt-get install', 'curl ', 'wget ']) {
      expect(launch, `a detached launch must not ${forbidden}`).not.toContain(forbidden)
    }
    // rc is renamed into place, which is what makes its presence mean complete.
    expect(launch).toContain('mv "$1/rc.tmp" "$1/rc"')

    host.exit(host.dir, 0)
    await h.tick()
    expect((await p).ok).toBe(true)
  })

  it('reaps the directory once the exit status has been read', async () => {
    const host = new FakeHost()
    const h = harness(host)
    const { req } = request()
    const p = h.exec(req)
    await h.flush()
    const dir = host.dir
    host.write(dir, 'done\n')
    host.exit(dir, 0)
    await h.tick()
    const r = await p
    expect(r.code).toBe(0)
    expect(host.dirs.has(dir), 'the marker directory should be gone once its answer is in hand').toBe(false)
    expect(host.countVerb('reap')).toBe(1)
  })

  it('refuses to launch a command carrying its own heredoc delimiter', async () => {
    // Belt and braces on the one way a command could break out of the wrapper.
    const host = new FakeHost()
    const h = harness(host)
    const { req } = request({ command: 'echo hi\nSPJOB_job1_EOF\nrm -rf /' })
    await expect(h.exec(req)).rejects.toThrow(/heredoc delimiter/)
  })
})

// =========================================================================
// The link drops
// =========================================================================

describe('when the connection dies underneath a running job', () => {
  it('reports the host as detached, not unreachable', async () => {
    // THE HEADLINE. `unreachable` points at the host and means "go and look at
    // that machine"; the machine is fine and the upgrade is still going. On the
    // attached path this same event was dpkg taking a SIGHUP.
    const host = new FakeHost()
    const h = harness(host)
    const { req, states } = request()
    const p = h.exec(req)
    await h.flush()
    host.disconnect()
    await h.tick()

    expect(states.map((s) => s.state)).toEqual(['detached'])
    expect(states[0].detached, 'the marker must be on the row before the first poll').toBeTruthy()
    // And it is still going: the executor has not settled.
    let settled = false
    void p.then(() => {
      settled = true
    })
    await h.flush()
    expect(settled).toBe(false)

    host.reconnect()
    host.exit(host.dir, 0)
    await h.tick()
    expect((await p).code).toBe(0)
  })

  it('picks the exit status up on the first successful poll after reconnecting', async () => {
    const host = new FakeHost()
    const h = harness(host)
    const { req } = request()
    const p = h.exec(req)
    await h.flush()
    const dir = host.dir

    host.write(dir, 'step one\n')
    host.disconnect()
    // Three failed polls while the link is down.
    await h.tick()
    await h.tick()
    await h.tick()
    // The command finished while nobody could see it.
    host.write(dir, 'step two\n')
    host.exit(dir, 7)
    host.reconnect()

    const before = host.countVerb('poll')
    await h.tick()
    const r = await p
    expect(r.code, 'the exit status must arrive on the FIRST poll that gets through').toBe(7)
    expect(host.countVerb('poll') - before).toBe(1)
    expect(r.ok).toBe(true)
  })

  it('backs off with equal jitter, capped, and never faster than the base', () => {
    // Asserted arithmetic rather than a sampled distribution: `rand` is
    // injected precisely so a schedule is a fact.
    const lo = nextRetryDelay(1, () => 0)
    const hi = nextRetryDelay(1, () => 1)
    expect(lo).toBe(JOB_RECONNECT_BASE_MS / 2)
    expect(hi).toBe(JOB_RECONNECT_BASE_MS)
    expect(nextRetryDelay(2, () => 0.5)).toBe(JOB_RECONNECT_BASE_MS * 1.5)
    // Capped, and the cap holds for an attempt count no loop would ever reach.
    expect(nextRetryDelay(40, () => 1)).toBe(JOB_RECONNECT_MAX_MS)
    expect(Number.isFinite(nextRetryDelay(1024, () => 1))).toBe(true)
  })

  it('waits the backoff, not the poll interval, while the link is down', async () => {
    const host = new FakeHost()
    const h = harness(host)
    const { req } = request()
    const p = h.exec(req)
    await h.flush()
    host.disconnect()
    await h.tick() // the poll that fails
    await h.tick() // the first retry, which also fails
    // First wait is the healthy cadence; the two after it are the backoff.
    // 3s is the healthy cadence; then equal jitter at rand()=0.5 over windows
    // of 2s and 4s.
    expect(h.waited.slice(0, 3)).toEqual([3_000, 1_500, 3_000])
    host.reconnect()
    host.exit(host.dir, 0)
    await h.tick()
    await p
  })

  it('lets only JOB_RECONNECT_GLOBAL_MAX hosts dial at once', async () => {
    // The laptop-wake case: every host notices the dead link in the same
    // millisecond, and per-host backoff cannot help because they are
    // synchronised by the wake rather than by each other. The cap is therefore
    // across the app — one executor, one gate, which is what main constructs.
    const hosts = new Map<string, FakeHost>()
    for (let i = 0; i < 6; i++) hosts.set(`h${i}`, new FakeHost())
    const holds: (() => void)[] = []
    let holding = false
    let inFlight = 0
    let peak = 0

    const h = harness(hosts.get('h0') as FakeHost, {
      run: async (cfg, command, ms) => {
        const host = hosts.get((cfg as { id: string }).id) as FakeHost
        if (holding && command.startsWith('SP_JOB_VERB=poll;')) {
          inFlight++
          peak = Math.max(peak, inFlight)
          await new Promise<void>((r) => holds.push(r))
          inFlight--
        }
        return host.run(cfg, command, ms)
      }
    })

    const runs = [...hosts.keys()].map((id) => {
      const { req } = request({ cfg: { id }, serverId: id, serverName: id })
      return h.exec(req)
    })
    await h.flush()
    expect([...hosts.values()].every((x) => x.dirs.size === 1)).toBe(true)

    // Every host loses the link at once, and every host fails its first poll.
    for (const host of hosts.values()) host.disconnect()
    for (let i = 0; i < 6; i++) await h.tick()

    // Now they all retry together, and the run is held so the gate is
    // observable rather than instantaneous.
    holding = true
    for (let i = 0; i < 6; i++) await h.tick()
    expect(peak, 'six hosts must not dial one bastion at once').toBe(JOB_RECONNECT_GLOBAL_MAX)
    expect(holds).toHaveLength(JOB_RECONNECT_GLOBAL_MAX)

    // A slot released is HANDED ON, not returned to a counter, so the host that
    // has been waiting longest goes next rather than whoever asks first.
    holds.shift()?.()
    await h.flush()
    expect(peak).toBe(JOB_RECONNECT_GLOBAL_MAX)
    expect(inFlight).toBe(JOB_RECONNECT_GLOBAL_MAX)

    // Drain: let everything through, bring the link back and let each job end.
    holding = false
    while (holds.length > 0) {
      holds.shift()?.()
      await h.flush()
    }
    for (const host of hosts.values()) {
      host.reconnect()
      host.exit(host.dir, 0)
    }
    while (h.pending > 0) await h.tick()
    expect((await Promise.all(runs)).every((r) => r.code === 0)).toBe(true)
  })
})

// =========================================================================
// The cursor
// =========================================================================

describe('the output cursor across a dropped link', () => {
  it('never rewinds and never repeats a byte across the seam', async () => {
    // The failure this is written against: a poller that counted the bytes it
    // RECEIVED rather than the window the host closed would re-send the overlap
    // after a reconnect, and a reader would see the middle of an upgrade twice.
    const host = new FakeHost()
    const h = harness(host)
    const { req, output, states } = request()
    const p = h.exec(req)
    await h.flush()
    const dir = host.dir

    host.write(dir, 'A'.repeat(30))
    await h.tick()
    host.write(dir, 'B'.repeat(30))
    host.disconnect()
    await h.tick()
    host.write(dir, 'C'.repeat(30))
    host.reconnect()
    await h.tick()
    host.exit(dir, 0)
    await h.tick()
    await p

    const seen = output.join('')
    expect(seen).toBe('A'.repeat(30) + 'B'.repeat(30) + 'C'.repeat(30))
    // The offset only ever moves forward, and lands exactly on what the host
    // wrote.
    const offsets = states
      .filter((s) => isJobDetachedHandle(s.detached))
      .map((s) => (s.detached as { readOffset: number }).readOffset)
    expect(offsets).toEqual([...offsets].sort((x, y) => x - y))
    expect(offsets[offsets.length - 1]).toBe(90)
  })

  it('drains a backlog bigger than one window without waiting between reads', async () => {
    const host = new FakeHost()
    const h = harness(host)
    const { req, output } = request()
    const p = h.exec(req)
    await h.flush()
    const dir = host.dir
    // Four windows' worth against a 64-byte window.
    host.write(dir, 'x'.repeat(250))
    host.exit(dir, 0)
    await h.tick()
    await p
    expect(output.join('')).toBe('x'.repeat(250))
    // One held wait, four polls — 64+64+64+58 — so the drain does not pay the
    // poll interval per window, which on a chatty upgrade is minutes of lag.
    expect(host.countVerb('poll')).toBe(4)
    expect(h.pending, 'and it did not schedule a wait it never used').toBe(0)
  })

  it('does not split a multi-byte character across a poll boundary', async () => {
    // The window is closed in BYTES on the host, so it can land in the middle of
    // a UTF-8 sequence. Decoding each poll on its own puts a replacement
    // character on both sides of every such boundary — in output somebody is
    // reading to find out what went wrong.
    const host = new FakeHost()
    const h = harness(host, { pollBytes: 7 })
    const { req, output } = request()
    const p = h.exec(req)
    await h.flush()
    const dir = host.dir
    const text = 'aé☃𝄞bcd'
    host.write(dir, text)
    host.exit(dir, 0)
    await h.tick()
    await p
    expect(output.join('')).toBe(text)
    expect(output.join('')).not.toContain('�')
  })
})

// =========================================================================
// Reclaim: the three-way, plus foreign
// =========================================================================

describe('reclaiming a marker', () => {
  it('reports orphaned when the marker is there, the pid is gone and no rc was written', async () => {
    const host = new FakeHost()
    const h = harness(host)
    const { req } = request()
    const p = h.exec(req)
    await h.flush()
    const dir = host.dir
    host.write(dir, 'half an upgrade\n')
    host.kill(dir)
    await h.tick()
    const r = await p
    expect(r.finalState).toBe('orphaned')
    expect(r.finalOutcome).toBe('orphaned')
    expect(r.error).toMatch(/no exit status was ever written/i)
    // The output it did produce is not thrown away with it.
    expect(host.dirs.has(dir)).toBe(false)
  })

  it('does not mistake a recycled pid for a live job', async () => {
    // After a reboot the recorded pid is very likely to belong to somebody
    // else. The strong check asks whether the process's argument list still
    // names this marker directory; the fake models a host where it does not.
    const host = new FakeHost()
    const h = harness(host)
    const { req } = request()
    const p = h.exec(req)
    await h.flush()
    const poll = host.commands.find((c) => c.startsWith('SP_JOB_VERB=poll;'))
    expect(poll, 'the poll must verify the pid, not merely kill -0 it').toBeUndefined()
    host.kill(host.dir) // pid gone: the strong check answers no
    await h.tick()
    expect((await p).finalState).toBe('orphaned')
    const polled = host.commands.find((c) => c.startsWith('SP_JOB_VERB=poll;')) as string
    expect(polled).toContain('ps -o args= -p "$SP_PID"')
    expect(polled).toContain('grep -qF -- "$SP_JOB_DIR"')
  })

  it('reads a foreign marker, and refuses to reap it', async () => {
    // Detect and degrade, do not lock. Two ShellPilots against one estate is a
    // real configuration, and a lock file would turn it into a job neither of
    // them can read.
    const host = new FakeHost()
    const h = harness(host)
    const { req, states, output } = request()
    const p = h.exec(req)
    await h.flush()
    const dir = host.dir
    host.steal(dir, 'sp-someone-else')
    host.write(dir, 'their output\n')
    host.exit(dir, 3)
    await h.tick()
    const r = await p

    expect(states.some((s) => s.state === 'foreign')).toBe(true)
    expect(output.join('')).toContain('their output')
    expect(r.code, 'the exit status is readable by anyone who can see the marker').toBe(3)
    expect(host.countVerb('reap')).toBe(0)
    expect(host.dirs.has(dir), 'another instance still needs that directory').toBe(true)
    expect(r.detachedHandle, 'the row keeps the handle, because the marker is still there').toBeTruthy()
  })

  it('says so when the marker has been removed underneath it', async () => {
    const host = new FakeHost()
    const h = harness(host)
    const { req } = request()
    const p = h.exec(req)
    await h.flush()
    host.dirs.clear()
    await h.tick()
    const r = await p
    expect(r.finalState).toBe('orphaned')
    expect(r.error).toMatch(/no longer on the host/i)
  })
})

// =========================================================================
// An expected reboot
// =========================================================================

describe('a step that restarts the machine', () => {
  it('is rebooting, not unreachable, while the host is down', async () => {
    const host = new FakeHost()
    const h = harness(host)
    const { req, states } = request({ command: 'sudo reboot' })
    const p = h.exec(req)
    await h.flush()
    host.disconnect()
    await h.tick()
    expect(states.map((s) => s.state)).toEqual(['detached', 'rebooting'])
    host.reconnect()
    host.kill(host.dir)
    await h.tick()
    // It comes back orphaned, which is the truth: the wrapper went down with
    // the machine and never wrote a status.
    expect((await p).finalState).toBe('orphaned')
  })

  it('agrees with broadcast about what restarts a machine', () => {
    // Two rules in two files with two different consequences. They may diverge
    // deliberately; they may not diverge by accident.
    for (const cmd of [
      'reboot',
      'sudo reboot',
      'shutdown -r now',
      'systemctl reboot',
      'sudo systemctl poweroff',
      'apt upgrade -y && sudo reboot'
    ]) {
      expect(restartsTheMachine(cmd), cmd).toBe(true)
      expect(assessCommand(cmd).risk, cmd).toBe('destructive')
    }
    // And the anchor holds: a read that merely mentions the word is not a
    // reboot, which is the whole reason the rule is not a substring search.
    for (const cmd of ['grep reboot /var/log/syslog', 'echo "reboot required"']) {
      expect(restartsTheMachine(cmd), cmd).toBe(false)
    }
  })
})

// =========================================================================
// Degrading
// =========================================================================

describe('a host that cannot detach', () => {
  it('falls back to the attached executor and says which host and why', async () => {
    const host = new FakeHost({ root: null })
    const h = harness(host)
    const { req, states, output } = request()
    const r = await h.exec(req)

    expect(host.dirs.size, 'nothing may be written to a host that failed the probe').toBe(0)
    expect(h.attachedCalls).toEqual(['apt full-upgrade -y'])
    expect(output.join('')).toBe('attached output\n')
    expect(r.ok).toBe(true)
    const degraded = states.find((s) => s.degraded)
    expect(degraded?.degraded).toMatch(/nowhere to keep a job marker/i)
    // And the Settings row is told, per host, by name.
    expect(h.caps).toHaveLength(1)
    expect(h.caps[0]).toMatchObject({ serverId: 'a', serverName: 'web-1', detached: false })
    expect(h.caps[0].reason).toMatch(/nowhere to keep a job marker/i)
  })

  it('falls back when neither setsid nor nohup is installed', async () => {
    const host = new FakeHost({ launcher: 'none' })
    const h = harness(host)
    const { req, states } = request()
    await h.exec(req)
    expect(h.attachedCalls).toHaveLength(1)
    expect(states.find((s) => s.degraded)?.degraded).toMatch(/neither setsid nor nohup/i)
  })

  it('falls back when the host answers the probe with something else entirely', async () => {
    const host = new FakeHost({ probeGarbage: true })
    const h = harness(host)
    const { req } = request()
    await h.exec(req)
    expect(h.attachedCalls).toHaveLength(1)
    expect(h.caps[0].reason).toMatch(/may not be a POSIX sh/i)
  })

  it('probes a host once, not once per step', async () => {
    const host = new FakeHost({ root: null })
    const h = harness(host)
    for (let step = 1; step <= 3; step++) {
      const { req } = request({ step })
      await h.exec(req)
    }
    expect(host.countVerb('probe')).toBe(1)
    expect(h.attachedCalls).toHaveLength(3)
  })

  it('runs attached, writing nothing, when the Settings switch is off', async () => {
    const host = new FakeHost()
    const h = harness(host, { enabled: () => false })
    const { req } = request()
    const r = await h.exec(req)
    expect(host.commands, 'the switch means nothing at all is sent to the host').toEqual([])
    expect(h.attachedCalls).toHaveLength(1)
    expect(r.ok).toBe(true)
  })

  it('uses the base64 body only where the host has base64', async () => {
    const host = new FakeHost({ base64: false })
    const h = harness(host)
    const { req, output } = request()
    const p = h.exec(req)
    await h.flush()
    host.write(host.dir, 'plain bytes\n')
    host.exit(host.dir, 0)
    await h.tick()
    await p
    expect(output.join('')).toBe('plain bytes\n')
    const poll = host.commands.find((c) => c.startsWith('SP_JOB_VERB=poll;')) as string
    expect(poll).not.toContain('| base64 |')
  })
})

// =========================================================================
// The vault
// =========================================================================

describe('when the vault is locked', () => {
  it('parks rather than erroring, and does not touch the host', async () => {
    // fleetSampler's rule. The difference is the consequence: a parked SAMPLE
    // loses a data point, and a parked POLL loses nothing, because the byte
    // cursor makes the next one pick up exactly where this would have.
    const host = new FakeHost()
    let unlocked = true
    const h = harness(host, { vaultUnlocked: () => unlocked, parkMs: 10_000 })
    const { req, states } = request()
    const p = h.exec(req)
    await h.flush()
    const dir = host.dir

    unlocked = false
    // The first tick releases the poll that was already scheduled; every wait
    // after it is a park, and a park touches nothing.
    await h.tick()
    const before = host.commands.length
    await h.tick()
    await h.tick()
    expect(host.commands.length, 'a locked vault must not open a connection').toBe(before)
    expect(h.waited.slice(-1)).toEqual([10_000])
    expect(states.some((s) => /vault is locked/i.test(s.error ?? ''))).toBe(true)

    unlocked = true
    host.write(dir, 'kept going the whole time\n')
    host.exit(dir, 0)
    // One tick to leave the park, one to take the poll it then schedules.
    await h.tick()
    await h.tick()
    const r = await p
    expect(r.code).toBe(0)
  })
})

// =========================================================================
// Timeouts and signals
// =========================================================================

describe('a detached step that runs past its timeout', () => {
  it('signals the remote process group before it gives up', async () => {
    // A timeout that leaves the command running has decided nothing, and it
    // costs more here than on the attached path: "still running" means a real
    // process that outlives this app.
    const host = new FakeHost()
    const h = harness(host)
    const { req } = request({ timeoutMs: 5_000 })
    const p = h.exec(req)
    await h.flush()
    const dir = host.dir
    h.advance(60_000)
    // One tick: the poll notices the deadline, signals, and re-reads at once
    // rather than paying another interval to find out what it did.
    await h.tick()
    const r = await p
    expect(host.countVerb('signal')).toBe(1)
    expect(r.error).toMatch(/timed out/i)
    // A process that is gone because WE signalled it is a timeout, not an
    // orphan: `orphaned` means nobody knows why it stopped, and here we do.
    expect(r.finalOutcome).toBe('timeout')
    expect(r.finalState, 'and it is a plain failure, not an unknown').toBeUndefined()
    expect(host.dirs.has(dir), 'nothing more can be read from it, so it is reaped').toBe(false)
  })

  it('kills the whole group under setsid and only the process under nohup', async () => {
    // apt is a parent and dpkg is where the work is, so the group is what has
    // to go. Under the nohup fallback the wrapper sits in the login shell's
    // group, and signalling that group would take the shell with it.
    for (const [launcher, expected] of [
      ['setsid', 'group'],
      ['nohup', 'process']
    ] as const) {
      const host = new FakeHost({ launcher })
      const h = harness(host)
      const { req } = request({ timeoutMs: 1 })
      const p = h.exec(req)
      await h.flush()
      h.advance(10_000)
      await h.tick()
      await p
      const signal = host.commands.find((c) => c.startsWith('SP_JOB_VERB=signal;')) as string
      expect(signal, 'the group is only signalled when the wrapper leads it').toContain(
        '[ "$SP_PID" = "$SP_PGID" ]'
      )
      // What the host actually did, recorded as it happened — not re-run
      // afterwards against a marker that has since been reaped.
      expect(host.signals, launcher).toEqual([expected])
    }
  })
})

// =========================================================================
// The probe's other job
// =========================================================================

describe('the capability probe', () => {
  it('resolves the state directory in order and never at the filesystem root', () => {
    const probe = buildJobProbe()
    // An unset XDG_STATE_HOME must expand to NOTHING, not to "/shellpilot/jobs"
    // — which as root would create a directory at the filesystem root.
    expect(probe).toContain('${XDG_STATE_HOME:+$XDG_STATE_HOME/shellpilot/jobs}')
    expect(probe).toContain('${HOME:+$HOME/.local/state/shellpilot/jobs}')
    expect(probe).toContain('/var/tmp/shellpilot-$(id -u 2>/dev/null)/jobs')
    // /tmp is tmpfs and reboot-cleared, and "the marker vanished" would be
    // indistinguishable from "the job never ran" in the one case — a host that
    // rebooted — where the difference is the whole answer.
    expect(probe).not.toMatch(/(?<!\/var)\/tmp\/shellpilot/)
  })

  it('reads rc BEFORE the output, which is what makes a finished poll complete', () => {
    // The fake answers polls from its own marker state, so it cannot enforce
    // the ORDER of two reads inside the shell — this asserts it on the text
    // instead, because getting it backwards is a silent bug rather than a
    // failure. `rc` exists only after the command has exited, so if it is there
    // before `out` is read, nothing can append to `out` afterwards and what
    // comes back is all of it. Reading rc last leaves a window where the final
    // lines were written between the two reads and reported as finished
    // without them — and there is no later poll to catch up, because a poll
    // that sees rc is the last one.
    const poll = buildJobPoll({ dir: '/var/tmp/x/j.1', offset: 0, base64: true })
    expect(poll.indexOf('rc=')).toBeLessThan(poll.indexOf('tail -c'))
    // And the window is closed on the HOST rather than by counting what
    // arrived, so a file the job is still appending to cannot be re-sent.
    expect(poll).toContain('SP_N=$((SP_SIZE - SP_JOB_OFF))')
    expect(poll).toContain('head -c "$SP_N"')
  })

  it('sweeps only old markers whose process is gone', () => {
    const probe = buildJobProbe({ sweepDays: 7 })
    expect(probe).toContain('-mtime +7')
    // A genuinely long job belonging to ANYBODY, including another instance,
    // is never swept out from under its reader.
    expect(probe).toContain('kill -0 "$p" 2>/dev/null; then continue')
  })
})

// =========================================================================
// Re-adoption from rows alone, against the real store
// =========================================================================

describe('picking a job up after a restart', () => {
  let dir: string
  const opened: HistoryStore[] = []

  beforeEach(() => {
    resetHistoryModuleForTests()
    delete process.env[DISABLE_ENV]
    opened.length = 0
    dir = mkdtempSync(join(tmpdir(), 'shellpilot-b2-'))
  })

  afterEach(async () => {
    await Promise.all(opened.map((s) => s.backupReady.catch(() => false)))
    for (const s of opened) s.close()
    opened.length = 0
    resetHistoryModuleForTests()
    try {
      rmSync(dir, { recursive: true, force: true })
    } catch {
      /* a leftover temp dir is not worth failing a test over */
    }
  })

  async function store(): Promise<HistoryStore> {
    const s = await loadHistory(dir)
    expect(s, 'node:sqlite did not open — every assertion below would be vacuous').not.toBeNull()
    opened.push(s as HistoryStore)
    return s as HistoryStore
  }

  const spec: JobSpec = { kind: 'command', title: 'Upgrade', steps: [{ command: 'apt full-upgrade -y' }] }

  it('resumes from the rows alone, and neither rewinds nor repeats its output', async () => {
    const s = await store()
    const host = new FakeHost()

    // --- the first ShellPilot: launches, reads some output, and is closed ---
    const first = harness(host)
    const progress: JobProgress[] = []
    const outputs: JobOutput[] = []
    const ticks: (() => void)[] = []
    const runner = new JobRunner({
      store: s,
      exec: first.exec,
      emit: (p) => progress.push(p),
      emitOutput: (o) => outputs.push(o),
      schedule: (fn) => ticks.push(fn)
    })
    const run = runner.run({
      jobId: 'j1',
      spec,
      targets: [{ serverId: 'a', serverName: 'web-1', cfg: { id: 'a' } }]
    })
    await first.flush()
    const marker = host.dir
    host.write(marker, 'first half\n')
    await first.tick()

    // The lid closes. The poller is holding a wait, so it notices at the next
    // one — in production three seconds later, here when the test says so.
    runner.disposeAll()
    expect(first.pending, 'the poller should be waiting, not spinning').toBe(1)
    await first.tick()
    await first.flush()
    await run

    const mid = s.readJob('j1')
    expect(mid?.targets[0].state, 'a detached host is not abandoned').toBe('detached')
    expect(isJobDetachedHandle(mid?.targets[0].detached)).toBe(true)
    expect(mid?.state, 'the job row stays open for the next launch to reclaim').toBe('running')

    // --- a second ShellPilot, which never saw any of that ---
    host.write(marker, 'second half\n')
    host.exit(marker, 0)
    const second = harness(host)
    const runner2 = new JobRunner({
      store: s,
      exec: second.exec,
      emit: (p) => progress.push(p),
      emitOutput: (o) => outputs.push(o),
      schedule: (fn) => ticks.push(fn)
    })
    // adopt() must NOT close it: there is a command on that host right now.
    expect(runner2.adopt()).toEqual([])
    const taken = runner2.reclaim({ cfgFor: () => ({ id: 'a' }) })
    expect(taken.map((j) => j.id)).toEqual(['j1'])
    await second.flush()
    await second.tick()
    await runner2.whenSettled('j1')
    for (const t of ticks.splice(0)) t()

    const done = s.readJob('j1')
    expect(done?.state).toBe('done')
    expect(done?.targets[0].state).toBe('ok')
    expect(done?.targets[0].exitCode).toBe(0)
    expect(done?.targets[0].detached, 'a reaped marker is cleared from the row').toBeNull()

    // The output is continuous: no byte lost at the restart seam, none written
    // twice, and the rows are in order.
    const rows = s.readJobOutput('j1', 'a')
    expect(rows.map((r) => r.text).join('')).toBe('first half\nsecond half\n')
    expect(rows.map((r) => r.seq)).toEqual(rows.map((_r, i) => i))
    expect(done?.targets[0].outOffset).toBe('first half\nsecond half\n'.length)
  })

  it('does not start hosts the job never reached', async () => {
    // A restart is not an authorisation. The confirmation a human gave does not
    // survive into this process yet — that is B3 — so twelve untouched hosts
    // are closed rather than launched on the strength of a record.
    const s = await store()
    const host = new FakeHost()
    const first = harness(host)
    const runner = new JobRunner({
      store: s,
      exec: first.exec,
      emit: () => {},
      emitOutput: () => {},
      schedule: () => {}
    })
    const run = runner.run({
      jobId: 'j2',
      spec: { ...spec, concurrency: 1 },
      targets: [
        { serverId: 'a', serverName: 'web-1', cfg: { id: 'a' } },
        { serverId: 'b', serverName: 'web-2', cfg: { id: 'b' } }
      ]
    })
    await first.flush()
    runner.disposeAll()
    await first.tick()
    await first.flush()
    await run

    host.exit(host.dir, 0)
    const second = harness(host)
    const runner2 = new JobRunner({
      store: s,
      exec: second.exec,
      emit: () => {},
      emitOutput: () => {},
      schedule: () => {}
    })
    runner2.reclaim({ cfgFor: () => ({ id: 'a' }) })
    await second.flush()
    await second.tick()
    await runner2.whenSettled('j2')

    const done = s.readJob('j2')
    const b = done?.targets.find((t) => t.serverId === 'b')
    expect(b?.state).toBe('skipped')
    expect(b?.outcome).toBe('cancelled')
    expect(b?.error).toMatch(/does not survive a restart yet/i)
    expect(host.dirs.size, 'nothing new was launched anywhere').toBe(0)
  })

  it('says so when the server has been removed from the workspace', async () => {
    const s = await store()
    const host = new FakeHost()
    const first = harness(host)
    const runner = new JobRunner({
      store: s,
      exec: first.exec,
      emit: () => {},
      emitOutput: () => {},
      schedule: () => {}
    })
    const run = runner.run({
      jobId: 'j3',
      spec,
      targets: [{ serverId: 'a', serverName: 'web-1', cfg: { id: 'a' } }]
    })
    await first.flush()
    runner.disposeAll()
    await first.tick()
    await first.flush()
    await run

    const second = harness(host)
    const runner2 = new JobRunner({
      store: s,
      exec: second.exec,
      emit: () => {},
      emitOutput: () => {},
      schedule: () => {}
    })
    runner2.reclaim({ cfgFor: () => null })
    await runner2.whenSettled('j3')
    const done = s.readJob('j3')
    expect(done?.targets[0].state).toBe('orphaned')
    expect(done?.targets[0].error).toMatch(/no longer in the workspace/i)
    // And the directory is named, so a person can go and read it by hand.
    expect(done?.targets[0].error).toContain(host.dir)
  })

  it('still closes an attached job as abandoned', async () => {
    // B1's behaviour is not disturbed by any of this: a row with no marker is a
    // command the kernel SIGHUP'd, and saying otherwise would be the lie the
    // whole item exists to stop telling.
    const s = await store()
    const attached: JobExecutor = () => new Promise<JobExecResult>(() => {})
    const runner = new JobRunner({
      store: s,
      exec: attached,
      emit: () => {},
      emitOutput: () => {},
      schedule: () => {}
    })
    void runner.run({
      jobId: 'j4',
      spec,
      targets: [{ serverId: 'a', serverName: 'web-1', cfg: { id: 'a' } }]
    })
    await Promise.resolve()
    runner.disposeAll()

    const runner2 = new JobRunner({
      store: s,
      exec: attached,
      emit: () => {},
      emitOutput: () => {},
      schedule: () => {}
    })
    expect(runner2.adopt().map((j) => j.id)).toEqual(['j4'])
    expect(runner2.reclaim({ cfgFor: () => ({ id: 'a' }) })).toEqual([])
    const done = s.readJob('j4')
    expect(done?.state).toBe('abandoned')
    expect(done?.targets[0].outcome).toBe('abandoned')
  })

  it('keeps a B2 row readable, and reads a malformed handle as no handle', async () => {
    const s = await store()
    s.createJob({
      id: 'j5',
      createdAt: Date.now() - DAY,
      workspaceId: null,
      title: 'Upgrade',
      kind: 'command',
      spec,
      risk: 'elevated',
      confirmation: { kind: 'confirm' },
      confirmedAt: null,
      state: 'running',
      targets: [{ serverId: 'a', serverName: 'web-1', ord: 0, state: 'pending' }]
    })
    // A row written by a build that is not this one. It must not be handed to
    // reclaim(), which would send a `rm -rf` at whatever `dir` says.
    s.updateJobTarget('j5', 'a', {
      state: 'detached',
      detached: { v: 99, dir: '/etc' } as never
    })
    const back = s.readJob('j5')
    expect(back?.targets[0].state, 'an unknown state reads back as itself').toBe('detached')
    expect(back?.targets[0].detached).toBeNull()
  })
})

// =========================================================================
// Housekeeping
// =========================================================================

describe('the launch grace', () => {
  it('is long enough that a slow host is not called a failed launch', () => {
    // The wrapper writes `pid` as its own first act, so the window this covers
    // is milliseconds on any host that is running at all.
    expect(JOB_LAUNCH_GRACE_MS).toBeGreaterThanOrEqual(10_000)
  })
})
