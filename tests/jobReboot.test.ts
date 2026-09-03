import { describe, it, expect } from 'vitest'
import { detachedJobExecutor, type JobRunResult } from '../src/main/services/jobDetached'
import type { JobExecutor } from '../src/main/services/jobRunner'
import { JOB_CMD_PREFIX, classifyJobPoll, restartsTheMachine } from '../src/shared/jobs'
import { REBOOT_BOOT_ID_MARK, buildRebootStep } from '../src/shared/patch'

// Reboot-and-wait — item 17's actual feature, and the one place B2's
// vocabulary got a fact exactly backwards.
//
// A host that stops answering because the job asked it to restart is not
// `unreachable`, and a wrapper the kernel took down with the rest of userspace
// is not `orphaned`. Both of those words point at a fault; here there is none,
// and the run has been told in advance exactly what is about to happen.
//
// The fake host below is jobDetached.test.ts's, cut down and taught one extra
// verb — the post-boot check — and it is driven by the REAL builders for that
// file's reason: a fake with its own idea of the protocol goes on passing after
// somebody changes the wrapper.
//
// WHAT THIS CANNOT PROVE, and it is the important half:
//
//  1. That a real machine actually restarts when told to. The fake decides that
//     by fiat. What is proved here is the state machine over it.
//  2. That `/proc/sys/kernel/random/boot_id` exists and changes across a reboot
//     on every distribution. It does on Linux; `verifyReboot` has an
//     `unverifiable` answer precisely because somewhere it will not.
//  3. That a marker directory under $HOME survives the reboot. It is not under
//     /tmp specifically so that it can — see JOB_STATE_ROOTS — but a
//     distribution with an aggressive tmpfiles.d policy and a /var/tmp
//     fallback would produce `missing`, which is a different (and honest)
//     outcome the fake does not exercise.

interface Marker {
  cmd: string
  instance: string
  pid: number | null
  pgid: number | null
  out: Buffer
  rc: number | null
  alive: boolean
}

class FakeHost {
  readonly dirs = new Map<string, Marker>()
  readonly commands: string[] = []
  connected = true
  bootId = 'boot-before'
  unitState = 'running'
  failed = ''
  /** The postboot probe answers nothing this build understands. */
  postbootGarbage = false
  private nextPid = 5000

  run = async (_cfg: unknown, command: string, _t: number): Promise<JobRunResult> => {
    this.commands.push(command)
    if (!this.connected) {
      return { ok: false, code: null, stdout: '', stderr: '', error: 'Timed out after 30000ms connecting' }
    }
    // The one verb that is not a job wrapper: the post-boot check.
    if (command.includes('shellpilot-postboot/1')) {
      if (this.postbootGarbage) return ok('sh: 1: Syntax error: word unexpected\n')
      return ok(
        [
          'shellpilot-postboot/1',
          `boot-id=${this.bootId}`,
          'uptime=17',
          `unit-state=${this.unitState}`,
          `failed=${this.failed}`,
          ''
        ].join('\n')
      )
    }
    const m = JOB_CMD_PREFIX.exec(command)
    if (!m) {
      throw new Error(
        'the fake host does not recognise this command, which means shared/jobs.ts changed its ' +
          `wrapper and this fake is now simulating a protocol nothing speaks:\n${command.slice(0, 200)}`
      )
    }
    const dir = m[2] === 'auto' ? '' : unquote(m[2])
    switch (m[1]) {
      case 'probe':
        return ok(
          'shellpilot-probe/1\nlauncher=setsid\nbase64=yes\nuid=1000\nroot=/home/ops/.local/state/shellpilot/jobs\n'
        )
      case 'launch': {
        const instance = /printf '%s\\n' '([^']+)' > "\$SP_JOB_DIR\/instance"/.exec(command)?.[1]
        const pid = this.nextPid++
        this.dirs.set(dir, {
          cmd: command,
          instance: instance as string,
          pid,
          pgid: pid,
          out: Buffer.alloc(0),
          rc: null,
          alive: true
        })
        return ok('shellpilot-launch/1\nerror=\n')
      }
      case 'poll': {
        const off = Number(/SP_JOB_OFF=(\d+);/.exec(command)?.[1] ?? 0)
        const max = Number(/SP_JOB_MAX=(\d+);/.exec(command)?.[1] ?? 1)
        const marker = this.dirs.get(dir)
        if (!marker) return ok('shellpilot-poll/1\nmarker=missing\nbody/1\n')
        const size = marker.out.length
        const sent = Math.max(0, Math.min(size - off, max))
        const body = marker.out.subarray(off, off + sent).toString('base64')
        return ok(
          [
            'shellpilot-poll/1',
            'marker=present',
            `instance=${marker.instance}`,
            `pid=${marker.pid ?? ''}`,
            `pgid=${marker.pgid ?? ''}`,
            `rc=${marker.rc ?? ''}`,
            `alive=${marker.alive && marker.pid !== null ? 'yes' : 'no'}`,
            'pidcheck=strong',
            // Emitted only where the poll asks for it, so a builder that stops
            // reading rc twice is a fake that stops answering twice.
            ...(command.includes('rc2=') ? [`rc2=${marker.rc ?? ''}`] : []),
            `size=${size}`,
            `sent=${sent}`,
            'body/1',
            body
          ].join('\n')
        )
      }
      case 'signal':
        return ok('shellpilot-signal/1\nsignalled=group\n')
      case 'reap':
        this.dirs.delete(dir)
        return ok('shellpilot-reap/1\nreaped=yes\n')
      default:
        throw new Error(`unknown verb ${m[1]}`)
    }
  }

  write(text: string): void {
    const m = this.marker()
    m.out = Buffer.concat([m.out, Buffer.from(text, 'utf8')])
  }

  /**
   * THE ORDINARY REBOOT, and the one the fake could always have produced and
   * was never asked to.
   *
   * `systemctl reboot` returns 0 the moment the request is accepted, and the
   * wrapper's very next instruction records that 0 — microseconds later, while
   * systemd is still stopping units. The marker root is a state directory and
   * not /tmp precisely so that it survives, so what the first poll after the
   * host comes back sees is `rc=0`, an exit status, on a marker that is still
   * there. Every reboot test in this file used to skip this step and go
   * straight to `goDown()`, which is the case where the kernel took the wrapper
   * before it could write anything — real, but rare.
   */
  rebootAccepted(rc = 0): void {
    this.marker().rc = rc
    this.marker().alive = false
  }

  /** The machine actually goes: sshd stops answering. */
  goDown(): void {
    this.marker().alive = false
    this.marker().pid = this.marker().pid
    this.connected = false
  }

  comeBack(bootId = 'boot-after'): void {
    this.bootId = bootId
    this.connected = true
  }

  marker(): Marker {
    const keys = [...this.dirs.keys()]
    expect(keys, 'expected exactly one marker directory').toHaveLength(1)
    return this.dirs.get(keys[0]) as Marker
  }

  get dir(): string {
    const keys = [...this.dirs.keys()]
    return keys[0]
  }
}

function ok(stdout: string): JobRunResult {
  return { ok: true, code: 0, stdout, stderr: '' }
}

function unquote(q: string): string {
  return q.slice(1, -1).split(`'\\''`).join("'")
}

function harness(host: FakeHost) {
  const waits: (() => void)[] = []
  let clock = 1_000
  const attached: JobExecutor = async () => ({ ok: true, code: 0 })

  const exec = detachedJobExecutor({
    run: host.run,
    instanceId: 'sp-me',
    attached,
    enabled: () => true,
    now: () => clock,
    sleep: () => new Promise<void>((resolve) => waits.push(resolve)),
    random: () => 0.5,
    pollMs: 3_000,
    pollBytes: 4096
  })

  const flush = async (): Promise<void> => {
    for (let i = 0; i < 50; i++) await Promise.resolve()
  }

  return {
    exec,
    flush,
    advance: (ms: number) => {
      clock += ms
    },
    get pending(): number {
      return waits.length
    },
    tick: async (): Promise<void> => {
      const next = waits.shift()
      expect(next, 'nothing was waiting — the poller is not where the test thinks it is').toBeDefined()
      ;(next as () => void)()
      await flush()
    }
  }
}

function request(over: Record<string, unknown> = {}) {
  const output: string[] = []
  const states: { state?: string; error?: string }[] = []
  return {
    output,
    states,
    req: {
      cfg: { id: 'a' },
      command: buildRebootStep(),
      timeoutMs: 900_000,
      jobId: 'jobreboot',
      serverId: 'a',
      serverName: 'web-1',
      step: 2,
      reboot: true,
      alive: () => true,
      onState: (u: never) => states.push(u),
      onOutput: (_s: 'out' | 'err', t: string) => output.push(t),
      ...over
    }
  }
}

// =========================================================================
// The classifier
// =========================================================================

describe('classifying a poll on a step that was declared to restart the machine', () => {
  const poll = {
    present: true,
    instance: 'sp-me',
    pid: 4321,
    pgid: 4321,
    rc: null,
    alive: false,
    pidCheck: 'strong' as const,
    size: 40,
    sent: 0,
    text: ''
  }

  it('reads a vanished wrapper as a restart rather than as an orphan', () => {
    expect(
      classifyJobPoll(poll, { instanceId: 'sp-me', launchedAt: 0, now: 1_000, expectsReboot: true })
    ).toEqual({ phase: 'rebooted', foreign: false })
  })

  it('still says orphaned when the step did not declare a reboot', () => {
    // A GUESS MUST NOT SUPPRESS `orphaned`. That state is the honest answer to
    // "the process is gone and nobody knows why", and turning it off because a
    // command mentioned `reboot` would be the smoothing-over B2 refused.
    expect(classifyJobPoll(poll, { instanceId: 'sp-me', launchedAt: 0, now: 1_000 })).toEqual({
      phase: 'orphaned',
      foreign: false
    })
  })

  it('does NOT accept a recorded exit status as the answer on a declared reboot', () => {
    // INVERTED, and this test as it stood is why the defect survived review:
    // it pinned "rc wins, unconditionally" as intended without confronting what
    // it implied for the only step type that has a `expectsReboot` at all.
    //
    // `buildRebootStep` ends in `systemctl reboot` or `shutdown -r now`. BOTH
    // RETURN 0 IMMEDIATELY — the exit status of a reboot command is the status
    // of ASKING — and the wrapper's next instruction writes that 0 to `rc`,
    // while systemd is still stopping units. The marker directory deliberately
    // survives the reboot, so the first poll after the host answers again finds
    // rc=0 and the old classifier called it `finished`: the executor reaped and
    // returned ok, and `buildRebootVerify`/`verifyReboot` — the whole of item
    // 17 — never ran on the one path they were written for. A host that came
    // back with eleven failed units, or that never rebooted because something
    // swallowed the request, reported success and the wave rolled on.
    //
    // So a declared reboot goes to `rebooted` whatever `rc` says. `rebooted` is
    // not a claim that the machine restarted; it is the state in which somebody
    // goes and looks.
    expect(
      classifyJobPoll(
        { ...poll, rc: 0 },
        { instanceId: 'sp-me', launchedAt: 0, now: 1_000, expectsReboot: true }
      ).phase
    ).toBe('rebooted')
    // And nothing changes for a step that did not declare one: an ordinary
    // command's exit status is still the answer, still checked first, because a
    // wrapper that has exited has no live pid by definition.
    expect(
      classifyJobPoll({ ...poll, rc: 0 }, { instanceId: 'sp-me', launchedAt: 0, now: 1_000 }).phase
    ).toBe('finished')
  })

  it('does not lean on the text matcher to know a reboot step is a reboot step', () => {
    // A REAL GAP, found by writing this test, and STILL real now that the
    // classifier reads sudo's flags. The reboot this codebase actually issues
    // is `if command -v systemctl …; then sudo -n systemctl reboot; else …`,
    // and the verb there sits after a `then` rather than at a command start.
    // No anchored text rule reaches it, and an unanchored one would flag every
    // `grep reboot /var/log/syslog` — which is the guard nobody reads.
    //
    // That is why `JobStep.reboot` is a declaration rather than a sniff, and
    // why planJob grades a declared reboot as destructive on its own.
    expect(restartsTheMachine(buildRebootStep())).toBe(false)
    // What the text matcher DOES see, it now sees whole. `sudo -n` was the
    // hole: the only escalation that cannot prompt, used everywhere in this
    // codebase, and invisible to a prefix that admitted no flags. jobs.ts
    // shares broadcast.ts's command-start fragment so the two cannot drift
    // apart on it again.
    expect(restartsTheMachine('sudo -n reboot')).toBe(true)
    expect(restartsTheMachine('reboot')).toBe(true)
    expect(restartsTheMachine('grep reboot /var/log/syslog')).toBe(false)
  })
})

// =========================================================================
// The whole cycle
// =========================================================================

describe('issuing a reboot and waiting for the host', () => {
  it('reports `rebooting` while the host is down, never `unreachable`', async () => {
    const host = new FakeHost()
    const h = harness(host)
    const { req, states } = request()
    const p = h.exec(req)
    await h.flush()

    // The step printed its boot id and then took the machine down.
    host.write(`${REBOOT_BOOT_ID_MARK}boot-before\n`)
    await h.tick()
    host.goDown()
    await h.tick()

    const seen = states.map((s) => s.state).filter(Boolean)
    expect(seen).toContain('rebooting')
    // The two words this must never be. `unreachable` points at a fault and
    // `abandoned` says ShellPilot dropped it; the disconnect was asked for.
    expect(seen).not.toContain('unreachable')
    expect(seen).not.toContain('orphaned')

    host.comeBack()
    await h.tick()
    const r = await p
    expect(r.ok).toBe(true)
    expect(r.code).toBe(0)
  })

  it('checks the host came back healthy rather than merely came back', async () => {
    const host = new FakeHost()
    const h = harness(host)
    const { req, output } = request()
    const p = h.exec(req)
    await h.flush()
    host.write(`${REBOOT_BOOT_ID_MARK}boot-before\n`)
    await h.tick()
    host.goDown()
    await h.tick()
    // It comes back, and it comes back broken.
    host.comeBack()
    host.unitState = 'degraded'
    host.failed = 'nginx.service '
    await h.tick()

    const r = await p
    expect(r.ok).toBe(false)
    // `unhealthy`, not `unreachable`: the host is answering. That is the whole
    // point of the outcome existing.
    expect(r.finalOutcome).toBe('unhealthy')
    expect(r.error).toContain('nginx.service')
    expect(output.join('')).toContain('nginx.service')
    // The post-boot probe really ran, rather than the verdict being assumed.
    expect(host.commands.some((c) => c.includes('shellpilot-postboot/1'))).toBe(true)
  })

  it('refuses to call it a restart when the boot id did not change', async () => {
    const host = new FakeHost()
    const h = harness(host)
    const { req } = request()
    const p = h.exec(req)
    await h.flush()
    host.write(`${REBOOT_BOOT_ID_MARK}boot-before\n`)
    await h.tick()
    host.goDown()
    await h.tick()
    // The link came back and the machine never went: the reboot was issued and
    // something refused or swallowed it.
    host.comeBack('boot-before')
    await h.tick()

    const r = await p
    expect(r.ok).toBe(false)
    expect(r.error).toContain('never restarted')
  })

  it('refuses to claim a restart it could not verify', async () => {
    const host = new FakeHost()
    const h = harness(host)
    const { req } = request()
    const p = h.exec(req)
    await h.flush()
    // No boot id was ever printed — an OS that does not expose one.
    await h.tick()
    host.goDown()
    await h.tick()
    host.comeBack()
    await h.tick()

    const r = await p
    expect(r.ok).toBe(false)
    expect(r.error).toContain('cannot prove')
  })

  it('gives up on a host that never comes back, and says the wait was expected', async () => {
    const host = new FakeHost()
    const h = harness(host)
    const { req, states } = request({ timeoutMs: 60_000 })
    const p = h.exec(req)
    await h.flush()
    host.write(`${REBOOT_BOOT_ID_MARK}boot-before\n`)
    await h.tick()
    host.goDown()
    // Past the deadline while still down.
    h.advance(120_000)
    await h.tick()

    const r = await p
    expect(r.finalOutcome).toBe('timeout')
    expect(r.error).toContain('NOT')
    expect(r.error).toContain('expected')
    // It was `rebooting` throughout, not `unreachable`.
    expect(states.map((s) => s.state)).toContain('rebooting')
  })

  // -----------------------------------------------------------------------
  // THE ORDINARY SEQUENCE — a reboot that works
  // -----------------------------------------------------------------------
  // Every test above this line drives `goDown()`: the wrapper is taken by the
  // kernel before it can record anything. That is real and it is rare. What
  // happens on essentially every real reboot is that `systemctl reboot` returns
  // 0, the wrapper writes `rc=0` microseconds later while systemd is still
  // stopping units, and the marker — which is in a state directory precisely so
  // that it survives — is still there with that 0 in it when the host answers
  // again. The fake could always have produced that. It was never asked to, and
  // in that gap item 17 was unreachable in production.

  it('verifies a reboot that recorded an exit status, which is all of them', async () => {
    const host = new FakeHost()
    const h = harness(host)
    const { req, output } = request()
    const p = h.exec(req)
    await h.flush()

    host.write(`${REBOOT_BOOT_ID_MARK}boot-before\n`)
    await h.tick()
    // The reboot was accepted and the wrapper recorded its 0. The host has not
    // gone yet — systemd is still stopping units — so nothing is concluded.
    host.rebootAccepted()
    await h.tick()
    expect(
      host.commands.some((c) => c.includes('shellpilot-postboot/1')),
      'a host that is still answering has not restarted yet, and must not be judged as if it had'
    ).toBe(false)
    let settled = false
    void p.then(() => {
      settled = true
    })
    await h.flush()
    expect(settled, 'rc=0 from a reboot command is the status of ASKING, not an answer').toBe(false)

    // Now it goes, and comes back with a unit that did not start.
    host.goDown()
    await h.tick()
    host.comeBack()
    host.unitState = 'degraded'
    host.failed = 'nginx.service '
    await h.tick()

    const r = await p
    // THE HEADLINE. Before this fix the poll above returned `ok: true, code: 0`
    // and the wave rolled on to the next host.
    expect(r.ok).toBe(false)
    expect(r.finalOutcome).toBe('unhealthy')
    expect(r.error).toContain('nginx.service')
    expect(output.join('')).toContain('nginx.service')
    expect(host.commands.some((c) => c.includes('shellpilot-postboot/1'))).toBe(true)
  })

  it('reports a clean reboot as a success, exit status and all', async () => {
    const host = new FakeHost()
    const h = harness(host)
    const { req, output } = request()
    const p = h.exec(req)
    await h.flush()
    host.write(`${REBOOT_BOOT_ID_MARK}boot-before\n`)
    await h.tick()
    host.rebootAccepted()
    await h.tick()
    host.goDown()
    await h.tick()
    host.comeBack()
    await h.tick()

    const r = await p
    expect(r.ok).toBe(true)
    expect(r.code).toBe(0)
    expect(output.join(''), 'and it says what it checked, not merely that it passed').toMatch(
      /restarted/i
    )
    expect(host.dirs.size, 'the marker is reaped once the answer is in hand').toBe(0)
  })

  it('says the reboot was swallowed when the host answers throughout', async () => {
    // rc=0 and the machine never goes: something accepted the request and did
    // nothing with it — a container, a masked target, a systemd that refused.
    // The host is answering the whole time, so `rebooting` never becomes a
    // timeout; what ends it is the boot id, which has not changed.
    const host = new FakeHost()
    const h = harness(host)
    const { req, states } = request({ timeoutMs: 60_000 })
    const p = h.exec(req)
    await h.flush()
    host.write(`${REBOOT_BOOT_ID_MARK}boot-before\n`)
    await h.tick()
    host.rebootAccepted()
    await h.tick()
    // It is waiting, and the row says why rather than showing a bare exit code.
    expect(states.some((x) => /still answering/i.test(x.error ?? ''))).toBe(true)
    // Past the deadline, still up, still the same boot.
    h.advance(120_000)
    await h.tick()

    const r = await p
    expect(r.ok).toBe(false)
    expect(r.error).toContain('never restarted')
    expect(r.finalOutcome).toBe('unhealthy')
  })

  it('does not wait on a reboot command that failed outright', async () => {
    // `sudo -n systemctl reboot` on a host without the sudoers rule exits
    // non-zero and nothing is going to happen. There is no reason to sit
    // through the deadline waiting for a machine that was never asked.
    const host = new FakeHost()
    const h = harness(host)
    const { req } = request()
    const p = h.exec(req)
    await h.flush()
    host.write(`${REBOOT_BOOT_ID_MARK}boot-before\n`)
    await h.tick()
    host.rebootAccepted(1)
    await h.tick()
    const r = await p
    expect(r.ok).toBe(false)
    expect(r.error).toContain('never restarted')
    // The status of the refusal is the useful half, and it is kept.
    expect(r.code).toBe(1)
  })

  it('verifies a reboot it is reclaiming, using the boot id from the row', async () => {
    // The boot id is printed once, on the way down, and a ShellPilot that was
    // restarted across the reboot never saw it go past. It is on the handle for
    // exactly this: without it every reclaimed reboot would come back
    // `unverifiable`, which is honest and which nothing could ever satisfy.
    const host = new FakeHost()
    const h = harness(host)
    const { req } = request()
    const p = h.exec(req)
    await h.flush()
    host.write(`${REBOOT_BOOT_ID_MARK}boot-before\n`)
    await h.tick()
    const dir = host.dir
    host.rebootAccepted()

    // A second ShellPilot picks the marker up from the row alone.
    const second = harness(host)
    const { req: req2 } = request({
      resume: {
        v: 1,
        dir,
        step: 2,
        instanceId: 'sp-me',
        launcher: 'setsid',
        base64: true,
        launchedAt: 1_000,
        readOffset: host.marker().out.length,
        command: buildRebootStep(),
        bootIdBefore: 'boot-before'
      }
    })
    host.comeBack()
    const p2 = second.exec(req2)
    await second.flush()
    await second.tick()
    const r2 = await p2
    expect(r2.ok, 'the boot id changed, so it restarted and came back clean').toBe(true)
    expect(
      host.commands.some((c) => c.includes('shellpilot-postboot/1')),
      'and it was CHECKED rather than assumed from the exit status on the marker'
    ).toBe(true)

    // The first watcher is left holding a marker somebody else reaped; it says
    // so rather than claiming an answer.
    while (h.pending > 0) await h.tick()
    const r = await p
    expect(r.ok).toBe(false)
  })

  it('leaves an ordinary detached job disconnect unbounded, as B2 designed it', async () => {
    // The deadline added for a reboot step must not leak onto the path whose
    // whole point is surviving a link that is down for as long as it takes.
    const host = new FakeHost()
    const h = harness(host)
    const { req } = request({ command: 'apt-get -y upgrade', reboot: false })
    void h.exec(req)
    await h.flush()
    host.connected = false
    h.advance(10_000_000)
    await h.tick()
    await h.tick()
    // Still polling, not resolved.
    expect(h.pending).toBeGreaterThan(0)
  })
})
