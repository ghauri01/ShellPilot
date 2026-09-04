import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { BroadcastRunner } from '../src/main/services/broadcast'
import type { BroadcastProgress, BroadcastRequest } from '../src/shared/broadcast'
import {
  BROADCAST_CONCURRENCY,
  BROADCAST_OUTPUT_CAP,
  approvalFor,
  planBroadcast
} from '../src/shared/broadcast'

// The approval model is settled elsewhere. What this has to get right is not
// undermining it: a cancel that does not actually stop the remaining hosts
// would give the whole model away, since the confirmation exists precisely
// because a broadcast is hard to take back.

const targets = (n: number): BroadcastRequest['targets'] =>
  Array.from({ length: n }, (_, i) => ({ serverId: `s${i}`, serverName: `host-${i}`, cfg: {} }))

/**
 * A run request carrying the approval B3 made mandatory.
 *
 * Every call below used to build the request by hand without one, which is why
 * this file did not type-check: `approval` has been required on
 * `BroadcastRequest` since the record became the thing a resumed job is
 * re-authorised from. The runner itself never reads it — `main` checks it
 * against a fresh `planBroadcast` before calling in — so the omission changed
 * no behaviour here, but a fixture that cannot be constructed is a fixture that
 * stops describing the call. Minted from the same `planBroadcast` the check
 * re-derives, so these requests are ones that check would accept.
 */
function req(o: Omit<BroadcastRequest, 'approval'>): BroadcastRequest {
  const plan = planBroadcast(o.command, o.targets)
  return {
    ...o,
    approval: approvalFor({
      surface: 'broadcast',
      commands: [o.command],
      targets: o.targets,
      plan,
      phrase: plan.confirmation.kind === 'type-to-confirm' ? plan.confirmation.phrase : null,
      confirmedAt: 1_700_000_000_000
    })
  }
}

function harness(over: { exec?: NonNullable<Parameters<typeof makeRunner>[0]>['exec'] } = {}) {
  return makeRunner(over)
}

function makeRunner(over: {
  exec?: (cfg: unknown, cmd: string, ms: number) => Promise<{ ok: boolean; code?: number | null; stdout?: string; stderr?: string; error?: string }>
} = {}) {
  const events: BroadcastProgress[] = []
  const started: string[] = []
  const gates: (() => void)[] = []
  const exec =
    over.exec ??
    (async (): Promise<{ ok: boolean; code: number; stdout: string }> => ({ ok: true, code: 0, stdout: 'out' }))
  const runner = new BroadcastRunner({
    exec: async (cfg, cmd, ms) => {
      started.push(cmd)
      return exec(cfg, cmd, ms)
    },
    emit: (e) => events.push(e)
  })
  return { runner, events, started, gates }
}

describe('running a command across hosts', () => {
  it('reports a result for every host', async () => {
    const h = harness()
    const out = await h.runner.run(req({ runId: 'r', command: 'uptime', targets: targets(4) }))
    expect(out).toHaveLength(4)
    expect(out.every((r) => r.state === 'ok')).toBe(true)
  })

  it('emits a running event before each host and a result after', async () => {
    const h = harness()
    await h.runner.run(req({ runId: 'r', command: 'uptime', targets: targets(2) }))
    const states = h.events.filter((e) => !e.done).map((e) => e.host.state)
    expect(states.filter((s) => s === 'running')).toHaveLength(2)
    expect(states.filter((s) => s === 'ok')).toHaveLength(2)
  })

  it('always emits a terminal event, even with no targets', async () => {
    // Otherwise the renderer waits forever for a run that already stopped.
    const h = harness()
    await h.runner.run(req({ runId: 'r', command: 'uptime', targets: [] }))
    expect(h.events.filter((e) => e.done)).toHaveLength(1)
  })

  it('treats a non-zero exit as a result, not a failure', async () => {
    // `grep` finding nothing exits 1. Calling that a failure would make half
    // the useful commands look broken.
    const h = makeRunner({ exec: async () => ({ ok: true, code: 1, stdout: '' }) })
    const out = await h.runner.run(req({ runId: 'r', command: 'grep x f', targets: targets(1) }))
    expect(out[0]).toMatchObject({ state: 'ok', exitCode: 1 })
  })

  it('keeps going when one host is unreachable', async () => {
    let n = 0
    const h = makeRunner({
      exec: async () => {
        n++
        if (n === 1) throw new Error('connect ETIMEDOUT')
        return { ok: true, code: 0, stdout: 'fine' }
      }
    })
    const out = await h.runner.run(req({ runId: 'r', command: 'uptime', targets: targets(3) }))
    expect(out.filter((r) => r.state === 'failed')).toHaveLength(1)
    expect(out.filter((r) => r.state === 'ok')).toHaveLength(2)
    expect(out.find((r) => r.state === 'failed')?.error).toMatch(/ETIMEDOUT/)
  })

  it('caps per-host output and says it did', async () => {
    const h = makeRunner({
      exec: async () => ({ ok: true, code: 0, stdout: 'x'.repeat(BROADCAST_OUTPUT_CAP + 500) })
    })
    const out = await h.runner.run(req({ runId: 'r', command: 'cat big', targets: targets(1) }))
    expect(out[0].stdout).toHaveLength(BROADCAST_OUTPUT_CAP)
    expect(out[0].truncated).toBe(true)
  })

  it('never opens more channels at once than the concurrency cap', async () => {
    // Fifteen hosts behind two bastions must not become fifteen simultaneous
    // exec channels through two machines.
    let live = 0
    let peak = 0
    const h = makeRunner({
      exec: async () => {
        live++
        peak = Math.max(peak, live)
        await new Promise((r) => setTimeout(r, 5))
        live--
        return { ok: true, code: 0, stdout: '' }
      }
    })
    await h.runner.run(req({ runId: 'r', command: 'uptime', targets: targets(10) }))
    expect(peak).toBeLessThanOrEqual(BROADCAST_CONCURRENCY)
  })
})

describe('cancelling', () => {
  it('stops hosts that have not started, and says they were skipped', async () => {
    // The property the confirmation model depends on. Not "stops eventually":
    // the remaining hosts must never run at all.
    let done = 0
    const runner = new BroadcastRunner({
      exec: async () => {
        done++
        if (done === 1) runnerRef.cancel('r')
        await new Promise((r) => setTimeout(r, 1))
        return { ok: true, code: 0, stdout: '' }
      },
      emit: () => {}
    })
    const runnerRef = runner
    const out = await runner.run(req({ runId: 'r', command: 'uptime', targets: targets(8) }))
    const ran = out.filter((r) => r.state === 'ok').length
    const skipped = out.filter((r) => r.state === 'skipped').length
    expect(skipped).toBeGreaterThan(0)
    expect(ran + skipped).toBe(8)
    // Every host is accounted for: the list does not simply end early.
    expect(out).toHaveLength(8)
  })

  it('marks the terminal event as cancelled', async () => {
    const events: BroadcastProgress[] = []
    const runner = new BroadcastRunner({
      exec: async () => {
        runner.cancel('r')
        return { ok: true, code: 0, stdout: '' }
      },
      emit: (e) => events.push(e)
    })
    await runner.run(req({ runId: 'r', command: 'uptime', targets: targets(3) }))
    expect(events.find((e) => e.done)?.cancelled).toBe(true)
  })

  it('reports whether there was anything to cancel', async () => {
    const h = harness()
    expect(h.runner.cancel('nope')).toBe(false)
  })

  it('does not let one run cancel another', async () => {
    // Two independent broadcasts; cancelling one must not silently kill
    // results the user is watching in the other.
    const runner = new BroadcastRunner({ exec: async () => ({ ok: true, code: 0, stdout: '' }), emit: () => {} })
    const a = runner.run(req({ runId: 'a', command: 'uptime', targets: targets(3) }))
    runner.cancel('b')
    const out = await a
    expect(out.every((r) => r.state === 'ok')).toBe(true)
  })
})

describe('two runs under one id', () => {
  it('refuses the second rather than losing the first', async () => {
    // The map is keyed by id, so a second run overwrote the first's entry and
    // then the first to finish deleted the second's — leaving a live broadcast
    // that `cancel` could not name and a Stop button that silently did nothing.
    const runner = new BroadcastRunner({
      exec: async () => {
        await new Promise((r) => setTimeout(r, 5))
        return { ok: true, code: 0, stdout: '' }
      },
      emit: () => {}
    })
    const first = runner.run(req({ runId: 'r', command: 'uptime', targets: targets(2) }))
    await expect(runner.run(req({ runId: 'r', command: 'uptime', targets: targets(2) }))).rejects.toThrow(/already running/)
    await first
    expect(runner.isRunning('r')).toBe(false)
  })

  it('leaves a live run cancellable after another run finishes', async () => {
    const runner = new BroadcastRunner({
      exec: async () => {
        await new Promise((r) => setTimeout(r, 10))
        return { ok: true, code: 0, stdout: '' }
      },
      emit: () => {}
    })
    const slow = runner.run(req({ runId: 'slow', command: 'uptime', targets: targets(4) }))
    await runner.run(req({ runId: 'quick', command: 'uptime', targets: [] }))
    expect(runner.cancel('slow')).toBe(true)
    await slow
  })
})

describe('a host that never answers', () => {
  it('ends the run anyway, and says which host it gave up on', async () => {
    // sshExec starts its own timer only after the connection is up, so a
    // connect that never completes is not covered by the per-host timeout at
    // all. Without a guard here the worker awaits forever: no result, no
    // terminal event, and cancel cannot help because it deliberately leaves a
    // running host alone.
    const events: BroadcastProgress[] = []
    const runner = new BroadcastRunner({
      stallGraceMs: 5,
      exec: async (_cfg, _cmd) => new Promise(() => {}),
      emit: (e) => events.push(e)
    })
    const out = await runner.run(req({ runId: 'r', command: 'uptime', timeoutMs: 1, targets: targets(2) }))
    expect(out).toHaveLength(2)
    expect(out.every((r) => r.state === 'failed')).toBe(true)
    expect(out[0].error).toMatch(/never answered/)
    expect(events.filter((e) => e.done)).toHaveLength(1)
    expect(runner.isRunning('r')).toBe(false)
  })

  it('does not give up on a host that answers within the grace', async () => {
    const runner = new BroadcastRunner({
      stallGraceMs: 200,
      exec: async () => {
        await new Promise((r) => setTimeout(r, 5))
        return { ok: true, code: 0, stdout: 'fine' }
      },
      emit: () => {}
    })
    const out = await runner.run(req({ runId: 'r', command: 'uptime', timeoutMs: 1, targets: targets(2) }))
    expect(out.every((r) => r.state === 'ok')).toBe(true)
  })
})

describe('the panel that drives it', () => {
  const panel = readFileSync(resolve(__dirname, '../src/renderer/src/components/monitor/BroadcastPanel.tsx'), 'utf8')

  it('cannot be left showing Stop for a run that never started', () => {
    // `running` was set true before the call and false only after it resolved,
    // so a rejected IPC wedged the panel: the only control on screen was a
    // Stop button for a run main knew nothing about.
    expect(panel).toMatch(/} finally \{[\s\S]{0,200}setRunning\(false\)/)
    expect(panel).toMatch(/catch \(e\)[\s\S]{0,400}setError\(/)
  })

  it('keeps the run id where an unmount cannot take it', () => {
    // Switching activity unmounts this panel while main is still working
    // through the hosts. With the id in component state alone, the remounted
    // panel could neither show the run nor stop it.
    expect(panel).toMatch(/^let liveRun/m)
    expect(panel).toMatch(/useRef<string>\(liveRun\?\.runId \?\? ''\)/)
  })

  it('does not navigate away from a live run', () => {
    // The "Open a terminal" button unmounts the results it is rendered beside,
    // taking the Stop button with them.
    expect(panel).toMatch(/\{!running && \([\s\S]{0,200}setActivity\('connections'\)/)
  })

  it('builds each host cfg from the server row it already has', () => {
    // `byId.get(t.serverId)!` was an assertion nobody could prove from the
    // call site; the rows are right there.
    expect(panel).not.toMatch(/\.get\([^)]*\)!/)
  })

  it('summarises the run rather than only listing it', () => {
    expect(panel).toMatch(/summariseBroadcast\(rows\)/)
  })

  it('does not offer to re-run anything as root', () => {
    // The panel is where the person is, so it is where a "retry with sudo"
    // button would go. It must not: the escalation is theirs to type, and
    // typing it puts the command back through the risk classifier.
    expect(panel).not.toMatch(/sudo:\s*true|retryAsRoot|autoSudo/)
    // It does have to say that nothing was retried, though — silence there is
    // the same lie as a blank cron panel.
    expect(panel).toMatch(/Nothing was retried as root/)
  })

  it('has one opinion about what a result means', () => {
    // The runner classifies. A second classifier here is a second thing to
    // drift, and the two disagreeing is invisible until someone reads both.
    expect(panel).toMatch(/r\.outcome \?\? classifyBroadcastResult\(r\)/)
    expect(panel).not.toMatch(/exitCode === 127|exitCode !== 0/)
  })
})

// ---------------------------------------------------------------------------
// Which hosts said what.
//
// "Non-zero is a result, not a failure" is right and stays. It is also not an
// answer: `docker ps` across fifteen hosts comes back as fifteen `state: 'ok'`
// rows, three of which are exit 127 because those boxes have no docker, and
// finding them means reading exit codes one at a time. The classification is
// additive — `state` keeps its meaning exactly — and it is done in the runner,
// which is the only place that has both the raw streams and the transport's own
// error text.
// ---------------------------------------------------------------------------

describe('telling the fan-out apart', () => {
  const one = async (
    r: { ok: boolean; code?: number | null; stdout?: string; stderr?: string; error?: string },
    command = 'docker ps'
  ) => {
    const h = makeRunner({ exec: async () => r })
    const out = await h.runner.run(req({ runId: 'r', command, targets: targets(1) }))
    return out[0]
  }

  it('marks a host that does not have the command', async () => {
    // 127 with the shell's own wording. This is the single most common
    // fan-out surprise and it used to be indistinguishable from a command
    // that ran and failed.
    const r = await one({ ok: true, code: 127, stdout: '', stderr: 'bash: docker: command not found' })
    expect(r.outcome).toBe('missing-command')
    // And the rule the classification must not break: the host DID answer.
    expect(r.state).toBe('ok')
    expect(r.exitCode).toBe(127)
  })

  it('recognises the busybox wording too', async () => {
    const r = await one({ ok: true, code: 127, stdout: '', stderr: 'sh: 1: docker: not found' })
    expect(r.outcome).toBe('missing-command')
  })

  it('does not call a working command missing because it mentioned a missing file', async () => {
    // `cat /nope` says "No such file or directory" about its ARGUMENT. Reading
    // that as a missing binary files a working host under "go and install
    // this", which is the wrong machine.
    const r = await one({
      ok: true,
      code: 1,
      stdout: '',
      stderr: 'cat: /etc/nope: No such file or directory'
    })
    expect(r.outcome).toBe('nonzero')
  })

  it('keeps a non-zero exit a result rather than a failure', async () => {
    // grep finding nothing. If this ever becomes a failure, half the useful
    // commands look broken.
    const r = await one({ ok: true, code: 1, stdout: '', stderr: '' }, 'grep nope /etc/hosts')
    expect(r.outcome).toBe('nonzero')
    expect(r.state).toBe('ok')
  })

  it('marks a host that refused the command', async () => {
    const r = await one({ ok: true, code: 126, stdout: '', stderr: 'bash: /usr/local/bin/x: Permission denied' })
    expect(r.outcome).toBe('permission-denied')
  })

  it('marks a sudo that would have needed a password', async () => {
    const r = await one({
      ok: true,
      code: 1,
      stdout: '',
      stderr: 'sudo: a password is required'
    })
    expect(r.outcome).toBe('permission-denied')
  })

  it('does not call a command that worked permission-denied for one unreadable file', async () => {
    // `find / -name x` prints hundreds of these and still does its job.
    // Colouring the host red would bury the answer it gave.
    const r = await one({
      ok: true,
      code: 1,
      stdout: '/home/me/x\n/srv/x\n',
      stderr: "find: '/proc/1': Permission denied"
    })
    expect(r.outcome).toBe('nonzero')
  })

  it('tells a timeout from an unreachable host', async () => {
    // Different machines to go and look at: one is a slow command or a slow
    // link, the other is a box or a bastion that is down.
    const slow = await one({ ok: false, error: 'Command timed out after 60000ms' })
    expect(slow.outcome).toBe('timeout')
    const dead = await one({ ok: false, error: 'connect ECONNREFUSED 10.0.0.4:22' })
    expect(dead.outcome).toBe('unreachable')
  })

  it('classifies a stall-guard rejection as a timeout', async () => {
    // The exec that never settles: sshExec's own timer starts only after the
    // connection is up, so a bastion that accepts TCP and then says nothing is
    // caught by the guard, not by the timeout.
    const runner = new BroadcastRunner({
      stallGraceMs: 5,
      exec: async () => new Promise(() => {}),
      emit: () => {}
    })
    const out = await runner.run(req({ runId: 'r', command: 'uptime', timeoutMs: 1, targets: targets(1) }))
    expect(out[0].state).toBe('failed')
    expect(out[0].outcome).toBe('timeout')
  })

  it('classifies from the uncapped streams', async () => {
    // The shell's "command not found" is the LAST thing on stderr. A host that
    // printed 20k of deprecation warnings first would have had it cut off
    // before anyone — or anything — could read it.
    const noise = 'warning: this is fine\n'.repeat(2_000)
    const r = await one({
      ok: true,
      code: 127,
      stdout: '',
      stderr: `${noise}bash: docker: command not found`
    })
    expect(r.truncated).toBe(true)
    expect(r.stderr?.length).toBe(BROADCAST_OUTPUT_CAP)
    expect(r.outcome).toBe('missing-command')
  })

  it('marks a host that was never started', async () => {
    const h = makeRunner({ exec: async () => ({ ok: true, code: 0, stdout: '' }) })
    h.runner.cancel('r')
    const started = h.runner.run(req({ runId: 'r', command: 'uptime', targets: targets(3) }))
    h.runner.cancel('r')
    const out = await started
    expect(out.every((r) => r.outcome === 'cancelled' || r.outcome === 'ok')).toBe(true)
  })
})

describe('what the runner refuses to do about a refusal', () => {
  it('never re-runs a refused command as root', async () => {
    // The decision, pinned. A fan-out retry is N simultaneous escalations of a
    // command the user approved UNPRIVILEGED, and re-running an arbitrary
    // command is a second execution rather than a retry: `a && b` that failed
    // partway has already had an effect. The reasoning is written out at the
    // end of shared/broadcast.ts.
    const seen: string[] = []
    const h = makeRunner({
      exec: async (_cfg, cmd) => {
        seen.push(cmd)
        return { ok: true, code: 126, stdout: '', stderr: 'bash: /sbin/reboot: Permission denied' }
      }
    })
    await h.runner.run(req({ runId: 'r', command: 'systemctl restart nginx', targets: targets(3) }))
    // Once per host, verbatim. Not twice, and never with a `sudo` we added.
    expect(seen).toEqual(['systemctl restart nginx', 'systemctl restart nginx', 'systemctl restart nginx'])
    expect(seen.some((c) => /\bsudo\b/.test(c))).toBe(false)
  })

  it('has no sudo probe anywhere in the runner', () => {
    const src = readFileSync(resolve(__dirname, '../src/main/services/broadcast.ts'), 'utf8')
    expect(src).not.toMatch(/sudo -n/)
  })
})
