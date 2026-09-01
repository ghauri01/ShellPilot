import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { BroadcastRunner } from '../src/main/services/broadcast'
import type { BroadcastProgress, BroadcastRequest } from '../src/shared/broadcast'
import { BROADCAST_CONCURRENCY, BROADCAST_OUTPUT_CAP } from '../src/shared/broadcast'

// The approval model is settled elsewhere. What this has to get right is not
// undermining it: a cancel that does not actually stop the remaining hosts
// would give the whole model away, since the confirmation exists precisely
// because a broadcast is hard to take back.

const targets = (n: number): BroadcastRequest['targets'] =>
  Array.from({ length: n }, (_, i) => ({ serverId: `s${i}`, serverName: `host-${i}`, cfg: {} }))

function harness(over: { exec?: Parameters<typeof makeRunner>[0]['exec'] } = {}) {
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
    const out = await h.runner.run({ runId: 'r', command: 'uptime', targets: targets(4) })
    expect(out).toHaveLength(4)
    expect(out.every((r) => r.state === 'ok')).toBe(true)
  })

  it('emits a running event before each host and a result after', async () => {
    const h = harness()
    await h.runner.run({ runId: 'r', command: 'uptime', targets: targets(2) })
    const states = h.events.filter((e) => !e.done).map((e) => e.host.state)
    expect(states.filter((s) => s === 'running')).toHaveLength(2)
    expect(states.filter((s) => s === 'ok')).toHaveLength(2)
  })

  it('always emits a terminal event, even with no targets', async () => {
    // Otherwise the renderer waits forever for a run that already stopped.
    const h = harness()
    await h.runner.run({ runId: 'r', command: 'uptime', targets: [] })
    expect(h.events.filter((e) => e.done)).toHaveLength(1)
  })

  it('treats a non-zero exit as a result, not a failure', async () => {
    // `grep` finding nothing exits 1. Calling that a failure would make half
    // the useful commands look broken.
    const h = makeRunner({ exec: async () => ({ ok: true, code: 1, stdout: '' }) })
    const out = await h.runner.run({ runId: 'r', command: 'grep x f', targets: targets(1) })
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
    const out = await h.runner.run({ runId: 'r', command: 'uptime', targets: targets(3) })
    expect(out.filter((r) => r.state === 'failed')).toHaveLength(1)
    expect(out.filter((r) => r.state === 'ok')).toHaveLength(2)
    expect(out.find((r) => r.state === 'failed')?.error).toMatch(/ETIMEDOUT/)
  })

  it('caps per-host output and says it did', async () => {
    const h = makeRunner({
      exec: async () => ({ ok: true, code: 0, stdout: 'x'.repeat(BROADCAST_OUTPUT_CAP + 500) })
    })
    const out = await h.runner.run({ runId: 'r', command: 'cat big', targets: targets(1) })
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
    await h.runner.run({ runId: 'r', command: 'uptime', targets: targets(10) })
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
    const out = await runner.run({ runId: 'r', command: 'uptime', targets: targets(8) })
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
    await runner.run({ runId: 'r', command: 'uptime', targets: targets(3) })
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
    const a = runner.run({ runId: 'a', command: 'uptime', targets: targets(3) })
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
    const first = runner.run({ runId: 'r', command: 'uptime', targets: targets(2) })
    await expect(runner.run({ runId: 'r', command: 'uptime', targets: targets(2) })).rejects.toThrow(/already running/)
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
    const slow = runner.run({ runId: 'slow', command: 'uptime', targets: targets(4) })
    await runner.run({ runId: 'quick', command: 'uptime', targets: [] })
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
    const out = await runner.run({ runId: 'r', command: 'uptime', timeoutMs: 1, targets: targets(2) })
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
    const out = await runner.run({ runId: 'r', command: 'uptime', timeoutMs: 1, targets: targets(2) })
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
})
