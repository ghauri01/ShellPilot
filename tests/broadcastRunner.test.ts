import { describe, it, expect } from 'vitest'
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
