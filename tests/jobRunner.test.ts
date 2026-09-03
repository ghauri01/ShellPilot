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
import { JobRunner, splitAtBytes, type JobExecResult } from '../src/main/services/jobRunner'
import type { JobOutput, JobProgress, JobSpec } from '../src/shared/jobs'
import {
  JOB_ABANDONED_ERROR,
  JOB_OUTPUT_HEAD,
  JOB_OUTPUT_RATE_PER_SEC,
  JOB_OUTPUT_RETENTION_DAYS,
  JOB_OUTPUT_TAIL,
  JOB_RECORD_RETENTION_DAYS,
  classifyJobResult,
  planJob
} from '../src/shared/jobs'

// A job is a broadcast that outlives its panel, and everything below is about
// the half that makes that true: the row exists before the first host is
// touched, every transition is written, and a job that was running when the
// process stopped is `abandoned` rather than a row still claiming to be going.
//
// The harness is logTailer.test.ts's, not broadcastRunner.test.ts's. There is
// no `await new Promise(r => setTimeout(r, 5))` anywhere in this file and there
// must not be: sleep-based synchronisation gets flakier as a state machine
// grows, and this one is going to grow through B2, B3 and B4. Ordering here is
// controlled by the test HOLDING each host's exec and releasing it by name,
// which is what makes "host b has not been reached" an assertion rather than a
// hope.

const DAY = 86_400_000

let dir: string
const opened: HistoryStore[] = []

beforeEach(() => {
  resetHistoryModuleForTests()
  delete process.env[DISABLE_ENV]
  opened.length = 0
  dir = mkdtempSync(join(tmpdir(), 'shellpilot-jobs-'))
})

afterEach(async () => {
  // The .bak runs on a native async task holding the source database open;
  // deleting the directory out from under it kills the worker rather than
  // raising anything catchable. Settle each store first.
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

async function openStore(): Promise<HistoryStore> {
  const s = await loadHistory(dir)
  expect(s, 'node:sqlite did not open — every assertion below would be vacuous').not.toBeNull()
  opened.push(s!)
  return s!
}

const ok: JobExecResult = { ok: true, code: 0, stdout: 'done\n' }

function spec(over: Partial<JobSpec> = {}): JobSpec {
  return { kind: 'command', title: 'Upgrade', steps: [{ command: 'apt upgrade -y' }], ...over }
}

/**
 * A runner whose every host is held at the exec until the test lets it go.
 *
 * `isOpening(id)` is the load-bearing half: it is how "cancel stopped the
 * queued hosts" is asserted as "host c was never reached", rather than as
 * "host c's result says skipped", which a runner could produce while still
 * having opened the channel.
 */
function harness(store: HistoryStore, over: { knownSecrets?: string[] } = {}) {
  const progress: JobProgress[] = []
  const outputs: JobOutput[] = []
  const opening = new Map<string, (r: JobExecResult) => void>()
  const streams = new Map<string, (stream: 'out' | 'err', text: string) => void>()
  const ticks: (() => void)[] = []
  let clock = 0

  const runner = new JobRunner({
    now: () => clock,
    store,
    emit: (p) => progress.push(p),
    emitOutput: (o) => outputs.push(o),
    // Injected rather than a real zero-delay timer, so a coalescing flush is
    // something the test performs rather than something it waits for.
    schedule: (fn) => ticks.push(fn),
    knownSecrets: () => over.knownSecrets ?? [],
    exec: (req) =>
      new Promise<JobExecResult>((resolve) => {
        const id = (req.cfg as { id: string }).id
        streams.set(id, req.onOutput)
        opening.set(id, resolve)
      })
  })

  return {
    runner,
    progress,
    outputs,
    /** True once run() has reached the exec for this host. */
    isOpening: (id: string) => opening.has(id),
    /** Push output as this host's command produces it. */
    feed: (id: string, text: string, stream: 'out' | 'err' = 'out') => streams.get(id)!(stream, text),
    /** Let this host's command finish. */
    finish: async (id: string, r: JobExecResult = ok) => {
      opening.get(id)!(r)
      opening.delete(id)
      await settle()
    },
    flushTicks: () => {
      for (const fn of ticks.splice(0)) fn()
    },
    tick: (ms: number) => {
      clock += ms
    },
    targets: (ids: string[]) => ids.map((id) => ({ serverId: id, serverName: `host-${id}`, cfg: { id } }))
  }
}

/**
 * Drain the microtask queue.
 *
 * A single macrotask, which by definition runs after every pending microtask —
 * not a sleep hoping the work has finished by then. Nothing in the runner uses
 * a timer on the success path, so this is exact rather than probabilistic.
 */
function settle(): Promise<void> {
  return new Promise((r) => setTimeout(r, 0))
}

// ---------------------------------------------------------------------------

describe('planning a job', () => {
  it('takes the highest risk over the steps, not the first or the last', () => {
    // `apt update` then `rm -rf /var/lib/x` is a destructive job. Reading only
    // one end of the list lets the dangerous half hide behind an ordinary
    // neighbour.
    const p = planJob(
      spec({ steps: [{ command: 'apt update' }, { command: 'rm -rf /var/lib/x' }] }),
      [{ serverId: 'a', serverName: 'a' }]
    )
    expect(p.risk).toBe('destructive')
    expect(p.confirmation).toEqual({ kind: 'type-to-confirm', phrase: 'RUN' })
  })

  it('sizes the confirmation on the largest cohort, not the total', () => {
    // Blast radius is what is SIMULTANEOUS. Fifty hosts rolled five at a time
    // is five hosts broken before anyone can stop it. Sizing on the total would
    // demand the strongest confirmation for the careful, staged version of the
    // same job — teaching people that rolling slowly costs them more friction.
    const staged = Array.from({ length: 50 }, (_, i) => ({
      serverId: `s${i}`,
      serverName: `s${i}`,
      cohort: `wave-${Math.floor(i / 5)}`
    }))
    const p = planJob(spec({ steps: [{ command: 'uptime' }] }), staged)
    expect(p.blastRadius).toBe(5)
    expect(p.totalHosts).toBe(50)
    expect(p.confirmation.kind).toBe('confirm')

    // The same fifty hosts in one cohort is fifty at once, and asks for the word.
    const all = staged.map((t) => ({ ...t, cohort: undefined }))
    expect(planJob(spec({ steps: [{ command: 'uptime' }] }), all).confirmation.kind).toBe(
      'type-to-confirm'
    )
  })

  it('says each reason once', () => {
    const p = planJob(
      spec({ steps: [{ command: 'rm -rf /a' }, { command: 'rm -rf /b' }] }),
      [{ serverId: 'a', serverName: 'a' }]
    )
    expect(p.reasons).toEqual(['deletes files recursively or forcibly'])
  })
})

describe('classifying a host', () => {
  it('extends the broadcast rules rather than restating them', () => {
    // The one thing that must not drift: a non-zero exit is a result. `grep`
    // finding nothing exits 1 and is a perfectly good answer.
    expect(classifyJobResult({ serverId: 'a', serverName: 'a', state: 'ok', exitCode: 1 })).toBe('nonzero')
    expect(
      classifyJobResult({ serverId: 'a', serverName: 'a', state: 'ok', exitCode: 127, stderr: 'x: not found' })
    ).toBe('missing-command')
  })

  it('has no answer while a host is waiting', () => {
    // `waiting` is not `pending`: the job has reached this host and is holding.
    // Neither is an outcome, and a category for "we do not know yet" would be
    // counted in a summary as though it were an answer.
    expect(classifyJobResult({ serverId: 'a', serverName: 'a', state: 'waiting' })).toBeNull()
  })

  it('calls an abandoned host abandoned, not unreachable', () => {
    // The host did nothing wrong. Filing this under `unreachable` points at the
    // machine; under `timeout` it claims we waited and gave up. Neither is what
    // happened: the app stopped and sshd sent SIGHUP.
    expect(
      classifyJobResult({ serverId: 'a', serverName: 'a', state: 'failed', error: JOB_ABANDONED_ERROR })
    ).toBe('abandoned')
  })
})

describe('running a job', () => {
  it('writes the row before the first host is touched', async () => {
    const store = await openStore()
    const h = harness(store)
    const p = h.runner.run({ jobId: 'j1', spec: spec(), targets: h.targets(['a']) })
    await settle()

    // The whole of what B1 adds over a broadcast. A crash between "the user
    // pressed Run" and "the first command went out" leaves a job in the store
    // rather than nothing at all.
    const mid = store.readJob('j1')
    expect(mid?.state).toBe('running')
    expect(mid?.startedAt).toBe(0)
    expect(mid?.targets.map((t) => t.state)).toEqual(['running'])
    expect(mid?.risk).toBe('elevated')
    // The confirmation is recorded as it was demanded, not re-derived on read.
    expect(mid?.confirmation).toEqual({ kind: 'confirm' })

    h.tick(500)
    await h.finish('a')
    const done = await p
    expect(done.state).toBe('done')
    expect(done.targets[0]).toMatchObject({ state: 'ok', outcome: 'ok', exitCode: 0, ms: 500 })
  })

  it('keeps the other hosts when one is unreachable', async () => {
    const store = await openStore()
    const h = harness(store)
    const p = h.runner.run({ jobId: 'j1', spec: spec(), targets: h.targets(['a', 'b']) })
    await settle()
    await h.finish('a', { ok: false, error: 'connect ECONNREFUSED' })
    await h.finish('b')
    const done = await p

    const byId = Object.fromEntries(done.targets.map((t) => [t.serverId, t]))
    expect(byId.a).toMatchObject({ state: 'failed', outcome: 'unreachable' })
    expect(byId.b).toMatchObject({ state: 'ok', outcome: 'ok' })
  })

  it('stops a host at the first step that does not exit zero', async () => {
    // `a && b`, because that is what a person typing two steps means. A job
    // whose second step ran after its first failed did something nobody asked
    // for.
    const store = await openStore()
    const h = harness(store)
    const p = h.runner.run({
      jobId: 'j1',
      spec: spec({ steps: [{ command: 'apt update' }, { command: 'apt upgrade -y' }] }),
      targets: h.targets(['a'])
    })
    await settle()
    await h.finish('a', { ok: true, code: 1, stderr: 'E: could not get lock\n' })
    const done = await p

    expect(done.targets[0]).toMatchObject({ state: 'ok', outcome: 'nonzero', exitCode: 1 })
    // The second step never ran: nothing is waiting at the exec for host a.
    expect(h.isOpening('a')).toBe(false)
  })

  it('fires a terminal event even with no targets at all', async () => {
    const store = await openStore()
    const h = harness(store)
    await h.runner.run({ jobId: 'j1', spec: spec(), targets: [] })
    expect(h.progress.filter((p) => p.done)).toHaveLength(1)
    expect(store.readJob('j1')?.state).toBe('done')
  })

  it('refuses a second run under a live id', async () => {
    // Two runs under one id is not a second job, it is one job the user can no
    // longer address: cancel names a single id and the first to finish would
    // delete the other's entry.
    const store = await openStore()
    const h = harness(store)
    const p = h.runner.run({ jobId: 'j1', spec: spec(), targets: h.targets(['a']) })
    await settle()
    await expect(h.runner.run({ jobId: 'j1', spec: spec(), targets: h.targets(['b']) })).rejects.toThrow(
      /already running/
    )
    await h.finish('a')
    await p
  })
})

describe('cancelling', () => {
  it('leaves a running host alone and stops the queued ones', async () => {
    const store = await openStore()
    const h = harness(store)
    const p = h.runner.run({
      jobId: 'j1',
      spec: spec({ concurrency: 1 }),
      targets: h.targets(['a', 'b', 'c'])
    })
    await settle()
    expect(h.isOpening('a')).toBe(true)
    expect(h.isOpening('b')).toBe(false)

    expect(h.runner.cancel('j1')).toBe(true)
    // Persisted before any host notices. A cancel the store does not know about
    // is a cancel that a restart undoes.
    expect(store.readJob('j1')?.cancelledAt).toBe(0)

    // Killing a command mid-write is how a half-applied change happens, so the
    // host that is already running finishes.
    await h.finish('a')

    // Asserted HERE, before the run is awaited, and that ordering is
    // deliberate: a runner that went on to open b would leave this test hanging
    // at the exec it never releases, and a timeout is a much worse failure
    // message than "expected true to be false" on the line that says what went
    // wrong.
    expect(h.isOpening('b'), 'host b was reached despite the cancel').toBe(false)
    expect(h.isOpening('c'), 'host c was reached despite the cancel').toBe(false)

    const done = await p
    const byId = Object.fromEntries(done.targets.map((t) => [t.serverId, t]))
    expect(byId.a).toMatchObject({ state: 'ok', outcome: 'ok' })
    expect(byId.b).toMatchObject({ state: 'skipped', outcome: 'cancelled' })
    expect(byId.c).toMatchObject({ state: 'skipped', outcome: 'cancelled' })
    expect(done.state).toBe('cancelled')
  })

  it('cancels nothing it does not have', async () => {
    const store = await openStore()
    const h = harness(store)
    expect(h.runner.cancel('nope')).toBe(false)
  })
})

describe('a job that was running when ShellPilot stopped', () => {
  it('is adopted from rows alone by a runner that never saw it', async () => {
    const store = await openStore()
    const first = harness(store)
    // Deliberately not awaited: this run never finishes, which is exactly what
    // a process going away looks like to the rows it left behind.
    void first.runner.run({
      jobId: 'j1',
      spec: spec({ concurrency: 1 }),
      targets: first.targets(['a', 'b'])
    })
    await settle()
    expect(store.readJob('j1')?.state).toBe('running')
    first.runner.disposeAll()

    // A second runner over the same store, with a different executor and no
    // memory of the first. Everything it knows comes off disk.
    const second = harness(store)
    second.tick(9_000)
    const adopted = second.runner.adopt()

    expect(adopted).toHaveLength(1)
    const job = store.readJob('j1')!
    expect(job.state).toBe('abandoned')
    expect(job.endedAt).toBe(9_000)

    const byId = Object.fromEntries(job.targets.map((t) => [t.serverId, t]))
    // The host that was mid-command. Not `timeout` (we did not wait), not
    // `unreachable` (the host was fine) — the channel died with the process and
    // the remote command was sent SIGHUP.
    expect(byId.a).toMatchObject({ state: 'failed', outcome: 'abandoned' })
    expect(byId.a.error).toContain('dpkg --configure -a')
    // The host behind it never started, and says so rather than inheriting the
    // running host's story.
    expect(byId.b).toMatchObject({ state: 'skipped', outcome: 'abandoned' })
    expect(byId.b.error).toMatch(/before this host was reached/)
  })

  it('does not touch a job this process is still running', async () => {
    const store = await openStore()
    const h = harness(store)
    const p = h.runner.run({ jobId: 'j1', spec: spec(), targets: h.targets(['a']) })
    await settle()

    // adopt() is a startup call, but a caller that runs it twice must not
    // rewrite a live run's rows out from under it.
    expect(h.runner.adopt()).toEqual([])
    expect(store.readJob('j1')?.state).toBe('running')

    await h.finish('a')
    expect((await p).state).toBe('done')
  })
})

describe('output', () => {
  it('keeps the head and the tail, and says how much of the middle went', async () => {
    // Broadcast keeps a 20 KB HEAD and calls it truncated. For a job that is
    // wrong: the answer to "did the upgrade work" is in the LAST twenty lines
    // — `E: Sub-process /usr/bin/dpkg returned an error code` — and a
    // prefix-only capture throws away exactly that, silently, every time the
    // output is long.
    const store = await openStore()
    const h = harness(store)
    const p = h.runner.run({ jobId: 'j1', spec: spec(), targets: h.targets(['a']) })
    await settle()

    const half = JOB_OUTPUT_TAIL / 2
    h.feed('a', 'H'.repeat(JOB_OUTPUT_HEAD))
    h.feed('a', 'B'.repeat(half))
    h.feed('a', 'C'.repeat(half))
    h.feed('a', 'D'.repeat(half))
    h.feed('a', `${'E'.repeat(half - 1)}\nE: dpkg returned an error code`.slice(0, half))
    await h.finish('a', { ok: true, code: 0 })
    await p

    const target = store.readJob('j1')!.targets[0]
    expect(target.outElided).toBe(JOB_OUTPUT_TAIL)
    expect(target.truncated).toBe(true)

    const rows = store.readJobOutput('j1', 'a')
    // head, the elision notice, then the last two chunks in order.
    expect(rows).toHaveLength(4)
    expect(rows[0].text.startsWith('H')).toBe(true)
    expect(rows[0].text).toHaveLength(JOB_OUTPUT_HEAD)
    expect(rows[1].text).toContain(`${JOB_OUTPUT_TAIL} bytes elided`)
    expect(rows[2].text.startsWith('D')).toBe(true)
    expect(rows[3].text.startsWith('E')).toBe(true)
    // The gap is a ROW, in order, not a flag somewhere else: a reader scrolling
    // the output sees where the missing bytes were.
    expect(rows.map((r) => r.seq)).toEqual([0, 1, 2, 3])
    // Bytes, not characters: the notice contains an ellipsis, and a cap that
    // counted UTF-16 units would drift from the byte budget it is spending.
    expect(target.outOffset).toBe(
      JOB_OUTPUT_HEAD +
        rows.slice(1).reduce((n, r) => n + Buffer.byteLength(r.text, 'utf8'), 0)
    )
  })

  it('caps inside a single chunk, because that is what the attached path sends', async () => {
    // The one that matters most, and the one a chunk-boundary cap gets wrong.
    // `sshExec` does not stream: it hands the whole of a host's output over in
    // one piece at the end. A cap that only compared whole chunks against the
    // budget would see one chunk, find the head empty, and write all of it —
    // the exact unbounded write the budget exists to prevent, on the one code
    // path B1 actually ships.
    const store = await openStore()
    const h = harness(store)
    const p = h.runner.run({ jobId: 'j1', spec: spec(), targets: h.targets(['a']) })
    await settle()
    const ending = 'E: dpkg returned an error\n'
    const stdout = `${'S'.repeat(JOB_OUTPUT_HEAD + JOB_OUTPUT_TAIL + 500_000)}${ending}`
    const total = Buffer.byteLength(stdout, 'utf8')
    await h.finish('a', { ok: true, code: 0, stdout })
    await p

    const rows = store.readJobOutput('j1', 'a')
    const stored = rows.reduce((n, r) => n + Buffer.byteLength(r.text, 'utf8'), 0)
    const target = store.readJob('j1')!.targets[0]

    expect(target.outElided).toBe(total - JOB_OUTPUT_HEAD - JOB_OUTPUT_TAIL)
    // Within the budget plus the notice, rather than the whole five megabytes.
    expect(stored).toBeLessThanOrEqual(
      JOB_OUTPUT_HEAD + JOB_OUTPUT_TAIL + Buffer.byteLength(rows[1]?.text ?? '', 'utf8')
    )
    expect(target.outOffset).toBe(stored)
    // And the answer — the last line — survived, which is the whole reason the
    // tail is kept.
    expect(rows[rows.length - 1].text.endsWith(ending)).toBe(true)
  })

  it('never splits a code point at the byte boundary', () => {
    // A cut landing inside a multi-byte sequence produces a replacement
    // character on BOTH sides of the seam — visible corruption in output
    // someone is reading to find out what went wrong.
    const text = 'aé'.repeat(10)
    for (let budget = 0; budget <= Buffer.byteLength(text, 'utf8') + 2; budget++) {
      const [head, tail] = splitAtBytes(text, budget)
      expect(head + tail, `budget ${budget}`).toBe(text)
      expect(head, `budget ${budget}`).not.toContain('�')
      expect(tail, `budget ${budget}`).not.toContain('�')
      expect(Buffer.byteLength(head, 'utf8'), `budget ${budget}`).toBeLessThanOrEqual(budget)
    }
  })

  it('persists nothing until the head fills, then nothing is lost from the front', async () => {
    const store = await openStore()
    const h = harness(store)
    const p = h.runner.run({ jobId: 'j1', spec: spec(), targets: h.targets(['a']) })
    await settle()
    h.feed('a', 'short output\n')
    await h.finish('a', { ok: true, code: 0 })
    await p

    expect(store.readJobOutput('j1', 'a').map((r) => r.text)).toEqual(['short output\n'])
    expect(store.readJob('j1')!.targets[0].outElided).toBe(0)
    expect(store.readJob('j1')!.targets[0].truncated).toBeUndefined()
  })

  it('redacts before it persists, never on the way out', async () => {
    // A secret that reaches the store is a secret in a file on disk that
    // outlives the session, and a redaction applied on read is one SELECT away
    // from being skipped.
    const store = await openStore()
    const h = harness(store, { knownSecrets: ['s3cr3t-vault-value'] })
    const p = h.runner.run({ jobId: 'j1', spec: spec(), targets: h.targets(['a']) })
    await settle()
    await h.finish('a', {
      ok: true,
      code: 0,
      stdout: 'DB_PASSWORD=hunter2\nremote said s3cr3t-vault-value\n'
    })
    await p

    const text = store.readJobOutput('j1', 'a').map((r) => r.text).join('')
    expect(text).not.toContain('hunter2')
    expect(text).not.toContain('s3cr3t-vault-value')
    expect(text).toContain('[REDACTED]')
    // And the pane got the redacted text too — one redaction, at the one place
    // the raw bytes are still in hand.
    expect(h.outputs.map((o) => o.text).join('')).not.toContain('hunter2')
  })

  it('coalesces a tick into one message rather than one per chunk', async () => {
    // `apt` writes a progress line per package. One IPC message each is a
    // flood, and a flood is indistinguishable from a freeze.
    const store = await openStore()
    const h = harness(store)
    const p = h.runner.run({ jobId: 'j1', spec: spec(), targets: h.targets(['a']) })
    await settle()
    h.feed('a', 'one\n')
    h.feed('a', 'two\n')
    h.feed('a', 'three\n')
    h.flushTicks()

    expect(h.outputs).toHaveLength(1)
    expect(h.outputs[0]).toMatchObject({ serverId: 'a', stream: 'out', text: 'one\ntwo\nthree\n' })

    await h.finish('a', { ok: true, code: 0 })
    await p
  })

  it('starts a new message when the stream changes', async () => {
    // Merging stdout and stderr loses which one said what, and that is the only
    // question an error is ever read for.
    const store = await openStore()
    const h = harness(store)
    const p = h.runner.run({ jobId: 'j1', spec: spec(), targets: h.targets(['a']) })
    await settle()
    h.feed('a', 'out1', 'out')
    h.feed('a', 'err1', 'err')
    h.feed('a', 'out2', 'out')
    h.flushTicks()

    expect(h.outputs.map((o) => `${o.stream}:${o.text}`)).toEqual(['out:out1', 'err:err1', 'out:out2'])
    await h.finish('a', { ok: true, code: 0 })
    await p
  })

  it('announces what the rate limit dropped instead of leaving a silent gap', async () => {
    // A gap nobody mentions is how someone concludes the upgrade hung.
    const store = await openStore()
    const h = harness(store)
    const p = h.runner.run({ jobId: 'j1', spec: spec(), targets: h.targets(['a']) })
    await settle()

    // The clock does not move, so every one of these lands in the same
    // one-second window.
    for (let i = 0; i < JOB_OUTPUT_RATE_PER_SEC + 3; i++) {
      h.feed('a', `chunk ${i}\n`)
      h.flushTicks()
    }

    const emitted = h.outputs.filter((o) => o.text !== '')
    expect(emitted).toHaveLength(JOB_OUTPUT_RATE_PER_SEC)
    const announced = h.outputs.filter((o) => (o.dropped ?? 0) > 0)
    expect(announced.length).toBeGreaterThan(0)
    expect(announced.reduce((n, o) => n + (o.dropped ?? 0), 0)).toBe(3)

    await h.finish('a', { ok: true, code: 0 })
    await p
  })

  it('lets the next window through', async () => {
    const store = await openStore()
    const h = harness(store)
    const p = h.runner.run({ jobId: 'j1', spec: spec(), targets: h.targets(['a']) })
    await settle()
    for (let i = 0; i < JOB_OUTPUT_RATE_PER_SEC; i++) {
      h.feed('a', 'x')
      h.flushTicks()
    }
    h.tick(1000)
    h.feed('a', 'after the window\n')
    h.flushTicks()

    expect(h.outputs[h.outputs.length - 1].text).toBe('after the window\n')
    await h.finish('a', { ok: true, code: 0 })
    await p
  })
})

describe('retention', () => {
  it('drops the output and keeps the job', async () => {
    // Output cannot be downsampled the way a metric series can — there is no
    // hourly mean of a dpkg log — so the only honest choices are keep it or
    // drop it. The summary behind it is tiny and lives twelve times longer.
    const store = await openStore()
    const h = harness(store)
    const p = h.runner.run({ jobId: 'j1', spec: spec(), targets: h.targets(['a']) })
    await settle()
    await h.finish('a', { ok: true, code: 0, stdout: 'a lot of dpkg chatter\n' })
    await p

    expect(store.readJobOutput('j1', 'a')).not.toHaveLength(0)

    const justInside = store.jobRetain((JOB_OUTPUT_RETENTION_DAYS - 1) * DAY)
    expect(justInside).toEqual({ outputDropped: 0, jobsDropped: 0 })

    const past = store.jobRetain((JOB_OUTPUT_RETENTION_DAYS + 1) * DAY)
    expect(past.outputDropped).toBeGreaterThan(0)
    expect(past.jobsDropped).toBe(0)
    // The row that answers "when did we last upgrade web-2, and did it exit 0"
    // is still there, with its per-host detail.
    const kept = store.readJob('j1')
    expect(kept?.state).toBe('done')
    expect(kept?.targets[0]).toMatchObject({ serverId: 'a', outcome: 'ok', exitCode: 0 })
    expect(store.readJobOutput('j1', 'a')).toEqual([])
  })

  it('drops the job itself only at the far horizon', async () => {
    const store = await openStore()
    const h = harness(store)
    const p = h.runner.run({ jobId: 'j1', spec: spec(), targets: h.targets(['a']) })
    await settle()
    await h.finish('a')
    await p

    expect(store.jobRetain((JOB_RECORD_RETENTION_DAYS - 1) * DAY).jobsDropped).toBe(0)
    expect(store.jobRetain((JOB_RECORD_RETENTION_DAYS + 1) * DAY).jobsDropped).toBe(1)
    expect(store.readJob('j1')).toBeNull()
    // The targets go with it. A job_target row whose job is gone is a row
    // nothing can ever read.
    expect(store.counts().jobs).toBe(0)
  })

  it('ships with the tables rather than after someone complains', async () => {
    // The store's own history is the argument: a retention rule added later
    // means the rows are already written. jobRetain exists in the same commit
    // as the three tables, and this asserts the horizons are the documented
    // ones rather than numbers somebody typed.
    expect(JOB_OUTPUT_RETENTION_DAYS).toBe(30)
    expect(JOB_RECORD_RETENTION_DAYS).toBe(365)
    expect(JOB_RECORD_RETENTION_DAYS).toBeGreaterThan(JOB_OUTPUT_RETENTION_DAYS)
  })
})

describe('disposal', () => {
  it('stops queued hosts when the window goes', async () => {
    // A job outlives its panel by design, so a window closing is exactly the
    // case where one would keep working through its queue with nowhere to
    // report.
    const store = await openStore()
    const h = harness(store)
    void h.runner.run({
      jobId: 'j1',
      spec: spec({ concurrency: 1 }),
      targets: h.targets(['a', 'b'])
    })
    await settle()
    h.runner.disposeAll()
    expect(h.runner.isRunning('j1')).toBe(false)
    await settle()
    expect(h.isOpening('b')).toBe(false)
  })
})
