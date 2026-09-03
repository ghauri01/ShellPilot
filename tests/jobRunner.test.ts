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
import { attachedJobExecutor, type ExecStreamHandlers } from '../src/main/services/jobExec'
import type {
  JobOutput,
  JobProgress,
  JobRunRequest,
  JobSpec,
  JobTargetRef
} from '../src/shared/jobs'
import {
  JOB_ABANDONED_ERROR,
  JOB_OUTPUT_HEAD,
  JOB_OUTPUT_RATE_PER_SEC,
  JOB_OUTPUT_RETENTION_DAYS,
  JOB_REDACT_LINE_CARRY,
  JOB_OUTPUT_TAIL,
  JOB_RECORD_RETENTION_DAYS,
  classifyJobResult,
  jobApprovalFor,
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
 * B3: the approval record main now demands with every run.
 *
 * Minted from the same `planJob` the runner re-derives, so the default case is
 * a record that agrees — which is what lets every test below go on asserting
 * what it was written to assert. The tests that care about B3 pass an
 * explicitly WRONG spec or target list and watch the run be refused; nothing
 * here weakens the check, it only supplies the thing a renderer would.
 */
function approved(
  req: Omit<JobRunRequest, 'approval'>,
  o: { phrase?: string | null; confirmedAt?: number; spec?: JobSpec; targets?: JobTargetRef[] } = {}
): JobRunRequest {
  // The spec and targets the record is minted FROM default to the ones the run
  // uses, and can be overridden so a test can approve one thing and run
  // another.
  const spec = o.spec ?? req.spec
  const targets = o.targets ?? req.targets
  const plan = planJob(spec, targets)
  return {
    ...req,
    approval: jobApprovalFor(spec, targets, {
      phrase:
        o.phrase !== undefined
          ? o.phrase
          : plan.confirmation.kind === 'type-to-confirm'
            ? plan.confirmation.phrase
            : null,
      confirmedAt: o.confirmedAt ?? 1_700_000_000_000
    })
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
    const p = h.runner.run(approved({ jobId: 'j1', spec: spec(), targets: h.targets(['a']) }))
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
    const p = h.runner.run(approved({ jobId: 'j1', spec: spec(), targets: h.targets(['a', 'b']) }))
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
    const p = h.runner.run(approved({
      jobId: 'j1',
      spec: spec({ steps: [{ command: 'apt update' }, { command: 'apt upgrade -y' }] }),
      targets: h.targets(['a'])
    }))
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
    await h.runner.run(approved({ jobId: 'j1', spec: spec(), targets: [] }))
    // The COUNT was the whole assertion, which one event for any job, carrying
    // anything at all, satisfied. What a listener is actually waiting for is
    // this job id and the finished row beside it — an event with no `job` on it
    // leaves a renderer holding a `done` it cannot draw.
    expect(h.progress.filter((p) => p.done).map((p) => `${p.jobId}:${p.job?.state}`)).toEqual([
      'j1:done'
    ])
    expect(store.readJob('j1')?.state).toBe('done')
  })

  it('refuses a second run under a live id', async () => {
    // Two runs under one id is not a second job, it is one job the user can no
    // longer address: cancel names a single id and the first to finish would
    // delete the other's entry.
    const store = await openStore()
    const h = harness(store)
    const p = h.runner.run(approved({ jobId: 'j1', spec: spec(), targets: h.targets(['a']) }))
    await settle()
    await expect(h.runner.run(approved({ jobId: 'j1', spec: spec(), targets: h.targets(['b']) }))).rejects.toThrow(
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
    const p = h.runner.run(approved({
      jobId: 'j1',
      spec: spec({ concurrency: 1 }),
      targets: h.targets(['a', 'b', 'c'])
    }))
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
    void first.runner.run(approved({
      jobId: 'j1',
      spec: spec({ concurrency: 1 }),
      targets: first.targets(['a', 'b'])
    }))
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
    //
    // `cancelled` — whose label is "not run" — and NOT `abandoned`. Nothing
    // ever touched this host, and `abandoned`'s own definition is "ShellPilot
    // stopped while this host was RUNNING". It is also the answer a
    // re-classification gives, and a stored outcome that disagrees with
    // classifyJobResult over the same row is a summary that changes depending
    // on which of the two a reader happened to use.
    expect(byId.b).toMatchObject({ state: 'skipped', outcome: 'cancelled' })
    expect(byId.b.error).toMatch(/before this host was reached/)
    expect(classifyJobResult(byId.b)).toBe(byId.b.outcome)
    expect(classifyJobResult(byId.a)).toBe(byId.a.outcome)
  })

  it('does not touch a job this process is still running', async () => {
    const store = await openStore()
    const h = harness(store)
    const p = h.runner.run(approved({ jobId: 'j1', spec: spec(), targets: h.targets(['a']) }))
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
    const p = h.runner.run(approved({ jobId: 'j1', spec: spec(), targets: h.targets(['a']) }))
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
    const p = h.runner.run(approved({ jobId: 'j1', spec: spec(), targets: h.targets(['a']) }))
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
    // Asserted BEFORE the arithmetic that spends it. `rows[1]?.text ?? ''`
    // below is a term on both sides of the same collection: drop the notice row
    // altogether and `stored` and the expected total fall by the same amount,
    // and the sum goes on balancing over output with no gap marked in it.
    expect(rows[1]?.text, 'nothing marks where the elided middle was').toContain('bytes elided')
    // EXACTLY the budget plus the notice, not "at most". A `<=` here is
    // satisfied by an implementation that stores the head and throws the tail
    // away — the failure this whole policy exists to prevent — so it asserted
    // nothing the other expectations did not already cover.
    expect(stored).toBe(
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
    const p = h.runner.run(approved({ jobId: 'j1', spec: spec(), targets: h.targets(['a']) }))
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
    const p = h.runner.run(approved({ jobId: 'j1', spec: spec(), targets: h.targets(['a']) }))
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

  it('redacts a secret split across two chunks', async () => {
    // Redaction is applied per chunk, and a socket boundary does not respect a
    // regex: `DB_PASSWORD=` ending one chunk and `hunter2` starting the next
    // matches no rule, and both halves are persisted verbatim. Latent while the
    // executor delivered one chunk; real the moment it streams.
    const store = await openStore()
    const h = harness(store)
    const p = h.runner.run(approved({ jobId: 'j1', spec: spec(), targets: h.targets(['a']) }))
    await settle()
    h.feed('a', 'DB_PASSWORD=')
    h.feed('a', 'hunter2\n')
    h.flushTicks()
    await h.finish('a', { ok: true, code: 0 })
    await p

    const text = store
      .readJobOutput('j1', 'a')
      .map((r) => r.text)
      .join('')
    expect(text, 'a secret straddling a chunk boundary was written to disk').not.toContain('hunter2')
    expect(text).toContain('[REDACTED]')
    expect(h.outputs.map((o) => o.text).join('')).not.toContain('hunter2')
  })

  it('redacts a private key that arrives one line at a time', async () => {
    // The one rule that spans lines, and the one whose seam costs a private key
    // rather than a password. The line boundary is not enough for it on its
    // own: `cat id_rsa` over a streaming channel arrives in whatever pieces the
    // socket hands over.
    const store = await openStore()
    const h = harness(store)
    const p = h.runner.run(approved({ jobId: 'j1', spec: spec(), targets: h.targets(['a']) }))
    await settle()
    h.feed('a', '-----BEGIN OPENSSH PRIVATE KEY-----\n')
    h.feed('a', 'b3BlbnNzaC1rZXktdjEAAAAABG5vbmU\n')
    h.feed('a', 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n')
    h.feed('a', '-----END OPENSSH PRIVATE KEY-----\n')
    h.flushTicks()
    await h.finish('a', { ok: true, code: 0 })
    await p

    const text = store
      .readJobOutput('j1', 'a')
      .map((r) => r.text)
      .join('')
    expect(text, 'a private key split over four chunks was written to disk').not.toContain(
      'b3BlbnNzaC1rZXktdjEAAAAABG5vbmU'
    )
    expect(text).toContain('[REDACTED]')
    expect(h.outputs.map((o) => o.text).join('')).not.toContain('b3BlbnNzaC1rZXktdjEAAAAABG5vbmU')
  })

  it('releases unterminated output once it passes the carry budget', async () => {
    // The cost of joining at the line boundary, pinned rather than left to be
    // discovered: output that ends at neither a newline nor a carriage return
    // is held — but only until it is this big, and never past the end of the
    // host's run. A prompt waiting on input must not leave the pane blank
    // forever.
    const store = await openStore()
    const h = harness(store)
    const p = h.runner.run(approved({ jobId: 'j1', spec: spec(), targets: h.targets(['a']) }))
    await settle()

    h.feed('a', 'no newline here')
    h.flushTicks()
    expect(h.outputs, 'an unterminated line went out before it could be joined').toEqual([])

    // Past the budget, so waiting any longer would be worse than the seam.
    h.feed('a', 'y'.repeat(JOB_REDACT_LINE_CARRY))
    h.flushTicks()
    expect(h.outputs).toHaveLength(1)
    expect(h.outputs[0].text.startsWith('no newline here')).toBe(true)

    // And whatever is still held when the host finishes goes out with it.
    h.feed('a', 'trailing')
    await h.finish('a', { ok: true, code: 0 })
    await p
    expect(h.outputs.map((o) => o.text).join('')).toContain('trailing')
    expect(
      store
        .readJobOutput('j1', 'a')
        .map((r) => r.text)
        .join('')
    ).toContain('trailing')
  })

  it('redacts the error it records, not only the output', async () => {
    // Every byte of output is scrubbed and the error beside it was not, into
    // the same row in the same file. A transport error routinely carries the
    // connection string it failed on.
    const store = await openStore()
    const h = harness(store, { knownSecrets: ['s3cr3t-vault-value'] })
    const p = h.runner.run(approved({ jobId: 'j1', spec: spec(), targets: h.targets(['a']) }))
    await settle()
    await h.finish('a', {
      ok: false,
      error: 'handshake failed for postgres://svc:s3cr3t-vault-value@db.internal:5432'
    })
    const done = await p

    expect(done.targets[0].error).not.toContain('s3cr3t-vault-value')
    expect(done.targets[0].error).toContain('[REDACTED]')
    expect(store.readJob('j1')!.targets[0].error).not.toContain('s3cr3t-vault-value')
    expect(JSON.stringify(h.progress)).not.toContain('s3cr3t-vault-value')
  })

  it('remembers after a restart that the executor dropped output', async () => {
    // `truncated` had nowhere to live: no patch field, no column, and
    // toJobTarget re-derives it from out_elided. So it was emitted live and
    // thrown away, and a restart turned "dpkg failed" back into "the command
    // produced no error" — verbatim the failure out_elided exists to prevent.
    const store = await openStore()
    const h = harness(store)
    const p = h.runner.run(approved({ jobId: 'j1', spec: spec(), targets: h.targets(['a']) }))
    await settle()
    await h.finish('a', {
      ok: true,
      code: 0,
      stdout: 'the first 200 KB\n',
      truncated: true,
      elided: 3_000_000
    })
    const done = await p
    expect(done.targets[0].truncated).toBe(true)

    // The read a restart does. The live object is not the record.
    const reread = store.readJob('j1')!.targets[0]
    expect(reread.outElided).toBe(3_000_000)
    expect(reread.truncated, 'a restart read the job back as untruncated').toBe(true)
  })

  it('says which step failed and that the rest did not run', async () => {
    // `result` is overwritten per step, so the row kept only the last step's
    // exit code and nothing said which of three steps produced it, that the
    // third never ran, or where one step's output ended and the next began.
    const store = await openStore()
    const h = harness(store)
    const p = h.runner.run(approved({
      jobId: 'j1',
      spec: spec({
        steps: [{ command: 'apt update' }, { command: 'apt upgrade -y' }, { command: 'reboot' }]
      }),
      targets: h.targets(['a'])
    }))
    await settle()
    await h.finish('a', { ok: true, code: 0, stdout: 'Reading package lists...\n' })
    await h.finish('a', { ok: true, code: 100, stderr: 'E: Sub-process dpkg returned an error\n' })
    const done = await p

    const text = store
      .readJobOutput('j1', 'a')
      .map((r) => r.text)
      .join('')
    expect(text, 'nothing marks where one step ended and the next began').toContain('step 2 of 3')
    expect(done.targets[0].exitCode).toBe(100)
    expect(done.targets[0].error, 'the row does not say which step failed').toMatch(/step 2 of 3/)
    expect(done.targets[0].error, 'the row does not say the rest were skipped').toMatch(
      /Step 3 did not run/
    )
  })

  it('coalesces a tick into one message rather than one per chunk', async () => {
    // `apt` writes a progress line per package. One IPC message each is a
    // flood, and a flood is indistinguishable from a freeze.
    const store = await openStore()
    const h = harness(store)
    const p = h.runner.run(approved({ jobId: 'j1', spec: spec(), targets: h.targets(['a']) }))
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
    const p = h.runner.run(approved({ jobId: 'j1', spec: spec(), targets: h.targets(['a']) }))
    await settle()
    // Newline-terminated, like real command output: an unterminated trailing
    // line is held back so a secret split across the chunk seam is redacted as
    // one string. That behaviour has its own test below.
    h.feed('a', 'out1\n', 'out')
    h.feed('a', 'err1\n', 'err')
    h.feed('a', 'out2\n', 'out')
    h.flushTicks()

    expect(h.outputs.map((o) => `${o.stream}:${o.text}`)).toEqual([
      'out:out1\n',
      'err:err1\n',
      'out:out2\n'
    ])
    await h.finish('a', { ok: true, code: 0 })
    await p
  })

  it('announces what the rate limit dropped instead of leaving a silent gap', async () => {
    // A gap nobody mentions is how someone concludes the upgrade hung.
    const store = await openStore()
    const h = harness(store)
    const p = h.runner.run(approved({ jobId: 'j1', spec: spec(), targets: h.targets(['a']) }))
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
    const p = h.runner.run(approved({ jobId: 'j1', spec: spec(), targets: h.targets(['a']) }))
    await settle()
    for (let i = 0; i < JOB_OUTPUT_RATE_PER_SEC; i++) {
      h.feed('a', 'x\n')
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
    const p = h.runner.run(approved({ jobId: 'j1', spec: spec(), targets: h.targets(['a']) }))
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
    const p = h.runner.run(approved({ jobId: 'j1', spec: spec(), targets: h.targets(['a']) }))
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

  it('refuses to drop the job rows against a clock a year ahead', async () => {
    // jobRetain's own reasoning is that a wrong clock costs "a month of
    // chatter, not a year of history" because the summary survives twelve
    // times longer. It also drops the job and target rows at now - 365d, so a
    // clock more than a year ahead — the snapshot-restore case retain()'s
    // guard cites, and which retain() itself refuses with 'clock-ahead' on the
    // very same pass — deletes the change log that argument depends on.
    const store = await openStore()
    const h = harness(store)
    const NOW = 1_700_000_000_000
    h.tick(NOW)
    const p = h.runner.run(approved({ jobId: 'j1', spec: spec(), targets: h.targets(['a']) }))
    await settle()
    await h.finish('a', { ok: true, code: 0, stdout: 'a lot of dpkg chatter\n' })
    await p

    const ahead = store.jobRetain(NOW + 400 * DAY)
    expect(ahead.skipped, 'the job-row sweep ran against a clock 400 days ahead').toBe('clock-ahead')
    expect(ahead.jobsDropped).toBe(0)
    expect(store.readJob('j1'), 'the change log the retention argument depends on was deleted').not.toBeNull()
    // The month of chatter is still the accepted cost — only the year of
    // history is defended.
    expect(ahead.outputDropped).toBeGreaterThan(0)
  })

  it('still ages out old jobs while the store looks current', async () => {
    // The guard must not turn into "job rows are never dropped". The newest
    // row is the second opinion; while it agrees with the clock, the horizon
    // applies exactly as documented.
    const store = await openStore()
    const NOW = 1_700_000_000_000
    const old = harness(store)
    old.tick(NOW - 400 * DAY)
    const p1 = old.runner.run(approved({ jobId: 'old', spec: spec(), targets: old.targets(['a']) }))
    await settle()
    await old.finish('a')
    await p1

    const fresh = harness(store)
    fresh.tick(NOW)
    const p2 = fresh.runner.run(approved({ jobId: 'new', spec: spec(), targets: fresh.targets(['a']) }))
    await settle()
    await fresh.finish('a')
    await p2

    const result = store.jobRetain(NOW)
    expect(result.skipped).toBeUndefined()
    expect(result.jobsDropped).toBe(1)
    expect(store.readJob('old')).toBeNull()
    expect(store.readJob('new')).not.toBeNull()
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
    void h.runner.run(approved({
      jobId: 'j1',
      spec: spec({ concurrency: 1 }),
      targets: h.targets(['a', 'b'])
    }))
    await settle()
    h.runner.disposeAll()
    expect(h.runner.isRunning('j1')).toBe(false)
    await settle()
    expect(h.isOpening('b')).toBe(false)
    // And the in-flight host still comes back afterwards, because the channel
    // outlives the window by however long the command takes. Released HERE
    // rather than left parked, which is the whole reason the assertions below
    // were reachable in production and not in this file.
    await h.finish('a')
  })

  it('leaves the rows for adopt() to close instead of calling the job cancelled', async () => {
    // On macOS closing the window does not quit, so disposeAll() runs while
    // the process lives on. The worker then returns, run()'s `finally` fires,
    // and a job that wrote itself `cancelled` + endedAt is a job
    // unfinishedJobs() can never select again — the host mid-exec stays
    // `running` forever, and `abandoned`, the headline of B1, is unreachable
    // on the ordinary path.
    const store = await openStore()
    const h = harness(store)
    void h.runner.run(approved({
      jobId: 'j1',
      spec: spec({ concurrency: 1 }),
      targets: h.targets(['a', 'b'])
    }))
    await settle()
    h.runner.disposeAll()
    h.tick(100)
    await h.finish('a')
    await settle()

    const job = store.readJob('j1')!
    expect(job.state, 'a disposed job wrote a terminal state adopt() can never see').toBe('running')
    expect(job.endedAt).toBeNull()
    expect(store.unfinishedJobs().map((j) => j.id)).toEqual(['j1'])
    // No target left claiming to be running under a job row that says it is
    // over — the pairing the store has no way to represent honestly.
    expect(job.targets.find((t) => t.serverId === 'a')?.state).not.toBe('running')

    // The next launch closes it, from rows alone.
    const second = harness(store)
    second.tick(9_000)
    expect(second.runner.adopt()).toHaveLength(1)
    const closed = store.readJob('j1')!
    expect(closed.state).toBe('abandoned')
    expect(closed.endedAt).toBe(9_000)
    const byId = Object.fromEntries(closed.targets.map((t) => [t.serverId, t]))
    expect(byId.a).toMatchObject({ state: 'failed', outcome: 'abandoned' })
    expect(byId.b).toMatchObject({ state: 'skipped', outcome: 'cancelled' })
  })

  it('writes no output rows for a run that no longer owns the id', async () => {
    // flushPending takes `owns`; flushTail did not, so the tail ring was
    // written by a run that had already lost the id — rows appearing under a
    // target the same pass then declined to update.
    const store = await openStore()
    const h = harness(store)
    void h.runner.run(approved({ jobId: 'j1', spec: spec(), targets: h.targets(['a']) }))
    await settle()
    h.feed('a', 'H'.repeat(JOB_OUTPUT_HEAD))
    // Past the head, so this parks in the tail ring rather than being written
    // straight through.
    h.feed('a', 'ten bytes\n')
    const beforeDispose = store.readJobOutput('j1', 'a').length
    expect(beforeDispose).toBe(1)

    h.runner.disposeAll()
    await h.finish('a')
    await settle()

    expect(
      store.readJobOutput('j1', 'a'),
      'the tail was flushed by a run that no longer owned the job id'
    ).toHaveLength(beforeDispose)
  })
})

describe('the attached executor', () => {
  it('hands every byte to the runner rather than buffering a capped copy', async () => {
    // `sshExec` stops appending at 200 KB and drops the rest, so the runner
    // never saw more than that — the head takes 64 KB, what is left fits under
    // the 192 KB tail budget, out_elided stays 0, and a 3 MB `apt
    // full-upgrade` reads back as complete. Streaming is what makes the
    // head+tail policy able to engage at all.
    let handlers: ExecStreamHandlers | null = null
    let stopped = 0
    const exec = attachedJobExecutor({
      stream: async (_cfg, _command, hs) => {
        handlers = hs
        return () => {
          stopped++
        }
      }
    })
    const seen: string[] = []
    const p = exec({
      cfg: {},
      command: 'apt full-upgrade -y',
      timeoutMs: 60_000,
      onOutput: (stream, text) => seen.push(`${stream}:${text.length}`)
    })
    await settle()
    handlers!.onStdout('X'.repeat(300_000))
    handlers!.onStderr('E: dpkg returned an error code\n')
    handlers!.onClose(100)

    const r = await p
    expect(r).toMatchObject({ ok: true, code: 100 })
    // Nothing comes back in `stdout`: it has already gone to the runner, and
    // returning it as well would write every byte twice.
    expect(r.stdout ?? '').toBe('')
    expect(seen).toEqual(['out:300000', 'err:31'])
    expect(stopped).toBe(0)
  })

  it('gives up on a command that never closes, and signals the remote', async () => {
    let stopped = 0
    const exec = attachedJobExecutor({
      stream: async () => () => {
        stopped++
      }
    })
    const r = await exec({ cfg: {}, command: 'sleep 999', timeoutMs: 5, onOutput: () => {} })
    expect(r.ok).toBe(false)
    expect(r.error).toMatch(/timed out/i)
    // Abandoning the channel without signalling is how a remote command is
    // orphaned holding its files open.
    expect(stopped).toBe(1)
  })

  it('reports a connection that never came up as an error, not as a result', async () => {
    const exec = attachedJobExecutor({
      stream: async () => {
        throw new Error('connect ECONNREFUSED 10.0.0.4:22')
      }
    })
    const r = await exec({ cfg: {}, command: 'uptime', timeoutMs: 1000, onOutput: () => {} })
    expect(r).toMatchObject({ ok: false, error: 'connect ECONNREFUSED 10.0.0.4:22' })
  })
})

describe('re-running a job id', () => {
  it('reports no host it never touched, and no output from the run before', async () => {
    // run() only refuses a LIVE id. A finished one is re-runnable, the job row
    // is replaced — and the target and output rows were not, so a second run
    // over one host inherited the first run's other host and interleaved its
    // output under a seq that restarts at zero.
    const store = await openStore()
    const first = harness(store)
    const p1 = first.runner.run(approved({ jobId: 'j1', spec: spec(), targets: first.targets(['a', 'b']) }))
    await settle()
    await first.finish('a', { ok: true, code: 0, stdout: 'RUN1-A\n' })
    await first.finish('b', { ok: true, code: 0, stdout: 'RUN1-B\n' })
    await p1

    const second = harness(store)
    const p2 = second.runner.run(approved({ jobId: 'j1', spec: spec(), targets: second.targets(['a']) }))
    await settle()
    await second.finish('a', { ok: true, code: 0, stdout: 'RUN2-ONLY\n' })
    const done = await p2

    expect(
      done.targets.map((t) => t.serverId),
      'a host the second run never contacted was reported as part of it'
    ).toEqual(['a'])
    expect(store.readJobOutput('j1', 'a').map((r) => r.text)).toEqual(['RUN2-ONLY\n'])
    expect(store.readJobOutput('j1', 'b')).toEqual([])
  })
})

