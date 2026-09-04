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
import { JobRunner, type JobExecResult } from '../src/main/services/jobRunner'
import type { JobProgress, JobRunRequest, JobSpec, JobTargetRef } from '../src/shared/jobs'
import { JOB_TERMINAL_STATES, jobApprovalFor, jobCohorts, planJob } from '../src/shared/jobs'
import { GATE_POLL_MS, GATE_WAIT_MS, type GateHost } from '../src/shared/patch'

// B4's staging and its health gate, and item 17's hard refusal — the three
// things that decide whether an estate upgrade keeps rolling.
//
// NO SLEEPS. Every host is held at its exec until the test releases it by name,
// and the gate's own wait is an injected promise the test resolves. That is
// what makes "wave 2 has not been reached" an assertion rather than a hope:
// this session found three flaky tests and all three were real production bugs.

let dir: string
const opened: HistoryStore[] = []

beforeEach(() => {
  resetHistoryModuleForTests()
  delete process.env[DISABLE_ENV]
  opened.length = 0
  dir = mkdtempSync(join(tmpdir(), 'shellpilot-stages-'))
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

async function openStore(): Promise<HistoryStore> {
  const s = await loadHistory(dir)
  expect(s, 'node:sqlite did not open — every assertion below would be vacuous').not.toBeNull()
  opened.push(s!)
  return s!
}

const ok: JobExecResult = { ok: true, code: 0, stdout: 'done\n' }

function spec(over: Partial<JobSpec> = {}): JobSpec {
  return {
    kind: 'patch',
    title: 'Updates',
    steps: [{ command: 'apt-get -y upgrade' }],
    gate: 'health',
    ...over
  }
}

/** Waves of one, in order: a, then b, then c. */
function waved(ids: string[]): JobRunRequest['targets'] {
  return ids.map((id, i) => ({
    serverId: id,
    serverName: `host-${id}`,
    cohort: `wave-${i + 1}`,
    cfg: { id }
  }))
}

function approved(
  req: Omit<JobRunRequest, 'approval'>,
  o: { spec?: JobSpec; targets?: JobTargetRef[] } = {}
): JobRunRequest {
  const s = o.spec ?? req.spec
  const t = o.targets ?? req.targets
  const plan = planJob(s, t)
  return {
    ...req,
    approval: jobApprovalFor(s, t, {
      phrase: plan.confirmation.kind === 'type-to-confirm' ? plan.confirmation.phrase : null,
      confirmedAt: 1_700_000_000_000
    })
  }
}

/**
 * A runner whose hosts are held at the exec and whose gate wait is held too.
 *
 * `health` is a plain map the test edits, so "the sampler has not reported
 * since the wave finished" is expressed by simply not touching it.
 */
function harness(
  store: HistoryStore,
  over: {
    guard?: (req: JobRunRequest) => string | null
    health?: (ids: string[]) => GateHost[]
    withoutHealth?: boolean
  } = {}
) {
  const progress: JobProgress[] = []
  const opening = new Map<string, (r: JobExecResult) => void>()
  const gateWaits: (() => void)[] = []
  const gateWaited: number[] = []
  let clock = 10_000
  const observed = new Map<string, GateHost>()

  const runner = new JobRunner({
    now: () => clock,
    store,
    emit: (p) => progress.push(p),
    emitOutput: () => {},
    schedule: (fn) => fn(),
    guard: over.guard,
    health: over.withoutHealth
      ? undefined
      : (over.health ??
        ((ids) =>
          ids.map(
            (id) =>
              observed.get(id) ?? {
                serverId: id,
                serverName: `host-${id}`,
                sampledAt: null,
                unreachable: false,
                unreachableError: null,
                failedUnits: []
              }
          ))),
    sleep: (ms) =>
      new Promise<void>((resolve) => {
        gateWaited.push(ms)
        gateWaits.push(resolve)
      }),
    exec: (req) =>
      new Promise<JobExecResult>((resolve) => {
        opening.set((req.cfg as { id: string }).id, resolve)
      })
  })

  const settle = (): Promise<void> => new Promise((r) => setTimeout(r, 0))

  return {
    runner,
    progress,
    isOpening: (id: string) => opening.has(id),
    finish: async (id: string, r: JobExecResult = ok) => {
      opening.get(id)!(r)
      opening.delete(id)
      await settle()
    },
    /** Record a health observation for a host, dated now. */
    observe: (id: string, over: Partial<GateHost> = {}) => {
      observed.set(id, {
        serverId: id,
        serverName: `host-${id}`,
        sampledAt: clock,
        unreachable: false,
        unreachableError: null,
        failedUnits: [],
        ...over
      })
    },
    tick: (ms: number) => {
      clock += ms
    },
    get gatePending(): number {
      return gateWaits.length
    },
    gateWaited,
    /** Release the gate's held wait so it re-asks. */
    releaseGate: async () => {
      const next = gateWaits.shift()
      expect(next, 'the gate is not waiting — the run is not where the test thinks it is').toBeDefined()
      ;(next as () => void)()
      await settle()
    },
    settle
  }
}

// =========================================================================
// Waves run in order
// =========================================================================

describe('waves', () => {
  it('does not reach wave 2 until wave 1 has finished', async () => {
    const store = await openStore()
    const h = harness(store)
    h.observe('a')
    const req = approved({ jobId: 'j1', spec: spec({ gate: 'none' }), targets: waved(['a', 'b']) })
    const run = h.runner.run(req)
    await h.settle()

    expect(h.isOpening('a')).toBe(true)
    // The assertion that matters: host b's channel has not been opened, not
    // merely that its row does not say ok yet.
    expect(h.isOpening('b')).toBe(false)
    await h.finish('a')
    expect(h.isOpening('b')).toBe(true)
    await h.finish('b')
    await run
    expect(store.readJob('j1')!.state).toBe('done')
  })

  it('keeps the caller order rather than sorting wave names', () => {
    // `wave-10` sorts before `wave-2` under every string comparison. An
    // implementation that sorted would reorder an operator's waves on the tenth
    // one, which is exactly where nobody would be looking.
    const order = jobCohorts([
      { serverId: 'a', cohort: 'wave-9' },
      { serverId: 'b', cohort: 'wave-10' },
      { serverId: 'c', cohort: 'wave-2' }
    ]).map((c) => c.name)
    expect(order).toEqual(['wave-9', 'wave-10', 'wave-2'])
  })
})

// =========================================================================
// The health gate
// =========================================================================

describe('the health gate between waves', () => {
  it('stops the run when the finished wave left a server with a failed unit', async () => {
    const store = await openStore()
    const h = harness(store)
    const req = approved({ jobId: 'j2', spec: spec(), targets: waved(['a', 'b', 'c']) })
    const run = h.runner.run(req)
    await h.settle()
    // The control for the assertion at the end of this test. `not.toContain` is
    // satisfied by a reader that returns nothing at all, so the reader is shown
    // finding this job FIRST, while it is still open — and only then shown not
    // finding it once it has halted.
    expect(store.unfinishedJobs().map((j) => j.id)).toEqual(['j2'])

    // Wave 1 ran and its host came back with nginx down.
    h.tick(1)
    h.observe('a', { failedUnits: ['nginx.service'] })
    await h.finish('a')

    // THE ASSERTION: wave 2 was never opened. Not "its row says skipped" —
    // never reached at all.
    expect(h.isOpening('b')).toBe(false)
    await run

    const job = store.readJob('j2')!
    // `halted`, not `cancelled`: nobody stopped this and it did not finish.
    expect(job.state).toBe('halted')
    const rows = Object.fromEntries(job.targets.map((t) => [t.serverId, t]))
    expect(rows.a.state).toBe('ok')
    expect(rows.b.state).toBe('skipped')
    expect(rows.c.state).toBe('skipped')
    // And the row answers the only question anyone asks afterwards.
    expect(rows.b.error).toContain('Nothing was installed on this server')
    expect(rows.b.error).toContain('nginx.service')

    // `halted` is TERMINAL. If it were not, the job would be adopted at the
    // next launch and its untouched hosts resumed on a confirmation nobody
    // gave — the exact thing B3's re-consent rule exists to prevent.
    expect(JOB_TERMINAL_STATES).toContain('halted')
    expect(store.unfinishedJobs().map((j) => j.id)).not.toContain('j2')
  })

  it('stops when the finished wave left a server unreachable', async () => {
    const store = await openStore()
    const h = harness(store)
    const req = approved({ jobId: 'j3', spec: spec(), targets: waved(['a', 'b']) })
    const run = h.runner.run(req)
    await h.settle()
    h.tick(1)
    h.observe('a', { unreachable: true, unreachableError: 'Connection refused' })
    await h.finish('a')
    expect(h.isOpening('b')).toBe(false)
    await run
    expect(store.readJob('j3')!.state).toBe('halted')
    expect(store.readJob('j3')!.targets.find((t) => t.serverId === 'b')!.error).toContain(
      'Connection refused'
    )
  })

  it('waits for a health check newer than the wave rather than passing on an old one', async () => {
    const store = await openStore()
    const h = harness(store)
    // An observation from BEFORE the wave ran. A gate that accepted it would
    // pass instantly, every time, on data from before the upgrade — which is
    // worse than no gate, because it looks like one.
    h.observe('a')
    const req = approved({ jobId: 'j4', spec: spec(), targets: waved(['a', 'b']) })
    const run = h.runner.run(req)
    await h.settle()
    h.tick(1)
    await h.finish('a')

    expect(h.isOpening('b')).toBe(false)
    expect(h.gatePending).toBe(1)
    expect(h.gateWaited[0]).toBe(GATE_POLL_MS)

    // A fresh sample lands, and only now does wave 2 start.
    h.tick(1)
    h.observe('a')
    await h.releaseGate()
    expect(h.isOpening('b')).toBe(true)
    await h.finish('b')
    await run
    expect(store.readJob('j4')!.state).toBe('done')
  })

  it('gives up rather than rolling on when no fresh check ever arrives', async () => {
    const store = await openStore()
    const h = harness(store)
    const req = approved({ jobId: 'j5', spec: spec(), targets: waved(['a', 'b']) })
    const run = h.runner.run(req)
    await h.settle()
    await h.finish('a')

    // Push past the deadline in one jump and let the gate re-ask.
    h.tick(GATE_WAIT_MS + 1)
    await h.releaseGate()
    await run

    const job = store.readJob('j5')!
    expect(job.state).toBe('halted')
    expect(job.targets.find((t) => t.serverId === 'b')!.error).toContain('there was still no')
    expect(h.isOpening('b')).toBe(false)
  })

  it('refuses to continue at all when the build has no health source', async () => {
    // A run confirmed WITH a gate must not silently become a run without one.
    const store = await openStore()
    const h = harness(store, { withoutHealth: true })
    const req = approved({ jobId: 'j6', spec: spec(), targets: waved(['a', 'b']) })
    const run = h.runner.run(req)
    await h.settle()
    await h.finish('a')
    await run
    expect(store.readJob('j6')!.state).toBe('halted')
    expect(store.readJob('j6')!.targets.find((t) => t.serverId === 'b')!.error).toContain(
      'no health source'
    )
  })

  it('does not gate a job that did not ask for one', async () => {
    const store = await openStore()
    const h = harness(store)
    const req = approved({ jobId: 'j7', spec: spec({ gate: 'none' }), targets: waved(['a', 'b']) })
    const run = h.runner.run(req)
    await h.settle()
    // The host is left with no observation at all, which a gate would hold on.
    await h.finish('a')
    expect(h.isOpening('b')).toBe(true)
    expect(h.gatePending).toBe(0)
    await h.finish('b')
    await run
    expect(store.readJob('j7')!.state).toBe('done')
  })

  it('does not gate after the last wave', async () => {
    // There is nothing it could hold back, and waiting five minutes to verify
    // a wave nothing follows would turn every staged run into one that appears
    // to hang at the end.
    const store = await openStore()
    const h = harness(store)
    const req = approved({ jobId: 'j8', spec: spec(), targets: waved(['a']) })
    const run = h.runner.run(req)
    await h.settle()
    await h.finish('a')
    await run
    expect(h.gatePending).toBe(0)
    expect(store.readJob('j8')!.state).toBe('done')
  })

  it('reports a server that cannot answer for its units without blocking on it', async () => {
    const store = await openStore()
    const h = harness(store)
    const req = approved({ jobId: 'j9', spec: spec(), targets: waved(['a', 'b']) })
    const run = h.runner.run(req)
    await h.settle()
    h.tick(1)
    // null, not []: no systemd. Blocking would make such a host permanently
    // unpatchable in a staged run.
    h.observe('a', { failedUnits: null })
    await h.finish('a')
    expect(h.isOpening('b')).toBe(true)
    await h.finish('b')
    await run
    expect(store.readJob('j9')!.state).toBe('done')
  })
})

// =========================================================================
// The hard refusal
// =========================================================================

describe('the reboot-ordering guard', () => {
  it('refuses the run before a single row is written', async () => {
    const store = await openStore()
    const guard = (): string =>
      'bastion is the jump host that web-1 connects through. Restarting it drops those connections.'
    const h = harness(store, { guard })
    const req = approved({ jobId: 'jg', spec: spec({ gate: 'none' }), targets: waved(['bastion']) })

    await expect(h.runner.run(req)).rejects.toThrow(/jump host/)
    // BEFORE THE ROW IS CREATED. A refused job that left a `queued` row would
    // be adopted at the next launch and recorded as one that was interrupted,
    // which would put a job nobody ran into a year-long record.
    expect(store.readJob('jg')).toBeNull()
    expect(h.isOpening('bastion')).toBe(false)
  })

  it('lets an unguarded run through untouched', async () => {
    const store = await openStore()
    const h = harness(store, { guard: () => null })
    const req = approved({ jobId: 'jh', spec: spec({ gate: 'none' }), targets: waved(['a']) })
    const run = h.runner.run(req)
    await h.settle()
    await h.finish('a')
    await run
    expect(store.readJob('jh')!.state).toBe('done')
  })
})

// =========================================================================
// What a reboot step costs at the dialog
// =========================================================================

describe('the confirmation a reboot step demands', () => {
  it('is destructive on the declaration, not on how the command reads', async () => {
    // WHAT THIS PINS. `assessCommand` is a text rule anchored to a command
    // start, so it grades what a command LOOKS like. A step that restarts the
    // machine from inside a wrapper script looks like nothing at all — and
    // that is not a hole to be patched, because the alternative to anchoring
    // is flagging every `grep reboot /var/log/syslog`.
    //
    // (It used to be pinned with `sudo -n systemctl reboot`, which read as
    // `elevated` because the sudo prefix admitted no flags — so restarting a
    // machine asked for a WEAKER confirmation than a bare `reboot`. That gap
    // is closed in broadcast.ts now; this rule is the defence in depth
    // beneath it, not a workaround for it.)
    const bare = planJob(
      { kind: 'patch', title: 't', steps: [{ command: 'sudo -n /usr/local/sbin/apply-kernel.sh' }] },
      [{ serverId: 'a', serverName: 'a' }]
    )
    expect(bare.risk).toBe('elevated')

    const declared = planJob(
      {
        kind: 'patch',
        title: 't',
        steps: [{ command: 'sudo -n /usr/local/sbin/apply-kernel.sh', reboot: true }]
      },
      [{ serverId: 'a', serverName: 'a' }]
    )
    expect(declared.risk).toBe('destructive')
    expect(declared.confirmation).toEqual({ kind: 'type-to-confirm', phrase: 'RUN' })
    expect(declared.reasons).toContain('a step in this job restarts the machine')
  })
})

// =========================================================================
// The approval path
// =========================================================================

describe('a patch run and its approval record', () => {
  it('refuses a target list that grew after it was confirmed', async () => {
    const store = await openStore()
    const h = harness(store)
    const targets = waved(['a', 'b'])
    // Approved for a and b; run against a, b and c.
    const req = approved(
      { jobId: 'ja', spec: spec(), targets: [...targets, { serverId: 'c', serverName: 'host-c', cohort: 'wave-3', cfg: { id: 'c' } }] },
      { targets }
    )
    await expect(h.runner.run(req)).rejects.toThrow(/not in the target list that was confirmed/)
    expect(store.readJob('ja')).toBeNull()
    expect(h.isOpening('a')).toBe(false)
  })

  it('refuses a server moved into a different wave', async () => {
    // Moving a host between waves changes how many run at once, which is what
    // the confirmation was sized against.
    const store = await openStore()
    const h = harness(store)
    const confirmed: JobTargetRef[] = [
      { serverId: 'a', serverName: 'host-a', cohort: 'wave-1' },
      { serverId: 'b', serverName: 'host-b', cohort: 'wave-2' }
    ]
    const req = approved(
      {
        jobId: 'jb',
        spec: spec(),
        targets: [
          { serverId: 'a', serverName: 'host-a', cohort: 'wave-1', cfg: { id: 'a' } },
          { serverId: 'b', serverName: 'host-b', cohort: 'wave-1', cfg: { id: 'b' } }
        ]
      },
      { targets: confirmed }
    )
    await expect(h.runner.run(req)).rejects.toThrow(/Moving a server between waves/)
    expect(store.readJob('jb')).toBeNull()
  })

  it('refuses an edited command under a stored approval', async () => {
    const store = await openStore()
    const h = harness(store)
    const req = approved(
      { jobId: 'jc', spec: spec(), targets: waved(['a']) },
      { spec: spec({ steps: [{ command: 'apt-get -y --dry-run upgrade' }] }) }
    )
    await expect(h.runner.run(req)).rejects.toThrow(/edited command needs a fresh confirmation/)
    expect(store.readJob('jc')).toBeNull()
  })

  it('refuses a reboot step that was not in what was approved', async () => {
    // The reboot IS a step, with its own line in the dialog. Nothing restarts a
    // machine that the operator was not shown.
    const store = await openStore()
    const h = harness(store)
    const withReboot = spec({
      steps: [{ command: 'apt-get -y upgrade' }, { command: 'systemctl reboot', reboot: true }]
    })
    const req = approved({ jobId: 'jd', spec: withReboot, targets: waved(['a']) }, { spec: spec() })
    await expect(h.runner.run(req)).rejects.toThrow(/covers 1 step\(s\) and this run has 2/)
    expect(store.readJob('jd')).toBeNull()
  })
})
