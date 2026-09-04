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
import { recordJobApproval, listJobApprovals } from '../src/main/services/approvalLog'
import type {
  CommandApproval,
  JobApprovalEntry,
  JobDetachedHandle,
  JobRunRequest,
  JobSpec,
  JobTargetRef
} from '../src/shared/jobs'
import { jobApprovalFor, planJob, verifyJobApproval } from '../src/shared/jobs'

// Roadmap item B3: a durable approval record, and enforcement moved into main.
//
// The thing under test is a claim about ROWS, not about a dialog: a process
// that never showed anybody anything can read a job back and answer "was this
// authorised, for exactly this?". So almost every assertion below is made
// against a SECOND JobRunner over the SAME store — which is what a restart is —
// rather than against the one that wrote the rows.
//
// The harness is logTailer.test.ts's, like jobRunner.test.ts's: there is no
// `setTimeout(r, 5)` anywhere in this file and there must not be. Every host is
// held at its exec and released by name, so "host b was never reached" is an
// assertion about a call that did not happen rather than about a row that has
// not changed yet.

let dir: string
const opened: HistoryStore[] = []

beforeEach(() => {
  resetHistoryModuleForTests()
  delete process.env[DISABLE_ENV]
  opened.length = 0
  dir = mkdtempSync(join(tmpdir(), 'shellpilot-approval-'))
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

const AT = 1_700_000_000_000
const ok: JobExecResult = { ok: true, code: 0, stdout: 'done\n' }

function spec(over: Partial<JobSpec> = {}): JobSpec {
  return { kind: 'command', title: 'Upgrade', steps: [{ command: 'apt upgrade -y' }], ...over }
}

/** The record a renderer would mint, defaulting to one that agrees. */
function approvalOf(
  s: JobSpec,
  targets: JobTargetRef[],
  o: { phrase?: string | null; confirmedAt?: number } = {}
): CommandApproval {
  const plan = planJob(s, targets)
  return jobApprovalFor(s, targets, {
    phrase:
      o.phrase !== undefined
        ? o.phrase
        : plan.confirmation.kind === 'type-to-confirm'
          ? plan.confirmation.phrase
          : null,
    confirmedAt: o.confirmedAt ?? AT
  })
}

/**
 * A runner whose hosts are held at the exec until the test lets them go, and
 * whose approval log is an array.
 *
 * `reached(id)` is the load-bearing half of the resume tests: "this host was
 * never started" has to be an assertion about a channel that was never opened,
 * not about a row that happens to say `skipped`.
 */
function harness(store: HistoryStore, o: { autoFinish?: boolean } = {}) {
  const log: Omit<JobApprovalEntry, 'id' | 'timestamp'>[] = []
  const opening = new Map<string, (r: JobExecResult) => void>()
  const ticks: (() => void)[] = []
  const runner = new JobRunner({
    now: () => AT,
    store,
    emit: () => {},
    emitOutput: () => {},
    schedule: (fn) => ticks.push(fn),
    approvalLog: (e) => log.push(e),
    exec: (req) =>
      new Promise<JobExecResult>((resolve) => {
        const id = req.serverId
        if (o.autoFinish) resolve(ok)
        else opening.set(id, resolve)
      })
  })
  return {
    runner,
    log,
    reached: (id: string) => opening.has(id),
    finish: async (id: string, r: JobExecResult = ok) => {
      opening.get(id)!(r)
      opening.delete(id)
      await settle()
    },
    events: (kind: string) => store.readEvents({ kind })
  }
}

function settle(): Promise<void> {
  return new Promise((r) => setTimeout(r, 0))
}

function req(over: Partial<JobRunRequest> & Pick<JobRunRequest, 'jobId'>): JobRunRequest {
  const s = over.spec ?? spec()
  const targets = over.targets ?? [{ serverId: 'a', serverName: 'web-1', cfg: { id: 'a' } }]
  return { spec: s, targets, approval: approvalOf(s, targets), ...over }
}

// ===========================================================================
// The record itself
// ===========================================================================

describe('the approval record', () => {
  it('carries the steps and the resolved target list, not a rule that could be re-evaluated', () => {
    const s = spec({ steps: [{ command: 'apt update' }, { command: 'apt full-upgrade -y' }] })
    const targets = [
      { serverId: 'a', serverName: 'web-1' },
      { serverId: 'b', serverName: 'web-2' }
    ]
    const a = approvalOf(s, targets)
    expect(a.commands).toEqual(['apt update', 'apt full-upgrade -y'])
    expect(a.targets).toEqual([
      { serverId: 'a', serverName: 'web-1' },
      { serverId: 'b', serverName: 'web-2' }
    ])
    expect(a.risk).toBe('elevated')
    expect(a.confirmedAt).toBe(AT)
  })

  it('does not carry a server address, a username or a credential', () => {
    // `approvalFor` copies field by field precisely so a caller handing it a
    // whole Server row cannot smuggle one into a record kept for a year and
    // written to a log.
    const rich = [
      { serverId: 'a', serverName: 'web-1', host: '10.0.0.4', username: 'root', password: 'hunter2' }
    ] as unknown as JobTargetRef[]
    const a = approvalOf(spec(), rich)
    expect(JSON.stringify(a)).not.toContain('10.0.0.4')
    expect(JSON.stringify(a)).not.toContain('hunter2')
    expect(a.targets[0]).toEqual({ serverId: 'a', serverName: 'web-1' })
  })
})

// ===========================================================================
// At launch: main re-derives, and refuses on disagreement
// ===========================================================================

describe('starting a job', () => {
  it('refuses a run with no approval record, and writes no job row at all', async () => {
    const s = await openStore()
    const h = harness(s)
    await expect(
      h.runner.run({
        jobId: 'j1',
        spec: spec(),
        targets: [{ serverId: 'a', serverName: 'web-1', cfg: { id: 'a' } }],
        approval: undefined as unknown as CommandApproval
      })
    ).rejects.toThrow(/never written down/i)

    // Refused BEFORE the row is created. A `queued` row for a job nobody ran
    // would be closed as `abandoned` at the next launch and would sit in a
    // year-long record as work that was interrupted.
    expect(s.readJob('j1')).toBeNull()
    expect(h.reached('a'), 'no channel was opened').toBe(false)
    expect(h.log.map((e) => e.event)).toEqual(['refused'])
    expect(h.events('job-refused')).toHaveLength(1)
  })

  it('runs when the record agrees, and stores it whole', async () => {
    const s = await openStore()
    const h = harness(s)
    const p = h.runner.run(req({ jobId: 'j1' }))
    await settle()
    await h.finish('a')
    await p

    const job = s.readJob('j1')
    expect(job?.state).toBe('done')
    expect(job?.approval?.commands).toEqual(['apt upgrade -y'])
    expect(job?.approval?.confirmedAt).toBe(AT)
    // The summary columns are written from the RE-DERIVATION, not copied out of
    // the record — which is what makes their agreement a fact about this build.
    expect(job?.risk).toBe('elevated')
    expect(job?.confirmedAt).toBe(AT)
    expect(h.log.map((e) => e.event)).toEqual(['granted'])
  })

  it('refuses when the command was edited underneath a stored approval', async () => {
    const s = await openStore()
    const h = harness(s)
    const targets = [{ serverId: 'a', serverName: 'web-1', cfg: { id: 'a' } }]
    await expect(
      h.runner.run({
        jobId: 'j1',
        spec: spec({ steps: [{ command: 'rm -rf /var/log' }] }),
        targets,
        // Approved as something else entirely.
        approval: approvalOf(spec({ steps: [{ command: 'uptime' }] }), targets)
      })
    ).rejects.toThrow(/step 1 was approved as `uptime` and is now `rm -rf \/var\/log`/)
    expect(s.readJob('j1')).toBeNull()
    expect(h.reached('a')).toBe(false)
  })

  it('refuses when a target was added after the approval', async () => {
    const s = await openStore()
    const h = harness(s)
    const approved = [{ serverId: 'a', serverName: 'web-1' }]
    await expect(
      h.runner.run({
        jobId: 'j1',
        spec: spec(),
        targets: [
          { serverId: 'a', serverName: 'web-1', cfg: { id: 'a' } },
          { serverId: 'b', serverName: 'db-1', cfg: { id: 'b' } }
        ],
        approval: approvalOf(spec(), approved)
      })
    ).rejects.toThrow(/db-1 was not in the target list that was confirmed/)
    expect(h.reached('a'), 'not even the server that WAS approved is started').toBe(false)
    expect(h.reached('b')).toBe(false)
  })

  it('allows a target to be dropped, because shrinking cannot raise a blast radius', async () => {
    // The other direction on purpose. Resuming three of fifteen hosts is what
    // reclaim does, and every one of the three was in the list confirmed.
    const s = await openStore()
    const h = harness(s)
    const approved = [
      { serverId: 'a', serverName: 'web-1' },
      { serverId: 'b', serverName: 'web-2' }
    ]
    const p = h.runner.run({
      jobId: 'j1',
      spec: spec(),
      targets: [{ serverId: 'a', serverName: 'web-1', cfg: { id: 'a' } }],
      approval: approvalOf(spec(), approved)
    })
    await settle()
    expect(h.reached('a')).toBe(true)
    await h.finish('a')
    await p
    expect(s.readJob('j1')?.state).toBe('done')
  })

  it('refuses when the classifier has since become stricter', async () => {
    const s = await openStore()
    const h = harness(s)
    const targets = [{ serverId: 'a', serverName: 'web-1', cfg: { id: 'a' } }]
    const sp = spec({ steps: [{ command: 'rm -rf /var/log' }] })
    // A record from a build whose rules were weaker: same command, same hosts,
    // graded `ordinary`. Today's rules call it destructive. This is the one
    // disagreement no amount of comparing the request to itself would catch.
    const stale: CommandApproval = {
      ...approvalOf(sp, targets),
      risk: 'ordinary',
      confirmation: { kind: 'none' },
      phrase: null
    }
    expect(planJob(sp, targets).risk, 'today it is destructive, or this proves nothing').toBe(
      'destructive'
    )
    await expect(h.runner.run({ jobId: 'j1', spec: sp, targets, approval: stale })).rejects.toThrow(
      /approved as `ordinary` and now classifies as `destructive`/
    )
    expect(h.reached('a')).toBe(false)
  })
})

// ===========================================================================
// The typed phrase
// ===========================================================================

describe('the phrase the user typed', () => {
  const destructive = spec({ steps: [{ command: 'rm -rf /var/lib/postgresql' }] })
  const one = [{ serverId: 'a', serverName: 'db-1', cfg: { id: 'a' } }]

  it('is demanded by the model this record is graded against', () => {
    // Fail-first guard: if the plan ever stops asking for a word here, the two
    // tests below would pass against a job that needed no phrase at all.
    expect(planJob(destructive, one).confirmation).toEqual({ kind: 'type-to-confirm', phrase: 'RUN' })
  })

  it('is refused when the record says nobody typed it', async () => {
    const s = await openStore()
    const h = harness(s)
    await expect(
      h.runner.run({
        jobId: 'j1',
        spec: destructive,
        targets: one,
        // The dialog demanded RUN. "The dialog demanded RUN" and "the user
        // typed RUN" are two different facts and only the second is consent.
        approval: approvalOf(destructive, one, { phrase: null })
      })
    ).rejects.toThrow(/needed the word RUN typed, and the record has no typed phrase at all/)
    expect(h.reached('a')).toBe(false)
  })

  it('is refused when the record has the wrong word', async () => {
    const s = await openStore()
    const h = harness(s)
    await expect(
      h.runner.run({
        jobId: 'j1',
        spec: destructive,
        targets: one,
        approval: approvalOf(destructive, one, { phrase: 'run' })
      })
    ).rejects.toThrow(/needed the word RUN typed, and the record has a different one/)
  })

  it('is recorded on the row when it was typed', async () => {
    const s = await openStore()
    const h = harness(s)
    const p = h.runner.run({
      jobId: 'j1',
      spec: destructive,
      targets: one,
      approval: approvalOf(destructive, one, { phrase: 'RUN' })
    })
    await settle()
    await h.finish('a')
    await p

    // Read back through the store, from rows alone.
    const job = s.readJob('j1')
    expect(job?.confirmation).toEqual({ kind: 'type-to-confirm', phrase: 'RUN' })
    expect(job?.approval?.phrase).toBe('RUN')
    expect(h.log[0].phrase).toBe('RUN')
  })
})

// ===========================================================================
// At resume: the re-consent decision
// ===========================================================================

/** A row set that looks exactly like a restart: one host detached on its
 *  marker, one host the job never reached. */
function seedInterrupted(
  s: HistoryStore,
  o: { approval: CommandApproval | null; spec?: JobSpec }
): void {
  const sp = o.spec ?? spec()
  s.createJob({
    id: 'j1',
    createdAt: AT - 60_000,
    workspaceId: null,
    title: sp.title,
    kind: 'command',
    spec: sp,
    risk: planJob(sp, []).risk,
    confirmation: { kind: 'confirm' },
    confirmedAt: o.approval?.confirmedAt ?? null,
    approval: o.approval,
    state: 'running',
    targets: [
      { serverId: 'a', serverName: 'web-1', ord: 0, state: 'pending' },
      { serverId: 'b', serverName: 'web-2', ord: 1, state: 'pending' }
    ]
  })
  const handle: JobDetachedHandle = {
    v: 1,
    dir: '/var/tmp/shellpilot-1000/jobs/j1.1',
    step: 1,
    instanceId: 'sp-test',
    launcher: 'setsid',
    base64: true,
    launchedAt: AT - 60_000,
    readOffset: 0,
    command: sp.steps[0].command
  }
  s.updateJobTarget('j1', 'a', { state: 'detached', detached: handle, startedAt: AT - 60_000 })
}

const twoHostApproval = (sp: JobSpec = spec()): CommandApproval =>
  approvalOf(sp, [
    { serverId: 'a', serverName: 'web-1' },
    { serverId: 'b', serverName: 'web-2' }
  ])

describe('resuming after a restart', () => {
  it('replays a stored approval that still matches, and follows the server that is running', async () => {
    const s = await openStore()
    seedInterrupted(s, { approval: twoHostApproval() })

    // A SECOND runner over the same rows. It never saw the dialog; everything
    // it knows comes out of the store.
    const h = harness(s)
    expect(h.runner.reclaim({ cfgFor: () => ({ id: 'a' }) }).map((j) => j.id)).toEqual(['j1'])
    await settle()
    expect(h.reached('a'), 'the detached server is picked up').toBe(true)
    await h.finish('a')
    await h.runner.whenSettled('j1')

    expect(h.log.map((e) => e.event)).toEqual(['resumed', 'sealed'])
    expect(h.log[0].confirmedAt).toBe(AT)
    expect(s.readJob('j1')?.targets.find((t) => t.serverId === 'a')?.state).toBe('ok')
  })

  it('finishes the running server and refuses to start the one it never reached', async () => {
    const s = await openStore()
    seedInterrupted(s, { approval: twoHostApproval() })
    const h = harness(s)
    h.runner.reclaim({ cfgFor: () => ({ id: 'a' }) })
    await settle()

    // THE ASSERTION THAT MATTERS: not that host b's row says skipped, but that
    // no channel to it was ever opened. A runner could produce that row while
    // still having run the command.
    expect(h.reached('b'), 'server b was never started').toBe(false)
    await h.finish('a')
    await h.runner.whenSettled('j1')

    const job = s.readJob('j1')
    const a = job?.targets.find((t) => t.serverId === 'a')
    const b = job?.targets.find((t) => t.serverId === 'b')
    expect(a?.state, 'the server that was already running finished').toBe('ok')
    expect(b?.state).toBe('skipped')
    expect(b?.outcome).toBe('cancelled')
    // The refusal names the confirmation it would have had to run on. B2 made
    // this refusal; B3 gives it its reason and its timestamp.
    expect(b?.error).toContain(new Date(AT).toISOString())
    expect(b?.error).toMatch(/needs a fresh one/)

    const sealed = h.log.find((e) => e.event === 'sealed')
    expect(sealed?.reason).toMatch(/needs a fresh one/)
    expect(h.events('job-reclaimed')[0].payload).toMatchObject({ sealed: 1, approval: 'verified' })
  })

  it('still follows a running server when the record no longer matches, and says so', async () => {
    const s = await openStore()
    // The spec in the row was edited under the approval — or the classifier
    // moved. Either way the record and the rows disagree.
    seedInterrupted(s, {
      approval: twoHostApproval(spec({ steps: [{ command: 'uptime' }] })),
      spec: spec({ steps: [{ command: 'apt upgrade -y' }] })
    })
    const h = harness(s)
    h.runner.reclaim({ cfgFor: () => ({ id: 'a' }) })
    await settle()

    // FINISHING IS NOT AN ACTION. The command is running on that machine
    // whether or not ShellPilot is watching; refusing to read its output would
    // throw away the exit status of something already happening and leave the
    // marker directory behind.
    expect(h.reached('a'), 'the running server is still followed').toBe(true)
    expect(h.reached('b'), 'and nothing new is started').toBe(false)
    await h.finish('a')
    await h.runner.whenSettled('j1')

    const refused = h.log.find((e) => e.event === 'refused')
    expect(refused?.reason).toMatch(/step 1 was approved as `uptime`/)
    expect(h.events('job-approval-disagreed')).toHaveLength(1)
    expect(s.readJob('j1')?.targets.find((t) => t.serverId === 'a')?.state).toBe('ok')
  })

  it('reports a row written before approvals were recorded rather than resuming it blind', async () => {
    const s = await openStore()
    seedInterrupted(s, { approval: null })
    const h = harness(s)
    h.runner.reclaim({ cfgFor: () => ({ id: 'a' }) })
    await settle()
    await h.finish('a')
    await h.runner.whenSettled('j1')

    const refused = h.log.find((e) => e.event === 'refused')
    expect(refused?.reason).toMatch(/never written down/i)
    const b = s.readJob('j1')?.targets.find((t) => t.serverId === 'b')
    expect(b?.state).toBe('skipped')
    expect(b?.error).toMatch(/carries no confirmation this process could check/)
  })

  it('a job running in THIS process reaches every server it was given', async () => {
    // The other half of the re-consent rule, and the contrast that makes the
    // test above mean something: within one process lifetime the approval is
    // carried, and host b is started normally. It is only across a restart that
    // a host which was never reached needs a fresh confirmation.
    //
    // The rule is structural rather than held in a flag — run() is the
    // same-lifetime path and reclaim() is the cross-restart one — so this pair
    // of tests is the only thing asserting it, and neither is redundant.
    const s = await openStore()
    const h = harness(s)
    const targets = [
      { serverId: 'a', serverName: 'web-1', cfg: { id: 'a' } },
      { serverId: 'b', serverName: 'web-2', cfg: { id: 'b' } }
    ]
    const p = h.runner.run({ jobId: 'j1', spec: spec(), targets, approval: approvalOf(spec(), targets) })
    await settle()
    expect(h.reached('a')).toBe(true)
    expect(h.reached('b')).toBe(true)
    await h.finish('a')
    await h.finish('b')
    await p
    // NAMED, not counted, and not `every`. `[].every(...)` is `true`, so the
    // old assertion was satisfied by a run that recorded NO target rows at all,
    // and equally by one that recorded only the first host — which is exactly
    // the claim in this test's name. Both hosts have to be there, by id, in
    // order, each with the state it reached.
    expect(s.readJob('j1')?.targets.map((t) => `${t.serverId}=${t.state}`)).toEqual(['a=ok', 'b=ok'])
  })
})

// ===========================================================================
// The verifier, on its own
// ===========================================================================

describe('verifyJobApproval', () => {
  const targets = [{ serverId: 'a', serverName: 'web-1' }]

  it('accepts a record that matches', () => {
    expect(verifyJobApproval(approvalOf(spec(), targets), spec(), targets)).toEqual({ ok: true })
  })

  it('rejects anything that is not a record at all', () => {
    for (const junk of [null, undefined, {}, 'yes', 42, { v: 2 }]) {
      const v = verifyJobApproval(junk, spec(), targets)
      expect(v.ok, `${JSON.stringify(junk)} was accepted as an approval`).toBe(false)
    }
  })

  it('rejects a record with a confirmedAt of zero, which is what a default looks like', () => {
    const a = { ...approvalOf(spec(), targets), confirmedAt: 0 }
    expect(verifyJobApproval(a, spec(), targets).ok).toBe(false)
  })

  it('rejects a step count that does not match, before it compares any text', () => {
    const a = approvalOf(spec({ steps: [{ command: 'apt update' }] }), targets)
    const v = verifyJobApproval(
      a,
      spec({ steps: [{ command: 'apt update' }, { command: 'reboot' }] }),
      targets
    )
    expect(v.ok).toBe(false)
    expect(v.ok === false && v.reason).toMatch(/covers 1 step\(s\) and this run has 2/)
  })

  it('does not care that a server was renamed', () => {
    // A rename changes the label on a machine, not the machine. Refusing to
    // finish an upgrade because somebody tidied a workspace name would be
    // friction with nothing behind it.
    const a = approvalOf(spec(), [{ serverId: 'a', serverName: 'old-name' }])
    expect(verifyJobApproval(a, spec(), [{ serverId: 'a', serverName: 'new-name' }])).toEqual({
      ok: true
    })
  })

  it('refuses a server moved into a bigger wave', () => {
    // Blast radius is what is simultaneous, and a cohort is what decides it.
    const staged: JobTargetRef[] = [
      { serverId: 'a', serverName: 'web-1', cohort: 'wave-1' },
      { serverId: 'b', serverName: 'web-2', cohort: 'wave-2' }
    ]
    const a = approvalOf(spec(), staged)
    const merged = staged.map((t) => ({ ...t, cohort: 'wave-1' }))
    const v = verifyJobApproval(a, spec(), merged)
    expect(v.ok).toBe(false)
    expect(v.ok === false && v.reason).toMatch(/was confirmed in wave "wave-2"/)
  })
})

// ===========================================================================
// The log
// ===========================================================================

describe('the approval log', () => {
  it('records a decision with the risk, the phrase, the servers and the reason', () => {
    recordJobApproval({
      surface: 'job',
      event: 'refused',
      jobId: 'log-1',
      title: 'Estate upgrade',
      risk: 'destructive',
      confirmation: 'type-to-confirm',
      phrase: 'RUN',
      confirmedAt: AT,
      hosts: ['web-1', 'web-2'],
      commands: ['rm -rf /var/log'],
      reason: 'a target was added'
    })
    const row = listJobApprovals(20).find((e) => e.jobId === 'log-1')
    expect(row?.event).toBe('refused')
    expect(row?.risk).toBe('destructive')
    expect(row?.phrase).toBe('RUN')
    expect(row?.hosts).toEqual(['web-1', 'web-2'])
    expect(row?.reason).toBe('a target was added')
    expect(row?.id).toBeTruthy()
    expect(row?.timestamp).toBeTruthy()
  })

  it('never stores a secret the command text carried', () => {
    // Same rule and the same writer-side discipline as recordAudit: a job's
    // step text is exactly where somebody pastes a password.
    recordJobApproval({
      surface: 'job',
      event: 'granted',
      jobId: 'log-2',
      title: 'Deploy',
      risk: 'elevated',
      confirmation: 'confirm',
      phrase: null,
      confirmedAt: AT,
      hosts: ['db-1'],
      commands: ['echo DB_PASSWORD=hunter2 >> /etc/app.env'],
      reason: 'PGPASSWORD=swordfish was in the reason too'
    })
    const row = listJobApprovals(20).find((e) => e.jobId === 'log-2')
    expect(row?.commands[0]).toContain('DB_PASSWORD')
    expect(row?.commands[0]).not.toContain('hunter2')
    expect(row?.reason).not.toContain('swordfish')
    expect(JSON.stringify(row)).not.toContain('hunter2')
  })

  it('carries no job output, ever', () => {
    // The field list is the guarantee. Output lives in the history store under
    // its own retention, capped and redacted there; a log of it would be a more
    // attractive target than the thing it was meant to protect.
    const row = recordJobApproval({
      surface: 'job',
      event: 'granted',
      jobId: 'log-3',
      title: 'x',
      risk: 'ordinary',
      confirmation: 'none',
      phrase: null,
      confirmedAt: AT,
      hosts: [],
      commands: []
    })
    expect(Object.keys(row).sort()).toEqual(
      [
        'commands',
        'confirmation',
        'confirmedAt',
        'event',
        'hosts',
        'id',
        'jobId',
        'phrase',
        'risk',
        'surface',
        'timestamp',
        'title'
      ].sort()
    )
  })

  it('gets the raw command from the runner, so redaction has exactly one home', async () => {
    // The runner deliberately does NOT pre-redact. If it did, a second writer
    // added later would inherit a half-redacted string and no way to tell.
    const s = await openStore()
    const h = harness(s, { autoFinish: true })
    const sp = spec({ steps: [{ command: 'echo DB_PASSWORD=hunter2' }] })
    const targets = [{ serverId: 'a', serverName: 'web-1', cfg: { id: 'a' } }]
    await h.runner.run({ jobId: 'j1', spec: sp, targets, approval: approvalOf(sp, targets) })
    expect(h.log[0].commands).toEqual(['echo DB_PASSWORD=hunter2'])

    // And the real writer is what removes it.
    const written = recordJobApproval({ ...h.log[0], jobId: 'log-4' })
    expect(written.commands[0]).not.toContain('hunter2')
  })
})
