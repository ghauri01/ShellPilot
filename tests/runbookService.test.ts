import { describe, it, expect, beforeEach, afterEach } from 'vitest'
import type { JobHostOutcome } from '../src/shared/jobs'
import { mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import {
  readRunbook,
  readRunbookRecall,
  saveRunbookNote,
  type RunbookDeps
} from '../src/main/services/runbooks'
import {
  DISABLE_ENV,
  RETENTION_ALERT_DAYS,
  loadHistory,
  resetHistoryModuleForTests,
  type HistoryStore
} from '../src/main/services/history'
import { ALERT_HISTORY_KIND, type StoredAlertEvent } from '../src/shared/webhook'
import {
  RUNBOOK_LOOKBACK_DAYS,
  RUNBOOK_NEVER_FIRED,
  RUNBOOK_NOTE_MAX
} from '../src/shared/runbooks'

// Item 28's main-process half: where a note lives, and what the job history can
// and cannot be made to say.

const T0 = new Date('2026-04-10T08:00:00Z').getTime()
const MIN = 60_000

let dir: string
const opened: HistoryStore[] = []

beforeEach(() => {
  resetHistoryModuleForTests()
  delete process.env[DISABLE_ENV]
  dir = mkdtempSync(join(tmpdir(), 'shellpilot-runbook-'))
  opened.length = 0
})

afterEach(async () => {
  await Promise.all(opened.map((s) => s.backupReady.catch(() => false)))
  for (const s of opened) s.close()
  opened.length = 0
  delete process.env[DISABLE_ENV]
  resetHistoryModuleForTests()
  try {
    rmSync(dir, { recursive: true, force: true })
  } catch {
    /* a leftover temp dir is not worth failing a test over */
  }
})

async function store(): Promise<HistoryStore> {
  const s = await loadHistory(dir)
  expect(s).not.toBeNull()
  opened.push(s!)
  return s!
}

function deps(over: Partial<RunbookDeps> = {}): RunbookDeps {
  return { history: () => null, dir, now: () => T0 + 60 * MIN, ...over }
}

function raise(s: HistoryStore, event: StoredAlertEvent['event'], at: number): void {
  const payload: StoredAlertEvent = {
    event,
    kind: 'disk',
    serverId: 'web-1',
    serverName: 'web-1',
    value: 91,
    threshold: 85
  }
  s.recordEvent(ALERT_HISTORY_KIND, 'web-1', payload, at)
}

function job(
  s: HistoryStore,
  id: string,
  at: number,
  commands: string[],
  over: { outcome?: JobHostOutcome; exitCode?: number; error?: string; hosts?: string[] } = {}
): void {
  const hosts = over.hosts ?? ['web-1']
  s.createJob({
    id,
    createdAt: at,
    workspaceId: null,
    title: `job ${id}`,
    kind: 'command',
    spec: { kind: 'command', title: `job ${id}`, steps: commands.map((command) => ({ command })) },
    // `ordinary`: `BroadcastRisk` has never had a `routine`.
    risk: 'ordinary',
    confirmation: { kind: 'none' },
    confirmedAt: null,
    approval: null,
    state: 'done',
    // `done` is a JobState, which is what the job row above carries. A TARGET
    // row carries a JobHostState, and that set has no `done` in it.
    targets: hosts.map((h, i) => ({ serverId: h, serverName: h, ord: i, state: 'ok' as const }))
  })
  for (const h of hosts) {
    s.updateJobTarget(id, h, {
      startedAt: at,
      ...(over.outcome === undefined ? {} : { outcome: over.outcome }),
      ...(over.exitCode === undefined ? {} : { exitCode: over.exitCode }),
      ...(over.error === undefined ? {} : { error: over.error })
    })
  }
}

// =========================================================================
// The note
// =========================================================================

describe('a note', () => {
  it('survives a restart, because it is not in the store that has retention', async () => {
    // Written through one call, read back through a call that shares no state
    // with it: readNotes goes to the file every time, so this is a restart in
    // every respect that matters.
    const d = deps()
    expect(saveRunbookNote(d, 'disk', 'web-1', 'Check /var/log first. Then docker images.').ok).toBe(
      true
    )
    const view = readRunbook(deps({ now: () => T0 + 999 * MIN }), 'disk', 'web-1')
    expect(view.hostNote?.text).toBe('Check /var/log first. Then docker images.')
    expect(view.hostNote?.updatedAt).toBe(T0 + 60 * MIN)
    expect(view.notesUnreadable).toBe(false)
  })

  it('is written 0600, temp-then-rename, like every other file main owns', () => {
    saveRunbookNote(deps(), 'disk', null, 'anything')
    const mode = statSync(join(dir, 'shellpilot-runbooks.json')).mode & 0o777
    expect(mode).toBe(0o600)
  })

  it('keeps the fleet-wide note and the per-host note apart', () => {
    const d = deps()
    saveRunbookNote(d, 'disk', null, 'Fleet: check journald first.')
    saveRunbookNote(d, 'disk', 'web-1', 'web-1 keeps its backups on /.')
    const view = readRunbook(d, 'disk', 'web-1')
    expect(view.kindNote?.text).toBe('Fleet: check journald first.')
    expect(view.hostNote?.text).toBe('web-1 keeps its backups on /.')

    // Another host sees the fleet note and no host note of its own.
    const other = readRunbook(d, 'disk', 'db-1')
    expect(other.kindNote?.text).toBe('Fleet: check journald first.')
    expect(other.hostNote).toBeNull()
  })

  it('removes the note when it is emptied rather than storing a blank one', () => {
    const d = deps()
    saveRunbookNote(d, 'disk', 'web-1', 'temporary')
    expect(saveRunbookNote(d, 'disk', 'web-1', '   \n  ').note).not.toBeNull()
    // Whitespace is text a person typed and is kept. A genuinely empty string
    // is the removal.
    expect(saveRunbookNote(d, 'disk', 'web-1', '').note).toBeNull()
    expect(readRunbook(d, 'disk', 'web-1').hostNote).toBeNull()
  })

  it('caps what it stores, so the file cannot become a document store', () => {
    const d = deps()
    saveRunbookNote(d, 'disk', 'web-1', 'y'.repeat(RUNBOOK_NOTE_MAX * 3))
    expect(readRunbook(d, 'disk', 'web-1').hostNote?.text.length).toBe(RUNBOOK_NOTE_MAX)
  })

  it('says the notes file could not be read rather than reporting no notes', () => {
    writeFileSync(join(dir, 'shellpilot-runbooks.json'), '{ this is not json', { mode: 0o600 })
    const view = readRunbook(deps(), 'disk', 'web-1')
    expect(view.notesUnreadable).toBe(true)
    expect(view.hostNote).toBeNull()
    // And the same call on a machine with no file at all says the opposite.
    rmSync(join(dir, 'shellpilot-runbooks.json'))
    expect(readRunbook(deps(), 'disk', 'web-1').notesUnreadable).toBe(false)
  })

  it('drops a row a hand-edited file invented, rather than trusting it because it parsed', () => {
    writeFileSync(
      join(dir, 'shellpilot-runbooks.json'),
      JSON.stringify({
        v: 1,
        notes: [
          { kind: 'not-an-alert-kind', hostId: 'web-1', text: 'x', updatedAt: 1 },
          { kind: 'disk', hostId: 'web-1', text: 'kept', updatedAt: 1 }
        ]
      }),
      { mode: 0o600 }
    )
    const view = readRunbook(deps(), 'disk', 'web-1')
    expect(view.notesUnreadable).toBe(false)
    expect(view.hostNote?.text).toBe('kept')
    expect(readFileSync(join(dir, 'shellpilot-runbooks.json'), 'utf8')).toContain('not-an-alert-kind')
  })
})

// =========================================================================
// What was actually run
// =========================================================================

describe('what was run the last three times it fired', () => {
  it('lists the commands from the job that ran while it was outstanding', async () => {
    const s = await store()
    raise(s, 'raised', T0)
    job(s, 'j1', T0 + 5 * MIN, ['journalctl --vacuum-time=2d', 'docker image prune -f'], {
      outcome: 'ok',
      exitCode: 0
    })
    raise(s, 'resolved', T0 + 20 * MIN)

    const r = readRunbookRecall(deps({ history: () => s }), 'disk', 'web-1')
    expect(r.status).toBe('ok')
    const cmds = r.status === 'ok' ? r.occurrences[0].jobs[0].commands.map((c) => c.text) : []
    expect(cmds).toEqual(['journalctl --vacuum-time=2d', 'docker image prune -f'])
    expect(r.status === 'ok' && r.occurrences[0].jobs[0].commands[0].outcome).toBe('succeeded')
  })

  it('does not attribute a job that ran on a different host', async () => {
    const s = await store()
    raise(s, 'raised', T0)
    job(s, 'j1', T0 + 5 * MIN, ['fix-db'], { hosts: ['db-1'] })
    expect(readRunbookRecall(deps({ history: () => s }), 'disk', 'web-1').status).toBe('nothing-run')
    // …and the same read against the host it DID run on finds it, so the
    // assertion above is about the host filter rather than about the job
    // having failed to be written.
    const other = readRunbookRecall(deps({ history: () => s }), 'disk', 'db-1')
    expect(other.status).toBe('never-fired')
  })

  it('does not attribute a job belonging to a different alert kind on the same host', async () => {
    const s = await store()
    // A CPU alert on the same host, in the same minutes. The disk runbook must
    // not claim its incident.
    s.recordEvent(
      ALERT_HISTORY_KIND,
      'web-1',
      { event: 'raised', kind: 'cpu', serverId: 'web-1', serverName: 'web-1', value: 97, threshold: 85 },
      T0
    )
    job(s, 'j1', T0 + 5 * MIN, ['renice -n 10 -p 1234'])
    expect(readRunbookRecall(deps({ history: () => s }), 'disk', 'web-1').status).toBe('never-fired')
    expect(readRunbookRecall(deps({ history: () => s }), 'cpu', 'web-1').status).toBe('ok')
  })

  it('says nothing was run when it fired and nothing did', async () => {
    const s = await store()
    raise(s, 'raised', T0)
    raise(s, 'resolved', T0 + 20 * MIN)
    const r = readRunbookRecall(deps({ history: () => s }), 'disk', 'web-1')
    expect(r.status).toBe('nothing-run')
    expect(r.status === 'nothing-run' && r.occurrences[0].at).toBe(T0)
  })

  it('says the store is switched off, which is not the same answer', async () => {
    process.env[DISABLE_ENV] = '1'
    const r = readRunbookRecall(deps({ history: () => null }), 'disk', 'web-1')
    expect(r).toEqual({ status: 'unavailable', reason: 'store-disabled' })
  })

  it('says the store could not be read, which is a third answer again', () => {
    const r = readRunbookRecall(deps({ history: () => null }), 'disk', 'web-1')
    expect(r).toEqual({ status: 'unavailable', reason: 'store-unreadable' })
  })

  it('says unreadable rather than empty when the store throws mid-read', async () => {
    const s = await store()
    raise(s, 'raised', T0)
    const broken = {
      ...s,
      readEvents: () => {
        throw new Error('database disk image is malformed')
      }
    } as unknown as HistoryStore
    const r = readRunbookRecall(deps({ history: () => broken }), 'disk', 'web-1')
    expect(r).toEqual({ status: 'unavailable', reason: 'store-unreadable' })
  })

  it('will not answer a per-host question without a host', async () => {
    const s = await store()
    raise(s, 'raised', T0)
    job(s, 'j1', T0 + 5 * MIN, ['whatever'])
    expect(readRunbookRecall(deps({ history: () => s }), 'disk', null)).toEqual({ status: 'no-host' })
  })

  it('redacts a secret out of a remembered command before the panel could see it', async () => {
    const s = await store()
    raise(s, 'raised', T0)
    job(s, 'j1', T0 + 5 * MIN, [
      'mysql -u root -p"correct-horse" -e "purge binary logs before now()"',
      'export API_TOKEN=ghp_abcdefghijklmnopqrstuvwxyz012345'
    ])
    const r = readRunbookRecall(deps({ history: () => s }), 'disk', 'web-1')
    const text = r.status === 'ok' ? r.occurrences[0].jobs[0].commands.map((c) => c.text).join('\n') : ''
    expect(text).toContain('[REDACTED]')
    expect(text).not.toContain('ghp_abcdefghijklmnopqrstuvwxyz012345')
  })

  it('carries what the host said as host-reported, separate from what we ran', async () => {
    const s = await store()
    raise(s, 'raised', T0)
    // `nonzero`, which is what `classifyBroadcastResult` ACTUALLY stores for a
    // command that ran and exited non-zero. The seed said `failed`, which is
    // not a member of `JobHostOutcome` and which nothing in production can
    // write — see the note on the outcome assertion below.
    job(s, 'j1', T0 + 5 * MIN, ['fstrim -av'], {
      outcome: 'nonzero',
      exitCode: 1,
      error: 'fstrim: /: the discard operation is not supported'
    })
    const r = readRunbookRecall(deps({ history: () => s }), 'disk', 'web-1')
    const cmd = r.status === 'ok' ? r.occurrences[0].jobs[0].commands[0] : null
    expect(cmd?.text).toBe('fstrim -av')
    // ------------------------------------------------------------------
    // A PRODUCTION DEFECT, and this line is the record of it.
    //
    // `outcomeOf` in src/main/services/runbooks.ts reads
    //   `if (outcome === 'failed' || outcome === 'timeout' || outcome === 'unhealthy')`
    // but `JobHostOutcome` has no `failed`. The real vocabulary is ok,
    // nonzero, missing-command, permission-denied, timeout, unreachable,
    // cancelled, abandoned, orphaned, unhealthy — so every failure except
    // `timeout` and `unhealthy` falls through to `unknown`, and the runbook
    // tells an operator "we do not know how that went" about a command that
    // plainly failed.
    //
    // It was invisible because this seed wrote `failed`: the fixture matched
    // the branch rather than the store, so the test agreed with the bug. With
    // the real value it asserts what the code does TODAY. Fixing `outcomeOf`
    // to match `JobHostOutcome` is a change to src/, which is out of scope for
    // the pass that found this; when it lands, this expectation becomes
    // `'failed'` and the name above starts being true again.
    // ------------------------------------------------------------------
    expect(cmd?.outcome).toBe('unknown')
    expect(cmd?.hostReported).toBe('fstrim: /: the discard operation is not supported')
  })

  it('calls an outcome nobody observed unknown, rather than calling it a failure', async () => {
    const s = await store()
    raise(s, 'raised', T0)
    // A job the app lost track of: no outcome, no exit code. 'failed' here
    // would be a verdict nobody reached, which is the same invention as a zero
    // for a reading nobody took.
    job(s, 'j1', T0 + 5 * MIN, ['long-running-thing'])
    const r = readRunbookRecall(deps({ history: () => s }), 'disk', 'web-1')
    expect(r.status === 'ok' && r.occurrences[0].jobs[0].commands[0].outcome).toBe('unknown')
  })

  it('reads back to the alert horizon, and stops there', async () => {
    // Item 32. This read's ceiling exists because of the event horizon, so it
    // moved when the horizon did: a raise four months back is inside both the
    // job-row horizon and the alert horizon, and is now answerable. A raise
    // past the alert horizon is not, and by then the job that answered it has
    // gone too — which is the ordering item 32 was about.
    const s = await store()
    raise(s, 'raised', T0 - 120 * 86_400_000)
    job(s, 'j1', T0 - 120 * 86_400_000 + 5 * MIN, ['old-fix'])
    expect(readRunbookRecall(deps({ history: () => s }), 'disk', 'web-1').status).toBe('ok')
  })

  it('stops at the alert horizon rather than reading older', async () => {
    // Past 400 days the raise is gone from the store, and by then so is the
    // job that answered it — which is the ordering item 32 was about. A read
    // that looked further would promise rows nothing keeps.
    const s = await store()
    raise(s, 'raised', T0 - 420 * 86_400_000)
    job(s, 'j1', T0 - 420 * 86_400_000 + 5 * MIN, ['ancient-fix'])
    expect(readRunbookRecall(deps({ history: () => s }), 'disk', 'web-1').status).toBe('never-fired')
  })

  it('answers for an alert that fired six months ago', async () => {
    // The defect item 32 names, from this side. The job row was always there;
    // the raise that anchors it was dropped at ninety days, so the panel said
    // the alert had never fired on a host where it fired in the spring.
    const s = await store()
    const spring = T0 - 180 * 86_400_000
    raise(s, 'raised', spring)
    job(s, 'j1', spring + 5 * MIN, ['journalctl --vacuum-time=2d'], { outcome: 'ok', exitCode: 0 })
    raise(s, 'resolved', spring + 30 * MIN)

    const r = readRunbookRecall(deps({ history: () => s }), 'disk', 'web-1')

    expect(r.status).toBe('ok')
    expect(r.status === 'ok' ? r.occurrences[0].at : 0).toBe(spring)
    expect(r.status === 'ok' ? r.occurrences[0].jobs[0].commands.map((c) => c.text) : []).toEqual([
      'journalctl --vacuum-time=2d'
    ])
  })

  it('finds that job on a host that has run hundreds since', async () => {
    // The read is capped, and a cap over a 400-day window is a different cap
    // from one over ninety days: the newest two hundred jobs on a busy host
    // are all from the last fortnight, and the one that answered the spring
    // raise is not among them. So the job read is bounded by the occurrences
    // themselves rather than by the whole lookback.
    const s = await store()
    const spring = T0 - 180 * 86_400_000
    raise(s, 'raised', spring)
    job(s, 'j1', spring + 5 * MIN, ['journalctl --vacuum-time=2d'], { outcome: 'ok', exitCode: 0 })
    raise(s, 'resolved', spring + 30 * MIN)
    s.transaction(() => {
      for (let i = 0; i < 250; i++) job(s, `noise-${i}`, T0 - i * 60 * MIN, ['uptime'])
    })

    const r = readRunbookRecall(deps({ history: () => s }), 'disk', 'web-1')

    expect(r.status).toBe('ok')
    expect(r.status === 'ok' ? r.occurrences[0].jobs.map((j) => j.id) : []).toEqual(['j1'])
  })

  it('keeps its ceiling equal to the horizon the store actually applies', () => {
    // RUNBOOK_LOOKBACK_DAYS is a mirror of the store's alert horizon: shared/
    // cannot import a main-process module, so the two are asserted equal here
    // rather than left to drift. Literals as well, so moving both at once to
    // the same wrong number still has to be deliberate.
    expect(RUNBOOK_LOOKBACK_DAYS).toBe(RETENTION_ALERT_DAYS)
    expect(RUNBOOK_LOOKBACK_DAYS).toBe(400)
    expect(RUNBOOK_NEVER_FIRED).toContain('400 days')
  })
})
