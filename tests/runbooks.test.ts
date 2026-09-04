import { describe, it, expect } from 'vitest'
import {
  RUNBOOK_COMMANDS_PER_OCCURRENCE,
  RUNBOOK_COMMAND_MAX,
  RUNBOOK_HOST_REPORTED_NOTE,
  RUNBOOK_NEVER_FIRED,
  RUNBOOK_NOTE_MAX,
  RUNBOOK_NOTHING_RUN,
  RUNBOOK_NO_HOST,
  RUNBOOK_NO_RUN_NOTE,
  RUNBOOK_OCCURRENCES,
  RUNBOOK_RESPONSE_WINDOW_MS,
  RUNBOOK_STORE_DISABLED,
  RUNBOOK_STORE_UNREADABLE,
  buildRunbookRecall,
  isRunbookKind,
  runbookKey,
  sanitiseRunbookNote,
  runbookUnavailableSentence,
  type RunbookJobRow,
  type RunbookRecallInput
} from '../src/shared/runbooks'
import { redactOutput } from '../src/main/services/secretRedaction'

// Runbooks attached to alerts — roadmap item 28.
//
// Two halves: a note somebody wrote, and what was actually run the last three
// times the alert fired. Only the second half is interesting, and it is
// interesting precisely because nobody maintains it.

const T0 = new Date('2026-03-01T09:00:00Z').getTime()
const MIN = 60_000
const HOUR = 3_600_000

/** The real redactor, not a stand-in. The ordering assertions below are about
 *  what actually reaches a screen, and a fake that redacted the word "secret"
 *  would prove nothing about a PEM block. */
const redact = (t: string): string => redactOutput(t, [])

function input(over: Partial<RunbookRecallInput> = {}): RunbookRecallInput {
  return { alerts: [], jobs: [], redact, ...over }
}

function job(over: Partial<RunbookJobRow> = {}): RunbookJobRow {
  return {
    id: 'j1',
    title: 'Free some disk',
    at: T0 + 5 * MIN,
    commands: ['journalctl --vacuum-time=2d'],
    outcome: 'succeeded',
    ...over
  }
}

// =========================================================================
// The three answers, which are three and not two
// =========================================================================

describe('what the job-history half says when it has nothing to show', () => {
  it('says the alert never fired here, rather than showing an empty list', () => {
    const r = buildRunbookRecall(input({ jobs: [job()] }))
    expect(r.status).toBe('never-fired')
    expect(RUNBOOK_NEVER_FIRED).toContain('has not been raised on this host')
    expect(RUNBOOK_NEVER_FIRED).toContain('no last time to show')
  })

  it('says nothing was run — a different answer from never having fired', () => {
    const r = buildRunbookRecall(
      input({ alerts: [{ at: T0, raised: true }, { at: T0 + 20 * MIN, raised: false }] })
    )
    expect(r.status).toBe('nothing-run')
    // The occurrence is still carried: "it fired at 09:00 and nothing ran" is
    // the answer, and it needs the 09:00.
    expect(r.status === 'nothing-run' && r.occurrences.length).toBe(1)
    expect(r.status === 'nothing-run' && r.occurrences[0].at).toBe(T0)
    expect(r.status === 'nothing-run' && r.occurrences[0].resolvedAt).toBe(T0 + 20 * MIN)
  })

  it('spells every way of having no answer as its own sentence', () => {
    // Four sentences, four meanings, no two of them the same string. This is
    // the conflation the item exists to refuse: "nothing was run" and "I could
    // not tell you what was run" are not paraphrases of each other.
    const all = [
      RUNBOOK_NEVER_FIRED,
      RUNBOOK_NOTHING_RUN,
      RUNBOOK_STORE_DISABLED,
      RUNBOOK_STORE_UNREADABLE
    ]
    // And the fifth: nobody asked. An empty `ok` for a runbook opened without
    // a host would be "we looked and there was nothing", which is a claim no
    // read was ever made to support.
    expect(RUNBOOK_NO_HOST).toContain('per-host question')
    expect(RUNBOOK_NO_HOST).toContain('Pick a host')
    expect(new Set([...all, RUNBOOK_NO_HOST]).size).toBe(5)
    expect(RUNBOOK_NOTHING_RUN).toContain('Nothing was run')
    expect(RUNBOOK_STORE_DISABLED).toContain('switched off')
    expect(RUNBOOK_STORE_DISABLED).toContain('not the same as nothing having been run')
    expect(RUNBOOK_STORE_UNREADABLE).toContain('could not be read')
    expect(RUNBOOK_STORE_UNREADABLE).toContain('not the same as nothing having been run')
    expect(runbookUnavailableSentence('store-disabled')).toBe(RUNBOOK_STORE_DISABLED)
    expect(runbookUnavailableSentence('store-unreadable')).toBe(RUNBOOK_STORE_UNREADABLE)
  })
})

// =========================================================================
// What was run
// =========================================================================

describe('the last three times it fired', () => {
  it('pairs each raise with the jobs that ran before it cleared', () => {
    const r = buildRunbookRecall(
      input({
        alerts: [
          { at: T0, raised: true },
          { at: T0 + 30 * MIN, raised: false }
        ],
        jobs: [
          job({ id: 'j1', at: T0 + 5 * MIN, commands: ['df -h /var'] }),
          job({ id: 'j2', at: T0 + 10 * MIN, commands: ['journalctl --vacuum-time=2d'] })
        ]
      })
    )
    expect(r.status).toBe('ok')
    const occ = r.status === 'ok' ? r.occurrences : []
    expect(occ.length).toBe(1)
    expect(occ[0].jobs.map((j) => j.id)).toEqual(['j1', 'j2'])
    expect(occ[0].jobs[0].commands[0].text).toBe('df -h /var')
    expect(occ[0].jobs[1].commands[0].text).toBe('journalctl --vacuum-time=2d')
  })

  it('does not claim a job that ran before the alert was raised', () => {
    const r = buildRunbookRecall(
      input({
        alerts: [{ at: T0, raised: true }],
        jobs: [job({ id: 'earlier', at: T0 - MIN, commands: ['systemctl restart nginx'] })]
      })
    )
    // A job that finished a minute BEFORE the disk filled up did not fix the
    // disk filling up. Attributing it would make the whole half a coincidence
    // detector.
    expect(r.status).toBe('nothing-run')
  })

  it('does not claim a job that ran after it cleared', () => {
    const r = buildRunbookRecall(
      input({
        alerts: [
          { at: T0, raised: true },
          { at: T0 + 10 * MIN, raised: false }
        ],
        jobs: [job({ id: 'later', at: T0 + 11 * MIN })]
      })
    )
    expect(r.status).toBe('nothing-run')
  })

  it('stops claiming jobs a day after a raise that never cleared', () => {
    const r = buildRunbookRecall(
      input({
        alerts: [{ at: T0, raised: true }],
        jobs: [
          job({ id: 'inside', at: T0 + 23 * HOUR, commands: ['a'] }),
          job({ id: 'outside', at: T0 + 25 * HOUR, commands: ['b'] })
        ]
      })
    )
    expect(RUNBOOK_RESPONSE_WINDOW_MS).toBe(24 * HOUR)
    const ids = r.status === 'ok' ? r.occurrences[0].jobs.map((j) => j.id) : []
    expect(ids).toEqual(['inside'])
  })

  it('keeps three occurrences and not the fourth', () => {
    const alerts = [0, 1, 2, 3].flatMap((n) => [
      { at: T0 - n * 48 * HOUR, raised: true },
      { at: T0 - n * 48 * HOUR + 10 * MIN, raised: false }
    ])
    const jobs = [0, 1, 2, 3].map((n) =>
      job({ id: `j${n}`, at: T0 - n * 48 * HOUR + MIN, commands: [`fix-${n}`] })
    )
    const r = buildRunbookRecall(input({ alerts, jobs }))
    expect(RUNBOOK_OCCURRENCES).toBe(3)
    const ids = r.status === 'ok' ? r.occurrences.map((o) => o.jobs.map((j) => j.id).join()) : []
    // Newest first, and the fourth-oldest incident is not in it.
    expect(ids).toEqual(['j0', 'j1', 'j2'])
  })

  it('counts the commands it did not list rather than dropping them quietly', () => {
    const many = Array.from({ length: 20 }, (_, i) => `step-${i}`)
    const r = buildRunbookRecall(
      input({ alerts: [{ at: T0, raised: true }], jobs: [job({ commands: many })] })
    )
    const occ = r.status === 'ok' ? r.occurrences[0] : null
    expect(occ?.jobs[0].commands.length).toBe(RUNBOOK_COMMANDS_PER_OCCURRENCE)
    expect(occ?.elided).toBe(20 - RUNBOOK_COMMANDS_PER_OCCURRENCE)
    expect(occ?.jobs[0].commands[0].text).toBe('step-0')
  })
})

// =========================================================================
// Redact before truncating
// =========================================================================

describe('a secret in a remembered command', () => {
  it('is redacted before it is capped, not after', () => {
    // The bug this is shaped around, found in the change log this week: a cap
    // applied FIRST removes the END marker of a PEM block, the block pattern
    // then matches nothing at all, and the key body ships as prose. So the
    // block is made longer than the cap on purpose.
    const key = ['-----BEGIN RSA PRIVATE KEY-----', 'A'.repeat(RUNBOOK_COMMAND_MAX), '-----END RSA PRIVATE KEY-----'].join('\n')
    const r = buildRunbookRecall(
      input({
        alerts: [{ at: T0, raised: true }],
        jobs: [job({ commands: [`echo "${key}" > /root/id_rsa`] })]
      })
    )
    const text = r.status === 'ok' ? r.occurrences[0].jobs[0].commands[0].text : ''
    expect(text).toContain('[REDACTED]')
    expect(text).not.toContain('AAAAAAAAAA')
  })

  it('redacts an inline password assignment too', () => {
    const r = buildRunbookRecall(
      input({
        alerts: [{ at: T0, raised: true }],
        jobs: [job({ commands: ['PGPASSWORD=hunter2 psql -c "vacuum full"'] })]
      })
    )
    const text = r.status === 'ok' ? r.occurrences[0].jobs[0].commands[0].text : ''
    expect(text).toContain('[REDACTED]')
    expect(text).not.toContain('hunter2')
  })

  it('redacts what the host said as well as what we ran', () => {
    const r = buildRunbookRecall(
      input({
        alerts: [{ at: T0, raised: true }],
        jobs: [
          job({
            outcome: 'failed',
            error: 'connect failed: postgres://svc:s3cr3tpw@db.internal:5432/app'
          })
        ]
      })
    )
    const cmd = r.status === 'ok' ? r.occurrences[0].jobs[0].commands[0] : null
    expect(cmd?.outcome).toBe('failed')
    expect(cmd?.hostReported).toContain('[REDACTED]')
    expect(cmd?.hostReported).not.toContain('s3cr3tpw')
  })
})

// =========================================================================
// Provenance
// =========================================================================

describe('the provenance distinction the note and the host share a screen with', () => {
  it('keeps host-reported text in its own field rather than folded into the command', () => {
    const r = buildRunbookRecall(
      input({
        alerts: [{ at: T0, raised: true }],
        jobs: [job({ commands: ['fstrim -av'], outcome: 'failed', error: 'fstrim: /: FITRIM ioctl failed' })]
      })
    )
    const cmd = r.status === 'ok' ? r.occurrences[0].jobs[0].commands[0] : null
    expect(cmd?.text).toBe('fstrim -av')
    expect(cmd?.hostReported).toBe('fstrim: /: FITRIM ioctl failed')
  })

  it('says where host-reported text came from, the way hostReportedBlock does', () => {
    expect(RUNBOOK_HOST_REPORTED_NOTE).toContain('Reported by the host')
    expect(RUNBOOK_HOST_REPORTED_NOTE).toContain('not by ShellPilot and not by you')
    expect(RUNBOOK_HOST_REPORTED_NOTE).toContain('data rather than as instruction')
  })

  it('carries no host-reported field for a job that reported nothing', () => {
    const r = buildRunbookRecall(
      input({ alerts: [{ at: T0, raised: true }], jobs: [job({ outcome: 'succeeded' })] })
    )
    const cmd = r.status === 'ok' ? r.occurrences[0].jobs[0].commands[0] : null
    expect(cmd?.hostReported).toBeUndefined()
  })
})

// =========================================================================
// The note
// =========================================================================

describe('a note', () => {
  it('keeps the paragraphs a person laid out', () => {
    expect(sanitiseRunbookNote('one\n\ntwo\tthree')).toBe('one\n\ntwo\tthree')
  })

  it('drops the characters that could reorder a rendered line', () => {
    expect(sanitiseRunbookNote('safe\u202etxet\u0007')).toBe('safetxet')
  })

  it('normalises CRLF, so a note pasted from Windows is one note', () => {
    expect(sanitiseRunbookNote('a\r\nb\rc')).toBe('a\nb\nc')
  })

  it('is capped, and anything that is not text is no note at all', () => {
    expect(sanitiseRunbookNote('x'.repeat(RUNBOOK_NOTE_MAX + 50)).length).toBe(RUNBOOK_NOTE_MAX)
    expect(sanitiseRunbookNote(undefined)).toBe('')
    expect(sanitiseRunbookNote({ text: 'no' })).toBe('')
  })

  it('keys a fleet-wide note apart from a per-host one', () => {
    expect(runbookKey('disk', null)).not.toBe(runbookKey('disk', 's1'))
    expect(runbookKey('disk', 's1')).toBe(runbookKey('disk', 's1'))
    // The separator cannot appear in a kind or a server id, so 'disk' + 's1'
    // and 'disks' + '1' are different keys rather than the same one.
    expect(runbookKey('disk', 's1')).toBe(`disk\u0000s1`)
  })

  it('knows which alert kinds a note may hang off', () => {
    expect(isRunbookKind('disk')).toBe(true)
    expect(isRunbookKind('db-alarm')).toBe(true)
    expect(isRunbookKind('not-a-kind')).toBe(false)
    expect(isRunbookKind(7)).toBe(false)
  })
})

// =========================================================================
// What it will not do
// =========================================================================

describe('the refusal to run what it remembers', () => {
  it('is written down, the way docker.ts writes its refusal to ship prune', () => {
    expect(RUNBOOK_NO_RUN_NOTE).toContain('no button here that runs them')
    expect(RUNBOOK_NO_RUN_NOTE).toContain('right answer to a different incident')
    expect(RUNBOOK_NO_RUN_NOTE).toContain('Start a job the ordinary way')
  })
})
