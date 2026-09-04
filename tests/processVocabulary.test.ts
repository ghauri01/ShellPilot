import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { join, resolve } from 'node:path'
import {
  MAX_PROCESSES,
  PROCESS_SECRET_KEY_RX,
  PROCESS_SECRET_LITERAL_REFUSAL,
  processDraftProblem,
  processFailureMessage,
  sanitiseProcess,
  sanitiseProcesses,
  toProcessView
} from '../src/shared/processes'
import type { ManagedProcess, ProcessDraft } from '../src/shared/processes'

const ROOT = resolve(__dirname, '..')

const draft = (over: Partial<ProcessDraft> = {}): ProcessDraft => ({
  name: 'API',
  command: '/usr/local/bin/node',
  args: ['server.js'],
  cwd: '/srv/api',
  env: [],
  restart: 'on-failure',
  readiness: { kind: 'spawned' },
  ...over
})

const stored = (over: Partial<ManagedProcess> = {}): ManagedProcess => ({
  id: 'p1',
  name: 'API',
  command: '/usr/local/bin/node',
  args: ['server.js'],
  cwd: '/srv/api',
  env: [],
  restart: 'on-failure',
  readiness: { kind: 'spawned' },
  createdAt: '2026-01-01T00:00:00.000Z',
  ...over
})

describe('a secret never becomes a stored literal', () => {
  it('refuses a literal whose name says it is a secret, and says where to put it', () => {
    const problem = processDraftProblem(
      draft({ env: [{ key: 'DATABASE_PASSWORD', kind: 'literal', value: 'hunter2' }] })
    )
    expect(problem).toBe(`DATABASE_PASSWORD: ${PROCESS_SECRET_LITERAL_REFUSAL}`)
    expect(PROCESS_SECRET_LITERAL_REFUSAL).toContain('vault')
  })

  it('refuses the same names secretRedaction already scrubs', () => {
    for (const key of [
      'DATABASE_PASSWORD',
      'DB_PASSWD',
      'KEY_PASSPHRASE',
      'CLIENT_SECRET',
      'GITHUB_TOKEN',
      'STRIPE_API_KEY',
      'STRIPE_APIKEY',
      'DEPLOY_PRIVATE_KEY',
      'AWS_ACCESS_KEY_ID',
      'GCP_CREDENTIAL'
    ]) {
      expect(PROCESS_SECRET_KEY_RX.test(key), key).toBe(true)
      expect(
        processDraftProblem(draft({ env: [{ key, kind: 'literal', value: 'x' }] })),
        key
      ).toBe(`${key}: ${PROCESS_SECRET_LITERAL_REFUSAL}`)
    }
  })

  it('lets the same name through as a VAULT REFERENCE, which is the alternative', () => {
    expect(
      processDraftProblem(
        draft({
          env: [
            { key: 'DATABASE_PASSWORD', kind: 'vault', vaultEntryId: 'v-9', slot: 'password' }
          ]
        })
      )
    ).toBe(null)
  })

  it('still refuses a hand-edited file, not merely a draft from the UI', () => {
    // The file is exactly as hostile as an IPC message: nothing stops someone
    // typing a secret into it directly, and a narrowing that only ran on the
    // create path would store it happily.
    const p = sanitiseProcess({
      ...stored(),
      env: [
        { key: 'API_TOKEN', kind: 'literal', value: 'ghp_realtoken' },
        { key: 'NODE_ENV', kind: 'literal', value: 'production' }
      ]
    })
    expect(p?.env).toEqual([{ key: 'NODE_ENV', kind: 'literal', value: 'production' }])
  })

  it('never puts an environment VALUE on the wire, vault or literal', () => {
    const view = toProcessView(
      stored({
        env: [
          { key: 'NODE_ENV', kind: 'literal', value: 'production' },
          { key: 'DATABASE_PASSWORD', kind: 'vault', vaultEntryId: 'v-9', slot: 'password' }
        ]
      })
    )
    expect(view.env).toEqual([
      { key: 'NODE_ENV', source: 'literal' },
      { key: 'DATABASE_PASSWORD', source: 'vault', vaultEntryId: 'v-9', slot: 'password' }
    ])
    // Belt and braces: the serialised view must not contain the string at all,
    // under any key a future field might add.
    expect(JSON.stringify(view)).not.toContain('production')
  })
})

describe('narrowing whatever was on disk', () => {
  it('drops a row with no command rather than storing a process that cannot run', () => {
    expect(sanitiseProcess({ ...stored(), command: '   ' })).toBe(null)
    expect(sanitiseProcess({ ...stored(), cwd: '' })).toBe(null)
    expect(sanitiseProcess({ ...stored(), id: '' })).toBe(null)
    expect(sanitiseProcess(null)).toBe(null)
  })

  it('keeps the other rows when one will not narrow', () => {
    const list = sanitiseProcesses({
      v: 1,
      processes: [stored({ id: 'a' }), { nonsense: true }, stored({ id: 'b' })]
    })
    expect(list.map((p) => p.id)).toEqual(['a', 'b'])
  })

  it('caps the list, so one file cannot describe unlimited local execution', () => {
    const many = Array.from({ length: MAX_PROCESSES + 20 }, (_v, i) => stored({ id: `p${i}` }))
    expect(sanitiseProcesses({ v: 1, processes: many })).toHaveLength(MAX_PROCESSES)
  })

  it('refuses an environment name that would need a shell quote', () => {
    expect(
      sanitiseProcess({ ...stored(), env: [{ key: 'A B', kind: 'literal', value: 'x' }] })?.env
    ).toEqual([])
    expect(
      sanitiseProcess({ ...stored(), env: [{ key: '9LIVES', kind: 'literal', value: 'x' }] })?.env
    ).toEqual([])
  })

  it('takes the LAST of two variables with the same name, which is the one that applies', () => {
    const p = sanitiseProcess({
      ...stored(),
      env: [
        { key: 'PORT', kind: 'literal', value: '3000' },
        { key: 'PORT', kind: 'literal', value: '4000' }
      ]
    })
    expect(p?.env).toEqual([{ key: 'PORT', kind: 'literal', value: '4000' }])
  })

  it('clamps a readiness timeout instead of trusting it', () => {
    expect(
      sanitiseProcess({ ...stored(), readiness: { kind: 'log', pattern: 'ready', timeoutMs: 0 } })
        ?.readiness
    ).toEqual({ kind: 'log', pattern: 'ready', timeoutMs: 1_000 })
    expect(
      sanitiseProcess({
        ...stored(),
        readiness: { kind: 'log', pattern: 'ready', timeoutMs: 99_999_999 }
      })?.readiness
    ).toEqual({ kind: 'log', pattern: 'ready', timeoutMs: 600_000 })
  })

  it('falls back to spawned readiness rather than dropping the process', () => {
    expect(sanitiseProcess({ ...stored(), readiness: { kind: 'nonsense' } })?.readiness).toEqual({
      kind: 'spawned'
    })
  })
})

describe('the supervisor speaks VPN and this does not', () => {
  it('never shows a person the word tunnel for their dev server', () => {
    expect(processFailureMessage('crash-loop')).toBe(
      'It kept exiting, so it was stopped rather than restarted again.'
    )
    expect(processFailureMessage('binary-missing')).toBe(
      'That program could not be found, so nothing was started.'
    )
    for (const code of ['crash-loop', 'binary-missing', 'handshake-timeout', 'internal', 'what']) {
      expect(processFailureMessage(code).toLowerCase(), code).not.toContain('tunnel')
    }
  })

  it('appends the detail the supervisor gathered rather than dropping it', () => {
    expect(processFailureMessage('crash-loop', 'It exited 7 times in 60 seconds.')).toBe(
      'It kept exiting, so it was stopped rather than restarted again. It exited 7 times in 60 seconds.'
    )
  })
})

describe('the refusals are written down where the next person will read them', () => {
  const src = readFileSync(join(ROOT, 'src/shared/processes.ts'), 'utf8')

  it('states the remote refusal, and points at the job engine rather than a held-open channel', () => {
    // Not a style check. The roadmap splits this item deliberately — local is
    // weeks, remote is materially more and gated on a design question — and
    // the thing that keeps someone from "just adding SSH" in six months is
    // that the argument is in the file they would edit. This asserts the two
    // load-bearing halves of it are there.
    expect(src).toContain(
      'shipping "we\n//     run your process over an SSH channel we hold open" is a promise about\n//     reliability the current transport does not make.'
    )
    expect(src).toContain('THE JOB ENGINE ALREADY SOLVED DETACHED REMOTE EXECUTION')
    expect(src).toContain('jobDetached.ts')
  })

  it('states that the list does not live in the renderer blob, and why', () => {
    expect(src).toContain('shellpilot-data.json')
    expect(src).toContain(
      'A COMMAND THAT RUNS ON THIS MACHINE DOES NOT BELONG IN AN EXPORTED\n//     BACKUP.'
    )
  })

  it('states that nothing starts on launch', () => {
    expect(src).toContain('AUTO-START ON LAUNCH')
    expect(src).toContain('Starting is a button, every time.')
  })
})
