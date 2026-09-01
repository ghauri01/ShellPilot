import { describe, it, expect, beforeEach } from 'vitest'
import { readFileSync, existsSync, rmSync, statSync } from 'node:fs'
import { join } from 'node:path'
import { app } from 'electron'
import { recordLocalSession, listLocalSessions } from '../src/main/services/localSessionLog'

// A record of which shells ran, and when. Deliberately a separate file from the
// AI audit log: that one answers "what did an agent do", is agent-shaped
// (agentName, capability, approval) and is displayed in the AI section. Local
// terminal rows there would mean an AI-labelled log full of things no AI did.

const FILE = join(app.getPath('userData'), 'shellpilot-local-sessions.jsonl')

const base = {
  sessionId: 'sess-1',
  shellId: 'darwin-zsh-b663616e',
  shellLabel: 'zsh (default)',
  shellPath: '/bin/zsh'
}

beforeEach(() => {
  rmSync(FILE, { force: true })
})

describe('recording', () => {
  it('writes one line per event and reads them back newest first', () => {
    recordLocalSession({ ...base, event: 'started', pid: 4242, cwd: '/tmp' })
    recordLocalSession({ ...base, event: 'exited', exitCode: 0, signal: 0 })

    const lines = readFileSync(FILE, 'utf8').split('\n').filter(Boolean)
    expect(lines).toHaveLength(2)

    const entries = listLocalSessions()
    expect(entries.map((e) => e.event)).toEqual(['exited', 'started'])
    expect(entries[1].pid).toBe(4242)
    expect(entries[1].cwd).toBe('/tmp')
    expect(entries[0].exitCode).toBe(0)
  })

  it('stamps an id and an ISO timestamp', () => {
    const e = recordLocalSession({ ...base, event: 'started' })
    expect(e.id).toMatch(/^local-/)
    expect(() => new Date(e.timestamp).toISOString()).not.toThrow()
    expect(new Date(e.timestamp).toISOString()).toBe(e.timestamp)
  })

  it('records a spawn that never happened', () => {
    // "Nothing ran" and "we tried and it failed" are different answers to the
    // same question, and only one of them means the machine is fine.
    recordLocalSession({
      ...base,
      event: 'failed',
      error: 'No shell is configured under the id "bogus".'
    })
    const [entry] = listLocalSessions()
    expect(entry.event).toBe('failed')
    expect(entry.error).toContain('bogus')
  })

  it('is append-only — an existing file is never rewritten', () => {
    recordLocalSession({ ...base, event: 'started' })
    const first = readFileSync(FILE, 'utf8')
    recordLocalSession({ ...base, event: 'exited', exitCode: 0 })
    const second = readFileSync(FILE, 'utf8')
    expect(second.startsWith(first)).toBe(true)
  })

  it('creates the file 0600', () => {
    recordLocalSession({ ...base, event: 'started' })
    // It names which shells a person runs and when they are at the machine.
    expect(statSync(FILE).mode & 0o077).toBe(0)
  })
})

describe('what is deliberately absent', () => {
  it('has no field that could carry terminal input or output', () => {
    // The privacy property this feature rests on. A shell session's contents
    // are the user's, and a log of them would be a far more attractive target
    // than the thing it was meant to protect. If a field is ever added here
    // that could hold typed input or program output, this test should fail and
    // the conversation should happen before it ships.
    const entry = recordLocalSession({ ...base, event: 'started', pid: 1, cwd: '/tmp' })
    expect(Object.keys(entry).sort()).toEqual(
      [
        'cwd',
        'event',
        'id',
        'pid',
        'sessionId',
        'shellId',
        'shellLabel',
        'shellPath',
        'timestamp'
      ].sort()
    )
  })
})

describe('reading', () => {
  it('returns nothing when no shell has ever run', () => {
    expect(existsSync(FILE)).toBe(false)
    expect(listLocalSessions()).toEqual([])
  })

  it('skips a corrupt line rather than losing the whole history', () => {
    recordLocalSession({ ...base, event: 'started' })
    const { appendFileSync } = require('node:fs') as typeof import('node:fs')
    appendFileSync(FILE, 'not json\n')
    recordLocalSession({ ...base, event: 'exited', exitCode: 0 })
    expect(listLocalSessions().map((e) => e.event)).toEqual(['exited', 'started'])
  })

  it('honours the limit', () => {
    for (let i = 0; i < 10; i++) {
      recordLocalSession({ ...base, event: 'started', sessionId: `sess-${i}` })
    }
    expect(listLocalSessions(3)).toHaveLength(3)
  })
})
