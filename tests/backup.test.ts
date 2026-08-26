import { describe, it, expect, afterEach } from 'vitest'
import { existsSync, writeFileSync, unlinkSync } from 'node:fs'
import { join } from 'node:path'
import { app } from 'electron'
import { deleteAllData } from '../src/main/services/backup'

const ALL_DATA_FILES = [
  'shellpilot-data.json',
  'shellpilot-secrets.json',
  'shellpilot-vault.json',
  'shellpilot-wslocks.json',
  'shellpilot-known-hosts.json',
  'shellpilot-mcp-config.json',
  'shellpilot-mcp-sessions.json',
  'shellpilot-ai-policy.json',
  'shellpilot-ai-audit.jsonl'
]

function paths(): string[] {
  return ALL_DATA_FILES.map((f) => join(app.getPath('userData'), f))
}

describe('deleteAllData', () => {
  afterEach(() => {
    for (const p of paths()) {
      try {
        if (existsSync(p)) unlinkSync(p)
      } catch {
        /* ignore */
      }
    }
  })

  it('removes every known data file', () => {
    for (const p of paths()) writeFileSync(p, '{}')
    expect(paths().every(existsSync)).toBe(true)

    const result = deleteAllData()

    expect(result.ok).toBe(true)
    expect(paths().some(existsSync)).toBe(false)
  })

  it('succeeds even when some or all files never existed', () => {
    // Nothing written this time — a fresh install with no data yet.
    const result = deleteAllData()
    expect(result.ok).toBe(true)
  })

  it('does not touch files outside the known list', () => {
    const untouched = join(app.getPath('userData'), 'some-other-file.json')
    writeFileSync(untouched, 'keep me')

    deleteAllData()

    expect(existsSync(untouched)).toBe(true)
    unlinkSync(untouched)
  })
})
