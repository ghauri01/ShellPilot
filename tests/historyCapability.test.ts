import { describe, it, expect } from 'vitest'
import { mkdtempSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

// The one risk the node:sqlite decision carries.
//
// Choosing the runtime's bundled SQLite over better-sqlite3 trades a dependency
// risk for a platform-version risk: nothing in package.json pins it, and the
// version is whatever Electron's Node happens to bundle. That is the cheaper of
// the two — zero prebuilds, zero packaging surface, zero signing surface — but
// it is only cheap while somebody would notice it changing.
//
// This test is that somebody. It is deliberately about the CAPABILITY and not
// about ShellPilot's own code, so an Electron bump that removes an export, or
// refuses WAL, or ships a SQLite too old for the features the schema uses,
// fails here with a sentence naming the thing that moved — rather than as an
// opaque runtime error on a user's machine at the first sweep.
describe('node:sqlite capability', () => {
  it('resolves at all', async () => {
    await expect(import('node:sqlite')).resolves.toBeTruthy()
  })

  it('exports DatabaseSync, StatementSync and backup', async () => {
    const mod = (await import('node:sqlite')) as unknown as Record<string, unknown>
    // Each asserted by name and separately: "one of the three is missing" is
    // not a useful failure message when it is the one the recovery ladder uses.
    expect(typeof mod.DatabaseSync).toBe('function')
    expect(typeof mod.StatementSync).toBe('function')
    expect(typeof mod.backup).toBe('function')
  })

  it('accepts PRAGMA journal_mode = WAL on a real file', async () => {
    const { DatabaseSync } = await import('node:sqlite')
    const dir = mkdtempSync(join(tmpdir(), 'shellpilot-cap-'))
    const db = new DatabaseSync(join(dir, 'cap.db'))
    try {
      const row = db.prepare('PRAGMA journal_mode = WAL').get() as { journal_mode?: string }
      // The store falls back to TRUNCATE when this is refused, which is correct
      // behaviour on a USB stick and a regression anywhere else. WAL is what the
      // normal install runs on and what synchronous=NORMAL is safe under.
      expect(String(row.journal_mode).toLowerCase()).toBe('wal')
    } finally {
      db.close()
    }
  })

  it('supports the SQL the schema actually depends on', async () => {
    const { DatabaseSync } = await import('node:sqlite')
    const db = new DatabaseSync(':memory:')
    try {
      // WITHOUT ROWID is the whole storage argument: the primary key IS the
      // table, so there is no second B-tree, which is what makes 21.9 bytes a
      // row true. An UPSERT with an excluded reference is how the hourly
      // roll-up merges. Neither is optional.
      db.exec(
        'CREATE TABLE t (ts INTEGER, host INTEGER, metric INTEGER, v REAL, PRIMARY KEY (ts, host, metric)) WITHOUT ROWID'
      )
      db.prepare('INSERT INTO t VALUES (?, ?, ?, ?)').run(1, 1, 1, 5)
      db.prepare(
        'INSERT INTO t VALUES (?, ?, ?, ?) ON CONFLICT(ts, host, metric) DO UPDATE SET v = excluded.v'
      ).run(1, 1, 1, 9)
      expect((db.prepare('SELECT v FROM t').get() as { v: number }).v).toBe(9)
    } finally {
      db.close()
    }
  })

  it('records the bundled SQLite version', async () => {
    const { DatabaseSync } = await import('node:sqlite')
    const db = new DatabaseSync(':memory:')
    try {
      const version = String((db.prepare('SELECT sqlite_version() AS v').get() as { v: string }).v)
      // Printed, not pinned. The point is that a bump is visible in CI output
      // next to a failure, not that a particular version is required — pinning
      // it would fail on every Electron upgrade for no reason.
      console.log(`[capability] node:sqlite reports SQLite ${version} on Node ${process.version}`)
      expect(version).toMatch(/^3\.\d+\.\d+/)
      // 3.24 is where UPSERT landed; anything older cannot run the roll-up.
      const [major, minor] = version.split('.').map(Number)
      expect(major).toBe(3)
      expect(minor).toBeGreaterThanOrEqual(24)
    } finally {
      db.close()
    }
  })
})
