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
// This test is that somebody — but only when it is run in the right runtime.
//
// WHICH RUNTIME IS THIS FILE ASSERTING ABOUT? Whichever one is executing it,
// and there are two:
//
//   * `npm test` runs it under vitest's own Node with electron mocked. An
//     Electron 43->44 bump changes NOTHING about what it executes here, so on
//     its own it would stay green through the exact regression it names, and
//     the SQLite version it records is the RUNNER's (3.51.3 on Node 22.23.1),
//     not the shipped one.
//   * `npm run test:capability` runs this same file inside Electron's bundled
//     Node via ELECTRON_RUN_AS_NODE — Node 24.18.1, SQLite 3.53.1, the runtime
//     ShellPilot actually ships. CI runs both. That second run is the one that
//     guards the decision; the first is a fast smoke check.
//
// The assertions below are deliberately about the CAPABILITY and not about
// ShellPilot's own code, so an Electron bump that removes an export, or refuses
// WAL, or ships a SQLite too old for the features the schema uses, fails with a
// sentence naming the thing that moved — rather than as an opaque runtime error
// on a user's machine at the first sweep.

// package.json's engines still allows Node >=20, and node:sqlite landed in
// 22.5. On such a machine these skip with a reason rather than failing a
// developer's whole suite for a module their Node cannot have; the runtime that
// must pass is Electron's, and CI runs it there.
const HAS_SQLITE = await import('node:sqlite').then(
  () => true,
  () => false
)

describe.skipIf(!HAS_SQLITE)('node:sqlite capability', () => {
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
        'CREATE TABLE t (ts INTEGER, server INTEGER, metric INTEGER, v REAL, PRIMARY KEY (ts, server, metric)) WITHOUT ROWID'
      )
      db.prepare('INSERT INTO t VALUES (?, ?, ?, ?)').run(1, 1, 1, 5)
      db.prepare(
        'INSERT INTO t VALUES (?, ?, ?, ?) ON CONFLICT(ts, server, metric) DO UPDATE SET v = excluded.v'
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
      console.log(
        `[capability] node:sqlite reports SQLite ${version} on Node ${process.version}` +
          `${process.versions.electron ? ` inside Electron ${process.versions.electron} — the shipped runtime` : ' (plain Node — NOT the shipped runtime)'}`
      )
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

describe('where this file is actually run', () => {
  it('names the runtime it is asserting about', () => {
    // This file's claim is about the runtime ShellPilot SHIPS — Electron's
    // bundled Node — and under plain vitest it is not running in it. Printed
    // rather than asserted, because both runs are legitimate; what is not
    // legitimate is reading a green tick here and believing an Electron bump
    // was checked.
    const runtime = process.versions.electron
      ? `Electron ${process.versions.electron} (Node ${process.versions.node}) — the runtime that ships`
      : `plain Node ${process.versions.node} — NOT the runtime that ships`
    console.log(`[capability] asserting about ${runtime}`)
    expect(typeof process.versions.node).toBe('string')
  })

  it('is run under Electron by CI, or these assertions are about the wrong SQLite', async () => {
    // Under vitest's own Node with electron mocked, an Electron 43->44 bump
    // changes nothing about what this file executes: it would stay green
    // through the exact regression it names, and the version it records is the
    // RUNNER's SQLite, not the shipped one. The only way this file guards what
    // it claims to guard is by also running inside Electron's Node.
    const { readFileSync } = await import('node:fs')
    const pkg = JSON.parse(readFileSync('package.json', 'utf8')) as {
      scripts: Record<string, string>
    }
    const script = pkg.scripts['test:capability']
    expect(script, 'package.json needs a test:capability script').toBeTruthy()
    expect(script).toContain('ELECTRON_RUN_AS_NODE=1')
    expect(script).toContain('tests/historyCapability.test.ts')

    const ci = readFileSync('.github/workflows/ci.yml', 'utf8')
    expect(ci, 'CI must run the capability file under Electron').toContain('npm run test:capability')
  })
})
