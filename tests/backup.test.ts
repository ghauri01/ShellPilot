import { describe, it, expect, afterEach } from 'vitest'
import { existsSync, readdirSync, writeFileSync, unlinkSync } from 'node:fs'
import { randomBytes, scrypt, createCipheriv } from 'node:crypto'
import { join } from 'node:path'
import { app } from 'electron'
import { backupImport, deleteAllData } from '../src/main/services/backup'
import { HISTORY_FILE } from '../src/main/services/history'

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

// The database and every sidecar the store can leave behind: the WAL and shm
// the journal mode creates, the .bak the recovery ladder restores from, and the
// timestamped copies the ladder moves a corrupt primary aside to.
function historyPaths(): string[] {
  const db = join(app.getPath('userData'), HISTORY_FILE)
  return [
    db,
    `${db}-wal`,
    `${db}-shm`,
    `${db}.bak`,
    // The backup is written here and renamed onto the .bak, so a process that
    // died under one leaves this behind holding the same inventory.
    `${db}.bak.tmp`,
    `${db}.corrupt-1700000000000`
  ]
}

function writeHistoryFiles(): void {
  for (const p of historyPaths()) writeFileSync(p, 'srv-prod-01 kernel 6.1.0 nginx.service :443')
}

function cleanup(): void {
  for (const p of [...paths(), ...historyPaths()]) {
    try {
      if (existsSync(p)) unlinkSync(p)
    } catch {
      /* ignore */
    }
  }
}

describe('deleteAllData', () => {
  afterEach(cleanup)

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

  it('deletes the history database, its sidecars, its backup and its corrupt copies', () => {
    // "Delete all data" that leaves shellpilot-history.db behind relaunches the
    // app on a file still holding every hostname, kernel version, systemd unit
    // and listening port in the estate — for ninety days — and then goes on
    // appending to it. history.ts chmods that file 0600 precisely because it is
    // sensitive; a delete that skips it is the same claim made backwards.
    writeHistoryFiles()
    expect(historyPaths().every(existsSync)).toBe(true)

    const result = deleteAllData()

    expect(result.ok).toBe(true)
    expect(historyPaths().filter(existsSync)).toEqual([])
    // And nothing history-shaped is left in the directory at all.
    expect(readdirSync(app.getPath('userData')).filter((f) => f.startsWith(HISTORY_FILE))).toEqual([])
  })

  it('closes the store before unlinking, because app.exit(0) never runs before-quit', () => {
    // relaunchApp() calls app.exit(0), which does NOT emit 'before-quit', so
    // the teardown that closes the store never runs on this path. Unlinking an
    // open database is EBUSY on Windows, so the close has to happen here.
    writeHistoryFiles()
    const sawFile: boolean[] = []
    deleteAllData(() => sawFile.push(existsSync(historyPaths()[0])))
    // Called exactly once, and while the database was still on disk — i.e.
    // before the unlink, not after it.
    expect(sawFile).toEqual([true])
    expect(historyPaths().some(existsSync)).toBe(false)
  })
})

// A bundle written the way backupExport writes one, so the import path can be
// exercised without a save dialog.
async function writeBundle(file: string, password: string): Promise<void> {
  const salt = randomBytes(16)
  const key: Buffer = await new Promise((resolve, reject) =>
    scrypt(password, salt, 32, { N: 32768, r: 8, p: 1, maxmem: 96 * 1024 * 1024 }, (err, dk) =>
      err ? reject(err) : resolve(dk as Buffer)
    )
  )
  const iv = randomBytes(12)
  const cipher = createCipheriv('aes-256-gcm', key, iv)
  const payload = {
    version: 1,
    createdAt: new Date().toISOString(),
    app: '0.9.7',
    data: { servers: [] },
    secrets: {},
    vault: null,
    workspaceLocks: null,
    knownHosts: null
  }
  const body = Buffer.concat([cipher.update(JSON.stringify(payload), 'utf8'), cipher.final()])
  writeFileSync(
    file,
    JSON.stringify({
      magic: 'shellpilot-backup',
      version: 1,
      kdf: 'scrypt',
      salt: salt.toString('base64'),
      iv: iv.toString('base64'),
      tag: cipher.getAuthTag().toString('base64'),
      data: body.toString('base64')
    })
  )
}

describe('backupImport', () => {
  afterEach(cleanup)

  it('clears the previous estate history rather than co-mingling it', async () => {
    // A bundle carries connections, credentials and vault — it does not carry
    // history. Restoring one onto a machine that already has a database leaves
    // the PREVIOUS estate's hostnames, units and ports underneath the new
    // estate's, in one table, with nothing marking which is which.
    const bundle = join(app.getPath('userData'), 'test.spbackup')
    await writeBundle(bundle, 'passphrase-1234')
    writeHistoryFiles()

    const result = await backupImport('passphrase-1234', bundle)

    expect(result.ok).toBe(true)
    expect(historyPaths().filter(existsSync)).toEqual([])
    unlinkSync(bundle)
  })
})
