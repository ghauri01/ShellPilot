import { describe, it, expect, beforeEach, afterEach } from 'vitest'
import { mkdtempSync, rmSync, readdirSync, readFileSync, writeFileSync, existsSync, unlinkSync } from 'node:fs'
import { readFile, writeFile, readdir, stat, unlink, rename } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { app } from 'electron'
import {
  backupImport,
  backupTick,
  buildBundle,
  discardStagedBackup,
  dumpToDestination,
  inspectRemoteBackup,
  listRemoteBackups,
  readTargets,
  runBackupToDestination,
  saveDestinations,
  scheduledPassphrase,
  verifyBundle,
  withNameTimes,
  writeTargets
} from '../src/main/services/backup'
import {
  databaseDumpTarget,
  dumpableDatabases,
  type SftpIo
} from '../src/main/services/backupTargets'
import { vaultCreate, vaultDestroy, vaultDispose, vaultLock, vaultSave } from '../src/main/services/vault'
import {
  dueDestinations,
  dumpCommand,
  dumpObjectName,
  destinationProblem,
  describeRun
} from '../src/shared/backup'
import type {
  BackupDestination,
  LocalBackupDestination,
  SftpBackupDestination
} from '../src/shared/backup'
import type { VaultEntry } from '../src/shared/vault'

const PASSPHRASE = 'correct-horse-battery'
const FIXED = new Date('2024-05-06T07:08:09.000Z')
const FIXED_NAME = 'shellpilot-20240506T070809Z.spbackup'

const dirs: string[] = []
function temp(): string {
  const d = mkdtempSync(join(tmpdir(), 'sp-backup-run-'))
  dirs.push(d)
  return d
}

function localDest(directory: string, over: Partial<LocalBackupDestination> = {}): LocalBackupDestination {
  return {
    id: 'dest-local',
    name: 'Backups folder',
    kind: 'local',
    directory,
    keep: 0,
    everyHours: 0,
    restoreTest: true,
    ...over
  }
}

function sftpDest(directory: string, over: Partial<SftpBackupDestination> = {}): SftpBackupDestination {
  return {
    id: 'dest-sftp',
    name: 'Backup box',
    kind: 'sftp',
    serverId: 'srv-1',
    directory,
    keep: 0,
    everyHours: 0,
    restoreTest: true,
    ...over
  }
}

/** The same real-directory SFTP stand-in the driver tests use: real files,
 *  real promises, the production driver on top of it. `faults` is how a
 *  connection that drops between two calls is reproduced without a network. */
function tempSftpIo(
  dir: string,
  faults: Partial<Record<'writeFile' | 'rename' | 'readFile' | 'readdir' | 'unlink', string>> = {}
): SftpIo {
  const boom = (op: keyof typeof faults): void => {
    const message = faults[op]
    if (message) throw new Error(message)
  }
  return {
    async readFile(path) {
      boom('readFile')
      return readFile(path)
    },
    async writeFile(path, data) {
      boom('writeFile')
      await writeFile(path, data, { mode: 0o600 })
    },
    async readdir(path) {
      boom('readdir')
      const out: { name: string; size: number; modified: number }[] = []
      for (const name of await readdir(path)) {
        const s = await stat(join(path, name))
        if (!s.isDirectory()) out.push({ name, size: s.size, modified: s.mtimeMs })
      }
      return out
    },
    async unlink(path) {
      boom('unlink')
      await unlink(path)
    },
    async rename(from, to) {
      boom('rename')
      await rename(from, to)
    },
    async close() {
      /* nothing held */
    }
  }
}

const USER_DATA = app.getPath('userData')

function cleanUserData(): void {
  for (const f of readdirSync(USER_DATA)) {
    try {
      rmSync(join(USER_DATA, f), { recursive: true, force: true })
    } catch {
      /* ignore */
    }
  }
}

beforeEach(() => {
  vaultDispose()
  cleanUserData()
})

afterEach(() => {
  for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true })
  vaultDispose()
})

// ---------------------------------------------------------------------------
// The bundle, and what "verified" means
// ---------------------------------------------------------------------------

describe('verifyBundle', () => {
  it('opens a bundle this app just wrote', async () => {
    const { bytes } = await buildBundle(PASSPHRASE)
    const v = await verifyBundle(bytes, PASSPHRASE)
    expect(v.ok).toBe(true)
    expect(v.bytes).toBe(bytes.length)
    expect(v.summary?.app).toBe('0.6.2')
  })

  it('detects a zero-length file, which a lazier check reads as valid and empty', async () => {
    // This is the exact shape of the bug this repo already shipped: the
    // history store's backup wrote over the file it was protecting, a failure
    // left it at zero bytes, and the reader accepted a zero-length file as a
    // valid empty database and reported a successful recovery.
    const v = await verifyBundle(Buffer.alloc(0), PASSPHRASE)
    expect(v.ok).toBe(false)
    expect(v.error).toBe('That file is not a ShellPilot backup.')
  })

  it('detects a truncated upload', async () => {
    const { bytes } = await buildBundle(PASSPHRASE)
    const v = await verifyBundle(bytes.subarray(0, Math.floor(bytes.length / 2)), PASSPHRASE)
    expect(v.ok).toBe(false)
    expect(v.error).toBe('That file is not a ShellPilot backup.')
  })

  it('detects a single flipped byte in the ciphertext', async () => {
    // Well-formed JSON, right magic, right length. Only the GCM tag says no —
    // which is the whole reason the restore test decrypts rather than reading.
    const { bytes } = await buildBundle(PASSPHRASE)
    const envelope = JSON.parse(bytes.toString('utf8')) as { data: string }
    const raw = Buffer.from(envelope.data, 'base64')
    raw[Math.floor(raw.length / 2)] ^= 0xff
    const corrupt = Buffer.from(
      JSON.stringify({ ...envelope, data: raw.toString('base64') }),
      'utf8'
    )
    expect(corrupt.length).toBe(bytes.length)

    const v = await verifyBundle(corrupt, PASSPHRASE)
    expect(v.ok).toBe(false)
    expect(v.error).toContain('did not decrypt')
  })

  it('detects a file that is not one of ours at all', async () => {
    const v = await verifyBundle(Buffer.from('{"magic":"something-else"}'), PASSPHRASE)
    expect(v.ok).toBe(false)
    expect(v.error).toBe('That file is not a ShellPilot backup.')
  })

  it('rejects the wrong passphrase rather than returning an empty payload', async () => {
    const { bytes } = await buildBundle(PASSPHRASE)
    const v = await verifyBundle(bytes, 'not-the-passphrase')
    expect(v.ok).toBe(false)
    expect(v.summary).toBe(undefined)
  })
})

// ---------------------------------------------------------------------------
// A run against a real local directory
// ---------------------------------------------------------------------------

describe('runBackupToDestination', () => {
  it('writes, reads back, test-restores, and says so', async () => {
    const dir = temp()
    const report = await runBackupToDestination(localDest(dir), PASSPHRASE, { now: () => FIXED })

    expect(report.ok).toBe(true)
    expect(report.failedStage).toBe(undefined)
    expect(report.name).toBe(FIXED_NAME)
    expect(report.verified).toBe(true)
    expect(report.restoreTested).toBe(true)
    expect(report.digest).toBe(report.readBackDigest)
    expect(report.restoreTest?.summary?.app).toBe('0.6.2')
    expect(readdirSync(dir)).toEqual([FIXED_NAME])

    // And the file on disk is genuinely a bundle, opened by the same code path
    // a restore would use.
    const onDisk = readFileSync(join(dir, FIXED_NAME))
    expect((await verifyBundle(onDisk, PASSPHRASE)).ok).toBe(true)
  })

  it('reports a write that fails part-way as failed, and leaves no generation behind', async () => {
    // The connection drops between the upload and the rename. A run that
    // reported partial success here, or that left a file under a real
    // generation name, is the failure mode this whole item exists to refuse.
    const dir = temp()
    const report = await runBackupToDestination(sftpDest(dir), PASSPHRASE, {
      now: () => FIXED,
      sftpIo: async () => tempSftpIo(dir, { rename: 'Connection reset by peer' })
    })

    expect(report.ok).toBe(false)
    expect(report.failedStage).toBe('write')
    expect(report.error).toBe('Connection reset by peer')
    expect(report.verified).toBe(false)
    expect(report.restoreTested).toBe(false)
    expect(readdirSync(dir)).toEqual([])
  })

  it('treats a destination it cannot read back as a failure, and removes what it wrote', async () => {
    // Write-only credentials, a bucket policy that allows PUT and not GET, a
    // filesystem that accepted the write and cannot serve it. In every case
    // there is now a file nobody can restore from, and calling that a backup
    // is how an operator stops thinking about it.
    const dir = temp()
    const report = await runBackupToDestination(sftpDest(dir), PASSPHRASE, {
      now: () => FIXED,
      sftpIo: async () => tempSftpIo(dir, { readFile: 'Permission denied' })
    })

    expect(report.ok).toBe(false)
    expect(report.failedStage).toBe('verify')
    expect(report.error).toContain('could not read it back: Permission denied')
    expect(report.error).toContain('A destination that cannot be read is not a backup')
    expect(report.verified).toBe(false)
    expect(readdirSync(dir)).toEqual([])
  })

  it('fails the run when the bytes come back different, and does not leave them looking like a backup', async () => {
    const dir = temp()
    const report = await runBackupToDestination(sftpDest(dir), PASSPHRASE, {
      now: () => FIXED,
      sftpIo: async () => {
        const io = tempSftpIo(dir)
        return { ...io, readFile: async () => Buffer.from('truncated by the far end') }
      }
    })

    expect(report.ok).toBe(false)
    expect(report.failedStage).toBe('verify')
    expect(report.error).toContain('came back as 24 bytes')
    expect(report.readBackDigest).not.toBe(report.digest)
    expect(readdirSync(dir)).toEqual([])
  })

  it('the restore test catches a corrupt archive that survived the checksum', async () => {
    // Bytes that round-trip perfectly and are still not a backup. The checksum
    // cannot see this; only decrypting can. `bundle` is the seam that lets a
    // healthy build produce one — see RunOptions.
    const dir = temp()
    const report = await runBackupToDestination(localDest(dir), PASSPHRASE, {
      now: () => FIXED,
      bundle: async () => ({
        bytes: Buffer.from('{"magic":"shellpilot-backup","version":1,"kdf":"scrypt","salt":"","iv":"","tag":"","data":""}'),
        summary: {
          createdAt: FIXED.toISOString(),
          app: '0.6.2',
          servers: 0,
          databases: 0,
          workspaces: 0,
          secrets: 0,
          hasVault: false
        }
      })
    })

    expect(report.ok).toBe(false)
    expect(report.failedStage).toBe('restore-test')
    // It got as far as matching bytes, which is exactly why the byte check is
    // not enough on its own.
    expect(report.verified).toBe(true)
    expect(report.restoreTested).toBe(false)
    expect(report.error).toContain('did not decrypt')
    expect(report.error).toContain('It has been removed.')
    expect(readdirSync(dir)).toEqual([])
  })

  it('refuses a passphrase too short to be worth encrypting with', async () => {
    const dir = temp()
    const report = await runBackupToDestination(localDest(dir), 'short', { now: () => FIXED })
    expect(report.ok).toBe(false)
    expect(report.failedStage).toBe('bundle')
    expect(report.error).toBe('Backup passphrase must be at least 8 characters.')
    expect(readdirSync(dir)).toEqual([])
  })

  it('reports the destination it could not even open', async () => {
    const report = await runBackupToDestination(localDest(''), PASSPHRASE, { now: () => FIXED })
    expect(report.ok).toBe(false)
    expect(report.failedStage).toBe('write')
    expect(report.error).toBe('This destination has no directory set.')
  })
})

// ---------------------------------------------------------------------------
// Retention, applied to a real directory by a real run
// ---------------------------------------------------------------------------

describe('retention during a run', () => {
  const older = [
    'shellpilot-20240101T000000Z.spbackup',
    'shellpilot-20240102T000000Z.spbackup',
    'shellpilot-20240103T000000Z.spbackup'
  ]

  it('deletes the oldest generations and keeps the newest, including the one just written', async () => {
    const dir = temp()
    for (const name of older) writeFileSync(join(dir, name), 'an older bundle')

    const report = await runBackupToDestination(localDest(dir, { keep: 2 }), PASSPHRASE, {
      now: () => FIXED
    })

    expect(report.ok).toBe(true)
    expect(report.removed).toEqual([
      'shellpilot-20240102T000000Z.spbackup',
      'shellpilot-20240101T000000Z.spbackup'
    ])
    expect(readdirSync(dir).sort()).toEqual([
      'shellpilot-20240103T000000Z.spbackup',
      FIXED_NAME
    ].sort())
  })

  it('does not delete the only generation there is', async () => {
    const dir = temp()
    const report = await runBackupToDestination(localDest(dir, { keep: 1 }), PASSPHRASE, {
      now: () => FIXED
    })
    expect(report.ok).toBe(true)
    expect(report.removed).toEqual([])
    expect(report.retentionRefused).toBe('Only one backup is here, and the last one is never deleted.')
    expect(readdirSync(dir)).toEqual([FIXED_NAME])
  })

  it('never deletes anything when the write failed', async () => {
    // Retention runs last for this reason: deleting a backup that works, in
    // favour of one that is not there, is strictly worse than keeping too many.
    const dir = temp()
    for (const name of older) writeFileSync(join(dir, name), 'an older bundle')

    const report = await runBackupToDestination(sftpDest(dir, { keep: 1 }), PASSPHRASE, {
      now: () => FIXED,
      sftpIo: async () => tempSftpIo(dir, { readFile: 'Permission denied' })
    })

    expect(report.ok).toBe(false)
    expect(report.removed).toEqual([])
    expect(readdirSync(dir).sort()).toEqual([...older].sort())
  })

  it('leaves files that are not ShellPilot backups alone', async () => {
    const dir = temp()
    for (const name of older) writeFileSync(join(dir, name), 'an older bundle')
    writeFileSync(join(dir, 'photos.zip'), 'somebody else’s file')

    const report = await runBackupToDestination(localDest(dir, { keep: 1 }), PASSPHRASE, {
      now: () => FIXED
    })

    expect(report.removed).toEqual(older.slice().reverse())
    expect(readdirSync(dir).sort()).toEqual([FIXED_NAME, 'photos.zip'].sort())
  })

  it('orders by the time in the name, not by the destination’s clock', async () => {
    // An SFTP mtime is the remote clock and an S3 LastModified is when the
    // bucket accepted the PUT. Trusting either would delete the wrong file on
    // a server whose clock is wrong.
    const generations = [
      { name: 'shellpilot-20240103T000000Z.spbackup', size: 1, modified: 5 },
      { name: 'shellpilot-20240101T000000Z.spbackup', size: 1, modified: 9999 }
    ]
    expect(withNameTimes(generations).map((g) => g.modified)).toEqual([
      Date.parse('2024-01-03T00:00:00Z'),
      Date.parse('2024-01-01T00:00:00Z')
    ])
  })
})

// ---------------------------------------------------------------------------
// Restore from a destination
// ---------------------------------------------------------------------------

describe('restore from a destination', () => {
  it('lists only ShellPilot backups, newest first', async () => {
    const dir = temp()
    writeFileSync(join(dir, 'shellpilot-20240101T000000Z.spbackup'), 'a')
    writeFileSync(join(dir, 'shellpilot-20240301T000000Z.spbackup'), 'b')
    writeFileSync(join(dir, 'shellpilot-20240201T000000Z.spbackup'), 'c')
    writeFileSync(join(dir, 'holiday.jpg'), 'not a backup')

    const result = await listRemoteBackups(localDest(dir))
    expect(result.ok).toBe(true)
    expect(result.generations?.map((g) => g.name)).toEqual([
      'shellpilot-20240301T000000Z.spbackup',
      'shellpilot-20240201T000000Z.spbackup',
      'shellpilot-20240101T000000Z.spbackup'
    ])
  })

  it('inspects before it imports, and stages the exact bytes it inspected', async () => {
    const dir = temp()
    await runBackupToDestination(localDest(dir), PASSPHRASE, { now: () => FIXED })

    const inspected = await inspectRemoteBackup(localDest(dir), FIXED_NAME, PASSPHRASE)
    expect(inspected.ok).toBe(true)
    expect(inspected.summary?.app).toBe('0.6.2')
    expect(inspected.path).toBeTruthy()
    // The staged copy is byte-identical to what is at the destination: the
    // import runs on what the user was shown, not on a second download.
    expect(readFileSync(inspected.path as string)).toEqual(readFileSync(join(dir, FIXED_NAME)))

    const imported = await backupImport(PASSPHRASE, inspected.path as string)
    expect(imported.ok).toBe(true)

    discardStagedBackup(inspected.path as string)
    expect(existsSync(inspected.path as string)).toBe(false)
  })

  it('refuses a corrupt archive at the destination instead of staging it for import', async () => {
    const dir = temp()
    writeFileSync(join(dir, FIXED_NAME), '{"magic":"shellpilot-backup","salt":"","iv":"","tag":"","data":""}')

    const inspected = await inspectRemoteBackup(localDest(dir), FIXED_NAME, PASSPHRASE)

    expect(inspected.ok).toBe(false)
    expect(inspected.error).toContain('did not decrypt')
    expect(inspected.path).toBe(undefined)
    // And nothing was staged for a later import to pick up.
    expect(readdirSync(USER_DATA).filter((f) => f.startsWith('staged-'))).toEqual([])
  })

  it('refuses a name that is not a ShellPilot backup', async () => {
    const dir = temp()
    const inspected = await inspectRemoteBackup(localDest(dir), '../../etc/passwd', PASSPHRASE)
    expect(inspected.ok).toBe(false)
    expect(inspected.error).toBe('“../../etc/passwd” is not a ShellPilot backup name.')
  })

  it('reports a destination that cannot be reached rather than an empty list', async () => {
    const result = await listRemoteBackups(localDest(join(temp(), 'does-not-exist')))
    expect(result.ok).toBe(false)
    expect(result.generations).toBe(undefined)
    expect(result.error).toContain('ENOENT')
  })
})

// ---------------------------------------------------------------------------
// The stored destinations
// ---------------------------------------------------------------------------

describe('destination storage', () => {
  it('starts empty and round-trips', () => {
    expect(readTargets().destinations).toEqual([])
    const dest = localDest('/tmp/x')
    saveDestinations([dest])
    expect(readTargets().destinations).toEqual([dest])
  })

  it('drops the run history of a destination that was deleted', () => {
    const a = localDest('/tmp/a', { id: 'a' })
    const b = localDest('/tmp/b', { id: 'b' })
    saveDestinations([a, b])
    writeTargets({ ...readTargets(), lastRunAt: { a: 111, b: 222 } })

    saveDestinations([a])

    expect(readTargets().lastRunAt).toEqual({ a: 111 })
  })

  it('is stored outside the file that travels inside every bundle', async () => {
    // shellpilot-data.json IS payload.data. A destination configuration kept
    // there would ride inside every bundle uploaded to the bucket it names.
    saveDestinations([localDest('/tmp/x')])
    const { bytes } = await buildBundle(PASSPHRASE)
    expect(bytes.toString('utf8')).not.toContain('/tmp/x')
    expect(existsSync(join(USER_DATA, 'shellpilot-backup-targets.json'))).toBe(true)
  })
})

// ---------------------------------------------------------------------------
// Scheduling
// ---------------------------------------------------------------------------

describe('dueDestinations', () => {
  const hourly = localDest('/tmp/x', { id: 'hourly', everyHours: 1 })
  const manual = localDest('/tmp/y', { id: 'manual', everyHours: 0 })

  it('runs a destination that has never run, immediately', () => {
    expect(dueDestinations([hourly, manual], {}, 1_000_000).map((d) => d.id)).toEqual(['hourly'])
  })

  it('waits a full period after the last attempt', () => {
    const t = 1_000_000_000
    expect(dueDestinations([hourly], { hourly: t }, t + 3599_000)).toEqual([])
    expect(dueDestinations([hourly], { hourly: t }, t + 3600_000).map((d) => d.id)).toEqual(['hourly'])
  })

  it('never schedules a destination with no interval', () => {
    expect(dueDestinations([manual], {}, Date.now())).toEqual([])
  })
})

describe('backupTick', () => {
  async function vaultWith(entries: Partial<VaultEntry>[]): Promise<void> {
    const created = await vaultCreate('vault-master-pw')
    expect(created.ok).toBe(true)
    vaultSave(
      entries.map((e, i) => ({
        id: `v${i}`,
        name: `entry ${i}`,
        kind: 'key' as const,
        url: '',
        username: '',
        password: '',
        notes: '',
        tags: [],
        fields: [],
        createdAt: '2024-01-01T00:00:00.000Z',
        updatedAt: '2024-01-01T00:00:00.000Z',
        ...e
      }))
    )
  }

  it('runs a due destination with the passphrase from the vault', async () => {
    const dir = temp()
    await vaultWith([{ id: 'pw', name: 'Backup passphrase', password: PASSPHRASE }])
    saveDestinations([localDest(dir, { everyHours: 1, passphraseVaultEntryId: 'pw' })])

    const { ran, skipped } = await backupTick(FIXED.getTime(), { now: () => FIXED })

    expect(skipped).toEqual({})
    expect(ran).toHaveLength(1)
    expect(ran[0].ok).toBe(true)
    expect(readdirSync(dir)).toEqual([FIXED_NAME])
    expect(readTargets().lastRunAt['dest-local']).toBe(FIXED.getTime())
    expect(readTargets().lastReport['dest-local'].name).toBe(FIXED_NAME)
  })

  it('says why it skipped a run rather than doing nothing quietly', async () => {
    const dir = temp()
    await vaultWith([{ id: 'pw', name: 'Backup passphrase', password: PASSPHRASE }])
    saveDestinations([localDest(dir, { everyHours: 1, passphraseVaultEntryId: 'pw' })])
    vaultLock()

    const { ran, skipped } = await backupTick(FIXED.getTime(), { now: () => FIXED })

    expect(ran).toEqual([])
    expect(skipped).toEqual({
      'dest-local': 'The passphrase lives in the vault, and the vault is locked.'
    })
    expect(readdirSync(dir)).toEqual([])
    // Not marked as attempted: a locked vault clears on its own, and pushing
    // the next attempt an hour out would turn an hourly backup into a daily one.
    expect(readTargets().lastRunAt).toEqual({})
  })

  it('marks a failing destination as attempted, so it is not retried every tick', async () => {
    await vaultWith([{ id: 'pw', name: 'Backup passphrase', password: PASSPHRASE }])
    saveDestinations([localDest('', { everyHours: 1, passphraseVaultEntryId: 'pw' })])

    const { ran } = await backupTick(FIXED.getTime(), { now: () => FIXED })

    expect(ran[0].ok).toBe(false)
    expect(readTargets().lastRunAt['dest-local']).toBe(FIXED.getTime())
  })

  it('names the vault entry when it holds nothing usable', async () => {
    await vaultWith([{ id: 'pw', name: 'Backup passphrase', password: 'tiny' }])
    saveDestinations([localDest(temp(), { everyHours: 1, passphraseVaultEntryId: 'pw' })])

    const { skipped } = await backupTick(FIXED.getTime(), { now: () => FIXED })

    expect(skipped['dest-local']).toBe(
      'Vault entry “Backup passphrase” holds a passphrase shorter than 8 characters.'
    )
  })

  it('says so when the destination names no passphrase entry at all', () => {
    expect(scheduledPassphrase(localDest('/tmp/x', { everyHours: 1 }))).toEqual({
      skipped: 'No vault entry is set to hold the passphrase for unattended runs.'
    })
  })

  it('says so when there is no vault on this machine', async () => {
    vaultDestroy()
    expect(
      scheduledPassphrase(localDest('/tmp/x', { everyHours: 1, passphraseVaultEntryId: 'pw' }))
    ).toEqual({
      skipped: 'The passphrase lives in the vault, and there is no vault on this machine.'
    })
  })
})

// ---------------------------------------------------------------------------
// Database dumps
// ---------------------------------------------------------------------------

describe('dumpCommand', () => {
  const target = {
    engine: 'postgres' as const,
    host: 'db.internal',
    port: 5432,
    username: 'reporting',
    database: 'orders'
  }

  it('builds the pg_dump argv, with the password nowhere in it', () => {
    expect(dumpCommand(target, 'hunter2')).toEqual({
      binary: 'pg_dump',
      args: [
        '--host', 'db.internal',
        '--port', '5432',
        '--username', 'reporting',
        '--no-password',
        '--format', 'plain',
        'orders'
      ],
      env: { PGPASSWORD: 'hunter2' }
    })
  })

  it('builds the mysqldump argv, with the password in the environment', () => {
    // `--password=` on the command line puts the credential in every process
    // listing on the machine. MYSQL_PWD does not.
    const cmd = dumpCommand({ ...target, engine: 'mysql', port: 3306 }, 'hunter2')
    expect(cmd.binary).toBe('mysqldump')
    expect(cmd.args).toEqual([
      '--host', 'db.internal',
      '--port', '3306',
      '--user', 'reporting',
      '--single-transaction',
      '--routines',
      '--events',
      'orders'
    ])
    expect(cmd.args.join(' ')).not.toContain('hunter2')
    expect(cmd.env).toEqual({ MYSQL_PWD: 'hunter2' })
  })

  it('names the dump so retention never mistakes it for an encrypted bundle', () => {
    expect(dumpObjectName(target, FIXED)).toBe('shellpilot-dump-orders-20240506T070809Z.sql')
  })
})

describe('dumpToDestination', () => {
  const target = {
    engine: 'postgres' as const,
    host: 'db.internal',
    port: 5432,
    username: 'reporting',
    database: 'orders'
  }

  it('writes the dump and verifies it by reading it back', async () => {
    const dir = temp()
    const report = await dumpToDestination(localDest(dir), target, 'pw', {
      now: () => FIXED,
      spawn: async () => ({
        stdout: Buffer.from('-- PostgreSQL database dump\nCREATE TABLE orders();\n'),
        stderr: '',
        code: 0,
        signal: null
      })
    })

    expect(report.ok).toBe(true)
    expect(report.verified).toBe(true)
    expect(report.name).toBe('shellpilot-dump-orders-20240506T070809Z.sql')
    expect(readFileSync(join(dir, report.name as string), 'utf8')).toBe(
      '-- PostgreSQL database dump\nCREATE TABLE orders();\n'
    )
  })

  it('refuses a dump binary that exited cleanly having written nothing', async () => {
    // An empty dump is never a correct dump, and a zero-byte file that a
    // reader accepts as "valid and empty" is precisely the bug this codebase
    // already shipped once against its own history database.
    const dir = temp()
    const report = await dumpToDestination(localDest(dir), target, 'pw', {
      now: () => FIXED,
      spawn: async () => ({ stdout: Buffer.alloc(0), stderr: '', code: 0, signal: null })
    })

    expect(report.ok).toBe(false)
    expect(report.error).toBe('pg_dump exited cleanly but produced no output.')
    expect(readdirSync(dir)).toEqual([])
  })

  it('reports the dump binary’s own complaint when it fails', async () => {
    const dir = temp()
    const report = await dumpToDestination(localDest(dir), target, 'pw', {
      now: () => FIXED,
      spawn: async () => ({
        stdout: Buffer.from('partial'),
        stderr: 'pg_dump: error: connection to server at "db.internal" failed',
        code: 1,
        signal: null
      })
    })

    expect(report.ok).toBe(false)
    expect(report.failedStage).toBe('bundle')
    expect(report.error).toBe(
      'pg_dump exited 1: pg_dump: error: connection to server at "db.internal" failed'
    )
    expect(readdirSync(dir)).toEqual([])
  })

  it('removes a dump it could not read back', async () => {
    const dir = temp()
    const report = await dumpToDestination(sftpDest(dir), target, 'pw', {
      now: () => FIXED,
      sftpIo: async () => tempSftpIo(dir, { readFile: 'Permission denied' }),
      spawn: async () => ({ stdout: Buffer.from('CREATE TABLE orders();'), stderr: '', code: 0, signal: null })
    })

    expect(report.ok).toBe(false)
    expect(report.failedStage).toBe('verify')
    expect(report.verified).toBe(false)
    expect(readdirSync(dir)).toEqual([])
  })
})

// ---------------------------------------------------------------------------
// What the user is told
// ---------------------------------------------------------------------------

describe('describeRun', () => {
  const base = {
    destinationId: 'd',
    destinationName: 'Off-site bucket',
    destinationKind: 's3' as const,
    startedAt: '',
    finishedAt: '',
    removed: [] as string[]
  }

  it('never says "backed up" about something that was not read back', () => {
    expect(
      describeRun({
        ...base,
        ok: false,
        verified: false,
        restoreTested: false,
        failedStage: 'verify',
        error: 'Permission denied'
      })
    ).toBe('Off-site bucket: failed while reading the bundle back — Permission denied')
  })

  it('says what it proved when it succeeded', () => {
    expect(
      describeRun({
        ...base,
        ok: true,
        name: FIXED_NAME,
        verified: true,
        restoreTested: true,
        removed: ['shellpilot-20240101T000000Z.spbackup']
      })
    ).toBe(
      `Off-site bucket: wrote ${FIXED_NAME}, read back and test-restored, removed 1 older`
    )
  })
})

describe('destinationProblem', () => {
  it('names the missing field rather than refusing silently', () => {
    expect(destinationProblem(localDest(''))).toBe('Choose a directory to write backups into.')
    expect(destinationProblem(sftpDest('/srv/b', { serverId: '' }))).toBe(
      'Choose which configured server to upload to.'
    )
  })

  it('explains why an S3 secret cannot live in settings', () => {
    const dest: BackupDestination = {
      id: 's3',
      name: 'Bucket',
      kind: 's3',
      endpoint: 'https://s3.example',
      region: 'eu-west-1',
      bucket: 'b',
      prefix: '',
      vaultEntryId: '',
      pathStyle: true,
      keep: 0,
      everyHours: 0,
      restoreTest: true
    }
    expect(destinationProblem(dest)).toContain('settings travel inside every backup written here')
  })

  it('requires a passphrase entry before a schedule can mean anything', () => {
    expect(destinationProblem(localDest('/tmp/x', { everyHours: 6 }))).toBe(
      'A scheduled run has nobody to type a passphrase, so it needs a vault entry holding one.'
    )
    expect(destinationProblem(localDest('/tmp/x', { everyHours: 6, passphraseVaultEntryId: 'v' }))).toBe(
      null
    )
  })
})

// Keeps the linter honest about an import used only for cleanup in one branch.
describe('staged downloads', () => {
  it('only ever removes files it staged itself', () => {
    const outsider = join(USER_DATA, 'not-staged.spbackup')
    writeFileSync(outsider, 'someone else’s file')
    discardStagedBackup(outsider)
    expect(existsSync(outsider)).toBe(true)
    unlinkSync(outsider)
  })
})

// ---------------------------------------------------------------------------
// Which databases a dump can come from
// ---------------------------------------------------------------------------

describe('databaseDumpTarget', () => {
  function saveDatabases(databases: Record<string, unknown>[]): void {
    writeFileSync(join(USER_DATA, 'shellpilot-data.json'), JSON.stringify({ databases }))
  }

  const direct = {
    id: 'db-orders',
    name: 'orders-prod',
    kind: 'postgres',
    host: 'db.internal',
    port: 5432,
    username: 'reporting',
    database: 'orders',
    uri: false,
    sshServerId: null,
    vpnProfileId: null
  }

  it('builds a dump target from a directly reachable database', () => {
    saveDatabases([direct])
    expect(databaseDumpTarget('db-orders')).toEqual({
      target: {
        engine: 'postgres',
        host: 'db.internal',
        port: 5432,
        username: 'reporting',
        database: 'orders'
      },
      password: ''
    })
  })

  it('refuses a database behind a bastion, rather than dialling an address it cannot reach', () => {
    // dbOps opens a forward for exactly this reason. A dump that ignored it
    // would sit on a TCP connect until it timed out and then report a network
    // error about the wrong address.
    saveDatabases([{ ...direct, sshServerId: 'srv-bastion' }])
    expect(databaseDumpTarget('db-orders')).toEqual({
      error:
        'This database is reached through a bastion or a VPN, and a dump runs from this machine directly — so it would be pointed at an address it cannot reach.'
    })
  })

  it('refuses a database behind a VPN for the same reason', () => {
    saveDatabases([{ ...direct, vpnProfileId: 'vpn-office' }])
    expect('error' in databaseDumpTarget('db-orders')).toBe(true)
  })

  it('refuses a connection defined by a connection string', () => {
    saveDatabases([{ ...direct, uri: true }])
    expect(databaseDumpTarget('db-orders')).toEqual({
      error:
        'This connection is defined by a connection string, and rebuilding a dump command out of one is how a dump ends up pointed at the wrong database.'
    })
  })

  it('refuses an engine there is no dump binary for, by name', () => {
    saveDatabases([{ ...direct, kind: 'mongodb' }])
    expect(databaseDumpTarget('db-orders')).toEqual({
      error: 'Dumps are only supported for PostgreSQL and MySQL, and this one is mongodb.'
    })
  })

  it('offers only the databases a dump could actually be taken from', () => {
    saveDatabases([
      direct,
      { ...direct, id: 'db-mysql', name: 'billing', kind: 'mysql', port: 3306 },
      { ...direct, id: 'db-mongo', name: 'events', kind: 'mongodb' },
      { ...direct, id: 'db-bastion', name: 'behind-bastion', sshServerId: 'srv-1' },
      { ...direct, id: 'db-uri', name: 'by-uri', uri: true }
    ])
    expect(dumpableDatabases()).toEqual([
      { id: 'db-orders', name: 'orders-prod', engine: 'postgres' },
      { id: 'db-mysql', name: 'billing', engine: 'mysql' }
    ])
  })

  it('says so when the database has been deleted since the destination was set up', () => {
    saveDatabases([])
    expect(databaseDumpTarget('db-orders')).toEqual({
      error: 'That database is no longer configured.'
    })
  })
})
