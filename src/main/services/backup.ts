import { app, dialog, BrowserWindow } from 'electron'
import { join } from 'node:path'
import { existsSync, readFileSync, writeFileSync, renameSync, unlinkSync } from 'node:fs'
import { randomBytes, scrypt, createCipheriv, createDecipheriv } from 'node:crypto'
import { spawn } from 'node:child_process'
import { exportSecrets, importSecrets } from './secrets'
import { removeHistoryFiles } from './history'
import { openTarget, sha256, type BackupTarget, type TargetDeps } from './backupTargets'
import { vaultList, vaultStatus } from './vault'
import {
  backupObjectName,
  backupObjectTime,
  dumpCommand,
  dumpObjectName,
  DUMP_BINARY,
  describeRun,
  dueDestinations,
  planRetention
} from '../../shared/backup'
import type {
  BackupDestination,
  BackupGeneration,
  BackupPayload,
  BackupResult,
  BackupRunReport,
  BackupStage,
  BackupSummary,
  BackupVerification,
  DumpCommand,
  DumpTarget
} from '../../shared/backup'

// A backup is a single passphrase-encrypted file containing everything needed
// to rebuild the app on another machine.
//
// Credentials on disk are sealed with the OS keychain, which is bound to this
// machine and user — copying that file elsewhere yields nothing recoverable.
// So the bundle unseals them and re-encrypts the whole payload under a
// passphrase the user supplies, which travels with the file.

const KDF = { N: 32768, r: 8, p: 1, keylen: 32, maxmem: 96 * 1024 * 1024 }
const MAGIC = 'shellpilot-backup'

interface Envelope {
  magic: string
  version: 1
  kdf: 'scrypt'
  salt: string
  iv: string
  tag: string
  data: string
}

const userFile = (name: string): string => join(app.getPath('userData'), name)

function derive(password: string, salt: Buffer): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    scrypt(password, salt, KDF.keylen, { N: KDF.N, r: KDF.r, p: KDF.p, maxmem: KDF.maxmem }, (err, dk) =>
      err ? reject(err) : resolve(dk as Buffer)
    )
  })
}

function readJson(name: string): unknown | null {
  try {
    const p = userFile(name)
    if (existsSync(p)) return JSON.parse(readFileSync(p, 'utf8'))
  } catch {
    /* treat unreadable as absent rather than failing the whole backup */
  }
  return null
}

function writeJson(name: string, value: unknown): void {
  const p = userFile(name)
  const tmp = `${p}.tmp`
  writeFileSync(tmp, JSON.stringify(value), { mode: 0o600 })
  renameSync(tmp, p)
}

function summarise(payload: BackupPayload): BackupSummary {
  const data = payload.data as
    | { servers?: unknown[]; databases?: unknown[]; workspaces?: unknown[] }
    | null
  return {
    createdAt: payload.createdAt,
    app: payload.app,
    servers: data?.servers?.length ?? 0,
    databases: data?.databases?.length ?? 0,
    workspaces: data?.workspaces?.length ?? 0,
    secrets: Object.keys(payload.secrets ?? {}).length,
    hasVault: payload.vault !== null
  }
}

export const MIN_PASSPHRASE = 8

/**
 * The bytes a backup file consists of, and what is in them.
 *
 * Split out of backupExport unchanged so there is exactly one place that
 * builds a bundle: the file the save dialog writes, the object uploaded to a
 * bucket and the file a scheduled run leaves in a directory are byte-for-byte
 * the same artefact, and none of them can drift away from the others by being
 * built somewhere else.
 */
export async function buildBundle(
  password: string
): Promise<{ bytes: Buffer; summary: BackupSummary }> {
  const payload: BackupPayload = {
    version: 1,
    createdAt: new Date().toISOString(),
    app: app.getVersion(),
    data: readJson('shellpilot-data.json'),
    secrets: exportSecrets(),
    vault: readJson('shellpilot-vault.json'),
    workspaceLocks: readJson('shellpilot-wslocks.json'),
    knownHosts: readJson('shellpilot-known-hosts.json')
  }

  const salt = randomBytes(16)
  const key = await derive(password, salt)
  const iv = randomBytes(12)
  const cipher = createCipheriv('aes-256-gcm', key, iv)
  const body = Buffer.concat([cipher.update(JSON.stringify(payload), 'utf8'), cipher.final()])
  const envelope: Envelope = {
    magic: MAGIC,
    version: 1,
    kdf: 'scrypt',
    salt: salt.toString('base64'),
    iv: iv.toString('base64'),
    tag: cipher.getAuthTag().toString('base64'),
    data: body.toString('base64')
  }
  key.fill(0)
  return { bytes: Buffer.from(JSON.stringify(envelope), 'utf8'), summary: summarise(payload) }
}

export async function backupExport(password: string): Promise<BackupResult> {
  if (password.length < MIN_PASSPHRASE) {
    return { ok: false, error: 'Backup passphrase must be at least 8 characters.' }
  }

  const win = BrowserWindow.getFocusedWindow() ?? BrowserWindow.getAllWindows()[0]
  const stamp = new Date().toISOString().slice(0, 10)
  const chosen = await dialog.showSaveDialog(win, {
    title: 'Save ShellPilot backup',
    defaultPath: join(app.getPath('downloads'), `shellpilot-backup-${stamp}.spbackup`),
    filters: [{ name: 'ShellPilot backup', extensions: ['spbackup'] }]
  })
  if (chosen.canceled || !chosen.filePath) return { ok: false, cancelled: true }

  try {
    const { bytes, summary } = await buildBundle(password)
    writeFileSync(chosen.filePath, bytes, { mode: 0o600 })
    return { ok: true, path: chosen.filePath, summary }
  } catch (err) {
    return { ok: false, error: err instanceof Error ? err.message : String(err) }
  }
}

async function decryptBundle(bytes: Buffer, password: string): Promise<BackupPayload> {
  let envelope: Envelope
  try {
    envelope = JSON.parse(bytes.toString('utf8')) as Envelope
  } catch {
    // A truncated upload, a text-mode transfer that mangled the file, or an
    // object that was never ours. All three are "not a ShellPilot backup", and
    // saying so beats a JSON parser's offset.
    throw new Error('That file is not a ShellPilot backup.')
  }
  if (envelope.magic !== MAGIC) throw new Error('That file is not a ShellPilot backup.')
  const key = await derive(password, Buffer.from(envelope.salt, 'base64'))
  const decipher = createDecipheriv('aes-256-gcm', key, Buffer.from(envelope.iv, 'base64'))
  decipher.setAuthTag(Buffer.from(envelope.tag, 'base64'))
  const plain = Buffer.concat([
    decipher.update(Buffer.from(envelope.data, 'base64')),
    decipher.final()
  ])
  key.fill(0)
  return JSON.parse(plain.toString('utf8')) as BackupPayload
}

async function decryptFile(path: string, password: string): Promise<BackupPayload> {
  return decryptBundle(readFileSync(path), password)
}

// Reads a bundle and reports what it holds, without changing anything.
export async function backupInspect(password: string, path?: string): Promise<BackupResult> {
  const win = BrowserWindow.getFocusedWindow() ?? BrowserWindow.getAllWindows()[0]
  let file = path
  if (!file) {
    const chosen = await dialog.showOpenDialog(win, {
      title: 'Open ShellPilot backup',
      properties: ['openFile'],
      filters: [{ name: 'ShellPilot backup', extensions: ['spbackup'] }]
    })
    if (chosen.canceled || !chosen.filePaths[0]) return { ok: false, cancelled: true }
    file = chosen.filePaths[0]
  }
  try {
    const payload = await decryptFile(file, password)
    return { ok: true, path: file, summary: summarise(payload) }
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err)
    return {
      ok: false,
      path: file,
      error: message.includes('ShellPilot backup')
        ? message
        : 'Could not decrypt the backup — check the passphrase.'
    }
  }
}

// Replaces local state with the bundle's contents, then restarts so every
// service re-reads its files from a consistent starting point.
export async function backupImport(
  password: string,
  path: string,
  closeHistory?: () => void
): Promise<BackupResult> {
  try {
    const payload = await decryptFile(path, password)
    const summary = summarise(payload)

    if (payload.data !== null) writeJson('shellpilot-data.json', payload.data)
    if (payload.vault !== null) writeJson('shellpilot-vault.json', payload.vault)
    if (payload.workspaceLocks !== null) writeJson('shellpilot-wslocks.json', payload.workspaceLocks)
    if (payload.knownHosts !== null) writeJson('shellpilot-known-hosts.json', payload.knownHosts)

    // The bundle carries connections, credentials and vault. It does not carry
    // history, and the history already on this machine belongs to a different
    // estate: keep it and the previous estate's hostnames, units and ports sit
    // underneath the restored ones in one table with nothing marking which is
    // which, and every "first seen" answer it gives is about somebody else's
    // server. So the store is cleared, exactly as deleteAllData clears it —
    // closed first, because unlinking an open database is EBUSY on Windows.
    //
    // After the writes above, not before: a bundle that fails to decrypt must
    // leave this machine exactly as it was, and by this line the local state
    // has already been replaced.
    closeHistory?.()
    removeHistoryFiles(app.getPath('userData'))

    const sealed = importSecrets(payload.secrets ?? {})
    if (!sealed) {
      return {
        ok: false,
        error:
          'Restored settings, but this system has no available secure storage, so credentials could not be saved.'
      }
    }
    return { ok: true, path, summary }
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err)
    return {
      ok: false,
      error: message.includes('ShellPilot backup')
        ? message
        : 'Could not decrypt the backup — check the passphrase.'
    }
  }
}

export function relaunchApp(): void {
  app.relaunch()
  app.exit(0)
}

// Deliberately its own file rather than a corner of shellpilot-data.json.
//
// shellpilot-data.json is `payload.data` — it is INSIDE every bundle. A
// destination's configuration describing the bucket that receives those
// bundles would therefore ride along in each one, and the vault entry ids it
// names would point at the credentials for the very store the file is sitting
// in. Keeping it out of the payload also means a restore does not silently
// re-point this machine at somebody else's bucket.
export const TARGETS_FILE = 'shellpilot-backup-targets.json'

// Every JSON file ShellPilot writes to userData — connections, credentials,
// vault, workspace locks, trusted host keys, and the AI/MCP bridge's own
// config, sessions, access-group policy and audit log. Deliberately exhaustive:
// leaving one behind after a "delete everything" is worse than deleting one
// that never existed, which unlinkSync's own try/catch already tolerates.
//
// The history database is NOT in this list because it is not one file: it is
// the database, two journal sidecars, a .bak and any number of timestamped
// corrupt copies. history.ts owns that list — see removeHistoryFiles — because
// a second copy of those suffixes over here is exactly how the database came to
// be missing from a delete that called itself exhaustive.
const ALL_DATA_FILES = [
  'shellpilot-data.json',
  'shellpilot-secrets.json',
  'shellpilot-vault.json',
  'shellpilot-wslocks.json',
  'shellpilot-known-hosts.json',
  'shellpilot-mcp-config.json',
  'shellpilot-mcp-sessions.json',
  'shellpilot-ai-policy.json',
  'shellpilot-ai-audit.jsonl',
  // Where backups go, how often, and which vault entries unlock the
  // destinations. No credential is in it — see backupTargets.ts — but the
  // endpoints, buckets and remote paths of every place this estate's secrets
  // are stored certainly are, and a "delete everything" that leaves behind a
  // map of where the copies live has not deleted everything.
  TARGETS_FILE
]

// The renderer only calls this once a fresh backup exists (`!backupDirty`),
// so this function itself does not re-check that — it only guards against
// leaving a partially-deleted mess if one file fails to unlink.
//
// `closeHistory` is not optional in practice, only in signature: relaunchApp()
// uses app.exit(0), which does NOT emit 'before-quit', so the teardown that
// closes the store never runs on this path. The store has to be closed here or
// the unlink below hits an open handle — EBUSY on Windows — and the app
// relaunches on a database it just told the user was deleted.
export function deleteAllData(closeHistory?: () => void): BackupResult {
  try {
    closeHistory?.()
    for (const name of ALL_DATA_FILES) {
      const p = userFile(name)
      if (existsSync(p)) unlinkSync(p)
    }
    // The database holds every hostname, kernel version, systemd unit and
    // listening port in the estate, for ninety days. history.ts chmods it 0600
    // because it is sensitive; a "delete all data" that leaves it behind and
    // then goes on appending to it is that same judgement made backwards.
    removeHistoryFiles(app.getPath('userData'))
    return { ok: true }
  } catch (err) {
    return { ok: false, error: err instanceof Error ? err.message : String(err) }
  }
}

// ---------------------------------------------------------------------------
// Destinations: where a bundle goes, on a schedule, and how we know it landed
// ---------------------------------------------------------------------------


export interface BackupTargetsFile {
  version: 1
  destinations: BackupDestination[]
  /** Destination id -> epoch ms of the last ATTEMPT. See dueDestinations. */
  lastRunAt: Record<string, number>
  /** Destination id -> the last run, success or failure, for the panel. */
  lastReport: Record<string, BackupRunReport>
}

const EMPTY_TARGETS: BackupTargetsFile = {
  version: 1,
  destinations: [],
  lastRunAt: {},
  lastReport: {}
}

export function readTargets(): BackupTargetsFile {
  const raw = readJson(TARGETS_FILE) as Partial<BackupTargetsFile> | null
  if (!raw || !Array.isArray(raw.destinations)) return { ...EMPTY_TARGETS }
  return {
    version: 1,
    destinations: raw.destinations,
    lastRunAt: raw.lastRunAt ?? {},
    lastReport: raw.lastReport ?? {}
  }
}

export function writeTargets(file: BackupTargetsFile): void {
  writeJson(TARGETS_FILE, file)
}

/** Replace the configured destinations, keeping the run history of the ones
 *  that survived and dropping the history of the ones that did not. */
export function saveDestinations(destinations: BackupDestination[]): BackupTargetsFile {
  const current = readTargets()
  const live = new Set(destinations.map((d) => d.id))
  const prune = <T>(m: Record<string, T>): Record<string, T> =>
    Object.fromEntries(Object.entries(m).filter(([id]) => live.has(id)))
  const next: BackupTargetsFile = {
    version: 1,
    destinations,
    lastRunAt: prune(current.lastRunAt),
    lastReport: prune(current.lastReport)
  }
  writeTargets(next)
  return next
}

/**
 * Decrypt a bundle and look inside it.
 *
 * This is the restore test, and it is the reason this feature is not cron plus
 * rsync. Reading bytes back off a destination proves the bytes are there; it
 * does not prove they are a backup. A file can round-trip perfectly and still
 * be an envelope whose ciphertext was corrupted before it was ever written, or
 * one written under a different passphrase, or a zero-byte file that a
 * filesystem is perfectly happy to hand back.
 *
 * So this decrypts with the real passphrase, authenticates the GCM tag, parses
 * the payload and checks the payload has the shape of a backup. Anything less
 * would be a check that passes on rubbish.
 */
export async function verifyBundle(bytes: Buffer, password: string): Promise<BackupVerification> {
  try {
    const payload = await decryptBundle(bytes, password)
    if (payload.version !== 1) {
      return { ok: false, error: `Decrypted, but the bundle says version ${String(payload.version)}.`, bytes: 0 }
    }
    // `secrets` is the field a restore re-seals into the keychain. A bundle
    // whose secrets are not an object would import as nothing, and finding
    // that out during a real restore is finding it out too late.
    if (typeof payload.secrets !== 'object' || payload.secrets === null || Array.isArray(payload.secrets)) {
      return { ok: false, error: 'Decrypted, but the bundle has no credential map.', bytes: 0 }
    }
    if (typeof payload.createdAt !== 'string' || !payload.createdAt) {
      return { ok: false, error: 'Decrypted, but the bundle has no creation time.', bytes: 0 }
    }
    return { ok: true, summary: summarise(payload), bytes: bytes.length }
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err)
    return {
      ok: false,
      bytes: 0,
      error: message.includes('ShellPilot backup')
        ? message
        : `The bundle at the destination did not decrypt — ${message}`
    }
  }
}

function fail(report: BackupRunReport, stage: BackupStage, err: unknown): BackupRunReport {
  return {
    ...report,
    ok: false,
    failedStage: stage,
    error: err instanceof Error ? err.message : String(err),
    finishedAt: new Date().toISOString()
  }
}

export interface RunOptions extends TargetDeps {
  /** Fixed clock, so a test can assert the object name as a literal. */
  now?: () => Date
  /**
   * Where the bytes come from. Defaults to `buildBundle`.
   *
   * A seam, and a narrow one: the restore test only ever fires on a bundle
   * that survived the checksum, which by construction a healthy build cannot
   * produce. Without a way to hand the run a bundle that is already broken,
   * the branch that catches a corrupt archive would be the one branch in this
   * file no test ever executed — which is exactly the branch a backup feature
   * cannot afford to have never run.
   */
  bundle?: (password: string) => Promise<{ bytes: Buffer; summary: BackupSummary }>
  /** Skip the decrypt-and-inspect pass even when the destination asks for it.
   *  Only the manual "write one now" path passes this, and only when the user
   *  turned it off. */
  restoreTest?: boolean
}

/**
 * Write one generation to one destination, and report only what was proved.
 *
 * The order is: build, write, read back and compare, decrypt and inspect,
 * then retention. Every one of those is a stage that can fail the run, and
 * retention is LAST on purpose — deleting an old generation before the new one
 * has been read back and opened is deleting a backup that works in favour of
 * one that might not be there.
 */
export async function runBackupToDestination(
  dest: BackupDestination,
  password: string,
  opts: RunOptions = {}
): Promise<BackupRunReport> {
  const now = opts.now ?? ((): Date => new Date())
  const startedAt = now().toISOString()
  const base: BackupRunReport = {
    ok: false,
    destinationId: dest.id,
    destinationName: dest.name,
    destinationKind: dest.kind,
    startedAt,
    finishedAt: startedAt,
    verified: false,
    restoreTested: false,
    removed: []
  }

  if (password.length < MIN_PASSPHRASE) {
    return fail(base, 'bundle', new Error('Backup passphrase must be at least 8 characters.'))
  }

  let bundle: { bytes: Buffer; summary: BackupSummary }
  try {
    bundle = await (opts.bundle ?? buildBundle)(password)
  } catch (err) {
    return fail(base, 'bundle', err)
  }

  const name = backupObjectName(now())
  const digest = sha256(bundle.bytes)
  let report: BackupRunReport = { ...base, name, bytes: bundle.bytes.length, digest }

  let target: BackupTarget
  try {
    target = await openTarget(dest, opts)
  } catch (err) {
    return fail(report, 'write', err)
  }

  try {
    try {
      await target.put(name, bundle.bytes)
    } catch (err) {
      // A put that threw may still have left something under the name — an
      // SFTP rename that succeeded and then a connection that dropped, say.
      // Reporting "failed" while leaving a file the next list() counts as a
      // generation is the partial-success this whole feature exists to refuse.
      await discard(target, name)
      return fail(report, 'write', err)
    }

    let readBack: Buffer
    try {
      readBack = await target.get(name)
    } catch (err) {
      await discard(target, name)
      return fail(
        report,
        'verify',
        new Error(
          `Wrote ${name}, but could not read it back: ${err instanceof Error ? err.message : String(err)}. A destination that cannot be read is not a backup, so it has been removed.`
        )
      )
    }

    const readBackDigest = sha256(readBack)
    report = { ...report, readBackDigest }
    if (readBackDigest !== digest) {
      await discard(target, name)
      return fail(
        report,
        'verify',
        new Error(
          `${name} came back as ${readBack.length} bytes, not the ${bundle.bytes.length} written (checksum ${readBackDigest.slice(0, 12)} against ${digest.slice(0, 12)}). It has been removed rather than left looking like a backup.`
        )
      )
    }
    report = { ...report, verified: true }

    const wantsTest = opts.restoreTest ?? dest.restoreTest
    if (wantsTest) {
      const verification = await verifyBundle(readBack, password)
      report = { ...report, restoreTest: verification, restoreTested: verification.ok }
      if (!verification.ok) {
        await discard(target, name)
        return fail(report, 'restore-test', new Error(`${verification.error} It has been removed.`))
      }
    }

    // Retention runs against what the destination actually holds now, not
    // against a count we kept: another machine may be writing here too, and a
    // deletion decided from a stale list deletes the wrong file.
    let generations: BackupGeneration[]
    try {
      generations = await target.list()
    } catch (err) {
      return fail(report, 'retention', err)
    }
    const plan = planRetention(withNameTimes(generations), dest.keep)
    const removed: string[] = []
    for (const g of plan.remove) {
      try {
        await target.remove(g.name)
        removed.push(g.name)
      } catch (err) {
        return fail({ ...report, removed }, 'retention', err)
      }
    }

    return {
      ...report,
      ok: true,
      removed,
      retentionRefused: plan.refused,
      finishedAt: new Date().toISOString()
    }
  } finally {
    await target.close().catch(() => undefined)
  }
}

/** Remove an object we have just decided is not a backup. Best effort, and
 *  deliberately silent: the caller is already reporting a failure, and a
 *  second one about the cleanup would bury it. */
async function discard(target: BackupTarget, name: string): Promise<void> {
  try {
    await target.remove(name)
  } catch {
    /* the destination keeps a file nothing will ever list as a generation */
  }
}

/** Prefer the timestamp in the name over the destination's own clock. An S3
 *  LastModified is when the bucket accepted the PUT and an SFTP mtime is the
 *  remote clock; the name is ours. */
export function withNameTimes(generations: BackupGeneration[]): BackupGeneration[] {
  return generations.map((g) => {
    const encoded = backupObjectTime(g.name)
    return encoded === null ? g : { ...g, modified: encoded }
  })
}

// ---------------------------------------------------------------------------
// Restore from a destination
// ---------------------------------------------------------------------------

export interface RemoteListResult {
  ok: boolean
  error?: string
  generations?: BackupGeneration[]
}

/** What is actually at a destination right now, newest first. Only our own
 *  names: someone else's files in that directory are not offered as things to
 *  restore from. */
export async function listRemoteBackups(
  dest: BackupDestination,
  deps: TargetDeps = {}
): Promise<RemoteListResult> {
  let target: BackupTarget
  try {
    target = await openTarget(dest, deps)
  } catch (err) {
    return { ok: false, error: err instanceof Error ? err.message : String(err) }
  }
  try {
    const all = withNameTimes(await target.list())
    const ours = all
      .filter((g) => backupObjectTime(g.name) !== null)
      .sort((a, b) => b.modified - a.modified)
    return { ok: true, generations: ours }
  } catch (err) {
    return { ok: false, error: err instanceof Error ? err.message : String(err) }
  } finally {
    await target.close().catch(() => undefined)
  }
}

/** Where a downloaded generation is staged before it is inspected. Inside
 *  userData rather than the OS temp directory: this file is the vault, and a
 *  world-readable /tmp is where it should least be. */
function stagingPath(name: string): string {
  return userFile(`staged-${name.replace(/[^A-Za-z0-9._-]/g, '_')}`)
}

/**
 * Download one generation and report what is inside it, changing nothing.
 *
 * The inspect-before-import discipline is the same one the local path already
 * has, and it matters MORE from a remote: the file came off a machine this one
 * does not control, so "what does it say it is" has to be answered before
 * anything is replaced. The download is staged to disk so `backupImport` runs
 * on exactly the bytes that were inspected — not on a second download that
 * could differ.
 */
export async function inspectRemoteBackup(
  dest: BackupDestination,
  name: string,
  password: string,
  deps: TargetDeps = {}
): Promise<BackupResult> {
  if (backupObjectTime(name) === null) {
    return { ok: false, error: `“${name}” is not a ShellPilot backup name.` }
  }
  let target: BackupTarget
  try {
    target = await openTarget(dest, deps)
  } catch (err) {
    return { ok: false, error: err instanceof Error ? err.message : String(err) }
  }
  try {
    const bytes = await target.get(name)
    const verification = await verifyBundle(bytes, password)
    if (!verification.ok || !verification.summary) {
      return { ok: false, error: verification.error ?? 'The bundle did not open.' }
    }
    const staged = stagingPath(name)
    writeFileSync(staged, bytes, { mode: 0o600 })
    return { ok: true, path: staged, summary: verification.summary }
  } catch (err) {
    return { ok: false, error: err instanceof Error ? err.message : String(err) }
  } finally {
    await target.close().catch(() => undefined)
  }
}

/** Delete a staged download. Called when the user cancels rather than
 *  restores, so a copy of the vault is not left lying in userData. */
export function discardStagedBackup(path: string): void {
  try {
    if (path.startsWith(join(app.getPath('userData'), 'staged-')) && existsSync(path)) unlinkSync(path)
  } catch {
    /* a file we could not remove is reported nowhere useful; it is inert */
  }
}

// ---------------------------------------------------------------------------
// Database dumps as a source
// ---------------------------------------------------------------------------

/**
 * The largest dump this will hold.
 *
 * A dump is verified the same way a bundle is — read back off the destination
 * and compared — which means both copies are in memory at once. Rather than
 * discover that at 4 GB by dying, this refuses at a stated limit and says so.
 * Raising it is a decision about memory, and it should look like one.
 */
export const MAX_DUMP_BYTES = 512 * 1024 * 1024

export interface DumpRunReport {
  ok: boolean
  destinationId: string
  destinationName: string
  name?: string
  bytes?: number
  digest?: string
  verified: boolean
  error?: string
  failedStage?: BackupStage
  startedAt: string
  finishedAt: string
}

export interface SpawnedDump {
  /** Everything the dump wrote to stdout. */
  stdout: Buffer
  /** The tail of stderr, for a message worth reading. */
  stderr: string
  code: number | null
  signal: string | null
}

export type DumpSpawner = (cmd: DumpCommand) => Promise<SpawnedDump>

/** The default spawner: run the dump binary on this machine. Separated so a
 *  test drives the real streaming, size-limit and verification logic without
 *  needing pg_dump installed. */
export const spawnDump: DumpSpawner = (cmd) =>
  new Promise((resolve, reject) => {
    const child = spawn(cmd.binary, cmd.args, {
      env: { ...process.env, ...cmd.env },
      stdio: ['ignore', 'pipe', 'pipe']
    })
    const out: Buffer[] = []
    let size = 0
    let err = ''
    let overflowed = false
    child.stdout.on('data', (c: Buffer) => {
      size += c.length
      if (size > MAX_DUMP_BYTES) {
        if (!overflowed) {
          overflowed = true
          child.kill('SIGTERM')
        }
        return
      }
      out.push(c)
    })
    child.stderr.on('data', (c: Buffer) => {
      err = (err + c.toString('utf8')).slice(-4000)
    })
    child.on('error', reject)
    child.on('close', (code, signal) => {
      if (overflowed) {
        reject(
          new Error(
            `The dump passed ${Math.round(MAX_DUMP_BYTES / (1024 * 1024))} MB, which is the most this can hold in memory while checking what it wrote. Nothing was uploaded.`
          )
        )
        return
      }
      resolve({ stdout: Buffer.concat(out), stderr: err.trim(), code, signal })
    })
  })

/**
 * Run pg_dump/mysqldump and put the result at a destination, verified.
 *
 * The dump is NOT encrypted by this — it is plaintext SQL, it is named .sql,
 * and it is not a `.spbackup`, so retention never counts it as a generation of
 * one. That is stated rather than assumed: a caller that thought this produced
 * an encrypted bundle would be putting a database in a bucket in the clear.
 */
export async function dumpToDestination(
  dest: BackupDestination,
  target: DumpTarget,
  password: string,
  opts: RunOptions & { spawn?: DumpSpawner } = {}
): Promise<DumpRunReport> {
  const now = opts.now ?? ((): Date => new Date())
  const startedAt = now().toISOString()
  const base: DumpRunReport = {
    ok: false,
    destinationId: dest.id,
    destinationName: dest.name,
    verified: false,
    startedAt,
    finishedAt: startedAt
  }
  const stop = (stage: BackupStage, err: unknown): DumpRunReport => ({
    ...base,
    failedStage: stage,
    error: err instanceof Error ? err.message : String(err),
    finishedAt: new Date().toISOString()
  })

  let dumped: SpawnedDump
  try {
    dumped = await (opts.spawn ?? spawnDump)(dumpCommand(target, password))
  } catch (err) {
    return stop('bundle', err)
  }
  if (dumped.code !== 0) {
    return stop(
      'bundle',
      new Error(
        `${DUMP_BINARY[target.engine]} exited ${dumped.signal ? `on ${dumped.signal}` : String(dumped.code)}${dumped.stderr ? `: ${dumped.stderr.split('\n').slice(-3).join(' ')}` : ''}`
      )
    )
  }
  // A dump binary that exits 0 having written nothing is the failure this
  // codebase already shipped once, in another shape: a zero-length file that a
  // reader accepts as valid and empty. An empty dump is never a correct dump.
  if (dumped.stdout.length === 0) {
    return stop('bundle', new Error(`${DUMP_BINARY[target.engine]} exited cleanly but produced no output.`))
  }

  const name = dumpObjectName(target, now())
  const digest = sha256(dumped.stdout)
  let driver: BackupTarget
  try {
    driver = await openTarget(dest, opts)
  } catch (err) {
    return stop('write', err)
  }
  try {
    try {
      await driver.put(name, dumped.stdout)
    } catch (err) {
      await discard(driver, name)
      return { ...stop('write', err), name, bytes: dumped.stdout.length, digest }
    }
    const readBack = await driver.get(name).catch((err: unknown) => err as Error)
    if (readBack instanceof Error || !Buffer.isBuffer(readBack)) {
      await discard(driver, name)
      return {
        ...stop('verify', new Error(`Wrote ${name} but could not read it back: ${String(readBack)}`)),
        name,
        bytes: dumped.stdout.length,
        digest
      }
    }
    if (sha256(readBack) !== digest) {
      await discard(driver, name)
      return {
        ...stop(
          'verify',
          new Error(
            `${name} came back as ${readBack.length} bytes, not the ${dumped.stdout.length} written. It has been removed.`
          )
        ),
        name,
        bytes: dumped.stdout.length,
        digest
      }
    }
    return {
      ...base,
      ok: true,
      name,
      bytes: dumped.stdout.length,
      digest,
      verified: true,
      finishedAt: new Date().toISOString()
    }
  } finally {
    await driver.close().catch(() => undefined)
  }
}

// ---------------------------------------------------------------------------
// Scheduling
// ---------------------------------------------------------------------------

/**
 * The passphrase a scheduled run encrypts with, out of the vault.
 *
 * Every failure here is a REASON, not a false. A scheduled backup that stops
 * happening and says nothing is the exact failure mode this whole item is
 * written against — the operator stops thinking about it, and finds out when
 * they need the file.
 */
export function scheduledPassphrase(dest: BackupDestination): { password?: string; skipped?: string } {
  if (!dest.passphraseVaultEntryId) {
    return { skipped: 'No vault entry is set to hold the passphrase for unattended runs.' }
  }
  const status = vaultStatus()
  if (!status.exists) return { skipped: 'The passphrase lives in the vault, and there is no vault on this machine.' }
  if (!status.unlocked) return { skipped: 'The passphrase lives in the vault, and the vault is locked.' }
  const entry = vaultList().entries?.find((e) => e.id === dest.passphraseVaultEntryId)
  if (!entry) return { skipped: 'The vault entry holding the passphrase no longer exists.' }
  if (!entry.password) return { skipped: `Vault entry “${entry.name}” has no secret to use as a passphrase.` }
  if (entry.password.length < MIN_PASSPHRASE) {
    return { skipped: `Vault entry “${entry.name}” holds a passphrase shorter than ${MIN_PASSPHRASE} characters.` }
  }
  return { password: entry.password }
}

export interface TickResult {
  ran: BackupRunReport[]
  /** Destination id -> why it did not run. Never empty-and-silent. */
  skipped: Record<string, string>
}

/**
 * One pass of the schedule.
 *
 * Exported and pure of timers so it can be driven directly by a test with a
 * fixed `now` — the alternative is a test that sleeps, which is a test that
 * gets flakier as the machine gets busier.
 */
export async function backupTick(now = Date.now(), opts: RunOptions = {}): Promise<TickResult> {
  const file = readTargets()
  const due = dueDestinations(file.destinations, file.lastRunAt, now)
  const result: TickResult = { ran: [], skipped: {} }
  for (const dest of due) {
    const { password, skipped } = scheduledPassphrase(dest)
    if (!password) {
      result.skipped[dest.id] = skipped ?? 'No passphrase available.'
      // NOT marked as attempted: a locked vault is a condition that clears on
      // its own, and pushing the next attempt a full period into the future
      // because the user happened to be locked at the tick would turn an
      // hourly backup into a daily one.
      continue
    }
    const report = await runBackupToDestination(dest, password, opts)
    result.ran.push(report)
    const current = readTargets()
    writeTargets({
      ...current,
      lastRunAt: { ...current.lastRunAt, [dest.id]: now },
      lastReport: { ...current.lastReport, [dest.id]: report }
    })
  }
  return result
}

let scheduleTimer: ReturnType<typeof setInterval> | null = null

/** How often the schedule is examined. Not how often a backup runs — that is
 *  each destination's `everyHours`. A five-minute tick means a destination set
 *  to six hours runs within five minutes of being due. */
export const TICK_MS = 5 * 60 * 1000

export function startBackupSchedule(onRun?: (line: string) => void): void {
  if (scheduleTimer) return
  scheduleTimer = setInterval(() => {
    void backupTick()
      .then(({ ran }) => {
        for (const r of ran) onRun?.(describeRun(r))
      })
      .catch((err: unknown) => {
        console.error('[backup] scheduled run failed:', err)
      })
  }, TICK_MS)
  // Never hold the process open for a backup that is not due.
  scheduleTimer.unref?.()
}

export function stopBackupSchedule(): void {
  if (scheduleTimer) clearInterval(scheduleTimer)
  scheduleTimer = null
}
