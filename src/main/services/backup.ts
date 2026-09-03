import { app, dialog, BrowserWindow } from 'electron'
import { join } from 'node:path'
import { existsSync, readFileSync, writeFileSync, renameSync, unlinkSync } from 'node:fs'
import { randomBytes, scrypt, createCipheriv, createDecipheriv } from 'node:crypto'
import { exportSecrets, importSecrets } from './secrets'
import { removeHistoryFiles } from './history'
import type { BackupPayload, BackupResult, BackupSummary } from '../../shared/backup'

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

export async function backupExport(password: string): Promise<BackupResult> {
  if (password.length < 8) {
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
    writeFileSync(chosen.filePath, JSON.stringify(envelope), { mode: 0o600 })
    key.fill(0)
    return { ok: true, path: chosen.filePath, summary: summarise(payload) }
  } catch (err) {
    return { ok: false, error: err instanceof Error ? err.message : String(err) }
  }
}

async function decryptFile(path: string, password: string): Promise<BackupPayload> {
  const envelope = JSON.parse(readFileSync(path, 'utf8')) as Envelope
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
  'shellpilot-ai-audit.jsonl'
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
