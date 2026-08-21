import { app, dialog, BrowserWindow } from 'electron'
import { join } from 'node:path'
import { existsSync, readFileSync, writeFileSync, renameSync } from 'node:fs'
import { randomBytes, scrypt, createCipheriv, createDecipheriv } from 'node:crypto'
import { exportSecrets, importSecrets } from './secrets'
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
export async function backupImport(password: string, path: string): Promise<BackupResult> {
  try {
    const payload = await decryptFile(path, password)
    const summary = summarise(payload)

    if (payload.data !== null) writeJson('shellpilot-data.json', payload.data)
    if (payload.vault !== null) writeJson('shellpilot-vault.json', payload.vault)
    if (payload.workspaceLocks !== null) writeJson('shellpilot-wslocks.json', payload.workspaceLocks)
    if (payload.knownHosts !== null) writeJson('shellpilot-known-hosts.json', payload.knownHosts)

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
