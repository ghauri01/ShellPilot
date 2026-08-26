import { app } from 'electron'
import { join } from 'node:path'
import { existsSync, readFileSync, writeFileSync, renameSync, unlinkSync } from 'node:fs'
import { randomBytes, scrypt, createCipheriv, createDecipheriv } from 'node:crypto'
import type { VaultEntry, VaultListResult, VaultResult, VaultStatus } from '../../shared/vault'

// The vault is encrypted with AES-256-GCM under a key derived from the user's
// master password via scrypt. The password is never stored — a wrong password
// simply fails the GCM authentication tag on decrypt.
//
// The KEY exists only in main-process memory while the vault is unlocked. The
// decrypted ENTRIES do not: vault:list ships them to the renderer, where they
// live in the Zustand store for as long as the vault is open. That is a
// deliberate consequence of showing them in a UI, but it means renderer-side
// script injection reaches vault plaintext, and the threat model has to say so
// rather than claim main-process confinement it does not have.

const FILE = join(app.getPath('userData'), 'shellpilot-vault.json')
const TMP = `${FILE}.tmp`

// 128 * N * r = 32 MiB of work per derivation; maxmem must exceed that.
const KDF = { N: 32768, r: 8, p: 1, keylen: 32, maxmem: 96 * 1024 * 1024 }

interface VaultFile {
  version: 1
  salt: string
  iv: string
  tag: string
  data: string
}

let key: Buffer | null = null
let salt: Buffer | null = null
let cache: VaultEntry[] | null = null

function derive(password: string, s: Buffer): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    scrypt(password, s, KDF.keylen, { N: KDF.N, r: KDF.r, p: KDF.p, maxmem: KDF.maxmem }, (err, dk) =>
      err ? reject(err) : resolve(dk as Buffer)
    )
  })
}

function readFile(): VaultFile | null {
  try {
    if (!existsSync(FILE)) return null
    return JSON.parse(readFileSync(FILE, 'utf8')) as VaultFile
  } catch {
    return null
  }
}

// Write through a temp file so a crash mid-write cannot truncate the vault.
function writeEncrypted(entries: VaultEntry[], k: Buffer, s: Buffer): void {
  const iv = randomBytes(12)
  const cipher = createCipheriv('aes-256-gcm', k, iv)
  const data = Buffer.concat([cipher.update(JSON.stringify(entries), 'utf8'), cipher.final()])
  const file: VaultFile = {
    version: 1,
    salt: s.toString('base64'),
    iv: iv.toString('base64'),
    tag: cipher.getAuthTag().toString('base64'),
    data: data.toString('base64')
  }
  writeFileSync(TMP, JSON.stringify(file), { mode: 0o600 })
  renameSync(TMP, FILE)
}

function decrypt(file: VaultFile, k: Buffer): VaultEntry[] {
  const decipher = createDecipheriv('aes-256-gcm', k, Buffer.from(file.iv, 'base64'))
  decipher.setAuthTag(Buffer.from(file.tag, 'base64'))
  const out = Buffer.concat([decipher.update(Buffer.from(file.data, 'base64')), decipher.final()])
  return JSON.parse(out.toString('utf8')) as VaultEntry[]
}

export function vaultStatus(): VaultStatus {
  return { exists: existsSync(FILE), unlocked: key !== null, entryCount: cache?.length ?? 0 }
}

export async function vaultCreate(password: string): Promise<VaultResult> {
  if (existsSync(FILE)) return { ok: false, error: 'A vault already exists on this machine.' }
  if (password.length < 8) return { ok: false, error: 'Master password must be at least 8 characters.' }
  try {
    const s = randomBytes(16)
    const k = await derive(password, s)
    writeEncrypted([], k, s)
    key = k
    salt = s
    cache = []
    return { ok: true }
  } catch (err) {
    return { ok: false, error: err instanceof Error ? err.message : String(err) }
  }
}

export async function vaultUnlock(password: string): Promise<VaultResult> {
  const file = readFile()
  if (!file) return { ok: false, error: 'No vault has been created yet.' }
  try {
    const s = Buffer.from(file.salt, 'base64')
    const k = await derive(password, s)
    cache = decrypt(file, k) // throws if the password is wrong
    key = k
    salt = s
    return { ok: true }
  } catch {
    key = null
    salt = null
    cache = null
    return { ok: false, error: 'Incorrect master password.' }
  }
}

// The derived key, for biometric unlock to hold on the user's behalf. Only
// ever readable while the vault is already unlocked — this cannot be used to
// obtain a key the caller did not already have — and never leaves the main
// process. Returned as a copy so a caller cannot zero the live key.
export function vaultExportKey(): { key: Buffer; salt: Buffer } | null {
  if (!key || !salt) return null
  return { key: Buffer.from(key), salt: Buffer.from(salt) }
}

// Unlock with a previously derived key instead of a password. The GCM tag is
// still what decides: a key that does not decrypt the file fails exactly as a
// wrong password does, so a corrupted or stale stored key cannot half-open a
// vault.
export function vaultUnlockWithKey(k: Buffer, s: Buffer): VaultResult {
  const file = readFile()
  if (!file) return { ok: false, error: 'No vault exists yet.' }
  try {
    const entries = decrypt(file, k)
    key = Buffer.from(k)
    salt = Buffer.from(s)
    cache = entries
    return { ok: true }
  } catch {
    return { ok: false, error: 'The stored key no longer opens this vault.' }
  }
}

export function vaultLock(): VaultResult {
  key?.fill(0)
  key = null
  salt = null
  cache = null
  return { ok: true }
}

export function vaultList(): VaultListResult {
  if (!key || !cache) return { ok: false, error: 'Vault is locked.' }
  return { ok: true, entries: cache }
}

export function vaultSave(entries: VaultEntry[]): VaultResult {
  if (!key || !salt) return { ok: false, error: 'Vault is locked.' }
  try {
    writeEncrypted(entries, key, salt)
    cache = entries
    return { ok: true }
  } catch (err) {
    return { ok: false, error: err instanceof Error ? err.message : String(err) }
  }
}

export async function vaultChangePassword(current: string, next: string): Promise<VaultResult> {
  if (next.length < 8) return { ok: false, error: 'Master password must be at least 8 characters.' }
  const file = readFile()
  if (!file) return { ok: false, error: 'No vault has been created yet.' }
  try {
    const entries = decrypt(file, await derive(current, Buffer.from(file.salt, 'base64')))
    const s = randomBytes(16)
    const k = await derive(next, s)
    writeEncrypted(entries, k, s)
    key?.fill(0)
    key = k
    salt = s
    cache = entries
    return { ok: true }
  } catch {
    return { ok: false, error: 'Incorrect current password.' }
  }
}

// Destroys the vault file. Only reachable from the UI behind an explicit
// confirmation, for when the master password is lost.
export function vaultDestroy(): VaultResult {
  try {
    vaultLock()
    if (existsSync(FILE)) unlinkSync(FILE)
    return { ok: true }
  } catch (err) {
    return { ok: false, error: err instanceof Error ? err.message : String(err) }
  }
}

export function vaultDispose(): void {
  vaultLock()
}
