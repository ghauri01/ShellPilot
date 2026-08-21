import { app } from 'electron'
import { join } from 'node:path'
import { existsSync, readFileSync, writeFileSync, renameSync } from 'node:fs'
import { randomBytes, scrypt, timingSafeEqual } from 'node:crypto'

// Per-workspace passwords. Only a scrypt verifier is stored — never the
// password itself, and never anything reversible.
//
// NOTE: this gates access to a workspace in the UI. It does not encrypt the
// workspace's servers/databases on disk; those still live in the normal data
// file. Use the Vault for secrets that must be encrypted at rest.

const FILE = join(app.getPath('userData'), 'shellpilot-wslocks.json')
const TMP = `${FILE}.tmp`
const KDF = { N: 32768, r: 8, p: 1, keylen: 32, maxmem: 96 * 1024 * 1024 }

interface Lock {
  salt: string
  hash: string
}
type LockMap = Record<string, Lock>

function derive(password: string, salt: Buffer): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    scrypt(password, salt, KDF.keylen, { N: KDF.N, r: KDF.r, p: KDF.p, maxmem: KDF.maxmem }, (err, dk) =>
      err ? reject(err) : resolve(dk as Buffer)
    )
  })
}

function read(): LockMap {
  try {
    if (existsSync(FILE)) return JSON.parse(readFileSync(FILE, 'utf8')) as LockMap
  } catch {
    /* ignore corrupt file */
  }
  return {}
}

function write(map: LockMap): void {
  writeFileSync(TMP, JSON.stringify(map), { mode: 0o600 })
  renameSync(TMP, FILE)
}

export function wsLockIds(): string[] {
  return Object.keys(read())
}

export async function wsLockVerify(id: string, password: string): Promise<boolean> {
  const lock = read()[id]
  if (!lock) return true // no password set — nothing to check
  try {
    const got = await derive(password, Buffer.from(lock.salt, 'base64'))
    const want = Buffer.from(lock.hash, 'base64')
    return got.length === want.length && timingSafeEqual(got, want)
  } catch {
    return false
  }
}

export async function wsLockSet(
  id: string,
  password: string,
  current?: string
): Promise<{ ok: boolean; error?: string }> {
  if (password.length < 6) return { ok: false, error: 'Password must be at least 6 characters.' }
  const map = read()
  if (map[id] && !(await wsLockVerify(id, current ?? ''))) {
    return { ok: false, error: 'Current password is incorrect.' }
  }
  try {
    const salt = randomBytes(16)
    const hash = await derive(password, salt)
    map[id] = { salt: salt.toString('base64'), hash: hash.toString('base64') }
    write(map)
    return { ok: true }
  } catch (err) {
    return { ok: false, error: err instanceof Error ? err.message : String(err) }
  }
}

export async function wsLockRemove(
  id: string,
  current: string
): Promise<{ ok: boolean; error?: string }> {
  const map = read()
  if (!map[id]) return { ok: true }
  if (!(await wsLockVerify(id, current))) return { ok: false, error: 'Password is incorrect.' }
  delete map[id]
  write(map)
  return { ok: true }
}

// Called when a workspace is deleted so no orphan verifier is left behind.
export function wsLockDelete(id: string): void {
  const map = read()
  if (!map[id]) return
  delete map[id]
  write(map)
}
