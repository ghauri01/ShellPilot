import type { WebContents } from 'electron'
import { basename } from 'node:path'
import { statSync } from 'node:fs'
import type { Client, SFTPWrapper, FileEntry } from 'ssh2'
import { acquire, release, type PooledConnection } from './ssh'
import type {
  SftpEntry,
  SftpResult,
  SftpUploadSummary,
  SshConnectConfig
} from '../../shared/ssh'

interface Conn {
  conn: PooledConnection
  sftp: SFTPWrapper
}

// One cached SFTP connection per server id. Opened lazily on first operation.
const conns = new Map<string, Conn>()

function openSftp(client: Client): Promise<SFTPWrapper> {
  return new Promise((resolve, reject) => {
    client.sftp((err, sftp) => (err ? reject(err) : resolve(sftp)))
  })
}

async function ensure(key: string, cfg: SshConnectConfig): Promise<SFTPWrapper> {
  const existing = conns.get(key)
  if (existing) return existing.sftp
  // Shares the terminal's authenticated connection, so browsing files never
  // triggers a second login.
  const conn = await acquire(cfg)
  const client = conn.client
  const sftp = await openSftp(client)
  client.on('close', () => conns.delete(key))
  conns.set(key, { conn, sftp })
  return sftp
}

function permString(entry: FileEntry): string {
  // longname looks like: -rw-r--r--   1 user group   1234 May  8 12:00 name
  const first = entry.longname?.split(/\s+/)[0]
  if (first && first.length >= 10) return first
  const m = entry.attrs.mode & 0o777
  return m.toString(8).padStart(4, '0')
}

function mapEntry(e: FileEntry): SftpEntry {
  const mode = e.attrs.mode
  const isDir = (mode & 0o170000) === 0o040000
  const isLink = (mode & 0o170000) === 0o120000
  return {
    name: e.filename,
    dir: isDir,
    link: isLink,
    size: e.attrs.size,
    mtime: e.attrs.mtime * 1000,
    perms: permString(e)
  }
}

export async function sftpConnect(key: string, cfg: SshConnectConfig): Promise<SftpResult<{ home: string }>> {
  try {
    const sftp = await ensure(key, cfg)
    const home = await new Promise<string>((resolve) => {
      sftp.realpath('.', (err, abs) => resolve(err ? '/' : abs))
    })
    return { ok: true, data: { home } }
  } catch (err) {
    return { ok: false, error: msg(err) }
  }
}

export async function sftpList(key: string, path: string): Promise<SftpResult<SftpEntry[]>> {
  const conn = conns.get(key)
  if (!conn) return { ok: false, error: 'not connected' }
  return new Promise((resolve) => {
    conn.sftp.readdir(path, (err, list) => {
      if (err) return resolve({ ok: false, error: err.message })
      const entries = list
        .map(mapEntry)
        .filter((e) => e.name !== '.' && e.name !== '..')
        .sort((a, b) => (a.dir === b.dir ? a.name.localeCompare(b.name) : a.dir ? -1 : 1))
      resolve({ ok: true, data: entries })
    })
  })
}

export async function sftpRead(key: string, path: string): Promise<SftpResult<string>> {
  const conn = conns.get(key)
  if (!conn) return { ok: false, error: 'not connected' }
  return new Promise((resolve) => {
    const chunks: Buffer[] = []
    const stream = conn.sftp.createReadStream(path)
    stream.on('data', (c: Buffer) => chunks.push(c))
    stream.on('error', (e: Error) => resolve({ ok: false, error: e.message }))
    stream.on('end', () => resolve({ ok: true, data: Buffer.concat(chunks).toString('utf8') }))
  })
}

export async function sftpWrite(key: string, path: string, content: string): Promise<SftpResult> {
  const conn = conns.get(key)
  if (!conn) return { ok: false, error: 'not connected' }
  return new Promise((resolve) => {
    conn.sftp.writeFile(path, content, (err) =>
      resolve(err ? { ok: false, error: err.message } : { ok: true })
    )
  })
}

function remoteJoin(dir: string, name: string): string {
  return dir.endsWith('/') ? `${dir}${name}` : `${dir}/${name}`
}

// fastPut streams the file in parallel chunks rather than buffering it in
// memory, so uploading a multi-GB archive is fine.
function putFile(
  sftp: SFTPWrapper,
  local: string,
  remote: string,
  onStep: (transferred: number, total: number) => void
): Promise<void> {
  return new Promise((resolve, reject) => {
    let reported = 0
    sftp.fastPut(
      local,
      remote,
      {
        // step fires per chunk; throttled to 512 KiB so a large file does not
        // flood the renderer with IPC messages.
        step: (transferred: number, _chunk: number, total: number) => {
          if (transferred === total || transferred - reported >= 512 * 1024) {
            reported = transferred
            onStep(transferred, total)
          }
        }
      },
      (err) => (err ? reject(err) : resolve())
    )
  })
}

// Uploads local files into a remote directory, one at a time so progress is
// meaningful and a failure part-way through still reports what did land.
export async function sftpUpload(
  wc: WebContents,
  key: string,
  localPaths: string[],
  remoteDir: string
): Promise<SftpResult<SftpUploadSummary>> {
  const conn = conns.get(key)
  if (!conn) return { ok: false, error: 'not connected' }

  const uploaded: string[] = []
  const failed: { name: string; error: string }[] = []

  for (let i = 0; i < localPaths.length; i++) {
    const local = localPaths[i]
    const name = basename(local)
    const send = (transferred: number, total: number): void => {
      if (!wc.isDestroyed()) {
        wc.send('sftp:progress', {
          key,
          name,
          transferred,
          total,
          index: i + 1,
          count: localPaths.length
        })
      }
    }
    try {
      // Directories would need a recursive walk; refuse them explicitly rather
      // than failing later with an opaque EISDIR.
      if (statSync(local).isDirectory()) throw new Error('folders cannot be uploaded yet')
      send(0, statSync(local).size)
      await putFile(conn.sftp, local, remoteJoin(remoteDir, name), send)
      uploaded.push(name)
    } catch (err) {
      failed.push({ name, error: msg(err) })
    }
  }

  return {
    ok: failed.length === 0,
    error: failed.length ? `${failed[0].name}: ${failed[0].error}` : undefined,
    data: { uploaded, failed }
  }
}

export async function sftpMkdir(key: string, path: string): Promise<SftpResult> {
  return op(key, (sftp, done) => sftp.mkdir(path, done))
}

export async function sftpRename(key: string, from: string, to: string): Promise<SftpResult> {
  return op(key, (sftp, done) => sftp.rename(from, to, done))
}

export async function sftpDelete(key: string, path: string, dir: boolean): Promise<SftpResult> {
  return op(key, (sftp, done) => (dir ? sftp.rmdir(path, done) : sftp.unlink(path, done)))
}

export function sftpDisconnect(key: string): void {
  const conn = conns.get(key)
  if (!conn) return
  {
    try {
      release(conn.conn)
    } catch {
      /* ignore */
    }
  }
  conns.delete(key)
}

export function sftpDisposeAll(): void {
  for (const k of [...conns.keys()]) sftpDisconnect(k)
}

function op(key: string, run: (sftp: SFTPWrapper, done: (err?: Error | null) => void) => void): Promise<SftpResult> {
  const conn = conns.get(key)
  if (!conn) return Promise.resolve({ ok: false, error: 'not connected' })
  return new Promise((resolve) => {
    run(conn.sftp, (err) => resolve(err ? { ok: false, error: err.message } : { ok: true }))
  })
}

function msg(err: unknown): string {
  return err instanceof Error ? err.message : String(err)
}
