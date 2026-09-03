import { createHash, createHmac } from 'node:crypto'
import { readFile, writeFile, readdir, stat, unlink, rename, mkdir } from 'node:fs/promises'
import { join } from 'node:path'
import type { SFTPWrapper } from 'ssh2'
import { acquire, release, type PooledConnection } from './ssh'
import { resolveChainSecrets } from './credentialResolver'
import { vaultList, vaultStatus } from './vault'
import { loadData } from './store'
import type {
  BackupDestination,
  BackupGeneration,
  LocalBackupDestination,
  S3BackupDestination,
  SftpBackupDestination
} from '../../shared/backup'
import type { SshAuth, SshHop } from '../../shared/ssh'
import type { VaultEntry } from '../../shared/vault'

// Where a backup lands, expressed as the four operations retention and
// restore-from-remote need: put it, read it back, list what is there, remove
// one. Nothing streams: a bundle is the app's settings, credentials and vault,
// which is kilobytes, and the whole point of this module is that every write
// is read back and compared, which needs the bytes anyway.
//
// A database dump is the exception and does not come through here — see
// dumpToDestination in backup.ts.
export interface BackupTarget {
  /**
   * Write `data` so that it is either fully there under `name` or not there at
   * all.
   *
   * Every driver that can do it writes to a scratch name and renames. This is
   * the same rule the history store's launch-time backup had to learn: it
   * wrote straight onto the file it was protecting, so a failure left a
   * zero-byte file, and SQLite reads a zero-length file as a valid empty
   * database — the recovery ladder restored it and reported success with
   * everything gone. A half-written bundle under a real generation name is
   * that bug with a different file extension.
   */
  put(name: string, data: Buffer): Promise<void>
  get(name: string): Promise<Buffer>
  list(): Promise<BackupGeneration[]>
  remove(name: string): Promise<void>
  /** Release any connection this driver opened. Always called. */
  close(): Promise<void>
}

export function sha256(data: Buffer): string {
  return createHash('sha256').update(data).digest('hex')
}

const PART_SUFFIX = '.part'

/** Names a driver's `list` must never report: our own scratch files, which are
 *  by definition incomplete. */
export function isScratchName(name: string): boolean {
  return name.endsWith(PART_SUFFIX)
}

// ---------------------------------------------------------------------------
// Local directory
// ---------------------------------------------------------------------------

export function localTarget(dest: LocalBackupDestination): BackupTarget {
  const dir = dest.directory
  return {
    async put(name, data) {
      await mkdir(dir, { recursive: true })
      const tmp = join(dir, `${name}${PART_SUFFIX}`)
      await writeFile(tmp, data, { mode: 0o600 })
      await rename(tmp, join(dir, name))
    },
    async get(name) {
      return readFile(join(dir, name))
    },
    async list() {
      const names = await readdir(dir)
      const out: BackupGeneration[] = []
      for (const name of names) {
        if (isScratchName(name)) continue
        try {
          const s = await stat(join(dir, name))
          if (s.isDirectory()) continue
          out.push({ name, size: s.size, modified: s.mtimeMs })
        } catch {
          /* vanished between readdir and stat: not a generation we can keep */
        }
      }
      return out
    },
    async remove(name) {
      await unlink(join(dir, name))
    },
    async close() {
      /* nothing held open */
    }
  }
}

// ---------------------------------------------------------------------------
// SFTP
// ---------------------------------------------------------------------------

/**
 * The remote filesystem, as the four-and-a-bit calls this module makes of it.
 *
 * An interface rather than an ssh2 `SFTPWrapper` directly so the tests can run
 * the real driver — the same put/verify/rename/retention logic, not a
 * reimplementation of it — against a real directory through a real async
 * callback boundary. A test that mocked the driver would only prove the mock
 * agrees with the driver.
 */
export interface SftpIo {
  readFile(path: string): Promise<Buffer>
  writeFile(path: string, data: Buffer): Promise<void>
  readdir(path: string): Promise<{ name: string; size: number; modified: number }[]>
  unlink(path: string): Promise<void>
  rename(from: string, to: string): Promise<void>
  close(): Promise<void>
}

export function remoteJoin(dir: string, name: string): string {
  if (!dir || dir === '.') return name
  return dir.endsWith('/') ? `${dir}${name}` : `${dir}/${name}`
}

export function sftpTargetFrom(dest: SftpBackupDestination, io: SftpIo): BackupTarget {
  const dir = dest.directory
  return {
    async put(name, data) {
      const tmp = remoteJoin(dir, `${name}${PART_SUFFIX}`)
      const final = remoteJoin(dir, name)
      await io.writeFile(tmp, data)
      try {
        await io.rename(tmp, final)
      } catch (err) {
        // A rename that fails leaves the scratch file behind. Nothing lists it
        // as a generation, but leaving it there means the next run's rename
        // fails on an existing name — clear it and report the original fault.
        try {
          await io.unlink(tmp)
        } catch {
          /* best effort */
        }
        throw err
      }
    },
    get: (name) => io.readFile(remoteJoin(dir, name)),
    async list() {
      const entries = await io.readdir(dir)
      return entries.filter((e) => !isScratchName(e.name))
    },
    remove: (name) => io.unlink(remoteJoin(dir, name)),
    close: () => io.close()
  }
}

function sftpWrapperIo(conn: PooledConnection, sftp: SFTPWrapper): SftpIo {
  let closed = false
  return {
    readFile: (path) =>
      new Promise((resolve, reject) => {
        sftp.readFile(path, (err, buf) => (err ? reject(err) : resolve(buf)))
      }),
    writeFile: (path, data) =>
      new Promise((resolve, reject) => {
        // mode 0600 on creation, not chmod afterwards: a bundle that is
        // group-readable for even a moment is readable for long enough.
        sftp.writeFile(path, data, { mode: 0o600 }, (err) => (err ? reject(err) : resolve()))
      }),
    readdir: (path) =>
      new Promise((resolve, reject) => {
        sftp.readdir(path, (err, list) =>
          err
            ? reject(err)
            : resolve(
                list
                  .filter((e) => (e.attrs.mode & 0o170000) !== 0o040000)
                  .map((e) => ({
                    name: e.filename,
                    size: e.attrs.size,
                    modified: e.attrs.mtime * 1000
                  }))
              )
        )
      }),
    unlink: (path) =>
      new Promise((resolve, reject) => {
        sftp.unlink(path, (err) => (err ? reject(err) : resolve()))
      }),
    rename: (from, to) =>
      new Promise((resolve, reject) => {
        sftp.rename(from, to, (err) => (err ? reject(err) : resolve()))
      }),
    async close() {
      if (closed) return
      closed = true
      try {
        release(conn)
      } catch {
        /* a pool that has already dropped the connection is fine */
      }
    }
  }
}

interface StoredServer {
  id: string
  name?: string
  host?: string
  port?: number
  username?: string
  auth?: SshAuth
  vpnProfileId?: string
  hops?: SshHop[]
}

/** The saved connection this destination uploads through. Read from the same
 *  store the terminal reads, so a destination cannot name a server that is not
 *  really there. */
export function storedServer(serverId: string): StoredServer | null {
  const data = loadData() as { servers?: StoredServer[] } | null
  return data?.servers?.find((s) => s.id === serverId) ?? null
}

async function openSftpIo(dest: SftpBackupDestination): Promise<SftpIo> {
  const server = storedServer(dest.serverId)
  if (!server || !server.host) {
    throw new Error(
      `This destination uploads to a server that is no longer configured (${dest.serverId}).`
    )
  }
  const cfg = resolveChainSecrets({
    serverId: server.id,
    serverName: server.name,
    host: server.host,
    port: server.port ?? 22,
    username: server.username ?? '',
    auth: server.auth ?? 'agent',
    vpnProfileId: server.vpnProfileId,
    hops: server.hops ?? []
  })
  // allowPrompt false: a scheduled backup runs with nobody watching, and an
  // unknown host key is then a refusal, not a dialog. Uploading the vault to
  // whatever answered on that address is exactly the thing host-key checking
  // exists to stop.
  const conn = await acquire(cfg, undefined, false)
  const sftp = await new Promise<SFTPWrapper>((resolve, reject) => {
    conn.client.sftp((err, s) => (err ? reject(err) : resolve(s)))
  })
  return sftpWrapperIo(conn, sftp)
}

// ---------------------------------------------------------------------------
// S3-compatible object storage
// ---------------------------------------------------------------------------

/**
 * Percent-encoding as SigV4 defines it, which is not what encodeURIComponent
 * does: `!`, `'`, `(`, `)` and `*` must be escaped, and a slash is escaped
 * everywhere except in the path.
 */
export function awsUriEncode(value: string, keepSlash = false): string {
  let out = ''
  for (const ch of Buffer.from(value, 'utf8')) {
    const c = String.fromCharCode(ch)
    if (/[A-Za-z0-9\-_.~]/.test(c) || (keepSlash && c === '/')) out += c
    else out += `%${ch.toString(16).toUpperCase().padStart(2, '0')}`
  }
  return out
}

export interface SigV4Input {
  method: string
  /** Path, already the value that goes on the wire, starting with '/'. */
  path: string
  /** Sorted `k=v` pairs joined by '&', or '' for none. */
  query: string
  host: string
  payloadSha256: string
  accessKeyId: string
  secretAccessKey: string
  region: string
  /** The `20240115T103000Z` form. */
  amzDate: string
}

/** `{ canonicalRequest, stringToSign, authorization }`, all three exported for
 *  a test to assert as literals rather than recompute. */
export function signS3Request(input: SigV4Input): {
  canonicalRequest: string
  stringToSign: string
  authorization: string
} {
  const date = input.amzDate.slice(0, 8)
  const scope = `${date}/${input.region}/s3/aws4_request`
  const canonicalHeaders =
    `host:${input.host}\n` + `x-amz-content-sha256:${input.payloadSha256}\n` + `x-amz-date:${input.amzDate}\n`
  const signedHeaders = 'host;x-amz-content-sha256;x-amz-date'
  const canonicalRequest = [
    input.method,
    input.path,
    input.query,
    canonicalHeaders,
    signedHeaders,
    input.payloadSha256
  ].join('\n')
  const stringToSign = [
    'AWS4-HMAC-SHA256',
    input.amzDate,
    scope,
    createHash('sha256').update(canonicalRequest, 'utf8').digest('hex')
  ].join('\n')
  const hmac = (key: Buffer | string, msg: string): Buffer =>
    createHmac('sha256', key).update(msg, 'utf8').digest()
  const signing = hmac(hmac(hmac(hmac(`AWS4${input.secretAccessKey}`, date), input.region), 's3'), 'aws4_request')
  const signature = createHmac('sha256', signing).update(stringToSign, 'utf8').digest('hex')
  return {
    canonicalRequest,
    stringToSign,
    authorization: `AWS4-HMAC-SHA256 Credential=${input.accessKeyId}/${scope}, SignedHeaders=${signedHeaders}, Signature=${signature}`
  }
}

/** The object key for a name, honouring the destination's prefix. */
export function s3Key(dest: S3BackupDestination, name: string): string {
  const prefix = dest.prefix.replace(/^\/+|\/+$/g, '')
  return prefix ? `${prefix}/${name}` : name
}

/** Origin plus path for a key, in whichever addressing style is configured. */
export function s3Endpoint(dest: S3BackupDestination, key: string): { url: string; host: string; path: string } {
  const base = new URL(dest.endpoint)
  const encoded = awsUriEncode(key, true)
  if (dest.pathStyle) {
    const path = `/${dest.bucket}/${encoded}`
    return { url: `${base.origin}${path}`, host: base.host, path }
  }
  const host = `${dest.bucket}.${base.host}`
  const path = `/${encoded}`
  return { url: `${base.protocol}//${host}${path}`, host, path }
}

/**
 * `<Contents>` out of a ListObjectsV2 response.
 *
 * A hand-rolled reader rather than an XML dependency, and deliberately narrow:
 * it takes Key, Size and LastModified and ignores everything else, so a store
 * that adds elements does not break it and one that omits Size reports 0
 * rather than NaN.
 */
export function parseListObjects(xml: string): { keys: BackupGeneration[]; nextToken: string | null } {
  const keys: BackupGeneration[] = []
  const blocks = xml.match(/<Contents>[\s\S]*?<\/Contents>/g) ?? []
  for (const block of blocks) {
    const key = /<Key>([\s\S]*?)<\/Key>/.exec(block)?.[1]
    if (!key) continue
    const size = Number(/<Size>(\d+)<\/Size>/.exec(block)?.[1] ?? '0')
    const iso = /<LastModified>([\s\S]*?)<\/LastModified>/.exec(block)?.[1]
    const modified = iso ? Date.parse(iso) : 0
    keys.push({ name: key, size: Number.isFinite(size) ? size : 0, modified: Number.isNaN(modified) ? 0 : modified })
  }
  const truncated = /<IsTruncated>\s*true\s*<\/IsTruncated>/i.test(xml)
  const token = /<NextContinuationToken>([\s\S]*?)<\/NextContinuationToken>/.exec(xml)?.[1] ?? null
  return { keys, nextToken: truncated ? token : null }
}

export type FetchLike = (url: string, init: {
  method: string
  headers: Record<string, string>
  body?: Buffer
}) => Promise<{ ok: boolean; status: number; text(): Promise<string>; arrayBuffer(): Promise<ArrayBuffer> }>

export interface S3Credentials {
  accessKeyId: string
  secretAccessKey: string
}

export function s3TargetFrom(
  dest: S3BackupDestination,
  creds: S3Credentials,
  fetchImpl: FetchLike,
  now: () => Date = () => new Date()
): BackupTarget {
  const call = async (
    method: string,
    key: string,
    body?: Buffer,
    query = ''
  ): Promise<{ status: number; ok: boolean; text: () => Promise<string>; arrayBuffer: () => Promise<ArrayBuffer> }> => {
    const { url, host, path } = s3Endpoint(dest, key)
    const payloadSha256 = createHash('sha256').update(body ?? Buffer.alloc(0)).digest('hex')
    const amzDate = now().toISOString().replace(/[-:]/g, '').replace(/\.\d{3}Z$/, 'Z')
    const { authorization } = signS3Request({
      method,
      path,
      query,
      host,
      payloadSha256,
      accessKeyId: creds.accessKeyId,
      secretAccessKey: creds.secretAccessKey,
      region: dest.region,
      amzDate
    })
    // `host` and `content-length` are signed but NOT sent explicitly: fetch
    // derives both from the URL and the body, and undici refuses a manual
    // `host`. The signed value and the sent value are the same string either
    // way, which is the only property the signature depends on.
    const headers: Record<string, string> = {
      'x-amz-content-sha256': payloadSha256,
      'x-amz-date': amzDate,
      authorization
    }
    return fetchImpl(query ? `${url}?${query}` : url, { method, headers, body })
  }

  const fail = async (what: string, res: { status: number; text: () => Promise<string> }): Promise<never> => {
    let detail = ''
    try {
      detail = (await res.text()).slice(0, 300)
    } catch {
      /* an unreadable body is still an HTTP status worth reporting */
    }
    throw new Error(`${what} failed with HTTP ${res.status}${detail ? `: ${detail}` : ''}`)
  }

  return {
    async put(name, data) {
      // No scratch-then-rename: a PUT either creates the whole object or does
      // not create it, and S3 has no rename — the alternative would be a copy,
      // which doubles the window in which a bundle exists under a name we did
      // not verify.
      const res = await call('PUT', s3Key(dest, name), data)
      if (!res.ok) await fail(`Uploading ${name}`, res)
    },
    async get(name) {
      const res = await call('GET', s3Key(dest, name))
      if (!res.ok) await fail(`Downloading ${name}`, res)
      return Buffer.from(await res.arrayBuffer())
    },
    async list() {
      const prefix = dest.prefix.replace(/^\/+|\/+$/g, '')
      const out: BackupGeneration[] = []
      let token: string | null = null
      // Bounded: a bucket someone else also writes to must not turn a list
      // into an unbounded loop.
      for (let page = 0; page < 20; page++) {
        const params = ['list-type=2', 'max-keys=1000']
        if (prefix) params.push(`prefix=${awsUriEncode(`${prefix}/`)}`)
        if (token) params.push(`continuation-token=${awsUriEncode(token)}`)
        const query = params.sort().join('&')
        const res = await call('GET', '', undefined, query)
        if (!res.ok) await fail('Listing the bucket', res)
        const { keys, nextToken } = parseListObjects(await res.text())
        for (const k of keys) {
          const name = prefix ? k.name.slice(prefix.length + 1) : k.name
          // Keys in a sub-"directory" of the prefix are not ours.
          if (!name || name.includes('/') || isScratchName(name)) continue
          out.push({ ...k, name })
        }
        if (!nextToken) break
        token = nextToken
      }
      return out
    },
    async remove(name) {
      const res = await call('DELETE', s3Key(dest, name))
      // 204 is the documented success; a store that answers 200 is also fine.
      if (!res.ok) await fail(`Deleting ${name}`, res)
    },
    async close() {
      /* stateless */
    }
  }
}

/**
 * The access key and secret for an S3 destination, out of the vault.
 *
 * Not out of the settings blob, and this is the whole reason the destination
 * stores an id: the settings blob is inside every bundle uploaded to this
 * bucket, so a secret access key kept there would be sitting in the bucket it
 * unlocks, in every generation, for as long as retention keeps them.
 */
export function s3Credentials(dest: S3BackupDestination): S3Credentials {
  const status = vaultStatus()
  if (!status.exists) {
    throw new Error('This destination authenticates with a vault entry, and there is no vault on this machine.')
  }
  if (!status.unlocked) {
    throw new Error('This destination authenticates with a vault entry, and the vault is locked.')
  }
  const entry: VaultEntry | undefined = vaultList().entries?.find((e) => e.id === dest.vaultEntryId)
  if (!entry) {
    throw new Error('The vault entry holding this destination’s access key no longer exists.')
  }
  if (!entry.username || !entry.password) {
    throw new Error(
      `Vault entry “${entry.name}” must hold the access key id as its username and the secret access key as its secret.`
    )
  }
  return { accessKeyId: entry.username, secretAccessKey: entry.password }
}

// ---------------------------------------------------------------------------
// Opening one
// ---------------------------------------------------------------------------

/** Injection points, so the tests exercise the real drivers over real I/O
 *  rather than a stand-in for them. */
export interface TargetDeps {
  sftpIo?: (dest: SftpBackupDestination) => Promise<SftpIo>
  fetchImpl?: FetchLike
  credentials?: (dest: S3BackupDestination) => S3Credentials
}

export async function openTarget(dest: BackupDestination, deps: TargetDeps = {}): Promise<BackupTarget> {
  switch (dest.kind) {
    case 'local':
      if (!dest.directory) throw new Error('This destination has no directory set.')
      return localTarget(dest)
    case 'sftp': {
      if (!dest.directory) throw new Error('This destination has no remote directory set.')
      const io = await (deps.sftpIo ?? openSftpIo)(dest)
      return sftpTargetFrom(dest, io)
    }
    case 's3': {
      if (!dest.bucket) throw new Error('This destination has no bucket set.')
      const creds = (deps.credentials ?? s3Credentials)(dest)
      const f: FetchLike =
        deps.fetchImpl ??
        ((url: string, init: { method: string; headers: Record<string, string>; body?: Buffer }) =>
          fetch(url, init as RequestInit))
      return s3TargetFrom(dest, creds, f)
    }
  }
}
