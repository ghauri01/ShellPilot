import { createHash, createHmac } from 'node:crypto'
import { readFile, writeFile, readdir, stat, unlink, rename, mkdir } from 'node:fs/promises'
import { join } from 'node:path'
import type { SFTPWrapper } from 'ssh2'
import { acquire, release, type PooledConnection } from './ssh'
import { resolveChainSecrets, resolveDbSecrets } from './credentialResolver'
import { vaultList, vaultStatus } from './vault'
import { loadData } from './store'
import type {
  BackupDestination,
  BackupGeneration,
  DumpEngine,
  DumpTarget,
  LocalBackupDestination,
  S3BackupDestination,
  SftpBackupDestination
} from '../../shared/backup'
import { s3PrefixProblem } from '../../shared/backup'
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

/**
 * The object key for a name, honouring the destination's prefix.
 *
 * A name is one object in one prefix, and this refuses to build a key out of
 * anything else. Against a real MinIO, `put('/name')` landed under `name` —
 * the store dropped the leading slash — and `list()` then reported `name`,
 * which is not the string the caller asked to write. Nothing in this app
 * generates such a name today (see backupObjectName and dumpObjectName), and
 * that is exactly why the day one does, it should stop here rather than
 * quietly write somewhere else.
 */
export function s3Key(dest: S3BackupDestination, name: string): string {
  if (!name || name.includes('/') || name === '.' || name === '..') {
    throw new Error(`“${name}” is not an object name: it must name one object inside the prefix.`)
  }
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
 * XML character references, resolved.
 *
 * A ListObjectsV2 body is XML, so `<Key>` is XML-escaped text and not the key.
 * A real MinIO returned `<Key>a&amp;b/…</Key>` for the key `a&b/…` and
 * `<Key>line&#x1;one</Key>` for a key holding a control character. Reading
 * those verbatim gives back a name that does not exist in the bucket — see the
 * comment on `list` for what that costs.
 *
 * Named entities are limited to the five XML predefines on purpose: anything
 * else in a ListObjectsV2 body would be a store inventing an entity, and
 * leaving `&nbsp;` alone is better than guessing at it.
 */
export function decodeXmlText(value: string): string {
  return value.replace(/&(#[Xx][0-9A-Fa-f]+|#[0-9]+|[A-Za-z]+);/g, (whole, body: string) => {
    if (body[0] === '#') {
      const hex = body[1] === 'x' || body[1] === 'X'
      const code = Number.parseInt(hex ? body.slice(2) : body.slice(1), hex ? 16 : 10)
      if (!Number.isInteger(code) || code < 0 || code > 0x10ffff) return whole
      try {
        return String.fromCodePoint(code)
      } catch {
        return whole
      }
    }
    switch (body) {
      case 'amp':
        return '&'
      case 'lt':
        return '<'
      case 'gt':
        return '>'
      case 'quot':
        return '"'
      case 'apos':
        return "'"
      default:
        return whole
    }
  })
}

/**
 * A key out of an `encoding-type=url` listing.
 *
 * Form encoding, not percent encoding, and the difference is not academic:
 * against MinIO the key `space name.spbackup` came back as
 * `space+name.spbackup` and `plus+name.spbackup` came back as
 * `plus%2Bname.spbackup`. Decoding with decodeURIComponent alone turns the
 * first into a name with a `+` where the space was.
 */
export function decodeS3Key(value: string): string {
  try {
    return decodeURIComponent(value.replace(/\+/g, '%20'))
  } catch {
    // A store that answered something that is not valid percent-encoding: the
    // raw text is a worse name than nothing, but a thrown listing is worse
    // still, and the startsWith check in `list` drops it.
    return value
  }
}

/**
 * `<Contents>` out of a ListObjectsV2 response.
 *
 * A hand-rolled reader rather than an XML dependency, and deliberately narrow:
 * it takes Key, Size and LastModified and ignores everything else, so a store
 * that adds elements does not break it and one that omits Size reports 0
 * rather than NaN.
 *
 * The one thing it is not narrow about is the key, because the key is a name
 * this module will later hand back to GET and DELETE.
 */
export function parseListObjects(xml: string): { keys: BackupGeneration[]; nextToken: string | null } {
  const keys: BackupGeneration[] = []
  // Set only when the store echoed `<EncodingType>url</EncodingType>`, which is
  // its statement that it applied the encoding we asked for. A store that
  // ignores `encoding-type` answers without the element and its keys are then
  // decoded as entities only — percent-decoding those would eat a literal `%`
  // in somebody's key.
  const urlEncoded = /<EncodingType>\s*url\s*<\/EncodingType>/i.test(xml)
  const blocks = xml.match(/<Contents>[\s\S]*?<\/Contents>/g) ?? []
  for (const block of blocks) {
    const raw = /<Key>([\s\S]*?)<\/Key>/.exec(block)?.[1]
    if (!raw) continue
    const key = urlEncoded ? decodeS3Key(decodeXmlText(raw)) : decodeXmlText(raw)
    if (!key) continue
    const size = Number(/<Size>(\d+)<\/Size>/.exec(block)?.[1] ?? '0')
    const iso = /<LastModified>([\s\S]*?)<\/LastModified>/.exec(block)?.[1]
    const modified = iso ? Date.parse(iso) : 0
    keys.push({ name: key, size: Number.isFinite(size) ? size : 0, modified: Number.isNaN(modified) ? 0 : modified })
  }
  const truncated = /<IsTruncated>\s*true\s*<\/IsTruncated>/i.test(xml)
  // Entity-decoded like any XML text, but NOT url-decoded even when the
  // listing is: `encoding-type` covers Delimiter, Prefix, Key and the marker
  // fields, and the continuation token is not one of them. Decoding it would
  // corrupt the `+` and `/` a base64 token is full of, and the next page would
  // come back empty or wrong.
  const rawToken = /<NextContinuationToken>([\s\S]*?)<\/NextContinuationToken>/.exec(xml)?.[1]
  const token = rawToken === undefined ? null : decodeXmlText(rawToken)
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
      const under = prefix ? `${prefix}/` : ''
      const out: BackupGeneration[] = []
      let token: string | null = null
      // Bounded: a bucket someone else also writes to must not turn a list
      // into an unbounded loop.
      for (let page = 0; page < 20; page++) {
        // `encoding-type=url` is what every AWS SDK asks for and it is not
        // cosmetic. Without it a key is XML text: MinIO returned the key
        // `a&b/…` as `a&amp;b/…`, this loop sliced `prefix.length + 1`
        // characters off a string four characters longer than the prefix, and
        // what came out had a `/` in it — so the generation was dropped. A
        // destination with an `&` in its prefix listed as empty: retention
        // deleted nothing and never would, "restore from here" offered
        // nothing, and the run still reported success. That is a backup that
        // is silently not a backup, which is the one failure this whole
        // feature exists to refuse.
        const params = ['list-type=2', 'max-keys=1000', 'encoding-type=url']
        if (prefix) params.push(`prefix=${awsUriEncode(under)}`)
        if (token) params.push(`continuation-token=${awsUriEncode(token)}`)
        const query = params.sort().join('&')
        const res = await call('GET', '', undefined, query)
        if (!res.ok) await fail('Listing the bucket', res)
        const { keys, nextToken } = parseListObjects(await res.text())
        for (const k of keys) {
          // startsWith rather than a length subtraction: if the key does not
          // begin with the prefix we asked the store for, then either the
          // store answered something else or the decoding above is wrong, and
          // in both cases the honest thing is to not claim it as a generation.
          if (!k.name.startsWith(under)) continue
          const name = k.name.slice(under.length)
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
      // Before the credential, so a prefix this driver cannot address is not
      // reported as a vault problem — and before the first request, so it is
      // not reported as SignatureDoesNotMatch either.
      const prefixProblem = s3PrefixProblem(dest.prefix)
      if (prefixProblem) throw new Error(prefixProblem)
      const creds = (deps.credentials ?? s3Credentials)(dest)
      const f: FetchLike =
        deps.fetchImpl ??
        ((url: string, init: { method: string; headers: Record<string, string>; body?: Buffer }) =>
          fetch(url, init as RequestInit))
      return s3TargetFrom(dest, creds, f)
    }
  }
}

// ---------------------------------------------------------------------------
// A database as a backup source
// ---------------------------------------------------------------------------

interface StoredDatabase {
  id: string
  name?: string
  kind?: string
  host?: string
  port?: number
  username?: string
  database?: string
  uri?: boolean
  sshServerId?: string | null
  vpnProfileId?: string | null
}

/** Databases a dump can actually be taken from, for the panel to offer. Only
 *  the two engines item 18 already knows how to reach, and only the ones this
 *  machine can reach directly — see databaseDumpTarget for why. */
export function dumpableDatabases(): { id: string; name: string; engine: DumpEngine }[] {
  const data = loadData() as { databases?: StoredDatabase[] } | null
  const out: { id: string; name: string; engine: DumpEngine }[] = []
  for (const db of data?.databases ?? []) {
    const engine = db.kind === 'postgres' ? 'postgres' : db.kind === 'mysql' ? 'mysql' : null
    if (!engine) continue
    if (db.sshServerId || db.vpnProfileId || db.uri) continue
    if (!db.host || !db.database) continue
    out.push({ id: db.id, name: db.name ?? db.database, engine })
  }
  return out
}

/**
 * Everything `pg_dump`/`mysqldump` needs for one saved database, or the reason
 * there is nothing to hand it.
 *
 * The refusals are deliberate and each names a thing this does not do rather
 * than trying and failing halfway:
 *
 *  - A bastion or a VPN means the database is not reachable from this process
 *    at that host and port. dbOps opens a forward for exactly this reason;
 *    a dump that ignored it would sit there until the TCP connect timed out
 *    and then report a network error about the wrong address.
 *  - A connection defined by a URI carries its own credentials and options in
 *    a string, and taking a host and port out of it to rebuild an argv is how
 *    a dump ends up pointed at the wrong database.
 *  - Only Postgres and MySQL: there is no mongodump or redis equivalent here,
 *    and pretending otherwise would produce an empty file with a .sql name.
 */
export function databaseDumpTarget(
  databaseId: string
): { target: DumpTarget; password: string } | { error: string } {
  const data = loadData() as { databases?: StoredDatabase[] } | null
  const db = data?.databases?.find((d) => d.id === databaseId)
  if (!db) return { error: 'That database is no longer configured.' }
  const engine: DumpEngine | null =
    db.kind === 'postgres' ? 'postgres' : db.kind === 'mysql' ? 'mysql' : null
  if (!engine) {
    return { error: `Dumps are only supported for PostgreSQL and MySQL, and this one is ${db.kind ?? 'of an unknown kind'}.` }
  }
  if (db.sshServerId || db.vpnProfileId) {
    return {
      error:
        'This database is reached through a bastion or a VPN, and a dump runs from this machine directly — so it would be pointed at an address it cannot reach.'
    }
  }
  if (db.uri) {
    return {
      error:
        'This connection is defined by a connection string, and rebuilding a dump command out of one is how a dump ends up pointed at the wrong database.'
    }
  }
  if (!db.host || !db.database) return { error: 'This database has no server or database name saved.' }
  const resolved = resolveDbSecrets<{ id: string; password?: string; uri?: string }>({ id: db.id })
  return {
    target: {
      engine,
      host: db.host,
      port: db.port ?? (engine === 'postgres' ? 5432 : 3306),
      username: db.username ?? '',
      database: db.database
    },
    password: resolved.password ?? ''
  }
}
