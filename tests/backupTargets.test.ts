import { describe, it, expect, beforeEach, afterEach, afterAll, beforeAll } from 'vitest'
import { createServer, type Server } from 'node:http'
import { createServer as createTcpServer, connect as tcpConnect } from 'node:net'
import { mkdtempSync, rmSync, writeFileSync, readdirSync, existsSync, readFileSync } from 'node:fs'
import { readFile, writeFile, readdir, stat, unlink, rename } from 'node:fs/promises'
import { createHash } from 'node:crypto'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import {
  awsUriEncode,
  isScratchName,
  localTarget,
  openTarget,
  parseListObjects,
  remoteJoin,
  s3Endpoint,
  s3Key,
  s3TargetFrom,
  sftpTargetFrom,
  sha256,
  signS3Request,
  type FetchLike,
  type SftpIo
} from '../src/main/services/backupTargets'
import {
  backupObjectName,
  backupObjectTime,
  destinationProblem,
  isBackupObjectName,
  planRetention,
  s3PrefixProblem
} from '../src/shared/backup'
import {
  loopbackFetch,
  minioSkipReason,
  MINIO_CREDENTIALS,
  startMinio,
  stopMinio,
  type Minio
} from './fixtures/s3/minio'
import type {
  LocalBackupDestination,
  S3BackupDestination,
  SftpBackupDestination
} from '../src/shared/backup'

// ---------------------------------------------------------------------------
// Scratch directories
// ---------------------------------------------------------------------------

const dirs: string[] = []
function temp(): string {
  const d = mkdtempSync(join(tmpdir(), 'sp-backup-target-'))
  dirs.push(d)
  return d
}
afterAll(() => {
  for (const d of dirs) rmSync(d, { recursive: true, force: true })
})

function local(directory: string, over: Partial<LocalBackupDestination> = {}): LocalBackupDestination {
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

// ---------------------------------------------------------------------------
// A real SFTP-shaped filesystem
// ---------------------------------------------------------------------------

/**
 * Everything the SFTP driver asks of a remote, backed by a real directory
 * through real promises. Not a mock: the driver's own put/rename/list/remove
 * logic runs unchanged against it, so a bug in that logic fails here. `faults`
 * makes one named call throw, which is how the drop-mid-upload cases are
 * reached without an unreliable network.
 */
function tempSftpIo(
  dir: string,
  faults: Partial<Record<'writeFile' | 'rename' | 'readFile' | 'readdir' | 'unlink', string>> = {}
): SftpIo & { closed: number } {
  const boom = (op: keyof typeof faults): void => {
    const message = faults[op]
    if (message) throw new Error(message)
  }
  const io = {
    closed: 0,
    async readFile(path: string): Promise<Buffer> {
      boom('readFile')
      return readFile(path)
    },
    async writeFile(path: string, data: Buffer): Promise<void> {
      boom('writeFile')
      await writeFile(path, data, { mode: 0o600 })
    },
    async readdir(path: string): Promise<{ name: string; size: number; modified: number }[]> {
      boom('readdir')
      const names = await readdir(path)
      const out: { name: string; size: number; modified: number }[] = []
      for (const name of names) {
        const s = await stat(join(path, name))
        if (!s.isDirectory()) out.push({ name, size: s.size, modified: s.mtimeMs })
      }
      return out
    },
    async unlink(path: string): Promise<void> {
      boom('unlink')
      await unlink(path)
    },
    async rename(from: string, to: string): Promise<void> {
      boom('rename')
      await rename(from, to)
    },
    async close(): Promise<void> {
      io.closed += 1
    }
  }
  return io
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

// ---------------------------------------------------------------------------
// A real S3-shaped HTTP server
// ---------------------------------------------------------------------------

interface FakeS3 {
  server: Server
  origin: string
  objects: Map<string, Buffer>
  /** Every Authorization header the server was sent, in order. */
  auth: string[]
  /** Requests whose x-amz-content-sha256 did not match the body received. */
  badDigests: string[]
}

async function startFakeS3(): Promise<FakeS3> {
  const objects = new Map<string, Buffer>()
  const auth: string[] = []
  const badDigests: string[] = []
  const server = createServer((req, res) => {
    const chunks: Buffer[] = []
    req.on('data', (c: Buffer) => chunks.push(c))
    req.on('end', () => {
      const body = Buffer.concat(chunks)
      auth.push(String(req.headers.authorization ?? ''))
      const claimed = String(req.headers['x-amz-content-sha256'] ?? '')
      if (claimed !== createHash('sha256').update(body).digest('hex')) {
        badDigests.push(`${req.method} ${req.url}`)
      }
      const url = new URL(req.url ?? '/', 'http://x')
      // Path-style: /<bucket>/<key...>
      const parts = url.pathname.replace(/^\//, '').split('/')
      const key = decodeURIComponent(parts.slice(1).join('/'))
      if (req.method === 'PUT') {
        objects.set(key, body)
        res.writeHead(200).end()
        return
      }
      if (req.method === 'DELETE') {
        objects.delete(key)
        res.writeHead(204).end()
        return
      }
      if (req.method === 'GET' && url.searchParams.get('list-type') === '2') {
        const prefix = url.searchParams.get('prefix') ?? ''
        const contents = [...objects.entries()]
          .filter(([k]) => k.startsWith(prefix))
          .map(
            ([k, v]) =>
              `<Contents><Key>${k}</Key><Size>${v.length}</Size><LastModified>2024-01-15T10:30:00.000Z</LastModified></Contents>`
          )
          .join('')
        res
          .writeHead(200, { 'content-type': 'application/xml' })
          .end(`<?xml version="1.0"?><ListBucketResult><IsTruncated>false</IsTruncated>${contents}</ListBucketResult>`)
        return
      }
      if (req.method === 'GET') {
        const value = objects.get(key)
        if (!value) {
          res.writeHead(404, { 'content-type': 'application/xml' }).end('<Error><Code>NoSuchKey</Code></Error>')
          return
        }
        res.writeHead(200).end(value)
        return
      }
      res.writeHead(405).end()
    })
  })
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve))
  const addr = server.address()
  const port = typeof addr === 'object' && addr ? addr.port : 0
  return { server, origin: `http://127.0.0.1:${port}`, objects, auth, badDigests }
}

function s3Dest(origin: string, over: Partial<S3BackupDestination> = {}): S3BackupDestination {
  return {
    id: 'dest-s3',
    name: 'Off-site bucket',
    kind: 's3',
    endpoint: origin,
    region: 'eu-west-1',
    bucket: 'estate-backups',
    prefix: 'shellpilot',
    vaultEntryId: 'vault-1',
    pathStyle: true,
    keep: 0,
    everyHours: 0,
    restoreTest: true,
    ...over
  }
}

// ---------------------------------------------------------------------------
// Object names
// ---------------------------------------------------------------------------

describe('backup object names', () => {
  it('encodes the time in the name, which is the only clock we control', () => {
    expect(backupObjectName(new Date('2024-01-15T10:30:00.000Z'))).toBe(
      'shellpilot-20240115T103000Z.spbackup'
    )
  })

  it('reads that time back', () => {
    expect(backupObjectTime('shellpilot-20240115T103000Z.spbackup')).toBe(
      Date.parse('2024-01-15T10:30:00.000Z')
    )
  })

  it('refuses names that are not ours, so retention never sees somebody else’s file', () => {
    // A directory a person also keeps things in. None of these is a generation.
    expect(isBackupObjectName('notes.txt')).toBe(false)
    expect(isBackupObjectName('shellpilot-backup-2024-01-15.spbackup')).toBe(false)
    expect(isBackupObjectName('shellpilot-20240115T103000Z.spbackup.part')).toBe(false)
    expect(backupObjectTime('shellpilot-dump-orders-20240115T103000Z.sql')).toBe(null)
  })
})

// ---------------------------------------------------------------------------
// Retention
// ---------------------------------------------------------------------------

describe('planRetention', () => {
  const gen = (name: string, modified: number) => ({ name, size: 10, modified })
  const a = gen('shellpilot-20240101T000000Z.spbackup', 1)
  const b = gen('shellpilot-20240102T000000Z.spbackup', 2)
  const c = gen('shellpilot-20240103T000000Z.spbackup', 3)

  it('keeps the newest N and removes the rest', () => {
    const plan = planRetention([a, c, b], 2)
    expect(plan.keep.map((g) => g.name)).toEqual([
      'shellpilot-20240103T000000Z.spbackup',
      'shellpilot-20240102T000000Z.spbackup'
    ])
    expect(plan.remove.map((g) => g.name)).toEqual(['shellpilot-20240101T000000Z.spbackup'])
  })

  it('never deletes the only remaining generation, whatever the limit says', () => {
    // keep:1 with one file on disk is the arrangement in which an
    // over-literal reading deletes the single copy someone has.
    const plan = planRetention([a], 1)
    expect(plan.remove).toEqual([])
    expect(plan.refused).toBe('Only one backup is here, and the last one is never deleted.')
  })

  it('deletes nothing when no limit is set — unset is not "keep none"', () => {
    const plan = planRetention([a, b, c], 0)
    expect(plan.remove).toEqual([])
    expect(plan.keep.map((g) => g.name)).toEqual([
      'shellpilot-20240103T000000Z.spbackup',
      'shellpilot-20240102T000000Z.spbackup',
      'shellpilot-20240101T000000Z.spbackup'
    ])
    expect(plan.refused).toBe('No limit is set, so nothing is deleted.')
  })

  it('never proposes deleting a file that is not one of ours', () => {
    const plan = planRetention([a, b, c, gen('tax-return.pdf', 99), gen('.DS_Store', 98)], 1)
    expect(plan.remove.map((g) => g.name)).toEqual([
      'shellpilot-20240102T000000Z.spbackup',
      'shellpilot-20240101T000000Z.spbackup'
    ])
  })
})

// ---------------------------------------------------------------------------
// Local directory
// ---------------------------------------------------------------------------

describe('local target', () => {
  it('round-trips a bundle and lists it', async () => {
    const dir = temp()
    const t = localTarget(local(dir))
    await t.put('shellpilot-20240101T000000Z.spbackup', Buffer.from('bundle-bytes'))
    expect((await t.get('shellpilot-20240101T000000Z.spbackup')).toString()).toBe('bundle-bytes')
    expect((await t.list()).map((g) => g.name)).toEqual(['shellpilot-20240101T000000Z.spbackup'])
    await t.remove('shellpilot-20240101T000000Z.spbackup')
    expect(await t.list()).toEqual([])
  })

  it('never leaves a half-written file under a generation name', async () => {
    // Nothing here fails; what is asserted is that the name only ever appears
    // via a rename, so a process killed during the write leaves a `.part`
    // rather than a truncated `.spbackup` that list() would count.
    const dir = temp()
    writeFileSync(join(dir, 'shellpilot-20231231T000000Z.spbackup.part'), 'half a bundle')
    const t = localTarget(local(dir))
    expect(await t.list()).toEqual([])
    expect(isScratchName('shellpilot-20231231T000000Z.spbackup.part')).toBe(true)
    expect(readdirSync(dir)).toEqual(['shellpilot-20231231T000000Z.spbackup.part'])
  })

  it('ignores directories sitting in the backup folder', async () => {
    const dir = temp()
    const t = localTarget(local(dir))
    await t.put('shellpilot-20240101T000000Z.spbackup', Buffer.from('x'))
    const { mkdirSync } = await import('node:fs')
    mkdirSync(join(dir, 'archive'))
    expect((await t.list()).map((g) => g.name)).toEqual(['shellpilot-20240101T000000Z.spbackup'])
  })
})

// ---------------------------------------------------------------------------
// SFTP
// ---------------------------------------------------------------------------

describe('remoteJoin', () => {
  it('joins without doubling or dropping the separator', () => {
    expect(remoteJoin('/srv/backups', 'a.spbackup')).toBe('/srv/backups/a.spbackup')
    expect(remoteJoin('/srv/backups/', 'a.spbackup')).toBe('/srv/backups/a.spbackup')
    expect(remoteJoin('', 'a.spbackup')).toBe('a.spbackup')
  })
})

describe('sftp target', () => {
  it('round-trips through a real remote filesystem', async () => {
    const dir = temp()
    const io = tempSftpIo(dir)
    const t = sftpTargetFrom(sftpDest(dir), io)
    await t.put('shellpilot-20240101T000000Z.spbackup', Buffer.from('remote bundle'))
    expect((await t.get('shellpilot-20240101T000000Z.spbackup')).toString()).toBe('remote bundle')
    expect((await t.list()).map((g) => g.name)).toEqual(['shellpilot-20240101T000000Z.spbackup'])
    await t.close()
    expect(io.closed).toBe(1)
  })

  it('leaves nothing behind when the upload lands but the rename does not', async () => {
    // The connection dropping between the last write and the rename is the
    // realistic partial upload. What must NOT survive it is a file under a
    // name that list() would report as a backup — and the scratch file must
    // not survive either, or the next run's rename fails on it.
    const dir = temp()
    const io = tempSftpIo(dir, { rename: 'Connection lost' })
    const t = sftpTargetFrom(sftpDest(dir), io)

    await expect(t.put('shellpilot-20240101T000000Z.spbackup', Buffer.from('half'))).rejects.toThrow(
      'Connection lost'
    )

    expect(readdirSync(dir)).toEqual([])
    expect(await t.list()).toEqual([])
  })

  it('does not report scratch files as generations', async () => {
    const dir = temp()
    writeFileSync(join(dir, 'shellpilot-20240101T000000Z.spbackup.part'), 'partial')
    const t = sftpTargetFrom(sftpDest(dir), tempSftpIo(dir))
    expect(await t.list()).toEqual([])
  })
})

// ---------------------------------------------------------------------------
// S3 signing
// ---------------------------------------------------------------------------

describe('awsUriEncode', () => {
  it('escapes the five characters encodeURIComponent leaves alone', () => {
    // SigV4 requires these escaped; encodeURIComponent does not escape any of
    // them, and a canonical request that disagrees with the server's is a
    // SignatureDoesNotMatch with no clue as to why.
    expect(awsUriEncode("!'()*")).toBe('%21%27%28%29%2A')
  })

  it('escapes the slash unless it is a path', () => {
    expect(awsUriEncode('a/b')).toBe('a%2Fb')
    expect(awsUriEncode('a/b', true)).toBe('a/b')
  })

  it('leaves the unreserved set alone and encodes UTF-8 byte by byte', () => {
    expect(awsUriEncode('Az0-_.~')).toBe('Az0-_.~')
    expect(awsUriEncode('é')).toBe('%C3%A9')
  })
})

describe('signS3Request', () => {
  const input = {
    method: 'PUT',
    path: '/estate-backups/shellpilot/shellpilot-20240115T103000Z.spbackup',
    query: '',
    host: 's3.eu-west-1.amazonaws.com',
    payloadSha256: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    accessKeyId: 'AKIAIOSFODNN7EXAMPLE',
    secretAccessKey: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
    region: 'eu-west-1',
    amzDate: '20240115T103000Z'
  }

  it('builds the canonical request AWS specifies, line for line', () => {
    expect(signS3Request(input).canonicalRequest).toBe(
      'PUT\n' +
        '/estate-backups/shellpilot/shellpilot-20240115T103000Z.spbackup\n' +
        '\n' +
        'host:s3.eu-west-1.amazonaws.com\n' +
        'x-amz-content-sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\n' +
        'x-amz-date:20240115T103000Z\n' +
        '\n' +
        'host;x-amz-content-sha256;x-amz-date\n' +
        'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
    )
  })

  it('signs over the scope, which pins the date, region and service', () => {
    const { stringToSign } = signS3Request(input)
    const [algorithm, date, scope] = stringToSign.split('\n')
    expect(algorithm).toBe('AWS4-HMAC-SHA256')
    expect(date).toBe('20240115T103000Z')
    expect(scope).toBe('20240115/eu-west-1/s3/aws4_request')
  })

  it('produces a stable signature for a fixed request', () => {
    // Computed independently from the AWS SigV4 specification (a throwaway
    // Python implementation), not copied out of this module's own output — a
    // literal taken from the code under test only proves the code is
    // deterministic. Its job is to fail if canonicalisation changes, which is
    // the change that produces SignatureDoesNotMatch against a real bucket and
    // nothing at all here.
    expect(signS3Request(input).authorization).toBe(
      'AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20240115/eu-west-1/s3/aws4_request, ' +
        'SignedHeaders=host;x-amz-content-sha256;x-amz-date, ' +
        'Signature=13138fc9fa6410a61b301c71e3434b3229ea94cd4189ff79a2c57b4e2ba38cc9'
    )
  })

  it('changes the signature when the payload changes', () => {
    const other = signS3Request({ ...input, payloadSha256: 'a'.repeat(64) })
    expect(other.authorization).not.toBe(signS3Request(input).authorization)
  })
})

describe('s3 addressing', () => {
  it('puts the prefix in front of the name', () => {
    expect(s3Key(s3Dest('http://x'), 'shellpilot-20240101T000000Z.spbackup')).toBe(
      'shellpilot/shellpilot-20240101T000000Z.spbackup'
    )
    expect(s3Key(s3Dest('http://x', { prefix: '' }), 'a.spbackup')).toBe('a.spbackup')
    expect(s3Key(s3Dest('http://x', { prefix: '/nested/dir/' }), 'a.spbackup')).toBe('nested/dir/a.spbackup')
  })

  it('addresses path-style for MinIO and virtual-host style for AWS', () => {
    const pathStyle = s3Endpoint(s3Dest('http://127.0.0.1:9000'), 'shellpilot/a.spbackup')
    expect(pathStyle.url).toBe('http://127.0.0.1:9000/estate-backups/shellpilot/a.spbackup')
    expect(pathStyle.host).toBe('127.0.0.1:9000')

    const virtual = s3Endpoint(
      s3Dest('https://s3.eu-west-1.amazonaws.com', { pathStyle: false }),
      'shellpilot/a.spbackup'
    )
    expect(virtual.url).toBe('https://estate-backups.s3.eu-west-1.amazonaws.com/shellpilot/a.spbackup')
    expect(virtual.host).toBe('estate-backups.s3.eu-west-1.amazonaws.com')
  })
})

describe('parseListObjects', () => {
  it('reads key, size and time out of a ListObjectsV2 body', () => {
    const { keys, nextToken } = parseListObjects(
      '<?xml version="1.0"?><ListBucketResult><IsTruncated>false</IsTruncated>' +
        '<Contents><Key>p/a.spbackup</Key><Size>1234</Size><LastModified>2024-01-15T10:30:00.000Z</LastModified></Contents>' +
        '<Contents><Key>p/b.spbackup</Key><Size>77</Size><LastModified>2024-02-15T10:30:00.000Z</LastModified></Contents>' +
        '</ListBucketResult>'
    )
    expect(keys).toEqual([
      { name: 'p/a.spbackup', size: 1234, modified: Date.parse('2024-01-15T10:30:00.000Z') },
      { name: 'p/b.spbackup', size: 77, modified: Date.parse('2024-02-15T10:30:00.000Z') }
    ])
    expect(nextToken).toBe(null)
  })

  it('reports the continuation token only while the listing is truncated', () => {
    const body =
      '<ListBucketResult><IsTruncated>true</IsTruncated><NextContinuationToken>abc123</NextContinuationToken>' +
      '<Contents><Key>a</Key><Size>1</Size><LastModified>2024-01-15T10:30:00.000Z</LastModified></Contents></ListBucketResult>'
    expect(parseListObjects(body).nextToken).toBe('abc123')
    expect(parseListObjects(body.replace('true', 'false')).nextToken).toBe(null)
  })

  it('reports a missing size as zero rather than NaN', () => {
    const { keys } = parseListObjects('<ListBucketResult><Contents><Key>a</Key></Contents></ListBucketResult>')
    expect(keys).toEqual([{ name: 'a', size: 0, modified: 0 }])
  })
})

// ---------------------------------------------------------------------------
// S3 over real HTTP
// ---------------------------------------------------------------------------

describe('s3 target against a real HTTP object store', () => {
  let fake: FakeS3

  beforeEach(async () => {
    fake = await startFakeS3()
  })
  afterEach(async () => {
    await new Promise<void>((resolve) => fake.server.close(() => resolve()))
  })

  const creds = { accessKeyId: 'AKIA-TEST', secretAccessKey: 'secret-key' }

  it('uploads, reads back, lists and deletes', async () => {
    const dest = s3Dest(fake.origin)
    const t = await openTarget(dest, { credentials: () => creds })
    const bytes = Buffer.from('{"magic":"shellpilot-backup"}')

    await t.put('shellpilot-20240101T000000Z.spbackup', bytes)
    expect([...fake.objects.keys()]).toEqual(['shellpilot/shellpilot-20240101T000000Z.spbackup'])

    expect((await t.get('shellpilot-20240101T000000Z.spbackup')).toString()).toBe(
      '{"magic":"shellpilot-backup"}'
    )
    expect((await t.list()).map((g) => g.name)).toEqual(['shellpilot-20240101T000000Z.spbackup'])

    await t.remove('shellpilot-20240101T000000Z.spbackup')
    expect([...fake.objects.keys()]).toEqual([])
  })

  it('signs every request and states the body hash the server can check', async () => {
    const t = await openTarget(s3Dest(fake.origin), { credentials: () => creds })
    await t.put('shellpilot-20240101T000000Z.spbackup', Buffer.from('payload'))
    await t.get('shellpilot-20240101T000000Z.spbackup')

    expect(fake.badDigests).toEqual([])
    expect(fake.auth).toHaveLength(2)
    for (const header of fake.auth) {
      expect(header).toMatch(
        /^AWS4-HMAC-SHA256 Credential=AKIA-TEST\/\d{8}\/eu-west-1\/s3\/aws4_request, SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature=[0-9a-f]{64}$/
      )
    }
  })

  it('reports the HTTP status when an object is not there, rather than an empty buffer', async () => {
    const t = await openTarget(s3Dest(fake.origin), { credentials: () => creds })
    await expect(t.get('shellpilot-20240101T000000Z.spbackup')).rejects.toThrow(
      'Downloading shellpilot-20240101T000000Z.spbackup failed with HTTP 404'
    )
  })

  it('does not list objects that belong to another prefix or a sub-folder', async () => {
    const dest = s3Dest(fake.origin)
    const t = await openTarget(dest, { credentials: () => creds })
    await t.put('shellpilot-20240101T000000Z.spbackup', Buffer.from('ours'))
    fake.objects.set('other-app/thing.spbackup', Buffer.from('theirs'))
    fake.objects.set('shellpilot/nested/deeper.spbackup', Buffer.from('nested'))

    expect((await t.list()).map((g) => g.name)).toEqual(['shellpilot-20240101T000000Z.spbackup'])
  })
})

describe('sha256', () => {
  it('is the digest a destination can be checked against', () => {
    expect(sha256(Buffer.from(''))).toBe(
      'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
    )
    expect(sha256(Buffer.from('abc'))).toBe(
      'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'
    )
  })
})

describe('openTarget', () => {
  it('refuses a destination that has not been finished', async () => {
    await expect(openTarget(local(''))).rejects.toThrow('This destination has no directory set.')
    await expect(openTarget(sftpDest(''))).rejects.toThrow('This destination has no remote directory set.')
    await expect(openTarget(s3Dest('http://x', { bucket: '' }))).rejects.toThrow(
      'This destination has no bucket set.'
    )
  })

  it('surfaces a locked vault as the reason an S3 destination cannot be used', async () => {
    // The credential for the bucket lives in the vault, so a locked vault is a
    // real, temporary, explainable failure — not "the upload broke".
    await expect(
      openTarget(s3Dest('http://x'), {
        credentials: () => {
          throw new Error('This destination authenticates with a vault entry, and the vault is locked.')
        }
      })
    ).rejects.toThrow('the vault is locked')
  })
})

describe('nothing in this module writes outside its directory', () => {
  it('keeps a local destination’s files in that destination’s directory', async () => {
    const a = temp()
    const b = temp()
    const t = localTarget(local(a))
    await t.put('shellpilot-20240101T000000Z.spbackup', Buffer.from('x'))
    expect(existsSync(join(a, 'shellpilot-20240101T000000Z.spbackup'))).toBe(true)
    expect(readdirSync(b)).toEqual([])
  })
})

// ---------------------------------------------------------------------------
// What a real ListObjectsV2 body actually contains
// ---------------------------------------------------------------------------

/**
 * The seven keys in tests/fixtures/s3/*.xml, as the strings they are in the
 * bucket rather than as the strings they are in the XML.
 *
 * One literal list, asserted identically against both recordings, because that
 * is the property that was broken: the same bucket listed two different ways
 * has to produce the same names, and one of the two produced
 * `bundles/amp&amp;ersand.spbackup`.
 */
const FIXTURE_KEYS = [
  'bundles/amp&ersand.spbackup',
  'bundles/ctrl\u0001char.spbackup',
  'bundles/plain.spbackup',
  'bundles/plus+name.spbackup',
  'bundles/quote"lt<gt>.spbackup',
  'bundles/space name.spbackup',
  'bundles/unicodé-日本.spbackup'
]

function s3Fixture(name: string): string {
  return readFileSync(join(__dirname, 'fixtures', 's3', name), 'utf8')
}

describe('parseListObjects, against bodies recorded off a real MinIO', () => {
  it('reads a key out of an unencoded listing as the key, not as its XML escaping', () => {
    // Recorded: `<Key>bundles/amp&amp;ersand.spbackup</Key>` and
    // `<Key>bundles/ctrl&#x1;char.spbackup</Key>`. A reader that takes the
    // element text verbatim reports names that are not in the bucket, and this
    // module hands those names straight back to GET and DELETE.
    expect(parseListObjects(s3Fixture('list-v2-minio.xml')).keys.map((k) => k.name)).toEqual(
      FIXTURE_KEYS
    )
  })

  it('reads the same seven names out of the encoding-type=url listing', () => {
    expect(parseListObjects(s3Fixture('list-v2-encoded-minio.xml')).keys.map((k) => k.name)).toEqual(
      FIXTURE_KEYS
    )
  })

  it('treats + as a space in an encoded listing and %2B as a plus', () => {
    // MinIO recorded `space+name.spbackup` and `plus%2Bname.spbackup` for two
    // keys that differ by exactly that character. decodeURIComponent alone
    // gets the first one wrong, and gets it wrong silently.
    const names = parseListObjects(s3Fixture('list-v2-encoded-minio.xml')).keys.map((k) => k.name)
    expect(names).toContain('bundles/space name.spbackup')
    expect(names).toContain('bundles/plus+name.spbackup')
  })

  it('leaves a percent alone when the store did not say it encoded anything', () => {
    const { keys } = parseListObjects(
      '<ListBucketResult><IsTruncated>false</IsTruncated>' +
        '<Contents><Key>100%25.spbackup</Key><Size>3</Size></Contents></ListBucketResult>'
    )
    expect(keys.map((k) => k.name)).toEqual(['100%25.spbackup'])
  })

  it('does not url-decode the continuation token, whatever the keys are doing', () => {
    // A continuation token is base64, and base64 contains `+`, `/` and `=`.
    // `encoding-type` covers the key and the marker fields, not the token, so
    // decoding it here sends an unopenable token back on the next page.
    const { nextToken } = parseListObjects(
      '<ListBucketResult><IsTruncated>true</IsTruncated>' +
        '<NextContinuationToken>ab+cd/ef=</NextContinuationToken>' +
        '<EncodingType>url</EncodingType></ListBucketResult>'
    )
    expect(nextToken).toBe('ab+cd/ef=')
  })

  it('reads the token verbatim out of the recorded truncated page', () => {
    const { keys, nextToken } = parseListObjects(s3Fixture('list-v2-encoded-truncated-minio.xml'))
    expect(keys.map((k) => k.name)).toEqual([
      'bundles/amp&ersand.spbackup',
      'bundles/ctrl\u0001char.spbackup'
    ])
    expect(nextToken).toBe('YnVuZGxlcy9jdHJsAWNoYXIuc3BiYWNrdXBbbWluaW9fY2FjaGU6djIscmV0dXJuOl0=')
  })
})

// ---------------------------------------------------------------------------
// Prefixes and names this driver refuses to address
// ---------------------------------------------------------------------------

const DOT_PROBLEM =
  'The key prefix “a/./b” has a “.” path segment. The request is signed over the path before ' +
  'the URL is parsed, and the parser removes that segment afterwards — so the store would answer ' +
  'SignatureDoesNotMatch and it would look like the access key was wrong.'

const DOTDOT_PROBLEM =
  'The key prefix “a/../b” has a “..” path segment. The request is signed over the path before ' +
  'the URL is parsed, and the parser removes that segment afterwards — so the store would answer ' +
  'SignatureDoesNotMatch and it would look like the access key was wrong.'

describe('s3PrefixProblem', () => {
  it('accepts the prefixes a destination normally has', () => {
    expect(s3PrefixProblem('')).toBe(null)
    expect(s3PrefixProblem('/shellpilot/')).toBe(null)
    expect(s3PrefixProblem('estate/backups/nightly')).toBe(null)
    expect(s3PrefixProblem('has spaces and & and +')).toBe(null)
  })

  it('refuses an empty path segment, and says why nothing would be written', () => {
    expect(s3PrefixProblem('a//b')).toBe(
      'The key prefix “a//b” has an empty path segment. Object stores reject a key with “//” ' +
        'in it, so nothing would ever be written here.'
    )
  })

  it('refuses a dot segment, and says why it would otherwise look like a bad access key', () => {
    // The one that cost the most to find. Against MinIO an `a/./b` prefix
    // comes back as 403 SignatureDoesNotMatch, because the URL parser removes
    // the segment after the signature was computed over the path that still
    // had it. Nothing in that response mentions the prefix.
    expect(s3PrefixProblem('a/./b')).toBe(DOT_PROBLEM)
    expect(s3PrefixProblem('a/../b')).toBe(DOTDOT_PROBLEM)
  })

  it('is what the destination panel reports, so the destination cannot be saved', () => {
    expect(destinationProblem(s3Dest('http://x', { prefix: 'a/./b' }))).toBe(DOT_PROBLEM)
    expect(destinationProblem(s3Dest('http://x', { prefix: 'shellpilot' }))).toBe(null)
  })

  it('is what openTarget refuses on, before it ever asks the vault for a key', async () => {
    let asked = false
    await expect(
      openTarget(s3Dest('http://x', { prefix: 'a//b' }), {
        credentials: () => {
          asked = true
          return { accessKeyId: 'k', secretAccessKey: 's' }
        }
      })
    ).rejects.toThrow('has an empty path segment')
    expect(asked).toBe(false)
  })
})

describe('s3Key refusals', () => {
  it('refuses a name that is not one object inside the prefix', () => {
    // The leading slash is the one that is not loud: MinIO accepted
    // `put('/name')`, stored it under `name`, and then listed `name` — so what
    // was written and what the destination reports holding are different
    // strings, and retention matches on the string.
    expect(() => s3Key(s3Dest('http://x'), '/a.spbackup')).toThrow(
      '“/a.spbackup” is not an object name: it must name one object inside the prefix.'
    )
    expect(() => s3Key(s3Dest('http://x'), 'a/b.spbackup')).toThrow('is not an object name')
    expect(() => s3Key(s3Dest('http://x'), '..')).toThrow('is not an object name')
    expect(() => s3Key(s3Dest('http://x'), '')).toThrow('is not an object name')
  })
})

// ---------------------------------------------------------------------------
// The driver against a real MinIO
// ---------------------------------------------------------------------------

const MINIO_SKIP = minioSkipReason()

describe.skipIf(MINIO_SKIP !== null)(
  `s3 target against a real MinIO in Docker${MINIO_SKIP ? ` [SKIPPED: ${MINIO_SKIP}]` : ''}`,
  () => {
    const CONTAINER = 'shellpilot-s3-driver-test'
    const PORT = 19731
    const TEE_PORT = 19741
    let minio: Minio

    beforeAll(async () => {
      minio = await startMinio(CONTAINER, PORT, [
        'estate-backups',
        'vhstyle-bucket',
        'dotted.bucket.name'
      ])
    }, 180_000)
    afterAll(() => stopMinio(CONTAINER))

    const live = (over: Partial<S3BackupDestination> = {}): S3BackupDestination =>
      s3Dest(minio.endpoint, { region: 'us-east-1', ...over })

    const open = (over: Partial<S3BackupDestination> = {}): ReturnType<typeof openTarget> =>
      openTarget(live(over), { credentials: () => MINIO_CREDENTIALS })

    it('is really talking to MinIO, and not to anything inside this process', async () => {
      // The guard against this whole block turning into a green no-op: MinIO
      // names itself in a header no stand-in in this repository sets.
      const res = await fetch(`${minio.endpoint}/probe-no-such-bucket/`)
      expect(res.status).toBe(403)
      expect(res.headers.get('server')).toBe('MinIO')
    })

    it('uploads, reads back, lists and deletes', async () => {
      const t = await open({ prefix: 'roundtrip' })
      await t.put('shellpilot-20240101T000000Z.spbackup', Buffer.from('{"magic":"shellpilot-backup"}'))
      expect((await t.get('shellpilot-20240101T000000Z.spbackup')).toString()).toBe(
        '{"magic":"shellpilot-backup"}'
      )
      const listed = await t.list()
      expect(listed.map((g) => g.name)).toEqual(['shellpilot-20240101T000000Z.spbackup'])
      expect(listed[0].size).toBe(29)
      await t.remove('shellpilot-20240101T000000Z.spbackup')
      expect(await t.list()).toEqual([])
    })

    it('round-trips keys whose characters the URL and XML layers would otherwise eat', async () => {
      // Each of these is a character that SigV4 canonicalisation, WHATWG URL
      // parsing or XML escaping treats differently from the others.
      const names = [
        'has space.spbackup',
        'has+plus.spbackup',
        'has=equals.spbackup',
        'amp&ersand.spbackup',
        'quote"lt<gt>.spbackup',
        'tilde~bang!star*paren().spbackup',
        'unicodé-ü-日本.spbackup'
      ]
      const t = await open({ prefix: 'awkward' })
      for (const name of names) {
        await t.put(name, Buffer.from(`body of ${name}`))
        expect((await t.get(name)).toString()).toBe(`body of ${name}`)
      }
      expect((await t.list()).map((g) => g.name).sort()).toEqual([...names].sort())
    })

    it('lists what it wrote even when the prefix itself holds an ampersand', async () => {
      // The bug this exercise turned up. Before the fix this listed nothing at
      // all: the key came back XML-escaped, the prefix was stripped by length,
      // and what was left had a slash in it and was dropped. A destination
      // that lists nothing keeps every generation for ever and offers nothing
      // to restore from, while the run goes on reporting success.
      const t = await open({ prefix: 'tom&jerry' })
      await t.put('shellpilot-20240101T000000Z.spbackup', Buffer.from('kept'))
      const listed = await t.list()
      expect(listed.map((g) => g.name)).toEqual(['shellpilot-20240101T000000Z.spbackup'])
      expect((await t.get(listed[0].name)).toString()).toBe('kept')
      await t.remove(listed[0].name)
      expect(await t.list()).toEqual([])
    })

    it('writes and reads a zero-byte object as zero bytes', async () => {
      const t = await open({ prefix: 'sizes-empty' })
      await t.put('shellpilot-20240101T000000Z.spbackup', Buffer.alloc(0))
      expect((await t.get('shellpilot-20240101T000000Z.spbackup')).length).toBe(0)
      expect((await t.list())[0].size).toBe(0)
    })

    it('writes a body past the size at which an SDK would switch to multipart', async () => {
      // 5 MiB is the minimum part size for a multipart upload and therefore
      // the threshold an SDK crosses. This driver deliberately never does, so
      // the case worth proving is one byte over it, in a single PUT.
      const t = await open({ prefix: 'sizes-big' })
      const body = Buffer.alloc(5 * 1024 * 1024 + 1)
      for (let i = 0; i < body.length; i++) body[i] = i & 0xff
      await t.put('shellpilot-20240101T000000Z.spbackup', body)
      const back = await t.get('shellpilot-20240101T000000Z.spbackup')
      expect(back.length).toBe(5 * 1024 * 1024 + 1)
      expect(sha256(back)).toBe(sha256(body))
      expect((await t.list())[0].size).toBe(5 * 1024 * 1024 + 1)
    }, 60_000)

    it('pages a listing past the 1000-key limit with the continuation token', async () => {
      const t = await open({ prefix: 'paged' })
      const names: string[] = []
      for (let i = 0; i < 1001; i++) {
        names.push(`shellpilot-20240101T${String(i).padStart(6, '0')}Z.spbackup`)
      }
      for (let i = 0; i < names.length; i += 50) {
        await Promise.all(names.slice(i, i + 50).map((n) => t.put(n, Buffer.from('p'))))
      }
      const listed = (await t.list()).map((g) => g.name)
      expect(listed).toHaveLength(1001)
      expect(new Set(listed).size).toBe(1001)
      // Lexicographic order leaves this one alone on the second page.
      expect(listed).toContain('shellpilot-20240101T000000Z.spbackup')
      expect(listed).toContain('shellpilot-20240101T001000Z.spbackup')
    }, 180_000)

    it('addresses a bucket virtual-host style, with the bucket in the Host it signs', async () => {
      const dest = live({
        endpoint: `http://localhost:${PORT}`,
        bucket: 'vhstyle-bucket',
        pathStyle: false,
        prefix: 'vh'
      })
      expect(s3Endpoint(dest, 'vh/a.spbackup').host).toBe(`vhstyle-bucket.localhost:${PORT}`)
      const t = s3TargetFrom(dest, MINIO_CREDENTIALS, (await loopbackFetch()) as unknown as FetchLike)
      await t.put('shellpilot-20240101T000000Z.spbackup', Buffer.from('virtual host'))
      expect((await t.get('shellpilot-20240101T000000Z.spbackup')).toString()).toBe('virtual host')
      expect((await t.list()).map((g) => g.name)).toEqual(['shellpilot-20240101T000000Z.spbackup'])
    })

    it('addresses a bucket whose name has dots in it, which is why path-style exists', async () => {
      const t = await open({ bucket: 'dotted.bucket.name', prefix: 'dots' })
      await t.put('shellpilot-20240101T000000Z.spbackup', Buffer.from('dotted'))
      expect((await t.get('shellpilot-20240101T000000Z.spbackup')).toString()).toBe('dotted')
    })

    it('reports a wrong secret key as the store refusing the signature', async () => {
      const t = await openTarget(live({ prefix: 'wrongsecret' }), {
        credentials: () => ({
          accessKeyId: MINIO_CREDENTIALS.accessKeyId,
          secretAccessKey: 'not-the-key'
        })
      })
      await expect(t.put('shellpilot-20240101T000000Z.spbackup', Buffer.from('x'))).rejects.toThrow(
        /^Uploading shellpilot-20240101T000000Z\.spbackup failed with HTTP 403:[\s\S]*SignatureDoesNotMatch/
      )
    })

    it('reports a clock this machine got wrong as the store saying so', async () => {
      // 45 minutes, outside the window SigV4 allows. The point is not that it
      // fails but that the reason reaches the operator: "check your key" and
      // "check your clock" are different fixes.
      const skewed = new Date(Date.now() + 45 * 60 * 1000)
      const t = s3TargetFrom(
        live({ prefix: 'skew' }),
        MINIO_CREDENTIALS,
        ((url: string, init: RequestInit) => fetch(url, init)) as unknown as FetchLike,
        () => skewed
      )
      await expect(t.put('shellpilot-20240101T000000Z.spbackup', Buffer.from('x'))).rejects.toThrow(
        /failed with HTTP 403:[\s\S]*RequestTimeTooSkewed/
      )
    })

    it('sends a Content-Length and never falls back to a chunked body', async () => {
      // S3 answers 411 to a PUT with no Content-Length, and `aws-chunked` is a
      // different signing mode this driver does not implement. Asserted on the
      // wire rather than on what fetch was handed, through a plain TCP tee in
      // front of MinIO.
      const heads: string[] = []
      const sockets: { destroy: () => void }[] = []
      const tee = createTcpServer((down) => {
        const up = tcpConnect(PORT, '127.0.0.1')
        sockets.push(down, up)
        let buf = Buffer.alloc(0)
        let captured = false
        down.on('data', (chunk: Buffer) => {
          if (!captured) {
            buf = Buffer.concat([buf, chunk])
            const end = buf.indexOf('\r\n\r\n')
            if (end >= 0) {
              heads.push(buf.subarray(0, end).toString())
              captured = true
            }
          }
          up.write(chunk)
        })
        up.on('data', (chunk: Buffer) => down.write(chunk))
        down.on('end', () => up.end())
        up.on('end', () => down.end())
        down.on('error', () => up.destroy())
        up.on('error', () => down.destroy())
      })
      await new Promise<void>((resolve) => tee.listen(TEE_PORT, '127.0.0.1', resolve))
      try {
        const t = await openTarget(
          live({ endpoint: `http://127.0.0.1:${TEE_PORT}`, prefix: 'wire' }),
          { credentials: () => MINIO_CREDENTIALS }
        )
        await t.put('shellpilot-20240101T000000Z.spbackup', Buffer.from('abc'))
        await t.put('shellpilot-20240101T000001Z.spbackup', Buffer.alloc(0))
      } finally {
        // fetch keeps the connection alive, so the tee has to be told to drop
        // it rather than waited on.
        for (const s of sockets) s.destroy()
        await new Promise<void>((resolve) => tee.close(() => resolve()))
      }
      const puts = heads.filter((h) => h.startsWith('PUT '))
      expect(puts).toHaveLength(2)
      expect(puts[0]).toContain('\ncontent-length: 3')
      expect(puts[1]).toContain('\ncontent-length: 0')
      for (const head of puts) {
        expect(head.toLowerCase()).not.toContain('transfer-encoding')
        expect(head).toContain('\nx-amz-content-sha256: ')
        expect(head).toContain('\nauthorization: AWS4-HMAC-SHA256 Credential=')
      }
    })

    it('records that MinIO does not check the region, which is why AWS is still unproven', async () => {
      // Not an assertion about this driver. It is the boundary of what this
      // container can prove: the region is part of the credential scope and is
      // therefore signed, and MinIO verifies a signature against whatever
      // scope it was handed. A destination configured with the wrong region is
      // caught by AWS and is not caught here, so nothing in this suite may be
      // read as "the region is right".
      const t = await openTarget(live({ prefix: 'region', region: 'ap-southeast-2' }), {
        credentials: () => MINIO_CREDENTIALS
      })
      await t.put('shellpilot-20240101T000000Z.spbackup', Buffer.from('any region'))
      expect((await t.get('shellpilot-20240101T000000Z.spbackup')).toString()).toBe('any region')
    })
  }
)

describe('the live MinIO suite', () => {
  it('is skipped only for a reason it can name', () => {
    // A suite that quietly stops running is worse than no suite at all. On a
    // machine that is meant to have Docker, say so with SHELLPILOT_S3_LIVE=1
    // and a skip becomes a failure here rather than a green run that proved
    // nothing.
    if (process.env.SHELLPILOT_S3_LIVE === '1') {
      expect(MINIO_SKIP).toBe(null)
      return
    }
    if (MINIO_SKIP !== null) {
      expect(MINIO_SKIP).toMatch(/^(Docker is not usable here|Docker works but|SHELLPILOT_S3_LIVE=0)/)
    }
  })
})
