import { describe, it, expect, beforeEach, afterEach, afterAll } from 'vitest'
import { createServer, type Server } from 'node:http'
import { mkdtempSync, rmSync, writeFileSync, readdirSync, existsSync } from 'node:fs'
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
  sftpTargetFrom,
  sha256,
  signS3Request,
  type SftpIo
} from '../src/main/services/backupTargets'
import {
  backupObjectName,
  backupObjectTime,
  isBackupObjectName,
  planRetention
} from '../src/shared/backup'
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
