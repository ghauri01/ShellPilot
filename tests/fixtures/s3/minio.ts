import { execFileSync } from 'node:child_process'

/**
 * A real MinIO in Docker, for the tests that will not accept a test double.
 *
 * The S3 driver is hand-rolled SigV4 over hand-rolled XML. Every part of that
 * — the canonical request, the header set, the credential scope, the payload
 * hash, the query canonicalisation, the escaping of a key on the way out and
 * the un-escaping of it on the way back — is a place where a test double
 * written by the same person who wrote the driver agrees with the driver and
 * a real server does not. This module is how that stops being a matter of
 * opinion.
 *
 * It found two real bugs on first contact; see the README beside it.
 */

export const MINIO_IMAGE = 'quay.io/minio/minio:latest'

/** Throwaway, created and destroyed with the container, never a real key. */
export const MINIO_CREDENTIALS = {
  accessKeyId: 'spilotthrowaway',
  secretAccessKey: 'spilotthrowaway-secret-0'
}

function run(args: string[], timeout = 120_000): string {
  return execFileSync('docker', args, { encoding: 'utf8', timeout, stdio: ['ignore', 'pipe', 'pipe'] })
}

let cachedReason: string | null | undefined

/**
 * Null when the live suite can and therefore MUST run here; otherwise the
 * sentence a skipped suite prints.
 *
 * The two halves are separate on purpose. "Docker is not installed" is a
 * machine that legitimately cannot run this. "Docker is here but the image
 * could not be fetched" is a different sentence, and printing the same one for
 * both is how a suite ends up silently never running on the machine everybody
 * assumed was covering it.
 *
 * `SHELLPILOT_S3_LIVE=0` skips regardless, for someone bisecting something
 * else. `SHELLPILOT_S3_LIVE=1` is the opposite lever and is checked by a test
 * that always runs: on a machine that is supposed to have Docker, a skip is a
 * failure.
 */
export function minioSkipReason(): string | null {
  if (cachedReason !== undefined) return cachedReason
  cachedReason = computeSkipReason()
  return cachedReason
}

function computeSkipReason(): string | null {
  if (process.env.SHELLPILOT_S3_LIVE === '0') {
    return 'SHELLPILOT_S3_LIVE=0 asked for it to be skipped'
  }
  try {
    run(['version', '--format', '{{.Server.Version}}'], 30_000)
  } catch (err) {
    return `Docker is not usable here (docker version: ${short(err)})`
  }
  try {
    run(['image', 'inspect', MINIO_IMAGE, '--format', '{{.Id}}'], 30_000)
    return null
  } catch {
    /* not pulled yet — try, once */
  }
  try {
    run(['pull', '--quiet', MINIO_IMAGE], 600_000)
    return null
  } catch (err) {
    return `Docker works but ${MINIO_IMAGE} could not be pulled (${short(err)})`
  }
}

function short(err: unknown): string {
  const message = err instanceof Error ? err.message : String(err)
  return message.split('\n')[0].slice(0, 160)
}

export interface Minio {
  /** Origin, path-style addressable. */
  endpoint: string
  /** The host part, for a virtual-host-style destination. */
  host: string
  container: string
}

/**
 * Start one, with the buckets already made.
 *
 * Buckets are created with the `mc` binary that ships inside the image rather
 * than by signing a CreateBucket with this repository's own signer: a fixture
 * that is built by the code under test cannot fail in a way that tells you the
 * code under test is wrong.
 *
 * MINIO_DOMAIN is set because virtual-host addressing is one of the two
 * addressing modes the driver has to get right, and without it MinIO reads
 * `bucket.localhost/key` as the key `key` in the bucket `bucket.localhost`.
 */
export async function startMinio(container: string, port: number, buckets: string[]): Promise<Minio> {
  try {
    run(['rm', '-f', container], 60_000)
  } catch {
    /* nothing of that name was running */
  }
  run([
    'run', '-d', '--rm', '--name', container,
    '-p', `${port}:9000`,
    '-e', `MINIO_ROOT_USER=${MINIO_CREDENTIALS.accessKeyId}`,
    '-e', `MINIO_ROOT_PASSWORD=${MINIO_CREDENTIALS.secretAccessKey}`,
    '-e', 'MINIO_DOMAIN=localhost',
    MINIO_IMAGE, 'server', '/data'
  ])

  const endpoint = `http://127.0.0.1:${port}`
  const deadline = Date.now() + 60_000
  for (;;) {
    try {
      const res = await fetch(`${endpoint}/minio/health/live`)
      if (res.ok) break
    } catch {
      /* still booting */
    }
    if (Date.now() > deadline) {
      // Deliberately a throw and not a skip. Docker answered, the image is
      // here, and the container still did not come up: that is a broken
      // machine or a broken fixture, and either way the suite must not quietly
      // report that everything is fine.
      throw new Error(`MinIO ${container} did not answer on ${endpoint} within 60s`)
    }
    await new Promise((r) => setTimeout(r, 200))
  }

  run([
    'exec', container, 'sh', '-c',
    `mc alias set loc http://127.0.0.1:9000 ${MINIO_CREDENTIALS.accessKeyId} ` +
      `${MINIO_CREDENTIALS.secretAccessKey} >/dev/null && ` +
      `mc mb -p ${buckets.map((b) => `loc/${b}`).join(' ')} >/dev/null`
  ])

  return { endpoint, host: `127.0.0.1:${port}`, container }
}

export function stopMinio(container: string): void {
  try {
    run(['rm', '-f', container], 60_000)
  } catch {
    /* already gone */
  }
}

/**
 * A fetch that resolves any hostname to the loopback address.
 *
 * Only for the virtual-host-addressing tests, and only DNS is faked: the
 * request is a real signed request over a real socket to the real MinIO, and
 * the `Host:` header it carries is `<bucket>.localhost:<port>` — the string
 * the driver signed. What is stubbed is the one thing that is not the
 * driver's, namely that `*.localhost` does not resolve on this machine.
 */
export async function loopbackFetch(): Promise<typeof fetch> {
  const { Agent } = await import('undici')
  const dispatcher = new Agent({
    connect: {
      lookup: (
        _hostname: string,
        options: { all?: boolean },
        callback: (err: Error | null, address: unknown, family?: number) => void
      ): void =>
        options && options.all
          ? callback(null, [{ address: '127.0.0.1', family: 4 }])
          : callback(null, '127.0.0.1', 4)
    }
  })
  return ((url: string, init?: RequestInit) =>
    fetch(url, { ...init, dispatcher } as RequestInit)) as unknown as typeof fetch
}
