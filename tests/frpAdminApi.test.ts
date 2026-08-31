import { afterEach, describe, it, expect } from 'vitest'
import net from 'node:net'
import http from 'node:http'
import { spawn, type ChildProcessByStdio } from 'node:child_process'
import type { Readable } from 'node:stream'
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'

import type { FrpProxy, FrpSpec } from '../src/shared/vpn'
import {
  FrpAdminApi,
  frpErrorFromLine,
  frpReadinessError,
  parseFrpStatus,
  stripAnsi,
  summariseFrpProxies
} from '../src/main/services/vpn/frpAdminApi'
import { frpEnv, generateFrpToml } from '../src/main/services/vpn/frpConfig'
import { VpnError } from '../src/main/services/vpn/errors'

// These tests drive the real fake-frpc.mjs over a real loopback socket rather
// than a mocked http module: the whole point of this client is what it does
// with an actual HTTP response, an actual 401 and an actual dropped connection.

const FIXTURE = fileURLToPath(new URL('./fixtures/fake-frpc.mjs', import.meta.url))
const ADMIN_USER = 'shellpilot'
const ADMIN_PASSWORD = 'run-password-7c1e'
const TOKEN = 'tok_live_9d2f'

function proxy(over: Partial<FrpProxy> = {}): FrpProxy {
  return {
    name: 'postgres',
    type: 'tcp',
    localIp: '127.0.0.1',
    localPort: 5432,
    remotePort: 15432,
    acknowledgedExposure: true,
    ...over
  }
}

function makeSpec(proxies: FrpProxy[]): FrpSpec {
  return {
    kind: 'frp',
    serverAddr: 'frp.example.com',
    serverPort: 7000,
    auth: { method: 'token', tokenRef: { vaultEntryId: 'v1', field: 'token' } },
    transport: { protocol: 'tcp', tlsEnable: true },
    proxies,
    visitors: []
  }
}

// ------------------------------------------------------------- harness

const cleanups: (() => void)[] = []

afterEach(() => {
  while (cleanups.length) cleanups.pop()?.()
})

/** Bind :0, note the port, release it. Same trick the driver uses to pick the
 *  admin port: frpc has no "tell me the port you chose" channel. */
function freePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const srv = net.createServer()
    srv.once('error', reject)
    srv.listen(0, '127.0.0.1', () => {
      const addr = srv.address()
      const port = typeof addr === 'object' && addr ? addr.port : 0
      srv.close(() => resolve(port))
    })
  })
}

interface Fake {
  api: FrpAdminApi
  child: ChildProcessByStdio<null, Readable, Readable>
  port: number
  toml: string
  stdout: string[]
  stderr: string[]
  exited: Promise<number | null>
}

async function startFake(
  spec: FrpSpec,
  failArgs: string[] = [],
  opts: { timeoutMs?: number } = {}
): Promise<Fake> {
  const port = await freePort()
  const dir = mkdtempSync(join(tmpdir(), 'sp-frp-'))
  cleanups.push(() => rmSync(dir, { recursive: true, force: true }))

  const run = { adminPort: port, adminUser: ADMIN_USER, adminPassword: ADMIN_PASSWORD }
  const toml = generateFrpToml(spec, run)
  const cfg = join(dir, 'frpc.toml')
  writeFileSync(cfg, toml, { mode: 0o600 })

  const env = frpEnv(spec, { token: TOKEN, proxySecretKeys: {}, pluginPasswords: {} }, run)
  const child = spawn(process.execPath, [FIXTURE, '-c', cfg, ...failArgs], {
    env: { ...process.env, ...env },
    stdio: ['ignore', 'pipe', 'pipe']
  })
  cleanups.push(() => {
    if (child.exitCode === null && child.signalCode === null) child.kill('SIGKILL')
  })

  const stdout: string[] = []
  const stderr: string[] = []
  child.stdout.setEncoding('utf8')
  child.stderr.setEncoding('utf8')
  child.stdout.on('data', (c: string) => stdout.push(...c.split('\n').filter(Boolean)))
  child.stderr.on('data', (c: string) => stderr.push(...c.split('\n').filter(Boolean)))
  const exited = new Promise<number | null>((resolve) => child.once('exit', (code) => resolve(code)))

  const api = new FrpAdminApi({
    port,
    user: ADMIN_USER,
    password: ADMIN_PASSWORD,
    timeoutMs: opts.timeoutMs ?? 4_000
  })
  return { api, child, port, toml, stdout, stderr, exited }
}

const sleep = (ms: number): Promise<void> => new Promise((r) => setTimeout(r, ms))

/** The admin listener is up and serving, whatever /healthz says about it.
 *  Needed for the wedged case, where /healthz is 503 by design. */
async function waitListening(fake: Fake, ms = 8_000): Promise<void> {
  const deadline = Date.now() + ms
  for (;;) {
    try {
      await fake.api.getConfig()
      return
    } catch {
      if (Date.now() > deadline) throw new Error(`fake frpc never listened: ${fake.stderr.join(' ')}`)
      await sleep(25)
    }
  }
}

async function waitHealthy(fake: Fake, ms = 8_000): Promise<void> {
  const deadline = Date.now() + ms
  for (;;) {
    try {
      await fake.api.healthz()
      return
    } catch {
      if (Date.now() > deadline) throw new Error(`fake frpc never answered: ${fake.stderr.join(' ')}`)
      await sleep(25)
    }
  }
}

// ------------------------------------------------------------------ tests

describe('FrpAdminApi against a live fake frpc', () => {
  it('polls /api/status until every proxy is running, and maps the fields', async () => {
    const spec = makeSpec([proxy(), proxy({ name: 'redis', localPort: 6379, remotePort: 16379 })])
    const fake = await startFake(spec)
    await waitHealthy(fake)

    const readiness = await fake.api.waitForReady(['postgres', 'redis'], { timeoutMs: 8_000 })
    expect(readiness.ready).toBe(true)
    expect(readiness.timedOut).toBe(false)
    expect(readiness.failed).toEqual([])
    expect(readiness.missing).toEqual([])

    const byName = new Map(readiness.proxies.map((p) => [p.name, p]))
    expect(byName.get('postgres')).toMatchObject({
      name: 'postgres',
      type: 'tcp',
      status: 'running',
      localAddr: '127.0.0.1:5432',
      remoteAddr: ':15432'
    })
    // frp reports no byte counters at all, so there is nothing to map onto
    // rxBytes/txBytes and we do not invent any.
    expect(byName.get('postgres')).not.toHaveProperty('rxBytes')
    expect(byName.get('redis')?.status).toBe('running')

    expect(summariseFrpProxies(readiness.proxies, ['postgres', 'redis'])).toEqual({
      state: 'connected'
    })

    // The log-capture path saw frpc-shaped lines on stdout — coloured, which
    // is why nothing matches until stripAnsi has run.
    const loginRaw = fake.stdout.find((l) => l.includes('login to server success'))
    expect(loginRaw).toBeDefined()
    expect(loginRaw).toContain('\u001b[')
    expect(
      /^\d{4}-\d\d-\d\d \d\d:\d\d:\d\d\.\d{3} \[I\] \[client\/service\.go:\d+\]/.test(
        stripAnsi(loginRaw as string)
      )
    ).toBe(true)
  })

  it('surfaces a proxy in `start error` as degraded, with frpc’s own wording', async () => {
    const spec = makeSpec([proxy(), proxy({ name: 'redis', localPort: 6379, remotePort: 16379 })])
    const fake = await startFake(spec, ['--fail', 'proxy-port'])
    await waitHealthy(fake)

    const readiness = await fake.api.waitForReady(['postgres', 'redis'], { timeoutMs: 8_000 })
    expect(readiness.ready).toBe(false)
    // It gives up as soon as the proxy reaches a terminal error rather than
    // burning the full 30 s: the error is no more useful later.
    expect(readiness.timedOut).toBe(false)
    expect(readiness.failed).toHaveLength(1)
    expect(readiness.failed[0].name).toBe('postgres')
    expect(readiness.failed[0].err).toContain('port already used')

    const summary = summariseFrpProxies(readiness.proxies, ['postgres', 'redis'])
    expect(summary.state).toBe('degraded')
    // Verbatim: frp already said something actionable and a rewrite says less.
    expect(summary.error).toContain(readiness.failed[0].err as string)
    expect(summary.errorCode).toBe('port-in-use')
  })

  it('times out rather than waiting forever when the engine wedges', async () => {
    const fake = await startFake(makeSpec([proxy()]), ['--fail', 'wedge'])
    await waitListening(fake)
    // /healthz stays 503 in this mode, which is what the supervisor's health
    // check would see; the admin API itself is still answering.
    await expect(fake.api.healthz()).rejects.toBeInstanceOf(VpnError)

    const readiness = await fake.api.waitForReady(['postgres'], {
      timeoutMs: 700,
      intervalMs: 100
    })
    expect(readiness.ready).toBe(false)
    expect(readiness.timedOut).toBe(true)
    expect(readiness.failed).toEqual([])
    expect(summariseFrpProxies(readiness.proxies, ['postgres']).state).toBe('starting')

    // A wedged client never logged in, so the table is empty and the honest
    // report is "the server did not accept a connection", not "timed out".
    expect(readiness.proxies).toEqual([])
    expect(frpReadinessError(readiness).code).toBe('server-rejected')
  })

  it('does not mistake the pre-login `200 {}` for a healthy tunnel', async () => {
    // frpc answers /api/status with an empty object until it has reached frps.
    // Iterating that response would report every configured proxy as fine.
    const fake = await startFake(makeSpec([proxy()]))
    await waitHealthy(fake)

    const early = await fake.api.status()
    if (early.length === 0) {
      expect(summariseFrpProxies(early, ['postgres']).state).toBe('starting')
      const readiness = await fake.api.waitForReady(['postgres'], {
        timeoutMs: 1,
        intervalMs: 1
      })
      if (readiness.proxies.length === 0) {
        expect(readiness.ready).toBe(false)
        expect(readiness.missing).toEqual(['postgres'])
      }
    }

    // And once it has logged in, the same call is ready.
    expect((await fake.api.waitForReady(['postgres'], { timeoutMs: 8_000 })).ready).toBe(true)
  })

  it('round-trips a hot reload: PUT /api/config then GET /api/reload', async () => {
    const spec = makeSpec([proxy()])
    const fake = await startFake(spec)
    await waitHealthy(fake)
    await fake.api.waitForReady(['postgres'], { timeoutMs: 8_000 })

    // Returned verbatim, templates unexpanded: the admin API is not a way to
    // read the token back out.
    const active = await fake.api.getConfig()
    expect(active).toBe(fake.toml)
    expect(active).toContain('auth.token  = "{{ .Envs.SP_FRP_TOKEN }}"')
    expect(active).not.toContain(TOKEN)
    expect(active).not.toContain(ADMIN_PASSWORD)

    const next = generateFrpToml(
      makeSpec([proxy(), proxy({ name: 'redis', localPort: 6379, remotePort: 16379 })]),
      { adminPort: fake.port, adminUser: ADMIN_USER }
    )
    await fake.api.reload(next)

    const afterReload = await fake.api.getConfig()
    expect(afterReload).toBe(next)
    // The round-trip sent templates, so no secret was ever written into frpc's
    // in-memory config.
    expect(afterReload).not.toContain(TOKEN)
    expect(afterReload).not.toContain(ADMIN_PASSWORD)
    const readiness = await fake.api.waitForReady(['postgres', 'redis'], { timeoutMs: 8_000 })
    expect(readiness.ready).toBe(true)

    // And the control connection was never dropped: no relogin line appeared.
    const logins = fake.stdout.filter((l) => l.includes('login to server success'))
    expect(logins).toHaveLength(1)

    const detail = await fake.api.proxyConfig('redis')
    expect(detail).toMatchObject({ name: 'redis', type: 'tcp' })
  })

  it('stops gracefully through POST /api/stop, tolerating the reply being cut short', async () => {
    const fake = await startFake(makeSpec([proxy()]))
    await waitHealthy(fake)

    await fake.api.stop()
    expect(await fake.exited).toBe(0)
    expect(fake.stdout.some((l) => l.includes('received stop request'))).toBe(true)
  })

  it('is refused by HTTP Basic when the per-run password is wrong', async () => {
    const fake = await startFake(makeSpec([proxy()]))
    await waitHealthy(fake)

    const wrong = new FrpAdminApi({
      port: fake.port,
      user: ADMIN_USER,
      password: 'not-the-run-password',
      timeoutMs: 4_000
    })
    // /healthz needs no credentials at all, so it stays green: liveness and
    // authorisation are separate questions and the client must not conflate
    // them.
    await expect(wrong.healthz()).resolves.toBeUndefined()

    const err = await wrong.status().catch((e: unknown) => e)
    expect(err).toBeInstanceOf(VpnError)
    expect((err as VpnError).code).toBe('permission-denied')
    // The message names the control channel, not the user's frps credentials.
    expect((err as VpnError).message).toContain('127.0.0.1')

    // The correct credentials still work, so this was authentication and not a
    // wedged server.
    expect((await fake.api.waitForReady(['postgres'], { timeoutMs: 8_000 })).ready).toBe(true)
  })

  it('reports an auth failure and a version mismatch with the right code', async () => {
    const authFake = await startFake(makeSpec([proxy()]), ['--fail', 'auth'])
    expect(await authFake.exited).toBe(1)
    const authLine = authFake.stderr.find((l) => l.includes('login to server failed'))
    expect(authLine).toBeDefined()
    expect(frpErrorFromLine(authLine as string)?.code).toBe('auth-failed')

    const versionFake = await startFake(makeSpec([proxy()]), ['--fail', 'version'])
    expect(await versionFake.exited).toBe(1)
    const versionLine = versionFake.stderr.find((l) => l.includes('login to server failed'))
    expect(frpErrorFromLine(versionLine as string)?.code).toBe('version-mismatch')

    // A login failure with no more specific cause is still classified.
    expect(frpErrorFromLine('login to server failed: i/o timeout')?.code).toBe('server-rejected')
    expect(frpErrorFromLine('start frpc service')).toBeNull()

    // frpc puts the same failure on stdout, coloured. It has to classify the
    // same way there, which it only does once the escapes are stripped.
    const colouredLine = authFake.stdout.find((l) => l.includes('login to server failed'))
    expect(colouredLine).toContain('\u001b[')
    expect(frpErrorFromLine(colouredLine as string)?.code).toBe('auth-failed')
  })

  it('exits after --fail crash-after, having served normally until then', async () => {
    const fake = await startFake(makeSpec([proxy()]), ['--fail', 'crash-after', '1500'])
    await waitHealthy(fake)
    expect((await fake.api.waitForReady(['postgres'], { timeoutMs: 8_000 })).ready).toBe(true)
    expect(await fake.exited).toBe(1)
    expect(fake.stderr.join('\n')).toContain('control connection closed unexpectedly')
  })

  it('reports its version the way the probe expects', async () => {
    const child = spawn(process.execPath, [FIXTURE, '--version'])
    let out = ''
    child.stdout.setEncoding('utf8')
    child.stdout.on('data', (c: string) => {
      out += c
    })
    await new Promise((r) => child.once('exit', r))
    // The real frpc prints the bare version and nothing else.
    expect(out.trim()).toBe('0.71.0')
  })
})

// ------------------------------------------------- transport-level rules

describe('FrpAdminApi transport rules', () => {
  function serve(handler: http.RequestListener): Promise<{ port: number }> {
    return new Promise((resolve) => {
      const srv = http.createServer(handler)
      cleanups.push(() => srv.close())
      srv.listen(0, '127.0.0.1', () => {
        const addr = srv.address()
        resolve({ port: typeof addr === 'object' && addr ? addr.port : 0 })
      })
    })
  }

  const clientFor = (port: number, timeoutMs = 250): FrpAdminApi =>
    new FrpAdminApi({ port, user: ADMIN_USER, password: ADMIN_PASSWORD, timeoutMs })

  it('gives up on a responder that never answers', async () => {
    // Accepts the connection, reads the request, then says nothing at all.
    const { port } = await serve(() => {})
    const err = await clientFor(port).status().catch((e: unknown) => e)
    expect(err).toBeInstanceOf(VpnError)
    expect((err as VpnError).code).toBe('internal')
    expect((err as VpnError).message).toContain('within 250 ms')
  })

  it('does not follow a redirect off 127.0.0.1', async () => {
    const { port } = await serve((_req, res) => {
      res.writeHead(302, { location: 'http://169.254.169.254/latest/meta-data/' })
      res.end()
    })
    const err = await clientFor(port).status().catch((e: unknown) => e)
    expect(err).toBeInstanceOf(VpnError)
    expect((err as VpnError).message).toContain('redirect')
  })

  it('refuses to buffer an unbounded response body', async () => {
    const { port } = await serve((_req, res) => {
      res.writeHead(200, { 'content-type': 'application/json' })
      const chunk = 'x'.repeat(64 * 1024)
      const pump = (): void => {
        if (res.writableEnded) return
        if (res.write(chunk)) setImmediate(pump)
        else res.once('drain', pump)
      }
      pump()
    })
    const api = new FrpAdminApi({
      port,
      user: ADMIN_USER,
      password: ADMIN_PASSWORD,
      timeoutMs: 4_000,
      maxBodyBytes: 128 * 1024
    })
    const err = await api.status().catch((e: unknown) => e)
    expect(err).toBeInstanceOf(VpnError)
    expect((err as VpnError).message).toContain('more than 131072 bytes')
  })

  it('classifies a non-2xx body rather than showing a bare status code', async () => {
    const { port } = await serve((_req, res) => {
      res.writeHead(500, { 'content-type': 'text/plain' })
      res.end('proxy name [redis] already exists')
    })
    const err = await clientFor(port, 2_000).status().catch((e: unknown) => e)
    expect((err as VpnError).code).toBe('interface-conflict')
  })
})

// ------------------------------------------------------------- parsing

describe('parseFrpStatus', () => {
  it('flattens the type-keyed object and normalises the snake_case wire names', () => {
    const proxies = parseFrpStatus(
      JSON.stringify({
        tcp: [
          {
            name: 'postgres',
            type: 'tcp',
            status: 'running',
            err: '',
            local_addr: '127.0.0.1:5432',
            remote_addr: ':15432',
            plugin: ''
          }
        ],
        stcp: [
          {
            name: 'secret-ssh',
            status: 'start error',
            err: 'proxy name already exists',
            local_addr: '127.0.0.1:22'
          }
        ],
        udp: []
      })
    )
    expect(proxies).toEqual([
      {
        name: 'postgres',
        type: 'tcp',
        status: 'running',
        err: undefined,
        localAddr: '127.0.0.1:5432',
        remoteAddr: ':15432'
      },
      {
        // No `type` on the wire: the group key stands in, which is what keeps
        // this working across an frp version that drops the field.
        name: 'secret-ssh',
        type: 'stcp',
        status: 'start error',
        err: 'proxy name already exists',
        localAddr: '127.0.0.1:22',
        remoteAddr: undefined
      }
    ])
  })

  it('ignores junk instead of throwing, but refuses a non-JSON body', () => {
    expect(parseFrpStatus('{}')).toEqual([])
    expect(parseFrpStatus(JSON.stringify({ tcp: [{ status: 'running' }] }))).toEqual([])
    expect(parseFrpStatus(JSON.stringify({ tcp: 'not-an-array' }))).toEqual([])
    expect(() => parseFrpStatus('<html>nope</html>')).toThrow(VpnError)
  })
})

describe('frpReadinessError', () => {
  const notReady = { ready: false, proxies: [], failed: [], missing: ['postgres'], timedOut: true }

  it('prefers the engine log over the timeout, most recent line first', () => {
    expect(
      frpReadinessError(notReady, [
        'try to connect to server...',
        '\u001b[1;31mlogin to server failed: authentication failed'
      ]).code
    ).toBe('auth-failed')
    expect(
      frpReadinessError(notReady, ['login to server failed: version mismatch']).code
    ).toBe('version-mismatch')
  })

  it('says the server never accepted a connection when the table is empty', () => {
    expect(frpReadinessError(notReady).code).toBe('server-rejected')
  })

  it('names the proxies that never started when some did', () => {
    const partial = {
      ready: false,
      proxies: [{ name: 'redis', type: 'tcp', status: 'running' }],
      failed: [],
      missing: ['postgres'],
      timedOut: true
    }
    const err = frpReadinessError(partial)
    expect(err.code).toBe('handshake-timeout')
    expect(err.message).toContain('postgres')
  })
})

describe('stripAnsi', () => {
  it('removes the colour frpc wraps every line in, reset prefix included', () => {
    const line =
      '\u001b[0m\u001b[1;34m2026-08-27 01:40:38.636 [I] [client/service.go:254] admin server listen on 127.0.0.1:41731'
    expect(stripAnsi(line)).toBe(
      '2026-08-27 01:40:38.636 [I] [client/service.go:254] admin server listen on 127.0.0.1:41731'
    )
    expect(stripAnsi('plain')).toBe('plain')
  })
})

describe('summariseFrpProxies', () => {
  const running = { name: 'a', type: 'tcp', status: 'running' }

  it('is starting while proxies are still coming up', () => {
    expect(
      summariseFrpProxies([{ name: 'a', type: 'tcp', status: 'wait start' }], ['a']).state
    ).toBe('starting')
  })

  it('never reports connected off an empty table, however it got there', () => {
    // The pre-login `200 {}` case, and the "expected nothing" case that would
    // otherwise let it through.
    expect(summariseFrpProxies([], ['a']).state).toBe('starting')
    expect(summariseFrpProxies([], []).state).toBe('starting')
    expect(summariseFrpProxies([running], []).state).toBe('starting')
  })

  it('is starting, not connected, when an expected proxy is missing entirely', () => {
    expect(summariseFrpProxies([running], ['a', 'b'])).toEqual({ state: 'starting' })
  })

  it('names how many others also failed', () => {
    const summary = summariseFrpProxies(
      [
        { name: 'a', type: 'tcp', status: 'start error', err: 'port already used' },
        { name: 'b', type: 'tcp', status: 'start error', err: 'proxy name already exists' }
      ],
      ['a', 'b']
    )
    expect(summary.state).toBe('degraded')
    expect(summary.error).toBe('Proxy "a": port already used (and 1 more)')
    expect(summary.errorCode).toBe('port-in-use')
  })
})
