import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import net from 'node:net'
import { spawn as nodeSpawn } from 'node:child_process'
import type { ChildProcess, SpawnOptions } from 'node:child_process'
import { createHash } from 'node:crypto'
import {
  chmodSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  statSync,
  writeFileSync
} from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'

import type { FrpProxy, FrpSpec, FrpVisitor, VpnProfile, VpnStatus } from '../src/shared/vpn'
import { resetBinaryCache } from '../src/main/services/vpn/binaries'
import type { ResolvedVpnSecrets, VpnDriverContext } from '../src/main/services/vpn/driver'
import {
  frpDriver,
  frpSecretsFrom,
  frpTuning,
  reserveAdminPort
} from '../src/main/services/vpn/drivers/frp'
import { Supervisor } from '../src/main/services/vpn/supervisor'

// The whole point of this driver is what it does with a real process, a real
// admin socket and real ANSI-coloured output arriving on stdout, so nothing
// here is mocked: the tests drive tests/fixtures/fake-frpc.mjs through the real
// Supervisor, and the driver resolves it through the real bundled-binary
// resolver by way of a shim on disk with a matching manifest hash.

const FIXTURE = fileURLToPath(new URL('./fixtures/fake-frpc.mjs', import.meta.url))
const PLATFORM_DIR = `${process.platform}-${process.arch}`
const FRPC = process.platform === 'win32' ? 'frpc.exe' : 'frpc'
const TOKEN = 'tok_live_a41f9c'
const PLUGIN_PASSWORD = 'pw_plugin_5521'

let root: string
let runDir: string
let binRoot: string
let supervisor: Supervisor
let previousBinDir: string | undefined
const cleanups: (() => void)[] = []

interface Spawned {
  command: string
  args: readonly string[]
  options: SpawnOptions
}

let spawns: Spawned[] = []

// ---------------------------------------------------------------- fixtures

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

function makeSpec(proxies: FrpProxy[], visitors: FrpVisitor[] = []): FrpSpec {
  return {
    kind: 'frp',
    serverAddr: 'frp.example.com',
    serverPort: 7000,
    auth: { method: 'token', tokenRef: { vaultEntryId: 'v1', field: 'token' } },
    transport: { protocol: 'tcp', tlsEnable: true },
    proxies,
    visitors
  }
}

function makeProfile(spec: FrpSpec): VpnProfile & { spec: FrpSpec } {
  return { id: 'vpn-frp-1', workspaceId: 'ws', name: 'Office frp', autoStart: false, spec }
}

function makeSecrets(over: Partial<ResolvedVpnSecrets> = {}): ResolvedVpnSecrets {
  const secrets: ResolvedVpnSecrets = { token: TOKEN, all: [], ...over }
  secrets.all = [
    secrets.token,
    ...Object.values(secrets.proxySecretKeys ?? {})
  ].filter((s): s is string => typeof s === 'string')
  return secrets
}

interface Ctx {
  ctx: VpnDriverContext
  patches: Partial<VpnStatus>[]
  logs: string[]
  states: () => string[]
}

function makeCtx(secrets = makeSecrets()): Ctx {
  const patches: Partial<VpnStatus>[] = []
  const logs: string[] = []
  return {
    ctx: {
      runDir,
      secrets,
      emit: (p) => patches.push(p),
      log: (line) => logs.push(line),
      askUser: async () => null,
      supervisor
    },
    patches,
    logs,
    states: () => patches.map((p) => p.state).filter((s): s is string => typeof s === 'string')
  }
}

/** A `frpc` the resolver will accept: an executable whose hash is in the
 *  manifest beside it. It forwards to the fixture and appends whatever failure
 *  mode the test asked for, which is how `--fail auth` reaches a child the
 *  driver spawned rather than one the test did. */
function installFrpcShim(): void {
  const dir = join(binRoot, PLATFORM_DIR)
  mkdirSync(dir, { recursive: true })
  const file = join(dir, FRPC)
  const node = JSON.stringify(process.execPath)
  const body = `#!/bin/sh\nexec ${node} ${JSON.stringify(FIXTURE)} "$@" $SP_TEST_FRP_FAIL\n`
  writeFileSync(file, body)
  chmodSync(file, 0o755)
  writeFileSync(
    join(binRoot, 'manifest.json'),
    JSON.stringify({
      version: '0.1.0',
      binaries: {
        [`${PLATFORM_DIR}/${FRPC}`]: { sha256: createHash('sha256').update(body).digest('hex') }
      }
    })
  )
}

function failMode(args: string): void {
  process.env.SP_TEST_FRP_FAIL = args
  cleanups.push(() => delete process.env.SP_TEST_FRP_FAIL)
}

// ----------------------------------------------------------------- helpers

const sleep = (ms: number): Promise<void> => new Promise((r) => setTimeout(r, ms))

async function waitFor(what: string, fn: () => boolean, ms = 10_000): Promise<void> {
  const deadline = Date.now() + ms
  for (;;) {
    if (fn()) return
    if (Date.now() > deadline) throw new Error(`never became true: ${what}`)
    await sleep(20)
  }
}

/** Holds a port for as long as the test needs it, so the driver's chosen admin
 *  port is genuinely unavailable when frpc tries to bind it. */
async function occupyPort(): Promise<number> {
  const port = await reserveAdminPort()
  const srv = net.createServer()
  await new Promise<void>((resolve) => srv.listen(port, '127.0.0.1', resolve))
  cleanups.push(() => srv.close())
  return port
}

function configText(): string {
  return readFileSync(join(runDir, 'frpc.toml'), 'utf8')
}

beforeEach(() => {
  root = mkdtempSync(join(tmpdir(), 'sp-frpdrv-'))
  runDir = join(root, 'run')
  binRoot = join(root, 'bin')
  mkdirSync(runDir, { recursive: true, mode: 0o700 })
  installFrpcShim()

  previousBinDir = process.env.SHELLPILOT_VPN_BIN_DIR
  process.env.SHELLPILOT_VPN_BIN_DIR = binRoot
  resetBinaryCache()

  spawns = []
  supervisor = new Supervisor({
    runRoot: join(root, 'pids'),
    spawn: (command, args, options): ChildProcess => {
      spawns.push({ command, args, options })
      return nodeSpawn(command, args, options)
    }
  })

  // Shorter than production so a wedged engine does not hold a test for half a
  // minute. Everything else keeps its real value.
  frpTuning.readinessTimeoutMs = 3_000
  frpTuning.reloadTimeoutMs = 3_000
})

afterEach(async () => {
  await frpDriver.disposeAll?.().catch(() => undefined)
  await supervisor.stopAll().catch(() => undefined)
  while (cleanups.length) cleanups.pop()?.()
  frpTuning.readinessTimeoutMs = 30_000
  frpTuning.reloadTimeoutMs = 10_000
  frpTuning.adminPortAttempts = 3
  frpTuning.adminPortPicker = null
  if (previousBinDir === undefined) delete process.env.SHELLPILOT_VPN_BIN_DIR
  else process.env.SHELLPILOT_VPN_BIN_DIR = previousBinDir
  resetBinaryCache()
  rmSync(root, { recursive: true, force: true })
})

// ------------------------------------------------------------------- tests

describe('frp driver lifecycle', () => {
  it('starts, reaches ready, reports the proxy table, reloads and stops gracefully', async () => {
    const profile = makeProfile(makeSpec([proxy()]))
    const c = makeCtx()

    const started = await frpDriver.start(profile, c.ctx)
    expect(started).toEqual({ ok: true, listeners: [] })
    expect(frpDriver.status(profile.id)?.state).toBe('connected')

    // frp reports no client-side byte counters anywhere, so the fields are
    // absent rather than zero: a zero would read as "no traffic".
    const stats = await frpDriver.stats(profile.id)
    expect(stats).not.toBeNull()
    expect(Object.keys(stats ?? {})).not.toContain('rxBytes')
    expect(Object.keys(stats ?? {})).not.toContain('txBytes')
    expect(stats?.proxies).toEqual([
      {
        name: 'postgres',
        type: 'tcp',
        status: 'running',
        err: undefined,
        localAddr: '127.0.0.1:5432',
        remoteAddr: ':15432'
      }
    ])

    // Hot reload: frp is the only engine that can take a new proxy set without
    // dropping its control connection, so the same child serves both.
    const pidBefore = spawns.length
    const grown = makeSpec([proxy(), proxy({ name: 'redis', localPort: 6379, remotePort: 16379 })])
    expect(await frpDriver.reload?.(profile.id, grown)).toEqual({ ok: true })
    expect(spawns.length).toBe(pidBefore)
    const after = await frpDriver.stats(profile.id)
    expect(after?.proxies?.map((p) => `${p.name}:${p.status}`).sort()).toEqual([
      'postgres:running',
      'redis:running'
    ])
    expect(configText()).toContain('"redis"')

    await frpDriver.stop(profile.id)
    // POST /api/stop, not a signal. This is the path Windows depends on, where
    // a non-console child has no SIGTERM at all.
    expect(c.logs.some((l) => l.includes('received stop request'))).toBe(true)
    expect(frpDriver.status(profile.id)).toBeNull()
  })

  it('has no openForward: frp exposes a local port, it does not carry traffic', () => {
    expect(frpDriver.openForward).toBeUndefined()
    expect(frpDriver.kind).toBe('frp')
  })

  it('probes the bundled frpc and reports the version it printed', async () => {
    const info = await frpDriver.probe()
    expect(info.available).toBe(true)
    expect(info.bundled).toBe(true)
    expect(info.kind).toBe('frp')
    expect(info.version).toBe('0.71.0')
  })

  it('reports a missing binary as unavailable with a reason rather than throwing', async () => {
    rmSync(join(binRoot, PLATFORM_DIR, FRPC), { force: true })
    resetBinaryCache()
    const info = await frpDriver.probe()
    expect(info.available).toBe(false)
    expect(info.reason).toContain(FRPC)
  })

  it('delegates validateConfig to the shared validator', () => {
    const bad = frpDriver.validateConfig(makeSpec([proxy({ acknowledgedExposure: false })]))
    expect(bad.ok).toBe(false)
    expect(bad.issues.some((i) => i.code === 'exposure-unacknowledged')).toBe(true)
    expect(frpDriver.validateConfig(makeSpec([proxy()])).ok).toBe(true)
  })
})

describe('frp exposure gate', () => {
  it('refuses to start a profile with an unacknowledged proxy, and spawns nothing', async () => {
    const unconfirmed = proxy({
      name: 'redis',
      localPort: 6379,
      remotePort: 16379,
      acknowledgedExposure: false
    })
    const profile = makeProfile(makeSpec([proxy(), unconfirmed]))
    const c = makeCtx()

    const result = await frpDriver.start(profile, c.ctx)
    expect(result.ok).toBe(false)
    expect(result.errorCode).toBe('exposure-unacknowledged')
    // The message names the port and who would be able to reach it; "advanced
    // setting" would not be a confirmation of anything.
    expect(result.error).toContain('127.0.0.1:6379 reachable from frp.example.com')
    expect(spawns).toEqual([])
  })
})

describe('frp secret handling', () => {
  it('passes every secret through the environment and never through argv', async () => {
    const secrets = makeSecrets({
      proxySecretKeys: { 'plugin:socks': PLUGIN_PASSWORD, private: 'stcp_secret_ff21' }
    })
    const spec = makeSpec([
      proxy(),
      proxy({
        name: 'private',
        type: 'stcp',
        localPort: 22,
        remotePort: undefined,
        secretKeyRef: { vaultEntryId: 'v2', field: 'proxySecretKey' }
      })
    ])
    const profile = makeProfile(spec)
    const c = makeCtx(secrets)

    expect(await frpDriver.start(profile, c.ctx)).toMatchObject({ ok: true })

    const launched = spawns[0]
    expect(launched.args).toEqual(['-c', join(runDir, 'frpc.toml')])
    const argv = [launched.command, ...launched.args].join(' ')
    for (const literal of [TOKEN, 'stcp_secret_ff21', PLUGIN_PASSWORD]) {
      expect(argv).not.toContain(literal)
    }

    const env = launched.options.env as Record<string, string>
    expect(env.SP_FRP_TOKEN).toBe(TOKEN)
    expect(env.SP_FRP_SECRET_1).toBe('stcp_secret_ff21')
    expect(env.SP_FRP_ADMIN).toMatch(/^[A-Za-z0-9_-]{20,}$/)

    // The config file may sit on disk precisely because it holds templates
    // rather than values — but it is still 0600, because it names every port
    // this machine is about to expose.
    const toml = configText()
    expect(toml).toMatch(/auth\.token\s+= "\{\{ \.Envs\.SP_FRP_TOKEN \}\}"/)
    expect(toml).not.toContain(TOKEN)
    expect(toml).not.toContain('stcp_secret_ff21')
    if (process.platform !== 'win32') {
      expect(statSync(join(runDir, 'frpc.toml')).mode & 0o777).toBe(0o600)
    }
  })

  it('unpacks the flat resolved bundle into frp shapes', () => {
    const adapted = frpSecretsFrom({
      token: TOKEN,
      password: 'oidc_client_secret',
      proxySecretKeys: { private: 'stcp_secret', 'plugin:socks': PLUGIN_PASSWORD },
      all: []
    })
    expect(adapted.token).toBe(TOKEN)
    // The OIDC client secret rides in the one free single-value slot.
    expect(adapted.oidcClientSecret).toBe('oidc_client_secret')
    expect(adapted.proxySecretKeys?.private).toBe('stcp_secret')
    expect(adapted.pluginPasswords).toEqual({ socks: PLUGIN_PASSWORD })
  })
})

describe('frp readiness', () => {
  it('does not mistake an empty /api/status for ready', async () => {
    // `--fail wedge` never logs in to frps, so `/api/status` answers `200 {}`
    // for as long as the process lives. A readiness check that iterated the
    // response would find nothing not-running and call that success.
    failMode('--fail wedge')
    const profile = makeProfile(makeSpec([proxy()]))
    const c = makeCtx()

    const result = await frpDriver.start(profile, c.ctx)
    expect(result.ok).toBe(false)
    expect(c.states()).not.toContain('connected')
  })

  it('classifies a wedged engine from its log instead of reporting a bare timeout', async () => {
    failMode('--fail wedge')
    const profile = makeProfile(makeSpec([proxy()]))
    const c = makeCtx()

    const result = await frpDriver.start(profile, c.ctx)
    // An empty proxy table after the deadline means frpc never registered
    // anything, which is a statement about the server rather than about time.
    expect(result.errorCode).toBe('server-rejected')
    expect(result.error).toContain('no proxy was ever registered')
    expect(frpDriver.status(profile.id)).toBeNull()
  })

  it('treats a visitors-only profile as ready once the control connection is up', async () => {
    const spec = makeSpec([], [
      {
        name: 'db-visitor',
        type: 'stcp',
        serverName: 'private',
        secretKeyRef: { vaultEntryId: 'v3', field: 'proxySecretKey' },
        bindAddr: '127.0.0.1',
        bindPort: 15_432
      }
    ])
    const profile = makeProfile(spec)
    const c = makeCtx(makeSecrets({ proxySecretKeys: { 'db-visitor': 'visitor_secret' } }))

    const result = await frpDriver.start(profile, c.ctx)
    expect(result.ok).toBe(true)
    // A visitor binds a real local port, so it is a listener in the sense the
    // rest of the app means. A proxy's port lives on the frp server and is
    // reported through the proxy table instead.
    expect(result.listeners).toEqual([{ kind: 'stcp', bindHost: '127.0.0.1', bindPort: 15_432 }])
  })
})

describe('frp failure mapping', () => {
  it('maps a rejected token to auth-failed with frp wording, and does not retry', async () => {
    failMode('--fail auth')
    const profile = makeProfile(makeSpec([proxy()]))
    const c = makeCtx()

    const result = await frpDriver.start(profile, c.ctx)
    expect(result.errorCode).toBe('auth-failed')
    expect(result.error).toContain("token in login doesn't match token from configuration")

    // E33: retrying a wrong token is five failed logins against the user's
    // account and a crash-loop error that never mentions the token.
    await sleep(400)
    expect(spawns.length).toBe(1)
  })

  it('classifies ANSI-coloured output, and stores the colour rather than the classification', async () => {
    failMode('--fail auth')
    const profile = makeProfile(makeSpec([proxy()]))
    const c = makeCtx()

    const result = await frpDriver.start(profile, c.ctx)
    // frpc really does wrap its lines, and puts the reset at the start of the
    // *next* line, so anything matched against them has to strip first.
    expect(c.logs.some((l) => l.includes('\u001b['))).toBe(true)
    expect(result.error).not.toContain('\u001b')
    expect(result.errorCode).toBe('auth-failed')
  })

  it('maps a version-skewed server to version-mismatch', async () => {
    failMode('--fail version')
    const profile = makeProfile(makeSpec([proxy()]))
    const result = await frpDriver.start(profile, makeCtx().ctx)
    expect(result.errorCode).toBe('version-mismatch')
  })

  it('reports a proxy that could not start as degraded, in frp own words', async () => {
    failMode('--fail proxy-port')
    const redis = proxy({ name: 'redis', localPort: 6379, remotePort: 16379 })
    const profile = makeProfile(makeSpec([proxy(), redis]))
    const c = makeCtx()

    // The tunnel is up: the control connection is alive and the other proxy is
    // carrying traffic. Amber, not red.
    const result = await frpDriver.start(profile, c.ctx)
    expect(result.ok).toBe(true)

    const status = frpDriver.status(profile.id)
    expect(status?.state).toBe('degraded')
    expect(status?.error).toContain('port already used')
    expect(status?.errorCode).toBe('port-in-use')

    const stats = await frpDriver.stats(profile.id)
    const failed = stats?.proxies?.find((p) => p.name === 'postgres')
    expect(failed?.status).toBe('start error')
    expect(failed?.err).toBe('port already used, remote port 15432')
  })

  it('lets the supervisor back off and restart when the engine dies after coming up', async () => {
    failMode('--fail crash-after 1500')
    const profile = makeProfile(makeSpec([proxy()]))
    const c = makeCtx()

    expect(await frpDriver.start(profile, c.ctx)).toMatchObject({ ok: true })
    // A drop after readiness is a new incident, not a bad config: this one is
    // the supervisor's to retry.
    await waitFor('a restart is scheduled', () => c.states().includes('reconnecting'))
    expect(frpDriver.status(profile.id)?.state).toBe('reconnecting')
    await waitFor('the engine is respawned', () => spawns.length >= 2)
  })
})

describe('frp admin port race', () => {
  it('retries with a new port when frpc cannot bind the one we released', async () => {
    const taken = await occupyPort()
    let picks = 0
    frpTuning.adminPortPicker = async () => {
      picks++
      return picks <= 2 ? taken : reserveAdminPort()
    }

    const profile = makeProfile(makeSpec([proxy()]))
    const result = await frpDriver.start(profile, makeCtx().ctx)

    expect(result.ok).toBe(true)
    expect(picks).toBe(3)
    expect(spawns.length).toBe(3)
  })

  it('gives up as port-in-use rather than looping forever', async () => {
    const taken = await occupyPort()
    frpTuning.adminPortAttempts = 2
    frpTuning.adminPortPicker = async () => taken

    const profile = makeProfile(makeSpec([proxy()]))
    const result = await frpDriver.start(profile, makeCtx().ctx)

    expect(result.ok).toBe(false)
    expect(result.errorCode).toBe('port-in-use')
    expect(spawns.length).toBe(2)
    expect(frpDriver.status(profile.id)).toBeNull()
  })
})
