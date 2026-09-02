import { describe, it, expect, afterEach } from 'vitest'
import { spawn as nodeSpawn } from 'node:child_process'
import type { ChildProcess, SpawnOptions } from 'node:child_process'
import { createHash } from 'node:crypto'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'

import type {
  OpenVpnSpec,
  VpnEngineInfo,
  VpnLogLine,
  VpnProfile,
  VpnPrompt,
  VpnStatus
} from '../src/shared/vpn'
import type { ResolvedVpnSecrets, VpnDriverContext } from '../src/main/services/vpn/driver'
import type { ElevatedProcess, ElevationRequest, Elevator } from '../src/main/services/vpn/elevation'
import { emitOvpnConfig, OVPN_PULL_FILTER_REJECTS } from '../src/main/services/vpn/parsers'
import { resetBinaryCache } from '../src/main/services/vpn/binaries'
import { Supervisor } from '../src/main/services/vpn/supervisor'
import {
  createOpenVpnDriver,
  elevatedLauncher,
  supervisedLauncher
} from '../src/main/services/vpn/drivers/openvpn'
import type { OpenVpnDriver } from '../src/main/services/vpn/drivers/openvpn'

// The whole OpenVPN lifecycle, end to end: the real `fake-openvpn.mjs` driven
// through the real `Supervisor` and the real `OpenVpnManagement` over real
// sockets. Only elevation is stubbed — the platform helpers start the engine
// outside our stdio, and every one of them wants a password.
//
// POSIX only, deliberately: the driver hands the config over on `/dev/stdin`
// and the management channel is a unix socket in a 0700 directory. The Windows
// shapes (a 0600 `p.ovpn`, a 127.0.0.1 management port) are covered by
// `ovpnManagement.test.ts` and by the parser tests.

const FAKE = fileURLToPath(new URL('./fixtures/fake-openvpn.mjs', import.meta.url))

const CONFIG_BODY = [
  'client',
  'dev tun',
  'proto udp',
  'remote vpn.example.com 1194',
  'nobind',
  'persist-key',
  'persist-tun',
  ''
].join('\n')

const USERNAME = 'alice'
const PASSWORD = 's3cr3t'
const PASSPHRASE = 'key-pass'

const b64 = (s: string): string => Buffer.from(s, 'utf8').toString('base64')
const sha256 = (s: string): string => createHash('sha256').update(s).digest('hex')

// ------------------------------------------------------------------ harness

interface Spawned {
  command: string
  args: string[]
}

interface Harness {
  driver: OpenVpnDriver
  profile: VpnProfile & { spec: OpenVpnSpec }
  ctx: VpnDriverContext
  supervisor: Supervisor
  runDir: string
  /** Every spawn the supervisor made, with the argv the driver built — before
   *  the fixture prefix this harness adds, so an assertion reads what the
   *  driver emitted and nothing else. */
  spawned: Spawned[]
  /** The fixture's stdout, unredacted. Tapped alongside the supervisor's own
   *  reader rather than instead of it: the ring buffer is redacted before
   *  storage, which is correct and is asserted below, but it means the ring
   *  cannot be used to prove which bytes actually went on the wire. */
  raw(): string
  logs: VpnLogLine[]
  patches: Partial<VpnStatus>[]
  prompts: VpnPrompt['kind'][]
  promptLabels: string[]
  elevations: number
}

interface HarnessOptions {
  /** Extra argv appended to the fixture, e.g. ['--fail', 'auth']. */
  fail?: string[]
  spec?: Partial<OpenVpnSpec>
  secrets?: Partial<ResolvedVpnSecrets>
  /** Answers handed back from `askUser`, in order. `null` is a cancel. */
  answers?: (string | null)[]
  /** Replaces the supervised launcher, for the elevation cases. */
  elevator?: Elevator
  connectTimeoutMs?: number
  maxRestarts?: number
}

const dirs: string[] = []
const supervisors: Supervisor[] = []

function makeHarness(o: HarnessOptions = {}): Harness {
  const runDir = mkdtempSync(join(tmpdir(), 'ovpn-drv-'))
  dirs.push(runDir)

  const spawned: Spawned[] = []
  let raw = ''

  const supervisor = new Supervisor({
    runRoot: runDir,
    // The fixture is a plain 0644 .mjs, so node runs it and the fixture path
    // is argv[0] of the script rather than of the process. Appending the
    // failure mode here keeps it out of the argv the assertions read.
    spawn: (command: string, args: readonly string[], options: SpawnOptions): ChildProcess => {
      spawned.push({ command, args: [...args] })
      const child = nodeSpawn(command, [FAKE, ...args, ...(o.fail ?? [])], options)
      child.stdout?.on('data', (c: Buffer) => {
        raw += c.toString('utf8')
      })
      return child
    }
  })
  supervisors.push(supervisor)

  const secrets: ResolvedVpnSecrets = {
    username: USERNAME,
    password: PASSWORD,
    keyPassphrase: PASSPHRASE,
    configBody: CONFIG_BODY,
    all: [USERNAME, PASSWORD, PASSPHRASE],
    ...o.secrets
  }

  const logs: VpnLogLine[] = []
  const patches: Partial<VpnStatus>[] = []
  const prompts: VpnPrompt['kind'][] = []
  const promptLabels: string[] = []
  const answers = [...(o.answers ?? [])]

  const ctx: VpnDriverContext = {
    runDir,
    secrets,
    emit: (patch) => patches.push(patch),
    log: (text, stream) => logs.push({ at: Date.now(), stream, text }),
    askUser: async (p) => {
      prompts.push(p.kind)
      promptLabels.push(p.label)
      return answers.length > 0 ? (answers.shift() ?? null) : null
    },
    supervisor
  }

  const harness = {
    elevations: 0
  } as Harness

  const engine: VpnEngineInfo = {
    kind: 'openvpn',
    available: true,
    path: process.execPath,
    sha256: 'f'.repeat(64),
    version: 'OpenVPN 2.6.12 (fake)',
    bundled: false
  }

  const elevator = o.elevator
  const driver = createOpenVpnDriver({
    launcher: elevator
      ? elevatedLauncher({
          get method() {
            return elevator.method
          },
          probe: () => elevator.probe(),
          run: (req: ElevationRequest): Promise<ElevatedProcess> => {
            harness.elevations++
            return elevator.run(req)
          }
        })
      : supervisedLauncher(),
    resolveEngine: async () => engine,
    connectTimeoutMs: o.connectTimeoutMs ?? 5_000,
    gracefulTimeoutMs: 500,
    backoff: { baseMs: 5, maxMs: 20, jitter: 0 },
    crashLoop: { windowMs: 60_000, maxRestarts: o.maxRestarts ?? 5 }
  })

  const profile: VpnProfile & { spec: OpenVpnSpec } = {
    id: 'ovpn-1',
    workspaceId: 'w1',
    name: 'Office',
    autoStart: false,
    spec: {
      kind: 'openvpn',
      configRef: { vaultEntryId: 'v1', field: 'configBody' },
      authMode: 'userpass',
      redirectGateway: false,
      ...o.spec
    }
  }

  return Object.assign(harness, {
    driver,
    profile,
    ctx,
    supervisor,
    runDir,
    spawned,
    raw: () => raw,
    logs,
    patches,
    prompts,
    promptLabels
  })
}

// The budget is deliberately just under vitest's own testTimeout (15s) rather
// than a tighter number of its own. These tests spawn a real stub binary and
// wait on its management channel, so the only honest deadline is "longer than
// this can legitimately take"; a second, tighter clock invented here fails runs
// that prove nothing about the driver.
//
// This is a mitigation, not a diagnosis. `stops cleanly when the one-time code
// prompt is dismissed` failed on CI at 5086ms against the old 5s budget while
// taking 115ms locally — a 43x gap that plain CPU contention does not explain.
// If it recurs at 12s the budget was never the cause: look instead at whether
// the stub exits on its own after `--fail otp` before the driver gets to write
// SIGTERM over the channel, which would mean the awaited line never arrives at
// any budget.
const waitFor = async (fn: () => boolean, ms = 12_000): Promise<void> => {
  const deadline = Date.now() + ms
  while (!fn()) {
    if (Date.now() > deadline) throw new Error('condition never held')
    await new Promise((r) => setTimeout(r, 10))
  }
}

const states = (h: Harness): (string | undefined)[] => h.patches.map((p) => p.state).filter(Boolean)

afterEach(async () => {
  await Promise.allSettled(supervisors.splice(0).map((s) => s.stopAll()))
  for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true })
})

// -------------------------------------------------------------------- argv

describe('OpenVPN driver argv', () => {
  it('puts the management socket somewhere sun_path can hold', async () => {
    // OpenVPN could not start on macOS at all: the socket lived under the run
    // directory, which is `~/Library/Application Support/ShellPilot/vpn-run/
    // vpn-<uuid>-<8 hex>` — 111 bytes for a seven-character username, so the
    // socket came to 123 and was refused before openvpn was ever launched. The
    // floor for that layout is 117, so no username made it fit.
    //
    // sun_path is 104 bytes on macOS and 108 on Linux; the code refuses over
    // 100. This asserts the number, not the directory, because the number is
    // the thing that was wrong.
    const h = makeHarness({ fail: ['--tick-ms', '25'] })
    await h.driver.start(h.profile, h.ctx)
    const args = h.spawned[0].args
    const sock = args[args.indexOf('--management') + 1]

    expect(Buffer.byteLength(sock)).toBeLessThanOrEqual(100)
    expect(sock.endsWith('/m.sock')).toBe(true)
    // Not under the run directory — that is what made it too long.
    expect(sock.startsWith(h.runDir)).toBe(false)
  })

  it('emits the pull-filter reject set, the split-tunnel filters and no secret', async () => {
    const h = makeHarness({ fail: ['--tick-ms', '25'] })
    await h.driver.start(h.profile, h.ctx)

    expect(h.spawned).toHaveLength(1)
    expect(h.spawned[0].command).toBe(process.execPath)
    // The socket path is deliberately random and NOT under the run directory,
    // so it is read out of argv rather than reconstructed. What it has to be is
    // asserted on its own below.
    const sock = h.spawned[0].args[h.spawned[0].args.indexOf('--management') + 1]
    expect(h.spawned[0].args).toEqual([
      '--config',
      '/dev/stdin',
      '--management',
      sock,
      'unix',
      '--management-client',
      '--management-query-passwords',
      '--management-hold',
      '--script-security',
      '1',
      '--pull-filter',
      'reject',
      'script-security',
      '--pull-filter',
      'reject',
      'up ',
      '--pull-filter',
      'reject',
      'down ',
      '--pull-filter',
      'reject',
      'route-method',
      '--pull-filter',
      'reject',
      'setenv opt ',
      '--pull-filter',
      'ignore',
      'redirect-gateway',
      '--route-nopull',
      '--auth-nocache',
      '--verb',
      '3'
    ])

    // Restated independently of the exact ordering above: a hostile server
    // pushing any of these is the second half of the RCE class the sanitizer
    // covers, and it is the half a local config cannot reach (E38).
    for (const f of OVPN_PULL_FILTER_REJECTS) expect(h.spawned[0].args).toContain(f)

    await h.driver.stop(h.profile.id)
  })

  it('drops --route-nopull only when the user asked for the default route', async () => {
    const h = makeHarness({ spec: { redirectGateway: true }, fail: ['--tick-ms', '25'] })
    await h.driver.start(h.profile, h.ctx)

    expect(h.spawned[0].args).not.toContain('--route-nopull')
    // The `ignore` filter goes with it; `reject` is unconditional.
    expect(h.spawned[0].args.join(' ')).not.toContain('--pull-filter ignore redirect-gateway')
    expect(h.spawned[0].args.join(' ')).toContain('--pull-filter reject script-security')

    await h.driver.stop(h.profile.id)
  })

  it('never puts a credential or the config body on the command line', async () => {
    const h = makeHarness({ fail: ['--tick-ms', '25'] })
    await h.driver.start(h.profile, h.ctx)

    const argv = h.spawned[0].args.join(' ')
    for (const secret of [USERNAME, PASSWORD, PASSPHRASE, 'remote vpn.example.com']) {
      expect(argv).not.toContain(secret)
    }
    // And nothing that would read one from a file either.
    expect(argv).not.toContain('--auth-user-pass')
    expect(argv).not.toContain('--askpass')

    await h.driver.stop(h.profile.id)
  })

  it('hands the config body to the child unchanged', async () => {
    const h = makeHarness({ fail: ['--tick-ms', '25'] })
    await h.driver.start(h.profile, h.ctx)

    // What the driver emits, not what was stored: `emitOvpnConfig` re-checks
    // the body and appends `redirect-gateway def1` when the profile asks for
    // it, so this is the only hash worth comparing against.
    const expected = sha256(emitOvpnConfig(h.profile.spec, CONFIG_BODY))
    expect(h.raw()).toContain(`CONFIG_SHA256=${expected}`)

    await h.driver.stop(h.profile.id)
  })

  it('appends redirect-gateway def1 to the body when the route is redirected', async () => {
    const h = makeHarness({ spec: { redirectGateway: true }, fail: ['--tick-ms', '25'] })
    await h.driver.start(h.profile, h.ctx)

    const emitted = emitOvpnConfig(h.profile.spec, CONFIG_BODY)
    expect(emitted).toContain('redirect-gateway def1')
    expect(h.raw()).toContain(`CONFIG_SHA256=${sha256(emitted)}`)

    await h.driver.stop(h.profile.id)
  })
})

// --------------------------------------------------------------- lifecycle

describe('OpenVPN driver lifecycle', () => {
  it('walks starting -> authenticating -> connected, reports stats and stops gracefully', async () => {
    const h = makeHarness({ fail: ['--tick-ms', '25'] })

    const result = await h.driver.start(h.profile, h.ctx)
    expect(result.ok).toBe(true)

    expect(states(h)).toContain('authenticating')
    expect(states(h)).toContain('connected')
    expect(h.driver.status(h.profile.id)?.state).toBe('connected')

    // The handshake goes out in the plan's order the moment the peer is
    // trusted, and `hold release` is what starts the connection.
    const wire = h.raw()
    expect(wire).toContain('RECV state on')
    expect(wire).toContain('RECV bytecount 5')
    expect(wire).toContain('RECV log on all')
    expect(wire).toContain('RECV hold release')

    // Stored credentials go over the channel, never to a prompt.
    expect(h.prompts).toEqual([])
    expect(wire).toContain(`AUTHPASS ${PASSWORD}`)

    await waitFor(() => (h.driver.status(h.profile.id)?.stats?.rxBytes ?? 0) > 0)
    const stats = await h.driver.stats(h.profile.id)
    expect(stats?.rxBytes).toBeGreaterThan(0)
    expect(stats?.txBytes).toBeGreaterThan(0)
    // Both come from the CONNECTED state line, not from a probe.
    expect(stats?.assignedIp).toBe('10.8.0.6')
    expect(stats?.remoteEndpoint).toBe('203.0.113.1:1194')

    await h.driver.stop(h.profile.id)
    expect(h.raw()).toContain('RECV signal SIGTERM')
    expect(h.driver.status(h.profile.id)).toBeNull()
    expect(await h.driver.stats(h.profile.id)).toBeNull()
  })

  it('does not implement openForward, because OpenVPN is always system-mode', () => {
    const h = makeHarness()
    expect(h.driver.openForward).toBeUndefined()
  })

  it('exposes a soft restart so a resume from sleep need not re-authenticate', async () => {
    const h = makeHarness({ fail: ['--tick-ms', '25'] })
    await h.driver.start(h.profile, h.ctx)

    expect(h.driver.softRestart(h.profile.id)).toBe(true)
    await waitFor(() => h.raw().includes('RECV signal SIGUSR1'))
    // A soft restart is a renegotiation, not a new process.
    expect(h.spawned).toHaveLength(1)

    await h.driver.stop(h.profile.id)
    expect(h.driver.softRestart(h.profile.id)).toBe(false)
  })

  it('redacts the credential echo before it reaches the log ring', async () => {
    const h = makeHarness({ fail: ['--tick-ms', '25'] })
    await h.driver.start(h.profile, h.ctx)

    const stored = h.logs.map((l) => l.text).join('\n')
    expect(stored).not.toContain(PASSWORD)
    expect(stored).not.toContain(PASSPHRASE)
    // The line itself is kept — only the value is gone, so the transcript is
    // still readable.
    expect(stored).toContain('AUTHPASS [REDACTED]')

    await h.driver.stop(h.profile.id)
  })
})

// -------------------------------------------------------------- credentials

describe('OpenVPN driver credentials', () => {
  it('refuses to answer a second time after the server rejects the first (E28)', async () => {
    const h = makeHarness({ fail: ['--fail', 'auth'] })

    await expect(h.driver.start(h.profile, h.ctx)).rejects.toMatchObject({ code: 'auth-failed' })

    const wire = h.raw()
    // The fixture asks twice — that is what real openvpn does. Exactly one
    // answer went back, which is the whole point: a retry storm locks the
    // account, and nobody's second attempt with the same password succeeds.
    expect(wire.split('AUTHPASS ').length - 1).toBe(1)
    expect(wire.split('RECV password "Auth"').length - 1).toBe(1)
    expect(wire.split(">PASSWORD:Need 'Auth'").length - 1).toBe(0)
    expect(h.prompts).toEqual([])
    // And no second process was launched to try again with the same secret.
    expect(h.spawned).toHaveLength(1)
  })

  it('asks for a one-time code and sends the exact SCRV1 bytes (E29)', async () => {
    const h = makeHarness({ fail: ['--fail', 'otp', '--tick-ms', '25'], answers: ['123456'] })

    const result = await h.driver.start(h.profile, h.ctx)
    expect(result.ok).toBe(true)

    expect(h.prompts).toEqual(['otp'])
    // The engine's own wording, verbatim: the server chose it and the user has
    // probably seen it in another client.
    expect(h.promptLabels[0]).toContain('SC:1,Enter your 6-digit code')

    expect(h.raw()).toContain(`AUTHPASS SCRV1:${b64(PASSWORD)}:${b64('123456')}`)
    // Never cached: nothing about the code is written anywhere reusable.
    expect(h.logs.map((l) => l.text).join('\n')).not.toContain('123456')

    await h.driver.stop(h.profile.id)
  })

  it('stops cleanly when the one-time code prompt is dismissed', async () => {
    const h = makeHarness({ fail: ['--fail', 'otp'], answers: [null] })

    await expect(h.driver.start(h.profile, h.ctx)).rejects.toMatchObject({
      code: 'auth-otp-required'
    })

    // Dismissing is an answer, so openvpn is asked to exit over its own
    // channel rather than being killed.
    await waitFor(() => h.raw().includes('RECV signal SIGTERM'))
    expect(h.raw()).not.toContain('AUTHPASS')
    expect(h.spawned).toHaveLength(1)
  })

  it('answers a private key passphrase over the channel, never with --askpass', async () => {
    const h = makeHarness({ fail: ['--fail', 'keypass', '--tick-ms', '25'] })

    const result = await h.driver.start(h.profile, h.ctx)
    expect(result.ok).toBe(true)

    expect(h.raw()).toContain(`KEYPASS ${PASSPHRASE}`)
    expect(h.spawned[0].args).not.toContain('--askpass')
    // Stored, so the user is not asked.
    expect(h.prompts).toEqual([])

    await h.driver.stop(h.profile.id)
  })

  it('round-trips a password containing a quote and a backslash', async () => {
    const nasty = 'a"b\\c d'
    const h = makeHarness({
      fail: ['--tick-ms', '25'],
      secrets: { password: nasty, all: [USERNAME, nasty, PASSPHRASE] }
    })

    const result = await h.driver.start(h.profile, h.ctx)
    expect(result.ok).toBe(true)

    const wire = h.raw()
    // Escaped on the way out …
    expect(wire).toContain('RECV password "Auth" "a\\"b\\\\c d"')
    // … and identical once openvpn's own tokenizer has undone it. An unescaped
    // quote here would end the value early and start a command nobody wrote.
    expect(wire).toContain(`AUTHPASS ${nasty}`)

    await h.driver.stop(h.profile.id)
  })

  it('asks for a password it does not hold rather than starting without one', async () => {
    const h = makeHarness({
      fail: ['--tick-ms', '25'],
      secrets: { password: undefined, all: [USERNAME] },
      answers: ['typed-in']
    })

    const result = await h.driver.start(h.profile, h.ctx)
    expect(result.ok).toBe(true)
    expect(h.prompts).toEqual(['password'])
    expect(h.raw()).toContain('AUTHPASS typed-in')

    await h.driver.stop(h.profile.id)
  })
})

// ------------------------------------------------------------------ failure

describe('OpenVPN driver failure handling', () => {
  it('maps a fatal resolver error to dns-failure and does not restart', async () => {
    const h = makeHarness({ fail: ['--fail', 'fatal-dns'] })

    await expect(h.driver.start(h.profile, h.ctx)).rejects.toMatchObject({ code: 'dns-failure' })
    expect(h.spawned).toHaveLength(1)
  })

  it('times the first connection out when the engine never becomes ready', async () => {
    const h = makeHarness({ fail: ['--fail', 'wedge'], connectTimeoutMs: 300 })

    await expect(h.driver.start(h.profile, h.ctx)).rejects.toMatchObject({
      code: 'handshake-timeout'
    })
  })

  it('backs off, retries and then gives up when the binary dies on start', async () => {
    const h = makeHarness({ fail: ['--fail', 'crash'], maxRestarts: 1 })

    await expect(h.driver.start(h.profile, h.ctx)).rejects.toMatchObject({ code: 'crash-loop' })

    // Two launches: one restart at the backoff delay, then the loop is broken
    // rather than run forever.
    expect(h.spawned.length).toBeGreaterThan(1)
    expect(h.logs.map((l) => l.text).join('\n')).toMatch(/retrying in \d+ ms/)
    expect(states(h)).toContain('reconnecting')
  })

  it('refuses a profile with no stored configuration body', async () => {
    const h = makeHarness({ secrets: { configBody: undefined, all: [] } })

    await expect(h.driver.start(h.profile, h.ctx)).rejects.toMatchObject({ code: 'config-invalid' })
    expect(h.spawned).toHaveLength(0)
  })

  it('refuses to start the same profile twice', async () => {
    const h = makeHarness({ fail: ['--tick-ms', '25'] })
    await h.driver.start(h.profile, h.ctx)

    await expect(h.driver.start(h.profile, h.ctx)).rejects.toMatchObject({ code: 'already-running' })

    await h.driver.stop(h.profile.id)
  })
})

// ---------------------------------------------------------------- elevation

describe('OpenVPN driver elevation', () => {
  function stubElevator(exit: { code: number | null; declined: boolean }): Elevator & {
    runs: ElevationRequest[]
  } {
    const runs: ElevationRequest[] = []
    return {
      runs,
      method: 'uac',
      probe: async () => ({ available: true, method: 'uac' }),
      run: async (req: ElevationRequest): Promise<ElevatedProcess> => {
        runs.push(req)
        return { pid: null, wait: async () => exit, kill: async () => undefined }
      }
    }
  }

  it('reports a dismissed prompt as elevation-declined and never asks again (E04)', async () => {
    const elevator = stubElevator({ code: null, declined: true })
    const h = makeHarness({ elevator })

    await expect(h.driver.start(h.profile, h.ctx)).rejects.toMatchObject({
      code: 'elevation-declined'
    })

    expect(h.elevations).toBe(1)
    // Nothing was supervised: the elevated engine is not our child.
    expect(h.spawned).toHaveLength(0)
    // And no secret was handed to the helper, whose argv is more visible than
    // an ordinary process's, not less.
    const argv = elevator.runs[0].args.join(' ')
    for (const secret of [USERNAME, PASSWORD, PASSPHRASE]) expect(argv).not.toContain(secret)
  })

  it('does not use /dev/stdin when a helper stands between us and the engine', async () => {
    const elevator = stubElevator({ code: null, declined: true })
    const h = makeHarness({ elevator })

    await expect(h.driver.start(h.profile, h.ctx)).rejects.toMatchObject({
      code: 'elevation-declined'
    })

    // osascript, Start-Process -Verb RunAs and the Interactive Service all
    // start the engine outside our stdio, so the body has to be a 0600 file in
    // the 0700 run directory instead.
    const args = elevator.runs[0].args
    expect(args[0]).toBe('--config')
    expect(args[1]).toBe(join(h.runDir, 'p.ovpn'))
  })

  it('refuses to start when the machine cannot elevate at all', async () => {
    const elevator: Elevator = {
      method: 'none',
      probe: async () => ({ available: false, method: 'none', reason: 'no polkit here.' }),
      run: async () => {
        throw new Error('should not be reached')
      }
    }
    const h = makeHarness({ elevator })

    await expect(h.driver.start(h.profile, h.ctx)).rejects.toMatchObject({ code: 'unsupported' })
  })
})

// --------------------------------------------------------------- validation

describe('OpenVPN driver validation and probe', () => {
  it('accepts a default profile and warns about the default route', () => {
    const h = makeHarness()
    const ok = h.driver.validateConfig(h.profile.spec)
    expect(ok.ok).toBe(true)
    expect(ok.issues.some((i) => i.code === 'default-route')).toBe(false)

    const redirected = h.driver.validateConfig({ ...h.profile.spec, redirectGateway: true })
    expect(redirected.ok).toBe(true)
    const warning = redirected.issues.find((i) => i.code === 'default-route')
    expect(warning?.severity).toBe('warning')
  })

  it('rejects a profile with no stored configuration', () => {
    const h = makeHarness()
    const v = h.driver.validateConfig({
      ...h.profile.spec,
      configRef: undefined as unknown as OpenVpnSpec['configRef']
    })
    expect(v.ok).toBe(false)
    expect(v.issues[0].code).toBe('missing-config')
  })

  it('rejects an out-of-range proxy or remote port', () => {
    const h = makeHarness()
    const v = h.driver.validateConfig({
      ...h.profile.spec,
      httpProxy: { host: 'corp-proxy', port: 0 },
      remotes: [{ host: 'vpn.example.com', port: 70000, proto: 'udp' }]
    })
    expect(v.ok).toBe(false)
    expect(v.issues.filter((i) => i.severity === 'error').map((i) => i.code)).toEqual([
      'bad-port',
      'bad-port'
    ])
  })

  // `probe()` resolves through the real `binaries.ts`, which reads
  // `process.platform` rather than the driver's injected one — it has to, since
  // it is deciding which file on this machine to run. So the two Windows-copy
  // tests below stub the process value, not just the driver option. Without
  // that they would resolve the macOS/Linux bundled openvpn and assert nothing
  // about Windows at all.
  async function probeAs(platform: NodeJS.Platform): Promise<VpnEngineInfo> {
    const descriptor = Object.getOwnPropertyDescriptor(process, 'platform')
    Object.defineProperty(process, 'platform', { value: platform, configurable: true })
    resetBinaryCache()
    try {
      return await createOpenVpnDriver({ platform }).probe()
    } finally {
      if (descriptor) Object.defineProperty(process, 'platform', descriptor)
      resetBinaryCache()
    }
  }

  it('tells a Windows user how to install OpenVPN, and does not lecture them about licences', async () => {
    // Windows is the one platform ShellPilot does not bundle OpenVPN for, so
    // it is the one platform where "install it" is still the right answer.
    const info = await probeAs('win32')
    // On a real Windows machine with OpenVPN installed the probe succeeds and
    // there is no hint to check.
    if (info.available) return
    expect(info.reason).toContain('openvpn.net')
    expect(info.reason).toContain('Interactive Service')
    // This used to carry "ShellPilot does not include OpenVPN, because its
    // licence and ShellPilot's cannot be combined" — true when it was written,
    // no longer true, and of no use at all to somebody whose tunnel will not
    // start. The licence reasoning lives in THIRD-PARTY-NOTICES.md and
    // docs/VPN.md; an error gets the one thing the reader can act on.
    expect(info.reason).not.toContain('licence')
    expect(info.reason).not.toContain('does not include OpenVPN')
  })

  it('says PATH is not searched on Windows', async () => {
    const info = await probeAs('win32')
    if (info.available) return
    // The message comes from the resolver, which is where the rule lives (E44).
    expect(info.reason).toMatch(/PATH|Program Files/)
  })

  it('finds the bundled OpenVPN on macOS and Linux without asking the user to install anything', async () => {
    if (process.platform === 'win32') return
    const info = await createOpenVpnDriver().probe()
    // A checkout that has not run `npm run build:engines` has no binary to
    // find, and that is a build state rather than a product claim — but the
    // message must still not be an install instruction, because installing
    // OpenVPN is not what fixes it.
    if (!info.available) {
      expect(info.reason).toContain('Reinstall ShellPilot')
      expect(info.reason).not.toContain('brew install')
      return
    }
    expect(info.bundled).toBe(true)
    expect(info.version).toContain('2.6')
  })
})
