import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import { execFileSync, spawn, type ChildProcess } from 'node:child_process'
import { existsSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { createInterface } from 'node:readline'
import { join, resolve } from 'node:path'
import net from 'node:net'
import type { OpenVpnSpec } from '../src/shared/vpn'
import { OpenVpnManagement } from '../src/main/services/vpn/openvpnManagement'
import { emitOvpnConfig, ovpnArgs } from '../src/main/services/vpn/parsers'

// Real engines, real sockets, no mocks.
//
// Everything else in the VPN suite runs against fake binaries, which is right:
// a fake can be made to fail on demand, it runs in milliseconds, and it works
// on a machine with nothing installed. What a fake cannot tell you is whether
// the protocol we implemented is the protocol the real program speaks.
//
// So this file is the other half, and it is opt-in for two honest reasons: it
// needs `npm run build:engines` to have run, and a real WireGuard handshake
// takes seconds rather than milliseconds.
//
//     npm run build:engines && VPN_E2E=1 npx vitest run tests/vpnEngines.e2e.test.ts
//
// It is not in the default suite, and CI does not gate on it — see the plan's
// §10 for the Linux nightly that should.

const ROOT = resolve(__dirname, '..')
const platformDir = `${process.platform}-${process.arch}`
const exe = process.platform === 'win32' ? '.exe' : ''
const NETD = join(ROOT, 'resources', 'bin', platformDir, `shellpilot-netd${exe}`)
const FRPC = join(ROOT, 'resources', 'bin', platformDir, `frpc${exe}`)
// No `${exe}`: ShellPilot bundles openvpn on macOS and Linux only, so there is
// never an openvpn.exe here to name.
const OPENVPN = join(ROOT, 'resources', 'bin', platformDir, 'openvpn')

function has(bin: string): boolean {
  return existsSync(bin)
}

const enabled = process.env.VPN_E2E === '1'
const describeE2e = enabled ? describe : describe.skip

// A minimal NDJSON client for the sidecar. Responses arrive in completion
// order, not request order — handlers run concurrently — so everything is
// matched strictly on id.
class Netd {
  private readonly proc: ChildProcess
  private seq = 0
  private readonly pending = new Map<string, (m: Record<string, unknown>) => void>()
  readonly events: { event: string; data: Record<string, unknown> }[] = []
  readonly stderr: string[] = []

  constructor(bin: string) {
    this.proc = spawn(bin, [], { stdio: ['pipe', 'pipe', 'pipe'] })
    createInterface({ input: this.proc.stdout as NodeJS.ReadableStream }).on('line', (line) => {
      let msg: Record<string, unknown>
      try {
        msg = JSON.parse(line)
      } catch {
        // Anything unparseable on stdout is a protocol violation: the channel
        // is JSON only, and one stray Println would break every client.
        this.stderr.push(`NON-JSON ON STDOUT: ${line}`)
        return
      }
      const id = msg.id as string | undefined
      if (id && this.pending.has(id)) {
        this.pending.get(id)?.(msg)
        this.pending.delete(id)
      } else if (msg.event) {
        this.events.push({ event: msg.event as string, data: (msg.data ?? {}) as Record<string, unknown> })
      }
    })
    this.proc.stderr?.on('data', (d: Buffer) => this.stderr.push(String(d)))
  }

  call(method: string, params: unknown = {}): Promise<Record<string, unknown>> {
    const id = String(++this.seq)
    return new Promise((res, rej) => {
      const timer = setTimeout(() => rej(new Error(`${method} timed out`)), 20_000)
      this.pending.set(id, (m) => {
        clearTimeout(timer)
        if (m.ok) res((m.result ?? {}) as Record<string, unknown>)
        else rej(new Error(`${method}: ${JSON.stringify(m.error)}`))
      })
      this.proc.stdin?.write(`${JSON.stringify({ id, method, params })}\n`)
    })
  }

  kill(): void {
    this.proc.kill('SIGKILL')
  }
}

const wg = (args: string[], input?: string): string =>
  execFileSync('wg', args, { input, encoding: 'utf8' }).trim()

function wgAvailable(): boolean {
  try {
    execFileSync('wg', ['--version'], { stdio: 'ignore' })
    return true
  } catch {
    return false
  }
}

describeE2e('shellpilot-netd against itself', () => {
  it('is built', () => {
    expect(
      has(NETD),
      `${NETD} is missing. Run: npm run build:engines`
    ).toBe(true)
  })

  it('answers ping with a version', async () => {
    const n = new Netd(NETD)
    try {
      const r = await n.call('ping')
      expect(r.version).toBeTypeOf('string')
      expect(r.goVersion).toMatch(/^go1\./)
    } finally {
      n.kill()
    }
  })

  it('completes a real handshake between two userspace peers, with no root', async () => {
    if (!wgAvailable()) {
      // `wg genkey` is only needed to mint keys; the tunnel itself is entirely
      // userspace. Skipping rather than failing keeps this runnable on a
      // machine without wireguard-tools.
      console.warn('skipping: wireguard-tools (wg) not on PATH')
      return
    }

    const aPriv = wg(['genkey'])
    const aPub = wg(['pubkey'], aPriv)
    const bPriv = wg(['genkey'])
    const bPub = wg(['pubkey'], bPriv)
    const port = 51899

    const A = new Netd(NETD)
    const B = new Netd(NETD)
    try {
      await A.call('wg.up', {
        tunnelId: 'a',
        iface: { privateKey: aPriv, addresses: ['10.9.0.1/32'], mtu: 1420, listenPort: port },
        peers: [{ publicKey: bPub, allowedIps: ['10.9.0.2/32'] }],
        listeners: []
      })

      const bUp = await B.call('wg.up', {
        tunnelId: 'b',
        iface: { privateKey: bPriv, addresses: ['10.9.0.2/32'], mtu: 1420 },
        peers: [
          {
            publicKey: aPub,
            endpoint: `127.0.0.1:${port}`,
            allowedIps: ['10.9.0.1/32'],
            persistentKeepalive: 1
          }
        ],
        // Port 0 must come back as the port actually bound.
        listeners: [{ kind: 'socks5', bindHost: '127.0.0.1', bindPort: 0 }]
      })

      const listeners = bUp.listeners as { kind: string; bindHost: string; bindPort: number }[]
      expect(listeners).toHaveLength(1)
      expect(listeners[0].bindPort).toBeGreaterThan(0)

      // Poll rather than sleep a fixed amount: a handshake is usually under a
      // second, and a fixed wait would be both slower and flakier.
      let a: Record<string, unknown> = {}
      let b: Record<string, unknown> = {}
      const sawConnected = (): boolean =>
        A.events.some((e) => e.event === 'wg.state' && e.data.state === 'connected')

      for (let i = 0; i < 40; i++) {
        a = await A.call('wg.stats', { tunnelId: 'a' })
        b = await B.call('wg.stats', { tunnelId: 'b' })
        // The stats counters and the state event are produced on different
        // schedules, so waiting only on the counters races the event. Both, or
        // keep polling.
        if (
          (a.lastHandshakeUnixSec as number) > 0 &&
          (b.lastHandshakeUnixSec as number) > 0 &&
          sawConnected()
        ) {
          break
        }
        await new Promise((r) => setTimeout(r, 250))
      }

      expect(a.lastHandshakeUnixSec, 'no handshake on side A').toBeGreaterThan(0)
      expect(b.lastHandshakeUnixSec, 'no handshake on side B').toBeGreaterThan(0)

      // Mirrored counters are what distinguishes a real encrypted exchange
      // from a state machine that merely says "connected".
      expect(a.rxBytes as number).toBeGreaterThan(0)
      expect(a.txBytes as number).toBeGreaterThan(0)
      expect(a.rxBytes).toBe(b.txBytes)
      expect(a.txBytes).toBe(b.rxBytes)

      // The handshake is reported as an absolute unix second, not an age. The
      // driver converts against a monotonic base; conflating the two under one
      // name is how the clock-jump bug (E63) gets written.
      const age = Math.floor(Date.now() / 1000) - (a.lastHandshakeUnixSec as number)
      expect(age).toBeLessThan(120)

      const connected = A.events.filter(
        (e) => e.event === 'wg.state' && e.data.state === 'connected'
      )
      expect(connected.length).toBeGreaterThan(0)

      // The private keys must never appear anywhere the parent can read.
      const spill = [...A.stderr, ...B.stderr, JSON.stringify(A.events), JSON.stringify(B.events)].join('\n')
      expect(spill).not.toContain(aPriv)
      expect(spill).not.toContain(bPriv)
      expect(spill).not.toContain('NON-JSON ON STDOUT')

      await B.call('wg.down', { tunnelId: 'b' })
      await A.call('wg.down', { tunnelId: 'a' })

      // The UDP port must be immediately rebindable, or teardown leaked.
      await new Promise<void>((res, rej) => {
        const s = net.createServer()
        s.once('error', rej)
        s.listen(port, '127.0.0.1', () => s.close(() => res()))
      })
    } finally {
      A.kill()
      B.kill()
    }
  }, 60_000)
})

describeE2e('frpc admin API', () => {
  let dir = ''
  let proc: ChildProcess | null = null
  let adminPort = 0
  // A port with nothing on it, chosen the same way. This used to be the
  // literal 7000, frp's documented default, and that is how this test lied on
  // macOS: AirPlay Receiver listens on 7000, so frpc connected to *something*,
  // the login did not fail, and the client stayed up. The test passed locally
  // for a reason that had nothing to do with what it was testing.
  let deadPort = 0

  /** A port the OS says is free, rather than one we hoped was.
   *
   *  This was hardcoded to 41732, and it failed in CI on both runners while
   *  passing on every developer machine. 41732 sits inside Linux's ephemeral
   *  range (32768-60999), so a busy runner — one that has just spent minutes
   *  pulling npm and Go packages — can legitimately already own it, and frpc's
   *  bind then fails before it ever serves anything. An idle laptop almost
   *  never collides, which is why a fixed port looks fine until it is running
   *  somewhere that does real work.
   *
   *  Asking for port 0 and reading back what was assigned narrows this to the
   *  instant between closing the probe and frpc binding. That race cannot be
   *  removed without frpc accepting a pre-opened socket, but it is a window of
   *  microseconds rather than a standing bet on one number. */
  const freePort = async (): Promise<number> =>
    new Promise((resolvePort, reject) => {
      const srv = net.createServer()
      srv.once('error', reject)
      srv.listen(0, '127.0.0.1', () => {
        const { port } = srv.address() as net.AddressInfo
        srv.close(() => resolvePort(port))
      })
    })

  beforeAll(async () => {
    dir = mkdtempSync(join(tmpdir(), 'sp-frp-'))
    adminPort = await freePort()
    // Allocated and released, so it is closed rather than merely assumed to be.
    deadPort = await freePort()
  })

  afterAll(() => {
    proc?.kill('SIGKILL')
    if (dir) rmSync(dir, { recursive: true, force: true })
  })

  it('is built', () => {
    expect(has(FRPC), `${FRPC} is missing. Run: npm run build:engines`).toBe(true)
  })

  it('serves /healthz unauthenticated and /api/* behind Basic auth', async () => {
    // The two are not interchangeable, and a readiness check that used the
    // wrong one would go green before frpc had contacted the server at all.
    const cfg = [
      'serverAddr = "127.0.0.1"',
      `serverPort = ${deadPort}`,
      'auth.method = "token"',
      'auth.token = "{{ .Envs.SP_FRP_TOKEN }}"',
      'webServer.addr = "127.0.0.1"',
      `webServer.port = ${adminPort}`,
      'webServer.user = "shellpilot"',
      'webServer.password = "{{ .Envs.SP_FRP_ADMIN }}"',
      // Without this frpc exits the moment its first login fails, and this
      // test deliberately has no frps to reach — the whole point is the admin
      // API's behaviour *before* the client has logged in, which is the window
      // a readiness check can get wrong.
      //
      // Confirmed by the binary itself, in CI, after this line was wrongly
      // removed: "login to the server failed ... With loginFailExit enabled,
      // no additional retries will be attempted". It had looked unnecessary
      // locally only because AirPlay was answering on the port the config then
      // used, so the login never failed in the first place.
      //
      // Production does not set this; the default applies there and the
      // supervisor's restart policy handles a failed login. This one field
      // differs from a generated config, in the direction that lets the test
      // observe the state it is about.
      'loginFailExit = false',
      'log.to = "console"',
      '',
      '[[proxies]]',
      'name = "postgres"',
      'type = "tcp"',
      'localIP = "127.0.0.1"',
      'localPort = 5432',
      'remotePort = 15432'
    ].join('\n')
    const path = join(dir, 'frpc.toml')
    writeFileSync(path, cfg)

    proc = spawn(FRPC, ['-c', path], {
      stdio: ['ignore', 'pipe', 'pipe'],
      env: { ...process.env, SP_FRP_TOKEN: 'zzsecrettokenvaluezz', SP_FRP_ADMIN: 'zzadminpwzz' }
    })

    // Keep what frpc says. When this failed in CI it reported only
    // `ECONNREFUSED`, which says the port is shut and nothing about why — and
    // the reason was in the output nobody was keeping. A real binary's
    // complaint is the most useful thing in the room when a real-binary test
    // fails.
    let output = ''
    proc.stdout?.on('data', (c: Buffer) => (output += c.toString()))
    proc.stderr?.on('data', (c: Buffer) => (output += c.toString()))
    let died: string | null = null
    proc.on('exit', (code, signal) => (died = `frpc exited early: code=${code} signal=${signal}`))

    const base = `http://127.0.0.1:${adminPort}`
    for (let i = 0; i < 40; i++) {
      if (died) break
      try {
        if ((await fetch(`${base}/healthz`)).ok) break
      } catch {
        // Not up yet.
      }
      await new Promise((r) => setTimeout(r, 250))
    }

    expect(died, `${died}\n--- frpc output ---\n${output}`).toBeNull()
    expect((await fetch(`${base}/healthz`)).status, `frpc output:\n${output}`).toBe(200)
    expect((await fetch(`${base}/api/status`)).status).toBe(401)

    const auth = { Authorization: `Basic ${Buffer.from('shellpilot:zzadminpwzz').toString('base64')}` }
    const status = await fetch(`${base}/api/status`, { headers: auth })
    expect(status.status).toBe(200)

    // With no frps reachable, this is an empty object rather than an error or
    // an empty array. A readiness check that iterates it would pass vacuously
    // on nothing, which is the difference between "connected" and "connected
    // to nothing".
    expect(await status.json()).toEqual({})

    // The admin API hands back the config with the templates unexpanded, so
    // the token never leaves the process.
    const conf = await (await fetch(`${base}/api/config`, { headers: auth })).text()
    expect(conf).toContain('{{ .Envs.SP_FRP_TOKEN }}')
    // The literal is deliberately not a substring of anything in the config —
    // a value like "tok" lives inside the word "token" and would make this
    // assertion fail for the wrong reason.
    expect(conf).not.toContain('zzsecrettokenvaluezz')
    expect(conf).not.toContain('zzadminpwzz')
  }, 30_000)
})

// --------------------------------------------------------------- openvpn

// The bundled OpenVPN, driven by the real driver plumbing.
//
// This is the test the bundling change turns on, and the reason it matters is
// narrow: `ovpnArgs` emits eleven flags, `emitOvpnConfig` emits a config, and
// `build-openvpn.sh` compiles OpenVPN with five features switched off. Nothing
// in the unit suite can tell you whether the flags survive the build — a
// fake binary accepts every argument. Here, an option this build does not
// understand is a fatal parse error before the management channel is ever
// dialled, and the test fails.
//
// No server, no certificates, no root. `--management-hold` makes openvpn stop
// after parsing options and connect back to us, which is exactly the window
// that proves the plumbing without needing a peer.
describeE2e('bundled openvpn', () => {
  let dir = ''

  beforeAll(() => {
    dir = mkdtempSync(join(tmpdir(), 'sp-ovpn-'))
  })

  afterAll(() => {
    if (dir) rmSync(dir, { recursive: true, force: true })
  })

  it('is built', () => {
    if (process.platform === 'win32') {
      // Windows drives a system install; see docs/VPN.md.
      console.warn('skipping: ShellPilot does not bundle openvpn on Windows')
      return
    }
    expect(has(OPENVPN), `${OPENVPN} is missing. Run: npm run build:engines`).toBe(true)
  })

  it('is the version we pinned, statically linked against the OpenSSL we pinned', () => {
    if (process.platform === 'win32' || !has(OPENVPN)) return
    // `--version` exits non-zero on some builds, so the output is what is
    // read, not the status.
    let out = ''
    try {
      out = execFileSync(OPENVPN, ['--version'], { encoding: 'utf8' })
    } catch (e) {
      out = String((e as { stdout?: string }).stdout ?? '')
    }
    expect(out).toContain('OpenVPN 2.6')
    expect(out).toMatch(/library versions: OpenSSL 3\./)
    // The build script switches these off on purpose. If a configure flag is
    // ever renamed upstream the build would quietly re-enable them, and the
    // first sign would be a plugin directive loading something.
    expect(out).toContain('enable_plugins=no')
    expect(out).toContain('enable_lzo=no')
    expect(out).toContain('enable_lz4=no')
  })

  it('accepts every argument the driver passes, and answers on the management channel', async () => {
    if (process.platform === 'win32' || !has(OPENVPN)) return

    const spec: OpenVpnSpec = {
      kind: 'openvpn',
      // Never dereferenced here: the config body is passed to
      // `emitOvpnConfig` directly, the way the driver passes what it already
      // read out of the vault.
      configRef: { vaultEntryId: 'e2e', field: 'configBody' },
      authMode: 'userpass',
      redirectGateway: false
    }
    // openvpn validates the option set before it dials the management socket,
    // and refuses a client config with no way to verify the peer and no way to
    // authenticate to it. `peer-fingerprint` and a bare `auth-user-pass`
    // satisfy both without a certificate on disk — and the bare form is what
    // the real driver relies on, since the credentials come over the
    // management channel rather than from a file (E28). The remote is never
    // contacted: --management-hold stops openvpn before it dials.
    const body = [
      'client',
      'dev tun',
      'proto udp',
      'remote 127.0.0.1 1194',
      'nobind',
      'auth-user-pass',
      `peer-fingerprint ${new Array(32).fill('AB').join(':')}`
    ].join('\n')

    const events: string[] = []
    const logs: string[] = []
    const management = new OpenVpnManagement(
      {
        emit: (patch) => events.push(String(patch.state ?? '')),
        log: (line, stream) => logs.push(`${stream}: ${line}`),
        askUser: async () => null,
        credentials: () => ({})
      },
      // `OpenVpnManagementOptions` has no `runDir`: the management channel
      // picks its own socket path, and this was passing a property nothing
      // read. `dir` is still the run directory for the config file below.
      {}
    )

    const endpoint = await management.listen()
    const configPath = join(dir, 'e2e.ovpn')
    writeFileSync(configPath, emitOvpnConfig(spec, body), { mode: 0o600 })
    const args = ovpnArgs(spec, {
      configPath,
      management: endpoint.socketPath
        ? { kind: 'unix', path: endpoint.socketPath }
        : { kind: 'tcp', host: '127.0.0.1', port: endpoint.port ?? 0 },
      verb: 3
    })

    const proc = spawn(OPENVPN, args, { cwd: dir, stdio: ['ignore', 'pipe', 'pipe'] })
    const exited = new Promise<number | null>((res) => proc.once('exit', (code) => res(code)))

    try {
      // openvpn dials us. If any argument above were rejected, or any option
      // the build no longer understands were in the config, it would have died
      // at parse time and this would wait out the loop instead.
      const seen = (needle: string): boolean => logs.some((l) => l.includes(needle))
      for (let i = 0; i < 150 && !seen('>PASSWORD:'); i++) {
        await new Promise((r) => setTimeout(r, 100))
      }
      const transcript = logs.join('\n')
      expect(logs.length, `openvpn never reached the management channel. exit=${proc.exitCode}`)
        .toBeGreaterThan(0)

      // Each of these is a distinct claim about the real binary, and each one
      // is a thing a fake could not have told us:
      //
      //  - it speaks management protocol version 5, the one we parse;
      //  - `--management-hold` took effect, so nothing was attempted before we
      //    were listening;
      //  - the three subscriptions the driver depends on were accepted —
      //    without `state on` there is no status, without `bytecount` there
      //    are no counters;
      //  - and it asked us for the credential over the channel rather than
      //    reading a file, which is the whole reason no secret is ever an
      //    argument (E28).
      expect(transcript).toContain('>INFO:OpenVPN Management Interface Version 5')
      expect(transcript).toContain('>HOLD:')
      expect(transcript).toContain('SUCCESS: real-time state notification set to ON')
      expect(transcript).toContain('SUCCESS: bytecount interval changed')
      expect(transcript).toContain(">PASSWORD:Need 'Auth' username/password")

      // The stop ladder's first rung: signal over the control channel rather
      // than a kill, because on Windows that is the only rung there is.
      management.sigterm()
      const code = await Promise.race([
        exited,
        new Promise<'timeout'>((r) => setTimeout(() => r('timeout'), 10_000))
      ])
      expect(code, 'openvpn ignored SIGTERM sent over the management channel').not.toBe('timeout')
      expect(logs.join('\n')).toContain('SUCCESS: signal SIGTERM thrown')
    } finally {
      management.close()
      proc.kill('SIGKILL')
    }
  }, 30_000)
})
