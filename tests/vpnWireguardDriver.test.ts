import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { spawn as nodeSpawn } from 'node:child_process'
import type { ChildProcess, SpawnOptions } from 'node:child_process'
import { generateKeyPairSync } from 'node:crypto'
import dgram from 'node:dgram'
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, statSync } from 'node:fs'
import net from 'node:net'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import { createInterface } from 'node:readline'
import { fileURLToPath } from 'node:url'

import type { NetApplyContext, NetStateFile } from '../src/main/services/vpn/netstate'
import type { RouteConflict } from '../src/main/services/vpn/routing/index'
import type { Elevator } from '../src/main/services/vpn/elevation'
import type { VpnEngineInfo, VpnProfile, VpnStatus, WireGuardSpec } from '../src/shared/vpn'
import { isWireGuardKey, WG_HANDSHAKE_STALE_SEC } from '../src/shared/vpn'
import { resetBinaryCache } from '../src/main/services/vpn/binaries'
import type { ResolvedVpnSecrets, VpnDriverContext } from '../src/main/services/vpn/driver'
import {
  applySystemNetworking,
  createMonotonicClock,
  handshakeAgeSec,
  parseNetdVersion,
  stateFromHandshakeAge,
  systemInterfaceName,
  systemRoutes,
  validateWireGuardSpec,
  wireguardDriver,
  wireguardTuning
} from '../src/main/services/vpn/drivers/wireguard'
import { Supervisor } from '../src/main/services/vpn/supervisor'

// What this file proves, and what it deliberately does not.
//
// The integration tests below drive the REAL `shellpilot-netd` through the
// REAL `Supervisor`: two userspace WireGuard devices are brought up on
// loopback UDP, they complete a genuine Noise handshake, and the driver is
// asked the same questions the manager asks it. Nothing about the control
// channel, the key path, the listeners or the teardown is faked.
//
// What is NOT claimed: payload delivery through the tunnel. `shellpilot-netd`
// is a client — it offers no way to publish a service *inside* the netstack
// and does no forwarding, so two netd processes can handshake and exchange
// keepalives but have nowhere to send a byte of application data. The
// listeners are therefore proven to bind (including bindPort 0 resolving to a
// real port), to accept a TCP connection, to speak SOCKS5 back to the client,
// and to attempt the dial through the tunnel and fail cleanly rather than
// hang. Actual echo-through-the-tunnel lives in the sidecar's own Go suite
// (`tunnel_test.go`, which runs an echo service inside the peer's netstack)
// and belongs in the nightly against a real WireGuard server.

const REPO_ROOT = fileURLToPath(new URL('..', import.meta.url))
const PLATFORM_DIR = `${process.platform}-${process.arch}`
const NETD = process.platform === 'win32' ? 'shellpilot-netd.exe' : 'shellpilot-netd'
const BIN_ROOT = join(REPO_ROOT, 'resources', 'bin')
const NETD_PATH = join(BIN_ROOT, PLATFORM_DIR, NETD)

// The sidecar is a build artefact, not a checked-in file, and `npm test` does
// not build it. Skipping with a reason beats failing every fresh checkout.
const HAVE_NETD = existsSync(NETD_PATH)
if (!HAVE_NETD) {
  console.warn(`[vpnWireguardDriver] ${NETD_PATH} is missing; run scripts/build-sidecar.sh. Integration tests skipped.`)
}

/**
 * How long a test that drives two real WireGuard devices may take.
 *
 * This has to exceed the driver's own `firstHandshakeTimeoutMs`, and that is
 * the entire point of it existing. vitest's global `testTimeout` is 15 s; the
 * beforeEach below deliberately gives the driver 25 s to see a first handshake,
 * because under a parallel suite two real devices occasionally need longer than
 * the 8 s it used to allow.
 *
 * Those two numbers were in the wrong order, and the effect was worse than
 * either alone. A handshake slower than 15 s could not succeed — vitest killed
 * the test first — and it could not fail usefully either, because the driver's
 * own error, the one that names the endpoint, the UDP port and the peer key
 * (E22/E27), was not due for another ten seconds. All that survived was
 * `Test timed out in 15000ms`, pointing at whichever test happened to be
 * running. That is why this flake outlived two attempts to diagnose it: the
 * budget raise landed, and the executioner's clock was never moved to match.
 *
 * Kept comfortably above the driver's budget rather than equal to it, so the
 * driver always loses the race and gets to explain itself. `guards the
 * handshake budget` below fails if the order is ever inverted again.
 */
const REAL_SIDECAR_TIMEOUT_MS = 40_000

const SERVER_IP = '10.7.0.2'
const CLIENT_IP = '10.7.0.1'
// Nothing listens here inside the peer's netstack, which is the point: the
// dial has to fail fast rather than hang for the sidecar's 30 s dial timeout.
const CLOSED_PORT = 9

// ------------------------------------------------------------------- keys

/**
 * A Curve25519 keypair in the base64 form the protocol takes. OpenSSL clamps
 * the private key at generation — the same clamping WireGuard applies — so the
 * derived public key is the one the device will use.
 *
 * Every key this returns must satisfy `isWireGuardKey`, and that is asserted
 * rather than assumed: the shared regex used to reject about a fifth of real
 * keys (its final-character class was missing `0`, `4` and `8`), which showed
 * up here as one flaky run in five. A generator that quietly retried would
 * have hidden the regression instead of failing on it.
 */
function keypair(): { privateKey: string; publicKey: string } {
  const { publicKey, privateKey } = generateKeyPairSync('x25519')
  const pub = publicKey.export({ type: 'spki', format: 'der' }).subarray(-32).toString('base64')
  const priv = privateKey.export({ type: 'pkcs8', format: 'der' }).subarray(-32).toString('base64')
  expect(isWireGuardKey(pub), `generated public key ${pub} was rejected by isWireGuardKey`).toBe(true)
  expect(isWireGuardKey(priv), `generated private key was rejected by isWireGuardKey`).toBe(true)
  return { privateKey: priv, publicKey: pub }
}

function freeUdpPort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const sock = dgram.createSocket('udp4')
    sock.once('error', reject)
    sock.bind(0, '127.0.0.1', () => {
      const port = sock.address().port
      sock.close(() => resolve(port))
    })
  })
}

// ------------------------------------------------------------- peer sidecar

interface PeerReply {
  ok?: boolean
  error?: { message?: string }
  result?: { rxBytes?: number; txBytes?: number }
}

/**
 * The far end of the tunnel: a second `shellpilot-netd`, driven straight over
 * its stdio rather than through the driver, because the driver has no reason
 * to expose `iface.listenPort` — a client picks its own source port, and only
 * the node being dialled needs a fixed one.
 */
class PeerNode {
  private seq = 0
  private readonly pending = new Map<string, (r: PeerReply) => void>()
  private readonly rejects = new Map<string, (e: Error) => void>()
  /** Everything the peer said on stderr, kept so a failure can quote it.
   *  Also drained rather than ignored: an unread pipe fills at 64 KB and the
   *  writer blocks there, which would be a hang caused by the harness. */
  private stderr = ''
  private died: string | null = null

  private constructor(
    private readonly child: ChildProcess,
    readonly port: number,
    readonly publicKey: string
  ) {}

  /** Start a peer, retrying when the port it picked is taken.
   *
   *  `freeUdpPort` binds port 0, reads the number and closes the socket, so
   *  what it returns is a port that *was* free. Between that close and the
   *  sidecar binding it there is a process spawn and a request round trip, and
   *  under a parallel suite full of sidecars something else occasionally takes
   *  it — observed here as `wg.up failed: ... bind: address already in use`,
   *  about once in eighty runs with six copies of this file running at once.
   *
   *  The window cannot be closed from the test side: the protocol has no way to
   *  ask the sidecar to bind an arbitrary free port and report which one it
   *  got, and adding one to the Go sidecar to suit a test is the wrong trade.
   *  So losing the race is made harmless instead of impossible. Three attempts
   *  makes a collision on every one of them vanishingly unlikely, and a
   *  genuinely broken bind still fails on the last attempt with its real error
   *  rather than being retried into a timeout. */
  static async start(clientPublicKey: string, attempt = 1): Promise<PeerNode> {
    try {
      return await PeerNode.startOnce(clientPublicKey)
    } catch (e) {
      const message = e instanceof Error ? e.message : String(e)
      if (attempt < 3 && /address already in use/i.test(message)) {
        return PeerNode.start(clientPublicKey, attempt + 1)
      }
      throw e
    }
  }

  private static async startOnce(clientPublicKey: string): Promise<PeerNode> {
    const keys = keypair()
    const port = await freeUdpPort()
    const child = nodeSpawn(NETD_PATH, [], { stdio: ['pipe', 'pipe', 'pipe'] })
    const node = new PeerNode(child, port, keys.publicKey)

    child.stderr?.setEncoding('utf8')
    child.stderr?.on('data', (c: string) => (node.stderr += c))

    // A peer that dies owes an answer to every call still waiting on it.
    // Without this the promise simply never settles and the test reports a
    // bare "timed out in 15000ms" naming whichever test lost the race, with
    // nothing about the peer at all — which is precisely how this flake stayed
    // undiagnosed.
    const abandon = (why: string): void => {
      node.died = why
      for (const [id, reject] of node.rejects) {
        node.pending.delete(id)
        reject(new Error(`${why}${node.stderr ? `\nstderr: ${node.stderr.trim()}` : ''}`))
      }
      node.rejects.clear()
    }
    child.on('exit', (code, signal) => {
      // SIGKILL is `stop()` doing its job at the end of a test.
      if (signal !== 'SIGKILL') abandon(`peer sidecar exited: code=${code} signal=${signal}`)
    })
    child.on('error', (e) => abandon(`peer sidecar could not be started: ${e.message}`))

    createInterface({ input: child.stdout!, crlfDelay: Infinity }).on('line', (line) => {
      if (!line.startsWith('{')) return
      let msg: PeerReply & { id?: string }
      try {
        msg = JSON.parse(line) as PeerReply & { id?: string }
      } catch {
        // Throwing in here is an unhandled exception in a readline callback,
        // which takes the whole worker down rather than failing one test.
        node.stderr += `\nunparseable stdout line: ${line}`
        return
      }
      if (typeof msg.id === 'string') {
        const done = node.pending.get(msg.id)
        node.pending.delete(msg.id)
        node.rejects.delete(msg.id)
        done?.(msg)
      }
    })

    const up = await node.call('wg.up', {
      tunnelId: 'peer',
      iface: {
        privateKey: keys.privateKey,
        addresses: [`${SERVER_IP}/32`],
        dns: [],
        mtu: 1420,
        listenPort: port
      },
      // No endpoint: the peer learns the client's source address from the
      // first handshake, which is how a real server behaves for roaming
      // clients.
      peers: [{ publicKey: clientPublicKey, endpoint: '', allowedIps: [`${CLIENT_IP}/32`] }],
      listeners: []
    })
    if (!up.ok) {
      // Reap it before retrying, or a losing attempt leaves a live sidecar
      // behind for the rest of the file.
      child.kill('SIGKILL')
      throw new Error(`peer wg.up failed: ${up.error?.message}`)
    }
    return node
  }

  /** Ask the peer something, and fail rather than wait forever.
   *
   *  The budget is below vitest's per-test timeout on purpose: a call that
   *  gives up first can say which method hung and what the peer printed, where
   *  the test timeout can only say that fifteen seconds passed. */
  call(method: string, params?: unknown, ms = 10_000): Promise<PeerReply> {
    const id = String(++this.seq)
    return new Promise((resolve, reject) => {
      if (this.died) {
        reject(new Error(`${this.died} (before ${method})`))
        return
      }
      const timer = setTimeout(() => {
        this.pending.delete(id)
        this.rejects.delete(id)
        reject(
          new Error(
            `peer never answered ${method} within ${ms}ms` +
              `${this.stderr ? `\nstderr: ${this.stderr.trim()}` : ''}`
          )
        )
      }, ms)
      this.pending.set(id, (r) => {
        clearTimeout(timer)
        resolve(r)
      })
      this.rejects.set(id, (e) => {
        clearTimeout(timer)
        reject(e)
      })
      this.child.stdin!.write(`${JSON.stringify({ id, method, params })}\n`, (err) => {
        // An EPIPE here means the peer is already gone. Reported rather than
        // swallowed, because the alternative is waiting out the timeout for a
        // process that will never read the request.
        if (err) {
          this.pending.delete(id)
          this.rejects.delete(id)
          clearTimeout(timer)
          reject(new Error(`could not send ${method} to the peer: ${err.message}`))
        }
      })
    })
  }

  async stop(): Promise<void> {
    this.child.kill('SIGKILL')
  }
}

// ------------------------------------------------------------------ harness

interface Spawned {
  command: string
  args: readonly string[]
  options: SpawnOptions
}

let root: string
let runDir: string
let supervisor: Supervisor
let spawns: Spawned[]
let stdinWrites: string[]
let children: ChildProcess[]
let previousBinDir: string | undefined
const cleanups: (() => void)[] = []

let client: { privateKey: string; publicKey: string }
let peer: PeerNode | null

const PROFILE_ID = 'vpn-wg-1'

function makeSpec(over: Partial<WireGuardSpec> = {}): WireGuardSpec {
  return {
    kind: 'wireguard',
    mode: 'userspace',
    privateKeyRef: { vaultEntryId: 'v1', field: 'privateKey' },
    addresses: [`${CLIENT_IP}/32`],
    dns: [],
    mtu: 1420,
    peers: [
      {
        publicKey: peer?.publicKey ?? keypair().publicKey,
        endpoint: `127.0.0.1:${peer?.port ?? 51820}`,
        allowedIps: ['10.7.0.0/24'],
        // Forces the device to initiate rather than waiting for traffic.
        persistentKeepalive: 1
      }
    ],
    listeners: [{ kind: 'socks5', bindHost: '127.0.0.1', bindPort: 0 }],
    ...over
  }
}

function makeProfile(spec: WireGuardSpec): VpnProfile & { spec: WireGuardSpec } {
  return { id: PROFILE_ID, workspaceId: 'ws', name: 'Office WireGuard', autoStart: false, spec }
}

function makeSecrets(): ResolvedVpnSecrets {
  return { privateKey: client.privateKey, presharedKeys: {}, all: [client.privateKey] }
}

interface Ctx {
  ctx: VpnDriverContext
  patches: Partial<VpnStatus>[]
  logs: string[]
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
    logs
  }
}

const sleep = (ms: number): Promise<void> => new Promise((r) => setTimeout(r, ms))

/** Holds a TCP port so the sidecar genuinely cannot bind it. */
async function occupyPort(): Promise<number> {
  const srv = net.createServer()
  await new Promise<void>((resolve) => srv.listen(0, '127.0.0.1', resolve))
  const addr = srv.address()
  cleanups.push(() => srv.close())
  return typeof addr === 'object' && addr ? addr.port : 0
}

function connect(port: number): Promise<net.Socket> {
  return new Promise((resolve, reject) => {
    const sock = net.connect(port, '127.0.0.1')
    sock.once('connect', () => resolve(sock))
    sock.once('error', reject)
  })
}

/** A minimal SOCKS5 CONNECT. Returns the REP byte the sidecar answered with,
 *  which is the only place the far side of the tunnel gets a say. */
async function socks5Connect(port: number, host: string, target: number): Promise<number> {
  const sock = await connect(port)
  try {
    sock.write(Buffer.from([0x05, 0x01, 0x00]))
    const greeting = await read(sock, 2)
    expect([greeting[0], greeting[1]]).toEqual([0x05, 0x00])

    const ip = host.split('.').map(Number)
    sock.write(Buffer.from([0x05, 0x01, 0x00, 0x01, ...ip, target >> 8, target & 0xff]))
    const reply = await read(sock, 4)
    expect(reply[0]).toBe(0x05)
    return reply[1]
  } finally {
    sock.destroy()
  }
}

function read(sock: net.Socket, n: number): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = []
    let total = 0
    const onData = (c: Buffer): void => {
      chunks.push(c)
      total += c.length
      if (total >= n) {
        sock.off('data', onData)
        resolve(Buffer.concat(chunks))
      }
    }
    sock.on('data', onData)
    sock.once('error', reject)
    sock.once('close', () => reject(new Error(`socket closed after ${total} of ${n} bytes`)))
    setTimeout(() => reject(new Error(`timed out waiting for ${n} bytes`)), 10_000).unref()
  })
}

/** Resolves with true when the peer closed the connection without sending
 *  anything — what a listener does when its dial through the tunnel fails. */
function closedWithoutData(sock: net.Socket, ms: number): Promise<boolean> {
  return new Promise((resolve) => {
    let sawData = false
    sock.on('data', () => (sawData = true))
    sock.once('close', () => resolve(!sawData))
    setTimeout(() => resolve(false), ms).unref()
  })
}

beforeEach(async () => {
  root = mkdtempSync(join(tmpdir(), 'sp-wgdrv-'))
  runDir = join(root, 'run')
  mkdirSync(runDir, { recursive: true, mode: 0o700 })

  previousBinDir = process.env.SHELLPILOT_VPN_BIN_DIR
  process.env.SHELLPILOT_VPN_BIN_DIR = BIN_ROOT
  resetBinaryCache()

  spawns = []
  stdinWrites = []
  children = []
  supervisor = new Supervisor({
    runRoot: join(root, 'pids'),
    spawn: (command, args, options): ChildProcess => {
      const child = nodeSpawn(command, args, options)
      spawns.push({ command, args: [...args], options })
      children.push(child)
      const stdin = child.stdin
      if (stdin) {
        // Wrapped rather than sniffed on the far side: this is the assertion
        // that the private key reached the engine on stdin and nowhere else.
        const original = stdin.write.bind(stdin) as (chunk: string) => boolean
        stdin.write = ((chunk: unknown): boolean => {
          stdinWrites.push(String(chunk))
          return original(String(chunk))
        }) as typeof stdin.write
      }
      return child
    }
  })

  client = keypair()
  peer = null

  // These are failure deadlines, not durations: a successful handshake ends
  // the wait as soon as it lands (~20-200 ms over loopback), so a generous
  // bound costs nothing on the happy path and only decides how long a genuine
  // failure takes to report.
  //
  // 8 s was too tight. The full suite runs ~66 files in parallel, several of
  // them spawning real processes, and under that load two real WireGuard
  // devices occasionally needed longer — so this test failed with
  // `handshake-timeout` while measuring the machine rather than the driver.
  // The cases that assert a handshake *not* happening set their own short
  // budget locally.
  wireguardTuning.firstHandshakeTimeoutMs = 25_000
  wireguardTuning.handshakePollMs = 200
  wireguardTuning.requestTimeoutMs = 20_000
})

/** Stands in for the bundled sidecar lookup.
 *
 *  The system-mode tests are about elevation, route conflicts and the argv the
 *  privileged sidecar is launched with — none of which needs a real 6 MB Go
 *  binary to exist. Depending on one made them pass on a developer machine that
 *  had run `build:engines` and fail on a clean CI runner with `binary-missing`,
 *  which is a test reporting the state of the checkout rather than the code. */
const fakeEngine = async (): Promise<VpnEngineInfo> => ({
  kind: 'wireguard',
  available: true,
  bundled: true,
  path: '/nonexistent/shellpilot-netd',
  version: '0.0.0-test',
  sha256: '0'.repeat(64)
})

afterEach(async () => {
  await wireguardDriver.disposeAll?.().catch(() => undefined)
  await supervisor.stopAll().catch(() => undefined)
  await peer?.stop()
  for (const c of children) if (c.exitCode === null) c.kill('SIGKILL')
  while (cleanups.length) cleanups.pop()?.()

  wireguardTuning.firstHandshakeTimeoutMs = 30_000
  wireguardTuning.handshakePollMs = 500
  wireguardTuning.requestTimeoutMs = 20_000
  wireguardTuning.wallNow = () => Date.now()
  wireguardTuning.platform = null
  wireguardTuning.elevator = null
  wireguardTuning.routeManager = null
  wireguardTuning.applyNet = null
  wireguardTuning.resolveEngine = null

  if (previousBinDir === undefined) delete process.env.SHELLPILOT_VPN_BIN_DIR
  else process.env.SHELLPILOT_VPN_BIN_DIR = previousBinDir
  resetBinaryCache()
  rmSync(root, { recursive: true, force: true })
})

// ================================================================ validation

describe('validateConfig', () => {
  it('accepts a well-formed userspace profile', () => {
    const result = validateWireGuardSpec(makeSpec())
    expect(result.ok).toBe(true)
    expect(result.issues.filter((i) => i.severity === 'error')).toEqual([])
  })

  it('treats allowedIps 0.0.0.0/0 in userspace mode as a warning, not an error (E17)', () => {
    const spec = makeSpec()
    spec.peers[0].allowedIps = ['0.0.0.0/0', '::/0']
    const result = validateWireGuardSpec(spec)

    expect(result.ok).toBe(true)
    const warning = result.issues.find((i) => i.code === 'default-route-userspace')
    expect(warning?.severity).toBe('warning')
    // The point of the warning is the false belief, not the danger: nothing is
    // routed system-wide, so the user must not read "all traffic" off this.
    expect(warning?.message).toMatch(/userspace mode changes no system routes/i)
    expect(warning?.message).toMatch(/Everything else on this machine keeps using your normal network/i)
  })

  it('rejects malformed keys, addresses, endpoints and MTU', () => {
    const spec = makeSpec({ addresses: ['10.0.0.2'], mtu: 70_000 })
    spec.peers[0].publicKey = 'not-a-key'
    spec.peers[0].endpoint = 'vpn.example.com'
    const codes = validateWireGuardSpec(spec).issues.filter((i) => i.severity === 'error')

    expect(codes.map((i) => i.path)).toEqual(
      expect.arrayContaining(['addresses[0]', 'mtu', 'peers[0].publicKey', 'peers[0].endpoint'])
    )
    expect(validateWireGuardSpec(spec).ok).toBe(false)
  })

  it('requires at least one peer', () => {
    const result = validateWireGuardSpec(makeSpec({ peers: [] }))
    expect(result.ok).toBe(false)
    expect(result.issues.some((i) => i.code === 'peers-empty')).toBe(true)
  })

  it('refuses two peers sharing one public key', () => {
    const spec = makeSpec()
    spec.peers = [spec.peers[0], { ...spec.peers[0], endpoint: '127.0.0.1:51821' }]
    const dup = validateWireGuardSpec(spec).issues.find((i) => i.code === 'public-key-duplicate')
    expect(dup?.severity).toBe('error')
    expect(dup?.path).toBe('peers[1].publicKey')
  })

  it('refuses two listeners on one port but allows several on port 0', () => {
    const clash = validateWireGuardSpec(
      makeSpec({
        listeners: [
          { kind: 'socks5', bindHost: '127.0.0.1', bindPort: 1080 },
          { kind: 'http', bindHost: '127.0.0.1', bindPort: 1080 }
        ]
      })
    )
    expect(clash.ok).toBe(false)
    expect(clash.issues.find((i) => i.code === 'port-duplicate')?.path).toBe('listeners[1].bindPort')

    const auto = validateWireGuardSpec(
      makeSpec({
        listeners: [
          { kind: 'socks5', bindHost: '127.0.0.1', bindPort: 0 },
          { kind: 'http', bindHost: '127.0.0.1', bindPort: 0 }
        ]
      })
    )
    expect(auto.ok).toBe(true)
  })

  it('warns rather than refuses when a listener is not on loopback (E25)', () => {
    const result = validateWireGuardSpec(
      makeSpec({ listeners: [{ kind: 'socks5', bindHost: '0.0.0.0', bindPort: 1080 }] })
    )
    expect(result.ok).toBe(true)
    const warning = result.issues.find((i) => i.code === 'listener-not-loopback')
    expect(warning?.severity).toBe('warning')
    expect(warning?.message).toMatch(/reachable from your local network/i)
  })

  it('is pure: the same spec validates the same way twice', () => {
    const spec = makeSpec()
    expect(validateWireGuardSpec(spec)).toEqual(validateWireGuardSpec(spec))
  })
})

// ==================================================================== clocks

describe('handshake age', () => {
  it('ignores a wall-clock jump backwards (E63)', () => {
    let wall = 1_800_000_000_000
    let mono = 0
    const clock = createMonotonicClock(
      () => wall,
      () => mono
    )

    mono += 5_000
    // The user notices their clock is an hour fast and corrects it.
    wall -= 3_600_000

    expect(clock.nowMs()).toBe(1_800_000_005_000)
  })

  it('never reports a negative age', () => {
    const clock = { nowMs: (): number => 1_000_000_000_000 }
    // A handshake stamped an hour in the future, which is what a corrected
    // clock leaves behind in the device's own record.
    expect(handshakeAgeSec(1_000_000_000 + 3_600, clock)).toBe(0)
    expect(handshakeAgeSec(1_000_000_000 - 42, clock)).toBe(42)
  })

  it('distinguishes "never handshaked" from "handshaked just now"', () => {
    const clock = { nowMs: (): number => 1_000_000_000_000 }
    expect(handshakeAgeSec(0, clock)).toBeUndefined()
    expect(handshakeAgeSec(undefined, clock)).toBeUndefined()
    expect(handshakeAgeSec(1_000_000_000, clock)).toBe(0)
  })

  it('turns 180 seconds into the degraded/connected boundary, never error', () => {
    expect(stateFromHandshakeAge(undefined)).toBe('starting')
    expect(stateFromHandshakeAge(WG_HANDSHAKE_STALE_SEC - 1)).toBe('connected')
    expect(stateFromHandshakeAge(WG_HANDSHAKE_STALE_SEC)).toBe('connected')
    expect(stateFromHandshakeAge(WG_HANDSHAKE_STALE_SEC + 1)).toBe('degraded')
    expect(stateFromHandshakeAge(86_400)).toBe('degraded')
  })
})

describe('parseNetdVersion', () => {
  it('unwraps the sidecar\'s JSON --version line', () => {
    expect(parseNetdVersion('{"version":"0.4.4","goVersion":"go1.26.5","buildSha":"abc1234"}')).toBe('0.4.4 (abc1234)')
    expect(parseNetdVersion('{"version":"0.4.4","buildSha":"unknown"}')).toBe('0.4.4')
    expect(parseNetdVersion('frp 0.62')).toBe('frp 0.62')
    expect(parseNetdVersion(undefined)).toBeUndefined()
  })
})

// =============================================================== system mode

describe('system mode', () => {
  /**
   * A stand-in for `shellpilot-netd --privileged`, speaking the real protocol
   * over a real unix socket.
   *
   * What this proves is the half that does not need root: the argv contract,
   * the nonce file and its modes, the authentication handshake, the shape of
   * `wg.up` in system mode, and — the point of the whole exercise — that every
   * route and every resolver change is addressed to the interface name the
   * sidecar reported rather than the one the driver asked for. It reports a
   * DIFFERENT name on purpose, because that is what a real kernel does on
   * macOS and can do anywhere.
   *
   * What it does NOT prove is that a real TUN device can be created, that `ip`
   * or `netsh` configure it correctly, or that traffic crosses it. None of
   * that can run without root, and faking it would be asserting that the fake
   * works.
   */
  interface FakeSidecar {
    elevator: Elevator
    launch: { command: string; args: string[] } | null
    calls: string[]
    requests: { method: string; params?: unknown }[]
    nonce: string
    nonceMode: number | null
    dirMode: number | null
    authNonce: string | null
    reportedIface: string
    closed: boolean
  }

  function fakePrivilegedSidecar(opts: { rejectAuth?: boolean } = {}): FakeSidecar {
    const state: FakeSidecar = {
      elevator: null as unknown as Elevator,
      launch: null,
      calls: [],
      requests: [],
      nonce: '',
      nonceMode: null,
      dirMode: null,
      authNonce: null,
      // Deliberately not systemInterfaceName(): the kernel gets the last word.
      reportedIface: 'utun-kernel-picked',
      closed: false
    }

    const serve = (socketPath: string, noncePath: string): void => {
      state.nonce = readFileSync(noncePath, 'utf8').trim()
      state.nonceMode = statSync(noncePath).mode & 0o777
      state.dirMode = statSync(dirname(noncePath)).mode & 0o777
      // The real sidecar deletes the nonce file the moment it reads it.
      rmSync(noncePath, { force: true })

      const server = net.createServer((sock) => {
        let authed = false
        let buffered = ''
        sock.on('data', (chunk) => {
          buffered += chunk.toString('utf8')
          for (;;) {
            const nl = buffered.indexOf('\n')
            if (nl < 0) break
            const line = buffered.slice(0, nl)
            buffered = buffered.slice(nl + 1)
            if (!line.trim()) continue
            const req = JSON.parse(line) as { id: string; method: string; params?: Record<string, unknown> }
            state.requests.push({ method: req.method, params: req.params })
            const reply = (result: unknown): void => {
              sock.write(`${JSON.stringify({ id: req.id, ok: true, result })}\n`)
            }
            if (!authed) {
              const given = String(req.params?.nonce ?? '')
              state.authNonce = given
              if (opts.rejectAuth || req.method !== 'auth' || given !== state.nonce) {
                sock.write(
                  `${JSON.stringify({ id: req.id, ok: false, error: { code: 'permission-denied', message: 'authentication failed' } })}\n`
                )
                sock.end()
                return
              }
              authed = true
              reply({ authenticated: true, privileged: true, version: '0.0.0-test', buildSha: 'test' })
              continue
            }
            switch (req.method) {
              case 'wg.up':
                reply({ tunnelId: req.params?.tunnelId, ifaceName: state.reportedIface, listeners: [], assignedIp: CLIENT_IP })
                break
              case 'wg.stats':
                reply({
                  tunnelId: req.params?.tunnelId,
                  rxBytes: 1024,
                  txBytes: 2048,
                  lastHandshakeUnixSec: Math.floor(Date.now() / 1000),
                  sampledAt: Date.now()
                })
                break
              case 'wg.down':
                reply({ tunnelId: req.params?.tunnelId })
                break
              case 'shutdown':
                reply({ stopping: true })
                sock.end()
                break
              default:
                sock.write(
                  `${JSON.stringify({ id: req.id, ok: false, error: { code: 'unsupported', message: `unknown method ${req.method}` } })}\n`
                )
            }
          }
        })
        sock.on('close', () => {
          state.closed = true
        })
      })
      server.listen(socketPath)
      cleanups.push(() => server.close())
    }

    state.elevator = elevator(
      {
        run: async (req) => {
          if (req.args[0] === '--privileged') {
            state.launch = { command: req.command, args: [...req.args] }
            const socketPath = req.args[req.args.indexOf('--socket') + 1]
            const noncePath = req.args[req.args.indexOf('--nonce-file') + 1]
            serve(socketPath, noncePath)
          }
          return {
            pid: 4242,
            // Never resolves for the sidecar launch: on Linux the elevated
            // process is a real child and `wait()` only settles when the
            // tunnel ends. Anything that awaits it unconditionally hangs, and
            // that is worth catching here rather than on a user's machine.
            wait: () =>
              req.args[0] === '--privileged'
                ? new Promise(() => {})
                : Promise.resolve({ code: 0, declined: false }),
            kill: async () => undefined
          }
        }
      },
      state.calls
    )
    return state
  }

  function elevator(over: Partial<Elevator> = {}, calls: string[] = []): Elevator {
    return {
      method: 'pkexec',
      probe: async () => ({ available: true, method: 'pkexec' }),
      run: async (req) => {
        calls.push(`${req.command} ${req.args.join(' ')}`)
        return { pid: 1, wait: async () => ({ code: 0, declined: false }), kill: async () => undefined }
      },
      ...over
    }
  }

  it('refuses on macOS before spawning or elevating anything (E02)', async () => {
    wireguardTuning.platform = 'darwin'
    const { ctx } = makeCtx()
    const result = await wireguardDriver.start(makeProfile(makeSpec({ mode: 'system' })), ctx)

    expect(result.ok).toBe(false)
    expect(result.errorCode).toBe('unsupported')
    expect(result.error).toMatch(/macOS/)
    expect(result.error).toMatch(/no signed privileged helper/i)
    // Nothing was started and no prompt was raised: an elevation dialog that
    // cannot lead anywhere is worse than a refusal.
    expect(spawns).toHaveLength(0)
    expect(wireguardDriver.status(PROFILE_ID)).toBeNull()
  })

  it('refuses a platform the sidecar has no privileged mode for', async () => {
    // Linux and Windows are open; anything else is a platform nobody has
    // taught the routing and DNS managers about, which is a refusal rather
    // than a default.
    wireguardTuning.platform = 'freebsd'
    const { ctx } = makeCtx()
    const result = await wireguardDriver.start(makeProfile(makeSpec({ mode: 'system' })), ctx)

    expect(result.ok).toBe(false)
    expect(result.errorCode).toBe('unsupported')
    expect(result.error).toMatch(/cannot create a system network interface/i)
    expect(spawns).toHaveLength(0)
  })

  it('refuses a full-tunnel profile before it elevates, and says why', async () => {
    // A full tunnel routes the encrypted packets that carry it back into
    // itself unless the peer endpoint is pinned outside, which ShellPilot does
    // not do yet. Bringing it up would take the machine off the network.
    const calls: string[] = []
    const { ctx } = makeCtx()
    const spec = makeSpec({ mode: 'system' })
    spec.peers = [{ publicKey: 'a', endpoint: '203.0.113.9:51820', allowedIps: ['0.0.0.0/0', '::/0'] }]

    await expect(
      applySystemNetworking(makeProfile(spec), ctx, 'run-1', {
        platform: 'linux',
        elevator: elevator({}, calls),
        routeManager: { conflicts: async () => [] },
        applyNet: async () => {
          throw new Error('must not apply anything')
        }
      })
    ).rejects.toMatchObject({ code: 'unsupported' })

    expect(calls).toEqual([])
    const issues = validateWireGuardSpec(spec).issues
    // Said in the form too, so the refusal is not a surprise at start time.
    expect(issues.some((i) => i.code === 'default-route-system-mode' && i.severity === 'error')).toBe(true)
  })

  it('applies routes and DNS against the interface name the sidecar reports, not the one it asked for', async () => {
    const fake = fakePrivilegedSidecar()
    const applied: { plan: { interfaceName: string; routes?: unknown; dns?: unknown }; ctx: NetApplyContext }[] = []
    wireguardTuning.platform = 'linux'
    wireguardTuning.resolveEngine = fakeEngine
    wireguardTuning.elevator = fake.elevator
    wireguardTuning.routeManager = { conflicts: async () => [] }
    wireguardTuning.applyNet = async (plan, netCtx) => {
      applied.push({ plan: plan as never, ctx: netCtx })
      return {
        version: 1,
        runId: 'run-1',
        platform: 'linux',
        interfaceName: plan.interfaceName,
        appliedAt: 0,
        bootAt: 0
      } as NetStateFile
    }

    const { ctx } = makeCtx()
    const result = await wireguardDriver.start(makeProfile(makeSpec({ mode: 'system', dns: ['10.7.0.2'] })), ctx)

    expect(result.ok, JSON.stringify(result)).toBe(true)
    // The kernel's name, not systemInterfaceName's guess. Everything the
    // machine is told to do is addressed to this.
    expect(fake.reportedIface).not.toBe(systemInterfaceName(PROFILE_ID, 'linux'))
    expect(applied).toHaveLength(1)
    expect(applied[0].plan.interfaceName).toBe(fake.reportedIface)
    expect(applied[0].plan.routes).toEqual([
      { destination: '10.7.0.0/24', interfaceName: fake.reportedIface }
    ])
    expect(applied[0].plan.dns).toMatchObject({ servers: ['10.7.0.2'], interfaceName: fake.reportedIface })

    await wireguardDriver.stop(PROFILE_ID)
  })

  it('elevates the sidecar with no secret on its command line, and authenticates with a 32-byte nonce', async () => {
    const fake = fakePrivilegedSidecar()
    wireguardTuning.platform = 'linux'
    wireguardTuning.resolveEngine = fakeEngine
    wireguardTuning.elevator = fake.elevator
    wireguardTuning.routeManager = { conflicts: async () => [] }
    wireguardTuning.applyNet = async (plan) =>
      ({ version: 1, runId: 'r', platform: 'linux', interfaceName: plan.interfaceName, appliedAt: 0, bootAt: 0 }) as NetStateFile

    const { ctx } = makeCtx()
    const result = await wireguardDriver.start(makeProfile(makeSpec({ mode: 'system' })), ctx)
    expect(result.ok, JSON.stringify(result)).toBe(true)

    const launch = fake.launch
    expect(launch).not.toBeNull()
    expect(launch?.args[0]).toBe('--privileged')
    expect(launch?.args).toContain('--socket')
    expect(launch?.args).toContain('--nonce-file')
    // The elevated process's argv is world-readable on every platform this
    // ships to, so what is on it is the whole security question.
    for (const a of launch?.args ?? []) {
      expect(a).not.toContain(client.privateKey)
      expect(a).not.toBe(fake.nonce)
    }
    // 32 bytes, as 64 hex characters, in a 0600 file inside a 0700 directory.
    expect(fake.nonce).toMatch(/^[0-9a-f]{64}$/)
    expect(fake.nonceMode).toBe(0o600)
    expect(fake.dirMode).toBe(0o700)
    // And the sidecar was asked to prove it had read that exact file.
    expect(fake.authNonce).toBe(fake.nonce)

    await wireguardDriver.stop(PROFILE_ID)
  })

  it('sends wg.up with no listeners, the planned name and logLevel error', async () => {
    const fake = fakePrivilegedSidecar()
    wireguardTuning.platform = 'linux'
    wireguardTuning.resolveEngine = fakeEngine
    wireguardTuning.elevator = fake.elevator
    wireguardTuning.routeManager = { conflicts: async () => [] }
    wireguardTuning.applyNet = async (plan) =>
      ({ version: 1, runId: 'r', platform: 'linux', interfaceName: plan.interfaceName, appliedAt: 0, bootAt: 0 }) as NetStateFile

    const { ctx } = makeCtx()
    await wireguardDriver.start(makeProfile(makeSpec({ mode: 'system' })), ctx)

    const up = fake.requests.find((r) => r.method === 'wg.up')
    const params = up?.params as { listeners?: unknown[]; ifaceName?: string; logLevel?: string; iface?: { privateKey?: string } }
    // Listeners are a userspace concept; the sidecar refuses them in system
    // mode, and this is why it never has to.
    expect(params?.listeners).toEqual([])
    expect(params?.ifaceName).toBe(systemInterfaceName(PROFILE_ID, 'linux'))
    // Without this the device puts a line per worker goroutine on the wire for
    // every single wg.up.
    expect(params?.logLevel).toBe('error')
    // The key still travels on the control channel and nowhere else.
    expect(params?.iface?.privateKey).toBe(client.privateKey)

    await wireguardDriver.stop(PROFILE_ID)
  })

  it('says wg.down and shutdown, then puts the network settings back', async () => {
    const fake = fakePrivilegedSidecar()
    const reverted: string[] = []
    wireguardTuning.platform = 'linux'
    wireguardTuning.resolveEngine = fakeEngine
    wireguardTuning.elevator = fake.elevator
    wireguardTuning.routeManager = { conflicts: async () => [] }
    wireguardTuning.applyNet = async (plan) =>
      ({ version: 1, runId: 'r', platform: 'linux', interfaceName: plan.interfaceName, appliedAt: 0, bootAt: 0 }) as NetStateFile

    const { ctx } = makeCtx()
    await wireguardDriver.start(makeProfile(makeSpec({ mode: 'system' })), ctx)
    reverted.push('started')

    await wireguardDriver.stop(PROFILE_ID)

    const methods = fake.requests.map((r) => r.method)
    expect(methods).toContain('wg.down')
    expect(methods).toContain('shutdown')
    // wg.down before shutdown: the interface (and every route on it) must be
    // gone before the process is.
    expect(methods.indexOf('wg.down')).toBeLessThan(methods.indexOf('shutdown'))
    expect(fake.closed).toBe(true)
    expect(wireguardDriver.status(PROFILE_ID)).toBeNull()
  })

  it('reports a sidecar that rejects the nonce as permission-denied, and changes nothing', async () => {
    const fake = fakePrivilegedSidecar({ rejectAuth: true })
    let appliedAnything = false
    wireguardTuning.platform = 'linux'
    wireguardTuning.resolveEngine = fakeEngine
    wireguardTuning.elevator = fake.elevator
    wireguardTuning.routeManager = { conflicts: async () => [] }
    wireguardTuning.applyNet = async () => {
      appliedAnything = true
      return {} as NetStateFile
    }

    const { ctx } = makeCtx()
    const result = await wireguardDriver.start(makeProfile(makeSpec({ mode: 'system' })), ctx)

    expect(result.ok).toBe(false)
    expect(result.errorCode).toBe('permission-denied')
    expect(appliedAnything).toBe(false)
  })

  it('turns a dismissed prompt for the sidecar itself into elevation-declined', async () => {
    let applied = false
    wireguardTuning.platform = 'linux'
    wireguardTuning.resolveEngine = fakeEngine
    wireguardTuning.routeManager = { conflicts: async () => [] }
    wireguardTuning.applyNet = async () => {
      applied = true
      return {} as NetStateFile
    }
    wireguardTuning.elevator = elevator({
      run: async () => ({
        pid: null,
        wait: async () => ({ code: null, declined: true }),
        kill: async () => undefined
      })
    })

    const { ctx } = makeCtx()
    const result = await wireguardDriver.start(makeProfile(makeSpec({ mode: 'system' })), ctx)

    expect(result.ok).toBe(false)
    expect(result.errorCode).toBe('elevation-declined')
    expect(applied).toBe(false)
  })

  it('refuses a prefix another interface already claims, before it elevates', async () => {
    const calls: string[] = []
    const conflict: RouteConflict = {
      kind: 'prefix-claimed',
      destination: '10.7.0.0/24',
      existing: { destination: '10.7.0.0/24', interfaceName: 'utun4', family: 'inet' },
      message: '10.7.0.0/24 is already routed through utun4.'
    }
    const { ctx } = makeCtx()

    await expect(
      applySystemNetworking(makeProfile(makeSpec({ mode: 'system' })), ctx, 'run-1', {
        platform: 'linux',
        elevator: elevator({}, calls),
        routeManager: { conflicts: async () => [conflict] },
        applyNet: async () => {
          throw new Error('must not apply anything after a refusal')
        }
      })
    ).rejects.toMatchObject({ code: 'interface-conflict', detail: conflict.message })

    expect(calls).toEqual([])
  })

  it('surfaces an ipv6 leak as a warning and still applies', async () => {
    const leak: RouteConflict = {
      kind: 'ipv6-leak',
      destination: '::/0',
      existing: { destination: '::/0', interfaceName: 'en0', family: 'inet6' },
      message: 'This profile does not carry IPv6. IPv6 traffic will bypass it.'
    }
    const applied: { plan: unknown; ctx: NetApplyContext }[] = []
    const { ctx, logs } = makeCtx()

    const result = await applySystemNetworking(makeProfile(makeSpec({ mode: 'system', dns: ['10.7.0.2'] })), ctx, 'run-1', {
      platform: 'linux',
      elevator: elevator(),
      routeManager: { conflicts: async () => [leak] },
      applyNet: async (plan, netCtx) => {
        applied.push({ plan, ctx: netCtx })
        return { version: 1, runId: 'run-1', platform: 'linux', interfaceName: 'x', appliedAt: 0, bootAt: 0 } as NetStateFile
      }
    })

    expect(result.warnings).toEqual([leak])
    expect(logs).toContain(leak.message)
    expect(applied).toHaveLength(1)
    expect(applied[0].plan).toMatchObject({
      interfaceName: systemInterfaceName(PROFILE_ID, 'linux'),
      routes: [{ destination: '10.7.0.0/24', interfaceName: systemInterfaceName(PROFILE_ID, 'linux') }],
      dns: { servers: ['10.7.0.2'], searchDomains: [], interfaceName: systemInterfaceName(PROFILE_ID, 'linux') }
    })
    // Declared honestly: no elevation helper on any platform can carry a stdin
    // payload, so a DNS backend that needs one reports `unsupported` rather
    // than running a command that silently does nothing.
    expect(applied[0].ctx.supportsStdin).toBe(false)
  })

  it('turns a dismissed prompt into elevation-declined, with no retry', async () => {
    const { ctx } = makeCtx()
    let runs = 0
    const netCtx = await applySystemNetworking(makeProfile(makeSpec({ mode: 'system' })), ctx, 'run-1', {
      platform: 'linux',
      elevator: elevator({
        run: async () => {
          runs++
          return { pid: null, wait: async () => ({ code: null, declined: true }), kill: async () => undefined }
        }
      }),
      routeManager: { conflicts: async () => [] },
      applyNet: async (_plan, c) => {
        await c.runPrivileged('ip', ['route', 'add', '10.7.0.0/24'])
        return {} as NetStateFile
      }
    }).catch((e: unknown) => e)

    expect(netCtx).toMatchObject({ code: 'elevation-declined' })
    expect(runs).toBe(1)
  })

  it('refuses to run an unavailable elevator', async () => {
    const { ctx } = makeCtx()
    await expect(
      applySystemNetworking(makeProfile(makeSpec({ mode: 'system' })), ctx, 'run-1', {
        platform: 'linux',
        elevator: elevator({ probe: async () => ({ available: false, method: 'none', reason: 'polkit is not installed.' }) }),
        routeManager: { conflicts: async () => [] }
      })
    ).rejects.toMatchObject({ code: 'unsupported', detail: 'polkit is not installed.' })
  })

  it('derives one route per distinct allowed prefix and a legal interface name', () => {
    const spec = makeSpec({ mode: 'system' })
    spec.peers = [
      { publicKey: 'a', endpoint: 'x:1', allowedIps: ['10.0.0.0/8', '192.168.0.0/16'] },
      { publicKey: 'b', endpoint: 'y:1', allowedIps: ['10.0.0.0/8', '::/0'] }
    ]
    expect(systemRoutes(spec, 'wg0').map((r) => r.destination)).toEqual([
      '10.0.0.0/8',
      '192.168.0.0/16',
      '::/0'
    ])
    // Linux caps interface names at 15 characters.
    expect(systemInterfaceName('vpn-abcdefgh-0123456789', 'linux').length).toBeLessThanOrEqual(15)
  })
})

// ================================================================ engine I/O

// Not gated on the sidecar being built: this is a relationship between two
// numbers, it costs nothing to check, and a checkout without the sidecar is
// exactly where someone edits a timeout without being able to run the tests
// that would notice.
describe('timeout budgets', () => {
  it('guards the handshake budget against the test timeout that kills it', () => {
    // The invariant this whole file's stability rests on, asserted rather than
    // remembered.
    //
    // The driver is allowed to wait `firstHandshakeTimeoutMs` for two real
    // devices to complete a Noise handshake. If the harness kills the test
    // before that budget expires, a slow handshake can neither succeed nor
    // report why it failed: what surfaces is a bare `Test timed out`, naming
    // whichever test drew the short straw and saying nothing about WireGuard.
    // That is exactly what happened when the budget was raised from 8 s to 25 s
    // and vitest's 15 s `testTimeout` was left behind, and it cost two
    // investigations that both concluded "undiagnosed".
    //
    // Revert `REAL_SIDECAR_TIMEOUT_MS` to the global 15 s and this fails here,
    // immediately and by name, instead of intermittently and anonymously
    // somewhere else.
    expect(
      REAL_SIDECAR_TIMEOUT_MS,
      'the per-test timeout must outlast the driver\'s first-handshake budget, ' +
        'or the driver never gets to report a handshake-timeout'
    ).toBeGreaterThan(wireguardTuning.firstHandshakeTimeoutMs)

    // And with room to spare: the test also has to start a peer sidecar and run
    // its assertions after the handshake lands.
    expect(REAL_SIDECAR_TIMEOUT_MS - wireguardTuning.firstHandshakeTimeoutMs).toBeGreaterThanOrEqual(
      10_000
    )
  })
})

describe.skipIf(!HAVE_NETD)('probe', () => {
  it('finds and hashes the bundled sidecar and reports a readable version', async () => {
    const info = await wireguardDriver.probe()
    expect(info).toMatchObject({ kind: 'wireguard', available: true, bundled: true })
    expect(info.path).toContain(NETD)
    expect(info.sha256).toMatch(/^[0-9a-f]{64}$/)
    // The sidecar answers `--version` with JSON, because stdout is
    // protocol-only for this binary. Unwrapped here so the UI shows a version
    // rather than a document.
    expect(info.version).toMatch(/^\d+\.\d+\.\d+/)
    expect(info.version?.startsWith('{')).toBe(false)
  })

  it('reports an absent sidecar as unavailable rather than throwing', async () => {
    process.env.SHELLPILOT_VPN_BIN_DIR = join(root, 'empty')
    resetBinaryCache()
    const info = await wireguardDriver.probe()
    expect(info.available).toBe(false)
    expect(info.reason).toMatch(/build-sidecar\.sh/)
  })
})

describe.skipIf(!HAVE_NETD)('start, over a real handshake', () => {
  async function startConnected(over: Partial<WireGuardSpec> = {}): Promise<Ctx> {
    peer = await PeerNode.start(client.publicKey)
    const harness = makeCtx()
    const result = await wireguardDriver.start(makeProfile(makeSpec(over)), harness.ctx)
    expect(result.error).toBeUndefined()
    expect(result.ok).toBe(true)
    return harness
  }

  /** The peer node's own view of the traffic, which is the only witness that
   *  something crossed the tunnel rather than looping back locally. */
  async function peerCounters(): Promise<{ rxBytes: number; txBytes: number }> {
    const reply = await peer!.call('wg.stats', { tunnelId: 'peer' })
    return { rxBytes: reply.result?.rxBytes ?? 0, txBytes: reply.result?.txBytes ?? 0 }
  }

  function boundPort(kind: string): number {
    const listeners = wireguardDriver.status(PROFILE_ID)?.listeners ?? []
    const found = listeners.find((l) => l.kind === kind)
    if (!found) throw new Error(`no ${kind} listener: ${JSON.stringify(listeners)}`)
    return found.bindPort
  }

  it('completes a handshake, binds the listeners and resolves bindPort 0 to a real port', async () => {
    await startConnected({
      listeners: [
        { kind: 'socks5', bindHost: '127.0.0.1', bindPort: 0 },
        { kind: 'forward', bindHost: '127.0.0.1', bindPort: 0, targetHost: SERVER_IP, targetPort: CLOSED_PORT }
      ]
    })

    const status = wireguardDriver.status(PROFILE_ID)
    expect(status?.state).toBe('connected')
    expect(status?.listeners).toHaveLength(2)
    for (const l of status?.listeners ?? []) {
      expect(l.bindPort).toBeGreaterThan(0)
      expect(l.bindHost).toBe('127.0.0.1')
    }
    expect(status?.listeners?.find((l) => l.kind === 'forward')).toMatchObject({
      targetHost: SERVER_IP,
      targetPort: CLOSED_PORT
    })
  }, REAL_SIDECAR_TIMEOUT_MS)

  it('sends every key on stdin and puts nothing on argv or in the environment', async () => {
    await startConnected()

    expect(spawns).toHaveLength(1)
    const [spawned] = spawns
    expect(spawned.command).toBe(NETD_PATH)
    // Not "no secret in argv" — no argv at all. There is nothing this engine
    // takes on a command line, so there is nothing to review.
    expect(spawned.args).toEqual([])
    expect(JSON.stringify(spawned.args)).not.toContain(client.privateKey)
    expect(JSON.stringify(spawned.options.env ?? {})).not.toContain(client.privateKey)

    // And it did arrive, on stdin, or the handshake above could not have
    // happened.
    expect(stdinWrites.join('')).toContain(client.privateKey)
    expect(stdinWrites.join('')).toContain('"wg.up"')
  }, REAL_SIDECAR_TIMEOUT_MS)

  it('reports live stats with a handshake age computed from the pinned clock', async () => {
    await startConnected()
    const stats = await wireguardDriver.stats(PROFILE_ID)

    expect(stats).not.toBeNull()
    expect(stats?.lastHandshakeSec).toBeGreaterThanOrEqual(0)
    expect(stats?.lastHandshakeSec).toBeLessThan(60)
    expect(stats?.assignedIp).toBe(CLIENT_IP)
    expect(stats?.remoteEndpoint).toBe(`127.0.0.1:${peer?.port}`)
    // A handshake is 148 bytes out and 92 back, so both counters have moved.
    expect(stats?.txBytes).toBeGreaterThan(0)
    expect(stats?.rxBytes).toBeGreaterThan(0)
    expect(wireguardDriver.status(PROFILE_ID)?.state).toBe('connected')
  }, REAL_SIDECAR_TIMEOUT_MS)

  it('calls a stale handshake degraded, not error (the 180 s boundary)', async () => {
    // The pinned clock is set 400 s ahead of the sidecar's, so the handshake
    // it reports is 400 s old the moment it happens. Same code path a tunnel
    // idle for seven minutes takes, without waiting seven minutes.
    const realNow = Date.now()
    wireguardTuning.wallNow = () => realNow + (WG_HANDSHAKE_STALE_SEC + 220) * 1000
    await startConnected()

    const stats = await wireguardDriver.stats(PROFILE_ID)
    expect(stats?.lastHandshakeSec).toBeGreaterThan(WG_HANDSHAKE_STALE_SEC)

    const status = wireguardDriver.status(PROFILE_ID)
    expect(status?.state).toBe('degraded')
    expect(status?.state).not.toBe('error')
    expect(status?.errorCode).toBe('handshake-timeout')
    expect(status?.error).toMatch(new RegExp(`over ${WG_HANDSHAKE_STALE_SEC}s`))
    expect(status?.error).toMatch(/still up/i)
  }, REAL_SIDECAR_TIMEOUT_MS)

  it('clamps the age at zero when the clock says the handshake is in the future (E63)', async () => {
    const realNow = Date.now()
    // Pinned an hour behind the sidecar: every handshake it records looks like
    // it has not happened yet.
    wireguardTuning.wallNow = () => realNow - 3_600_000
    await startConnected()

    const stats = await wireguardDriver.stats(PROFILE_ID)
    expect(stats?.lastHandshakeSec).toBe(0)
    expect(stats?.lastHandshakeSec).not.toBeLessThan(0)
    expect(wireguardDriver.status(PROFILE_ID)?.state).toBe('connected')
  }, REAL_SIDECAR_TIMEOUT_MS)

  it('carries a SOCKS5 conversation and dials through the tunnel', async () => {
    await startConnected()
    const before = await peerCounters()

    // The greeting and the reply are real bytes across the listener. The
    // outcome then comes from the far end of the tunnel: the SYN is
    // encrypted, sent over loopback UDP, decrypted by the peer's netstack,
    // refused, and the refusal travels back the same way.
    const started = Date.now()
    const rep = await socks5Connect(boundPort('socks5'), SERVER_IP, CLOSED_PORT)
    const elapsed = Date.now() - started

    expect(rep).not.toBe(0x00)
    // Fast, not hung: the sidecar's own dial timeout is 30 s, so anything
    // near that would mean the packet went nowhere.
    expect(elapsed).toBeLessThan(5_000)

    // The proof that it was the tunnel and not loopback: the peer node, a
    // separate process reachable only through WireGuard, saw the bytes and
    // answered.
    const after = await peerCounters()
    expect(after.rxBytes).toBeGreaterThan(before.rxBytes)
    expect(after.txBytes).toBeGreaterThan(before.txBytes)
  }, REAL_SIDECAR_TIMEOUT_MS)

  it('accepts a connection on a forward listener and fails the dial cleanly', async () => {
    await startConnected({
      listeners: [
        { kind: 'forward', bindHost: '127.0.0.1', bindPort: 0, targetHost: SERVER_IP, targetPort: CLOSED_PORT }
      ]
    })
    const before = await peerCounters()

    const sock = await connect(boundPort('forward'))
    // Closed, not hung: the dial is refused across the tunnel in well under
    // the sidecar's 30 s dial timeout.
    expect(await closedWithoutData(sock, 10_000)).toBe(true)
    sock.destroy()

    const after = await peerCounters()
    expect(after.rxBytes).toBeGreaterThan(before.rxBytes)
  }, REAL_SIDECAR_TIMEOUT_MS)

  it('opens and closes an ephemeral forward', async () => {
    await startConnected()

    const forward = await wireguardDriver.openForward!(PROFILE_ID, SERVER_IP, CLOSED_PORT)
    expect(forward.port).toBeGreaterThan(0)

    const sock = await connect(forward.port)
    sock.destroy()

    forward.close()
    // Poll rather than sleep a fixed 300 ms. Closing a listener is not
    // instantaneous and a fixed wait is a bet on how busy the machine is; this
    // asserts the same thing without the bet.
    await waitFor('the forward to stop accepting', async () => {
      try {
        const probe = await connect(forward.port)
        probe.destroy()
        return false
      } catch (e) {
        return (e as NodeJS.ErrnoException).code === 'ECONNREFUSED'
      }
    })
  }, REAL_SIDECAR_TIMEOUT_MS)

  it('tears everything down on stop and leaves no listener behind', async () => {
    await startConnected({
      listeners: [
        { kind: 'socks5', bindHost: '127.0.0.1', bindPort: 0 },
        { kind: 'forward', bindHost: '127.0.0.1', bindPort: 0, targetHost: SERVER_IP, targetPort: CLOSED_PORT }
      ]
    })
    const ports = (wireguardDriver.status(PROFILE_ID)?.listeners ?? []).map((l) => l.bindPort)
    const child = children[0]

    await wireguardDriver.stop(PROFILE_ID)

    expect(wireguardDriver.status(PROFILE_ID)).toBeNull()
    expect(supervisor.get(PROFILE_ID)).toBeUndefined()
    await waitFor('the sidecar to exit', () => child.exitCode !== null || child.signalCode !== null)
    // `wg.down` blocks until every listener is closed, so the ports are ours
    // to take the moment the stop returns.
    for (const port of ports) {
      const srv = net.createServer()
      await new Promise<void>((resolve, reject) => {
        srv.once('error', reject)
        srv.listen(port, '127.0.0.1', resolve)
      })
      await new Promise<void>((resolve) => srv.close(() => resolve()))
    }
  }, REAL_SIDECAR_TIMEOUT_MS)

  it('sends wg.down before shutdown so the ports are free before the process goes', async () => {
    await startConnected()
    await wireguardDriver.stop(PROFILE_ID)

    const written = stdinWrites.join('')
    expect(written).toContain('"wg.down"')
    expect(written).toContain('"shutdown"')
    expect(written.indexOf('"wg.down"')).toBeLessThan(written.indexOf('"shutdown"'))
  }, REAL_SIDECAR_TIMEOUT_MS)
})

describe.skipIf(!HAVE_NETD)('failures the user can act on', () => {
  it('names the endpoint, the UDP port and the peer key when no handshake arrives (E22/E27)', async () => {
    wireguardTuning.firstHandshakeTimeoutMs = 2_500
    const spec = makeSpec()
    // Nothing is listening on this UDP port, so no handshake is ever answered.
    spec.peers[0].endpoint = '127.0.0.1:9'
    const publicKey = spec.peers[0].publicKey
    const { ctx } = makeCtx()

    const result = await wireguardDriver.start(makeProfile(spec), ctx)

    expect(result.ok).toBe(false)
    expect(result.errorCode).toBe('handshake-timeout')
    expect(result.error).toContain('127.0.0.1:9')
    expect(result.error).toMatch(/UDP/)
    expect(result.error).toMatch(/blocked/i)
    expect(result.error).toMatch(/sign in to this network/i)
    // From the model, never scraped from a log: the redactor cannot tell a
    // public key from a private one and blanks both.
    expect(result.error).toContain(publicKey)

    // One attempt. Retrying a blocked UDP port five times only produces a
    // `crash-loop` error that says nothing about the port.
    expect(spawns).toHaveLength(1)
    expect(supervisor.get(PROFILE_ID)).toBeUndefined()
    await waitFor('the sidecar to exit', () => children[0].exitCode !== null || children[0].signalCode !== null)
  }, REAL_SIDECAR_TIMEOUT_MS)

  it('names the port that is already in use (E24)', async () => {
    const taken = await occupyPort()
    peer = await PeerNode.start(client.publicKey)
    const { ctx } = makeCtx()

    const result = await wireguardDriver.start(
      makeProfile(makeSpec({ listeners: [{ kind: 'socks5', bindHost: '127.0.0.1', bindPort: taken }] })),
      ctx
    )

    expect(result.ok).toBe(false)
    expect(result.errorCode).toBe('port-in-use')
    expect(result.error).toContain(String(taken))
    expect(result.error).toMatch(/leave it as 0/i)
    expect(supervisor.get(PROFILE_ID)).toBeUndefined()
  }, REAL_SIDECAR_TIMEOUT_MS)

  it('reports a non-loopback bind back verbatim so the UI can warn (E25)', async () => {
    peer = await PeerNode.start(client.publicKey)
    const { ctx, logs } = makeCtx()

    const result = await wireguardDriver.start(
      makeProfile(makeSpec({ listeners: [{ kind: 'socks5', bindHost: '0.0.0.0', bindPort: 0 }] })),
      ctx
    )

    expect(result.ok).toBe(true)
    // Never normalised to 127.0.0.1: a UI showing loopback here would be
    // hiding a LAN-visible proxy.
    expect(result.listeners?.[0].bindHost).toBe('0.0.0.0')
    expect(logs.some((l) => /reachable from your local network/i.test(l))).toBe(true)
  }, REAL_SIDECAR_TIMEOUT_MS)

  it('refuses a profile whose key never made it out of the vault', async () => {
    peer = await PeerNode.start(client.publicKey)
    const { ctx } = makeCtx({ all: [] })

    const result = await wireguardDriver.start(makeProfile(makeSpec()), ctx)
    expect(result.ok).toBe(false)
    expect(result.errorCode).toBe('config-invalid')
    expect(supervisor.get(PROFILE_ID)).toBeUndefined()
  }, REAL_SIDECAR_TIMEOUT_MS)

  it('returns null stats and no forward for a profile that is not running', async () => {
    expect(await wireguardDriver.stats(PROFILE_ID)).toBeNull()
    expect(wireguardDriver.status(PROFILE_ID)).toBeNull()
    await expect(wireguardDriver.openForward!(PROFILE_ID, SERVER_IP, CLOSED_PORT)).rejects.toMatchObject({
      code: 'internal'
    })
  }, REAL_SIDECAR_TIMEOUT_MS)
})

// Accepts an async predicate too: some conditions can only be observed by
// attempting something (dialling a port to see whether it still accepts).
async function waitFor(
  what: string,
  fn: () => boolean | Promise<boolean>,
  ms = 10_000
): Promise<void> {
  const deadline = Date.now() + ms
  for (;;) {
    if (await fn()) return
    if (Date.now() > deadline) throw new Error(`never became true: ${what}`)
    await sleep(20)
  }
}
