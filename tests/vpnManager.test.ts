import { beforeEach, describe, expect, it, vi } from 'vitest'
import type { VpnDriver, VpnDriverContext } from '../src/main/services/vpn/driver'
import type { VpnProfile, VpnStartResult } from '../src/shared/vpn'

// The manager is the part that is the same for every engine, so it is tested
// against a fake one. What is under test here is the ordering and the failure
// handling — start cannot race stop, secrets are resolved fresh and never
// cached, dependents die before the transport, and a log line is redacted
// before it is stored rather than before it is shown.

const WG_KEY = 'aGVsbG8gd29ybGQgdGhpcyBpcyBhIGZha2Uga2V5ISE='
const PASSWORD = 'hunter2-not-in-any-log'

let profiles: VpnProfile[] = []
vi.mock('../src/main/services/store', () => ({
  loadData: () => ({ vpns: profiles }),
  saveData: vi.fn()
}))

vi.mock('../src/main/services/mcpDataCache', () => ({
  listCachedVpns: () => profiles.map((p) => ({ id: p.id, name: p.name, workspaceId: p.workspaceId })),
  listCachedServers: () => [],
  listCachedDatabases: () => [],
  listCachedTunnels: () => [],
  getCachedVpn: (id: string) => profiles.find((p) => p.id === id) ?? null
}))

class VaultLockedError extends Error {}
let vaultLocked = false
let resolveCalls = 0
vi.mock('../src/main/services/credentialResolver', () => ({
  VaultLockedError,
  isVaultLockedError: (e: unknown) => e instanceof VaultLockedError,
  resolveVpnSecrets: async () => {
    resolveCalls++
    if (vaultLocked) throw new VaultLockedError('locked')
    return { privateKey: WG_KEY, password: PASSWORD, all: [WG_KEY, PASSWORD] }
  }
}))

const disposedRunDirs: string[] = []
vi.mock('../src/main/services/vpn/runDir', () => ({
  createRunDir: async (id: string) => `/tmp/vpn-run/${id}`,
  disposeRunDir: async (id: string) => {
    disposedRunDirs.push(id)
  },
  sweepRunDirs: async () => undefined
}))

const supervisorCalls: string[] = []
vi.mock('../src/main/services/vpn/supervisor', () => ({
  Supervisor: class {
    async reapOrphans(): Promise<void> {
      supervisorCalls.push('reapOrphans')
    }
    async stopAll(): Promise<void> {
      supervisorCalls.push('stopAll')
    }
  }
}))

// The fake engine. Each test rewires `behaviour` rather than re-mocking.
const behaviour = {
  start: async (_p: VpnProfile, _ctx: VpnDriverContext): Promise<VpnStartResult> => ({ ok: true }),
  stop: async (_id: string): Promise<void> => undefined,
  validate: () => ({ ok: true, issues: [] })
}
const events: string[] = []
let lastCtx: VpnDriverContext | null = null

const fakeDriver: VpnDriver = {
  kind: 'wireguard',
  validateConfig: () => behaviour.validate(),
  probe: async () => ({ kind: 'wireguard', available: true, bundled: true }),
  start: async (p, ctx) => {
    lastCtx = ctx
    events.push('driver.start')
    return behaviour.start(p, ctx)
  },
  stop: async (id, opts) => {
    events.push(`driver.stop${opts?.force ? ':force' : ''}`)
    return behaviour.stop(id)
  },
  status: () => null,
  stats: async () => null,
  openForward: async () => ({ port: 51999, close: () => events.push('forward.close') })
}

vi.mock('../src/main/services/vpn/drivers', () => ({
  driverFor: () => fakeDriver,
  allDrivers: () => [fakeDriver]
}))

const mgr = await import('../src/main/services/vpn/manager')
const deps = await import('../src/main/services/vpn/dependencies')

function wgProfile(over: Partial<VpnProfile> = {}): VpnProfile {
  return {
    id: 'v1',
    workspaceId: 'w1',
    name: 'office',
    autoStart: false,
    spec: {
      kind: 'wireguard',
      mode: 'userspace',
      privateKeyRef: { vaultEntryId: 'e1', field: 'privateKey' },
      addresses: ['10.0.0.2/32'],
      dns: [],
      peers: [],
      listeners: []
    },
    ...over
  }
}

beforeEach(() => {
  profiles = [wgProfile()]
  vaultLocked = false
  resolveCalls = 0
  events.length = 0
  supervisorCalls.length = 0
  disposedRunDirs.length = 0
  lastCtx = null
  behaviour.start = async () => ({ ok: true })
  behaviour.stop = async () => undefined
  behaviour.validate = () => ({ ok: true, issues: [] })
  mgr.resetVpnManagerState()
  deps.clearAllVpnConsumers()
})

describe('profile loading', () => {
  it('reads profiles from the shared data blob', () => {
    expect(mgr.vpnProfiles().map((p) => p.id)).toEqual(['v1'])
  })

  it('skips a half-written or pre-feature entry instead of throwing on every list', () => {
    profiles = [wgProfile(), { id: 'broken' } as unknown as VpnProfile, null as unknown as VpnProfile]
    expect(mgr.vpnProfiles()).toHaveLength(1)
  })

  it('reports a never-started profile as stopped rather than omitting it', () => {
    expect(mgr.vpnList()).toEqual([{ id: 'v1', kind: 'wireguard', state: 'stopped', restarts: 0 }])
  })

  it('refuses an ambiguous name rather than picking one', () => {
    profiles = [wgProfile({ id: 'a' }), wgProfile({ id: 'b' })]
    expect(mgr.vpnProfileByName('office')).toBeNull()
    profiles = [wgProfile({ id: 'a' })]
    expect(mgr.vpnProfileByName('  OFFICE ')?.id).toBe('a')
  })

  it('scopes a name lookup to the caller workspaces', () => {
    profiles = [wgProfile({ id: 'a', workspaceId: 'w1' })]
    expect(mgr.vpnProfileByName('office', ['w2'])).toBeNull()
    expect(mgr.vpnProfileByName('office', ['w1', 'w2'])?.id).toBe('a')
  })
})

describe('start', () => {
  it('resolves secrets and hands them to the driver', async () => {
    await mgr.vpnStart('v1')
    expect(resolveCalls).toBe(1)
    expect(lastCtx?.secrets.privateKey).toBe(WG_KEY)
    expect(mgr.vpnStatus('v1')?.state).toBe('connected')
  })

  it('is idempotent: a second start returns the live status without respawning', async () => {
    await mgr.vpnStart('v1')
    events.length = 0
    const again = await mgr.vpnStart('v1')
    expect(again.ok).toBe(true)
    expect(events).toEqual([])
  })

  it('serialises a start that lands during a stop', async () => {
    await mgr.vpnStart('v1')
    // The gate is created up front rather than inside the stub. Creating it
    // lazily deadlocks: doStop awaits releaseDependents before it ever calls
    // the driver, so the release function is still the placeholder at the
    // moment the test would call it.
    let releaseStop!: () => void
    const stopGate = new Promise<void>((r) => (releaseStop = r))
    behaviour.stop = () => stopGate

    const stopping = mgr.vpnStop('v1')
    const starting = mgr.vpnStart('v1')
    releaseStop()
    await Promise.all([stopping, starting])

    // The stop must complete before the start begins, or two engines end up
    // fighting over one listen port.
    expect(events).toEqual(['driver.start', 'driver.stop', 'driver.start'])
  })

  it('a stop landing mid-start does not wedge the start', async () => {
    // The reported failure: the guard was read before it was armed, with an
    // await in between, so a stop arriving during a start ran alongside it —
    // and the supervisor then deleted the run without settling the promise
    // spawn() had handed out. The Start button spun forever and the IPC invoke
    // never replied.
    let releaseStart!: () => void
    const startGate = new Promise<void>((r) => (releaseStart = r))
    behaviour.start = async () => {
      await startGate
      return { ok: true }
    }

    const started = mgr.vpnStart('v1')
    const stopped = mgr.vpnStop('v1')
    releaseStart()

    // Both settle. Before the fix, `started` never did.
    await expect(
      Promise.race([
        Promise.all([started, stopped]).then(() => 'settled'),
        new Promise((r) => setTimeout(() => r('WEDGED'), 2000))
      ])
    ).resolves.toBe('settled')

    // And they ran in order rather than concurrently.
    expect(events).toEqual(['driver.start', 'driver.stop'])
  })

  it('runs queued operations in the order they were requested', async () => {
    const order: string[] = []
    behaviour.start = async () => {
      order.push('start')
      return { ok: true }
    }
    behaviour.stop = async () => {
      order.push('stop')
    }
    // Fired synchronously, with no awaits between them — the case where a
    // read-then-arm guard is guaranteed to miss.
    const a = mgr.vpnStart('v1')
    const b = mgr.vpnStop('v1')
    const c = mgr.vpnStart('v1')
    await Promise.all([a, b, c])
    expect(order).toEqual(['start', 'stop', 'start'])
  })

  it('a failed operation does not cancel what is queued behind it', async () => {
    behaviour.start = async () => {
      throw new Error('boom')
    }
    const failing = mgr.vpnStart('v1')
    const after = mgr.vpnStop('v1')
    await failing
    await expect(after).resolves.toEqual({ ok: true })
  })

  it('fails with vault-locked and never falls back to an unencrypted source', async () => {
    vaultLocked = true
    const r = await mgr.vpnStart('v1')
    expect(r.ok).toBe(false)
    expect(r.errorCode).toBe('vault-locked')
    // The driver was never reached, so nothing could have started unprotected.
    expect(events).toEqual([])
    expect(mgr.vpnStatus('v1')?.state).toBe('error')
  })

  it('cleans up the run directory when the vault is locked', async () => {
    vaultLocked = true
    await mgr.vpnStart('v1')
    expect(disposedRunDirs).toHaveLength(1)
  })

  it('refuses an invalid spec before resolving any secret', async () => {
    behaviour.validate = () => ({
      ok: false,
      issues: [{ path: 'peers[0].endpoint', severity: 'error', code: 'bad', message: 'not a host:port' }]
    })
    const r = await mgr.vpnStart('v1')
    expect(r.errorCode).toBe('config-invalid')
    // The validator's message, which is a sentence — but not its dotted spec
    // path. This surfaces as a toast with the profile form closed, so
    // "peers[0].endpoint" would be internal notation pointing at nothing.
    expect(r.error).toContain('not a host:port')
    expect(r.error).not.toContain('peers[0]')
    expect(resolveCalls).toBe(0)
  })

  it('surfaces a driver throw as an error state, not an unhandled rejection', async () => {
    behaviour.start = async () => {
      throw new Error('engine exploded')
    }
    const r = await mgr.vpnStart('v1')
    expect(r.ok).toBe(false)
    expect(mgr.vpnStatus('v1')?.state).toBe('error')
    expect(disposedRunDirs).toHaveLength(1)
  })

  it('names the other profile when two want the same port (E52)', async () => {
    // "Port 1080 is already in use" sends the user hunting through their whole
    // machine. The answer is nearly always the other profile they left
    // running, and only the manager can see that.
    const withSocks = (id: string, port: number): VpnProfile =>
      wgProfile({
        id,
        name: `office-${id}`,
        spec: {
          kind: 'wireguard',
          mode: 'userspace',
          privateKeyRef: { vaultEntryId: 'e1', field: 'privateKey' },
          addresses: ['10.0.0.2/32'],
          dns: [],
          peers: [],
          listeners: [{ kind: 'socks5', bindHost: '127.0.0.1', bindPort: port }]
        }
      })

    profiles = [withSocks('v1', 1080), withSocks('v2', 1080)]
    behaviour.start = async () => ({
      ok: true,
      listeners: [{ kind: 'socks5', bindHost: '127.0.0.1', bindPort: 1080 }]
    })

    await mgr.vpnStart('v1')
    events.length = 0

    const second = await mgr.vpnStart('v2')
    expect(second.ok).toBe(false)
    expect(second.errorCode).toBe('port-in-use')
    expect(second.error).toContain('office-v1')
    // Refused before the engine was ever spawned, so there is no half-started
    // run to clean up.
    expect(events).toEqual([])
  })

  it('allows the same port once the other profile has stopped', async () => {
    const withSocks = (id: string): VpnProfile =>
      wgProfile({
        id,
        spec: {
          kind: 'wireguard',
          mode: 'userspace',
          privateKeyRef: { vaultEntryId: 'e1', field: 'privateKey' },
          addresses: ['10.0.0.2/32'],
          dns: [],
          peers: [],
          listeners: [{ kind: 'socks5', bindHost: '127.0.0.1', bindPort: 1080 }]
        }
      })
    profiles = [withSocks('v1'), withSocks('v2')]
    behaviour.start = async () => ({
      ok: true,
      listeners: [{ kind: 'socks5', bindHost: '127.0.0.1', bindPort: 1080 }]
    })

    await mgr.vpnStart('v1')
    await mgr.vpnStop('v1')
    expect((await mgr.vpnStart('v2')).ok).toBe(true)
  })

  it('does not treat port 0 as a conflict', async () => {
    // Port 0 means "pick one", so two profiles asking for it can never clash.
    const auto = (id: string): VpnProfile =>
      wgProfile({
        id,
        spec: {
          kind: 'wireguard',
          mode: 'userspace',
          privateKeyRef: { vaultEntryId: 'e1', field: 'privateKey' },
          addresses: ['10.0.0.2/32'],
          dns: [],
          peers: [],
          listeners: [{ kind: 'socks5', bindHost: '127.0.0.1', bindPort: 0 }]
        }
      })
    profiles = [auto('v1'), auto('v2')]
    behaviour.start = async () => ({
      ok: true,
      listeners: [{ kind: 'socks5', bindHost: '127.0.0.1', bindPort: 49152 }]
    })

    await mgr.vpnStart('v1')
    expect((await mgr.vpnStart('v2')).ok).toBe(true)
  })

  it('catches a wildcard bind shadowing a loopback one', async () => {
    // 0.0.0.0:1080 and 127.0.0.1:1080 collide, and comparing only the exact
    // host:port pair would miss exactly the case that bites.
    const mk = (id: string, host: string): VpnProfile =>
      wgProfile({
        id,
        name: `p-${id}`,
        spec: {
          kind: 'wireguard',
          mode: 'userspace',
          privateKeyRef: { vaultEntryId: 'e1', field: 'privateKey' },
          addresses: ['10.0.0.2/32'],
          dns: [],
          peers: [],
          listeners: [{ kind: 'socks5', bindHost: host, bindPort: 1080 }]
        }
      })
    profiles = [mk('v1', '0.0.0.0'), mk('v2', '127.0.0.1')]
    behaviour.start = async () => ({
      ok: true,
      listeners: [{ kind: 'socks5', bindHost: '0.0.0.0', bindPort: 1080 }]
    })

    await mgr.vpnStart('v1')
    const second = await mgr.vpnStart('v2')
    expect(second.errorCode).toBe('port-in-use')
    expect(second.error).toContain('p-v1')
  })

  it('reports a missing profile rather than throwing', async () => {
    profiles = []
    const r = await mgr.vpnStart('v1')
    expect(r.ok).toBe(false)
    expect(r.errorCode).toBe('config-invalid')
  })

  it('does not cache plaintext between starts', async () => {
    await mgr.vpnStart('v1')
    await mgr.vpnStop('v1')
    vaultLocked = true
    // Locking the vault between two starts must actually stop the second one.
    const r = await mgr.vpnStart('v1')
    expect(r.errorCode).toBe('vault-locked')
    expect(resolveCalls).toBe(2)
  })
})

describe('logs', () => {
  it('redacts before storing, so the buffer itself never holds the key', async () => {
    await mgr.vpnStart('v1')
    lastCtx?.log(`peer configured with private_key ${WG_KEY} and password ${PASSWORD}`, 'stderr')

    const lines = mgr.vpnLogs('v1')
    expect(lines).toHaveLength(1)
    expect(lines[0].text).not.toContain(WG_KEY)
    expect(lines[0].text).not.toContain(PASSWORD)
    expect(lines[0].text).toContain('[REDACTED]')
  })

  it('bounds the ring buffer', async () => {
    await mgr.vpnStart('v1')
    for (let i = 0; i < 2500; i++) lastCtx?.log(`line ${i}`, 'stdout')
    const lines = mgr.vpnLogs('v1', 10_000)
    expect(lines.length).toBeLessThanOrEqual(2000)
    // Oldest dropped, newest kept.
    expect(lines[lines.length - 1].text).toBe('line 2499')
  })

  it('returns nothing for a profile that has never run', () => {
    expect(mgr.vpnLogs('v1')).toEqual([])
  })

  it('keeps the last run log after the run is torn down', async () => {
    // Every failure path tears the run down before emitting the error, and the
    // ring used to go with it — so vpn:logs returned [] from the moment the
    // error appeared, while the error itself said "Open the log to see why".
    await mgr.vpnStart('v1')
    lastCtx?.log('peer handshake failed', 'stderr')
    await mgr.vpnStop('v1')

    const lines = mgr.vpnLogs('v1')
    expect(lines.map((l) => l.text)).toContain('peer handshake failed')
  })

  it('bounds the ring by bytes as well as by lines', async () => {
    await mgr.vpnStart('v1')
    // Ten lines of 512 KB each: well inside the 2000-line cap, well past the
    // 1 MB byte budget.
    for (let i = 0; i < 10; i++) lastCtx?.log('x'.repeat(512 * 1024), 'stdout')
    const total = mgr.vpnLogs('v1', 10_000).reduce((n, l) => n + l.text.length, 0)
    expect(total).toBeLessThanOrEqual(2 * 1024 * 1024)
    // The newest line always survives, however large it is.
    expect(mgr.vpnLogs('v1', 10_000).length).toBeGreaterThan(0)
  })
})

describe('stop and dependents', () => {
  it('closes dependents before the transport', async () => {
    await mgr.vpnStart('v1')
    const fwd = await mgr.vpnOpenForward('v1', 'db.internal', 5432, {
      kind: 'database',
      id: 'd1',
      name: 'prod'
    })
    expect(fwd.port).toBe(51999)
    expect(deps.hasLiveVpnDependents('v1')).toBe(true)

    events.length = 0
    await mgr.vpnStop('v1')
    // Nothing may observe a half-dead network: the consumer is released first.
    expect(events).toEqual(['driver.stop'])
    expect(deps.hasLiveVpnDependents('v1')).toBe(false)
  })

  it('reports a stop as successful when nothing was running', async () => {
    expect(await mgr.vpnStop('v1')).toEqual({ ok: true })
  })

  it('does not report stopped when the engine refused to die', async () => {
    // Showing a stopped tunnel while a process still holds the port — and, in
    // system mode, still holds the user's routes — is worse than showing the
    // failure.
    await mgr.vpnStart('v1')
    behaviour.stop = async () => {
      throw new Error('engine would not exit')
    }
    const r = await mgr.vpnStop('v1')
    expect(r.ok).toBe(false)
    expect(mgr.vpnStatus('v1')?.state).toBe('error')
    expect(mgr.vpnStatus('v1')?.error).toContain('engine would not exit')
  })

  it('clears a previous error when a later stop succeeds', async () => {
    await mgr.vpnStart('v1')
    behaviour.stop = async () => {
      throw new Error('engine would not exit')
    }
    await mgr.vpnStop('v1')
    behaviour.stop = async () => undefined
    await mgr.vpnStart('v1')
    await mgr.vpnStop('v1')
    expect(mgr.vpnStatus('v1')?.state).toBe('stopped')
    expect(mgr.vpnStatus('v1')?.errorCode).toBeUndefined()
  })

  it('releases dependents even when the engine refuses to stop', async () => {
    // The session is finished either way; leaving it registered would make a
    // later start think something was still riding a tunnel that is gone.
    await mgr.vpnStart('v1')
    await mgr.vpnOpenForward('v1', 'h', 1, { kind: 'session', id: 's1', name: 'x' })
    behaviour.stop = async () => {
      throw new Error('engine would not exit')
    }
    await mgr.vpnStop('v1')
    expect(deps.hasLiveVpnDependents('v1')).toBe(false)
  })

  it('passes force through', async () => {
    await mgr.vpnStart('v1')
    events.length = 0
    await mgr.vpnStop('v1', { force: true })
    expect(events).toEqual(['driver.stop:force'])
  })

  it('reconciles everything when the driver reports a drop', async () => {
    // The whole point of the `dropped` hook. Emitting state:'error' alone left
    // the Live entry, its run directory, its resolved plaintext secrets and
    // every dependent registration in place — so hasLiveVpnDependents went on
    // lying to the stop confirmation and to the MCP policy check, and OpenVPN
    // refused the next start with "already running" beside a dead tunnel.
    await mgr.vpnStart('v1')
    await mgr.vpnOpenForward('v1', 'db.internal', 5432, {
      kind: 'database',
      id: 'd1',
      name: 'prod'
    })
    expect(deps.hasLiveVpnDependents('v1')).toBe(true)
    events.length = 0
    disposedRunDirs.length = 0

    lastCtx?.dropped('the endpoint stopped answering', 'network-unreachable')
    await new Promise((r) => setTimeout(r, 0))

    const st = mgr.vpnStatus('v1')
    expect(st?.state).toBe('error')
    expect(st?.error).toContain('the endpoint stopped answering')
    // Dependents released, the driver told to stop, the run torn down.
    expect(deps.hasLiveVpnDependents('v1')).toBe(false)
    expect(events).toContain('driver.stop:force')
    expect(disposedRunDirs).toHaveLength(1)
  })

  it('a drop leaves the profile startable again', async () => {
    await mgr.vpnStart('v1')
    lastCtx?.dropped('link went away')
    await new Promise((r) => setTimeout(r, 0))
    events.length = 0
    const again = await mgr.vpnStart('v1')
    expect(again.ok).toBe(true)
    expect(events).toContain('driver.start')
  })

  it('ignores a drop for a profile that is not running', async () => {
    await expect(mgr.vpnDropped('v1', 'nothing here')).resolves.toBeUndefined()
  })

  it('closes dependents when the tunnel drops on its own', async () => {
    await mgr.vpnStart('v1')
    await mgr.vpnOpenForward('v1', 'db.internal', 5432, { kind: 'session', id: 's1', name: 'psql' })
    await mgr.vpnDropped('v1', 'handshake lost')

    expect(deps.hasLiveVpnDependents('v1')).toBe(false)
    const st = mgr.vpnStatus('v1')
    expect(st?.state).toBe('error')
    expect(st?.error).toContain('handshake lost')
  })

  it('surfaces the VPN error when a forward is opened over a VPN that will not start', async () => {
    // Otherwise this arrives downstream as an unexplained ETIMEDOUT, which is
    // the worst failure mode this feature has.
    vaultLocked = true
    await expect(
      mgr.vpnOpenForward('v1', 'db.internal', 5432, { kind: 'database', id: 'd1', name: 'prod' })
    ).rejects.toMatchObject({ code: 'vault-locked' })
  })

  it('releases the dependent registration when the forward is closed', async () => {
    await mgr.vpnStart('v1')
    const fwd = await mgr.vpnOpenForward('v1', 'h', 1, { kind: 'session', id: 's1', name: 'x' })
    fwd.close()
    expect(deps.hasLiveVpnDependents('v1')).toBe(false)
    // Double close is a normal consequence of teardown racing a user action.
    expect(() => fwd.close()).not.toThrow()
    expect(events.filter((e) => e === 'forward.close')).toHaveLength(1)
  })
})

describe('status shape', () => {
  it('stamps `since` on a state change but not on a stats-only update', async () => {
    await mgr.vpnStart('v1')
    const since = mgr.vpnStatus('v1')?.since
    expect(since).toBeTypeOf('number')

    lastCtx?.emit({ stats: { rxBytes: 10, txBytes: 20, sampledAt: Date.now() } })
    expect(mgr.vpnStatus('v1')?.since).toBe(since)
  })

  it('clears a previous error when the tunnel comes back up', async () => {
    behaviour.start = async () => ({ ok: false, error: 'nope', errorCode: 'handshake-timeout' as const })
    await mgr.vpnStart('v1')
    expect(mgr.vpnStatus('v1')?.errorCode).toBe('handshake-timeout')

    behaviour.start = async () => ({ ok: true })
    await mgr.vpnStart('v1')
    expect(mgr.vpnStatus('v1')?.state).toBe('connected')
    expect(mgr.vpnStatus('v1')?.errorCode).toBeUndefined()
  })
})

describe('validation', () => {
  it('does not let a throwing validator take the window down', () => {
    behaviour.validate = () => {
      throw new Error('regex blew up')
    }
    const v = mgr.vpnValidate(wgProfile().spec)
    expect(v.ok).toBe(false)
    expect(v.issues[0].code).toBe('validator-failed')
  })
})

describe('prompts', () => {
  it('returns null when no window can answer, rather than hanging', async () => {
    await mgr.vpnStart('v1')
    await expect(
      lastCtx?.askUser({ kind: 'otp', label: 'Enter your code', echo: false })
    ).resolves.toBeNull()
  })

  it('routes a prompt with the profile identity attached', async () => {
    const seen: unknown[] = []
    mgr.setVpnPrompter(async (p) => {
      seen.push(p)
      return '123456'
    })
    await mgr.vpnStart('v1')
    const answer = await lastCtx?.askUser({ kind: 'otp', label: 'Enter your code', echo: false })
    expect(answer).toBe('123456')
    expect(seen[0]).toMatchObject({ profileId: 'v1', profileName: 'office', kind: 'otp' })
  })
})

describe('lifecycle', () => {
  it('reaps orphans before starting anything', async () => {
    profiles = [wgProfile({ autoStart: true })]
    await mgr.vpnInit()
    expect(supervisorCalls[0]).toBe('reapOrphans')
  })

  it('does not let one failing autostart stop the app from booting', async () => {
    behaviour.start = async () => {
      throw new Error('nope')
    }
    profiles = [wgProfile({ autoStart: true })]
    await expect(mgr.vpnInit()).resolves.toBeUndefined()
  })

  it('runs init once', async () => {
    await mgr.vpnInit()
    await mgr.vpnInit()
    expect(supervisorCalls.filter((c) => c === 'reapOrphans')).toHaveLength(1)
  })

  it('force-stops everything on dispose', async () => {
    await mgr.vpnStart('v1')
    events.length = 0
    await mgr.vpnDisposeAll()
    expect(events).toContain('driver.stop:force')
    expect(supervisorCalls).toContain('stopAll')
  })
})
