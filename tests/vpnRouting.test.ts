import { describe, it, expect, beforeEach, vi } from 'vitest'

// Every read this module does goes through execFile, so the whole platform
// surface can be driven from captured command output. The argv assertions are
// the point of the file: a typo in one of these strings is a broken network on
// a machine nobody is testing on.
const h = vi.hoisted(() => ({
  replies: new Map<string, { code?: number; stdout?: string; stderr?: string }>(),
  reads: [] as { cmd: string; args: string[] }[]
}))

vi.mock('node:child_process', () => ({
  execFile: (
    cmd: string,
    args: string[],
    _opts: unknown,
    cb: (e: unknown, stdout: string, stderr: string) => void
  ) => {
    h.reads.push({ cmd, args })
    const reply = h.replies.get(`${cmd} ${args.join(' ')}`) ?? {
      code: 1,
      stderr: `no fixture for ${cmd} ${args.join(' ')}`
    }
    const code = reply.code ?? 0
    setImmediate(() =>
      code === 0
        ? cb(null, reply.stdout ?? '', reply.stderr ?? '')
        : cb(Object.assign(new Error(`exit ${code}`), { code }), reply.stdout ?? '', reply.stderr ?? '')
    )
    return undefined
  },
  spawn: () => {
    throw new Error('spawn is not used by the routing managers')
  }
}))

import { VpnError } from '../src/main/services/vpn/errors'
import type { NetApplyContext, PrivilegedResult } from '../src/main/services/vpn/netstate'
import {
  claimsDefault,
  detectIpv6Leak,
  expandDefaultRoutes,
  maskToPrefix,
  normalizeCidr,
  routeManagerFor
} from '../src/main/services/vpn/routing/index'
import type { RouteSpec } from '../src/main/services/vpn/routing/index'
import { parseRouteGet } from '../src/main/services/vpn/routing/darwin'
import { parseIpRoute } from '../src/main/services/vpn/routing/linux'
import {
  parseNetshShowRoute,
  parseRoutePrint,
  parseShowInterfaces
} from '../src/main/services/vpn/routing/win32'

function reply(key: string, stdout: string, code = 0): void {
  h.replies.set(key, { code, stdout })
}

interface Recorder {
  ctx: NetApplyContext
  calls: { cmd: string; args: string[] }[]
  result: PrivilegedResult
}

function recorder(over: Partial<NetApplyContext> = {}): Recorder {
  const rec: Recorder = {
    calls: [],
    result: { code: 0, stdout: '', stderr: '' },
    ctx: {
      runId: 'run-1',
      runDir: '/tmp/vpn-run/run-1',
      supportsStdin: true,
      runPrivileged: async (cmd, args) => {
        rec.calls.push({ cmd, args })
        return rec.result
      },
      ...over
    }
  }
  return rec
}

const argv = (rec: Recorder): string[][] => rec.calls.map((c) => c.args)

// ------------------------------------------------------------------ fixtures

const DARWIN_DEFAULT_V4 = `   route to: default
destination: default
       mask: default
    gateway: 192.168.1.1
  interface: en0
      flags: <UP,GATEWAY,DONE,STATIC,PRCLONING,GLOBAL>
 recvpipe  sendpipe  ssthresh  rtt,msec    rttvar  hopcount      mtu     expire
       0         0         0         0         0         0      1500         0
`

const DARWIN_DEFAULT_V6 = `   route to: default
destination: default
       mask: default
    gateway: fe80::1%en0
  interface: en0
      flags: <UP,GATEWAY,DONE,STATIC>
`

const DARWIN_CLAIMED = `   route to: 10.8.0.0
destination: 10.8.0.0
       mask: 255.255.255.0
    gateway: 10.9.0.1
  interface: utun9
      flags: <UP,GATEWAY,DONE,STATIC>
`

const LINUX_V4 = `default via 192.168.1.1 dev eth0 proto dhcp src 192.168.1.50 metric 100
10.8.0.0/24 dev wg0 proto kernel scope link src 10.8.0.2
172.17.0.0/16 dev docker0 proto kernel scope link src 172.17.0.1 linkdown
192.168.1.0/24 dev eth0 proto kernel scope link src 192.168.1.50 metric 100
`

const LINUX_V6 = `::1 dev lo proto kernel metric 256 pref medium
fe80::/64 dev eth0 proto kernel metric 256 pref medium
default via fe80::1 dev eth0 proto ra metric 1024 expires 1798sec hoplimit 64 pref medium
`

const WIN_ROUTE_PRINT = `===========================================================================
Interface List
 24...00 00 00 00 00 00 00 e0 ......ShellPilot Tunnel
 12...ac de 48 00 11 22 ......Intel(R) Ethernet Connection
  1...........................Software Loopback Interface 1
===========================================================================

IPv4 Route Table
===========================================================================
Active Routes:
Network Destination        Netmask          Gateway       Interface  Metric
          0.0.0.0          0.0.0.0      192.168.1.1     192.168.1.50     25
        127.0.0.0        255.0.0.0         On-link         127.0.0.1    331
     192.168.1.0    255.255.255.0         On-link      192.168.1.50    281
===========================================================================
Persistent Routes:
  None

IPv6 Route Table
===========================================================================
Active Routes:
 If Metric Network Destination      Gateway
  1    331 ::1/128                  On-link
 12    281 ::/0                     fe80::1
===========================================================================
`

const WIN_SHOW_INTERFACES = `
Idx     Met         MTU          State                Name
---  ----------  ----------  ------------  ---------------------------
  1          75  4294967295  connected     Loopback Pseudo-Interface 1
 12          25        1500  connected     Ethernet
 24           5        1420  connected     ShellPilot Tunnel
`

const WIN_SHOW_ROUTE_V4 = `
Publish  Type      Met  Prefix                    Idx  Gateway/Interface Name
-------  --------  ---  ------------------------  ---  ------------------------
No       Manual    256  0.0.0.0/0                  12  192.168.1.1
No       System    256  10.8.0.0/24                31  OtherVPN
No       System    256  127.0.0.0/8                 1  Loopback Pseudo-Interface 1
`

const WIN_SHOW_ROUTE_V6 = `
Publish  Type      Met  Prefix                    Idx  Gateway/Interface Name
-------  --------  ---  ------------------------  ---  ------------------------
No       Manual    256  ::/0                       12  fe80::1
`

function winReads(): void {
  reply('route print', WIN_ROUTE_PRINT)
  reply('netsh interface ipv4 show interfaces', WIN_SHOW_INTERFACES)
  reply('netsh interface ipv6 show interfaces', WIN_SHOW_INTERFACES)
  reply('netsh interface ipv4 show route', WIN_SHOW_ROUTE_V4)
  reply('netsh interface ipv6 show route', WIN_SHOW_ROUTE_V6)
}

beforeEach(() => {
  h.replies.clear()
  h.reads.length = 0
})

// -------------------------------------------------------------------- shared

describe('routing helpers', () => {
  it('never turns a default route into a default-route replacement', () => {
    // The two halves win on longest-prefix match without the original default
    // ever being removed, so a crash leaves the host's own default intact.
    expect(expandDefaultRoutes([{ destination: '0.0.0.0/0', interfaceName: 'wg0' }])).toEqual([
      { destination: '0.0.0.0/1', interfaceName: 'wg0' },
      { destination: '128.0.0.0/1', interfaceName: 'wg0' }
    ])
    expect(expandDefaultRoutes([{ destination: '::/0', interfaceName: 'wg0' }])).toEqual([
      { destination: '::/1', interfaceName: 'wg0' },
      { destination: '8000::/1', interfaceName: 'wg0' }
    ])
  })

  it('leaves a non-default prefix alone apart from normalising it', () => {
    expect(expandDefaultRoutes([{ destination: '10.8.0.0/24', interfaceName: 'wg0' }])).toEqual([
      { destination: '10.8.0.0/24', interfaceName: 'wg0' }
    ])
    expect(normalizeCidr('10.8.0.1')).toBe('10.8.0.1/32')
    expect(normalizeCidr('default')).toBe('0.0.0.0/0')
    expect(normalizeCidr('default', 'inet6')).toBe('::/0')
  })

  it('reads a dotted netmask back as a prefix length and rejects a discontiguous one', () => {
    expect(maskToPrefix('255.255.255.0')).toBe(24)
    expect(maskToPrefix('0.0.0.0')).toBe(0)
    expect(maskToPrefix('255.255.255.255')).toBe(32)
    expect(maskToPrefix('255.0.255.0')).toBeNull()
    expect(maskToPrefix('nonsense')).toBeNull()
  })

  it('recognises a full tunnel however it was written', () => {
    expect(claimsDefault([{ destination: '0.0.0.0/0', interfaceName: 'wg0' }], 'inet')).toBe(true)
    expect(
      claimsDefault(
        [
          { destination: '0.0.0.0/1', interfaceName: 'wg0' },
          { destination: '128.0.0.0/1', interfaceName: 'wg0' }
        ],
        'inet'
      )
    ).toBe(true)
    expect(claimsDefault([{ destination: '10.8.0.0/24', interfaceName: 'wg0' }], 'inet')).toBe(false)
  })

  it('reports an IPv6 leak, and only when the server actually has IPv6 (E16)', () => {
    const v6Default = { destination: '::/0', gateway: 'fe80::1', interfaceName: 'eth0', family: 'inet6' as const }
    const leak = detectIpv6Leak([{ destination: '0.0.0.0/0', interfaceName: 'wg0' }], [v6Default])
    expect(leak?.kind).toBe('ipv6-leak')
    expect(leak?.message).toContain('fe80::1')
    expect(leak?.message).toContain('eth0')

    expect(
      detectIpv6Leak(
        [
          { destination: '0.0.0.0/0', interfaceName: 'wg0' },
          { destination: '::/0', interfaceName: 'wg0' }
        ],
        [v6Default]
      )
    ).toBeNull()
    expect(detectIpv6Leak([{ destination: '0.0.0.0/0', interfaceName: 'wg0' }], [])).toBeNull()
  })

  it('refuses a platform it has no implementation for rather than guessing', () => {
    expect(() => routeManagerFor('freebsd')).toThrow(VpnError)
  })
})

// -------------------------------------------------------------------- darwin

describe('darwin routes', () => {
  const mgr = (): ReturnType<typeof routeManagerFor> => routeManagerFor('darwin')

  function darwinDefaults(v6 = true): void {
    reply('route -n get default', DARWIN_DEFAULT_V4)
    if (v6) reply('route -n get -inet6 default', DARWIN_DEFAULT_V6)
    else h.replies.set('route -n get -inet6 default', { code: 1, stderr: 'route: writing to routing socket: not in table' })
  }

  it('parses route -n get into the three fields that matter', () => {
    const fields = parseRouteGet(DARWIN_DEFAULT_V4)
    expect(fields.destination).toBe('default')
    expect(fields.gateway).toBe('192.168.1.1')
    expect(fields.interface).toBe('en0')
  })

  it('snapshots both default routes', async () => {
    darwinDefaults()
    const snap = await mgr().snapshot()
    expect(snap.platform).toBe('darwin')
    expect(snap.planned).toEqual([])
    expect(snap.defaults).toEqual([
      { destination: 'default', gateway: '192.168.1.1', interfaceName: 'en0', family: 'inet' },
      { destination: 'default', gateway: 'fe80::1%en0', interfaceName: 'en0', family: 'inet6' }
    ])
  })

  it('treats "not in table" as no default rather than as a failure', async () => {
    darwinDefaults(false)
    const snap = await mgr().snapshot()
    expect(snap.defaults.map((d) => d.family)).toEqual(['inet'])
  })

  it('produces the exact argv for apply, including the IPv6 and gateway forms', async () => {
    const rec = recorder()
    await mgr().apply(
      [
        { destination: '10.8.0.0/24', interfaceName: 'utun4' },
        { destination: 'fd00::/64', interfaceName: 'utun4' },
        { destination: '172.16.0.0/12', interfaceName: 'utun4', gateway: '10.8.0.1' },
        { destination: '0.0.0.0/0', interfaceName: 'utun4' }
      ],
      rec.ctx
    )
    expect(rec.calls.every((c) => c.cmd === 'route')).toBe(true)
    expect(argv(rec)).toEqual([
      ['-n', 'add', '-net', '10.8.0.0/24', '-interface', 'utun4'],
      ['-n', 'add', '-inet6', '-net', 'fd00::/64', '-interface', 'utun4'],
      ['-n', 'add', '-net', '172.16.0.0/12', '10.8.0.1'],
      ['-n', 'add', '-net', '0.0.0.0/1', '-interface', 'utun4'],
      ['-n', 'add', '-net', '128.0.0.0/1', '-interface', 'utun4']
    ])
  })

  it('produces the exact argv for revert and puts the more specific route back first', async () => {
    darwinDefaults()
    const rec = recorder()
    await mgr().revert(
      {
        platform: 'darwin',
        capturedAt: 0,
        defaults: [],
        planned: [
          { destination: '10.8.0.0/24', interfaceName: 'utun4' },
          { destination: '0.0.0.0/0', interfaceName: 'utun4' }
        ]
      },
      rec.ctx
    )
    expect(argv(rec)).toEqual([
      ['-n', 'delete', '-net', '128.0.0.0/1', '-interface', 'utun4'],
      ['-n', 'delete', '-net', '0.0.0.0/1', '-interface', 'utun4'],
      ['-n', 'delete', '-net', '10.8.0.0/24', '-interface', 'utun4']
    ])
  })

  it('reverts idempotently when the routes have already gone', async () => {
    darwinDefaults()
    const rec = recorder()
    rec.result = { code: 1, stdout: '', stderr: 'route: not in table' }
    const snapshot = {
      platform: 'darwin' as const,
      capturedAt: 0,
      defaults: [],
      planned: [{ destination: '10.8.0.0/24', interfaceName: 'utun4' }]
    }
    await mgr().revert(snapshot, rec.ctx)
    const first = argv(rec)
    rec.calls.length = 0
    await expect(mgr().revert(snapshot, rec.ctx)).resolves.toBeUndefined()
    expect(argv(rec)).toEqual(first)
  })

  it('puts a default route back when it went missing while we were up', async () => {
    h.replies.set('route -n get default', { code: 1, stderr: 'not in table' })
    h.replies.set('route -n get -inet6 default', { code: 1, stderr: 'not in table' })
    const rec = recorder()
    await mgr().revert(
      {
        platform: 'darwin',
        capturedAt: 0,
        defaults: [{ destination: 'default', gateway: '192.168.1.1', interfaceName: 'en0', family: 'inet' }],
        planned: []
      },
      rec.ctx
    )
    expect(argv(rec)).toEqual([['-n', 'add', 'default', '192.168.1.1']])
  })

  it('maps a permission failure onto a code the user gets a sentence for', async () => {
    const rec = recorder()
    rec.result = { code: 1, stdout: '', stderr: 'route: writing to routing socket: Operation not permitted' }
    await expect(
      mgr().apply([{ destination: '10.8.0.0/24', interfaceName: 'utun4' }], rec.ctx)
    ).rejects.toMatchObject({ code: 'permission-denied' })
  })

  it('treats an identical existing route as a retry, not a failure', async () => {
    const rec = recorder()
    rec.result = { code: 1, stdout: '', stderr: 'route: writing to routing socket: File exists' }
    await expect(
      mgr().apply([{ destination: '10.8.0.0/24', interfaceName: 'utun4' }], rec.ctx)
    ).resolves.toBeUndefined()
  })

  it('names the interface already holding a prefix (E15)', async () => {
    darwinDefaults()
    reply('route -n get 10.8.0.0/24', DARWIN_CLAIMED)
    const conflicts = await mgr().conflicts([{ destination: '10.8.0.0/24', interfaceName: 'utun4' }])
    const claimed = conflicts.filter((c) => c.kind === 'prefix-claimed')
    expect(claimed).toHaveLength(1)
    expect(claimed[0]).toMatchObject({ kind: 'prefix-claimed', destination: '10.8.0.0/24' })
    expect(claimed[0].message).toContain('utun9')
    expect(claimed[0].message).toContain('10.9.0.1')
  })

  it('does not call the covering default route a conflict', async () => {
    // No IPv6 default on this host either, so there is nothing at all to say.
    darwinDefaults(false)
    reply('route -n get 10.8.0.0/24', DARWIN_DEFAULT_V4)
    expect(await mgr().conflicts([{ destination: '10.8.0.0/24', interfaceName: 'utun4' }])).toEqual([])
  })

  it('reports the IPv6 leak alongside the prefix conflicts', async () => {
    darwinDefaults()
    reply('route -n get 0.0.0.0/1', DARWIN_DEFAULT_V4)
    reply('route -n get 128.0.0.0/1', DARWIN_DEFAULT_V4)
    const conflicts = await mgr().conflicts([{ destination: '0.0.0.0/0', interfaceName: 'utun4' }])
    expect(conflicts.map((c) => c.kind)).toContain('ipv6-leak')
  })
})

// --------------------------------------------------------------------- linux

describe('linux routes', () => {
  const mgr = (): ReturnType<typeof routeManagerFor> => routeManagerFor('linux')

  function linuxTable(): void {
    reply('ip -4 route show default', 'default via 192.168.1.1 dev eth0 proto dhcp metric 100\n')
    reply('ip -6 route show default', 'default via fe80::1 dev eth0 proto ra metric 1024 pref medium\n')
    reply('ip -4 route show', LINUX_V4)
    reply('ip -6 route show', LINUX_V6)
  }

  it('parses ip route show, keywords and all', () => {
    const v4 = parseIpRoute(LINUX_V4, 'inet')
    expect(v4[0]).toEqual({
      destination: '0.0.0.0/0',
      gateway: '192.168.1.1',
      interfaceName: 'eth0',
      metric: 100,
      family: 'inet'
    })
    expect(v4[1]).toEqual({ destination: '10.8.0.0/24', interfaceName: 'wg0', family: 'inet' })
    const v6 = parseIpRoute(LINUX_V6, 'inet6')
    expect(v6.map((e) => e.destination)).toEqual(['::1/128', 'fe80::/64', '::/0'])
  })

  it('ignores the continuation lines of a multipath route', () => {
    const text = `default proto static metric 20
\tnexthop via 10.0.0.1 dev eth0 weight 1
\tnexthop via 10.0.1.1 dev eth1 weight 1
`
    expect(parseIpRoute(text, 'inet')).toHaveLength(1)
  })

  it('snapshots only the defaults', async () => {
    linuxTable()
    const snap = await mgr().snapshot()
    expect(snap.defaults.map((d) => d.destination)).toEqual(['0.0.0.0/0', '::/0'])
  })

  it('produces the exact argv for apply, with an explicit family flag', async () => {
    const rec = recorder()
    await mgr().apply(
      [
        { destination: '10.8.0.0/24', interfaceName: 'wg0' },
        { destination: 'fd00::/64', interfaceName: 'wg0' },
        { destination: '172.16.0.0/12', interfaceName: 'wg0', gateway: '10.8.0.1', metric: 50 },
        { destination: '0.0.0.0/0', interfaceName: 'wg0' }
      ],
      rec.ctx
    )
    expect(rec.calls.every((c) => c.cmd === 'ip')).toBe(true)
    expect(argv(rec)).toEqual([
      ['-4', 'route', 'replace', '10.8.0.0/24', 'dev', 'wg0'],
      ['-6', 'route', 'replace', 'fd00::/64', 'dev', 'wg0'],
      ['-4', 'route', 'replace', '172.16.0.0/12', 'via', '10.8.0.1', 'dev', 'wg0', 'metric', '50'],
      ['-4', 'route', 'replace', '0.0.0.0/1', 'dev', 'wg0'],
      ['-4', 'route', 'replace', '128.0.0.0/1', 'dev', 'wg0']
    ])
  })

  it('produces the exact argv for revert', async () => {
    linuxTable()
    const rec = recorder()
    await mgr().revert(
      {
        platform: 'linux',
        capturedAt: 0,
        defaults: [],
        planned: [
          { destination: '10.8.0.0/24', interfaceName: 'wg0' },
          { destination: '::/0', interfaceName: 'wg0' }
        ]
      },
      rec.ctx
    )
    expect(argv(rec)).toEqual([
      ['-6', 'route', 'del', '8000::/1', 'dev', 'wg0'],
      ['-6', 'route', 'del', '::/1', 'dev', 'wg0'],
      ['-4', 'route', 'del', '10.8.0.0/24', 'dev', 'wg0']
    ])
  })

  it('survives a revert against routes that have already gone', async () => {
    linuxTable()
    const rec = recorder()
    rec.result = { code: 2, stdout: '', stderr: 'RTNETLINK answers: No such process' }
    const snapshot = {
      platform: 'linux' as const,
      capturedAt: 0,
      defaults: [],
      planned: [{ destination: '10.8.0.0/24', interfaceName: 'wg0' }]
    }
    await expect(mgr().revert(snapshot, rec.ctx)).resolves.toBeUndefined()
    await expect(mgr().revert(snapshot, rec.ctx)).resolves.toBeUndefined()
  })

  it('finds a prefix another interface already holds, and the IPv6 leak', async () => {
    linuxTable()
    const conflicts = await mgr().conflicts([
      { destination: '10.8.0.0/24', interfaceName: 'wg1' },
      { destination: '0.0.0.0/0', interfaceName: 'wg1' }
    ])
    const claimed = conflicts.filter((c) => c.kind === 'prefix-claimed')
    expect(claimed).toHaveLength(1)
    expect(claimed[0].destination).toBe('10.8.0.0/24')
    expect(claimed[0].message).toContain('wg0')
    expect(conflicts.some((c) => c.kind === 'ipv6-leak')).toBe(true)
  })

  it('does not call our own interface a conflict', async () => {
    linuxTable()
    const conflicts = await mgr().conflicts([{ destination: '10.8.0.0/24', interfaceName: 'wg0' }])
    expect(conflicts.filter((c) => c.kind === 'prefix-claimed')).toEqual([])
  })
})

// --------------------------------------------------------------------- win32

describe('win32 routes', () => {
  const mgr = (): ReturnType<typeof routeManagerFor> => routeManagerFor('win32')

  it('maps a localised interface list to indexes positionally', () => {
    expect(parseShowInterfaces(WIN_SHOW_INTERFACES)).toEqual({
      'Loopback Pseudo-Interface 1': 1,
      Ethernet: 12,
      'ShellPilot Tunnel': 24
    })
  })

  it('parses both halves of route print', () => {
    const table = parseRoutePrint(WIN_ROUTE_PRINT)
    expect(table.filter((e) => e.family === 'inet').map((e) => e.destination)).toEqual([
      '0.0.0.0/0',
      '127.0.0.0/8',
      '192.168.1.0/24'
    ])
    expect(table.find((e) => e.destination === '0.0.0.0/0')?.gateway).toBe('192.168.1.1')
    // On-link is not a next hop.
    expect(table.find((e) => e.destination === '127.0.0.0/8')?.gateway).toBeUndefined()
    expect(table.filter((e) => e.family === 'inet6').map((e) => e.destination)).toEqual(['::1/128', '::/0'])
    expect(table.find((e) => e.destination === '::/0')?.interfaceIndex).toBe(12)
  })

  it('parses netsh show route by index', () => {
    expect(parseNetshShowRoute(WIN_SHOW_ROUTE_V4, 'inet')).toEqual([
      { destination: '0.0.0.0/0', gateway: '192.168.1.1', interfaceIndex: 12, metric: 256, family: 'inet' },
      { destination: '10.8.0.0/24', gateway: 'OtherVPN', interfaceIndex: 31, metric: 256, family: 'inet' },
      {
        destination: '127.0.0.0/8',
        gateway: 'Loopback Pseudo-Interface 1',
        interfaceIndex: 1,
        metric: 256,
        family: 'inet'
      }
    ])
  })

  it('snapshots the defaults and the name-to-index map', async () => {
    winReads()
    const snap = await mgr().snapshot()
    expect(snap.defaults.map((d) => d.destination)).toEqual(['0.0.0.0/0', '::/0'])
    expect(snap.interfaceIndex?.['ShellPilot Tunnel']).toBe(24)
  })

  it('produces the exact argv for apply, addressing the interface by index', async () => {
    winReads()
    const rec = recorder()
    await mgr().apply(
      [
        { destination: '10.8.0.0/24', interfaceName: 'ShellPilot Tunnel' },
        { destination: 'fd00::/64', interfaceName: 'ShellPilot Tunnel' },
        { destination: '0.0.0.0/0', interfaceName: 'ShellPilot Tunnel', gateway: '10.8.0.1', metric: 5 }
      ],
      rec.ctx
    )
    expect(rec.calls.every((c) => c.cmd === 'netsh')).toBe(true)
    expect(argv(rec)).toEqual([
      ['interface', 'ipv4', 'add', 'route', 'prefix=10.8.0.0/24', 'interface=24', 'store=active'],
      ['interface', 'ipv6', 'add', 'route', 'prefix=fd00::/64', 'interface=24', 'store=active'],
      [
        'interface',
        'ipv4',
        'add',
        'route',
        'prefix=0.0.0.0/1',
        'interface=24',
        'nexthop=10.8.0.1',
        'metric=5',
        'store=active'
      ],
      [
        'interface',
        'ipv4',
        'add',
        'route',
        'prefix=128.0.0.0/1',
        'interface=24',
        'nexthop=10.8.0.1',
        'metric=5',
        'store=active'
      ]
    ])
  })

  it('refuses to guess when the interface name resolves to no index', async () => {
    winReads()
    const rec = recorder()
    await expect(
      mgr().apply([{ destination: '10.8.0.0/24', interfaceName: 'Gone' }], rec.ctx)
    ).rejects.toMatchObject({ code: 'interface-conflict' })
    expect(rec.calls).toEqual([])
  })

  it('produces the exact argv for revert and uses the index the snapshot recorded', async () => {
    // The adapter is gone, so a fresh lookup would find nothing; the snapshot
    // is what still knows which index to delete against.
    reply('netsh interface ipv4 show interfaces', 'Idx     Met         MTU          State                Name\n')
    reply('netsh interface ipv6 show interfaces', 'Idx     Met         MTU          State                Name\n')
    const rec = recorder()
    await mgr().revert(
      {
        platform: 'win32',
        capturedAt: 0,
        defaults: [],
        planned: [{ destination: '10.8.0.0/24', interfaceName: 'ShellPilot Tunnel' }],
        interfaceIndex: { 'ShellPilot Tunnel': 24 }
      },
      rec.ctx
    )
    expect(argv(rec)).toEqual([
      ['interface', 'ipv4', 'delete', 'route', 'prefix=10.8.0.0/24', 'interface=24', 'store=active']
    ])
  })

  it('does nothing when neither the snapshot nor the system knows the index', async () => {
    reply('netsh interface ipv4 show interfaces', '')
    reply('netsh interface ipv6 show interfaces', '')
    const rec = recorder()
    await mgr().revert(
      {
        platform: 'win32',
        capturedAt: 0,
        defaults: [],
        planned: [{ destination: '10.8.0.0/24', interfaceName: 'ShellPilot Tunnel' }]
      },
      rec.ctx
    )
    expect(rec.calls).toEqual([])
  })

  it('compares interfaces by index when detecting a conflict', async () => {
    winReads()
    const routes: RouteSpec[] = [{ destination: '10.8.0.0/24', interfaceName: 'ShellPilot Tunnel' }]
    const conflicts = await mgr().conflicts(routes)
    const claimed = conflicts.filter((c) => c.kind === 'prefix-claimed')
    expect(claimed).toHaveLength(1)
    expect(claimed[0].existing.interfaceIndex).toBe(31)
    expect(claimed[0].message).toContain('interface 31')
  })
})
