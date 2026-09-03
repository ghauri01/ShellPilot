import { describe, it, expect } from 'vitest'
import { parseServices, parseListeners, sumNetwork } from '../src/main/services/metrics'

// Real output shapes from the two probes, including the awkward ones: dual
// stack rows, IPv6 endpoints, udp rows that have no LISTEN state, and hosts
// where the probe ran without the privilege to name the owning process.

describe('systemd units', () => {
  it('reads the plain list-units format', () => {
    const out = parseServices([
      'nginx.service loaded active running A high performance web server',
      'ssh.service loaded active running OpenBSD Secure Shell server'
    ])
    expect(out).toEqual([
      { name: 'nginx', active: 'active', sub: 'running', description: 'A high performance web server' },
      { name: 'ssh', active: 'active', sub: 'running', description: 'OpenBSD Secure Shell server' }
    ])
  })

  it('keeps failed units, which are the ones worth seeing', () => {
    // Some versions still print the bullet through --plain.
    const out = parseServices(['● postgresql.service loaded failed failed PostgreSQL RDBMS'])
    expect(out).toEqual([
      { name: 'postgresql', active: 'failed', sub: 'failed', description: 'PostgreSQL RDBMS' }
    ])
  })

  it('ignores non-service units and blank lines', () => {
    expect(parseServices(['', '  ', 'foo.socket loaded active listening A socket'])).toEqual([])
  })

  it('survives a truncated line rather than emitting a half-parsed unit', () => {
    expect(parseServices(['nginx.service loaded'])).toEqual([])
  })
})

describe('listeners from ss', () => {
  const lines = (extra: string[] = []): string[] => [
    'src:ss',
    'tcp   LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=812,fd=3))',
    'tcp   LISTEN 0 128 [::]:22 [::]:* users:(("sshd",pid=812,fd=4))',
    ...extra
  ]

  it('reads address, port and the owning process', () => {
    const { listeners, source } = parseListeners(lines())
    expect(source).toBe('ss')
    // 0.0.0.0, :: and * all mean every interface, so they report as one.
    expect(listeners).toEqual([{ proto: 'tcp', address: '*', port: 22, process: 'sshd', pid: 812 }])
  })

  it('collapses the v4 and v6 rows of one dual-stack listener', () => {
    // ss prints both; a reader wants one row per proto/address/port.
    expect(parseListeners(lines())).toMatchObject({ listeners: [{ port: 22 }] })
  })

  it('keeps a specific bind address rather than flattening everything', () => {
    // Only wildcards collapse: 127.0.0.1:5432 is a materially different thing
    // from *:5432 and must not be reported as the same.
    const { listeners } = parseListeners(['src:ss', 'tcp LISTEN 0 128 127.0.0.1:5432 0.0.0.0:*'])
    expect(listeners[0]).toMatchObject({ address: '127.0.0.1', port: 5432 })
  })

  it('parses an IPv6 endpoint by the last colon, not the first', () => {
    const { listeners } = parseListeners(['src:ss', 'tcp LISTEN 0 128 [fe80::1]:8080 [::]:*'])
    expect(listeners[0]).toMatchObject({ address: 'fe80::1', port: 8080 })
  })

  it('keeps a udp row, which never says LISTEN', () => {
    const { listeners } = parseListeners(['src:ss', 'udp UNCONN 0 0 0.0.0.0:53 0.0.0.0:*'])
    expect(listeners).toMatchObject([{ proto: 'udp', port: 53 }])
  })

  it('reports the socket even when the owner is not visible', () => {
    // An unprivileged probe sees the listener but not whose it is; that is
    // still worth showing.
    const { listeners } = parseListeners(['src:ss', 'tcp LISTEN 0 128 0.0.0.0:443 0.0.0.0:*'])
    expect(listeners[0]).toEqual({ proto: 'tcp', address: '*', port: 443 })
  })

  it('orders by port so the list is stable between polls', () => {
    const { listeners } = parseListeners([
      'src:ss',
      'tcp LISTEN 0 128 0.0.0.0:8080 0.0.0.0:*',
      'tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:*'
    ])
    expect(listeners.map((l) => l.port)).toEqual([22, 8080])
  })
})

describe('listeners from netstat', () => {
  it('reads the netstat column layout and its pid/program field', () => {
    const { listeners, source } = parseListeners([
      'src:netstat',
      'tcp 0 0 0.0.0.0:22 0.0.0.0:* LISTEN 812/sshd'
    ])
    expect(source).toBe('netstat')
    expect(listeners).toEqual([{ proto: 'tcp', address: '*', port: 22, process: 'sshd', pid: 812 }])
  })

  it('skips established connections, which are not listeners', () => {
    const { listeners } = parseListeners([
      'src:netstat',
      'tcp 0 0 10.0.0.1:22 10.0.0.9:51234 ESTABLISHED 812/sshd'
    ])
    expect(listeners).toEqual([])
  })

  it('collapses tcp and tcp6 rows of one dual-stack listener', () => {
    // netstat names the families `tcp` and `tcp6` where ss says `tcp` twice.
    // The rows are stored under the normalised proto, so keying the dedupe on
    // the raw one let both through and produced two identical rows: an
    // inflated port count, and a duplicate React key in a list that
    // re-renders every couple of seconds.
    const { listeners } = parseListeners([
      'src:netstat',
      'tcp 0 0 0.0.0.0:22 0.0.0.0:* LISTEN 812/sshd',
      'tcp6 0 0 :::22 :::* LISTEN 812/sshd'
    ])
    expect(listeners).toEqual([{ proto: 'tcp', address: '*', port: 22, process: 'sshd', pid: 812 }])
  })

  it('collapses a dual-stack udp listener the same way', () => {
    const { listeners } = parseListeners([
      'src:netstat',
      'udp 0 0 0.0.0.0:53 0.0.0.0:* 900/systemd-resolve',
      'udp6 0 0 :::53 :::* 900/systemd-resolve'
    ])
    expect(listeners).toMatchObject([{ proto: 'udp', address: '*', port: 53 }])
  })

  it('keeps two rows that differ by more than address family', () => {
    // The collapse is only ever between the two families of one listener. A
    // v6-only service on its own port is a separate thing and must survive.
    const { listeners } = parseListeners([
      'src:netstat',
      'tcp 0 0 0.0.0.0:22 0.0.0.0:* LISTEN 812/sshd',
      'tcp6 0 0 :::8080 :::* LISTEN 913/node'
    ])
    expect(listeners.map((l) => `${l.proto}:${l.port}`)).toEqual(['tcp:22', 'tcp:8080'])
  })

  it('produces a unique proto/address/port key for every row it returns', () => {
    // What the UI actually depends on: the port table keys its rows on exactly
    // these three fields.
    const { listeners } = parseListeners([
      'src:netstat',
      'tcp 0 0 0.0.0.0:22 0.0.0.0:* LISTEN 812/sshd',
      'tcp6 0 0 :::22 :::* LISTEN 812/sshd',
      'tcp 0 0 127.0.0.1:5432 0.0.0.0:* LISTEN 700/postgres',
      'udp 0 0 0.0.0.0:53 0.0.0.0:* 900/resolved',
      'udp6 0 0 :::53 :::* 900/resolved'
    ])
    const keys = listeners.map((l) => `${l.proto}-${l.address}-${l.port}`)
    expect(new Set(keys).size).toBe(keys.length)
    expect(keys).toHaveLength(3)
  })
})

describe('when neither probe exists', () => {
  it('reports no source rather than an empty result that looks like no listeners', () => {
    // "cannot see listeners" and "no listeners" are different answers, and the
    // UI has to be able to tell them apart.
    const { listeners, source } = parseListeners([])
    expect(source).toBeNull()
    expect(listeners).toEqual([])
  })
})

// Real /proc/net/dev lines from a host running k3s and Docker. Copied verbatim
// rather than composed, because the shape of this file — the leading spaces on
// short names, the sixteen columns, the veth names — is the whole difficulty.
const NET = [
  '    lo: 34828634   76373    0    0    0     0          0         0 34828634   76373    0    0    0    0       0          0',
  '  eth0: 4612042408 2345155    0    1    0     0          0         0 278195406 1813928    0    0    0    0       0          0',
  'docker0: 101948839  237472    0    0    0     0          0         0 53049184  269059    0    0    0    0       0          0',
  'veth6802495: 43974884   43395    0    0    0     0          0         0 10157324   53754    0    0    0    0       0          0',
  'flannel.1:       0       0    0    0    0     0          0         0        0       0    0    5    0    0       0          0',
  '  cni0: 10197601   34119    0    0    0     0          0       140  7083309   38317    0    0    0    0       0          0',
  'vethbf86cd0a: 9679005   23646    0    0    0     0          0         0  6082462   27670    0    0    0    0       0          0'
]

describe('network totals on a host with bridges', () => {
  it('counts only the physical interface when sysfs names one', () => {
    // The bug: a packet for a container is counted on eth0, again on the
    // bridge, and again on the veth. Measured at 5-9x the truth on a real
    // k3s host, on a number the fleet view shows as fact.
    const { netRx, netTx } = sumNetwork(NET, ['eth0'])
    expect(netRx).toBe(4612042408)
    expect(netTx).toBe(278195406)
  })

  it('falls back to every non-loopback interface when sysfs names none', () => {
    // A container has no physical interface — its veth IS the wire — and a
    // host whose sysfs we could not read should not silently report zero.
    const { netRx } = sumNetwork(NET, [])
    expect(netRx).toBe(4612042408 + 101948839 + 43974884 + 0 + 10197601 + 9679005)
  })

  it('never counts loopback', () => {
    // 34MB of loopback on this host, which is not network traffic by any
    // reading, and is exactly the kind of number that makes an idle host look
    // busy.
    // Loopback alone must total zero, in both modes.
    const lo = ['    lo: 34828634 1 0 0 0 0 0 0 34828634 1 0 0 0 0 0 0']
    expect(sumNetwork(lo, []).netRx).toBe(0)
    expect(sumNetwork(lo, ['eth0']).netRx).toBe(0)
  })

  it('reads transmitted bytes from the ninth column, not a receive one', () => {
    const { netTx } = sumNetwork(['  eth0: 100 1 0 0 0 0 0 0 999 2 0 0 0 0 0 0'], ['eth0'])
    expect(netTx).toBe(999)
  })
})
