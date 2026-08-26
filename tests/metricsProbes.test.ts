import { describe, it, expect } from 'vitest'
import { parseServices, parseListeners } from '../src/main/services/metrics'

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
