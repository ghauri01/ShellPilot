import { describe, it, expect } from 'vitest'
import {
  DISK_DANGER,
  coverageLine,
  diskLine,
  failureLine,
  isLoopback,
  level,
  splitListeners,
  summariseFleetHealth,
  unreachableLine
} from '../src/renderer/src/components/monitor/hostHealth'
import type { ServerRef } from '../src/renderer/src/components/monitor/hostHealth'
import type { HostMetrics, PortListener, ServiceUnit } from '../src/shared/ssh'

function server(id: string, name = id): ServerRef {
  return { id, name, status: 'online' }
}

function unit(name: string, over: Partial<ServiceUnit> = {}): ServiceUnit {
  return { name, active: 'active', sub: 'running', description: '', ...over }
}

const failedUnit = (name: string): ServiceUnit =>
  unit(name, { active: 'failed', sub: 'failed', description: 'broke' })

function host(over: Partial<HostMetrics> = {}): HostMetrics {
  return {
    cpu: 5,
    memPct: 40,
    memUsed: 4_000_000_000,
    memTotal: 10_000_000_000,
    diskPct: 20,
    diskUsed: 20_000_000_000,
    diskTotal: 100_000_000_000,
    netRx: 0,
    netTx: 0,
    uptime: 1000,
    hostname: 'h',
    kernel: '6.1',
    cores: 4,
    services: [],
    listeners: [],
    listenerSource: 'ss',
    ...over
  }
}

function listener(port: number, address: string, over: Partial<PortListener> = {}): PortListener {
  return { proto: 'tcp', address, port, ...over }
}

describe('level', () => {
  it('matches the disk threshold the attention list uses', () => {
    expect(level(DISK_DANGER)).toBe('warn')
    expect(level(DISK_DANGER + 0.1)).toBe('danger')
  })

  it('grades the middle band as a warning', () => {
    expect(level(0)).toBe('ok')
    expect(level(65)).toBe('ok')
    expect(level(65.1)).toBe('warn')
  })
})

describe('summariseFleetHealth', () => {
  it('separates servers needing attention from the rest', () => {
    const h = summariseFleetHealth([server('a'), server('b')], {
      a: host({ services: [failedUnit('nginx')] }),
      b: host()
    })
    expect(h.attention.map((r) => r.id)).toEqual(['a'])
    expect(h.rest.map((r) => r.id)).toEqual(['b'])
    expect(h.failedUnits).toBe(1)
    expect(h.failingHosts).toBe(1)
  })

  it('treats a unit failed on either field as failed', () => {
    const h = summariseFleetHealth([server('a')], {
      a: host({
        services: [unit('x', { active: 'failed' }), unit('y', { sub: 'failed' }), unit('z')]
      })
    })
    expect(h.attention[0].failed?.map((u) => u.name)).toEqual(['x', 'y'])
  })

  it('never reads a server without systemd as a server with nothing failed', () => {
    const h = summariseFleetHealth([server('a')], { a: host({ services: null }) })
    expect(h.attention).toHaveLength(0)
    expect(h.rest[0].failed).toBeNull()
    expect(h.rest[0].running).toBeNull()
    expect(h.blind).toBe(1)
  })

  it('reads an empty unit list as a real answer, not a missing one', () => {
    const h = summariseFleetHealth([server('a')], { a: host({ services: [] }) })
    expect(h.rest[0].failed).toEqual([])
    expect(h.rest[0].running).toBe(0)
    expect(h.blind).toBe(0)
  })

  it('keeps the null listener case distinct from an empty one', () => {
    const h = summariseFleetHealth([server('a'), server('b')], {
      a: host({ listeners: null, listenerSource: null }),
      b: host({ listeners: [] })
    })
    expect(h.rest[0].listeners).toBeNull()
    expect(h.rest[1].listeners).toEqual([])
  })

  it('still lists a server whose service and port probes both failed', () => {
    // It reported CPU, memory and disk perfectly well; dropping it entirely
    // would understate how much of the estate is covered.
    const h = summariseFleetHealth([server('a')], {
      a: host({ services: null, listeners: null, listenerSource: null })
    })
    expect(h.rest.map((r) => r.id)).toEqual(['a'])
  })

  it('flags a disk past the danger mark and not one at it', () => {
    const h = summariseFleetHealth([server('a'), server('b')], {
      a: host({ diskPct: DISK_DANGER + 1 }),
      b: host({ diskPct: DISK_DANGER })
    })
    expect(h.attention.map((r) => r.id)).toEqual(['a'])
    expect(h.diskHosts).toBe(1)
  })

  it('does not alarm on a server that reported no filesystem at all', () => {
    const h = summariseFleetHealth([server('a')], {
      a: host({ diskPct: 100, diskTotal: 0, diskUsed: 0 })
    })
    expect(h.attention).toHaveLength(0)
  })

  it('leaves CPU and memory pressure out of the attention list', () => {
    // Both recover on their own; a list that fills with things that fix
    // themselves stops being read.
    const h = summariseFleetHealth([server('a')], { a: host({ cpu: 99, memPct: 99 }) })
    expect(h.attention).toHaveLength(0)
  })

  it('counts servers that have not reported instead of hiding them', () => {
    const h = summariseFleetHealth([server('a'), server('b'), server('c')], { a: host() })
    expect(h.silent).toBe(2)
    expect(h.totalServers).toBe(3)
  })

  it('puts failed units ahead of disk pressure', () => {
    const h = summariseFleetHealth([server('a', 'aaa'), server('b', 'bbb')], {
      a: host({ diskPct: 99 }),
      b: host({ services: [failedUnit('nginx')] })
    })
    expect(h.attention.map((r) => r.name)).toEqual(['bbb', 'aaa'])
  })

  it('does not reorder attention rows when a failure count changes', () => {
    const two = summariseFleetHealth([server('a', 'aaa'), server('b', 'bbb')], {
      a: host({ services: [failedUnit('one')] }),
      b: host({ services: [failedUnit('two'), failedUnit('three')] })
    })
    const one = summariseFleetHealth([server('a', 'aaa'), server('b', 'bbb')], {
      a: host({ services: [failedUnit('one')] }),
      b: host({ services: [failedUnit('two')] })
    })
    expect(two.attention.map((r) => r.name)).toEqual(['aaa', 'bbb'])
    expect(one.attention.map((r) => r.name)).toEqual(['aaa', 'bbb'])
  })

  it('leaves the healthy servers in the order they were given', () => {
    const h = summariseFleetHealth([server('c', 'ccc'), server('a', 'aaa'), server('b', 'bbb')], {
      a: host(),
      b: host(),
      c: host()
    })
    expect(h.rest.map((r) => r.name)).toEqual(['ccc', 'aaa', 'bbb'])
  })
})

describe('servers that could not be checked', () => {
  const failure = (error: string, at = 1_000): { error: string; at: number } => ({ error, at })

  it('lists an unreachable server instead of counting it as silent', () => {
    // Silent means "we have never heard anything". A refused connection is
    // something heard, and it is the answer the user needs to see.
    const h = summariseFleetHealth([server('a')], {}, { a: failure('Connection refused') })
    expect(h.silent).toBe(0)
    expect(h.unreachable.map((r) => r.id)).toEqual(['a'])
    expect(h.unreachable[0].error).toBe('Connection refused')
    expect(h.unreachable[0].at).toBe(1_000)
  })

  it('carries the last good sample alongside the failure', () => {
    const h = summariseFleetHealth(
      [server('a')],
      { a: host({ services: [unit('nginx')], listeners: [listener(443, '*')] }) },
      { a: failure('Timed out') }
    )
    expect(h.unreachable[0].last?.running).toBe(1)
    expect(h.unreachable[0].last?.listeners).toEqual([listener(443, '*')])
  })

  it('has no last sample for a server that has never answered', () => {
    const h = summariseFleetHealth([server('a')], {}, { a: failure('No route to server') })
    expect(h.unreachable[0].last).toBeNull()
  })

  it('keeps a stale sample out of the healthy list', () => {
    // The numbers are from before the host went quiet. Showing them as its
    // current state is the exact confusion the error was recorded to prevent.
    const h = summariseFleetHealth([server('a'), server('b')], { a: host(), b: host() }, {
      a: failure('Connection refused')
    })
    expect(h.rest.map((r) => r.id)).toEqual(['b'])
    expect(h.attention).toEqual([])
  })

  it('does not raise an alarm from a stale failure on an unreachable server', () => {
    // The unit may well have been restarted in the meantime; we cannot say.
    const h = summariseFleetHealth(
      [server('a')],
      { a: host({ services: [failedUnit('nginx')], diskPct: 99 }) },
      { a: failure('Connection refused') }
    )
    expect(h.attention).toEqual([])
    expect(h.failedUnits).toBe(0)
    expect(h.diskHosts).toBe(0)
    expect(failureLine(h)).toBeNull()
    expect(diskLine(h)).toBeNull()
  })

  it('leaves an unreachable server out of the reporting count', () => {
    const h = summariseFleetHealth([server('a'), server('b')], { b: host() }, {
      a: failure('Connection refused')
    })
    expect(coverageLine(h)).toBe('1 of 2 servers reporting')
  })

  it('says how many servers could not be checked, in the right number', () => {
    const one = summariseFleetHealth([server('a')], {}, { a: failure('x') })
    const two = summariseFleetHealth([server('a'), server('b')], {}, {
      a: failure('x'),
      b: failure('y')
    })
    expect(unreachableLine(one)).toBe('1 server could not be checked')
    expect(unreachableLine(two)).toBe('2 servers could not be checked')
  })

  it('says nothing when every server answered', () => {
    expect(unreachableLine(summariseFleetHealth([server('a')], { a: host() }))).toBeNull()
  })

  it('treats no error map at all as no errors', () => {
    const h = summariseFleetHealth([server('a')], { a: host() })
    expect(h.unreachable).toEqual([])
  })
})

describe('splitListeners', () => {
  it('separates loopback from anything reachable off the box', () => {
    const groups = splitListeners([
      listener(5432, '127.0.0.1'),
      listener(443, '*'),
      listener(6379, '::1'),
      listener(22, '10.0.0.4')
    ])
    expect(groups.exposed.map((l) => l.port)).toEqual([22, 443])
    expect(groups.loopback.map((l) => l.port)).toEqual([5432, 6379])
  })

  it('sorts each group by port rather than trusting the probe order', () => {
    const groups = splitListeners([listener(8080, '*'), listener(80, '*'), listener(443, '*')])
    expect(groups.exposed.map((l) => l.port)).toEqual([80, 443, 8080])
  })

  it('orders same-port rows by protocol so the list is stable', () => {
    const groups = splitListeners([
      listener(53, '*', { proto: 'udp' }),
      listener(53, '*', { proto: 'tcp' })
    ])
    expect(groups.exposed.map((l) => l.proto)).toEqual(['tcp', 'udp'])
  })

  it('treats a wildcard bind as exposed, because it is', () => {
    expect(isLoopback('*')).toBe(false)
    expect(isLoopback('127.0.0.1')).toBe(true)
    expect(isLoopback('127.53.0.1')).toBe(true)
    expect(isLoopback('::1')).toBe(true)
    expect(isLoopback('10.0.0.1')).toBe(false)
    // Not loopback: an address that merely starts with the same digits.
    expect(isLoopback('1270.0.0.1')).toBe(false)
  })
})

describe('summary copy', () => {
  const withFailures = (units: number, hostsFailing: number): ReturnType<typeof summariseFleetHealth> =>
    summariseFleetHealth(
      Array.from({ length: hostsFailing }, (_, i) => server(`s${i}`)),
      Object.fromEntries(
        Array.from({ length: hostsFailing }, (_, i) => [
          `s${i}`,
          host({
            services: Array.from({ length: Math.ceil(units / hostsFailing) }, (_, j) =>
              failedUnit(`u${i}${j}`)
            )
          })
        ])
      )
    )

  it('says nothing when nothing has failed', () => {
    expect(failureLine(summariseFleetHealth([server('a')], { a: host() }))).toBeNull()
    expect(diskLine(summariseFleetHealth([server('a')], { a: host() }))).toBeNull()
  })

  it('agrees with itself about singular and plural', () => {
    expect(failureLine(withFailures(1, 1))).toBe('1 failed service on 1 server')
    expect(failureLine(withFailures(4, 2))).toBe('4 failed services on 2 servers')
  })

  it('names how much of the estate the panel actually covers', () => {
    const partial = summariseFleetHealth([server('a'), server('b'), server('c')], {
      a: host(),
      b: host({ services: null })
    })
    expect(coverageLine(partial)).toBe('2 of 3 servers reporting · 1 cannot list services')
  })

  it('says when a server could not list its ports, which is not "no ports"', () => {
    const h = summariseFleetHealth([server('a'), server('b')], {
      a: host({ listeners: null, listenerSource: null }),
      b: host({ listeners: [] })
    })
    expect(h.portBlind).toBe(1)
    expect(coverageLine(h)).toBe('2 servers reporting · 1 cannot list ports')
  })

  it('names both blind spots separately, because either can happen alone', () => {
    const h = summariseFleetHealth([server('a')], {
      a: host({ services: null, listeners: null, listenerSource: null })
    })
    expect(coverageLine(h)).toBe(
      '1 server reporting · 1 cannot list services · 1 cannot list ports'
    )
  })

  it('counts an empty port list as a real answer, not a blind spot', () => {
    const h = summariseFleetHealth([server('a')], { a: host({ listeners: [] }) })
    expect(h.portBlind).toBe(0)
    expect(coverageLine(h)).toBe('1 server reporting')
  })

  it('keeps "of N" singular when the estate is one server', () => {
    const none = summariseFleetHealth([server('a')], {})
    expect(coverageLine(none)).toBe('0 of 1 server reporting')
  })

  it('drops the "of N" when every server is reporting', () => {
    const all = summariseFleetHealth([server('a'), server('b')], { a: host(), b: host() })
    expect(coverageLine(all)).toBe('2 servers reporting')
  })

  it('reports a single reporting server in the singular', () => {
    expect(coverageLine(summariseFleetHealth([server('a')], { a: host() }))).toBe(
      '1 server reporting'
    )
  })

  it('counts servers low on disk', () => {
    const h = summariseFleetHealth([server('a'), server('b')], {
      a: host({ diskPct: 99 }),
      b: host({ diskPct: 92 })
    })
    expect(diskLine(h)).toBe('2 servers low on disk')
  })
})
