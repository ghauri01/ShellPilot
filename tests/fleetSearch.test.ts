import { describe, it, expect } from 'vitest'
import { searchFleet, coverageSentence, FLEET_SEARCH_CAP } from '../src/renderer/src/lib/fleetSearch'
import type { FleetSearchInput } from '../src/renderer/src/lib/fleetSearch'
import type { HostMetrics, ServiceUnit, PortListener } from '../src/shared/ssh'

// The monitor already collects every unit and every socket on every sweep and
// discards all but the two a card has room for. Searching it is cheap. Saying
// honestly what could NOT be searched is the part that makes it trustworthy:
// three results drawn from four hosts out of fifteen is a lie by omission
// unless the gap is on screen, and the gaps are all different — never sampled,
// no systemd, no port probe, or gone unreachable since.

const host = (over: Partial<HostMetrics> = {}): HostMetrics => ({
  cpu: 1, memPct: 1, memUsed: 1, memTotal: 2, diskPct: 1, diskUsed: 1, diskTotal: 2,
  netRx: 0, netTx: 0, uptime: 100, hostname: 'box', kernel: 'Linux 6.1', cores: 4,
  services: [], listeners: [], listenerSource: 'ss',
  ...over
})
const unit = (name: string, description = '', active = 'active', sub = 'running'): ServiceUnit =>
  ({ name, description, active, sub })
const port = (p: number, over: Partial<PortListener> = {}): PortListener =>
  ({ proto: 'tcp', address: '0.0.0.0', port: p, ...over })

const input = (over: Partial<FleetSearchInput> = {}): FleetSearchInput => ({
  servers: [{ id: 'a', name: 'web-01' }],
  hosts: { a: { host: host(), at: 1_000 } },
  errors: {},
  ...over
})

describe('finding things across the estate', () => {
  it('finds a unit by name', () => {
    const r = searchFleet(input({
      hosts: { a: { host: host({ services: [unit('nginx.service', 'web server')] }), at: 1_000 } }
    }), 'nginx')
    expect(r.matches).toHaveLength(1)
    expect(r.matches[0]).toMatchObject({ kind: 'unit', label: 'nginx.service', serverName: 'web-01' })
  })

  it('finds a unit by its description, not only its name', () => {
    const r = searchFleet(input({
      hosts: { a: { host: host({ services: [unit('pg.service', 'PostgreSQL database')] }), at: 1 } }
    }), 'postgres')
    expect(r.matches.map((m) => m.label)).toEqual(['pg.service'])
  })

  it('matches a bare number as an exact port, not a substring', () => {
    // "80" must not return 8080, 8081 and 3080. This is the query people
    // actually type and the one a substring match gets most wrong.
    const r = searchFleet(input({
      hosts: { a: { host: host({ listeners: [port(80), port(8080), port(3080)] }), at: 1 } }
    }), '80')
    expect(r.matches.map((m) => m.label)).toEqual(['tcp/80'])
  })

  it('finds a port by owning process', () => {
    const r = searchFleet(input({
      hosts: { a: { host: host({ listeners: [port(6379, { process: 'redis-server', pid: 9 })] }), at: 1 } }
    }), 'redis')
    expect(r.matches[0]).toMatchObject({ kind: 'port', label: 'tcp/6379', detail: 'redis-server (pid 9)' })
  })

  it('says the owner is invisible rather than leaving it blank', () => {
    // A blank reads as "nothing owns this socket", which is a different and
    // wrong answer from "the probe could not see who does".
    const r = searchFleet(input({
      hosts: { a: { host: host({ listeners: [port(443)] }), at: 1 } }
    }), '443')
    expect(r.matches[0].detail).toMatch(/not visible at this privilege/)
  })

  it('finds the host itself by hostname or kernel', () => {
    const r = searchFleet(input({
      hosts: { a: { host: host({ hostname: 'inter-scanner-01' }), at: 1 } }
    }), 'scanner')
    expect(r.matches[0]).toMatchObject({ kind: 'host', label: 'web-01' })
  })

  it('returns nothing for an empty query rather than everything', () => {
    const r = searchFleet(input({
      hosts: { a: { host: host({ services: [unit('a.service')] }), at: 1 } }
    }), '   ')
    expect(r.matches).toEqual([])
  })

  it('carries the sample age on every match', () => {
    const r = searchFleet(input({
      hosts: { a: { host: host({ services: [unit('x.service')] }), at: 4_242 } }
    }), 'x.service')
    expect(r.matches[0].at).toBe(4_242)
  })
})

describe('what the search admits it could not see', () => {
  it('names hosts that have never been sampled', () => {
    const r = searchFleet(input({
      servers: [{ id: 'a', name: 'web-01' }, { id: 'b', name: 'db-01' }],
      hosts: { a: { host: host(), at: 1 } }
    }), 'anything')
    expect(r.coverage.notChecked).toEqual(['db-01'])
    expect(r.coverage.searched).toEqual(['web-01'])
  })

  it('separates "no systemd here" from "no unit matched"', () => {
    // The null-vs-empty distinction the sampler is careful about, carried into
    // search. Collapsing them tells someone a unit is absent when nobody looked.
    const r = searchFleet(input({
      hosts: { a: { host: host({ services: null }), at: 1 } }
    }), 'nginx')
    expect(r.coverage.noServiceView).toEqual(['web-01'])
    const empty = searchFleet(input({ hosts: { a: { host: host({ services: [] }), at: 1 } } }), 'nginx')
    expect(empty.coverage.noServiceView).toEqual([])
  })

  it('separates "no port probe" from "no port matched"', () => {
    const r = searchFleet(input({
      hosts: { a: { host: host({ listeners: null }), at: 1 } }
    }), '443')
    expect(r.coverage.noPortView).toEqual(['web-01'])
  })

  it('keeps rows from a host that has since gone unreachable, and marks them', () => {
    // Dropping them would answer "postgres is nowhere" when the truth is
    // "postgres was on that box and the box stopped answering".
    const r = searchFleet(input({
      hosts: { a: { host: host({ services: [unit('pg.service')] }), at: 1_000 } },
      errors: { a: { error: 'timed out', at: 2_000 } }
    }), 'pg')
    expect(r.matches[0].stale).toBe(true)
    expect(r.coverage.unreachable).toEqual(['web-01'])
  })

  it('does not mark rows stale when the error predates the sample', () => {
    // It failed, then answered. That is a recovered host, not a stale row.
    const r = searchFleet(input({
      hosts: { a: { host: host({ services: [unit('pg.service')] }), at: 2_000 } },
      errors: { a: { error: 'blip', at: 1_000 } }
    }), 'pg')
    expect(r.matches[0].stale).toBeUndefined()
    expect(r.coverage.unreachable).toEqual([])
  })

  it('is silent only when every host was searched with both probes working', () => {
    const clean = searchFleet(input(), 'web')
    expect(coverageSentence(clean.coverage)).toBeNull()
  })

  it('says so in one sentence when anything was missed', () => {
    const r = searchFleet(input({
      servers: [{ id: 'a', name: 'web-01' }, { id: 'b', name: 'db-01' }],
      hosts: { a: { host: host({ services: null }), at: 1 } }
    }), 'x')
    const sentence = coverageSentence(r.coverage)
    expect(sentence).toMatch(/db-01 have not been checked/)
    expect(sentence).toMatch(/no systemd on web-01/)
  })
})

describe('result volume', () => {
  it('caps the list and reports how many it dropped', () => {
    const many = Array.from({ length: FLEET_SEARCH_CAP + 25 }, (_, i) => unit(`svc-${i}.service`))
    const r = searchFleet(input({ hosts: { a: { host: host({ services: many }), at: 1 } } }), 'svc-')
    expect(r.matches).toHaveLength(FLEET_SEARCH_CAP)
    // Silently cutting would let someone conclude a port is unused anywhere
    // when it was simply past the end of the list.
    expect(r.truncated).toBe(25)
  })

  it('ranks an exact label match above a substring one', () => {
    const r = searchFleet(input({
      hosts: { a: { host: host({ services: [unit('my-nginx-helper.service'), unit('nginx')] }), at: 1 } }
    }), 'nginx')
    expect(r.matches[0].label).toBe('nginx')
  })
})
