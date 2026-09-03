import { describe, it, expect } from 'vitest'
import { searchFleet, coverageSentence, matchKey, FLEET_SEARCH_CAP } from '../src/renderer/src/lib/fleetSearch'
import type { FleetSearchInput } from '../src/renderer/src/lib/fleetSearch'
import { FACT_SOURCE_IDS, FACT_SOURCE_LABEL } from '../src/shared/hostFacts'
import type { FactSourceId, FactSourceReport, FactStatus, HostFacts } from '../src/shared/hostFacts'
import type { HostMetrics, ServiceUnit, PortListener } from '../src/shared/ssh'

// The monitor already collects every unit and every socket on every sweep and
// discards all but the two a card has room for. Searching it is cheap. Saying
// honestly what could NOT be searched is the part that makes it trustworthy:
// three results drawn from four hosts out of fifteen is a lie by omission
// unless the gap is on screen, and the gaps are all different — never sampled,
// no systemd, no port probe, gone unreachable since, no host facts yet, no
// package manager, or a distribution that can never answer the question asked.

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

/** Every source `ok` unless named otherwise. A test that cares about one
 *  status should not have to spell out the other eight. */
const sources = (over: Partial<Record<FactSourceId, FactStatus>> = {}): FactSourceReport[] =>
  FACT_SOURCE_IDS.map((id) => ({ id, label: FACT_SOURCE_LABEL[id], status: over[id] ?? 'ok' }))

/** A plain apt host: everything known, nothing unsupported. */
const facts = (over: Partial<HostFacts> = {}): HostFacts => ({
  distroId: 'ubuntu',
  distroVersion: '24.04',
  prettyName: 'Ubuntu 24.04.1 LTS',
  arch: 'x86_64',
  cpuModel: 'AMD EPYC 7543 32-Core Processor',
  packageManager: 'apt',
  pendingUpdates: 3,
  securityUpdates: 1,
  rebootRequired: false,
  rebootReason: null,
  virtualisation: 'kvm',
  metadataAt: 900,
  collectedAt: 1_000,
  sources: sources(),
  ...over
})

/** An Arch box: pending updates are countable, security updates never are. */
const archFacts = (): HostFacts =>
  facts({
    distroId: 'arch',
    distroVersion: null,
    prettyName: 'Arch Linux',
    packageManager: 'pacman',
    securityUpdates: null,
    virtualisation: 'none',
    sources: sources({ 'security-updates': 'unsupported' })
  })

const input = (over: Partial<FleetSearchInput> = {}): FleetSearchInput => ({
  servers: [{ id: 'a', name: 'web-01' }],
  hosts: { a: { host: host(), at: 1_000 } },
  errors: {},
  // Facts are REQUIRED on the input, and the default here is a host whose facts
  // were collected and could answer everything — so a test that says nothing
  // about facts is testing a clean estate rather than accidentally testing the
  // gap. Tests about the gaps pass their own.
  facts: { a: { facts: facts(), at: 1_000 } },
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

  it('marks rows stale when the error and the sample share a timestamp', () => {
    // A success DELETES the stored error (store/fleet.ts `report`), so an error
    // being present at all means it was recorded after the last good sample.
    // When the two tie — same sweep, or two events inside one millisecond — the
    // error is still the later of the two, and `>` would quietly un-mark a host
    // that is currently failing.
    const r = searchFleet(input({
      hosts: { a: { host: host({ services: [unit('pg.service')] }), at: 2_000 } },
      errors: { a: { error: 'timed out', at: 2_000 } }
    }), 'pg')
    expect(r.matches[0].stale).toBe(true)
    expect(r.coverage.unreachable).toEqual(['web-01'])
  })

  it('does not count a host with neither probe as searched', () => {
    // Nothing on it was searchable but its own name. Counting it put a
    // reassuring number on screen — "Searched 1 host" — that the results behind
    // it did not support, and named the host twice under two separate gaps
    // rather than once under the gap that actually applied.
    const r = searchFleet(input({
      hosts: { a: { host: host({ services: null, listeners: null }), at: 1 } }
    }), 'nginx')
    expect(r.coverage.searched).toEqual([])
    expect(r.coverage.noProbes).toEqual(['web-01'])
    expect(r.coverage.noServiceView).toEqual([])
    expect(r.coverage.noPortView).toEqual([])
    const sentence = coverageSentence(r.coverage)
    expect(sentence).toBe(
      'Units and ports searched on 0 hosts, host facts on 1 — neither systemd nor a port probe on web-01.'
    )
  })

  it('still counts a host with one probe missing as searched', () => {
    const r = searchFleet(input({
      hosts: { a: { host: host({ services: null }), at: 1 } }
    }), 'nginx')
    expect(r.coverage.searched).toEqual(['web-01'])
    expect(r.coverage.noProbes).toEqual([])
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

describe('finding a host by what it IS', () => {
  // Host facts, roadmap item C. "Which boxes are Rocky", "which are on KVM" and
  // "which use apt" were all unanswerable without visiting every host, and the
  // answers have been in memory since the sampler's first sweep.

  const matched = (query: string, over: Partial<HostFacts> = {}): string[] =>
    searchFleet(input({ facts: { a: { facts: facts(over), at: 1 } } }), query).matches.map(
      (m) => m.label
    )

  it('finds a host by its distribution id', () => {
    expect(matched('ubuntu')).toEqual(['web-01'])
  })

  it('finds a host by its package manager', () => {
    expect(matched('apt')).toEqual(['web-01'])
  })

  it('finds a host by its virtualisation type', () => {
    expect(matched('kvm')).toEqual(['web-01'])
  })

  it('finds a rocky host by its distribution id', () => {
    expect(
      matched('rocky', { distroId: 'rocky', prettyName: 'Rocky Linux 9.4 (Blue Onyx)' })
    ).toEqual(['web-01'])
  })

  it('finds a host by version, architecture and CPU model too', () => {
    expect(matched('24.04')).toEqual(['web-01'])
    expect(matched('x86_64')).toEqual(['web-01'])
    expect(matched('epyc')).toEqual(['web-01'])
  })

  it('does not invent a match for a host whose facts were never collected', () => {
    // The gap is reported, not papered over. A host with no facts is not an
    // Ubuntu host that failed to say so.
    const r = searchFleet(input({ facts: {} }), 'ubuntu')
    expect(r.matches).toEqual([])
    expect(r.coverage.noFacts).toEqual(['web-01'])
  })

  it('ranks an exact distro id above a host that merely contains it', () => {
    // The same defect the hostname ranking fixed: a host found by a field the
    // label does not contain used to score worst-possible and sort last.
    const r = searchFleet(
      input({
        servers: [{ id: 'a', name: 'web-01' }, { id: 'b', name: 'arch-mirror-01' }],
        hosts: { a: { host: host(), at: 1 }, b: { host: host(), at: 1 } },
        facts: { a: { facts: archFacts(), at: 1 }, b: { facts: facts(), at: 1 } }
      }),
      'arch'
    )
    expect(r.matches.map((m) => m.serverName)).toEqual(['web-01', 'arch-mirror-01'])
  })

  it('puts the distribution on the row, so a host found by "kvm" says why', () => {
    const r = searchFleet(input(), 'kvm')
    expect(r.matches[0].detail).toContain('Ubuntu 24.04.1 LTS')
    expect(r.matches[0].detail).toContain('kvm')
    expect(r.matches[0].detail).toContain('apt')
  })
})

describe('what the search admits it cannot ever know', () => {
  // The facts buckets. They are a second axis, not a share of the first: the
  // metrics sweep runs every couple of minutes and the facts probe hourly, so a
  // host sampled forty times can still have no facts, and folding the two
  // together would report an estate as unchecked while it is being checked
  // constantly.

  it('names hosts whose facts have never been collected', () => {
    const r = searchFleet(
      input({
        servers: [{ id: 'a', name: 'web-01' }, { id: 'b', name: 'db-01' }],
        hosts: { a: { host: host(), at: 1 }, b: { host: host(), at: 1 } },
        facts: { a: { facts: facts(), at: 1 } }
      }),
      'x'
    )
    expect(r.coverage.noFacts).toEqual(['db-01'])
    expect(r.coverage.factsSearched).toEqual(['web-01'])
  })

  it('does not name a never-sampled host twice', () => {
    // The sampler only probes facts after a successful metrics sample, so a
    // host nothing has ever sampled has never had facts collected either.
    // Reporting it under both gaps says less than reporting it under the one
    // that explains both.
    const r = searchFleet(
      input({ servers: [{ id: 'z', name: 'new-01' }], hosts: {}, facts: {} }),
      'x'
    )
    expect(r.coverage.notChecked).toEqual(['new-01'])
    expect(r.coverage.noFacts).toEqual([])
  })

  it('keeps the facts gap for a host with facts but no metrics sample yet', () => {
    // The comment on the never-sampled branch used to justify itself with "the
    // sampler only probes facts after a successful metrics sample". True of
    // main. NOT true of the store this function reads: FleetWatcher seeds facts
    // on mount and "Check now" fetches them directly, while metrics arrive only
    // from the live subscription with no seed at all. For the first sweep
    // interval after launch `facts[id]` exists and `hosts[id]` does not — and
    // this Arch box's "can never report security updates" was silently dropped
    // from the coverage sentence for exactly that window.
    const r = searchFleet(
      input({
        servers: [{ id: 'a', name: 'arch-01' }],
        hosts: {},
        facts: { a: { facts: archFacts(), at: 1 } }
      }),
      'x'
    )
    // The metrics gap is still reported: nothing has sampled its units or ports.
    expect(r.coverage.notChecked).toEqual(['arch-01'])
    // And so is the facts one, which is what we actually know about it.
    expect(r.coverage.factsSearched).toEqual(['arch-01'])
    expect(r.coverage.securityUnsupported).toEqual(['arch-01'])
    expect(coverageSentence(r.coverage)).toContain('can never report security updates')
  })

  it('treats factsSearched as the denominator, not as a fourth disjoint bucket', () => {
    // Pinned because the header comment used to claim the four facts fields
    // were "mutually disjoint ... a host reaches exactly one of them", and a
    // future edit trusting that would double-count. Only the three GAP buckets
    // are disjoint; `factsSearched` counts every host that has facts at all and
    // therefore overlaps both of the "facts collected, but..." buckets.
    const r = searchFleet(
      input({
        servers: [{ id: 'a', name: 'web-01' }, { id: 'b', name: 'arch-01' }],
        hosts: { a: { host: host(), at: 1 }, b: { host: host(), at: 1 } },
        facts: {
          a: {
            facts: facts({
              packageManager: null,
              pendingUpdates: null,
              securityUpdates: null,
              sources: sources({
                'package-manager': 'no-tool',
                updates: 'no-tool',
                'security-updates': 'no-tool'
              })
            }),
            at: 1
          },
          b: { facts: archFacts(), at: 1 }
        }
      }),
      'x'
    )
    expect(r.coverage.factsSearched).toEqual(['web-01', 'arch-01'])
    expect(r.coverage.noPackageManager).toEqual(['web-01'])
    expect(r.coverage.securityUnsupported).toEqual(['arch-01'])
    expect(r.coverage.noFacts).toEqual([])
    // The three gaps, pairwise disjoint — the property the comment should have
    // claimed, and the only one a future edit may rely on.
    const gaps = [
      r.coverage.noFacts,
      r.coverage.noPackageManager,
      r.coverage.securityUnsupported
    ].flat()
    expect(new Set(gaps).size).toBe(gaps.length)
  })

  it('names hosts with no package manager, and does not also call them unsupported', () => {
    // The two buckets are disjoint. A host with no package manager cannot
    // report a security count either, but the reason is "there is nothing to
    // ask", not "the distribution does not publish it" — and an operator does
    // something different about each.
    const r = searchFleet(
      input({
        facts: {
          a: {
            facts: facts({
              packageManager: null,
              pendingUpdates: null,
              securityUpdates: null,
              sources: sources({
                'package-manager': 'no-tool',
                updates: 'no-tool',
                'security-updates': 'no-tool'
              })
            }),
            at: 1
          }
        }
      }),
      'x'
    )
    expect(r.coverage.noPackageManager).toEqual(['web-01'])
    expect(r.coverage.securityUnsupported).toEqual([])
  })

  it('names hosts that can NEVER report a security count', () => {
    const r = searchFleet(input({ facts: { a: { facts: archFacts(), at: 1 } } }), 'x')
    expect(r.coverage.securityUnsupported).toEqual(['web-01'])
    expect(r.coverage.noPackageManager).toEqual([])
    // It was still searched. `unsupported` is about one question, not the host.
    expect(r.coverage.factsSearched).toEqual(['web-01'])
  })

  it('tells someone searching "security" that five hosts can never answer', () => {
    // The headline case for the whole bucket. Three hits and no sentence reads
    // as "the estate has three security-related things"; five Arch and Alpine
    // boxes are permanently outside that number and nothing else on screen
    // would say so.
    const servers = [
      { id: 'a', name: 'web-01' },
      ...Array.from({ length: 5 }, (_, i) => ({ id: `arch-${i}`, name: `arch-0${i}` }))
    ]
    const hosts = Object.fromEntries(
      servers.map((s) => [
        s.id,
        {
          host: host({
            services: s.id === 'a' ? [unit('security-scan.service', 'nightly security scan')] : []
          }),
          at: 1
        }
      ])
    )
    const factsByServer = Object.fromEntries(
      servers.map((s) => [s.id, { facts: s.id === 'a' ? facts() : archFacts(), at: 1 }])
    )
    const r = searchFleet(input({ servers, hosts, facts: factsByServer }), 'security')
    expect(r.matches).toHaveLength(1)
    expect(r.coverage.securityUnsupported).toHaveLength(5)
    const sentence = coverageSentence(r.coverage)
    expect(sentence).toContain('can never report security updates')
    // Names, not a count. "5 hosts could not answer" prompts the question this
    // sentence exists to answer.
    expect(sentence).toContain('arch-00, arch-01, arch-02 and 2 more')
  })

  it('counts facts separately from units and ports in the sentence', () => {
    const r = searchFleet(
      input({
        servers: [{ id: 'a', name: 'web-01' }, { id: 'b', name: 'db-01' }],
        hosts: { a: { host: host(), at: 1 }, b: { host: host(), at: 1 } },
        facts: { a: { facts: facts(), at: 1 } }
      }),
      'x'
    )
    const sentence = coverageSentence(r.coverage)
    // Two hosts searched for units and ports, one for facts. One number
    // covering both would be true of neither.
    expect(sentence).toContain('Units and ports searched on 2 hosts, host facts on 1')
    expect(sentence).toContain('no host facts collected yet for db-01')
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

describe('ranking what actually matched', () => {
  // A match whose label the query never appears in used to score worst-possible
  // and sort below every incidental substring hit — which is every host found by
  // its hostname, every unit found by its description and every port found by
  // its owning process. The label is what is DISPLAYED; it is not necessarily
  // what was searched.

  it('ranks a host found by an exact hostname above a unit that merely contains the query', () => {
    const r = searchFleet(input({
      hosts: {
        a: {
          host: host({ hostname: 'db-primary', services: [unit('my-db-primary-helper.service')] }),
          at: 1
        }
      }
    }), 'db-primary')
    expect(r.matches.map((m) => m.kind)).toEqual(['host', 'unit'])
  })

  it('ranks a unit whose description is the query above one that merely contains it', () => {
    const r = searchFleet(input({
      hosts: {
        a: {
          host: host({
            services: [unit('a-postgres-thing.service', 'nothing'), unit('pg.service', 'postgres')]
          }),
          at: 1
        }
      }
    }), 'postgres')
    expect(r.matches[0].label).toBe('pg.service')
  })

  it('ranks a port whose process is the query above one that merely contains it', () => {
    const r = searchFleet(input({
      hosts: {
        a: {
          host: host({
            listeners: [port(6379, { process: 'redis' }), port(1, { process: 'x-redis-y' })]
          }),
          at: 1
        }
      }
    }), 'redis')
    expect(r.matches[0].label).toBe('tcp/6379')
  })
})

describe('what counts as a port', () => {
  it('does not treat five digits above 65535 as a port', () => {
    // 99999 is not a port. Treating it as one compared it against every
    // listener's port number, matched nothing, and reported "no results" for a
    // query that plainly appears in the data.
    const r = searchFleet(input({
      hosts: { a: { host: host({ listeners: [port(8080, { process: 'app-99999' })] }), at: 1 } }
    }), '99999')
    expect(r.matches.map((m) => m.label)).toEqual(['tcp/8080'])
  })

  it('does not treat 0 as a port', () => {
    // Nothing listens on port 0 — the kernel prints it for "any" — so an exact
    // match on it can only ever return nothing. As a substring it finds every
    // socket bound to 0.0.0.0, which is what someone typing it can plausibly
    // have meant.
    const r = searchFleet(input({
      hosts: { a: { host: host({ listeners: [port(8080)] }), at: 1 } }
    }), '0')
    expect(r.matches.filter((m) => m.kind === 'port').map((m) => m.label)).toEqual(['tcp/8080'])
  })

  it('still matches a real port exactly', () => {
    const r = searchFleet(input({
      hosts: { a: { host: host({ listeners: [port(65535), port(6553)] }), at: 1 } }
    }), '65535')
    expect(r.matches.map((m) => m.label)).toEqual(['tcp/65535'])
  })
})

describe('one row, one key', () => {
  it('gives two sockets on the same port and different addresses distinct keys', () => {
    // kind:serverId:label is the same string for both — same protocol, same
    // port, same host — and duplicate React keys make rows drop or update as
    // each other.
    const r = searchFleet(input({
      hosts: {
        a: {
          host: host({
            listeners: [port(443, { address: '0.0.0.0' }), port(443, { address: '::1' })]
          }),
          at: 1
        }
      }
    }), '443')
    expect(r.matches).toHaveLength(2)
    const naive = new Set(r.matches.map((m) => `${m.kind}:${m.serverId}:${m.label}`))
    expect(naive.size).toBe(1)
    const keys = new Set(r.matches.map((m, i) => matchKey(m, i)))
    expect(keys.size).toBe(2)
  })

  it('keeps keys distinct even for two byte-identical rows', () => {
    // netstat can print the same socket twice; a key that depends only on the
    // row's content cannot separate them.
    const r = searchFleet(input({
      hosts: { a: { host: host({ listeners: [port(443), port(443)] }), at: 1 } }
    }), '443')
    const keys = new Set(r.matches.map((m, i) => matchKey(m, i)))
    expect(keys.size).toBe(r.matches.length)
  })
})

describe('a server listed twice', () => {
  it('scans it once', () => {
    // Otherwise every row is duplicated, the host is counted twice in the
    // coverage sentence, and the two copies collide on a React key.
    const r = searchFleet(input({
      servers: [{ id: 'a', name: 'web-01' }, { id: 'a', name: 'web-01' }],
      hosts: { a: { host: host({ services: [unit('nginx.service')] }), at: 1 } }
    }), 'nginx')
    expect(r.matches).toHaveLength(1)
    expect(r.coverage.searched).toEqual(['web-01'])
  })
})
