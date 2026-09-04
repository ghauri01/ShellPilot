// @vitest-environment jsdom
import { beforeEach, describe, expect, it } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { stubBridge } from './setup/renderer'
import { InventoryPanel } from '../src/renderer/src/components/monitor/InventoryPanel'
import { useFleet } from '../src/renderer/src/store/fleet'
import {
  FACTS_STATUS_MARKER,
  FACT_SOURCE_IDS,
  FACT_SOURCE_LABEL,
  METADATA_STALE_MS,
  parseHostFacts
} from '../src/shared/hostFacts'
import type { FactSourceId, FactSourceReport, FactStatus, HostFacts } from '../src/shared/hostFacts'
import type { HostMetrics } from '../src/shared/ssh'
import type { Server } from '../src/renderer/src/types'

// The inventory table — roadmap item C, renderer half.
//
// Every test here is about ONE thing: a cell with no value must never be
// readable as a cell with the value zero. That is not a presentation
// preference. Two of the five package managers can never count security
// updates and a third silently returns zero rows where the repositories publish
// no updateinfo, so an inventory that prints `0` for those hosts is telling an
// operator the estate is clean during exactly the week a CVE lands.
//
// src/shared/hostFacts.ts goes to real trouble to keep `unsupported`, `denied`,
// `no-tool`, `absent`, `stale-metadata` and "never collected" apart on the way
// in. All of it is thrown away by one `?? '—'` in a renderer, and until this
// file there was nothing that could notice.

const MINUTE = 60_000
const DAY = 24 * 60 * MINUTE

function server(id: string, name: string): Server {
  return {
    id,
    workspaceId: 'ws-default',
    folderId: null,
    name,
    host: `${id}.example.internal`,
    port: 22,
    username: 'ops',
    auth: 'key',
    status: 'online',
    tags: [],
    favorite: false,
    os: 'linux',
    route: [],
    vpnProfileId: null
  }
}

const metrics = (over: Partial<HostMetrics> = {}): HostMetrics => ({
  cpu: 1, memPct: 1, memUsed: 1, memTotal: 8 * 1024 * 1024 * 1024,
  diskPct: 1, diskUsed: 1, diskTotal: 2, netRx: 0, netTx: 0, uptime: 100,
  hostname: 'box', kernel: 'Linux 6.8.0-45-generic', cores: 4,
  services: [], listeners: [], listenerSource: 'ss',
  ...over
})

/** Every source `ok` unless named. A test about one status should not have to
 *  spell out the other eight. */
const sources = (over: Partial<Record<FactSourceId, FactStatus>> = {}): FactSourceReport[] =>
  FACT_SOURCE_IDS.map((id) => ({ id, label: FACT_SOURCE_LABEL[id], status: over[id] ?? 'ok' }))

const facts = (over: Partial<HostFacts> = {}): HostFacts => ({
  distroId: 'ubuntu',
  distroVersion: '24.04',
  prettyName: 'Ubuntu 24.04.1 LTS',
  arch: 'x86_64',
  cpuModel: 'AMD EPYC 7543',
  packageManager: 'apt',
  pendingUpdates: 0,
  securityUpdates: 0,
  rebootRequired: false,
  rebootReason: null,
  virtualisation: 'kvm',
  metadataAt: Date.now() - 30 * MINUTE,
  collectedAt: Date.now(),
  sources: sources(),
  ...over
})

/**
 * An Arch host. Pending updates are countable from the local sync database;
 * security updates are not countable at all, on any Arch host, ever.
 */
const archFacts = (over: Partial<HostFacts> = {}): HostFacts =>
  facts({
    distroId: 'arch',
    distroVersion: null,
    prettyName: 'Arch Linux',
    packageManager: 'pacman',
    pendingUpdates: 7,
    securityUpdates: null,
    virtualisation: 'none',
    sources: sources({ 'security-updates': 'unsupported' }),
    ...over
  })

/**
 * Facts as the parser actually produces them, from collector-shaped output.
 *
 * The fixtures above hand-set `sources`, which is fine for a status the
 * collector reports (`unsupported`, `denied`) but wrong for `stale-metadata`:
 * nothing on a host ever says that word. `parseHostFacts` DERIVES it by
 * comparing `meta-at` against METADATA_STALE_MS. A test that hand-sets it
 * exercises the panel and not the threshold, and would keep passing if the
 * derivation were deleted outright — so the staleness tests go through here.
 */
function collectedFacts(
  over: Record<string, string> = {},
  now = Date.now()
): ReturnType<typeof parseHostFacts> {
  const values: Record<string, string> = {
    'os-id': 'ID=ubuntu',
    'os-version': 'VERSION_ID="24.04"',
    'os-pretty': 'PRETTY_NAME="Ubuntu 24.04.1 LTS"',
    arch: 'x86_64',
    'cpu-model': 'AMD EPYC 7543',
    pkg: 'apt',
    pending: '12',
    security: '3',
    reboot: 'no',
    virt: 'kvm',
    'meta-at': String(Math.floor((now - 30 * MINUTE) / 1000)),
    ...over
  }
  const output = [
    ...Object.entries(values).map(([k, v]) => `V ${k} ${v}`),
    FACTS_STATUS_MARKER,
    ...FACT_SOURCE_IDS.map((id) => `${id} ok -`)
  ].join('\n')
  return parseHostFacts(output, now)
}

/** `meta-at` for a cache last refreshed `ms` ago. */
const metaAgo = (ms: number, now = Date.now()): Record<string, string> => ({
  'meta-at': String(Math.floor((now - ms) / 1000))
})

/** Seed the store the panel reads, the way FleetWatcher does at runtime. */
function seed(
  serverId: string,
  opts: { facts?: HostFacts; at?: number; metrics?: HostMetrics; error?: string } = {}
): void {
  const s = useFleet.getState()
  if (opts.metrics) s.report(serverId, opts.metrics, Date.now())
  if (opts.facts) s.reportFacts(serverId, opts.facts, opts.at ?? Date.now())
  if (opts.error) s.reportFactsError(serverId, opts.error, Date.now())
}

/** One cell, by host and column, independent of column order — the hardware
 *  disclosure changes that. */
function cell(hostName: string, column: string): HTMLElement {
  const el = document.querySelector(`td[data-host="${hostName}"][data-col="${column}"]`)
  if (!el) throw new Error(`no "${column}" cell for ${hostName}`)
  return el as HTMLElement
}

/** Host names in the order the table currently renders them. */
function rowOrder(): string[] {
  return [...document.querySelectorAll('td[data-col="host"]')].map(
    (td) => (td as HTMLElement).getAttribute('data-host') ?? ''
  )
}

beforeEach(() => {
  stubBridge({})
})

describe('a gap is never a zero', () => {
  // THE test. If only one thing in this file survives, it is this one.
  it('renders an unsupported security count as words, not as 0', async () => {
    // The Ubuntu host carries a NON-ZERO count on purpose. With it at 0 the
    // headline reads "0 security updates" whether `summarise` excludes the Arch
    // host or folds it in as a zero, so the assertion below could not tell the
    // two apart — a broken summary would have passed. At 5 it can: exclusion
    // says 5, inclusion-as-zero says 5 too, but a summary that counted the
    // unanswerable host as a CONTRIBUTOR is caught by the caveat assertions,
    // and a summary that dropped the real count is caught by the 5.
    seed('srv-u', { facts: facts({ securityUpdates: 5 }), metrics: metrics() })
    seed('srv-a', { facts: archFacts(), metrics: metrics() })
    render(<InventoryPanel servers={[server('srv-u', 'ubuntu-01'), server('srv-a', 'arch-01')]} />)

    // The host that genuinely has some.
    expect(cell('ubuntu-01', 'security').textContent).toBe('5')

    // The host that cannot know. Not "0", not "—", not blank, and containing no
    // digit at all — a reader skimming the column must not be able to land on
    // this cell and come away with a number.
    const unanswerable = cell('arch-01', 'security')
    const text = unanswerable.textContent ?? ''
    expect(text).not.toBe('0')
    expect(text).not.toBe('—')
    expect(text.trim()).not.toBe('')
    expect(text).not.toMatch(/\d/)
    expect(text).toMatch(/cannot be answered/i)
    // And the two cells must not be the same string, which is the only way a
    // column of them is readable at all.
    expect(text).not.toBe(cell('ubuntu-01', 'security').textContent)

    // The sentence behind it, in the collector's own terms.
    const help = unanswerable.querySelector('[title]')?.getAttribute('title') ?? ''
    expect(help).toMatch(/never as zero/i)

    // And it is said once more above the table, because a total of 0 security
    // updates drawn from an estate half of which can never contribute is a
    // different number from a total of 0.
    expect(document.body.textContent).toMatch(/can never report a security update count/i)
    // Not decoration on the count: the unanswerable host is excluded from it.
    // The total is the Ubuntu host's 5 alone, and the caveat names exactly one
    // host as excluded — which is only true if `unsupported` was neither summed
    // as 0 nor summed at all.
    expect(document.body.textContent).toMatch(/5 security updates/)
    expect(document.body.textContent).toMatch(/1 server can never report a security update count/i)
    expect(document.body.textContent).toMatch(/not in the 5 above/i)
    await Promise.resolve()
  })

  it('renders a server with no facts yet as not-collected, not as zero updates', () => {
    // Facts are hourly. A server added ten minutes ago genuinely has none, and
    // "0 pending updates, 0 security updates, no reboot needed" is the single
    // most dangerous thing this panel could say about a host nobody has asked.
    seed('srv-u', { facts: facts({ pendingUpdates: 4 }), metrics: metrics() })
    seed('srv-new', { metrics: metrics() })
    render(<InventoryPanel servers={[server('srv-u', 'ubuntu-01'), server('srv-new', 'new-01')]} />)

    for (const column of ['pending', 'security', 'reboot', 'distro', 'pkg', 'factsAge']) {
      const text = cell('new-01', column).textContent ?? ''
      expect(text, column).toMatch(/not collected yet/i)
      expect(text, column).not.toMatch(/\d/)
    }
    // The host that WAS collected still reads normally beside it.
    expect(cell('ubuntu-01', 'pending').textContent).toBe('4')

    const help = cell('new-01', 'pending').querySelector('[title]')?.getAttribute('title') ?? ''
    expect(help).toMatch(/once an hour/i)
  })
})

  it('does not headline "0 security updates" when every probe was denied', () => {
    // THE regression this test exists for. Three hosts, every one of them
    // refused the security probe. Each CELL says "not permitted" — that half was
    // always right. The estate line above them said "0 security updates" and
    // nothing else, because `summary.securityUnknown` was computed and then
    // never rendered anywhere in the repo: the only caveat on screen was the one
    // for `unsupported`, and none of these hosts is unsupported.
    //
    // A non-root account across a twelve-host estate therefore read "0 security
    // updates" during exactly the week a CVE lands — the failure the module
    // header says the whole item exists to prevent, told by the summary instead
    // of by the cell.
    const denied = (): HostFacts =>
      facts({
        securityUpdates: null,
        sources: sources({ 'security-updates': 'denied' })
      })
    seed('srv-1', { facts: denied(), metrics: metrics() })
    seed('srv-2', { facts: denied(), metrics: metrics() })
    seed('srv-3', { facts: denied(), metrics: metrics() })
    render(
      <InventoryPanel
        servers={[
          server('srv-1', 'deny-01'),
          server('srv-2', 'deny-02'),
          server('srv-3', 'deny-03')
        ]}
      />
    )

    // The cell was already honest.
    expect(cell('deny-01', 'security').textContent).toMatch(/not permitted/i)

    // The estate line must be too. A bare "0 security updates" with nothing
    // beside it is the lie.
    const text = document.body.textContent ?? ''
    expect(text).toMatch(/3 servers could not answer/i)

    // And the gap is named as one that can CLOSE — a different account gets an
    // answer here, which is the whole difference from `unsupported`.
    expect(text).toMatch(/can close/i)
    // This estate has no unsupported host, so the permanent caveat must not
    // appear: the two must not collapse into one another.
    expect(text).not.toMatch(/can never report a security update count/i)
  })

describe('the second staleness axis', () => {
  it('flags a stale package cache beside the counts it undermines', () => {
    // "0 pending updates" read out of a cache last refreshed forty days ago is
    // a lie, and it is a lie told by a number that is otherwise correct. The
    // warning has to arrive with the number, in the same cell — a stale marker
    // in a column three to the right loses to the number every time.
    //
    // Built from collector output through `parseHostFacts`, so the
    // `stale-metadata` status is DERIVED from the forty-day timestamp rather
    // than asserted by the fixture. Hand-setting it tested the panel and left
    // the derivation — the thing METADATA_STALE_MS actually drives — untouched.
    seed('srv-s', { facts: collectedFacts(metaAgo(40 * DAY)), metrics: metrics() })
    render(<InventoryPanel servers={[server('srv-s', 'stale-01')]} />)

    const pending = cell('stale-01', 'pending')
    expect(pending.textContent).toContain('12')
    expect(pending.textContent).toMatch(/stale cache/i)
    // The security count is read out of the same cache and is undermined by the
    // same fact.
    expect(cell('stale-01', 'security').textContent).toContain('3')
    expect(cell('stale-01', 'security').textContent).toMatch(/stale cache/i)

    const help = pending.querySelector('.inv-stale')?.getAttribute('title') ?? ''
    expect(help).toMatch(/has not been refreshed/i)

    // A host whose cache is current carries no marker, or the marker means
    // nothing — and this one goes through the same derivation, so the negative
    // is the derivation's own answer rather than a fixture that never mentioned
    // staleness.
    seed('srv-f', { facts: collectedFacts(metaAgo(30 * MINUTE)), metrics: metrics() })
    render(<InventoryPanel servers={[server('srv-f', 'fresh-01')]} />)
    expect(cell('fresh-01', 'pending').textContent).not.toMatch(/stale/i)
  })

  it('renders the fact age and the metadata age as two separate things', () => {
    // "Collected 5 minutes ago, from package metadata 40 days old" is the
    // honest reading of this row. Merging them into one age lets a fresh
    // collection vouch for a stale cache, which is exactly how a confident zero
    // gets on screen.
    const at = Date.now() - 5 * MINUTE
    seed('srv-s', { at, facts: collectedFacts(metaAgo(40 * DAY)), metrics: metrics() })
    render(<InventoryPanel servers={[server('srv-s', 'stale-01')]} />)

    const collected = cell('stale-01', 'factsAge').textContent ?? ''
    const metadata = cell('stale-01', 'metadataAge').textContent ?? ''
    expect(collected).toMatch(/^5m$/)
    expect(metadata).toMatch(/^40d/)
    // Two cells, two different answers. One age would have had to pick.
    expect(collected).not.toBe(metadata)

    // And both in one sentence on the row, since that is how a person reads it.
    const row = cell('stale-01', 'factsAge').closest('tr')
    expect(row?.getAttribute('title')).toBe(
      'collected 5m ago, from package metadata 40d old'
    )
  })

  it('derives staleness from METADATA_STALE_MS, on both sides of it', () => {
    // The threshold itself, exercised rather than asserted about the fixture.
    // `expect(40 * DAY).toBeGreaterThan(METADATA_STALE_MS)` was a fixture
    // self-check wearing threshold coverage as a hat: it compared two constants
    // and would have passed with the whole derivation deleted. This drives one
    // host either side of the real boundary through `parseHostFacts` and asks
    // the panel what it shows.
    const HOUR = 60 * MINUTE
    const now = Date.now()
    seed('srv-under', {
      facts: collectedFacts(metaAgo(METADATA_STALE_MS - HOUR, now), now),
      metrics: metrics()
    })
    seed('srv-over', {
      facts: collectedFacts(metaAgo(METADATA_STALE_MS + HOUR, now), now),
      metrics: metrics()
    })
    render(
      <InventoryPanel
        servers={[server('srv-under', 'under-01'), server('srv-over', 'over-01')]}
      />
    )

    // An hour inside the threshold: a count with nothing qualifying it.
    expect(cell('under-01', 'pending').textContent).toContain('12')
    expect(cell('under-01', 'pending').textContent).not.toMatch(/stale/i)
    expect(cell('under-01', 'metadataAge').textContent).not.toMatch(/stale/i)

    // An hour outside it: the same count, now marked, in both the cell that
    // carries the number and the cell that carries the cache's age.
    expect(cell('over-01', 'pending').textContent).toContain('12')
    expect(cell('over-01', 'pending').textContent).toMatch(/stale cache/i)
    expect(cell('over-01', 'security').textContent).toMatch(/stale cache/i)
    expect(cell('over-01', 'metadataAge').textContent).toMatch(/stale cache/i)

    // And the estate line says how many hosts the totals above it are drawn
    // from a stale cache on — one, not two.
    expect(document.body.textContent).toMatch(/1 server counted from a stale package cache/i)
  })
})

describe('sorting', () => {
  it('sorts servers with no update count LAST, in both directions', async () => {
    // The decision, pinned. A gap is not a magnitude: sorting it as 0 puts "we
    // could not count the updates on this host" at the top of an ascending sort
    // among the hosts that genuinely have none, which is the same lie the text
    // of the cell is careful not to tell, told by position instead. Last in
    // both directions means its position carries no information and does not
    // appear to.
    const user = userEvent.setup()
    seed('srv-zero', { facts: facts({ pendingUpdates: 0 }), metrics: metrics() })
    seed('srv-many', { facts: facts({ pendingUpdates: 12 }), metrics: metrics() })
    seed('srv-deny', {
      facts: facts({
        pendingUpdates: null,
        securityUpdates: null,
        sources: sources({ updates: 'denied', 'security-updates': 'denied' })
      }),
      metrics: metrics()
    })
    render(
      <InventoryPanel
        servers={[
          server('srv-zero', 'zero-01'),
          server('srv-many', 'many-01'),
          server('srv-deny', 'denied-01')
        ]}
      />
    )

    // A count column starts on "most first", which is what anyone clicking
    // Updates wants to see.
    await user.click(screen.getByRole('button', { name: /Updates/ }))
    expect(rowOrder()).toEqual(['many-01', 'zero-01', 'denied-01'])

    // Reversed. The hosts that HAVE answers swap; the one that does not stays
    // where it was — it never occupies the position a value would.
    await user.click(screen.getByRole('button', { name: /Updates/ }))
    expect(rowOrder()).toEqual(['zero-01', 'many-01', 'denied-01'])
    // Stated as its own assertion because it is the thing that must not regress:
    // an unknown sorted as 0 would land first here, next to the real zero.
    expect(rowOrder()[0]).not.toBe('denied-01')
    expect(rowOrder().at(-1)).toBe('denied-01')
  })

  it('gives three different kinds of gap one defined order, whatever the input order', async () => {
    // The previous test used a single gap host, so "gaps sort last" was all it
    // could pin. The question it left open is the one a reader of a real estate
    // hits: `unsupported`, `denied` and `not-collected` all have a null sort
    // key, so what decides their order among themselves? It must be a property
    // of the rows and not of whatever order the server list happened to arrive
    // in, or the table reshuffles under someone as unrelated data updates.
    //
    // The answer, pinned: the name tiebreak, applied UNREVERSED, so the block
    // of gap hosts is alphabetical and identical in both directions. Nothing
    // about which gap it is may move a row, because none of the three carries
    // more magnitude than the others — they carry none.
    const user = userEvent.setup()
    seed('srv-many', { facts: facts({ securityUpdates: 9 }), metrics: metrics() })
    seed('srv-zero', { facts: facts({ securityUpdates: 0 }), metrics: metrics() })
    seed('srv-unsup', { facts: archFacts(), metrics: metrics() })
    seed('srv-deny', {
      facts: facts({
        securityUpdates: null,
        sources: sources({ 'security-updates': 'denied' })
      }),
      metrics: metrics()
    })
    // No facts at all: `not-collected`, the third kind.
    seed('srv-none', { metrics: metrics() })
    render(
      // Deliberately NOT in the expected order, and with the three gap hosts
      // interleaved among the two that have values.
      <InventoryPanel
        servers={[
          server('srv-unsup', 'c-gap'),
          server('srv-zero', 'zero-01'),
          server('srv-none', 'b-gap'),
          server('srv-many', 'many-01'),
          server('srv-deny', 'a-gap')
        ]}
      />
    )

    // Security starts descending: most first, then the three gaps, alphabetical.
    expect(rowOrder()).toEqual(['many-01', 'zero-01', 'a-gap', 'b-gap', 'c-gap'])
    // Each of the three is a different kind of gap, so the order above is not
    // three rows that happen to look alike.
    expect(cell('a-gap', 'security').textContent).toMatch(/not permitted/i)
    expect(cell('b-gap', 'security').textContent).toMatch(/not collected yet/i)
    expect(cell('c-gap', 'security').textContent).toMatch(/cannot be answered/i)

    // Reversed. The two hosts with values swap. The three gap rows do not move
    // at all — not relative to each other and not relative to the end of the
    // table — because reversing an ordering that carries no information would
    // only make it look like it carried some.
    await user.click(screen.getByRole('button', { name: /Security/ }))
    expect(rowOrder()).toEqual(['zero-01', 'many-01', 'a-gap', 'b-gap', 'c-gap'])
  })
})

describe('the first thing a user sees', () => {
  it('says what to do next when nothing has been collected', () => {
    // The module is off by default, so this IS the first screen for everyone
    // who turns it on. "No data" would be true and useless.
    seed('srv-u', { metrics: metrics() })
    render(<InventoryPanel servers={[server('srv-u', 'ubuntu-01')]} />)
    const text = document.body.textContent ?? ''
    expect(text).toMatch(/No server facts have been collected yet/i)
    expect(text).toMatch(/once an hour/i)
    expect(text).toMatch(/background checking/i)
    expect(screen.getByRole('button', { name: /Check now/ })).toBeTruthy()
  })

  it('keeps the thirteen columns readable by hiding hardware until asked', async () => {
    const user = userEvent.setup()
    seed('srv-u', { facts: facts(), metrics: metrics() })
    render(<InventoryPanel servers={[server('srv-u', 'ubuntu-01')]} />)

    // What the host NEEDS is on screen without asking.
    expect(cell('ubuntu-01', 'security')).toBeTruthy()
    expect(cell('ubuntu-01', 'pending')).toBeTruthy()
    // What it IS is one click away.
    expect(document.querySelector('td[data-col="cpu"]')).toBeNull()
    await user.click(screen.getByRole('button', { name: /Show hardware/ }))
    expect(cell('ubuntu-01', 'cpu').textContent).toContain('EPYC')
    expect(cell('ubuntu-01', 'kernel').textContent).toContain('6.8.0')
  })
})
