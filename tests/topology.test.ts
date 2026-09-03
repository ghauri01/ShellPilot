import { describe, it, expect } from 'vitest'
import {
  buildTopology,
  databasesOn,
  dependentsOf,
  isJumpHost,
  rebootBlockFor,
  sameWaveDatabaseBlocks,
  unmatchedHopNote,
  type TopologyServer
} from '../src/shared/topology'

// The jump-host graph, and the hole in it.
//
// Everything here is about one question asked at the moment a patch run is
// about to restart a machine: WHO ELSE GOES DOWN WITH IT. There is no general
// answer, so the tests are as much about what this refuses to claim as about
// what it computes — the `unmatchedHops` block below is the important half of
// the file, not a footnote to it.

function srv(id: string, name: string, via: (string | null)[] = []): TopologyServer {
  return {
    id,
    name,
    route: via.map((v, i) =>
      v === null
        ? { host: `bastion-${i}.example.internal`, port: 22, username: 'ops' }
        : { serverId: v, host: `${v}.example.internal`, port: 22, username: 'ops' }
    )
  }
}

describe('the jump-host graph', () => {
  it('names the servers that route through a host', () => {
    const topo = buildTopology([
      srv('bastion', 'bastion'),
      srv('web', 'web-1', ['bastion']),
      srv('db', 'db-1', ['bastion'])
    ])
    expect(isJumpHost(topo, 'bastion')).toBe(true)
    expect(dependentsOf(topo, 'bastion').map((d) => d.name)).toEqual(['db-1', 'web-1'])
    // A leaf is not a jump host, and being a leaf is not the same as being
    // safe — see the unmatched-hop tests below.
    expect(isJumpHost(topo, 'web')).toBe(false)
  })

  it('refuses a reboot of a host other servers connect through', () => {
    const topo = buildTopology([srv('bastion', 'bastion'), srv('web', 'web-1', ['bastion'])])
    const block = rebootBlockFor(topo, 'bastion')
    expect(block).not.toBeNull()
    expect(block!.kind).toBe('jump-host')
    // The dependent is NAMED. "This host has dependents" makes an operator go
    // and look; "web-1 connects through it" is the answer.
    expect(block!.reason).toContain('web-1')
    expect(block!.reason).toContain('will not do it')
    expect(rebootBlockFor(topo, 'web')).toBeNull()
  })

  it('does not treat a server that is its own hop as its own dependent', () => {
    // A configuration mistake, not a dependency. Reading it as one would make
    // that server permanently unrebootable for being its own bastion.
    const topo = buildTopology([srv('a', 'alpha', ['a'])])
    expect(isJumpHost(topo, 'a')).toBe(false)
    expect(rebootBlockFor(topo, 'a')).toBeNull()
  })

  it('counts one server twice in another route as one dependent', () => {
    const topo = buildTopology([srv('b', 'bastion'), srv('w', 'web', ['b', 'b'])])
    expect(dependentsOf(topo, 'b')).toHaveLength(1)
  })
})

describe('the hole in the graph', () => {
  it('reports hops that are not backed by a saved server rather than ignoring them', () => {
    // THE CASE THIS EXISTS FOR: two servers share a bastion that was never
    // saved as a server. The graph cannot see the edge, so neither of them
    // looks like a jump host — and if one of the hosts being rebooted IS that
    // bastion, nothing would say so.
    const topo = buildTopology([srv('web', 'web-1', [null]), srv('app', 'app-1', [null])])
    expect(isJumpHost(topo, 'web')).toBe(false)
    expect(topo.unmatchedHops).toHaveLength(2)
    const note = unmatchedHopNote(topo)
    expect(note).not.toBeNull()
    expect(note).toContain('2 hops')
    expect(note).toContain('web-1')
    // The sentence has to say what the CONSEQUENCE is, not merely that a count
    // exists. A number with no meaning attached is skipped.
    expect(note).toContain('share a bastion')
  })

  it('says nothing at all when every hop resolved', () => {
    // A line reading "0 hops could not be matched" trains people to skip the
    // line that matters.
    const topo = buildTopology([srv('b', 'bastion'), srv('w', 'web', ['b'])])
    expect(topo.unmatchedHops).toEqual([])
    expect(unmatchedHopNote(topo)).toBeNull()
  })

  it('counts a hop pointing at a server that is not in the list as unmatched, not as an edge', () => {
    // A dangling reference — deleted, or in another workspace. Treating it as
    // an edge would put a refusal on a host nobody can name; dropping it
    // silently would shorten the count that admits the graph is incomplete.
    const topo = buildTopology([srv('w', 'web-1', ['ghost'])])
    expect(dependentsOf(topo, 'ghost')).toEqual([])
    expect(topo.unmatchedHops).toHaveLength(1)
    expect(topo.unmatchedHops[0].where).toContain('ghost')
    expect(unmatchedHopNote(topo)).toContain('1 hop is')
  })

  it('names the hop without inventing a credential', () => {
    const topo = buildTopology([
      { id: 'w', name: 'web', route: [{ host: 'jump.example', port: 2222, username: 'ops' }] }
    ])
    expect(topo.unmatchedHops[0].where).toBe('ops@jump.example:2222')
  })
})

describe('saved databases on a host', () => {
  const servers = [srv('a', 'db-a'), srv('b', 'db-b'), srv('c', 'db-c')]
  const dbs = [
    { id: 'd1', name: 'orders (primary)', kind: 'postgres', database: 'orders', sshServerId: 'a' },
    { id: 'd2', name: 'orders (replica)', kind: 'postgres', database: 'orders', sshServerId: 'b' },
    { id: 'd3', name: 'analytics', kind: 'postgres', database: 'analytics', sshServerId: 'c' }
  ]

  it('refuses to restart two hosts carrying the same saved database in one wave', () => {
    const topo = buildTopology(servers, dbs)
    expect(databasesOn(topo, 'a').map((d) => d.database)).toEqual(['orders'])
    const blocks = sameWaveDatabaseBlocks(topo, ['a', 'b'])
    expect(blocks.map((b) => b.serverName).sort()).toEqual(['db-a', 'db-b'])
    // And it says what the claim actually rests on, rather than implying
    // ShellPilot understands replication.
    expect(blocks[0].reason).toContain('does not know whether they replicate')
  })

  it('allows them in different waves', () => {
    const topo = buildTopology(servers, dbs)
    expect(sameWaveDatabaseBlocks(topo, ['a'])).toEqual([])
    expect(sameWaveDatabaseBlocks(topo, ['b'])).toEqual([])
  })

  it('does not collide unrelated databases of the same kind', () => {
    // Kind alone would refuse an entire wave of PostgreSQL servers that have
    // nothing to do with each other.
    const topo = buildTopology(servers, dbs)
    expect(sameWaveDatabaseBlocks(topo, ['a', 'c'])).toEqual([])
  })

  it('ignores a database saved without a name, because there is nothing to match', () => {
    const topo = buildTopology(servers, [
      { id: 'x', name: 'x', kind: 'redis', database: '', sshServerId: 'a' },
      { id: 'y', name: 'y', kind: 'redis', database: '', sshServerId: 'b' }
    ])
    expect(sameWaveDatabaseBlocks(topo, ['a', 'b'])).toEqual([])
  })

  it('ignores a database not reached through any saved server', () => {
    const topo = buildTopology(servers, [
      { id: 'x', name: 'x', kind: 'postgres', database: 'orders', sshServerId: null }
    ])
    expect(databasesOn(topo, 'a')).toEqual([])
  })
})
