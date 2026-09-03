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

describe('a bastion the graph can only recognise by its address', () => {
  // The hole above is real, but it has a floor: a hop that names no saved
  // server is still an ADDRESS the user typed, and a saved server is still an
  // address the user typed. When the two are the same string, the machine is
  // not invisible — it is sitting in the list under another name, and a note
  // saying "somewhere out there is a hop we cannot see" is the one sentence
  // that is definitely wrong.

  it('resolves a bare hop to the saved server at the same address', () => {
    // web-1 routes through bare bastion.example. That machine is ALSO saved,
    // as `bastion`. Rebooting `bastion` drops web-1 — and keying on serverId
    // alone, nothing refuses it.
    const topo = buildTopology([
      { id: 'b', name: 'bastion', host: 'bastion.example', port: 22 },
      {
        id: 'w',
        name: 'web-1',
        host: 'web.example',
        port: 22,
        route: [{ host: 'bastion.example', port: 22, username: 'ops' }]
      }
    ])
    expect(isJumpHost(topo, 'b')).toBe(true)
    expect(dependentsOf(topo, 'b').map((d) => d.name)).toEqual(['web-1'])
    expect(dependentsOf(topo, 'b')[0].matchedBy).toBe('address')
    const block = rebootBlockFor(topo, 'b')
    expect(block).not.toBeNull()
    expect(block!.reason).toContain('web-1')
    // And it says HOW it made the match, because an address match is a
    // different claim from a saved reference and must not read as one.
    expect(block!.reason).toContain('bastion.example:22')
    expect(block!.reason).toContain('by the address')
  })

  it('stops counting a hop it resolved by address as part of the hole', () => {
    // The note exists to say the graph cannot see something. Once it can, the
    // note is a lie in the operator's favour, which is the direction that
    // matters.
    const topo = buildTopology([
      { id: 'b', name: 'bastion', host: 'bastion.example', port: 22 },
      { id: 'w', name: 'web-1', route: [{ host: 'bastion.example', port: 22 }] }
    ])
    expect(topo.unmatchedHops).toEqual([])
    expect(unmatchedHopNote(topo)).toBeNull()
  })

  it('refuses a reboot of the second saved record for one machine', () => {
    // bastion-a and bastion-b are the same box saved twice. X routes through
    // bastion-a by serverId; nothing names bastion-b at all. Rebooting
    // bastion-b takes X's connection down, and a serverId-only check returns
    // null for it.
    const topo = buildTopology([
      { id: 'id1', name: 'bastion-a', host: 'bastion.example', port: 22 },
      { id: 'id2', name: 'bastion-b', host: 'bastion.example', port: 22 },
      { id: 'x', name: 'x-1', route: [{ serverId: 'id1', host: 'bastion.example', port: 22 }] }
    ])
    expect(rebootBlockFor(topo, 'id1')).not.toBeNull()
    const second = rebootBlockFor(topo, 'id2')
    expect(second, 'rebooting the duplicate record drops x-1 and nothing refused it').not.toBeNull()
    expect(second!.reason).toContain('x-1')
    expect(dependentsOf(topo, 'id2')[0].matchedBy).toBe('address')
  })

  it('finds the duplicate even when the hop carries only a serverId', () => {
    // The hop names id1 and nothing else; the address comes from id1's own
    // saved record. Without that step the duplicate is invisible whenever the
    // route was built by picking a server from a list, which is how the app
    // builds them.
    const topo = buildTopology([
      { id: 'id1', name: 'bastion-a', host: 'bastion.example', port: 22 },
      { id: 'id2', name: 'bastion-b', host: 'bastion.example', port: 22 },
      { id: 'x', name: 'x-1', route: [{ serverId: 'id1' }] }
    ])
    expect(rebootBlockFor(topo, 'id2')).not.toBeNull()
  })

  it('matches on host AND port, so a different service on one box is not one machine', () => {
    const topo = buildTopology([
      { id: 'b', name: 'bastion', host: 'shared.example', port: 2222 },
      { id: 'w', name: 'web-1', route: [{ host: 'shared.example', port: 22 }] }
    ])
    expect(rebootBlockFor(topo, 'b')).toBeNull()
    expect(topo.unmatchedHops).toHaveLength(1)
  })

  it('treats an omitted port as 22 on both sides, and ignores case', () => {
    const topo = buildTopology([
      { id: 'b', name: 'bastion', host: 'Bastion.Example' },
      { id: 'w', name: 'web-1', route: [{ host: 'bastion.example' }] }
    ])
    expect(dependentsOf(topo, 'b').map((d) => d.name)).toEqual(['web-1'])
  })

  it('does not make a server its own dependent by matching its own address', () => {
    // The self-referencing-hop rule, restated for the address path: a server
    // whose route hop is its own address is a configuration mistake, not a
    // dependency, and reading it as one makes that host permanently
    // unrebootable for being its own bastion.
    const topo = buildTopology([
      { id: 'a', name: 'alpha', host: 'alpha.example', port: 22, route: [{ host: 'alpha.example' }] }
    ])
    expect(isJumpHost(topo, 'a')).toBe(false)
    expect(rebootBlockFor(topo, 'a')).toBeNull()
    // And it is not part of the hole either: the hop resolved, to the one
    // machine it could not possibly be a hidden bastion for.
    expect(topo.unmatchedHops).toEqual([])
  })

  it('resolves a dangling serverId by address rather than reporting a hole', () => {
    // The reference is dead — deleted, or another workspace — but the address
    // beside it is still a saved server. Demoting to unmatched here would
    // print a note about a hop that is sitting in the list.
    const topo = buildTopology([
      { id: 'b', name: 'bastion', host: 'bastion.example', port: 22 },
      { id: 'w', name: 'web-1', route: [{ serverId: 'ghost', host: 'bastion.example', port: 22 }] }
    ])
    expect(dependentsOf(topo, 'b').map((d) => d.name)).toEqual(['web-1'])
    expect(topo.unmatchedHops).toEqual([])
  })

  it('still demotes a dangling serverId with no usable address to the hole', () => {
    // Unchanged and load-bearing: refusing on a host nobody can name is worse
    // than counting it.
    const topo = buildTopology([{ id: 'w', name: 'web-1', route: [{ serverId: 'ghost' }] }])
    expect(topo.unmatchedHops).toHaveLength(1)
    expect(topo.unmatchedHops[0].where).toContain('ghost')
  })

  it('keeps blocking every link of a transitive chain on its own direct dependent', () => {
    // Sound and must stay: a -> b -> c, every intermediate has a direct
    // dependent, so each link refuses on its own without the graph ever
    // claiming to compute reachability.
    const topo = buildTopology([
      { id: 'c', name: 'core', host: 'core.example' },
      { id: 'b', name: 'mid', host: 'mid.example', route: [{ serverId: 'c' }] },
      { id: 'a', name: 'edge', host: 'edge.example', route: [{ serverId: 'b' }] }
    ])
    expect(rebootBlockFor(topo, 'c')!.reason).toContain('mid')
    expect(rebootBlockFor(topo, 'b')!.reason).toContain('edge')
    expect(rebootBlockFor(topo, 'a')).toBeNull()
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
