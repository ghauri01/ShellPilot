import { describe, it, expect } from 'vitest'
import {
  summariseAccessGroup,
  summariseFilePolicies,
  capabilityDecisions,
  ELEVATED_CAPABILITIES
} from '../src/renderer/src/components/ai/accessGroupSummary'
import { evaluateCapability, evaluateFilePath } from '../src/main/services/policyEngine'
import { AI_CAPABILITIES } from '../src/shared/mcp'
import type { AccessGroup, AiCapabilityPolicy, PermissionValue } from '../src/shared/mcp'

// Mirrors policyStore.allowAll(): the seeded groups are built by overriding an
// all-allow baseline, and the summaries below are only meaningful if the
// fixtures match what the store actually writes.
function allowAll(overrides: Partial<AiCapabilityPolicy> = {}): AiCapabilityPolicy {
  return {
    viewServer: 'allow',
    terminal: 'allow',
    readFiles: 'allow',
    writeFiles: 'allow',
    sftpDownload: 'allow',
    sftpUpload: 'allow',
    sshTunnel: 'allow',
    databaseAccess: 'allow',
    sudo: 'allow',
    serverMetrics: 'allow',
    manageServers: 'deny',
    vpnControl: 'deny',
    ...overrides
  }
}

function everything(value: PermissionValue): AiCapabilityPolicy {
  return Object.fromEntries(AI_CAPABILITIES.map(({ id }) => [id, value])) as AiCapabilityPolicy
}

function group(capabilities: AiCapabilityPolicy, filePolicies: AccessGroup['filePolicies'] = []): AccessGroup {
  return { id: 'g', name: 'G', builtIn: false, capabilities, filePolicies }
}

describe('capabilityDecisions', () => {
  it('covers every capability in the grid', () => {
    expect(capabilityDecisions(group(everything('allow')))).toHaveLength(AI_CAPABILITIES.length)
  })

  it('treats an absent capability as deny, matching evaluateCapability', () => {
    // A group written before vpnControl existed has no key for it. The policy
    // engine reads `?? 'deny'`; if the summary read it as anything else it
    // would tell an upgraded install it has a permission the engine refuses.
    const partial = { ...everything('allow') } as Record<string, PermissionValue>
    delete partial.vpnControl
    const decisions = capabilityDecisions(group(partial as AiCapabilityPolicy))
    expect(decisions.find((d) => d.id === 'vpnControl')?.value).toBe('deny')
  })

  it('does not claim a group with a missing capability can do everything', () => {
    const partial = { ...everything('allow') } as Record<string, PermissionValue>
    delete partial.sudo
    const summary = summariseAccessGroup(group(partial as AiCapabilityPolicy))
    expect(summary.sentence).toContain('Cannot use sudo')
    expect(summary.sentence).not.toContain('everything')
    expect(summary.elevated).not.toContain('sudo')
  })
})

describe('summariseAccessGroup — built-in groups', () => {
  it('Read Only says it can read and cannot write or escalate', () => {
    const s = summariseAccessGroup(
      group(allowAll({ writeFiles: 'deny', sftpUpload: 'deny', sshTunnel: 'deny', sudo: 'deny' }))
    )
    expect(s.sentence).toBe(
      'Can see server details, run commands, read files, download files, query databases, and read server metrics without asking. ' +
        'Cannot use sudo, add servers to the workspace, control VPNs and reverse proxies, write files, upload files, or open SSH tunnels.'
    )
    expect(s.counts).toEqual({ allow: 6, ask: 0, deny: 6 })
    expect(s.elevated).toEqual([])
  })

  it('Read & Write asks before writing and still refuses sudo', () => {
    const s = summariseAccessGroup(
      group(
        allowAll({
          writeFiles: 'ask',
          sftpUpload: 'ask',
          sshTunnel: 'ask',
          sudo: 'deny',
          manageServers: 'ask',
          vpnControl: 'ask'
        })
      )
    )
    expect(s.clauses[0]).toBe(
      'Can see server details, run commands, read files, download files, query databases, and read server metrics without asking.'
    )
    expect(s.clauses[1]).toBe(
      'Asks you first before adding servers to the workspace, controlling VPNs and reverse proxies, writing files, uploading files, and opening SSH tunnels.'
    )
    expect(s.clauses[2]).toBe('Cannot use sudo.')
    expect(s.elevated).toEqual([])
  })

  it('Sudo Access asks before sudo and denies nothing', () => {
    const s = summariseAccessGroup(
      group(
        allowAll({
          writeFiles: 'ask',
          sftpUpload: 'ask',
          sshTunnel: 'ask',
          sudo: 'ask',
          manageServers: 'ask',
          vpnControl: 'ask'
        })
      )
    )
    expect(s.clauses).toHaveLength(2)
    expect(s.clauses[1]).toContain('Asks you first before using sudo,')
    expect(s.sentence).not.toContain('Cannot')
    // Asking is not granting: nothing here happens without a human.
    expect(s.elevated).toEqual([])
    expect(s.counts).toEqual({ allow: 6, ask: 6, deny: 0 })
  })

  it('Full Access still gates the three dangerous capabilities behind a prompt', () => {
    const s = summariseAccessGroup(
      group(allowAll({ sudo: 'ask', manageServers: 'ask', vpnControl: 'ask' }))
    )
    expect(s.clauses[0]).toBe(
      'Can see server details, run commands, read files, write files, download files, upload files, open SSH tunnels, query databases, and read server metrics without asking.'
    )
    expect(s.clauses[1]).toBe(
      'Asks you first before using sudo, adding servers to the workspace, and controlling VPNs and reverse proxies.'
    )
    expect(s.elevated).toEqual([])
  })

  it('the new-group default leads with what it can do', () => {
    const s = summariseAccessGroup(
      group(
        allowAll({
          terminal: 'ask',
          writeFiles: 'deny',
          sftpUpload: 'deny',
          sshTunnel: 'deny',
          databaseAccess: 'ask',
          sudo: 'deny'
        })
      )
    )
    expect(s.clauses[0]).toBe(
      'Can see server details, read files, download files, and read server metrics without asking.'
    )
    expect(s.clauses[1]).toBe('Asks you first before running commands and querying databases.')
    expect(s.clauses[2]).toContain('Cannot use sudo, add servers to the workspace')
  })
})

describe('summariseAccessGroup — edge cases', () => {
  it('says so plainly when everything is denied', () => {
    const s = summariseAccessGroup(group(everything('deny')))
    expect(s.sentence).toBe('Allows nothing — every AI request against the server is refused.')
    expect(s.counts).toEqual({ allow: 0, ask: 0, deny: 12 })
    expect(s.elevated).toEqual([])
  })

  it('names the dangerous capabilities when everything is allowed', () => {
    const s = summariseAccessGroup(group(everything('allow')))
    expect(s.sentence).toBe(
      'Can do everything without asking — including using sudo, adding servers to the workspace, and controlling VPNs and reverse proxies.'
    )
    expect(s.elevated).toEqual(ELEVATED_CAPABILITIES)
  })

  it('has no Can clause when every capability needs a prompt', () => {
    const s = summariseAccessGroup(group(everything('ask')))
    expect(s.clauses).toHaveLength(1)
    expect(s.sentence.startsWith('Asks you first before ')).toBe(true)
    expect(s.sentence).not.toContain('Can ')
  })

  it('names a dangerous capability first when it is allowed outright', () => {
    // The whole point of the summary: sudo at allow must be the first thing
    // read, never averaged into "9 capabilities allowed".
    const s = summariseAccessGroup(
      group(allowAll({ terminal: 'ask', writeFiles: 'ask', sftpUpload: 'ask', sshTunnel: 'ask' }))
    )
    expect(s.clauses[0].startsWith('Can use sudo,')).toBe(true)
    expect(s.elevated).toEqual(['sudo'])
  })

  it('orders every allowed dangerous capability ahead of the mundane ones', () => {
    const s = summariseAccessGroup(
      group(allowAll({ manageServers: 'allow', vpnControl: 'allow', writeFiles: 'ask' }))
    )
    expect(
      s.clauses[0].startsWith('Can use sudo, add servers to the workspace, control VPNs and reverse proxies,')
    ).toBe(true)
    expect(s.elevated).toEqual(ELEVATED_CAPABILITIES)
  })

  it('describes a single allowed capability without a stray conjunction', () => {
    const s = summariseAccessGroup(group({ ...everything('deny'), viewServer: 'allow' }))
    expect(s.clauses[0]).toBe('Can see server details without asking.')
  })

  it('joins exactly two items with "and" / "or" and no comma', () => {
    const s = summariseAccessGroup(
      group({ ...everything('deny'), viewServer: 'allow', serverMetrics: 'allow', sudo: 'ask' })
    )
    expect(s.clauses[0]).toBe('Can see server details and read server metrics without asking.')
    expect(s.clauses[1]).toBe('Asks you first before using sudo.')
  })
})

describe('summariseFilePolicies', () => {
  it('explains the fallback when there are no rules', () => {
    const s = summariseFilePolicies([])
    expect(s.sentence).toBe('No path rules — every file follows the read and write settings above.')
    expect(s.total).toBe(0)
  })

  it('counts denying and asking rules separately', () => {
    const s = summariseFilePolicies([
      { id: '1', pattern: '/etc/shadow', read: 'deny', write: 'deny' },
      { id: '2', pattern: '/root/.ssh/**', read: 'deny', write: 'deny' },
      { id: '3', pattern: '/etc/nginx/**', write: 'ask' },
      { id: '4', pattern: '/var/www/**', write: 'ask' },
      { id: '5', pattern: '/srv/**', write: 'allow' }
    ])
    expect(s.sentence).toBe('5 path rules — 2 blocking access and 2 asking first.')
    expect({ total: s.total, denying: s.denying, asking: s.asking }).toEqual({
      total: 5,
      denying: 2,
      asking: 2
    })
  })

  it('counts a rule that denies only one direction as a blocking rule', () => {
    const s = summariseFilePolicies([{ id: '1', pattern: '/etc/**', read: 'allow', write: 'deny' }])
    expect(s.sentence).toBe('1 path rule — 1 blocking access.')
  })

  it('does not double-count a rule that both denies and asks', () => {
    const s = summariseFilePolicies([{ id: '1', pattern: '/etc/**', read: 'ask', write: 'deny' }])
    expect(s).toMatchObject({ total: 1, denying: 1, asking: 0 })
  })

  it('omits the breakdown when no rule denies or asks', () => {
    const s = summariseFilePolicies([{ id: '1', pattern: '/srv/**', write: 'allow' }])
    expect(s.sentence).toBe('1 path rule.')
  })
})

// Mirrors policyStore.defaultFilePolicies(): 19 rules that deny both read and
// write on credential stores and shell history, plus two write-ask rules. The
// point of restating it here rather than using a two-rule stand-in is that the
// summary of the SHIPPED "Read Only" group is what was wrong.
function seededFilePolicies(): AccessGroup['filePolicies'] {
  const deny = (pattern: string): AccessGroup['filePolicies'][number] => ({
    id: pattern,
    pattern,
    read: 'deny',
    write: 'deny'
  })
  return [
    deny('/etc/shadow'),
    deny('/etc/gshadow'),
    deny('/root/.ssh/**'),
    deny('/home/*/.ssh/**'),
    deny('/Users/*/.ssh/**'),
    deny('?:/Users/*/.ssh/**'),
    deny('?:/Users/*/AppData/Roaming/Microsoft/Crypto/**'),
    deny('?:/Users/*/AppData/Roaming/Microsoft/Protect/**'),
    deny('?:/Users/*/AppData/Local/Microsoft/Credentials/**'),
    deny('?:/Users/*/AppData/Roaming/Microsoft/Credentials/**'),
    deny('?:/Users/*/AppData/Roaming/Microsoft/Windows/PowerShell/PSReadLine/**'),
    ...['/root', '/home/*', '/Users/*', '?:/Users/*'].flatMap((home) => [
      deny(`${home}/.*_history`),
      deny(`${home}/.local/share/fish/fish_history`)
    ]),
    { id: 'nginx', pattern: '/etc/nginx/**', write: 'ask' as const },
    { id: 'www', pattern: '/var/www/**', write: 'ask' as const }
  ]
}

// evaluateFilePath picks the longest matching rule that defines a value for the
// mode and RETURNS IT — the `blanket.decision === 'deny'` check below it is
// only reached when nothing matched. So a path rule outranks the capability in
// both directions, and these are the cases where a flat clause would lie.
describe('summariseAccessGroup — path rules outrank the capability', () => {
  it('does not claim a group cannot read files when a rule allows a path', () => {
    // Read files = DENY plus the rule the editor offers at AiAccessGroups:190.
    // The old summary said "Cannot ... read files" while an agent read /var/log.
    const s = summariseAccessGroup(
      group(allowAll({ readFiles: 'deny' }), [{ id: '1', pattern: '/var/log/**', read: 'allow' }])
    )
    expect(s.sentence).toContain('Cannot read files — except 1 path rule that allows it.')
    expect(s.overriddenByPath).toEqual(['readFiles'])
    // and it is not left sitting in the flat "Cannot" list as an absolute
    expect(s.clauses).toContain('Cannot add servers to the workspace or control VPNs and reverse proxies.')
  })

  it('does not claim a group can read files freely when a rule blocks a path', () => {
    const s = summariseAccessGroup(
      group(allowAll(), [{ id: '1', pattern: '/etc/shadow', read: 'deny', write: 'deny' }])
    )
    expect(s.sentence).toContain('Can read files without asking — except 1 path rule that blocks it.')
    expect(s.sentence).toContain('Can write files without asking — except 1 path rule that blocks it.')
  })

  it('orders a widening exception ahead of a narrowing one', () => {
    const s = summariseAccessGroup(
      group(allowAll({ readFiles: 'ask' }), [
        { id: '1', pattern: '/etc/shadow', read: 'deny' },
        { id: '2', pattern: '/var/log/**', read: 'allow' },
        { id: '3', pattern: '/srv/**', read: 'deny' }
      ])
    )
    expect(s.sentence).toContain(
      'Asks you first before reading files — except 1 path rule that allows it and 2 that block it.'
    )
  })

  it('ignores rules that only restate the capability', () => {
    const s = summariseAccessGroup(
      group(allowAll({ writeFiles: 'ask' }), [{ id: '1', pattern: '/etc/nginx/**', write: 'ask' }])
    )
    // A rule that agrees is not an exception, and counting it would inflate a
    // number the card is asking the reader to trust.
    expect(s.overriddenByPath).toEqual([])
    expect(s.sentence).not.toContain('except')
  })

  it('ignores a rule that leaves the mode unset', () => {
    const s = summariseAccessGroup(
      group(allowAll({ readFiles: 'deny' }), [{ id: '1', pattern: '/etc/nginx/**', write: 'ask' }])
    )
    expect(s.overriddenByPath).toEqual(['writeFiles'])
    // readFiles has no rule touching it, so it stays in the flat clause.
    expect(s.sentence).toContain('or read files.')
  })

  it('treats an explicit null on a rule the way evaluateFilePath does', () => {
    // evaluateFilePath filters on `!== undefined`, so a null still matches and
    // still wins — then falls through gate() to allow.
    const rule = { id: '1', pattern: '/var/log/**', read: null } as unknown as AccessGroup['filePolicies'][number]
    const s = summariseAccessGroup(group(allowAll({ readFiles: 'deny' }), [rule]))
    expect(s.sentence).toContain('Cannot read files — except 1 path rule that allows it.')
  })

  it('stops the shipped Read Only group contradicting itself', () => {
    // policyStore seeds two `write: 'ask'` rules into a group whose writeFiles
    // is deny, so the card said "Cannot ... write files" and the rule list said
    // "2 asking first" on the same screen.
    const s = summariseAccessGroup(
      group(
        allowAll({ writeFiles: 'deny', sftpUpload: 'deny', sshTunnel: 'deny', sudo: 'deny' }),
        seededFilePolicies()
      )
    )
    expect(s.clauses).toEqual([
      'Can see server details, run commands, download files, query databases, and read server metrics without asking.',
      'Cannot use sudo, add servers to the workspace, control VPNs and reverse proxies, upload files, or open SSH tunnels.',
      'Can read files without asking — except 19 path rules that block it.',
      'Cannot write files — except 2 path rules that ask you first.'
    ])
    // The grid still shows what the grid shows; the rules qualify it.
    expect(s.counts).toEqual({ allow: 6, ask: 0, deny: 6 })
    expect(s.overriddenByPath).toEqual(['readFiles', 'writeFiles'])
  })

  it('qualifies "allows nothing" when a path rule grants something', () => {
    const s = summariseAccessGroup(
      group(everything('deny'), [{ id: '1', pattern: '/var/log/**', read: 'allow' }])
    )
    expect(s.clauses[0]).toBe(
      'Allows nothing except the file paths below — every other AI request against the server is refused.'
    )
    expect(s.clauses[1]).toBe('Cannot read files — except 1 path rule that allows it.')
  })

  it('qualifies "everything" when a path rule takes something away', () => {
    const s = summariseAccessGroup(
      group(everything('allow'), [{ id: '1', pattern: '/etc/shadow', read: 'deny', write: 'deny' }])
    )
    expect(s.clauses[0]).toBe(
      'Can do everything without asking except the file paths below — including using sudo, adding servers to the workspace, and controlling VPNs and reverse proxies.'
    )
    expect(s.elevated).toEqual(ELEVATED_CAPABILITIES)
  })
})

describe('summariseAccessGroup — a value that is not a permission', () => {
  const odd = (v: unknown): AiCapabilityPolicy =>
    ({ ...allowAll(), readFiles: v } as unknown as AiCapabilityPolicy)

  it('reports it as allowed, because that is what gate() does with it', () => {
    // gate() checks === 'deny', then === 'ask', then proceeds. policyStore.read
    // validates only that `groups` is an array, so this reaches the engine.
    expect(capabilityDecisions(group(odd('maybe'))).find((d) => d.id === 'readFiles')).toMatchObject({
      value: 'allow',
      unrecognised: 'maybe'
    })
  })

  it('names it instead of dropping it out of the sentence', () => {
    const s = summariseAccessGroup(group(odd('maybe')))
    expect(s.clauses[0]).toBe(
      'Read files ("maybe") is set to a value ShellPilot does not recognise, so the policy engine allows it. Set it again below.'
    )
    expect(s.unrecognised).toEqual(['readFiles'])
    // It used to match none of the three filters and appear in no clause at all
    // while the agent read files anyway.
    expect(s.sentence).toContain('read files')
    expect(s.counts.allow + s.counts.ask + s.counts.deny).toBe(AI_CAPABILITIES.length)
  })

  it('still distinguishes absent (denied) from invalid (allowed)', () => {
    const missing = { ...allowAll() } as Record<string, unknown>
    delete missing.readFiles
    const absent = capabilityDecisions(group(missing as AiCapabilityPolicy)).find(
      (d) => d.id === 'readFiles'
    )
    expect(absent?.value).toBe('deny')
    expect(absent?.unrecognised).toBeUndefined()
    // null is absent too — `?? 'deny'` catches it, and so must this.
    expect(
      capabilityDecisions(group(odd(null))).find((d) => d.id === 'readFiles')?.value
    ).toBe('deny')
  })

  it('counts an unreadable elevated capability as granted with no prompt', () => {
    const s = summariseAccessGroup(
      group({ ...everything('deny'), sudo: 'ALLOW' } as unknown as AiCapabilityPolicy)
    )
    // The engine will run sudo silently, so the card's "No prompt" chip must lit.
    expect(s.elevated).toEqual(['sudo'])
    expect(s.clauses[0]).toContain('Sudo / privilege escalation ("ALLOW")')
  })

  it('lists several unreadable values in one clause', () => {
    const s = summariseAccessGroup(
      group({ ...allowAll(), readFiles: 'maybe', terminal: 7 } as unknown as AiCapabilityPolicy)
    )
    expect(s.clauses[0]).toBe(
      'Execute terminal commands ("7") and Read files ("maybe") are set to values ShellPilot does not recognise, so the policy engine allows them. Set them again below.'
    )
    expect(s.unrecognised).toEqual(['terminal', 'readFiles'])
  })

  it('does not let a long value run the card', () => {
    const s = summariseAccessGroup(group(odd('a'.repeat(200))))
    expect(s.clauses[0]).toContain(`("${'a'.repeat(24)}…")`)
  })
})

describe('summariseFilePolicies — rules that outrank the capabilities', () => {
  it('says how many rules grant more than the grid above does', () => {
    const s = summariseFilePolicies(
      [
        { id: '1', pattern: '/etc/shadow', read: 'deny', write: 'deny' },
        { id: '2', pattern: '/var/log/**', read: 'allow' },
        { id: '3', pattern: '/etc/nginx/**', write: 'ask' }
      ],
      allowAll({ readFiles: 'deny', writeFiles: 'deny' })
    )
    expect(s.sentence).toBe(
      '3 path rules — 1 blocking access and 1 asking first. 2 grant more than the capabilities above, and the path rule wins.'
    )
    expect(s.widening).toBe(2)
  })

  it('says nothing extra when every rule only narrows', () => {
    const s = summariseFilePolicies(
      [{ id: '1', pattern: '/etc/shadow', read: 'deny', write: 'deny' }],
      allowAll()
    )
    expect(s.sentence).toBe('1 path rule — 1 blocking access.')
    expect(s.widening).toBe(0)
  })

  it('counts a capability that is absent as denied, so a rule on it widens', () => {
    const missing = { ...allowAll() } as Record<string, unknown>
    delete missing.writeFiles
    const s = summariseFilePolicies(
      [{ id: '1', pattern: '/srv/**', write: 'ask' }],
      missing as AiCapabilityPolicy
    )
    expect(s.sentence).toBe(
      '1 path rule — 1 asking first. 1 grants more than the capabilities above, and the path rule wins.'
    )
  })

  it('reports no widening when it was not given the capabilities', () => {
    expect(summariseFilePolicies([{ id: '1', pattern: '/srv/**', write: 'allow' }]).widening).toBe(0)
  })
})

// The summary's whole premise, asserted against the engine it is describing
// rather than against a comment. If evaluateFilePath ever consults the blanket
// capability first, these fail and the clauses above become the wrong shape.
describe('the precedence the summary is built on', () => {
  const g = (
    capabilities: AiCapabilityPolicy,
    filePolicies: AccessGroup['filePolicies']
  ): AccessGroup => group(capabilities, filePolicies)

  it('lets a path rule read past a capability denial', () => {
    const decision = evaluateFilePath(
      g(allowAll({ readFiles: 'deny' }), [{ id: '1', pattern: '/var/log/**', read: 'allow' }]),
      '/var/log/syslog',
      'read'
    )
    expect(decision.decision).toBe('allow')
  })

  it('lets a path rule ask where the capability denies', () => {
    // The shipped Read Only shape: writeFiles deny, /etc/nginx/** write ask.
    const decision = evaluateFilePath(
      g(allowAll({ writeFiles: 'deny' }), [{ id: '1', pattern: '/etc/nginx/**', write: 'ask' }]),
      '/etc/nginx/nginx.conf',
      'write'
    )
    expect(decision.decision).toBe('ask')
  })

  it('falls back to the capability only where no rule matches', () => {
    expect(
      evaluateFilePath(
        g(allowAll({ readFiles: 'deny' }), [{ id: '1', pattern: '/var/log/**', read: 'allow' }]),
        '/home/me/notes.txt',
        'read'
      ).decision
    ).toBe('deny')
  })

  it('ignores a rule that sets only the other mode', () => {
    expect(
      evaluateFilePath(
        g(allowAll({ readFiles: 'deny' }), [{ id: '1', pattern: '/etc/nginx/**', write: 'ask' }]),
        '/etc/nginx/nginx.conf',
        'read'
      ).decision
    ).toBe('deny')
  })

  it('hands an unrecognised value straight through, which gate() then allows', () => {
    const decision = evaluateCapability(
      g({ ...allowAll(), readFiles: 'maybe' } as unknown as AiCapabilityPolicy, []),
      'readFiles'
    )
    // Not 'deny' and not 'ask' — gate() tests both, then proceeds.
    expect(decision.decision).not.toBe('deny')
    expect(decision.decision).not.toBe('ask')
  })
})

// The grid is where a user consents. They consent to the row they read, so the
// row has to describe the grant and not a narrower version of it. Server
// metrics is the case that went wrong: it meant CPU and memory when people set
// it, and get_server_metrics later began returning the host's failed units and
// its full listening-port table under the same unchanged label.
describe('the capability grid describes what it grants', () => {
  it('gives every capability a detail line', () => {
    for (const c of AI_CAPABILITIES) {
      expect(c.detail, c.id).toBeTruthy()
    }
  })

  it('never lets a detail just restate its own label', () => {
    // A detail that echoes the label adds nothing and reads as if the row were
    // documented when it is not.
    const norm = (s: string): string => s.toLowerCase().replace(/[^a-z]/g, '')
    for (const c of AI_CAPABILITIES) {
      expect(norm(c.detail), c.id).not.toBe(norm(c.label))
      expect(c.detail.length, c.id).toBeGreaterThan(c.label.length)
    }
  })

  it('says that server metrics includes the port and service inventory', () => {
    const cap = AI_CAPABILITIES.find((c) => c.id === 'serverMetrics')
    const text = `${cap?.label} ${cap?.detail}`.toLowerCase()
    // Both halves matter: a reader who skims only the label still has to learn
    // that this is more than capacity.
    expect(cap?.label.toLowerCase()).toMatch(/port/)
    expect(text).toMatch(/listening port/)
    expect(text).toMatch(/systemd|unit|service/)
  })
})
