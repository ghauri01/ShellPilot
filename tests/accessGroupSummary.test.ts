import { describe, it, expect } from 'vitest'
import {
  summariseAccessGroup,
  summariseFilePolicies,
  capabilityDecisions,
  ELEVATED_CAPABILITIES
} from '../src/renderer/src/components/ai/accessGroupSummary'
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
