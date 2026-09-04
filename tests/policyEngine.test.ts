import { describe, it, expect } from 'vitest'
import {
  resolveGroupId,
  evaluateCapability,
  evaluateCommand,
  evaluateFilePath,
  classifyCommand,
  mostRestrictive,
  globToRegExp
} from '../src/main/services/policyEngine'
import type { AccessGroup, AiCapabilityPolicy, PolicyAssignment } from '../src/shared/mcp'

function group(overrides: Partial<AccessGroup['capabilities']> = {}, filePolicies: AccessGroup['filePolicies'] = []): AccessGroup {
  return {
    id: 'g1',
    name: 'Test Group',
    builtIn: false,
    capabilities: {
      viewServer: 'allow',
      terminal: 'allow',
      readFiles: 'allow',
      writeFiles: 'deny',
      sftpDownload: 'allow',
      sftpUpload: 'deny',
      sshTunnel: 'deny',
      databaseAccess: 'allow',
      sudo: 'deny',
      serverMetrics: 'allow',
      // The three capabilities added after this fixture was written. Omitted,
      // every group built here fell through `evaluateCapability`'s
      // `?? 'deny'`, so nothing in this file exercised them under a group that
      // actually names them — and nothing exercised the fallback ON PURPOSE
      // either. Both are covered now: these three, and the test at the foot of
      // `evaluateCapability` for a group saved before a capability existed.
      hostFacts: 'allow',
      // Roadmap item 31, and denied here rather than allowed: it is the one
      // capability in the grid no MCP tool reads at all, so a fixture that
      // granted it would suggest the engine has something to hand an agent.
      // What it gates is whether ShellPilot's own posture probe may collect a
      // host's firewall rule lines.
      firewallRules: 'deny',
      manageServers: 'deny',
      vpnControl: 'deny',
      ...overrides
    },
    filePolicies
  }
}

describe('evaluateCapability', () => {
  it('denies when no group is assigned (No AI Access)', () => {
    expect(evaluateCapability(null, 'terminal').decision).toBe('deny')
  })

  it('reflects ALLOW / ASK / DENY from the group', () => {
    const g = group({ terminal: 'allow', writeFiles: 'ask', sudo: 'deny' })
    expect(evaluateCapability(g, 'terminal').decision).toBe('allow')
    expect(evaluateCapability(g, 'writeFiles').decision).toBe('ask')
    expect(evaluateCapability(g, 'sudo').decision).toBe('deny')
  })

  it('denies a capability a group saved before it existed has no entry for', () => {
    // The upgrade path, and the reason `evaluateCapability` ends in `?? 'deny'`
    // rather than falling through: `undefined` reads as neither 'deny' nor
    // 'ask' at the call sites and would behave like ALLOW, so shipping a new
    // capability would silently widen what every group already saved permits.
    //
    // Asserted deliberately here because the fixture above used to leave three
    // real capabilities out, which meant this branch was reached by accident
    // and would have stopped being reached the moment somebody filled them in.
    const stale = group()
    delete (stale.capabilities as Partial<AiCapabilityPolicy>).vpnControl
    expect(evaluateCapability(stale, 'vpnControl').decision).toBe('deny')
  })
})

describe('read-only, read/write and sudo groups', () => {
  it('Read Only: terminal allowed, writes and sudo denied', () => {
    const readOnly = group({ terminal: 'allow', writeFiles: 'deny', sudo: 'deny' })
    expect(evaluateCommand(readOnly, 'ls -la').decision).toBe('allow')
    expect(evaluateFilePath(readOnly, '/tmp/x', 'write').decision).toBe('deny')
    expect(evaluateCommand(readOnly, 'sudo systemctl restart nginx').decision).toBe('deny')
  })

  it('Read & Write: writes require approval, sudo still denied', () => {
    const readWrite = group({ terminal: 'allow', writeFiles: 'ask', sudo: 'deny' })
    expect(evaluateFilePath(readWrite, '/tmp/x', 'write').decision).toBe('ask')
    expect(evaluateCommand(readWrite, 'sudo systemctl restart nginx').decision).toBe('deny')
  })

  it('Sudo Access: sudo commands require approval, never auto-allowed', () => {
    const sudoGroup = group({ terminal: 'allow', sudo: 'ask' })
    expect(evaluateCommand(sudoGroup, 'sudo systemctl restart nginx').decision).toBe('ask')
    expect(evaluateCommand(sudoGroup, 'systemctl status nginx').decision).toBe('allow')
  })

  it('a custom group behaves like any other — no hard-coded three tiers', () => {
    const logsOnly = group({ terminal: 'ask', readFiles: 'allow', writeFiles: 'deny' })
    expect(evaluateCommand(logsOnly, 'tail -f /var/log/syslog').decision).toBe('ask')
  })
})

describe('unrestricted shells are always denied', () => {
  const fullAccess = group({ terminal: 'allow', sudo: 'allow' })

  it.each(['sudo -i', 'sudo su', 'sudo su -', 'sudo bash', 'sudo /bin/sh', 'su -', 'su - root'])(
    '%s is denied even when sudo=allow',
    (cmd) => {
      const result = evaluateCommand(fullAccess, cmd)
      expect(result.decision).toBe('deny')
    }
  )

  it('an ordinary sudo command is not affected', () => {
    expect(classifyCommand('sudo systemctl restart nginx').isUnrestrictedShell).toBe(false)
    expect(classifyCommand('sudo systemctl restart nginx').isSudo).toBe(true)
  })
})

describe('file path rules', () => {
  it('sensitive paths deny even when writeFiles/readFiles is allowed', () => {
    const g = group(
      { readFiles: 'allow', writeFiles: 'allow' },
      [{ id: 'r1', pattern: '/etc/shadow', read: 'deny', write: 'deny' }]
    )
    expect(evaluateFilePath(g, '/etc/shadow', 'read').decision).toBe('deny')
  })

  it('the most specific matching pattern wins', () => {
    const g = group({ writeFiles: 'allow' }, [
      { id: 'r1', pattern: '/var/www/**', write: 'ask' },
      { id: 'r2', pattern: '/var/www/html/public/**', write: 'allow' }
    ])
    expect(evaluateFilePath(g, '/var/www/html/public/index.html', 'write').decision).toBe('allow')
    expect(evaluateFilePath(g, '/var/www/html/private/config.php', 'write').decision).toBe('ask')
  })

  it('unmatched paths fall back to the blanket capability', () => {
    const g = group({ readFiles: 'allow', writeFiles: 'deny' }, [])
    expect(evaluateFilePath(g, '/home/ubuntu/notes.txt', 'read').decision).toBe('allow')
    expect(evaluateFilePath(g, '/home/ubuntu/notes.txt', 'write').decision).toBe('deny')
  })

  it('globToRegExp matches nested paths under **', () => {
    const rx = globToRegExp('/root/.ssh/**')
    expect(rx.test('/root/.ssh/id_rsa')).toBe(true)
    expect(rx.test('/root/.ssh/keys/id_rsa')).toBe(true)
    expect(rx.test('/root/other')).toBe(false)
  })
})

describe('inheritance and server-specific overrides', () => {
  it('a server with no assignment falls back to the workspace default', () => {
    const assignments: PolicyAssignment[] = [
      { id: 'a1', scope: { level: 'workspace', workspaceId: 'ws-prod' }, groupId: 'grp-read-only' }
    ]
    expect(resolveGroupId(assignments, 'srv-1', 'ws-prod')).toBe('grp-read-only')
  })

  it('a server-specific override wins over the workspace default', () => {
    const assignments: PolicyAssignment[] = [
      { id: 'a1', scope: { level: 'workspace', workspaceId: 'ws-prod' }, groupId: 'grp-read-only' },
      { id: 'a2', scope: { level: 'server', serverId: 'srv-test' }, groupId: 'grp-read-write' }
    ]
    expect(resolveGroupId(assignments, 'srv-test', 'ws-prod')).toBe('grp-read-write')
    expect(resolveGroupId(assignments, 'srv-other', 'ws-prod')).toBe('grp-read-only')
  })

  it('a workspace with no assignment at all defaults to No AI Access', () => {
    expect(resolveGroupId([], 'srv-1', 'ws-unconfigured')).toBeNull()
  })
})

describe('mostRestrictive', () => {
  it('deny beats ask beats allow, in either order', () => {
    expect(mostRestrictive({ decision: 'allow', reason: 'a' }, { decision: 'deny', reason: 'b' }).decision).toBe('deny')
    expect(mostRestrictive({ decision: 'deny', reason: 'a' }, { decision: 'allow', reason: 'b' }).decision).toBe('deny')
    expect(mostRestrictive({ decision: 'ask', reason: 'a' }, { decision: 'allow', reason: 'b' }).decision).toBe('ask')
    expect(mostRestrictive({ decision: 'allow', reason: 'a' }, { decision: 'allow', reason: 'b' }).decision).toBe('allow')
  })
})
