import { describe, it, expect, beforeEach } from 'vitest'
import { listGroups, resetPolicyCacheForTests } from '../src/main/services/policyStore'
import { evaluateCommand, evaluateFilePath, extractPathAccesses } from '../src/main/services/policyEngine'
import type { AccessGroup } from '../src/shared/mcp'

let readOnly: AccessGroup
let full: AccessGroup

beforeEach(() => {
  resetPolicyCacheForTests()
  readOnly = listGroups().find((g) => g.id === 'grp-read-only')!
  full = listGroups().find((g) => g.id === 'grp-full')!
})

const decide = (g: AccessGroup, cmd: string): string => evaluateCommand(g, cmd).decision

describe('path extraction', () => {
  it('reads operands of file-reading commands', () => {
    expect(extractPathAccesses('cat /etc/shadow')).toEqual([{ path: '/etc/shadow', mode: 'read' }])
    expect(extractPathAccesses('tail -n 50 /var/log/syslog')).toEqual([
      { path: '/var/log/syslog', mode: 'read' }
    ])
  })

  it('ignores relative operands, which cannot be matched against a pattern', () => {
    expect(extractPathAccesses('cat shadow')).toEqual([])
    expect(extractPathAccesses('cat ./notes.txt')).toEqual([])
  })

  it('sees through wrappers and their flags', () => {
    expect(extractPathAccesses('sudo cat /etc/shadow')).toEqual([{ path: '/etc/shadow', mode: 'read' }])
    expect(extractPathAccesses('sudo -u root cat /etc/shadow')).toEqual([{ path: '/etc/shadow', mode: 'read' }])
    expect(extractPathAccesses('env FOO=1 cat /etc/shadow')).toEqual([{ path: '/etc/shadow', mode: 'read' }])
    expect(extractPathAccesses('/bin/cat /etc/shadow')).toEqual([{ path: '/etc/shadow', mode: 'read' }])
  })

  it('treats redirections as writes regardless of the command', () => {
    expect(extractPathAccesses('echo hi > /etc/passwd')).toEqual([{ path: '/etc/passwd', mode: 'write' }])
    expect(extractPathAccesses('echo hi >> /etc/passwd')).toEqual([{ path: '/etc/passwd', mode: 'write' }])
    expect(extractPathAccesses('wc -l < /etc/shadow')).toEqual([{ path: '/etc/shadow', mode: 'read' }])
  })

  it('handles every command in a chain, including through a pipe', () => {
    expect(extractPathAccesses('ls /tmp && cat /etc/shadow')).toEqual([{ path: '/etc/shadow', mode: 'read' }])
    expect(extractPathAccesses('cat /etc/shadow | base64')).toEqual([{ path: '/etc/shadow', mode: 'read' }])
    expect(extractPathAccesses('cat /etc/hosts; cat /etc/shadow')).toEqual([
      { path: '/etc/hosts', mode: 'read' },
      { path: '/etc/shadow', mode: 'read' }
    ])
  })

  it('does not split on a separator inside quotes', () => {
    expect(extractPathAccesses('grep "a;b" /etc/shadow')).toEqual([{ path: '/etc/shadow', mode: 'read' }])
  })

  it('distinguishes copy sources from destinations', () => {
    expect(extractPathAccesses('cp /etc/hosts /tmp/hosts')).toEqual([
      { path: '/etc/hosts', mode: 'read' },
      { path: '/tmp/hosts', mode: 'write' }
    ])
  })

  it('treats sed as a write only with -i', () => {
    expect(extractPathAccesses('sed -n 1p /etc/hosts')).toEqual([{ path: '/etc/hosts', mode: 'read' }])
    expect(extractPathAccesses('sed -i s/a/b/ /etc/hosts')).toEqual([{ path: '/etc/hosts', mode: 'write' }])
  })

  it('reads dd operands from if= and of=', () => {
    expect(extractPathAccesses('dd if=/etc/shadow of=/tmp/out')).toEqual([
      { path: '/etc/shadow', mode: 'read' },
      { path: '/tmp/out', mode: 'write' }
    ])
  })

  it('finds nothing in commands that touch no files', () => {
    expect(extractPathAccesses('uptime')).toEqual([])
    expect(extractPathAccesses('systemctl status nginx')).toEqual([])
    expect(extractPathAccesses('df -h')).toEqual([])
  })
})

describe('command and file policy agree', () => {
  it('refuses via execute_command what read_file already refuses', () => {
    // The regression this exists for: path rules used to apply only to the
    // SFTP tools, so the shell equivalent was the way around them.
    for (const path of ['/etc/shadow', '/etc/gshadow', '/root/.ssh/id_rsa', '/home/bob/.ssh/id_rsa']) {
      expect(evaluateFilePath(readOnly, path, 'read').decision).toBe('deny')
      expect(decide(readOnly, `cat ${path}`)).toBe('deny')
    }
  })

  it('closes the same hole for sudo, which returned early before', () => {
    // Full Access has sudo at ask, so without the path check this was 'ask'.
    expect(decide(full, 'sudo cat /etc/shadow')).toBe('deny')
  })

  it('applies write rules to redirections', () => {
    // /var/www/** is write: ask in the seeded policy.
    expect(decide(full, 'echo x > /var/www/index.html')).toBe('ask')
    // Full Access leaves writeFiles at allow, so a path with no rule is unchanged.
    expect(decide(full, 'echo x > /tmp/scratch')).toBe('allow')
    // Read & Write keeps writeFiles at ask, and that still applies.
    const readWrite = listGroups().find((g) => g.id === 'grp-read-write')!
    expect(decide(readWrite, 'echo x > /tmp/scratch')).toBe('ask')
  })

  it('leaves ordinary commands exactly as they were', () => {
    expect(decide(readOnly, 'uptime')).toBe('allow')
    expect(decide(readOnly, 'cat /etc/hosts')).toBe('allow')
    expect(decide(readOnly, 'systemctl status nginx')).toBe('allow')
  })

  it('never widens a decision the command rules already made', () => {
    // Read Only denies sudo outright; a harmless path cannot soften that.
    expect(decide(readOnly, 'sudo cat /etc/hosts')).toBe('deny')
    // Unrestricted shells stay blocked whatever paths appear.
    expect(decide(full, 'sudo -i')).toBe('deny')
  })

  it('takes the most restrictive path in a chain', () => {
    expect(decide(readOnly, 'cat /etc/hosts && cat /etc/shadow')).toBe('deny')
  })
})
