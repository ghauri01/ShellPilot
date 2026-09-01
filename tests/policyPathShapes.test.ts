import { describe, it, expect } from 'vitest'
import { extractPathAccesses, evaluateFilePath, isAbsolute } from '../src/main/services/policyEngine'
import { listGroups, resetPolicyCacheForTests, migrateForTests } from '../src/main/services/policyStore'
import type { AccessGroup } from '../src/shared/mcp'

// Two bugs that made the seeded file-deny rules silently ineffective on macOS
// and Windows *remote* targets. Both failed open and both looked configured in
// the UI, which is the combination worth a regression test.
//
//   1. The seeds covered /root and /home but not /Users, so a macOS target had
//      no rule on ~/.ssh at all.
//   2. isAbsolute was `t.startsWith('/')`, so a Windows command produced zero
//      PathAccess entries and every file rule was skipped.
//
// Three of the four built-in groups allow readFiles outright, so in both cases
// the most obvious attack — reading a private key — went straight through.

// Deliberately reads the SHIPPED seeds rather than building filePolicies
// inline the way the other policy tests do. Bug 1 was a defect in the seeds
// themselves, so a test that supplies its own patterns would pass against the
// broken default and prove nothing.
//
// "Read Only" is the least privileged built-in group that still allows reading
// files, which is what makes a missing path rule cost something there.
const readOnly = (): AccessGroup => {
  resetPolicyCacheForTests()
  const groups = listGroups()
  const g = groups.find((x) => x.name === 'Read Only')
  if (!g) throw new Error(`no built-in "Read Only" group; found: ${groups.map((x) => x.name).join(', ')}`)
  return g
}

describe('isAbsolute recognises all three shapes', () => {
  it.each([
    ['/etc/shadow', true],
    ['/Users/me/.ssh/id_rsa', true],
    ['C:\\Users\\me\\.ssh\\id_rsa', true],
    ['C:/Users/me/.ssh/id_rsa', true],
    ['d:\\data\\x', true],
    ['\\\\server\\share\\secret', true],
    ['//server/share/secret', true],
    // Relative stays out: we cannot resolve it without the remote cwd.
    ['id_rsa', false],
    ['./id_rsa', false],
    ['..\\id_rsa', false],
    // A lone colon is not a drive.
    ['C:', false],
    ['http://example.com/x', false]
  ])('%s -> %s', (input, expected) => {
    expect(isAbsolute(input as string)).toBe(expected)
  })
})

describe('bug 1 — macOS home directories', () => {
  it('denies reading an SSH key under /Users', () => {
    // Before the fix the only home-dir rule was /home/*/.ssh/**, which matches
    // nothing on a Mac, and readFiles: allow did the rest.
    expect(evaluateFilePath(readOnly(), '/Users/zeeshan/.ssh/id_rsa', 'read').decision).toBe('deny')
  })

  it('still denies the Linux path it always did', () => {
    expect(evaluateFilePath(readOnly(), '/home/ubuntu/.ssh/id_rsa', 'read').decision).toBe('deny')
    expect(evaluateFilePath(readOnly(), '/root/.ssh/id_rsa', 'read').decision).toBe('deny')
  })

  it('does not deny an unrelated file under /Users', () => {
    // The rule must be about .ssh, not about home directories in general.
    expect(evaluateFilePath(readOnly(), '/Users/zeeshan/notes.txt', 'read').decision).toBe('allow')
  })

  it('extracts the path from a real command', () => {
    expect(extractPathAccesses('cat /Users/zeeshan/.ssh/id_rsa')).toEqual([
      { path: '/Users/zeeshan/.ssh/id_rsa', mode: 'read' }
    ])
  })
})

describe('bug 2 — Windows drive-letter paths', () => {
  it('extracts a path from `type C:\\Users\\me\\.ssh\\id_rsa`', () => {
    // The whole failure in one line: before the fix this returned [].
    expect(extractPathAccesses('type C:\\Users\\me\\.ssh\\id_rsa')).toEqual([
      { path: 'C:\\Users\\me\\.ssh\\id_rsa', mode: 'read' }
    ])
  })

  it('denies it', () => {
    expect(evaluateFilePath(readOnly(), 'C:\\Users\\me\\.ssh\\id_rsa', 'read').decision).toBe('deny')
  })

  it('matches whatever separator and casing the command happens to use', () => {
    for (const p of [
      'C:\\Users\\me\\.ssh\\id_rsa',
      'C:/Users/me/.ssh/id_rsa',
      'c:\\users\\me\\.ssh\\id_rsa',
      'C:\\USERS\\ME\\.SSH\\ID_RSA'
    ]) {
      expect(evaluateFilePath(readOnly(), p, 'read').decision, p).toBe('deny')
    }
  })

  it('applies to any drive, not just C:', () => {
    expect(evaluateFilePath(readOnly(), 'D:\\Users\\me\\.ssh\\id_rsa', 'read').decision).toBe('deny')
  })

  it('recognises PowerShell as well as cmd', () => {
    expect(extractPathAccesses('Get-Content C:\\Users\\me\\.ssh\\id_rsa')).toEqual([
      { path: 'C:\\Users\\me\\.ssh\\id_rsa', mode: 'read' }
    ])
  })

  it('treats a cmd-style /Q flag as a flag, not a path', () => {
    // `/Q` starts with a slash and would have looked absolute to a naive fix.
    expect(extractPathAccesses('del /Q C:\\Users\\me\\.ssh\\id_rsa')).toEqual([
      { path: 'C:\\Users\\me\\.ssh\\id_rsa', mode: 'write' }
    ])
  })

  it('does not mistake a POSIX operand for a flag', () => {
    // Guard against the flag-stripping above leaking into the POSIX path.
    expect(extractPathAccesses('cat /etc/shadow')).toEqual([
      { path: '/etc/shadow', mode: 'read' }
    ])
  })
})

describe('bug 2 — UNC paths', () => {
  it('recognises a UNC path as absolute and extracts it', () => {
    expect(extractPathAccesses('type \\\\fileserver\\home\\me\\.ssh\\id_rsa')).toEqual([
      { path: '\\\\fileserver\\home\\me\\.ssh\\id_rsa', mode: 'read' }
    ])
  })

  it('evaluates a UNC path against a rule written with forward slashes', () => {
    const g: AccessGroup = {
      ...readOnly(),
      filePolicies: [
        { id: 'fp-unc', pattern: '//fileserver/home/**', read: 'deny', write: 'deny' }
      ]
    }
    expect(evaluateFilePath(g, '\\\\fileserver\\home\\me\\.ssh\\id_rsa', 'read').decision).toBe('deny')
  })
})

describe('existing installs, not just fresh ones', () => {
  // The fix is worth nothing if it only reaches new installs: everyone who
  // already runs ShellPilot is the population that is currently exposed.
  // backfillCapabilities covers capabilities and explicitly not filePolicies,
  // so the seeds needed their own generation-based migration.
  const legacyState = () => ({
    version: 1 as const,
    assignments: [],
    serverMeta: [],
    // No filePolicyGeneration — exactly what a pre-fix file looks like.
    groups: [
      {
        id: 'grp-read-only',
        name: 'Read Only',
        builtIn: true,
        capabilities: {
          viewServer: 'allow', terminal: 'allow', readFiles: 'allow', writeFiles: 'deny',
          sftpDownload: 'allow', sftpUpload: 'deny', sshTunnel: 'deny', databaseAccess: 'allow',
          sudo: 'deny', serverMetrics: 'allow', manageServers: 'deny', vpnControl: 'deny'
        },
        filePolicies: [
          { id: 'fp1', pattern: '/etc/shadow', read: 'deny', write: 'deny' },
          { id: 'fp2', pattern: '/home/*/.ssh/**', read: 'deny', write: 'deny' }
        ]
      }
    ]
  })

  it('adds the macOS and Windows rules to a policy file written before the fix', () => {
    const migrated = migrateForTests(legacyState() as never)
    const patterns = migrated.groups[0].filePolicies.map((p) => p.pattern)
    expect(patterns).toContain('/Users/*/.ssh/**')
    expect(patterns).toContain('?:/Users/*/.ssh/**')
    // and keeps what was already there
    expect(patterns).toContain('/etc/shadow')
    expect(patterns).toContain('/home/*/.ssh/**')
  })

  it('is idempotent — a second load adds nothing', () => {
    const once = migrateForTests(legacyState() as never)
    const before = once.groups[0].filePolicies.length
    const twice = migrateForTests(once)
    expect(twice.groups[0].filePolicies).toHaveLength(before)
  })

  it('does not resurrect a rule the user deleted after the migration ran', () => {
    // Generation already at latest, rule absent because it was removed on
    // purpose. The seeds are ordinary data and a deletion has to stick.
    const state = migrateForTests(legacyState() as never)
    state.groups[0].filePolicies = state.groups[0].filePolicies.filter(
      (p) => p.pattern !== '/Users/*/.ssh/**'
    )
    const again = migrateForTests(state)
    expect(again.groups[0].filePolicies.map((p) => p.pattern)).not.toContain('/Users/*/.ssh/**')
  })

  it('leaves custom groups alone', () => {
    const state = legacyState() as never as ReturnType<typeof legacyState>
    state.groups[0].builtIn = false
    const migrated = migrateForTests(state as never)
    expect(migrated.groups[0].filePolicies.map((p) => p.pattern)).not.toContain('/Users/*/.ssh/**')
  })
})

describe('what deliberately still gets through', () => {
  it('does not resolve a relative path against an unknown remote cwd', () => {
    // policyEngine documents this: `cd /root/.ssh && cat id_rsa` evades
    // extraction by design, because the working directory is not knowable from
    // the command string. Recorded here so a future reader does not mistake it
    // for an oversight of this fix.
    expect(extractPathAccesses('cd /root/.ssh && cat id_rsa')).toEqual([])
  })
})
