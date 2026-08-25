import { describe, it, expect, beforeEach } from 'vitest'
import {
  listGroups,
  createGroup,
  deleteGroup,
  setAssignment,
  listAssignments,
  removeAssignment,
  resetPolicyCacheForTests
} from '../src/main/services/policyStore'

describe('policy store', () => {
  beforeEach(() => resetPolicyCacheForTests())

  it('seeds the four default access groups on first use', () => {
    const groups = listGroups()
    const names = groups.map((g) => g.name).sort()
    expect(names).toEqual(['Full Access', 'Read & Write', 'Read Only', 'Sudo Access'].sort())
    expect(groups.every((g) => g.builtIn)).toBe(true)
  })

  it('supports creating a custom group', () => {
    const g = createGroup('Logs Only')
    expect(g.builtIn).toBe(false)
    expect(listGroups().some((x) => x.id === g.id)).toBe(true)
  })

  it('refuses to delete a built-in group', () => {
    const readOnly = listGroups().find((g) => g.name === 'Read Only')!
    const result = deleteGroup(readOnly.id)
    expect(result.ok).toBe(false)
    expect(listGroups().some((g) => g.id === readOnly.id)).toBe(true)
  })

  it('deletes a custom group and clears assignments pointing at it', () => {
    const g = createGroup('Emergency Access')
    setAssignment({ level: 'server', serverId: 'srv-1' }, g.id)
    const result = deleteGroup(g.id)
    expect(result.ok).toBe(true)
    const assignment = listAssignments().find((a) => a.scope.level === 'server' && a.scope.serverId === 'srv-1')
    expect(assignment?.groupId).toBeNull()
  })

  it('setAssignment replaces rather than duplicates an existing scope', () => {
    setAssignment({ level: 'workspace', workspaceId: 'ws-1' }, 'grp-read-only')
    setAssignment({ level: 'workspace', workspaceId: 'ws-1' }, 'grp-full')
    const matches = listAssignments().filter((a) => a.scope.level === 'workspace' && a.scope.workspaceId === 'ws-1')
    expect(matches).toHaveLength(1)
    expect(matches[0].groupId).toBe('grp-full')
  })

  it('removeAssignment deletes it outright (server reverts to inheriting)', () => {
    const a = setAssignment({ level: 'server', serverId: 'srv-2' }, 'grp-read-only')
    removeAssignment(a.id)
    expect(listAssignments().some((x) => x.id === a.id)).toBe(false)
  })
})
