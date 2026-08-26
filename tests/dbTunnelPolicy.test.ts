import { describe, it, expect, beforeEach } from 'vitest'
import { listGroups, resetPolicyCacheForTests } from '../src/main/services/policyStore'
import {
  classifyStatement,
  evaluateDatabaseStatement,
  evaluateTunnelOpen
} from '../src/main/services/policyEngine'
import type { AccessGroup } from '../src/shared/mcp'

let readOnly: AccessGroup
let readWrite: AccessGroup
let full: AccessGroup

beforeEach(() => {
  resetPolicyCacheForTests()
  readOnly = listGroups().find((g) => g.id === 'grp-read-only')!
  readWrite = listGroups().find((g) => g.id === 'grp-read-write')!
  full = listGroups().find((g) => g.id === 'grp-full')!
})

describe('statement classification', () => {
  it('recognises reads across dialects', () => {
    for (const s of ['SELECT 1', 'show tables', 'EXPLAIN SELECT * FROM t', 'WITH x AS (SELECT 1) SELECT * FROM x', 'GET mykey', 'db.users.find({})']) {
      expect(classifyStatement(s), s).toBe('read')
    }
  })

  it('reads mongo shell syntax, where the verb is not first', () => {
    expect(classifyStatement('db.users.find({})')).toBe('read')
    expect(classifyStatement('db.orders.aggregate([])')).toBe('read')
    expect(classifyStatement('db.users.insertOne({})')).toBe('mutating')
    expect(classifyStatement('db.users.deleteMany({})')).toBe('mutating')
    expect(classifyStatement('db.users.drop()')).toBe('destructive')
    expect(classifyStatement('db.dropDatabase()')).toBe('destructive')
  })

  it('recognises writes', () => {
    for (const s of ['INSERT INTO t VALUES (1)', 'update t set a=1', 'DELETE FROM t', 'SET k v']) {
      expect(classifyStatement(s), s).toBe('mutating')
    }
  })

  it('recognises schema and permission changes as destructive', () => {
    for (const s of ['DROP TABLE t', 'truncate t', 'ALTER TABLE t ADD c int', 'GRANT ALL ON t TO x', 'FLUSHALL']) {
      expect(classifyStatement(s), s).toBe('destructive')
    }
  })

  it('cannot be smuggled past by chaining a write onto a read', () => {
    expect(classifyStatement('SELECT 1; DROP TABLE users')).toBe('destructive')
    expect(classifyStatement('SELECT 1; DELETE FROM users')).toBe('mutating')
  })

  it('sees through comments used to hide the verb', () => {
    expect(classifyStatement('/* SELECT */ DROP TABLE t')).toBe('destructive')
    expect(classifyStatement('-- harmless\nDELETE FROM t')).toBe('mutating')
  })

  it('treats an unrecognised verb as a write, not a read', () => {
    // Guessing "harmless" is the expensive direction to be wrong in.
    expect(classifyStatement('pg_terminate_backend(1)')).toBe('mutating')
  })
})

describe('database statements against a group', () => {
  it('lets Read Only read but never write', () => {
    expect(evaluateDatabaseStatement(readOnly, 'SELECT 1').decision).toBe('allow')
    expect(evaluateDatabaseStatement(readOnly, 'DELETE FROM t').decision).toBe('deny')
    expect(evaluateDatabaseStatement(readOnly, 'DROP TABLE t').decision).toBe('deny')
  })

  it('never lets a write through silently, even on Full Access', () => {
    // databaseAccess and writeFiles are both ALLOW on Full Access, so without
    // the clamp this would be a silent DROP TABLE.
    expect(evaluateDatabaseStatement(full, 'SELECT 1').decision).toBe('allow')
    expect(evaluateDatabaseStatement(full, 'UPDATE t SET a=1').decision).toBe('ask')
    expect(evaluateDatabaseStatement(full, 'DROP TABLE t').decision).toBe('ask')
  })

  it('keeps asking on Read & Write, which already asks for writes', () => {
    expect(evaluateDatabaseStatement(readWrite, 'INSERT INTO t VALUES (1)').decision).toBe('ask')
  })

  it('denies everything when databaseAccess is denied', () => {
    const denied = { ...full, capabilities: { ...full.capabilities, databaseAccess: 'deny' as const } }
    expect(evaluateDatabaseStatement(denied, 'SELECT 1').decision).toBe('deny')
  })

  it('denies when no group is assigned at all', () => {
    expect(evaluateDatabaseStatement(null, 'SELECT 1').decision).toBe('deny')
  })
})

describe('opening a tunnel', () => {
  it('is denied for Read Only, which denies sshTunnel', () => {
    expect(evaluateTunnelOpen(readOnly).decision).toBe('deny')
  })

  it('always asks, never silently binds a port', () => {
    expect(evaluateTunnelOpen(readWrite).decision).toBe('ask')
    expect(evaluateTunnelOpen(full).decision).toBe('ask')
  })
})
