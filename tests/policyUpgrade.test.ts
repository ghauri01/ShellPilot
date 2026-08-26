import { describe, it, expect, beforeEach } from 'vitest'
import { writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { app } from 'electron'
import { listGroups, getGroup, resetPolicyCacheForTests } from '../src/main/services/policyStore'
import { evaluateCapability } from '../src/main/services/policyEngine'
import { AI_CAPABILITIES } from '../src/shared/mcp'

const FILE = join(app.getPath('userData'), 'shellpilot-ai-policy.json')

// A policy file written before manageServers existed: every group is missing
// the key, which is what every upgraded install looks like.
function writeLegacyPolicy(): void {
  const legacyCaps = {
    viewServer: 'allow',
    terminal: 'allow',
    readFiles: 'allow',
    writeFiles: 'allow',
    sftpDownload: 'allow',
    sftpUpload: 'allow',
    sshTunnel: 'allow',
    databaseAccess: 'allow',
    sudo: 'ask',
    serverMetrics: 'allow'
  }
  writeFileSync(
    FILE,
    JSON.stringify({
      version: 1,
      groups: [
        { id: 'grp-read-only', name: 'Read Only', builtIn: true, capabilities: { ...legacyCaps, writeFiles: 'deny', sudo: 'deny' }, filePolicies: [] },
        { id: 'grp-full', name: 'Full Access', builtIn: true, capabilities: { ...legacyCaps }, filePolicies: [] },
        { id: 'grp-custom', name: 'Logs Only', builtIn: false, capabilities: { ...legacyCaps }, filePolicies: [] }
      ],
      assignments: [],
      serverMeta: []
    })
  )
}

beforeEach(() => {
  resetPolicyCacheForTests()
  writeLegacyPolicy()
})

describe('upgrading a policy file written before a capability existed', () => {
  it('leaves no capability undefined on any group', () => {
    const missing: string[] = []
    for (const g of listGroups()) {
      for (const { id } of AI_CAPABILITIES) {
        if (g.capabilities[id] === undefined) missing.push(`${g.name}.${id}`)
      }
    }
    expect(missing).toEqual([])
  })

  it('gives a built-in group what a fresh install would have given it', () => {
    // Not 'allow' — Full Access seeds manageServers at ASK, so every add still
    // raises an approval prompt.
    expect(getGroup('grp-full')?.capabilities.manageServers).toBe('ask')
    expect(getGroup('grp-read-only')?.capabilities.manageServers).toBe('deny')
  })

  it('denies a new capability on a custom group, which has no intent on record', () => {
    expect(getGroup('grp-custom')?.capabilities.manageServers).toBe('deny')
  })

  it('does not disturb capabilities the file already set', () => {
    const readOnly = getGroup('grp-read-only')!
    expect(readOnly.capabilities.writeFiles).toBe('deny')
    expect(readOnly.capabilities.sudo).toBe('deny')
    expect(readOnly.capabilities.terminal).toBe('allow')
  })

  it('makes the backfilled capability actually usable', () => {
    // Before the backfill this evaluated to deny via the undefined guard, and
    // no amount of changing other settings could shift it.
    expect(evaluateCapability(getGroup('grp-full'), 'manageServers').decision).toBe('ask')
  })
})
