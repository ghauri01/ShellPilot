import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { TOUR_STEPS } from '../src/renderer/src/components/onboarding/tourSteps'

// What is workspace-scoped and what is not, pinned so the claim and the code
// cannot drift apart again. The onboarding text said every vault entry belonged
// to a workspace; it never has.

const types = readFileSync('src/renderer/src/types.ts', 'utf8')
const vaultShared = readFileSync('src/shared/vault.ts', 'utf8')

const hasWorkspaceId = (src: string, iface: string): boolean => {
  const start = src.indexOf(`interface ${iface}`)
  if (start === -1) throw new Error(`no interface ${iface}`)
  return src.slice(start, src.indexOf('}', start)).includes('workspaceId')
}

describe('what a workspace actually isolates', () => {
  it.each(['Server', 'DatabaseConn', 'Tunnel'])('%s is workspace-scoped', (iface) => {
    expect(hasWorkspaceId(types, iface)).toBe(true)
  })

  it('a vault entry is not, and the docs must keep saying so', () => {
    // One vault per installation, shared by every workspace. If this ever gains
    // a workspaceId the copy asserted below has to change with it.
    expect(hasWorkspaceId(vaultShared, 'VaultEntry')).toBe(false)
  })
})

describe('the walkthrough does not overclaim isolation', () => {
  it('never says vault entries belong to a workspace', () => {
    const workspaces = TOUR_STEPS.find((s) => s.id === 'workspaces')!
    expect(workspaces.body).not.toMatch(/tunnel and vault entry belongs/)
  })

  it('says explicitly that the vault is shared across workspaces', () => {
    const text = TOUR_STEPS.map((s) => s.body).join(' ')
    expect(text).toMatch(/vault is (the exception|shared)|shared across every workspace/i)
  })

  it('still tells people workspaces can be password-protected', () => {
    // The real isolation is worth keeping in the tour; only the vault claim was
    // wrong.
    expect(TOUR_STEPS.find((s) => s.id === 'workspaces')!.body).toMatch(/password-protect/i)
  })
})

describe('SECURITY.md states the boundary', () => {
  it('says the vault is not workspace-scoped', () => {
    const doc = readFileSync('SECURITY.md', 'utf8')
    expect(doc).toMatch(/vault is not workspace-scoped/i)
  })
})
