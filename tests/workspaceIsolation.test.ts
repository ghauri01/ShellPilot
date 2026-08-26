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

  it('a vault entry can belong to one, optionally', () => {
    // Optional, because "shared" is a real state: one credential used from
    // several workspaces should exist once.
    expect(vaultShared).toMatch(/workspaceId\?: string/)
  })
})

describe('the walkthrough does not overclaim isolation', () => {
  it('explains that an entry can be shared rather than implying total isolation', () => {
    // The vault is filtered by workspace, not cryptographically separated, and
    // the tour must not imply otherwise.
    const text = TOUR_STEPS.map((s) => s.body).join(' ')
    expect(text).toMatch(/marked shared/i)
  })

  it('still tells people workspaces can be password-protected', () => {
    // The real isolation is worth keeping in the tour; only the vault claim was
    // wrong.
    expect(TOUR_STEPS.find((s) => s.id === 'workspaces')!.body).toMatch(/password-protect/i)
  })
})

describe('SECURITY.md states the boundary', () => {
  it('says filtering is not a cryptographic boundary', () => {
    const doc = readFileSync('SECURITY.md', 'utf8')
    expect(doc).toMatch(/filtered by workspace, not separated by it/i)
    expect(doc).toMatch(/not\*{0,2} a cryptographic boundary/i)
  })
})
