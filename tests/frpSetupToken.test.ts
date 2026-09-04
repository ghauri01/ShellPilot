import { beforeEach, describe, expect, it, vi } from 'vitest'
import type { VaultEntry } from '../src/shared/vault'

// The one secret the guided tunnel setup collects.
//
// The setup's whole promise is "once, and then never again". Before this
// channel existed the frp form ended that flow with a sentence — "Token — add
// one to this profile's vault entry before starting" — which is a correct
// instruction and the wrong place to meet it.
//
// The vault below is the real `vaultBridge` over a fake store rather than a
// stub of the bridge, for the reason tests/vpnKeyStaging.test.ts gives: a test
// that mocked the writing function and asserted it was not called would pass
// just as happily if the code had found another way to write.

let vaultEntries: VaultEntry[] = []
let vaultUnlocked = true

vi.mock('../src/main/services/secrets', () => ({
  getSecret: () => null,
  setSecret: () => undefined
}))

vi.mock('../src/main/services/vault', () => ({
  vaultStatus: () => ({ exists: true, unlocked: vaultUnlocked, entryCount: vaultEntries.length }),
  vaultList: () =>
    vaultUnlocked ? { ok: true, entries: vaultEntries } : { ok: false, error: 'Vault is locked.' },
  vaultSave: (entries: VaultEntry[]) => {
    if (!vaultUnlocked) return { ok: false, error: 'Vault is locked.' }
    vaultEntries = entries
    return { ok: true }
  }
}))

const { storeFrpToken } = await import('../src/main/services/vpn/frpSetup')

const TOKEN = 'sp-frp-token-a3f9'

beforeEach(() => {
  vaultEntries = []
  vaultUnlocked = true
})

describe('storing an frp server token', () => {
  it('writes it to the vault and returns a ref, not the token', async () => {
    const result = await storeFrpToken({
      profileName: 'Tunnel host',
      workspaceId: 'ws-1',
      token: TOKEN
    })

    expect(result.ok).toBe(true)
    expect(result.tokenRef?.field).toBe('token')
    expect(result.tokenRef?.vaultEntryId).toBe(result.vaultEntryId)
    // Nothing secret comes back out. The renderer holds the token for as long
    // as the form is open and then forgets it; the profile carries the ref.
    expect(JSON.stringify(result)).not.toContain(TOKEN)

    expect(vaultEntries).toHaveLength(1)
    expect(vaultEntries[0].name).toBe('Tunnel host')
    expect(vaultEntries[0].kind).toBe('vpn')
    expect(vaultEntries[0].tags).toEqual(['vpn', 'frp'])
    // `token` maps onto the password slot, which is what the vault UI renders,
    // so the credential is recognisable there rather than being a nameless
    // custom field.
    expect(vaultEntries[0].password).toBe(TOKEN)
  })

  it('releases the entry it replaces, and only after the new one is written', async () => {
    const first = await storeFrpToken({
      profileName: 'Tunnel host',
      workspaceId: 'ws-1',
      token: TOKEN
    })
    const second = await storeFrpToken({
      profileName: 'Tunnel host',
      workspaceId: 'ws-1',
      token: 'sp-frp-token-rotated',
      replaces: first.vaultEntryId
    })

    expect(second.ok).toBe(true)
    expect(vaultEntries.map((e) => e.id)).toEqual([second.vaultEntryId])
    expect(vaultEntries[0].password).toBe('sp-frp-token-rotated')
  })

  it('does not release the old token when the rotation is refused', async () => {
    const first = await storeFrpToken({
      profileName: 'Tunnel host',
      workspaceId: 'ws-1',
      token: TOKEN
    })
    // A rotation that never gets as far as writing anything. The release is
    // the destructive half of this operation and it must be reached only by a
    // path that has already succeeded — a release hoisted above the checks
    // would leave the profile pointing at nothing, holding a token that is
    // written down nowhere else.
    const refused = await storeFrpToken({
      profileName: 'Tunnel host',
      workspaceId: 'ws-1',
      token: '',
      replaces: first.vaultEntryId
    })

    expect(refused.ok).toBe(false)
    expect(vaultEntries.map((e) => e.id)).toEqual([first.vaultEntryId])
    expect(vaultEntries[0].password).toBe(TOKEN)
  })

  it('asks for an unlock rather than reporting an error the user cannot act on', async () => {
    vaultUnlocked = false
    const result = await storeFrpToken({
      profileName: 'Tunnel host',
      workspaceId: 'ws-1',
      token: TOKEN
    })
    expect(result.ok).toBe(false)
    expect(result.errorCode).toBe('vault-locked')
    expect(result.error).toBe(
      'Unlock the vault before saving this token — this is where it will be stored.'
    )
  })

  it('refuses an empty token and writes nothing', async () => {
    const result = await storeFrpToken({
      profileName: 'Tunnel host',
      workspaceId: 'ws-1',
      token: '   '
    })
    expect(result.ok).toBe(false)
    expect(result.error).toBe('No token was supplied.')
    expect(vaultEntries).toEqual([])
  })
})
