import { beforeEach, describe, expect, it, vi } from 'vitest'
import type { VaultEntry } from '../src/shared/vault'

// Generating a WireGuard key must not store one.
//
// The profile form offers "Generate keypair" inside a dialog with a Cancel
// button, and it used to write the key to the vault the moment that button was
// pressed. Press Generate, change your mind, press Cancel, and an entry stayed
// behind that no profile referenced — the user had asked for a key and then
// said no, and got one anyway. Cosmetic rather than a leak, since it was
// visible in the vault UI and repeated generates replaced rather than
// accumulated, but wrong.
//
// The fix splits one operation into two: `mintKeypair` makes a pair and touches
// nothing, `storeKeypair` writes. These tests are about that boundary, so the
// assertion that matters most is a negative one — after minting, the vault is
// exactly as it was.
//
// The vault here is the real `vaultBridge` over a fake store, not a stub of the
// bridge itself. A test that mocked the writing function and then asserted the
// mock was not called would pass just as happily if the code had found some
// other way to write.

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

// Real-shaped material: 44-char base64, so nothing downstream rejects it for
// the wrong reason.
const PRIV_A = 'yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk='
const PUB_A = 'xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg='
const PRIV_B = 'aFpCyhws9cxwWoV4xELtfJvjJN+zQVRPISllRWgeopU='
const PUB_B = 'pkPvgzKnI5aurLXke0Gm5mrEX12B/I025l5wMfdPolI='

const keygen = vi.fn(async (params?: { publicKeyFor?: string }) => {
  // Mirrors the sidecar: with a private key it derives, without one it mints.
  if (params?.publicKeyFor) {
    return { publicKey: params.publicKeyFor === PRIV_B ? PUB_B : PUB_A }
  }
  return { privateKey: PRIV_A, publicKey: PUB_A }
})

vi.mock('../src/main/services/vpn/drivers/wireguard', () => ({
  wireguardDriver: { keygen: (p?: { publicKeyFor?: string }) => keygen(p) }
}))

const { mintKeypair, storeKeypair } = await import('../src/main/services/vpn/keys')

const vpnEntries = (): VaultEntry[] => vaultEntries.filter((e) => e.kind === 'vpn')

beforeEach(() => {
  vaultEntries = []
  vaultUnlocked = true
  keygen.mockClear()
})

describe('generating a key', () => {
  it('hands back a usable pair', async () => {
    const res = await mintKeypair()
    expect(res.ok).toBe(true)
    expect(res.privateKey).toBe(PRIV_A)
    expect(res.publicKey).toBe(PUB_A)
  })

  it('writes nothing to the vault', async () => {
    // The bug, stated as a test. Before the split this call left an entry.
    await mintKeypair()
    expect(vaultEntries).toEqual([])
  })

  it('still writes nothing after the user generates several times', async () => {
    // Someone deciding they do not like the look of a key and pressing the
    // button again is ordinary behaviour, not misuse.
    await mintKeypair()
    await mintKeypair()
    await mintKeypair()
    expect(vaultEntries).toEqual([])
  })

  it('reports a sidecar that answers without a private key rather than storing a blank', async () => {
    keygen.mockResolvedValueOnce({ publicKey: PUB_A } as { privateKey?: string; publicKey: string })
    const res = await mintKeypair()
    expect(res.ok).toBe(false)
    expect(vaultEntries).toEqual([])
  })
})

describe('generate, then cancel', () => {
  it('leaves no vault entry behind', async () => {
    // The whole point, end to end at this boundary: the form mints, the user
    // presses Cancel, and `storeKeypair` is simply never reached. There is no
    // cleanup path to get wrong because there is nothing to clean up.
    const minted = await mintKeypair()
    expect(minted.ok).toBe(true)

    // …Cancel. Nothing else happens.

    expect(vpnEntries()).toHaveLength(0)
    expect(vaultEntries).toEqual([])
  })
})

describe('generate, then save', () => {
  it('stores exactly one entry and returns the ref the profile keeps', async () => {
    const minted = await mintKeypair()
    const stored = await storeKeypair({
      profileName: 'Office WireGuard',
      workspaceId: 'w1',
      privateKey: minted.privateKey!
    })

    expect(stored.ok).toBe(true)
    expect(stored.privateKeyRef?.vaultEntryId).toBe(stored.vaultEntryId)
    expect(vpnEntries()).toHaveLength(1)
  })

  it('names the entry after the profile, so it is recognisable in the vault UI', async () => {
    await storeKeypair({ profileName: 'Office WireGuard', workspaceId: 'w1', privateKey: PRIV_A })
    expect(vpnEntries()[0].name).toContain('Office WireGuard')
  })

  it('falls back to a name rather than storing an untitled entry', async () => {
    await storeKeypair({ profileName: '   ', workspaceId: 'w1', privateKey: PRIV_A })
    expect(vpnEntries()[0].name.trim()).not.toBe('')
  })

  it('derives the public key instead of trusting one it was handed', async () => {
    // A stored pair whose halves do not match is the worst outcome available
    // here: it saves, it looks right on screen, the user authorises it on their
    // server, and the handshake silently never completes. So the public half is
    // computed from the private one at the point of storage.
    await storeKeypair({ profileName: 'p', workspaceId: 'w1', privateKey: PRIV_B })
    expect(keygen).toHaveBeenCalledWith({ publicKeyFor: PRIV_B })
  })
})

describe('replacing a stored key', () => {
  it('releases the old entry once the new one is written', async () => {
    const first = await storeKeypair({ profileName: 'p', workspaceId: 'w1', privateKey: PRIV_A })
    expect(vpnEntries()).toHaveLength(1)

    const second = await storeKeypair({
      profileName: 'p',
      workspaceId: 'w1',
      privateKey: PRIV_B,
      replaces: first.vaultEntryId
    })

    expect(second.ok).toBe(true)
    expect(vpnEntries().map((e) => e.id)).toEqual([second.vaultEntryId])
  })

  it('keeps the old entry when the new one could not be written', async () => {
    // Releasing first would lose a working key to a write that then failed,
    // which is the one outcome here worse than an orphan.
    const first = await storeKeypair({ profileName: 'p', workspaceId: 'w1', privateKey: PRIV_A })
    vaultUnlocked = false

    const second = await storeKeypair({
      profileName: 'p',
      workspaceId: 'w1',
      privateKey: PRIV_B,
      replaces: first.vaultEntryId
    })

    expect(second.ok).toBe(false)
    vaultUnlocked = true
    expect(vpnEntries().map((e) => e.id)).toEqual([first.vaultEntryId])
  })
})

describe('a locked vault', () => {
  it('is reported as vault-locked, so the form can offer to unlock it', async () => {
    // `withVaultUnlock` in the renderer keys off this exact code. Anything else
    // and Save fails with advice the user has no way to act on.
    vaultUnlocked = false
    const res = await storeKeypair({ profileName: 'p', workspaceId: 'w1', privateKey: PRIV_A })
    expect(res.ok).toBe(false)
    expect(res.errorCode).toBe('vault-locked')
  })

  it('does not stop a key being generated, because generating stores nothing', async () => {
    // Worth pinning: the old combined operation had to fail here, since it
    // wrote. Making the user unlock the vault before they can even see what a
    // key looks like is a prompt for no reason.
    vaultUnlocked = false
    const res = await mintKeypair()
    expect(res.ok).toBe(true)
    expect(res.publicKey).toBe(PUB_A)
  })
})
