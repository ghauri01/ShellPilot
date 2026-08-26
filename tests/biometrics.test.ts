import { describe, it, expect, beforeEach, vi, afterEach } from 'vitest'
import { mkdtempSync, readFileSync, existsSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

// Biometric unlock is a GATE, not a key: Electron's promptTouchID
// authenticates the person, it does not return a Secure Enclave key bound to
// that authentication. So the vault's derived key is stored, encrypted with
// safeStorage, behind that prompt. These pin the properties that trade buys
// and the ones it must not cost.

let dir: string
let canTouchID = true
let promptResult: 'ok' | 'cancel' = 'ok'
let encryptionAvailable = true
let unlocked = true
let exported: { key: Buffer; salt: Buffer } | null = { key: Buffer.alloc(32, 7), salt: Buffer.alloc(16, 3) }
let unlockWithKeyResult = { ok: true as boolean, error: undefined as string | undefined }
const promptCalls: string[] = []

vi.mock('electron', async () => {
  const { mkdtempSync } = await import('node:fs')
  const { tmpdir } = await import('node:os')
  const { join } = await import('node:path')
  const d = mkdtempSync(join(tmpdir(), 'shellpilot-bio-'))
  return {
    app: { getPath: () => d },
    safeStorage: {
      isEncryptionAvailable: () => encryptionAvailable,
      // Reversible stand-in for the OS keychain: the point under test is the
      // flow, not the OS primitive.
      encryptString: (s: string) => Buffer.from(`enc:${s}`, 'utf8'),
      decryptString: (b: Buffer) => b.toString('utf8').replace(/^enc:/, '')
    },
    systemPreferences: {
      canPromptTouchID: () => canTouchID,
      promptTouchID: async (reason: string) => {
        promptCalls.push(reason)
        if (promptResult === 'cancel') throw new Error('Authentication cancelled')
      }
    }
  }
})

vi.mock('../src/main/services/vault', () => ({
  vaultStatus: () => ({ exists: true, unlocked, entryCount: 0 }),
  vaultExportKey: () => exported,
  vaultUnlockWithKey: () => unlockWithKeyResult
}))

const bio = await import('../src/main/services/biometrics')

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), 'x-'))
  canTouchID = true
  promptResult = 'ok'
  encryptionAvailable = true
  unlocked = true
  exported = { key: Buffer.alloc(32, 7), salt: Buffer.alloc(16, 3) }
  unlockWithKeyResult = { ok: true, error: undefined }
  promptCalls.length = 0
  bio.disableBiometricUnlock()
})
afterEach(() => vi.restoreAllMocks())

describe('support detection', () => {
  it('reports Touch ID on a Mac with an enrolled fingerprint', () => {
    const s = bio.biometricSupport()
    expect(s.available).toBe(process.platform === 'darwin')
    if (process.platform === 'darwin') expect(s.kind).toBe('touch-id')
  })

  it('explains itself when unavailable rather than offering an inert switch', () => {
    canTouchID = false
    const s = bio.biometricSupport()
    expect(s.available).toBe(false)
    expect(s.reason).toBeTruthy()
  })

  it('is unavailable with no secure storage, whatever the sensor says', () => {
    encryptionAvailable = false
    expect(bio.biometricSupport().available).toBe(false)
  })
})

describe('session scope — the default, and the reason this is defensible', () => {
  it('writes nothing to disk', async () => {
    if (!bio.biometricSupport().available) return
    expect(bio.enableBiometricUnlock('session').ok).toBe(true)
    const { app } = await import('electron')
    // KeePassXC's model: an attacker who can read your files gets nothing,
    // because there is nothing on disk to read.
    expect(existsSync(join(app.getPath('userData'), 'shellpilot-vault-bio.json'))).toBe(false)
    expect(bio.biometricScope()).toBe('session')
  })

  it('still unlocks while the app is running', async () => {
    if (!bio.biometricSupport().available) return
    bio.enableBiometricUnlock('session')
    expect((await bio.biometricUnlock()).ok).toBe(true)
    expect(promptCalls).toHaveLength(1)
  })

  it('is forgotten when the vault locks', async () => {
    // Otherwise "lock" would not mean locked.
    if (!bio.biometricSupport().available) return
    bio.enableBiometricUnlock('session')
    bio.forgetSessionKey()
    expect(bio.biometricEnabled()).toBe(false)
    expect((await bio.biometricUnlock()).ok).toBe(false)
  })

  it('removes any previously persisted key, so "session only" means it', async () => {
    if (!bio.biometricSupport().available) return
    bio.enableBiometricUnlock('persistent')
    const { app } = await import('electron')
    const file = join(app.getPath('userData'), 'shellpilot-vault-bio.json')
    expect(existsSync(file)).toBe(true)
    bio.enableBiometricUnlock('session')
    expect(existsSync(file)).toBe(false)
  })
})

describe('persistent scope — the weaker, explicit opt-in', () => {
  it('survives on disk and reports itself as the persistent kind', () => {
    if (!bio.biometricSupport().available) return
    expect(bio.enableBiometricUnlock('persistent').ok).toBe(true)
    expect(bio.biometricScope()).toBe('persistent')
  })

  it('is not what a plain enable gives you', () => {
    // The default must be the safe one.
    if (!bio.biometricSupport().available) return
    bio.enableBiometricUnlock()
    expect(bio.biometricScope()).toBe('session')
  })
})

describe('enabling', () => {
  it('refuses while the vault is locked', () => {
    // There must be no path here that turns a fingerprint into access the
    // caller did not already have.
    unlocked = false
    expect(bio.enableBiometricUnlock().ok).toBe(false)
    expect(bio.biometricEnabled()).toBe(false)
  })

  it('stores the key only after the vault is open', () => {
    if (!bio.biometricSupport().available) return
    expect(bio.enableBiometricUnlock().ok).toBe(true)
    expect(bio.biometricEnabled()).toBe(true)
  })

  it('never writes the key in the clear, on the path that does write', async () => {
    if (!bio.biometricSupport().available) return
    bio.enableBiometricUnlock('persistent')
    const { app } = await import('electron')
    const raw = readFileSync(join(app.getPath('userData'), 'shellpilot-vault-bio.json'), 'utf8')
    const keyB64 = Buffer.alloc(32, 7).toString('base64')

    // The derived key must not be recoverable by reading the file alone —
    // that is the whole reason it goes through safeStorage.
    expect(raw).not.toContain(keyB64)

    // What is on disk is the safeStorage ciphertext, and only that.
    const stored = JSON.parse(raw) as { key: string; salt: string }
    expect(Buffer.from(stored.key, 'base64').toString('utf8')).toBe(`enc:${keyB64}`)
    // The salt is not secret; it is stored plainly so a stale key can still be
    // recognised as belonging to this vault.
    expect(stored.salt).toBe(Buffer.alloc(16, 3).toString('base64'))
  })
})

describe('unlocking', () => {
  it('does nothing when it was never set up', async () => {
    const r = await bio.biometricUnlock()
    expect(r.ok).toBe(false)
    expect(promptCalls).toHaveLength(0)
  })

  it('prompts, then unlocks with the stored key', async () => {
    if (!bio.biometricSupport().available) return
    bio.enableBiometricUnlock()
    expect((await bio.biometricUnlock()).ok).toBe(true)
    expect(promptCalls).toHaveLength(1)
  })

  it('fails without unlocking when the prompt is cancelled', async () => {
    if (!bio.biometricSupport().available) return
    bio.enableBiometricUnlock()
    promptResult = 'cancel'
    expect((await bio.biometricUnlock()).ok).toBe(false)
    // Still set up — a cancelled prompt is not a reason to forget the key.
    expect(bio.biometricEnabled()).toBe(true)
  })

  it('forgets a key that no longer opens the vault', async () => {
    // The master password changed, or the file was replaced. Keeping it would
    // fail on every future unlock with nothing explaining why.
    if (!bio.biometricSupport().available) return
    bio.enableBiometricUnlock()
    unlockWithKeyResult = { ok: false, error: 'stale' }
    expect((await bio.biometricUnlock()).ok).toBe(false)
    expect(bio.biometricEnabled()).toBe(false)
  })
})

describe('disabling', () => {
  it('removes the stored key', () => {
    if (!bio.biometricSupport().available) return
    bio.enableBiometricUnlock()
    expect(bio.disableBiometricUnlock().ok).toBe(true)
    expect(bio.biometricEnabled()).toBe(false)
  })

  it('is safe to call when nothing is stored', () => {
    expect(bio.disableBiometricUnlock().ok).toBe(true)
  })
})

describe('platforms without a biometric prompt', () => {
  it('says why, in terms a user can act on', () => {
    // An inert switch with no explanation is worse than an honest absence:
    // the reason has to distinguish "your Mac has no enrolled fingerprint"
    // from "this platform cannot do it at all".
    const support = bio.biometricSupport()
    if (support.available) return
    expect(support.reason).toBeTruthy()
    expect(support.reason).toMatch(/master password|fingerprint|secure storage/i)
  })

  it('never reports a kind it cannot actually prompt with', () => {
    const support = bio.biometricSupport()
    if (!support.available) expect(support.kind).toBe('none')
  })
})

describe('failing closed', () => {
  it('authenticates for a kind it knows', async () => {
    if (!bio.biometricSupport().available) return
    await expect(bio.authenticateFor('touch-id', 'test')).resolves.toBeUndefined()
    expect(promptCalls).toHaveLength(1)
  })

  it('throws for a kind it has no prompt for, rather than falling through', async () => {
    // Regression: written inline this was `if (kind === 'touch-id') await
    // prompt()` — authenticate conditionally, then decrypt unconditionally.
    // Adding a windows-hello branch to biometricSupport() without touching the
    // unlock path would have shipped a vault that opens with no prompt at all.
    await expect(bio.authenticateFor('windows-hello', 'test')).rejects.toThrow(/windows-hello/)
    expect(promptCalls).toHaveLength(0)
  })

  it('throws for "none", which is what an unsupported platform reports', async () => {
    await expect(bio.authenticateFor('none', 'test')).rejects.toThrow()
    expect(promptCalls).toHaveLength(0)
  })
})
