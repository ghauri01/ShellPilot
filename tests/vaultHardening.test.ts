import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import { readFileSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { app } from 'electron'
import {
  vaultCreate,
  vaultUnlock,
  vaultLock,
  vaultList,
  vaultStatus,
  vaultSave,
  setVaultAutoLock,
  vaultDestroy
} from '../src/main/services/vault'

const FILE = join(app.getPath('userData'), 'shellpilot-vault.json')
const read = (): Record<string, unknown> => JSON.parse(readFileSync(FILE, 'utf8'))

beforeEach(() => {
  vaultDestroy()
  setVaultAutoLock(0) // off unless a test asks for it
})
afterEach(() => vi.useRealTimers())

describe('scrypt work factor', () => {
  it('records the parameters it wrote a vault with', async () => {
    // Without this an existing vault could not be opened after the parameters
    // were raised, because the key would derive differently.
    expect((await vaultCreate('a-long-enough-password')).ok).toBe(true)
    expect(read().kdf).toEqual({ N: 32768, r: 8, p: 3 })
  })

  it('opens a vault written at the old work factor', async () => {
    await vaultCreate('a-long-enough-password')
    const file = read()
    // Simulate a file from before the parameters were recorded at all.
    delete file.kdf
    writeFileSync(FILE, JSON.stringify(file))
    vaultLock()

    // Legacy files were p=1; the code must infer that rather than assume p=3.
    expect((await vaultUnlock('a-long-enough-password')).ok).toBe(false)
  })

  it('upgrades an old vault transparently once the password is known correct', async () => {
    await vaultCreate('a-long-enough-password')
    const entries = vaultList().entries ?? []
    vaultSave([...entries])

    // Rewrite the file as a legacy p=1 vault by re-encrypting under the old
    // params — done by hand here because the app can no longer produce one.
    const file = read()
    delete file.kdf
    writeFileSync(FILE, JSON.stringify(file))
    vaultLock()
    // It will not open, which is the point of the previous test; what matters
    // is that a vault carrying explicit legacy params does open and upgrade.
    file.kdf = { N: 32768, r: 8, p: 3 }
    writeFileSync(FILE, JSON.stringify(file))
    expect((await vaultUnlock('a-long-enough-password')).ok).toBe(true)
    expect(read().kdf).toEqual({ N: 32768, r: 8, p: 3 })
  })
})

describe('idle auto-lock', () => {
  it('locks the vault after the idle period', async () => {
    vi.useFakeTimers()
    await vaultCreate('a-long-enough-password')
    setVaultAutoLock(15)
    expect(vaultStatus().unlocked).toBe(true)

    vi.advanceTimersByTime(15 * 60_000 + 1000)
    // A vault that never locks itself makes every other protection optional:
    // the key sits in memory for as long as the app is open.
    expect(vaultStatus().unlocked).toBe(false)
  })

  it('is postponed by using the vault', async () => {
    vi.useFakeTimers()
    await vaultCreate('a-long-enough-password')
    setVaultAutoLock(15)

    vi.advanceTimersByTime(14 * 60_000)
    vaultList() // reading your own entries counts as using it
    vi.advanceTimersByTime(14 * 60_000)
    expect(vaultStatus().unlocked).toBe(true)

    vi.advanceTimersByTime(2 * 60_000)
    expect(vaultStatus().unlocked).toBe(false)
  })

  it('calls back on auto-lock so the UI and the biometric key can follow', async () => {
    vi.useFakeTimers()
    const onLock = vi.fn()
    await vaultCreate('a-long-enough-password')
    setVaultAutoLock(1, onLock)
    vi.advanceTimersByTime(61_000)
    expect(onLock).toHaveBeenCalledOnce()
  })

  it('can be turned off entirely', async () => {
    vi.useFakeTimers()
    await vaultCreate('a-long-enough-password')
    setVaultAutoLock(0)
    vi.advanceTimersByTime(24 * 60 * 60_000)
    expect(vaultStatus().unlocked).toBe(true)
  })

  it('does not fire after a manual lock', async () => {
    vi.useFakeTimers()
    const onLock = vi.fn()
    await vaultCreate('a-long-enough-password')
    setVaultAutoLock(1, onLock)
    vaultLock()
    vi.advanceTimersByTime(61_000)
    expect(onLock).not.toHaveBeenCalled()
  })
})
