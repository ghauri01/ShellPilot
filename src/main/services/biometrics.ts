import { app, safeStorage, systemPreferences } from 'electron'
import { join } from 'node:path'
import { existsSync, readFileSync, writeFileSync, unlinkSync } from 'node:fs'
import { vaultExportKey, vaultUnlockWithKey, vaultStatus } from './vault'
import type { VaultResult } from '../../shared/vault'

// Biometric unlock for the vault.
//
// What this is, stated plainly, because the difference matters. Touch ID here
// is a GATE, not a key: Electron's promptTouchID authenticates the person at
// the keyboard, it does not hand back a Secure Enclave key bound to that
// authentication. So enabling this stores the vault's derived key on disk,
// encrypted with safeStorage — the OS keychain on macOS, DPAPI on Windows,
// libsecret on Linux — and puts a biometric prompt in front of reading it.
//
// The trade that buys: the vault opens with a fingerprint instead of a
// master password. The trade that costs: the key is now recoverable by
// anything able to read this file AND call safeStorage as this OS user, where
// before it existed only in memory and only after someone typed the password.
// That is a real reduction, which is why this is opt-in, off by default, and
// says so where it is switched on.
//
// The master password is never stored — only the derived key, so the password
// itself cannot be recovered from this file even by someone who defeats both.

const FILE = join(app.getPath('userData'), 'shellpilot-vault-bio.json')

// The session-scoped store: the wrapped key lives here, in main-process memory,
// and dies with the process. This is KeePassXC's model, and it is the reason
// this feature can be defended at all — an attacker who can read your files
// gets nothing, because there is nothing on disk to read. Touch ID reopens the
// vault while ShellPilot is running; the master password is typed once per
// launch.
//
// The on-disk variant below survives a restart and is the weaker thing. It is a
// separate, explicit opt-in rather than the default.
let sessionKey: StoredKey | null = null

export type BiometricKind = 'touch-id' | 'windows-hello' | 'none'

export interface BiometricSupport {
  available: boolean
  kind: BiometricKind
  // Why it is unavailable, for the UI to show instead of an inert switch.
  reason?: string
}

interface StoredKey {
  version: 1
  kind: BiometricKind
  key: string
  salt: string
}

export function biometricSupport(): BiometricSupport {
  if (!safeStorage.isEncryptionAvailable()) {
    return { available: false, kind: 'none', reason: 'This system has no secure storage available.' }
  }
  if (process.platform === 'darwin') {
    // canPromptTouchID is false on a Mac with no Touch Bar/sensor, and on one
    // where the user has not enrolled a fingerprint.
    return systemPreferences.canPromptTouchID()
      ? { available: true, kind: 'touch-id' }
      : { available: false, kind: 'none', reason: 'No enrolled Touch ID fingerprint on this Mac.' }
  }
  if (process.platform === 'win32') {
    // Electron exposes promptTouchID for macOS and nothing equivalent for
    // Windows Hello — reaching Windows.Security.Credentials.UI needs a native
    // addon, and there is no maintained npm package that provides one for
    // Electron. Writing and shipping an unverifiable native module into the
    // path that guards a credential store is a worse outcome than not offering
    // the feature, so this reports honestly instead.
    //
    // Everything except the prompt is already platform-agnostic: safeStorage
    // is DPAPI here, and biometricUnlock() only needs a provider that can
    // authenticate the person. Adding one is a self-contained change to this
    // function.
    return {
      available: false,
      kind: 'none',
      reason:
        'Windows Hello needs a native module that Electron does not provide, so vault unlock is by ' +
        'master password on Windows for now.'
    }
  }
  return {
    available: false,
    kind: 'none',
    reason: 'Biometric unlock is not available on this platform; unlock with your master password.'
  }
}

function read(): StoredKey | null {
  try {
    if (!existsSync(FILE)) return null
    return JSON.parse(readFileSync(FILE, 'utf8')) as StoredKey
  } catch {
    return null
  }
}

export type BiometricScope = 'session' | 'persistent'

export function biometricEnabled(): boolean {
  return sessionKey !== null || read() !== null
}

// Which of the two a vault is currently set up for, so the UI can say so rather
// than showing one switch for two materially different things.
export function biometricScope(): BiometricScope | null {
  if (sessionKey) return 'session'
  return read() ? 'persistent' : null
}

export function disableBiometricUnlock(): VaultResult {
  sessionKey = null
  try {
    if (existsSync(FILE)) unlinkSync(FILE)
    return { ok: true }
  } catch (err) {
    return { ok: false, error: (err as Error).message }
  }
}

// Locking the vault must also drop a session-scoped key, or "lock" would be a
// lie: the whole point is that it does not outlive the unlocked state by more
// than the app's own lifetime.
export function forgetSessionKey(): void {
  sessionKey = null
}

// Requires the vault to be unlocked already, because the key being stored is
// the one currently in memory. There is no path here that turns a biometric
// into access the caller did not already have.
export function enableBiometricUnlock(scope: BiometricScope = 'session'): VaultResult {
  const support = biometricSupport()
  if (!support.available) return { ok: false, error: support.reason ?? 'Biometric unlock is unavailable.' }
  if (!vaultStatus().unlocked) return { ok: false, error: 'Unlock the vault first.' }

  const exported = vaultExportKey()
  if (!exported) return { ok: false, error: 'Unlock the vault first.' }

  try {
    const payload: StoredKey = {
      version: 1,
      kind: support.kind,
      key: safeStorage.encryptString(exported.key.toString('base64')).toString('base64'),
      salt: exported.salt.toString('base64')
    }
    if (scope === 'session') {
      sessionKey = payload
      // Any previous on-disk key is stale the moment a session key exists, and
      // leaving it behind would mean "session only" still had a file.
      if (existsSync(FILE)) unlinkSync(FILE)
    } else {
      writeFileSync(FILE, JSON.stringify(payload), { mode: 0o600 })
      // And the mirror of the line above. `biometricScope()` reads the session
      // key first, so leaving one in memory here would write the file, return
      // ok, and still report `session` -- the user turns on "remember across
      // restarts", sees the switch stay where it was, and concludes the feature
      // is broken. The two scopes are exclusive, and each enable says so.
      sessionKey = null
    }
    return { ok: true }
  } catch (err) {
    return { ok: false, error: `Could not store the key: ${(err as Error).message}` }
  }
}

// Fails closed on any kind it has no prompt for.
//
// This was written inline as `if (kind === 'touch-id') await prompt(...)`, which
// authenticated conditionally and then decrypted unconditionally — so adding a
// windows-hello branch to biometricSupport() without also touching the unlock
// path would have shipped a vault that opens with no prompt at all. Separated
// out so the gate is a single expression that either authenticates or throws,
// and so a test can prove it refuses an unknown kind.
export async function authenticateFor(kind: BiometricKind, reason: string): Promise<void> {
  switch (kind) {
    case 'touch-id':
      await systemPreferences.promptTouchID(reason)
      return
    default:
      throw new Error(`No way to authenticate for "${kind}" on this platform.`)
  }
}

export async function biometricUnlock(reason = 'unlock your ShellPilot vault'): Promise<VaultResult> {
  const stored = sessionKey ?? read()
  if (!stored) return { ok: false, error: 'Biometric unlock is not set up for this vault.' }
  const support = biometricSupport()
  if (!support.available) return { ok: false, error: support.reason ?? 'Biometric unlock is unavailable.' }

  try {
    await authenticateFor(support.kind, reason)
  } catch (err) {
    // A cancelled prompt is not a failure worth alarming about; the caller
    // falls back to the password field either way.
    return { ok: false, error: (err as Error).message || 'Biometric authentication was cancelled.' }
  }

  try {
    const key = Buffer.from(safeStorage.decryptString(Buffer.from(stored.key, 'base64')), 'base64')
    const result = vaultUnlockWithKey(key, Buffer.from(stored.salt, 'base64'))
    // A key that no longer opens the vault — the master password was changed,
    // or the file was replaced — is dead weight that would fail every time.
    if (!result.ok) disableBiometricUnlock()
    return result
  } catch (err) {
    return { ok: false, error: `Could not read the stored key: ${(err as Error).message}` }
  }
}
