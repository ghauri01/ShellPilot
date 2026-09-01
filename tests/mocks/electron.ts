// Minimal stand-in for the `electron` module so the main-process services
// under test can run outside a real Electron process. userData resolves to a
// fresh temp directory per test file, the same way portable.ts redirects it
// to a folder beside the executable — the services under test never know the
// difference, which is exactly the property portable mode relies on.
import { mkdtempSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

const userDataDir = mkdtempSync(join(tmpdir(), 'shellpilot-test-'))

export const app = {
  getPath: (_name: string): string => userDataDir,
  // clientConfig.ts derives the bridge script path from this; outside a
  // packaged build it is the project root, exactly as in `electron-vite dev`.
  getAppPath: (): string => process.cwd(),
  // Two consumers, neither of which asserts on the value: the updater reports
  // the running version, and shellDiscovery.ts stamps it into
  // TERM_PROGRAM_VERSION for every local shell. Any well-formed semver does.
  //
  // It is deliberately a literal and not package.json's version, so a release
  // bump never has to touch a test. That does mean it drifts from the real
  // version — it already has — which is harmless precisely because nothing
  // compares the two.
  getVersion: (): string => '0.6.2',
  isPackaged: false
}

// The updater opens the releases page here when a platform cannot self-install.
export const shell = {
  openExternal: async (_url: string): Promise<void> => undefined
}

// A no-op "encryption" so secrets.ts can be exercised without a real OS
// keychain. Good enough for tests that only check the shape of the flow.
export const safeStorage = {
  isEncryptionAvailable: (): boolean => true,
  encryptString: (s: string): Buffer => Buffer.from(s, 'utf8'),
  decryptString: (b: Buffer): string => b.toString('utf8')
}

export const dialog = {
  showMessageBox: async () => ({ response: 1 })
}

// backup.ts references this at module scope (only called from
// export/inspect, neither of which the backup tests exercise), so it just
// needs to exist, not do anything.
export const BrowserWindow = {
  getFocusedWindow: () => null,
  getAllWindows: () => []
}
