import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { join, resolve } from 'node:path'

// The properties of this feature that are true because of how it is WIRED,
// not because of what any function returns. Each one is checkable by reading,
// which is the only reason it stays true through the next edit.

const ROOT = resolve(__dirname, '..')
const read = (p: string): string => readFileSync(join(ROOT, p), 'utf8')

const main = read('src/main/index.ts')
const preload = read('src/preload/index.ts')
const service = read('src/main/services/credProxy.ts')
const shared = read('src/shared/credproxy.ts')

describe('one listener, constructed in one place', () => {
  it('is built exactly once, in main', () => {
    // The same rule the job runner has, for the same reason: a second
    // construction site would be a second listener with its own idea of which
    // credential may go where, and "read main/index.ts to see the whole model"
    // is the property that makes this reviewable at all.
    expect(main.match(/new CredProxy\(/g) ?? []).toHaveLength(1)
  })

  it('is not constructed anywhere in the renderer', () => {
    expect(preload).not.toContain('new CredProxy')
  })
})

describe('the channels main serves and the channels preload calls are the same set', () => {
  // Written out rather than derived from each other. Two hand-written lists
  // compared against one literal is the only version of this that catches a
  // channel added on one side and forgotten on the other.
  const CHANNELS = [
    'credproxy:calls',
    'credproxy:remove-rule',
    'credproxy:rotate-token',
    'credproxy:rules',
    'credproxy:save-rule',
    'credproxy:start',
    'credproxy:status',
    'credproxy:stop',
    'credproxy:token'
  ]

  it('main handles exactly these', () => {
    const handled = [...main.matchAll(/ipcMain\.handle\('(credproxy:[a-z-]+)'/g)]
      .map((m) => m[1])
      .sort()
    expect(handled).toEqual(CHANNELS)
  })

  it('preload invokes exactly these', () => {
    const invoked = [...preload.matchAll(/ipcRenderer\.invoke\('(credproxy:[a-z-]+)'/g)]
      .map((m) => m[1])
      .sort()
    expect(invoked).toEqual(CHANNELS)
  })
})

describe('the design decision is visible in the code, not only in the roadmap', () => {
  // "Recommend the rewrite. A tool whose pitch is 'your secrets never leave'
  // should not ship a CA into the user's trust store." Nothing here terminates
  // anyone else's TLS, so nothing here needs a certificate authority — and the
  // cheapest way to keep that true is for the words never to appear.
  it('ships no certificate authority and terminates no TLS it was not given', () => {
    for (const forbidden of [
      'createCertificate',
      'https.createServer',
      'createSecureServer',
      'rejectUnauthorized',
      'NODE_TLS_REJECT_UNAUTHORIZED',
      'addTrustedCert',
      'security add-trusted-cert'
    ]) {
      expect(service, forbidden).not.toContain(forbidden)
      expect(shared, forbidden).not.toContain(forbidden)
    }
  })

  it('binds loopback, once, and names no other interface', () => {
    expect(service).toContain("server.listen(this.file.port, '127.0.0.1'")
    // One bind. A second would be a second interface by definition.
    expect(service.match(/\.listen\(/g) ?? []).toHaveLength(1)
    // The wildcard addresses, in every form someone would type them — as a
    // bind host, or as the omitted-host default that means the same thing.
    expect(service).not.toContain('0.0.0.0')
    expect(service).not.toContain("'::'")
    expect(service).not.toContain('listen(this.file.port)')
  })

  it('never follows a redirect', () => {
    expect(service).toContain("redirect: 'manual'")
    expect(service).not.toContain("redirect: 'follow'")
  })
})

describe('what crosses the bridge, and what does not', () => {
  it('exposes the client token deliberately, because the user pastes it', () => {
    expect(preload).toContain("ipcRenderer.invoke('credproxy:token')")
  })

  // A rule carries a vault entry ID. The value behind it is read in main at
  // request time and put on the wire; there is no channel that hands it back.
  it('has no channel that returns a resolved API credential', () => {
    for (const forbidden of [
      'credproxy:reveal',
      'credproxy:credential',
      'credproxy:secret',
      'resolveVaultField',
      'resolveCredential'
    ]) {
      expect(preload, forbidden).not.toContain(forbidden)
    }
  })

  it('resolves the credential through credentialResolver, in main, at request time', () => {
    expect(main).toContain('resolveVaultField')
    expect(main).toContain("from './services/credentialResolver'")
  })

  // The two failures are different states with different fixes, and a proxy
  // that collapsed them would tell someone to check a vault entry that is
  // fine, or to unlock a vault that already is.
  it('maps a locked vault and an empty entry onto different reasons', () => {
    expect(main).toContain("reason: 'vault-locked'")
    expect(main).toContain("reason: 'credential-missing'")
    expect(main).toContain('isVaultLockedError')
  })
})

describe('the service holds no key material of its own', () => {
  // The RuleEngine discipline: this is the one module in the app that talks to
  // third-party hosts, so the OS keychain and the vault master key must not be
  // inside its reach. Everything arrives through deps.
  it('imports neither the vault nor the keychain', () => {
    for (const forbidden of [
      "from './vault'",
      "from './secrets'",
      "from 'electron'",
      'safeStorage',
      'vaultList',
      'vaultStatus'
    ]) {
      expect(service, forbidden).not.toContain(forbidden)
    }
  })
})
