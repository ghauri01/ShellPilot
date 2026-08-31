import { describe, expect, it } from 'vitest'
import { readFileSync } from 'node:fs'
import { isEngineBundledOn, userSuppliesEngine } from '../src/shared/vpnEngines'

// The predicate that decides, in two processes at once, whether an engine is
// ours to ship or the user's to install.
//
// It earns its own test file because it is the only thing keeping the main
// process and the renderer in agreement. `binaries.ts` asks it whether to look
// for a bundled binary; three pieces of UI copy ask it whether to offer a
// download link. Those used to be separate `platform === 'win32'` checks, and
// the failure mode when they drifted was not a crash — it was ShellPilot
// telling a macOS user to go and install an OpenVPN that was already on their
// disk, hash-verified, a directory away.

const EVERY_PLATFORM: NodeJS.Platform[] = ['darwin', 'linux', 'win32']

describe('isEngineBundledOn', () => {
  it('ships OpenVPN on macOS and Linux but not Windows', () => {
    // Not a licence boundary — the GPL permits bundling everywhere. OpenVPN on
    // Windows opens a tun adapter that already exists and cannot create one,
    // so a bundled openvpn.exe would abort on a clean machine.
    expect(isEngineBundledOn('openvpn', 'darwin')).toBe(true)
    expect(isEngineBundledOn('openvpn', 'linux')).toBe(true)
    expect(isEngineBundledOn('openvpn', 'win32')).toBe(false)
  })

  it('treats a .exe name as the same engine', () => {
    // `binaries.ts` reaches this with whatever name the caller used, and on
    // Windows that is `openvpn.exe`. Without the suffix strip the map lookup
    // misses, the engine reads as bundled-everywhere, and Windows silently
    // goes looking for a binary that is never built.
    for (const platform of EVERY_PLATFORM) {
      expect(isEngineBundledOn('openvpn.exe', platform)).toBe(
        isEngineBundledOn('openvpn', platform)
      )
    }
  })

  it('ships the engines that are not in the map on every platform', () => {
    // Absence from the map means "everywhere". Getting this backwards would
    // make a quarantined sidecar look like something the user should download
    // from the WireGuard project, which is the wrong project entirely.
    for (const platform of EVERY_PLATFORM) {
      expect(isEngineBundledOn('shellpilot-netd', platform)).toBe(true)
      expect(isEngineBundledOn('frpc', platform)).toBe(true)
      expect(isEngineBundledOn('shellpilot-netd.exe', platform)).toBe(true)
      expect(isEngineBundledOn('frpc.exe', platform)).toBe(true)
    }
  })
})

describe('userSuppliesEngine', () => {
  it('is true only where we ship nothing', () => {
    expect(userSuppliesEngine('openvpn', 'win32')).toBe(true)
    expect(userSuppliesEngine('openvpn.exe', 'win32')).toBe(true)
    expect(userSuppliesEngine('openvpn', 'darwin')).toBe(false)
    expect(userSuppliesEngine('openvpn', 'linux')).toBe(false)
  })

  it('is never true for an engine that always ships', () => {
    for (const platform of EVERY_PLATFORM) {
      expect(userSuppliesEngine('shellpilot-netd', platform)).toBe(false)
      expect(userSuppliesEngine('frpc', platform)).toBe(false)
    }
  })

  it('answers "not the user\'s" while the platform is still unknown', () => {
    // The renderer learns its platform over an IPC round trip, so `null` is a
    // real state that lasts a frame or two on every launch. The asymmetry is
    // the whole point of the null rule: withholding an Install button for one
    // frame is recoverable, while telling someone to install software they
    // already have is not. A truthy default here would flash that advice at
    // every macOS and Linux user on startup.
    expect(userSuppliesEngine('openvpn', null)).toBe(false)
    expect(userSuppliesEngine('openvpn.exe', null)).toBe(false)
    expect(userSuppliesEngine('shellpilot-netd', null)).toBe(false)
  })

  it('is exactly the negation of isEngineBundledOn once the platform is known', () => {
    // The two are used by different processes for different decisions, and
    // they must not be able to disagree — a UI that offers a download for an
    // engine the resolver is about to find is the bug this module exists to
    // prevent.
    for (const platform of EVERY_PLATFORM) {
      for (const name of ['openvpn', 'openvpn.exe', 'shellpilot-netd', 'frpc']) {
        expect(userSuppliesEngine(name, platform)).toBe(!isEngineBundledOn(name, platform))
      }
    }
  })
})

describe('the module stays loadable from the renderer', () => {
  it('imports nothing', () => {
    // This is the property that let the predicate move out of `binaries.ts` in
    // the first place: that file imports `electron`, so the renderer cannot
    // load it. An import added here — `electron`, `node:os`, anything that
    // reaches for `process` — breaks the renderer bundle rather than failing a
    // type check, so it is asserted on the source text where it is cheap to
    // catch. Keep this module dependency-free; put anything that needs a
    // runtime somewhere else.
    const source = readFileSync('src/shared/vpnEngines.ts', 'utf8')
    // Comments are stripped first, so the module's own prose about importing
    // nothing cannot trip its own guard.
    const code = source.split('\n').filter((line) => {
      const t = line.trim()
      return !t.startsWith('//') && !t.startsWith('*') && !t.startsWith('/*')
    })
    // Three forms, because all three reach a module at runtime and all three
    // break the renderer bundle: a static `import`, a dynamic `import(...)`,
    // and a `require(...)`. Checking only the first would leave the guard blind
    // to the exact thing it exists to catch.
    //
    // `import type` is exempt, and that is not a hole — type imports are
    // erased before a bundler ever sees them, so they cannot break anything.
    const offenders = code.filter(
      (line) =>
        (/^\s*import\b/.test(line) && !/^\s*import type\b/.test(line)) ||
        /\brequire\s*\(|\bimport\s*\(/.test(line)
    )
    expect(offenders, `vpnEngines.ts must import nothing:\n${offenders.join('\n')}`).toEqual([])
  })
})
