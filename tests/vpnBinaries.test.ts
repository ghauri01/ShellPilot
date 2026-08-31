import { describe, it, expect, beforeEach, afterEach } from 'vitest'
import {
  chmodSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  realpathSync,
  rmSync,
  symlinkSync,
  writeFileSync
} from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { createHash } from 'node:crypto'
import {
  resetBinaryCache,
  resolveBundled,
  resolveSystem,
  sha256File
} from '../src/main/services/vpn/binaries'
import { isVpnError } from '../src/main/services/vpn/errors'

const PLATFORM_DIR = `${process.platform}-${process.arch}`
const NETD = process.platform === 'win32' ? 'shellpilot-netd.exe' : 'shellpilot-netd'
const SHIM = '#!/bin/sh\necho "OpenVPN 2.6.99 fixture"\n'

let root: string
let binRoot: string
let previousBinDir: string | undefined
let previousPath: string | undefined
let platformDescriptor: PropertyDescriptor | undefined

function hash(text: string): string {
  return createHash('sha256').update(text).digest('hex')
}

function writeManifest(entries: Record<string, { sha256: string; size?: number }>): void {
  writeFileSync(join(binRoot, 'manifest.json'), JSON.stringify({ version: '0.1.0', binaries: entries }))
}

function stubPlatform(value: NodeJS.Platform): void {
  platformDescriptor ??= Object.getOwnPropertyDescriptor(process, 'platform')
  Object.defineProperty(process, 'platform', { value, configurable: true })
}

/** An executable that answers `--version`, so the resolver's version probe has
 *  something real to read rather than a mock of itself. */
function writeShim(dir: string, name: string): string {
  const file = join(dir, name)
  writeFileSync(file, SHIM)
  chmodSync(file, 0o755)
  return file
}

beforeEach(() => {
  root = mkdtempSync(join(tmpdir(), 'sp-bin-'))
  binRoot = join(root, 'bin')
  mkdirSync(join(binRoot, PLATFORM_DIR), { recursive: true })
  previousBinDir = process.env.SHELLPILOT_VPN_BIN_DIR
  previousPath = process.env.PATH
  process.env.SHELLPILOT_VPN_BIN_DIR = binRoot
  resetBinaryCache()
})

afterEach(() => {
  if (platformDescriptor) Object.defineProperty(process, 'platform', platformDescriptor)
  platformDescriptor = undefined
  if (previousBinDir === undefined) delete process.env.SHELLPILOT_VPN_BIN_DIR
  else process.env.SHELLPILOT_VPN_BIN_DIR = previousBinDir
  if (previousPath === undefined) delete process.env.PATH
  else process.env.PATH = previousPath
  resetBinaryCache()
  rmSync(root, { recursive: true, force: true })
})

describe('bundled binary integrity', () => {
  it('accepts a binary whose hash matches the manifest', async () => {
    const body = 'not really a sidecar, but it hashes just as well'
    const file = writeShim(join(binRoot, PLATFORM_DIR), NETD)
    writeFileSync(file, body)
    writeManifest({ [`${PLATFORM_DIR}/${NETD}`]: { sha256: hash(body), size: body.length } })

    const info = await resolveBundled('shellpilot-netd')
    expect(info.available).toBe(true)
    expect(info.bundled).toBe(true)
    expect(info.kind).toBe('wireguard')
    expect(info.path).toBe(file)
    expect(info.sha256).toBe(await sha256File(file))
  })

  it('refuses a binary whose bytes disagree with the manifest', async () => {
    const file = join(binRoot, PLATFORM_DIR, NETD)
    writeFileSync(file, 'the bytes we expected')
    writeManifest({ [`${PLATFORM_DIR}/${NETD}`]: { sha256: hash('the bytes we expected') } })
    // Tampered after the manifest was written, which is exactly the case the
    // per-run verification exists to catch (E42).
    writeFileSync(file, 'the bytes we got')

    await expect(resolveBundled('shellpilot-netd')).rejects.toMatchObject({
      code: 'binary-untrusted'
    })
  })

  it('reports a missing binary by path and mentions antivirus', async () => {
    writeManifest({ [`${PLATFORM_DIR}/${NETD}`]: { sha256: hash('anything') } })
    const err = await resolveBundled('shellpilot-netd').catch((e) => e)
    expect(isVpnError(err) && err.code).toBe('binary-missing')
    expect(err.detail).toContain(join(binRoot, PLATFORM_DIR, NETD))
    expect(err.detail).toContain('antivirus')
  })

  it('treats a zero-length file as missing, not as a hash mismatch', async () => {
    // Quarantine leaves an empty stub behind; calling that "untrusted" would
    // point the user at the wrong fix.
    writeFileSync(join(binRoot, PLATFORM_DIR, NETD), '')
    writeManifest({ [`${PLATFORM_DIR}/${NETD}`]: { sha256: hash('') } })

    await expect(resolveBundled('shellpilot-netd')).rejects.toMatchObject({
      code: 'binary-missing'
    })
  })

  it('treats an unlisted binary as missing, not as tampered', async () => {
    // A dev checkout before the sidecar has been built: an absence, and
    // calling it a tamper would train people to ignore the word.
    writeFileSync(join(binRoot, PLATFORM_DIR, NETD), 'built, but never recorded')
    writeManifest({})

    const err = await resolveBundled('shellpilot-netd').catch((e) => e)
    expect(isVpnError(err) && err.code).toBe('binary-missing')
    expect(err.detail).toContain('build-sidecar')
  })

  it('verifies once per app run rather than once per spawn', async () => {
    const body = 'stable bytes'
    const file = join(binRoot, PLATFORM_DIR, NETD)
    writeFileSync(file, body)
    writeManifest({ [`${PLATFORM_DIR}/${NETD}`]: { sha256: hash(body) } })

    const first = await resolveBundled('shellpilot-netd')
    rmSync(file)
    // Still cached: the check is a per-run gate before first exec, not a
    // filesystem watch.
    expect((await resolveBundled('shellpilot-netd')).sha256).toBe(first.sha256)
  })
})

describe('system binary resolution', () => {
  it('accepts a confirmed absolute path and reports its hash and version', async () => {
    const dir = join(root, 'sbin')
    mkdirSync(dir, { mode: 0o755 })
    const file = writeShim(dir, 'openvpn')

    const info = await resolveSystem('openvpn', { binaryPath: file, confirmed: true })
    expect(info.available).toBe(true)
    expect(info.bundled).toBe(false)
    // The real path, not the one that was typed: the symlink is not what runs.
    expect(info.path).toBe(realpathSync(file))
    expect(info.sha256).toBe(await sha256File(file))
    expect(info.version).toContain('OpenVPN 2.6.99')
  })

  it('ignores an override the user never confirmed', async () => {
    const dir = join(root, 'sbin2')
    mkdirSync(dir, { mode: 0o755 })
    const file = writeShim(dir, 'openvpn')

    const err = await resolveSystem('openvpn', { binaryPath: file }).catch((e) => e)
    expect(isVpnError(err) && err.code).toBe('config-invalid')
    expect(err.detail).toContain('not been confirmed')
  })

  it('refuses a relative path', async () => {
    const err = await resolveSystem('openvpn', {
      binaryPath: 'bin/openvpn',
      confirmed: true
    }).catch((e) => e)
    expect(isVpnError(err) && err.code).toBe('config-invalid')
    expect(err.detail).toContain('relative path')
  })

  it('refuses a binary sitting in a world-writable directory', async () => {
    const dir = join(root, 'open')
    mkdirSync(dir)
    chmodSync(dir, 0o777)
    const file = writeShim(dir, 'openvpn')

    const err = await resolveSystem('openvpn', { binaryPath: file, confirmed: true }).catch((e) => e)
    expect(isVpnError(err) && err.code).toBe('config-invalid')
    expect(err.detail).toContain('world-writable')
  })

  it('refuses a symlink that leaves the directory it was found in', async () => {
    const visible = join(root, 'visible')
    const elsewhere = join(root, 'elsewhere')
    mkdirSync(visible, { mode: 0o755 })
    mkdirSync(elsewhere, { mode: 0o755 })
    const real = writeShim(elsewhere, 'real-openvpn')
    const link = join(visible, 'openvpn')
    symlinkSync(real, link)

    const err = await resolveSystem('openvpn', { binaryPath: link, confirmed: true }).catch((e) => e)
    expect(isVpnError(err) && err.code).toBe('config-invalid')
    expect(err.detail).toContain('outside')
  })

  it('never searches PATH on Windows', async () => {
    const dir = join(root, 'hijack')
    mkdirSync(dir, { mode: 0o755 })
    // The textbook hijack: a writable directory early on PATH holding
    // something named like the real thing (E44).
    writeShim(dir, 'openvpn.exe')
    writeShim(dir, 'openvpn')
    process.env.PATH = dir
    stubPlatform('win32')

    const err = await resolveSystem('openvpn', {}).catch((e) => e)
    expect(isVpnError(err) && err.code).toBe('binary-missing')
    expect(err.detail).toContain('does not search PATH on Windows')
    expect(err.detail).not.toContain(dir)
  })

  it.skipIf(
    ['/usr/sbin/openvpn', '/usr/local/sbin/openvpn', '/opt/homebrew/sbin/openvpn', '/usr/bin/openvpn'].some(
      (p) => existsSync(p)
    )
  )('falls back to PATH on POSIX once the fixed locations come up empty', async () => {
    const dir = join(root, 'pathdir')
    mkdirSync(dir, { mode: 0o755 })
    const file = writeShim(dir, 'openvpn')
    process.env.PATH = dir

    const info = await resolveSystem('openvpn', {})
    expect(info.path).toBe(realpathSync(file))
    expect(info.bundled).toBe(false)
  })
})
