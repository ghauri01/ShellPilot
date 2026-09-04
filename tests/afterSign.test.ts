import { describe, it, expect, beforeEach, afterEach } from 'vitest'
import { createHash } from 'node:crypto'
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { createRequire } from 'node:module'

const require_ = createRequire(import.meta.url)
const { rehashManifest } = require_('../scripts/after-sign.cjs') as {
  rehashManifest: (binRoot: string) => string[]
}

const sha = (s: string): string => createHash('sha256').update(s).digest('hex')

describe('the manifest describes what actually shipped', () => {
  // Every macOS release shipped engines the app then refused to run: the build
  // scripts hashed each binary, electron-builder signed it — which rewrites the
  // file — and the recorded hash described bytes that no longer existed.
  let root: string

  beforeEach(() => {
    root = mkdtempSync(join(tmpdir(), 'sp-aftersign-'))
    mkdirSync(join(root, 'darwin-arm64'), { recursive: true })
  })
  afterEach(() => rmSync(root, { recursive: true, force: true }))

  // `version` too: `ManifestEntry` in src/main/services/vpn/binaries.ts carries
  // one, and the third test below reads it. Without it that read had no member
  // to resolve against.
  const manifest = (): Record<string, { sha256: string; size?: number; version?: string }> =>
    JSON.parse(readFileSync(join(root, 'manifest.json'), 'utf8')).binaries

  it('repoints an entry at the bytes on disk, and reports the change', () => {
    writeFileSync(join(root, 'darwin-arm64', 'shellpilot-netd'), 'SIGNED BYTES')
    writeFileSync(
      join(root, 'manifest.json'),
      JSON.stringify({
        version: 1,
        binaries: { 'darwin-arm64/shellpilot-netd': { sha256: sha('UNSIGNED'), size: 8, version: '1.2.3' } }
      })
    )
    const changed = rehashManifest(root)
    expect(changed).toHaveLength(1)
    expect(manifest()['darwin-arm64/shellpilot-netd'].sha256).toBe(sha('SIGNED BYTES'))
    // The size has to move with the hash: a signature changes both, and a stale
    // size is the next thing to be wrong about.
    expect(manifest()['darwin-arm64/shellpilot-netd'].size).toBe('SIGNED BYTES'.length)
  })

  it('keeps the version, which is not derivable from the bytes', () => {
    writeFileSync(join(root, 'darwin-arm64', 'frpc'), 'x')
    writeFileSync(
      join(root, 'manifest.json'),
      JSON.stringify({ version: 1, binaries: { 'darwin-arm64/frpc': { sha256: sha('old'), version: '0.71.0' } } })
    )
    rehashManifest(root)
    expect(manifest()['darwin-arm64/frpc'].version).toBe('0.71.0')
  })

  it('reports nothing when the manifest is already true', () => {
    writeFileSync(join(root, 'darwin-arm64', 'openvpn'), 'same')
    writeFileSync(
      join(root, 'manifest.json'),
      JSON.stringify({ version: 1, binaries: { 'darwin-arm64/openvpn': { sha256: sha('same') } } })
    )
    expect(rehashManifest(root)).toEqual([])
  })

  it('ignores files the manifest does not track', () => {
    // Licence notices sit beside the engines. Inventing entries for them would
    // make the app demand a hash for something it never execs.
    writeFileSync(join(root, 'darwin-arm64', 'NOTICE'), 'MIT')
    writeFileSync(join(root, 'manifest.json'), JSON.stringify({ version: 1, binaries: {} }))
    expect(rehashManifest(root)).toEqual([])
    expect(Object.keys(manifest())).toEqual([])
  })
})
