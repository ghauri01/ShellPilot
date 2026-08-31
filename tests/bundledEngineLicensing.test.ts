import { describe, expect, it } from 'vitest'
import { readFileSync } from 'node:fs'
import { load } from 'js-yaml'

// Licence compliance is the one part of the build that has no runtime symptom.
//
// A binary that will not start fails loudly on the first connect. A GPL-2.0
// binary shipped without its corresponding source, or a proprietary DLL shipped
// without its licence text, runs perfectly and is discovered by somebody else.
// So the obligations are asserted here, against the scripts and the notices
// that carry them, where breaking one fails a pull request.
//
// These are checks on our own files, not on upstream. Nothing here downloads
// anything or needs the engines to have been built.

const openvpnScript = readFileSync('scripts/build-openvpn.sh', 'utf8')
const wintunScript = readFileSync('scripts/fetch-wintun.sh', 'utf8')
const notices = readFileSync('THIRD-PARTY-NOTICES.md', 'utf8')

describe('the OpenVPN build is pinned to something specific', () => {
  it('pins a tag and the commit that tag must resolve to', () => {
    // A tag alone is a mutable pointer. Re-pointing it at a different commit
    // would change what we ship and what we publish as "the source", with no
    // diff in this repository at all.
    expect(openvpnScript).toMatch(/OPENVPN_TAG="\$\{OPENVPN_TAG:-v\d+\.\d+\.\d+\}"/)
    expect(openvpnScript).toMatch(/OPENVPN_EXPECT_COMMIT="\$\{OPENVPN_EXPECT_COMMIT:-[0-9a-f]{40}\}"/)
    // And it must actually compare them, not merely record both.
    expect(openvpnScript).toContain('Refusing to build.')
  })

  it('pins OpenSSL by tarball hash, not by URL', () => {
    // HTTPS authenticates the host and says nothing about the bytes.
    expect(openvpnScript).toMatch(/OPENSSL_SHA256="\$\{OPENSSL_SHA256:-[0-9a-f]{64}\}"/)
    expect(openvpnScript).toContain('verifying openssl tarball')
  })

  it('writes the corresponding source from the commit it built', () => {
    // GPL-2.0 §3. `git archive` of the verified commit, so the archive cannot
    // drift from the binary even if the working tree does.
    expect(openvpnScript).toContain('git -C "$SRC" archive')
    expect(openvpnScript).toContain('$SRC_SHA')
  })

  it('ships the licence and the OpenSSL exception with the binary', () => {
    // GPL-2.0 §1 wants the licence. COPYRIGHT.GPL carries the linking
    // exception, which is the clause that makes the static OpenSSL link
    // lawful — shipping only COPYING would drop the half that matters here.
    expect(openvpnScript).toContain('COPYING')
    expect(openvpnScript).toContain('COPYRIGHT.GPL')
  })
})

describe('Wintun is redistributed on the terms it allows', () => {
  it('pins the published ZIP by SHA-256 and verifies it every run', () => {
    expect(wintunScript).toMatch(/WINTUN_SHA256="\$\{WINTUN_SHA256:-[0-9a-f]{64}\}"/)
    expect(wintunScript).toContain('verifying wintun zip')
  })

  it('copies the DLL out unmodified', () => {
    // Clause 3(a) forbids modifying or extracting from the Software, so the
    // only permitted operation is a copy. No strip, no re-sign, no repack.
    expect(wintunScript).toMatch(/cp "\$src" "\$OUT_ROOT\/\$nodedir\/wintun\.dll"/)
    // Comments stripped first: the script says in prose that it does not strip
    // or sign, and matching its own explanation would be a self-defeating
    // assertion.
    const code = wintunScript
      .split('\n')
      .filter((l) => !l.trim().startsWith('#'))
      .join('\n')
    expect(code).not.toMatch(/\bstrip\b|\bcodesign\b|signtool/)
  })

  it('ships its licence text', () => {
    // Clause 3(c): its proprietary notices must travel with it.
    expect(wintunScript).toContain('LICENSE.txt')
    expect(wintunScript).toContain('resources/licenses/wintun')
  })
})

describe('the notices say what actually ships', () => {
  it('states plainly that a proprietary component is included', () => {
    // ShellPilot is presented as open source. The single exception has to be
    // findable by someone skimming, not buried in a table cell.
    expect(notices).toMatch(/not open source/i)
    expect(notices).toMatch(/wintun\.dll` is proprietary|Wintun is bundled on Windows/i)
  })

  it('does not still claim OpenVPN is unbundled', () => {
    // The old text was a whole section arguing why it was not shipped. Leaving
    // any of it behind would make the file contradict the installer.
    expect(notices).not.toContain('OpenVPN is deliberately **not** bundled')
    expect(notices).not.toContain('Wintun is not bundled either')
  })

  it('points at the published source rather than offering to supply it', () => {
    // §3 is satisfied by the archive being on the release page. An offer
    // nobody can act on is not compliance.
    expect(notices).toContain('openvpn-<version>-source.tar.gz')
    expect(notices).toMatch(/GPL-2\.0 §3/)
  })

  it('does not let the npm licence summary read as a claim about the installer', () => {
    // "No GPL, AGPL, LGPL, SSPL, or proprietary-licensed dependencies" is true
    // of the npm tree and false of the installer, and the two sit close enough
    // together to be read as one statement.
    const summary = notices.slice(notices.indexOf('License summary:'))
    expect(summary.slice(0, 800)).toContain('npm tree only')
  })
})

describe('the licence texts reach the installed app', () => {
  const builder = load(readFileSync('electron-builder.yml', 'utf8')) as {
    files?: string[]
    extraResources?: { from: string; to: string; filter?: string[] }[]
  }

  it('includes resources/licenses in the package', () => {
    // `resources/**` carries them; `!resources/bin/**` deliberately does not
    // exclude them. If someone ever narrows that glob, the licence files stop
    // shipping and nothing else changes.
    expect(builder.files).toContain('resources/**')
    const excludes = (builder.files ?? []).filter((f) => f.startsWith('!'))
    expect(excludes.every((f) => !f.includes('licenses'))).toBe(true)
  })

  it('copies the whole per-platform bin directory, not a list of executables', () => {
    // wintun.dll is a library rather than a program, and it only works if it
    // lands beside shellpilot-netd.exe. A filter that named executables would
    // silently leave it out.
    const bin = (builder.extraResources ?? []).find((r) => r.from.includes('resources/bin/$'))
    expect(bin?.filter).toEqual(['**/*'])
  })
})
