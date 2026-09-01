import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { load } from 'js-yaml'
// The same matcher electron-builder uses, so a pattern that passes here is a
// pattern that behaves the same way during a real pack.
import { minimatch } from 'minimatch'

// Packaging is the part of the local terminal that CI cannot otherwise check:
// nothing on a pull request runs electron-builder to completion, and the one
// thing that would prove the layout is right — launching the packed app and
// opening a shell — is not something any runner here does. What a plain YAML
// parse *can* assert is the shape the runtime depends on, which is where every
// packaging bug in this feature lives:
//
//   * @lydell/node-pty resolves its binding out of a SIBLING package
//     (@lydell/node-pty-darwin-arm64 and friends) with a computed require, so
//     unpacking only the meta package leaves the real pty.node in the archive.
//   * That sibling also ships `spawn-helper`, an executable that is
//     posix_spawn'd, not dlopen'd — it needs a real path on disk and its +x bit.
//   * The siblings declare "os"/"cpu", so one `npm ci` installs exactly one of
//     them, while electron-builder packs one node_modules into BOTH macOS
//     bundles. Nothing about that is visible in a --dir pack of the host arch.
//
// Interface note: `hardenedRuntime` is deliberately NOT asserted here. It
// already is, at tests/releaseWorkflow.test.ts:143-147, and a second copy is a
// second thing to update.

interface Builder {
  files: string[]
  asarUnpack: string[]
  includePdb?: boolean
  mac: { extendInfo?: Record<string, string>; target?: Array<{ target: string; arch?: string[] }> }
}
interface Step {
  uses?: string
  run?: string
  name?: string
  if?: string
  env?: Record<string, unknown>
  with?: Record<string, unknown>
}
interface Job {
  'runs-on'?: string
  strategy?: { matrix?: Record<string, unknown> }
  env?: Record<string, unknown>
  steps?: Step[]
}
interface Workflow {
  jobs: Record<string, Job>
}

const cfg = load(readFileSync('electron-builder.yml', 'utf8')) as Builder
const ci = load(readFileSync('.github/workflows/ci.yml', 'utf8')) as Workflow
const release = load(readFileSync('.github/workflows/release.yml', 'utf8')) as Workflow
const steps = (j: Job | undefined): Step[] => j?.steps ?? []

describe('node-pty is unpacked as a whole package directory', () => {
  it('names the package dir, never a *.node glob', () => {
    // node-pty ships `spawn-helper`, a Mach-O/ELF EXECUTABLE that is
    // fork/exec'd on every spawn (lib/unixTerminal.js:31-34 builds its path and
    // rewrites app.asar to app.asar.unpacked). A '**/*.node' pattern leaves the
    // helper inside the asar, where it has no path on disk to hand to
    // posix_spawn and every spawn fails with ENOENT. Unpacking the directory at
    // build time also preserves the +x bit, which asar's runtime extraction
    // does not.
    expect(cfg.asarUnpack.join('\n')).toContain('@lydell/node-pty')
    expect(cfg.asarUnpack.some((p) => p.includes('node-pty') && p.endsWith('*.node'))).toBe(false)
  })

  it('covers the per-platform prebuild packages too', () => {
    // The meta package is 5 files and no binary: index.js does
    // require(`@lydell/node-pty-${process.platform}-${process.arch}`) at load
    // time. Unpacking only the meta package unpacks nothing that matters.
    expect(cfg.asarUnpack.some((p) => /@lydell\/node-pty-\*/.test(p))).toBe(true)
  })

  it('keeps the two patterns distinct, so the sibling glob cannot be dropped as redundant', () => {
    // '@lydell/node-pty/**' does not match '@lydell/node-pty-darwin-arm64/...':
    // minimatch compares path segments, and `node-pty` is not `node-pty-*`.
    // Verified against minimatch with electron-builder's own {dot: true}
    // options. They are two patterns because they have to be.
    const pkg = cfg.asarUnpack.filter((p) => /@lydell\/node-pty\/\*\*$/.test(p))
    const siblings = cfg.asarUnpack.filter((p) => /@lydell\/node-pty-\*\/\*\*$/.test(p))
    expect(pkg).toHaveLength(1)
    expect(siblings).toHaveLength(1)
  })
})

describe('the installers carry no redistributable-ConPTY payload', () => {
  const conpty = cfg.files.filter((p) => p.includes('conpty'))

  it('excludes the bundled conpty redistributable', () => {
    // The system ConPTY in conhost.exe is used instead (useConptyDll: false in
    // localPty.ts). Shipping unsigned Microsoft binaries we never load is
    // exactly what the Defender and ClamAV hard-fail gates in the release
    // workflow exist to catch.
    expect(conpty).toHaveLength(1)
  })

  // Run the glob rather than compare its text.
  //
  // The previous version of these tests asserted the pattern STRING, and passed
  // against a pattern that matched nothing: with a leading `**/` already
  // present, a second `**/` in the middle makes minimatch match no path at all.
  // conpty.dll and OpenConsole.exe shipped into the first 0.8.0 Windows build
  // and only the pack verifier caught it, in CI, after the tag was pushed.
  // A test that reads a pattern cannot tell you the pattern works.
  const WIN = 'node_modules/@lydell/node-pty-win32-x64/prebuilds/win32-x64/'
  const excludes = (path: string): boolean =>
    minimatch(path, conpty[0].slice(1), { dot: true })

  it('scopes the exclusion to node-pty rather than to every prebuilds/ directory', () => {
    // `prebuilds/` is a prebuildify convention, not a node-pty invention. An
    // unscoped pattern would silently strip files out of any future dependency
    // that happens to use the same layout.
    expect(conpty[0]).toContain('node_modules/@lydell/node-pty-')
    expect(excludes('node_modules/other-dep/prebuilds/win32-x64/conpty/thing.dll')).toBe(false)
  })

  it('actually matches the redistributable it is meant to exclude', () => {
    expect(excludes(`${WIN}conpty/conpty.dll`)).toBe(true)
    expect(excludes(`${WIN}conpty/OpenConsole.exe`)).toBe(true)
  })

  it('leaves the ConPTY bindings one level up in place', () => {
    // conpty.node and conpty_console_list.node are the bindings the app loads.
    // A `conpty*` pattern would take them out and break Windows entirely.
    expect(excludes(`${WIN}conpty.node`)).toBe(false)
    expect(excludes(`${WIN}conpty_console_list.node`)).toBe(false)
  })

  it('does not re-add the dead .pdb negation', () => {
    // appFileCopier.js:128-132 already strips *.pdb from node_modules unless
    // includePdb is set, so '!**/prebuilds/**/*.pdb' is a no-op that reads like
    // a protection. The guard that means something is the flag itself.
    expect(cfg.files.some((p) => p.includes('.pdb'))).toBe(false)
    expect(cfg.includePdb).not.toBe(true)
  })
})

describe('macOS file-access usage descriptions', () => {
  // These strings are the BODY TEXT of the TCC consent prompt raised the first
  // time anything under the bundle touches ~/Documents, ~/Desktop, ~/Downloads
  // or a removable volume — `ls ~/Downloads` is the second thing anyone types
  // into a terminal.
  //
  // They are optional for this class: without them macOS supplies generic copy
  // and a denial is EPERM, not termination. (Termination on a missing usage
  // description is real, but for Camera/Contacts/Photos, not Files and
  // Folders. Terminal.app declares none of these keys.) We set them because a
  // dialog that explains why a terminal wants your Downloads folder gets
  // approved and a generic one gets declined.
  it.each([
    'NSDocumentsFolderUsageDescription',
    'NSDesktopFolderUsageDescription',
    'NSDownloadsFolderUsageDescription',
    'NSRemovableVolumesUsageDescription'
  ])('%s is present and explains itself', (key) => {
    expect(cfg.mac.extendInfo?.[key]).toBeTruthy()
    expect((cfg.mac.extendInfo?.[key] ?? '').length).toBeGreaterThan(20)
  })
})

describe('a macOS artifact cannot claim an architecture its node_modules does not carry', () => {
  const dmg = (cfg.mac.target ?? []).find((t) => t.target === 'dmg')

  it('builds both mac architectures from the one build', () => {
    // Intel Macs are still a shipped target and the release notes link an x64
    // dmg by name.
    expect(dmg?.arch).toEqual(['x64', 'arm64'])
  })

  it('installs both prebuild siblings before packaging them', () => {
    // THE bug this whole file exists for. @lydell/node-pty-* declares
    // "os"/"cpu", so `npm ci` on the arm64 runner installs the arm64 sibling
    // and nothing else — and electron-builder then packs that one
    // node_modules into BOTH bundles. Without this step the x64 dmg ships the
    // arm64 binding and every Intel Mac gets MODULE_NOT_FOUND on first local
    // tab, while every check in CI passes: a --dir pack covers the host arch
    // only, and the release's signature loop looks at whichever .app it finds.
    const step = steps(release.jobs.build).find((s) => /node-pty-darwin-x64/.test(s.run ?? ''))
    expect(step, 'no release step force-installs the macOS node-pty prebuilds').toBeTruthy()
    expect(step?.run).toContain('node-pty-darwin-arm64')
    expect(step?.if).toContain('macos')
  })
})

describe('the pack job proves the layout on all three platforms', () => {
  const pack = ci.jobs.pack

  it('runs on Windows, macOS and Linux', () => {
    // CI has always been ubuntu-only and has never run electron-builder, so
    // until this job the first test of a PACKAGED app was a release tag.
    const os = pack?.strategy?.matrix?.os
    expect(os).toEqual(expect.arrayContaining(['ubuntu-latest', 'macos-latest', 'windows-latest']))
  })

  it('verifies the pack it just produced', () => {
    expect(steps(pack).some((s) => /electron-builder --dir/.test(s.run ?? ''))).toBe(true)
    expect(steps(pack).some((s) => /verify-local-pty-pack\.mjs/.test(s.run ?? ''))).toBe(true)
  })

  it('signs on pull requests, so the packed app is one configuration and not two', () => {
    // isSignAllowed() (macCodeSign.js:21) returns false whenever
    // GITHUB_BASE_REF is set, so without this the PR-packed .app is unsigned
    // while the main-packed one is signed — same job, two different artifacts,
    // and the signature-shaped failures only ever appear after merge.
    expect(String(pack?.env?.CSC_FOR_PULL_REQUEST ?? '')).toBe('true')
  })
})

describe('the release signature check cannot pass by finding nothing', () => {
  const step = steps(release.jobs.build).find((s) => /codesign --verify/.test(s.run ?? ''))
  // Comments in that step name the constructs it exists to avoid, so match on
  // the shell it actually runs.
  const run = (step?.run ?? '')
    .split('\n')
    .filter((l) => !/^\s*#/.test(l))
    .join('\n')

  it('verifies every .app under release/, not just the first', () => {
    // Two dmgs are built from one job, so `find … | head -n1` inspects one
    // bundle and reports on both.
    expect(step, 'no step verifies the macOS signature').toBeTruthy()
    expect(run).not.toMatch(/head -n ?1/)
  })

  it('fails when the unpacked bindings are not there at all', () => {
    // A `-d` test on …/@lydell succeeds as soon as the 13.5 KB meta package is
    // copied. If the sibling asarUnpack pattern is ever dropped, `find` matches
    // zero files, the loop body never runs, and the release ships a
    // binding-less app green. Counting is what makes the check a check.
    expect(run).toMatch(/COUNT|count/)
    expect(run).toMatch(/::error::/)
    expect(run).toMatch(/exit 1/)
  })
})
