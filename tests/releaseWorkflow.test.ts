import { describe, it, expect } from 'vitest'
import { mkdirSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { execFileSync } from 'node:child_process'
import { load } from 'js-yaml'

// The release workflow only ever runs on a version tag, so every bug in it has
// been discovered by publishing a broken release. Two already were:
//
//   1. Notes silently not publishing at all, for every release in the project's
//      history — the generator worked the whole time; the upload step never
//      applied its output.
//   2. `gh release edit` failing with "fatal: not a git repository", because
//      the publish job downloaded artifacts but never checked out the repo.
//
// Neither is a bug in the notes content, so no amount of testing the generator
// would have found either. They are bugs in the SHAPE of the workflow, which
// is a thing a plain YAML parse can assert on every pull request.

interface Step {
  uses?: string
  run?: string
  name?: string
  id?: string
  with?: Record<string, unknown>
  env?: Record<string, unknown>
}
interface Job {
  'runs-on'?: string
  env?: Record<string, unknown>
  steps?: Step[]
}
interface Workflow {
  on?: unknown
  concurrency?: unknown
  permissions?: Record<string, string>
  jobs: Record<string, Job>
}

const wf = load(readFileSync('.github/workflows/release.yml', 'utf8')) as Workflow
const jobs = Object.entries(wf.jobs)
const steps = (j: Job): Step[] => j.steps ?? []
const usesGh = (j: Job): boolean => steps(j).some((s) => /(^|\s)gh\s/.test(s.run ?? ''))
const hasCheckout = (j: Job): boolean => steps(j).some((s) => (s.uses ?? '').includes('actions/checkout'))

describe('every job that shells out to gh can resolve the repository', () => {
  it.each(jobs)('%s', (_name, job) => {
    if (!usesGh(job)) return
    // gh finds the repo from a git remote or from GH_REPO. With neither it
    // fails at runtime with "fatal: not a git repository" — which is exactly
    // how v0.3.1 shipped with no notes.
    const env = { ...(wf as { env?: Record<string, unknown> }).env, ...job.env }
    expect(hasCheckout(job) || 'GH_REPO' in env).toBe(true)
  })
})

describe('nothing becomes public before it has been verified', () => {
  const release = wf.jobs.release
  const upload = steps(release).find((s) => (s.uses ?? '').includes('action-gh-release'))

  it('uploads assets to a draft', () => {
    // A draft sends no watcher notifications and is not /releases/latest, so a
    // failure after this point is invisible rather than published-and-wrong.
    expect(upload?.with?.draft).toBe(true)
  })

  it('publishes the draft only after the notes step', () => {
    const flip = steps(release).findIndex((s) => /--draft=false/.test(s.run ?? ''))
    const uploadAt = steps(release).findIndex((s) => (s.uses ?? '').includes('action-gh-release'))
    expect(flip).toBeGreaterThan(uploadAt)
  })

  it('verifies content rather than length', () => {
    const notes = steps(release).find((s) => /--draft=false/.test(s.run ?? ''))?.run ?? ''
    // A length check passes on any body over the threshold, including one with
    // none of our content in it.
    expect(notes).not.toMatch(/-lt 200/)
    expect(notes).toContain('expected.txt')
  })

  it('fails the job when the notes did not land', () => {
    const notes = steps(release).find((s) => /--draft=false/.test(s.run ?? ''))?.run ?? ''
    expect(notes).toMatch(/::error::/)
    expect(notes).toMatch(/exit 1/)
  })
})

describe('a prerelease tag must not be published on the stable channel', () => {
  // electron-updater's stable clients resolve updates through
  // /repos/:o/:r/releases/latest, which GitHub defines as the newest release
  // that is NOT marked prerelease. So publishing a v0.7.0-beta.1 tag with
  // --latest is not a mislabelled release page: it is an immediate offer of a
  // beta build to every stable user on their next update check, and it cannot
  // be withdrawn from the ones who have already taken it. The final line of
  // the publish step used to do exactly that for every tag, and because this
  // workflow only ever runs on a tag, the first beta push would have been the
  // discovery.
  const publish = steps(wf.jobs.release).find((s) => /--draft=false/.test(s.run ?? ''))?.run ?? ''
  const editLines = publish
    .split('\n')
    .map((l) => l.trim())
    .filter((l) => l.startsWith('gh release edit') && l.includes('--draft=false'))

  it('decides the channel from the tag', () => {
    // v0.7.0-beta.1 carries a semver prerelease component and v0.7.0 does not.
    // The tag-matches-package.json step guarantees the tag is "v" plus the
    // package.json version, so there is nothing else in the string a dash
    // could mean.
    expect(publish).toMatch(/\{TAG#v\}/)
    expect(publish).toMatch(/case\s+"?\$\{?VERSION/)
  })

  it('does not publish every tag the same way', () => {
    // A single unconditional edit is the bug itself, whatever flags it carries.
    expect(editLines.length).toBeGreaterThan(1)
  })

  it('marks a prerelease tag as a prerelease, and not as latest', () => {
    const pre = editLines.find((l) => l.includes('--prerelease'))
    expect(pre, 'no branch publishes a tag with --prerelease').toBeTruthy()
    // Omitting --latest only leaves the flag at whatever is already on the
    // release, which is not the same thing as saying it is not the latest.
    expect(pre).toContain('--latest=false')
  })

  it('still marks a stable tag as latest', () => {
    const stable = editLines.find((l) => /--latest(?!=)/.test(l))
    expect(stable, 'no branch publishes a stable tag with --latest').toBeTruthy()
    expect(stable).not.toContain('--prerelease')
  })
})

describe('the update manifests ship as deliberately as the installers', () => {
  const upload = steps(wf.jobs.build).find(
    (s) =>
      (s.uses ?? '').includes('upload-artifact') &&
      String(s.with?.name ?? '').startsWith('shellpilot-')
  )
  const path = String(upload?.with?.path ?? '')

  it('uploads the channel yml for both channels', () => {
    // electron-updater reads exactly one file to decide whether an update
    // exists at all: latest*.yml on the stable channel, beta*.yml on a
    // prerelease tag, named by electron-builder from the version's semver
    // prerelease component. Until they were listed here they reached the
    // release only as a side effect of electron-builder's own default publish
    // policy, so anything that turned that off — a config change, a token
    // scope, a version bump of the builder — would have left every installer
    // in place, every step green, and over-the-air updates silently dead.
    expect(path).toContain('release/latest*.yml')
    expect(path).toContain('release/beta*.yml')
  })

  it('carries them through to the release', () => {
    // Listing them above is only worth anything if the release job uploads
    // everything it downloaded.
    const ghRelease = steps(wf.jobs.release).find((s) => (s.uses ?? '').includes('action-gh-release'))
    expect(String(ghRelease?.with?.files ?? '')).toContain('artifacts/**')
  })

  it('keeps them out of the checksum table', () => {
    // The table lists what a human downloads and verifies by hand. The find
    // that builds it selects installer extensions rather than excluding
    // metadata ones, so adding the yml above adds no rows to it — asserted
    // here because "it happens to filter the right way" is the kind of thing
    // that stops being true without anyone noticing.
    const notes = steps(wf.jobs.release).find((s) => s.name === 'Build release notes')?.run ?? ''
    const checksumBlock = notes.slice(notes.indexOf('CHECKSUMS='), notes.indexOf('sha256sum'))
    expect(checksumBlock).toBeTruthy()
    expect(checksumBlock).not.toMatch(/\.yml/)
    expect(checksumBlock).not.toMatch(/blockmap/)
  })
})

describe('a build that produced nothing must not publish', () => {
  it('treats missing artifacts as an error, not a warning', () => {
    const upload = steps(wf.jobs.build).find((s) => (s.uses ?? '').includes('upload-artifact'))
    // Otherwise the notes link to files that were never built, and every step
    // still goes green.
    expect(upload?.with?.['if-no-files-found']).toBe('error')
  })
})

describe('two releases cannot race', () => {
  it('serialises on the ref', () => {
    // Re-pushing a tag would otherwise run two jobs editing one release body.
    expect(wf.concurrency).toBeTruthy()
  })
})

describe('inline shell in the release job does not keep growing', () => {
  // A ratchet pinned to today's sizes, not an aspiration. "Build release notes"
  // is 101 lines of shell that only ever executes on a version tag, which is
  // precisely why its bugs — a downloads table verified by nothing, a checksum
  // pipeline nobody could run — are discoverable only by publishing. Extracting
  // it to a script the test suite can call is the real fix; until then this
  // stops it getting worse.
  //
  // Raised once, from 102, when GPL-2.0 §3 compliance moved into the notes:
  // bundling OpenVPN obliges us to publish its corresponding source, and a
  // release asset nobody is told about is not an offer. That is a section and
  // a fallback line for when the archive is missing, and it is the kind of
  // growth the ratchet exists to make deliberate rather than to prevent.
  //
  // "Publish release notes" was raised once too, from 50, when the beta
  // channel arrived. The final line of that step used to publish every tag the
  // same way, so it now branches on whether the tag carries a semver
  // prerelease component — a few lines of shell, and rather more explaining
  // why, because the cost of the branch being wrong is every stable user being
  // offered a beta. Reviewing that reasoning at the point of change is worth
  // more than the lines it costs.
  // Raised again, from 120, when the Gatekeeper note moved to the top of the
  // page. macOS reports this app as "damaged" and offers Move to Trash as the
  // obvious button; the explanation was previously the last paragraph, under
  // every checksum table, which for that particular message is close to not
  // having written it. Moving it up also meant correcting it — the old copy
  // told people to right-click → Open, a bypass Apple removed in macOS 15, so
  // following it returned them to the same dialog. Net +20 lines after deleting
  // the paragraph it replaced, and the notes now open with the one thing a
  // first-time downloader has to read before they act on a Trash button.
  const CEILING: Record<string, number> = {
    'Scan installers with ClamAV': 25,
    'Build release notes': 145,
    'Publish release notes': 75
  }

  it.each(Object.entries(CEILING))('%s stays within its ceiling', (name, max) => {
    const step = steps(wf.jobs.release).find((s) => s.name === name)
    expect(step, name).toBeTruthy()
    expect((step?.run ?? '').split('\n').length).toBeLessThanOrEqual(max)
  })

  it('has no run step that the ratchet does not know about', () => {
    // A new inline block should be a deliberate decision, not something that
    // appears unmeasured.
    const named = steps(wf.jobs.release)
      .filter((s) => s.run)
      .map((s) => s.name ?? '')
    expect(named.sort()).toEqual(Object.keys(CEILING).sort())
  })
})

describe('macOS build hardening', () => {
  const builder = load(readFileSync('electron-builder.yml', 'utf8')) as {
    mac?: { hardenedRuntime?: boolean; entitlements?: string; identity?: string }
  }

  it('enables the hardened runtime', () => {
    // Without it a same-user process can inject into ShellPilot and read an
    // unlocked vault key from memory, which defeats every protection the vault
    // has. It needs no Developer ID — ad-hoc signing carries it fine.
    expect(builder.mac?.hardenedRuntime).toBe(true)
  })

  it('ships the entitlements the hardened runtime needs', () => {
    // asarUnpack keeps ssh2/cpu-features .node binaries outside the archive on
    // purpose; without disable-library-validation they will not load.
    expect(builder.mac?.entitlements).toBe('build/entitlements.mac.plist')
    const plist = readFileSync('build/entitlements.mac.plist', 'utf8')
    expect(plist).toContain('com.apple.security.cs.disable-library-validation')
    expect(plist).toContain('com.apple.security.cs.allow-jit')
  })
})

describe('GPL-2.0 §3: the OpenVPN source is published with the binaries', () => {
  // ShellPilot bundles OpenVPN on macOS and Linux. That makes this project a
  // distributor of GPL-2.0 binaries, and §3 obliges a distributor to supply
  // the corresponding source. The obligation is not discharged by a script
  // that *can* produce a tarball — it is discharged by the tarball being on
  // the release page. So it is asserted here, where a workflow edit that
  // dropped it fails a pull request rather than a licence.
  const upload = steps(wf.jobs.build).find(
    (s) => (s.uses ?? '').includes('upload-artifact') && s.with?.name === 'openvpn-source'
  )

  it('uploads the source archive from the build job', () => {
    expect(upload, 'no step uploads an "openvpn-source" artifact').toBeTruthy()
    expect(upload?.with?.path).toContain('.openvpn-src')
  })

  it('fails the build when the archive was not produced', () => {
    // A silent no-op here publishes GPL binaries with no source beside them,
    // and every step still goes green.
    expect(upload?.with?.['if-no-files-found']).toBe('error')
  })

  it('names the archive in the release notes', () => {
    // An asset nobody is pointed at is not an offer of source.
    const notes = steps(wf.jobs.release).find((s) => s.name === 'Build release notes')?.run ?? ''
    expect(notes).toContain('openvpn-*-source.tar.gz')
    expect(notes).toMatch(/GPL-2\.0/)
  })

  it('includes the archive in the checksum table', () => {
    // The checksums are how a downloader proves the source they got is the
    // source this workflow archived.
    const notes = steps(wf.jobs.release).find((s) => s.name === 'Build release notes')?.run ?? ''
    const checksumBlock = notes.slice(notes.indexOf('CHECKSUMS='), notes.indexOf('sha256sum'))
    expect(checksumBlock).toContain('openvpn-*-source.tar.gz')
  })
})

// The Gatekeeper note, and where it sits.
//
// macOS tells people this app is DAMAGED and offers a Move to Trash button as
// the obvious action. That wording is what an unnotarized, ad-hoc signed app
// gets — the signature is valid and `codesign --verify --strict --deep` passes
// — but a reader cannot know that from the dialog. The explanation used to be
// the last paragraph of the notes, below every checksum table, which for this
// particular message is close to not having written it.
//
// These run the generator and assert on the markdown it actually produces,
// rather than on the YAML that produces it: the property that matters is what
// a person sees at the top of the page.
describe('the first-run note', () => {
  const notes = ((): string => {
    const step = (wf.jobs.release.steps ?? []).find(
      (s) => s.name === 'Build release notes'
    )
    if (!step?.run) throw new Error('the Build release notes step is gone')
    const dir = mkdtempSync(join(tmpdir(), 'notes-'))
    mkdirSync(join(dir, 'artifacts'))
    writeFileSync(join(dir, 'gen.sh'), step.run)
    execFileSync('bash', ['gen.sh'], {
      cwd: dir,
      env: { ...process.env, TAG: 'v9.9.9', VT_RESULTS: '', CLAMAV_STATUS: '', CLAMAV_VERSION: '' }
    })
    return readFileSync(join(dir, 'release-notes.md'), 'utf8')
  })()

  it('is the first thing on the page', () => {
    // Not "appears somewhere": the whole defect was that it appeared, at the
    // bottom, after the reader had already met the Trash button.
    expect(notes.trimStart().startsWith('## First run')).toBe(true)
  })

  it('comes before the download links', () => {
    const headings = [...notes.matchAll(/^## (.+)$/gm)].map((m) => m[1])
    expect(headings.indexOf('First run')).toBeLessThan(headings.indexOf('Downloads'))
    expect(headings.indexOf('First run')).toBe(0)
  })

  it('uses the word macOS actually shows, so the note is findable', () => {
    // A reader searching the page for the word in their dialog has to land on
    // it. "not notarized" is the cause, not the symptom, and nobody searches
    // for it.
    expect(notes).toMatch(/damaged/i)
  })

  it('does not send Sequoia users to a bypass Apple removed', () => {
    // The old copy said right-click → Open. That has not worked since macOS 15,
    // and following it leaves the reader back at the same dialog concluding the
    // download really is corrupt.
    const firstRun = notes.slice(0, notes.indexOf('## Downloads'))
    expect(firstRun).not.toMatch(/right-click[^.]*→\s*\*\*Open\*\*/i)
    // Paired with the positive, so this cannot pass by the section vanishing.
    expect(firstRun).toMatch(/Open Anyway/)
    expect(firstRun).toMatch(/xattr -dr com\.apple\.quarantine/)
  })

  it('spells xattr with its full path', () => {
    // A Homebrew or pip `xattr` earlier on PATH may not support -r, and the
    // failure looks like the workaround itself being wrong.
    expect(notes).toMatch(/\/usr\/bin\/xattr -dr/)
  })

  it('still tells Windows users about SmartScreen', () => {
    // Moving the macOS half up must not strand the Windows half behind.
    expect(notes.slice(0, notes.indexOf('## Downloads'))).toMatch(/SmartScreen/)
  })
})
