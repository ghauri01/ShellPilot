import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
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
  const CEILING: Record<string, number> = {
    'Scan installers with ClamAV': 25,
    'Build release notes': 102,
    'Publish release notes': 50
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
