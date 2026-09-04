import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import {
  DOCKER_ACTION_MAX_REFS,
  DOCKER_MARKERS,
  DOCKER_RECLAIM_KINDS,
  buildDockerReclaimCommand,
  buildDockerReclaimPreview,
  diffDockerReclaim,
  dockerReclaimBlocked,
  parseDockerDiskDetailOutput,
  parseDockerReclaimOutput,
  planDockerReclaim,
  validateDockerObjectId,
  type DockerDiskDetail,
  type DockerReclaimItem
} from '../src/shared/docker'

// Reclaim by id — roadmap 21b, and the answer to the refusal 21a wrote down.
//
// The refusal was falsifiable rather than a preference: prune's "blast radius
// is not knowable from the UI that offers it". So every case below is really
// asking one question — is the blast radius still exactly the list on screen?
// A test that only checked "did the container go away" would pass against the
// version of this feature that runs `prune` and gets lucky.
//
// Fixtures are real. `reclaim-*-docker-29.txt` were recorded from Docker
// 29.5.3 against objects created for the recording; see
// tests/fixtures/docker/README.md, including what was NOT recorded (podman).

const fixture = (name: string): string =>
  readFileSync(join(__dirname, 'fixtures/docker', name), 'utf8')

const REMOVED = fixture('reclaim-removed-docker-29.txt')
const REFUSED = fixture('reclaim-refused-docker-29.txt')
const MULTITAG = fixture('reclaim-multitag-docker-29.txt')
const SHORTNAME = fixture('reclaim-refused-shortname-docker-29.txt')
const REAL_DFV = fixture('system-df-v-docker-29.txt')

const dfvOutput = (body: string): string =>
  `${DOCKER_MARKERS.dfDetail}\n${body}\n${DOCKER_MARKERS.end}\n`

/** The recorded host's itemised disk, parsed. The preview's only input. */
function recordedDisk(): DockerDiskDetail {
  const r = parseDockerDiskDetailOutput(dfvOutput(REAL_DFV), 0)
  if (!r.ok) throw new Error(`the recorded df -v no longer parses: ${r.detail}`)
  return r.disk
}

const item = (over: Partial<DockerReclaimItem> & Pick<DockerReclaimItem, 'kind' | 'id'>): DockerReclaimItem => ({
  label: over.id,
  size: '0B',
  sizeBytes: 0,
  ...over
})

// ---------------------------------------------------------------------------
// What is offered, and — more to the point — what is not
// ---------------------------------------------------------------------------

describe('the offer set, built from the itemised read and nothing else', () => {
  it('offers only stopped containers, dangling-or-unreferenced images, and unlinked volumes', () => {
    const p = buildDockerReclaimPreview(recordedDisk())
    // Recorded host: `old-frontend` is Exited (137), `migration-runner` is
    // Created. The other five are Up.
    expect(p.items.filter((i) => i.kind === 'container').map((i) => i.label).sort()).toEqual([
      'migration-runner',
      'old-frontend'
    ])
    // Four images with CONTAINERS 0, one of them the `<none>:<none>` dangling one.
    expect(p.items.filter((i) => i.kind === 'image').map((i) => i.label).sort()).toEqual([
      '<none>:<none>',
      'app-frontend:latest',
      'app-listener:latest',
      'mysql:8.0.42'
    ])
    // Two volumes with LINKS 0 — one anonymous, one named.
    expect(p.items.filter((i) => i.kind === 'volume').map((i) => i.label).sort()).toEqual([
      '3f4acbc1072ddddc74459dc2dbc21eb1a7fb39fb88720e6b4514fc6bcf4f2801',
      'stack_pgdata'
    ])
  })

  it('never offers a volume with links, whatever its size', () => {
    // The single most regretted removal there is. `e9c06091…` is 1.386GB with
    // one link on the recorded host, which is exactly the row a size-sorted
    // list puts at the top and an operator reaches for first.
    const p = buildDockerReclaimPreview(recordedDisk())
    const linked = 'e9c06091ebdd38a00b437a20a8cbd5d1226292e8191d1af544b9f8a087daa81e'
    expect(p.items.map((i) => i.id)).not.toContain(linked)
    expect(p.withheld.find((w) => w.id === linked)?.reason).toBe('1 container linked to it')
  })

  it('never offers a paused or a restarting container', () => {
    // Docker prunes neither. Offering them would widen the blast radius past
    // what "unused" means to the person reading the list — and `paused` is the
    // dangerous one, because a paused container is a RUNNING process with its
    // memory intact.
    const disk = recordedDisk()
    disk.containers = [
      { ...disk.containers[0], id: 'aaaaaaaaaaaa', name: 'held', state: 'paused' },
      { ...disk.containers[0], id: 'bbbbbbbbbbbb', name: 'flapping', state: 'restarting' },
      { ...disk.containers[0], id: 'cccccccccccc', name: 'crashed', state: 'exited' }
    ]
    const p = buildDockerReclaimPreview(disk)
    expect(p.items.filter((i) => i.kind === 'container').map((i) => i.label)).toEqual(['crashed'])
    expect(p.withheld.find((w) => w.label === 'held')?.reason).toBe(
      'it is paused, which docker does not prune either'
    )
    expect(p.withheld.find((w) => w.label === 'flapping')?.reason).toBe(
      'it is restarting, which docker does not prune either'
    )
  })

  it('never offers a build cache entry, because removing one means a prune', () => {
    const disk = recordedDisk()
    disk.buildCache = [
      { id: 'x9f2ab', type: 'regular', size: '1.2GB', sizeBytes: 1.2e9, created: '', lastUsed: '', usage: 0, shared: 'false' }
    ]
    const p = buildDockerReclaimPreview(disk)
    expect(p.items.map((i) => i.kind)).not.toContain('cache')
    expect(p.withheld.find((w) => w.id === 'x9f2ab')?.reason).toBe(
      'a build cache entry can only be removed by `docker builder prune`, and nothing here runs a prune'
    )
  })

  it('withholds rather than guesses when the runtime would not say', () => {
    // A runtime that prints no CONTAINERS or LINKS column reads as null, and
    // null is not zero. Treating it as zero is how a podman host would have its
    // in-use volume offered on a technicality.
    const disk = recordedDisk()
    disk.containers = []
    disk.buildCache = []
    disk.images = [{ ...disk.images[0], id: 'aaaaaaaaaaaa', containers: null }]
    disk.volumes = [{ name: 'unknown-links', links: null, size: '1GB', sizeBytes: 1e9, anonymous: false }]
    const p = buildDockerReclaimPreview(disk)
    expect(p.items).toEqual([])
    expect(p.withheld.map((w) => w.reason)).toContain(
      'this runtime did not say how many containers reference it'
    )
    expect(p.withheld.map((w) => w.reason)).toContain(
      'this runtime did not say how many containers are linked to it'
    )
  })

  it('carries the image UNIQUE SIZE, not the SIZE that counts shared layers', () => {
    const p = buildDockerReclaimPreview(recordedDisk())
    // app-listener is 152MB of layers of which 2.105kB is its own. Showing
    // 152MB next to a checkbox would promise 152MB back that removing it does
    // not free.
    const listener = p.items.find((i) => i.label === 'app-listener:latest')
    expect(listener?.size).toBe('2.105kB')
  })
})

// ---------------------------------------------------------------------------
// The plan: blast radius, not count
// ---------------------------------------------------------------------------

describe('how hard the operator has to press, and why it is not about how many', () => {
  it('makes a single volume typed-confirm and destructive, on its own', () => {
    const plan = planDockerReclaim([item({ kind: 'volume', id: 'pgdata', anonymous: false })])
    expect(plan.risk).toBe('destructive')
    expect(plan.confirmation).toEqual({ kind: 'type-to-confirm', phrase: 'REMOVE' })
  })

  it('does not escalate fifty images to what one volume gets', () => {
    // The point of the whole model. Fifty dangling images are a `docker pull`
    // away; one volume is somebody's database. A count-based rule gets this
    // exactly backwards, and `planDockerAction` — which IS count-based, and
    // right to be, because stopping things is reversible — is the wrong pattern
    // to copy here.
    const many = Array.from({ length: 50 }, (_, n) =>
      item({ kind: 'image', id: `aaaaaaaaaa${String(n).padStart(2, '0')}` })
    )
    const plan = planDockerReclaim(many)
    expect(plan.risk).toBe('elevated')
    expect(plan.confirmation).toEqual({ kind: 'confirm' })
    expect(planDockerReclaim([item({ kind: 'volume', id: 'one' })]).confirmation.kind).toBe('type-to-confirm')
  })

  it('never lets a removal run on a bare click', () => {
    for (const kind of DOCKER_RECLAIM_KINDS) {
      const plan = planDockerReclaim([item({ kind, id: kind === 'volume' ? 'v' : 'aaaaaaaaaaaa' })])
      expect(plan.confirmation.kind, kind).not.toBe('none')
    }
  })

  it('keeps caveats out of reasons, because they argue for nothing', () => {
    const plan = planDockerReclaim([
      item({ kind: 'volume', id: 'stack_pgdata', anonymous: false }),
      item({ kind: 'image', id: 'b7d3f9a10c22', dangling: true }),
      item({ kind: 'container', id: '7f1e0c9a3d55', mountedVolumes: 2 })
    ])
    // Reasons are why this is being asked about at all.
    expect(plan.reasons).toContain(
      'removes 1 volume, and what is inside a volume cannot be recovered afterwards'
    )
    // Caveats are what would otherwise be found out afterwards, and none of
    // them is an argument for pressing harder.
    expect(plan.caveats).toContain(
      "a dangling image is a previous build's layers; no registry has a copy, so it comes back only by rebuilding"
    )
    expect(plan.caveats).toContain(
      '1 container here mount local volumes; removing the container leaves those volumes behind, it does not delete them'
    )
    expect(plan.caveats.some((c) => c.includes('skips these on Docker 23 and later'))).toBe(true)
    for (const c of plan.caveats) expect(plan.reasons).not.toContain(c)
  })

  it('says out loud that this removes a named volume where docker itself would not', () => {
    // Docker 23 changed `volume prune` to skip named volumes because removing
    // them was the regret people kept reporting. This removes them. An operator
    // who has internalised "prune leaves my named volumes alone" is the exact
    // person this caveat is for.
    const named = planDockerReclaim([item({ kind: 'volume', id: 'stack_pgdata', anonymous: false })])
    expect(named.caveats.join(' ')).toContain('1 named volume')
    const anon = planDockerReclaim([
      item({ kind: 'volume', id: '3f4acbc1072ddddc74459dc2dbc21eb1a7fb39fb88720e6b4514fc6bcf4f2801', anonymous: true })
    ])
    expect(anon.caveats.join(' ')).not.toContain('named volume')
  })
})

// ---------------------------------------------------------------------------
// The re-preview, which is the whole feature
// ---------------------------------------------------------------------------

describe('the re-preview, and the refusal when the host moved under it', () => {
  const selected = [
    item({ kind: 'container', id: '9b2c7e4d1a08', label: 'old-frontend', size: '412MB' }),
    item({ kind: 'volume', id: 'stack_pgdata', label: 'stack_pgdata', size: '2.41GB' })
  ]

  it('runs nothing when a selected container came back to life between the two reads', () => {
    // The case this whole step exists for. Something restarted `old-frontend`
    // while the dialog was open. Removing it anyway is the failure; removing
    // it "because docker will refuse if it matters" is trusting a race.
    const fresh = {
      items: [selected[1]],
      withheld: [
        { kind: 'container' as const, id: '9b2c7e4d1a08', label: 'old-frontend', reason: 'it is running' }
      ]
    }
    const diff = diffDockerReclaim(selected, fresh)
    expect(dockerReclaimBlocked(diff)).toBe(true)
    expect(diff.ineligible).toEqual([{ item: selected[0], detail: 'it is running' }])
    expect(diff.gone).toEqual([])
  })

  it('runs nothing when a selected item vanished entirely', () => {
    const diff = diffDockerReclaim(selected, { items: [selected[0]], withheld: [] })
    expect(dockerReclaimBlocked(diff)).toBe(true)
    expect(diff.gone.map((i) => i.label)).toEqual(['stack_pgdata'])
  })

  it('runs nothing when a selected item is the same object at a different size', () => {
    // The operator approved "2.41GB". If it is 9GB now, something is writing
    // to it, which is a fact about the host they should see before it goes.
    const grown = [...selected]
    const diff = diffDockerReclaim(selected, {
      items: [grown[0], { ...grown[1], size: '9.02GB', sizeBytes: 9.02e9 }],
      withheld: []
    })
    expect(dockerReclaimBlocked(diff)).toBe(true)
    expect(diff.changed).toEqual([{ item: selected[1], detail: 'it is now 9.02GB, not 2.41GB' }])
  })

  it('runs nothing when an image was retagged under its id', () => {
    const img = item({ kind: 'image', id: '206af11251e4', label: 'app-frontend:latest', size: '866.5MB' })
    const diff = diffDockerReclaim([img], {
      items: [{ ...img, label: 'app-frontend:rollback' }],
      withheld: []
    })
    expect(dockerReclaimBlocked(diff)).toBe(true)
    expect(diff.changed[0].detail).toBe('it is now app-frontend:rollback, not app-frontend:latest')
  })

  it('does NOT refuse merely because new things became removable', () => {
    // The good half of the same coin. Those items are untouched by
    // construction — the command carries explicit ids and theirs are not among
    // them — so refusing here would make a busy host permanently unreclaimable
    // while protecting nothing. They are named, not acted on.
    const newcomer = item({ kind: 'container', id: 'dddddddddddd', label: 'just-crashed' })
    const diff = diffDockerReclaim(selected, { items: [...selected, newcomer], withheld: [] })
    expect(dockerReclaimBlocked(diff)).toBe(false)
    expect(diff.appeared).toEqual([newcomer])
  })

  it('is quiet when nothing moved', () => {
    const diff = diffDockerReclaim(selected, { items: [...selected], withheld: [] })
    expect(dockerReclaimBlocked(diff)).toBe(false)
    expect(diff).toEqual({ gone: [], ineligible: [], changed: [], appeared: [] })
  })
})

// ---------------------------------------------------------------------------
// The command
// ---------------------------------------------------------------------------

describe('the command, which is a list of ids and cannot become anything else', () => {
  const four: DockerReclaimItem[] = [
    item({ kind: 'container', id: '4b07fd557da1', label: 'sp21b-created' }),
    item({ kind: 'image', id: 'cfa60c5d01ea', label: '<none>:<none>' }),
    item({ kind: 'volume', id: 'sp21b-named-free' }),
    item({ kind: 'network', id: '41263af10316' })
  ]

  it('removes an image by its ID and never by its tag', () => {
    // `docker rmi nginx:latest` untags. `docker rmi <id>` removes. They are two
    // operations wearing one verb, and the tag→id lookup that would let a tag
    // in can race with a rebuild.
    const cmd = buildDockerReclaimCommand([
      item({ kind: 'image', id: '206af11251e4', label: 'app-frontend:latest' })
    ])
    expect(cmd).toMatch(/"\$SP_BIN" rmi 206af11251e4 2>&1/)
    expect(cmd).not.toContain('app-frontend')
    expect(cmd).not.toContain(':latest')
    expect(() =>
      buildDockerReclaimCommand([item({ kind: 'image', id: 'app-frontend:latest' })])
    ).toThrow(/refusing/)
    expect(() => buildDockerReclaimCommand([item({ kind: 'image', id: 'nginx' })])).toThrow(/refusing/)
  })

  it('gives each kind its own verb, its own marker and its own block', () => {
    const cmd = buildDockerReclaimCommand(four)
    expect(cmd).toContain(`echo "${DOCKER_MARKERS.rmContainer}"; "$SP_BIN" rm 4b07fd557da1 2>&1`)
    expect(cmd).toContain(`echo "${DOCKER_MARKERS.rmImage}"; "$SP_BIN" rmi cfa60c5d01ea 2>&1`)
    expect(cmd).toContain(`echo "${DOCKER_MARKERS.rmVolume}"; "$SP_BIN" volume rm sp21b-named-free 2>&1`)
    expect(cmd).toContain(`echo "${DOCKER_MARKERS.rmNetwork}"; "$SP_BIN" network rm 41263af10316 2>&1`)
  })

  it('puts containers before images, which docker requires and the preview makes safe', () => {
    const cmd = buildDockerReclaimCommand(four)
    expect(cmd.indexOf(DOCKER_MARKERS.rmContainer)).toBeLessThan(cmd.indexOf(DOCKER_MARKERS.rmImage))
    // And the ordering cannot widen the set the way `system prune -a` does,
    // because an image with a referencing container is never offered at all.
    const disk = recordedDisk()
    const referenced = disk.images.filter((i) => (i.containers ?? 0) > 0).map((i) => i.id)
    const offered = buildDockerReclaimPreview(disk).items.map((i) => i.id)
    expect(referenced.length).toBeGreaterThan(0)
    for (const id of referenced) expect(offered).not.toContain(id)
  })

  it('has no room in its grammar for a flag', () => {
    for (const flag of ['-a', '--all', '-f', '--force', '--volumes', '--filter', '-v']) {
      expect(() => buildDockerReclaimCommand([item({ kind: 'image', id: flag })]), flag).toThrow(/refusing/)
      expect(() => buildDockerReclaimCommand([item({ kind: 'volume', id: flag })]), flag).toThrow(/refusing/)
    }
    const cmd = buildDockerReclaimCommand(four)
    expect(cmd).not.toMatch(/\s-f\b|\s--force\b|\s-a\b|\s--all\b|\s--volumes\b/)
  })

  it('refuses an empty list rather than removing nothing quietly', () => {
    expect(() => buildDockerReclaimCommand([])).toThrow(/refusing to build a reclaim command with no items/)
  })

  it('refuses an unknown kind, a shell metacharacter and a duplicate', () => {
    expect(() =>
      buildDockerReclaimCommand([item({ kind: 'everything' as 'image', id: 'cfa60c5d01ea' })])
    ).toThrow(/refusing/)
    expect(() =>
      buildDockerReclaimCommand([item({ kind: 'container', id: 'cfa60c5d01ea; reboot' })])
    ).toThrow(/refusing/)
    expect(() =>
      buildDockerReclaimCommand([item({ kind: 'volume', id: '$(id)' })])
    ).toThrow(/refusing/)
    expect(() =>
      buildDockerReclaimCommand([
        item({ kind: 'image', id: 'cfa60c5d01ea' }),
        item({ kind: 'image', id: 'cfa60c5d01ea' })
      ])
    ).toThrow(/names the same object twice/)
  })

  it('is capped absolutely', () => {
    const many = Array.from({ length: DOCKER_ACTION_MAX_REFS + 1 }, (_, n) =>
      item({ kind: 'volume', id: `vol-${n}` })
    )
    expect(() => buildDockerReclaimCommand(many)).toThrow(/more than 50 items/)
  })

  it('asks the same question with and without sudo', () => {
    const plain = buildDockerReclaimCommand(four)
    const sudo = buildDockerReclaimCommand(four, { sudo: true }).replace(/sudo -n /g, '')
    expect(sudo).toBe(plain)
    expect(plain).not.toMatch(/sudo/)
  })

  it('rejects a short id shorter than docker prints', () => {
    // `docker rmi cfa` is a prefix match against every image on the host and
    // will happily remove a different one.
    expect(validateDockerObjectId('cfa')).toBe(false)
    expect(validateDockerObjectId('cfa60c5d01ea')).toBe(true)
    expect(validateDockerObjectId('CFA60C5D01EA')).toBe(false)
  })
})

// ---------------------------------------------------------------------------
// What happened, per item, against real recorded output
// ---------------------------------------------------------------------------

describe('what happened to each object, read from Docker 29.5.3', () => {
  const removed: DockerReclaimItem[] = [
    item({ kind: 'container', id: '4b07fd557da1', label: 'sp21b-created' }),
    item({ kind: 'image', id: 'cfa60c5d01ea', label: '<none>:<none>' }),
    item({ kind: 'volume', id: 'sp21b-named-free' }),
    item({ kind: 'volume', id: '69dbb0eae15f46080632879a4ce04fbd211e4c8ae3f378b4c5f069ae0e5732f2', anonymous: true }),
    item({ kind: 'network', id: '41263af10316' })
  ]

  it('reads a successful run of all four commands', () => {
    const r = parseDockerReclaimOutput(removed, REMOVED, 0)
    expect(r.ok).toBe(true)
    if (!r.ok) return
    expect(r.outcomes.map((o) => o.ok)).toEqual([true, true, true, true, true])
    expect(r.unattributed).toEqual([])
  })

  it('recognises rmi, which does not echo the id it was given', () => {
    // The recorded line is `Deleted: sha256:cfa60c5d01eaa6d817…`. An equality
    // match reports this successful removal as "docker did not say what
    // happened", which is the answer that sends someone to check by hand.
    const r = parseDockerReclaimOutput([removed[1]], REMOVED, 0)
    expect(r.ok).toBe(true)
    if (!r.ok) return
    expect(r.outcomes[0]).toEqual({ item: removed[1], ok: true })
  })

  it("attributes each refusal to the right object, in docker's own words", () => {
    const refused: DockerReclaimItem[] = [
      item({ kind: 'container', id: 'f4a732d020f7', label: 'sp21b-running' }),
      item({ kind: 'container', id: '000000000000', label: 'gone-already' }),
      item({ kind: 'image', id: '56f53e94e311', label: 'sp21b-keep:latest' }),
      item({ kind: 'image', id: '410766c85e52', label: 'sp21b-multi:one' }),
      item({ kind: 'volume', id: 'sp21b-named-inuse' })
    ]
    const r = parseDockerReclaimOutput(refused, REFUSED, 1)
    // docker never failed to RUN, so this is a successful read of five failed
    // removals — not a failed read.
    expect(r.ok).toBe(true)
    if (!r.ok) return
    expect(r.outcomes.map((o) => o.ok)).toEqual([false, false, false, false, false])
    expect(r.outcomes[0].error).toContain('container is running')
    expect(r.outcomes[1].error).toContain('No such container: 000000000000')
    expect(r.outcomes[2].error).toContain('image is being used by stopped container 11339eaf9fd8')
    expect(r.outcomes[3].error).toContain('image is being used by running container')
    expect(r.outcomes[4].error).toContain('volume is in use')
    expect(r.unattributed).toEqual([])
  })

  it('does not let a volume error be attributed to a container the operator also picked', () => {
    // A busy volume's refusal names the CONTAINER holding it, in full:
    // `remove data: volume is in use - [7800236b94a8…]`. Recorded against a
    // volume called `data`, and the SHORT name is the whole point of that
    // recording: references are matched longest-first, so a 12-character
    // container id sorts ahead of a four-character volume name, and a parser
    // that pools the four blocks into one body hands the volume's error to the
    // container and leaves the volume saying nothing happened. Both objects are
    // in this selection, which is the ordinary case — you clear out a stopped
    // stack's container and its volume together.
    const both: DockerReclaimItem[] = [
      item({ kind: 'container', id: '7800236b94a8', label: 'sp21b-holder' }),
      item({ kind: 'volume', id: 'data' })
    ]
    const r = parseDockerReclaimOutput(both, SHORTNAME, 1)
    expect(r.ok).toBe(true)
    if (!r.ok) return
    // The container's block is absent from this recording, so the honest answer
    // for it is that docker said nothing — NOT the volume's error.
    expect(r.outcomes[0].error).toBe('docker did not say what happened to this object')
    expect(r.outcomes[1].error).toContain('remove data: volume is in use')
  })

  it('reads the multi-tag refusal, which is by-id failing safe', () => {
    const multi = [item({ kind: 'image', id: '410766c85e52', label: 'sp21b-multi:one' })]
    const r = parseDockerReclaimOutput(multi, MULTITAG, 1)
    expect(r.ok).toBe(true)
    if (!r.ok) return
    expect(r.outcomes[0].ok).toBe(false)
    expect(r.outcomes[0].error).toContain('image is referenced in multiple repositories')
  })

  it('says nothing rather than assuming, for an object docker never mentioned', () => {
    const ghost = [item({ kind: 'network', id: 'aaaaaaaaaaaa' })]
    const r = parseDockerReclaimOutput(ghost, `${DOCKER_MARKERS.rmNetwork}\n${DOCKER_MARKERS.end}\n`, 0)
    expect(r.ok).toBe(true)
    if (!r.ok) return
    expect(r.outcomes[0].error).toBe('docker did not say what happened to this object')
  })

  it('reports a refused socket as a failed read, not as five failed removals', () => {
    const denied =
      'permission denied while trying to connect to the Docker daemon socket at unix:///var/run/docker.sock'
    const r = parseDockerReclaimOutput(
      [item({ kind: 'container', id: '4b07fd557da1' })],
      `${DOCKER_MARKERS.rmContainer}\n${denied}\n${DOCKER_MARKERS.end}\n`,
      1
    )
    expect(r.ok).toBe(false)
    if (r.ok) return
    expect(r.reason).toBe('permission-denied')
  })

  it('reports docker never having run as a failed read', () => {
    const r = parseDockerReclaimOutput(
      [item({ kind: 'container', id: '4b07fd557da1' })],
      'sh: 1: docker: not found\n',
      127
    )
    expect(r.ok).toBe(false)
    if (r.ok) return
    expect(r.reason).toBe('not-installed')
  })
})

// ---------------------------------------------------------------------------
// The number this must still never produce
// ---------------------------------------------------------------------------

describe("the headline figure, which is still docker's and not a sum", () => {
  it('is not derivable from the offer set, and the offer set does not try', () => {
    const p = buildDockerReclaimPreview(recordedDisk())
    // No total on the preview, no total on the plan. The reclaimable figure the
    // panel shows comes from `docker system df`'s own RECLAIMABLE column, where
    // docker did the arithmetic on a host that knows which layers are shared.
    for (const key of Object.keys(p)) expect(key).not.toMatch(/total|reclaimable/i)
    for (const key of Object.keys(planDockerReclaim(p.items))) expect(key).not.toMatch(/total|bytes/i)
  })

  it('would overstate the disk by 161MB on the recorded host if it summed', () => {
    // Kept as a live number rather than a comment: two images share a 152.5MB
    // base and two more share 8.658MB, so summing SIZE invents disk that is
    // not there. The offer set carries UNIQUE SIZE for exactly this reason.
    const disk = recordedDisk()
    const naive = disk.images.reduce((n, i) => n + (i.sizeBytes ?? 0), 0)
    const honest = disk.images.reduce((n, i) => n + (i.uniqueSizeBytes ?? 0), 0)
    expect(naive - honest).toBeGreaterThan(150e6)
  })
})
