import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { assessCommand, confirmationFor, type BroadcastConfirmation } from '../src/shared/broadcast'
import {
  DOCKER_ACTIONS,
  DOCKER_INSPECT_FIELDS,
  DOCKER_ITEM_SEP,
  DOCKER_MARKERS,
  DOCKER_SEP,
  DOCKER_SUB_SEP,
  buildDockerActionCommand,
  buildDockerDiskCommand,
  buildDockerDiskDetailCommand,
  buildDockerInspectCommand,
  buildDockerListCommand,
  buildDockerLogsCommand,
  buildDockerReclaimCommand,
  buildDockerStatsCommand,
  formatDockerEngineAge,
  groupByComposeProject,
  parseDockerActionOutput,
  parseDockerDiskDetailOutput,
  parseDockerDiskOutput,
  parseDockerEngineBuild,
  parseDockerInspectOutput,
  parseDockerOutput,
  parseDockerSize,
  parseDockerStatsOutput,
  planDockerAction,
  type DockerConfirmation,
  type DockerContainer,
  type DockerDiskDetail
} from '../src/shared/docker'

// Day-to-day operations, tested against output shapes copied from real docker
// and podman installs rather than invented ones.
//
// The rule every case below is really testing is the module's one rule: a
// failure must say WHICH failure it was. "Nothing here" for a permissions
// problem is just as wrong on `docker system df` as it is on `docker ps`, and
// on df it is worse, because the panel is being read during a disk-full
// incident.

const row = (...f: string[]): string => f.join(DOCKER_SEP)

const DENIED =
  'permission denied while trying to connect to the Docker daemon socket at unix:///var/run/docker.sock'

// ---------------------------------------------------------------------------
// docker system df
// ---------------------------------------------------------------------------

// Copied from docker 24.0.7 on a host that had been building for a while.
const REAL_DF = [
  'TYPE            TOTAL     ACTIVE    SIZE      RECLAIMABLE',
  'Images          31        9         12.71GB   8.216GB (64%)',
  'Containers      14        9         1.216GB   214.7MB (17%)',
  'Local Volumes   12        7         3.093GB   1.221GB (39%)',
  'Build Cache     213       0         6.417GB   6.417GB'
].join('\n')

// podman 4.9.4. Wider columns, no build cache row at all.
const PODMAN_DF = [
  'TYPE            TOTAL       ACTIVE      SIZE        RECLAIMABLE',
  'Images          3           1           1.093GB     1.093GB (100%)',
  'Containers      2           0           0B          0B (0%)',
  'Local Volumes   1           0           0B          0B (0%)'
].join('\n')

const dfOutput = (body: string): string => `${DOCKER_MARKERS.df}\n${body}\n`

describe('where the disk went', () => {
  it('reads a real docker system df', () => {
    const r = parseDockerDiskOutput(dfOutput(REAL_DF), 0)
    expect(r.ok).toBe(true)
    if (!r.ok) return
    expect(r.rows.map((x) => x.type)).toEqual(['Images', 'Containers', 'Local Volumes', 'Build Cache'])
    expect(r.rows[0]).toMatchObject({ total: 31, active: 9, size: '12.71GB' })
    expect(r.rows[0].reclaimablePercent).toBe(64)
    expect(r.rows[0].reclaimableBytes).toBeCloseTo(8.216e9, -6)
  })

  it('keeps "Local Volumes" as one type rather than two columns', () => {
    // The only type name with a space in it, and the reason the column split
    // is on two spaces rather than one.
    const r = parseDockerDiskOutput(dfOutput(REAL_DF), 0)
    expect(r.ok && r.rows[2].type).toBe('Local Volumes')
    expect(r.ok && r.rows[2].total).toBe(12)
  })

  it('reads a reclaimable figure printed without a percentage', () => {
    // docker prints Build Cache's reclaimable bare on some versions.
    const r = parseDockerDiskOutput(dfOutput(REAL_DF), 0)
    const cache = r.ok ? r.rows[3] : null
    expect(cache?.reclaimablePercent).toBeNull()
    expect(cache?.reclaimableBytes).toBeCloseTo(6.417e9, -6)
  })

  it('reads podman, which has no build cache row', () => {
    const r = parseDockerDiskOutput(dfOutput(PODMAN_DF), 0)
    expect(r.ok).toBe(true)
    if (!r.ok) return
    expect(r.rows).toHaveLength(3)
    expect(r.rows[1]).toMatchObject({ type: 'Containers', size: '0B', reclaimablePercent: 0 })
  })

  it('says "you cannot look" rather than reporting a server that uses no disk', () => {
    // The whole point. Four zeroes during a disk-full incident is the most
    // expensive lie this module could tell.
    const r = parseDockerDiskOutput(dfOutput(DENIED), 1)
    expect(r.ok).toBe(false)
    expect(!r.ok && r.reason).toBe('permission-denied')
  })

  it('does not call a stopped daemon an empty disk either', () => {
    const msg = 'Cannot connect to the Docker daemon at unix:///var/run/docker.sock. Is the docker daemon running?'
    const r = parseDockerDiskOutput(dfOutput(msg), 1)
    expect(!r.ok && r.reason).toBe('daemon-unreachable')
  })

  it('reports a missing binary when the marker never printed', () => {
    const r = parseDockerDiskOutput('bash: docker: command not found\n', 127)
    expect(!r.ok && r.reason).toBe('not-installed')
  })

  it('ignores the podman-docker shim notice', () => {
    const out = dfOutput(['Emulate Docker CLI using podman. Create /etc/containers/nodocker to quiet msg', PODMAN_DF].join('\n'))
    const r = parseDockerDiskOutput(out, 0)
    expect(r.ok && r.rows).toHaveLength(3)
  })

  it('is not a verbose dump', () => {
    // `-v` lists every image and volume by name: a page of output for a
    // paragraph of answer.
    expect(buildDockerDiskCommand()).not.toMatch(/\bdf\s+-v|--verbose/)
  })

  it('does not use --format, whose field names the two runtimes disagree about', () => {
    expect(buildDockerDiskCommand()).not.toMatch(/--format/)
  })

  it('resolves the binary and can run as root', () => {
    expect(buildDockerDiskCommand()).toContain('/usr/local/bin/docker')
    expect(buildDockerDiskCommand({ sudo: true })).toMatch(/sudo -n "\$SP_BIN" system df/)
    expect(buildDockerDiskCommand()).not.toMatch(/sudo/)
  })
})

describe('sizes as docker writes them', () => {
  it('reads the decimal units docker prints', () => {
    expect(parseDockerSize('12.71GB')).toBeCloseTo(12.71e9, -6)
    expect(parseDockerSize('214.7MB')).toBeCloseTo(214.7e6, -3)
    expect(parseDockerSize('0B')).toBe(0)
  })

  it('reads binary units too, rather than guessing and being 7% wrong', () => {
    expect(parseDockerSize('1GiB')).toBe(1024 ** 3)
    expect(parseDockerSize('45.2MiB')).toBeCloseTo(45.2 * 1024 * 1024, -2)
  })

  it('returns null rather than a number it made up', () => {
    for (const bad of ['', '-', 'lots', '12', '12 apples']) {
      expect(parseDockerSize(bad), bad).toBeNull()
    }
  })
})

// ---------------------------------------------------------------------------
// docker system df -v — the same disk, per item
// ---------------------------------------------------------------------------

// Structure recorded from a real `docker system df -v` on docker 29.5.3; see
// tests/fixtures/docker/README.md for what was recorded and what was added by
// hand, and for the gap this directory does not pretend to cover (podman).
const REAL_DFV = readFileSync(join(__dirname, 'fixtures/docker/system-df-v-docker-29.txt'), 'utf8')

const dfvOutput = (body: string, buildTime?: string): string =>
  [DOCKER_MARKERS.engine, buildTime ?? '', DOCKER_MARKERS.dfDetail, body, DOCKER_MARKERS.end].join('\n')

// Headers with nothing under them: a docker that is installed, running, and
// holding nothing at all.
const EMPTY_STORE = [
  'Images space usage:',
  '',
  'REPOSITORY   TAG       IMAGE ID   CREATED   SIZE      SHARED SIZE   UNIQUE SIZE   CONTAINERS',
  '',
  'Containers space usage:',
  '',
  'CONTAINER ID   IMAGE     COMMAND   LOCAL VOLUMES   SIZE      CREATED   STATUS    NAMES',
  '',
  'Local Volumes space usage:',
  '',
  'VOLUME NAME   LINKS     SIZE',
  '',
  'Build cache usage: 0B',
  '',
  'CACHE ID   CACHE TYPE   SIZE      CREATED   LAST USED   USAGE     SHARED'
].join('\n')

const okDetail = (out: string): DockerDiskDetail => {
  const r = parseDockerDiskDetailOutput(out, 0)
  if (!r.ok) throw new Error(`expected a readable listing, got ${r.reason}: ${r.detail}`)
  return r.disk
}

describe('which image, which volume — not which category', () => {
  it('reads all four sections of a recorded docker 29 listing', () => {
    const d = okDetail(dfvOutput(REAL_DFV))
    expect(d.images).toHaveLength(8)
    expect(d.containers).toHaveLength(7)
    expect(d.volumes).toHaveLength(4)
    // The table printed with no rows under it. Present and empty, which is a
    // different fact from absent.
    expect(d.buildCache).toHaveLength(0)
    expect(d.sections).toEqual({ images: true, containers: true, volumes: true, buildCache: true })
    expect(d.unreadable).toBe(0)
  })

  it('reads UNIQUE SIZE, which is the only honest per-image number', () => {
    // 152MB of layers, 2.105kB of them this image's own. Reporting SIZE per
    // item is how a panel tells someone to delete 152MB and frees two.
    const d = okDetail(dfvOutput(REAL_DFV))
    const listener = d.images.find((i) => i.repository === 'app-listener')
    expect(listener).toMatchObject({ tag: 'latest', size: '152MB', uniqueSize: '2.105kB' })
    expect(listener?.sharedSizeBytes).toBeCloseTo(152.5e6, -4)
    expect(listener?.uniqueSizeBytes).toBeCloseTo(2105, -1)
    expect(listener?.containers).toBe(0)
  })

  it('marks the dangling image rather than showing it as a repository called <none>', () => {
    const d = okDetail(dfvOutput(REAL_DFV))
    const dangling = d.images.filter((i) => i.dangling)
    expect(dangling).toHaveLength(1)
    expect(dangling[0]).toMatchObject({ repository: '<none>', tag: '<none>', id: 'b7d3f9a10c22' })
    // A tagged image is never dangling, however little of it is unique.
    expect(d.images.filter((i) => i.repository === 'postgres').every((i) => !i.dangling)).toBe(true)
  })

  it('survives a COMMAND containing spaces and the ellipsis docker truncates with', () => {
    // The column the `/\s{2,}/` split cannot survive: a quoted string with
    // spaces inside one cell.
    const d = okDetail(dfvOutput(REAL_DFV))
    const pgbouncer = d.containers.find((c) => c.name === 'stack-pgbouncer-1')
    expect(pgbouncer?.command).toBe('"/bin/sh -c \'set -e\\n…"')
    expect(pgbouncer?.image).toBe('example/pgbouncer:v1.25.2-p0')
    expect(pgbouncer?.size).toBe('1.99kB')
    expect(pgbouncer?.localVolumes).toBe(0)
  })

  it('reads a COMMAND containing two consecutive spaces, which the fixture does not have', () => {
    // The case the recording did not happen to contain, and the reason this
    // parser is positional rather than a `/\s{2,}/` split: a split on two
    // spaces reads THIS row as fourteen columns and puts the tail of the
    // command where LOCAL VOLUMES should be. `sh -c 'a  b'` is an ordinary
    // entrypoint, not a contrivance.
    //
    // The header and the column offsets below are the recorded ones, copied
    // verbatim from the fixture; only the COMMAND cell's contents differ.
    const body = [
      'Containers space usage:',
      '',
      'CONTAINER ID   IMAGE                                              COMMAND                   LOCAL VOLUMES   SIZE      CREATED        STATUS                     NAMES',
      'aa11bb22cc33   busybox:1.36                                       "sh -c \'a  b\'"            0               12B       2 days ago     Exited (0) 2 days ago      double-space'
    ].join('\n')
    const d = okDetail(dfvOutput(body))
    expect(d.containers).toHaveLength(1)
    expect(d.containers[0]).toMatchObject({
      id: 'aa11bb22cc33',
      image: 'busybox:1.36',
      command: '"sh -c \'a  b\'"',
      localVolumes: 0,
      size: '12B',
      status: 'Exited (0) 2 days ago',
      state: 'exited',
      name: 'double-space'
    })
  })

  it('keeps a status with spaces in it as one field, and derives the state from it', () => {
    const d = okDetail(dfvOutput(REAL_DFV))
    const up = d.containers.find((c) => c.name === 'stack-postgres-2')
    expect(up).toMatchObject({ status: 'Up 7 days (healthy)', state: 'running' })
    // `Exited (137)` is an OOM kill, and the parenthesised code is part of the
    // status rather than a column of its own.
    const exited = d.containers.find((c) => c.name === 'old-frontend')
    expect(exited).toMatchObject({ status: 'Exited (137) 2 days ago', state: 'exited', size: '412MB' })
    const created = d.containers.find((c) => c.name === 'migration-runner')
    expect(created).toMatchObject({ status: 'Created', state: 'created', localVolumes: 2 })
  })

  it('reads a volume name wider than its own column header', () => {
    // 64 hex characters under an 11-character heading. A parser that trusted
    // the header width would truncate every anonymous volume on the host.
    const d = okDetail(dfvOutput(REAL_DFV))
    const big = d.volumes.find((v) => v.sizeBytes !== null && v.sizeBytes > 1e9 && v.anonymous)
    expect(big?.name).toBe('e9c06091ebdd38a00b437a20a8cbd5d1226292e8191d1af544b9f8a087daa81e')
    expect(big?.links).toBe(1)
    expect(big?.size).toBe('1.386GB')
  })

  it('tells an unlinked anonymous volume from an unlinked NAMED one', () => {
    // There is no flag for this, only the shape of the name — and the
    // difference is whether the thing with no links is rubbish or a database
    // whose container happens to be stopped.
    const d = okDetail(dfvOutput(REAL_DFV))
    const unlinked = d.volumes.filter((v) => v.links === 0)
    expect(unlinked.map((v) => v.anonymous)).toEqual([true, false])
    expect(unlinked[1]).toMatchObject({ name: 'stack_pgdata', size: '2.41GB', anonymous: false })
  })

  it('reports an empty build cache as present and empty, not as absent', () => {
    const d = okDetail(dfvOutput(REAL_DFV))
    expect(d.sections.buildCache).toBe(true)
    expect(d.buildCache).toEqual([])
  })

  it('says a runtime printed no build cache table at all', () => {
    // podman has historically omitted it, and "no build cache on this host" is
    // a different sentence from "this runtime does not have build cache".
    const withoutCache = REAL_DFV.slice(0, REAL_DFV.indexOf('Build cache usage:'))
    const d = okDetail(dfvOutput(withoutCache))
    expect(d.sections.buildCache).toBe(false)
    expect(d.images.length).toBeGreaterThan(0)
  })

  it('reads a build cache that has entries in it', () => {
    const body = [
      'Build cache usage: 1.2GB',
      '',
      'CACHE ID       CACHE TYPE     SIZE      CREATED         LAST USED       USAGE     SHARED',
      'x7k2m9p4q1w8   regular        1.101GB   3 weeks ago     2 weeks ago     4         false',
      'b3n6v0z5t2r9   source.local   0B        3 weeks ago     2 weeks ago     11        true'
    ].join('\n')
    const d = okDetail(dfvOutput(body))
    expect(d.buildCache).toHaveLength(2)
    expect(d.buildCache[0]).toMatchObject({
      id: 'x7k2m9p4q1w8',
      type: 'regular',
      size: '1.101GB',
      lastUsed: '2 weeks ago',
      usage: 4,
      shared: 'false'
    })
  })

  it('reads a server whose store is genuinely empty as empty', () => {
    // Headers with nothing under them. The one case where an empty list is the
    // true answer, and it must not be confused with the refusals below.
    const r = parseDockerDiskDetailOutput(dfvOutput(EMPTY_STORE), 0)
    expect(r.ok).toBe(true)
    expect(r.ok && r.disk.images).toEqual([])
    expect(r.ok && r.disk.sections.images).toBe(true)
  })

  it('still reads an empty store as empty when the shell left a line on stderr', () => {
    // The reader merges stderr onto stdout, so anything the LOGIN SHELL says
    // lands after the listing. With no closing marker it fell inside the last
    // table's column context, counted as an unreadable row, and — because an
    // empty store has no readable rows to outweigh it — came back as "docker
    // returned an error that could not be classified". A fresh docker install
    // on a host that prints a locale warning is not a permissions problem, and
    // this is the exact inversion the module exists to prevent, in the place
    // it is read from: a disk-full incident.
    for (const noise of [
      'bash: warning: setlocale: LC_ALL: cannot change locale (en_GB.UTF-8)',
      'Welcome to Ubuntu 24.04.1 LTS (GNU/Linux 6.8.0-51-generic x86_64)'
    ]) {
      const r = parseDockerDiskDetailOutput(`${dfvOutput(EMPTY_STORE)}\n${noise}`, 0)
      expect(r.ok, noise).toBe(true)
      expect(r.ok && r.disk.unreadable, noise).toBe(0)
      expect(r.ok && r.disk.images, noise).toEqual([])
    }
  })

  it('does not count that same shell noise as a row of a populated server either', () => {
    const noisy = `${dfvOutput(REAL_DFV)}\nbash: warning: setlocale: LC_ALL: cannot change locale`
    const r = parseDockerDiskDetailOutput(noisy, 0)
    expect(r.ok && r.disk.unreadable).toBe(0)
    expect(r.ok && r.disk.images).toHaveLength(8)
  })

  it('ignores a warning docker slipped in without reading it as a row', () => {
    const noisy = ['Emulate Docker CLI using podman. Create /etc/containers/nodocker to quiet msg', REAL_DFV].join(
      '\n'
    )
    const d = okDetail(dfvOutput(noisy))
    expect(d.images).toHaveLength(8)
    expect(d.unreadable).toBe(0)
  })

  it('says "you cannot look" rather than reporting an empty disk', () => {
    // The rule the whole module exists for, and it is worth more here than
    // anywhere: this listing is read during a disk-full incident.
    const r = parseDockerDiskDetailOutput(dfvOutput(DENIED), 1)
    expect(r.ok).toBe(false)
    expect(!r.ok && r.reason).toBe('permission-denied')
    expect(!r.ok && r.detail).toMatch(/docker\.sock/)
  })

  it('does not call a stopped daemon an empty disk either', () => {
    const msg = 'Cannot connect to the Docker daemon at unix:///var/run/docker.sock. Is the docker daemon running?'
    const r = parseDockerDiskDetailOutput(dfvOutput(msg), 1)
    expect(!r.ok && r.reason).toBe('daemon-unreachable')
  })

  it('reports a missing binary when the marker never printed', () => {
    const r = parseDockerDiskDetailOutput('bash: docker: command not found\n', 127)
    expect(!r.ok && r.reason).toBe('not-installed')
  })

  it('refuses to report tables it could not read as an empty server', () => {
    // A runtime whose columns are not the ones assumed here. Empty lists would
    // be the same lie as the refusal cases above, wearing a different hat.
    const body = ['Images space usage:', '', 'REPO SIZE THINGS', 'some row we cannot read at all'].join('\n')
    const r = parseDockerDiskDetailOutput(dfvOutput(body), 0)
    expect(r.ok).toBe(false)
    expect(!r.ok && r.detail).toMatch(/could not read/)
  })

  it('calls a 64-character name anonymous only when it is actually hex', () => {
    // The shape is the only evidence there is, and `name.length === 64` is not
    // the shape: a named volume of exactly 64 non-hex characters would be
    // reported as generated rubbish and truncated to twelve characters in the
    // UI, which is the opposite of what it is.
    const name = 'z'.repeat(64)
    const body = [
      'Local Volumes space usage:',
      '',
      'VOLUME NAME                                                        LINKS   SIZE',
      'zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz   1       2.41GB',
      'a1b2c3d4a1b2c3d4a1b2c3d4a1b2c3d4a1b2c3d4a1b2c3d4a1b2c3d4a1b2c3d4   0       12B'
    ].join('\n')
    const d = okDetail(dfvOutput(body))
    expect(d.volumes).toHaveLength(2)
    expect(d.volumes[0]).toMatchObject({ name, anonymous: false })
    expect(d.volumes[1].anonymous).toBe(true)
  })

  it('says it does not know how many, rather than saying none', () => {
    // A runtime that omits LINKS or CONTAINERS has told us nothing about the
    // count. `Number('')` is 0, and "0 containers" is the sentence that gets an
    // image deleted — so these are null, which the panel renders as `?`.
    const volumes = [
      'Local Volumes space usage:',
      '',
      'VOLUME NAME    SIZE',
      'stack_pgdata   2.41GB'
    ].join('\n')
    const dv = okDetail(dfvOutput(volumes))
    expect(dv.volumes).toHaveLength(1)
    expect(dv.volumes[0]).toMatchObject({ name: 'stack_pgdata', links: null })

    const images = [
      'Images space usage:',
      '',
      'REPOSITORY   TAG    IMAGE ID       CREATED       SIZE',
      'nginx        1.25   206af11251e4   6 hours ago   142MB'
    ].join('\n')
    const di = okDetail(dfvOutput(images))
    expect(di.images).toHaveLength(1)
    expect(di.images[0]).toMatchObject({ repository: 'nginx', containers: null })
  })

  it('reads a row whose COMMAND contains an astral-plane character', () => {
    // docker renders through Go's tabwriter, which pads by RUNES. A JS string
    // index counts UTF-16 units, so one emoji shifts every column after it by
    // one and the whole row stops parsing — the container silently vanishes
    // from a listing whose entire job is to be complete.
    const body = [
      'Containers space usage:',
      '',
      'CONTAINER ID   IMAGE          COMMAND    LOCAL VOLUMES   SIZE   CREATED      STATUS    NAMES',
      'aa11bb22cc33   busybox:1.36   "🚀🚀🚀🚀🚀🚀"   0               12B    2 days ago   Created   rocket'
    ].join('\n')
    const d = okDetail(dfvOutput(body))
    expect(d.unreadable).toBe(0)
    expect(d.containers).toHaveLength(1)
    expect(d.containers[0]).toMatchObject({
      id: 'aa11bb22cc33',
      image: 'busybox:1.36',
      command: '"🚀🚀🚀🚀🚀🚀"',
      localVolumes: 0,
      size: '12B',
      name: 'rocket'
    })
  })

  it('keeps unreadable rows counted rather than dropping them quietly', () => {
    const body = [REAL_DFV, 'WARNING: this row belongs to no column set at all'].join('\n')
    const d = okDetail(dfvOutput(body))
    expect(d.unreadable).toBe(1)
    expect(d.buildCache).toEqual([])
  })
})

describe('how old the engine on this server is', () => {
  const buildTime = '2021-06-02T11:54:33.000000000+00:00'
  const at = (iso: string): number => Date.parse(iso)

  it('reads the build time the daemon reports about itself', () => {
    const r = parseDockerDiskDetailOutput(dfvOutput(REAL_DFV, buildTime), 0)
    expect(r.ok && r.engine).toMatchObject({ date: '2021-06-02', raw: buildTime })
  })

  it('states an absolute age, which cannot go stale and cannot be wrong', () => {
    const build = parseDockerEngineBuild(buildTime)
    expect(build).not.toBeNull()
    if (build === null) return
    expect(formatDockerEngineAge(build, at('2025-09-01T00:00:00Z'))).toBe('built 2021-06-02, 4 years ago')
    expect(formatDockerEngineAge(build, at('2021-08-20T00:00:00Z'))).toBe('built 2021-06-02, 2 months ago')
    expect(formatDockerEngineAge(build, at('2021-06-03T12:00:00Z'))).toBe('built 2021-06-02, 1 day ago')
    expect(formatDockerEngineAge(build, at('2021-06-02T18:00:00Z'))).toBe('built 2021-06-02, today')
  })

  it('says nothing about age when the two machines disagree about the date', () => {
    // A build date in the future is this laptop's clock, not a fact about that
    // host, and "built in 3 days" is not a sentence worth printing.
    const build = parseDockerEngineBuild(buildTime)
    expect(build && formatDockerEngineAge(build, at('2020-01-01T00:00:00Z'))).toBe('built 2021-06-02')
  })

  it('shows nothing at all when the runtime will not answer', () => {
    // podman's docker shim fails `.Server.*` templates with a nil-pointer
    // error. Degrading to no age line is the honest form of that; inventing a
    // date from whatever it did print is not.
    for (const bad of [
      '',
      '<no value>',
      'template: :1:9: executing "" at <.Server.BuildTime>: nil pointer evaluating *types.Version.Server',
      'Emulate Docker CLI using podman. Create /etc/containers/nodocker to quiet msg',
      '24.0.7',
      // Go's and Unix's zero times. podman's docker-compat derives BuildTime
      // from an int64 that formats as the epoch when it was never set, and
      // "built 1970-01-01, 56 years ago" is the year-24 mistake wearing a
      // timestamp. Docker did not exist before 2013.
      '1970-01-01T00:00:00Z',
      '0001-01-01T00:00:00Z',
      // Near-misses `Date.parse` accepts happily and turns into a date nobody
      // reported. This is what the shape check is for; the four above it get
      // through the shape check and are stopped by the epoch floor.
      '2021',
      '2021-06',
      '06/02/2021',
      'Wed Jun 02 2021'
    ]) {
      expect(parseDockerEngineBuild(bad), bad).toBeNull()
    }
    expect(parseDockerEngineBuild(undefined)).toBeNull()
  })

  it('reports the date the daemon printed, not the one this laptop is in', () => {
    // `new Date(at).toISOString()` normalises to UTC, so an engine built at
    // half eleven at night in Chicago was reported as having been built the
    // next day.
    const build = parseDockerEngineBuild('2021-06-02T23:30:00-05:00')
    expect(build?.date).toBe('2021-06-02')
  })

  it('does not fail the listing when the engine will not say', () => {
    // The build-time block ends in `|| true` and sits BEFORE the listing, so
    // its failure cannot take the read with it.
    const r = parseDockerDiskDetailOutput(dfvOutput(REAL_DFV, '<no value>'), 0)
    expect(r.ok).toBe(true)
    expect(r.ok && r.engine).toBeNull()
    expect(r.ok && r.disk.images.length).toBe(8)
  })

  it('asks the daemon rather than the network or a baked table of releases', () => {
    const cmd = buildDockerDiskDetailCommand()
    expect(cmd).toContain('{{.Server.BuildTime}}')
    expect(cmd).not.toMatch(/curl|wget|https?:/)
  })

  it('closes the listing with a marker, without losing its exit status', () => {
    // Without this, everything the login shell left on stderr lands inside the
    // last table's columns and is counted as a row that could not be read.
    // The status still has to be the listing's own: it is what tells a host
    // with no docker from a host with an empty store.
    const cmd = buildDockerDiskDetailCommand()
    const tail = cmd.slice(cmd.indexOf('system df -v'))
    expect(tail).toContain(DOCKER_MARKERS.end)
    expect(tail).toMatch(/SP_RC=\$\?/)
    expect(tail).toMatch(/exit \$SP_RC$/)
  })

  it('puts the block that may fail before the block that may not', () => {
    // Only the last block's exit status survives, and the parser uses that
    // status to tell a host with no docker from a host with an empty store.
    const cmd = buildDockerDiskDetailCommand()
    expect(cmd.indexOf('|| true')).toBeLessThan(cmd.indexOf('system df -v'))
    expect(cmd.slice(cmd.indexOf('system df -v'))).not.toContain('|| true')
  })
})

describe('the itemised read is built the way every other read is', () => {
  it('resolves the binary and can run as root', () => {
    expect(buildDockerDiskDetailCommand()).toContain('/usr/local/bin/docker')
    expect(buildDockerDiskDetailCommand({ sudo: true })).toMatch(/sudo -n "\$SP_BIN" system df -v/)
    expect(buildDockerDiskDetailCommand()).not.toMatch(/sudo/)
  })

  it('asks the same question with and without sudo', () => {
    const plain = buildDockerDiskDetailCommand()
    const sudo = buildDockerDiskDetailCommand({ sudo: true }).replace(/sudo -n /g, '')
    expect(sudo).toBe(plain)
  })

  it('does not use --format for the listing, whose field names the runtimes disagree about', () => {
    const cmd = buildDockerDiskDetailCommand()
    expect(cmd.slice(cmd.indexOf('system df -v'))).not.toMatch(/--format/)
  })
})

describe('the number this must never produce', () => {
  // `docker image ls` SIZE counts layers shared with other images. Summing per
  // item overstates the disk, sometimes by a multiple — and it looks correct in
  // every hand-written fixture, because a fixture has no shared layers. The
  // headline stays with the non-verbose `system df`, where docker did the
  // arithmetic on the host.
  it('does not offer a total anywhere in the itemised shape', () => {
    const d = okDetail(dfvOutput(REAL_DFV))
    for (const key of Object.keys(d)) expect(key).not.toMatch(/total/i)
  })

  it('proves the sum would be wrong on the recorded server', () => {
    const d = okDetail(dfvOutput(REAL_DFV))
    const summed = d.images.reduce((n, i) => n + (i.sizeBytes ?? 0), 0)
    const honest = d.images.reduce((n, i) => n + (i.uniqueSizeBytes ?? 0), 0)
    // Two images share a 152.5MB base and two more share 8.658MB, so the naive
    // sum invents roughly 161MB of disk that does not exist.
    expect(summed - honest).toBeGreaterThan(150e6)
  })

  it('leaves the headline where docker computed it', () => {
    const panel = read('src/renderer/src/components/docker/DockerPanel.tsx')
    // Scoped to the ONE component that renders per-item sizes, because that is
    // the only place this bug can live. Counting `.reduce(` across the whole
    // file was neither necessary nor sufficient: it fails on any unrelated
    // reduce added anywhere in a thousand lines, and it passes a hand-rolled
    // `let n = 0; for (const i of images) n += i.uniqueSizeBytes ?? 0`, which
    // IS the bug.
    const at = panel.indexOf('function DiskItems(')
    expect(at, 'DiskItems was renamed or moved; this guard needs to follow it').toBeGreaterThan(-1)
    // From the brace that opens the body — not from the signature, whose
    // destructured props close with a `}` of their own — to the first `}` in
    // the first column, which is the end of the function.
    const opens = panel.indexOf('React.JSX.Element {', at)
    expect(opens, 'DiskItems no longer has the signature this guard looks for').toBeGreaterThan(at)
    const rest = panel.slice(opens)
    const closes = rest.indexOf('\n}')
    const diskItems = rest.slice(0, closes === -1 ? undefined : closes)
    // Any accumulation over the per-item byte fields, however it is spelled.
    expect(diskItems).not.toMatch(/\.reduce\(/)
    expect(diskItems).not.toMatch(/\+=/)
    expect(diskItems).not.toMatch(/SizeBytes[^\n]*\+/)
    // A computed total, not the word — the tooltip legitimately says "in
    // total" when the runtime gave no unique size and the figure IS the total.
    expect(diskItems).not.toMatch(/\b(?:const|let|var)\s+\w*[Tt]otal/)
    // The one total the panel does show is docker's own, computed on the host
    // where the layer sharing is known — and it lives outside this component.
    expect(panel.slice(0, at)).toMatch(/reclaimableBytes \?\? 0/)
  })
})

// ---------------------------------------------------------------------------
// compose grouping
// ---------------------------------------------------------------------------

const listOutput = (opts: { version?: string; compose?: string; ps: string[] }): string =>
  [
    opts.version ?? '24.0.7',
    DOCKER_MARKERS.compose,
    opts.compose ?? '',
    DOCKER_MARKERS.ps,
    ...opts.ps
  ].join('\n')

describe('grouping by compose project, which is how people think about a server', () => {
  const ps = [
    row('aaa1', 'shop-web-1', 'shop/web:1.4', 'running', 'Up 3 hours', '0.0.0.0:80->80/tcp', 'now'),
    row('bbb2', 'shop-db-1', 'postgres:16', 'running', 'Up 3 hours', '', 'now'),
    row('ccc3', 'watchtower', 'containrrr/watchtower', 'running', 'Up 9 days', '', 'now')
  ]

  it('attaches the labels docker reports', () => {
    const out = listOutput({
      compose: [row('aaa1', 'shop', 'web'), row('bbb2', 'shop', 'db'), row('ccc3', '', '')].join('\n'),
      ps
    })
    const r = parseDockerOutput(out, 0)
    expect(r.ok).toBe(true)
    if (!r.ok) return
    expect(r.containers[0]).toMatchObject({ composeProject: 'shop', composeService: 'web' })
    expect(r.containers[2].composeProject).toBeUndefined()
    expect(r.composeLabels).toBe('read')
  })

  it('says the labels were unreadable rather than showing everything ungrouped', () => {
    // podman's ps template has no .Label method, and the difference between
    // "nothing here uses compose" and "this runtime would not tell me" is the
    // difference between a fact and an assumption.
    const out = listOutput({
      version: '4.9.4',
      compose:
        'Error: template: list:1:14: executing "list" at <.Label>: can\'t evaluate field Label in type *entities.ListContainer',
      ps
    })
    const r = parseDockerOutput(out, 0)
    expect(r.ok).toBe(true)
    if (!r.ok) return
    // The container list still came back. That is the point of asking
    // separately: the grouping is the convenience, the list is the feature.
    expect(r.containers).toHaveLength(3)
    expect(r.composeLabels).toBe('unavailable')
  })

  it('is silent about grouping when the collector never asked', () => {
    const out = ['24.0.7', DOCKER_MARKERS.ps, ...ps].join('\n')
    const r = parseDockerOutput(out, 0)
    expect(r.ok && r.composeLabels).toBeUndefined()
    expect(r.ok && r.containers[0].composeProject).toBeUndefined()
  })

  it('does not let the compose block break the version, the rows or the diagnosis', () => {
    const out = listOutput({ compose: row('aaa1', 'shop', 'web'), ps })
    const r = parseDockerOutput(out, 0)
    expect(r.ok && r.version).toBe('24.0.7')
    expect(r.ok && r.containers).toHaveLength(3)
  })

  it('still reports a server with no docker as not installed', () => {
    // The regression the block ordering exists to prevent: the compose command
    // ends in `|| true`, so putting it AFTER `docker ps` would replace the 127
    // that says the binary is missing with a 0 that says the host is quiet.
    const out = [
      'bash: docker: command not found',
      DOCKER_MARKERS.compose,
      'bash: docker: command not found',
      DOCKER_MARKERS.ps,
      'bash: docker: command not found'
    ].join('\n')
    const r = parseDockerOutput(out, 127)
    expect(!r.ok && r.reason).toBe('not-installed')
  })

  it('puts the compose block before the list in the built command', () => {
    const cmd = buildDockerListCommand()
    expect(cmd.indexOf(DOCKER_MARKERS.compose)).toBeLessThan(cmd.indexOf(DOCKER_MARKERS.ps))
    // …and the ps block, whose exit status is the diagnosis, is last and NOT
    // protected by `|| true`.
    expect(cmd.slice(cmd.indexOf(DOCKER_MARKERS.ps))).not.toMatch(/\|\| true/)
  })

  it('asks for labels in a way that cannot take the listing down with it', () => {
    expect(buildDockerListCommand()).toMatch(/com\.docker\.compose\.project.*\|\| true/s)
  })

  it('groups projects first and leaves strays visible at the end', () => {
    const mk = (name: string, project?: string, service?: string): DockerContainer => ({
      id: name,
      shortId: name,
      name,
      image: 'x',
      state: 'running',
      status: 'Up',
      ports: '',
      createdAt: 'now',
      composeProject: project,
      composeService: service
    })
    const groups = groupByComposeProject([
      mk('loose'),
      mk('zeta-web-1', 'zeta', 'web'),
      mk('alpha-db-1', 'alpha', 'db'),
      mk('alpha-web-1', 'alpha', 'web')
    ])
    expect(groups.map((g) => g.project)).toEqual(['alpha', 'zeta', null])
    expect(groups[0].containers.map((c) => c.composeService)).toEqual(['db', 'web'])
    // A stray container nobody's compose file owns is frequently the thing
    // being looked for, so it gets a bucket rather than being dropped.
    expect(groups[2].containers.map((c) => c.name)).toEqual(['loose'])
  })

  it('has no ungrouped bucket when there is nothing to put in it', () => {
    expect(groupByComposeProject([])).toEqual([])
  })
})

// ---------------------------------------------------------------------------
// inspect
// ---------------------------------------------------------------------------

const inspectRow = (over: Partial<Record<number, string>> = {}): string => {
  const f = [
    '9f8e7d6c5b4a39281726354453627180a1b2c3d4e5f60718293a4b5c6d7e8f90',
    '/shop-web-1',
    'shop/web:1.4',
    'sha256:2b7c1a0f8e9d6c5b4a39281726354453627180a1b2c3d4e5f60718293a4b5c6d',
    'running',
    '0',
    '2026-08-30T09:14:02.113244871Z',
    '2026-08-28T11:02:44.9931Z',
    'unless-stopped',
    '0',
    '3',
    '14',
    [`80/tcp${DOCKER_SUB_SEP}0.0.0.0:8080 `, `443/tcp${DOCKER_SUB_SEP}`].join(DOCKER_ITEM_SEP) + DOCKER_ITEM_SEP,
    [
      `bind${DOCKER_SUB_SEP}/srv/shop/config${DOCKER_SUB_SEP}/etc/shop${DOCKER_SUB_SEP}ro`,
      `volume${DOCKER_SUB_SEP}shop_media${DOCKER_SUB_SEP}/var/lib/shop/media${DOCKER_SUB_SEP}rw`
    ].join(DOCKER_ITEM_SEP) + DOCKER_ITEM_SEP,
    `shop_default${DOCKER_SUB_SEP}172.19.0.4${DOCKER_ITEM_SEP}`,
    'json-file'
  ]
  for (const [k, v] of Object.entries(over)) f[Number(k)] = v as string
  return f.join(DOCKER_SEP)
}

const inspectOutput = (health: string, body: string): string =>
  [DOCKER_MARKERS.health, health, DOCKER_MARKERS.inspect, body].join('\n')

describe('what a container is actually wired to', () => {
  it('reads the fields an operator asks for', () => {
    const r = parseDockerInspectOutput(inspectOutput('healthy', inspectRow()), 0)
    expect(r.ok).toBe(true)
    if (!r.ok) return
    const i = r.inspect
    expect(i.name).toBe('shop-web-1')
    expect(i.shortId).toBe('9f8e7d6c5b4a')
    expect(i.image).toBe('shop/web:1.4')
    expect(i.imageId).toMatch(/^sha256:/)
    expect(i.restartPolicy).toBe('unless-stopped')
    expect(i.restartCount).toBe(3)
    expect(i.health).toBe('healthy')
    expect(i.logDriver).toBe('json-file')
  })

  it('separates a published port from one that is merely exposed', () => {
    const r = parseDockerInspectOutput(inspectOutput('healthy', inspectRow()), 0)
    expect(r.ok && r.inspect.ports).toEqual([
      { container: '80/tcp', host: '0.0.0.0:8080' },
      { container: '443/tcp', host: '' }
    ])
  })

  it('keeps a mount, its direction and whether it is writable', () => {
    const r = parseDockerInspectOutput(inspectOutput('', inspectRow()), 0)
    expect(r.ok && r.inspect.mounts).toEqual([
      { type: 'bind', source: '/srv/shop/config', destination: '/etc/shop', mode: 'ro' },
      { type: 'volume', source: 'shop_media', destination: '/var/lib/shop/media', mode: 'rw' }
    ])
  })

  it('reports env as a COUNT and nothing else', () => {
    const r = parseDockerInspectOutput(inspectOutput('', inspectRow()), 0)
    expect(r.ok && r.inspect.envCount).toBe(14)
    // Nothing on the parsed object is a place a value could hide.
    expect(JSON.stringify(r)).not.toMatch(/PASSWORD|SECRET|_KEY|postgres:\/\//i)
  })

  it('says "no healthcheck" rather than "unknown health"', () => {
    // A container with no healthcheck has a nil .State.Health, so the probe
    // prints a template error to a stream that is discarded. A chip reading
    // "unknown" would be a claim about the container; null is the truth.
    const noHealth = inspectOutput('', inspectRow())
    expect(parseDockerInspectOutput(noHealth, 0).ok).toBe(true)
    const r = parseDockerInspectOutput(noHealth, 0)
    expect(r.ok && r.inspect.health).toBeNull()
  })

  it('reads an unhealthy container', () => {
    const r = parseDockerInspectOutput(inspectOutput('unhealthy', inspectRow()), 0)
    expect(r.ok && r.inspect.health).toBe('unhealthy')
  })

  it('reads a stopped container that exited badly', () => {
    const r = parseDockerInspectOutput(
      inspectOutput('', inspectRow({ 4: 'exited', 5: '137' })),
      0
    )
    expect(r.ok && r.inspect.status).toBe('exited')
    expect(r.ok && r.inspect.exitCode).toBe(137)
  })

  it('reads a container with no ports, no mounts and no networks', () => {
    const r = parseDockerInspectOutput(inspectOutput('', inspectRow({ 12: '', 13: '', 14: '' })), 0)
    expect(r.ok && r.inspect.ports).toEqual([])
    expect(r.ok && r.inspect.mounts).toEqual([])
    expect(r.ok && r.inspect.networks).toEqual([])
  })

  it('says a permissions problem is one, rather than showing a blank container', () => {
    const r = parseDockerInspectOutput(inspectOutput('', DENIED), 1)
    expect(!r.ok && r.reason).toBe('permission-denied')
  })

  it('says so when a runtime renders a different number of fields', () => {
    const r = parseDockerInspectOutput(inspectOutput('', row('a', 'b', 'c')), 0)
    expect(r.ok).toBe(false)
    expect(!r.ok && r.detail).toMatch(new RegExp(`${DOCKER_INSPECT_FIELDS}`))
  })

  it('reports a container docker has never heard of', () => {
    const r = parseDockerInspectOutput(
      inspectOutput('', 'Error: No such object: ghost'),
      1
    )
    expect(r.ok).toBe(false)
    expect(!r.ok && r.detail).toMatch(/No such object/)
  })
})

describe('the inspect command itself', () => {
  const cmd = buildDockerInspectCommand('shop-web-1')

  it('never asks for the whole object', () => {
    // `docker inspect ref` with no template dumps Config.Env, which on a real
    // host is database URLs and API keys. Every invocation is templated.
    const invocations = cmd.match(/inspect\s+\S+/g) ?? []
    expect(invocations.length).toBeGreaterThan(0)
    for (const inv of invocations) expect(inv).toMatch(/inspect\s+--format/)
  })

  it('asks for the COUNT of environment variables, never the values', () => {
    expect(cmd).toContain('{{len .Config.Env}}')
    expect(cmd).not.toMatch(/range[^}]*\.Config\.Env/)
    expect(cmd).not.toMatch(/\{\{\.Config\.Env\}\}/)
  })

  it('does not read the other two fields secrets end up in', () => {
    // `--password` in an entrypoint is not rare, and a command line is as good
    // a hiding place for a credential as an environment variable.
    expect(cmd).not.toMatch(/\.Config\.Cmd/)
    expect(cmd).not.toMatch(/Entrypoint/)
  })

  it('quotes the template with single quotes, because it contains $p and $b', () => {
    // The trap this pins: inside a double-quoted shell word the shell expands
    // $p, $b, $n and $c to nothing, and every container silently reports no
    // ports, no mounts and no networks. The bug would look like data, not like
    // a quoting error.
    expect(cmd).toContain("--format '{{.Id}}")
    expect(cmd).toMatch(/\$p/)
    for (const frag of cmd.split('--format ').slice(1)) {
      expect(frag.startsWith("'")).toBe(true)
    }
  })

  it('runs the health probe first so the exit status belongs to the inspect', () => {
    // The health probe ends in `|| true`. Last, it would erase the 127 that
    // says docker is not installed.
    expect(cmd.indexOf(DOCKER_MARKERS.health)).toBeLessThan(cmd.indexOf(DOCKER_MARKERS.inspect))
    expect(cmd.slice(cmd.indexOf(DOCKER_MARKERS.inspect))).not.toMatch(/\|\| true/)
  })

  it('refuses a reference it cannot prove safe rather than escaping it', () => {
    for (const bad of ['a; rm -rf /', '$(id)', '`id`', 'a b', '--format={{json .}}', '']) {
      expect(() => buildDockerInspectCommand(bad), bad).toThrow(/refusing/)
    }
  })

  it('can run as root and resolves the binary either way', () => {
    expect(buildDockerInspectCommand('web', { sudo: true })).toMatch(/sudo -n "\$SP_BIN" inspect/)
    expect(buildDockerInspectCommand('web')).toContain('/opt/homebrew/bin/docker')
  })
})

// ---------------------------------------------------------------------------
// stats
// ---------------------------------------------------------------------------

const statsOutput = (body: string): string => `${DOCKER_MARKERS.stats}\n${body}\n`

describe('CPU and memory, one shot', () => {
  const body = [
    row('shop-web-1', '2.41%', '182.7MiB / 3.842GiB', '4.64%', '1.44GB / 3.21GB', '112MB / 2.4GB'),
    row('shop-db-1', '0.12%', '45.2MiB / 3.842GiB', '1.15%', '900kB / 1.2MB', '0B / 0B')
  ].join('\n')

  it('reads a real stats table', () => {
    const r = parseDockerStatsOutput(statsOutput(body), 0)
    expect(r.ok).toBe(true)
    if (!r.ok) return
    expect(r.stats[0]).toMatchObject({ name: 'shop-web-1', cpuPercent: 2.41, memPercent: 4.64 })
    expect(r.stats[0].memUsage).toBe('182.7MiB / 3.842GiB')
  })

  it('reports a container it could not sample as unknown, not as idle', () => {
    // docker prints `--` for a container whose cgroup it cannot read. Zero
    // would read as "this container is doing nothing", which is a diagnosis.
    const r = parseDockerStatsOutput(statsOutput(row('x', '--', '-- / --', '--', '-- / --', '-- / --')), 0)
    expect(r.ok && r.stats[0].cpuPercent).toBeNull()
    expect(r.ok && r.stats[0].memPercent).toBeNull()
  })

  it('does not render a refused socket as a server with no load', () => {
    const r = parseDockerStatsOutput(statsOutput(DENIED), 1)
    expect(!r.ok && r.reason).toBe('permission-denied')
  })

  it('ignores the podman shim notice printed before the table', () => {
    const out = statsOutput(
      ['Emulate Docker CLI using podman. Create /etc/containers/nodocker to quiet msg', body].join('\n')
    )
    expect(parseDockerStatsOutput(out, 0).ok).toBe(true)
  })

  it('does not stream', () => {
    expect(buildDockerStatsCommand(['web'])).toMatch(/stats --no-stream/)
  })

  it('never samples the whole server by accident', () => {
    // Bare `docker stats` samples every running container. "Everything" is not
    // a target the caller chose.
    expect(() => buildDockerStatsCommand([])).toThrow(/refusing/)
    expect(() => buildDockerStatsCommand(new Array(101).fill('web'))).toThrow(/refusing/)
  })

  it('refuses a reference it cannot prove safe', () => {
    expect(() => buildDockerStatsCommand(['web', 'a; reboot'])).toThrow(/refusing/)
  })

  it('leaves out the one field the two runtimes spell differently', () => {
    // docker says .PIDs, podman says .PIDS, Go templates are case-sensitive,
    // and a wrong field name fails the whole table rather than one column.
    expect(buildDockerStatsCommand(['web'])).not.toMatch(/\.PIDs|\.PIDS/)
  })
})

// ---------------------------------------------------------------------------
// lifecycle
// ---------------------------------------------------------------------------

describe('how hard the user has to press', () => {
  it('does not nag about starting one container', () => {
    // Start is additive, it is undone by the stop button next to it, and the
    // user pressed a button labelled Start. Nagging on the safe case is how
    // people learn to click through the dangerous one.
    expect(planDockerAction('start', ['a']).confirmation).toEqual({ kind: 'none' })
  })

  it('asks before stopping or restarting one container', () => {
    // Both interrupt every connection the container is serving, and
    // shared/broadcast.ts independently classifies `docker stop` as elevated —
    // which on a single target is exactly a confirm step.
    expect(planDockerAction('stop', ['a']).confirmation).toEqual({ kind: 'confirm' })
    expect(planDockerAction('restart', ['a']).confirmation).toEqual({ kind: 'confirm' })
    expect(planDockerAction('stop', ['a']).risk).toBe('elevated')
  })

  it('makes the user type the verb for a fan-out', () => {
    // Stopping a compose project takes a stack down, and a misclick on a group
    // header should not be able to do that.
    expect(planDockerAction('restart', ['a', 'b']).confirmation).toEqual({
      kind: 'type-to-confirm',
      phrase: 'RESTART'
    })
    expect(planDockerAction('start', ['a', 'b']).confirmation).toEqual({
      kind: 'type-to-confirm',
      phrase: 'START'
    })
  })

  it('names the verb rather than a generic word', () => {
    // A phrase retyped for every action is a phrase typed without reading.
    const phrases = DOCKER_ACTIONS.map((a) => {
      const c = planDockerAction(a, ['x', 'y']).confirmation
      return c.kind === 'type-to-confirm' ? c.phrase : null
    })
    expect(new Set(phrases).size).toBe(DOCKER_ACTIONS.length)
    expect(phrases).not.toContain('RUN')
  })

  it('says why, in words a dialog can show', () => {
    expect(planDockerAction('stop', ['a']).reasons.join()).toMatch(/connection/)
    expect(planDockerAction('restart', ['a', 'b', 'c']).reasons.join()).toMatch(/3 containers/)
  })

  it('never returns "just do it" for an empty selection', () => {
    expect(planDockerAction('stop', []).confirmation.kind).not.toBe('none')
  })
})

describe('the lifecycle command', () => {
  it('builds the three verbs and nothing else', () => {
    expect(buildDockerActionCommand('restart', ['web'])).toMatch(/"\$SP_BIN" restart web 2>&1/)
    for (const bad of ['rm', 'kill', 'prune', 'down', 'exec', 'run', 'stop; rm -rf /']) {
      expect(() => buildDockerActionCommand(bad as never, ['web']), bad).toThrow(/refusing/)
    }
  })

  it('refuses references it cannot prove safe rather than escaping them', () => {
    for (const bad of ['a; rm -rf /', '$(id)', '`id`', '--volumes', 'a b']) {
      expect(() => buildDockerActionCommand('stop', [bad]), bad).toThrow(/refusing/)
    }
    expect(() => buildDockerActionCommand('stop', [])).toThrow(/refusing/)
    expect(() => buildDockerActionCommand('stop', new Array(51).fill('web'))).toThrow(/refusing/)
  })

  it('validates the stop grace period, which also arrives over IPC', () => {
    expect(buildDockerActionCommand('stop', ['web'], { timeoutSec: 30 })).toMatch(/stop -t 30 web/)
    for (const bad of [-1, 1.5, NaN, 99999, '30' as unknown as number]) {
      expect(() => buildDockerActionCommand('stop', ['web'], { timeoutSec: bad }), String(bad)).toThrow(/refusing/)
    }
    // `docker start` has no such flag; accepting it would build a broken
    // command rather than saying no.
    expect(() => buildDockerActionCommand('start', ['web'], { timeoutSec: 10 })).toThrow(/refusing/)
  })

  it('runs as root only when told to', () => {
    expect(buildDockerActionCommand('stop', ['web'])).not.toMatch(/sudo/)
    expect(buildDockerActionCommand('stop', ['web'], { sudo: true })).toMatch(/sudo -n "\$SP_BIN" stop/)
  })
})

describe('what happened to each container', () => {
  const act = (body: string): string => `${DOCKER_MARKERS.act}\n${body}\n`

  it('reads docker echoing the containers it acted on', () => {
    const r = parseDockerActionOutput(['web', 'db'], act('web\ndb'), 0)
    expect(r.ok).toBe(true)
    if (!r.ok) return
    expect(r.outcomes).toEqual([
      { ref: 'web', ok: true },
      { ref: 'db', ok: true }
    ])
  })

  it('keeps a partial fan-out per container rather than as one exit code', () => {
    // "The command exited 1" says nothing about which of the two is still up,
    // and that is the only question anyone asks afterwards.
    const out = act(['web', 'Error response from daemon: No such container: db'].join('\n'))
    const r = parseDockerActionOutput(['web', 'db'], out, 1)
    expect(r.ok).toBe(true)
    if (!r.ok) return
    expect(r.outcomes[0]).toEqual({ ref: 'web', ok: true })
    expect(r.outcomes[1].ok).toBe(false)
    expect(r.outcomes[1].error).toMatch(/No such container/)
  })

  it('does not let one container claim another container’s error', () => {
    // `web` is a prefix of `web-worker`, and attributing longest-first is what
    // stops the shorter name swallowing the longer one's failure.
    const out = act(['web', 'Error response from daemon: cannot stop container: web-worker: permission denied'].join('\n'))
    const r = parseDockerActionOutput(['web', 'web-worker'], out, 1)
    expect(r.ok && r.outcomes[0]).toEqual({ ref: 'web', ok: true })
    expect(r.ok && r.outcomes[1].ok).toBe(false)
  })

  it('does not claim success for a container docker never mentioned', () => {
    const r = parseDockerActionOutput(['web', 'db'], act('web'), 0)
    expect(r.ok && r.outcomes[1]).toMatchObject({ ok: false })
    expect(r.ok && r.outcomes[1].error).toMatch(/did not say/)
  })

  it('reports a refused socket as a refused socket, not as "nothing happened"', () => {
    const r = parseDockerActionOutput(['web'], act(DENIED), 1)
    expect(r.ok).toBe(false)
    expect(!r.ok && r.reason).toBe('permission-denied')
  })

  it('reports a dead daemon rather than a container that would not stop', () => {
    const msg = 'Cannot connect to the Docker daemon at unix:///var/run/docker.sock. Is the docker daemon running?'
    const r = parseDockerActionOutput(['web'], act(msg), 1)
    expect(!r.ok && r.reason).toBe('daemon-unreachable')
  })

  it('reports a missing binary when the marker never printed', () => {
    const r = parseDockerActionOutput(['web'], 'bash: docker: command not found\n', 127)
    expect(!r.ok && r.reason).toBe('not-installed')
  })

  it('keeps lines it could not attribute rather than dropping them', () => {
    const r = parseDockerActionOutput(['web'], act('web\nWARNING: No swap limit support'), 0)
    expect(r.ok && r.unattributed).toEqual(['WARNING: No swap limit support'])
  })
})

// ---------------------------------------------------------------------------
// the line this module does not cross
// ---------------------------------------------------------------------------

describe('what cannot be built at all', () => {
  // Every builder in the module EXCEPT the reclaim one, which exists to remove
  // things and is held to its own rules in tests/dockerReclaim.test.ts.
  const everything = (): string[] => [
    buildDockerListCommand(),
    buildDockerListCommand({ sudo: true }),
    buildDockerDiskCommand(),
    buildDockerDiskDetailCommand(),
    buildDockerDiskDetailCommand({ sudo: true }),
    buildDockerInspectCommand('web'),
    buildDockerStatsCommand(['web']),
    buildDockerLogsCommand('web'),
    ...DOCKER_ACTIONS.map((a) => buildDockerActionCommand(a, ['web']))
  ]

  it('has no builder but the reclaim one that can remove anything', () => {
    // Removing a container is recoverable only if you can reconstruct how it
    // was run; removing a volume is not recoverable at all. Exactly ONE builder
    // in this module is allowed to say so, it takes an explicit list of ids,
    // and it is the one deliberately left out of `everything()` above. A `rm`
    // appearing in the list command, or the stats command, or the log tailer,
    // is this feature having leaked into a read.
    for (const cmd of everything()) {
      expect(cmd, cmd.slice(0, 60)).not.toMatch(/\b(rm|rmi)\b/)
      expect(cmd, cmd.slice(0, 60)).not.toMatch(/\bprune\b/)
      expect(cmd, cmd.slice(0, 60)).not.toMatch(/\bvolume\s+(rm|prune)/)
    }
  })

  it('has no prune, in any spelling, and that invariant got STRONGER', () => {
    // `docker system prune` deletes every stopped container and — with the flag
    // people habitually add — every unused volume, where "unused" means "not
    // attached right now". Its blast radius is not knowable from the UI that
    // would offer it.
    //
    // Reclaim-by-id does not soften this; it is the reason it holds. The whole
    // point of removing by id is that the blast radius IS the list, so a prune
    // appearing anywhere — including inside the reclaim builder, which is the
    // one place it would look reasonable — is the feature having reverted to
    // the thing it was built to replace. So the reclaim command is checked
    // here too, and only for this.
    const withReclaim = [
      ...everything(),
      buildDockerReclaimCommand([
        { kind: 'container', id: '4b07fd557da1', label: 'x', size: '0B', sizeBytes: 0 },
        { kind: 'image', id: 'cfa60c5d01ea', label: 'y', size: '0B', sizeBytes: 0 },
        { kind: 'volume', id: 'pgdata', label: 'pgdata', size: '0B', sizeBytes: 0 },
        { kind: 'network', id: '41263af10316', label: 'z', size: '0B', sizeBytes: 0 }
      ]),
      buildDockerReclaimCommand([{ kind: 'image', id: 'cfa60c5d01ea', label: 'y', size: '0B', sizeBytes: 0 }], {
        sudo: true
      })
    ]
    for (const cmd of withReclaim) {
      expect(cmd).not.toMatch(/\bprune\b/)
      expect(cmd).not.toMatch(/system\s+prune|image\s+prune|builder\s+prune|volume\s+prune|network\s+prune/)
    }
  })

  it('cannot kill, only stop', () => {
    // stop sends SIGTERM and waits; kill does not, and the difference is
    // whether a database finishes its write.
    for (const cmd of everything()) expect(cmd).not.toMatch(/\bkill\b/)
    expect(DOCKER_ACTIONS).not.toContain('kill')
  })

  it('cannot start a shell', () => {
    for (const cmd of everything()) expect(cmd).not.toMatch(/\bexec\b|\brun\b/)
  })
})

describe('the log window, which also arrives over IPC', () => {
  it('is unchanged when nothing is asked for', () => {
    expect(buildDockerLogsCommand('web', 500)).toContain('"$SP_BIN" logs --tail 500 web 2>&1')
  })

  it('adds timestamps and a relative window when asked', () => {
    expect(buildDockerLogsCommand('web', 200, false, { timestamps: true, since: '10m' })).toContain(
      '"$SP_BIN" logs --tail 200 --timestamps --since 10m web 2>&1'
    )
  })

  it('refuses a window it cannot prove safe rather than escaping it', () => {
    for (const bad of ['10m; reboot', '$(id)', '2026-01-01', '10y', '', 10 as unknown as string]) {
      expect(() => buildDockerLogsCommand('web', 200, false, { since: bad as string }), String(bad)).toThrow(
        /refusing/
      )
    }
  })

  it('brings the binary resolver with it when it runs as root', () => {
    const cmd = buildDockerLogsCommand('web', 200, false, { sudo: true })
    expect(cmd).toContain('/usr/local/bin/docker')
    expect(cmd).toMatch(/sudo -n "\$SP_BIN" logs --tail 200 web 2>&1/)
  })
})

// ---------------------------------------------------------------------------
// The approval model, and who is allowed to reach any of this
// ---------------------------------------------------------------------------

describe("the approval model is broadcast's, not a second dialect of it", () => {
  it('has a confirmation shape the two can exchange', () => {
    // Declared separately so the docker module does not depend on the
    // broadcast module being enabled — but if the shapes drift, this stops
    // compiling, which is the point of writing it down.
    const fromDocker: DockerConfirmation = { kind: 'type-to-confirm', phrase: 'STOP' }
    const asBroadcast: BroadcastConfirmation = fromDocker
    const backAgain: DockerConfirmation = asBroadcast
    expect(backAgain).toEqual(fromDocker)
  })

  it('reaches the same verdict broadcast reaches about `docker stop`', () => {
    // Two subsystems, written apart, agreeing that stopping a container on one
    // target is a confirm step. That agreement is the model working rather
    // than two people's taste happening to line up.
    expect(assessCommand('docker stop web').risk).toBe('elevated')
    expect(confirmationFor('elevated', 1)).toEqual({ kind: 'confirm' })
    expect(planDockerAction('stop', ['web']).confirmation).toEqual({ kind: 'confirm' })
  })

  it('escalates a fan-out, exactly as broadcast escalates one', () => {
    expect(planDockerAction('stop', ['a', 'b']).confirmation.kind).toBe('type-to-confirm')
  })
})

const read = (p: string): string => readFileSync(join(__dirname, '..', p), 'utf8')

describe('what must NOT be able to reach this', () => {
  it('is not exposed to the MCP bridge', () => {
    // An agent gets execute_command gated per server against an access group.
    // Restarting a container, or reading a host's disk usage, is a different
    // risk with a different consent story; growing one because the UI did
    // would be an accident rather than a decision.
    const mcp = read('src/main/services/mcpServer.ts')
    for (const forbidden of [
      'buildDockerActionCommand',
      'buildDockerDiskCommand',
      'buildDockerDiskDetailCommand',
      'buildDockerInspectCommand',
      'buildDockerStatsCommand',
      'planDockerAction',
      'DockerReader',
      'docker system df',
      'system df -v',
      'docker inspect',
      'docker restart'
    ]) {
      expect(mcp, forbidden).not.toContain(forbidden)
    }
  })

  it('cannot act without going through a plan', () => {
    // The single call site is what makes the model enforceable by reading.
    // A second `act(` anywhere in the panel would be a path around the dialog.
    const panel = read('src/renderer/src/components/docker/DockerPanel.tsx')
    expect(panel.match(/\.act\?\.\(/g) ?? []).toHaveLength(1)
    expect(panel).toMatch(/planDockerAction\(action, refs\)/)
    // …and the only branch that skips the dialog is the one the plan asks for.
    expect(panel).toMatch(/plan\.confirmation\.kind === 'none'/)
  })

  it('never offers to show an environment variable', () => {
    const panel = read('src/renderer/src/components/docker/DockerPanel.tsx')
    expect(panel).toMatch(/envCount/)
    expect(panel).not.toMatch(/envValues|\.env\b|showEnv/)
  })
})

describe('template quoting, which fails silently when it is wrong', () => {
  it('escapes the label key so the shell hands docker a quoted template', () => {
    // The compose format is a double-quoted shell word containing a
    // double-quoted Go template argument. Drop the backslashes and the shell
    // ends the word early, docker gets `{{.Label` and renders nothing — a
    // grouping that is silently always empty rather than an error anyone sees.
    expect(buildDockerListCommand()).toContain('{{.Label \\"com.docker.compose.project\\"}}')
  })

  it('renders exactly the number of fields the inspect parser expects', () => {
    const cmd = buildDockerInspectCommand('web')
    const fmt = cmd.slice(cmd.lastIndexOf("--format '") + "--format '".length)
    expect(fmt.slice(0, fmt.indexOf("'")).split(DOCKER_SEP)).toHaveLength(DOCKER_INSPECT_FIELDS)
  })
})
