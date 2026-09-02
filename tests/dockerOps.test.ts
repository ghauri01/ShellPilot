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
  buildDockerInspectCommand,
  buildDockerListCommand,
  buildDockerLogsCommand,
  buildDockerStatsCommand,
  groupByComposeProject,
  parseDockerActionOutput,
  parseDockerDiskOutput,
  parseDockerInspectOutput,
  parseDockerOutput,
  parseDockerSize,
  parseDockerStatsOutput,
  planDockerAction,
  type DockerConfirmation,
  type DockerContainer
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

  it('says "you cannot look" rather than reporting a host that uses no disk', () => {
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

describe('grouping by compose project, which is how people think about a host', () => {
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

  it('still reports a host with no docker as not installed', () => {
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

  it('does not render a refused socket as a host with no load', () => {
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

  it('never samples the whole host by accident', () => {
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
  const everything = (): string[] => [
    buildDockerListCommand(),
    buildDockerListCommand({ sudo: true }),
    buildDockerDiskCommand(),
    buildDockerInspectCommand('web'),
    buildDockerStatsCommand(['web']),
    buildDockerLogsCommand('web'),
    ...DOCKER_ACTIONS.map((a) => buildDockerActionCommand(a, ['web']))
  ]

  it('has no builder that can remove a container, an image or a volume', () => {
    // Removing a container is recoverable only if you can reconstruct how it
    // was run; removing a volume is not recoverable at all. A button cannot
    // carry that, so no builder here can produce one.
    for (const cmd of everything()) {
      expect(cmd, cmd.slice(0, 60)).not.toMatch(/\b(rm|rmi)\b/)
      expect(cmd, cmd.slice(0, 60)).not.toMatch(/\bprune\b/)
      expect(cmd, cmd.slice(0, 60)).not.toMatch(/\bvolume\s+(rm|prune)/)
    }
  })

  it('has no prune, in any spelling', () => {
    // `docker system prune` deletes every stopped container and — with the flag
    // people habitually add — every unused volume, where "unused" means "not
    // attached right now". Its blast radius is not knowable from the UI that
    // would offer it.
    for (const cmd of everything()) expect(cmd).not.toMatch(/system\s+prune|image\s+prune|builder\s+prune/)
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
    expect(buildDockerLogsCommand('web', 500)).toBe('docker logs --tail 500 web 2>&1')
  })

  it('adds timestamps and a relative window when asked', () => {
    expect(buildDockerLogsCommand('web', 200, false, { timestamps: true, since: '10m' })).toBe(
      'docker logs --tail 200 --timestamps --since 10m web 2>&1'
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
      'buildDockerInspectCommand',
      'buildDockerStatsCommand',
      'planDockerAction',
      'DockerReader',
      'docker system df',
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
