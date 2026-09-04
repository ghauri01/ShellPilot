// Compose: the FILE half of docker.
//
// The container half already exists and is not rebuilt here. `shared/docker.ts`
// reads `com.docker.compose.project` / `.service` from a separate `docker ps`
// whose failure is survivable, carries `composeLabels: 'read' | 'unavailable'`
// so "no compose projects here" stays distinct from "could not read labels",
// and `groupByComposeProject` already buckets containers by project. That is
// the running state, and this module consumes it rather than asking again.
//
// What is new is everything the labels cannot tell you:
//
//  * **Which compose files exist on this host.** A label names a project, not a
//    file. `docker compose ls` answers it where the engine is new enough; a
//    BOUNDED filesystem search answers it where it is not, and the bound is the
//    feature, not a detail — an unbounded `find /` on a production host is its
//    own outage. See COMPOSE_SEARCH_ROOTS.
//  * **What the file DECLARES.** The labels say what is running. The file says
//    what is supposed to be. The difference — a declared service with no
//    container — is the single most useful thing this module produces, and it
//    is not derivable from `docker ps` at all.
//  * **`pull` and `up -d`**, as jobs through the engine that already exists.
//    Not a second execution path: `composeJobSpec` returns a `JobSpec` and the
//    job runner does the rest, so the approval record, the resume check and the
//    audit trail are the ones already written and tested.
//  * **Editing an image tag**, the narrow write that is worth the risk.
//
// ======================================================================
// THE RULE THIS MODULE IS ORGANISED AROUND: NO ENVIRONMENT VALUE IS EVER READ
// ======================================================================
//
// This is not caution, it is the recorded behaviour of the tool. On a real
// project (tests/fixtures/docker/compose-config-interpolated-docker-29.json,
// recorded, not invented) `docker compose config` prints:
//
//     environment:
//       REDIS_PASSWORD: hunter2-not-a-real-password
//
// It resolves `${REDIS_PASSWORD}` out of `.env` and it inlines every `env_file`
// it can read. So the obvious implementation — run `docker compose config`,
// show the result — is a credential dump with a nice table, on a host the
// operator picked from a dropdown, into a renderer process, into any error
// detail that output later lands in.
//
// So:
//
//  1. **The safe form of the command is the only form built.** Every config
//     read here passes `--no-interpolate --no-env-resolution`. With those,
//     `${REDIS_PASSWORD}` stays the six-character string `${REDIS_PASSWORD}`
//     and an `env_file` stays a PATH. Both halves verified against the recorded
//     fixture pair.
//  2. **The parser discards values anyway.** `--no-interpolate` does nothing
//     about a password typed literally into the compose file, which is a thing
//     people do. So `parseComposeConfig` records a variable's NAME and where it
//     would come from, and never keeps the right-hand side — there is no field
//     on `ComposeEnvVar` that could hold one. A leak would have to be a new
//     field, which is a code review, not an accident.
//  3. **`.env` files are summarised on the host, by name.** The variable names
//     come back; the values are cut off by `awk` before they reach the SSH
//     channel. This is the same trick `buildDockerInspectCommand` already uses
//     for `Config.Env`, where the COUNT is computed by the remote template so
//     the values never cross the wire.
//
// What that costs, said out loud rather than hidden: the panel can tell an
// operator that `REDIS_PASSWORD` is set and cannot tell them what it is. That
// is the correct trade for this application, and `COMPOSE_ENV_DISCLOSURE` is
// the sentence the UI puts on screen so the operator knows it is a decision and
// not a bug.
//
// ======================================================================
// WHAT IS REFUSED
// ======================================================================
//
// `docker compose down` is not here and is not an oversight — see
// COMPOSE_REFUSALS. docker.ts already refuses `prune`, `rm` and `kill` with a
// written reason rather than a scarier dialog, and this follows that shape
// exactly.

import type { DockerContainer, DockerFailure } from './docker'
import { DOCKER_MARKERS, classifyDockerFailure, resolveBinary, section } from './docker'
import type { JobSpec, JobStep } from './jobs'

// ---------------------------------------------------------------- failure

/**
 * Why compose could not be read.
 *
 * `DockerFailure`'s four cases plus one: the docker binary can be present, the
 * daemon up and the socket readable, and `docker compose` still not exist —
 * that is every host running the v1 `docker-compose` python script, and every
 * minimal install that did not ship the CLI plugin. Folding it into
 * `not-installed` would send someone to install docker on a host that has it.
 */
export type ComposeFailure = DockerFailure | 'compose-unavailable'

export const COMPOSE_FAILURE_HELP: Record<ComposeFailure, string> = {
  'not-installed':
    'No docker on this server. Looked on PATH and in /usr/bin, /usr/local/bin, /snap/bin, /opt/homebrew/bin and /usr/sbin.',
  'daemon-unreachable':
    'Docker is installed but its daemon is not answering, so it cannot say which compose projects it is running.',
  'permission-denied':
    'This user cannot talk to the docker socket, so compose cannot be asked anything. The compose FILES may still be readable — the filesystem search below does not go through the daemon.',
  'compose-unavailable':
    'Docker is here, but `docker compose` is not. That is normal on servers still running the v1 `docker-compose` script, which is a separate program with a different command line. ShellPilot does not drive v1: its flags differ enough that guessing would be running an unverified command on someone else\u2019s server.',
  unknown: 'Compose returned an error that could not be classified. The raw message is below.'
}

/** The `docker compose` plugin is missing, as the CLI words it. */
const COMPOSE_MISSING =
  /is not a docker command|unknown docker command|docker: 'compose' is not|no such command|unknown command "compose"/i

// ---------------------------------------------------------------- markers

/**
 * Section markers, in the shape `shared/docker.ts` established.
 *
 * The name between the affixes is `-` followed by uppercase letters ONLY, and
 * that is a constraint rather than a convention: docker.ts's `section()` finds
 * the end of a block by searching for the next string matching `ANY_MARKER`,
 * which is `/===SHELLPILOT-[A-Z]+===/`. A marker spelled any other way is
 * invisible to that search, so the block before it would silently swallow every
 * block after it — a config parse that quietly contained the service list too.
 *
 * They are `C`-prefixed so a compose marker cannot collide with a docker one if
 * the two collectors ever share a round trip.
 */
export const COMPOSE_MARKERS = {
  version: '===SHELLPILOT-CVER===',
  ls: '===SHELLPILOT-CLS===',
  find: '===SHELLPILOT-CFIND===',
  config: '===SHELLPILOT-CCFG===',
  services: '===SHELLPILOT-CSVC===',
  envNames: '===SHELLPILOT-CENV===',
  end: DOCKER_MARKERS.end
} as const

// Lines that are the shell or docker complaining rather than answering.
// Deliberately a copy of docker.ts's BLOCK_FAILURE rather than an import of it:
// that constant is private there, and exporting a regex so a second module can
// share it makes one module's parsing depend on the other's internals.
const BLOCK_FAILURE =
  /permission denied|cannot connect to|unable to connect|error during connect|is the docker daemon running|command not found|:\s*not found|could not be found|^error\b|template:.*executing/i

function nonEmptyLines(text: string): string[] {
  return text
    .split('\n')
    .map((l) => l.trim())
    .filter((l) => l !== '')
}

function blockFailure(
  text: string,
  exitCode: number | null
): { reason: ComposeFailure; detail: string } | null {
  const lines = nonEmptyLines(text)
  const missing = lines.find((l) => COMPOSE_MISSING.test(l))
  if (missing) return { reason: 'compose-unavailable', detail: missing }
  const failing = lines.filter((l) => BLOCK_FAILURE.test(l))
  if (failing.length === 0) return null
  return {
    reason: classifyDockerFailure(failing.join('\n'), exitCode),
    detail: failing[failing.length - 1]
  }
}

/** `"$SP_BIN"`, or `sudo -n "$SP_BIN"`. Same two forms docker.ts uses. */
function runner(sudo: boolean | undefined): string {
  return sudo ? 'sudo -n "$SP_BIN"' : '"$SP_BIN"'
}

// ------------------------------------------------------- bounded discovery

/**
 * Where a filesystem search for compose files is allowed to look.
 *
 * THE BOUND IS THE FEATURE. `find / -name docker-compose.yml` on a host with a
 * cold page cache, a large NFS mount or a few million inodes is an incident:
 * it holds an exec channel open for minutes, it thrashes the disk of the
 * machine the operator was worried about, and it is indistinguishable from an
 * attack in an audit log. Four separate limits apply and every one of them is
 * reported to the panel by `composeSearchBound()`, because a search whose
 * bounds are invisible is a search whose empty result cannot be interpreted:
 *
 *  1. These roots, and no others. They are where compose projects are put on
 *     servers — not where they COULD be. `/` is not on the list and adding it
 *     is not a configuration option.
 *  2. `COMPOSE_SEARCH_MAX_DEPTH` levels below each root.
 *  3. `-xdev`, so the search never crosses onto another filesystem. This is
 *     what keeps a stray NFS or sshfs mount under `/srv` from turning a local
 *     search into a network one that hangs.
 *  4. `COMPOSE_SEARCH_MAX_RESULTS` paths, then the pipe closes.
 *
 * A search that hits the cap says so — see `ComposeSearchResult.truncated` —
 * rather than presenting a partial answer as a complete one.
 */
export const COMPOSE_SEARCH_ROOTS: readonly string[] = [
  '/srv',
  '/opt',
  '/home',
  '/root',
  '/var/www',
  '/data',
  '/docker',
  '/stacks'
]

export const COMPOSE_SEARCH_MAX_DEPTH = 4
export const COMPOSE_SEARCH_MAX_RESULTS = 200

/**
 * Directories never descended into.
 *
 * `node_modules` alone is the difference between a search that finishes and one
 * that does not: a single JavaScript project can hold tens of thousands of
 * directories and a handful of example `docker-compose.yml` files belonging to
 * dependencies, which are noise even when the search is fast.
 */
export const COMPOSE_SEARCH_PRUNED: readonly string[] = [
  'node_modules',
  '.git',
  'vendor',
  '.cache',
  '.venv',
  'site-packages',
  '.terraform'
]

/** The four names compose itself looks for, in its own precedence order. */
export const COMPOSE_FILE_NAMES: readonly string[] = [
  'compose.yaml',
  'compose.yml',
  'docker-compose.yaml',
  'docker-compose.yml'
]

export interface ComposeSearchBound {
  roots: readonly string[]
  maxDepth: number
  maxResults: number
  pruned: readonly string[]
  fileNames: readonly string[]
  /** Always false. Stated as data so the panel can print it rather than a developer remembering to. */
  crossesFilesystems: boolean
}

export function composeSearchBound(): ComposeSearchBound {
  return {
    roots: COMPOSE_SEARCH_ROOTS,
    maxDepth: COMPOSE_SEARCH_MAX_DEPTH,
    maxResults: COMPOSE_SEARCH_MAX_RESULTS,
    pruned: COMPOSE_SEARCH_PRUNED,
    fileNames: COMPOSE_FILE_NAMES,
    crossesFilesystems: false
  }
}

/**
 * The bounded `find`.
 *
 * `-maxdepth` comes immediately after the roots because GNU find warns when a
 * global option follows a test, and a warning line inside a block this parser
 * reads as paths is a path it cannot use. The prune clause comes before the
 * name clause for the ordinary find reason: `-prune` has to win before the
 * directory is descended.
 *
 * stderr is discarded, not folded in. Every root that does not exist on this
 * host produces one "No such file or directory" line, and on a normal server
 * most of these roots do not exist — folding those in would mean the common
 * case looks like a failure. The block ends `|| true` for the same reason:
 * find exits non-zero when any root is missing, and `head` closing the pipe
 * makes it non-zero again.
 */
export function buildComposeSearchCommand(): string {
  const prune = COMPOSE_SEARCH_PRUNED.map((d) => `-name ${d}`).join(' -o ')
  const names = COMPOSE_FILE_NAMES.map((n) => `-name ${n}`).join(' -o ')
  return (
    `find ${COMPOSE_SEARCH_ROOTS.join(' ')} -xdev -maxdepth ${COMPOSE_SEARCH_MAX_DEPTH} ` +
    `\\( ${prune} \\) -prune -o -type f \\( ${names} \\) -print 2>/dev/null | ` +
    `head -n ${COMPOSE_SEARCH_MAX_RESULTS} || true`
  )
}

export interface ComposeFileHit {
  path: string
  /** The directory compose would treat as the project directory. */
  directory: string
  /** The basename, which decides compose's own precedence. */
  fileName: string
}

export interface ComposeSearchResult {
  files: ComposeFileHit[]
  /** The cap was reached, so this list is a prefix and not an inventory. */
  truncated: boolean
  bound: ComposeSearchBound
}

export function parseComposeSearchOutput(text: string): ComposeSearchResult {
  const files: ComposeFileHit[] = []
  const seen = new Set<string>()
  for (const line of text.split('\n')) {
    // NOT trimmed: a path may legitimately end in a space, and trimming would
    // produce a path that does not exist. Only the line ending is stripped.
    const path = line.replace(/[\r\n]+$/, '')
    if (path === '' || !path.startsWith('/')) continue
    const slash = path.lastIndexOf('/')
    const fileName = path.slice(slash + 1)
    if (!COMPOSE_FILE_NAMES.includes(fileName)) continue
    if (seen.has(path)) continue
    seen.add(path)
    files.push({ path, directory: slash === 0 ? '/' : path.slice(0, slash), fileName })
  }
  files.sort((a, b) => a.path.localeCompare(b.path))
  return { files, truncated: files.length >= COMPOSE_SEARCH_MAX_RESULTS, bound: composeSearchBound() }
}

// --------------------------------------------------------------- projects

export interface ComposeProjectSummary {
  name: string
  /** Verbatim as compose wrote it: `running(3)`, `exited(1), running(2)`. */
  status: string
  /** Parsed out of `status`. null when the wording was not one this parser knows. */
  running: number | null
  stopped: number | null
  /** Every file, in compose's own order. A project may have several. */
  configFiles: string[]
}

/**
 * `docker compose ls --all --format json`, with the table form as the fallback.
 *
 * `--all` is not optional. Without it compose omits projects with no running
 * container ENTIRELY — verified against the recorded fixture pair, where the
 * same host reports `running(2)` without the flag and `exited(1), running(2)`
 * with it. A compose panel that cannot see a stopped stack is a panel that
 * cannot answer the question people actually open it with.
 */
export function parseComposeProjectsJson(text: string): ComposeProjectSummary[] | null {
  const start = text.indexOf('[')
  const end = text.lastIndexOf(']')
  if (start === -1 || end <= start) return null
  let raw: unknown
  try {
    raw = JSON.parse(text.slice(start, end + 1))
  } catch {
    return null
  }
  if (!Array.isArray(raw)) return null
  const out: ComposeProjectSummary[] = []
  for (const row of raw) {
    if (typeof row !== 'object' || row === null) continue
    const r = row as Record<string, unknown>
    const name = typeof r.Name === 'string' ? r.Name : ''
    if (name === '') continue
    const status = typeof r.Status === 'string' ? r.Status : ''
    out.push({ name, status, ...countsFrom(status), configFiles: splitConfigFiles(r.ConfigFiles) })
  }
  return out
}

/**
 * The table form.
 *
 * Two columns hold values with spaces in them, both recorded rather than
 * imagined: STATUS reads `exited(1), running(2)` and CONFIG FILES is a path,
 * which on the recording host was `/srv/Ops Platform/billing/...`. So the split
 * is on runs of two or more spaces and the LAST column takes the whole
 * remainder — a `split(/\s+/)` would cut a real path in half at the space in a
 * directory name.
 */
export function parseComposeProjectsTable(text: string): ComposeProjectSummary[] {
  const lines = text.split('\n').filter((l) => l.trim() !== '')
  const out: ComposeProjectSummary[] = []
  for (const line of lines) {
    if (/^NAME\s{2,}STATUS/.test(line)) continue
    const first = line.search(/\s{2,}/)
    if (first === -1) continue
    const name = line.slice(0, first)
    const rest = line.slice(first).replace(/^\s+/, '')
    const second = rest.search(/\s{2,}/)
    if (second === -1) continue
    const status = rest.slice(0, second)
    const files = rest.slice(second).replace(/^\s+/, '').replace(/\s+$/, '')
    out.push({ name, status, ...countsFrom(status), configFiles: splitConfigFiles(files) })
  }
  return out
}

/**
 * `running(3)` / `exited(1), running(2)` into two numbers.
 *
 * Anything that is neither running nor exited — `paused`, `restarting`, and
 * whatever compose adds next — counts as stopped rather than being dropped,
 * because the number the operator is comparing against is the declared service
 * count and a silently discarded state makes that comparison wrong.
 */
function countsFrom(status: string): { running: number | null; stopped: number | null } {
  const parts = status.match(/([a-z]+)\((\d+)\)/gi)
  if (parts === null || parts.length === 0) return { running: null, stopped: null }
  let running = 0
  let stopped = 0
  for (const part of parts) {
    const m = part.match(/([a-z]+)\((\d+)\)/i)
    if (m === null) continue
    const n = Number(m[2])
    if (m[1].toLowerCase() === 'running') running += n
    else stopped += n
  }
  return { running, stopped }
}

/** Compose joins several files into ONE comma-separated field. Recorded, not assumed. */
function splitConfigFiles(value: unknown): string[] {
  if (typeof value !== 'string') return []
  return value
    .split(',')
    .map((f) => f.trim())
    .filter((f) => f !== '')
}

// ------------------------------------------------------------ list command

export type ComposeListProbe =
  | {
      ok: true
      /** `docker compose version`'s answer, or null when it did not say. */
      composeVersion: string | null
      projects: ComposeProjectSummary[]
      /**
       * Whether `docker compose ls` answered at all.
       *
       * `unavailable` is NOT an error: it is a host with no compose plugin,
       * where the filesystem search is the whole answer. The panel says which,
       * because "this host runs no compose projects" and "this host cannot be
       * asked" are the two statements this module exists to keep apart.
       */
      projectsFrom: 'compose-ls' | 'unavailable'
      search: ComposeSearchResult | null
      usedSudo?: boolean
    }
  | { ok: false; reason: ComposeFailure; detail: string }

/**
 * One round trip: the compose version, the project list, and the bounded search.
 *
 * ORDERING IS LOAD-BEARING and follows docker.ts's rule exactly. The two blocks
 * that are allowed to fail — the version probe and the search — end `|| true`,
 * and both sit BEFORE the block whose exit status the parser reads. A `|| true`
 * after the `ls` would erase the only signal that separates "docker is not
 * here" from "docker is here and runs nothing".
 */
export function buildComposeListCommand(opts: { sudo?: boolean; search?: boolean } = {}): string {
  const run = runner(opts.sudo)
  const parts = [
    resolveBinary('docker'),
    `echo "${COMPOSE_MARKERS.version}"`,
    `${run} compose version --short 2>&1 || true`
  ]
  if (opts.search !== false) {
    parts.push(`echo "${COMPOSE_MARKERS.find}"`, buildComposeSearchCommand())
  }
  parts.push(
    `echo "${COMPOSE_MARKERS.ls}"`,
    `${run} compose ls --all --format json 2>&1`,
    `echo "${COMPOSE_MARKERS.end}"`
  )
  return parts.join('; ')
}

export function parseComposeListOutput(output: string, exitCode: number | null): ComposeListProbe {
  const versionPart = section(output, COMPOSE_MARKERS.version)
  const findPart = section(output, COMPOSE_MARKERS.find)
  const lsPart = section(output, COMPOSE_MARKERS.ls)

  // No `ls` marker means the shell never reached it — docker is missing, or the
  // transport truncated. That is the one case where the version block is the
  // diagnosis rather than a cosmetic extra.
  if (lsPart === undefined) {
    const text = versionPart ?? output
    const failure = blockFailure(text, exitCode)
    return {
      ok: false,
      reason: failure?.reason ?? 'unknown',
      detail: failure?.detail ?? nonEmptyLines(text)[0] ?? 'docker compose did not run'
    }
  }

  const search = findPart === undefined ? null : parseComposeSearchOutput(findPart)

  const lsFailure = blockFailure(lsPart, exitCode)
  if (lsFailure !== null) {
    // A missing compose plugin is survivable when the filesystem search found
    // files: the operator can still be shown what is on disk, and told plainly
    // that the daemon could not be asked what is running. Any other failure is
    // a failure of the read.
    if (lsFailure.reason === 'compose-unavailable') {
      return {
        ok: true,
        composeVersion: null,
        projects: [],
        projectsFrom: 'unavailable',
        search
      }
    }
    return { ok: false, ...lsFailure }
  }

  const projects = parseComposeProjectsJson(lsPart) ?? parseComposeProjectsTable(lsPart)
  return {
    ok: true,
    composeVersion: extractComposeVersion(versionPart ?? ''),
    projects,
    projectsFrom: 'compose-ls',
    search
  }
}

/** `v2.29.7` / `Docker Compose version v2.29.7` → `2.29.7`. */
export function extractComposeVersion(text: string): string | null {
  for (const line of nonEmptyLines(text).reverse()) {
    const m = line.match(/v?(\d+\.\d+[\w.+-]*)/)
    if (m) return m[1]
  }
  return null
}

// ------------------------------------------------------------ path safety

/**
 * A path safe to single-quote into a shell command.
 *
 * Spaces are ALLOWED and that is deliberate: the recorded fixture's own config
 * path is `/srv/Ops Platform/billing/docker-compose.test.yml`, so a validator
 * that rejected spaces would refuse a real host's real project. Single quotes
 * are refused, because a single quote is the one character that ends the
 * quoting this builder relies on. Control characters are refused because a
 * newline is a second command.
 */
const PATH_RE = /^\/[^'\n\r\0]{1,4095}$/

export function validateComposePath(path: unknown): boolean {
  if (typeof path !== 'string') return false
  if (!PATH_RE.test(path)) return false
  // eslint-disable-next-line no-control-regex
  if (/[\u0000-\u001f\u007f]/.test(path)) return false
  return true
}

/** Compose's own constraint on a project name, plus the length cap it enforces. */
const PROJECT_RE = /^[a-z0-9][a-z0-9_-]{0,62}$/

export function validateComposeProject(name: unknown): boolean {
  return typeof name === 'string' && PROJECT_RE.test(name)
}

/** A service key as compose allows it. Used before a name is interpolated. */
const SERVICE_RE = /^[a-zA-Z0-9][a-zA-Z0-9._-]{0,62}$/

export function validateComposeService(name: unknown): boolean {
  return typeof name === 'string' && SERVICE_RE.test(name)
}

function quote(path: string): string {
  return `'${path}'`
}

/** `--project-name X -f a -f b`, with everything validated first. */
function projectFlags(project: ComposeProjectRef): string {
  if (!validateComposeProject(project.name)) {
    throw new Error('refusing to build a compose command from an invalid project name')
  }
  if (!Array.isArray(project.files) || project.files.length === 0) {
    throw new Error('refusing to build a compose command with no compose file')
  }
  if (project.files.length > COMPOSE_MAX_FILES) {
    throw new Error(`refusing to build a compose command with more than ${COMPOSE_MAX_FILES} files`)
  }
  for (const f of project.files) {
    if (!validateComposePath(f)) {
      throw new Error('refusing to build a compose command from an invalid file path')
    }
  }
  return `--project-name ${quote(project.name)} ${project.files.map((f) => `-f ${quote(f)}`).join(' ')}`
}

/** Compose itself has no limit; this one bounds a command line built from IPC input. */
export const COMPOSE_MAX_FILES = 10

export interface ComposeProjectRef {
  name: string
  /** Every file, in order. Order is significant to compose: later files override earlier ones. */
  files: string[]
}

// ------------------------------------------------------- reading a project

/**
 * The SAFE config read, and the only one this module builds.
 *
 * `--no-interpolate` keeps `${REDIS_PASSWORD}` a variable name. `--no-env-resolution`
 * keeps an `env_file` a path instead of inlining what is in it. Drop either one
 * and the recorded fixture shows exactly what comes back:
 * `REDIS_PASSWORD: hunter2-not-a-real-password`.
 *
 * `--format json` because the alternative is YAML and this repository has no
 * runtime YAML parser — `js-yaml` is a devDependency, so a shipping module
 * cannot import it. Where `--format json` is not supported (compose before
 * 2.20) that block simply fails and the `--services` block below still answers
 * with the service names, which is the minimum this feature needs.
 */
export function buildComposeConfigCommand(
  project: ComposeProjectRef,
  opts: { sudo?: boolean } = {}
): string {
  const flags = projectFlags(project)
  const run = runner(opts.sudo)
  return [
    resolveBinary('docker'),
    // Allowed to fail, and therefore first: an older compose has no
    // `--format json` and the `--services` block below is the fallback.
    `echo "${COMPOSE_MARKERS.config}"`,
    `${run} compose ${flags} config --format json --no-interpolate --no-env-resolution 2>&1 || true`,
    `echo "${COMPOSE_MARKERS.services}"`,
    `${run} compose ${flags} config --services 2>&1`,
    `echo "${COMPOSE_MARKERS.end}"`
  ].join('; ')
}

export type ComposeEnvOrigin =
  /** A value written into the compose file itself. The value is NOT kept. */
  | 'literal'
  /** `${SOMETHING}` — resolved from `.env` or the host environment at run time. */
  | 'interpolated'
  /** Named with no value: compose passes the host's own value through. */
  | 'passthrough'

export interface ComposeEnvVar {
  name: string
  origin: ComposeEnvOrigin
  /** For `interpolated`, the variable it reads. `REDIS_PASSWORD` in `${REDIS_PASSWORD}`. */
  variable?: string
  /**
   * Whether the compose file gives this a value at all.
   *
   * THERE IS NO FIELD HOLDING THE VALUE, and there is not going to be one. See
   * the module header: adding one is the whole leak, and its absence from this
   * interface is what makes that a code review rather than an accident.
   */
  set: boolean
}

export interface ComposeServiceDecl {
  name: string
  /** null for a service built from source, which has nothing to pull. */
  image: string | null
  build: boolean
  containerName: string | null
  dependsOn: string[]
  /** As compose normalised them: `18080:80`, `6379`. */
  ports: string[]
  profiles: string[]
  /** Names and origins. Never values. */
  environment: ComposeEnvVar[]
  /** Paths only. Their CONTENTS are never read by anything in this module. */
  envFiles: string[]
  restart: string | null
}

export interface ComposeProjectConfig {
  /** `name:` from the rendered model, which is the project name compose will use. */
  name: string | null
  services: ComposeServiceDecl[]
  volumes: string[]
  networks: string[]
  /** True when only `--services` answered, so images and ports are unknown rather than absent. */
  namesOnly: boolean
}

export type ComposeConfigProbe =
  | { ok: true; config: ComposeProjectConfig; usedSudo?: boolean }
  | { ok: false; reason: ComposeFailure; detail: string }

/**
 * The one place a compose model is turned into our own shape.
 *
 * Everything it copies is a name, a path, an image reference or a count.
 * Nothing it copies is a value out of `environment`, and the shape it copies
 * INTO has nowhere to put one.
 */
export function parseComposeConfigJson(text: string): ComposeProjectConfig | null {
  const start = text.indexOf('{')
  const end = text.lastIndexOf('}')
  if (start === -1 || end <= start) return null
  let raw: unknown
  try {
    raw = JSON.parse(text.slice(start, end + 1))
  } catch {
    return null
  }
  if (typeof raw !== 'object' || raw === null) return null
  const model = raw as Record<string, unknown>
  const servicesRaw = model.services
  if (typeof servicesRaw !== 'object' || servicesRaw === null) return null

  const services: ComposeServiceDecl[] = []
  for (const [name, value] of Object.entries(servicesRaw as Record<string, unknown>)) {
    const s = (typeof value === 'object' && value !== null ? value : {}) as Record<string, unknown>
    services.push({
      name,
      image: typeof s.image === 'string' && s.image !== '' ? s.image : null,
      build: s.build !== undefined && s.build !== null,
      containerName: typeof s.container_name === 'string' ? s.container_name : null,
      dependsOn: dependsOnOf(s.depends_on),
      ports: portsOf(s.ports),
      profiles: stringsOf(s.profiles),
      environment: environmentOf(s.environment),
      envFiles: envFilesOf(s.env_file),
      restart: typeof s.restart === 'string' ? s.restart : null
    })
  }
  services.sort((a, b) => a.name.localeCompare(b.name))
  return {
    name: typeof model.name === 'string' ? model.name : null,
    services,
    volumes: keysOf(model.volumes),
    networks: keysOf(model.networks),
    namesOnly: false
  }
}

function keysOf(value: unknown): string[] {
  if (typeof value !== 'object' || value === null) return []
  return Object.keys(value as Record<string, unknown>).sort()
}

function stringsOf(value: unknown): string[] {
  if (!Array.isArray(value)) return []
  return value.filter((v): v is string => typeof v === 'string')
}

function dependsOnOf(value: unknown): string[] {
  // Both shapes are real and compose emits whichever the file used: a bare
  // list in a file it did not normalise, a map once it has.
  if (Array.isArray(value)) return stringsOf(value).sort()
  if (typeof value === 'object' && value !== null) return Object.keys(value as object).sort()
  return []
}

function portsOf(value: unknown): string[] {
  if (!Array.isArray(value)) return []
  const out: string[] = []
  for (const p of value) {
    if (typeof p === 'string' || typeof p === 'number') {
      out.push(String(p))
      continue
    }
    if (typeof p !== 'object' || p === null) continue
    const o = p as Record<string, unknown>
    const target = o.target === undefined ? '' : String(o.target)
    const published = typeof o.published === 'string' || typeof o.published === 'number' ? String(o.published) : ''
    out.push(published === '' ? target : `${published}:${target}`)
  }
  return out
}

function envFilesOf(value: unknown): string[] {
  if (typeof value === 'string') return [value]
  if (!Array.isArray(value)) return []
  const out: string[] = []
  for (const e of value) {
    if (typeof e === 'string') out.push(e)
    // Compose 2.24 and later render `env_file` as `{path, required}`. Recorded.
    else if (typeof e === 'object' && e !== null && typeof (e as Record<string, unknown>).path === 'string') {
      out.push((e as Record<string, unknown>).path as string)
    }
  }
  return out
}

/** `${NAME}`, `${NAME:-default}`, `${NAME:?message}` — the name is the part before the operator. */
const INTERPOLATION_RE = /^\$\{?([A-Za-z_][A-Za-z0-9_]*)[:\-?+}]?/

/**
 * Environment, as NAMES.
 *
 * Both shapes below appear in ONE recorded document, which is the reason this
 * function exists rather than a two-line `Object.keys`: with
 * `--no-interpolate`, compose leaves one service's `environment` a map and
 * another's a `KEY=VALUE` list, in the same render. A parser that handled only
 * the map silently reported a service as having no environment at all.
 */
function environmentOf(value: unknown): ComposeEnvVar[] {
  const out: ComposeEnvVar[] = []
  const add = (name: string, rhs: string | null): void => {
    if (name === '') return
    if (rhs === null) {
      out.push({ name, origin: 'passthrough', set: false })
      return
    }
    const m = rhs.match(INTERPOLATION_RE)
    if (m) {
      out.push({ name, origin: 'interpolated', variable: m[1], set: true })
      return
    }
    // The value is looked at exactly this far — is it empty — and then dropped.
    out.push({ name, origin: 'literal', set: rhs !== '' })
  }

  if (Array.isArray(value)) {
    for (const entry of value) {
      if (typeof entry !== 'string') continue
      const eq = entry.indexOf('=')
      if (eq === -1) add(entry.trim(), null)
      else add(entry.slice(0, eq).trim(), entry.slice(eq + 1))
    }
  } else if (typeof value === 'object' && value !== null) {
    for (const [name, v] of Object.entries(value as Record<string, unknown>)) {
      if (v === null || v === undefined) add(name, null)
      else add(name, String(v))
    }
  }
  out.sort((a, b) => a.name.localeCompare(b.name))
  return out
}

export function parseComposeConfigOutput(output: string, exitCode: number | null): ComposeConfigProbe {
  const configPart = section(output, COMPOSE_MARKERS.config)
  const servicesPart = section(output, COMPOSE_MARKERS.services)

  if (servicesPart === undefined) {
    const text = configPart ?? output
    const failure = blockFailure(text, exitCode)
    return {
      ok: false,
      reason: failure?.reason ?? 'unknown',
      detail: failure?.detail ?? nonEmptyLines(text)[0] ?? 'docker compose config did not run'
    }
  }

  if (configPart !== undefined) {
    const parsed = parseComposeConfigJson(configPart)
    if (parsed !== null) return { ok: true, config: parsed }
  }

  // The rich form did not answer. Before falling back to names, find out
  // whether the NAMES block is answering either — a permission failure with a
  // names-only model behind it would read as "this project declares nothing",
  // which is the lie this module is built to avoid.
  const failure = blockFailure(servicesPart, exitCode)
  if (failure !== null) return { ok: false, ...failure }

  const names = nonEmptyLines(servicesPart).filter((l) => validateComposeService(l))
  if (names.length === 0) {
    const configFailure = configPart === undefined ? null : blockFailure(configPart, exitCode)
    if (configFailure !== null) return { ok: false, ...configFailure }
    return {
      ok: false,
      reason: 'unknown',
      detail: 'docker compose config returned nothing this parser could read'
    }
  }
  return {
    ok: true,
    config: {
      name: null,
      services: names.sort().map((name) => ({
        name,
        image: null,
        build: false,
        containerName: null,
        dependsOn: [],
        ports: [],
        profiles: [],
        environment: [],
        envFiles: [],
        restart: null
      })),
      volumes: [],
      networks: [],
      namesOnly: true
    }
  }
}

// ----------------------------------------------------- declared vs running

/**
 * Whether a declared service has anything to show for itself.
 *
 * `missing` is the state this whole module was built to be able to say. A
 * container that exists and is down is visible in the container panel already;
 * a service that was never created has NO container, no label, and therefore no
 * row anywhere in this application until the file is read.
 */
export type ComposeServiceRunState = 'running' | 'partial' | 'stopped' | 'missing'

export interface ComposeServiceState {
  declared: ComposeServiceDecl
  containers: DockerContainer[]
  state: ComposeServiceRunState
}

export interface ComposeProjectView {
  project: string
  services: ComposeServiceState[]
  /**
   * Containers labelled with this project that the file does not declare.
   *
   * Listed rather than dropped: it is a service someone removed from the file
   * without bringing down, or a file that is not the one this project was
   * started from. Both are worth seeing.
   */
  undeclared: DockerContainer[]
  /** Declared services with no container at all. A convenience over `services`. */
  missing: string[]
}

export function joinComposeState(
  project: string,
  config: ComposeProjectConfig,
  containers: DockerContainer[]
): ComposeProjectView {
  const mine = containers.filter((c) => c.composeProject === project)
  const byService = new Map<string, DockerContainer[]>()
  for (const c of mine) {
    const key = c.composeService ?? ''
    const list = byService.get(key)
    if (list) list.push(c)
    else byService.set(key, [c])
  }

  const services: ComposeServiceState[] = []
  const missing: string[] = []
  for (const declared of config.services) {
    const found = byService.get(declared.name) ?? []
    byService.delete(declared.name)
    let state: ComposeServiceRunState
    if (found.length === 0) {
      state = 'missing'
      missing.push(declared.name)
    } else {
      const up = found.filter((c) => c.state === 'running').length
      state = up === 0 ? 'stopped' : up === found.length ? 'running' : 'partial'
    }
    services.push({ declared, containers: found, state })
  }

  const undeclared: DockerContainer[] = []
  for (const list of byService.values()) undeclared.push(...list)
  undeclared.sort((a, b) => a.name.localeCompare(b.name))
  return { project, services, undeclared, missing }
}

// -------------------------------------------------------- the env-file half

/**
 * What the panel is allowed to say about a `.env`, and the sentence it says it with.
 *
 * On screen, verbatim. The operator should learn this from the UI rather than
 * from a surprise, because "ShellPilot cannot show me this" is a support
 * question and "ShellPilot showed my production database password to whoever
 * was standing behind me" is an incident.
 */
export const COMPOSE_ENV_DISCLOSURE =
  'ShellPilot reads the NAMES of the variables in this file and never their values. ' +
  'The values are cut off on the server itself, so they do not cross the connection, ' +
  'are not held in memory here, and cannot appear in an error message. A variable is ' +
  'shown as set or empty; to see a value, open the file on the server.'

export interface ComposeEnvName {
  name: string
  /** The file gives it a non-empty value. Which value is not read. */
  set: boolean
}

export interface ComposeEnvFileSummary {
  path: string
  readable: boolean
  names: ComposeEnvName[]
}

/**
 * Variable NAMES out of an env file, with the values removed ON THE HOST.
 *
 * The awk program prints `S name` or `E name` and nothing else. There is no
 * form of this command whose output contains a value, which is the point: the
 * safety is a property of the command, not of a parser downstream of it that
 * somebody might later "improve".
 *
 * `index($0, "=")` rather than `-F=`, because a value may itself contain `=`
 * (a base64 secret usually does) and splitting on every `=` would make `$2`
 * only the first fragment — still a fragment of a secret. Taking the name as
 * everything before the FIRST `=` and never referring to the rest is the only
 * shape where no field holds any part of a value.
 */
export function buildComposeEnvNamesCommand(paths: string[], opts: { sudo?: boolean } = {}): string {
  if (!Array.isArray(paths) || paths.length === 0) {
    throw new Error('refusing to build an env-file command with no paths')
  }
  if (paths.length > COMPOSE_MAX_FILES) {
    throw new Error(`refusing to read more than ${COMPOSE_MAX_FILES} env files at once`)
  }
  for (const p of paths) {
    if (!validateComposePath(p)) {
      throw new Error('refusing to build an env-file command from an invalid path')
    }
  }
  const awk =
    "awk '{ i = index($0, \"=\"); " +
    'if (i < 2) next; ' +
    'n = substr($0, 1, i - 1); ' +
    'sub(/^[ \\t]*(export[ \\t]+)?/, "", n); ' +
    'sub(/[ \\t]+$/, "", n); ' +
    'if (n !~ /^[A-Za-z_][A-Za-z0-9_]*$/) next; ' +
    'print (length($0) > i ? "S " : "E ") n }\''
  const cmd = opts.sudo ? 'sudo -n cat' : 'cat'
  return paths
    .map(
      (p) =>
        `echo "${COMPOSE_MARKERS.envNames}"; echo "FILE ${p.replace(/"/g, '')}"; ` +
        `${cmd} ${quote(p)} 2>/dev/null | ${awk} || true`
    )
    .concat(`echo "${COMPOSE_MARKERS.end}"`)
    .join('; ')
}

/**
 * Parse the name listing.
 *
 * A file that could not be read produces its `FILE` line and nothing after it,
 * which is `readable: false` — distinct from a file that exists and declares
 * nothing. The two look identical if you only count names, and they mean
 * opposite things.
 */
export function parseComposeEnvNamesOutput(output: string): ComposeEnvFileSummary[] {
  const out: ComposeEnvFileSummary[] = []
  const blocks = output.split(COMPOSE_MARKERS.envNames).slice(1)
  for (const block of blocks) {
    const body = block.split(COMPOSE_MARKERS.end)[0]
    const lines = nonEmptyLines(body)
    const head = lines.find((l) => l.startsWith('FILE '))
    if (head === undefined) continue
    const path = head.slice('FILE '.length).trim()
    const names: ComposeEnvName[] = []
    for (const line of lines) {
      const m = line.match(/^([SE]) ([A-Za-z_][A-Za-z0-9_]*)$/)
      if (m === null) continue
      names.push({ name: m[2], set: m[1] === 'S' })
    }
    // Any line that is neither the header nor a name means `cat` said
    // something — a missing file, a refused read. Either way the file was not
    // read, and an empty name list would claim it was and found nothing.
    const noise = lines.filter((l) => l !== head && !/^[SE] [A-Za-z_][A-Za-z0-9_]*$/.test(l))
    out.push({ path, readable: noise.length === 0, names })
  }
  return out
}

// ------------------------------------------------------------- refusals

/**
 * What this module will not run, with the reason written down.
 *
 * The shape docker.ts already uses for `prune`, `rm` and `kill`: a named
 * refusal with the argument in it, not a scarier dialog. Item 21b settled the
 * principle — a blast radius that is not knowable from the UI offering it is
 * answered by showing a literal list, not by making the button redder — and
 * `down` is the compose-shaped instance of exactly that.
 */
export const COMPOSE_REFUSALS: Record<string, string> = {
  down:
    '`docker compose down` removes every container in the project, and its network with them. ' +
    'What it costs is not visible from a compose panel: whether a container was carrying state ' +
    'nobody wrote down, whether it can be recreated from the file in front of you, and whether ' +
    'the file in front of you is the one it was created from are three questions this UI cannot ' +
    'answer, and the button would be offering to act as though it had. Stop the containers ' +
    'instead — that is reversible, it is on the container panel already, and it is what people ' +
    'reach for `down` to do nine times in ten.',
  'down -v':
    '`docker compose down -v` deletes the project\u2019s named volumes. That is the database. ' +
    'It is not recoverable, it is not undone by running `up` again, and no confirmation dialog ' +
    'makes it knowable from here.',
  rm: '`docker compose rm` removes stopped containers. See `down`: recoverable only if you can reconstruct how they were run, which this panel cannot show you.',
  kill: '`docker compose kill` sends SIGKILL with no grace period. `stop` sends SIGTERM and waits, and the difference is whether a database finishes its write.'
}

/** The refusal text for a verb this module will not run, or null when it will. */
export function composeRefusal(action: string): string | null {
  const key = String(action).trim().toLowerCase()
  return COMPOSE_REFUSALS[key] ?? null
}

// ----------------------------------------------------------------- jobs

/**
 * The two verbs that ARE offered.
 *
 * `pull` fetches images and changes nothing that is running. `up -d` starts
 * what is declared and recreates what has drifted. Neither removes anything,
 * which is the line — and the line is drawn here in a list rather than in a
 * dialog, so a verb cannot be added by someone editing a UI file.
 */
export type ComposeAction = 'pull' | 'up'
export const COMPOSE_ACTIONS: readonly ComposeAction[] = ['pull', 'up']

/**
 * The shell for one compose verb.
 *
 * `--project-name` is passed explicitly rather than being inferred from the
 * directory. Compose infers it from the project directory's BASENAME, so two
 * different hosts with `/srv/edge` and `/opt/stacks/edge` both call the project
 * `edge`, and a job that relied on inference would act on whatever the
 * directory happened to be called at the time. The name is part of the approval
 * record because it is part of the command.
 *
 * `up` is `up -d` and nothing else. Not `--remove-orphans` (that removes
 * containers, see COMPOSE_REFUSALS), not `--force-recreate` (that restarts
 * services the operator did not ask about), not `--build`.
 */
export function buildComposeActionCommand(
  action: ComposeAction,
  project: ComposeProjectRef,
  opts: { sudo?: boolean; services?: string[] } = {}
): string {
  const refusal = composeRefusal(action)
  if (refusal !== null) throw new Error(`refusing to build a compose command: ${refusal}`)
  if (!COMPOSE_ACTIONS.includes(action)) {
    throw new Error('refusing to build a command for an unknown compose action')
  }
  const flags = projectFlags(project)
  const services = opts.services ?? []
  for (const s of services) {
    if (!validateComposeService(s)) {
      throw new Error('refusing to build a compose command from an invalid service name')
    }
  }
  const tail = services.length === 0 ? '' : ` ${services.map(quote).join(' ')}`
  const verb = action === 'up' ? 'up -d' : 'pull'
  const run = opts.sudo ? 'sudo -n docker' : 'docker'
  return `${run} compose ${flags} ${verb}${tail}`
}

export interface ComposeJobPlan {
  action: ComposeAction
  project: ComposeProjectRef
  spec: JobSpec
  /** The sentence the dialog puts under the command. */
  detail: string
}

/**
 * A compose verb as a `JobSpec`, run by the engine that already exists.
 *
 * Deliberately NOT a second execution path. `planJob` grades the risk from the
 * step text, `jobApprovalFor` mints the record, `verifyJobApproval` re-checks it
 * at launch and again at resume, and the runner owns the output, the retry and
 * the audit row. Everything this function does is produce the steps; every
 * safety property comes from the engine reading them.
 *
 * ONE STEP, not two. `pull` then `up` in a single spec would be a job whose
 * approval record says "pull and up" and whose failure at step two leaves a
 * host in a state the record does not describe. They are separate jobs so the
 * operator confirms, sees and can stop each one.
 */
export function composeJobSpec(
  action: ComposeAction,
  project: ComposeProjectRef,
  opts: { sudo?: boolean; services?: string[] } = {}
): ComposeJobPlan {
  const command = buildComposeActionCommand(action, project, opts)
  const services = opts.services ?? []
  const scope = services.length === 0 ? 'every service' : services.join(', ')
  const detail =
    action === 'pull'
      ? `Fetches the images ${project.name} declares for ${scope}. Nothing running changes: a pulled image is used at the next \`up\`.`
      : `Starts ${scope} in ${project.name} and recreates any container whose declaration has changed. Nothing is removed.`
  const steps: JobStep[] = [{ command, timeoutMs: COMPOSE_STEP_TIMEOUT_MS[action] }]
  return {
    action,
    project,
    detail,
    spec: {
      kind: 'command',
      title: `Compose ${action === 'up' ? 'up -d' : 'pull'} · ${project.name}`,
      steps
    }
  }
}

/**
 * Per-step budgets.
 *
 * A `pull` of a multi-gigabyte image over a slow link is slow rather than
 * broken, and the default step timeout would report a working pull as a failure
 * partway through — leaving a half-fetched layer set and a job record that
 * says something untrue about it.
 */
export const COMPOSE_STEP_TIMEOUT_MS: Record<ComposeAction, number> = {
  pull: 1_800_000,
  up: 900_000
}

// ------------------------------------------------------- the image tag edit

/**
 * An image reference, validated before it is written into someone's file.
 *
 * Deliberately strict about the tag and permissive about the registry: a
 * registry host can carry a port and a path, a tag cannot carry a slash, and a
 * digest is hex of a stated length. The thing being prevented is not a shell
 * injection — this value is written into a file, not a command — it is a file
 * edit that leaves the project unparseable, which is a worse outcome than a
 * refused edit because it is discovered at the next deploy.
 */
const IMAGE_RE =
  /^(?:[a-zA-Z0-9._-]+(?::\d+)?\/)?[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*(?:\/[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*)*(?::[a-zA-Z0-9_][a-zA-Z0-9._-]{0,127})?(?:@sha256:[a-f0-9]{64})?$/

export function validateImageRef(ref: unknown): boolean {
  if (typeof ref !== 'string' || ref.length === 0 || ref.length > 512) return false
  // Checked BEFORE the pattern, because the pattern alone accepted
  // `../etc/passwd`: a registry component is `[a-zA-Z0-9._-]+`, which `..`
  // satisfies, so a path traversal read as `registry `..`, image `etc/passwd``
  // and was written straight into someone's compose file. Found by the test
  // below rather than by review, which is why it is spelled out here.
  if (ref.startsWith('.') || ref.startsWith('/') || ref.includes('..')) return false
  return IMAGE_RE.test(ref)
}

export type ComposeImageEditPlan =
  | {
      ok: true
      service: string
      /** 1-based, so it matches what an editor shows the operator. */
      line: number
      from: string
      to: string
      /** The whole line as it is now and as it will be. The dialog shows both. */
      before: string
      after: string
    }
  | { ok: false; reason: string }

/**
 * Find the ONE line to change, and change nothing else.
 *
 * A text edit rather than a YAML round trip, and that is the decision here. The
 * round trip is easy to write and it rewrites the whole file: it drops every
 * comment, reorders keys, reflows anchors and normalises quoting. The operator
 * asked to change a tag; handing them a diff touching two hundred lines means
 * they cannot review it, and a compose file's comments are frequently the only
 * documentation a stack has.
 *
 * So: locate `services:`, locate the service key at one indent level below it,
 * locate that block's `image:` line, and replace exactly the value on it. The
 * indentation is what bounds the block — the next line indented at or above the
 * service key's level ends it — which is also why a service whose `image:` is
 * inside a nested map is not matched and is refused rather than guessed at.
 */
export function planComposeImageEdit(
  fileText: string,
  service: string,
  newRef: string
): ComposeImageEditPlan {
  if (!validateComposeService(service)) return { ok: false, reason: 'not a valid service name' }
  if (!validateImageRef(newRef)) {
    return { ok: false, reason: `\`${newRef}\` is not a valid image reference` }
  }
  const lines = fileText.split('\n')

  let inServices = false
  let servicesIndent = -1
  let serviceIndent = -1
  let imageIndent = -1
  let inService = false

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i]
    if (line.trim() === '' || /^\s*#/.test(line)) continue
    const indent = line.length - line.replace(/^\s*/, '').length

    if (!inServices) {
      if (/^\s*services:\s*(#.*)?$/.test(line)) {
        inServices = true
        servicesIndent = indent
      }
      continue
    }

    // A key back at or left of `services:` ends the services block.
    if (indent <= servicesIndent) {
      if (inService) break
      inServices = false
      continue
    }

    if (!inService) {
      const m = line.match(/^(\s*)([A-Za-z0-9][A-Za-z0-9._-]*):\s*(#.*)?$/)
      if (m && m[2] === service) {
        inService = true
        serviceIndent = indent
      }
      continue
    }

    // Back out to the service-key level or further left: this service is done.
    if (indent <= serviceIndent) break

    // Only the service's OWN `image:`. `imageIndent` is fixed by the first key
    // seen inside the service block, so a deeper `image:` — one belonging to a
    // nested map like `build:` or `deploy:` — is skipped rather than edited.
    if (imageIndent === -1) imageIndent = indent
    if (indent !== imageIndent) continue
    const m = line.match(/^(\s*)image:(\s*)(.*)$/)
    if (m === null) continue
    const rest = m[3]
    const valueMatch = rest.match(/^(['"]?)([^'"#]*?)\1(\s*(?:#.*)?)$/)
    if (valueMatch === null) return { ok: false, reason: `could not read the image value on line ${i + 1}` }
    const quoteChar = valueMatch[1]
    const from = valueMatch[2].trim()
    if (from === '') return { ok: false, reason: `\`${service}\` has an empty image value` }
    const trailing = valueMatch[3]
    const after = `${m[1]}image:${m[2]}${quoteChar}${newRef}${quoteChar}${trailing}`
    return { ok: true, service, line: i + 1, from, to: newRef, before: line, after }
  }

  if (!inService) return { ok: false, reason: `\`${service}\` is not declared in this file` }
  return { ok: false, reason: `\`${service}\` declares no image in this file — it is built, not pulled` }
}

/**
 * Apply a plan to the same text it was planned against.
 *
 * `before` is re-checked rather than trusted. A plan travels through IPC and
 * back, and the file may have been changed by someone else in between; writing
 * a computed line onto a line that is no longer the one it was computed from is
 * how an edit silently lands in the wrong place.
 */
export function applyComposeImageEdit(fileText: string, plan: ComposeImageEditPlan): string {
  if (!plan.ok) throw new Error('refusing to apply a compose edit that was not planned')
  const lines = fileText.split('\n')
  const idx = plan.line - 1
  if (idx < 0 || idx >= lines.length) {
    throw new Error('refusing to apply a compose edit past the end of the file')
  }
  if (lines[idx] !== plan.before) {
    throw new Error('refusing to apply a compose edit: the file has changed since it was planned')
  }
  lines[idx] = plan.after
  return lines.join('\n')
}

/**
 * The heredoc delimiter, and the reason it is a heredoc at all.
 *
 * A QUOTED delimiter means the shell performs no expansion inside the body:
 * no `$`, no backtick, no backslash handling. So the file content — which is a
 * YAML document from the host, not something this process composed — cannot
 * become shell. The one thing that could break out is a line of the body equal
 * to the delimiter, which is why `buildComposeWriteCommand` refuses content
 * containing it rather than escaping around it.
 *
 * base64 was the alternative and is worse here: `base64 -d` is GNU, `-D` is
 * BSD, and the fallback dance is a second thing to get wrong. The heredoc is
 * also READABLE — the operator can see the file they are about to write in the
 * command itself.
 */
export const COMPOSE_HEREDOC = 'SHELLPILOT_COMPOSE_EOF'

/**
 * Write a compose file back, keeping a copy of what was there.
 *
 * `cp -p` first, then a temp file, then `mv`. The backup is not politeness: a
 * compose file is frequently the only record of how a stack is meant to run,
 * and a truncated write during a flaky SSH session would destroy it. `mv`
 * within one directory is atomic, so a reader never sees a half file.
 */
export function buildComposeWriteCommand(
  path: string,
  content: string,
  opts: { sudo?: boolean } = {}
): string {
  if (!validateComposePath(path)) {
    throw new Error('refusing to write to an invalid compose file path')
  }
  if (typeof content !== 'string') throw new Error('refusing to write non-string compose content')
  if (content.length > COMPOSE_MAX_FILE_BYTES) {
    throw new Error(`refusing to write a compose file larger than ${COMPOSE_MAX_FILE_BYTES} bytes`)
  }
  if (content.split('\n').some((l) => l === COMPOSE_HEREDOC)) {
    throw new Error('refusing to write compose content containing the heredoc delimiter')
  }
  const body = content.endsWith('\n') ? content : `${content}\n`
  const tmp = quote(`${path}.shellpilot-tmp`)
  const bak = quote(`${path}.shellpilot-bak`)
  const target = quote(path)
  const sudo = opts.sudo ? 'sudo -n ' : ''
  return [
    `${sudo}cp -p ${target} ${bak}`,
    `${sudo}tee ${tmp} >/dev/null <<'${COMPOSE_HEREDOC}'\n${body}${COMPOSE_HEREDOC}`,
    `${sudo}mv ${tmp} ${target}`,
    `echo "${COMPOSE_MARKERS.end}"`
  ].join(' && ')
}

/** Compose files are configuration. Anything this large is not one. */
export const COMPOSE_MAX_FILE_BYTES = 512 * 1024

/** Read a compose file for editing. Read-only, and bounded for the same reason. */
export function buildComposeReadCommand(path: string, opts: { sudo?: boolean } = {}): string {
  if (!validateComposePath(path)) throw new Error('refusing to read an invalid compose file path')
  const cmd = opts.sudo ? 'sudo -n head' : 'head'
  return `${cmd} -c ${COMPOSE_MAX_FILE_BYTES} ${quote(path)} 2>&1`
}

// ------------------------------------------------------------- the bridge

export interface ComposeBridge {
  list(cfg: unknown, opts?: { sudo?: boolean; autoSudo?: boolean; search?: boolean }): Promise<ComposeListProbe>
  config(
    cfg: unknown,
    project: ComposeProjectRef,
    opts?: { sudo?: boolean; autoSudo?: boolean }
  ): Promise<ComposeConfigProbe>
  envNames(
    cfg: unknown,
    paths: string[],
    opts?: { sudo?: boolean; autoSudo?: boolean }
  ): Promise<ComposeEnvProbe>
  readFile(
    cfg: unknown,
    path: string,
    opts?: { sudo?: boolean }
  ): Promise<{ ok: boolean; text?: string; error?: string }>
  writeImageTag(
    cfg: unknown,
    req: ComposeImageWriteRequest,
    opts?: { sudo?: boolean }
  ): Promise<ComposeImageWriteResult>
}

export type ComposeEnvProbe =
  | { ok: true; files: ComposeEnvFileSummary[]; usedSudo?: boolean }
  | { ok: false; reason: ComposeFailure; detail: string }

export interface ComposeImageWriteRequest {
  path: string
  service: string
  image: string
  /** The plan the operator was shown. Re-derived and compared before anything is written. */
  expect: { line: number; before: string }
}

export type ComposeImageWriteResult =
  | { ok: true; plan: Extract<ComposeImageEditPlan, { ok: true }>; backup: string }
  | { ok: false; reason: string }
