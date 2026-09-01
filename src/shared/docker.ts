// Docker: list containers on a server, read their logs, open a shell in one.
//
// Two decisions, both taken from the roadmap and both worth restating because
// the rest follows from them.
//
// **We shell out to the `docker` binary rather than speaking the API.** Far
// less work, and it inherits the user's existing auth — including the cloud
// provider credential helpers we would otherwise have to reimplement. It costs
// structured errors and a dependency on the binary being present, and both are
// handled explicitly here rather than surfacing as a blank panel: `docker` not
// installed, the daemon not running, and the user not being in the `docker`
// group are three different problems with three different fixes, and a UI that
// says "no containers" for all three is lying about two of them.
//
// **A container shell is a third TerminalTransport, not a new terminal.**
// `docker exec -it` is a PTY over a channel, which is the shape the transport
// abstraction already has.
//
// The thing to keep in view: `docker exec` is arbitrary code execution on the
// host, and membership of the `docker` group is root-equivalent on most
// installs. Anything that grants it is granting that, and this module is off by
// default for exactly that reason.

export interface DockerContainer {
  id: string
  /** Short id, which is what people actually read and type. */
  shortId: string
  name: string
  image: string
  /** Raw `State` — running, exited, paused, restarting, created, dead. */
  state: string
  /** Human status as docker writes it: "Up 3 hours", "Exited (0) 2 days ago". */
  status: string
  ports: string
  createdAt: string
}

export type DockerProbe =
  | { ok: true; version: string; containers: DockerContainer[] }
  | { ok: false; reason: DockerFailure; detail: string }

/**
 * Why docker could not be read.
 *
 * Separated because the fixes are completely different, and "no containers" as
 * a catch-all is the failure mode this exists to avoid.
 */
export type DockerFailure =
  | 'not-installed'
  | 'daemon-unreachable'
  | 'permission-denied'
  | 'unknown'

export const DOCKER_FAILURE_HELP: Record<DockerFailure, string> = {
  'not-installed': 'The docker command is not on this host, or not on the PATH the SSH session gets.',
  'daemon-unreachable':
    'Docker is installed but its daemon is not answering. It may not be running, or it may be listening on a socket this user cannot see.',
  'permission-denied':
    'This user cannot talk to the docker socket. Adding them to the docker group grants root-equivalent access on most installs, so that is a decision worth making deliberately.',
  unknown: 'Docker returned an error that could not be classified. The raw message is below.'
}

/**
 * Classify a failed `docker` invocation.
 *
 * Ordered most specific first: a permission error also mentions the socket, so
 * checking for the daemon first would misreport it as "not running" and send
 * someone to restart a daemon that is already up.
 */
export function classifyDockerFailure(stderr: string, exitCode: number | null): DockerFailure {
  const s = stderr.toLowerCase()
  if (/permission denied/.test(s) && /docker\.sock|daemon/.test(s)) return 'permission-denied'
  if (/got permission denied while trying to connect/.test(s)) return 'permission-denied'
  if (/not found|no such file or directory|command not found/.test(s) || exitCode === 127) {
    return 'not-installed'
  }
  if (/cannot connect to the docker daemon|is the docker daemon running/.test(s)) return 'daemon-unreachable'
  return 'unknown'
}

// `--format` with an explicit separator rather than `--format '{{json .}}'`:
// the JSON shape has changed between docker versions and podman's differs
// again, whereas these fields have been stable for years. A separator that
// cannot appear in any of them keeps the split honest.
export const DOCKER_SEP = ''

export const DOCKER_LIST_COMMAND = [
  'docker version --format "{{.Server.Version}}" 2>&1',
  `echo "===SHELLPILOT-PS==="`,
  `docker ps --all --no-trunc --format "{{.ID}}${DOCKER_SEP}{{.Names}}${DOCKER_SEP}{{.Image}}${DOCKER_SEP}{{.State}}${DOCKER_SEP}{{.Status}}${DOCKER_SEP}{{.Ports}}${DOCKER_SEP}{{.CreatedAt}}" 2>&1`
].join('; ')

/**
 * Parse the collector's output.
 *
 * Returns the failure classification rather than an empty list when docker
 * could not be reached, so the panel can say which of the three problems it is.
 */
export function parseDockerOutput(output: string, exitCode: number | null): DockerProbe {
  const [versionPart, psPart] = output.split('===SHELLPILOT-PS===')
  const version = (versionPart ?? '').trim()

  // The version probe failing means docker itself is unusable; nothing after it
  // is worth reading.
  if (psPart === undefined || /error|denied|not found|cannot connect/i.test(version)) {
    return {
      ok: false,
      reason: classifyDockerFailure(version, exitCode),
      detail: version.split('\n')[0] ?? 'docker did not run'
    }
  }

  const lines = psPart.split('\n').map((l) => l.trim()).filter(Boolean)
  // `docker ps` can succeed at version and still fail here — a daemon that
  // stopped between the two, most obviously.
  const failing = lines.find((l) => /permission denied|cannot connect to the docker daemon/i.test(l))
  if (failing) {
    return { ok: false, reason: classifyDockerFailure(failing, exitCode), detail: failing }
  }

  const containers: DockerContainer[] = []
  for (const line of lines) {
    const f = line.split(DOCKER_SEP)
    if (f.length < 7) continue
    const [id, name, image, state, status, ports, createdAt] = f
    containers.push({
      id,
      shortId: id.slice(0, 12),
      name,
      image,
      state,
      status,
      ports: ports.trim(),
      createdAt
    })
  }
  return { ok: true, version, containers }
}

// Container ids and names are echoed into a shell command, so they are
// validated rather than escaped — the same rule the log tailer follows.
// Docker's own constraint is [a-zA-Z0-9][a-zA-Z0-9_.-]* for names, and ids are
// hex.
const REF_RE = /^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}$/

export function validateContainerRef(ref: string): boolean {
  return REF_RE.test(ref.trim())
}

/** `docker logs`, bounded. Never built from an unvalidated reference. */
export function buildDockerLogsCommand(ref: string, lines = 200, follow = false): string {
  if (!validateContainerRef(ref)) throw new Error('refusing to build a command from an invalid container reference')
  return `docker logs --tail ${lines}${follow ? ' -f' : ''} ${ref} 2>&1`
}

/**
 * `docker exec` for a shell.
 *
 * Tries bash and falls back to sh, because a minimal image has no bash and the
 * failure is otherwise an immediately-dead pane with no explanation.
 */
export function buildDockerShellCommand(ref: string): string {
  if (!validateContainerRef(ref)) throw new Error('refusing to build a command from an invalid container reference')
  return `docker exec -it ${ref} /bin/bash 2>/dev/null || docker exec -it ${ref} /bin/sh`
}
