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
  | { ok: true; version: string | null; containers: DockerContainer[] }
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

// A missing binary is reported by the *shell*, not by docker, and every shell
// words it differently. `no such file or directory` is deliberately NOT in this
// list on its own: docker 24 and rootless podman report a missing *socket* with
// `connect: no such file or directory`, which is the daemon being down.
const NOT_INSTALLED = [
  /command not found/,
  /:\s*not found/, // dash/busybox: "sh: 1: docker: not found"
  /could not be found/, // WSL: "The command 'docker' could not be found in this WSL 2 distro."
  /\bdocker: no such file or directory/, // a broken symlink on PATH
  /\bpodman: no such file or directory/
]

// The daemon side. Checked BEFORE the missing-binary patterns because the
// modern "daemon is down" message contains `no such file or directory` and
// misreading it sends someone to install docker on a host that already has it.
const DAEMON_DOWN = [
  /cannot connect to the docker daemon/,
  /is the docker daemon running/,
  /docker daemon is not running/,
  /cannot connect to podman/,
  /unable to connect to podman socket/,
  /error during connect/, // docker 24 / Windows named pipe
  /the system cannot find the file specified/,
  /\bdial unix\b/,
  /connection refused/
]

/**
 * Classify a failed `docker` invocation.
 *
 * Order matters and is not the obvious one:
 *
 *  1. Permission, because a permission error also names the socket and the
 *     daemon, so any daemon check placed first swallows it and sends someone to
 *     restart a daemon that is already up.
 *  2. The daemon, because docker 24's and rootless podman's "daemon is not
 *     answering" message ends in `connect: no such file or directory` - the
 *     same phrase a shell uses for a missing binary. Classifying that as
 *     "not installed" is the "fix the wrong machine" failure this module exists
 *     to avoid.
 *  3. Only then the shell's own "I could not find that program" wording.
 */
export function classifyDockerFailure(stderr: string, exitCode: number | null): DockerFailure {
  const s = stderr.toLowerCase()
  if (/permission denied/.test(s) && /docker\.sock|podman\.sock|daemon|socket/.test(s)) return 'permission-denied'
  if (/got permission denied while trying to connect/.test(s)) return 'permission-denied'
  if (DAEMON_DOWN.some((re) => re.test(s))) return 'daemon-unreachable'
  if (NOT_INSTALLED.some((re) => re.test(s))) return 'not-installed'
  // 127 is the shell's "no such command". Last, so it never overrides a daemon
  // message that happened to come back with an odd exit code.
  if (exitCode === 127) return 'not-installed'
  return 'unknown'
}

// `--format` with an explicit separator rather than `--format '{{json .}}'`:
// the JSON shape has changed between docker versions and podman's differs
// again, whereas these fields have been stable for years.
//
// The separator is U+0001 (SOH), written as an escape so it is visible in the
// source rather than an invisible byte someone deletes by accident. Why it
// survives the whole path:
//
//  * It cannot occur in any field. Docker's own name grammar is
//    `[a-zA-Z0-9][a-zA-Z0-9_.-]*`, image references are restricted to
//    alphanumerics and `/:@._-`, and State, Status, Ports and CreatedAt are all
//    generated by docker from fixed vocabularies and timestamps. None can carry
//    a C0 control byte.
//  * It survives SSH: `sshExec` uses ssh2's *exec* channel, not a shell or PTY,
//    so there is no line discipline to translate or swallow control bytes.
//  * It survives JSON IPC: `JSON.stringify` escapes it as a six-character
//    \u0001 sequence and `JSON.parse` restores it; Electron's structured
//    clone copies strings verbatim.
//
// A printable separator would be easier to eyeball in a log, but there is no
// printable byte that is impossible in an image reference *and* in a Ports
// string, so this one stays.
export const DOCKER_SEP = '\u0001'

export const DOCKER_LIST_COMMAND = [
  // Two probes, because they answer different questions. `--format
  // {{.Server.Version}}` asks the daemon its version, which podman (whose
  // `docker` is usually a shim) cannot answer at all - it fails with a
  // nil-pointer template error. Falling back to `--version` means a podman host
  // reports a version instead of being classified as a broken docker.
  //
  // The first probe's stderr goes to /dev/null on purpose: its failure is not
  // evidence of anything (podman fails it while working perfectly), and letting
  // its error text into the version block is what made a working host look
  // broken. The real diagnosis comes from `docker ps` below.
  'docker version --format "{{.Server.Version}}" 2>/dev/null || docker --version 2>&1',
  `echo "===SHELLPILOT-PS==="`,
  `docker ps --all --no-trunc --format "{{.ID}}${DOCKER_SEP}{{.Names}}${DOCKER_SEP}{{.Image}}${DOCKER_SEP}{{.State}}${DOCKER_SEP}{{.Status}}${DOCKER_SEP}{{.Ports}}${DOCKER_SEP}{{.CreatedAt}}" 2>&1`
].join('; ')

// Lines in the ps block that are docker complaining rather than docker
// listing. Only ever applied to lines carrying no separator, so a container
// whose image is `acme/permission-denied` is never read as an error.
const PS_FAILURE =
  /permission denied|cannot connect to|unable to connect|error during connect|^error\b|template:.*executing/i

/**
 * Pull a version out of the version block.
 *
 * Real hosts print things before the answer: `WARNING: Error loading config
 * file: /home/u/.docker/config.json: ... permission denied`, buildx plugin
 * warnings, and podman-docker's unconditional `Emulate Docker CLI using
 * podman.` notice. The previous version tested the whole block against
 * /error|denied/ and so reported a host with an unreadable
 * ~/.docker/config.json as a socket permissions failure - a different machine's
 * problem entirely.
 *
 * So: take the last line that looks like a version and ignore the rest.
 */
export function extractDockerVersion(text: string): string | null {
  const lines = text
    .split('\n')
    .map((l) => l.trim())
    .filter(Boolean)
  for (let i = lines.length - 1; i >= 0; i--) {
    const line = lines[i]
    if (/^\d+\.\d+/.test(line)) return line // the `--format` answer, alone on its line
    // `Docker version 24.0.7, build afdd53b` / `podman version 4.9.4`
    const m = line.match(/\bversion\s+v?(\d[\w.+-]*)/i)
    if (m) return m[1].replace(/[.,]+$/, '')
  }
  return null
}

/** `<no value>` is what a Go template prints for a field the binary does not
 *  have - docker before 20.10 has no `.State`. A chip reading `<no value>` is
 *  worse than one derived from the status line everybody already reads. */
function stateFrom(state: string, status: string): string {
  const s = state.trim()
  if (s !== '' && s !== '<no value>') return s
  if (/^up\b/i.test(status)) return 'running'
  if (/^exited\b/i.test(status)) return 'exited'
  if (/^created\b/i.test(status)) return 'created'
  if (/^restarting\b/i.test(status)) return 'restarting'
  if (/^paused\b/i.test(status)) return 'paused'
  if (/^dead\b/i.test(status)) return 'dead'
  return 'unknown'
}

/**
 * Parse the collector's output.
 *
 * Returns the failure classification rather than an empty list when docker
 * could not be reached, so the panel can say which of the three problems it is.
 *
 * The version block is no longer allowed to fail the whole read. It is
 * cosmetic - the containers are the point - and on a podman host, or one with a
 * warning-producing docker config, it is noisy in ways that say nothing about
 * whether `docker ps` works.
 */
export function parseDockerOutput(output: string, exitCode: number | null): DockerProbe {
  const MARKER = '===SHELLPILOT-PS==='
  const at = output.indexOf(MARKER)
  const versionPart = at === -1 ? output : output.slice(0, at)
  const psPart = at === -1 ? undefined : output.slice(at + MARKER.length)

  // No marker at all means the shell never reached the second command: docker
  // is missing, or the transport cut the output off. That is the only case
  // where the version block is the diagnosis.
  if (psPart === undefined) {
    const detail = versionPart.split('\n').find((l) => l.trim() !== '')?.trim() ?? 'docker did not run'
    return { ok: false, reason: classifyDockerFailure(versionPart, exitCode), detail }
  }

  const lines = psPart
    .split('\n')
    .map((l) => l.trim())
    .filter(Boolean)

  // A real row carries six separators. Everything else is docker talking to us:
  // a warning ("WARNING: bridge-nf-call-iptables is disabled"), the
  // podman-docker shim's "Emulate Docker CLI using podman." notice, or an
  // error. Splitting on that before pattern-matching keeps a container's own
  // fields from ever being read as an error message.
  const rows = lines.filter((l) => l.includes(DOCKER_SEP))
  const noise = lines.filter((l) => !l.includes(DOCKER_SEP))

  const failing = noise.find((l) => PS_FAILURE.test(l))
  if (failing) return { ok: false, reason: classifyDockerFailure(failing, exitCode), detail: failing }

  const containers: DockerContainer[] = []
  const malformed: string[] = []
  for (const line of rows) {
    const f = line.split(DOCKER_SEP)
    if (f.length !== 7) {
      malformed.push(line)
      continue
    }
    const [id, name, image, state, status, ports, createdAt] = f
    containers.push({
      id,
      shortId: id.slice(0, 12),
      name,
      image,
      state: stateFrom(state, status),
      status,
      ports: ports.trim(),
      createdAt
    })
  }

  // Rows shaped wrong with nothing parsed means the template did not render the
  // way this parser assumes - a different runtime, most likely. Reporting "no
  // containers" there is the exact lie this module is built to avoid.
  if (containers.length === 0 && malformed.length > 0) {
    return {
      ok: false,
      reason: 'unknown',
      detail: `docker ps returned ${malformed.length} row(s) this parser could not read: ${malformed[0].split(DOCKER_SEP).join(' | ')}`
    }
  }

  return { ok: true, version: extractDockerVersion(versionPart), containers }
}

// Container ids and names are echoed into a shell command, so they are
// validated rather than escaped — the same rule the log tailer follows.
// Docker's own constraint is [a-zA-Z0-9][a-zA-Z0-9_.-]* for names, and ids are
// hex. The cap is 255 because that is docker's own name limit and Kubernetes'
// generated `k8s_POD_<pod>_<ns>_<uid>_<n>` names get long.
const REF_RE = /^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,254}$/

export function validateContainerRef(ref: string): boolean {
  return REF_RE.test(ref.trim())
}

/**
 * The `--tail` count, made safe to interpolate.
 *
 * `lines` reaches this through IPC, where the `lines: number` annotation on the
 * handler is a compile-time claim and nothing more — a structured-clone value
 * arrives with whatever type the caller sent. `--tail ${lines}` with a string
 * is a command injection, and it is not the caller's job to notice: this
 * function is exported, and every other builder here refuses bad input on its
 * own rather than trusting who called it.
 *
 * Refusing outright (the rule the reference validator follows) rather than
 * silently defaulting, so a caller passing rubbish finds out.
 */
function validTailCount(lines: unknown): number {
  if (typeof lines !== 'number' || !Number.isInteger(lines) || lines < 1 || lines > 100_000) {
    throw new Error('refusing to build a command from an invalid log line count')
  }
  return lines
}

/** `docker logs`, bounded. Never built from an unvalidated reference or count. */
export function buildDockerLogsCommand(ref: string, lines: number = 200, follow = false): string {
  if (!validateContainerRef(ref)) throw new Error('refusing to build a command from an invalid container reference')
  const tail = validTailCount(lines)
  return `docker logs --tail ${tail}${follow ? ' -f' : ''} ${ref} 2>&1`
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
