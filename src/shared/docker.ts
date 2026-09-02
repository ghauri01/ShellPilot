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
  /**
   * `com.docker.compose.project` / `com.docker.compose.service`, when the
   * runtime would tell us.
   *
   * Optional rather than defaulted to a string, because "not a compose
   * container" and "this runtime could not answer" are different facts and the
   * panel groups differently for each. Read from a SEPARATE `docker ps` whose
   * failure is ignored — see `buildDockerListCommand`.
   */
  composeProject?: string
  composeService?: string
}

export type DockerProbe =
  | {
      ok: true
      version: string | null
      containers: DockerContainer[]
      /**
       * Read as root after the unprivileged attempt was refused.
       *
       * Surfaced rather than hidden: running as root is a thing the user should
       * know happened, even when it is the only way to get an answer.
       */
      usedSudo?: boolean
      /**
       * Whether compose grouping could be read at all.
       *
       * `unavailable` means this runtime could not render the label template,
       * so every container looks ungrouped — which is a different statement
       * from "none of these containers belong to a compose project", and the
       * panel says which one it is rather than letting the user infer the
       * wrong one. Absent when the collector did not ask.
       */
      composeLabels?: 'read' | 'unavailable'
    }
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
  'not-installed':
    'No docker on this host. Looked on PATH and in /usr/bin, /usr/local/bin, /snap/bin, /opt/homebrew/bin and /usr/sbin. If it lives somewhere else, a symlink into /usr/local/bin is the usual fix.',
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

/**
 * Two more levels, for the fields that are lists.
 *
 * `docker inspect` has to answer "which ports, which mounts, which networks" in
 * ONE template, and a Go template renders one line. So a field may hold a list
 * (items separated by U+0002) and an item may hold fields of its own (U+0003).
 * Every argument for U+0001 above applies unchanged: these are C0 control bytes,
 * nothing docker generates can contain one, the ssh exec channel has no line
 * discipline to translate them, and JSON escapes them on the way to the
 * renderer.
 */
export const DOCKER_ITEM_SEP = '\u0002'
export const DOCKER_SUB_SEP = '\u0003'

/**
 * Where a tool actually lives when an SSH session cannot find it.
 *
 * `ssh host cmd` runs a NON-LOGIN shell, which on most distributions means a
 * PATH of roughly `/usr/bin:/bin` — no `/usr/local/bin`, no `/snap/bin`, no
 * `/opt/homebrew/bin`. So "command not found" over SSH very often means
 * "installed, but not somewhere this shell looks", which is a completely
 * different problem from not being installed and has a completely different
 * fix.
 *
 * Emits a shell fragment that sets `$SP_BIN` to the first thing that exists,
 * so the caller can run `"$SP_BIN" ...` and get the same answer a login shell
 * would.
 */
export function resolveBinary(name: string, extraPaths: string[] = []): string {
  const candidates = [
    name,
    `/usr/bin/${name}`,
    `/usr/local/bin/${name}`,
    `/snap/bin/${name}`,
    `/opt/homebrew/bin/${name}`,
    `/usr/sbin/${name}`,
    ...extraPaths
  ]
  // `command -v` rather than `which`: built in, and it is the POSIX spelling.
  return (
    `SP_BIN=""; for c in ${candidates.join(' ')}; do ` +
    `command -v "$c" >/dev/null 2>&1 && SP_BIN="$c" && break; done; ` +
    `[ -z "$SP_BIN" ] && SP_BIN=${name}`
  )
}

/**
 * Whether this account could re-run something as root WITHOUT being asked for
 * a password.
 *
 * `sudo -n` never prompts — it fails immediately when a password is required.
 * That is the whole reason it is safe to probe: it cannot hang an exec waiting
 * on a tty that is not there, and it cannot silently consume a cached sudo
 * timestamp the user did not intend for us.
 */
export const SUDO_PROBE = 'sudo -n true >/dev/null 2>&1 && echo SP_SUDO_OK || true'

/**
 * Build the read command, optionally as root and with the binary resolved.
 *
 * `sudo` is a parameter rather than a second constant because the retry has to
 * be the SAME probe — a sudo path that read differently would answer a
 * different question and the two results could not be compared.
 */
export function buildDockerListCommand(opts: { sudo?: boolean } = {}): string {
  const run = opts.sudo ? 'sudo -n "$SP_BIN"' : '"$SP_BIN"'
  return [
    resolveBinary('docker'),
    `${run} version --format "{{.Server.Version}}" 2>/dev/null || ${run} --version 2>&1`,
    // Compose labels, asked for SEPARATELY and allowed to fail.
    //
    // `{{.Label "x"}}` is a docker CLI template method. A runtime that does not
    // have it fails the template and returns nothing for the WHOLE listing, so
    // folding these two fields into the main `docker ps` below would trade the
    // feature (the container list) for the convenience (grouping it). Asked
    // for on its own, a runtime that cannot answer costs a grouping the panel
    // then says it could not read.
    //
    // Placed BEFORE the ps block, not after, and that ordering is load-bearing:
    // this line ends in `|| true`, and a `|| true` after `docker ps` would
    // overwrite the exit status parseDockerOutput uses to tell a host with no
    // docker from a host with no containers. stderr is folded in rather than
    // discarded so a template failure is visible as such.
    `echo "${DOCKER_MARKERS.compose}"`,
    `${run} ps --all --no-trunc --format "{{.ID}}${DOCKER_SEP}{{.Label \\"com.docker.compose.project\\"}}${DOCKER_SEP}{{.Label \\"com.docker.compose.service\\"}}" 2>&1 || true`,
    `echo "${DOCKER_MARKERS.ps}"`,
    `${run} ps --all --no-trunc --format "{{.ID}}${DOCKER_SEP}{{.Names}}${DOCKER_SEP}{{.Image}}${DOCKER_SEP}{{.State}}${DOCKER_SEP}{{.Status}}${DOCKER_SEP}{{.Ports}}${DOCKER_SEP}{{.CreatedAt}}" 2>&1`
  ].join('; ')
}

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
  const head = at === -1 ? output : output.slice(0, at)
  const psPart = at === -1 ? undefined : output.slice(at + MARKER.length)

  // The compose block sits between the version probe and the list. Absent is
  // the normal case for output this parser has seen before — an older
  // collector, or any caller building the command itself — so its absence is
  // not a failure, it is simply no grouping.
  const composeAt = head.indexOf(DOCKER_MARKERS.compose)
  const versionPart = composeAt === -1 ? head : head.slice(0, composeAt)
  const compose =
    composeAt === -1
      ? { labels: new Map<string, { project?: string; service?: string }>(), available: false }
      : parseComposeLabels(head.slice(composeAt + DOCKER_MARKERS.compose.length))

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

  // Nothing listed, nothing recognised, and a non-zero exit: `docker ps` did
  // not run. The exit status is the honest signal here — an empty list comes
  // back as 0 — and it is what keeps the shell's own wording ("docker: command
  // not found") from having to be pattern-matched against warning lines, where
  // a stray "not found" would be read as a missing binary. Without this, a host
  // with no docker at all reports "Docker is running and has no containers."
  if (rows.length === 0 && noise.length > 0 && exitCode !== 0) {
    const detail = noise[noise.length - 1]
    return { ok: false, reason: classifyDockerFailure(noise.join('\n'), exitCode), detail }
  }

  const containers: DockerContainer[] = []
  const malformed: string[] = []
  for (const line of rows) {
    const f = line.split(DOCKER_SEP)
    if (f.length !== 7) {
      malformed.push(line)
      continue
    }
    const [id, name, image, state, status, ports, createdAt] = f
    const labels = compose.labels.get(id)
    containers.push({
      id,
      shortId: id.slice(0, 12),
      name,
      image,
      state: stateFrom(state, status),
      status,
      ports: ports.trim(),
      createdAt,
      composeProject: labels?.project,
      composeService: labels?.service
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

  return {
    ok: true,
    version: extractDockerVersion(versionPart),
    containers,
    composeLabels: composeAt === -1 ? undefined : compose.available ? 'read' : 'unavailable'
  }
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

/**
 * A relative `--since`, made safe to interpolate.
 *
 * Docker also accepts an RFC3339 timestamp and a Unix epoch, and neither is
 * accepted here: a duration is what an operator actually types ("the last ten
 * minutes"), it has a shape a regex can prove, and the other two are more
 * grammar to get wrong for no operational gain. Refused rather than defaulted,
 * like every other validator in this file.
 */
function validSince(since: unknown): string {
  if (typeof since !== 'string' || !/^[0-9]{1,6}[smh]$/.test(since)) {
    throw new Error('refusing to build a command from an invalid log window')
  }
  return since
}

export interface DockerLogsOptions {
  /** Read as root. Brings the binary resolver with it, the same as every other builder. */
  sudo?: boolean
  /** `--timestamps`. Off by default because it doubles the width of every line. */
  timestamps?: boolean
  /** A relative window: `10m`, `2h`, `900s`. */
  since?: string
}

/**
 * `docker logs`, bounded. Never built from an unvalidated reference or count.
 *
 * With no options this is byte-for-byte the command it has always been — a
 * bare `docker logs`, no binary resolution, nothing shell-significant but the
 * deliberate `2>&1`. Options bring the resolver in, because the moment root is
 * involved the PATH an ssh non-login shell gets is the next thing to go wrong.
 */
export function buildDockerLogsCommand(
  ref: string,
  lines: number = 200,
  follow = false,
  opts: DockerLogsOptions = {}
): string {
  if (!validateContainerRef(ref)) throw new Error('refusing to build a command from an invalid container reference')
  const tail = validTailCount(lines)
  const flags = [
    `--tail ${tail}`,
    opts.timestamps ? '--timestamps' : '',
    opts.since !== undefined ? `--since ${validSince(opts.since)}` : '',
    follow ? '-f' : ''
  ]
    .filter((f) => f !== '')
    .join(' ')
  if (opts.sudo !== true) {
    // The unchanged shape. Anything else here would make the common path
    // depend on a shell fragment it does not need.
    return `docker logs ${flags} ${ref} 2>&1`
  }
  return [resolveBinary('docker'), `sudo -n "$SP_BIN" logs ${flags} ${ref} 2>&1`].join('; ')
}

/**
 * `docker exec` for a shell.
 *
 * Tries bash and falls back to sh, because a minimal image has no bash and the
 * failure is otherwise an immediately-dead pane with no explanation.
 */
export function buildDockerShellCommand(ref: string, opts: { sudo?: boolean } = {}): string {
  if (!validateContainerRef(ref)) throw new Error('refusing to build a command from an invalid container reference')
  // The binary is resolved and the socket permission is honoured here for the
  // same reason the read paths do it: an account that cannot reach the docker
  // socket cannot exec either, and a panel that lists containers as root and
  // then opens a shell as nobody is not one feature, it is two that disagree.
  const run = opts.sudo ? 'sudo -n "$SP_BIN"' : '"$SP_BIN"'
  return [
    resolveBinary('docker'),
    `${run} exec -it ${ref} /bin/bash 2>/dev/null || ${run} exec -it ${ref} /bin/sh`
  ].join('; ')
}

// ===========================================================================
// Day-to-day operations
// ===========================================================================
//
// Everything above this line reads a list. Everything below it is what an
// operator actually reaches for once the list is on screen: where the disk
// went, what a container is wired to, how hard it is working, and — the only
// state-changing thing here — start/stop/restart.
//
// Three rules hold for all of it, and they are the same three the list follows:
//
//  1. Commands are BUILT by validating builders that throw. Nothing here
//     escapes user input, because escaping is a promise about a shell we do not
//     control. A reference that cannot be proven safe produces an exception,
//     not a quoted string.
//  2. A block that fails must say WHICH failure it was. "Nothing here" for a
//     permissions problem is the lie this whole module is shaped around
//     avoiding, and it is just as wrong for `docker system df` as it is for
//     `docker ps`.
//  3. Secrets never leave the host. `docker inspect` with no template dumps
//     `Config.Env`, which on a real host is database URLs, API keys and signing
//     secrets. So inspect is a hand-written template naming the fields we want,
//     and environment is reported as a COUNT computed by the remote Go
//     template. The values are never read, never cross the SSH channel, never
//     reach main's memory and therefore cannot end up in an error detail.
//
// What is deliberately NOT here, and will not be added casually:
//
//  * `docker rm` / `rmi` / `volume rm`. Removing a container is recoverable
//    only if you can reconstruct how it was run; removing a volume is not
//    recoverable at all. A button cannot carry that.
//  * `docker system prune`. It deletes every stopped container, every dangling
//    image, every unused network and — with one more flag people habitually
//    add — every unused volume, on a host where "unused" means "not attached
//    right now", which includes the database volume of anything that happens to
//    be stopped. It is the single most regretted docker command, its blast
//    radius is not knowable from the UI that offers it, and the disk-usage
//    panel above it exists precisely so the operator can decide what to remove
//    themselves, in a shell, with the numbers in front of them.
//  * `docker kill`. `stop` sends SIGTERM and waits; kill does not, and the
//    difference is whether a database finishes its write.

const ANY_MARKER = /===SHELLPILOT-[A-Z]+===/

/**
 * Section markers.
 *
 * Every collector below is several docker invocations inside a single round
 * trip, and the markers are what let one block fail without taking the read
 * with it — the rule the version block already follows.
 */
export const DOCKER_MARKERS = {
  ps: '===SHELLPILOT-PS===',
  compose: '===SHELLPILOT-COMPOSE===',
  df: '===SHELLPILOT-DF===',
  inspect: '===SHELLPILOT-INSPECT===',
  health: '===SHELLPILOT-HEALTH===',
  stats: '===SHELLPILOT-STATS===',
  act: '===SHELLPILOT-ACT==='
} as const

/**
 * The text after `marker`, up to the next marker.
 *
 * `undefined` for a marker that never appeared is load-bearing and different
 * from an empty string: it means the shell never reached that command, which is
 * a diagnosis, whereas an empty section is an answer.
 */
function section(output: string, marker: string): string | undefined {
  const at = output.indexOf(marker)
  if (at === -1) return undefined
  const rest = output.slice(at + marker.length)
  const next = rest.search(ANY_MARKER)
  return next === -1 ? rest : rest.slice(0, next)
}

function nonEmptyLines(text: string): string[] {
  return text
    .split('\n')
    .map((l) => l.trim())
    .filter((l) => l !== '')
}

// Lines that are docker complaining rather than docker answering. Wider than
// PS_FAILURE because these blocks have no separator to tell a row from a
// message, so the shell's own wording has to be in here too.
const BLOCK_FAILURE =
  /permission denied|cannot connect to|unable to connect|error during connect|is the docker daemon running|command not found|:\s*not found|could not be found|^error\b|template:.*executing/i

/**
 * The failure a block reports, or null when it is not reporting one.
 *
 * Every parser below calls this before concluding "nothing here", because
 * "nothing here" and "you are not allowed to look" are the two answers this
 * module exists to keep apart.
 */
function blockFailure(text: string, exitCode: number | null): { reason: DockerFailure; detail: string } | null {
  const failing = nonEmptyLines(text).filter((l) => BLOCK_FAILURE.test(l))
  if (failing.length === 0) return null
  return { reason: classifyDockerFailure(failing.join('\n'), exitCode), detail: failing[failing.length - 1] }
}

/** `"$SP_BIN"`, or `sudo -n "$SP_BIN"`. The one place the two differ. */
function runner(sudo: boolean | undefined): string {
  return sudo ? 'sudo -n "$SP_BIN"' : '"$SP_BIN"'
}

// --------------------------------------------------------------- compose

/**
 * `com.docker.compose.project` / `.service` per container id.
 *
 * Read by a SECOND `docker ps` rather than by widening the main template, and
 * that is the whole point: `{{.Label "x"}}` is a docker CLI template method,
 * and a runtime that does not have it fails the template and returns NOTHING
 * for the entire listing. Grouping is a convenience; the container list is the
 * feature. So the convenience is asked for separately, in a block whose failure
 * is survivable, and the panel says when it could not be read rather than
 * quietly showing every container as ungrouped.
 */
function parseComposeLabels(text: string): {
  labels: Map<string, { project?: string; service?: string }>
  available: boolean
} {
  const labels = new Map<string, { project?: string; service?: string }>()
  const all = nonEmptyLines(text)
  const rows = all.filter((l) => l.includes(DOCKER_SEP))
  const noise = all.filter((l) => !l.includes(DOCKER_SEP))
  for (const line of rows) {
    const f = line.split(DOCKER_SEP)
    if (f.length !== 3) continue
    const [id, project, service] = f
    if (project.trim() === '' && service.trim() === '') continue
    labels.set(id, {
      project: project.trim() === '' ? undefined : project.trim(),
      service: service.trim() === '' ? undefined : service.trim()
    })
  }
  // Noise with no rows at all is a template this runtime could not render. Not
  // an error worth failing the read over, but not "no compose containers"
  // either, and the difference is what the panel tells the user.
  const available = !(rows.length === 0 && noise.some((l) => BLOCK_FAILURE.test(l)))
  return { labels, available }
}

export interface DockerComposeGroup {
  /** null is the ungrouped bucket — containers nobody's compose file owns. */
  project: string | null
  containers: DockerContainer[]
}

/**
 * Containers grouped the way people think about a host.
 *
 * Compose projects first, alphabetically, then everything else. The ungrouped
 * bucket goes last rather than being hidden: a stray container nobody's compose
 * file owns is frequently the thing being looked for.
 */
export function groupByComposeProject(containers: DockerContainer[]): DockerComposeGroup[] {
  const byProject = new Map<string, DockerContainer[]>()
  const loose: DockerContainer[] = []
  for (const c of containers) {
    if (c.composeProject === undefined || c.composeProject === '') loose.push(c)
    else {
      const list = byProject.get(c.composeProject)
      if (list) list.push(c)
      else byProject.set(c.composeProject, [c])
    }
  }
  const order = (a: DockerContainer, b: DockerContainer): number =>
    (a.composeService ?? a.name).localeCompare(b.composeService ?? b.name)
  const groups: DockerComposeGroup[] = [...byProject.entries()]
    .sort((a, b) => a[0].localeCompare(b[0]))
    .map(([project, list]) => ({ project, containers: [...list].sort(order) }))
  if (loose.length > 0) groups.push({ project: null, containers: [...loose].sort(order) })
  return groups
}

// ------------------------------------------------------------ system df

/** One row of `docker system df`. */
export interface DockerDiskRow {
  /** `Images`, `Containers`, `Local Volumes`, `Build Cache`. Verbatim. */
  type: string
  total: number | null
  active: number | null
  /** As docker wrote it — "6.789GB". Shown, so the UI never re-renders a number docker already formatted. */
  size: string
  sizeBytes: number | null
  reclaimable: string
  reclaimableBytes: number | null
  reclaimablePercent: number | null
}

export type DockerDiskProbe =
  | { ok: true; rows: DockerDiskRow[]; usedSudo?: boolean }
  | { ok: false; reason: DockerFailure; detail: string }

/**
 * `docker system df`.
 *
 * Deliberately NOT `--format`: podman and docker disagree about the field names
 * (`.Size` vs `.RawSize`, `.Total` vs `.TotalCount`) and a template that names
 * the wrong one fails outright, which would turn "your disk is full" into "this
 * host is broken". The plain table has been column-stable for years, its
 * columns are separated by two or more spaces, and the one type name containing
 * a space — `Local Volumes` — is exactly why the split is on two.
 *
 * No `-v`: the verbose form lists every image and volume by name and is a page
 * of output for a paragraph of answer.
 */
export function buildDockerDiskCommand(opts: { sudo?: boolean } = {}): string {
  const run = runner(opts.sudo)
  return [
    resolveBinary('docker'),
    `echo "${DOCKER_MARKERS.df}"`,
    `${run} system df 2>&1`
  ].join('; ')
}

const SIZE_UNITS: Record<string, number> = {
  b: 1,
  kb: 1e3,
  mb: 1e6,
  gb: 1e9,
  tb: 1e12,
  pb: 1e15,
  kib: 1024,
  mib: 1024 ** 2,
  gib: 1024 ** 3,
  tib: 1024 ** 4,
  pib: 1024 ** 5
}

/**
 * "6.789GB" as a number of bytes, or null.
 *
 * Both unit families, because docker prints decimal (`GB`, from go-units'
 * HumanSize) and several tools in the same family print binary (`GiB`).
 * Guessing one and being wrong by 7% is the sort of number an operator makes a
 * capacity decision on, so both are read literally.
 */
export function parseDockerSize(text: string): number | null {
  const m = text.trim().match(/^([0-9]+(?:\.[0-9]+)?)\s*([a-zA-Z]{1,3})$/)
  if (!m) return null
  const unit = SIZE_UNITS[m[2].toLowerCase()]
  if (unit === undefined) return null
  return Number(m[1]) * unit
}

function parseCount(text: string): number | null {
  const t = text.trim()
  if (!/^-?\d+$/.test(t)) return null
  return Number(t)
}

export function parseDockerDiskOutput(output: string, exitCode: number | null): DockerDiskProbe {
  const body = section(output, DOCKER_MARKERS.df)
  if (body === undefined) {
    const detail = nonEmptyLines(output)[0] ?? 'docker did not run'
    return { ok: false, reason: classifyDockerFailure(output, exitCode), detail }
  }

  const rows: DockerDiskRow[] = []
  for (const line of nonEmptyLines(body)) {
    if (/^TYPE\s/i.test(line)) continue
    const cols = line.split(/\s{2,}/).map((c) => c.trim())
    // TYPE TOTAL ACTIVE SIZE RECLAIMABLE. A row with fewer columns is not a row.
    if (cols.length < 4) continue
    if (parseCount(cols[1]) === null) continue
    const reclaimable = cols[4] ?? ''
    const pct = reclaimable.match(/\((\d+(?:\.\d+)?)%\)/)
    rows.push({
      type: cols[0],
      total: parseCount(cols[1]),
      active: parseCount(cols[2]),
      size: cols[3],
      sizeBytes: parseDockerSize(cols[3]),
      reclaimable,
      reclaimableBytes: parseDockerSize(reclaimable.replace(/\s*\([^)]*\)\s*$/, '')),
      reclaimablePercent: pct ? Number(pct[1]) : null
    })
  }

  if (rows.length === 0) {
    // A permissions problem must never render as "this host uses no disk".
    const failure = blockFailure(body, exitCode)
    if (failure) return { ok: false, ...failure }
    return {
      ok: false,
      reason: 'unknown',
      detail:
        nonEmptyLines(body)[0] ??
        'docker system df returned nothing this parser could read'
    }
  }
  return { ok: true, rows }
}

// -------------------------------------------------------------- inspect

export interface DockerPortBinding {
  /** `80/tcp` — the port inside the container. */
  container: string
  /** `0.0.0.0:8080`, or '' when the port is exposed but not published. */
  host: string
}

export interface DockerMount {
  type: string
  source: string
  destination: string
  mode: 'rw' | 'ro'
}

export interface DockerNetworkAttachment {
  name: string
  ip: string
}

export interface DockerInspect {
  id: string
  shortId: string
  name: string
  /** The image as the container was asked for — `nginx:1.25`. */
  image: string
  /** The digest it actually resolved to. The two disagree constantly, and that disagreement is usually the bug. */
  imageId: string
  status: string
  exitCode: number | null
  startedAt: string
  createdAt: string
  /** `no`, `always`, `unless-stopped`, `on-failure`. Empty string when unset. */
  restartPolicy: string
  restartMaxRetries: number | null
  /** How many times docker has already restarted it. A number climbing on its own is a crash loop. */
  restartCount: number | null
  /** null when the image declares no healthcheck, which is not the same as unhealthy. */
  health: string | null
  /**
   * HOW MANY environment variables, never which or what.
   *
   * Counted by the remote Go template, so the values are not read, do not cross
   * the channel and cannot reach an error string. A container's environment is
   * where its database password lives.
   */
  envCount: number | null
  ports: DockerPortBinding[]
  mounts: DockerMount[]
  networks: DockerNetworkAttachment[]
  logDriver: string
}

export type DockerInspectProbe =
  | { ok: true; inspect: DockerInspect; usedSudo?: boolean }
  | { ok: false; reason: DockerFailure; detail: string }

/**
 * The inspect template — every field this app is willing to read, and no more.
 *
 * A whitelist rather than a filter, because the two fail in opposite
 * directions: a filter that misses a field leaks it, a whitelist that misses a
 * field merely fails to show it. `Config.Env`, `Config.Cmd` and
 * `Config.Entrypoint` are all absent on purpose — the first carries secrets
 * outright and the other two carry them often enough (`--password` in an
 * entrypoint is not rare).
 *
 * The ranges are what force the two extra separator levels: a Go template
 * renders one line, so a list has to live inside a field.
 */
const INSPECT_TEMPLATE = [
  '{{.Id}}',
  '{{.Name}}',
  '{{.Config.Image}}',
  '{{.Image}}',
  '{{.State.Status}}',
  '{{.State.ExitCode}}',
  '{{.State.StartedAt}}',
  '{{.Created}}',
  '{{.HostConfig.RestartPolicy.Name}}',
  '{{.HostConfig.RestartPolicy.MaximumRetryCount}}',
  '{{.RestartCount}}',
  '{{len .Config.Env}}',
  `{{range $p, $b := .NetworkSettings.Ports}}{{$p}}${DOCKER_SUB_SEP}{{range $b}}{{.HostIp}}:{{.HostPort}} {{end}}${DOCKER_ITEM_SEP}{{end}}`,
  `{{range .Mounts}}{{.Type}}${DOCKER_SUB_SEP}{{.Source}}${DOCKER_SUB_SEP}{{.Destination}}${DOCKER_SUB_SEP}{{if .RW}}rw{{else}}ro{{end}}${DOCKER_ITEM_SEP}{{end}}`,
  `{{range $n, $c := .NetworkSettings.Networks}}{{$n}}${DOCKER_SUB_SEP}{{$c.IPAddress}}${DOCKER_ITEM_SEP}{{end}}`,
  '{{.HostConfig.LogConfig.Type}}'
].join(DOCKER_SEP)

/** How many fields `INSPECT_TEMPLATE` renders. Pinned so a field added without a parser change fails loudly. */
export const DOCKER_INSPECT_FIELDS = 16

/**
 * `docker inspect`, reduced to the fields above.
 *
 * The health probe is a SEPARATE invocation ending in `|| true`, and it has to
 * be: a container with no healthcheck has a nil `.State.Health`, so
 * `{{.State.Health.Status}}` is a template error on exactly the containers most
 * hosts are full of. Folded into the main template it would fail the whole
 * inspect for every container that is merely not health-checked.
 *
 * It runs FIRST so the main inspect is the last command in the pipeline and its
 * exit status is the one the transport reports — `|| true` at the end would
 * erase the 127 that says docker is not installed.
 *
 * The format string is in SINGLE quotes. It contains `$p`, `$b`, `$n` and `$c`,
 * which a double-quoted shell word would expand to nothing, silently producing
 * empty ports, mounts and networks on every container.
 */
export function buildDockerInspectCommand(ref: string, opts: { sudo?: boolean } = {}): string {
  if (!validateContainerRef(ref)) throw new Error('refusing to build a command from an invalid container reference')
  const run = runner(opts.sudo)
  return [
    resolveBinary('docker'),
    `echo "${DOCKER_MARKERS.health}"`,
    `${run} inspect --format '{{.State.Health.Status}}' ${ref} 2>/dev/null || true`,
    `echo "${DOCKER_MARKERS.inspect}"`,
    `${run} inspect --format '${INSPECT_TEMPLATE}' ${ref} 2>&1`
  ].join('; ')
}

function splitItems(field: string): string[] {
  return field.split(DOCKER_ITEM_SEP).filter((i) => i.trim() !== '')
}

export function parseDockerInspectOutput(output: string, exitCode: number | null): DockerInspectProbe {
  const body = section(output, DOCKER_MARKERS.inspect)
  if (body === undefined) {
    const detail = nonEmptyLines(output)[0] ?? 'docker did not run'
    return { ok: false, reason: classifyDockerFailure(output, exitCode), detail }
  }

  const row = nonEmptyLines(body).find((l) => l.includes(DOCKER_SEP))
  if (row === undefined) {
    const failure = blockFailure(body, exitCode)
    if (failure) return { ok: false, ...failure }
    return {
      ok: false,
      reason: 'unknown',
      detail: nonEmptyLines(body)[0] ?? 'docker inspect returned nothing'
    }
  }

  const f = row.split(DOCKER_SEP)
  if (f.length !== DOCKER_INSPECT_FIELDS) {
    // A different runtime rendered a different number of fields. Saying so
    // beats showing a container with half its wiring blank.
    return {
      ok: false,
      reason: 'unknown',
      detail: `docker inspect returned ${f.length} fields where this parser expects ${DOCKER_INSPECT_FIELDS}`
    }
  }

  const ports: DockerPortBinding[] = splitItems(f[12]).map((item) => {
    const [container, host = ''] = item.split(DOCKER_SUB_SEP)
    return { container: container.trim(), host: host.trim() }
  })

  const mounts: DockerMount[] = splitItems(f[13]).flatMap((item) => {
    const parts = item.split(DOCKER_SUB_SEP)
    if (parts.length !== 4) return []
    return [{ type: parts[0], source: parts[1], destination: parts[2], mode: parts[3] === 'ro' ? 'ro' : 'rw' }]
  })

  const networks: DockerNetworkAttachment[] = splitItems(f[14]).flatMap((item) => {
    const parts = item.split(DOCKER_SUB_SEP)
    if (parts.length < 1 || parts[0].trim() === '') return []
    return [{ name: parts[0].trim(), ip: (parts[1] ?? '').trim() }]
  })

  // The health block is allowed to be missing, empty, or noise: no healthcheck
  // is the common case, and "unknown" is a lie a chip would tell.
  const healthBlock = section(output, DOCKER_MARKERS.health) ?? ''
  const healthLine = nonEmptyLines(healthBlock).find((l) => /^(starting|healthy|unhealthy|none)$/i.test(l))

  const id = f[0]
  return {
    ok: true,
    inspect: {
      id,
      shortId: id.slice(0, 12),
      // docker returns the name with a leading slash. Nobody types it that way.
      name: f[1].replace(/^\//, ''),
      image: f[2],
      imageId: f[3],
      status: f[4],
      exitCode: parseCount(f[5]),
      startedAt: f[6],
      createdAt: f[7],
      restartPolicy: f[8].trim(),
      restartMaxRetries: parseCount(f[9]),
      restartCount: parseCount(f[10]),
      health: healthLine ? healthLine.toLowerCase() : null,
      envCount: parseCount(f[11]),
      ports,
      mounts,
      networks,
      logDriver: f[15].trim()
    }
  }
}

// ---------------------------------------------------------------- stats

export interface DockerStat {
  name: string
  cpuPercent: number | null
  /** As docker wrote it: "45.2MiB / 1.944GiB". */
  memUsage: string
  memPercent: number | null
  netIo: string
  blockIo: string
}

export type DockerStatsProbe =
  | { ok: true; stats: DockerStat[]; usedSudo?: boolean }
  | { ok: false; reason: DockerFailure; detail: string }

/** Containers per stats call. A bound on the command length, not a product limit. */
export const DOCKER_STATS_MAX_REFS = 100

/**
 * `docker stats --no-stream` for named containers.
 *
 * `--no-stream` because a streaming stats table is a second live channel to
 * manage for a number that is interesting once. The references are explicit —
 * bare `docker stats` would sample every running container on the host, and
 * "everything" is not a target the caller chose.
 *
 * `.PIDs` is left out although it is useful: docker spells it `.PIDs` and
 * podman spells it `.PIDS`, Go templates are case-sensitive, and a wrong field
 * name fails the whole table rather than one column.
 */
export function buildDockerStatsCommand(refs: string[], opts: { sudo?: boolean } = {}): string {
  if (!Array.isArray(refs) || refs.length === 0) {
    throw new Error('refusing to build a stats command with no container references')
  }
  if (refs.length > DOCKER_STATS_MAX_REFS) {
    throw new Error(`refusing to build a stats command for more than ${DOCKER_STATS_MAX_REFS} containers`)
  }
  for (const ref of refs) {
    if (!validateContainerRef(ref)) throw new Error('refusing to build a command from an invalid container reference')
  }
  const run = runner(opts.sudo)
  const fmt = [
    '{{.Name}}',
    '{{.CPUPerc}}',
    '{{.MemUsage}}',
    '{{.MemPerc}}',
    '{{.NetIO}}',
    '{{.BlockIO}}'
  ].join(DOCKER_SEP)
  return [
    resolveBinary('docker'),
    `echo "${DOCKER_MARKERS.stats}"`,
    `${run} stats --no-stream --format "${fmt}" ${refs.join(' ')} 2>&1`
  ].join('; ')
}

function parsePercent(text: string): number | null {
  const m = text.trim().match(/^([0-9]+(?:\.[0-9]+)?)\s*%$/)
  return m ? Number(m[1]) : null
}

export function parseDockerStatsOutput(output: string, exitCode: number | null): DockerStatsProbe {
  const body = section(output, DOCKER_MARKERS.stats)
  if (body === undefined) {
    const detail = nonEmptyLines(output)[0] ?? 'docker did not run'
    return { ok: false, reason: classifyDockerFailure(output, exitCode), detail }
  }

  const all = nonEmptyLines(body)
  const rows = all.filter((l) => l.includes(DOCKER_SEP))
  const noise = all.filter((l) => !l.includes(DOCKER_SEP))

  const stats: DockerStat[] = []
  for (const line of rows) {
    const f = line.split(DOCKER_SEP)
    if (f.length !== 6) continue
    stats.push({
      name: f[0].trim(),
      // docker prints `--` for a container it could not sample. A null says so;
      // a zero would read as an idle container.
      cpuPercent: parsePercent(f[1]),
      memUsage: f[2].trim(),
      memPercent: parsePercent(f[3]),
      netIo: f[4].trim(),
      blockIo: f[5].trim()
    })
  }

  if (stats.length === 0) {
    const failure = blockFailure(noise.join('\n'), exitCode)
    if (failure) return { ok: false, ...failure }
    return {
      ok: false,
      reason: 'unknown',
      detail: noise[noise.length - 1] ?? 'docker stats returned nothing this parser could read'
    }
  }
  return { ok: true, stats }
}

// ------------------------------------------------------------- lifecycle
//
// THE APPROVAL MODEL, borrowed from shared/broadcast.ts.
//
// Broadcast's model is built around blast radius rather than command text, and
// the three rules that matter transfer unchanged:
//
//  1. Targets are explicit. There is no "all containers" action and no saved
//     selection. The user picks, every time, and sees the list before it runs.
//  2. Confirmation strength scales with the target count AND with what the verb
//     does. One container the user just clicked is not a fan-out; a whole
//     compose project is.
//  3. Nothing is safe by omission.
//
// The shape of `DockerConfirmation` mirrors `BroadcastConfirmation` exactly and
// is declared here rather than imported, on purpose: modules are independently
// enableable, and docker taking a hard dependency on broadcast's file would
// make one module's presence depend on another's. The model is copied; the
// code is not shared. If broadcast's shape changes, the test that pins them
// together is the thing that notices.
//
// Where the strengths land, and why:
//
//  * `start` on one container: no dialog. It is additive, it is undone by the
//    stop button next to it, and the user pressed a button labelled Start.
//    Nagging on the safe case is how people learn to click through the
//    dangerous one — broadcast's own words.
//  * `stop` and `restart` on one container: a confirm step. Both interrupt
//    every connection the container is serving, and broadcast independently
//    classifies `docker stop` as elevated, which on a single target is exactly
//    a confirm. Two subsystems reaching the same answer is the model working.
//  * ANY of them on more than one container: type-to-confirm. This is the
//    fan-out case — stopping a compose project takes down a stack, and a
//    misclick on a group header should not be able to do that.
//  * The typed phrase is the verb (STOP, RESTART, START), not a generic RUN.
//    A phrase the user retypes for every action is a phrase they type without
//    reading; naming the verb makes the dialog say what is about to happen.

export type DockerAction = 'start' | 'stop' | 'restart'

/** The allow-list. `action` reaches a builder over IPC, where its type is a claim, not a fact. */
export const DOCKER_ACTIONS: readonly DockerAction[] = ['start', 'stop', 'restart']

export type DockerActionRisk = 'ordinary' | 'elevated'

export type DockerConfirmation =
  /** Run on click. One container, and the verb only adds. */
  | { kind: 'none' }
  /** A confirm step naming the containers. */
  | { kind: 'confirm' }
  /** The user types this exact word. Reserved for the fan-out. */
  | { kind: 'type-to-confirm'; phrase: string }

export interface DockerActionPlan {
  action: DockerAction
  /** Container names, explicit and in order, as the dialog will show them. */
  targets: string[]
  risk: DockerActionRisk
  confirmation: DockerConfirmation
  reasons: string[]
}

/** Above this many containers, every verb escalates to type-to-confirm. */
export const DOCKER_TYPE_ABOVE_CONTAINERS = 1

export function planDockerAction(action: DockerAction, targets: string[]): DockerActionPlan {
  const reasons: string[] = []
  const risk: DockerActionRisk = action === 'start' ? 'ordinary' : 'elevated'
  if (action === 'stop') reasons.push('stops a running container and every connection it is serving')
  if (action === 'restart') reasons.push('interrupts every connection the container is serving')
  if (targets.length > 1) reasons.push(`affects ${targets.length} containers at once`)

  let confirmation: DockerConfirmation
  if (targets.length === 0) confirmation = { kind: 'confirm' }
  else if (targets.length > DOCKER_TYPE_ABOVE_CONTAINERS) {
    confirmation = { kind: 'type-to-confirm', phrase: action.toUpperCase() }
  } else if (risk === 'elevated') confirmation = { kind: 'confirm' }
  else confirmation = { kind: 'none' }

  return { action, targets, risk, confirmation, reasons }
}

/** Containers per lifecycle call. The fan-out already needs a typed phrase; this bounds it absolutely. */
export const DOCKER_ACTION_MAX_REFS = 50

function validTimeoutSeconds(seconds: unknown): number {
  if (typeof seconds !== 'number' || !Number.isInteger(seconds) || seconds < 0 || seconds > 3600) {
    throw new Error('refusing to build a command from an invalid stop timeout')
  }
  return seconds
}

/**
 * `docker start|stop|restart`.
 *
 * `action` is checked against the allow-list rather than interpolated on the
 * strength of its TypeScript type: it arrives over IPC, where a type annotation
 * is a compile-time claim and a structured-clone value carries whatever the
 * caller sent. `'stop; rm -rf /'` is a valid string.
 *
 * `-t` is docker's grace period before SIGKILL. Left at docker's own default
 * unless asked, and validated as an integer when it is, for the same reason
 * `--tail` is.
 */
export function buildDockerActionCommand(
  action: DockerAction,
  refs: string[],
  opts: { sudo?: boolean; timeoutSec?: number } = {}
): string {
  if (!DOCKER_ACTIONS.includes(action)) throw new Error('refusing to build a command for an unknown docker action')
  if (!Array.isArray(refs) || refs.length === 0) {
    throw new Error('refusing to build a lifecycle command with no container references')
  }
  if (refs.length > DOCKER_ACTION_MAX_REFS) {
    throw new Error(`refusing to act on more than ${DOCKER_ACTION_MAX_REFS} containers at once`)
  }
  for (const ref of refs) {
    if (!validateContainerRef(ref)) throw new Error('refusing to build a command from an invalid container reference')
  }
  const run = runner(opts.sudo)
  let flags = ''
  if (opts.timeoutSec !== undefined) {
    if (action === 'start') throw new Error('refusing to build a start command with a stop timeout')
    flags = ` -t ${validTimeoutSeconds(opts.timeoutSec)}`
  }
  return [
    resolveBinary('docker'),
    `echo "${DOCKER_MARKERS.act}"`,
    `${run} ${action}${flags} ${refs.join(' ')} 2>&1`
  ].join('; ')
}

export interface DockerActionOutcome {
  ref: string
  ok: boolean
  error?: string
}

export type DockerActionResult =
  | {
      ok: true
      outcomes: DockerActionOutcome[]
      /** Lines docker printed that name no container. Shown rather than dropped. */
      unattributed: string[]
      usedSudo?: boolean
    }
  | { ok: false; reason: DockerFailure; detail: string }

/**
 * What actually happened to each container.
 *
 * docker echoes the reference it acted on, one per line, and prints an error
 * line naming the reference it could not. Both are per container, so the result
 * is per container: "the command exited 1" tells an operator nothing about
 * which of the five containers is still up.
 *
 * `ok: false` is reserved for the case where docker never ran — a dead daemon,
 * a refused socket, a missing binary. A container that failed on its own terms
 * is a successful read of a failed action, and flattening the two would put a
 * permissions problem behind the words "nothing happened".
 */
export function parseDockerActionOutput(
  refs: string[],
  output: string,
  exitCode: number | null
): DockerActionResult {
  const body = section(output, DOCKER_MARKERS.act)
  if (body === undefined) {
    const detail = nonEmptyLines(output)[0] ?? 'docker did not run'
    return { ok: false, reason: classifyDockerFailure(output, exitCode), detail }
  }

  const all = nonEmptyLines(body)
  const done = new Set<string>()
  const errors = new Map<string, string>()
  const unattributed: string[] = []

  for (const line of all) {
    const hit = refs.find((r) => r === line)
    if (hit !== undefined) {
      done.add(hit)
      continue
    }
    // An error line names its container; attribute it so the row can say why.
    // Longest first, so `web` does not claim `web-worker`'s error.
    const named = [...refs].sort((a, b) => b.length - a.length).find((r) => line.includes(r))
    if (named !== undefined && !done.has(named)) {
      if (!errors.has(named)) errors.set(named, line)
      continue
    }
    unattributed.push(line)
  }

  if (done.size === 0 && errors.size === 0) {
    const failure = blockFailure(unattributed.join('\n'), exitCode)
    if (failure) return { ok: false, ...failure }
  }

  const outcomes: DockerActionOutcome[] = refs.map((ref) => {
    if (done.has(ref)) return { ref, ok: true }
    const error = errors.get(ref)
    if (error !== undefined) return { ref, ok: false, error }
    // Not mentioned at all. Saying so is the honest answer; assuming success
    // would tell an operator a container is up when nothing confirmed it.
    return { ref, ok: false, error: 'docker did not say what happened to this container' }
  })

  return { ok: true, outcomes, unattributed }
}

// ------------------------------------------------------------- the bridge

/**
 * What the preload must expose for the panel to work.
 *
 * Declared here rather than inferred from `src/preload/index.ts` so the two
 * halves can be written and type-checked independently: the renderer holds this
 * interface, the preload is annotated with it, and a channel added on one side
 * and forgotten on the other is a compile error rather than a runtime
 * `undefined is not a function`.
 *
 * The renderer treats every method as optional (`Partial<DockerBridge>`), which
 * is not defensive clutter: the docker module ships disabled, and a build where
 * the preload half has not landed yet must degrade to a disabled button rather
 * than a white panel.
 *
 * Nothing here is reachable by an agent. The MCP bridge gates `execute_command`
 * per server against an access group; container lifecycle is a different risk
 * with a different consent story, and giving one to an agent because the UI
 * happened to grow one would be an accident rather than a decision.
 */
export interface DockerBridge {
  list(cfg: unknown, opts?: { sudo?: boolean; autoSudo?: boolean }): Promise<DockerProbe>
  canSudo(cfg: unknown): Promise<boolean>
  logs(
    cfg: unknown,
    ref: string,
    lines: number,
    opts?: DockerLogsOptions
  ): Promise<{ ok: boolean; output: string; error?: string }>
  disk(cfg: unknown, opts?: { sudo?: boolean; autoSudo?: boolean }): Promise<DockerDiskProbe>
  inspect(cfg: unknown, ref: string, opts?: { sudo?: boolean; autoSudo?: boolean }): Promise<DockerInspectProbe>
  stats(cfg: unknown, refs: string[], opts?: { sudo?: boolean; autoSudo?: boolean }): Promise<DockerStatsProbe>
  act(
    cfg: unknown,
    action: DockerAction,
    refs: string[],
    opts?: { sudo?: boolean; timeoutSec?: number }
  ): Promise<DockerActionResult>
}
