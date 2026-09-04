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
//  * `docker system prune`, in every spelling — `system`, `image`, `volume`,
//    `network`, `builder`, `container`. It deletes every stopped container,
//    every dangling image, every unused network and — with one more flag people
//    habitually add — every unused volume, on a host where "unused" means "not
//    attached right now", which includes the database volume of anything that
//    happens to be stopped. It is the single most regretted docker command, and
//    the objection that keeps it out is falsifiable rather than a preference:
//    **its blast radius is not knowable from the UI that offers it.**
//
//    That objects to `prune`, not to reclaiming disk. The answer is to make the
//    blast radius a literal list of ids, which is what the reclaim section near
//    the bottom of this file does — `docker rm` / `rmi` / `volume rm` /
//    `network rm` against exactly the ids a preview displayed, and nothing
//    else. So `prune` is not merely still absent; it is absent *because* the
//    replacement exists, and `tests/dockerOps.test.ts` holds every builder in
//    this file to that.
//
//    `-a` is refused rather than deferred, and for a reason that is not about
//    taste either. `system prune -a` removes stopped containers FIRST, so an
//    image whose only reference was a stopped container becomes unreferenced
//    within the same command and is deleted too. A preview built by listing
//    images beforehand cannot show that image. It is not a race; it is a
//    preview that is structurally wrong.
//  * `docker kill`. `stop` sends SIGTERM and waits; kill does not, and the
//    difference is whether a database finishes its write.
//  * `--force` / `-f` on any removal. A forced removal is docker overruling its
//    own safety check, and the checks it overrules — "container is running",
//    "image is being used by stopped container X", "volume is in use" — are the
//    exact facts a preview taken thirty seconds ago cannot vouch for. Refusing
//    them means a target that stopped being safe fails on its own terms, in
//    docker's own words, per item.

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
  dfDetail: '===SHELLPILOT-DFV===',
  engine: '===SHELLPILOT-ENGINE===',
  inspect: '===SHELLPILOT-INSPECT===',
  health: '===SHELLPILOT-HEALTH===',
  stats: '===SHELLPILOT-STATS===',
  act: '===SHELLPILOT-ACT===',
  /**
   * One marker per removal kind, because the four commands are four different
   * programs and their output must never be pooled.
   *
   * `docker volume rm` names the CONTAINER that holds a busy volume in its
   * error line — `volume is in use - [f4a732d020f7…]` — and a container id in
   * that line has nothing to do with a container the operator also selected.
   * Attributing per block keeps that line inside the volume block, where the
   * only references it can be matched against are volume names.
   */
  rmContainer: '===SHELLPILOT-RMCONTAINER===',
  rmImage: '===SHELLPILOT-RMIMAGE===',
  rmVolume: '===SHELLPILOT-RMVOLUME===',
  rmNetwork: '===SHELLPILOT-RMNETWORK===',
  /**
   * A CLOSING marker, which the others do not need.
   *
   * `attempt()` merges stderr onto stdout, so anything the login shell says —
   * a locale warning, an motd, a transport notice — arrives AFTER the last
   * block. Every other collector reads a block that is followed by another
   * marker, so that noise falls outside it. The itemised disk listing is the
   * last block in its round trip, and without a marker behind it the noise
   * landed inside the final table's column offsets and was counted as a row
   * that could not be read.
   */
  end: '===SHELLPILOT-END==='
} as const

/**
 * The text after `marker`, up to the next marker.
 *
 * `undefined` for a marker that never appeared is load-bearing and different
 * from an empty string: it means the shell never reached that command, which is
 * a diagnosis, whereas an empty section is an answer.
 */
export function section(output: string, marker: string): string | undefined {
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

// --------------------------------------------------- system df -v, itemised

// THE NUMBER THIS SECTION MUST NEVER PRODUCE, stated before the types because
// every reviewer's first instinct is to add it:
//
//   **Per-item sizes do not add up to a total, and summing them is wrong.**
//
// `SIZE` in the images table is the size of every layer the image is built
// from, and layers are shared: eight images off the same base each report the
// base's bytes. Adding them can overstate the disk by a multiple — and it looks
// correct in every hand-written fixture, because a fixture nobody recorded has
// no shared layers in it. `UNIQUE SIZE` is the honest per-image figure (docker
// computes it against the whole store), but even those do not sum to
// "reclaimable", because whether an image is reclaimable depends on what is
// referencing it right now.
//
// So the headline number keeps coming from the NON-verbose `docker system df`,
// where docker did the arithmetic itself and knows about the sharing. This
// section exists to answer "which of these is big", per item, and nothing here
// totals anything.

/** One row of the `Images space usage:` table. */
export interface DockerDiskImage {
  /** `<none>` when nothing tags it. Kept verbatim — docker's own word for it. */
  repository: string
  tag: string
  /** Short id, as docker prints it here. */
  id: string
  created: string
  /** Every layer, INCLUDING ones other images share. Never summed. See above. */
  size: string
  sizeBytes: number | null
  sharedSize: string
  sharedSizeBytes: number | null
  /** The bytes that belong to this image alone — the honest per-image figure. */
  uniqueSize: string
  uniqueSizeBytes: number | null
  /** How many containers reference it. 0 with no tag is the classic leftover. */
  containers: number | null
  /** `<none>:<none>`. A build's previous layer set, orphaned by the next build. */
  dangling: boolean
}

/** One row of the `Containers space usage:` table. */
export interface DockerDiskContainer {
  id: string
  image: string
  /** Quoted, and truncated by docker with a unicode ellipsis. Shown as given. */
  command: string
  localVolumes: number | null
  /** The container's writable layer — NOT its image. */
  size: string
  sizeBytes: number | null
  created: string
  /** `Up 17 hours (healthy)`, `Exited (137) 2 days ago`, `Created`. */
  status: string
  /** Derived from the status, the same way the container list derives it. */
  state: string
  name: string
}

/** One row of the `Local Volumes space usage:` table. */
export interface DockerDiskVolume {
  name: string
  /** 0 means no container references it — which is not the same as unwanted. */
  links: number | null
  size: string
  sizeBytes: number | null
  /**
   * A 64-hex name is one docker generated for an unnamed mount; anything else
   * is a name a person typed. There is no flag for this, only the shape, and
   * the difference matters: an anonymous volume with no links is usually
   * rubbish, a named one with no links is usually a stopped database.
   */
  anonymous: boolean
}

/** One row of the `Build cache usage:` table. */
export interface DockerDiskCacheEntry {
  id: string
  type: string
  size: string
  sizeBytes: number | null
  created: string
  lastUsed: string
  usage: number | null
  /** `true`/`false` as docker printed it. Not coerced — podman may not print it. */
  shared: string
}

export interface DockerDiskDetail {
  images: DockerDiskImage[]
  containers: DockerDiskContainer[]
  volumes: DockerDiskVolume[]
  buildCache: DockerDiskCacheEntry[]
  /**
   * Which tables the runtime actually printed.
   *
   * podman has historically omitted the build cache table entirely, and "this
   * host has no build cache" and "this runtime does not have build cache" are
   * different sentences. Absent is not empty — the same distinction `section()`
   * keeps for markers.
   */
  sections: { images: boolean; containers: boolean; volumes: boolean; buildCache: boolean }
  /** Rows inside a table this parser could not read. Counted, never dropped quietly. */
  unreadable: number
}

/**
 * When the engine running on this host was BUILT.
 *
 * `{{.Server.BuildTime}}` and nothing else: no network call, and no baked table
 * of release dates. A table needs an owner and a refresh cadence, and a table
 * that has rotted states something false — whereas a build date is a fact the
 * daemon already knows about itself and cannot go stale.
 */
export interface DockerEngineBuild {
  /** Exactly what the template printed. */
  raw: string
  /** `2021-06-02` — the date, without a time nobody is going to read. */
  date: string
  epochMs: number
}

export type DockerDiskDetailProbe =
  | { ok: true; disk: DockerDiskDetail; engine: DockerEngineBuild | null; usedSudo?: boolean }
  | { ok: false; reason: DockerFailure; detail: string }

/**
 * `docker system df -v`, plus the engine's build date.
 *
 * Two blocks, and the ORDER is load-bearing. The build-time probe ends in
 * `|| true`, so it has to come first: only the last block's exit status
 * survives, and a `|| true` after `system df -v` would erase the status the
 * parser uses to tell a host with no docker from a host with an empty store.
 *
 * The build-time probe's stderr goes to /dev/null for the same reason the
 * version probe's does — podman's docker shim cannot answer `.Server.*` at all
 * and fails it with a nil-pointer template error, which is not evidence of
 * anything. A host that cannot answer simply gets no age line.
 *
 * `-v` here, unlike `buildDockerDiskCommand`, is the entire point: the summary
 * gives four category totals, and "which of these images is the big one" is not
 * answerable from four numbers. It is a page of output, so it is a separate
 * read the operator asks for rather than something every refresh pays for.
 */
export function buildDockerDiskDetailCommand(opts: { sudo?: boolean } = {}): string {
  const run = runner(opts.sudo)
  return [
    resolveBinary('docker'),
    `echo "${DOCKER_MARKERS.engine}"`,
    `${run} version --format "{{.Server.BuildTime}}" 2>/dev/null || true`,
    `echo "${DOCKER_MARKERS.dfDetail}"`,
    `${run} system df -v 2>&1`,
    // The listing's own status, held over the echo and handed back. A bare
    // `echo` after it would replace the status the parser uses to tell a host
    // with no docker from a host with an empty store — which is why every
    // other block here is ordered rather than bracketed.
    `SP_RC=$?; echo "${DOCKER_MARKERS.end}"; exit $SP_RC`
  ].join('; ')
}

/**
 * The engine build date, or null.
 *
 * Deliberately strict about the shape: docker prints an RFC3339 timestamp, and
 * anything else in this block is the runtime declining to answer — `<no
 * value>`, a Go template error, or podman's shim notice. Handing those to
 * `Date.parse`, which will cheerfully invent a date out of a version string, is
 * how a panel ends up asserting the daemon was built in the year 24.
 */
/**
 * Docker's first public release. Anything claiming to predate it is a sentinel
 * rather than a build time, and there is no version of this panel where the
 * difference matters less than the difference between them.
 */
const DOCKER_EXISTED_FROM = Date.parse('2013-03-01T00:00:00Z')

export function parseDockerEngineBuild(text: string | undefined): DockerEngineBuild | null {
  if (text === undefined) return null
  for (const line of nonEmptyLines(text)) {
    if (!/^\d{4}-\d{2}-\d{2}[T ]/.test(line)) continue
    const at = Date.parse(line)
    if (Number.isNaN(at)) continue
    // A timestamp that is well shaped and still not a fact. podman's
    // docker-compat derives BuildTime from an int64 that formats as the Unix
    // epoch when it was never set, and Go's own zero value formats as
    // `0001-01-01T00:00:00Z`. Both pass every shape check there is, and
    // "built 1970-01-01, 56 years ago" is the year-24 mistake in a costume.
    if (at < DOCKER_EXISTED_FROM) continue
    // The date the DAEMON printed, not the same instant expressed in UTC:
    // `toISOString` moved an engine built at half eleven at night in Chicago
    // onto the following day. The shape check above guarantees the first ten
    // characters are that date.
    return { raw: line, date: line.slice(0, 10), epochMs: at }
  }
  return null
}

/**
 * "built 2021-06-02, 4 years ago".
 *
 * `now` is a parameter rather than a call to `Date.now()` so this is a function
 * of its inputs and can be tested without freezing the clock.
 *
 * A build date in the future is a clock disagreement between this machine and
 * that one, not a fact about the engine, so it reports the date and stops
 * rather than saying "in 3 days".
 */
export function formatDockerEngineAge(build: DockerEngineBuild, now: number): string {
  const days = Math.floor((now - build.epochMs) / 86_400_000)
  if (days < 0) return `built ${build.date}`
  const plural = (n: number, unit: string): string => `${n} ${unit}${n === 1 ? '' : 's'} ago`
  const years = Math.floor(days / 365.25)
  const months = Math.floor(days / 30.44)
  if (years >= 1) return `built ${build.date}, ${plural(years, 'year')}`
  if (months >= 1) return `built ${build.date}, ${plural(months, 'month')}`
  if (days === 0) return `built ${build.date}, today`
  return `built ${build.date}, ${plural(days, 'day')}`
}

/**
 * A column of one of the four tables: its header, and where it starts.
 *
 * WHY POSITIONAL, when every other parser in this file splits on a separator.
 *
 * The verbose tables have two columns with spaces INSIDE a single cell, so the
 * `/\s{2,}/` split the summary parser uses does not survive them: `COMMAND` is
 * a quoted string docker truncates with a unicode ellipsis — `"/bin/sh -c 'set
 * -e\n…"` — and `STATUS` reads `Up 17 hours (healthy)` or `Exited (137) 2 days
 * ago`. Splitting on two-or-more spaces happens to work on the recorded fixture
 * and stops working the first time a command line contains a double space,
 * which is not a hypothetical: `sh -c 'a  b'` is a real entrypoint.
 *
 * docker renders these through Go's tabwriter, which pads every column to the
 * widest cell in it INCLUDING the header — so the header row's offsets are the
 * table's offsets, for every row, exactly. Cutting there reads a cell that
 * contains anything at all.
 *
 * Columns are looked up BY NAME rather than by index, because the runtimes
 * disagree about which columns exist and an index would silently read the wrong
 * one. A column this runtime did not print reads as absent instead.
 */
interface DiskColumn {
  name: string
  start: number
  end: number
}

function diskColumns(header: string): DiskColumn[] {
  // Column headings are separated by two or more spaces and several contain ONE
  // space (`IMAGE ID`, `SHARED SIZE`, `VOLUME NAME`), so a single space is part
  // of a name and two is a boundary.
  const re = /\S+(?: \S+)*/g
  const found: { text: string; at: number }[] = []
  let m: RegExpExecArray | null
  // Offsets are counted in CODE POINTS, and `cell` cuts in them too. Go's
  // tabwriter pads by runes; a JavaScript string index counts UTF-16 units, so
  // one astral-plane character in a COMMAND shifted every column after it and
  // dropped the whole row from a listing whose only job is to be complete.
  while ((m = re.exec(header)) !== null) found.push({ text: m[0], at: [...header.slice(0, m.index)].length })
  return found.map((f, i) => ({
    name: f.text.toUpperCase(),
    start: f.at,
    // The last column runs to the end of the line: a name wider than its own
    // header must not be clipped.
    end: i + 1 < found.length ? found[i + 1].at : Number.MAX_SAFE_INTEGER
  }))
}

function cell(columns: DiskColumn[], row: string, name: string): string {
  const col = columns.find((c) => c.name === name)
  if (col === undefined) return ''
  return [...row].slice(col.start, col.end).join('').trim()
}

type DiskSectionKind = 'images' | 'containers' | 'volumes' | 'cache'

/**
 * Which table a heading opens, or null for a line that is not a heading.
 *
 * Matched on the keyword rather than the whole sentence: docker writes `Local
 * Volumes space usage:` and `Build cache usage: 0B` — two different shapes
 * already — and podman words them differently again.
 */
function diskSectionKind(line: string): DiskSectionKind | null {
  const t = line.trim()
  if (!/\busage:/i.test(t)) return null
  if (/^images\b/i.test(t)) return 'images'
  if (/^containers\b/i.test(t)) return 'containers'
  if (/\bvolumes\b/i.test(t)) return 'volumes'
  if (/\bcache\b/i.test(t)) return 'cache'
  return null
}

/** A header row is entirely upper case; a warning docker slipped in is not. */
function isDiskHeader(line: string): boolean {
  return !/[a-z]/.test(line) && /[A-Z]/.test(line)
}

export function parseDockerDiskDetailOutput(output: string, exitCode: number | null): DockerDiskDetailProbe {
  const body = section(output, DOCKER_MARKERS.dfDetail)
  if (body === undefined) {
    const detail = nonEmptyLines(output)[0] ?? 'docker did not run'
    return { ok: false, reason: classifyDockerFailure(output, exitCode), detail }
  }
  const engine = parseDockerEngineBuild(section(output, DOCKER_MARKERS.engine))

  const disk: DockerDiskDetail = {
    images: [],
    containers: [],
    volumes: [],
    buildCache: [],
    sections: { images: false, containers: false, volumes: false, buildCache: false },
    unreadable: 0
  }

  let kind: DiskSectionKind | null = null
  let columns: DiskColumn[] | null = null
  // Lines are NOT trimmed: the column offsets are measured from the start of
  // the line, so leading space is data here rather than noise.
  for (const raw of body.split('\n')) {
    const line = raw.replace(/\s+$/, '')
    if (line.trim() === '') continue

    const heading = diskSectionKind(line)
    if (heading !== null) {
      kind = heading
      columns = null
      if (heading === 'cache') disk.sections.buildCache = true
      else disk.sections[heading] = true
      continue
    }
    // Anything before the first heading is docker talking rather than
    // answering — the podman-docker shim notice, a bridge-nf warning. Kept out
    // of the tables; still visible to blockFailure below.
    if (kind === null) continue
    if (columns === null) {
      if (isDiskHeader(line)) columns = diskColumns(line)
      else disk.unreadable++
      continue
    }

    if (kind === 'images') {
      const repository = cell(columns, line, 'REPOSITORY')
      const tag = cell(columns, line, 'TAG')
      const size = cell(columns, line, 'SIZE')
      if (repository === '' || parseDockerSize(size) === null) {
        disk.unreadable++
        continue
      }
      const sharedSize = cell(columns, line, 'SHARED SIZE')
      const uniqueSize = cell(columns, line, 'UNIQUE SIZE')
      disk.images.push({
        repository,
        tag,
        id: cell(columns, line, 'IMAGE ID'),
        created: cell(columns, line, 'CREATED'),
        size,
        sizeBytes: parseDockerSize(size),
        sharedSize,
        sharedSizeBytes: parseDockerSize(sharedSize),
        uniqueSize,
        uniqueSizeBytes: parseDockerSize(uniqueSize),
        containers: parseCount(cell(columns, line, 'CONTAINERS')),
        dangling: repository === '<none>' && tag === '<none>'
      })
      continue
    }

    if (kind === 'containers') {
      const id = cell(columns, line, 'CONTAINER ID')
      const size = cell(columns, line, 'SIZE')
      if (id === '' || parseDockerSize(size) === null) {
        disk.unreadable++
        continue
      }
      const status = cell(columns, line, 'STATUS')
      disk.containers.push({
        id,
        image: cell(columns, line, 'IMAGE'),
        command: cell(columns, line, 'COMMAND'),
        localVolumes: parseCount(cell(columns, line, 'LOCAL VOLUMES')),
        size,
        sizeBytes: parseDockerSize(size),
        created: cell(columns, line, 'CREATED'),
        status,
        // This table has no State column, so the status line is all there is —
        // the same fallback the container list already uses.
        state: stateFrom('', status),
        name: cell(columns, line, 'NAMES')
      })
      continue
    }

    if (kind === 'volumes') {
      const name = cell(columns, line, 'VOLUME NAME')
      const size = cell(columns, line, 'SIZE')
      if (name === '' || parseDockerSize(size) === null) {
        disk.unreadable++
        continue
      }
      disk.volumes.push({
        name,
        links: parseCount(cell(columns, line, 'LINKS')),
        size,
        sizeBytes: parseDockerSize(size),
        anonymous: /^[0-9a-f]{64}$/.test(name)
      })
      continue
    }

    const id = cell(columns, line, 'CACHE ID')
    const size = cell(columns, line, 'SIZE')
    if (id === '' || parseDockerSize(size) === null) {
      disk.unreadable++
      continue
    }
    disk.buildCache.push({
      id,
      type: cell(columns, line, 'CACHE TYPE'),
      size,
      sizeBytes: parseDockerSize(size),
      created: cell(columns, line, 'CREATED'),
      lastUsed: cell(columns, line, 'LAST USED'),
      usage: parseCount(cell(columns, line, 'USAGE')),
      shared: cell(columns, line, 'SHARED')
    })
  }

  const items = disk.images.length + disk.containers.length + disk.volumes.length + disk.buildCache.length
  if (items === 0) {
    // The rule the whole module is built on: "nothing here" and "you are not
    // allowed to look" must never render the same.
    const failure = blockFailure(body, exitCode)
    if (failure) return { ok: false, ...failure }
    const printed =
      disk.sections.images || disk.sections.containers || disk.sections.volumes || disk.sections.buildCache
    if (!printed) {
      return {
        ok: false,
        reason: 'unknown',
        detail: nonEmptyLines(body)[0] ?? 'docker system df -v returned nothing this parser could read'
      }
    }
    // Tables printed, and every row inside them unreadable: a runtime whose
    // columns are not the ones assumed here. Reporting that as an empty store
    // is the same lie as reporting a refused socket as one.
    if (disk.unreadable > 0) {
      return {
        ok: false,
        reason: 'unknown',
        detail: `docker system df -v returned ${disk.unreadable} row(s) this parser could not read`
      }
    }
  }
  return { ok: true, disk, engine }
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

// ------------------------------------------------------- reclaim, by id
//
// The answer to `prune`, and it is the same answer the header gives: the
// objection to `prune` was that its blast radius is not knowable from the UI
// that offers it, so the blast radius here is **a literal list of ids**.
//
// Nothing below ever runs `prune`. `docker rm`, `docker rmi`, `docker volume
// rm` and `docker network rm` are given exactly the ids a preview displayed,
// and the consequences of that are all in the right direction:
//
//  * Anything that became eligible AFTER the preview is untouched, because it
//    is not in the list. The container that crashed while the operator was
//    reading the dialog survives. `prune` cannot make that promise; a list can.
//  * Anything that stopped being eligible fails on its own terms, in docker's
//    own words, per item — `container is running`, `image is being used by
//    stopped container X`, `volume is in use`. Recorded on Docker 29.5.3; see
//    tests/fixtures/docker/reclaim-refused-docker-29.txt.
//
// THE THREE RULES THAT SHAPE THE SELECTION, none of which is a preference:
//
//  1. **Nothing is offered that docker itself would not prune, and several
//     things docker WOULD prune are still not offered.** A paused or restarting
//     container is not offered: docker does not prune either, and offering them
//     widens the blast radius past what was asked for. A volume with LINKS > 0
//     is never offered at all.
//  2. **Nothing is pre-selected, and there is no select-all.** The lifecycle
//     header above states the rule this inherits — targets are explicit, there
//     is no "all containers" action. A select-all checkbox is `prune` under
//     another name, reached by one click instead of one flag.
//  3. **An image is removed by ID, never by tag.** `docker rmi nginx:latest`
//     UNTAGS; `docker rmi <id>` removes. They are different operations wearing
//     the same verb, and resolving a tag to an id is a lookup that can race
//     with a rebuild. By-id also fails safe in the one ambiguous case: an image
//     carrying more than one tag is refused rather than half-removed —
//     `conflict: unable to delete 410766c85e52 (must be forced) - image is
//     referenced in multiple repositories`, recorded on 29.5.3.
//
// THE RISK MODEL IS `planK8sRollout`'S, NOT `planDockerAction`'S. Lifecycle
// escalates on the target COUNT, because stopping ten containers is a fan-out
// and stopping one is not. Removal does not work like that: one volume is
// unrecoverable and fifty dangling images are re-pullable, so the count is the
// wrong axis entirely. What escalates here is what the removal costs if it was
// wrong — and `caveats` is carried separately from `reasons` for the reason
// K8sRolloutPlan gives: they are not arguments for pressing harder, they are
// things that would otherwise be discovered afterwards.

export type DockerReclaimKind = 'container' | 'image' | 'volume' | 'network'

/** The allow-list. A kind reaches the builder over IPC, where its type is a claim. */
export const DOCKER_RECLAIM_KINDS: readonly DockerReclaimKind[] = [
  'container',
  'image',
  'volume',
  'network'
]

export interface DockerReclaimItem {
  kind: DockerReclaimKind
  /**
   * What docker is told. An id for a container, an image or a network; a NAME
   * for a volume, because a volume has no other handle — `docker volume rm`
   * takes names and docker's anonymous names are 64 hex characters, which is an
   * id in everything but the column heading.
   *
   * Never a tag. See rule 3 above and `buildDockerReclaimCommand`.
   */
  id: string
  /** What the row reads as — `nginx:1.25`, `old-frontend`. Shown, never sent. */
  label: string
  /** Docker's own formatting of this item's bytes. Displayed per row; NEVER summed. */
  size: string
  sizeBytes: number | null
  /** Volumes only: 64 hex characters is a name docker generated, anything else is one a person typed. */
  anonymous?: boolean
  /** Images only: `<none>:<none>` — a previous build's layers, which no registry has a copy of. */
  dangling?: boolean
  /** Containers only: how many local volumes it mounts. `docker rm` does not remove them. */
  mountedVolumes?: number
}

/** Something the itemised read listed and this refuses to offer, with the reason it refuses. */
export interface DockerReclaimWithheld {
  kind: DockerReclaimKind | 'cache'
  id: string
  label: string
  reason: string
}

export interface DockerReclaimPreview {
  items: DockerReclaimItem[]
  withheld: DockerReclaimWithheld[]
}

/**
 * States a container may be in and still be offered.
 *
 * `paused` and `restarting` are absent deliberately: docker prunes neither, and
 * a UI that offers them is removing things the operator's mental model of
 * "unused" does not contain. `dead` is present — it is a container whose
 * filesystem docker failed to tear down, and it is exactly the leftover this
 * feature is for.
 */
const RECLAIMABLE_CONTAINER_STATES = ['exited', 'created', 'dead']

/**
 * Turn the itemised disk read into what may be offered, and what may not.
 *
 * A pure function of one read, so the offer set is reproducible: the same
 * listing always produces the same items, which is what makes the re-preview
 * diff below mean anything at all.
 *
 * Build cache is never offered. There is no `docker builder rm <id>` — a single
 * cache entry can only be removed by `docker builder prune --filter`, which is
 * `prune`, and the whole point of this section is that it does not run one.
 */
export function buildDockerReclaimPreview(disk: DockerDiskDetail): DockerReclaimPreview {
  const items: DockerReclaimItem[] = []
  const withheld: DockerReclaimWithheld[] = []

  for (const c of disk.containers) {
    const label = c.name === '' ? c.id : c.name
    if (c.state === 'running') {
      withheld.push({ kind: 'container', id: c.id, label, reason: 'it is running' })
      continue
    }
    if (c.state === 'paused' || c.state === 'restarting') {
      withheld.push({
        kind: 'container',
        id: c.id,
        label,
        reason: `it is ${c.state}, which docker does not prune either`
      })
      continue
    }
    if (!RECLAIMABLE_CONTAINER_STATES.includes(c.state)) {
      withheld.push({ kind: 'container', id: c.id, label, reason: 'its state could not be read' })
      continue
    }
    items.push({
      kind: 'container',
      id: c.id,
      label,
      size: c.size,
      sizeBytes: c.sizeBytes,
      mountedVolumes: c.localVolumes ?? undefined
    })
  }

  for (const i of disk.images) {
    const label = `${i.repository}:${i.tag}`
    if (i.id === '') {
      withheld.push({
        kind: 'image',
        id: '',
        label,
        reason: 'this runtime printed no image id, and an image is only ever removed by id'
      })
      continue
    }
    if (i.containers === null) {
      withheld.push({
        kind: 'image',
        id: i.id,
        label,
        reason: 'this runtime did not say how many containers reference it'
      })
      continue
    }
    if (i.containers > 0) {
      withheld.push({
        kind: 'image',
        id: i.id,
        label,
        reason: `${i.containers} container${i.containers === 1 ? '' : 's'} still reference it`
      })
      continue
    }
    items.push({
      kind: 'image',
      id: i.id,
      label,
      // UNIQUE SIZE, because SIZE counts layers shared with other images. The
      // fallback is for a runtime that prints no such column.
      size: i.uniqueSize === '' ? i.size : i.uniqueSize,
      sizeBytes: i.uniqueSize === '' ? i.sizeBytes : i.uniqueSizeBytes,
      dangling: i.dangling
    })
  }

  for (const v of disk.volumes) {
    if (v.links === null) {
      withheld.push({
        kind: 'volume',
        id: v.name,
        label: v.name,
        reason: 'this runtime did not say how many containers are linked to it'
      })
      continue
    }
    if (v.links > 0) {
      withheld.push({
        kind: 'volume',
        id: v.name,
        label: v.name,
        reason: `${v.links} container${v.links === 1 ? '' : 's'} linked to it`
      })
      continue
    }
    items.push({
      kind: 'volume',
      id: v.name,
      label: v.name,
      size: v.size,
      sizeBytes: v.sizeBytes,
      anonymous: v.anonymous
    })
  }

  for (const c of disk.buildCache) {
    withheld.push({
      kind: 'cache',
      id: c.id,
      label: c.id,
      reason: 'a build cache entry can only be removed by `docker builder prune`, and nothing here runs a prune'
    })
  }

  return { items, withheld }
}

export type DockerReclaimRisk = 'elevated' | 'destructive'

export interface DockerReclaimPlan {
  items: DockerReclaimItem[]
  risk: DockerReclaimRisk
  confirmation: DockerConfirmation
  reasons: string[]
  /**
   * Ways this will not do what the button implies.
   *
   * Kept apart from `reasons` for the reason `K8sRolloutPlan` gives: they are
   * not arguments for pressing harder — they are things that would otherwise be
   * discovered afterwards.
   */
  caveats: string[]
}

/** The word the operator types. Names the verb, so the dialog says what happens. */
export const DOCKER_RECLAIM_PHRASE = 'REMOVE'

/**
 * How hard the operator has to press to remove this set.
 *
 * NEVER `{ kind: 'none' }`, and not because deletion feels serious: there is no
 * undo button next to it the way `start` sits next to `stop`.
 *
 * The one unconditional escalation is a volume, and it does not scale with
 * count because the cost does not. One volume is somebody's database and it is
 * not coming back; a hundred dangling images are a `docker pull` away. Count is
 * the wrong axis, which is why this is `planK8sRollout`'s shape and not
 * `planDockerAction`'s.
 */
export function planDockerReclaim(items: DockerReclaimItem[]): DockerReclaimPlan {
  const of = (kind: DockerReclaimKind): DockerReclaimItem[] => items.filter((i) => i.kind === kind)
  const containers = of('container')
  const images = of('image')
  const volumes = of('volume')
  const networks = of('network')
  const plural = (n: number, word: string): string => `${n} ${word}${n === 1 ? '' : 's'}`

  const reasons: string[] = []
  const caveats: string[] = []

  if (volumes.length > 0) {
    reasons.push(
      `removes ${plural(volumes.length, 'volume')}, and what is inside a volume cannot be recovered afterwards`
    )
  }
  if (containers.length > 0) {
    reasons.push(
      `removes ${plural(containers.length, 'container')}, which can only be brought back if you know how it was run`
    )
  }
  if (images.length > 0) {
    reasons.push(
      `removes ${plural(images.length, 'image')}, which has to be pulled or rebuilt to come back`
    )
  }
  if (networks.length > 0) reasons.push(`removes ${plural(networks.length, 'network')}`)

  const named = volumes.filter((v) => v.anonymous !== true)
  if (named.length > 0) {
    // Docker 23 changed `volume prune` to skip named volumes precisely because
    // removing them was the regret people kept reporting. This does remove
    // them — by name, one at a time, because that is what was selected — and
    // saying so is the difference between a decision and a surprise.
    caveats.push(
      `${plural(named.length, 'named volume')} — docker's own \`volume prune\` skips these on Docker 23 and later, and this does not, because you picked them by name`
    )
  }
  if (images.some((i) => i.dangling === true)) {
    caveats.push(
      'a dangling image is a previous build\'s layers; no registry has a copy, so it comes back only by rebuilding'
    )
  }
  if (images.length > 0) {
    caveats.push(
      'an image carrying more than one tag is refused rather than untagged — docker says so per image and the image stays'
    )
  }
  const orphaning = containers.filter((c) => (c.mountedVolumes ?? 0) > 0)
  if (orphaning.length > 0) {
    caveats.push(
      `${plural(orphaning.length, 'container')} here mount local volumes; removing the container leaves those volumes behind, it does not delete them`
    )
  }
  caveats.push(
    'only the ids listed here are removed — anything that became removable while this dialog was open is left alone'
  )

  const risk: DockerReclaimRisk = volumes.length > 0 ? 'destructive' : 'elevated'
  const confirmation: DockerConfirmation =
    volumes.length > 0 ? { kind: 'type-to-confirm', phrase: DOCKER_RECLAIM_PHRASE } : { kind: 'confirm' }

  return { items, risk, confirmation, reasons, caveats }
}

// ------------------------------------------------- the re-preview, and the diff

export interface DockerReclaimChange {
  item: DockerReclaimItem
  /** What moved, in the words the dialog prints verbatim. */
  detail: string
}

export interface DockerReclaimDiff {
  /** Selected items the fresh read does not list at all. Already gone, or renamed. */
  gone: DockerReclaimItem[]
  /** Selected items still there and no longer offerable — something started using them. */
  ineligible: DockerReclaimChange[]
  /** Selected items whose displayed figures moved since the operator read them. */
  changed: DockerReclaimChange[]
  /**
   * Newly offerable items nobody has seen.
   *
   * Reported, and NOT a reason to refuse. They are untouched by construction —
   * the command carries explicit ids and theirs are not among them — so
   * refusing on them would make a busy host permanently unreclaimable while
   * protecting nothing. The count on screen would otherwise be quietly wrong,
   * which is the only thing worth saying about them.
   */
  appeared: DockerReclaimItem[]
}

const keyOf = (i: { kind: string; id: string }): string => `${i.kind} ${i.id}`

/**
 * The selected set, against a listing taken a moment ago.
 *
 * This is the honest answer to everything that can move between the preview and
 * the click, and it is why the executed set never has to be trusted: the ids are
 * re-derived from a fresh read, and if the fresh read disagrees with what the
 * operator was shown, nothing runs.
 */
export function diffDockerReclaim(
  selected: DockerReclaimItem[],
  fresh: DockerReclaimPreview
): DockerReclaimDiff {
  const offered = new Map(fresh.items.map((i) => [keyOf(i), i]))
  const refused = new Map(fresh.withheld.map((w) => [keyOf(w), w]))
  const chosen = new Set(selected.map(keyOf))

  const gone: DockerReclaimItem[] = []
  const ineligible: DockerReclaimChange[] = []
  const changed: DockerReclaimChange[] = []

  for (const item of selected) {
    const k = keyOf(item)
    const now = offered.get(k)
    if (now === undefined) {
      const why = refused.get(k)
      if (why !== undefined) ineligible.push({ item, detail: why.reason })
      else gone.push(item)
      continue
    }
    if (now.label !== item.label) {
      changed.push({ item, detail: `it is now ${now.label}, not ${item.label}` })
      continue
    }
    if (now.size !== item.size) {
      changed.push({ item, detail: `it is now ${now.size}, not ${item.size}` })
    }
  }

  const appeared = fresh.items.filter((i) => !chosen.has(keyOf(i)))
  return { gone, ineligible, changed, appeared }
}

/**
 * Whether the fresh read disagrees with what the operator approved.
 *
 * `appeared` is excluded on purpose — see the field's own note. Everything else
 * means the dialog was describing a host that no longer exists, and the honest
 * response to that is to show the diff and remove nothing.
 */
export function dockerReclaimBlocked(diff: DockerReclaimDiff): boolean {
  return diff.gone.length > 0 || diff.ineligible.length > 0 || diff.changed.length > 0
}

// ------------------------------------------------------------ the removal

/**
 * A docker object id: hex, short or full, and nothing else.
 *
 * This is the rule that keeps `rmi` off tags. A tag contains `:` or `/` and a
 * repository name contains letters, so neither can pass — which means
 * `buildDockerReclaimCommand` cannot be handed `nginx:latest` even by a caller
 * that means well, and cannot be handed `-f` or `--force` by one that does not.
 */
const OBJECT_ID_RE = /^[0-9a-f]{12,64}$/

export function validateDockerObjectId(id: string): boolean {
  return OBJECT_ID_RE.test(id.trim())
}

/**
 * A volume reference, which is a NAME and not an id.
 *
 * Docker's own volume-name grammar, the same one `validateContainerRef`
 * enforces for containers. An anonymous volume's name is 64 hex characters and
 * passes this too.
 */
export function validateDockerVolumeRef(name: string): boolean {
  return REF_RE.test(name.trim())
}

/** The docker subcommand each kind is removed with. Never `prune`, in any spelling. */
const RECLAIM_VERB: Record<DockerReclaimKind, string> = {
  container: 'rm',
  image: 'rmi',
  volume: 'volume rm',
  network: 'network rm'
}

const RECLAIM_MARKER: Record<DockerReclaimKind, string> = {
  container: DOCKER_MARKERS.rmContainer,
  image: DOCKER_MARKERS.rmImage,
  volume: DOCKER_MARKERS.rmVolume,
  network: DOCKER_MARKERS.rmNetwork
}

/**
 * `docker rm` / `rmi` / `volume rm` / `network rm`, against exactly these ids.
 *
 * No flags. Not `-f`, not `-a`, not `--volumes`, not `--filter` — the argument
 * grammar has no room for one, because every reference is matched against a
 * regex that admits only hex or a docker name. That is not defence in depth
 * dressed up: it is the reason an operator can read the built command and know
 * what it will touch, which was the original objection to `prune`.
 *
 * ORDER IS LOAD-BEARING, and it is not the `system prune -a` hazard in
 * miniature. Containers go first because docker refuses to remove an image a
 * container still references — but an image with a referencing container is
 * never OFFERED (see `buildDockerReclaimPreview`), so removing a container here
 * can never make a selected image removable that the preview called blocked.
 * The ordering serves docker's dependency; it cannot widen the set.
 *
 * Each kind is its own block behind its own marker so one failing command
 * cannot swallow the next one's output, and so a volume's error line — which
 * names the CONTAINER holding it — is never matched against a container the
 * operator also selected.
 */
export function buildDockerReclaimCommand(
  items: DockerReclaimItem[],
  opts: { sudo?: boolean } = {}
): string {
  if (!Array.isArray(items) || items.length === 0) {
    throw new Error('refusing to build a reclaim command with no items')
  }
  if (items.length > DOCKER_ACTION_MAX_REFS) {
    throw new Error(`refusing to remove more than ${DOCKER_ACTION_MAX_REFS} items at once`)
  }
  const seen = new Set<string>()
  for (const item of items) {
    if (item === null || typeof item !== 'object') {
      throw new Error('refusing to build a reclaim command from something that is not an item')
    }
    if (!DOCKER_RECLAIM_KINDS.includes(item.kind)) {
      throw new Error('refusing to build a reclaim command for an unknown docker object kind')
    }
    if (typeof item.id !== 'string') {
      throw new Error('refusing to build a reclaim command from a reference that is not a string')
    }
    const ok = item.kind === 'volume' ? validateDockerVolumeRef(item.id) : validateDockerObjectId(item.id)
    if (!ok) {
      // An image reference that is a tag lands here, and that is the point:
      // `docker rmi nginx:latest` untags where `docker rmi <id>` removes.
      throw new Error('refusing to build a reclaim command from an invalid docker object reference')
    }
    const k = keyOf(item)
    // The same id twice would make docker's second attempt fail with "no such
    // object", which is a failure this app invented and would then have to
    // explain. Refused instead.
    if (seen.has(k)) throw new Error('refusing to build a reclaim command that names the same object twice')
    seen.add(k)
  }

  const run = runner(opts.sudo)
  const blocks: string[] = []
  for (const kind of DOCKER_RECLAIM_KINDS) {
    const refs = items.filter((i) => i.kind === kind).map((i) => i.id.trim())
    if (refs.length === 0) continue
    blocks.push(`echo "${RECLAIM_MARKER[kind]}"`)
    blocks.push(`${run} ${RECLAIM_VERB[kind]} ${refs.join(' ')} 2>&1`)
  }
  return [
    resolveBinary('docker'),
    ...blocks,
    // The last block's own status, held over the echo and handed back — the
    // same shape `buildDockerDiskDetailCommand` uses, and for the same reason.
    // The closing marker keeps a login shell's parting words (an motd, a locale
    // warning) out of the final block, where they would be read as a line
    // docker printed about an object.
    `SP_RC=$?; echo "${DOCKER_MARKERS.end}"; exit $SP_RC`
  ].join('; ')
}

export interface DockerReclaimOutcome {
  item: DockerReclaimItem
  ok: boolean
  error?: string
}

export type DockerReclaimResult =
  | {
      ok: true
      outcomes: DockerReclaimOutcome[]
      /** Lines docker printed that name no selected object. Shown rather than dropped. */
      unattributed: string[]
      usedSudo?: boolean
    }
  | { ok: false; reason: DockerFailure; detail: string }

/**
 * A line saying an object went away.
 *
 * `docker rm`, `docker volume rm` and `docker network rm` echo the reference
 * they were given, verbatim, one per line. `docker rmi` does not: it prints
 * `Untagged: <ref>` and `Deleted: sha256:<64 hex>`, and the short id it was
 * given is a PREFIX of that digest rather than equal to it. Both recorded on
 * Docker 29.5.3 — see tests/fixtures/docker/reclaim-removed-docker-29.txt.
 */
const REMOVED_LINE = /^(Untagged|Deleted):\s/i

/**
 * What actually happened to each object.
 *
 * `ok: false` is reserved for docker never having run — a dead daemon, a
 * refused socket, a missing binary. An object that failed on its own terms is a
 * successful read of a failed removal, and flattening the two would put a
 * permissions problem behind the words "nothing happened". The same division
 * `parseDockerActionOutput` makes, for the same reason.
 */
export function parseDockerReclaimOutput(
  items: DockerReclaimItem[],
  output: string,
  exitCode: number | null
): DockerReclaimResult {
  const kinds = [...new Set(items.map((i) => i.kind))]
  const bodies = new Map<DockerReclaimKind, string>()
  for (const kind of kinds) {
    const body = section(output, RECLAIM_MARKER[kind])
    if (body !== undefined) bodies.set(kind, body)
  }
  // Not one block reached: the shell never got to any docker at all.
  if (bodies.size === 0) {
    const detail = nonEmptyLines(output)[0] ?? 'docker did not run'
    return { ok: false, reason: classifyDockerFailure(output, exitCode), detail }
  }

  const done = new Set<string>()
  const errors = new Map<string, string>()
  const unattributed: string[] = []

  for (const kind of kinds) {
    const body = bodies.get(kind)
    if (body === undefined) continue
    // Only this kind's references are candidates, so a volume's `volume is in
    // use - [<container id>]` can never be attributed to a container.
    const refs = items.filter((i) => i.kind === kind)
    // Longest first, so a short id that prefixes a longer one does not claim
    // the other's line.
    const byLength = [...refs].sort((a, b) => b.id.length - a.id.length)
    for (const line of nonEmptyLines(body)) {
      const exact = byLength.find((r) => r.id === line)
      if (exact !== undefined) {
        done.add(keyOf(exact))
        continue
      }
      const named = byLength.find((r) => line.includes(r.id))
      if (named !== undefined) {
        const k = keyOf(named)
        if (REMOVED_LINE.test(line)) {
          done.add(k)
          continue
        }
        if (!done.has(k) && !errors.has(k)) errors.set(k, line)
        continue
      }
      unattributed.push(line)
    }
  }

  if (done.size === 0 && errors.size === 0) {
    const failure = blockFailure(unattributed.join('\n'), exitCode)
    if (failure) return { ok: false, ...failure }
  }

  const outcomes: DockerReclaimOutcome[] = items.map((item) => {
    const k = keyOf(item)
    if (done.has(k)) return { item, ok: true }
    const error = errors.get(k)
    if (error !== undefined) return { item, ok: false, error }
    // Not mentioned at all. Saying so is the honest answer; assuming success
    // would tell an operator a volume is gone when nothing confirmed it — and
    // assuming failure would tell them it is still there when it may not be.
    return { item, ok: false, error: 'docker did not say what happened to this object' }
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
  diskDetail(cfg: unknown, opts?: { sudo?: boolean; autoSudo?: boolean }): Promise<DockerDiskDetailProbe>
  inspect(cfg: unknown, ref: string, opts?: { sudo?: boolean; autoSudo?: boolean }): Promise<DockerInspectProbe>
  stats(cfg: unknown, refs: string[], opts?: { sudo?: boolean; autoSudo?: boolean }): Promise<DockerStatsProbe>
  act(
    cfg: unknown,
    action: DockerAction,
    refs: string[],
    opts?: { sudo?: boolean; timeoutSec?: number }
  ): Promise<DockerActionResult>
  /**
   * Remove exactly these objects.
   *
   * Takes ITEMS rather than refs, because the kind decides which docker verb
   * runs and a bare list of ids would leave main guessing. There is no
   * `prune` channel and there is no `force` option: the plan, the re-preview
   * and the diff decide whether this is called at all, and the builder decides
   * what it is allowed to say.
   */
  reclaim(
    cfg: unknown,
    items: DockerReclaimItem[],
    opts?: { sudo?: boolean }
  ): Promise<DockerReclaimResult>
}
