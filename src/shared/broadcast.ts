// Running one command on many servers at once.
//
// THE APPROVAL MODEL, settled before the executor was written, because the
// executor is easy and this is not.
//
// The thing that makes broadcast different from a terminal is not that it runs
// a command — the user can already do that on any one host. It is that a
// mistake is simultaneous and irreversible across the estate. `rm -rf /var/log`
// on the wrong host is a bad evening; on fifteen hosts at once it is the
// evening plus every log you would have used to understand it. So the model is
// built around blast radius rather than around the command text alone:
//
//  1. Targets are always explicit. There is no "all servers" default and no
//     saved target set that could drift as the workspace changes. The user
//     picks, every time, and sees the list before it runs.
//  2. Confirmation strength scales with how many hosts are selected and how
//     dangerous the command reads. One host, harmless command: just run it —
//     nagging on the safe case is how people learn to click through the
//     dangerous one. Many hosts or a destructive verb: type the word.
//  3. Nothing is classified as safe by omission. An unrecognised command on
//     twelve hosts is still twelve hosts.
//  4. Sequential with a small concurrency cap, for the same reason the sampler
//     sweeps sequentially: fifteen hosts behind two bastions means fifteen
//     simultaneous exec channels through two machines an operator cannot
//     afford to wobble.
//  5. Cancellable, and cancelling means hosts not yet started never start.
//     A broadcast you cannot stop is the failure mode this whole model exists
//     to avoid.
//  6. Results stay per host. Merging output into one stream loses which
//     machine said what, which is the only question that matters afterwards.
//
// Deliberately NOT reachable by an agent. The MCP bridge gates
// `execute_command` per server against an access group; a fan-out primitive is
// a different risk with a different consent story, and giving one to an agent
// because the UI happened to grow one would be an accident rather than a
// decision.

export type BroadcastRisk = 'ordinary' | 'elevated' | 'destructive'

export interface BroadcastPlan {
  command: string
  risk: BroadcastRisk
  /** Servers this will run on, in order. */
  targets: { serverId: string; serverName: string }[]
  /** What the user must do before this runs. */
  confirmation: BroadcastConfirmation
  /** Why it was classified this way, for the dialog to show. */
  reasons: string[]
}

export type BroadcastConfirmation =
  /** Run on click. One host, nothing alarming in the command. */
  | { kind: 'none' }
  /** A normal confirm step naming the hosts. */
  | { kind: 'confirm' }
  /** The user types this exact word. Reserved for genuine blast radius. */
  | { kind: 'type-to-confirm'; phrase: string }

/** Above this many hosts, even an ordinary command gets a confirm step. */
export const CONFIRM_ABOVE_HOSTS = 1
/** Above this many hosts, an ordinary command escalates to type-to-confirm. */
export const TYPE_ABOVE_HOSTS = 5

// Verbs that destroy state, stop machines, or overwrite devices. Matched on the
// command as written; this is a UX guard that decides how hard the user has to
// press, not a security boundary. Anyone typing here already has a shell on
// these hosts — the point is to make an accident require a deliberate act, not
// to stop an attacker.
// A verb only counts where a command can actually start: the beginning of the
// line, or after a pipe, semicolon, &&, || or newline — optionally behind sudo.
//
// Without this the classifier flags `grep reboot /var/log/syslog` as "stops the
// machine", which is worse than useless: a guard that cries wolf on a read-only
// grep is a guard people learn to click through, and it is then not there for
// the `reboot` that meant it.
function atCommandStart(verbs: string): RegExp {
  return new RegExp(String.raw`(^|[;&|(]|\n)\s*(?:\w+=\S+\s+)*(?:sudo\s+|doas\s+)?(?:${verbs})\b`)
}

// A flag argument, wherever it appears in a command's argument list rather than
// only immediately after the verb. `chmod 777 -R /srv` is the same command as
// `chmod -R 777 /srv`, and a guard that only reads the first token is a guard
// that misses whichever order the person happened to type.
function flagAnywhere(verb: string, flags: string): RegExp {
  return new RegExp(
    String.raw`(^|[;&|(]|\n)\s*(?:sudo\s+|doas\s+)?(?:${verb})(?:\s+[^\s;|&]+)*\s+(?:${flags})\b`
  )
}

const DESTRUCTIVE = [
  // Long options count: `rm --recursive --force /` is the same command, and
  // reading only the short flags made the most explicit spelling the one that
  // ran with no confirmation at all.
  {
    rx: /(^|[;&|(]|\n)\s*(?:sudo\s+|doas\s+)?rm\s+((-[a-zA-Z]*[rf][a-zA-Z]*|--recursive|--force|--no-preserve-root)\s+)+/,
    why: 'deletes files recursively or forcibly'
  },
  // `find … -exec rm` and `… | xargs rm` are how a bulk delete is actually
  // typed. Neither puts `rm` at a command start, so the anchored rule above
  // reads both as ordinary.
  { rx: /-exec\s+(?:sudo\s+|doas\s+)?rm\b/, why: 'deletes files through find -exec' },
  { rx: /\bxargs\s+(?:-\S+\s+)*(?:sudo\s+|doas\s+)?rm\b/, why: 'deletes files through xargs' },
  { rx: /(^|[;&|(]|\n)\s*(?:sudo\s+|doas\s+)?find\s[^;|&]*\s-delete\b/, why: 'deletes every file find matches' },
  { rx: atCommandStart('mkfs(\\.\\w+)?|fdisk|parted|wipefs'), why: 'writes to a partition table or filesystem' },
  { rx: /(^|[;&|(]|\n)\s*(?:sudo\s+|doas\s+)?dd\s[^|;]*\bof=/, why: 'writes directly to a device or file with dd' },
  { rx: atCommandStart('shutdown|poweroff|halt|reboot'), why: 'stops or restarts the machine' },
  // systemd's own spellings of the same thing. `systemctl poweroff` puts
  // `systemctl` at the command start, so the verb rule above never sees it.
  {
    rx: /(^|[;&|(]|\n)\s*(?:sudo\s+|doas\s+)?systemctl\s+(poweroff|reboot|halt|kexec)\b/,
    why: 'stops or restarts the machine'
  },
  { rx: atCommandStart('userdel|groupdel'), why: 'removes an account' },
  { rx: /\bdrop\s+(database|table)\b/i, why: 'drops a database or table' },
  { rx: atCommandStart('truncate|shred'), why: 'destroys file contents' },
  { rx: flagAnywhere('chown', '-[a-zA-Z]*R[a-zA-Z]*|--recursive'), why: 'changes ownership recursively' },
  { rx: flagAnywhere('chmod', '-[a-zA-Z]*R[a-zA-Z]*|--recursive'), why: 'changes permissions recursively' },
  { rx: /(^|[;&|(]|\n)\s*(?:sudo\s+|doas\s+)?(kill|killall|pkill)\s+(-9|-KILL|-s\s*(9|KILL|SIGKILL))\b/, why: 'sends SIGKILL' },
  // `\b-F\b` never matched ` -F`: there is no word boundary between a space and
  // a dash, so the single most common way to flush a firewall read as ordinary.
  {
    rx: /(^|[;&|(]|\n)\s*(?:sudo\s+|doas\s+)?(iptables|ip6tables|nft|ufw)\b[^;|]*(\bflush\b|\s-F\b|\breset\b)/,
    why: 'clears firewall rules'
  },
  { rx: />\s*\/dev\/[sn][dv]/, why: 'redirects output onto a block device' },
  { rx: /(^|[;&|(]|\n)\s*(?:sudo\s+|doas\s+)?systemctl\s+(stop|disable|mask)\b/, why: 'stops or disables a service' },
  { rx: /(^|[;&|(]|\n)\s*(?:sudo\s+|doas\s+)?service\s+\S+\s+stop\b/, why: 'stops a service' },
  // One key away from `crontab -e`, and it takes the whole schedule with it.
  { rx: /(^|[;&|(]|\n)\s*(?:sudo\s+|doas\s+)?crontab\s+-[a-z]*r[a-z]*\b/, why: 'removes the crontab' },
  { rx: atCommandStart('lvremove|vgremove|pvremove'), why: 'removes a volume or volume group' },
  { rx: /(^|[;&|(]|\n)\s*(?:sudo\s+|doas\s+)?(zfs|zpool)\s+destroy\b/, why: 'destroys a dataset or pool' }
]

const ELEVATED = [
  // Anchored to a command start rather than to position zero: `curl … | sudo
  // bash` is root, and reading only the first word said it was not.
  { rx: atCommandStart('sudo|doas'), why: 'runs as root' },
  { rx: /(^|[;&|(]|\n)\s*(?:sudo\s+|doas\s+)?systemctl\s+(restart|reload)\b/, why: 'restarts a service' },
  { rx: /(^|[;&|(]|\n)\s*(?:sudo\s+|doas\s+)?service\s+\S+\s+(restart|reload)\b/, why: 'restarts a service' },
  {
    rx: /(^|[;&|(]|\n)\s*(?:sudo\s+|doas\s+)?(apt|apt-get|yum|dnf|apk|pacman)\s+(install|remove|purge|autoremove|upgrade|dist-upgrade|full-upgrade|update)\b/,
    why: 'changes installed packages'
  },
  // The noun-verb spellings (`docker system prune`, `docker volume rm`) are the
  // common ones now, and the verb-only rule matched none of them.
  {
    rx: /(^|[;&|(]|\n)\s*(?:sudo\s+|doas\s+)?(docker|podman)\s+(?:(?:container|image|volume|network|system|compose)\s+)?(rm|rmi|stop|kill|prune|down)\b/,
    why: 'removes or stops containers'
  }
]

export interface RiskAssessment {
  risk: BroadcastRisk
  reasons: string[]
}

/**
 * How dangerous the command reads.
 *
 * Text-based and therefore defeatable — `$(echo rm) -rf /` is not caught, and
 * is not meant to be. Someone constructing that is not making the mistake this
 * guards against. What it catches is the real accident: a correct, obvious,
 * destructive command aimed at more hosts than intended.
 */
export function assessCommand(command: string): RiskAssessment {
  const reasons: string[] = []
  let risk: BroadcastRisk = 'ordinary'

  for (const { rx, why } of DESTRUCTIVE) {
    if (rx.test(command)) {
      risk = 'destructive'
      reasons.push(why)
    }
  }
  if (risk !== 'destructive') {
    for (const { rx, why } of ELEVATED) {
      if (rx.test(command)) {
        risk = 'elevated'
        reasons.push(why)
      }
    }
  }
  return { risk, reasons }
}

/**
 * The confirmation a given command and target list requires.
 *
 * Both inputs matter and neither dominates. A destructive command on one host
 * still gets typed confirmation, because the command is the danger. An ordinary
 * command on twelve hosts also gets it, because the count is.
 */
export function confirmationFor(risk: BroadcastRisk, hostCount: number): BroadcastConfirmation {
  if (hostCount === 0) return { kind: 'confirm' }
  if (risk === 'destructive') return { kind: 'type-to-confirm', phrase: 'RUN' }
  if (risk === 'elevated' && hostCount > TYPE_ABOVE_HOSTS) return { kind: 'type-to-confirm', phrase: 'RUN' }
  if (hostCount > TYPE_ABOVE_HOSTS) return { kind: 'type-to-confirm', phrase: 'RUN' }
  if (risk === 'elevated' || hostCount > CONFIRM_ABOVE_HOSTS) return { kind: 'confirm' }
  return { kind: 'none' }
}

export function planBroadcast(
  command: string,
  targets: { serverId: string; serverName: string }[]
): BroadcastPlan {
  const { risk, reasons } = assessCommand(command)
  return { command, risk, targets, confirmation: confirmationFor(risk, targets.length), reasons }
}

// ---------------------------------------------------------------- execution

export type BroadcastHostState = 'pending' | 'running' | 'ok' | 'failed' | 'skipped'

export interface BroadcastHostResult {
  serverId: string
  serverName: string
  state: BroadcastHostState
  exitCode?: number
  stdout?: string
  stderr?: string
  error?: string
  ms?: number
  truncated?: boolean
  /**
   * What actually happened, one level below `state`.
   *
   * `state` answers "did the host answer us", which is the question the runner
   * can answer honestly and the question the "non-zero is a result" rule
   * depends on. It is not the question the operator is asking. Running
   * `docker ps` across fifteen hosts, the thing they need to see is which three
   * do not have docker — and today that is fifteen rows of `exit 127` mixed
   * into fifteen rows of output, to be read one at a time.
   *
   * So the classification is additive: `state` keeps its meaning exactly (a
   * missing command is still `ok`, because the host did answer), and this says
   * what the answer was. Set by the runner so it is derived once, from the
   * place that also knows the transport-level error text.
   */
  outcome?: BroadcastHostOutcome
}

/**
 * The categories an operator actually sorts a fan-out by.
 *
 * Deliberately not a severity ordering. `nonzero` is not a lesser `ok`: a grep
 * that matched nothing exits 1 and is a perfectly good answer, which is exactly
 * why the runner refuses to call a non-zero exit a failure.
 */
export type BroadcastHostOutcome =
  /** Exit 0. */
  | 'ok'
  /** Ran, exited non-zero. A result, not a failure. */
  | 'nonzero'
  /** The command is not on this host — the single most common fan-out surprise. */
  | 'missing-command'
  /** The host refused to run it as this user. */
  | 'permission-denied'
  /** No answer inside the time allowed. */
  | 'timeout'
  /** Never got as far as running anything: connect refused, host down, bastion dead. */
  | 'unreachable'
  /** Never started, because the run was cancelled. */
  | 'cancelled'

export const BROADCAST_OUTCOME_LABEL: Record<BroadcastHostOutcome, string> = {
  ok: 'ok',
  nonzero: 'non-zero exit',
  'missing-command': 'command not on this host',
  'permission-denied': 'permission denied',
  timeout: 'timed out',
  unreachable: 'unreachable',
  cancelled: 'not run'
}

// A missing command is reported by the SHELL, not by the program, and every
// shell words it differently — the same problem the Docker module solves for
// one host, and the same list, because it is a fact about shells rather than
// about docker.
//
// `no such file or directory` is deliberately NOT here: it is also what `cat
// /nope` says about its ARGUMENT, and reading that as "the command is missing"
// would file a perfectly working host under "you need to install this". It is
// picked up below, but only alongside exit 127, where the shell is the one
// saying it about the command itself.
const MISSING_COMMAND = [
  /command not found/i,
  /:\s*not found/, // dash/busybox: "sh: 1: docker: not found"
  /is not recognized as an internal or external command/i,
  /unknown command/i
]

// Whole-command refusals, not "one file in a tree was unreadable". `find /
// -name x` prints hundreds of "Permission denied" lines and still does its job;
// calling that host permission-denied would bury the answer it gave.
const PERMISSION = [
  /permission denied/i,
  /operation not permitted/i,
  /must be (run as |)root/i,
  /is not in the sudoers file/i,
  /sudo: a (password|terminal) is required/i,
  /sudo: no tty present/i
]

const TIMED_OUT = /timed out|never answered/i

/**
 * Which category a finished host falls into.
 *
 * Returns null while the host is still pending or running — a category for
 * "we do not know yet" would end up counted in the summary as though it were an
 * answer.
 *
 * Order matters:
 *
 *  1. The shell's own "no such command" wording, before any exit code, because
 *     some shells exit 1 or 2 for it.
 *  2. Exit 126, which is unambiguous: the file was found and could not be
 *     executed.
 *  3. A permission refusal in stderr, but ONLY with no stdout. A command that
 *     produced output and also hit an unreadable file did its job.
 *  4. Exit 127 last, so it never overrides a message that said something more
 *     specific.
 */
export function classifyBroadcastResult(r: BroadcastHostResult): BroadcastHostOutcome | null {
  if (r.state === 'pending' || r.state === 'running') return null
  if (r.state === 'skipped') return 'cancelled'
  // A transport failure. The distinction the operator needs here is "the host
  // did not answer in time" from "we never reached the host at all": one is a
  // slow command or a slow link, the other is a machine or a bastion to go and
  // look at.
  if (r.state === 'failed') return TIMED_OUT.test(r.error ?? '') ? 'timeout' : 'unreachable'

  const stderr = r.stderr ?? ''
  const stdout = r.stdout ?? ''
  if (MISSING_COMMAND.some((re) => re.test(stderr))) return 'missing-command'
  if (r.exitCode === 126) return 'permission-denied'
  if (stdout.trim() === '' && PERMISSION.some((re) => re.test(stderr))) return 'permission-denied'
  if (r.exitCode === 127) return 'missing-command'
  return (r.exitCode ?? 0) === 0 ? 'ok' : 'nonzero'
}

export interface BroadcastSummary {
  total: number
  /** Not yet finished. Counted separately so the categories always sum. */
  running: number
  counts: Record<BroadcastHostOutcome, number>
}

/**
 * Fifteen hosts, made scannable.
 *
 * The result list is the record and stays complete — merged output loses which
 * machine said what — but a list is not an answer. "12 ok, 2 command not on
 * this host, 1 timed out" is, and it is the line that tells someone whether
 * they need to read the list at all.
 */
export function summariseBroadcast(results: BroadcastHostResult[]): BroadcastSummary {
  const counts: Record<BroadcastHostOutcome, number> = {
    ok: 0,
    nonzero: 0,
    'missing-command': 0,
    'permission-denied': 0,
    timeout: 0,
    unreachable: 0,
    cancelled: 0
  }
  let running = 0
  for (const r of results) {
    // The runner's own classification wins when it is there: it saw the raw
    // transport error, and re-deriving it from a result that has been through
    // IPC would be a second implementation to drift.
    const o = r.outcome ?? classifyBroadcastResult(r)
    if (o === null) running++
    else counts[o]++
  }
  return { total: results.length, running, counts }
}

// ---- Why there is no sudo retry here -----------------------------------
//
// The Docker reader retries a refused read as root, and the obvious question is
// why broadcast does not. Four reasons, and they all come from this being a
// fan-out rather than a read:
//
//  1. The user approved THIS command, not this command as root. The whole
//     approval model above scales the confirmation to the blast radius, and the
//     radius was computed from the text they typed. Silently re-running it with
//     more privilege raises the radius AFTER consent was given, which inverts
//     the model rather than extending it.
//  2. It is not a retry, it is a second execution. `docker ps` is idempotent
//     and read-only; a broadcast command is arbitrary, and `a && b` that fails
//     partway through has already had an effect. Running it again — as root,
//     this time — is a different and worse thing than trying again.
//  3. One escalation is a decision; N simultaneous escalations across an estate
//     is an event. The retry would fan out to every host that refused, each
//     with its own sudoers policy, in one click.
//  4. The user can already do it, better. Typing `sudo` themselves is one word,
//     and it goes through `assessCommand`, which classifies `sudo` as elevated
//     and asks for the confirmation that escalation deserves.
//
// So what broadcast owes the operator is not the escalation — it is knowing
// they need it. `permission-denied` is a first-class outcome above, and the
// panel says which hosts refused and that prefixing sudo is theirs to decide.

export interface BroadcastProgress {
  runId: string
  host: BroadcastHostResult
  /** Set on the final event so the renderer knows the run is over. */
  done?: boolean
  /** Hosts never started because the run was cancelled. */
  cancelled?: boolean
}

export interface BroadcastRequest {
  runId: string
  command: string
  timeoutMs?: number
  /**
   * The record of what the user was asked and what they answered — B3.
   *
   * Required, and checked in main against a fresh `planBroadcast` over this
   * very request before a single channel is opened. Before B3 the plan was
   * computed in the renderer's `useMemo` and thrown away, so `broadcast:run`
   * took a command and a target list and had no idea whether anybody had
   * agreed to either. See CommandApproval at the foot of this file for why
   * that stopped being acceptable.
   */
  approval: CommandApproval
  targets: {
    serverId: string
    serverName: string
    cfg: unknown
  }[]
}

/** Simultaneous exec channels. Small on purpose — see the header. */
export const BROADCAST_CONCURRENCY = 3
export const BROADCAST_TIMEOUT_MS = 60_000
/**
 * How long past the per-host timeout the runner waits before giving up on an
 * executor that has not settled.
 *
 * `sshExec` starts its own timer only after the connection is acquired, so a
 * host whose connect never completes — a bastion that accepts TCP and then says
 * nothing, a trust prompt nobody answers — leaves the runner awaiting forever:
 * no result, no terminal event, and a Stop button that cannot help because
 * cancel deliberately leaves running hosts alone. The grace is generous because
 * a slow multi-hop connect is normal; what it rules out is "never".
 */
export const BROADCAST_STALL_GRACE_MS = 30_000
/** Per-host output kept, in characters. A fan-out can produce a lot. */
export const BROADCAST_OUTPUT_CAP = 20_000

// ===========================================================================
// B3: the approval record
// ===========================================================================
//
// WHY THIS IS HERE AND NOT ONLY IN jobs.ts. A job is a broadcast that outlives
// its panel, and B3's whole point is that there is ONE approval model rather
// than two. jobs.ts imports this file; this file imports nothing. So the record
// and the check live at the bottom, where both surfaces can reach them, and the
// only thing each surface supplies is its own re-derived plan — `planBroadcast`
// for one command against a flat target list, `planJob` for a step list against
// cohorts.
//
// ---------------------------------------------------------------------------
// REVERSING A SETTLED DECISION, deliberately, and here is the reasoning
// ---------------------------------------------------------------------------
// main/index.ts used to state that main does not re-derive the approval model,
// because "the renderer is where the user is and is not a trust boundary here".
// Both halves of that were true and the conclusion has stopped being true, for
// a reason that did not exist when it was written:
//
//   The renderer is where the user is. It is also GONE by the time a detached
//   job needs re-authorising.
//
// B2 made a job outlive the process. A job resumed at the next launch is being
// acted on by a ShellPilot that never showed anybody a dialog, and "the
// renderer computed a plan" is not a fact that survives a restart — it was
// never written down anywhere. `BroadcastPlan` was computed in a `useMemo` and
// thrown away.
//
// This is still not an attacker boundary and is not sold as one: anyone driving
// the renderer already has a shell on these hosts. What it is, is a RECORD and
// an AGREEMENT CHECK. The record says what a human was asked and what they
// answered; the check says the thing about to run is still the thing they were
// asked about. Those two are what a durable job needs and what neither the
// renderer-only path nor the AI capability gate produces.

/** A host as it appeared in the list the user confirmed. */
export interface ApprovalTargetRef {
  serverId: string
  serverName: string
  cohort?: string
}

/**
 * What a human was asked, and what they answered.
 *
 * Written with the job, in the row, so a process that never saw the dialog can
 * ask "was this authorised, for exactly this?" and answer from rows alone. It
 * carries the RESOLVED target list rather than a selection rule for the reason
 * broadcast refuses saved target sets at all: a rule re-evaluated later is a
 * blast radius that can grow after consent was given.
 *
 * `phrase` is the word the user actually typed, kept because "the dialog
 * demanded RUN" and "the user typed RUN" are two different facts and only the
 * second one is consent. It is not a secret and is one of three literals, but
 * it goes through `redactOutput` on its way to the log with everything else,
 * because a redaction rule with an exception is a redaction rule someone will
 * eventually widen.
 */
export interface CommandApproval {
  v: 1
  /** Which surface produced it. Recorded, never used to weaken a check. */
  surface: 'broadcast' | 'job'
  /** The command text of every step, in order, exactly as approved. */
  commands: string[]
  targets: ApprovalTargetRef[]
  risk: BroadcastRisk
  confirmation: BroadcastConfirmation
  /** The phrase typed, where one was required. Null where none was. */
  phrase: string | null
  confirmedAt: number
}

export type ApprovalVerdict = { ok: true } | { ok: false; reason: string }

export function isCommandApproval(v: unknown): v is CommandApproval {
  if (typeof v !== 'object' || v === null) return false
  const a = v as Partial<CommandApproval>
  return (
    a.v === 1 &&
    (a.surface === 'broadcast' || a.surface === 'job') &&
    Array.isArray(a.commands) &&
    a.commands.every((c) => typeof c === 'string') &&
    Array.isArray(a.targets) &&
    a.targets.every(
      (t) =>
        typeof t === 'object' &&
        t !== null &&
        typeof (t as ApprovalTargetRef).serverId === 'string' &&
        typeof (t as ApprovalTargetRef).serverName === 'string'
    ) &&
    (a.risk === 'ordinary' || a.risk === 'elevated' || a.risk === 'destructive') &&
    typeof a.confirmation === 'object' &&
    a.confirmation !== null &&
    (a.phrase === null || typeof a.phrase === 'string') &&
    typeof a.confirmedAt === 'number' &&
    Number.isFinite(a.confirmedAt) &&
    a.confirmedAt > 0
  )
}

/**
 * Mint the record at the moment the human answers.
 *
 * The plan is passed in rather than derived here, because the two surfaces
 * derive it differently — see the header — and a mint that re-derived would be
 * a third copy of the rule.
 */
export function approvalFor(o: {
  surface: 'broadcast' | 'job'
  commands: string[]
  targets: ApprovalTargetRef[]
  plan: { risk: BroadcastRisk; confirmation: BroadcastConfirmation }
  phrase?: string | null
  confirmedAt: number
}): CommandApproval {
  return {
    v: 1,
    surface: o.surface,
    commands: [...o.commands],
    // Copied field by field, so a caller's richer object — a whole Server row,
    // with a host and a username on it — cannot smuggle itself into a record
    // that is kept for a year and written to a log.
    targets: o.targets.map((t) => ({
      serverId: t.serverId,
      serverName: t.serverName,
      ...(t.cohort === undefined ? {} : { cohort: t.cohort })
    })),
    risk: o.plan.risk,
    confirmation: o.plan.confirmation,
    phrase: o.phrase ?? null,
    confirmedAt: o.confirmedAt
  }
}

/** One line of a command, short enough to put in a refusal message. */
function snippet(s: string): string {
  const one = s.replace(/\s+/g, ' ').trim()
  return one.length <= 60 ? one : `${one.slice(0, 57)}…`
}

function sameConfirmation(a: BroadcastConfirmation, b: BroadcastConfirmation): boolean {
  if (a.kind !== b.kind) return false
  if (a.kind === 'type-to-confirm' && b.kind === 'type-to-confirm') return a.phrase === b.phrase
  return true
}

/**
 * Is the thing about to run still the thing that was approved?
 *
 * Answered from the record and from a FRESH re-derivation, never from the
 * record alone. The three disagreements it exists to catch are the three that
 * actually happen:
 *
 *  - THE COMMAND WAS EDITED under a stored approval. The record's copy of the
 *    step text is what makes this visible; comparing the spec to itself would
 *    always agree.
 *  - A TARGET WAS ADDED. Consent was given for a blast radius, and a radius
 *    that grows after the fact is the exact accident the whole model exists to
 *    prevent.
 *  - THE CLASSIFIER GOT STRICTER. A command that read `elevated` in the build
 *    that asked and reads `destructive` in the build that resumes was approved
 *    against a weaker demand than the one now in force. Refusing is the only
 *    reading of that which does not silently downgrade a safety rule the
 *    project deliberately tightened.
 *
 * SERVER NAMES ARE NOT COMPARED, and that is a decision rather than an
 * oversight: a rename changes the label on a machine and not the machine, and
 * refusing to finish an upgrade because somebody tidied up a workspace name
 * would be friction with no safety behind it. Ids and cohorts are compared,
 * because those are what gets connected to and what sized the confirmation.
 */
export function verifyApproval(
  approval: unknown,
  actual: { commands: string[]; targets: ApprovalTargetRef[] },
  rederived: { risk: BroadcastRisk; confirmation: BroadcastConfirmation }
): ApprovalVerdict {
  if (!isCommandApproval(approval)) {
    return {
      ok: false,
      reason:
        'no usable approval record came with this run. Nothing runs on a confirmation that was ' +
        'never written down — re-open the panel and confirm it again.'
    }
  }

  if (approval.commands.length !== actual.commands.length) {
    return {
      ok: false,
      reason:
        `the approval covers ${approval.commands.length} step(s) and this run has ` +
        `${actual.commands.length}. Confirm it again.`
    }
  }
  for (let i = 0; i < actual.commands.length; i++) {
    if (approval.commands[i] !== actual.commands[i]) {
      return {
        ok: false,
        reason:
          `step ${i + 1} was approved as \`${snippet(approval.commands[i])}\` and is now ` +
          `\`${snippet(actual.commands[i])}\`. An edited command needs a fresh confirmation.`
      }
    }
  }

  const approved = new Map(approval.targets.map((t) => [t.serverId, t.cohort ?? '']))
  const added = actual.targets.filter((t) => !approved.has(t.serverId))
  if (added.length > 0) {
    return {
      ok: false,
      reason:
        `${added.map((t) => t.serverName).join(', ')} ${added.length === 1 ? 'was' : 'were'} not in ` +
        'the target list that was confirmed. A host added after the fact runs on nobody’s ' +
        'approval.'
    }
  }
  // A SHRUNK list is allowed, and only in this direction. Resuming three of a
  // job's fifteen hosts is exactly what B2's reclaim does, and every one of
  // those three was in the list the user confirmed. Growth is the danger;
  // shrinkage cannot raise a blast radius. It is still reported below when the
  // cohort a survivor sits in has changed, because that CAN raise one.
  for (const t of actual.targets) {
    const cohort = approved.get(t.serverId)
    if (cohort !== undefined && cohort !== (t.cohort ?? '')) {
      return {
        ok: false,
        reason:
          `${t.serverName} was confirmed in wave "${cohort || 'all at once'}" and is now in ` +
          `"${t.cohort ?? 'all at once'}". Moving a host between waves changes how many run at ` +
          'once, which is what the confirmation was sized against.'
      }
    }
  }

  if (approval.risk !== rederived.risk) {
    return {
      ok: false,
      reason:
        `this was approved as \`${approval.risk}\` and now classifies as \`${rederived.risk}\`. ` +
        'The record is held to the stricter reading, so it needs confirming again.'
    }
  }
  if (!sameConfirmation(approval.confirmation, rederived.confirmation)) {
    return {
      ok: false,
      reason:
        `this was approved with a \`${approval.confirmation.kind}\` step and now requires ` +
        `\`${rederived.confirmation.kind}\`. Confirm it again.`
    }
  }
  if (approval.confirmation.kind === 'type-to-confirm' && approval.phrase !== approval.confirmation.phrase) {
    return {
      ok: false,
      reason:
        `this needed the word ${approval.confirmation.phrase} typed, and the record ` +
        `${approval.phrase === null ? 'has no typed phrase at all' : 'has a different one'}.`
    }
  }
  return { ok: true }
}
