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
}

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
