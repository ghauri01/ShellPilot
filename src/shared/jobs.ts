import type {
  BroadcastConfirmation,
  BroadcastHostOutcome,
  BroadcastHostResult,
  BroadcastRisk
} from './broadcast'
import { assessCommand, classifyBroadcastResult, confirmationFor } from './broadcast'

// The vocabulary of a job — roadmap item B1.
//
// A job is a command against a target set whose state is PERSISTED: it exists
// in the store before it starts, every transition is written, and it can be
// read back after a restart by something that never saw it run. That is the
// whole of what B1 claims, and it is deliberately less than what "durable"
// usually implies.
//
// ---------------------------------------------------------------------------
// What B1 does NOT claim, said plainly, because the honest version is load-
// bearing for everything below
// ---------------------------------------------------------------------------
// B1 runs on the existing ATTACHED path, and that path is not merely limited —
// it is harmful for long work. `sshExec` on timeout resolves and abandons
// without signalling the remote, and a dying socket means sshd sends SIGHUP,
// which `apt` and `dpkg` do not ignore. Nine minutes into an estate upgrade,
// closing the lid is not "lost output": it is dpkg interrupted on every host,
// and the recovery is `dpkg --configure -a` on each of them.
//
// So a job that was running when ShellPilot stopped is `abandoned`, not
// `resumed` and not `unknown`. That outcome is the point: it is the difference
// between a store that records what happened and a UI that quietly implies the
// work is still going. B2 swaps the execution strategy underneath — a detached
// launch with a marker directory — and the runner takes its executor as an
// injected strategy for exactly that reason. Nothing in this file describes how
// a command is executed.
//
// ---------------------------------------------------------------------------
// Why the approval model is re-exported rather than forked
// ---------------------------------------------------------------------------
// `assessCommand` and `confirmationFor` are the settled model, with the
// reasoning written out at the top of shared/broadcast.ts. A job is a broadcast
// that outlives its panel; it is not a different risk calculus, and a second
// copy of a safety rule is a second thing to drift. They are re-exported
// verbatim. What a job DOES add is `planJob` below, and the only thing it
// changes is which host count the model is evaluated against.
//
// ---------------------------------------------------------------------------
// Not agent-reachable. Ever.
// ---------------------------------------------------------------------------
// Broadcast is deliberately not reachable by an agent, and a job engine is
// strictly more powerful. The argument is in tests/jobsNotExposed.test.ts and
// it is not the broadcast one repeated: DURABILITY DEFEATS REVOCATION.
// `denyAllPending()` resolves requests that are *pending*; it can do nothing
// about a job already running on fifteen hosts, because nothing is pending.

export type { BroadcastConfirmation, BroadcastRisk } from './broadcast'
export { assessCommand, confirmationFor } from './broadcast'

// ---------------------------------------------------------------- vocabulary

/**
 * What one host in a job is doing.
 *
 * The first five are broadcast's, unchanged and meaning exactly what they mean
 * there — `ok` is "the host answered", not "the command succeeded", which is
 * why a non-zero exit is a result rather than a failure.
 *
 * `waiting` is the one B1 adds, and it is not a synonym for `pending`.
 * `pending` means the job has not reached this host yet; `waiting` means the
 * job has reached it and is deliberately holding — behind the concurrency cap,
 * or behind a gate. A UI that cannot tell them apart shows fifteen identical
 * rows and no answer to "why has nothing started".
 *
 * B2 adds four more, and each one is in this union because a code path in this
 * build reaches it — the rule B1 stated when it refused to add them early:
 *
 *  - `detached` — the command is running on the host and ShellPilot is not
 *    holding the channel. Either it never held one after the launch, or the
 *    link dropped and the poller is backing off. It is NOT `unreachable`: the
 *    host may well be fine and the work is certainly continuing.
 *  - `orphaned` — the marker directory is there, the pid is gone, and no `rc`
 *    was ever written. The wrapper died without recording an answer: the OOM
 *    killer, `kill -9`, or the host going down under it. Distinct from
 *    `failed` because nobody knows whether the command finished its work.
 *  - `rebooting` — the host stopped answering while the step that was running
 *    is one that restarts the machine. The roadmap names this the case today's
 *    vocabulary gets exactly backwards: an EXPECTED reboot classified as
 *    `unreachable`. Reached from `restartsTheMachine()` below, which is why it
 *    is in the union rather than reserved.
 *  - `foreign` — the marker was written by a different ShellPilot instance.
 *    Readable, never reapable. See JOB_INSTANCE_NOTE.
 *
 * `waiting` is B1's, and it is not a synonym for `pending`. `pending` means the
 * job has not reached this host yet; `waiting` means the job has reached it and
 * is deliberately holding — behind the concurrency cap, or behind a gate. A UI
 * that cannot tell them apart shows fifteen identical rows and no answer to
 * "why has nothing started".
 */
export type JobHostState =
  | 'pending'
  | 'waiting'
  | 'running'
  | 'ok'
  | 'failed'
  | 'skipped'
  | 'detached'
  | 'orphaned'
  | 'rebooting'
  | 'foreign'

export const JOB_HOST_STATES: readonly JobHostState[] = [
  'pending',
  'waiting',
  'running',
  'ok',
  'failed',
  'skipped',
  'detached',
  'orphaned',
  'rebooting',
  'foreign'
]

/**
 * Still reserved by name only, after B2 took the other three.
 *
 * Empty, and kept rather than deleted: it is the list of states the store will
 * accept as strings without this build being able to write one, and the next
 * item that needs a state has to put it here first and then earn its way into
 * the union above by having a code path reach it. B1 wrote that rule down; B2
 * is the first thing to satisfy it, and `parked` is the candidate B4 will
 * argue for.
 */
export const RESERVED_JOB_HOST_STATES: readonly string[] = []

/**
 * States a host can be in while the work is still going.
 *
 * The distinction the job list needs and cannot derive: `ok`/`failed`/
 * `skipped`/`orphaned` are answers, and everything else is a host that has not
 * given one. `orphaned` is deliberately on the ANSWER side — "nobody will ever
 * know how this ended" is a terminal fact, not a pending one, and leaving it
 * open would keep a job running forever against a pid that no longer exists.
 */
export const JOB_HOST_LIVE_STATES: readonly JobHostState[] = [
  'pending',
  'waiting',
  'running',
  'detached',
  'rebooting',
  'foreign'
]

export function isJobHostLive(state: string): boolean {
  return (JOB_HOST_LIVE_STATES as readonly string[]).includes(state)
}

/**
 * What actually happened to one host, one level below `state`.
 *
 * Broadcast's seven, plus `abandoned`. That one is B1's honest name for the
 * case the attached path really has: ShellPilot stopped while this host was
 * running, so the channel went with it and the remote process was sent SIGHUP.
 * It is NOT `timeout` (we did not wait and give up), NOT `unreachable` (the
 * host was fine), and NOT `cancelled` (nobody asked for it). Filing it under
 * any of those three would be recording someone else's fault.
 *
 * B2 adds `orphaned`, which is the one honest answer the attached path could
 * never give: the marker directory survived, the wrapper's pid did not, and no
 * `rc` was ever written. The command may have completed its work and been
 * killed a microsecond before recording it, or it may have died a third of the
 * way through an upgrade. Filing that under `timeout` or `unreachable` would
 * claim to know which.
 */
export type JobHostOutcome = BroadcastHostOutcome | 'abandoned' | 'orphaned'

export const JOB_OUTCOME_LABEL: Record<JobHostOutcome, string> = {
  ok: 'ok',
  nonzero: 'non-zero exit',
  'missing-command': 'command not on this host',
  'permission-denied': 'permission denied',
  timeout: 'timed out',
  unreachable: 'unreachable',
  cancelled: 'not run',
  abandoned: 'abandoned when ShellPilot stopped',
  orphaned: 'ended without recording an exit status'
}

/**
 * The error text a host carries when the app stopped underneath it.
 *
 * Exported so the runner that writes it and the classifier that reads it
 * cannot drift — a regex matching a string literal typed in two places is a
 * bug waiting for someone to reword a sentence.
 */
export const JOB_ABANDONED_ERROR =
  'ShellPilot stopped while this host was running — the SSH channel closed and the remote ' +
  'command was sent SIGHUP. If it was a package operation, the host may need `dpkg --configure -a`.'

const ABANDONED = /ShellPilot stopped while/i

/**
 * Which category a finished host falls into.
 *
 * EXTENDS `classifyBroadcastResult` rather than restating it: everything about
 * missing commands, exit 126/127, permission refusals and the "non-zero is a
 * result" rule is settled there and is not re-litigated here. Two things are
 * added, both of which broadcast has no way to express:
 *
 *  1. `waiting` is not an answer, so it returns null the way `pending` and
 *     `running` do.
 *  2. An abandoned host is a `failed` whose error says the app stopped. Without
 *     this it would classify as `unreachable`, which points at the host — and
 *     the host did nothing wrong.
 */
export function classifyJobResult(r: JobHostResult): JobHostOutcome | null {
  // B2's live states are not answers either, for `waiting`'s reason. A
  // `detached` host is still working; a `rebooting` one is expected back; a
  // `foreign` one belongs to another instance and its answer will arrive from
  // its own marker. Returning an outcome for any of them would put a verdict
  // next to work that has not finished.
  if (r.state === 'waiting' || r.state === 'detached' || r.state === 'rebooting') return null
  if (r.state === 'foreign') return null
  if (r.state === 'orphaned') return 'orphaned'
  if (r.state === 'failed' && ABANDONED.test(r.error ?? '')) return 'abandoned'
  return classifyBroadcastResult(r as BroadcastHostResult)
}

/**
 * One host's row.
 *
 * Every field broadcast's `BroadcastHostResult` has, spelled identically, so
 * the renderer's existing result rendering can be pointed at a job without a
 * translation layer — and so `classifyJobResult` can hand a row straight to
 * `classifyBroadcastResult`. The extra fields are the ones only a PERSISTED
 * run needs: when it started and ended in wall-clock terms rather than a
 * duration, where it sits in the target order, and how much output was elided.
 */
export interface JobHostResult {
  serverId: string
  serverName: string
  state: JobHostState
  exitCode?: number
  stdout?: string
  stderr?: string
  error?: string
  ms?: number
  truncated?: boolean
  outcome?: JobHostOutcome
  /** Position in the target list, so a read-back preserves the order shown. */
  ord?: number
  startedAt?: number
  endedAt?: number
  /** Bytes of output persisted for this host. */
  outOffset?: number
  /** Bytes dropped from the MIDDLE of the output. See JOB_OUTPUT_HEAD. */
  outElided?: number
  /**
   * B2's marker handle, when this host's step was launched detached.
   *
   * Persisted on the row rather than held in memory, because the whole claim of
   * a detached job is that a ShellPilot which never saw it start can pick it
   * up. Null on every host that ran attached, which is how a reader tells the
   * two apart a month later.
   */
  detached?: JobDetachedHandle | null
  /**
   * Set when this host could not run detached and fell back to the attached
   * path, with the host's own reason.
   *
   * PER HOST, and surfaced rather than logged: an estate where one busybox
   * appliance has no setsid is an estate where fourteen hosts survive the lid
   * closing and one does not, and an operator who is not told which is the one
   * has been given a guarantee that is false for a host they cannot name.
   */
  degraded?: string
}

/** What a job is. Only `command` exists in B1; B4 adds staged kinds. */
export type JobKind = 'command'

export interface JobStep {
  command: string
  /** Per-host timeout for this step. Defaults to JOB_STEP_TIMEOUT_MS. */
  timeoutMs?: number
}

export interface JobSpec {
  kind: JobKind
  /** What the user called it. Shown in the list; never parsed. */
  title: string
  steps: JobStep[]
  /** Simultaneous hosts. Clamped by the runner; see JOB_CONCURRENCY. */
  concurrency?: number
}

/**
 * One host a job runs on.
 *
 * `cohort` is what makes `planJob` different from `planBroadcast`. Hosts in the
 * same cohort run together; cohorts run one after another. B1 puts every host
 * in one cohort, so the two plans agree — the field exists now because the
 * confirmation a job asks for is decided at plan time and persisted, and adding
 * cohorts in B4 must not change what an already-recorded approval meant.
 */
export interface JobTargetRef {
  serverId: string
  serverName: string
  cohort?: string
}

export interface JobPlan {
  risk: BroadcastRisk
  confirmation: BroadcastConfirmation
  reasons: string[]
  /** Hosts that will be in flight at once — what the confirmation was sized
   *  against. See planJob. */
  blastRadius: number
  /** Total hosts the job touches, which is NOT what sized the confirmation. */
  totalHosts: number
}

/**
 * The confirmation this job requires, and why.
 *
 * Two departures from `planBroadcast`, both of them the reason this function
 * exists rather than a call to that one:
 *
 *  1. **Risk is the MAXIMUM over the steps.** A job whose first step is
 *     `apt update` and whose second is `apt full-upgrade` is an upgrade. Taking
 *     the first step's risk, or the last one's, would let the dangerous half
 *     hide behind an ordinary neighbour.
 *
 *  2. **The host count is the LARGEST COHORT, not the total.** Blast radius is
 *     what is simultaneous. Fifty hosts rolled five at a time is five hosts
 *     broken before anyone can stop it; fifty at once is fifty. Sizing the
 *     confirmation on the total would demand the strongest confirmation for the
 *     careful, staged version of the same job — teaching people that rolling
 *     slowly costs them more friction, which is exactly backwards.
 *
 *     The total is still reported, because the dialog should say both.
 */
export function planJob(spec: JobSpec, targets: JobTargetRef[]): JobPlan {
  let risk: BroadcastRisk = 'ordinary'
  const reasons: string[] = []
  const order: BroadcastRisk[] = ['ordinary', 'elevated', 'destructive']
  for (const step of spec.steps) {
    const a = assessCommand(step.command)
    if (order.indexOf(a.risk) > order.indexOf(risk)) risk = a.risk
    // Deduped: two `rm -rf` steps are one reason, said once. The dialog is
    // read, and a repeated line reads as noise rather than as emphasis.
    for (const why of a.reasons) if (!reasons.includes(why)) reasons.push(why)
  }

  const perCohort = new Map<string, number>()
  for (const t of targets) {
    const key = t.cohort ?? ''
    perCohort.set(key, (perCohort.get(key) ?? 0) + 1)
  }
  const blastRadius = perCohort.size === 0 ? 0 : Math.max(...perCohort.values())

  return {
    risk,
    confirmation: confirmationFor(risk, blastRadius),
    reasons,
    blastRadius,
    totalHosts: targets.length
  }
}

// ------------------------------------------------------------------ records

/**
 * Where the job as a whole is.
 *
 * `abandoned` is a job-level state and not just a per-host outcome: a job that
 * was running when the app stopped did not finish, and calling it `done` would
 * put a tick next to work nobody knows the end of. It is set at adoption, by
 * the runner reading rows it did not write.
 */
export type JobState = 'queued' | 'running' | 'done' | 'cancelled' | 'abandoned'

/** The row, without the per-host detail. What a list renders. */
export interface JobRecord {
  id: string
  createdAt: number
  workspaceId: string | null
  title: string
  kind: JobKind
  spec: JobSpec
  risk: BroadcastRisk
  /** The confirmation the plan demanded, as it was demanded.
   *
   *  Recorded, not re-derived. B3 makes this a full approval record with who
   *  and when; persisting the demand now means a job read back after a restart
   *  can at least say what standard it was held to, rather than re-running
   *  today's classifier over yesterday's command and possibly getting a
   *  different answer. */
  confirmation: BroadcastConfirmation
  /** When the user satisfied that confirmation. B3 makes this authoritative. */
  confirmedAt: number | null
  state: JobState
  startedAt: number | null
  endedAt: number | null
  cancelledAt: number | null
}

/** A job and every host in it. What a detail view renders. */
export interface JobDetail extends JobRecord {
  targets: JobHostResult[]
}

export interface JobOutputLine {
  serverId: string
  seq: number
  at: number
  stream: 'out' | 'err'
  text: string
}

// ------------------------------------------------------------------- events

export interface JobProgress {
  jobId: string
  /** The job row, whenever the job's own state changed. */
  job?: JobRecord
  /** The host row, whenever a host's state changed. */
  host?: JobHostResult
  /** Set on the final event, so a listener never waits forever for a job that
   *  has already stopped. */
  done?: boolean
  cancelled?: boolean
}

export interface JobOutput {
  jobId: string
  serverId: string
  at: number
  stream: 'out' | 'err'
  /** One tick's worth of output, already joined. NOT one line — see
   *  JOB_OUTPUT_RATE_PER_SEC. */
  text: string
  /**
   * Chunks the rate limiter dropped since the last event for this host.
   *
   * Announced, never silent. logTail's model: a gap nobody mentions is how
   * someone concludes a command went quiet, and on a job that conclusion is
   * "the upgrade hung" rather than "the pane throttled".
   */
  dropped?: number
}

// -------------------------------------------------------------- the bridge

/**
 * The renderer-facing surface, as an interface rather than as whatever the
 * preload happens to define.
 *
 * The preload annotates its `jobs` object against this, so a handler added in
 * main and forgotten in the preload — or the reverse — is a compile error
 * instead of an `undefined is not a function` the first time someone presses
 * the button.
 */
export interface JobsBridge {
  list(limit?: number): Promise<JobRecord[]>
  get(jobId: string): Promise<JobDetail | null>
  run(req: JobRunRequest): Promise<JobDetail>
  cancel(jobId: string): Promise<boolean>
  /**
   * Turn detached execution on or off for this machine.
   *
   * Off yields B1's behaviour exactly — nothing is written to any host, and a
   * job that was running when ShellPilot stopped is `abandoned`. Pushed from
   * the renderer's settings the way `ssh.setPoolIdle` is, because that is where
   * the switch the user flicks lives; main holds the value and the executor
   * reads it per launch, so flipping it does not disturb a job already going.
   */
  setDetached(enabled: boolean): Promise<void>
  /** What each host was found capable of, for the row that says which hosts
   *  degraded and why. Empty until a job has probed a host. */
  capabilities(): Promise<JobHostCapabilityReport[]>
  onProgress(fn: (p: JobProgress) => void): () => void
  onOutput(fn: (o: JobOutput) => void): () => void
}

/** One host's answer to the capability probe, as the UI shows it. */
export interface JobHostCapabilityReport {
  serverId: string
  serverName: string
  at: number
  detached: boolean
  /** Null when detached; the host's own reason otherwise. */
  reason: string | null
  root: string | null
  launcher: JobLauncher
}

export interface JobRunRequest {
  jobId: string
  workspaceId?: string | null
  spec: JobSpec
  /** Satisfied at plan time in the renderer, where the user is. Persisted with
   *  the job so the record says what was asked of them. B3 moves the
   *  enforcement into main. */
  confirmedAt?: number
  targets: {
    serverId: string
    serverName: string
    cohort?: string
    cfg: unknown
  }[]
}

// ----------------------------------------------------------------- numbers

/** Simultaneous exec channels, for the same reason broadcast caps at three:
 *  fifteen hosts behind two bastions is fifteen channels through two machines
 *  an operator cannot afford to wobble. */
export const JOB_CONCURRENCY = 3

/** Per-host, per-step timeout. Longer than a broadcast's minute because a job
 *  is the thing you start BECAUSE it is long — and still finite, because the
 *  attached path cannot honestly promise more than it can hold a socket for. */
export const JOB_STEP_TIMEOUT_MS = 900_000

/** How long past the step timeout the runner waits on an executor that has not
 *  settled. Same reasoning as BROADCAST_STALL_GRACE_MS: `sshExec` starts its
 *  own timer only after the connection is acquired, so a connect that never
 *  completes is not covered by the timeout at all. */
export const JOB_STALL_GRACE_MS = 30_000

/**
 * Output kept per host: the first 64 KB and the last 192 KB.
 *
 * Broadcast keeps a 20 KB HEAD and calls it truncated. For a fan-out read
 * that is defensible; for a job it is wrong, and the runner already works
 * around it by classifying from the uncapped stream. The answer to "did the
 * upgrade work" is in the LAST twenty lines — `E: Sub-process
 * /usr/bin/dpkg returned an error code`, `Need to get 0 B`, the list of held
 * packages — and a prefix-only capture throws away exactly that, silently,
 * every time the output is long.
 *
 * So: head plus tail, with `out_elided` recording the bytes dropped from the
 * middle. The split is deliberately lopsided at 1:3.
 *
 *  - The head is 64 KB because what it has to hold is the START of the run:
 *    the command echo, the package list, the "the following NEW packages will
 *    be installed" block. A real `apt full-upgrade` on a Debian host with 200
 *    pending packages produces about 12–18 KB before the first download line,
 *    so 64 KB holds it with room for a preamble several times larger than the
 *    ones actually measured.
 *  - The tail is 192 KB because it has to hold the END plus whatever noisy
 *    thing preceded it. `dpkg` triggers, `update-initramfs`, kernel postinst
 *    and `needrestart` together run to roughly 40–90 KB on a machine that has
 *    not been upgraded in a while; 192 KB survives all of that and still has
 *    the error above it.
 *  - 256 KB total per host, so a fifteen-host estate upgrade is at most ~3.8 MB
 *    of output rows — an order of magnitude under the metric tier's steady
 *    state, and bounded per job rather than per hour.
 *
 * The middle is what goes, because the middle of an apt run is the download
 * progress: the least informative bytes in the file, and by far the most of
 * them.
 */
export const JOB_OUTPUT_HEAD = 64 * 1024
export const JOB_OUTPUT_TAIL = 192 * 1024
export const JOB_OUTPUT_CAP = JOB_OUTPUT_HEAD + JOB_OUTPUT_TAIL

/** The marker written where the elided middle was, so a reader of the stored
 *  output sees a gap rather than a seam. */
export function elisionNotice(bytes: number): string {
  return `\n… ${bytes} bytes elided from the middle of this host's output …\n`
}

/**
 * The marker written into the output where one step ends and the next begins.
 *
 * A row in the stream rather than a field somewhere else, for elisionNotice's
 * reason: a reader scrolling a host's output has to see the boundary WHERE it
 * is. Without it a three-step job is one undifferentiated wall of text and
 * "which step printed this" has no answer at all — and the head budget is per
 * host, so a chatty first step can consume the whole of it and leave the
 * boundary as the only evidence the later steps existed.
 *
 * Only written when there is more than one step: a marker above the only step
 * there is is noise.
 */
export function stepNotice(index: number, total: number, command: string): string {
  return `\n… step ${index} of ${total}: ${command} …\n`
}

/**
 * What the target row says about a step that did not exit zero.
 *
 * `result` is overwritten per step, so the row carries the LAST step's exit
 * code and nothing else. On step 2 of 3 failing that is an exit code with no
 * subject: nothing says which command produced it and nothing says step 3 was
 * never run. Both belong on the row, because the row is what survives the
 * 30-day output horizon by a factor of twelve.
 */
export function stepFailureNote(
  index: number,
  total: number,
  command: string,
  exitCode: number | null | undefined
): string {
  const what = exitCode === null || exitCode === undefined ? 'did not complete' : `exited ${exitCode}`
  // The steps that did not run are NAMED, not counted. "1 later step did not
  // run" makes a reader go back to the spec and count; "Step 3 did not run"
  // is the answer.
  const rest =
    index >= total
      ? ''
      : index + 1 === total
        ? ` Step ${total} did not run.`
        : ` Steps ${index + 1}–${total} did not run.`
  return `step ${index} of ${total} (\`${command}\`) ${what}.${rest}`
}

/**
 * Bytes of each stream kept purely to classify the host's result.
 *
 * The TAIL, not the head, for the reason the runner already gives: the shell's
 * "command not found" is the last thing on stderr, and a host that printed 20k
 * of warnings first would have had it cut off. A streaming executor hands its
 * output over and returns nothing, so without this the classifier would see an
 * empty stderr and call every failing command `nonzero`.
 */
export const JOB_CLASSIFY_BYTES = 8 * 1024

/**
 * How much of a partial last line is held back between chunks before it is
 * redacted.
 *
 * Redaction runs per chunk, and a socket boundary does not respect a regex:
 * `DB_PASSWORD=` ending one chunk and `hunter2` starting the next matches no
 * rule and both halves are written verbatim. Every pattern rule except the PEM
 * block is single-line, so joining at the line boundary closes the seam — and
 * holding only a PARTIAL line means output that ends at one is not delayed at
 * all, which is nearly all real output and keeps the live pane live.
 *
 * `\r` counts as a boundary as well as `\n`, so a progress bar redrawing in
 * place is not held either — it ends every redraw with one.
 *
 * The known cost, taken deliberately: a command that emits neither, such as a
 * prompt waiting on input, is delayed until it has produced this many bytes or
 * finished. The alternative is emitting a secret in two halves because the
 * kernel happened to split the read there, and a bounded delay on unterminated
 * output is the cheaper of the two.
 */
export const JOB_REDACT_LINE_CARRY = 4 * 1024

/**
 * How much of an unterminated PEM block is held back.
 *
 * The one rule that spans lines, so the line boundary above is not enough for
 * it — and it is the rule whose failure costs a private key rather than a
 * password. Capped for the same reason: a `-----BEGIN` with no `-----END`
 * behind it must not buffer a host's entire output.
 */
export const JOB_REDACT_BLOCK_CARRY = 64 * 1024

/**
 * Output chunks emitted to the renderer per host per second.
 *
 * Coalesced per tick like ssh.ts's interactive terminal, NOT per line like
 * logTail: `apt` writes a progress line per download and a job emitting one IPC
 * message each floods the renderer, and the user's conclusion is "ShellPilot
 * froze" rather than "that upgrade is chatty". The cap is on MESSAGES, so a
 * host that produces a megabyte in one tick still sends it — as one message.
 */
export const JOB_OUTPUT_RATE_PER_SEC = 20

// ---------------------------------------------------------------- retention

/**
 * How long a job's OUTPUT is kept: 30 days.
 *
 * Output cannot be downsampled the way a metric series can — there is no
 * hourly mean of a dpkg log, so the only honest options are keep it or drop
 * it. 30 days is the window in which "what did that upgrade actually say"
 * still gets asked: past a month the question people ask is "when did we last
 * run it and did it work", and that is answered by the rows below.
 *
 * Sized: 256 KB per host is the worst case above, a fifteen-host estate
 * upgraded weekly is ~15 MB a month of output at the cap, and real output is
 * far under it. That sits inside the store's existing budget rather than
 * next to it.
 */
export const JOB_OUTPUT_RETENTION_DAYS = 30

/**
 * How long the job and target ROWS are kept: 365 days.
 *
 * They are tiny — a job row is a title, a spec and five timestamps; a target
 * row is a state, an outcome and an exit code — and they are what a change log
 * reads. "This host was rebooted on the 14th, by this job, and exited 0" is
 * worth a year; the 200 KB of dpkg chatter behind it is not.
 *
 * Shipped in the same commit as the tables, deliberately, for the reason
 * written at the top of history.ts: a store that only gains a retention rule
 * after someone complains has already written the year of rows.
 */
export const JOB_RECORD_RETENTION_DAYS = 365

// ===========================================================================
// B2: detached execution
// ===========================================================================
//
// ---------------------------------------------------------------------------
// EXACTLY WHAT LANDS ON THE HOST, because an operator deserves the list
// ---------------------------------------------------------------------------
// One directory, and five small files inside it:
//
//   <root>/<jobId>.<step>/cmd       the command text, as the user typed it
//   <root>/<jobId>.<step>/instance  the id of the ShellPilot that launched it
//   <root>/<jobId>.<step>/pid       the wrapper's pid, written by the wrapper
//   <root>/<jobId>.<step>/pgid      its process group, for the cancel rule
//   <root>/<jobId>.<step>/out       the command's stdout and stderr, appended
//   <root>/<jobId>.<step>/rc        its exit status, written temp-then-renamed
//
// That is the whole of it. NO binary is copied, NO package is installed, NO
// service or timer or cron entry is created, and NOTHING runs after the command
// finishes. The directory is removed as soon as its `rc` has been read
// (`buildJobReap`), and any directory older than JOB_MARKER_SWEEP_DAYS whose
// pid is gone is removed by the capability probe at the next launch
// (`buildJobProbe`) — so a marker left behind by a laptop that never came back
// is cleaned up by the next job against that host rather than living forever.
//
// `rc` is written to `rc.tmp` and RENAMED, so its presence means it is
// complete. That is store.ts's discipline and it is here for store.ts's reason:
// a reader that can see a half-written status is a reader that will eventually
// act on one. rename(2) within a directory is atomic on every filesystem this
// runs on.
//
// The research behind this item established that the repository makes NO
// written "nothing is installed on your hosts" commitment anywhere, so this is
// a design judgement rather than a promise being broken — and it is why the
// Settings switch exists (JOB_DETACHED_SETTING_NOTE): an operator who wants
// nothing at all written keeps B1's attached behaviour, honestly labelled.
//
// ---------------------------------------------------------------------------
// WHY A DIRECTORY AND NOT A FIFO
// ---------------------------------------------------------------------------
// A FIFO blocks its WRITER when no reader is attached. On a job engine whose
// entire purpose is surviving the reader going away, that is not a limitation,
// it is the exact inversion of the requirement: closing the laptop would stop
// the upgrade at the first write past the pipe buffer. A regular file plus a
// byte offset gives an exact monotonic cursor and never blocks anything.
//
// ---------------------------------------------------------------------------
// WHY THE STATE DIRECTORY IS RESOLVED IN THAT ORDER
// ---------------------------------------------------------------------------
// `$XDG_STATE_HOME/shellpilot/jobs`, then `~/.local/state/shellpilot/jobs`,
// then `/var/tmp/shellpilot-$(id -u)/jobs`. State, not cache and not runtime:
// this outlives a login by design. `$HOME` is tried before `/var/tmp` because
// it is the user's own and is where an operator would look; `/var/tmp` is the
// fallback because `$HOME` may be read-only (immutable images), full (quota),
// or on an autofs mount that is not there at boot. `/tmp` is deliberately NOT
// in the list: it is tmpfs on most modern distributions and is cleared at
// reboot, and "the marker vanished" would be indistinguishable from "the job
// never ran" in exactly the case — a host that rebooted — where the difference
// is the whole answer.

/**
 * Why the launching instance is recorded, and what happens when it is not us.
 *
 * DETECT AND DEGRADE, DO NOT LOCK. Two ShellPilots against one estate is a
 * real configuration — a laptop and a desktop, or one person and their
 * colleague — and a lock file would turn that into a job neither of them can
 * read. So:
 *
 *  - READS ARE ALWAYS ALLOWED. Anyone who can see the marker can follow the
 *    output and learn the exit status. Information is not the dangerous part.
 *  - CANCEL IS IDEMPOTENT and is not gated on the instance. `kill -TERM` on a
 *    process group that is already gone is a no-op, and refusing to let the
 *    person in front of the machine stop an upgrade because a different app
 *    started it would be the wrong failure by a wide margin.
 *  - REAP IS REFUSED for a foreign instance, and the host is reported in the
 *    `foreign` state. Deleting the directory is the one operation that
 *    destroys something another reader still needs.
 */
export const JOB_INSTANCE_NOTE =
  'This job was launched by a different ShellPilot instance. Its output and exit status are ' +
  'readable here and it can still be cancelled; its marker directory is left in place for the ' +
  'instance that started it.'

/** What the Settings switch turns off, spelled once so main and the UI agree. */
export const JOB_DETACHED_SETTING_NOTE =
  'Detached jobs write one directory with five small files under your own state directory on ' +
  'each host, so a job survives the connection dropping. Nothing is installed and nothing runs ' +
  'after the job. With this off, jobs run on the attached path: closing the lid mid-upgrade ' +
  'sends SIGHUP to the remote command, and apt and dpkg do not ignore it.'

/** The three candidate roots, in resolution order. Documentation for the UI;
 *  the shell in `buildJobProbe` is what actually decides. */
export const JOB_STATE_ROOTS: readonly string[] = [
  '$XDG_STATE_HOME/shellpilot/jobs',
  '$HOME/.local/state/shellpilot/jobs',
  '/var/tmp/shellpilot-$(id -u)/jobs'
]

// ------------------------------------------------------------------ numbers

/**
 * How often a healthy detached job is polled: every 3 seconds.
 *
 * Slower than a terminal and much faster than the fleet sampler, because what
 * it costs is one short exec on a pooled connection and what it buys is a
 * live-looking pane on work that can run for an hour. It is not a heartbeat:
 * missing a poll costs nothing at all, since the next one reads from the same
 * byte offset.
 */
export const JOB_POLL_MS = 3_000

/**
 * Bytes of output a single poll may carry: 96 KB.
 *
 * `sshExec` stops appending at 200 KB and drops the rest, and the poll body is
 * base64 where the host has it — 96 KB of output is 128 KB on the wire, which
 * leaves room for the header and stays clear of the cap. A poll that finds more
 * than this waiting says so (`more`), and the poller reads again immediately
 * rather than waiting for the next tick, so a chatty job is drained at
 * connection speed rather than at 96 KB per 3 seconds.
 */
export const JOB_POLL_BYTES = 96 * 1024

/**
 * How long after a launch the wrapper has to write its `pid` before the marker
 * is called a failed launch rather than a slow one: 30 seconds.
 *
 * The launch command returns as soon as the background process is started, and
 * the wrapper writes `pid` as its own first act. On a loaded host that is still
 * a few hundred milliseconds. 30 seconds is far past any of it and is short
 * enough that a launch which genuinely did not take is reported while the
 * operator is still watching.
 */
export const JOB_LAUNCH_GRACE_MS = 30_000

/** Reconnect backoff: first retry at 2s, doubling, capped at 60s. */
export const JOB_RECONNECT_BASE_MS = 2_000
export const JOB_RECONNECT_MAX_MS = 60_000

/**
 * How many hosts may be attempting a reconnect at once, across the whole app.
 *
 * The case this exists for is a laptop waking up: fifteen detached jobs all
 * notice the link at the same instant and all dial the same bastion in the same
 * millisecond. Per-host backoff does not help — they are synchronised by the
 * wake, not by each other — so the cap is GLOBAL, and it is three for the
 * reason JOB_CONCURRENCY is three: fifteen channels through two machines an
 * operator cannot afford to wobble.
 */
export const JOB_RECONNECT_GLOBAL_MAX = 3

/** Marker directories older than this whose pid is gone are swept at the next
 *  probe. Long enough that a laptop away for a working week still finds its own
 *  job's output; short enough that nothing accumulates. */
export const JOB_MARKER_SWEEP_DAYS = 7

/**
 * How long the runner waits on a detached executor that has not settled.
 *
 * JOB_STALL_GRACE_MS (30s) is sized for the attached path, where the executor's
 * own timer is the only thing between a hung connect and a worker that waits
 * forever. A detached executor deliberately outlives a dropped link, so its
 * worst honest case is one full reconnect backoff plus a poll — and a 30-second
 * grace would kill it in the middle of exactly the recovery it exists to
 * perform.
 */
export const JOB_DETACHED_STALL_GRACE_MS = JOB_RECONNECT_MAX_MS * 2 + JOB_POLL_MS

// ------------------------------------------------------------ shell plumbing

/**
 * Every wrapper command starts with these two assignments.
 *
 * They are real shell — the script below uses both — and they are also the
 * CONTRACT the test fake reads. `tests/jobDetached.test.ts` drives a virtual
 * marker directory by parsing this prefix out of the command the builders
 * produce, which means a change to the wrapper that the fake has not been
 * taught about fails loudly rather than being quietly simulated against the
 * old shape.
 */
export const JOB_CMD_PREFIX = /^SP_JOB_VERB=([a-z]+); SP_JOB_DIR=('(?:[^']|'\\'')*'|auto);/

export type JobVerb = 'probe' | 'launch' | 'poll' | 'signal' | 'reap'

/** Single-quote for `sh`. The only character that cannot appear inside single
 *  quotes is the single quote, which is closed, escaped and reopened. */
export function shQuote(s: string): string {
  return `'${s.split("'").join(`'\\''`)}'`
}

/**
 * Ids that may be used to build a path on a remote host.
 *
 * Job ids and instance ids are minted by ShellPilot and are already uuid-like,
 * so this rejects nothing real. It exists because the alternative — trusting
 * that — is one refactor away from a caller passing something with a `/` or a
 * `..` in it, and the marker root is a directory this code creates and deletes
 * recursively.
 */
const SAFE_ID = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/

export function assertSafeJobId(id: string, what: string): void {
  if (!SAFE_ID.test(id) || id.includes('..')) {
    throw new Error(`${what} must be a plain identifier, got ${JSON.stringify(id)}`)
  }
}

/** The marker directory for one step of one job. One directory per step rather
 *  than per job: `out`, `pid` and `rc` describe a single process, and a second
 *  step appending to the first one's `out` would make the byte cursor mean two
 *  different things. */
export function jobMarkerDir(root: string, jobId: string, step: number): string {
  assertSafeJobId(jobId, 'a job id')
  if (!Number.isInteger(step) || step < 1 || step > 999) {
    throw new Error(`a step index must be 1-999, got ${step}`)
  }
  return `${root.replace(/\/+$/, '')}/${jobId}.${step}`
}

// ----------------------------------------------------------------- the probe

export type JobLauncher = 'setsid' | 'nohup' | 'none'

export interface JobHostCapability {
  /** The writable state directory this host resolved to, or null if none of
   *  the three candidates could be created and written. */
  root: string | null
  launcher: JobLauncher
  /** `base64` is present, so poll bodies come back byte-exact. See parseJobPoll. */
  base64: boolean
  uid: number | null
  /** True when a detached launch is possible at all on this host. */
  ok: boolean
  /** Why not, in a sentence a person can act on. Null when `ok`. */
  reason: string | null
}

/**
 * Ask a host whether it can run a detached job, and sweep old markers.
 *
 * Two jobs in one command because both are once-per-host-per-launch and the
 * expensive part is the round trip, not the work. The sweep is deliberately
 * conservative: it removes only directories older than JOB_MARKER_SWEEP_DAYS
 * whose recorded pid is no longer alive, so a genuinely long job belonging to
 * anybody — including another instance — is never swept out from under its
 * reader.
 *
 * `setsid` is util-linux and is absent from some busybox builds, so `nohup` is
 * the fallback. It is a weaker guarantee and the difference is recorded rather
 * than smoothed over: setsid puts the command in its own SESSION, so it has no
 * controlling terminal to be hung up and its process group can be signalled as
 * a unit; nohup only sets SIGHUP to ignore in the one process it starts. See
 * buildJobSignal for what that costs at cancel time.
 */
export function buildJobProbe(opts: { sweepDays?: number } = {}): string {
  const days = Math.max(1, Math.round(opts.sweepDays ?? JOB_MARKER_SWEEP_DAYS))
  return [
    'SP_JOB_VERB=probe; SP_JOB_DIR=auto;',
    // A function rather than a `for` over an unquoted list: a $HOME with a
    // space in it would word-split, and the failure would be creating two
    // directories with half a path each.
    'sp_try() { [ -n "$1" ] || return 1; mkdir -p "$1" 2>/dev/null || return 1; [ -w "$1" ] || return 1; SP_ROOT=$1; return 0; };',
    'SP_ROOT=;',
    // ${VAR:+...} expands to NOTHING when the variable is unset or empty, so an
    // unset XDG_STATE_HOME cannot resolve to "/shellpilot/jobs" — which as root
    // would create a directory at the filesystem root.
    'sp_try "${XDG_STATE_HOME:+$XDG_STATE_HOME/shellpilot/jobs}" || sp_try "${HOME:+$HOME/.local/state/shellpilot/jobs}" || sp_try "/var/tmp/shellpilot-$(id -u 2>/dev/null)/jobs" || SP_ROOT=;',
    'SP_LAUNCH=none;',
    'if command -v setsid >/dev/null 2>&1; then SP_LAUNCH=setsid; elif command -v nohup >/dev/null 2>&1; then SP_LAUNCH=nohup; fi;',
    'SP_B64=no;',
    'if printf x | base64 >/dev/null 2>&1; then SP_B64=yes; fi;',
    // The sweep. `find -maxdepth 0 -mtime +N` on the directory itself asks one
    // question about one path and prints nothing when the answer is no.
    `if [ -n "$SP_ROOT" ]; then for d in "$SP_ROOT"/*; do [ -d "$d" ] || continue; [ -n "$(find "$d" -maxdepth 0 -mtime +${days} 2>/dev/null)" ] || continue; p=$(cat "$d/pid" 2>/dev/null); if [ -n "$p" ] && kill -0 "$p" 2>/dev/null; then continue; fi; rm -rf "$d"; done; fi;`,
    "echo 'shellpilot-probe/1';",
    'echo "launcher=$SP_LAUNCH";',
    'echo "base64=$SP_B64";',
    'echo "uid=$(id -u 2>/dev/null)";',
    // Last, and read as "everything after the first =", so a root containing a
    // space or an equals sign survives the round trip.
    'echo "root=$SP_ROOT"'
  ].join(' ')
}

export function parseJobProbe(stdout: string): JobHostCapability {
  const fields = headerFields(stdout)
  const root = fields.get('root') || null
  const launcherRaw = fields.get('launcher') ?? 'none'
  const launcher: JobLauncher =
    launcherRaw === 'setsid' ? 'setsid' : launcherRaw === 'nohup' ? 'nohup' : 'none'
  const uidRaw = fields.get('uid')
  const uid = uidRaw !== undefined && /^\d+$/.test(uidRaw) ? Number(uidRaw) : null
  const base64 = fields.get('base64') === 'yes'
  const signed = stdout.includes('shellpilot-probe/1')
  let reason: string | null = null
  if (!signed) {
    reason =
      'the capability probe produced nothing this build understands — the remote shell may not ' +
      'be a POSIX sh'
  } else if (root === null) {
    reason =
      'none of ' +
      JOB_STATE_ROOTS.join(', ') +
      ' could be created and written, so there is nowhere to keep a job marker'
  } else if (launcher === 'none') {
    reason = 'neither setsid nor nohup is installed, so a command cannot be detached from the channel'
  }
  return { root, launcher, base64, uid, ok: reason === null, reason }
}

// ---------------------------------------------------------------- the launch

export interface JobLaunchSpec {
  dir: string
  jobId: string
  instanceId: string
  command: string
  launcher: 'setsid' | 'nohup'
}

export interface JobLaunchResult {
  ok: boolean
  /** Why the launch did not take, from the host's own mouth. */
  error: string | null
}

/**
 * Start the command detached, and close the channel.
 *
 * Four details, each of which is the difference between this working and this
 * looking like it works:
 *
 *  1. THE COMMAND IS WRITTEN TO A FILE and run as `sh cmd`. Nothing has to
 *     survive two levels of shell quoting, so a command containing quotes,
 *     newlines or `$` reaches the host exactly as the user typed it. The
 *     heredoc delimiter carries the job id, and a command that somehow
 *     contains that line is refused at build time rather than silently
 *     truncated.
 *  2. ALL THREE STANDARD STREAMS ARE REDIRECTED. An exec channel does not
 *     close while a background process still holds its stdout, so without
 *     this the "detached" launch would keep the very channel it is supposed
 *     to be free of, and the whole thing would behave like the attached path
 *     with extra steps.
 *  3. THE WRAPPER WRITES ITS OWN PID, rather than the launcher echoing `$!`.
 *     `setsid` forks when its caller is already a process group leader and
 *     execs when it is not, so `$!` is the right pid in one case and the pid
 *     of an already-exited parent in the other. `$$` inside the wrapper is
 *     always the process that is actually running the command.
 *  4. `rc` IS WRITTEN TEMP-THEN-RENAMED. Its presence means it is complete.
 */
export function buildJobLaunch(spec: JobLaunchSpec): string {
  assertSafeJobId(spec.jobId, 'a job id')
  assertSafeJobId(spec.instanceId, 'an instance id')
  const eof = `SPJOB_${spec.jobId.replace(/[^A-Za-z0-9]/g, '_')}_EOF`
  if (spec.command.split('\n').some((l) => l.trim() === eof)) {
    throw new Error('the command contains this job\u2019s heredoc delimiter and cannot be launched')
  }
  const d = shQuote(spec.dir)
  // The wrapper, as one single-quoted argument to `sh -c`. `$1` is the marker
  // directory, passed as an argument so this string contains no interpolation
  // at all.
  const wrapper =
    'printf "%s\\n" "$$" > "$1/pid.tmp" && mv "$1/pid.tmp" "$1/pid"; ' +
    // `ps -o pgid=` is POSIX. The value is what buildJobSignal compares against
    // the pid before it dares signal a whole process group.
    'ps -o pgid= -p $$ 2>/dev/null | tr -d " " > "$1/pgid.tmp" && mv "$1/pgid.tmp" "$1/pgid"; ' +
    'sh "$1/cmd" >> "$1/out" 2>&1; ' +
    'printf "%s\\n" "$?" > "$1/rc.tmp"; mv "$1/rc.tmp" "$1/rc"'
  return [
    `SP_JOB_VERB=launch; SP_JOB_DIR=${d};`,
    'mkdir -p "$SP_JOB_DIR" || { echo "shellpilot-launch/1"; echo "error=cannot create the marker directory"; exit 0; };',
    `cat > "$SP_JOB_DIR/cmd" <<'${eof}'\n${spec.command}\n${eof}\n`,
    `printf '%s\\n' ${shQuote(spec.instanceId)} > "$SP_JOB_DIR/instance";`,
    ': > "$SP_JOB_DIR/out";',
    `${spec.launcher} sh -c ${shQuote(wrapper)} sh "$SP_JOB_DIR" </dev/null >/dev/null 2>&1 &`,
    'echo "shellpilot-launch/1"; echo "error="'
  ].join(' ')
}

export function parseJobLaunch(stdout: string): JobLaunchResult {
  if (!stdout.includes('shellpilot-launch/1')) {
    return {
      ok: false,
      error: 'the launch produced nothing this build understands — the remote shell may not be a POSIX sh'
    }
  }
  const err = headerFields(stdout).get('error') || null
  return { ok: err === null, error: err }
}

// ------------------------------------------------------------------ the poll

export interface JobPollResult {
  /** False when the marker directory is not there at all. */
  present: boolean
  instance: string | null
  pid: number | null
  pgid: number | null
  /** The recorded exit status. Present means the job is over, because `rc` is
   *  renamed into place. */
  rc: number | null
  alive: boolean
  /**
   * How `alive` was decided. `strong` means the pid is running AND its argument
   * list still names this marker directory; `weak` means only `kill -0`
   * answered, because the host has no usable `ps`.
   *
   * The difference matters exactly once and it matters a lot: after a reboot
   * the recorded pid is very likely to have been reused by an unrelated
   * process, and a `weak` check would report that stranger as our job — and
   * then, on cancel, signal it.
   */
  pidCheck: 'strong' | 'weak'
  /** Bytes in `out` at the moment the poll read it. */
  size: number
  /** Bytes this poll carried. The cursor advances by exactly this. */
  sent: number
  /** More output was waiting than one poll may carry. */
  more: boolean
  /** The output itself, already decoded. */
  text: string
}

export function buildJobPoll(p: {
  dir: string
  offset: number
  maxBytes?: number
  base64: boolean
}): string {
  const max = Math.max(1, Math.floor(p.maxBytes ?? JOB_POLL_BYTES))
  const off = Math.max(0, Math.floor(p.offset))
  const body = p.base64
    ? 'tail -c +$((SP_JOB_OFF + 1)) "$SP_JOB_DIR/out" 2>/dev/null | head -c "$SP_N" | base64 | tr -d "\\n"'
    : 'tail -c +$((SP_JOB_OFF + 1)) "$SP_JOB_DIR/out" 2>/dev/null | head -c "$SP_N"'
  return [
    `SP_JOB_VERB=poll; SP_JOB_DIR=${shQuote(p.dir)}; SP_JOB_OFF=${off}; SP_JOB_MAX=${max};`,
    'echo "shellpilot-poll/1";',
    'if [ ! -d "$SP_JOB_DIR" ]; then echo "marker=missing"; echo "body/1"; exit 0; fi;',
    'echo "marker=present";',
    'echo "instance=$(head -n1 "$SP_JOB_DIR/instance" 2>/dev/null)";',
    'SP_PID=$(head -n1 "$SP_JOB_DIR/pid" 2>/dev/null); SP_PGID=$(head -n1 "$SP_JOB_DIR/pgid" 2>/dev/null);',
    'echo "pid=$SP_PID"; echo "pgid=$SP_PGID";',
    // rc IS READ BEFORE THE OUTPUT, and the order is the whole argument for
    // this poll being complete. `rc` exists only after the command has exited,
    // so if it is there before we read `out`, nothing can append to `out`
    // afterwards and what we read is all of it. Reading rc last would leave a
    // window where the final lines were written between the two reads and
    // reported as finished without them — and there is no later poll to catch
    // up, because a poll that sees rc is the last one.
    'if [ -f "$SP_JOB_DIR/rc" ]; then echo "rc=$(head -n1 "$SP_JOB_DIR/rc" 2>/dev/null)"; else echo "rc="; fi;',
    'SP_ALIVE=no; SP_CHECK=weak;',
    'if [ -n "$SP_PID" ] && kill -0 "$SP_PID" 2>/dev/null; then SP_ALIVE=yes; fi;',
    // The strong check: the pid is only ours if its argument list still names
    // this marker directory, which the wrapper carries because the directory is
    // passed to it as an argument.
    'if [ -n "$SP_PID" ] && SP_ARGS=$(ps -o args= -p "$SP_PID" 2>/dev/null); then SP_CHECK=strong; if printf "%s" "$SP_ARGS" | grep -qF -- "$SP_JOB_DIR"; then SP_ALIVE=yes; else SP_ALIVE=no; fi; fi;',
    'echo "alive=$SP_ALIVE"; echo "pidcheck=$SP_CHECK";',
    'SP_SIZE=$(wc -c < "$SP_JOB_DIR/out" 2>/dev/null | tr -dc "0-9"); [ -n "$SP_SIZE" ] || SP_SIZE=0;',
    'echo "size=$SP_SIZE";',
    // The window is closed on the HOST, not by counting what arrived: `wc -c`
    // and `tail` are two reads of a file the job is still appending to, so a
    // reader that trusted the byte count of what it received would re-send the
    // overlap at the next poll and duplicate it in the record.
    'SP_N=$((SP_SIZE - SP_JOB_OFF)); [ "$SP_N" -gt 0 ] 2>/dev/null || SP_N=0; if [ "$SP_N" -gt "$SP_JOB_MAX" ]; then SP_N=$SP_JOB_MAX; fi;',
    'echo "sent=$SP_N";',
    'echo "body/1";',
    `if [ "$SP_N" -gt 0 ]; then ${body}; fi;`,
    'exit 0'
  ].join(' ')
}

/**
 * Read one poll.
 *
 * The body is separated from the header by a `body/1` line and is taken as
 * everything after the FIRST one, so output that happens to contain that line
 * is not a problem — the header is over by then either way.
 *
 * `carry` is the price of a byte-exact cursor. The window is closed in bytes on
 * the host, so it can end in the middle of a UTF-8 sequence; decoding each poll
 * on its own would put a replacement character on both sides of every such
 * boundary. The trailing incomplete sequence is therefore held back as BYTES
 * and prepended to the next poll's body. Where the host has no `base64` the
 * body has already been decoded by the transport and this cannot be done, which
 * is why the probe records it: `sent` still advances exactly, so nothing is
 * lost or repeated, but a multi-byte character split across a poll boundary is
 * rendered as a replacement character. That is a cosmetic cost on hosts without
 * coreutils or busybox base64, taken deliberately over a cursor that drifts.
 */
export function parseJobPoll(
  stdout: string,
  opts: { base64: boolean; carry?: Buffer } = { base64: true }
): JobPollResult & { carry: Buffer } {
  const cut = stdout.indexOf('body/1')
  const head = cut < 0 ? stdout : stdout.slice(0, cut)
  const rawBody = cut < 0 ? '' : stdout.slice(cut + 'body/1'.length).replace(/^\r?\n?/, '')
  const f = headerFields(head)
  const num = (k: string): number | null => {
    const v = f.get(k)
    return v !== undefined && /^\d+$/.test(v) ? Number(v) : null
  }
  const sent = num('sent') ?? 0
  const size = num('size') ?? 0

  let text = ''
  let carry = Buffer.alloc(0)
  if (opts.base64) {
    // `tr -d` already removed the newlines base64 wraps at; anything else that
    // is not base64 alphabet is dropped rather than throwing, because a poll
    // whose body is slightly odd should cost one chunk of output and not the
    // whole job.
    const bytes = Buffer.from(rawBody.replace(/[^A-Za-z0-9+/=]/g, ''), 'base64')
    const joined = opts.carry && opts.carry.length > 0 ? Buffer.concat([opts.carry, bytes]) : bytes
    const keep = incompleteUtf8Tail(joined)
    carry = keep > 0 ? joined.subarray(joined.length - keep) : Buffer.alloc(0)
    text = joined.subarray(0, joined.length - keep).toString('utf8')
  } else {
    text = rawBody
  }

  return {
    present: f.get('marker') === 'present',
    instance: f.get('instance') || null,
    pid: num('pid'),
    pgid: num('pgid'),
    rc: num('rc'),
    alive: f.get('alive') === 'yes',
    pidCheck: f.get('pidcheck') === 'strong' ? 'strong' : 'weak',
    size,
    sent,
    more: size > 0 && sent > 0 && size - sent > 0 && sent >= JOB_POLL_BYTES,
    text,
    carry
  }
}

/**
 * Bytes at the end of `buf` that are the start of a UTF-8 sequence but not all
 * of it. Never more than three, and zero for a buffer that ends cleanly.
 */
function incompleteUtf8Tail(buf: Buffer): number {
  for (let back = 1; back <= 3 && back <= buf.length; back++) {
    const b = buf[buf.length - back]
    if ((b & 0xc0) === 0x80) continue // continuation byte; keep walking back
    const need = b >= 0xf0 ? 4 : b >= 0xe0 ? 3 : b >= 0xc0 ? 2 : 1
    return need > back ? back : 0
  }
  return 0
}

// ---------------------------------------------------- what the poll means

export type JobPollPhase =
  | 'starting'
  | 'running'
  | 'finished'
  | 'orphaned'
  | 'missing'
  | 'failed-launch'

export interface JobPollVerdict {
  phase: JobPollPhase
  /** The marker belongs to another ShellPilot. Reads and cancel are fine; reap
   *  is not. See JOB_INSTANCE_NOTE. */
  foreign: boolean
}

/**
 * The three-way reclaim, plus the two cases a three-way answer cannot express.
 *
 *   rc present                      -> finished. The status is the answer.
 *   rc absent, pid alive            -> running.
 *   rc absent, pid gone             -> ORPHANED. The wrapper died without
 *                                      recording anything: the OOM killer,
 *                                      `kill -9`, or the host going down.
 *
 * And the two:
 *
 *   the directory is not there      -> missing. Either it was reaped by
 *                                      somebody, or this is a host that never
 *                                      ran the job.
 *   no pid yet, launched moments ago-> starting. The wrapper writes `pid` as
 *                                      its first act, so this window is
 *                                      milliseconds; past JOB_LAUNCH_GRACE_MS
 *                                      it becomes `failed-launch`, which is a
 *                                      different fact from `orphaned` — the
 *                                      command never began.
 *
 * `rc` is checked FIRST and unconditionally. A wrapper that has exited has no
 * live pid by definition, so an implementation that asked "is it alive" first
 * would report every finished job as orphaned.
 */
export function classifyJobPoll(
  poll: JobPollResult,
  ctx: { instanceId: string; launchedAt: number; now: number; graceMs?: number }
): JobPollVerdict {
  const foreign = poll.instance !== null && poll.instance !== ctx.instanceId
  if (!poll.present) return { phase: 'missing', foreign: false }
  if (poll.rc !== null) return { phase: 'finished', foreign }
  if (poll.pid === null) {
    const grace = ctx.graceMs ?? JOB_LAUNCH_GRACE_MS
    return { phase: ctx.now - ctx.launchedAt <= grace ? 'starting' : 'failed-launch', foreign }
  }
  if (poll.alive) return { phase: 'running', foreign }
  return { phase: 'orphaned', foreign }
}

// ---------------------------------------------------------------- the signal

/**
 * Stop a detached job.
 *
 * IDEMPOTENT BY CONSTRUCTION: signalling a pid that is gone is a no-op that
 * reports success, which is what lets cancel be pressed twice, or by a second
 * ShellPilot, without anything having to hold a lock.
 *
 * THE GROUP IS ONLY SIGNALLED WHEN THE WRAPPER IS ITS OWN GROUP LEADER, i.e.
 * when the recorded pgid equals the recorded pid. Under `setsid` that is always
 * true and the whole group goes — which is what a package operation needs,
 * because `apt` is a parent and `dpkg` is where the work is. Under the `nohup`
 * fallback the wrapper sits in the login shell's process group, and
 * `kill -TERM -<pgid>` would signal that shell and everything else in it. So
 * the fallback signals the one process and says so; a child that outlives its
 * parent there is a real limitation of the fallback and not something to paper
 * over.
 *
 * THE PID IS VERIFIED BEFORE IT IS SIGNALLED, by the same argument-list check
 * the poll uses. A recorded pid on a host that has since rebooted is very
 * likely to belong to somebody else's process, and "ShellPilot sent SIGTERM to
 * an unrelated pid" is the one bug in this file that could not be undone.
 */
export function buildJobSignal(p: { dir: string; signal?: 'TERM' | 'KILL' }): string {
  const sig = p.signal === 'KILL' ? 'KILL' : 'TERM'
  return [
    `SP_JOB_VERB=signal; SP_JOB_DIR=${shQuote(p.dir)}; SP_JOB_SIG=${sig};`,
    'echo "shellpilot-signal/1";',
    'SP_PID=$(head -n1 "$SP_JOB_DIR/pid" 2>/dev/null); SP_PGID=$(head -n1 "$SP_JOB_DIR/pgid" 2>/dev/null);',
    'if [ -z "$SP_PID" ]; then echo "signalled=none"; exit 0; fi;',
    'SP_ARGS=$(ps -o args= -p "$SP_PID" 2>/dev/null) || SP_ARGS=;',
    'if [ -n "$SP_ARGS" ] && ! printf "%s" "$SP_ARGS" | grep -qF -- "$SP_JOB_DIR"; then echo "signalled=stale"; exit 0; fi;',
    `if [ -n "$SP_PGID" ] && [ "$SP_PID" = "$SP_PGID" ] && [ "$SP_PID" -gt 1 ] 2>/dev/null; then kill -${sig} -- "-$SP_PID" 2>/dev/null; echo "signalled=group"; else kill -${sig} "$SP_PID" 2>/dev/null; echo "signalled=process"; fi;`,
    'exit 0'
  ].join(' ')
}

export type JobSignalOutcome = 'group' | 'process' | 'none' | 'stale' | 'unknown'

export function parseJobSignal(stdout: string): JobSignalOutcome {
  const v = headerFields(stdout).get('signalled')
  return v === 'group' || v === 'process' || v === 'none' || v === 'stale' ? v : 'unknown'
}

// ------------------------------------------------------------------ the reap

/**
 * Remove the marker directory.
 *
 * Called once the exit status has been READ AND PERSISTED, never before: the
 * directory is the only copy of the answer until it is in the store, and a reap
 * that ran first would turn a completed upgrade into `missing`.
 *
 * The instance check is made by the CALLER, not here, and deliberately: this
 * builder is also what a future "clean up this host" action would use, and a
 * refusal that lives in the shell would have to be worked around rather than
 * decided.
 */
export function buildJobReap(p: { dir: string }): string {
  return [
    `SP_JOB_VERB=reap; SP_JOB_DIR=${shQuote(p.dir)};`,
    'rm -rf "$SP_JOB_DIR" 2>/dev/null;',
    'if [ -d "$SP_JOB_DIR" ]; then echo "shellpilot-reap/1"; echo "reaped=no"; else echo "shellpilot-reap/1"; echo "reaped=yes"; fi'
  ].join(' ')
}

export function parseJobReap(stdout: string): boolean {
  return headerFields(stdout).get('reaped') === 'yes'
}

// -------------------------------------------------------- reconnect backoff

/**
 * How long to wait before the next reconnect attempt.
 *
 * Equal jitter: half the window is fixed and half is random, so retries spread
 * out without any host being able to retry immediately in a tight loop. Full
 * jitter would allow a 1ms retry after a 60s wait, which on a bastion that has
 * just come back is the stampede this is here to prevent; no jitter at all
 * synchronises every host that dropped at the same moment — which, when the
 * cause is a laptop lid, is all of them.
 *
 * `rand` is injected so the test suite asserts the schedule rather than
 * sampling it.
 */
export function nextRetryDelay(
  attempt: number,
  rand: () => number = Math.random,
  o: { baseMs?: number; maxMs?: number } = {}
): number {
  const base = o.baseMs ?? JOB_RECONNECT_BASE_MS
  const max = o.maxMs ?? JOB_RECONNECT_MAX_MS
  const n = Math.max(1, Math.floor(attempt))
  // Shift rather than Math.pow, and clamped before it is used: attempt 40 would
  // otherwise be Infinity, and Infinity * 0.5 is still Infinity.
  const window = Math.min(max, base * 2 ** Math.min(n - 1, 30))
  const half = window / 2
  return Math.round(half + rand() * half)
}

// ------------------------------------------------------- the expected reboot

/**
 * Does this command restart the machine?
 *
 * The roadmap's example of a state today's vocabulary gets backwards: a host
 * that stops answering because the job asked it to reboot is reported
 * `unreachable`, which reads as a fault and is the opposite of the truth.
 *
 * These two patterns are broadcast.ts's, deliberately duplicated rather than
 * imported, because there they are RISK rules — one entry in a list whose
 * output is a confirmation dialog — and here the question is a different one
 * with a different consequence. `tests/jobDetached.test.ts` asserts the two
 * agree, so a command this calls a restart that broadcast does not call
 * destructive is a test failure rather than a slow divergence.
 *
 * Anchored at a command start for broadcast's reason, which is worth repeating
 * because it is the whole reason the rule is not a substring search: without
 * the anchor, `grep reboot /var/log/syslog` is "restarts the machine", and a
 * guard that cries wolf on a read-only grep is a guard nobody reads.
 */
const RESTARTS = [
  /(^|[;&|(]|\n)\s*(?:\w+=\S+\s+)*(?:sudo\s+|doas\s+)?(?:shutdown|poweroff|halt|reboot)\b/,
  /(^|[;&|(]|\n)\s*(?:sudo\s+|doas\s+)?systemctl\s+(?:poweroff|reboot|halt|kexec)\b/
]

export function restartsTheMachine(command: string): boolean {
  return RESTARTS.some((rx) => rx.test(command))
}

// ------------------------------------------------------------------ helpers

/** `key=value` lines, first `=` wins, later keys overwrite earlier ones. Values
 *  may contain anything but a newline — which is why `root=` is emitted last by
 *  the probe and read whole. */
function headerFields(text: string): Map<string, string> {
  const out = new Map<string, string>()
  for (const line of text.split('\n')) {
    const eq = line.indexOf('=')
    if (eq <= 0) continue
    const key = line.slice(0, eq).trim()
    if (!/^[a-z0-9_]+$/.test(key)) continue
    out.set(key, line.slice(eq + 1).replace(/\r$/, '').trim())
  }
  return out
}

// -------------------------------------------------- what the runner persists

/**
 * The handle that makes a detached job reclaimable FROM ROWS ALONE.
 *
 * Written to the target row at launch, before the first poll. Everything a
 * cold-started ShellPilot needs in order to find a job it never saw start: the
 * directory, the step it belongs to, who launched it, when, and how far the
 * output cursor got.
 *
 * `readOffset` is NOT `out_offset`. out_offset counts bytes PERSISTED after
 * redaction and after the head+tail cap threw the middle away; readOffset
 * counts bytes CONSUMED from the host's `out` file. Conflating them would make
 * the cursor rewind by exactly the number of elided bytes the first time a job
 * produced more than 256 KB, and re-read that many bytes of output it had
 * already recorded.
 */
export interface JobDetachedHandle {
  v: 1
  dir: string
  step: number
  instanceId: string
  launcher: 'setsid' | 'nohup'
  base64: boolean
  launchedAt: number
  readOffset: number
  /** The command, so a reclaiming instance can say what it is watching and can
   *  ask restartsTheMachine() about it without re-deriving the step. */
  command: string
}

export function isJobDetachedHandle(v: unknown): v is JobDetachedHandle {
  if (typeof v !== 'object' || v === null) return false
  const h = v as Partial<JobDetachedHandle>
  return (
    h.v === 1 &&
    typeof h.dir === 'string' &&
    typeof h.step === 'number' &&
    typeof h.instanceId === 'string' &&
    typeof h.launchedAt === 'number' &&
    typeof h.readOffset === 'number'
  )
}

/** The error a reclaimed host carries when its wrapper died without an answer. */
export const JOB_ORPHANED_ERROR =
  'The command was launched and its marker directory is still here, but the process is gone and ' +
  'no exit status was ever written \u2014 the OOM killer, a kill -9, or the host going down under ' +
  'it. Whether the work completed is not knowable from here; check the output above.'

/** The error a host carries when a detached launch could not even start. */
export const JOB_LAUNCH_FAILED_ERROR =
  'The detached launch left a marker directory but no process ever recorded a pid, so the command ' +
  'never began.'
