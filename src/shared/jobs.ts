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
 * RESERVED FOR B2, deliberately absent from this union: `detached` (launched,
 * channel gone), `orphaned` (marker present, pid gone, no exit status) and
 * `rebooting` (an EXPECTED reboot, which today classifies as `unreachable` —
 * the opposite of the truth). They are named here so the names are taken and
 * so nobody invents a fourth spelling, and they are NOT in the union because
 * B1 cannot produce one: a state no code path can reach is a promise the store
 * would be making on the executor's behalf. See RESERVED_JOB_HOST_STATES.
 */
export type JobHostState = 'pending' | 'waiting' | 'running' | 'ok' | 'failed' | 'skipped'

export const JOB_HOST_STATES: readonly JobHostState[] = [
  'pending',
  'waiting',
  'running',
  'ok',
  'failed',
  'skipped'
]

/**
 * B2's states, reserved by name only. Nothing in B1 writes one, and the store
 * accepts them as strings so a B2 row is readable by a B1 build rather than
 * being silently dropped on read.
 */
export const RESERVED_JOB_HOST_STATES: readonly string[] = ['detached', 'orphaned', 'rebooting']

/**
 * What actually happened to one host, one level below `state`.
 *
 * Broadcast's seven, plus `abandoned`. That one is B1's honest name for the
 * case the attached path really has: ShellPilot stopped while this host was
 * running, so the channel went with it and the remote process was sent SIGHUP.
 * It is NOT `timeout` (we did not wait and give up), NOT `unreachable` (the
 * host was fine), and NOT `cancelled` (nobody asked for it). Filing it under
 * any of those three would be recording someone else's fault.
 */
export type JobHostOutcome = BroadcastHostOutcome | 'abandoned'

export const JOB_OUTCOME_LABEL: Record<JobHostOutcome, string> = {
  ok: 'ok',
  nonzero: 'non-zero exit',
  'missing-command': 'command not on this host',
  'permission-denied': 'permission denied',
  timeout: 'timed out',
  unreachable: 'unreachable',
  cancelled: 'not run',
  abandoned: 'abandoned when ShellPilot stopped'
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
  if (r.state === 'waiting') return null
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
  onProgress(fn: (p: JobProgress) => void): () => void
  onOutput(fn: (o: JobOutput) => void): () => void
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
