import { randomBytes } from 'node:crypto'
import {
  buildCronReadCommand,
  buildCronWriteCommand,
  parseCronRead,
  parseCronWriteResult,
  parseCrontabDocument,
  planCronEdit,
  resolveCronEdit,
  summariseCronSources,
  type CronEditPlan,
  type CronEditPlanReply,
  type CronEditRequest,
  type CronEditTargetRef,
  type CronSourceReport,
  type CronWriteReply
} from '../../shared/cron'
import { planBroadcast, verifyApproval } from '../../shared/broadcast'

// The main-process half of editing a scheduled job — roadmap item 6e.
//
// ---------------------------------------------------------------------------
// WHY THIS IS TWO ROUND TRIPS AND NOT ONE
// ---------------------------------------------------------------------------
// `crontab -` replaces the whole file. There is no line editing, so an edit is
// necessarily read-modify-write, and the bytes being modified have to be the
// bytes that are on the host RIGHT NOW rather than the ones a collection
// happened to catch a few minutes ago.
//
// So: `plan` reads the crontab and works out the exact bytes it would install;
// the operator confirms THAT; `write` re-derives the same command from the same
// bytes and runs it. The host checks the file has not moved underneath in
// between, which is the part that actually holds — a check made here would be
// a check about a file we are no longer looking at.
//
// ---------------------------------------------------------------------------
// THE RENDERER NEVER SUPPLIES A COMMAND
// ---------------------------------------------------------------------------
// It supplies the two files — the bytes it was shown and the bytes it wants —
// and main builds the shell from them. That differs from `broadcast:run`, where
// the command IS the user's input and there is nothing to derive it from, and
// the difference is worth keeping: everything that reaches a shell here comes
// out of `buildCronWriteCommand`, so reading that one function is enough to
// know what can run.
//
// The approval record is the broadcast/job one, unchanged. A cron edit is a
// write to the file that decides what runs unattended, so it goes through the
// path that records what a human was asked and checks that the thing about to
// run is still the thing they answered about — not around it.

interface ExecLike {
  ok: boolean
  code: number | null
  stdout?: string
  stderr?: string
  error?: string
  truncated?: boolean
}

export interface CronEditDeps {
  exec: (cfg: unknown, command: string, timeoutMs: number) => Promise<ExecLike>
  /**
   * Where the approval decision is written down. Injected rather than imported
   * so this file stays free of `electron`, which is what lets the shell-level
   * tests run it at all.
   */
  recordApproval: (entry: {
    surface: 'broadcast' | 'job'
    event: 'granted' | 'refused'
    jobId: string
    title: string
    risk: 'ordinary' | 'elevated' | 'destructive'
    confirmation: string
    phrase: string | null
    confirmedAt: number | null
    hosts: string[]
    commands: string[]
    reason?: string
  }) => void
}

/**
 * A token that names one change's backup: UTC timestamp, then six random hex.
 *
 * Timestamped so `ls` in a shell six weeks later sorts the backups in the order
 * they happened, and so the operator can tell when one was taken without
 * reading it. Random tail because two edits in the same second on the same host
 * must not share a backup file — the second one would overwrite the only copy
 * of what the first one replaced.
 */
export function mintCronToken(now = new Date()): string {
  const p = (n: number, w = 2): string => String(n).padStart(w, '0')
  const stamp =
    `${p(now.getUTCFullYear(), 4)}${p(now.getUTCMonth() + 1)}${p(now.getUTCDate())}` +
    `T${p(now.getUTCHours())}${p(now.getUTCMinutes())}${p(now.getUTCSeconds())}Z`
  return `${stamp}-${randomBytes(3).toString('hex')}`
}

const READ_TIMEOUT = 20_000
const WRITE_TIMEOUT = 30_000

/** One sentence for a host that did not answer, or answered with a refusal. */
function execFailure(r: ExecLike): string | null {
  if (!r.ok) return r.error ?? 'the host could not be reached'
  // Output the transport had to cut short is not output this can plan against.
  // A crontab clipped at the transport's cap parses into a document that is
  // MISSING ITS TAIL, and writing that back would delete every job past the
  // cut — silently, because cron reports nothing when a job stops existing.
  if (r.truncated) {
    return 'this crontab is larger than a single command can return, so ShellPilot will not edit it — the part it could not read is the part it would delete.'
  }
  return null
}

/**
 * Read the crontab and work out what one edit would install.
 *
 * The read half's own source report is what says whether the crontab was
 * READABLE, and that is checked here rather than trusted from the collection:
 * a source the collector called `partial` is half a file, and half a file is
 * not a file to write back.
 */
export async function planCronEditOnHost(
  deps: CronEditDeps,
  target: CronEditTargetRef,
  req: CronEditRequest,
  opts: { sources?: CronSourceReport[] } = {}
): Promise<CronEditPlanReply> {
  // The collection's own verdict, when the panel has one to offer. A `partial`
  // or `denied` user-crontab source means the list on screen is not the whole
  // file, and an edit planned against a list that is missing lines is an edit
  // that deletes them.
  const source = opts.sources?.find((s) => s.id === 'user-crontab')
  if (source && (source.status === 'partial' || source.status === 'denied' || source.status === 'unknown')) {
    const gaps = summariseCronSources([source]).incomplete
    return {
      ok: false,
      reason:
        `${target.serverName} reported this crontab as \`${source.status}\` when it was read` +
        `${gaps[0]?.detail ? ` (${gaps[0].detail})` : ''}, so ShellPilot only has part of it. ` +
        'A write replaces the whole file, and the part it could not read is the part it would delete.'
    }
  }

  const r = await deps.exec(target.cfg, buildCronReadCommand(), READ_TIMEOUT)
  const failed = execFailure(r)
  if (failed) return { ok: false, reason: failed }

  const read = parseCronRead(r.stdout ?? '')
  if (read.status === 'no-tool') {
    return { ok: false, reason: `${target.serverName} has no crontab command, so there is nothing here to edit.` }
  }
  if (read.status === 'unknown') {
    return {
      ok: false,
      reason: `${target.serverName} would not say what is in this account’s crontab${read.detail ? `: ${read.detail}` : '.'}`
    }
  }

  const doc = parseCrontabDocument(read.text, 'crontab -l', 'user-crontab', false)
  // The panel points at a LINE, not at a position. Resolving it against the
  // file the host just handed over is where "that job is not there any more"
  // gets answered, rather than an index quietly landing on a different job.
  const resolved = resolveCronEdit(doc, req)
  if (!resolved.ok) return { ok: false, reason: resolved.reason }
  const plan: CronEditPlan = planCronEdit(doc, resolved.edit)
  if (!plan.ok) return { ok: false, reason: plan.reason }

  const token = mintCronToken()
  return {
    ok: true,
    before: plan.before,
    after: plan.after,
    summary: plan.summary,
    addedFinalNewline: plan.addedFinalNewline,
    token,
    command: buildCronWriteCommand({ before: plan.before, after: plan.after, token })
  }
}

/**
 * Install the planned bytes, once the operator has confirmed them.
 *
 * The command is rebuilt here from `before`, `after` and `token` rather than
 * being taken as text, so nothing the renderer sends is executed as shell. What
 * `verifyApproval` then compares is that rebuilt command against the one the
 * record says was approved — so an edit to any of the three inputs after the
 * confirmation shows up as a command that does not match, and is refused.
 */
export async function writeCronEdit(
  deps: CronEditDeps,
  target: CronEditTargetRef,
  req: { before: string; after: string; token: string; runId: string; approval?: unknown }
): Promise<CronWriteReply> {
  const host = { serverId: target.serverId, serverName: target.serverName }
  let command: string
  try {
    command = buildCronWriteCommand({ before: req.before, after: req.after, token: req.token })
  } catch (e) {
    // The token is validated inside the builder because that is where it
    // reaches a command that replaces a crontab. A bad one is a bug or an
    // attempt, and neither gets a host.
    return {
      ...host,
      ok: false,
      outcome: 'no-answer',
      detail: e instanceof Error ? e.message : String(e)
    }
  }

  const plan = planBroadcast(command, [host])
  const verdict = verifyApproval(req.approval, { commands: [command], targets: [host] }, plan)
  const logRow = {
    surface: 'broadcast' as const,
    jobId: req.runId,
    title: `Scheduled job edit on ${target.serverName}`,
    risk: plan.risk,
    confirmation: plan.confirmation.kind,
    phrase: null as string | null,
    confirmedAt: null as number | null,
    hosts: [target.serverName],
    commands: [command]
  }
  if (!verdict.ok) {
    deps.recordApproval({ ...logRow, event: 'refused', reason: verdict.reason })
    return { ...host, ok: false, outcome: 'no-answer', detail: `This change was not made: ${verdict.reason}` }
  }
  deps.recordApproval({ ...logRow, event: 'granted' })

  const r = await deps.exec(target.cfg, command, WRITE_TIMEOUT)
  if (!r.ok) {
    // The connection failed. That is NOT the same as the change failing, and
    // saying so is the point: the command may have run to completion on the
    // host with the answer lost on the way back.
    return {
      ...host,
      ok: false,
      outcome: 'no-answer',
      detail: `${r.error ?? 'the host could not be reached'}. The change may or may not have been applied — read the crontab again before doing anything else.`
    }
  }
  const result = parseCronWriteResult(r.stdout ?? '')
  return { ...host, ok: result.outcome === 'written', ...result }
}
