import { app } from 'electron'
import { join } from 'node:path'
import { existsSync, readFileSync, appendFileSync } from 'node:fs'
import { randomBytes } from 'node:crypto'
import type { JobApprovalEntry } from '../../shared/jobs'
import { redactOutput } from './secretRedaction'

// A record of what a human was asked before a job or a broadcast ran, and what
// they answered — roadmap item B3.
//
// ---------------------------------------------------------------------------
// A THIRD FILE, AND A THIRD MODULE. Both halves are deliberate.
// ---------------------------------------------------------------------------
// The obvious move was to give `recordAudit` in auditLog.ts a second caller.
// It was rejected twice over.
//
// FIRST, docs/AI-SECURITY.md states plainly that `recordAudit` is called from
// `mcpServer.ts` and nowhere else, so `shellpilot-ai-audit.jsonl` is a record
// of THE MCP BRIDGE rather than of everything ShellPilot does. That is not a
// stale sentence — it is what the "no record of what an agent did" row in the
// threat table rests on, and its whole value is that a reader can trust every
// row in that file to be an agent's. A job is human-only by construction: it is
// not reachable from the bridge and will not be, because durability defeats
// revocation — `denyAllPending()` resolves requests that are PENDING, and a job
// already detached on fifteen hosts has nothing pending to deny. So every row a
// job wrote there would be an AI-labelled row no AI produced, which is exactly
// the argument this repository already accepted for the local terminal and its
// own `shellpilot-local-sessions.jsonl`. The precedent is followed rather than
// reopened.
//
// SECOND, and this is the half that decided the MODULE rather than just the
// file: `auditLog.ts` is inside the agent-reachable import closure, and
// `tests/jobsNotExposed.test.ts` walks that closure and refuses to let any
// module in it so much as import the job vocabulary. Putting the writer in
// auditLog.ts would have pulled `shared/jobs.ts` in behind it — through a
// type-only import, erased at runtime and therefore harmless in itself, which
// is precisely the kind of edge that erodes a boundary one reasonable step at a
// time. That test says "move the helper, not this assertion", and it is right.
//
// Same discipline as both of its siblings: append-only JSON lines, never
// rewritten in place so a crash mid-write corrupts at most the last line, 0600,
// and every free-text field redacted before it is written rather than before it
// is displayed.
//
// WHAT IS NEVER RECORDED HERE: a job's OUTPUT. That lives in the history store
// under its own 30-day retention, capped and redacted there. This file answers
// "was this authorised, by whom, for exactly what" and nothing finer.
const FILE = join(app.getPath('userData'), 'shellpilot-job-approvals.jsonl')

const uid = (): string => `appr-${Date.now().toString(36)}-${randomBytes(4).toString('hex')}`

/**
 * Record one approval decision for a job or a broadcast.
 *
 * REDACTION HAPPENS HERE, at the writer, not at the caller. The runner hands
 * over the step text as the user typed it, and a job's step text is exactly
 * where somebody pastes `mysql -u root -phunter2` or a connection string with a
 * password in it. Doing it at the boundary means the second caller — the
 * broadcast handler in main/index.ts — cannot forget, and neither can a third.
 *
 * Host names and the job title go through it too. They are chosen by the user
 * and are normally harmless, and "normally harmless" is not a category this
 * file has.
 */
export function recordJobApproval(
  entry: Omit<JobApprovalEntry, 'id' | 'timestamp'>
): JobApprovalEntry {
  const full: JobApprovalEntry = {
    id: uid(),
    timestamp: new Date().toISOString(),
    ...entry,
    title: redactOutput(entry.title),
    phrase: entry.phrase === null ? null : redactOutput(entry.phrase),
    hosts: entry.hosts.map((h) => redactOutput(h)),
    commands: entry.commands.map((c) => redactOutput(c)),
    ...(entry.reason === undefined ? {} : { reason: redactOutput(entry.reason) })
  }
  try {
    appendFileSync(FILE, `${JSON.stringify(full)}\n`, { mode: 0o600 })
  } catch (err) {
    // A log that cannot be written must not take the job down with it — the
    // refusal that produced this row has already happened either way, and the
    // check does not depend on the record of it.
    console.error('[job-approval] failed to append entry:', err)
  }
  return full
}

export function listJobApprovals(limit = 500): JobApprovalEntry[] {
  try {
    if (!existsSync(FILE)) return []
    const lines = readFileSync(FILE, 'utf8').split('\n').filter(Boolean)
    const entries: JobApprovalEntry[] = []
    for (const line of lines.slice(-limit)) {
      try {
        entries.push(JSON.parse(line) as JobApprovalEntry)
      } catch {
        /* skip a corrupt line rather than fail the whole read */
      }
    }
    return entries.reverse()
  } catch (err) {
    console.error('[job-approval] failed to read log:', err)
    return []
  }
}
