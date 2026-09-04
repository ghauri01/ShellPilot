/**
 * How long the three append-only JSON-lines logs keep a line.
 *
 * `auditLog`, `approvalLog` and `localSessionLog` had no horizon at all: they
 * grew for as long as the app was used. In practice that is slow -- one line
 * per approval or per agent call, never per line of output -- but slow is not
 * bounded, and "it will be fine" is not a retention policy. The history store
 * has had a horizon per event kind since item 32; these are the files that were
 * left out of it.
 *
 * A YEAR, deliberately generous. These answer "who did what, and who approved
 * it", which is a question asked long after the fact -- during an incident
 * review, or when somebody wants to know when a credential was last used. A
 * thirty-day window would be tidier and would have thrown away the answer.
 */
export const JSONL_RETENTION_DAYS = 365

/**
 * A second bound, on count rather than age.
 *
 * Age alone does not protect against a pathological run -- an agent in a retry
 * loop can write a great many lines inside the horizon. This caps the file
 * regardless, and is high enough that a normal year never reaches it.
 */
export const JSONL_RETENTION_MAX_LINES = 50_000

/**
 * Lines that survive, oldest first, and how many were dropped.
 *
 * Pure, so the policy can be tested without a filesystem -- which matters more
 * than usual here, because the failure mode of getting it wrong is silently
 * destroying audit records and nobody noticing until they are wanted.
 *
 * Three rules, and each exists because the obvious implementation gets it
 * wrong:
 *
 *  1. **A line whose timestamp cannot be read is KEPT.** Dropping it would mean
 *     a corrupt or future-format line is deleted precisely because we could not
 *     understand it, which is the worst possible reason to destroy an audit
 *     record. The read paths already skip unparseable lines rather than failing;
 *     this must not go further and remove them.
 *  2. **The newest `minKeep` lines survive regardless of age.** A vault used
 *     once and left alone for two years should still be able to say what
 *     happened that once, rather than opening on an empty log.
 *  3. **The count bound drops the OLDEST**, not the newest.
 */
export function retainedLines(
  lines: readonly string[],
  opts: { now: number; days?: number; maxLines?: number; minKeep?: number }
): { kept: string[]; dropped: number } {
  const days = opts.days ?? JSONL_RETENTION_DAYS
  const maxLines = opts.maxLines ?? JSONL_RETENTION_MAX_LINES
  const minKeep = opts.minKeep ?? 100
  const cutoff = opts.now - days * 24 * 60 * 60 * 1000

  const floor = lines.length > minKeep ? lines.length - minKeep : 0
  const byAge = lines.filter((line, i) => {
    if (i >= floor) return true
    const at = timestampOf(line)
    // Unreadable timestamp: keep. See rule 1.
    if (at === null) return true
    return at >= cutoff
  })

  const kept = byAge.length > maxLines ? byAge.slice(byAge.length - maxLines) : byAge
  return { kept, dropped: lines.length - kept.length }
}

/** The `timestamp` an entry was written with, or null if it cannot be read. */
export function timestampOf(line: string): number | null {
  try {
    const v = (JSON.parse(line) as { timestamp?: unknown }).timestamp
    if (typeof v !== 'string') return null
    const ms = Date.parse(v)
    return Number.isFinite(ms) ? ms : null
  } catch {
    return null
  }
}
