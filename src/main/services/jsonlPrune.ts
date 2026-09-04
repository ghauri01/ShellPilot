import { existsSync, readFileSync, renameSync, unlinkSync, writeFileSync } from 'node:fs'
import { retainedLines } from '../../shared/jsonlRetention'

/**
 * Apply the retention horizon to one append-only JSON-lines log.
 *
 * THE APPEND-ONLY PROPERTY IS THE POINT, AND PRUNING MUST NOT COST IT. Each of
 * these files is documented as never rewritten in place, so that a crash
 * mid-write corrupts at most the last line rather than the whole history. A
 * prune that opens the file for writing and truncates it gives that up: a crash
 * during the rewrite loses everything, and it loses it during the one operation
 * that touches every line.
 *
 * So the survivors are written to a sibling and renamed over the original.
 * `rename` within a filesystem is atomic, so at every instant a reader sees
 * either the whole old file or the whole new one, and a crash leaves one of the
 * two rather than a half-written log. This is the same manoeuvre the remote
 * wrapper uses for its `rc` file, for the same reason.
 *
 * Returns how many lines went, or null if the file was left alone.
 */
export function pruneJsonl(file: string, now = Date.now()): number | null {
  try {
    if (!existsSync(file)) return null
    const raw = readFileSync(file, 'utf8')
    const lines = raw.split('\n').filter(Boolean)
    const { kept, dropped } = retainedLines(lines, { now })
    // Nothing to do is the overwhelmingly common case, and it must not rewrite
    // the file: a rename a day for no reason is a needless chance to lose one.
    if (dropped === 0) return null

    const tmp = `${file}.pruning`
    writeFileSync(tmp, kept.length ? `${kept.join('\n')}\n` : '', { mode: 0o600 })
    renameSync(tmp, file)
    return dropped
  } catch (err) {
    // A log that cannot be pruned keeps growing, which is the state it was in
    // before this existed. Failing the app's startup over it would be worse.
    console.error(`[retention] could not prune ${file}:`, err)
    try {
      const tmp = `${file}.pruning`
      if (existsSync(tmp)) unlinkSync(tmp)
    } catch {
      /* the temp file is not worth a second failure */
    }
    return null
  }
}
