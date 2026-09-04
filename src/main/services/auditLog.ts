import { app } from 'electron'
import { join } from 'node:path'
import { existsSync, readFileSync, appendFileSync } from 'node:fs'
import { randomBytes } from 'node:crypto'
import type { AuditEntry } from '../../shared/mcp'
import { redactOutput } from './secretRedaction'

// Append-only JSON-lines file. Never rewritten in place (only appended to),
// so a crash mid-write can corrupt at most the last line rather than the
// whole history. Entries never carry secret material — every free-text field
// is redacted before it is written, not just before it is displayed.
const FILE = join(app.getPath('userData'), 'shellpilot-ai-audit.jsonl')

/** Exported so retention prunes THIS file rather than a second copy of the
 *  name. Two places spelling a filename is how one of them gets it wrong. */
export const AUDIT_LOG_PATH = FILE

const uid = (): string => `audit-${Date.now().toString(36)}-${randomBytes(4).toString('hex')}`

export function recordAudit(entry: Omit<AuditEntry, 'id' | 'timestamp'>): AuditEntry {
  const full: AuditEntry = {
    id: uid(),
    timestamp: new Date().toISOString(),
    ...entry,
    action: redactOutput(entry.action),
    error: entry.error ? redactOutput(entry.error) : entry.error
  }
  try {
    appendFileSync(FILE, `${JSON.stringify(full)}\n`, { mode: 0o600 })
  } catch (err) {
    console.error('[audit] failed to append entry:', err)
  }
  return full
}

export function listAudit(limit = 500): AuditEntry[] {
  try {
    if (!existsSync(FILE)) return []
    const lines = readFileSync(FILE, 'utf8').split('\n').filter(Boolean)
    const entries: AuditEntry[] = []
    for (const line of lines.slice(-limit)) {
      try {
        entries.push(JSON.parse(line) as AuditEntry)
      } catch {
        /* skip a corrupt line rather than fail the whole read */
      }
    }
    return entries.reverse()
  } catch (err) {
    console.error('[audit] failed to read log:', err)
    return []
  }
}
