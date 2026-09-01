import { app } from 'electron'
import { join } from 'node:path'
import { existsSync, readFileSync, appendFileSync } from 'node:fs'
import { randomBytes } from 'node:crypto'

// A record of which shells ran on this machine, and when.
//
// Deliberately NOT the AI audit log. That file answers "what did an agent do",
// its entries are agent-shaped (agentName, capability, approval) and its viewer
// lives in the AI section — putting local terminal rows there would mean an
// AI-labelled log containing things no AI did, which is exactly the kind of
// thing that stops people trusting a log at all.
//
// What is recorded: one entry when a shell starts, one when it exits. Shell
// label, resolved path, pid, cwd, exit status. What is never recorded:
// keystrokes, output, or anything typed into the terminal. This answers "did
// something run locally at 03:00, and what was it" and nothing finer. A shell
// session's contents are the user's, and a log of them would be a far more
// attractive target than the thing it was meant to protect.
const FILE = join(app.getPath('userData'), 'shellpilot-local-sessions.jsonl')

export type LocalSessionEvent = 'started' | 'exited' | 'failed'

export interface LocalSessionEntry {
  id: string
  timestamp: string
  event: LocalSessionEvent
  sessionId: string
  shellId: string
  // Human-readable, e.g. "zsh (default)" or "WSL · Ubuntu-24.04".
  shellLabel: string
  // The absolute path actually spawned, after discovery resolved it.
  shellPath: string
  cwd?: string
  pid?: number
  exitCode?: number
  signal?: number
  // Only set for 'failed' — why the spawn did not happen.
  error?: string
}

const uid = (): string => `local-${Date.now().toString(36)}-${randomBytes(4).toString('hex')}`

// Append-only JSON lines, 0600, same discipline as the AI audit log: never
// rewritten in place, so a crash mid-write corrupts at most the last line.
export function recordLocalSession(
  entry: Omit<LocalSessionEntry, 'id' | 'timestamp'>
): LocalSessionEntry {
  const full: LocalSessionEntry = {
    id: uid(),
    timestamp: new Date().toISOString(),
    ...entry
  }
  try {
    appendFileSync(FILE, `${JSON.stringify(full)}\n`, { mode: 0o600 })
  } catch (err) {
    // A log that cannot be written must not take the terminal down with it.
    console.error('[local-session] failed to append entry:', err)
  }
  return full
}

export function listLocalSessions(limit = 500): LocalSessionEntry[] {
  try {
    if (!existsSync(FILE)) return []
    const lines = readFileSync(FILE, 'utf8').split('\n').filter(Boolean)
    const entries: LocalSessionEntry[] = []
    for (const line of lines.slice(-limit)) {
      try {
        entries.push(JSON.parse(line) as LocalSessionEntry)
      } catch {
        /* skip a corrupt line rather than fail the whole read */
      }
    }
    return entries.reverse()
  } catch (err) {
    console.error('[local-session] failed to read log:', err)
    return []
  }
}
