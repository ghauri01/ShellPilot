import { app } from 'electron'
import { join } from 'node:path'
import { readFileSync, writeFileSync, existsSync, renameSync, copyFileSync } from 'node:fs'

// Non-secret application data (workspaces, folders, servers, vpns, tunnels).
// Secrets live separately in secrets.ts. This is a plain JSON snapshot the
// renderer owns; main only reads and writes the blob.
const FILE = join(app.getPath('userData'), 'shellpilot-data.json')
const TMP = `${FILE}.tmp`
const BAK = `${FILE}.bak`

export function loadData(): unknown | null {
  try {
    if (existsSync(FILE)) return JSON.parse(readFileSync(FILE, 'utf8'))
  } catch (err) {
    console.error('[store] primary data file unreadable, trying backup:', err)
    // A corrupt primary is exactly what the backup copy exists for. Losing
    // every server because of one bad write is not acceptable.
    try {
      if (existsSync(BAK)) return JSON.parse(readFileSync(BAK, 'utf8'))
    } catch (bakErr) {
      console.error('[store] backup unreadable too:', bakErr)
    }
  }
  return null
}

// Written temp-then-rename, like the vault and the workspace locks. Writing
// straight over the live file meant a crash, a power loss or a full disk mid
// write could truncate it — losing every server, database and folder.
export function saveData(data: unknown): void {
  try {
    const json = JSON.stringify(data)
    // Never leave the previous good copy behind on a partial write.
    if (existsSync(FILE)) {
      try {
        copyFileSync(FILE, BAK)
      } catch {
        /* a missing backup must not stop the save */
      }
    }
    writeFileSync(TMP, json, { mode: 0o600 })
    renameSync(TMP, FILE)
  } catch (err) {
    console.error('[store] save failed:', err)
  }
}
