import { app, shell, type WebContents } from 'electron'
import { join } from 'node:path'
import { mkdirSync, writeFileSync, readFileSync, statSync, unwatchFile, watchFile, rmSync } from 'node:fs'
import { spawn } from 'node:child_process'
import { createHash } from 'node:crypto'
import { sftpRead, sftpWrite } from './sftp'

// Opens a remote file in the user's own editor (VS Code, or whatever the OS
// associates) instead of the built-in inline editor, then writes it back on
// every save.
//
// Change detection is stat polling rather than fs.watch on purpose: editors
// like VS Code save atomically by writing a temp file and renaming over the
// target, which breaks a plain watch on the original inode.

interface Session {
  key: string
  remotePath: string
  localPath: string
  lastMtime: number
  saving: boolean
}

const sessions = new Map<string, Session>()
const ROOT = join(app.getPath('userData'), 'external-edit')

// Keeps the original filename so the editor picks the right syntax
// highlighting, but namespaces by remote path so two files called config.yml
// never collide.
function localPathFor(key: string, remotePath: string): string {
  const hash = createHash('sha256').update(`${key}:${remotePath}`).digest('hex').slice(0, 12)
  const dir = join(ROOT, hash)
  mkdirSync(dir, { recursive: true })
  return join(dir, remotePath.split('/').pop() || 'file')
}

function launch(localPath: string, command: string): void {
  if (!command.trim()) {
    void shell.openPath(localPath)
    return
  }
  // detached so closing the editor later cannot take the app down with it
  const child = spawn(command, [localPath], { detached: true, stdio: 'ignore', shell: true })
  child.on('error', () => void shell.openPath(localPath))
  child.unref()
}

export async function externalEditOpen(
  wc: WebContents,
  key: string,
  remotePath: string,
  command: string
): Promise<{ ok: boolean; error?: string; localPath?: string }> {
  const res = await sftpRead(key, remotePath)
  if (!res.ok) return { ok: false, error: res.error ?? 'Could not read the file' }

  try {
    const localPath = localPathFor(key, remotePath)
    writeFileSync(localPath, res.data ?? '', 'utf8')

    // Re-opening the same file should not stack watchers.
    const existing = sessions.get(localPath)
    if (existing) unwatchFile(localPath)

    const session: Session = {
      key,
      remotePath,
      localPath,
      lastMtime: statSync(localPath).mtimeMs,
      saving: false
    }
    sessions.set(localPath, session)

    watchFile(localPath, { interval: 700 }, (curr) => {
      const s = sessions.get(localPath)
      if (!s || s.saving) return
      if (curr.mtimeMs === s.lastMtime || curr.size === 0) return
      s.lastMtime = curr.mtimeMs
      s.saving = true
      void (async () => {
        try {
          const body = readFileSync(localPath, 'utf8')
          const w = await sftpWrite(s.key, s.remotePath, body)
          if (!wc.isDestroyed()) {
            wc.send('sftp:external-saved', {
              remotePath: s.remotePath,
              ok: w.ok,
              error: w.error
            })
          }
        } finally {
          s.saving = false
        }
      })()
    })

    launch(localPath, command)
    return { ok: true, localPath }
  } catch (err) {
    return { ok: false, error: err instanceof Error ? err.message : String(err) }
  }
}

export function externalEditStop(remotePath: string): void {
  for (const [localPath, s] of sessions) {
    if (s.remotePath !== remotePath) continue
    unwatchFile(localPath)
    sessions.delete(localPath)
  }
}

export function externalEditDisposeAll(): void {
  for (const localPath of sessions.keys()) unwatchFile(localPath)
  sessions.clear()
  // The temp copies are just caches of remote files; do not leave them behind.
  try {
    rmSync(ROOT, { recursive: true, force: true })
  } catch {
    /* ignore */
  }
}
