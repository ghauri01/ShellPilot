import { isAbsolute } from 'node:path'
import { existsSync, statSync } from 'node:fs'
import { z } from 'zod'
import type { LocalConnectConfig } from '../../shared/local'

// The main-side half of the local terminal's front door: is the feature on, and
// is this request shaped like something we are willing to spawn a shell for.
//
// Both halves live in main on purpose. The renderer has a
// `settings.localTerminalEnabled` toggle, but a renderer-side flag constrains
// only the honest UI — the threat this guards against is a compromised renderer
// calling window.shellpilot.local.connect() directly, which never goes near the
// toggle. So the flag is mirrored here and every local:* handler consults this
// copy.

let enabled = true

// Read the flag out of the renderer's data blob, which main already receives on
// every data:save. Absent means ON, deliberately: settings are persisted
// wholesale (store/persist.ts save()) and merged saved-over-default, so if this
// key ever ships as `false` that false is written to disk and permanently wins
// over any later default change. Treating absence as ON means only an explicit
// user toggle can disable it, which is the same pattern `shortcuts` uses and
// documents at store/app.ts:67-71.
export function syncLocalTerminalEnabled(data: unknown): void {
  const settings = (data as { settings?: { localTerminalEnabled?: unknown } } | null)?.settings
  enabled = settings?.localTerminalEnabled !== false
}

export function isLocalTerminalEnabled(): boolean {
  return enabled
}

// Test seam. Not exported to the renderer or reachable over IPC.
export function setLocalTerminalEnabledForTests(value: boolean): void {
  enabled = value
}

// Session ids are renderer-chosen and become IPC channel name suffixes
// (`local:data:${sessionId}`), so they are constrained to characters that
// cannot collide with another namespace's channels or grow without bound.
const SESSION_ID = /^[A-Za-z0-9._:-]{1,128}$/

// cols/rows go straight into forkpty's winsize on POSIX and a ConPTY COORD on
// Windows, inside a beta native addon. localResize already clamps; localConnect
// did not, which is the asymmetry finding #24 is about. 1000 is far past any
// real terminal and well short of anything that would upset the allocator.
const DIMENSION = z.number().int().min(1).max(1000)

const schema = z.object({
  sessionId: z.string().regex(SESSION_ID),
  shellId: z.string().min(1).max(256),
  cwd: z.string().min(1).max(4096).optional(),
  cols: DIMENSION,
  rows: DIMENSION
})

export type LocalConnectRejection =
  | { ok: true; cfg: LocalConnectConfig }
  | { ok: false; reason: string }

export function parseLocalConnect(input: unknown): LocalConnectRejection {
  const parsed = schema.safeParse(input)
  if (!parsed.success) {
    return { ok: false, reason: 'The local terminal request was malformed.' }
  }
  const cfg = parsed.data

  if (cfg.cwd !== undefined) {
    // A relative cwd would resolve against main's own working directory, which
    // is not a place the user asked to start a shell.
    if (!isAbsolute(cfg.cwd)) {
      return { ok: false, reason: 'The starting directory must be an absolute path.' }
    }
    // On Windows a UNC path makes the spawn touch a remote SMB share, which is
    // an NTLM-hash-leak primitive. A local terminal has no business starting
    // there, and refusing it costs nothing.
    if (process.platform === 'win32' && /^[\\/]{2}/.test(cfg.cwd)) {
      return { ok: false, reason: 'The starting directory cannot be a network path.' }
    }
    // node-pty fails opaquely on a missing or non-directory cwd; say which.
    try {
      if (!existsSync(cfg.cwd) || !statSync(cfg.cwd).isDirectory()) {
        return { ok: false, reason: `The starting directory does not exist: ${cfg.cwd}` }
      }
    } catch {
      return { ok: false, reason: `The starting directory is not readable: ${cfg.cwd}` }
    }
  }

  return { ok: true, cfg }
}

// The same id rule, for the fire-and-forget channels. They carry no reply, so an
// invalid id is dropped rather than reported.
export function isValidSessionId(id: unknown): id is string {
  return typeof id === 'string' && SESSION_ID.test(id)
}
