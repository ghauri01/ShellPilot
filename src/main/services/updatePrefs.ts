import { app } from 'electron'
import { join } from 'node:path'
import { existsSync, readFileSync, writeFileSync, renameSync, unlinkSync } from 'node:fs'
import { DEFAULT_UPDATE_PREFS } from '../../shared/updater'
import type { CheckIntervalHours, UpdateChannel, UpdatePrefs } from '../../shared/updater'

// Every other user-facing setting lives in the one zustand blob the renderer
// owns and writes through store.ts. These cannot: the updater runs in main and
// makes its first decision — check on launch or not, on which channel — before
// a BrowserWindow exists, let alone a hydrated renderer store. Reading that
// blob from main would mean parsing a shape main does not own; waiting for the
// renderer would mean the launch check is no longer a launch check. So the
// updater keeps its own small file, written and read entirely in main.
const FILE = join(app.getPath('userData'), 'update-prefs.json')
const TMP = `${FILE}.tmp`

const CHANNELS: UpdateChannel[] = ['stable', 'beta']
const INTERVALS: CheckIntervalHours[] = [0, 6, 24]

const bool = (v: unknown, fallback: boolean): boolean => (typeof v === 'boolean' ? v : fallback)

// A prefs file is not a trusted input. It survives downgrades, hand edits and
// half-written upgrades, and every field here feeds straight into
// electron-updater — an unknown channel string would be handed to
// GitHubProvider verbatim and resolve to releases that do not exist. So each
// field is narrowed back to a value the rest of the code has a branch for,
// rather than trusted because the file parsed.
function validate(raw: Partial<UpdatePrefs>): UpdatePrefs {
  const channel = CHANNELS.includes(raw.channel as UpdateChannel)
    ? (raw.channel as UpdateChannel)
    : DEFAULT_UPDATE_PREFS.channel
  const checkIntervalHours = INTERVALS.includes(raw.checkIntervalHours as CheckIntervalHours)
    ? (raw.checkIntervalHours as CheckIntervalHours)
    : DEFAULT_UPDATE_PREFS.checkIntervalHours
  return {
    autoCheck: bool(raw.autoCheck, DEFAULT_UPDATE_PREFS.autoCheck),
    checkIntervalHours,
    autoDownload: bool(raw.autoDownload, DEFAULT_UPDATE_PREFS.autoDownload),
    autoInstallOnQuit: bool(raw.autoInstallOnQuit, DEFAULT_UPDATE_PREFS.autoInstallOnQuit),
    channel,
    lastCheckedAt: typeof raw.lastCheckedAt === 'string' ? raw.lastCheckedAt : null
  }
}

function read(): UpdatePrefs {
  try {
    if (existsSync(FILE)) {
      const parsed = JSON.parse(readFileSync(FILE, 'utf8')) as Partial<UpdatePrefs>
      if (parsed && typeof parsed === 'object') return validate(parsed)
    }
  } catch (err) {
    // Nothing here is worth failing app start over. Defaults are a working
    // updater; a throw at import time is a window that never opens.
    console.error('[updater] prefs unreadable, using defaults:', err)
  }
  return { ...DEFAULT_UPDATE_PREFS }
}

// Temp-then-rename with mode 0o600, matching store.ts/vault.ts/policyStore.ts.
// No backup copy though: unlike the server list, a lost prefs file costs the
// user four toggles, so the extra write per save is not worth it.
function write(prefs: UpdatePrefs): void {
  try {
    writeFileSync(TMP, JSON.stringify(prefs), { mode: 0o600 })
    renameSync(TMP, FILE)
  } catch (err) {
    console.error('[updater] prefs save failed:', err)
  }
}

let cache: UpdatePrefs | null = null

export function getUpdatePrefs(): UpdatePrefs {
  if (!cache) cache = read()
  return cache
}

export function setUpdatePrefs(patch: Partial<UpdatePrefs>): UpdatePrefs {
  const next = validate({ ...getUpdatePrefs(), ...patch })
  cache = next
  write(next)
  return next
}

// Test-only, same convention as policyStore's resetPolicyCacheForTests: drop
// the cache and the file so the next read starts from the defaults rather than
// whatever the previous test wrote.
export function resetUpdatePrefsCacheForTests(): void {
  cache = null
  try {
    if (existsSync(FILE)) unlinkSync(FILE)
  } catch {
    /* ignore */
  }
}
