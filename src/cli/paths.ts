import { homedir } from 'node:os'
import { join } from 'node:path'
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs'

// Deliberately separate from ShellPilot Desktop/Core's own userData directory:
// this is a small cache the CLI keeps for itself, keyed by agent, so it does
// not need to re-pair on every launch. It holds only an already-scoped MCP
// bearer token — the same kind of secret a user would otherwise paste into a
// client's mcp.json by hand, nothing more sensitive than that.
function configDir(): string {
  if (process.platform === 'win32') {
    return join(process.env.APPDATA || join(homedir(), 'AppData', 'Roaming'), 'ShellPilot', 'cli')
  }
  if (process.platform === 'darwin') {
    return join(homedir(), 'Library', 'Application Support', 'ShellPilot', 'cli')
  }
  return join(process.env.XDG_CONFIG_HOME || join(homedir(), '.config'), 'shellpilot', 'cli')
}

export interface CachedSession {
  token: string
  port: number
  expiresAt: string | null
}

type Cache = Record<string, CachedSession>

function cacheFile(): string {
  return join(configDir(), 'sessions.json')
}

function loadCache(): Cache {
  try {
    return JSON.parse(readFileSync(cacheFile(), 'utf8')) as Cache
  } catch {
    return {}
  }
}

function writeCache(cache: Cache): void {
  mkdirSync(configDir(), { recursive: true })
  writeFileSync(cacheFile(), JSON.stringify(cache, null, 2), { mode: 0o600 })
}

export function getCachedSession(agentKey: string): CachedSession | null {
  const entry = loadCache()[agentKey]
  if (!entry) return null
  if (entry.expiresAt && new Date(entry.expiresAt).getTime() <= Date.now()) return null
  return entry
}

export function saveCachedSession(agentKey: string, session: CachedSession): void {
  const cache = loadCache()
  cache[agentKey] = session
  writeCache(cache)
}
