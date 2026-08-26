import { app } from 'electron'
import { homedir } from 'node:os'
import { join, dirname } from 'node:path'
import { existsSync, mkdirSync, readFileSync, writeFileSync, copyFileSync, renameSync } from 'node:fs'

// Writes MCP client configuration on the user's behalf, so connecting an agent
// is a button rather than a hand-edited JSON file with a 130-character absolute
// path in it. Nothing here grants access — the token it embeds was already
// minted by mcpAuth with an explicit workspace/group scope.

const SERVER_KEY = 'shellpilot'

// process.execPath is ShellPilot's own Electron binary. With
// ELECTRON_RUN_AS_NODE it runs plain JS, so the bridge needs no separate Node
// install and does not depend on PATH — which Claude Desktop does not inherit
// from a login shell, and which is the usual reason a `"command": "node"` entry
// works in a terminal and fails inside the app.
function bridgeScript(): string {
  const appPath = app.getAppPath()
  // Packaged builds run from app.asar; asarUnpack (electron-builder.yml) keeps
  // out/cli outside it precisely so it can be spawned as a real file, and a
  // child process cannot be launched from inside an archive at all.
  const root = appPath.endsWith('app.asar') ? `${appPath}.unpacked` : appPath
  return join(root, 'out', 'cli', 'index.js')
}

export interface BridgeInvocation {
  command: string
  args: string[]
  env: Record<string, string>
}

export function bridgeInvocation(token: string, port: number): BridgeInvocation {
  return {
    command: process.execPath,
    args: [bridgeScript(), 'bridge', '--token', token, '--port', String(port)],
    env: { ELECTRON_RUN_AS_NODE: '1' }
  }
}

export function httpUrl(port: number): string {
  return `http://127.0.0.1:${port}/mcp`
}

// The one-liner for Claude Code, which speaks Streamable HTTP directly and so
// needs no bridge process at all.
//
// Removes first, because `claude mcp add` refuses a name that already exists
// ("MCP server shellpilot already exists in user config") rather than replacing
// it. Every time after the first is a re-registration — a new session, or a
// revoked one being replaced — so the plain add would have failed exactly when
// it was needed most. `shellpilot claude` has always done remove-then-add for
// this reason (src/cli/agents.ts); this just matches it.
export function claudeCodeCommand(token: string, port: number): string {
  const add = [
    'claude mcp add -s user --transport http',
    SERVER_KEY,
    httpUrl(port),
    `--header "Authorization: Bearer ${token}"`
  ].join(' ')
  return `claude mcp remove ${SERVER_KEY} -s user 2>/dev/null; ${add}`
}

export function claudeDesktopConfigPath(): string {
  if (process.platform === 'win32') {
    return join(process.env.APPDATA || join(homedir(), 'AppData', 'Roaming'), 'Claude', 'claude_desktop_config.json')
  }
  if (process.platform === 'darwin') {
    return join(homedir(), 'Library', 'Application Support', 'Claude', 'claude_desktop_config.json')
  }
  return join(process.env.XDG_CONFIG_HOME || join(homedir(), '.config'), 'Claude', 'claude_desktop_config.json')
}

export function codexConfigPath(): string {
  // Codex uses ~/.codex on every platform, including Windows.
  return join(homedir(), '.codex', 'config.toml')
}

export interface WriteResult {
  ok: boolean
  path: string
  backedUpTo?: string
  error?: string
}

export function writeClaudeDesktopConfig(token: string, port: number): WriteResult {
  return writeClaudeDesktopConfigTo(claudeDesktopConfigPath(), token, port)
}

// Merges a `shellpilot` entry into whatever is already in the file. A user's
// other MCP servers are none of our business, so an unreadable or non-JSON file
// is a hard stop rather than something to overwrite with a clean config — the
// entry can always be added by hand from the docs.
//
// Takes the path explicitly so tests can exercise the merge without writing to
// the real Claude Desktop config on the machine running them.
export function writeClaudeDesktopConfigTo(file: string, token: string, port: number): WriteResult {
  let existing: Record<string, unknown> = {}
  let backedUpTo: string | undefined

  if (existsSync(file)) {
    let raw: string
    try {
      raw = readFileSync(file, 'utf8')
    } catch (err) {
      return { ok: false, path: file, error: `Could not read ${file}: ${(err as Error).message}` }
    }
    if (raw.trim()) {
      try {
        const parsed: unknown = JSON.parse(raw)
        if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) throw new Error('not a JSON object')
        existing = parsed as Record<string, unknown>
      } catch (err) {
        return {
          ok: false,
          path: file,
          error:
            `${file} is not valid JSON (${(err as Error).message}), so it was left untouched. ` +
            `Fix or move the file and try again, or add the entry by hand — see docs/AI-MCP.md.`
        }
      }
    }
    backedUpTo = `${file}.shellpilot-backup`
    try {
      copyFileSync(file, backedUpTo)
    } catch {
      // A backup is a courtesy, not a precondition — the merge below preserves
      // every key it did not write, so failing to copy is not worth aborting for.
      backedUpTo = undefined
    }
  }

  const servers =
    existing.mcpServers && typeof existing.mcpServers === 'object' && !Array.isArray(existing.mcpServers)
      ? { ...(existing.mcpServers as Record<string, unknown>) }
      : {}

  const { command, args, env } = bridgeInvocation(token, port)
  servers[SERVER_KEY] = { command, args, env }

  const next = { ...existing, mcpServers: servers }

  try {
    mkdirSync(dirname(file), { recursive: true })
    const tmp = `${file}.shellpilot-tmp`
    writeFileSync(tmp, `${JSON.stringify(next, null, 2)}\n`, 'utf8')
    renameSync(tmp, file)
  } catch (err) {
    return { ok: false, path: file, error: `Could not write ${file}: ${(err as Error).message}` }
  }

  return { ok: true, path: file, backedUpTo }
}

// Codex reads a TOML config and, like Claude Desktop, launches MCP servers as
// stdio subprocesses — so it gets the same bridge, in a different file format.
//
// There is no TOML dependency in this project and adding one for three
// key/value pairs is not worth it, so the entry is spliced in as a marked
// block, the same approach `shellpilot codex` already uses (src/cli/agents.ts).
// TOML basic-string escaping is a subset of JSON's, which makes JSON.stringify
// a safe way to quote each value.
const TOML_START = '# >>> shellpilot managed block — written by ShellPilot, safe to remove >>>'
const TOML_END = '# <<< shellpilot managed block <<<'

export function writeCodexConfig(token: string, port: number): WriteResult {
  return writeCodexConfigTo(codexConfigPath(), token, port)
}

export function writeCodexConfigTo(file: string, token: string, port: number): WriteResult {
  const { command, args, env } = bridgeInvocation(token, port)
  const block = [
    TOML_START,
    '[mcp_servers.shellpilot]',
    `command = ${JSON.stringify(command)}`,
    `args = [${args.map((a) => JSON.stringify(a)).join(', ')}]`,
    `env = { ${Object.entries(env)
      .map(([k, v]) => `${k} = ${JSON.stringify(v)}`)
      .join(', ')} }`,
    TOML_END
  ].join('\n')

  let existing = ''
  let backedUpTo: string | undefined

  if (existsSync(file)) {
    try {
      existing = readFileSync(file, 'utf8')
    } catch (err) {
      return { ok: false, path: file, error: `Could not read ${file}: ${(err as Error).message}` }
    }
    backedUpTo = `${file}.shellpilot-backup`
    try {
      copyFileSync(file, backedUpTo)
    } catch {
      backedUpTo = undefined
    }
  }

  // Replacing between the markers keeps everything the user wrote around it,
  // and re-running replaces the previous block rather than stacking another.
  const startIdx = existing.indexOf(TOML_START)
  const endIdx = existing.indexOf(TOML_END)
  const next =
    startIdx !== -1 && endIdx !== -1 && endIdx > startIdx
      ? existing.slice(0, startIdx) + block + existing.slice(endIdx + TOML_END.length)
      : existing.trimEnd() + (existing.trim() ? '\n\n' : '') + block + '\n'

  try {
    mkdirSync(dirname(file), { recursive: true })
    const tmp = `${file}.shellpilot-tmp`
    writeFileSync(tmp, next, 'utf8')
    renameSync(tmp, file)
  } catch (err) {
    return { ok: false, path: file, error: `Could not write ${file}: ${(err as Error).message}` }
  }

  return { ok: true, path: file, backedUpTo }
}
