import { spawnSync } from 'node:child_process'
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { homedir } from 'node:os'
import { join } from 'node:path'

function bridgeArgs(execPath: string, selfScript: string, token: string, port: number): string[] {
  return [selfScript, 'bridge', '--token', token, '--port', String(port)]
}

// Re-registers (remove, then add) so a fresh pairing always replaces a
// stale/expired token instead of leaving Claude Code pointed at one that no
// longer works.
export function registerClaudeMcp(execPath: string, selfScript: string, token: string, port: number): void {
  spawnSync('claude', ['mcp', 'remove', 'shellpilot'], { stdio: 'ignore', shell: process.platform === 'win32' })
  const res = spawnSync(
    'claude',
    ['mcp', 'add', '--transport', 'stdio', 'shellpilot', '--', execPath, ...bridgeArgs(execPath, selfScript, token, port)],
    { stdio: ['ignore', 'ignore', 'inherit'], shell: process.platform === 'win32' }
  )
  if (res.error || res.status !== 0) {
    throw new Error('Could not register ShellPilot with Claude Code. Is the `claude` CLI installed and on PATH?')
  }
}

const TOML_START = '# >>> shellpilot managed block — edited by `shellpilot codex`, safe to remove >>>'
const TOML_END = '# <<< shellpilot managed block <<<'

// Codex's MCP config is a TOML file, not JSON, and there is no existing TOML
// dependency in this project — string-splice a marked block instead of
// pulling one in for two key/value pairs. TOML basic-string escaping is a
// subset of JSON's, so JSON.stringify is a safe way to quote each value.
export function registerCodexMcp(execPath: string, selfScript: string, token: string, port: number): void {
  const dir = join(homedir(), '.codex')
  const file = join(dir, 'config.toml')
  mkdirSync(dir, { recursive: true })
  const existing = existsSync(file) ? readFileSync(file, 'utf8') : ''

  const args = bridgeArgs(execPath, selfScript, token, port)
  const block = [
    TOML_START,
    '[mcp_servers.shellpilot]',
    `command = ${JSON.stringify(execPath)}`,
    `args = [${args.map((a) => JSON.stringify(a)).join(', ')}]`,
    TOML_END
  ].join('\n')

  const startIdx = existing.indexOf(TOML_START)
  const endIdx = existing.indexOf(TOML_END)
  const next =
    startIdx !== -1 && endIdx !== -1
      ? existing.slice(0, startIdx) + block + existing.slice(endIdx + TOML_END.length)
      : existing.trimEnd() + (existing.trim() ? '\n\n' : '') + block + '\n'

  writeFileSync(file, next, 'utf8')
}
