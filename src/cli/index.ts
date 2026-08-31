#!/usr/bin/env node
import { fileURLToPath } from 'node:url'
import { spawn } from 'node:child_process'
import { getOrPairSession } from './pairing.js'
import { runBridge } from './bridge.js'
import { registerClaudeMcp, registerCodexMcp } from './agents.js'
import { runVpnCommand } from './vpn.js'

const selfScript = fileURLToPath(import.meta.url)
const execPath = process.execPath

function argValue(args: string[], flag: string): string | undefined {
  const i = args.indexOf(flag)
  return i === -1 ? undefined : args[i + 1]
}

function spawnInherit(cmd: string, args: string[], extraEnv: Record<string, string> = {}): Promise<number> {
  return new Promise((resolve) => {
    const child = spawn(cmd, args, {
      stdio: 'inherit',
      shell: process.platform === 'win32',
      env: { ...process.env, ...extraEnv }
    })
    child.on('exit', (code) => resolve(code ?? 1))
    child.on('error', (err) => {
      console.error(`Could not start "${cmd}": ${err.message}`)
      resolve(1)
    })
  })
}

function printHelp(): void {
  console.log(`ShellPilot CLI launcher

Usage:
  shellpilot claude            Launch Claude Code with ShellPilot MCP auto-configured
  shellpilot codex             Launch Codex with ShellPilot MCP auto-configured
  shellpilot run -- <command>  Launch any command with SHELLPILOT_MCP_COMMAND/ARGS set
  shellpilot vpn <subcommand>  List, start or stop VPN profiles (see: shellpilot vpn help)

Requires ShellPilot Desktop/Core already running, with AI & MCP enabled (AI & MCP → Security).
First run pairs with it: a one-time code appears in ShellPilot for you to type here. Set
SHELLPILOT_PORT if ShellPilot's MCP bridge is not on the default port 5177.`)
}

async function main(): Promise<void> {
  const [cmd, ...rest] = process.argv.slice(2)

  if (cmd === 'bridge') {
    const token = argValue(rest, '--token')
    const port = Number(argValue(rest, '--port'))
    if (!token || !port) {
      console.error('Usage: shellpilot bridge --token <token> --port <port>')
      process.exitCode = 1
      return
    }
    await runBridge(token, port)
    return
  }

  if (cmd === 'claude') {
    const { token, port } = await getOrPairSession('claude', 'Claude Code (CLI)')
    registerClaudeMcp(execPath, selfScript, token, port)
    process.exitCode = await spawnInherit('claude', rest)
    return
  }

  if (cmd === 'codex') {
    const { token, port } = await getOrPairSession('codex', 'Codex (CLI)')
    registerCodexMcp(execPath, selfScript, token, port)
    process.exitCode = await spawnInherit('codex', rest)
    return
  }

  if (cmd === 'run') {
    const sepIdx = rest.indexOf('--')
    const target = sepIdx === -1 ? rest : rest.slice(sepIdx + 1)
    if (target.length === 0) {
      console.error('Usage: shellpilot run -- <command> [args...]')
      process.exitCode = 1
      return
    }
    const [targetCmd, ...targetArgs] = target
    const { token, port } = await getOrPairSession(targetCmd, `${targetCmd} (CLI)`)
    process.exitCode = await spawnInherit(targetCmd, targetArgs, {
      SHELLPILOT_MCP_COMMAND: execPath,
      SHELLPILOT_MCP_ARGS: JSON.stringify([selfScript, 'bridge', '--token', token, '--port', String(port)])
    })
    return
  }

  if (cmd === 'vpn') {
    // Routed through the MCP session rather than straight into the app, so it
    // inherits the vpnControl capability check, the approval prompt and the
    // audit entry instead of quietly bypassing all three.
    const session = await getOrPairSession('cli-vpn', 'ShellPilot CLI (vpn)')
    process.exitCode = await runVpnCommand(rest, session)
    return
  }

  printHelp()
  process.exitCode = cmd ? 1 : 0
}

main().catch((err) => {
  console.error(err instanceof Error ? err.message : String(err))
  process.exitCode = 1
})
