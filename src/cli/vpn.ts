import { Client } from '@modelcontextprotocol/sdk/client/index.js'
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js'

// `shellpilot vpn list|status|up|down`.
//
// Deliberately implemented as MCP tool calls against the running app rather
// than as a direct path into main. That is not a shortcut — it is the security
// property: the CLI is an AI-adjacent surface, so it goes through exactly the
// same `vpnControl` capability check, the same approval prompt and the same
// audit entry an agent would. A second entry point into the manager would be a
// second thing to get right, and the first thing an attacker would look for.
//
// The consequences are visible and intended: `vpn up` can block waiting for the
// user to approve it in the app, `vpn up` on an frp profile is refused outright,
// and there is no `vpn add`.

interface ToolText {
  content?: { type?: string; text?: string }[]
  isError?: boolean
}

function renderToolResult(result: unknown): { text: string; isError: boolean } {
  const r = result as ToolText
  const text = (r.content ?? [])
    .filter((c) => c.type === 'text' && typeof c.text === 'string')
    .map((c) => c.text as string)
    .join('\n')
  return { text: text || '(no output)', isError: r.isError === true }
}

async function withClient<T>(
  token: string,
  port: number,
  fn: (c: Client) => Promise<T>
): Promise<T> {
  const client = new Client({ name: 'shellpilot-cli', version: '1' }, { capabilities: {} })
  const transport = new StreamableHTTPClientTransport(new URL(`http://127.0.0.1:${port}/mcp`), {
    requestInit: { headers: { Authorization: `Bearer ${token}` } }
  })
  await client.connect(transport)
  try {
    return await fn(client)
  } finally {
    await client.close().catch(() => undefined)
  }
}

export function printVpnHelp(): void {
  console.log(`shellpilot vpn — control VPN and reverse-proxy profiles

Usage:
  shellpilot vpn list              List profiles and whether each is running
  shellpilot vpn status <name>     Show one profile
  shellpilot vpn up <name>         Start a profile
  shellpilot vpn down <name>       Stop a profile

Profiles are created in the ShellPilot app, not here — this command can only run
one you have already defined, and it cannot change where a profile points.

Starting a VPN always asks for approval in the app, even when the access group
allows it, because it changes which network your other sessions traverse.
Reverse-proxy (frp) profiles cannot be started from here at all: they make a
local port reachable from a remote server, and that has to be a decision someone
makes in front of the app.`)
}

export async function runVpnCommand(
  args: string[],
  session: { token: string; port: number }
): Promise<number> {
  const [sub, name] = args

  if (!sub || sub === 'help' || sub === '--help' || sub === '-h') {
    printVpnHelp()
    return sub ? 0 : 1
  }

  if (sub === 'list' || sub === 'status') {
    if (sub === 'status' && !name) {
      console.error('Usage: shellpilot vpn status <name>')
      return 1
    }
    return withClient(session.token, session.port, async (client) => {
      const result = await client.callTool({ name: 'list_vpns', arguments: {} })
      const { text, isError } = renderToolResult(result)
      if (isError) {
        console.error(text)
        return 1
      }
      if (sub === 'list') {
        console.log(text)
        return 0
      }
      // Filter client-side rather than adding a per-profile tool: the tool
      // surface is deliberately two verbs wide, and a name that matches
      // nothing should say so rather than print an empty list.
      const wanted = (name as string).toLowerCase()
      const lines = text.split('\n').filter((l) => l.toLowerCase().includes(wanted))
      if (lines.length === 0) {
        console.error(`No VPN profile named "${name}".`)
        return 1
      }
      console.log(lines.join('\n'))
      return 0
    })
  }

  if (sub === 'up' || sub === 'down') {
    if (!name) {
      console.error(`Usage: shellpilot vpn ${sub} <name>`)
      return 1
    }
    return withClient(session.token, session.port, async (client) => {
      if (sub === 'up') {
        console.error('Waiting for approval in ShellPilot...')
      }
      const result = await client.callTool({
        name: 'set_vpn',
        arguments: { vpnName: name, running: sub === 'up' }
      })
      const { text, isError } = renderToolResult(result)
      if (isError) {
        console.error(text)
        return 1
      }
      console.log(text)
      return 0
    })
  }

  console.error(`Unknown vpn command "${sub}".`)
  printVpnHelp()
  return 1
}
