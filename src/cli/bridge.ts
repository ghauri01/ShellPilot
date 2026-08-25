import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js'
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js'

// Pure protocol relay: an MCP client (Claude Code, Codex, ...) talks stdio to
// this process; every message is forwarded, unmodified, to ShellPilot's own
// MCP server over the already-existing authenticated HTTP endpoint, and every
// reply is forwarded back. No tool/session/policy logic lives here — that all
// stays exactly where it already is, in mcpServer.ts and the services it
// calls, so a stdio-only client gets the identical security/audit/approval
// path an HTTP client would.
export async function runBridge(token: string, port: number): Promise<void> {
  const server = new StdioServerTransport()
  const client = new StreamableHTTPClientTransport(new URL(`http://127.0.0.1:${port}/mcp`), {
    requestInit: { headers: { Authorization: `Bearer ${token}` } }
  })

  server.onmessage = (message) => {
    void client.send(message)
  }
  client.onmessage = (message) => {
    void server.send(message)
  }

  let closing = false
  const shutdown = async (): Promise<void> => {
    if (closing) return
    closing = true
    await Promise.allSettled([server.close(), client.close()])
    process.exit(0)
  }
  server.onclose = () => void shutdown()
  client.onclose = () => void shutdown()
  server.onerror = (err) => console.error('[shellpilot bridge] stdio error:', err.message)
  client.onerror = (err) => console.error('[shellpilot bridge] http error:', err.message)

  await client.start()
  await server.start()
}
