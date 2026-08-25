import { createInterface } from 'node:readline/promises'
import { getCachedSession, saveCachedSession } from './paths.js'

const DEFAULT_PORT = 5177

function basePort(): number {
  const fromEnv = process.env.SHELLPILOT_PORT ? Number(process.env.SHELLPILOT_PORT) : NaN
  return Number.isFinite(fromEnv) && fromEnv > 0 ? fromEnv : DEFAULT_PORT
}

async function postJson(port: number, path: string, body: unknown): Promise<Record<string, unknown>> {
  const res = await fetch(`http://127.0.0.1:${port}${path}`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body)
  })
  return (await res.json()) as Record<string, unknown>
}

export interface ResolvedSession {
  token: string
  port: number
}

// Reuses a cached, not-yet-expired token when there is one; otherwise walks
// the human through the pairing-code flow against the already-running
// ShellPilot Desktop/Core, then caches the token it comes back with.
export async function getOrPairSession(agentKey: string, agentName: string): Promise<ResolvedSession> {
  const cached = getCachedSession(agentKey)
  if (cached) return { token: cached.token, port: cached.port }

  const port = basePort()

  let start: Record<string, unknown>
  try {
    start = await postJson(port, '/pair/start', { agentName })
  } catch {
    throw new Error(
      `Could not reach ShellPilot on 127.0.0.1:${port}. Open ShellPilot and turn on "Enable AI & MCP access" ` +
        `under AI & MCP → Security, or set SHELLPILOT_PORT if it uses a different port.`
    )
  }
  if (typeof start.error === 'string') throw new Error(start.error)
  const pairingId = start.pairingId as string
  const expiresInSeconds = start.expiresInSeconds as number

  console.log('Open ShellPilot — a one-time pairing code will appear there.')
  const rl = createInterface({ input: process.stdin, output: process.stdout })
  try {
    const deadline = Date.now() + expiresInSeconds * 1000
    for (;;) {
      if (Date.now() > deadline) throw new Error('Pairing code expired. Run the command again.')
      const code = (await rl.question('Enter the 6-digit code shown in ShellPilot: ')).trim()
      const confirm = await postJson(port, '/pair/confirm', { pairingId, code })
      if (confirm.ok) {
        const token = confirm.token as string
        const confirmedPort = confirm.port as number
        const expiresAt = (confirm.expiresAt as string | null) ?? null
        saveCachedSession(agentKey, { token, port: confirmedPort, expiresAt })
        return { token, port: confirmedPort }
      }
      console.log((confirm.error as string) ?? 'Incorrect code, try again.')
    }
  } finally {
    rl.close()
  }
}
