// Creating a server has to happen in the renderer: it owns the connection list
// (store/app.ts) and persistence auto-saves from there, which is also what
// refreshes the MCP cache. Main asks for the work and awaits the answer, the
// same shape as the keyboard-interactive prompt round trip in index.ts.

export interface AgentServerRequest {
  workspaceId: string
  name: string
  host: string
  port: number
  username: string
  auth: 'password' | 'key' | 'agent'
  password?: string
  keyPath?: string
  passphrase?: string
  os?: string
}

export interface AgentServerResult {
  ok: boolean
  serverId?: string
  error?: string
}

type Creator = (req: AgentServerRequest) => Promise<AgentServerResult>

let creator: Creator | null = null

export function setAgentServerCreator(fn: Creator): void {
  creator = fn
}

// A closed window is not an error worth retrying — the approval it would have
// needed cannot be shown either.
export function createServerForAgent(req: AgentServerRequest): Promise<AgentServerResult> {
  if (!creator) return Promise.resolve({ ok: false, error: 'ShellPilot is not ready to add a server right now.' })
  return creator(req)
}

export function resetAgentServerCreatorForTests(): void {
  creator = null
}
