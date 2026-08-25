import { useEffect, useState } from 'react'
import { Plus, Copy, Ban, Octagon } from 'lucide-react'
import { toast } from '../../store/toast'
import type { McpAgentSession, AccessGroup } from '../../../../shared/mcp'

interface WorkspaceOpt {
  id: string
  name: string
}

function fmtTime(iso: string | null): string {
  if (!iso) return 'Never'
  return new Date(iso).toLocaleString()
}

function isLive(s: McpAgentSession): boolean {
  return !s.revoked && (!s.expiresAt || new Date(s.expiresAt) > new Date())
}

function CreateSessionForm({
  workspaces,
  groups,
  onCreated
}: {
  workspaces: WorkspaceOpt[]
  groups: AccessGroup[]
  onCreated: () => void
}): React.JSX.Element {
  const [agentName, setAgentName] = useState('Claude Code')
  const [workspaceId, setWorkspaceId] = useState(workspaces[0]?.id ?? '')
  const [groupId, setGroupId] = useState(groups[0]?.id ?? '')
  const [ttl, setTtl] = useState(60)
  const [issued, setIssued] = useState<{ token: string; port: number | null } | null>(null)

  // workspaces/groups arrive async (an IPC round-trip after this form has
  // already mounted with empty props), so the useState initializers above
  // usually capture '' and never get a second chance — the dropdowns then
  // *look* selected but the state backing them is empty, and Create fails
  // with "create a workspace first" even though one exists. Backfill once
  // real data shows up, but only while the user hasn't picked something.
  useEffect(() => {
    if (!workspaceId && workspaces.length > 0) setWorkspaceId(workspaces[0].id)
  }, [workspaces, workspaceId])
  useEffect(() => {
    if (!groupId && groups.length > 0) setGroupId(groups[0].id)
  }, [groups, groupId])

  const create = async (): Promise<void> => {
    const workspace = workspaces.find((w) => w.id === workspaceId)
    const group = groups.find((g) => g.id === groupId)
    if (!workspace) {
      toast('Create a workspace first')
      return
    }
    const result = await window.shellpilot?.aiMcp.createSession({
      agentName: agentName.trim() || 'Unnamed agent',
      workspaceId: workspace.id,
      workspaceName: workspace.name,
      groupId: group?.id ?? null,
      groupName: group?.name ?? 'No AI Access',
      ttlMinutes: ttl === 0 ? null : ttl
    })
    if (!result) return
    const status = await window.shellpilot?.aiMcp.status()
    setIssued({ token: result.token, port: status?.port ?? null })
    onCreated()
  }

  if (issued) {
    const url = `http://127.0.0.1:${issued.port ?? '(disabled)'}/mcp`
    const jsonConfig = JSON.stringify(
      { mcpServers: { shellpilot: { url, headers: { Authorization: `Bearer ${issued.token}` } } } },
      null,
      2
    )
    return (
      <div className="settings-section" style={{ marginBottom: 24 }}>
        <h3>Session created</h3>
        <div className="s-desc">
          This token is shown only once. ShellPilot stores only its hash — if you lose it, revoke
          the session and create a new one. Copy the block below into an MCP client that takes a
          JSON config (e.g. Gemini CLI). For Claude Code or Codex, you don't need this at all —
          just run <code className="mono">shellpilot claude</code> or{' '}
          <code className="mono">shellpilot codex</code>; its one-time pairing code replaces
          copying a token by hand.
        </div>
        <div className="setting-row">
          <div className="s-info">
            <div className="s-title">mcp.json snippet</div>
            <div className="s-desc">For clients configured via a JSON file.</div>
          </div>
          <button
            className="btn sm"
            onClick={() => {
              navigator.clipboard.writeText(jsonConfig)
              toast('Config copied')
            }}
          >
            <Copy size={13} /> Copy JSON config
          </button>
        </div>
        <div className="setting-row">
          <div className="s-info">
            <div className="s-title mono">{issued.token}</div>
            <div className="s-desc">Raw token, if you need it on its own.</div>
          </div>
          <button
            className="btn sm"
            onClick={() => {
              navigator.clipboard.writeText(issued.token)
              toast('Token copied')
            }}
          >
            <Copy size={13} /> Copy token
          </button>
        </div>
        <button className="btn sm" style={{ marginTop: 12 }} onClick={() => setIssued(null)}>
          Done
        </button>
      </div>
    )
  }

  return (
    <div className="settings-section" style={{ marginBottom: 24 }}>
      <h3>New AI agent session</h3>
      <div className="setting-row">
        <div className="s-info">
          <div className="s-title">Agent name</div>
          <div className="s-desc">A label for the Active Sessions list — e.g. "Claude Code", "Codex".</div>
        </div>
        <input className="input" value={agentName} onChange={(e) => setAgentName(e.target.value)} />
      </div>
      <div className="setting-row">
        <div className="s-info">
          <div className="s-title">Workspace</div>
          <div className="s-desc">This session only ever sees servers inside this workspace.</div>
        </div>
        <select className="input" value={workspaceId} onChange={(e) => setWorkspaceId(e.target.value)}>
          {workspaces.map((w) => (
            <option key={w.id} value={w.id}>
              {w.name}
            </option>
          ))}
        </select>
      </div>
      <div className="setting-row">
        <div className="s-info">
          <div className="s-title">Access group ceiling</div>
          <div className="s-desc">
            The most this session can ever do, regardless of what a server is separately assigned to.
          </div>
        </div>
        <select className="input" value={groupId} onChange={(e) => setGroupId(e.target.value)}>
          {groups.map((g) => (
            <option key={g.id} value={g.id}>
              {g.name}
            </option>
          ))}
        </select>
      </div>
      <div className="setting-row">
        <div className="s-info">
          <div className="s-title">Expires after</div>
          <div className="s-desc">The session stops working once this elapses.</div>
        </div>
        <select className="input" value={ttl} onChange={(e) => setTtl(Number(e.target.value))}>
          <option value={15}>15 minutes</option>
          <option value={60}>1 hour</option>
          <option value={480}>8 hours</option>
          <option value={10080}>7 days</option>
          <option value={0}>Never</option>
        </select>
      </div>
      <button className="btn sm primary" onClick={create}>
        <Plus size={13} /> Create session
      </button>
    </div>
  )
}

export function AiAgents({ sessionsOnly = false }: { sessionsOnly?: boolean }): React.JSX.Element {
  const [sessions, setSessions] = useState<McpAgentSession[]>([])
  const [workspaces, setWorkspaces] = useState<WorkspaceOpt[]>([])
  const [groups, setGroups] = useState<AccessGroup[]>([])

  const load = (): void => {
    void window.shellpilot?.aiMcp.listSessions().then((s) => setSessions(s ?? []))
    void window.shellpilot?.aiPolicy.listWorkspaces().then((w) => setWorkspaces(w ?? []))
    void window.shellpilot?.aiPolicy.listGroups().then((g) => setGroups(g ?? []))
  }

  useEffect(() => {
    load()
    const t = setInterval(load, 5000)
    return () => clearInterval(t)
  }, [])

  const killAll = async (): Promise<void> => {
    const result = await window.shellpilot?.aiMcp.killAllSessions()
    toast(result ? `Revoked ${result.revoked} session(s), denied ${result.denied} pending request(s)` : 'Failed')
    load()
  }

  return (
    <div className="settings-section">
      <h2>{sessionsOnly ? 'Active Sessions' : 'AI Agents'}</h2>
      <div className="sub">
        {sessionsOnly
          ? 'Every agent currently authorized to talk to ShellPilot, with its workspace and access group.'
          : 'Create a scoped session for each AI client, then paste its token into that client\'s MCP configuration.'}
      </div>

      {!sessionsOnly && <CreateSessionForm workspaces={workspaces} groups={groups} onCreated={load} />}

      {sessions.length === 0 && <div className="s-desc">No sessions yet.</div>}

      {sessions.map((s) => (
        <div className="list-row" key={s.id}>
          <div>
            <div className="r-title">{s.agentName}</div>
            <div className="r-sub">
              Workspace: {s.workspaceName} · Access group: {s.groupName} · Started {fmtTime(s.createdAt)}
              {s.expiresAt ? ` · Expires ${fmtTime(s.expiresAt)}` : ' · No expiration'}
            </div>
          </div>
          <div className="spacer" />
          <div className="r-stat">{isLive(s) ? 'Active' : s.revoked ? 'Revoked' : 'Expired'}</div>
          <button
            className="btn sm danger"
            disabled={!isLive(s)}
            onClick={async () => {
              await window.shellpilot?.aiMcp.revokeSession(s.id)
              toast(`Revoked ${s.agentName}`)
              load()
            }}
          >
            <Ban size={13} /> Revoke
          </button>
        </div>
      ))}

      {sessions.some(isLive) && (
        <button className="btn danger" style={{ marginTop: 18 }} onClick={killAll}>
          <Octagon size={14} /> Stop all AI access
        </button>
      )}
    </div>
  )
}
