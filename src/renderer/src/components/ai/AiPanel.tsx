import { useEffect, useState } from 'react'
import { LayoutDashboard, Users, ShieldCheck, Radio, CircleCheck, ScrollText, Lock } from 'lucide-react'
import { clsx } from '../../lib/format'
import { AiAgents } from './AiAgents'
import { AiAccessGroups } from './AiAccessGroups'
import { AiApprovals } from './AiApprovals'
import { AiAuditLog } from './AiAuditLog'
import { AiSecurity } from './AiSecurity'
import { ConnectAgent } from './ConnectAgent'
import { useNav } from '../../store/nav'
import type { AiSection } from '../../store/nav'
import type { McpAgentSession, ApprovalRequest } from '../../../../shared/mcp'

const SECTIONS: { id: AiSection; label: string; icon: React.JSX.Element }[] = [
  { id: 'overview', label: 'Overview', icon: <LayoutDashboard size={16} /> },
  { id: 'agents', label: 'AI Agents', icon: <Users size={16} /> },
  { id: 'groups', label: 'Access Groups', icon: <ShieldCheck size={16} /> },
  { id: 'sessions', label: 'Active Sessions', icon: <Radio size={16} /> },
  { id: 'approvals', label: 'Approvals', icon: <CircleCheck size={16} /> },
  { id: 'audit', label: 'Audit Log', icon: <ScrollText size={16} /> },
  { id: 'security', label: 'Security', icon: <Lock size={16} /> }
]

function Overview(): React.JSX.Element {
  const [sessions, setSessions] = useState<McpAgentSession[]>([])
  const [approvals, setApprovals] = useState<ApprovalRequest[]>([])
  const [status, setStatus] = useState<{ running: boolean; port: number | null }>({ running: false, port: null })

  const load = (): void => {
    void window.shellpilot?.aiMcp.listSessions().then((s) => setSessions(s ?? []))
    void window.shellpilot?.aiMcp.listApprovals().then((a) => setApprovals(a ?? []))
    void window.shellpilot?.aiMcp.status().then((s) => s && setStatus(s))
  }

  useEffect(() => {
    load()
    const t = setInterval(load, 4000)
    return () => clearInterval(t)
  }, [])

  const active = sessions.filter((s) => !s.revoked && (!s.expiresAt || new Date(s.expiresAt) > new Date()))

  return (
    <div className="settings-section">
      <h2>AI & MCP</h2>
      <div className="sub">
        Let AI agents like Claude Code, Codex, Gemini CLI and other MCP-compatible clients operate your
        servers through ShellPilot — without ever seeing an SSH password, private key or database
        credential. ShellPilot resolves the friendly names, enforces access-group policy and asks for
        your approval on anything sensitive.
      </div>

      <div className="card-grid" style={{ marginTop: 18 }}>
        <div className="card">
          <div className="s-title">Bridge status</div>
          <div className="s-desc">{status.running ? `Running on 127.0.0.1:${status.port}` : 'Disabled'}</div>
        </div>
        <div className="card">
          <div className="s-title">Active sessions</div>
          <div className="s-desc">{active.length} of {sessions.length} connected agent session(s)</div>
        </div>
        <div className="card">
          <div className="s-title">Pending approvals</div>
          <div className="s-desc">{approvals.length} action(s) waiting on you</div>
        </div>
      </div>

      <ConnectAgent onConnected={load} />

      <h3 style={{ marginTop: 24 }}>How it works</h3>
      <ol className="s-desc" style={{ lineHeight: 1.8 }}>
        <li>Create an access group (or use a default) describing what AI is allowed to do.</li>
        <li>Assign your workspaces/servers to an access group — most servers default to No AI Access.</li>
        <li>Create an AI Agent session scoped to one or more workspaces and an access group, and copy its token.</li>
        <li>Point Claude Code, Codex or another MCP client at ShellPilot's local MCP server with that token.</li>
        <li>Approve or deny sensitive actions as they come up — the AI waits for your answer.</li>
      </ol>
      <div className="s-desc">
        <b>Connect an agent</b> above does steps 1–4 in one click. Codex and Gemini CLI are still
        wired up by hand — <code className="mono">shellpilot codex</code>, or the snippet under AI
        Agents.
      </div>
    </div>
  )
}

export function AiPanel(): React.JSX.Element {
  // Held in the nav store rather than locally so a message elsewhere in the app
  // can send the user straight to the page that fixes it.
  const section = useNav((s) => s.aiSection)
  const setSection = useNav((s) => s.setAiSection)

  return (
    <div className="main">
      <div className="settings">
        <nav className="settings-nav">
          {SECTIONS.map((s) => (
            <button
              key={s.id}
              className={clsx('nav-item', section === s.id && 'active')}
              onClick={() => setSection(s.id)}
            >
              {s.icon}
              {s.label}
            </button>
          ))}
        </nav>
        <div className="settings-content">
          {section === 'overview' && <Overview />}
          {section === 'agents' && <AiAgents />}
          {section === 'groups' && <AiAccessGroups />}
          {section === 'sessions' && <AiAgents sessionsOnly />}
          {section === 'approvals' && <AiApprovals />}
          {section === 'audit' && <AiAuditLog />}
          {section === 'security' && <AiSecurity />}
        </div>
      </div>
    </div>
  )
}
