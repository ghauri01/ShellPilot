import { useEffect, useState } from 'react'
import { ChevronDown, ChevronRight } from 'lucide-react'
import { toast } from '../../store/toast'
import { clsx } from '../../lib/format'
import type { AccessGroup, McpAgentSession } from '../../../../shared/mcp'

interface Explanation {
  capability: string
  label: string
  decision: 'allow' | 'ask' | 'deny'
  reason: string
  fromScope: 'allow' | 'ask' | 'deny'
  fromSession: 'allow' | 'ask' | 'deny' | null
  decidedBy: 'scope' | 'session' | 'both'
}

const VERDICT: Record<string, string> = { allow: 'ALLOW', ask: 'ASK', deny: 'DENY' }

// Answers the question the permission model actually raises — "what can this
// agent do, and which of the two layers decided that" — in the place the user
// is already looking. Until now nothing in the app could answer it: the only
// thing that computed effective permissions was the get_server_details MCP
// tool, so the agent could see the answer and the person could not.
export function SessionAccess({
  session,
  groups,
  onChanged
}: {
  session: McpAgentSession
  groups: AccessGroup[]
  onChanged: () => void
}): React.JSX.Element {
  const [open, setOpen] = useState(false)
  const [rows, setRows] = useState<Explanation[] | null>(null)

  useEffect(() => {
    if (!open) return
    void window.shellpilot?.aiMcp
      .explainAccess?.(session.id, null)
      .then((r) => setRows((r as Explanation[] | null) ?? []))
  }, [open, session.id, session.groupId])

  const changeGroup = async (groupId: string): Promise<void> => {
    const group = groups.find((g) => g.id === groupId) ?? null
    const api = window.shellpilot?.aiMcp
    if (typeof api?.setSessionGroup !== 'function') {
      toast('This build cannot change a session ceiling — restart the app', 'error')
      return
    }
    await api.setSessionGroup(session.id, group?.id ?? null, group?.name ?? 'No AI Access')
    toast(`${session.agentName} ceiling is now ${group?.name ?? 'No AI Access'}`, 'ok')
    setRows(null)
    onChanged()
  }

  return (
    <div style={{ width: '100%' }}>
      <div className="row" style={{ gap: 8, alignItems: 'center', marginTop: 6 }}>
        <span className="s-desc">Ceiling</span>
        <select
          className="input"
          style={{ maxWidth: 180 }}
          value={session.groupId ?? ''}
          onChange={(e) => void changeGroup(e.target.value)}
        >
          {groups.map((g) => (
            <option key={g.id} value={g.id}>
              {g.name}
            </option>
          ))}
        </select>
        <button className="btn sm" onClick={() => setOpen((v) => !v)}>
          {open ? <ChevronDown size={13} /> : <ChevronRight size={13} />} Effective access
        </button>
      </div>

      {open && (
        <div style={{ marginTop: 8 }}>
          {rows === null && <div className="s-desc">Working it out…</div>}
          {rows?.length === 0 && <div className="s-desc">This session is scoped to no workspace.</div>}
          {rows && rows.length > 0 && (
            <table className="mini-table" style={{ width: '100%' }}>
              <thead>
                <tr>
                  <th>Capability</th>
                  <th>Workspace</th>
                  <th>This session</th>
                  <th>Result</th>
                </tr>
              </thead>
              <tbody>
                {rows.map((r) => (
                  <tr key={r.capability}>
                    <td>{r.label}</td>
                    <td className={clsx('mono', r.decidedBy === 'scope' && 'strong')}>{VERDICT[r.fromScope]}</td>
                    <td className={clsx('mono', r.decidedBy === 'session' && 'strong')}>
                      {r.fromSession ? VERDICT[r.fromSession] : '—'}
                    </td>
                    <td className="mono strong">{VERDICT[r.decision]}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
          <div className="s-desc" style={{ marginTop: 6 }}>
            The stricter of the two wins. The bolded column is the one that decided — if it is
            <b> This session</b>, changing access groups in Settings will not help; change the
            ceiling above instead.
          </div>
        </div>
      )}
    </div>
  )
}
