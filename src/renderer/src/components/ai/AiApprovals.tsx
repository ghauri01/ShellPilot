import { useEffect, useState } from 'react'
import { Check, X } from 'lucide-react'
import type { ApprovalRequest } from '../../../../shared/mcp'
import { bridgeOn } from '../../lib/bridge'

export function AiApprovals(): React.JSX.Element {
  const [approvals, setApprovals] = useState<ApprovalRequest[]>([])

  const load = (): void => {
    void window.shellpilot?.aiMcp.listApprovals().then((a) => setApprovals(a ?? []))
  }

  useEffect(() => {
    load()
    const off = bridgeOn('aiMcp.onApprovalEvent', window.shellpilot?.aiMcp?.onApprovalEvent, load)
    const t = setInterval(load, 3000)
    return () => {
      off?.()
      clearInterval(t)
    }
  }, [])

  const respond = async (id: string, decision: 'approved' | 'denied'): Promise<void> => {
    await window.shellpilot?.aiMcp.respondApproval(id, decision)
    load()
  }

  return (
    <div className="settings-section">
      <h2>Approvals</h2>
      <div className="sub">
        Actions an access group marked ASK wait here for your decision. An AI agent can never approve
        its own request — only this UI can.
      </div>

      {approvals.length === 0 && <div className="s-desc">Nothing waiting on you right now.</div>}

      {approvals.map((a) => (
        <div className="list-row" key={a.id}>
          <div>
            <div className="r-title">{a.agentName}</div>
            <div className="r-sub">
              {a.workspaceName} / {a.serverName} · risk: {a.risk.toUpperCase()}
            </div>
            <div className="r-sub mono">{a.action}</div>
          </div>
          <div className="spacer" />
          <button className="btn sm danger" onClick={() => respond(a.id, 'denied')}>
            <X size={13} /> Deny
          </button>
          <button className="btn sm primary" onClick={() => respond(a.id, 'approved')}>
            <Check size={13} /> Approve once
          </button>
        </div>
      ))}
    </div>
  )
}
