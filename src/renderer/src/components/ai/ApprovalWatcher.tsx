import { useEffect, useState } from 'react'
import { Modal } from '../common/Modal'
import type { ApprovalRequest } from '../../../../shared/mcp'
import { bridgeOn } from '../../lib/bridge'

// Mounted once at the app root so an approval request surfaces no matter
// which tab the user is on — an AI agent waiting on a sudo command should not
// require the user to already be looking at AI & MCP > Approvals.
export function ApprovalWatcher(): React.JSX.Element | null {
  const [queue, setQueue] = useState<ApprovalRequest[]>([])

  useEffect(() => {
    void window.shellpilot?.aiMcp.listApprovals().then((a) => setQueue(a ?? []))
    const off = bridgeOn('aiMcp.onApprovalEvent', window.shellpilot?.aiMcp?.onApprovalEvent, (e) => {
      if (e.type === 'created') setQueue((q) => [...q, e.request])
      else setQueue((q) => q.filter((r) => r.id !== e.request.id))
    })
    return () => off?.()
  }, [])

  const current = queue[0]
  if (!current) return null

  const respond = async (decision: 'approved' | 'denied'): Promise<void> => {
    await window.shellpilot?.aiMcp.respondApproval(current.id, decision)
    setQueue((q) => q.filter((r) => r.id !== current.id))
  }

  return (
    <Modal title="AI action requires approval" onClose={() => respond('denied')}>
      <div className="setting-row">
        <div className="s-info">
          <div className="s-title">Agent</div>
          <div className="s-desc">{current.agentName}</div>
        </div>
      </div>
      <div className="setting-row">
        <div className="s-info">
          <div className="s-title">Workspace / Server</div>
          <div className="s-desc">
            {current.workspaceName} / {current.serverName}
          </div>
        </div>
      </div>
      <div className="setting-row">
        <div className="s-info">
          <div className="s-title">Action</div>
          <div className="s-desc mono">{current.action}</div>
        </div>
      </div>
      <div className="setting-row">
        <div className="s-info">
          <div className="s-title">Risk</div>
          <div className="s-desc">{current.risk.toUpperCase()}</div>
        </div>
      </div>
      <div className="setting-row" style={{ marginTop: 12 }}>
        <button className="btn danger" onClick={() => respond('denied')}>
          Deny
        </button>
        <button className="btn primary" onClick={() => respond('approved')}>
          Approve once
        </button>
      </div>
      {queue.length > 1 && <div className="s-desc" style={{ marginTop: 8 }}>{queue.length - 1} more waiting</div>}
    </Modal>
  )
}
