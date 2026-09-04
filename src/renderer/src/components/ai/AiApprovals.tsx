import { useEffect, useState } from 'react'
import { Check, X } from 'lucide-react'
import type { ApprovalRequest } from '../../../../shared/mcp'
import { bridgeOn } from '../../lib/bridge'

export function AiApprovals(): React.JSX.Element {
  // `null` until the first read comes back, NOT `[]`.
  //
  // This panel says "Nothing waiting on you right now", and that sentence is
  // the reason an operator walks away from this screen. Said before the read
  // returned, it is a claim about an agent that may be blocked on a decision
  // this very moment. Of the three screens in this app that assert an absence,
  // this is the one whose absence someone acts on.
  const [approvals, setApprovals] = useState<ApprovalRequest[] | null>(null)
  // A read that FAILED is not an empty list either, and it used to become one:
  // the promise had no rejection path, so a bridge error left the panel saying
  // nothing was waiting, for as long as it stayed open.
  const [unreadable, setUnreadable] = useState(false)

  const load = (): void => {
    void window.shellpilot?.aiMcp
      .listApprovals()
      .then((a) => {
        setApprovals(a ?? [])
        setUnreadable(false)
      })
      .catch(() => setUnreadable(true))
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

      {unreadable ? (
        <div className="s-desc state-unknown">
          The list of pending approvals could not be read, so this is not a statement that none are
          waiting.
        </div>
      ) : approvals === null ? (
        <div className="s-desc state-unknown">Checking for anything waiting…</div>
      ) : approvals.length === 0 ? (
        <div className="s-desc">Nothing waiting on you right now.</div>
      ) : null}

      {(approvals ?? []).map((a) => (
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
