import { useEffect, useState } from 'react'
import type { AuditEntry } from '../../../../shared/mcp'

function resultColor(r: AuditEntry['result']): string {
  if (r === 'success') return 'var(--text-success, #3fb950)'
  if (r === 'denied') return 'var(--text-danger, #f85149)'
  return 'var(--text-warning, #d29922)'
}

export function AiAuditLog(): React.JSX.Element {
  const [entries, setEntries] = useState<AuditEntry[]>([])

  const load = (): void => {
    void window.shellpilot?.aiMcp.listAudit(300).then((e) => setEntries(e ?? []))
  }
  useEffect(() => {
    load()
    const t = setInterval(load, 5000)
    return () => clearInterval(t)
  }, [])

  return (
    <div className="settings-section">
      <h2>Audit Log</h2>
      <div className="sub">
        Every AI action ShellPilot processed, whether allowed, approved, denied or failed. Never
        includes passwords, keys or other secrets.
      </div>

      {entries.length === 0 && <div className="s-desc">No AI activity recorded yet.</div>}

      {entries.length > 0 && (
        <table className="table">
          <thead>
            <tr>
              <th>Time</th>
              <th>Agent</th>
              <th>Workspace / Server</th>
              <th>Action</th>
              <th>Approval</th>
              <th>Result</th>
            </tr>
          </thead>
          <tbody>
            {entries.map((e) => (
              <tr key={e.id}>
                <td className="mono">{new Date(e.timestamp).toLocaleString()}</td>
                <td>{e.agentName}</td>
                <td>
                  {e.workspaceName ?? '—'} / {e.serverName ?? '—'}
                </td>
                <td className="mono">{e.action}</td>
                <td>{e.approval}</td>
                <td style={{ color: resultColor(e.result) }}>
                  {e.result}
                  {e.exitCode !== undefined ? ` (${e.exitCode})` : ''}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  )
}
