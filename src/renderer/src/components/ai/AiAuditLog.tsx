import { useEffect, useMemo, useState } from 'react'
import type { AuditEntry } from '../../../../shared/mcp'

function resultColor(r: AuditEntry['result']): string {
  if (r === 'success') return 'var(--text-success, #3fb950)'
  if (r === 'denied') return 'var(--text-danger, #f85149)'
  return 'var(--text-warning, #d29922)'
}

const FETCH_LIMIT = 2000
const ALL = '__all'

// <input type="date"> works in local time, but AuditEntry.timestamp is UTC
// ISO — convert the boundary at local midnight, not at UTC midnight, so a
// "from 2026-01-01" filter matches what the user actually typed.
function startOfLocalDay(dateStr: string): number {
  const d = new Date(dateStr)
  d.setHours(0, 0, 0, 0)
  return d.getTime()
}
function endOfLocalDay(dateStr: string): number {
  const d = new Date(dateStr)
  d.setHours(23, 59, 59, 999)
  return d.getTime()
}

export function AiAuditLog(): React.JSX.Element {
  const [entries, setEntries] = useState<AuditEntry[]>([])
  const [search, setSearch] = useState('')
  const [workspace, setWorkspace] = useState(ALL)
  const [server, setServer] = useState(ALL)
  const [from, setFrom] = useState('')
  const [to, setTo] = useState('')

  const load = (): void => {
    void window.shellpilot?.aiMcp.listAudit(FETCH_LIMIT).then((e) => setEntries(e ?? []))
  }
  useEffect(() => {
    load()
    const t = setInterval(load, 5000)
    return () => clearInterval(t)
  }, [])

  const workspaceOptions = useMemo(
    () => [...new Set(entries.map((e) => e.workspaceName).filter((w): w is string => !!w))].sort(),
    [entries]
  )
  const serverOptions = useMemo(() => {
    const inWorkspace = workspace === ALL ? entries : entries.filter((e) => e.workspaceName === workspace)
    return [...new Set(inWorkspace.map((e) => e.serverName).filter((s): s is string => !!s))].sort()
  }, [entries, workspace])

  // Changing workspace can strip out the currently-selected server; drop back
  // to "All servers" rather than silently filtering on a server that is no
  // longer a valid option for the chosen workspace.
  useEffect(() => {
    if (server !== ALL && !serverOptions.includes(server)) setServer(ALL)
  }, [serverOptions, server])

  const filtered = useMemo(() => {
    const fromMs = from ? startOfLocalDay(from) : null
    const toMs = to ? endOfLocalDay(to) : null
    const q = search.trim().toLowerCase()
    return entries.filter((e) => {
      if (workspace !== ALL && e.workspaceName !== workspace) return false
      if (server !== ALL && e.serverName !== server) return false
      const ts = new Date(e.timestamp).getTime()
      if (fromMs !== null && ts < fromMs) return false
      if (toMs !== null && ts > toMs) return false
      if (q) {
        const haystack = `${e.agentName} ${e.workspaceName ?? ''} ${e.serverName ?? ''} ${e.action}`.toLowerCase()
        if (!haystack.includes(q)) return false
      }
      return true
    })
  }, [entries, search, workspace, server, from, to])

  const filtersActive = search !== '' || workspace !== ALL || server !== ALL || from !== '' || to !== ''
  const clearFilters = (): void => {
    setSearch('')
    setWorkspace(ALL)
    setServer(ALL)
    setFrom('')
    setTo('')
  }

  return (
    <div className="settings-section">
      <h2>Audit Log</h2>
      <div className="sub">
        Every AI action ShellPilot processed, whether allowed, approved, denied or failed. Never
        includes passwords, keys or other secrets.
      </div>

      {entries.length === 0 && <div className="s-desc">No AI activity recorded yet.</div>}

      {entries.length > 0 && (
        <>
          <div className="setting-row" style={{ flexWrap: 'wrap', gap: 10 }}>
            <input
              className="input"
              style={{ flex: '2 1 220px' }}
              placeholder="Search agent, workspace, server or action…"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
            />
            <select className="input" style={{ flex: '1 1 160px' }} value={workspace} onChange={(e) => setWorkspace(e.target.value)}>
              <option value={ALL}>All workspaces</option>
              {workspaceOptions.map((w) => (
                <option key={w} value={w}>
                  {w}
                </option>
              ))}
            </select>
            <select className="input" style={{ flex: '1 1 160px' }} value={server} onChange={(e) => setServer(e.target.value)}>
              <option value={ALL}>All servers</option>
              {serverOptions.map((s) => (
                <option key={s} value={s}>
                  {s}
                </option>
              ))}
            </select>
            <input
              className="input"
              type="date"
              style={{ flex: '1 1 140px' }}
              value={from}
              max={to || undefined}
              onChange={(e) => setFrom(e.target.value)}
              aria-label="From date"
            />
            <input
              className="input"
              type="date"
              style={{ flex: '1 1 140px' }}
              value={to}
              min={from || undefined}
              onChange={(e) => setTo(e.target.value)}
              aria-label="To date"
            />
            {filtersActive && (
              <button className="btn sm" onClick={clearFilters}>
                Clear filters
              </button>
            )}
          </div>

          <div className="s-desc" style={{ marginBottom: 8 }}>
            {filtered.length === entries.length
              ? `${entries.length} entr${entries.length === 1 ? 'y' : 'ies'}`
              : `${filtered.length} of ${entries.length} entries match`}
          </div>

          {filtered.length === 0 && <div className="s-desc">No entries match these filters.</div>}

          {filtered.length > 0 && (
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
                {filtered.map((e) => (
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
        </>
      )}
    </div>
  )
}
