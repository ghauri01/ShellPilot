import { useEffect, useState } from 'react'
import { Copy, TriangleAlert, Terminal, MonitorSmartphone, SquareTerminal } from 'lucide-react'
import { toast } from '../../store/toast'
import type { ToastAction } from '../../store/toast'
import { useApp } from '../../store/app'
import { openAi, openSettings } from '../../store/nav'
import type { AccessGroup } from '../../../../shared/mcp'

type Target = 'claude-code' | 'claude-desktop' | 'codex'

interface Ready {
  target: Target
  command?: string
  path?: string
  backedUpTo?: string
}

// A failure carries the button that fixes it. Each step here fails for its own
// reason and each reason has its own next step, so the two travel together
// rather than the catch block guessing from the wording of a message.
class StepError extends Error {
  readonly action?: ToastAction
  constructor(message: string, action?: ToastAction) {
    super(message)
    this.action = action
  }
}

// Claude Desktop and Codex both launch MCP servers as stdio subprocesses and
// have nowhere to put a bearer token for a local URL, so both get the bridge
// entry written into their own config file. Only Claude Code speaks Streamable
// HTTP directly, which is why it gets a command to paste instead.
const FILE_CLIENTS: Record<'claude-desktop' | 'codex', string> = {
  'claude-desktop': 'Claude Desktop',
  codex: 'Codex'
}

const TARGETS: { id: Target; label: string; agentName: string; icon: React.JSX.Element }[] = [
  { id: 'claude-code', label: 'Connect Claude Code', agentName: 'Claude Code', icon: <Terminal size={13} /> },
  {
    id: 'claude-desktop',
    label: 'Connect Claude Desktop',
    agentName: 'Claude Desktop',
    icon: <MonitorSmartphone size={13} />
  },
  { id: 'codex', label: 'Connect Codex', agentName: 'Codex', icon: <SquareTerminal size={13} /> }
]

// Everything under "How it works" — enable the bridge, give the workspaces an
// access group, mint a session, hand the token to the client — collapsed into
// one button per client. Done by hand it spans three tabs, and skipping the
// assignment step leaves an agent that connects successfully and is then denied
// on every single call, which reads as a broken integration rather than an
// empty policy.
export function ConnectAgent({ onConnected }: { onConnected?: () => void }): React.JSX.Element {
  const [groups, setGroups] = useState<AccessGroup[]>([])
  const [groupId, setGroupId] = useState('')
  const [busy, setBusy] = useState<Target | null>(null)
  const [ready, setReady] = useState<Ready | null>(null)
  const [error, setError] = useState<{ text: string; action?: ToastAction } | null>(null)

  useEffect(() => {
    void window.shellpilot?.aiPolicy.listGroups().then((g) => {
      const list = g ?? []
      setGroups(list)
      // Read & Write rather than Read Only, because a session's group is fixed
      // for its whole life and Read Only cannot add a server however the
      // workspace is later configured — so the one-click path could never use
      // add_server, and the only symptom was a denial that pointed at settings
      // which do not affect an existing connection. Nothing here is granted
      // silently: every mutating capability in Read & Write is ASK, so writes,
      // uploads, tunnels and adding a server each still raise an approval
      // prompt. The picker is right there for anyone who wants narrower.
      setGroupId((prev) => prev || list.find((x) => x.id === 'grp-read-write')?.id || list[0]?.id || '')
    })
  }, [])

  const connect = async (target: Target, agentName: string): Promise<void> => {
    const api = window.shellpilot
    if (!api) return
    setBusy(target)
    setError(null)
    setReady(null)
    try {
      const config = await api.aiMcp.getConfig()
      if (!config.enabled) {
        const result = await api.aiMcp.setConfig({ enabled: true })
        if (result.error) {
          throw new StepError(
            `ShellPilot could not listen on port ${config.port}: ${result.error}. Another program is probably using it.`,
            { label: 'Change the port', run: () => openAi('security') }
          )
        }
      }

      const status = await api.aiMcp.status()
      if (!status?.running || !status.port) {
        throw new StepError('AI & MCP access did not start, so there is nothing for the agent to connect to.', {
          label: 'Open AI settings',
          run: () => openAi('security')
        })
      }

      const workspaces = (await api.aiPolicy.listWorkspaces()) ?? []
      if (workspaces.length === 0) {
        throw new StepError('There are no workspaces yet, and an agent session has to be scoped to at least one.', {
          label: 'Open Connections',
          run: () => useApp.getState().setActivity('connections')
        })
      }

      const group = groups.find((g) => g.id === groupId) ?? null

      // Without an assignment resolveGroupId() returns null and every tool call
      // is denied with "No AI access is assigned to this server", so a
      // connection that looks fine does nothing. Only ever fills gaps — a
      // workspace the user has already assigned (to No AI Access included) is
      // left exactly as they set it.
      const assignments = (await api.aiPolicy.listAssignments()) ?? []
      const assigned = new Set(
        assignments.filter((a) => a.scope.level === 'workspace').map((a) => (a.scope as { workspaceId: string }).workspaceId)
      )
      for (const w of workspaces) {
        if (!assigned.has(w.id)) {
          await api.aiPolicy.setAssignment({ level: 'workspace', workspaceId: w.id }, group?.id ?? null)
        }
      }

      const created = await api.aiMcp.createSession({
        agentName,
        workspaces: workspaces.map((w) => ({ id: w.id, name: w.name })),
        groupId: group?.id ?? null,
        groupName: group?.name ?? 'No AI Access',
        // A config-file client has no way to re-pair when a token lapses — it
        // would just stop working silently. Revoke under Active Sessions
        // instead, which is visible and deliberate.
        ttlMinutes: null
      })
      if (!created) {
        throw new StepError('ShellPilot could not issue a session for this agent.', {
          label: 'Create one by hand',
          run: () => openAi('agents')
        })
      }

      if (target === 'claude-code') {
        const command = await api.aiMcp.claudeCodeCommand(created.token, status.port)
        await navigator.clipboard.writeText(command)
        setReady({ target, command })
        toast('Command copied — paste it in a terminal')
      } else {
        const label = FILE_CLIENTS[target]
        const write = target === 'codex' ? api.aiMcp.writeCodexConfig : api.aiMcp.writeClaudeDesktopConfig
        if (typeof write !== 'function') {
          throw new StepError(`This build of ShellPilot cannot configure ${label} for you.`, {
            label: 'Check for updates',
            run: () => openSettings('general')
          })
        }
        const result = await write(created.token, status.port)
        // Nothing in the app can fix a config file it is not allowed to write,
        // so this one says what happened and stops there rather than offering a
        // button that would do nothing.
        if (!result.ok) throw new StepError(result.error ?? `The ${label} config file could not be written.`)
        setReady({ target, path: result.path, backedUpTo: result.backedUpTo })
        toast(`${label} is configured. Quit it and open it again to pick ShellPilot up.`, 'ok')
      }
      onConnected?.()
    } catch (err) {
      setError({
        text: err instanceof Error ? err.message : String(err),
        action: err instanceof StepError ? err.action : undefined
      })
    } finally {
      setBusy(null)
    }
  }

  return (
    <div style={{ marginTop: 24 }}>
      <h3>Connect an agent</h3>
      <div className="s-desc" style={{ marginBottom: 12 }}>
        Turns on the bridge, gives every workspace an access group if it has none, creates a session
        and hands it to the client. The session does not expire — revoke it under Active Sessions.
      </div>

      <div className="setting-row">
        <div className="s-info">
          <div className="s-title">Access group</div>
          <div className="s-desc">
            The ceiling for what the agent can do. Applied to any workspace that has no group yet;
            workspaces you have already assigned are left alone.
            <br />
            <b>Fixed for the life of the session.</b> Changing access groups later does not affect a
            connection that already exists — you would revoke it under Active Sessions and connect
            again.
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

      <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', marginTop: 4 }}>
        {TARGETS.map((t) => (
          <button
            key={t.id}
            className="btn sm primary"
            disabled={busy !== null}
            onClick={() => void connect(t.id, t.agentName)}
          >
            {t.icon} {busy === t.id ? 'Connecting…' : t.label}
          </button>
        ))}
      </div>

      {error && (
        <div className="setting-row" style={{ marginTop: 12, alignItems: 'flex-start' }}>
          <div className="s-info">
            <div className="s-title">
              <TriangleAlert size={13} /> Could not connect
            </div>
            <div className="s-desc">{error.text}</div>
          </div>
          {error.action && (
            <button className="btn sm primary" onClick={error.action.run}>
              {error.action.label}
            </button>
          )}
        </div>
      )}

      {ready?.target === 'claude-code' && ready.command && (
        <div className="settings-section" style={{ marginTop: 12 }}>
          <h3>Claude Code</h3>
          <div className="s-desc">
            Copied to your clipboard. Paste it into a terminal — it registers ShellPilot with Claude
            Code for every project. The token is in that command and is shown only once here.
          </div>
          <div className="setting-row">
            <div className="s-info">
              <div className="s-title mono" style={{ wordBreak: 'break-all' }}>
                {ready.command}
              </div>
            </div>
            <button
              className="btn sm"
              onClick={() => {
                void navigator.clipboard.writeText(ready.command ?? '')
                toast('Command copied')
              }}
            >
              <Copy size={13} /> Copy again
            </button>
          </div>
        </div>
      )}

      {ready && ready.target !== 'claude-code' && ready.path && (
        <div className="settings-section" style={{ marginTop: 12 }}>
          <h3>{FILE_CLIENTS[ready.target]}</h3>
          <div className="s-desc">
            Written to <code className="mono">{ready.path}</code>. That file is only read at
            startup, so quit the app completely and reopen it — ShellPilot then appears in its
            tools.
            {ready.backedUpTo ? (
              <>
                {' '}
                The previous file was copied to <code className="mono">{ready.backedUpTo}</code>.
              </>
            ) : null}
          </div>
        </div>
      )}
    </div>
  )
}
