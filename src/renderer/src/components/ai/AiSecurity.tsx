import { useEffect, useState } from 'react'
import { Copy, Octagon } from 'lucide-react'
import { clsx } from '../../lib/format'
import { toast } from '../../store/toast'
import type { McpGlobalConfig } from '../../../../shared/mcp'

function copy(text: string): void {
  navigator.clipboard.writeText(text)
  toast('Copied')
}

export function AiSecurity(): React.JSX.Element {
  const [config, setConfig] = useState<McpGlobalConfig | null>(null)
  const [status, setStatus] = useState<{ running: boolean; port: number | null }>({ running: false, port: null })

  const load = (): void => {
    void window.shellpilot?.aiMcp.getConfig().then((c) => c && setConfig(c))
    void window.shellpilot?.aiMcp.status().then((s) => s && setStatus(s))
  }
  useEffect(load, [])

  const update = async (patch: Partial<McpGlobalConfig>): Promise<void> => {
    const result = await window.shellpilot?.aiMcp.setConfig(patch)
    if (!result) return
    setConfig(result.config)
    if (result.error) toast(`Could not start MCP server: ${result.error}`)
    load()
  }

  const killAll = async (): Promise<void> => {
    const result = await window.shellpilot?.aiMcp.killAllSessions()
    toast(result ? `Stopped ${result.revoked} session(s)` : 'Failed')
  }

  if (!config) return <div className="settings-section" />

  const port = status.port ?? config.port
  const cliCommand = `claude mcp add --transport http shellpilot http://127.0.0.1:${port}/mcp --header "Authorization: Bearer <token>"`
  const jsonConfig = JSON.stringify(
    {
      mcpServers: {
        shellpilot: {
          type: 'http',
          url: `http://127.0.0.1:${port}/mcp`,
          headers: { Authorization: 'Bearer <token>' }
        }
      }
    },
    null,
    2
  )

  return (
    <div className="settings-section">
      <h2>Security</h2>
      <div className="sub">Global configuration for the ShellPilot MCP bridge itself.</div>

      <div className="setting-row">
        <div className="s-info">
          <div className="s-title">Enable AI & MCP access</div>
          <div className="s-desc">
            {status.running
              ? `Listening on 127.0.0.1:${port} — never reachable from outside this machine.`
              : 'Off. No AI agent can reach ShellPilot while disabled.'}
          </div>
        </div>
        <span
          className={clsx('switch', config.enabled && 'on')}
          onClick={() => update({ enabled: !config.enabled })}
        />
      </div>

      <div className="setting-row">
        <div className="s-info">
          <div className="s-title">Local port</div>
          <div className="s-desc">Restart the bridge (toggle it off and on) after changing this.</div>
        </div>
        <input
          className="input"
          style={{ width: 100 }}
          type="number"
          value={config.port}
          onChange={(e) => update({ port: Number(e.target.value) || config.port })}
        />
      </div>

      <div className="setting-row">
        <div className="s-info">
          <div className="s-title">Approval timeout</div>
          <div className="s-desc">How long an ASK action waits for you before it is treated as denied.</div>
        </div>
        <select
          className="input"
          value={config.approvalTimeoutSeconds}
          onChange={(e) => update({ approvalTimeoutSeconds: Number(e.target.value) })}
        >
          <option value={60}>1 minute</option>
          <option value={120}>2 minutes</option>
          <option value={300}>5 minutes</option>
          <option value={600}>10 minutes</option>
        </select>
      </div>

      <div className="setting-row">
        <div className="s-info">
          <div className="s-title">🚨 Stop all AI access</div>
          <div className="s-desc">
            Immediately revokes every active session and denies every pending approval request.
          </div>
        </div>
        <button className="btn danger" onClick={killAll}>
          <Octagon size={14} /> Stop all AI access
        </button>
      </div>

      <h3 style={{ marginTop: 24 }}>Connecting Claude Code</h3>
      <div className="s-desc">
        Create a session under AI & MCP → AI Agents to get a token, then run:
      </div>
      <div className="setting-row">
        <code className="mono" style={{ flex: 1, wordBreak: 'break-all' }}>
          {cliCommand}
        </code>
        <button className="btn sm" onClick={() => copy(cliCommand)}>
          <Copy size={13} />
        </button>
      </div>

      <h3 style={{ marginTop: 18 }}>Connecting Codex, Gemini CLI or another MCP client</h3>
      <div className="s-desc">
        Most MCP-compatible clients accept a Streamable HTTP server via JSON configuration, for example:
      </div>
      <div className="setting-row">
        <pre className="mono" style={{ flex: 1, whiteSpace: 'pre-wrap' }}>{jsonConfig}</pre>
        <button className="btn sm" onClick={() => copy(jsonConfig)}>
          <Copy size={13} />
        </button>
      </div>
      <div className="s-desc">
        Works the same way whether ShellPilot is installed normally or running in portable mode — the
        port and token are all any client needs.
      </div>

      <h3 style={{ marginTop: 18 }}>Or skip typing tokens: the ShellPilot CLI launcher</h3>
      <div className="s-desc">
        Install the CLI once (<code className="mono">npm install -g shellpilot</code>, or{' '}
        <code className="mono">npm install -g .</code> from this repo), then run{' '}
        <code className="mono">shellpilot claude</code> or <code className="mono">shellpilot codex</code>. The
        first run pops a one-time pairing code right here in ShellPilot — type it into the terminal and the
        session, token and MCP config are wired up for you. <code className="mono">shellpilot run -- &lt;command&gt;</code>{' '}
        works the same way for any other MCP-aware CLI.
      </div>
    </div>
  )
}
