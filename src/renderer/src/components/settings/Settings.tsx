import { useEffect, useState } from 'react'
import {
  Sliders,
  Palette,
  TerminalSquare,
  Server,
  KeyRound,
  Shield,
  FolderCog,
  Activity,
  Code2,
  Keyboard,
  Bell,
  Wrench,
  DatabaseBackup, Compass } from 'lucide-react'
import { useApp } from '../../store/app'
import type { ThemeMode } from '../../store/app'
import { clsx } from '../../lib/format'
import { ShortcutManager } from './ShortcutManager'
import { BackupPanel } from './BackupPanel'
import { UpdatePanel } from './UpdatePanel'
import { useOnboarding } from '../../store/onboarding'
import { SshSessions } from './SshSessions'
import { toast } from '../../store/toast'

const SECTIONS = [
  { id: 'general', label: 'General', icon: <Sliders size={16} /> },
  { id: 'appearance', label: 'Appearance', icon: <Palette size={16} /> },
  { id: 'terminal', label: 'Terminal', icon: <TerminalSquare size={16} /> },
  { id: 'connections', label: 'Connections', icon: <Server size={16} /> },
  { id: 'ssh', label: 'SSH', icon: <KeyRound size={16} /> },
  { id: 'security', label: 'Security', icon: <Shield size={16} /> },
  { id: 'sftp', label: 'SFTP', icon: <FolderCog size={16} /> },
  { id: 'monitoring', label: 'Monitoring', icon: <Activity size={16} /> },
  { id: 'editor', label: 'Editor', icon: <Code2 size={16} /> },
  { id: 'shortcuts', label: 'Keyboard Shortcuts', icon: <Keyboard size={16} /> },
  { id: 'backup', label: 'Backup & Restore', icon: <DatabaseBackup size={16} /> },
  { id: 'notifications', label: 'Notifications', icon: <Bell size={16} /> },
  { id: 'advanced', label: 'Advanced', icon: <Wrench size={16} /> }
] as const

type SectionId = (typeof SECTIONS)[number]['id']

// A toggle backed by real, persisted state — unlike `Toggle` below, which is
// still placeholder UI holding its value in local state.
function SettingSwitch({
  label,
  desc,
  checked,
  onChange
}: {
  label: string
  desc: string
  checked: boolean
  onChange: (v: boolean) => void
}): React.JSX.Element {
  return (
    <div className="setting-row">
      <div className="s-info">
        <div className="s-title">{label}</div>
        <div className="s-desc">{desc}</div>
      </div>
      <span className={clsx('switch', checked && 'on')} onClick={() => onChange(!checked)} />
    </div>
  )
}

// Real data: the SSH host keys trusted on first use. Forgetting one is how a
// user recovers after a server is legitimately rebuilt with a new key.
function KnownHosts(): React.JSX.Element {
  const [hosts, setHosts] = useState<{ id: string; fingerprint: string; addedAt: string }[]>([])

  const load = (): void => {
    void window.shellpilot?.knownHosts.list().then((h) => setHosts(h ?? []))
  }
  useEffect(load, [])

  return (
    <div style={{ marginBottom: 18 }}>
      <div className="setting-row">
        <div className="s-info">
          <div className="s-title">Trusted SSH host keys</div>
          <div className="s-desc">
            {hosts.length
              ? 'Connections are refused if a host presents a different key than the one saved here.'
              : 'No hosts trusted yet — the first connection to a server will ask.'}
          </div>
        </div>
        <button className="btn sm" onClick={load}>
          Refresh
        </button>
      </div>
      {hosts.map((h) => (
        <div className="setting-row" key={h.id}>
          <div className="s-info">
            <div className="s-title mono">{h.id}</div>
            <div className="s-desc mono" style={{ fontSize: 11 }}>
              {h.fingerprint}
            </div>
          </div>
          <button
            className="btn sm danger"
            onClick={async () => {
              await window.shellpilot?.knownHosts.forget(h.id)
              toast(`Forgot host key for ${h.id}`)
              load()
            }}
          >
            Forget
          </button>
        </div>
      ))}
    </div>
  )
}

function Toggle({ label, desc, initial = false }: { label: string; desc: string; initial?: boolean }): React.JSX.Element {
  const [on, setOn] = useState(initial)
  return (
    <div className="setting-row">
      <div className="s-info">
        <div className="s-title">{label}</div>
        <div className="s-desc">{desc}</div>
      </div>
      <span className={clsx('switch', on && 'on')} onClick={() => setOn((v) => !v)} />
    </div>
  )
}

export function Settings(): React.JSX.Element {
  const [section, setSection] = useState<SectionId>('appearance')
  const startTour = useOnboarding((s) => s.start)
  const theme = useApp((s) => s.theme)
  const setTheme = useApp((s) => s.setTheme)
  const settings = useApp((s) => s.settings)
  const setSettings = useApp((s) => s.setSettings)
  const zoomTerminal = useApp((s) => s.zoomTerminal)

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
          {section === 'general' && <UpdatePanel />}

          {section === 'general' && (
            <div className="settings-section">
              <h2>Walkthrough</h2>
              <div className="sub">A short tour of what is here and where it lives.</div>
              <div className="setting-row">
                <div className="s-info">
                  <div className="s-title">Show the walkthrough</div>
                  <div className="s-desc">
                    Runs once on a first launch. Reopen it here whenever you want — it switches to
                    each feature as it describes it, so nothing is hidden while you read.
                  </div>
                </div>
                <button className="btn sm" onClick={() => startTour()}>
                  <Compass size={13} /> Start walkthrough
                </button>
              </div>
            </div>
          )}

          {section === 'appearance' && (
            <div className="settings-section">
              <h2>Appearance</h2>
              <div className="sub">Theme and visual density.</div>
              <div className="setting-row">
                <div className="s-info">
                  <div className="s-title">Theme</div>
                  <div className="s-desc">Dark is the primary ShellPilot experience.</div>
                </div>
                <div className="segment">
                  {(['dark', 'light', 'system'] as ThemeMode[]).map((t) => (
                    <button
                      key={t}
                      className={clsx('seg-btn', theme === t && 'active')}
                      onClick={() => setTheme(t)}
                      style={{ textTransform: 'capitalize' }}
                    >
                      {t}
                    </button>
                  ))}
                </div>
              </div>
              <SettingSwitch
                label="Compact density"
                desc="Tighter rows and padding across trees, lists and the docked monitor. Font sizes are unchanged."
                checked={settings.compactDensity}
                onChange={(v) => setSettings({ compactDensity: v })}
              />
              <Toggle label="Show status bar" desc="Display the bottom status bar." initial />
              <Toggle label="Animated transitions" desc="Subtle motion on menus and modals." initial />
            </div>
          )}

          {section === 'terminal' && (
            <div className="settings-section">
              <h2>Terminal</h2>
              <div className="sub">Font, cursor and scrollback behaviour.</div>
              <div className="setting-row">
                <div className="s-info">
                  <div className="s-title">Font family</div>
                  <div className="s-desc">Monospace font used in the terminal.</div>
                </div>
                <select className="select" style={{ width: 220 }}>
                  <option>JetBrains Mono</option>
                  <option>SF Mono</option>
                  <option>Cascadia Code</option>
                  <option>Menlo</option>
                </select>
              </div>
              <div className="setting-row">
                <div className="s-info">
                  <div className="s-title">Font size</div>
                  <div className="s-desc">
                    Applies to open terminals immediately. Also <b>Ctrl +</b> / <b>Ctrl -</b> /{' '}
                    <b>Ctrl 0</b>, or Ctrl+scroll inside a terminal.
                  </div>
                </div>
                <div className="row" style={{ gap: 6 }}>
                  <button className="btn sm" onClick={() => zoomTerminal(-1)}>
                    −
                  </button>
                  <span className="mono" style={{ width: 34, textAlign: 'center' }}>
                    {settings.terminalFontSize}
                  </span>
                  <button className="btn sm" onClick={() => zoomTerminal(1)}>
                    +
                  </button>
                  <button className="btn sm" onClick={() => zoomTerminal('reset')}>
                    Reset
                  </button>
                </div>
              </div>
              <Toggle label="Cursor blink" desc="Blink the terminal cursor." initial />
              <Toggle label="Copy on select" desc="Automatically copy selected text." />
              <Toggle label="Scroll to bottom on output" desc="Follow new output automatically." initial />
            </div>
          )}

          {section === 'shortcuts' && (
            <div className="settings-section">
              <h2>Keyboard Shortcuts</h2>
              <div className="sub">Record a combination by clicking a shortcut. Conflicts are highlighted.</div>
              <SettingSwitch
                label="Include hidden workspaces in Ctrl+1…9"
                desc="When on, hidden workspaces take their place in the numbering and can be switched to by shortcut. When off, they are skipped and the numbers close up around them."
                checked={settings.switchHiddenWorkspaces}
                onChange={(v) => setSettings({ switchHiddenWorkspaces: v })}
              />
              <ShortcutManager />
            </div>
          )}

          {section === 'editor' && (
            <div className="settings-section">
              <h2>Editor</h2>
              <div className="sub">How remote files open from the Files view.</div>
              <div className="setting-row">
                <div className="s-info">
                  <div className="s-title">External editor command</div>
                  <div className="s-desc">
                    Run to open a remote file — <code>code</code> for VS Code, <code>subl</code>,{' '}
                    <code>nvim</code>, and so on. Leave empty to use the system default for the file
                    type. Saving in the editor uploads the file back automatically.
                  </div>
                </div>
                <input
                  className="input"
                  style={{ width: 180 }}
                  placeholder="system default"
                  value={settings.externalEditorCommand}
                  onChange={(e) => setSettings({ externalEditorCommand: e.target.value })}
                />
              </div>
              <SettingSwitch
                label="Open files externally by default"
                desc="Double-clicking a file in the Files view uses the external editor instead of the built-in inline editor."
                checked={settings.openFilesExternally}
                onChange={(v) => setSettings({ openFilesExternally: v })}
              />
            </div>
          )}

          {section === 'monitoring' && (
            <div className="settings-section">
              <h2>Monitoring</h2>
              <div className="sub">Host metrics and resource alerts.</div>
              <SettingSwitch
                label="Resource alerts"
                desc="Notify when a host's CPU or memory stays at or above the threshold. Repeats once a minute while it lasts, and clears itself on recovery."
                checked={settings.resourceAlertsEnabled}
                onChange={(v) => setSettings({ resourceAlertsEnabled: v })}
              />
              <div className="setting-row">
                <div className="s-info">
                  <div className="s-title">Alert threshold</div>
                  <div className="s-desc">
                    Alerts use metrics already being sampled, so they add no extra load. A host is
                    only sampled while its monitor is on screen.
                  </div>
                </div>
                <div className="segment">
                  {[70, 80, 90, 95].map((t) => (
                    <button
                      key={t}
                      className={clsx('seg-btn', settings.resourceAlertThreshold === t && 'active')}
                      disabled={!settings.resourceAlertsEnabled}
                      onClick={() => setSettings({ resourceAlertThreshold: t })}
                    >
                      {t}%
                    </button>
                  ))}
                </div>
              </div>
              <SettingSwitch
                label="Show monitor under the terminal"
                desc="Live CPU, memory, disk and network docked below the session. Sampling only runs for the visible tab."
                checked={settings.showMonitorStrip}
                onChange={(v) => setSettings({ showMonitorStrip: v })}
              />
            </div>
          )}

          {section === 'ssh' && (
            <div className="settings-section">
              <h2>SSH</h2>
              <div className="sub">Connection reuse and re-authentication policy.</div>
              <SshSessions />
            </div>
          )}

          {section === 'backup' && (
            <div className="settings-section">
              <h2>Backup &amp; Restore</h2>
              <div className="sub">Export an encrypted copy of everything, or restore from one.</div>
              <BackupPanel />
            </div>
          )}

          {section === 'security' && (
            <div className="settings-section">
              <h2>Vault</h2>
              <div className="sub">The encrypted store for passwords, SSH keys and API keys.</div>
              <div className="setting-row">
                <div className="s-info">
                  <div className="s-title">Lock after inactivity</div>
                  <div className="s-desc">
                    While the vault is unlocked its key is in memory and its entries are on screen.
                    Locking clears both. The timer counts vault inactivity, not time since you
                    started the app.
                  </div>
                </div>
                <select
                  className="input"
                  style={{ maxWidth: 160 }}
                  value={settings.vaultAutoLockMinutes}
                  onChange={(e) => setSettings({ vaultAutoLockMinutes: Number(e.target.value) })}
                >
                  <option value={5}>5 minutes</option>
                  <option value={15}>15 minutes</option>
                  <option value={30}>30 minutes</option>
                  <option value={60}>1 hour</option>
                  <option value={0}>Never</option>
                </select>
              </div>
            </div>
          )}

          {section === 'security' && (
            <div className="settings-section">
              <h2>Security</h2>
              <div className="sub">Credential storage and workspace locking.</div>
              <KnownHosts />
              <Toggle label="Store credentials in OS keychain" desc="Use the platform secure store — never plaintext." initial />
              <Toggle label="Auto-lock workspaces" desc="Lock password-protected workspaces after inactivity." initial />
              <div className="setting-row">
                <div className="s-info">
                  <div className="s-title">Auto-lock timeout</div>
                  <div className="s-desc">Minutes of inactivity before locking.</div>
                </div>
                <input className="input" style={{ width: 80 }} defaultValue="15" />
              </div>
              <Toggle label="Confirm destructive commands" desc="Require confirmation for rm, systemctl stop, etc." initial />
            </div>
          )}

          {![
            'general',
            'appearance',
            'terminal',
            'shortcuts',
            'security',
            'editor',
            'backup',
            'ssh',
            'monitoring'
          ].includes(section) && (
            <div className="settings-section">
              <h2>{SECTIONS.find((s) => s.id === section)?.label}</h2>
              <div className="sub">Configure {section} preferences for this workspace.</div>
              <Toggle label={`Enable ${section} features`} desc="Turn this subsystem on." initial />
              <Toggle label="Sync across workspaces" desc="Share these settings between workspaces." />
              <div className="setting-row">
                <div className="s-info">
                  <div className="s-title">Reset {section}</div>
                  <div className="s-desc">Restore defaults for this section.</div>
                </div>
                <button className="btn sm" onClick={() => toast('Section reset')}>
                  Reset
                </button>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
