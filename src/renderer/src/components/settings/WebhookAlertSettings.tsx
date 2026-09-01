import { useEffect, useState } from 'react'
import { clsx } from '../../lib/format'
import type { WebhookConfig } from '../../../../shared/webhook'

// The URL is never read back across the bridge — main reports only whether one
// is set. It is a bearer credential (anyone holding a Slack webhook can post as
// you), so the renderer has no reason to hold its value and every reason not to.

export function WebhookAlertSettings(): React.JSX.Element {
  const [cfg, setCfg] = useState<WebhookConfig>({
    enabled: false,
    hasUrl: false,
    notifyOnResolved: true
  })
  const [draft, setDraft] = useState('')
  const [saveMsg, setSaveMsg] = useState<{ ok: boolean; text: string } | null>(null)
  const [testMsg, setTestMsg] = useState<{ ok: boolean; text: string } | null>(null)
  const [testing, setTesting] = useState(false)

  useEffect(() => {
    void window.shellpilot?.webhook?.status().then((s) => s && setCfg(s))
  }, [])

  const apply = async (next: Partial<WebhookConfig>): Promise<void> => {
    const merged = { ...cfg, ...next }
    setCfg(merged)
    const s = await window.shellpilot?.webhook?.configure({
      enabled: merged.enabled,
      notifyOnResolved: merged.notifyOnResolved
    })
    if (s) setCfg(s)
  }

  const saveUrl = async (): Promise<void> => {
    const res = await window.shellpilot?.webhook?.setUrl(draft)
    if (!res) return
    setSaveMsg(
      res.ok
        ? { ok: true, text: draft.trim() === '' ? 'Webhook URL removed.' : 'Saved.' }
        : { ok: false, text: res.error ?? 'Could not save.' }
    )
    if (res.ok) {
      setDraft('')
      setTestMsg(null)
      const s = await window.shellpilot?.webhook?.status()
      if (s) setCfg(s)
    }
  }

  const test = async (): Promise<void> => {
    setTesting(true)
    setTestMsg(null)
    const r = await window.shellpilot?.webhook?.test()
    setTesting(false)
    if (!r) return
    setTestMsg(
      r.ok
        ? { ok: true, text: `Delivered${r.status ? ` (HTTP ${r.status})` : ''}. Check the channel.` }
        : { ok: false, text: r.error ?? 'Delivery failed.' }
    )
  }

  return (
    <>
      <SettingRowSwitchLike>
        <div className="s-info">
          <div className="s-title">Send alerts to a webhook</div>
          <div className="s-desc">
            POSTs a small JSON message to any HTTPS endpoint — Slack, Discord, Teams and most
            alerting systems accept one. Only the server&rsquo;s name, what fired and when are sent;
            never a host, an IP, a log line or command output.
            {!cfg.hasUrl && ' Add a URL below to enable this.'}
          </div>
        </div>
        <label className="switch">
          <input
            type="checkbox"
            checked={cfg.enabled}
            disabled={!cfg.hasUrl}
            onChange={(e) => void apply({ enabled: e.target.checked })}
          />
          <span />
        </label>
      </SettingRowSwitchLike>

      <div className="setting-row">
        <div className="s-info">
          <div className="s-title">Webhook URL</div>
          <div className="s-desc">
            {cfg.hasUrl
              ? 'A URL is saved. It is stored with your other secrets and is never shown again — paste a new one to replace it, or save an empty field to remove it.'
              : 'Stored with your other secrets, not in settings or backups. https only, since the URL is itself a credential.'}
          </div>
          {saveMsg && (
            <div className={clsx('s-desc', saveMsg.ok ? 'ok' : 'danger')}>{saveMsg.text}</div>
          )}
        </div>
        <div className="row-actions">
          <input
            className="input"
            type="password"
            placeholder={cfg.hasUrl ? '••••••••  paste to replace' : 'https://hooks.slack.com/services/…'}
            value={draft}
            onChange={(e) => {
              setDraft(e.target.value)
              setSaveMsg(null)
            }}
          />
          <button className="btn" onClick={() => void saveUrl()}>
            Save
          </button>
        </div>
      </div>

      <div className="setting-row">
        <div className="s-info">
          <div className="s-title">Test delivery</div>
          <div className="s-desc">
            Sends one sample alert now, so a wrong URL is found here rather than during an incident.
          </div>
          {testMsg && (
            <div className={clsx('s-desc', testMsg.ok ? 'ok' : 'danger')}>{testMsg.text}</div>
          )}
        </div>
        <button className="btn" disabled={!cfg.hasUrl || testing} onClick={() => void test()}>
          {testing ? 'Sending…' : 'Send test'}
        </button>
      </div>

      <SettingRowSwitchLike>
        <div className="s-info">
          <div className="s-title">Also send when it recovers</div>
          <div className="s-desc">
            An alert with no resolution leaves the reader working out whether it is still happening.
          </div>
        </div>
        <label className="switch">
          <input
            type="checkbox"
            checked={cfg.notifyOnResolved}
            disabled={!cfg.enabled}
            onChange={(e) => void apply({ notifyOnResolved: e.target.checked })}
          />
          <span />
        </label>
      </SettingRowSwitchLike>
    </>
  )
}

// SettingSwitch owns its own label/desc props, and these rows need extra
// content under the description, so they use the same markup directly rather
// than growing that component a `children` escape hatch.
function SettingRowSwitchLike({ children }: { children: React.ReactNode }): React.JSX.Element {
  return <div className="setting-row">{children}</div>
}
