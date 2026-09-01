import { useEffect, useState } from 'react'
import { clsx, duration } from '../../lib/format'
import { useApp } from '../../store/app'
import type { WebhookConfig, WebhookDeliveryStatus } from '../../../../shared/webhook'

// The URL is never read back across the bridge — main reports only whether one
// is set. It is a bearer credential (anyone holding a Slack webhook can post as
// you), so the renderer has no reason to hold its value and every reason not to.

// Tone of a line under a setting. Not a boolean, because "the test was
// delivered but nothing else will be" is neither a success nor a failure, and
// showing it in green is how a user concludes they are covered when they are
// not.
type Tone = 'ok' | 'warn' | 'danger'

export function WebhookAlertSettings(): React.JSX.Element {
  const [cfg, setCfg] = useState<WebhookConfig>({
    enabled: false,
    hasUrl: false,
    notifyOnResolved: true
  })
  const [delivery, setDelivery] = useState<WebhookDeliveryStatus | null>(null)
  const [draft, setDraft] = useState('')
  const [saveMsg, setSaveMsg] = useState<{ tone: Tone; text: string } | null>(null)
  const [testMsg, setTestMsg] = useState<{ tone: Tone; text: string } | null>(null)
  const [testing, setTesting] = useState(false)
  // The master gate. Every webhook here is posted from inside checkResourceAlerts
  // or checkUnitAlerts, and both return early when this is off.
  const alertsEnabled = useApp((s) => s.settings.resourceAlertsEnabled)
  const setSettings = useApp((s) => s.setSettings)

  useEffect(() => {
    void window.shellpilot?.webhook?.status().then((s) => s && setCfg(s))
  }, [])

  // What actually happened to the alerts this endpoint was supposed to carry.
  // Polled while the pane is open, not pushed: deliveries happen on the alert
  // path, which has nothing to tell a settings screen, and the numbers move on
  // the order of an alert rather than a frame. The interval dies with the pane.
  useEffect(() => {
    let live = true
    const read = (): void => {
      void window.shellpilot?.webhook?.delivery().then((d) => {
        if (live && d) setDelivery(d)
      })
    }
    read()
    const t = setInterval(read, 10_000)
    return () => {
      live = false
      clearInterval(t)
    }
  }, [])

  const apply = async (next: Partial<WebhookConfig>): Promise<void> => {
    const merged = { ...cfg, ...next }
    setCfg(merged)
    // Main holds these in memory only, and FleetWatcher pushes the persisted
    // copy back to it on every mount. Writing settings here as well is what
    // makes the switch survive a restart — without it the next launch pushed
    // the untouched default and silently turned the webhook off again.
    setSettings({
      webhookAlertsEnabled: merged.enabled,
      webhookNotifyOnResolved: merged.notifyOnResolved
    })
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
        ? { tone: 'ok', text: draft.trim() === '' ? 'Webhook URL removed.' : 'Saved.' }
        : { tone: 'danger', text: res.error ?? 'Could not save.' }
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
    if (!r.ok) {
      setTestMsg({ tone: 'danger', text: r.error ?? 'Delivery failed.' })
      return
    }
    // The test posts whatever the switches say, because a URL is worth checking
    // before you commit to it. That makes an unqualified "Delivered" a lie by
    // omission: the message lands in the channel, the user concludes alerting
    // is wired, and nothing is ever sent again.
    const off: string[] = []
    if (!alertsEnabled) off.push('Alerts')
    if (!cfg.enabled) off.push('Send alerts to a webhook')
    const delivered = `Delivered${r.status ? ` (HTTP ${r.status})` : ''}. Check the channel.`
    setTestMsg(
      off.length === 0
        ? { tone: 'ok', text: delivered }
        : {
            tone: 'warn',
            text: `${delivered} Nothing else will be sent, though — the test ignores the switches, and ${off.join(' and ')} ${off.length === 1 ? 'is' : 'are'} off.`
          }
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
          <div className="s-desc">
            It carries what Alerts raises, so that switch has to be on too. And nothing is raised
            while you are elsewhere unless servers are checked in the background — so with that off,
            this stays silent in exactly the case you set it up for.
          </div>
        </div>
        {/* `.switch` is a styled span with an `.on` class; there is no
            `:checked` selector anywhere in the stylesheet. These three rows
            used a <label><input type=checkbox> instead, which meant they never
            showed their on state and drew a raw checkbox over the pill. */}
        <span
          className={clsx('switch', cfg.enabled && 'on', !cfg.hasUrl && 'disabled')}
          onClick={() => {
            if (cfg.hasUrl) void apply({ enabled: !cfg.enabled })
          }}
        />
      </SettingRowSwitchLike>

      <div className="setting-row">
        <div className="s-info">
          <div className="s-title">Webhook URL</div>
          <div className="s-desc">
            {cfg.hasUrl
              ? 'A URL is saved. It is stored with your other secrets and is never shown again — paste a new one to replace it, or save an empty field to remove it.'
              : 'Stored with your other secrets, not in settings or backups. https only, since the URL is itself a credential.'}
          </div>
          {saveMsg && <div className={clsx('s-desc', saveMsg.tone)}>{saveMsg.text}</div>}
        </div>
        <div className="input-group" style={{ width: 300 }}>
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
          {testMsg && <div className={clsx('s-desc', testMsg.tone)}>{testMsg.text}</div>}
          <DeliveryLines delivery={delivery} hasUrl={cfg.hasUrl} />
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
        <span
          className={clsx('switch', cfg.notifyOnResolved && cfg.enabled && 'on', !cfg.enabled && 'disabled')}
          onClick={() => {
            if (cfg.enabled) void apply({ notifyOnResolved: !cfg.notifyOnResolved })
          }}
        />
      </SettingRowSwitchLike>
    </>
  )
}

// What the endpoint has actually received, next to the button that claims it
// works. `dropped` in particular: shared/webhook.ts keeps that counter because
// an alerting path that silently discards is worse than one that does not
// exist, and until this it was counted and never shown to anybody.
function DeliveryLines({
  delivery,
  hasUrl
}: {
  delivery: WebhookDeliveryStatus | null
  hasUrl: boolean
}): React.JSX.Element | null {
  if (!delivery || !hasUrl) return null
  const lines: { tone?: Tone; text: string }[] = []
  if (delivery.dropped > 0) {
    lines.push({
      tone: 'danger',
      text: `${delivery.dropped} alert${delivery.dropped === 1 ? '' : 's'} dropped since launch. More than 30 in one minute are discarded rather than queued, so those were never delivered.`
    })
  }
  if (delivery.lastError) {
    lines.push({ tone: 'danger', text: `Last delivery failed: ${delivery.lastError}` })
  } else if (delivery.lastSentAt) {
    lines.push({ tone: 'ok', text: `Last alert delivered ${duration(delivery.lastSentAt)} ago.` })
  } else if (delivery.dropped === 0) {
    // Uncoloured on purpose: nothing has fired is the ordinary state, not a
    // warning. It is here so a quiet endpoint reads as quiet rather than
    // unknown.
    lines.push({ text: 'No alert has been delivered since launch.' })
  }
  return (
    <>
      {lines.map((l) => (
        <div key={l.text} className={clsx('s-desc', l.tone)}>
          {l.text}
        </div>
      ))}
    </>
  )
}

// SettingSwitch owns its own label/desc props, and these rows need extra
// content under the description, so they use the same markup directly rather
// than growing that component a `children` escape hatch.
function SettingRowSwitchLike({ children }: { children: React.ReactNode }): React.JSX.Element {
  return <div className="setting-row">{children}</div>
}
