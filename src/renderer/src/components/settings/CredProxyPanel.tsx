import { useCallback, useEffect, useState } from 'react'
import { clsx } from '../../lib/format'
import {
  CRED_PROXY_LOOPBACK_NOTE,
  CRED_PROXY_TOKEN_HEADER,
  CRED_PROXY_TOKEN_NOTE,
  CRED_PROXY_TOKEN_STATE_NOTE,
  credProxyTokenState,
  type CredProxyToken,
  credProxyBaseUrl,
  describeInjection
} from '../../../../shared/credproxy'
import type {
  CredProxyCall,
  CredProxyInjectionKind,
  CredProxyRule,
  CredProxySlot,
  CredProxyStatus
} from '../../../../shared/credproxy'
import type { VaultEntry } from '../../../../shared/vault'

// The API credential proxy — roadmap item 7, settings half.
//
// What this pane has to make true, beyond letting someone type a rule:
//
//  * The TOKEN's power is stated where the token is, in the sentence next to
//    the copy button, not in a docs page. A token whose holder has not been
//    told what it grants is a token that ends up in a chat window.
//  * "It is only on loopback" is not a permission, and the pane says so —
//    every process running as this user can reach the port.
//  * A rule reads as a SENTENCE about where a credential goes, because that is
//    the thing being authorised. "Billing API — https://api.stripe.com, key
//    from Stripe live key, sent as Authorization: Bearer."
//  * The recent calls are visible here rather than in a separate log, because
//    a rule that quietly stopped matching looks exactly like a rule that is
//    working until you look at whether anything went through it.

type Tone = 'ok' | 'warn' | 'danger'

const INJECTIONS: { kind: CredProxyInjectionKind; label: string; needs: string | null }[] = [
  { kind: 'bearer', label: 'Authorization: Bearer', needs: null },
  { kind: 'header', label: 'A named header', needs: 'Header name' },
  { kind: 'query', label: 'A query parameter', needs: 'Parameter name' },
  { kind: 'basic', label: 'Basic auth', needs: 'Username' }
]

const SLOTS: { slot: CredProxySlot; label: string }[] = [
  { slot: 'password', label: 'The entry’s API key / password' },
  { slot: 'privateKey', label: 'The entry’s key material' },
  { slot: 'username', label: 'The entry’s username' },
  { slot: 'field', label: 'A named custom field' }
]

interface Draft {
  id?: string
  name: string
  origin: string
  vaultEntryId: string
  slot: CredProxySlot
  fieldKey: string
  kind: CredProxyInjectionKind
  injectionName: string
}

const emptyDraft = (): Draft => ({
  name: '',
  origin: '',
  vaultEntryId: '',
  slot: 'password',
  fieldKey: '',
  kind: 'bearer',
  injectionName: ''
})

export function CredProxyPanel(): React.JSX.Element {
  const [status, setStatus] = useState<CredProxyStatus | null>(null)
  // `null` until read. The sentence this guards is REASSURING -- "the proxy
  // will refuse everything, that is the safe state" -- and a false reassurance
  // is worse than a false alarm: it tells an operator the credential proxy is
  // locked down at a moment when it may hold permissive rules nobody has
  // fetched yet.
  const [rules, setRules] = useState<CredProxyRule[] | null>(null)
  // And the case that would otherwise wait forever: no channel means no rules
  // are coming, which is a definite answer rather than a pending one.
  const [unavailable, setUnavailable] = useState(false)
  const [calls, setCalls] = useState<CredProxyCall[]>([])
  const [entries, setEntries] = useState<VaultEntry[]>([])
  // `null` until read, like every other list in this app that says an absence.
  const [tokens, setTokens] = useState<CredProxyToken[] | null>(null)
  const [newTokenName, setNewTokenName] = useState('')
  const [newTokenExpiry, setNewTokenExpiry] = useState('')

  const loadTokens = useCallback(async (): Promise<void> => {
    const list = await window.shellpilot?.credproxy?.tokens?.()
    setTokens(list ?? [])
  }, [])

  const createToken = async (): Promise<void> => {
    const res = await window.shellpilot?.credproxy?.createToken?.(
      newTokenName.trim(),
      // A date input gives a day, and a token should last to the END of the day
      // it names rather than expiring at midnight as somebody starts work.
      newTokenExpiry === '' ? null : new Date(`${newTokenExpiry}T23:59:59Z`).toISOString()
    )
    if (res?.ok && res.token) {
      await navigator.clipboard?.writeText(res.token).catch(() => {})
      setMsg({
        tone: 'ok',
        text: `Token for “${newTokenName.trim()}” created and copied. It is the only copy you need — ShellPilot keeps it too.`
      })
      setNewTokenName('')
      setNewTokenExpiry('')
      await loadTokens()
    } else {
      setMsg({ tone: 'danger', text: res?.error ?? 'Could not create the token.' })
    }
  }

  const copyToken = async (id: string): Promise<void> => {
    const value = await window.shellpilot?.credproxy?.tokenValue?.(id)
    if (value) {
      await navigator.clipboard?.writeText(value).catch(() => {})
      setMsg({ tone: 'ok', text: 'Token copied.' })
    } else {
      setMsg({ tone: 'danger', text: 'That token’s value could not be read.' })
    }
  }

  const revokeToken = async (id: string, name: string): Promise<void> => {
    // Revoking is not reversible and stops whatever holds it, so it asks --
    // and names the token, so the answer is to a question rather than a reflex.
    if (
      !window.confirm(
        `Revoke “${name}”?\n\nAnything still using this token starts being refused immediately, and it cannot be un-revoked. Other tokens are unaffected.`
      )
    ) {
      return
    }
    const res = await window.shellpilot?.credproxy?.revokeToken?.(id)
    if (res?.ok) {
      setMsg({ tone: 'ok', text: `“${name}” revoked.` })
      await loadTokens()
    } else {
      setMsg({ tone: 'danger', text: res?.error ?? 'Could not revoke the token.' })
    }
  }
  const [draft, setDraft] = useState<Draft | null>(null)
  const [msg, setMsg] = useState<{ tone: Tone; text: string } | null>(null)
  const [portDraft, setPortDraft] = useState('')

  const refresh = useCallback(async (): Promise<void> => {
    const api = window.shellpilot?.credproxy
    if (!api) {
      setUnavailable(true)
      return
    }
    setUnavailable(false)
    const [s, r, c] = await Promise.all([api.status(), api.rules(), api.calls(50)])
    if (s) {
      setStatus(s)
      setPortDraft(String(s.port))
    }
    if (r) setRules(r)
    if (c) setCalls(c)
  }, [])

  useEffect(() => {
    void refresh()
    void loadTokens()
  }, [refresh, loadTokens])

  // The vault list is read only to name entries in the picker. Its VALUES are
  // never used here — a rule stores an entry id, and main reads the credential
  // at request time.
  useEffect(() => {
    void window.shellpilot?.vault?.list().then((res) => {
      if (res?.ok && res.entries) setEntries(res.entries)
    })
  }, [])

  // Polled while the pane is open. Calls happen on the proxy's own path, which
  // has nothing to tell a settings screen, and they move on the order of a
  // request rather than a frame. The interval dies with the pane.
  useEffect(() => {
    const t = setInterval(() => void refresh(), 5_000)
    return () => clearInterval(t)
  }, [refresh])

  const toggle = async (on: boolean): Promise<void> => {
    setMsg(null)
    const api = window.shellpilot?.credproxy
    if (!api) return
    if (!on) {
      const s = await api.stop()
      if (s) setStatus(s)
      return
    }
    const port = Number(portDraft)
    const res = await api.start(Number.isInteger(port) && port > 0 ? port : undefined)
    if (!res) return
    if (res.status) setStatus(res.status)
    if (!res.ok) setMsg({ tone: 'danger', text: res.error ?? 'The listener could not start.' })
  }



  const save = async (): Promise<void> => {
    if (!draft) return
    setMsg(null)
    const res = await window.shellpilot?.credproxy?.saveRule({
      id: draft.id,
      name: draft.name,
      origin: draft.origin,
      credential: {
        vaultEntryId: draft.vaultEntryId,
        slot: draft.slot,
        ...(draft.slot === 'field' ? { fieldKey: draft.fieldKey } : {})
      },
      injection: { kind: draft.kind, name: draft.injectionName },
      enabled: true
    })
    if (!res) return
    if (!res.ok) {
      setMsg({ tone: 'danger', text: res.error })
      return
    }
    setDraft(null)
    await refresh()
  }

  const remove = async (id: string): Promise<void> => {
    await window.shellpilot?.credproxy?.removeRule(id)
    await refresh()
  }

  const entryName = (id: string): string =>
    entries.find((e) => e.id === id)?.name ?? 'a vault entry that is no longer there'

  const needs = INJECTIONS.find((i) => i.kind === draft?.kind)?.needs ?? null

  return (
    <div className="credproxy-panel">
      <div className="setting-row">
        <div className="s-info">
          <div className="s-title">API credential proxy</div>
          <div className="s-desc">
            A script, a dev server or an agent calls a third-party API through ShellPilot without
            ever holding the key. Point its base URL at the address below; the credential is added
            here, on the way out, and never comes back in a response.
            <br />
            Nothing is intercepted and no certificate is installed — a caller opts in by pointing at
            us, which is why an unconfigured tool is unaffected.
          </div>
        </div>
        <span
          className={clsx('switch', status?.listening && 'on')}
          role="switch"
          aria-checked={status?.listening ? 'true' : 'false'}
          aria-label="Run the API credential proxy"
          onClick={() => void toggle(!status?.listening)}
        />
      </div>

      <div className="setting-row">
        <div className="s-info">
          <div className="s-title">Port</div>
          <div className="s-desc">
            {status?.address
              ? `Listening on ${status.address}.`
              : 'Not listening. It binds 127.0.0.1 only.'}{' '}
            {CRED_PROXY_LOOPBACK_NOTE}
          </div>
        </div>
        <input
          className="input"
          style={{ width: 90 }}
          aria-label="Proxy port"
          value={portDraft}
          onChange={(e) => setPortDraft(e.target.value)}
          onBlur={() => {
            if (status?.listening) void toggle(true)
          }}
        />
      </div>

      {status?.parked && (
        <div className="s-note warn" role="status">
          {status.parked.reason === 'vault-locked'
            ? `The vault is locked, so ${status.parked.calls} call${status.parked.calls === 1 ? '' : 's'} ${status.parked.calls === 1 ? 'was' : 'were'} parked since ${new Date(status.parked.since).toLocaleTimeString()} rather than sent without a credential. Unlock it and they will go through.`
            : `A rule points at a vault entry that no longer holds anything. ${status.parked.calls} call${status.parked.calls === 1 ? '' : 's'} refused since ${new Date(status.parked.since).toLocaleTimeString()}.`}
        </div>
      )}

      <div className="setting-row">
        <div className="s-info">
          <div className="s-title">Tokens</div>
          <div className="s-desc">
            One per caller, sent as <code>{CRED_PROXY_TOKEN_HEADER}</code> on every request.{' '}
            {CRED_PROXY_TOKEN_NOTE}
            <br />
            Give each script or agent its own, so revoking one does not stop the others.
          </div>
        </div>
        <div className="row-actions">
          <input
            className="input"
            placeholder="What is it for"
            aria-label="Token name"
            value={newTokenName}
            onChange={(e) => setNewTokenName(e.target.value)}
            style={{ width: 190 }}
          />
          <input
            className="input"
            type="date"
            aria-label="Token end date (optional)"
            title="Optional end date. A token with no end date never expires."
            value={newTokenExpiry}
            onChange={(e) => setNewTokenExpiry(e.target.value)}
            style={{ width: 150 }}
          />
          <button className="btn primary" disabled={newTokenName.trim() === ''} onClick={() => void createToken()}>
            Create token
          </button>
        </div>
      </div>

      {tokens === null ? (
        <div className="s-note state-unknown">Reading the tokens…</div>
      ) : tokens.length === 0 ? (
        <div className="s-note">
          No tokens, so every request is refused. Create one above and give it to the script that
          needs it.
        </div>
      ) : (
        <ul className="credproxy-rules">
          {tokens.map((t) => {
            const state = credProxyTokenState(t, Date.now())
            return (
              <li key={t.id} className="credproxy-rule">
                <div>
                  <div className="r-title">
                    {t.name}{' '}
                    <span className={clsx(state === 'active' ? 'ok' : 'state-unknown')}>· {state}</span>
                  </div>
                  <div className="r-sub">
                    {t.expiresAt ? `Ends ${new Date(t.expiresAt).toLocaleDateString()}` : 'No end date'}
                    {' · '}
                    {/* The only thing that makes an unused token safe to revoke,
                        and the only reason anybody ever does. */}
                    {t.lastUsedAt
                      ? `last used ${new Date(t.lastUsedAt).toLocaleString()}`
                      : 'never used'}
                  </div>
                  <div className="r-sub faint">{CRED_PROXY_TOKEN_STATE_NOTE[state]}</div>
                </div>
                <div className="row-actions">
                  {state === 'active' && (
                    <>
                      <button className="btn sm" onClick={() => void copyToken(t.id)}>
                        Copy
                      </button>
                      <button className="btn sm danger" onClick={() => void revokeToken(t.id, t.name)}>
                        Revoke
                      </button>
                    </>
                  )}
                </div>
              </li>
            )
          })}
        </ul>
      )}

      {msg && (
        <div className={clsx('s-note', msg.tone)} role="status">
          {msg.text}
        </div>
      )}

      {/* ---------------------------------------------------------------- */}

      <div className="setting-row">
        <div className="s-info">
          <div className="s-title">Rules</div>
          <div className="s-desc">
            One destination, one credential, one way of sending it. Nothing applies by default: a
            destination with no rule is refused, never forwarded.
          </div>
        </div>
        <button className="btn" onClick={() => setDraft(emptyDraft())}>
          Add rule
        </button>
      </div>

      {unavailable && (
        <div className="s-note state-unknown">
          This build does not expose the credential proxy, so what it would allow cannot be read
          here.
        </div>
      )}

      {!unavailable && rules === null && !draft && (
        <div className="s-note state-unknown">Reading the rules…</div>
      )}

      {rules?.length === 0 && !draft && (
        <div className="s-note">
          No rules yet, so the proxy will refuse everything. That is the safe state, not a broken
          one.
        </div>
      )}

      <ul className="credproxy-rules">
        {(rules ?? []).map((r) => (
          <li key={r.id} className="credproxy-rule">
            <div>
              <div className="rule-name">{r.name}</div>
              <div className="rule-detail">
                {r.origin} — key from “{entryName(r.credential.vaultEntryId)}”, sent as{' '}
                {describeInjection(r.injection)}
                {r.enabled ? '' : ' (switched off)'}
              </div>
              {status?.listening && (
                <div className="rule-detail">
                  Point your client at{' '}
                  <code>{credProxyBaseUrl(status.port, r.origin)}</code>
                </div>
              )}
            </div>
            <div className="row-actions">
              <button
                className="btn"
                onClick={() =>
                  setDraft({
                    id: r.id,
                    name: r.name,
                    origin: r.origin,
                    vaultEntryId: r.credential.vaultEntryId,
                    slot: r.credential.slot,
                    fieldKey: r.credential.fieldKey ?? '',
                    kind: r.injection.kind,
                    injectionName: r.injection.name ?? ''
                  })
                }
              >
                Edit
              </button>
              <button className="btn danger" onClick={() => void remove(r.id)}>
                Remove
              </button>
            </div>
          </li>
        ))}
      </ul>

      {draft && (
        <div className="credproxy-draft">
          <input
            className="input"
            aria-label="Rule name"
            placeholder="Billing API"
            value={draft.name}
            onChange={(e) => setDraft({ ...draft, name: e.target.value })}
          />
          <input
            className="input"
            aria-label="Destination"
            placeholder="https://api.example.com"
            value={draft.origin}
            onChange={(e) => setDraft({ ...draft, origin: e.target.value })}
          />
          <div className="s-desc">
            The exact origin, and only that origin. A rule for api.example.com does not cover
            api.example.com.something-else, and it does not follow a redirect anywhere either.
          </div>
          <select
            className="input"
            aria-label="Vault entry"
            value={draft.vaultEntryId}
            onChange={(e) => setDraft({ ...draft, vaultEntryId: e.target.value })}
          >
            <option value="">Choose a vault entry…</option>
            {entries.map((e) => (
              <option key={e.id} value={e.id}>
                {e.name}
              </option>
            ))}
          </select>
          <select
            className="input"
            aria-label="Which field"
            value={draft.slot}
            onChange={(e) => setDraft({ ...draft, slot: e.target.value as CredProxySlot })}
          >
            {SLOTS.map((s) => (
              <option key={s.slot} value={s.slot}>
                {s.label}
              </option>
            ))}
          </select>
          {draft.slot === 'field' && (
            <input
              className="input"
              aria-label="Field name"
              placeholder="publishable_key"
              value={draft.fieldKey}
              onChange={(e) => setDraft({ ...draft, fieldKey: e.target.value })}
            />
          )}
          <select
            className="input"
            aria-label="How it is sent"
            value={draft.kind}
            onChange={(e) =>
              setDraft({ ...draft, kind: e.target.value as CredProxyInjectionKind })
            }
          >
            {INJECTIONS.map((i) => (
              <option key={i.kind} value={i.kind}>
                {i.label}
              </option>
            ))}
          </select>
          {needs && (
            <input
              className="input"
              aria-label={needs}
              placeholder={needs}
              value={draft.injectionName}
              onChange={(e) => setDraft({ ...draft, injectionName: e.target.value })}
            />
          )}
          <div className="row-actions">
            <button className="btn primary" onClick={() => void save()}>
              Save rule
            </button>
            <button className="btn" onClick={() => setDraft(null)}>
              Cancel
            </button>
          </div>
        </div>
      )}

      {/* ---------------------------------------------------------------- */}

      <div className="setting-row">
        <div className="s-info">
          <div className="s-title">Recent calls</div>
          <div className="s-desc">
            Destination, rule, outcome and how long it took. Never the body, the headers or the
            query string — a rule that puts the key in a query parameter is exactly the rule whose
            query string must not be written down.
          </div>
        </div>
      </div>

      {calls.length === 0 ? (
        <div className="s-note">Nothing has come through yet.</div>
      ) : (
        <ul className="credproxy-calls">
          {calls.map((c) => (
            <li key={c.id} className={clsx('credproxy-call', c.outcome !== 'forwarded' && 'refused')}>
              <span className="call-method">{c.method}</span>
              <span className="call-target">
                {c.origin}
                {c.path}
              </span>
              <span className="call-outcome">
                {c.outcome === 'forwarded' ? `${c.status}` : c.outcome}
              </span>
              <span className="call-rule">{c.ruleName ?? 'no rule'}</span>
              <span className="call-ms">{c.ms} ms</span>
              {c.detail && <span className="call-detail">{c.detail}</span>}
            </li>
          ))}
        </ul>
      )}
    </div>
  )
}
