import { Trash2 } from 'lucide-react'
import type { FrpProxy, FrpProxyType } from '../../types'
import { clsx } from '../../lib/format'
import { BindWarning } from './VpnStatusCard'

const TYPES: FrpProxyType[] = ['tcp', 'udp', 'http', 'https', 'stcp', 'sudp', 'xtcp', 'tcpmux']

// http/https are addressed by hostname on the frp server; the rest take a port.
const BY_DOMAIN: FrpProxyType[] = ['http', 'https']
// stcp/sudp/xtcp are only reachable by a visitor holding the shared secret, so
// they are not "published" the way a plain tcp proxy is.
const SECRET_TYPES: FrpProxyType[] = ['stcp', 'sudp', 'xtcp']

interface FrpProxyEditorProps {
  proxy: FrpProxy
  serverAddr: string
  /** Validation messages for this proxy, keyed by the field name inside it. */
  issues: Record<string, string>
  onChange: (next: FrpProxy) => void
  onRemove: () => void
}

export function FrpProxyEditor({
  proxy,
  serverAddr,
  issues,
  onChange,
  onRemove
}: FrpProxyEditorProps): React.JSX.Element {
  const set = (patch: Partial<FrpProxy>): void => onChange({ ...proxy, ...patch })

  const byDomain = BY_DOMAIN.includes(proxy.type)
  const secret = SECRET_TYPES.includes(proxy.type)
  const where = byDomain
    ? proxy.customDomains?.[0] || (proxy.subdomain ? `${proxy.subdomain}.${serverAddr}` : serverAddr)
    : serverAddr

  // The whole value of this gate is that it names what actually becomes
  // reachable. Before the port and the server are filled in it would read
  // "Make 127.0.0.1:0 reachable from your frp server", which states nothing —
  // so say what is missing instead, and refuse to be ticked until it is real.
  // `where` is used rather than the bare server address because for an
  // http/https proxy the reachable name is the domain, not the frp host.
  const missing = !proxy.localPort ? 'a local port' : !where.trim() ? 'the frp server address' : null
  const exposureSentence = missing
    ? `Set ${missing} first — then confirm what this proxy makes reachable.`
    : `Make ${proxy.localIp || '127.0.0.1'}:${proxy.localPort} reachable from ${where.trim()}.`
  const toggleExposure = (): void => {
    if (missing) return
    set({ acknowledgedExposure: !proxy.acknowledgedExposure })
  }

  return (
    <div className="hop-card" style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
      <div className="row" style={{ gap: 6 }}>
        <input
          className="input"
          style={{ flex: 1, minWidth: 110 }}
          placeholder="Proxy name"
          value={proxy.name}
          onChange={(e) => set({ name: e.target.value })}
        />
        <select
          className="input"
          style={{ width: 96 }}
          value={proxy.type}
          onChange={(e) => set({ type: e.target.value as FrpProxyType })}
        >
          {TYPES.map((t) => (
            <option key={t} value={t}>
              {t}
            </option>
          ))}
        </select>
        <button className="icon-btn sm" title="Remove proxy" onClick={onRemove}>
          <Trash2 size={14} />
        </button>
      </div>
      {issues.name && <FieldError message={issues.name} />}

      <div className="input-group">
        <input
          className="input"
          placeholder="127.0.0.1"
          value={proxy.localIp}
          onChange={(e) => set({ localIp: e.target.value })}
        />
        <input
          className="input"
          type="number"
          placeholder="Local port"
          value={proxy.localPort || ''}
          onChange={(e) => set({ localPort: Number(e.target.value) })}
        />
        {!byDomain && !secret && (
          <input
            className="input"
            type="number"
            placeholder="Remote port"
            value={proxy.remotePort ?? ''}
            onChange={(e) => set({ remotePort: e.target.value ? Number(e.target.value) : undefined })}
          />
        )}
      </div>
      {issues.localIp && <FieldError message={issues.localIp} />}
      {issues.localPort && <FieldError message={issues.localPort} />}
      {issues.remotePort && <FieldError message={issues.remotePort} />}
      <BindWarning host={proxy.localIp} what="the service behind this proxy" />

      {byDomain && (
        <div className="input-group">
          <input
            className="input"
            placeholder="Custom domain (app.example.com)"
            value={proxy.customDomains?.join(', ') ?? ''}
            onChange={(e) =>
              set({
                customDomains: e.target.value
                  .split(',')
                  .map((d) => d.trim())
                  .filter(Boolean)
              })
            }
          />
          <input
            className="input"
            placeholder="Subdomain"
            value={proxy.subdomain ?? ''}
            onChange={(e) => set({ subdomain: e.target.value || undefined })}
          />
        </div>
      )}

      {secret && (
        <span className="field-hint">
          Visitors need the shared secret for this proxy. It lives in the vault, not here.
        </span>
      )}

      {/* The gate. Written out in full, with the real host and the real port,
          because "expose this proxy" is a sentence that tells the user nothing
          they had not already assumed. start() refuses without this ticked. */}
      <label className="row" style={{ gap: 8, alignItems: 'flex-start' }}>
        <span
          className={clsx('switch', proxy.acknowledgedExposure && 'on')}
          style={{ marginTop: 1 }}
          // This is the only thing standing between the user and publishing a
          // local port, so it has to be operable and perceivable without a
          // mouse. The bare `.switch` span used elsewhere in the app has no
          // role, no tab stop and no key handling; clicking the sentence did
          // nothing either, because the label wrapped no form control.
          role="switch"
          tabIndex={missing ? -1 : 0}
          aria-checked={proxy.acknowledgedExposure}
          aria-label={exposureSentence}
          onClick={toggleExposure}
          onKeyDown={(e) => {
            if (e.key === ' ' || e.key === 'Enter') {
              e.preventDefault()
              toggleExposure()
            }
          }}
        />
        <span
          style={{
            fontSize: 12,
            color: proxy.acknowledgedExposure ? 'var(--text-muted)' : 'var(--warn)'
          }}
        >
          {exposureSentence}
        </span>
      </label>
    </div>
  )
}

function FieldError({ message }: { message: string }): React.JSX.Element {
  return (
    <span className="field-hint" style={{ color: 'var(--danger)' }}>
      {message}
    </span>
  )
}
