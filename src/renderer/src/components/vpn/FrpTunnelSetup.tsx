import { useState } from 'react'
import { Modal } from '../common/Modal'
import { useApp } from '../../store/app'
import { toast } from '../../store/toast'
import { clsx } from '../../lib/format'
import { withVaultUnlock } from '../../lib/withVaultUnlock'
import {
  delegationRecord,
  isDelegatableDomain,
  publicHostFrom,
  publicUrl
} from '../../../../shared/frpTunnel'
import type { FrpPublicHost, FrpSpec, FrpTokenResult, VpnProfile } from '../../../../shared/vpn'

/**
 * `vpn.frpToken`, read off the bridge rather than called through it.
 *
 * The preload declaration for this channel lives in a file another agent holds
 * this session and is delivered as a patch, so the typed bridge does not name
 * it yet. Reading it through a narrow local type is what `bridgeHas` already
 * assumes anyway — every renderer call site has to survive a preload bundle
 * older than the renderer (see lib/bridge.ts) — and it keeps the argument and
 * result types checked rather than reaching for `any`.
 *
 * Once the patch is applied this can become a plain `window.shellpilot.vpn`
 * call and this type can go.
 */
type FrpTokenChannel = (req: {
  profileName: string
  workspaceId: string
  token: string
  replaces?: string
}) => Promise<FrpTokenResult>

function frpTokenChannel(): FrpTokenChannel | undefined {
  const vpn = window.shellpilot?.vpn as unknown as
    | { frpToken?: FrpTokenChannel }
    | undefined
  return typeof vpn?.frpToken === 'function' ? vpn.frpToken.bind(vpn) : undefined
}

/**
 * The one-time setup, and the only place ShellPilot says what frp cannot do
 * for you.
 *
 * ngrok hands out a URL because ngrok runs the server it resolves to. frp does
 * not; somebody has to point a domain at a host they control. That is a real
 * cost and pretending otherwise would be the whole feature's undoing — a URL
 * that looks like magic and then 404s at the DNS layer is worse than the form
 * it replaced, because the form never claimed to have finished.
 *
 * So the cost is paid here, once, in full, with the actual DNS record written
 * out to be copied. And then it is over: `FrpPublicHost.confirmedAt` is
 * stamped, `frpPublishReadiness` starts answering yes, and nothing in this pane
 * mentions domains again.
 *
 * What it deliberately does NOT do is check. There is no resolver call, no
 * "verifying…" spinner, no green tick. ShellPilot cannot see the operator's
 * zone, and a check that passed because a stale cache answered would be a
 * worse lie than no check at all. The confirmation records that the operator
 * says the record exists, and the wording says exactly that.
 */

interface FrpTunnelSetupProps {
  workspaceId: string
  /** An existing frp profile to promote into the tunnel host, if there is one
   *  worth reusing. A fresh profile otherwise. */
  existing?: VpnProfile | null
  onClose: () => void
  /** The saved profile, so the caller can carry straight on into a publish. */
  onDone: (profile: VpnProfile) => void
}

const SCHEMES: FrpPublicHost['scheme'][] = ['https', 'http']

export function FrpTunnelSetup({
  workspaceId,
  existing,
  onClose,
  onDone
}: FrpTunnelSetupProps): React.JSX.Element {
  const upsertVpnProfile = useApp((s) => s.upsertVpnProfile)
  const base = existing?.spec.kind === 'frp' ? existing.spec : null

  const [name, setName] = useState(existing?.name ?? 'Tunnel host')
  const [serverAddr, setServerAddr] = useState(base?.serverAddr ?? '')
  const [serverPort, setServerPort] = useState(base?.serverPort ?? 7000)
  const [token, setToken] = useState('')
  const [baseDomain, setBaseDomain] = useState(base?.publicHost?.baseDomain ?? '')
  const [scheme, setScheme] = useState<FrpPublicHost['scheme']>(base?.publicHost?.scheme ?? 'https')
  const [vhostPort, setVhostPort] = useState<string>(String(base?.publicHost?.port ?? ''))
  const [confirmed, setConfirmed] = useState(false)
  const [saving, setSaving] = useState(false)

  // The token channel is newer than some preload bundles (see lib/bridge.ts).
  // Without it the setup still completes — it just cannot finish the one step
  // that needs main, and says so rather than silently dropping the token.
  const storeToken = frpTokenChannel()

  const domainOk = isDelegatableDomain(baseDomain)
  const serverOk = serverAddr.trim().length > 0 && serverPort > 0 && serverPort < 65536
  const ready = domainOk && serverOk && confirmed && !saving

  const record = delegationRecord(baseDomain, serverAddr)
  const example = domainOk
    ? publicUrl(
        publicHostFrom({
          baseDomain,
          scheme,
          port: vhostPort ? Number(vhostPort) : undefined,
          now: 1
        }),
        'staging'
      )
    : null

  const finish = async (): Promise<void> => {
    if (!ready) return
    setSaving(true)
    try {
      let tokenRef = base?.auth.tokenRef
      if (token.trim() && storeToken) {
        const stored = await withVaultUnlock(`Saving the frp token for ${name.trim()}`, () =>
          storeToken({
            profileName: name.trim() || 'Tunnel host',
            workspaceId,
            token: token.trim(),
            ...(tokenRef?.vaultEntryId ? { replaces: tokenRef.vaultEntryId } : {})
          })
        )
        if (!stored?.ok || !stored.tokenRef) {
          // The dialog stays open with everything still typed in, so the user
          // can unlock the vault and press Finish again rather than starting
          // the setup over.
          toast(stored?.error ?? 'The token could not be saved to the vault.', 'error')
          return
        }
        tokenRef = stored.tokenRef
      }

      // Preserve whatever the existing profile already had. A tunnel host
      // promoted from an imported frpc.toml keeps its proxies, its transport
      // and — if it authenticates by OIDC and no token was typed — its auth.
      const auth: FrpSpec['auth'] = tokenRef
        ? { ...(base?.auth ?? { method: 'token' }), method: 'token', tokenRef }
        : (base?.auth ?? { method: 'token' })

      const spec: FrpSpec = {
        ...(base ?? {
          kind: 'frp',
          transport: { protocol: 'tcp', tlsEnable: true },
          proxies: [],
          visitors: []
        }),
        kind: 'frp',
        serverAddr: serverAddr.trim(),
        serverPort,
        auth,
        publicHost: publicHostFrom({
          baseDomain,
          scheme,
          port: vhostPort ? Number(vhostPort) : undefined
        })
      }

      const profile: VpnProfile = {
        id: existing?.id ?? `vpn-${crypto.randomUUID()}`,
        workspaceId,
        name: name.trim() || 'Tunnel host',
        autoStart: existing?.autoStart ?? false,
        spec
      }
      upsertVpnProfile(profile)
      toast(`${profile.name} saved`, 'ok')
      onDone(profile)
    } finally {
      setSaving(false)
    }
  }

  return (
    <Modal
      title="Set up a tunnel host"
      subtitle="Once. After this, publishing a port is one step."
      size="lg"
      onClose={onClose}
      footer={
        <>
          <span className="grow" />
          <button className="btn" onClick={onClose}>
            Cancel
          </button>
          <button className="btn primary" disabled={!ready} onClick={() => void finish()}>
            Finish setup
          </button>
        </>
      }
    >
      <div className="col" style={{ gap: 14 }}>
        {/* Said once, here, and nowhere else in this pane. */}
        <p className="muted" style={{ fontSize: 12, margin: 0, lineHeight: 1.5 }}>
          ShellPilot does not host public addresses. frp publishes through an frp server you run,
          under a domain you own — so those are the two things this asks for. It is the only time
          it will.
        </p>

        <label className="field">
          <span className="field-label">Name</span>
          <input className="input" value={name} onChange={(e) => setName(e.target.value)} />
        </label>

        <div className="field-row">
          <label className="field">
            <span className="field-label">frp server address</span>
            <input
              className="input"
              placeholder="frp.example.com"
              value={serverAddr}
              onChange={(e) => setServerAddr(e.target.value)}
            />
          </label>
          <label className="field">
            <span className="field-label">Control port</span>
            <input
              className="input"
              type="number"
              placeholder="7000"
              value={serverPort || ''}
              onChange={(e) => setServerPort(Number(e.target.value))}
            />
          </label>
        </div>

        <label className="field">
          <span className="field-label">Server token</span>
          <input
            className="input"
            type="password"
            placeholder={base?.auth.tokenRef ? 'Stored in the vault — type to replace' : 'auth.token from frps.toml'}
            value={token}
            onChange={(e) => setToken(e.target.value)}
            disabled={!storeToken}
          />
          <span className="field-hint">
            {storeToken
              ? 'Stored in the vault. Leave it empty if your frp server has no token.'
              : 'This build of the preload bridge cannot store a token yet — add one to this profile’s vault entry instead.'}
          </span>
        </label>

        <div className="divider" />

        <div className="field-row">
          <label className="field">
            <span className="field-label">Your domain</span>
            <input
              className="input"
              placeholder="tunnel.example.com"
              value={baseDomain}
              onChange={(e) => setBaseDomain(e.target.value)}
            />
            {baseDomain.trim() !== '' && !domainOk && (
              <span className="field-hint" style={{ color: 'var(--danger)' }}>
                This is not a domain name.
              </span>
            )}
          </label>
          <label className="field">
            <span className="field-label">Served over</span>
            <select
              className="input"
              value={scheme}
              onChange={(e) => setScheme(e.target.value as FrpPublicHost['scheme'])}
            >
              {SCHEMES.map((s) => (
                <option key={s} value={s}>
                  {s}
                </option>
              ))}
            </select>
          </label>
          <label className="field">
            <span className="field-label">Port in the URL</span>
            <input
              className="input"
              type="number"
              placeholder={scheme === 'https' ? '443' : '80'}
              value={vhostPort}
              onChange={(e) => setVhostPort(e.target.value)}
            />
          </label>
        </div>
        {scheme === 'https' && (
          // frp does not terminate TLS for a plain local HTTP service. Someone
          // has to — Caddy, nginx, a load balancer — and a scheme picked as a
          // wish fails in the browser rather than here, where it could be
          // explained.
          <span className="field-hint">
            Choose https only if something in front of your frp server terminates TLS for these
            names. frp does not do it for you.
          </span>
        )}

        <div className="field">
          <span className="field-label">The DNS record</span>
          <code
            className="input"
            style={{ display: 'block', fontSize: 12, padding: '6px 8px', userSelect: 'text' }}
          >
            {record}
          </code>
          <span className="field-hint">
            A wildcard, so every service you publish later gets a name without another DNS change.
            {example ? ` A service named "staging" would appear at ${example}.` : ''}
          </span>
        </div>

        {/* The gate. Not a check: nothing here resolves the name, and a green
            tick this app cannot honestly earn is exactly the kind of magic
            this whole flow exists to avoid. */}
        <label className="row" style={{ gap: 8, alignItems: 'flex-start' }}>
          <span
            className={clsx('switch', confirmed && 'on')}
            style={{ marginTop: 1 }}
            role="switch"
            tabIndex={0}
            aria-checked={confirmed}
            aria-label="I have created this record, and my frp server serves HTTP for these names."
            onClick={() => setConfirmed(!confirmed)}
            onKeyDown={(e) => {
              if (e.key === ' ' || e.key === 'Enter') {
                e.preventDefault()
                setConfirmed(!confirmed)
              }
            }}
          />
          <span style={{ fontSize: 12, color: confirmed ? 'var(--text-muted)' : 'var(--warn)' }}>
            I have created this record, and my frp server serves HTTP for these names. ShellPilot
            does not check — it cannot see your DNS.
          </span>
        </label>
      </div>
    </Modal>
  )
}
