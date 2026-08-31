import { useEffect, useMemo, useState } from 'react'
import { AlertTriangle, Plus, ScrollText, Trash2 } from 'lucide-react'
import { Modal } from '../common/Modal'
import { useApp } from '../../store/app'
import { toast } from '../../store/toast'
import { clsx } from '../../lib/format'
import { bridgeHas } from '../../lib/bridge'
import { isCidr, isWireGuardKey, parseVpnEndpoint } from '../../../../shared/vpn'
import type {
  FrpProxy,
  FrpSpec,
  OpenVpnAuthMode,
  OpenVpnSpec,
  VpnListener,
  VpnProfile,
  VpnValidationIssue,
  WireGuardPeer,
  WireGuardSpec
} from '../../types'
import { BindWarning } from './VpnStatusCard'
import { FrpProxyEditor } from './FrpProxyEditor'

const listStr = (a: string[] | undefined): string => (a ?? []).join(', ')
const parseList = (s: string): string[] =>
  s
    .split(',')
    .map((t) => t.trim())
    .filter(Boolean)

const KIND_SUBTITLE: Record<VpnProfile['spec']['kind'], string> = {
  wireguard: 'WireGuard',
  openvpn: 'OpenVPN',
  frp: 'frp reverse proxy'
}

interface VpnProfileFormProps {
  profile: VpnProfile
  onClose: () => void
}

export function VpnProfileForm({ profile, onClose }: VpnProfileFormProps): React.JSX.Element {
  const upsertVpnProfile = useApp((s) => s.upsertVpnProfile)
  // "Edit New frp client" is what the title said for a profile being created.
  // The caller mints the profile before opening the form, so the honest test is
  // whether the store has seen this id yet.
  const isNew = useApp((s) => !s.vpns.some((v) => v.id === profile.id))
  const [draft, setDraft] = useState<VpnProfile>(profile)
  const [issues, setIssues] = useState<VpnValidationIssue[]>([])

  // validate() is pure and cheap in main — no process, no network — so it can
  // run while the user types. Debounced only enough to collapse a burst.
  useEffect(() => {
    if (!bridgeHas(window.shellpilot?.vpn as Record<string, unknown> | undefined, 'validate')) return
    let live = true
    const t = setTimeout(() => {
      void window.shellpilot?.vpn.validate(draft.spec).then((v) => {
        if (live && v) setIssues(v.issues)
      })
    }, 200)
    return () => {
      live = false
      clearTimeout(t)
    }
  }, [draft.spec])

  const byPath = useMemo(() => {
    const m: Record<string, VpnValidationIssue> = {}
    // An error beats a warning on the same field: the blocking problem is the
    // one the user has to fix first.
    for (const i of issues) {
      const held = m[i.path]
      if (!held || (held.severity === 'warning' && i.severity === 'error')) m[i.path] = i
    }
    return m
  }, [issues])

  // Which paths a field actually put on screen this render.
  //
  // The form renders <Issue at="..."> for a hand-picked set of paths, and the
  // validators emit plenty of others — `dns[0]`, `peers[0].allowedIps[1]`,
  // `listeners[0].targetHost`, `proxies[0].secretKeyRef`. Every one of those
  // used to disappear, leaving a greyed Save and "2 problems to fix" with
  // nothing indicating where. Collecting what was shown lets the footer list
  // whatever was not.
  const shown = useMemo(() => new Set<string>(), [issues])

  const blocking = issues.filter((i) => i.severity === 'error')
  const stripped = draft.spec.strippedDirectives ?? []

  const save = (): void => {
    if (blocking.length > 0 || !draft.name.trim()) return
    upsertVpnProfile({ ...draft, name: draft.name.trim() })
    toast(`${draft.name.trim()} saved`, 'ok')
    onClose()
  }

  const setSpec = <T extends VpnProfile['spec']>(spec: T): void => setDraft((d) => ({ ...d, spec }))

  return (
    <Modal
      title={isNew ? `New ${KIND_SUBTITLE[draft.spec.kind]}` : `Edit ${draft.name || 'profile'}`}
      subtitle={KIND_SUBTITLE[draft.spec.kind]}
      size="lg"
      onClose={onClose}
      footer={
        <>
          <UnrenderedIssues
            blocking={blocking}
            shown={shown}
            nameMissing={!draft.name.trim()}
          />
          <span className="grow" />
          <button className="btn sm" onClick={onClose}>
            Cancel
          </button>
          <button
            className="btn primary sm"
            disabled={blocking.length > 0 || !draft.name.trim()}
            onClick={save}
          >
            Save
          </button>
        </>
      }
    >
      <div className="card" style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
        <label className="field">
          <span className="field-label">Name</span>
          <input
            className="input"
            value={draft.name}
            onChange={(e) => setDraft((d) => ({ ...d, name: e.target.value }))}
          />
        </label>

        <label className="row" style={{ gap: 8 }}>
          <span
            className={clsx('switch', draft.autoStart && 'on')}
            onClick={() => setDraft((d) => ({ ...d, autoStart: !d.autoStart }))}
          />
          <span className="muted" style={{ fontSize: 12 }}>
            Connect automatically when ShellPilot starts
          </span>
        </label>

        <div className="divider" />

        {draft.spec.kind === 'wireguard' && (
          <WireGuardFields spec={draft.spec} issue={byPath} shown={shown} onChange={setSpec} />
        )}
        {draft.spec.kind === 'openvpn' && (
          <OpenVpnFields spec={draft.spec} issue={byPath} shown={shown} onChange={setSpec} />
        )}
        {draft.spec.kind === 'frp' && (
          <FrpFields spec={draft.spec} issue={byPath} shown={shown} onChange={setSpec} />
        )}

        {stripped.length > 0 && (
          // Kept reachable from the profile, not only from the import modal:
          // "why does this profile not set my DNS" is a question asked months
          // after the modal that answered it was closed.
          <details className="disclosure">
            <summary className="disclosure-head">
              <ScrollText size={13} />
              {stripped.length} {stripped.length === 1 ? 'directive was' : 'directives were'} removed
              when this profile was imported
            </summary>
            <div className="disclosure-body">
              {stripped.map((d, i) => (
                <div key={`${d.directive}-${i}`} className="col" style={{ gap: 2 }}>
                  <code
                    className="mono"
                    style={{
                      fontSize: 12,
                      color: d.severity === 'rejected' ? 'var(--danger)' : 'var(--warn)'
                    }}
                  >
                    {d.directive}
                  </code>
                  <span className="faint" style={{ fontSize: 11 }}>
                    {d.reason}
                  </span>
                </div>
              ))}
            </div>
          </details>
        )}

      </div>
    </Modal>
  )
}

/** Blocking problems that no field displayed.
 *
 *  A disabled Save must never be the only signal. Anything a field already
 *  showed inline is left out — repeating it in the footer just makes the real
 *  orphan harder to spot. */
function UnrenderedIssues({
  blocking,
  shown,
  nameMissing
}: {
  blocking: VpnValidationIssue[]
  shown: Set<string>
  nameMissing: boolean
}): React.JSX.Element | null {
  const orphans = blocking.filter((i) => !shown.has(i.path))
  if (orphans.length === 0 && !nameMissing) return null
  return (
    <div
      className="row"
      style={{ gap: 6, alignItems: 'flex-start', color: 'var(--danger)', fontSize: 11 }}
    >
      <AlertTriangle size={12} style={{ flexShrink: 0, marginTop: 2 }} />
      <div style={{ display: 'flex', flexDirection: 'column', gap: 2, minWidth: 0 }}>
        {nameMissing && <span>Give this profile a name.</span>}
        {orphans.map((i) => (
          <span key={i.path + i.code}>{i.message}</span>
        ))}
      </div>
    </div>
  )
}

// ---------------------------------------------------------------- shared bits

/** Why system mode cannot be chosen here, or null when it can.
 *
 *  Kept in one place so the wording matches what the driver actually throws —
 *  a form that offers a mode the engine refuses is worse than one that never
 *  offered it. */
function useSystemModeBlocked(): string | null {
  const [platform, setPlatform] = useState<NodeJS.Platform | null>(null)
  useEffect(() => {
    let live = true
    void window.shellpilot?.platform().then((p) => {
      if (live) setPlatform(p)
    })
    return () => {
      live = false
    }
  }, [])
  if (platform !== 'darwin') return null
  return 'System mode is not available on macOS: ShellPilot has no signed privileged helper, so it cannot create a system network interface. Userspace mode gives the same tunnel through local listeners and needs no administrator rights.'
}

/** A checkbox that turns a blocking validation error into an accepted choice.
 *
 *  Deliberately a real `<input type="checkbox">` rather than the app's `.switch`
 *  span: this gates a decision with a security consequence, and the span
 *  pattern has no role, no tab stop and no key handling, so it cannot be
 *  operated or perceived without a mouse. */
function Confirm({
  checked,
  onChange,
  label
}: {
  checked: boolean
  onChange: (v: boolean) => void
  label: string
}): React.JSX.Element {
  return (
    <label
      className="row"
      style={{ gap: 8, alignItems: 'flex-start', cursor: 'pointer', fontSize: 12 }}
    >
      <input
        type="checkbox"
        checked={checked}
        onChange={(e) => onChange(e.target.checked)}
        style={{ marginTop: 2, flexShrink: 0 }}
      />
      <span style={{ color: checked ? 'var(--muted)' : 'var(--warn)' }}>{label}</span>
    </label>
  )
}

type IssueMap = Record<string, VpnValidationIssue>

/** Renders whatever main said about one dotted path in the spec, against the
 *  field that path names.
 *
 *  Matching is by **prefix**, so `at="dns"` also catches `dns[0]` and
 *  `at="auth"` catches `auth.tokenRef`. Exact matching meant a single bad DNS
 *  entry produced a blocking error that no field displayed — and `at="auth"`
 *  matched nothing at all, because the validator's paths are `auth.tokenRef`
 *  and `auth.method`.
 *
 *  `shown` collects every path this rendered, so the footer can list the ones
 *  no field claimed rather than leaving a disabled Save as the only signal. */
function Issue({
  at,
  map,
  shown
}: {
  at: string
  map: IssueMap
  shown?: Set<string>
}): React.JSX.Element | null {
  const matches = matchIssues(at, map)
  for (const m of matches) shown?.add(m.path)
  if (matches.length === 0) return null
  return (
    <>
      {matches.map((i) => (
        <span
          key={i.path + i.code}
          className="field-hint"
          style={{ color: i.severity === 'error' ? 'var(--danger)' : 'var(--warn)' }}
        >
          {i.message}
        </span>
      ))}
    </>
  )
}

/** Issues at `at` itself, or nested beneath it — `dns[0]`, `auth.tokenRef`,
 *  `peers[0].allowedIps[2]`. An error sorts before a warning. */
function matchIssues(at: string, map: IssueMap): VpnValidationIssue[] {
  const out: VpnValidationIssue[] = []
  for (const [path, issue] of Object.entries(map)) {
    if (path === at || path.startsWith(`${at}[`) || path.startsWith(`${at}.`)) out.push(issue)
  }
  return out.sort((a, b) => (a.severity === b.severity ? 0 : a.severity === 'error' ? -1 : 1))
}

/** A local shape check next to the field, so a mistyped key is caught here
 *  rather than as a silent no-handshake ten seconds after Start. */
function Hint({
  ok,
  when,
  text
}: {
  ok: boolean
  when: boolean
  text: string
}): React.JSX.Element | null {
  if (!when || ok) return null
  return (
    <span className="field-hint" style={{ color: 'var(--warn)' }}>
      {text}
    </span>
  )
}

// ------------------------------------------------------------------ wireguard

interface WgProps {
  spec: WireGuardSpec
  issue: IssueMap
  shown: Set<string>
  onChange: (spec: WireGuardSpec) => void
}

function WireGuardFields({ spec, issue, onChange, shown }: WgProps): React.JSX.Element {
  const systemModeBlocked = useSystemModeBlocked()
  const set = (patch: Partial<WireGuardSpec>): void => onChange({ ...spec, ...patch })
  const setPeer = (i: number, patch: Partial<WireGuardPeer>): void =>
    set({ peers: spec.peers.map((p, n) => (n === i ? { ...p, ...patch } : p)) })

  return (
    <>
      <div className="field">
        <span className="field-label">Mode</span>
        <div className="row" style={{ gap: 6 }}>
          {(['userspace', 'system'] as const).map((m) => (
            <button
              key={m}
              className={clsx('btn sm', spec.mode === m && 'primary')}
              // System mode is refused outright on macOS. Leaving the button
              // live meant it could be picked and saved, and only failed at
              // Start — the choice looked supported right up to the moment it
              // was not.
              disabled={m === 'system' && systemModeBlocked !== null}
              onClick={() => set({ mode: m })}
            >
              {m === 'userspace' ? 'Userspace (no admin)' : 'System interface'}
            </button>
          ))}
        </div>
        {systemModeBlocked !== null && (
          // Next to the control, not in a tooltip: a disabled thing that does
          // not say why is just a dead end.
          <span className="field-hint" style={{ color: 'var(--warn)' }}>
            {systemModeBlocked}
          </span>
        )}
        <span className="field-hint">
          {spec.mode === 'userspace'
            ? 'The tunnel is exposed as local listeners only. No TUN device, no route changes, no elevation prompt.'
            : 'Creates a real network interface and changes routes and DNS. Asks for elevation every time it starts. A full tunnel (0.0.0.0/0) is not supported in this mode.'}
        </span>
      </div>

      <label className="field">
        <span className="field-label">Addresses</span>
        <input
          className="input"
          placeholder="10.0.0.2/32, fd00::2/128"
          value={listStr(spec.addresses)}
          onChange={(e) => set({ addresses: parseList(e.target.value) })}
        />
        <Issue at="addresses" map={issue} shown={shown} />
        <Hint
          when={spec.addresses.length > 0}
          ok={spec.addresses.every(isCidr)}
          text="Each address needs a prefix length, e.g. 10.0.0.2/32."
        />
      </label>

      <div className="field-row">
        <label className="field">
          <span className="field-label">DNS</span>
          <input
            className="input"
            placeholder="1.1.1.1"
            value={listStr(spec.dns)}
            onChange={(e) => set({ dns: parseList(e.target.value) })}
          />
          <Issue at="dns" map={issue} shown={shown} />
        </label>
        <label className="field">
          <span className="field-label">MTU</span>
          <input
            className="input"
            type="number"
            placeholder="1420"
            value={spec.mtu ?? ''}
            onChange={(e) => set({ mtu: e.target.value ? Number(e.target.value) : undefined })}
          />
          <Issue at="mtu" map={issue} shown={shown} />
        </label>
      </div>

      <div className="field">
        <div className="row" style={{ gap: 8 }}>
          <span className="field-label">Peers</span>
          <span className="grow" />
          <button
            className="btn sm"
            onClick={() =>
              set({ peers: [...spec.peers, { publicKey: '', endpoint: '', allowedIps: ['0.0.0.0/0'] }] })
            }
          >
            <Plus size={13} /> Add peer
          </button>
        </div>
        {spec.peers.map((p, i) => (
          <div key={i} className="hop-card" style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
            <div className="row" style={{ gap: 6 }}>
              <input
                className="input"
                style={{ flex: 1 }}
                placeholder="Peer public key"
                value={p.publicKey}
                onChange={(e) => setPeer(i, { publicKey: e.target.value })}
              />
              <button
                className="icon-btn sm"
                title="Remove peer"
                onClick={() => set({ peers: spec.peers.filter((_, n) => n !== i) })}
              >
                <Trash2 size={14} />
              </button>
            </div>
            <Issue at={`peers[${i}].publicKey`} map={issue} />
            <Hint
              when={!!p.publicKey}
              ok={isWireGuardKey(p.publicKey)}
              text="A WireGuard key is 44 base64 characters ending in '='."
            />

            <div className="input-group">
              <input
                className="input"
                placeholder="vpn.example.com:51820"
                value={p.endpoint}
                onChange={(e) => setPeer(i, { endpoint: e.target.value })}
              />
              <input
                className="input"
                type="number"
                style={{ maxWidth: 130 }}
                placeholder="Keepalive (s)"
                value={p.persistentKeepalive ?? ''}
                onChange={(e) =>
                  setPeer(i, {
                    persistentKeepalive: e.target.value ? Number(e.target.value) : undefined
                  })
                }
              />
            </div>
            <Issue at={`peers[${i}].endpoint`} map={issue} />
            <Hint
              when={!!p.endpoint}
              ok={parseVpnEndpoint(p.endpoint) !== null}
              text="Endpoints are host:port, or [v6-address]:port."
            />

            <input
              className="input"
              placeholder="Allowed IPs — 0.0.0.0/0, ::/0"
              value={listStr(p.allowedIps)}
              onChange={(e) => setPeer(i, { allowedIps: parseList(e.target.value) })}
            />
            <Issue at={`peers[${i}].allowedIps`} map={issue} />
          </div>
        ))}
      </div>

      {spec.mode === 'userspace' && (
        <ListenerFields
          listeners={spec.listeners}
          issue={issue} shown={shown}
          onChange={(listeners) => set({ listeners })}
        />
      )}
    </>
  )
}

// ------------------------------------------------------------------ listeners

interface ListenerProps {
  listeners: VpnListener[]
  issue: IssueMap
  shown: Set<string>
  onChange: (l: VpnListener[]) => void
}

function ListenerFields({ listeners, issue, onChange, shown }: ListenerProps): React.JSX.Element {
  const replace = (i: number, next: VpnListener): void =>
    onChange(listeners.map((l, n) => (n === i ? next : l)))

  return (
    <div className="field">
      <div className="row" style={{ gap: 8 }}>
        <span className="field-label">Local listeners</span>
        <span className="grow" />
        <button
          className="btn sm"
          onClick={() =>
            onChange([...listeners, { kind: 'socks5', bindHost: '127.0.0.1', bindPort: 1080 }])
          }
        >
          <Plus size={13} /> Add listener
        </button>
      </div>
      <span className="field-hint">
        In userspace mode these are the only way traffic reaches the tunnel — nothing is routed
        system-wide.
      </span>
      {listeners.map((l, i) => (
        <div key={i} className="hop-card" style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
          <div className="input-group">
            <select
              className="input"
              style={{ maxWidth: 110 }}
              value={l.kind}
              onChange={(e) => {
                const kind = e.target.value as VpnListener['kind']
                replace(
                  i,
                  kind === 'forward'
                    ? { kind, bindHost: l.bindHost, bindPort: l.bindPort, targetHost: '', targetPort: 0 }
                    : { kind, bindHost: l.bindHost, bindPort: l.bindPort }
                )
              }}
            >
              <option value="socks5">SOCKS5</option>
              <option value="http">HTTP proxy</option>
              <option value="forward">Forward</option>
            </select>
            <input
              className="input"
              placeholder="127.0.0.1"
              value={l.bindHost}
              onChange={(e) => replace(i, { ...l, bindHost: e.target.value })}
            />
            <input
              className="input"
              type="number"
              style={{ maxWidth: 110 }}
              placeholder="Port"
              value={l.bindPort || ''}
              onChange={(e) => replace(i, { ...l, bindPort: Number(e.target.value) })}
            />
            <button
              className="icon-btn sm"
              title="Remove listener"
              onClick={() => onChange(listeners.filter((_, n) => n !== i))}
            >
              <Trash2 size={14} />
            </button>
          </div>
          {l.kind === 'forward' && (
            <div className="input-group">
              <input
                className="input"
                placeholder="Target host inside the tunnel"
                value={l.targetHost}
                onChange={(e) => replace(i, { ...l, targetHost: e.target.value })}
              />
              <input
                className="input"
                type="number"
                style={{ maxWidth: 110 }}
                placeholder="Target port"
                value={l.targetPort || ''}
                onChange={(e) => replace(i, { ...l, targetPort: Number(e.target.value) })}
              />
            </div>
          )}
          <Issue at={`listeners[${i}].bindHost`} map={issue} shown={shown} />
          <Issue at={`listeners[${i}].bindPort`} map={issue} shown={shown} />
          {/* A Forward listener seeds an empty target host and port 0, so these
              two are the errors a user is most likely to be staring at — and
              they were the ones with no field to appear against. */}
          <Issue at={`listeners[${i}].targetHost`} map={issue} shown={shown} />
          <Issue at={`listeners[${i}].targetPort`} map={issue} shown={shown} />
          <BindWarning host={l.bindHost} what="this listener" />
        </div>
      ))}
    </div>
  )
}

// -------------------------------------------------------------------- openvpn

interface OvpnProps {
  spec: OpenVpnSpec
  issue: IssueMap
  shown: Set<string>
  onChange: (spec: OpenVpnSpec) => void
}

const AUTH_LABEL: Record<OpenVpnAuthMode, string> = {
  none: 'Certificate only',
  userpass: 'Username and password',
  'userpass-otp': 'Username, password and a one-time code'
}

function OpenVpnFields({ spec, issue, onChange, shown }: OvpnProps): React.JSX.Element {
  const set = (patch: Partial<OpenVpnSpec>): void => onChange({ ...spec, ...patch })

  return (
    <>
      <label className="field">
        <span className="field-label">Authentication</span>
        <select
          className="input"
          value={spec.authMode}
          onChange={(e) => set({ authMode: e.target.value as OpenVpnAuthMode })}
        >
          {(Object.keys(AUTH_LABEL) as OpenVpnAuthMode[]).map((m) => (
            <option key={m} value={m}>
              {AUTH_LABEL[m]}
            </option>
          ))}
        </select>
        <Issue at="authMode" map={issue} shown={shown} />
        <span className="field-hint">
          Credentials live in the vault and are handed to OpenVPN over its management socket — never
          written to a file, never passed on the command line.
        </span>
      </label>

      {spec.remotes && spec.remotes.length > 0 && (
        <div className="field">
          <span className="field-label">Remotes</span>
          <div className="col" style={{ gap: 2 }}>
            {spec.remotes.map((r, i) => (
              <span key={i} className="mono" style={{ fontSize: 12 }}>
                {r.host}:{r.port} {r.proto}
              </span>
            ))}
          </div>
          {/* Read-only: they come out of the sanitised config body in the vault,
              and editing them here would desynchronise the two. */}
          <span className="field-hint">Taken from the imported profile.</span>
        </div>
      )}

      <label className="row" style={{ gap: 8, alignItems: 'flex-start' }}>
        <span
          className={clsx('switch', spec.redirectGateway && 'on')}
          style={{ marginTop: 1 }}
          onClick={() => set({ redirectGateway: !spec.redirectGateway })}
        />
        <span style={{ fontSize: 12, color: spec.redirectGateway ? 'var(--warn)' : 'var(--text-muted)' }}>
          Send all traffic through this VPN. Off by default: a downloaded profile asking for your
          default route is not a good enough reason to give it.
        </span>
      </label>

      {spec.staticChallenge && (
        <div className="field">
          <span className="field-label">Static challenge</span>
          <span className="muted" style={{ fontSize: 12 }}>
            {spec.staticChallenge.text}
          </span>
        </div>
      )}

      <label className="field">
        <span className="field-label">OpenVPN binary</span>
        <input
          className="input"
          placeholder="Detected automatically"
          value={spec.binaryPath ?? ''}
          onChange={(e) => set({ binaryPath: e.target.value || undefined })}
        />
        <Issue at="binaryPath" map={issue} shown={shown} />
        <span className="field-hint">
          ShellPilot does not ship an OpenVPN binary. Leave this empty to use an allowlisted system
          install.
        </span>
      </label>
    </>
  )
}

// ------------------------------------------------------------------------ frp

interface FrpProps {
  spec: FrpSpec
  issue: IssueMap
  shown: Set<string>
  onChange: (spec: FrpSpec) => void
}

function FrpFields({ spec, issue, onChange, shown }: FrpProps): React.JSX.Element {
  const set = (patch: Partial<FrpSpec>): void => onChange({ ...spec, ...patch })

  // Re-keys `proxies[3].localPort` to `localPort` for the row that owns it, so
  // the editor does not have to know its own index.
  const proxyIssues = (i: number): Record<string, string> => {
    const prefix = `proxies[${i}].`
    const out: Record<string, string> = {}
    for (const [path, v] of Object.entries(issue)) {
      if (path.startsWith(prefix)) out[path.slice(prefix.length)] = v.message
    }
    return out
  }

  const addProxy = (): void =>
    set({
      proxies: [
        ...spec.proxies,
        {
          name: `proxy-${spec.proxies.length + 1}`,
          type: 'tcp',
          localIp: '127.0.0.1',
          localPort: 0,
          acknowledgedExposure: false
        } satisfies FrpProxy
      ]
    })

  return (
    <>
      <div className="field-row">
        <label className="field">
          <span className="field-label">Server address</span>
          <input
            className="input"
            placeholder="frp.example.com"
            value={spec.serverAddr}
            onChange={(e) => set({ serverAddr: e.target.value })}
          />
          <Issue at="serverAddr" map={issue} shown={shown} />
        </label>
        <label className="field">
          <span className="field-label">Server port</span>
          <input
            className="input"
            type="number"
            placeholder="7000"
            value={spec.serverPort || ''}
            onChange={(e) => set({ serverPort: Number(e.target.value) })}
          />
          <Issue at="serverPort" map={issue} shown={shown} />
        </label>
      </div>

      <div className="field-row">
        <label className="field">
          <span className="field-label">Transport</span>
          <select
            className="input"
            value={spec.transport.protocol}
            onChange={(e) =>
              set({
                transport: {
                  ...spec.transport,
                  protocol: e.target.value as FrpSpec['transport']['protocol']
                }
              })
            }
          >
            {(['tcp', 'kcp', 'quic', 'websocket', 'wss'] as const).map((p) => (
              <option key={p} value={p}>
                {p}
              </option>
            ))}
          </select>
        </label>
        <label className="field">
          <span className="field-label">Corporate proxy</span>
          <input
            className="input"
            placeholder="http://proxy:8080"
            value={spec.transport.proxyUrl ?? ''}
            onChange={(e) =>
              set({ transport: { ...spec.transport, proxyUrl: e.target.value || undefined } })
            }
          />
          <Issue at="transport.proxyUrl" map={issue} shown={shown} />
        </label>
      </div>

      <label className="row" style={{ gap: 8 }}>
        <span
          className={clsx('switch', spec.transport.tlsEnable && 'on')}
          onClick={() => set({ transport: { ...spec.transport, tlsEnable: !spec.transport.tlsEnable } })}
        />
        <span className="muted" style={{ fontSize: 12 }}>
          Encrypt the control connection with TLS
        </span>
      </label>

      {/* Turning TLS off is a blocking error unless it is confirmed, and until
          this existed there was no control anywhere that could confirm it — the
          profile simply became unsavable, with "1 problem to fix" as the only
          explanation. The confirmation is stored on the spec, so it satisfies
          validation at start time too rather than only in this form. */}
      {!spec.transport.tlsEnable && (
        <Confirm
          checked={spec.confirmations?.allowPlaintextTransport === true}
          onChange={(v) =>
            set({ confirmations: { ...spec.confirmations, allowPlaintextTransport: v } })
          }
          label="Send the control connection unencrypted. Anyone on the path can read the token and the traffic."
        />
      )}

      <div className="field">
        <span className="field-label">Authentication</span>
        <span className="muted" style={{ fontSize: 12 }}>
          {spec.auth.method === 'oidc'
            ? `OIDC — ${spec.auth.oidc?.clientId ?? 'client not set'}`
            : spec.auth.tokenRef
              ? 'Token, held in the vault'
              : 'Token — add one to this profile’s vault entry before starting'}
        </span>
        <Issue at="auth" map={issue} shown={shown} />
      </div>

      <div className="divider" />

      <div className="field">
        <div className="row" style={{ gap: 8 }}>
          <span className="field-label">Proxies</span>
          <span className="grow" />
          <button className="btn sm" onClick={addProxy}>
            <Plus size={13} /> Add proxy
          </button>
        </div>
        {spec.proxies.length === 0 && (
          <span className="field-hint">An frp client with no proxies connects and exposes nothing.</span>
        )}
        {spec.proxies.map((p, i) => (
          <FrpProxyEditor
            key={i}
            proxy={p}
            serverAddr={spec.serverAddr}
            issues={proxyIssues(i)}
            onChange={(next) => set({ proxies: spec.proxies.map((q, n) => (n === i ? next : q)) })}
            onRemove={() => set({ proxies: spec.proxies.filter((_, n) => n !== i) })}
          />
        ))}
      </div>

      {spec.visitors.length > 0 && (
        <div className="field">
          <span className="field-label">Visitors</span>
          {spec.visitors.map((v, i) => (
            <div key={i} className="col" style={{ gap: 4 }}>
              <span className="mono" style={{ fontSize: 12 }}>
                {v.name} ({v.type}) → {v.serverName} on {v.bindAddr}:{v.bindPort}
              </span>
              <BindWarning host={v.bindAddr} what="this visitor" />
            </div>
          ))}
        </div>
      )}
    </>
  )
}
