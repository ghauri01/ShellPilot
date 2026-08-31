import { useCallback, useEffect, useRef, useState } from 'react'
import { AlertTriangle, FileUp, ShieldAlert, Upload } from 'lucide-react'
import { Modal } from '../common/Modal'
import { VpnProfileForm } from './VpnProfileForm'
import { useApp } from '../../store/app'
import { toast } from '../../store/toast'
import type { StrippedDirective, VpnImportResult, VpnKind, VpnProfile } from '../../types'
import { bridgeHas } from '../../lib/bridge'
import { isVaultLocked, withVaultUnlock } from '../../lib/withVaultUnlock'

const ACCEPT: Record<VpnKind, string> = {
  wireguard: '.conf',
  openvpn: '.ovpn,.conf',
  frp: '.toml,.ini'
}

const HINT: Record<VpnKind, string> = {
  wireguard: 'Paste a WireGuard .conf, or drop the file here.',
  openvpn: 'Paste an .ovpn profile, or drop the file here.',
  frp: 'Paste an frpc .toml (or .ini), or drop the file here.'
}

const TITLE: Record<VpnKind, string> = {
  wireguard: 'Import WireGuard config',
  openvpn: 'Import OpenVPN profile',
  frp: 'Import frp client config'
}

interface VpnImportModalProps {
  kind: VpnKind
  onClose: () => void
}

// Import is the one moment the user hands us a file somebody else wrote, so it
// is also the one moment to say plainly what we refused to carry over. The
// report is shown before anything is written: a profile that silently dropped
// the half of the config that made it work is worse than a failed import.
export function VpnImportModal({ kind, onClose }: VpnImportModalProps): React.JSX.Element {
  const workspaceId = useApp((s) => s.activeId())
  const upsertVpnProfile = useApp((s) => s.upsertVpnProfile)

  const [text, setText] = useState('')
  const [name, setName] = useState('')
  const [nameTouched, setNameTouched] = useState(false)
  const [report, setReport] = useState<VpnImportResult | null>(null)
  const [parsing, setParsing] = useState(false)
  const [saving, setSaving] = useState(false)
  const [dragging, setDragging] = useState(false)
  const [readWarnings, setReadWarnings] = useState(false)
  // Shown in the card rather than thrown at a toast: the modal stays open on a
  // failed commit, and the card is where there is room for the whole reason
  // next to the button that resolves it.
  const [commitError, setCommitError] = useState<{ message: string; vaultLocked: boolean } | null>(
    null
  )
  // Set when the import committed but the profile is not startable yet, so the
  // modal hands straight over to the form instead of closing.
  const [created, setCreated] = useState<VpnProfile | null>(null)
  const fileInput = useRef<HTMLInputElement>(null)
  // Read, not tracked: once the user names the profile, a later re-parse must
  // not fight them for the field.
  const touched = useRef(false)
  touched.current = nameTouched

  // Parsing is pure in main — no process, no network — so re-running it while
  // the user edits costs nothing but IPC. Debounced enough to collapse a paste.
  useEffect(() => {
    const body = text.trim()
    if (!body) {
      setReport(null)
      return
    }
    if (!bridgeHas(window.shellpilot?.vpn as Record<string, unknown> | undefined, 'import')) return
    let live = true
    setParsing(true)
    const t = setTimeout(() => {
      void window.shellpilot?.vpn.import(kind, body).then((r) => {
        if (!live) return
        setParsing(false)
        setReport(r ?? null)
        // Every re-parse clears the acknowledgement: the user has not read a
        // list they have not been shown yet. The last commit failure goes with
        // it — it was about text that is no longer in the box.
        setReadWarnings(false)
        setCommitError(null)
        if (r?.name && !touched.current) setName(r.name)
      })
    }, 250)
    return () => {
      live = false
      clearTimeout(t)
    }
  }, [text, kind])

  const takeFile = useCallback(async (file: File) => {
    const body = await file.text()
    setText(body)
    setNameTouched(true)
    setName((n) => n || file.name.replace(/\.(conf|ovpn|toml|ini)$/i, ''))
  }, [])

  const stripped: StrippedDirective[] = report?.stripped ?? []
  const rejected = stripped.filter((d) => d.severity === 'rejected')
  const removed = stripped.filter((d) => d.severity === 'removed')
  const blocked = rejected.length > 0 || (report ? !report.ok : false)
  const needsAck = removed.length > 0 && !readWarnings
  // `!parsing` belongs in here as much as the rest of it. A click that lands
  // inside the parse debounce would otherwise commit text whose stripped
  // report the user has not been shown — which is the one thing the subtitle
  // of this modal promises will never happen.
  const canSave = !!report?.spec && !blocked && !needsAck && !!name.trim() && !saving && !parsing

  // The footer line does double duty: it is the modal's status, and it is the
  // reason Import is disabled, sitting next to the button it is about. It says
  // what is true right now — "paste a config to begin" after a config had been
  // pasted and rejected was both stale and no help at all.
  const status = (): string => {
    if (parsing) return 'Checking this config…'
    if (saving) return 'Importing…'
    if (!text.trim()) return 'Paste or drop a config to begin.'
    if (rejected.length > 0)
      return 'This config was rejected. Remove the directive above, then paste it again.'
    if (blocked || !report?.spec) return report?.error ?? 'This config could not be read.'
    if (needsAck)
      return removed.length === 1
        ? 'Read the removed directive above to continue.'
        : 'Read the removed directives above to continue.'
    if (!name.trim()) return 'Name this profile to import it.'
    // "Ready to import." sitting under a red box that says it was not imported
    // is the kind of contradiction that makes people distrust the whole screen.
    if (commitError) return 'Not imported — see the message above.'
    return 'Ready to import.'
  }

  const save = async (): Promise<void> => {
    if (!canSave) return
    setSaving(true)
    setCommitError(null)
    // Commit re-runs the import in main so the secrets land in the vault there.
    // The parse we already hold carries refs, never key material, so it can
    // never be the thing that gets saved.
    //
    // Wrapped because the vault is where those secrets go, so a shut vault
    // stops the import — and asking here and carrying straight on is the whole
    // point: the common case is a password box and then a finished import, not
    // a red sentence about a thing the user has not met yet and has to go and
    // find. `commitImport`'s preload signature predates `errorCode`, but its
    // handler has returned one from the start (services/vpn/import.ts), and
    // withVaultUnlock reads the value rather than the declared type.
    const committed = await withVaultUnlock(`Importing ${name.trim()}`, () =>
      Promise.resolve(
        window.shellpilot?.vpn.commitImport(name.trim(), workspaceId, kind, text.trim())
      )
    )
    setSaving(false)
    if (!committed?.ok || !committed.spec) {
      // True only when the user declined the dialog above — withVaultUnlock has
      // already asked once and retried.
      const vaultLocked = isVaultLocked(committed)
      setCommitError({
        message: vaultLocked
          ? 'Nothing was imported: this profile’s keys and certificates are stored in the vault, and the vault is shut.'
          : (committed?.error ?? 'This profile could not be imported.'),
        vaultLocked
      })
      return
    }
    const spec = committed.spec
    // Keep the report on the profile. Six months from now, "why does this
    // profile not set my DNS" is answerable from the profile itself rather than
    // from a modal the user closed at import time.
    if (!spec.strippedDirectives && stripped.length > 0) spec.strippedDirectives = stripped
    const profile: VpnProfile = {
      id: `vpn-${crypto.randomUUID()}`,
      workspaceId,
      name: name.trim(),
      autoStart: false,
      spec
    }
    upsertVpnProfile(profile)
    // frp is the one kind that is not startable the moment it is imported:
    // every imported proxy arrives with acknowledgedExposure false and start()
    // refuses until each one is ticked. "Press Start to connect" would send the
    // user at a button that cannot move, so say what actually stands in the way
    // and open the form that holds the ticks.
    const proxies = spec.kind === 'frp' ? spec.proxies : []
    if (proxies.length > 0) {
      const what =
        proxies.length === 1
          ? 'what its proxy exposes'
          : `what each of its ${proxies.length} proxies exposes`
      toast(`${profile.name} imported — confirm ${what} before starting`, 'ok')
      setCreated(profile)
      return
    }
    toast(`${profile.name} imported — press Start to connect`, 'ok')
    onClose()
  }

  // Handing over rather than closing. The profile is saved either way, but
  // leaving the user to find the form themselves is how an imported frp client
  // sits there unstartable with no obvious next move.
  if (created) return <VpnProfileForm profile={created} onClose={onClose} />

  return (
    <Modal
      title={TITLE[kind]}
      subtitle="Nothing is saved until you have seen what was stripped out"
      size="lg"
      onClose={onClose}
      // In the sticky footer, like every other modal in the app. Inside
      // `children` the whole row scrolls with the body, so on a config with a
      // long stripped-directive report both Import and the line explaining why
      // it is disabled start out below the fold.
      footer={
        <>
          <span className="faint" style={{ flex: 1, fontSize: 11, textAlign: 'right' }}>
            {status()}
          </span>
          <button className="btn" onClick={onClose}>
            Cancel
          </button>
          <button className="btn primary" disabled={!canSave} onClick={() => void save()}>
            Import profile
          </button>
        </>
      }
    >
      <div className="card" style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
        <div
          className="col"
          style={{
            gap: 8,
            padding: 10,
            borderRadius: 'var(--r-md)',
            border: `1px dashed ${dragging ? 'var(--accent)' : 'var(--border)'}`,
            background: dragging ? 'var(--accent-soft)' : undefined
          }}
          onDragOver={(e) => {
            e.preventDefault()
            setDragging(true)
          }}
          onDragLeave={() => setDragging(false)}
          onDrop={(e) => {
            e.preventDefault()
            setDragging(false)
            const file = e.dataTransfer.files[0]
            if (file) void takeFile(file)
          }}
        >
          <div className="row" style={{ gap: 8 }}>
            <FileUp size={14} className="faint" />
            <span className="muted" style={{ fontSize: 12 }}>
              {HINT[kind]}
            </span>
            <span className="grow" />
            <button className="btn sm" onClick={() => fileInput.current?.click()}>
              <Upload size={13} /> Choose file
            </button>
            <input
              ref={fileInput}
              type="file"
              accept={ACCEPT[kind]}
              style={{ display: 'none' }}
              onChange={(e) => {
                const file = e.target.files?.[0]
                if (file) void takeFile(file)
              }}
            />
          </div>
          <textarea
            className="textarea"
            style={{ minHeight: 130 }}
            // The whole modal exists to receive a paste, so the paste target is
            // what the keyboard should already be in.
            autoFocus
            spellCheck={false}
            placeholder={HINT[kind]}
            value={text}
            onChange={(e) => setText(e.target.value)}
          />
        </div>

        {rejected.length > 0 && (
          <div
            className="col"
            style={{
              gap: 6,
              padding: 10,
              borderRadius: 'var(--r-md)',
              background: 'var(--danger-soft)',
              color: 'var(--danger)'
            }}
          >
            <div className="row" style={{ gap: 8, fontWeight: 600, fontSize: 12 }}>
              <ShieldAlert size={14} />
              <span>This config cannot be imported</span>
            </div>
            {/* Quoting the line matters. "Rejected for security reasons" sends
                the user to a forum; the directive itself sends them to the one
                line they have to remove or ask their admin about. */}
            {rejected.map((d, i) => (
              <div key={`${d.directive}-${i}`} className="col" style={{ gap: 2 }}>
                <code className="mono" style={{ fontSize: 12 }}>
                  {d.directive}
                </code>
                <span style={{ fontSize: 11, opacity: 0.9 }}>{d.reason}</span>
              </div>
            ))}
            <span style={{ fontSize: 11, opacity: 0.9 }}>
              These directives run commands on your machine. ShellPilot re-emits a config it
              generated itself, so it cannot honour them — and importing while pretending it had
              would be a lie about what this profile does.
            </span>
          </div>
        )}

        {commitError && (
          <div className="conn-error" style={{ borderRadius: 'var(--r-sm)', border: 'none' }}>
            <AlertTriangle size={13} style={{ flexShrink: 0 }} />
            <span className="grow">{commitError.message}</span>
            {commitError.vaultLocked && (
              <button
                className="btn sm primary"
                style={{ flexShrink: 0 }}
                onClick={() => void save()}
              >
                Unlock vault and import
              </button>
            )}
          </div>
        )}

        {report?.error && rejected.length === 0 && (
          <div className="conn-error" style={{ borderRadius: 'var(--r-sm)', border: 'none' }}>
            <AlertTriangle size={13} />
            <span>{report.error}</span>
          </div>
        )}

        {removed.length > 0 && (
          <div className="col" style={{ gap: 6 }}>
            <span className="field-label" style={{ color: 'var(--warn)' }}>
              {removed.length} {removed.length === 1 ? 'directive was' : 'directives were'} removed
            </span>
            <div
              className="paste-preview"
              style={{ maxHeight: 150 }}
              onScroll={(e) => {
                const el = e.currentTarget
                if (el.scrollHeight - el.scrollTop - el.clientHeight < 8) setReadWarnings(true)
              }}
              // A short list has nothing to scroll, so it counts as read as soon
              // as it is on screen — otherwise Import could never enable.
              ref={(el) => {
                if (el && el.scrollHeight <= el.clientHeight) setReadWarnings(true)
              }}
            >
              {removed.map((d, i) => (
                <div key={`${d.directive}-${i}`} style={{ marginBottom: 6 }}>
                  <div style={{ color: 'var(--warn)' }}>{d.directive}</div>
                  <div className="faint">{d.reason}</div>
                </div>
              ))}
            </div>
            {needsAck && (
              <span className="faint" style={{ fontSize: 11 }}>
                Scroll to the end of the list to continue.
              </span>
            )}
          </div>
        )}

        {(report?.warnings.length ?? 0) > 0 && (
          <div className="col" style={{ gap: 4 }}>
            {report?.warnings.map((w, i) => (
              <div key={i} className="row" style={{ gap: 6, color: 'var(--warn)', fontSize: 11 }}>
                <AlertTriangle size={12} />
                <span>{w}</span>
              </div>
            ))}
          </div>
        )}

        <label className="field">
          <span className="field-label">Profile name</span>
          <input
            className="input"
            value={name}
            placeholder="Office VPN"
            onChange={(e) => {
              setNameTouched(true)
              setName(e.target.value)
            }}
          />
        </label>
      </div>
    </Modal>
  )
}
