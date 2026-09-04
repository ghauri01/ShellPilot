import { useEffect, useRef, useState } from 'react'
import { Copy, Eye, EyeOff, Fingerprint, KeyRound, Lock, Plus, ShieldCheck, Trash2, Unlock } from 'lucide-react'
import { useVault, newField } from '../../store/vault'
import { toast } from '../../store/toast'
import { clsx } from '../../lib/format'
import { useApp } from '../../store/app'
import { bridgeOn } from '../../lib/bridge'
import {
  VAULT_KIND_LABEL,
  VAULT_KIND_FIELDS,
  VAULT_SECRET_LABEL,
  hiddenFieldsFor,
  type VaultEntry,
  type VaultKind
} from '../../../../shared/vault'

const KINDS: VaultKind[] = ['login', 'url', 'key', 'sshkey', 'note']

// Which of the built-in fields each kind actually shows. The picker used to
// change nothing but an icon in the sidebar: every kind rendered URL, Username
// and Password, so a Note asked for a password and an API key had nowhere
// obvious to put the key. Name, tags, custom fields and notes are on every
// kind and are not listed here.
//
// Switching kind never deletes anything. A value typed under one kind is still
// stored, still searchable, and comes back if the kind is switched back — so
// this only decides what is on screen, which is the one thing it should decide.

function copy(label: string, value: string): void {
  if (!value) return
  window.shellpilot?.clipboard.write(value)
  toast(`${label} copied`)
}

export function VaultView(): React.JSX.Element {
  const exists = useVault((s) => s.exists)
  const unlocked = useVault((s) => s.unlocked)
  const refresh = useVault((s) => s.refresh)

  useEffect(() => {
    void refresh()
  }, [refresh])

  // Main locked the vault on an idle timeout. Drop the decrypted entries the
  // renderer is holding — leaving them would make the lock cosmetic, since the
  // plaintext lives here too.
  useEffect(
    () =>
      bridgeOn('vault.onAutoLocked', window.shellpilot?.vault?.onAutoLocked, () => {
        useVault.setState({ unlocked: false, entries: [], selectedId: null })
        // The unlock field is on screen the moment this fires — this view is
        // the only thing that listens — so the message points at it rather
        // than opening a second way to do the same thing.
        toast('Vault locked after inactivity — enter your master password to open it again')
      }),
    []
  )

  if (!exists) return <VaultGate mode="create" />
  if (!unlocked) return <VaultGate mode="unlock" />
  return <VaultBrowser />
}

// Create-master-password and unlock share a layout; only the copy and the
// action differ.
// What the platform actually calls it. Saying "Touch ID" on a Windows machine
// would be worse than saying nothing.
const BIO_LABEL: Record<string, string> = {
  'touch-id': 'Touch ID',
  'windows-hello': 'Windows Hello'
}

// 12, not 8. The vault file is the thing an attacker copies, and against a
// stolen file the master password's length is worth more than anything the
// unlock UI does. Only applies to passwords being chosen now — an existing
// vault is not forced to change on upgrade.
const MIN_PASSWORD = 12

function VaultGate({ mode }: { mode: 'create' | 'unlock' }): React.JSX.Element {
  const create = useVault((s) => s.create)
  const unlock = useVault((s) => s.unlock)
  const error = useVault((s) => s.error)
  const clearError = useVault((s) => s.clearError)
  const busy = useVault((s) => s.busy)

  const [password, setPassword] = useState('')
  const [confirm, setConfirm] = useState('')
  const [show, setShow] = useState(false)

  const bioAvailable = useVault((s) => s.bioAvailable)
  const bioEnabled = useVault((s) => s.bioEnabled)
  const bioKind = useVault((s) => s.bioKind)
  const refreshBiometrics = useVault((s) => s.refreshBiometrics)
  const unlockWithBiometrics = useVault((s) => s.unlockWithBiometrics)
  const canUseBio = mode === 'unlock' && bioAvailable && bioEnabled

  useEffect(() => {
    void refreshBiometrics()
  }, [refreshBiometrics])

  // Deliberately NOT fired automatically. The prompt is a gate, not a
  // cryptographic step, and a prompt that appears unbidden every time the app
  // opens trains people to touch the sensor without reading it — which is
  // exactly the habit that makes a prompt worth phishing. The button is one
  // click and says what it does.

  const creating = mode === 'create'
  const mismatch = creating && confirm.length > 0 && password !== confirm
  const canSubmit =
    password.length >= (creating ? MIN_PASSWORD : 1) && !mismatch && (!creating || confirm.length > 0)

  const passwordRef = useRef<HTMLInputElement>(null)

  const submit = async (): Promise<void> => {
    if (!canSubmit || busy) return
    const ok = creating ? await create(password) : await unlock(password)
    if (!ok) {
      // The only place this can be fixed is the field the user just typed in,
      // so put the cursor back in it with the attempt selected — the next
      // keystroke replaces it, and nobody has to work out where to try again.
      passwordRef.current?.select()
      passwordRef.current?.focus()
      return
    }
    setPassword('')
    setConfirm('')
    toast(creating ? 'Vault created' : 'Vault unlocked')
  }

  return (
    <div className="main vault-gate">
      <div className="vault-gate-card">
        <div className="vault-gate-icon">{creating ? <ShieldCheck size={26} /> : <Lock size={26} />}</div>
        <h2>{creating ? 'Create your vault' : 'Vault locked'}</h2>
        <p className="faint">
          {creating
            ? 'The vault keeps passwords, SSH keys and other secrets encrypted on this machine, so ShellPilot can use them without you retyping them. Pick a master password to protect it — it is never stored anywhere, so if you lose it the contents cannot be recovered.'
            : 'Enter the master password you chose for this vault. It stays open until you lock it, quit ShellPilot, or leave it idle long enough to lock itself.'}
        </p>

        {canUseBio && (
          <button
            className="btn primary"
            style={{ width: '100%', marginBottom: 10 }}
            disabled={busy}
            onClick={() => void unlockWithBiometrics()}
          >
            <Fingerprint size={15} /> Unlock with {BIO_LABEL[bioKind] ?? 'biometrics'}
          </button>
        )}

        <div className="row" style={{ gap: 6, marginTop: 4 }}>
          <input
            className="input"
            ref={passwordRef}
            type={show ? 'text' : 'password'}
            autoFocus
            style={{ flex: 1 }}
            placeholder={creating ? `Master password (min ${MIN_PASSWORD} characters)` : 'Master password'}
            value={password}
            onChange={(e) => {
              clearError()
              setPassword(e.target.value)
            }}
            onKeyDown={(e) => e.key === 'Enter' && void submit()}
          />
          <button className="icon-btn" title={show ? 'Hide' : 'Show'} onClick={() => setShow((v) => !v)}>
            {show ? <EyeOff size={16} /> : <Eye size={16} />}
          </button>
        </div>

        {creating && (
          <input
            className="input"
            type={show ? 'text' : 'password'}
            style={{ width: '100%', marginTop: 6 }}
            placeholder="Confirm master password"
            value={confirm}
            onChange={(e) => setConfirm(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && void submit()}
          />
        )}

        {/* Said here because the create screen is where people look for it and
            do not find it: a fingerprint cannot open a vault that does not
            exist yet — enableBiometricUnlock stores the key already in memory,
            and until a master password derives one there is nothing to store.
            Without this line the absence reads as the feature being missing.
            Gated on bioAvailable so it is never a promise this machine cannot
            keep, which is the whole point of biometricSupport() reporting a
            reason instead of a boolean. */}
        {creating && bioAvailable && (
          <div className="s-desc" style={{ marginTop: 6 }}>
            You can turn on {BIO_LABEL[bioKind] ?? 'biometric'} unlock as soon as the vault is set
            up, so this is the last time you type this password today.
          </div>
        )}

        {mismatch && <div className="vault-error">Passwords do not match.</div>}
        {error && <div className="vault-error">{error}</div>}
        {/* There is no reset link to offer, so say that plainly instead of
            leaving someone hunting for one. Caps lock is the usual culprit. */}
        {error && !creating && (
          <div className="s-desc" style={{ marginTop: 6 }}>
            Master passwords are case sensitive — check caps lock. Nothing can reset one: only this
            password opens this vault.
            {canUseBio ? ` You can also unlock with ${BIO_LABEL[bioKind] ?? 'biometrics'} above.` : ''}
          </div>
        )}

        <button
          className="btn primary"
          style={{ width: '100%', marginTop: 10, justifyContent: 'center' }}
          disabled={!canSubmit || busy}
          onClick={() => void submit()}
        >
          {creating ? <ShieldCheck size={15} /> : <Unlock size={15} />}
          {creating ? 'Create vault' : 'Unlock'}
        </button>
      </div>
    </div>
  )
}

// Remembers a decline so the offer is made once, not every unlock. A UI
// preference, so it lives with the UI rather than in the vault file.
const BIO_OFFER_DISMISSED = 'shellpilot.vault.bioOfferDismissed'

// Offered right after a successful unlock, which is the one moment the value
// is obvious — the user has just typed a long password and is about to do it
// again tomorrow. A toggle in the toolbar is discoverable only by someone
// already looking for it, which is nobody.
function BiometricOffer(): React.JSX.Element | null {
  const bioAvailable = useVault((s) => s.bioAvailable)
  const bioEnabled = useVault((s) => s.bioEnabled)
  const bioKind = useVault((s) => s.bioKind)
  const setBiometrics = useVault((s) => s.setBiometrics)
  const [dismissed, setDismissed] = useState(() => localStorage.getItem(BIO_OFFER_DISMISSED) === '1')

  if (!bioAvailable || bioEnabled || dismissed) return null
  const label = BIO_LABEL[bioKind] ?? 'biometrics'

  const decline = (): void => {
    localStorage.setItem(BIO_OFFER_DISMISSED, '1')
    setDismissed(true)
  }

  return (
    <div className="vault-bio-offer">
      <Fingerprint size={18} style={{ color: 'var(--accent)', flexShrink: 0 }} />
      <div style={{ flex: 1 }}>
        <div className="s-title">Unlock with {label} next time?</div>
        <div className="s-desc">
          Your master password is never stored either way, and you can change this at any time.
          <br />
          <b>While the app is running</b> — nothing extra is written to disk. You type the master
          password once per launch, and {label} reopens the vault after that.
          <br />
          <b>Across restarts</b> — the vault&rsquo;s key is saved to this Mac&rsquo;s keychain, so
          you stop typing the password altogether. It is the more convenient choice and the weaker
          one: anything that can read that keychain entry as your account can then open the vault.
        </div>
      </div>
      <button
        className="btn sm primary"
        onClick={() =>
          void setBiometrics(true, 'persistent').then(
            (ok) => ok && toast(`${label} unlock enabled, and remembered across restarts`, 'ok')
          )
        }
      >
        Across restarts
      </button>
      <button
        className="btn sm"
        onClick={() =>
          void setBiometrics(true, 'session').then((ok) => ok && toast(`${label} unlock enabled`, 'ok'))
        }
      >
        While it&rsquo;s running
      </button>
      <button className="btn sm" onClick={decline}>
        Not now
      </button>
    </div>
  )
}

function VaultBrowser(): React.JSX.Element {
  const bioAvailable = useVault((s) => s.bioAvailable)
  const bioEnabled = useVault((s) => s.bioEnabled)
  const bioKind = useVault((s) => s.bioKind)
  const bioScope = useVault((s) => s.bioScope)
  const setBiometrics = useVault((s) => s.setBiometrics)
  const refreshBiometrics = useVault((s) => s.refreshBiometrics)

  useEffect(() => {
    void refreshBiometrics()
  }, [refreshBiometrics])

  const entries = useVault((s) => s.entries)
  const selectedId = useVault((s) => s.selectedId)
  const lock = useVault((s) => s.lock)
  const addEntry = useVault((s) => s.addEntry)
  const error = useVault((s) => s.error)
  const [changing, setChanging] = useState(false)

  const entry = entries.find((e) => e.id === selectedId) ?? null

  return (
    <div className="main">
      <div className="viewbar">
        <KeyRound size={14} style={{ color: 'var(--accent)' }} />
        <b>Vault</b>
        <span className="server-meta">{entries.length} entries</span>
        <span className="spacer" />
        {bioAvailable && (
          <button
            className={clsx('btn', 'sm', bioEnabled && 'active')}
            title={
              bioEnabled
                ? `Stop unlocking with ${BIO_LABEL[bioKind] ?? 'biometrics'}, and delete the stored key`
                : `Store this vault's key so ${BIO_LABEL[bioKind] ?? 'biometrics'} can unlock it`
            }
            onClick={() => void setBiometrics(!bioEnabled)}
          >
            <Fingerprint size={13} /> {BIO_LABEL[bioKind] ?? 'Biometrics'}:{' '}
            {bioEnabled ? (bioScope === 'persistent' ? 'on, saved' : 'on, this session') : 'off'}
          </button>
        )}
        {/* The upgrade had no control at all: `persistent` was implemented,
            tested and reachable only by calling the store by hand, so a user who
            turned this on and then found the password prompt waiting after a
            restart had no way to say "no, keep it". */}
        {bioAvailable && bioEnabled && bioScope === 'session' && (
          <button
            className="btn sm"
            title={`Save this vault's key to the keychain so ${
              BIO_LABEL[bioKind] ?? 'biometrics'
            } opens it after a restart too. Anything that can read that entry as your account can then open the vault.`}
            onClick={() =>
              void setBiometrics(true, 'persistent').then(
                (ok) => ok && toast('Key saved — this vault opens after a restart now', 'ok')
              )
            }
          >
            Keep after restart
          </button>
        )}
        <button className="btn sm" onClick={() => setChanging((v) => !v)}>
          Change password
        </button>
        <button className="btn sm" onClick={() => void addEntry()}>
          <Plus size={13} /> New entry
        </button>
        <button className="btn sm" onClick={() => void lock()}>
          <Lock size={13} /> Lock
        </button>
      </div>

      <BiometricOffer />

      {/* While the change-password form is open it shows the failure beside the
          field that caused it, so the same sentence is not also floated at the
          top of the view, away from anything that can act on it. */}
      {error && !changing && <div className="vault-error" style={{ margin: 12 }}>{error}</div>}
      {changing && <ChangePassword onDone={() => setChanging(false)} />}

      {entry ? (
        <EntryEditor entry={entry} />
      ) : (
        <div className="faint" style={{ padding: 24, fontSize: 13 }}>
          Select an entry, or create one with <b>New entry</b>.
        </div>
      )}
    </div>
  )
}

function ChangePassword({ onDone }: { onDone: () => void }): React.JSX.Element {
  const changePassword = useVault((s) => s.changePassword)
  const clearError = useVault((s) => s.clearError)
  const error = useVault((s) => s.error)
  const busy = useVault((s) => s.busy)
  const bioEnabled = useVault((s) => s.bioEnabled)
  const bioKind = useVault((s) => s.bioKind)
  const [current, setCurrent] = useState('')
  const [next, setNext] = useState('')
  const currentRef = useRef<HTMLInputElement>(null)

  const ready = !busy && current.length > 0 && next.length >= MIN_PASSWORD

  const close = (): void => {
    clearError()
    onDone()
  }

  const save = async (): Promise<void> => {
    if (!ready) return
    if (await changePassword(current, next)) {
      toast('Master password changed', 'ok')
      close()
      return
    }
    // "Incorrect current password" is the only failure this form produces in
    // practice, and it is fixed in the field right here — so the cursor goes
    // back to it with the attempt selected rather than the user being told off
    // from somewhere else on the page.
    currentRef.current?.select()
    currentRef.current?.focus()
  }

  return (
    <div className="vault-panel">
      <div className="row" style={{ gap: 6 }}>
        <input
          className="input"
          ref={currentRef}
          type="password"
          autoFocus
          placeholder="Current master password"
          value={current}
          onChange={(e) => {
            clearError()
            setCurrent(e.target.value)
          }}
          onKeyDown={(e) => e.key === 'Enter' && void save()}
        />
        <input
          className="input"
          type="password"
          placeholder={`New master password (min ${MIN_PASSWORD} characters)`}
          value={next}
          onChange={(e) => {
            clearError()
            setNext(e.target.value)
          }}
          onKeyDown={(e) => e.key === 'Enter' && void save()}
        />
        <button className="btn primary sm" disabled={!ready} onClick={() => void save()}>
          Save
        </button>
        <button className="btn sm" onClick={close}>
          Cancel
        </button>
      </div>
      {error && <div className="vault-error">{error}</div>}
      <div className="faint" style={{ fontSize: 11, marginTop: 6 }}>
        Every entry is re-encrypted under the new password. Nothing moves and nothing is lost — but
        there is still no way to recover the vault if the new password is forgotten.
        {bioEnabled
          ? ` ${BIO_LABEL[bioKind] ?? 'Biometric'} unlock stops working until you switch it back on in the toolbar above: the key it saved was for the old password.`
          : ''}
      </div>
    </div>
  )
}

function EntryEditor({ entry }: { entry: VaultEntry }): React.JSX.Element {
  const update = useVault((s) => s.updateEntry)
  const remove = useVault((s) => s.deleteEntry)
  const [revealed, setRevealed] = useState<Record<string, boolean>>({})

  const set = (patch: Partial<VaultEntry>): void => void update(entry.id, patch)
  const toggle = (id: string): void => setRevealed((r) => ({ ...r, [id]: !r[id] }))

  const setField = (id: string, patch: Partial<(typeof entry.fields)[number]>): void =>
    set({ fields: entry.fields.map((f) => (f.id === id ? { ...f, ...patch } : f)) })

  const workspaces = useApp((s) => s.workspaces)
  const shown = VAULT_KIND_FIELDS[entry.kind] ?? VAULT_KIND_FIELDS.login

  // A value that belongs to a field this kind does not show is still stored and
  // still searchable, but it is now invisible — so say so rather than let it
  // look lost.
  const hiddenWithValue = hiddenFieldsFor(entry)

  return (
    <div className="vault-editor">
      <div className="row" style={{ gap: 8 }}>
        <input
          className="input"
          style={{ flex: 1, fontWeight: 600 }}
          value={entry.name}
          placeholder="Entry name"
          onChange={(e) => set({ name: e.target.value })}
        />
        <select className="input" value={entry.kind} onChange={(e) => set({ kind: e.target.value as VaultKind })}>
          {KINDS.map((k) => (
            <option key={k} value={k}>
              {VAULT_KIND_LABEL[k]}
            </option>
          ))}
        </select>
        <button
          className="btn sm danger"
          title="Delete this entry"
          onClick={() => {
            // Same question the sidebar asks. Two delete paths that disagree
            // about whether this is confirmable is worse than either.
            if (
              !window.confirm(
                `Delete “${entry.name}” from the vault?\n\nThis cannot be undone, and anything using this entry will stop being able to authenticate.`
              )
            ) {
              return
            }
            remove(entry.id)
            toast(`${entry.name} deleted`)
          }}
        >
          <Trash2 size={13} />
        </button>
      </div>

      {shown.url && (
        <Row label="URL" value={entry.url} onChange={(v) => set({ url: v })} placeholder="https://…" />
      )}
      {shown.username && (
        <Row label="Username" value={entry.username} onChange={(v) => set({ username: v })} />
      )}
      {shown.keys && (
        <>
          <Multiline
            label="Private key"
            value={entry.privateKey ?? ''}
            onChange={(v) => set({ privateKey: v })}
            placeholder={'-----BEGIN OPENSSH PRIVATE KEY-----\n…'}
            secret
            revealed={!!revealed.__privkey}
            onReveal={() => toggle('__privkey')}
          />
          <Multiline
            label="Public key"
            value={entry.publicKey ?? ''}
            onChange={(v) => set({ publicKey: v })}
            placeholder="ssh-ed25519 AAAA… user@host"
          />
        </>
      )}
      {shown.secret && (
        <Row
          label={VAULT_SECRET_LABEL[shown.secret]}
          value={entry.password}
          onChange={(v) => set({ password: v })}
          secret
          revealed={!!revealed.__pw}
          onReveal={() => toggle('__pw')}
        />
      )}
      <div className="row" style={{ gap: 6 }}>
        <span className="vault-label">Workspace</span>
        <select
          className="input"
          style={{ flex: 1 }}
          value={entry.workspaceId ?? ''}
          onChange={(e) => set({ workspaceId: e.target.value || undefined })}
        >
          <option value="">Shared — visible in every workspace</option>
          {workspaces.map((w) => (
            <option key={w.id} value={w.id}>
              {w.name}
            </option>
          ))}
        </select>
      </div>

      <Row
        label="Tags"
        value={entry.tags.join(', ')}
        onChange={(v) => set({ tags: v.split(',').map((t) => t.trim()).filter(Boolean) })}
        placeholder="prod, aws"
      />

      {hiddenWithValue.length > 0 && (
        <div className="s-desc" style={{ marginTop: 8 }}>
          This entry also has a stored {hiddenWithValue.join(' and ')}, kept but not shown for a{' '}
          {VAULT_KIND_LABEL[entry.kind].toLowerCase()}. Switch the type back to see it.
        </div>
      )}

      <div className="vault-section-title">
        Custom fields
        <button className="btn sm" onClick={() => set({ fields: [...entry.fields, newField()] })}>
          <Plus size={13} /> Add field
        </button>
      </div>

      {entry.fields.map((f) => (
        <div className="row" key={f.id} style={{ gap: 6 }}>
          <input
            className="input"
            style={{ width: 170 }}
            placeholder="key"
            value={f.key}
            onChange={(e) => setField(f.id, { key: e.target.value })}
          />
          <input
            className="input"
            style={{ flex: 1 }}
            placeholder="value"
            type={f.secret && !revealed[f.id] ? 'password' : 'text'}
            value={f.value}
            onChange={(e) => setField(f.id, { value: e.target.value })}
          />
          <button
            className="icon-btn sm"
            title={f.secret ? 'Marked secret' : 'Mark as secret'}
            onClick={() => setField(f.id, { secret: !f.secret })}
          >
            {f.secret ? <Lock size={14} /> : <Unlock size={14} />}
          </button>
          {f.secret && (
            <button className="icon-btn sm" title="Reveal" onClick={() => toggle(f.id)}>
              {revealed[f.id] ? <EyeOff size={14} /> : <Eye size={14} />}
            </button>
          )}
          <button className="icon-btn sm" title="Copy value" onClick={() => copy(f.key || 'Value', f.value)}>
            <Copy size={14} />
          </button>
          <button
            className="icon-btn sm"
            title="Remove field"
            onClick={() => set({ fields: entry.fields.filter((x) => x.id !== f.id) })}
          >
            <Trash2 size={14} />
          </button>
        </div>
      ))}

      <div className="vault-section-title">Notes</div>
      <textarea
        className="textarea"
        style={{ width: '100%', minHeight: 90 }}
        value={entry.notes}
        spellCheck={false}
        onChange={(e) => set({ notes: e.target.value })}
      />

      <div className="faint" style={{ fontSize: 11 }}>
        Updated {new Date(entry.updatedAt).toLocaleString()}
      </div>
    </div>
  )
}

// PEM material is many lines long and unusable in a single-line input, which
// is why storing the key itself was never practical before.
function Multiline({
  label,
  value,
  onChange,
  placeholder,
  secret,
  revealed,
  onReveal
}: {
  label: string
  value: string
  onChange: (v: string) => void
  placeholder?: string
  secret?: boolean
  revealed?: boolean
  onReveal?: () => void
}): React.JSX.Element {
  const masked = secret && !revealed && value.length > 0
  return (
    <div className="row" style={{ gap: 6, alignItems: 'flex-start' }}>
      <span className="vault-label" style={{ paddingTop: 8 }}>
        {label}
      </span>
      <textarea
        className="input mono"
        style={{ flex: 1, minHeight: 96, resize: 'vertical', lineHeight: 1.4 }}
        spellCheck={false}
        placeholder={placeholder}
        // A revealed key is shown verbatim; a hidden one shows its shape, so
        // you can tell an entry holds a key without exposing it on screen.
        value={masked ? `${value.split('\n').length} lines hidden` : value}
        readOnly={masked}
        onChange={(e) => onChange(e.target.value)}
      />
      <div className="col" style={{ gap: 4 }}>
        {secret && (
          <button className="icon-btn sm" title="Reveal" onClick={onReveal}>
            {revealed ? <EyeOff size={14} /> : <Eye size={14} />}
          </button>
        )}
        <button className="icon-btn sm" title={`Copy ${label.toLowerCase()}`} onClick={() => copy(label, value)}>
          <Copy size={14} />
        </button>
      </div>
    </div>
  )
}

function Row({
  label,
  value,
  onChange,
  placeholder,
  secret,
  revealed,
  onReveal
}: {
  label: string
  value: string
  onChange: (v: string) => void
  placeholder?: string
  secret?: boolean
  revealed?: boolean
  onReveal?: () => void
}): React.JSX.Element {
  return (
    <div className="row" style={{ gap: 6 }}>
      <span className="vault-label">{label}</span>
      <input
        className="input"
        style={{ flex: 1 }}
        type={secret && !revealed ? 'password' : 'text'}
        placeholder={placeholder}
        value={value}
        onChange={(e) => onChange(e.target.value)}
      />
      {secret && (
        <button className="icon-btn sm" title="Reveal" onClick={onReveal}>
          {revealed ? <EyeOff size={14} /> : <Eye size={14} />}
        </button>
      )}
      <button className="icon-btn sm" title={`Copy ${label.toLowerCase()}`} onClick={() => copy(label, value)}>
        <Copy size={14} />
      </button>
    </div>
  )
}
