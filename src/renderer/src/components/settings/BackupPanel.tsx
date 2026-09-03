import { useRef, useState } from 'react'
import { AlertTriangle, CheckCircle2, Download, Loader2, ShieldCheck, Trash2, Upload } from 'lucide-react'
import { useApp } from '../../store/app'
import { BackupDestinations } from './BackupDestinations'
import { toast } from '../../store/toast'
import type { BackupResult, BackupSummary } from '../../../../shared/backup'

function when(iso: string | null): string {
  if (!iso) return 'never'
  return new Date(iso).toLocaleString()
}

// A full path in a sentence is unreadable; the file's own name is the part
// someone recognises — and naming it is the difference between "that failed"
// and "that file failed", which is what tells them to pick a different one.
function fileName(path: string): string {
  return path.split(/[\\/]/).pop() || path
}

/** A failure, parked next to the control that caused it and carrying the way
 *  out. `where` is only about placement: an error about a backup file belongs
 *  beside the restore controls, not floating at the top of the panel where
 *  nothing can be done about it. */
interface PanelError {
  where: 'export' | 'import' | 'delete'
  text: string
  actions?: { label: string; run: () => void }[]
}

export function BackupPanel(): React.JSX.Element {
  const settings = useApp((s) => s.settings)
  const setSettings = useApp((s) => s.setSettings)

  const [exportPw, setExportPw] = useState('')
  const [exportPw2, setExportPw2] = useState('')
  const [importPw, setImportPw] = useState('')
  const [busy, setBusy] = useState<'export' | 'inspect' | 'import' | 'delete' | null>(null)
  const [staged, setStaged] = useState<{ path: string; summary: BackupSummary } | null>(null)
  const [error, setError] = useState<PanelError | null>(null)
  const [confirmDelete, setConfirmDelete] = useState(false)
  const [deleteTyped, setDeleteTyped] = useState('')
  const exportPwRef = useRef<HTMLInputElement>(null)

  const MIN_PASSPHRASE = 8
  const exportReady = exportPw.length >= MIN_PASSPHRASE && exportPw === exportPw2

  /** Did this call succeed? A cancelled dialog is neither success nor failure —
   *  the user already knows what they did, so it says nothing. */
  const failed = (r: BackupResult | undefined): boolean => {
    if (!r || r.cancelled) return true
    if (r.ok) setError(null)
    return !r.ok
  }

  const runExport = async (): Promise<void> => {
    if (!exportReady || busy) return
    setBusy('export')
    const r = await window.shellpilot?.backup.export(exportPw)
    setBusy(null)
    if (r?.cancelled) return
    if (failed(r)) {
      setError({
        where: 'export',
        text: `Nothing was written: ${r?.error ?? 'the file could not be saved.'} Your passphrase is still in the fields above.`,
        actions: [{ label: 'Try again', run: () => void runExport() }]
      })
      return
    }
    setSettings({ backupDirty: false, lastBackupAt: new Date().toISOString() })
    setExportPw('')
    setExportPw2('')
    toast(`Backup saved to ${r?.path}`, 'ok')
  }

  // `path` re-reads a file already chosen, which is what makes "try again after
  // fixing the passphrase" possible without walking back through the file
  // picker to select the very same file.
  const runInspect = async (path?: string): Promise<void> => {
    if (!importPw || busy) return
    setBusy('inspect')
    const r = await window.shellpilot?.backup.inspect(importPw, path)
    setBusy(null)
    if (r?.cancelled) return
    if (failed(r)) {
      const file = r?.path
      setError({
        where: 'import',
        text: file
          ? `${fileName(file)} did not open. ${r?.error ?? ''} The passphrase is the one chosen when that backup was made — not your vault master password.`
          : `That backup did not open. ${r?.error ?? ''}`,
        actions: [
          ...(file ? [{ label: 'Try this file again', run: () => void runInspect(file) }] : []),
          { label: 'Choose a different file', run: () => void runInspect() }
        ]
      })
      return
    }
    if (!r?.path || !r.summary) return
    setStaged({ path: r.path, summary: r.summary })
  }

  const runImport = async (): Promise<void> => {
    if (!staged || busy) return
    setBusy('import')
    const r = await window.shellpilot?.backup.import(importPw, staged.path)
    setBusy(null)
    if (failed(r)) {
      setError({
        where: 'import',
        // Not "nothing happened": a restore can fail after it has already
        // written some files, so the wording must not promise otherwise.
        text: `${fileName(staged.path)} was not fully restored. ${r?.error ?? 'The restore could not be completed.'}`,
        actions: [
          { label: 'Try again', run: () => void runImport() },
          { label: 'Choose a different file', run: () => void runInspect() }
        ]
      })
      return
    }
    toast('Backup restored — restarting', 'ok')
    setTimeout(() => void window.shellpilot?.backup.relaunch(), 700)
  }

  const runDeleteAll = async (): Promise<void> => {
    if (settings.backupDirty || deleteTyped !== 'DELETE' || busy) return
    setBusy('delete')
    const r = await window.shellpilot?.backup.deleteAll()
    setBusy(null)
    if (failed(r)) {
      setError({
        where: 'delete',
        // Deletion walks a list of files, so a failure can land half way
        // through. Saying "nothing was deleted" would be a guess.
        text: `Deleting stopped part of the way through: ${r?.error ?? 'a file could not be removed.'} Some data may already be gone — run it again to finish, or restore the backup above.`,
        actions: [{ label: 'Try again', run: () => void runDeleteAll() }]
      })
      return
    }
    toast('All data deleted — restarting', 'ok')
    setTimeout(() => void window.shellpilot?.backup.relaunch(), 700)
  }

  const errorFor = (where: PanelError['where']): React.JSX.Element | null =>
    error?.where === where ? (
      <div className="vault-error">
        <div className="row" style={{ gap: 8, alignItems: 'flex-start' }}>
          <span className="grow">{error.text}</span>
          {error.actions?.map((a) => (
            <button key={a.label} className="btn sm" style={{ flexShrink: 0 }} onClick={a.run}>
              {a.label}
            </button>
          ))}
        </div>
      </div>
    ) : null

  return (
    <div>
      <div className={settings.backupDirty ? 'backup-banner warn' : 'backup-banner ok'}>
        {settings.backupDirty ? <AlertTriangle size={16} /> : <CheckCircle2 size={16} />}
        <div>
          <div className="s-title">
            {settings.backupDirty ? 'Backup out of date' : 'Backup up to date'}
          </div>
          <div className="s-desc">
            {settings.backupDirty
              ? 'Your connections have changed since the last export. Download a new backup and store it somewhere safe so this configuration can be recovered.'
              : `Last exported ${when(settings.lastBackupAt)}.`}
          </div>
        </div>
      </div>

      <h3 className="backup-h">Download backup</h3>
      <p className="s-desc" style={{ marginBottom: 10 }}>
        Writes a single encrypted file containing your workspaces, servers, databases, tunnels,
        stored credentials, vault and trusted host keys. Credentials are re-encrypted under this
        passphrase, so the file restores on any machine — and is unreadable without it.
      </p>
      <div className="row" style={{ gap: 8 }}>
        <input
          className="input grow"
          ref={exportPwRef}
          type="password"
          placeholder={`Backup passphrase (min ${MIN_PASSPHRASE} characters)`}
          value={exportPw}
          onChange={(e) => setExportPw(e.target.value)}
        />
        <input
          className="input grow"
          type="password"
          placeholder="Confirm passphrase"
          value={exportPw2}
          onChange={(e) => setExportPw2(e.target.value)}
        />
        <button
          className="btn primary"
          disabled={!exportReady || busy !== null}
          title={
            exportReady
              ? 'Choose where to save the backup'
              : exportPw.length < MIN_PASSPHRASE
                ? `Pick a passphrase of at least ${MIN_PASSPHRASE} characters first`
                : 'The two passphrases must match'
          }
          onClick={() => void runExport()}
        >
          {busy === 'export' ? <Loader2 size={14} className="spin" /> : <Download size={14} />}
          Download
        </button>
      </div>
      {exportPw2.length > 0 && exportPw !== exportPw2 && (
        <div className="s-desc" style={{ color: 'var(--danger)' }}>Passphrases do not match.</div>
      )}
      <div className="s-desc" style={{ marginTop: 6 }}>
        <ShieldCheck size={12} /> Choose a passphrase you can find again — there is no way to open
        the file without it, and nothing here can reset it.
      </div>
      {errorFor('export')}

      <h3 className="backup-h">Restore from backup</h3>
      <p className="s-desc" style={{ marginBottom: 10 }}>
        Replaces everything currently in this app with the contents of the backup file. Type the
        passphrase for that backup first, then choose the file — you get to see what is inside it
        before anything is replaced, and the app restarts once the restore completes. The recorded
        history of the servers already on this machine is cleared as part of the restore: a backup
        does not carry history, and keeping the old estate's would leave two estates in one
        timeline.
      </p>
      <div className="row" style={{ gap: 8 }}>
        <input
          className="input grow"
          type="password"
          placeholder="Passphrase used for that backup"
          value={importPw}
          onChange={(e) => {
            setImportPw(e.target.value)
            setStaged(null)
            // The message named a file and a passphrase that no longer apply.
            if (error?.where === 'import') setError(null)
          }}
        />
        <button
          className="btn"
          disabled={!importPw || busy !== null}
          title={importPw ? 'Pick the backup file to read' : 'Type the backup passphrase first'}
          onClick={() => void runInspect()}
        >
          {busy === 'inspect' ? <Loader2 size={14} className="spin" /> : <Upload size={14} />}
          Choose file…
        </button>
      </div>
      {errorFor('import')}

      {staged && (
        <div className="backup-banner warn" style={{ marginTop: 12 }}>
          <AlertTriangle size={16} />
          <div style={{ flex: 1 }}>
            <div className="s-title">Replace current data?</div>
            <div className="s-desc">
              {staged.path}
              <br />
              Created {when(staged.summary.createdAt)} · {staged.summary.workspaces} workspaces ·{' '}
              {staged.summary.servers} servers · {staged.summary.databases} databases ·{' '}
              {staged.summary.secrets} credentials
              {staged.summary.hasVault ? ' · vault included' : ''}
            </div>
          </div>
          <button className="btn sm" onClick={() => setStaged(null)}>
            Cancel
          </button>
          <button className="btn sm danger" disabled={busy !== null} onClick={() => void runImport()}>
            {busy === 'import' ? <Loader2 size={13} className="spin" /> : null}
            Restore and restart
          </button>
        </div>
      )}

      <BackupDestinations />

      <h3 className="backup-h" style={{ color: 'var(--danger)' }}>
        Danger zone
      </h3>
      <p className="s-desc" style={{ marginBottom: 10 }}>
        Permanently deletes every workspace, server, database, tunnel, stored credential, the
        vault, trusted host keys and AI/MCP configuration — everything a backup covers, gone from
        this machine. It also deletes the recorded history: every sample, event and observed fact
        about your servers. This cannot be undone from within the app, and a backup does not
        contain the history — only what a backup covers can be brought back.
      </p>

      {settings.backupDirty ? (
        <div className="backup-banner warn">
          <AlertTriangle size={16} />
          <div style={{ flex: 1 }}>
            <div className="s-title">Back up first</div>
            <div className="s-desc">
              Your data has changed since the last backup — download one before deleting anything,
              or whatever changed since then is gone for good.
            </div>
          </div>
          {/* "Above" is a direction, not a next step. This puts the cursor in
              the field that does it. */}
          <button
            className="btn sm"
            onClick={() => {
              exportPwRef.current?.scrollIntoView({ block: 'center' })
              exportPwRef.current?.focus()
            }}
          >
            Back up now
          </button>
        </div>
      ) : !confirmDelete ? (
        <button className="btn danger" onClick={() => setConfirmDelete(true)}>
          <Trash2 size={14} /> Delete all data
        </button>
      ) : (
        <div className="backup-banner warn">
          <AlertTriangle size={16} />
          <div style={{ flex: 1 }}>
            <div className="s-title">This deletes everything on this machine</div>
            <div className="s-desc" style={{ marginBottom: 8 }}>
              Type <strong>DELETE</strong> to confirm. The app restarts once it's done.
            </div>
            <input
              className="input"
              style={{ maxWidth: 200 }}
              value={deleteTyped}
              onChange={(e) => setDeleteTyped(e.target.value)}
              placeholder="DELETE"
              autoFocus
            />
          </div>
          <button
            className="btn sm"
            onClick={() => {
              setConfirmDelete(false)
              setDeleteTyped('')
            }}
          >
            Cancel
          </button>
          <button
            className="btn sm danger"
            disabled={deleteTyped !== 'DELETE' || busy !== null}
            onClick={() => void runDeleteAll()}
          >
            {busy === 'delete' ? <Loader2 size={13} className="spin" /> : <Trash2 size={13} />}
            Delete everything
          </button>
        </div>
      )}
      {errorFor('delete')}
    </div>
  )
}
