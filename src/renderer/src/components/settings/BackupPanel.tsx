import { useState } from 'react'
import { AlertTriangle, CheckCircle2, Download, Loader2, ShieldCheck, Upload } from 'lucide-react'
import { useApp } from '../../store/app'
import { toast } from '../../store/toast'
import type { BackupResult, BackupSummary } from '../../../../shared/backup'

function when(iso: string | null): string {
  if (!iso) return 'never'
  return new Date(iso).toLocaleString()
}

export function BackupPanel(): React.JSX.Element {
  const settings = useApp((s) => s.settings)
  const setSettings = useApp((s) => s.setSettings)

  const [exportPw, setExportPw] = useState('')
  const [exportPw2, setExportPw2] = useState('')
  const [importPw, setImportPw] = useState('')
  const [busy, setBusy] = useState<'export' | 'inspect' | 'import' | null>(null)
  const [staged, setStaged] = useState<{ path: string; summary: BackupSummary } | null>(null)
  const [error, setError] = useState<string | null>(null)

  const exportReady = exportPw.length >= 8 && exportPw === exportPw2

  const report = (r: BackupResult | undefined): boolean => {
    if (!r) return false
    if (r.cancelled) return false
    if (!r.ok) {
      setError(r.error ?? 'Operation failed.')
      return false
    }
    setError(null)
    return true
  }

  const runExport = async (): Promise<void> => {
    if (!exportReady || busy) return
    setBusy('export')
    const r = await window.shellpilot?.backup.export(exportPw)
    setBusy(null)
    if (!report(r)) return
    setSettings({ backupDirty: false, lastBackupAt: new Date().toISOString() })
    setExportPw('')
    setExportPw2('')
    toast(`Backup saved to ${r?.path}`, 'ok')
  }

  const runInspect = async (): Promise<void> => {
    if (!importPw || busy) return
    setBusy('inspect')
    const r = await window.shellpilot?.backup.inspect(importPw)
    setBusy(null)
    if (!report(r) || !r?.path || !r.summary) return
    setStaged({ path: r.path, summary: r.summary })
  }

  const runImport = async (): Promise<void> => {
    if (!staged || busy) return
    setBusy('import')
    const r = await window.shellpilot?.backup.import(importPw, staged.path)
    setBusy(null)
    if (!report(r)) return
    toast('Backup restored — restarting', 'ok')
    setTimeout(() => void window.shellpilot?.backup.relaunch(), 700)
  }

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

      {error && <div className="vault-error">{error}</div>}

      <h3 className="backup-h">Download backup</h3>
      <p className="s-desc" style={{ marginBottom: 10 }}>
        Writes a single encrypted file containing your workspaces, servers, databases, tunnels,
        stored credentials, vault and trusted host keys. Credentials are re-encrypted under this
        passphrase, so the file restores on any machine — and is unreadable without it.
      </p>
      <div className="row" style={{ gap: 8 }}>
        <input
          className="input grow"
          type="password"
          placeholder="Backup passphrase (min 8 characters)"
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
        <button className="btn primary" disabled={!exportReady || busy !== null} onClick={() => void runExport()}>
          {busy === 'export' ? <Loader2 size={14} className="spin" /> : <Download size={14} />}
          Download
        </button>
      </div>
      {exportPw2.length > 0 && exportPw !== exportPw2 && (
        <div className="s-desc" style={{ color: 'var(--danger)' }}>Passphrases do not match.</div>
      )}
      <div className="s-desc" style={{ marginTop: 6 }}>
        <ShieldCheck size={12} /> There is no recovery if the passphrase is lost.
      </div>

      <h3 className="backup-h">Restore from backup</h3>
      <p className="s-desc" style={{ marginBottom: 10 }}>
        Replaces everything currently in this app with the contents of the backup file. The app
        restarts once the restore completes.
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
          }}
        />
        <button className="btn" disabled={!importPw || busy !== null} onClick={() => void runInspect()}>
          {busy === 'inspect' ? <Loader2 size={14} className="spin" /> : <Upload size={14} />}
          Choose file…
        </button>
      </div>

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
    </div>
  )
}
