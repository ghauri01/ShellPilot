import { useCallback, useEffect, useState } from 'react'
import {
  AlertTriangle,
  CheckCircle2,
  CloudUpload,
  Database,
  FolderOpen,
  Loader2,
  Plus,
  RotateCcw,
  ShieldAlert,
  Trash2
} from 'lucide-react'
import { useApp } from '../../store/app'
import { useVault } from '../../store/vault'
import { toast } from '../../store/toast'
import {
  BACKUP_DESTINATION_EXPOSURE,
  BACKUP_DESTINATION_KINDS,
  BACKUP_DESTINATION_LABEL,
  BACKUP_STAGE_LABEL,
  destinationProblem
} from '../../../../shared/backup'
import type {
  BackupDestination,
  BackupDestinationKind,
  BackupGeneration,
  BackupRunReport,
  BackupSummary,
  BackupTargetsFile,
  DumpEngine
} from '../../../../shared/backup'

const MIN_PASSPHRASE = 8

function uid(): string {
  return `bd-${Math.random().toString(36).slice(2, 10)}${Date.now().toString(36)}`
}

function blank(kind: BackupDestinationKind): BackupDestination {
  const base = { id: uid(), name: '', keep: 0, everyHours: 0, restoreTest: true }
  if (kind === 'local') return { ...base, kind: 'local', directory: '' }
  if (kind === 'sftp') return { ...base, kind: 'sftp', serverId: '', directory: '' }
  return {
    ...base,
    kind: 's3',
    endpoint: '',
    region: '',
    bucket: '',
    prefix: '',
    vaultEntryId: '',
    pathStyle: true
  }
}

function when(ms: number | undefined): string {
  return ms ? new Date(ms).toLocaleString() : 'never'
}

/** What the last run actually proved, in the words of what was checked. Never
 *  "backed up" for a run that was not read back — see describeRun in shared. */
function outcome(report: BackupRunReport | undefined): { ok: boolean; text: string } | null {
  if (!report) return null
  if (!report.ok) {
    const stage = report.failedStage ? BACKUP_STAGE_LABEL[report.failedStage] : 'running'
    return { ok: false, text: `Failed while ${stage}: ${report.error ?? 'no reason given'}` }
  }
  const proved = report.restoreTested
    ? 'read back off the destination and test-restored'
    : 'read back off the destination and matched'
  const removed = report.removed.length ? `, ${report.removed.length} older removed` : ''
  return { ok: true, text: `${report.name} — ${proved}${removed}` }
}

export function BackupDestinations(): React.JSX.Element {
  const servers = useApp((s) => s.servers)
  const vaultUnlocked = useVault((s) => s.unlocked)
  const vaultEntries = useVault((s) => s.entries)

  const [file, setFile] = useState<BackupTargetsFile | null>(null)
  const [editing, setEditing] = useState<BackupDestination | null>(null)
  const [busy, setBusy] = useState<string | null>(null)
  const [runPw, setRunPw] = useState<Record<string, string>>({})
  const [browsing, setBrowsing] = useState<string | null>(null)
  const [generations, setGenerations] = useState<BackupGeneration[]>([])
  const [browseError, setBrowseError] = useState<string | null>(null)
  const [staged, setStaged] = useState<{ path: string; summary: BackupSummary; name: string } | null>(
    null
  )
  const [databases, setDatabases] = useState<{ id: string; name: string; engine: DumpEngine }[]>([])
  const [dumpChoice, setDumpChoice] = useState<Record<string, string>>({})
  const [dumpResult, setDumpResult] = useState<Record<string, string>>({})

  const load = useCallback(async (): Promise<void> => {
    const f = await window.shellpilot?.backup.destinations?.()
    if (f) setFile(f)
  }, [])

  useEffect(() => {
    void load()
    void window.shellpilot?.backup.dumpableDatabases?.().then((d) => setDatabases(d ?? []))
  }, [load])

  const destinations = file?.destinations ?? []

  const persist = async (next: BackupDestination[]): Promise<void> => {
    const saved = await window.shellpilot?.backup.saveDestinations?.(next)
    if (saved) setFile(saved)
  }

  const runNow = async (dest: BackupDestination): Promise<void> => {
    const password = runPw[dest.id] ?? ''
    if (password.length < MIN_PASSPHRASE) return
    setBusy(dest.id)
    const report = await window.shellpilot?.backup.runDestination?.(dest.id, password)
    setBusy(null)
    await load()
    if (!report) return
    if (report.ok) {
      setRunPw((p) => ({ ...p, [dest.id]: '' }))
      toast(`${dest.name}: ${report.name} written and verified`, 'ok')
    } else {
      // Deliberately not a toast that says "check the panel": the reason is
      // already on the card, and the toast that hides it is how a failing
      // backup becomes a backup nobody thinks about.
      toast(`${dest.name} failed — ${report.error ?? 'no reason given'}`, 'error')
    }
  }

  const browse = async (dest: BackupDestination): Promise<void> => {
    setBusy(dest.id)
    setBrowseError(null)
    setStaged(null)
    const r = await window.shellpilot?.backup.listRemote?.(dest.id)
    setBusy(null)
    if (!r?.ok) {
      setBrowsing(dest.id)
      setGenerations([])
      setBrowseError(r?.error ?? 'That destination could not be read.')
      return
    }
    setBrowsing(dest.id)
    setGenerations(r.generations ?? [])
  }

  const inspect = async (dest: BackupDestination, name: string): Promise<void> => {
    const password = runPw[dest.id] ?? ''
    if (!password) return
    setBusy(dest.id)
    const r = await window.shellpilot?.backup.inspectRemote?.(dest.id, name, password)
    setBusy(null)
    if (!r?.ok || !r.path || !r.summary) {
      setBrowseError(r?.error ?? 'That backup did not open.')
      setStaged(null)
      return
    }
    setBrowseError(null)
    setStaged({ path: r.path, summary: r.summary, name })
  }

  const restore = async (): Promise<void> => {
    if (!staged) return
    setBusy('restore')
    const r = await window.shellpilot?.backup.import(
      runPw[browsing ?? ''] ?? '',
      staged.path
    )
    setBusy(null)
    if (!r?.ok) {
      setBrowseError(`${staged.name} was not fully restored. ${r?.error ?? ''}`)
      return
    }
    toast('Backup restored — restarting', 'ok')
    setTimeout(() => void window.shellpilot?.backup.relaunch(), 700)
  }

  const dump = async (dest: BackupDestination): Promise<void> => {
    const databaseId = dumpChoice[dest.id]
    if (!databaseId) return
    setBusy(dest.id)
    const r = await window.shellpilot?.backup.dumpDatabase?.(dest.id, databaseId)
    setBusy(null)
    setDumpResult((p) => ({
      ...p,
      [dest.id]: r?.ok
        ? `${r.name} written and read back (${r.bytes} bytes).`
        : `Nothing was written: ${r?.error ?? 'the dump could not be taken.'}`
    }))
  }

  const cancelStaged = (): void => {
    if (staged) void window.shellpilot?.backup.discardStaged?.(staged.path)
    setStaged(null)
  }

  return (
    <div>
      <h3 className="backup-h">Backup destinations</h3>
      <p className="s-desc" style={{ marginBottom: 10 }}>
        Somewhere for a backup to go that is not this machine, written on a schedule and checked
        after every write. Each generation is read back off the destination and decrypted before
        the run is called a success, and older generations are only deleted once the new one has
        passed both.
      </p>

      <div className="backup-banner warn" style={{ marginBottom: 12 }}>
        <ShieldAlert size={16} />
        <div>
          <div className="s-title">A backup is your whole vault, wherever you send it</div>
          <div className="s-desc">
            Every file written here contains your stored credentials, your vault and your trusted
            host keys, encrypted under one passphrase. Choosing a destination is choosing somewhere
            for those to live.
          </div>
        </div>
      </div>

      {file?.corrupt && (
        <div className="backup-banner warn" style={{ marginBottom: 12 }}>
          <AlertTriangle size={16} />
          <div>
            <div className="s-title">Your destinations could not be read</div>
            <div className="s-desc">
              {file.corrupt} Saving a destination from here moves the unreadable file aside rather
              than writing over it, so what was in it stays recoverable by hand.
            </div>
          </div>
        </div>
      )}

      {file === null && !editing && (
        // `destinations` is `file?.destinations ?? []`, so before the read it
        // is empty for the same reason it is empty when there are none. Saying
        // "no destinations yet" then is a claim about where the backups are
        // going, made before anyone looked.
        <p className="s-desc state-unknown" style={{ marginBottom: 10 }}>
          Reading your backup destinations…
        </p>
      )}

      {file !== null && destinations.length === 0 && !editing && (
        <p className="s-desc" style={{ marginBottom: 10 }}>
          No destinations yet. Backups still work through the file you download above.
        </p>
      )}

      {destinations.map((dest) => {
        const report = file?.lastReport[dest.id]
        const status = outcome(report)
        const problem = destinationProblem(dest)
        const password = runPw[dest.id] ?? ''
        return (
          <div key={dest.id} className="backup-banner ok" style={{ marginBottom: 10, alignItems: 'flex-start' }}>
            {status ? (
              status.ok ? (
                <CheckCircle2 size={16} />
              ) : (
                <AlertTriangle size={16} />
              )
            ) : (
              <CloudUpload size={16} />
            )}
            <div style={{ flex: 1, minWidth: 0 }}>
              <div className="s-title">
                {dest.name || '(unnamed)'} · {BACKUP_DESTINATION_LABEL[dest.kind]}
              </div>
              <div className="s-desc">
                {dest.kind === 'local' && dest.directory}
                {dest.kind === 'sftp' &&
                  `${servers.find((s) => s.id === dest.serverId)?.name ?? 'a server that no longer exists'}:${dest.directory}`}
                {dest.kind === 's3' && `${dest.bucket}/${dest.prefix} at ${dest.endpoint}`}
              </div>
              <div className="s-desc">
                {dest.everyHours > 0 ? `Every ${dest.everyHours}h` : 'Manual only'} ·{' '}
                {dest.keep > 0 ? `keeps ${dest.keep}` : 'keeps everything'} ·{' '}
                {dest.restoreTest ? 'test-restores each write' : 'no restore test'} · last attempt{' '}
                {when(file?.lastRunAt[dest.id])}
              </div>
              {problem && (
                <div className="s-desc" style={{ color: 'var(--danger)' }}>
                  {problem}
                </div>
              )}
              {status && (
                <div
                  className="s-desc"
                  style={{ color: status.ok ? undefined : 'var(--danger)', marginTop: 4 }}
                >
                  {status.text}
                </div>
              )}
              <div className="row" style={{ gap: 8, marginTop: 8 }}>
                <input
                  className="input grow"
                  type="password"
                  placeholder={`Backup passphrase (min ${MIN_PASSPHRASE})`}
                  value={password}
                  onChange={(e) => setRunPw((p) => ({ ...p, [dest.id]: e.target.value }))}
                />
                <button
                  className="btn sm"
                  disabled={password.length < MIN_PASSPHRASE || busy !== null || problem !== null}
                  title={
                    problem ??
                    (password.length < MIN_PASSPHRASE
                      ? 'Type the passphrase to encrypt this backup with'
                      : 'Write a backup here now and verify it')
                  }
                  onClick={() => void runNow(dest)}
                >
                  {busy === dest.id ? <Loader2 size={13} className="spin" /> : <CloudUpload size={13} />}
                  Back up now
                </button>
                <button className="btn sm" disabled={busy !== null} onClick={() => void browse(dest)}>
                  <RotateCcw size={13} /> Restore from here
                </button>
                <button className="btn sm" onClick={() => setEditing(dest)}>
                  Edit
                </button>
                <button
                  className="btn sm danger"
                  title="Removes this destination from ShellPilot. The backups already at it are left alone."
                  onClick={() => void persist(destinations.filter((d) => d.id !== dest.id))}
                >
                  <Trash2 size={13} />
                </button>
              </div>

              {databases.length > 0 && (
                <div style={{ marginTop: 8 }}>
                  <div className="row" style={{ gap: 8 }}>
                    <select
                      className="input"
                      value={dumpChoice[dest.id] ?? ''}
                      onChange={(e) => setDumpChoice((p) => ({ ...p, [dest.id]: e.target.value }))}
                    >
                      <option value="">Dump a database here…</option>
                      {databases.map((d) => (
                        <option key={d.id} value={d.id}>
                          {d.name} ({d.engine})
                        </option>
                      ))}
                    </select>
                    <button
                      className="btn sm"
                      disabled={!dumpChoice[dest.id] || busy !== null}
                      onClick={() => void dump(dest)}
                    >
                      <Database size={13} /> Dump now
                    </button>
                  </div>
                  {/* Said at the button, not in documentation: a dump is not a
                      ShellPilot bundle and nothing encrypts it. Somebody who
                      assumed otherwise has just put a database in a bucket in
                      the clear. */}
                  <div className="s-desc">
                    A dump is plain SQL, written alongside the backups and encrypted by nothing.
                    Retention does not touch it, and a restore cannot read it — it is for the
                    database, not for this app.
                  </div>
                  {dumpResult[dest.id] && (
                    <div className="s-desc" style={{ marginTop: 4 }}>{dumpResult[dest.id]}</div>
                  )}
                </div>
              )}

              {browsing === dest.id && (
                <div style={{ marginTop: 10 }}>
                  {browseError && (
                    <div className="vault-error">{browseError}</div>
                  )}
                  {!browseError && generations.length === 0 && (
                    <div className="s-desc">No ShellPilot backups at this destination yet.</div>
                  )}
                  {generations.map((g) => (
                    <div key={g.name} className="row" style={{ gap: 8, marginTop: 4 }}>
                      <span className="grow s-desc">
                        {g.name} · {new Date(g.modified).toLocaleString()} · {g.size} bytes
                      </span>
                      <button
                        className="btn sm"
                        disabled={!password || busy !== null}
                        title={
                          password
                            ? 'Download it and show what is inside before anything is replaced'
                            : 'Type the passphrase used for that backup first'
                        }
                        onClick={() => void inspect(dest, g.name)}
                      >
                        Open
                      </button>
                    </div>
                  ))}
                  {staged && (
                    <div className="backup-banner warn" style={{ marginTop: 10 }}>
                      <AlertTriangle size={16} />
                      <div style={{ flex: 1 }}>
                        <div className="s-title">Replace current data?</div>
                        <div className="s-desc">
                          {staged.name} · created {new Date(staged.summary.createdAt).toLocaleString()} ·{' '}
                          {staged.summary.workspaces} workspaces · {staged.summary.servers} servers ·{' '}
                          {staged.summary.databases} databases · {staged.summary.secrets} credentials
                          {staged.summary.hasVault ? ' · vault included' : ''}
                        </div>
                      </div>
                      <button className="btn sm" onClick={cancelStaged}>
                        Cancel
                      </button>
                      <button className="btn sm danger" disabled={busy !== null} onClick={() => void restore()}>
                        Restore and restart
                      </button>
                    </div>
                  )}
                </div>
              )}
            </div>
          </div>
        )
      })}

      {editing ? (
        <DestinationEditor
          value={editing}
          servers={servers.map((s) => ({ id: s.id, name: s.name }))}
          vaultUnlocked={vaultUnlocked}
          vaultEntries={vaultEntries.map((e) => ({ id: e.id, name: e.name }))}
          onCancel={() => setEditing(null)}
          onSave={(next) => {
            const others = destinations.filter((d) => d.id !== next.id)
            void persist([...others, next])
            setEditing(null)
          }}
        />
      ) : (
        <div className="row" style={{ gap: 8 }}>
          {BACKUP_DESTINATION_KINDS.map((kind) => (
            <button key={kind} className="btn sm" onClick={() => setEditing(blank(kind))}>
              <Plus size={13} /> {BACKUP_DESTINATION_LABEL[kind]}
            </button>
          ))}
        </div>
      )}
    </div>
  )
}

interface EditorProps {
  value: BackupDestination
  servers: { id: string; name: string }[]
  vaultUnlocked: boolean
  vaultEntries: { id: string; name: string }[]
  onCancel: () => void
  onSave: (dest: BackupDestination) => void
}

function DestinationEditor(props: EditorProps): React.JSX.Element {
  const [dest, setDest] = useState<BackupDestination>(props.value)
  const patch = (p: Partial<BackupDestination>): void =>
    setDest((d) => ({ ...d, ...p }) as BackupDestination)
  const problem = destinationProblem(dest)

  return (
    <div className="backup-banner warn" style={{ alignItems: 'flex-start', marginTop: 10 }}>
      <ShieldAlert size={16} />
      <div style={{ flex: 1 }}>
        <div className="s-title">{BACKUP_DESTINATION_LABEL[dest.kind]}</div>

        {/* The security statement sits here, above the fields, because this is
            the moment the decision is made. A footnote further down the page
            is a footnote nobody read before they typed a bucket name. */}
        <div className="s-desc" style={{ marginBottom: 8 }}>
          {BACKUP_DESTINATION_EXPOSURE[dest.kind]}
        </div>

        <div className="row" style={{ gap: 8, marginBottom: 6 }}>
          <input
            className="input grow"
            placeholder="Name this destination"
            value={dest.name}
            onChange={(e) => patch({ name: e.target.value })}
          />
        </div>

        {dest.kind === 'local' && (
          <div className="row" style={{ gap: 8, marginBottom: 6 }}>
            <input
              className="input grow"
              placeholder="Folder to write backups into"
              value={dest.directory}
              onChange={(e) => patch({ directory: e.target.value })}
            />
            <button
              className="btn sm"
              onClick={() => {
                void window.shellpilot?.backup.chooseDirectory?.().then((dir) => {
                  if (dir) patch({ directory: dir })
                })
              }}
            >
              <FolderOpen size={13} /> Choose…
            </button>
          </div>
        )}

        {dest.kind === 'sftp' && (
          <div className="row" style={{ gap: 8, marginBottom: 6 }}>
            <select
              className="input"
              value={dest.serverId}
              onChange={(e) => patch({ serverId: e.target.value })}
            >
              <option value="">Choose a server…</option>
              {props.servers.map((s) => (
                <option key={s.id} value={s.id}>
                  {s.name}
                </option>
              ))}
            </select>
            <input
              className="input grow"
              placeholder="Remote directory, e.g. /srv/shellpilot-backups"
              value={dest.directory}
              onChange={(e) => patch({ directory: e.target.value })}
            />
          </div>
        )}

        {dest.kind === 'sftp' && (
          <div className="s-desc" style={{ marginBottom: 6 }}>
            Uploads over that server&apos;s existing credentials — this destination stores none of
            its own, and an unattended run refuses an unknown host key rather than asking.
          </div>
        )}

        {dest.kind === 's3' && (
          <>
            <div className="row" style={{ gap: 8, marginBottom: 6 }}>
              <input
                className="input grow"
                placeholder="Endpoint, e.g. https://s3.eu-west-1.amazonaws.com"
                value={dest.endpoint}
                onChange={(e) => patch({ endpoint: e.target.value })}
              />
              <input
                className="input"
                style={{ maxWidth: 140 }}
                placeholder="Region"
                value={dest.region}
                onChange={(e) => patch({ region: e.target.value })}
              />
            </div>
            <div className="row" style={{ gap: 8, marginBottom: 6 }}>
              <input
                className="input grow"
                placeholder="Bucket"
                value={dest.bucket}
                onChange={(e) => patch({ bucket: e.target.value })}
              />
              <input
                className="input grow"
                placeholder="Key prefix (optional)"
                value={dest.prefix}
                onChange={(e) => patch({ prefix: e.target.value })}
              />
              <label className="s-desc" style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
                <input
                  type="checkbox"
                  checked={dest.pathStyle}
                  onChange={(e) => patch({ pathStyle: e.target.checked })}
                />
                Path-style
              </label>
            </div>
            <div className="row" style={{ gap: 8, marginBottom: 6 }}>
              <select
                className="input grow"
                value={dest.vaultEntryId}
                disabled={!props.vaultUnlocked}
                onChange={(e) => patch({ vaultEntryId: e.target.value })}
              >
                <option value="">Vault entry holding the access key…</option>
                {props.vaultEntries.map((e) => (
                  <option key={e.id} value={e.id}>
                    {e.name}
                  </option>
                ))}
              </select>
            </div>
            <div className="s-desc" style={{ marginBottom: 6 }}>
              The access key id goes in that entry&apos;s username and the secret key in its secret.
              It has to be a vault entry: application settings travel inside every backup written
              here, so a secret key kept there would be sitting in the bucket it unlocks.
              {!props.vaultUnlocked && ' Unlock the vault to choose one.'}
            </div>
          </>
        )}

        <div className="row" style={{ gap: 8, marginBottom: 6 }}>
          <label className="s-desc" style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
            Run every
            <input
              className="input"
              style={{ width: 70 }}
              type="number"
              min={0}
              value={dest.everyHours}
              onChange={(e) => patch({ everyHours: Math.max(0, Number(e.target.value) || 0) })}
            />
            hours (0 = manual)
          </label>
          <label className="s-desc" style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
            Keep
            <input
              className="input"
              style={{ width: 70 }}
              type="number"
              min={0}
              value={dest.keep}
              onChange={(e) => patch({ keep: Math.max(0, Number(e.target.value) || 0) })}
            />
            generations (0 = all)
          </label>
          <label className="s-desc" style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
            <input
              type="checkbox"
              checked={dest.restoreTest}
              onChange={(e) => patch({ restoreTest: e.target.checked })}
            />
            Test-restore every write
          </label>
        </div>

        {dest.everyHours > 0 && (
          <>
            <div className="row" style={{ gap: 8, marginBottom: 6 }}>
              <select
                className="input grow"
                value={dest.passphraseVaultEntryId ?? ''}
                disabled={!props.vaultUnlocked}
                onChange={(e) => patch({ passphraseVaultEntryId: e.target.value || undefined })}
              >
                <option value="">Vault entry holding the backup passphrase…</option>
                {props.vaultEntries.map((e) => (
                  <option key={e.id} value={e.id}>
                    {e.name}
                  </option>
                ))}
              </select>
            </div>
            <div className="s-desc" style={{ marginBottom: 6 }}>
              Nobody is present at 3am to type a passphrase, so a scheduled run reads one from the
              vault — which means scheduled runs only happen while the vault is unlocked. A run
              that is skipped for that reason says so rather than quietly not happening.
            </div>
          </>
        )}

        {problem && (
          <div className="s-desc" style={{ color: 'var(--danger)', marginBottom: 6 }}>
            {problem}
          </div>
        )}
      </div>
      <button className="btn sm" onClick={props.onCancel}>
        Cancel
      </button>
      <button className="btn sm primary" disabled={problem !== null} onClick={() => props.onSave(dest)}>
        Save destination
      </button>
    </div>
  )
}
