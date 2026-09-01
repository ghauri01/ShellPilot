import { useCallback, useEffect, useRef, useState } from 'react'
import {
  ExternalLink,
  Folder,
  File,
  Upload,
  Download,
  FolderPlus,
  ChevronRight,
  Home,
  RefreshCw,
  Search,
  Edit3,
  Trash2,
  Link2,
  Loader2,
  AlertTriangle
} from 'lucide-react'
import { ContextMenu, MenuEntry } from '../connections/ContextMenu'
import { Modal } from '../common/Modal'
import { toast } from '../../store/toast'
import { useApp } from '../../store/app'
import { bytes, clsx } from '../../lib/format'
import { sshHopsFor } from '../../lib/ssh'
import { withVaultUnlock } from '../../lib/withVaultUnlock'
import { classifyConnectionError, errorText } from '../../lib/connectionError'
import { openSettings } from '../../store/nav'
import type { Server } from '../../types'
import type { SftpEntry, SftpProgress, SftpResult, SshAuth } from '../../../../shared/ssh'
import { bridgeOn } from '../../lib/bridge'

const asAuth = (a: string): SshAuth => (a === 'password' || a === 'agent' ? a : 'key')

function join(dir: string, name: string): string {
  return dir === '/' ? `/${name}` : `${dir}/${name}`
}

// Local paths come from the OS, so they may be Windows-style.
function baseName(p: string): string {
  return p.split(/[\\/]/).pop() ?? p
}

function mtimeLabel(ms: number): string {
  if (!ms) return '—'
  const d = new Date(ms)
  return `${d.toLocaleString('en-US', { month: 'short' })} ${String(d.getDate()).padStart(2, '0')} ${d
    .toTimeString()
    .slice(0, 5)}`
}

/** Something the user can click about a failure. */
interface Fix {
  label: string
  run: () => void
}

interface SftpFailure {
  message: string
  detail?: string
  fix?: Fix
  retry: Fix
}

const MISSING = /no such file|ENOENT/i

// A file operation that failed, said as a sentence.
//
// "Rename failed" tells the user only that they already know. Which file, in
// which directory, and whether the server said "you may not" or "that is not
// there" is the part that decides what they do next — so that is what this
// says. An error nothing recognises keeps the server's own words: an unhelpful
// string still beats discarding the only evidence there is.
function fileFailure(verb: string, what: string, dir: string, error: string | undefined): string {
  if (classifyConnectionError(error) === 'permission') return `${dir} does not allow you to ${verb} ${what}.`
  if (error && MISSING.test(error)) return `${what} is no longer in ${dir}.`
  return error ? `Could not ${verb} ${what} — ${error}` : `Could not ${verb} ${what}.`
}

// Why the SSH chain behind the Files tab would not come up, and the one screen
// that holds the setting to change.
function connectFailure(
  server: Server,
  error: string | undefined,
  editServer: (id: string) => void,
  retry: Fix
): SftpFailure {
  const fixServer: Fix = { label: `Edit ${server.name}`, run: () => editServer(server.id) }
  const of = (message: string, fix?: Fix): SftpFailure => ({ message, detail: error, fix, retry })

  switch (classifyConnectionError(error)) {
    case 'host-key':
      return of(`${server.name} presented a different host key, so the connection was refused.`, {
        label: 'Review saved keys',
        run: () => openSettings('security')
      })
    case 'key-missing':
      return of(`${server.name}'s private key file is not where the connection says it is.`, fixServer)
    case 'passphrase':
      return of(`${server.name}'s private key needs a passphrase.`, fixServer)
    case 'auth':
      return of(`${server.name} rejected the saved credential.`, fixServer)
    case 'refused':
      return of(`Nothing is listening on ${server.host}:${server.port}.`, fixServer)
    case 'unreachable':
      return of(`${server.host} did not answer in time.`, fixServer)
    default:
      return of(`Could not open files on ${server.name}.`)
  }
}

// ---- Real SFTP -------------------------------------------------------------
function RealSftp({ server, tabId }: { server: Server; tabId?: string }): React.JSX.Element {
  const key = server.id
  const [path, setPath] = useState('/')
  const [entries, setEntries] = useState<SftpEntry[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<SftpFailure | null>(null)
  const [query, setQuery] = useState('')
  const [ctx, setCtx] = useState<{ x: number; y: number; entry: SftpEntry } | null>(null)
  const [creating, setCreating] = useState(false)
  const [newName, setNewName] = useState('')
  const [renaming, setRenaming] = useState<string | null>(null)
  const [editor, setEditor] = useState<{ path: string; content: string } | null>(null)
  const [progress, setProgress] = useState<SftpProgress | null>(null)
  const [dropping, setDropping] = useState(false)
  const editorCommand = useApp((s) => s.settings.externalEditorCommand)
  const preferExternal = useApp((s) => s.settings.openFilesExternally)
  const openServerEditor = useApp((s) => s.openServerEditor)

  // Remote writes triggered by an external save happen in the main process, so
  // the result is reported back here.
  useEffect(() => {
    return bridgeOn('sftp.onExternalSaved', window.shellpilot?.sftp?.onExternalSaved, (r) => {
      const name = r.remotePath.split('/').pop()
      if (r.ok) toast(`${name} saved to the server`, 'ok')
      // No button: the file is open in the user's own editor, and saving it
      // there again is the retry — one that exists outside this window.
      else if (r.error) toast(`${name} was saved locally but not uploaded — ${r.error}`, 'error')
      else toast(`${name} was saved locally, but uploading it to the server failed.`, 'error')
    })
  }, [])
  const [linked, setLinked] = useState(true)
  const connectedRef = useRef(false)

  // Sync with the terminal: follow its cwd (via OSC 7) and push `cd` when the
  // user navigates here.
  //
  // Both live under the **active pane's** id, not the tab's: a tab holds up to
  // four terminals and "the terminal" this view follows is whichever one has
  // focus. Reading `tabSession[tabId]` — which is what this did while a tab had
  // exactly one session — now matches nothing at all, so the link silently
  // stops working rather than following the wrong pane.
  //
  // And only a pane on *this* server: a tab can hold a local shell beside a
  // remote one, and a local pane's OSC-7 cwd is a path on this machine. Left
  // unfiltered, focusing it would send the browser off to list `/Users/…` on
  // the server and push a `cd` for it down the wrong session.
  const paneId = useApp((s) => {
    const tp = tabId ? s.panes[tabId] : undefined
    const pane = tp?.panes.find((p) => p.id === tp.activePaneId)
    return pane?.target.kind === 'ssh' && pane.target.serverId === server.id ? pane.id : undefined
  })
  const session = useApp((s) => (paneId ? s.tabSession[paneId] : undefined))
  const termCwd = useApp((s) => (paneId ? s.tabCwd[paneId] : undefined))
  const setTabCwd = useApp((s) => s.setTabCwd)

  const cfg = useCallback(
    () => ({
      sessionId: `sftp-${server.id}`,
      serverId: server.id,
      host: server.host,
      port: server.port,
      username: server.username,
      auth: asAuth(server.auth),
      cols: 80,
      rows: 24,
      hops: sshHopsFor(server)
    }),
    [server]
  )

  // Any call over this channel can need a credential the vault holds, and the
  // handler rejects rather than returning a result when it is locked. Routing
  // through withVaultUnlock turns that into an unlock dialog and a call that
  // finishes, instead of a promise nobody catches and a spinner that never stops.
  const unlocked = useCallback(
    <T,>(run: () => Promise<T>): Promise<T> => withVaultUnlock(`Opening files on ${server.name}`, run),
    [server.name]
  )

  const list = useCallback(
    async (p: string): Promise<boolean> => {
      setLoading(true)
      setError(null)
      let res: SftpResult<SftpEntry[]> | undefined
      try {
        res = await unlocked(async () => window.shellpilot?.sftp.list(key, p))
      } catch (err) {
        res = { ok: false, error: errorText(err) }
      }
      if (res?.ok && res.data) {
        setEntries(res.data)
        setPath(p)
        setLoading(false)
        return true
      }
      const detail = res?.error
      const message =
        classifyConnectionError(detail) === 'permission'
          ? `You do not have permission to open ${p}.`
          : detail && MISSING.test(detail)
            ? `${p} is not there any more.`
            : `Could not open ${p}.`
      // A failed step into a directory leaves the last good one loaded, so the
      // way out is back to it rather than a retry that fails the same way.
      setError({
        message,
        detail,
        retry:
          p === path
            ? { label: 'Try again', run: () => void list(p) }
            : { label: `Back to ${path}`, run: () => void list(path) }
      })
      setLoading(false)
      return false
    },
    [key, path, unlocked]
  )

  // Navigate here AND mirror the change to the terminal (cd) when linked.
  const navigate = useCallback(
    async (p: string): Promise<void> => {
      const ok = await list(p)
      if (!ok) return
      if (paneId) setTabCwd(paneId, p)
      if (linked && session) {
        const q = p.replace(/'/g, `'\\''`)
        window.shellpilot?.ssh.write(session, `cd '${q}'\n`)
      }
    },
    [list, paneId, setTabCwd, linked, session]
  )

  // Opening the channel, and the way back in after it failed. Retrying a failed
  // connect has to redial — listing a key that never connected only produces a
  // second, less recognisable failure.
  const connect = useCallback(
    async (alive: () => boolean): Promise<void> => {
      setLoading(true)
      setError(null)
      let res: SftpResult<{ home: string }> | undefined
      try {
        res = await unlocked(async () => window.shellpilot?.sftp.connect(key, cfg()))
      } catch (err) {
        res = { ok: false, error: errorText(err) }
      }
      if (!alive()) return
      if (res?.ok) {
        connectedRef.current = true
        // Start where the terminal is, if known; otherwise the SFTP home.
        await list(termCwd || res.data?.home || '/')
        return
      }
      setError(
        connectFailure(server, res?.error, openServerEditor, {
          label: 'Try again',
          run: () => void connect(() => true)
        })
      )
      setLoading(false)
    },
    // list and termCwd deliberately excluded: this reconnects a channel, and
    // rebuilding it whenever the current directory changes would redial the
    // whole jump chain on every navigation.
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [key, cfg, unlocked, server, openServerEditor]
  )

  useEffect(() => {
    let alive = true
    void connect(() => alive)
    return () => {
      // Keep the SFTP connection cached in the main process so re-opening the
      // Files tab is instant instead of re-establishing the SSH/jump chain.
      alive = false
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [key])

  // Follow the terminal's cwd when it changes (does not push cd back).
  useEffect(() => {
    if (linked && termCwd && connectedRef.current && termCwd !== path && !loading) {
      void list(termCwd)
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [termCwd, linked])

  const open = (e: SftpEntry): void => {
    if (e.dir) void navigate(join(path, e.name))
    else if (preferExternal) void openExternally(e)
    else void openFile(e)
  }

  // Opens in the user's own editor (VS Code by default) and writes the file
  // back on every save, instead of the built-in inline editor.
  const openExternally = async (e: SftpEntry): Promise<void> => {
    const remote = join(path, e.name)
    const r = await window.shellpilot?.sftp.editExternal(key, remote, editorCommand)
    if (r?.ok) toast(`Opened ${e.name} — saves upload automatically`, 'ok')
    else
      toast(fileFailure('open', e.name, path, r?.error), 'error', {
        label: 'Open here instead',
        run: () => void openFile(e)
      })
  }

  const openFile = async (e: SftpEntry): Promise<void> => {
    if (e.size > 2_000_000) {
      toast(`${e.name} is ${bytes(e.size)} — too large for the editor in this window.`, 'error', {
        label: editorCommand ? `Open in ${editorCommand}` : 'Open in your editor',
        run: () => void openExternally(e)
      })
      return
    }
    const res = await window.shellpilot?.sftp.read(key, join(path, e.name))
    if (res?.ok) setEditor({ path: join(path, e.name), content: res.data ?? '' })
    // No button: the same read through the external editor goes down the same
    // channel and is refused for the same reason.
    else toast(fileFailure('read', e.name, path, res?.error), 'error')
  }

  const saveFile = async (content: string): Promise<void> => {
    if (!editor) return
    const name = editor.path.split('/').pop() ?? editor.path
    const res = await window.shellpilot?.sftp.write(key, editor.path, content)
    if (res?.ok) {
      toast(`${name} saved`, 'ok')
      setEditor(null)
    } else
      // The editor stays open, so the retry writes exactly what is still on
      // screen rather than whatever the file happens to hold now.
      toast(fileFailure('save', name, path, res?.error), 'error', {
        label: 'Try again',
        run: () => void saveFile(content)
      })
  }

  const createFolder = async (): Promise<void> => {
    if (!newName.trim()) return setCreating(false)
    const res = await window.shellpilot?.sftp.mkdir(key, join(path, newName.trim()))
    if (res?.ok) {
      toast(`Created ${newName.trim()}`)
      setNewName('')
      setCreating(false)
      void list(path)
      // The name field stays open behind this, so there is nothing a button
      // would do that the still-focused input does not already offer.
    } else toast(fileFailure('create', newName.trim(), path, res?.error), 'error')
  }

  const doRename = async (from: SftpEntry, to: string): Promise<void> => {
    setRenaming(null)
    if (!to.trim() || to === from.name) return
    const res = await window.shellpilot?.sftp.rename(key, join(path, from.name), join(path, to.trim()))
    if (res?.ok) void list(path)
    else
      toast(fileFailure('rename', from.name, path, res?.error), 'error', {
        label: 'Rename again',
        run: () => setRenaming(from.name)
      })
  }

  const remove = async (e: SftpEntry): Promise<void> => {
    if (!window.confirm(`Delete ${e.name}? This cannot be undone.`)) return
    const res = await window.shellpilot?.sftp.remove(key, join(path, e.name), e.dir)
    if (res?.ok) {
      toast(`Deleted ${e.name}`)
      void list(path)
      // Actionless on purpose: the same delete against the same permissions
      // fails the same way, and a button that repeats it is theatre.
    } else toast(fileFailure('delete', e.name, path, res?.error), 'error')
  }

  // Transfer progress is reported from the main process while an upload runs.
  useEffect(() => {
    return bridgeOn('sftp.onProgress', window.shellpilot?.sftp?.onProgress, (p) => {
      if (p.key === key) setProgress(p)
    })
  }, [key])

  const upload = async (locals: string[]): Promise<void> => {
    const paths = locals.filter(Boolean)
    // One transfer at a time: they share the single cached SFTP channel.
    if (!paths.length || progress) return
    const clashes = paths.map(baseName).filter((n) => entries.some((x) => x.name === n))
    if (clashes.length && !window.confirm(`Overwrite on the server?\n\n${clashes.join('\n')}`)) return
    // Shown immediately: the first step event only arrives once bytes move.
    setProgress({ key, name: baseName(paths[0]), transferred: 0, total: 0, index: 1, count: paths.length })
    const res = await window.shellpilot?.sftp.upload(key, paths, path)
    setProgress(null)
    const done = res?.data?.uploaded.length ?? 0
    const failed = res?.data?.failed ?? []
    if (done) toast(`Uploaded ${done} file${done > 1 ? 's' : ''} to ${path}`, 'ok')
    for (const f of failed) {
      // The summary reports basenames; the local file that produced one is
      // still in `paths`, which is what makes a per-file retry possible.
      const local = paths.find((x) => baseName(x) === f.name)
      toast(
        fileFailure('upload', f.name, path, f.error),
        'error',
        local ? { label: 'Try again', run: () => void upload([local]) } : undefined
      )
    }
    if (!done && !failed.length)
      toast(res?.error ? `Nothing was uploaded to ${path} — ${res.error}` : `Nothing was uploaded to ${path}.`, 'error', {
        label: 'Choose files',
        run: () => void pickAndUpload()
      })
    void list(path)
  }

  const pickAndUpload = async (): Promise<void> => {
    const picked = await window.shellpilot?.dialog.openUpload()
    if (picked?.length) await upload(picked)
  }

  const onDrop = (ev: React.DragEvent): void => {
    ev.preventDefault()
    setDropping(false)
    const paths = Array.from(ev.dataTransfer.files)
      .map((f) => window.shellpilot?.sftp.pathFor(f))
      .filter((p): p is string => !!p)
    if (paths.length) void upload(paths)
  }

  const menu = (e: SftpEntry): MenuEntry[] => [
    ...(!e.dir
      ? [
          { label: 'Open in editor (inline)', icon: <Edit3 size={14} />, onClick: () => void openFile(e) },
          {
            label: editorCommand ? `Open in ${editorCommand}` : 'Open in default app',
            icon: <ExternalLink size={14} />,
            onClick: () => void openExternally(e)
          }
        ]
      : []),
    { label: 'Rename', icon: <Edit3 size={14} />, onClick: () => setRenaming(e.name) },
    {
      label: 'Download',
      icon: <Download size={14} />,
      // Saving to a chosen folder is not built yet. Opening the file in an
      // editor does fetch a local copy, which is what most people want when
      // they reach for Download — so that is offered rather than a dead end.
      onClick: () =>
        toast('Saving to a folder is not built yet.', 'info', {
          label: editorCommand ? `Open in ${editorCommand}` : 'Open in your editor',
          run: () => void openExternally(e)
        })
    },
    { separator: true, label: '' },
    { label: 'Delete', icon: <Trash2 size={14} />, danger: true, onClick: () => void remove(e) }
  ]

  const parts = path === '/' ? [] : path.split('/').filter(Boolean)
  const visible = entries.filter((e) => e.name.toLowerCase().includes(query.toLowerCase()))

  return (
    <div
      className="content"
      style={{
        paddingTop: 0,
        outline: dropping ? '2px dashed var(--accent)' : undefined,
        outlineOffset: -4
      }}
      onDragOver={(ev) => {
        // Without this the window would try to navigate to the dropped file.
        ev.preventDefault()
        setDropping(true)
      }}
      onDragLeave={(ev) => {
        if (!ev.currentTarget.contains(ev.relatedTarget as Node | null)) setDropping(false)
      }}
      onDrop={onDrop}
    >
      <div className="viewbar" style={{ margin: '0 -20px 16px', paddingLeft: 20, paddingRight: 20 }}>
        <button className="icon-btn" onClick={() => void navigate('/')} title="Root">
          <Home size={15} />
        </button>
        <div className="row" style={{ gap: 2, flex: 1, overflow: 'hidden' }}>
          {parts.map((p, i) => (
            <span key={i} className="row" style={{ gap: 2 }}>
              <ChevronRight size={13} className="faint" />
              <button className="btn ghost sm" onClick={() => void navigate('/' + parts.slice(0, i + 1).join('/'))}>
                {p}
              </button>
            </span>
          ))}
        </div>
        <button
          className={clsx('icon-btn', linked && 'active')}
          title={linked ? 'Following terminal directory — click to unlink' : 'Not following terminal — click to link'}
          onClick={() => setLinked((v) => !v)}
        >
          <Link2 size={15} />
        </button>
        <button className="icon-btn" title="Refresh" onClick={() => void list(path)}>
          <RefreshCw size={14} />
        </button>
        <button className="btn sm" onClick={() => setCreating(true)}>
          <FolderPlus size={13} /> New folder
        </button>
        <button
          className="btn sm"
          disabled={!!progress}
          title="Upload files — you can also drag them onto this list"
          onClick={() => void pickAndUpload()}
        >
          <Upload size={13} /> Upload
        </button>
      </div>

      <div className="row" style={{ marginBottom: 12, gap: 6, position: 'relative' }}>
        <Search size={14} className="faint" style={{ position: 'absolute', left: 10 }} />
        <input
          className="input grow"
          style={{ paddingLeft: 30 }}
          placeholder="Filter files…"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
        />
      </div>

      {progress && (
        <div className="row" style={{ marginBottom: 12, gap: 10 }}>
          <Upload size={14} className="faint" />
          <span className="faint" style={{ fontSize: 12, whiteSpace: 'nowrap' }}>
            {progress.name}
            {progress.count > 1 ? ` · ${progress.index}/${progress.count}` : ''}
            {progress.total ? ` · ${bytes(progress.transferred)} / ${bytes(progress.total)}` : ''}
          </span>
          <div className="bar" style={{ flex: 1 }}>
            <span
              style={{
                width: `${progress.total ? Math.round((progress.transferred / progress.total) * 100) : 0}%`
              }}
            />
          </div>
        </div>
      )}

      {loading && (
        <div className="empty" style={{ height: 200 }}>
          <Loader2 size={22} className="spin" />
          <p>Loading {path}…</p>
        </div>
      )}

      {error && !loading && (
        <div className="empty" style={{ height: 220 }}>
          <div className="empty-icon" style={{ color: 'var(--danger)' }}>
            <AlertTriangle size={22} />
          </div>
          <h3>{error.message}</h3>
          {error.detail && error.detail !== error.message && (
            <p className="mono selectable" style={{ fontSize: 11 }}>
              {error.detail}
            </p>
          )}
          <div className="row" style={{ gap: 8 }}>
            {error.fix && (
              <button className="btn primary" onClick={error.fix.run}>
                {error.fix.label}
              </button>
            )}
            <button className="btn" onClick={error.retry.run}>
              <RefreshCw size={14} /> {error.retry.label}
            </button>
          </div>
        </div>
      )}

      {!loading && !error && (
        <table className="table">
          <thead>
            <tr>
              <th style={{ width: '50%' }}>Name</th>
              <th>Size</th>
              <th>Modified</th>
              <th>Permissions</th>
            </tr>
          </thead>
          <tbody>
            {creating && (
              <tr>
                <td colSpan={4}>
                  <div className="row" style={{ gap: 8 }}>
                    <FolderPlus size={15} style={{ color: 'var(--warn)' }} />
                    <input
                      className="input"
                      autoFocus
                      style={{ height: 28 }}
                      placeholder="Folder name"
                      value={newName}
                      onChange={(e) => setNewName(e.target.value)}
                      onKeyDown={(e) => {
                        if (e.key === 'Enter') void createFolder()
                        if (e.key === 'Escape') setCreating(false)
                      }}
                      onBlur={() => void createFolder()}
                    />
                  </div>
                </td>
              </tr>
            )}
            {visible.map((e) => (
              <tr
                key={e.name}
                style={{ cursor: 'pointer' }}
                onDoubleClick={() => open(e)}
                onContextMenu={(ev) => {
                  ev.preventDefault()
                  setCtx({ x: ev.clientX, y: ev.clientY, entry: e })
                }}
              >
                <td>
                  {renaming === e.name ? (
                    <input
                      className="input"
                      autoFocus
                      style={{ height: 26 }}
                      defaultValue={e.name}
                      onKeyDown={(ev) => {
                        if (ev.key === 'Enter') void doRename(e, (ev.target as HTMLInputElement).value)
                        if (ev.key === 'Escape') setRenaming(null)
                      }}
                      onBlur={(ev) => void doRename(e, ev.target.value)}
                    />
                  ) : (
                    <span className="row" style={{ gap: 8 }} onClick={() => open(e)}>
                      {e.dir ? (
                        <Folder size={15} style={{ color: 'var(--warn)' }} />
                      ) : e.link ? (
                        <Link2 size={15} className="faint" />
                      ) : (
                        <File size={15} className="faint" />
                      )}
                      {e.name}
                    </span>
                  )}
                </td>
                <td className="faint">{e.dir ? '—' : bytes(e.size)}</td>
                <td className="faint">{mtimeLabel(e.mtime)}</td>
                <td className="mono faint">{e.perms}</td>
              </tr>
            ))}
            {visible.length === 0 && (
              <tr>
                <td colSpan={4} className="faint" style={{ padding: 20, textAlign: 'center' }}>
                  Empty directory
                </td>
              </tr>
            )}
          </tbody>
        </table>
      )}

      {ctx && <ContextMenu x={ctx.x} y={ctx.y} entries={menu(ctx.entry)} onClose={() => setCtx(null)} />}

      {editor && (
        <FileEditor
          path={editor.path}
          initial={editor.content}
          onClose={() => setEditor(null)}
          onSave={saveFile}
        />
      )}
    </div>
  )
}

function FileEditor({
  path,
  initial,
  onClose,
  onSave
}: {
  path: string
  initial: string
  onClose: () => void
  onSave: (c: string) => void
}): React.JSX.Element {
  const [content, setContent] = useState(initial)
  const dirty = content !== initial
  return (
    <Modal
      title={path.split('/').pop() ?? 'File'}
      subtitle={path}
      size="lg"
      onClose={onClose}
      footer={
        <>
          <span className="faint mono" style={{ fontSize: 11 }}>
            {content.length} bytes {dirty ? '· modified' : ''}
          </span>
          <span className="spacer" />
          <button className="btn" onClick={onClose}>
            Close
          </button>
          <button className="btn primary" disabled={!dirty} onClick={() => onSave(content)}>
            Save
          </button>
        </>
      }
    >
      <textarea
        className="textarea"
        style={{ minHeight: '52vh', fontSize: 12 }}
        value={content}
        spellCheck={false}
        onChange={(e) => setContent(e.target.value)}
      />
    </Modal>
  )
}

// ---- Demo (simulated) ------------------------------------------------------
const DEMO_TREE: Record<string, { name: string; dir: boolean; size: number; mtime: string; perms: string }[]> = {
  '/': [
    { name: 'etc', dir: true, size: 0, mtime: 'Apr 12', perms: 'drwxr-xr-x' },
    { name: 'home', dir: true, size: 0, mtime: 'Mar 02', perms: 'drwxr-xr-x' },
    { name: 'opt', dir: true, size: 0, mtime: 'Jan 20', perms: 'drwxr-xr-x' },
    { name: 'var', dir: true, size: 0, mtime: 'May 01', perms: 'drwxr-xr-x' }
  ],
  '/opt': [
    { name: 'app', dir: true, size: 0, mtime: 'May 08', perms: 'drwxr-xr-x' },
    { name: 'docker-compose.yml', dir: false, size: 2143, mtime: 'May 08', perms: '-rw-r--r--' },
    { name: '.env', dir: false, size: 512, mtime: 'May 08', perms: '-rw-------' }
  ],
  '/opt/app': [
    { name: 'src', dir: true, size: 0, mtime: 'May 07', perms: 'drwxr-xr-x' },
    { name: 'package.json', dir: false, size: 1820, mtime: 'May 07', perms: '-rw-r--r--' },
    { name: 'nginx.conf', dir: false, size: 3412, mtime: 'Apr 30', perms: '-rw-r--r--' },
    { name: 'server.js', dir: false, size: 9821, mtime: 'May 07', perms: '-rw-r--r--' }
  ]
}
const EDITORS = ['VS Code', 'Cursor', 'Sublime Text', 'Notepad++', 'System Default']

function DemoSftp(): React.JSX.Element {
  const setModal = useApp((s) => s.setModal)
  const [path, setPath] = useState('/opt/app')
  const [query, setQuery] = useState('')
  const [ctx, setCtx] = useState<{ x: number; y: number; name: string; dir: boolean } | null>(null)
  const entries = (DEMO_TREE[path] ?? []).filter((e) => e.name.toLowerCase().includes(query.toLowerCase()))
  const parts = path === '/' ? [] : path.split('/').filter(Boolean)

  // Everything in this pane is a fixture. Saying "(demo)" after the fact
  // explains nothing to someone who never chose a demo — the way out of it is
  // a real server, so that is the button.
  const notReal = (what: string): void =>
    toast(`${what} does nothing here — this is a sample file list, not a real server.`, 'info', {
      label: 'Add a real server',
      run: () => setModal('add-server')
    })

  const open = (e: { name: string; dir: boolean }): void => {
    if (e.dir) {
      const next = path === '/' ? `/${e.name}` : `${path}/${e.name}`
      if (DEMO_TREE[next]) setPath(next)
      else notReal(`${e.name}/`)
    } else notReal(e.name)
  }

  return (
    <div className="content" style={{ paddingTop: 0 }}>
      <div className="viewbar" style={{ margin: '0 -20px 16px', paddingLeft: 20, paddingRight: 20 }}>
        <button className="icon-btn" onClick={() => setPath('/')} title="Root">
          <Home size={15} />
        </button>
        <div className="row" style={{ gap: 2, flex: 1, overflow: 'hidden' }}>
          {parts.map((p, i) => (
            <span key={i} className="row" style={{ gap: 2 }}>
              <ChevronRight size={13} className="faint" />
              <button className="btn ghost sm" onClick={() => setPath('/' + parts.slice(0, i + 1).join('/'))}>
                {p}
              </button>
            </span>
          ))}
        </div>
        <span className="chip warn">demo</span>
        <button className="btn sm">
          <Upload size={13} /> Upload
        </button>
      </div>

      <div className="row" style={{ marginBottom: 12, gap: 6, position: 'relative' }}>
        <Search size={14} className="faint" style={{ position: 'absolute', left: 10 }} />
        <input
          className="input grow"
          style={{ paddingLeft: 30 }}
          placeholder="Filter files…"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
        />
      </div>

      <table className="table">
        <thead>
          <tr>
            <th style={{ width: '50%' }}>Name</th>
            <th>Size</th>
            <th>Modified</th>
            <th>Permissions</th>
          </tr>
        </thead>
        <tbody>
          {entries.map((e) => (
            <tr
              key={e.name}
              style={{ cursor: 'pointer' }}
              onClick={() => open(e)}
              onContextMenu={(ev) => {
                ev.preventDefault()
                setCtx({ x: ev.clientX, y: ev.clientY, name: e.name, dir: e.dir })
              }}
            >
              <td>
                <span className="row" style={{ gap: 8 }}>
                  {e.dir ? <Folder size={15} style={{ color: 'var(--warn)' }} /> : <File size={15} className="faint" />}
                  {e.name}
                </span>
              </td>
              <td className="faint">{e.dir ? '—' : bytes(e.size)}</td>
              <td className="faint">{e.mtime}</td>
              <td className="mono faint">{e.perms}</td>
            </tr>
          ))}
        </tbody>
      </table>

      {ctx && (
        <ContextMenu
          x={ctx.x}
          y={ctx.y}
          onClose={() => setCtx(null)}
          entries={[
            { label: 'Download', icon: <Download size={14} />, onClick: () => notReal('Download') },
            ...(!ctx.dir
              ? EDITORS.map((ed) => ({
                  label: `Open with ${ed}`,
                  icon: <Edit3 size={14} />,
                  onClick: () => notReal(`Open with ${ed}`)
                }))
              : []),
            { separator: true, label: '' },
            { label: 'Delete', icon: <Trash2 size={14} />, danger: true, onClick: () => notReal('Delete') }
          ]}
        />
      )}
    </div>
  )
}

export function SftpView({ server, tabId }: { server: Server; tabId?: string }): React.JSX.Element {
  return server.demo === false ? <RealSftp server={server} tabId={tabId} /> : <DemoSftp />
}
