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
import type { Server } from '../../types'
import type {SftpEntry, SftpProgress, SshAuth} from '../../../../shared/ssh'

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

// ---- Real SFTP -------------------------------------------------------------
function RealSftp({ server, tabId }: { server: Server; tabId?: string }): React.JSX.Element {
  const key = server.id
  const [path, setPath] = useState('/')
  const [entries, setEntries] = useState<SftpEntry[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
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

  // Remote writes triggered by an external save happen in the main process, so
  // the result is reported back here.
  useEffect(() => {
    return window.shellpilot?.sftp.onExternalSaved((r) => {
      const name = r.remotePath.split('/').pop()
      if (r.ok) toast(`${name} saved to the server`, 'ok')
      else toast(`${name}: ${r.error ?? 'upload failed'}`, 'error')
    })
  }, [])
  const [linked, setLinked] = useState(true)
  const connectedRef = useRef(false)

  // Sync with the terminal: follow its cwd (via OSC 7) and push `cd` when the
  // user navigates here.
  const session = useApp((s) => (tabId ? s.tabSession[tabId] : undefined))
  const termCwd = useApp((s) => (tabId ? s.tabCwd[tabId] : undefined))
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

  const list = useCallback(
    async (p: string): Promise<boolean> => {
      setLoading(true)
      setError(null)
      const res = await window.shellpilot?.sftp.list(key, p)
      if (res?.ok && res.data) {
        setEntries(res.data)
        setPath(p)
        setLoading(false)
        return true
      }
      setError(res?.error ?? 'Failed to list directory')
      setLoading(false)
      return false
    },
    [key]
  )

  // Navigate here AND mirror the change to the terminal (cd) when linked.
  const navigate = useCallback(
    async (p: string): Promise<void> => {
      const ok = await list(p)
      if (!ok) return
      if (tabId) setTabCwd(tabId, p)
      if (linked && session) {
        const q = p.replace(/'/g, `'\\''`)
        window.shellpilot?.ssh.write(session, `cd '${q}'\n`)
      }
    },
    [list, tabId, setTabCwd, linked, session]
  )

  useEffect(() => {
    let alive = true
    ;(async () => {
      setLoading(true)
      const res = await window.shellpilot?.sftp.connect(key, cfg())
      if (!alive) return
      if (res?.ok) {
        connectedRef.current = true
        // Start where the terminal is, if known; otherwise the SFTP home.
        await list(termCwd || res.data?.home || '/')
      } else {
        setError(res?.error ?? 'Connection failed')
        setLoading(false)
      }
    })()
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
    else toast(r?.error ?? 'Could not open the file', 'error')
  }

  const openFile = async (e: SftpEntry): Promise<void> => {
    if (e.size > 2_000_000) {
      toast('File too large to edit inline', 'error')
      return
    }
    const res = await window.shellpilot?.sftp.read(key, join(path, e.name))
    if (res?.ok) setEditor({ path: join(path, e.name), content: res.data ?? '' })
    else toast(res?.error ?? 'Read failed', 'error')
  }

  const saveFile = async (content: string): Promise<void> => {
    if (!editor) return
    const res = await window.shellpilot?.sftp.write(key, editor.path, content)
    if (res?.ok) {
      toast('Saved', 'ok')
      setEditor(null)
    } else toast(res?.error ?? 'Write failed', 'error')
  }

  const createFolder = async (): Promise<void> => {
    if (!newName.trim()) return setCreating(false)
    const res = await window.shellpilot?.sftp.mkdir(key, join(path, newName.trim()))
    if (res?.ok) {
      toast(`Created ${newName.trim()}`)
      setNewName('')
      setCreating(false)
      void list(path)
    } else toast(res?.error ?? 'mkdir failed', 'error')
  }

  const doRename = async (from: SftpEntry, to: string): Promise<void> => {
    setRenaming(null)
    if (!to.trim() || to === from.name) return
    const res = await window.shellpilot?.sftp.rename(key, join(path, from.name), join(path, to.trim()))
    if (res?.ok) void list(path)
    else toast(res?.error ?? 'Rename failed', 'error')
  }

  const remove = async (e: SftpEntry): Promise<void> => {
    if (!window.confirm(`Delete ${e.name}? This cannot be undone.`)) return
    const res = await window.shellpilot?.sftp.remove(key, join(path, e.name), e.dir)
    if (res?.ok) {
      toast(`Deleted ${e.name}`)
      void list(path)
    } else toast(res?.error ?? 'Delete failed', 'error')
  }

  // Transfer progress is reported from the main process while an upload runs.
  useEffect(() => {
    return window.shellpilot?.sftp.onProgress((p) => {
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
    for (const f of failed) toast(`${f.name}: ${f.error}`, 'error')
    if (!done && !failed.length) toast(res?.error ?? 'Upload failed', 'error')
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
    { label: 'Download', icon: <Download size={14} />, onClick: () => toast('Download coming soon') },
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
        <div className="empty" style={{ height: 200 }}>
          <div className="empty-icon" style={{ color: 'var(--danger)' }}>
            <AlertTriangle size={22} />
          </div>
          <h3>Could not open SFTP</h3>
          <p className="mono">{error}</p>
          <button className="btn" onClick={() => void list(path)}>
            <RefreshCw size={14} /> Retry
          </button>
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
  const [path, setPath] = useState('/opt/app')
  const [query, setQuery] = useState('')
  const [ctx, setCtx] = useState<{ x: number; y: number; name: string; dir: boolean } | null>(null)
  const entries = (DEMO_TREE[path] ?? []).filter((e) => e.name.toLowerCase().includes(query.toLowerCase()))
  const parts = path === '/' ? [] : path.split('/').filter(Boolean)

  const open = (e: { name: string; dir: boolean }): void => {
    if (e.dir) {
      const next = path === '/' ? `/${e.name}` : `${path}/${e.name}`
      if (DEMO_TREE[next]) setPath(next)
      else toast(`${e.name}/ is empty (demo)`)
    } else toast(`Opening ${e.name}… (demo)`)
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
            { label: 'Download', icon: <Download size={14} />, onClick: () => toast('demo') },
            ...(!ctx.dir
              ? EDITORS.map((ed) => ({ label: `Open with ${ed}`, icon: <Edit3 size={14} />, onClick: () => toast(`Open in ${ed} (demo)`) }))
              : []),
            { separator: true, label: '' },
            { label: 'Delete', icon: <Trash2 size={14} />, danger: true, onClick: () => toast('demo', 'error') }
          ]}
        />
      )}
    </div>
  )
}

export function SftpView({ server, tabId }: { server: Server; tabId?: string }): React.JSX.Element {
  return server.demo === false ? <RealSftp server={server} tabId={tabId} /> : <DemoSftp />
}
