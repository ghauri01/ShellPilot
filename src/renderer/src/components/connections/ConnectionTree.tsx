import { useMemo, useState } from 'react'
import {
  ChevronRight,
  Folder,
  FolderOpen,
  FolderPlus,
  Star,
  Terminal as TerminalIcon,
  Activity,
  FolderTree,
  Copy,
  Pencil,
  Trash2,
  Route,
  Server as ServerIcon,
  Plug
} from 'lucide-react'
import { useApp, useWorkspaceFolders, useWorkspaceServers } from '../../store/app'
import { clsx } from '../../lib/format'
import { toast } from '../../store/toast'
import { ContextMenu, MenuEntry } from './ContextMenu'
import type { Server } from '../../types'

interface Ctx {
  x: number
  y: number
  server: Server
}

export function ConnectionTree(): React.JSX.Element {
  const folders = useWorkspaceFolders()
  const servers = useWorkspaceServers()
  const openServer = useApp((s) => s.openServer)
  const newSession = useApp((s) => s.newSession)
  const toggleFavorite = useApp((s) => s.toggleFavorite)
  const openRouteEditor = useApp((s) => s.openRouteEditor)
  const openServerEditor = useApp((s) => s.openServerEditor)
  const addServer = useApp((s) => s.addServer)
  const deleteServer = useApp((s) => s.deleteServer)
  const addFolder = useApp((s) => s.addFolder)
  const renameFolder = useApp((s) => s.renameFolder)
  const deleteFolder = useApp((s) => s.deleteFolder)
  const moveServerToFolder = useApp((s) => s.moveServerToFolder)
  const activeTab = useApp((s) => s.activeTab())

  const [query, setQuery] = useState('')
  const [collapsed, setCollapsed] = useState<Record<string, boolean>>({})
  const [ctx, setCtx] = useState<Ctx | null>(null)
  const [folderCtx, setFolderCtx] = useState<{ x: number; y: number; id: string } | null>(null)
  const [renaming, setRenaming] = useState<string | null>(null)
  const [dragId, setDragId] = useState<string | null>(null)
  const [dropFolder, setDropFolder] = useState<string | null>(null)

  const folderMenu = (id: string, name: string): MenuEntry[] => [
    { label: 'Rename', icon: <Route size={14} />, onClick: () => setRenaming(id) },
    { label: 'New subfolder', icon: <FolderPlus size={14} />, onClick: () => addFolder('New folder', id) },
    { separator: true, label: '' },
    { label: `Delete "${name}"`, icon: <Trash2 size={14} />, danger: true, onClick: () => deleteFolder(id) }
  ]

  const FolderLabel = ({ id, name }: { id: string; name: string }): React.JSX.Element =>
    renaming === id ? (
      <input
        className="input"
        autoFocus
        style={{ height: 22, padding: '0 6px', flex: 1 }}
        defaultValue={name}
        onClick={(e) => e.stopPropagation()}
        onKeyDown={(e) => {
          if (e.key === 'Enter') {
            renameFolder(id, (e.target as HTMLInputElement).value.trim() || name)
            setRenaming(null)
          }
          if (e.key === 'Escape') setRenaming(null)
        }}
        onBlur={(e) => {
          renameFolder(id, e.target.value.trim() || name)
          setRenaming(null)
        }}
      />
    ) : (
      <span className="label">{name}</span>
    )

  const q = query.trim().toLowerCase()
  const match = (s: Server): boolean =>
    !q || s.name.toLowerCase().includes(q) || s.host.includes(q) || s.tags.some((t) => t.includes(q))

  const favorites = servers.filter((s) => s.favorite && match(s))
  const rootFolders = folders.filter((f) => f.parentId === null)

  const serversIn = (folderId: string | null): Server[] =>
    servers.filter((s) => s.folderId === folderId && match(s))

  const recent = useMemo(() => servers.slice(0, 3), [servers])

  const entries = (s: Server): MenuEntry[] => [
    { label: 'Connect', icon: <Plug size={14} />, onClick: () => openServer(s.id, 'terminal') },
    { label: 'New session', icon: <TerminalIcon size={14} />, onClick: () => newSession(s.id) },
    { label: 'Open monitor', icon: <Activity size={14} />, onClick: () => openServer(s.id, 'monitor') },
    { separator: true, label: '' },
    { label: 'Edit server', icon: <Pencil size={14} />, onClick: () => openServerEditor(s.id) },
    { label: 'Edit jump route', icon: <Route size={14} />, onClick: () => openRouteEditor(s.id) },
    {
      label: s.favorite ? 'Remove favorite' : 'Add favorite',
      icon: <Star size={14} />,
      onClick: () => toggleFavorite(s.id)
    },
    {
      label: 'Duplicate',
      icon: <Copy size={14} />,
      onClick: () => {
        const id = addServer({ ...s, name: `${s.name} copy` })
        // A credential is held in the OS keychain under the server's own id,
        // so the copy starts without one. Saying so here beats an
        // authentication failure later that reads as the original having
        // broken. SSH-agent servers carry no stored credential either way.
        if (s.auth === 'agent') toast(`${s.name} copy added`, 'ok')
        else
          toast(`${s.name} copy was added without a credential.`, 'info', {
            label: 'Add one',
            run: () => openServerEditor(id)
          })
      }
    },
    { separator: true, label: '' },
    {
      label: 'Delete',
      icon: <Trash2 size={14} />,
      danger: true,
      onClick: () => {
        deleteServer(s.id)
        void window.shellpilot?.secrets.delete(s.id)
        toast(`${s.name} deleted`)
      }
    }
  ]

  const ServerRow = ({ s, nested }: { s: Server; nested?: boolean }): React.JSX.Element => (
    <div
      className={clsx('tree-row', activeTab?.serverId === s.id && 'active')}
      style={nested ? undefined : { paddingLeft: 8 }}
      draggable
      onDragStart={() => setDragId(s.id)}
      onDragEnd={() => setDragId(null)}
      // Handled on mousedown via the click counter: the click handler swaps
      // the active tab, which re-renders this row, and a dblclick event that
      // lands on a replaced node never fires.
      onMouseDown={(e) => {
        if (e.detail >= 2) {
          e.preventDefault()
          newSession(s.id)
        }
      }}
      onClick={(e) => {
        if (e.detail >= 2) return
        openServer(s.id)
      }}
      onContextMenu={(e) => {
        e.preventDefault()
        setCtx({ x: e.clientX, y: e.clientY, server: s })
      }}
      title={`${s.username}@${s.host}:${s.port} — double-click for a new session`}
    >
      <span className={clsx('status-dot', s.status)} />
      <span className="label">{s.name}</span>
      {s.route.length > 0 && <Route size={12} className="faint" />}
      <span className="spacer" />
      {s.favorite && <Star size={12} className="fav" fill="currentColor" />}
    </div>
  )

  return (
    <>
      <div className="sidebar-search">
        <input
          className="input"
          style={{ height: 30, width: '100%' }}
          placeholder="Search connections…"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
        />
      </div>

      {favorites.length > 0 && (
        <div className="tree-section">
          <div className="tree-section-label">
            <Star size={11} /> Favorites
          </div>
          {favorites.map((s) => (
            <ServerRow key={s.id} s={s} />
          ))}
        </div>
      )}

      <div className="tree-section">
        <div
          className={clsx('tree-section-label', dropFolder === '__root__' && 'dragover')}
          onDragOver={(e) => {
            if (dragId) {
              e.preventDefault()
              setDropFolder('__root__')
            }
          }}
          onDragLeave={() => setDropFolder(null)}
          onDrop={() => {
            if (dragId) moveServerToFolder(dragId, null)
            setDropFolder(null)
            setDragId(null)
          }}
        >
          <FolderTree size={11} /> Connections <span className="count">{servers.length}</span>
          <button
            className="icon-btn xs"
            title="New folder"
            onClick={(e) => {
              e.stopPropagation()
              setRenaming(addFolder('New folder', null))
            }}
          >
            <FolderPlus size={13} />
          </button>
        </div>

        {rootFolders.map((f) => {
          const open = !collapsed[f.id]
          const childFolders = folders.filter((cf) => cf.parentId === f.id)
          const direct = serversIn(f.id)
          return (
            <div key={f.id}>
              <div
                className={clsx('tree-row', dropFolder === f.id && 'dragover')}
                onClick={() => renaming !== f.id && setCollapsed((c) => ({ ...c, [f.id]: !c[f.id] }))}
                onDoubleClick={() => setRenaming(f.id)}
                onContextMenu={(e) => {
                  e.preventDefault()
                  setFolderCtx({ x: e.clientX, y: e.clientY, id: f.id })
                }}
                onDragOver={(e) => {
                  if (dragId) {
                    e.preventDefault()
                    setDropFolder(f.id)
                  }
                }}
                onDragLeave={() => setDropFolder(null)}
                onDrop={() => {
                  if (dragId) {
                    moveServerToFolder(dragId, f.id)
                    toast(`Moved to ${f.name}`)
                  }
                  setDropFolder(null)
                  setDragId(null)
                }}
              >
                <ChevronRight size={14} className={clsx('chev', open && 'open')} />
                {open ? (
                  <FolderOpen size={15} className="folder-icon" />
                ) : (
                  <Folder size={15} className="folder-icon" />
                )}
                <FolderLabel id={f.id} name={f.name} />
                <span className="spacer" />
                <span className="faint" style={{ fontSize: 11 }}>
                  {direct.length + childFolders.reduce((n, c) => n + serversIn(c.id).length, 0)}
                </span>
              </div>
              {open && (
                <div className="tree-children">
                  {childFolders.map((cf) => {
                    const copen = !collapsed[cf.id]
                    return (
                      <div key={cf.id}>
                        <div
                          className={clsx('tree-row', dropFolder === cf.id && 'dragover')}
                          onClick={() => renaming !== cf.id && setCollapsed((c) => ({ ...c, [cf.id]: !c[cf.id] }))}
                          onDoubleClick={() => setRenaming(cf.id)}
                          onContextMenu={(e) => {
                            e.preventDefault()
                            setFolderCtx({ x: e.clientX, y: e.clientY, id: cf.id })
                          }}
                          onDragOver={(e) => {
                            if (dragId) {
                              e.preventDefault()
                              setDropFolder(cf.id)
                            }
                          }}
                          onDragLeave={() => setDropFolder(null)}
                          onDrop={() => {
                            if (dragId) {
                              moveServerToFolder(dragId, cf.id)
                              toast(`Moved to ${cf.name}`)
                            }
                            setDropFolder(null)
                            setDragId(null)
                          }}
                        >
                          <ChevronRight size={14} className={clsx('chev', copen && 'open')} />
                          {copen ? (
                            <FolderOpen size={15} className="folder-icon" />
                          ) : (
                            <Folder size={15} className="folder-icon" />
                          )}
                          <FolderLabel id={cf.id} name={cf.name} />
                        </div>
                        {copen && (
                          <div className="tree-children">
                            {serversIn(cf.id).map((s) => (
                              <ServerRow key={s.id} s={s} nested />
                            ))}
                          </div>
                        )}
                      </div>
                    )
                  })}
                  {direct.map((s) => (
                    <ServerRow key={s.id} s={s} nested />
                  ))}
                </div>
              )}
            </div>
          )
        })}

        {serversIn(null).map((s) => (
          <ServerRow key={s.id} s={s} />
        ))}
      </div>

      <div className="tree-section">
        <div className="tree-section-label">
          <ServerIcon size={11} /> Recent
        </div>
        {recent.map((s) => (
          <div key={s.id} className="tree-row" onClick={() => openServer(s.id)}>
            <span className={clsx('status-dot', s.status)} />
            <span className="label">{s.name}</span>
          </div>
        ))}
      </div>

      {ctx && (
        <ContextMenu x={ctx.x} y={ctx.y} entries={entries(ctx.server)} onClose={() => setCtx(null)} />
      )}
      {folderCtx && (
        <ContextMenu
          x={folderCtx.x}
          y={folderCtx.y}
          entries={folderMenu(folderCtx.id, folders.find((f) => f.id === folderCtx.id)?.name ?? '')}
          onClose={() => setFolderCtx(null)}
        />
      )}
    </>
  )
}
