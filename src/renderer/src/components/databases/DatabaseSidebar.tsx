import { useState } from 'react'
import {
  ChevronRight,
  Database,
  Folder as FolderIcon,
  FolderOpen,
  FolderPlus,
  Pencil,
  Trash2,
  Plug
} from 'lucide-react'
import { useApp, useWorkspaceDatabases, useWorkspaceFolders } from '../../store/app'
import { clsx } from '../../lib/format'
import { toast } from '../../store/toast'
import { ContextMenu, MenuEntry } from '../connections/ContextMenu'
import type { DatabaseConn, DbKind, Folder } from '../../types'

export const KIND_COLOR: Record<DbKind, string> = {
  postgres: '#58a6ff',
  mysql: '#e3873c',
  mssql: '#f85149',
  mongodb: '#3fb950',
  redis: '#db61a2'
}
export const KIND_SHORT: Record<DbKind, string> = {
  postgres: 'PG',
  mysql: 'SQL',
  mssql: 'MS',
  mongodb: 'MDB',
  redis: 'RDS'
}

export function DatabaseSidebar(): React.JSX.Element {
  const databases = useWorkspaceDatabases()
  const folders = useWorkspaceFolders('database')
  const activeId = useApp((s) => s.activeDatabaseId)
  const openDatabase = useApp((s) => s.openDatabase)
  const deleteDatabase = useApp((s) => s.deleteDatabase)
  const addFolder = useApp((s) => s.addFolder)
  const renameFolder = useApp((s) => s.renameFolder)
  const deleteFolder = useApp((s) => s.deleteFolder)
  const moveDatabaseToFolder = useApp((s) => s.moveDatabaseToFolder)

  const [ctx, setCtx] = useState<{ x: number; y: number; id: string; name: string } | null>(null)
  const [folderCtx, setFolderCtx] = useState<{ x: number; y: number; id: string } | null>(null)
  const [renaming, setRenaming] = useState<string | null>(null)
  const [collapsed, setCollapsed] = useState<Record<string, boolean>>({})
  const [dragId, setDragId] = useState<string | null>(null)
  const [dropTarget, setDropTarget] = useState<string | null>(null)

  const dbsIn = (folderId: string | null): DatabaseConn[] =>
    databases.filter((d) => (d.folderId ?? null) === folderId)

  const childrenOf = (parentId: string | null): Folder[] =>
    folders.filter((f) => f.parentId === parentId)

  // Total databases inside a folder and everything below it.
  const countDeep = (folderId: string): number =>
    dbsIn(folderId).length + childrenOf(folderId).reduce((n, c) => n + countDeep(c.id), 0)

  const drop = (folderId: string | null, label: string): void => {
    if (dragId) {
      moveDatabaseToFolder(dragId, folderId)
      toast(`Moved to ${label}`)
    }
    setDropTarget(null)
    setDragId(null)
  }

  const folderMenu = (id: string, name: string): MenuEntry[] => [
    { label: 'Rename', icon: <Pencil size={14} />, onClick: () => setRenaming(id) },
    {
      label: 'New subfolder',
      icon: <FolderPlus size={14} />,
      onClick: () => setRenaming(addFolder('New folder', id, 'database'))
    },
    { separator: true, label: '' },
    { label: `Delete "${name}"`, icon: <Trash2 size={14} />, danger: true, onClick: () => deleteFolder(id) }
  ]

  const dbRow = (d: DatabaseConn): React.JSX.Element => (
    <div
      key={d.id}
      className={clsx('tree-row', activeId === d.id && 'active')}
      draggable
      onDragStart={() => setDragId(d.id)}
      onDragEnd={() => setDragId(null)}
      onClick={() => openDatabase(d.id)}
      onContextMenu={(e) => {
        e.preventDefault()
        setCtx({ x: e.clientX, y: e.clientY, id: d.id, name: d.name })
      }}
      title={`${d.username}@${d.host}:${d.port}`}
    >
      <span
        className="mono"
        style={{ fontSize: 9, fontWeight: 700, color: KIND_COLOR[d.kind], width: 26, flex: 'none' }}
      >
        {KIND_SHORT[d.kind]}
      </span>
      <span className="label">{d.name}</span>
    </div>
  )

  const folderLabel = (f: Folder): React.JSX.Element =>
    renaming === f.id ? (
      <input
        className="input"
        autoFocus
        style={{ height: 22, padding: '0 6px', flex: 1 }}
        defaultValue={f.name}
        onClick={(e) => e.stopPropagation()}
        onKeyDown={(e) => {
          if (e.key === 'Enter') {
            renameFolder(f.id, (e.target as HTMLInputElement).value.trim() || f.name)
            setRenaming(null)
          }
          if (e.key === 'Escape') setRenaming(null)
        }}
        onBlur={(e) => {
          renameFolder(f.id, e.target.value.trim() || f.name)
          setRenaming(null)
        }}
      />
    ) : (
      <span className="label">{f.name}</span>
    )

  // Rendered recursively so folders can nest arbitrarily deep.
  const folderNode = (f: Folder): React.JSX.Element => {
    const open = !collapsed[f.id]
    return (
      <div key={f.id}>
        <div
          className={clsx('tree-row', dropTarget === f.id && 'dragover')}
          onClick={() => renaming !== f.id && setCollapsed((c) => ({ ...c, [f.id]: !c[f.id] }))}
          onDoubleClick={() => setRenaming(f.id)}
          onContextMenu={(e) => {
            e.preventDefault()
            setFolderCtx({ x: e.clientX, y: e.clientY, id: f.id })
          }}
          onDragOver={(e) => {
            if (dragId) {
              e.preventDefault()
              setDropTarget(f.id)
            }
          }}
          onDragLeave={() => setDropTarget(null)}
          onDrop={() => drop(f.id, f.name)}
        >
          <ChevronRight size={14} className={clsx('chev', open && 'open')} />
          {open ? (
            <FolderOpen size={15} className="folder-icon" />
          ) : (
            <FolderIcon size={15} className="folder-icon" />
          )}
          {folderLabel(f)}
          <span className="spacer" />
          <span className="faint" style={{ fontSize: 11 }}>
            {countDeep(f.id)}
          </span>
        </div>
        {open && (
          <div className="tree-children">
            {childrenOf(f.id).map(folderNode)}
            {dbsIn(f.id).map(dbRow)}
          </div>
        )}
      </div>
    )
  }

  const rootDbs = dbsIn(null)

  return (
    <div className="tree-section">
      <div
        className={clsx('tree-section-label', dropTarget === '__root__' && 'dragover')}
        onDragOver={(e) => {
          if (dragId) {
            e.preventDefault()
            setDropTarget('__root__')
          }
        }}
        onDragLeave={() => setDropTarget(null)}
        onDrop={() => drop(null, 'Databases')}
      >
        <Database size={11} /> Databases <span className="count">{databases.length}</span>
        <button
          className="icon-btn xs"
          title="New folder"
          onClick={(e) => {
            e.stopPropagation()
            setRenaming(addFolder('New folder', null, 'database'))
          }}
        >
          <FolderPlus size={13} />
        </button>
      </div>

      {childrenOf(null).map(folderNode)}
      {rootDbs.map(dbRow)}

      {databases.length === 0 && folders.length === 0 && (
        <div className="faint" style={{ padding: '8px 10px', fontSize: 12 }}>
          No database connections yet.
        </div>
      )}

      {ctx && (
        <ContextMenu
          x={ctx.x}
          y={ctx.y}
          onClose={() => setCtx(null)}
          entries={[
            { label: 'Open', icon: <Plug size={14} />, onClick: () => openDatabase(ctx.id) },
            { separator: true, label: '' },
            {
              label: 'Delete',
              icon: <Trash2 size={14} />,
              danger: true,
              onClick: () => {
                deleteDatabase(ctx.id)
                void window.shellpilot?.secrets.delete(ctx.id)
                toast(`${ctx.name} deleted`)
              }
            }
          ]}
        />
      )}
      {folderCtx && (
        <ContextMenu
          x={folderCtx.x}
          y={folderCtx.y}
          entries={folderMenu(folderCtx.id, folders.find((f) => f.id === folderCtx.id)?.name ?? '')}
          onClose={() => setFolderCtx(null)}
        />
      )}
    </div>
  )
}
