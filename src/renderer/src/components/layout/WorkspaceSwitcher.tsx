import { useRef, useState } from 'react'
import { ChevronDown, Plus, Settings2, Eye, EyeOff, Check } from 'lucide-react'
import { useApp } from '../../store/app'
import { useClickOutside } from '../../hooks/useClickOutside'
import { switchableWorkspaces } from '../../hooks/useHotkeys'
import type { WorkspaceColor } from '../../types'

const colorVar: Record<WorkspaceColor, string> = {
  green: 'var(--ws-green)',
  purple: 'var(--ws-purple)',
  blue: 'var(--ws-blue)',
  orange: 'var(--ws-orange)',
  red: 'var(--ws-red)',
  cyan: 'var(--ws-cyan)',
  pink: 'var(--ws-pink)'
}

const mod = navigator.platform.toLowerCase().includes('mac') ? '⌘' : 'Ctrl '

export function WorkspaceSwitcher(): React.JSX.Element {
  const [open, setOpen] = useState(false)
  const ref = useRef<HTMLDivElement>(null)
  useClickOutside(ref, () => setOpen(false), open)

  const workspaces = useApp((s) => s.workspaces)
  const activeId = useApp((s) => s.activeWorkspaceId)
  const setWorkspace = useApp((s) => s.setWorkspace)
  const setModal = useApp((s) => s.setModal)

  const includeHidden = useApp((s) => s.settings.switchHiddenWorkspaces)

  const active = workspaces.find((w) => w.id === activeId) ?? workspaces[0]
  const visible = workspaces.filter((w) => !w.hidden)
  const hidden = workspaces.filter((w) => w.hidden)

  // Badges are derived from the same ordering the shortcut uses, so what the
  // menu shows always matches what the key actually does.
  const order = switchableWorkspaces(workspaces, includeHidden)
  const numberOf = (id: string): number | null => {
    const i = order.findIndex((w) => w.id === id)
    return i >= 0 && i < 9 ? i + 1 : null
  }
  const badge = (id: string): React.JSX.Element | null => {
    const n = numberOf(id)
    return n === null ? null : (
      <span className="kbd" title={`Switch with Ctrl+${n}`}>
        {mod}
        {n}
      </span>
    )
  }

  return (
    <div className="tooltip-server no-drag" ref={ref}>
      <button className="ws-trigger" onClick={() => setOpen((v) => !v)}>
        <span className="ws-dot" style={{ background: colorVar[active.color], color: colorVar[active.color] }} />
        <span>{active.name}</span>
        <ChevronDown size={14} className="faint" />
      </button>

      {open && (
        <div className="menu" style={{ top: 34, left: 0, width: 260 }}>
          <div className="menu-label">Workspaces</div>
          {visible.map((w) => (
            <button
              key={w.id}
              className="menu-item"
              onClick={() => {
                setWorkspace(w.id)
                setOpen(false)
              }}
            >
              <span className="ws-dot" style={{ background: colorVar[w.color], color: colorVar[w.color] }} />
              <span>{w.name}</span>
              {w.locked && <span className="chip">🔒</span>}
              <span className="spacer" />
              {badge(w.id)}
              {w.id === activeId && <Check size={14} className="accent" style={{ color: 'var(--accent)' }} />}
            </button>
          ))}

          {hidden.length > 0 && (
            <>
              <div className="menu-sep" />
              {/* Hidden workspaces are only listed individually when they are
                  shortcut-reachable — otherwise their numbers would be
                  invisible and the numbering would look wrong. */}
              {includeHidden ? (
                hidden.map((w) => (
                  <button
                    key={w.id}
                    className="menu-item"
                    style={{ opacity: 0.65 }}
                    onClick={() => {
                      setWorkspace(w.id)
                      setOpen(false)
                    }}
                  >
                    <EyeOff size={14} className="faint" />
                    <span>{w.name}</span>
                    <span className="spacer" />
                    {badge(w.id)}
                    {w.id === activeId && <Check size={14} style={{ color: 'var(--accent)' }} />}
                  </button>
                ))
              ) : (
                <div className="menu-item" style={{ cursor: 'default', color: 'var(--text-faint)' }}>
                  <Eye size={14} />
                  <span>Hidden workspaces</span>
                  <span className="spacer" />
                  <span className="chip">{hidden.length}</span>
                </div>
              )}
            </>
          )}

          <div className="menu-sep" />
          <button
            className="menu-item"
            onClick={() => {
              setModal('workspaces')
              setOpen(false)
            }}
          >
            <Plus size={14} />
            <span>New workspace</span>
          </button>
          <button
            className="menu-item"
            onClick={() => {
              setModal('workspaces')
              setOpen(false)
            }}
          >
            <Settings2 size={14} />
            <span>Manage workspaces</span>
          </button>
        </div>
      )}
    </div>
  )
}

export { colorVar }
