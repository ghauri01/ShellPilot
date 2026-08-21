import { ReactNode, useEffect, useRef } from 'react'
import { createPortal } from 'react-dom'
import { useClickOutside } from '../../hooks/useClickOutside'

export interface MenuEntry {
  label: string
  icon?: ReactNode
  onClick?: () => void
  danger?: boolean
  separator?: boolean
  disabled?: boolean
}

interface ContextMenuProps {
  x: number
  y: number
  entries: MenuEntry[]
  onClose: () => void
}

export function ContextMenu({ x, y, entries, onClose }: ContextMenuProps): React.JSX.Element {
  const ref = useRef<HTMLDivElement>(null)
  useClickOutside(ref, onClose)
  const [px, py] = clamp(x, y)
  useEffect(() => {
    const onScroll = (): void => onClose()
    window.addEventListener('resize', onScroll)
    return () => window.removeEventListener('resize', onScroll)
  }, [onClose])

  return createPortal(
    <div className="menu" style={{ top: py, left: px }} ref={ref}>
      {entries.map((e, i) =>
        e.separator ? (
          <div className="menu-sep" key={i} />
        ) : (
          <button
            key={i}
            className={`menu-item${e.danger ? ' danger' : ''}`}
            disabled={e.disabled}
            onClick={() => {
              e.onClick?.()
              onClose()
            }}
          >
            {e.icon}
            <span>{e.label}</span>
          </button>
        )
      )}
    </div>,
    document.body
  )
}

function clamp(x: number, y: number): [number, number] {
  const menuW = 230
  const menuH = 320
  const px = Math.min(x, window.innerWidth - menuW - 8)
  const py = Math.min(y, window.innerHeight - menuH - 8)
  return [Math.max(8, px), Math.max(8, py)]
}
