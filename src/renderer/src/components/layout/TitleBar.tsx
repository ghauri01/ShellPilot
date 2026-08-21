import { useEffect, useState } from 'react'
import { Search, Minus, Square, Copy, X, Compass } from 'lucide-react'
import { useApp } from '../../store/app'
import { WorkspaceSwitcher } from './WorkspaceSwitcher'
import { useShortcutHint } from '../../hooks/useShortcutHint'

export function TitleBar(): React.JSX.Element {
  const togglePalette = useApp((s) => s.togglePalette)
  // Ctrl+K does not reach the app from inside a terminal — the shell owns it —
  // so the chip advertises the terminal binding whenever focus is in one.
  const paletteKeys = useShortcutHint('palette', 'palette-global')
  const [maximized, setMaximized] = useState(false)
  const [isMac, setIsMac] = useState(false)

  useEffect(() => {
    window.shellpilot?.platform().then((p) => setIsMac(p === 'darwin'))
    window.shellpilot?.window.isMaximized().then(setMaximized)
    const off = window.shellpilot?.window.onMaximizedChange(setMaximized)
    return off
  }, [])

  const ctrl = (a: 'minimize' | 'toggle-maximize' | 'close'): void => {
    window.shellpilot?.window.control(a)
  }

  return (
    <div className="titlebar" style={isMac ? { paddingLeft: 78 } : undefined}>
      <div className="brand">
        <div className="brand-mark">
          <Compass size={14} strokeWidth={2.4} />
        </div>
        <span className="brand-name">
          Shell<b>Pilot</b>
        </span>
      </div>

      <WorkspaceSwitcher />

      <div className="titlebar-search">
        <button className="cmd-trigger" onClick={() => togglePalette(true)}>
          <Search size={13} />
          <span>Search or run a command…</span>
          <span className="cmd-keys">
            {paletteKeys.map((k, i) => (
              <span className="kbd" key={i}>
                {k}
              </span>
            ))}
          </span>
        </button>
      </div>

      {!isMac && (
        <div className="win-controls">
          <button className="win-btn" onClick={() => ctrl('minimize')} aria-label="Minimize">
            <Minus size={15} />
          </button>
          <button className="win-btn" onClick={() => ctrl('toggle-maximize')} aria-label="Maximize">
            {maximized ? <Copy size={12} /> : <Square size={12} />}
          </button>
          <button className="win-btn close" onClick={() => ctrl('close')} aria-label="Close">
            <X size={16} />
          </button>
        </div>
      )}
    </div>
  )
}
