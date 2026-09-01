import { useEffect, useRef, useState } from 'react'
import { ChevronDown, Terminal as TerminalIcon, RotateCw } from 'lucide-react'
import { useApp } from '../../store/app'
import { ContextMenu, MenuEntry } from '../connections/ContextMenu'

// The caret half of the tab bar's split `+` button: a dropdown of the shells
// this machine actually has, so a local terminal can be opened without there
// being a local tab to duplicate.
//
// It is also the one thing that populates `localShells`. The store's
// `refreshLocalShells` exists but nothing else calls it, and until something
// does, `openLocalById` resolves nothing and the hotkey and the palette group
// are both silently inert. This component is mounted for the life of the
// workspace panel, so asking once on mount is effectively asking at app start —
// deliberately here rather than in a shell-list-shaped `useEffect` bolted to
// App.tsx, so there is exactly one owner of that call.
export function LocalShellMenu(): React.JSX.Element | null {
  const shells = useApp((s) => s.localShells)
  const refreshLocalShells = useApp((s) => s.refreshLocalShells)
  const openLocal = useApp((s) => s.openLocal)
  // Absence means enabled everywhere this flag is read — main's own copy
  // (services/localGate.ts) does the same, and the two must not disagree.
  const enabled = useApp((s) => s.settings.localTerminalEnabled !== false)
  const btnRef = useRef<HTMLButtonElement>(null)
  const [at, setAt] = useState<{ x: number; y: number } | null>(null)

  useEffect(() => {
    if (!enabled) return
    // No catch chain: refreshLocalShells swallows a missing bridge itself and
    // resolves to an empty list, which renders as the empty-state entry below.
    void refreshLocalShells()
  }, [enabled, refreshLocalShells])

  if (!enabled) return null

  // The default shell first, then the rest in discovery order. Chosen with
  // `isDefault`, never by matching anything against the id: ids are opaque
  // ('darwin-zsh-b663616e' is a readable prefix plus a digest of the path) and
  // parsing one is how two shells with the same basename become one entry.
  const ordered = [...shells].sort((a, b) => Number(!!b.isDefault) - Number(!!a.isDefault))

  const entries: MenuEntry[] =
    ordered.length === 0
      ? [{ label: 'No shells found on this machine', disabled: true }]
      : ordered.map((sh) => ({
          label: sh.isDefault ? `${sh.label} — default` : sh.label,
          icon: <TerminalIcon size={14} />,
          onClick: () => openLocal(sh)
        }))

  return (
    <>
      <button
        ref={btnRef}
        className="tab-new"
        style={{ width: 22 }}
        title="New local shell"
        aria-label="New local shell"
        onClick={() => {
          const r = btnRef.current?.getBoundingClientRect()
          setAt({ x: r?.left ?? 0, y: (r?.bottom ?? 0) + 4 })
        }}
      >
        <ChevronDown size={14} />
      </button>
      {at && (
        <ContextMenu
          x={at.x}
          y={at.y}
          entries={[
            ...entries,
            { separator: true, label: '' },
            {
              label: 'Rescan shells',
              icon: <RotateCw size={14} />,
              // `true` makes main re-enumerate instead of answering from its
              // cache, which is the only reason this entry exists — a shell
              // installed while the app was running is otherwise invisible.
              onClick: () => void refreshLocalShells(true)
            }
          ]}
          onClose={() => setAt(null)}
        />
      )}
    </>
  )
}
