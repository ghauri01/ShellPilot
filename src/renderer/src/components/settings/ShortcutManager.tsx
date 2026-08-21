import { useEffect, useMemo, useState } from 'react'
import { RotateCcw, Download, Upload, AlertTriangle, X } from 'lucide-react'
import { useApp } from '../../store/app'
import { toast } from '../../store/toast'
import {
  COMMANDS,
  COMMANDS_BY_ID,
  comboFrom,
  displayCombo,
  findConflicts,
  resolveBindings
} from '../../lib/shortcuts'

const SCOPE_LABEL: Record<string, string> = {
  app: 'Outside terminals',
  global: 'Everywhere',
  terminal: 'In terminals'
}

export function ShortcutManager(): React.JSX.Element {
  const overrides = useApp((s) => s.settings.shortcuts)
  const setShortcut = useApp((s) => s.setShortcut)
  const resetShortcuts = useApp((s) => s.resetShortcuts)
  const [recording, setRecording] = useState<string | null>(null)

  const bindings = useMemo(() => resolveBindings(overrides), [overrides])
  const conflicts = useMemo(() => findConflicts(bindings), [bindings])

  // While recording, every key press belongs to the recorder — captured on the
  // way down so the app's own shortcuts cannot swallow the combo being bound.
  useEffect(() => {
    if (!recording) return
    const handler = (e: KeyboardEvent): void => {
      e.preventDefault()
      e.stopPropagation()
      if (e.key === 'Escape') return setRecording(null)
      // Backspace clears the binding; the command then has no key at all.
      if (e.key === 'Backspace' || e.key === 'Delete') {
        setShortcut(recording, '')
        return setRecording(null)
      }
      const combo = comboFrom(e)
      if (!combo) return
      setShortcut(recording, combo)
      setRecording(null)
    }
    window.addEventListener('keydown', handler, true)
    return () => window.removeEventListener('keydown', handler, true)
  }, [recording, setShortcut])

  const exportJson = async (): Promise<void> => {
    const ok = await window.shellpilot?.dialog.saveJson(
      'shellpilot-shortcuts.json',
      JSON.stringify({ shortcuts: overrides }, null, 2)
    )
    if (ok) toast('Shortcuts exported')
  }

  const importJson = async (): Promise<void> => {
    const raw = await window.shellpilot?.dialog.openJson()
    if (!raw) return
    const parsed = parseShortcutFile(raw)
    if (!parsed) return toast('That file is not a ShellPilot shortcut export')
    resetShortcuts()
    for (const [id, keys] of Object.entries(parsed)) setShortcut(id, keys)
    toast(`Imported ${Object.keys(parsed).length} shortcut(s)`)
  }

  const groups = useMemo(() => {
    const out: { group: string; ids: string[] }[] = []
    for (const c of COMMANDS) {
      const last = out[out.length - 1]
      if (last?.group === c.group) last.ids.push(c.id)
      else out.push({ group: c.group, ids: [c.id] })
    }
    return out
  }, [])

  return (
    <div>
      <div className="row" style={{ marginBottom: 16 }}>
        <span className="faint" style={{ fontSize: 12 }}>
          Click a shortcut and press the keys you want. Backspace clears it, Esc cancels.
        </span>
        <span className="spacer" />
        <button
          className="btn sm"
          onClick={() => {
            resetShortcuts()
            toast('Shortcuts reset to defaults')
          }}
        >
          <RotateCcw size={13} /> Reset
        </button>
        <button className="btn sm" onClick={() => void exportJson()}>
          <Download size={13} /> Export
        </button>
        <button className="btn sm" onClick={() => void importJson()}>
          <Upload size={13} /> Import
        </button>
      </div>

      {groups.map(({ group, ids }) => (
        <div key={group}>
          <div className="palette-group">{group}</div>
          {ids.map((id) => {
            const cmd = COMMANDS_BY_ID.get(id)
            if (!cmd) return null
            const keys = cmd.fixed ? cmd.keys : bindings.get(id) ?? ''
            const clash = !cmd.fixed && keys ? conflicts.get(keys)?.includes(id) : false
            const overridden = !cmd.fixed && overrides[id] !== undefined
            return (
              <div className="sc-row" key={id}>
                <span className="sc-name">
                  {cmd.name}
                  <span className="faint" style={{ marginLeft: 8, fontSize: 11 }}>
                    {SCOPE_LABEL[cmd.scope]}
                    {cmd.hint ? ` · ${cmd.hint}` : ''}
                  </span>
                </span>
                {clash && (
                  <span className="sc-conflict">
                    <AlertTriangle size={12} /> conflict
                  </span>
                )}
                {overridden && (
                  <button
                    className="icon-btn"
                    title={`Restore default (${cmd.keys})`}
                    onClick={() => setShortcut(id, null)}
                  >
                    <RotateCcw size={12} />
                  </button>
                )}
                <button
                  className={`sc-record${recording === id ? ' recording' : ''}`}
                  disabled={cmd.fixed}
                  title={cmd.fixed ? 'This shortcut cannot be changed' : 'Click, then press keys'}
                  onClick={() => !cmd.fixed && setRecording(id)}
                  style={clash ? { borderColor: 'var(--danger)', color: 'var(--danger)' } : undefined}
                >
                  {recording === id ? (
                    'Press keys…'
                  ) : keys ? (
                    displayCombo(keys).map((k, i) => (
                      <span className="kbd" key={i}>
                        {k}
                      </span>
                    ))
                  ) : (
                    <span className="faint">
                      <X size={12} /> unbound
                    </span>
                  )}
                </button>
              </div>
            )
          })}
        </div>
      ))}
    </div>
  )
}

// An exported file is only trusted as far as its shape: a flat map of known
// command ids to strings. Unknown ids are dropped rather than stored, so an
// old export cannot resurrect a command that no longer exists.
function parseShortcutFile(raw: string): Record<string, string> | null {
  let data: unknown
  try {
    data = JSON.parse(raw)
  } catch {
    return null
  }
  const shortcuts = (data as { shortcuts?: unknown })?.shortcuts
  if (!shortcuts || typeof shortcuts !== 'object' || Array.isArray(shortcuts)) return null
  const out: Record<string, string> = {}
  for (const [id, keys] of Object.entries(shortcuts as Record<string, unknown>)) {
    if (typeof keys === 'string' && COMMANDS_BY_ID.has(id)) out[id] = keys
  }
  return out
}
