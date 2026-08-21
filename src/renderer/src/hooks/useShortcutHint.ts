import { useEffect, useState } from 'react'
import { useApp } from '../store/app'
import { displayCombo, resolveBindings } from '../lib/shortcuts'

// Whether focus currently sits inside a terminal. Terminals take a different
// set of bindings, so anything that advertises a shortcut has to know which
// context the user is in.
export function useTerminalFocus(): boolean {
  const [inTerminal, setInTerminal] = useState(false)
  useEffect(() => {
    // focusout fires before the next element is focused, so activeElement is
    // still settling; reading it on the next tick gives the final answer and
    // avoids a flicker when moving between two terminals.
    let queued: ReturnType<typeof setTimeout> | null = null
    const update = (): void => {
      if (queued) clearTimeout(queued)
      queued = setTimeout(() => {
        const el = document.activeElement as HTMLElement | null
        setInTerminal(!!el?.closest?.('.xterm, .terminal-wrap'))
      }, 0)
    }
    update()
    document.addEventListener('focusin', update)
    document.addEventListener('focusout', update)
    return () => {
      if (queued) clearTimeout(queued)
      document.removeEventListener('focusin', update)
      document.removeEventListener('focusout', update)
    }
  }, [])
  return inTerminal
}

// The keys to advertise for a command right now, already split for rendering
// as <kbd> chips. Commands that need a separate binding inside a terminal pass
// it as `terminalCommandId`; the hint then follows focus, so the user is only
// ever shown a shortcut that actually works where they are standing.
// Either id falls back to the other when its own binding is cleared.
export function useShortcutHint(commandId: string, terminalCommandId?: string): string[] {
  const overrides = useApp((s) => s.settings.shortcuts)
  const inTerminal = useTerminalFocus()
  const bindings = resolveBindings(overrides)
  const preferred = inTerminal && terminalCommandId ? terminalCommandId : commandId
  const fallback = preferred === commandId ? terminalCommandId : commandId
  const keys = bindings.get(preferred) || (fallback ? bindings.get(fallback) : '') || ''
  return displayCombo(keys)
}
