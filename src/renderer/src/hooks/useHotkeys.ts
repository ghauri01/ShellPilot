import { useEffect } from 'react'
import { useApp } from '../store/app'
import { COMMANDS_BY_ID, comboFrom, resolveBindings, type Scope } from '../lib/shortcuts'
import type { Workspace } from '../types'

type Store = ReturnType<typeof useApp.getState>

// Clipboard/search actions a terminal supplies for the terminal-scope commands.
// The terminal owns them, so they are handed in rather than reached for here.
export interface TerminalActions {
  copy: () => void
  paste: () => void
  find?: () => void
}

// What each command does. Returning false means "not applicable right now"
// (no tab open, workspace has no password) and lets the key through to
// whatever would normally receive it.
const RUNNERS: Record<string, (s: Store, term?: TerminalActions) => boolean> = {
  palette: (s) => (s.togglePalette(), true),
  'palette-global': (s) => (s.togglePalette(), true),
  settings: (s) => (s.setActivity('settings'), true),
  'toggle-sidebar': (s) => (s.toggleSidebar(), true),
  'toggle-sidebar-global': (s) => (s.toggleSidebar(), true),

  'new-server': (s) => (s.setModal('add-server'), true),
  // Mirrors the tab bar's + button: another session on the current server, or
  // the add-server dialog when there is nothing to open a session against.
  'new-terminal': (s) => {
    const serverId = s.activeTab()?.serverId
    if (serverId) s.newSession(serverId)
    else s.setModal('add-server')
    return true
  },
  'duplicate-tab': (s) => {
    const tab = s.activeTab()
    return tab ? (s.duplicateTab(tab.id), true) : false
  },
  'close-tab': (s) => (s.activeTabId ? (s.closeTab(s.activeTabId), true) : false),
  'next-tab': (s) => (s.cycleTab(1), true),
  'prev-tab': (s) => (s.cycleTab(-1), true),
  'split-v': (s) => splitActive(s, 'v'),
  'split-h': (s) => splitActive(s, 'h'),

  'new-workspace': (s) => (s.setModal('workspaces'), true),
  // Locking an unprotected workspace would drop you out of it with no way
  // back in, so this only applies where a password is actually set.
  'lock-workspace': (s) => {
    const ws = s.activeWorkspace()
    if (!ws?.hasPassword) return false
    s.lockWorkspace(ws.id)
    return true
  },

  'open-files': (s) => {
    const tab = s.activeTab()
    return tab ? (s.setTabView(tab.id, 'files'), true) : false
  },
  'open-monitor': (s) => (s.setActivity('monitor'), true),
  'zoom-in': (s) => (s.zoomTerminal(1), true),
  'zoom-in-alt': (s) => (s.zoomTerminal(1), true),
  'zoom-out': (s) => (s.zoomTerminal(-1), true),
  'zoom-reset': (s) => (s.zoomTerminal('reset'), true),

  'term-copy': (_s, term) => (term ? (term.copy(), true) : false),
  'term-copy-alt': (_s, term) => (term ? (term.copy(), true) : false),
  'term-paste': (_s, term) => (term ? (term.paste(), true) : false),
  'term-paste-alt': (_s, term) => (term ? (term.paste(), true) : false),
  'term-find': (_s, term) => (term?.find ? (term.find(), true) : false),
  'term-find-alt': (_s, term) => (term?.find ? (term.find(), true) : false)
}

// Splitting only means anything for a terminal tab backed by a live server.
function splitActive(s: Store, dir: 'h' | 'v'): boolean {
  const tab = s.activeTab()
  if (!tab?.serverId) return false
  s.toggleSplit(tab.id, dir)
  return true
}

// Whether a command bound in `scope` should fire for a key event seen in
// `where`. 'global' fires everywhere; the other two only in their own context.
function scopeApplies(scope: Scope, where: 'app' | 'terminal'): boolean {
  return scope === 'global' || scope === where
}

// Runs whatever the user has bound to this key event, if anything.
// `where` is 'terminal' when focus is inside a terminal, which is what keeps
// shell control keys (Ctrl+K, Ctrl+W, Ctrl+L …) reaching the remote host —
// only 'global' and 'terminal' bindings are considered there.
export function runShortcut(
  e: KeyboardEvent,
  where: 'app' | 'terminal',
  term?: TerminalActions
): boolean {
  const combo = comboFrom(e)
  if (!combo) return false
  const s = useApp.getState()
  const bindings = resolveBindings(s.settings.shortcuts)

  for (const [id, keys] of bindings) {
    if (keys !== combo) continue
    const cmd = COMMANDS_BY_ID.get(id)
    if (!cmd || !scopeApplies(cmd.scope, where)) continue
    if (RUNNERS[id]?.(s, term)) return true
  }

  // Ctrl/Cmd+1…9 jumps to the Nth visible workspace. Checked after the user's
  // bindings so rebinding a digit still wins, and matched on e.code so it
  // lands on the right digit under non-US keyboard layouts.
  return switchWorkspaceByDigit(e, s)
}

function switchWorkspaceByDigit(e: KeyboardEvent, s: Store): boolean {
  if (!(e.ctrlKey || e.metaKey) || e.shiftKey || e.altKey) return false
  const digit = /^(?:Digit|Numpad)([1-9])$/.exec(e.code)?.[1]
  if (!digit) return false
  const target = switchableWorkspaces(s.workspaces, s.settings.switchHiddenWorkspaces)[
    Number(digit) - 1
  ]
  if (!target) return false
  if (target.id !== s.activeWorkspaceId) s.setWorkspace(target.id)
  return true
}

// The switcher menu and the Ctrl+1…9 shortcuts must agree on ordering, so both
// number the workspaces through here. With `includeHidden` off, hidden
// workspaces are skipped entirely and the numbering closes up around them.
export function switchableWorkspaces(workspaces: Workspace[], includeHidden: boolean): Workspace[] {
  return includeHidden ? workspaces : workspaces.filter((w) => !w.hidden)
}

function inTerminal(target: EventTarget | null): boolean {
  return !!(target as HTMLElement)?.closest?.('.xterm, .terminal-wrap')
}

export function useHotkeys(): void {
  useEffect(() => {
    const handler = (e: KeyboardEvent): void => {
      // Terminals route their own keys through runShortcut via
      // attachCustomKeyEventHandler, so they are skipped here.
      if (inTerminal(e.target)) return
      if (runShortcut(e, 'app')) e.preventDefault()
    }
    window.addEventListener('keydown', handler)
    return () => window.removeEventListener('keydown', handler)
  }, [])
}
