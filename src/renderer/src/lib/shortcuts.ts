// The single source of truth for keyboard shortcuts.
//
// Every binding is a canonical combo string ("Ctrl+Shift+P") produced by
// `comboFrom` — the recorder in Settings and the dispatcher in useHotkeys both
// call it, so what the user presses while recording is exactly what matches
// later. Nothing else parses key events.

export type Scope = 'global' | 'app' | 'terminal'

export interface Command {
  id: string
  name: string
  group: string
  // Where the binding is live:
  //   app      – only when focus is outside a terminal, so shell control keys
  //              (Ctrl+K, Ctrl+W, Ctrl+L …) still reach the remote host.
  //   global   – everywhere, terminals included. Reserve for combos no shell
  //              owns, which in practice means Shift-qualified ones.
  //   terminal – only inside a terminal (clipboard, find).
  scope: Scope
  keys: string
  // Bindings the app computes rather than matches — shown for reference, not
  // rebindable.
  fixed?: boolean
  hint?: string
}

// Order here is the order shown in Settings.
export const COMMANDS: Command[] = [
  { id: 'palette', name: 'Command Palette', group: 'General', scope: 'app', keys: 'Ctrl+K' },
  {
    id: 'palette-global',
    name: 'Command Palette (in terminal)',
    group: 'General',
    scope: 'global',
    keys: 'Ctrl+Shift+P',
    hint: 'Ctrl+K is kill-line in a shell, so terminals need a second binding.'
  },
  { id: 'settings', name: 'Open Settings', group: 'General', scope: 'app', keys: 'Ctrl+,' },
  { id: 'toggle-sidebar', name: 'Toggle Sidebar', group: 'General', scope: 'app', keys: 'Ctrl+B' },
  {
    id: 'toggle-sidebar-global',
    name: 'Toggle Sidebar (in terminal)',
    group: 'General',
    scope: 'global',
    keys: 'Ctrl+Shift+B',
    hint: 'Ctrl+B is backward-char and the tmux prefix, so terminals need a second binding.'
  },

  { id: 'new-server', name: 'New Server', group: 'Tabs', scope: 'app', keys: 'Ctrl+N' },
  { id: 'new-terminal', name: 'New Terminal', group: 'Tabs', scope: 'app', keys: 'Ctrl+T' },
  {
    id: 'new-local-terminal',
    name: 'New Local Terminal',
    group: 'Tabs',
    scope: 'app',
    keys: 'Ctrl+Shift+T',
    hint: 'Opens a shell on this machine, not on a server.'
  },
  { id: 'duplicate-tab', name: 'Duplicate Tab', group: 'Tabs', scope: 'app', keys: 'Ctrl+Shift+D' },
  { id: 'close-tab', name: 'Close Tab', group: 'Tabs', scope: 'app', keys: 'Ctrl+W' },
  { id: 'next-tab', name: 'Next Tab', group: 'Tabs', scope: 'global', keys: 'Ctrl+Tab' },
  { id: 'prev-tab', name: 'Previous Tab', group: 'Tabs', scope: 'global', keys: 'Ctrl+Shift+Tab' },
  { id: 'split-v', name: 'Split Right', group: 'Tabs', scope: 'app', keys: 'Ctrl+\\' },
  { id: 'split-h', name: 'Split Down', group: 'Tabs', scope: 'app', keys: 'Ctrl+Shift+\\' },

  {
    id: 'new-workspace',
    name: 'New Workspace',
    group: 'Workspaces',
    scope: 'global',
    keys: 'Ctrl+Shift+N'
  },
  {
    id: 'switch-workspace',
    name: 'Switch to Workspace 1–9',
    group: 'Workspaces',
    scope: 'global',
    keys: 'Ctrl+1…9',
    fixed: true,
    hint: 'Numbering follows the sidebar order.'
  },
  {
    id: 'lock-workspace',
    name: 'Lock Workspace',
    group: 'Workspaces',
    scope: 'app',
    keys: 'Ctrl+L',
    hint: 'Only for workspaces that have a password set.'
  },

  { id: 'open-files', name: 'Open Files', group: 'Views', scope: 'global', keys: 'Ctrl+Shift+E' },
  { id: 'open-monitor', name: 'Open Fleet Monitor', group: 'Views', scope: 'app', keys: 'Ctrl+M' },
  { id: 'zoom-in', name: 'Zoom In', group: 'Views', scope: 'global', keys: 'Ctrl+=' },
  {
    id: 'zoom-in-alt',
    name: 'Zoom In (alternate)',
    group: 'Views',
    scope: 'global',
    keys: 'Ctrl+Shift+=',
    hint: 'The shifted form of the same key, which is how "Ctrl +" is usually typed.'
  },
  { id: 'zoom-out', name: 'Zoom Out', group: 'Views', scope: 'global', keys: 'Ctrl+-' },
  { id: 'zoom-reset', name: 'Reset Zoom', group: 'Views', scope: 'global', keys: 'Ctrl+0' },

  { id: 'term-copy', name: 'Copy', group: 'Terminal', scope: 'terminal', keys: 'Ctrl+Shift+C' },
  {
    id: 'term-copy-alt',
    name: 'Copy (alternate)',
    group: 'Terminal',
    scope: 'terminal',
    keys: 'Ctrl+Insert'
  },
  { id: 'term-paste', name: 'Paste', group: 'Terminal', scope: 'terminal', keys: 'Ctrl+Shift+V' },
  {
    id: 'term-paste-alt',
    name: 'Paste (alternate)',
    group: 'Terminal',
    scope: 'terminal',
    keys: 'Shift+Insert'
  },
  { id: 'term-find', name: 'Find in Terminal', group: 'Terminal', scope: 'terminal', keys: 'Ctrl+Shift+F' },
  {
    id: 'term-find-alt',
    name: 'Find in Terminal (alternate)',
    group: 'Terminal',
    scope: 'terminal',
    keys: 'Ctrl+F'
  }
]

export const COMMANDS_BY_ID = new Map(COMMANDS.map((c) => [c.id, c]))

// Punctuation and named keys, keyed by e.code so the combo survives a
// non-US layout. Letters and digits are derived from their code prefixes.
const CODE_TOKENS: Record<string, string> = {
  Backslash: '\\',
  BracketLeft: '[',
  BracketRight: ']',
  Comma: ',',
  Period: '.',
  Slash: '/',
  Semicolon: ';',
  Quote: "'",
  Backquote: '`',
  Minus: '-',
  Equal: '=',
  NumpadAdd: '=',
  NumpadSubtract: '-',
  NumpadDecimal: '.',
  NumpadDivide: '/',
  NumpadMultiply: '*',
  NumpadEnter: 'Enter',
  Space: 'Space',
  ArrowUp: 'Up',
  ArrowDown: 'Down',
  ArrowLeft: 'Left',
  ArrowRight: 'Right'
}

const MODIFIER_KEYS = new Set(['Control', 'Meta', 'Alt', 'Shift'])

// The printable/named token for a key press, without modifiers.
function keyToken(e: KeyboardEvent): string | null {
  if (MODIFIER_KEYS.has(e.key)) return null
  const code = e.code
  if (/^Key[A-Z]$/.test(code)) return code.slice(3)
  const digit = /^(?:Digit|Numpad)([0-9])$/.exec(code)?.[1]
  if (digit) return digit
  if (/^F[1-9][0-9]?$/.test(code)) return code
  if (CODE_TOKENS[code]) return CODE_TOKENS[code]
  // Keyboards that report no useful code (IME, some virtual keyboards) still
  // give a usable e.key.
  if (!code && e.key.length === 1) return e.key.toUpperCase()
  if (['Tab', 'Enter', 'Escape', 'Backspace', 'Delete', 'Insert', 'Home', 'End', 'PageUp', 'PageDown'].includes(code)) {
    return code
  }
  return e.key.length === 1 ? e.key.toUpperCase() : e.key
}

// Canonical combo for a key event, or null if only modifiers are held.
// Cmd is folded into Ctrl: one stored binding then works on both platforms,
// which is also how the app has always matched (e.ctrlKey || e.metaKey).
export function comboFrom(e: KeyboardEvent): string | null {
  const token = keyToken(e)
  if (!token) return null
  const parts: string[] = []
  if (e.ctrlKey || e.metaKey) parts.push('Ctrl')
  if (e.altKey) parts.push('Alt')
  if (e.shiftKey) parts.push('Shift')
  parts.push(token)
  return parts.join('+')
}

// Display form. Only differs from storage on macOS, where Ctrl is really Cmd.
export function displayCombo(combo: string, mac = isMac()): string[] {
  if (!combo) return []
  return combo.split('+').map((p) => (p === 'Ctrl' && mac ? 'Cmd' : p))
}

export function isMac(): boolean {
  return typeof navigator !== 'undefined' && /Mac|iPhone|iPad/.test(navigator.platform)
}

// Effective binding for every command: built-in defaults with the user's
// overrides applied. An override of '' means the user unbound it.
export function resolveBindings(overrides: Record<string, string>): Map<string, string> {
  const out = new Map<string, string>()
  for (const c of COMMANDS) {
    if (c.fixed) continue
    const keys = overrides[c.id] ?? c.keys
    if (keys) out.set(c.id, keys)
  }
  return out
}

// Two commands clash only where their scopes overlap — 'global' overlaps
// everything, 'app' and 'terminal' never see each other's key events.
export function scopesOverlap(a: Scope, b: Scope): boolean {
  return a === 'global' || b === 'global' || a === b
}

// combo -> command ids sharing it within an overlapping scope.
export function findConflicts(bindings: Map<string, string>): Map<string, string[]> {
  const byCombo = new Map<string, string[]>()
  for (const [id, keys] of bindings) {
    byCombo.set(keys, [...(byCombo.get(keys) ?? []), id])
  }
  const conflicts = new Map<string, string[]>()
  for (const [combo, ids] of byCombo) {
    if (ids.length < 2) continue
    const clashing = ids.filter((id) =>
      ids.some((other) => {
        if (other === id) return false
        const a = COMMANDS_BY_ID.get(id)?.scope
        const b = COMMANDS_BY_ID.get(other)?.scope
        return !!a && !!b && scopesOverlap(a, b)
      })
    )
    if (clashing.length > 1) conflicts.set(combo, clashing)
  }
  return conflicts
}
