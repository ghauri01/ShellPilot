import { useCallback, useEffect, useLayoutEffect, useRef, useState } from 'react'
import { ClipboardPaste, Copy, Eraser, Loader2, TextSelect } from 'lucide-react'
import { ContextMenu, type MenuEntry } from '../connections/ContextMenu'
import { shellPrompt } from '../../../../shared/dbshell'
import type { DbShellResult } from '../../../../shared/dbshell'
import type { DbConnectConfig, DbKind } from '../../../../shared/db'

interface Entry {
  id: number
  prompt: string
  input: string
  result?: DbShellResult
}

interface Props {
  cfg: DbConnectConfig
  kind: DbKind
  dbName: string
  // Applied when a command switches database (`use x`, `\c x`).
  onUseDatabase: (name: string) => void
  // Applied when a command changed the schema (DDL, drop, insert into a new
  // collection) so the sidebar can reload.
  onSchemaChanged: () => void
}

const BANNER: Record<DbKind, string> = {
  mongodb: 'MongoDB shell — type "help" for commands.',
  postgres: 'PostgreSQL shell — SQL plus \\l, \\dt, \\d <table>. Type "help".',
  mysql: 'MySQL shell — SQL plus \\l, \\dt, \\d <table>. Type "help".',
  mssql: 'SQL Server shell — T-SQL plus \\l, \\dt, \\d <table>. Type "help".',
  redis: 'Redis shell — type "help" for commands.'
}

export function DbShell({ cfg, kind, dbName, onUseDatabase, onSchemaChanged }: Props): React.JSX.Element {
  const [entries, setEntries] = useState<Entry[]>([])
  const [input, setInput] = useState('')
  const [busy, setBusy] = useState(false)
  const [history, setHistory] = useState<string[]>([])
  const [histIdx, setHistIdx] = useState(-1)
  const [menu, setMenu] = useState<{ x: number; y: number } | null>(null)
  const scrollRef = useRef<HTMLDivElement>(null)
  const inputRef = useRef<HTMLTextAreaElement>(null)
  const nextId = useRef(0)

  const prompt = shellPrompt(kind, dbName, cfg.username)

  useLayoutEffect(() => {
    const el = scrollRef.current
    if (el) el.scrollTop = el.scrollHeight
  }, [entries, busy])

  // Grow the input with its content, up to a sensible ceiling.
  useEffect(() => {
    const el = inputRef.current
    if (!el) return
    el.style.height = 'auto'
    el.style.height = `${Math.min(el.scrollHeight, 160)}px`
  }, [input])

  const submit = useCallback(async () => {
    const line = input
    if (!line.trim() || busy) return
    const id = nextId.current++
    setEntries((e) => [...e, { id, prompt, input: line }])
    setHistory((h) => (h[h.length - 1] === line ? h : [...h, line]))
    setHistIdx(-1)
    setInput('')
    setBusy(true)

    const r = (await window.shellpilot?.db.shell(cfg, line)) ?? { ok: false, error: 'No response' }

    if (r.clear) setEntries([])
    else setEntries((e) => e.map((x) => (x.id === id ? { ...x, result: r } : x)))
    if (r.useDatabase) onUseDatabase(r.useDatabase)
    if (r.refreshSchema) onSchemaChanged()
    setBusy(false)
    inputRef.current?.focus()
  }, [input, busy, prompt, cfg, onUseDatabase, onSchemaChanged])

  const onKeyDown = (e: React.KeyboardEvent<HTMLTextAreaElement>): void => {
    const el = e.currentTarget
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault()
      void submit()
      return
    }
    if (e.key === 'ArrowUp' && el.selectionStart === 0 && history.length) {
      e.preventDefault()
      const i = histIdx === -1 ? history.length - 1 : Math.max(0, histIdx - 1)
      setHistIdx(i)
      setInput(history[i])
      return
    }
    if (e.key === 'ArrowDown' && el.selectionStart === el.value.length && histIdx !== -1) {
      e.preventDefault()
      const i = histIdx + 1
      if (i >= history.length) {
        setHistIdx(-1)
        setInput('')
      } else {
        setHistIdx(i)
        setInput(history[i])
      }
      return
    }
    if (e.key === 'l' && e.ctrlKey) {
      e.preventDefault()
      setEntries([])
    }
  }

  const copySelection = (): boolean => {
    const sel = window.getSelection()?.toString()
    if (!sel) return false
    window.shellpilot?.clipboard.write(sel)
    return true
  }

  const pasteIntoInput = (): void => {
    const t = window.shellpilot?.clipboard.read()
    if (!t) return
    const el = inputRef.current
    if (el && document.activeElement === el) {
      const { selectionStart: a, selectionEnd: b } = el
      setInput((s) => s.slice(0, a ?? s.length) + t + s.slice(b ?? s.length))
    } else {
      setInput((s) => s + t)
    }
    el?.focus()
  }

  const selectAllOutput = (): void => {
    const el = scrollRef.current
    if (!el) return
    const range = document.createRange()
    range.selectNodeContents(el)
    const sel = window.getSelection()
    sel?.removeAllRanges()
    sel?.addRange(range)
  }

  // Clipboard keys are handled here rather than left to the browser because the
  // caret usually sits in the input while the selection the user wants lives up
  // in the scrollback.
  const onShellKeyDown = (e: React.KeyboardEvent): void => {
    if (!(e.ctrlKey || e.metaKey)) return
    const k = e.key.toLowerCase()
    const ta = inputRef.current
    if (k === 'c') {
      const inputHasSelection = ta && ta.selectionStart !== ta.selectionEnd
      if (!inputHasSelection && copySelection()) e.preventDefault()
      return
    }
    if (k === 'v' && document.activeElement !== ta) {
      pasteIntoInput()
      e.preventDefault()
      return
    }
    if (k === 'a' && document.activeElement !== ta) {
      selectAllOutput()
      e.preventDefault()
    }
  }

  const menuEntries = (): MenuEntry[] => {
    const hasSelection = !!window.getSelection()?.toString()
    return [
      { label: 'Copy', icon: <Copy size={14} />, onClick: () => copySelection() },
      { label: 'Paste', icon: <ClipboardPaste size={14} />, onClick: pasteIntoInput },
      { separator: true, label: '' },
      { label: hasSelection ? 'Select all output' : 'Select all', icon: <TextSelect size={14} />, onClick: selectAllOutput },
      { label: 'Clear', icon: <Eraser size={14} />, onClick: () => setEntries([]) }
    ]
  }

  return (
    <div
      className="dbshell"
      onKeyDown={onShellKeyDown}
      // Focus the input on a plain click, but never while the user is
      // selecting text — focusing would collapse the selection.
      onMouseUp={() => {
        if (!window.getSelection()?.toString()) inputRef.current?.focus()
      }}
      onContextMenu={(e) => {
        e.preventDefault()
        setMenu({ x: e.clientX, y: e.clientY })
      }}
    >
      <div className="dbshell-scroll" ref={scrollRef}>
        <div className="dbshell-banner">{BANNER[kind]}</div>
        {entries.map((e) => (
          <div key={e.id} className="dbshell-entry">
            <div className="dbshell-line">
              <span className="dbshell-prompt">{e.prompt}</span>
              <span className="dbshell-echo">{e.input}</span>
            </div>
            {e.result ? <Output result={e.result} /> : <div className="dbshell-pending">…</div>}
          </div>
        ))}
        <div className="dbshell-line dbshell-active">
          <span className="dbshell-prompt">{prompt}</span>
          <textarea
            ref={inputRef}
            className="dbshell-input"
            rows={1}
            autoFocus
            spellCheck={false}
            value={input}
            disabled={busy}
            onChange={(e) => setInput(e.target.value)}
            onKeyDown={onKeyDown}
          />
          {busy && <Loader2 size={13} className="spin" />}
        </div>
      </div>
      <div className="dbshell-hint">
        <span>
          <b>Enter</b> run · <b>Shift+Enter</b> newline · <b>↑</b> history · <b>Ctrl+C/V</b> copy &amp; paste ·{' '}
          <b>Ctrl+L</b> clear · <b>help</b> for commands
        </span>
      </div>
      {menu && <ContextMenu x={menu.x} y={menu.y} entries={menuEntries()} onClose={() => setMenu(null)} />}
    </div>
  )
}

function Output({ result }: { result: DbShellResult }): React.JSX.Element | null {
  if (!result.ok) {
    return <div className="dbshell-error">{result.error}</div>
  }
  const parts: React.JSX.Element[] = []
  if (result.text) parts.push(<pre key="t" className="dbshell-out">{result.text}</pre>)
  if (result.columns?.length) {
    parts.push(
      <pre key="r" className="dbshell-out">
        {renderTable(result.columns, result.rows ?? [])}
      </pre>
    )
  }
  if (result.json !== undefined) {
    parts.push(
      <pre key="j" className="dbshell-out">
        {JSON.stringify(result.json, null, 2)}
      </pre>
    )
  }
  if (result.note || result.elapsedMs != null) {
    parts.push(
      <div key="n" className="dbshell-note">
        {result.note}
        {result.note && result.elapsedMs != null ? ' · ' : ''}
        {result.elapsedMs != null ? `${result.elapsedMs} ms` : ''}
      </div>
    )
  }
  if (!parts.length) return <div className="dbshell-note">ok</div>
  return <>{parts}</>
}

// Align rows into fixed-width columns, psql style.
function renderTable(columns: string[], rows: unknown[][]): string {
  const cell = (v: unknown): string =>
    v === null || v === undefined ? '' : typeof v === 'object' ? JSON.stringify(v) : String(v)
  const body = rows.map((r) => columns.map((_, i) => cell(r[i])))
  const widths = columns.map((c, i) =>
    Math.min(60, Math.max(c.length, ...body.map((r) => r[i].length), 0))
  )
  const pad = (s: string, w: number): string => (s.length > w ? s.slice(0, w - 1) + '…' : s.padEnd(w))
  const lines = [
    columns.map((c, i) => pad(c, widths[i])).join('  '),
    widths.map((w) => '─'.repeat(w)).join('  '),
    ...body.map((r) => r.map((c, i) => pad(c, widths[i])).join('  '))
  ]
  return lines.join('\n').replace(/[ ]+$/gm, '')
}
