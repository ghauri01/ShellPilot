import { useEffect, useRef, useState } from 'react'
import { ArrowDown, ArrowUp, CaseSensitive, Regex, WholeWord, X } from 'lucide-react'
import type { SearchAddon } from '@xterm/addon-search'
import { clsx } from '../../lib/format'

// Search bar over the terminal scrollback. The SearchAddon was already loaded
// but had no keybinding or UI, so searching did nothing.
export function TerminalSearch({
  search,
  onClose
}: {
  search: React.RefObject<SearchAddon | null>
  onClose: () => void
}): React.JSX.Element {
  const [term, setTerm] = useState('')
  const [caseSensitive, setCaseSensitive] = useState(false)
  const [wholeWord, setWholeWord] = useState(false)
  const [regex, setRegex] = useState(false)
  const [result, setResult] = useState<{ index: number; count: number } | null>(null)
  const inputRef = useRef<HTMLInputElement>(null)

  const options = {
    caseSensitive,
    wholeWord,
    regex,
    decorations: {
      matchBackground: '#4d3b00',
      matchOverviewRuler: '#e3b341',
      activeMatchBackground: '#8a6d00',
      activeMatchColorOverviewRuler: '#f0c674'
    }
  }

  useEffect(() => {
    inputRef.current?.focus()
    inputRef.current?.select()
  }, [])

  // The addon reports match counts asynchronously as it scans the buffer.
  useEffect(() => {
    const addon = search.current
    if (!addon) return
    const d = addon.onDidChangeResults?.((r) =>
      setResult(r ? { index: r.resultIndex, count: r.resultCount } : null)
    )
    return () => d?.dispose()
  }, [search])

  const find = (dir: 1 | -1): void => {
    const addon = search.current
    if (!addon || !term) return
    if (dir === 1) addon.findNext(term, options)
    else addon.findPrevious(term, options)
  }

  // Re-run on every change so results track what is typed.
  useEffect(() => {
    const addon = search.current
    if (!addon) return
    if (!term) {
      addon.clearDecorations()
      setResult(null)
      return
    }
    addon.findNext(term, options)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [term, caseSensitive, wholeWord, regex])

  const close = (): void => {
    search.current?.clearDecorations()
    onClose()
  }

  return (
    <div className="term-search">
      <input
        ref={inputRef}
        className="input"
        placeholder="Find in terminal…"
        value={term}
        onChange={(e) => setTerm(e.target.value)}
        onKeyDown={(e) => {
          if (e.key === 'Enter') find(e.shiftKey ? -1 : 1)
          if (e.key === 'Escape') close()
        }}
      />
      <span className={clsx('term-search-count', term && result?.count === 0 && 'none')}>
        {term ? (result ? `${result.count ? result.index + 1 : 0}/${result.count}` : '…') : ''}
      </span>
      <button
        className={clsx('icon-btn sm', caseSensitive && 'active')}
        title="Match case"
        onClick={() => setCaseSensitive((v) => !v)}
      >
        <CaseSensitive size={14} />
      </button>
      <button
        className={clsx('icon-btn sm', wholeWord && 'active')}
        title="Whole word"
        onClick={() => setWholeWord((v) => !v)}
      >
        <WholeWord size={14} />
      </button>
      <button
        className={clsx('icon-btn sm', regex && 'active')}
        title="Regular expression"
        onClick={() => setRegex((v) => !v)}
      >
        <Regex size={14} />
      </button>
      <button className="icon-btn sm" title="Previous (Shift+Enter)" onClick={() => find(-1)}>
        <ArrowUp size={14} />
      </button>
      <button className="icon-btn sm" title="Next (Enter)" onClick={() => find(1)}>
        <ArrowDown size={14} />
      </button>
      <button className="icon-btn sm" title="Close (Esc)" onClick={close}>
        <X size={14} />
      </button>
    </div>
  )
}
