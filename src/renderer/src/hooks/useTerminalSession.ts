import { useCallback, useEffect, useRef, useState } from 'react'
import { Terminal } from '@xterm/xterm'
import { FitAddon } from '@xterm/addon-fit'
import { WebLinksAddon } from '@xterm/addon-web-links'
import { SearchAddon } from '@xterm/addon-search'
import { useApp } from '../store/app'
import { runShortcut } from './useHotkeys'
import type { TerminalTransport } from '../lib/transport'

// The xterm primitives live here rather than in TerminalView because the hook
// is their only real consumer; TerminalView imports them back for the demo
// shell. The other direction would be a module cycle.

export function themeFromCss(): Record<string, string> {
  const css = getComputedStyle(document.documentElement)
  const v = (n: string): string => css.getPropertyValue(n).trim()
  return {
    background: v('--bg-terminal'),
    foreground: v('--text'),
    cursor: v('--accent'),
    cursorAccent: v('--bg-terminal'),
    selectionBackground: v('--accent-soft'),
    black: '#0b0e14',
    red: '#f85149',
    green: '#3fb950',
    yellow: '#d29922',
    blue: '#58a6ff',
    magenta: '#a371f7',
    cyan: '#22c7d6',
    white: '#e6edf3',
    brightBlack: '#6b7484'
  }
}

// FitAddon throws "Cannot read properties of undefined (reading 'dimensions')"
// when the host has no layout box (0x0, e.g. a hidden/display:none tab). Only
// fit when the element is actually visible and sized.
export function safeFit(fit: FitAddon, host: HTMLDivElement): void {
  if (host.clientWidth > 0 && host.clientHeight > 0) {
    try {
      fit.fit()
    } catch {
      /* terminal not ready / detached */
    }
  }
}

// Robustly keep the terminal fitted to its container. Fits immediately, on the
// next frame, after a short delay (fonts/layout settle), on every resize, and
// whenever the element transitions hidden -> visible (background tab shown).
export function observeSize(
  fit: FitAddon,
  host: HTMLDivElement,
  onFit?: () => void
): () => void {
  const doFit = (): void => {
    safeFit(fit, host)
    if (host.clientWidth > 0) onFit?.()
  }
  doFit()
  const raf = requestAnimationFrame(doFit)
  const t = setTimeout(doFit, 80)
  const ro = new ResizeObserver(doFit)
  ro.observe(host)
  const io = new IntersectionObserver((entries) => {
    if (entries.some((e) => e.isIntersecting)) doFit()
  })
  io.observe(host)
  return () => {
    cancelAnimationFrame(raf)
    clearTimeout(t)
    ro.disconnect()
    io.disconnect()
  }
}

export function createTerm(
  host: HTMLDivElement,
  fontSize: number
): { term: Terminal; fit: FitAddon; search: SearchAddon } {
  const term = new Terminal({
    fontFamily: getComputedStyle(document.documentElement).getPropertyValue('--font-mono').trim(),
    fontSize,
    lineHeight: 1.35,
    cursorBlink: true,
    allowProposedApi: true,
    theme: themeFromCss() as never,
    scrollback: 10000
  })
  const fit = new FitAddon()
  const search = new SearchAddon()
  term.loadAddon(fit)
  term.loadAddon(new WebLinksAddon())
  term.loadAddon(search)
  term.open(host)

  // xterm's default renderer builds DOM nodes for every cell, which is what
  // makes typing feel delayed on a busy screen. The GPU renderer draws to a
  // canvas instead. Loaded after open() because it needs a live element, and
  // guarded so a machine without working WebGL simply keeps the DOM renderer.
  void import('@xterm/addon-webgl')
    .then(({ WebglAddon }) => {
      const webgl = new WebglAddon()
      // A lost context (driver reset, GPU switch) must not leave a dead canvas.
      webgl.onContextLoss(() => webgl.dispose())
      term.loadAddon(webgl)
    })
    .catch(() => {
      /* no WebGL here — the DOM renderer still works */
    })

  safeFit(fit, host)
  return { term, fit, search }
}

// Clipboard (copy-on-select + paste) and terminal-aware shortcut routing.
// Only bindings the user has scoped to a terminal (clipboard, find) or to
// every context (Ctrl+Shift+P etc.) are intercepted; all other control keys —
// Ctrl+C/O/X/A/E/W/K/B and friends — pass through to the shell so nano, vim,
// bash line editing and Ctrl+C all behave normally.
export function setupTerminalUX(
  term: Terminal,
  host: HTMLDivElement,
  onFind?: () => void,
  onConfirmPaste?: (text: string, lines: number) => void
): () => void {
  const copySel = (): void => {
    const sel = term.getSelection()
    if (sel) window.shellpilot?.clipboard.write(sel)
  }
  const paste = (): void => {
    const t = window.shellpilot?.clipboard.read()
    if (!t) return
    // A pasted block runs line by line the moment it lands. Confirm anything
    // multi-line so a stray paste cannot execute a script on a production box.
    const lines = t.split(/\r?\n/).filter((l) => l.length > 0)
    const multiline = /\r?\n/.test(t.trimEnd())
    if (multiline && onConfirmPaste) {
      onConfirmPaste(t, lines.length)
      return
    }
    term.paste(t)
  }

  // onSelectionChange fires on every mouse move during a drag, and each copy
  // is a synchronous clipboard write across the context bridge. Coalesce to
  // the end of the gesture.
  let selTimer: ReturnType<typeof setTimeout> | null = null
  const selDisp = term.onSelectionChange(() => {
    if (selTimer) clearTimeout(selTimer)
    selTimer = setTimeout(copySel, 120)
  })

  term.attachCustomKeyEventHandler((e) => {
    if (e.type !== 'keydown') return true
    // Every binding — clipboard, find, and the app shortcuts that must win
    // even inside a terminal — resolves through the user's shortcut map.
    // The 'terminal' context is what leaves shell control keys (Ctrl+K,
    // Ctrl+W, Ctrl+L …) untouched, so they still reach the remote host.
    if (runShortcut(e, 'terminal', { copy: copySel, paste, find: onFind })) {
      e.preventDefault()
      return false
    }
    return true // everything else goes to the shell
  })

  // Right-click paste (PuTTY / MobaXterm style).
  const onCtx = (ev: MouseEvent): void => {
    ev.preventDefault()
    paste()
  }
  host.addEventListener('contextmenu', onCtx)

  return () => {
    if (selTimer) clearTimeout(selTimer)
    selDisp.dispose()
    host.removeEventListener('contextmenu', onCtx)
  }
}

export function parseOsc7(data: string): string | null {
  // data looks like: file://hostname/absolute/path
  const m = data.match(/^file:\/\/[^/]*(\/.*)$/)
  if (!m) return null
  try {
    return decodeURIComponent(m[1])
  } catch {
    return m[1]
  }
}

/**
 * One live terminal bound to one transport.
 *
 * Two properties this hook exists to preserve, both load-bearing:
 *
 *  - the xterm instance outlives the session. It is built once per transport
 *    and torn down only when the transport changes, so a reconnect keeps the
 *    scrollback — usually the thing you most want to read after a drop.
 *  - a reconnect is a `generation` bump, which re-runs exactly the same code
 *    path as the first connect rather than a second, subtly different one.
 *
 * Both effects therefore key on `transport.key`, never on the transport
 * object, which is rebuilt on every render of the component above.
 */
export function useTerminalSession(
  transport: TerminalTransport,
  hostRef: React.RefObject<HTMLDivElement | null>,
  onFind: () => void,
  onConfirmPaste: (text: string, lines: number) => void,
  tabId?: string
): {
  termRef: React.RefObject<Terminal | null>
  searchRef: React.RefObject<SearchAddon | null>
  dead: string | null
  reconnect: () => void
} {
  const setTabSession = useApp((s) => s.setTabSession)
  const setTabCwd = useApp((s) => s.setTabCwd)
  const fontSize = useApp((s) => s.settings.terminalFontSize)
  // Kept in refs so the zoom effect can reach the live terminal without
  // rebuilding it — recreating would drop the session.
  const termRef = useRef<Terminal | null>(null)
  const fitRef = useRef<FitAddon | null>(null)
  const searchRef = useRef<SearchAddon | null>(null)
  const sessionRef = useRef<string | null>(null)

  // Font size is read once at creation; later changes are applied below.
  const initialFontSize = useRef(fontSize)

  // Why the session ended, or null while it is alive. A closed session used to
  // leave a terminal that could not be typed into and could not be brought
  // back — the only way out was closing the tab and opening the server again.
  const [dead, setDead] = useState<string | null>(null)
  // Bumped to rebuild the session. The effect already tears everything down on
  // cleanup, so a reconnect is the same code path as the first connect.
  const [generation, setGeneration] = useState(0)

  // The terminal is built once per transport. Rebuilding it on a reconnect
  // would throw away the scrollback, so it deliberately outlives the session.
  useEffect(() => {
    if (!hostRef.current) return
    const { term, fit, search } = createTerm(hostRef.current, initialFontSize.current)
    termRef.current = term
    fitRef.current = fit
    searchRef.current = search
    const disposeUX = setupTerminalUX(
      term,
      hostRef.current,
      () => onFind(),
      (text, lines) => onConfirmPaste(text, lines)
    )

    // Report cwd changes to the store (for SFTP follow) if the shell emits
    // OSC 7 on each prompt. Harmless when it doesn't — and a local zsh with
    // add-zsh-hook emits it exactly like a remote one, so this works for local
    // tabs with no extra wiring.
    const oscDisp = term.parser.registerOscHandler(7, (data) => {
      const p = parseOsc7(data)
      if (p && tabId) setTabCwd(tabId, p)
      return true
    })

    const host = hostRef.current
    // Resizes reach whichever session is current, or nothing at all while the
    // terminal is sitting dead between sessions.
    const disposeSize = observeSize(fit, host, () => {
      const id = sessionRef.current
      if (id) transport.resize(id, term.cols, term.rows)
    })

    return () => {
      disposeSize()
      disposeUX()
      oscDisp.dispose()
      termRef.current = null
      fitRef.current = null
      searchRef.current = null
      term.dispose()
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [transport.key])

  // The session, which can be torn down and rebuilt under the same terminal.
  // Bumping `generation` reconnects.
  useEffect(() => {
    const term = termRef.current
    if (!term) return
    const sessionId = `sess-${transport.key}-${Math.random().toString(36).slice(2)}`
    sessionRef.current = sessionId

    if (generation > 0) term.writeln('')
    term.writeln('\x1b[38;5;80mShellPilot\x1b[0m')
    term.writeln(`Connecting to \x1b[1m${transport.title}\x1b[0m (${transport.endpoint})…`)

    const offData = transport.onData(sessionId, (d) => {
      // xterm calls back once the chunk has been parsed into the buffer. Main
      // stops reading the pty when too many code units are outstanding, so
      // this is what unblocks it — without the callback the window never
      // reopens and a large `cat` stalls forever after the first burst.
      //
      // `d.length` is UTF-16 code units, which is what main counts on the way
      // out. Never a byte count: the two disagree on every non-ASCII character
      // and the difference is an unrepayable deficit that wedges the session.
      term.write(d, () => transport.ack?.(sessionId, d.length))
    })
    const offStatus = transport.onStatus(sessionId, (s) => {
      if (s.phase === 'progress') {
        if (s.line) term.writeln(s.line)
      } else if (s.phase === 'ready') {
        transport.onLifecycle?.('online')
        if (tabId) setTabSession(tabId, sessionId)
      } else {
        term.writeln(`\r\n\x1b[31mConnection failed: ${s.message ?? 'unknown error'}\x1b[0m`)
        transport.onLifecycle?.('offline')
        setDead(s.message ?? 'Connection failed')
      }
    })
    const offClose = transport.onClose(sessionId, (why) => {
      term.writeln(`\r\n\x1b[90m[session closed${why ? ` · ${why}` : ''}]\x1b[0m`)
      term.writeln('\x1b[90mPress Enter to reconnect in this tab.\x1b[0m')
      transport.onLifecycle?.('offline')
      setDead(why ? `Session closed · ${why}` : 'Session closed')
    })

    transport.onLifecycle?.('connecting')
    void transport.connect(sessionId, term.cols, term.rows).catch((err) => {
      transport.onLifecycle?.('offline')
      setDead(`Session closed · ${err instanceof Error ? err.message : String(err)}`)
    })

    const onInput = term.onData((d) => transport.write(sessionId, d))

    return () => {
      onInput.dispose()
      offData()
      offStatus()
      offClose()
      if (tabId) setTabSession(tabId, null)
      sessionRef.current = null
      transport.close(sessionId)
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [transport.key, generation])

  // Zoom is applied to the live terminal rather than recreating it, which
  // would drop the session. Refit so the new cell size is used, then tell the
  // pty its new dimensions so wrapping stays correct.
  useEffect(() => {
    const term = termRef.current
    const fit = fitRef.current
    const host = hostRef.current
    if (!term || !fit || !host) return
    term.options.fontSize = fontSize
    safeFit(fit, host)
    if (sessionRef.current) transport.resize(sessionRef.current, term.cols, term.rows)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [fontSize, hostRef])

  const reconnect = useCallback(() => {
    setDead(null)
    setGeneration((g) => g + 1)
  }, [])

  return { termRef, searchRef, dead, reconnect }
}
