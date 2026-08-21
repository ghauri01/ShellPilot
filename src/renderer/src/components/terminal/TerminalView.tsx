import { useCallback, useEffect, useRef, useState } from 'react'
import { RotateCw } from 'lucide-react'
import { Terminal } from '@xterm/xterm'
import { FitAddon } from '@xterm/addon-fit'
import { WebLinksAddon } from '@xterm/addon-web-links'
import { SearchAddon } from '@xterm/addon-search'
import { TerminalSearch } from './TerminalSearch'
import { PasteConfirm } from './PasteConfirm'
import { useApp } from '../../store/app'
import { runShortcut } from '../../hooks/useHotkeys'
import { sshHopsFor } from '../../lib/ssh'
import type { Server } from '../../types'
import type { SshAuth, SshCloseInfo } from '../../../../shared/ssh'

function themeFromCss(): Record<string, string> {
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
function safeFit(fit: FitAddon, host: HTMLDivElement): void {
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
function observeSize(fit: FitAddon, host: HTMLDivElement, onFit?: () => void): () => void {
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

function createTerm(
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

const asAuth = (a: string): SshAuth => (a === 'password' || a === 'agent' ? a : 'key')

// Clipboard (copy-on-select + paste) and terminal-aware shortcut routing.
// Only bindings the user has scoped to a terminal (clipboard, find) or to
// every context (Ctrl+Shift+P etc.) are intercepted; all other control keys —
// Ctrl+C/O/X/A/E/W/K/B and friends — pass through to the shell so nano, vim,
// bash line editing and Ctrl+C all behave normally.
function setupTerminalUX(
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

// Plain-language reason a session ended, or '' when the far end said nothing
// (a dropped link, or a bastion that went away mid-session).
function closeReason(info: SshCloseInfo): string {
  if (info.signal) {
    // A server-side idle timeout is by far the most common HUP, and it is
    // worth naming rather than leaving as a bare signal.
    return info.signal === 'HUP' ? 'closed by server (SIGHUP — often an idle timeout)' : `signal ${info.signal}`
  }
  if (info.code === 0) return 'shell exited'
  if (typeof info.code === 'number') return `shell exited with ${info.code}`
  return ''
}

// ---- Real SSH session ------------------------------------------------------
function parseOsc7(data: string): string | null {
  // data looks like: file://hostname/absolute/path
  const m = data.match(/^file:\/\/[^/]*(\/.*)$/)
  if (!m) return null
  try {
    return decodeURIComponent(m[1])
  } catch {
    return m[1]
  }
}

function useRealSession(
  server: Server,
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
  const setServerStatus = useApp((s) => s.setServerStatus)
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

  // The terminal is built once per server. Rebuilding it on a reconnect would
  // throw away the scrollback, which is usually the thing you most want to
  // read after a session drops, so it deliberately outlives the SSH session.
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

    // Report cwd changes to the store (for SFTP follow) if the remote shell
    // emits OSC 7 on each prompt. Harmless when it doesn't.
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
      if (id) window.shellpilot?.ssh.resize(id, term.cols, term.rows)
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
  }, [server.id])

  // The SSH session, which can be torn down and rebuilt under the same
  // terminal. Bumping `generation` reconnects.
  useEffect(() => {
    const term = termRef.current
    if (!term) return
    const bridge = window.shellpilot
    const sessionId = `sess-${server.id}-${Math.random().toString(36).slice(2)}`
    sessionRef.current = sessionId

    // Jump hops need their own credentials: either the secrets stored against
    // the saved server they point at, or a key path set directly on the hop.
    const hops = sshHopsFor(server)

    if (generation > 0) term.writeln('')
    term.writeln('\x1b[38;5;80mShellPilot\x1b[0m')
    term.writeln(`Connecting to \x1b[1m${server.name}\x1b[0m (${server.host}:${server.port})…`)

    const offData = bridge?.ssh.onData(sessionId, (d) => term.write(d))
    const offStatus = bridge?.ssh.onStatus(sessionId, (s) => {
      if (s.phase === 'hop') {
        term.writeln(`\x1b[90m↪ hop ${(s.hopIndex ?? 0) + 1}/${s.hopCount}\x1b[0m`)
      } else if (s.phase === 'ready') {
        setServerStatus(server.id, 'online')
        if (tabId) setTabSession(tabId, sessionId)
      } else if (s.phase === 'error') {
        term.writeln(`\r\n\x1b[31mConnection failed: ${s.message ?? 'unknown error'}\x1b[0m`)
        setServerStatus(server.id, 'offline')
        setDead(s.message ?? 'Connection failed')
      }
    })
    const offClose = bridge?.ssh.onClose(sessionId, (info) => {
      const why = closeReason(info)
      term.writeln(`\r\n\x1b[90m[session closed${why ? ` · ${why}` : ''}]\x1b[0m`)
      term.writeln('\x1b[90mPress Enter to reconnect in this tab.\x1b[0m')
      setServerStatus(server.id, 'offline')
      setDead(why ? `Session closed · ${why}` : 'Session closed')
    })

    setServerStatus(server.id, 'connecting')
    void bridge?.ssh.connect({
      sessionId,
      serverId: server.id,
      host: server.host,
      port: server.port,
      username: server.username,
      auth: asAuth(server.auth),
      cols: term.cols,
      rows: term.rows,
      hops
    })

    const onInput = term.onData((d) => bridge?.ssh.write(sessionId, d))

    return () => {
      onInput.dispose()
      offData?.()
      offStatus?.()
      offClose?.()
      if (tabId) setTabSession(tabId, null)
      sessionRef.current = null
      bridge?.ssh.close(sessionId)
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [server.id, generation])

  // Zoom is applied to the live terminal rather than recreating it, which
  // would drop the session. Refit so the new cell size is used, then tell the
  // remote pty its new dimensions so wrapping stays correct.
  useEffect(() => {
    const term = termRef.current
    const fit = fitRef.current
    const host = hostRef.current
    if (!term || !fit || !host) return
    term.options.fontSize = fontSize
    safeFit(fit, host)
    if (sessionRef.current) window.shellpilot?.ssh.resize(sessionRef.current, term.cols, term.rows)
  }, [fontSize, hostRef])

  const reconnect = useCallback(() => {
    setDead(null)
    setGeneration((g) => g + 1)
  }, [])

  return { termRef, searchRef, dead, reconnect }
}

// ---- Simulated demo shell --------------------------------------------------
const MOCK: Record<string, string> = {
  ls: 'app  config  docker-compose.yml  logs  node_modules  package.json  src',
  uname: 'Linux',
  date: 'Live shell — connect a backend to run real commands',
  help: 'Simulated shell. Try: ls, pwd, whoami, uptime, echo <text>, clear'
}

function useDemoSession(server: Server, hostRef: React.RefObject<HTMLDivElement | null>): void {
  useEffect(() => {
    if (!hostRef.current) return
    const { term, fit } = createTerm(hostRef.current, useApp.getState().settings.terminalFontSize)
    const disposeUX = setupTerminalUX(term, hostRef.current)
    const user = server.username
    const short = server.name.toLowerCase().split(' ')[0]
    const home = `/home/${user}`
    const prompt = (): void => term.write(`\r\n\x1b[32m${user}@${short}\x1b[0m:\x1b[34m~\x1b[0m$ `)

    term.writeln('\x1b[38;5;80mShellPilot\x1b[0m — simulated session')
    term.writeln(`Connected to \x1b[1m${server.name}\x1b[0m (${server.host}) · ${server.os}`)
    if (server.route.length) {
      term.writeln(`\x1b[90mvia ${server.route.map((h) => h.label).join(' -> ')}\x1b[0m`)
    }
    term.writeln('\x1b[90mType "help" for available commands.\x1b[0m')
    prompt()

    let line = ''
    const run = (cmd: string): void => {
      const [c, ...rest] = cmd.split(' ')
      if (c === '') return
      if (c === 'clear') return term.clear()
      if (c === 'echo') return void term.write(`\r\n${rest.join(' ')}`)
      if (c === 'whoami') return void term.write(`\r\n${user}`)
      if (c === 'pwd') return void term.write(`\r\n${home}`)
      if (c === 'uptime')
        return void term.write('\r\n 14:22:01 up 18 days,  4:21,  1 user,  load average: 0.24, 0.19, 0.14')
      if (c in MOCK) return void term.write(`\r\n${MOCK[c]}`)
      term.write(`\r\n\x1b[31m${c}: command not found\x1b[0m`)
    }

    const onInput = term.onData((data) => {
      for (const ch of data) {
        const code = ch.charCodeAt(0)
        if (ch === '\r') {
          run(line.trim())
          line = ''
          prompt()
        } else if (code === 127) {
          if (line.length) {
            line = line.slice(0, -1)
            term.write('\b \b')
          }
        } else if (code === 3) {
          term.write('^C')
          line = ''
          prompt()
        } else if (code >= 32) {
          line += ch
          term.write(ch)
        }
      }
    })

    const host = hostRef.current
    const disposeSize = observeSize(fit, host)

    return () => {
      onInput.dispose()
      disposeSize()
      disposeUX()
      term.dispose()
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [server.id])
}

function DemoTerminal({ server }: { server: Server }): React.JSX.Element {
  const hostRef = useRef<HTMLDivElement>(null)
  useDemoSession(server, hostRef)
  return (
    <div className="terminal-wrap">
      <div className="xterm-host" ref={hostRef} />
    </div>
  )
}

function RealTerminal({ server, tabId }: { server: Server; tabId?: string }): React.JSX.Element {
  const hostRef = useRef<HTMLDivElement>(null)
  const zoom = useApp((s) => s.zoomTerminal)
  const [finding, setFinding] = useState(false)
  const [pending, setPending] = useState<{ text: string; lines: number } | null>(null)
  const { termRef, searchRef, dead, reconnect } = useRealSession(
    server,
    hostRef,
    () => setFinding(true),
    (text, lines) => setPending({ text, lines }),
    tabId
  )
  return (
    <div
      className="terminal-wrap"
      // Ctrl+wheel zooms, matching every other terminal emulator.
      onWheel={(e) => {
        if (!e.ctrlKey && !e.metaKey) return
        e.preventDefault()
        zoom(e.deltaY < 0 ? 1 : -1)
      }}
    >
      <div className="xterm-host" ref={hostRef} />
      {dead && (
        <div className="term-dead">
          <div className="td-box">
            <div className="td-title">{dead}</div>
            <div className="td-sub">
              {server.username}@{server.host}:{server.port}
            </div>
            <button className="btn primary" autoFocus onClick={reconnect}>
              <RotateCw size={14} /> Reconnect
            </button>
            <div className="td-hint">
              The scrollback above is kept. Reconnecting reuses the pooled
              connection when one is still open, so it usually skips
              authentication.
            </div>
          </div>
        </div>
      )}
      {pending && (
        <PasteConfirm
          text={pending.text}
          lines={pending.lines}
          server={server.name}
          onCancel={() => setPending(null)}
          onConfirm={() => {
            termRef.current?.paste(pending.text)
            setPending(null)
            termRef.current?.focus()
          }}
        />
      )}
      {finding && (
        <TerminalSearch
          search={searchRef}
          onClose={() => {
            setFinding(false)
            termRef.current?.focus()
          }}
        />
      )}
    </div>
  )
}

export function TerminalView({ server, tabId }: { server: Server; tabId?: string }): React.JSX.Element {
  return server.demo === false ? (
    <RealTerminal server={server} tabId={tabId} />
  ) : (
    <DemoTerminal server={server} />
  )
}
