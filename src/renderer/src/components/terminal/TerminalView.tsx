import { useEffect, useRef, useState } from 'react'
import { RotateCw, Terminal as TerminalIcon } from 'lucide-react'
import { TerminalSearch } from './TerminalSearch'
import { PasteConfirm } from './PasteConfirm'
import { EmptyState } from '../common/EmptyState'
import { useApp } from '../../store/app'
import {
  createTerm,
  observeSize,
  setupTerminalUX,
  useTerminalSession
} from '../../hooks/useTerminalSession'
import type { TerminalTransport } from '../../lib/transport'
import type { Server } from '../../types'

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

// ---- Real session ----------------------------------------------------------
function RealTerminal({
  transport,
  tabId
}: {
  transport: TerminalTransport
  tabId?: string
}): React.JSX.Element {
  const hostRef = useRef<HTMLDivElement>(null)
  const zoom = useApp((s) => s.zoomTerminal)
  const [finding, setFinding] = useState(false)
  const [pending, setPending] = useState<{ text: string; lines: number } | null>(null)
  const { termRef, searchRef, dead, reconnect } = useTerminalSession(
    transport,
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
            <div className="td-sub">{transport.subtitle}</div>
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
          server={transport.title}
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

// A terminal is either driven by a transport (SSH or a local pty — this
// component does not care which) or, for a demo server, by the simulated
// shell. Callers that have a real target must pass a transport: an SSH tab
// with no transport is a bug in the caller, not a demo session.
export function TerminalView({
  transport,
  server,
  tabId
}: {
  transport?: TerminalTransport
  // Only for the demo path, which is still keyed on a Server.
  server?: Server
  tabId?: string
}): React.JSX.Element {
  if (transport) return <RealTerminal transport={transport} tabId={tabId} />
  if (server && server.demo !== false) return <DemoTerminal server={server} />
  return (
    <EmptyState
      icon={<TerminalIcon size={26} />}
      title="Session unavailable"
      message="This session has no transport."
    />
  )
}
