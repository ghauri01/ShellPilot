import { X, Terminal as TerminalIcon } from 'lucide-react'
import { useApp } from '../../store/app'
import type { Pane, PaneTarget, TabPanes } from '../../store/app'
import { clsx } from '../../lib/format'
import { EmptyState } from '../common/EmptyState'
import { TerminalView } from '../terminal/TerminalView'
import { localTransport, sshTransport } from '../../lib/transport'
import type { TerminalTransport } from '../../lib/transport'
import type { Server } from '../../types'

// The N panes of one tab, laid out along a single axis.
//
// Replaces the hard-coded two-pane block this file was extracted from, which
// gave the second pane no `tabId` — so its OSC-7 cwd and its session id went
// nowhere and SFTP could only ever follow the first one.
//
// Two things here are load-bearing and easy to undo by accident:
//
//  - **The React key is the pane id, minted by the store.** It is what keeps the
//    xterm instance and its scrollback alive across a re-render, a re-orient and
//    a sibling being closed. An id derived during render would rebuild every
//    terminal on every render.
//  - **The grid is rendered even for a single pane.** Wrapping the lone terminal
//    in the same `.splits`/`.split-pane` markup a split one uses means splitting
//    and un-splitting moves nothing in the DOM around the surviving pane, so its
//    session survives. Rendering the terminal bare when unsplit and wrapped when
//    split would remount it on every toggle.
export function PaneGrid({ tabId, tp }: { tabId: string; tp: TabPanes }): React.JSX.Element {
  const servers = useApp((s) => s.servers)
  const localShells = useApp((s) => s.localShells)
  const setServerStatus = useApp((s) => s.setServerStatus)
  const setActivePane = useApp((s) => s.setActivePane)
  const closePane = useApp((s) => s.closePane)

  // Transports are deliberately rebuilt on every render. Both effects in
  // useTerminalSession key on `transport.key`, never on the object, so identity
  // churn costs nothing — and memoising it would only hide the fact that the
  // key, not the reference, is what a session's lifetime is tied to.
  const resolve = (target: PaneTarget): { transport?: TerminalTransport; server?: Server } => {
    if (target.kind === 'local') {
      const shell = localShells.find((sh) => sh.id === target.shellId)
      return shell ? { transport: localTransport(shell, target.cwd) } : {}
    }
    const server = servers.find((sv) => sv.id === target.serverId)
    if (!server) return {}
    // A demo server has no transport: TerminalView falls through to the
    // simulated shell, which is the one case `server` is still passed for.
    return server.demo === false
      ? { transport: sshTransport(server, setServerStatus), server }
      : { server }
  }

  const single = tp.panes.length < 2

  return (
    <div className="splits" style={{ flexDirection: tp.direction === 'h' ? 'column' : 'row' }}>
      {tp.panes.map((p) => (
        <div
          key={p.id}
          className={clsx('split-pane', !single && p.id === tp.activePaneId && 'active')}
          // mousedown rather than click: focus should follow the press that put
          // the cursor in the terminal, before xterm swallows the event.
          onMouseDown={() => setActivePane(tabId, p.id)}
          style={{
            position: 'relative',
            display: 'flex',
            flexDirection: 'column',
            minHeight: 0,
            // Only meaningful with a sibling to distinguish it from, and drawn
            // inside the pane so it costs no layout.
            outline: !single && p.id === tp.activePaneId ? '1px solid var(--accent)' : undefined,
            outlineOffset: '-1px'
          }}
        >
          {!single && (
            <button
              className="icon-btn"
              title="Close pane"
              aria-label="Close pane"
              // Sits over the terminal, so it carries its own background rather
              // than relying on whatever character happens to be underneath it.
              style={{
                position: 'absolute',
                top: 4,
                right: 6,
                zIndex: 15,
                background: 'var(--bg-panel)'
              }}
              onClick={(e) => {
                e.stopPropagation()
                closePane(tabId, p.id)
              }}
            >
              <X size={13} />
            </button>
          )}
          <PaneBody pane={p} resolve={resolve} />
        </div>
      ))}
    </div>
  )
}

function PaneBody({
  pane,
  resolve
}: {
  pane: Pane
  resolve: (t: PaneTarget) => { transport?: TerminalTransport; server?: Server }
}): React.JSX.Element {
  const { transport, server } = resolve(pane.target)
  if (!transport && !server) {
    return (
      <EmptyState
        icon={<TerminalIcon size={26} />}
        title="Session unavailable"
        message={
          pane.target.kind === 'local'
            ? 'This shell is no longer available on this machine.'
            : 'This server no longer exists.'
        }
      />
    )
  }
  // `tabId` is the prop's name, but a **pane** id is what it is given: it is the
  // key `tabSession`/`tabCwd` are written under, and a session belongs to a
  // pane. SftpView reads the active pane's entry back out through the same key.
  return <TerminalView transport={transport} server={server} tabId={pane.id} />
}
