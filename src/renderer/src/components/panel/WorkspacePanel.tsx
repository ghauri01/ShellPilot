import { useEffect, useState } from 'react'
import {
  X,
  Plus,
  Copy,
  ArrowLeftToLine,
  ArrowRightToLine,
  Terminal as TerminalIcon,
  FolderOpen,
  Activity,
  SplitSquareHorizontal,
  SplitSquareVertical,
  Columns3,
  Search,
  Server as ServerIcon
} from 'lucide-react'
import { MAX_PANES, splitDirectionOf, useApp, useWorkspaceTabs } from '../../store/app'
import type { TabPanes } from '../../store/app'
import { ContextMenu, MenuEntry } from '../connections/ContextMenu'
import { clsx } from '../../lib/format'
import { EmptyState } from '../common/EmptyState'
import { TerminalView } from '../terminal/TerminalView'
import { containerTransport, localTransport, sshTransport } from '../../lib/transport'
import { LocalShellMenu } from '../terminal/LocalShellMenu'
import { PaneGrid } from './PaneGrid'
import { MonitorView } from './MonitorView'
import { MonitorStrip } from './MonitorStrip'
import { SftpView } from './SftpView'
import type { PanelView, Server, Tab } from '../../types'

const VIEWS: { id: PanelView; label: string; icon: React.ReactNode }[] = [
  { id: 'terminal', label: 'Terminal', icon: <TerminalIcon size={14} /> },
  { id: 'monitor', label: 'Monitor', icon: <Activity size={14} /> },
  { id: 'files', label: 'Files', icon: <FolderOpen size={14} /> }
]

// A single tab pane. Every view the user has opened (Terminal / Monitor /
// Files) stays mounted for the tab's lifetime — only visibility toggles — so
// the SSH shell, the SFTP browser (path/state) and the live monitor all
// survive switching views and switching between tabs. Views are mounted
// lazily: a view isn't created until it's first opened.
function TabPane({
  tab,
  server,
  tp,
  active
}: {
  tab: Tab
  server: Server | undefined
  // The tab's panes. Undefined only for a tab written into the store directly
  // rather than through one of the actions that create one — see Terminals().
  tp: TabPanes | undefined
  // Every tab stays mounted so sessions survive, so background work must be
  // gated on visibility rather than on being rendered.
  active: boolean
}): React.JSX.Element {
  const [visited, setVisited] = useState<Set<PanelView>>(() => new Set([tab.view]))
  useEffect(() => {
    setVisited((v) => (v.has(tab.view) ? v : new Set(v).add(tab.view)))
  }, [tab.view])

  // A local tab has no server and must never be handed one: Monitor, the
  // docked strip and SFTP all take a non-optional `Server` and would need a
  // synthesized row, which is exactly what the tab union exists to prevent.
  // Only the terminal is meaningful here, so it is rendered on its own rather
  // than inside the view-switching frame below.
  if (tab.kind === 'local') return <Terminals tab={tab} tp={tp} />

  if (!server) {
    return <EmptyState icon={<TerminalIcon size={26} />} title="Session unavailable" message="This server no longer exists." />
  }

  const paneStyle = (view: PanelView): React.CSSProperties => ({
    display: tab.view === view ? 'flex' : 'none',
    flexDirection: 'column',
    flex: 1,
    minHeight: 0
  })

  return (
    <>
      {visited.has('terminal') && (
        <div style={paneStyle('terminal')}>
          <Terminals tab={tab} tp={tp} />
          {/* Docked under the terminal rather than a separate view, so host
              load can be watched while working. */}
          <MonitorStrip server={server} visible={active} />
        </div>
      )}
      {visited.has('monitor') && (
        <div style={paneStyle('monitor')}>
          <MonitorView server={server} visible={active && tab.view === 'monitor'} />
        </div>
      )}
      {visited.has('files') && (
        <div style={paneStyle('files')}>
          <SftpView server={server} tabId={tab.id} />
        </div>
      )}
    </>
  )
}

// The terminal half of a tab: its panes, or — for a tab that somehow has none —
// the single-pane rendering this file had before panes existed.
//
// The fallback is unreachable through the store, which mints `panes[tab.id]` in
// every action that creates a tab. It exists so that a tab written straight into
// state (a test, or a future session-restore path) still shows a working
// terminal instead of a blank rectangle; it just cannot be split, and its
// session is keyed by the tab id rather than a pane id.
function Terminals({ tab, tp }: { tab: Tab; tp: TabPanes | undefined }): React.JSX.Element {
  const servers = useApp((s) => s.servers)
  const localShells = useApp((s) => s.localShells)
  const setServerStatus = useApp((s) => s.setServerStatus)

  if (tp) return <PaneGrid tabId={tab.id} tp={tp} />

  if (tab.kind === 'local') {
    const shell = localShells.find((sh) => sh.id === tab.shellId)
    if (!shell) {
      return (
        <EmptyState
          icon={<TerminalIcon size={26} />}
          title="Session unavailable"
          message="This shell is no longer available on this machine."
        />
      )
    }
    return <TerminalView transport={localTransport(shell, tab.cwd)} tabId={tab.id} />
  }
  const server = servers.find((sv) => sv.id === tab.serverId)
  if (!server) {
    return <EmptyState icon={<TerminalIcon size={26} />} title="Session unavailable" message="This server no longer exists." />
  }
  // A demo server has no transport: TerminalView falls through to the
  // simulated shell, which is what `server` is still passed for.
  const transport =
    server.demo === false
      ? tab.containerRef
        ? containerTransport(server, tab.containerRef, setServerStatus, tab.containerSudo === true)
        : sshTransport(server, setServerStatus)
      : undefined
  return <TerminalView transport={transport} server={server} tabId={tab.id} />
}

export function WorkspacePanel(): React.JSX.Element {
  // Tabs shown in the bar: this workspace only.
  const tabs = useWorkspaceTabs()
  // Every tab in every workspace stays mounted, so switching workspace does
  // not tear down a session and kill whatever command is running in it.
  const allTabs = useApp((s) => s.tabs)
  const activeTabId = useApp((s) => s.activeTabId)
  const setActiveTab = useApp((s) => s.setActiveTab)
  const closeTab = useApp((s) => s.closeTab)
  const setTabView = useApp((s) => s.setTabView)
  const setModal = useApp((s) => s.setModal)
  const newSession = useApp((s) => s.newSession)
  const openLocalById = useApp((s) => s.openLocalById)
  const duplicateTab = useApp((s) => s.duplicateTab)
  const closeOtherTabs = useApp((s) => s.closeOtherTabs)
  const closeTabsToLeft = useApp((s) => s.closeTabsToLeft)
  const closeTabsToRight = useApp((s) => s.closeTabsToRight)
  const closeAllTabs = useApp((s) => s.closeAllTabs)
  const servers = useApp((s) => s.servers)
  const localShells = useApp((s) => s.localShells)
  const active = tabs.find((t) => t.id === activeTabId) ?? null
  const panes = useApp((s) => s.panes)
  const toggleSplit = useApp((s) => s.toggleSplit)
  const splitPane = useApp((s) => s.splitPane)
  const [tabMenu, setTabMenu] = useState<{ x: number; y: number; tabId: string } | null>(null)

  const server = active?.kind === 'ssh' ? servers.find((s) => s.id === active.serverId) : undefined
  // Null while the tab holds a single pane: `TabPanes.direction` always holds a
  // letter, but there is no split to highlight until there are two panes. This
  // is the replacement for reading `tabSplit[id]`, which is gone.
  const activeSplit = splitDirectionOf(panes, active?.id)
  const activePaneCount = active ? panes[active.id]?.panes.length ?? 1 : 1
  const atPaneCap = activePaneCount >= MAX_PANES
  // What the viewbar says the tab is talking to. An SSH tab names the account;
  // a local one names the shell it started, which is the only comparable fact
  // and the one the dead-session overlay shows too.
  const activeShellPath =
    active?.kind === 'local'
      ? localShells.find((sh) => sh.id === active.shellId)?.path
      : undefined
  // A new session on whatever the current tab is: another shell on the same
  // server, another shell of the same kind on this machine, or — with no tab
  // at all — the only thing left to offer, which is adding a server.
  const addTab = (): void => {
    if (active?.kind === 'ssh') newSession(active.serverId)
    else if (active?.kind === 'local') openLocalById(active.shellId, active.cwd)
    else setModal('add-server')
  }

  const tabMenuEntries = (tabId: string): MenuEntry[] => {
    const idx = tabs.findIndex((t) => t.id === tabId)
    return [
      { label: 'Duplicate Tab', icon: <Copy size={14} />, onClick: () => duplicateTab(tabId) },
      { separator: true, label: '' },
      { label: 'Close', icon: <X size={14} />, onClick: () => closeTab(tabId) },
      {
        label: 'Close Others',
        icon: <X size={14} />,
        disabled: tabs.length < 2,
        onClick: () => closeOtherTabs(tabId)
      },
      {
        label: 'Close All to the Left',
        icon: <ArrowLeftToLine size={14} />,
        disabled: idx <= 0,
        onClick: () => closeTabsToLeft(tabId)
      },
      {
        label: 'Close All to the Right',
        icon: <ArrowRightToLine size={14} />,
        disabled: idx === tabs.length - 1,
        onClick: () => closeTabsToRight(tabId)
      },
      { separator: true, label: '' },
      { label: 'Close All Tabs', icon: <X size={14} />, danger: true, onClick: () => closeAllTabs() }
    ]
  }

  return (
    <div className="main">
      <div className="tabbar">
        {tabs.map((t) => {
          const srv = t.kind === 'ssh' ? servers.find((s) => s.id === t.serverId) : undefined
          return (
            <div
              key={t.id}
              className={clsx('tab', t.id === activeTabId && 'active')}
              onClick={() => setActiveTab(t.id)}
              onAuxClick={(e) => e.button === 1 && closeTab(t.id)}
              onContextMenu={(e) => {
                e.preventDefault()
                setTabMenu({ x: e.clientX, y: e.clientY, tabId: t.id })
              }}
            >
              {srv && <span className={clsx('status-dot', srv.status)} />}
              <span className="title">{t.title}</span>
              <button
                className="close"
                onClick={(e) => {
                  e.stopPropagation()
                  closeTab(t.id)
                }}
              >
                <X size={13} />
              </button>
            </div>
          )
        })}
        {/* A split button: the plus repeats whatever the current tab is, the
            caret opens the list of shells on this machine. */}
        <button className="tab-new" title="New session" onClick={addTab}>
          <Plus size={16} />
        </button>
        <LocalShellMenu />
      </div>

      {tabMenu && (
        <ContextMenu
          x={tabMenu.x}
          y={tabMenu.y}
          entries={tabMenuEntries(tabMenu.tabId)}
          onClose={() => setTabMenu(null)}
        />
      )}

      {/* The viewbar used to be gated on `active && server`, which left a local
          tab with no viewbar and therefore no split controls. The three-view
          segment is the only SSH-only half; the split controls belong to any
          terminal. An SSH tab whose server is gone still shows nothing, which is
          the case the old condition was actually covering. */}
      {active && (active.kind === 'local' || server) && (
        <div className="viewbar">
          {active.kind === 'ssh' && (
            <div className="segment">
              {VIEWS.map((v) => (
                <button
                  key={v.id}
                  className={clsx('seg-btn', active.view === v.id && 'active')}
                  onClick={() => setTabView(active.id, v.id)}
                >
                  {v.icon} {v.label}
                </button>
              ))}
            </div>
          )}
          <span className="spacer" />
          <div className="server-meta mono">
            {server ? `${server.username}@${server.host}:${server.port}` : activeShellPath ?? ''}
          </div>
          {active.view === 'terminal' && (
            <div className="row" style={{ gap: 2 }}>
              <button className="icon-btn" title="Search">
                <Search size={15} />
              </button>
              <button
                className={clsx('icon-btn', activeSplit === 'v' && 'active')}
                title="Split vertical"
                onClick={() => toggleSplit(active.id, 'v')}
              >
                <SplitSquareHorizontal size={15} />
              </button>
              <button
                className={clsx('icon-btn', activeSplit === 'h' && 'active')}
                title="Split horizontal"
                onClick={() => toggleSplit(active.id, 'h')}
              >
                <SplitSquareVertical size={15} />
              </button>
              {/* The two buttons above are toggles — they take a tab between
                  one pane and two, which is the contract they have always had.
                  Panes three and four are reachable only from here, and the cap
                  is shown as a disabled button rather than enforced silently
                  when it is pressed. */}
              <button
                className="icon-btn"
                disabled={atPaneCap}
                title={
                  atPaneCap
                    ? `Maximum of ${MAX_PANES} panes per tab`
                    : 'Add a pane on the same target'
                }
                onClick={() => splitPane(active.id, activeSplit ?? 'v')}
              >
                <Columns3 size={15} />
              </button>
            </div>
          )}
        </div>
      )}

      <div className="panel-body">
        {/* Rendered inline rather than as an early return: returning early
            would unmount every pane, killing sessions in other workspaces. */}
        {tabs.length === 0 && (
          <EmptyState
            icon={<ServerIcon size={26} />}
            title="No open sessions"
            message="Select a server from the sidebar to open a terminal, or add your first connection to get started."
            action={
              <button className="btn primary" onClick={() => setModal('add-server')}>
                <Plus size={15} /> Add Server
              </button>
            }
          />
        )}
        {allTabs.map((t) => (
          <div
            key={t.id}
            className="tab-pane"
            style={{ display: t.id === activeTabId ? 'flex' : 'none' }}
          >
            <TabPane
              tab={t}
              server={t.kind === 'ssh' ? servers.find((s) => s.id === t.serverId) : undefined}
              tp={panes[t.id]}
              active={t.id === activeTabId}
            />
          </div>
        ))}
      </div>
    </div>
  )
}
