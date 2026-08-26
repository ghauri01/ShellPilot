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
  Search,
  Server as ServerIcon
} from 'lucide-react'
import { useApp, useWorkspaceTabs } from '../../store/app'
import type { TabSplit } from '../../store/app'
import { ContextMenu, MenuEntry } from '../connections/ContextMenu'
import { clsx } from '../../lib/format'
import { EmptyState } from '../common/EmptyState'
import { TerminalView } from '../terminal/TerminalView'
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
  split,
  active
}: {
  tab: Tab
  server: Server | undefined
  split: TabSplit
  // Every tab stays mounted so sessions survive, so background work must be
  // gated on visibility rather than on being rendered.
  active: boolean
}): React.JSX.Element {
  const [visited, setVisited] = useState<Set<PanelView>>(() => new Set([tab.view]))
  useEffect(() => {
    setVisited((v) => (v.has(tab.view) ? v : new Set(v).add(tab.view)))
  }, [tab.view])

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
          {split ? (
            <div className="splits" style={{ flexDirection: split === 'h' ? 'column' : 'row' }}>
              <div className="split-pane">
                <TerminalView server={server} tabId={tab.id} />
              </div>
              <div className="split-pane">
                <TerminalView server={server} />
              </div>
            </div>
          ) : (
            <TerminalView server={server} tabId={tab.id} />
          )}
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
  const duplicateTab = useApp((s) => s.duplicateTab)
  const closeOtherTabs = useApp((s) => s.closeOtherTabs)
  const closeTabsToLeft = useApp((s) => s.closeTabsToLeft)
  const closeTabsToRight = useApp((s) => s.closeTabsToRight)
  const closeAllTabs = useApp((s) => s.closeAllTabs)
  const servers = useApp((s) => s.servers)
  const active = tabs.find((t) => t.id === activeTabId) ?? null
  const splits = useApp((s) => s.tabSplit)
  const toggleSplit = useApp((s) => s.toggleSplit)
  const [tabMenu, setTabMenu] = useState<{ x: number; y: number; tabId: string } | null>(null)

  const server = active ? servers.find((s) => s.id === active.serverId) : undefined
  const activeSplit = active ? splits[active.id] ?? null : null
  const addTab = (): void => {
    if (active?.serverId) newSession(active.serverId)
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
          const srv = servers.find((s) => s.id === t.serverId)
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
        <button className="tab-new" title="New session" onClick={addTab}>
          <Plus size={16} />
        </button>
      </div>

      {tabMenu && (
        <ContextMenu
          x={tabMenu.x}
          y={tabMenu.y}
          entries={tabMenuEntries(tabMenu.tabId)}
          onClose={() => setTabMenu(null)}
        />
      )}

      {active && server && (
        <div className="viewbar">
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
          <span className="spacer" />
          <div className="server-meta mono">
            {server.username}@{server.host}:{server.port}
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
              server={servers.find((s) => s.id === t.serverId)}
              split={splits[t.id] ?? null}
              active={t.id === activeTabId}
            />
          </div>
        ))}
      </div>
    </div>
  )
}
