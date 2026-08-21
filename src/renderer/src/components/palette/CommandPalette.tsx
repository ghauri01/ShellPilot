import { useMemo, useRef, useState, useEffect } from 'react'
import {
  Search,
  Server as ServerIcon,
  Network,
  Layers,
  Settings,
  Plus,
  Copy,
  Terminal as TerminalIcon,
  Activity,
  Download,
  CornerDownLeft
} from 'lucide-react'
import { useApp } from '../../store/app'
import { useClickOutside } from '../../hooks/useClickOutside'

interface Cmd {
  id: string
  group: string
  title: string
  sub?: string
  icon: React.ReactNode
  run: () => void
}

export function CommandPalette(): React.JSX.Element {
  const store = useApp()
  const close = (): void => store.togglePalette(false)
  const ref = useRef<HTMLDivElement>(null)
  const inputRef = useRef<HTMLInputElement>(null)
  useClickOutside(ref, close)

  const [q, setQ] = useState('')
  const [idx, setIdx] = useState(0)

  useEffect(() => {
    inputRef.current?.focus()
  }, [])

  const commands = useMemo<Cmd[]>(() => {
    const list: Cmd[] = []
    store.workspaces
      .filter((w) => !w.hidden)
      .forEach((w) =>
        list.push({
          id: `ws-${w.id}`,
          group: 'Workspaces',
          title: w.name,
          sub: 'Switch workspace',
          icon: <Layers size={16} />,
          run: () => store.setWorkspace(w.id)
        })
      )
    store
      .workspaceServers()
      .forEach((s) =>
        list.push({
          id: `s-${s.id}`,
          group: 'Servers',
          title: s.name,
          sub: `${s.username}@${s.host}`,
          icon: <ServerIcon size={16} />,
          run: () => {
            store.setActivity('connections')
            store.openServer(s.id, 'terminal')
          }
        })
      )
    store
      .workspaceTunnels()
      .forEach((t) =>
        list.push({
          id: `t-${t.id}`,
          group: 'Tunnels',
          title: t.name,
          sub: `${t.listen} → ${t.target}`,
          icon: <Network size={16} />,
          run: () => store.setActivity('tunnels')
        })
      )

    const current = store.activeTab()
    const actions: Cmd[] = [
      // Opening a server from here focuses its existing tab, so duplicating is
      // the way to get a second session on the same box from the palette.
      ...(current
        ? [
            {
              id: 'a-dup',
              group: 'Actions',
              title: 'Duplicate Current Tab',
              sub: current.title,
              icon: <Copy size={16} />,
              run: () => store.duplicateTab(current.id)
            }
          ]
        : []),
      { id: 'a-add', group: 'Actions', title: 'Add Server', icon: <Plus size={16} />, run: () => store.setModal('add-server') },
      { id: 'a-ws', group: 'Actions', title: 'New Workspace', icon: <Plus size={16} />, run: () => store.setModal('workspaces') },
      { id: 'a-mon', group: 'Actions', title: 'Open Fleet Monitor', icon: <Activity size={16} />, run: () => store.setActivity('monitor') },
      { id: 'a-term', group: 'Actions', title: 'Open Connections', icon: <TerminalIcon size={16} />, run: () => store.setActivity('connections') },
      {
        id: 'a-import',
        group: 'Actions',
        title: 'Import Servers from ~/.ssh/config',
        sub: 'Bulk-import hosts you already have, ProxyJump included',
        icon: <Download size={16} />,
        run: () => {
          store.setActivity('connections')
          store.setModal('import-ssh')
        }
      },
      { id: 'a-set', group: 'Settings', title: 'Open Settings', icon: <Settings size={16} />, run: () => store.setActivity('settings') }
    ]
    return [...actions, ...list]
  }, [store])

  const filtered = useMemo(() => {
    const query = q.trim().toLowerCase()
    if (!query) return commands
    return commands.filter(
      (c) => c.title.toLowerCase().includes(query) || c.sub?.toLowerCase().includes(query) || c.group.toLowerCase().includes(query)
    )
  }, [q, commands])

  useEffect(() => setIdx(0), [q])

  const exec = (c?: Cmd): void => {
    if (!c) return
    c.run()
    close()
  }

  const onKey = (e: React.KeyboardEvent): void => {
    if (e.key === 'ArrowDown') {
      e.preventDefault()
      setIdx((i) => Math.min(filtered.length - 1, i + 1))
    } else if (e.key === 'ArrowUp') {
      e.preventDefault()
      setIdx((i) => Math.max(0, i - 1))
    } else if (e.key === 'Enter') {
      e.preventDefault()
      exec(filtered[idx])
    }
  }

  // group rendering
  let lastGroup = ''

  return (
    <div className="palette-scrim">
      <div className="palette" ref={ref}>
        <div className="palette-input">
          <Search size={18} className="faint" />
          <input
            ref={inputRef}
            value={q}
            onChange={(e) => setQ(e.target.value)}
            onKeyDown={onKey}
            placeholder="Search servers, workspaces, tunnels, actions…"
          />
          <span className="kbd">Esc</span>
        </div>
        <div className="palette-list">
          {filtered.length === 0 && <div className="palette-empty">No results for “{q}”</div>}
          {filtered.map((c, i) => {
            const showGroup = c.group !== lastGroup
            lastGroup = c.group
            return (
              <div key={c.id}>
                {showGroup && <div className="palette-group">{c.group}</div>}
                <div
                  className={`palette-item${i === idx ? ' active' : ''}`}
                  onMouseEnter={() => setIdx(i)}
                  onClick={() => exec(c)}
                >
                  <span className="p-icon">{c.icon}</span>
                  <span className="p-title">{c.title}</span>
                  {c.sub && <span className="p-sub">{c.sub}</span>}
                  <span className="spacer" />
                  {i === idx && <CornerDownLeft size={14} className="faint" />}
                </div>
              </div>
            )
          })}
        </div>
      </div>
    </div>
  )
}
