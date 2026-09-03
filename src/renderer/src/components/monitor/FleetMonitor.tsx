import { useEffect, useMemo, useState } from 'react'
import {
  Activity,
  ChevronRight,
  Cpu,
  FolderPlus,
  HardDrive,
  MemoryStick,
  Server as ServerIcon,
  Trash2
} from 'lucide-react'
import { useApp, useWorkspaceMonitorGroups, useWorkspaceServers } from '../../store/app'
import { EmptyState } from '../common/EmptyState'
import { ServerMonitorCard } from './ServerMonitorCard'
import { fleetTotals, useFleet } from '../../store/fleet'
import { bridgeHas } from '../../lib/bridge'
import { bytes, clsx } from '../../lib/format'
import type { MonitorGroup, Server } from '../../types'
import { FleetHealth } from './FleetHealth'
import { FleetSearch } from './FleetSearch'
import { InventoryPanel } from './InventoryPanel'
import { BroadcastPanel } from './BroadcastPanel'
import { LogTailPanel } from './LogTailPanel'
import { CronPanel } from './CronPanel'
import { MODULES, moduleEnabled, type ModuleDef, type ModuleId } from '../../../../shared/modules'
import { openSettings } from '../../store/nav'
import { DockerPanel } from '../docker/DockerPanel'
import { KubernetesPanel } from '../kubernetes/KubernetesPanel'

function pct(used: number, total: number): number {
  return total > 0 ? (used / total) * 100 : 0
}

// What is being dragged, and where it would land. Cards and groups share one
// drag state because a card can be dropped on a group header and a group can
// be dropped between groups — keeping two would let both highlight at once.
type Drag = { kind: 'card'; id: string } | { kind: 'group'; id: string } | null
type DropAt = { groupId: string; index: number } | null

function GroupSection({
  group,
  index,
  cards,
  drag,
  dropAt,
  groupDrop,
  setDrag,
  setDropAt,
  setGroupDrop,
  commit
}: {
  group: MonitorGroup
  index: number
  cards: Server[]
  drag: Drag
  dropAt: DropAt
  groupDrop: number | null
  setDrag: (d: Drag) => void
  setDropAt: (d: DropAt) => void
  setGroupDrop: (i: number | null) => void
  commit: () => void
}): React.JSX.Element {
  const openServer = useApp((s) => s.openServer)
  const toggleMonitorGroup = useApp((s) => s.toggleMonitorGroup)
  const renameMonitorGroup = useApp((s) => s.renameMonitorGroup)
  const deleteMonitorGroup = useApp((s) => s.deleteMonitorGroup)
  const [renaming, setRenaming] = useState(false)

  const draggingCard = drag?.kind === 'card'
  const draggingGroup = drag?.kind === 'group'

  // A slot opens where the card would land. Rendered as a real grid item so
  // the surrounding cards move aside instead of the drop being a guess.
  const slotAt = (i: number): React.JSX.Element | null =>
    draggingCard && dropAt?.groupId === group.id && dropAt.index === i ? (
      <div
        key={`slot-${i}`}
        className="card-slot"
        // Hovering the slot must hold the position it is already showing.
        // Without this the event reaches the grid, which reads any uncovered
        // space as "drop at the end", and the gap jumps away from the cursor.
        onDragOver={(e) => {
          e.preventDefault()
          e.stopPropagation()
        }}
        onDrop={(e) => {
          e.preventDefault()
          e.stopPropagation()
          commit()
        }}
      />
    ) : null

  return (
    <section className={clsx('monitor-group', groupDrop === index && 'group-dragover')}>
      <div
        className={clsx('mg-head', draggingCard && dropAt?.groupId === group.id && 'dragover')}
        draggable={!group.system && !renaming}
        onDragStart={() => !group.system && setDrag({ kind: 'group', id: group.id })}
        onDragEnd={() => {
          setDrag(null)
          setDropAt(null)
          setGroupDrop(null)
        }}
        onDragOver={(e) => {
          if (draggingGroup && !group.system) {
            e.preventDefault()
            setGroupDrop(index)
            return
          }
          // Dropping a card on the header files it at the end of the group,
          // which is the only way to reach a collapsed one.
          if (draggingCard) {
            e.preventDefault()
            setDropAt({ groupId: group.id, index: cards.length })
          }
        }}
        onDrop={(e) => {
          e.preventDefault()
          commit()
        }}
        onClick={() => !renaming && toggleMonitorGroup(group.id)}
        onDoubleClick={() => !group.system && setRenaming(true)}
      >
        <ChevronRight size={15} className={clsx('chev', !group.collapsed && 'open')} />
        {renaming ? (
          <input
            className="mg-rename"
            autoFocus
            defaultValue={group.name}
            onClick={(e) => e.stopPropagation()}
            onBlur={(e) => {
              const v = e.target.value.trim()
              if (v) renameMonitorGroup(group.id, v)
              setRenaming(false)
            }}
            onKeyDown={(e) => {
              if (e.key === 'Enter') e.currentTarget.blur()
              if (e.key === 'Escape') setRenaming(false)
            }}
          />
        ) : (
          <span className="mg-name">{group.name}</span>
        )}
        <span className="count">{cards.length}</span>
        <span className="grow" />
        {!group.system && !renaming && (
          <button
            className="icon-btn xs"
            title="Delete group — its cards move back to Ungrouped"
            onClick={(e) => {
              e.stopPropagation()
              deleteMonitorGroup(group.id)
            }}
          >
            <Trash2 size={13} />
          </button>
        )}
      </div>

      {!group.collapsed && (
        <div
          className="monitor"
          onDragOver={(e) => {
            if (!draggingCard) return
            e.preventDefault()
            setDropAt({ groupId: group.id, index: cards.length })
          }}
          onDrop={(e) => {
            e.preventDefault()
            commit()
          }}
        >
          {cards.map((s, i) => (
            <div key={s.id} style={{ display: 'contents' }}>
              {slotAt(i)}
              <div
                className={clsx('card-drag', drag?.kind === 'card' && drag.id === s.id && 'dragging')}
                draggable
                onDragStart={() => setDrag({ kind: 'card', id: s.id })}
                onDragEnd={() => {
                  setDrag(null)
                  setDropAt(null)
                }}
                onDragOver={(e) => {
                  if (!draggingCard) return
                  e.preventDefault()
                  // Left half of a card means "before it", right half "after".
                  e.stopPropagation()
                  const r = e.currentTarget.getBoundingClientRect()
                  const after = e.clientX > r.left + r.width / 2
                  setDropAt({ groupId: group.id, index: after ? i + 1 : i })
                }}
                onDrop={(e) => {
                  e.preventDefault()
                  e.stopPropagation()
                  commit()
                }}
              >
                <ServerMonitorCard server={s} onOpen={() => openServer(s.id, 'monitor')} />
              </div>
            </div>
          ))}
          {slotAt(cards.length)}
          {cards.length === 0 && (
            <div className="mg-empty">Drag cards here</div>
          )}
        </div>
      )}
    </section>
  )
}

export function FleetMonitor(): React.JSX.Element {
  const servers = useWorkspaceServers()
  const openServerTab = useApp((s) => s.openServer)
  // A disabled module is one more branch, not a new mechanism — the same way
  // the activity bar and viewbar already hide what does not apply.
  const modules = useApp((s) => s.settings.modules)

  // Sub-navigation, added after looking at the composite rather than at each
  // panel on its own.
  //
  // Every module built today appended a panel to this page. With all of them on
  // that was five stacked forms ABOVE the health summary and the server cards —
  // so the thing the page is named for sat below four tools nobody was using at
  // that moment, and the first screen was a wall of inputs. Each panel was
  // reasonable; the page was not.
  //
  // Panels stay MOUNTED and are hidden rather than unmounted. A running
  // broadcast or an open log tail must survive looking at the overview — and
  // LogTailPanel stops its remote command on unmount, so switching tab would
  // otherwise kill a tail the user is in the middle of reading.
  const [tab, setTab] = useState<'overview' | ModuleId>('overview')
  const tabs = useMemo<ModuleDef[]>(
    () => MODULES.filter((m) => moduleEnabled(modules, m.id)),
    [modules]
  )
  // A module switched off while its tab is open would otherwise leave the page
  // blank with no way back.
  const activeTab = tab === 'overview' || tabs.some((t) => t.id === tab) ? tab : 'overview'
  const show = (id: 'overview' | ModuleId): React.CSSProperties | undefined =>
    activeTab === id ? undefined : { display: 'none' }
  const groups = useWorkspaceMonitorGroups()
  const hosts = useFleet((s) => s.hosts)
  const workspaceId = useApp((s) => s.activeWorkspaceId)
  const syncMonitorLayout = useApp((s) => s.syncMonitorLayout)
  const moveMonitorCard = useApp((s) => s.moveMonitorCard)
  const moveMonitorGroup = useApp((s) => s.moveMonitorGroup)
  const addMonitorGroup = useApp((s) => s.addMonitorGroup)

  const [drag, setDrag] = useState<Drag>(null)
  const [dropAt, setDropAt] = useState<DropAt>(null)
  const [groupDrop, setGroupDrop] = useState<number | null>(null)

  // Files newly added servers onto the wall and drops ones that are gone.
  // Keyed on the server set and the workspace, and a no-op when the layout is
  // already right, so it cannot loop with its own state update.
  const serverIds = servers.map((s) => s.id).join(',')
  useEffect(() => {
    syncMonitorLayout()
  }, [serverIds, workspaceId, syncMonitorLayout])

  // Sweep the estate now that somebody is looking at it, so the health panel
  // is not showing whatever the last scheduled sweep found up to a couple of
  // minutes ago. Once per mount: the background interval owns the cadence from
  // here, and re-requesting on every server edit would be a full sweep per
  // keystroke in the rename box.
  useEffect(() => {
    if (!bridgeHas(window.shellpilot?.fleet as Record<string, unknown> | undefined, 'sampleNow')) {
      return
    }
    void window.shellpilot?.fleet?.sampleNow()
  }, [])

  const online = servers.filter((s) => s.status === 'online').length
  const totals = fleetTotals(
    servers.map((s) => s.id),
    hosts
  )

  const commit = (): void => {
    if (drag?.kind === 'card' && dropAt) moveMonitorCard(drag.id, dropAt.groupId, dropAt.index)
    if (drag?.kind === 'group' && groupDrop !== null) moveMonitorGroup(drag.id, groupDrop)
    setDrag(null)
    setDropAt(null)
    setGroupDrop(null)
  }

  if (servers.length === 0) {
    return (
      <div className="panel-body">
        <EmptyState
          icon={<Activity size={26} />}
          title="Nothing to monitor"
          message="Add a server to start streaming live CPU, memory, disk and network metrics."
        />
      </div>
    )
  }

  const byId = new Map(servers.map((s) => [s.id, s]))

  return (
    <div className="content">
      <div className="content-header">
        <div>
          <h1>Fleet Monitor</h1>
          <div className="sub">
            {online} of {servers.length} servers online · live metrics
          </div>
        </div>
        <span className="spacer" />
        <button className="btn ghost" onClick={() => addMonitorGroup('New group')}>
          <FolderPlus size={14} /> New group
        </button>
      </div>

      {/* Correctly switching every new module off on upgrade has a cost: the
          user sees nothing new and has no reason to look for it. One line,
          shown only when they are ALL off, rather than a per-module nag that
          would teach people to ignore this row. */}
      {tabs.length === 0 && (
        <div className="s-desc" style={{ marginBottom: 12 }}>
          Search, estate inventory, running a command across servers, log tailing, scheduled
          jobs, Docker and Kubernetes are available and switched off.{' '}
          <button className="btn ghost sm" onClick={() => openSettings('modules')}>
            Choose modules
          </button>
        </div>
      )}

      {tabs.length > 0 && (
        <div className="segment monitor-tabs">
          <button
            className={clsx('seg-btn', activeTab === 'overview' && 'active')}
            onClick={() => setTab('overview')}
          >
            Overview
          </button>
          {tabs.map((m) => (
            <button
              key={m.id}
              className={clsx('seg-btn', activeTab === m.id && 'active')}
              onClick={() => setTab(m.id)}
            >
              {m.label}
            </button>
          ))}
        </div>
      )}

      {moduleEnabled(modules, 'fleetSearch') && (
        <div style={show('fleetSearch')}>
          <FleetSearch servers={servers} onOpen={(id) => openServerTab(id, 'monitor')} />
        </div>
      )}
      {moduleEnabled(modules, 'inventory') && (
        <div style={show('inventory')}>
          <InventoryPanel servers={servers} onOpen={(id) => openServerTab(id, 'monitor')} />
        </div>
      )}
      {moduleEnabled(modules, 'broadcast') && (
        <div style={show('broadcast')}>
          <BroadcastPanel servers={servers} />
        </div>
      )}
      {moduleEnabled(modules, 'logTail') && (
        <div style={show('logTail')}>
          <LogTailPanel servers={servers} />
        </div>
      )}
      {moduleEnabled(modules, 'cron') && (
        <div style={show('cron')}>
          <CronPanel servers={servers} />
        </div>
      )}
      {moduleEnabled(modules, 'docker') && (
        <div style={show('docker')}>
          <DockerPanel servers={servers} />
        </div>
      )}
      {moduleEnabled(modules, 'kubernetes') && (
        <div style={show('kubernetes')}>
          <KubernetesPanel servers={servers} />
        </div>
      )}

      <div style={show('overview')}>
        <FleetHealth servers={servers} />

      {totals.reporting > 0 && (
        <div className="fleet-totals">
          <div className="ft-item">
            <ServerIcon size={14} className="faint" />
            <div>
              <div className="ft-value">{totals.reporting}</div>
              <div className="ft-label">
                {totals.reporting === servers.length
                  ? 'servers reporting'
                  : `of ${servers.length} servers reporting`}
              </div>
            </div>
          </div>
          <div className="ft-item">
            <Cpu size={14} className="faint" />
            <div>
              <div className="ft-value">{totals.cores}</div>
              <div className="ft-label">vCPU total</div>
            </div>
          </div>
          <div className="ft-item">
            <MemoryStick size={14} className="faint" />
            <div>
              <div className="ft-value">{bytes(totals.memTotal)}</div>
              <div className="ft-label">
                RAM · {bytes(totals.memUsed)} used ({pct(totals.memUsed, totals.memTotal).toFixed(0)}%)
              </div>
            </div>
          </div>
          <div className="ft-item">
            <HardDrive size={14} className="faint" />
            <div>
              <div className="ft-value">{bytes(totals.diskTotal)}</div>
              <div className="ft-label">
                Disk · {bytes(totals.diskUsed)} used ({pct(totals.diskUsed, totals.diskTotal).toFixed(0)}%)
              </div>
            </div>
          </div>
        </div>
      )}

      <div
        className="monitor-groups"
        // A drag that ends outside any target must not leave the wall stuck in
        // a highlighted state.
        onDragEnd={() => {
          setDrag(null)
          setDropAt(null)
          setGroupDrop(null)
        }}
      >
        {groups.map((g, i) => (
          <GroupSection
            key={g.id}
            group={g}
            index={i}
            cards={g.serverIds.map((id) => byId.get(id)).filter((s): s is Server => !!s)}
            drag={drag}
            dropAt={dropAt}
            groupDrop={groupDrop}
            setDrag={setDrag}
            setDropAt={setDropAt}
            setGroupDrop={setGroupDrop}
            commit={commit}
          />
        ))}
        </div>
      </div>
    </div>
  )
}
