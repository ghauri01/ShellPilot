import { useEffect, useMemo, useState } from 'react'
import { Plus, Trash2, Save, ChevronDown, ChevronRight, TriangleAlert, X } from 'lucide-react'
import { toast } from '../../store/toast'
import { useNav } from '../../store/nav'
import { AI_CAPABILITIES } from '../../../../shared/mcp'
import type { AccessGroup, AiCapability, FilePathRule, PermissionValue, PolicyAssignment } from '../../../../shared/mcp'

const PERM_OPTIONS: PermissionValue[] = ['allow', 'ask', 'deny']

function PermSegment({
  value,
  onChange
}: {
  value: PermissionValue
  onChange: (v: PermissionValue) => void
}): React.JSX.Element {
  return (
    <div className="segment">
      {PERM_OPTIONS.map((p) => (
        <button
          key={p}
          className={`seg-btn ${value === p ? 'active' : ''}`}
          onClick={() => onChange(p)}
          type="button"
        >
          {p.toUpperCase()}
        </button>
      ))}
    </div>
  )
}

// Every capability in AI_CAPABILITIES is now gated by at least one tool —
// sshTunnel by list_tunnels/set_tunnel, databaseAccess by query_database,
// vpnControl by list_vpns/set_vpn — so the grid no longer carries a
// "displayed but does nothing" tier. If one is ever added back, it needs a
// visible marker here rather than a silent row: a permission the user believes
// they have set is worse than one that does not exist.

// A dozen rows of ALLOW/ASK/DENY is the wrong first thing to read. Most groups
// are describable in a sentence, and the person who genuinely needs
// per-capability control will open the grid.
function CapabilitySummary({ group }: { group: AccessGroup }): React.JSX.Element {
  const named = (v: PermissionValue): string[] =>
    AI_CAPABILITIES.filter(({ id }) => group.capabilities[id] === v).map(({ label }) => label.toLowerCase())
  const allowed = named('allow')
  const asked = named('ask')
  const denied = named('deny')

  const line = (title: string, items: string[], note: string): React.JSX.Element | null =>
    items.length === 0 ? null : (
      <div className="s-desc" style={{ marginTop: 4 }}>
        <b>{title}</b> {note} — {items.join(', ')}.
      </div>
    )

  return (
    <div>
      {line('Without asking:', allowed, 'the agent just does these')}
      {line('With your approval:', asked, 'you get a prompt each time')}
      {line('Never:', denied, 'refused outright')}
    </div>
  )
}

function GroupEditor({ group, onChange, onSave, onDelete }: {
  group: AccessGroup
  onChange: (g: AccessGroup) => void
  onSave: () => void
  onDelete: () => void
}): React.JSX.Element {
  const [showGrid, setShowGrid] = useState(false)
  const setCap = (cap: AiCapability, value: PermissionValue): void => {
    onChange({ ...group, capabilities: { ...group.capabilities, [cap]: value } })
  }

  const setRule = (id: string, patch: Partial<FilePathRule>): void => {
    onChange({ ...group, filePolicies: group.filePolicies.map((r) => (r.id === id ? { ...r, ...patch } : r)) })
  }

  const addRule = (): void => {
    onChange({
      ...group,
      filePolicies: [...group.filePolicies, { id: `fp-${Date.now()}`, pattern: '/path/**', write: 'ask' }]
    })
  }

  const removeRule = (id: string): void => {
    onChange({ ...group, filePolicies: group.filePolicies.filter((r) => r.id !== id) })
  }

  return (
    <div>
      <div className="setting-row">
        <div className="s-info">
          <div className="s-title">Name</div>
        </div>
        <input
          className="input"
          value={group.name}
          disabled={group.builtIn}
          onChange={(e) => onChange({ ...group, name: e.target.value })}
        />
      </div>

      <h3 style={{ marginTop: 18 }}>What this group allows</h3>
      <CapabilitySummary group={group} />
      <button className="btn sm" style={{ marginTop: 10 }} onClick={() => setShowGrid((v) => !v)}>
        {showGrid ? <ChevronDown size={13} /> : <ChevronRight size={13} />} Per-capability settings
      </button>

      {showGrid &&
        AI_CAPABILITIES.map(({ id, label }) => (
          <div className="setting-row" key={id}>
            <div className="s-info">
              <div className="s-title">{label}</div>
            </div>
            <PermSegment value={group.capabilities[id]} onChange={(v) => setCap(id, v)} />
          </div>
        ))}

      <h3 style={{ marginTop: 18 }}>File path rules</h3>
      <div className="s-desc">
        The most specific matching pattern wins; anything unmatched falls back to Read/Write Files above.
        Sudo -i/su/bash-style unrestricted shells are always blocked and are not configurable here.
      </div>
      {group.filePolicies.map((rule) => (
        <div className="setting-row" key={rule.id}>
          <input
            className="input mono"
            style={{ flex: 1 }}
            value={rule.pattern}
            onChange={(e) => setRule(rule.id, { pattern: e.target.value })}
          />
          <select
            className="input"
            style={{ width: 110 }}
            value={rule.read ?? ''}
            onChange={(e) => setRule(rule.id, { read: (e.target.value || undefined) as PermissionValue | undefined })}
          >
            <option value="">read: —</option>
            {PERM_OPTIONS.map((p) => (
              <option key={p} value={p}>
                read: {p}
              </option>
            ))}
          </select>
          <select
            className="input"
            style={{ width: 110 }}
            value={rule.write ?? ''}
            onChange={(e) => setRule(rule.id, { write: (e.target.value || undefined) as PermissionValue | undefined })}
          >
            <option value="">write: —</option>
            {PERM_OPTIONS.map((p) => (
              <option key={p} value={p}>
                write: {p}
              </option>
            ))}
          </select>
          <button className="icon-btn" onClick={() => removeRule(rule.id)} aria-label="Remove rule">
            <Trash2 size={14} />
          </button>
        </div>
      ))}
      <button className="btn sm" onClick={addRule}>
        <Plus size={13} /> Add path rule
      </button>

      <div className="setting-row" style={{ marginTop: 18 }}>
        <button className="btn sm primary" onClick={onSave}>
          <Save size={13} /> Save group
        </button>
        {!group.builtIn && (
          <button className="btn sm danger" onClick={onDelete}>
            <Trash2 size={13} /> Delete group
          </button>
        )}
      </div>
    </div>
  )
}

interface WorkspaceOpt {
  id: string
  name: string
}
interface ServerOpt {
  id: string
  workspaceId: string
  name: string
}

function ServerAssignment({ groups }: { groups: AccessGroup[] }): React.JSX.Element {
  const [workspaces, setWorkspaces] = useState<WorkspaceOpt[]>([])
  const [servers, setServers] = useState<ServerOpt[]>([])
  const [assignments, setAssignments] = useState<PolicyAssignment[]>([])
  const [activeWorkspaceId, setActiveWorkspaceId] = useState('')

  const load = (): void => {
    void window.shellpilot?.aiPolicy.listWorkspaces().then((w) => {
      setWorkspaces(w ?? [])
      setActiveWorkspaceId((prev) => prev || w?.[0]?.id || '')
    })
    void window.shellpilot?.aiPolicy.listServers().then((s) => setServers(s ?? []))
    void window.shellpilot?.aiPolicy.listAssignments().then((a) => setAssignments(a ?? []))
  }
  useEffect(load, [])

  const workspaceAssignment = assignments.find(
    (a) => a.scope.level === 'workspace' && a.scope.workspaceId === activeWorkspaceId
  )
  const serversHere = useMemo(
    () => servers.filter((s) => s.workspaceId === activeWorkspaceId),
    [servers, activeWorkspaceId]
  )

  // An assignment that silently fails to save is the worst kind of permission
  // bug: the control shows what the user picked and the policy engine still
  // sees the old value. Say so, and offer the retry rather than describing it.
  const apply = async (change: () => Promise<unknown> | undefined, retry: () => void): Promise<void> => {
    try {
      await change()
    } catch (err) {
      toast(`That assignment was not saved: ${err instanceof Error ? err.message : String(err)}`, 'error', {
        label: 'Try again',
        run: retry
      })
    }
    load()
  }

  const setWorkspaceGroup = async (groupId: string | null): Promise<void> => {
    const scope = { level: 'workspace', workspaceId: activeWorkspaceId } as const
    await apply(
      () => window.shellpilot?.aiPolicy.setAssignment(scope, groupId),
      () => void setWorkspaceGroup(groupId)
    )
  }
  const setServerOverride = async (serverId: string, groupId: string | null): Promise<void> => {
    await apply(
      () => window.shellpilot?.aiPolicy.setAssignment({ level: 'server', serverId }, groupId),
      () => void setServerOverride(serverId, groupId)
    )
  }
  const clearServerOverride = async (serverId: string): Promise<void> => {
    const existing = assignments.find((a) => a.scope.level === 'server' && a.scope.serverId === serverId)
    if (!existing) return load()
    await apply(
      () => window.shellpilot?.aiPolicy.removeAssignment(existing.id),
      () => void clearServerOverride(serverId)
    )
  }

  return (
    <div id="ai-assignments">
      <h2>Server & workspace assignment</h2>
      <div className="sub">
        Assign an access group per workspace as the default, then override individual servers. A server
        with no override inherits its workspace's default; a workspace with no assignment is No AI
        Access.
      </div>

      {!workspaceAssignment?.groupId && (
        // Unassigned is the state a fresh install is in, and it denies every
        // call. Saying nothing here is what makes an agent look broken rather
        // than unconfigured: it connects, lists its tools, and is refused on
        // everything.
        <div className="setting-row" style={{ alignItems: 'flex-start' }}>
          <div className="s-info">
            <div className="s-title">
              <TriangleAlert size={13} /> This workspace is not assigned to an access group
            </div>
            <div className="s-desc">
              Every AI request against its servers is denied. An agent will still connect and list its
              tools, then fail on each call — pick a group below to change that.
            </div>
          </div>
        </div>
      )}
      <div className="setting-row">
        <div className="s-info">
          <div className="s-title">Workspace</div>
        </div>
        <select className="input" value={activeWorkspaceId} onChange={(e) => setActiveWorkspaceId(e.target.value)}>
          {workspaces.map((w) => (
            <option key={w.id} value={w.id}>
              {w.name}
            </option>
          ))}
        </select>
      </div>
      <div className="setting-row">
        <div className="s-info">
          <div className="s-title">Default access group for this workspace</div>
        </div>
        <select
          className="input"
          value={workspaceAssignment?.groupId ?? ''}
          onChange={(e) => setWorkspaceGroup(e.target.value || null)}
        >
          <option value="">No AI Access</option>
          {groups.map((g) => (
            <option key={g.id} value={g.id}>
              {g.name}
            </option>
          ))}
        </select>
      </div>

      <h3 style={{ marginTop: 16 }}>Per-server overrides</h3>
      {serversHere.length === 0 && <div className="s-desc">No servers in this workspace.</div>}
      {serversHere.map((s) => {
        const override = assignments.find((a) => a.scope.level === 'server' && a.scope.serverId === s.id)
        return (
          <div className="setting-row" key={s.id}>
            <div className="s-info">
              <div className="s-title">{s.name}</div>
            </div>
            <select
              className="input"
              value={override ? override.groupId ?? '' : '__inherit'}
              onChange={(e) => {
                if (e.target.value === '__inherit') return clearServerOverride(s.id)
                return setServerOverride(s.id, e.target.value || null)
              }}
            >
              <option value="__inherit">(workspace default)</option>
              <option value="">No AI Access</option>
              {groups.map((g) => (
                <option key={g.id} value={g.id}>
                  {g.name}
                </option>
              ))}
            </select>
          </div>
        )
      })}
    </div>
  )
}

// The assignment table lives at the bottom of this same page, so "go and check
// what this changed" is a scroll, not a search.
function showAssignments(): void {
  document.getElementById('ai-assignments')?.scrollIntoView({ behavior: 'smooth', block: 'start' })
}

export function AiAccessGroups(): React.JSX.Element {
  const [groups, setGroups] = useState<AccessGroup[]>([])
  const [selectedId, setSelectedId] = useState<string | null>(null)
  const [draft, setDraft] = useState<AccessGroup | null>(null)
  // null = not naming a new group. '' = the naming row is open and empty.
  const [newName, setNewName] = useState<string | null>(null)
  const focusGroupId = useNav((s) => s.aiGroupId)
  const clearAiGroup = useNav((s) => s.clearAiGroup)

  const load = (): void => {
    void window.shellpilot?.aiPolicy.listGroups().then((g) => {
      setGroups(g ?? [])
      setSelectedId((prev) => prev ?? g?.[0]?.id ?? null)
    })
  }
  useEffect(load, [])

  // Somebody sent the user here to look at one particular group — open it,
  // rather than dropping them on whichever group happened to be selected.
  useEffect(() => {
    if (!focusGroupId) return
    setSelectedId(focusGroupId)
    clearAiGroup()
  }, [focusGroupId, clearAiGroup])

  useEffect(() => {
    setDraft(groups.find((g) => g.id === selectedId) ?? null)
  }, [selectedId, groups])

  // Was window.prompt(), which Electron does not implement: the button threw
  // and nothing happened at all. Naming it in place also puts the new group's
  // settings on screen the moment it exists.
  const createGroup = async (): Promise<void> => {
    const name = (newName ?? '').trim()
    if (!name) return
    try {
      const g = await window.shellpilot?.aiPolicy.createGroup(name)
      if (!g) throw new Error('No group came back')
      setNewName(null)
      setSelectedId(g.id)
      load()
      // Deliberately not "created, you're done": a new group is not empty, it
      // arrives with defaults, and the summary showing them is right below.
      toast(`Created ${g.name}. Check what it allows below before you assign it to anything.`, 'ok')
    } catch (err) {
      toast(`${name} was not created: ${err instanceof Error ? err.message : String(err)}`, 'error', {
        label: 'Try again',
        run: () => void createGroup()
      })
    }
  }

  const saveGroup = async (): Promise<void> => {
    if (!draft) return
    try {
      await window.shellpilot?.aiPolicy.saveGroup(draft)
      toast(`Saved ${draft.name}`, 'ok')
      load()
    } catch (err) {
      // Reload so the editor shows what is actually stored — leaving unsaved
      // edits on screen next to a failure reads as if they took effect.
      load()
      toast(`${draft.name} was not saved: ${err instanceof Error ? err.message : String(err)}`, 'error', {
        label: 'Try again',
        run: () => void saveGroup()
      })
    }
  }

  const deleteGroup = async (): Promise<void> => {
    if (!draft) return
    const name = draft.name
    const result = await window.shellpilot?.aiPolicy.deleteGroup(draft.id)
    if (result && !result.ok) {
      toast(result.error ?? `${name} could not be deleted.`, 'error')
      return
    }
    setSelectedId(null)
    load()
    // Deleting a group is not neutral: everything assigned to it drops to No AI
    // Access, which the user finds out about later as agents being refused.
    toast(`Deleted ${name}. Anything assigned to it is now No AI Access.`, 'ok', {
      label: 'Review assignments',
      run: showAssignments
    })
  }

  return (
    <div className="settings-section">
      <h2>Access Groups</h2>
      <div className="sub">
        Define what AI is allowed to do — per capability, not just a single yes/no. Four defaults are
        provided; create as many custom groups as you need (Logs Only, Production Read Only, ...).
      </div>

      <div className="setting-row">
        <select className="input" value={selectedId ?? ''} onChange={(e) => setSelectedId(e.target.value)}>
          {groups.map((g) => (
            <option key={g.id} value={g.id}>
              {g.name}
            </option>
          ))}
        </select>
        <button className="btn sm" onClick={() => setNewName('')}>
          <Plus size={13} /> New group
        </button>
      </div>

      {newName !== null && (
        <div className="setting-row">
          <div className="s-info">
            <div className="s-title">Name the new group</div>
            <div className="s-desc">
              A new group starts by allowing reads, asking before terminal and database access, and
              refusing writes and sudo. You can change all of it next.
            </div>
          </div>
          <input
            className="input"
            autoFocus
            placeholder="e.g. Logs Only"
            value={newName}
            onChange={(e) => setNewName(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === 'Enter') void createGroup()
              if (e.key === 'Escape') setNewName(null)
            }}
          />
          <button className="btn sm primary" disabled={!newName.trim()} onClick={() => void createGroup()}>
            Create
          </button>
          <button className="icon-btn" aria-label="Cancel" onClick={() => setNewName(null)}>
            <X size={14} />
          </button>
        </div>
      )}

      {draft && <GroupEditor group={draft} onChange={setDraft} onSave={saveGroup} onDelete={deleteGroup} />}

      <hr style={{ margin: '28px 0', border: 'none', borderTop: '1px solid var(--border)' }} />

      <ServerAssignment groups={groups} />
    </div>
  )
}
