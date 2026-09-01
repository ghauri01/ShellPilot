import { useEffect, useMemo, useState } from 'react'
import { Plus, Trash2, Save, SlidersHorizontal, FolderTree, ChevronRight, TriangleAlert, X } from 'lucide-react'
import { toast } from '../../store/toast'
import { useNav } from '../../store/nav'
import { AI_CAPABILITIES } from '../../../../shared/mcp'
import { summariseAccessGroup, summariseFilePolicies } from './accessGroupSummary'
import type { AccessGroupSummary } from './accessGroupSummary'
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

// A dozen rows of ALLOW/ASK/DENY is the wrong first thing to read. The card is
// what a person meets first, and the sentence on it is generated from this
// group's own capabilities — edit the grid and the card stops describing a
// preset and starts describing what the group now actually does.
function GroupCard({
  group,
  summary,
  selected,
  onSelect
}: {
  group: AccessGroup
  summary: AccessGroupSummary
  selected: boolean
  onSelect: () => void
}): React.JSX.Element {
  return (
    <button type="button" className={`ag-card ${selected ? 'selected' : ''}`} aria-pressed={selected} onClick={onSelect}>
      <div className="ag-card-head">
        <span className="ag-card-name">{group.name}</span>
        {group.builtIn && <span className="chip">Built-in</span>}
        {summary.elevated.length > 0 && (
          <span className="chip danger">
            <TriangleAlert size={10} /> No prompt
          </span>
        )}
      </div>
      {summary.clauses.map((clause) => (
        <span className="ag-card-line" key={clause}>
          {clause}
        </span>
      ))}
    </button>
  )
}

function GroupEditor({ group, summary, onChange, onSave, onDelete }: {
  group: AccessGroup
  summary: AccessGroupSummary
  onChange: (g: AccessGroup) => void
  onSave: () => void
  onDelete: () => void
}): React.JSX.Element {
  // Passing the capabilities in is what lets this header say which rules grant
  // MORE than the grid above does. evaluateFilePath returns the most specific
  // matching rule before it ever looks at the blanket capability, so that
  // number is not a footnote — it is the set of rules that outrank the grid.
  const files = summariseFilePolicies(group.filePolicies, group.capabilities)
  const setCap = (cap: AiCapability, value: PermissionValue): void => {
    onChange({ ...group, capabilities: { ...group.capabilities, [cap]: value } })
  }

  const setRule = (id: string, patch: Partial<FilePathRule>): void => {
    onChange({ ...group, filePolicies: group.filePolicies.map((r) => (r.id === id ? { ...r, ...patch } : r)) })
  }

  const addRule = (): void => {
    onChange({
      ...group,
      // Not Date.now(): two rules added inside the same millisecond shared an
      // id, and both setRule and removeRule match on it — so editing one
      // pattern rewrote the other, and deleting one deleted both. React keyed
      // the rows on it too, which is how it looked like a rendering glitch.
      filePolicies: [
        ...group.filePolicies,
        { id: `fp-${crypto.randomUUID()}`, pattern: '/path/**', write: 'ask' }
      ]
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

      {summary.elevated.length > 0 && (
        // An elevated capability at ALLOW is the one setting on this screen
        // that can be reached by accident and never announces itself again —
        // there is no prompt to notice, only a command that silently succeeds.
        <div className="setting-row" style={{ alignItems: 'flex-start' }}>
          <div className="s-info">
            <div className="s-title">
              <TriangleAlert size={13} /> This group grants privileged access with no prompt
            </div>
            <div className="s-desc">
              An agent can act on it without you seeing anything. Set it to ASK in Capabilities below if you
              want to approve each use.
            </div>
          </div>
        </div>
      )}

      <details className="disclosure" style={{ marginTop: 18 }}>
        <summary className="disclosure-head">
          <ChevronRight size={14} className="chev" />
          <SlidersHorizontal size={13} />
          Capabilities — set each of the {AI_CAPABILITIES.length} individually
          <span className="ag-counts">
            {/* A zero is noise here: "0 ask" makes the reader look for
                something that is not there. */}
            {summary.counts.allow > 0 && <span className="chip ok">{summary.counts.allow} allow</span>}
            {summary.counts.ask > 0 && <span className="chip warn">{summary.counts.ask} ask</span>}
            {summary.counts.deny > 0 && <span className="chip">{summary.counts.deny} deny</span>}
          </span>
        </summary>
        <div className="disclosure-body" style={{ gap: 0 }}>
          {AI_CAPABILITIES.map(({ id, label }) => (
            <div className="setting-row" key={id}>
              <div className="s-info">
                <div className="s-title">{label}</div>
              </div>
              {/* Absent means denied to the policy engine, so show DENY rather
                  than an empty segment on a group that predates a capability. */}
              <PermSegment value={group.capabilities[id] ?? 'deny'} onChange={(v) => setCap(id, v)} />
            </div>
          ))}
        </div>
      </details>

      <details className="disclosure" style={{ marginTop: 10 }}>
        <summary className="disclosure-head">
          <ChevronRight size={14} className="chev" />
          <FolderTree size={13} />
          File path rules — {files.sentence}
        </summary>
        <div className="disclosure-body" style={{ gap: 0 }}>
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
                aria-label="Path pattern"
                onChange={(e) => setRule(rule.id, { pattern: e.target.value })}
              />
              <select
                className="input"
                style={{ width: 110 }}
                aria-label={`Read permission for ${rule.pattern}`}
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
                aria-label={`Write permission for ${rule.pattern}`}
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
          <button className="btn sm" style={{ marginTop: 12, alignSelf: 'flex-start' }} onClick={addRule}>
            <Plus size={13} /> Add path rule
          </button>
        </div>
      </details>

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
  // The group the user clicked while the current one had unsaved edits. Held
  // here rather than applied, so the choice is theirs.
  const [pendingId, setPendingId] = useState<string | null>(null)
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

  const stored = useMemo(() => groups.find((g) => g.id === selectedId) ?? null, [groups, selectedId])
  // The card for the group being edited renders from `draft`, so every keystroke
  // in the grid below updates the sentence above — which reads as "applied".
  // Nothing is, until Save. Comparing against what is stored is the only way to
  // know whether clicking another card would throw work away.
  const dirty = !!draft && !!stored && JSON.stringify(draft) !== JSON.stringify(stored)

  const selectGroup = (id: string): void => {
    if (id === selectedId) return
    if (dirty) return setPendingId(id)
    setSelectedId(id)
  }

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
      toast(`Created ${g.name}. Read what its card says it allows before you assign it to anything.`, 'ok')
    } catch (err) {
      toast(`${name} was not created: ${err instanceof Error ? err.message : String(err)}`, 'error', {
        label: 'Try again',
        run: () => void createGroup()
      })
    }
  }

  const saveGroup = async (): Promise<boolean> => {
    if (!draft) return false
    try {
      await window.shellpilot?.aiPolicy.saveGroup(draft)
      toast(`Saved ${draft.name}`, 'ok')
      load()
      return true
    } catch (err) {
      // Reload so the editor shows what is actually stored — leaving unsaved
      // edits on screen next to a failure reads as if they took effect.
      load()
      toast(`${draft.name} was not saved: ${err instanceof Error ? err.message : String(err)}`, 'error', {
        label: 'Try again',
        run: () => void saveGroup()
      })
      return false
    }
  }

  // Takes id and name rather than reading `draft`, because the retry runs after
  // a reload that may already have dropped the group from the list — see the
  // divergence the catch below describes.
  const deleteGroupById = async (id: string, name: string): Promise<void> => {
    try {
      const result = await window.shellpilot?.aiPolicy.deleteGroup(id)
      // No bridge means nothing was deleted. `result && !result.ok` read that
      // as success and toasted "Deleted X" over a call that never happened.
      if (!result) throw new Error('ShellPilot is not available in this window.')
      if (!result.ok) {
        toast(result.error ?? `${name} could not be deleted.`, 'error')
        return
      }
      setSelectedId(null)
      setPendingId(null)
      load()
      // Deleting a group is not neutral: everything assigned to it drops to No AI
      // Access, which the user finds out about later as agents being refused.
      toast(`Deleted ${name}. Anything assigned to it is now No AI Access.`, 'ok', {
        label: 'Review assignments',
        run: showAssignments
      })
    } catch (err) {
      // The only mutation on this screen that had no catch. policyStore.deleteGroup
      // removes the group from its cached state BEFORE write() throws, so an
      // EACCES or ENOSPC leaves main's memory and the file on disk disagreeing:
      // reloading now shows the group gone, and restarting brings it back. Say
      // that, rather than letting the user discover it a week later.
      load()
      toast(
        `${name} was not deleted: ${err instanceof Error ? err.message : String(err)}. It may reappear when ShellPilot restarts.`,
        'error',
        { label: 'Try again', run: () => void deleteGroupById(id, name) }
      )
    }
  }

  const deleteGroup = async (): Promise<void> => {
    if (!draft) return
    await deleteGroupById(draft.id, draft.name)
  }

  const pendingName = groups.find((g) => g.id === pendingId)?.name ?? 'another group'
  const switchTo = (id: string): void => {
    setPendingId(null)
    setSelectedId(id)
  }

  return (
    <div className="settings-section">
      <h2>Access Groups</h2>
      <div className="sub">
        Define what AI is allowed to do — per capability, not just a single yes/no. Each card describes
        itself from its own settings, so it stays accurate after you edit it. Pick one to change what it
        permits, or create your own (Logs Only, Production Read Only, ...).
      </div>

      <div className="ag-grid">
        {groups.map((g) => (
          <GroupCard
            key={g.id}
            group={g}
            // The card for the group being edited reads from the draft, so the
            // sentence answers "what did that change actually do" while the
            // grid below is still open — before anything is saved.
            summary={summariseAccessGroup(draft?.id === g.id ? draft : g)}
            selected={selectedId === g.id}
            onSelect={() => selectGroup(g.id)}
          />
        ))}
      </div>

      {pendingId && draft && (
        // Switching used to reset the draft from `groups` with no check at all.
        // The card above has been showing the edits the whole time, which reads
        // as "saved" — so losing them silently on the next click is the one
        // outcome this screen cannot afford.
        <div className="setting-row" style={{ alignItems: 'flex-start' }}>
          <div className="s-info">
            <div className="s-title">
              <TriangleAlert size={13} /> {draft.name} has unsaved changes
            </div>
            <div className="s-desc">
              The card shows them, but nothing is stored until you save — the policy engine is still
              enforcing the old settings. Opening {pendingName} now discards them.
            </div>
          </div>
          <button
            className="btn sm primary"
            onClick={() => {
              const to = pendingId
              void saveGroup().then((ok) => ok && switchTo(to))
            }}
          >
            <Save size={13} /> Save and switch
          </button>
          <button className="btn sm danger" onClick={() => switchTo(pendingId)}>
            Discard changes
          </button>
          <button className="btn sm" onClick={() => setPendingId(null)}>
            Keep editing
          </button>
        </div>
      )}

      <div className="setting-row">
        <div className="s-info">
          <div className="s-title">{draft ? `Editing ${draft.name}` : 'Pick a group to edit'}</div>
        </div>
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

      {draft && (
        <GroupEditor
          group={draft}
          summary={summariseAccessGroup(draft)}
          onChange={setDraft}
          onSave={saveGroup}
          onDelete={deleteGroup}
        />
      )}

      <hr style={{ margin: '28px 0', border: 'none', borderTop: '1px solid var(--border)' }} />

      <ServerAssignment groups={groups} />
    </div>
  )
}
