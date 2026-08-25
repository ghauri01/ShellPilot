import { useEffect, useMemo, useState } from 'react'
import { Plus, Trash2, Save } from 'lucide-react'
import { toast } from '../../store/toast'
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

function GroupEditor({ group, onChange, onSave, onDelete }: {
  group: AccessGroup
  onChange: (g: AccessGroup) => void
  onSave: () => void
  onDelete: () => void
}): React.JSX.Element {
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

      <h3 style={{ marginTop: 18 }}>Capabilities</h3>
      {AI_CAPABILITIES.map(({ id, label }) => (
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

  const setWorkspaceGroup = async (groupId: string | null): Promise<void> => {
    await window.shellpilot?.aiPolicy.setAssignment({ level: 'workspace', workspaceId: activeWorkspaceId }, groupId)
    load()
  }
  const setServerOverride = async (serverId: string, groupId: string | null): Promise<void> => {
    await window.shellpilot?.aiPolicy.setAssignment({ level: 'server', serverId }, groupId)
    load()
  }
  const clearServerOverride = async (serverId: string): Promise<void> => {
    const existing = assignments.find((a) => a.scope.level === 'server' && a.scope.serverId === serverId)
    if (existing) await window.shellpilot?.aiPolicy.removeAssignment(existing.id)
    load()
  }

  return (
    <div>
      <h2>Server & workspace assignment</h2>
      <div className="sub">
        Assign an access group per workspace as the default, then override individual servers. A server
        with no override inherits its workspace's default; a workspace with no assignment is No AI
        Access.
      </div>
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

export function AiAccessGroups(): React.JSX.Element {
  const [groups, setGroups] = useState<AccessGroup[]>([])
  const [selectedId, setSelectedId] = useState<string | null>(null)
  const [draft, setDraft] = useState<AccessGroup | null>(null)

  const load = (): void => {
    void window.shellpilot?.aiPolicy.listGroups().then((g) => {
      setGroups(g ?? [])
      setSelectedId((prev) => prev ?? g?.[0]?.id ?? null)
    })
  }
  useEffect(load, [])

  useEffect(() => {
    setDraft(groups.find((g) => g.id === selectedId) ?? null)
  }, [selectedId, groups])

  const createGroup = async (): Promise<void> => {
    const name = window.prompt('New access group name')
    if (!name) return
    const g = await window.shellpilot?.aiPolicy.createGroup(name)
    if (g) setSelectedId(g.id)
    load()
  }

  const saveGroup = async (): Promise<void> => {
    if (!draft) return
    await window.shellpilot?.aiPolicy.saveGroup(draft)
    toast(`Saved ${draft.name}`)
    load()
  }

  const deleteGroup = async (): Promise<void> => {
    if (!draft) return
    const result = await window.shellpilot?.aiPolicy.deleteGroup(draft.id)
    if (result && !result.ok) {
      toast(result.error ?? 'Could not delete group')
      return
    }
    setSelectedId(null)
    load()
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
        <button className="btn sm" onClick={createGroup}>
          <Plus size={13} /> New group
        </button>
      </div>

      {draft && <GroupEditor group={draft} onChange={setDraft} onSave={saveGroup} onDelete={deleteGroup} />}

      <hr style={{ margin: '28px 0', border: 'none', borderTop: '1px solid var(--border)' }} />

      <ServerAssignment groups={groups} />
    </div>
  )
}
