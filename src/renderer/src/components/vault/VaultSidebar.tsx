import { KeyRound, Lock, Globe, StickyNote, User, FileKey, Shield } from 'lucide-react'
import { useVault } from '../../store/vault'
import { clsx } from '../../lib/format'
import { useApp } from '../../store/app'
import { vaultMatches, vaultEntriesFor, isSharedVaultEntry, type VaultKind } from '../../../../shared/vault'

const KIND_ICON: Record<VaultKind, React.ReactNode> = {
  login: <User size={13} className="faint" />,
  url: <Globe size={13} className="faint" />,
  key: <KeyRound size={13} className="faint" />,
  sshkey: <FileKey size={13} className="faint" />,
  note: <StickyNote size={13} className="faint" />,
  vpn: <Shield size={13} className="faint" />
}

export function VaultSidebar(): React.JSX.Element {
  const unlocked = useVault((s) => s.unlocked)
  const entries = useVault((s) => s.entries)
  const selectedId = useVault((s) => s.selectedId)
  const select = useVault((s) => s.select)
  const query = useVault((s) => s.query)
  const setQuery = useVault((s) => s.setQuery)
  const activeWorkspaceId = useApp((s) => s.activeWorkspaceId)

  if (!unlocked) {
    return (
      <div className="tree-section">
        <div className="faint" style={{ padding: '10px 12px', fontSize: 12, display: 'flex', gap: 6 }}>
          <Lock size={13} /> Vault is locked.
        </div>
      </div>
    )
  }

  // Entries belonging to this workspace, plus the shared ones. Hidden from
  // view, not cryptographically separated — the vault is still one encrypted
  // file under one master password, and SECURITY.md says so.
  const visible = vaultEntriesFor(entries, activeWorkspaceId)
  const shown = visible.filter((e) => vaultMatches(e, query))
  const hiddenCount = entries.length - visible.length

  return (
    <>
      <div className="sidebar-search">
        <input
          className="input"
          style={{ height: 30, width: '100%' }}
          placeholder="Search vault…"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
        />
      </div>
      <div className="tree-section">
        <div className="tree-section-label">
          Entries <span className="count">{shown.length}</span>
        </div>
        {hiddenCount > 0 && (
          // Saying nothing here would recreate the original confusion in the
          // opposite direction: entries you saved would simply be missing.
          <div className="faint" style={{ padding: '2px 12px 6px', fontSize: 11 }}>
            {hiddenCount} more in other workspaces
          </div>
        )}
        {shown.map((e) => (
          <div
            key={e.id}
            className={clsx('tree-row', selectedId === e.id && 'active')}
            onClick={() => select(e.id)}
            title={e.url || e.username || e.name}
          >
            {KIND_ICON[e.kind]}
            {isSharedVaultEntry(e) && (
              <span className="faint" style={{ fontSize: 10 }} title="Visible in every workspace">
                shared
              </span>
            )}
            <span className="label">{e.name}</span>
          </div>
        ))}
        {shown.length === 0 && (
          <div className="faint" style={{ padding: '8px 10px', fontSize: 12 }}>
            {entries.length ? 'No matches.' : 'No entries yet.'}
          </div>
        )}
      </div>
    </>
  )
}
