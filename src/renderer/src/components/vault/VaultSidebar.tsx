import { KeyRound, Lock, Globe, StickyNote, User, FileKey } from 'lucide-react'
import { useVault } from '../../store/vault'
import { clsx } from '../../lib/format'
import { vaultMatches, type VaultKind } from '../../../../shared/vault'

const KIND_ICON: Record<VaultKind, React.ReactNode> = {
  login: <User size={13} className="faint" />,
  url: <Globe size={13} className="faint" />,
  key: <KeyRound size={13} className="faint" />,
  sshkey: <FileKey size={13} className="faint" />,
  note: <StickyNote size={13} className="faint" />
}

export function VaultSidebar(): React.JSX.Element {
  const unlocked = useVault((s) => s.unlocked)
  const entries = useVault((s) => s.entries)
  const selectedId = useVault((s) => s.selectedId)
  const select = useVault((s) => s.select)
  const query = useVault((s) => s.query)
  const setQuery = useVault((s) => s.setQuery)

  if (!unlocked) {
    return (
      <div className="tree-section">
        <div className="faint" style={{ padding: '10px 12px', fontSize: 12, display: 'flex', gap: 6 }}>
          <Lock size={13} /> Vault is locked.
        </div>
      </div>
    )
  }

  const shown = entries.filter((e) => vaultMatches(e, query))

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
        {shown.map((e) => (
          <div
            key={e.id}
            className={clsx('tree-row', selectedId === e.id && 'active')}
            onClick={() => select(e.id)}
            title={e.url || e.username || e.name}
          >
            {KIND_ICON[e.kind]}
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
