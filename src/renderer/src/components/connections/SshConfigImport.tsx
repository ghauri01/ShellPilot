import { useEffect, useState } from 'react'
import { Download, Loader2, Check, FolderPlus } from 'lucide-react'
import { Modal } from '../common/Modal'
import { useApp } from '../../store/app'
import { toast } from '../../store/toast'
import { clsx } from '../../lib/format'
import type { SshConfigHost } from '../../../../shared/sshconfig'
import type { Hop } from '../../types'

let hopSeq = 0

// ProxyJump points at another config entry (or a bare user@host:port), which
// becomes a jump hop on the imported server.
function hopsFor(entry: SshConfigHost, all: SshConfigHost[]): Hop[] {
  if (!entry.proxyJump) return []
  return entry.proxyJump
    .split(',')
    .map((raw): Hop | null => {
      const spec = raw.trim()
      if (!spec) return null
      const match = all.find((h) => h.alias === spec)
      if (match) {
        // Carry the jump host's own IdentityFile, otherwise the hop would
        // authenticate with nothing.
        return {
          id: `hop-${hopSeq++}`,
          label: match.alias,
          host: match.hostName,
          port: match.port,
          username: match.user || 'root',
          auth: match.identityFile ? ('key' as const) : ('agent' as const),
          keyPath: match.identityFile
        }
      }
      const at = spec.lastIndexOf('@')
      const user = at === -1 ? '' : spec.slice(0, at)
      const hostPart = spec.slice(at + 1)
      const colon = hostPart.lastIndexOf(':')
      const host = colon === -1 ? hostPart : hostPart.slice(0, colon)
      const port = colon === -1 ? 22 : Number(hostPart.slice(colon + 1)) || 22
      return { id: `hop-${hopSeq++}`, label: spec, host, port, username: user || 'root', auth: 'key' as const }
    })
    .filter((h): h is Hop => h !== null)
}

export function SshConfigImport(): React.JSX.Element {
  const setModal = useApp((s) => s.setModal)
  const addServer = useApp((s) => s.addServer)
  const addFolder = useApp((s) => s.addFolder)
  const servers = useApp((s) => s.workspaceServers())

  const [loading, setLoading] = useState(true)
  const [hosts, setHosts] = useState<SshConfigHost[]>([])
  const [path, setPath] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [picked, setPicked] = useState<Record<string, boolean>>({})
  const [intoFolder, setIntoFolder] = useState(true)

  useEffect(() => {
    void window.shellpilot?.sshConfig.read().then((r) => {
      setLoading(false)
      if (!r) return
      setPath(r.path)
      if (!r.ok) {
        setError(r.error ?? 'Could not read the SSH config')
        return
      }
      const list = r.hosts ?? []
      setHosts(list)
      // Pre-select everything that is not already in this workspace.
      setPicked(
        Object.fromEntries(
          list.map((h) => [h.alias, !servers.some((s) => s.host === h.hostName && s.name === h.alias)])
        )
      )
    })
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  const chosen = hosts.filter((h) => picked[h.alias])

  const runImport = async (): Promise<void> => {
    if (chosen.length === 0) return
    const folderId = intoFolder ? addFolder('Imported from ~/.ssh/config', null, 'server') : null

    for (const h of chosen) {
      const id = addServer({
        name: h.alias,
        host: h.hostName,
        port: h.port,
        username: h.user || 'root',
        auth: h.identityFile ? 'key' : 'agent',
        folderId,
        route: hopsFor(h, hosts),
        tags: ['imported']
      })
      // The key path travels through the encrypted secret store, same as a
      // manually added server.
      if (h.identityFile) {
        await window.shellpilot?.secrets.set(id, JSON.stringify({ keyPath: h.identityFile }))
      }
    }
    toast(`Imported ${chosen.length} server${chosen.length === 1 ? '' : 's'}`, 'ok')
    setModal(null)
  }

  return (
    <Modal
      title="Import from SSH config"
      subtitle={path || '~/.ssh/config'}
      size="lg"
      onClose={() => setModal(null)}
      footer={
        <>
          <span className="spacer" />
          <button className="btn" onClick={() => setModal(null)}>
            Cancel
          </button>
          <button className="btn primary" disabled={chosen.length === 0} onClick={() => void runImport()}>
            <Download size={14} /> Import {chosen.length || ''}
          </button>
        </>
      }
    >
      {loading && (
        <div className="row" style={{ gap: 8, padding: 12 }}>
          <Loader2 size={15} className="spin" /> Reading {path || 'SSH config'}…
        </div>
      )}

      {error && <div className="vault-error">{error}</div>}

      {!loading && !error && hosts.length === 0 && (
        <div className="faint" style={{ padding: 12 }}>
          No concrete hosts found. Entries using only wildcards (<span className="mono">Host *</span>) are
          treated as defaults and are not imported on their own.
        </div>
      )}

      {hosts.length > 0 && (
        <>
          <div className="row" style={{ gap: 8, marginBottom: 8 }}>
            <button
              className="btn sm"
              onClick={() => setPicked(Object.fromEntries(hosts.map((h) => [h.alias, true])))}
            >
              Select all
            </button>
            <button className="btn sm" onClick={() => setPicked({})}>
              Select none
            </button>
            <span className="spacer" />
            <label className="row" style={{ gap: 8 }}>
              <span className={clsx('switch', intoFolder && 'on')} onClick={() => setIntoFolder((v) => !v)} />
              <span className="muted">
                <FolderPlus size={13} /> Group into a folder
              </span>
            </label>
          </div>

          <div style={{ maxHeight: 340, overflowY: 'auto' }}>
            {hosts.map((h) => {
              const on = !!picked[h.alias]
              const existing = servers.some((s) => s.host === h.hostName && s.name === h.alias)
              return (
                <div
                  key={h.alias}
                  className="list-row"
                  style={{ cursor: 'pointer', opacity: on ? 1 : 0.55 }}
                  onClick={() => setPicked((p) => ({ ...p, [h.alias]: !on }))}
                >
                  <span
                    className={clsx('status-dot', on ? 'online' : 'offline')}
                    style={{ display: 'grid', placeItems: 'center' }}
                  >
                    {on && <Check size={9} />}
                  </span>
                  <div>
                    <div className="r-title">
                      {h.alias}
                      {existing && <span className="chip" style={{ marginLeft: 8 }}>already added</span>}
                    </div>
                    <div className="r-sub mono">
                      {h.user ? `${h.user}@` : ''}
                      {h.hostName}
                      {h.port !== 22 ? `:${h.port}` : ''}
                      {h.proxyJump ? ` · jump ${h.proxyJump}` : ''}
                      {h.identityFile ? ` · ${h.identityFile}` : ''}
                    </div>
                  </div>
                </div>
              )
            })}
          </div>
        </>
      )}
    </Modal>
  )
}
