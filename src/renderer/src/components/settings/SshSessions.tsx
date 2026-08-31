import { useEffect, useState } from 'react'
import { Link2, Unlink } from 'lucide-react'
import { useApp } from '../../store/app'
import { toast } from '../../store/toast'
import { clsx } from '../../lib/format'

interface PoolEntry {
  key: string
  host: string
  username: string
  sessions: number
}

// Retention choices for the authenticated master connection. Longer means a
// two-factor code is requested less often; shorter means it is dropped sooner
// after you stop using the server.
const CHOICES: { minutes: number; label: string }[] = [
  { minutes: 0, label: 'Immediately' },
  { minutes: 5, label: '5 min' },
  { minutes: 15, label: '15 min' },
  { minutes: 60, label: '1 hour' },
  { minutes: -1, label: 'Until app exits' }
]

export function SshSessions(): React.JSX.Element {
  const settings = useApp((s) => s.settings)
  const setSettings = useApp((s) => s.setSettings)
  const [pool, setPool] = useState<PoolEntry[]>([])

  const load = (): void => {
    void window.shellpilot?.ssh.poolList().then((p) => setPool(p ?? []))
  }

  useEffect(() => {
    load()
    const t = setInterval(load, 4000)
    return () => clearInterval(t)
  }, [])

  return (
    <div>
      <div className="setting-row">
        <div className="s-info">
          <div className="s-title">Keep authenticated connection</div>
          <div className="s-desc">
            New sessions, file browsing and monitoring reuse an existing authenticated connection
            instead of logging in again. On servers with two-factor authentication, a code is only
            requested when no connection is being reused — so this sets how often you are asked.
          </div>
        </div>
        <div className="segment">
          {CHOICES.map((c) => (
            <button
              key={c.minutes}
              className={clsx('seg-btn', settings.sshMasterIdleMinutes === c.minutes && 'active')}
              onClick={() => setSettings({ sshMasterIdleMinutes: c.minutes })}
            >
              {c.label}
            </button>
          ))}
        </div>
      </div>

      <div className="setting-row">
        <div className="s-info">
          <div className="s-title">Shared connections</div>
          <div className="s-desc">
            {pool.length
              ? 'Disconnecting one forces the next connection to that server to authenticate again.'
              : 'None open. The first connection to a server authenticates and is then reused.'}
          </div>
        </div>
        <button className="btn sm" onClick={load}>
          Refresh
        </button>
      </div>

      {pool.map((p) => (
        <div className="setting-row" key={p.key}>
          <div className="s-info">
            <div className="s-title mono">
              <Link2 size={12} /> {p.username}@{p.host}
            </div>
            <div className="s-desc">
              {p.sessions === 0
                ? 'idle — kept for reuse'
                : `${p.sessions} active session${p.sessions === 1 ? '' : 's'}`}
            </div>
          </div>
          <button
            className="btn sm danger"
            onClick={async () => {
              const close = async (): Promise<void> => {
                try {
                  await window.shellpilot?.ssh.poolClose(p.key)
                  toast(
                    `Disconnected ${p.username}@${p.host}. The next connection to it will authenticate again.`,
                    'ok'
                  )
                } catch (err) {
                  // The row stays on screen either way, so without this the
                  // button would look like it simply did not work.
                  toast(
                    `${p.username}@${p.host} is still connected: ${err instanceof Error ? err.message : String(err)}`,
                    'error',
                    { label: 'Try again', run: () => void close() }
                  )
                }
                load()
              }
              await close()
            }}
          >
            <Unlink size={13} /> Disconnect
          </button>
        </div>
      ))}
    </div>
  )
}
