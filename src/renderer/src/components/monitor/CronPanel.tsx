import { useMemo, useState } from 'react'
import { CalendarClock, RefreshCw, ShieldAlert } from 'lucide-react'
import { sshHopsFor } from '../../lib/ssh'
import { clsx } from '../../lib/format'
import { CRON_STATUS_HELP, summariseCronSources } from '../../../../shared/cron'
import type { CronEntry, CronSourceReport } from '../../../../shared/cron'
import type { Server } from '../../types'

// What is scheduled across the estate — currently unanswerable without visiting
// every box.
//
// Read-only on purpose. Cron's traps are all silent misreads rather than
// errors, so the parser earns trust by being checked against real hosts before
// anything is allowed to write.

interface HostCron {
  serverId: string
  serverName: string
  entries: CronEntry[]
  unparsed: number
  /**
   * What each source had to say for itself.
   *
   * Optional because it arrives over IPC: a main process that has not been
   * taught to forward it sends nothing, and a panel that treated that as "all
   * five read fine" would be inventing the very reassurance this field exists
   * to withdraw.
   */
  sources?: CronSourceReport[]
  error?: string
}

const KIND_LABEL: Record<CronEntry['kind'], string> = {
  'user-crontab': 'user crontab',
  'system-crontab': '/etc/crontab',
  'cron.d': 'cron.d',
  'systemd-timer': 'systemd timer',
  'other-user-crontab': 'crontab spool'
}

/**
 * What a host's list of jobs is actually worth.
 *
 * This is the whole point of the change. "Nothing scheduled." under a host name
 * is a claim, and until now it was made just as confidently for a box whose
 * /etc/cron.d we were refused as for one that genuinely has nothing. An
 * operator has no way to tell those apart from the outside, so the panel has to
 * say which it is.
 */
function SourceStatus({ sources }: { sources?: CronSourceReport[] }): React.JSX.Element {
  if (!sources || sources.length === 0) {
    return (
      <div className="faint" style={{ fontSize: 11 }}>
        This host did not report which sources it managed to read, so this list may be incomplete.
      </div>
    )
  }
  const { answered, total, incomplete, usedSudo } = summariseCronSources(sources)
  const complete = incomplete.length === 0
  return (
    <div style={{ fontSize: 11 }}>
      <span className={clsx(complete ? 'faint' : 'warn')}>
        {complete ? `read all ${total} sources` : `read ${answered} of ${total} sources`}
      </span>
      {/* Reading as root is a thing that happened, not an implementation
          detail. It is surfaced for the same reason the Docker panel surfaces
          it: silent escalation is the wrong trade even when it is the only way
          to get an answer. */}
      {usedSudo && (
        <span className="faint" title="Some sources were readable only as root, and were read with sudo -n — which never prompts.">
          {' '}
          · read as root
        </span>
      )}
      {incomplete.map((s) => (
        <div key={s.id} className="warn" style={{ marginTop: 2 }}>
          <ShieldAlert size={11} /> {s.label}: {CRON_STATUS_HELP[s.status]}
          {s.detail ? ` (${s.detail})` : ''}
        </div>
      ))}
    </div>
  )
}

export function CronPanel({ servers }: { servers: Server[] }): React.JSX.Element {
  const [rows, setRows] = useState<HostCron[] | null>(null)
  const [loading, setLoading] = useState(false)
  const [filter, setFilter] = useState('')

  const eligible = useMemo(() => servers.filter((s) => s.status !== 'offline'), [servers])

  const collect = async (): Promise<void> => {
    setLoading(true)
    try {
      const res = await window.shellpilot?.cron?.collect(
        eligible.map((s) => ({
          serverId: s.id,
          serverName: s.name,
          cfg: {
            sessionId: `cron-${s.id}`,
            cols: 80,
            rows: 24,
            serverId: s.id,
            host: s.host,
            port: s.port,
            username: s.username,
            auth: s.auth === 'password' || s.auth === 'agent' ? s.auth : 'key',
            hops: sshHopsFor(s)
          }
        }))
      )
      setRows(res ?? [])
    } finally {
      // The handler catches per host today, so nothing here throws — but one
      // rejected invoke away, a button that never stops spinning is a UI that
      // has silently stopped working.
      setLoading(false)
    }
  }

  const q = filter.trim().toLowerCase()
  const visible = (rows ?? []).map((h) => ({
    ...h,
    entries: q === '' ? h.entries : h.entries.filter((e) => `${e.command} ${e.origin} ${e.user ?? ''}`.toLowerCase().includes(q))
  }))
  const total = visible.reduce((n, h) => n + h.entries.length, 0)
  const failed = visible.filter((h) => h.error)
  const unparsed = visible.reduce((n, h) => n + h.unparsed, 0)
  const partial = visible.filter(
    (h) => !h.error && (h.sources?.length ?? 0) > 0 && summariseCronSources(h.sources ?? []).incomplete.length > 0
  ).length

  return (
    <div className="bc-panel">
      <div className="row" style={{ gap: 8, alignItems: 'center' }}>
        <CalendarClock size={14} className="faint" />
        <b className="grow">Scheduled jobs</b>
        {rows && (
          <input
            className="input"
            style={{ maxWidth: 220 }}
            placeholder="Filter by command or file…"
            value={filter}
            onChange={(e) => setFilter(e.target.value)}
          />
        )}
        <button className="btn" disabled={loading || eligible.length === 0} onClick={() => void collect()}>
          <RefreshCw size={13} className={clsx(loading && 'spin')} /> {rows ? 'Refresh' : 'Read schedules'}
        </button>
      </div>

      {!rows && !loading && (
        <div className="s-desc">
          Reads crontabs, /etc/crontab, /etc/cron.d, other accounts’ crontabs and systemd timers
          from every online server, and says which of those it was actually allowed to read.
          Sources that are root-only are retried with <span className="mono">sudo -n</span>, which
          never prompts for a password. Nothing is written or changed — this only looks.
        </div>
      )}

      {rows && (
        <>
          <div className="row muted" style={{ fontSize: 11, marginTop: 8, gap: 12 }}>
            <span>
              {total} job{total === 1 ? '' : 's'} across {visible.length - failed.length} host
              {visible.length - failed.length === 1 ? '' : 's'}
            </span>
            {/* Lines that looked like jobs but did not parse are counted, not
                hidden. A schedule silently missing from this view is a command
                running on a box that nobody knows about. */}
            {unparsed > 0 && <span className="warn">{unparsed} line{unparsed === 1 ? '' : 's'} not understood</span>}
            {/* Counted across the estate as well as per host: with a dozen
                servers, a single host whose cron.d was refused is easy to
                scroll past, and it is exactly the host you would want to look
                at. */}
            {partial > 0 && (
              <span className="warn">
                {partial} host{partial === 1 ? '' : 's'} only partly readable
              </span>
            )}
          </div>

          {failed.map((h) => (
            <div key={h.serverId} className="s-desc danger">
              {h.serverName}: {h.error}
            </div>
          ))}

          {visible
            .filter((h) => !h.error)
            .map((h) => (
              <div key={h.serverId} style={{ marginTop: 10 }}>
                <div className="s-title">
                  {h.serverName} <span className="faint">· {h.entries.length}</span>
                </div>
                <SourceStatus sources={h.sources} />
                {h.entries.length === 0 && (
                  <div className="faint" style={{ fontSize: 12 }}>
                    {q !== ''
                      ? 'Nothing matching.'
                      : // Only claimed when every source actually answered. On a
                        // host where /etc/cron.d was refused, "Nothing
                        // scheduled" is a sentence about our permissions
                        // wearing a sentence about the host.
                        (h.sources?.length ?? 0) > 0 &&
                          summariseCronSources(h.sources ?? []).incomplete.length === 0
                        ? 'Nothing scheduled.'
                        : 'Nothing found in the sources that could be read.'}
                  </div>
                )}
                {h.entries.map((e, i) => (
                  <div key={`${e.origin}:${i}`} className="cron-row">
                    <span className="chip">{KIND_LABEL[e.kind]}</span>
                    <span className="mono cron-when">
                      {e.kind === 'systemd-timer' ? (e.nextRun ? `next ${e.nextRun}` : 'no next run') : e.schedule}
                    </span>
                    {/* Null means "a valid schedule I decline to describe".
                        A wrong sentence about when a job runs is worse than
                        none. */}
                    <span className="faint cron-desc">{e.description ?? ''}</span>
                    {/* `e.input` is the text after an unescaped `%`, which
                        cron pipes to the command on stdin rather than running.
                        Showing it inside the command would be showing a command
                        that is not the one that runs. */}
                    <span
                      className="mono grow cron-cmd"
                      title={e.input === undefined ? e.command : `${e.command}\n\nstdin:\n${e.input}`}
                    >
                      {e.command}
                      {e.input !== undefined && <span className="faint"> · stdin</span>}
                    </span>
                    {e.user && <span className="faint">{e.user}</span>}
                  </div>
                ))}
              </div>
            ))}
        </>
      )}
    </div>
  )
}
