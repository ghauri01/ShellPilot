import { useCallback, useEffect, useMemo, useState } from 'react'
import { AlertTriangle, Bot, History, RefreshCw, Server as ServerIcon, User } from 'lucide-react'
import { clsx } from '../../lib/format'
import { openSettings } from '../../store/nav'
import {
  CHANGELOG_KINDS,
  CHANGELOG_SWITCH_OFF,
  CHANGELOG_SWITCH_ON,
  changeLogCoverageText,
  type ChangeLogActor,
  type ChangeLogBridge,
  type ChangeLogFilter,
  type ChangeLogKind,
  type ChangeLogPage
} from '../../../../shared/changelog'
import type { Server } from '../../types'

// "What did I change on Tuesday." — roadmap item 14, the view.
//
// One timeline over four append-only records that never met: the local session
// log, the approval log, the agent audit log and the durable store's events.
// The merge, the ordering and the redaction all happen in main; this renders
// what came back and — the part that matters — renders what did NOT.
//
// THE COVERAGE LINES ARE NOT DECORATION. A timeline is read as a complete
// account of a period, so a source that was missing, unreadable or truncated
// has to say so IN the timeline; leaving it out turns "I could not read the
// approval log" into "you approved nothing that day". That is the failure
// alertCoverage.ts was written for one level up, and the sentences here come
// from the same place its sentences do — a function over what actually
// happened, never a paraphrase written beside a switch.
//
// This panel never re-sorts, re-filters or re-derives what it was given. The
// ordering is total and lives in shared/changelog.ts; a second, subtly
// different opinion about it here is how two screens end up disagreeing about
// what happened when.

const WINDOWS: { id: string; label: string; ms: number | null }[] = [
  { id: '24h', label: 'Last 24 hours', ms: 86_400_000 },
  { id: '7d', label: 'Last 7 days', ms: 7 * 86_400_000 },
  { id: '30d', label: 'Last 30 days', ms: 30 * 86_400_000 },
  { id: 'all', label: 'Everything kept', ms: null }
]

const ACTOR_LABEL: Record<ChangeLogActor, string> = {
  human: 'You',
  agent: 'An agent',
  // Not a person and not an agent. A host that went unreachable at 03:00 was
  // nobody's doing, and filing it under either of the other two would make
  // this screen answer "what did I do" with something nobody did.
  system: 'ShellPilot itself'
}

const KIND_LABEL: Record<ChangeLogKind, string> = {
  shell: 'Local shells',
  approval: 'Approvals',
  'agent-action': 'Agent actions',
  job: 'Jobs',
  host: 'Hosts',
  store: 'The store itself'
}

function bridge(): Partial<ChangeLogBridge> | undefined {
  return (window.shellpilot as unknown as { changelog?: Partial<ChangeLogBridge> } | undefined)
    ?.changelog
}

function when(ts: number): string {
  const d = new Date(ts)
  return `${d.toLocaleDateString()} ${d.toLocaleTimeString()}`
}

function ActorIcon({ actor }: { actor: ChangeLogActor }): React.JSX.Element {
  if (actor === 'agent') return <Bot size={12} className="faint" />
  if (actor === 'human') return <User size={12} className="faint" />
  return <ServerIcon size={12} className="faint" />
}

export function ChangeLogPanel({ servers }: { servers: Server[] }): React.JSX.Element {
  // The store keeps a server ID on an event and nothing else, and a year later
  // a uuid is not a host. Main does not hold the workspace's server list — the
  // renderer does — so the name is resolved here, and a host that has since
  // been removed falls back to the id rather than to nothing. An empty cell
  // would read as "no host", which is the wrong fact.
  const nameOf = useCallback(
    (id: string): string => servers.find((s) => s.id === id)?.name ?? id,
    [servers]
  )
  const [windowId, setWindowId] = useState('7d')
  const [actor, setActor] = useState<ChangeLogActor | 'any'>('any')
  const [kind, setKind] = useState<ChangeLogKind | 'any'>('any')
  const [host, setHost] = useState('')
  const [page, setPage] = useState<ChangeLogPage | null>(null)
  const [reading, setReading] = useState(false)
  // A bridge older than this renderer, which happens under `electron-vite dev`
  // for the rest of a session. Said out loud rather than rendered as an empty
  // timeline, which would read as "nothing happened".
  const [unavailable, setUnavailable] = useState(false)

  const filter = useMemo<ChangeLogFilter>(() => {
    const w = WINDOWS.find((x) => x.id === windowId) ?? WINDOWS[1]
    return {
      ...(w.ms === null ? {} : { from: Date.now() - w.ms }),
      ...(actor === 'any' ? {} : { actors: [actor] }),
      ...(kind === 'any' ? {} : { kinds: [kind] }),
      ...(host === '' ? {} : { hosts: [host] })
    }
  }, [windowId, actor, kind, host])

  const read = useCallback(async (): Promise<void> => {
    const api = bridge()
    if (typeof api?.read !== 'function') {
      setUnavailable(true)
      return
    }
    setReading(true)
    try {
      setPage(await api.read(filter))
      setUnavailable(false)
    } finally {
      setReading(false)
    }
  }, [filter])

  useEffect(() => {
    void read()
  }, [read])

  return (
    <div className="bc-panel">
      <div className="panel-head">
        <span className="panel-head-icon">
          <History size={14} />
        </span>
        <h2 className="ui-section-title">Change log</h2>
        <p className="ui-note panel-head-purpose">
          What ShellPilot itself changed on the estate, and when — with the coverage of each
          source stated, so a quiet window is not read as a quiet week.
        </p>
        <div className="panel-head-actions">
          {/* The panel's only action, and it was styled `ghost sm` — its least
              prominent variant. It is the whole point of opening this tab. */}
          <button className="btn primary" onClick={() => void read()} disabled={reading}>
            <RefreshCw size={12} /> Refresh
          </button>
        </div>
      </div>

      {unavailable && (
        <div className="panel-note is-alarm" data-testid="changelog-unavailable">
          The change log could not be read: this window is newer than the preload script it booted
          with. Restart the app to rebuild it. Nothing below is a statement about what happened.
        </div>
      )}

      {page !== null && !page.enabled && (
        <div className="panel-note is-unknown" data-testid="changelog-off">
          {CHANGELOG_SWITCH_OFF}{' '}
          <button className="btn ghost sm" onClick={() => openSettings('modules')}>
            Modules
          </button>
        </div>
      )}

      {page?.enabled === true && (
        <>
          <div className="panel-note" data-testid="changelog-on">
            {CHANGELOG_SWITCH_ON}
          </div>

          <div className="row" style={{ gap: 8, flexWrap: 'wrap', marginTop: 8 }}>
            <select
              className="input sm"
              aria-label="Time range"
              value={windowId}
              onChange={(e) => setWindowId(e.target.value)}
            >
              {WINDOWS.map((w) => (
                <option key={w.id} value={w.id}>
                  {w.label}
                </option>
              ))}
            </select>
            <select
              className="input sm"
              aria-label="Who"
              value={actor}
              onChange={(e) => setActor(e.target.value as ChangeLogActor | 'any')}
            >
              <option value="any">Anyone</option>
              {(Object.keys(ACTOR_LABEL) as ChangeLogActor[]).map((a) => (
                <option key={a} value={a}>
                  {ACTOR_LABEL[a]}
                </option>
              ))}
            </select>
            <select
              className="input sm"
              aria-label="What"
              value={kind}
              onChange={(e) => setKind(e.target.value as ChangeLogKind | 'any')}
            >
              <option value="any">Everything</option>
              {CHANGELOG_KINDS.map((k) => (
                <option key={k} value={k}>
                  {KIND_LABEL[k]}
                </option>
              ))}
            </select>
            <select
              className="input sm"
              aria-label="Host"
              value={host}
              onChange={(e) => setHost(e.target.value)}
            >
              <option value="">Every server</option>
              {servers.map((s) => (
                <option key={s.id} value={s.id}>
                  {s.name}
                </option>
              ))}
            </select>
          </div>

          {/* Coverage first, above the timeline and not beside it. What a
              reader must not be able to do is scan the rows, conclude the day
              was quiet, and only then discover a source was unreadable. */}
          {page.coverage.map((row) => (
            <div
              key={row.source}
              className={clsx(
                'panel-note',
                // Unreadable and truncated are both "we do not know", not "we
                // found something bad" — the role that used to be amber
                // alongside genuine degradations, and did not render at all.
                (row.state === 'unreadable' || row.state === 'truncated') && 'is-unknown'
              )}
              data-testid={`changelog-coverage-${row.source}`}
            >
              {(row.state === 'unreadable' || row.state === 'truncated') && (
                <AlertTriangle size={12} className="faint" />
              )}{' '}
              {changeLogCoverageText(row)}
            </div>
          ))}

          {page.hostFilterHidUnattributed !== undefined && (
            <div className="panel-note is-unknown" data-testid="changelog-host-filter-note">
              {page.hostFilterHidUnattributed} entries in this window name no server at all — a local
              shell, or a job that had not reached one — so filtering by server hides them. They are
              not absent; they are unattributed.
            </div>
          )}

          {page.more && (
            <div className="panel-note" data-testid="changelog-more">
              More entries matched than fit on one page. The oldest shown is{' '}
              {page.oldest === null ? 'unknown' : when(page.oldest)}; narrow the window to see
              further back.
            </div>
          )}

          {page.entries.length === 0 ? (
            // The sentence is kept word for word — a test guards it, and it
            // is the one claim this panel exists to make. What is added is the
            // next step, which it never had.
            <div className="panel-empty" data-testid="changelog-empty">
              <p className="panel-empty-title">Nothing matched this window.</p>
              <p className="panel-empty-body">
                Nothing matched this window — read the coverage above before reading that as a
                quiet period.
              </p>
              <p className="panel-empty-body">
                Widening the time range, or clearing the server filter, is the next thing to try.
              </p>
            </div>
          ) : (
            <div className="col" style={{ gap: 6, marginTop: 10 }} data-testid="changelog-entries">
              {page.entries.map((e) => (
                <div key={e.id} className="row" style={{ gap: 8, alignItems: 'flex-start' }}>
                  <span className="mono faint" style={{ whiteSpace: 'nowrap' }}>
                    {when(e.ts)}
                  </span>
                  <ActorIcon actor={e.actor} />
                  <div className="col grow" style={{ gap: 2 }}>
                    <div>
                      <b>{ACTOR_LABEL[e.actor]}</b> · {e.summary}
                      {(e.hosts.length > 0 || e.hostId !== null) && (
                        <span className="faint">
                          {' '}
                          · {(e.hosts.length > 0 ? e.hosts : [nameOf(e.hostId!)]).join(', ')}
                        </span>
                      )}
                    </div>
                    {e.detail.length > 0 && (
                      <div className="mono faint" style={{ fontSize: 11 }}>
                        {e.detail.join(' · ')}
                      </div>
                    )}
                  </div>
                </div>
              ))}
            </div>
          )}
        </>
      )}
    </div>
  )
}
