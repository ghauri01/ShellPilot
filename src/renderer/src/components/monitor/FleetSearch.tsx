import { useMemo, useState } from 'react'
import { Search, X, Server as ServerIcon, Boxes, Network } from 'lucide-react'
import { useFleet } from '../../store/fleet'
import { searchFleet, coverageSentence, matchKey, type FleetMatch } from '../../lib/fleetSearch'
import { duration } from '../../lib/format'
import type { Server } from '../../types'

// Fleet-wide search over what the sampler already knows.
//
// Deliberately not a new activity in the rail: this is the monitor's own data,
// and an eighth icon for it would cost more than it returns. It sits above the
// cards and takes the panel over only while there is a query.

const ICON = {
  host: ServerIcon,
  unit: Boxes,
  port: Network
} as const

function Row({ m, onOpen }: { m: FleetMatch; onOpen: (serverId: string) => void }): React.JSX.Element {
  const Icon = ICON[m.kind]
  return (
    <button className="fleet-hit" onClick={() => onOpen(m.serverId)} title={`Open ${m.serverName}`}>
      <Icon size={13} className="faint" />
      <b className="mono">{m.label}</b>
      <span className="faint grow">{m.detail}</span>
      {/* `.chip` is the badge idiom here, with .danger/.warn modifiers —
          FleetHealth above uses the same. There is no `.pill` in the
          stylesheet, and inventing one renders unstyled text. */}
      {m.badge && <span className={m.badge === 'failed' ? 'chip danger' : 'chip'}>{m.badge}</span>}
      <span className="faint">{m.serverName}</span>
      {/* The age is not a detail. A search that answers from a sweep four
          minutes old and does not say so is indistinguishable from one that
          just asked the host. */}
      <span className="faint mono" style={{ fontSize: 11 }}>
        {m.stale ? 'last seen ' : ''}
        {duration(m.at)} ago
      </span>
    </button>
  )
}

export function FleetSearch({
  servers,
  onOpen
}: {
  servers: Server[]
  onOpen: (serverId: string) => void
}): React.JSX.Element {
  const [query, setQuery] = useState('')
  const samples = useFleet((s) => s.samples)
  const errors = useFleet((s) => s.errors)

  const result = useMemo(
    () => searchFleet({ servers: servers.map((s) => ({ id: s.id, name: s.name })), hosts: samples, errors }, query),
    [servers, samples, errors, query]
  )
  const coverage = coverageSentence(result.coverage)
  const active = query.trim() !== ''
  // `searched` deliberately excludes a host that has a sample but neither
  // probe, so it is no longer the test for "has anything been sampled at all".
  const nothingSampled =
    result.coverage.searched.length === 0 && result.coverage.noProbes.length === 0

  return (
    <div className="fleet-search">
      <div className="input-group">
        <Search size={14} className="faint" />
        <input
          className="input"
          placeholder="Search units, ports and hosts across the workspace…"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
        />
        {active && (
          <button className="icon-btn sm" title="Clear" onClick={() => setQuery('')}>
            <X size={13} />
          </button>
        )}
      </div>

      {active && (
        <div className="fleet-results">
          <div className="row muted" style={{ fontSize: 11, justifyContent: 'space-between' }}>
            <span>
              {result.matches.length} match{result.matches.length === 1 ? '' : 'es'}
              {result.truncated > 0 && ` · ${result.truncated} more not shown`}
            </span>
          </div>

          {/* Always above the results, never below. Someone reading three hits
              needs to know they came from four hosts out of fifteen before they
              conclude anything from the number. */}
          {coverage && <div className="s-desc warn">{coverage}</div>}

          {result.matches.length === 0 && (
            <div className="faint" style={{ padding: '10px 0' }}>
              {/* "Nothing was sampled" and "nothing matched" are different
                  answers, and so is "the hosts were sampled but neither probe
                  ran on them" — that last one has a sample and would otherwise
                  be told to turn on background checking it already has on. */}
              {nothingSampled
                ? 'No host has been sampled yet, so there is nothing to search. Turn on background checking, or open a server.'
                : 'Nothing matched on the hosts that could be searched.'}
            </div>
          )}

          {/* The key must be unique per row, not merely descriptive: two sockets
              with the same protocol and port on different addresses share
              kind, server and label. */}
          {result.matches.map((m, i) => (
            <Row key={matchKey(m, i)} m={m} onOpen={onOpen} />
          ))}
        </div>
      )}
    </div>
  )
}
