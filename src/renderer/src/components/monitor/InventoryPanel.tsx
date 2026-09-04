import { useMemo, useState } from 'react'
import { ArrowDown, ArrowUp, Boxes, RefreshCw, ShieldQuestion } from 'lucide-react'
import { useFleet } from '../../store/fleet'
import { openSettings } from '../../store/nav'
import { bridgeHas } from '../../lib/bridge'
import { clsx } from '../../lib/format'
import {
  INVENTORY_COLUMNS,
  buildRow,
  gapIsLoud,
  sortRows,
  summarise,
  type InventoryColumn,
  type InventoryColumnId,
  type InventoryRow,
  type SortDirection
} from '../../lib/inventory'
import type { Server } from '../../types'

// The estate inventory — roadmap item C, renderer half.
//
// Every host, what it is, and what it needs. It is a table, and the table is
// the easy part; `lib/inventory.ts` holds the part that is not, which is that
// every cell can be empty for a different reason and none of those reasons is
// a dash. This file renders cells and never formats a fact.
//
// A tab inside the Fleet Monitor rather than an activity of its own, for the
// reason FleetSearch states about itself: this is the monitor's own data, and
// an eighth icon for it would cost more than it returns.
//
// The module is OFF by default — see src/shared/modules.ts — so the first thing
// most people will see here is the empty state. It says what to do next.

function SortHeader({
  column,
  sort,
  onSort
}: {
  column: InventoryColumn
  sort: { column: InventoryColumnId; direction: SortDirection }
  onSort: (id: InventoryColumnId) => void
}): React.JSX.Element {
  const active = sort.column === column.id
  return (
    <th
      className={clsx(column.numeric && 'num', active && 'sorted')}
      aria-sort={active ? (sort.direction === 'asc' ? 'ascending' : 'descending') : 'none'}
    >
      <button
        className="inv-sort"
        onClick={() => onSort(column.id)}
        title={
          column.help
            ? `${column.help} Click to sort; hosts with no value for this column always sort last.`
            : 'Click to sort. Hosts with no value for this column always sort last.'
        }
      >
        {column.label}
        {active &&
          (sort.direction === 'asc' ? <ArrowUp size={11} /> : <ArrowDown size={11} />)}
      </button>
    </th>
  )
}

function Cell({ row, column }: { row: InventoryRow; column: InventoryColumn }): React.JSX.Element {
  const cell = row.cells[column.id]
  return (
    // `data-host`/`data-col` name the cell for anything that has to find one —
    // a test, or a person reading the DOM — without depending on column order,
    // which the disclosure below changes.
    <td data-host={row.serverName} data-col={column.id} className={clsx(column.numeric && 'num')}>
      {cell.gap === null ? (
        <>
          <span className={clsx(column.numeric && 'mono')} title={cell.help || undefined}>
            {cell.text}
          </span>
          {/* Beside the number it undermines, not in a distant column. A count
              read out of a package cache nobody has refreshed in six weeks is
              still the best answer available and still not a current one, and
              the two facts have to arrive together or the first one wins. */}
          {cell.staleMetadata && (
            <span className="chip warn inv-stale" title={cell.help}>
              stale cache
            </span>
          )}
        </>
      ) : (
        // Never a dash, never a zero, never blank. The words are the feature:
        // "cannot be answered" and "0" must not be confusable, because on an
        // Arch or Alpine host the true security count is the former and the
        // number a naive renderer would print is the latter.
        <span className={clsx('inv-na', gapIsLoud(cell.gap) && 'loud')} title={cell.help}>
          {cell.text}
        </span>
      )}
    </td>
  )
}

export function InventoryPanel({
  servers,
  onOpen
}: {
  servers: Server[]
  onOpen?: (serverId: string) => void
}): React.JSX.Element {
  const samples = useFleet((s) => s.samples)
  const facts = useFleet((s) => s.facts)
  const reportFacts = useFleet((s) => s.reportFacts)
  const reportFactsError = useFleet((s) => s.reportFactsError)
  const [sort, setSort] = useState<{ column: InventoryColumnId; direction: SortDirection }>({
    column: 'security',
    direction: 'desc'
  })
  // Thirteen columns is not a table anyone reads. The eight that answer "what
  // does this host need" are always on; the five that answer "what is it" are
  // one click away and stay open once opened.
  const [hardware, setHardware] = useState(false)
  const [busy, setBusy] = useState(false)

  // `Date.now()` once per render rather than per cell, so the two ages in a row
  // are quoted against the same instant. Two cells disagreeing by a
  // millisecond is invisible; two cells disagreeing about which is older is not.
  const rows = useMemo(() => {
    const now = Date.now()
    return servers.map((s) => {
      const f = facts[s.id]
      return buildRow(
        {
          serverId: s.id,
          serverName: s.name,
          facts: f?.facts ?? null,
          factsAt: f?.at ?? null,
          // An error only explains an ABSENCE. With facts in hand the last good
          // collection is what the row shows, with its own age on it, and the
          // failure is reported above the table rather than by blanking a host
          // we still know things about.
          factsError: f?.facts ? null : (f?.error ?? null),
          metrics: samples[s.id]?.host ?? null
        },
        now
      )
    })
  }, [servers, facts, samples])

  const sorted = useMemo(() => sortRows(rows, sort.column, sort.direction), [rows, sort])
  const summary = useMemo(() => summarise(rows), [rows])
  const columns = INVENTORY_COLUMNS.filter((c) => c.primary || hardware)
  const failed = servers
    .map((s) => ({ name: s.name, error: facts[s.id]?.error }))
    .filter((r): r is { name: string; error: string } => !!r.error)

  const onSort = (column: InventoryColumnId): void =>
    setSort((s) =>
      s.column === column
        ? { column, direction: s.direction === 'asc' ? 'desc' : 'asc' }
        : // A new column starts descending for the counts and ages — "most
          // updates first" is what anyone sorting Updates wants — and ascending
          // for the text columns, where A-Z is.
          {
            column,
            direction: INVENTORY_COLUMNS.find((c) => c.id === column)?.numeric ? 'desc' : 'asc'
          }
    )

  const check = async (): Promise<void> => {
    setBusy(true)
    try {
      // A sweep now, so a host whose facts have never been collected gets them
      // without waiting for the background interval.
      if (bridgeHas(window.shellpilot?.fleet as Record<string, unknown> | undefined, 'sampleNow')) {
        await window.shellpilot?.fleet?.sampleNow()
      }
      // And a read of what main already holds, which is the part that fills the
      // table immediately: the sampler has been collecting facts since its
      // first sweep whether or not this panel was ever open.
      if (!bridgeHas(window.shellpilot?.fleet as Record<string, unknown> | undefined, 'facts')) return
      await Promise.all(
        servers.map(async (s) => {
          const r = await window.shellpilot?.fleet?.facts(s.id)
          if (!r) return
          if (r.facts && r.at !== undefined) reportFacts(s.id, r.facts, r.at)
          if (r.error) reportFactsError(s.id, r.error, r.errorAt ?? Date.now())
        })
      )
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="bc-panel">
      <div className="panel-head">
        <span className="panel-head-icon">
          <Boxes size={14} />
        </span>
        <h2 className="ui-section-title">Inventory</h2>
        <p className="ui-note panel-head-purpose">
          What each host is running and what it is owed — distribution, kernel, pending and
          security updates. Read from package caches as they are; nothing is installed or
          refreshed.
        </p>
        <div className="panel-head-actions">
          {summary.withFacts > 0 && (
            <button
              className="btn ghost sm"
              onClick={() => setHardware((h) => !h)}
              title="Kernel, architecture, CPU model, RAM and virtualisation — what the host IS, as opposed to what it needs."
            >
              {hardware ? 'Hide hardware' : 'Show hardware'}
            </button>
          )}
          <button
            className="btn primary"
            disabled={busy || servers.length === 0}
            onClick={() => void check()}
            title="Sweeps the estate now and re-reads what has already been collected. Facts are re-collected at most once an hour per host, so a host checked recently keeps the figures it has."
          >
            <RefreshCw size={13} className={clsx(busy && 'spin')} /> Check now
          </button>
        </div>
      </div>

      {summary.withFacts === 0 ? (
        // The paragraph is unchanged. What changed is that it is now framed as
        // an empty state rather than set in the same size and colour as the
        // table it stands in for, and that the button it names — "Press Check
        // now" — is now the one primary control on the panel instead of being
        // styled identically to Show hardware. The second half of its advice
        // ("make sure background checking is on in Settings") gets the button
        // it never had: the primary stays in the header, where it is in the
        // same place on every panel, so it is deliberately NOT repeated here.
        <div className="panel-empty">
          <p className="panel-empty-title">No host facts have been collected yet.</p>
          <p className="panel-empty-body">
            ShellPilot collects them about once an hour, on the same background sweep as metrics —
            so a server added in the last hour, or an estate whose background checking has just
            been switched on, will not have any yet. Press <b>Check now</b> to sweep immediately,
            and make sure background checking is on in Settings. Nothing is installed, refreshed or
            changed by this: package caches are read as they are, and their age is reported next to
            the counts.
          </p>
          <div className="panel-empty-actions">
            <button className="btn ghost sm" onClick={() => openSettings('monitoring')}>
              Open Monitoring settings
            </button>
          </div>
        </div>
      ) : (
        <>
          <div className="panel-stats">
            <span>
              {summary.hosts} host{summary.hosts === 1 ? '' : 's'} · facts for {summary.withFacts}
            </span>
            <span>
              {summary.pendingTotal} pending update{summary.pendingTotal === 1 ? '' : 's'}
              {/* Counted, not skipped. A total drawn from nine hosts out of
                  twelve is a different number from a total drawn from twelve. */}
              {summary.pendingUnknown > 0 && (
                <span className="state-unknown"> · {summary.pendingUnknown} host
                  {summary.pendingUnknown === 1 ? '' : 's'} could not be counted</span>
              )}
            </span>
            <span>
              {summary.securityTotal} security update{summary.securityTotal === 1 ? '' : 's'}
              {/* The same treatment the pending total already had, and the one
                  whose absence made this line dangerous: a security total with
                  nothing beside it reads as an estate-wide figure. Three hosts
                  that all refused the probe produced "0 security updates" and
                  not one word more, which is the exact sentence a non-root
                  account must never be shown during the week a CVE lands. */}
              {summary.securityUnknown > 0 && (
                <span className="state-unknown"> · {summary.securityUnknown} host
                  {summary.securityUnknown === 1 ? '' : 's'} could not answer</span>
              )}
            </span>
            {/* The counts above are read out of package caches, and a cache
                nobody has refreshed in six weeks answers confidently and
                wrongly. Each such cell is marked in the table; this is the
                estate-level roll-up of how much of the totals rests on one. */}
            {summary.staleMetadata > 0 && (
              <span
                className="state-watch"
                title="ShellPilot never refreshes a package cache — refreshing is a network operation and on some package managers it can break the host — so a count read out of an old cache is reported with the cache's age beside it rather than silently presented as current."
              >
                {summary.staleMetadata} host{summary.staleMetadata === 1 ? '' : 's'} counted from a
                stale package cache
              </span>
            )}
            {summary.rebootsOwed > 0 && (
              <span className="state-watch">
                {summary.rebootsOwed} host{summary.rebootsOwed === 1 ? '' : 's'} awaiting a reboot
              </span>
            )}
          </div>

          {/* The line that keeps the security total honest. Without it, "4
              security updates" reads as an estate-wide figure when it may be
              drawn from a third of the estate — and the hosts it excludes are
              excluded permanently, not until the next sweep. */}
          {summary.securityUnanswerable > 0 && (
            <div className="panel-note is-unknown">
              <ShieldQuestion size={12} />{' '}
              {summary.securityUnanswerable} host
              {summary.securityUnanswerable === 1 ? '' : 's'} can never report a security update
              count, so {summary.securityUnanswerable === 1 ? 'it is' : 'they are'} not in the{' '}
              {summary.securityTotal} above. Arch and Alpine have no security channel at all, and
              dnf cannot answer where the repositories publish no updateinfo. Treat those hosts as
              unknown, never as zero.
            </div>
          )}

          {/* The other half of the same honesty, and a DIFFERENT sentence.
              `unsupported` above is a property of the distribution and no
              amount of waiting or privilege changes it. Everything counted
              here is a gap that can close — a probe refused for want of
              privilege, a host whose facts have not been collected yet, a
              probe that ran and failed. Folding the two into one number would
              tell an operator that a fixable permission problem is a permanent
              fact about their estate, and the reverse. */}
          {summary.securityUnknown > 0 && (
            <div className="panel-note is-unknown">
              <ShieldQuestion size={12} /> {summary.securityUnknown} host
              {summary.securityUnknown === 1 ? '' : 's'} did not answer the security question, so{' '}
              {summary.securityUnknown === 1 ? 'it is' : 'they are'} not in the{' '}
              {summary.securityTotal} above. These are gaps that can close: a probe refused for want
              of privilege answers for an account that has it, and a host whose facts have not been
              collected yet answers on the next sweep. The Security column says which applies to
              which host.
            </div>
          )}

          {failed.map((f) => (
            <div key={f.name} className="panel-note is-alarm">
              {f.name}: the facts probe failed — {f.error}
            </div>
          ))}

          <div className="inv-scroll">
            <table className="table inv-table">
              <thead>
                <tr>
                  {columns.map((c) => (
                    <SortHeader key={c.id} column={c} sort={sort} onSort={onSort} />
                  ))}
                </tr>
              </thead>
              <tbody>
                {sorted.map((r) => (
                  // Both ages on the row itself, in one sentence. "Collected 5
                  // minutes ago, from package metadata 40 days old" is the
                  // honest reading of this row and it does not fit in a cell.
                  <tr key={r.serverId} title={r.ages}>
                    {columns.map((c) =>
                      c.id === 'host' ? (
                        <td key={c.id} data-host={r.serverName} data-col="host">
                          {onOpen ? (
                            <button
                              className="inv-host"
                              onClick={() => onOpen(r.serverId)}
                              title={`Open ${r.serverName}`}
                            >
                              {r.serverName}
                            </button>
                          ) : (
                            <span>{r.serverName}</span>
                          )}
                          {r.hostname && r.hostname !== r.serverName && (
                            <div className="faint mono" style={{ fontSize: 10 }}>
                              {r.hostname}
                            </div>
                          )}
                        </td>
                      ) : (
                        <Cell key={c.id} row={r} column={c} />
                      )
                    )}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </>
      )}
    </div>
  )
}
