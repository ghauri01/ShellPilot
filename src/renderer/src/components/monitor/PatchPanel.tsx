import { useEffect, useMemo, useState } from 'react'
import { AlertTriangle, Ban, RefreshCw, ShieldQuestion, Wrench } from 'lucide-react'
import { useFleet } from '../../store/fleet'
import { useApp } from '../../store/app'
import { bridgeHas } from '../../lib/bridge'
import { clsx } from '../../lib/format'
import { sshHopsFor } from '../../lib/ssh'
import {
  PATCH_GAP_LABEL,
  PATCH_NO_AUTOMATION_NOTE,
  blockSummary,
  buildPatchRow,
  planIsBlocked,
  planPatch,
  planWaves,
  summarisePatch,
  type PatchCount,
  type PatchScope
} from '../../../../shared/patch'
import {
  JOB_OUTCOME_LABEL,
  jobApprovalFor,
  planJob,
  type JobHostResult,
  type JobProgress
} from '../../../../shared/jobs'
import type { Server } from '../../types'

// Patch and update management — roadmap item 17, renderer half.
//
// The most common recurring task in the job this app is named for, and the
// first screen in ShellPilot that does it.
//
// THREE THINGS THIS SCREEN REFUSES TO DO, all of them argued in
// src/shared/patch.ts and src/shared/topology.ts rather than here:
//
//  1. It will not schedule. There is no "patch nightly" and there will not be
//     one; see PATCH_NO_AUTOMATION_NOTE, which is printed on the screen rather
//     than left in a comment.
//  2. It will not treat "cannot answer" as zero. The security column is
//     `lib/inventory.ts`'s vocabulary, word for word, because the two panels sit
//     next to each other and a user who learns "cannot be answered" in one must
//     not meet a different phrase for the same fact here.
//  3. It will not restart a host other servers connect through. That is a HARD
//     REFUSAL — the run cannot be started at all while one is in the plan — and
//     it is enforced again in main, because a check that lives only in a panel
//     is a check the next caller does not have.
//
// The table itself is deliberately the SMALL half of this file. Everything that
// decides anything is in shared/, where it can be tested without a DOM and
// where main can call the same function.

function Count({ count }: { count: PatchCount }): React.JSX.Element {
  if (count.gap === null) {
    return (
      <>
        <span className="mono" title={count.help || undefined}>
          {count.value}
        </span>
        {count.staleMetadata && (
          <span className="chip warn inv-stale" title={count.help}>
            stale cache
          </span>
        )}
      </>
    )
  }
  // Never a dash, never a zero, never blank. On an Arch or Alpine host the true
  // security count is "cannot be answered" and the two must not be confusable.
  return (
    <span
      className={clsx('faint', count.gap === 'unsupported' && 'warn')}
      title={count.help}
    >
      {PATCH_GAP_LABEL[count.gap]}
    </span>
  )
}

export function PatchPanel({ servers }: { servers: Server[] }): React.JSX.Element {
  const facts = useFleet((s) => s.facts)
  const reportFacts = useFleet((s) => s.reportFacts)
  const reportFactsError = useFleet((s) => s.reportFactsError)
  const databases = useApp((s) => s.databases)

  const [selected, setSelected] = useState<Set<string>>(new Set())
  // `all`, not `security`, and it is a deliberate choice rather than a default
  // nobody thought about. apt has NO security-only command — every recipe that
  // claims to have one installs dependencies the operator did not ask for — so
  // a screen that opened on "security only" would exclude the whole Debian
  // family by default and look broken to most of its users. The option is one
  // click away, and picking it explains per host why a host is excluded, which
  // is the honest way to teach that this is a property of the distribution.
  const [scope, setScope] = useState<PatchScope>('all')
  const [waveSize, setWaveSize] = useState(1)
  const [reboot, setReboot] = useState(false)
  const [healthGate, setHealthGate] = useState(true)
  const [phrase, setPhrase] = useState('')
  const [confirming, setConfirming] = useState(false)
  const [busy, setBusy] = useState(false)
  const [running, setRunning] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [results, setResults] = useState<Record<string, JobHostResult>>({})

  const rows = useMemo(
    () =>
      servers.map((s) => {
        const f = facts[s.id]
        return buildPatchRow({
          serverId: s.id,
          serverName: s.name,
          facts: f?.facts ?? null,
          factsAt: f?.at ?? null,
          // An error only explains an ABSENCE. With facts in hand the last good
          // collection is what the row shows, and the failure is reported above
          // the table rather than by blanking a host we still know things about.
          factsError: f?.facts ? null : (f?.error ?? null)
        })
      }),
    [servers, facts]
  )

  const summary = useMemo(() => summarisePatch(rows), [rows])
  const byId = useMemo(() => new Map(rows.map((r) => [r.serverId, r])), [rows])
  const chosen = useMemo(
    () => servers.filter((s) => selected.has(s.id)),
    [servers, selected]
  )

  const plan = useMemo(
    () =>
      planPatch({
        scope,
        hosts: chosen.map((s) => ({
          serverId: s.id,
          serverName: s.name,
          packageManager: byId.get(s.id)?.packageManager ?? null
        })),
        waveSize,
        reboot,
        healthGate,
        // A host that is not asking for a reboot does not get one. "Restart
        // after upgrading" means restart the machines that say they need it,
        // not every machine in the selection.
        rebootWanted: (id) => byId.get(id)?.rebootRequired === true,
        servers: servers.map((s) => ({ id: s.id, name: s.name, route: s.route })),
        databases: databases.map((d) => ({
          id: d.id,
          name: d.name,
          kind: d.kind,
          database: d.database,
          sshServerId: d.sshServerId
        }))
      }),
    [scope, chosen, byId, waveSize, reboot, healthGate, servers, databases]
  )

  // The confirmation is sized against the LARGEST WAVE, not the total — see
  // planJob. Rolling fifty hosts one at a time must not demand a stronger
  // confirmation than doing all fifty at once, which is what sizing on the
  // total would produce.
  const jobPlans = useMemo(
    () => plan.jobs.map((j) => ({ ...j, plan: planJob(j.spec, j.targets) })),
    [plan]
  )
  const strongest = jobPlans.some((j) => j.plan.confirmation.kind === 'type-to-confirm')
    ? 'type-to-confirm'
    : jobPlans.some((j) => j.plan.confirmation.kind === 'confirm')
      ? 'confirm'
      : 'none'
  const blocked = planIsBlocked(plan)
  const waves = useMemo(
    () => planWaves(chosen.map((s) => ({ serverId: s.id, serverName: s.name })), waveSize),
    [chosen, waveSize]
  )

  useEffect(() => {
    if (!window.shellpilot?.jobs) return
    return window.shellpilot.jobs.onProgress((p: JobProgress) => {
      if (p.host) setResults((r) => ({ ...r, [p.host!.serverId]: { ...r[p.host!.serverId], ...p.host! } }))
      if (p.done) setRunning(false)
    })
  }, [])

  const toggle = (id: string): void =>
    setSelected((prev) => {
      const next = new Set(prev)
      if (next.has(id)) next.delete(id)
      else next.add(id)
      return next
    })

  const check = async (): Promise<void> => {
    setBusy(true)
    try {
      if (bridgeHas(window.shellpilot?.fleet as Record<string, unknown> | undefined, 'sampleNow')) {
        await window.shellpilot?.fleet?.sampleNow()
      }
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

  const start = async (): Promise<void> => {
    // The refusal is re-checked at the moment of the press, not only when the
    // plan was rendered: a workspace edit between the two can add a dependent
    // to a host that had none.
    if (planIsBlocked(plan) || jobPlans.length === 0) return
    const confirmedAt = Date.now()
    setConfirming(false)
    setError(null)
    setRunning(true)
    setResults(
      Object.fromEntries(
        plan.hosts
          .filter((h) => h.excluded === null)
          .map((h) => [
            h.serverId,
            { serverId: h.serverId, serverName: h.serverName, state: 'pending' as const }
          ])
      )
    )
    try {
      // ONE JOB PER PACKAGE MANAGER, run in sequence rather than together. A
      // JobSpec is one step list for every host in it, so a mixed estate cannot
      // be one job without the spec lying about what ran where — and
      // `verifyApproval` compares the step TEXT, so a spec whose command was
      // substituted per host could not be checked against the record at all.
      for (const j of jobPlans) {
        const approval = jobApprovalFor(j.spec, j.targets, {
          phrase: j.plan.confirmation.kind === 'type-to-confirm' ? phrase.trim() : null,
          confirmedAt
        })
        await window.shellpilot?.jobs?.run({
          jobId: crypto.randomUUID(),
          spec: j.spec,
          approval,
          targets: j.targets.map((t) => {
            const s = servers.find((x) => x.id === t.serverId)!
            return {
              serverId: t.serverId,
              serverName: t.serverName,
              cohort: t.cohort,
              cfg: {
                sessionId: `patch-${t.serverId}`,
                cols: 80,
                rows: 24,
                serverId: s.id,
                host: s.host,
                port: s.port,
                username: s.username,
                auth: s.auth === 'password' || s.auth === 'agent' ? s.auth : 'key',
                hops: sshHopsFor(s)
              }
            }
          })
        })
      }
    } catch (e) {
      // Without this the panel is wedged: `running` stays true and the reason
      // nothing started is never said out loud. Main's refusals — an unapproved
      // run, a reboot-ordering block it saw and this panel did not — arrive
      // here as a thrown message, and they are the ones most worth printing.
      setError(e instanceof Error ? e.message : String(e))
    } finally {
      setPhrase('')
      setRunning(false)
    }
  }

  const canConfirm = strongest !== 'type-to-confirm' || phrase.trim() === 'RUN'
  const resultRows = Object.values(results)

  return (
    <div className="bc-panel">
      <div className="row" style={{ gap: 8, alignItems: 'center' }}>
        <Wrench size={14} className="faint" />
        <b className="grow">Patch and updates</b>
        <button
          className="btn ghost sm"
          disabled={running || rows.every((r) => !r.hasWork)}
          data-testid="patch-select-needy"
          onClick={() =>
            setSelected(new Set(rows.filter((r) => r.hasWork).map((r) => r.serverId)))
          }
          title="Selects the hosts that report something to install or a reboot they are owed. A host whose counts could not be read is NOT selected: it is unknown, not known to be clean, and picking it would be this screen deciding something for you."
        >
          Select what needs something
        </button>
        <button
          className="btn"
          disabled={busy || servers.length === 0}
          onClick={() => void check()}
          title="Sweeps the estate now and re-reads what has already been collected. Nothing is installed and no package cache is refreshed by this."
        >
          <RefreshCw size={13} className={clsx(busy && 'spin')} /> Check now
        </button>
      </div>

      {/* The refusal, on the screen and not only in the source. An operator who
          is looking for "patch everything nightly" deserves to be told it is not
          here and why, in the place they went looking for it. */}
      <div className="s-desc" data-testid="patch-no-automation">
        {PATCH_NO_AUTOMATION_NOTE}
      </div>

      {summary.withFacts === 0 ? (
        <div className="s-desc">
          <b>No host facts have been collected yet.</b> Update counts come from the same hourly
          sweep the inventory reads. Press <b>Check now</b>, and make sure background checking is
          on in Settings.
        </div>
      ) : (
        <>
          <div
            className={clsx('s-desc', !summary.allClear && 'warn')}
            data-testid="patch-summary"
          >
            {/* `allClear` is FALSE whenever a single host could not answer, and
                that is the whole reason the field exists rather than the panel
                comparing totals to zero. An estate is not clear because the
                hosts that could answer had nothing to say. */}
            {summary.allClear ? <b>All clear. </b> : null}
            {summary.allClearNote}
          </div>

          {summary.securityUnanswerable > 0 && (
            <div className="s-desc warn" data-testid="patch-unanswerable">
              <ShieldQuestion size={12} /> {summary.securityUnanswerable} host
              {summary.securityUnanswerable === 1 ? '' : 's'} can never report a security update
              count, so {summary.securityUnanswerable === 1 ? 'it is' : 'they are'} not in the{' '}
              {summary.securityTotal} above. Arch and Alpine have no security channel at all, and
              dnf cannot answer where the repositories publish no updateinfo. Treat those hosts as
              unknown, never as zero.
            </div>
          )}

          <div className="inv-scroll">
            <table className="table inv-table">
              <thead>
                <tr>
                  <th />
                  <th>Host</th>
                  <th>Packages</th>
                  <th className="num">Updates</th>
                  <th className="num">Security</th>
                  <th>Reboot</th>
                </tr>
              </thead>
              <tbody>
                {rows.map((r) => (
                  <tr key={r.serverId} data-host={r.serverName}>
                    <td>
                      <input
                        type="checkbox"
                        aria-label={`Select ${r.serverName}`}
                        checked={selected.has(r.serverId)}
                        onChange={() => toggle(r.serverId)}
                        disabled={running}
                      />
                    </td>
                    <td data-col="host">{r.serverName}</td>
                    <td data-col="pkg">
                      {r.packageManager ?? (
                        <span className="faint">not identified</span>
                      )}
                    </td>
                    <td data-col="pending" className="num">
                      <Count count={r.pending} />
                    </td>
                    <td data-col="security" className="num">
                      <Count count={r.security} />
                    </td>
                    <td data-col="reboot">
                      {r.rebootGap !== null ? (
                        <span className="faint">{PATCH_GAP_LABEL[r.rebootGap]}</span>
                      ) : r.rebootRequired ? (
                        <span className="warn" title={r.rebootReason ?? undefined}>
                          owed
                        </span>
                      ) : (
                        'no'
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </>
      )}

      {chosen.length > 0 && (
        <div className="bc-controls" style={{ marginTop: 10 }}>
          <div className="row wrap" style={{ gap: 10, alignItems: 'center' }}>
            <label>
              Install{' '}
              <select
                aria-label="What to install"
                value={scope}
                onChange={(e) => setScope(e.target.value as PatchScope)}
                disabled={running}
              >
                <option value="security">security updates only</option>
                <option value="all">all pending updates</option>
              </select>
            </label>
            <label>
              in waves of{' '}
              <input
                type="number"
                aria-label="Hosts per wave"
                min={1}
                max={Math.max(1, chosen.length)}
                value={waveSize}
                onChange={(e) => setWaveSize(Math.max(1, Number(e.target.value) || 1))}
                style={{ width: 56 }}
                disabled={running}
              />
            </label>
            <label>
              <input
                type="checkbox"
                checked={healthGate}
                onChange={(e) => setHealthGate(e.target.checked)}
                disabled={running}
              />{' '}
              hold between waves until the estate looks healthy
            </label>
            <label>
              <input
                type="checkbox"
                checked={reboot}
                onChange={(e) => setReboot(e.target.checked)}
                disabled={running}
              />{' '}
              restart the hosts that say they need it
            </label>
          </div>

          <div className="muted" style={{ fontSize: 11, marginTop: 6 }}>
            {waves.length} wave{waves.length === 1 ? '' : 's'}:{' '}
            {waves.map((w) => `${w.name} (${w.hosts.map((h) => h.serverName).join(', ')})`).join(' → ')}
          </div>

          {/* THE TOPOLOGY HOLE, surfaced rather than papered over. A hop with no
              saved server behind it is invisible to the jump-host graph, so two
              servers can share a bastion the checks below cannot see. Printed
              next to the refusals, where it qualifies them. */}
          {plan.unmatchedNote !== null && (
            <div className="s-desc warn" data-testid="patch-unmatched-hops">
              <AlertTriangle size={12} /> {plan.unmatchedNote}
            </div>
          )}

          {plan.excluded.map((x) => (
            <div key={x.serverId} className="s-desc" data-testid="patch-excluded">
              <b>{x.serverName}</b> is not in this run: {x.reason}
            </div>
          ))}

          {/* A HARD REFUSAL. Not a confirmation, not a checkbox that can be
              ticked past. The run button is disabled while any of these stands,
              and main refuses the same run independently. */}
          {plan.blocks.map((b) => (
            <div key={`${b.kind}:${b.serverId}`} className="s-desc danger" data-testid="patch-block">
              <Ban size={12} /> {b.reason}
            </div>
          ))}

          {jobPlans.map((j) => (
            <div key={j.packageManager} className="s-desc" data-testid="patch-command">
              <b>{j.packageManager}</b> · {j.detail}
              <div className="mono" style={{ marginTop: 4, whiteSpace: 'pre-wrap' }}>
                {j.spec.steps.map((st) => st.command).join('\n')}
              </div>
            </div>
          ))}

          {error !== null && (
            <div className="s-desc danger" data-testid="patch-error">
              {error}
            </div>
          )}

          <div className="row" style={{ gap: 8, marginTop: 8 }}>
            <button
              className="btn primary"
              data-testid="patch-run"
              disabled={running || blocked || jobPlans.length === 0}
              title={blocked ? (blockSummary(plan) ?? undefined) : undefined}
              onClick={() => (strongest === 'none' ? void start() : setConfirming(true))}
            >
              {scope === 'security' ? 'Install security updates' : 'Install updates'} on{' '}
              {plan.hosts.filter((h) => h.excluded === null).length} host
              {plan.hosts.filter((h) => h.excluded === null).length === 1 ? '' : 's'}
            </button>
          </div>

          {confirming && (
            <div className="bc-confirm">
              <div>
                This will run on{' '}
                {plan.hosts.filter((h) => h.excluded === null).map((h) => h.serverName).join(', ')} in{' '}
                {waves.length} wave{waves.length === 1 ? '' : 's'}
                {reboot ? ', restarting the hosts that say they need it' : ''}.
              </div>
              {strongest === 'type-to-confirm' && (
                <input
                  className="input"
                  aria-label="Type RUN to confirm"
                  placeholder="Type RUN to run"
                  value={phrase}
                  onChange={(e) => setPhrase(e.target.value)}
                />
              )}
              <div className="row" style={{ gap: 8 }}>
                <button className="btn" onClick={() => setConfirming(false)}>
                  Cancel
                </button>
                <button
                  className="btn primary"
                  disabled={!canConfirm}
                  data-testid="patch-confirm"
                  onClick={() => void start()}
                >
                  Run
                </button>
              </div>
            </div>
          )}
        </div>
      )}

      {resultRows.length > 0 && (
        <table className="table" style={{ marginTop: 10 }}>
          <tbody>
            {resultRows.map((r) => (
              <tr key={r.serverId} data-result={r.serverName}>
                <td>{r.serverName}</td>
                <td>{r.state}</td>
                <td className="muted">{r.outcome ? JOB_OUTCOME_LABEL[r.outcome] : ''}</td>
                <td className="muted">{r.error ?? ''}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  )
}
