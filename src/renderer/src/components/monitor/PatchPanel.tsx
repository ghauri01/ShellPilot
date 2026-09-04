import { useEffect, useMemo, useState } from 'react'
import { AlertTriangle, Ban, RefreshCw, ShieldQuestion, Wrench } from 'lucide-react'
import { useFleet } from '../../store/fleet'
import { useApp } from '../../store/app'
import { bridgeHas } from '../../lib/bridge'
import { openSettings } from '../../store/nav'
import { clsx } from '../../lib/format'
import { sshHopsFor } from '../../lib/ssh'
import {
  GATE_SAMPLER_NOTE,
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
// FOUR THINGS THIS SCREEN REFUSES TO DO, all of them argued in
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
//  4. It will not offer a safeguard that cannot work. The wave health gate
//     reads the fleet sampler's cache; with background checking off there is
//     nothing to read, so the checkbox is withheld and the reason names the
//     switch. A control that looks like extra care and behaves like a
//     five-minute silence followed by a halt is worse than no control.
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
  // The gate's one dependency, read here rather than assumed. See `gateUsable`.
  const samplingEnabled = useApp((s) => s.settings.fleetSamplingEnabled)

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
  // Wanted, not effective. `gateUsable` below decides whether it can be had:
  // the gate reads the fleet sampler's cache, and the sampler is off by
  // default, so a gate ticked in that state is not a stricter run — it is a run
  // that applies wave 1, waits GATE_WAIT_MS for a health observation that no
  // process is producing, and halts with every remaining host "not run".
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

  // A gate that CANNOT PASS is worse than no gate: it looks like extra care and
  // behaves like a five-minute silence followed by a halt. `gateHealthFor` in
  // main reads the fleet sampler's cache and nothing else — deliberately, so
  // there is one implementation of "is this host healthy" — which means with
  // background checking off every host is `sampledAt: null`, every wave is
  // `stale`, and the run stops after wave 1 no matter how healthy the estate
  // is. So the checkbox is not merely warned about, it is withheld, and the
  // note says which switch to go and turn on.
  const gateUsable = samplingEnabled
  const gateOn = healthGate && gateUsable

  // Hosts where at least one question had no answer: not selected by "select
  // what needs something" (they are unknown, not known to need something) but
  // offered explicitly, because silently omitting the hosts nobody can vouch
  // for is how they stay unlooked-at.
  const needy = useMemo(() => rows.filter((r) => r.hasWork === 'yes'), [rows])
  const unanswerable = useMemo(() => rows.filter((r) => r.hasWork === 'unknown'), [rows])
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
        healthGate: gateOn,
        // A host that is not asking for a reboot does not get one. "Restart
        // after upgrading" means restart the machines that say they need it,
        // not every machine in the selection.
        rebootWanted: (id) => byId.get(id)?.rebootRequired === true,
        // host/port, not just id/name/route. A hop that names no saved server
        // is still an address, and a saved server is still an address; when
        // they match, the "invisible" bastion is sitting in this very list
        // under another name. Dropping them here would hand buildTopology a
        // graph that cannot express the question.
        servers: servers.map((s) => ({
          id: s.id,
          name: s.name,
          host: s.host,
          port: s.port,
          route: s.route
        })),
        databases: databases.map((d) => ({
          id: d.id,
          name: d.name,
          kind: d.kind,
          database: d.database,
          sshServerId: d.sshServerId
        }))
      }),
    [scope, chosen, byId, waveSize, reboot, gateOn, servers, databases]
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
      <div className="panel-head">
        <span className="panel-head-icon">
          <Wrench size={14} />
        </span>
        <h2 className="ui-section-title">Patch and updates</h2>
        <p className="ui-note panel-head-purpose">
          Choose the servers to update, review the plan, then run it in waves. Nothing installs
          until you confirm, and there is no unattended mode.
        </p>
        <div className="panel-head-actions">
        <button
          className="btn ghost sm"
          disabled={running || needy.length === 0}
          data-testid="patch-select-needy"
          onClick={() => setSelected(new Set(needy.map((r) => r.serverId)))}
          title="Selects the servers that report something to install or a reboot they are owed. A server whose counts could not be read is NOT selected here: it is unknown, not known to need something, and picking it would be this screen deciding something for you. The button beside this one offers those servers separately."
        >
          Select what needs something
        </button>
        {/* The hosts nobody can vouch for, OFFERED rather than omitted. They
            are not selected by the button above — "unknown" is not "needs
            something" and this screen does not decide that for anyone — but
            leaving them out with no mention was the same silence in the other
            direction, and on an estate where every host is unanswerable it left
            a disabled button next to a summary saying the opposite. */}
        {unanswerable.length > 0 && (
          <button
            className="btn ghost sm warn"
            disabled={running}
            data-testid="patch-select-unknown"
            onClick={() =>
              setSelected((prev) => new Set([...prev, ...unanswerable.map((r) => r.serverId)]))
            }
            title="Adds the servers where at least one question had no answer — a count that could not be read, a security channel that does not exist, a reboot flag nothing could check. They are unknown, not known to be clean, and nothing here can tell you which. Adding them to the selection is a decision for you to make deliberately."
          >
            <ShieldQuestion size={13} /> Add {unanswerable.length} that could not answer
          </button>
        )}
        <button
          className="btn primary"
          disabled={busy || servers.length === 0}
          onClick={() => void check()}
          title="Sweeps the estate now and re-reads what has already been collected. Nothing is installed and no package cache is refreshed by this."
        >
          <RefreshCw size={13} className={clsx(busy && 'spin')} /> Check now
        </button>
        </div>
      </div>

      {/* The refusal, on the screen and not only in the source. An operator who
          is looking for "patch everything nightly" deserves to be told it is not
          here and why, in the place they went looking for it. */}
      <div className="panel-note" data-testid="patch-no-automation">
        {PATCH_NO_AUTOMATION_NOTE}
      </div>

      {summary.withFacts === 0 ? (
        <div className="panel-empty">
          <p className="panel-empty-title">No server facts have been collected yet.</p>
          <p className="panel-empty-body">
            Update counts come from the same hourly sweep the inventory reads. Press{' '}
            <b>Check now</b>, and make sure background checking is on in Settings.
          </p>
          <div className="panel-empty-actions">
            <button className="btn ghost sm" onClick={() => openSettings('monitoring')}>
              Open Monitoring settings
            </button>
          </div>
        </div>
      ) : (
        <>
          <div
            // `allClear` false covers both "something needs installing" and
            // "a host could not answer", so the generic attention role rather
            // than the unknown one — the unanswerable count gets its own
            // `is-unknown` note directly below, where it can be precise.
            className={clsx('panel-note', summary.allClear ? 'is-ok' : 'is-watch')}
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
            <div className="panel-note is-unknown" data-testid="patch-unanswerable">
              <ShieldQuestion size={12} /> {summary.securityUnanswerable} server
              {summary.securityUnanswerable === 1 ? '' : 's'} can never report a security update
              count, so {summary.securityUnanswerable === 1 ? 'it is' : 'they are'} not in the{' '}
              {summary.securityTotal} above. Arch and Alpine have no security channel at all, and
              dnf cannot answer where the repositories publish no updateinfo. Treat those servers as
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
                        <span className="state-watch" title={r.rebootReason ?? undefined}>
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
                aria-label="Servers per wave"
                min={1}
                max={Math.max(1, chosen.length)}
                value={waveSize}
                onChange={(e) => setWaveSize(Math.max(1, Number(e.target.value) || 1))}
                style={{ width: 56 }}
                disabled={running}
              />
            </label>
            <label title={gateUsable ? undefined : GATE_SAMPLER_NOTE}>
              <input
                type="checkbox"
                checked={gateOn}
                onChange={(e) => setHealthGate(e.target.checked)}
                disabled={running || !gateUsable}
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
              restart the servers that say they need it
            </label>
          </div>

          {/* Said where the checkbox is, not in a log five minutes after the
              run halted. A disabled control with no explanation is indistinguishable
              from a broken one. */}
          {!gateUsable && (
            <div className="panel-note is-unknown" data-testid="patch-gate-unavailable">
              <AlertTriangle size={12} /> The wave gate is unavailable. {GATE_SAMPLER_NOTE} Until it
              is on, the waves below roll on one after another with nothing checking the estate in
              between — run them in small waves and watch, or turn the sampler on first.
            </div>
          )}

          <div className="panel-stats">
            {waves.length} wave{waves.length === 1 ? '' : 's'}:{' '}
            {waves.map((w) => `${w.name} (${w.hosts.map((h) => h.serverName).join(', ')})`).join(' → ')}
          </div>

          {/* THE TOPOLOGY HOLE, surfaced rather than papered over. A hop with no
              saved server behind it is invisible to the jump-host graph, so two
              servers can share a bastion the checks below cannot see. Printed
              next to the refusals, where it qualifies them. */}
          {plan.unmatchedNote !== null && (
            <div className="panel-note is-unknown" data-testid="patch-unmatched-hops">
              <AlertTriangle size={12} /> {plan.unmatchedNote}
            </div>
          )}

          {plan.excluded.map((x) => (
            <div key={x.serverId} className="panel-note" data-testid="patch-excluded">
              <b>{x.serverName}</b> is not in this run: {x.reason}
            </div>
          ))}

          {/* A HARD REFUSAL. Not a confirmation, not a checkbox that can be
              ticked past. The run button is disabled while any of these stands,
              and main refuses the same run independently. */}
          {plan.blocks.map((b) => (
            <div key={`${b.kind}:${b.serverId}`} className="panel-note is-alarm" data-testid="patch-block">
              <Ban size={12} /> {b.reason}
            </div>
          ))}

          {jobPlans.map((j) => (
            <div key={j.packageManager} className="panel-note" data-testid="patch-command">
              <b>{j.packageManager}</b> · {j.detail}
              <div className="mono" style={{ marginTop: 4, whiteSpace: 'pre-wrap' }}>
                {j.spec.steps.map((st) => st.command).join('\n')}
              </div>
            </div>
          ))}

          {error !== null && (
            <div className="panel-note is-alarm" data-testid="patch-error">
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
              {plan.hosts.filter((h) => h.excluded === null).length} server
              {plan.hosts.filter((h) => h.excluded === null).length === 1 ? '' : 's'}
            </button>
          </div>

          {confirming && (
            <div className="bc-confirm">
              <div>
                This will run on{' '}
                {plan.hosts.filter((h) => h.excluded === null).map((h) => h.serverName).join(', ')} in{' '}
                {waves.length} wave{waves.length === 1 ? '' : 's'}
                {reboot ? ', restarting the servers that say they need it' : ''}.
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
