import { useEffect, useMemo, useRef, useState } from 'react'
import { Play, Square, Terminal, ChevronRight, TriangleAlert } from 'lucide-react'
import { useApp } from '../../store/app'
import { bridgeOn } from '../../lib/bridge'
import { sshHopsFor } from '../../lib/ssh'
import { clsx } from '../../lib/format'
import {
  BROADCAST_OUTCOME_LABEL,
  approvalFor,
  classifyBroadcastResult,
  planBroadcast,
  summariseBroadcast,
  type BroadcastHostOutcome,
  type BroadcastHostResult,
  type BroadcastProgress
} from '../../../../shared/broadcast'
import type { Server } from '../../types'

// Run one command across many servers.
//
// The approval model is in shared/broadcast.ts. This is where it is ASKED,
// because this is where the person is — and since B3 it is no longer the only
// place it is enforced. This panel mints a CommandApproval from the plan it
// showed and the phrase that was typed, sends it with the run, and main
// re-derives the same plan over the same request and refuses if the two
// disagree.
//
// That reverses the note this comment used to carry ("a second copy of the rule
// in main would be a second thing to drift"), and the reasoning is at the foot
// of shared/broadcast.ts. In short: the renderer is where the user is, and it
// is also gone by the time a durable job needs re-authorising — so the plan has
// to become a record rather than a value in a useMemo, and a record nobody
// checks is a comment.

// The runner classifies; this is the fallback for a result that predates the
// field, and it keeps the panel from having a second opinion about what a
// result means.
const outcomeOf = (r: BroadcastHostResult): BroadcastHostOutcome | null =>
  r.outcome ?? classifyBroadcastResult(r)

// Tone by outcome, not by exit code.
//
// `missing-command` is amber rather than red on purpose: on a fan-out it is
// usually not a fault at all, it is the answer ("these four boxes do not run
// docker"). Colouring it the same as an unreachable host would make the one
// row that needs someone to go and look indistinguishable from four that do
// not.
// The four status roles rather than the three colour names. `cancelled` moves
// off the amber the other four shared: a host that never ran is an outcome
// nobody has, which is a different thing from a host that ran and refused, and
// the two were the same colour. (They were in fact the same NO colour — bare
// `.warn` and `.danger` have never had a rule in global.css.)
const TONE: Record<BroadcastHostOutcome, string> = {
  ok: 'state-ok',
  nonzero: 'state-watch',
  'missing-command': 'state-watch',
  'permission-denied': 'state-watch',
  timeout: 'state-alarm',
  unreachable: 'state-alarm',
  cancelled: 'state-unknown'
}

function resultTone(r: BroadcastHostResult): string {
  const o = outcomeOf(r)
  return o === null ? '' : TONE[o]
}

function HostResult({ r }: { r: BroadcastHostResult }): React.JSX.Element {
  const [open, setOpen] = useState(false)
  const out = [r.stdout, r.stderr].filter((s) => s && s.trim() !== '').join('\n')
  const outcome = outcomeOf(r)
  const took = r.ms !== undefined ? ` · ${(r.ms / 1000).toFixed(1)}s` : ''
  const summary =
    r.state === 'running'
      ? 'running…'
      : outcome === null
        ? 'waiting…'
        : outcome === 'cancelled'
          ? 'not run — cancelled'
          : outcome === 'unreachable' || outcome === 'timeout'
            ? (r.error ?? BROADCAST_OUTCOME_LABEL[outcome])
            : // The exit code stays visible next to the category. The category
              // is what makes the list scannable; the code is what someone
              // checks when they do not believe it.
              `${BROADCAST_OUTCOME_LABEL[outcome]} · exit ${r.exitCode ?? 0}${took}`

  return (
    <div className="bc-host">
      <button className="bc-host-head" onClick={() => setOpen((v) => !v)} disabled={!out}>
        <ChevronRight size={13} className={clsx('chev', open && 'open')} style={{ opacity: out ? 1 : 0.25 }} />
        <b>{r.serverName}</b>
        <span className={clsx('grow faint', resultTone(r))}>{summary}</span>
        {r.truncated && <span className="chip warn">output cut</span>}
      </button>
      {open && out && <pre className="bc-out">{out}</pre>}
    </div>
  )
}

// A run outlives this panel. Switching activity unmounts it while main is still
// working through the hosts, and with the run id held only in component state
// the remounted panel could neither show the run nor stop it: N hosts still
// executing and no way to say stop. Module scope rather than the app store
// because nothing outside this file has any use for it.
let liveRun: { runId: string; results: Record<string, BroadcastHostResult> } | null = null

export function BroadcastPanel({ servers }: { servers: Server[] }): React.JSX.Element {
  const [command, setCommand] = useState('')
  const [selected, setSelected] = useState<Set<string>>(new Set())
  const [phrase, setPhrase] = useState('')
  const [confirming, setConfirming] = useState(false)
  const [running, setRunning] = useState(liveRun !== null)
  const [results, setResults] = useState<Record<string, BroadcastHostResult>>(() => liveRun?.results ?? {})
  const [error, setError] = useState<string | null>(null)
  const runId = useRef<string>(liveRun?.runId ?? '')
  const setActivity = useApp((s) => s.setActivity)

  // Only servers that are actually reachable can be targets. Offering an
  // offline host is offering a guaranteed failure row.
  const eligible = useMemo(() => servers.filter((s) => s.status !== 'offline'), [servers])
  // The chosen servers, not just their ids: the cfg handed to main is built
  // from these rows, and looking each one up again by id afterwards is how a
  // lookup ends up with a `!` on it that nobody can prove.
  const chosen = useMemo(() => eligible.filter((s) => selected.has(s.id)), [eligible, selected])
  const targets = useMemo(() => chosen.map((s) => ({ serverId: s.id, serverName: s.name })), [chosen])
  const plan = useMemo(() => planBroadcast(command, targets), [command, targets])

  useEffect(() => {
    return bridgeOn('broadcast.onProgress', window.shellpilot?.broadcast?.onProgress, (p: BroadcastProgress) => {
      if (p.runId !== runId.current) return
      if (p.done) {
        liveRun = null
        setRunning(false)
        return
      }
      setResults((prev) => ({ ...prev, [p.host.serverId]: p.host }))
    })
  }, [])

  // Mirrored so a remount can show what has arrived so far.
  useEffect(() => {
    if (liveRun) liveRun.results = results
  }, [results])

  const toggle = (id: string): void =>
    setSelected((prev) => {
      const next = new Set(prev)
      if (next.has(id)) next.delete(id)
      else next.add(id)
      return next
    })

  const start = async (): Promise<void> => {
    if (targets.length === 0 || command.trim() === '') return
    // B3: the record is minted HERE, from the plan this panel just showed the
    // user and the phrase they actually typed — before the state that holds
    // either is cleared. Until B3 this plan was computed in a useMemo, used to
    // gate a dialog, and thrown away: `broadcast:run` took a command and a
    // target list, and main had no idea whether anybody had agreed to either.
    //
    // Minted from `plan` and `phrase` rather than re-derived, so what is
    // recorded is what was on screen. Main re-derives it independently and
    // refuses if the two disagree, which is the check — a record the sender
    // also grades would grade nothing.
    const approval = approvalFor({
      surface: 'broadcast',
      commands: [command],
      targets,
      plan,
      phrase: plan.confirmation.kind === 'type-to-confirm' ? phrase.trim() : null,
      confirmedAt: Date.now()
    })
    setConfirming(false)
    setPhrase('')
    setError(null)
    setRunning(true)
    // Seeded pending so every selected host has a row from the first frame.
    // A list that fills in as results arrive hides which hosts are still to
    // come, which is the thing you want to know while it is running.
    const seeded = Object.fromEntries(
      targets.map((t) => [t.serverId, { ...t, state: 'pending' as const }])
    )
    setResults(seeded)
    const id = crypto.randomUUID()
    runId.current = id
    liveRun = { runId: id, results: seeded }
    try {
      await window.shellpilot?.broadcast?.run({
        runId: id,
        command,
        approval,
        targets: chosen.map((s) => ({
          serverId: s.id,
          serverName: s.name,
          cfg: {
            sessionId: `broadcast-${s.id}`,
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
      })
    } catch (e) {
      // Without this the panel is wedged: `running` stays true, so the only
      // control on screen is a Stop button for a run that never started, and
      // the reason it did not start is never said out loud.
      setError(e instanceof Error ? e.message : String(e))
    } finally {
      // Also clears a run whose `done` event arrived while this panel was
      // unmounted — otherwise a remount would show a finished run as live.
      liveRun = null
      setRunning(false)
    }
  }

  const attempt = (): void => {
    if (plan.confirmation.kind === 'none') void start()
    else setConfirming(true)
  }

  const canConfirm =
    plan.confirmation.kind !== 'type-to-confirm' || phrase.trim() === plan.confirmation.phrase

  const rows = Object.values(results)
  const summary = summariseBroadcast(rows)
  const finished = rows.length - summary.running
  // Only the categories that actually occurred, in a fixed order so the line
  // does not reshuffle itself as results land. `ok` is included even at zero
  // once something has finished: "0 ok" is the most important thing that line
  // can say, and dropping it because the count is zero is the one case where
  // its absence reads as reassurance.
  const chips = ([
    'ok',
    'nonzero',
    'missing-command',
    'permission-denied',
    'timeout',
    'unreachable',
    'cancelled'
  ] as BroadcastHostOutcome[])
    .filter((o) => summary.counts[o] > 0 || (o === 'ok' && finished > 0))
    .map((o) => ({ o, n: summary.counts[o] }))
  const refused = rows.filter((r) => outcomeOf(r) === 'permission-denied')

  return (
    <div className="bc-panel">
      <div className="panel-head no-purpose">
        <span className="panel-head-icon">
          <Terminal size={14} />
        </span>
        <h2 className="ui-section-title">Run a command</h2>
        <div className="panel-head-actions" style={{ flexWrap: 'nowrap', minWidth: 0, flex: 1 }}>
        <input
          className="input grow mono"
          placeholder="Command to run on the selected servers…"
          value={command}
          onChange={(e) => setCommand(e.target.value)}
          disabled={running}
        />
        {running ? (
          <button
            className="btn danger"
            onClick={() => void window.shellpilot?.broadcast?.cancel(runId.current)}
            title="Hosts that have not started will not start. A host already running is left to finish — killing it mid-write is how a change ends up half applied."
          >
            <Square size={13} /> Stop
          </button>
        ) : (
          <button className="btn primary" disabled={targets.length === 0 || command.trim() === ''} onClick={attempt}>
            <Play size={13} /> Run
          </button>
        )}
        </div>
      </div>

      {/* The purpose line, under the composer rather than above it: the field
          is what the eye should reach first here, unlike every read-only panel
          where the title is. */}
      <p className="ui-note">
        Runs one command on every server you pick, one connection each. Nothing runs until you
        confirm, and a command that changes or destroys state says so before the dialog opens.
      </p>

      <div className="row wrap" style={{ gap: 6, marginTop: 8 }}>
        {eligible.length === 0 && (
          <span className="state-unknown">No server in this workspace is online.</span>
        )}
        {eligible.map((s) => (
          <button
            key={s.id}
            className={clsx('chip', selected.has(s.id) && 'on')}
            onClick={() => toggle(s.id)}
            disabled={running}
          >
            {s.name}
          </button>
        ))}
        {eligible.length > 1 && (
          <button
            className="btn ghost sm"
            disabled={running}
            onClick={() =>
              setSelected((p) => (p.size === eligible.length ? new Set() : new Set(eligible.map((s) => s.id))))
            }
          >
            {selected.size === eligible.length ? 'Clear' : 'Select all'}
          </button>
        )}
      </div>

      {/* The reasons are shown before the run, not inside the dialog only:
          someone reading the command should see how it was read without
          having to press Run to find out. */}
      {error && <div className="panel-note is-alarm">{error}</div>}

      {plan.risk !== 'ordinary' && command.trim() !== '' && (
        <div className={clsx('panel-note', plan.risk === 'destructive' ? 'is-alarm' : 'is-watch')}>
          <TriangleAlert size={12} /> This {plan.risk === 'destructive' ? 'destroys state' : 'changes state'} —{' '}
          {plan.reasons.join('; ')}.
        </div>
      )}

      {confirming && (
        <div className="bc-confirm">
          <div className="panel-subtitle">
            Run on {targets.length} server{targets.length === 1 ? '' : 's'}?
          </div>
          <div className="panel-note mono">{command}</div>
          <div className="panel-note">{targets.map((t) => t.serverName).join(', ')}</div>
          {plan.confirmation.kind === 'type-to-confirm' && (
            <div className="input-group" style={{ marginTop: 6 }}>
              <input
                className="input"
                placeholder={`Type ${plan.confirmation.phrase} to run`}
                value={phrase}
                onChange={(e) => setPhrase(e.target.value)}
                autoFocus
              />
            </div>
          )}
          <div className="row" style={{ gap: 8, marginTop: 8 }}>
            <button className="btn primary" disabled={!canConfirm} onClick={() => void start()}>
              Run
            </button>
            <button className="btn ghost" onClick={() => { setConfirming(false); setPhrase('') }}>
              Cancel
            </button>
          </div>
        </div>
      )}

      {rows.length > 0 && (
        <div className="bc-results">
          <div className="row muted" style={{ fontSize: 11, justifyContent: 'space-between' }}>
            <span className="row" style={{ gap: 8, flexWrap: 'wrap' }}>
              <span>
                {finished} of {rows.length} finished
              </span>
              {/* Fifteen hosts is a list nobody reads top to bottom. This is
                  the line that says whether they need to. */}
              {chips.map(({ o, n }) => (
                <span key={o} className={clsx(TONE[o])}>
                  {n} {BROADCAST_OUTCOME_LABEL[o]}
                </span>
              ))}
            </span>
            {/* Not while it is running: this navigates away, which unmounts
                the panel and takes the results with it — including the Stop
                button for hosts that are still executing. */}
            {!running && (
              <button className="btn ghost sm" onClick={() => setActivity('connections')}>
                Open a terminal
              </button>
            )}
          </div>
          {/* Said once, here, rather than on each refused row: the decision
              is one decision. Escalation is deliberately the operator's to
              make — see the note at the end of shared/broadcast.ts. Re-running
              this as root on their behalf would raise the blast radius after
              they had already approved it at a lower one. */}
          {refused.length > 0 && (
            <div className="panel-note is-watch">
              {refused.length === 1
                ? `${refused[0].serverName} refused this command for this account.`
                : `${refused.length} hosts refused this command for this account.`}{' '}
              Nothing was retried as root. Prefixing the command with{' '}
              <span className="mono">sudo</span> will re-run it here — and will ask you to confirm
              again, because running as root across several hosts is a bigger thing than running it
              as yourself.
            </div>
          )}
          {rows.map((r) => (
            <HostResult key={r.serverId} r={r} />
          ))}
        </div>
      )}

      {/* The state this panel never had. With servers online and nothing run
          yet it rendered a command field, a row of chips and nothing else — no
          statement of the order the two are meant to be used in, and no hint
          that picking a host is a separate step from typing the command. */}
      {rows.length === 0 && !confirming && eligible.length > 0 && (
        <div className="panel-empty">
          <p className="panel-empty-title">Nothing has been run yet.</p>
          <p className="panel-empty-body">
            {targets.length === 0
              ? 'Pick the servers to run on from the row above, type a command, then press Run.'
              : `${targets.length} server${targets.length === 1 ? '' : 's'} selected. Type a command above, then press Run.`}{' '}
            Results appear here, one block per host, and a host that refuses is reported rather
            than retried as root.
          </p>
        </div>
      )}
    </div>
  )
}
