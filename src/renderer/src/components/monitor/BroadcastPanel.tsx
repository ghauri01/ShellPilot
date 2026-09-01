import { useEffect, useMemo, useRef, useState } from 'react'
import { Play, Square, Terminal, ChevronRight, TriangleAlert } from 'lucide-react'
import { useApp } from '../../store/app'
import { bridgeOn } from '../../lib/bridge'
import { sshHopsFor } from '../../lib/ssh'
import { clsx } from '../../lib/format'
import { planBroadcast, type BroadcastHostResult, type BroadcastProgress } from '../../../../shared/broadcast'
import type { Server } from '../../types'

// Run one command across many servers.
//
// The approval model is in shared/broadcast.ts. This is where it is enforced,
// because this is where the person is: main runs what it is told, and a second
// copy of the rule there would be a second thing to drift out of step.

function resultTone(r: BroadcastHostResult): string {
  if (r.state === 'failed') return 'danger'
  if (r.state === 'skipped') return 'warn'
  if (r.state === 'ok' && r.exitCode && r.exitCode !== 0) return 'warn'
  return ''
}

function HostResult({ r }: { r: BroadcastHostResult }): React.JSX.Element {
  const [open, setOpen] = useState(false)
  const out = [r.stdout, r.stderr].filter((s) => s && s.trim() !== '').join('\n')
  const summary =
    r.state === 'running'
      ? 'running…'
      : r.state === 'skipped'
        ? 'not run — cancelled'
        : r.state === 'failed'
          ? (r.error ?? 'failed')
          : `exit ${r.exitCode ?? 0}${r.ms !== undefined ? ` · ${(r.ms / 1000).toFixed(1)}s` : ''}`

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
  const finished = rows.filter((r) => r.state !== 'pending' && r.state !== 'running').length

  return (
    <div className="bc-panel">
      <div className="row" style={{ gap: 8, alignItems: 'center' }}>
        <Terminal size={14} className="faint" />
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

      <div className="row wrap" style={{ gap: 6, marginTop: 8 }}>
        {eligible.length === 0 && <span className="faint">No server in this workspace is online.</span>}
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
      {error && <div className="s-desc danger">{error}</div>}

      {plan.risk !== 'ordinary' && command.trim() !== '' && (
        <div className={clsx('s-desc', plan.risk === 'destructive' ? 'danger' : 'warn')}>
          <TriangleAlert size={12} /> This {plan.risk === 'destructive' ? 'destroys state' : 'changes state'} —{' '}
          {plan.reasons.join('; ')}.
        </div>
      )}

      {confirming && (
        <div className="bc-confirm">
          <div className="s-title">
            Run on {targets.length} server{targets.length === 1 ? '' : 's'}?
          </div>
          <div className="s-desc mono">{command}</div>
          <div className="s-desc">{targets.map((t) => t.serverName).join(', ')}</div>
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
            <span>
              {finished} of {rows.length} finished
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
          {rows.map((r) => (
            <HostResult key={r.serverId} r={r} />
          ))}
        </div>
      )}
    </div>
  )
}
