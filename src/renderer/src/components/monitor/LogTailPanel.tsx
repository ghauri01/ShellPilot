import { useEffect, useMemo, useRef, useState } from 'react'
import { Play, Square, ScrollText, Pause, Filter, ShieldAlert } from 'lucide-react'
import { bridgeOn } from '../../lib/bridge'
import { sshHopsFor } from '../../lib/ssh'
import { clsx } from '../../lib/format'
import {
  LOG_ISSUE_HELP,
  LOG_PRIORITIES,
  LOG_RING,
  filterLogLines,
  validateLogSource,
  type LogLine,
  type LogPriority,
  type LogSource,
  type LogTailState,
  type UnitChoice
} from '../../../../shared/logtail'
import type { Server } from '../../types'

// "A unit failed" is the question the monitor now answers. This is "why".
//
// Several hosts at once on purpose: the useful comparison when a unit fails on
// one box is what the same unit is saying on the box where it is fine.
//
// The panel's job beyond drawing lines is to never let an empty pane speak for
// itself. journald answers a read this account may not perform with silence
// rather than an error, `tail -F` on a path that does not exist waits forever,
// and a host with no systemd produces one line of shell output styled as a log
// entry. All three look like "this service is quiet", so all three are named
// here — and when root was used to get an answer, that is said for the tail's
// whole life rather than once, at the top, where it scrolls away in a second.

const HOST_COLOURS = ['var(--accent)', '#d98d4b', '#7ab87a', '#b57edc', '#4bb5d9', '#d97b7b']

/**
 * Pause and resume, which main gained and the preload bridge has not yet been
 * given. Declared here so the call sites are typed and so the exact shape the
 * wiring has to produce is written down in one place rather than inferred from
 * a cast at each call.
 *
 * Both are guarded at the call site: an unwired bridge must say so, not quietly
 * do nothing while the button changes state.
 */
interface PauseBridge {
  pause?: (tailId: string) => Promise<boolean>
  resume?: (tailId: string) => Promise<boolean>
}

/**
 * A jump from somewhere else in the monitor — the failed-unit list is the one
 * that matters — into a tail of that unit on that host.
 *
 * `nonce` rather than a value comparison: jumping to the same unit on the same
 * host twice in a row is a thing someone does, and a prop that only changes
 * when the target changes cannot express it.
 */
export interface LogTailJump {
  kind: LogSource['kind']
  target: string
  serverId: string
  nonce: number
}

export function LogTailPanel({ servers, jump }: { servers: Server[]; jump?: LogTailJump }): React.JSX.Element {
  const [kind, setKind] = useState<LogSource['kind']>('unit')
  const [target, setTarget] = useState('')
  const [priority, setPriority] = useState<LogPriority | ''>('')
  const [since, setSince] = useState('')
  const [filter, setFilter] = useState('')
  const [selected, setSelected] = useState<Set<string>>(new Set())
  const [lines, setLines] = useState<LogLine[]>([])
  const [states, setStates] = useState<Record<string, LogTailState>>({})
  const [running, setRunning] = useState(false)
  const [paused, setPaused] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [follow, setFollow] = useState(true)
  const tailId = useRef('')
  // The hosts this tail was started on. A tail is over when all of them have
  // ended, and "all of them" cannot be read off the state map alone: the first
  // host to fail would otherwise look like every host having finished.
  const startedOn = useRef<string[]>([])
  const scroller = useRef<HTMLDivElement | null>(null)

  const eligible = useMemo(() => servers.filter((s) => s.status !== 'offline'), [servers])
  const cfgFor = (s: Server): unknown => ({
    sessionId: `logtail-units-${s.id}`,
    cols: 80,
    rows: 24,
    serverId: s.id,
    host: s.host,
    port: s.port,
    username: s.username,
    auth: s.auth === 'password' || s.auth === 'agent' ? s.auth : 'key',
    hops: sshHopsFor(s)
  })

  // Units on the first selected host, for the picker. One host, not all of
  // them: the list is nearly identical across an estate and asking every server
  // on every selection change is a lot of exec channels for an autocomplete.
  const [units, setUnits] = useState<UnitChoice[]>([])
  const unitHost = eligible.find((s) => selected.has(s.id))
  useEffect(() => {
    if (kind !== 'unit' || !unitHost) {
      setUnits([])
      return
    }
    let live = true
    void (window.shellpilot?.logtail as { units?: (cfg: unknown) => Promise<{ ok: boolean; units: UnitChoice[] }> })
      ?.units?.(cfgFor(unitHost))
      .then((r) => {
        // A failure here is silent on purpose: the field still works typed, and
        // an error about an autocomplete would sit next to the real diagnosis
        // this panel exists to show.
        if (live && r?.ok) setUnits(r.units)
      })
      .catch(() => {})
    return () => {
      live = false
    }
    // Keyed on the host's ID, not the object. `eligible` is rebuilt whenever
    // any server's status flips, so depending on `unitHost` itself would
    // refetch the unit list on every connect and disconnect in the workspace.
    // The directive has to sit immediately above the code — with the reasoning
    // above it, "next line" was another comment and it suppressed nothing.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [kind, unitHost?.id])

  const colourOf = useMemo(() => {
    const m = new Map<string, string>()
    eligible.forEach((s, i) => m.set(s.id, HOST_COLOURS[i % HOST_COLOURS.length]))
    return m
  }, [eligible])

  useEffect(() => {
    const offLine = bridgeOn('logtail.onLine', window.shellpilot?.logtail?.onLine, (l: LogLine) => {
      if (l.tailId !== tailId.current) return
      // A ring, not an ever-growing array: a chatty host will otherwise put a
      // million nodes in the DOM and the pane stops scrolling.
      setLines((prev) => (prev.length >= LOG_RING ? [...prev.slice(prev.length - LOG_RING + 1), l] : [...prev, l]))
    })
    const offState = bridgeOn('logtail.onState', window.shellpilot?.logtail?.onState, (s: LogTailState) => {
      if (s.tailId !== tailId.current) return
      setStates((prev) => ({ ...prev, [s.serverId]: s }))
    })
    return () => {
      offLine?.()
      offState?.()
    }
  }, [])

  // Stop the remote command when this pane goes away. Without it a following
  // journalctl keeps running on every selected host with nobody reading it.
  useEffect(() => {
    return () => {
      if (tailId.current) void window.shellpilot?.logtail?.stop(tailId.current)
    }
  }, [])

  useEffect(() => {
    if (!follow || !scroller.current) return
    scroller.current.scrollTop = scroller.current.scrollHeight
  }, [lines, follow])

  // A tail can end without anyone pressing Stop: `tail -F` on a path that never
  // appears exits, journalctl dies with the connection. Without this the panel
  // still shows Stop, the inputs stay disabled, and the only way to tail
  // anything again is to press Stop on something that already stopped.
  useEffect(() => {
    if (!running || startedOn.current.length === 0) return
    const over = startedOn.current.every((id) => {
      const s = states[id]
      return s !== undefined && (s.state === 'ended' || s.state === 'failed')
    })
    if (over) {
      setRunning(false)
      setPaused(false)
    }
  }, [states, running])

  const begin = async (source: LogSource, targetIds: string[]): Promise<void> => {
    const v = validateLogSource(source)
    if (!v.ok) {
      setError(v.error)
      return
    }
    const targets = eligible.filter((s) => targetIds.includes(s.id))
    if (targets.length === 0) {
      setError('Pick at least one server.')
      return
    }
    setError(null)
    setLines([])
    setStates({})
    setPaused(false)
    const id = crypto.randomUUID()
    tailId.current = id
    startedOn.current = targets.map((s) => s.id)
    setRunning(true)
    try {
      const res = await window.shellpilot?.logtail?.start(
        id,
        source,
        targets.map((s) => ({
          serverId: s.id,
          serverName: s.name,
          cfg: {
            sessionId: `logtail-${s.id}`,
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
      // `undefined` means the bridge is not there at all, which is a tail that
      // will never produce a line. Treating only `{ok:false}` as failure left
      // the panel showing Stop over a stream that was never going to start.
      if (!res || !res.ok) {
        setError(res?.error ?? 'Could not start the tail.')
        setRunning(false)
      }
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e))
      setRunning(false)
    }
  }

  const sourceFrom = (over: Partial<LogSource> = {}): LogSource => ({
    kind,
    target,
    // journalctl's flags, and only journalctl's: `tail` has no notion of either,
    // and sending them anyway would build a command that cannot run.
    ...(kind === 'unit' && priority !== '' ? { priority } : {}),
    ...(kind === 'unit' && since.trim() !== '' ? { since: since.trim() } : {}),
    ...over
  })

  const start = (): Promise<void> => begin(sourceFrom(), [...selected])

  /**
   * Re-read the same source as root.
   *
   * Only offered when the preflight said root would change the answer AND that
   * `sudo -n` works here, so pressing it cannot produce a password prompt on a
   * host that would ask for one.
   */
  const retryAsRoot = (): Promise<void> => begin(sourceFrom({ sudo: 'always' }), startedOn.current)

  const bridge = window.shellpilot?.logtail as (PauseBridge & { stop?: (id: string) => Promise<boolean> }) | undefined

  const togglePause = async (): Promise<void> => {
    const call = paused ? bridge?.resume : bridge?.pause
    if (typeof call !== 'function') {
      setError('This build cannot pause a tail — the pause bridge is not wired.')
      return
    }
    try {
      await call(tailId.current)
      setPaused((v) => !v)
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e))
    }
  }

  const stop = async (): Promise<void> => {
    try {
      await window.shellpilot?.logtail?.stop(tailId.current)
    } finally {
      // Stop must always leave the panel usable, even if the call itself threw:
      // a Stop button that stays a Stop button is a pane you cannot get out of.
      setRunning(false)
      setPaused(false)
    }
  }

  const toggle = (id: string): void =>
    setSelected((prev) => {
      const next = new Set(prev)
      if (next.has(id)) next.delete(id)
      else next.add(id)
      return next
    })

  // A jump from the failed-unit list: adopt its unit and host, then tail. The
  // point of the jump is that it lands on lines, not on a filled-in form.
  const lastJump = useRef(0)
  useEffect(() => {
    if (!jump || jump.nonce === lastJump.current) return
    lastJump.current = jump.nonce
    setKind(jump.kind)
    setTarget(jump.target)
    setSelected(new Set([jump.serverId]))
    void begin({ kind: jump.kind, target: jump.target }, [jump.serverId])
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [jump])

  const failed = Object.values(states).filter((s) => s.state === 'failed')
  // Anything the preflight found worth saying, plus every host that got in as
  // root. Both are drawn for as long as the tail lives, above the stream rather
  // than inside it, because a notice that scrolls is a notice that is gone.
  const notes = Object.values(states).filter((s) => s.diagnosis && (s.diagnosis.issue !== 'ok' || s.diagnosis.usedSudo))
  const shown = useMemo(() => filterLogLines(lines, filter), [lines, filter])

  return (
    <div className="bc-panel">
      <div className="row" style={{ gap: 8, alignItems: 'center' }}>
        <ScrollText size={14} className="faint" />
        <div className="segment">
          <button className={clsx('seg-btn', kind === 'unit' && 'active')} disabled={running} onClick={() => setKind('unit')}>
            Unit
          </button>
          <button className={clsx('seg-btn', kind === 'file' && 'active')} disabled={running} onClick={() => setKind('file')}>
            File
          </button>
        </div>
        {/* A picker for units, a free field for paths.
            A unit name typed from memory is how you get "systemd does not know
            this unit" — the panel explains that well, but not making the
            mistake beats explaining it. A datalist rather than a select so the
            field is still typable: a host with three hundred services is faster
            to filter than to scroll, and a unit that is masked or not yet
            loaded can still be entered by hand.
            Paths stay a plain field — there is no bounded list to offer. */}
        <input
          className="input grow mono"
          list={kind === 'unit' ? 'sp-unit-list' : undefined}
          placeholder={
            kind === 'unit'
              ? units.length
                ? `nginx.service — ${units.length} on this host`
                : 'nginx.service'
              : '/var/log/syslog'
          }
          value={target}
          onChange={(e) => {
            setTarget(e.target.value)
            setError(null)
          }}
          disabled={running}
        />
        {kind === 'unit' && (
          <datalist id="sp-unit-list">
            {units.map((u) => (
              <option key={u.name} value={u.name}>
                {u.active === 'failed' ? 'failed — ' : ''}
                {u.description}
              </option>
            ))}
          </datalist>
        )}
        {running && (
          <button className="btn" onClick={() => void togglePause()} title="Hold the stream without closing the connection">
            {paused ? <Play size={13} /> : <Pause size={13} />} {paused ? 'Resume' : 'Pause'}
          </button>
        )}
        {running ? (
          <button className="btn danger" onClick={() => void stop()}>
            <Square size={13} /> Stop
          </button>
        ) : (
          <button className="btn primary" disabled={target.trim() === ''} onClick={() => void start()}>
            <Play size={13} /> Tail
          </button>
        )}
      </div>

      {/* -p and --since are the two flags people reach for during an incident,
          and they are journalctl's alone. */}
      {kind === 'unit' && (
        <div className="row" style={{ gap: 8, alignItems: 'center', marginTop: 8 }}>
          <select
            className="select"
            value={priority}
            disabled={running}
            onChange={(e) => setPriority(e.target.value as LogPriority | '')}
            title="journalctl -p: this severity and worse"
          >
            <option value="">Any priority</option>
            {LOG_PRIORITIES.map((p) => (
              <option key={p} value={p}>
                {p} and worse
              </option>
            ))}
          </select>
          <input
            className="input grow"
            placeholder="Since — 2 hours ago, yesterday, 2024-01-01 09:30"
            value={since}
            disabled={running}
            onChange={(e) => {
              setSince(e.target.value)
              setError(null)
            }}
          />
        </div>
      )}

      <div className="row wrap" style={{ gap: 6, marginTop: 8 }}>
        {eligible.map((s) => (
          <button
            key={s.id}
            className={clsx('chip', selected.has(s.id) && 'on')}
            onClick={() => toggle(s.id)}
            disabled={running}
            style={selected.has(s.id) ? { background: colourOf.get(s.id), borderColor: colourOf.get(s.id) } : undefined}
          >
            {s.name}
          </button>
        ))}
      </div>

      {error && <div className="s-desc danger">{error}</div>}
      {/* A host that refused is named rather than silently missing from the
          stream — otherwise its absence reads as "that host is quiet". */}
      {failed.map((f) => (
        <div key={f.serverId} className="s-desc danger">
          {f.serverName}: {f.error ?? 'could not tail'}
        </div>
      ))}

      {notes.map((s) => {
        const d = s.diagnosis!
        return (
          <div key={s.serverId} className="row wrap" style={{ gap: 6, alignItems: 'center', marginTop: 6 }}>
            <span className="chip" style={{ color: colourOf.get(s.serverId) }}>
              {s.serverName}
            </span>
            {/* Root, said for as long as the tail runs. The operator has to be
                able to see at any moment that these lines came from a
                privileged read, not only in the second after they started it. */}
            {d.usedSudo && (
              <span className="chip warn" title="This host refused the unprivileged read, so it was retried with sudo -n">
                <ShieldAlert size={11} /> reading as root
              </span>
            )}
            {/* `waiting` separates "nothing yet, and that may be fine" — a file
                tail -F will pick up, a unit that genuinely has not spoken —
                from "this is wrong", so an empty pane with a good reason is
                not dressed as a failure. */}
            {d.issue !== 'ok' && (
              <span className={clsx('s-desc', !d.waiting && 'danger')}>{LOG_ISSUE_HELP[d.issue]}</span>
            )}
            {/* Only when it would help and cannot prompt. */}
            {!d.usedSudo && d.sudoAvailable && (d.issue === 'journal-unreadable' || d.issue === 'file-denied') && (
              <button className="btn" onClick={() => void retryAsRoot()}>
                Retry as root
              </button>
            )}
          </div>
        )
      })}

      {lines.length > 0 && (
        <>
          <div className="row" style={{ gap: 6, alignItems: 'center', marginTop: 10 }}>
            <Filter size={13} className="faint" />
            <input
              className="input grow mono"
              placeholder="Filter — text, /regex/, or !exclude"
              value={filter}
              onChange={(e) => setFilter(e.target.value)}
            />
          </div>
          <div className="row muted" style={{ fontSize: 11, justifyContent: 'space-between', marginTop: 8 }}>
            <span>
              {filter.trim() === '' ? (
                <>
                  {lines.length}
                  {lines.length >= LOG_RING ? `+ lines (oldest dropped past ${LOG_RING})` : ' lines'}
                </>
              ) : (
                // The denominator matters: "12 lines" under a filter reads as a
                // quiet host unless it says what it is 12 of.
                `${shown.length} of ${lines.length} lines match`
              )}
              {paused && ' — paused, the host is still being followed'}
            </span>
            <label className="row" style={{ gap: 6 }}>
              <span
                className={clsx('switch', follow && 'on')}
                onClick={() => setFollow((v) => !v)}
                style={{ transform: 'scale(0.8)' }}
              />
              Follow
            </label>
          </div>
          <div className="bc-out log-stream" ref={scroller} style={{ maxHeight: 360, marginLeft: 0 }}>
            {shown.map((l) => (
              <div key={`${l.serverId}:${l.seq}`} className={clsx('log-line', l.isError && 'danger')}>
                <span className="log-host" style={{ color: colourOf.get(l.serverId) }}>
                  {l.serverName}
                </span>
                <span>{l.text}</span>
              </div>
            ))}
          </div>
        </>
      )}
    </div>
  )
}
