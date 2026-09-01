import { useEffect, useMemo, useRef, useState } from 'react'
import { Play, Square, ScrollText } from 'lucide-react'
import { bridgeOn } from '../../lib/bridge'
import { sshHopsFor } from '../../lib/ssh'
import { clsx } from '../../lib/format'
import { LOG_RING, validateLogSource, type LogLine, type LogSource, type LogTailState } from '../../../../shared/logtail'
import type { Server } from '../../types'

// "A unit failed" is the question the monitor now answers. This is "why".
//
// Several hosts at once on purpose: the useful comparison when a unit fails on
// one box is what the same unit is saying on the box where it is fine.

const HOST_COLOURS = ['var(--accent)', '#d98d4b', '#7ab87a', '#b57edc', '#4bb5d9', '#d97b7b']

export function LogTailPanel({ servers }: { servers: Server[] }): React.JSX.Element {
  const [kind, setKind] = useState<LogSource['kind']>('unit')
  const [target, setTarget] = useState('')
  const [selected, setSelected] = useState<Set<string>>(new Set())
  const [lines, setLines] = useState<LogLine[]>([])
  const [states, setStates] = useState<Record<string, LogTailState>>({})
  const [running, setRunning] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [follow, setFollow] = useState(true)
  const tailId = useRef('')
  // The hosts this tail was started on. A tail is over when all of them have
  // ended, and "all of them" cannot be read off the state map alone: the first
  // host to fail would otherwise look like every host having finished.
  const startedOn = useRef<string[]>([])
  const scroller = useRef<HTMLDivElement | null>(null)

  const eligible = useMemo(() => servers.filter((s) => s.status !== 'offline'), [servers])
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
    if (over) setRunning(false)
  }, [states, running])

  const start = async (): Promise<void> => {
    const source: LogSource = { kind, target }
    const v = validateLogSource(source)
    if (!v.ok) {
      setError(v.error)
      return
    }
    const targets = eligible.filter((s) => selected.has(s.id))
    if (targets.length === 0) {
      setError('Pick at least one server.')
      return
    }
    setError(null)
    setLines([])
    setStates({})
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

  const stop = async (): Promise<void> => {
    try {
      await window.shellpilot?.logtail?.stop(tailId.current)
    } finally {
      // Stop must always leave the panel usable, even if the call itself threw:
      // a Stop button that stays a Stop button is a pane you cannot get out of.
      setRunning(false)
    }
  }

  const toggle = (id: string): void =>
    setSelected((prev) => {
      const next = new Set(prev)
      if (next.has(id)) next.delete(id)
      else next.add(id)
      return next
    })

  const failed = Object.values(states).filter((s) => s.state === 'failed')

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
        <input
          className="input grow mono"
          placeholder={kind === 'unit' ? 'nginx.service' : '/var/log/syslog'}
          value={target}
          onChange={(e) => {
            setTarget(e.target.value)
            setError(null)
          }}
          disabled={running}
        />
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

      {lines.length > 0 && (
        <>
          <div className="row muted" style={{ fontSize: 11, justifyContent: 'space-between', marginTop: 10 }}>
            <span>
              {lines.length}
              {lines.length >= LOG_RING ? `+ lines (oldest dropped past ${LOG_RING})` : ' lines'}
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
            {lines.map((l) => (
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
