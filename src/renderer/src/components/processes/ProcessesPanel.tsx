import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { Activity, Play, Plus, RotateCw, Square, Trash2 } from 'lucide-react'
import { clsx } from '../../lib/format'
import {
  PROCESS_LOG_PAGE,
  processDraftProblem
} from '../../../../shared/processes'
import type {
  ManagedProcessView,
  ProcessEnvVar,
  ProcessDraft,
  ProcessLogLine,
  ProcessState,
  ProcessStatus,
  ProcessesBridge
} from '../../../../shared/processes'

// Roadmap item 1 — the local half. See src/shared/processes.ts for why there
// is no remote half, no auto-start, and no environment VALUE anywhere in this
// file.
//
// ---------------------------------------------------------------------------
// IT POLLS. THERE IS NO LOG STREAM AND NO STATUS EVENT.
// ---------------------------------------------------------------------------
//
// A crash-looping process writes as fast as the OS will let it, and a push
// channel repaints this at exactly that rate. The ring in main is bounded, but
// a stream out of a bounded ring is not — the bound is on what is HELD, not on
// what is SENT. Polling makes the cost of a process that has lost its mind one
// capped page per interval, whatever it is doing, and it makes that cost
// visible in one constant rather than emergent from how fast a child writes.
//
// The interval only runs while this tab is the one on screen, and only while
// the window has focus: FleetMonitor keeps every panel mounted and hidden, so
// an unconditional interval here would be a poll per second for a tab nobody
// is looking at.

/** How often the visible tab asks. Fast enough that Start feels immediate,
 *  slow enough that it is not a busy loop. */
const POLL_MS = 1_500

/**
 * The bridge, or null when this build's main process has none.
 *
 * Checked at runtime rather than assumed, the same way `CronPanel.editBridge`
 * is: a main process that has not been taught these channels answers nothing,
 * and a button that silently does nothing is worse than an absent one.
 */
function processBridge(): ProcessesBridge | null {
  const p = (window.shellpilot as { processes?: Partial<ProcessesBridge> } | undefined)?.processes
  return p && typeof p.list === 'function' && typeof p.start === 'function'
    ? (p as ProcessesBridge)
    : null
}

const STATE_LABEL: Record<ProcessState, string> = {
  stopped: 'Stopped',
  starting: 'Starting',
  running: 'Running',
  'crash-looped': 'Crash-looped',
  failed: 'Failed'
}

const STATE_CLASS: Record<ProcessState, string> = {
  stopped: '',
  starting: 'warn',
  running: 'ok',
  'crash-looped': 'danger',
  failed: 'danger'
}

const emptyDraft = (): ProcessDraft => ({
  name: '',
  command: '',
  args: [],
  cwd: '',
  env: [],
  restart: 'on-failure',
  readiness: { kind: 'spawned' }
})

export function ProcessesPanel(): React.JSX.Element {
  const bridge = useMemo(processBridge, [])
  const [rows, setRows] = useState<ManagedProcessView[]>([])
  const [status, setStatus] = useState<Record<string, ProcessStatus>>({})
  const [openId, setOpenId] = useState<string | null>(null)
  const [logs, setLogs] = useState<ProcessLogLine[]>([])
  const [busy, setBusy] = useState<string | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [adding, setAdding] = useState(false)
  const [draft, setDraft] = useState<ProcessDraft>(emptyDraft)
  const [argsText, setArgsText] = useState('')

  // Held in a ref so the polling effect does not re-subscribe every time the
  // open row changes, which would restart the interval on each keystroke.
  const openRef = useRef<string | null>(null)
  openRef.current = openId

  const refresh = useCallback(async (): Promise<void> => {
    if (!bridge) return
    try {
      const [list, statuses] = await Promise.all([bridge.list(), bridge.status()])
      setRows(list)
      setStatus(Object.fromEntries(statuses.map((s) => [s.id, s])))
      const open = openRef.current
      // One capped page, and only for the row that is actually open. A closed
      // drawer costs nothing.
      setLogs(open ? await bridge.logs(open, PROCESS_LOG_PAGE) : [])
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e))
    }
  }, [bridge])

  useEffect(() => {
    void refresh()
  }, [refresh, openId])

  useEffect(() => {
    if (!bridge) return
    const id = setInterval(() => {
      // Nothing while the window is in the background. A supervised process is
      // watched by main whether or not anybody is looking at it; this poll only
      // exists to redraw a table.
      if (document.visibilityState === 'visible') void refresh()
    }, POLL_MS)
    return () => clearInterval(id)
  }, [bridge, refresh])

  const act = async (id: string, fn: () => Promise<unknown>): Promise<void> => {
    setBusy(id)
    setError(null)
    try {
      await fn()
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e))
    } finally {
      setBusy(null)
      await refresh()
    }
  }

  const setEnv = (i: number, next: ProcessEnvVar): void => {
    setDraft((d) => ({ ...d, env: d.env.map((e, j) => (j === i ? next : e)) }))
  }

  const submit = async (): Promise<void> => {
    if (!bridge) return
    const next: ProcessDraft = {
      ...draft,
      name: draft.name.trim(),
      command: draft.command.trim(),
      cwd: draft.cwd.trim(),
      // Whitespace-separated, which is a deliberate limit rather than a
      // shortcut: an argument containing a space needs quoting, quoting needs
      // a parser, and a parser here would be a shell — which is the one thing
      // this feature does not have. Nothing is ever handed to `sh`.
      args: argsText.split(/\s+/).filter(Boolean)
    }
    const problem = processDraftProblem(next)
    if (problem) {
      setError(problem)
      return
    }
    setError(null)
    try {
      await bridge.create(next)
      setAdding(false)
      setDraft(emptyDraft())
      setArgsText('')
      await refresh()
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e))
    }
  }

  if (!bridge) {
    return (
      <div className="panel-body">
        <div className="s-desc">
          This build of ShellPilot cannot supervise local processes.
        </div>
      </div>
    )
  }

  return (
    <div className="panel-body">
      <div className="content-header" style={{ paddingLeft: 0, paddingRight: 0 }}>
        <div>
          <h2 style={{ margin: 0, fontSize: 15 }}>Local processes</h2>
          <div className="sub">
            On this machine only. Nothing here starts by itself — a process runs when you
            press Start and not before.
          </div>
        </div>
        <span className="spacer" />
        <button className="btn ghost" onClick={() => setAdding((v) => !v)}>
          <Plus size={14} /> Add a process
        </button>
      </div>

      {error && (
        <div className="s-desc danger" role="alert" style={{ marginBottom: 10 }}>
          {error}
        </div>
      )}

      {adding && (
        <div className="card" style={{ marginBottom: 12, padding: 12 }}>
          <label className="s-label">Name</label>
          <input
            className="input"
            value={draft.name}
            onChange={(e) => setDraft({ ...draft, name: e.target.value })}
            placeholder="API server"
          />
          <label className="s-label">Command</label>
          <input
            className="input"
            value={draft.command}
            onChange={(e) => setDraft({ ...draft, command: e.target.value })}
            placeholder="/usr/local/bin/node"
          />
          <label className="s-label">Arguments</label>
          <input
            className="input"
            value={argsText}
            onChange={(e) => setArgsText(e.target.value)}
            placeholder="server.js --port 3000"
          />
          <div className="s-desc">
            Separated by spaces, and passed straight to the program. There is no shell here,
            so nothing is expanded and nothing is quoted — and a secret in this list would be
            readable by every account on this machine through <code>ps</code>. Use an
            environment variable from the vault instead.
          </div>
          <label className="s-label">Working directory</label>
          <input
            className="input"
            value={draft.cwd}
            onChange={(e) => setDraft({ ...draft, cwd: e.target.value })}
            placeholder="/srv/api"
          />
          <label className="s-label">Environment</label>
          {draft.env.map((e, i) => (
            <div key={i} style={{ display: 'flex', gap: 6, marginBottom: 4 }}>
              <input
                className="input"
                style={{ flex: '0 0 34%' }}
                value={e.key}
                aria-label={`Variable ${i + 1} name`}
                onChange={(ev) => setEnv(i, { ...e, key: ev.target.value })}
                placeholder="NODE_ENV"
              />
              <select
                className="input"
                style={{ flex: '0 0 26%' }}
                aria-label={`Variable ${i + 1} source`}
                value={e.kind}
                onChange={(ev) =>
                  setEnv(
                    i,
                    ev.target.value === 'vault'
                      ? { key: e.key, kind: 'vault', vaultEntryId: '', slot: 'password' }
                      : { key: e.key, kind: 'literal', value: '' }
                  )
                }
              >
                <option value="literal">a value</option>
                <option value="vault">the vault</option>
              </select>
              {e.kind === 'literal' ? (
                <input
                  className="input"
                  value={e.value}
                  aria-label={`Variable ${i + 1} value`}
                  onChange={(ev) => setEnv(i, { ...e, value: ev.target.value })}
                  placeholder="production"
                />
              ) : (
                <input
                  className="input"
                  value={e.vaultEntryId}
                  aria-label={`Variable ${i + 1} vault entry`}
                  onChange={(ev) => setEnv(i, { ...e, vaultEntryId: ev.target.value })}
                  placeholder="vault entry id"
                />
              )}
              <button
                className="btn ghost sm"
                aria-label={`Remove variable ${i + 1}`}
                onClick={() => setDraft({ ...draft, env: draft.env.filter((_x, j) => j !== i) })}
              >
                <Trash2 size={13} />
              </button>
            </div>
          ))}
          <button
            className="btn ghost sm"
            onClick={() =>
              setDraft({
                ...draft,
                env: [...draft.env, { key: '', kind: 'literal', value: '' }]
              })
            }
          >
            <Plus size={13} /> Add a variable
          </button>
          <div className="s-desc">
            A name that looks like a secret — anything with PASSWORD, TOKEN, SECRET, KEY or
            CREDENTIAL in it — can only come from the vault. The value is then read when the
            process starts, is never written to disk here, and is scrubbed out of the output
            below before it is stored.
            {/* A vault entry is identified rather than PICKED, and that is a
                boundary rather than an oversight: a module may not reach
                `window.shellpilot.vault` (MODULE_FORBIDDEN_BRIDGE), which
                returns every entry with its password in it. A picker needs
                main to offer names and ids WITHOUT values — a channel that
                does not exist yet, and adding one is a decision about the
                vault rather than about this panel. */}
          </div>

          <label className="s-label">Restart</label>
          <select
            className="input"
            value={draft.restart}
            onChange={(e) =>
              setDraft({ ...draft, restart: e.target.value as ProcessDraft['restart'] })
            }
          >
            <option value="never">Never</option>
            <option value="on-failure">If it exits with an error</option>
            <option value="always">Always</option>
          </select>
          <label className="s-label">Ready when</label>
          <select
            className="input"
            value={draft.readiness.kind}
            onChange={(e) =>
              setDraft({
                ...draft,
                readiness:
                  e.target.value === 'log'
                    ? { kind: 'log', pattern: '', timeoutMs: 30_000 }
                    : { kind: 'spawned' }
              })
            }
          >
            <option value="spawned">It has started</option>
            <option value="log">It prints a line containing…</option>
          </select>
          {draft.readiness.kind === 'log' && (
            <>
              <input
                className="input"
                value={draft.readiness.pattern}
                onChange={(e) =>
                  setDraft({
                    ...draft,
                    readiness: { kind: 'log', pattern: e.target.value, timeoutMs: 30_000 }
                  })
                }
                placeholder="listening on"
              />
              <div className="s-desc">
                Plain text, matched anywhere in a line. Not a pattern language.
              </div>
            </>
          )}
          <div style={{ display: 'flex', gap: 8, marginTop: 10 }}>
            <button className="btn" onClick={() => void submit()}>
              Add
            </button>
            <button className="btn ghost" onClick={() => setAdding(false)}>
              Cancel
            </button>
          </div>
        </div>
      )}

      {rows.length === 0 && !adding && (
        <div className="s-desc">
          <Activity size={14} /> No processes yet. Add one to run it under supervision —
          restarts, backoff and crash-loop detection included.
        </div>
      )}

      {rows.map((p) => {
        const st = status[p.id]
        const state = st?.state ?? 'stopped'
        const live = state === 'running' || state === 'starting'
        return (
          <div key={p.id} className="card" style={{ marginBottom: 8, padding: 10 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <strong>{p.name}</strong>
              <span className={clsx('chip', STATE_CLASS[state])}>{STATE_LABEL[state]}</span>
              {st && st.pid > 0 && <span className="s-desc">pid {st.pid}</span>}
              {st && st.restarts > 0 && (
                <span className="s-desc">
                  {st.restarts} restart{st.restarts === 1 ? '' : 's'}
                </span>
              )}
              <span className="spacer" />
              <button
                className="btn ghost sm"
                disabled={busy === p.id || live}
                onClick={() => void act(p.id, () => bridge.start(p.id))}
              >
                <Play size={13} /> Start
              </button>
              <button
                className="btn ghost sm"
                disabled={busy === p.id || !live}
                onClick={() => void act(p.id, () => bridge.stop(p.id))}
              >
                <Square size={13} /> Stop
              </button>
              <button
                className="btn ghost sm"
                disabled={busy === p.id}
                onClick={() => void act(p.id, () => bridge.restart(p.id))}
              >
                <RotateCw size={13} /> Restart
              </button>
              <button
                className="btn ghost sm"
                disabled={busy === p.id}
                onClick={() => void act(p.id, () => bridge.remove(p.id))}
                aria-label="Delete"
                title="Stops it first, then removes it"
              >
                <Trash2 size={13} />
              </button>
            </div>

            <div className="s-desc" style={{ marginTop: 4 }}>
              <code>
                {p.command} {p.args.join(' ')}
              </code>{' '}
              in <code>{p.cwd}</code>
            </div>

            {p.env.length > 0 && (
              <div className="s-desc">
                {/* Keys and where each value comes from. Never a value: main
                    does not send one, and there is nothing here that could
                    display one if it did. */}
                {p.env.map((e) => (
                  <span key={e.key} className="chip" style={{ marginRight: 4 }}>
                    {e.key}
                    {e.source === 'vault' ? ' · from the vault' : ''}
                  </span>
                ))}
              </div>
            )}

            {/* Why it is not running, when there is a why. Said on the row
                rather than in a toast: the answer has to still be there when
                somebody comes back to the tab. */}
            {st?.error && (
              <div className="s-desc danger" style={{ marginTop: 4 }}>
                {st.error}
              </div>
            )}

            <button
              className="btn ghost sm"
              style={{ marginTop: 6 }}
              onClick={() => setOpenId(openId === p.id ? null : p.id)}
            >
              {openId === p.id ? 'Hide output' : 'Show output'}
            </button>

            {openId === p.id && (
              <pre
                className="log-drawer"
                style={{ maxHeight: 260, overflow: 'auto', marginTop: 6 }}
              >
                {logs.length === 0
                  ? 'Nothing yet.'
                  : logs.map((l) => `${l.stream === 'stderr' ? '! ' : ''}${l.text}`).join('\n')}
              </pre>
            )}
          </div>
        )
      })}
    </div>
  )
}
