import { useMemo, useState } from 'react'
import { Container, RefreshCw, ScrollText, SquareTerminal, TriangleAlert } from 'lucide-react'
import { useApp } from '../../store/app'
import { sshHopsFor } from '../../lib/ssh'
import { clsx } from '../../lib/format'
import {
  DOCKER_FAILURE_HELP,
  validateContainerRef,
  type DockerContainer,
  type DockerProbe
} from '../../../../shared/docker'
import type { Server } from '../../types'

// Containers on a server.
//
// The panel's job is mostly to not lie when docker cannot be read: a missing
// binary, a stopped daemon and a permissions problem all produce "nothing" from
// a naive implementation, and they have three different fixes.

function stateTone(state: string): string {
  if (state === 'running') return ''
  if (state === 'exited' || state === 'dead') return 'danger'
  return 'warn'
}

export function DockerPanel({ servers }: { servers: Server[] }): React.JSX.Element {
  const [serverId, setServerId] = useState<string>('')
  const [probe, setProbe] = useState<DockerProbe | null>(null)
  const [loading, setLoading] = useState(false)
  const [logs, setLogs] = useState<{ ref: string; output: string } | null>(null)
  const openContainerShell = useApp((st) => st.openContainerShell)

  const eligible = useMemo(() => servers.filter((s) => s.status !== 'offline'), [servers])
  const server = eligible.find((s) => s.id === serverId) ?? eligible[0]

  const cfgFor = (s: Server): unknown => ({
    sessionId: `docker-${s.id}`,
    cols: 80,
    rows: 24,
    serverId: s.id,
    host: s.host,
    port: s.port,
    username: s.username,
    auth: s.auth === 'password' || s.auth === 'agent' ? s.auth : 'key',
    hops: sshHopsFor(s)
  })

  const load = async (): Promise<void> => {
    if (!server) return
    setLoading(true)
    setLogs(null)
    try {
      const r = await window.shellpilot?.docker?.list(cfgFor(server))
      setProbe(r ?? null)
    } catch (e) {
      setProbe({ ok: false, reason: 'unknown', detail: e instanceof Error ? e.message : String(e) })
    } finally {
      // In a finally, so a rejected invoke leaves a button the user can press
      // again rather than one that spins forever.
      setLoading(false)
    }
  }

  const openLogs = async (c: DockerContainer): Promise<void> => {
    if (!server) return
    // `docker:logs` is the one handler that can reject: buildDockerLogsCommand
    // refuses a reference it cannot prove safe rather than escaping it. Asking
    // first turns an unhandled rejection and a pane stuck on "Loading…" into a
    // sentence saying what happened.
    if (!validateContainerRef(c.name)) {
      setLogs({ ref: c.name, output: 'This container has a name logs cannot be requested for safely.' })
      return
    }
    setLogs({ ref: c.name, output: 'Loading…' })
    try {
      const r = await window.shellpilot?.docker?.logs(cfgFor(server), c.name, 200)
      setLogs({ ref: c.name, output: r?.output || r?.error || 'No output.' })
    } catch (e) {
      setLogs({ ref: c.name, output: e instanceof Error ? e.message : String(e) })
    }
  }

  return (
    <div className="bc-panel">
      <div className="row" style={{ gap: 8, alignItems: 'center' }}>
        <Container size={14} className="faint" />
        <b className="grow">Containers</b>
        <select
          className="input"
          style={{ maxWidth: 200 }}
          value={server?.id ?? ''}
          onChange={(e) => {
            setServerId(e.target.value)
            setProbe(null)
            setLogs(null)
          }}
        >
          {eligible.map((s) => (
            <option key={s.id} value={s.id}>
              {s.name}
            </option>
          ))}
        </select>
        <button className="btn" disabled={loading || !server} onClick={() => void load()}>
          <RefreshCw size={13} className={clsx(loading && 'spin')} /> {probe ? 'Refresh' : 'Read containers'}
        </button>
      </div>

      {eligible.length === 0 && <div className="s-desc">No server in this workspace is online.</div>}

      {!probe && !loading && eligible.length > 0 && (
        <div className="s-desc">
          Runs <span className="mono">docker ps</span> on the selected server using the docker binary
          already installed there. Reading only — nothing is started, stopped or removed.
        </div>
      )}

      {/* Three different problems, three different fixes. A panel that shows
          an empty list for all of them is lying about two. */}
      {probe && !probe.ok && (
        <div className="s-desc danger">
          <TriangleAlert size={12} /> {DOCKER_FAILURE_HELP[probe.reason]}
          <div className="mono" style={{ marginTop: 4, opacity: 0.8 }}>
            {probe.detail}
          </div>
        </div>
      )}

      {probe?.ok && (
        <>
          <div className="row muted" style={{ fontSize: 11, marginTop: 8, gap: 12 }}>
            {/* null when the host answered with something that was not a
                version — podman's docker shim, most often. Saying nothing
                beats printing "docker null". */}
            <span>{probe.version ? `docker ${probe.version}` : 'docker'}</span>
            <span>
              {probe.containers.length} container{probe.containers.length === 1 ? '' : 's'}
            </span>
          </div>
          {probe.containers.length === 0 && (
            <div className="faint" style={{ fontSize: 12 }}>
              Docker is running and has no containers.
            </div>
          )}
          {probe.containers.map((c) => (
            <div key={c.id} className="cron-row">
              <span className={clsx('chip', stateTone(c.state))}>{c.state}</span>
              <span className="mono cron-when">{c.name}</span>
              <span className="faint cron-desc">{c.image}</span>
              <span className="faint grow" title={c.ports}>
                {c.status}
              </span>
              <button className="icon-btn sm" title="Last 200 log lines" onClick={() => void openLogs(c)}>
                <ScrollText size={13} />
              </button>
              {/* Only for a container that is actually running — `docker exec`
                  into a stopped one fails with a message the user then has to
                  go and read, and the button implies it would work.
                  Deliberately no confirmation dialog: the user picked this
                  container and pressed a button labelled shell, which is the
                  approval. A modal here would be the nag that teaches
                  click-through on the ones that matter. */}
              {c.state === 'running' && validateContainerRef(c.name) && server && (
                <button
                  className="icon-btn sm"
                  title={`Open a shell in ${c.name}. This runs commands inside the container, on ${server.name}.`}
                  onClick={() => openContainerShell(server.id, c.name)}
                >
                  <SquareTerminal size={13} />
                </button>
              )}
            </div>
          ))}
        </>
      )}

      {logs && (
        <>
          <div className="row muted" style={{ fontSize: 11, marginTop: 10 }}>
            <span className="grow">Logs · {logs.ref}</span>
            <button className="btn ghost sm" onClick={() => setLogs(null)}>
              Close
            </button>
          </div>
          <pre className="bc-out" style={{ marginLeft: 0, maxHeight: 300 }}>
            {logs.output}
          </pre>
        </>
      )}
    </div>
  )
}
