import { useMemo, useState } from 'react'
import { Boxes, RefreshCw, ScrollText, TriangleAlert } from 'lucide-react'
import { sshHopsFor } from '../../lib/ssh'
import { clsx } from '../../lib/format'
import {
  K8S_FAILURE_HELP,
  validatePodName,
  type K8sPod,
  type K8sProbe
} from '../../../../shared/kubernetes'
import type { Server } from '../../types'

// Pods on a cluster reachable from a server.
//
// Read-only, and the UI says so rather than leaving it implied — a Kubernetes
// panel that looks like it might scale or delete something is worse than one
// that plainly cannot.

function podTone(p: K8sPod): string {
  if (/CrashLoopBackOff|Error|Failed|Evicted/i.test(p.status)) return 'danger'
  if (p.status === 'Succeeded' || p.status === 'Completed') return ''
  const [ready, total] = p.ready.split('/')
  if (p.status === 'Running' && ready === total) return ''
  return 'warn'
}

export function KubernetesPanel({ servers }: { servers: Server[] }): React.JSX.Element {
  const [serverId, setServerId] = useState('')
  const [context, setContext] = useState('')
  const [probe, setProbe] = useState<K8sProbe | null>(null)
  const [loading, setLoading] = useState(false)
  const [logs, setLogs] = useState<{ pod: string; output: string } | null>(null)
  const [filter, setFilter] = useState('')

  const eligible = useMemo(() => servers.filter((s) => s.status !== 'offline'), [servers])
  const server = eligible.find((s) => s.id === serverId) ?? eligible[0]

  const cfgFor = (s: Server): unknown => ({
    sessionId: `k8s-${s.id}`,
    cols: 80,
    rows: 24,
    serverId: s.id,
    host: s.host,
    port: s.port,
    username: s.username,
    auth: s.auth === 'password' || s.auth === 'agent' ? s.auth : 'key',
    hops: sshHopsFor(s)
  })

  const load = async (ctx?: string): Promise<void> => {
    if (!server) return
    setLoading(true)
    setLogs(null)
    try {
      const r = await window.shellpilot?.k8s?.read(cfgFor(server), ctx || undefined)
      setProbe(r ?? null)
    } catch (e) {
      setProbe({ ok: false, reason: 'unknown', detail: e instanceof Error ? e.message : String(e) })
    } finally {
      // In a finally so a rejected invoke leaves a button that can be pressed
      // again rather than one that spins forever.
      setLoading(false)
    }
  }

  const openLogs = async (p: K8sPod): Promise<void> => {
    if (!server) return
    // buildK8sLogsCommand refuses a name it cannot prove safe rather than
    // escaping it, so asking first turns a rejected invoke into a sentence.
    if (!validatePodName(p.name)) {
      setLogs({ pod: p.name, output: 'This pod has a name logs cannot be requested for safely.' })
      return
    }
    setLogs({ pod: p.name, output: 'Loading…' })
    try {
      const r = await window.shellpilot?.k8s?.logs(
        cfgFor(server),
        p.namespace,
        p.name,
        200,
        context || undefined
      )
      setLogs({ pod: p.name, output: r?.output || r?.error || 'No output.' })
    } catch (e) {
      setLogs({ pod: p.name, output: e instanceof Error ? e.message : String(e) })
    }
  }

  const q = filter.trim().toLowerCase()
  const allPods = probe?.ok ? probe.pods : []
  const pods =
    q === ''
      ? allPods
      : allPods.filter((p) => `${p.namespace} ${p.name} ${p.status} ${p.node}`.toLowerCase().includes(q))

  return (
    <div className="bc-panel">
      <div className="row" style={{ gap: 8, alignItems: 'center' }}>
        <Boxes size={14} className="faint" />
        <b className="grow">Pods</b>
        <select
          className="input"
          style={{ maxWidth: 170 }}
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
        {/* Choosing a context here passes --context for THIS read only. It does
            not run `kubectl config use-context`, which would repoint the
            cluster for every process on that host. */}
        {probe?.ok && probe.contexts.length > 1 && (
          <select
            className="input"
            style={{ maxWidth: 200 }}
            value={context || probe.currentContext || ''}
            onChange={(e) => {
              setContext(e.target.value)
              void load(e.target.value)
            }}
          >
            {probe.contexts.map((c) => (
              <option key={c.name} value={c.name}>
                {c.name}
                {c.current ? ' (current)' : ''}
              </option>
            ))}
          </select>
        )}
        <button className="btn" disabled={loading || !server} onClick={() => void load(context)}>
          <RefreshCw size={13} className={clsx(loading && 'spin')} />{' '}
          {probe ? 'Refresh' : 'Read cluster'}
        </button>
      </div>

      {eligible.length === 0 && <div className="s-desc">No server in this workspace is online.</div>}

      {!probe && !loading && eligible.length > 0 && (
        <div className="s-desc">
          Runs <span className="mono">kubectl</span> on the selected server, using whatever
          kubeconfig that host already has. Reading only: it never switches your context, never execs
          into a pod, and never applies or deletes anything.
        </div>
      )}

      {/* Six failure classes with six different fixes. "No pods" for a
          permissions problem is the lie this panel exists to avoid. */}
      {probe && !probe.ok && (
        <div className="s-desc danger">
          <TriangleAlert size={12} /> {K8S_FAILURE_HELP[probe.reason]}
          <div className="mono" style={{ marginTop: 4, opacity: 0.8 }}>
            {probe.detail}
          </div>
        </div>
      )}

      {probe?.ok && (
        <>
          <div className="row muted wrap" style={{ fontSize: 11, marginTop: 8, gap: 12 }}>
            <span>{probe.version ? `kubectl ${probe.version}` : 'kubectl'}</span>
            {probe.currentContext && <span>context {probe.currentContext}</span>}
            <span>
              {pods.length} pod{pods.length === 1 ? '' : 's'}
              {q !== '' && ` of ${allPods.length}`}
            </span>
            {/* An empty list means something different depending on this, so it
                is never left for the reader to assume. */}
            {!probe.allNamespaces && (
              <span className="warn">
                one namespace only — this account cannot list across the cluster
              </span>
            )}
            <span className="spacer" />
            {allPods.length > 0 && (
              <input
                className="input"
                style={{ maxWidth: 180 }}
                placeholder="Filter pods…"
                value={filter}
                onChange={(e) => setFilter(e.target.value)}
              />
            )}
          </div>

          {allPods.length === 0 && (
            <div className="faint" style={{ fontSize: 12 }}>
              {probe.allNamespaces
                ? 'The cluster answered and has no pods.'
                : 'No pods in the namespace this account can read.'}
            </div>
          )}

          {pods.map((p) => (
            <div key={`${p.namespace}/${p.name}`} className="cron-row">
              <span className={clsx('chip', podTone(p))}>{p.status}</span>
              <span className="mono cron-when">{p.ready}</span>
              <span className="faint cron-desc">{p.namespace}</span>
              <span className="mono grow cron-cmd" title={`${p.name} on ${p.node || 'unscheduled'}`}>
                {p.name}
              </span>
              {p.restarts > 0 && (
                <span className={clsx('chip', p.restarts > 5 ? 'danger' : 'warn')}>
                  {p.restarts} restart{p.restarts === 1 ? '' : 's'}
                </span>
              )}
              <button
                className="icon-btn sm"
                title="Last 200 log lines, all containers"
                onClick={() => void openLogs(p)}
              >
                <ScrollText size={13} />
              </button>
            </div>
          ))}
        </>
      )}

      {logs && (
        <>
          <div className="row muted" style={{ fontSize: 11, marginTop: 10 }}>
            <span className="grow">Logs · {logs.pod}</span>
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
