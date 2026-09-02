import { useMemo, useState } from 'react'
import {
  Activity,
  Boxes,
  Gauge,
  Layers,
  RefreshCw,
  RotateCw,
  ScrollText,
  Server as ServerIcon,
  Siren,
  TriangleAlert
} from 'lucide-react'
import { sshHopsFor } from '../../lib/ssh'
import { clsx } from '../../lib/format'
import {
  K8S_FAILURE_HELP,
  k8sRelativeTime,
  nodeIsUnhealthy,
  planK8sRollout,
  readsAfterNamespaceChange,
  validatePodName,
  workloadIsDegraded,
  type K8sDiagnosis,
  type K8sEvent,
  type K8sOverview,
  type K8sPod,
  type K8sProbe,
  type K8sRead,
  type K8sRolloutPlan,
  type K8sRolloutResult,
  type K8sRolloutTarget,
  type K8sTextRead,
  type K8sUsage,
  type K8sWorkload
} from '../../../../shared/kubernetes'
import type { Server } from '../../types'

// Pods on a cluster reachable from a server, and what you do about them.
//
// The first version of this panel was reconnaissance: it listed pods and read
// 200 static log lines, so it could tell you a pod was in CrashLoopBackOff and
// then had nothing further to say. Everything past the pod list is the "why",
// in roughly the order an operator asks for it — events, the previous
// container's logs, then the workload behind the pod and the node under it.
//
// It is read-only with EXACTLY one exception, `kubectl rollout restart`, and
// the exception is treated as one: it has its own confirmation, scaled to blast
// radius the way shared/broadcast.ts scales its own. Nothing here switches the
// context, execs into a pod, or deletes anything — see the header of
// shared/kubernetes.ts, which explains why pod deletion in particular is
// missing rather than forgotten.

/**
 * The channels this panel calls, described where it calls them.
 *
 * `window.shellpilot.k8s` is built in the preload and its type comes from
 * there, so the four operational channels do not exist on it until the main
 * process wires them. They are optional here on purpose: a panel that assumes a
 * channel exists renders a permanent spinner when it does not, and "this build
 * has no diagnose channel" is a sentence, not a mystery.
 */
interface K8sBridge {
  read?: (cfg: unknown, context?: string, namespace?: string) => Promise<K8sProbe>
  logs?: (
    cfg: unknown,
    namespace: string,
    pod: string,
    lines: number,
    context?: string
  ) => Promise<{ ok: boolean; output: string; error?: string }>
  diagnose?: (
    cfg: unknown,
    namespace: string,
    pod: string,
    context?: string,
    previousLines?: number
  ) => Promise<K8sDiagnosis>
  overview?: (cfg: unknown, context?: string, namespace?: string) => Promise<K8sOverview>
  usage?: (cfg: unknown, context?: string, namespace?: string) => Promise<K8sUsage>
  rolloutRestart?: (
    cfg: unknown,
    target: K8sRolloutTarget,
    confirmed: boolean
  ) => Promise<K8sRolloutResult>
}

const bridge = (): K8sBridge =>
  ((window.shellpilot as { k8s?: K8sBridge } | undefined)?.k8s ?? {}) as K8sBridge

const NOT_WIRED = 'This build has no such channel — the main process has not registered it.'

function podTone(p: K8sPod): string {
  if (/CrashLoopBackOff|Error|Failed|Evicted/i.test(p.status)) return 'danger'
  if (p.status === 'Succeeded' || p.status === 'Completed') return ''
  const [ready, total] = p.ready.split('/')
  if (p.status === 'Running' && ready === total) return ''
  return 'warn'
}

/**
 * What a block says when it could not be read.
 *
 * Every read renders through this rather than falling back to an empty list.
 * RBAC is per resource — a token that lists pods very often cannot list events
 * — so "no events" and "not allowed to see events" appear next to each other
 * constantly, and they mean opposite things.
 */
function Denied({ read, what }: { read: { reason: keyof typeof K8S_FAILURE_HELP; detail: string }; what: string }): React.JSX.Element {
  // `no-previous` and `no-metrics` are not the user's problem to fix and are
  // not failures of this account — dressing them in a red warning triangle
  // teaches people to ignore the triangle.
  const benign = read.reason === 'no-previous' || read.reason === 'no-metrics'
  return (
    <div className={clsx('s-desc', benign ? 'faint' : 'danger')}>
      {!benign && <TriangleAlert size={12} />} {what}: {K8S_FAILURE_HELP[read.reason]}
      <div className="mono" style={{ marginTop: 4, opacity: 0.8, whiteSpace: 'pre-wrap' }}>
        {read.detail}
      </div>
    </div>
  )
}

function EventRows({ events }: { events: K8sEvent[] }): React.JSX.Element {
  return (
    <>
      {events.map((e, i) => (
        <div key={`${e.objectName}-${e.reason}-${e.lastSeen}-${i}`} className="cron-row">
          <span className={clsx('chip', e.type === 'Warning' && 'warn')}>{e.reason}</span>
          <span className="mono cron-when">{k8sRelativeTime(e.lastSeen) || '—'}</span>
          <span className="faint cron-desc" title={`${e.objectKind}/${e.objectName}`}>
            {e.objectName}
          </span>
          <span className="grow cron-cmd" title={e.message}>
            {e.message}
          </span>
          {/* A repeat count is the difference between "it hiccuped" and "it has
              been doing this four hundred times". */}
          {e.count > 1 && <span className={clsx('chip', e.count > 20 && 'warn')}>×{e.count}</span>}
        </div>
      ))}
    </>
  )
}

function readEmpty<T>(r: K8sRead<T>): boolean {
  return r.ok && r.items.length === 0
}

export function KubernetesPanel({ servers }: { servers: Server[] }): React.JSX.Element {
  const [serverId, setServerId] = useState('')
  const [context, setContext] = useState('')
  const [namespace, setNamespace] = useState('')
  const [probe, setProbe] = useState<K8sProbe | null>(null)
  const [loading, setLoading] = useState(false)
  const [logs, setLogs] = useState<{ pod: string; output: string } | null>(null)
  const [filter, setFilter] = useState('')

  const [view, setView] = useState<'pods' | 'cluster' | 'usage'>('pods')
  const [overview, setOverview] = useState<K8sOverview | null>(null)
  const [overviewLoading, setOverviewLoading] = useState(false)
  const [usage, setUsage] = useState<K8sUsage | null>(null)
  const [usageLoading, setUsageLoading] = useState(false)
  const [diag, setDiag] = useState<{ pod: string; result: K8sDiagnosis | null; error?: string } | null>(
    null
  )

  // The state change, and everything it needs to be deliberate.
  const [pending, setPending] = useState<{ plan: K8sRolloutPlan } | null>(null)
  const [phrase, setPhrase] = useState('')
  const [restarting, setRestarting] = useState(false)
  const [restartResult, setRestartResult] = useState<{ name: string; r: K8sRolloutResult } | null>(null)

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

  // `ns` overrides the namespace in state. Every one of these can be called
  // from the change handler of the control that sets that state, and React has
  // not applied it yet at that point — so reading it here would fetch the
  // selection the user just moved away from. `??` and not `||`: empty string is
  // "all namespaces", a real choice, not an absent one.
  const load = async (ctx?: string, ns?: string): Promise<void> => {
    if (!server) return
    setLoading(true)
    setLogs(null)
    setDiag(null)
    try {
      const r = await bridge().read?.(cfgFor(server), ctx || undefined, (ns ?? namespace) || undefined)
      setProbe(r ?? null)
    } catch (e) {
      setProbe({ ok: false, reason: 'unknown', detail: e instanceof Error ? e.message : String(e) })
    } finally {
      // In a finally so a rejected invoke leaves a button that can be pressed
      // again rather than one that spins forever.
      setLoading(false)
    }
  }

  const loadOverview = async (ns?: string): Promise<void> => {
    if (!server) return
    setOverviewLoading(true)
    try {
      const fn = bridge().overview
      if (!fn) {
        const f = { ok: false, reason: 'unknown', detail: NOT_WIRED } as const
        setOverview({ deployments: f, statefulSets: f, daemonSets: f, nodes: f, events: f })
        return
      }
      setOverview(await fn(cfgFor(server), context || undefined, (ns ?? namespace) || undefined))
    } catch (e) {
      const f = {
        ok: false,
        reason: 'unknown',
        detail: e instanceof Error ? e.message : String(e)
      } as const
      setOverview({ deployments: f, statefulSets: f, daemonSets: f, nodes: f, events: f })
    } finally {
      setOverviewLoading(false)
    }
  }

  const loadUsage = async (ns?: string): Promise<void> => {
    if (!server) return
    setUsageLoading(true)
    try {
      const fn = bridge().usage
      if (!fn) {
        const f = { ok: false, reason: 'unknown', detail: NOT_WIRED } as const
        setUsage({ pods: f, nodes: f })
        return
      }
      setUsage(await fn(cfgFor(server), context || undefined, (ns ?? namespace) || undefined))
    } catch (e) {
      const f = {
        ok: false,
        reason: 'unknown',
        detail: e instanceof Error ? e.message : String(e)
      } as const
      setUsage({ pods: f, nodes: f })
    } finally {
      setUsageLoading(false)
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
      const r = await bridge().logs?.(cfgFor(server), p.namespace, p.name, 200, context || undefined)
      setLogs({ pod: p.name, output: r?.output || r?.error || 'No output.' })
    } catch (e) {
      setLogs({ pod: p.name, output: e instanceof Error ? e.message : String(e) })
    }
  }

  /** The first thing anyone runs on a pod that is not Running. */
  const diagnose = async (p: K8sPod): Promise<void> => {
    if (!server) return
    if (!validatePodName(p.name) ) {
      setDiag({ pod: p.name, result: null, error: 'This pod has a name kubectl cannot be asked about safely.' })
      return
    }
    setDiag({ pod: p.name, result: null })
    try {
      const fn = bridge().diagnose
      if (!fn) {
        setDiag({ pod: p.name, result: null, error: NOT_WIRED })
        return
      }
      const r = await fn(cfgFor(server), p.namespace, p.name, context || undefined, 200)
      setDiag({ pod: p.name, result: r })
    } catch (e) {
      setDiag({ pod: p.name, result: null, error: e instanceof Error ? e.message : String(e) })
    }
  }

  const askToRestart = (w: K8sWorkload): void => {
    // The plan is computed here so the dialog can explain itself, and computed
    // AGAIN in the main process before anything runs — a plan that crossed IPC
    // is a value a caller could have written, not a decision.
    setRestartResult(null)
    setPhrase('')
    setPending({
      plan: planK8sRollout({
        kind: w.kind,
        namespace: w.namespace,
        name: w.name,
        desired: w.desired,
        strategy: w.strategy || null,
        context: context || (probe?.ok ? probe.currentContext : null)
      })
    })
  }

  const runRestart = async (): Promise<void> => {
    if (!server || !pending) return
    setRestarting(true)
    try {
      const fn = bridge().rolloutRestart
      const target = pending.plan.target
      const r = fn
        ? await fn(cfgFor(server), target, true)
        : { ok: false, output: '', status: '', reason: 'unknown' as const, detail: NOT_WIRED }
      setRestartResult({ name: `${target.kind}/${target.name}`, r })
      setPending(null)
      setPhrase('')
      // Re-read, because the whole point is watching the replicas come back.
      if (r.ok) void loadOverview()
    } catch (e) {
      setRestartResult({
        name: `${pending.plan.target.kind}/${pending.plan.target.name}`,
        r: {
          ok: false,
          output: '',
          status: '',
          reason: 'unknown',
          detail: e instanceof Error ? e.message : String(e)
        }
      })
      setPending(null)
    } finally {
      setRestarting(false)
    }
  }

  const q = filter.trim().toLowerCase()
  const allPods = probe?.ok ? probe.pods : []
  const pods =
    q === ''
      ? allPods
      : allPods.filter((p) =>
          `${p.namespace} ${p.name} ${p.status} ${p.node}`.toLowerCase().includes(q)
        )

  const canConfirm =
    !pending ||
    pending.plan.confirmation.kind !== 'type-to-confirm' ||
    phrase.trim() === pending.plan.confirmation.phrase

  const workloadRows = (r: K8sRead<K8sWorkload>, label: string): React.JSX.Element => {
    if (!r.ok) return <Denied read={r} what={label} />
    if (r.items.length === 0) return <div className="faint" style={{ fontSize: 12 }}>No {label.toLowerCase()}.</div>
    return (
      <>
        {r.items.map((w) => (
          <div key={`${w.namespace}/${w.name}`} className="cron-row">
            <span className={clsx('chip', workloadIsDegraded(w) && 'warn')}>
              {w.ready}/{w.desired}
            </span>
            <span className="faint cron-desc">{w.namespace}</span>
            <span className="mono grow cron-cmd" title={`${w.kind} ${w.namespace}/${w.name}`}>
              {w.name}
            </span>
            {/* Shown, not hidden: it is the difference between a restart nobody
                notices and one that takes the workload fully down, and it is
                what decides how hard the confirmation presses. */}
            {w.strategy && w.strategy !== 'RollingUpdate' && (
              <span className="chip warn">{w.strategy}</span>
            )}
            <button
              className="icon-btn sm"
              title={`kubectl rollout restart ${w.kind}/${w.name} — replaces every pod of this workload`}
              onClick={() => askToRestart(w)}
            >
              <RotateCw size={13} />
            </button>
          </div>
        ))}
      </>
    )
  }

  const textBlock = (r: K8sTextRead, label: string): React.JSX.Element =>
    r.ok ? (
      <pre className="bc-out" style={{ marginLeft: 0, maxHeight: 260 }}>
        {r.text}
      </pre>
    ) : (
      <Denied read={r} what={label} />
    )

  return (
    <div className="bc-panel">
      <div className="row" style={{ gap: 8, alignItems: 'center' }}>
        <Boxes size={14} className="faint" />
        <b className="grow">Kubernetes</b>
        <select
          className="input"
          style={{ maxWidth: 170 }}
          value={server?.id ?? ''}
          onChange={(e) => {
            setServerId(e.target.value)
            setProbe(null)
            setLogs(null)
            setDiag(null)
            setOverview(null)
            setUsage(null)
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
              setOverview(null)
              setUsage(null)
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
        {probe?.ok && probe.namespaces.length > 0 && (
          <select
            className="input"
            style={{ maxWidth: 170 }}
            value={namespace}
            onChange={(e) => {
              // Changing the namespace has to REREAD, not just discard.
              //
              // This cleared the cached reads and stopped, which left the pane
              // holding the previous namespace's pods and showed an empty
              // "namespace X" heading under the cluster tab. The data came back
              // only when the user clicked another tab, because those handlers
              // reload whatever is null — so the control appeared to do nothing
              // and the fix appeared to be "go somewhere else and come back".
              //
              // The context selector beside this one always reloaded. This is
              // the same control over the same reads and it behaves the same
              // way now.
              const ns = e.target.value
              setNamespace(ns)
              setOverview(null)
              setUsage(null)
              const again = readsAfterNamespaceChange(view)
              if (again.pods) void load(context, ns)
              if (again.overview) void loadOverview(ns)
              if (again.usage) void loadUsage(ns)
            }}
            title="Scopes the cluster and usage reads. Nodes are cluster-scoped and are never namespace-filtered."
          >
            <option value="">all namespaces</option>
            {probe.namespaces.map((n) => (
              <option key={n} value={n}>
                {n}
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
          kubeconfig that host already has. Reading only, with one exception:{' '}
          <span className="mono">rollout restart</span>, which asks first. It never switches your
          context, never execs into a pod, and never deletes anything.
        </div>
      )}

      {/* Failure classes with different fixes. "No pods" for a permissions
          problem is the lie this panel exists to avoid. */}
      {probe && !probe.ok && <Denied read={probe} what="Reading the cluster" />}

      {probe?.ok && (
        <>
          <div className="row wrap" style={{ gap: 6, marginTop: 8 }}>
            <button
              className={clsx('chip', view === 'pods' && 'on')}
              onClick={() => setView('pods')}
            >
              <Boxes size={12} /> Pods
            </button>
            <button
              className={clsx('chip', view === 'cluster' && 'on')}
              onClick={() => {
                setView('cluster')
                if (!overview) void loadOverview()
              }}
            >
              <Layers size={12} /> Workloads, nodes &amp; events
            </button>
            <button
              className={clsx('chip', view === 'usage' && 'on')}
              onClick={() => {
                setView('usage')
                if (!usage) void loadUsage()
              }}
            >
              <Gauge size={12} /> Usage
            </button>
            <span className="spacer" />
            <span className="muted" style={{ fontSize: 11 }}>
              {probe.version ? `kubectl ${probe.version}` : 'kubectl'}
              {probe.currentContext ? ` · ${context || probe.currentContext}` : ''}
            </span>
          </div>

          {view === 'pods' && (
            <>
              <div className="row muted wrap" style={{ fontSize: 11, marginTop: 8, gap: 12 }}>
                <span>
                  {pods.length} pod{pods.length === 1 ? '' : 's'}
                  {q !== '' && ` of ${allPods.length}`}
                </span>
                {/* An empty list means something different depending on this, so
                    it is never left for the reader to assume. */}
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
                  <span
                    className="mono grow cron-cmd"
                    title={`${p.name} on ${p.node || 'unscheduled'}`}
                  >
                    {p.name}
                  </span>
                  {p.restarts > 0 && (
                    <span className={clsx('chip', p.restarts > 5 ? 'danger' : 'warn')}>
                      {p.restarts} restart{p.restarts === 1 ? '' : 's'}
                    </span>
                  )}
                  {/* First, and to the left of the log button, because it is
                      what you actually want: a CrashLoopBackOff pod's CURRENT
                      logs are usually empty and its events are the story. */}
                  <button
                    className="icon-btn sm"
                    title="Describe, events, and the PREVIOUS container's logs — why this pod is unhealthy"
                    onClick={() => void diagnose(p)}
                  >
                    <Siren size={13} />
                  </button>
                  <button
                    className="icon-btn sm"
                    title="Last 200 log lines from the running containers"
                    onClick={() => void openLogs(p)}
                  >
                    <ScrollText size={13} />
                  </button>
                </div>
              ))}
            </>
          )}

          {view === 'cluster' && (
            <>
              <div className="row muted" style={{ fontSize: 11, marginTop: 8 }}>
                <span className="grow">
                  {namespace ? `namespace ${namespace}` : 'all namespaces'}
                </span>
                <button className="btn ghost sm" disabled={overviewLoading} onClick={() => void loadOverview()}>
                  <RefreshCw size={12} className={clsx(overviewLoading && 'spin')} /> Refresh
                </button>
              </div>

              {!overview && overviewLoading && <div className="faint" style={{ fontSize: 12 }}>Reading…</div>}

              {overview && (
                <>
                  <div className="s-title" style={{ marginTop: 8 }}>
                    <Layers size={12} /> Deployments
                  </div>
                  {workloadRows(overview.deployments, 'Deployments')}

                  {/* StatefulSets and DaemonSets are only drawn when there are
                      any, or when the read was refused. A permanently empty
                      heading is noise; a refused read is not. */}
                  {(!overview.statefulSets.ok || !readEmpty(overview.statefulSets)) && (
                    <>
                      <div className="s-title" style={{ marginTop: 8 }}>
                        <Layers size={12} /> StatefulSets
                      </div>
                      {workloadRows(overview.statefulSets, 'StatefulSets')}
                    </>
                  )}
                  {(!overview.daemonSets.ok || !readEmpty(overview.daemonSets)) && (
                    <>
                      <div className="s-title" style={{ marginTop: 8 }}>
                        <Layers size={12} /> DaemonSets
                      </div>
                      {workloadRows(overview.daemonSets, 'DaemonSets')}
                    </>
                  )}

                  <div className="s-title" style={{ marginTop: 10 }}>
                    <ServerIcon size={12} /> Nodes
                  </div>
                  {!overview.nodes.ok ? (
                    <Denied read={overview.nodes} what="Nodes" />
                  ) : overview.nodes.items.length === 0 ? (
                    <div className="faint" style={{ fontSize: 12 }}>No nodes.</div>
                  ) : (
                    overview.nodes.items.map((n) => (
                      <div key={n.name} className="cron-row">
                        <span className={clsx('chip', nodeIsUnhealthy(n) && 'danger')}>{n.status}</span>
                        <span className="mono cron-when">{n.age}</span>
                        <span className="faint cron-desc">{n.roles || '—'}</span>
                        <span className="mono grow cron-cmd">{n.name}</span>
                        <span className="faint">{n.version}</span>
                      </div>
                    ))
                  )}

                  <div className="s-title" style={{ marginTop: 10 }}>
                    <Activity size={12} /> Events, newest first
                  </div>
                  {!overview.events.ok ? (
                    <Denied read={overview.events} what="Events" />
                  ) : overview.events.items.length === 0 ? (
                    <div className="faint" style={{ fontSize: 12 }}>
                      No events. The API server keeps them for about an hour, so a quiet list can
                      also mean nothing has happened recently.
                    </div>
                  ) : (
                    <EventRows events={overview.events.items} />
                  )}
                </>
              )}
            </>
          )}

          {view === 'usage' && (
            <>
              <div className="row muted" style={{ fontSize: 11, marginTop: 8 }}>
                <span className="grow">
                  <span className="mono">kubectl top</span> — needs a Metrics API in the cluster
                </span>
                <button className="btn ghost sm" disabled={usageLoading} onClick={() => void loadUsage()}>
                  <RefreshCw size={12} className={clsx(usageLoading && 'spin')} /> Refresh
                </button>
              </div>
              {!usage && usageLoading && <div className="faint" style={{ fontSize: 12 }}>Reading…</div>}
              {usage && (
                <>
                  {!usage.nodes.ok ? (
                    <Denied read={usage.nodes} what="Node usage" />
                  ) : (
                    usage.nodes.items.map((n) => (
                      <div key={n.name} className="cron-row">
                        <span className="chip">{n.cpuPercent} cpu</span>
                        <span className="chip">{n.memoryPercent} mem</span>
                        <span className="mono grow cron-cmd">{n.name}</span>
                        <span className="faint mono">
                          {n.cpu} · {n.memory}
                        </span>
                      </div>
                    ))
                  )}
                  {!usage.pods.ok ? (
                    <Denied read={usage.pods} what="Pod usage" />
                  ) : (
                    usage.pods.items.map((p) => (
                      <div key={`${p.namespace}/${p.name}`} className="cron-row">
                        <span className="mono cron-when">{p.cpu}</span>
                        <span className="mono cron-when">{p.memory}</span>
                        <span className="faint cron-desc">{p.namespace}</span>
                        <span className="mono grow cron-cmd">{p.name}</span>
                      </div>
                    ))
                  )}
                </>
              )}
            </>
          )}
        </>
      )}

      {/* ---- the state change, and the only dialog in this panel ---- */}
      {pending && (
        <div className="bc-confirm">
          <div className="s-title">
            Restart {pending.plan.target.kind} {pending.plan.target.name}?
          </div>
          <div className="s-desc mono">
            kubectl rollout restart {pending.plan.target.kind}/{pending.plan.target.name} --namespace=
            {pending.plan.target.namespace}
            {pending.plan.target.context ? ` --context=${pending.plan.target.context}` : ''}
          </div>
          <div className={clsx('s-desc', pending.plan.risk === 'destructive' ? 'danger' : 'warn')}>
            <TriangleAlert size={12} /> This changes the cluster — {pending.plan.reasons.join('; ')}.
          </div>
          {/* Kept apart from the reasons: these are not arguments for pressing
              harder, they are things that would otherwise be discovered from a
              restart that appeared to work and changed nothing. */}
          {pending.plan.caveats.map((c) => (
            <div key={c} className="s-desc faint">
              {c}
            </div>
          ))}
          {pending.plan.confirmation.kind === 'type-to-confirm' && (
            <div className="input-group" style={{ marginTop: 6 }}>
              <input
                className="input"
                placeholder={`Type ${pending.plan.confirmation.phrase} to restart`}
                value={phrase}
                onChange={(e) => setPhrase(e.target.value)}
                autoFocus
              />
            </div>
          )}
          <div className="row" style={{ gap: 8, marginTop: 8 }}>
            <button
              className="btn primary"
              disabled={!canConfirm || restarting}
              onClick={() => void runRestart()}
            >
              Restart
            </button>
            <button
              className="btn ghost"
              onClick={() => {
                setPending(null)
                setPhrase('')
              }}
            >
              Cancel
            </button>
          </div>
        </div>
      )}

      {restartResult && (
        <div className={clsx('s-desc', restartResult.r.ok ? '' : 'danger')}>
          <span className="grow">
            {restartResult.r.ok
              ? `${restartResult.name}: ${restartResult.r.output}`
              : `${restartResult.name} was not restarted — ${
                  restartResult.r.reason ? K8S_FAILURE_HELP[restartResult.r.reason] : ''
                }`}
          </span>
          <div className="mono" style={{ marginTop: 4, opacity: 0.8, whiteSpace: 'pre-wrap' }}>
            {restartResult.r.ok ? restartResult.r.status : restartResult.r.detail}
          </div>
          <button className="btn ghost sm" onClick={() => setRestartResult(null)}>
            Close
          </button>
        </div>
      )}

      {/* ---- why this pod is unhealthy ---- */}
      {diag && (
        <>
          <div className="row muted" style={{ fontSize: 11, marginTop: 10 }}>
            <span className="grow">Diagnosis · {diag.pod}</span>
            <button className="btn ghost sm" onClick={() => setDiag(null)}>
              Close
            </button>
          </div>
          {diag.error && <div className="s-desc danger">{diag.error}</div>}
          {!diag.result && !diag.error && (
            <div className="faint" style={{ fontSize: 12 }}>Reading…</div>
          )}
          {diag.result && (
            <>
              {/* Events first. They are the answer far more often than the
                  logs are, and a Pending pod has nothing else at all. */}
              <div className="s-title" style={{ marginTop: 6 }}>
                <Activity size={12} /> Events
              </div>
              {!diag.result.events.ok ? (
                <Denied read={diag.result.events} what="Events" />
              ) : diag.result.events.items.length === 0 ? (
                <div className="faint" style={{ fontSize: 12 }}>
                  No events for this pod. They expire after about an hour, so this is not proof
                  nothing happened.
                </div>
              ) : (
                <EventRows events={diag.result.events.items} />
              )}

              <div className="s-title" style={{ marginTop: 10 }}>
                <ScrollText size={12} /> Previous container
              </div>
              {textBlock(diag.result.previousLogs, 'Previous container logs')}

              <div className="s-title" style={{ marginTop: 10 }}>
                <Boxes size={12} /> describe
              </div>
              {textBlock(diag.result.describe, 'Describe')}
            </>
          )}
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
