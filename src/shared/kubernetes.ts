// Kubernetes: contexts, namespaces and pods on a server that has kubectl.
//
// The roadmap is blunt about this one — "contexts, namespaces and RBAC are a
// product in themselves, and doing it badly is worse than not doing it" — so
// what ships here is deliberately the readable half, and the file says where
// the line is rather than leaving the next person to discover it.
//
// WHAT THIS DOES: reads the current context, lists contexts and namespaces,
// lists pods with their real state, and reads a pod's logs.
//
// It also does the things an operator reaches for during an incident, because
// the first version of this file was reconnaissance rather than operations —
// it could tell you a pod was in CrashLoopBackOff and then had nothing further
// to say, which is the point at which everyone gives up and opens a terminal:
//  - `describe pod` plus that pod's EVENTS. A Pending or CrashLoopBackOff pod
//    is unreadable without its events; they carry the scheduler's reason, the
//    image pull error, the failing probe.
//  - The PREVIOUS container's logs. For a crashlooping pod the current
//    container is usually seconds old and empty, and the previous one holds the
//    stack trace. Showing only the current logs is showing the useless half.
//  - Deployments, StatefulSets and DaemonSets with ready/desired, node status,
//    namespace-wide events newest first, and `kubectl top` when a Metrics API
//    is present.
//  - Exactly one thing that changes the cluster: `kubectl rollout restart`.
//
// WHAT IT DELIBERATELY DOES NOT DO:
//  - Switch contexts. `kubectl config use-context` mutates the user's kubeconfig
//    for every process on that host, not just for us. A tool that silently
//    repoints someone's cluster because they clicked a dropdown is how you
//    apply a manifest to prod believing it is staging. Context is chosen per
//    read, with `--context`, and never persisted.
//  - Exec into a pod. That is `docker exec` with more blast radius and an
//    entirely separate RBAC story, and it belongs behind the same approval
//    model broadcast has rather than a button next to a pod name.
//  - Delete anything — including a single pod, which is the one deletion people
//    ask for. The brief was to work out whether we can TELL when it is safe,
//    and the honest answer is only half. `.metadata.ownerReferences` does say
//    whether a controller will recreate the pod, so the catastrophic case (a
//    bare pod, owned by nothing, gone for good) is detectable. What it does not
//    say is whether the workload can afford to lose that replica right now: a
//    one-replica Deployment's pod is "safe" by ownership and an outage in fact,
//    and a pod that is currently the only Ready endpoint behind a Service is
//    the same. Distinguishing those needs the endpoint state at the moment of
//    the click, which we do not have. `rollout restart` reaches the same
//    remediation through the controller, gradually and reversibly, so the
//    delete button buys a narrow "this one pod is wedged" case at the price of
//    a control that is unrecoverable when it is wrong. Not worth it.
//  - Apply, scale, drain, cordon, or edit. Scale and drain in particular read
//    like the same class of action as a restart and are not: a rollout restart
//    converges back to the workload's own declared state, and scale and drain
//    leave the cluster somewhere the user now has to remember to undo.
//  - Reach the MCP bridge. Nothing here is registered as an agent tool. The
//    bridge gates `execute_command` per server against an access group; a
//    cluster-wide restart primitive is a different risk with a different
//    consent story, and it would arrive there by accident rather than by
//    decision. `rollout restart` is a human clicking a confirm dialog.
//
// RBAC is the part that makes Kubernetes different from Docker, and the honest
// position is that we cannot predict it: a token may list pods in one namespace
// and nothing in another, and `kubectl` reports that as an error on stderr with
// a zero-length list. Reporting "no pods" for a permissions failure is the same
// lie the Docker module is shaped to avoid, so the failure classes below carry
// the same weight as the data.

export interface K8sPod {
  namespace: string
  name: string
  /** Ready containers over total, as kubectl prints it: "1/1", "0/2". */
  ready: string
  /** Running, Pending, CrashLoopBackOff, Completed, Error, … */
  status: string
  restarts: number
  age: string
  node: string
}

export interface K8sContext {
  name: string
  current: boolean
}

export type K8sProbe =
  | {
      ok: true
      /** Client version string, or null when kubectl printed something unexpected. */
      version: string | null
      contexts: K8sContext[]
      currentContext: string | null
      namespaces: string[]
      pods: K8sPod[]
      /**
       * True when pods were listed across all namespaces. False when RBAC
       * limited us to one, which changes what an empty list means.
       */
      allNamespaces: boolean
    }
  | { ok: false; reason: K8sFailure; detail: string }

/**
 * Why kubectl could not be read.
 *
 * `forbidden` and `no-cluster` are the two that matter and the two a naive
 * implementation collapses into "no pods". They have nothing in common: one is
 * a token that needs different RBAC, the other is a kubeconfig pointing at
 * something that is not answering.
 */
export type K8sFailure =
  | 'not-installed'
  | 'no-kubeconfig'
  | 'no-cluster'
  | 'forbidden'
  | 'unauthorized'
  /**
   * `kubectl top` answered, and there is no Metrics API behind it.
   *
   * Its own class because the alternative is showing an empty usage table,
   * which reads as "this cluster is idle" — the same lie as "no pods" for a
   * permissions failure, just about a different resource. An RBAC denial ON
   * the metrics API is still `forbidden`; this is the case where the API is
   * not there at all.
   */
  | 'no-metrics'
  /**
   * There is no previous container instance to read logs from.
   *
   * Not really a failure — it means this container has never restarted — but
   * it arrives as a kubectl error and would otherwise be rendered as one, or
   * worse, as an empty log pane that looks like a container which crashed
   * silently.
   */
  | 'no-previous'
  | 'unknown'

export const K8S_FAILURE_HELP: Record<K8sFailure, string> = {
  // Says where we looked, because we now look. The old wording — "or not on the
  // PATH an SSH session gets" — described a limitation that resolveBinary
  // removed, so it sent people to check a PATH that had already been searched.
  'not-installed':
    'No kubectl on this host. Looked on PATH and in /usr/bin, /usr/local/bin, /snap/bin, /opt/homebrew/bin, /usr/sbin, plus the k3s, rke2 and microk8s wrappers. If it lives somewhere else, a symlink into /usr/local/bin is the usual fix.',
  'no-kubeconfig':
    'kubectl is installed but found no kubeconfig. It looks in $KUBECONFIG then ~/.kube/config, and an SSH session may not have the same environment as a login shell.',
  'no-cluster':
    'kubectl has a config but the cluster is not answering — the API server may be down, or the context may point somewhere unreachable from this host.',
  forbidden:
    'This account is authenticated but its RBAC does not allow listing these resources. That is a different problem from there being none, and the roles it needs are named in the raw error below.',
  unauthorized:
    'The cluster rejected these credentials. A token or client certificate has most likely expired.',
  'no-metrics':
    'kubectl top needs a Metrics API in the cluster — metrics-server, or whatever your provider ships — and nothing is answering on it. This is not "zero usage": there is no source to ask. If metrics-server was installed in the last minute or two it may simply not have scraped yet.',
  'no-previous':
    'This container has no previous instance, which means it has not restarted. There is nothing to read, and that is good news about this pod rather than a failed read.',
  unknown: 'kubectl returned an error that could not be classified. The raw message is below.'
}

/**
 * Why there is no sudo retry here, unlike Docker.
 *
 * Docker's "permission denied" is a unix group problem, and root fixes it.
 * Kubernetes `forbidden` is cluster RBAC — it is about the identity in the
 * kubeconfig, not the uid running kubectl — so `sudo kubectl` does not
 * escalate anything. Worse, it reads ROOT's kubeconfig, which usually does not
 * exist, turning a precise "your token cannot list pods" into a vague "no
 * configuration has been provided" and sending the user somewhere unrelated.
 *
 * The useful failover for kubectl is finding the binary, which is what
 * buildK8sReadCommand does.
 */
export const K8S_SUDO_DOES_NOT_HELP = true

/**
 * Classify a failed kubectl invocation.
 *
 * Ordered most specific first. `forbidden` is checked before `no-cluster`
 * because an RBAC denial mentions the server too, and getting that order wrong
 * sends someone to debug a healthy API server.
 */
export function classifyK8sFailure(stderr: string, exitCode: number | null): K8sFailure {
  const s = stderr.toLowerCase()
  // "not installed" is restricted to SHELL wordings, and is checked last among
  // the specific cases rather than first.
  //
  // The Docker module had exactly this bug and it is worth not repeating: a
  // path error like `stat /home/u/.kube/config: no such file or directory` is
  // a config problem on a host that HAS kubectl, and classifying it as a
  // missing binary sends someone to install something that is already there.
  const shellMissing =
    /(^|:\s)(command not found|kubectl: not found)|is not recognized as an internal/.test(s) ||
    exitCode === 127
  if (/forbidden|cannot list resource|is not allowed|rbac/.test(s)) return 'forbidden'
  if (/unauthorized|invalid bearer token|certificate has expired|token is expired/.test(s)) {
    return 'unauthorized'
  }
  // AFTER forbidden/unauthorized, deliberately. `nodes.metrics.k8s.io is
  // forbidden` is an RBAC denial that happens to name the metrics API, and
  // classifying it as "no metrics-server" would send someone to install a
  // component that is already running.
  if (
    /metrics api not available|metrics not available yet|metrics-server|heapster|\.metrics\.k8s\.io/.test(
      s
    )
  ) {
    return 'no-metrics'
  }
  // `kubectl logs --previous` on a container that has never restarted. The
  // words "not found" appear, which is why this is checked before the
  // missing-binary rule rather than left to fall through to `unknown`.
  if (/previous terminated container/.test(s)) return 'no-previous'
  if (/no configuration has been provided|kubeconfig|\.kube\/config/.test(s)) return 'no-kubeconfig'
  if (shellMissing) return 'not-installed'
  if (/forbidden|cannot list resource|is not allowed|rbac/.test(s)) return 'forbidden'
  if (/unauthorized|invalid bearer token|certificate has expired|token is expired/.test(s)) {
    return 'unauthorized'
  }
  // "did you specify the right host or port" is what kubectl says for a dead
  // cluster; the kubeconfig wordings above already claimed the no-config case.
  if (
    /connection refused|unable to connect|dial tcp|i\/o timeout|no route to host|did you specify the right host|was refused/.test(
      s
    )
  ) {
    return 'no-cluster'
  }
  return 'unknown'
}

import { resolveBinary } from './docker'

// Names are echoed into a shell command, so they are validated rather than
// escaped — the same rule the log tailer and the docker module follow.
// Kubernetes names are RFC 1123 labels; contexts are looser but bounded.
const NAME_RE = /^[a-z0-9]([-a-z0-9.]{0,251}[a-z0-9])?$/i
const CONTEXT_RE = /^[a-zA-Z0-9][a-zA-Z0-9_.:@/-]{0,252}$/

export const validatePodName = (v: string): boolean => NAME_RE.test(v.trim())
export const validateNamespace = (v: string): boolean => NAME_RE.test(v.trim())
export const validateContext = (v: string): boolean => CONTEXT_RE.test(v.trim())


/**
 * Every kubectl invocation in this file goes through the same PATH resolution.
 *
 * `ssh host cmd` runs a NON-LOGIN shell — PATH is roughly /usr/bin:/bin, with
 * no /usr/local/bin and no /snap/bin. kubectl is very commonly installed in
 * exactly those places, so "command not found" over SSH usually means "not
 * where this shell looks" rather than "not installed", and those have
 * different fixes. k3s and microk8s ship their own wrappers, which is why they
 * are in the list.
 *
 * It is one function rather than a line copied into each builder because the
 * logs builder originally called a bare `kubectl`: the pod list resolved the
 * binary and worked, then the log button on one of those very pods said
 * kubectl was not installed. A resolver used by only some of the callers is
 * worse than none, because it makes the failure inconsistent.
 */
export const k8sResolve = (): string =>
  resolveBinary('kubectl', [
    '/var/lib/rancher/rke2/bin/kubectl',
    '/usr/local/bin/k3s',
    '/snap/bin/microk8s.kubectl'
  ])

/** The resolved binary, as it is written into a command. */
const K = '"$SP_BIN"'

/**
 * On EVERY call, without exception.
 *
 * kubectl's default is to wait forever. A dead cluster would otherwise hang the
 * SSH exec until the transport's own timeout, with no output to explain why —
 * and a multi-call round trip would spend that wait several times over.
 */
const T = ' --request-timeout=10s'

/**
 * One kubectl call, with the shared flags and the section marker that lets the
 * parser tell this call's output from the next one's.
 *
 * Markers are echoed BEFORE the block, matching buildK8sReadCommand, so that a
 * call which produces nothing still leaves an empty section rather than
 * shifting the following one's output into it.
 */
const call = (marker: string, args: string): string =>
  `echo "===SHELLPILOT-${marker}==="; ${K} ${args}${T} 2>&1`

/**
 * One round trip that reads everything.
 *
 * `--request-timeout` on every call: kubectl's default is to wait forever, and
 * a dead cluster would otherwise hang the SSH exec until its own timeout, with
 * no output to explain why.
 *
 * Pods are attempted across all namespaces first and fall back to the current
 * one, because `--all-namespaces` is the common RBAC denial and falling back is
 * more useful than failing. The marker records which happened so an empty list
 * can be described accurately.
 */
export function buildK8sReadCommand(context?: string, namespace?: string): string {
  const ctx = context && validateContext(context) ? ` --context=${context}` : ''
  const ns = namespace && validateNamespace(namespace) ? ` --namespace=${namespace}` : ''
  const t = T
  const resolve = k8sResolve()
  const k = K
  // PHASE is not what kubectl shows, and the difference is the whole point of
  // this column.
  //
  // `.status.phase` for a CrashLoopBackOff pod is literally `Running` — the pod
  // is running, it is the container inside that keeps dying. kubectl's own
  // STATUS column shows the container's waiting/terminated REASON instead, which
  // is why kubectl says `CrashLoopBackOff` and `ImagePullBackOff` where the
  // phase says `Running` and `Pending`.
  //
  // Caught against a real cluster: a deliberately crashlooping pod with three
  // restarts was reported as `Running`, which is the one word that makes an
  // operator stop looking. `podTone` keys on CrashLoopBackOff and could never
  // have matched either.
  const cols =
    `custom-columns=NS:.metadata.namespace,NAME:.metadata.name,` +
    `READY:.status.containerStatuses[*].ready,PHASE:.status.phase,` +
    // How many containers the pod ASKED for. A pod that never scheduled has no
    // containerStatuses at all, so counting those gives 0/0 where kubectl says
    // 0/1 — it falls back to the spec, and so do we.
    `WANT:.spec.containers[*].name,` +
    `WAIT:.status.containerStatuses[*].state.waiting.reason,` +
    `TERM:.status.containerStatuses[*].state.terminated.reason,` +
    `RESTARTS:.status.containerStatuses[*].restartCount,NODE:.spec.nodeName,START:.status.startTime`
  return [
    resolve,
    `${k} version --client -o json${t} 2>&1`,
    'echo "===SHELLPILOT-CTX==="',
    `${k} config get-contexts --no-headers${t} 2>&1`,
    'echo "===SHELLPILOT-NS==="',
    `${k} get ns --no-headers -o custom-columns=NAME:.metadata.name${ctx}${t} 2>&1`,
    'echo "===SHELLPILOT-PODS-ALL==="',
    `${k} get pods --all-namespaces --no-headers -o ${cols}${ctx}${t} 2>&1`,
    'echo "===SHELLPILOT-PODS-NS==="',
    `${k} get pods --no-headers -o ${cols}${ctx}${ns}${t} 2>&1`
  ].join('; ')
}

const section = (output: string, name: string): string => {
  // \r?\n: a host whose shell emits CRLF would otherwise match no marker at
  // all and report an empty cluster. The cron collector had this exact bug.
  const m = output.match(new RegExp(`===SHELLPILOT-${name}===\\r?\\n([\\s\\S]*?)(?====SHELLPILOT-|$)`))
  return m ? m[1] : ''
}

// Only ever applied to a line that does NOT parse as data.
//
// A namespace called `error-reporting`, or a pod named `unauthorized-probe`,
// is a perfectly ordinary thing to have — and matching this pattern against
// data lines would silently drop it. The Docker module hit the same trap with a
// container named `permission-denied-test`. kubectl's own errors are prefixed
// (`error:`, `Error from server`) or are a bare sentence with spaces, neither
// of which a single resource name can be.
const looksLikeError = (text: string): boolean =>
  /^\s*(error[:\s]|Error from server|The connection to the server|Unable to connect)/i.test(text) ||
  // Only with surrounding spaces: these are sentences kubectl writes, not
  // fragments of a name. `\bunauthorized\b` matched inside
  // `unauthorized-probe`, because a hyphen is a word boundary — so a perfectly
  // ordinary namespace disappeared from the list.
  /(^|\s)(forbidden|unauthorized)(\s|:|$)/i.test(text) ||
  /connection refused|permission denied/i.test(text)

/** `custom-columns` prints `<none>` for an absent value and joins arrays with commas. */
function cleanCell(v: string): string {
  return v === '<none>' || v === '<nil>' ? '' : v
}

/** First real reason in a comma-joined custom-columns cell, or null. */
function firstReason(cell: string): string | null {
  for (const r of cleanCell(cell).split(',')) {
    const v = r.trim()
    if (v !== '' && v !== '<none>') return v
  }
  return null
}

function parsePods(text: string): K8sPod[] {
  const pods: K8sPod[] = []
  for (const raw of text.split('\n')) {
    const line = raw.trim()
    if (line === '' || looksLikeError(line)) continue
    const f = line.split(/\s+/)
    if (f.length < 10) continue
    const [ns, name, ready, phase, want, wait, term, restarts, node, start] = f
    // READY comes back as "true,true" or "true,false"; kubectl's own table
    // shows "2/2". Reconstructing it keeps the column meaning what operators
    // expect rather than showing raw booleans.
    const flags = cleanCell(ready).split(',').filter(Boolean)
    const readyCount = flags.filter((x) => x === 'true').length
    const restartList = cleanCell(restarts).split(',').filter(Boolean).map(Number)
    pods.push({
      namespace: ns,
      name,
      ready: flags.length
        ? `${readyCount}/${flags.length}`
        : `0/${cleanCell(want).split(',').filter(Boolean).length || 0}`,
      // Reason first, phase as the fallback — the order kubectl itself uses.
      // A multi-container pod reports one reason per container; the first
      // non-empty one is the one that explains why the pod is not ready.
      status: firstReason(wait) ?? firstReason(term) ?? phase,
      restarts: restartList.length ? Math.max(...restartList) : 0,
      age: cleanCell(start),
      node: cleanCell(node)
    })
  }
  return pods
}

function parseContexts(text: string): { contexts: K8sContext[]; current: string | null } {
  const contexts: K8sContext[] = []
  let current: string | null = null
  for (const raw of text.split('\n')) {
    const line = raw.trimEnd()
    if (line.trim() === '' || looksLikeError(line)) continue
    // `get-contexts --no-headers` marks the current one with a leading `*`.
    const isCurrent = /^\s*\*/.test(line)
    const f = line.replace(/^\s*\*?\s*/, '').split(/\s+/)
    if (!f[0]) continue
    contexts.push({ name: f[0], current: isCurrent })
    if (isCurrent) current = f[0]
  }
  return { contexts, current }
}

export function parseK8sOutput(output: string, exitCode: number | null): K8sProbe {
  const versionText = (output.split('===SHELLPILOT-CTX===')[0] ?? '').trim()

  // The version probe is the only one that tells us kubectl exists at all.
  if (!output.includes('===SHELLPILOT-CTX===') || /command not found|not found/i.test(versionText)) {
    return {
      ok: false,
      reason: classifyK8sFailure(versionText, exitCode),
      detail: versionText.split('\n')[0] || 'kubectl did not run'
    }
  }

  const ctxText = section(output, 'CTX')
  const nsText = section(output, 'NS')
  const allText = section(output, 'PODS-ALL')
  const nsPodText = section(output, 'PODS-NS')

  // If every read failed the same way, that is the answer — reporting an empty
  // cluster would be the lie this module exists to avoid.
  const allFailed = [ctxText, nsText, allText, nsPodText].every(
    (t) => t.trim() === '' || looksLikeError(t)
  )
  if (allFailed) {
    const firstError = [ctxText, nsText, allText, nsPodText]
      .map((t) => t.split('\n').find((l) => looksLikeError(l)))
      .find(Boolean)
    return {
      ok: false,
      reason: classifyK8sFailure(firstError ?? '', exitCode),
      detail: (firstError ?? 'kubectl returned nothing').trim()
    }
  }

  const { contexts, current } = parseContexts(ctxText)
  // A namespace line is one token that is a valid Kubernetes name. Deciding by
  // SHAPE rather than by content is immune to what anyone calls a namespace —
  // an error from kubectl is a sentence with spaces and cannot be mistaken for
  // one, and `unauthorized-probe` cannot be mistaken for an error.
  const namespaces = nsText
    .split('\n')
    .map((l) => l.trim())
    .filter((l) => l !== '' && !/\s/.test(l) && validateNamespace(l))

  // --all-namespaces is the common RBAC denial. Falling back to the current
  // namespace is more useful than failing, and recording which one answered is
  // what lets an empty list be described honestly.
  const allOk = !looksLikeError(allText) && allText.trim() !== ''
  const pods = allOk ? parsePods(allText) : parsePods(nsPodText)

  const versionMatch = versionText.match(/"gitVersion"\s*:\s*"([^"]+)"/)
  return {
    ok: true,
    version: versionMatch ? versionMatch[1] : null,
    contexts,
    currentContext: current,
    namespaces,
    pods,
    allNamespaces: allOk
  }
}

/**
 * `kubectl logs`, bounded. Never built from unvalidated names.
 *
 * `previous` reads the container instance BEFORE the running one, which for a
 * crashlooping pod is the only instance with anything in it — the current
 * container is usually a few seconds old and empty. It is a separate flag
 * rather than the default because on a healthy pod it is an error, and because
 * a pane that silently swaps which instance it is showing is a pane you cannot
 * trust during an incident.
 */
export function buildK8sLogsCommand(
  namespace: string,
  pod: string,
  lines = 200,
  context?: string,
  opts: { previous?: boolean } = {}
): string {
  if (!validateNamespace(namespace) || !validatePodName(pod)) {
    throw new Error('refusing to build a command from an invalid pod or namespace name')
  }
  const n = Math.min(5_000, Math.max(1, Math.floor(Number(lines))))
  const safe = Number.isFinite(n) ? n : 200
  const ctx = context && validateContext(context) ? ` --context=${context}` : ''
  const prev = opts.previous ? ' --previous' : ''
  // --all-containers so a multi-container pod does not silently show one of
  // them; --prefix so you can tell which.
  //
  // Through the resolver, like every other call: the pod list finds kubectl in
  // /usr/local/bin over SSH and this used to call a bare `kubectl`, so the log
  // button on a pod we had just listed reported that kubectl was not installed.
  return [
    k8sResolve(),
    `${K} logs --namespace=${namespace} ${pod} --tail=${safe} --all-containers --prefix${prev}${T}${ctx} 2>&1`
  ].join('; ')
}

// ============================================================== operations
//
// Everything below is what an operator actually reaches for at 03:00, and the
// shape of all of it is set by one rule the read half already follows: a
// forbidden read must never render as "none".
//
// The difference here is that RBAC is PER RESOURCE. A token that lists pods
// very often cannot list events, and a token scoped to a namespace almost
// never lists nodes. Collapsing a round trip into one ok/failed answer would
// mean either throwing away the pods because the events were denied, or —
// worse — showing an empty events list next to a CrashLoopBackOff pod, which
// reads as "nothing happened to this pod" at exactly the moment something did.
// So every block below carries its own outcome.

/**
 * One resource read, with its own RBAC verdict.
 *
 * `{ ok: true, items: [] }` and a failure are different answers and the UI
 * must be able to tell them apart, which is the entire reason this is not
 * just `T[]`.
 */
export type K8sRead<T> =
  | { ok: true; items: T[] }
  | { ok: false; reason: K8sFailure; detail: string }

/** The same, for a block that is text a human reads rather than rows. */
export type K8sTextRead =
  | { ok: true; text: string }
  | { ok: false; reason: K8sFailure; detail: string }

export interface K8sEvent {
  namespace: string
  /** `Normal` or `Warning`. Warnings are what you are looking for. */
  type: string
  /** BackOff, Failed, FailedScheduling, Unhealthy, Killing, … */
  reason: string
  /** The kind and name of the object it happened to. */
  objectKind: string
  objectName: string
  /** How many times this event has repeated. 1 when the field is absent. */
  count: number
  /** RFC3339, or '' when kubectl had neither timestamp. */
  lastSeen: string
  message: string
}

export type K8sWorkloadKind = 'deployment' | 'statefulset' | 'daemonset'

export const K8S_WORKLOAD_KINDS: readonly K8sWorkloadKind[] = [
  'deployment',
  'statefulset',
  'daemonset'
]

export interface K8sWorkload {
  kind: K8sWorkloadKind
  namespace: string
  name: string
  /** Replicas the spec asks for. For a DaemonSet, nodes it should run on. */
  desired: number
  ready: number
  updated: number
  available: number
  /**
   * RollingUpdate, Recreate, OnDelete, or '' when kubectl did not say.
   *
   * Read, rather than assumed, because it is the difference between a restart
   * that keeps the service up and one that takes it fully down — and the
   * confirmation the user is asked for depends on knowing which.
   */
  strategy: string
  /** RFC3339 creation timestamp. */
  created: string
}

export interface K8sNode {
  name: string
  /** Ready, NotReady, Ready,SchedulingDisabled, Unknown. */
  status: string
  roles: string
  age: string
  version: string
}

export interface K8sPodUsage {
  namespace: string
  name: string
  /** As kubectl prints it: "12m", "1005m". */
  cpu: string
  /** As kubectl prints it: "45Mi". */
  memory: string
}

export interface K8sNodeUsage {
  name: string
  cpu: string
  cpuPercent: string
  memory: string
  memoryPercent: string
}

/** Everything the "why is this pod unhealthy" round trip brings back. */
export interface K8sDiagnosis {
  namespace: string
  pod: string
  describe: K8sTextRead
  events: K8sRead<K8sEvent>
  /** The previous container instance's logs — the crashloop's actual story. */
  previousLogs: K8sTextRead
}

export interface K8sOverview {
  deployments: K8sRead<K8sWorkload>
  statefulSets: K8sRead<K8sWorkload>
  daemonSets: K8sRead<K8sWorkload>
  nodes: K8sRead<K8sNode>
  events: K8sRead<K8sEvent>
}

export interface K8sUsage {
  pods: K8sRead<K8sPodUsage>
  nodes: K8sRead<K8sNodeUsage>
}

/**
 * Events kept after sorting, per block.
 *
 * A busy namespace produces thousands and nobody reads past the first screen;
 * the cap is applied AFTER sorting newest-first so it keeps the ones that
 * matter rather than whichever the API happened to return first.
 */
export const K8S_EVENT_LIMIT = 200

/**
 * Bytes of raw event output the shell will pass back.
 *
 * A cluster in trouble emits events faster than anything else, and this is the
 * one block that can genuinely return megabytes. Truncation costs the tail of
 * one line, which the parser then skips.
 */
const EVENT_BYTE_CAP = 200_000

// MESSAGE is last on purpose: it is the only column that contains spaces, so
// the parser can split the fixed columns off the front and keep the rest whole.
// Putting it anywhere else would truncate every message at its first space.
const EVENT_COLS =
  'custom-columns=LAST:.lastTimestamp,ETIME:.eventTime,TYPE:.type,REASON:.reason,' +
  'KIND:.involvedObject.kind,OBJECT:.involvedObject.name,NS:.metadata.namespace,' +
  'COUNT:.count,MESSAGE:.message'

const EVENT_FIXED_COLS = 8

// Shared by all three workload kinds so one parser can read them. The field
// paths differ per kind — a DaemonSet counts nodes, not replicas — which is
// exactly why they are spelled out per kind rather than guessed.
const workloadCols = (kind: K8sWorkloadKind): string => {
  const head = 'custom-columns=NS:.metadata.namespace,NAME:.metadata.name,'
  const tail = ',AGE:.metadata.creationTimestamp'
  if (kind === 'deployment') {
    return `${head}DESIRED:.spec.replicas,READY:.status.readyReplicas,UPDATED:.status.updatedReplicas,AVAILABLE:.status.availableReplicas,STRATEGY:.spec.strategy.type${tail}`
  }
  if (kind === 'statefulset') {
    return `${head}DESIRED:.spec.replicas,READY:.status.readyReplicas,UPDATED:.status.updatedReplicas,AVAILABLE:.status.currentReplicas,STRATEGY:.spec.updateStrategy.type${tail}`
  }
  return `${head}DESIRED:.status.desiredNumberScheduled,READY:.status.numberReady,UPDATED:.status.updatedNumberScheduled,AVAILABLE:.status.numberAvailable,STRATEGY:.spec.updateStrategy.type${tail}`
}

const scope = (context?: string, namespace?: string): { ctx: string; ns: string } => ({
  ctx: context && validateContext(context) ? ` --context=${context}` : '',
  ns: namespace && validateNamespace(namespace) ? ` --namespace=${namespace}` : ' --all-namespaces'
})

/**
 * The first thing anyone runs on a pod that is not Running.
 *
 * Three calls in one round trip because they are one question. `describe`
 * already prints an Events section, and it is not enough on its own: it shows
 * only events still within the API server's retention for that object and
 * elides the repeats, and — the part that matters here — `describe` needs GET
 * on pods while events need LIST on events, so a token can be allowed one and
 * denied the other. Asking separately is what lets the panel say which of the
 * two was refused instead of showing a pod with no explanation.
 *
 * Throws rather than escapes, like every other builder in this file.
 */
export function buildK8sDiagnoseCommand(
  namespace: string,
  pod: string,
  context?: string,
  previousLines = 200
): string {
  if (!validateNamespace(namespace) || !validatePodName(pod)) {
    throw new Error('refusing to build a command from an invalid pod or namespace name')
  }
  const ctx = context && validateContext(context) ? ` --context=${context}` : ''
  const n = Math.min(5_000, Math.max(1, Math.floor(Number(previousLines))))
  const lines = Number.isFinite(n) ? n : 200
  const ns = ` --namespace=${namespace}`
  return [
    k8sResolve(),
    call('DESCRIBE', `describe pod ${pod}${ns}${ctx}`),
    // Scoped to this one object. `kubectl get events` unfiltered in a busy
    // namespace buries the pod you are looking at under everything else.
    call(
      'EVENTS',
      `get events${ns} --field-selector=involvedObject.name=${pod} --no-headers -o ${EVENT_COLS}${ctx}`
    ),
    call('PREVIOUS', `logs ${pod}${ns} --previous --all-containers --prefix --tail=${lines}${ctx}`)
  ].join('; ')
}

/**
 * Workloads, nodes and recent events — the "what is actually broken" sweep.
 *
 * One round trip rather than five channels: during an incident these are read
 * together, and five sequential SSH round trips through a bastion is five
 * times the latency for the same screen. Each block still carries its own RBAC
 * verdict, so a token that can list deployments but not nodes gets the
 * deployments and an honest sentence about the nodes.
 */
export function buildK8sOverviewCommand(context?: string, namespace?: string): string {
  const { ctx, ns } = scope(context, namespace)
  return [
    k8sResolve(),
    call('DEPLOY', `get deployments${ns} --no-headers -o ${workloadCols('deployment')}${ctx}`),
    call('STS', `get statefulsets${ns} --no-headers -o ${workloadCols('statefulset')}${ctx}`),
    call('DS', `get daemonsets${ns} --no-headers -o ${workloadCols('daemonset')}${ctx}`),
    // Nodes are cluster-scoped: --namespace does not apply and passing it would
    // be a lie about what is being read. A namespace-scoped token is denied
    // here, which is a normal answer and is reported as one.
    call('NODES', `get nodes --no-headers${ctx}`),
    `${call('EVENTS', `get events${ns} --no-headers -o ${EVENT_COLS}${ctx}`)} | head -c ${EVENT_BYTE_CAP}`
  ].join('; ')
}

/**
 * `kubectl top`, which needs a Metrics API that most clusters do not have.
 *
 * Separate from the overview because it is the one read whose absence is
 * normal. Folding it in would make every overview wait on a call that fails on
 * a majority of clusters, and would tempt the parser into showing an empty
 * usage table — which reads as "idle" rather than "not measured".
 */
export function buildK8sTopCommand(context?: string, namespace?: string): string {
  const { ctx, ns } = scope(context, namespace)
  return [
    k8sResolve(),
    call('TOPPODS', `top pods${ns} --no-headers${ctx}`),
    call('TOPNODES', `top nodes --no-headers${ctx}`)
  ].join('; ')
}

/**
 * The one command in this file that changes the cluster.
 *
 * `rollout restart` patches a restart annotation into the pod template, and the
 * controller then replaces the pods under its own update strategy. That is the
 * most common remediation there is, and it is also the reason the approval
 * model applies — see planK8sRollout below for why it is never a bare click.
 *
 * The read that follows it is `rollout status --watch=false`. Without
 * `--watch=false` kubectl blocks until the rollout finishes, which on a stuck
 * image pull is forever: it would hold the SSH exec open past every timeout
 * and leave the user with a spinner and no idea whether the restart even
 * started. One-shot status answers the only question that matters immediately,
 * which is whether the API server accepted it.
 */
export function buildK8sRolloutRestartCommand(
  kind: K8sWorkloadKind,
  namespace: string,
  name: string,
  context?: string
): string {
  // The kind is an allowlist rather than a validated string: there is no
  // reason for it to be free text, and `rollout restart` accepts resource
  // types we have not thought about.
  if (!K8S_WORKLOAD_KINDS.includes(kind)) {
    throw new Error('refusing to restart a resource kind this module does not know')
  }
  if (!validateNamespace(namespace) || !validatePodName(name)) {
    throw new Error('refusing to build a command from an invalid workload or namespace name')
  }
  const ctx = context && validateContext(context) ? ` --context=${context}` : ''
  const ns = ` --namespace=${namespace}`
  return [
    k8sResolve(),
    call('RESTART', `rollout restart ${kind}/${name}${ns}${ctx}`),
    call('STATUS', `rollout status ${kind}/${name}${ns} --watch=false${ctx}`)
  ].join('; ')
}

// ------------------------------------------------------- parsing the blocks

// `kubectl` prints this when a read SUCCEEDED and matched nothing. It is
// recognised explicitly rather than left to fall through: today the shape tests
// in each parser reject it anyway and `looksLikeError` does not match it, so
// this is belt-and-braces — but the day someone widens the error pattern, the
// thing it would quietly turn into is "this account was denied", which is the
// exact inversion this module exists to prevent.
const NO_RESOURCES = /^no resources found/i

/**
 * Turn one block into rows or into an honest failure.
 *
 * Three outcomes, and the middle one is the whole point:
 *  - rows parsed → ok, even if an error line also appears. A partial answer is
 *    still an answer, and dropping it because kubectl also grumbled would lose
 *    real data.
 *  - nothing parsed and an error line present → that failure, classified.
 *  - nothing parsed and no error → genuinely empty. "No resources found in X
 *    namespace" is kubectl SUCCEEDING, and reads as an error to anything
 *    matching on the word "no" — so it is recognised explicitly.
 */
function readBlock<T>(
  text: string,
  parse: (t: string) => T[],
  exitCode: number | null
): K8sRead<T> {
  const items = parse(text)
  if (items.length > 0) return { ok: true, items }
  const trimmed = text.trim()
  if (trimmed === '' || NO_RESOURCES.test(trimmed)) return { ok: true, items: [] }
  const errLine = text
    .split('\n')
    .map((l) => l.trim())
    .find((l) => l !== '' && looksLikeError(l))
  if (errLine) {
    return { ok: false, reason: classifyK8sFailure(errLine, exitCode), detail: errLine }
  }
  return { ok: true, items: [] }
}

/** The same for a text block, where "did it work" is not a row count. */
function readTextBlock(text: string, exitCode: number | null): K8sTextRead {
  const trimmed = text.trim()
  if (trimmed === '') {
    return { ok: false, reason: 'unknown', detail: 'kubectl returned nothing for this read' }
  }
  const lines = trimmed.split('\n')
  // A text block is a failure only when the error is ALL there is. `describe`
  // output can legitimately contain the word "Forbidden" inside an event
  // message — that is a pod being told off by the API server, not a read that
  // was refused — and treating it as our own failure would replace the exact
  // explanation the operator opened this pane to see.
  const allError = lines.every((l) => l.trim() === '' || looksLikeError(l))
  if (allError) {
    const first = lines.find((l) => looksLikeError(l)) ?? trimmed
    return { ok: false, reason: classifyK8sFailure(first, exitCode), detail: first.trim() }
  }
  return { ok: true, text: trimmed }
}

const num = (v: string): number => {
  const n = Number(cleanCell(v))
  return Number.isFinite(n) ? n : 0
}

// A data row is recognised by its SHAPE, never by its content — the rule the
// pod parser above states and the one that matters most here.
//
// `looksLikeError` would have eaten the single most valuable event in the set:
// `Failed to pull image "x": ... 403 Forbidden` is a real Warning event, and
// its message ends in a word the error pattern matches with a leading space.
// The panel would then have shown a pod stuck in ImagePullBackOff next to an
// empty event list. Nothing kubectl writes as an error has `Normal` or
// `Warning` as its third whitespace-separated token, so that is the test.
const EVENT_TYPE_RE = /^(Normal|Warning)$/

function parseEvents(text: string): K8sEvent[] {
  const events: K8sEvent[] = []
  for (const raw of text.split('\n')) {
    const line = raw.trim()
    if (line === '' || NO_RESOURCES.test(line)) continue
    const f = line.split(/\s+/)
    if (f.length < EVENT_FIXED_COLS + 1) continue
    if (!EVENT_TYPE_RE.test(f[2])) continue
    const [last, etime, type, reason, kind, object, ns, count] = f
    // Everything after the fixed columns is the message, rejoined with single
    // spaces. custom-columns pads with spaces, so the original run-lengths are
    // not recoverable and are not meaningful either.
    const message = f.slice(EVENT_FIXED_COLS).join(' ')
    // Two timestamp fields because the two event APIs disagree: the legacy one
    // fills .lastTimestamp, events.k8s.io/v1 leaves it null and fills
    // .eventTime. Reading only the first is how a modern cluster's events all
    // come back with no time at all.
    const seen = cleanCell(last) || cleanCell(etime)
    events.push({
      namespace: cleanCell(ns),
      type: cleanCell(type),
      reason: cleanCell(reason),
      objectKind: cleanCell(kind),
      objectName: cleanCell(object),
      // .count is absent on the new API's non-series events, and an event that
      // happened once is exactly that rather than zero times.
      count: cleanCell(count) === '' ? 1 : num(count),
      lastSeen: seen,
      message
    })
  }
  // Newest first, which is how you find what just broke. Sorted here rather
  // than with `--sort-by`: that is a client-side sort inside kubectl which
  // errors outright on some versions when an item is missing the field, and
  // losing the whole block to a sort is a bad trade for an ordering we can do.
  // A stable sort keeps API order among events we could not time.
  const key = (e: K8sEvent): number => {
    const t = Date.parse(e.lastSeen)
    return Number.isFinite(t) ? t : -Infinity
  }
  return events.sort((a, b) => key(b) - key(a)).slice(0, K8S_EVENT_LIMIT)
}

/** A replica count column: a number, or `<none>` where the status is not set. */
const COUNT_CELL_RE = /^(\d+|<none>|<nil>)$/

function parseWorkloads(text: string, kind: K8sWorkloadKind): K8sWorkload[] {
  const rows: K8sWorkload[] = []
  for (const raw of text.split('\n')) {
    const line = raw.trim()
    if (line === '' || NO_RESOURCES.test(line)) continue
    const f = line.split(/\s+/)
    if (f.length < 8) continue
    const [ns, name, desired, ready, updated, available, strategy, created] = f
    // Shape again, and it is doing real work: `Error from server (Forbidden):
    // deployments.apps is forbidden: User ...` splits into eight-plus tokens
    // whose first two pass a name check, and without a numeric test on the
    // replica columns it would land in the list as a workload called `from` in
    // a namespace called `Error`.
    if (!validateNamespace(ns) || !validatePodName(name)) continue
    if (!COUNT_CELL_RE.test(desired) || !COUNT_CELL_RE.test(ready)) continue
    rows.push({
      kind,
      namespace: ns,
      name,
      desired: num(desired),
      ready: num(ready),
      updated: num(updated),
      available: num(available),
      strategy: cleanCell(strategy),
      created: cleanCell(created)
    })
  }
  return rows
}

/** What kubectl computes into the STATUS column, and nothing else. */
const NODE_STATUS_RE = /^(Ready|NotReady|Unknown)(,SchedulingDisabled)?$/

function parseNodes(text: string): K8sNode[] {
  const nodes: K8sNode[] = []
  for (const raw of text.split('\n')) {
    const line = raw.trim()
    if (line === '' || NO_RESOURCES.test(line)) continue
    // The default `get nodes` table: NAME STATUS ROLES AGE VERSION. Used
    // instead of custom-columns because STATUS there is a computed summary —
    // it is what turns a set of conditions into `NotReady` or
    // `Ready,SchedulingDisabled`, and reproducing that from JSONPath means
    // reimplementing kubectl's own logic slightly wrong.
    const f = line.split(/\s+/)
    if (f.length < 5) continue
    const [name, status, roles, age, version] = f
    if (!validatePodName(name) || !NODE_STATUS_RE.test(status)) continue
    nodes.push({ name, status, roles: cleanCell(roles), age, version })
  }
  return nodes
}

// `12m`, `1005m`, `0`. Quantities, which no line of kubectl error prose is.
const CPU_RE = /^\d+[mnu]?$/
const MEM_RE = /^\d+([KMGT]i)?$/

function parsePodUsage(text: string): K8sPodUsage[] {
  const rows: K8sPodUsage[] = []
  for (const raw of text.split('\n')) {
    const line = raw.trim()
    if (line === '' || NO_RESOURCES.test(line)) continue
    const f = line.split(/\s+/)
    // 4 fields with --all-namespaces (NAMESPACE NAME CPU MEM), 3 without.
    if (f.length === 4 && CPU_RE.test(f[2]) && MEM_RE.test(f[3])) {
      rows.push({ namespace: f[0], name: f[1], cpu: f[2], memory: f[3] })
    } else if (f.length === 3 && CPU_RE.test(f[1]) && MEM_RE.test(f[2])) {
      rows.push({ namespace: '', name: f[0], cpu: f[1], memory: f[2] })
    }
  }
  return rows
}

const PERCENT_RE = /^\d+%$/

function parseNodeUsage(text: string): K8sNodeUsage[] {
  const rows: K8sNodeUsage[] = []
  for (const raw of text.split('\n')) {
    const line = raw.trim()
    if (line === '' || NO_RESOURCES.test(line)) continue
    const f = line.split(/\s+/)
    if (f.length < 5) continue
    if (!PERCENT_RE.test(f[2]) || !PERCENT_RE.test(f[4])) continue
    rows.push({ name: f[0], cpu: f[1], cpuPercent: f[2], memory: f[3], memoryPercent: f[4] })
  }
  return rows
}

export function parseK8sDiagnosis(
  namespace: string,
  pod: string,
  output: string,
  exitCode: number | null
): K8sDiagnosis {
  return {
    namespace,
    pod,
    describe: readTextBlock(section(output, 'DESCRIBE'), exitCode),
    events: readBlock(section(output, 'EVENTS'), parseEvents, exitCode),
    previousLogs: readTextBlock(section(output, 'PREVIOUS'), exitCode)
  }
}

export function parseK8sOverview(output: string, exitCode: number | null): K8sOverview {
  return {
    deployments: readBlock(section(output, 'DEPLOY'), (t) => parseWorkloads(t, 'deployment'), exitCode),
    statefulSets: readBlock(section(output, 'STS'), (t) => parseWorkloads(t, 'statefulset'), exitCode),
    daemonSets: readBlock(section(output, 'DS'), (t) => parseWorkloads(t, 'daemonset'), exitCode),
    nodes: readBlock(section(output, 'NODES'), parseNodes, exitCode),
    events: readBlock(section(output, 'EVENTS'), parseEvents, exitCode)
  }
}

export function parseK8sUsage(output: string, exitCode: number | null): K8sUsage {
  return {
    pods: readBlock(section(output, 'TOPPODS'), parsePodUsage, exitCode),
    nodes: readBlock(section(output, 'TOPNODES'), parseNodeUsage, exitCode)
  }
}

export interface K8sRolloutResult {
  ok: boolean
  /** What `rollout restart` said. */
  output: string
  /** What `rollout status --watch=false` said, when it got that far. */
  status: string
  reason?: K8sFailure
  detail?: string
}

export function parseK8sRolloutResult(output: string, exitCode: number | null): K8sRolloutResult {
  const restart = section(output, 'RESTART').trim()
  const status = section(output, 'STATUS').trim()
  // kubectl prints `deployment.apps/web restarted` on success. Deciding on the
  // presence of an error rather than on that exact sentence, because the
  // wording has changed between versions and a version bump must not turn a
  // successful restart into a reported failure.
  const failed =
    restart === '' || restart.split('\n').every((l) => l.trim() === '' || looksLikeError(l))
  if (failed) {
    const first = restart.split('\n').find((l) => looksLikeError(l)) ?? restart
    return {
      ok: false,
      output: restart,
      status,
      reason: classifyK8sFailure(first, exitCode),
      detail: first.trim() || 'kubectl returned nothing'
    }
  }
  return { ok: true, output: restart, status }
}

// ------------------------------------------------------- the approval model
//
// shared/broadcast.ts settled how this project asks before it acts, and the
// reasoning transfers: confirmation strength scales with blast radius, nothing
// is safe by omission, and a guard that nags on the harmless case is a guard
// people learn to click through. The confirmation TYPE is imported rather than
// re-declared so there is one vocabulary in the app; what is computed from is
// different, because a rollout's blast radius is replicas rather than hosts.
//
// WHY A ROLLOUT RESTART IS NEVER A BARE CLICK, unlike broadcast's one-host
// harmless case: there is no harmless case. Every rollout restart terminates
// every running pod of that workload. On a healthy Deployment with a rolling
// strategy that is invisible to users and completely routine — which is
// precisely why it is easy to fire at the wrong row in a list where prod and
// staging namespaces sit three pixels apart. A confirm step naming the
// workload and namespace is the cheapest possible defence against the only
// mistake anyone actually makes here, which is target selection.
//
// WHY IT IS NOT `type-to-confirm` EVERY TIME: because it is not reboot. It is
// reversible in the sense that matters — the controller converges back to the
// workload's own declared state, no manifest is edited, nothing is deleted, and
// a restart of a healthy stateless Deployment is something operators do several
// times a day. Making them type a word for that is how the word stops meaning
// anything by the time a StatefulSet is selected.

import type { BroadcastConfirmation, BroadcastRisk } from './broadcast'

export interface K8sRolloutTarget {
  kind: K8sWorkloadKind
  namespace: string
  name: string
  /** Replicas the workload declares, or null when it was not read. */
  desired: number | null
  /** RollingUpdate | Recreate | OnDelete | null when it was not read. */
  strategy: string | null
  context?: string | null
}

export interface K8sRolloutPlan {
  target: K8sRolloutTarget
  risk: BroadcastRisk
  confirmation: BroadcastConfirmation
  reasons: string[]
  /**
   * Ways this will not do what the button implies.
   *
   * Kept apart from `reasons` because they are not arguments for pressing
   * harder — they are things that would otherwise be discovered afterwards,
   * from a restart that appeared to succeed and changed nothing.
   */
  caveats: string[]
}

/** Above this many replicas, a restart is a thundering herd worth typing for. */
export const K8S_TYPE_ABOVE_REPLICAS = 10

/**
 * Namespaces and contexts that look like production.
 *
 * A heuristic, and only ever used to escalate — never to relax a confirmation.
 * A namespace called `staging-prod-mirror` asking for one extra keystroke costs
 * nothing; the reverse mistake costs an outage. Bounded by separators so
 * `reproducible-builds` is not read as prod.
 */
const PROD_RE = /(^|[-_./:])(prod|production|prd|live)([-_./:]|$)/i

/**
 * How hard the user has to press to restart this workload.
 *
 * Never `none` — see the header above. Escalates to type-to-confirm on the four
 * cases where a restart stops being routine.
 */
export function planK8sRollout(target: K8sRolloutTarget): K8sRolloutPlan {
  const reasons: string[] = ['replaces every running pod of this workload']
  const caveats: string[] = []
  let risk: BroadcastRisk = 'elevated'
  let type = false

  if (target.kind === 'statefulset') {
    // A StatefulSet is where the data is. Its pods restart one at a time in
    // ordinal order, each waiting for the last to be Ready, so a restart of a
    // three-node database is three sequential leader elections — fine when
    // intended, and how you take a quorum down when it was the wrong row.
    risk = 'destructive'
    type = true
    reasons.push(
      'a StatefulSet holds state — its pods restart one at a time, in order, which is how a database quorum gets rolled'
    )
  }
  if (target.strategy === 'Recreate') {
    // Not a rolling update at all: every pod is stopped before any replacement
    // is started. This workload is down for the length of the restart.
    risk = 'destructive'
    type = true
    reasons.push(
      'the Recreate strategy stops every pod before starting any — this workload is fully down until the new pods are Ready'
    )
  }
  if (target.kind !== 'statefulset' && target.strategy !== 'Recreate' && (target.desired ?? 2) <= 1) {
    // One replica has no second pod to serve traffic. The default rolling
    // update does start the replacement first, so this is not certain
    // downtime — but it depends on the replacement being schedulable, and a
    // ReadWriteOnce volume, a host port or a full node all make it not.
    type = true
    reasons.push(
      'one replica — the replacement is started first, but if it cannot be scheduled (a ReadWriteOnce volume, a host port, a full node) this workload stays down until it can'
    )
  }
  if ((target.desired ?? 0) >= K8S_TYPE_ABOVE_REPLICAS) {
    type = true
    reasons.push(
      `${target.desired} replicas restart from this one click, which is a real load spike on whatever they connect to`
    )
  }
  const prodHit = [target.namespace, target.context ?? ''].find((v) => v && PROD_RE.test(v))
  if (prodHit) {
    type = true
    reasons.push(`"${prodHit}" reads as production`)
  }

  if (target.strategy === 'OnDelete') {
    // The restart annotation is written and nothing is replaced: pods are only
    // updated when deleted by hand. kubectl refuses this outright on some
    // versions and silently succeeds on others, and both leave an operator
    // believing they restarted something they did not.
    caveats.push(
      'this workload updates OnDelete: the restart marks the template but replaces no pod until each one is deleted by hand — kubectl may refuse it outright'
    )
  }
  if (target.strategy === null) {
    caveats.push(
      'the update strategy was not read, so how disruptive this is could not be judged — the confirmation below assumes the routine case'
    )
  }

  return {
    target,
    risk,
    // Type-to-confirm says RESTART rather than broadcast's RUN: the word you
    // type should name what is about to happen, in a dialog whose whole job is
    // to interrupt an autopilot.
    confirmation: type ? { kind: 'type-to-confirm', phrase: 'RESTART' } : { kind: 'confirm' },
    reasons,
    caveats
  }
}

/**
 * "2m", "4h", "3d" — how long ago, for an events list.
 *
 * Events are read as a timeline and an RFC3339 timestamp is not one. Clamped
 * at zero because a node whose clock is ahead of ours would otherwise report
 * negative time, which reads as a parsing bug rather than as clock skew.
 */
export function k8sRelativeTime(iso: string, now: number = Date.now()): string {
  const t = Date.parse(iso)
  if (!Number.isFinite(t)) return ''
  const s = Math.max(0, Math.floor((now - t) / 1000))
  if (s < 60) return `${s}s`
  const m = Math.floor(s / 60)
  if (m < 60) return `${m}m`
  const h = Math.floor(m / 60)
  if (h < 48) return `${h}h`
  return `${Math.floor(h / 24)}d`
}

/** A workload the operator should look at before anything else. */
export function workloadIsDegraded(w: K8sWorkload): boolean {
  return w.ready < w.desired || (w.desired > 0 && w.available < w.desired)
}

/** A node in this state explains a great many pod symptoms at once. */
export function nodeIsUnhealthy(n: K8sNode): boolean {
  return !/^Ready$/i.test(n.status)
}
