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
// It reads the things that are cheap and were missing: PVC capacity (both the
// request and the capacity, because a Pending claim has one and not the other),
// ingress hosts and TLS secret NAMES, RBAC bindings including the cluster-wide
// ones, which secrets EXIST and what their keys are called but never a value,
// a deprecated-API scan that reports what it could not check, and a Helm
// release list on the hosts that have helm.
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
//  - Apply a manifest, scale, or edit. Applying in particular is a GitOps
//    pipeline's job: a manifest that reaches a cluster from a desktop button
//    is a manifest with no review, no diff against what is in git, and no
//    record anywhere but this app — which is how a staging manifest reaches
//    prod. Scale and edit leave the cluster somewhere the user now has to
//    remember to undo, unlike a rollout restart, which converges back to the
//    workload's own declared state.
//
//  - Reach the MCP bridge. Nothing here is registered as an agent tool. The
//    bridge gates `execute_command` per server against an access group; a
//    cluster-wide restart primitive is a different risk with a different
//    consent story, and it would arrive there by accident rather than by
//    decision. `rollout restart` is a human clicking a confirm dialog.
//
// CORDON, UNCORDON AND DRAIN now ship. A cordon changes one boolean on the
// Node object and evicts nothing, so it is the honest first step; a drain is
// the dangerous one, and it ships only because the two things the refusal
// above named as missing — PDB awareness and endpoint state at the moment of
// the click — are now read and are now BLOCKING. A drain that cannot see a
// PodDisruptionBudget is refused rather than attempted. See
// buildK8sDrainPreflightCommand and assessK8sDrain.
//
// EXEC now ships, behind exactly the approval model the refusal above named:
// `approvalFor` mints a record when the human types the phrase and
// `verifyApproval` checks the command text, the target and the confirmation
// strength against a fresh re-derivation before anything runs. It is not a
// shell session — one command, no TTY, no stdin. See buildK8sExecCommand.
//
// Single-pod DELETION is still refused, and the second half of the paragraph
// above is still why: a drain answers "can this node lose everything on it",
// which is a question about a node and is answerable from the node's own pod
// list. "Can this workload lose this one pod" is a question about a workload,
// and `rollout restart` already reaches the same remediation through the
// controller.
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
  /**
   * `kubectl exec` reached the container and found no shell in it.
   *
   * Its own class because it is the normal answer for a distroless or
   * scratch-based image, which is most of what modern builds produce, and
   * because the alternative wording is the container runtime's — an
   * `OCI runtime exec failed … stat /bin/sh: no such file or directory`
   * sentence that reads like a broken cluster rather than an image that
   * deliberately ships no shell. Same posture as `no-metrics`.
   */
  | 'no-shell'
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
  'no-shell':
    'This container has no shell. That is the normal state of a distroless or scratch image and is not a broken pod — there is simply no /bin/sh inside it to run a command with, so nothing this app can send will run there. A debug sidecar (kubectl debug) is the usual way in, and it is not something this panel does.',
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
  // Before the kubeconfig rule, which matches on `no such file or directory`
  // wordings that name a path — and the container runtime's no-shell sentence
  // is exactly one of those, about a path inside the container rather than the
  // user's kubeconfig.
  if (
    /oci runtime exec failed|exec: "[^"]*": (?:stat|executable file) .*not found|no such file or directory: unknown/.test(
      s
    )
  ) {
    return 'no-shell'
  }
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
 * Node names are RFC 1123 too, and this is a separate export rather than a
 * reuse of `validatePodName` because of what it guards: every node-lifecycle
 * builder below writes this straight into a `kubectl cordon`/`drain` argument,
 * and a reader checking that path should find a function whose name says
 * "node" rather than one whose name says "pod".
 */
export const validateNodeName = (v: string): boolean => NAME_RE.test(v.trim())


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

/** Which reads the panel must repeat when the selected namespace changes.
 *
 *  Every read in this panel is namespace-scoped except the node list, so
 *  changing the namespace invalidates all of them. The pod list is always
 *  re-read because it is behind the default tab; the other two are re-read
 *  only when their tab is the one being looked at, since both are loaded
 *  lazily on first view anyway.
 *
 *  Named and tested because the bug was an ABSENCE: the namespace control
 *  discarded the cached reads and started no new ones, so it looked inert and
 *  the data only reappeared after clicking a different tab. A missing call is
 *  invisible in review — there is nothing on the screen to be wrong about.
 */
export function readsAfterNamespaceChange(view: 'pods' | 'cluster' | 'usage' | 'resources'): {
  pods: boolean
  overview: boolean
  usage: boolean
  resources: boolean
} {
  return {
    pods: true,
    overview: view === 'cluster',
    usage: view === 'usage',
    // The storage/ingress/access reads are namespace-scoped like the others —
    // PVCs, Ingresses, RoleBindings and Secrets all are, and only the
    // ClusterRoleBinding half is not. Leaving this out would have reproduced
    // the exact bug this function was named for, one tab further along: the
    // namespace control looks inert and the data only reappears after clicking
    // a different tab.
    resources: view === 'resources'
  }
}

// =========================================================================
// NODE LIFECYCLE, PART 1: CORDON AND UNCORDON
// =========================================================================
//
// The honest first step. `kubectl cordon` sets `.spec.unschedulable = true`
// on one Node object and does nothing else: no pod is evicted, no pod is
// moved, nothing that is currently serving stops serving. The only thing that
// changes is where the SCHEDULER is willing to put pods it has not placed yet.
//
// That is why this ships ahead of drain rather than with it. The failure mode
// of a wrong cordon is that a node quietly stops taking work and somebody
// notices an hour later that capacity is short; the failure mode of a wrong
// drain is an outage in the next ten seconds. They are not the same control
// and they do not deserve the same dialog.
//
// UNCORDON IS STILL CONFIRMED, which looks like the guard-that-nags this
// project warns about, and is not. A node is cordoned because a human decided
// it should be — usually because it is about to be rebooted, reimaged or
// pulled from the fleet — and that decision is not written down anywhere the
// app can read. Undoing it puts fresh pods onto a machine that is halfway
// through maintenance, and the person who gets paged is the one who cordoned
// it. One click that says which node is the whole cost.

export type K8sSchedulingAction = 'cordon' | 'uncordon'

export const K8S_SCHEDULING_ACTIONS: readonly K8sSchedulingAction[] = ['cordon', 'uncordon']

/**
 * Cordon or uncordon one node.
 *
 * The action is an allowlist rather than free text for the same reason the
 * rollout builder's `kind` is: there is no case where it should be anything
 * else, and `kubectl` has a great many subcommands that take a node name.
 */
export function buildK8sCordonCommand(
  node: string,
  action: K8sSchedulingAction,
  context?: string
): string {
  if (!K8S_SCHEDULING_ACTIONS.includes(action)) {
    throw new Error('refusing to run a scheduling action this module does not know')
  }
  if (!validateNodeName(node)) {
    throw new Error('refusing to build a command from an invalid node name')
  }
  const ctx = context && validateContext(context) ? ` --context=${context}` : ''
  return [
    k8sResolve(),
    call('CORDON', `${action} ${node}${ctx}`),
    // Re-read the node afterwards, in the same round trip. Without it the panel
    // has to either believe its own optimistic update or fire a second SSH
    // call, and the first of those is how a control ends up showing a state the
    // cluster does not have — which for a maintenance freeze is the one lie
    // that matters.
    call('NODE', `get node ${node} --no-headers${ctx}`)
  ].join('; ')
}

export interface K8sCordonResult {
  ok: boolean
  action: K8sSchedulingAction
  node: string
  /**
   * kubectl said "already cordoned" / "already uncordoned".
   *
   * A distinct field rather than folded into `ok`, because it is the answer to
   * a different question. The action succeeded — the node is in the state that
   * was asked for — but nothing changed, and telling an operator "cordoned"
   * when somebody else cordoned it an hour ago hides the fact that a
   * maintenance window they do not know about is already open.
   */
  alreadyInState: boolean
  /** What kubectl printed for the action. */
  output: string
  /** The node row read back afterwards, or '' when that read failed too. */
  node_status: string
  reason?: K8sFailure
  detail?: string
}

const ALREADY_RE = /already (cordoned|uncordoned)/i

export function parseK8sCordonResult(
  action: K8sSchedulingAction,
  node: string,
  output: string,
  exitCode: number | null
): K8sCordonResult {
  const said = section(output, 'CORDON').trim()
  const nodeRow = section(output, 'NODE').trim()
  const status = nodeRow === '' || looksLikeError(nodeRow) ? '' : nodeRow
  // Decided on the presence of an error line rather than on kubectl's exact
  // success sentence, the same way parseK8sRolloutResult is — the wording has
  // moved between versions and a version bump must not turn a cordon that
  // worked into a reported failure.
  const failed =
    said === '' || said.split('\n').every((l) => l.trim() === '' || looksLikeError(l))
  if (failed) {
    const first = said.split('\n').find((l) => looksLikeError(l)) ?? said
    return {
      ok: false,
      action,
      node,
      alreadyInState: false,
      output: said,
      node_status: status,
      reason: classifyK8sFailure(first, exitCode),
      detail: first.trim() || 'kubectl returned nothing'
    }
  }
  return {
    ok: true,
    action,
    node,
    alreadyInState: ALREADY_RE.test(said),
    output: said,
    node_status: status
  }
}

export interface K8sCordonTarget {
  node: string
  action: K8sSchedulingAction
  /**
   * Pods currently running on this node, or null when it was not read.
   *
   * Only ever used to describe the blast radius in words. A cordon evicts none
   * of them, and saying so with a number is what stops an operator believing
   * it did.
   */
  podCount: number | null
  context?: string | null
}

export interface K8sCordonPlan {
  target: K8sCordonTarget
  risk: BroadcastRisk
  confirmation: BroadcastConfirmation
  reasons: string[]
  caveats: string[]
}

/**
 * How hard the user has to press to change one node's schedulability.
 *
 * Never type-to-confirm, in either direction, and that is the point of having
 * a separate plan function rather than reusing the rollout's. Nothing is
 * evicted and nothing is deleted; the state is one boolean and the undo is the
 * other button on the same row. Demanding a typed word here is how the typed
 * word stops meaning anything by the time a drain asks for one.
 */
export function planK8sCordon(target: K8sCordonTarget): K8sCordonPlan {
  const reasons: string[] = []
  const caveats: string[] = []
  const prodHit = [target.node, target.context ?? ''].find((v) => v && PROD_RE.test(v))

  if (target.action === 'cordon') {
    reasons.push('the scheduler stops placing new pods on this node')
    reasons.push(
      target.podCount === null
        ? 'pods already running here keep running — a cordon evicts nothing'
        : `the ${target.podCount} pod(s) already running here keep running — a cordon evicts nothing`
    )
    caveats.push(
      'a cordon has no expiry: the node stays unschedulable until somebody uncordons it, and a rollout that needs to reschedule here will sit Pending instead'
    )
  } else {
    reasons.push('the scheduler starts placing new pods on this node again')
    caveats.push(
      'a node is usually cordoned because somebody is working on it — reboot, reimage, or taking it out of the fleet — and that reason is not recorded anywhere this app can read'
    )
  }
  if (prodHit) {
    reasons.push(`"${prodHit}" reads as production`)
  }

  return {
    target,
    // `elevated` rather than `ordinary` even for uncordon: both directions move
    // a machine in or out of a fleet's capacity, and neither is something to
    // do while looking at something else.
    risk: 'elevated',
    confirmation: { kind: 'confirm' },
    reasons,
    caveats
  }
}

// =========================================================================
// NODE LIFECYCLE, PART 2: DRAIN
// =========================================================================
//
// The dangerous one, and the file's original refusal named the precondition:
// ownership references tell you a pod will be RECREATED, they do not tell you
// the workload can afford to lose it RIGHT NOW. That gap is what this section
// closes, and the rule is that it closes it or the drain does not run — there
// is no "warn harder and let them through" path here.
//
// A DRAIN IS NOT ATOMIC, which is the fact that decides the whole design.
// Recorded against a real three-node cluster: a drain of a node holding one
// `search` pod and one `catalog` pod evicted `search`, then hit a
// PodDisruptionBudget on `catalog` and retried it every five seconds until the
// timeout. It ended with `error: unable to drain node`, exit 1 — and one pod
// already gone. So a drain that "fails" has still moved half the workloads,
// and a check that happens after the click is not a check. Everything below
// runs BEFORE kubectl drain is built.
//
// WHAT IS CHECKED, AND WHY EACH ONE IS HERE:
//
//  1. A POD WITH NO OWNER. `kubectl drain` refuses these itself unless given
//     `--force`, and we do not pass `--force`. It is in the list anyway
//     because the operator should be told which pod and why before the
//     command runs, rather than reading kubectl's doubled "cannot delete
//     cannot delete Pods that declare no controller" out of an error pane.
//
//  2. A PDB WITH NO DISRUPTIONS LEFT. `.status.disruptionsAllowed` at zero
//     means the API server will reject the eviction with `Cannot evict pod as
//     it would violate the pod's disruption budget.` — recorded verbatim.
//     kubectl then retries forever. A drain that ignores PodDisruptionBudgets
//     is how a service goes down during routine maintenance.
//
//  3. A POD COVERED BY MORE THAN ONE PDB. Found by running it, and not
//     something documentation would have shown: the API server answers
//
//       This pod has more than one PodDisruptionBudget, which the eviction
//       subresource does not support.
//
//     — regardless of what either budget allows. Two PDBs that each permit a
//     disruption still make every pod they overlap on completely unevictable,
//     so a check that only looked at `disruptionsAllowed` would have cleared a
//     drain that cannot make progress at all.
//
//  4. A PDB SELECTOR WE CANNOT EVALUATE. `matchLabels` we can match against a
//     pod's labels. `matchExpressions` we cannot, from a list read. An
//     unevaluated selector is an UNKNOWN, and the entire premise of this
//     module is that "could not see" must never render as "nothing there" —
//     so an unreadable selector in a namespace whose pods are about to be
//     evicted refuses the drain instead of being skipped.
//
//  5. THE ONLY READY ENDPOINT BEHIND A SERVICE. The case the original refusal
//     named. Ownership says this pod comes back; the EndpointSlice says that
//     between now and then the Service has nowhere to send traffic. Read at
//     the moment of the click, because that is the only moment it is true of.
//
//  6. AN emptyDir VOLUME. `kubectl drain` refuses without
//     `--delete-emptydir-data`, and that flag deletes the data. We do not pass
//     it, so this is a refusal with a name rather than a flag we quietly set.
//
//  7. ANY READ THAT DID NOT ANSWER. RBAC refuses verbs individually — a token
//     can list pods and be denied PodDisruptionBudgets, and the API server
//     says so on stderr while the list comes back empty. An empty PDB list
//     from a denied read is indistinguishable from a cluster with no PDBs
//     unless the failure is carried, which is why `unchecked` exists and why
//     it blocks exactly as hard as a real blocker does.
//
// WHAT IS STILL REFUSED: `--force` (bare pods) and `--delete-emptydir-data`.
// Both turn a blocked drain into a successful one by destroying the thing
// that blocked it, which is not the same as the drain being safe.

/** A pod on the node being drained, as the preflight read it. */
export interface K8sDrainPod {
  namespace: string
  name: string
  /** ReplicaSet, StatefulSet, DaemonSet, Job, Node (a static pod), or '' for a bare pod. */
  ownerKind: string
  ownerName: string
  phase: string
  /** True when this is a static pod mirrored onto the API server. */
  mirror: boolean
  /** Labels, for matching PodDisruptionBudget selectors. */
  labels: Record<string, string>
  /** How many emptyDir volumes the pod declares. */
  emptyDirs: number
}

/** A PodDisruptionBudget, with the half of its selector we can evaluate. */
export interface K8sPdb {
  namespace: string
  name: string
  /** `.status.disruptionsAllowed`, or null when the field was absent. */
  disruptionsAllowed: number | null
  currentHealthy: number | null
  desiredHealthy: number | null
  expectedPods: number | null
  matchLabels: Record<string, string>
  /**
   * True when the selector carries matchExpressions.
   *
   * The flag rather than the expressions themselves, because we do not
   * evaluate them — we refuse. Storing a parsed form we never use would read
   * as though we did.
   */
  hasMatchExpressions: boolean
}

/** The Ready pods behind one Service, unioned across its EndpointSlices. */
export interface K8sServiceEndpoints {
  namespace: string
  service: string
  /** Pod names that are Ready right now. */
  readyPods: string[]
  /**
   * Ready endpoints with no `targetRef` — the API server's own Service has
   * one. Counted separately because they keep a Service serving without being
   * a pod anything here can evict.
   */
  readyWithoutPod: number
}

export interface K8sDrainNode {
  name: string
  unschedulable: boolean
  /** 'True', 'False', 'Unknown', or '' when the condition was not read. */
  ready: string
}

export type K8sDrainBlockerKind =
  | 'bare-pod'
  | 'pdb-exhausted'
  | 'pdb-multiple'
  | 'pdb-unreadable-selector'
  | 'sole-ready-endpoint'
  | 'local-storage'

export interface K8sDrainBlocker {
  kind: K8sDrainBlockerKind
  namespace: string
  /** The pod, PDB or Service this is about. */
  subject: string
  detail: string
}

/** A read that did not answer, and therefore a question nobody can say yes to. */
export interface K8sDrainUnchecked {
  /** Which read. */
  read: 'node' | 'pods' | 'pdbs' | 'endpoints'
  reason: K8sFailure
  detail: string
  /** What is now unknown, in the words the refusal will use. */
  meaning: string
}

export interface K8sDrainAssessment {
  node: string
  nodeState: K8sDrainNode | null
  /** Pods a drain would actually evict: not DaemonSet-owned, not static, not finished. */
  evictable: K8sDrainPod[]
  /** Set aside by `--ignore-daemonsets`. */
  daemonSetPods: K8sDrainPod[]
  /** Static pods. A drain cannot evict them and the kubelet keeps running them. */
  mirrorPods: K8sDrainPod[]
  /** Succeeded or Failed. Nothing to evict. */
  finishedPods: K8sDrainPod[]
  blockers: K8sDrainBlocker[]
  unchecked: K8sDrainUnchecked[]
  /**
   * True only when every read answered AND nothing blocks.
   *
   * Deliberately not "no blockers": a preflight that could not list
   * PodDisruptionBudgets has no blockers either, and that is the failure this
   * whole module is shaped to refuse.
   */
  safe: boolean
}

const DRAIN_PODS_JSONPATH =
  `'jsonpath={range .items[*]}{.metadata.namespace}{"|"}{.metadata.name}{"|"}` +
  `{.metadata.ownerReferences[0].kind}{"|"}{.metadata.ownerReferences[0].name}{"|"}` +
  `{.status.phase}{"|"}{.metadata.annotations.kubernetes\\.io/config\\.mirror}{"|"}` +
  `{.metadata.labels}{"|"}{.spec.volumes[*].emptyDir}{"\\n"}{end}'`

const DRAIN_PDB_JSONPATH =
  `'jsonpath={range .items[*]}{.metadata.namespace}{"|"}{.metadata.name}{"|"}` +
  `{.status.disruptionsAllowed}{"|"}{.status.currentHealthy}{"|"}{.status.desiredHealthy}{"|"}` +
  `{.status.expectedPods}{"|"}{.spec.selector.matchLabels}{"|"}` +
  `{.spec.selector.matchExpressions}{"\\n"}{end}'`

// The nested `range` is what makes this safe. A flat
// `{.endpoints[*].targetRef.name}` and `{.endpoints[*].conditions.ready}` are
// two independently joined lists, and an endpoint with no targetRef — the
// `default/kubernetes` Service has exactly one — shortens the first list and
// silently shifts every readiness flag onto the wrong pod. Pairing them inside
// one range means the two halves can never come apart.
const DRAIN_SLICE_JSONPATH =
  `'jsonpath={range .items[*]}{.metadata.namespace}{"|"}` +
  `{.metadata.labels.kubernetes\\.io/service-name}{"|"}` +
  `{range .endpoints[*]}{.targetRef.name}{"="}{.conditions.ready}{","}{end}{"\\n"}{end}'`

const DRAIN_NODE_JSONPATH =
  `'jsonpath={.metadata.name}{"|"}{.spec.unschedulable}{"|"}` +
  `{range .status.conditions[?(@.type=="Ready")]}{.status}{end}{"\\n"}'`

/**
 * Everything the drain decision is made from, in one round trip.
 *
 * One trip rather than four because the four are one question asked at one
 * moment. Endpoint readiness in particular is only true of the instant it was
 * read, and four sequential SSH round trips through a bastion would spread
 * that instant over several seconds of a cluster that is, by hypothesis,
 * about to be changed.
 *
 * Every field is read as jsonpath rather than custom-columns, which is a
 * departure from the rest of this file and a deliberate one: labels and PDB
 * selectors are MAPS, and kubectl renders a map in custom-columns as Go's
 * `map[a:1 b:2]` — spaces and all — which a column-splitting parser cannot
 * take apart. jsonpath prints compact JSON with no spaces, and `|` is not a
 * legal character in any Kubernetes name or label value, so the delimiter
 * cannot appear inside a field.
 */
export function buildK8sDrainPreflightCommand(node: string, context?: string): string {
  if (!validateNodeName(node)) {
    throw new Error('refusing to build a command from an invalid node name')
  }
  const ctx = context && validateContext(context) ? ` --context=${context}` : ''
  return [
    k8sResolve(),
    call('DNODE', `get node ${node} -o ${DRAIN_NODE_JSONPATH}${ctx}`),
    call(
      'DPODS',
      `get pods --all-namespaces --field-selector spec.nodeName=${node} -o ${DRAIN_PODS_JSONPATH}${ctx}`
    ),
    // Cluster-wide rather than per namespace: the pods on one node can belong
    // to any namespace, and asking per namespace would need a list of
    // namespaces this token may well not be allowed to read either.
    call('DPDB', `get poddisruptionbudgets --all-namespaces -o ${DRAIN_PDB_JSONPATH}${ctx}`),
    // EndpointSlice, not Endpoints. `kubectl get endpoints` on 1.33 prints
    // `Warning: v1 Endpoints is deprecated in v1.33+` onto stderr, which the
    // builders redirect into the data block — and on a later server it stops
    // answering at all.
    call('DEPS', `get endpointslices --all-namespaces -o ${DRAIN_SLICE_JSONPATH}${ctx}`)
  ].join('; ')
}

/** `{"a":"b"}` from jsonpath, or `{}` for a field that was absent. */
function parseLabelJson(raw: string): Record<string, string> {
  const t = raw.trim()
  if (t === '' || t === '{}' || t === '<none>') return {}
  try {
    const v: unknown = JSON.parse(t)
    if (typeof v !== 'object' || v === null || Array.isArray(v)) return {}
    const out: Record<string, string> = {}
    for (const [k, val] of Object.entries(v as Record<string, unknown>)) {
      if (typeof val === 'string') out[k] = val
    }
    return out
  } catch {
    return {}
  }
}

const intOrNull = (raw: string): number | null => {
  const t = raw.trim()
  if (t === '') return null
  const n = Number(t)
  return Number.isFinite(n) ? n : null
}

const DRAIN_POD_FIELDS = 8

function parseDrainPods(text: string): K8sDrainPod[] {
  const pods: K8sDrainPod[] = []
  for (const raw of text.split('\n')) {
    const line = raw.trim()
    if (line === '' || NO_RESOURCES.test(line)) continue
    const f = line.split('|')
    // Shape, never content — the rule the pod and event parsers already
    // follow. An RBAC error sentence has no `|` in it at all, so it cannot
    // reach eight fields, and a namespace called `error-reporting` still can.
    if (f.length < DRAIN_POD_FIELDS) continue
    const [ns, name, ownerKind, ownerName, phase, mirror, labels] = f
    if (!validateNamespace(ns) || !validatePodName(name)) continue
    const emptyDirBlob = f.slice(DRAIN_POD_FIELDS - 1).join('|').trim()
    pods.push({
      namespace: ns,
      name,
      ownerKind: ownerKind.trim(),
      ownerName: ownerName.trim(),
      phase: phase.trim(),
      mirror: mirror.trim() !== '',
      labels: parseLabelJson(labels),
      // jsonpath joins repeated matches with a SPACE — recorded from a pod with
      // two emptyDir volumes, which printed `{} {"sizeLimit":"1Gi"}`. Counting
      // the `{` is what survives that; splitting on whitespace would report one.
      emptyDirs: (emptyDirBlob.match(/\{/g) ?? []).length
    })
  }
  return pods
}

const DRAIN_PDB_FIELDS = 8

function parseDrainPdbs(text: string): K8sPdb[] {
  const out: K8sPdb[] = []
  for (const raw of text.split('\n')) {
    const line = raw.trim()
    if (line === '' || NO_RESOURCES.test(line)) continue
    const f = line.split('|')
    if (f.length < DRAIN_PDB_FIELDS) continue
    const [ns, name, allowed, healthy, desired, expected, matchLabels] = f
    if (!validateNamespace(ns) || !validatePodName(name)) continue
    const expr = f.slice(DRAIN_PDB_FIELDS - 1).join('|').trim()
    out.push({
      namespace: ns,
      name,
      disruptionsAllowed: intOrNull(allowed),
      currentHealthy: intOrNull(healthy),
      desiredHealthy: intOrNull(desired),
      expectedPods: intOrNull(expected),
      matchLabels: parseLabelJson(matchLabels),
      hasMatchExpressions: expr !== '' && expr !== '<none>'
    })
  }
  return out
}

function parseDrainEndpoints(text: string): K8sServiceEndpoints[] {
  // Keyed so several EndpointSlices for one Service are unioned. A Service
  // with more than a hundred endpoints gets more than one slice, and reading
  // each slice as its own Service would report a pod as the sole endpoint of a
  // Service that has ninety-nine others.
  const byService = new Map<string, K8sServiceEndpoints>()
  for (const raw of text.split('\n')) {
    const line = raw.trim()
    if (line === '' || NO_RESOURCES.test(line)) continue
    const f = line.split('|')
    if (f.length < 3) continue
    const [ns, service] = f
    if (!validateNamespace(ns) || service.trim() === '') continue
    const key = `${ns}/${service}`
    const entry = byService.get(key) ?? {
      namespace: ns,
      service: service.trim(),
      readyPods: [],
      readyWithoutPod: 0
    }
    for (const pair of f.slice(2).join('|').split(',')) {
      if (pair.trim() === '') continue
      const eq = pair.lastIndexOf('=')
      if (eq < 0) continue
      const pod = pair.slice(0, eq).trim()
      const ready = pair.slice(eq + 1).trim()
      if (ready !== 'true') continue
      if (pod === '') entry.readyWithoutPod += 1
      else if (!entry.readyPods.includes(pod)) entry.readyPods.push(pod)
    }
    byService.set(key, entry)
  }
  return [...byService.values()]
}

function parseDrainNode(text: string): K8sDrainNode | null {
  for (const raw of text.split('\n')) {
    const line = raw.trim()
    if (line === '') continue
    const f = line.split('|')
    if (f.length < 3) continue
    if (!validateNodeName(f[0])) continue
    return {
      name: f[0].trim(),
      // Absent when the node is schedulable — the field only exists once
      // something has set it — so "not the string true" is the test.
      unschedulable: f[1].trim() === 'true',
      ready: f[2].trim()
    }
  }
  return null
}

/** Does this PDB's matchLabels selector cover this pod? */
function pdbCovers(pdb: K8sPdb, pod: K8sDrainPod): boolean {
  if (pdb.namespace !== pod.namespace) return false
  const keys = Object.keys(pdb.matchLabels)
  // An EMPTY selector is not "matches nothing" — in Kubernetes a PDB with
  // `selector: {}` matches EVERY pod in its namespace. Reading it the other
  // way round is the single most dangerous mistake available here: it would
  // silently clear a drain against a budget covering the whole namespace.
  if (keys.length === 0) return true
  return keys.every((k) => pod.labels[k] === pdb.matchLabels[k])
}

const DAEMONSET_KINDS = /^DaemonSet$/
const FINISHED_PHASES = /^(Succeeded|Failed)$/

/**
 * Decide whether this node can be drained, from a preflight and nothing else.
 *
 * Pure, so the same decision can be tested against recorded cluster output and
 * re-derived in the main process from a fresh read. The renderer's copy is a
 * preview; the one that matters is taken again immediately before the drain
 * command is built.
 */
export function assessK8sDrain(
  node: string,
  input: {
    nodeState: K8sRead<K8sDrainNode>
    pods: K8sRead<K8sDrainPod>
    pdbs: K8sRead<K8sPdb>
    endpoints: K8sRead<K8sServiceEndpoints>
  }
): K8sDrainAssessment {
  const unchecked: K8sDrainUnchecked[] = []
  const push = (
    read: K8sDrainUnchecked['read'],
    r: { ok: false; reason: K8sFailure; detail: string },
    meaning: string
  ): void => {
    unchecked.push({ read, reason: r.reason, detail: r.detail, meaning })
  }

  if (!input.nodeState.ok) {
    push('node', input.nodeState, 'whether this node exists, and whether it is already cordoned')
  }
  if (!input.pods.ok) {
    push('pods', input.pods, 'what is running on this node at all')
  }
  if (!input.pdbs.ok) {
    push(
      'pdbs',
      input.pdbs,
      'whether a PodDisruptionBudget would reject these evictions — an empty budget list from a denied read looks exactly like a cluster that has none'
    )
  }
  if (!input.endpoints.ok) {
    push(
      'endpoints',
      input.endpoints,
      'whether any of these pods is the last Ready endpoint behind a Service'
    )
  }

  const allPods = input.pods.ok ? input.pods.items : []
  const daemonSetPods = allPods.filter((p) => DAEMONSET_KINDS.test(p.ownerKind))
  const mirrorPods = allPods.filter((p) => p.mirror && !DAEMONSET_KINDS.test(p.ownerKind))
  const finishedPods = allPods.filter(
    (p) =>
      FINISHED_PHASES.test(p.phase) && !DAEMONSET_KINDS.test(p.ownerKind) && !p.mirror
  )
  const evictable = allPods.filter(
    (p) => !DAEMONSET_KINDS.test(p.ownerKind) && !p.mirror && !FINISHED_PHASES.test(p.phase)
  )

  const blockers: K8sDrainBlocker[] = []
  const pdbs = input.pdbs.ok ? input.pdbs.items : []
  const namespacesInPlay = new Set(evictable.map((p) => p.namespace))

  // 4, first: an unreadable selector in a namespace whose pods are about to
  // move. Reported per PDB rather than per pod, because the thing nobody can
  // evaluate is the budget, and naming it is what lets somebody go and read it.
  for (const pdb of pdbs) {
    if (!pdb.hasMatchExpressions) continue
    if (!namespacesInPlay.has(pdb.namespace)) continue
    blockers.push({
      kind: 'pdb-unreadable-selector',
      namespace: pdb.namespace,
      subject: pdb.name,
      detail:
        `this PodDisruptionBudget selects pods with matchExpressions, which a list read cannot evaluate. ` +
        `Whether it covers the pods on ${node} is unknown, and an unknown budget is not a permission.`
    })
  }

  for (const pod of evictable) {
    if (pod.ownerKind === '') {
      blockers.push({
        kind: 'bare-pod',
        namespace: pod.namespace,
        subject: pod.name,
        detail:
          'nothing owns this pod, so nothing recreates it. Draining the node deletes it for good.'
      })
    }
    if (pod.emptyDirs > 0) {
      blockers.push({
        kind: 'local-storage',
        namespace: pod.namespace,
        subject: pod.name,
        detail:
          `this pod has ${pod.emptyDirs} emptyDir volume(s). kubectl refuses to evict it without ` +
          `--delete-emptydir-data, and that flag deletes the data rather than moving it.`
      })
    }

    const covering = pdbs.filter((b) => pdbCovers(b, pod))
    if (covering.length > 1) {
      blockers.push({
        kind: 'pdb-multiple',
        namespace: pod.namespace,
        subject: pod.name,
        detail:
          `covered by ${covering.length} PodDisruptionBudgets (${covering.map((b) => b.name).join(', ')}). ` +
          `The eviction subresource refuses a pod with more than one budget outright, whatever either one allows.`
      })
    }
    for (const b of covering) {
      if (b.disruptionsAllowed !== null && b.disruptionsAllowed <= 0) {
        blockers.push({
          kind: 'pdb-exhausted',
          namespace: pod.namespace,
          subject: pod.name,
          detail:
            `PodDisruptionBudget ${b.name} allows ${b.disruptionsAllowed} disruptions right now ` +
            `(${b.currentHealthy ?? '?'} healthy, ${b.desiredHealthy ?? '?'} required). The API server ` +
            `will reject this eviction and kubectl will retry it until the timeout.`
        })
      }
    }

    for (const svc of input.endpoints.ok ? input.endpoints.items : []) {
      if (svc.namespace !== pod.namespace) continue
      if (!svc.readyPods.includes(pod.name)) continue
      if (svc.readyPods.length + svc.readyWithoutPod > 1) continue
      blockers.push({
        kind: 'sole-ready-endpoint',
        namespace: pod.namespace,
        subject: pod.name,
        detail:
          `this pod is the only Ready endpoint behind Service ${svc.service}. Its owner will recreate it, ` +
          `and between the eviction and the replacement becoming Ready that Service has nowhere to send traffic.`
      })
    }
  }

  return {
    node,
    nodeState: input.nodeState.ok ? (input.nodeState.items[0] ?? null) : null,
    evictable,
    daemonSetPods,
    mirrorPods,
    finishedPods,
    blockers,
    unchecked,
    safe: blockers.length === 0 && unchecked.length === 0
  }
}

export function parseK8sDrainPreflight(
  node: string,
  output: string,
  exitCode: number | null
): K8sDrainAssessment {
  return assessK8sDrain(node, {
    nodeState: readBlock(section(output, 'DNODE'), (t) => {
      const n = parseDrainNode(t)
      return n === null ? [] : [n]
    }, exitCode),
    pods: readBlock(section(output, 'DPODS'), parseDrainPods, exitCode),
    pdbs: readBlock(section(output, 'DPDB'), parseDrainPdbs, exitCode),
    endpoints: readBlock(section(output, 'DEPS'), parseDrainEndpoints, exitCode)
  })
}

/**
 * How long kubectl will keep retrying evictions before giving up.
 *
 * Bounded, and not optional. Without `--timeout` a drain blocked by a
 * PodDisruptionBudget retries every five seconds forever, holding the SSH exec
 * open past every timeout this app has. Two minutes is long enough for a
 * rolling replacement to become Ready and short enough that the user gets an
 * answer.
 */
export const K8S_DRAIN_TIMEOUT_SECONDS = 120

/**
 * The drain itself.
 *
 * Three flags and no more:
 *  - `--ignore-daemonsets`, because a DaemonSet pod is recreated on the same
 *    node by definition and refusing to drain over one means never draining.
 *  - `--timeout`, see above.
 *  - `--delete-emptydir-data=false` and `--force=false` written EXPLICITLY
 *    rather than left to kubectl's defaults. They are the two flags that turn
 *    a blocked drain into a successful one by destroying what blocked it, a
 *    future kubectl could change either default, and a reader auditing this
 *    line should be able to see the answer rather than have to know it.
 */
export function buildK8sDrainCommand(node: string, context?: string): string {
  if (!validateNodeName(node)) {
    throw new Error('refusing to build a command from an invalid node name')
  }
  const ctx = context && validateContext(context) ? ` --context=${context}` : ''
  return [
    k8sResolve(),
    call(
      'DRAIN',
      `drain ${node} --ignore-daemonsets --force=false --delete-emptydir-data=false ` +
        `--timeout=${K8S_DRAIN_TIMEOUT_SECONDS}s${ctx}`
    ),
    call('NODE', `get node ${node} --no-headers${ctx}`)
  ].join('; ')
}

export interface K8sDrainResult {
  ok: boolean
  node: string
  /** Pods kubectl reported as evicted, in the order it reported them. */
  evicted: string[]
  /** Pods it was still trying to evict when it stopped. */
  pending: string[]
  /**
   * Pods a PodDisruptionBudget is STILL holding, once the retries are read.
   *
   * Its own field because it is the one failure that means "try again later"
   * rather than "something is wrong" — and because if the preflight cleared
   * the drain and this is non-empty, the cluster changed between the check and
   * the click, which is worth being able to see.
   *
   * Pods that were rejected and then evicted on a later retry are NOT here,
   * and that is a correction the real recording forced: a drain of five pods
   * printed a budget rejection for `search-698cd569f8-hhqrl` and then evicted
   * it eight seconds later, once its sibling had come back Ready. Listing it
   * as blocked would have named a pod that is already gone, next to the two
   * that genuinely never moved.
   */
  pdbRejected: string[]
  /**
   * A drain that failed after evicting something.
   *
   * The field the recording forced: a real blocked drain moved one pod and
   * then stalled on another. Rendering that as a plain failure tells the
   * operator the node is untouched, which is how somebody reboots it.
   */
  partial: boolean
  output: string
  node_status: string
  reason?: K8sFailure
  detail?: string
}

const EVICTED_RE = /^pod\/(\S+) evicted$/
const PDB_REJECT_RE = /error when evicting pods?\/"([^"]+)"/
const EVICTING_RE = /^evicting pod (?:(\S+)\/)?(\S+)$/

export function parseK8sDrainResult(
  node: string,
  output: string,
  exitCode: number | null
): K8sDrainResult {
  const said = section(output, 'DRAIN')
  const nodeRow = section(output, 'NODE').trim()
  const status = nodeRow === '' || looksLikeError(nodeRow) ? '' : nodeRow

  const evicted: string[] = []
  const attempted: string[] = []
  const pdbRejected: string[] = []
  for (const raw of said.split('\n')) {
    const line = raw.trim()
    const ev = EVICTED_RE.exec(line)
    if (ev) {
      if (!evicted.includes(ev[1])) evicted.push(ev[1])
      continue
    }
    const trying = EVICTING_RE.exec(line)
    if (trying && !attempted.includes(trying[2])) attempted.push(trying[2])
    // Matched anywhere in the line, not anchored: kubectl prints these both on
    // their own and rolled up inside a bracketed list at the end.
    if (/violate the pod's disruption budget/.test(line)) {
      const who = PDB_REJECT_RE.exec(line)
      if (who && !pdbRejected.includes(who[1])) pdbRejected.push(who[1])
    }
  }
  const pending = attempted.filter((p) => !evicted.includes(p))
  // See the field comment: a rejection that a later retry got past is not a
  // pod the budget is holding.
  const stillRejected = pdbRejected.filter((p) => !evicted.includes(p))

  // kubectl's own summary line for a drain that did not finish. Decided on
  // this rather than on the exit code alone, because the exec's exit code is
  // the last command in the chain — the node read — not the drain.
  const failed =
    /^error: unable to drain node/m.test(said) ||
    /There are pending nodes to be drained/.test(said) ||
    said.trim() === ''
  if (failed) {
    const first =
      said.split('\n').map((l) => l.trim()).find((l) => l !== '' && looksLikeError(l)) ?? said.trim()
    return {
      ok: false,
      node,
      evicted,
      pending,
      pdbRejected: stillRejected,
      partial: evicted.length > 0,
      output: said.trim(),
      node_status: status,
      reason: classifyK8sFailure(first, exitCode),
      detail: first || 'kubectl returned nothing'
    }
  }
  return {
    ok: true,
    node,
    evicted,
    pending,
    pdbRejected: stillRejected,
    partial: false,
    output: said.trim(),
    node_status: status
  }
}

export interface K8sDrainPlan {
  node: string
  assessment: K8sDrainAssessment
  risk: BroadcastRisk
  confirmation: BroadcastConfirmation
  reasons: string[]
  caveats: string[]
  /**
   * Why this drain will not be run at all.
   *
   * Empty means it may be. Non-empty means the confirmation below is never
   * shown — a refusal is not a scarier dialog, it is no dialog.
   */
  refusals: string[]
}

/** The word a drain makes you type. Never anything softer. */
export const K8S_DRAIN_PHRASE = 'DRAIN'

/**
 * Whether this drain may be offered, and how hard the user has to press.
 *
 * `type-to-confirm` unconditionally, which is the opposite of the rollout's
 * scaling rule and is right for the same reason the rollout's is: a rollout
 * restart converges back to the workload's declared state, and a drain leaves
 * every pod on some other node and the node itself out of the fleet until
 * somebody uncordons it. There is no routine case to keep the typed word cheap
 * for.
 */
export function planK8sDrain(assessment: K8sDrainAssessment): K8sDrainPlan {
  const refusals = [
    ...assessment.unchecked.map(
      (u) =>
        `the ${u.read} read did not answer (${u.reason}: ${u.detail}), so nobody can say ${u.meaning}`
    ),
    ...assessment.blockers.map((b) => `${b.namespace}/${b.subject}: ${b.detail}`)
  ]
  const reasons = [
    `every pod on ${assessment.node} that a controller owns is evicted and rescheduled elsewhere`,
    `${assessment.evictable.length} pod(s) move; ${assessment.daemonSetPods.length} DaemonSet pod(s) are left where they are`
  ]
  const caveats: string[] = [
    'a drain cordons the node first and does not uncordon it afterwards — the node stays out of the fleet until somebody puts it back',
    // The recorded behaviour, and the reason the result type carries `partial`.
    'a drain that fails has still evicted whatever it got through before it stopped; it is not all-or-nothing'
  ]
  if (assessment.mirrorPods.length > 0) {
    caveats.push(
      `${assessment.mirrorPods.length} static pod(s) here cannot be evicted at all — the kubelet keeps running them from disk, whatever the API server says`
    )
  }
  if (assessment.nodeState?.ready === 'False' || assessment.nodeState?.ready === 'Unknown') {
    caveats.push(
      'this node is not Ready, so its kubelet may never confirm the deletions and the drain can sit on pods that are already gone'
    )
  }

  return {
    node: assessment.node,
    assessment,
    risk: 'destructive',
    confirmation: { kind: 'type-to-confirm', phrase: K8S_DRAIN_PHRASE },
    reasons,
    caveats,
    refusals
  }
}

// =========================================================================
// EXEC INTO A POD
// =========================================================================
//
// The file's original refusal read: "that is `docker exec` with more blast
// radius and an entirely separate RBAC story, and it belongs behind the same
// approval model broadcast has rather than a button next to a pod name." That
// approval model now exists and is durable — `approvalFor` and
// `verifyApproval` in shared/broadcast.ts — so this is that precondition, met.
//
// WHAT REUSING IT BUYS, over a confirm dialog:
//  - The command text is WRITTEN DOWN at the moment the human answers, so a
//    command edited between the dialog and the run is caught by comparison
//    rather than trusted.
//  - The target is written down too, so an exec approved against one host
//    cannot be replayed against another.
//  - The confirmation STRENGTH is re-derived and compared, so a build that
//    later decides exec deserves more than it did cannot honour an approval
//    minted under the weaker rule.
// None of that is available from a boolean called `confirmed`.
//
// THIS IS NOT AN INTERACTIVE SHELL, and the naming says so. There is no TTY,
// no stdin and no session: one command runs, its output comes back, and that
// is the whole of it. An SSH exec is one-shot, and a control that looked like
// a terminal but silently dropped everything the program wrote to stdin would
// be worse than not having one.
//
// STILL REFUSED HERE, and for the same reason as everything else in this file:
// APPLYING A MANIFEST. `kubectl apply` is a GitOps pipeline's job. A manifest
// that reaches a cluster from a desktop button has had no review, no diff
// against what is in git and no record anywhere but this app — which is
// exactly how a staging manifest reaches prod. Note that it is not refused
// because it is dangerous and exec is safe; exec is plainly the more powerful
// of the two. It is refused because there is a system whose job this is, and
// putting a second uncoordinated writer next to it is the problem.

/**
 * A shell single-quoted literal holding exactly these bytes.
 *
 * `'\''` is the only escape a POSIX single-quoted string has, and with it the
 * quoting is total: no expansion, no substitution, no backslash processing.
 * The same helper `shared/cron.ts` uses on a crontab body and for the same
 * reason — this is arbitrary text somebody typed, going onto a command line,
 * so the quoting has to be exactly right rather than nearly right.
 *
 * ONCE, not twice, and that was worth getting wrong to find out. The string
 * crosses exactly one shell: the SSH login shell running our command chain.
 * kubectl then hands `-c <arg>` to the container as a single argv element with
 * no shell in between, so a second layer of quoting is not defence — it is a
 * literal pair of quote characters that `/bin/sh -c` reads as part of the
 * command name. Recorded against a real cluster, the double-quoted form came
 * back as
 *
 *   line 0: echo "it's $HOME and `date` and 'quoted'"; id: not found
 *
 * — the entire command treated as one word that does not exist.
 */
function k8sShellLiteral(s: string): string {
  return `'${s.replaceAll("'", `'\\''`)}'`
}

/** The shell run inside the container. */
export const K8S_EXEC_SHELL = '/bin/sh'

/**
 * Bytes of exec output carried back.
 *
 * A `cat` of the wrong file is the most ordinary mistake available here and it
 * would otherwise stream a gigabyte through the SSH transport into a renderer
 * that has to hold all of it.
 */
export const K8S_EXEC_OUTPUT_CAP = 200_000

export interface K8sExecTarget {
  /** The host whose kubectl runs this — recorded in the approval. */
  serverId: string
  serverName: string
  namespace: string
  pod: string
  /** '' when the pod has one container and none was chosen. */
  container: string
  /** What to run. Arbitrary text; quoted, never validated. */
  command: string
  context?: string | null
}

/**
 * `kubectl exec <pod> -- /bin/sh -c '<command>'`, as one shell line.
 *
 * Names are validated the way every other builder here validates them. The
 * COMMAND is not, and cannot be — it is the whole point of the feature — so it
 * is quoted instead, twice, and the approval record is what stands in for a
 * validation the shape of this argument does not admit.
 */
export function buildK8sExecCommand(target: K8sExecTarget): string {
  if (!validateNamespace(target.namespace) || !validatePodName(target.pod)) {
    throw new Error('refusing to build a command from an invalid pod or namespace name')
  }
  if (target.container !== '' && !validatePodName(target.container)) {
    throw new Error('refusing to build a command from an invalid container name')
  }
  if (target.command.trim() === '') {
    throw new Error('refusing to exec an empty command')
  }
  const ctx =
    target.context && validateContext(target.context) ? ` --context=${target.context}` : ''
  const c = target.container === '' ? '' : ` --container=${target.container}`
  // NOT `call()`, and this is the only builder in the file that cannot use it.
  // `call` appends `--request-timeout=10s` to the end of the argument list, and
  // everything after `--` belongs to the container: the flag arrived inside the
  // pod as `sh`'s `$0`, which the recording shows as
  // `--request-timeout=10s: line 0: …: not found`. Every kubectl flag has to be
  // on the near side of the separator.
  return [
    k8sResolve(),
    'echo "===SHELLPILOT-EXEC==="',
    // No -t and no -i, deliberately. See the header: this is one command, not
    // a session, and a TTY on a non-interactive SSH exec produces a stream
    // nobody is reading from.
    `${K} exec ${target.pod} --namespace=${target.namespace}${c}${ctx}${T} ` +
      `-- ${K8S_EXEC_SHELL} -c ${k8sShellLiteral(target.command)} 2>&1 | head -c ${K8S_EXEC_OUTPUT_CAP}`
  ].join('; ')
}

export interface K8sExecResult {
  ok: boolean
  /** Combined stdout and stderr from inside the container. */
  output: string
  /**
   * What the program inside the container exited with, when kubectl said.
   *
   * SEPARATE FROM `ok`, and the distinction is the whole reason this field
   * exists. `ok` answers "did the exec happen"; this answers "did the thing
   * you asked for work". A `cat` of a missing file is a successful exec of a
   * failing command — recorded output:
   *
   *   cat: can't open '/nope/missing': No such file or directory
   *   command terminated with exit code 1
   *
   * Neither of those lines is a kubectl error, so collapsing them into `ok:
   * false` would report an RBAC-shaped failure for a typo'd path. Reporting
   * only `ok: true` and hiding the code is the other half of the same mistake:
   * a command that failed would read as one that worked. kubectl prints this
   * line only for a NON-ZERO exit, so `null` means either zero or nothing said.
   */
  containerExit: number | null
  reason?: K8sFailure
  detail?: string
}

// kubectl's own line, printed only when the program exited non-zero.
const EXEC_EXIT_RE = /^command terminated with exit code (\d+)$/m

// The wording a container with no shell produces. Recorded from `kubectl exec`
// into a `registry.k8s.io/pause` container, which is what a distroless image
// looks like from here.
const NO_SHELL_RE =
  /OCI runtime exec failed|exec: "[^"]*": (?:stat|executable file) .*not found|no such file or directory: unknown/i

/**
 * Read what came back from inside the container.
 *
 * THE HARD PART IS THAT THERE IS NO SUCCESS MARKER. `kubectl exec` prints
 * whatever the program printed and nothing of its own, so an exec that worked
 * and produced no output is indistinguishable from one that produced no output
 * because it never ran — except by the errors kubectl itself writes. Those are
 * the only thing classified here; everything else is the container's, including
 * the word "error", which a program inside is perfectly entitled to print.
 */
export function parseK8sExecResult(output: string, exitCode: number | null): K8sExecResult {
  const said = section(output, 'EXEC')
  const trimmed = said.trim()
  const exitMatch = EXEC_EXIT_RE.exec(trimmed)
  const containerExit = exitMatch ? Number(exitMatch[1]) : null
  if (NO_SHELL_RE.test(trimmed)) {
    return {
      ok: false,
      output: trimmed,
      containerExit,
      reason: 'no-shell',
      detail: trimmed.split('\n')[0]
    }
  }
  const lines = trimmed === '' ? [] : trimmed.split('\n')
  // Same rule as readTextBlock: a failure only when the error is ALL there is.
  // A program that printed three lines of its own and then `Error: bad input`
  // ran fine and said so, and reporting that as a kubectl failure would replace
  // the answer the operator asked for.
  const allError = lines.length > 0 && lines.every((l) => l.trim() === '' || looksLikeError(l))
  if (allError) {
    const first = lines.find((l) => looksLikeError(l)) ?? trimmed
    return {
      ok: false,
      output: trimmed,
      containerExit,
      reason: classifyK8sFailure(first, exitCode),
      detail: first.trim()
    }
  }
  // An empty answer is a SUCCESS here, unlike a cordon. `kubectl exec … -- touch
  // /tmp/x` prints nothing and worked.
  return { ok: true, output: trimmed, containerExit }
}

export interface K8sExecPlan {
  target: K8sExecTarget
  risk: BroadcastRisk
  confirmation: BroadcastConfirmation
  reasons: string[]
  caveats: string[]
}

/** The word an exec makes you type. */
export const K8S_EXEC_PHRASE = 'EXEC'

/**
 * How hard the user has to press to run something inside a container.
 *
 * `destructive` and type-to-confirm ALWAYS, with no cheap case — which is the
 * opposite of the rollout's graded rule and is not a failure to grade. A
 * rollout restart is one known action whose blast radius can be computed from
 * the workload; an exec is arbitrary code, and there is nothing to compute
 * from. `ls` and `rm -rf /` are the same request from here, and a rule that
 * tried to tell them apart would be a command classifier inside a container we
 * cannot see, guessing at a shell we did not choose.
 *
 * `assessCommand` in shared/broadcast.ts is deliberately NOT reused for that
 * reason: it grades commands running on a host we know things about, and its
 * "ordinary" verdict would be a claim about a container image nobody here has
 * read.
 */
export function planK8sExec(target: K8sExecTarget): K8sExecPlan {
  const reasons = [
    `runs arbitrary code inside ${target.namespace}/${target.pod}${target.container === '' ? '' : ` (container ${target.container})`}`,
    // The RBAC point the original refusal made. `pods/exec` is a separate
    // subresource from `pods`, and a token that can read every pod in the
    // cluster may hold no exec permission at all — or the reverse.
    'exec is its own RBAC subresource: what this can do inside the container is whatever the container’s own service account and user allow, not what this app can read'
  ]
  const caveats = [
    'one command, no TTY and no stdin — this is not a shell session, and a program that waits for input will hang until the timeout rather than prompt',
    ...(target.container === ''
      ? [
          // kubectl prints `Defaulted container "x" out of: x, y` onto stderr,
          // which the builder redirects into the output block — so the answer
          // says which container it ran in. Saying so up front is cheaper than
          // reading a command's output and wondering why it found nothing: on a
          // pod with a sidecar, the first container is very often the one you
          // did not mean.
          'no container was named, so kubectl runs this in the pod’s default container and says which one in its output — on a pod with a sidecar that is often not the one you meant'
        ]
      : []),
    'anything written to a path that is not a mounted volume is lost when the container restarts, and a crashlooping container may restart mid-command',
    `output is truncated at ${K8S_EXEC_OUTPUT_CAP} bytes`
  ]
  const prodHit = [target.namespace, target.context ?? ''].find((v) => v && PROD_RE.test(v))
  if (prodHit) reasons.push(`"${prodHit}" reads as production`)

  return {
    target,
    risk: 'destructive',
    confirmation: { kind: 'type-to-confirm', phrase: K8S_EXEC_PHRASE },
    reasons,
    caveats
  }
}

// =========================================================================
// THE READS THAT WERE MISSING, AND ARE CHEAP
// =========================================================================
//
// PVC capacity, ingress, RBAC bindings, secret EXISTENCE, a deprecated-API
// scan and a Helm release list. All read-only, all one round trip each, and
// each one is here because its absence made the panel lie by omission about
// something an operator was already looking for.
//
// SECRETS ARE THE ONE WITH A RULE. This lists which secrets exist and what
// their KEYS are called, and it never reads a value. That is not a policy
// bolted on afterwards, it is the shape of the query: `kubectl get secret -o
// custom-columns=...:.data` renders the whole map, base64 and all, and every
// jsonpath that reaches a key also reaches its value. The go-template below
// iterates `$k, $v` and emits only `$k`, which is the one form that CANNOT
// emit a value — and `tests/kubernetesReads.test.ts` asserts, against a
// fixture recorded from a cluster with known secret values in it, that those
// values appear nowhere in the output.

export interface K8sPvc {
  namespace: string
  name: string
  /** Bound, Pending, Lost. */
  status: string
  /** The PV behind it, or '' while Pending. */
  volume: string
  /** What the claim ASKED for. Present even while Pending. */
  requested: string
  /**
   * What it actually GOT, or '' while Pending.
   *
   * Both are carried, and that is the point of this read rather than a
   * simplification of it. A Pending claim has a request and no capacity — the
   * recorded fixture has exactly one, waiting on a WaitForFirstConsumer
   * StorageClass — so a panel showing only `.status.capacity` renders a blank
   * where a 2Gi request is, which reads as a volume with no size rather than a
   * volume that was never provisioned.
   */
  capacity: string
  accessModes: string
  storageClass: string
}

export interface K8sIngress {
  namespace: string
  name: string
  className: string
  /** The load balancer address, or '' when no controller has claimed it. */
  address: string
  /** Names of the TLS secrets it references. Not their contents. */
  tlsSecrets: string[]
  /** One per rule: `host /path->service:port /path2->service2:port`. */
  rules: string[]
}

export interface K8sRoleBinding {
  /** '' for a ClusterRoleBinding. */
  namespace: string
  name: string
  /** Role or ClusterRole. */
  roleKind: string
  roleName: string
  /** `Kind:namespace/name`, as read. */
  subjects: string[]
  clusterScoped: boolean
}

export interface K8sSecretRef {
  namespace: string
  name: string
  /** Opaque, kubernetes.io/tls, helm.sh/release.v1, … */
  type: string
  /** The KEY NAMES only. Never a value; see the section header. */
  keys: string[]
  created: string
}

export interface K8sResources {
  pvcs: K8sRead<K8sPvc>
  ingresses: K8sRead<K8sIngress>
  roleBindings: K8sRead<K8sRoleBinding>
  secrets: K8sRead<K8sSecretRef>
}

const PVC_COLS =
  'custom-columns=NS:.metadata.namespace,NAME:.metadata.name,STATUS:.status.phase,' +
  'VOL:.spec.volumeName,REQ:.spec.resources.requests.storage,CAP:.status.capacity.storage,' +
  'MODES:.status.accessModes,SC:.spec.storageClassName'

const INGRESS_JSONPATH =
  `'jsonpath={range .items[*]}{.metadata.namespace}{"|"}{.metadata.name}{"|"}` +
  `{.spec.ingressClassName}{"|"}{range .status.loadBalancer.ingress[*]}{.ip}{.hostname}{";"}{end}{"|"}` +
  `{range .spec.tls[*]}{.secretName}{";"}{end}{"|"}` +
  `{range .spec.rules[*]}{.host}{range .http.paths[*]}{" "}{.path}{"->"}` +
  `{.backend.service.name}{":"}{.backend.service.port.number}{end}{";"}{end}{"\\n"}{end}'`

const RBAC_JSONPATH =
  `'jsonpath={range .items[*]}{.metadata.namespace}{"|"}{.metadata.name}{"|"}` +
  `{.roleRef.kind}{"|"}{.roleRef.name}{"|"}` +
  `{range .subjects[*]}{.kind}{":"}{.namespace}{"/"}{.name}{";"}{end}{"\\n"}{end}'`

// go-template rather than jsonpath, and this is the security-relevant line in
// the file. `range $k, $v := .data` is the only kubectl output form that can
// enumerate a secret's keys WITHOUT being able to reach its values: jsonpath
// has no key-enumeration operator, so every jsonpath that names `.data` prints
// the map, base64 values included. `$v` appears nowhere below, deliberately.
const SECRET_TEMPLATE =
  `'{{range .items}}{{.metadata.namespace}}|{{.metadata.name}}|{{.type}}|` +
  `{{range $k,$v := .data}}{{$k}},{{end}}|{{.metadata.creationTimestamp}}{{"\\n"}}{{end}}'`

/**
 * The four reads the panel was missing, in one round trip.
 *
 * Namespace-scoped or cluster-wide by the same `scope()` rule as the overview,
 * except the ClusterRoleBinding read, which is cluster-scoped by definition and
 * would be a lie about what is being read if it took a namespace.
 */
export function buildK8sResourcesCommand(context?: string, namespace?: string): string {
  const { ctx, ns } = scope(context, namespace)
  return [
    k8sResolve(),
    call('PVC', `get pvc${ns} --no-headers -o ${PVC_COLS}${ctx}`),
    call('ING', `get ingress${ns} -o ${INGRESS_JSONPATH}${ctx}`),
    call('RB', `get rolebindings${ns} -o ${RBAC_JSONPATH}${ctx}`),
    call('CRB', `get clusterrolebindings -o ${RBAC_JSONPATH}${ctx}`),
    // `-o go-template` and NOT `-o custom-columns` or jsonpath. See the comment
    // on SECRET_TEMPLATE: this is the only form that cannot print a value.
    call('SEC', `get secrets${ns} -o go-template=${SECRET_TEMPLATE}${ctx}`)
  ].join('; ')
}

// A PVC row is recognised by its PHASE, the way an event row is recognised by
// its type — and for the same reason, discovered the same way.
//
// The first version tested `fields >= 8` and validated the first two as names,
// which a real Forbidden sentence passes: it has far more than eight
// whitespace-separated tokens, `Error` is a valid RFC 1123 name and so is
// `from`. The recorded denial parsed as a PersistentVolumeClaim called `from`
// in a namespace called `Error`, and the read reported OK — a permissions
// failure rendered as data, which is the exact inversion this module exists to
// prevent. Nothing kubectl writes as an error has `Bound`, `Pending` or `Lost`
// as its third token.
const PVC_PHASE_RE = /^(Bound|Pending|Lost)$/

function parsePvcs(text: string): K8sPvc[] {
  const out: K8sPvc[] = []
  for (const raw of text.split('\n')) {
    const line = raw.trim()
    if (line === '' || NO_RESOURCES.test(line)) continue
    const f = line.split(/\s+/)
    // EXACTLY eight. The custom-columns above emit eight and a row with more
    // tokens is a sentence, not a row.
    if (f.length !== 8) continue
    if (!PVC_PHASE_RE.test(f[2])) continue
    if (!validateNamespace(f[0]) || !validatePodName(f[1])) continue
    out.push({
      namespace: f[0],
      name: f[1],
      status: cleanCell(f[2]),
      volume: cleanCell(f[3]),
      requested: cleanCell(f[4]),
      capacity: cleanCell(f[5]),
      accessModes: cleanCell(f[6]),
      storageClass: cleanCell(f[7])
    })
  }
  return out
}

const splitList = (s: string): string[] =>
  s.split(';').map((v) => v.trim()).filter((v) => v !== '')

function parseIngresses(text: string): K8sIngress[] {
  const out: K8sIngress[] = []
  for (const raw of text.split('\n')) {
    const line = raw.trim()
    if (line === '' || NO_RESOURCES.test(line)) continue
    const f = line.split('|')
    if (f.length < 6) continue
    if (!validateNamespace(f[0]) || !validatePodName(f[1])) continue
    out.push({
      namespace: f[0],
      name: f[1],
      className: f[2].trim(),
      address: splitList(f[3]).join(', '),
      tlsSecrets: splitList(f[4]),
      rules: splitList(f.slice(5).join('|'))
    })
  }
  return out
}

function parseRoleBindings(text: string, clusterScoped: boolean): K8sRoleBinding[] {
  const out: K8sRoleBinding[] = []
  for (const raw of text.split('\n')) {
    const line = raw.trim()
    if (line === '' || NO_RESOURCES.test(line)) continue
    const f = line.split('|')
    if (f.length < 5) continue
    // Names are NOT validated here, and that is not an oversight. RBAC objects
    // are routinely called things like `kubeadm:bootstrap-signer-clusterinfo`
    // and `system::extension-apiserver-authentication-reader`, which no RFC
    // 1123 test accepts — running one against them would silently drop most of
    // a cluster's real bindings. Shape is the test, as everywhere else here.
    if (f[1].trim() === '') continue
    if (f[0] !== '' && !validateNamespace(f[0])) continue
    out.push({
      namespace: f[0].trim(),
      name: f[1].trim(),
      roleKind: f[2].trim(),
      roleName: f[3].trim(),
      subjects: splitList(f.slice(4).join('|')),
      clusterScoped
    })
  }
  return out
}

function parseSecretRefs(text: string): K8sSecretRef[] {
  const out: K8sSecretRef[] = []
  for (const raw of text.split('\n')) {
    const line = raw.trim()
    if (line === '' || NO_RESOURCES.test(line)) continue
    const f = line.split('|')
    if (f.length < 5) continue
    if (!validateNamespace(f[0]) || f[1].trim() === '') continue
    out.push({
      namespace: f[0],
      name: f[1].trim(),
      type: f[2].trim(),
      keys: f[3].split(',').map((k) => k.trim()).filter((k) => k !== ''),
      created: f[4].trim()
    })
  }
  return out
}

export function parseK8sResources(output: string, exitCode: number | null): K8sResources {
  const rb = readBlock(section(output, 'RB'), (t) => parseRoleBindings(t, false), exitCode)
  const crb = readBlock(section(output, 'CRB'), (t) => parseRoleBindings(t, true), exitCode)
  return {
    pvcs: readBlock(section(output, 'PVC'), parsePvcs, exitCode),
    ingresses: readBlock(section(output, 'ING'), parseIngresses, exitCode),
    // Merged, but a denial on EITHER half fails the whole read rather than
    // being quietly dropped: a token that can list RoleBindings and not
    // ClusterRoleBindings would otherwise show a namespace's bindings and
    // silently omit the cluster-admin grant, which is the single most
    // important row in this table.
    roleBindings: !rb.ok
      ? rb
      : !crb.ok
        ? crb
        : { ok: true, items: [...rb.items, ...crb.items] },
    secrets: readBlock(section(output, 'SEC'), parseSecretRefs, exitCode)
  }
}

// ------------------------------------------------- deprecated API scan

/**
 * API groupVersions Kubernetes has removed, or announced it will.
 *
 * A SNAPSHOT, and stated as one. It is accurate as of Kubernetes 1.33 and it
 * will go stale; a scan that quietly reports "nothing deprecated" from a table
 * three releases old is the failure mode, which is why `K8sApiScan` carries
 * what the scan could not check rather than only what it found.
 */
export interface K8sDeprecatedApi {
  groupVersion: string
  /** Minor release it was removed in, or will be. */
  removedIn: string
  /** What replaced it. */
  replacement: string
}

export const K8S_DEPRECATED_APIS: readonly K8sDeprecatedApi[] = [
  { groupVersion: 'extensions/v1beta1', removedIn: '1.22', replacement: 'apps/v1 and networking.k8s.io/v1' },
  { groupVersion: 'apps/v1beta1', removedIn: '1.16', replacement: 'apps/v1' },
  { groupVersion: 'apps/v1beta2', removedIn: '1.16', replacement: 'apps/v1' },
  { groupVersion: 'networking.k8s.io/v1beta1', removedIn: '1.22', replacement: 'networking.k8s.io/v1' },
  { groupVersion: 'rbac.authorization.k8s.io/v1beta1', removedIn: '1.22', replacement: 'rbac.authorization.k8s.io/v1' },
  { groupVersion: 'apiextensions.k8s.io/v1beta1', removedIn: '1.22', replacement: 'apiextensions.k8s.io/v1' },
  { groupVersion: 'admissionregistration.k8s.io/v1beta1', removedIn: '1.22', replacement: 'admissionregistration.k8s.io/v1' },
  { groupVersion: 'certificates.k8s.io/v1beta1', removedIn: '1.22', replacement: 'certificates.k8s.io/v1' },
  { groupVersion: 'coordination.k8s.io/v1beta1', removedIn: '1.22', replacement: 'coordination.k8s.io/v1' },
  { groupVersion: 'storage.k8s.io/v1beta1', removedIn: '1.22', replacement: 'storage.k8s.io/v1' },
  { groupVersion: 'policy/v1beta1', removedIn: '1.25', replacement: 'policy/v1 (and PodSecurityPolicy has no replacement — see Pod Security Admission)' },
  { groupVersion: 'batch/v1beta1', removedIn: '1.25', replacement: 'batch/v1' },
  { groupVersion: 'discovery.k8s.io/v1beta1', removedIn: '1.25', replacement: 'discovery.k8s.io/v1' },
  { groupVersion: 'events.k8s.io/v1beta1', removedIn: '1.25', replacement: 'events.k8s.io/v1' },
  { groupVersion: 'node.k8s.io/v1beta1', removedIn: '1.25', replacement: 'node.k8s.io/v1' },
  { groupVersion: 'autoscaling/v2beta1', removedIn: '1.25', replacement: 'autoscaling/v2' },
  { groupVersion: 'autoscaling/v2beta2', removedIn: '1.26', replacement: 'autoscaling/v2' },
  { groupVersion: 'flowcontrol.apiserver.k8s.io/v1beta1', removedIn: '1.29', replacement: 'flowcontrol.apiserver.k8s.io/v1' },
  { groupVersion: 'flowcontrol.apiserver.k8s.io/v1beta2', removedIn: '1.29', replacement: 'flowcontrol.apiserver.k8s.io/v1' },
  { groupVersion: 'flowcontrol.apiserver.k8s.io/v1beta3', removedIn: '1.32', replacement: 'flowcontrol.apiserver.k8s.io/v1' }
]

export interface K8sApiFinding {
  groupVersion: string
  removedIn: string
  replacement: string
  /**
   * True when this server has ALREADY passed the removal release and is still
   * serving it — which does happen, on a distribution that carries patches.
   */
  pastRemoval: boolean
}

export interface K8sApiScan {
  /** The SERVER's version, not the client's. */
  serverVersion: string | null
  served: K8sRead<string>
  findings: K8sApiFinding[]
  /**
   * What this scan did not and could not look at.
   *
   * Not a disclaimer. This scan reads what the API SERVER SERVES, and that is
   * a different question from the one people think they are asking, which is
   * "will my manifests still apply next release". The gap is large enough that
   * reporting only the findings would be the same lie as an empty pod list
   * from a denied read, so it is carried in the result and rendered with it.
   */
  notChecked: string[]
}

export function buildK8sApiScanCommand(context?: string): string {
  const ctx = context && validateContext(context) ? ` --context=${context}` : ''
  return [
    k8sResolve(),
    call('SRVVER', `version -o json${ctx}`),
    call('APIVER', `api-versions${ctx}`)
  ].join('; ')
}

const MINOR_RE = /^v?(\d+)\.(\d+)/

/** Is `a` at or past `b`, as Kubernetes minor releases? */
function atOrPast(a: string, b: string): boolean {
  const ma = MINOR_RE.exec(a)
  const mb = MINOR_RE.exec(b)
  if (!ma || !mb) return false
  const [, aMaj, aMin] = ma
  const [, bMaj, bMin] = mb
  return Number(aMaj) > Number(bMaj) || (aMaj === bMaj && Number(aMin) >= Number(bMin))
}

/**
 * The four things this scan cannot see, in the words it reports them in.
 *
 * Exported so the panel and the test name the same list; they are properties
 * of the method, not of any particular cluster.
 */
export const K8S_API_SCAN_BLIND_SPOTS: readonly string[] = [
  'what your manifests and Helm charts DECLARE. An object written as policy/v1beta1 is stored once and served back under policy/v1, so nothing readable from the API says which version a chart still sends. This scan reads the server, not your repository.',
  'CustomResourceDefinitions and aggregated APIs. Their versions are the operator author’s to deprecate and are not in the table below.',
  'controllers and webhooks that CALL a removed API. Those break at the client, and nothing on the server records that they were going to.',
  'anything the table has not caught up with. It is a snapshot taken at Kubernetes 1.33 and it will go stale — a scan that reports nothing from a table three releases old looks exactly like a cluster with nothing wrong.'
]

export function parseK8sApiScan(output: string, exitCode: number | null): K8sApiScan {
  const verBlock = section(output, 'SRVVER')
  let serverVersion: string | null = null
  try {
    const j = JSON.parse(verBlock.trim()) as { serverVersion?: { gitVersion?: string } }
    serverVersion = j.serverVersion?.gitVersion ?? null
  } catch {
    // kubectl printed something that is not JSON — an error, most likely. The
    // version stays null and the served read below carries the reason.
    serverVersion = null
  }
  const served = readBlock(
    section(output, 'APIVER'),
    (t) =>
      t
        .split('\n')
        .map((l) => l.trim())
        // Shape: a groupVersion is one token with no spaces. kubectl's error
        // sentences all have spaces in them.
        .filter((l) => l !== '' && !/\s/.test(l) && !NO_RESOURCES.test(l)),
    exitCode
  )
  const findings: K8sApiFinding[] = []
  if (served.ok) {
    for (const gv of served.items) {
      const hit = K8S_DEPRECATED_APIS.find((d) => d.groupVersion === gv)
      if (!hit) continue
      findings.push({
        groupVersion: hit.groupVersion,
        removedIn: hit.removedIn,
        replacement: hit.replacement,
        pastRemoval: serverVersion !== null && atOrPast(serverVersion, hit.removedIn)
      })
    }
  }
  const notChecked = [...K8S_API_SCAN_BLIND_SPOTS]
  if (!served.ok) {
    // The read itself failed, so "no findings" means nothing at all. First in
    // the list because it is the only entry that is about THIS run.
    notChecked.unshift(
      `the served API list could not be read (${served.reason}: ${served.detail}), so the findings below are empty because nothing was looked at`
    )
  }
  if (serverVersion === null) {
    notChecked.unshift(
      'the server version could not be read, so nothing here can say whether this cluster is already past a removal release'
    )
  }
  return { serverVersion, served, findings, notChecked }
}

// ------------------------------------------------- helm

export interface K8sHelmRelease {
  name: string
  namespace: string
  revision: string
  status: string
  chart: string
  appVersion: string
  updated: string
}

export type K8sHelmList =
  | { ok: true; releases: K8sHelmRelease[] }
  | { ok: false; reason: 'not-installed' | 'failed'; detail: string }

/**
 * `helm list -A`, on a host that may well not have helm.
 *
 * Its own command and its own result type, for the reason `kubectl top` has
 * both: helm is absent from most hosts, and folding it into a read that
 * usually succeeds would make the common case wait on a call that usually
 * fails — and would tempt the panel into showing an empty release table, which
 * reads as "nothing is installed by Helm" rather than "helm is not here".
 *
 * `resolveBinary` is reused: helm is very often in /usr/local/bin, which an
 * `ssh host cmd` non-login shell does not have on its PATH.
 */
export function buildK8sHelmListCommand(context?: string): string {
  const ctx = context && validateContext(context) ? ` --kube-context=${context}` : ''
  return [
    resolveBinary('helm', ['/usr/local/bin/helm', '/snap/bin/helm']),
    'echo "===SHELLPILOT-HELM==="',
    `"$SP_BIN" list --all-namespaces --output json${ctx} 2>&1`
  ].join('; ')
}

const HELM_MISSING_RE = /(^|:\s)(command not found|helm: not found)|no such file or directory/i

export function parseK8sHelmList(output: string, exitCode: number | null): K8sHelmList {
  const said = section(output, 'HELM').trim()
  if (said === '') {
    return { ok: false, reason: 'failed', detail: 'helm returned nothing' }
  }
  if (HELM_MISSING_RE.test(said) || exitCode === 127) {
    return {
      ok: false,
      reason: 'not-installed',
      detail:
        'No helm on this host. That is not a statement about the cluster — releases installed from somewhere else are still there, this host just cannot list them.'
    }
  }
  try {
    const rows = JSON.parse(said) as Record<string, unknown>[]
    if (!Array.isArray(rows)) return { ok: false, reason: 'failed', detail: said.split('\n')[0] }
    const str = (v: unknown): string => (typeof v === 'string' ? v : '')
    return {
      ok: true,
      releases: rows.map((r) => ({
        name: str(r.name),
        namespace: str(r.namespace),
        revision: str(r.revision),
        status: str(r.status),
        chart: str(r.chart),
        appVersion: str(r.app_version),
        updated: str(r.updated)
      }))
    }
  } catch {
    return { ok: false, reason: 'failed', detail: said.split('\n')[0] }
  }
}
