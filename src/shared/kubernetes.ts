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
// WHAT IT DELIBERATELY DOES NOT DO:
//  - Switch contexts. `kubectl config use-context` mutates the user's kubeconfig
//    for every process on that host, not just for us. A tool that silently
//    repoints someone's cluster because they clicked a dropdown is how you
//    apply a manifest to prod believing it is staging. Context is chosen per
//    read, with `--context`, and never persisted.
//  - Exec into a pod. That is `docker exec` with more blast radius and an
//    entirely separate RBAC story, and it belongs behind the same approval
//    model broadcast has rather than a button next to a pod name.
//  - Anything that writes: no apply, delete, scale, drain, or cordon.
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
  | 'unknown'

export const K8S_FAILURE_HELP: Record<K8sFailure, string> = {
  'not-installed': 'kubectl is not on this host, or not on the PATH an SSH session gets.',
  'no-kubeconfig':
    'kubectl is installed but found no kubeconfig. It looks in $KUBECONFIG then ~/.kube/config, and an SSH session may not have the same environment as a login shell.',
  'no-cluster':
    'kubectl has a config but the cluster is not answering — the API server may be down, or the context may point somewhere unreachable from this host.',
  forbidden:
    'This account is authenticated but its RBAC does not allow listing these resources. That is a different problem from there being none, and the roles it needs are named in the raw error below.',
  unauthorized:
    'The cluster rejected these credentials. A token or client certificate has most likely expired.',
  unknown: 'kubectl returned an error that could not be classified. The raw message is below.'
}

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

// Names are echoed into a shell command, so they are validated rather than
// escaped — the same rule the log tailer and the docker module follow.
// Kubernetes names are RFC 1123 labels; contexts are looser but bounded.
const NAME_RE = /^[a-z0-9]([-a-z0-9.]{0,251}[a-z0-9])?$/i
const CONTEXT_RE = /^[a-zA-Z0-9][a-zA-Z0-9_.:@/-]{0,252}$/

export const validatePodName = (v: string): boolean => NAME_RE.test(v.trim())
export const validateNamespace = (v: string): boolean => NAME_RE.test(v.trim())
export const validateContext = (v: string): boolean => CONTEXT_RE.test(v.trim())


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
  const t = ' --request-timeout=10s'
  const cols =
    `custom-columns=NS:.metadata.namespace,NAME:.metadata.name,` +
    `READY:.status.containerStatuses[*].ready,PHASE:.status.phase,` +
    `RESTARTS:.status.containerStatuses[*].restartCount,NODE:.spec.nodeName,START:.status.startTime`
  return [
    `kubectl version --client -o json${t} 2>&1`,
    'echo "===SHELLPILOT-CTX==="',
    `kubectl config get-contexts --no-headers${t} 2>&1`,
    'echo "===SHELLPILOT-NS==="',
    `kubectl get ns --no-headers -o custom-columns=NAME:.metadata.name${ctx}${t} 2>&1`,
    'echo "===SHELLPILOT-PODS-ALL==="',
    `kubectl get pods --all-namespaces --no-headers -o ${cols}${ctx}${t} 2>&1`,
    'echo "===SHELLPILOT-PODS-NS==="',
    `kubectl get pods --no-headers -o ${cols}${ctx}${ns}${t} 2>&1`
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

function parsePods(text: string): K8sPod[] {
  const pods: K8sPod[] = []
  for (const raw of text.split('\n')) {
    const line = raw.trim()
    if (line === '' || looksLikeError(line)) continue
    const f = line.split(/\s+/)
    if (f.length < 7) continue
    const [ns, name, ready, phase, restarts, node, start] = f
    // READY comes back as "true,true" or "true,false"; kubectl's own table
    // shows "2/2". Reconstructing it keeps the column meaning what operators
    // expect rather than showing raw booleans.
    const flags = cleanCell(ready).split(',').filter(Boolean)
    const readyCount = flags.filter((x) => x === 'true').length
    const restartList = cleanCell(restarts).split(',').filter(Boolean).map(Number)
    pods.push({
      namespace: ns,
      name,
      ready: flags.length ? `${readyCount}/${flags.length}` : '0/0',
      status: phase,
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

/** `kubectl logs`, bounded. Never built from unvalidated names. */
export function buildK8sLogsCommand(
  namespace: string,
  pod: string,
  lines = 200,
  context?: string
): string {
  if (!validateNamespace(namespace) || !validatePodName(pod)) {
    throw new Error('refusing to build a command from an invalid pod or namespace name')
  }
  const n = Math.min(5_000, Math.max(1, Math.floor(Number(lines))))
  const safe = Number.isFinite(n) ? n : 200
  const ctx = context && validateContext(context) ? ` --context=${context}` : ''
  // --all-containers so a multi-container pod does not silently show one of
  // them; --prefix so you can tell which.
  return `kubectl logs --namespace=${namespace} ${pod} --tail=${safe} --all-containers --prefix --request-timeout=10s${ctx} 2>&1`
}
