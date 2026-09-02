import { describe, it, expect } from 'vitest'
import {
  parseK8sOutput,
  classifyK8sFailure,
  buildK8sReadCommand,
  buildK8sLogsCommand,
  validatePodName,
  validateContext
} from '../src/shared/kubernetes'

// The roadmap's warning about Kubernetes is that doing it badly is worse than
// not doing it, and the specific way it goes bad is RBAC: a token can list pods
// in one namespace and nothing in another, and kubectl reports that as an error
// with a zero-length list. "No pods" for a permissions failure is the same lie
// the Docker module is shaped to avoid.


// A pod row in the column order `buildK8sReadCommand` actually emits:
//   NS NAME READY PHASE WANT WAIT TERM RESTARTS NODE START
//
// These fixtures previously had seven columns because that is what I guessed
// kubectl printed. Running the real command against a real cluster showed ten,
// and showed that `.status.phase` is `Running` for a CrashLoopBackOff pod —
// which is why STATUS now comes from the container's waiting/terminated reason
// and the phase is only a fallback.
const podRow = (o: {
  ns?: string; name: string; ready?: string; phase?: string; want?: string
  wait?: string; term?: string; restarts?: string; node?: string; start?: string
}): string =>
  [
    o.ns ?? 'default',
    o.name,
    o.ready ?? 'true',
    o.phase ?? 'Running',
    o.want ?? 'app',
    o.wait ?? '<none>',
    o.term ?? '<none>',
    o.restarts ?? '0',
    o.node ?? 'node-1',
    o.start ?? '2026-09-01T10:00:00Z'
  ].join('   ')

const out = (parts: Record<string, string>): string =>
  [
    parts.version ?? '{"clientVersion":{"gitVersion":"v1.29.2"}}',
    '===SHELLPILOT-CTX===',
    parts.ctx ?? '',
    '===SHELLPILOT-NS===',
    parts.ns ?? '',
    '===SHELLPILOT-PODS-ALL===',
    parts.all ?? '',
    '===SHELLPILOT-PODS-NS===',
    parts.nsPods ?? ''
  ].join('\n')

describe('reading a cluster', () => {
  const sample = out({
    ctx: '*         prod-eks    prod-eks    admin      default\n          staging     staging     admin      default',
    ns: 'default\nkube-system\napp',
    all: [
      podRow({ name: 'web-7d9f', ready: 'true,true', want: 'a,b', restarts: '0,0' }),
      podRow({ ns: 'kube-system', name: 'coredns-abc', restarts: '3', node: 'node-2' }),
      podRow({ ns: 'app', name: 'worker-1', ready: 'true,false', want: 'a,b', restarts: '0,12' })
    ].join('\n')
  })

  it('reads contexts and marks the current one', () => {
    const r = parseK8sOutput(sample, 0)
    expect(r.ok).toBe(true)
    if (!r.ok) return
    expect(r.contexts.map((c) => c.name)).toEqual(['prod-eks', 'staging'])
    expect(r.currentContext).toBe('prod-eks')
  })

  it('rebuilds the ready column operators expect', () => {
    // kubectl's custom-columns prints "true,false"; its own table prints "1/2".
    // Showing raw booleans would be technically true and unreadable.
    const r = parseK8sOutput(sample, 0)
    if (!r.ok) return
    expect(r.pods.find((p) => p.name === 'worker-1')?.ready).toBe('1/2')
    expect(r.pods.find((p) => p.name === 'web-7d9f')?.ready).toBe('2/2')
  })

  it('reports the worst restart count across containers, not the first', () => {
    // A pod with one calm container and one crashlooping is a crashlooping pod.
    const r = parseK8sOutput(sample, 0)
    if (!r.ok) return
    expect(r.pods.find((p) => p.name === 'worker-1')?.restarts).toBe(12)
  })

  it('says whether it saw all namespaces', () => {
    const r = parseK8sOutput(sample, 0)
    expect(r.ok && r.allNamespaces).toBe(true)
  })
})

describe('RBAC, which is what makes this different from docker', () => {
  it('falls back to the current namespace when --all-namespaces is forbidden', () => {
    // The common real denial. Failing entirely would be less useful than
    // showing the one namespace this token can actually read.
    const r = parseK8sOutput(
      out({
        ctx: '*  prod  prod  admin  default',
        ns: 'default',
        all: 'Error from server (Forbidden): pods is forbidden: User "dev" cannot list resource "pods" in API group "" at the cluster scope',
        nsPods: podRow({ name: 'web-1' })
      }),
      0
    )
    expect(r.ok).toBe(true)
    if (!r.ok) return
    expect(r.pods).toHaveLength(1)
    // And it must SAY so — an empty or partial list means something different
    // depending on this flag.
    expect(r.allNamespaces).toBe(false)
  })

  it('does not report an empty cluster when every read was denied', () => {
    const r = parseK8sOutput(
      out({
        ctx: 'error: You must be logged in to the server (Unauthorized)',
        ns: 'error: You must be logged in to the server (Unauthorized)',
        all: 'error: You must be logged in to the server (Unauthorized)',
        nsPods: 'error: You must be logged in to the server (Unauthorized)'
      }),
      1
    )
    expect(r.ok).toBe(false)
    if (r.ok) return
    expect(r.reason).toBe('unauthorized')
  })

  it('tells forbidden apart from a dead cluster', () => {
    // Both mention the server. Getting the order wrong sends someone to debug
    // a healthy API server.
    expect(
      classifyK8sFailure('Error from server (Forbidden): pods is forbidden: User cannot list resource', 1)
    ).toBe('forbidden')
    expect(
      classifyK8sFailure('The connection to the server 10.0.0.1:6443 was refused - did you specify the right host or port?', 1)
    ).toBe('no-cluster')
  })

  it('tells a missing kubeconfig apart from a dead cluster', () => {
    // kubectl says "did you specify the right host or port" for both; the
    // kubeconfig wording is the only tiebreak.
    expect(classifyK8sFailure('error: no configuration has been provided, try setting KUBERNETES_MASTER', 1)).toBe(
      'no-kubeconfig'
    )
  })

  it('knows kubectl is simply absent', () => {
    expect(classifyK8sFailure('bash: kubectl: command not found', 127)).toBe('not-installed')
    const r = parseK8sOutput('bash: kubectl: command not found', 127)
    expect(r.ok).toBe(false)
    expect(!r.ok && r.reason).toBe('not-installed')
  })

  it('falls back to unknown rather than guessing', () => {
    expect(classifyK8sFailure('something nobody has seen before', 1)).toBe('unknown')
  })
})

describe('commands', () => {
  it('never switches the context persistently', () => {
    // `kubectl config use-context` rewrites the user's kubeconfig for every
    // process on that host. Choosing per read with --context cannot repoint
    // somebody's cluster behind their back.
    const cmd = buildK8sReadCommand('prod-eks')
    expect(cmd).toMatch(/--context=prod-eks/)
    expect(cmd).not.toMatch(/use-context/)
  })

  it('is read-only', () => {
    const cmd = buildK8sReadCommand('prod', 'default')
    expect(cmd).not.toMatch(/\b(apply|delete|scale|drain|cordon|edit|patch|exec)\b/)
  })

  it('bounds every call, because kubectl waits forever by default', () => {
    // A dead cluster would otherwise hang the SSH exec with no output.
    const cmd = buildK8sReadCommand()
    // Every INVOCATION, which now goes through "$SP_BIN" — the PATH resolver
    // mentions kubectl by name without being a call, and matching on the word
    // would test the resolver rather than the calls.
    // A CALL runs the binary; the resolver's fallback assigns to it. Matching
    // on the variable name alone caught the assignment too.
    const calls = cmd.split(';').filter((p) => /"\$SP_BIN"\s+\w/.test(p))
    expect(calls.length).toBeGreaterThanOrEqual(5)
    for (const part of calls) expect(part, part).toMatch(/--request-timeout=/)
  })

  it('ignores a context or namespace it cannot prove safe', () => {
    // Refuses rather than escapes, like every other builder here.
    const cmd = buildK8sReadCommand('prod; rm -rf /', 'ns; reboot')
    expect(cmd).not.toMatch(/rm -rf/)
    expect(cmd).not.toMatch(/reboot/)
  })

  it('throws rather than building logs from an invalid name', () => {
    expect(() => buildK8sLogsCommand('default', 'pod; reboot')).toThrow(/refusing/)
    expect(() => buildK8sLogsCommand('ns; id', 'web')).toThrow(/refusing/)
  })

  it('clamps the log line count, which crosses IPC untyped', () => {
    const cmd = buildK8sLogsCommand('default', 'web', '200; curl x | sh' as unknown as number)
    expect(cmd).not.toMatch(/curl/)
    expect(cmd).toMatch(/--tail=200/)
  })

  it('shows every container in a multi-container pod, and says which', () => {
    // Otherwise one container's logs silently stand in for the pod's.
    const cmd = buildK8sLogsCommand('default', 'web')
    expect(cmd).toMatch(/--all-containers/)
    expect(cmd).toMatch(/--prefix/)
  })

  it('validates names against what Kubernetes actually allows', () => {
    expect(validatePodName('web-7d9f-abc12')).toBe(true)
    expect(validatePodName('a; rm -rf /')).toBe(false)
    // Context names are looser — EKS and GKE use ARNs and slashes.
    expect(validateContext('arn:aws:eks:eu-west-1:123:cluster/prod')).toBe(true)
    expect(validateContext('ctx; reboot')).toBe(false)
  })
})

// Three bug classes the Docker/cron review found in the modules written earlier
// today. This parser was written after those existed and before that review
// landed, so it had all three. Pinned here so the lesson does not have to be
// learned a third time.
describe('mistakes inherited from the modules written before this one', () => {
  it('does not call a kubeconfig path error a missing binary', () => {
    // Docker classified `dial unix /var/run/docker.sock: no such file or
    // directory` as not-installed, which sends someone to install something
    // already present. Same words, same trap here.
    expect(
      classifyK8sFailure('error: stat /home/ops/.kube/config: no such file or directory', 1)
    ).toBe('no-kubeconfig')
    // A genuine missing binary must still be caught.
    expect(classifyK8sFailure('bash: kubectl: command not found', 127)).toBe('not-installed')
    expect(classifyK8sFailure('zsh: command not found: kubectl', 1)).toBe('not-installed')
  })

  it('reads a cluster whose shell emits CRLF', () => {
    // The cron collector matched `===\n` exactly, so a CRLF host matched no
    // marker at all and reported as empty — a silent, total failure.
    const crlf = [
      '{"clientVersion":{"gitVersion":"v1.29.2"}}',
      '===SHELLPILOT-CTX===',
      '*  prod  prod  admin  default',
      '===SHELLPILOT-NS===',
      'default',
      '===SHELLPILOT-PODS-ALL===',
      podRow({ name: 'web-1' }),
      '===SHELLPILOT-PODS-NS===',
      ''
    ].join('\r\n')
    const r = parseK8sOutput(crlf, 0)
    expect(r.ok).toBe(true)
    expect(r.ok && r.pods).toHaveLength(1)
    expect(r.ok && r.currentContext).toBe('prod')
  })

  it('does not drop a namespace or pod whose name contains an error word', () => {
    // Docker hit this with a container named `permission-denied-test`. A
    // namespace called `error-reporting` is an ordinary thing to have.
    const r = parseK8sOutput(
      out({
        ctx: '*  prod  prod  admin  default',
        ns: 'default\nerror-reporting\nunauthorized-probe',
        all: [
          podRow({ ns: 'error-reporting', name: 'forbidden-checker' }),
          podRow({ ns: 'unauthorized-probe', name: 'timeout-watchdog', node: 'node-2' })
        ].join('\n')
      }),
      0
    )
    expect(r.ok).toBe(true)
    if (!r.ok) return
    expect(r.namespaces).toEqual(['default', 'error-reporting', 'unauthorized-probe'])
    expect(r.pods.map((p) => p.name)).toEqual(['forbidden-checker', 'timeout-watchdog'])
  })

  it('still recognises a real kubectl error among data lines', () => {
    // The counterpart: loosening the pattern must not blind it to the thing it
    // is for.
    const r = parseK8sOutput(
      out({
        ctx: 'error: You must be logged in to the server (Unauthorized)',
        ns: 'error: You must be logged in to the server (Unauthorized)',
        all: 'Error from server (Forbidden): pods is forbidden',
        nsPods: 'Error from server (Forbidden): pods is forbidden'
      }),
      1
    )
    expect(r.ok).toBe(false)
  })
})


// "kubectl: command not found" over SSH is usually wrong about the cause.
//
// `ssh host cmd` runs a NON-LOGIN shell, so PATH is roughly /usr/bin:/bin — no
// /usr/local/bin, no /snap/bin. That is where kubectl most often lives, so the
// message sends someone to install a thing that is already there.
describe('finding the binary a non-login shell cannot see', () => {
  it('looks in the places a login shell would', () => {
    const cmd = buildK8sReadCommand()
    for (const p of ['/usr/local/bin/kubectl', '/snap/bin/kubectl', '/usr/bin/kubectl']) {
      expect(cmd, p).toContain(p)
    }
  })

  it('covers the wrappers k3s and microk8s ship instead of kubectl', () => {
    const cmd = buildK8sReadCommand()
    expect(cmd).toContain('/snap/bin/microk8s.kubectl')
    expect(cmd).toContain('/var/lib/rancher/rke2/bin/kubectl')
  })

  it('falls back to the bare name so PATH still gets a chance', () => {
    // If none of the candidates exist, running `kubectl` unqualified is still
    // the right last attempt — the user may have it somewhere unusual.
    expect(buildK8sReadCommand()).toMatch(/SP_BIN=kubectl/)
  })

  it('does not try sudo, because sudo cannot fix RBAC', () => {
    // Docker permission denied is a unix group problem root solves. Kubernetes
    // `forbidden` is about the identity in the kubeconfig, and `sudo kubectl`
    // reads ROOT's kubeconfig — usually absent — turning a precise error into
    // a vague one.
    expect(buildK8sReadCommand()).not.toMatch(/sudo/)
  })
})


// ===========================================================================
// Operations: what an operator reaches for during an incident.
//
// The first version of this module could tell you a pod was in
// CrashLoopBackOff and then had nothing further to say. Everything below is
// the part that answers "why", and every fixture here is real kubectl output
// — including the error strings, because the error strings are the product.
// ===========================================================================

import {
  buildK8sDiagnoseCommand,
  buildK8sOverviewCommand,
  buildK8sTopCommand,
  buildK8sRolloutRestartCommand,
  parseK8sDiagnosis,
  parseK8sOverview,
  parseK8sUsage,
  parseK8sRolloutResult,
  planK8sRollout,
  k8sRelativeTime,
  workloadIsDegraded,
  nodeIsUnhealthy,
  K8S_FAILURE_HELP
} from '../src/shared/kubernetes'

const block = (parts: Record<string, string>): string =>
  Object.entries(parts)
    .map(([k, v]) => `===SHELLPILOT-${k}===\n${v}`)
    .join('\n')

// Real `kubectl describe pod` output, trimmed to the parts anyone reads.
const DESCRIBE_CRASHLOOP = `Name:             web-7d9f-x2k41
Namespace:        default
Priority:         0
Node:             node-2/10.0.1.42
Start Time:       Tue, 01 Sep 2026 09:02:11 +0000
Labels:           app=web
                  pod-template-hash=7d9f
Status:           Running
IP:               10.244.2.17
Controlled By:    ReplicaSet/web-7d9f
Containers:
  web:
    Container ID:   containerd://9f1c2a0b
    Image:          registry.example.com/web:1.4.2
    State:          Waiting
      Reason:       CrashLoopBackOff
    Last State:     Terminated
      Reason:       Error
      Exit Code:    1
      Started:      Tue, 01 Sep 2026 09:13:58 +0000
      Finished:     Tue, 01 Sep 2026 09:14:01 +0000
    Ready:          False
    Restart Count:  7
Conditions:
  Type              Status
  Ready             False
Events:
  Type     Reason     Age                    From     Message
  ----     ------     ----                   ----     -------
  Warning  BackOff    2m17s (x42 over 12m)   kubelet  Back-off restarting failed container web`

// Real `kubectl get events` under the custom-columns this module asks for.
// Column order is LAST ETIME TYPE REASON KIND OBJECT NS COUNT MESSAGE.
const POD_EVENTS = [
  '2026-09-01T09:02:12Z   <none>                 Normal    Scheduled   Pod   web-7d9f-x2k41   default   <none>   Successfully assigned default/web-7d9f-x2k41 to node-2',
  '2026-09-01T09:14:22Z   <none>                 Warning   BackOff     Pod   web-7d9f-x2k41   default   417      Back-off restarting failed container web in pod web-7d9f-x2k41_default(9f1c2a0b)',
  '<none>                 2026-09-01T09:03:40Z   Normal    Pulled      Pod   web-7d9f-x2k41   default   <none>   Successfully pulled image "registry.example.com/web:1.4.2" in 1.203s (1.203s including waiting)'
].join('\n')

describe('why is this pod unhealthy', () => {
  const output = block({
    DESCRIBE: DESCRIBE_CRASHLOOP,
    EVENTS: POD_EVENTS,
    PREVIOUS: 'panic: dial tcp 10.0.3.9:5432: connect: connection refused\n\ngoroutine 1 [running]:\nmain.main()'
  })

  it('brings back describe, events and the previous container in one read', () => {
    const d = parseK8sDiagnosis('default', 'web-7d9f-x2k41', output, 0)
    expect(d.describe.ok).toBe(true)
    expect(d.events.ok).toBe(true)
    expect(d.previousLogs.ok).toBe(true)
    expect(d.events.ok && d.events.items).toHaveLength(3)
  })

  it('puts the newest event first, which is what just broke', () => {
    const d = parseK8sDiagnosis('default', 'web-7d9f-x2k41', output, 0)
    if (!d.events.ok) throw new Error('events should have parsed')
    expect(d.events.items[0].reason).toBe('BackOff')
    expect(d.events.items[0].type).toBe('Warning')
  })

  it('reads the timestamp from EITHER event API', () => {
    // events.k8s.io/v1 leaves .lastTimestamp null and fills .eventTime.
    // Reading only the first is how a modern cluster's events all come back
    // with no time at all — and then sort into an arbitrary order.
    const d = parseK8sDiagnosis('default', 'web-7d9f-x2k41', output, 0)
    if (!d.events.ok) throw new Error('events should have parsed')
    const pulled = d.events.items.find((e) => e.reason === 'Pulled')
    expect(pulled?.lastSeen).toBe('2026-09-01T09:03:40Z')
  })

  it('keeps the whole message, which is the only part that explains anything', () => {
    const d = parseK8sDiagnosis('default', 'web-7d9f-x2k41', output, 0)
    if (!d.events.ok) throw new Error('events should have parsed')
    expect(d.events.items[0].message).toBe(
      'Back-off restarting failed container web in pod web-7d9f-x2k41_default(9f1c2a0b)'
    )
    expect(d.events.items[0].count).toBe(417)
  })

  it('counts an event with no count field as having happened once, not zero', () => {
    const d = parseK8sDiagnosis('default', 'web-7d9f-x2k41', output, 0)
    if (!d.events.ok) throw new Error('events should have parsed')
    expect(d.events.items.find((e) => e.reason === 'Scheduled')?.count).toBe(1)
  })

  it('does not drop the image-pull event because its message ends in "Forbidden"', () => {
    // The single most valuable event in a set, and a content-matching error
    // filter eats it: a registry 403 is a real Warning whose message ends in a
    // word the error pattern matches. The panel would then show a pod stuck in
    // ImagePullBackOff next to an empty event list.
    const denied =
      '2026-09-01T09:20:00Z   <none>   Warning   Failed   Pod   web-7d9f-x2k41   default   9   Failed to pull image "registry.example.com/web:1.4.2": failed to resolve reference: unexpected status from HEAD request: 403 Forbidden'
    const d = parseK8sDiagnosis('default', 'web-7d9f-x2k41', block({ EVENTS: denied }), 0)
    expect(d.events.ok).toBe(true)
    if (!d.events.ok) return
    expect(d.events.items).toHaveLength(1)
    expect(d.events.items[0].message).toMatch(/403 Forbidden$/)
  })

  it('says there is no previous container rather than showing an empty pane', () => {
    // A healthy pod has no previous instance. Rendered as a failure it looks
    // like a container that crashed silently; rendered as an empty log pane it
    // looks like one that logged nothing.
    const d = parseK8sDiagnosis(
      'default',
      'web-1',
      block({
        DESCRIBE: DESCRIBE_CRASHLOOP,
        EVENTS: '',
        PREVIOUS:
          'Error from server (BadRequest): previous terminated container "web" in pod "web-1" not found'
      }),
      1
    )
    expect(d.previousLogs.ok).toBe(false)
    expect(!d.previousLogs.ok && d.previousLogs.reason).toBe('no-previous')
    expect(K8S_FAILURE_HELP['no-previous']).toMatch(/has not restarted/)
  })

  it('does not read the word Forbidden inside describe output as its own failure', () => {
    // describe prints the pod's own events, and one of them can be a registry
    // 403. Treating that as "we were refused" replaces the exact explanation
    // the operator opened this pane to read.
    const describe = `${DESCRIBE_CRASHLOOP}
  Warning  Failed  1m  kubelet  Error: 403 Forbidden`
    const d = parseK8sDiagnosis('default', 'web-1', block({ DESCRIBE: describe }), 0)
    expect(d.describe.ok).toBe(true)
  })
})

describe('RBAC is per resource, not per round trip', () => {
  // The reason every block carries its own verdict. A token that lists pods
  // very often cannot list events.
  const EVENTS_FORBIDDEN =
    'Error from server (Forbidden): events is forbidden: User "system:serviceaccount:default:dev" cannot list resource "events" in API group "" in the namespace "default"'

  it('keeps describe when only events were denied', () => {
    const d = parseK8sDiagnosis(
      'default',
      'web-1',
      block({ DESCRIBE: DESCRIBE_CRASHLOOP, EVENTS: EVENTS_FORBIDDEN, PREVIOUS: 'boom' }),
      1
    )
    expect(d.describe.ok).toBe(true)
    expect(d.events.ok).toBe(false)
    expect(!d.events.ok && d.events.reason).toBe('forbidden')
  })

  it('never renders a denied read as an empty list', () => {
    const d = parseK8sDiagnosis('default', 'web-1', block({ EVENTS: EVENTS_FORBIDDEN }), 1)
    // The whole module exists so that this is impossible.
    expect(d.events).not.toEqual({ ok: true, items: [] })
  })

  it('tells "denied" apart from "genuinely nothing"', () => {
    // kubectl prints this on stdout for an empty result, and it is a SUCCESS.
    const d = parseK8sDiagnosis(
      'default',
      'web-1',
      block({ EVENTS: 'No resources found in default namespace.' }),
      0
    )
    expect(d.events).toEqual({ ok: true, items: [] })
  })

  it('keeps the rows it did get when kubectl also complained', () => {
    // A partial answer is still an answer, and dropping it loses real data.
    const d = parseK8sDiagnosis(
      'default',
      'web-1',
      block({ EVENTS: `${POD_EVENTS}\nError from server: etcdserver: request timed out` }),
      1
    )
    expect(d.events.ok).toBe(true)
    expect(d.events.ok && d.events.items).toHaveLength(3)
  })
})

describe('what is actually broken: workloads, nodes, namespace events', () => {
  const OVERVIEW = block({
    DEPLOY: [
      'default       web       3   3   3   3   RollingUpdate   2026-08-12T09:00:00Z',
      'default       legacy    1   1   1   1   Recreate        2026-05-02T11:00:00Z',
      'kube-system   coredns   2   1   2   1   RollingUpdate   2026-01-04T08:00:00Z'
    ].join('\n'),
    STS: [
      'prod   postgres   3   3   3   3   RollingUpdate   2026-02-01T00:00:00Z',
      'prod   redis      3   2   3   2   OnDelete        2026-02-01T00:00:00Z'
    ].join('\n'),
    DS: 'kube-system   node-exporter   3   2   3   2   RollingUpdate   2026-01-04T08:00:00Z',
    NODES: [
      'node-1   Ready                      control-plane   214d   v1.29.2',
      'node-2   NotReady                   <none>          214d   v1.29.2',
      'node-3   Ready,SchedulingDisabled   <none>          88d    v1.29.2'
    ].join('\n'),
    EVENTS: POD_EVENTS
  })

  it('reads ready against desired for all three workload kinds', () => {
    const o = parseK8sOverview(OVERVIEW, 0)
    if (!o.deployments.ok || !o.statefulSets.ok || !o.daemonSets.ok) throw new Error('should parse')
    expect(o.deployments.items.find((w) => w.name === 'coredns')).toMatchObject({
      desired: 2,
      ready: 1,
      strategy: 'RollingUpdate'
    })
    // A DaemonSet counts nodes, not replicas — different JSONPath, same shape.
    expect(o.daemonSets.items[0]).toMatchObject({ desired: 3, ready: 2, kind: 'daemonset' })
    expect(o.statefulSets.items.find((w) => w.name === 'redis')?.strategy).toBe('OnDelete')
  })

  it('reads the update strategy, because the confirmation depends on it', () => {
    const o = parseK8sOverview(OVERVIEW, 0)
    if (!o.deployments.ok) throw new Error('should parse')
    expect(o.deployments.items.find((w) => w.name === 'legacy')?.strategy).toBe('Recreate')
  })

  it('surfaces a NotReady node, which explains a lot of pod symptoms at once', () => {
    const o = parseK8sOverview(OVERVIEW, 0)
    if (!o.nodes.ok) throw new Error('should parse')
    expect(o.nodes.items.filter(nodeIsUnhealthy).map((n) => n.name)).toEqual(['node-2', 'node-3'])
    expect(o.nodes.items[2].status).toBe('Ready,SchedulingDisabled')
  })

  it('flags a degraded workload', () => {
    const o = parseK8sOverview(OVERVIEW, 0)
    if (!o.deployments.ok) throw new Error('should parse')
    expect(o.deployments.items.filter(workloadIsDegraded).map((w) => w.name)).toEqual(['coredns'])
  })

  it('does not invent a workload out of an RBAC error line', () => {
    // `Error from server (Forbidden): deployments.apps is forbidden: User ...`
    // splits into eight-plus tokens whose first two pass a name check. Without
    // a shape test on the replica columns it lands in the list as a workload
    // called `from` in a namespace called `Error`.
    const o = parseK8sOverview(
      block({
        DEPLOY:
          'Error from server (Forbidden): deployments.apps is forbidden: User "dev" cannot list resource "deployments" in API group "apps" in the namespace "kube-system"'
      }),
      1
    )
    expect(o.deployments.ok).toBe(false)
    expect(!o.deployments.ok && o.deployments.reason).toBe('forbidden')
  })

  it('gives up the nodes without giving up the workloads', () => {
    // A namespace-scoped token is denied nodes. That is normal, and it must
    // not cost the reads that succeeded.
    const o = parseK8sOverview(
      block({
        DEPLOY: 'default   web   3   3   3   3   RollingUpdate   2026-08-12T09:00:00Z',
        NODES:
          'Error from server (Forbidden): nodes is forbidden: User "dev" cannot list resource "nodes" in API group "" at the cluster scope'
      }),
      1
    )
    expect(o.deployments.ok && o.deployments.items).toHaveLength(1)
    expect(!o.nodes.ok && o.nodes.reason).toBe('forbidden')
  })
})

describe('kubectl top, whose absence is normal', () => {
  it('says there is no metrics-server rather than showing an idle cluster', () => {
    // The real message on a cluster with no Metrics API. Rendered as an empty
    // table it reads as "nothing is using anything".
    const u = parseK8sUsage(
      block({ TOPPODS: 'error: Metrics API not available', TOPNODES: 'error: Metrics API not available' }),
      1
    )
    expect(u.pods.ok).toBe(false)
    expect(!u.pods.ok && u.pods.reason).toBe('no-metrics')
    expect(K8S_FAILURE_HELP['no-metrics']).toMatch(/no source to ask/)
  })

  it('recognises the older heapster wording too', () => {
    const u = parseK8sUsage(
      block({
        TOPNODES:
          'Error from server (NotFound): the server could not find the requested resource (get services http:heapster:)'
      }),
      1
    )
    expect(!u.nodes.ok && u.nodes.reason).toBe('no-metrics')
  })

  it('does not call an RBAC denial on the metrics API a missing metrics-server', () => {
    // Both mention metrics. One means "install a component", the other means
    // "ask for a role" — sending someone to install something already running
    // is the exact failure this module is shaped to avoid.
    const u = parseK8sUsage(
      block({
        TOPNODES:
          'Error from server (Forbidden): nodes.metrics.k8s.io is forbidden: User "dev" cannot list resource "nodes" in API group "metrics.k8s.io" at the cluster scope'
      }),
      1
    )
    expect(!u.nodes.ok && u.nodes.reason).toBe('forbidden')
  })

  it('parses real top output for pods and nodes', () => {
    const u = parseK8sUsage(
      block({
        TOPPODS: [
          'default       web-7d9f-x2k41   12m   148Mi',
          'kube-system   coredns-abc      4m    18Mi'
        ].join('\n'),
        TOPNODES: 'node-1   241m   6%    2317Mi   29%'
      }),
      0
    )
    if (!u.pods.ok || !u.nodes.ok) throw new Error('should parse')
    expect(u.pods.items[0]).toEqual({
      namespace: 'default',
      name: 'web-7d9f-x2k41',
      cpu: '12m',
      memory: '148Mi'
    })
    expect(u.nodes.items[0]).toEqual({
      name: 'node-1',
      cpu: '241m',
      cpuPercent: '6%',
      memory: '2317Mi',
      memoryPercent: '29%'
    })
  })
})

describe('the one thing that changes the cluster', () => {
  it('never runs on a bare click', () => {
    // broadcast's rule 3: nothing is safe by omission. Every rollout restart
    // terminates every running pod of the workload, and the mistake anyone
    // actually makes is picking the wrong row.
    const p = planK8sRollout({
      kind: 'deployment',
      namespace: 'staging',
      name: 'web',
      desired: 3,
      strategy: 'RollingUpdate'
    })
    expect(p.confirmation.kind).toBe('confirm')
    expect(p.risk).toBe('elevated')
  })

  it('makes you type the word for a StatefulSet', () => {
    // Its pods restart one at a time, in order. That is how a database quorum
    // gets rolled when the wrong row was selected.
    const p = planK8sRollout({
      kind: 'statefulset',
      namespace: 'staging',
      name: 'postgres',
      desired: 3,
      strategy: 'RollingUpdate'
    })
    expect(p.confirmation).toEqual({ kind: 'type-to-confirm', phrase: 'RESTART' })
    expect(p.risk).toBe('destructive')
    expect(p.reasons.join(' ')).toMatch(/one at a time/)
  })

  it('makes you type the word for a Recreate deployment, which goes fully down', () => {
    const p = planK8sRollout({
      kind: 'deployment',
      namespace: 'staging',
      name: 'legacy',
      desired: 1,
      strategy: 'Recreate'
    })
    expect(p.confirmation.kind).toBe('type-to-confirm')
    expect(p.risk).toBe('destructive')
    expect(p.reasons.join(' ')).toMatch(/stops every pod before starting any/)
  })

  it('escalates on a namespace or context that reads as production', () => {
    const byNs = planK8sRollout({
      kind: 'deployment',
      namespace: 'prod',
      name: 'web',
      desired: 3,
      strategy: 'RollingUpdate'
    })
    expect(byNs.confirmation.kind).toBe('type-to-confirm')
    const byCtx = planK8sRollout({
      kind: 'deployment',
      namespace: 'apps',
      name: 'web',
      desired: 3,
      strategy: 'RollingUpdate',
      context: 'arn:aws:eks:eu-west-1:123:cluster/production'
    })
    expect(byCtx.confirmation.kind).toBe('type-to-confirm')
  })

  it('does not read "reproducible" or "products" as production', () => {
    // A guard that cries wolf is a guard people learn to click through.
    const p = planK8sRollout({
      kind: 'deployment',
      namespace: 'reproducible-builds',
      name: 'web',
      desired: 3,
      strategy: 'RollingUpdate'
    })
    expect(p.confirmation.kind).toBe('confirm')
  })

  it('escalates on one replica and on a big fleet, for opposite reasons', () => {
    const single = planK8sRollout({
      kind: 'deployment',
      namespace: 'apps',
      name: 'web',
      desired: 1,
      strategy: 'RollingUpdate'
    })
    expect(single.confirmation.kind).toBe('type-to-confirm')
    expect(single.reasons.join(' ')).toMatch(/ReadWriteOnce/)
    const many = planK8sRollout({
      kind: 'deployment',
      namespace: 'apps',
      name: 'web',
      desired: 24,
      strategy: 'RollingUpdate'
    })
    expect(many.confirmation.kind).toBe('type-to-confirm')
  })

  it('warns that an OnDelete workload will not actually restart', () => {
    // The restart is accepted, the template is marked, and no pod is replaced
    // until it is deleted by hand. An operator believing they restarted
    // something they did not is worse than a refusal.
    const p = planK8sRollout({
      kind: 'daemonset',
      namespace: 'kube-system',
      name: 'node-exporter',
      desired: 3,
      strategy: 'OnDelete'
    })
    expect(p.caveats.join(' ')).toMatch(/deleted by hand/)
  })

  it('says so when it could not read the strategy, instead of assuming', () => {
    const p = planK8sRollout({
      kind: 'deployment',
      namespace: 'apps',
      name: 'web',
      desired: 3,
      strategy: null
    })
    expect(p.caveats.join(' ')).toMatch(/not read/)
  })

  it('reads a successful restart without depending on kubectl\'s exact wording', () => {
    const r = parseK8sRolloutResult(
      block({
        RESTART: 'deployment.apps/web restarted',
        STATUS: 'Waiting for deployment "web" rollout to finish: 1 out of 3 new replicas have been updated...'
      }),
      0
    )
    expect(r.ok).toBe(true)
    expect(r.status).toMatch(/1 out of 3/)
  })

  it('reports a refused restart as forbidden, not as a successful no-op', () => {
    const r = parseK8sRolloutResult(
      block({
        RESTART:
          'Error from server (Forbidden): deployments.apps "web" is forbidden: User "dev" cannot patch resource "deployments" in API group "apps" in the namespace "prod"',
        STATUS: 'Error from server (Forbidden): deployments.apps "web" is forbidden'
      }),
      1
    )
    expect(r.ok).toBe(false)
    expect(r.reason).toBe('forbidden')
  })
})

describe('the new commands obey the same rules as the old ones', () => {
  const everyCall = (cmd: string): string[] =>
    cmd.split(';').filter((p) => /"\$SP_BIN"\s+\w/.test(p))

  it('bounds every call in every builder', () => {
    for (const cmd of [
      buildK8sDiagnoseCommand('default', 'web-1'),
      buildK8sOverviewCommand('prod-eks', 'default'),
      buildK8sTopCommand(),
      buildK8sRolloutRestartCommand('deployment', 'default', 'web')
    ]) {
      const calls = everyCall(cmd)
      expect(calls.length).toBeGreaterThan(0)
      for (const part of calls) expect(part, part).toMatch(/--request-timeout=/)
    }
  })

  it('resolves the binary in every builder, including logs', () => {
    // The pod list resolved kubectl in /usr/local/bin and worked; the log
    // button on one of those very pods called a bare `kubectl` and reported it
    // was not installed. A resolver used by only some callers is worse than
    // none, because the failure becomes inconsistent.
    for (const cmd of [
      buildK8sLogsCommand('default', 'web-1'),
      buildK8sDiagnoseCommand('default', 'web-1'),
      buildK8sOverviewCommand(),
      buildK8sTopCommand(),
      buildK8sRolloutRestartCommand('deployment', 'default', 'web')
    ]) {
      expect(cmd).toContain('/usr/local/bin/kubectl')
      expect(cmd).toContain('SP_BIN=kubectl')
    }
  })

  it('throws rather than escaping a name it cannot prove safe', () => {
    expect(() => buildK8sDiagnoseCommand('default', 'web; reboot')).toThrow(/refusing/)
    expect(() => buildK8sDiagnoseCommand('ns; id', 'web')).toThrow(/refusing/)
    expect(() => buildK8sRolloutRestartCommand('deployment', 'default', 'web; rm -rf /')).toThrow(
      /refusing/
    )
    expect(() => buildK8sRolloutRestartCommand('deployment', 'ns; id', 'web')).toThrow(/refusing/)
    // The kind is an allowlist, not free text: `rollout restart` accepts
    // resource types this module has not thought about.
    expect(() =>
      buildK8sRolloutRestartCommand('pod' as 'deployment', 'default', 'web')
    ).toThrow(/refusing/)
  })

  it('still never switches the context persistently', () => {
    for (const cmd of [
      buildK8sDiagnoseCommand('default', 'web-1', 'prod-eks'),
      buildK8sOverviewCommand('prod-eks'),
      buildK8sTopCommand('prod-eks'),
      buildK8sRolloutRestartCommand('deployment', 'default', 'web', 'prod-eks')
    ]) {
      expect(cmd).toMatch(/--context=prod-eks/)
      expect(cmd).not.toMatch(/use-context/)
    }
  })

  it('never deletes, execs, applies, scales, drains or cordons', () => {
    // The refusals the module header names, pinned so a later addition has to
    // argue with a test rather than slip past a review.
    for (const cmd of [
      buildK8sDiagnoseCommand('default', 'web-1'),
      buildK8sOverviewCommand(),
      buildK8sTopCommand(),
      buildK8sRolloutRestartCommand('statefulset', 'prod', 'postgres')
    ]) {
      expect(cmd).not.toMatch(/\b(delete|exec|apply|scale|drain|cordon|uncordon|edit)\b/)
    }
  })

  it('reads the previous container only when asked', () => {
    expect(buildK8sLogsCommand('default', 'web-1')).not.toMatch(/--previous/)
    expect(buildK8sLogsCommand('default', 'web-1', 200, undefined, { previous: true })).toMatch(
      /--previous/
    )
    // The diagnose round trip always wants it: that is the whole point of it.
    expect(buildK8sDiagnoseCommand('default', 'web-1')).toMatch(/--previous/)
  })

  it('scopes the pod events to that pod, not the whole namespace', () => {
    // Unfiltered, a busy namespace buries the pod you are looking at.
    const cmd = buildK8sDiagnoseCommand('default', 'web-7d9f-x2k41')
    expect(cmd).toMatch(/--field-selector=involvedObject\.name=web-7d9f-x2k41/)
  })

  it('does not let rollout status block until the rollout finishes', () => {
    // Without --watch=false kubectl waits for completion, which on a stuck
    // image pull is forever: it holds the exec open past every timeout and
    // leaves the user unable to tell whether the restart even started.
    expect(buildK8sRolloutRestartCommand('deployment', 'default', 'web')).toMatch(/--watch=false/)
  })

  it('does not ask a namespace-scoped flag of a cluster-scoped resource', () => {
    // `kubectl get nodes --namespace=x` is a lie about what is being read.
    const nodesCall = buildK8sOverviewCommand(undefined, 'default')
      .split(';')
      .find((p) => /get nodes/.test(p))
    expect(nodesCall).toBeDefined()
    expect(nodesCall).not.toMatch(/--namespace/)
    expect(nodesCall).not.toMatch(/--all-namespaces/)
  })

  it('still does not try sudo, because sudo cannot fix RBAC', () => {
    for (const cmd of [
      buildK8sDiagnoseCommand('default', 'web-1'),
      buildK8sOverviewCommand(),
      buildK8sTopCommand(),
      buildK8sRolloutRestartCommand('deployment', 'default', 'web')
    ]) {
      expect(cmd).not.toMatch(/sudo/)
    }
  })
})

describe('an events list is read as a timeline', () => {
  it('says how long ago, not when', () => {
    const now = Date.parse('2026-09-01T12:00:00Z')
    expect(k8sRelativeTime('2026-09-01T11:59:30Z', now)).toBe('30s')
    expect(k8sRelativeTime('2026-09-01T11:58:00Z', now)).toBe('2m')
    expect(k8sRelativeTime('2026-09-01T09:00:00Z', now)).toBe('3h')
    expect(k8sRelativeTime('2026-08-20T12:00:00Z', now)).toBe('12d')
  })

  it('clamps a node whose clock is ahead of ours', () => {
    // Negative time reads as a parsing bug rather than as clock skew.
    const now = Date.parse('2026-09-01T12:00:00Z')
    expect(k8sRelativeTime('2026-09-01T12:05:00Z', now)).toBe('0s')
  })

  it('returns nothing for a timestamp kubectl did not have', () => {
    expect(k8sRelativeTime('')).toBe('')
    expect(k8sRelativeTime('<none>')).toBe('')
  })
})

describe('an empty answer is not a denied one, for every resource', () => {
  // The contract the panel depends on. Getting it wrong in either direction is
  // a lie: "denied" shown as empty hides a permissions problem, and empty shown
  // as denied invents one.
  const EMPTY = 'No resources found in default namespace.'

  it('reads an empty result as success everywhere', () => {
    const o = parseK8sOverview(
      block({ DEPLOY: EMPTY, STS: EMPTY, DS: EMPTY, NODES: EMPTY, EVENTS: EMPTY }),
      0
    )
    for (const r of [o.deployments, o.statefulSets, o.daemonSets, o.nodes, o.events]) {
      expect(r).toEqual({ ok: true, items: [] })
    }
    const u = parseK8sUsage(block({ TOPPODS: EMPTY, TOPNODES: EMPTY }), 0)
    expect(u.pods).toEqual({ ok: true, items: [] })
    expect(u.nodes).toEqual({ ok: true, items: [] })
  })
})

// Found by running the real command against a real k3s cluster with a
// deliberately crashlooping pod in it. No fixture caught this because every
// fixture encoded my own guess at kubectl's output.
describe('status is what kubectl shows, not the pod phase', () => {
  it('reports CrashLoopBackOff rather than Running', () => {
    // `.status.phase` for a crashlooping pod is literally `Running` — the POD
    // is running, the container inside keeps dying. Reporting the phase showed
    // a pod with five restarts as healthy, which is the one word that makes an
    // operator stop looking. Verified against a real cluster: kubectl said
    // `Error`, we said `Running`.
    const r = parseK8sOutput(
      out({ all: podRow({ name: 'boom', ready: 'false', phase: 'Running', term: 'Error', restarts: '5' }) }),
      0
    )
    expect(r.ok && r.pods[0].status).toBe('Error')
  })

  it('prefers a waiting reason over a terminated one', () => {
    // ImagePullBackOff is a waiting reason and it is what kubectl shows.
    const r = parseK8sOutput(
      out({ all: podRow({ name: 'pull', ready: 'false', phase: 'Pending', wait: 'ImagePullBackOff' }) }),
      0
    )
    expect(r.ok && r.pods[0].status).toBe('ImagePullBackOff')
  })

  it('falls back to the phase when no container has a reason', () => {
    const r = parseK8sOutput(out({ all: podRow({ name: 'fine' }) }), 0)
    expect(r.ok && r.pods[0].status).toBe('Running')
  })

  it('takes the first real reason in a multi-container pod', () => {
    // custom-columns joins per container. One healthy container must not hide
    // the one that is failing.
    const r = parseK8sOutput(
      out({ all: podRow({ name: 'multi', ready: 'true,false', want: 'a,b', wait: '<none>,CrashLoopBackOff' }) }),
      0
    )
    expect(r.ok && r.pods[0].status).toBe('CrashLoopBackOff')
  })

  it('counts containers from the spec when the pod never scheduled', () => {
    // A Pending pod has no containerStatuses at all, so counting those gave
    // 0/0 where kubectl says 0/1 — it falls back to the spec, and so do we.
    const r = parseK8sOutput(
      out({ all: podRow({ name: 'pending', ready: '<none>', phase: 'Pending', want: 'only', node: '<none>' }) }),
      0
    )
    expect(r.ok && r.pods[0].ready).toBe('0/1')
  })
})
