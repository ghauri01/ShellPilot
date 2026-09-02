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
      'default     web-7d9f          true,true    Running   0,0   node-1   2026-09-01T10:00:00Z',
      'kube-system coredns-abc       true         Running   3     node-2   2026-08-20T09:00:00Z',
      'app         worker-1          true,false   Running   0,12  node-1   2026-09-01T11:00:00Z'
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
        nsPods: 'default  web-1  true  Running  0  node-1  2026-09-01T10:00:00Z'
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
      'default  web-1  true  Running  0  node-1  2026-09-01T10:00:00Z',
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
          'error-reporting    forbidden-checker   true  Running  0  node-1  2026-09-01T10:00:00Z',
          'unauthorized-probe timeout-watchdog    true  Running  0  node-2  2026-09-01T10:00:00Z'
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
