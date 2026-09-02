import type {
  K8sDiagnosis,
  K8sOverview,
  K8sProbe,
  K8sRolloutResult,
  K8sRolloutTarget,
  K8sUsage,
  K8sWorkloadKind
} from '../../shared/kubernetes'
import {
  buildK8sDiagnoseCommand,
  buildK8sOverviewCommand,
  buildK8sReadCommand,
  buildK8sRolloutRestartCommand,
  buildK8sTopCommand,
  parseK8sDiagnosis,
  parseK8sOutput,
  parseK8sOverview,
  parseK8sRolloutResult,
  parseK8sUsage,
  planK8sRollout
} from '../../shared/kubernetes'

// Reading Kubernetes on a remote host, and the one thing that writes.
//
// Thin, like DockerReader: the parsing and the RBAC failure classification live
// in shared/kubernetes.ts where they can be tested without a cluster, and this
// is only the round trip.
//
// There is deliberately no sudo path anywhere in here, unlike DockerReader.
// Docker's "permission denied" is a unix group problem and root fixes it;
// Kubernetes `forbidden` is cluster RBAC about the identity in the kubeconfig,
// so `sudo kubectl` escalates nothing and reads ROOT's kubeconfig — which
// usually does not exist, turning a precise "your token cannot list events"
// into a vague "no configuration has been provided". See
// K8S_SUDO_DOES_NOT_HELP.

export type K8sExec = (
  cfg: unknown,
  command: string,
  timeoutMs: number
) => Promise<{ ok: boolean; code?: number | null; stdout?: string; stderr?: string; error?: string }>

/** Both streams. kubectl's own stderr is redirected into stdout by the builders,
 * so anything left on stderr came from the shell or the transport — joined on a
 * newline rather than glued, because concatenating it directly welds it onto
 * the last data row and turns a real one into a row the parser cannot read. */
const merge = (r: { stdout?: string; stderr?: string }): string => {
  const stdout = r.stdout ?? ''
  const stderr = r.stderr ?? ''
  return stderr === '' ? stdout : `${stdout}\n${stderr}`
}

export class KubernetesReader {
  constructor(private readonly deps: { exec: K8sExec }) {}

  async read(cfg: unknown, context?: string, namespace?: string): Promise<K8sProbe> {
    try {
      // 30s: four kubectl calls, each already bounded at 10s by
      // --request-timeout, plus the SSH round trip.
      const r = await this.deps.exec(cfg, buildK8sReadCommand(context, namespace), 30_000)
      if (!r.ok) {
        // A transport failure is not a cluster failure. Saying "kubectl is not
        // installed" when the HOST was unreachable sends someone to fix the
        // wrong machine entirely.
        return { ok: false, reason: 'unknown', detail: r.error ?? 'could not reach the host' }
      }
      return parseK8sOutput(`${r.stdout ?? ''}${r.stderr ?? ''}`, r.code ?? null)
    } catch (e) {
      return { ok: false, reason: 'unknown', detail: e instanceof Error ? e.message : String(e) }
    }
  }

  /**
   * Why a pod is unhealthy: describe, its events, and the previous container's
   * logs.
   *
   * A transport failure fails all three blocks the same way rather than being
   * reported as three separate cluster problems — the host was unreachable, and
   * saying "this account cannot list events" would be inventing an RBAC
   * problem out of a network one.
   */
  async diagnose(
    cfg: unknown,
    namespace: string,
    pod: string,
    context?: string,
    previousLines = 200
  ): Promise<K8sDiagnosis> {
    const fail = (detail: string): K8sDiagnosis => ({
      namespace,
      pod,
      describe: { ok: false, reason: 'unknown', detail },
      events: { ok: false, reason: 'unknown', detail },
      previousLogs: { ok: false, reason: 'unknown', detail }
    })
    try {
      // buildK8sDiagnoseCommand throws on a name it cannot prove safe rather
      // than escaping it; that surfaces here as a sentence rather than as a
      // rejected invoke with no explanation.
      const cmd = buildK8sDiagnoseCommand(namespace, pod, context, previousLines)
      const r = await this.deps.exec(cfg, cmd, 30_000)
      if (!r.ok) return fail(r.error ?? 'could not reach the host')
      return parseK8sDiagnosis(namespace, pod, merge(r), r.code ?? null)
    } catch (e) {
      return fail(e instanceof Error ? e.message : String(e))
    }
  }

  /** Workloads, nodes and recent events. */
  async overview(cfg: unknown, context?: string, namespace?: string): Promise<K8sOverview> {
    const fail = (detail: string): K8sOverview => {
      const f = { ok: false, reason: 'unknown', detail } as const
      return { deployments: f, statefulSets: f, daemonSets: f, nodes: f, events: f }
    }
    try {
      // 45s rather than the read's 30s: five kubectl calls at up to 10s each,
      // and a per-call bound that adds up to more than the exec's own timeout
      // would mean the transport gives up first and the user sees a timeout
      // instead of the four blocks that did answer.
      const r = await this.deps.exec(cfg, buildK8sOverviewCommand(context, namespace), 45_000)
      if (!r.ok) return fail(r.error ?? 'could not reach the host')
      return parseK8sOverview(merge(r), r.code ?? null)
    } catch (e) {
      return fail(e instanceof Error ? e.message : String(e))
    }
  }

  /** `kubectl top`, which most clusters cannot answer. */
  async usage(cfg: unknown, context?: string, namespace?: string): Promise<K8sUsage> {
    const fail = (detail: string): K8sUsage => {
      const f = { ok: false, reason: 'unknown', detail } as const
      return { pods: f, nodes: f }
    }
    try {
      const r = await this.deps.exec(cfg, buildK8sTopCommand(context, namespace), 25_000)
      if (!r.ok) return fail(r.error ?? 'could not reach the host')
      return parseK8sUsage(merge(r), r.code ?? null)
    } catch (e) {
      return fail(e instanceof Error ? e.message : String(e))
    }
  }

  /**
   * The one call that changes the cluster.
   *
   * The confirmation happens in the renderer, before this is reached, and this
   * method re-derives the plan rather than trusting one that crossed IPC: a
   * plan is a structured-clone value with no runtime type, and a caller that
   * sent `{confirmation:{kind:'none'}}` would otherwise be deciding its own
   * approval. What the main process CAN check is that the request is one this
   * module is willing to make at all — a known kind, valid names — and
   * buildK8sRolloutRestartCommand throws on anything else.
   *
   * `confirmed` is required and must be true. It is not the security boundary
   * (nothing on this side of IPC can be), it is a guard against a caller that
   * reached the channel without going through a dialog at all — which, since
   * this is the only state-changing channel in the module, is worth failing
   * loudly rather than quietly running.
   */
  async rolloutRestart(
    cfg: unknown,
    target: K8sRolloutTarget,
    confirmed: boolean
  ): Promise<K8sRolloutResult> {
    if (confirmed !== true) {
      return {
        ok: false,
        output: '',
        status: '',
        reason: 'unknown',
        detail: 'refusing to restart a workload without an explicit confirmation'
      }
    }
    try {
      const cmd = buildK8sRolloutRestartCommand(
        target.kind as K8sWorkloadKind,
        target.namespace,
        target.name,
        target.context ?? undefined
      )
      // 30s: the restart itself returns immediately — it is a patch — and the
      // one-shot `rollout status` does not wait. Anything longer here would be
      // waiting on the API server, not on the rollout.
      const r = await this.deps.exec(cfg, cmd, 30_000)
      if (!r.ok) {
        return {
          ok: false,
          output: '',
          status: '',
          reason: 'unknown',
          // A transport failure leaves the restart in an UNKNOWN state rather
          // than a failed one: the command may well have reached the host and
          // run. Saying "it did not restart" would be a guess, and the wrong
          // guess makes someone click again.
          detail: `${r.error ?? 'could not reach the host'} — the restart may or may not have been sent; re-read the workload before retrying`
        }
      }
      return parseK8sRolloutResult(merge(r), r.code ?? null)
    } catch (e) {
      return {
        ok: false,
        output: '',
        status: '',
        reason: 'unknown',
        detail: e instanceof Error ? e.message : String(e)
      }
    }
  }

  /** Exposed so the main process can log what was approved, in its own words. */
  plan(target: K8sRolloutTarget): ReturnType<typeof planK8sRollout> {
    return planK8sRollout(target)
  }
}
