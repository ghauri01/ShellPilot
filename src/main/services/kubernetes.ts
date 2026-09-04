import type {
  K8sCordonResult,
  K8sCordonTarget,
  K8sDrainAssessment,
  K8sDrainPlan,
  K8sDrainResult,
  K8sExecResult,
  K8sExecTarget,
  K8sDiagnosis,
  K8sOverview,
  K8sProbe,
  K8sRolloutResult,
  K8sRolloutTarget,
  K8sSchedulingAction,
  K8sUsage,
  K8sWorkloadKind
} from '../../shared/kubernetes'
import {
  buildK8sCordonCommand,
  buildK8sDiagnoseCommand,
  buildK8sDrainCommand,
  buildK8sDrainPreflightCommand,
  buildK8sExecCommand,
  buildK8sOverviewCommand,
  buildK8sReadCommand,
  buildK8sRolloutRestartCommand,
  buildK8sTopCommand,
  parseK8sCordonResult,
  parseK8sDiagnosis,
  assessK8sDrain,
  parseK8sDrainPreflight,
  parseK8sDrainResult,
  parseK8sExecResult,
  parseK8sOutput,
  parseK8sOverview,
  parseK8sRolloutResult,
  parseK8sUsage,
  planK8sCordon,
  planK8sDrain,
  planK8sExec,
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

import { verifyApproval } from '../../shared/broadcast'

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

  /**
   * Cordon or uncordon one node.
   *
   * Shaped exactly like `rolloutRestart` and for the same reasons: `confirmed`
   * must be literally true, the builder throws on a name it cannot prove safe,
   * and the plan is re-derived here rather than trusted across IPC.
   *
   * A TRANSPORT FAILURE IS AN UNKNOWN STATE, not a failed cordon — the same
   * reading as the restart. `cordon` is a one-field patch and it may well have
   * reached the API server before the SSH connection died. Saying "the node
   * was not cordoned" would be a guess, and the wrong guess sends someone to
   * click again on a node that is already frozen, or worse, to start a reboot
   * believing the freeze did not take.
   */
  async cordon(
    cfg: unknown,
    target: K8sCordonTarget,
    confirmed: boolean
  ): Promise<K8sCordonResult> {
    const action = target.action as K8sSchedulingAction
    const fail = (detail: string, reason: K8sCordonResult['reason'] = 'unknown'): K8sCordonResult => ({
      ok: false,
      action,
      node: target.node,
      alreadyInState: false,
      output: '',
      node_status: '',
      reason,
      detail
    })
    if (confirmed !== true) {
      return fail(`refusing to ${action} a node without an explicit confirmation`)
    }
    try {
      const cmd = buildK8sCordonCommand(target.node, action, target.context ?? undefined)
      // 20s: two kubectl calls, each already bounded at 10s by
      // --request-timeout, plus the SSH round trip. Neither waits on anything
      // in the cluster — a cordon is a patch and the node read is a get.
      const r = await this.deps.exec(cfg, cmd, 20_000)
      if (!r.ok) {
        return fail(
          `${r.error ?? 'could not reach the host'} — the ${action} may or may not have been applied; re-read the node before retrying`
        )
      }
      return parseK8sCordonResult(action, target.node, merge(r), r.code ?? null)
    } catch (e) {
      return fail(e instanceof Error ? e.message : String(e))
    }
  }

  /**
   * Read everything the drain decision is made from.
   *
   * Exposed on its own so the panel can show the verdict BEFORE anyone reaches
   * for a confirm dialog. It is a preview and nothing more — `drain` below
   * takes this read again for itself, because endpoint readiness is only true
   * of the instant it was read and the instant that matters is the one
   * immediately before the command runs.
   */
  async drainPreflight(cfg: unknown, node: string, context?: string): Promise<K8sDrainAssessment> {
    const fail = (detail: string): K8sDrainAssessment => {
      const f = { ok: false, reason: 'unknown', detail } as const
      // A transport failure makes every one of the four reads unknown, which is
      // exactly what it is. Reporting it as "no PodDisruptionBudgets" would be
      // the lie this module exists to refuse, arriving by a different route.
      return assessK8sDrain(node, { nodeState: f, pods: f, pdbs: f, endpoints: f })
    }
    try {
      const cmd = buildK8sDrainPreflightCommand(node, context)
      // 45s: four kubectl calls at up to 10s each plus the SSH round trip. Same
      // reasoning as the overview — a per-call bound that adds up past the
      // exec's own timeout means the transport gives up first and the user sees
      // a timeout instead of the three blocks that did answer.
      const r = await this.deps.exec(cfg, cmd, 45_000)
      if (!r.ok) return fail(r.error ?? 'could not reach the host')
      return parseK8sDrainPreflight(node, merge(r), r.code ?? null)
    } catch (e) {
      return fail(e instanceof Error ? e.message : String(e))
    }
  }

  /**
   * Drain a node, or refuse to.
   *
   * THE PREFLIGHT IS TAKEN HERE, not accepted from the caller, and that is the
   * whole security and correctness story of this method. An assessment that
   * crossed IPC is a structured-clone value with no runtime type; a caller that
   * sent `{safe:true, blockers:[]}` would be granting itself permission to
   * drain. It is also stale by construction — the renderer computed it when the
   * dialog opened and the user has been reading it since.
   *
   * A REFUSAL IS NOT A SCARIER DIALOG. When the preflight says no, no drain
   * command is built at all and the reasons come back as text. There is no
   * override flag on this method, and `--force` / `--delete-emptydir-data` are
   * not passed anywhere in this module — both of those turn a blocked drain
   * into a successful one by destroying whatever blocked it.
   */
  async drain(
    cfg: unknown,
    node: string,
    context: string | undefined,
    confirmed: boolean
  ): Promise<K8sDrainResult & { plan?: K8sDrainPlan }> {
    const fail = (detail: string, plan?: K8sDrainPlan): K8sDrainResult & { plan?: K8sDrainPlan } => ({
      ok: false,
      node,
      evicted: [],
      pending: [],
      pdbRejected: [],
      partial: false,
      output: '',
      node_status: '',
      reason: 'unknown',
      detail,
      ...(plan === undefined ? {} : { plan })
    })
    if (confirmed !== true) {
      return fail('refusing to drain a node without an explicit confirmation')
    }
    try {
      const assessment = await this.drainPreflight(cfg, node, context)
      const plan = planK8sDrain(assessment)
      if (plan.refusals.length > 0) {
        return fail(
          `refusing to drain ${node}: ${plan.refusals.join(' — ')}`,
          plan
        )
      }
      // 150s against the drain's own 120s --timeout. The transport must outlast
      // kubectl, or a drain that stalls on a budget is reported as a host that
      // went away — and the operator is then told the node is untouched when it
      // has been cordoned and half emptied.
      const r = await this.deps.exec(cfg, buildK8sDrainCommand(node, context), 150_000)
      if (!r.ok) {
        return fail(
          `${r.error ?? 'could not reach the host'} — the drain was sent and its outcome is unknown; the node has been cordoned and some pods may already have moved. Re-read the node before retrying.`,
          plan
        )
      }
      return { ...parseK8sDrainResult(node, merge(r), r.code ?? null), plan }
    } catch (e) {
      return fail(e instanceof Error ? e.message : String(e))
    }
  }

  /**
   * Run one command inside a container, against a written-down approval.
   *
   * The approval is not a boolean and this method does not take one. It takes
   * the RECORD a human's answer produced, and it checks three things against a
   * fresh re-derivation before anything runs:
   *
   *  - the command text is the one that was approved, byte for byte. The
   *    record carries it, so an exec edited between the dialog and the run is
   *    a comparison rather than an act of faith. This is the check a `confirmed
   *    === true` flag cannot make at all: the flag says a dialog was answered,
   *    not what it said.
   *  - the host is one that was in the confirmed target list.
   *  - the confirmation demanded now is the confirmation that was answered. A
   *    build that later decides exec needs more than it did will not honour an
   *    approval minted under the weaker rule.
   *
   * `verifyApproval` is shared/broadcast.ts's, unmodified. Re-implementing the
   * comparison here would be a second verifier that can drift from the first,
   * which is the failure the single-record design exists to prevent.
   */
  async exec(cfg: unknown, target: K8sExecTarget, approval: unknown): Promise<K8sExecResult> {
    try {
      // Built BEFORE the check, because the built command is what the check is
      // about. Verifying a target object and then building from it separately
      // would leave a gap between what was agreed and what runs.
      const command = buildK8sExecCommand(target)
      const plan = planK8sExec(target)
      const verdict = verifyApproval(
        approval,
        {
          commands: [command],
          targets: [{ serverId: target.serverId, serverName: target.serverName }]
        },
        { risk: plan.risk, confirmation: plan.confirmation }
      )
      if (!verdict.ok) {
        return { ok: false, output: '', containerExit: null, reason: 'unknown', detail: verdict.reason }
      }
      // 60s. An exec runs somebody else's program and there is no sensible
      // upper bound on it, so this is a deliberate ceiling rather than a
      // measurement: past a minute the answer is "use a job", and a command
      // that waits on stdin would otherwise hold the transport open forever.
      const r = await this.deps.exec(cfg, command, 60_000)
      if (!r.ok) {
        return {
          ok: false,
          output: '',
          containerExit: null,
          reason: 'unknown',
          // The same reading as the restart and the drain. A transport failure
          // leaves the exec in an UNKNOWN state: it may well have reached the
          // host and run, and telling somebody it did not is how a command that
          // is not idempotent gets run twice.
          detail: `${r.error ?? 'could not reach the host'} — the command may or may not have run inside the container`
        }
      }
      return parseK8sExecResult(merge(r), r.code ?? null)
    } catch (e) {
      return {
        ok: false,
        output: '',
        containerExit: null,
        reason: 'unknown',
        detail: e instanceof Error ? e.message : String(e)
      }
    }
  }

  /** Exposed so the main process can log what was approved, in its own words. */
  plan(target: K8sRolloutTarget): ReturnType<typeof planK8sRollout> {
    return planK8sRollout(target)
  }

  /** The same, for a scheduling change. */
  cordonPlan(target: K8sCordonTarget): ReturnType<typeof planK8sCordon> {
    return planK8sCordon(target)
  }

  /**
   * The same, for an exec — and the renderer needs BOTH halves of this.
   *
   * The plan is what the dialog is built from, and `buildK8sExecCommand` is
   * what the approval must record: an approval minted against anything other
   * than the exact command string this service will rebuild is one
   * `verifyApproval` refuses. Exposing the pair together is what keeps those
   * from drifting apart.
   */
  execPlan(target: K8sExecTarget): {
    plan: ReturnType<typeof planK8sExec>
    command: string
  } {
    return { plan: planK8sExec(target), command: buildK8sExecCommand(target) }
  }
}
