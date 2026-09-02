import type { K8sProbe } from '../../shared/kubernetes'
import { buildK8sReadCommand, parseK8sOutput } from '../../shared/kubernetes'

// Reading Kubernetes on a remote host.
//
// Thin, like DockerReader: the parsing and the RBAC failure classification live
// in shared/kubernetes.ts where they can be tested without a cluster, and this
// is only the round trip.

export type K8sExec = (
  cfg: unknown,
  command: string,
  timeoutMs: number
) => Promise<{ ok: boolean; code?: number | null; stdout?: string; stderr?: string; error?: string }>

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
}
