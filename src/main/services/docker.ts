import type { DockerProbe } from '../../shared/docker'
import { DOCKER_LIST_COMMAND, parseDockerOutput } from '../../shared/docker'

// Reading docker on a remote host.
//
// Thin on purpose: the parsing and the failure classification are in
// shared/docker.ts where they can be tested without an SSH connection, and this
// is only the round trip.

export type DockerExec = (
  cfg: unknown,
  command: string,
  timeoutMs: number
) => Promise<{ ok: boolean; code?: number | null; stdout?: string; stderr?: string; error?: string }>

export interface DockerDeps {
  exec: DockerExec
}

export class DockerReader {
  constructor(private readonly deps: DockerDeps) {}

  async list(cfg: unknown): Promise<DockerProbe> {
    try {
      const r = await this.deps.exec(cfg, DOCKER_LIST_COMMAND, 20_000)
      if (!r.ok) {
        // A transport failure is not a docker failure, and saying "docker is
        // not installed" when the host was simply unreachable sends someone to
        // fix the wrong machine.
        return { ok: false, reason: 'unknown', detail: r.error ?? 'could not reach the host' }
      }
      return parseDockerOutput(`${r.stdout ?? ''}${r.stderr ?? ''}`, r.code ?? null)
    } catch (e) {
      return { ok: false, reason: 'unknown', detail: e instanceof Error ? e.message : String(e) }
    }
  }
}
