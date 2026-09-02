import type { DockerProbe } from '../../shared/docker'
import { SUDO_PROBE, buildDockerListCommand, parseDockerOutput } from '../../shared/docker'

// Reading docker on a remote host.
//
// Thin on purpose: the parsing and the failure classification are in
// shared/docker.ts where they can be tested without an SSH connection, and this
// is only the round trip — plus the one decision that needs two of them.

export type DockerExec = (
  cfg: unknown,
  command: string,
  timeoutMs: number
) => Promise<{ ok: boolean; code?: number | null; stdout?: string; stderr?: string; error?: string }>

export interface DockerDeps {
  exec: DockerExec
}

export interface DockerListOptions {
  /**
   * Skip the unprivileged attempt and read as root immediately.
   *
   * Set by the panel's toggle, for the very common case of an operator who
   * knows this account is not in the docker group and does not want to pay a
   * failed round trip every refresh.
   */
  sudo?: boolean
  /**
   * Retry as root when the unprivileged read is refused. On by default.
   *
   * Safe to have on because the retry uses `sudo -n`, which NEVER prompts: it
   * either works, because this account already has passwordless sudo — a
   * decision the user made on that host, not one we are making for them — or it
   * fails immediately. It cannot hang an exec waiting for a tty that is not
   * there, and it cannot consume a cached sudo timestamp interactively.
   *
   * The result says when root was used. Escalating silently would be the wrong
   * trade even when it is the only way to get an answer.
   */
  autoSudo?: boolean
}

export class DockerReader {
  constructor(private readonly deps: DockerDeps) {}

  private async run(cfg: unknown, sudo: boolean): Promise<DockerProbe> {
    const r = await this.deps.exec(cfg, buildDockerListCommand({ sudo }), 20_000)
    if (!r.ok) {
      // A transport failure is not a docker failure, and saying "docker is
      // not installed" when the host was simply unreachable sends someone to
      // fix the wrong machine.
      return { ok: false, reason: 'unknown', detail: r.error ?? 'could not reach the host' }
    }
    // Both streams, joined on a newline rather than glued. The collector
    // redirects docker's own stderr into stdout, so anything left on stderr
    // came from the shell or the transport — and concatenating it directly
    // welded it onto the last `docker ps` row, turning a real container into
    // a row the parser could not read.
    const stdout = r.stdout ?? ''
    const stderr = r.stderr ?? ''
    const merged = stderr === '' ? stdout : `${stdout}\n${stderr}`
    return parseDockerOutput(merged, r.code ?? null)
  }

  /** Whether this account can become root without being asked for a password. */
  async canSudo(cfg: unknown): Promise<boolean> {
    try {
      const r = await this.deps.exec(cfg, SUDO_PROBE, 10_000)
      return (r.stdout ?? '').includes('SP_SUDO_OK')
    } catch {
      return false
    }
  }

  async list(cfg: unknown, opts: DockerListOptions = {}): Promise<DockerProbe> {
    try {
      if (opts.sudo) {
        const forced = await this.run(cfg, true)
        return forced.ok ? { ...forced, usedSudo: true } : forced
      }

      const first = await this.run(cfg, false)
      // Only a socket-permission refusal is worth retrying. A missing binary,
      // a dead daemon or an unclassifiable error are not things root fixes,
      // and retrying them would just double the wait before the same answer.
      if (first.ok || first.reason !== 'permission-denied' || opts.autoSudo === false) return first

      if (!(await this.canSudo(cfg))) return first
      const elevated = await this.run(cfg, true)
      // If root does not help either, report the ORIGINAL failure: it is the
      // one that describes the user's actual situation, and a second error
      // about sudo would send them somewhere unrelated.
      return elevated.ok ? { ...elevated, usedSudo: true } : first
    } catch (e) {
      return { ok: false, reason: 'unknown', detail: e instanceof Error ? e.message : String(e) }
    }
  }
}
