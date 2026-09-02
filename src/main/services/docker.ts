import type {
  DockerAction,
  DockerActionResult,
  DockerDiskProbe,
  DockerFailure,
  DockerInspectProbe,
  DockerProbe,
  DockerStatsProbe
} from '../../shared/docker'
import {
  SUDO_PROBE,
  buildDockerActionCommand,
  buildDockerDiskCommand,
  buildDockerInspectCommand,
  buildDockerListCommand,
  buildDockerStatsCommand,
  parseDockerActionOutput,
  parseDockerDiskOutput,
  parseDockerInspectOutput,
  parseDockerOutput,
  parseDockerStatsOutput
} from '../../shared/docker'

// Reading docker on a remote host, and the three lifecycle verbs.
//
// Thin on purpose: the parsing, the command building and the failure
// classification are in shared/docker.ts where they can be tested without an
// SSH connection. What lives here is the round trip — plus the one decision
// that needs two of them, and the one place that decision does NOT apply.
//
// THE SUDO DISCIPLINE, in one place because it is the thing most likely to be
// got wrong by the next person adding a method:
//
//  * `sudo -n` never prompts. That is the entire reason any of this is safe to
//    do automatically: it either works, because the user already configured
//    passwordless sudo on that host, or it fails immediately. It cannot hang an
//    exec waiting for a tty that is not there and it cannot interactively
//    consume a cached sudo timestamp.
//  * The retry only happens for `permission-denied`. Root does not install
//    docker and does not start a dead daemon; retrying those just doubles the
//    wait before the same answer.
//  * If root does not help either, the ORIGINAL failure is reported. A second
//    error about sudo describes our workaround, not the user's problem.
//  * When root WAS used, the result says so. Escalating silently would be the
//    wrong trade even when it is the only way to get an answer.
//  * READS auto-escalate. STATE CHANGES DO NOT — see `act`.

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

export interface DockerActionOptions {
  /**
   * Run the action as root.
   *
   * Never inferred, unlike a read. See `act`.
   */
  sudo?: boolean
  /** `docker stop -t` — the grace period before SIGKILL. docker's own default when unset. */
  timeoutSec?: number
}

/**
 * The shape the failover needs from any probe: whether it worked, and if not,
 * which failure it was.
 *
 * Every parser in shared/docker.ts returns a union that satisfies this, which
 * is what lets one failover implementation serve all of them instead of four
 * near-copies drifting apart.
 */
interface Probe {
  ok: boolean
  reason?: DockerFailure
  usedSudo?: boolean
}

/** `docker system df` walks every image and volume; a big host is slow rather than broken. */
const DF_TIMEOUT_MS = 60_000
const READ_TIMEOUT_MS = 20_000
const STATS_TIMEOUT_MS = 30_000

/**
 * `docker stop` waits for the container to go down before it gives up, so the
 * budget has to grow with the target count — but not without limit, or a
 * wedged daemon holds an exec channel open all afternoon.
 */
function actionTimeoutMs(refs: number): number {
  return Math.min(120_000, 20_000 + refs * 15_000)
}

export class DockerReader {
  constructor(private readonly deps: DockerDeps) {}

  /** One round trip. Everything above this is policy; this is the wire. */
  private async attempt<R extends Probe>(
    cfg: unknown,
    command: string,
    parse: (output: string, code: number | null) => R,
    timeoutMs: number,
    onTransportFailure: (detail: string) => R
  ): Promise<R> {
    const r = await this.deps.exec(cfg, command, timeoutMs)
    if (!r.ok) {
      // A transport failure is not a docker failure, and saying "docker is
      // not installed" when the host was simply unreachable sends someone to
      // fix the wrong machine.
      return onTransportFailure(r.error ?? 'could not reach the host')
    }
    // Both streams, joined on a newline rather than glued. The collectors
    // redirect docker's own stderr into stdout, so anything left on stderr
    // came from the shell or the transport — and concatenating it directly
    // welded it onto the last row, turning a real container into a row the
    // parser could not read.
    const stdout = r.stdout ?? ''
    const stderr = r.stderr ?? ''
    const merged = stderr === '' ? stdout : `${stdout}\n${stderr}`
    return parse(merged, r.code ?? null)
  }

  /**
   * A read, with the sudo failover described in the header.
   *
   * Returns whether root was used rather than stamping the result itself: the
   * caller has the concrete type and can add `usedSudo` without a cast, and a
   * cast here would be a cast on every future probe shape.
   */
  private async readWithFailover<R extends Probe>(
    cfg: unknown,
    build: (sudo: boolean) => string,
    parse: (output: string, code: number | null) => R,
    onTransportFailure: (detail: string) => R,
    opts: DockerListOptions,
    timeoutMs: number
  ): Promise<{ result: R; usedSudo: boolean }> {
    const run = (sudo: boolean): Promise<R> =>
      this.attempt(cfg, build(sudo), parse, timeoutMs, onTransportFailure)

    if (opts.sudo) return { result: await run(true), usedSudo: true }

    const first = await run(false)
    // Only a socket-permission refusal is worth retrying. A missing binary,
    // a dead daemon or an unclassifiable error are not things root fixes,
    // and retrying them would just double the wait before the same answer.
    if (first.ok || first.reason !== 'permission-denied' || opts.autoSudo === false) {
      return { result: first, usedSudo: false }
    }
    if (!(await this.canSudo(cfg))) return { result: first, usedSudo: false }

    const elevated = await run(true)
    // If root does not help either, report the ORIGINAL failure: it is the
    // one that describes the user's actual situation, and a second error
    // about sudo would send them somewhere unrelated.
    return elevated.ok ? { result: elevated, usedSudo: true } : { result: first, usedSudo: false }
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
      const { result, usedSudo } = await this.readWithFailover<DockerProbe>(
        cfg,
        (sudo) => buildDockerListCommand({ sudo }),
        parseDockerOutput,
        (detail) => ({ ok: false, reason: 'unknown', detail }),
        opts,
        READ_TIMEOUT_MS
      )
      return result.ok && usedSudo ? { ...result, usedSudo: true } : result
    } catch (e) {
      return { ok: false, reason: 'unknown', detail: e instanceof Error ? e.message : String(e) }
    }
  }

  /**
   * Disk usage by images, containers, volumes and build cache.
   *
   * A read, so it gets the same failover as the list. Disk-full is the most
   * common docker incident there is and it is invisible from `docker ps`, so a
   * permissions problem here has to say "you are not allowed to look" rather
   * than showing four zeroes — a host reported as using no disk is worse than
   * one reported as unreadable.
   */
  async disk(cfg: unknown, opts: DockerListOptions = {}): Promise<DockerDiskProbe> {
    try {
      const { result, usedSudo } = await this.readWithFailover<DockerDiskProbe>(
        cfg,
        (sudo) => buildDockerDiskCommand({ sudo }),
        parseDockerDiskOutput,
        (detail) => ({ ok: false, reason: 'unknown', detail }),
        opts,
        DF_TIMEOUT_MS
      )
      return result.ok && usedSudo ? { ...result, usedSudo: true } : result
    } catch (e) {
      return { ok: false, reason: 'unknown', detail: e instanceof Error ? e.message : String(e) }
    }
  }

  /**
   * Ports, mounts, restart policy, health, image digest — and the NUMBER of
   * environment variables.
   *
   * Never their values, and never a raw `docker inspect`: the untemplated form
   * dumps `Config.Env`, which on a real host is database URLs and API keys.
   * The count is computed by the remote Go template, so the values are not read
   * on the host, do not cross the SSH channel, and cannot end up in an error
   * detail this process later hands to the renderer.
   *
   * The builder throws on a reference it cannot prove safe. That is left to
   * propagate rather than folded into a `DockerFailure`: it is not a condition
   * of the host, and dressing it as one would put an injection attempt behind
   * the words "docker returned an error that could not be classified".
   */
  async inspect(cfg: unknown, ref: string, opts: DockerListOptions = {}): Promise<DockerInspectProbe> {
    // Outside the try, deliberately: a refused build must reject the call.
    const build = (sudo: boolean): string => buildDockerInspectCommand(ref, { sudo })
    build(opts.sudo === true)
    try {
      const { result, usedSudo } = await this.readWithFailover<DockerInspectProbe>(
        cfg,
        build,
        parseDockerInspectOutput,
        (detail) => ({ ok: false, reason: 'unknown', detail }),
        opts,
        READ_TIMEOUT_MS
      )
      return result.ok && usedSudo ? { ...result, usedSudo: true } : result
    } catch (e) {
      return { ok: false, reason: 'unknown', detail: e instanceof Error ? e.message : String(e) }
    }
  }

  /** One-shot CPU and memory for named containers. `--no-stream`; see the builder. */
  async stats(cfg: unknown, refs: string[], opts: DockerListOptions = {}): Promise<DockerStatsProbe> {
    const build = (sudo: boolean): string => buildDockerStatsCommand(refs, { sudo })
    build(opts.sudo === true)
    try {
      const { result, usedSudo } = await this.readWithFailover<DockerStatsProbe>(
        cfg,
        build,
        parseDockerStatsOutput,
        (detail) => ({ ok: false, reason: 'unknown', detail }),
        opts,
        STATS_TIMEOUT_MS
      )
      return result.ok && usedSudo ? { ...result, usedSudo: true } : result
    } catch (e) {
      return { ok: false, reason: 'unknown', detail: e instanceof Error ? e.message : String(e) }
    }
  }

  /**
   * start / stop / restart.
   *
   * The one method here that changes state, and the one that does NOT
   * auto-escalate. The reads above may quietly retry as root because a read
   * retried as root produces the same answer either way; an ACTION retried as
   * root is a privileged write the user did not ask for. They approved
   * "restart this container", not "restart this container as root if the socket
   * says no", and `sudo -n` succeeding is not consent — it is a sudoers file
   * the user wrote for other reasons.
   *
   * So a refused action reports `permission-denied` and stops. The panel then
   * offers root as a second, explicit press, and the user sees the word before
   * it happens rather than afterwards in a footnote.
   *
   * The approval model itself lives in shared/docker.ts next to
   * `planDockerAction`, and is enforced where the human is — the same division
   * broadcast makes. What this method enforces is the part a dialog cannot: the
   * references are validated by a builder that throws, and the action is
   * checked against an allow-list rather than interpolated, because both arrive
   * over IPC where a TypeScript type is a claim and not a fact.
   */
  async act(
    cfg: unknown,
    action: DockerAction,
    refs: string[],
    opts: DockerActionOptions = {}
  ): Promise<DockerActionResult> {
    // Built before the try: a refused build is a rejected call, not a docker
    // failure dressed up as one.
    const command = buildDockerActionCommand(action, refs, { sudo: opts.sudo, timeoutSec: opts.timeoutSec })
    try {
      const result = await this.attempt<DockerActionResult>(
        cfg,
        command,
        (output, code) => parseDockerActionOutput(refs, output, code),
        actionTimeoutMs(refs.length),
        (detail) => ({ ok: false, reason: 'unknown', detail })
      )
      return result.ok && opts.sudo === true ? { ...result, usedSudo: true } : result
    } catch (e) {
      return { ok: false, reason: 'unknown', detail: e instanceof Error ? e.message : String(e) }
    }
  }
}
