import type {
  ComposeConfigProbe,
  ComposeEnvProbe,
  ComposeFailure,
  ComposeImageEditPlan,
  ComposeImageWriteRequest,
  ComposeImageWriteResult,
  ComposeListProbe,
  ComposeProjectRef
} from '../../shared/compose'
import {
  applyComposeImageEdit,
  buildComposeConfigCommand,
  buildComposeEnvNamesCommand,
  buildComposeListCommand,
  buildComposeReadCommand,
  buildComposeWriteCommand,
  parseComposeConfigOutput,
  parseComposeEnvNamesOutput,
  parseComposeListOutput,
  planComposeImageEdit,
  validateComposePath
} from '../../shared/compose'
import { SUDO_PROBE } from '../../shared/docker'

// The compose round trips.
//
// Thin, for the same reason `services/docker.ts` is thin: the parsing, the
// command building and the failure classification live in `shared/compose.ts`
// where they are tested without an SSH connection. What is here is the wire,
// plus the two decisions that need it.
//
// **The sudo discipline is docker's, unchanged.** Reads auto-escalate through
// `sudo -n`, which never prompts; a `permission-denied` is the only failure
// worth retrying as root, because root does not install a missing binary; and
// the result says when root was used. WRITES DO NOT AUTO-ESCALATE. The operator
// approved "change this tag", not "change it as root if the file says no", and
// a passwordless sudoers entry is a decision they made for other reasons.
//
// **This class is a sibling of DockerReader, not a subclass of it.** The
// failover is thirty lines and it is copied rather than shared, which is the
// same call docker.ts makes about broadcast's confirmation model and for the
// same reason: modules are independently enableable, and making compose's
// round trip depend on docker's internals would tie one module's presence to
// another's file. The tests hold the two shapes together.
//
// **Nothing here ever reads an environment value.** `envNames` runs a command
// whose awk program prints names and cannot print values — see
// `buildComposeEnvNamesCommand`. There is no method on this class that returns
// the contents of a `.env`, and `readFile` is deliberately restricted to a
// compose file the caller names, which is not a secret store.

export type ComposeExec = (
  cfg: unknown,
  command: string,
  timeoutMs: number
) => Promise<{ ok: boolean; code?: number | null; stdout?: string; stderr?: string; error?: string }>

export interface ComposeDeps {
  exec: ComposeExec
}

export interface ComposeReadOptions {
  /** Skip the unprivileged attempt and read as root immediately. */
  sudo?: boolean
  /** Retry as root when the unprivileged read is refused. On by default. */
  autoSudo?: boolean
}

interface Probe {
  ok: boolean
  reason?: ComposeFailure
  usedSudo?: boolean
}

/**
 * The listing budget, which is larger than docker's read budget on purpose.
 *
 * It contains the bounded filesystem search, and a bounded search on a cold
 * cache is slow rather than broken. The bound is what keeps this a number
 * instead of an open-ended wait: eight roots, four levels, one filesystem.
 */
const LIST_TIMEOUT_MS = 60_000
const READ_TIMEOUT_MS = 30_000
const WRITE_TIMEOUT_MS = 20_000

export class ComposeReader {
  constructor(private readonly deps: ComposeDeps) {}

  private async attempt<R extends Probe>(
    cfg: unknown,
    command: string,
    parse: (output: string, code: number | null) => R,
    timeoutMs: number,
    onTransportFailure: (detail: string) => R
  ): Promise<R> {
    const r = await this.deps.exec(cfg, command, timeoutMs)
    // A transport failure is not a compose failure. Saying "compose is not
    // installed" for a host that was simply unreachable sends someone to fix
    // the wrong machine.
    if (!r.ok) return onTransportFailure(r.error ?? 'could not reach the host')
    const stdout = r.stdout ?? ''
    const stderr = r.stderr ?? ''
    // Joined on a newline rather than glued: the collectors redirect the
    // command's own stderr into stdout, so anything left on stderr came from
    // the shell, and concatenating it directly welds it onto the last line of
    // the last block.
    const merged = stderr === '' ? stdout : `${stdout}\n${stderr}`
    return parse(merged, r.code ?? null)
  }

  private async readWithFailover<R extends Probe>(
    cfg: unknown,
    build: (sudo: boolean) => string,
    parse: (output: string, code: number | null) => R,
    onTransportFailure: (detail: string) => R,
    opts: ComposeReadOptions,
    timeoutMs: number
  ): Promise<{ result: R; usedSudo: boolean }> {
    const run = (sudo: boolean): Promise<R> =>
      this.attempt(cfg, build(sudo), parse, timeoutMs, onTransportFailure)

    if (opts.sudo) return { result: await run(true), usedSudo: true }

    const first = await run(false)
    // Only a socket-permission refusal is worth retrying. A missing binary, a
    // dead daemon, a compose plugin that is not installed — root fixes none of
    // them, and retrying just doubles the wait before the same answer.
    if (first.ok || first.reason !== 'permission-denied' || opts.autoSudo === false) {
      return { result: first, usedSudo: false }
    }
    if (!(await this.canSudo(cfg))) return { result: first, usedSudo: false }

    const elevated = await run(true)
    // If root does not help either, report the ORIGINAL failure: it describes
    // the user's situation, where a second error about sudo describes ours.
    return elevated.ok ? { result: elevated, usedSudo: true } : { result: first, usedSudo: false }
  }

  async canSudo(cfg: unknown): Promise<boolean> {
    try {
      const r = await this.deps.exec(cfg, SUDO_PROBE, 10_000)
      return (r.stdout ?? '').includes('SP_SUDO_OK')
    } catch {
      return false
    }
  }

  /** Projects docker knows about, plus the bounded search for files it does not. */
  async list(
    cfg: unknown,
    opts: ComposeReadOptions & { search?: boolean } = {}
  ): Promise<ComposeListProbe> {
    try {
      const { result, usedSudo } = await this.readWithFailover<ComposeListProbe>(
        cfg,
        (sudo) => buildComposeListCommand({ sudo, search: opts.search }),
        parseComposeListOutput,
        (detail) => ({ ok: false, reason: 'unknown', detail }),
        opts,
        LIST_TIMEOUT_MS
      )
      return result.ok && usedSudo ? { ...result, usedSudo: true } : result
    } catch (e) {
      return { ok: false, reason: 'unknown', detail: e instanceof Error ? e.message : String(e) }
    }
  }

  /**
   * What a project DECLARES.
   *
   * The builder throws on a project name or a file path it cannot prove safe,
   * and that is left outside the try on purpose: a refused build must reject
   * the call rather than arriving as a `ComposeFailure`, which would dress an
   * injection attempt up as a condition of the host.
   */
  async config(
    cfg: unknown,
    project: ComposeProjectRef,
    opts: ComposeReadOptions = {}
  ): Promise<ComposeConfigProbe> {
    const build = (sudo: boolean): string => buildComposeConfigCommand(project, { sudo })
    build(opts.sudo === true)
    try {
      const { result, usedSudo } = await this.readWithFailover<ComposeConfigProbe>(
        cfg,
        build,
        parseComposeConfigOutput,
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
   * Which variables an env file declares. NEVER what they are set to.
   *
   * The stripping happens on the remote host, in the awk program the builder
   * writes: the values are gone before the SSH channel sees them, so they are
   * not in this process's memory, not in a rejected promise, and not in an
   * error detail the renderer later displays. That is the same discipline
   * `buildDockerInspectCommand` follows for `Config.Env`.
   */
  async envNames(
    cfg: unknown,
    paths: string[],
    opts: ComposeReadOptions = {}
  ): Promise<ComposeEnvProbe> {
    const build = (sudo: boolean): string => buildComposeEnvNamesCommand(paths, { sudo })
    build(opts.sudo === true)
    try {
      const { result, usedSudo } = await this.readWithFailover<ComposeEnvProbe>(
        cfg,
        build,
        (output) => ({ ok: true, files: parseComposeEnvNamesOutput(output) }),
        (detail) => ({ ok: false, reason: 'unknown', detail }),
        opts,
        READ_TIMEOUT_MS
      )
      return result.ok && usedSudo ? { ...result, usedSudo: true } : result
    } catch (e) {
      return { ok: false, reason: 'unknown', detail: e instanceof Error ? e.message : String(e) }
    }
  }

  /** A compose file's text, bounded, for the tag editor to plan against. */
  async readFile(
    cfg: unknown,
    path: string,
    opts: { sudo?: boolean } = {}
  ): Promise<{ ok: boolean; text?: string; error?: string }> {
    const command = buildComposeReadCommand(path, opts)
    try {
      const r = await this.deps.exec(cfg, command, READ_TIMEOUT_MS)
      if (!r.ok) return { ok: false, error: r.error ?? 'could not reach the host' }
      const text = r.stdout ?? ''
      const stderr = (r.stderr ?? '').trim()
      // `head` writes its refusal to stderr and nothing to stdout. A file that
      // is genuinely empty produces neither, and the two are different facts.
      if (text === '' && stderr !== '') return { ok: false, error: stderr }
      return { ok: true, text }
    } catch (e) {
      return { ok: false, error: e instanceof Error ? e.message : String(e) }
    }
  }

  /**
   * Change one image tag in one compose file.
   *
   * THE READ-MODIFY-WRITE IS RE-DERIVED HERE, not carried from the renderer.
   * The request says which line the operator was shown and what was on it;
   * this method re-reads the file, re-plans the edit against what is on the
   * host NOW, and refuses when the two disagree. Applying a line the renderer
   * computed would write a stale edit into a file somebody else has changed —
   * and the renderer is not a trust boundary, so a plan arriving from it is a
   * claim about a file, not a fact about one.
   *
   * No sudo failover. See the header: a write is not a read.
   */
  async writeImageTag(
    cfg: unknown,
    req: ComposeImageWriteRequest,
    opts: { sudo?: boolean } = {}
  ): Promise<ComposeImageWriteResult> {
    if (!validateComposePath(req?.path)) return { ok: false, reason: 'not a valid compose file path' }
    const read = await this.readFile(cfg, req.path, opts)
    if (!read.ok || read.text === undefined) {
      return { ok: false, reason: read.error ?? 'could not read the compose file' }
    }

    const plan: ComposeImageEditPlan = planComposeImageEdit(read.text, req.service, req.image)
    if (!plan.ok) return { ok: false, reason: plan.reason }

    // The operator confirmed a specific line with specific text on it. If the
    // file moved under them, they are approving something they did not see.
    if (req.expect?.line !== plan.line || req.expect?.before !== plan.before) {
      return {
        ok: false,
        reason:
          'the compose file on the host is not the one this edit was planned against — it has changed since it was read. Nothing was written.'
      }
    }

    let updated: string
    try {
      updated = applyComposeImageEdit(read.text, plan)
    } catch (e) {
      return { ok: false, reason: e instanceof Error ? e.message : String(e) }
    }

    const command = buildComposeWriteCommand(req.path, updated, opts)
    try {
      const r = await this.deps.exec(cfg, command, WRITE_TIMEOUT_MS)
      if (!r.ok) return { ok: false, reason: r.error ?? 'could not reach the host' }
      const merged = `${r.stdout ?? ''}${r.stderr ?? ''}`
      // The write chain is `cp && tee && mv && echo <end marker>`. The marker
      // is the only proof the `mv` ran: a non-zero exit is conclusive, but a
      // shell that died between stages can exit 0 with the file half replaced,
      // and reporting that as a successful edit is the worst outcome here.
      if ((r.code ?? 0) !== 0 || !merged.includes('===SHELLPILOT-END===')) {
        return { ok: false, reason: merged.trim() || 'the compose file was not written' }
      }
      return { ok: true, plan, backup: `${req.path}.shellpilot-bak` }
    } catch (e) {
      return { ok: false, reason: e instanceof Error ? e.message : String(e) }
    }
  }
}
