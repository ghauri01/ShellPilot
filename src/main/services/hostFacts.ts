import type { HostFacts, HostFactsCollectOptions } from '../../shared/hostFacts'
import { FACTS_STATUS_MARKER, buildHostFactsCommand, parseHostFacts } from '../../shared/hostFacts'

// Reading host facts over SSH — roadmap item C, main-process half.
//
// Thin on purpose, the same way DockerReader is thin: the command building, the
// parsing and every allow-list live in shared/hostFacts.ts where they can be
// tested without an SSH connection. What lives here is the round trip and the
// failure classification.
//
// TWO THINGS THIS DOES NOT DO, both deliberate:
//
//  * It does not use metrics.ts's `exec`. That helper resolves on `close` and
//    DISCARDS the exit code, and exit status is the API for three of the probes
//    inside the collector — dnf signals updates with 100, zypper reboot-needed
//    with 102, and `needs-restarting -r` says "reboot owed" with 1. Those codes
//    are consumed inside the shell script, but the script's own status still
//    has to be visible here to tell "the shell ran and answered" from "the
//    shell never ran". sshExec returns `{ok, stdout, stderr, code}`; this uses
//    that.
//
//  * It never sends a second command built from the first one's output. The
//    package manager is detected on the host, inside the one script. Round-
//    tripping a value the host chose and interpolating it into a command is the
//    shape of the injection this app has already had once.
//
// THE THREE-WAY FAILURE CLASSIFICATION, copied from docker.ts because the
// lesson transfers: "could not reach the host", "the host answered but not with
// our output" and "the host answered and some probes could not see anything"
// have three different fixes, and collapsing them sends someone to the wrong
// machine. The third is not a failure at all here — it is a successful
// collection whose FactSourceReports say what was not visible, which is the
// whole point of the item.

/**
 * The exec shape this reader needs. Structural rather than an import of
 * sshExec, so tests can hand over a function and never open a connection —
 * the same reason FleetSamplerDeps takes its sampler by injection.
 */
export type HostFactsExec = (
  cfg: unknown,
  command: string,
  timeoutMs: number
) => Promise<{ ok: boolean; code?: number | null; stdout?: string; stderr?: string; error?: string }>

export interface HostFactsDeps {
  exec: HostFactsExec
  /** Injectable so a test can pin the clock that decides `stale-metadata`. */
  now?: () => number
}

export type HostFactsFailure =
  /** The transport failed: unreachable, refused, timed out, no credentials.
   *  Nothing was learned about the host and nothing should be inferred. */
  | 'unreachable'
  /** The command ran and its status block never arrived. A shell that is not
   *  POSIX, output truncated by the transport cap, or a host that closed the
   *  channel mid-write. Distinct from `unreachable` because the machine is
   *  fine and the fix is on this side. */
  | 'no-output'
  | 'unknown'

export type HostFactsProbe =
  | { ok: true; facts: HostFacts }
  | { ok: false; reason: HostFactsFailure; detail: string }

/**
 * How long the collector is given.
 *
 * Generous compared with a metrics sample, because `dnf -C check-update` walks
 * the whole cached repository set and takes seconds on a host with a dozen
 * repositories — and this runs hourly, not every two minutes, so a slow answer
 * costs almost nothing. Short enough that a wedged package manager cannot hold
 * an exec channel open on the connection a terminal may be typing over.
 */
export const HOST_FACTS_TIMEOUT_MS = 45_000

export class HostFactsReader {
  constructor(private readonly deps: HostFactsDeps) {}

  async read(cfg: unknown, opts: HostFactsCollectOptions = {}): Promise<HostFactsProbe> {
    const command = buildHostFactsCommand(opts)
    try {
      const r = await this.deps.exec(cfg, command, HOST_FACTS_TIMEOUT_MS)
      if (!r.ok) {
        // A transport failure is not a host failure. Saying "this host has no
        // package manager" when the SSH connection never opened would put a
        // fabricated inventory row in front of an operator.
        return { ok: false, reason: 'unreachable', detail: r.error ?? 'could not reach the host' }
      }
      // stderr is NOT merged into stdout here, unlike the Docker reader.
      //
      // Every probe in the collector redirects its own stderr to /dev/null, so
      // anything on stderr came from the shell or the transport and is not part
      // of the answer. Merging it would splice unclassified text into the value
      // region, where a `V `-prefixed line from a noisy shell profile would be
      // read as a fact.
      const stdout = r.stdout ?? ''
      const facts = parseHostFacts(stdout, (this.deps.now ?? Date.now)())
      // Neither the status block nor a single value line means the script never
      // ran — a non-POSIX shell, or output cut before anything was written.
      // Reported as its own failure rather than as a host with nine unknowns,
      // which would look like a real collection from a very unhelpful machine.
      if (!stdout.includes(FACTS_STATUS_MARKER) && !/^V /m.test(stdout)) {
        const detail = (r.stderr ?? '').trim().slice(0, 200) || 'the host returned no collector output'
        return { ok: false, reason: 'no-output', detail }
      }
      return { ok: true, facts }
    } catch (e) {
      return { ok: false, reason: 'unknown', detail: e instanceof Error ? e.message : String(e) }
    }
  }
}
