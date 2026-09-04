import type { HostPosture, PostureCollectOptions } from '../../shared/posture'
import { POSTURE_STATUS_MARKER, buildPostureCommand, parsePosture } from '../../shared/posture'

// Reading a host's security posture over SSH — roadmap item 24, main half.
//
// Thin on purpose, exactly as HostFactsReader and AccessReader are thin: the
// command building, the parsing, the baseline and every allow-list live in
// src/shared/posture.ts where they can be tested without an SSH connection.
// What lives here is the round trip and the failure classification.
//
// TWO THINGS THIS DOES NOT DO, both deliberate and both borrowed from
// hostFacts.ts because the reasoning is identical:
//
//  * It does not use metrics.ts's `exec`, which resolves on `close` and
//    DISCARDS the exit code. Nothing inside this collector uses exit status as
//    an API the way dnf and zypper do — the nft and iptables branches read
//    their own `$?` inside the script — but the SCRIPT's own status still has
//    to be visible here to tell "the shell ran and answered" from "the shell
//    never ran", and that distinction is what separates `no-output` from a
//    host that genuinely has no firewall tooling.
//
//  * It never sends a second command built from the first one's output. Every
//    path read here is a literal in the one script; nothing the host says is
//    round-tripped back to TypeScript and interpolated into a follow-up, which
//    is the shape of the injection this app has already had once.
//
// THE THREE-WAY FAILURE CLASSIFICATION, and it matters more here than in any
// other collector: "could not reach the host", "the host answered but not with
// our output" and "the host answered and some probes could not see anything"
// have three different fixes. The third is not a failure at all — it is a
// successful collection whose PostureSourceReports say what was not visible,
// which is the whole point of the item. Collapsing the first into the third
// would put "this host has no firewall rules" in front of somebody running a
// security review over a machine nobody managed to connect to.

/**
 * The exec shape this reader needs. Structural rather than an import of
 * sshExec, so tests can hand over a function and never open a connection — the
 * same reason FleetSamplerDeps takes its samplers by injection.
 */
export type PostureExec = (
  cfg: unknown,
  command: string,
  timeoutMs: number
) => Promise<{ ok: boolean; code?: number | null; stdout?: string; stderr?: string; error?: string }>

export interface PostureDeps {
  exec: PostureExec
  /** Injectable so a test can pin the clock a collection is stamped with. */
  now?: () => number
}

export type PostureFailure =
  /** The transport failed: unreachable, refused, timed out, no credentials.
   *  Nothing was learned and — the point of this whole item — nothing may be
   *  inferred. A host that could not be reached is not a host with no
   *  firewall. */
  | 'unreachable'
  /** The command ran and its status block never arrived: a shell that is not
   *  POSIX, output truncated by the transport cap, or a channel closed
   *  mid-write. The machine is fine and the fix is on this side. */
  | 'no-output'
  | 'unknown'

export type PostureProbe =
  | { ok: true; posture: HostPosture }
  | { ok: false; reason: PostureFailure; detail: string }

/**
 * How long the collector is given.
 *
 * The same budget as the host-facts probe rather than the access probe's
 * longer one. This runs a bounded number of commands — four or five tool
 * invocations and a handful of file reads — none of which walks a directory
 * service the way the account loop can. The one that can take real time is
 * `lastb` on a host with a very large btmp, which is a sequential read of a
 * file and not a network round trip.
 *
 * Short enough that a wedged `iptables` waiting on the xtables lock cannot hold
 * an exec channel open on the connection a terminal may be typing over. It runs
 * hourly, so a slow answer costs almost nothing.
 */
export const POSTURE_TIMEOUT_MS = 45_000

export class PostureReader {
  constructor(private readonly deps: PostureDeps) {}

  /**
   * One collection.
   *
   * `opts` is the whole of the consent surface this class has, and the default
   * matters: an empty options object collects the SCALARS ONLY — item 24's
   * reading — and no firewall rule lines. The caller has to say
   * `firewallRules: true`, which main does per server from the `firewallRules`
   * capability on the access group governing it, and only for `allow`.
   *
   * Gating here rather than in the panel is item 31's decision and not a
   * detail: the rules are omitted from the COMMAND, so an ungranted host is
   * never asked for them, they never reach the wire, and they are never in
   * this process at all. A reader that collected them and declined to display
   * them would have had them in memory and in the transport's buffers, which
   * outlives the decision not to draw them.
   */
  async read(cfg: unknown, opts: PostureCollectOptions = {}): Promise<PostureProbe> {
    const command = buildPostureCommand(opts)
    try {
      const r = await this.deps.exec(cfg, command, POSTURE_TIMEOUT_MS)
      if (!r.ok) {
        // A transport failure is not a host failure, and this is the single
        // most important line in the file. Reporting "no firewall rules, sshd
        // not hardened" for a connection that never opened would put a
        // fabricated security finding — in either direction — in front of
        // somebody acting on it.
        return { ok: false, reason: 'unreachable', detail: r.error ?? 'could not reach the host' }
      }
      // stderr is NOT merged into stdout, unlike the Docker reader. Every probe
      // in the collector redirects its own stderr to /dev/null, so anything on
      // stderr came from the shell or the transport and is not part of the
      // answer. Merging it would splice unclassified text into the record
      // region, where a `V `-prefixed line from a noisy shell profile would be
      // read as a firewall value.
      const stdout = r.stdout ?? ''
      if (!stdout.includes(POSTURE_STATUS_MARKER)) {
        // No status block means no collection. Reported as its own failure
        // rather than as a host with four unknowns, which would look like a
        // real reading of a very unhelpful machine — and unlike the facts
        // collector, there is no partial answer worth keeping here: without the
        // status block every value is unattributed, and an unattributed
        // firewall reading is exactly what this item exists to refuse.
        const detail = (r.stderr ?? '').trim().slice(0, 200) || 'the host returned no collector output'
        return { ok: false, reason: 'no-output', detail }
      }
      return { ok: true, posture: parsePosture(stdout, (this.deps.now ?? Date.now)()) }
    } catch (e) {
      return { ok: false, reason: 'unknown', detail: e instanceof Error ? e.message : String(e) }
    }
  }
}
