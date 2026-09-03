import { createHash } from 'node:crypto'
import type { HostAccess, AccessCollectOptions, Sha256 } from '../../shared/access'
import { ACCESS_STATUS_MARKER, buildAccessCommand, parseAccessCollection } from '../../shared/access'

// Reading fleet key and access state over SSH — roadmap item 23, main half.
//
// Thin on purpose, exactly as HostFactsReader is thin: the command building,
// the parsing, the fingerprinting and every allow-list live in
// src/shared/access.ts where they can be tested without an SSH connection. What
// lives here is the round trip, the SHA-256 the shared parser is handed, and
// the failure classification.
//
// THE SHA-256, and why it is passed in rather than imported there:
// src/shared/access.ts is bundled into the renderer, and a top-level
// `node:crypto` import in a shared file breaks that build. The requirement it
// serves is unchanged — fingerprints are computed in TypeScript from the key
// blob and never by shelling out to `ssh-keygen`, which is not guaranteed
// present on a host and would mean a machine missing OpenSSH's own tooling
// could not have its keys identified at all.
//
// TWO THINGS THIS DOES NOT DO, both deliberate and both borrowed from
// hostFacts.ts because the reasoning is identical:
//
//  * It does not use metrics.ts's `exec`, which resolves on `close` and
//    discards the exit code. Nothing inside this collector uses exit status as
//    an API the way dnf and zypper do, but the SCRIPT's own status still has to
//    be visible here to tell "the shell ran and answered" from "the shell never
//    ran" — and that distinction is what separates `no-output` from a host with
//    no accounts.
//
//  * It never sends a second command built from the first one's output. Every
//    path read here is derived on the host, inside the one script, from
//    /etc/passwd. Round-tripping a home directory back to TypeScript and
//    interpolating it into a second command is the shape of the injection this
//    app has already had once.

export type AccessExec = (
  cfg: unknown,
  command: string,
  timeoutMs: number
) => Promise<{ ok: boolean; code?: number | null; stdout?: string; stderr?: string; error?: string }>

export interface AccessDeps {
  exec: AccessExec
  /** Injectable so a test can pin the clock a collection is stamped with. */
  now?: () => number
  /** Injectable so a test can prove the fingerprint comes from the injected
   *  hash rather than from anything this file happens to have imported. */
  sha256?: Sha256
}

export type AccessFailure =
  /** The transport failed: unreachable, refused, timed out, no credentials.
   *  Nothing was learned and — the point of this whole item — nothing may be
   *  inferred. A host that could not be reached is not a host with no keys. */
  | 'unreachable'
  /** The command ran and its status block never arrived: a shell that is not
   *  POSIX, output truncated by the transport cap, or a channel closed
   *  mid-write. The machine is fine and the fix is on this side. */
  | 'no-output'
  | 'unknown'

export type AccessProbe =
  | { ok: true; access: HostAccess }
  | { ok: false; reason: AccessFailure; detail: string }

/**
 * How long the collector is given.
 *
 * Longer than the host-facts budget. This one stats a home directory and reads
 * a file per included account, and on a host whose /etc/passwd is backed by a
 * directory service that is a hundred round trips to something that may be slow.
 * It runs hourly, so a slow answer costs almost nothing — and the account cap in
 * shared/access.ts bounds the work even when the timeout does not fire.
 */
export const ACCESS_TIMEOUT_MS = 60_000

const nodeSha256: Sha256 = (data) => new Uint8Array(createHash('sha256').update(data).digest())

export class AccessReader {
  constructor(private readonly deps: AccessDeps) {}

  async read(cfg: unknown, opts: AccessCollectOptions = {}): Promise<AccessProbe> {
    const command = buildAccessCommand(opts)
    try {
      const r = await this.deps.exec(cfg, command, ACCESS_TIMEOUT_MS)
      if (!r.ok) {
        // A transport failure is not a host failure, and this is the single
        // most important line in the file. Reporting "this host trusts no keys"
        // when the connection never opened would put a fabricated all-clear in
        // front of somebody running an access review.
        return { ok: false, reason: 'unreachable', detail: r.error ?? 'could not reach the host' }
      }
      // stderr is NOT merged into stdout, unlike the Docker reader. Every probe
      // in the collector redirects its own stderr to /dev/null, so anything on
      // stderr came from the shell or the transport and is not part of the
      // answer. Merging it would splice unclassified text into the record
      // region, where a `K `-prefixed line from a noisy shell profile would be
      // read as somebody's authorized key.
      const stdout = r.stdout ?? ''
      if (!stdout.includes(ACCESS_STATUS_MARKER)) {
        // No status block means no collection. Reported as its own failure
        // rather than as a host with six unknowns and no accounts, which would
        // look like a real reading of a very empty machine.
        const detail = (r.stderr ?? '').trim().slice(0, 200) || 'the host returned no collector output'
        return { ok: false, reason: 'no-output', detail }
      }
      const access = parseAccessCollection(stdout, {
        sha256: this.deps.sha256 ?? nodeSha256,
        now: (this.deps.now ?? Date.now)()
      })
      return { ok: true, access }
    } catch (e) {
      return { ok: false, reason: 'unknown', detail: e instanceof Error ? e.message : String(e) }
    }
  }
}
