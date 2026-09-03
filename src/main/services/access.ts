import { createHash } from 'node:crypto'
import type {
  AccessCollectOptions,
  AccessCommitOutcome,
  AccessVerifyResult,
  HostAccess,
  Sha256
} from '../../shared/access'
import {
  ACCESS_COMMITTED_PREFIX,
  ACCESS_ROLLBACK_SECONDS,
  ACCESS_STATUS_MARKER,
  accessBackupPath,
  accessDisarmCommand,
  accessVerifyCommand,
  buildAccessCommand,
  describeAccessOutcome,
  judgeAccessVerification,
  parseAccessCollection
} from '../../shared/access'

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

// ---------------------------------------------------------------------------
// The confirmation — roadmap item 23, rule 2
// ---------------------------------------------------------------------------
//
// This file is the ONLY place in the repository that issues
// `accessDisarmCommand`, and tests/accessWrite.test.ts fails if that stops
// being true. What earns it the privilege is what it cannot do:
//
//  * It does not import ./ssh. There is no expression here that can reach
//    `acquire()`, the pool, or a connection anything else is using — the
//    session arrives as an injected dependency, the same way `AccessReader`
//    takes its `exec`. A future edit that wanted to confirm over the pooled
//    connection would have to add an import, which the guard test sees.
//
//  * It does not decide what counts as independent. `judgeAccessVerification`
//    in shared/access.ts does, from evidence, with its own tests. This file
//    gathers the evidence and obeys.
//
//  * It never issues the disarm over a connection other than the one that was
//    judged. Both commands go through the same `session` value, so "verified
//    on one connection, confirmed on another" is not a state this can be in.
//
// WHY THE DISARM RUNS ON THE VERIFYING SESSION and not on a third connection:
// a third connection would be a third thing that can fail, and its failure
// would land in the window between "proved safe" and "made permanent" — which
// is the window the dead-man's switch exists to close. One session that
// authenticated after the write does both, or the host reverts.

/**
 * A connection that authenticated for THIS call and belongs to no pool.
 *
 * Structural rather than an import of `FreshSession`, for the reason the job
 * spec in shared/access.ts is structural: nothing here should be able to name
 * the transport, because naming it is the first step to reaching into it.
 */
export interface AccessFreshSession {
  connectionId: string
  pooledConnectionIds: string[]
  authenticatedAt: number
  exec: (command: string, timeoutMs?: number) => Promise<AccessVerifyResult>
  close: () => void
}

export interface AccessCommitDeps {
  /**
   * MUST open a connection that authenticates during this call and is not in
   * any pool. `sshOpenFresh` is the only implementation the app ships; a
   * `sshExec`-shaped one would satisfy the types and fail the judgement, which
   * is the point of the judgement.
   */
  openFresh: (cfg: unknown) => Promise<AccessFreshSession>
  now?: () => number
}

/**
 * How long the confirmation is given.
 *
 * Much shorter than the collector's budget, and shorter than the rollback
 * window by a wide margin: this is one connect and two one-line commands, and
 * a confirmation still waiting when the host restores itself is worse than one
 * that gave up early — the early one reports `reverted-unconfirmed` honestly
 * while the late one would report `committed` for a file that is no longer
 * there.
 */
export const ACCESS_CONFIRM_TIMEOUT_MS = 20_000

export interface AccessCommitRequest {
  serverId: string
  serverName: string
  /** The account whose authorized_keys was staged. */
  user: string
  /** The change's token: what named its backup and its marker on the host. */
  token: string
  /** The key file as the read half saw it, for the backup path in the report. */
  keyPath: string
  /** When the staged write finished on the host. The whole judgement turns on
   *  the verifying session having authenticated after this. */
  stagedAt: number
  rollbackSeconds?: number
}

export interface AccessCommitReport {
  serverId: string
  serverName: string
  user: string
  token: string
  outcome: AccessCommitOutcome
  /** One sentence, already written for a person. */
  detail: string
  /** Where the previous file is, whichever way this went. */
  backupPath: string
  at: number
}

export class AccessCommitter {
  constructor(private readonly deps: AccessCommitDeps) {}

  async confirm(cfg: unknown, req: AccessCommitRequest): Promise<AccessCommitReport> {
    const clock = this.deps.now ?? Date.now
    const rollbackSeconds = req.rollbackSeconds ?? ACCESS_ROLLBACK_SECONDS
    const backupPath = accessBackupPath(req.keyPath, req.token)

    // THE DEADLINE IS CHECKED BEFORE ANYTHING IS OPENED, and not only to save a
    // connection. Past the deadline the host has already put the previous file
    // back, so a session opened now authenticates against the OLD
    // authorized_keys — it would very likely succeed, and it would be proving
    // something about a file the change never touched. A late check is not
    // merely useless; it is the one that could talk this into confirming.
    //
    // Routed through the same judgement rather than duplicated, so there is one
    // deadline and one sentence for it. `judgeAccessVerification` tests this
    // first, so evidence it has not gathered yet cannot change the answer.
    const expired = judgeAccessVerification({
      token: req.token,
      stagedAt: req.stagedAt,
      rollbackSeconds,
      now: clock(),
      evidence: { session: null, verify: null }
    })
    if (expired.outcome === 'reverted-unconfirmed') {
      return this.report(req, expired.outcome, expired.reason, backupPath, rollbackSeconds, clock())
    }

    let session: AccessFreshSession | null = null
    let openError: string | undefined
    try {
      session = await this.deps.openFresh(cfg)
    } catch (e) {
      // Not classified further, and shared/access.ts says why: a refused key
      // and an unreachable host are the same fact from here, and both mean the
      // same thing about what may happen next.
      openError = e instanceof Error ? e.message : String(e)
    }

    try {
      const verify = session
        ? await this.run(session, accessVerifyCommand(req.token))
        : null

      const verdict = judgeAccessVerification({
        token: req.token,
        stagedAt: req.stagedAt,
        rollbackSeconds,
        now: clock(),
        evidence: {
          session: session
            ? {
                connectionId: session.connectionId,
                pooledConnectionIds: session.pooledConnectionIds,
                authenticatedAt: session.authenticatedAt
              }
            : null,
          openError,
          verify
        }
      })

      let outcome = verdict.outcome
      let reason = verdict.reason

      if (verdict.commit && session) {
        const disarm = await this.run(session, accessDisarmCommand(req.keyPath, req.token))
        if (!disarm.ok || disarm.code !== 0 || !disarm.stdout.includes(ACCESS_COMMITTED_PREFIX)) {
          // Verified and then not confirmed. The change was fine; the sentence
          // that reaches the operator has to say so, because the host is about
          // to undo it and there is nothing to investigate.
          outcome = 'reverted-unconfirmed'
          const said = (disarm.stderr ?? '').trim().split('\n')[0].slice(0, 160)
          reason = `the host let a new session in, but the confirmation could not be written to it (${said || disarm.error || `exit ${String(disarm.code)}`}).`
        }
      }

      return this.report(req, outcome, reason, backupPath, rollbackSeconds, clock())
    } finally {
      // Always. A confirmation that leaked an authenticated session would leave
      // a second way into the host open for the life of the process, which is
      // the opposite of what this feature is for.
      session?.close()
    }
  }

  private report(
    req: AccessCommitRequest,
    outcome: AccessCommitOutcome,
    reason: string,
    backupPath: string,
    rollbackSeconds: number,
    at: number
  ): AccessCommitReport {
    return {
      serverId: req.serverId,
      serverName: req.serverName,
      user: req.user,
      token: req.token,
      outcome,
      detail: describeAccessOutcome({
        outcome,
        serverName: req.serverName,
        user: req.user,
        backupPath,
        rollbackSeconds,
        reason
      }),
      backupPath,
      at
    }
  }

  /** Never throws: a session that dies mid-check is a failed verification, not
   *  an exception thrown while deciding whether a key change is permanent. */
  private async run(session: AccessFreshSession, command: string): Promise<AccessVerifyResult> {
    try {
      return await session.exec(command, ACCESS_CONFIRM_TIMEOUT_MS)
    } catch (e) {
      return { ok: false, code: null, stdout: '', stderr: '', error: e instanceof Error ? e.message : String(e) }
    }
  }
}
