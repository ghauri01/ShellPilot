import { createHash } from 'node:crypto'
import {
  DRIFT_MARKER,
  DRIFT_PREVIEW_CHARS,
  DRIFT_WATCHES,
  buildDriftCommand,
  normaliseForWatch,
  parseDriftCollection,
  type DriftNormaliseContext,
  type DriftReading,
  type DriftWatch,
  type HostDrift
} from '../../shared/drift'
import { redactOutput } from './secretRedaction'

// Reading watched configuration files over SSH — roadmap item 25, main half.
//
// Thin, exactly as HostFactsReader, AccessReader and PostureReader are thin:
// the command building, the parsing, the normalisation rules and the whole
// comparison live in src/shared/drift.ts where they are testable without an SSH
// connection. What lives here is the round trip, the failure classification —
// and the one thing that CANNOT live in shared, because it must never run in
// the renderer: redaction and hashing.
//
// ---------------------------------------------------------------------------
// ORDER OF OPERATIONS, AND WHY IT IS THIS ORDER
// ---------------------------------------------------------------------------
//
// A watched file may be sshd_config. It may also be something with a password
// in it. So content is redacted before anything else happens to it, and in
// particular BEFORE ANY TRUNCATION:
//
//   decode -> seal an unterminated key block -> redact -> hash -> normalise ->
//   hash -> truncate for the preview
//
// Capping first is the bug this codebase found in the change log this week. The
// PEM pattern in secretRedaction.ts needs both `-----BEGIN ... PRIVATE KEY-----`
// and the matching END; cut the tail off and the pattern matches nothing, the
// redaction silently does nothing, and the key body ships as prose into
// whatever the cap was protecting. Truncation is therefore the LAST thing that
// happens, and it happens only to the preview.
//
// The collector helps by never truncating on the host either: a file over the
// read cap is reported `partial` with no content sent at all, rather than as a
// prefix that could be cut mid-key. `sealUnterminatedKeyBlock` below covers
// what is left — a file that genuinely contains a BEGIN with no END, which is
// rarer and is exactly as dangerous.
//
// ---------------------------------------------------------------------------
// WHAT REACHES THE DURABLE STORE
// ---------------------------------------------------------------------------
//
// Two hashes and a status. Not the file. `driftToFacts` below is the whole of
// what is written, and it holds no content of any kind — the roadmap's own
// sizing note flags file contents as the thing that changes the store's growth
// more than samples do, and it is right. A hash answers "do these differ",
// which is the question.
//
// `preview` is bounded redacted text kept in the sampler's memory so the panel
// can show a side by side. It is never written, never survives a restart, and
// its bound is stated on screen.

/**
 * The exec shape this reader needs. Structural rather than an import of
 * sshExec, so tests hand over a function and never open a connection — the same
 * reason FleetSamplerDeps takes its samplers by injection.
 */
export type DriftExec = (
  cfg: unknown,
  command: string,
  timeoutMs: number
) => Promise<{ ok: boolean; code?: number | null; stdout?: string; stderr?: string; error?: string }>

export interface DriftDeps {
  exec: DriftExec
  /** Injectable so a test can pin the clock a collection is stamped with. */
  now?: () => number
  /** Overridable so a test does not have to build a tree at seven absolute
   *  paths. Production always uses the catalogue. */
  watches?: DriftWatch[]
}

export type DriftFailure =
  /** The transport failed: unreachable, refused, timed out, no credentials.
   *  Nothing was learned and nothing may be inferred — a host that could not be
   *  reached is not a host whose configuration matches. */
  | 'unreachable'
  /** The command ran and its closing marker never arrived: a shell that is not
   *  POSIX, output truncated by the transport cap, or a channel closed
   *  mid-write. */
  | 'no-output'
  | 'unknown'

export type DriftProbe =
  | { ok: true; drift: HostDrift }
  | { ok: false; reason: DriftFailure; detail: string }

/**
 * How long the collector is given.
 *
 * The same budget as the host-facts and posture probes. This runs a bounded
 * number of stats and reads a bounded number of bytes; nothing here walks a
 * directory service the way the access probe's account loop can.
 */
export const DRIFT_TIMEOUT_MS = 45_000

/** The prefix everything this feature writes to the durable store lives under,
 *  so the sampler can retire the whole set in one call. */
export const DRIFT_FACT_PREFIX = 'drift:'

const BEGIN_KEY = /-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----/g

/**
 * Terminate a private key block that has no end.
 *
 * secretRedaction.ts's PEM rule is anchored on both markers, which is correct
 * for the output of a command that either printed the key or did not. A FILE
 * can end mid-key — truncated by whatever wrote it, or genuinely corrupt — and
 * then the rule matches nothing and the key body goes through untouched.
 *
 * So an unterminated BEGIN takes everything after it. Deliberately greedy: what
 * follows a BEGIN with no END is either key material or the end of the file,
 * and losing the tail of a config from the panel is the cheaper mistake by a
 * very wide margin.
 *
 * Runs BEFORE redactOutput rather than instead of it — the pattern rules there
 * catch everything else, and this only closes the one hole the anchoring
 * leaves.
 */
export function sealUnterminatedKeyBlock(text: string): string {
  BEGIN_KEY.lastIndex = 0
  let m: RegExpExecArray | null
  while ((m = BEGIN_KEY.exec(text)) !== null) {
    const after = text.slice(m.index + m[0].length)
    if (/-----END [A-Z0-9 ]*PRIVATE KEY-----/.test(after)) continue
    // No end marker anywhere after this BEGIN. Everything from here on is
    // treated as key material.
    return `${text.slice(0, m.index)}-----BEGIN PRIVATE KEY-----\n[REDACTED]\n-----END PRIVATE KEY-----`
  }
  return text
}

/** sha256, hex. Of the REDACTED text, always — see the order note above. */
export function driftHash(text: string): string {
  return createHash('sha256').update(text, 'utf8').digest('hex')
}

/**
 * Turn one decoded file into a reading: redact, hash, normalise, hash, bound.
 *
 * Exported because the ordering here is the part most worth testing directly,
 * and a test that had to stand up a fake SSH channel to check it would be
 * testing the channel.
 */
export function readingFromContent(
  watch: DriftWatch,
  content: string,
  ctx: DriftNormaliseContext,
  bytes?: number
): DriftReading {
  // 1. Seal, then redact. Nothing has been shortened yet, so both halves of a
  //    PEM block are still present for the pattern that needs them.
  const safe = redactOutput(sealUnterminatedKeyBlock(content))
  const redacted = safe !== content
  // 2. Hash the redacted text. This is the "are these byte-identical" answer,
  //    and it is an answer about the redacted form on purpose: the unredacted
  //    bytes must not survive this function in any form, hash included.
  const hash = driftHash(safe)
  // 3. Normalise the same redacted text and hash that.
  const normalised = normaliseForWatch(safe, watch, ctx)
  return {
    watchId: watch.id,
    status: 'ok',
    bytes,
    hash,
    normalisedHash: driftHash(normalised.text),
    applied: normalised.applied,
    redacted: redacted || undefined,
    // 4. And only now, last of all, shorten — for display, from text that has
    //    already been through every redaction rule.
    preview: safe.slice(0, DRIFT_PREVIEW_CHARS)
  }
}

export class DriftReader {
  constructor(private readonly deps: DriftDeps) {}

  async read(cfg: unknown, ctx: DriftNormaliseContext = {}): Promise<DriftProbe> {
    const watches = this.deps.watches ?? DRIFT_WATCHES
    const command = buildDriftCommand({ watches })
    try {
      const r = await this.deps.exec(cfg, command, DRIFT_TIMEOUT_MS)
      if (!r.ok) {
        // A transport failure is not a host failure, and this is the single
        // most important line in the file. Reporting a host with no readings —
        // which the comparison would render as "not collected" at best and
        // could render as "matches" if anything downstream ever got sloppy — is
        // the failure mode this whole item is shaped around refusing.
        return { ok: false, reason: 'unreachable', detail: r.error ?? 'could not reach the host' }
      }
      // stderr is NOT merged into stdout. Every read in the collector redirects
      // its own stderr, so anything on stderr came from the shell or the
      // transport. Merging it would splice unclassified text into the record
      // region where a line beginning `D ` would be read as file content.
      const stdout = r.stdout ?? ''
      if (!stdout.includes(DRIFT_MARKER)) {
        const detail = (r.stderr ?? '').trim().slice(0, 200) || 'the host returned no collector output'
        return { ok: false, reason: 'no-output', detail }
      }
      const parsed = parseDriftCollection(stdout, watches)
      const at = (this.deps.now ?? Date.now)()
      const readings: DriftReading[] = parsed.files.map((f) => {
        const watch = watches.find((w) => w.id === f.watchId) as DriftWatch
        if (f.status !== 'ok' || f.contentB64 === undefined) {
          return { watchId: f.watchId, status: f.status, bytes: f.bytes, detail: f.detail }
        }
        let content: string
        try {
          content = Buffer.from(f.contentB64, 'base64').toString('utf8')
        } catch {
          // Undecodable content is not a file we know anything about, and
          // certainly not one that matches. `unknown`, with the reason.
          return {
            watchId: f.watchId,
            status: 'unknown',
            bytes: f.bytes,
            detail: 'the content could not be decoded'
          }
        }
        return readingFromContent(watch, content, ctx, f.bytes)
      })
      // A collection whose closing marker never arrived is still returned — the
      // per-file records that DID close are real, and the parser has already
      // downgraded any unclosed one to `unknown`. Dropping the whole thing
      // would turn a partially answered host into an uncollected one, which
      // says less.
      if (!parsed.complete && readings.every((x) => x.status === 'unknown')) {
        return { ok: false, reason: 'no-output', detail: 'the collector output was cut off before any file' }
      }
      return { ok: true, drift: { at, readings } }
    } catch (e) {
      return { ok: false, reason: 'unknown', detail: e instanceof Error ? e.message : String(e) }
    }
  }
}

/**
 * Drift as the store wants it: string keys, string values, NO CONTENT.
 *
 * Two hashes and a status per watched file, and the status is written for every
 * watch on every collection — including the ones that could not be read, whose
 * hashes are simply absent. A complete key set on every collection is what
 * makes an unconditional prefix sweep safe on the sampler's side, exactly as it
 * is for `postureToFacts`.
 *
 * The status row is the one that earns its place in history six months from
 * now: `drift:sshd-config:status = denied` still says "nobody was allowed to
 * look" long after the reason is forgotten, where a missing hash alone would be
 * indistinguishable from a host that had not been swept.
 */
export function driftToFacts(drift: HostDrift): Record<string, string> {
  const out: Record<string, string> = {}
  for (const r of drift.readings) {
    out[`${DRIFT_FACT_PREFIX}${r.watchId}:status`] = r.status
    if (r.hash) out[`${DRIFT_FACT_PREFIX}${r.watchId}:hash`] = r.hash
    if (r.normalisedHash) out[`${DRIFT_FACT_PREFIX}${r.watchId}:normalised`] = r.normalisedHash
    // Which rules were doing work, so a change event on the normalised hash can
    // be read later without the file. A list of ids, never file text.
    if (r.applied && r.applied.length) {
      out[`${DRIFT_FACT_PREFIX}${r.watchId}:ignored`] = r.applied.join(',')
    }
    if (r.redacted) out[`${DRIFT_FACT_PREFIX}${r.watchId}:redacted`] = 'true'
  }
  return out
}
