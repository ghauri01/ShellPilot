// Configuration drift — roadmap item 25. The whole model, none of the I/O.
//
// "All twelve web servers have this nginx.conf. Three do not."
//
// ---------------------------------------------------------------------------
// THE HARD PART IS NOT THE DIFF
// ---------------------------------------------------------------------------
//
// Two copies of the same managed file are almost never byte-identical. They
// differ in trailing whitespace, in the hostname the template stamped into
// them, in a `# generated 2026-09-03T04:00:11Z` header, in an `Include` line
// pointing at a per-host drop-in directory, and in comment churn nobody ever
// reads. A naive comparison reports every host as divergent within a day of
// shipping, everybody stops looking, and the feature is dead.
//
// So this file is mostly about NORMALISATION, and about the two ways
// normalisation can lie:
//
//  1. Hidden heuristics. If the app decides for itself that whitespace does
//     not count, an operator staring at two visibly different files being
//     called the same has no way to find out why. Every rule here is DECLARED
//     — it has an id, a label, a sentence saying exactly what it removes, and
//     a worked example — and every watched file names the rules it is compared
//     under. The panel renders that list. There is no rule that is not on it.
//
//  2. Silence. Saying "identical" about two files that differ, because a rule
//     ate the difference, is how this stops being trusted. So a comparison has
//     THREE outcomes where a diff has two: `identical` (byte-for-byte, after
//     redaction), `ignored-difference` (the raw bytes differ and the normalised
//     forms match — here are the rules that were doing work), and `differs`.
//     "Differs in ways I was told to ignore" is a real answer and it is
//     reported as itself, never folded into "same".
//
// ---------------------------------------------------------------------------
// A HOST THAT COULD NOT BE READ IS NOT A HOST THAT MATCHES
// ---------------------------------------------------------------------------
//
// This codebase has been bitten by the inverse repeatedly: a Postgres role that
// got NULL columns and no error rendered as "streaming, 0 bytes behind"; an
// unreadable sshd drop-in was skipped silently while the source reported `ok`;
// `absent` was conflated with "could not read" until the honesty banner became
// permanent wallpaper.
//
// So every reading carries a `DriftStatus` — the same seven-word vocabulary
// `AccessStatus` and `FactStatus` already use, not a parallel one — and only
// `ok` is ever compared. `absent` is its own VERDICT rather than a coverage
// footnote, because "three of them do not have this file" is the answer the
// roadmap sentence asks for. Everything else is `unread`, named in coverage,
// and counted in neither the matching nor the diverging column.
//
// `partial` is deliberately NOT compared. A read capped at the transport limit
// hashes a PREFIX, and two hosts truncated at the same cap with different tails
// would hash identically and be called the same — the exact silent lie above,
// arriving through the back door. A file too big to read whole is reported as
// too big to compare.
//
// ---------------------------------------------------------------------------
// WHAT THIS WILL NOT DO
// ---------------------------------------------------------------------------
//
// It does not push a file to bring a host into line. See DRIFT_NO_PUSH below;
// the argument is stated there in full and asserted in tests/drift.test.ts, the
// same way src/shared/docker.ts states its refusal to ship `docker system
// prune`.

// ---------------------------------------------------------------------------
// Statuses
// ---------------------------------------------------------------------------

/**
 * Why a watched file is missing, or present but qualified.
 *
 * The SAME vocabulary as `AccessStatus` in access.ts and `FactStatus` in
 * hostFacts.ts, deliberately and without additions. A parallel vocabulary would
 * mean a fourth table of near-synonyms for a reader to hold in their head, and
 * every one of these seven means here exactly what it means there.
 */
export type DriftStatus =
  /** The file was read whole. This is the only status that is COMPARED. */
  | 'ok'
  /** The file is larger than the read cap, so only a prefix could be read.
   *  Not compared: a prefix hash calls two files with different tails the
   *  same. */
  | 'partial'
  /** The file genuinely is not on this host, and that was CHECKED — the
   *  directory above it was proven traversable first, so this is never a
   *  permission bit reading as an empty answer. */
  | 'absent'
  /** It exists and this account may not read it, or the directory above it
   *  cannot be traversed. NOT the same as there being nothing there. */
  | 'denied'
  /** The tool that answers this is not installed. `base64` is what the
   *  collector needs and busybox has one; a host without it exists. */
  | 'no-tool'
  /** The path is there and is not a regular file — a directory, a socket, a
   *  device. No amount of privilege turns it into something to compare. */
  | 'unsupported'
  /** The probe ran and its answer could not be read, the collector never
   *  reported on this file, or its content block was cut off in transit.
   *  Never treat as "nothing there" and never as "matches". */
  | 'unknown'

export const DRIFT_STATUSES: DriftStatus[] = [
  'ok',
  'partial',
  'absent',
  'denied',
  'no-tool',
  'unsupported',
  'unknown'
]

/** One sentence per status, written for the person deciding whether to act. */
export const DRIFT_STATUS_HELP: Record<DriftStatus, string> = {
  ok: 'Read in full and compared. A verdict of "identical" here means identical, not "we could not look".',
  partial:
    'The file is larger than the read cap, so only the beginning could be read — and a comparison over the beginning would call two files with different endings the same. It is reported, and not compared.',
  absent: 'This server does not have the file, and that was checked rather than inferred from a failed stat.',
  denied:
    'It exists and this account was not allowed to read it, or the directory above it could not be traversed. This is NOT the same as the file being absent, and it is NOT the same as matching.',
  'no-tool': 'The server has no base64, so the collector had no safe way to carry the content back.',
  unsupported: 'The path exists and is not a regular file. There is nothing here to compare.',
  unknown:
    'The probe ran and this file was not reported on, or its content arrived cut off. Treat as UNKNOWN — never as "none" and never as "the same as everyone else".'
}

// ---------------------------------------------------------------------------
// Normalisation rules — the declared half of the feature
// ---------------------------------------------------------------------------

export type DriftRuleId =
  | 'line-endings'
  | 'include-lines'
  | 'comments'
  | 'timestamps'
  | 'hostnames'
  | 'trailing-space'
  | 'inner-space'
  | 'blank-lines'
  | 'line-order'

export interface DriftRule {
  id: DriftRuleId
  label: string
  /** What it removes, in one sentence, for an operator asking why two visibly
   *  different files are being called the same. */
  detail: string
  /** A worked before/after, because the sentence alone is not enough to
   *  predict what a rule will eat. Rendered next to it in the panel. */
  example: { before: string; after: string }
}

/**
 * The pipeline order.
 *
 * FIXED, and independent of the order a watch lists its rules in. Order
 * changes the result — dropping comments before substituting timestamps means
 * a timestamp inside a comment never needs substituting — and an operator
 * reading a rule list must be reading the order it actually runs in.
 */
export const DRIFT_RULE_ORDER: DriftRuleId[] = [
  'line-endings',
  'include-lines',
  'comments',
  'timestamps',
  'hostnames',
  'trailing-space',
  'inner-space',
  'blank-lines',
  'line-order'
]

export const DRIFT_RULES: DriftRule[] = [
  {
    id: 'line-endings',
    label: 'Line endings',
    detail:
      'Treats a CRLF line ending as a LF one. A file edited on Windows and the same file edited on the server are the same file.',
    example: { before: 'listen 80;\\r\\n', after: 'listen 80;\\n' }
  },
  {
    id: 'include-lines',
    label: 'Include directives',
    detail:
      'Drops whole lines whose first word is include, Include, include_dir, includedir or .include. These point at per-server drop-in directories, so they differ by design — and dropping them means the CONTENT of those drop-ins is not compared either, because this reads one path per server.',
    example: { before: 'Include /etc/ssh/sshd_config.d/*.conf', after: '(line removed)' }
  },
  {
    id: 'comments',
    label: 'Whole-line comments',
    detail:
      "Drops lines whose first non-blank character is the watched file's comment character. Only WHOLE-line comments: a trailing comment after a directive is left alone, because deciding where a comment starts inside a line means knowing the file's quoting rules, and getting that wrong silently changes a directive.",
    example: { before: '# managed by puppet', after: '(line removed)' }
  },
  {
    id: 'timestamps',
    label: 'Dates and times',
    detail:
      'Replaces ISO dates, ISO date-times, bare HH:MM:SS clock times and ten-digit unix seconds with a placeholder. This is what a "generated at" header churns on. It also hides a genuine difference between two dates that are both dates — a certificate validity line, for instance — so it is off for files where a date is the setting.',
    example: { before: '# generated 2026-09-03T04:00:11Z', after: '# generated <date>T<time>Z' }
  },
  {
    id: 'hostnames',
    label: "The server's own name",
    detail:
      "Replaces this server's hostname, its short name and the server's name in ShellPilot with a placeholder, case-insensitively. A template that stamps the machine's name into a file makes every copy unique; this is what makes them comparable. It cannot see a per-server name it was not told about.",
    example: { before: 'server_name web-03.example.internal;', after: 'server_name <host>.example.internal;' }
  },
  {
    id: 'trailing-space',
    label: 'Trailing whitespace',
    detail: 'Removes spaces and tabs at the end of a line. Nothing reads them and every editor treats them differently.',
    example: { before: 'worker_processes 4;   ', after: 'worker_processes 4;' }
  },
  {
    id: 'inner-space',
    label: 'Runs of spaces inside a line',
    detail:
      'Collapses a run of spaces or tabs BETWEEN two tokens down to one space. Leading indentation is left exactly as it is, because in a YAML file indentation is the syntax.',
    example: { before: 'PermitRootLogin\tno', after: 'PermitRootLogin no' }
  },
  {
    id: 'blank-lines',
    label: 'Blank lines',
    detail:
      "Drops lines that are empty or contain only whitespace. A file's final newline is its terminator rather than a blank line, so whether a file ends with one stops being a difference — and this rule does not report itself as having done work merely because a file ended properly.",
    example: { before: '(an empty line)', after: '(line removed)' }
  },
  {
    id: 'line-order',
    label: 'Line order',
    detail:
      'Sorts the remaining lines, so two files with the same lines in a different order compare equal. The loudest rule here: in a file where order is meaning — an nginx location block, an iptables ruleset — this will call two genuinely different configurations the same. It is off unless the watched file is a set rather than a sequence.',
    example: { before: 'b\\na', after: 'a\\nb' }
  }
]

export function driftRule(id: DriftRuleId): DriftRule {
  const r = DRIFT_RULES.find((x) => x.id === id)
  // Not a throw: an unknown id can only arrive from a stored watch written by
  // a newer version, and a panel that crashed on one would be worse than a
  // panel that says it does not know what the rule does.
  return (
    r ?? {
      id,
      label: id,
      detail: 'This version of ShellPilot does not know what this rule does, so it is not applied.',
      example: { before: '', after: '' }
    }
  )
}

// ---------------------------------------------------------------------------
// What is watched
// ---------------------------------------------------------------------------

export interface DriftWatch {
  id: string
  label: string
  /** An absolute path, a literal, and never built from anything a host said.
   *  Every one of these is embedded in the collector script as-is. */
  path: string
  /** The comment character the `comments` rule uses for this file. */
  comment: string
  /** The rules this file is compared under. Rendered in the panel, in
   *  DRIFT_RULE_ORDER, with each rule's own sentence beside it. */
  rules: DriftRuleId[]
  /** Why this rule set and not another — the sentence an operator reads when
   *  they disagree with a verdict. */
  note: string
}

/**
 * The catalogue.
 *
 * A FIXED list rather than something an operator types a path into, and that is
 * a real limitation worth stating rather than hiding: "snapshot a file on one
 * host" in the roadmap implies picking the file. What a free-text path would
 * need before it could ship is a stored watch definition with its own rule
 * selection, an approval story for reading an arbitrary path on every host in
 * the estate once an hour, and a much harder answer to the secrets question
 * below — `/etc/nginx/nginx.conf` is a known quantity, `whatever the operator
 * typed` is not.
 *
 * Every path here is a configuration file that is meant to be the same across a
 * role, and none of them is a credential store. That is a property of the LIST,
 * not of the reader, which is why the list is fixed.
 */
export const DRIFT_WATCHES: DriftWatch[] = [
  {
    id: 'sshd-config',
    label: 'sshd configuration',
    path: '/etc/ssh/sshd_config',
    comment: '#',
    rules: [
      'line-endings',
      'include-lines',
      'comments',
      'trailing-space',
      'inner-space',
      'blank-lines'
    ],
    note: 'Include lines are dropped because a drop-in directory is per-server by design. Order is NOT normalised: in sshd_config the first occurrence of a keyword wins, so two files with the same lines in a different order are two different configurations.'
  },
  {
    id: 'nginx-conf',
    label: 'nginx.conf',
    path: '/etc/nginx/nginx.conf',
    comment: '#',
    rules: [
      'line-endings',
      'include-lines',
      'comments',
      'hostnames',
      'trailing-space',
      'inner-space',
      'blank-lines'
    ],
    note: 'Hostnames are substituted because server_name is templated per server. Order is not normalised: location matching is ordered.'
  },
  {
    id: 'resolv-conf',
    label: 'resolv.conf',
    path: '/etc/resolv.conf',
    comment: '#',
    rules: ['line-endings', 'comments', 'trailing-space', 'inner-space', 'blank-lines'],
    note: 'Order is not normalised: nameserver lines are tried in the order they appear, so a server that lists the secondary first is genuinely different.'
  },
  {
    id: 'hosts',
    label: '/etc/hosts',
    path: '/etc/hosts',
    comment: '#',
    rules: [
      'line-endings',
      'comments',
      'hostnames',
      'trailing-space',
      'inner-space',
      'blank-lines',
      'line-order'
    ],
    note: 'The one watch with line-order on: /etc/hosts is a lookup table, not a sequence, and every server has its own name in it — which the hostnames rule substitutes so the tables can be compared at all.'
  },
  {
    id: 'sysctl-conf',
    label: 'sysctl.conf',
    path: '/etc/sysctl.conf',
    comment: '#',
    rules: [
      'line-endings',
      'comments',
      'trailing-space',
      'inner-space',
      'blank-lines',
      'line-order'
    ],
    note: 'Order is normalised: sysctl.conf is a set of key = value settings and the last assignment wins, so two files with the same assignments in a different order do apply the same kernel settings.'
  },
  {
    id: 'chrony-conf',
    label: 'chrony.conf',
    path: '/etc/chrony/chrony.conf',
    comment: '#',
    rules: [
      'line-endings',
      'include-lines',
      'comments',
      'trailing-space',
      'inner-space',
      'blank-lines'
    ],
    note: 'Time sources drifting apart across a fleet is the classic cause of "the logs do not line up". Order is not normalised: chrony tries sources in order.'
  },
  {
    id: 'timezone',
    label: '/etc/timezone',
    path: '/etc/timezone',
    comment: '#',
    rules: ['line-endings', 'trailing-space', 'blank-lines'],
    note: 'One line. Almost nothing is normalised because there is almost nothing to normalise, which makes it the cheapest illustration of what a clean comparison looks like.'
  }
]

export function driftWatch(id: string): DriftWatch | undefined {
  return DRIFT_WATCHES.find((w) => w.id === id)
}

// ---------------------------------------------------------------------------
// Normalisation
// ---------------------------------------------------------------------------

export interface DriftNormaliseContext {
  /** The host's own hostname, as the metrics probe reported it. */
  hostname?: string
  /** The server's name in ShellPilot, which is often the short hostname. */
  serverName?: string
  /**
   * The comment character the `comments` rule uses, from the WATCH.
   *
   * Passed in rather than sniffed from the file. Guessing it means guessing
   * wrong on the one file where `;` is a value, and a rule that removes lines
   * has to be predictable from its declaration alone.
   */
  comment?: string
}

export interface DriftNormalised {
  text: string
  /**
   * The rules that ACTUALLY CHANGED this file. Not the rules that were
   * enabled — the ones that did something.
   *
   * This is what turns "these two files match" into "these two files match
   * because of these rules", which is the difference between a feature an
   * operator trusts and one they stop opening.
   */
  applied: DriftRuleId[]
}

const ISO_DATE = /\d{4}-\d{2}-\d{2}/g
const CLOCK = /\b\d{2}:\d{2}:\d{2}(?:\.\d+)?\b/g
const UNIX_SECONDS = /\b1[0-9]{9}\b/g
const INCLUDE_LINE = /^\s*(?:\.?include(?:_dir|dir)?)\b/i

function escapeRegExp(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
}

/**
 * Apply a watch's rules, and report which of them did anything.
 *
 * Runs in DRIFT_RULE_ORDER whatever order `rules` is in — see the note there.
 * An unknown rule id is ignored rather than throwing, and because it is not in
 * `applied` it can never be quoted as the reason two files matched.
 */
export function normaliseConfig(
  text: string,
  rules: DriftRuleId[],
  ctx: DriftNormaliseContext = {}
): DriftNormalised {
  const on = new Set(rules)
  const applied: DriftRuleId[] = []
  // `changed` compares against what the text was BEFORE this rule, so a rule
  // that is enabled and finds nothing to do is honestly not listed.
  const step = (id: DriftRuleId, next: string, before: string): string => {
    if (next !== before) applied.push(id)
    return next
  }

  let body = text
  if (on.has('line-endings')) body = step('line-endings', body.replace(/\r\n/g, '\n').replace(/\r/g, '\n'), body)

  let lines = body.split('\n')

  if (on.has('include-lines')) {
    const before = lines
    lines = lines.filter((l) => !INCLUDE_LINE.test(l))
    if (lines.length !== before.length) applied.push('include-lines')
  }

  if (on.has('comments')) {
    const mark = ctx.comment ?? '#'
    const before = lines
    lines = lines.filter((l) => !l.trimStart().startsWith(mark))
    if (lines.length !== before.length) applied.push('comments')
  }

  body = lines.join('\n')

  if (on.has('timestamps')) {
    body = step(
      'timestamps',
      body.replace(ISO_DATE, '<date>').replace(CLOCK, '<time>').replace(UNIX_SECONDS, '<epoch>'),
      body
    )
  }

  if (on.has('hostnames')) {
    // Longest first, so replacing the short name does not leave the tail of the
    // FQDN behind as a difference of its own.
    const names = [ctx.hostname, ctx.serverName, ctx.hostname?.split('.')[0], ctx.serverName?.split('.')[0]]
      .filter((n): n is string => typeof n === 'string' && n.trim().length >= 2)
      .sort((a, b) => b.length - a.length)
    let next = body
    for (const n of names) next = next.replace(new RegExp(escapeRegExp(n), 'gi'), '<host>')
    body = step('hostnames', next, body)
  }

  if (on.has('trailing-space')) body = step('trailing-space', body.replace(/[ \t]+$/gm, ''), body)
  if (on.has('inner-space')) {
    // `(\S)[ \t]{2,}` and not `[ \t]{2,}`: the leading indentation of a line has
    // no non-space before it, so it is never touched. In a YAML file the
    // indentation is the syntax, and collapsing it would silently reparent a
    // key.
    body = step('inner-space', body.replace(/(\S)[ \t]+/g, '$1 '), body)
  }

  if (on.has('blank-lines')) {
    const before = body.split('\n')
    // A file's final newline produces one empty trailing element, and that is
    // the file TERMINATOR rather than a blank line. Counting it would make this
    // rule report itself as having done work on almost every file that exists,
    // and `ignoredBy` — the list an operator reads to find out why two files
    // were called the same — would be noise on every row.
    if (before.length > 0 && before[before.length - 1] === '') before.pop()
    const kept = before.filter((l) => l.trim() !== '')
    if (kept.length !== before.length) applied.push('blank-lines')
    body = kept.join('\n')
  }

  if (on.has('line-order')) {
    const before = body.split('\n')
    const sorted = [...before].sort()
    if (sorted.join('\n') !== before.join('\n')) applied.push('line-order')
    body = sorted.join('\n')
  }

  return { text: body, applied }
}

/**
 * Normalise one file the way its watch declares.
 *
 * The entry point callers should use: it takes the rule list AND the comment
 * character from the same declaration, so the two can never drift apart.
 */
export function normaliseForWatch(
  text: string,
  watch: DriftWatch,
  ctx: DriftNormaliseContext = {}
): DriftNormalised {
  return normaliseConfig(text, watch.rules, { ...ctx, comment: watch.comment })
}

// ---------------------------------------------------------------------------
// The collector protocol
// ---------------------------------------------------------------------------

export const DRIFT_MARKER = '===SHELLPILOT-DRIFT==='
export const DRIFT_STATUS_MARKER = '===SHELLPILOT-DRIFT-STATUS==='

/**
 * The biggest file the collector will carry back, in bytes.
 *
 * A file bigger than this is reported `partial` and its CONTENT IS NOT SENT AT
 * ALL. That is the important half: the alternative — send the first 256 KiB —
 * splits whatever is at the boundary, and if what is at the boundary is the
 * middle of a PEM block then the `-----END ... PRIVATE KEY-----` line never
 * arrives, the redaction pattern that needs both ends matches nothing, and the
 * key body ships as prose. Refusing the read is the only version of this with
 * no cliff in it.
 *
 * 256 KiB is about forty times the largest stock nginx.conf.
 */
export const DRIFT_READ_CAP = 262_144

/**
 * How much redacted content is kept for the side-by-side view, in characters.
 *
 * Bounded, and the bound is stated on screen. Nothing of this is written to the
 * durable store — see DriftReading.preview.
 */
export const DRIFT_PREVIEW_CHARS = 4_000

/**
 * The read command.
 *
 * Same discipline as cron.ts, hostFacts.ts, access.ts and posture.ts: no
 * `set -e`, every read conditional, every path a literal from DRIFT_WATCHES,
 * and nothing the host says is ever interpolated into a follow-up command.
 *
 * NO SUDO, anywhere, at build time rather than guarded at runtime — so "this
 * command contains no sudo" is a property a reader can check and a test does.
 * Every watched path is world-readable on a stock install; a host where one is
 * not answers `denied`, which is a true statement about what this account can
 * see and is a great deal better than teaching a background sweep to read
 * configuration files as root once an hour.
 *
 * CONTENT IS BASE64. The alternative is dumping file text between markers,
 * which is fine in cron.ts and is not fine here: a watched file is exactly the
 * sort of place a line reading `===SHELLPILOT-DRIFT-STATUS===` could be
 * planted. Base64's alphabet contains no space, no `-` and no `=` except as
 * terminator, and every content line is prefixed anyway, so file content cannot
 * forge a record tag or a marker.
 */
export function buildDriftCommand(opts: { watches?: DriftWatch[]; cap?: number } = {}): string {
  const watches = opts.watches ?? DRIFT_WATCHES
  const cap = opts.cap ?? DRIFT_READ_CAP
  const parts: string[] = [
    'SP_B64=""; for c in base64 /usr/bin/base64 /bin/base64; do ' +
      'command -v "$c" >/dev/null 2>&1 && SP_B64="$c" && break; done',
    `SP_CAP=${cap}`,
    `printf '%s\\n' '${DRIFT_MARKER}'`
  ]
  for (const w of watches) {
    // `${p%/*}` rather than dirname: one fewer binary to depend on, and every
    // path here is absolute so the expansion always yields the parent.
    const dir = w.path.replace(/\/[^/]*$/, '') || '/'
    parts.push(
      [
        // Traversal FIRST. `[ -e ]` on a path inside a directory this account
        // cannot traverse returns false, which is indistinguishable from the
        // file not being there — and reporting `absent` for a permission bit
        // is the single most likely way this feature could lie. access.ts
        // learned this the same way.
        `if [ ! -x '${dir}' ]; then printf 'F %s denied -\\n' '${w.id}';`,
        `elif [ ! -e '${w.path}' ]; then printf 'F %s absent -\\n' '${w.id}';`,
        `elif [ ! -f '${w.path}' ]; then printf 'F %s unsupported -\\n' '${w.id}';`,
        `elif [ ! -r '${w.path}' ]; then printf 'F %s denied -\\n' '${w.id}';`,
        `elif [ -z "$SP_B64" ]; then printf 'F %s no-tool -\\n' '${w.id}';`,
        `else SP_N=$(wc -c < '${w.path}' 2>/dev/null | tr -d ' '); [ -n "$SP_N" ] || SP_N=0;`,
        `if [ "$SP_N" -gt "$SP_CAP" ]; then printf 'F %s partial %s\\n' '${w.id}' "$SP_N";`,
        `else printf 'F %s ok %s\\n' '${w.id}' "$SP_N";`,
        `"$SP_B64" < '${w.path}' 2>/dev/null | sed 's/^/D /';`,
        // The closing record. A content block with no `X` behind it was cut
        // off in transit, and the parser refuses it rather than hashing a
        // fragment.
        `printf 'X %s\\n' '${w.id}'; fi; fi`
      ].join(' ')
    )
  }
  // Printed from a shell literal that nothing read from a file ever touched, so
  // its presence really does mean the script reached the end.
  parts.push(`printf '%s\\n' '${DRIFT_STATUS_MARKER}'`)
  return parts.join('\n')
}

/** One watched file as the host reported it, before any redaction. */
export interface DriftFileRead {
  watchId: string
  status: DriftStatus
  /** Size in bytes as the host measured it, where it got that far. */
  bytes?: number
  /** Base64 of the file, present only for `ok`. */
  contentB64?: string
  detail?: string
}

export interface DriftCollection {
  files: DriftFileRead[]
  /** The script printed its closing marker. False means the output was cut
   *  off, and every file with no record of its own is `unknown`. */
  complete: boolean
}

/**
 * Parse the collector's output.
 *
 * Every watch in `watches` gets a record, including the ones the host never
 * mentioned — those come back `unknown`, never absent from the list. A watch
 * silently missing from a result is a watch nobody notices is not being
 * checked.
 */
export function parseDriftCollection(out: string, watches: DriftWatch[] = DRIFT_WATCHES): DriftCollection {
  const seen = new Map<string, DriftFileRead>()
  const body = out.includes(DRIFT_MARKER) ? out.slice(out.indexOf(DRIFT_MARKER) + DRIFT_MARKER.length) : ''
  const complete = out.includes(DRIFT_STATUS_MARKER)
  let open: { id: string; chunks: string[] } | null = null

  for (const raw of body.split('\n')) {
    const line = raw.endsWith('\r') ? raw.slice(0, -1) : raw
    if (line.startsWith('D ')) {
      if (open) open.chunks.push(line.slice(2))
      continue
    }
    if (line.startsWith('X ')) {
      const id = line.slice(2).trim()
      const rec = seen.get(id)
      if (open && open.id === id && rec) rec.contentB64 = open.chunks.join('')
      open = null
      continue
    }
    if (!line.startsWith('F ')) continue
    const [id, status, size] = line.slice(2).split(' ')
    if (!id) continue
    const known = DRIFT_STATUSES.includes(status as DriftStatus) ? (status as DriftStatus) : 'unknown'
    const bytes = size !== undefined && /^\d+$/.test(size) ? Number(size) : undefined
    const rec: DriftFileRead = { watchId: id, status: known, bytes }
    seen.set(id, rec)
    open = known === 'ok' ? { id, chunks: [] } : null
  }

  return {
    complete,
    files: watches.map((w) => {
      const rec = seen.get(w.id)
      if (!rec) {
        return {
          watchId: w.id,
          status: 'unknown',
          detail: 'the collector did not report on this file'
        }
      }
      if (rec.status === 'ok' && rec.contentB64 === undefined) {
        // An `ok` header with no closed content block. The output was cut off
        // mid-file, and a hash of a fragment is exactly the lie `partial`
        // exists to refuse — so it is not one, it is `unknown`.
        return {
          watchId: w.id,
          status: 'unknown',
          bytes: rec.bytes,
          detail: 'the content block was cut off before it finished'
        }
      }
      return rec
    })
  }
}

// ---------------------------------------------------------------------------
// A reading — what a host contributes to a comparison
// ---------------------------------------------------------------------------

/**
 * One watched file on one host, AFTER redaction and hashing.
 *
 * WHAT IS AND IS NOT KEPT, because this is the part the roadmap's own sizing
 * note singles out. `hash` and `normalisedHash` are what answer "do these
 * differ", and they are the only two things written to the durable store.
 * `preview` is bounded, redacted, and lives in the sampler's memory for the
 * side-by-side view — it is never a fact and never survives a restart.
 */
export interface DriftReading {
  watchId: string
  status: DriftStatus
  detail?: string
  bytes?: number
  /** Hash of the file as read, AFTER redaction. Absent unless `status` is
   *  `ok`. */
  hash?: string
  /** Hash of the normalised form of that same redacted text. */
  normalisedHash?: string
  /** Which declared rules actually changed this file. */
  applied?: DriftRuleId[]
  /**
   * Secret-shaped text was replaced before either hash was taken.
   *
   * Surfaced rather than kept quiet: redaction is a comparison hazard as well
   * as a safety measure. Two hosts whose only difference is inside a redacted
   * span hash the same and are reported identical, and an operator has to be
   * able to know that happened.
   */
  redacted?: boolean
  /** Bounded redacted text for the side-by-side view. In memory only. */
  preview?: string
}

export interface HostDrift {
  at: number
  readings: DriftReading[]
}

export function driftReading(drift: HostDrift | undefined, watchId: string): DriftReading | undefined {
  return drift?.readings.find((r) => r.watchId === watchId)
}

// ---------------------------------------------------------------------------
// Comparison
// ---------------------------------------------------------------------------

export type DriftVerdict =
  /** The host the others are compared against. */
  | 'baseline'
  /** Byte-for-byte the same as the baseline, after redaction. */
  | 'identical'
  /** The bytes differ and the normalised forms match. The difference is inside
   *  what the declared rules remove. Reported as ITSELF — never as
   *  `identical`. */
  | 'ignored-difference'
  /** Genuinely different. */
  | 'differs'
  /** The file is not on this host, and that was checked. */
  | 'absent'
  /** Could not be compared. `status` says which kind of could-not. NEVER
   *  counted as matching. */
  | 'unread'

export interface DriftHostResult {
  serverId: string
  serverName: string
  verdict: DriftVerdict
  status: DriftStatus
  detail?: string
  bytes?: number
  /**
   * For `ignored-difference`: the declared rules that changed EITHER this file
   * or the baseline's.
   *
   * Candidates, and the wording on screen says so. Proving which single rule is
   * load-bearing would mean re-normalising both files once per rule with that
   * rule removed, which needs both files' contents — and not keeping those is
   * the storage decision above. Naming the rules that were doing work is what
   * can be said honestly from two hashes and two rule lists.
   */
  ignoredBy?: DriftRuleId[]
  redacted?: boolean
  /** When this host's reading was collected. */
  at?: number
}

/**
 * Which hosts are not in the comparison, and why — each in its own bucket.
 *
 * Modelled on FleetCoverage in renderer/src/lib/fleetSearch.ts, including the
 * part that matters: the gap buckets are DISJOINT and every one of them names
 * hosts rather than counting them, because "3 hosts could not be read" prompts
 * the question this is supposed to answer.
 *
 * `compared` is the denominator and overlaps `redacted` deliberately — a host
 * whose file had a secret in it was still compared.
 */
export interface DriftCoverage {
  /** Read in full and compared. */
  compared: string[]
  /** The file is genuinely not there. A finding, not a gap — and its own
   *  bucket so it is never counted as either. */
  absent: string[]
  /** No drift collection for this host at all: never swept, or the whole
   *  probe failed. */
  notCollected: string[]
  /** Too big for the read cap, so not compared. */
  tooLarge: string[]
  denied: string[]
  noTool: string[]
  unsupported: string[]
  unknown: string[]
  /** Compared, and secret-shaped text was replaced first. Overlaps
   *  `compared`. */
  redacted: string[]
}

export interface DriftComparisonInput {
  watch: DriftWatch
  hosts: { serverId: string; serverName: string; drift?: HostDrift; error?: string }[]
  /** Pin a host as the reference. Without one, the largest group of matching
   *  normalised hashes is used and `baselineChosen` says so. */
  baselineServerId?: string
}

export interface DriftComparison {
  watch: DriftWatch
  baselineServerId: string | null
  /** True when nobody pinned a baseline and the majority was used. The panel
   *  says which, because "three hosts differ" and "three hosts differ from a
   *  host we picked for you" are different sentences. */
  baselineChosen: boolean
  results: DriftHostResult[]
  coverage: DriftCoverage
  /** Hosts whose normalised form matches the baseline: identical plus
   *  ignored-difference. The number the headline sentence uses. */
  matching: number
  diverging: number
}

const STATUS_BUCKET: Record<DriftStatus, keyof DriftCoverage | null> = {
  ok: null,
  partial: 'tooLarge',
  absent: 'absent',
  denied: 'denied',
  'no-tool': 'noTool',
  unsupported: 'unsupported',
  unknown: 'unknown'
}

export function compareDrift(input: DriftComparisonInput): DriftComparison {
  const coverage: DriftCoverage = {
    compared: [],
    absent: [],
    notCollected: [],
    tooLarge: [],
    denied: [],
    noTool: [],
    unsupported: [],
    unknown: [],
    redacted: []
  }

  // One pass to read every host's reading for this watch, then a second to
  // decide verdicts — the baseline may be any of them.
  const rows = input.hosts.map((h) => {
    const reading = driftReading(h.drift, input.watch.id)
    return { ...h, reading }
  })

  for (const r of rows) {
    if (!r.drift || !r.reading) {
      coverage.notCollected.push(r.serverName)
      continue
    }
    const bucket = STATUS_BUCKET[r.reading.status]
    if (bucket) coverage[bucket].push(r.serverName)
    else {
      coverage.compared.push(r.serverName)
      if (r.reading.redacted) coverage.redacted.push(r.serverName)
    }
  }

  // Choose the baseline. A pinned host that could not be read is NOT silently
  // replaced by a majority: it is dropped and `baselineServerId` goes null, so
  // the panel says "the host you pinned could not be read" instead of quietly
  // comparing against somebody else.
  const comparable = rows.filter((r) => r.reading?.status === 'ok' && r.reading.normalisedHash)
  let baseline = input.baselineServerId
    ? comparable.find((r) => r.serverId === input.baselineServerId)
    : undefined
  let baselineChosen = false
  if (!baseline && !input.baselineServerId) {
    const counts = new Map<string, number>()
    for (const r of comparable) {
      const k = r.reading?.normalisedHash as string
      counts.set(k, (counts.get(k) ?? 0) + 1)
    }
    let best: string | null = null
    let bestN = 0
    for (const [k, n] of counts) {
      if (n > bestN) {
        best = k
        bestN = n
      }
    }
    if (best !== null) {
      // Deterministic within the winning group: sorted by name, so the same
      // estate always produces the same reference and a verdict does not move
      // between refreshes.
      baseline = [...comparable]
        .filter((r) => r.reading?.normalisedHash === best)
        .sort((a, b) => a.serverName.localeCompare(b.serverName))[0]
      baselineChosen = true
    }
  }

  const baseHash = baseline?.reading?.hash
  const baseNorm = baseline?.reading?.normalisedHash
  const baseApplied = baseline?.reading?.applied ?? []

  const results: DriftHostResult[] = rows.map((r) => {
    const reading = r.reading
    const common = {
      serverId: r.serverId,
      serverName: r.serverName,
      at: r.drift?.at,
      bytes: reading?.bytes,
      redacted: reading?.redacted
    }
    if (!r.drift || !reading) {
      return {
        ...common,
        verdict: 'unread' as const,
        status: 'unknown' as const,
        detail: r.error ?? 'this server has not been collected yet'
      }
    }
    if (reading.status === 'absent') {
      return { ...common, verdict: 'absent' as const, status: 'absent' as const, detail: reading.detail }
    }
    if (reading.status !== 'ok' || !reading.normalisedHash) {
      return { ...common, verdict: 'unread' as const, status: reading.status, detail: reading.detail }
    }
    if (baseline && r.serverId === baseline.serverId) {
      return { ...common, verdict: 'baseline' as const, status: 'ok' as const }
    }
    if (baseNorm === undefined) {
      // Nothing to compare against — every readable host is its own island.
      return { ...common, verdict: 'unread' as const, status: 'ok' as const, detail: 'no baseline to compare against' }
    }
    if (reading.normalisedHash !== baseNorm) {
      return { ...common, verdict: 'differs' as const, status: 'ok' as const }
    }
    if (reading.hash === baseHash) {
      return { ...common, verdict: 'identical' as const, status: 'ok' as const }
    }
    // The case this whole file exists for. The bytes differ; the normalised
    // forms do not. Say so, and name the rules that were doing work on either
    // side rather than calling it "the same".
    const ignoredBy = DRIFT_RULE_ORDER.filter(
      (id) => (reading.applied ?? []).includes(id) || baseApplied.includes(id)
    )
    return { ...common, verdict: 'ignored-difference' as const, status: 'ok' as const, ignoredBy }
  })

  const matching = results.filter((r) => r.verdict === 'baseline' || r.verdict === 'identical' || r.verdict === 'ignored-difference').length
  const diverging = results.filter((r) => r.verdict === 'differs').length

  return {
    watch: input.watch,
    baselineServerId: baseline?.serverId ?? null,
    baselineChosen,
    results,
    coverage,
    matching,
    diverging
  }
}

/**
 * One sentence describing what was and was not compared.
 *
 * Returns null only when every host was read and compared — the one case where
 * silence is accurate. Every clause NAMES hosts rather than counting them, for
 * the reason coverageSentence in fleetSearch.ts does.
 */
export function driftCoverageSentence(c: DriftCoverage): string | null {
  const list = (names: string[]): string =>
    names.length <= 3 ? names.join(', ') : `${names.slice(0, 3).join(', ')} and ${names.length - 3} more`
  const parts: string[] = []
  if (c.notCollected.length) parts.push(`${list(c.notCollected)} have not been collected yet`)
  if (c.denied.length) parts.push(`${list(c.denied)} would not let this account read it — that is not the same as matching`)
  if (c.tooLarge.length) parts.push(`too large to compare on ${list(c.tooLarge)}`)
  if (c.noTool.length) parts.push(`no base64 on ${list(c.noTool)}`)
  if (c.unsupported.length) parts.push(`the path is not a regular file on ${list(c.unsupported)}`)
  if (c.unknown.length) parts.push(`${list(c.unknown)} did not report on it`)
  if (c.redacted.length) {
    parts.push(
      `secret-shaped text was replaced before comparing on ${list(c.redacted)}, so a difference inside it is invisible here`
    )
  }
  if (parts.length === 0) return null
  const n = c.compared.length
  return `Compared on ${n} server${n === 1 ? '' : 's'} — ${parts.join('; ')}.`
}

// ---------------------------------------------------------------------------
// What this will not do
// ---------------------------------------------------------------------------

/**
 * The refusal, stated the way src/shared/docker.ts states its refusal to ship
 * `docker system prune`, and asserted in tests/drift.test.ts.
 *
 * The obvious next button on a panel that has just told you three hosts differ
 * from nine is "make them match". It is not here and it is not coming here.
 *
 *  * It would be a SECOND EXECUTION PATH beside the job engine. Everything in
 *    this app that changes a host goes through a plan the operator reads, an
 *    approval minted against that exact plan and target list, and a runner that
 *    re-derives both before it touches anything. A write bolted onto a read
 *    panel has none of that, and the second one is always the one with the
 *    weaker story — see the access module, whose write half needed a dead-man's
 *    switch, a staged rollback and a re-derived plan before it could exist at
 *    all, and is still gated off.
 *
 *  * The blast radius is not knowable from this panel. "Three hosts differ" is
 *    a statement about a hash. It does not say whether the three are wrong or
 *    whether the nine are — a canary that was upgraded first looks exactly like
 *    a host that drifted — and pushing the majority's file over the minority's
 *    is how a fleet loses the one machine that had the fix.
 *
 *  * The normalisation rules make it worse, not better. This panel deliberately
 *    calls two files "the same" when their difference is inside what a rule
 *    removes. A push would overwrite exactly those per-host differences the
 *    rules exist to tolerate — the hostname in the template, the include
 *    pointing at the drop-in — which is the one class of change the comparison
 *    is least equipped to have an opinion about.
 *
 * Copying a file to a set of hosts is a job. It is spelled as one, with the
 * plan and the approval a job carries.
 */
export const DRIFT_NO_PUSH =
  'Configuration drift reads and compares. It never writes a file to a server to bring it into line: ' +
  'that is a job, and it goes through a plan you read and an approval minted against it, not a button ' +
  'on a comparison. Nor could this panel decide which side is right — a server that was fixed first and a ' +
  'server that drifted look the same from here.'
