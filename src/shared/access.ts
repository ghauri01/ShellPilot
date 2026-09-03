// Who can get into a host, and with which key — roadmap item 23, the read half.
//
// One `authorized_keys` file per user per host is the whole dataset, and no GUI
// SSH client inventories it. "Which of my fifteen hosts still trusts the laptop
// I sold" is the question; the answer is a fingerprint, seen on a list of hosts.
//
// Adjacent and nearly free once the reader exists, so collected in the same
// round trip: whether an account's password is locked, whether the account has
// expired, which administrative groups it is in, and when it last logged in
// where the host will say.
//
// ---------------------------------------------------------------------------
// The honesty requirement, which IS the feature
// ---------------------------------------------------------------------------
//
// A host whose `authorized_keys` could not be read is NOT a host with no keys.
// That sentence is the entire reason this file is shaped the way it is:
//
//  1. Every per-account key list is `AuthorizedKey[] | null`, and every null
//     carries an `AccessStatus` saying which kind of null it is. `denied`,
//     `absent`, `no-tool` and `unsupported` are four different answers with four
//     different fixes and they never collapse into one.
//
//  2. `absent` is only ever claimed when it was actually checked. A home
//     directory that this account cannot traverse makes `[ -e ~/.ssh/authorized_keys ]`
//     return false, which is indistinguishable from the file not being there —
//     so the collector tests the traversal FIRST and reports `denied` rather
//     than letting a permission bit read as an empty inventory. That is the
//     single most likely way this feature could lie, and it is checked before
//     anything else.
//
//  3. Counts are reported alongside the number of accounts they could NOT be
//     read for. `summariseAccess` refuses to answer "are there unknown keys
//     here" at all when any account is unreadable — see `AccessSummary.certain`.
//     A "no unknown keys" conclusion drawn over a host that hid half its
//     accounts is worse than no conclusion.
//
// ---------------------------------------------------------------------------
// Why the output format is stricter than cron.ts's
// ---------------------------------------------------------------------------
//
// `authorized_keys` is attacker-controlled text on a host that may already be
// compromised, and a key comment is free-form. cron.ts dumps file text between
// section markers, which is fine there and would not be fine here: a key
// comment reading `===SHELLPILOT-ACCESS===` would forge a section boundary.
//
// So this borrows hostFacts.ts's stricter discipline and extends it to a
// multi-record stream. EVERY line the collector emits is a tagged record —
// `V`, `U`, `S`, `L` or `K` — whose payload has had control characters DELETED
// ON THE HOST and is length-capped there. A value therefore cannot become a
// second line, cannot forge a record tag it is not already inside, and cannot
// forge the status marker, which stays the only structural token and is still
// printed once at the end out of a shell variable nothing read from a file ever
// touched.
//
// Otherwise the same rules as cron.ts and hostFacts.ts: no `set -e`, every read
// conditional or `|| true`, and sudo omitted at BUILD time rather than guarded
// at runtime, so "this command contains no sudo" is a property a reader can
// check. tests/access.test.ts asserts exactly that.
//
// ---------------------------------------------------------------------------
// What is deliberately NOT read
// ---------------------------------------------------------------------------
//
// /etc/shadow. Lock state comes from `passwd -S -a`, which is one call, needs
// root once rather than once per account, and — the point — never puts a
// password hash into the output at all. Reading the file and stripping the hash
// in TypeScript would work right up until a malformed line moved a field, and
// the failure mode is a password hash in a log.
//
// Private keys, anywhere. This reads the file that says which keys a host
// TRUSTS. It never reads `~/.ssh/id_*`.

import { SUDO_PROBE, resolveBinary } from './docker'

// ---- Statuses -------------------------------------------------------------

/**
 * Why something here is missing, or present but qualified.
 *
 * Deliberately the same vocabulary as `FactStatus` in hostFacts.ts, minus the
 * two that cannot occur (`stale-metadata` — nothing here is cached) and plus
 * `partial`, which cron.ts already needed for the same reason: a directory
 * where four of six files were readable is not `ok` and is not `denied`.
 */
export type AccessStatus =
  /** Read it. An empty list here really is empty. */
  | 'ok'
  /** Read some of it. Some accounts or files answered and others did not. */
  | 'partial'
  /** The thing genuinely is not on this host, and that was CHECKED — not
   *  inferred from a stat this account was not allowed to perform. */
  | 'absent'
  /** It exists and this account may not read it. A different account, or sudo,
   *  would see more. */
  | 'denied'
  /** The tool that answers this is not installed. */
  | 'no-tool'
  /** This host cannot answer this question at all. Busybox `passwd` has no
   *  `-S`, so no lock state exists to read on Alpine however privileged we are.
   *  Distinct from `denied`, and no amount of root changes it. */
  | 'unsupported'
  /** The probe ran and its answer could not be read, or the collector never
   *  reported on it. Never treat as "nothing there". */
  | 'unknown'

export const ACCESS_STATUSES: AccessStatus[] = [
  'ok',
  'partial',
  'absent',
  'denied',
  'no-tool',
  'unsupported',
  'unknown'
]

/**
 * One sentence per status, written for the person deciding whether to act on
 * what is next to it. `denied` gets the most actionable one because it is the
 * only status a person can do something about immediately.
 */
export const ACCESS_STATUS_HELP: Record<AccessStatus, string> = {
  ok: 'Read successfully. An empty list here means empty, not "we could not look".',
  partial:
    'Some of it was read and some was not. The values shown are real; they are not the whole picture, and the accounts that could not be read are counted separately rather than being left out.',
  absent: 'This host does not have the file that answers this, and that was checked rather than assumed.',
  denied:
    'It exists and this account was not allowed to read it. A different account, or passwordless sudo, would see more. This is NOT the same as there being nothing there.',
  'no-tool': 'The program that answers this is not installed on this host.',
  unsupported:
    'This host cannot answer this question at all — not a permission problem and not a missing tool. Treat it as UNKNOWN, never as "none".',
  unknown: 'The probe ran and its answer could not be read, or the collector never reported on it.'
}

/** The six things the collector reports on, each read independently. */
export type AccessSourceId =
  | 'accounts'
  | 'authorized-keys'
  | 'sshd-config'
  | 'account-status'
  | 'sudoers'
  | 'last-login'

export const ACCESS_SOURCE_IDS: AccessSourceId[] = [
  'accounts',
  'authorized-keys',
  'sshd-config',
  'account-status',
  'sudoers',
  'last-login'
]

export const ACCESS_SOURCE_LABEL: Record<AccessSourceId, string> = {
  accounts: 'Accounts',
  'authorized-keys': 'Authorized keys',
  'sshd-config': 'sshd configuration',
  'account-status': 'Password lock state',
  sudoers: 'Administrative groups',
  'last-login': 'Last login'
}

export interface AccessSourceReport {
  id: AccessSourceId
  label: string
  status: AccessStatus
  /** Read as root after the unprivileged attempt was refused. Never silent. */
  usedSudo?: boolean
  /** The collector's own words, when it had any. Always sanitised. */
  detail?: string
}

/** Look one source up without a find() at every call site. */
export function accessSource(access: HostAccess, id: AccessSourceId): AccessSourceReport {
  return (
    access.sources.find((s) => s.id === id) ?? {
      id,
      label: ACCESS_SOURCE_LABEL[id],
      status: 'unknown',
      detail: 'the collector did not report on this source'
    }
  )
}

// ---- Keys -----------------------------------------------------------------

/**
 * The key types sshd will accept on an authorized_keys line.
 *
 * Allow-listed rather than shape-matched because everything downstream switches
 * on it, and because the type is what decides how `bits` is derived. A line
 * whose first token is not one of these is either an options prefix (handled)
 * or malformed (reported as such) — it is never stored under a type nobody has
 * heard of.
 */
export const KEY_TYPES = [
  'ssh-rsa',
  'ssh-dss',
  'ssh-ed25519',
  'ssh-ed448',
  'ecdsa-sha2-nistp256',
  'ecdsa-sha2-nistp384',
  'ecdsa-sha2-nistp521',
  'sk-ssh-ed25519@openssh.com',
  'sk-ecdsa-sha2-nistp256@openssh.com',
  'ssh-rsa-cert-v01@openssh.com',
  'ssh-dss-cert-v01@openssh.com',
  'ssh-ed25519-cert-v01@openssh.com',
  'ecdsa-sha2-nistp256-cert-v01@openssh.com',
  'ecdsa-sha2-nistp384-cert-v01@openssh.com',
  'ecdsa-sha2-nistp521-cert-v01@openssh.com',
  'sk-ssh-ed25519-cert-v01@openssh.com',
  'sk-ecdsa-sha2-nistp256-cert-v01@openssh.com'
] as const
export type KeyType = (typeof KEY_TYPES)[number]

/** Why a line produced no fingerprint. Never collapsed into "skipped": a line
 *  sshd would accept and we could not read is a hole in the inventory. */
export type KeyProblem =
  /** The line has no recognisable `<type> <base64>` pair at all. */
  | 'malformed'
  /** A type token this build does not know. The line may be perfectly valid on
   *  a newer sshd; it is reported, counted, and NOT fingerprinted. */
  | 'unknown-type'
  /** The blob is not decodable base64. */
  | 'bad-base64'
  /** The blob decoded, and the algorithm name inside it is not the one the line
   *  declares. sshd rejects these; a human reading the file would not notice. */
  | 'type-mismatch'
  /** The line was longer than the collector's per-line cap and arrived cut, so
   *  the blob cannot be trusted to be whole. */
  | 'truncated'

export const KEY_PROBLEM_HELP: Record<KeyProblem, string> = {
  malformed:
    'This line is in the file and is not a key ShellPilot can read. sshd may still accept it, so it is counted rather than hidden.',
  'unknown-type':
    'The key type on this line is not one this version of ShellPilot knows. It is very likely valid — a newer algorithm — and it is NOT fingerprinted, so it will not match anything in the fleet view.',
  'bad-base64': 'The key body on this line is not valid base64, so no fingerprint could be computed from it.',
  'type-mismatch':
    'The algorithm named at the start of the line is not the algorithm inside the key itself. sshd rejects lines like this; a person reading the file would not notice.',
  truncated:
    'This line was longer than the collector transmits and arrived cut short, so its fingerprint would be wrong. The line is reported and deliberately not fingerprinted.'
}

/**
 * Options that RESTRICT what a key can do, as opposed to describing it.
 *
 * Worth separating because they change what the key means: a key with
 * `command=` is a single-purpose key and a key with `from=` is pinned to a
 * source. Anything not on this list is reported verbatim (sanitised) rather
 * than dropped — an option this build does not know is still an option.
 */
export const RESTRICTING_OPTIONS = [
  'command',
  'from',
  'restrict',
  'no-pty',
  'no-agent-forwarding',
  'no-port-forwarding',
  'no-x11-forwarding',
  'no-user-rc',
  'principals',
  'expiry-time',
  'permitopen',
  'permitlisten',
  'tunnel',
  'cert-authority',
  'verify-required',
  'environment',
  'agent-forwarding',
  'port-forwarding',
  'pty',
  'user-rc',
  'x11-forwarding',
  'touch-required',
  'no-touch-required'
] as const

/** One line of one authorized_keys file. */
export interface AuthorizedKey {
  /**
   * OpenSSH's own `SHA256:<base64>` form, computed HERE from the blob.
   *
   * Never by shelling out to `ssh-keygen -l`: it is not guaranteed present, it
   * is another round trip, and it would mean a host with no OpenSSH client
   * tooling could not have its keys identified at all. The base64 is already in
   * hand and SHA-256 is in the standard library.
   *
   * null when `problem` says why.
   */
  fingerprint: string | null
  type: KeyType | null
  /** The type token as written, when it is not one we know. Sanitised. */
  rawType: string | null
  /** Key size where the blob makes it derivable. null for types where it is
   *  fixed and uninteresting, or where the blob did not parse. */
  bits: number | null
  /** The free-form trailing comment. Sanitised and capped — it is the most
   *  attacker-controlled string in this whole feature. */
  comment: string | null
  /** Option names present on the line, in order, sanitised. Empty when the line
   *  has no options prefix. */
  options: string[]
  /** True when any option restricts the key rather than merely describing it. */
  restricted: boolean
  /** 1-based line number in the file, so a finding can be pointed at. */
  line: number
  problem: KeyProblem | null
}

// ---- Accounts -------------------------------------------------------------

/**
 * The administrative groups membership of which is worth reporting.
 *
 * A proxy for sudo rights and named as one. The authoritative answer is
 * `sudo -l -U <user>`, which needs root, runs once per account and writes a
 * line to the sudo log every time — cron.ts already established that a probe
 * which mails root a pile of denials on every refresh is not worth having. Group
 * membership costs nothing, is right on the overwhelming majority of hosts, and
 * `AccessAccount.sudoIsProxy` says out loud that it is an inference.
 */
export const ADMIN_GROUPS = ['sudo', 'wheel', 'admin', 'adm', 'root', 'sudoers', 'toor'] as const

export interface AccessAccount {
  /** From /etc/passwd. Shape-validated: a username with a space in it is not a
   *  username this app will act on. */
  user: string
  uid: number | null
  /** Login shell as written. Free text. */
  shell: string | null
  /** Home directory as written. Free text — and the path the key file was
   *  looked for under, so it is shown rather than assumed. */
  home: string | null
  /**
   * The keys on this account, or null.
   *
   * A null here is NOT "no keys". Read `keysStatus`: `denied` means the file or
   * the path to it is closed to this account, `absent` means it was checked and
   * is not there, `unknown` means even root could not read it.
   */
  keys: AuthorizedKey[] | null
  keysStatus: AccessStatus
  keysDetail?: string
  /** The file was read as root after the unprivileged attempt was refused. */
  keysUsedSudo?: boolean
  /** The path that was read, or would have been. */
  keyPath: string | null
  /**
   * `~/.ssh/authorized_keys2` exists on this account.
   *
   * Reported and NOT read. It has been deprecated since 2001, sshd still
   * consults it by default, and a key hiding in it is exactly the kind of thing
   * this feature exists to surface — so its presence is a finding on its own
   * rather than a silent gap.
   */
  hasLegacyKeyFile: boolean
  /** Password state from `passwd -S -a`. null when that could not be read;
   *  `accountStatus` says why. NOT the same as "cannot log in" — see
   *  `passwordLockBlocksKeys`. */
  passwordLocked: boolean | null
  accountStatus: AccessStatus
  /** The host's own words for when the account expires, sanitised. */
  expiresText: string | null
  /** True only when a date was parsed and it is in the past. null when the
   *  question could not be answered — never false as a stand-in. */
  expired: boolean | null
  /** Administrative groups this account is in, from `id -nG`. Empty is a real
   *  answer; null means the groups could not be read. */
  adminGroups: string[] | null
  /** The last login as the host phrased it, sanitised. */
  lastLoginText: string | null
  /** Epoch milliseconds, when the phrase above parsed AND the host reported its
   *  UTC offset. null otherwise, with `lastLoginText` still shown. */
  lastLoginAt: number | null
  /** The host said this account has never logged in. Distinct from "we could
   *  not tell", which is both fields null. */
  neverLoggedIn: boolean
}

/**
 * Whether a locked password stops this account being used over SSH.
 *
 * It does not, and this function exists so nothing in the app quietly assumes
 * otherwise. `passwd -l` puts a `!` in front of the hash, which defeats
 * password authentication and has NO effect on public-key authentication. An
 * account with a locked password and a live `authorized_keys` entry is fully
 * usable by whoever holds that key — which is the exact combination an access
 * review is looking for and the exact combination a naive reading of "locked"
 * would file as safe.
 *
 * What does stop it: an expired account (`chage -E`), or a shell of
 * `/usr/sbin/nologin` / `/bin/false`.
 */
export function passwordLockBlocksKeys(): false {
  return false
}

/** Shells that mean this account cannot get an interactive session even with a
 *  working key. `command=` keys still run, which is why this is reported rather
 *  than used to exclude an account from the inventory. */
export function shellIsNoLogin(shell: string | null): boolean {
  if (shell === null) return false
  return /(^|\/)(nologin|false|sync|shutdown|halt)$/.test(shell.trim())
}

// ---- The collection -------------------------------------------------------

export interface HostAccess {
  accounts: AccessAccount[]
  /**
   * The `AuthorizedKeysFile` directives found in sshd's config, verbatim.
   *
   * More than one means the config disagrees with itself across
   * sshd_config and sshd_config.d, and sshd's first-match-wins rule plus an
   * `Include` at the top of the file makes "which one applies" genuinely
   * ambiguous from the outside. Rather than guess, all of them are reported and
   * `keyFileIsDefault` goes null.
   */
  authorizedKeysFile: string[]
  /**
   * Whether sshd looks where this collector looked.
   *
   * `true` means the directives seen are the default and the inventory below is
   * the whole story. `false` means sshd reads keys from somewhere this does not,
   * and the inventory is INCOMPLETE — a fact that has to travel with it.
   * `null` means the config could not be read or disagreed with itself.
   */
  keyFileIsDefault: boolean | null
  /**
   * sshd is configured with an `AuthorizedKeysCommand`.
   *
   * When true, keys can come from a directory service and the files on disk are
   * not the whole set — the single most important caveat this feature can
   * carry, because every count below is then a lower bound.
   */
  authorizedKeysCommand: string | null
  /** The account this collection ran as, so "the key I am connected with"
   *  can be identified without a second round trip. */
  collectedAs: string | null
  /** Epoch milliseconds by OUR clock. */
  collectedAt: number
  /** The host's own clock at collection, epoch ms, when it said. Kept because a
   *  last-login timestamp is meaningless against a clock that disagrees. */
  hostNow: number | null
  sources: AccessSourceReport[]
}

/**
 * How often to collect. The same hourly cadence host facts use, and for the
 * same reason: an authorized_keys file changes when a person edits it, not
 * continuously, and this probe reads a file per account.
 */
export const ACCESS_INTERVAL_MS = 60 * 60 * 1000

// ---- Building the command -------------------------------------------------

export interface AccessCollectOptions {
  /**
   * Retry a refused read as root, with `sudo -n` only.
   *
   * Worth having because it is the difference between inventorying one account
   * and inventorying the host: on a normal Linux box the connecting user can
   * read their own `~/.ssh/authorized_keys` and nobody else's.
   *
   * Safe to have on for the reason the Docker reader gives: `sudo -n` NEVER
   * prompts. It works because this account already has passwordless sudo — a
   * decision made on that host — or it fails instantly. It cannot hang an exec
   * waiting for a tty.
   *
   * When false, the word `sudo` does not appear in the built command at all.
   * A test asserts that; a runtime guard could not.
   */
  sudo?: boolean
}

/** The only structural token in the output. No record can equal it: every
 *  record line begins with a tag and a space. */
export const ACCESS_STATUS_MARKER = '===SHELLPILOT-ACCESS==='

/**
 * The most accounts enumerated in one collection.
 *
 * A bound rather than a guess: the loop does a handful of stats and up to two
 * forks per included account, and a host with a directory-service-backed
 * /etc/passwd can have thousands. Hosts over the cap are reported as `partial`
 * rather than silently truncated.
 */
export const ACCOUNT_CAP = 200

/** Per-line cap, applied ON THE HOST. A 4096-bit RSA key with options is around
 *  900 characters; this is generous enough that a truncation means the line was
 *  abusive, and small enough that a file of 8 KB comments cannot flood the
 *  transport. A line that hits it is reported with `problem: 'truncated'`. */
export const KEY_LINE_CAP = 2048

/** Per-value cap for everything else, matching hostFacts.ts. */
const VALUE_CAP = 512

/**
 * One round trip. No mutation, no sourcing, no interpolation of host output
 * into a later command, and no private key is read anywhere in it.
 *
 * Structure, in order:
 *   1. helpers, the sudo probe, and the host's own clock
 *   2. sshd's key-file directives — read FIRST, because they decide whether the
 *      inventory below is complete
 *   3. `passwd -S -a` once, for lock state, with no hash anywhere near it
 *   4. `lastlog` (or `last`) once, for the whole host
 *   5. the per-account loop: traversal check, key file, groups, expiry
 *
 * No `set -e`. Every read is conditional or ends in `|| true`, and the last
 * command is a `printf`, so a host with no sshd_config, no `passwd -S`, no
 * `lastlog` and an unreadable /etc/passwd still returns a status block saying
 * exactly that and exits 0.
 */
export function buildAccessCommand(opts: AccessCollectOptions = {}): string {
  const sudo = opts.sudo !== false
  // Omitted entirely rather than left behind a dead `[ "$SP_SUDO" = 1 ]`
  // branch, exactly as cron.ts and hostFacts.ts do it.
  const ifSudo = (...lines: string[]): string[] => (sudo ? lines : [])
  const probe = sudo ? `SP_SUDO=0\n[ "$(${SUDO_PROBE})" = SP_SUDO_OK ] && SP_SUDO=1` : 'SP_SUDO=0'

  const findBin = (name: string, varName: string, extra: string[] = []): string[] => [
    resolveBinary(name, extra),
    `${varName}=""`,
    `command -v "$SP_BIN" >/dev/null 2>&1 && ${varName}="$SP_BIN"`
  ]

  return [
    // C locale for the whole script. `lastlog` and `chage` print dates through
    // the locale, and a host in de_DE would emit `Di 2 Sep` — parseable by
    // nobody. This is the difference between a timestamp and a shrug.
    'LC_ALL=C',
    'export LC_ALL',

    // A literal newline in a variable so statuses accumulate one per line.
    // `$(printf ...)` cannot be used: command substitution strips trailing
    // newlines, which is the entire content here.
    "SP_NL='\n'",
    'SP_STATUS=""',
    'sp_note() { SP_STATUS="$SP_STATUS$*$SP_NL"; }',
    // THE defence, and the reason a key comment cannot forge anything. Control
    // characters — newlines and carriage returns included — are deleted on the
    // host and the result is cut. A value can never become a second line, forge
    // a record tag or forge the status marker.
    // Tabs become spaces BEFORE control characters are deleted, and that order
    // is load-bearing. `AuthorizedKeysFile\t.ssh/authorized_keys` is how the
    // stock sshd_config on Debian actually spells it; deleting the tab produces
    // `AuthorizedKeysFile.ssh/authorized_keys`, and the directive parser on the
    // other side then reads the whole thing as one word and reports that sshd
    // looks somewhere non-default — an alarming, entirely fabricated finding.
    `sp_clean() { printf '%s' "$1" | tr '\\011' ' ' | tr -d '\\000-\\037\\177' | cut -c1-${VALUE_CAP}; }`,
    "sp_val() { SP_V=$(sp_clean \"$2\"); [ -n \"$SP_V\" ] && printf 'V %s %s\\n' \"$1\" \"$SP_V\"; }",
    // The account field is emitted LAST on the line so it may contain spaces —
    // a username, a home path or a shell can, and none of them can contain a
    // newline by the time this runs.
    "sp_user() { SP_V=$(sp_clean \"$3\"); [ -n \"$SP_V\" ] && printf 'U %s %s %s\\n' \"$1\" \"$2\" \"$SP_V\"; }",
    // A key line, with its length BEFORE truncation. Without the length there
    // is no way to tell a line that fitted from one that was cut, and a
    // fingerprint over a cut blob is a confident wrong answer.
    'sp_key() {',
    `SP_K=$(printf '%s' "$3" | tr '\\011' ' ' | tr -d '\\000-\\037\\177')`,
    'SP_KN=${#SP_K}',
    `[ "$SP_KN" -gt 0 ] && printf 'K %s %s %s %s\\n' "$1" "$2" "$SP_KN" "$(printf '%s' "$SP_K" | cut -c1-${KEY_LINE_CAP})"`,
    '}',
    probe,

    // ---- the host's own clock -------------------------------------------
    // Both halves. A last-login date is local time with no offset in it, so
    // without `%z` it cannot become an instant, and without `%s` there is
    // nothing to notice a host whose clock is a year out.
    `sp_val now "$(date +%s 2>/dev/null || true)"`,
    `sp_val tz "$(date +%z 2>/dev/null || true)"`,
    `sp_val self "$(id -un 2>/dev/null || true)"`,

    // ---- sshd: where does it actually look for keys? ---------------------
    // First, because it decides whether everything below is the whole story.
    // Every matching directive is emitted rather than the first one: sshd
    // resolves first-match-wins, Debian puts `Include sshd_config.d/*.conf` at
    // the TOP of the file so an included file wins, and guessing which applies
    // from out here would be a guess. Two disagreeing directives report as
    // ambiguous, which is the truth.
    'SP_SSHD=""',
    '[ -r /etc/ssh/sshd_config ] && SP_SSHD=/etc/ssh/sshd_config',
    'if [ -n "$SP_SSHD" ]; then',
    'for f in /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf; do',
    '[ -f "$f" ] && [ -r "$f" ] || continue',
    `sp_val keyfile "$(grep -i -E '^[[:space:]]*AuthorizedKeysFile[[:space:]]' "$f" 2>/dev/null | head -1)"`,
    `sp_val keycmd "$(grep -i -E '^[[:space:]]*AuthorizedKeysCommand[[:space:]]' "$f" 2>/dev/null | head -1)"`,
    'done',
    'sp_note sshd-config ok - "$SP_SSHD"',
    'elif [ -e /etc/ssh/sshd_config ]; then',
    'sp_note sshd-config denied - "sshd_config exists and this account cannot read it"',
    'else',
    'sp_note sshd-config absent - "this host has no /etc/ssh/sshd_config"',
    'fi',

    // ---- lock state, once, with no hash in sight -------------------------
    // `passwd -S -a` rather than /etc/shadow. One call instead of one per
    // account, one sudo log line instead of a pile, and — the point — a
    // password hash never enters the output at all.
    ...findBin('passwd', 'SP_PASSWD'),
    'SP_PWS=""',
    'if [ -z "$SP_PASSWD" ]; then',
    'sp_note account-status no-tool - "this host has no passwd command"',
    'else',
    'SP_ERR=$("$SP_PASSWD" -S -a 2>&1 >/dev/null || true)',
    'if SP_PWS=$("$SP_PASSWD" -S -a 2>/dev/null) && [ -n "$SP_PWS" ]; then',
    'sp_note account-status ok -',
    ...ifSudo(
      'elif [ "$SP_SUDO" = 1 ] && SP_PWS=$(sudo -n "$SP_PASSWD" -S -a 2>/dev/null) && [ -n "$SP_PWS" ]; then',
      'sp_note account-status ok root'
    ),
    'else',
    'SP_PWS=""',
    // busybox's passwd has no -S at all, which is not a permission problem and
    // no amount of root fixes it. Told apart by what the tool said, because the
    // exit status is the same either way.
    'case "$SP_ERR" in',
    '*nrecognized*|*nvalid\\ option*|*llegal\\ option*|*"BusyBox"*|*"Usage:"*)',
    'sp_note account-status unsupported - "the passwd on this host has no -S, so no lock state exists to read" ;;',
    '*) sp_note account-status denied - "passwd -S -a needs root on this host" ;;',
    'esac',
    'fi',
    'fi',
    // Emitted with the status FIRST and the account name last, so a username
    // with a space in it cannot shift the field that matters. The status is
    // matched against a literal list, so a forged line can only ever produce
    // one of the four words shadow-utils itself uses.
    `printf '%s\\n' "$SP_PWS" | while read -r SP_SU SP_SST SP_SREST; do`,
    'case "$SP_SST" in',
    `L|LK|P|PS|NP) printf 'S %s %s\\n' "$SP_SST" "$(sp_clean "$SP_SU")" ;;`,
    'esac',
    'done',

    // ---- last login, once for the whole host -----------------------------
    // `lastlog` first: it reports every account including the ones that have
    // never logged in, which is the answer an access review wants. It is being
    // removed from newer distributions, so `last` is the fallback — that only
    // reports accounts with a session in wtmp, so "never logged in" becomes
    // "not in the answer", and the status says which tool produced it.
    ...findBin('lastlog', 'SP_LASTLOG'),
    ...findBin('last', 'SP_LAST'),
    'SP_LL=""',
    'SP_LLW="-"',
    'if [ -n "$SP_LASTLOG" ] && SP_LL=$("$SP_LASTLOG" 2>/dev/null | head -n 500) && [ -n "$SP_LL" ]; then',
    'sp_note last-login ok - "lastlog"',
    'elif [ -n "$SP_LAST" ] && SP_LL=$("$SP_LAST" -w -F -n 200 2>/dev/null | head -n 200) && [ -n "$SP_LL" ]; then',
    'SP_LLW=last',
    'sp_note last-login partial - "lastlog is not available; last reports only accounts with a session still in wtmp"',
    'elif [ -z "$SP_LASTLOG" ] && [ -z "$SP_LAST" ]; then',
    'SP_LL=""',
    'sp_note last-login no-tool - "neither lastlog nor last is installed"',
    'else',
    'SP_LL=""',
    'sp_note last-login denied - "the login database could not be read"',
    'fi',
    `sp_val lltool "$SP_LLW"`,
    `printf '%s\\n' "$SP_LL" | while IFS= read -r SP_LR; do`,
    '[ -n "$SP_LR" ] && printf \'L %s\\n\' "$(sp_clean "$SP_LR")"',
    'done',

    // ---- accounts ---------------------------------------------------------
    'SP_PWOK=0',
    'if [ -r /etc/passwd ]; then',
    'SP_PWOK=1',
    'elif [ -e /etc/passwd ]; then',
    'sp_note accounts denied - "/etc/passwd exists and this account cannot read it"',
    'else',
    'sp_note accounts absent - "this host has no /etc/passwd"',
    'fi',
    ...findBin('chage', 'SP_CHAGE'),
    'if [ "$SP_PWOK" = 1 ]; then',
    // The count is reported from the PARENT, after the loop, using a file the
    // subshell writes — no. It is reported by TypeScript instead, from the
    // records it actually received, because this loop is a subshell and
    // anything it accumulates dies with it. Which accounts were included and
    // which could not be read are both visible in the U records, so the
    // summary is derivable and does not need to survive the pipe.
    'sp_note accounts ok -',
    `cat /etc/passwd 2>/dev/null | { SP_I=0; SP_N=0`,
    'while IFS=: read -r SP_U SP_X SP_UID SP_GID SP_GECOS SP_HOME SP_SHELL; do',
    '[ -n "$SP_U" ] || continue',
    '[ -n "$SP_UID" ] || continue',
    'SP_N=$((SP_N+1))',
    `[ "$SP_N" -gt ${ACCOUNT_CAP} ] && break`,

    // Which accounts are worth a stat. Root always; anything with a login
    // shell always; and — the case that matters — a nologin account that has an
    // authorized_keys file anyway, which is exactly what a `git` or `deploy`
    // account looks like and exactly the one an inventory must not skip.
    'SP_F=""',
    '[ -n "$SP_HOME" ] && SP_F="$SP_HOME/.ssh/authorized_keys"',
    'SP_INC=0',
    '[ "$SP_UID" = 0 ] && SP_INC=1',
    'case "$SP_SHELL" in',
    "*nologin|*/false|*/sync|*/shutdown|*/halt|'') ;;",
    '*) SP_INC=1 ;;',
    'esac',
    '[ "$SP_INC" = 0 ] && [ -n "$SP_F" ] && [ -e "$SP_F" ] && SP_INC=1',
    '[ "$SP_INC" = 1 ] || continue',
    'SP_I=$((SP_I+1))',
    'sp_user "$SP_I" uid "$SP_UID"',
    'sp_user "$SP_I" shell "$SP_SHELL"',
    'sp_user "$SP_I" home "$SP_HOME"',
    'sp_user "$SP_I" path "$SP_F"',
    'sp_user "$SP_I" name "$SP_U"',

    // THE check that keeps this feature honest.
    //
    // A home directory this account cannot traverse makes `[ -e "$f" ]` false,
    // which is indistinguishable from the file not being there. Test the
    // traversal FIRST and report `denied`, or a permission bit reads as an
    // empty inventory — the single most likely way this could lie.
    'SP_KS=unknown',
    'SP_KW="-"',
    'SP_TXT=""',
    'if [ -z "$SP_HOME" ]; then SP_KS=absent',
    'elif [ ! -d "$SP_HOME" ]; then SP_KS=absent',
    'elif [ ! -x "$SP_HOME" ]; then SP_KS=denied',
    'elif [ ! -d "$SP_HOME/.ssh" ]; then SP_KS=absent',
    'elif [ ! -x "$SP_HOME/.ssh" ]; then SP_KS=denied',
    'elif [ ! -e "$SP_F" ]; then SP_KS=absent',
    'elif SP_TXT=$(cat "$SP_F" 2>/dev/null); then SP_KS=ok',
    'else SP_KS=denied',
    'fi',
    ...ifSudo(
      // Root settles both questions at once, so the answer stops being an
      // inference. `--` because a home path out of /etc/passwd can begin with a
      // dash and `ls -d -foo` is a different command.
      'if [ "$SP_KS" != ok ] && [ "$SP_SUDO" = 1 ] && [ -n "$SP_F" ]; then',
      'if SP_TXT=$(sudo -n cat "$SP_F" 2>/dev/null); then',
      'SP_KS=ok; SP_KW=root',
      'elif sudo -n ls -d -- "$SP_F" >/dev/null 2>&1; then',
      // It is there and root could not read it either. Not `denied` — a
      // different account would not help — and emphatically not `absent`.
      'SP_KS=unknown; SP_KW=root',
      'else',
      // Root looked and it is not there. This is the ONE place `absent` is
      // claimed from something other than a check this account could make.
      'SP_KS=absent; SP_KW=root',
      'fi',
      'fi'
    ),
    'sp_user "$SP_I" keys "$SP_KS $SP_KW"',
    // Deprecated since 2001, still consulted by sshd, and a key hiding in it is
    // exactly what this feature exists to surface. Reported, not read.
    '[ -n "$SP_HOME" ] && [ -e "$SP_HOME/.ssh/authorized_keys2" ] && sp_user "$SP_I" keys2 present',
    'if [ "$SP_KS" = ok ]; then',
    `printf '%s\\n' "$SP_TXT" | { SP_L=0`,
    'while IFS= read -r SP_LINE; do',
    'SP_L=$((SP_L+1))',
    '[ -n "$SP_LINE" ] && sp_key "$SP_I" "$SP_L" "$SP_LINE"',
    'done',
    '}',
    'fi',

    // Groups, for every included account: one fork, no privilege, and right on
    // the overwhelming majority of hosts.
    `SP_G=$(id -nG "$SP_U" 2>/dev/null || true)`,
    '[ -n "$SP_G" ] && sp_user "$SP_I" groups "$SP_G"',

    // Expiry, ONLY for accounts that actually hold keys. `chage -l` needs root
    // for anyone but yourself, so doing it for every account would write a sudo
    // log line per account per hour on a host with forty of them, to answer a
    // question about accounts that cannot be logged into anyway.
    'if [ "$SP_KS" = ok ] && [ -n "$SP_CHAGE" ]; then',
    `SP_CH=$("$SP_CHAGE" -l "$SP_U" 2>/dev/null || true)`,
    ...ifSudo('[ -z "$SP_CH" ] && [ "$SP_SUDO" = 1 ] && SP_CH=$(sudo -n "$SP_CHAGE" -l "$SP_U" 2>/dev/null || true)'),
    `SP_EX=$(printf '%s\\n' "$SP_CH" | grep -i 'Account expires' | head -1 | cut -d: -f2-)`,
    '[ -n "$SP_CH" ] && sp_user "$SP_I" expires "$SP_EX"',
    'fi',
    'done',
    '}',
    'fi',

    // Group membership is read per account above and never fails as a unit, so
    // its source status is about whether ANY account answered — derived in
    // TypeScript from the records, like `authorized-keys`. What the shell can
    // say is whether the tool exists at all.
    ...findBin('id', 'SP_ID'),
    'if [ -n "$SP_ID" ]; then',
        // Worded to avoid the bare word `sudo`. The one rule worth grepping this
    // whole command for is that every escalation in it is `sudo -n`, and a
    // false positive in a comment is a false positive somebody has to argue
    // with — cron.ts spells the same idea `root` for the same reason.
    'sp_note sudoers ok - "group membership is a proxy for administrative rights, not a reading of the sudoers file"',
    'else',
    'sp_note sudoers no-tool - "this host has no id command"',
    'fi',

    // Printed once, at the end, out of a variable that nothing read from a file
    // ever touched.
    `printf '%s\\n%s' '${ACCESS_STATUS_MARKER}' "$SP_STATUS"`
  ].join('\n')
}

/** The shipped command, built once. */
export const ACCESS_COMMAND = buildAccessCommand()

// ---- Parsing --------------------------------------------------------------

// Control characters, zero-width marks and the bidi overrides, stripped from
// every free-text field the host wrote.
//
// The collector already deletes control characters ON the host, which is what
// makes the record format unforgeable. This is a different job and it cannot
// happen there: `tr -d '\000-\037\177'` works on bytes and U+202E is three of
// them. A bidi override reorders what a HUMAN sees without changing what a
// parser reads — precisely the wrong way round for a key comment somebody is
// about to decide whether to revoke.
const UNSAFE_FREE =
  // eslint-disable-next-line no-control-regex -- matching them is the point
  /[\u0000-\u001f\u007f-\u009f\u200b-\u200f\u202a-\u202e\u2066-\u2069\u2028\u2029]/g

/** How much of a key comment is kept. Long enough for a real one
 *  (`user@laptop`, or a ticket reference); short enough that an 8 KB comment
 *  cannot push a table off the screen or a tool result past its budget. */
export const COMMENT_CAP = 200

function freeText(value: string | null | undefined, max = VALUE_CAP): string | null {
  if (value === null || value === undefined) return null
  const flat = value.replace(UNSAFE_FREE, ' ').replace(/\s+/g, ' ').trim()
  if (flat === '') return null
  return flat.length > max ? `${flat.slice(0, max)}…` : flat
}

/** A username as this app is prepared to act on one. Deliberately tighter than
 *  POSIX allows: everything downstream uses it as a fact key and a table row,
 *  and a name with a space or a colon in it would break both. */
const USER_RE = /^[A-Za-z_][A-Za-z0-9._-]{0,63}\$?$/

// ---- Base64 and fingerprints ----------------------------------------------

/**
 * The SHA-256 the fingerprint is computed with, injected.
 *
 * Not an import of `node:crypto`, because this file is shared and the renderer
 * bundles it — a top-level `node:` import here breaks the renderer build. The
 * main process passes `createHash('sha256')`; a test passes the same thing. The
 * point stands either way: the fingerprint is computed HERE from the blob, and
 * never by shelling out to `ssh-keygen`, which is not guaranteed present and
 * would mean a host missing OpenSSH's own tooling could not identify its keys.
 */
export type Sha256 = (data: Uint8Array) => Uint8Array

const B64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'

/** Strict base64 decode. Returns null rather than throwing or guessing: a blob
 *  that is not decodable is a `bad-base64` problem, which is a reportable
 *  finding and not an exception. */
export function decodeBase64(input: string): Uint8Array | null {
  const s = input.replace(/=+$/, '')
  if (s.length === 0 || /[^A-Za-z0-9+/]/.test(s) || s.length % 4 === 1) return null
  const out = new Uint8Array(Math.floor((s.length * 3) / 4))
  let acc = 0
  let bits = 0
  let n = 0
  for (const ch of s) {
    acc = (acc << 6) | B64.indexOf(ch)
    bits += 6
    if (bits >= 8) {
      bits -= 8
      out[n++] = (acc >> bits) & 0xff
    }
  }
  return out.subarray(0, n)
}

function encodeBase64(bytes: Uint8Array): string {
  let out = ''
  for (let i = 0; i < bytes.length; i += 3) {
    const a = bytes[i]
    const b = i + 1 < bytes.length ? bytes[i + 1] : -1
    const c = i + 2 < bytes.length ? bytes[i + 2] : -1
    out += B64[a >> 2]
    out += B64[((a & 3) << 4) | (b < 0 ? 0 : b >> 4)]
    out += b < 0 ? '=' : B64[((b & 15) << 2) | (c < 0 ? 0 : c >> 6)]
    out += c < 0 ? '=' : B64[c & 63]
  }
  return out
}

/**
 * OpenSSH's `SHA256:` fingerprint form: base64 of the digest, padding stripped.
 *
 * The padding matters. `ssh-keygen -l` prints it without, and a fingerprint
 * with a trailing `=` would never string-match one a person pasted out of a
 * terminal — which is the entire way this feature gets used.
 */
export function sshFingerprint(blob: Uint8Array, sha256: Sha256): string {
  return `SHA256:${encodeBase64(sha256(blob)).replace(/=+$/, '')}`
}

/**
 * The length-prefixed fields at the front of an SSH public key blob.
 *
 * Every blob starts with the algorithm name as a 4-byte-length-prefixed string,
 * which is what lets a line claiming `ssh-ed25519` over an RSA blob be caught.
 * Returns null on any inconsistency rather than reading past the end.
 */
function sshFields(blob: Uint8Array, max = 4): Uint8Array[] | null {
  const out: Uint8Array[] = []
  let i = 0
  while (i + 4 <= blob.length && out.length < max) {
    const len = (blob[i] << 24) | (blob[i + 1] << 16) | (blob[i + 2] << 8) | blob[i + 3]
    if (len < 0 || i + 4 + len > blob.length) return out.length > 0 ? out : null
    out.push(blob.subarray(i + 4, i + 4 + len))
    i += 4 + len
  }
  return out.length > 0 ? out : null
}

const ascii = (b: Uint8Array): string => Array.from(b, (c) => String.fromCharCode(c)).join('')

/**
 * Key size, where the blob makes it derivable.
 *
 * RSA and DSA carry their modulus, so the size is real rather than assumed —
 * and a 1024-bit RSA key still trusted by a host is a finding worth surfacing.
 * The fixed-size curves are returned from the name because there is nothing to
 * measure. A certificate blob is a different structure and returns null rather
 * than a number read out of the wrong field.
 */
export function keyBits(type: string, blob: Uint8Array): number | null {
  if (type.includes('-cert-v01@')) return null
  if (type === 'ssh-ed25519' || type === 'sk-ssh-ed25519@openssh.com') return 256
  if (type === 'ssh-ed448') return 448
  const curve = /nistp(\d+)$/.exec(type)
  if (curve) return Number(curve[1])
  if (type !== 'ssh-rsa' && type !== 'ssh-dss') return null
  const fields = sshFields(blob, 3)
  // ssh-rsa is [name, e, n]; ssh-dss is [name, p, ...] and p is the modulus.
  const mod = type === 'ssh-rsa' ? fields?.[2] : fields?.[1]
  if (!mod || mod.length === 0) return null
  let i = 0
  while (i < mod.length && mod[i] === 0) i++
  if (i >= mod.length) return null
  let bits = (mod.length - i - 1) * 8
  for (let b = mod[i]; b > 0; b >>= 1) bits++
  return bits
}

// ---- One authorized_keys line ---------------------------------------------

/**
 * Split an options prefix off the front of a line.
 *
 * Options are comma-separated and may contain quoted strings with spaces in
 * them — `command="/usr/bin/rsync --server"` is the common case and a naive
 * split on whitespace attributes the key type to `--server`. So this scans for
 * the first whitespace OUTSIDE quotes, with `\"` and `\\` honoured inside them
 * as OpenSSH does.
 *
 * Returns null when the line does not begin with options at all.
 */
export function splitKeyOptions(line: string): { options: string; rest: string } | null {
  let inQuote = false
  for (let i = 0; i < line.length; i++) {
    const c = line[i]
    if (inQuote && c === '\\') {
      i++
      continue
    }
    if (c === '"') {
      inQuote = !inQuote
      continue
    }
    if (!inQuote && (c === ' ' || c === '\t')) {
      const options = line.slice(0, i)
      const rest = line.slice(i).replace(/^[ \t]+/, '')
      return rest === '' ? null : { options, rest }
    }
  }
  return null
}

/** Option NAMES off an options prefix, in order. The values are deliberately
 *  discarded: a `command="…"` value is an arbitrary shell command written by
 *  whoever wrote the file, and the fact that the option is there is the finding.
 *  Which option it is, is the part worth showing. */
export function parseKeyOptionNames(options: string): string[] {
  const names: string[] = []
  let inQuote = false
  let start = 0
  const push = (raw: string): void => {
    const name = raw.trim().split('=')[0].trim().toLowerCase()
    // Shape-checked, not allow-listed: an option this build has not heard of is
    // still an option and hiding it would be the same lie as hiding a key.
    if (/^[a-z][a-z0-9-]{0,31}$/.test(name)) names.push(name)
    else if (name !== '') names.push('(unreadable)')
  }
  for (let i = 0; i < options.length; i++) {
    const c = options[i]
    if (inQuote && c === '\\') {
      i++
      continue
    }
    if (c === '"') inQuote = !inQuote
    else if (c === ',' && !inQuote) {
      push(options.slice(start, i))
      start = i + 1
    }
  }
  push(options.slice(start))
  return names.slice(0, 24)
}

/**
 * One line of an authorized_keys file, fingerprinted where possible.
 *
 * `truncated` is passed in rather than inferred, because only the collector
 * knows how long the line was before it was cut — and a fingerprint over a cut
 * blob is not a missing answer, it is a confidently wrong one that would fail
 * to match the same key somewhere else in the fleet.
 */
export function parseAuthorizedKeyLine(
  raw: string,
  line: number,
  sha256: Sha256,
  truncated = false
): AuthorizedKey | null {
  const text = raw.replace(UNSAFE_FREE, ' ').trim()
  // Blank and comment lines are not keys and are not findings. sshd skips
  // leading whitespace before deciding, and so does this.
  if (text === '' || text.startsWith('#')) return null

  const base: AuthorizedKey = {
    fingerprint: null,
    type: null,
    rawType: null,
    bits: null,
    comment: null,
    options: [],
    restricted: false,
    line,
    problem: 'malformed'
  }

  let body = text
  const split = splitKeyOptions(text)
  // A line beginning with a known key type has no options, whatever else is on
  // it, so `ssh-rsa AAAA… command=notanoption` is read the way sshd reads it:
  // the third field is a comment.
  //
  // Otherwise a prefix is only treated as options when it LOOKS like options —
  // it assigns (`command="…"`), it lists (`no-pty,no-agent-forwarding`), or it
  // is a bare option OpenSSH defines. Without that test any junk line is read
  // as `<options> <type> <blob>`: `garbage line here` becomes a key of type
  // "line", filed as a possibly-valid newer algorithm, and a corrupt file reads
  // as an exotic one.
  const firstToken = text.split(/[ \t]+/)[0]
  const looksLikeOptions =
    split !== null &&
    (/[=,]/.test(split.options) ||
      (RESTRICTING_OPTIONS as readonly string[]).includes(split.options.toLowerCase()))
  const hasOptions = !(KEY_TYPES as readonly string[]).includes(firstToken) && looksLikeOptions
  if (hasOptions && split) {
    base.options = parseKeyOptionNames(split.options)
    base.restricted = base.options.some((o) =>
      (RESTRICTING_OPTIONS as readonly string[]).includes(o)
    )
    body = split.rest
  }

  const parts = body.split(/[ \t]+/)
  const rawType = parts[0] ?? ''
  const blob64 = parts[1] ?? ''
  const comment = parts.slice(2).join(' ')
  base.comment = freeText(comment, COMMENT_CAP)
  base.rawType = freeText(rawType, 64)

  if (rawType === '' || blob64 === '') return base

  if (!(KEY_TYPES as readonly string[]).includes(rawType)) {
    // `unknown-type` is a real answer and `malformed` is a real answer, and
    // telling them apart matters: the first says "a key this build cannot
    // fingerprint, treat the inventory as incomplete", the second says "a line
    // that is not a key at all". The discriminator is the key's own structure —
    // every SSH public key blob begins with its algorithm name as a
    // length-prefixed string, and that name matching the token on the line is
    // something a corrupt line cannot fake by accident.
    const probe = decodeBase64(blob64)
    const fields = probe && sshFields(probe, 1)
    const inner = fields && fields[0] ? ascii(fields[0]) : ''
    return { ...base, problem: inner === rawType ? 'unknown-type' : 'malformed' }
  }
  const type = rawType as KeyType
  if (truncated) return { ...base, type, problem: 'truncated' }

  const blob = decodeBase64(blob64)
  if (blob === null) return { ...base, type, problem: 'bad-base64' }

  const fields = sshFields(blob, 1)
  const inner = fields && fields[0] ? ascii(fields[0]) : ''
  if (inner !== rawType) {
    // sshd rejects these outright. A person reading the file would not notice,
    // which is exactly why it is worth saying.
    return { ...base, type, problem: 'type-mismatch' }
  }

  return {
    ...base,
    type,
    fingerprint: sshFingerprint(blob, sha256),
    bits: keyBits(type, blob),
    problem: null
  }
}

// ---- The whole collection --------------------------------------------------

const SCALAR_KEYS = ['now', 'tz', 'self', 'keyfile', 'keycmd', 'lltool'] as const
type ScalarKey = (typeof SCALAR_KEYS)[number]

const USER_FIELDS = ['name', 'uid', 'shell', 'home', 'path', 'keys', 'keys2', 'groups', 'expires'] as const
type UserField = (typeof USER_FIELDS)[number]

/** sshd's compiled-in default. Anything else means keys live somewhere this
 *  collector did not look. */
const DEFAULT_KEY_FILES = ['.ssh/authorized_keys', '.ssh/authorized_keys2']

function parseStatusLine(line: string): AccessSourceReport | null {
  const [id, status, readBy, ...rest] = line.trim().split(/\s+/)
  if (!ACCESS_SOURCE_IDS.includes(id as AccessSourceId)) return null
  const detail = freeText(rest.join(' ').replace(/^"|"$/g, '')) ?? ''
  return {
    id: id as AccessSourceId,
    label: ACCESS_SOURCE_LABEL[id as AccessSourceId],
    // An unrecognised status becomes `unknown` rather than being passed
    // through: everything downstream switches on it, and a value outside the
    // union renders as nothing at all.
    status: ACCESS_STATUSES.includes(status as AccessStatus) ? (status as AccessStatus) : 'unknown',
    ...(readBy === 'root' ? { usedSudo: true } : {}),
    ...(detail === '' || detail === '-' ? {} : { detail })
  }
}

const MONTHS = ['jan', 'feb', 'mar', 'apr', 'may', 'jun', 'jul', 'aug', 'sep', 'oct', 'nov', 'dec']

/**
 * The date out of a `lastlog` or `last` row, as an instant.
 *
 * Both print LOCAL time with no offset that can be relied on — `lastlog` may
 * print a zone abbreviation, `last -F` prints none at all, and an abbreviation
 * is ambiguous across hemispheres anyway. So the offset comes from the host
 * itself (`date +%z`, collected in the same round trip), which is the only
 * source that is actually correct.
 *
 * Returns null when there is no offset to apply. The host's own words are kept
 * either way: "we cannot turn this into an instant" is not "we do not know when
 * they logged in", and the second is a worse answer than showing the phrase.
 */
export function parseLoginInstant(text: string, tzOffsetMinutes: number | null): number | null {
  // The offset group is matched EXPLICITLY rather than skipped over with a lazy
  // `.*?`. `lastlog` prints `Tue Sep  2 06:00:01 +0000 2026`, and a lazy hop to
  // "the next four digits" finds `0000` — a year of zero, rejected, and every
  // last-login on the host silently reduced to a phrase with no instant behind
  // it. The bug reads as "we could not parse this host's dates".
  const m =
    /\b([A-Z][a-z]{2}) {1,2}(\d{1,2}) (\d{2}):(\d{2})(?::(\d{2}))?(?: ([+-]\d{4})| [A-Z]{2,5})? (\d{4})\b/.exec(
      text
    )
  if (!m) return null
  const month = MONTHS.indexOf(m[1].toLowerCase())
  if (month === -1) return null
  const day = Number(m[2])
  const year = Number(m[7])
  if (day < 1 || day > 31 || year < 1970 || year > 2200) return null
  // An offset printed ON the row beats the host's current one. They agree
  // almost always, and where they do not — a login recorded before a DST
  // change — the row is the one that was actually written at the time.
  const offset = parseTzOffset(m[6]) ?? tzOffsetMinutes
  if (offset === null) return null
  const utc = Date.UTC(year, month, day, Number(m[3]), Number(m[4]), Number(m[5] ?? '0'))
  return utc - offset * 60_000
}

/** `+0530` as minutes east of UTC. */
export function parseTzOffset(raw: string | undefined): number | null {
  if (!raw) return null
  const m = /^([+-])(\d{2})(\d{2})$/.exec(raw.trim())
  if (!m) return null
  const mins = Number(m[2]) * 60 + Number(m[3])
  if (mins > 16 * 60) return null
  return m[1] === '-' ? -mins : mins
}

/**
 * `chage -l`'s "Account expires" value, decided against the host's own clock.
 *
 * Day granularity, so the comparison is given a day of slack: an account that
 * expires today is not reported as expired, because `chage` expiry takes effect
 * at the end of the day and calling it expired at 00:01 would be wrong for
 * twenty-four hours.
 */
export function parseExpiry(text: string, hostNow: number | null): boolean | null {
  const t = text.trim().toLowerCase()
  if (t === '' || t === 'never') return t === 'never' ? false : null
  if (hostNow === null) return null
  const m = /\b([A-Z][a-z]{2})\w*\s+(\d{1,2}),?\s+(\d{4})\b/.exec(text)
  if (!m) return null
  const month = MONTHS.indexOf(m[1].toLowerCase())
  if (month === -1) return null
  const at = Date.UTC(Number(m[3]), month, Number(m[2]) + 1)
  return hostNow > at
}

export interface ParseAccessDeps {
  sha256: Sha256
  /** Our clock. Injected so a test can pin it, exactly as parseHostFacts does. */
  now?: number
}

/**
 * Turn one collection into `HostAccess`, with every null explained.
 *
 * Three things happen here that the collector deliberately does not do, for the
 * reason hostFacts.ts gives: the shell says which probe ran, and only this side
 * can say whether its answer survived.
 *
 *  - `authorized-keys` is DERIVED. The shell never reports it, because the
 *    account loop is a subshell and anything it accumulated would die with the
 *    pipe. It is computed from the per-account statuses that did arrive, which
 *    is more honest anyway: "read 4 of 7 accounts" is a fact about the records
 *    in hand rather than a count the shell had to be trusted to keep.
 *  - `sudoers` is downgraded from `ok` to `partial` when some accounts reported
 *    groups and others did not.
 *  - Every account with `keysStatus: 'ok'` gets a real list, possibly empty.
 *    Every other account gets `keys: null`. There is no path here that produces
 *    an empty list for an account that was not read.
 */
export function parseAccessCollection(output: string, deps: ParseAccessDeps): HostAccess {
  const now = deps.now ?? Date.now()
  const lines = output.split('\n')
  const markerAt = lines.findIndex((l) => l.replace(/\r$/, '') === ACCESS_STATUS_MARKER)
  const body = lines.slice(0, markerAt === -1 ? lines.length : markerAt)

  const scalars = new Map<ScalarKey, string[]>()
  const userFields = new Map<number, Map<UserField, string>>()
  const keyLines = new Map<number, { line: number; len: number; text: string }[]>()
  const lockStates = new Map<string, string>()
  const loginRows: string[] = []

  for (const rawLine of body) {
    const line = rawLine.replace(/\r$/, '')
    const tag = line.slice(0, 2)

    if (tag === 'V ') {
      const rest = line.slice(2)
      const sp = rest.indexOf(' ')
      if (sp === -1) continue
      const key = rest.slice(0, sp)
      if (!(SCALAR_KEYS as readonly string[]).includes(key)) continue
      const bucket = scalars.get(key as ScalarKey) ?? []
      bucket.push(rest.slice(sp + 1))
      scalars.set(key as ScalarKey, bucket)
      continue
    }

    if (tag === 'U ') {
      const m = /^U (\d{1,4}) ([a-z0-9]+) (.*)$/.exec(line)
      if (!m) continue
      const field = m[2]
      if (!(USER_FIELDS as readonly string[]).includes(field)) continue
      const idx = Number(m[1])
      const fields = userFields.get(idx) ?? new Map<UserField, string>()
      fields.set(field as UserField, m[3])
      userFields.set(idx, fields)
      continue
    }

    if (tag === 'K ') {
      const m = /^K (\d{1,4}) (\d{1,6}) (\d{1,9}) (.*)$/.exec(line)
      if (!m) continue
      const idx = Number(m[1])
      const bucket = keyLines.get(idx) ?? []
      bucket.push({ line: Number(m[2]), len: Number(m[3]), text: m[4] })
      keyLines.set(idx, bucket)
      continue
    }

    if (tag === 'S ') {
      // `S <state> <user>` — state first so a username with a space in it
      // cannot shift the field that decides whether an account is locked.
      const m = /^S (L|LK|P|PS|NP) (.+)$/.exec(line)
      if (m && USER_RE.test(m[2])) lockStates.set(m[2], m[1])
      continue
    }

    if (tag === 'L ') loginRows.push(line.slice(2))
  }

  const reported = new Map<AccessSourceId, AccessSourceReport>()
  if (markerAt !== -1) {
    for (const line of lines.slice(markerAt + 1)) {
      if (line.trim() === '') continue
      const s = parseStatusLine(line)
      if (s) reported.set(s.id, s)
    }
  }
  const source = (id: AccessSourceId): AccessSourceReport =>
    reported.get(id) ?? {
      id,
      label: ACCESS_SOURCE_LABEL[id],
      status: 'unknown' as const,
      detail:
        markerAt === -1
          ? 'the collector never returned its status block, so nothing here was confirmed'
          : 'the collector did not report on this source'
    }

  const last = (k: ScalarKey): string | undefined => {
    const v = scalars.get(k)
    return v && v.length > 0 ? v[v.length - 1] : undefined
  }

  const hostNowSeconds = last('now')
  const hostNow = hostNowSeconds && /^\d{1,11}$/.test(hostNowSeconds.trim())
    ? Number(hostNowSeconds.trim()) * 1000
    : null
  const tzOffset = parseTzOffset(last('tz'))
  const selfRaw = (last('self') ?? '').trim()
  const collectedAs = USER_RE.test(selfRaw) ? selfRaw : null

  // Every directive line seen, in file order, with the directive word stripped.
  const directiveValues = (k: 'keyfile' | 'keycmd'): string[] => {
    const out: string[] = []
    for (const raw of scalars.get(k) ?? []) {
      const v = freeText(raw.replace(/^[ \t]*[A-Za-z]+[ \t]+/, ''))
      if (v !== null && !out.includes(v)) out.push(v)
    }
    return out
  }
  const authorizedKeysFile = directiveValues('keyfile')
  const commands = directiveValues('keycmd')
  const authorizedKeysCommand =
    commands.length === 0 || /^none$/i.test(commands[0]) ? null : commands[0]

  // Whether sshd looks where this collector looked. `null` — could not tell —
  // for both "the config was unreadable" and "the config disagrees with
  // itself", because both mean the same thing to a reader: the inventory below
  // may not be the whole story and nobody can say from here.
  let keyFileIsDefault: boolean | null = null
  if (source('sshd-config').status === 'absent') {
    // No sshd_config at all means sshd, if it is running, is on its
    // compiled-in defaults — which is exactly where this looked.
    keyFileIsDefault = true
  } else if (source('sshd-config').status === 'ok') {
    if (authorizedKeysFile.length === 0) keyFileIsDefault = true
    else if (authorizedKeysFile.length === 1) {
      const paths = authorizedKeysFile[0].split(/\s+/).filter((p) => p !== '')
      keyFileIsDefault = paths.every((p) => DEFAULT_KEY_FILES.includes(p.replace(/^%h\//, '')))
    }
  }

  // The login rows, indexed by the account they name. `lastlog` prints one row
  // per account; `last` prints one per session, newest first — so the FIRST row
  // for a user wins under both.
  const loginByUser = new Map<string, string>()
  for (const row of loginRows) {
    const user = row.split(/\s+/)[0] ?? ''
    if (!USER_RE.test(user) || loginByUser.has(user)) continue
    loginByUser.set(user, row)
  }

  const accounts: AccessAccount[] = []
  for (const idx of [...userFields.keys()].sort((a, b) => a - b)) {
    const f = userFields.get(idx)!
    const user = (f.get('name') ?? '').trim()
    // An account whose name this app cannot key on is dropped rather than shown
    // under a mangled label. It is not silent: the derived `accounts` status
    // below counts what was dropped.
    if (!USER_RE.test(user)) continue

    const uidRaw = (f.get('uid') ?? '').trim()
    const [statusWord, readBy] = (f.get('keys') ?? '').trim().split(/\s+/)
    const keysStatus: AccessStatus = ACCESS_STATUSES.includes(statusWord as AccessStatus)
      ? (statusWord as AccessStatus)
      : 'unknown'

    // The one invariant that matters: a list exists ONLY for an account whose
    // file was actually read. Everything else gets null and a reason.
    let keys: AuthorizedKey[] | null = null
    if (keysStatus === 'ok') {
      keys = []
      for (const k of (keyLines.get(idx) ?? []).slice(0, 500)) {
        const parsed = parseAuthorizedKeyLine(k.text, k.line, deps.sha256, k.len > KEY_LINE_CAP)
        if (parsed) keys.push(parsed)
      }
    }

    const groupsRaw = f.get('groups')
    const adminGroups =
      groupsRaw === undefined
        ? null
        : groupsRaw
            .split(/\s+/)
            .filter((g) => (ADMIN_GROUPS as readonly string[]).includes(g.toLowerCase()))

    const lock = lockStates.get(user)
    const accountStatus = source('account-status').status
    const passwordLocked =
      lock === undefined ? null : lock === 'L' || lock === 'LK'

    const expiresRaw = f.get('expires')
    const loginRow = loginByUser.get(user)
    const neverLoggedIn = loginRow !== undefined && /\*\*Never logged in\*\*/i.test(loginRow)

    accounts.push({
      user,
      uid: /^\d{1,10}$/.test(uidRaw) ? Number(uidRaw) : null,
      shell: freeText(f.get('shell'), 128),
      home: freeText(f.get('home'), 256),
      keys,
      keysStatus,
      ...(keysStatus === 'ok' ? {} : { keysDetail: ACCESS_STATUS_HELP[keysStatus] }),
      ...(readBy === 'root' ? { keysUsedSudo: true } : {}),
      keyPath: freeText(f.get('path'), 256),
      hasLegacyKeyFile: f.get('keys2') === 'present',
      // `passwordLocked` is null unless the tool actually answered for THIS
      // account. An account missing from `passwd -S -a` output is not an
      // unlocked account.
      passwordLocked: accountStatus === 'ok' ? passwordLocked : null,
      accountStatus: accountStatus === 'ok' && lock === undefined ? 'unknown' : accountStatus,
      expiresText: freeText(expiresRaw, 64),
      expired: expiresRaw === undefined ? null : parseExpiry(expiresRaw, hostNow),
      adminGroups,
      lastLoginText: neverLoggedIn ? null : freeText(loginRow, 128),
      lastLoginAt: loginRow && !neverLoggedIn ? parseLoginInstant(loginRow, tzOffset) : null,
      neverLoggedIn
    })
  }

  // ---- the two derived sources ---------------------------------------------
  //
  // Derived rather than reported because the account loop runs in a subshell
  // and nothing it accumulates survives the pipe — see the note in the command
  // builder. Computing them from the records that actually arrived is the more
  // honest form anyway: it counts what is in hand rather than what the shell
  // said it had.
  const accountsSource = source('accounts')
  const read = accounts.filter((a) => a.keysStatus === 'ok').length
  let keysSource: AccessSourceReport = {
    id: 'authorized-keys',
    label: ACCESS_SOURCE_LABEL['authorized-keys'],
    status: 'unknown',
    detail: 'no accounts were enumerated, so no key file could be looked for'
  }
  if (accountsSource.status === 'ok') {
    const denied = accounts.filter((a) => a.keysStatus === 'denied' || a.keysStatus === 'unknown').length
    const sudoUsed = accounts.some((a) => a.keysUsedSudo)
    if (accounts.length === 0) {
      keysSource = {
        ...keysSource,
        status: 'absent',
        detail: 'this host has no accounts that could hold an authorized_keys file'
      }
    } else if (denied === 0) {
      keysSource = { ...keysSource, status: 'ok', detail: `read all ${accounts.length} accounts` }
    } else if (read > 0) {
      keysSource = {
        ...keysSource,
        status: 'partial',
        detail: `read ${read} of ${accounts.length} accounts; ${denied} could not be read and are excluded from every count`
      }
    } else {
      keysSource = {
        ...keysSource,
        status: 'denied',
        detail: `none of the ${accounts.length} accounts' key files could be read by this account`
      }
    }
    if (sudoUsed) keysSource = { ...keysSource, usedSudo: true }
  } else {
    keysSource = { ...keysSource, status: accountsSource.status, detail: accountsSource.detail }
  }

  let sudoersSource = source('sudoers')
  if (sudoersSource.status === 'ok' && accounts.length > 0) {
    const withGroups = accounts.filter((a) => a.adminGroups !== null).length
    if (withGroups === 0) {
      sudoersSource = {
        ...sudoersSource,
        status: 'denied',
        detail: 'no account returned a group list'
      }
    } else if (withGroups < accounts.length) {
      sudoersSource = {
        ...sudoersSource,
        status: 'partial',
        detail: `group membership was read for ${withGroups} of ${accounts.length} accounts`
      }
    }
  }

  return {
    accounts,
    authorizedKeysFile,
    keyFileIsDefault,
    authorizedKeysCommand,
    collectedAs,
    collectedAt: now,
    hostNow,
    sources: [
      accountsSource,
      keysSource,
      source('sshd-config'),
      source('account-status'),
      sudoersSource,
      source('last-login')
    ]
  }
}

// ---- Summaries -------------------------------------------------------------

export interface AccessSummary {
  /** Accounts whose key file was read. */
  accountsRead: number
  /** Accounts enumerated but whose key file was NOT read, for any reason. These
   *  are excluded from every count below and are the reason `certain` exists. */
  accountsUnread: number
  /** Keys across the accounts that WERE read. Never a total for the host. */
  keys: number
  /** Distinct fingerprints across the accounts that were read. */
  fingerprints: Set<string>
  /** Lines in a read file that produced no fingerprint. A hole, not a zero. */
  unfingerprinted: number
  /** Keys carrying a restricting option. */
  restricted: number
  /**
   * Whether a "no unknown keys here" conclusion may be drawn at all.
   *
   * False when ANY account could not be read, when sshd is configured with an
   * AuthorizedKeysCommand, when its AuthorizedKeysFile is not the default or
   * could not be determined, or when a legacy authorized_keys2 file exists
   * somewhere. In every one of those cases the counts above are a LOWER BOUND
   * and must never be rendered as an answer.
   */
  certain: boolean
  /** Why not, in one phrase each, for the panel to print. Empty when certain. */
  uncertainty: string[]
}

/**
 * What can and cannot be concluded from one collection.
 *
 * The `certain` flag is the whole point. A count of keys on a host where two
 * home directories were closed to us is a count of SOME of the keys, and the
 * difference between that and an answer is the difference between this feature
 * being useful and it being dangerous.
 */
export function summariseAccess(access: HostAccess): AccessSummary {
  const readAccounts = access.accounts.filter((a) => a.keys !== null)
  const unread = access.accounts.length - readAccounts.length
  const fingerprints = new Set<string>()
  let keys = 0
  let unfingerprinted = 0
  let restricted = 0
  for (const a of readAccounts) {
    for (const k of a.keys ?? []) {
      keys++
      if (k.fingerprint === null) unfingerprinted++
      else fingerprints.add(k.fingerprint)
      if (k.restricted) restricted++
    }
  }

  const uncertainty: string[] = []
  if (unread > 0) {
    uncertainty.push(
      `${unread} of ${access.accounts.length} accounts could not be read, so any key they trust is not counted here`
    )
  }
  if (access.authorizedKeysCommand !== null) {
    uncertainty.push(
      'sshd is configured with an AuthorizedKeysCommand, so it can accept keys that are not in any file on disk'
    )
  }
  if (access.keyFileIsDefault === false) {
    uncertainty.push(
      'sshd is configured to read authorized keys from a path other than the default, which this collection does not read'
    )
  } else if (access.keyFileIsDefault === null) {
    uncertainty.push(
      'sshd’s AuthorizedKeysFile setting could not be determined, so it is not known whether this is where it looks'
    )
  }
  const legacy = access.accounts.filter((a) => a.hasLegacyKeyFile).map((a) => a.user)
  if (legacy.length > 0) {
    uncertainty.push(
      `${legacy.length} account${legacy.length === 1 ? ' has' : 's have'} a legacy .ssh/authorized_keys2 file, which sshd still reads and this collection does not`
    )
  }
  if (unfingerprinted > 0) {
    uncertainty.push(
      `${unfingerprinted} line${unfingerprinted === 1 ? '' : 's'} in a file that was read could not be fingerprinted, so ${unfingerprinted === 1 ? 'it' : 'they'} cannot be matched against other hosts`
    )
  }

  return {
    accountsRead: readAccounts.length,
    accountsUnread: unread,
    keys,
    fingerprints,
    unfingerprinted,
    restricted,
    certain: uncertainty.length === 0,
    uncertainty
  }
}

/**
 * Where one fingerprint is trusted across the estate, and where that could not
 * be determined.
 *
 * `unreadable` is not decoration. A fingerprint that appears on four hosts and
 * could not be looked for on three more has NOT been shown to be absent from
 * those three, and an operator revoking a key needs both lists — the second one
 * is the list of machines they still have to go and check by hand.
 */
export interface KeyPresence {
  fingerprint: string
  /** serverId → the accounts on that host that trust it. */
  on: Map<string, string[]>
  /** serverIds whose inventory was incomplete, for any reason. */
  unreadable: string[]
}

export function keyPresence(
  fingerprint: string,
  collections: { serverId: string; access: HostAccess }[]
): KeyPresence {
  const on = new Map<string, string[]>()
  const unreadable: string[] = []
  for (const { serverId, access } of collections) {
    const users: string[] = []
    for (const a of access.accounts) {
      if (a.keys?.some((k) => k.fingerprint === fingerprint)) users.push(a.user)
    }
    if (users.length > 0) on.set(serverId, users)
    // Listed even when the key WAS found: a host where one account answered and
    // another did not may trust it twice, and "found here" is not "fully
    // enumerated here".
    if (!summariseAccess(access).certain) unreadable.push(serverId)
  }
  return { fingerprint, on, unreadable }
}

// ---- Storage ---------------------------------------------------------------

/**
 * The prefix every access fact is stored under in the durable store (item A).
 *
 * Same store as host facts, never a second one, and never `shellpilot-data.json`
 * — that blob is the encrypted backup payload rather than somewhere to keep an
 * hourly inventory.
 */
export const ACCESS_FACT_PREFIX = 'access:'

/** The per-account key sub-prefix, which is also the retirement scope. A key
 *  removed from a host has to stop being a current fact, and the fact-removed
 *  event that produces IS the audit trail this feature is for. */
export function accessKeyPrefix(user: string): string {
  return `${ACCESS_FACT_PREFIX}user:${user}:key:`
}

/**
 * Access as the store wants it: string keys, string values.
 *
 * Two rules, both inherited from hostFactsToFacts and both load-bearing:
 *
 *  1. A null is written as its STATUS, never as an empty string or a zero. So
 *     `access:user:deploy:keys = denied` survives into history, and a report
 *     written six months from now can still tell "this account trusted no keys"
 *     from "nobody could see whether it did".
 *
 *  2. Per-key facts are written ONLY for accounts whose file was read. The
 *     caller retires them per account for the same reason — retiring keys for an
 *     account whose file could not be read this hour would record every one of
 *     them as removed, which is a fabricated security event.
 */
export function accessToFacts(access: HostAccess): Record<string, string> {
  const out: Record<string, string> = {}
  for (const s of access.sources) out[`${ACCESS_FACT_PREFIX}source:${s.id}`] = s.status

  const summary = summariseAccess(access)
  out[`${ACCESS_FACT_PREFIX}accountsRead`] = String(summary.accountsRead)
  out[`${ACCESS_FACT_PREFIX}accountsUnread`] = String(summary.accountsUnread)
  out[`${ACCESS_FACT_PREFIX}complete`] = String(summary.certain)
  out[`${ACCESS_FACT_PREFIX}keyFileIsDefault`] =
    access.keyFileIsDefault === null ? 'unknown' : String(access.keyFileIsDefault)
  if (access.authorizedKeysCommand !== null) {
    out[`${ACCESS_FACT_PREFIX}authorizedKeysCommand`] = access.authorizedKeysCommand
  }

  for (const a of access.accounts) {
    const base = `${ACCESS_FACT_PREFIX}user:${a.user}:`
    out[`${base}keys`] = a.keys === null ? a.keysStatus : String(a.keys.length)
    out[`${base}shell`] = a.shell ?? 'unknown'
    out[`${base}passwordLocked`] =
      a.passwordLocked === null ? a.accountStatus : String(a.passwordLocked)
    out[`${base}adminGroups`] = a.adminGroups === null ? 'unknown' : a.adminGroups.join(',')
    if (a.expired !== null) out[`${base}expired`] = String(a.expired)
    if (a.hasLegacyKeyFile) out[`${base}legacyKeyFile`] = 'present'
    // Only for accounts that were read. An unread account contributes no key
    // rows at all, so nothing can later be mistaken for "these were removed".
    for (const k of a.keys ?? []) {
      if (k.fingerprint === null) continue
      out[`${accessKeyPrefix(a.user)}${k.fingerprint}`] =
        `${k.type ?? 'unknown'}${k.restricted ? ' restricted' : ''}`
    }
  }
  return out
}
