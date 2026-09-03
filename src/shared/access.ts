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
  /** The line trusts a CERTIFICATE and the public key inside it could not be
   *  read out. A certificate is a signature wrapped around a key, and the key
   *  is the thing an estate-wide "where is this trusted" question is about —
   *  so a certificate whose inner key cannot be recovered is a hole in the
   *  inventory, exactly like an unreadable file. It is NEVER fingerprinted
   *  from the certificate blob instead: that value is per-certificate, because
   *  the nonce is random, and it would match nothing anywhere while looking
   *  like an answer. */
  | 'certificate'

export const KEY_PROBLEM_HELP: Record<KeyProblem, string> = {
  malformed:
    'This line is in the file and is not a key ShellPilot can read. sshd may still accept it, so it is counted rather than hidden.',
  'unknown-type':
    'The key type on this line is not one this version of ShellPilot knows. It is very likely valid — a newer algorithm — and it is NOT fingerprinted, so it will not match anything in the fleet view.',
  'bad-base64': 'The key body on this line is not valid base64, so no fingerprint could be computed from it.',
  'type-mismatch':
    'The algorithm named at the start of the line is not the algorithm inside the key itself. sshd rejects lines like this; a person reading the file would not notice.',
  truncated:
    'This line was longer than the collector transmits and arrived cut short, so its fingerprint would be wrong. The line is reported and deliberately not fingerprinted.',
  certificate:
    'This line trusts a certificate, and the public key inside the certificate could not be read out of it. The certificate itself is deliberately not fingerprinted: that value is different for every certificate issued to the same key, so it would match nothing on any other host while looking like an answer.'
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

/**
 * Options that BROADEN what a line trusts, rather than restricting it.
 *
 * One member, and it needs its own category rather than a footnote.
 * `cert-authority` does not say "this key, under these conditions" — it says
 * "anything this CA will ever sign", including keys that do not exist yet and
 * that no inventory of any file on any host could enumerate. Filed under
 * RESTRICTING_OPTIONS, as it was, it counted toward `summary.restricted` and
 * inverted its own meaning in the one column an operator scans for "which of
 * these are limited".
 *
 * It is also why `summariseAccess` refuses to be `certain` about a host that
 * has one: the count of keys in the files is not a count of who can log in.
 */
export const BROADENING_OPTIONS = ['cert-authority'] as const

/**
 * Every option name this build recognises, for the one place the DISTINCTION
 * does not matter: deciding whether a bare first token is an options prefix at
 * all. `cert-authority ssh-ed25519 AAAA…` has no comma and no equals in it, so
 * without this list it reads as a key of type `cert-authority`.
 */
const KNOWN_OPTIONS: readonly string[] = [...RESTRICTING_OPTIONS, ...BROADENING_OPTIONS]

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
  /** True when an option BROADENS what this line trusts — `cert-authority`.
   *  Never folded into `restricted`: they point in opposite directions. */
  broadened: boolean
  /**
   * This line trusts a certificate rather than a bare key.
   *
   * `fingerprint` then names the key INSIDE the certificate, which is what
   * `ssh-keygen -l` prints for a certificate and what makes the same key
   * recognisable across hosts however each one chose to trust it.
   */
  certificate: boolean
  /** 1-based line number in the file, so a finding can be pointed at. */
  line: number
  problem: KeyProblem | null
  /**
   * The base64 body, kept verbatim, and ONLY for a key that fingerprinted.
   *
   * Carried because the write half removes a key by matching its exact body:
   * a fingerprint cannot be computed in POSIX sh, and removing by line number
   * would edit whatever happens to be on that line now rather than the key that
   * was there when the inventory was read. It costs ~700 characters per RSA key
   * in memory and is the difference between a precise removal and an
   * approximate one — and nothing approximate is run against an
   * authorized_keys file.
   *
   * null for a CERTIFICATE line even though it fingerprinted. The fingerprint
   * names the key inside, and one key can be certified any number of times
   * with different bodies — so a body here would be one of several lines the
   * fingerprint matches, and a removal built from it would remove fewer lines
   * than the plan expected. Refusing to supply one turns that into a block
   * with a sentence, which is the honest form of the same refusal.
   */
  blob: string | null
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
   * Whether `~/.ssh/authorized_keys2` exists on this account.
   *
   * Reported and NOT read. It has been deprecated since 2001, sshd still
   * consults it by default, and a key hiding in it is exactly the kind of thing
   * this feature exists to surface — so its presence is a finding on its own
   * rather than a silent gap.
   *
   * `null` when the collector could not tell: a home directory or `.ssh` this
   * account cannot traverse, which root could not settle either. NOT false —
   * false is a claim that it was looked for and is not there, and the whole
   * point of this field is that a key sshd reads and this does not must never
   * hide behind a "complete picture" banner.
   */
  hasLegacyKeyFile: boolean | null
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
   * Whether sshd reads THE FILE THIS COLLECTION READ — `.ssh/authorized_keys`.
   *
   * A DIFFERENT QUESTION from `keyFileIsDefault`, and the difference is a
   * whole class of silently-ineffective write. Setting `AuthorizedKeysFile`
   * REPLACES OpenSSH's default list rather than adding to it, so a host
   * configured `AuthorizedKeysFile .ssh/authorized_keys2` reads only keys2 —
   * every path it names is still a member of the default list, so "is this the
   * default set?" answered yes while "does it read the file we are about to
   * edit?" answered no. The write half asked the first question and acted on
   * the answer to the second.
   *
   * `null` for the same three reasons `keyFileIsDefault` is null: the config
   * could not be read, part of it could not be read, or it disagrees with
   * itself. The write gate treats null as a refusal.
   */
  readsTheFileWeRead: boolean | null
  /**
   * Whether sshd also reads `.ssh/authorized_keys2`, which this collection
   * probes for but never reads the contents of.
   *
   * Its own field because it decides whether a revocation from
   * `authorized_keys` can be reported as a revocation at all: a key written
   * into both files is still trusted after one of them is edited.
   */
  readsLegacyKeyFile: boolean | null
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
  /**
   * EVERY key THIS session authenticated with, from sshd's own
   * `SSH_AUTH_INFO_0`.
   *
   * A LIST, not one value, and that is the finding rather than a generalisation
   * for its own sake. `AuthenticationMethods publickey,publickey` is a real and
   * increasingly common configuration, and sshd reports it as one factor PER
   * LINE in the same variable. Reading only the first line protects only the
   * first key, and the second one holds the connection open just as hard.
   *
   * Empty when the host would not say — `ExposeAuthInfo` is off by default, so
   * on most hosts this will be empty. See `sessionKeysCertain`, which is what
   * separates "there is provably no key here to protect" from "nobody can
   * tell".
   */
  sessionKeyFingerprints: string[]
  /**
   * Whether `sessionKeyFingerprints` may be relied on as THE set of keys
   * holding this connection open.
   *
   * True only when the host named at least one public key for this session and
   * every one of them was fingerprinted exactly. False when the host said
   * nothing, and false when it said something this could not turn into a
   * fingerprint — a blob cut by the collector's own line cap, a key type this
   * build does not know, a factor in a shape it does not recognise.
   *
   * THE TRUNCATION CASE IS WHY THIS IS A SEPARATE FLAG AND NOT `length > 0`.
   * A fingerprint computed over a cut blob is not a missing answer, it is a
   * confident wrong one: it matches nothing, so the exact check in
   * `planAccessChange` silently does not fire — and an empty list that looked
   * like "the host said nothing" would at least have taken the conservative
   * branch. So a factor that could not be fingerprinted clears this flag, and
   * the conservative branch is taken instead.
   */
  sessionKeysCertain: boolean
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
    // Which key THIS session authenticated with, straight from sshd.
    //
    // The only authoritative answer to that question, and the reason it is
    // collected here rather than guessed later: revoking a key is the one write
    // this app can make that locks you out of the host you would use to undo
    // it, and "do not remove the key I am on" needs a fact rather than an
    // inference. sshd sets SSH_AUTH_INFO_0 to the authentication method and, for
    // publickey, the key itself — but only where `ExposeAuthInfo yes` is set,
    // which is not the default. So it is asked for, used when it is there, and
    // its ABSENCE is a first-class state that changes what a revoke is allowed
    // to do. See planAccessChange.
    // ONE RECORD PER FACTOR, WITH ITS PRE-TRUNCATION LENGTH. Both halves of
    // that are fixes for a silent bypass, and both are worth naming.
    //
    // THE LENGTH. `sp_val` cuts at VALUE_CAP (512), which is generous for a
    // hostname and not generous at all for a key: `publickey ssh-rsa <blob>` is
    // 390 characters for RSA-2048 and 562 for RSA-3072. Cut there, the blob
    // still decodes — it just decodes to a DIFFERENT key — so the fingerprint
    // came out clean, matched nothing in the file, and rule 1's exact check did
    // not fire, on the one configuration (`ExposeAuthInfo yes`) where rule 1 is
    // supposed to be exact. The cap here is KEY_LINE_CAP, the same one an
    // authorized_keys line gets, so no key anyone actually uses is cut at all;
    // and the length is carried anyway, because a cap is a cliff and the flag
    // is what makes going over it safe rather than merely unlikely.
    //
    // THE SPLIT. `sp_clean` DELETES control characters, newline included, so
    // `AuthenticationMethods publickey,publickey` — two factors, one per line
    // in this variable — flattened into a single corrupt record that parsed as
    // nothing. Splitting first protects every key the session presented instead
    // of, at best, the first.
    'sp_auth() {',
    `SP_A=$(printf '%s' "$1" | tr '\\011' ' ' | tr -d '\\000-\\037\\177')`,
    'SP_AN=${#SP_A}',
    `[ "$SP_AN" -gt 0 ] && printf 'A %s %s\\n' "$SP_AN" "$(printf '%s' "$SP_A" | cut -c1-${KEY_LINE_CAP})"`,
    '}',
    `printf '%s\\n' "$SSH_AUTH_INFO_0" | while IFS= read -r SP_AL; do sp_auth "$SP_AL"; done`,

    // ---- sshd: where does it actually look for keys? ---------------------
    // First, because it decides whether everything below is the whole story.
    // Every matching directive is emitted rather than the first one: sshd
    // resolves first-match-wins, Debian puts `Include sshd_config.d/*.conf` at
    // the TOP of the file so an included file wins, and guessing which applies
    // from out here would be a guess. Two disagreeing directives report as
    // ambiguous, which is the truth.
    //
    // TRAVERSAL BEFORE EXISTENCE, the same discipline the account loop below
    // applies to a home directory and did not used to apply here. `chmod 700
    // /etc/ssh` is on plenty of hardened images; `[ -e /etc/ssh/sshd_config ]`
    // through a directory this account cannot enter is FALSE, which is
    // indistinguishable from the file not being there — and `absent` takes the
    // parser's "no config, so the compiled-in default applies" branch straight
    // to `keyFileIsDefault = true`. A permission bit reading as a clean bill of
    // health, one directory up from where the same mistake was already guarded
    // against.
    //
    // AND A FILE SKIPPED IS A FILE REPORTED. A 0600 root-only hardening
    // drop-in is ordinary. Skipping it silently and then noting `ok` meant the
    // parser saw zero AuthorizedKeysFile directives, concluded the default was
    // in force, and called the inventory complete over a config it had read
    // part of. The note is decided in a variable and emitted ONCE at the end so
    // there is exactly one status for this source, whichever branch set it.
    ...ifSudo(...findBin('sshd', 'SP_SSHDBIN')),
    'SP_SSHD=""',
    'SP_SSHD_MISS=0',
    'SP_SSHD_ST=ok',
    'SP_SSHD_W="-"',
    'SP_SSHD_D="-"',
    'if [ ! -d /etc/ssh ]; then',
    'SP_SSHD_ST=absent; SP_SSHD_D="this host has no /etc/ssh directory"',
    'elif [ ! -x /etc/ssh ]; then',
    'SP_SSHD_ST=denied; SP_SSHD_MISS=1',
    'SP_SSHD_D="/etc/ssh exists and this account cannot enter it, so nothing about where sshd looks for keys was read"',
    'elif [ -r /etc/ssh/sshd_config ]; then',
    'SP_SSHD=/etc/ssh/sshd_config',
    'SP_SSHD_D="$SP_SSHD"',
    'for f in /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf; do',
    '[ -f "$f" ] || continue',
    'if [ -r "$f" ]; then',
    `sp_val keyfile "$(grep -i -E '^[[:space:]]*AuthorizedKeysFile[[:space:]]' "$f" 2>/dev/null | head -1)"`,
    `sp_val keycmd "$(grep -i -E '^[[:space:]]*AuthorizedKeysCommand[[:space:]]' "$f" 2>/dev/null | head -1)"`,
    'else',
    'SP_SSHD_MISS=1',
    'fi',
    'done',
    // A drop-in directory that cannot be entered hides an unknown number of
    // files, so it is the same finding as one unreadable file and worse.
    '[ -d /etc/ssh/sshd_config.d ] && [ ! -x /etc/ssh/sshd_config.d ] && SP_SSHD_MISS=1',
    'if [ "$SP_SSHD_MISS" = 1 ]; then',
    'SP_SSHD_ST=partial',
    'SP_SSHD_D="a file under /etc/ssh could not be read, so a directive moving the key file may not be in what was read"',
    'fi',
    'elif [ -e /etc/ssh/sshd_config ]; then',
    'SP_SSHD_ST=denied; SP_SSHD_MISS=1',
    'SP_SSHD_D="sshd_config exists and this account cannot read it"',
    'else',
    'SP_SSHD_ST=absent; SP_SSHD_D="this host has no /etc/ssh/sshd_config"',
    'fi',
    ...ifSudo(
      // `sshd -T` prints the EFFECTIVE configuration, every Include resolved
      // and every drop-in applied, so it settles in one call what a pile of
      // file reads can only approximate.
      //
      // Asked for ONLY when the unprivileged read produced no directives at
      // all — /etc/ssh untraversable, or sshd_config itself unreadable. Where
      // some files WERE read, adding a second, differently-spelled copy of the
      // same directive (`sshd -T` prints the resolved list, the file prints
      // what somebody typed) would make the two disagree and report ambiguity
      // where there is none, or force this to arbitrate between them — which
      // is exactly what the "two disagreeing directives report as ambiguous"
      // rule above refuses to do. A `partial` stays `partial`.
      'if [ "$SP_SSHD_MISS" = 1 ] && [ -z "$SP_SSHD" ] && [ "$SP_SUDO" = 1 ] && [ -n "$SP_SSHDBIN" ]; then',
      'SP_SSHD_T=$(sudo -n "$SP_SSHDBIN" -T 2>/dev/null || true)',
      'if [ -n "$SP_SSHD_T" ]; then',
      `sp_val keyfile "$(printf '%s\\n' "$SP_SSHD_T" | grep -i -E '^[[:space:]]*AuthorizedKeysFile[[:space:]]' | head -1)"`,
      `sp_val keycmd "$(printf '%s\\n' "$SP_SSHD_T" | grep -i -E '^[[:space:]]*AuthorizedKeysCommand[[:space:]]' | head -1)"`,
      'SP_SSHD_ST=ok; SP_SSHD_W=root',
      'SP_SSHD_D="sshd -T reported the effective configuration"',
      'fi',
      'fi'
    ),
    'sp_note sshd-config "$SP_SSHD_ST" "$SP_SSHD_W" "$SP_SSHD_D"',

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

    // authorized_keys2: deprecated since 2001, still consulted by sshd, and a
    // key hiding in it is exactly what this feature exists to surface.
    // Reported, not read.
    //
    // THREE STATES, and the same traversal-first discipline as the main file
    // above. This used to be a bare `[ -e ]` running as the connecting account,
    // sitting AFTER the escalation block — so on a 0700 home `sudo -n cat` set
    // the main file to `ok` (the account IS read, as root) while this test
    // returned false through a directory the connecting account cannot enter.
    // `hasLegacyKeyFile` came out false, contributed no uncertainty, and a key
    // in ~deploy/.ssh/authorized_keys2 was invisible under a banner saying the
    // picture was complete. "We could not look" is now its own answer.
    'SP_K2=unknown',
    'if [ -z "$SP_HOME" ]; then SP_K2=absent',
    'elif [ ! -d "$SP_HOME" ]; then SP_K2=absent',
    'elif [ ! -x "$SP_HOME" ]; then SP_K2=unknown',
    'elif [ ! -d "$SP_HOME/.ssh" ]; then SP_K2=absent',
    'elif [ ! -x "$SP_HOME/.ssh" ]; then SP_K2=unknown',
    'elif [ -e "$SP_HOME/.ssh/authorized_keys2" ]; then SP_K2=present',
    'else SP_K2=absent',
    'fi',
    ...ifSudo(
      // The same escalation the main file gets, for the same reason: root
      // settles it, so the answer stops being an inference from a permission
      // bit. `--` because a home path out of /etc/passwd can begin with a dash.
      'if [ "$SP_K2" = unknown ] && [ "$SP_SUDO" = 1 ] && [ -n "$SP_HOME" ]; then',
      'if sudo -n ls -d -- "$SP_HOME/.ssh/authorized_keys2" >/dev/null 2>&1; then SP_K2=present',
      'else SP_K2=absent',
      'fi',
      'fi'
    ),
    'sp_user "$SP_I" keys2 "$SP_K2"',
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

// ---- Certificates ---------------------------------------------------------

/**
 * For each certificate type, the plain key it certifies and how many of the
 * certificate's length-prefixed fields — the ones straight after the nonce —
 * make up that key.
 *
 * A certificate blob is `string type, string nonce, <the key's own fields>,
 * uint64 serial, …`. The key's fields are exactly the ones that follow its own
 * algorithm name in a plain blob, so the inner public key is recovered by
 * putting the plain type name back in front of them — which is why this table
 * is field COUNTS and not offsets.
 *
 * Sizes, per PROTOCOL.certkeys: RSA is `e, n`; DSA is `p, q, g, y`; Ed25519 is
 * the key alone; ECDSA is `curve, point`; and the security-key variants carry
 * one more field, the application string, which is part of the key blob and
 * therefore part of what is fingerprinted.
 */
const CERT_INNER: Record<string, { type: KeyType; fields: number }> = {
  'ssh-rsa-cert-v01@openssh.com': { type: 'ssh-rsa', fields: 2 },
  'ssh-dss-cert-v01@openssh.com': { type: 'ssh-dss', fields: 4 },
  'ssh-ed25519-cert-v01@openssh.com': { type: 'ssh-ed25519', fields: 1 },
  'ecdsa-sha2-nistp256-cert-v01@openssh.com': { type: 'ecdsa-sha2-nistp256', fields: 2 },
  'ecdsa-sha2-nistp384-cert-v01@openssh.com': { type: 'ecdsa-sha2-nistp384', fields: 2 },
  'ecdsa-sha2-nistp521-cert-v01@openssh.com': { type: 'ecdsa-sha2-nistp521', fields: 2 },
  'sk-ssh-ed25519-cert-v01@openssh.com': { type: 'sk-ssh-ed25519@openssh.com', fields: 2 },
  'sk-ecdsa-sha2-nistp256-cert-v01@openssh.com': {
    type: 'sk-ecdsa-sha2-nistp256@openssh.com',
    fields: 3
  }
}

/** Is this type a certificate rather than a bare key? */
export function isCertificateType(type: string): boolean {
  return Object.prototype.hasOwnProperty.call(CERT_INNER, type)
}

/** The inverse of `sshFields` for the fields it hands back. */
function sshEncode(parts: Uint8Array[]): Uint8Array {
  let n = 0
  for (const p of parts) n += 4 + p.length
  const out = new Uint8Array(n)
  let i = 0
  for (const p of parts) {
    out[i++] = (p.length >>> 24) & 0xff
    out[i++] = (p.length >>> 16) & 0xff
    out[i++] = (p.length >>> 8) & 0xff
    out[i++] = p.length & 0xff
    out.set(p, i)
    i += p.length
  }
  return out
}

const asciiBytes = (s: string): Uint8Array => Uint8Array.from(s, (c) => c.charCodeAt(0) & 0xff)

/**
 * The public key a certificate certifies, as a plain key blob.
 *
 * THE fix for the finding this exists to close. `ssh-keygen -l` on a
 * certificate prints the fingerprint of the key inside it, identical to the
 * fingerprint of the plain key — because that is the identity anybody cares
 * about. Hashing the certificate blob instead produces a value that is
 * different for every certificate ever issued to the same key, since the nonce
 * is random by design: it matches nothing on any other host, and it looks
 * exactly like an answer.
 *
 * Returns null rather than a partial reconstruction whenever the structure does
 * not hold — an unknown certificate type, an algorithm name inside that is not
 * the one on the line, or a blob too short for the fields the type requires.
 * The caller reports `certificate` and fingerprints nothing.
 */
export function certifiedKeyBlob(
  certType: string,
  cert: Uint8Array
): { type: KeyType; blob: Uint8Array } | null {
  const inner = CERT_INNER[certType]
  if (!inner) return null
  // name, nonce, then the key's own fields — and no more, so a cert whose key
  // fields run into the serial is caught by the length check rather than
  // silently absorbing the wrong bytes.
  const want = 2 + inner.fields
  const fields = sshFields(cert, want)
  if (fields === null || fields.length !== want) return null
  if (ascii(fields[0]) !== certType) return null
  return {
    type: inner.type,
    blob: sshEncode([asciiBytes(inner.type), ...fields.slice(2)])
  }
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
    broadened: false,
    certificate: false,
    line,
    problem: 'malformed',
    blob: null
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
    (/[=,]/.test(split.options) || KNOWN_OPTIONS.includes(split.options.toLowerCase()))
  const hasOptions = !(KEY_TYPES as readonly string[]).includes(firstToken) && looksLikeOptions
  if (hasOptions && split) {
    base.options = parseKeyOptionNames(split.options)
    base.restricted = base.options.some((o) =>
      (RESTRICTING_OPTIONS as readonly string[]).includes(o)
    )
    // Separate, and never OR'd into the line above. `cert-authority` is the one
    // option that makes a line trust more rather than less.
    base.broadened = base.options.some((o) =>
      (BROADENING_OPTIONS as readonly string[]).includes(o)
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

  if (isCertificateType(type)) {
    // The key INSIDE the certificate, which is what `ssh-keygen -l` prints and
    // the only value that means anything across hosts. See certifiedKeyBlob.
    const certified = certifiedKeyBlob(type, blob)
    if (certified === null) return { ...base, type, certificate: true, problem: 'certificate' }
    return {
      ...base,
      type,
      certificate: true,
      fingerprint: sshFingerprint(certified.blob, sha256),
      bits: keyBits(certified.type, certified.blob),
      problem: null,
      // Deliberately not the certificate's own body — see the field's own note.
      blob: null
    }
  }

  return {
    ...base,
    type,
    fingerprint: sshFingerprint(blob, sha256),
    bits: keyBits(type, blob),
    problem: null,
    // Only on a key that decoded and whose declared type matched the type
    // inside it. A blob kept for a line that failed either check would be a
    // blob the write half might one day match on.
    blob: blob64
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
  /** One per line of SSH_AUTH_INFO_0, with the length it had before the
   *  collector's cap. */
  const authFactors: { len: number; text: string }[] = []

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

    if (tag === 'A ') {
      // `A <length-before-truncation> <factor>`, shaped like `K` and for the
      // same reason: without the length there is no way to tell a factor that
      // fitted from one that was cut.
      const m = /^A (\d{1,9}) (.*)$/.exec(line)
      if (!m) continue
      authFactors.push({ len: Number(m[1]), text: m[2] })
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

  // `SSH_AUTH_INFO_0` is `<method> [<keytype> <blob>]`, ONE LINE PER FACTOR.
  // Fingerprinted through exactly the same path an authorized_keys line takes —
  // the same parser, the same truncation flag — so a match against one is a
  // match on identical terms rather than on two implementations that agree
  // today.
  //
  // EVERY FAILURE HERE CLEARS `certain` RATHER THAN BEING SKIPPED. A factor
  // this cannot read is a key that might be holding the connection open and
  // cannot be named, which is precisely the state the conservative half of rule
  // 1 exists for. Dropping it quietly would leave a list that looks complete.
  const sessionKeyFingerprints: string[] = []
  let sessionKeysCertain = authFactors.length > 0
  for (const f of authFactors) {
    const text = f.text.trim()
    if (!/^publickey\b/.test(text)) {
      // A `password` or `keyboard-interactive` factor names no key. It is not a
      // failure to read one — but it is not a key this can protect either, so
      // it neither adds to the list nor clears the flag on its own.
      continue
    }
    const m = /^publickey\s+(\S+\s+\S+)\s*$/.exec(text)
    if (!m) {
      sessionKeysCertain = false
      continue
    }
    // `f.len > KEY_LINE_CAP` is the flag the authorized_keys path already
    // passes 60 lines below, and its absence here was the bypass: a cut blob
    // decodes to a different key rather than to nothing, so the fingerprint
    // came out looking like an answer.
    const fp =
      parseAuthorizedKeyLine(m[1], 0, deps.sha256, f.len > KEY_LINE_CAP)?.fingerprint ?? null
    if (fp === null) sessionKeysCertain = false
    else sessionKeyFingerprints.push(fp)
  }
  // A session the host says used no key at all leaves nothing to compare
  // against, and the account ShellPilot connects as is not where this build
  // spends a maybe. Treated as "cannot tell", which is the conservative branch.
  if (sessionKeyFingerprints.length === 0) sessionKeysCertain = false

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
  // for "the config was unreadable", for "part of the config was unreadable",
  // and for "the config disagrees with itself", because all three mean the same
  // thing to a reader: the inventory below may not be the whole story and
  // nobody can say from here.
  //
  // Only `absent` and `ok` conclude anything, and that is stated as a rule
  // rather than left to fall out of the branches: `partial` reaching the `ok`
  // arm would answer "yes, the default is in force" from a config file this
  // collection read some of, which is the finding this whole block exists to
  // stop.
  let keyFileIsDefault: boolean | null = null
  // The question the WRITE half needs answered, which is not the one above.
  // See `readsTheFileWeRead` on HostAccess for why they came apart.
  let readsTheFileWeRead: boolean | null = null
  let readsLegacyKeyFile: boolean | null = null
  const onTheCompiledInDefault = (): void => {
    keyFileIsDefault = true
    readsTheFileWeRead = true
    readsLegacyKeyFile = true
  }
  if (source('sshd-config').status === 'absent') {
    // No sshd_config at all means sshd, if it is running, is on its
    // compiled-in defaults — which is exactly where this looked.
    onTheCompiledInDefault()
  } else if (source('sshd-config').status === 'ok') {
    if (authorizedKeysFile.length === 0) onTheCompiledInDefault()
    else if (authorizedKeysFile.length === 1) {
      const paths = authorizedKeysFile[0].split(/\s+/).filter((p) => p !== '')
      // `paths.length > 0` is not a formality. `.every()` over an EMPTY list is
      // true, so an `AuthorizedKeysFile` directive whose value did not survive
      // sanitising answered "yes, the default is in force" — the same trap one
      // level down from the one this block exists to fix.
      const named = paths.map((p) => p.replace(/^%h\//, ''))
      keyFileIsDefault = named.length > 0 && named.every((p) => DEFAULT_KEY_FILES.includes(p))
      // CONTAINS, not is-a-subset-of. This is the fix: a directive naming only
      // `.ssh/authorized_keys2` is a subset of the default list and is not the
      // file this collection read.
      readsTheFileWeRead = named.includes('.ssh/authorized_keys')
      readsLegacyKeyFile = named.includes('.ssh/authorized_keys2')
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
    // key set was ESTABLISHED. Everything else gets null and a reason.
    //
    // TWO statuses establish it, not one. `ok` read the file. `absent` is a
    // POSITIVE finding, and the collector goes to real trouble for it: it tests
    // that the home directory and `.ssh` can be traversed BEFORE testing
    // whether the file is there, precisely so a permission bit can never read
    // as an empty inventory — and where the connecting account cannot tell, the
    // sudo branch settles it as root or reports `unknown` rather than `absent`.
    // An account that reached here as `absent` has had its key set determined
    // to be empty. Calling that unread put the "this is not a complete picture"
    // banner up permanently on estates with nothing wrong with them, and a
    // banner that is always up is wallpaper.
    //
    // `denied`, `unknown`, `no-tool`, `unsupported` and `partial` stay null.
    // None of them was checked, and a null is the only honest value.
    let keys: AuthorizedKey[] | null = null
    if (keysStatus === 'ok' || keysStatus === 'absent') {
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
      // 'present' → yes, 'unknown' → the host said it could not tell, anything
      // else → no. A MISSING record reads as no: the collector emits this word
      // unconditionally for every account it emits at all, so its absence means
      // a malformed record stream rather than a host declining to answer — and
      // that case is already reported, loudly, by `keysStatus`.
      hasLegacyKeyFile:
        f.get('keys2') === 'present' ? true : f.get('keys2') === 'unknown' ? null : false,
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
    readsTheFileWeRead,
    readsLegacyKeyFile,
    authorizedKeysCommand,
    collectedAs,
    sessionKeyFingerprints,
    sessionKeysCertain,
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
   * Lines carrying `cert-authority` — trust delegated to a certificate
   * authority rather than granted to a key.
   *
   * Its own number and NOT part of `restricted`, which it used to be counted
   * in. It points the other way: a CA line makes the host accept everything
   * that CA will ever sign, including keys nobody has generated yet, and no
   * inventory of files on hosts can enumerate them.
   */
  certificateAuthorities: number
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
  let certificateAuthorities = 0
  for (const a of readAccounts) {
    for (const k of a.keys ?? []) {
      keys++
      if (k.fingerprint === null) unfingerprinted++
      else fingerprints.add(k.fingerprint)
      if (k.restricted) restricted++
      if (k.broadened) certificateAuthorities++
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
  // The narrower fact, and the one a reader most needs. `AuthorizedKeysFile
  // .ssh/authorized_keys2` names nothing outside the compiled-in default list,
  // so the clause above stays quiet — and every key on this screen is still a
  // key sshd does not look at.
  if (access.readsTheFileWeRead === false) {
    uncertainty.push(
      'sshd does not read .ssh/authorized_keys on this host, which is the file this collection read, so the keys listed here are not the keys it accepts'
    )
  }
  const legacy = access.accounts.filter((a) => a.hasLegacyKeyFile === true).map((a) => a.user)
  if (legacy.length > 0) {
    uncertainty.push(
      `${legacy.length} account${legacy.length === 1 ? ' has' : 's have'} a legacy .ssh/authorized_keys2 file, which sshd still reads and this collection does not`
    )
  }
  // "We could not look" is a different sentence from "it is there", and it has
  // to be one of these too: a key in a file sshd reads and this does not, on an
  // account nobody could check, is exactly what a complete-picture banner over
  // the top of it would hide.
  const legacyUnknown = access.accounts.filter((a) => a.hasLegacyKeyFile === null).map((a) => a.user)
  if (legacyUnknown.length > 0) {
    uncertainty.push(
      `${legacyUnknown.length} account${legacyUnknown.length === 1 ? '' : 's'} could not be checked for a legacy .ssh/authorized_keys2 file, which sshd still reads and this collection does not`
    )
  }
  if (unfingerprinted > 0) {
    uncertainty.push(
      `${unfingerprinted} line${unfingerprinted === 1 ? '' : 's'} in a file that was read could not be fingerprinted, so ${unfingerprinted === 1 ? 'it' : 'they'} cannot be matched against other hosts`
    )
  }
  // The one uncertainty that no amount of reading can remove. A cert-authority
  // line delegates trust to a signer, so the set of keys this host accepts is
  // not written down on this host — or on any other.
  if (certificateAuthorities > 0) {
    uncertainty.push(
      `${certificateAuthorities} line${certificateAuthorities === 1 ? '' : 's'} trust${certificateAuthorities === 1 ? 's' : ''} a certificate authority, so this host also accepts every key that authority signs — including keys that do not exist yet and are in no file anywhere`
    )
  }

  return {
    accountsRead: readAccounts.length,
    accountsUnread: unread,
    keys,
    fingerprints,
    unfingerprinted,
    restricted,
    certificateAuthorities,
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
    // The status, never a silence. `unknown` in the history is the difference
    // between "this account had no second key file" and "nobody could tell".
    out[`${base}legacyKeyFile`] =
      a.hasLegacyKeyFile === null ? 'unknown' : a.hasLegacyKeyFile ? 'present' : 'absent'
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

// ---------------------------------------------------------------------------
// The write half — roadmap item 23, stage 2
// ---------------------------------------------------------------------------
//
// Writing `authorized_keys` is the highest-consequence write this app can make.
// Every other write it does is recoverable from the terminal it opened; a bad
// one here locks you out of the host you would use to fix it, and if it is
// rolled across a selection it locks you out of all of them at once, in the
// order they were healthy.
//
// So this half is built as a PROTOCOL rather than a command, and the protocol
// is the feature. Three rules, none of them optional, none of them a warning:
//
//  1. NEVER REMOVE THE KEY THE CURRENT SESSION IS AUTHENTICATED WITH.
//     Enforced as a hard block on the plan, not a dialog. Where sshd will say
//     which key that is (`ExposeAuthInfo`, collected as
//     `sessionKeyFingerprints`), the check is exact. Where it will not — the
//     default on most hosts — the plan says so, and a revoke against the
//     account this session is running as is blocked outright rather than
//     attempted on a guess. Revoking a DIFFERENT account's key cannot lock this
//     session out and is allowed; that distinction is what keeps the rule from
//     being either useless or a lie.
//
//  2. NEVER COMMIT WITHOUT A SECOND, INDEPENDENT SESSION.
//     Implemented as a dead-man's switch rather than as verify-then-commit,
//     because verify-then-commit still has a window: the verifier passes, the
//     next connection does not, and nothing on the host is watching. Here the
//     staged write ARMS a restore on the host itself. If nobody disarms it
//     within the deadline the host puts the old file back with no help from us
//     — which is the only form of safety that survives us being the thing that
//     is locked out. The disarm command is returned separately from the job and
//     is the ONLY thing that makes the change permanent.
//
//  3. ALWAYS LEAVE A TIMESTAMPED BACKUP ON THE HOST.
//     `cp -p` before anything else, into a name carrying the collection's own
//     timestamp, and the write does not proceed if the backup did not land. A
//     backup the operator can find in a shell is worth more than any rollback
//     this app can offer, because it works when this app is not the thing
//     holding the connection.
//
// ---------------------------------------------------------------------------
// What is deliberately NOT here, and will not be added casually
// ---------------------------------------------------------------------------
//
// The same shape as the docker module's refusal to ship `prune`, for the same
// reason: the argument has to be written down where the next person will read
// it before adding the button.
//
//  * ANYTHING THAT ISSUES THE DISARM. `accessDisarmCommand()` exists and
//    nothing in this repository calls it. Rule 2 is only real if the disarm
//    happens after a genuinely independent AUTHENTICATION — a new connection
//    that presented a key to sshd and was accepted — and the job engine cannot
//    provide one: steps share a pooled, already-authenticated transport, so a
//    step that "verifies" proves only that the session which wrote the file can
//    still write files. Shipping a disarm that runs as another job step would
//    turn rule 2 into a comment. What has to exist first is a connection test
//    that forcibly drops any pooled connection for the host and re-authenticates
//    from scratch; until it does, the change is staged, the host's own watchdog
//    is the safety net, and nothing here makes anything permanent.
//
//  * REPLACING A FILE WHOLESALE. Add and revoke are both edits to the file as
//    it was READ this hour, expressed as an append or as an exact-blob removal.
//    A "set the keys on this host to exactly these" operation cannot be made
//    safe from an inventory that may be an hour old: it would silently delete a
//    key added since, and the person who added it is the person who most needs
//    it to be there.
//
//  * REVOKING FROM AN ACCOUNT WHOSE FILE WAS NOT READ. There is no line to
//    remove and no count to check afterwards, so the operation cannot verify
//    itself. It is a block, not a skip — an account quietly left out of a
//    fleet-wide revocation is the exact failure the read half exists to prevent.
//
//  * `sudo` IN THE WRITE. The read half escalates because reading another
//    account's key file is normal and harmless. Writing one is not, and an
//    escalated write is a write nobody watching the sudo log can distinguish
//    from an attacker with the same access. Every command built here runs as
//    the connecting account, against files it can already write, and a host
//    where that is not enough is a host this should refuse rather than force.

// ---------------------------------------------------------------------------
// THE GATE
// ---------------------------------------------------------------------------
//
// The write half is switched off in this build. The read half ships without
// it.
//
// WHY, in one sentence: adversarial review found five blockers in the plan
// path, and every one of them sits behind a promise of safety rather than in
// front of it — which makes shipping the buttons worse than shipping nothing.
// The dead-man's rollback in rule 2 is the whole reason a key change is offered
// at all, and A ROLLBACK THAT CANNOT BE RELIED ON IS WORSE THAN NO ROLLBACK,
// because the operator is told they are safe. Somebody with no rollback tries
// one host and keeps a terminal open. Somebody who believes they have one
// selects twelve.
//
// WHAT IS NOT DONE HERE, and this part matters as much: nothing below is
// deleted. `planAccessChange`, `buildStagedWrite`, `buildRevokeKeyCommand`,
// `buildAddKeyCommand`, `accessDisarmCommand` and `AccessCommitter` all stay,
// and so does every test they have. They are being fixed next, and those tests
// are the written record of what is wrong with them. Deleting the code along
// with the button would delete the evidence and the argument at the same time.
//
// HOW IT IS ENFORCED. Main checks this constant at the top of both
// `access:plan` and `access:run`, before anything is derived — so it covers
// every caller and not only the renderer. The panel reads the same constant to
// decide whether to draw a button, and prints ACCESS_WRITE_DISABLED_REASON
// where the button would have been, because a control that quietly vanished
// reads as a feature that has not arrived rather than one that was withdrawn.
// tests/accessWrite.test.ts fails if either half of that stops being true.
export const ACCESS_WRITE_ENABLED = false

/**
 * What the panel says where the button would be. One source of words, so the
 * renderer and anything else that has to explain this cannot drift apart.
 */
export const ACCESS_WRITE_DISABLED_REASON =
  'Changing authorized keys is not enabled in this build. The safety net behind it — the host ' +
  'restoring its own previous file if nothing confirms the change — is not yet dependable, and a ' +
  'rollback that cannot be relied on is worse than no rollback at all, because it tells you that ' +
  'you are safe. Reading is unaffected: nothing on this screen writes to any host.'

/**
 * What the write half will and will not be able to do when it is switched back
 * on, said before anybody picks a target.
 *
 * Scope honesty, and it belongs in front of the feature rather than in a
 * refusal after somebody has selected twelve hosts. "Revoke a key across the
 * fleet" describes something broader than what this builds: the staged command
 * resolves `$HOME/.ssh/authorized_keys` on the host, so it can only ever edit
 * the account ShellPilot connects as — and rule 1 blocks it even there unless
 * sshd will say which key the session is authenticated with, which is off by
 * default.
 */
export const ACCESS_WRITE_SCOPE =
  'Even once it is enabled it will only ever edit ~/.ssh/authorized_keys for the account ' +
  'ShellPilot connects as on each host — not another account\u2019s file, and not any path sshd was ' +
  'configured to read instead. On the account it connects as it also needs the host to report ' +
  'which key this session authenticated with (sshd\u2019s ExposeAuthInfo, off by default); without ' +
  'that it refuses, because nothing can prove the key being removed is not the one holding the ' +
  'connection open.'

/** How long the host waits for a disarm before putting the old file back.
 *
 *  Long enough for a person to try a real connection from a real terminal, and
 *  short enough that a forgotten stage does not leave a machine in a half-state
 *  overnight. It is a restore, so erring long costs an unwanted rollback and
 *  erring short costs nothing but a retry. */
export const ACCESS_ROLLBACK_SECONDS = 300

/** The marker whose EXISTENCE disarms the watchdog. Named per change, so two
 *  overlapping stages on one host cannot disarm each other. */
export function accessCommitMarker(token: string): string {
  return `.shellpilot-access-${token}.commit`
}

export type AccessChangeKind = 'add' | 'revoke'

export interface AccessChangeRequest {
  kind: AccessChangeKind
  /**
   * For `add`: the authorized_keys line to append, exactly as it will be
   * written. For `revoke`: unused — the key is named by fingerprint.
   */
  keyLine?: string
  /** For `revoke`: which key, by the fingerprint the read half computed. */
  fingerprint?: string
  /** One entry per host and account the change applies to. */
  targets: AccessChangeTarget[]
  /** Milliseconds, used to name the backup and the change token. Injected so a
   *  test pins it and so two hosts in one run share one name. */
  now: number
  /** Fingerprints that must never be removed, whatever else is asked.
   *  The caller adds anything it knows; the session key is added here. */
  protect?: string[]
  /** How long the host waits before restoring itself. Injected ONLY so a test
   *  can watch a real rollback happen rather than assert on the text of a
   *  `sleep`; nothing in the app passes it. */
  rollbackSeconds?: number
}

export interface AccessChangeTarget {
  serverId: string
  serverName: string
  /** The collection this change is derived from. A change is always an edit to
   *  a file that was READ, never to one that was assumed. */
  access: HostAccess
  /** Which account on that host. */
  user: string
}

/** A refusal. Never a warning and never overridable: every one of these is a
 *  case where proceeding could remove the only way back into the host. */
export interface AccessBlock {
  serverId: string
  serverName: string
  user: string
  kind:
    /** Rule 1, exactly: the key asked for is the key this session is on. */
    | 'is-session-key'
    /** Rule 1, conservatively: the host will not say which key this session is
     *  on, and this revoke targets the account the session runs as. */
    | 'session-key-unknown'
    /** The account's file was not read, so there is nothing to edit and no
     *  count to check afterwards. */
    | 'not-read'
    /** The key is not on this account, so removing it would be a no-op the run
     *  would nevertheless report as a change. */
    | 'not-present'
    /** The key is already on this account. */
    | 'already-present'
    /** sshd reads keys from somewhere this does not, so an edit here may not be
     *  the edit that matters. */
    | 'not-the-file-sshd-reads'
  reason: string
}

/**
 * A `JobSpec` and a `JobTargetRef`, declared structurally rather than imported.
 *
 * NOT a style choice. tests/jobsNotExposed.test.ts walks the import closure of
 * everything the MCP bridge and the CLI can reach and fails if any of it
 * imports the job engine — because `denyAllPending()`, the stop-all-AI-access
 * switch, works by resolving PENDING requests, and a job already running on
 * fifteen hosts has nothing pending. This file is reached from the fleet
 * sampler, which the bridge reads, so importing `./jobs` for two type aliases
 * would put the job vocabulary inside that closure for the sake of a compiler
 * convenience.
 *
 * The shapes are still checked against the real ones: tests/accessWrite.test.ts
 * assigns a produced spec to a `JobSpec` and a produced target list to
 * `JobTargetRef[]`, so a drift between the two is a compile error in a place
 * that is allowed to import both.
 */
export interface AccessJobSpec {
  /**
   * `access`, not `command`, and the difference is what a job list is FOR.
   *
   * A key change staged by this planner is a change record — this host stopped
   * trusting that key on the 14th — and a row that could not be told apart
   * from somebody's ad-hoc `systemctl restart nginx` would make the audit
   * trail this whole item exists to produce unfilterable. The kind is declared
   * on the jobs side (`JobKind` in src/shared/jobs.ts) because this file may
   * not import that one; see the note on this interface.
   *
   * It changes nothing about how the job runs, and it does NOT mean the change
   * is permanent: an `access` job stages, and only a confirmation over an
   * independent session commits.
   */
  kind: 'access'
  title: string
  steps: { command: string }[]
  concurrency?: number
}

export interface AccessJobTarget {
  serverId: string
  serverName: string
}

export interface AccessChangePlan {
  /** The job, or null when every target was blocked. */
  spec: AccessJobSpec | null
  targets: AccessJobTarget[]
  blocks: AccessBlock[]
  /** Per host, what the disarm would be. Returned separately from the job on
   *  purpose — see the refusal above. Nothing in this repository calls it. */
  disarm: { serverId: string; command: string }[]
  /** The token naming this change's backup and marker on every host. */
  token: string
  /** Seconds the host will wait before restoring itself. */
  rollbackSeconds: number
}

/** Used where a line is being validated rather than identified. */
const SHAPE_ONLY_HASH: Sha256 = () => new Uint8Array(32)

// A base64 key blob and nothing else. Applied before the blob is put anywhere
// near a command: it is the one value from the collection that reaches a shell,
// and the character class is narrow enough that no quoting question arises.
const BLOB_RE = /^[A-Za-z0-9+/]{32,4096}={0,2}$/
// An authorized_keys line safe to append. Deliberately narrower than what sshd
// accepts: no quotes, no backticks, no dollars, no backslashes, nothing that
// changes meaning inside the single-quoted context it is written into. A key
// with an option value this rejects is a key to add by hand.
const APPENDABLE_RE = /^[A-Za-z0-9+/=@._:,\- ]{16,2048}$/

/**
 * Turn a requested change into a job, or into the reasons it is not one.
 *
 * Every refusal is a BLOCK. There is no path here that returns a warning for
 * something a person could click past, because the three rules at the top of
 * this section are the whole reason the feature is shippable and a rule with an
 * override is a default.
 */
export function planAccessChange(req: AccessChangeRequest): AccessChangePlan {
  const token = String(req.now)
  const blocks: AccessBlock[] = []
  const targets: AccessJobTarget[] = []
  const disarm: { serverId: string; command: string }[] = []
  const commands: string[] = []

  const key = req.kind === 'revoke' ? (req.fingerprint ?? '') : ''
  // Blobs, per host: the same key can be written with different comments on
  // different hosts, and the removal matches the BLOB.
  const perHost: { t: AccessChangeTarget; blob: string; path: string; count: number }[] = []

  for (const t of req.targets) {
    const account = t.access.accounts.find((a) => a.user === t.user)
    const block = (kind: AccessBlock['kind'], reason: string): void => {
      blocks.push({ serverId: t.serverId, serverName: t.serverName, user: t.user, kind, reason })
    }

    if (!account || account.keys === null || account.keyPath === null) {
      block(
        'not-read',
        `${t.user}'s authorized_keys on ${t.serverName} was not read in the last collection, so there is nothing to edit and no way to check the result. Reading it is the fix; guessing is not.`
      )
      continue
    }

    // sshd reading from somewhere else makes this edit possibly irrelevant —
    // and an irrelevant revocation is worse than no revocation, because it is
    // reported as done.
    //
    // `readsTheFileWeRead`, NOT `keyFileIsDefault`. Setting AuthorizedKeysFile
    // replaces OpenSSH's default list rather than adding to it, so a host
    // configured `AuthorizedKeysFile .ssh/authorized_keys2` names nothing
    // outside the default list — `keyFileIsDefault` was true — and reads only
    // keys2. The staged write then edited `~/.ssh/authorized_keys`, and the
    // revocation was staged, verified, committed and reported done with the key
    // still trusted. Which is, verbatim, what the sentence below calls worse
    // than none.
    //
    // `!== true` and not `=== false`, so `null` refuses too. Null is what a
    // config that could not be read, a config only PARTLY read, and a config
    // that disagrees with itself all produce, and none of the three is a
    // licence to edit a file on a guess.
    if (t.access.readsTheFileWeRead !== true || t.access.authorizedKeysCommand !== null) {
      block(
        'not-the-file-sshd-reads',
        `sshd on ${t.serverName} is not known to read ${account.keyPath}. Editing it may not change who can log in, and a revocation that is reported as done and did nothing is worse than none.`
      )
      continue
    }

    // The same failure from the other side, and the reason it is checked
    // separately: on a host that IS on the compiled-in default, sshd reads
    // `.ssh/authorized_keys2` as well. A key written into both files is still
    // trusted after this edits one of them — a revocation reported as done that
    // changed nothing about who can log in.
    //
    // `!== false`, so an account whose keys2 could not be checked refuses too.
    // "Nobody could look" is not "it is not there".
    if (
      req.kind === 'revoke' &&
      t.access.readsLegacyKeyFile !== false &&
      account.hasLegacyKeyFile !== false
    ) {
      block(
        'not-the-file-sshd-reads',
        account.hasLegacyKeyFile === null
          ? `${t.user}@${t.serverName} could not be checked for a legacy .ssh/authorized_keys2, which sshd also reads and this collection does not. A key in that file would survive this change and be reported as revoked.`
          : `${t.user}@${t.serverName} has a legacy .ssh/authorized_keys2, which sshd also reads and this collection does not. The same key may be in it, in which case this change would remove nothing and be reported as done.`
      )
      continue
    }

    if (req.kind === 'revoke') {
      const protect = new Set([...(req.protect ?? [])])
      for (const fp of t.access.sessionKeyFingerprints) protect.add(fp)

      // RULE 1, exactly.
      if (protect.has(key)) {
        block(
          'is-session-key',
          `that key is the one this session is authenticated with on ${t.serverName}. Removing it would end ShellPilot's own way back into the host, so it is refused here rather than confirmed anywhere.`
        )
        continue
      }
      // RULE 1, conservatively. `collectedAs` is the account this session runs
      // as; another account's keys cannot lock this session out, so the refusal
      // is scoped to the one that can.
      if (!t.access.sessionKeysCertain && t.access.collectedAs === t.user) {
        block(
          'session-key-unknown',
          `${t.serverName} did not name every key this session authenticated with — either sshd's ExposeAuthInfo is off, or what it said could not be turned into a fingerprint exactly — and this would edit the keys of the very account ShellPilot connects as. Without that fact nothing can prove the key being removed is not the one holding this connection open.`
        )
        continue
      }

      const matches = account.keys.filter((k) => k.fingerprint === key)
      if (matches.length === 0) {
        block(
          'not-present',
          `that key is not on ${t.user}@${t.serverName}. It is left out rather than counted as removed — a revocation report that includes hosts nothing happened on is not a revocation report.`
        )
        continue
      }
      // The blob is recovered from the line the read half kept. Validated
      // before it goes anywhere near a command; the character class is why no
      // quoting question arises.
      const blob = blobOf(account, key)
      if (blob === null || !BLOB_RE.test(blob)) {
        block(
          'not-read',
          `the stored copy of that key on ${t.serverName} is not in a form this can match exactly, so the removal could not be made precise. Nothing approximate is run against an authorized_keys file.`
        )
        continue
      }
      perHost.push({ t, blob, path: account.keyPath, count: matches.length })
    } else {
      const line = (req.keyLine ?? '').trim()
      // A constant hash, because only the SHAPE of the line is being checked
      // here — that it parses, that its type is one this build knows, and that
      // its body decodes and matches. The fingerprint of a key being ADDED is
      // computed by the next collection, off the host, where it belongs.
      const parsed = parseAuthorizedKeyLine(line, 1, SHAPE_ONLY_HASH)
      if (!parsed || parsed.problem !== null || !APPENDABLE_RE.test(line)) {
        block(
          'not-read',
          `the key to add is not a line this will write. It has to be a single authorized_keys entry this build can parse, using only characters that cannot change meaning inside a shell command.`
        )
        continue
      }
      const blob = line.split(/\s+/).find((p) => BLOB_RE.test(p)) ?? ''
      if (blob === '') {
        block('not-read', `the key to add has no readable body, so there is nothing to write.`)
        continue
      }
      if (account.keys.some((k) => k.fingerprint !== null && blobOfLine(k) === blob)) {
        block(
          'already-present',
          `that key is already on ${t.user}@${t.serverName}. Adding it again would leave a duplicate line and report a change that did not happen.`
        )
        continue
      }
      perHost.push({ t, blob: line, path: account.keyPath, count: 0 })
    }
  }

  for (const h of perHost) {
    targets.push({ serverId: h.t.serverId, serverName: h.t.serverName })
    disarm.push({
      serverId: h.t.serverId,
      command: accessDisarmCommand(h.path, token)
    })
  }

  // One job, one step list, one command — so `verifyApproval` can compare the
  // approved text against what runs. That means every host in the job must get
  // the SAME command, which is why the path is not interpolated per host: the
  // step resolves `$HOME` on the host instead. A selection spanning accounts
  // with different home directories is still one command, and a selection
  // spanning different ACCOUNTS is refused by construction — see the caller.
  let spec: AccessJobSpec | null = null
  if (perHost.length > 0) {
    const first = perHost[0]
    const command =
      req.kind === 'revoke'
        ? buildRevokeKeyCommand({
            path: first.path,
            blob: first.blob,
            token,
            expectRemoved: first.count,
            rollbackSeconds: req.rollbackSeconds
          })
        : buildAddKeyCommand({ path: first.path, line: first.blob, token, rollbackSeconds: req.rollbackSeconds })
    commands.push(command)
    spec = {
      kind: 'access',
      title:
        req.kind === 'revoke'
          ? `Stage revocation of ${key.slice(0, 22)}… from ${first.t.user}`
          : `Stage a new key for ${first.t.user}`,
      steps: [{ command }],
      // One host at a time. A key change rolled across a selection in parallel
      // is the case where a mistake reaches every machine before the first
      // failure is visible; serialised, the second host is still reachable
      // while the first is being looked at.
      concurrency: 1
    }
  }

  return { spec, targets, blocks, disarm, token, rollbackSeconds: ACCESS_ROLLBACK_SECONDS }
}

/** The base64 body of one stored key, for an exact-match removal. */
function blobOfLine(k: AuthorizedKey): string | null {
  return k.blob
}

/**
 * The body to match on for one fingerprint, or null when there is not exactly
 * one.
 *
 * EVERY line carrying the fingerprint is checked, not the first. A certificate
 * line fingerprints to the key inside it and deliberately keeps no body — so an
 * account trusting a key both plainly and through a certificate has two lines
 * for one fingerprint and only one body, and taking the first one would build a
 * removal that deletes one line while the plan's count expects two. The host
 * would catch it and roll back, which is safe and reads as a mystery. Refusing
 * here makes it a block with a sentence instead.
 */
function blobOf(account: AccessAccount, fingerprint: string): string | null {
  const bodies: (string | null)[] = []
  for (const k of account.keys ?? []) {
    if (k.fingerprint === fingerprint) bodies.push(blobOfLine(k))
  }
  if (bodies.length !== 1) return null
  return bodies[0]
}

/**
 * Stage a removal: back up, filter, replace, and arm the host's own restore.
 *
 * Nothing about this is atomic across the three, and it does not need to be —
 * what it needs is that no step can leave the file in a state the host cannot
 * get out of by itself. `cp -p` first so the backup exists before anything is
 * touched. `grep -v -F` into a NEW file so a failed filter cannot truncate the
 * original. `mv` last, which is atomic within the filesystem. And the watchdog
 * armed before the command returns, so a connection that dies in the next
 * second still ends with the old file back.
 */
export function buildRevokeKeyCommand(o: {
  path: string
  blob: string
  token: string
  expectRemoved: number
  rollbackSeconds?: number
}): string {
  if (!BLOB_RE.test(o.blob)) throw new Error('refusing to build a removal from an unvalidated key body')
  return buildStagedWrite({
    path: o.path,
    token: o.token,
    rollbackSeconds: o.rollbackSeconds,
    // -F is fixed-string and -v inverts: every line carrying this exact body
    // goes, and nothing else can match because a base64 body is not a
    // substring of anything else in the file.
    // `|| [ $? = 1 ]` and not `|| true`, and the difference is the whole point.
    // `grep -v` exits 1 when it selects NO lines, which is exactly what
    // revoking the last key on an account looks like — so a bare `||` failure
    // branch turns the most final revocation there is into "the new file could
    // not be built", and the count check that would have caught a real problem
    // never runs. Exit 2 is a real error and still stops the change.
    produce: `{ grep -v -F -- '${o.blob}' "$SP_F" > "$SP_T" || [ $? = 1 ]; }`,
    // The count is checked, not assumed. A filter that removed the wrong number
    // of lines is a filter that did something nobody asked for, and the answer
    // is to put the backup back rather than to report success.
    expect: `SP_WANT=$((SP_BEFORE-${o.expectRemoved}))`
  })
}

/** Stage an addition: back up, copy, append, replace, arm. */
export function buildAddKeyCommand(o: {
  path: string
  line: string
  token: string
  rollbackSeconds?: number
}): string {
  if (!APPENDABLE_RE.test(o.line)) throw new Error('refusing to build an append from an unvalidated line')
  return buildStagedWrite({
    path: o.path,
    token: o.token,
    rollbackSeconds: o.rollbackSeconds,
    // The trailing newline is not decoration: plenty of authorized_keys files
    // ship without one, and appending to such a file without adding it first
    // glues the new key onto the end of the last one — which sshd then reads as
    // one malformed line, silently removing the key that was already working.
    produce: `cp -p "$SP_F" "$SP_T" && { [ -s "$SP_T" ] && [ "$(tail -c1 "$SP_T")" != "" ] && printf '\\n' >> "$SP_T"; printf '%s\\n' '${o.line}' >> "$SP_T"; }`,
    expect: 'SP_WANT=$((SP_BEFORE+1))'
  })
}

/**
 * The shape both changes share.
 *
 * No `set -e`, as everywhere else in this file — but note that every step here
 * is chained with `&&` rather than being independent, which is the opposite
 * discipline and the right one: a read may fail and still leave a useful
 * collection, whereas a write whose backup failed must not proceed to the part
 * that replaces the file.
 */
function buildStagedWrite(o: {
  path: string
  token: string
  produce: string
  expect: string
  rollbackSeconds?: number
}): string {
  const marker = accessCommitMarker(o.token)
  const wait = o.rollbackSeconds ?? ACCESS_ROLLBACK_SECONDS
  return [
    'LC_ALL=C',
    'export LC_ALL',
    // The path is resolved on the host from $HOME, never interpolated, so one
    // approved command text covers every host in the selection and
    // verifyApproval has something to compare.
    `SP_F="$HOME/.ssh/authorized_keys"`,
    `SP_B="$SP_F.shellpilot-${o.token}.bak"`,
    `SP_T="$SP_F.shellpilot-${o.token}.new"`,
    `SP_M="$HOME/.ssh/${marker}"`,
    'SP_LOCK="$HOME/.ssh/.shellpilot-access.lock"',

    // ---- ONE STAGED CHANGE AT A TIME -------------------------------------
    //
    // Every stage arms an INDEPENDENT watchdog holding its own copy of whatever
    // the file was at ITS start, and the disarm marker is named per change — so
    // confirming change 2 says nothing whatsoever to change 1's watchdog. Two
    // revokes a second apart, the second verified and committed: the file was
    // right after the commit, and eleven seconds later the first watchdog put
    // BOTH revoked keys back, including the one the audit trail said was gone.
    //
    // The likely path is not two operators racing. It is one operator: a revoke
    // reports verification-failed, they fix the plan and restage inside the
    // 300-second window.
    //
    // THE ANSWER IS A REFUSAL, and it is chosen over making the watchdogs aware
    // of each other on purpose. The alternative in front of it was a lock
    // holding the live watchdog's pid, killed and replaced before arming — and
    // killing change 1's watchdog while change 1 is still unconfirmed is
    // exactly "silently make change 1 permanent", which is the same class of
    // failure pointing the other way. There is no version of overlapping
    // changes that is safe with one backup per host, and a host is only ever
    // blocked for as long as its own rollback window: the watchdog removes the
    // backup whichever way it goes, so the refusal clears itself.
    //
    // TWO MECHANISMS, because they cover different things. The `.bak` glob is
    // the durable one — it survives this process dying and is what actually
    // stops the restage-inside-the-window case. `mkdir` is atomic and covers
    // the sliver the glob cannot: two runs reaching the check between each
    // other's check and `cp`.
    // The two reasons `mkdir` fails are not the same reason and must not read
    // as one: the lock already being there is another change in flight, and
    // anything else is a `~/.ssh` this account cannot write — which is a
    // different problem with a different fix.
    'mkdir "$SP_LOCK" 2>/dev/null || { [ -d "$SP_LOCK" ] && { echo "another key change is starting on this host right now; nothing was changed" >&2; exit 6; }; echo "a lock could not be created in ~/.ssh, so nothing was changed" >&2; exit 3; }',
    'trap \'rmdir "$SP_LOCK" 2>/dev/null\' EXIT INT TERM HUP',
    'for SP_OLD in "$HOME"/.ssh/*.shellpilot-*.bak; do [ -e "$SP_OLD" ] || continue; echo "a key change staged earlier is still waiting for its rollback window to close ($SP_OLD); nothing was changed" >&2; exit 6; done',

    // Refuse before touching anything. A file this account cannot write is a
    // file the change cannot make, and finding that out after the backup is
    // written leaves litter for no reason.
    '[ -f "$SP_F" ] || { echo "no authorized_keys to change" >&2; exit 3; }',
    '[ -w "$SP_F" ] || { echo "authorized_keys is not writable by this account" >&2; exit 3; }',
    // RULE 3. Before anything else, and the run stops if it did not land.
    'cp -p "$SP_F" "$SP_B" || { rm -f "$SP_B"; echo "could not write a backup; nothing was changed" >&2; exit 3; }',
    '[ -s "$SP_B" ] || { rm -f "$SP_B"; echo "the backup is empty; nothing was changed" >&2; exit 3; }',
    // `|| echo 0` would be a bug here, and it is worth naming because it is
    // the obvious way to write it: `grep -c` PRINTS its count and then exits 1
    // when the count is zero, so `$(grep -c . f || echo 0)` yields the two-line
    // string "0\n0" on an empty file. The comparison below then fails against a
    // count that was right, and the most final revocation there is — taking the
    // last key off an account — reports that the file came out the wrong size.
    'SP_BEFORE=$(grep -c . "$SP_F" 2>/dev/null || true)',
    "case \"$SP_BEFORE\" in ''|*[!0-9]*) SP_BEFORE=0 ;; esac",
    o.expect,
    `${o.produce} || { rm -f "$SP_T" "$SP_B"; echo "the new file could not be built; nothing was changed" >&2; exit 3; }`,
    'SP_AFTER=$(grep -c . "$SP_T" 2>/dev/null || true)',
    "case \"$SP_AFTER\" in ''|*[!0-9]*) SP_AFTER=0 ;; esac",
    // The count check, before the replacement rather than after it. A file that
    // came out the wrong size never becomes the live file at all.
    // The backup goes with it. A backup left behind by a change that did not
    // happen would refuse every future change on this host under the
    // one-at-a-time rule above, for ever.
    '[ "$SP_AFTER" = "$SP_WANT" ] || { rm -f "$SP_T" "$SP_B"; echo "the new file has $SP_AFTER lines and $SP_WANT were expected; nothing was changed" >&2; exit 4; }',
    'chmod 600 "$SP_T" 2>/dev/null || true',

    // ---- RULE 2: arm the host's own rollback, and PROVE it armed ----------
    //
    // Armed BEFORE the replacement, so that if the mv succeeds and this session
    // dies in the same instant the watchdog is already running. That ordering
    // was always right. What was missing is that NOTHING CHECKED. The launch
    // was a bare line in a `\n`-joined script with no `set -e` and no `&&`, so
    // its failure was discarded and the mv ran anyway: the key went, the
    // STAGED line promised a rollback that did not exist, and
    // `describeAccessOutcome` later told the operator their previous file was
    // back.
    //
    // AND THE REALISTIC TRIGGER IS NOT A MISSING `nohup`. It is systemd-logind
    // with `KillUserProcesses=yes` — the upstream default, shipped by RHEL 8/9,
    // CentOS Stream and Fedora — which SIGKILLs the whole user slice when the
    // exec channel closes. `nohup` sets SIGHUP to ignore in one process and
    // does nothing whatsoever about that. On those hosts the dead-man's switch
    // died with the session EVERY TIME.
    //
    // So three things, in order:
    //
    //  1. CHOOSE A LAUNCHER THAT CAN ACTUALLY SURVIVE, preferring the one that
    //     survives the case above. `systemd-run --user --scope` puts the
    //     watchdog in a transient scope of its own, OUTSIDE the logind session
    //     scope that KillUserProcesses kills — which `setsid` does not do, for
    //     all that it is the stronger POSIX answer: a new session escapes the
    //     terminal, not the cgroup. `nohup` is last and weakest. The choice is
    //     probed on the host rather than assumed, and `systemd-run` is probed
    //     by RUNNING it, because it is present and non-functional on any host
    //     whose session has no user bus.
    //
    //     `disown` is not among them for the reason the detached job engine
    //     dropped it: it is a bashism, and this command has to run under the
    //     `/bin/sh` that is actually there.
    //
    //  2. REFUSE IF THERE IS NONE. A host that cannot leave a process running
    //     after the session ends is a host this must not write to at all — the
    //     rollback is not a nicety on top of the change, it is the reason the
    //     change is allowed to be attempted.
    //
    //  3. PROVE IT ARMED. The watchdog's FIRST action is to create its arming
    //     sentinel, so the sentinel existing means a process is running that
    //     holds the backup path and the deadline. Polled for a few seconds, and
    //     the mv is gated on it. A watchdog that was launched into a slice
    //     about to be killed does not get that far, and nothing is replaced.
    `SP_ARM="$SP_F.shellpilot-${o.token}.armed"`,
    'rm -f "$SP_M" "$SP_ARM"',
    'SP_L=',
    // `--quiet` so the scope name does not land in the job output; `--collect`
    // so a scope whose process died is not left behind as a failed unit.
    'if command -v systemd-run >/dev/null 2>&1 && systemd-run --user --scope --quiet --collect true >/dev/null 2>&1; then SP_L="systemd-run --user --scope --quiet --collect"; elif command -v setsid >/dev/null 2>&1; then SP_L=setsid; elif command -v nohup >/dev/null 2>&1; then SP_L=nohup; fi',
    '[ -n "$SP_L" ] || { rm -f "$SP_T" "$SP_B"; echo "this host has no way to leave a process running after the session ends, so the rollback could not be armed and nothing was changed" >&2; exit 5; }',
    // Unquoted on purpose: `$SP_L` is one of three literals this file wrote,
    // and the systemd one is four words.
    `$SP_L sh -c ': > "$3"; sleep ${wait}; [ -f "$0" ] || cp -p "$1" "$2"; rm -f "$0" "$1" "$3"' "$SP_M" "$SP_B" "$SP_F" "$SP_ARM" </dev/null >/dev/null 2>&1 &`,
    'SP_WPID=$!',
    // A fractional sleep is not POSIX and a host without one must not spend
    // thirty seconds here, so the tick is probed and the try count follows it.
    // Either way this waits about three seconds and no longer.
    'if sleep 0.1 2>/dev/null; then SP_TICK=0.1; SP_TRIES=30; else SP_TICK=1; SP_TRIES=3; fi',
    'SP_N=0',
    'while [ ! -f "$SP_ARM" ] && [ "$SP_N" -lt "$SP_TRIES" ]; do sleep "$SP_TICK"; SP_N=$((SP_N+1)); done',
    // `kill` is best effort: with `nohup` and `setsid` the recorded pid IS the
    // watchdog, and with a systemd scope it is the launcher and the scope may
    // outlive it. Either way the file was never replaced, so the worst a
    // survivor can do at its deadline is copy the backup over an identical
    // file and tidy up after itself.
    '[ -f "$SP_ARM" ] || { kill "$SP_WPID" 2>/dev/null; rm -f "$SP_T" "$SP_B" "$SP_ARM"; echo "the rollback did not start on this host, so nothing was changed" >&2; exit 5; }',

    'mv "$SP_T" "$SP_F" || { echo "the file could not be replaced" >&2; exit 3; }',
    // Said out loud, in the job output, so the operator reading the pane knows
    // the change is NOT permanent, knows how long they have, and knows how
    // strong the thing holding the deadline is. A `nohup` watchdog and a
    // systemd scope are not the same promise and are not reported as one.
    `echo "STAGED: $SP_F changed from $SP_BEFORE to $SP_AFTER lines. The previous file is at $SP_B and will be put back automatically in ${wait}s unless a new session confirms this change. The rollback is running under $SP_L."`
  ].join('\n')
}

/**
 * The one thing that may reach a command in these two builders.
 *
 * A token is `String(req.now)` today and it is still validated, because the
 * value is interpolated into a shell command that runs against an
 * `authorized_keys` file, and "the only caller passes digits" is a property of
 * this week's callers rather than of this function. Letters are allowed so a
 * test can name a change `t3`.
 */
const TOKEN_RE = /^[A-Za-z0-9]{1,32}$/

/**
 * Ask the host whether the staged change is still waiting on a confirmation.
 *
 * RUN ONLY OVER A SESSION THAT AUTHENTICATED AFTER THE WRITE. That is not
 * advice to the reader of this function — the connection is what is being
 * tested. There is nothing in the OUTPUT of this command that proves who ran
 * it; the proof is that sshd let a new connection in at all, holding the key
 * material as it now stands on the host. Running this over the pooled
 * connection that wrote the file would produce the same `VERIFIED:` line and
 * mean nothing whatsoever.
 *
 * What the command itself adds is the other half: that this session landed on
 * the host and the account the change was staged on, rather than on some other
 * machine that happens to accept the same key. The backup named with this
 * change's own token exists on exactly one host, in exactly one home directory.
 */
export const ACCESS_VERIFIED_PREFIX = 'VERIFIED: '

export function accessVerifyCommand(token: string): string {
  if (!TOKEN_RE.test(token)) throw new Error('refusing to build a verification for an unvalidated token')
  return [
    'LC_ALL=C',
    'export LC_ALL',
    'SP_F="$HOME/.ssh/authorized_keys"',
    `SP_B="$SP_F.shellpilot-${token}.bak"`,
    // The backup is the staged change's own footprint, and it is named with
    // this change's token — so finding it is finding THIS change, on THIS
    // host, in THIS account's home directory. A session that landed somewhere
    // else fails here rather than confirming a change it never saw.
    '[ -f "$SP_B" ] || { echo "no staged change with this token is waiting here" >&2; exit 3; }',
    // And the file the change produced has to be readable by the account that
    // just logged in. A key change that leaves sshd's own file unreadable is
    // the shape of the lockout this whole protocol exists to survive.
    '[ -r "$SP_F" ] || { echo "the changed authorized_keys cannot be read back" >&2; exit 3; }',
    `echo "${ACCESS_VERIFIED_PREFIX}${token}"`
  ].join('\n')
}

/**
 * Make a staged change permanent.
 *
 * It must only ever be run over a connection that authenticated AFTER the
 * staged write. Run over the session that made the change it proves nothing at
 * all, and rule 2 becomes a comment.
 *
 * ONE CALLER, and the refusal at the top of this section is now a rule about
 * WHERE rather than about WHETHER: src/main/services/access.ts issues this, and
 * only after `judgeAccessVerification` has been satisfied by an independent
 * session. tests/accessWrite.test.ts enforces both — that no other file in
 * `src/` mentions it, and that the caller cannot reach a pooled connection.
 */
export const ACCESS_COMMITTED_PREFIX = 'COMMITTED: '

export function accessDisarmCommand(path: string, token: string): string {
  if (!TOKEN_RE.test(token)) throw new Error('refusing to build a confirmation for an unvalidated token')
  const marker = accessCommitMarker(token)
  return [
    'LC_ALL=C',
    'export LC_ALL',
    `SP_M="$HOME/.ssh/${marker}"`,
    // Creating the marker is the whole commit. The watchdog is already asleep
    // holding the backup path; it wakes, sees the marker, and leaves the new
    // file alone.
    ': > "$SP_M" || { echo "could not confirm the change" >&2; exit 3; }',
    `echo "${ACCESS_COMMITTED_PREFIX}${path}"`
  ].join('\n')
}

// ---------------------------------------------------------------------------
// The confirmation — roadmap item 23, stage 3
// ---------------------------------------------------------------------------
//
// The write half staged a change and armed the host's own watchdog, and then
// stopped, because the only honest thing to do next needed something that did
// not exist: a session that authenticated AFTER the write. It exists now
// (`sshOpenFresh` in src/main/services/ssh.ts), and this is the rule it feeds.
//
// The rule lives HERE, apart from the transport, on purpose. A transport that
// decided whether it was independent enough would be marking its own homework;
// what it can honestly report is what it observed — when its handshake
// completed, and what the pool was holding at the time — and what to make of
// that is a policy question with a test.
//
// THREE OUTCOMES, AND THEY ARE NOT TWO. The temptation is to collapse the last
// two into "failed", and it would be wrong in the direction that matters:
//
//   committed                    — a second session got in, the watchdog was
//                                  called off, the new file is the file.
//   reverted-verification-failed — a second session could NOT get in. The host
//                                  put the old file back. This is the change
//                                  being rejected, and the operator has learned
//                                  something real about that host.
//   reverted-unconfirmed         — nobody ever told the host either way, so it
//                                  did what it promised. ShellPilot was closed,
//                                  or the network went, or the confirmation
//                                  itself could not be written. NOTHING IS
//                                  WRONG WITH THE CHANGE. Reporting this as a
//                                  failure would teach an operator to distrust
//                                  the one mechanism that protects them, and
//                                  the correct response is to stage it again
//                                  rather than to go looking for a fault.

export type AccessCommitOutcome =
  | 'committed'
  | 'reverted-verification-failed'
  | 'reverted-unconfirmed'

/** What an independent session reported about ITSELF. Facts, not a verdict. */
export interface AccessSessionEvidence {
  /** Identity of the connection the check ran over. */
  connectionId: string
  /** Every pooled connection that existed while it was opened. */
  pooledConnectionIds: string[]
  /** When this connection's authentication handshake completed. */
  authenticatedAt: number
}

/** What the verification command came back with. */
export interface AccessVerifyResult {
  ok: boolean
  code: number | null
  stdout: string
  stderr: string
  error?: string
}

export interface AccessCommitEvidence {
  /** Null when no independent session could be opened at all. */
  session: AccessSessionEvidence | null
  /** Why there is no session, when there is none. */
  openError?: string
  /** Null when the check never ran, because there was nothing to run it over. */
  verify: AccessVerifyResult | null
}

export interface AccessVerdict {
  /**
   * Whether the disarm may be issued.
   *
   * `outcome` is what the outcome WILL BE if it lands — a disarm that fails to
   * reach the host leaves the change unconfirmed, and the caller downgrades.
   */
  commit: boolean
  outcome: AccessCommitOutcome
  /** Why, in a sentence that can be shown to a person. Empty when committed. */
  reason: string
}

/**
 * Decide whether a staged change may be made permanent.
 *
 * Every branch that is not a commit is a REVERT, and none of them needs an
 * action: the host is already holding a watchdog that will put the old file
 * back. So there is no rollback path here, no cleanup, and no failure this can
 * itself cause — doing nothing is the safe operation, which is the property
 * that made the dead-man's switch the right shape in the first place.
 */
export function judgeAccessVerification(o: {
  token: string
  /** When the staged write finished on the host. */
  stagedAt: number
  rollbackSeconds: number
  now: number
  evidence: AccessCommitEvidence
}): AccessVerdict {
  const deadline = o.stagedAt + o.rollbackSeconds * 1000

  // FIRST, because it makes every other check moot. Past the deadline the host
  // has already restored itself and removed the marker's reason to exist;
  // writing one now would be a confirmation of nothing, and reporting
  // `committed` off the back of it would be a lie told to the one person who
  // needs to know the change did not stick.
  if (o.now >= deadline) {
    return {
      commit: false,
      outcome: 'reverted-unconfirmed',
      reason: `the ${o.rollbackSeconds}-second window closed before this could be confirmed, so the host has already put the previous file back.`
    }
  }

  if (o.evidence.session === null) {
    return {
      commit: false,
      outcome: 'reverted-verification-failed',
      // Deliberately not diagnosed further. A refused key and an unreachable
      // host look the same from here, and both mean the same thing about what
      // may be done next: nothing.
      reason: `a second, independent session could not be opened after the change (${o.evidence.openError ?? 'no reason given'}). A rejected key and an unreachable host are indistinguishable from here, and both mean the change must not be made permanent.`
    }
  }

  // The check that gives rule 2 its content. A session that authenticated
  // BEFORE the file was replaced has proved nothing about the file that is
  // there now — which is exactly what a "verify" step sharing the job's pooled
  // transport would have been.
  if (o.evidence.session.authenticatedAt <= o.stagedAt) {
    return {
      commit: false,
      outcome: 'reverted-verification-failed',
      reason: `the session that ran the check authenticated before the change was written, so it says nothing about the file that is on the host now.`
    }
  }

  // And the same rule from the other side. `sshOpenFresh` cannot produce this,
  // because an unpooled connection is never entered into the pool — which is
  // why this is worth checking: it fires when something has quietly started
  // confirming changes over the connection that made them.
  if (o.evidence.session.pooledConnectionIds.includes(o.evidence.session.connectionId)) {
    return {
      commit: false,
      outcome: 'reverted-verification-failed',
      reason: `the check ran over a pooled connection — the same already-authenticated transport that wrote the file — so it proves only that the writer can still write.`
    }
  }

  const v = o.evidence.verify
  if (!v || !v.ok || v.code !== 0) {
    const said = (v?.stderr ?? '').trim().split('\n')[0].slice(0, 160)
    return {
      commit: false,
      outcome: 'reverted-verification-failed',
      reason: said
        ? `the new session reached the host and the check failed there: ${said}`
        : `the new session reached the host and the check did not complete (${v?.error ?? `exit ${String(v?.code)}`}).`
    }
  }
  if (!v.stdout.includes(`${ACCESS_VERIFIED_PREFIX}${o.token}`)) {
    return {
      commit: false,
      outcome: 'reverted-verification-failed',
      reason: `the new session did not find this change staged where it landed, so it is not the host and account the change was made on.`
    }
  }

  return { commit: true, outcome: 'committed', reason: '' }
}

/**
 * One sentence per outcome, written once so main and the renderer cannot say
 * different things about the same event.
 *
 * The three read differently on purpose. An operator scanning a list has to be
 * able to tell "this host rejected the change" from "nobody confirmed it in
 * time" without opening anything, because the second is not a fault and the
 * first is.
 */
export function describeAccessOutcome(o: {
  outcome: AccessCommitOutcome
  serverName: string
  user: string
  backupPath: string
  rollbackSeconds: number
  reason: string
}): string {
  switch (o.outcome) {
    case 'committed':
      // The window, not "still on the host", because the watchdog removes the
      // backup when it wakes and finds itself called off — which it has to, or
      // the next change on this host would be refused for ever by the
      // one-staged-change-at-a-time rule. An operator who wants that file wants
      // it now, and telling them it will be there indefinitely is how they find
      // out otherwise at the worst moment.
      return `Committed on ${o.serverName}. A second session authenticated after the change and called off the host's rollback, so ${o.user}'s authorized_keys is now permanent. The previous file is at ${o.backupPath} until the ${o.rollbackSeconds}-second window closes, after which the host removes it.`
    case 'reverted-verification-failed':
      // NOT "the previous file is back", which is a claim about something this
      // process cannot see. The staged write proves the watchdog armed before
      // it replaces anything, so what can honestly be said is that it was
      // running and holding the deadline — and then where to look, because the
      // operator reading this may be the one who has just been locked out.
      return `Reverted on ${o.serverName}: the check failed. ${o.reason} The host's rollback was armed and confirmed running before anything was replaced, and was left armed, so ${o.user}'s previous authorized_keys should be back within ${o.rollbackSeconds}s of the change. It is restored from ${o.backupPath}; if you can still reach the host, that is where to look.`
    case 'reverted-unconfirmed':
      return `Reverted on ${o.serverName}: nothing confirmed it in time. ${o.reason} That is the dead-man's switch doing its job rather than the change failing — ${o.user}'s previous authorized_keys is back, the host is exactly as it was, and it can be staged again.`
  }
}

/** Where the previous file is left, for the sentence above and for a person in
 *  a shell who needs it when this app is the thing that is locked out. */
export function accessBackupPath(keyPath: string, token: string): string {
  return `${keyPath}.shellpilot-${token}.bak`
}

/**
 * What one host's key change came to, ready to be shown to a person.
 *
 * Here rather than beside the thing that produces it, because the renderer has
 * to render it and the renderer cannot import from `main/`.
 */
export interface AccessCommitReport {
  serverId: string
  serverName: string
  user: string
  token: string
  outcome: AccessCommitOutcome
  /** One sentence, already written. See describeAccessOutcome. */
  detail: string
  /** Where the previous file is, whichever way this went. */
  backupPath: string
  at: number
}

/** A target this run would not touch, and why. Distinct from an AccessBlock:
 *  a block is the planner refusing, this is the caller refusing before the
 *  planner is asked. */
export interface AccessRefusal {
  serverId: string
  serverName: string
  user: string
  reason: string
}

/** A host where the staged write itself did not land. Nothing was changed
 *  there and there is nothing to confirm, which is a fourth thing and not one
 *  of the three outcomes. */
export interface AccessStagingFailure {
  serverId: string
  serverName: string
  /** What the host said, first line, as it said it. */
  detail: string
}

export interface AccessChangePreview {
  /** The token this plan is named by. Passed back with the run so main derives
   *  the same command the operator agreed to. */
  token: string
  /** Exactly what will run on every host. Empty when nothing will. */
  command: string
  hosts: { serverId: string; serverName: string; user: string }[]
  blocks: AccessBlock[]
  refusals: AccessRefusal[]
  rollbackSeconds: number
}

export interface AccessRunRequest {
  kind: AccessChangeKind
  /** For a revoke. */
  fingerprint?: string
  /** The token from the preview the operator was shown. */
  token: string
  /** The command text they were shown, checked in main against a freshly
   *  derived one before a single host is touched — the shape `broadcast:run`
   *  uses, for the same reason: a plan computed in the renderer and thrown
   *  away is not a record of anybody agreeing to anything. */
  confirmedCommand: string
  targets: { serverId: string; serverName: string; user: string; cfg: unknown }[]
}

export interface AccessRunResult {
  blocks: AccessBlock[]
  refusals: AccessRefusal[]
  notStaged: AccessStagingFailure[]
  reports: AccessCommitReport[]
}
