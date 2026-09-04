// Security posture — roadmap item 24. READING STATE, NOT SCANNING.
//
// Which firewall is active and what shape its rules are, whether SELinux or
// AppArmor is enforcing, how sshd is configured against a hardening baseline,
// and how many logins have failed. Slow cadence, like item C's facts: none of
// these change between two-minute metrics sweeps, and all of them change when a
// person edits a file.
//
// ---------------------------------------------------------------------------
// The scope discipline IS the item
// ---------------------------------------------------------------------------
//
// This is NOT a vulnerability scanner and must not become one. The distribution
// already knows which of its packages carry security fixes; `apt-check`,
// `dnf --security check-update` and `zypper list-patches --category security`
// are better answers than anything a desktop app computes from a CVE feed, and
// item C already collects all three. This file CONSUMES that count — see
// `securityUpdateReading` at the bottom — and never recomputes it. There is no
// CVE list here, no package-version comparison, and no severity scoring, and
// adding one would mean shipping a feed, keeping it fresh, and being wrong
// about backported fixes on every enterprise distribution simultaneously.
//
// Everything read here is state that already exists on the host and that a
// person could read by hand in one command.
//
// ---------------------------------------------------------------------------
// The honesty rule, which bites harder here than anywhere else
// ---------------------------------------------------------------------------
//
// A CHECK THAT COULD NOT RUN IS NOT A CHECK THAT PASSED. Everywhere else in
// this codebase that sentence protects a count; here it protects a security
// conclusion, which is worse to get wrong:
//
//  1. A host whose firewall could not be read must NEVER render as "no
//     firewall rules". `denied` and `0 rules` are different answers with
//     different fixes, and only one of them is an all-clear.
//
//  2. A host whose sshd config could not be read must NEVER render as
//     "hardened". `judgeSshd` refuses to return a `hardened` verdict for any
//     directive whose value is null, whatever the reason the value is null —
//     see the assertion in its body.
//
//  3. No firewall tool AT ALL is `unsupported`, not "no rules". The kernel can
//     filter perfectly well with no userspace tool installed: nftables rules
//     loaded from a file at boot, a cloud security group in front of the NIC,
//     or a ruleset put there by something that then removed itself. "There is
//     nothing here to ask" is the true statement; "there is no firewall" is
//     not, and this build cannot tell them apart.
//
// The vocabulary is item C's and item 23's, deliberately reused rather than
// re-invented: `ok`, `partial`, `absent`, `denied`, `no-tool`, `unsupported`,
// `unknown`. A parallel set of words for the same seven ideas would mean the
// renderer had two vocabularies to explain and the store two spellings to keep.
//
// ---------------------------------------------------------------------------
// Traversal before existence
// ---------------------------------------------------------------------------
//
// `[ -e /etc/ssh/sshd_config ]` returns FALSE on a host with `chmod 700
// /etc/ssh`, which is on plenty of hardened images. That is "cannot see", not
// "absent" — and `absent` for sshd_config would mean "the compiled-in defaults
// apply", which is a confident statement about a configuration nobody read.
// src/shared/access.ts gets this right for home directories and for /etc/ssh;
// the same test is applied here to /etc/ssh, /etc/ufw, /etc/firewalld and
// /sys/kernel/security before anything inside them is believed absent.
//
// ---------------------------------------------------------------------------
// Why the output format is hostFacts.ts's and not metrics.ts's
// ---------------------------------------------------------------------------
//
// Every value here is read out of a file or printed by a tool the host
// controls, and on a compromised host a `PermitRootLogin` value is attacker-
// controlled text. metrics.ts fences sections with markers and cuts at the next
// one, so a value containing a marker would truncate its own section and shift
// every later value — a host could move its own firewall status by naming an
// ssh user carefully.
//
// So: status accumulates in a shell variable and is printed ONCE at the end,
// where nothing read out of a file has touched it; every value is a single
// tagged line (`V` for a scalar, `D` for one sshd directive) whose payload has
// had tabs folded to spaces and control characters DELETED ON THE HOST and is
// length-capped there. A value cannot become a second line, cannot forge a
// record tag, and cannot forge the status marker — which stays the only
// structural token and is matched by whole-line equality.
//
// Same rules as cron.ts, hostFacts.ts and access.ts otherwise: no `set -e`,
// every read conditional or `|| true`, and sudo omitted at BUILD time rather
// than guarded at runtime, so "this command contains no sudo" is a property
// somebody can check by reading it. tests/posture.test.ts asserts exactly that.
//
// ---------------------------------------------------------------------------
// What is deliberately NOT here, and will not be added casually
// ---------------------------------------------------------------------------
//
// Stated in the shape src/shared/docker.ts states its refusal to ship
// `docker system prune`, because the reasoning is the same kind:
//
//  * `ufw enable` / `ufw disable`, `firewall-cmd --add-*`, `nft add rule`,
//    `iptables -A`. Every one of them can lock the operator out of the host
//    they would use to undo it — the same blast radius as the authorized_keys
//    write in item 23, with none of that write's dead-man's switch. A firewall
//    change needs a staged write, an independent re-authentication and an
//    automatic revert, and until something is built that has all three, the
//    honest button is no button.
//
//  * `setenforce 1`. It is one word, it is instantly reversible, and it is
//    still refused: switching SELinux from permissive to enforcing on a host
//    whose policy was never written for it takes services down immediately and
//    in a way that reads as an unrelated outage. The panel says the mode; a
//    person decides.
//
//  * Any write to sshd_config, and any `systemctl restart sshd`. Restarting
//    sshd from a tool whose only channel to the host is sshd is the definition
//    of sawing the branch off.
//
//  * `fail2ban-client` anything. Reading its state would be in scope; banning
//    and unbanning is a control plane, not a posture read.
//
// This module issues exactly five kinds of command — `status`/`list`/`--state`
// reads, file reads, `sshd -T`, `lastb`/`journalctl`, and `command -v`. Nothing
// in it takes an argument that changes the host.

// `resolveBinary` and `SUDO_PROBE` are the Docker module's, for the reason
// cron.ts, hostFacts.ts and access.ts all borrow them: both encode a fact about
// the environment rather than anything about Docker — that `ssh host cmd` gets
// a non-login PATH of roughly /usr/bin:/bin, so /usr/local/bin and /usr/sbin
// are not on it, and that `sudo -n` is the only escalation that cannot prompt.
// The strict base64 decoder src/shared/access.ts already owns. Reused rather
// than written twice: it refuses anything outside the alphabet instead of
// guessing, which is exactly what a certificate body coming off a host needs,
// and it is in a shared file with no `node:` imports so the renderer can bundle
// it. See the note there on why this codebase decodes rather than shelling out.
import { decodeBase64 } from './access'
import { SUDO_PROBE, resolveBinary } from './docker'
import type { FactStatus, HostFacts } from './hostFacts'
import { factSource } from './hostFacts'

// ---- Statuses -------------------------------------------------------------

/**
 * Why something here is missing, or present but qualified.
 *
 * The same seven words as `AccessStatus` in access.ts, which are `FactStatus`
 * minus `stale-metadata` plus `partial`. Reused rather than re-declared as a
 * new union with the same members, so a renderer that already knows how to say
 * "denied" does not need a second table of sentences.
 */
export type PostureStatus =
  /** Read it. A zero here really is a zero — the probe looked and found none. */
  | 'ok'
  /** Read some of it. One source answered and another was refused. */
  | 'partial'
  /** The thing genuinely is not on this host, and that was CHECKED — not
   *  inferred from a stat this account was not allowed to perform. */
  | 'absent'
  /** It exists and this account may not read it. A different account, or
   *  passwordless sudo, would see more. NOT the same as there being nothing. */
  | 'denied'
  /** The program that answers this is not installed. */
  | 'no-tool'
  /** This host cannot answer this question at all, and no privilege changes
   *  that. Used for a host with no firewall tooling of any kind: the kernel may
   *  still be filtering and there is nothing installed to ask. */
  | 'unsupported'
  /** The probe ran and its answer could not be read, or the collector never
   *  reported on it. Never treat as "nothing there". */
  | 'unknown'

export const POSTURE_STATUSES: PostureStatus[] = [
  'ok',
  'partial',
  'absent',
  'denied',
  'no-tool',
  'unsupported',
  'unknown'
]

/**
 * One sentence per status, for the person deciding whether to act on what is
 * next to it. `unsupported` and `denied` get the long ones: they are the two
 * that a reader is most likely to skim as "fine".
 */
export const POSTURE_STATUS_HELP: Record<PostureStatus, string> = {
  ok: 'Read successfully. A zero here means the probe looked and found none, not "we could not look".',
  partial:
    'Some of it was read and some was not. What is shown is real; it is not the whole picture, and the part that was refused is named rather than left out.',
  absent: 'This host does not have the thing that answers this, and that was checked rather than assumed.',
  denied:
    'It exists and this account was not allowed to read it. A different account, or passwordless sudo, would see more. This is NOT the same as there being no rules, no policy or no failures.',
  'no-tool': 'The program that answers this is not installed on this host.',
  unsupported:
    'This host cannot answer this question at all. For the firewall that means no firewall tooling is installed — which is not the same as no filtering: the kernel can enforce a ruleset loaded at boot with nothing left on disk to ask. Treat it as UNKNOWN, never as "open".',
  unknown: 'The probe ran and its answer could not be read, or the collector never reported on it.'
}

/** The six things the collector reports on, each read independently. */
export type PostureSourceId =
  | 'firewall'
  | 'mandatory-access'
  | 'sshd-hardening'
  | 'failed-logins'
  | 'oom-kills'
  | 'certificates'

export const POSTURE_SOURCE_IDS: PostureSourceId[] = [
  'firewall',
  'mandatory-access',
  'sshd-hardening',
  'failed-logins',
  'oom-kills',
  'certificates'
]

export const POSTURE_SOURCE_LABEL: Record<PostureSourceId, string> = {
  firewall: 'Firewall',
  'mandatory-access': 'SELinux / AppArmor',
  'sshd-hardening': 'sshd configuration',
  'failed-logins': 'Failed logins',
  'oom-kills': 'OOM kills',
  certificates: 'Certificate expiry'
}

export interface PostureSourceReport {
  id: PostureSourceId
  label: string
  status: PostureStatus
  /** Read as root after the unprivileged attempt was refused. Never silent. */
  usedSudo?: boolean
  /** The collector's own words, when it had any. Always sanitised. */
  detail?: string
}

/** Look one source up without a find() at every call site. */
export function postureSource(posture: HostPosture, id: PostureSourceId): PostureSourceReport {
  return (
    posture.sources.find((s) => s.id === id) ?? {
      id,
      label: POSTURE_SOURCE_LABEL[id],
      status: 'unknown',
      detail: 'the collector did not report on this source'
    }
  )
}

// ---- Firewall -------------------------------------------------------------

/**
 * The tools that can answer "what is filtering here".
 *
 * ufw and firewalld are FRONT ENDS; nftables and iptables are the kernel-level
 * view underneath them. Both halves are reported, and that is the point rather
 * than thoroughness: "ufw is inactive" on its own reads as "nothing is
 * filtering", and on a host where a cloud-init nftables ruleset is doing the
 * work that is exactly wrong. See `FirewallState.backend`.
 */
export const FIREWALL_TOOLS = ['ufw', 'firewalld', 'nftables', 'iptables'] as const
export type FirewallTool = (typeof FIREWALL_TOOLS)[number]

/** The kernel-level tools, which are also the backend values. */
export const FIREWALL_BACKENDS = ['nftables', 'iptables'] as const
export type FirewallBackend = (typeof FIREWALL_BACKENDS)[number]

/**
 * What the collector could see of the packet filter.
 *
 * Every field is `T | null` and every null is explained by the `firewall`
 * source report. There is no field here whose zero means "we did not look".
 */
export interface FirewallState {
  /** The front end that owns the rules, or the backend tool when no front end
   *  is installed. Null when nothing could be identified. */
  tool: FirewallTool | null
  /** Whether the front end says it is switched on. Null is NOT false. */
  active: boolean | null
  /** ufw's default policies. Free-form words from the host, allow-listed. */
  policyIn: string | null
  policyOut: string | null
  /** How many rules the front end lists. Null when the list was refused —
   *  which is the case this whole file exists to keep distinct from `0`. */
  rules: number | null
  /** Of those, how many deny or reject. */
  denyRules: number | null
  /** firewalld's default zone and its active zones. */
  zone: string | null
  zones: string[]
  /**
   * The kernel-level reading, taken INDEPENDENTLY of the front end.
   *
   * Present whenever nft or iptables could be run at all. `rules: 0` here with
   * a status of `ok` is a real finding — the kernel filter table is empty. The
   * same 0 with a status of `denied` is not a finding at all.
   */
  backend: {
    tool: FirewallBackend | null
    rules: number | null
    /** The INPUT chain's policy: `accept`, `drop`, `reject`. */
    policyIn: string | null
    status: PostureStatus
  }
  /**
   * Whether the RULE LINES were asked for on this host at all — roadmap item
   * 31, and the first thing a reader of this object has to know.
   *
   * False means nobody granted the capability, so `ruleLines` being empty says
   * nothing about the host. True with an empty `ruleLines` means the read that
   * would have produced them was refused. Those are opposite findings and a
   * single empty array cannot carry both, which is why this is not inferred
   * from the array's length.
   */
  rulesRequested: boolean
  /**
   * The rules themselves, as the host printed them, in at most two readings:
   * the front end's own listing and the kernel tables underneath.
   *
   * A reading is present ONLY when its source answered. There is no empty
   * listing standing in for a refusal — "this host lists no rules" and "this
   * host would not tell us its rules" are the two answers this whole file
   * exists to keep apart, and one of them is an all-clear.
   */
  ruleLines: FirewallRuleListing[]
}

// ---- The rules themselves — roadmap item 31 --------------------------------
//
// Item 24 reports SCALARS: a tool name, an on/off, a default policy, a count.
// Every one of them goes through the single-line unforgeable path, which is the
// strongest safety property this collector has. This is the one thing here that
// is neither a count nor a word from a fixed vocabulary: it is ADDRESSES AND
// PORTS, many lines of them, written by the host.
//
// So it is bounded three ways, all of them ON THE HOST:
//
//   * a cap on how many lines are emitted per reading, with the number that
//     MATCHED emitted beside them, so a truncation is a stated fact rather than
//     a shorter list that reads as a complete one;
//   * a cap on the length of each line;
//   * the same control-character deletion every other value gets, so a rule
//     cannot become two records, cannot forge a record tag and cannot forge the
//     status marker. The status block is still accumulated in a shell variable
//     and printed once at the end, where nothing read out of a file has
//     touched it.
//
// And it is COLLECTED ONLY WHERE SOMEBODY GRANTED IT — see
// PostureCollectOptions.firewallRules. The commands that list rules are not in
// the built script otherwise.
//
// What is deliberately NOT here: any judgement about whether a rule is a good
// one. "3306/tcp ALLOW IN Anywhere" is a fact an operator can act on. "This
// rule is insecure" is a claim this tool cannot support and would be wrong
// about the first time somebody has a reason — a database deliberately open to
// a peered network, a rule that a security group in front of the NIC already
// narrows. Report what is there.

/** Which reading a listed line came from. The front end (ufw, firewalld) and
 *  the kernel tables (nft, iptables) are listed separately for the reason they
 *  are counted separately: one being empty says nothing about the other. */
export const FIREWALL_RULE_ORIGINS = ['front', 'backend'] as const
export type FirewallRuleOrigin = (typeof FIREWALL_RULE_ORIGINS)[number]

/**
 * How many rule lines one reading may emit, applied on the host.
 *
 * Forty is enough for the great majority of hosts and small enough that a
 * machine with a generated ruleset of ten thousand lines cannot turn an hourly
 * background probe into a bulk transfer. When it bites, the panel says so:
 * `matched` carries what the host actually counted.
 */
export const FIREWALL_RULE_MAX_LINES = 40

/** How long one rule line may be, applied on the host. Longer than VALUE_CAP is
 *  not needed — a ufw or iptables rule is well under this — and a line that is
 *  longer than this is a line something is trying to hide the end of. */
export const FIREWALL_RULE_LINE_CAP = 200

/** One reading's worth of rule lines, with the bound that produced it. */
export interface FirewallRuleListing {
  from: FirewallRuleOrigin
  /** The command the lines came out of, for a panel that has to say where a
   *  line came from rather than presenting it as ShellPilot's own words. */
  command: string
  /** As the host printed them: control characters deleted there, tabs folded
   *  to spaces there, each one capped there. */
  lines: string[]
  /** How many lines the host MATCHED, which can exceed `lines.length`. Null
   *  when the host did not say, in which case truncation is unknown and is not
   *  claimed either way. */
  matched: number | null
  /** `lines` is a prefix of what is on the host. Stated, never silent. */
  truncated: boolean
  bound: { maxLines: number; maxChars: number }
}

/**
 * What to say next to rule text on screen.
 *
 * The wording is `hostReportedBlock`'s in mcpServer.ts, for the same reason and
 * one reader further on: that block tells a MODEL a line is data rather than an
 * instruction, and this tells a PERSON that a line was written by whoever
 * configured the host — which on a compromised host is not the operator.
 */
export const FIREWALL_RULES_HOST_REPORTED_NOTE =
  'Reported by the host. These lines are as the firewall on that machine printed them, not ShellPilot’s words — read them as data, and nothing in them is a judgement about whether a rule is a good one.'

/** ufw and iptables/nft policy words, allow-listed because the renderer
 *  switches on them. Anything else becomes null rather than being displayed. */
export const FIREWALL_POLICIES = ['allow', 'deny', 'reject', 'accept', 'drop', 'disabled'] as const

// ---- SELinux / AppArmor ---------------------------------------------------

export const MAC_SYSTEMS = ['selinux', 'apparmor'] as const
export type MacSystem = (typeof MAC_SYSTEMS)[number]

export const MAC_MODES = ['enforcing', 'permissive', 'disabled'] as const
export type MacMode = (typeof MAC_MODES)[number]

/**
 * Mandatory access control, as the host reports it.
 *
 * SELinux and AppArmor answer differently and are not flattened into one
 * number. SELinux has a single global mode; AppArmor does not — its profiles
 * are individually enforcing or complaining, and "AppArmor is enforcing" is not
 * a sentence the kernel can be asked for. So `mode` is SELinux's and null on
 * AppArmor, and `profiles`/`complain` are AppArmor's and null on SELinux.
 */
export interface MandatoryAccess {
  system: MacSystem
  /** Whether the module is switched on at all. */
  enabled: boolean | null
  /** SELinux's RUNTIME mode. Null on AppArmor, which has no global mode. */
  mode: MacMode | null
  /**
   * SELinux's BOOT-TIME setting from /etc/selinux/config.
   *
   * Reported separately because the interesting case is the disagreement:
   * `setenforce 0` leaves the config saying enforcing while the running kernel
   * is permissive, and the host reverts at the next reboot. One field could not
   * say that.
   */
  bootMode: MacMode | null
  /** AppArmor profiles loaded, and how many of them merely complain. Null on
   *  SELinux, and null on AppArmor when the profile list was refused. */
  profiles: number | null
  complain: number | null
}

// ---- sshd against a hardening baseline ------------------------------------

/**
 * The seven directives worth reading, in the order they are shown.
 *
 * Not a checklist somebody copied: each one changes who can get in, and each
 * one has a well-known bad value that ships as a distribution default
 * somewhere. Anything beyond these seven — ciphers, MACs, KEX algorithms — is a
 * cryptographic policy question whose right answer depends on what has to
 * connect, and a panel that flagged it would be wrong on every host with a
 * legacy appliance behind it.
 */
export const SSHD_DIRECTIVES = [
  'PermitRootLogin',
  'PasswordAuthentication',
  'PubkeyAuthentication',
  'X11Forwarding',
  'PermitEmptyPasswords',
  'MaxAuthTries',
  'AllowUsers',
  'AllowGroups'
] as const
export type SshdDirective = (typeof SSHD_DIRECTIVES)[number]

/** The lowercase spelling `sshd -T` uses, which is also how the collector tags
 *  each record. sshd_config itself is case-insensitive on directive names. */
export const SSHD_DIRECTIVE_KEY: Record<SshdDirective, string> = {
  PermitRootLogin: 'permitrootlogin',
  PasswordAuthentication: 'passwordauthentication',
  PubkeyAuthentication: 'pubkeyauthentication',
  X11Forwarding: 'x11forwarding',
  PermitEmptyPasswords: 'permitemptypasswords',
  MaxAuthTries: 'maxauthtries',
  AllowUsers: 'allowusers',
  AllowGroups: 'allowgroups'
}

const SSHD_KEY_TO_DIRECTIVE = new Map<string, SshdDirective>(
  SSHD_DIRECTIVES.map((d) => [SSHD_DIRECTIVE_KEY[d], d])
)

/**
 * What this build thinks of one directive's value.
 *
 * `unknown` is not a hedge, it is the answer for every directive whose value
 * could not be read — and it is what makes "this host could not be checked"
 * impossible to confuse with "this host is fine".
 */
export type SshdVerdict =
  /** The value meets the baseline. */
  | 'hardened'
  /** The value is one of the known-bad ones. */
  | 'weak'
  /** Read, valid, and neither clearly good nor clearly bad. */
  | 'neutral'
  /** Not read, not recognised, or read from a source that disagreed with
   *  itself. NEVER a pass. */
  | 'unknown'

export interface SshdReading {
  directive: SshdDirective
  /** The host's value, sanitised and allow-listed where the directive has a
   *  fixed vocabulary. Null when it was not read or was not recognised. */
  value: string | null
  verdict: SshdVerdict
  /** Why this verdict, in one sentence for the person reading the row. */
  detail: string
  /** Set when the collector saw the directive more than once with different
   *  values — two drop-ins disagreeing, or a value this build cannot resolve
   *  the precedence of. Reported rather than arbitrated. */
  ambiguous?: boolean
}

export interface SshdHardening {
  /**
   * TRUE when the reading came from `sshd -T`, which prints the EFFECTIVE
   * configuration with every Include resolved and every default filled in.
   *
   * FALSE when it came from reading files, and that difference is the whole
   * reason the flag exists: from files, a directive that is simply not written
   * down anywhere is UNKNOWN — sshd's compiled-in default applies and this
   * build cannot see which OpenSSH version is deciding it. Rendering such a
   * host as "PermitRootLogin: prohibit-password" would be inventing a value.
   */
  effective: boolean
  readings: SshdReading[]
  /**
   * How many `Match` blocks the configuration has.
   *
   * Directives inside one apply conditionally, so a global value read from
   * files is not the value that applies to every connection. Zero means the
   * global reading is the whole story; anything else means it is not, and the
   * panel says so. Null when the config was not read.
   */
  matchBlocks: number | null
}

/**
 * The baseline, as data rather than as a chain of ifs.
 *
 * `weak` values are the ones with a concrete consequence, not the ones a
 * benchmark disapproves of. `hardened` values are the ones that remove that
 * consequence. Everything else is `neutral` — deliberately, because a panel
 * that painted half a config amber would train people to ignore it.
 */
const SSHD_BASELINE: Record<
  SshdDirective,
  { values: readonly string[] | null; hardened: readonly string[]; weak: readonly string[]; why: string }
> = {
  PermitRootLogin: {
    values: ['yes', 'no', 'prohibit-password', 'without-password', 'forced-commands-only'],
    hardened: ['no'],
    weak: ['yes'],
    why: 'root may log in over ssh with a password, so every password-guessing attempt is aimed at an account that already has everything'
  },
  PasswordAuthentication: {
    values: ['yes', 'no'],
    hardened: ['no'],
    weak: ['yes'],
    why: 'passwords are accepted, so this host can be brute-forced from the internet'
  },
  PubkeyAuthentication: {
    values: ['yes', 'no'],
    hardened: ['yes'],
    weak: ['no'],
    why: 'public keys are refused, which leaves passwords or nothing'
  },
  X11Forwarding: {
    values: ['yes', 'no'],
    hardened: ['no'],
    weak: ['yes'],
    why: 'X11 forwarding is on, which gives a connecting client a path back into the session that opened it'
  },
  PermitEmptyPasswords: {
    values: ['yes', 'no'],
    hardened: ['no'],
    weak: ['yes'],
    why: 'an account with an empty password can log in without one'
  },
  // Numeric: judged by the parser rather than by membership. `values: null`
  // says so, and `judgeSshd` handles it.
  MaxAuthTries: {
    values: null,
    hardened: [],
    weak: [],
    why: 'how many authentication attempts one connection may make before it is dropped'
  },
  AllowUsers: {
    values: null,
    hardened: [],
    weak: [],
    why: 'when set, only these users may log in at all'
  },
  AllowGroups: {
    values: null,
    hardened: [],
    weak: [],
    why: 'when set, only members of these groups may log in at all'
  }
}

/** Above this, MaxAuthTries stops meaningfully limiting a guessing attempt.
 *  OpenSSH's own default is 6; distributions that harden set 3 or 4. */
export const MAX_AUTH_TRIES_WEAK = 6

// ---- Failed logins --------------------------------------------------------

export const FAILED_LOGIN_TOOLS = ['lastb', 'journal'] as const
export type FailedLoginTool = (typeof FAILED_LOGIN_TOOLS)[number]

/**
 * A COUNT, not a list.
 *
 * Deliberate, and not laziness: every field on a failed-login record is
 * attacker-chosen — the username, the source address as the host resolved it,
 * the terminal. Putting a list of them on screen means putting attacker text in
 * front of an operator and, through the MCP surface's own sanitiser, in front
 * of an agent. The counts answer the question an operator actually has ("is
 * something hammering this box, and is it spraying usernames or targeting
 * one"), and they cannot carry a payload.
 */
export interface FailedLoginSummary {
  tool: FailedLoginTool
  /** How many failed attempts the record covers. */
  count: number | null
  /** How many distinct usernames those attempts named. A spray and a targeted
   *  attempt produce very different numbers here for the same count. */
  users: number | null
  /**
   * What the count covers, as the host said it.
   *
   * `lastb` reads btmp, which is rotated — so the window is "since this btmp
   * was created", and the host's own `btmp begins <date>` line is carried
   * verbatim rather than being turned into a number this side cannot verify.
   * The journal path asks for a fixed window and says so.
   */
  window: string | null
}

/** The journal window the collector asks for. Named here so the parser, the
 *  renderer and the test all quote the same number. */
export const FAILED_LOGIN_WINDOW_HOURS = 24

// ---- OOM kills ------------------------------------------------------------
//
// THE SCOPE DECISION, stated here because the decision IS the work.
//
// 1. WHAT COUNTS AS ONE KILL. The kernel writes a dozen to several thousand
//    lines for a single OOM kill: an `invoked oom-killer` header, a call
//    trace, a Mem-Info block, and then one `[ pid ]` row for EVERY process on
//    the machine as it dumps the task list it chose from. Counting lines that
//    merely mention memory counts the task list, and a host with four hundred
//    processes reports one kill as four hundred. Counting `invoked oom-killer`
//    is closer and still wrong in both directions: one invocation can reap
//    more than one process, and an invocation that finds nothing killable
//    reaps none.
//
//    So ONE KILL IS ONE `Killed process <pid> (<comm>)` LINE. That line is
//    written once per process actually reaped, by the global path and by the
//    cgroup-v2 memcg path alike (`Memory cgroup out of memory: Killed
//    process ...`), on every kernel that has an OOM killer. It is also the one
//    line the task-list rows cannot imitate.
//
// 2. WHICH WINDOW. A fixed 24 hours, and the SAME 24 as the failed-login
//    probe next door, so the panel has one window to explain rather than two.
//
//    The alternatives were both rejected for reasons this codebase has already
//    paid for once. "Since boot" is what an unadorned `dmesg` gives, and a
//    host up for four hundred days would report a kill from last March as
//    news at every collection forever — which is precisely the chronic-alert
//    failure the durable half of store/alerts.ts was written to end. "Since
//    the last sample" needs state kept on the host between collections, and an
//    hourly probe that drifts, retries or is run twice by `Check now` would
//    double-count or skip.
//
//    A fixed window also makes the finding RESOLVABLE, which is what lets this
//    be a state kind at all: twenty-four hours after the last kill the count
//    returns to zero and the condition "this host has been killing processes
//    for memory today" becomes false by observation rather than by assumption.
//
// 3. WHAT A HALF-PROBE MAY CLAIM, which is the honesty requirement and the
//    reason this was deferred rather than shipped with the other ten kinds.
//    Only the journal can be ASKED for a window. `dmesg` reads a ring buffer,
//    which is not a period of time — it holds as much as it holds, and on a
//    chatty host that can be minutes. `/var/log/kern.log` is whatever logrotate
//    has not turned over yet. So the three sources do not produce the same
//    answer and are not interchangeable, and `oomWindowIsStated` is what every
//    consumer asks before it treats a zero as a finding. A zero from a ring
//    buffer is not "no OOM kills in the last day"; it is "nothing in whatever
//    the buffer still holds", and this build will not shorten that.
//
// And the sentence this whole section exists for: journald is frequently
// root-only, `dmesg` is refused outright wherever `kernel.dmesg_restrict` is
// set — which is most modern distributions — and a container typically has
// neither. Every one of those is `denied` or `no-tool`. NONE of them is
// `ok` with a count of zero.

export const OOM_SOURCES = ['journal', 'dmesg', 'kern-log'] as const
export type OomSource = (typeof OOM_SOURCES)[number]

/** The window the collector asks the journal for. Named here so the parser,
 *  the renderer and the test all quote the same number, exactly as
 *  FAILED_LOGIN_WINDOW_HOURS is. */
export const OOM_WINDOW_HOURS = 24

/**
 * Whether this source's answer covers a window somebody can name.
 *
 * TRUE ONLY FOR THE JOURNAL. The other two read a buffer and a file whose
 * extent nothing on this side can establish, so their zero is not a statement
 * about a period and must never be rendered or alerted as one. A count ABOVE
 * zero is trustworthy from all three — a `Killed process` line that was read
 * happened, whatever window it was read over.
 */
export function oomWindowIsStated(source: OomSource): boolean {
  return source === 'journal'
}

/**
 * COUNTS ONLY, for the reason FailedLoginSummary gives and one more.
 *
 * A victim's `comm` is a string the process chose for itself, so on a shared
 * host or in a container it is attacker-chosen text — the same argument that
 * keeps usernames off the failed-login record. What is carried instead is how
 * many DISTINCT names the kills named, which is the question an operator
 * actually has: eight kills of one process is a service in a restart loop
 * eating the box, and eight kills of eight processes is a box that ran out of
 * memory once and reaped whatever was nearest.
 */
export interface OomKillSummary {
  source: OomSource
  /** How many processes the kernel reaped. Null is NOT zero. */
  count: number | null
  /** How many distinct process names those kills named. */
  processes: number | null
  /** What the count covers, as the collector stated it. */
  window: string | null
}

// ---- Certificates on hosts we manage --------------------------------------
//
// NOT A DNS/TLS PRODUCT. There is no chain validation here, no OCSP, no
// hostname matching, no cipher opinion and nothing that opens a socket. The
// question is the one an operator actually loses sleep over: "is a certificate
// on one of MY boxes about to expire while the renewal that was supposed to
// handle it has quietly stopped running".
//
// ---------------------------------------------------------------------------
// THE SCOPE DECISION, which is the work
// ---------------------------------------------------------------------------
//
// WHICH PATHS. An unbounded walk of /etc on a production host is its own
// outage, so this borrows the whole discipline of `buildComposeSearchCommand`
// in src/shared/compose.ts: named roots, `-maxdepth`, `-xdev`, a result cap,
// and all four printed on screen rather than buried here.
//
//   /etc/letsencrypt/live   The renewal-managed set, and the highest-value
//                           one by a distance: a certbot timer that stopped
//                           firing is the single most common way a certificate
//                           on a managed host expires.
//   /etc/pki/tls/certs      RHEL's host certificates.
//   /etc/nginx              Where a hand-placed certificate sits, next to the
//   /etc/apache2            configuration that references it. Reading the
//   /etc/httpd              config to find `ssl_certificate` lines would find
//                           more, and would mean parsing two more
//                           configuration languages to do it; the directory is
//                           where they nearly always are.
//
// AND WHAT IS DELIBERATELY NOT A ROOT: /etc/ssl/certs. On Debian and Ubuntu
// that directory IS the distribution trust store — roughly 150 root CA
// certificates, symlinked by subject hash, owned by the `ca-certificates`
// package. Watching it would mean alerting an operator that a root CA they do
// not control and cannot renew expires in three weeks, roughly 150 times, and
// burying the one certificate that is theirs. The bundles that live in the
// other roots are excluded by name for the same reason — see CERT_SKIPPED.
//
// HOW MANY. CERT_SEARCH_MAX_FILES, and the cap is low on purpose: a host with
// more host certificates than this in these directories is unusual, and
// `truncated` says out loud that the list is a prefix rather than an
// inventory. A cap that was generous enough never to be hit would be a cap
// that let a pathological tree hold an SSH channel open.
//
// ---------------------------------------------------------------------------
// WHY THE CERTIFICATE IS PARSED HERE AND NOT BY openssl ON THE HOST
// ---------------------------------------------------------------------------
//
// `openssl x509 -enddate -noout` is the obvious command and it is refused, for
// exactly the reason src/shared/access.ts refuses `ssh-keygen -l` and computes
// its own fingerprints: the tool is not universally present. Alpine ships
// without the `openssl` binary unless somebody installs it, minimal and
// distroless container images ship without it, and a host that has certificates
// and no openssl would report NO CERTIFICATES — which is the half-probe this
// whole item was deferred rather than ship.
//
// A certificate's validity is four ASN.1 fields into the DER, and DER is a
// tag-length-value format a hundred lines of TypeScript can walk. This file
// already trusts that argument once: access.ts walks SSH key blobs by hand.
//
// The cost, stated: this side has to be strict, because a certificate is a file
// a host controls. `certificateNotAfter` returns a failure on ANY inconsistency
// — a length that runs past the end, a tag that is not the one the structure
// requires, a time that is not RFC 5280's UTC form — and never reads past the
// buffer. A certificate that could not be parsed is `unparseable`, which is a
// FINDING. It is never a certificate that is valid.
//
// ---------------------------------------------------------------------------
// THE HONESTY REQUIREMENT
// ---------------------------------------------------------------------------
//
//  * A directory that could not be entered is not a directory with no
//    certificates. `/etc/letsencrypt` is 0700 root on Debian, so this is the
//    COMMON case rather than an edge one: `unreadableRoots` counts them, the
//    source reads `partial` or `denied`, and nothing renders as "none found".
//  * A file that could not be read is `unreadable`, not absent.
//  * A certificate that could not be parsed is `unparseable`, not valid.
//  * A host where the search ran cleanly and found nothing has NO expiry
//    reading at all — `certificateDays` is null. "No certificates" is not
//    "infinitely far from expiry", and an alert path that treated it as a
//    number would report every host in the estate as healthy on this axis.

export const CERT_SEARCH_ROOTS = [
  '/etc/letsencrypt/live',
  '/etc/pki/tls/certs',
  '/etc/nginx',
  '/etc/apache2',
  '/etc/httpd'
] as const

/** Deep enough for `/etc/letsencrypt/live/<domain>/fullchain.pem` and for the
 *  `ssl/<site>/` layout people give nginx, and no deeper. */
export const CERT_SEARCH_MAX_DEPTH = 3

/** The cap on files read. `truncated` says when it was reached. */
export const CERT_SEARCH_MAX_FILES = 16

/** The most base64 transmitted per certificate. A leaf certificate is 1.1 to
 *  2.2 KB of base64, so this holds a whole normal one; a certificate longer
 *  than this arrives cut and is reported `truncated`, which is a gap and not a
 *  date. Sixteen of these is the worst case this probe can put on the wire. */
export const CERT_B64_CAP = 2048

export const CERT_NAMES = ['*.pem', '*.crt', '*.cer'] as const

/**
 * Names never read, and every one of them earns its place.
 *
 * The three `ca-*` bundles are the distribution trust store wherever it leaks
 * into a root that IS watched; `chain.pem` is the intermediate, whose expiry is
 * the CA's problem and not the operator's; `privkey.pem` is a PRIVATE KEY and
 * must never be opened at all. The key is belt to the braces of the collector's
 * own extractor, which can only ever transmit bytes lying between a BEGIN
 * CERTIFICATE and an END CERTIFICATE line — a key file yields nothing from it
 * even if a name slips through.
 */
export const CERT_SKIPPED = [
  'ca-bundle.crt',
  'ca-bundle.trust.crt',
  'ca-certificates.crt',
  'chain.pem',
  'privkey.pem',
  'dhparam.pem'
] as const

/** The bounds, as DATA, so the panel prints them rather than a developer
 *  remembering to. Same shape and same reason as `composeSearchBound`. */
export interface CertSearchBound {
  roots: readonly string[]
  maxDepth: number
  maxFiles: number
  names: readonly string[]
  skipped: readonly string[]
  /** Always false. `-xdev` is in the command; stating it as data is what puts
   *  it on screen next to the other three. */
  crossesFilesystems: boolean
}

export function certSearchBound(): CertSearchBound {
  return {
    roots: CERT_SEARCH_ROOTS,
    maxDepth: CERT_SEARCH_MAX_DEPTH,
    maxFiles: CERT_SEARCH_MAX_FILES,
    names: CERT_NAMES,
    skipped: CERT_SKIPPED,
    crossesFilesystems: false
  }
}

/**
 * The line, in days remaining.
 *
 * Thirty, because that is the number certbot itself renews at: a Let's Encrypt
 * certificate inside thirty days of expiry is one whose renewal was SUPPOSED
 * to have run and has not. That is the finding — not "this certificate is
 * getting old", which is not actionable, but "the automation you believe in
 * has stopped".
 *
 * Fixed rather than the configurable resource threshold, exactly as
 * DISK_DANGER, INODE_DANGER and LOAD_DANGER are fixed: it is not a percentage,
 * it does not belong on a slider beside one, and it is the number the panel
 * colours a row at. Here rather than in the alert store so the panel and the
 * alert cannot end up a few days apart — the trap `isDiskCritical` was written
 * to close.
 */
export const CERT_EXPIRY_DAYS = 30

/** At or below the line. A certificate ON thirty days is inside the window
 *  certbot would already have renewed in. */
export function isCertificateExpiringSoon(days: number): boolean {
  return days <= CERT_EXPIRY_DAYS
}

/** Why a file the search found has no date on it. Never `null` alongside a
 *  date, and never absent alongside no date. */
export type CertReadProblem =
  /** The file was found and could not be opened. NOT a file with no
   *  certificate in it. */
  | 'unreadable'
  /** It opened and holds no `-----BEGIN CERTIFICATE-----` block: a private
   *  key, a CSR, a DH parameter file, a README somebody named `.pem`. */
  | 'not-a-certificate'
  /** The certificate is longer than CERT_B64_CAP and its validity was not
   *  inside the part that was transmitted. */
  | 'truncated'
  /** It decoded and its DER is not a certificate this build can date. NOT a
   *  certificate that is valid. */
  | 'unparseable'

export interface CertificateReading {
  /** The path as the host printed it, scrubbed like any other host text. */
  path: string
  /** notAfter in epoch milliseconds, or null with a `problem` beside it. */
  notAfter: number | null
  /** Whole days from the collection to notAfter. NEGATIVE means it expired
   *  that many days ago, which is a different sentence from expiring soon and
   *  is rendered as one. */
  daysRemaining: number | null
  problem: CertReadProblem | null
}

export interface CertificateInventory {
  certificates: CertificateReading[]
  /** The file cap was reached, so this is a prefix rather than an inventory. */
  truncated: boolean
  /** Roots that are present on this host and could not be entered. A number
   *  above zero is why "none found" may not be said. */
  unreadableRoots: number
  bound: CertSearchBound
}

// ---- The posture itself ---------------------------------------------------

export interface HostPosture {
  firewall: FirewallState | null
  mandatoryAccess: MandatoryAccess | null
  sshd: SshdHardening | null
  failedLogins: FailedLoginSummary | null
  oomKills: OomKillSummary | null
  certificates: CertificateInventory | null
  /** Epoch milliseconds this collection ran, by OUR clock. */
  collectedAt: number
  sources: PostureSourceReport[]
}

/**
 * How often to collect.
 *
 * Hourly, the same slow clock as item C's facts and item 23's keys, and
 * emphatically NOT the two-minute metrics sweep. A firewall ruleset changes
 * when somebody changes it; `sshd -T` forks a copy of sshd; and `lastb` reads a
 * file that grows with every failed login on a box under attack. Thirty times
 * an hour would be thirty times the cost for an answer that moved once.
 */
export const POSTURE_INTERVAL_MS = 60 * 60 * 1000

// ---- Building the command -------------------------------------------------

export interface PostureCollectOptions {
  /**
   * Retry a refused read as root, with `sudo -n` only.
   *
   * Worth having because most of this item is root-only on a normal host:
   * `ufw status` refuses a non-root caller outright, `nft list ruleset` and
   * `iptables -S` need CAP_NET_ADMIN, `sshd -T` reads the host keys, and
   * /var/log/btmp is 0600 root. Without sudo this collector reports `denied`
   * honestly and says very little.
   *
   * Safe to have on for the reason the Docker reader gives: `sudo -n` NEVER
   * prompts. It works because this account already has passwordless sudo — a
   * decision made on that host — or it fails instantly. It cannot hang an exec
   * waiting for a tty that is not there.
   *
   * When false, the word `sudo` does not appear in the built command at all.
   * A test asserts that; a runtime guard could not.
   */
  sudo?: boolean
  /**
   * Collect the firewall RULE LINES as well as the scalars — roadmap item 31.
   *
   * OFF BY DEFAULT, and off in the command rather than off in the renderer.
   * A collector that reads a host's rules and then declines to display them
   * has still read them: they were on the wire, in this process's memory and
   * in whatever the transport buffered, and any of that outlives the decision
   * not to draw them. So the commands that list rules are omitted at BUILD
   * time — the same discipline as `sudo` above, and testable the same way.
   *
   * What turns it on is the `firewallRules` capability on the access group
   * that governs the server, which is the line in the consent grid the roadmap
   * asked for. Only `allow` collects: this runs on an unattended hourly sweep
   * with nobody at the screen, so an `ask` has nobody to ask.
   */
  firewallRules?: boolean
}

/** The only structural token in the output. No record can equal it: every
 *  record line begins with a tag and a space. */
export const POSTURE_STATUS_MARKER = '===SHELLPILOT-POSTURE==='

/** Per-value cap applied ON THE HOST, matching hostFacts.ts. An 8 KB
 *  `AllowUsers` line arrives as 512 harmless characters. */
const VALUE_CAP = 512

/** The most sshd directive records one collection will emit. Eight directives
 *  across a main file and a handful of drop-ins is a dozen at most on any real
 *  host; the cap is what stops a config of ten thousand `AllowUsers` lines
 *  from becoming ten thousand records. */
const DIRECTIVE_CAP = 64

/**
 * One round trip. No mutation, no sourcing, and no interpolation of host output
 * into a later command.
 *
 * Structure, in order:
 *   1. helpers and the sudo probe
 *   2. the firewall: front end (ufw, firewalld) then backend (nft, iptables),
 *      both, because "the front end is off" is not "nothing is filtering"
 *   3. SELinux or AppArmor
 *   4. sshd, preferring `sshd -T` and falling back to reading files
 *   5. failed logins, preferring lastb and falling back to the journal
 *
 * No `set -e`. Every read is conditional or ends in `|| true`, and the last
 * command is a `printf`, so a host with no firewall tool, no MAC, no
 * sshd_config and no btmp still returns a status block saying exactly that and
 * exits 0.
 */
export function buildPostureCommand(opts: PostureCollectOptions = {}): string {
  const sudo = opts.sudo !== false
  // OPT-IN, unlike `sudo`: absent means no. Item 31's whole argument is that a
  // rule list is collected because somebody asked for it, so the default of an
  // options object nobody filled in has to be "did not ask".
  const rules = opts.firewallRules === true
  // Omitted entirely rather than left behind a dead `[ "$SP_SUDO" = 1 ]`
  // branch, exactly as cron.ts, hostFacts.ts and access.ts do it: "this command
  // contains no sudo at all" is a property a reader can check, and a runtime
  // guard is not.
  const ifSudo = (...lines: string[]): string[] => (sudo ? lines : [])
  // Same shape, same reason: with the capability ungranted the words `sp_rule`
  // and `fw-rule-lines-front` do not appear in the script at all, so "this
  // command does not read the rules" is a property somebody can check by
  // reading it — and a test asserts exactly that.
  const ifRules = (...lines: string[]): string[] => (rules ? lines : [])
  /**
   * List one reading's rules: count what matched, then emit at most the cap.
   *
   * The COUNT AND THE LIST ARE THE SAME GREP, deliberately. A list filtered one
   * way beside a count taken another is two answers to one question, and the
   * one a person would trust is whichever is on screen.
   *
   * `|| true` on the counting grep for the reason every other counting grep
   * here has it: grep exits 1 when it selects nothing, which is the answer
   * zero rather than an error. `while read` over a pipe rather than `for` so a
   * rule containing a space stays one rule.
   */
  const listRules = (origin: FirewallRuleOrigin, blob: string, pattern: string): string[] =>
    ifRules(
      `SP_RL=$(printf '%s\\n' "${blob}" | grep -E '${pattern}' || true)`,
      `sp_val fw-rule-lines-${origin} "$(printf '%s\\n' "$SP_RL" | grep -c . || true)"`,
      `printf '%s\\n' "$SP_RL" | head -n ${FIREWALL_RULE_MAX_LINES} | while IFS= read -r SP_L; do sp_rule ${origin} "$SP_L"; done`
    )
  const probe = sudo ? `SP_SUDO=0\n[ "$(${SUDO_PROBE})" = SP_SUDO_OK ] && SP_SUDO=1` : 'SP_SUDO=0'

  // One binary lookup, stashed under its own name. resolveBinary writes SP_BIN,
  // so it has to be copied before the next call.
  const findBin = (name: string, varName: string, extra: string[] = []): string[] => [
    resolveBinary(name, extra),
    `${varName}=""`,
    `command -v "$SP_BIN" >/dev/null 2>&1 && ${varName}="$SP_BIN"`
  ]

  // The eight directives, as one case-insensitive alternation. `[[:space:]=]`
  // because sshd_config accepts `Key=value` as well as `Key value`, and a
  // pattern that only matched the space form would report a host using the
  // other spelling as having nothing set at all.
  const DIRECTIVE_RX = `^[[:space:]]*(${SSHD_DIRECTIVES.join('|')})[[:space:]=]`

  return [
    // C locale for the whole script. `lastb` prints dates through the locale and
    // `firewall-cmd` translates its own state words, so without this a host in
    // de_DE reports a firewall state of `wird ausgeführt`, which parses as
    // nothing.
    'LC_ALL=C',
    'export LC_ALL',

    // A literal newline in a variable so statuses accumulate one per line.
    // `$(printf ...)` cannot be used: command substitution strips trailing
    // newlines, which is the entire content here.
    "SP_NL='\n'",
    'SP_STATUS=""',
    'sp_note() { SP_STATUS="$SP_STATUS$*$SP_NL"; }',
    // THE defence, and the reason a PermitRootLogin value cannot forge
    // anything. Tabs become spaces FIRST — `PermitRootLogin\tyes` is how plenty
    // of hand-edited configs actually spell it, and deleting the tab would
    // produce `PermitRootLoginyes`, which parses as a directive nobody has
    // heard of. Then control characters, newlines and carriage returns
    // included, are DELETED, and the result is cut. A value can never become a
    // second line, forge a record tag, or forge the status marker.
    `sp_clean() { printf '%s' "$1" | tr '\\011' ' ' | tr -d '\\000-\\037\\177' | cut -c1-${VALUE_CAP}; }`,
    'sp_val() { SP_V=$(sp_clean "$2"); [ -n "$SP_V" ] && printf \'V %s %s\\n\' "$1" "$SP_V"; }',
    // One firewall rule line — roadmap item 31, and the only record here whose
    // payload is neither a count nor a word from a fixed list. It gets the
    // SAME scrub as every other value (tabs to spaces first, then control
    // characters deleted, so a rule can never become a second record or forge
    // the status marker) and its own tighter cap. The origin is a literal this
    // file wrote, never anything read off the host, so a rule that begins with
    // the word `front` is a rule whose text begins with `front`.
    ...ifRules(
      `sp_rule() { SP_V=$(printf '%s' "$2" | tr '\\011' ' ' | tr -d '\\000-\\037\\177' | cut -c1-${FIREWALL_RULE_LINE_CAP}); [ -n "$SP_V" ] && printf 'R %s %s\\n' "$1" "$SP_V"; }`
    ),
    // One sshd directive, name and value together on one line, because the
    // parser has to see which key a value belongs to rather than trusting
    // position. Emitted once per matching line rather than once per directive,
    // so two drop-ins that disagree arrive as two records and are reported as
    // ambiguous instead of one of them being silently picked.
    "sp_dir() { SP_V=$(sp_clean \"$1\"); [ -n \"$SP_V\" ] && printf 'D %s\\n' \"$SP_V\"; }",
    // One certificate: the base64 body FIRST and the path last, so a path
    // containing a space is the remainder of the line rather than something
    // the parser has to guess the end of. The body gets its own cap — a
    // certificate is kilobytes and VALUE_CAP is 512 — and its own scrub, which
    // deletes control characters AND spaces: base64 contains neither, so
    // anything removed here was never part of a certificate. A body that
    // survives to nothing becomes `-`, which the parser reads as a file it
    // could not open rather than as an empty certificate.
    `sp_cert() { SP_B=$(printf '%s' "$1" | tr -d '\\000-\\037\\177 ' | cut -c1-${CERT_B64_CAP}); SP_P=$(sp_clean "$2"); [ -n "$SP_P" ] && printf 'C %s %s\\n' "\${SP_B:--}" "$SP_P"; }`,
    probe,

    // =====================================================================
    // FIREWALL
    // =====================================================================
    //
    // Two readings, always, and that is the design rather than thoroughness.
    // A front end reporting `inactive` says nothing about whether the kernel is
    // filtering: a cloud image with an nftables ruleset loaded by systemd at
    // boot has ufw installed, inactive, and a closed box. Reporting only the
    // front end would render that host as unprotected, and reporting only the
    // backend would lose the ufw rule list an operator actually edits.
    //
    // SP_FW_READ / SP_FW_MISS count what answered and what was refused, and the
    // status is decided from them ONCE at the end — so there is exactly one
    // status for this source whichever branch set it, which is the fix access.ts
    // had to make after a skipped file left a source reading `ok`.
    ...findBin('ufw', 'SP_UFW'),
    ...findBin('firewall-cmd', 'SP_FWC'),
    ...findBin('nft', 'SP_NFT'),
    ...findBin('iptables', 'SP_IPT'),
    // Emitted whenever the rule collection was BUILT IN, before anything is
    // read, so the parser can tell "nobody granted this" from "it was granted
    // and every read was refused". Those have different fixes and only one of
    // them is about the host.
    ...ifRules('sp_val fw-rule-collection on'),
    'SP_FW_READ=0',
    'SP_FW_MISS=0',
    'SP_FW_W="-"',
    'SP_FW_D="-"',
    'SP_FW_ANY=0',
    '[ -n "$SP_UFW" ] || [ -n "$SP_FWC" ] || [ -n "$SP_NFT" ] || [ -n "$SP_IPT" ] && SP_FW_ANY=1',

    // ---- ufw -------------------------------------------------------------
    'if [ -n "$SP_UFW" ]; then',
    'SP_OUT=$("$SP_UFW" status verbose 2>/dev/null)',
    ...ifSudo(
      'if [ "${SP_OUT#*Status:}" = "$SP_OUT" ] && [ "$SP_SUDO" = 1 ]; then',
      'SP_OUT=$(sudo -n "$SP_UFW" status verbose 2>/dev/null)',
      '[ "${SP_OUT#*Status:}" != "$SP_OUT" ] && SP_FW_W=root',
      'fi'
    ),
    // Shape-checked before it is believed: `ufw status` prints an error to
    // stderr and nothing to stdout for a non-root caller, and a pipeline's exit
    // status would be the last command's rather than ufw's.
    'if [ "${SP_OUT#*Status:}" != "$SP_OUT" ]; then',
    'sp_val fw-tool ufw',
    `sp_val fw-active "$(printf '%s\\n' "$SP_OUT" | grep -i '^Status:' | head -1 | sed 's/^[^:]*:[[:space:]]*//')"`,
    'SP_DEF=$(printf \'%s\\n\' "$SP_OUT" | grep -i \'^Default:\' | head -1)',
    // `Default: deny (incoming), allow (outgoing), disabled (routed)`
    `sp_val fw-policy-in "$(printf '%s' "$SP_DEF" | sed -n 's/.*[:,][[:space:]]*\\([a-z]*\\)[[:space:]]*(incoming).*/\\1/p')"`,
    `sp_val fw-policy-out "$(printf '%s' "$SP_DEF" | sed -n 's/.*[:,][[:space:]]*\\([a-z]*\\)[[:space:]]*(outgoing).*/\\1/p')"`,
    // `|| true` on every counting grep. grep exits 1 when it selects no lines,
    // which is not an error here — it is the answer zero — and the shape of bug
    // that has already been found once in this codebase.
    `sp_val fw-rules "$(printf '%s\\n' "$SP_OUT" | grep -c -E '(ALLOW|DENY|REJECT|LIMIT)[[:space:]]+(IN|OUT|FWD)' || true)"`,
    `sp_val fw-deny "$(printf '%s\\n' "$SP_OUT" | grep -c -E '(DENY|REJECT)[[:space:]]+(IN|OUT|FWD)' || true)"`,
    // The rules themselves — item 31. The SAME grep that produced the count
    // above, so the list and the number cannot disagree.
    ...listRules('front', '$SP_OUT', '(ALLOW|DENY|REJECT|LIMIT)[[:space:]]+(IN|OUT|FWD)'),
    'SP_FW_READ=1',
    'SP_FW_D="ufw status verbose"',
    // TRAVERSAL BEFORE EXISTENCE. `chmod 700 /etc/ufw` makes `[ -r
    // /etc/ufw/ufw.conf ]` false, which is indistinguishable from the file not
    // being there — and "no ufw.conf" would take the branch that says ufw was
    // never configured.
    'elif [ -d /etc/ufw ] && [ ! -x /etc/ufw ]; then',
    'SP_FW_MISS=1',
    'SP_FW_D="ufw is installed, its status needs root here, and /etc/ufw cannot be entered by this account"',
    'elif [ -r /etc/ufw/ufw.conf ]; then',
    // The on/off flag WITHOUT the rules. Reported as a partial reading rather
    // than as a firewall reading: knowing ufw is enabled says nothing about
    // what it lets through, and a panel that showed `active` with no rule count
    // would read as a complete answer.
    'sp_val fw-tool ufw',
    `sp_val fw-active "$(grep -i '^ENABLED=' /etc/ufw/ufw.conf 2>/dev/null | head -1 | sed 's/^[^=]*=//')"`,
    'SP_FW_READ=1',
    'SP_FW_MISS=1',
    'SP_FW_D="ufw status needs root on this host, so only /etc/ufw/ufw.conf was read: it says whether ufw is switched on and nothing about the rules"',
    'else',
    'SP_FW_MISS=1',
    'SP_FW_D="ufw is installed and reading its status needs root on this host"',
    'fi',

    // ---- firewalld -------------------------------------------------------
    'elif [ -n "$SP_FWC" ]; then',
    'SP_ST=$("$SP_FWC" --state 2>/dev/null)',
    ...ifSudo(
      'if [ -z "$SP_ST" ] && [ "$SP_SUDO" = 1 ]; then',
      'SP_ST=$(sudo -n "$SP_FWC" --state 2>/dev/null)',
      '[ -n "$SP_ST" ] && SP_FW_W=root',
      'fi'
    ),
    'if [ -n "$SP_ST" ]; then',
    'sp_val fw-tool firewalld',
    'sp_val fw-active "$SP_ST"',
    'SP_FW_READ=1',
    'SP_FW_D="firewall-cmd --state"',
    // The zones and the rule shape, asked for separately and allowed to fail:
    // `--state` answers for a caller polkit lets through while `--list-all`
    // does not, and folding them together would trade the state for the list.
    `SP_ZN=$("$SP_FWC" --get-default-zone 2>/dev/null)`,
    `SP_ZA=$("$SP_FWC" --get-active-zones 2>/dev/null)`,
    `SP_LA=$("$SP_FWC" --list-all 2>/dev/null)`,
    ...ifSudo(
      'if [ -z "$SP_LA" ] && [ "$SP_SUDO" = 1 ]; then',
      'SP_ZN=$(sudo -n "$SP_FWC" --get-default-zone 2>/dev/null)',
      'SP_ZA=$(sudo -n "$SP_FWC" --get-active-zones 2>/dev/null)',
      'SP_LA=$(sudo -n "$SP_FWC" --list-all 2>/dev/null)',
      '[ -n "$SP_LA" ] && SP_FW_W=root',
      'fi'
    ),
    '[ -n "$SP_ZN" ] && sp_val fw-zone "$SP_ZN"',
    // A zone name sits at column 0; its interfaces are indented under it.
    `[ -n "$SP_ZA" ] && sp_val fw-zones "$(printf '%s\\n' "$SP_ZA" | grep -v '^[[:space:]]' | tr '\\n' ',')"`,
    'if [ -n "$SP_LA" ]; then',
    `sp_val fw-policy-in "$(printf '%s\\n' "$SP_LA" | grep -E '^[[:space:]]*target:' | head -1 | sed 's/^[^:]*:[[:space:]]*//')"`,
    // Services, ports and rich rules together: what this zone lets in.
    `SP_SV=$(printf '%s\\n' "$SP_LA" | grep -E '^[[:space:]]*(services|ports):' | sed 's/^[^:]*:[[:space:]]*//')`,
    `SP_RR=$(printf '%s\\n' "$SP_LA" | grep -c -E '^[[:space:]]*rule ' || true)`,
    `SP_SVN=$(printf '%s\\n' "$SP_SV" | tr ' ' '\\n' | grep -c . || true)`,
    'sp_val fw-rules "$((SP_SVN + SP_RR))"',
    // What this zone lets in, as firewalld itself prints it: the services and
    // ports lines and every rich rule. An empty field (`protocols:` with
    // nothing after it) is dropped rather than listed as a rule.
    ...listRules(
      'front',
      '$SP_LA',
      '^[[:space:]]*((services|ports|protocols|forward-ports|source-ports):[[:space:]]*[^[:space:]]|rule )'
    ),
    'else',
    'SP_FW_MISS=1',
    'SP_FW_D="firewalld is running and listing its rules needs root on this host"',
    'fi',
    'elif [ -d /etc/firewalld ] && [ ! -x /etc/firewalld ]; then',
    // Traversal before existence again. A firewalld config directory this
    // account cannot enter is not a host without firewalld.
    'SP_FW_MISS=1',
    'SP_FW_D="firewalld is installed, its state needs root here, and /etc/firewalld cannot be entered by this account"',
    'else',
    'SP_FW_MISS=1',
    'SP_FW_D="firewall-cmd is installed and it answered nothing, so neither its state nor its rules were read"',
    'fi',
    'fi',

    // ---- the backend, ALWAYS ---------------------------------------------
    // Read whether or not a front end answered, because the front end saying
    // "inactive" is not the kernel saying "nothing is filtering".
    'SP_BE_ST=unsupported',
    'SP_BE_W="-"',
    'if [ -n "$SP_NFT" ]; then',
    'SP_OUT=$("$SP_NFT" list ruleset 2>/dev/null)',
    'SP_RC=$?',
    ...ifSudo(
      'if [ "$SP_RC" != 0 ] && [ "$SP_SUDO" = 1 ]; then',
      'SP_OUT=$(sudo -n "$SP_NFT" list ruleset 2>/dev/null)',
      'SP_RC=$?',
      '[ "$SP_RC" = 0 ] && SP_BE_W=root',
      'fi'
    ),
    // Exit status, not emptiness. An EMPTY ruleset prints nothing and exits 0,
    // and that is a real finding — the kernel filter tables have no rules in
    // them. Treating empty output as a failure would hide it; treating a
    // failure as empty output would invent it.
    'if [ "$SP_RC" = 0 ]; then',
    'sp_val fw-backend nftables',
    `sp_val fw-backend-rules "$(printf '%s\\n' "$SP_OUT" | grep -c -E '^[[:space:]]+[a-z]' || true)"`,
    `sp_val fw-backend-policy "$(printf '%s\\n' "$SP_OUT" | grep -E 'hook input' | head -1 | sed -n 's/.*policy[[:space:]]*\\([a-z]*\\).*/\\1/p')"`,
    // The same indented-line pattern the count uses, for listRules' reason.
    ...listRules('backend', '$SP_OUT', '^[[:space:]]+[a-z]'),
    'SP_BE_ST=ok',
    'else',
    'SP_BE_ST=denied',
    'fi',
    'fi',
    // iptables second, and only when nft did not answer: on a modern host
    // `iptables` is a shim over the same nft tables, so asking both would count
    // the same rules twice under two names.
    'if [ "$SP_BE_ST" != ok ] && [ -n "$SP_IPT" ]; then',
    'SP_OUT=$("$SP_IPT" -S 2>/dev/null)',
    'SP_RC=$?',
    ...ifSudo(
      'if [ "$SP_RC" != 0 ] && [ "$SP_SUDO" = 1 ]; then',
      'SP_OUT=$(sudo -n "$SP_IPT" -S 2>/dev/null)',
      'SP_RC=$?',
      '[ "$SP_RC" = 0 ] && SP_BE_W=root',
      'fi'
    ),
    'if [ "$SP_RC" = 0 ]; then',
    'sp_val fw-backend iptables',
    `sp_val fw-backend-rules "$(printf '%s\\n' "$SP_OUT" | grep -c '^-A ' || true)"`,
    `sp_val fw-backend-policy "$(printf '%s\\n' "$SP_OUT" | grep -E '^-P INPUT ' | head -1 | sed 's/^-P INPUT[[:space:]]*//')"`,
    // `-A` only, matching the count. The chain policies are already reported
    // as fw-backend-policy and listing them here would count them twice.
    ...listRules('backend', '$SP_OUT', '^-A '),
    'SP_BE_ST=ok',
    'else',
    'SP_BE_ST=denied',
    'fi',
    'fi',
    'sp_val fw-backend-status "$SP_BE_ST"',
    '[ "$SP_BE_ST" = ok ] && SP_FW_READ=1',
    '[ "$SP_BE_ST" = denied ] && SP_FW_MISS=1',

    // ---- one status for the firewall, decided once -----------------------
    'if [ "$SP_FW_ANY" = 0 ]; then',
    // NOT `no-tool`, and the detail says why. The kernel can be filtering with
    // nothing installed to ask — an nftables ruleset restored at boot, or a
    // hypervisor security group in front of the NIC. "There is nothing here to
    // ask" is true; "there is no firewall" is not, and this build cannot tell
    // them apart.
    'sp_note firewall unsupported - "this host has none of ufw, firewalld, nft or iptables installed, so nothing here can be asked what the kernel is filtering — which is NOT the same as nothing being filtered"',
    'elif [ "$SP_FW_READ" = 1 ] && [ "$SP_FW_MISS" = 0 ]; then',
    'sp_note firewall ok "$SP_FW_W" "$SP_FW_D"',
    'elif [ "$SP_FW_READ" = 1 ]; then',
    'sp_note firewall partial "$SP_FW_W" "$SP_FW_D"',
    'else',
    'sp_note firewall denied "$SP_FW_W" "$SP_FW_D"',
    'fi',

    // =====================================================================
    // SELINUX / APPARMOR
    // =====================================================================
    ...findBin('getenforce', 'SP_GE'),
    ...findBin('aa-status', 'SP_AA', ['/usr/sbin/apparmor_status']),
    'SP_MAC_ST=unknown',
    'SP_MAC_W="-"',
    'SP_MAC_D="-"',
    // SELinux first: where both are present the one with a mounted selinuxfs is
    // the one the kernel is enforcing with.
    'if [ -d /sys/fs/selinux ]; then',
    'sp_val mac-system selinux',
    'SP_EN=""',
    '[ -r /sys/fs/selinux/enforce ] && SP_EN=$(cat /sys/fs/selinux/enforce 2>/dev/null)',
    'case "$SP_EN" in',
    '1) sp_val mac-mode enforcing; sp_val mac-enabled yes; SP_MAC_ST=ok; SP_MAC_D="/sys/fs/selinux/enforce" ;;',
    '0) sp_val mac-mode permissive; sp_val mac-enabled yes; SP_MAC_ST=ok; SP_MAC_D="/sys/fs/selinux/enforce" ;;',
    '*)',
    'SP_GEO=""',
    '[ -n "$SP_GE" ] && SP_GEO=$("$SP_GE" 2>/dev/null)',
    'case "$SP_GEO" in',
    'Enforcing) sp_val mac-mode enforcing; sp_val mac-enabled yes; SP_MAC_ST=ok; SP_MAC_D="getenforce" ;;',
    'Permissive) sp_val mac-mode permissive; sp_val mac-enabled yes; SP_MAC_ST=ok; SP_MAC_D="getenforce" ;;',
    'Disabled) sp_val mac-mode disabled; sp_val mac-enabled no; SP_MAC_ST=ok; SP_MAC_D="getenforce" ;;',
    // selinuxfs is mounted and neither the file nor getenforce would say. That
    // is a permission answer, not a "SELinux is off" answer.
    '*) SP_MAC_ST=denied; SP_MAC_D="selinuxfs is mounted and neither /sys/fs/selinux/enforce nor getenforce could be read" ;;',
    'esac',
    ';;',
    'esac',
    // The BOOT-TIME setting, which is a different fact from the running one and
    // the interesting case is the disagreement: `setenforce 0` leaves this file
    // saying enforcing while the kernel is permissive until the next reboot.
    'if [ -r /etc/selinux/config ]; then',
    `sp_val mac-boot "$(grep -E '^[[:space:]]*SELINUX=' /etc/selinux/config 2>/dev/null | tail -1 | sed 's/^[^=]*=//')"`,
    'fi',
    // ---- AppArmor --------------------------------------------------------
    'elif [ -e /sys/module/apparmor/parameters/enabled ] || [ -n "$SP_AA" ]; then',
    'sp_val mac-system apparmor',
    'SP_AE=""',
    '[ -r /sys/module/apparmor/parameters/enabled ] && SP_AE=$(cat /sys/module/apparmor/parameters/enabled 2>/dev/null)',
    'case "$SP_AE" in',
    'Y|y) sp_val mac-enabled yes; SP_MAC_ST=ok; SP_MAC_D="/sys/module/apparmor/parameters/enabled" ;;',
    'N|n) sp_val mac-enabled no; SP_MAC_ST=ok; SP_MAC_D="/sys/module/apparmor/parameters/enabled" ;;',
    '*) SP_MAC_ST=denied; SP_MAC_D="the apparmor module parameter could not be read" ;;',
    'esac',
    // The profile counts. Root-only on every distribution that ships AppArmor,
    // so their absence is `partial` rather than a zero: "0 profiles loaded" and
    // "the profile list needs root" are opposite findings.
    //
    // TRAVERSAL BEFORE EXISTENCE: /sys/kernel/security is commonly mode 700, so
    // testing for the profiles file through it answers false on a host that has
    // one.
    'SP_PROF=""',
    'if [ -d /sys/kernel/security ] && [ ! -x /sys/kernel/security ]; then',
    'SP_MAC_D="apparmor is enabled and /sys/kernel/security cannot be entered by this account, so no profile count was read"',
    '[ "$SP_MAC_ST" = ok ] && SP_MAC_ST=partial',
    'elif [ -r /sys/kernel/security/apparmor/profiles ]; then',
    'SP_PROF=$(cat /sys/kernel/security/apparmor/profiles 2>/dev/null)',
    ...ifSudo(
      'elif [ "$SP_SUDO" = 1 ]; then',
      'SP_PROF=$(sudo -n cat /sys/kernel/security/apparmor/profiles 2>/dev/null)',
      '[ -n "$SP_PROF" ] && SP_MAC_W=root'
    ),
    'fi',
    'if [ -n "$SP_PROF" ]; then',
    `sp_val mac-profiles "$(printf '%s\\n' "$SP_PROF" | grep -c . || true)"`,
    `sp_val mac-complain "$(printf '%s\\n' "$SP_PROF" | grep -c '(complain)' || true)"`,
    'elif [ "$SP_MAC_ST" = ok ]; then',
    'SP_MAC_ST=partial',
    'SP_MAC_D="apparmor is enabled and its profile list needs root on this host, so how many profiles are loaded was not read"',
    'fi',
    'else',
    // CHECKED absent, not assumed. Both interfaces were looked for and neither
    // is there — a real finding on a stock Debian without apparmor installed.
    'sp_note mandatory-access absent - "this host has neither SELinux nor AppArmor: no selinuxfs, no apparmor module and neither getenforce nor aa-status is installed"',
    'SP_MAC_ST=""',
    'fi',
    '[ -n "$SP_MAC_ST" ] && sp_note mandatory-access "$SP_MAC_ST" "$SP_MAC_W" "$SP_MAC_D"',

    // =====================================================================
    // SSHD AGAINST THE HARDENING BASELINE
    // =====================================================================
    //
    // `sshd -T` is preferred and is asked for FIRST, which is the opposite of
    // what access.ts does and for a reason worth writing down. access.ts is
    // looking for the presence of ONE directive and mixing two spellings of it
    // would manufacture a disagreement; this is reading a whole directive set,
    // where `sshd -T` is strictly better — it prints the EFFECTIVE
    // configuration with every Include resolved, every Match block excluded
    // from the global view, and every compiled-in default filled in, which is
    // the only way to know what a default actually is on this host's OpenSSH.
    //
    // The two sources are never mixed. Whichever answered is named in the
    // status, and `sshd-src` tells the parser which — because a directive
    // missing from `sshd -T` output means something quite different from a
    // directive missing from a file.
    ...ifSudo(...findBin('sshd', 'SP_SSHDBIN', ['/usr/sbin/sshd', '/usr/local/sbin/sshd'])),
    'SP_SSHD_ST=unknown',
    'SP_SSHD_W="-"',
    'SP_SSHD_D="-"',
    'SP_SSHD_SRC=""',
    ...ifSudo(
      'if [ "$SP_SUDO" = 1 ] && [ -n "$SP_SSHDBIN" ]; then',
      'SP_T=$(sudo -n "$SP_SSHDBIN" -T 2>/dev/null || true)',
      'if [ -n "$SP_T" ]; then',
      'SP_SSHD_SRC=effective',
      `printf '%s\\n' "$SP_T" | grep -i -E '${DIRECTIVE_RX}' | head -${DIRECTIVE_CAP} | while IFS= read -r SP_L; do sp_dir "$SP_L"; done`,
      // sshd -T resolves Match blocks out of the global view rather than
      // showing them, so the count is not available from it. Zero would be a
      // lie and null is the truth: the parser is told nothing and reports
      // nothing.
      'SP_SSHD_ST=ok',
      'SP_SSHD_W=root',
      'SP_SSHD_D="sshd -T reported the effective configuration"',
      'fi',
      'fi'
    ),
    'if [ -z "$SP_SSHD_SRC" ]; then',
    // TRAVERSAL BEFORE EXISTENCE, and this is the single most dangerous place
    // in the file to get it wrong. `chmod 700 /etc/ssh` is on plenty of
    // hardened images; `[ -e /etc/ssh/sshd_config ]` through a directory this
    // account cannot enter is FALSE, and "there is no sshd_config" would mean
    // "the compiled-in defaults apply", which is a confident statement about a
    // configuration nobody read — on a host that is, by the shape of the
    // failure, more hardened than average rather than less.
    'if [ ! -d /etc/ssh ]; then',
    'SP_SSHD_ST=absent',
    'SP_SSHD_D="this host has no /etc/ssh directory"',
    'elif [ ! -x /etc/ssh ]; then',
    'SP_SSHD_ST=denied',
    'SP_SSHD_D="/etc/ssh exists and this account cannot enter it, so nothing about how sshd is configured was read"',
    'elif [ -r /etc/ssh/sshd_config ]; then',
    'SP_SSHD_SRC=files',
    'SP_SSHD_MISS=0',
    'SP_SSHD_MATCH=0',
    // Drop-ins FIRST, then the main file. Debian and Ubuntu put `Include
    // /etc/ssh/sshd_config.d/*.conf` at the TOP of sshd_config and sshd takes
    // the FIRST value it sees for a directive, so a drop-in wins there. Reading
    // in that order means `head -1` on the far side matches what sshd does on
    // the layout almost every host actually has — and where it does not, two
    // different values arrive as two records and are reported as ambiguous
    // rather than arbitrated. That is also why `sshd -T` is preferred above.
    'for f in /etc/ssh/sshd_config.d/*.conf /etc/ssh/sshd_config; do',
    '[ -f "$f" ] || continue',
    'if [ -r "$f" ]; then',
    // Everything up to the first `Match` line is the GLOBAL section. Directives
    // after one apply conditionally, and reading them as global would report a
    // host that allows passwords for one user as allowing them for everyone.
    // sshd is case-insensitive on directive names, hence the character classes.
    `SP_G=$(sed -n '/^[[:space:]]*[Mm][Aa][Tt][Cc][Hh][[:space:]]/q;p' "$f" 2>/dev/null | head -n 500)`,
    `SP_SSHD_MATCH=$((SP_SSHD_MATCH + $(grep -c -i -E '^[[:space:]]*Match[[:space:]]' "$f" 2>/dev/null || true)))`,
    `printf '%s\\n' "$SP_G" | grep -i -E '${DIRECTIVE_RX}' | head -${DIRECTIVE_CAP} | while IFS= read -r SP_L; do sp_dir "$SP_L"; done`,
    'else',
    // A FILE SKIPPED IS A FILE REPORTED. A 0600 root-only hardening drop-in is
    // ordinary, and skipping it silently would mean the reading looked complete
    // over a config that was read in part — the exact bug access.ts had.
    'SP_SSHD_MISS=1',
    'fi',
    'done',
    // A drop-in directory that cannot be entered hides an unknown number of
    // files, which is the same finding as one unreadable file and worse.
    '[ -d /etc/ssh/sshd_config.d ] && [ ! -x /etc/ssh/sshd_config.d ] && SP_SSHD_MISS=1',
    'sp_val sshd-match "$SP_SSHD_MATCH"',
    'if [ "$SP_SSHD_MISS" = 1 ]; then',
    'SP_SSHD_ST=partial',
    'SP_SSHD_D="a file under /etc/ssh could not be read, so a directive overriding one of these may not be in what was read"',
    'else',
    'SP_SSHD_ST=ok',
    'SP_SSHD_D="/etc/ssh/sshd_config and its drop-ins"',
    'fi',
    'elif [ -e /etc/ssh/sshd_config ]; then',
    'SP_SSHD_ST=denied',
    'SP_SSHD_D="sshd_config exists and this account cannot read it"',
    'else',
    'SP_SSHD_ST=absent',
    'SP_SSHD_D="/etc/ssh can be entered and there is no sshd_config in it"',
    'fi',
    'fi',
    '[ -n "$SP_SSHD_SRC" ] && sp_val sshd-src "$SP_SSHD_SRC"',
    'sp_note sshd-hardening "$SP_SSHD_ST" "$SP_SSHD_W" "$SP_SSHD_D"',

    // =====================================================================
    // FAILED LOGINS
    // =====================================================================
    //
    // COUNTS ONLY, and that is a decision rather than an omission. Every field
    // on a failed-login record — the username, the source as the host resolved
    // it, the terminal — is attacker-chosen text, so a list of them is attacker
    // text on an operator's screen. The two counts answer the question an
    // operator actually has ("is something hammering this box, and is it
    // spraying names or targeting one") and cannot carry a payload.
    //
    // NOTHING IS BUFFERED IN A SHELL VARIABLE HERE, unlike every other block
    // above. A ruleset and an sshd_config are kilobytes; btmp on a host that
    // has been under a credential-stuffing run for a month is tens of
    // megabytes, and `SP_LB=$(lastb)` would hold all of it in the remote
    // shell's memory to produce a number. So the counting happens inside the
    // pipeline and only the number is ever assigned. The cost is that a
    // pipeline's exit status is the LAST command's, so the readability of btmp
    // is established from what lastb wrote to STDERR — the same way access.ts
    // tells a busybox `passwd` from a permission problem.
    ...findBin('lastb', 'SP_LASTB'),
    ...findBin('journalctl', 'SP_JCTL'),
    'SP_FL_ST=no-tool',
    'SP_FL_W="-"',
    'SP_FL_D="neither lastb nor journalctl is installed, so no record of failed logins can be read"',
    // Rows that are not attempts: the trailing `btmp begins <date>` line and
    // blank lines.
    "SP_FLX='^(btmp begins|[[:space:]]*$)'",
    'SP_LASTB_RUN=""',
    'if [ -n "$SP_LASTB" ]; then',
    // The error text, with lastb's own output thrown away. Empty means it could
    // read btmp — including the case where btmp is readable and EMPTY, which is
    // a genuine zero and must not become a failure.
    'SP_ERR=$("$SP_LASTB" 2>&1 >/dev/null | head -n 3)',
    '[ -z "$SP_ERR" ] && SP_LASTB_RUN="$SP_LASTB"',
    ...ifSudo(
      'if [ -n "$SP_ERR" ] && [ "$SP_SUDO" = 1 ]; then',
      'SP_E2=$(sudo -n "$SP_LASTB" 2>&1 >/dev/null | head -n 3)',
      'if [ -z "$SP_E2" ]; then SP_ERR=""; SP_LASTB_RUN="sudo -n $SP_LASTB"; SP_FL_W=root; fi',
      'fi'
    ),
    'if [ -n "$SP_LASTB_RUN" ]; then',
    'sp_val fail-tool lastb',
    // THE EMPTY-BTMP CASE, which is where a counting probe usually goes wrong.
    // `grep -v` exits 1 when it selects no lines and `grep -c` exits 1 when it
    // counts none — the shape of bug the cron harness has already found once in
    // this codebase. What carries it here is that `grep -c` still PRINTS `0`,
    // and that the count is taken from the substitution's OUTPUT rather than
    // from whether the pipeline succeeded: a probe written as
    // `SP_ROWS=$(...); [ -n "$SP_ROWS" ] && sp_val fail-count ...` reads an
    // empty btmp as "no count at all" instead of as zero, and the source then
    // downgrades to `unknown` on a host that answered perfectly well. The
    // `|| true` is belt to that braces.
    `sp_val fail-count "$($SP_LASTB_RUN 2>/dev/null | grep -v -E "$SP_FLX" | grep -c . || true)"`,
    // Distinct usernames: column one, deduplicated. A hundred attempts spread
    // over a hundred names and a hundred aimed at root are the same count and
    // very different situations.
    `sp_val fail-users "$($SP_LASTB_RUN 2>/dev/null | grep -v -E "$SP_FLX" | sed 's/[[:space:]].*//' | sort -u | grep -c . || true)"`,
    // btmp is rotated, so the window is "since this file was created" and the
    // host's own sentence for that is carried verbatim rather than turned into
    // a number this side cannot verify.
    `sp_val fail-window "$($SP_LASTB_RUN 2>/dev/null | grep -i '^btmp begins' | head -1 || true)"`,
    'SP_FL_ST=ok',
    'SP_FL_D="lastb, over the whole of the current btmp"',
    'else',
    // Told apart by what the tool SAID, because there is no exit status left to
    // read. A missing btmp is a real absence — plenty of hardened and
    // container images ship without one, and no failed login can ever be
    // recorded there — and it is a different fix from a permission problem.
    'case "$SP_ERR" in',
    '*"No such file"*|*"no such file"*|*"cannot open"*)',
    'SP_FL_ST=absent',
    'SP_FL_D="this host has no /var/log/btmp, so failed logins are not being recorded there at all" ;;',
    '*)',
    'SP_FL_ST=denied',
    'SP_FL_D="/var/log/btmp exists and reading it needs root on this host" ;;',
    'esac',
    'fi',
    'fi',
    // The journal, only when lastb did not answer. Its window is FIXED and
    // stated, unlike btmp's, which runs from whenever logrotate last turned the
    // file over — so the two readings are not interchangeable and `fail-tool`
    // says which produced the number.
    'if [ "$SP_FL_ST" != ok ] && [ -n "$SP_JCTL" ]; then',
    // `-n 0` is the cheap readability probe: it opens the journal, prints
    // nothing and exits 1 when this account may not read it. Without it the
    // counting pipelines below would report 0 for a refusal.
    'SP_JRUN=""',
    '"$SP_JCTL" --no-pager -q -n 0 >/dev/null 2>&1 && SP_JRUN="$SP_JCTL"',
    ...ifSudo(
      'if [ -z "$SP_JRUN" ] && [ "$SP_SUDO" = 1 ]; then',
      'sudo -n "$SP_JCTL" --no-pager -q -n 0 >/dev/null 2>&1 && { SP_JRUN="sudo -n $SP_JCTL"; SP_FL_W=root; }',
      'fi'
    ),
    'if [ -n "$SP_JRUN" ]; then',
    'sp_val fail-tool journal',
    `SP_JQ='(Failed password|Invalid user|authentication failure|Failed publickey)'`,
    `SP_JA="--no-pager -q --since -${FAILED_LOGIN_WINDOW_HOURS}hours -t sshd"`,
    `sp_val fail-count "$($SP_JRUN $SP_JA 2>/dev/null | grep -c -E "$SP_JQ" || true)"`,
    // `Failed password for invalid user bob from 10.0.0.1` and `Failed password
    // for bob from 10.0.0.1`: the name is the field before `from`.
    `sp_val fail-users "$($SP_JRUN $SP_JA 2>/dev/null | grep -E "$SP_JQ" | sed -n 's/.*for \\(invalid user \\)\\{0,1\\}\\([^ ]*\\) from .*/\\2/p' | sort -u | grep -c . || true)"`,
    `sp_val fail-window "the last ${FAILED_LOGIN_WINDOW_HOURS} hours of the journal"`,
    'SP_FL_ST=ok',
    'SP_FL_D="journalctl -t sshd"',
    'elif [ "$SP_FL_ST" = no-tool ]; then',
    'SP_FL_ST=denied',
    'SP_FL_D="the journal is present and this account may not read it"',
    'fi',
    'fi',
    'sp_note failed-logins "$SP_FL_ST" "$SP_FL_W" "$SP_FL_D"',

    // =====================================================================
    // OOM KILLS
    // =====================================================================
    //
    // Three sources, in a strict order of preference, because they do not give
    // the same answer: the kernel journal can be asked for a WINDOW, and the
    // other two cannot. See the block comment on OomKillSummary for the whole
    // scope decision; what matters here is that the source is emitted with the
    // count, so nothing downstream can read a ring-buffer zero as a statement
    // about the last day.
    //
    // SP_JCTL is the one resolved by the failed-login block above rather than a
    // second lookup, and that ordering dependency is deliberate: `findBin`
    // emits a `for c in journalctl ...` line, and a second one would be a
    // second place a host without journalctl has to be told about.
    ...findBin('dmesg', 'SP_DMESG'),
    'SP_OOM_ST=no-tool',
    'SP_OOM_W="-"',
    'SP_OOM_D="this host has no readable kernel journal, no readable dmesg and no /var/log/kern.log, so whether the OOM killer has run cannot be established"',
    // Set the moment something that COULD have answered refuses. Without it a
    // host whose journal exists and is root-only, with no dmesg and no
    // kern.log, would fall through to `no-tool` — which reads as "there is
    // nothing here to ask" when the truth is "there is, and you may not".
    'SP_OOM_REF=0',
    // ONE LINE PER KILL, and the whole counting decision is this pattern.
    // `Killed process <pid> (<comm>)` is written once per process actually
    // reaped, by the global and the cgroup paths alike. The alternatives all
    // inflate: the kernel dumps one `[ pid ]` task-list row per process on the
    // machine before it chooses, so anything matching those counts the host's
    // process table rather than its kills.
    "SP_OOMX='Killed process [0-9]'",
    // The victim's name, off the same line, and it never leaves the host: only
    // how many DISTINCT names is emitted. A `comm` is a string a process chose
    // for itself — the same reason the failed-login probe carries counts and
    // not usernames.
    "SP_OOMN='s/.*Killed process [0-9][0-9]* (\\([^)]*\\)).*/\\1/p'",

    // ---- the kernel journal, the only source with a window ---------------
    //
    // `-k` is its OWN readability question and is probed separately rather
    // than inherited from the failed-login block's answer: the kernel log is
    // not the same set of records as sshd's, and an account in `adm` may read
    // one and not the other. `-n 0` opens the journal, prints nothing, and
    // exits non-zero when this account may not read it — without it the
    // counting pipelines below would report 0 for a refusal.
    'SP_OOMRUN=""',
    'if [ -n "$SP_JCTL" ]; then',
    '"$SP_JCTL" --no-pager -q -k -n 0 >/dev/null 2>&1 && SP_OOMRUN="$SP_JCTL"',
    ...ifSudo(
      'if [ -z "$SP_OOMRUN" ] && [ "$SP_SUDO" = 1 ]; then',
      'sudo -n "$SP_JCTL" --no-pager -q -k -n 0 >/dev/null 2>&1 && { SP_OOMRUN="sudo -n $SP_JCTL"; SP_OOM_W=root; }',
      'fi'
    ),
    '[ -z "$SP_OOMRUN" ] && SP_OOM_REF=1',
    'fi',
    'if [ -n "$SP_OOMRUN" ]; then',
    'sp_val oom-tool journal',
    `SP_OOMA="--no-pager -q -k --since -${OOM_WINDOW_HOURS}hours"`,
    // Taken from the substitution's OUTPUT rather than from whether the
    // pipeline succeeded, exactly as the failed-login counts are: `grep -c`
    // exits 1 when it counts none and still PRINTS `0`, and a probe that read
    // the exit status would turn a host with no OOM kills into a host that
    // could not be asked.
    `sp_val oom-count "$($SP_OOMRUN $SP_OOMA 2>/dev/null | grep -c -E "$SP_OOMX" || true)"`,
    `sp_val oom-procs "$($SP_OOMRUN $SP_OOMA 2>/dev/null | sed -n "$SP_OOMN" | sort -u | grep -c . || true)"`,
    `sp_val oom-window "the last ${OOM_WINDOW_HOURS} hours of the kernel journal"`,
    'SP_OOM_ST=ok',
    `SP_OOM_D="journalctl -k over the last ${OOM_WINDOW_HOURS} hours"`,
    'fi',

    // ---- dmesg, which is a buffer and not a window -----------------------
    'if [ "$SP_OOM_ST" != ok ] && [ -n "$SP_DMESG" ]; then',
    // `kernel.dmesg_restrict` is set on most modern distributions and the
    // refusal goes to STDERR with an exit status a pipeline would swallow.
    // Read the way lastb is read, for the same reason.
    'SP_ERR=$("$SP_DMESG" 2>&1 >/dev/null | head -n 3)',
    'SP_DRUN=""',
    '[ -z "$SP_ERR" ] && SP_DRUN="$SP_DMESG"',
    ...ifSudo(
      'if [ -n "$SP_ERR" ] && [ "$SP_SUDO" = 1 ]; then',
      'SP_E2=$(sudo -n "$SP_DMESG" 2>&1 >/dev/null | head -n 3)',
      'if [ -z "$SP_E2" ]; then SP_DRUN="sudo -n $SP_DMESG"; SP_OOM_W=root; fi',
      'fi'
    ),
    'if [ -n "$SP_DRUN" ]; then',
    'sp_val oom-tool dmesg',
    `sp_val oom-count "$($SP_DRUN 2>/dev/null | grep -c -E "$SP_OOMX" || true)"`,
    `sp_val oom-procs "$($SP_DRUN 2>/dev/null | sed -n "$SP_OOMN" | sort -u | grep -c . || true)"`,
    'sp_val oom-window "the kernel ring buffer, which reaches back only as far as it has not been overwritten"',
    // PARTIAL, not ok, and this is the line that keeps the item honest. The
    // buffer is not a period of time: on a chatty host it holds minutes. A
    // count above zero here is real; a zero is not a statement about a day.
    'SP_OOM_ST=partial',
    'SP_OOM_D="dmesg. The ring buffer is not a time window - it holds as much as it holds, so a zero read from it is not a report of no OOM kills in the last day"',
    'else',
    'SP_OOM_ST=denied',
    'SP_OOM_REF=1',
    'SP_OOM_D="dmesg is installed and the kernel refused to let this account read the ring buffer, which is what kernel.dmesg_restrict does. This is NOT a report of no OOM kills."',
    'fi',
    'fi',

    // ---- /var/log/kern.log, for a host with neither ----------------------
    //
    // Traversal before existence, as everywhere else in this file: a
    // `chmod 700 /var/log` makes `[ -f /var/log/kern.log ]` false, and that is
    // "cannot see", not "the kernel log is not written here".
    'if [ "$SP_OOM_ST" != ok ] && [ "$SP_OOM_ST" != partial ]; then',
    'if [ -d /var/log ] && [ ! -x /var/log ]; then',
    'SP_OOM_ST=denied',
    'SP_OOM_REF=1',
    'SP_OOM_D="/var/log exists on this host and this account may not enter it, so the kernel log inside it was never opened"',
    'elif [ -f /var/log/kern.log ]; then',
    // The error text with the count thrown away, so a permission problem is
    // told apart from a file that genuinely holds no kills.
    'SP_KERR=$(grep -c -E "$SP_OOMX" /var/log/kern.log 2>&1 >/dev/null | head -n 1)',
    'SP_KRUN=""',
    // The escalation PREFIX, and it is a variable set only inside `ifSudo`
    // rather than a word this branch spells out. A build without sudo must
    // contain no `sudo` anywhere at all — tests/posture.test.ts reads the
    // shipped command as a document and asserts exactly that, which is the
    // whole reason sudo is omitted at build time instead of guarded at
    // runtime. A `[ "$SP_KRUN" = sudo ]` here put the word back.
    'SP_KCAT=""',
    '[ -z "$SP_KERR" ] && SP_KRUN=1',
    ...ifSudo(
      'if [ -n "$SP_KERR" ] && [ "$SP_SUDO" = 1 ]; then',
      'SP_KE2=$(sudo -n grep -c -E "$SP_OOMX" /var/log/kern.log 2>&1 >/dev/null | head -n 1)',
      'if [ -z "$SP_KE2" ]; then SP_KRUN=1; SP_KCAT="sudo -n"; SP_OOM_W=root; fi',
      'fi'
    ),
    'if [ -n "$SP_KRUN" ]; then',
    'sp_val oom-tool kern-log',
    `sp_val oom-count "$($SP_KCAT grep -c -E "$SP_OOMX" /var/log/kern.log 2>/dev/null || true)"`,
    `sp_val oom-procs "$($SP_KCAT sed -n "$SP_OOMN" /var/log/kern.log 2>/dev/null | sort -u | grep -c . || true)"`,
    'sp_val oom-window "the current /var/log/kern.log, which logrotate turns over on a schedule this side cannot see"',
    'SP_OOM_ST=partial',
    'SP_OOM_D="/var/log/kern.log. Rotated on a schedule this side cannot see, so a zero read from it is not a report of no OOM kills in the last day"',
    'else',
    'SP_OOM_ST=denied',
    'SP_OOM_REF=1',
    'SP_OOM_D="/var/log/kern.log exists and reading it needs root on this host"',
    'fi',
    'fi',
    'fi',

    // "There is nothing here to ask" and "there is, and you may not" are
    // different answers with different fixes, and only one of them is a gap a
    // person can close. The whole point of SP_OOM_REF.
    'if [ "$SP_OOM_ST" = no-tool ] && [ "$SP_OOM_REF" = 1 ]; then',
    'SP_OOM_ST=denied',
    'SP_OOM_D="a kernel log is present on this host and this account may not read it. This is NOT a report of no OOM kills."',
    'fi',
    'sp_note oom-kills "$SP_OOM_ST" "$SP_OOM_W" "$SP_OOM_D"',

    // =====================================================================
    // CERTIFICATES
    // =====================================================================
    //
    // A BOUNDED search, and the bounds are the compose module's four —
    // named roots, `-maxdepth`, `-xdev` and a result cap — for the reason
    // buildComposeSearchCommand gives: an unbounded walk of /etc on a
    // production host is its own outage. `certSearchBound()` hands all four to
    // the panel so they are read rather than trusted.
    //
    // WHAT LEAVES THE HOST is the base64 between a BEGIN CERTIFICATE and an
    // END CERTIFICATE line, and NOTHING else. That is a property of the
    // extractor rather than of the skip list: pointed at `privkey.pem` it
    // emits nothing at all, so a private key cannot be transmitted even if a
    // name slips past CERT_SKIPPED. The FIRST block only — `fullchain.pem`
    // holds the leaf first and the intermediates after it, and an
    // intermediate's expiry is the CA's problem rather than the operator's.
    //
    // The certificate is DATED IN TYPESCRIPT and not by `openssl x509` here.
    // See the block comment on CERT_SEARCH_ROOTS: openssl is not universally
    // present, and a host with certificates and no openssl reporting NO
    // CERTIFICATES is the half-probe this item was deferred rather than ship.
    'SP_CERT_ST=absent',
    'SP_CERT_W="-"',
    'SP_CERT_D="none of the certificate directories ShellPilot looks in is present on this host"',
    'SP_CERT_ROOTS=""',
    // The escalation prefix, empty unless a root needed root. /etc/letsencrypt
    // is 0700 root on Debian, which makes this the COMMON case rather than an
    // edge one — and it is a variable rather than a spelled-out word so a build
    // without sudo contains none.
    'SP_CERT_SU=""',
    'SP_CERT_MISS=0',
    'SP_CERT_ANY=0',
    'SP_CERT_LIST=""',
    ...CERT_SEARCH_ROOTS.flatMap((r) => {
      // Literals, so their parents are literals too and no dirname runs on the
      // host. Only a parent that is not /etc is worth testing: a /etc nobody
      // can enter is a host on which nothing in this file works.
      const parent = r.slice(0, r.lastIndexOf('/'))
      return [
        `if [ -d ${r} ] && [ -x ${r} ]; then`,
        `SP_CERT_ANY=1; SP_CERT_ROOTS="$SP_CERT_ROOTS ${r}"`,
        ...ifSudo(
          `elif [ "$SP_SUDO" = 1 ] && sudo -n test -x ${r}; then`,
          `SP_CERT_ANY=1; SP_CERT_ROOTS="$SP_CERT_ROOTS ${r}"; SP_CERT_SU="sudo -n"; SP_CERT_W=root`
        ),
        `elif [ -d ${r} ]; then`,
        'SP_CERT_ANY=1; SP_CERT_MISS=$((SP_CERT_MISS+1))',
        // TRAVERSAL BEFORE EXISTENCE, and here it is the whole case rather
        // than a corner: `[ -d /etc/letsencrypt/live ]` is FALSE on a host
        // whose /etc/letsencrypt is 0700, so without this branch the single
        // most important root on the box reads as "not present" — which is
        // exactly "a directory that could not be read is not a directory with
        // no certificates", got wrong.
        ...(parent === '/etc'
          ? []
          : [
              `elif [ -d ${parent} ] && [ ! -x ${parent} ]; then`,
              'SP_CERT_ANY=1; SP_CERT_MISS=$((SP_CERT_MISS+1))'
            ]),
        'fi'
      ]
    }),
    'if [ -n "$SP_CERT_ROOTS" ]; then',
    // `-maxdepth` immediately after the roots, because GNU find warns when a
    // global option follows a test and a warning line in this block is a path
    // the loop below would try to open. stderr discarded and `|| true` for
    // compose.ts's reasons: find exits non-zero when a root vanishes between
    // the test above and here, and `head` closing the pipe makes it non-zero
    // again.
    `SP_CERT_LIST=$($SP_CERT_SU find $SP_CERT_ROOTS -xdev -maxdepth ${CERT_SEARCH_MAX_DEPTH} -type f \\( ${CERT_NAMES.map((n) => `-name '${n}'`).join(' -o ')} \\) ${CERT_SKIPPED.map((n) => `! -name ${n}`).join(' ')} -print 2>/dev/null | head -n ${CERT_SEARCH_MAX_FILES} || true)`,
    'fi',
    'if [ -n "$SP_CERT_LIST" ]; then',
    // `while read` over a pipe rather than `for f in $SP_CERT_LIST`, so a
    // certificate under a path with a space in it is read rather than split
    // into two paths that do not exist. Nothing is accumulated in the
    // subshell — every record is printed as it is read — so the pipeline
    // costing a subshell costs nothing.
    'printf \'%s\\n\' "$SP_CERT_LIST" | while IFS= read -r f; do',
    '[ -n "$f" ] || continue',
    // awk rather than sed: `sed -n \'/a/,/b/{...q...}\' is accepted by GNU sed
    // and is exactly the kind of block BSD sed has historically been fussy
    // about, and this has to run on whatever POSIX userland the host has.
    `SP_B64=$($SP_CERT_SU awk '/-----BEGIN CERTIFICATE-----/{f=1;next} /-----END CERTIFICATE-----/{if(f)exit} f{print}' "$f" 2>/dev/null | tr -d '\\n\\r')`,
    // TWO SENTINELS, not one, because the causes have different fixes. `.` is
    // a file that opened and holds no certificate — a key, a CSR, a README
    // somebody named .pem. Empty becomes `-`: the file was found and could not
    // be opened, which is NOT a file with no certificate in it.
    'if [ -n "$SP_B64" ]; then sp_cert "$SP_B64" "$f"',
    `elif $SP_CERT_SU head -c 1 "$f" >/dev/null 2>&1; then sp_cert . "$f"`,
    'else sp_cert "" "$f"; fi',
    'done',
    'fi',
    // Decided ONCE, at the end, from what was counted rather than inside
    // whichever branch ran last — the fix access.ts had to make after a
    // skipped file left a source reading `ok`.
    'if [ "$SP_CERT_ANY" = 0 ]; then',
    'SP_CERT_ST=absent',
    'elif [ -z "$SP_CERT_ROOTS" ]; then',
    'SP_CERT_ST=denied',
    'SP_CERT_D="every certificate directory present on this host refused to be entered. This is NOT a report of no certificates."',
    'elif [ "$SP_CERT_MISS" -gt 0 ]; then',
    'SP_CERT_ST=partial',
    'SP_CERT_D="some certificate directories were read and some refused to be entered. A directory that could not be read is not a directory with no certificates."',
    'else',
    'SP_CERT_ST=ok',
    'SP_CERT_D="read every certificate directory that is present on this host"',
    'fi',
    'sp_val cert-refused "$SP_CERT_MISS"',
    // Emitted on every run including the empty one, so the parser can tell "the
    // search ran and found nothing" from "this block never ran" — the same
    // distinction fw-backend-status is deliberately NOT counted for.
    'sp_val cert-searched "$SP_CERT_ANY"',
    'sp_note certificates "$SP_CERT_ST" "$SP_CERT_W" "$SP_CERT_D"',

    // Printed once, at the end, from a variable nothing read out of a file ever
    // touched. This is the cron.ts discipline and it is the reason a
    // PermitRootLogin value cannot forge a firewall status.
    `printf '%s\\n%s' '${POSTURE_STATUS_MARKER}' "$SP_STATUS"`
  ].join('\n')
}

/** The shipped command, built once. */
export const POSTURE_COMMAND = buildPostureCommand()

// ---- Parsing --------------------------------------------------------------

/** The keys the collector may emit. Anything else is discarded rather than
 *  stored under a name the rest of the app would then have to distrust. */
const VALUE_KEYS = [
  'fw-tool',
  'fw-active',
  'fw-policy-in',
  'fw-policy-out',
  'fw-rules',
  'fw-deny',
  'fw-zone',
  'fw-zones',
  'fw-backend',
  'fw-backend-rules',
  'fw-backend-policy',
  'fw-backend-status',
  'fw-rule-collection',
  'fw-rule-lines-front',
  'fw-rule-lines-backend',
  'mac-system',
  'mac-mode',
  'mac-enabled',
  'mac-boot',
  'mac-profiles',
  'mac-complain',
  'sshd-src',
  'sshd-match',
  'fail-tool',
  'fail-count',
  'fail-users',
  'fail-window',
  'oom-tool',
  'oom-count',
  'oom-procs',
  'oom-window',
  'cert-refused',
  'cert-searched',
] as const
type ValueKey = (typeof VALUE_KEYS)[number]

// Control characters, zero-width marks and the bidi overrides, stripped from
// every free-text field the host wrote.
//
// The collector already deletes control characters ON the host, which is what
// makes the output format unforgeable. This is a different job and it CANNOT
// happen there: `tr -d '\000-\037\177'` operates on bytes and U+202E is three
// of them. A bidi override reorders what a human sees without changing what a
// parser reads — the wrong way round for anything a person is going to act on,
// and worse here than anywhere else in the app, because the thing a person acts
// on is a security finding.
const UNSAFE_FREE =
  // eslint-disable-next-line no-control-regex -- matching them is the point
  /[\u0000-\u001f\u007f-\u009f\u200b-\u200f\u202a-\u202e\u2066-\u2069\u2028\u2029]/g

/** Free text as it is safe to hand on: no control characters, no bidi, runs of
 *  whitespace collapsed, and empty normalised to null rather than ''. */
function freeText(value: string | null | undefined): string | null {
  if (value === null || value === undefined) return null
  const flat = value.replace(UNSAFE_FREE, ' ').replace(/\s+/g, ' ').trim()
  return flat === '' ? null : flat
}

/** A count, or null. Never `0` as a stand-in for "could not read". */
function parseCount(raw: string | undefined): number | null {
  if (raw === undefined) return null
  const t = raw.trim()
  if (!/^\d{1,9}$/.test(t)) return null
  return Number(t)
}

/** One of a fixed set, lowercased, or null. A value outside the set did not
 *  come from a tool this build knows, so it is dropped rather than displayed. */
function oneOf<T extends string>(raw: string | undefined, allowed: readonly T[]): T | null {
  if (raw === undefined) return null
  const t = raw.trim().toLowerCase()
  return (allowed as readonly string[]).includes(t) ? (t as T) : null
}

/**
 * The on/off words the two front ends use.
 *
 * ufw says `active`/`inactive` from `status` and `yes`/`no` from ufw.conf;
 * firewalld says `running`/`not running`. Anything else — including the empty
 * string — is null, which is NOT false.
 */
function parseActive(raw: string | undefined): boolean | null {
  if (raw === undefined) return null
  const t = raw.trim().toLowerCase()
  if (t === 'active' || t === 'yes' || t === 'running' || t === 'enabled') return true
  if (t === 'inactive' || t === 'no' || t === 'not running' || t === 'disabled') return false
  return null
}

// ---- Dating a certificate, from its DER, here --------------------------------
//
// A hundred lines instead of `openssl x509 -enddate`, for access.ts's reason:
// the tool is not universally present and a host that has certificates and no
// openssl would report having none.
//
// The rule every branch obeys: RETURN A FAILURE ON ANY INCONSISTENCY, and
// never read past the buffer. A certificate is a file the host controls, and
// the one thing that must never come out of here is a date this build was not
// certain of.

interface Tlv {
  tag: number
  /** First byte of the value. */
  start: number
  /** One past the last byte of the value, which MAY exceed the buffer — that
   *  is how truncation is detected rather than crashed on. */
  end: number
}

/**
 * One DER tag-length-value header at `at`.
 *
 * Refuses the two things a certificate's spine never contains and an attacker
 * might: a multi-byte tag, and BER's indefinite length. Refuses a long-form
 * length of more than four bytes because nothing in a certificate needs one and
 * accepting it is how a length becomes an unbounded integer.
 */
function readTlv(der: Uint8Array, at: number): Tlv | null {
  if (at < 0 || at + 2 > der.length) return null
  const tag = der[at]
  if ((tag & 0x1f) === 0x1f) return null
  let i = at + 1
  let len = der[i++]
  if ((len & 0x80) !== 0) {
    const n = len & 0x7f
    if (n === 0 || n > 4 || i + n > der.length) return null
    len = 0
    for (let j = 0; j < n; j++) len = len * 256 + der[i++]
  }
  return { tag, start: i, end: i + len }
}

/** ASCII, one byte per character, because every field read here is ASCII by
 *  definition and a multi-byte decode would invent characters. */
const asciiOf = (b: Uint8Array): string => Array.from(b, (c) => String.fromCharCode(c)).join('')

/**
 * An ASN.1 UTCTime or GeneralizedTime, as RFC 5280 requires them to be written.
 *
 * §4.1.2.5 requires seconds and requires Z, so a value without them is a
 * certificate this build will not date rather than one it will guess at.
 * §4.1.2.5.1 is the two-digit-year rule: 50 and above is 19YY, below it 20YY.
 */
function asn1Time(tag: number, body: Uint8Array): number | null {
  const s = asciiOf(body)
  let year: number
  let m: RegExpExecArray | null
  if (tag === 0x17) {
    m = /^(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z$/.exec(s)
    if (m === null) return null
    const yy = Number(m[1])
    year = yy >= 50 ? 1900 + yy : 2000 + yy
  } else if (tag === 0x18) {
    m = /^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z$/.exec(s)
    if (m === null) return null
    year = Number(m[1])
  } else {
    return null
  }
  const mo = Number(m[2])
  const d = Number(m[3])
  const h = Number(m[4])
  const mi = Number(m[5])
  const se = Number(m[6])
  // Checked rather than left to Date.UTC, which rolls a month of 13 into the
  // next January instead of refusing it.
  if (mo < 1 || mo > 12 || d < 1 || d > 31 || h > 23 || mi > 59 || se > 60) return null
  const t = Date.UTC(year, mo - 1, d, h, mi, Math.min(se, 59))
  return Number.isFinite(t) ? t : null
}

export type CertNotAfter =
  | { ok: true; notAfter: number }
  | { ok: false; problem: 'truncated' | 'unparseable' }

/**
 * `notAfter`, walked out of the certificate's DER.
 *
 *   Certificate ::= SEQUENCE {
 *     tbsCertificate ::= SEQUENCE {
 *       [0] version           OPTIONAL and EXPLICIT, absent on a v1 certificate
 *       serialNumber          INTEGER
 *       signature             SEQUENCE
 *       issuer                SEQUENCE
 *       validity              SEQUENCE { notBefore, notAfter }
 *       ...
 *
 * Everything before `validity` is skipped by length rather than decoded: this
 * has no business knowing what an issuer DN contains, and the less of a
 * host-controlled file it interprets the better.
 *
 * TRUNCATED VERSUS UNPARSEABLE is decided from the outer SEQUENCE's own
 * declared length. The collector caps how much base64 it sends, so a
 * certificate with a very long issuer really can arrive with its validity cut
 * off — and "we did not transmit enough of this" is a different sentence from
 * "this is not a certificate", with a different fix.
 */
export function certificateNotAfter(der: Uint8Array): CertNotAfter {
  const cert = readTlv(der, 0)
  if (cert === null || cert.tag !== 0x30) return { ok: false, problem: 'unparseable' }
  // Everything below fails one way when the buffer simply ran out and another
  // when what is here is not a certificate.
  const fail = (): CertNotAfter => ({
    ok: false,
    problem: cert.end > der.length ? 'truncated' : 'unparseable'
  })

  const tbs = readTlv(der, cert.start)
  if (tbs === null || tbs.tag !== 0x30) return fail()

  let at = tbs.start
  let f = readTlv(der, at)
  if (f === null) return fail()
  // [0] EXPLICIT version. Absent on a v1 certificate, which is rare and legal.
  if (f.tag === 0xa0) {
    at = f.end
    f = readTlv(der, at)
    if (f === null) return fail()
  }
  if (f.tag !== 0x02) return fail() // serialNumber
  at = f.end
  f = readTlv(der, at)
  if (f === null || f.tag !== 0x30) return fail() // signature AlgorithmIdentifier
  at = f.end
  f = readTlv(der, at)
  if (f === null || f.tag !== 0x30) return fail() // issuer Name
  at = f.end
  const validity = readTlv(der, at)
  if (validity === null || validity.tag !== 0x30) return fail()

  const notBefore = readTlv(der, validity.start)
  if (notBefore === null) return fail()
  const notAfter = readTlv(der, notBefore.end)
  if (notAfter === null) return fail()
  // The bytes have to actually BE here. Without this the subarray below would
  // silently shorten and `asn1Time` would refuse a date that is merely absent —
  // reporting a cut certificate as unparseable rather than as truncated.
  if (notAfter.end > der.length) return { ok: false, problem: 'truncated' }

  const t = asn1Time(notAfter.tag, der.subarray(notAfter.start, notAfter.end))
  return t === null ? { ok: false, problem: 'unparseable' } : { ok: true, notAfter: t }
}

/**
 * One `C` record, turned into a reading.
 *
 * The two sentinels are the collector's, and they are two words rather than one
 * because the causes have different fixes: `-` is a file the search found and
 * could not open, and `.` is a file that opened and holds no certificate at
 * all — a private key, a CSR, a README somebody named `.pem`.
 */
function readCertificate(body: string, rawPath: string, now: number): CertificateReading {
  const path = freeText(rawPath) ?? ''
  const gap = (problem: CertReadProblem): CertificateReading => ({
    path,
    notAfter: null,
    daysRemaining: null,
    problem
  })
  if (body === '-' || body === '') return gap('unreadable')
  if (body === '.') return gap('not-a-certificate')
  const der = decodeBase64(body)
  if (der === null || der.length === 0) return gap('unparseable')
  const r = certificateNotAfter(der)
  if (!r.ok) return gap(r.problem)
  return {
    path,
    notAfter: r.notAfter,
    // Floored, so "12 days" means at least twelve whole days and an expiry
    // three days ago is -3 rather than -2.something rounded towards zero.
    daysRemaining: Math.floor((r.notAfter - now) / 86_400_000),
    problem: null
  }
}

/**
 * The fewest days remaining across every certificate that PARSED.
 *
 * Null, not Infinity and not a large number, when nothing parsed. A host with
 * no certificates is not a host whose certificates are fine, and a host whose
 * certificate directory was refused is neither — see the honesty rules on
 * CertificateInventory.
 */
export function soonestCertificateExpiry(inv: CertificateInventory | null): number | null {
  if (inv === null) return null
  let soonest: number | null = null
  for (const c of inv.certificates) {
    if (c.daysRemaining === null) continue
    if (soonest === null || c.daysRemaining < soonest) soonest = c.daysRemaining
  }
  return soonest
}

function parseStatusLine(line: string): PostureSourceReport | null {
  const [id, status, readBy, ...rest] = line.trim().split(/\s+/)
  if (!POSTURE_SOURCE_IDS.includes(id as PostureSourceId)) return null
  // The collector's own words, and they came off the host: a detail can carry a
  // filename or a tool's error message. Same treatment as any other free text.
  const detail = freeText(rest.join(' ').replace(/^"|"$/g, '')) ?? ''
  return {
    id: id as PostureSourceId,
    label: POSTURE_SOURCE_LABEL[id as PostureSourceId],
    // An unrecognised status becomes `unknown` rather than being passed
    // through: everything downstream switches on this, and a value outside the
    // union renders as nothing at all — which for a security panel means a
    // blank cell where a warning belonged.
    status: POSTURE_STATUSES.includes(status as PostureStatus) ? (status as PostureStatus) : 'unknown',
    ...(readBy === 'root' ? { usedSudo: true } : {}),
    ...(detail === '' || detail === '-' ? {} : { detail })
  }
}

/**
 * Judge one directive against the baseline.
 *
 * THE RULE THIS FUNCTION EXISTS TO ENFORCE: a null value is never `hardened`
 * and never `neutral`. Every path that cannot produce a value produces
 * `unknown`, so "this host could not be checked" is structurally incapable of
 * rendering as "this host is fine". A directive read from FILES and simply not
 * present is also null — sshd's compiled-in default applies and this build
 * cannot see which OpenSSH version is deciding it — which is why `sshd -T` is
 * preferred and why `effective` is carried on the reading.
 */
export function judgeSshd(
  directive: SshdDirective,
  raw: string | null,
  opts: { effective: boolean; ambiguous?: boolean; sourceStatus: PostureStatus }
): SshdReading {
  const base = SSHD_BASELINE[directive]
  const unknown = (detail: string): SshdReading => ({
    directive,
    value: null,
    verdict: 'unknown',
    detail,
    ...(opts.ambiguous ? { ambiguous: true } : {})
  })

  if (opts.ambiguous) {
    return unknown(
      'the files that were read set this directive more than once, with different values. ShellPilot will not guess which one sshd resolves to; run the check with passwordless sudo so `sshd -T` can answer, or reconcile the drop-ins.'
    )
  }
  if (raw === null) {
    if (opts.sourceStatus === 'denied' || opts.sourceStatus === 'absent') {
      return unknown('sshd’s configuration could not be read on this host, so this is unchecked — not passing.')
    }
    if (opts.effective) {
      return unknown('sshd reported its effective configuration and this directive was not in it, which this build cannot explain.')
    }
    return unknown(
      'not set in the files that were read, so sshd’s compiled-in default applies — and which default that is depends on the OpenSSH version, which reading files cannot see. Passwordless sudo lets `sshd -T` answer exactly.'
    )
  }

  const value = freeText(raw)
  if (value === null) return unknown('the host reported an empty value for this directive.')

  // Numeric directive.
  if (directive === 'MaxAuthTries') {
    const n = parseCount(value)
    if (n === null) return unknown('the host reported a value for MaxAuthTries that is not a number.')
    return {
      directive,
      value: String(n),
      verdict: n > MAX_AUTH_TRIES_WEAK ? 'weak' : n <= 3 ? 'hardened' : 'neutral',
      detail:
        n > MAX_AUTH_TRIES_WEAK
          ? `one connection may make ${n} authentication attempts before it is dropped, which is more than OpenSSH's own default of ${MAX_AUTH_TRIES_WEAK} and stops meaningfully limiting a guessing attempt.`
          : `one connection may make ${n} authentication attempts before it is dropped.`
    }
  }

  // Free-text list directives. Their presence is the finding; their contents
  // are usernames, which are the host's own text and are shown as written.
  if (directive === 'AllowUsers' || directive === 'AllowGroups') {
    const entries = value.split(/\s+/).filter((s) => s !== '')
    return {
      directive,
      value,
      verdict: 'hardened',
      detail: `${base.why}. ${entries.length} ${entries.length === 1 ? 'entry' : 'entries'} listed. Anyone not covered cannot log in at all, which is a stronger restriction than any of the other directives here.`
    }
  }

  const allowed = base.values
  const lower = value.toLowerCase()
  if (allowed !== null && !allowed.includes(lower)) {
    // The forgery guard. A host that writes `PermitRootLogin
    // yes===SHELLPILOT-POSTURE===` — or anything else outside sshd's own
    // vocabulary — gets `unknown`, not a value the panel would render.
    return unknown(
      `the host reported a value for ${directive} that is not one sshd accepts, so nothing is concluded from it.`
    )
  }
  if (base.hardened.includes(lower)) {
    return { directive, value: lower, verdict: 'hardened', detail: `${directive} is ${lower}.` }
  }
  if (base.weak.includes(lower)) {
    return { directive, value: lower, verdict: 'weak', detail: base.why }
  }
  return { directive, value: lower, verdict: 'neutral', detail: `${directive} is ${lower}.` }
}

/**
 * Turn one collection into a posture, with every null explained.
 *
 * Two things happen here that the collector deliberately does not do, both
 * borrowed from parseHostFacts because the reasoning transfers exactly:
 *
 *  - A source the collector called `ok` is DOWNGRADED to `unknown` when the
 *    value it was reporting on is missing or unparseable. The shell says which
 *    probe ran; only this side can say whether its answer survived.
 *  - Every judgement — the sshd verdicts especially — is computed here rather
 *    than on the host, from allow-listed values, so nothing the host writes can
 *    become a verdict.
 */
export function parsePosture(output: string, now = Date.now()): HostPosture {
  const lines = output.split('\n')
  // The ONLY structural token, matched by WHOLE-LINE equality. A value line
  // always begins `V ` or `D ` and never contains a newline, so no value can
  // ever equal this — which is what stops a `PermitRootLogin` value from ending
  // the value region early and shifting every status after it.
  const markerAt = lines.findIndex((l) => l.replace(/\r$/, '') === POSTURE_STATUS_MARKER)

  const values = new Map<ValueKey, string>()
  /** Every value seen for one directive, in the order the collector emitted
   *  them, so a disagreement can be reported rather than arbitrated. */
  const directives = new Map<SshdDirective, string[]>()
  /** One entry per file the bounded search found, in the order it found them. */
  const certRecords: { body: string; path: string }[] = []
  /** Firewall rule lines, per reading, in the order the host printed them. */
  const ruleRecords = new Map<FirewallRuleOrigin, string[]>()

  for (const raw of lines.slice(0, markerAt === -1 ? lines.length : markerAt)) {
    const line = raw.replace(/\r$/, '')
    if (line.startsWith('V ')) {
      const rest = line.slice(2)
      const sp = rest.indexOf(' ')
      if (sp === -1) continue
      const key = rest.slice(0, sp)
      if (!(VALUE_KEYS as readonly string[]).includes(key)) continue
      // Last wins, matching the collector's own last-definition-wins reads.
      values.set(key as ValueKey, rest.slice(sp + 1))
      continue
    }
    if (line.startsWith('R ')) {
      // `R <origin> <text>`. The origin is a literal the collector wrote and is
      // allow-listed here, so a record with anything else in that position was
      // not written by this build and is dropped rather than filed under a
      // name the panel would then render.
      const rest = line.slice(2)
      const sp = rest.indexOf(' ')
      if (sp === -1) continue
      const origin = rest.slice(0, sp)
      if (!(FIREWALL_RULE_ORIGINS as readonly string[]).includes(origin)) continue
      // Capped on the way in as well as on the host, for DIRECTIVE_CAP's
      // reason: the host's `head -n` is what should bound this, and a host that
      // ignored it must not be able to make the panel draw ten thousand rules.
      const seen = ruleRecords.get(origin as FirewallRuleOrigin) ?? []
      if (seen.length < FIREWALL_RULE_MAX_LINES) {
        // freeText again, on top of the host's own scrub: `tr -d` works on
        // BYTES and U+202E is three of them. A bidi override in a rule reorders
        // what a person sees without changing what the parser read, which is
        // the wrong way round for an address somebody is about to act on.
        const text = freeText(rest.slice(sp + 1))
        if (text !== null) seen.push(text.slice(0, FIREWALL_RULE_LINE_CAP))
      }
      ruleRecords.set(origin as FirewallRuleOrigin, seen)
      continue
    }
    if (line.startsWith('C ')) {
      // `C <base64> <path>`. The path is the REMAINDER, so a path with a space
      // in it survives; the body has no spaces by construction.
      const rest = line.slice(2)
      const sp = rest.indexOf(' ')
      if (sp === -1) continue
      // Capped on the way in as well as on the host, for DIRECTIVE_CAP's
      // reason: the host's `head -n` is what should bound this, and a host that
      // ignored it must not be able to make the parser walk ten thousand
      // certificates.
      if (certRecords.length < CERT_SEARCH_MAX_FILES) {
        certRecords.push({ body: rest.slice(0, sp), path: rest.slice(sp + 1) })
      }
      continue
    }
    if (!line.startsWith('D ')) continue
    // `D PermitRootLogin yes` or `D PermitRootLogin=yes`. The name is
    // allow-listed against the eight, so a config line for a directive nobody
    // asked about — or a forged one — is dropped rather than stored.
    const body = line.slice(2).trim()
    const m = /^([A-Za-z0-9]+)[\s=]+(.*)$/.exec(body)
    if (!m) continue
    const directive = SSHD_KEY_TO_DIRECTIVE.get(m[1].toLowerCase())
    if (!directive) continue
    const seen = directives.get(directive) ?? []
    seen.push(m[2].trim())
    directives.set(directive, seen)
  }

  const reported = new Map<PostureSourceId, PostureSourceReport>()
  if (markerAt !== -1) {
    for (const line of lines.slice(markerAt + 1)) {
      if (line.trim() === '') continue
      const s = parseStatusLine(line)
      if (s) reported.set(s.id, s)
    }
  }

  const source = (id: PostureSourceId): PostureSourceReport =>
    reported.get(id) ?? {
      id,
      label: POSTURE_SOURCE_LABEL[id],
      status: 'unknown' as const,
      detail:
        markerAt === -1
          ? 'the collector never returned its status block, so nothing here was confirmed'
          : 'the collector did not report on this source'
    }

  // ---- firewall ----------------------------------------------------------
  const fwTool = oneOf(values.get('fw-tool'), FIREWALL_TOOLS)
  const backendTool = oneOf(values.get('fw-backend'), FIREWALL_BACKENDS)
  const backendStatus = oneOf(values.get('fw-backend-status'), POSTURE_STATUSES) ?? 'unknown'
  const zonesRaw = freeText(values.get('fw-zones'))
  const fwActive = parseActive(values.get('fw-active'))
  const fwRules = parseCount(values.get('fw-rules'))
  const fwBackendRules = parseCount(values.get('fw-backend-rules'))
  // NULL WHEN NOTHING WAS READ, and this is not a tidiness point.
  //
  // A `FirewallState` with a tool of null, a rules count of null and an active
  // flag of null is the Postgres failure this codebase has already had once,
  // wearing a different hat: a row per object with every column empty and no
  // error attached, which renders as a real reading of a very quiet host. The
  // reason lives on the source report; the state object exists only when
  // something was actually established, so a renderer cannot accidentally show
  // an empty firewall row instead of the sentence saying why there is none.
  //
  // `fw-backend-status` is deliberately NOT counted as content: the collector
  // emits it on every run, including the `unsupported` one, so counting it
  // would make this condition true for every host.
  // ---- the rule lines — item 31 ------------------------------------------
  //
  // A listing exists for a reading ONLY when that reading answered, which the
  // collector says by emitting its `fw-rule-lines-*` count — zero included.
  // Without the count there is no listing at all, so "the ruleset was refused"
  // can never arrive as "the ruleset is empty".
  const ruleCommand: Record<FirewallRuleOrigin, string> = {
    front: fwTool === 'firewalld' ? 'firewall-cmd --list-all' : 'ufw status verbose',
    backend: backendTool === 'iptables' ? 'iptables -S' : 'nft list ruleset'
  }
  const rulesRequested = values.get('fw-rule-collection')?.trim() === 'on'
  const ruleLines: FirewallRuleListing[] = []
  for (const origin of FIREWALL_RULE_ORIGINS) {
    const matched = parseCount(values.get(`fw-rule-lines-${origin}` as ValueKey))
    if (matched === null) continue
    const lines = ruleRecords.get(origin) ?? []
    ruleLines.push({
      from: origin,
      command: ruleCommand[origin],
      lines,
      matched,
      // A host that matched more than it sent has been cut. Stated here so no
      // renderer has to derive it, and so a listing whose count went missing
      // does not silently claim to be complete.
      truncated: matched > lines.length,
      bound: { maxLines: FIREWALL_RULE_MAX_LINES, maxChars: FIREWALL_RULE_LINE_CAP }
    })
  }

  const firewall: FirewallState | null =
    fwTool === null && backendTool === null && fwActive === null && fwRules === null && fwBackendRules === null
      ? null
      : {
          tool: fwTool ?? backendTool,
          active: fwActive,
          policyIn: oneOf(values.get('fw-policy-in'), FIREWALL_POLICIES),
          policyOut: oneOf(values.get('fw-policy-out'), FIREWALL_POLICIES),
          rules: fwRules,
          denyRules: parseCount(values.get('fw-deny')),
          zone: freeText(values.get('fw-zone')),
          zones: zonesRaw === null ? [] : zonesRaw.split(',').map((z) => z.trim()).filter((z) => z !== ''),
          backend: {
            tool: backendTool,
            rules: fwBackendRules,
            policyIn: oneOf(values.get('fw-backend-policy'), FIREWALL_POLICIES),
            status: backendStatus
          },
          rulesRequested,
          ruleLines
        }

  // ---- SELinux / AppArmor ------------------------------------------------
  const macSystem = oneOf(values.get('mac-system'), MAC_SYSTEMS)
  const mandatoryAccess: MandatoryAccess | null =
    macSystem === null
      ? null
      : {
          system: macSystem,
          enabled: parseActive(values.get('mac-enabled')),
          mode: oneOf(values.get('mac-mode'), MAC_MODES),
          bootMode: oneOf(values.get('mac-boot'), MAC_MODES),
          profiles: parseCount(values.get('mac-profiles')),
          complain: parseCount(values.get('mac-complain'))
        }

  // ---- sshd --------------------------------------------------------------
  const sshdSrc = values.get('sshd-src')?.trim()
  const sshdStatus = source('sshd-hardening').status
  const effective = sshdSrc === 'effective'
  const sshd: SshdHardening | null =
    sshdSrc !== 'effective' && sshdSrc !== 'files'
      ? // No source at all means nothing was read. Null rather than a set of
        // eight `unknown` readings, so the panel shows one honest sentence
        // instead of eight rows that look like a checklist that ran.
        null
      : {
          effective,
          matchBlocks: parseCount(values.get('sshd-match')),
          readings: SSHD_DIRECTIVES.map((d) => {
            const seen = directives.get(d) ?? []
            // Two different values from two files sshd resolves by a precedence
            // this build will not guess at. Reported as ambiguous, which is the
            // truth, rather than picked.
            const distinct = [...new Set(seen.map((v) => v.trim().toLowerCase()))]
            return judgeSshd(d, seen.length === 0 ? null : seen[0], {
              effective,
              ambiguous: distinct.length > 1,
              sourceStatus: sshdStatus
            })
          })
        }

  // ---- failed logins -----------------------------------------------------
  const failTool = oneOf(values.get('fail-tool'), FAILED_LOGIN_TOOLS)
  const failedLogins: FailedLoginSummary | null =
    failTool === null
      ? null
      : {
          tool: failTool,
          count: parseCount(values.get('fail-count')),
          users: parseCount(values.get('fail-users')),
          window: freeText(values.get('fail-window'))
        }

  // ---- OOM kills ---------------------------------------------------------
  //
  // Null when no source answered at all, exactly as `failedLogins` is: a
  // summary object with a null count and a null source would render as a real
  // reading of a very quiet host, and the reason lives on the source report.
  const oomSource = oneOf(values.get('oom-tool'), OOM_SOURCES)
  const oomKills: OomKillSummary | null =
    oomSource === null
      ? null
      : {
          source: oomSource,
          count: parseCount(values.get('oom-count')),
          processes: parseCount(values.get('oom-procs')),
          window: freeText(values.get('oom-window'))
        }

  // ---- certificates ------------------------------------------------------
  //
  // Null ONLY when the block never ran. `cert-searched` is emitted on every
  // collection including the one that found nothing, so "the search ran and
  // this host has no certificates in the roots it looks in" is an inventory
  // with an empty list — a reading — and not a null.
  const certSearched = values.get('cert-searched') !== undefined
  const certificates: CertificateInventory | null =
    !certSearched && certRecords.length === 0
      ? null
      : {
          certificates: certRecords.map((c) => readCertificate(c.body, c.path, now)),
          // The host's `head -n` cap was reached, so this list is a prefix
          // rather than an inventory and the panel says so.
          truncated: certRecords.length >= CERT_SEARCH_MAX_FILES,
          unreadableRoots: parseCount(values.get('cert-refused')) ?? 0,
          bound: certSearchBound()
        }

  // A probe the collector said `ok` about, whose value did not survive, is
  // `unknown` — not `ok` with a null next to it. That substitution is how a
  // security panel ends up showing an all-clear it never earned.
  const confirm = (id: PostureSourceId, present: boolean, why: string): PostureSourceReport => {
    const s = source(id)
    if (s.status !== 'ok' || present) return s
    return { ...s, status: 'unknown', detail: why }
  }

  const sources: PostureSourceReport[] = [
    confirm(
      'firewall',
      firewall !== null && (firewall.tool !== null || firewall.backend.tool !== null),
      'the firewall probe reported success and named no tool, so nothing about what this host filters was established'
    ),
    confirm(
      'mandatory-access',
      mandatoryAccess !== null,
      'the SELinux/AppArmor probe reported success and named no system'
    ),
    confirm(
      'sshd-hardening',
      sshd !== null,
      'the sshd probe reported success and returned no configuration to read'
    ),
    confirm(
      'failed-logins',
      failedLogins !== null && failedLogins.count !== null,
      'the failed-login probe reported success and returned no count'
    ),
    confirm(
      'oom-kills',
      oomKills !== null && oomKills.count !== null,
      'the OOM probe reported success and returned no count, so whether this host has killed anything for memory was not established'
    ),
    confirm(
      'certificates',
      certificates !== null,
      'the certificate probe reported success and returned no search at all, so nothing about what expires on this host was established'
    )
  ]

  return {
    firewall,
    mandatoryAccess,
    sshd,
    failedLogins,
    oomKills,
    certificates,
    collectedAt: now,
    sources
  }
}

// ---- Consuming item C's security update count -----------------------------

/**
 * The pending security update count, TAKEN FROM ITEM C rather than recomputed.
 *
 * This is the scope discipline of the whole item expressed as a function. The
 * distribution knows which of its packages carry security fixes and its answer
 * is better than anything computed here from a CVE feed; `hostFacts.ts` already
 * collects it, already knows that Arch and Alpine can never answer, and already
 * knows that dnf returns a silent zero where the repositories publish no
 * updateinfo. All of that is inherited by reading `HostFacts`, and none of it
 * is re-derived.
 *
 * The status comes straight off the fact source, so `unsupported` stays
 * `unsupported` — the panel shows "cannot be answered", never "0".
 */
export function securityUpdateReading(facts: HostFacts | null): {
  count: number | null
  status: FactStatus
  detail: string
} {
  if (facts === null) {
    return {
      count: null,
      status: 'unknown',
      detail:
        'no host facts have been collected for this server yet, so its security update count is unknown. Switch on the Inventory collection, or wait for the next hourly sweep.'
    }
  }
  const s = factSource(facts, 'security-updates')
  return {
    count: facts.securityUpdates,
    status: s.status,
    detail: s.detail ?? ''
  }
}

// ---- What the alert bus is allowed to be told -----------------------------
//
// The DECISION lives here rather than in the renderer, for the reason
// `isDiskCritical` lives in hostHealth.ts: an alert that made its own judgement
// could disagree with the panel beside it, and the two have to be the same
// comparison in one place. store/alerts.ts owns damping, repeat windows and
// snooze; WHAT it is told is decided here, and is testable without a window.

export interface PostureAlertReadings {
  /**
   * Whether this host has OOM-killed a process inside a window that was
   * actually read.
   *
   *   true   A `Killed process` line was read. A kill that was read happened,
   *          whatever window it was read over, so a `partial` source counts.
   *   false  A STATED window was read and held none. Only the journal can
   *          produce this — see oomWindowIsStated.
   *   null   The kernel log could not be read, or was read over a window that
   *          cannot support the claim. Never raised, never resolved, never
   *          read as healthy.
   *
   * The asymmetry is the point rather than an oversight: a ring buffer can
   * prove a kill and cannot disprove one.
   */
  oomKills: boolean | null
  /** Our words, for the alert detail. Never the host's, and written in the
   *  character class store/alerts.ts scrubs a detail to — so no commas. */
  oomDetail: string
  /**
   * Days remaining on the SOONEST certificate that parsed, or null.
   *
   * NULL, not a large number, when nothing parsed — and that covers three
   * different hosts which must all be silent rather than healthy: one whose
   * certificate directories refused to be entered, one whose certificates
   * could not be parsed, and one that genuinely has none in the roots this
   * looks in. "No certificates" is not "infinitely far from expiry", and a
   * path that turned it into a number would report the whole estate clean.
   *
   * Negative means expired that many days ago, which the alert renders as a
   * different sentence rather than as a small number.
   */
  certDays: number | null
}

export function postureAlertReadings(posture: HostPosture | null): PostureAlertReadings {
  if (posture === null) return { oomKills: null, oomDetail: '', certDays: null }

  const oom = posture.oomKills
  const oomStatus = postureSource(posture, 'oom-kills').status
  let oomKills: boolean | null = null
  let oomDetail = ''
  if (oom !== null && oom.count !== null) {
    if (oom.count > 0 && (oomStatus === 'ok' || oomStatus === 'partial')) {
      oomKills = true
      oomDetail =
        oom.processes === null
          ? `${oom.count} killed`
          : `${oom.count} killed across ${oom.processes} process${oom.processes === 1 ? '' : 'es'}`
    } else if (oom.count === 0 && oomStatus === 'ok' && oomWindowIsStated(oom.source)) {
      oomKills = false
    }
    // Everything else stays null. A ZERO FROM A RING BUFFER LANDS HERE, and it
    // is the line this item was deferred over: a half-probe reporting "no OOM
    // kills" when it could not read a window is the alert this refuses to send.
  }

  // The soonest certificate that PARSED. A certificate that could not be read
  // contributes nothing rather than contributing reassurance: it is counted as
  // a gap by the panel and by the roll-up, and the alert simply has one fewer
  // number to be worst.
  return { oomKills, oomDetail, certDays: soonestCertificateExpiry(posture.certificates) }
}

/**
 * Whether anything about this host's certificates could not be read.
 *
 * Deliberately TRUE for a directory that refused entry as well as for a file
 * that would not parse: both are reasons the number above may be missing the
 * certificate that actually matters, and a panel that showed "45 days" beside
 * a silently skipped /etc/letsencrypt would be worse than one that showed
 * nothing.
 */
export function certificatesIncomplete(inv: CertificateInventory | null): boolean {
  if (inv === null) return true
  return inv.unreadableRoots > 0 || inv.truncated || inv.certificates.some((c) => c.problem !== null)
}

// ---- Summary --------------------------------------------------------------

/**
 * What the estate looks like, with the gaps counted rather than skipped.
 *
 * Every "how many hosts have X" number here has a matching "how many could not
 * be asked" beside it, because a security roll-up drawn over the hosts that
 * answered is the exact shape of reassuring fiction this item exists to avoid.
 */
export interface PostureSummary {
  hosts: number
  /** Hosts with any collection at all. */
  collected: number
  /** Firewall: active, inactive, and could-not-tell. The third is not folded
   *  into the second. */
  firewallActive: number
  firewallInactive: number
  firewallUnknown: number
  /** SELinux/AppArmor enforcing, and hosts with no MAC at all — which is a
   *  finding, not a gap — kept apart from hosts that could not be asked. */
  macEnforcing: number
  macAbsent: number
  macUnknown: number
  /** Hosts with at least one `weak` sshd directive, and hosts whose sshd
   *  configuration could not be read at all. */
  sshdWeak: number
  sshdUnknown: number
  /** Hosts that have OOM-killed something inside a window that was read, and
   *  hosts where that could not be established — which includes every host
   *  answered by a ring buffer, whose zero is not a statement about a day. */
  oomKilling: number
  oomUnknown: number
  /** Hosts with a certificate at or inside the line, hosts with one that has
   *  already expired, and hosts where some part of the certificate search
   *  could not be read. The third is not folded into "fine": a host whose
   *  /etc/letsencrypt refused to be entered is not a host with no
   *  certificates. */
  certExpiringSoon: number
  certExpired: number
  certUnknown: number
}

export function summarisePosture(
  rows: { posture: HostPosture | null }[]
): PostureSummary {
  const out: PostureSummary = {
    hosts: rows.length,
    collected: 0,
    firewallActive: 0,
    firewallInactive: 0,
    firewallUnknown: 0,
    macEnforcing: 0,
    macAbsent: 0,
    macUnknown: 0,
    sshdWeak: 0,
    sshdUnknown: 0,
    oomKilling: 0,
    oomUnknown: 0,
    certExpiringSoon: 0,
    certExpired: 0,
    certUnknown: 0
  }
  for (const { posture } of rows) {
    if (posture === null) {
      // Never collected. Counted in every "unknown" bucket rather than being
      // left out of the denominators, so a fleet where nothing has been
      // collected does not read as a fleet with nothing wrong.
      out.firewallUnknown++
      out.macUnknown++
      out.sshdUnknown++
      out.oomUnknown++
      out.certUnknown++
      continue
    }
    out.collected++

    const fw = postureSource(posture, 'firewall')
    // `ok` is the ONLY status that lets an active/inactive answer count. A
    // `partial` reading of ufw.conf says whether ufw is switched on and nothing
    // about what it lets through, and a `denied` one says nothing at all.
    if (fw.status === 'ok' && posture.firewall?.active === true) out.firewallActive++
    else if (fw.status === 'ok' && posture.firewall?.active === false) out.firewallInactive++
    else if (
      fw.status === 'ok' &&
      // `posture.firewall !== null` spelled out rather than reached through
      // `?.`: optional chaining yields `undefined`, and `undefined !== null` is
      // TRUE, so the short spelling would take this branch for a host that read
      // no firewall at all.
      posture.firewall !== null &&
      posture.firewall.backend.tool !== null &&
      posture.firewall.backend.status === 'ok'
    ) {
      // No front end, and the kernel tables were read. Rules present means
      // something is filtering; zero rules read cleanly means nothing is.
      if ((posture.firewall.backend.rules ?? 0) > 0) out.firewallActive++
      else out.firewallInactive++
    } else out.firewallUnknown++

    const mac = postureSource(posture, 'mandatory-access')
    if (mac.status === 'absent') out.macAbsent++
    else if (mac.status === 'ok' && posture.mandatoryAccess?.system === 'selinux') {
      if (posture.mandatoryAccess.mode === 'enforcing') out.macEnforcing++
      else if (posture.mandatoryAccess.mode === null) out.macUnknown++
    } else if (
      (mac.status === 'ok' || mac.status === 'partial') &&
      posture.mandatoryAccess?.system === 'apparmor'
    ) {
      // AppArmor has no global mode, so "enforcing" here means enabled with no
      // profile in complain mode. A host whose profile list was refused is
      // unknown rather than enforcing: complain-mode profiles are exactly what
      // the refused list would have shown.
      if (posture.mandatoryAccess.enabled !== true) out.macUnknown++
      else if (posture.mandatoryAccess.complain === null) out.macUnknown++
      else if (posture.mandatoryAccess.complain === 0) out.macEnforcing++
    } else out.macUnknown++

    const ssh = postureSource(posture, 'sshd-hardening')
    if (posture.sshd === null || ssh.status === 'denied' || ssh.status === 'absent') out.sshdUnknown++
    else if (posture.sshd.readings.some((r) => r.verdict === 'weak')) out.sshdWeak++
    else if (posture.sshd.readings.every((r) => r.verdict === 'unknown')) out.sshdUnknown++

    // Taken through the SAME function the alert bus is given, so the roll-up
    // and the alert can never disagree about what a ring-buffer zero means.
    const oom = postureAlertReadings(posture).oomKills
    if (oom === true) out.oomKilling++
    else if (oom === null) out.oomUnknown++

    // Through the same function again, for the same reason. `certExpired` is
    // counted SEPARATELY from `certExpiringSoon` rather than as its worst
    // case: "expires in four days" and "expired four days ago" are different
    // incidents, one of which is already an outage.
    const days = postureAlertReadings(posture).certDays
    if (days !== null && days < 0) out.certExpired++
    else if (days !== null && isCertificateExpiringSoon(days)) out.certExpiringSoon++
    if (certificatesIncomplete(posture.certificates)) out.certUnknown++
  }
  return out
}

// ---- Storage --------------------------------------------------------------

/**
 * The prefix every posture value is stored under in the durable store (item A).
 *
 * A prefix rather than loose keys because `retireFacts` sweeps by prefix: a
 * host that stops being able to answer a question it used to answer must lose
 * the old key rather than keeping it forever next to a fresher one.
 */
export const POSTURE_FACT_PREFIX = 'posture:'

/**
 * Posture as the store wants it: string keys, string values.
 *
 * A null is written as its SOURCE STATUS, never as an empty string, a zero or
 * a `false`. That is what makes `posture:firewallRules = denied` survive into
 * history, so a report written six months from now can still tell "this host
 * had no firewall rules" from "nobody was allowed to look".
 *
 * Every field is written on every collection — including the ones that are
 * null — so the key set is complete whatever the probe managed, which is what
 * makes an unconditional prefix sweep safe on the sampler's side.
 */
export function postureToFacts(posture: HostPosture): Record<string, string> {
  const out: Record<string, string> = {}
  const put = (key: string, value: string | number | boolean | null, id: PostureSourceId): void => {
    out[`${POSTURE_FACT_PREFIX}${key}`] = value === null ? postureSource(posture, id).status : String(value)
  }
  put('firewallTool', posture.firewall?.tool ?? null, 'firewall')
  put('firewallActive', posture.firewall?.active ?? null, 'firewall')
  put('firewallPolicyIn', posture.firewall?.policyIn ?? null, 'firewall')
  put('firewallRules', posture.firewall?.rules ?? null, 'firewall')
  put('firewallDenyRules', posture.firewall?.denyRules ?? null, 'firewall')
  // AND NOT THE RULE LINES — roadmap item 31, and the one thing in this
  // collection that stops here.
  //
  // Everything else in this function is a count or a word from a fixed
  // vocabulary. A rule line is an address and a port, and this store is
  // durable, fleet-wide and swept by prefix rather than read: writing them
  // would keep "which address may reach 3306 on every host in the estate" on
  // this disk months after the hour it was collected in. What the capability
  // was granted for is a person looking at one host's rules in the panel, and
  // the shape of that consent does not stretch to a fleet-wide history nobody
  // asked for. The count goes; the addresses do not.
  //
  // tests/posture.test.ts asserts it, because a comment is not a mechanism.
  put('firewallBackend', posture.firewall?.backend.tool ?? null, 'firewall')
  put('firewallBackendRules', posture.firewall?.backend.rules ?? null, 'firewall')
  put('macSystem', posture.mandatoryAccess?.system ?? null, 'mandatory-access')
  put('macMode', posture.mandatoryAccess?.mode ?? null, 'mandatory-access')
  put('macBootMode', posture.mandatoryAccess?.bootMode ?? null, 'mandatory-access')
  put('macProfiles', posture.mandatoryAccess?.profiles ?? null, 'mandatory-access')
  put('macComplain', posture.mandatoryAccess?.complain ?? null, 'mandatory-access')
  put('sshdSource', posture.sshd === null ? null : posture.sshd.effective ? 'effective' : 'files', 'sshd-hardening')
  put('sshdMatchBlocks', posture.sshd?.matchBlocks ?? null, 'sshd-hardening')
  for (const d of SSHD_DIRECTIVES) {
    const r = posture.sshd?.readings.find((x) => x.directive === d)
    // The VERDICT, not the value. A history row saying `weak` six months from
    // now is readable without knowing what sshd's vocabulary was that week —
    // and `unknown` is stored as `unknown` rather than being omitted, so a
    // directive that stopped being readable is visible as a change.
    out[`${POSTURE_FACT_PREFIX}sshd:${SSHD_DIRECTIVE_KEY[d]}`] =
      r === undefined ? postureSource(posture, 'sshd-hardening').status : r.value === null ? r.verdict : r.value
  }
  put('failedLoginTool', posture.failedLogins?.tool ?? null, 'failed-logins')
  put('failedLogins', posture.failedLogins?.count ?? null, 'failed-logins')
  put('failedLoginUsers', posture.failedLogins?.users ?? null, 'failed-logins')
  put('oomTool', posture.oomKills?.source ?? null, 'oom-kills')
  put('oomKills', posture.oomKills?.count ?? null, 'oom-kills')
  put('oomProcesses', posture.oomKills?.processes ?? null, 'oom-kills')
  put('certificatesFound', posture.certificates?.certificates.length ?? null, 'certificates')
  put('certificateRootsRefused', posture.certificates?.unreadableRoots ?? null, 'certificates')
  put('certificateDaysRemaining', soonestCertificateExpiry(posture.certificates), 'certificates')
  put(
    'certificatesUnread',
    posture.certificates === null
      ? null
      : posture.certificates.certificates.filter((c) => c.problem !== null).length,
    'certificates'
  )
  // The status of every source, so history can say WHY a null was null at the
  // time rather than only that it was null.
  for (const s of posture.sources) out[`${POSTURE_FACT_PREFIX}source:${s.id}`] = s.status
  return out
}
