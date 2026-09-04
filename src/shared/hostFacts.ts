// What a host IS, as opposed to what it is currently doing — roadmap item C.
//
// Distro, architecture, CPU model, package manager, pending updates, SECURITY
// updates specifically, whether a reboot is owed, and what kind of machine this
// is. Slow cadence: a distribution does not change between two-minute sweeps.
//
// Kernel, total memory and uptime are deliberately NOT here. They are already
// on HostMetrics and collecting them twice would give the app two answers to
// one question, which is how they start disagreeing.
//
// ---------------------------------------------------------------------------
// The honesty requirements, which ARE the feature
// ---------------------------------------------------------------------------
//
// 1. `unsupported` is a first-class status, distinct from both 0 and
//    not-checked. Two of the five package managers can NEVER count security
//    updates — Arch has no security channel at all, and Alpine tracks secfixes
//    in build metadata rather than in the installed index — and a third, dnf,
//    silently returns zero rows when the repositories publish no `updateinfo`.
//    That last case is indistinguishable from "no security updates" unless it
//    is probed for, so it is probed for. A silent zero during a CVE week is the
//    precise failure this file exists to prevent.
//
// 2. Nothing here mutates. No `apt update`, no `pacman -Sy`, no `dnf
//    makecache`. All three hit the network, take seconds, and `pacman -Sy`
//    creates the partial-upgrade state that is the classic way to break an Arch
//    box. `apt … update` is classified ELEVATED in shared/broadcast.ts — a
//    background probe must not do what the broadcast panel would make a human
//    confirm.
//
// 3. Because the caches are read rather than refreshed, their AGE is reported.
//    "0 pending updates" from metadata refreshed forty days ago is a lie. That
//    is a second staleness axis, distinct from the fact's own collection age,
//    and both are representable: `metadataAt` and `collectedAt`.
//
// 4. /etc/os-release is READ and parsed here, never sourced. `. /etc/os-release`
//    on a host under an attacker's control is arbitrary code execution as the
//    SSH user.
//
// ---------------------------------------------------------------------------
// Why this is shaped like cron.ts and not like metrics.ts
// ---------------------------------------------------------------------------
//
// metrics.ts fences its sections with `__MARKER__` and `section()` cuts at the
// next one. Every value here is either read out of a file the host controls
// (PRETTY_NAME) or printed by a tool the host controls (the CPU model), so a
// value containing a marker would truncate its own section and shift every
// later fact — a host could move its security-update count by naming itself
// carefully.
//
// cron.ts already solved this: accumulate status in a shell variable and print
// it once at the end, where nothing read out of a file can forge it. This goes
// one step further, because it can: there are no file dumps here, only scalars,
// so EVERY value is emitted as a single `V <key> <value>` line with control
// characters — newlines included — deleted on the host before it is printed.
// A value therefore cannot become a second line, cannot forge a key, and cannot
// forge the status marker, which is the only structural token in the output.
//
// Same discipline as cron.ts otherwise: no `set -e`, every read conditional or
// `|| true`, and sudo omitted at build time rather than guarded at runtime, so
// "this command contains no sudo" is a property somebody can check by reading
// it. tests/hostFacts.test.ts asserts exactly that.

// `resolveBinary` and `SUDO_PROBE` are the Docker module's, for the same reason
// cron.ts borrows them: both encode a fact about the environment rather than
// anything about Docker — that `ssh host cmd` gets a non-login PATH of roughly
// /usr/bin:/bin, and that `sudo -n` is the only escalation that cannot prompt.
import { SUDO_PROBE, resolveBinary } from './docker'

// ---- Statuses -------------------------------------------------------------

/**
 * Why a fact is missing, or why it is present but qualified.
 *
 * Every null on HostFacts is explained by a matching source report. "No pending
 * updates" and "could not check for updates" must stay visibly different, or
 * the feature lies during exactly the week a CVE matters.
 */
export type FactStatus =
  /** Read it. A zero here really is a zero. */
  | 'ok'
  /** The thing genuinely is not on this host — no /etc/os-release, no cpuinfo. */
  | 'absent'
  /** It exists and this account may not read it. */
  | 'denied'
  /** The tool that answers this is not installed. */
  | 'no-tool'
  /**
   * We have an answer, but the data behind it is old enough that the answer
   * should not be trusted. Only ever set on `package-metadata`: it is the
   * second staleness axis, and it qualifies the update counts rather than
   * replacing them.
   */
  | 'stale-metadata'
  /**
   * This host CANNOT answer this question, and no amount of privilege or
   * retrying changes that. Arch and Alpine for security counts; dnf where the
   * repositories publish no updateinfo. Distinct from `0` and from
   * "not checked", and that distinction is the whole point of the item.
   */
  | 'unsupported'
  /** Something else happened, or the collector never reported on this source. */
  | 'unknown'

export const FACT_STATUSES: FactStatus[] = [
  'ok',
  'absent',
  'denied',
  'no-tool',
  'stale-metadata',
  'unsupported',
  'unknown'
]

/**
 * One sentence per status, written for the person deciding whether to act on
 * the number next to it. `unsupported` gets the longest one because it is the
 * status people will not have seen before and the one most likely to be read as
 * "zero".
 */
export const FACT_STATUS_HELP: Record<FactStatus, string> = {
  ok: 'Read successfully. A zero here means zero, not "we could not look".',
  absent: 'This server does not have the file or flag that answers this, so there is nothing to read.',
  denied: 'It exists and this account was not allowed to read it. A different account might see more.',
  'no-tool': 'The program that answers this is not installed on this server.',
  'stale-metadata':
    'The answer was read from a package cache that has not been refreshed recently, so it describes the estate as it was then, not now. ShellPilot never refreshes it, because that is a network operation and on some package managers it can break the server.',
  unsupported:
    'This server cannot answer this question at all — not because of a permission or a missing tool, but because the distribution does not publish the data. Treat it as UNKNOWN, never as zero.',
  unknown: 'The probe ran and its answer could not be read, or the collector never reported on it.'
}

/** The nine things the collector reports on, each read independently. */
export type FactSourceId =
  | 'os-release'
  | 'architecture'
  | 'cpu'
  | 'virtualisation'
  | 'package-manager'
  | 'updates'
  | 'security-updates'
  | 'reboot-required'
  | 'package-metadata'

export const FACT_SOURCE_IDS: FactSourceId[] = [
  'os-release',
  'architecture',
  'cpu',
  'virtualisation',
  'package-manager',
  'updates',
  'security-updates',
  'reboot-required',
  'package-metadata'
]

export const FACT_SOURCE_LABEL: Record<FactSourceId, string> = {
  'os-release': 'Distribution',
  architecture: 'Architecture',
  cpu: 'CPU model',
  virtualisation: 'Virtualisation',
  'package-manager': 'Package manager',
  updates: 'Pending updates',
  'security-updates': 'Security updates',
  'reboot-required': 'Reboot required',
  'package-metadata': 'Package metadata age'
}

export interface FactSourceReport {
  id: FactSourceId
  /** What to call it on screen. */
  label: string
  status: FactStatus
  /** Read as root after the unprivileged attempt was refused. Never silent. */
  usedSudo?: boolean
  /** The collector's own words, when it had any. Always sanitised. */
  detail?: string
}

// ---- Allow-lists ----------------------------------------------------------
//
// These three are validated against a TypeScript list rather than merely
// sanitised, because they are the fields anything downstream will switch on. A
// host must not be able to invent a package manager value, and an agent must
// not be told this box runs a distribution nobody has heard of because its
// os-release said so.

/**
 * Distribution IDs, as os-release spells them.
 *
 * Anything unrecognised becomes `other` — never dropped, because "we do not
 * know this distro" and "this host reported no ID at all" are different facts.
 * The pretty name still carries the host's own words, sanitised, so nothing is
 * actually lost.
 */
export const DISTRO_IDS = [
  'almalinux',
  'alpine',
  'altlinux',
  'amzn',
  'arch',
  'archarm',
  'astra',
  'centos',
  'clear-linux-os',
  'debian',
  'deepin',
  'devuan',
  'elementary',
  'endeavouros',
  'fedora',
  'freebsd',
  'garuda',
  'gentoo',
  'kali',
  'linuxmint',
  'mageia',
  'manjaro',
  'neon',
  'netbsd',
  'nixos',
  'ol',
  'openbsd',
  'openeuler',
  'opensuse',
  'opensuse-leap',
  'opensuse-tumbleweed',
  'openwrt',
  'photon',
  'pop',
  'raspbian',
  'rhel',
  'rocky',
  'scientific',
  'sled',
  'sles',
  'slackware',
  'ubuntu',
  'void',
  'zorin',
  'other'
] as const
export type DistroId = (typeof DISTRO_IDS)[number]

/** What `systemd-detect-virt` can say, plus `other` for anything newer. */
export const VIRTUALISATIONS = [
  'none',
  'acrn',
  'amazon',
  'apple-virtualization',
  'bhyve',
  'bochs',
  'docker',
  'kvm',
  'lxc',
  'lxc-libvirt',
  'microsoft',
  'openvz',
  'oracle',
  'parallels',
  'podman',
  'pouch',
  'powervm',
  'proot',
  'qemu',
  'qnx',
  'rkt',
  'systemd-nspawn',
  'uml',
  'vmware',
  'wsl',
  'xen',
  'zvm',
  'other'
] as const
export type Virtualisation = (typeof VIRTUALISATIONS)[number]

/**
 * The five package managers, plus yum as its own value.
 *
 * There is no `other` here on purpose. The collector emits one of these six
 * literals and nothing else, so a value outside the list did not come from the
 * collector — it is forged, and the right answer is `null` with the source
 * marked `unknown`, not a shrug.
 */
export const PACKAGE_MANAGERS = ['apt', 'dnf', 'yum', 'zypper', 'pacman', 'apk'] as const
export type PackageManager = (typeof PACKAGE_MANAGERS)[number]

/**
 * Which managers can count security updates AT ALL, before any host-specific
 * probing. dnf and yum are `maybe`: it depends entirely on whether the
 * repositories this host is pointed at publish `updateinfo`, which is why the
 * collector probes for it rather than assuming.
 */
export const SECURITY_COUNT_SUPPORT: Record<PackageManager, 'yes' | 'maybe' | 'never'> = {
  apt: 'yes',
  zypper: 'yes',
  dnf: 'maybe',
  yum: 'maybe',
  pacman: 'never',
  apk: 'never'
}

// ---- The facts themselves -------------------------------------------------

/**
 * Every scalar is `T | null`, and every null is explained by the matching
 * entry in `sources`. There is no "0 means we did not look" anywhere in here.
 */
export interface HostFacts {
  /** os-release ID, allow-listed. `other` when the host named something this
   *  build does not know; null when it named nothing. */
  distroId: DistroId | null
  /** os-release VERSION_ID, verbatim after quote-stripping. */
  distroVersion: string | null
  /** os-release PRETTY_NAME. FREE TEXT the host wrote about itself — it must go
   *  through remoteText and inside hostReportedBlock before any agent sees it. */
  prettyName: string | null
  /** `uname -m`, shape-validated rather than allow-listed: a new architecture
   *  is a thing that happens, an architecture containing a space is not. */
  arch: string | null
  /** FREE TEXT, same handling as prettyName. */
  cpuModel: string | null
  packageManager: PackageManager | null
  /** Updates the local cache knows about. Never a refreshed count — see
   *  `metadataAt` for how old the cache behind it is. */
  pendingUpdates: number | null
  /**
   * Security updates specifically, or null.
   *
   * A null here is NOT zero. Read `sources` for which: `unsupported` means this
   * host can never answer, `unknown` means the probe failed, `no-tool` means
   * there is no package manager at all.
   */
  securityUpdates: number | null
  rebootRequired: boolean | null
  /** The packages that asked for the reboot. FREE TEXT. */
  rebootReason: string | null
  virtualisation: Virtualisation | null
  /** Epoch milliseconds the package metadata was last refreshed, by the host's
   *  own clock. The second staleness axis. */
  metadataAt: number | null
  /** Epoch milliseconds this collection ran, by OUR clock. The first axis. */
  collectedAt: number
  sources: FactSourceReport[]
}

/**
 * How old package metadata may get before the update counts stop meaning
 * anything. Seven days is generous: a host on a weekly `apt update` timer sits
 * just inside it, and one that stopped refreshing a month ago is well outside.
 */
export const METADATA_STALE_MS = 7 * 24 * 60 * 60 * 1000

/**
 * How often to collect. Hourly, not the two-minute metrics cadence: a
 * distribution does not change between samples, and the update counts move when
 * a cron job refreshes a cache, not continuously.
 */
export const HOST_FACTS_INTERVAL_MS = 60 * 60 * 1000
export const HOST_FACTS_INTERVAL_MIN_MS = 5 * 60 * 1000

/** Look one source up without a find() at every call site. */
export function factSource(facts: HostFacts, id: FactSourceId): FactSourceReport {
  return (
    facts.sources.find((s) => s.id === id) ?? {
      id,
      label: FACT_SOURCE_LABEL[id],
      status: 'unknown',
      detail: 'the collector did not report on this source'
    }
  )
}

// ---- Building the command -------------------------------------------------

export interface HostFactsCollectOptions {
  /**
   * Retry a refused probe as root. On by default, and `sudo -n` only.
   *
   * Worth having because two probes genuinely want root on some hosts —
   * `needs-restarting -r` reads every process's /proc entry, and zypper's
   * caches are root-only on a hardened SUSE box. Safe to have on for the reason
   * the Docker reader gives: `sudo -n` NEVER prompts. It either works, because
   * this account already has passwordless sudo — a decision made on that host —
   * or it fails instantly. It cannot hang an exec waiting for a tty.
   *
   * When false, the word `sudo` does not appear in the built command at all.
   * That is asserted by a test, and a runtime guard could not be.
   */
  sudo?: boolean
}

/** The only structural token in the output. Values can never contain it,
 *  because a value is always one line beginning `V `. */
export const FACTS_STATUS_MARKER = '===SHELLPILOT-FACTS==='

/**
 * One round trip, no mutation, no sourcing, and no interpolation of host output
 * into a later command.
 *
 * The package manager is detected ON the host, inside this one script. It is
 * never round-tripped back to TypeScript and re-sent — that would be a second
 * connection and, worse, a command built from a string the host chose.
 *
 * Structure, in order, because two of the blocks depend on the ones above them:
 *   1. helpers and the sudo probe
 *   2. os-release, architecture, CPU, virtualisation — independent
 *   3. the Debian-family reboot flag, which any host may have
 *   4. package-manager detection
 *   5. the per-manager block: pending, security, metadata age, and reboot where
 *      the flag in (3) did not already answer it
 *
 * No `set -e`. Every read is conditional or ends in `|| true`, and the last
 * command is a `printf`, so a host with no package manager, no systemd and no
 * /proc/cpuinfo still returns every other fact and exits 0.
 */
export function buildHostFactsCommand(opts: HostFactsCollectOptions = {}): string {
  const sudo = opts.sudo !== false
  // Omitted entirely rather than left behind a dead `[ "$SP_SUDO" = 1 ]`
  // branch, exactly as cron.ts does it: "this command contains no sudo at all"
  // is a property a reader can check, and a runtime guard is not.
  const ifSudo = (...lines: string[]): string[] => (sudo ? lines : [])
  const probe = sudo
    ? `SP_SUDO=0\n[ "$(${SUDO_PROBE})" = SP_SUDO_OK ] && SP_SUDO=1`
    : 'SP_SUDO=0'

  // One binary lookup, stashed under its own name. cron.ts's pattern:
  // resolveBinary writes SP_BIN, so it has to be copied before the next call.
  const findBin = (name: string, varName: string, extra: string[] = []): string[] => [
    resolveBinary(name, extra),
    `${varName}=""`,
    `command -v "$SP_BIN" >/dev/null 2>&1 && ${varName}="$SP_BIN"`
  ]

  // A dnf/yum check-update row is `<name>  <version>  <repo>` at column 0.
  // Obsoleting rows are indented, so anchoring on a non-space first character
  // excludes them; section headers have two fields, so requiring three excludes
  // those.
  const PKG_ROW = '^[^[:space:]]+[[:space:]]+[^[:space:]]+[[:space:]]+[^[:space:]]+[[:space:]]*$'

  return [
    // A literal newline in a variable so statuses accumulate one per line.
    // `$(printf ...)` cannot be used: command substitution strips trailing
    // newlines, which is the entire content here.
    "SP_NL='\n'",
    'SP_STATUS=""',
    'sp_note() { SP_STATUS="$SP_STATUS$*$SP_NL"; }',
    // THE defence. Control characters — newlines and carriage returns included
    // — are deleted on the host, and the result is cut to 512 characters, so a
    // value can never become a second line, forge a key, or forge the status
    // marker. An 8 KB PRETTY_NAME arrives as 512 harmless characters.
    "sp_val() { SP_V=$(printf '%s' \"$2\" | tr -d '\\000-\\037\\177' | cut -c1-512); " +
      "[ -n \"$SP_V\" ] && printf 'V %s %s\\n' \"$1\" \"$SP_V\"; }",
    // mtime of one path, as epoch seconds. GNU/busybox `stat -c %Y` first,
    // `date -r` second for the BSD-ish hosts that have no GNU stat.
    'sp_mtime() {',
    '[ -n "$1" ] && [ -e "$1" ] || { sp_note package-metadata unknown - "no package metadata timestamp to read"; return 0; }',
    'SP_T=$(stat -c %Y "$1" 2>/dev/null || date -r "$1" +%s 2>/dev/null || true)',
    'case "$SP_T" in',
    '""|*[!0-9]*) sp_note package-metadata unknown - "the metadata timestamp could not be read" ;;',
    '*) sp_val meta-at "$SP_T"; sp_note package-metadata ok - "$1" ;;',
    'esac',
    '}',
    probe,

    // ---- os-release: read, never sourced ---------------------------------
    // Each key is grepped separately and the LAST definition wins, which is what
    // sourcing would have done. The `KEY=` prefix is left on the value so the
    // parser can confirm which key it is looking at rather than trusting
    // position; quote-stripping and unescaping happen in TypeScript.
    'SP_OSR=""',
    '[ -r /etc/os-release ] && SP_OSR=/etc/os-release',
    '[ -z "$SP_OSR" ] && [ -r /usr/lib/os-release ] && SP_OSR=/usr/lib/os-release',
    'if [ -n "$SP_OSR" ]; then',
    `sp_val os-id "$(grep -E '^ID=' "$SP_OSR" 2>/dev/null | tail -1)"`,
    `sp_val os-version "$(grep -E '^VERSION_ID=' "$SP_OSR" 2>/dev/null | tail -1)"`,
    `sp_val os-pretty "$(grep -E '^PRETTY_NAME=' "$SP_OSR" 2>/dev/null | tail -1)"`,
    'sp_note os-release ok - "$SP_OSR"',
    'elif [ -e /etc/os-release ] || [ -e /usr/lib/os-release ]; then',
    'sp_note os-release denied - "os-release exists and this account cannot read it"',
    'else',
    'sp_note os-release absent - "this server has no os-release file"',
    'fi',

    // ---- architecture ----------------------------------------------------
    'SP_ARCH=$(uname -m 2>/dev/null || true)',
    'if [ -n "$SP_ARCH" ]; then',
    'sp_val arch "$SP_ARCH"',
    'sp_note architecture ok -',
    'else',
    'sp_note architecture unknown - "uname -m said nothing"',
    'fi',

    // ---- CPU model -------------------------------------------------------
    // x86 spells it `model name`; ARM boards use `Model` or `Hardware`, and
    // some report only `Processor`. First match wins.
    'if [ -r /proc/cpuinfo ]; then',
    `SP_CPU=$(grep -E '^(model name|Model|cpu model|Hardware|Processor)[[:space:]]*:' /proc/cpuinfo 2>/dev/null | head -1 | cut -d: -f2-)`,
    'if [ -n "$SP_CPU" ]; then',
    'sp_val cpu-model "$SP_CPU"',
    'sp_note cpu ok -',
    'else',
    'sp_note cpu absent - "/proc/cpuinfo names no CPU model on this architecture"',
    'fi',
    'elif [ -e /proc/cpuinfo ]; then',
    'sp_note cpu denied -',
    'else',
    'sp_note cpu absent - "this server has no /proc/cpuinfo"',
    'fi',

    // ---- virtualisation --------------------------------------------------
    // systemd-detect-virt prints `none` and exits 1 on bare metal, so `|| true`
    // is load-bearing rather than defensive.
    ...findBin('systemd-detect-virt', 'SP_VIRT', ['/lib/systemd/systemd-detect-virt', '/usr/lib/systemd/systemd-detect-virt']),
    'if [ -n "$SP_VIRT" ]; then',
    'SP_VT=$("$SP_VIRT" 2>/dev/null || true)',
    'if [ -n "$SP_VT" ]; then',
    'sp_val virt "$SP_VT"',
    'sp_note virtualisation ok -',
    'else',
    'sp_note virtualisation unknown - "systemd-detect-virt produced no answer"',
    'fi',
    'elif [ -f /.dockerenv ]; then',
    'sp_val virt docker',
    'sp_note virtualisation ok - "inferred from /.dockerenv"',
    'elif [ -f /run/.containerenv ]; then',
    'sp_val virt podman',
    'sp_note virtualisation ok - "inferred from /run/.containerenv"',
    'else',
    'sp_note virtualisation no-tool - "systemd-detect-virt is not installed"',
    'fi',

    // ---- the Debian-family reboot flag ----------------------------------
    // Checked before the package-manager block because any host may carry it,
    // and because the per-manager reboot probes below defer to it.
    //
    // Its ABSENCE proves nothing on its own: the flag is created by
    // update-notifier-common's apt hook, and a minimal Debian without that
    // package never writes it however many kernels it installs. So the absent
    // case checks whether the mechanism is even present, and says `unsupported`
    // when it is not, rather than reporting a confident "no reboot needed".
    'SP_RB=0',
    'if [ -e /var/run/reboot-required ] || [ -e /run/reboot-required ]; then',
    'sp_val reboot yes',
    'SP_RP=""',
    'for f in /var/run/reboot-required.pkgs /run/reboot-required.pkgs; do',
    '[ -z "$SP_RP" ] && [ -r "$f" ] && SP_RP=$(tr "\\n" " " < "$f" 2>/dev/null)',
    'done',
    '[ -n "$SP_RP" ] && sp_val reboot-pkgs "$SP_RP"',
    'sp_note reboot-required ok - "the reboot-required flag file is present"',
    'SP_RB=1',
    'elif [ -x /usr/share/update-notifier/notify-reboot-required ]; then',
    'sp_val reboot no',
    'sp_note reboot-required ok - "update-notifier is installed and has raised no flag"',
    'SP_RB=1',
    'fi',

    // ---- which package manager ------------------------------------------
    // Detected here, on the host, in this same round trip. The value is never
    // sent back to TypeScript and re-used to build a second command.
    ...findBin('apt-get', 'SP_APT'),
    ...findBin('dnf', 'SP_DNF'),
    ...findBin('zypper', 'SP_ZYP'),
    ...findBin('pacman', 'SP_PAC'),
    ...findBin('apk', 'SP_APK', ['/sbin/apk']),
    ...findBin('yum', 'SP_YUM'),
    'SP_PM=""',
    // Order matters. RHEL 8+ ships `yum` as a symlink to dnf, so dnf has to be
    // tested first or every modern Red Hat host reports the legacy tool.
    'if [ -n "$SP_APT" ]; then SP_PM=apt',
    'elif [ -n "$SP_DNF" ]; then SP_PM=dnf',
    'elif [ -n "$SP_ZYP" ]; then SP_PM=zypper',
    'elif [ -n "$SP_PAC" ]; then SP_PM=pacman',
    'elif [ -n "$SP_APK" ]; then SP_PM=apk',
    'elif [ -n "$SP_YUM" ]; then SP_PM=yum',
    'fi',
    'if [ -n "$SP_PM" ]; then',
    'sp_val pkg "$SP_PM"',
    'sp_note package-manager ok -',
    'else',
    'sp_note package-manager no-tool - "none of apt, dnf, yum, zypper, pacman or apk is installed"',
    'fi',

    // ---- apt --------------------------------------------------------------
    'SP_PEND=-1',
    'if [ "$SP_PM" = apt ]; then',
    // update-notifier's apt-check is the best path: it is what Ubuntu's own MOTD
    // counts with, it needs no root, and it prints `<updates>;<security>` on
    // STDERR, hence the 2>&1.
    'SP_AC=""',
    'if [ -x /usr/lib/update-notifier/apt-check ]; then',
    'SP_OUT=$(/usr/lib/update-notifier/apt-check 2>&1 | tail -1)',
    // Shape-checked before it is believed. A pipeline's exit status is tail's,
    // so `if apt-check | tail -1; then` would take this branch even when
    // apt-check crashed and printed a traceback.
    'case "$SP_OUT" in',
    '*[0-9]";"[0-9]*) SP_AC="$SP_OUT" ;;',
    'esac',
    'fi',
    'if [ -n "$SP_AC" ]; then',
    'sp_val pending "${SP_AC%%;*}"',
    'sp_val security "${SP_AC##*;}"',
    'sp_note updates ok - "apt-check"',
    'sp_note security-updates ok - "apt-check"',
    // The fallback. `-s` is a simulation and `Debug::NoLocking` means it does
    // not want /var/lib/dpkg/lock, so it needs no root and touches nothing.
    // There is deliberately no `apt-get update` anywhere near this.
    'elif SP_OUT=$("$SP_APT" -s -o Debug::NoLocking=true upgrade 2>/dev/null); then',
    `SP_PEND=$(printf '%s\\n' "$SP_OUT" | grep -c '^Inst ' || true)`,
    'sp_val pending "$SP_PEND"',
    // An Inst line names its origin in brackets: `(… Debian-Security:12/…-security [amd64])`.
    // The archive suffix is what marks it, which is what the roadmap's research
    // settled on.
    `sp_val security "$(printf '%s\\n' "$SP_OUT" | grep '^Inst ' | grep -c -- '-security' || true)"`,
    'sp_note updates ok - "apt-get -s upgrade, from the local cache"',
    'sp_note security-updates ok - "counted Inst lines from a -security origin"',
    'else',
    'sp_note updates unknown - "apt-get -s upgrade did not complete"',
    'sp_note security-updates unknown - "pending updates could not be counted, so neither could security updates"',
    'fi',
    // Age of the cache the counts came from. The success stamp is the honest
    // one — it is written only when an update actually succeeded; the lists
    // directory is the fallback for hosts without update-notifier.
    'SP_MT=""',
    '[ -f /var/lib/apt/periodic/update-success-stamp ] && SP_MT=/var/lib/apt/periodic/update-success-stamp',
    '[ -z "$SP_MT" ] && [ -d /var/lib/apt/lists ] && SP_MT=$(ls -t /var/lib/apt/lists/*Packages* /var/lib/apt/lists/*Release 2>/dev/null | head -1)',
    'sp_mtime "$SP_MT"',

    // ---- dnf / yum --------------------------------------------------------
    'elif [ "$SP_PM" = dnf ] || [ "$SP_PM" = yum ]; then',
    'SP_PMB="$SP_DNF"',
    '[ "$SP_PM" = yum ] && SP_PMB="$SP_YUM"',
    // -C is cache-only: no network, no makecache, no metadata refresh. Exit 100
    // is the API for "there are updates" — which is why this uses sshExec's
    // code rather than metrics.ts's exec, and why the code is captured here
    // rather than being allowed to fall off the end of a pipeline.
    'SP_OUT=$("$SP_PMB" -C --quiet check-update 2>/dev/null)',
    'SP_RC=$?',
    'if [ "$SP_RC" = 100 ]; then',
    `SP_PEND=$(printf '%s\\n' "$SP_OUT" | grep -c -E '${PKG_ROW}' || true)`,
    'sp_val pending "$SP_PEND"',
    'sp_note updates ok - "check-update exited 100, meaning updates are available"',
    'elif [ "$SP_RC" = 0 ]; then',
    'SP_PEND=0',
    'sp_val pending 0',
    'sp_note updates ok - "check-update exited 0, meaning nothing is pending"',
    'else',
    'sp_note updates unknown - "check-update exited $SP_RC"',
    'fi',
    // THE dnf trap, and the reason this item exists. Where the repositories
    // publish no updateinfo, `--security check-update` returns ZERO ROWS —
    // indistinguishable from "no security updates". Rocky, Alma and Fedora
    // publish it; CentOS Stream historically does not, and plenty of internal
    // mirrors strip it. So it is probed for, and its absence is `unsupported`.
    `SP_UI=$("$SP_PMB" -C --quiet updateinfo summary 2>/dev/null || true)`,
    `SP_UIN=$(printf '%s\\n' "$SP_UI" | grep -c -E '[0-9]+[[:space:]]+(Security|Bugfix|Enhancement|New Package|Other)' || true)`,
    'if [ "$SP_UIN" -gt 0 ]; then',
    `sp_val security "$("$SP_PMB" -C --quiet --security check-update 2>/dev/null | grep -c -E '${PKG_ROW}' || true)"`,
    'sp_note security-updates ok - "this server\'s repositories publish updateinfo"',
    'elif [ "$SP_PEND" -gt 0 ]; then',
    'sp_note security-updates unsupported - "updateinfo returned nothing while updates are pending, so dnf would report zero security updates whether or not any exist"',
    'elif [ "$SP_PEND" = 0 ]; then',
    'sp_val security 0',
    'sp_note security-updates ok - "no packages are pending at all, so none of them can be a security update"',
    'else',
    'sp_note security-updates unknown - "pending updates could not be counted, so neither could security updates"',
    'fi',
    // needs-restarting -r: exit 1 means a reboot is owed, 0 means it is not.
    // Another exit-code API, and another reason exec's discarded code was not
    // good enough.
    'if [ "$SP_RB" = 0 ]; then',
    ...findBin('needs-restarting', 'SP_NR'),
    'SP_RC=127',
    'if [ -n "$SP_NR" ]; then "$SP_NR" -r >/dev/null 2>&1; SP_RC=$?',
    'else "$SP_PMB" needs-restarting -r >/dev/null 2>&1; SP_RC=$?',
    'fi',
    ...ifSudo(
      // Only when the unprivileged run answered neither 0 nor 1 — root does not
      // install a missing tool, so this is the one case worth a second trip.
      'if [ "$SP_RC" != 0 ] && [ "$SP_RC" != 1 ] && [ "$SP_SUDO" = 1 ] && [ -n "$SP_NR" ]; then',
      'sudo -n "$SP_NR" -r >/dev/null 2>&1',
      'SP_RC=$?',
      '[ "$SP_RC" = 0 ] || [ "$SP_RC" = 1 ] && SP_ROOT=root',
      'fi'
    ),
    'case "$SP_RC" in',
    '0) sp_val reboot no; sp_note reboot-required ok "${SP_ROOT:--}" "needs-restarting -r exited 0" ;;',
    '1) sp_val reboot yes; sp_note reboot-required ok "${SP_ROOT:--}" "needs-restarting -r exited 1" ;;',
    '*) sp_note reboot-required no-tool - "needs-restarting is not available on this server" ;;',
    'esac',
    'fi',
    'SP_MT=$(ls -t /var/cache/dnf/*/repodata/repomd.xml /var/cache/yum/*/*/repomd.xml 2>/dev/null | head -1)',
    'sp_mtime "$SP_MT"',

    // ---- zypper -----------------------------------------------------------
    'elif [ "$SP_PM" = zypper ]; then',
    // --no-refresh is the whole point: it forbids the repository refresh zypper
    // would otherwise do, which is a network operation.
    'SP_OUT=$("$SP_ZYP" --non-interactive --no-refresh list-updates 2>/dev/null)',
    'SP_RC=$?',
    'if [ "$SP_RC" = 0 ]; then',
    `SP_PEND=$(printf '%s\\n' "$SP_OUT" | grep -c -E '^v[[:space:]]*\\|' || true)`,
    'sp_val pending "$SP_PEND"',
    'sp_note updates ok - "zypper list-updates --no-refresh"',
    'else',
    'sp_note updates unknown - "zypper list-updates exited $SP_RC"',
    'fi',
    // The best security path of any manager: SUSE genuinely models patches by
    // category, so this is a real answer rather than a heuristic over origins.
    'SP_OUT=$("$SP_ZYP" --non-interactive --no-refresh list-patches --category security 2>/dev/null)',
    'SP_RC=$?',
    'if [ "$SP_RC" = 0 ]; then',
    `sp_val security "$(printf '%s\\n' "$SP_OUT" | grep -c -E '\\|[[:space:]]*security[[:space:]]*\\|' || true)"`,
    'sp_note security-updates ok - "zypper list-patches --category security"',
    'else',
    'sp_note security-updates unknown - "zypper list-patches exited $SP_RC"',
    'fi',
    'if [ "$SP_RB" = 0 ]; then',
    // 102 is zypper's "a reboot is needed" exit code. 100 and 101 mean updates
    // and security updates are needed respectively, neither of which is a reboot.
    '"$SP_ZYP" --non-interactive --no-refresh patch-check >/dev/null 2>&1',
    'SP_RC=$?',
    'case "$SP_RC" in',
    '102) sp_val reboot yes; sp_note reboot-required ok - "zypper patch-check exited 102" ;;',
    '0|100|101) sp_val reboot no; sp_note reboot-required ok - "zypper patch-check exited $SP_RC" ;;',
    '*) sp_note reboot-required unknown - "zypper patch-check exited $SP_RC" ;;',
    'esac',
    'fi',
    'SP_MT=$(ls -t /var/cache/zypp/raw/*/repodata/repomd.xml /var/cache/zypp/solv/*/cookie 2>/dev/null | head -1)',
    'sp_mtime "$SP_MT"',

    // ---- pacman -----------------------------------------------------------
    'elif [ "$SP_PM" = pacman ]; then',
    // -Qu reads the LOCAL sync database and nothing else. There is no -Sy here
    // and there never will be: `pacman -Sy` without a full upgrade creates the
    // partial-upgrade state that is the classic way to break an Arch box.
    // `checkupdates` from pacman-contrib is also refused — it syncs to a
    // temporary database, which is still a network fetch.
    'SP_OUT=$("$SP_PAC" -Qu 2>/dev/null)',
    'SP_RC=$?',
    'if [ "$SP_RC" = 0 ] || [ "$SP_RC" = 1 ]; then',
    `sp_val pending "$(printf '%s\\n' "$SP_OUT" | grep -c -E '^[^[:space:]]+[[:space:]]' || true)"`,
    'sp_note updates ok - "pacman -Qu, from the local sync database"',
    'else',
    'sp_note updates unknown - "pacman -Qu exited $SP_RC"',
    'fi',
    'sp_note security-updates unsupported - "Arch Linux has no security update channel, so this number cannot exist on any Arch server"',
    'if [ "$SP_RB" = 0 ]; then',
    'sp_note reboot-required unsupported - "Arch Linux publishes no reboot-required flag"',
    'fi',
    'sp_mtime /var/lib/pacman/sync/core.db',

    // ---- apk --------------------------------------------------------------
    'elif [ "$SP_PM" = apk ]; then',
    // --no-network is load-bearing. Without it apk fetches the repository
    // indexes when they are not cached, which is exactly the network operation
    // this collector refuses to perform.
    `SP_OUT=$("$SP_APK" version -l '<' --no-network 2>/dev/null)`,
    'SP_RC=$?',
    'if [ "$SP_RC" = 0 ]; then',
    `sp_val pending "$(printf '%s\\n' "$SP_OUT" | grep -c -E '[[:space:]]<[[:space:]]' || true)"`,
    `sp_note updates ok - "apk version -l '<' --no-network"`,
    'else',
    'sp_note updates unknown - "apk version exited $SP_RC"',
    'fi',
    'sp_note security-updates unsupported - "Alpine records security fixes in build metadata, not in the installed package index, so no count exists on the server"',
    'if [ "$SP_RB" = 0 ]; then',
    'sp_note reboot-required unsupported - "Alpine publishes no reboot-required flag"',
    'fi',
    'SP_MT=$(ls -t /var/cache/apk/*.tar.gz /var/cache/apk/* 2>/dev/null | head -1)',
    'sp_mtime "$SP_MT"',

    // ---- no package manager at all ---------------------------------------
    'else',
    'sp_note updates no-tool - "there is no package manager to ask"',
    'sp_note security-updates no-tool - "there is no package manager to ask"',
    'sp_note package-metadata no-tool - "there is no package manager whose metadata could be dated"',
    'if [ "$SP_RB" = 0 ]; then',
    'sp_note reboot-required unknown - "no package manager and no reboot-required flag"',
    'fi',
    'fi',

    // Printed once, at the end, from a variable nothing read out of a file ever
    // touched. This is the cron.ts discipline and it is the reason a
    // PRETTY_NAME cannot forge a security-update status.
    `printf '%s\\n%s' '${FACTS_STATUS_MARKER}' "$SP_STATUS"`
  ].join('\n')
}

/** The shipped command, built once. */
export const HOST_FACTS_COMMAND = buildHostFactsCommand()

// ---- Parsing --------------------------------------------------------------

/** The keys the collector may emit. Anything else is discarded rather than
 *  stored under a name the rest of the app would then have to distrust. */
const VALUE_KEYS = [
  'os-id',
  'os-version',
  'os-pretty',
  'arch',
  'cpu-model',
  'pkg',
  'pending',
  'security',
  'reboot',
  'reboot-pkgs',
  'virt',
  'meta-at'
] as const
type ValueKey = (typeof VALUE_KEYS)[number]

/**
 * os-release, parsed rather than sourced.
 *
 * The line arrives with its `KEY=` prefix intact so this can confirm which key
 * it is looking at rather than trusting the collector's ordering. Quoting
 * follows os-release's own rules: the value may be single- or double-quoted,
 * and inside double quotes `\\`, `\$`, `` \` `` and `\"` are escapes.
 */
export function parseOsReleaseValue(raw: string | undefined, key: string): string | null {
  if (!raw) return null
  const eq = raw.indexOf('=')
  if (eq === -1) return null
  if (raw.slice(0, eq).trim() !== key) return null
  let v = raw.slice(eq + 1).trim()
  const quote = v[0]
  if ((quote === '"' || quote === "'") && v.length >= 2 && v[v.length - 1] === quote) {
    v = v.slice(1, -1)
    if (quote === '"') v = v.replace(/\\([\\$`"])/g, '$1')
  }
  v = v.trim()
  return v === '' ? null : v
}

/** A count, or null. Never `0` as a stand-in for "could not read". */
function parseCount(raw: string | undefined): number | null {
  if (raw === undefined) return null
  const t = raw.trim()
  if (!/^\d{1,9}$/.test(t)) return null
  return Number(t)
}

/** An epoch-seconds timestamp. Wider than parseCount because a date is ten
 *  digits now and eleven from the year 2286 — a package count is not. */
function parseEpochSeconds(raw: string | undefined): number | null {
  if (raw === undefined) return null
  const t = raw.trim()
  if (!/^\d{1,11}$/.test(t)) return null
  return Number(t)
}

// Control characters, zero-width marks and the bidi overrides, stripped from
// every free-text field the host wrote.
//
// The collector already deletes control characters ON the host, which is what
// makes the output format unforgeable. This is a different job and it happens
// here because it CANNOT happen there: `tr -d '\000-\037\177'` operates on
// bytes and U+202E is three of them. A bidi override reorders what a human
// sees without changing what a parser reads — the wrong way round for anything
// a person is going to act on — so it is removed once, here, rather than left
// for each consumer to remember. mcpServer's remoteText strips it again on the
// way to an agent; a renderer gets it clean without having to know.
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

function parseStatusLine(line: string): FactSourceReport | null {
  const [id, status, readBy, ...rest] = line.trim().split(/\s+/)
  if (!FACT_SOURCE_IDS.includes(id as FactSourceId)) return null
  // The collector's own words, and they came off the host: a detail can carry
  // a filename or a tool's error message. Same treatment as any other free text.
  const detail = freeText(rest.join(' ').replace(/^"|"$/g, '')) ?? ''
  return {
    id: id as FactSourceId,
    label: FACT_SOURCE_LABEL[id as FactSourceId],
    // An unrecognised status becomes `unknown` rather than being passed
    // through: everything downstream switches on this, and a value outside the
    // union renders as nothing at all.
    status: FACT_STATUSES.includes(status as FactStatus) ? (status as FactStatus) : 'unknown',
    ...(readBy === 'root' ? { usedSudo: true } : {}),
    ...(detail === '' || detail === '-' ? {} : { detail })
  }
}

/**
 * Turn one collection into facts, with every null explained.
 *
 * Two things happen here that the collector deliberately does not do:
 *
 *  - A source the collector called `ok` is DOWNGRADED to `unknown` when the
 *    value it was reporting on is missing or unparseable. The shell says which
 *    probe ran; only this side can say whether its answer survived. That keeps
 *    the shell simple and keeps "the probe ran" and "the probe answered" from
 *    being conflated.
 *  - `package-metadata` is downgraded to `stale-metadata` when the timestamp is
 *    older than METADATA_STALE_MS. That is the second staleness axis, and it is
 *    computed against `now` rather than being baked into the output, so a
 *    stored fact re-read a week later is judged as of when it is read.
 */
export function parseHostFacts(output: string, now = Date.now()): HostFacts {
  const lines = output.split('\n')
  // The ONLY structural token. A value line always begins `V ` and never
  // contains a newline, so no value can ever equal this.
  const markerAt = lines.findIndex((l) => l.replace(/\r$/, '') === FACTS_STATUS_MARKER)

  const values = new Map<ValueKey, string>()
  for (const raw of lines.slice(0, markerAt === -1 ? lines.length : markerAt)) {
    const line = raw.replace(/\r$/, '')
    if (!line.startsWith('V ')) continue
    const rest = line.slice(2)
    const sp = rest.indexOf(' ')
    if (sp === -1) continue
    const key = rest.slice(0, sp)
    if (!(VALUE_KEYS as readonly string[]).includes(key)) continue
    // Last wins, matching the collector's own last-definition-wins reads.
    values.set(key as ValueKey, rest.slice(sp + 1))
  }

  const reported = new Map<FactSourceId, FactSourceReport>()
  if (markerAt !== -1) {
    for (const line of lines.slice(markerAt + 1)) {
      if (line.trim() === '') continue
      const s = parseStatusLine(line)
      if (s) reported.set(s.id, s)
    }
  }

  const source = (id: FactSourceId): FactSourceReport =>
    reported.get(id) ?? {
      id,
      label: FACT_SOURCE_LABEL[id],
      status: 'unknown' as const,
      detail:
        markerAt === -1
          ? 'the collector never returned its status block, so nothing here was confirmed'
          : 'the collector did not report on this source'
    }

  const rawId = parseOsReleaseValue(values.get('os-id'), 'ID')
  const distroVersion = freeText(parseOsReleaseValue(values.get('os-version'), 'VERSION_ID'))
  const prettyName = freeText(parseOsReleaseValue(values.get('os-pretty'), 'PRETTY_NAME'))

  // Allow-listed, not merely sanitised. `other` when the host named something
  // this build does not know — never dropped, because "an unfamiliar distro"
  // and "no ID at all" are different facts.
  let distroId: DistroId | null = null
  if (rawId !== null) {
    const lower = rawId.toLowerCase()
    distroId = (DISTRO_IDS as readonly string[]).includes(lower) ? (lower as DistroId) : 'other'
  }

  // Shape-validated rather than allow-listed: a new architecture is a thing
  // that happens, an architecture containing a space is not.
  const rawArch = values.get('arch')?.trim() ?? ''
  const arch = /^[A-Za-z0-9_]{1,32}$/.test(rawArch) ? rawArch : null

  const cpuModel = freeText(values.get('cpu-model'))

  const rawPm = values.get('pkg')?.trim() ?? ''
  // No `other` fallback. The collector emits one of six literals; anything else
  // did not come from the collector.
  const packageManager = (PACKAGE_MANAGERS as readonly string[]).includes(rawPm)
    ? (rawPm as PackageManager)
    : null

  const rawVirt = values.get('virt')?.trim().toLowerCase() ?? ''
  const virtualisation: Virtualisation | null =
    rawVirt === ''
      ? null
      : (VIRTUALISATIONS as readonly string[]).includes(rawVirt)
        ? (rawVirt as Virtualisation)
        : 'other'

  const pendingUpdates = parseCount(values.get('pending'))
  const securityUpdates = parseCount(values.get('security'))
  const rebootRaw = values.get('reboot')?.trim()
  const rebootRequired = rebootRaw === 'yes' ? true : rebootRaw === 'no' ? false : null
  const rebootReason = freeText(values.get('reboot-pkgs'))

  const metaSeconds = parseEpochSeconds(values.get('meta-at'))
  const metadataAt = metaSeconds === null ? null : metaSeconds * 1000

  // A probe the collector said `ok` about, whose value did not survive, is
  // `unknown` — not `ok` with a null next to it.
  const confirm = (id: FactSourceId, present: boolean, why: string): FactSourceReport => {
    const s = source(id)
    if (s.status !== 'ok' || present) return s
    return { ...s, status: 'unknown', detail: why }
  }

  let metadata = confirm(
    'package-metadata',
    metadataAt !== null,
    'the collector reported a metadata timestamp that could not be read as a date'
  )
  if (metadata.status === 'ok' && metadataAt !== null && now - metadataAt > METADATA_STALE_MS) {
    const days = Math.floor((now - metadataAt) / (24 * 60 * 60 * 1000))
    metadata = {
      ...metadata,
      status: 'stale-metadata',
      detail: `the package cache behind these counts was last refreshed ${days} day${days === 1 ? '' : 's'} ago`
    }
  }

  const sources: FactSourceReport[] = [
    confirm(
      'os-release',
      rawId !== null || prettyName !== null,
      'os-release was read and named neither an ID nor a pretty name'
    ),
    confirm('architecture', arch !== null, 'uname -m returned something that is not an architecture'),
    confirm('cpu', cpuModel !== null, '/proc/cpuinfo was read and named no model'),
    confirm('virtualisation', virtualisation !== null, 'the virtualisation probe returned nothing usable'),
    confirm(
      'package-manager',
      packageManager !== null,
      'the collector named a package manager that is not one of the six it can detect'
    ),
    confirm('updates', pendingUpdates !== null, 'the update count could not be read as a number'),
    confirm('security-updates', securityUpdates !== null, 'the security update count could not be read as a number'),
    confirm('reboot-required', rebootRequired !== null, 'the reboot probe returned neither yes nor no'),
    metadata
  ]

  return {
    distroId,
    distroVersion,
    prettyName,
    arch,
    cpuModel,
    packageManager,
    pendingUpdates,
    securityUpdates,
    rebootRequired,
    rebootReason,
    virtualisation,
    metadataAt,
    collectedAt: now,
    sources
  }
}

// ---- Storage --------------------------------------------------------------

/**
 * The prefix every host fact is stored under in the durable store (item A).
 *
 * A prefix rather than loose keys because `retireFacts` sweeps by prefix: a
 * host that changes package manager — or stops being able to answer a question
 * it used to answer — must lose the old key rather than keeping it forever next
 * to a fresher one.
 */
export const HOST_FACT_PREFIX = 'host:'

/**
 * Facts as the store wants them: string keys, string values.
 *
 * A null is written as its STATUS, never as an empty string or a zero. That is
 * what makes `host:securityUpdates = unsupported` survive into history, so a
 * report written six months from now can still tell "this host had no security
 * updates" from "this host could never have told us".
 */
export function hostFactsToFacts(facts: HostFacts): Record<string, string> {
  const out: Record<string, string> = {}
  const put = (key: string, value: string | number | boolean | null, id: FactSourceId): void => {
    out[`${HOST_FACT_PREFIX}${key}`] = value === null ? factSource(facts, id).status : String(value)
  }
  put('distroId', facts.distroId, 'os-release')
  put('distroVersion', facts.distroVersion, 'os-release')
  put('prettyName', facts.prettyName, 'os-release')
  put('arch', facts.arch, 'architecture')
  put('cpuModel', facts.cpuModel, 'cpu')
  put('packageManager', facts.packageManager, 'package-manager')
  put('pendingUpdates', facts.pendingUpdates, 'updates')
  put('securityUpdates', facts.securityUpdates, 'security-updates')
  put('rebootRequired', facts.rebootRequired, 'reboot-required')
  put('virtualisation', facts.virtualisation, 'virtualisation')
  if (facts.rebootReason !== null) out[`${HOST_FACT_PREFIX}rebootReason`] = facts.rebootReason
  // Both staleness axes, stored. Without metadataAt the counts read as current
  // forever, which is the lie this item exists to prevent.
  out[`${HOST_FACT_PREFIX}metadataAt`] =
    facts.metadataAt === null ? factSource(facts, 'package-metadata').status : String(facts.metadataAt)
  // The status of every source, so history can say why a null was null at the
  // time rather than only that it was null.
  for (const s of facts.sources) out[`${HOST_FACT_PREFIX}source:${s.id}`] = s.status
  return out
}
