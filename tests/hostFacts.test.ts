import { describe, it, expect, beforeEach, afterAll } from 'vitest'
import { execFileSync } from 'node:child_process'
import { chmodSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import {
  FACTS_STATUS_MARKER,
  FACT_STATUS_HELP,
  HOST_FACTS_COMMAND,
  METADATA_STALE_MS,
  buildHostFactsCommand,
  factSource,
  hostFactsToFacts,
  parseHostFacts,
  parseOsReleaseValue
} from '../src/shared/hostFacts'
import type { FactSourceId, HostFacts } from '../src/shared/hostFacts'
import { HostFactsReader } from '../src/main/services/hostFacts'

// ---------------------------------------------------------------------------
// PROVENANCE, stated rather than assumed — the rule tests/fixtures/docker's
// README sets out, applied here because this file needs it more.
//
// Two kinds of input appear below and they are NOT equally trustworthy:
//
//   * The COLLECTOR'S OWN OUTPUT (`V key value` lines and the status block) is
//     ShellPilot's format, not a vendor's. Writing it by hand in a test is
//     writing the format down twice, which is exactly what a parser test is
//     for.
//
//   * The PACKAGE MANAGERS' output is a vendor format, and NONE of it was
//     captured from a real host in the session that wrote this file. There was
//     no Debian, Rocky, SUSE, Arch or Alpine host to run against. The fake
//     binaries below reproduce the *shape* each tool documents — apt-check's
//     `updates;security` on stderr, an `Inst … Debian-Security:… -security`
//     line, dnf's three-column check-update rows and its exit 100, zypper's
//     `v |` and `| security |` table rows, `needs-restarting -r`'s 0/1, apk's
//     ` < ` lines — reconstructed from documentation and memory rather than
//     recorded.
//
//     So what the harness below PROVES is the shell: whether the collector
//     calls the right thing, whether `|| true` is in the right place, whether
//     an exit code is read rather than discarded, and whether `unsupported`
//     really is reported instead of a zero. What it does NOT prove is that a
//     real `zypper list-patches` on SLE 15 SP6 prints the columns in that
//     order. Those column assumptions are unverified and are the first thing to
//     check against a real host.
//
//     The dnf `updateinfo` case is the one where this matters least, happily:
//     the branch that matters is "updateinfo answered NOTHING", and an empty
//     answer has no format to get wrong.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// The command, read as a document
// ---------------------------------------------------------------------------

describe('the shipped collector, as text', () => {
  it('contains no sudo at all when built without it', () => {
    // Mirrors tests/cron.test.ts. The point of omitting sudo at BUILD time
    // rather than guarding it at runtime is that this assertion is possible: a
    // dead `[ "$SP_SUDO" = 1 ]` branch would never run, but nobody could check
    // that by reading the command.
    expect(buildHostFactsCommand({ sudo: false })).not.toMatch(/\bsudo\b/)
  })

  it('escalates only with sudo -n, which cannot prompt', () => {
    const sudos = HOST_FACTS_COMMAND.match(/\bsudo\b[^\n]*/g) ?? []
    expect(sudos.length, 'no sudo at all — this assertion checked nothing').toBeGreaterThan(0)
    for (const line of sudos) expect(line, line).toMatch(/sudo -n\b/)
  })

  it('never sources os-release', () => {
    // `. /etc/os-release` on a host under an attacker's control is arbitrary
    // code execution as the SSH user. It is read and parsed in TypeScript.
    expect(HOST_FACTS_COMMAND).not.toMatch(/(^|[\s;(])\.\s+\/(etc|usr\/lib)\/os-release/)
    expect(HOST_FACTS_COMMAND).not.toMatch(/\bsource\b/)
  })

  it('never mutates: no cache refresh reaches the network', () => {
    // Each of these hits the network and takes seconds, and `pacman -Sy`
    // creates the partial-upgrade state that is the classic way to break an
    // Arch box. `apt … update` is ELEVATED in shared/broadcast.ts — a
    // background probe must not do what the panel would make a human confirm.
    // A space after the binary name, so `/var/lib/apt/periodic/update-success-stamp`
    // — a path this DOES read — is not mistaken for `apt-get update`.
    expect(HOST_FACTS_COMMAND).not.toMatch(/\bapt(-get)?\s+[^\n]*\bupdate\b/)
    expect(HOST_FACTS_COMMAND).not.toMatch(/-Sy/)
    expect(HOST_FACTS_COMMAND).not.toMatch(/\bmakecache\b/)
    expect(HOST_FACTS_COMMAND).not.toMatch(/\bcheckupdates\b/)
    // zypper refreshes by default, so the absence of a refresh verb is not
    // enough — every invocation has to forbid it explicitly.
    // `(?! \])` skips the `[ -n "$SP_ZYP" ]` detection line and leaves only the
    // lines that actually RUN the binary.
    const invocations = (v: string): string[] => HOST_FACTS_COMMAND.match(new RegExp(`"\\$${v}"(?! \\])[^\n]*`, 'g')) ?? []
    const zypper = invocations('SP_ZYP')
    expect(zypper.length, 'no zypper invocation found — this checked nothing').toBeGreaterThan(0)
    for (const line of zypper) expect(line, line).toMatch(/--no-refresh/)
    // dnf reads the cache only.
    const dnf = invocations('SP_PMB')
    expect(dnf.length, 'no dnf invocation found — this checked nothing').toBeGreaterThan(0)
    for (const line of dnf) expect(line, line).toMatch(/(-C\b|needs-restarting)/)
    // apk fetches indexes it has not cached unless told not to.
    const apk = invocations('SP_APK')
    expect(apk.length, 'no apk invocation found — this checked nothing').toBeGreaterThan(0)
    for (const line of apk) expect(line, line).toMatch(/--no-network/)
  })

  it('has no set -e, so one missing tool cannot end the collection', () => {
    expect(HOST_FACTS_COMMAND).not.toMatch(/set -e/)
  })

  it('prints its status block last, from a variable', () => {
    // The cron.ts discipline: statuses are accumulated in SP_STATUS and printed
    // once at the end, where nothing read out of a file has ever been.
    expect(HOST_FACTS_COMMAND.trimEnd().endsWith('"$SP_STATUS"')).toBe(true)
  })

  it('strips control characters from every value on the server', () => {
    // The single defence that makes the format unforgeable: a value can never
    // become a second line, so it can never invent a key or a status.
    expect(HOST_FACTS_COMMAND).toMatch(/sp_val\(\)[^\n]*tr -d '\\000-\\037\\177'/)
  })
})

// ---------------------------------------------------------------------------
// os-release, parsed rather than sourced
// ---------------------------------------------------------------------------

describe('os-release values', () => {
  it('reads the quoted form Debian and Ubuntu actually write', () => {
    expect(parseOsReleaseValue('PRETTY_NAME="Debian GNU/Linux 12 (bookworm)"', 'PRETTY_NAME')).toBe(
      'Debian GNU/Linux 12 (bookworm)'
    )
    expect(parseOsReleaseValue('ID=debian', 'ID')).toBe('debian')
    expect(parseOsReleaseValue('VERSION_ID="12"', 'VERSION_ID')).toBe('12')
  })

  it('unescapes what a shell would have unescaped, without running a shell', () => {
    expect(parseOsReleaseValue('PRETTY_NAME="a \\"quoted\\" name"', 'PRETTY_NAME')).toBe('a "quoted" name')
    expect(parseOsReleaseValue('PRETTY_NAME="cost \\$5 \\\\ back"', 'PRETTY_NAME')).toBe('cost $5 \\ back')
  })

  it('refuses a line whose key is not the one asked for', () => {
    // The collector emits the `KEY=` prefix so this can confirm which key it is
    // looking at rather than trusting position. A host that reorders its
    // os-release cannot make its ID land in the pretty name.
    expect(parseOsReleaseValue('ID=debian', 'PRETTY_NAME')).toBeNull()
    expect(parseOsReleaseValue('nonsense', 'ID')).toBeNull()
    expect(parseOsReleaseValue(undefined, 'ID')).toBeNull()
  })

  it('treats an empty value as absent rather than as an empty name', () => {
    expect(parseOsReleaseValue('PRETTY_NAME=""', 'PRETTY_NAME')).toBeNull()
  })
})

// ---------------------------------------------------------------------------
// The parser
// ---------------------------------------------------------------------------

const NOW = Date.parse('2026-09-03T12:00:00Z')

/** Build collector-shaped output. This is ShellPilot's own format, so writing
 *  it here is writing the format down twice — which is the point. */
function collected(values: Record<string, string>, statuses: string[]): string {
  return [
    ...Object.entries(values).map(([k, v]) => `V ${k} ${v}`),
    FACTS_STATUS_MARKER,
    ...statuses
  ].join('\n')
}

const DEBIAN_VALUES = {
  'os-id': 'ID=debian',
  'os-version': 'VERSION_ID="12"',
  'os-pretty': 'PRETTY_NAME="Debian GNU/Linux 12 (bookworm)"',
  arch: 'x86_64',
  'cpu-model': ' Intel(R) Xeon(R) CPU E5-2670 v3 @ 2.30GHz',
  pkg: 'apt',
  pending: '7',
  security: '2',
  reboot: 'yes',
  'reboot-pkgs': 'linux-image-6.1.0-23-amd64 libssl3 ',
  virt: 'kvm',
  'meta-at': String(Math.floor((NOW - 3_600_000) / 1000))
}

const DEBIAN_STATUSES = [
  'os-release ok - /etc/os-release',
  'architecture ok -',
  'cpu ok -',
  'virtualisation ok -',
  'package-manager ok -',
  'updates ok - apt-check',
  'security-updates ok - apt-check',
  'reboot-required ok - the reboot-required flag file is present',
  'package-metadata ok - /var/lib/apt/periodic/update-success-stamp'
]

const status = (f: HostFacts, id: FactSourceId): string => factSource(f, id).status

describe('parsing a collection', () => {
  it('reads a complete apt server', () => {
    const f = parseHostFacts(collected(DEBIAN_VALUES, DEBIAN_STATUSES), NOW)
    expect(f.distroId).toBe('debian')
    expect(f.distroVersion).toBe('12')
    expect(f.prettyName).toBe('Debian GNU/Linux 12 (bookworm)')
    expect(f.arch).toBe('x86_64')
    expect(f.cpuModel).toBe('Intel(R) Xeon(R) CPU E5-2670 v3 @ 2.30GHz')
    expect(f.packageManager).toBe('apt')
    expect(f.pendingUpdates).toBe(7)
    expect(f.securityUpdates).toBe(2)
    expect(f.rebootRequired).toBe(true)
    expect(f.rebootReason).toBe('linux-image-6.1.0-23-amd64 libssl3')
    expect(f.virtualisation).toBe('kvm')
    expect(f.collectedAt).toBe(NOW)
    expect(f.sources.every((s) => s.status === 'ok')).toBe(true)
  })

  it('keeps a real zero as a zero', () => {
    // The other half of the honesty requirement, and the easy one to lose while
    // fixing the hard one: a fully patched host must report 0, not "unknown".
    const f = parseHostFacts(
      collected({ ...DEBIAN_VALUES, pending: '0', security: '0' }, DEBIAN_STATUSES),
      NOW
    )
    expect(f.pendingUpdates).toBe(0)
    expect(f.securityUpdates).toBe(0)
    expect(status(f, 'security-updates')).toBe('ok')
  })

  it('reports an unsupported security count as null, never as zero', () => {
    // THE test. On Arch and Alpine this number cannot exist, and on a dnf host
    // whose repositories publish no updateinfo it reads as zero when it is not.
    const { security: _drop, ...noSecurity } = DEBIAN_VALUES
    const f = parseHostFacts(
      collected({ ...noSecurity, pkg: 'pacman' }, [
        ...DEBIAN_STATUSES.filter((s) => !s.startsWith('security-updates')),
        'security-updates unsupported - Arch Linux has no security update channel'
      ]),
      NOW
    )
    expect(f.securityUpdates).toBeNull()
    expect(status(f, 'security-updates')).toBe('unsupported')
    // And the help string must not read as reassurance.
    expect(FACT_STATUS_HELP.unsupported).toMatch(/never as zero/i)
  })

  it('downgrades a probe that claimed ok but produced no readable number', () => {
    // The shell says which probe ran; only this side can say whether its answer
    // survived. A source left at `ok` with a null beside it would be the exact
    // conflation this file exists to prevent.
    const f = parseHostFacts(collected({ ...DEBIAN_VALUES, security: 'lots' }, DEBIAN_STATUSES), NOW)
    expect(f.securityUpdates).toBeNull()
    expect(status(f, 'security-updates')).toBe('unknown')
    expect(status(f, 'updates')).toBe('ok')
  })

  it('marks metadata stale on its own axis, without touching the counts', () => {
    const old = String(Math.floor((NOW - METADATA_STALE_MS - 33 * 24 * 3600_000) / 1000))
    const f = parseHostFacts(collected({ ...DEBIAN_VALUES, 'meta-at': old }, DEBIAN_STATUSES), NOW)
    // The counts are still what the host said. They are not deleted, they are
    // qualified — "0 pending updates from a cache refreshed 40 days ago" needs
    // both halves to be a useful sentence.
    expect(f.pendingUpdates).toBe(7)
    expect(status(f, 'updates')).toBe('ok')
    expect(status(f, 'package-metadata')).toBe('stale-metadata')
    expect(factSource(f, 'package-metadata').detail).toMatch(/40 days ago/)
  })

  it('judges staleness against the clock it is read with, not the one it was collected with', () => {
    // Facts are stored and re-read later. A staleness flag baked in at
    // collection time would still say "fresh" a month afterwards.
    const out = collected(DEBIAN_VALUES, DEBIAN_STATUSES)
    expect(status(parseHostFacts(out, NOW), 'package-metadata')).toBe('ok')
    expect(status(parseHostFacts(out, NOW + METADATA_STALE_MS * 2), 'package-metadata')).toBe(
      'stale-metadata'
    )
  })

  it('reports every source unknown when the status block never arrived', () => {
    // Output cut by the transport cap, or a shell that never ran the script. A
    // list that quietly shrank to four sources would read as complete.
    const f = parseHostFacts('V arch x86_64\nV pending 7', NOW)
    expect(f.sources).toHaveLength(9)
    expect(f.sources.every((s) => s.status === 'unknown')).toBe(true)
    expect(factSource(f, 'updates').detail).toMatch(/never returned its status block/)
  })

  it('fills in a source the collector said nothing about', () => {
    const f = parseHostFacts(collected(DEBIAN_VALUES, ['architecture ok -']), NOW)
    expect(status(f, 'virtualisation')).toBe('unknown')
    expect(factSource(f, 'virtualisation').detail).toMatch(/did not report on this source/)
  })

  it('records that a probe was read as root', () => {
    const f = parseHostFacts(
      collected(DEBIAN_VALUES, [...DEBIAN_STATUSES.slice(0, 7), 'reboot-required ok root exited 1']),
      NOW
    )
    expect(factSource(f, 'reboot-required').usedSudo).toBe(true)
  })
})

describe('the three allow-lists', () => {
  it('keeps an unfamiliar distro as `other` rather than dropping it', () => {
    const f = parseHostFacts(collected({ ...DEBIAN_VALUES, 'os-id': 'ID=hypothetixos' }, DEBIAN_STATUSES), NOW)
    // Not null: "an unfamiliar distro" and "no ID at all" are different facts,
    // and the pretty name still carries the host's own words.
    expect(f.distroId).toBe('other')
  })

  it('refuses a package manager the collector could not have emitted', () => {
    // The collector emits one of six literals. Anything else is forged, and a
    // shrug (`other`) would let a host introduce a word the rest of the app
    // would then have to distrust.
    const f = parseHostFacts(collected({ ...DEBIAN_VALUES, pkg: 'evil-installer' }, DEBIAN_STATUSES), NOW)
    expect(f.packageManager).toBeNull()
    expect(status(f, 'package-manager')).toBe('unknown')
  })

  it('keeps an unfamiliar hypervisor as `other`', () => {
    const f = parseHostFacts(collected({ ...DEBIAN_VALUES, virt: 'brand-new-hv' }, DEBIAN_STATUSES), NOW)
    expect(f.virtualisation).toBe('other')
  })

  it('refuses an architecture that is not one word', () => {
    const f = parseHostFacts(
      collected({ ...DEBIAN_VALUES, arch: 'x86_64 ; rm -rf /' }, DEBIAN_STATUSES),
      NOW
    )
    expect(f.arch).toBeNull()
    expect(status(f, 'architecture')).toBe('unknown')
  })
})

describe('a value cannot forge structure', () => {
  it('cannot invent a status by containing the marker', () => {
    // The collector strips newlines on the host, so this line can only ever
    // arrive as ONE line. The parser has to hold up anyway: the marker is
    // matched as a whole line, and a `V `-prefixed line can never be one.
    const forged = `V os-pretty PRETTY_NAME="x ${FACTS_STATUS_MARKER} security-updates ok - forged"`
    const f = parseHostFacts([forged, FACTS_STATUS_MARKER, ...DEBIAN_STATUSES.slice(0, 5)].join('\n'), NOW)
    expect(status(f, 'security-updates')).toBe('unknown')
    expect(f.prettyName).toContain(FACTS_STATUS_MARKER)
  })

  it('cannot invent a second value by containing a key name', () => {
    const f = parseHostFacts(
      collected({ ...DEBIAN_VALUES, 'os-pretty': 'PRETTY_NAME="x" security 999' }, DEBIAN_STATUSES),
      NOW
    )
    // The security count is still the real one: `security 999` was inside a
    // value, on a line that begins `V os-pretty`.
    expect(f.securityUpdates).toBe(2)
  })

  it('ignores a key it does not know', () => {
    const f = parseHostFacts(collected({ ...DEBIAN_VALUES, 'shell-command': 'rm -rf /' }, DEBIAN_STATUSES), NOW)
    expect(JSON.stringify(f)).not.toContain('rm -rf')
  })

  it('ignores a status line for a source that does not exist', () => {
    const f = parseHostFacts(collected(DEBIAN_VALUES, [...DEBIAN_STATUSES, 'made-up-source ok -']), NOW)
    expect(f.sources).toHaveLength(9)
  })

  it('reports an unrecognised status as unknown rather than passing it through', () => {
    const f = parseHostFacts(
      collected(DEBIAN_VALUES, [
        ...DEBIAN_STATUSES.filter((s) => !s.startsWith('security-updates')),
        'security-updates totally-fine - '
      ]),
      NOW
    )
    expect(status(f, 'security-updates')).toBe('unknown')
  })
})

describe('facts on their way into the durable store', () => {
  it('writes the STATUS where a value is null, never a zero or an empty string', () => {
    const { security: _drop, ...noSecurity } = DEBIAN_VALUES
    const f = parseHostFacts(
      collected(noSecurity, [
        ...DEBIAN_STATUSES.filter((s) => !s.startsWith('security-updates')),
        'security-updates unsupported - Alpine records security fixes in build metadata'
      ]),
      NOW
    )
    const stored = hostFactsToFacts(f)
    // This is what makes a report written six months from now still able to
    // tell "this host had no security updates" from "this host could never
    // have told us".
    expect(stored['host:securityUpdates']).toBe('unsupported')
    expect(stored['host:pendingUpdates']).toBe('7')
    expect(stored['host:source:security-updates']).toBe('unsupported')
  })

  it('writes a key for every field, so retirement never half-empties a server', () => {
    const f = parseHostFacts('', NOW)
    const stored = hostFactsToFacts(f)
    // A completely failed probe still produces a full key set. The sampler
    // retires by prefix against exactly these keys, so a short set would delete
    // the rest of the inventory and record a fact-removed event for each.
    expect(Object.keys(stored)).toContain('host:distroId')
    expect(Object.keys(stored)).toContain('host:metadataAt')
    expect(stored['host:distroId']).toBe('unknown')
    expect(stored['host:metadataAt']).toBe('unknown')
  })

  it('stores both staleness axes', () => {
    const f = parseHostFacts(collected(DEBIAN_VALUES, DEBIAN_STATUSES), NOW)
    expect(hostFactsToFacts(f)['host:metadataAt']).toBe(String(f.metadataAt))
  })
})

// ---------------------------------------------------------------------------
// The reader, and its three-way failure classification
// ---------------------------------------------------------------------------

describe('the reader', () => {
  it('calls a transport failure a transport failure', () => {
    // Saying "this host has no package manager" when the connection never
    // opened would put a fabricated inventory row in front of an operator.
    const reader = new HostFactsReader({
      exec: async () => ({ ok: false, error: 'connect ECONNREFUSED' })
    })
    return reader.read({}).then((r) => {
      expect(r).toEqual({ ok: false, reason: 'unreachable', detail: 'connect ECONNREFUSED' })
    })
  })

  it('tells "the server said nothing" apart from "the server said it could not see"', async () => {
    const reader = new HostFactsReader({
      exec: async () => ({ ok: true, code: 127, stdout: '', stderr: 'sh: not found' })
    })
    const r = await reader.read({})
    expect(r.ok).toBe(false)
    if (!r.ok) {
      expect(r.reason).toBe('no-output')
      expect(r.detail).toBe('sh: not found')
    }
  })

  it('treats a collection full of unknowns as a success, because it is one', async () => {
    // Nine sources that each say why they saw nothing is a complete answer, and
    // the most useful one this feature produces on a locked-down host.
    const reader = new HostFactsReader({
      exec: async () => ({
        ok: true,
        code: 0,
        stdout: collected({}, ['os-release denied -', 'cpu denied -'])
      }),
      now: () => NOW
    })
    const r = await reader.read({})
    expect(r.ok).toBe(true)
    if (r.ok) {
      expect(status(r.facts, 'os-release')).toBe('denied')
      expect(r.facts.collectedAt).toBe(NOW)
    }
  })

  it('does not merge stderr into the value region', async () => {
    // Every probe in the collector redirects its own stderr away, so anything
    // left there came from the shell. Merging it would let a noisy login
    // profile write a `V ` line into the facts.
    const reader = new HostFactsReader({
      exec: async () => ({
        ok: true,
        code: 0,
        stdout: collected(DEBIAN_VALUES, DEBIAN_STATUSES),
        stderr: 'V security 0\nV pkg pacman'
      }),
      now: () => NOW
    })
    const r = await reader.read({})
    expect(r.ok && r.facts.securityUpdates).toBe(2)
    expect(r.ok && r.facts.packageManager).toBe('apt')
  })

  it('passes the sudo option through to the command it sends', async () => {
    let sent = ''
    const reader = new HostFactsReader({
      exec: async (_cfg, command) => {
        sent = command
        return { ok: true, code: 0, stdout: collected({}, []) }
      }
    })
    await reader.read({}, { sudo: false })
    expect(sent).not.toMatch(/\bsudo\b/)
  })
})

// ---------------------------------------------------------------------------
// The collector, actually run.
//
// Everything above tests strings. That is not enough here: the whole feature is
// a SHELL script that has to tell "zero security updates" from "this host
// cannot count security updates", and a shell script is exactly the kind of
// thing that reads correctly and does the wrong thing. So these run the REAL
// shipped command through /bin/sh against a directory tree built to look like a
// host, with the absolute paths redirected into it and every package manager
// hidden unless the test provides one.
//
// Hiding is not optional politeness: without it, running this suite on a Debian
// CI box would find the CI box's own apt and the tree under `root` would stop
// being the only thing measured.
// ---------------------------------------------------------------------------

/** Paths the collector reads, redirected into the fake tree in ONE pass so that
 *  /var/run/reboot-required is not rewritten twice via its /run/ substring. */
const ABS_PATHS =
  /\/(?:etc\/os-release|usr\/lib\/os-release|proc\/cpuinfo|var\/run\/reboot-required|run\/reboot-required|var\/lib\/apt|var\/lib\/pacman|var\/cache\/(?:dnf|yum|zypp|apk)|usr\/lib\/update-notifier|usr\/share\/update-notifier|\.dockerenv|run\/\.containerenv)/g

const HIDEABLE = [
  'apt-get',
  'dnf',
  'zypper',
  'pacman',
  'apk',
  'yum',
  'systemd-detect-virt',
  'needs-restarting'
]

interface FakeHost {
  root: string
  bin: string
  file: (rel: string, body: string) => void
  script: (name: string, body: string) => void
  collect: (opts?: { sudo?: boolean; have?: string[]; env?: Record<string, string> }) => HostFacts
}

function fakeHost(): FakeHost {
  const root = mkdtempSync(join(tmpdir(), 'sp-facts-'))
  const bin = join(root, 'bin')
  mkdirSync(bin, { recursive: true })

  const file = (rel: string, body: string): void => {
    const f = join(root, rel)
    mkdirSync(join(f, '..'), { recursive: true })
    writeFileSync(f, body)
  }
  const script = (name: string, body: string): void => {
    const f = join(bin, name)
    writeFileSync(f, `#!/bin/sh\n${body}\n`)
    chmodSync(f, 0o755)
  }

  // A `stat` that answers `-c %Y` on every platform. macOS has no GNU stat and
  // its `date -r` takes seconds rather than a file, so without this the
  // metadata-age branch could only be tested on Linux — and the branch worth
  // testing is the collector's handling of the answer, not GNU coreutils.
  script(
    'stat',
    '[ "$1" = "-c" ] && [ "$2" = "%Y" ] && { [ -e "$3" ] && { echo "${SP_MTIME:-1756900000}"; exit 0; }; exit 1; }\nexit 1'
  )
  // A sudo that behaves like the real one in the only ways that matter: it
  // refuses to do anything without -n, and answers the probe.
  script(
    'sudo',
    '[ "$1" = "-n" ] || { echo "sudo: a password is required" >&2; exit 1; }\nshift\n' +
      '[ "$1" = "true" ] && exit 0\nexec "$@"'
  )

  return {
    root,
    bin,
    file,
    script,
    collect: ({ sudo = true, have = [], env = {} } = {}) => {
      let cmd = buildHostFactsCommand({ sudo }).replace(ABS_PATHS, (m) => root + m)
      for (const name of HIDEABLE) {
        if (have.includes(name)) continue
        cmd = cmd
          .replace(new RegExp(`for c in ${name}[^;]*;`), `for c in sp-absent-${name};`)
          .replace(new RegExp(`SP_BIN=${name}(?=[\\s;]|$)`), `SP_BIN=sp-absent-${name}`)
      }
      const out = execFileSync('/bin/sh', ['-c', cmd], {
        encoding: 'utf8',
        env: { PATH: `${bin}:/usr/bin:/bin`, ...env }
      })
      return parseHostFacts(out, NOW)
    }
  }
}

const trees: string[] = []
afterAll(() => {
  for (const t of trees) rmSync(t, { recursive: true, force: true })
})

describe.skipIf(process.platform === 'win32')('the collector, run against a host-shaped tree', () => {
  let host: FakeHost

  beforeEach(() => {
    host = fakeHost()
    trees.push(host.root)
    host.file(
      'etc/os-release',
      'PRETTY_NAME="Debian GNU/Linux 12 (bookworm)"\nNAME="Debian GNU/Linux"\nVERSION_ID="12"\nID=debian\n'
    )
    host.file(
      'proc/cpuinfo',
      'processor\t: 0\nvendor_id\t: GenuineIntel\nmodel name\t: Intel(R) Xeon(R) CPU E5-2670 v3 @ 2.30GHz\ncache size\t: 30720 KB\n'
    )
  })

  it('reads a server with nothing on it, and says so nine times over', () => {
    const f = host.collect()
    expect(f.distroId).toBe('debian')
    expect(f.prettyName).toBe('Debian GNU/Linux 12 (bookworm)')
    expect(f.cpuModel).toBe('Intel(R) Xeon(R) CPU E5-2670 v3 @ 2.30GHz')
    expect(f.arch).not.toBeNull()
    // No package manager at all — a container, or something minimal. Every
    // update field is a null with a reason, not a zero.
    expect(f.packageManager).toBeNull()
    expect(f.pendingUpdates).toBeNull()
    expect(f.securityUpdates).toBeNull()
    expect(status(f, 'package-manager')).toBe('no-tool')
    expect(status(f, 'updates')).toBe('no-tool')
    expect(status(f, 'security-updates')).toBe('no-tool')
    expect(status(f, 'virtualisation')).toBe('no-tool')
  })

  it('says `denied` rather than `absent` when os-release exists and cannot be read', () => {
    // The distinction cron.ts was built around: "nothing here" and "I was not
    // allowed to look" are different answers and only one is good news.
    chmodSync(join(host.root, 'etc/os-release'), 0o000)
    const f = host.collect()
    // Running as root would defeat this; skip rather than assert a falsehood.
    if (status(f, 'os-release') === 'ok') return
    expect(status(f, 'os-release')).toBe('denied')
    expect(f.prettyName).toBeNull()
  })

  it('runs with no sudo in the command at all', () => {
    const f = host.collect({ sudo: false })
    expect(f.distroId).toBe('debian')
  })

  // ---- apt --------------------------------------------------------------

  const APT_UPGRADE = [
    'case "$*" in',
    '  *upgrade*)',
    "    cat <<'EOF'",
    'NOTE: This is only a simulation!',
    'Reading package lists...',
    'Inst libc6 [2.36-9+deb12u3] (2.36-9+deb12u7 Debian:12/stable [amd64])',
    'Inst openssl [3.0.11-1] (3.0.15-1~deb12u1 Debian-Security:12/stable-security [amd64])',
    'Inst libssl3 [3.0.11-1] (3.0.15-1~deb12u1 Debian-Security:12/stable-security [amd64])',
    'Inst tzdata [2024a-0+deb12u1] (2025b-0+deb12u1 Debian:12/stable [all])',
    'Conf libc6 (2.36-9+deb12u7 Debian:12/stable [amd64])',
    'EOF',
    '    exit 0 ;;',
    'esac',
    'exit 1'
  ].join('\n')

  it('counts apt updates from the simulation, and the security ones by origin', () => {
    host.script('apt-get', APT_UPGRADE)
    host.file('var/lib/apt/periodic/update-success-stamp', '')
    const f = host.collect({ have: ['apt-get'] })
    expect(f.packageManager).toBe('apt')
    expect(f.pendingUpdates).toBe(4)
    // Two of the four come from a -security origin.
    expect(f.securityUpdates).toBe(2)
    expect(status(f, 'security-updates')).toBe('ok')
    expect(f.metadataAt).toBe(1756900000 * 1000)
  })

  it('prefers apt-check, which is what Ubuntu counts with', () => {
    host.script('apt-get', APT_UPGRADE)
    const check = join(host.root, 'usr/lib/update-notifier/apt-check')
    mkdirSync(join(check, '..'), { recursive: true })
    // Real apt-check writes `<updates>;<security>` to STDERR, which is why the
    // collector redirects it.
    writeFileSync(check, '#!/bin/sh\nprintf "9;3" >&2\n')
    chmodSync(check, 0o755)
    const f = host.collect({ have: ['apt-get'] })
    expect(f.pendingUpdates).toBe(9)
    expect(f.securityUpdates).toBe(3)
    expect(factSource(f, 'updates').detail).toBe('apt-check')
  })

  it('does not believe an apt-check that crashed', () => {
    // A pipeline's exit status is `tail`'s, so an `if apt-check | tail -1` would
    // take the branch even when apt-check printed a traceback. The fallback has
    // to run instead.
    host.script('apt-get', APT_UPGRADE)
    const check = join(host.root, 'usr/lib/update-notifier/apt-check')
    mkdirSync(join(check, '..'), { recursive: true })
    writeFileSync(check, '#!/bin/sh\necho "Traceback (most recent call last):" >&2\nexit 1\n')
    chmodSync(check, 0o755)
    const f = host.collect({ have: ['apt-get'] })
    expect(f.pendingUpdates).toBe(4)
    expect(factSource(f, 'updates').detail).toMatch(/apt-get -s upgrade/)
  })

  it('reports metadata age as its own staleness axis, and flags it when old', () => {
    host.script('apt-get', APT_UPGRADE)
    host.file('var/lib/apt/periodic/update-success-stamp', '')
    const fortyDaysAgo = Math.floor((NOW - 40 * 24 * 3600_000) / 1000)
    const f = host.collect({ have: ['apt-get'], env: { SP_MTIME: String(fortyDaysAgo) } })
    // "0 pending updates" from a cache refreshed forty days ago is a lie; four
    // pending updates from one is only half an answer. The counts survive, the
    // staleness is stated next to them.
    expect(f.pendingUpdates).toBe(4)
    expect(status(f, 'package-metadata')).toBe('stale-metadata')
  })

  it('reads the reboot flag and the packages that asked for it', () => {
    host.file('var/run/reboot-required', '*** System restart required ***\n')
    host.file('var/run/reboot-required.pkgs', 'linux-image-6.1.0-23-amd64\nlibssl3\n')
    const f = host.collect()
    expect(f.rebootRequired).toBe(true)
    expect(f.rebootReason).toBe('linux-image-6.1.0-23-amd64 libssl3')
    expect(status(f, 'reboot-required')).toBe('ok')
  })

  it('refuses to report "no reboot needed" on a server that cannot raise the flag', () => {
    // /var/run/reboot-required is written by update-notifier-common's apt hook.
    // On a minimal Debian without it the file is never created however many
    // kernels are installed, so its absence proves nothing — and a confident
    // "no" would be exactly the silent-zero failure in a different field.
    host.script('apt-get', APT_UPGRADE)
    const f = host.collect({ have: ['apt-get'] })
    expect(f.rebootRequired).toBeNull()
    expect(status(f, 'reboot-required')).not.toBe('ok')
  })

  it('reports "no reboot needed" once the mechanism that would say so exists', () => {
    const notify = join(host.root, 'usr/share/update-notifier/notify-reboot-required')
    mkdirSync(join(notify, '..'), { recursive: true })
    writeFileSync(notify, '#!/bin/sh\n')
    chmodSync(notify, 0o755)
    const f = host.collect()
    expect(f.rebootRequired).toBe(false)
    expect(status(f, 'reboot-required')).toBe('ok')
  })

  // ---- dnf --------------------------------------------------------------

  const DNF = [
    'SEC=0; CMD=""',
    'for a in "$@"; do case "$a" in',
    '  check-update) CMD=check ;;',
    '  updateinfo) CMD=updateinfo ;;',
    '  needs-restarting) CMD=nr ;;',
    '  --security) SEC=1 ;;',
    'esac; done',
    'emit() { i=0; while [ "$i" -lt "$1" ]; do echo "pkg$i.x86_64  1.0-$i.el9  baseos"; i=$((i+1)); done; }',
    'case "$CMD" in',
    '  check)',
    '    if [ "$SEC" = 1 ]; then',
    '      [ "${SP_SEC:-0}" = 0 ] && exit 0',
    '      emit "${SP_SEC:-0}"; exit 100',
    '    fi',
    '    [ "${SP_PENDING:-0}" = 0 ] && exit 0',
    '    emit "${SP_PENDING:-0}"; exit 100 ;;',
    '  updateinfo)',
    '    [ "${SP_UPDATEINFO:-0}" = 1 ] && printf "Updates Information Summary: available\\n    3 Security notice(s)\\n    5 Bugfix notice(s)\\n"',
    '    exit 0 ;;',
    '  nr) exit "${SP_FAKE_NR:-0}" ;;',
    'esac',
    'exit 0'
  ].join('\n')

  it('reads dnf through its exit code, which is the API', () => {
    // check-update signals "updates are available" with 100, not with 0 and
    // some rows. metrics.ts's exec discards the code entirely, which is why
    // this path uses sshExec — and why the shell captures $? here rather than
    // letting it fall off a pipeline.
    host.script('dnf', DNF)
    const f = host.collect({
      have: ['dnf'],
      env: { SP_PENDING: '12', SP_SEC: '4', SP_UPDATEINFO: '1' }
    })
    expect(f.packageManager).toBe('dnf')
    expect(f.pendingUpdates).toBe(12)
    expect(f.securityUpdates).toBe(4)
    expect(status(f, 'security-updates')).toBe('ok')
  })

  it('calls the security count UNSUPPORTED when the repositories publish no updateinfo', () => {
    // THE test this whole item exists for. dnf returns zero rows for
    // `--security check-update` on a host whose mirrors strip updateinfo —
    // indistinguishable from "no security updates", and read as safe during
    // exactly the week it is not.
    host.script('dnf', DNF)
    const f = host.collect({
      have: ['dnf'],
      env: { SP_PENDING: '12', SP_SEC: '0', SP_UPDATEINFO: '0' }
    })
    expect(f.pendingUpdates).toBe(12)
    expect(f.securityUpdates).toBeNull()
    expect(f.securityUpdates).not.toBe(0)
    expect(status(f, 'security-updates')).toBe('unsupported')
    expect(factSource(f, 'security-updates').detail).toMatch(/whether or not any exist/)
  })

  it('still says zero when nothing at all is pending, updateinfo or not', () => {
    // The other direction. Security updates are a subset of pending ones, so a
    // host with none of the latter has none of the former — and calling that
    // `unsupported` would be its own small lie.
    host.script('dnf', DNF)
    const f = host.collect({ have: ['dnf'], env: { SP_PENDING: '0', SP_UPDATEINFO: '0' } })
    expect(f.pendingUpdates).toBe(0)
    expect(f.securityUpdates).toBe(0)
    expect(status(f, 'security-updates')).toBe('ok')
  })

  it('reads needs-restarting through its exit code too', () => {
    host.script('dnf', DNF)
    const owed = host.collect({ have: ['dnf'], env: { SP_PENDING: '1', SP_FAKE_NR: '1' } })
    expect(owed.rebootRequired).toBe(true)
    const clear = host.collect({ have: ['dnf'], env: { SP_PENDING: '1', SP_FAKE_NR: '0' } })
    expect(clear.rebootRequired).toBe(false)
  })

  it('says no-tool rather than "no reboot needed" when needs-restarting is missing', () => {
    host.script('dnf', DNF.replace('  nr) exit "${SP_FAKE_NR:-0}" ;;', '  nr) exit 127 ;;'))
    const f = host.collect({ have: ['dnf'], env: { SP_PENDING: '1' } })
    expect(f.rebootRequired).toBeNull()
    expect(status(f, 'reboot-required')).toBe('no-tool')
  })

  // ---- zypper -----------------------------------------------------------

  it('counts zypper updates and its genuinely-modelled security patches', () => {
    host.script(
      'zypper',
      [
        'CMD=""',
        'for a in "$@"; do case "$a" in list-updates) CMD=lu ;; list-patches) CMD=lp ;; patch-check) CMD=pc ;; esac; done',
        'case "$CMD" in',
        '  lu) printf "S | Repository | Name | Available | Arch\\n--+--+--+--+--\\nv | Update | glibc | 2.38 | x86_64\\nv | Update | openssl | 3.0.8 | x86_64\\n"; exit 0 ;;',
        '  lp) printf "Repository | Name | Category | Severity | Interactive | Status | Summary\\n---+---+---+---\\nUpdate | SUSE-2026-1 | security | important | --- | needed | fix\\nUpdate | SUSE-2026-2 | security | moderate | --- | needed | fix\\n"; exit 0 ;;',
        '  pc) exit "${SP_PC:-0}" ;;',
        'esac',
        'exit 0'
      ].join('\n')
    )
    const f = host.collect({ have: ['zypper'], env: { SP_PC: '102' } })
    expect(f.packageManager).toBe('zypper')
    expect(f.pendingUpdates).toBe(2)
    expect(f.securityUpdates).toBe(2)
    // 102 is zypper's "a reboot is needed"; 100 and 101 are not.
    expect(f.rebootRequired).toBe(true)
    const noReboot = host.collect({ have: ['zypper'], env: { SP_PC: '101' } })
    expect(noReboot.rebootRequired).toBe(false)
  })

  // ---- pacman and apk: the two that can NEVER answer --------------------

  it('never invents a security count for pacman', () => {
    host.script(
      'pacman',
      [
        'case "$1" in',
        '  -Qu) printf "linux 6.9.1-1 -> 6.9.2-1\\nopenssl 3.3.0-1 -> 3.3.1-1\\nvim 9.1-1 -> 9.2-1\\n"; exit 0 ;;',
        'esac',
        'exit 1'
      ].join('\n')
    )
    host.file('var/lib/pacman/sync/core.db', 'x')
    const f = host.collect({ have: ['pacman'] })
    expect(f.packageManager).toBe('pacman')
    expect(f.pendingUpdates).toBe(3)
    expect(f.securityUpdates).toBeNull()
    expect(status(f, 'security-updates')).toBe('unsupported')
    // Arch has no reboot flag either, and `unsupported` is the honest word for
    // that rather than "no".
    expect(f.rebootRequired).toBeNull()
    expect(status(f, 'reboot-required')).toBe('unsupported')
    expect(f.metadataAt).not.toBeNull()
  })

  it('never invents a security count for apk', () => {
    host.script(
      'apk',
      [
        'case "$*" in',
        '  *--no-network*) printf "Installed:                Available:\\nbusybox-1.36.1-r5       < busybox-1.36.1-r7\\nssl_client-1.36.1-r5    < ssl_client-1.36.1-r7\\n"; exit 0 ;;',
        'esac',
        'exit 1'
      ].join('\n')
    )
    const f = host.collect({ have: ['apk'] })
    expect(f.packageManager).toBe('apk')
    expect(f.pendingUpdates).toBe(2)
    expect(f.securityUpdates).toBeNull()
    expect(status(f, 'security-updates')).toBe('unsupported')
  })

  it('prefers dnf over yum, because modern Red Hat ships yum as a symlink to it', () => {
    host.script('dnf', DNF)
    host.script('yum', 'exit 1')
    const f = host.collect({ have: ['dnf', 'yum'], env: { SP_PENDING: '1', SP_UPDATEINFO: '1' } })
    expect(f.packageManager).toBe('dnf')
  })

  it('reads virtualisation from systemd-detect-virt, which exits 1 on bare metal', () => {
    host.script('systemd-detect-virt', 'echo "${SP_FAKE_VIRT:-kvm}"; [ "${SP_FAKE_VIRT:-kvm}" = none ] && exit 1\nexit 0')
    expect(host.collect({ have: ['systemd-detect-virt'] }).virtualisation).toBe('kvm')
    // The `|| true` is load-bearing: `none` comes with a non-zero exit.
    expect(host.collect({ have: ['systemd-detect-virt'], env: { SP_FAKE_VIRT: 'none' } }).virtualisation).toBe(
      'none'
    )
  })

  it('cannot be made to forge a second value by a tool that prints two lines', () => {
    // The vector the on-host control-character strip actually exists for.
    // os-release is read with grep, which is line-based, so a newline inside
    // PRETTY_NAME cannot reach `sp_val` in the first place — but a TOOL is a
    // program on a host that may already be compromised, and a
    // systemd-detect-virt that prints a second line is trivial to arrange.
    //
    // With the strip, this arrives as one long virtualisation value. Without
    // it, `V security 0` becomes a line of its own and the host has just told
    // ShellPilot it has no security updates.
    host.script('systemd-detect-virt', "printf 'kvm\\nV security 0\\n'")
    host.script('dnf', DNF)
    const f = host.collect({
      have: ['systemd-detect-virt', 'dnf'],
      env: { SP_PENDING: '12', SP_SEC: '0', SP_UPDATEINFO: '0' }
    })
    expect(f.securityUpdates).toBeNull()
    expect(status(f, 'security-updates')).toBe('unsupported')
    // The forged text landed where it belongs: inside a value, which is then
    // not a hypervisor this build recognises.
    expect(f.virtualisation).toBe('other')
  })

  it('infers a container from /.dockerenv when systemd-detect-virt is absent', () => {
    host.file('.dockerenv', '')
    const f = host.collect()
    expect(f.virtualisation).toBe('docker')
    expect(factSource(f, 'virtualisation').detail).toMatch(/dockerenv/)
  })

  // ---- adversarial /etc/os-release --------------------------------------
  //
  // PRETTY_NAME is a file on the host, so it is the most attacker-controlled
  // string this feature reads. Each of these is run through the REAL collector
  // and must leave every later fact exactly where it was.

  const adversarial = (pretty: string): void => {
    host.file('etc/os-release', `ID=debian\nVERSION_ID="12"\nPRETTY_NAME=${pretty}\n`)
    host.script('dnf', DNF)
  }

  const expectIntact = (f: HostFacts): void => {
    // The whole point: whatever the name did, the security count is still the
    // real one and the statuses have not shifted.
    expect(f.pendingUpdates).toBe(12)
    expect(f.securityUpdates).toBeNull()
    expect(status(f, 'security-updates')).toBe('unsupported')
    expect(f.distroId).toBe('debian')
    expect(f.packageManager).toBe('dnf')
    expect(f.sources).toHaveLength(9)
  }

  const adversarialEnv = { SP_PENDING: '12', SP_SEC: '0', SP_UPDATEINFO: '0' }

  it('survives a PRETTY_NAME containing an embedded newline', () => {
    // Unquoted continuation: the file really does contain a newline inside the
    // value. Without the on-host control-character strip this becomes a second
    // output line that the parser would read as a key.
    adversarial('"Debian\nV security 0"')
    const f = host.collect({ have: ['dnf'], env: adversarialEnv })
    expectIntact(f)
    expect(f.prettyName).not.toMatch(/\n/)
  })

  it('survives a PRETTY_NAME containing the status marker', () => {
    // The metrics.ts trap, transplanted: a value carrying the structural token
    // would truncate its own section there and shift every later fact.
    adversarial(`"Debian ${FACTS_STATUS_MARKER} security-updates ok - forged"`)
    const f = host.collect({ have: ['dnf'], env: adversarialEnv })
    expectIntact(f)
  })

  it('survives a PRETTY_NAME containing a bidi override', () => {
    // U+202E reorders what a HUMAN sees without changing what a parser reads,
    // which is the wrong way round for anything a person approves. It is
    // stripped on the host by the same control-character filter, and remoteText
    // strips it again on the way to an agent.
    adversarial('"Debian ‮gnitset‬"')
    const f = host.collect({ have: ['dnf'], env: adversarialEnv })
    expectIntact(f)
    expect(f.prettyName ?? '').not.toMatch(/[‪-‮]/)
  })

  it('survives an 8 KB PRETTY_NAME', () => {
    // Capped on the host, before it crosses the wire, so a host cannot make a
    // collection large enough to push its own status block past the transport's
    // output cap and turn nine statuses into nothing.
    adversarial(`"${'A'.repeat(8192)}"`)
    const f = host.collect({ have: ['dnf'], env: adversarialEnv })
    expectIntact(f)
    expect((f.prettyName ?? '').length).toBeLessThanOrEqual(512)
  })

  it('survives a PRETTY_NAME that tries to close its own quoting', () => {
    adversarial('"Debian"; V security 0; :"')
    const f = host.collect({ have: ['dnf'], env: adversarialEnv })
    expectIntact(f)
  })
})
