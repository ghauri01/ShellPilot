import { describe, it, expect, afterAll } from 'vitest'
import { execFileSync } from 'node:child_process'
import { chmodSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import {
  FAILED_LOGIN_WINDOW_HOURS,
  MAX_AUTH_TRIES_WEAK,
  POSTURE_COMMAND,
  POSTURE_FACT_PREFIX,
  POSTURE_STATUS_MARKER,
  buildPostureCommand,
  judgeSshd,
  parsePosture,
  postureSource,
  postureToFacts,
  securityUpdateReading,
  summarisePosture
} from '../src/shared/posture'
import type { HostPosture, PostureSourceId, SshdDirective } from '../src/shared/posture'
import { parseHostFacts } from '../src/shared/hostFacts'

// ---------------------------------------------------------------------------
// PROVENANCE, stated rather than assumed — the rule tests/hostFacts.test.ts
// sets out, and this file needs it at least as much.
//
// Two kinds of input appear below and they are NOT equally trustworthy:
//
//   * The COLLECTOR'S OWN OUTPUT (`V key value`, `D Directive value`, and the
//     status block) is ShellPilot's format. Writing it by hand in a test is
//     writing the format down twice, which is what a parser test is for.
//
//   * The TOOLS' output — `ufw status verbose`, `firewall-cmd --list-all`,
//     `nft list ruleset`, `iptables -S`, `sshd -T`, `lastb` — is a vendor
//     format, and NONE of it was captured from a real host in the session that
//     wrote this file. There was no Ubuntu box with ufw, no RHEL box with
//     firewalld, and no host with a populated btmp to run against. The fake
//     binaries below reproduce the SHAPE each tool documents, reconstructed
//     from documentation and memory rather than recorded.
//
//     So what the harness PROVES is the shell: whether the collector calls the
//     right thing, whether `|| true` is in the right place, whether a
//     permission failure is told apart from an empty answer, and whether
//     `denied` really is reported instead of a zero. What it does NOT prove is
//     that a real `ufw status verbose` on Ubuntu 24.04 spells its Default line
//     the way the fixture does. Those column assumptions are unverified and are
//     the first thing to check against a real host — see the report.
// ---------------------------------------------------------------------------

const NOW = 1_800_000_000_000
const parse = (out: string): HostPosture => parsePosture(out, NOW)
const statusOf = (p: HostPosture, id: PostureSourceId): string => postureSource(p, id).status
const reading = (p: HostPosture, d: SshdDirective): { value: string | null; verdict: string } => {
  const r = p.sshd?.readings.find((x) => x.directive === d)
  if (!r) throw new Error(`no reading for ${d}`)
  return { value: r.value, verdict: r.verdict }
}

// ---------------------------------------------------------------------------
// The command, read as a document
// ---------------------------------------------------------------------------

describe('the shipped collector, as text', () => {
  it('contains no sudo at all when built without it', () => {
    // Mirrors cron.ts, hostFacts.ts and access.ts. The point of omitting sudo
    // at BUILD time rather than guarding it at runtime is that this assertion
    // is possible: a dead `[ "$SP_SUDO" = 1 ]` branch would never run, and
    // nobody could check that by reading the command.
    expect(buildPostureCommand({ sudo: false })).not.toMatch(/\bsudo\b/)
  })

  it('escalates only with sudo -n, which cannot prompt', () => {
    const sudos = POSTURE_COMMAND.match(/\bsudo\b[^\n]*/g) ?? []
    expect(sudos.length, 'no sudo at all — this assertion checked nothing').toBeGreaterThan(0)
    for (const line of sudos) expect(line, line).toMatch(/sudo -n\b/)
  })

  it('has no set -e, so one refused read cannot end the collection', () => {
    expect(POSTURE_COMMAND).not.toMatch(/set -e/)
  })

  it('changes nothing on the host', () => {
    // The refusal src/shared/posture.ts states, asserted rather than promised.
    // Every one of these can lock the operator out of the host they would use
    // to undo it, and none of them belongs in a background probe that runs on
    // every server every hour.
    expect(POSTURE_COMMAND, 'ufw enable/disable').not.toMatch(/ufw"?\s+(enable|disable|allow|deny|reset|reload)/)
    expect(POSTURE_COMMAND, 'setenforce').not.toMatch(/\bsetenforce\b/)
    expect(POSTURE_COMMAND, 'aa-enforce / aa-complain').not.toMatch(/\baa-(enforce|complain|disable)\b/)
    expect(POSTURE_COMMAND, 'firewall-cmd writes').not.toMatch(/--(add|remove|set|permanent|reload|runtime-to-permanent)/)
    expect(POSTURE_COMMAND, 'nft writes').not.toMatch(/nft"?\s+(add|delete|flush|insert|replace)/)
    expect(POSTURE_COMMAND, 'iptables writes').not.toMatch(/SP_IPT"\s+-[ADIFPXNZ]\b/)
    expect(POSTURE_COMMAND, 'systemctl').not.toMatch(/\bsystemctl\b/)
    expect(POSTURE_COMMAND, 'fail2ban control').not.toMatch(/\bfail2ban-client\b/)
    // No redirection into anything under /etc or /sys. The collector reads;
    // a `>` pointed at a config file is the shape of the bug that would make
    // this a write tool by accident.
    expect(POSTURE_COMMAND).not.toMatch(/>\s*\/(etc|sys|proc)\//)
  })

  it('never sources or executes a file it read', () => {
    // `. /etc/ufw/ufw.conf` would be arbitrary code execution as the SSH user
    // on a host under an attacker's control, and ufw.conf is a shell fragment
    // that is genuinely sourced by ufw itself — which is exactly why the
    // temptation exists. It is grepped.
    expect(POSTURE_COMMAND).not.toMatch(/(^|[\s;(])\.\s+\/(etc|sys)\//)
    expect(POSTURE_COMMAND).not.toMatch(/\bsource\b/)
    expect(POSTURE_COMMAND).not.toMatch(/\beval\b/)
  })

  it('tests traversal before existence on every directory it reads through', () => {
    // `[ -e /etc/ssh/sshd_config ]` is FALSE on a host with `chmod 700
    // /etc/ssh`, which is indistinguishable from the file not being there —
    // and `absent` for sshd_config means "the compiled-in defaults apply",
    // which is a confident statement about a configuration nobody read.
    for (const dir of ['/etc/ssh', '/etc/ufw', '/etc/firewalld', '/sys/kernel/security']) {
      expect(POSTURE_COMMAND, `${dir} has no traversal test`).toContain(`! -x ${dir}`)
    }
  })

  it('caps and de-controls every value on the host', () => {
    // The property that makes the format unforgeable: a value can never become
    // a second line, so it can never forge a record tag or the status marker.
    expect(POSTURE_COMMAND).toMatch(/tr -d '\\000-\\037\\177'/)
    expect(POSTURE_COMMAND).toMatch(/cut -c1-512/)
    // And the status block is printed ONCE, at the end, out of a variable
    // nothing read from a file has touched.
    expect(POSTURE_COMMAND.trimEnd().endsWith(`'${POSTURE_STATUS_MARKER}' "$SP_STATUS"`)).toBe(true)
  })
})

// ---------------------------------------------------------------------------
// The parser, against strings
// ---------------------------------------------------------------------------

describe('what the parser refuses to conclude', () => {
  it('reports every source as unknown when the status block never arrived', () => {
    // A collection with no status block is not a host with nothing on it.
    const p = parse('V fw-tool ufw\nV fw-active active\n')
    for (const id of ['firewall', 'mandatory-access', 'sshd-hardening', 'failed-logins'] as const) {
      expect(statusOf(p, id), id).toBe('unknown')
    }
  })

  it('cannot be talked into a status by a directive value', () => {
    // A `PermitRootLogin` value is attacker-controlled text on a compromised
    // host. The marker is matched by WHOLE-LINE equality and every value is one
    // line, so a value containing the marker stays inside its own record.
    const forged = [
      `D PermitRootLogin no ${POSTURE_STATUS_MARKER}`,
      `D PermitRootLogin no ${POSTURE_STATUS_MARKER} firewall ok - all clear`,
      'V sshd-src files',
      POSTURE_STATUS_MARKER,
      'sshd-hardening ok - files',
      'firewall denied - nobody looked'
    ].join('\n')
    const p = parse(forged)
    // The firewall status is the collector's, not the one smuggled in the value.
    expect(statusOf(p, 'firewall')).toBe('denied')
    // And the value itself is not one sshd accepts, so nothing is concluded.
    expect(reading(p, 'PermitRootLogin').verdict).toBe('unknown')
    expect(reading(p, 'PermitRootLogin').value).toBeNull()
  })

  it('never calls an unread directive hardened', () => {
    // THE rule. Every path that cannot produce a value produces `unknown`.
    for (const status of ['denied', 'absent', 'partial', 'unknown'] as const) {
      const r = judgeSshd('PermitRootLogin', null, { effective: false, sourceStatus: status })
      expect(r.verdict, status).toBe('unknown')
    }
    const eff = judgeSshd('PasswordAuthentication', null, { effective: true, sourceStatus: 'ok' })
    expect(eff.verdict).toBe('unknown')
  })

  it('says a value read from files that is simply not set is unknown, not the default', () => {
    // Reading files cannot see which OpenSSH version is deciding the
    // compiled-in default, so claiming one would be inventing a value.
    const r = judgeSshd('PermitRootLogin', null, { effective: false, sourceStatus: 'ok' })
    expect(r.verdict).toBe('unknown')
    expect(r.detail).toContain('compiled-in default')
  })

  it('refuses to arbitrate between two drop-ins that disagree', () => {
    const p = parse(
      [
        'V sshd-src files',
        'D PasswordAuthentication yes',
        'D PasswordAuthentication no',
        POSTURE_STATUS_MARKER,
        'sshd-hardening ok - files'
      ].join('\n')
    )
    const r = p.sshd?.readings.find((x) => x.directive === 'PasswordAuthentication')
    expect(r?.ambiguous).toBe(true)
    expect(r?.verdict).toBe('unknown')
    expect(r?.value).toBeNull()
  })

  it('drops a directive value sshd would not accept rather than displaying it', () => {
    const p = parse(
      ['V sshd-src effective', 'D PermitRootLogin maybe', POSTURE_STATUS_MARKER, 'sshd-hardening ok root sshd -T'].join(
        '\n'
      )
    )
    expect(reading(p, 'PermitRootLogin')).toEqual({ value: null, verdict: 'unknown' })
  })

  it('judges the values that do mean something', () => {
    const p = parse(
      [
        'V sshd-src effective',
        'D permitrootlogin yes',
        'D passwordauthentication no',
        'D pubkeyauthentication yes',
        'D permitemptypasswords no',
        'D x11forwarding yes',
        `D maxauthtries ${MAX_AUTH_TRIES_WEAK + 1}`,
        'D allowusers deploy ops',
        POSTURE_STATUS_MARKER,
        'sshd-hardening ok root sshd -T'
      ].join('\n')
    )
    expect(reading(p, 'PermitRootLogin')).toEqual({ value: 'yes', verdict: 'weak' })
    expect(reading(p, 'PasswordAuthentication')).toEqual({ value: 'no', verdict: 'hardened' })
    expect(reading(p, 'PubkeyAuthentication')).toEqual({ value: 'yes', verdict: 'hardened' })
    expect(reading(p, 'PermitEmptyPasswords')).toEqual({ value: 'no', verdict: 'hardened' })
    expect(reading(p, 'X11Forwarding')).toEqual({ value: 'yes', verdict: 'weak' })
    expect(reading(p, 'MaxAuthTries')).toEqual({ value: '7', verdict: 'weak' })
    expect(reading(p, 'AllowUsers')).toEqual({ value: 'deploy ops', verdict: 'hardened' })
    // Not set anywhere, and `sshd -T` should have printed it — so unknown
    // rather than a silent pass.
    expect(reading(p, 'AllowGroups').verdict).toBe('unknown')
    expect(p.sshd?.effective).toBe(true)
  })

  it('keeps a firewall that could not be read out of the "no rules" reading', () => {
    const p = parse(
      ['V fw-tool ufw', 'V fw-backend-status denied', POSTURE_STATUS_MARKER, 'firewall denied - needs root'].join('\n')
    )
    expect(statusOf(p, 'firewall')).toBe('denied')
    expect(p.firewall?.rules).toBeNull()
    expect(p.firewall?.backend.rules).toBeNull()
    expect(p.firewall?.backend.status).toBe('denied')
  })

  it('downgrades a source the collector called ok whose value did not survive', () => {
    // The shell says which probe ran; only this side can say whether its answer
    // survived. `ok` with nothing next to it is the shape of a fabricated
    // all-clear.
    const p = parse([POSTURE_STATUS_MARKER, 'firewall ok - ufw status verbose'].join('\n'))
    expect(statusOf(p, 'firewall')).toBe('unknown')
    expect(postureSource(p, 'firewall').detail).toContain('named no tool')
  })

  it('treats an empty firewall reading as null rather than an empty state object', () => {
    const p = parse([POSTURE_STATUS_MARKER, 'firewall unsupported - nothing installed'].join('\n'))
    expect(p.firewall).toBeNull()
    expect(statusOf(p, 'firewall')).toBe('unsupported')
  })

  it('does not read "not running" as running', () => {
    const p = parse(
      ['V fw-tool firewalld', 'V fw-active not running', POSTURE_STATUS_MARKER, 'firewall ok - state'].join('\n')
    )
    expect(p.firewall?.active).toBe(false)
  })
})

// ---------------------------------------------------------------------------
// Item C's security update count, CONSUMED
// ---------------------------------------------------------------------------

describe('the security update count comes from item C and is not recomputed', () => {
  const facts = (lines: string[]): ReturnType<typeof parseHostFacts> =>
    parseHostFacts(lines.join('\n'), NOW)

  it('carries an unsupported count through as unsupported, never as zero', () => {
    // An Arch host can NEVER report a security update count. Rendering that as
    // 0 during a CVE week is the precise failure item C exists to prevent, and
    // this item must not undo it by re-deriving the number.
    const f = facts([
      'V pkg pacman',
      '===SHELLPILOT-FACTS===',
      'package-manager ok -',
      'security-updates unsupported - "Arch Linux has no security update channel"'
    ])
    const r = securityUpdateReading(f)
    expect(r.count).toBeNull()
    expect(r.status).toBe('unsupported')
  })

  it('carries a real zero through as a real zero', () => {
    const f = facts([
      'V pkg apt',
      'V security 0',
      '===SHELLPILOT-FACTS===',
      'package-manager ok -',
      'security-updates ok - apt-check'
    ])
    expect(securityUpdateReading(f)).toMatchObject({ count: 0, status: 'ok' })
  })

  it('says so when there are no facts at all rather than reporting zero', () => {
    const r = securityUpdateReading(null)
    expect(r.count).toBeNull()
    expect(r.status).toBe('unknown')
  })
})

// ---------------------------------------------------------------------------
// Storage and the estate roll-up
// ---------------------------------------------------------------------------

describe('what reaches the durable store', () => {
  it('writes a status where a value is null, never a zero or a false', () => {
    const p = parse([POSTURE_STATUS_MARKER, 'firewall denied - needs root', 'failed-logins denied - needs root'].join('\n'))
    const f = postureToFacts(p)
    expect(f[`${POSTURE_FACT_PREFIX}firewallRules`]).toBe('denied')
    expect(f[`${POSTURE_FACT_PREFIX}firewallActive`]).toBe('denied')
    expect(f[`${POSTURE_FACT_PREFIX}failedLogins`]).toBe('denied')
    expect(f[`${POSTURE_FACT_PREFIX}source:firewall`]).toBe('denied')
  })

  it('writes a complete key set whatever the probe managed', () => {
    // What makes an unconditional prefix sweep safe on the sampler's side: a
    // failed probe still produces every key, so retiring against the output
    // cannot delete a row the probe simply did not reach this hour.
    const full = postureToFacts(
      parse(
        [
          'V fw-tool ufw',
          'V fw-active active',
          'V fw-rules 4',
          'V sshd-src effective',
          'D permitrootlogin no',
          'V fail-tool lastb',
          'V fail-count 2',
          'V mac-system selinux',
          'V mac-mode enforcing',
          POSTURE_STATUS_MARKER,
          'firewall ok - ufw',
          'mandatory-access ok - selinuxfs',
          'sshd-hardening ok root sshd -T',
          'failed-logins ok root lastb'
        ].join('\n')
      )
    )
    const empty = postureToFacts(parse(POSTURE_STATUS_MARKER))
    expect(Object.keys(empty).sort()).toEqual(Object.keys(full).sort())
  })
})

describe('the estate roll-up counts the gaps rather than skipping them', () => {
  const collected = (lines: string[]): { posture: HostPosture | null } => ({ posture: parse(lines.join('\n')) })

  it('never lets an unread host land in the "fine" column', () => {
    const s = summarisePosture([
      // Read, and genuinely on.
      collected(['V fw-tool ufw', 'V fw-active active', POSTURE_STATUS_MARKER, 'firewall ok - ufw']),
      // Refused. Not inactive, not active — unknown.
      collected(['V fw-tool ufw', POSTURE_STATUS_MARKER, 'firewall denied - needs root']),
      // Only ufw.conf was readable: it says ufw is on and nothing about rules.
      collected(['V fw-tool ufw', 'V fw-active yes', POSTURE_STATUS_MARKER, 'firewall partial - ufw.conf only']),
      // Never collected at all.
      { posture: null }
    ])
    expect(s).toMatchObject({ hosts: 4, collected: 3, firewallActive: 1, firewallInactive: 0, firewallUnknown: 3 })
  })

  it('keeps "this host has no SELinux or AppArmor" apart from "nobody could look"', () => {
    const s = summarisePosture([
      collected([POSTURE_STATUS_MARKER, 'mandatory-access absent - neither is installed']),
      collected([POSTURE_STATUS_MARKER, 'mandatory-access denied - selinuxfs is mounted and unreadable'])
    ])
    expect(s.macAbsent).toBe(1)
    expect(s.macUnknown).toBe(1)
    expect(s.macEnforcing).toBe(0)
  })

  it('does not call AppArmor enforcing when the profile list was refused', () => {
    // Complain-mode profiles are exactly what the refused list would have
    // shown, so "enabled and I could not count the complaining ones" is not
    // "enforcing".
    const s = summarisePosture([
      collected([
        'V mac-system apparmor',
        'V mac-enabled yes',
        POSTURE_STATUS_MARKER,
        'mandatory-access partial - the profile list needs root'
      ])
    ])
    expect(s.macEnforcing).toBe(0)
    expect(s.macUnknown).toBe(1)
  })

  it('counts a host whose sshd could not be read as unknown, not as unproblematic', () => {
    const s = summarisePosture([
      collected(['V sshd-src files', 'D permitrootlogin yes', POSTURE_STATUS_MARKER, 'sshd-hardening ok - files']),
      collected([POSTURE_STATUS_MARKER, 'sshd-hardening denied - /etc/ssh cannot be entered'])
    ])
    expect(s.sshdWeak).toBe(1)
    expect(s.sshdUnknown).toBe(1)
  })
})

// ---------------------------------------------------------------------------
// The collector, actually run.
//
// Everything above tests parsers against strings. That is not enough for this
// item: the whole point of it is a SHELL script that has to tell "refused" from
// "nothing there" across four independent probes, and a shell script is exactly
// the kind of thing that reads correctly and does the wrong thing. So these run
// the real shipped command through /bin/sh against a directory tree built to
// look like a host, with the absolute paths redirected into it.
// ---------------------------------------------------------------------------

/** Paths the collector reads, redirected into the fake tree in ONE pass. */
const ABS_PATHS =
  /\/(?:etc\/(?:ufw|firewalld|ssh|selinux)|sys\/fs\/selinux|sys\/module\/apparmor|sys\/kernel\/security)/g

/** Every binary the collector resolves, so a test can say which ones exist. */
const HIDEABLE = [
  'ufw',
  'firewall-cmd',
  'nft',
  'iptables',
  'getenforce',
  'aa-status',
  'sshd',
  'lastb',
  'journalctl'
]

interface FakeHost {
  root: string
  bin: string
  file: (rel: string, body: string) => void
  dir: (rel: string) => string
  script: (name: string, body: string) => void
  collect: (opts?: { sudo?: boolean; have?: string[]; env?: Record<string, string> }) => HostPosture
}

function fakeHost(): FakeHost {
  const root = mkdtempSync(join(tmpdir(), 'sp-posture-'))
  const bin = join(root, 'bin')
  mkdirSync(bin, { recursive: true })

  const file = (rel: string, body: string): void => {
    const f = join(root, rel)
    mkdirSync(join(f, '..'), { recursive: true })
    writeFileSync(f, body)
  }
  const dir = (rel: string): string => {
    const d = join(root, rel)
    mkdirSync(d, { recursive: true })
    return d
  }
  const script = (name: string, body: string): void => {
    const f = join(bin, name)
    writeFileSync(f, `#!/bin/sh\n${body}\n`)
    chmodSync(f, 0o755)
  }

  // A sudo that behaves like the real one in the only ways that matter: it
  // refuses to do anything without -n, it answers the probe, and it runs the
  // command with SP_ROOTONLY cleared — which is what being root means here.
  // PATH is deliberately preserved: resolveBinary leaves SP_BIN as a bare name
  // when the name is on PATH, so a sudo that reset PATH would fail to find the
  // very tool it was asked to escalate.
  script(
    'sudo',
    '[ "$1" = "-n" ] || { echo "sudo: a password is required" >&2; exit 1; }\nshift\n' +
      '[ "$1" = "true" ] && exit 0\nexec env SP_ROOTONLY= "$@"'
  )

  return {
    root,
    bin,
    file,
    dir,
    script,
    collect: ({ sudo = true, have = [], env = {} } = {}) => {
      let cmd = buildPostureCommand({ sudo }).replace(ABS_PATHS, (m) => root + m)
      for (const name of HIDEABLE) {
        if (have.includes(name)) continue
        cmd = cmd
          .replace(new RegExp(`for c in ${name}[^;]*;`), `for c in sp-absent-${name};`)
          .replace(new RegExp(`SP_BIN=${name}(?=[\\s;]|$)`), `SP_BIN=sp-absent-${name}`)
      }
      const out = execFileSync('/bin/sh', ['-c', cmd], {
        encoding: 'utf8',
        env: { PATH: `${bin}:/usr/bin:/bin`, SP_ROOTONLY: '', ...env }
      })
      return parsePosture(out, NOW)
    }
  }
}

const trees: string[] = []
afterAll(() => {
  for (const t of trees) rmSync(t, { recursive: true, force: true })
})

function host(): FakeHost {
  const h = fakeHost()
  trees.push(h.root)
  return h
}

/** A tool that refuses unless SP_ROOTONLY no longer names it — which is what
 *  the fake sudo above clears. Real permissions cannot be used for these,
 *  because the test process is not root and a fake sudo does not make it so. */
const rootOnly = (name: string, body: string): string =>
  `case ":$SP_ROOTONLY:" in *:${name}:*) echo "${name}: you must be root" >&2; exit 1;; esac\n${body}`

const UFW_STATUS = [
  'Status: active',
  'Logging: on (low)',
  'Default: deny (incoming), allow (outgoing), disabled (routed)',
  'New profiles: skip',
  '',
  'To                         Action      From',
  '--                         ------      ----',
  '22/tcp                     ALLOW IN    Anywhere',
  '443/tcp                    ALLOW IN    Anywhere',
  '3306/tcp                   DENY IN     Anywhere'
].join('\\n')

// The test process cannot make a directory unreadable to itself when it is
// root, and the traversal cases are the ones this item most needs. Skipped
// rather than silently passing.
const AS_ROOT = typeof process.getuid === 'function' && process.getuid() === 0

describe.skipIf(process.platform === 'win32')('the collector, run against a host-shaped tree', () => {
  // ---- firewall ---------------------------------------------------------

  it('reads ufw and reports the shape of its rules', () => {
    const h = host()
    h.script('ufw', `printf '${UFW_STATUS}\\n'`)
    const p = h.collect({ have: ['ufw'] })
    expect(statusOf(p, 'firewall')).toBe('ok')
    expect(p.firewall).toMatchObject({
      tool: 'ufw',
      active: true,
      policyIn: 'deny',
      policyOut: 'allow',
      rules: 3,
      denyRules: 1
    })
  })

  it('escalates to root for a ufw that refuses an unprivileged caller', () => {
    const h = host()
    h.script('ufw', rootOnly('ufw', `printf '${UFW_STATUS}\\n'`))
    const p = h.collect({ have: ['ufw'], env: { SP_ROOTONLY: 'ufw' } })
    expect(statusOf(p, 'firewall')).toBe('ok')
    expect(postureSource(p, 'firewall').usedSudo).toBe(true)
    expect(p.firewall?.rules).toBe(3)
  })

  it('reports a refused ufw as denied, NEVER as a host with no rules', () => {
    // THE bug this whole item is shaped around. `ufw status` prints its refusal
    // on stderr and nothing on stdout, so a collector that trusted an empty
    // answer would report a wide-open box as having no rules at all.
    const h = host()
    h.script('ufw', rootOnly('ufw', `printf '${UFW_STATUS}\\n'`))
    const p = h.collect({ sudo: false, have: ['ufw'], env: { SP_ROOTONLY: 'ufw' } })
    expect(statusOf(p, 'firewall')).toBe('denied')
    // NOT an object with every field null next to a `denied` source. A state
    // where nothing was read is no state at all, so a renderer cannot show an
    // empty firewall row where the sentence explaining the refusal belongs.
    expect(p.firewall).toBeNull()
  })

  it('falls back to ufw.conf as PARTIAL, because on/off is not the rules', () => {
    const h = host()
    h.script('ufw', rootOnly('ufw', `printf '${UFW_STATUS}\\n'`))
    h.file('etc/ufw/ufw.conf', 'ENABLED=yes\nLOGLEVEL=low\n')
    const p = h.collect({ sudo: false, have: ['ufw'], env: { SP_ROOTONLY: 'ufw' } })
    expect(statusOf(p, 'firewall')).toBe('partial')
    expect(p.firewall?.active).toBe(true)
    // Knowing ufw is switched on says NOTHING about what it lets through.
    expect(p.firewall?.rules).toBeNull()
  })

  it.skipIf(AS_ROOT)('reads an unenterable /etc/ufw as cannot-see, not as absent', () => {
    const h = host()
    h.script('ufw', rootOnly('ufw', `printf '${UFW_STATUS}\\n'`))
    h.file('etc/ufw/ufw.conf', 'ENABLED=yes\n')
    chmodSync(join(h.root, 'etc/ufw'), 0o600)
    try {
      const p = h.collect({ sudo: false, have: ['ufw'], env: { SP_ROOTONLY: 'ufw' } })
      expect(statusOf(p, 'firewall')).toBe('denied')
      expect(postureSource(p, 'firewall').detail).toContain('cannot be entered')
      expect(p.firewall).toBeNull()
    } finally {
      chmodSync(join(h.root, 'etc/ufw'), 0o755)
    }
  })

  it('reads a host with no firewall tooling at all as unsupported, not as open', () => {
    // `no-tool` would be defensible and `ok` with zero rules would not: the
    // kernel can be filtering a ruleset loaded at boot with nothing left on
    // disk to ask, and this build cannot tell that apart from an open box.
    const p = host().collect({ have: [] })
    expect(statusOf(p, 'firewall')).toBe('unsupported')
    expect(p.firewall).toBeNull()
    expect(postureSource(p, 'firewall').detail).toContain('NOT the same as nothing being filtered')
  })

  it('reads an EMPTY nftables ruleset as a real zero and a refused one as denied', () => {
    // An empty ruleset prints nothing and exits 0; a refusal prints nothing and
    // exits 1. Distinguished by the exit status, because the output is
    // identical and one of them is a finding.
    const empty = host()
    empty.script('nft', 'exit 0')
    const e = empty.collect({ have: ['nft'] })
    expect(statusOf(e, 'firewall')).toBe('ok')
    expect(e.firewall?.backend).toMatchObject({ tool: 'nftables', rules: 0, status: 'ok' })

    const refused = host()
    refused.script('nft', 'echo "Operation not permitted" >&2; exit 1')
    const r = refused.collect({ sudo: false, have: ['nft'] })
    expect(statusOf(r, 'firewall')).toBe('denied')
    expect(r.firewall).toBeNull()
  })

  it('reads the kernel tables even when the front end says it is switched off', () => {
    // "ufw is inactive" is not "nothing is filtering". A cloud image with an
    // nftables ruleset loaded by systemd at boot has ufw installed, inactive,
    // and a closed box.
    const h = host()
    h.script('ufw', "printf 'Status: inactive\\n'")
    h.script(
      'nft',
      "printf 'table inet filter {\\n  chain input {\\n    type filter hook input priority 0; policy drop;\\n" +
        "    tcp dport 22 accept\\n  }\\n}\\n'"
    )
    const p = h.collect({ have: ['ufw', 'nft'] })
    expect(p.firewall?.active).toBe(false)
    expect(p.firewall?.backend).toMatchObject({ tool: 'nftables', policyIn: 'drop', status: 'ok' })
    expect(p.firewall?.backend.rules).toBeGreaterThan(0)
  })

  it('reads iptables when nft is not there', () => {
    const h = host()
    h.script(
      'iptables',
      "printf -- '-P INPUT DROP\\n-P FORWARD DROP\\n-P OUTPUT ACCEPT\\n-A INPUT -p tcp --dport 22 -j ACCEPT\\n'"
    )
    const p = h.collect({ have: ['iptables'] })
    expect(p.firewall?.backend).toMatchObject({ tool: 'iptables', rules: 1, policyIn: 'drop', status: 'ok' })
    expect(statusOf(p, 'firewall')).toBe('ok')
  })

  it('reads firewalld state and zone shape', () => {
    const h = host()
    h.script(
      'firewall-cmd',
      [
        'case "$1" in',
        "--state) echo running ;;",
        '--get-default-zone) echo public ;;',
        "--get-active-zones) printf 'public\\n  interfaces: eth0\\n' ;;",
        "--list-all) printf 'public (active)\\n  target: default\\n  services: dhcpv6-client ssh\\n  ports: 8080/tcp\\n' ;;",
        'esac'
      ].join('\n')
    )
    const p = h.collect({ have: ['firewall-cmd'] })
    expect(statusOf(p, 'firewall')).toBe('ok')
    expect(p.firewall).toMatchObject({ tool: 'firewalld', active: true, zone: 'public', rules: 3 })
    expect(p.firewall?.zones).toEqual(['public'])
  })

  // ---- SELinux / AppArmor ------------------------------------------------

  it('reads SELinux enforcing, and shows the boot setting that disagrees with it', () => {
    // `setenforce 0` leaves the config saying enforcing while the kernel is
    // permissive until the next reboot. One field could not say that.
    const h = host()
    h.dir('sys/fs/selinux')
    h.file('sys/fs/selinux/enforce', '0')
    h.file('etc/selinux/config', '# comment\nSELINUX=enforcing\nSELINUXTYPE=targeted\n')
    const p = h.collect()
    expect(statusOf(p, 'mandatory-access')).toBe('ok')
    expect(p.mandatoryAccess).toMatchObject({ system: 'selinux', mode: 'permissive', bootMode: 'enforcing' })
  })

  it('falls back to getenforce when selinuxfs will not answer', () => {
    const h = host()
    h.dir('sys/fs/selinux')
    h.script('getenforce', 'echo Enforcing')
    const p = h.collect({ have: ['getenforce'] })
    expect(p.mandatoryAccess).toMatchObject({ system: 'selinux', mode: 'enforcing', enabled: true })
  })

  it('reports selinuxfs that answers nothing as denied, not as disabled', () => {
    const h = host()
    h.dir('sys/fs/selinux')
    const p = h.collect({ have: [] })
    expect(statusOf(p, 'mandatory-access')).toBe('denied')
    expect(p.mandatoryAccess?.mode).toBeNull()
  })

  it('reads a host with neither SELinux nor AppArmor as absent, having checked', () => {
    const p = host().collect({ have: [] })
    expect(statusOf(p, 'mandatory-access')).toBe('absent')
    expect(p.mandatoryAccess).toBeNull()
  })

  it('reads AppArmor profiles, and counts the complaining ones', () => {
    const h = host()
    h.file('sys/module/apparmor/parameters/enabled', 'Y\n')
    h.file(
      'sys/kernel/security/apparmor/profiles',
      '/usr/sbin/cupsd (enforce)\n/usr/bin/man (enforce)\n/usr/sbin/named (complain)\n'
    )
    const p = h.collect()
    expect(statusOf(p, 'mandatory-access')).toBe('ok')
    expect(p.mandatoryAccess).toMatchObject({ system: 'apparmor', enabled: true, profiles: 3, complain: 1 })
  })

  it.skipIf(AS_ROOT)('reads an unenterable /sys/kernel/security as partial, not as zero profiles', () => {
    const h = host()
    h.file('sys/module/apparmor/parameters/enabled', 'Y\n')
    h.file('sys/kernel/security/apparmor/profiles', '/usr/sbin/named (complain)\n')
    chmodSync(join(h.root, 'sys/kernel/security'), 0o600)
    try {
      const p = h.collect({ sudo: false })
      expect(statusOf(p, 'mandatory-access')).toBe('partial')
      expect(p.mandatoryAccess?.enabled).toBe(true)
      // NOT 0. A zero here would read as "no profiles loaded", which is the
      // opposite of what an unreadable list means.
      expect(p.mandatoryAccess?.profiles).toBeNull()
      expect(p.mandatoryAccess?.complain).toBeNull()
    } finally {
      chmodSync(join(h.root, 'sys/kernel/security'), 0o755)
    }
  })

  // ---- sshd --------------------------------------------------------------

  it('prefers sshd -T, which is the effective configuration', () => {
    const h = host()
    h.dir('etc/ssh')
    h.file('etc/ssh/sshd_config', 'PermitRootLogin yes\n')
    h.script(
      'sshd',
      "[ \"$1\" = -T ] && printf 'permitrootlogin no\\npasswordauthentication no\\npubkeyauthentication yes\\n" +
        "x11forwarding no\\npermitemptypasswords no\\nmaxauthtries 3\\n'"
    )
    const p = h.collect({ have: ['sshd'] })
    expect(statusOf(p, 'sshd-hardening')).toBe('ok')
    expect(postureSource(p, 'sshd-hardening').usedSudo).toBe(true)
    expect(p.sshd?.effective).toBe(true)
    // The file said `yes`; the effective configuration says `no`, and the two
    // are never mixed.
    expect(reading(p, 'PermitRootLogin')).toEqual({ value: 'no', verdict: 'hardened' })
    expect(reading(p, 'MaxAuthTries')).toEqual({ value: '3', verdict: 'hardened' })
  })

  it('reads the files when sshd -T is not available, and says the reading is not effective', () => {
    const h = host()
    h.dir('etc/ssh')
    h.file('etc/ssh/sshd_config', 'Port 22\nPermitRootLogin yes\nPasswordAuthentication yes\n')
    const p = h.collect({ sudo: false })
    expect(statusOf(p, 'sshd-hardening')).toBe('ok')
    expect(p.sshd?.effective).toBe(false)
    expect(reading(p, 'PermitRootLogin')).toEqual({ value: 'yes', verdict: 'weak' })
    // Not written down anywhere, and reading files cannot see the compiled-in
    // default. Unknown, never a pass.
    expect(reading(p, 'X11Forwarding').verdict).toBe('unknown')
  })

  it('reads the tab-separated spelling the stock Debian config actually uses', () => {
    // `PermitRootLogin\tprohibit-password`. Deleting the tab instead of folding
    // it to a space produces `PermitRootLoginprohibit-password`, which parses
    // as a directive nobody has heard of — the bug access.ts already hit once.
    const h = host()
    h.dir('etc/ssh')
    h.file('etc/ssh/sshd_config', 'PermitRootLogin\tprohibit-password\n')
    const p = h.collect({ sudo: false })
    expect(reading(p, 'PermitRootLogin')).toEqual({ value: 'prohibit-password', verdict: 'neutral' })
  })

  it('reads the Key=value spelling too', () => {
    const h = host()
    h.dir('etc/ssh')
    h.file('etc/ssh/sshd_config', 'PasswordAuthentication=no\n')
    const p = h.collect({ sudo: false })
    expect(reading(p, 'PasswordAuthentication')).toEqual({ value: 'no', verdict: 'hardened' })
  })

  it.skipIf(AS_ROOT)('reads an unenterable /etc/ssh as cannot-see, NEVER as hardened', () => {
    // THE case the roadmap names. `chmod 700 /etc/ssh` is on plenty of
    // hardened images, `[ -e /etc/ssh/sshd_config ]` through it is FALSE, and
    // `absent` would mean "the compiled-in defaults apply" — a confident
    // statement about a configuration nobody read, on a host that is by the
    // shape of the failure MORE hardened than average.
    const h = host()
    h.dir('etc/ssh')
    h.file('etc/ssh/sshd_config', 'PermitRootLogin no\nPasswordAuthentication no\n')
    chmodSync(join(h.root, 'etc/ssh'), 0o600)
    try {
      const p = h.collect({ sudo: false })
      expect(statusOf(p, 'sshd-hardening')).toBe('denied')
      expect(postureSource(p, 'sshd-hardening').detail).toContain('cannot enter it')
      expect(p.sshd).toBeNull()
    } finally {
      chmodSync(join(h.root, 'etc/ssh'), 0o755)
    }
  })

  it('reads a host with /etc/ssh and no sshd_config in it as absent, having checked', () => {
    const h = host()
    h.dir('etc/ssh')
    const p = h.collect({ sudo: false })
    expect(statusOf(p, 'sshd-hardening')).toBe('absent')
    expect(p.sshd).toBeNull()
  })

  it.skipIf(AS_ROOT)('reports a drop-in it could not read rather than calling the reading complete', () => {
    // A 0600 root-only hardening drop-in is ordinary. Skipping it silently and
    // then reporting `ok` is how a reading of half a config looks complete.
    const h = host()
    h.dir('etc/ssh')
    h.file('etc/ssh/sshd_config', 'PermitRootLogin yes\n')
    h.file('etc/ssh/sshd_config.d/10-hard.conf', 'PermitRootLogin no\n')
    chmodSync(join(h.root, 'etc/ssh/sshd_config.d/10-hard.conf'), 0o000)
    try {
      const p = h.collect({ sudo: false })
      expect(statusOf(p, 'sshd-hardening')).toBe('partial')
      expect(postureSource(p, 'sshd-hardening').detail).toContain('could not be read')
      // The readable half is still reported rather than being thrown away to
      // protect the point.
      expect(reading(p, 'PermitRootLogin').value).toBe('yes')
    } finally {
      chmodSync(join(h.root, 'etc/ssh/sshd_config.d/10-hard.conf'), 0o644)
    }
  })

  it('reports two drop-ins that disagree as ambiguous rather than picking one', () => {
    const h = host()
    h.dir('etc/ssh')
    h.file('etc/ssh/sshd_config', 'PasswordAuthentication yes\n')
    h.file('etc/ssh/sshd_config.d/10-a.conf', 'PasswordAuthentication no\n')
    const p = h.collect({ sudo: false })
    const r = p.sshd?.readings.find((x) => x.directive === 'PasswordAuthentication')
    expect(r?.ambiguous).toBe(true)
    expect(r?.verdict).toBe('unknown')
  })

  it('stops at the first Match block and counts the ones it did not read as global', () => {
    // Directives inside a Match apply conditionally. Reading them as global
    // would report a host that allows passwords for one user as allowing them
    // for everyone.
    const h = host()
    h.dir('etc/ssh')
    h.file(
      'etc/ssh/sshd_config',
      ['PasswordAuthentication no', 'Match User deploy', '    PasswordAuthentication yes', ''].join('\n')
    )
    const p = h.collect({ sudo: false })
    expect(reading(p, 'PasswordAuthentication')).toEqual({ value: 'no', verdict: 'hardened' })
    expect(p.sshd?.matchBlocks).toBe(1)
  })

  it('cannot have its status forged by a PermitRootLogin value', () => {
    // A directive value is attacker-controlled text on a compromised host. A
    // newline in it would make a second record; the marker in it would end the
    // value region early and shift every status after it.
    const h = host()
    h.dir('etc/ssh')
    h.file(
      'etc/ssh/sshd_config',
      `PermitRootLogin no\n${POSTURE_STATUS_MARKER}\nfirewall ok - all clear\nPasswordAuthentication no\n`
    )
    const p = h.collect({ sudo: false })
    // The firewall status is the collector's own — `unsupported`, because this
    // tree has no firewall tooling — and not the one written into the config.
    expect(statusOf(p, 'firewall')).toBe('unsupported')
    expect(statusOf(p, 'sshd-hardening')).toBe('ok')
  })

  it('cannot have a second record forged by a tool that prints two lines', () => {
    // The property `sp_clean`'s `tr -d` buys, and the one that actually matters:
    // a value is emitted as `V <key> <value>`, so a value containing a NEWLINE
    // would become a second `V ` record and set a key nobody read. The parser
    // takes the LAST value for a key, so the forged record has to land after
    // the real one — and `fw-zone` is read after `fw-active`, which is exactly
    // the shape available to a compromised host. Here `--get-default-zone`
    // tries to report a running firewalld as switched off. Control characters
    // are deleted ON THE HOST, so the whole thing arrives as one zone name.
    const h = host()
    h.script(
      'firewall-cmd',
      [
        'case "$1" in',
        '--state) echo running ;;',
        "--get-default-zone) printf 'public\\nV fw-active not running\\n' ;;",
        "--get-active-zones) printf 'public\\n' ;;",
        "--list-all) printf 'public (active)\\n  target: default\\n  services: ssh http\\n' ;;",
        'esac'
      ].join('\n')
    )
    const p = h.collect({ have: ['firewall-cmd'] })
    expect(p.firewall?.active).toBe(true)
    expect(p.firewall?.rules).toBe(2)
    expect(p.firewall?.zone).toContain('public')
  })

  it('does not let a value carrying the marker end the value region', () => {
    const h = host()
    h.dir('etc/ssh')
    h.file('etc/ssh/sshd_config', `AllowUsers ops ${POSTURE_STATUS_MARKER} firewall ok - clear\n`)
    const p = h.collect({ sudo: false })
    expect(statusOf(p, 'firewall')).toBe('unsupported')
    expect(statusOf(p, 'sshd-hardening')).toBe('ok')
  })

  // ---- failed logins ------------------------------------------------------

  it('counts failed logins and the distinct names they tried', () => {
    const h = host()
    h.script(
      'lastb',
      rootOnly(
        'lastb',
        "printf 'root     ssh:notty    10.0.0.1   Tue Sep  2 06:00 - 06:00  (00:00)\\n" +
          "root     ssh:notty    10.0.0.1   Tue Sep  2 06:01 - 06:01  (00:00)\\n" +
          "admin    ssh:notty    10.0.0.2   Tue Sep  2 06:02 - 06:02  (00:00)\\n\\n" +
          "btmp begins Mon Sep  1 00:00:01 2026\\n'"
      )
    )
    const p = h.collect({ have: ['lastb'], env: { SP_ROOTONLY: 'lastb' } })
    expect(statusOf(p, 'failed-logins')).toBe('ok')
    expect(postureSource(p, 'failed-logins').usedSudo).toBe(true)
    expect(p.failedLogins).toMatchObject({ tool: 'lastb', count: 3, users: 2 })
    expect(p.failedLogins?.window).toContain('btmp begins')
  })

  it('reads an empty btmp as a real zero', () => {
    // `grep -v` exits 1 when it selects no lines, which on an empty btmp is the
    // correct answer rather than an error — the shape of bug the cron harness
    // has already found once in this codebase.
    const h = host()
    h.script('lastb', "printf '\\nbtmp begins Mon Sep  1 00:00:01 2026\\n'")
    const p = h.collect({ have: ['lastb'] })
    expect(statusOf(p, 'failed-logins')).toBe('ok')
    expect(p.failedLogins).toMatchObject({ count: 0, users: 0 })
  })

  it('reads a refused btmp as denied, not as no failed logins', () => {
    const h = host()
    h.script('lastb', rootOnly('lastb', "printf 'root ssh:notty 10.0.0.1\\n'"))
    const p = h.collect({ sudo: false, have: ['lastb'], env: { SP_ROOTONLY: 'lastb' } })
    expect(statusOf(p, 'failed-logins')).toBe('denied')
    expect(p.failedLogins).toBeNull()
  })

  it('reads a missing btmp as absent, which is a different fix', () => {
    const h = host()
    h.script('lastb', 'echo "lastb: cannot open /var/log/btmp: No such file or directory" >&2; exit 1')
    const p = h.collect({ sudo: false, have: ['lastb'] })
    expect(statusOf(p, 'failed-logins')).toBe('absent')
    expect(postureSource(p, 'failed-logins').detail).toContain('not being recorded there at all')
  })

  it('falls back to the journal, and says which tool answered', () => {
    const h = host()
    h.script(
      'journalctl',
      [
        'for a in "$@"; do [ "$a" = "0" ] && exit 0; done',
        "printf 'Sep 02 06:00:01 h sshd[1]: Failed password for root from 10.0.0.1 port 1 ssh2\\n" +
          "Sep 02 06:00:02 h sshd[2]: Failed password for invalid user bob from 10.0.0.2 port 2 ssh2\\n" +
          "Sep 02 06:00:03 h sshd[3]: Accepted publickey for ops from 10.0.0.3 port 3 ssh2\\n'"
      ].join('\n')
    )
    const p = h.collect({ have: ['journalctl'] })
    expect(statusOf(p, 'failed-logins')).toBe('ok')
    expect(p.failedLogins).toMatchObject({ tool: 'journal', count: 2, users: 2 })
    expect(p.failedLogins?.window).toContain(String(FAILED_LOGIN_WINDOW_HOURS))
  })

  it('reads a host with neither lastb nor the journal as no-tool', () => {
    const p = host().collect({ have: [] })
    expect(statusOf(p, 'failed-logins')).toBe('no-tool')
    expect(p.failedLogins).toBeNull()
  })

  // ---- the whole thing ---------------------------------------------------

  it('returns every source and exits 0 on a host that can answer nothing', () => {
    // No firewall tool, no MAC, no /etc/ssh, no lastb, no journal. The
    // collector still returns a status for all four and exits cleanly, which is
    // what "no set -e, every read conditional" buys.
    const p = host().collect({ have: [] })
    expect(p.sources.map((s) => `${s.id}=${s.status}`)).toEqual([
      'firewall=unsupported',
      'mandatory-access=absent',
      'sshd-hardening=absent',
      'failed-logins=no-tool'
    ])
  })
})
