import { describe, it, expect, afterAll } from 'vitest'
import { execFileSync } from 'node:child_process'
import { createHash } from 'node:crypto'
import { chmodSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import {
  ACCESS_COMMAND,
  ACCESS_SOURCE_IDS,
  ACCESS_STATUS_HELP,
  ACCESS_STATUS_MARKER,
  KEY_LINE_CAP,
  accessKeyPrefix,
  accessSource,
  accessToFacts,
  buildAccessCommand,
  decodeBase64,
  keyBits,
  keyPresence,
  parseAccessCollection,
  parseAuthorizedKeyLine,
  parseExpiry,
  parseKeyOptionNames,
  parseLoginInstant,
  parseTzOffset,
  splitKeyOptions,
  summariseAccess,
  type HostAccess,
  type Sha256
} from '../src/shared/access'
import { AccessReader } from '../src/main/services/access'

// Fleet keys and access — roadmap item 23, the read half.
//
// Two kinds of test here, and the second kind is the one that matters.
//
// The parser tests below run against strings, which is fine for the parser and
// proves nothing about the thing this feature actually is: a SHELL SCRIPT that
// has to tell "this account has no authorized_keys" apart from "this account's
// home directory is closed to us", on a host where getting that wrong prints a
// clean bill of health over a machine that trusts a key somebody took with them
// when they left.
//
// So the second half runs the REAL shipped command through /bin/sh against a
// directory tree built to look like a host, with the absolute paths redirected
// into it — the harness tests/cron.test.ts established. Exit-code handling and
// `|| true` placement cannot be tested any other way, and they are where this
// will break.

const sha256: Sha256 = (data) => new Uint8Array(createHash('sha256').update(data).digest())

// Real key material, with fingerprints and bit counts taken from `ssh-keygen -l`
// rather than from this implementation. A fingerprint test that computes its own
// expectation is a test that the code agrees with itself.
const ED25519 = 'AAAAC3NzaC1lZDI1NTE5AAAAIJp0kFqDkGDMEnCH7mFY3sBRb+tSVEyKvJhLhZ+SHDdw'
const ED25519_FP = 'SHA256:wVlk8sEGn2qqP1yFjdkoYGu+eWPmKJ/koiL8zATTjxI'
const ED25519_B = 'AAAAC3NzaC1lZDI1NTE5AAAAIN+Qq8Z0mHqxr4RMlBFPHU6JmsFvNzZYuHkWkQrgnJ2s'
const ED25519_B_FP = 'SHA256:Kh/dB+J46zzk3b+72O1DqnLW16xNkYitzUOrofTSSL8'
const RSA2048 =
  'AAAAB3NzaC1yc2EAAAADAQABAAABAQCtKQ/AOy0hzFSfCbl8vjq+z0WVWCTt+eZob+hiLwhaiIB4qnSt1wCBgy7UrrhY49IqYcfhJyd1NMgek0ffNl+rwPFs2dN5tTRXdKRY4CdVSrOi5ZAb2nfp5gOxQXcuXMSk+lpJa3B7fhR6IZDPUBJqf9UU3pg5try0ZwhYs1U7zFYar9zKoZi0cDR7XktHwXJq5yJdF24jS+r6n+GAnHMSOAJd2i+UE8N3CT4yEhDMzlP0F5m7V1cOlXw0QqO5Hvfua34kaUmpiYHg6Lf7V4t4Hckv7yRQaGDEvt0a0pZF6VJ9t7VBh7SaIppT2GpY/cuURwbiu7PtVpg0kSzxwI7R'
const RSA2048_FP = 'SHA256:eQGY4iY48MSjqJHIkXpciUEwUlg0uv4zP3nnNFzMzxY'

// ---------------------------------------------------------------------------
// Certificates, from real ssh-keygen output
// ---------------------------------------------------------------------------
//
// Generated with `ssh-keygen -s ca -I … <key>.pub`, and the fingerprints below
// are what `ssh-keygen -l` prints for BOTH the certificate and the plain key it
// certifies — because that is what a certificate is: a signature wrapped around
// a public key, and the key inside it is the thing a fleet-wide "where is this
// key trusted" question is about.
//
// Nothing of this shape reached parseAuthorizedKeyLine before. The one cert
// test in this file passed an RSA blob under a cert type name, which exercises
// the type-mismatch short-circuit and never the certificate path at all — which
// is why the certificate blob was being fingerprinted whole, producing a value
// that is per-certificate (the nonce is random) and matches nothing anywhere.

const ED25519_CERT =
  'AAAAIHNzaC1lZDI1NTE5LWNlcnQtdjAxQG9wZW5zc2guY29tAAAAIIrQXaEc5/+ytaTzD1zi8Je/zv6vKCsqRDPF8j+fVjBtAAAAIFPcms7SlRCx9tF7C19deCyX/wZe+lTm4afHbHljUa6JAAAAAAAAAAAAAAABAAAAA29wcwAAAAcAAAADb3BzAAAAAGqZVywAAAAAbHk5jAAAAAAAAACCAAAAFXBlcm1pdC1YMTEtZm9yd2FyZGluZwAAAAAAAAAXcGVybWl0LWFnZW50LWZvcndhcmRpbmcAAAAAAAAAFnBlcm1pdC1wb3J0LWZvcndhcmRpbmcAAAAAAAAACnBlcm1pdC1wdHkAAAAAAAAADnBlcm1pdC11c2VyLXJjAAAAAAAAAAAAAAAzAAAAC3NzaC1lZDI1NTE5AAAAIBW4FTgMQy75BqNzjwFoRSrnt/PmsMpEotGHqm7MrsVqAAAAUwAAAAtzc2gtZWQyNTUxOQAAAEBhckJEMGGZyZrBrS1X4VSErhjDcNhcvGzDPxphaxq1q9hdw+NruopYisw0Fx0omzT7u1zRYwc8ZovmmoykTAUH'
/** What `ssh-keygen -l` prints for ED25519_CERT — and for the plain key. */
const ED25519_CERT_FP = 'SHA256:w6jcjwf1BKla85KDOsNAWdBD/Yg/8RqwzUAwuVellko'
const ED25519_CERT_INNER =
  'AAAAC3NzaC1lZDI1NTE5AAAAIFPcms7SlRCx9tF7C19deCyX/wZe+lTm4afHbHljUa6J'

const RSA_CERT =
  'AAAAHHNzaC1yc2EtY2VydC12MDFAb3BlbnNzaC5jb20AAAAgiJywqzc54YQKtnGjahSd0fJ1iR2nRvtrL3TAoLLddB8AAAADAQABAAABAQCiIajlc/Ahpf3yDfVaMcH88zgs1+7C8dALsl0hN8Y29V0/nuVEjWF7PjssM2S7kdeF80Oncc0oOm6t9SB/xK842R2DV47ITIpCPtnrg9OBk/wfWObBdm/SY5/vc7UdHA50TdgbM++74GamVGAlNuB00qQdhgjHM4Kddlxw2MH8uwgnITxZZ9pCsLE4DqW5IbQcoDk1R3h0KklZTNLfUPolYbIhi4qKnNfP6lw5Cc5gbJifleKri14tjb12kevqfNnF8rUCDCAJI819NRbjQipNuV6+DND0FqgvMfcIy61XC5VmrheCDcVgu3faWWVLkzAYXvFpRElub52TjWn9X9aPAAAAAAAAAAAAAAABAAAAA3JzYQAAAAcAAAADb3BzAAAAAGqZVywAAAAAbHk5jAAAAAAAAACCAAAAFXBlcm1pdC1YMTEtZm9yd2FyZGluZwAAAAAAAAAXcGVybWl0LWFnZW50LWZvcndhcmRpbmcAAAAAAAAAFnBlcm1pdC1wb3J0LWZvcndhcmRpbmcAAAAAAAAACnBlcm1pdC1wdHkAAAAAAAAADnBlcm1pdC11c2VyLXJjAAAAAAAAAAAAAAAzAAAAC3NzaC1lZDI1NTE5AAAAIBW4FTgMQy75BqNzjwFoRSrnt/PmsMpEotGHqm7MrsVqAAAAUwAAAAtzc2gtZWQyNTUxOQAAAEDVh2PXsIFfh5ZYAKtX1vHaJLDkueWUOJQY8Zvg16xJGmumOpJaa3FLXlhzeMElf5HHa+r1asalB7TcFZcsfhYF'
const RSA_CERT_FP = 'SHA256:124k69rmaFn2zwy4VB1WhP9G/+ATN8IfER4441fO6M4'
const RSA_CERT_INNER =
  'AAAAB3NzaC1yc2EAAAADAQABAAABAQCiIajlc/Ahpf3yDfVaMcH88zgs1+7C8dALsl0hN8Y29V0/nuVEjWF7PjssM2S7kdeF80Oncc0oOm6t9SB/xK842R2DV47ITIpCPtnrg9OBk/wfWObBdm/SY5/vc7UdHA50TdgbM++74GamVGAlNuB00qQdhgjHM4Kddlxw2MH8uwgnITxZZ9pCsLE4DqW5IbQcoDk1R3h0KklZTNLfUPolYbIhi4qKnNfP6lw5Cc5gbJifleKri14tjb12kevqfNnF8rUCDCAJI819NRbjQipNuV6+DND0FqgvMfcIy61XC5VmrheCDcVgu3faWWVLkzAYXvFpRElub52TjWn9X9aP'

const EC384_CERT =
  'AAAAKGVjZHNhLXNoYTItbmlzdHAzODQtY2VydC12MDFAb3BlbnNzaC5jb20AAAAgsR/kbrPaj6A8zA9KBYmiJO5faV4vLWADVGatp4JaXaoAAAAIbmlzdHAzODQAAABhBBR8p/bKSqlyR+aLXGd2IyxVwmX8JsBSY+HryN7A7h6oi7oSg6d7Bh/UZbUZvNBL1DMkWuLxbiWWIAZbJ4qgPp6rm9pxuHZSjm3eUiGyxIWCvqcpXXg+BkXkNQo/nWcnDQAAAAAAAAAAAAAAAQAAAAJlYwAAAAcAAAADb3BzAAAAAGqZVywAAAAAbHk5jAAAAAAAAACCAAAAFXBlcm1pdC1YMTEtZm9yd2FyZGluZwAAAAAAAAAXcGVybWl0LWFnZW50LWZvcndhcmRpbmcAAAAAAAAAFnBlcm1pdC1wb3J0LWZvcndhcmRpbmcAAAAAAAAACnBlcm1pdC1wdHkAAAAAAAAADnBlcm1pdC11c2VyLXJjAAAAAAAAAAAAAAAzAAAAC3NzaC1lZDI1NTE5AAAAIBW4FTgMQy75BqNzjwFoRSrnt/PmsMpEotGHqm7MrsVqAAAAUwAAAAtzc2gtZWQyNTUxOQAAAEAStV7QHJiOIGjV35WVD5LS2I/DToycb1huIiEcezVePJLNR45emYGlZLxE2JwODdzBz3tniyaN1w08JoESgkoG'
const EC384_CERT_FP = 'SHA256:gtWoyOmo2i7ZLipEy3jUGRqEbkQL8cz2mSTvNCNXrxc'
const EC384_CERT_INNER =
  'AAAAE2VjZHNhLXNoYTItbmlzdHAzODQAAAAIbmlzdHAzODQAAABhBBR8p/bKSqlyR+aLXGd2IyxVwmX8JsBSY+HryN7A7h6oi7oSg6d7Bh/UZbUZvNBL1DMkWuLxbiWWIAZbJ4qgPp6rm9pxuHZSjm3eUiGyxIWCvqcpXXg+BkXkNQo/nWcnDQ=='
const ECDSA384 =
  'AAAAE2VjZHNhLXNoYTItbmlzdHAzODQAAAAIbmlzdHAzODQAAABhBMmWJrQwHGkavmhaNvBw/5aX7grH2ANdGwvWDVFE/Xxt3nagdDUjaG1pUV+A0sKHfYR2lP8UEYcahL33yFxIbMxCp7SgQoKRsXeaHiP6wVsXvyUC+Eq1Vtpa7BymMO/kkA=='
const ECDSA384_FP = 'SHA256:IDlE8LLk5Dn2TEciFeo2RY9Ef+3lWdZYDnjVlx+rd2o'

// ---------------------------------------------------------------------------
// The command, as a string
// ---------------------------------------------------------------------------

describe('the command the collector sends', () => {
  it('contains no sudo at all when built without it', () => {
    // Mirrors tests/hostFacts.test.ts and tests/cron.test.ts. Omitting sudo at
    // BUILD time rather than guarding it at runtime is what makes "this command
    // contains no sudo" a property a reader can check; a runtime guard could
    // not be checked this way, which is the entire argument for building it
    // this way.
    expect(buildAccessCommand({ sudo: false })).not.toMatch(/\bsudo\b/)
  })

  it('escalates only with sudo -n, which cannot prompt', () => {
    const sudos = ACCESS_COMMAND.match(/\bsudo\b[^\n]*/g) ?? []
    // Without this the assertion below passes vacuously on a command with no
    // sudo in it at all, which is the shape of a guard that checks nothing.
    expect(sudos.length, 'no sudo at all — this assertion checked nothing').toBeGreaterThan(3)
    for (const line of sudos) expect(line, line).toMatch(/sudo -n\b/)
  })

  it('never reads /etc/shadow, and never a private key', () => {
    // The lock state comes from `passwd -S -a`. Reading the shadow file and
    // stripping the hash in TypeScript would work right up until a malformed
    // line moved a field, and the failure mode of that is a password hash in a
    // log. And this feature reads the file that says which keys a host TRUSTS —
    // it has no business anywhere near ~/.ssh/id_*.
    expect(ACCESS_COMMAND).not.toMatch(/\/etc\/shadow/)
    expect(ACCESS_COMMAND).not.toMatch(/id_rsa|id_ed25519|id_ecdsa|PRIVATE KEY/)
    expect(ACCESS_COMMAND).toMatch(/passwd" -S -a|passwd -S -a|\$SP_PASSWD" -S -a/)
  })

  it('never shells out to ssh-keygen for a fingerprint', () => {
    // It is not guaranteed present, it is another round trip, and a host
    // missing OpenSSH's own tooling would have its keys go unidentified —
    // which is the case an inventory most needs to cover.
    expect(ACCESS_COMMAND).not.toMatch(/ssh-keygen/)
  })

  it('uses no set -e, so one missing file does not end the collection', () => {
    expect(ACCESS_COMMAND).not.toMatch(/set -e/)
  })

  it('pins the locale, so a date is parseable on a host that is not in English', () => {
    // `lastlog` and `chage` print through the locale. Without this a host in
    // de_DE emits `Di 2 Sep` and every last-login on it silently loses its
    // timestamp.
    expect(ACCESS_COMMAND).toMatch(/^LC_ALL=C\nexport LC_ALL\n/)
  })
})

// ---------------------------------------------------------------------------
// Fingerprints and key lines
// ---------------------------------------------------------------------------

describe('fingerprinting, against ssh-keygen’s own answers', () => {
  it('produces OpenSSH’s SHA256 form with the padding stripped', () => {
    // The padding matters: `ssh-keygen -l` prints none, and a fingerprint with
    // a trailing `=` would never string-match one a person pasted out of a
    // terminal — which is the entire way this feature gets used.
    const k = parseAuthorizedKeyLine(`ssh-ed25519 ${ED25519} alice@laptop`, 1, sha256)!
    expect(k.fingerprint).toBe(ED25519_FP)
    expect(k.fingerprint).not.toMatch(/=/)
  })

  it('derives the key size from the blob, not from the type name', () => {
    // A 1024-bit RSA key still trusted by a host is a finding, and the only
    // place that number exists is inside the modulus.
    expect(parseAuthorizedKeyLine(`ssh-rsa ${RSA2048} x`, 1, sha256)!.bits).toBe(2048)
    expect(parseAuthorizedKeyLine(`ssh-rsa ${RSA2048} x`, 1, sha256)!.fingerprint).toBe(RSA2048_FP)
    expect(parseAuthorizedKeyLine(`ecdsa-sha2-nistp384 ${ECDSA384} x`, 1, sha256)!.bits).toBe(384)
    expect(parseAuthorizedKeyLine(`ecdsa-sha2-nistp384 ${ECDSA384} x`, 1, sha256)!.fingerprint).toBe(
      ECDSA384_FP
    )
    expect(parseAuthorizedKeyLine(`ssh-ed25519 ${ED25519} x`, 1, sha256)!.bits).toBe(256)
  })

  it('computes the fingerprint with the hash it was handed', () => {
    // Not with anything the module happened to import. The renderer bundles
    // src/shared/access.ts, so a top-level node:crypto import there breaks the
    // build — the injection is what keeps the fingerprinting in shared code.
    const calls: number[] = []
    const counting: Sha256 = (d) => {
      calls.push(d.length)
      return new Uint8Array(32)
    }
    const k = parseAuthorizedKeyLine(`ssh-ed25519 ${ED25519} x`, 1, counting)!
    expect(calls).toEqual([51])
    expect(k.fingerprint).toBe(`SHA256:${'A'.repeat(43)}`)
  })

  it('rejects base64 it cannot decode rather than fingerprinting garbage', () => {
    expect(decodeBase64('!!!!')).toBeNull()
    expect(decodeBase64('')).toBeNull()
    const k = parseAuthorizedKeyLine('ssh-ed25519 not-base64!! x', 1, sha256)!
    expect(k.problem).toBe('bad-base64')
    expect(k.fingerprint).toBeNull()
  })

  it('catches a line whose declared type is not the type inside the key', () => {
    // sshd rejects these outright and a person reading the file would not
    // notice, which is exactly why it is worth saying.
    const k = parseAuthorizedKeyLine(`ssh-rsa ${ED25519} x`, 1, sha256)!
    expect(k.problem).toBe('type-mismatch')
    expect(k.fingerprint).toBeNull()
  })

  it('leaves a certificate blob’s bit count null rather than reading the wrong field', () => {
    // A PLAIN RSA blob under a cert type name: not a certificate at all, so
    // there is no nonce to step over and nothing to measure.
    expect(keyBits('ssh-rsa-cert-v01@openssh.com', decodeBase64(RSA2048)!)).toBeNull()
  })

  // -------------------------------------------------------------------------
  // Certificates
  // -------------------------------------------------------------------------
  //
  // THE finding this whole group exists for. `ssh-keygen -l` on a certificate
  // prints the fingerprint of the key INSIDE it, identical to the plain key's.
  // Fingerprinting the certificate blob instead produces a value that is
  // per-certificate — the nonce is random — and matches nothing on any other
  // host, while `problem` stays null so `certain` stays true beside it.
  //
  // The consequence is the silent third answer this module exists to prevent:
  // "which of my hosts still trusts the laptop I sold" answers NO for every
  // host that trusts it through a certificate, with `certain: true` beside it.

  it.each([
    ['ssh-ed25519-cert-v01@openssh.com', ED25519_CERT, ED25519_CERT_FP, ED25519_CERT_INNER, 256],
    ['ssh-rsa-cert-v01@openssh.com', RSA_CERT, RSA_CERT_FP, RSA_CERT_INNER, 2048],
    ['ecdsa-sha2-nistp384-cert-v01@openssh.com', EC384_CERT, EC384_CERT_FP, EC384_CERT_INNER, 384]
  ])('fingerprints %s over the key inside it, as ssh-keygen -l does', (type, cert, fp, inner, bits) => {
    const k = parseAuthorizedKeyLine(`${type} ${cert} ops@laptop`, 1, sha256)!
    // The fingerprint FIRST, because it is the lie: the value below is what
    // `ssh-keygen -l` prints, and what the certificate blob hashes to instead
    // is a number with no meaning on any other host.
    expect(k.fingerprint).toBe(fp)
    expect(k.problem).toBeNull()
    expect(k.type).toBe(type)
    expect(k.certificate).toBe(true)
    expect(k.bits).toBe(bits)
    // And the plain key it certifies fingerprints to the SAME value, which is
    // the whole point: one key, one identity, however a host chose to trust it.
    const plain = parseAuthorizedKeyLine(`${type.replace(/-cert-v01@openssh\.com$/, '')} ${inner} ops@laptop`, 1, sha256)!
    expect(plain.fingerprint).toBe(fp)
  })

  it('does not keep a certificate body for the write half to match on', () => {
    // A fingerprint now names the key inside, and one key can be certified any
    // number of times with different bodies. A removal that matched ONE of
    // those bodies while the plan expected to remove all of them would fail its
    // own count check and roll the host back — safe, and a confusing report.
    // Refusing to hand over a body is the honest form of the same refusal.
    const k = parseAuthorizedKeyLine(`ssh-ed25519-cert-v01@openssh.com ${ED25519_CERT} x`, 1, sha256)!
    expect(k.blob).toBeNull()
  })

  it('reports a certificate it cannot read the key out of rather than guessing one', () => {
    // Truncated after the algorithm name and the nonce: structurally a
    // certificate, with no key in it. This is a hole in the inventory and it is
    // counted as one — never fingerprinted from whatever bytes are present.
    const stunted = 'AAAAIHNzaC1lZDI1NTE5LWNlcnQtdjAxQG9wZW5zc2guY29tAAAAIIrQXaEc5/+ytaTzD1zi8Je/zv6vKCsqRDPF8j+fVjBt'
    const k = parseAuthorizedKeyLine(`ssh-ed25519-cert-v01@openssh.com ${stunted} x`, 1, sha256)!
    expect(k.problem).toBe('certificate')
    expect(k.fingerprint).toBeNull()
  })

  it('files cert-authority as broadening trust, never as restricting it', () => {
    // `cert-authority` is the one option in an authorized_keys file that makes
    // the host trust MORE than the line in front of it: everything that CA will
    // ever sign, including keys that do not exist yet. Counting it as a
    // restriction inverts its meaning in the one column an operator scans.
    const k = parseAuthorizedKeyLine(`cert-authority ssh-ed25519 ${ED25519} the-ca`, 1, sha256)!
    expect(k.options).toEqual(['cert-authority'])
    expect(k.restricted).toBe(false)
    expect(k.broadened).toBe(true)
    // And it is still read as an options prefix, not as a key of type
    // "cert-authority" — the bare-token form has no comma or equals in it.
    expect(k.type).toBe('ssh-ed25519')
    expect(k.fingerprint).toBe(ED25519_FP)
  })

  it('keeps cert-authority out of the restricted count and in its own', () => {
    const a = collected([
      'U 1 keys ok -',
      'U 1 name ops',
      `K 1 1 90 cert-authority ssh-ed25519 ${ED25519} the-ca`,
      `K 1 2 90 command="/bin/true" ssh-ed25519 ${ED25519_B} pinned`
    ], OK_STATUS)
    const s = summariseAccess(a)
    expect(s.restricted).toBe(1)
    expect(s.certificateAuthorities).toBe(1)
    // A CA line means this host will accept keys that are in no file anywhere,
    // so no count taken from the files is an answer about the host.
    expect(s.certain).toBe(false)
    expect(s.uncertainty.join(' ')).toMatch(/certificate authority/i)
  })
})

describe('an authorized_keys line, adversarially', () => {
  it('splits an options prefix containing a quoted command with spaces in it', () => {
    // The common case, and the one a naive whitespace split gets wrong: it
    // attributes the key type to `--server`.
    const line = `command="/usr/bin/rsync --server -vlogDtpre.iLsfx . /srv",no-pty,from="10.0.0.0/8" ssh-ed25519 ${ED25519} backup`
    const k = parseAuthorizedKeyLine(line, 3, sha256)!
    expect(k.type).toBe('ssh-ed25519')
    expect(k.fingerprint).toBe(ED25519_FP)
    expect(k.options).toEqual(['command', 'no-pty', 'from'])
    expect(k.restricted).toBe(true)
    expect(k.comment).toBe('backup')
  })

  it('reads a line that starts with a key type as having no options at all', () => {
    // sshd reads the third field as a comment here, whatever it looks like.
    const k = parseAuthorizedKeyLine(`ssh-ed25519 ${ED25519} command=notanoption`, 1, sha256)!
    expect(k.options).toEqual([])
    expect(k.comment).toBe('command=notanoption')
  })

  it('does not read a junk line as an exotic key type', () => {
    // `garbage line here` split as `<options> <type> <blob>` gives a key of
    // type "line", filed as a possibly-valid newer algorithm — so a corrupt
    // file reads as an interesting one. The discriminator is the key's own
    // embedded algorithm name, which junk cannot fake by accident.
    const k = parseAuthorizedKeyLine('garbage line here', 5, sha256)!
    expect(k.problem).toBe('malformed')
    expect(k.type).toBeNull()
    // And it invents no options either. A prefix is only options when it looks
    // like options — it assigns, it lists, or it is one OpenSSH defines — so a
    // junk first word does not become a restriction on a key that has none.
    expect(k.options).toEqual([])
    expect(k.restricted).toBe(false)
  })

  it('keeps a genuinely unknown type distinct from a malformed line', () => {
    // A key type this build has not heard of is very likely real on a newer
    // sshd. Calling it malformed would hide it from the person auditing the
    // file; calling it a key would claim a fingerprint that does not exist.
    // Built rather than pasted, so the blob really does carry the name it
    // claims — a hand-typed one that is off by a byte tests the wrong branch.
    const name = 'ssh-future'
    const raw = new Uint8Array(4 + name.length + 4 + 32)
    raw[3] = name.length
    for (let i = 0; i < name.length; i++) raw[4 + i] = name.charCodeAt(i)
    raw[4 + name.length + 3] = 32
    let bin = ''
    for (const b of raw) bin += String.fromCharCode(b)
    const blob = btoa(bin)
    const inner = decodeBase64(blob)!
    expect(String.fromCharCode(...inner.subarray(4, 4 + name.length))).toBe('ssh-future')
    const k = parseAuthorizedKeyLine(`ssh-future ${blob} x`, 1, sha256)!
    expect(k.problem).toBe('unknown-type')
    expect(k.rawType).toBe('ssh-future')
    expect(k.fingerprint).toBeNull()
  })

  it('refuses to fingerprint a line the collector had to cut short', () => {
    // A fingerprint over a truncated blob is not a missing answer — it is a
    // confidently wrong one that fails to match the same key on another host.
    const k = parseAuthorizedKeyLine(`ssh-ed25519 ${ED25519} x`, 1, sha256, true)!
    expect(k.problem).toBe('truncated')
    expect(k.fingerprint).toBeNull()
  })

  it('strips a bidi override out of a comment', () => {
    // It reorders what a HUMAN sees without changing what a parser reads —
    // exactly the wrong way round for a key somebody is deciding whether to
    // revoke.
    const k = parseAuthorizedKeyLine(
      `ssh-ed25519 ${ED25519} ci‮gnitset‬@build`,
      1,
      sha256
    )!
    expect(k.comment).not.toMatch(/[‪-‮]/)
    expect(k.fingerprint).toBe(ED25519_FP)
  })

  it('caps an 8 KB comment instead of carrying it', () => {
    const k = parseAuthorizedKeyLine(`ssh-ed25519 ${ED25519} ${'A'.repeat(8192)}`, 1, sha256)!
    expect(k.comment!.length).toBeLessThan(220)
    expect(k.comment!.endsWith('…')).toBe(true)
    expect(k.fingerprint).toBe(ED25519_FP)
  })

  it('skips comment and blank lines without counting them as keys', () => {
    expect(parseAuthorizedKeyLine('# a comment', 1, sha256)).toBeNull()
    expect(parseAuthorizedKeyLine('   ', 2, sha256)).toBeNull()
    expect(parseAuthorizedKeyLine('  # indented', 3, sha256)).toBeNull()
  })

  it('reads option names and never option values', () => {
    // A `command=` value is an arbitrary shell command written by whoever wrote
    // the file. That the option is there is the finding; the string is not
    // something to carry around.
    expect(parseKeyOptionNames('command="rm -rf /",no-pty')).toEqual(['command', 'no-pty'])
    expect(JSON.stringify(parseKeyOptionNames('command="rm -rf /"'))).not.toMatch(/rm/)
    expect(splitKeyOptions('restrict ssh-ed25519 AAAA')!.options).toBe('restrict')
  })
})

// ---------------------------------------------------------------------------
// Dates
// ---------------------------------------------------------------------------

describe('reading the host’s own dates', () => {
  it('does not mistake a UTC offset for a year', () => {
    // `lastlog` prints `Tue Sep  2 06:00:01 +0000 2026`. A lazy hop to "the
    // next four digits" finds `0000`, which is rejected as a year — and every
    // last-login on the host silently loses its timestamp while the phrase
    // stays on screen looking fine.
    const at = parseLoginInstant('root pts/0 10.0.0.1 Tue Sep 2 06:00:01 +0000 2026', 0)
    expect(at).toBe(Date.UTC(2026, 8, 2, 6, 0, 1))
  })

  it('prefers an offset printed on the row over the host’s current one', () => {
    // They agree almost always. Where they do not — a login recorded before a
    // DST change — the row is the one that was written at the time.
    expect(parseLoginInstant('ops pts/0 h Mon Jan 5 09:30:00 +0100 2026', 600)).toBe(
      Date.UTC(2026, 0, 5, 8, 30, 0)
    )
  })

  it('reads a `last -F` row, which carries no offset at all', () => {
    expect(parseLoginInstant('ops pts/1 10.0.0.9 Tue Sep 2 06:00:01 2026 - still', 330)).toBe(
      Date.UTC(2026, 8, 2, 6, 0, 1) - 330 * 60_000
    )
  })

  it('returns null rather than a guess when there is no offset to apply', () => {
    expect(parseLoginInstant('ops pts/1 h Tue Sep 2 06:00:01 2026', null)).toBeNull()
    expect(parseTzOffset('+0530')).toBe(330)
    expect(parseTzOffset('-0800')).toBe(-480)
    expect(parseTzOffset('garbage')).toBeNull()
  })

  it('gives an account expiring today the rest of the day', () => {
    // chage expiry takes effect at the end of the day; calling it expired at
    // 00:01 would be wrong for twenty-four hours.
    const today = Date.UTC(2026, 0, 5, 0, 1)
    expect(parseExpiry('Jan 05, 2026', today)).toBe(false)
    expect(parseExpiry('Jan 04, 2026', today)).toBe(true)
    expect(parseExpiry('never', today)).toBe(false)
    expect(parseExpiry('Jan 05, 2026', null)).toBeNull()
  })
})

// ---------------------------------------------------------------------------
// The collection, parsed
// ---------------------------------------------------------------------------

/** Collector-shaped output, so the parser is exercised on records rather than
 *  on a hand-built object it would never see in production. */
function collected(body: string[], status: string[]): HostAccess {
  return parseAccessCollection([...body, ACCESS_STATUS_MARKER, ...status].join('\n'), {
    sha256,
    now: 1_800_000_000_000
  })
}

const OK_STATUS = [
  'accounts ok -',
  'sshd-config ok - /etc/ssh/sshd_config',
  'account-status ok -',
  'sudoers ok -',
  'last-login ok - lastlog'
]

describe('a collection, and the nulls in it', () => {
  it('gives an account whose file was read a list, and one that was not a reason', () => {
    // THE invariant. There is no path in the parser that produces an empty
    // array for an account nobody could read.
    const a = collected(
      [
        'V now 1800000000',
        'V tz +0000',
        'V self ops',
        'U 1 uid 1000',
        'U 1 keys ok -',
        'U 1 name ops',
        `K 1 1 60 ssh-ed25519 ${ED25519} ops@laptop`,
        'U 2 uid 1001',
        'U 2 keys denied -',
        'U 2 name deploy',
        'U 3 uid 1002',
        'U 3 keys absent -',
        'U 3 name backup'
      ],
      OK_STATUS
    )
    expect(a.accounts.map((x) => x.user)).toEqual(['ops', 'deploy', 'backup'])
    expect(a.accounts[0].keys!.map((k) => k.fingerprint)).toEqual([ED25519_FP])
    expect(a.accounts[1].keys).toBeNull()
    expect(a.accounts[1].keysStatus).toBe('denied')
    // `absent` is an ANSWER, not a null. The collector establishes it by
    // testing the traversal of the home directory and of .ssh before it looks
    // for the file, so a permission bit can never arrive here as `absent`.
    expect(a.accounts[2].keys).toEqual([])
    expect(a.accounts[2].keysStatus).toBe('absent')
    // The reason is still carried beside it: "empty because there is no file"
    // is a different sentence from "empty because the file is empty".
    expect(a.accounts[2].keysDetail).toBe(ACCESS_STATUS_HELP.absent)
  })

  it('cannot have a status forged by a key comment', () => {
    // The comment is `===SHELLPILOT-ACCESS===`. Every record carries a tag and
    // a space in front of it, so a file's content can never be an exact-match
    // marker line — and the status block is printed once, at the end, out of a
    // variable nothing read from a file ever touched.
    const a = collected(
      [
        'U 1 keys ok -',
        'U 1 name ops',
        `K 1 1 90 ssh-ed25519 ${ED25519} ${ACCESS_STATUS_MARKER}`,
        `K 1 2 40 accounts denied - forged`
      ],
      OK_STATUS
    )
    expect(accessSource(a, 'accounts').status).toBe('ok')
    expect(a.accounts[0].keys![0].comment).toBe(ACCESS_STATUS_MARKER)
    expect(a.accounts[0].keys![0].fingerprint).toBe(ED25519_FP)
  })

  it('flags a line the collector had to cut, using the length it reported', () => {
    // The length is BEFORE truncation, which is the only way to tell a line
    // that fitted from one that was cut.
    const a = collected(
      ['U 1 keys ok -', 'U 1 name ops', `K 1 1 ${KEY_LINE_CAP + 1} ssh-ed25519 ${ED25519} x`],
      OK_STATUS
    )
    expect(a.accounts[0].keys![0].problem).toBe('truncated')
    expect(a.accounts[0].keys![0].fingerprint).toBeNull()
  })

  it('drops an account whose name this app could not act on', () => {
    const a = collected(['U 1 keys ok -', 'U 1 name ../../etc/passwd'], OK_STATUS)
    expect(a.accounts).toEqual([])
  })

  it('reads a lock state only for the account the tool actually named', () => {
    // An account missing from `passwd -S -a` output is not an unlocked account.
    const a = collected(
      ['S L ops', 'U 1 keys ok -', 'U 1 name ops', 'U 2 keys ok -', 'U 2 name deploy'],
      OK_STATUS
    )
    expect(a.accounts[0].passwordLocked).toBe(true)
    expect(a.accounts[1].passwordLocked).toBeNull()
    expect(a.accounts[1].accountStatus).toBe('unknown')
  })

  it('reports a locked password as not blocking key authentication', () => {
    // `passwd -l` puts a `!` in front of the hash. It defeats password
    // authentication and has no effect on public-key authentication, so a
    // locked account with a live key is fully usable by whoever holds it —
    // which is the exact combination an access review is looking for and the
    // one a naive reading of "locked" files as safe.
    const a = collected(
      ['S L ops', 'U 1 keys ok -', 'U 1 name ops', `K 1 1 60 ssh-ed25519 ${ED25519} old-laptop`],
      OK_STATUS
    )
    expect(a.accounts[0].passwordLocked).toBe(true)
    expect(a.accounts[0].keys).toHaveLength(1)
  })

  it('says the collection is incomplete when sshd reads keys from elsewhere', () => {
    const a = collected(
      ['V keyfile AuthorizedKeysFile /etc/ssh/keys/%u', 'U 1 keys ok -', 'U 1 name ops'],
      OK_STATUS
    )
    expect(a.keyFileIsDefault).toBe(false)
    const s = summariseAccess(a)
    expect(s.certain).toBe(false)
    expect(s.uncertainty.join(' ')).toMatch(/other than the default/)
  })

  it('accepts the stock tab-separated directive as the default', () => {
    // On Debian the stock sshd_config spells it with a tab. Deleting the tab
    // instead of turning it into a space produces
    // `AuthorizedKeysFile.ssh/authorized_keys`, which reads as a non-default
    // path — an alarming, entirely fabricated finding on a stock host.
    const a = collected(
      ['V keyfile AuthorizedKeysFile .ssh/authorized_keys', 'U 1 keys ok -', 'U 1 name ops'],
      OK_STATUS
    )
    expect(a.keyFileIsDefault).toBe(true)
    expect(summariseAccess(a).certain).toBe(true)
  })

  it('cannot decide when the config disagrees with itself', () => {
    // sshd resolves first-match-wins and Debian's Include is at the top of the
    // file, so which of two directives applies is genuinely not knowable from
    // out here. Reported as unknown rather than guessed.
    const a = collected(
      [
        'V keyfile AuthorizedKeysFile .ssh/authorized_keys',
        'V keyfile AuthorizedKeysFile /etc/ssh/keys/%u',
        'U 1 keys ok -',
        'U 1 name ops'
      ],
      OK_STATUS
    )
    expect(a.keyFileIsDefault).toBeNull()
    expect(summariseAccess(a).certain).toBe(false)
  })

  it('treats an AuthorizedKeysCommand as making every count a lower bound', () => {
    const a = collected(
      ['V keycmd AuthorizedKeysCommand /usr/bin/sss_ssh_authorizedkeys', 'U 1 keys ok -', 'U 1 name ops'],
      OK_STATUS
    )
    expect(a.authorizedKeysCommand).toBe('/usr/bin/sss_ssh_authorizedkeys')
    expect(summariseAccess(a).uncertainty.join(' ')).toMatch(/not in any file on disk/)
  })

  it('ignores an AuthorizedKeysCommand of none, which is the default', () => {
    const a = collected(['V keycmd AuthorizedKeysCommand none', 'U 1 keys ok -', 'U 1 name ops'], OK_STATUS)
    expect(a.authorizedKeysCommand).toBeNull()
    expect(summariseAccess(a).certain).toBe(true)
  })

  it('flags a legacy authorized_keys2, which sshd reads and this does not', () => {
    const a = collected(['U 1 keys ok -', 'U 1 keys2 present', 'U 1 name ops'], OK_STATUS)
    expect(a.accounts[0].hasLegacyKeyFile).toBe(true)
    expect(summariseAccess(a).certain).toBe(false)
  })

  it('derives read-N-of-M rather than trusting the shell to have counted', () => {
    const a = collected(
      ['U 1 keys ok -', 'U 1 name ops', 'U 2 keys denied -', 'U 2 name deploy'],
      OK_STATUS
    )
    const s = accessSource(a, 'authorized-keys')
    expect(s.status).toBe('partial')
    expect(s.detail).toContain('read 1 of 2 accounts')
  })

  it('counts an account with no authorized_keys as READ, not as unread', () => {
    // A stock Ubuntu cloud image: `root` has a login shell and no
    // authorized_keys, `ubuntu` has one. `absent` is a POSITIVE finding the
    // collector went to trouble to establish — it tests the traversal of the
    // home directory and of .ssh FIRST so a permission bit can never read as an
    // empty inventory, and only then claims the file is not there.
    //
    // Filing that alongside `denied` made the honesty banner permanent wallpaper
    // on a fully-read estate, and an operator who learns to scroll past the
    // banner is an operator who will scroll past it on the host where it means
    // something. The header of shared/access.ts brags about keeping `denied`,
    // `absent`, `no-tool`, `unsupported` and `partial` apart on the way in;
    // summariseAccess collapsed all five on the way out.
    const a = collected(
      [
        'U 1 uid 0',
        'U 1 shell /bin/bash',
        'U 1 keys absent -',
        'U 1 name root',
        'U 2 uid 1000',
        'U 2 keys ok -',
        'U 2 name ubuntu',
        `K 2 1 60 ssh-ed25519 ${ED25519} ops@laptop`
      ],
      OK_STATUS
    )
    const root = a.accounts.find((x) => x.user === 'root')!
    // An empty list, and the status still says WHY it is empty.
    expect(root.keys).toEqual([])
    expect(root.keysStatus).toBe('absent')
    const s = summariseAccess(a)
    expect(s).toMatchObject({ accountsRead: 2, accountsUnread: 0, keys: 1, certain: true })
    expect(s.uncertainty).toEqual([])
    // And the whole-host source is `ok`, not `partial`.
    expect(accessSource(a, 'authorized-keys').status).toBe('ok')
  })

  it('still refuses to call a denied or unknown account empty', () => {
    // The other half, and the one that must not move. `absent` was CHECKED;
    // `denied`, `unknown`, `no-tool` and `unsupported` were not, and a null is
    // the only honest value for them.
    for (const status of ['denied', 'unknown', 'no-tool', 'unsupported'] as const) {
      const a = collected([`U 1 keys ${status} -`, 'U 1 name ops'], OK_STATUS)
      expect(a.accounts[0].keys, status).toBeNull()
      expect(summariseAccess(a).certain, status).toBe(false)
    }
  })

  it('reports every account denied as denied, not as an empty estate', () => {
    const a = collected(
      ['U 1 keys denied -', 'U 1 name ops', 'U 2 keys denied -', 'U 2 name deploy'],
      OK_STATUS
    )
    expect(accessSource(a, 'authorized-keys').status).toBe('denied')
    expect(summariseAccess(a)).toMatchObject({ accountsRead: 0, accountsUnread: 2, keys: 0, certain: false })
  })

  it('carries the accounts failure forward when nothing could be enumerated', () => {
    const a = collected([], ['accounts denied - /etc/passwd exists and this account cannot read it'])
    expect(accessSource(a, 'authorized-keys').status).toBe('denied')
    expect(a.accounts).toEqual([])
  })

  it('reports every source as unknown when the status block never arrived', () => {
    const a = parseAccessCollection('U 1 keys ok -\nU 1 name ops', { sha256, now: 1 })
    // The list is asserted to be COMPLETE before it is walked. A bare
    // `for (const s of a.sources)` over an empty array is a test that asserts
    // nothing, and `sources: []` is exactly what a refactor that stopped
    // reporting sources at all would produce.
    expect(a.sources.map((s) => s.id).sort()).toEqual([...ACCESS_SOURCE_IDS].sort())
    for (const s of a.sources) expect(s.status, s.id).toBe('unknown')
  })
})

describe('what may and may not be concluded', () => {
  const withUnread = collected(
    [
      'U 1 keys ok -',
      'U 1 name ops',
      `K 1 1 60 ssh-ed25519 ${ED25519} ops@laptop`,
      'U 2 keys denied -',
      'U 2 name deploy'
    ],
    OK_STATUS
  )

  it('refuses to call a partial reading an answer', () => {
    const s = summariseAccess(withUnread)
    expect(s.keys).toBe(1)
    expect(s.accountsUnread).toBe(1)
    expect(s.certain).toBe(false)
    expect(s.uncertainty[0]).toMatch(/1 of 2 accounts could not be read/)
  })

  it('counts an unfingerprintable line as a hole rather than skipping it', () => {
    const a = collected(
      ['U 1 keys ok -', 'U 1 name ops', 'K 1 1 20 garbage line here'],
      OK_STATUS
    )
    const s = summariseAccess(a)
    expect(s.keys).toBe(1)
    expect(s.unfingerprinted).toBe(1)
    expect(s.fingerprints.size).toBe(0)
    expect(s.certain).toBe(false)
  })

  it('lists the hosts a key could not be looked for on, beside the ones it is on', () => {
    // A fingerprint on four hosts that could not be looked for on three more
    // has NOT been shown to be absent from those three. The second list is the
    // set of machines somebody still has to check by hand.
    const clean = collected(
      ['U 1 keys ok -', 'U 1 name ops', `K 1 1 60 ssh-ed25519 ${ED25519} ops@laptop`],
      OK_STATUS
    )
    const p = keyPresence(ED25519_FP, [
      { serverId: 'a', access: clean },
      { serverId: 'b', access: withUnread },
      { serverId: 'c', access: collected(['U 1 keys denied -', 'U 1 name ops'], OK_STATUS) }
    ])
    expect([...p.on.keys()]).toEqual(['a', 'b'])
    // 'b' appears in BOTH: it trusts the key on one account and could not be
    // fully enumerated, and "found here" is not "fully enumerated here".
    expect(p.unreadable).toEqual(['b', 'c'])
  })
})

// ---------------------------------------------------------------------------
// Storage
// ---------------------------------------------------------------------------

describe('what goes into the durable store', () => {
  const a = collected(
    [
      'S L deploy',
      'U 1 keys ok -',
      'U 1 name ops',
      `K 1 1 60 ssh-ed25519 ${ED25519} ops@laptop`,
      'U 2 keys denied -',
      'U 2 name deploy'
    ],
    OK_STATUS
  )
  const facts = accessToFacts(a)

  it('writes a status where a value is missing, never a zero', () => {
    // `access:user:deploy:keys = denied` has to survive into history, or a
    // report written six months from now cannot tell "this account trusted no
    // keys" from "nobody could see whether it did".
    expect(facts['access:user:deploy:keys']).toBe('denied')
    expect(facts['access:user:ops:keys']).toBe('1')
  })

  it('writes no key rows at all for an account it could not read', () => {
    // The delicate part. A fact-removed event on an authorized key reads as
    // "this key was revoked on this host" — the audit trail this item exists to
    // produce, and the thing that must never be fabricated. An account with no
    // rows written contributes nothing that could later look like a revocation.
    const deployRows = Object.keys(facts).filter((k) => k.startsWith(accessKeyPrefix('deploy')))
    expect(deployRows).toEqual([])
    expect(Object.keys(facts)).toContain(`${accessKeyPrefix('ops')}${ED25519_FP}`)
  })

  it('records whether the collection was complete, so history knows too', () => {
    expect(facts['access:complete']).toBe('false')
    expect(facts['access:accountsRead']).toBe('1')
    expect(facts['access:accountsUnread']).toBe('1')
    expect(facts['access:source:authorized-keys']).toBe('partial')
  })
})

// ---------------------------------------------------------------------------
// The reader
// ---------------------------------------------------------------------------

describe('the reader’s failure classification', () => {
  it('calls a transport failure unreachable and invents no inventory', () => {
    // The single most important line in main/services/access.ts. "This host
    // trusts no keys" when the connection never opened is a fabricated
    // all-clear in front of somebody running an access review.
    const r = new AccessReader({ exec: async () => ({ ok: false, error: 'ECONNREFUSED' }) })
    return r.read({}).then((p) => {
      expect(p).toEqual({ ok: false, reason: 'unreachable', detail: 'ECONNREFUSED' })
    })
  })

  it('calls a missing status block no-output rather than an empty host', () => {
    const r = new AccessReader({ exec: async () => ({ ok: true, stdout: 'V now 1\n', stderr: 'csh: syntax' }) })
    return r.read({}).then((p) => {
      expect(p.ok).toBe(false)
      expect(p).toMatchObject({ reason: 'no-output', detail: 'csh: syntax' })
    })
  })

  it('passes the sudo option through to the command it actually sends', () => {
    let sent = ''
    const r = new AccessReader({
      exec: async (_c, command) => {
        sent = command
        return { ok: true, stdout: `${ACCESS_STATUS_MARKER}\naccounts absent -` }
      }
    })
    return r.read({}, { sudo: false }).then(() => {
      // Asserted over the WHOLE command, not a slice of it. A guard whose
      // window ends before the text that could have said `sudo` checks nothing.
      expect(sent).not.toMatch(/\bsudo\b/)
      expect(sent.length).toBeGreaterThan(1000)
    })
  })

  it('never merges stderr into the record region', () => {
    // A `K `-prefixed line from a noisy shell profile would be read as
    // somebody's authorized key.
    const r = new AccessReader({
      exec: async () => ({
        ok: true,
        stdout: `U 1 keys ok -\nU 1 name ops\n${ACCESS_STATUS_MARKER}\n${OK_STATUS.join('\n')}`,
        stderr: `K 1 1 60 ssh-ed25519 ${ED25519} injected`
      })
    })
    return r.read({}).then((p) => {
      expect(p.ok).toBe(true)
      expect((p as { access: HostAccess }).access.accounts[0].keys).toEqual([])
    })
  })
})

// ---------------------------------------------------------------------------
// The collector, actually run
// ---------------------------------------------------------------------------
//
// Everything above tests strings. That is not enough for this item: the whole
// point of it is a shell script that has to tell four indistinguishable
// situations apart, and a shell script is exactly the kind of thing that reads
// correctly and does the wrong thing. So these run the REAL shipped command
// through /bin/sh against a tree built to look like a host.
//
// Deliberately NOT covered here: the sudo branches. A fake `sudo` cannot read a
// directory the test process itself cannot open, so proving "root saw what we
// could not" would need real root. Those are asserted structurally above.

interface FakeHost {
  root: string
  bin: string
  file: (rel: string, body: string) => void
  script: (name: string, body: string) => void
  collect: (opts?: { sudo?: boolean; hide?: string[] }) => string
}

const HIDEABLE = ['passwd', 'lastlog', 'last', 'chage', 'id']

function fakeHost(): FakeHost {
  const root = mkdtempSync(join(tmpdir(), 'sp-access-'))
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

  // shadow-utils' `passwd -S -a`, which is where lock state comes from. It
  // never prints a hash, which is the entire reason it is used.
  script('passwd', '[ "$1" = "-S" ] && { printf "root P 09/13/2024 0 99999 7 -1\\nops L 09/13/2024 0 99999 7 -1\\n"; exit 0; }\nexit 1')
  script(
    'lastlog',
    'printf "Username         Port     From             Latest\\n' +
      'root             pts/0    10.0.0.1         Tue Sep  2 06:00:01 +0000 2026\\n' +
      'ops                                        **Never logged in**\\n"'
  )
  script('chage', 'printf "Last password change : Sep 13, 2024\\nAccount expires : never\\n"')

  return {
    root,
    bin,
    file,
    script,
    collect: ({ sudo = false, hide = [] } = {}) => {
      let cmd = buildAccessCommand({ sudo })
        .replaceAll('/etc/passwd', `${root}/etc/passwd`)
        // Without the trailing slash too: the collector tests `/etc/ssh`
        // itself for traversability before it looks inside it.
        .replaceAll('/etc/ssh', `${root}/etc/ssh`)
      for (const name of hide) {
        cmd = cmd
          .replace(new RegExp(`for c in ${name}[^;]*;`), `for c in sp-absent-${name};`)
          .replace(new RegExp(`SP_BIN=${name}(?=[\\s;]|$)`), `SP_BIN=sp-absent-${name}`)
      }
      return execFileSync('/bin/sh', ['-c', cmd], {
        encoding: 'utf8',
        env: { PATH: `${bin}:/usr/bin:/bin` }
      })
    }
  }
}

const trees: string[] = []
afterAll(() => {
  for (const t of trees) rmSync(t, { recursive: true, force: true })
})

const parse = (out: string): HostAccess => parseAccessCollection(out, { sha256, now: 1_800_000_000_000 })
const acct = (a: HostAccess, user: string): HostAccess['accounts'][number] => {
  const found = a.accounts.find((x) => x.user === user)
  if (!found) throw new Error(`no account reported for ${user}: ${a.accounts.map((x) => x.user).join(',')}`)
  return found
}

describe.skipIf(process.platform === 'win32')('the collector, run against a host-shaped tree', () => {
  function host(): FakeHost {
    const h = fakeHost()
    trees.push(h.root)
    h.file(
      'etc/passwd',
      [
        `root:x:0:0:root:${h.root}/root:/bin/bash`,
        `ops:x:1000:1000:Ops:${h.root}/home/ops:/bin/bash`,
        `deploy:x:1001:1001:Deploy:${h.root}/home/deploy:/usr/sbin/nologin`,
        `noshell:x:1002:1002:No shell:${h.root}/home/noshell:/usr/sbin/nologin`,
        `nohome:x:1003:1003:No home:${h.root}/home/gone:/bin/sh`,
        ''
      ].join('\n')
    )
    h.file('etc/ssh/sshd_config', 'Port 22\nAuthorizedKeysFile\t.ssh/authorized_keys\n')
    h.file('home/ops/.ssh/authorized_keys', `ssh-ed25519 ${ED25519} ops@laptop\n`)
    // A nologin account WITH a key file, which is exactly what a deploy account
    // looks like and exactly the one an inventory must not skip.
    h.file('home/deploy/.ssh/authorized_keys', `ssh-rsa ${RSA2048} ci@build\n`)
    // A nologin account with no key file, which is the noise this filters out.
    mkdirSync(join(h.root, 'home/noshell'), { recursive: true })
    return h
  }

  it('always ends with a status block, whatever it did or did not find', () => {
    const out = host().collect()
    expect(out).toContain(ACCESS_STATUS_MARKER)
    expect(parse(out).sources.map((s) => `${s.id}=${s.status}`)).toEqual([
      'accounts=ok',
      'authorized-keys=ok',
      'sshd-config=ok',
      'account-status=ok',
      // `partial`, and correctly so: the tree names accounts the machine
      // running this test does not have, so `id -nG` answers for some and not
      // for others. That is exactly the shape of a real host where one account
      // comes from a directory service that is down, and reporting it as `ok`
      // would claim group membership had been read for everybody.
      'sudoers=partial',
      'last-login=ok'
    ])
    const a = parse(host().collect())
    expect(a.accounts.filter((x) => x.adminGroups === null).length).toBeGreaterThan(0)
  })

  it('includes a nologin account that has keys and skips one that does not', () => {
    const a = parse(host().collect())
    expect(a.accounts.map((x) => x.user).sort()).toEqual(['deploy', 'nohome', 'ops', 'root'])
    expect(acct(a, 'deploy').keys!.map((k) => k.fingerprint)).toEqual([RSA2048_FP])
    expect(acct(a, 'ops').keys!.map((k) => k.fingerprint)).toEqual([ED25519_FP])
  })

  it('reports a home directory it cannot traverse as denied, NOT as absent', () => {
    // The single most likely way this feature could lie. A home directory this
    // account cannot enter makes `[ -e ~/.ssh/authorized_keys ]` return false,
    // which is indistinguishable from the file not being there — so a
    // permission bit reads as an empty inventory unless the traversal is
    // checked first.
    const h = host()
    chmodSync(join(h.root, 'home/ops'), 0o000)
    try {
      const a = parse(h.collect())
      expect(acct(a, 'ops').keysStatus).toBe('denied')
      expect(acct(a, 'ops').keys).toBeNull()
      // And the host as a whole must stop claiming to be a complete reading.
      expect(accessSource(a, 'authorized-keys').status).toBe('partial')
      expect(summariseAccess(a).certain).toBe(false)
    } finally {
      chmodSync(join(h.root, 'home/ops'), 0o755)
    }
  })

  it('reports an unreadable key file as denied while its directory is fine', () => {
    const h = host()
    chmodSync(join(h.root, 'home/ops/.ssh/authorized_keys'), 0o000)
    try {
      expect(acct(parse(h.collect()), 'ops').keysStatus).toBe('denied')
    } finally {
      chmodSync(join(h.root, 'home/ops/.ssh/authorized_keys'), 0o644)
    }
  })

  it('reports a missing home directory as absent, which it checked', () => {
    expect(acct(parse(host().collect()), 'nohome').keysStatus).toBe('absent')
    expect(acct(parse(host().collect()), 'root').keysStatus).toBe('absent')
  })

  it('flags a legacy authorized_keys2 without reading it', () => {
    const h = host()
    h.file('home/ops/.ssh/authorized_keys2', `ssh-ed25519 ${ED25519_B} hidden\n`)
    const out = h.collect()
    const a = parse(out)
    expect(acct(a, 'ops').hasLegacyKeyFile).toBe(true)
    // Read means read. The key in it must not appear anywhere in the output.
    expect(out).not.toContain(ED25519_B)
    expect(summariseAccess(a).certain).toBe(false)
  })

  it('keeps the stock tab-separated directive readable as the default', () => {
    const a = parse(host().collect())
    expect(a.authorizedKeysFile).toEqual(['.ssh/authorized_keys'])
    expect(a.keyFileIsDefault).toBe(true)
  })

  it('cannot have its status block forged by a file it reads', () => {
    // A comment carrying the marker, a whole line equal to it, and a line
    // shaped like a status entry. None of them may reach the status block.
    const h = host()
    h.file(
      'home/ops/.ssh/authorized_keys',
      [
        `ssh-ed25519 ${ED25519} ${ACCESS_STATUS_MARKER}`,
        ACCESS_STATUS_MARKER,
        'accounts denied - forged by the file',
        `ssh-ed25519 ${ED25519_B} second@key`,
        ''
      ].join('\n')
    )
    const out = h.collect()
    const a = parse(out)
    // Exactly one marker line in the whole output — the one the collector
    // printed itself.
    expect(out.split('\n').filter((l) => l === ACCESS_STATUS_MARKER)).toHaveLength(1)
    expect(accessSource(a, 'accounts').status).toBe('ok')
    expect(acct(a, 'ops').keys!.map((k) => k.fingerprint)).toEqual([
      ED25519_FP,
      null,
      null,
      ED25519_B_FP
    ])
  })

  it('truncates an 8 KB comment on the host and says the line was cut', () => {
    const h = host()
    h.file('home/ops/.ssh/authorized_keys', `ssh-ed25519 ${ED25519} ${'A'.repeat(8192)}\n`)
    const out = h.collect()
    expect(out.split('\n').every((l) => l.length < KEY_LINE_CAP + 64)).toBe(true)
    const k = acct(parse(out), 'ops').keys![0]
    expect(k.problem).toBe('truncated')
    expect(k.fingerprint).toBeNull()
  })

  it('reads a newline in a comment as what it actually is: a second, broken line', () => {
    // A file cannot contain a comment with a newline in it — the newline ends
    // the line. What it produces is a valid key and a malformed line after it,
    // and reporting the second one is the honest outcome: it is a line sshd
    // will look at and reject.
    const h = host()
    h.file('home/ops/.ssh/authorized_keys', `ssh-ed25519 ${ED25519} my\nkey\n`)
    const keys = acct(parse(h.collect()), 'ops').keys!
    expect(keys).toHaveLength(2)
    expect(keys[0]).toMatchObject({ fingerprint: ED25519_FP, comment: 'my', line: 1 })
    expect(keys[1]).toMatchObject({ problem: 'malformed', line: 2 })
  })

  it('keeps an options prefix intact through the shell', () => {
    const h = host()
    h.file(
      'home/ops/.ssh/authorized_keys',
      `command="/usr/bin/rsync --server . /srv",no-pty ssh-ed25519 ${ED25519} backup\n`
    )
    const k = acct(parse(h.collect()), 'ops').keys![0]
    expect(k.fingerprint).toBe(ED25519_FP)
    expect(k.options).toEqual(['command', 'no-pty'])
    expect(k.restricted).toBe(true)
  })

  it('reads a bidi override out of the file and does not pass it on', () => {
    const h = host()
    h.file('home/ops/.ssh/authorized_keys', `ssh-ed25519 ${ED25519} ci‮gnitset@build\n`)
    const k = acct(parse(h.collect()), 'ops').keys![0]
    expect(k.comment).not.toMatch(/[‪-‮]/)
    expect(k.fingerprint).toBe(ED25519_FP)
  })

  // -------------------------------------------------------------------------
  // sshd's config, and the two ways reading part of it read as reading all of it
  // -------------------------------------------------------------------------

  it('says partial, not ok, when a sshd_config.d drop-in cannot be read', () => {
    // A 0600 root-only hardening drop-in is ordinary. The loop skipped it with
    // `[ -f ] && [ -r ] || continue` and then noted `sshd-config ok`
    // unconditionally, so the parser saw zero AuthorizedKeysFile directives,
    // concluded `keyFileIsDefault = true`, and the collection called itself a
    // complete picture of a host whose sshd config it had only partly read.
    //
    // The file skipped here is the one that matters: it moves the key file.
    const h = host()
    h.file('etc/ssh/sshd_config.d/10-hardening.conf', 'AuthorizedKeysFile /etc/ssh/keys/%u\n')
    chmodSync(join(h.root, 'etc/ssh/sshd_config.d/10-hardening.conf'), 0o000)
    const a = parse(h.collect())
    expect(accessSource(a, 'sshd-config').status).toBe('partial')
    // And nothing downstream may conclude the inventory is the whole story.
    expect(a.keyFileIsDefault).toBeNull()
    expect(summariseAccess(a).certain).toBe(false)
  })

  it('says denied, not absent, when /etc/ssh cannot be traversed', () => {
    // `chmod 700 /etc/ssh` is on plenty of hardened images. `[ -e
    // /etc/ssh/sshd_config ]` is then false through an untraversable directory
    // — indistinguishable from the file not being there — so the collector
    // reported `absent`, and `absent` took the parser's "no config, so the
    // compiled-in default applies" branch to `keyFileIsDefault = true`.
    //
    // This is the traversal-before-existence discipline the file applies
    // carefully to home directories at the account loop, and did not apply to
    // /etc/ssh.
    const h = host()
    chmodSync(join(h.root, 'etc/ssh'), 0o000)
    try {
      const a = parse(h.collect())
      expect(accessSource(a, 'sshd-config').status).toBe('denied')
      expect(a.keyFileIsDefault).toBeNull()
      expect(summariseAccess(a).certain).toBe(false)
    } finally {
      chmodSync(join(h.root, 'etc/ssh'), 0o755)
    }
  })

  it('still says absent when /etc/ssh really is not there', () => {
    // The other half. A host with no sshd config at all is a host running the
    // compiled-in default, which IS where this collector looks — and calling
    // that uncertain would be the wallpaper failure in the other direction.
    const h = fakeHost()
    trees.push(h.root)
    h.file('etc/passwd', `ops:x:1000:1000:Ops:${h.root}/home/ops:/bin/bash\n`)
    const a = parse(h.collect())
    expect(accessSource(a, 'sshd-config').status).toBe('absent')
    expect(a.keyFileIsDefault).toBe(true)
  })

  it('reads a drop-in it CAN read and still says ok', () => {
    const h = host()
    h.file('etc/ssh/sshd_config.d/10-cloudimg.conf', 'PasswordAuthentication no\n')
    const a = parse(h.collect())
    expect(accessSource(a, 'sshd-config').status).toBe('ok')
    expect(a.keyFileIsDefault).toBe(true)
  })

  it('says no-tool rather than none when the login database has no reader', () => {
    const a = parse(host().collect({ hide: ['lastlog', 'last'] }))
    expect(accessSource(a, 'last-login').status).toBe('no-tool')
    expect(acct(a, 'root').lastLoginAt).toBeNull()
    expect(acct(a, 'root').neverLoggedIn).toBe(false)
  })

  it('says never-logged-in only when the host said so', () => {
    const a = parse(host().collect())
    expect(acct(a, 'ops').neverLoggedIn).toBe(true)
    expect(acct(a, 'root').neverLoggedIn).toBe(false)
    expect(acct(a, 'root').lastLoginAt).toBe(Date.UTC(2026, 8, 2, 6, 0, 1))
  })

  it('tells a busybox passwd apart from a permission problem', () => {
    // No amount of root fixes a `passwd` with no `-S`, and calling it `denied`
    // would send somebody looking for a sudoers rule that would not help.
    const h = host()
    h.script('passwd', 'echo "BusyBox v1.36.1 multi-call binary." >&2\nexit 1')
    expect(accessSource(parse(h.collect()), 'account-status').status).toBe('unsupported')
  })

  it('says denied when passwd -S exists and refuses', () => {
    const h = host()
    h.script('passwd', 'echo "passwd: Permission denied" >&2\nexit 1')
    const a = parse(h.collect())
    expect(accessSource(a, 'account-status').status).toBe('denied')
    expect(acct(a, 'ops').passwordLocked).toBeNull()
  })

  it('says no-tool when there is no passwd at all', () => {
    expect(accessSource(parse(host().collect({ hide: ['passwd'] })), 'account-status').status).toBe(
      'no-tool'
    )
  })

  it('exits cleanly and still reports when nothing on the host answers', () => {
    // No sshd_config, no tools, no key files. The `|| true` placement and the
    // absence of `set -e` are what make this a collection rather than a crash,
    // and neither can be tested any other way than by running it.
    const h = fakeHost()
    trees.push(h.root)
    h.file('etc/passwd', `ops:x:1000:1000:Ops:${h.root}/home/ops:/bin/bash\n`)
    const a = parse(h.collect({ hide: HIDEABLE }))
    expect(a.sources.map((s) => `${s.id}=${s.status}`)).toEqual([
      'accounts=ok',
      // `ok`, not `absent`. One account was enumerated and its key file was
      // CHECKED and is not there — which is a complete reading of a host that
      // trusts nobody, and a different fact from a host whose accounts could
      // not be enumerated at all.
      'authorized-keys=ok',
      'sshd-config=absent',
      'account-status=no-tool',
      'sudoers=no-tool',
      'last-login=no-tool'
    ])
    expect(acct(a, 'ops').keysStatus).toBe('absent')
    expect(acct(a, 'ops').adminGroups).toBeNull()
  })

  it('reports the account it ran as, and the host’s own clock', () => {
    const a = parse(host().collect())
    expect(a.collectedAs).toBe(execFileSync('id', ['-un'], { encoding: 'utf8' }).trim())
    expect(a.hostNow).toBeGreaterThan(1_700_000_000_000)
  })

  it('runs with no sudo in the command at all when built without it', () => {
    const h = host()
    let cmd = buildAccessCommand({ sudo: false })
    expect(cmd).not.toMatch(/\bsudo\b/)
    // And it still collects — a no-sudo build is the one an account without
    // passwordless sudo actually gets, not a degraded special case.
    cmd = cmd.replaceAll('/etc/passwd', `${h.root}/etc/passwd`).replaceAll('/etc/ssh/', `${h.root}/etc/ssh/`)
    const out = execFileSync('/bin/sh', ['-c', cmd], {
      encoding: 'utf8',
      env: { PATH: `${h.bin}:/usr/bin:/bin` }
    })
    expect(acct(parse(out), 'ops').keys).toHaveLength(1)
  })
})
