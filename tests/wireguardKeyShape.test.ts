import { describe, expect, it } from 'vitest'
import { generateKeyPairSync } from 'node:crypto'
import { isWireGuardKey } from '../src/shared/vpn'
import { redactOutput } from '../src/main/services/secretRedaction'
import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'

// The 43rd character of a base64-encoded 32-byte value is constrained, and
// getting its character class wrong is both silent and expensive.
//
// A WireGuard key is 32 bytes. Base64 emits 44 characters; the last is always
// `=`, and the 43rd encodes only the low nibble of the final byte shifted left
// by two. That takes sixteen values — 0, 4, ... 60 — which are base64
// `AEIMQUYcgkosw048`.
//
// The first thirteen are letters and the last three are digits, which is
// exactly why `048` gets dropped. When it was, 19% of real keys were affected:
// the form refused them as malformed, and — the part that matters — the log
// redactor let them through, so roughly one private key in five would have
// been written to the log ring and the audit log in the clear.
//
// These tests generate real X25519 keys rather than fixtures, because a
// fixture set is chosen by whoever wrote the regex and will agree with it by
// construction.

const LEGAL_43RD = 'AEIMQUYcgkosw048'
const B64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'

function realKey(): string {
  const { privateKey } = generateKeyPairSync('x25519')
  // The raw scalar is the last 32 bytes of the PKCS#8 DER encoding.
  return privateKey.export({ type: 'pkcs8', format: 'der' }).subarray(-32).toString('base64')
}

describe('the constrained character', () => {
  it('is exactly the sixteen values the encoding can produce', () => {
    // (byte31 & 0x0F) << 2 → 0, 4, ... 60.
    const derived = Array.from({ length: 16 }, (_, i) => B64[i * 4]).join('')
    expect(derived).toBe(LEGAL_43RD)
  })

  it('includes the three digits, which is the part that gets dropped', () => {
    for (const c of ['0', '4', '8']) expect(LEGAL_43RD).toContain(c)
  })
})

describe('isWireGuardKey', () => {
  it('accepts every one of 2000 real keys', () => {
    const rejected: string[] = []
    for (let i = 0; i < 2000; i++) {
      const k = realKey()
      if (!isWireGuardKey(k)) rejected.push(k)
    }
    expect(
      rejected.slice(0, 5),
      `${rejected.length}/2000 real WireGuard keys were rejected. If the rejected ` +
        `keys end in 0, 4 or 8, the final character class is missing "048".`
    ).toEqual([])
  })

  it('accepts a key ending in each legal character', () => {
    // Constructed rather than generated, so a run cannot miss a rare case.
    for (const c of LEGAL_43RD) {
      const key = `${'A'.repeat(42)}${c}=`
      expect(isWireGuardKey(key), `rejected a key ending in "${c}="`).toBe(true)
    }
  })

  it('still rejects things that are not keys', () => {
    expect(isWireGuardKey('')).toBe(false)
    expect(isWireGuardKey('not-a-key')).toBe(false)
    // Wrong length.
    expect(isWireGuardKey(`${'A'.repeat(41)}A=`)).toBe(false)
    expect(isWireGuardKey(`${'A'.repeat(43)}A=`)).toBe(false)
    // No padding.
    expect(isWireGuardKey('A'.repeat(44))).toBe(false)
    // A 43rd character the encoding cannot produce: 'B' is value 1, and only
    // multiples of 4 are reachable.
    expect(isWireGuardKey(`${'A'.repeat(42)}B=`)).toBe(false)
    expect(isWireGuardKey(`${'A'.repeat(42)}1=`)).toBe(false)
  })
})

describe('the log redactor', () => {
  it('blanks every one of 2000 real keys', () => {
    // This is the security-relevant half. A key the form rejects is an
    // annoyance; a key the redactor misses is a private key in the audit log.
    const leaked: string[] = []
    for (let i = 0; i < 2000; i++) {
      const k = realKey()
      const line = `[netd] configuring peer with private_key ${k} on utun4`
      if (redactOutput(line).includes(k)) leaked.push(k)
    }
    expect(
      leaked.slice(0, 5),
      `${leaked.length}/2000 real WireGuard keys survived redaction. Check the ` +
        `final character class in secretRedaction.ts.`
    ).toEqual([])
  })

  it('does not eat ordinary base64-looking output', () => {
    // A sha256 digest and a longer blob must survive, or every log line
    // carrying a hash turns into [REDACTED].
    const digest = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
    expect(redactOutput(`sha256=${digest}`)).toContain(digest)
    const long = Buffer.alloc(64, 7).toString('base64')
    expect(redactOutput(`blob ${long}`)).toContain(long)
  })
})

describe('the sidecar carries the same class', () => {
  it('matches the TypeScript one character for character', () => {
    // netd redacts on its own side too, as a last line of defence before
    // anything crosses the pipe. Two copies of one rule drift; this is what
    // notices.
    const go = readFileSync(resolve(__dirname, '../sidecar/netd/tunnel.go'), 'utf8')
    const m = /\[A-Za-z0-9\+\/\]\{42\}\[([A-Za-z0-9]+)\]=/.exec(go)
    expect(m, 'could not find the key regex in sidecar/netd/tunnel.go').not.toBeNull()
    expect(m?.[1]).toBe(LEGAL_43RD)
  })

  it('matches the redactor rule in secretRedaction.ts', () => {
    const ts = readFileSync(
      resolve(__dirname, '../src/main/services/secretRedaction.ts'),
      'utf8'
    )
    const m = /\{42\}\[([A-Za-z0-9]+)\]=/.exec(ts)
    expect(m?.[1]).toBe(LEGAL_43RD)
  })
})
