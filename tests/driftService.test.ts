import { describe, expect, it, vi } from 'vitest'
import {
  DRIFT_FACT_PREFIX,
  DriftReader,
  driftHash,
  driftToFacts,
  readingFromContent,
  sealUnterminatedKeyBlock,
  type DriftExec
} from '../src/main/services/drift'
import {
  DRIFT_MARKER,
  DRIFT_PREVIEW_CHARS,
  DRIFT_STATUS_MARKER,
  driftWatch,
  type DriftWatch,
  type HostDrift
} from '../src/shared/drift'

// Configuration drift — roadmap item 25, the main-process half.
//
// Two things live here and nowhere else, and both are the kind of thing that
// looks fine on screen when it is wrong: the ORDER in which content is
// redacted, hashed and shortened, and what does and does not reach the durable
// store.

const WATCH = driftWatch('sshd-config') as DriftWatch
const TZ = driftWatch('timezone') as DriftWatch

const b64 = (s: string): string => Buffer.from(s, 'utf8').toString('base64')

const collector = (body: string[], complete = true): string =>
  [DRIFT_MARKER, ...body, ...(complete ? [DRIFT_STATUS_MARKER] : [])].join('\n')

const exec =
  (stdout: string, over: Partial<Awaited<ReturnType<DriftExec>>> = {}): DriftExec =>
  async () => ({ ok: true, code: 0, stdout, ...over })

// ---------------------------------------------------------------------------
// Secrets
// ---------------------------------------------------------------------------

describe('a secret in a watched file never reaches the store or the panel', () => {
  const KEY_BODY = 'MIIEowIBAAKCAQEAy8Dbv8prpJ/0kKhlGeJYozo2t60EG8L0561g13R29LvMR5hy'

  it('redacts a whole private key block before it is hashed or shown', () => {
    const content = `# host key\n-----BEGIN RSA PRIVATE KEY-----\n${KEY_BODY}\n-----END RSA PRIVATE KEY-----\n`
    const r = readingFromContent(WATCH, content, {})
    expect(r.preview).not.toContain(KEY_BODY)
    expect(r.redacted).toBe(true)
    // And the hash is a hash of the redacted text, not of the original — the
    // unredacted bytes must not survive this function in ANY form.
    expect(r.hash).not.toBe(driftHash(content))
  })

  it('redacts a key block that has no end marker at all', () => {
    // The bug this ordering exists for, in its purest form. secretRedaction's
    // PEM rule is anchored on BOTH markers; a file that ends mid-key matches
    // nothing and the key body goes through untouched.
    //
    // Fail-first, with the seal removed:
    //   AssertionError: expected '# host key\n-----BEGIN RSA PRIVATE…' not to
    //   contain 'MIIEowIBAAKCAQEAy8Dbv8prpJ/0kKhlGeJYozo2t60EG8L0561g13R29LvMR5hy'
    const content = `# host key\n-----BEGIN RSA PRIVATE KEY-----\n${KEY_BODY}\n`
    const r = readingFromContent(WATCH, content, {})
    expect(r.preview).not.toContain(KEY_BODY)
    expect(r.redacted).toBe(true)
  })

  it('redacts and hashes the whole file, and truncates only the preview', () => {
    // The other half of "redact before you truncate", and the half that decides
    // whether the comparison is worth anything: the cap is a DISPLAY bound. If
    // it were applied first, every hash would be a hash of the first 4000
    // characters and two hosts differing only past that point would be reported
    // identical — the same silent lie `partial` is refused for.
    //
    // Fail-first, with `content.slice(0, DRIFT_PREVIEW_CHARS)` moved above the
    // redaction so everything downstream sees the capped text:
    //   AssertionError: expected '40ec95406d4915e4f9b6d189be65ca8e89367…'
    //   not to be '40ec95406d4915e4f9b6d189be65ca8e89367…' // Object.is equality
    const pad = '# padding line\n'.repeat(Math.ceil(DRIFT_PREVIEW_CHARS / 15))
    const a = readingFromContent(WATCH, `${pad}PermitRootLogin no\n`, {})
    const b = readingFromContent(WATCH, `${pad}PermitRootLogin yes\n`, {})
    expect(a.hash).not.toBe(b.hash)
    expect(a.normalisedHash).not.toBe(b.normalisedHash)
    // And the preview really is bounded, so the whole file is not being carried
    // around in memory under another name.
    expect((a.preview as string).length).toBeLessThanOrEqual(DRIFT_PREVIEW_CHARS)
  })

  it('redacts a key that straddles the preview boundary', () => {
    // A PEM block starting before the cap and ending after it. secretRedaction's
    // rule is anchored on BOTH markers, so an implementation that capped first
    // would keep the BEGIN and the body and drop the END, and the pattern would
    // match nothing.
    const pad = '# padding line\n'.repeat(Math.ceil(DRIFT_PREVIEW_CHARS / 15))
    const content = `${pad}-----BEGIN RSA PRIVATE KEY-----\n${KEY_BODY}\n-----END RSA PRIVATE KEY-----\n`
    const r = readingFromContent(WATCH, content, {})
    expect(r.preview).not.toContain(KEY_BODY)
    expect(r.redacted).toBe(true)
  })

  it('redacts a password assignment sitting in an ordinary config line', () => {
    const r = readingFromContent(WATCH, 'DB_PASSWORD=hunter2\nPort 22\n', {})
    expect(r.preview).not.toContain('hunter2')
    expect(r.preview).toContain('[REDACTED]')
  })

  it('puts nothing but hashes and statuses in the store', () => {
    // The storage decision, asserted against the values rather than against a
    // count of keys: no fact may contain the file, a line of it, or a secret
    // that was in it.
    const content = 'DB_PASSWORD=hunter2\nPort 22\n'
    const drift: HostDrift = { at: 1, readings: [readingFromContent(WATCH, content, {})] }
    const facts = driftToFacts(drift)
    for (const [k, v] of Object.entries(facts)) {
      expect(k.startsWith(DRIFT_FACT_PREFIX), k).toBe(true)
      expect(v, k).not.toContain('hunter2')
      expect(v, k).not.toContain('Port 22')
      expect(v, k).not.toContain('[REDACTED]')
    }
    expect(Object.keys(facts).sort()).toEqual([
      'drift:sshd-config:hash',
      'drift:sshd-config:normalised',
      'drift:sshd-config:redacted',
      'drift:sshd-config:status'
    ])
  })

  it('carries no preview through to the facts, however long it is', () => {
    const drift: HostDrift = {
      at: 1,
      readings: [readingFromContent(WATCH, 'Port 22\n'.repeat(500), {})]
    }
    for (const v of Object.values(driftToFacts(drift))) expect(v.length).toBeLessThan(80)
  })

  it('says on the reading that redaction happened, because it hides differences too', () => {
    // Two hosts whose only difference is inside a redacted span hash the same
    // and are reported identical. An operator has to be able to know that.
    const clean = readingFromContent(WATCH, 'Port 22\n', {})
    expect(clean.redacted).toBeUndefined()
    const dirty = readingFromContent(WATCH, 'Port 22\nAPI_TOKEN=abc123xyz\n', {})
    expect(dirty.redacted).toBe(true)
  })
})

describe('sealing an unterminated key block', () => {
  it('leaves a file with no key in it exactly as it was', () => {
    expect(sealUnterminatedKeyBlock('Port 22\n')).toBe('Port 22\n')
  })

  it('leaves a properly terminated block for the redactor to handle', () => {
    const t = '-----BEGIN RSA PRIVATE KEY-----\nAAA\n-----END RSA PRIVATE KEY-----\n'
    expect(sealUnterminatedKeyBlock(t)).toBe(t)
  })

  it('takes everything after an unterminated BEGIN', () => {
    const out = sealUnterminatedKeyBlock('head\n-----BEGIN EC PRIVATE KEY-----\nAAA\nBBB\n')
    expect(out).toBe('head\n-----BEGIN PRIVATE KEY-----\n[REDACTED]\n-----END PRIVATE KEY-----')
    expect(out).not.toContain('AAA')
  })
})

// ---------------------------------------------------------------------------
// Normalisation, at the point it is used
// ---------------------------------------------------------------------------

describe('two files differing only in a declared-ignorable way', () => {
  it('get the same normalised hash and a different raw one', () => {
    // The pair the whole feature turns on: identical settings, different
    // comment and different trailing whitespace. sshd-config declares
    // `comments` and `trailing-space`, so they compare equal — and the raw
    // hashes still differ, which is what makes the verdict `ignored-difference`
    // rather than `identical`.
    const a = readingFromContent(WATCH, '# managed by puppet\nPort 22\nPermitRootLogin no   \n', {})
    const b = readingFromContent(WATCH, '# managed by ansible\nPort 22\nPermitRootLogin no\n', {})
    expect(a.normalisedHash).toBe(b.normalisedHash)
    expect(a.hash).not.toBe(b.hash)
    expect(a.applied).toEqual(['comments', 'trailing-space'])
    expect(b.applied).toEqual(['comments'])
  })

  it('does not make two genuinely different settings match', () => {
    const a = readingFromContent(WATCH, 'PermitRootLogin no\n', {})
    const b = readingFromContent(WATCH, 'PermitRootLogin yes\n', {})
    expect(a.normalisedHash).not.toBe(b.normalisedHash)
  })

  it('uses the server context it was given for the hostname rule', () => {
    const nginx = driftWatch('nginx-conf') as DriftWatch
    const a = readingFromContent(nginx, 'server_name web-01.example.internal;\n', {
      hostname: 'web-01.example.internal',
      serverName: 'web-01'
    })
    const b = readingFromContent(nginx, 'server_name web-02.example.internal;\n', {
      hostname: 'web-02.example.internal',
      serverName: 'web-02'
    })
    expect(a.normalisedHash).toBe(b.normalisedHash)
    expect(a.applied).toContain('hostnames')
  })
})

// ---------------------------------------------------------------------------
// The reader
// ---------------------------------------------------------------------------

describe('the reader', () => {
  it('reports a transport failure as unreachable and returns no readings at all', () => {
    // A host that could not be reached is not a host whose configuration
    // matches. There is no partial answer here to salvage.
    const reader = new DriftReader({ exec: async () => ({ ok: false, error: 'connect ETIMEDOUT' }) })
    return reader.read({}).then((r) => {
      expect(r.ok).toBe(false)
      if (r.ok) throw new Error('unreachable')
      expect(r.reason).toBe('unreachable')
      expect(r.detail).toBe('connect ETIMEDOUT')
    })
  })

  it('reports output with no marker in it as no-output, quoting stderr', async () => {
    const reader = new DriftReader({
      exec: async () => ({ ok: true, stdout: 'bash: syntax error', stderr: 'not a posix shell' })
    })
    const r = await reader.read({})
    expect(r.ok).toBe(false)
    if (r.ok) return
    expect(r.reason).toBe('no-output')
    expect(r.detail).toBe('not a posix shell')
  })

  it('turns a good collection into hashed readings and stamps the injected clock', async () => {
    const reader = new DriftReader({
      exec: exec(collector(['F timezone ok 14', `D ${b64('Europe/London\n')}`, 'X timezone'])),
      now: () => 4_242,
      watches: [TZ]
    })
    const r = await reader.read({})
    expect(r.ok).toBe(true)
    if (!r.ok) return
    expect(r.drift.at).toBe(4_242)
    expect(r.drift.readings).toHaveLength(1)
    expect(r.drift.readings[0].status).toBe('ok')
    expect(r.drift.readings[0].preview).toBe('Europe/London\n')
    expect(r.drift.readings[0].hash).toBe(driftHash('Europe/London\n'))
  })

  it('keeps a file it could not read as its own status, with no hash', async () => {
    const reader = new DriftReader({
      exec: exec(collector(['F timezone denied -'])),
      watches: [TZ]
    })
    const r = await reader.read({})
    expect(r.ok).toBe(true)
    if (!r.ok) return
    expect(r.drift.readings[0].status).toBe('denied')
    expect(r.drift.readings[0].hash).toBeUndefined()
    expect(r.drift.readings[0].normalisedHash).toBeUndefined()
  })

  it('does not merge stderr into the record region', async () => {
    // A shell profile that prints `D bm9uc2Vuc2U=` on stderr would otherwise be
    // spliced into a file's content block.
    const reader = new DriftReader({
      exec: exec(collector(['F timezone ok 14', `D ${b64('Europe/London\n')}`, 'X timezone']), {
        stderr: 'D bm9uc2Vuc2U=\n'
      }),
      watches: [TZ]
    })
    const r = await reader.read({})
    expect(r.ok).toBe(true)
    if (!r.ok) return
    expect(r.drift.readings[0].preview).toBe('Europe/London\n')
  })

  it('gives every watch a reading even when the server mentioned none of them', async () => {
    const reader = new DriftReader({ exec: exec(collector([])), watches: [TZ, WATCH] })
    const r = await reader.read({})
    expect(r.ok).toBe(true)
    if (!r.ok) return
    expect(r.drift.readings.map((x) => `${x.watchId}=${x.status}`)).toEqual([
      'timezone=unknown',
      'sshd-config=unknown'
    ])
  })

  it('sends the command once, with no sudo in it', async () => {
    const seen: string[] = []
    const reader = new DriftReader({
      exec: async (_cfg, command) => {
        seen.push(command)
        return { ok: true, stdout: collector(['F timezone absent -']) }
      },
      watches: [TZ]
    })
    await reader.read({})
    expect(seen[0]).not.toMatch(/\bsudo\b/)
    expect(seen[0]).toContain("'/etc/timezone'")
  })

  it('classifies a thrown exec as unknown rather than letting it escape', async () => {
    const reader = new DriftReader({
      exec: vi.fn(async () => {
        throw new Error('channel closed')
      })
    })
    const r = await reader.read({})
    expect(r.ok).toBe(false)
    if (r.ok) return
    expect(r.reason).toBe('unknown')
    expect(r.detail).toBe('channel closed')
  })
})

// ---------------------------------------------------------------------------
// Facts
// ---------------------------------------------------------------------------

describe('what is written to history', () => {
  it('writes a status for every watched file, read or not', () => {
    // A complete key set on every collection is what makes an unconditional
    // prefix sweep safe on the sampler's side, and it is what lets a report
    // six months from now say WHY a hash was missing.
    const drift: HostDrift = {
      at: 1,
      readings: [
        { watchId: 'timezone', status: 'ok', hash: 'h', normalisedHash: 'n' },
        { watchId: 'sshd-config', status: 'denied' }
      ]
    }
    expect(driftToFacts(drift)).toEqual({
      'drift:timezone:status': 'ok',
      'drift:timezone:hash': 'h',
      'drift:timezone:normalised': 'n',
      'drift:sshd-config:status': 'denied'
    })
  })

  it('records which rules were doing work, as ids and never as file text', () => {
    const drift: HostDrift = {
      at: 1,
      readings: [
        { watchId: 'timezone', status: 'ok', hash: 'h', normalisedHash: 'n', applied: ['comments', 'blank-lines'] }
      ]
    }
    expect(driftToFacts(drift)['drift:timezone:ignored']).toBe('comments,blank-lines')
  })
})
