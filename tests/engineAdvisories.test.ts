import { readFileSync } from 'node:fs'
import { describe, expect, it } from 'vitest'
// The script is plain ESM with no types of its own. It used to carry a
// `@ts-expect-error`; under `tsconfig.tests.json`'s `allowJs` TypeScript infers
// its exports instead, so the directive was reported unused.
import { cpeFor, evaluate, readPins, summarise } from '../scripts/check-engine-advisories.mjs'

// Bundling OpenVPN and OpenSSL made their CVEs ours to patch. This suite covers
// the watcher that notices.
//
// Every NVD payload here was recorded from the live API rather than written by
// hand, because the thing most likely to be wrong about a feed reader is what
// the feed actually looks like. Fixtures mean the suite never touches the
// network: a test that fails when NVD is slow teaches people to ignore it.

const fixture = (name: string): unknown =>
  JSON.parse(readFileSync(`tests/fixtures/advisories/${name}.json`, 'utf8'))

const CLEAR = fixture('nvd-openssl-3.5.8-clear')
const DCO = fixture('nvd-openvpn-2.6.22-dco')
const VULNERABLE = fixture('nvd-openssl-3.0.0-vulnerable')

const SUPPRESSIONS = JSON.parse(readFileSync('security/engine-advisory-suppressions.json', 'utf8'))
  .suppressions as {
  cve: string
  reason: string
  addedOn: string
  reviewBy: string
  appliesToVersion: string
  detail: string[]
}[]

const NONE: unknown[] = []
const empty = { totalResults: 0, vulnerabilities: NONE }

describe('reading the pins', () => {
  // The watcher parses the build script instead of restating the versions. A
  // copy would drift the first time someone bumps one and not the other, and
  // it would drift silently — still green, now certifying a version nobody
  // ships. These tests are what make parsing safe to rely on.
  const source = readFileSync('scripts/build-openvpn.sh', 'utf8')

  it('agrees with the versions the build actually uses', () => {
    const pins = readPins(source)
    expect(source).toContain(`OPENVPN_TAG="\${OPENVPN_TAG:-v${pins.openvpn}}"`)
    expect(source).toContain(`OPENSSL_VERSION="\${OPENSSL_VERSION:-${pins.openssl}}"`)
  })

  it('strips the tag prefix, because a CPE carries a bare version', () => {
    expect(readPins(source).openvpn).not.toMatch(/^v/)
  })

  it('refuses to guess when a pin is missing', () => {
    // Failing loudly beats defaulting: a watcher that invents a version checks
    // something nobody ships and reports it clear.
    expect(() => readPins('OPENSSL_VERSION="${OPENSSL_VERSION:-3.5.8}"\n')).toThrow(/OPENVPN_TAG/)
  })
})

describe('the CPE query', () => {
  it('builds the exact form NVD matches on', () => {
    expect(cpeFor('openvpn', '2.6.22')).toBe('cpe:2.3:a:openvpn:openvpn:2.6.22:*:*:*:*:*:*:*')
  })
})

describe('reading a response', () => {
  it('pulls out what a human needs to triage', () => {
    const [a] = summarise(DCO)
    expect(a.id).toBe('CVE-2026-11604')
    expect(a.severity).toBe('MEDIUM')
    expect(a.description).toContain('ovpn-dco-win')
  })

  it('reports an unscored advisory rather than dropping it', () => {
    // A CVE awaiting analysis has no CVSS vector. Skipping it because it is
    // hard to rank would hide the newest advisories, which are the ones worth
    // knowing about.
    const [a] = summarise({
      vulnerabilities: [{ cve: { id: 'CVE-9999-1', descriptions: [{ lang: 'en', value: 'x' }] } }]
    })
    expect(a.severity).toBe('UNKNOWN')
    expect(a.score).toBeNull()
  })

  it('treats an empty response as empty, not as an error', () => {
    expect(summarise(CLEAR)).toEqual([])
  })
})

describe('the verdict', () => {
  const base = {
    pins: { openvpn: '2.6.22', openssl: '3.5.8' },
    suppressions: SUPPRESSIONS,
    today: '2026-08-31'
  }

  it('passes when both engines come back clear', () => {
    const { findings } = evaluate({ ...base, responses: { openvpn: empty, openssl: CLEAR } })
    expect(findings).toEqual([])
  })

  it('fails on an advisory nobody has ruled on', () => {
    // The control: OpenSSL 3.0.0's real CVEs, against a pin claiming to be it.
    const { findings } = evaluate({
      ...base,
      pins: { openssl: '3.0.0' },
      responses: { openssl: VULNERABLE }
    })
    expect(findings.length).toBeGreaterThan(0)
    expect(findings[0].product).toBe('openssl')
  })

  it('passes a suppressed advisory, and says why in the log rather than hiding it', () => {
    const { findings, notes } = evaluate({
      ...base,
      responses: { openvpn: DCO, openssl: CLEAR }
    })
    expect(findings).toEqual([])
    expect(notes.join('\n')).toContain('CVE-2026-11604')
    expect(notes.join('\n')).toContain('ovpn-dco-win')
  })

  it('stops honouring a suppression once the pin moves', () => {
    // The reasoning was recorded about 2.6.22. It may still hold at 2.7.0 and
    // it may not, and the watcher is not the thing that can tell. Re-raising
    // asks a human; assuming would be the failure this file exists to prevent.
    const { findings } = evaluate({
      ...base,
      pins: { openvpn: '2.7.0' },
      responses: { openvpn: DCO }
    })
    expect(findings).toHaveLength(1)
    expect(findings[0].note).toContain('2.7.0 is pinned')
  })

  it('stops honouring a suppression once it is past review', () => {
    const { findings } = evaluate({
      ...base,
      pins: { openvpn: '2.6.22' },
      today: '2099-01-01',
      responses: { openvpn: DCO }
    })
    expect(findings).toHaveLength(1)
    expect(findings[0].note).toContain('lapsed')
  })

  it('refuses to call a pin clear when it was never checked', () => {
    // The failure this whole script is shaped around. A response that went
    // missing must surface as an error the runner turns into exit 2, never as
    // an empty finding list that reads exactly like good news.
    expect(() => evaluate({ ...base, responses: { openvpn: empty } })).toThrow(/openssl/)
  })

  it('never lets an existing suppression cover a new CVE', () => {
    // Matching on anything looser than an exact id — a prefix, a product, a
    // year — would let tomorrow's advisory inherit yesterday's excuse.
    const invented = JSON.parse(JSON.stringify(DCO))
    invented.vulnerabilities[0].cve.id = 'CVE-2027-00001'
    const { findings } = evaluate({
      ...base,
      pins: { openvpn: '2.6.22' },
      responses: { openvpn: invented }
    })
    expect(findings).toHaveLength(1)
    expect(findings[0].id).toBe('CVE-2027-00001')
  })
})

describe('the suppression file', () => {
  it('gives every entry a reason, a date and a review date', () => {
    for (const s of SUPPRESSIONS) {
      expect(s.cve, 'suppression without a CVE id').toMatch(/^CVE-\d{4}-\d{4,}$/)
      expect(s.reason?.length, `${s.cve} has no reason`).toBeGreaterThan(10)
      expect(s.addedOn, `${s.cve} has no addedOn`).toMatch(/^\d{4}-\d{2}-\d{2}$/)
      expect(s.reviewBy, `${s.cve} has no reviewBy`).toMatch(/^\d{4}-\d{2}-\d{2}$/)
      expect(s.appliesToVersion, `${s.cve} does not say which version`).toBeTruthy()
      expect(s.reviewBy > s.addedOn, `${s.cve} expires before it was added`).toBe(true)
    }
  })

  it('argues reachability, not severity', () => {
    // "Only medium" is not a reason to ignore a CVE in something we ship; "the
    // code is not compiled in" is. This catches the tempting bad entry.
    for (const s of SUPPRESSIONS) {
      const prose = `${s.reason} ${(s.detail ?? []).join(' ')}`.toLowerCase()
      expect(prose, `${s.cve} argues from severity`).not.toMatch(
        /\b(low severity|only medium|score is low|not important|minor issue)\b/
      )
    }
  })

  it('keeps CVE-2026-11604 justified by the build flag that is actually set', () => {
    // The suppression rests on --disable-dco. If that flag ever leaves the
    // build, the reasoning is void and this test is what notices.
    const entry = SUPPRESSIONS.find((s) => s.cve === 'CVE-2026-11604')
    expect(entry).toBeDefined()
    expect(readFileSync('scripts/build-openvpn.sh', 'utf8')).toContain('--disable-dco')
  })
})
