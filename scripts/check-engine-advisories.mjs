#!/usr/bin/env node
// Watch the bundled engines for published CVEs.
//
// Bundling OpenVPN and OpenSSL moved their patching onto us. A macOS or Linux
// user used to get fixes from brew or apt within days of an advisory; now they
// get them when ShellPilot cuts a release. Nothing in the build notices that an
// advisory exists, so without this the first warning would be a bug report.
//
// Exit codes are the interface, because the difference matters:
//
//   0  checked, clear
//   1  an advisory affects a pinned version, and is not suppressed
//   2  could not check — network, feed shape, a bad pin
//
// 2 is deliberately not 0. A watcher that reports "clear" when it could not
// reach the feed is worse than no watcher: it manufactures the confidence it
// was built to earn.
//
// ---------------------------------------------------------------- data source
//
// NVD's REST API 2.0, queried by exact CPE with `isVulnerable`. That flag is
// load-bearing, not decoration. Without it, NVD returns every CVE whose
// configuration *mentions* the CPE, including as the platform a different
// product runs on: querying openssl:3.5.8 plainly returns five CVEs, and all
// five are about Mutt, OpenLDAP and mod_ssl. A watch reporting those would be
// ignored inside a week, which is the failure mode this exists to avoid.
//
// With the flag, the same query returns 0, and openssl:3.0.0 — the control —
// returns 60. Both are pinned as fixtures in tests/fixtures/advisories.

import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..')
const BUILD_SCRIPT = join(ROOT, 'scripts', 'build-openvpn.sh')
const SUPPRESSIONS = join(ROOT, 'security', 'engine-advisory-suppressions.json')
const NVD = 'https://services.nvd.nist.gov/rest/json/cves/2.0'

/** Read the pinned versions out of the build script.
 *
 *  Not restated here, and that is the whole point. A version constant copied
 *  into the watcher is a second source of truth that drifts silently: bump the
 *  build, forget the watcher, and it goes on cheerfully certifying a version
 *  nobody ships. Parsing the script means the two cannot disagree. */
export function readPins(source) {
  const pick = (name) => {
    const m = source.match(new RegExp(`^${name}="\\$\\{${name}:-([^}"]+)\\}"`, 'm'))
    if (!m) throw new Error(`no ${name} pin found in build-openvpn.sh`)
    return m[1]
  }
  return {
    // The tag is `v2.6.22`; CPEs carry the bare version.
    openvpn: pick('OPENVPN_TAG').replace(/^v/, ''),
    openssl: pick('OPENSSL_VERSION')
  }
}

export const cpeFor = (product, version) =>
  `cpe:2.3:a:${product}:${product}:${version}:*:*:*:*:*:*:*`

/** Reduce an NVD response to the fields a human needs to triage it. */
export function summarise(payload) {
  return (payload.vulnerabilities ?? []).map((v) => {
    const cve = v.cve
    const metric =
      cve.metrics?.cvssMetricV40?.[0]?.cvssData ??
      cve.metrics?.cvssMetricV31?.[0]?.cvssData ??
      cve.metrics?.cvssMetricV30?.[0]?.cvssData
    return {
      id: cve.id,
      severity: metric?.baseSeverity ?? 'UNKNOWN',
      score: metric?.baseScore ?? null,
      description: (cve.descriptions ?? []).find((d) => d.lang === 'en')?.value ?? ''
    }
  })
}

/** Decide the outcome. Pure, so the tests drive it with recorded payloads.
 *
 *  `today` is injected rather than read from the clock so an expiry test is not
 *  a test that starts failing on a particular morning. */
export function evaluate({ pins, responses, suppressions, today }) {
  const findings = []
  const notes = []

  for (const [product, version] of Object.entries(pins)) {
    // A pin with no response was not checked, and "not checked" must never
    // reduce to "clear" — that is the whole reason this script distinguishes
    // exit 2 from exit 0. Refusing here means a fetch that quietly went
    // missing cannot be laundered into a pass.
    if (!responses[product]) throw new Error(`no advisory response for ${product} ${version}`)

    for (const advisory of summarise(responses[product])) {
      const s = suppressions.find((x) => x.cve === advisory.id)
      if (!s) {
        findings.push({ ...advisory, product, version })
        continue
      }
      // A suppression is a judgement made on a day, about a version. Both can
      // stop being true: the version moves, or the reasoning ages out. Either
      // makes it a finding again rather than a silent pass.
      if (s.appliesToVersion && s.appliesToVersion !== version) {
        findings.push({
          ...advisory,
          product,
          version,
          note: `suppressed for ${product} ${s.appliesToVersion}, but ${version} is pinned`
        })
      } else if (s.reviewBy && s.reviewBy < today) {
        findings.push({
          ...advisory,
          product,
          version,
          note: `suppression lapsed on ${s.reviewBy} and needs re-checking`
        })
      } else {
        notes.push(`${advisory.id} (${product} ${version}) suppressed: ${s.reason}`)
      }
    }
  }

  return { findings, notes }
}

/** GET with retries. NVD rate-limits unauthenticated callers and times out
 *  under load; a nightly job that cries wolf on a slow morning gets muted. */
async function fetchAdvisories(cpe, { retries = 4, wait = 8000, fetchImpl = fetch } = {}) {
  const url = `${NVD}?cpeName=${encodeURIComponent(cpe)}&isVulnerable=`
  let last
  for (let attempt = 0; attempt <= retries; attempt++) {
    if (attempt > 0) await new Promise((r) => setTimeout(r, wait * attempt))
    try {
      const res = await fetchImpl(url)
      if (!res.ok) {
        last = new Error(`NVD returned HTTP ${res.status} for ${cpe}`)
        continue
      }
      const body = await res.json()
      if (typeof body.totalResults !== 'number') {
        // Shape changed, or a proxy served us an error page as JSON. Either
        // way this is "could not check", not "clear".
        last = new Error(`NVD response for ${cpe} has no totalResults`)
        continue
      }
      return body
    } catch (err) {
      last = err
    }
  }
  throw last
}

async function main() {
  const pins = readPins(readFileSync(BUILD_SCRIPT, 'utf8'))
  const { suppressions } = JSON.parse(readFileSync(SUPPRESSIONS, 'utf8'))
  const today = new Date().toISOString().slice(0, 10)

  console.log('Pinned engine versions, read from scripts/build-openvpn.sh:')
  for (const [p, v] of Object.entries(pins)) console.log(`  ${p} ${v}`)
  console.log()

  const responses = {}
  for (const [product, version] of Object.entries(pins)) {
    try {
      responses[product] = await fetchAdvisories(cpeFor(product, version))
    } catch (err) {
      console.error(`Could not check ${product} ${version}: ${err.message}`)
      console.error('Reporting "unable to check" rather than "clear".')
      process.exit(2)
    }
  }

  const { findings, notes } = evaluate({ pins, responses, suppressions, today })

  for (const n of notes) console.log(`suppressed  ${n}`)
  if (notes.length) console.log()

  // Say plainly what is not covered. A green check that quietly means "two of
  // the four bundled binaries" is the same false confidence in a nicer hat.
  console.log('Not watched here: frpc and wintun.dll have no usable CPE feed.')
  console.log('Node dependencies are covered by `npm audit` in CI, Go by go.sum.')
  console.log()

  if (findings.length === 0) {
    console.log('No unsuppressed advisories against the pinned engines.')
    return
  }

  console.error(`${findings.length} advisory/advisories affect a pinned engine:\n`)
  for (const f of findings) {
    console.error(`  ${f.id}  ${f.severity}${f.score ? ` (${f.score})` : ''}  ${f.product} ${f.version}`)
    if (f.note) console.error(`    ${f.note}`)
    console.error(`    ${f.description.replace(/\s+/g, ' ').slice(0, 300)}`)
    console.error(`    https://nvd.nist.gov/vuln/detail/${f.id}\n`)
  }
  console.error('Bump the pin in scripts/build-openvpn.sh and cut a release, or')
  console.error('add a reasoned entry to security/engine-advisory-suppressions.json.')
  process.exit(1)
}

// Only run when invoked directly, so the tests can import the pure parts.
if (process.argv[1] && import.meta.url === `file://${process.argv[1]}`) {
  main().catch((err) => {
    console.error(err)
    process.exit(2)
  })
}
