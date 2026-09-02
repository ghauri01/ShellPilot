// Rewrite resources/bin/manifest.json to describe the binaries as they ACTUALLY
// ship, then re-seal the bundle.
//
// The bug this exists for: every VPN and frp profile refused to start with "The
// bundled tunnel program does not match its expected checksum, so it was not
// run." — on every macOS build ever released, for every user.
//
// The build scripts hash each engine the moment they produce it. electron-builder
// then signs the nested Mach-O binaries, because arm64 macOS will not exec an
// unsigned one at all, and signing REWRITES the file. So the manifest recorded
// the pre-signing bytes while the app shipped the post-signing bytes, and
// `resolveBundled` compared the two and refused to run the engine. Nothing was
// tampered with; the check was asking about a file that no longer existed in
// that form.
//
// Ad-hoc signing is not even deterministic — signing identical input twice
// produces two different files — so there is no ordering of "hash, then sign"
// that can work. The hash has to be taken after the last thing that writes the
// file, which is what this hook is.
//
// Re-sealing afterwards is not optional: editing anything under Contents/
// invalidates the bundle signature, and macOS then reports the app as damaged —
// the exact failure `identity: '-'` in electron-builder.yml exists to avoid.
// Re-signing the bundle does NOT touch the already-signed nested binaries
// (verified: their hashes are identical before and after), so the manifest
// written here stays true.

const { execFileSync } = require('node:child_process')
const { createHash } = require('node:crypto')
const { existsSync, readdirSync, readFileSync, statSync, writeFileSync } = require('node:fs')
const { join } = require('node:path')

const sha256 = (file) => createHash('sha256').update(readFileSync(file)).digest('hex')

/**
 * Point every manifest entry at the bytes now on disk under `binRoot`, and
 * return one line per entry that moved.
 *
 * Pure filesystem work, no signing, so the rule can be tested without building
 * and signing an app bundle. It walks what is actually in the directory rather
 * than what the manifest claims: an entry describing a binary that did not ship
 * is exactly the stale state this exists to stop, and only the directory knows.
 */
function rehashManifest(binRoot) {
  const manifestPath = join(binRoot, 'manifest.json')
  const manifest = JSON.parse(readFileSync(manifestPath, 'utf8'))
  manifest.binaries = manifest.binaries ?? {}

  const changed = []
  for (const platformDir of readdirSync(binRoot)) {
    const dir = join(binRoot, platformDir)
    if (!statSync(dir).isDirectory()) continue
    for (const name of readdirSync(dir)) {
      const file = join(dir, name)
      if (!statSync(file).isFile()) continue
      const entry = manifest.binaries[`${platformDir}/${name}`]
      // Not an engine we track — licence notices and the like live here too.
      if (!entry) continue
      const actual = sha256(file)
      if (entry.sha256 === actual) continue
      changed.push(`${platformDir}/${name} ${entry.sha256.slice(0, 12)} -> ${actual.slice(0, 12)}`)
      entry.sha256 = actual
      entry.size = statSync(file).size
    }
  }

  if (changed.length > 0) writeFileSync(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`)
  return changed
}

exports.rehashManifest = rehashManifest

exports.default = async function afterSign(context) {
  const { appOutDir, packager, electronPlatformName } = context

  // Only macOS re-signs what we shipped. On Windows and Linux nothing rewrites
  // the engines after the build scripts hash them, so the manifest is already
  // true and rewriting it here would be churn.
  if (electronPlatformName !== 'darwin') return

  const app = join(appOutDir, `${packager.appInfo.productFilename}.app`)
  const binRoot = join(app, 'Contents', 'Resources', 'bin')
  if (!existsSync(join(binRoot, 'manifest.json'))) {
    // A build with no engines is a real configuration, and inventing a manifest
    // for it would be worse than leaving it alone.
    console.log('  • after-sign: no bin/manifest.json in the bundle, nothing to re-hash')
    return
  }

  const changed = rehashManifest(binRoot)
  if (changed.length === 0) {
    // Not a no-op worth hiding: if signing ever stops rewriting the binaries,
    // this line is how we find out, rather than assuming the hook still earns
    // its keep.
    console.log('  • after-sign: manifest already matched the signed binaries')
    return
  }
  for (const line of changed) console.log(`  • after-sign: ${line}`)

  // Re-seal with the SAME options electron-builder used, read from its own
  // config rather than repeated here — a hardcoded `--sign -` would silently
  // strip the hardened runtime and the entitlements, and would be wrong the day
  // this project gets a Developer ID.
  const mac = packager.platformSpecificBuildOptions ?? {}
  const args = ['--force', '--sign', mac.identity ?? '-']
  if (mac.hardenedRuntime) args.push('--options', 'runtime')
  if (mac.entitlements) args.push('--entitlements', mac.entitlements)
  args.push(app)
  execFileSync('codesign', args, { stdio: 'inherit' })

  // Prove the thing this hook is for, here, where a failure stops the build.
  // `--deep` is what catches a broken seal over Resources, which is precisely
  // what rewriting the manifest risks.
  execFileSync('codesign', ['--verify', '--strict', '--deep', app], { stdio: 'inherit' })
  console.log('  • after-sign: manifest rewritten and bundle re-sealed')
}
