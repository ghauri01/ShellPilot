#!/usr/bin/env node
// Fail the build if the tunnel engines for the host platform are missing or do
// not match resources/bin/manifest.json.
//
// electron-builder pulls resources/bin/${platform}-${arch} in through
// extraResources, and a missing directory there is not an error at package
// time — it just produces an installer with no engines, which fails at runtime
// as "binary-missing" on every profile the user has. That is a bad way to find
// out, so this runs between the engine build and the package step.
//
// It also re-verifies the hashes, which catches the case the app itself guards
// against: a build machine where something rewrote a binary after it was
// hashed.
import { createHash } from 'node:crypto'
import { createReadStream } from 'node:fs'
import { readFile, stat } from 'node:fs/promises'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const BIN_ROOT = join(ROOT, 'resources', 'bin')

// Every engine the app expects to find. Keep this in step with the drivers:
// an engine added to the app but not listed here would ship missing and this
// check would pass.
const REQUIRED = ['shellpilot-netd', 'frpc']

function sha256File(path) {
  return new Promise((res, rej) => {
    const h = createHash('sha256')
    const s = createReadStream(path)
    s.on('error', rej)
    s.on('data', (c) => h.update(c))
    s.on('end', () => res(h.digest('hex')))
  })
}

// Which platform-arch directories this build needs. A macOS release is a
// universal-ish dual build (x64 and arm64 dmgs), so both are required there;
// the other two ship a single arch.
function requiredDirs() {
  if (process.platform === 'darwin') return ['darwin-x64', 'darwin-arm64']
  if (process.platform === 'win32') return ['win32-x64']
  return ['linux-x64']
}

async function main() {
  let manifest
  try {
    manifest = JSON.parse(await readFile(join(BIN_ROOT, 'manifest.json'), 'utf8'))
  } catch (e) {
    console.error(`::error::resources/bin/manifest.json is missing or unreadable (${e.message}).`)
    console.error('Run `npm run build:engines` before packaging.')
    process.exit(1)
  }

  const problems = []
  for (const dir of requiredDirs()) {
    for (const name of REQUIRED) {
      const exe = dir.startsWith('win32') ? '.exe' : ''
      const key = `${dir}/${name}${exe}`
      const entry = manifest.binaries?.[key]
      if (!entry) {
        problems.push(`${key}: not in the manifest`)
        continue
      }
      const file = join(BIN_ROOT, dir, `${name}${exe}`)
      let st
      try {
        st = await stat(file)
      } catch {
        problems.push(`${key}: listed in the manifest but not on disk`)
        continue
      }
      if (st.size !== entry.size) {
        problems.push(`${key}: size ${st.size} does not match the manifest's ${entry.size}`)
        continue
      }
      const actual = await sha256File(file)
      if (actual !== entry.sha256) {
        problems.push(`${key}: sha256 ${actual} does not match the manifest's ${entry.sha256}`)
        continue
      }
      // `version` is what binaries.ts reports to the UI. Without it the
      // resolver falls back to running the binary with --version, and
      // shellpilot-netd answers that in JSON — so a missing field here shows
      // up as a JSON document where a version number should be.
      if (!entry.version) problems.push(`${key}: no version recorded in the manifest`)
      console.log(`ok  ${key}  ${entry.sha256.slice(0, 12)}  ${st.size} bytes  v${entry.version}`)
    }
  }

  if (problems.length) {
    for (const p of problems) console.error(`::error::${p}`)
    console.error('Run `npm run build:engines`, then try again.')
    process.exit(1)
  }
  console.log('engine manifest verified')
}

main().catch((e) => {
  console.error(e)
  process.exit(1)
})
