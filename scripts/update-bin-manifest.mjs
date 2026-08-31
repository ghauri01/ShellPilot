#!/usr/bin/env node
// Rebuild resources/bin/manifest.json for one engine, leaving the other
// engines' entries alone.
//
// Two build scripts write into the same tree (build-sidecar.sh, build-frpc.sh)
// and they run independently, so neither can own the whole file: whichever ran
// last would erase the other's entries and the app would refuse to exec a
// binary it has no hash for. Merging here, keyed by binary name, is what makes
// the two scripts order-independent.
//
// Usage: node scripts/update-bin-manifest.mjs <binaryBaseName>
//   e.g. node scripts/update-bin-manifest.mjs frpc
//        node scripts/update-bin-manifest.mjs shellpilot-netd
import { createHash } from 'node:crypto'
import { createReadStream } from 'node:fs'
import { mkdir, readdir, readFile, stat, writeFile } from 'node:fs/promises'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const BIN_ROOT = join(ROOT, 'resources', 'bin')
const MANIFEST = join(BIN_ROOT, 'manifest.json')

// Node's platform-arch names. These are the directory names because they are
// what process.platform/process.arch produce at runtime and what
// electron-builder's ${platform}-${arch} macro expands to, so one string
// works in a dev checkout and in a packaged app alike.
const PLATFORM_DIRS = [
  'darwin-x64',
  'darwin-arm64',
  'linux-x64',
  'linux-arm64',
  'win32-x64',
  'win32-arm64'
]

function sha256File(path) {
  return new Promise((res, rej) => {
    const h = createHash('sha256')
    const s = createReadStream(path)
    s.on('error', rej)
    s.on('data', (c) => h.update(c))
    s.on('end', () => res(h.digest('hex')))
  })
}

async function readManifest() {
  try {
    const parsed = JSON.parse(await readFile(MANIFEST, 'utf8'))
    if (parsed && typeof parsed === 'object' && parsed.binaries) return parsed
  } catch {
    // No manifest yet, or an unreadable one. Either way we are about to write
    // a complete one for this engine; a corrupt file is not worth preserving.
  }
  return { version: 1, binaries: {} }
}

async function main() {
  const name = process.argv[2]
  if (!name) {
    console.error('usage: update-bin-manifest.mjs <binaryBaseName>')
    process.exit(2)
  }

  await mkdir(BIN_ROOT, { recursive: true })
  const manifest = await readManifest()

  // Drop this engine's existing entries first, so a target that is no longer
  // built does not linger with a stale hash.
  for (const key of Object.keys(manifest.binaries)) {
    const base = key.split('/').pop() ?? ''
    if (base === name || base === `${name}.exe`) delete manifest.binaries[key]
  }

  let found = 0
  for (const dir of PLATFORM_DIRS) {
    const exe = dir.startsWith('win32') ? '.exe' : ''
    const file = join(BIN_ROOT, dir, `${name}${exe}`)
    let st
    try {
      st = await stat(file)
    } catch {
      continue
    }
    if (!st.isFile() || st.size === 0) continue
    // `version` is the field binaries.ts reads. It matters: without it the
    // resolver falls back to running the binary with --version, and
    // shellpilot-netd answers that in JSON — so the engine version shown in
    // the UI would be a JSON document rather than a version.
    const version = process.env[`${name.toUpperCase().replace(/-/g, '_')}_VERSION`]
    manifest.binaries[`${dir}/${name}${exe}`] = {
      sha256: await sha256File(file),
      size: st.size,
      // Recorded for support: "which build is this?" is otherwise unanswerable
      // once the binary is stripped.
      version: version ?? undefined
    }
    found++
  }

  if (found === 0) {
    console.error(`no ${name} binaries found under ${BIN_ROOT}`)
    process.exit(1)
  }

  await writeFile(MANIFEST, `${JSON.stringify(manifest, null, 2)}\n`, 'utf8')
  console.log(`manifest: ${found} ${name} target(s)`)

  // Report anything present but unlisted — an unrecognised file in the bin
  // tree will fail verification at runtime, and finding that out at build time
  // is much cheaper.
  for (const dir of PLATFORM_DIRS) {
    let entries
    try {
      entries = await readdir(join(BIN_ROOT, dir))
    } catch {
      continue
    }
    for (const e of entries) {
      if (!manifest.binaries[`${dir}/${e}`]) console.warn(`warning: ${dir}/${e} is not in the manifest`)
    }
  }
}

main().catch((e) => {
  console.error(e)
  process.exit(1)
})
