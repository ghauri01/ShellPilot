#!/usr/bin/env node
// Fail the build if a packaged app could not open a local terminal.
//
// Everything the local terminal needs at runtime is decided at package time and
// is invisible until someone opens a shell:
//
//   * @lydell/node-pty is a five-file meta package with no binary in it. Its
//     index.js does require(`@lydell/node-pty-${platform}-${arch}`), so the
//     binding lives in a SIBLING package, and unpacking only the meta package
//     out of the asar unpacks nothing that matters.
//   * On macOS and Linux that sibling also ships `spawn-helper`, an executable
//     that is posix_spawn'd rather than dlopen'd. It needs a real path on disk
//     and its +x bit — a .node inside an asar can still be loaded, an
//     executable inside one cannot be run. (mode 644 on that file is what
//     disqualified node-pty@1.1.0 in the first place.)
//     The +x bit is necessary but not sufficient, and this script cannot check
//     the rest: an AppImage is a squashfs mounted at runtime, so on a host whose
//     /tmp is `noexec` the mode bit is intact and the exec still fails with
//     EACCES. pty.node survives that — it is dlopen'd — and spawn-helper does
//     not, which makes it an AppImage-only, host-only failure that no pack
//     inspection can see. It is a manual test (`mount -o remount,noexec /tmp`);
//     the fix, if it bites, is copying spawn-helper to userData at 0700 on
//     first use.
//   * On Windows neither of those files exists at all: the binding is
//     conpty.node plus conpty_console_list.node, and the bundled
//     redistributable ConPTY under conpty/ is deliberately excluded because
//     localPty.ts uses the system one in conhost.exe.
//
// Usage:
//   node scripts/verify-local-pty-pack.mjs <dir> [--platform <p>] [--arch <a>]...
//
// <dir> is electron-builder's output directory (`release`). --platform and
// --arch default to this machine's, which is right for a --dir pack; the
// release workflow passes `--arch x64 --arch arm64` on macOS, because one job
// packs one node_modules into both bundles and both architectures' prebuilds
// therefore have to be in it.
//
// Prints ::error:: and exits non-zero on any failure, like
// scripts/verify-bin-manifest.mjs.
import { readFileSync } from 'node:fs'
import { readdir, stat } from 'node:fs/promises'
import { dirname, join, resolve, sep } from 'node:path'
import { fileURLToPath } from 'node:url'

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const PACKAGE = '@lydell/node-pty'

function parseArgs(argv) {
  const out = { dir: null, platform: process.platform, archs: [] }
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i]
    if (a === '--platform') out.platform = argv[++i]
    else if (a === '--arch') out.archs.push(argv[++i])
    else if (a.startsWith('--')) {
      console.error(`::error::unknown option ${a}`)
      process.exit(1)
    } else if (out.dir === null) out.dir = a
  }
  if (!out.dir) out.dir = 'release'
  if (out.archs.length === 0) out.archs = [process.arch]
  return out
}

// Every packed bundle under the output directory, as the path of its
// `resources` directory — the one place the layout is the same on all three
// platforms. electron-builder writes mac/ and mac-arm64/ for macOS,
// win-unpacked/ for Windows and linux-unpacked/ for Linux, and a --dir pack and
// a full installer build leave the same directories behind, so this looks for
// the shape rather than for any of those names.
async function findPackedResources(dir) {
  const found = []
  async function walk(current, depth) {
    if (depth > 4) return
    let entries
    try {
      entries = await readdir(current, { withFileTypes: true })
    } catch {
      return
    }
    for (const e of entries) {
      if (!e.isDirectory()) continue
      const p = join(current, e.name)
      if (e.name.endsWith('.app')) {
        found.push(join(p, 'Contents', 'Resources'))
        continue
      }
      if (e.name === 'resources') {
        found.push(p)
        continue
      }
      await walk(p, depth + 1)
    }
  }
  await walk(dir, 0)
  return found
}

async function listFiles(dir) {
  const out = []
  async function walk(current) {
    let entries
    try {
      entries = await readdir(current, { withFileTypes: true })
    } catch {
      return
    }
    for (const e of entries) {
      const p = join(current, e.name)
      if (e.isDirectory()) await walk(p)
      else out.push(p)
    }
  }
  await walk(dir)
  return out
}

async function main() {
  const { dir, platform, archs } = parseArgs(process.argv.slice(2))

  // Inert without the dependency: the whole packaging change is additive, and
  // this script exists to protect node-pty, not to mandate it.
  let deps = {}
  try {
    deps = JSON.parse(readFileSync(join(ROOT, 'package.json'), 'utf8')).dependencies ?? {}
  } catch (e) {
    console.error(`::error::cannot read package.json (${e.message})`)
    process.exit(1)
  }
  if (!(PACKAGE in deps)) {
    console.log(`${PACKAGE} is not a dependency of this build; nothing to verify.`)
    return
  }

  const outDir = resolve(dir)
  const roots = await findPackedResources(outDir)
  if (roots.length === 0) {
    console.error(`::error::no packed application found under ${dir}/ — did electron-builder run?`)
    process.exit(1)
  }

  const problems = []
  for (const resources of roots) {
    const label = resources.slice(outDir.length + 1) || resources
    const lydell = join(resources, 'app.asar.unpacked', 'node_modules', '@lydell')

    let ok = false
    try {
      ok = (await stat(join(lydell, 'node-pty'))).isDirectory()
    } catch {
      /* reported below */
    }
    if (!ok) {
      // The asarUnpack pattern for the meta package was dropped, or this
      // bundle is not an Electron app at all.
      problems.push(`${label}: ${PACKAGE} is not unpacked (${lydell}/node-pty does not exist)`)
      continue
    }

    const files = await listFiles(lydell)
    const rel = files.map((f) => f.slice(lydell.length + 1).split(sep).join('/'))
    const before = problems.length

    // The load-bearing assertion, and the one that fails when a macOS x64 dmg
    // is packed from an arm64-only node_modules: the binding is looked up as
    // @lydell/node-pty-<platform>-<arch>, at runtime, on the user's machine.
    for (const arch of archs) {
      const pkg = `node-pty-${platform}-${arch}`
      const prebuilds = `${pkg}/prebuilds/${platform}-${arch}/`
      const binding = platform === 'win32' ? 'conpty.node' : 'pty.node'
      if (!rel.some((f) => f === `${prebuilds}${binding}`)) {
        problems.push(`${label}: ${prebuilds}${binding} is missing — the ${arch} build has no PTY binding`)
      }
      if (platform === 'win32') {
        // windowsPtyAgent.js forks a console-list agent that loads this one.
        if (!rel.some((f) => f === `${prebuilds}conpty_console_list.node`)) {
          problems.push(`${label}: ${prebuilds}conpty_console_list.node is missing`)
        }
      } else if (platform === 'darwin') {
        // spawn-helper is macOS-only, and this check used to run on Linux too,
        // which failed the first 0.8.0 build. It exists to avoid fork() in a
        // hardened-runtime process, where Big Sur and later charge roughly
        // 300ms per spawn (microsoft/node-pty#476) — a macOS problem with a
        // macOS fix. The Linux sibling ships prebuilds/linux-x64/pty.node and
        // nothing else, and forks directly.
        //
        // Not just present: executable. asar's runtime extraction does not
        // preserve the mode bit, which is why the directory is unpacked at
        // build time instead.
        const helper = `${prebuilds}spawn-helper`
        const onDisk = files[rel.indexOf(helper)]
        if (!onDisk) {
          problems.push(`${label}: ${helper} is missing — every spawn would fail with ENOENT`)
        } else {
          const mode = (await stat(onDisk)).mode
          if ((mode & 0o111) === 0) {
            problems.push(`${label}: ${helper} is mode ${(mode & 0o777).toString(8)}, not executable`)
          }
        }
      }
    }

    // The redistributable ConPTY is excluded in electron-builder.yml; the
    // bindings that sit one level above it must survive that exclusion.
    for (const f of rel) {
      if (f.includes('/conpty/')) problems.push(`${label}: ${f} should have been excluded from the build`)
      if (f.endsWith('.pdb')) problems.push(`${label}: ${f} is a debug symbol file and should not ship`)
    }

    if (problems.length === before) console.log(`ok  ${label}  ${rel.length} unpacked file(s) under @lydell`)
  }

  if (problems.length) {
    for (const p of problems) console.error(`::error::${p}`)
    console.error(
      'This pack is not what the local terminal needs at runtime. Check the asarUnpack\n' +
        'and files patterns in electron-builder.yml, and on macOS that both prebuild\n' +
        'siblings were installed before packaging.'
    )
    process.exit(1)
  }
  console.log(`node-pty pack verified for ${platform}-${archs.join(', ')}`)
}

main().catch((e) => {
  console.error(e)
  process.exit(1)
})
