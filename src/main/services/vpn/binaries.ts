import { execFile } from 'node:child_process'
import { createHash } from 'node:crypto'
import { createReadStream } from 'node:fs'
import { readFile, realpath, stat } from 'node:fs/promises'
import { delimiter, dirname, isAbsolute, join, relative, sep } from 'node:path'
import { app } from 'electron'
import type { VpnEngineInfo, VpnKind } from '../../../shared/vpn'
import { isEngineBundledOn } from '../../../shared/vpnEngines'
import { VpnError } from './errors'

// Deciding which file to execute is the whole of this module, and it is the
// single most security-sensitive decision the VPN layer makes: everything
// downstream runs with the user's privileges and, in system mode, with the
// user's elevation. Two entirely separate paths:
//
//  - `resolveBundled` for what we ship. We know the exact bytes, so we check
//    them against a manifest on every app run before the first exec (E42).
//  - `resolveSystem` for an engine the user already has. We cannot know the
//    bytes, so we constrain *where* it may come from instead, with no PATH
//    search on Windows (E44) and no relative paths, world-writable parents,
//    or symlinks out of an allowlisted root (E45).
//
// `resolveEngineBinary` is the two in order, and is what the OpenVPN driver
// calls: ShellPilot now ships `openvpn` on macOS and Linux, but a Windows
// build has none — and someone may still want the copy they installed
// themselves. See its own comment for why the ordering is not symmetric.

// Read at call time, not module load: `process.platform` is stubbed in the
// resolver tests, and a constant captured at import would silently ignore it.
function exeSuffix(): string {
  return process.platform === 'win32' ? '.exe' : ''
}

// Which engine each binary implements. The name alone reaches the caller, so
// this is where it turns back into a `VpnKind` for the returned info.
const ENGINE_KIND: Record<string, VpnKind> = {
  'shellpilot-netd': 'wireguard',
  frpc: 'frp',
  openvpn: 'openvpn'
}

// The only directories a system-installed OpenVPN is accepted from, in the
// order they are tried. A fixed list rather than a search: on Windows the
// search *is* the vulnerability.
const SYSTEM_CANDIDATES: Record<string, { posix: string[]; win32: string[] }> = {
  openvpn: {
    posix: [
      '/usr/sbin/openvpn',
      '/usr/local/sbin/openvpn',
      '/opt/homebrew/sbin/openvpn',
      '/usr/bin/openvpn'
    ],
    win32: [
      'C:\\Program Files\\OpenVPN\\bin\\openvpn.exe',
      'C:\\Program Files (x86)\\OpenVPN\\bin\\openvpn.exe'
    ]
  }
}

// A symlink is allowed to move a candidate around inside these roots — Homebrew
// keeps the real binary in `Cellar` and links it into `sbin` — but not out of
// them. `/usr/sbin/openvpn -> /tmp/evil` is the attack this rejects.
const PLATFORM_ROOTS: { posix: string[]; win32: string[] } = {
  posix: ['/usr', '/opt', '/bin', '/sbin'],
  win32: ['C:\\Program Files', 'C:\\Program Files (x86)', 'C:\\Windows']
}

// Which build script produces which engine. Named in the "it is not here"
// message, because "run scripts/build-sidecar.sh" — which this used to say for
// every engine — sends someone chasing a missing OpenVPN with the WireGuard
// build. An unknown name falls back to `npm run build:engines`, which is
// always right and only less specific.
const BUILD_SCRIPT: Record<string, string> = {
  'shellpilot-netd': 'scripts/build-sidecar.sh',
  frpc: 'scripts/build-frpc.sh',
  openvpn: 'scripts/build-openvpn.sh'
}

interface ManifestEntry {
  sha256: string
  size?: number
  version?: string
}

interface BinaryManifest {
  version?: string
  binaries?: Record<string, ManifestEntry | string>
}

// Verification is per app run, not per spawn: a supervised engine restarts on
// backoff and re-hashing a 30 MB sidecar on every restart would be pure cost.
const bundledCache = new Map<string, VpnEngineInfo>()
let manifestCache: BinaryManifest | null = null

/** Drops the per-run caches. Tests use it between fixture trees; production
 *  never calls it, which is the point of caching per run. */
export function resetBinaryCache(): void {
  bundledCache.clear()
  manifestCache = null
}

export function sha256File(path: string): Promise<string> {
  return new Promise((resolve, reject) => {
    const hash = createHash('sha256')
    const stream = createReadStream(path)
    stream.on('error', reject)
    // Streamed rather than readFile'd: these are tens of megabytes and the
    // main process is also drawing the UI.
    stream.on('data', (chunk) => hash.update(chunk))
    stream.on('end', () => resolve(hash.digest('hex')))
  })
}

function kindOf(name: string): VpnKind {
  const base = name.endsWith('.exe') ? name.slice(0, -4) : name
  const kind = ENGINE_KIND[base]
  if (!kind) throw new VpnError('internal', `Unknown VPN engine binary ${JSON.stringify(name)}.`)
  return kind
}

/** `resources/bin` in a dev checkout, `<resourcesPath>/bin` when packaged.
 *  The relative shape below the root is identical in both, so nothing else in
 *  this module has to know which one it got. */
function bundledRoot(): string {
  const override = process.env.SHELLPILOT_VPN_BIN_DIR
  if (override) return override
  if (app?.isPackaged && process.resourcesPath) return join(process.resourcesPath, 'bin')
  const appPath = typeof app?.getAppPath === 'function' ? app.getAppPath() : process.cwd()
  return join(appPath, 'resources', 'bin')
}

/** POSIX-separated, relative to the `bin` root. This is the manifest key, so
 *  it must be built the same way on every platform. */
function manifestKey(name: string): string {
  return `${process.platform}-${process.arch}/${name}${exeSuffix()}`
}

async function loadManifest(root: string): Promise<BinaryManifest | null> {
  if (manifestCache) return manifestCache
  try {
    const parsed = JSON.parse(await readFile(join(root, 'manifest.json'), 'utf8')) as BinaryManifest
    manifestCache = parsed
    return parsed
  } catch {
    return null
  }
}

function entryOf(manifest: BinaryManifest | null, key: string): ManifestEntry | null {
  const raw = manifest?.binaries?.[key]
  if (!raw) return null
  return typeof raw === 'string' ? { sha256: raw } : raw
}

/**
 * Locate and integrity-check a binary ShellPilot ships. Throws rather than
 * returning an unavailable `VpnEngineInfo` so a caller cannot accidentally
 * treat a tampered binary as merely absent; `VpnDriver.probe()` catches and
 * shapes it for the UI.
 */
export async function resolveBundled(name: string): Promise<VpnEngineInfo> {
  const cached = bundledCache.get(name)
  if (cached) return cached

  const kind = kindOf(name)
  const root = bundledRoot()
  const key = manifestKey(name)
  const file = join(root, ...key.split('/'))

  const st = await stat(file).catch(() => null)
  if (!st || !st.isFile() || st.size === 0) {
    // A zero-length file is the shape antivirus quarantine leaves behind, and
    // it is indistinguishable from a truncated download, so both get the same
    // message naming the path (E43).
    throw new VpnError(
      'binary-missing',
      `Looked for ${file}. If this is a development checkout, run ${BUILD_SCRIPT[name] ?? 'npm run build:engines'} to build it; otherwise antivirus software may have quarantined it.`
    )
  }

  const manifest = await loadManifest(root)
  const entry = entryOf(manifest, key)
  if (!entry) {
    // A missing manifest or a missing entry is the normal state of a dev
    // checkout before the engines have been built. That is an absence, not a
    // tamper, and calling it a tamper would train people to ignore the word.
    throw new VpnError(
      'binary-missing',
      `${file} is not listed in ${join(root, 'manifest.json')}, so it cannot be verified. Run ${BUILD_SCRIPT[name] ?? 'npm run build:engines'} to produce both.`
    )
  }

  const actual = await sha256File(file)
  if (actual !== entry.sha256) {
    throw new VpnError(
      'binary-untrusted',
      `${file} hashes to ${actual} but the manifest records ${entry.sha256}.`
    )
  }

  const info: VpnEngineInfo = {
    kind,
    available: true,
    path: file,
    sha256: actual,
    version: entry.version ?? (await probeVersion(file)),
    bundled: true
  }
  bundledCache.set(name, info)
  return info
}

export interface SystemResolveOptions {
  /** An absolute path the user typed into the profile. */
  binaryPath?: string
  /** Whether the user confirmed that path in the UI. An unconfirmed path is
   *  ignored: a `binaryPath` that arrived inside an imported `.ovpn` is the
   *  file's opinion about what to execute, not the user's (E44). */
  confirmed?: boolean
}

/**
 * Locate an engine the user supplies. Ordered: the confirmed override, then a
 * fixed per-OS allowlist, then — on POSIX only — `PATH`.
 */
export async function resolveSystem(
  name: string,
  opts: SystemResolveOptions = {}
): Promise<VpnEngineInfo> {
  const kind = kindOf(name)
  const win32 = process.platform === 'win32'
  const roots = win32 ? PLATFORM_ROOTS.win32 : PLATFORM_ROOTS.posix

  if (opts.binaryPath) {
    if (!opts.confirmed) {
      throw new VpnError(
        'config-invalid',
        `The program path ${opts.binaryPath} has not been confirmed, so it was not run.`
      )
    }
    // A rejected override is reported rather than skipped: the user asked for
    // this exact file, and silently falling through to a different one would
    // run something they did not choose.
    const problem = await checkExecutable(opts.binaryPath, [dirname(opts.binaryPath), ...roots])
    if (problem) throw new VpnError('config-invalid', `${opts.binaryPath} ${problem}`)
    return describe(kind, opts.binaryPath)
  }

  const fixed = SYSTEM_CANDIDATES[name]
  const candidates = fixed ? (win32 ? fixed.win32 : fixed.posix) : []
  for (const candidate of candidates) {
    if (await checkExecutable(candidate, roots)) continue
    return describe(kind, candidate)
  }

  // No PATH search on Windows, ever. `PATH` there routinely contains
  // per-user, user-writable directories, and the current directory has
  // historically been searched as well, so a PATH hit is not evidence that
  // the administrator installed anything (E44).
  if (!win32) {
    for (const dir of (process.env.PATH ?? '').split(delimiter)) {
      if (!dir) continue
      const candidate = join(dir, name)
      if (await checkExecutable(candidate, [dir, ...roots])) continue
      return describe(kind, candidate)
    }
  }

  // Where it looked, and nothing else. What to do about it — install the
  // engine, or point the profile at a copy — used to be tacked on here, which
  // put four sentences of advice in a toast with no control in it. The UI
  // renders the code's hint and a button that performs it, and shows this
  // detail behind a Details disclosure for whoever actually wants the paths.
  const where = candidates.length ? candidates.join(', ') : 'the standard install locations'
  throw new VpnError(
    'binary-missing',
    win32
      ? `Looked in ${where}. ShellPilot does not search PATH on Windows.`
      : `Looked in ${where} and on PATH.`
  )
}

/**
 * Locate an engine: the copy ShellPilot ships if there is one, otherwise the
 * copy the user installed.
 *
 * The order is not symmetric, and each step is a separate decision:
 *
 *  1. **A confirmed `binaryPath` wins outright.** The user pointed at a file;
 *     running a different one instead would be answering a question they did
 *     not ask. Unconfirmed paths are still refused by `resolveSystem` (E44).
 *  2. **Then the bundled copy.** We built it, we know its bytes, and the
 *     manifest check runs before the first exec. A system install can be any
 *     version, patched or not, and on Windows arrives from a `PATH` we refuse
 *     to search at all.
 *  3. **Then the system allowlist.** ShellPilot ships `openvpn` on macOS and
 *     Linux only, so on Windows this is the sole path — and on the other two
 *     it still serves the person who deliberately runs their distribution's
 *     build.
 *
 * A bundled binary that *exists* but fails its hash check is a tamper, and
 * that error is rethrown rather than falling through: silently running a
 * different copy would turn the one signal we have into nothing at all.
 */
export async function resolveEngineBinary(
  name: string,
  opts: SystemResolveOptions = {}
): Promise<VpnEngineInfo> {
  if (opts.binaryPath) return resolveSystem(name, opts)
  // Nothing to look for, so nothing to report about not finding it. Reporting
  // "run scripts/build-openvpn.sh" on Windows would send the reader to build a
  // target that does not exist.
  // `process.platform` read here rather than inside the predicate, so the
  // resolver tests that stub it still drive this decision.
  if (!isEngineBundledOn(name, process.platform)) return resolveSystem(name, opts)

  let bundledProblem: string
  try {
    return await resolveBundled(name)
  } catch (e) {
    if (e instanceof VpnError && e.code === 'binary-untrusted') throw e
    // `detail`, not `message`: the message already carries the generic
    // "could not be found" sentence, and the error thrown below adds it back.
    bundledProblem = detailOf(e)
  }

  try {
    return await resolveSystem(name, opts)
  } catch (e) {
    // Both halves in one detail. Reporting only the second would say "install
    // openvpn" on a build that was supposed to ship one, which sends the
    // reader to fix the wrong thing.
    throw new VpnError('binary-missing', `${bundledProblem} ${detailOf(e)}`)
  }
}

function detailOf(e: unknown): string {
  if (e instanceof VpnError) return e.detail ?? e.message
  return e instanceof Error ? e.message : String(e)
}

async function describe(kind: VpnKind, path: string): Promise<VpnEngineInfo> {
  // The real path is what actually executes, so that is what gets hashed and
  // reported: auditing the symlink would audit the wrong bytes.
  const real = await realpath(path)
  return {
    kind,
    available: true,
    path: real,
    sha256: await sha256File(real),
    version: await probeVersion(real),
    bundled: false
  }
}

/** Returns a sentence describing why the candidate is unacceptable, or null
 *  when it is fine. Phrased as a fragment so callers can prefix the path. */
async function checkExecutable(candidate: string, allowedRoots: string[]): Promise<string | null> {
  if (!isAbsolute(candidate)) return 'is a relative path, which depends on the working directory.'

  let real: string
  try {
    real = await realpath(candidate)
  } catch {
    return 'does not exist.'
  }

  // The roots are realpath'd too. On macOS the temp and /var trees are
  // themselves symlinks, so comparing a resolved file against an unresolved
  // root would report an escape for every legitimate path.
  const roots = await Promise.all(allowedRoots.map((r) => realpath(r).catch(() => r)))
  if (!roots.some((root) => isInside(real, root))) {
    return `resolves to ${real}, which is outside ${allowedRoots.join(', ')}.`
  }

  const st = await stat(real).catch(() => null)
  if (!st || !st.isFile()) return 'is not a file.'
  if (st.size === 0) return 'is empty, which is what antivirus quarantine leaves behind.'

  // POSIX modes are not meaningful on Windows — every file reports 0666 — so
  // checking them there would reject everything for no gain. NTFS ACLs are
  // the equivalent check and are left to the allowlisted-root constraint.
  if (process.platform === 'win32') return null

  if ((st.mode & 0o111) === 0) return 'is not executable.'

  // Anyone who can write the directory can replace the file in it, so a
  // world-writable ancestor makes the hash we just took meaningless. The
  // sticky bit does not help: /tmp is sticky and still lets anyone create.
  for (let dir = dirname(real); ; dir = dirname(dir)) {
    const dst = await stat(dir).catch(() => null)
    if (dst && (dst.mode & 0o002) !== 0) {
      return `is inside the world-writable directory ${dir}, so any user could replace it.`
    }
    if (dirname(dir) === dir) break
  }
  return null
}

function isInside(child: string, root: string): boolean {
  const norm = (p: string): string => (process.platform === 'win32' ? p.toLowerCase() : p)
  const rel = relative(norm(root), norm(child))
  return rel === '' || (!rel.startsWith(`..${sep}`) && rel !== '..' && !isAbsolute(rel))
}

/** First non-empty line of `<binary> --version`, or undefined. Best effort:
 *  the version is shown in the UI and audited on change, but nothing refuses
 *  to run without it. */
function probeVersion(file: string): Promise<string | undefined> {
  return new Promise((resolve) => {
    // OpenVPN exits 1 from `--version`, so the exit code is deliberately
    // ignored and only the output is read. ENOEXEC — a file that is executable
    // but is not a program for this machine — throws out of spawn rather than
    // arriving at the callback, and must not take the whole resolve down with
    // it: the version is decoration, the hash is the check that matters.
    try {
      execFile(
        file,
        ['--version'],
        { timeout: 5_000, windowsHide: true, maxBuffer: 1 << 20 },
        (_err, stdout, stderr) => {
          const line = `${stdout}\n${stderr}`
            .split(/\r?\n/)
            .map((s) => s.trim())
            .find(Boolean)
          resolve(line || undefined)
        }
      )
    } catch {
      resolve(undefined)
    }
  })
}
