import { execFile } from 'node:child_process'
import { createHash } from 'node:crypto'
import { existsSync, realpathSync } from 'node:fs'
import { homedir, userInfo } from 'node:os'
import { basename, dirname, join } from 'node:path'
import { promisify } from 'node:util'
import { app } from 'electron'
import type { LocalShell } from '../../shared/local'

const run = promisify(execFile)

// ---------------------------------------------------------------------------
// Pure parsers. These are the parts that can be tested off-platform, which is
// most of what goes wrong here.
// ---------------------------------------------------------------------------

// `wsl.exe -l -q` writes UTF-16LE, with a BOM. Decoding it as UTF-8 yields
// names interleaved with NULs, which are useless as a `-d` argument.
export function parseWslDistros(buf: Buffer): string[] {
  return buf
    .toString('utf16le')
    .replace(/^\ufeff/, '')
    .split(/\r?\n/)
    .map((l) => l.trim())
    .filter((l) => l.length > 0)
}

export function parseDsclShell(out: string): string | null {
  return /^UserShell:\s*(\S+)\s*$/m.exec(out)?.[1] ?? null
}

// The shell's own name, lower-cased and without the .exe.
//
// Not node:path's basename: that is the POSIX flavour on a POSIX host, so
// basename('C:\\Windows\\System32\\cmd.exe') is the entire string. These
// helpers run against Windows paths on a Linux CI runner (and against the
// parsed output of Windows tools generally), so the separator set is fixed
// here rather than inherited from the host.
function shellName(path: string): string {
  const segments = path.split(/[\\/]+/).filter((s) => s.length > 0)
  const last = segments[segments.length - 1] ?? ''
  return last.replace(/\.exe$/i, '').toLowerCase()
}

// Shells that must never be offered as an interactive session.
const NON_INTERACTIVE = new Set(['dash', 'nologin', 'false', 'sync', 'git-shell'])

// Whether a path is worth offering as somebody's terminal.
//
// The check runs on the RESOLVED path, not the one it was given, because the
// case it exists for is a symlink: on Debian and Ubuntu /bin/sh is a link to
// dash, and dash in a terminal is a support ticket — arrow keys print ^[[A and
// there is no history at all. A basename check on the link name sees "sh",
// finds it in no denylist, and offers it.
//
// Resolving rather than denying the name "sh" is deliberate the other way too:
// on RHEL and on macOS /bin/sh is bash, and a name-only rule would throw away
// a perfectly good shell. A broken link resolves to nothing and is judged on
// the name it was given — being unable to resolve it is not evidence against
// it, and existsSync at the call sites is what actually rejects it.
export function isInteractiveShell(path: string): boolean {
  if (path.length === 0) return false
  return !NON_INTERACTIVE.has(shellName(resolvePath(path)))
}

// realpathSync, or the path itself when it will not resolve. Used for two
// things that both have to see through a link: judging what a shell really is,
// and deciding whether two entries are the same shell. Never used as the path
// to spawn — that stays the one the user's $SHELL or the OS actually named.
function resolvePath(path: string): string {
  try {
    return realpathSync(path)
  } catch {
    /* broken link, or a path that does not exist: use it as given */
    return path
  }
}

// A shell's id, derived from its FULL path.
//
// The basename alone is not enough: /bin/zsh and /opt/homebrew/bin/zsh are
// different shells, and giving them one id made the second unselectable
// (findShell matched the first) and handed React two children with the same
// key. The readable prefix keeps ids greppable in logs and audit entries; the
// 8-hex digest of the absolute path is what makes them unique and stable.
export function shellIdFor(prefix: string, path: string): string {
  const digest = createHash('sha256').update(path).digest('hex').slice(0, 8)
  return `${prefix}-${shellName(path)}-${digest}`
}

// Final labels for a list of POSIX shells.
//
// Two shells can share a name and still be two different shells — a Homebrew
// zsh next to /bin/zsh is the ordinary case on macOS. Fixing their ids (above)
// made the second one selectable; this is what makes it tellable-apart, by
// naming the directory but only where there is actually an ambiguity, so the
// common one-zsh machine still reads plainly "zsh".
//
// "(default)" is last and means what it says: the shell the OS considers the
// user's own. An earlier draft attached it to the shell *being zsh*, which
// labelled the wrong row on any machine whose login shell is bash.
export function finaliseLabels(shells: LocalShell[]): LocalShell[] {
  const counts = new Map<string, number>()
  for (const s of shells) counts.set(shellName(s.path), (counts.get(shellName(s.path)) ?? 0) + 1)
  for (const s of shells) {
    const name = basename(s.path)
    const ambiguous = (counts.get(shellName(s.path)) ?? 0) > 1
    s.label = `${ambiguous ? `${name} — ${dirname(s.path)}` : name}${s.isDefault ? ' (default)' : ''}`
  }
  return shells
}

// ---------------------------------------------------------------------------
// Environment
// ---------------------------------------------------------------------------

// Variables that turn a shell the user starts into something they did not ask
// for. Stripped by prefix where the whole family is ours, by name where it is
// not.
//
// ELECTRON_* is ours wholesale: ELECTRON_RUN_AS_NODE turns any Electron binary
// the user runs into a bare Node, ELECTRON_NO_ASAR changes how their next
// Electron app loads its own code, and ELECTRON_RENDERER_URL is a dev-only
// artefact of ShellPilot's own launch. None of them mean anything in a user's
// terminal. Naming three of them (as an earlier draft did) leaves the rest.
const STRIPPED_PREFIXES = ['ELECTRON_']

// The NODE_* ones are not a family we can strip wholesale — NODE_ENV,
// NODE_PATH and NODE_EXTRA_CA_CERTS are the user's own and belong in their
// shell — so they are listed individually. NODE_REPL_EXTERNAL_MODULE is here
// because it is a separate code-execution channel from NODE_OPTIONS, not a
// special case of it: it loads an arbitrary module into every `node` the user
// starts, and stripping NODE_OPTIONS does nothing about it.
const STRIPPED_NAMES = new Set(['NODE_OPTIONS', 'NODE_REPL_EXTERNAL_MODULE', 'NODE_V8_COVERAGE'])

// The environment every local shell starts from.
//
// Two jobs. First, strip what Electron put there for its own child processes.
// Second, declare what a terminal is, so programs stop guessing.
//
// Everything else is forwarded verbatim, which is only safe because ShellPilot
// parks nothing sensitive in its own process.env — no vault material, no
// credentials, no MCP pairing token. tests/shellDiscovery.test.ts asserts that
// stays true; if that test ever has to be relaxed, this function becomes an
// allowlist instead.
export function sanitisedEnv(): Record<string, string> {
  const env: Record<string, string> = {}
  for (const [k, v] of Object.entries(process.env)) {
    if (v === undefined) continue
    if (STRIPPED_NAMES.has(k)) continue
    if (STRIPPED_PREFIXES.some((p) => k.startsWith(p))) continue
    env[k] = v
  }
  env.TERM = 'xterm-256color'
  env.COLORTERM = 'truecolor'
  env.TERM_PROGRAM = 'ShellPilot'
  env.TERM_PROGRAM_VERSION = app.getVersion()
  // An AppImage started from a desktop launcher can have no locale at all,
  // which makes every UTF-8 box-drawing character in the shell prompt render
  // as mojibake. Set a default; never override one the user has.
  if (!env.LANG && !env.LC_ALL) env.LANG = 'en_US.UTF-8'
  return env
}

// ---------------------------------------------------------------------------
// Per-OS discovery
// ---------------------------------------------------------------------------

// macOS. A login shell is mandatory, not a preference.
//
// A GUI Electron app is launched by launchd, and launchd's PATH is the minimal
// /usr/bin:/bin:/usr/sbin:/sbin. Everything a developer actually uses —
// /opt/homebrew/bin, /usr/local/bin, whatever /etc/paths.d contributes — is
// assembled by path_helper, which runs from /etc/zprofile and /etc/profile.
// Those are read by a LOGIN shell only. Without -l the user gets a terminal
// where `brew`, `node`, `git` from Xcode-alternatives and their whole toolchain
// are simply not found, and it looks like ShellPilot broke their machine.
// Terminal.app and iTerm2 both start login shells for exactly this reason.
async function discoverDarwin(): Promise<LocalShell[]> {
  const shells: LocalShell[] = []
  let preferred = ''

  const fromEnv = process.env.SHELL
  if (fromEnv && existsSync(fromEnv) && isInteractiveShell(fromEnv)) preferred = fromEnv

  // $SHELL is absent when the app was launched from Finder rather than from a
  // terminal, which is the normal case. Directory Services knows the answer.
  if (!preferred) {
    try {
      const { stdout } = await run(
        '/usr/bin/dscl',
        ['.', '-read', `/Users/${userInfo().username}`, 'UserShell'],
        { timeout: 4000 }
      )
      const shell = parseDsclShell(stdout)
      if (shell && existsSync(shell) && isInteractiveShell(shell)) preferred = shell
    } catch {
      /* fall through to the hard default */
    }
  }

  if (!preferred) preferred = '/bin/zsh'

  const seen = new Set<string>()
  const push = (path: string, isDefault: boolean): void => {
    if (!existsSync(path) || !isInteractiveShell(path)) return
    // Keyed on the RESOLVED path: /bin/bash is a link to /usr/bin/bash on
    // several distributions, and listing one shell twice is worse than the
    // collision this replaces. The row still spawns the path as named.
    const key = resolvePath(path)
    if (seen.has(key)) return
    seen.add(key)
    const name = basename(path)
    shells.push({
      id: shellIdFor('darwin', path),
      // Provisional; finaliseLabels below decides what it actually reads.
      label: name,
      kind: 'posix',
      path,
      args: ['-l'],
      isDefault
    })
  }

  push(preferred, true)
  // Offer the other system shells too, so a zsh user can still reach bash. The
  // dedupe is by path, which is also what keeps a homebrew zsh and /bin/zsh as
  // two separate, separately selectable entries.
  for (const alt of ['/bin/zsh', '/bin/bash']) push(alt, false)
  return finaliseLabels(shells)
}

// Linux. $SHELL first, then the passwd entry, then bash, then /bin/sh.
//
// -i rather than -l for bash, and this asymmetry with macOS is deliberate: a
// bash LOGIN shell reads ~/.bash_profile and deliberately does NOT read
// ~/.bashrc, which is where essentially every Linux user's aliases, prompt and
// completion live. A Linux desktop session already inherits ~/.profile through
// the display manager, so there is no PATH problem to solve here — the macOS
// launchd problem simply does not exist. zsh and fish read their rc file in
// both modes, so they get -l.
async function discoverLinux(): Promise<LocalShell[]> {
  const shells: LocalShell[] = []
  const seen = new Set<string>()
  const push = (path: string, isDefault = false): void => {
    if (!path || !existsSync(path) || !isInteractiveShell(path)) return
    // Resolved, so a $SHELL of /usr/bin/bash and an alt of /bin/bash are one
    // row on the distributions where /bin is a link to /usr/bin.
    const key = resolvePath(path)
    if (seen.has(key)) return
    seen.add(key)
    const name = basename(path)
    shells.push({
      id: shellIdFor('linux', path),
      // Provisional; finaliseLabels below decides what it actually reads.
      label: name,
      kind: 'posix',
      path,
      args: name === 'bash' ? ['-i'] : ['-l'],
      isDefault
    })
  }

  let preferred = process.env.SHELL ?? ''
  if (!preferred) {
    try {
      preferred = userInfo().shell ?? ''
    } catch {
      /* no passwd entry (a container running as an unmapped uid) */
    }
  }
  push(preferred, true)
  if (shells.length === 0) push('/bin/bash', true)
  // Last resort only. On Debian and Ubuntu this is a link to dash and push()
  // drops it — isInteractiveShell resolves the link, which is the whole point
  // of resolving it — so this line fires only where /bin/sh is a real shell.
  if (shells.length === 0) push('/bin/sh', true)
  for (const alt of ['/bin/bash', '/usr/bin/zsh', '/usr/bin/fish']) push(alt)
  return finaliseLabels(shells)
}

// Windows. Absolute paths only, never a PATH search: the same rule
// src/main/services/vpn/binaries.ts enforces for engine binaries, for the same
// reason. A writable directory earlier on PATH than System32 is a local
// privilege escalation, and "pwsh" is a name an attacker can plant.
async function discoverWin32(): Promise<LocalShell[]> {
  const shells: LocalShell[] = []
  const sysRoot = process.env.SystemRoot ?? 'C:\\Windows'
  const pf = process.env.ProgramFiles ?? 'C:\\Program Files'
  const localAppData = process.env.LOCALAPPDATA ?? join(homedir(), 'AppData', 'Local')

  const cmd = process.env.ComSpec ?? join(sysRoot, 'System32', 'cmd.exe')
  if (existsSync(cmd)) {
    shells.push({
      id: shellIdFor('win32', cmd),
      label: 'Command Prompt',
      kind: 'cmd',
      path: cmd,
      args: []
    })
  }

  const ps51 = join(sysRoot, 'System32', 'WindowsPowerShell', 'v1.0', 'powershell.exe')
  if (existsSync(ps51)) {
    shells.push({
      id: shellIdFor('win32', ps51),
      label: 'Windows PowerShell',
      kind: 'powershell',
      path: ps51,
      // -NoLogo suppresses the banner; -ExecutionPolicy is deliberately NOT
      // set — changing a machine's script policy from a terminal launcher is
      // not ours to do.
      args: ['-NoLogo']
    })
  }

  for (const pwsh of [
    join(pf, 'PowerShell', '7', 'pwsh.exe'),
    join(localAppData, 'Microsoft', 'WindowsApps', 'pwsh.exe')
  ]) {
    if (existsSync(pwsh)) {
      shells.push({
        id: shellIdFor('win32', pwsh),
        label: 'PowerShell 7',
        kind: 'pwsh',
        path: pwsh,
        args: ['-NoLogo']
      })
      break
    }
  }

  const git = await gitBashPath()
  if (git) {
    shells.push({
      id: shellIdFor('win32', git),
      label: 'Git Bash',
      kind: 'gitbash',
      path: git,
      // --login runs /etc/profile, which is what puts Git's own bin on PATH.
      // -i is what makes it read ~/.bashrc.
      args: ['--login', '-i']
    })
  }

  for (const root of ['C:\\msys64', 'C:\\msys32']) {
    const bash = join(root, 'usr', 'bin', 'bash.exe')
    if (!existsSync(bash)) continue
    shells.push({
      id: shellIdFor('win32-msys2', bash),
      label: 'MSYS2 UCRT64',
      kind: 'msys2',
      path: bash,
      args: ['-l', '-i'],
      // MSYSTEM selects the toolchain (UCRT64 / MINGW64 / MSYS); without it
      // the shell starts in MSYS mode and the mingw compilers are not on PATH.
      // CHERE_INVOKING keeps the shell in the directory it was started in —
      // without it /etc/profile cds to $HOME and the tab's cwd is discarded.
      env: { MSYSTEM: 'UCRT64', CHERE_INVOKING: '1' }
    })
    break
  }

  for (const distro of await wslDistros()) {
    // Not shellIdFor: every distro is the same wsl.exe, so the path is not
    // what distinguishes them. The distro name is, and it is already unique.
    shells.push({
      id: `wsl:${distro}`,
      label: `WSL · ${distro}`,
      kind: 'wsl',
      path: join(sysRoot, 'System32', 'wsl.exe'),
      args: ['-d', distro]
    })
  }

  // PowerShell 7 if the user installed it, Windows PowerShell otherwise, and
  // whatever came first if neither exists. Marked here rather than at the push
  // sites so exactly one row ever carries it — and so the "(default)" suffix
  // and the flag cannot disagree.
  const preferred =
    shells.find((s) => s.kind === 'pwsh') ?? shells.find((s) => s.kind === 'powershell') ?? shells[0]
  if (preferred) {
    preferred.isDefault = true
    preferred.label = `${preferred.label} (default)`
  }
  return shells
}

// HKLM\SOFTWARE\GitForWindows\InstallPath is what a system-wide Git for
// Windows install writes; the WOW6432Node mirror covers a 32-bit Git on a
// 64-bit machine, and HKCU covers the per-user install, which is what the
// installer offers by default to a non-administrator and is therefore the
// common case on a managed machine.
// `reg query` rather than a registry npm package: no new native dependency for
// one lookup, and reg.exe is in System32 on every Windows since 2000.
async function gitBashPath(): Promise<string | null> {
  const keys = [
    'HKCU\\SOFTWARE\\GitForWindows',
    'HKLM\\SOFTWARE\\GitForWindows',
    'HKLM\\SOFTWARE\\WOW6432Node\\GitForWindows'
  ]
  const reg = join(process.env.SystemRoot ?? 'C:\\Windows', 'System32', 'reg.exe')
  for (const key of keys) {
    try {
      const { stdout } = await run(reg, ['query', key, '/v', 'InstallPath'], { timeout: 4000 })
      const install = /InstallPath\s+REG_SZ\s+(.+?)\s*$/m.exec(stdout)?.[1]
      if (!install) continue
      const bash = join(install, 'bin', 'bash.exe')
      if (existsSync(bash)) return bash
    } catch {
      /* key absent: Git is not installed this way */
    }
  }
  return null
}

async function wslDistros(): Promise<string[]> {
  try {
    const { stdout } = await run(
      join(process.env.SystemRoot ?? 'C:\\Windows', 'System32', 'wsl.exe'),
      ['-l', '-q'],
      {
        timeout: 6000,
        // Buffer, not a string: the output is UTF-16LE and a utf8 decode here
        // destroys it before parseWslDistros can see it.
        encoding: 'buffer'
      }
    )
    return parseWslDistros(stdout)
  } catch {
    return []
  }
}

// ---------------------------------------------------------------------------
// Public surface
// ---------------------------------------------------------------------------

// Discovery shells out (dscl, reg, wsl) and the answer does not change while
// the app runs, so it is computed once. `refresh` exists for the case that
// does change it: the user installing WSL or Git while ShellPilot is open.
let cache: Promise<LocalShell[]> | null = null

export function listShells(refresh = false): Promise<LocalShell[]> {
  if (refresh) cache = null
  if (!cache) {
    const discover =
      process.platform === 'darwin'
        ? discoverDarwin
        : process.platform === 'win32'
          ? discoverWin32
          : discoverLinux
    // An empty list is a survivable answer — the UI says the local terminal is
    // unavailable — and a rejected promise cached forever is not.
    cache = discover().catch(() => [])
  }
  return cache
}

// Exact match or nothing.
//
// The silent fallback this replaces ("…?? the default ?? shells[0]") made the
// shellId non-enforcing: any unknown or attacker-chosen id spawned the user's
// default shell and reported `ready`, and the caller's own "no shell under
// that id" error could only ever fire on a machine with zero shells. Picking
// the default is a decision for whoever opens the terminal, made explicitly.
export async function findShell(id: string): Promise<LocalShell | null> {
  return (await listShells()).find((s) => s.id === id) ?? null
}
