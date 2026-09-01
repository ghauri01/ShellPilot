// Shared local-terminal types used by main, preload and renderer. Deliberately
// a sibling of src/shared/ssh.ts rather than an extension of it: a local shell
// has no host, no port, no username and no auth, and modelling it as an SshHop
// with those fields blanked is how a local session ends up in a code path that
// tries to dial it.

export type LocalShellKind = 'posix' | 'cmd' | 'powershell' | 'pwsh' | 'gitbash' | 'msys2' | 'wsl'

export interface LocalShell {
  // Derived from the shell's absolute path, so it is stable for as long as
  // that path is: 'darwin-zsh-3f2a1c04', 'win32-pwsh-9b7e0d12', and
  // 'wsl:Ubuntu-24.04' for WSL, where the path is the same wsl.exe for every
  // distro and the distro name is the distinguishing part.
  //
  // It is NOT persisted anywhere — tabs live only in memory (persist.ts:8-20
  // saves servers, settings and vault state, never tabs). It has to survive
  // exactly one thing: a listShells(refresh) while a picker is open, so the
  // selection the user is looking at still resolves afterwards.
  id: string
  label: string
  kind: LocalShellKind
  // Absolute. Never a bare name resolved from PATH — same reasoning as
  // src/main/services/vpn/binaries.ts: on Windows the PATH search is the
  // vulnerability.
  path: string
  args: string[]
  // Merged over the sanitised parent environment, never replacing it.
  env?: Record<string, string>
  // True for the one shell the OS considers the user's own.
  isDefault?: boolean
}

export interface LocalConnectConfig {
  sessionId: string
  shellId: string
  // Absent means the user's home directory.
  cwd?: string
  cols: number
  rows: number
}

export type LocalStatusPhase = 'spawning' | 'ready' | 'error'

export interface LocalStatus {
  sessionId: string
  phase: LocalStatusPhase
  message?: string
  pid?: number
  shellLabel?: string
}

// Why the shell ended, as node-pty's onExit reported it.
//
// Close to SshCloseInfo (src/shared/ssh.ts:26-31) but NOT interchangeable with
// it: `signal` here is the raw POSIX signal *number* node-pty hands back
// (9, 15), whereas SshCloseInfo.signal is the *name* the server sent ('HUP').
// A renderer that formats both with one function prints "signal 9" as
// "signal HUP" or vice versa, so the two stay separately narrowed.
export interface LocalCloseInfo {
  exitCode?: number
  signal?: number
}
