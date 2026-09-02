import type { SshAuth, SshCloseInfo } from '../../../shared/ssh'
import type { LocalCloseInfo, LocalShell } from '../../../shared/local'
import type { Server } from '../types'
import { sshHopsFor } from './ssh'
import { withVaultUnlock } from './withVaultUnlock'
import { buildDockerShellCommand } from '../../../shared/docker'

// Everything a terminal needs to run a session, with no knowledge of whether
// the bytes come from a socket or a pty. `useTerminalSession` talks only to
// this; TerminalView chooses which implementation to hand it.
export interface TerminalTransport {
  // Identity of the thing being connected to. Both effects in
  // useTerminalSession key on this, so it must be stable for the life of a
  // pane and different for different targets.
  key: string
  // The name of the target. Shown in the connecting banner and handed to
  // PasteConfirm, which asks "run this on <title>?".
  title: string
  // How to reach the account: 'user@host:port' for SSH, the shell's absolute
  // path locally. Shown in the dead-session overlay.
  subtitle: string
  // What the connecting banner names in parentheses. Deliberately *not*
  // `subtitle`: the SSH greeting has always read "Connecting to box
  // (10.0.0.4:22)…" without the username, and this phase is a pure refactor.
  endpoint: string
  connect(sessionId: string, cols: number, rows: number): Promise<void>
  write(sessionId: string, data: string): void
  resize(sessionId: string, cols: number, rows: number): void
  close(sessionId: string): void
  // Called once per chunk after xterm has parsed it, counted in UTF-16 code
  // units — the same unit main counts on the way out. SSH has no such
  // callback (its backpressure comes from the TCP and ssh2 channel windows);
  // local uses it to reopen the pty read window.
  ack?(sessionId: string, units: number): void
  onData(sessionId: string, cb: (d: string) => void): () => void
  // A single normalised status callback so the hook does not switch on kind.
  onStatus(
    sessionId: string,
    cb: (s: { phase: 'progress' | 'ready' | 'error'; line?: string; message?: string }) => void
  ): () => void
  onClose(sessionId: string, cb: (reason: string) => void): () => void
  // Only SSH has one; local sessions do not touch Server.status.
  onLifecycle?(phase: 'connecting' | 'online' | 'offline'): void
}

const asAuth = (a: string): SshAuth => (a === 'password' || a === 'agent' ? a : 'key')

// Plain-language reason a session ended, or '' when the far end said nothing
// (a dropped link, or a bastion that went away mid-session).
//
// There are two of these rather than one because the two close infos are not
// interchangeable: SshCloseInfo.signal is the *name* the server sent ('HUP'),
// LocalCloseInfo.signal is the raw POSIX signal *number* node-pty reports (9,
// 15). Formatting both with one function prints "signal 9" as "signal HUP".
function sshCloseReason(info: SshCloseInfo): string {
  if (info.signal) {
    // A server-side idle timeout is by far the most common HUP, and it is
    // worth naming rather than leaving as a bare signal.
    return info.signal === 'HUP'
      ? 'closed by server (SIGHUP — often an idle timeout)'
      : `signal ${info.signal}`
  }
  if (info.code === 0) return 'shell exited'
  if (typeof info.code === 'number') return `shell exited with ${info.code}`
  return ''
}

// node-pty reports a clean exit as `{ exitCode: 0, signal: 0 }` — `signal` is
// the number 0, not undefined — so the truthiness test below is what keeps a
// normal `exit` from being reported as "killed by signal 0". Anything that
// changes this to `info.signal !== undefined` breaks every clean exit.
function localCloseReason(info: LocalCloseInfo): string {
  if (info.signal) return `killed by signal ${info.signal}`
  if (info.exitCode === 0) return 'shell exited'
  if (typeof info.exitCode === 'number') return `shell exited with ${info.exitCode}`
  return ''
}

export function sshTransport(
  server: Server,
  setServerStatus: (id: string, s: Server['status']) => void
): TerminalTransport {
  const api = (): typeof window.shellpilot.ssh | undefined => window.shellpilot?.ssh
  return {
    key: `ssh:${server.id}`,
    title: server.name,
    subtitle: `${server.username}@${server.host}:${server.port}`,
    endpoint: `${server.host}:${server.port}`,
    connect: (sessionId, cols, rows) =>
      // A credential kept in the vault is unreadable while the vault is
      // locked. Rather than failing with instructions to go and unlock it and
      // start again, ask here and carry straight on.
      withVaultUnlock(`Connecting to ${server.name}`, () =>
        Promise.resolve(
          api()?.connect({
            sessionId,
            serverId: server.id,
            host: server.host,
            port: server.port,
            username: server.username,
            auth: asAuth(server.auth),
            cols,
            rows,
            // Jump hops need their own credentials: either the secrets stored
            // against the saved server they point at, or a key path set
            // directly on the hop.
            hops: sshHopsFor(server)
          })
        )
      ),
    write: (id, d) => api()?.write(id, d),
    resize: (id, c, r) => api()?.resize(id, c, r),
    close: (id) => api()?.close(id),
    onData: (id, cb) => api()?.onData(id, cb) ?? ((): void => {}),
    onStatus: (id, cb) =>
      api()?.onStatus(id, (s) => {
        if (s.phase === 'hop') {
          cb({
            phase: 'progress',
            line: `\x1b[90m↪ hop ${(s.hopIndex ?? 0) + 1}/${s.hopCount}\x1b[0m`
          })
        } else if (s.phase === 'ready') cb({ phase: 'ready' })
        else if (s.phase === 'error') cb({ phase: 'error', message: s.message ?? 'unknown error' })
      }) ?? ((): void => {}),
    onClose: (id, cb) => api()?.onClose(id, (info) => cb(sshCloseReason(info))) ?? ((): void => {}),
    onLifecycle: (phase) => {
      if (phase === 'connecting') setServerStatus(server.id, 'connecting')
      else setServerStatus(server.id, phase === 'online' ? 'online' : 'offline')
    }
  }
}

/**
 * A shell inside a container, over the server that hosts it.
 *
 * The third TerminalTransport, and deliberately a transport rather than a new
 * terminal: `docker exec -it` is a PTY over a channel, which is exactly what an
 * SSH login shell is. Everything after connect — write, resize, close, the
 * close reason, the vault-unlock prompt — is the SSH implementation unchanged.
 *
 * The command is built by `buildDockerShellCommand`, which validates the
 * container reference and throws rather than escaping it. Nothing here accepts
 * a command from anywhere else.
 *
 * Worth stating plainly, because the button is small and the consequence is
 * not: this is arbitrary code execution on the host. Anyone who can reach the
 * docker socket is effectively root on most installs. It sits behind a module
 * that is off by default, and it is not reachable by an agent — the MCP bridge
 * has no container tool and `execute_command` is gated per server.
 */
export function containerTransport(
  server: Server,
  containerRef: string,
  setServerStatus: (id: string, s: Server['status']) => void,
  // True when the panel had to read this host's containers as root. An account
  // that cannot reach the docker socket cannot exec either, so a shell opened
  // without it fails the same way the listing would have.
  sudo = false
): TerminalTransport {
  const base = sshTransport(server, setServerStatus)
  return {
    ...base,
    // NOT the host's lifecycle. `sshTransport` reports connecting/online/offline
    // into `setServerStatus`, and spreading that here meant a container shell
    // that failed — a wrong image, no /bin/sh, a refused docker socket — marked
    // the SERVER offline. The Fleet Monitor then stopped sampling a host that
    // was perfectly reachable, and the only way back was reconnecting a plain
    // SSH session by hand.
    //
    // A container shell says nothing about the host it runs on. The pooled
    // connection is shared and refcounted, so the host's own sessions keep it
    // alive regardless of what happens in here.
    onLifecycle: undefined,
    // Distinct from the server's own key so a container shell and a shell on
    // the host are different sessions rather than one stealing the other.
    key: `container:${server.id}:${containerRef}`,
    title: containerRef,
    subtitle: `container on ${server.name}`,
    endpoint: `${containerRef} · ${server.host}`,
    connect: (sessionId, cols, rows) =>
      withVaultUnlock(`Opening a shell in ${containerRef}`, () =>
        Promise.resolve(
          window.shellpilot?.ssh?.connect({
            sessionId,
            serverId: server.id,
            host: server.host,
            port: server.port,
            username: server.username,
            auth: asAuth(server.auth),
            cols,
            rows,
            hops: sshHopsFor(server),
            initialCommand: buildDockerShellCommand(containerRef, { sudo })
          })
        )
      )
  }
}

export function localTransport(shell: LocalShell, cwd?: string): TerminalTransport {
  // Resolved per call rather than captured: the renderer can hot-reload while
  // the process keeps the preload bundle it booted with, and a namespace that
  // does not exist must degrade to a dead session, not a thrown effect.
  const api = (): typeof window.shellpilot.local | undefined => window.shellpilot?.local
  return {
    key: `local:${shell.id}:${cwd ?? ''}`,
    title: shell.label,
    subtitle: shell.path,
    endpoint: shell.path,
    connect: (sessionId, cols, rows) =>
      Promise.resolve(api()?.connect({ sessionId, shellId: shell.id, cwd, cols, rows })),
    write: (id, d) => api()?.write(id, d),
    // Code units, never bytes. Main counts UTF-16 code units on the way out,
    // and mixing the two accrues a deficit that never repays: past the
    // high-water mark the pty stays paused forever on any non-ASCII output.
    // tests/localPtyFlowControl.test.ts reproduces that deadlock.
    ack: (id, units) => api()?.ack(id, units),
    resize: (id, c, r) => api()?.resize(id, c, r),
    close: (id) => api()?.close(id),
    onData: (id, cb) => api()?.onData(id, cb) ?? ((): void => {}),
    onStatus: (id, cb) =>
      api()?.onStatus(id, (s) => {
        if (s.phase === 'ready') cb({ phase: 'ready' })
        else if (s.phase === 'error') cb({ phase: 'error', message: s.message ?? 'unknown error' })
      }) ?? ((): void => {}),
    onClose: (id, cb) => api()?.onClose(id, (info) => cb(localCloseReason(info))) ?? ((): void => {})
  }
}
