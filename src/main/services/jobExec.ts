import type { JobExecResult, JobExecutor } from './jobRunner'

// The attached executor — roadmap item B1.
//
// Lives here rather than inline in main/index.ts for one reason: it is the
// piece of the job engine with a real policy in it, and a policy nobody can
// run in a test is a policy nobody has checked. main/index.ts needs an Electron
// app object to import at all.
//
// ---------------------------------------------------------------------------
// Why this streams rather than calling sshExec
// ---------------------------------------------------------------------------
// `sshExec` appends until 200 KB and then DROPS everything after, which makes
// the runner's head+tail policy unreachable on the only executor B1 ships. The
// head takes the first 64 KB, the remaining 136 KB fits comfortably under the
// 192 KB tail budget, so out_elided stays 0, no elision notice is written, and
// a 3 MB `apt full-upgrade` stores its first 200 KB and reads back as complete.
// The bytes that answer "did it work" — `E: Sub-process /usr/bin/dpkg returned
// an error code` — are in the 2.8 MB nobody kept. That is precisely the failure
// the head+tail split and `out_elided` were designed to prevent, arriving one
// layer below them.
//
// Streaming also makes the pane live. `sshExec` hands a host's whole output
// over at the end, so a forty-minute upgrade showed nothing for forty minutes —
// on a feature whose selling point is watching long work.
//
// What it does NOT change is the honesty at the top of shared/jobs.ts: this is
// still the ATTACHED path. A dying socket is SIGHUP, apt and dpkg do not ignore
// it, and a job that was running when ShellPilot stopped is `abandoned`. B2
// replaces this module with a detached launch; nothing else moves, which is the
// whole reason the executor is an injected strategy.

/** ssh.ts's `sshExecStream` handler shape, restated so this module does not
 *  have to import the transport in order to be testable. */
export interface ExecStreamHandlers {
  onStdout: (chunk: string) => void
  onStderr: (chunk: string) => void
  onClose: (code: number | null) => void
  onError: (message: string) => void
}

export interface AttachedExecDeps {
  /**
   * Start the command and stream it. Resolves with a stop function; rejects if
   * the connection never came up.
   *
   * `sshExecStream` bound with the caller's secret resolution, injected so a
   * test can drive the seam without a socket.
   */
  stream: (
    cfg: unknown,
    command: string,
    handlers: ExecStreamHandlers,
    allowPrompt: boolean
  ) => Promise<() => void>
}

/**
 * A JobExecutor over a streaming SSH channel.
 *
 * Three things it owns, and each is here because the transport does not do it:
 *
 *  1. THE TIMEOUT. `sshExecStream` has none — a tail is supposed to run until
 *     it is stopped. The timer is armed BEFORE the connection is attempted, so
 *     TCP connect, every hop's forward and the key exchange are inside the
 *     timeout the caller asked for, which is the guarantee `sshExec` had to be
 *     corrected to make.
 *
 *  2. SIGNALLING ON THE WAY OUT. The stop function sends TERM before closing
 *     the channel. Simply abandoning it orphans the remote process holding its
 *     files open — the leak this app already fixed once for log tailing.
 *
 *  3. NOT RETURNING THE OUTPUT. Every byte has already gone to the runner
 *     through `onOutput`; returning it in `stdout` as well would write all of
 *     it a second time, past the head budget, as a single chunk.
 */
export function attachedJobExecutor(deps: AttachedExecDeps): JobExecutor {
  return async ({ cfg, command, timeoutMs, onOutput }) =>
    await new Promise<JobExecResult>((resolve) => {
      let settled = false
      let stop: (() => void) | null = null
      const done = (r: JobExecResult): void => {
        if (settled) return
        settled = true
        clearTimeout(timer)
        resolve(r)
      }
      const timer = setTimeout(() => {
        // Signal first, THEN report. A timeout that leaves the command running
        // is a timeout that has decided nothing.
        try {
          stop?.()
        } catch {
          /* the channel may already be gone; the answer is decided either way */
        }
        done({ ok: false, code: null, error: `Command timed out after ${timeoutMs}ms` })
      }, timeoutMs)
      // A pending timer is not a reason to hold the process open at quit.
      if (typeof timer.unref === 'function') timer.unref()

      deps
        .stream(
          cfg,
          command,
          {
            onStdout: (text) => onOutput('out', text),
            onStderr: (text) => onOutput('err', text),
            // A non-zero exit is a RESULT, not an error — broadcast's rule and
            // the runner's. `ok` means the host answered.
            onClose: (code) => done({ ok: true, code }),
            onError: (message) => done({ ok: false, code: null, error: message })
          },
          // allowPrompt false, for broadcast's reason: a fan-out across hosts
          // with unknown keys would raise a stack of identical trust dialogs,
          // and a stack of identical modals is not a decision anyone can reason
          // about.
          false
        )
        .then(
          (s) => {
            // The deadline can fire while the connection is still coming up. If
            // it did, this channel is already unwanted — close it rather than
            // leaking an authenticated master for a job that gave up.
            if (settled) {
              try {
                s()
              } catch {
                /* nothing left to close */
              }
              return
            }
            stop = s
          },
          (e) => done({ ok: false, code: null, error: e instanceof Error ? e.message : String(e) })
        )
    })
}
