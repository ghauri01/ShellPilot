import { homedir } from 'node:os'
import type { WebContents } from 'electron'
import type {
  LocalCloseInfo,
  LocalConnectConfig,
  LocalShell,
  LocalStatus,
  LocalStatusPhase
} from '../../shared/local'
import { recordLocalSession } from './localSessionLog'
import { findShell, sanitisedEnv } from './shellDiscovery'

// node-pty is loaded lazily, on the first connect, and never at module scope.
// A machine where the native binding will not load (an unsupported libc, a
// hardened-runtime failure we did not predict) must still get an app that
// starts and does everything else — the local terminal is the feature that
// fails, not ShellPilot.
//
// The laziness is also what keeps this module unit-testable: everything above
// localConnect is pure and importable with the native package absent entirely.
// tests/localPtyFlowControl.test.ts depends on that property.
type Pty = {
  pid: number
  write(data: string): void
  resize(cols: number, rows: number): void
  kill(signal?: string): void
  pause(): void
  resume(): void
  onData(cb: (d: string) => void): { dispose(): void }
  onExit(cb: (e: { exitCode: number; signal?: number }) => void): { dispose(): void }
}
type NodePty = { spawn(file: string, args: string[], opts: Record<string, unknown>): Pty }
let ptyModule: NodePty | null = null
let ptyLoadError: string | null = null

// Kill switch for the whole feature, checked before the native import so that
// setting it genuinely prevents the binding from being dlopen'd at all. This is
// the escape hatch the rollback rows name: a user whose machine is wedged by
// the pty can start the app with it set and get everything except local shells.
const DISABLE_ENV = 'ELECTRON_DISABLE_LOCAL_TERMINAL'

async function loadPty(): Promise<NodePty> {
  if (ptyModule) return ptyModule
  if (ptyLoadError) throw new Error(ptyLoadError)

  if (process.env[DISABLE_ENV] === '1') {
    ptyLoadError =
      `The local terminal is disabled on this machine (${DISABLE_ENV}=1). ` +
      `Unset it and restart ShellPilot to use local shells. SSH sessions are unaffected.`
    throw new Error(ptyLoadError)
  }

  let raw: unknown
  try {
    raw = await import('@lydell/node-pty')
  } catch (err) {
    ptyLoadError =
      `The local terminal is unavailable on this machine: the pseudo-terminal ` +
      `binding failed to load (${err instanceof Error ? err.message : String(err)}). ` +
      `SSH sessions are unaffected.`
    throw new Error(ptyLoadError)
  }

  // @lydell/node-pty is CommonJS. Under an ESM `import()` its module.exports
  // lands on `.default`, but bundlers and Node's cjs-module-lexer also hoist
  // named exports onto the namespace, so both shapes occur depending on how
  // this file is built. The old `as unknown as NodePty` double cast asserted
  // one of them and would have turned the other into an opaque
  // "spawn is not a function" at the first connect.
  const mod = ((raw as { default?: unknown }).default ?? raw) as NodePty
  if (typeof mod.spawn !== 'function') {
    // Deliberately a different message from the catch above: this is the
    // module's export shape changing, not the native binding failing, and the
    // two have completely different fixes.
    ptyLoadError =
      `The local terminal is unavailable on this machine: @lydell/node-pty loaded ` +
      `but exposes no spawn() function (got ${typeof mod.spawn}) — the module's ` +
      `export shape is not what ShellPilot expects. SSH sessions are unaffected.`
    throw new Error(ptyLoadError)
  }

  ptyModule = mod
  return mod
}

// The pause/resume tokens node-pty intercepts. NOT '\x13'/'\x11'.
//
// With handleFlowControl on, node-pty compares each written chunk against
// these strings and, on a match, pauses/resumes its read loop instead of
// forwarding the bytes. A renderer keystroke arrives as its own write with
// data exactly '\x13' when the user presses Ctrl+S — so binding the token to
// XOFF would silently swallow Ctrl+S in vim, in emacs, and in every program
// that binds it. An OSC sequence nobody can type has no such collision.
//
// Q1 is closed: handleFlowControl / flowControlPause / flowControlResume were
// verified present in the shipped tarball (lib/terminal.js:33-35, 76-84), so
// there is no capability fallback here and none is needed. Do not re-open it.
const FLOW_PAUSE = '\u001b]777;shellpilot-pause\u0007'
const FLOW_RESUME = '\u001b]777;shellpilot-resume\u0007'

// UTF-16 code units in flight to the renderer before we stop reading, and the
// level we wait to fall back to before reading again. 512 KB is roughly a
// screenful of `yes` at 60 Hz; below ~64 KB the resume happens often enough
// that a fast `cat` of a large file never stalls visibly.
export const FLOW_HIGH_WATER = 512 * 1024
export const FLOW_LOW_WATER = 64 * 1024

export function flowWindow(w: { pause: () => void; resume: () => void }): {
  onSent: (units: number) => void
  onAck: (units: number) => void
  outstanding: () => number
} {
  let outstanding = 0
  let paused = false
  return {
    onSent: (units) => {
      if (!Number.isFinite(units)) return
      outstanding += units
      if (!paused && outstanding > FLOW_HIGH_WATER) {
        paused = true
        w.pause()
      }
    },
    onAck: (units) => {
      // Reject non-finite values here as well as at the IPC edge. Math.max(0,
      // NaN) is NaN, and NaN > FLOW_HIGH_WATER is false forever — so a single
      // poisoned ack permanently disables the pause path and restores the
      // unbounded memory growth this window exists to prevent.
      if (!Number.isFinite(units)) return
      outstanding = Math.max(0, outstanding - units)
      if (paused && outstanding < FLOW_LOW_WATER) {
        paused = false
        w.resume()
      }
    },
    // Exposed for tests: the invariant that matters is that a fully-acked
    // session returns to exactly zero, and there is no way to observe that
    // from pause/resume alone below the high-water mark.
    outstanding: () => outstanding
  }
}

// Byte-for-byte the same shape as the SSH coalescer at
// src/main/services/ssh.ts:602-617, and for the same reason: `cat` on a large
// file arrives as hundreds of small chunks, and one IPC message each floods
// the renderer and stalls input. A single keystroke echo still goes out
// immediately — the timer only batches what arrives inside one tick.
export function coalescer(send: (payload: string) => void): {
  push: (d: Buffer | string) => void
  dispose: () => void
} {
  let pending: string[] = []
  let flushTimer: ReturnType<typeof setTimeout> | null = null
  const flush = (): void => {
    flushTimer = null
    if (pending.length === 0) return
    const payload = pending.length === 1 ? pending[0] : pending.join('')
    pending = []
    send(payload)
  }
  return {
    push: (d) => {
      pending.push(typeof d === 'string' ? d : d.toString('utf8'))
      if (!flushTimer) flushTimer = setTimeout(flush, 0)
    },
    dispose: () => {
      if (flushTimer) clearTimeout(flushTimer)
      flush()
    }
  }
}

// The coalescer and the flow window wired together, which is the only way
// either is used in production. It exists as its own export so that a test can
// drive the exact accounting localConnect uses — the bug this guards against
// (finding #3) lived precisely in this wiring and was invisible to any test
// that called onSent/onAck with matched integers by construction.
export function outputPipe(
  w: { pause: () => void; resume: () => void },
  send: (payload: string) => void
): {
  push: (d: Buffer | string) => void
  dispose: () => void
  onAck: (units: number) => void
  outstanding: () => number
} {
  const window_ = flowWindow(w)
  const out = coalescer((payload) => {
    // UTF-16 code units, NOT Buffer.byteLength.
    //
    // The renderer acks with `d.length` on the string it received, so both
    // sides of the window must count the same unit. Counting bytes here and
    // code units there accrues a permanent deficit on every multi-byte
    // character — onAck's Math.max(0, …) clamps over-acks but cannot repay an
    // under-ack — and once `outstanding` passes FLOW_HIGH_WATER the pty is
    // paused forever. That freezes the session mid-output on htop, on vim
    // with a Unicode statusline, on fzf, on any Powerlevel10k prompt.
    window_.onSent(payload.length)
    send(payload)
  })
  return {
    push: out.push,
    dispose: out.dispose,
    onAck: window_.onAck,
    outstanding: window_.outstanding
  }
}

interface Session {
  // null while a connect is in flight — the id is claimed before the first
  // await so a concurrent close is observable. See localConnect.
  pty: Pty | null
  disposers: (() => void)[]
  ack: (units: number) => void
  // The WebContents that opened this session. Every subsequent call must come
  // from the same one.
  //
  // Session ids are chosen by the renderer and kept in a module-global map, so
  // without this a second window could write into the first window's shell just
  // by guessing an id. ssh.ts has the same hole (sshWrite at :641-643 takes only
  // the id) and gets away with it because there is exactly one BrowserWindow
  // today — but on the local side the thing on the other end of a stray write is
  // a shell running as the user, so the check is worth its three lines now
  // rather than after a popped-out terminal window makes it exploitable.
  wcId: number
}
const sessions = new Map<string, Session>()

// Look a session up only on behalf of the WebContents that owns it. A mismatch
// is treated exactly like a missing session — the caller learns nothing about
// whether the id exists.
function owned(sessionId: string, wcId: number): Session | undefined {
  const s = sessions.get(sessionId)
  return s && s.wcId === wcId ? s : undefined
}

function send(wc: WebContents, channel: string, ...args: unknown[]): void {
  if (!wc.isDestroyed()) wc.send(channel, ...args)
}
function status(
  wc: WebContents,
  sessionId: string,
  phase: LocalStatusPhase,
  extra: Partial<LocalStatus> = {}
): void {
  send(wc, `local:status:${sessionId}`, { sessionId, phase, ...extra } satisfies LocalStatus)
}

export async function localConnect(wc: WebContents, cfg: LocalConnectConfig): Promise<void> {
  const { sessionId } = cfg
  status(wc, sessionId, 'spawning')
  // Claim the id before the first await, so a localClose() arriving mid-connect
  // has something to delete and the re-check after spawn() can see that it did.
  // Held by identity, not just by key: if a localClose() deletes this entry and
  // a fresh localConnect() claims the same id, the checks below must see that
  // this attempt was superseded rather than stomping the newer session.
  const placeholder: Session = { pty: null, ack: () => {}, disposers: [], wcId: wc.id }
  sessions.set(sessionId, placeholder)
  // Held outside the try so the failure path can name the shell when discovery
  // did resolve one and the spawn is what went wrong.
  let shellForLog: LocalShell | null = null
  try {
    const shell = await findShell(cfg.shellId)
    // findShell is exact-match-or-null: an unknown id is a real error, not a
    // reason to silently hand the user some other shell (finding #25).
    if (!shell) throw new Error(`No shell is configured under the id "${cfg.shellId}".`)
    shellForLog = shell
    const pty = (await loadPty()).spawn(shell.path, shell.args, {
      name: 'xterm-256color',
      cols: cfg.cols,
      rows: cfg.rows,
      cwd: cfg.cwd ?? homedir(),
      env: { ...sanitisedEnv(), ...(shell.env ?? {}) },
      useConpty: true,
      // See Phase 0 Q3. The bundled redistributable ConPTY is deliberately not
      // shipped; the one in conhost.exe is used instead.
      useConptyDll: false,
      handleFlowControl: true,
      flowControlPause: FLOW_PAUSE,
      flowControlResume: FLOW_RESUME
    })

    const out = outputPipe(
      {
        pause: () => pty.write(FLOW_PAUSE),
        resume: () => pty.write(FLOW_RESUME)
      },
      (payload) => send(wc, `local:data:${sessionId}`, payload)
    )

    const dataDisp = pty.onData((d) => out.push(d))
    const exitDisp = pty.onExit((e) => {
      const exit: LocalCloseInfo = { exitCode: e.exitCode, signal: e.signal }
      // Detach the data listener BEFORE flushing: a chunk arriving after
      // out.dispose() would re-arm the flush timer and emit local:data:* after
      // local:close:*, into a terminal the renderer has already marked dead.
      dataDisp.dispose()
      out.dispose()
      send(wc, `local:close:${sessionId}`, exit)
      sessions.delete(sessionId)
      recordLocalSession({
        event: 'exited',
        sessionId,
        shellId: shell.id,
        shellLabel: shell.label,
        shellPath: shell.path,
        exitCode: e.exitCode,
        signal: e.signal
      })
    })

    // Re-check the placeholder. localClose() may have run during either await
    // above — ordinary on a fast open-then-close, and guaranteed in dev under
    // React StrictMode, where the session effect mounts, cleans up and remounts
    // while the first (slow, native) loadPty() is still resolving. ssh.ts:565
    // and :572-577 do exactly this; dropping it orphans a live shell that
    // nothing but localDisposeAll() at quit will ever reap.
    if (sessions.get(sessionId) !== placeholder) {
      dataDisp.dispose()
      exitDisp.dispose()
      out.dispose()
      try {
        pty.kill()
      } catch {
        /* already gone */
      }
      return
    }

    sessions.set(sessionId, {
      pty,
      ack: out.onAck,
      disposers: [() => dataDisp.dispose(), () => exitDisp.dispose(), () => out.dispose()],
      wcId: wc.id
    })
    status(wc, sessionId, 'ready', { pid: pty.pid, shellLabel: shell.label })
    // One line per session start, to shellpilot-local-sessions.jsonl — never the
    // AI audit log, which answers a different question. Nothing typed into the
    // shell is recorded, here or anywhere.
    recordLocalSession({
      event: 'started',
      sessionId,
      shellId: shell.id,
      shellLabel: shell.label,
      shellPath: shell.path,
      cwd: cfg.cwd,
      pid: pty.pid
    })
  } catch (err) {
    // Drop the claim so the id is not held by a dead placeholder that
    // localWrite/localAck would silently no-op against forever.
    if (sessions.get(sessionId) === placeholder) sessions.delete(sessionId)
    const message = err instanceof Error ? err.message : String(err)
    status(wc, sessionId, 'error', { message })
    // A spawn that never happened is worth a line too — "nothing ran" and "we
    // tried and it failed" are different answers to the same question, and only
    // one of them means the machine is fine.
    recordLocalSession({
      event: 'failed',
      sessionId,
      shellId: cfg.shellId,
      shellLabel: shellForLog?.label ?? cfg.shellId,
      shellPath: shellForLog?.path ?? '',
      cwd: cfg.cwd,
      error: message
    })
  }
}

export function localWrite(wcId: number, sessionId: string, data: string): void {
  // A renderer that could write the sentinel could stall its own session for
  // good, so the tokens are refused on the way in. Nothing legitimate sends
  // them: they exist only for this module's own pause()/resume().
  if (data === FLOW_PAUSE || data === FLOW_RESUME) return
  // `?.pty?.` — pty is null while a connect is still in flight.
  owned(sessionId, wcId)?.pty?.write(data)
}

export function localAck(wcId: number, sessionId: string, units: number): void {
  // Reject non-finite values. Math.max(0, NaN) is NaN, and NaN > FLOW_HIGH_WATER
  // is false forever — so a single ack(undefined) from a buggy or hostile
  // renderer permanently disables the pause path and restores the unbounded
  // memory growth the flow window exists to prevent. An over-large number is
  // harmless: it clamps to zero, and a renderer can already lift its own
  // backpressure by simply never acking.
  if (!Number.isFinite(units)) return
  owned(sessionId, wcId)?.ack(units)
}

export function localResize(wcId: number, sessionId: string, cols: number, rows: number): void {
  try {
    owned(sessionId, wcId)?.pty?.resize(Math.max(1, cols), Math.max(1, rows))
  } catch {
    /* a pty that exited between the resize and this call is not an error */
  }
}

// wcId is optional so teardown paths (localDisposeAll, a destroyed WebContents)
// can close a session they do not "own". Every renderer-driven path passes it.
export function localClose(sessionId: string, wcId?: number): void {
  const s = wcId === undefined ? sessions.get(sessionId) : owned(sessionId, wcId)
  if (!s) return
  // Deleting the entry is what an in-flight localConnect observes when it
  // re-checks after spawn(); it then kills the pty it just created and returns.
  sessions.delete(sessionId)
  for (const d of s.disposers) d()
  try {
    s.pty?.kill()
  } catch {
    /* already gone */
  }
}

export function localDisposeAll(): void {
  for (const id of [...sessions.keys()]) localClose(id)
}

// Reap every shell a window opened, when that window goes away. Without this a
// closed window's shells keep running until quit, holding a WebContents that
// send() will refuse to write to — invisible processes with nowhere to report.
export function localDisposeForWebContents(wcId: number): void {
  for (const [id, s] of [...sessions.entries()]) {
    if (s.wcId === wcId) localClose(id)
  }
}
