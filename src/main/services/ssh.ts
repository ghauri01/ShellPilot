import net from 'node:net'
import { Client, type ConnectConfig } from 'ssh2'
import type { ClientChannel } from 'ssh2'
import { readFileSync, existsSync } from 'node:fs'
import { WebContents } from 'electron'
import type { SshCloseInfo, SshConnectConfig, SshHop, SshStatus, SshStatusPhase } from '../../shared/ssh'
import { verifyHostKey } from './knownhosts'
import { isEncryptedPrivateKey } from './sshKeys'

interface Session {
  conn: PooledConnection | null
  stream: ClientChannel | null
}

const sessions = new Map<string, Session>()

export interface KeyboardPrompt {
  prompt: string
  echo: boolean
}
export interface KeyboardRequest {
  host: string
  username: string
  // Present when the hop maps to a saved server, so an answer can be stored.
  serverId?: string
  name: string
  instructions: string
  prompts: KeyboardPrompt[]
}
export type Prompter = (req: KeyboardRequest) => Promise<string[]>

// Servers enforcing multi-factor auth (AuthenticationMethods
// publickey,keyboard-interactive) accept the key and then ask for a second
// factor. Without answering that challenge the connection fails with a generic
// "All configured authentication methods failed".
let prompter: Prompter | null = null
export function setSshPrompter(p: Prompter): void {
  prompter = p
}

function send(wc: WebContents, channel: string, ...args: unknown[]): void {
  if (!wc.isDestroyed()) wc.send(channel, ...args)
}

function status(wc: WebContents, sessionId: string, phase: SshStatusPhase, extra: Partial<SshStatus> = {}): void {
  send(wc, `ssh:status:${sessionId}`, { sessionId, phase, ...extra } satisfies SshStatus)
}

// "All configured authentication methods failed" is what ssh2 reports for
// every auth problem, including ones we can identify precisely here. Check the
// key material up front and fail with something actionable instead.
function loadPrivateKey(hop: SshHop): string {
  if (hop.privateKey) return hop.privateKey
  if (!hop.keyPath) {
    throw new Error(
      `No private key is configured for ${hop.username}@${hop.host}. Edit the server and select a key file, or switch it to password/agent authentication.`
    )
  }
  const path = hop.keyPath.replace(/^"(.*)"$/, '$1').trim()
  if (!existsSync(path)) {
    throw new Error(`Private key not found: ${path}`)
  }

  let key: string
  try {
    key = readFileSync(path, 'utf8')
  } catch (err) {
    throw new Error(`Could not read private key ${path}: ${(err as Error).message}`)
  }

  if (key.startsWith('PuTTY-User-Key-File')) {
    throw new Error(
      `${path} is a PuTTY .ppk key, which is not supported. Convert it in PuTTYgen with Conversions → Export OpenSSH key, then select the converted file.`
    )
  }
  if (/^ssh-(rsa|ed25519|dss)\s|^ecdsa-sha2-/.test(key.trim())) {
    throw new Error(
      `${path} is a public key, not a private key. Select the matching private key file (the one without the .pub suffix).`
    )
  }
  if (!/-----BEGIN [^-]*PRIVATE KEY-----/.test(key)) {
    throw new Error(`${path} does not look like a private key file.`)
  }
  if (isEncryptedPrivateKey(key.slice(0, 512)) && !hop.passphrase) {
    throw new Error(
      `${path} is passphrase-protected. Edit the server and enter the key passphrase.`
    )
  }
  return key
}

function authFor(hop: SshHop): Partial<ConnectConfig> {
  const agent = process.env.SSH_AUTH_SOCK || (process.platform === 'win32' ? 'pageant' : undefined)
  switch (hop.auth) {
    case 'password':
      return { password: hop.password }
    case 'agent':
      return { agent }
    case 'key':
    default:
      return { privateKey: loadPrivateKey(hop), passphrase: hop.passphrase }
  }
}

// Interactive typing feels laggy without this. Node sockets have Nagle's
// algorithm on by default, which holds a small keystroke packet back waiting
// for more data — up to ~40ms per character round trip. OpenSSH sets
// TCP_NODELAY for exactly this reason; ssh2 does not.
function tcpSocket(host: string, port: number): Promise<net.Socket> {
  return new Promise((resolve, reject) => {
    const socket = net.connect({ host, port })
    socket.setNoDelay(true)
    socket.once('connect', () => {
      socket.removeListener('error', reject)
      resolve(socket)
    })
    socket.once('error', reject)
  })
}

async function connectClient(
  hop: SshHop,
  sock?: NodeJS.ReadableStream,
  allowPrompt = true
): Promise<Client> {
  // Hops ride an SSH channel, which has no TCP options of its own; only the
  // first, real socket needs the flag.
  const transport = sock ?? (await tcpSocket(hop.host, hop.port || 22))
  return new Promise((resolve, reject) => {
    const client = new Client()
    const config: ConnectConfig = {
      host: hop.host,
      port: hop.port || 22,
      username: hop.username,
      readyTimeout: 20000,
      keepaliveInterval: 15000,
      // Required for the second factor after a public key is accepted.
      tryKeyboard: true,
      // Trust-on-first-use: unknown hosts prompt, changed keys are refused.
      hostVerifier: ((key: Buffer, cb: (ok: boolean) => void) => {
        void verifyHostKey(hop.host, hop.port || 22, key, allowPrompt).then(cb)
      }) as never,
      ...authFor(hop),
      // A pre-established socket: our own TCP connection, or the channel
      // opened through the previous hop.
      sock: transport as never
    }
    client.on('ready', () => resolve(client))
    // ssh2's typings for this event are narrower than its runtime signature.
    ;(client as unknown as { on: (e: string, cb: (...a: never[]) => void) => void }).on(
      'keyboard-interactive',
      ((
        name: string,
        instructions: string,
        _lang: string,
        prompts: KeyboardPrompt[],
        finish: (answers: string[]) => void
      ) => {
        // A single hidden prompt on a password-auth server is the password
        // itself; anything else is a real challenge for the user.
        const single = prompts.length === 1 && !prompts[0].echo
        if (hop.auth === 'password' && hop.password && single) {
          finish([hop.password])
          return
        }
        if (!prompter) {
          finish([])
          return
        }
        void prompter({
          host: hop.host,
          username: hop.username,
          serverId: (hop as SshHop & { serverId?: string }).serverId,
          name,
          instructions,
          prompts: prompts.map((p) => ({ prompt: p.prompt, echo: p.echo }))
        })
          .then(finish)
          .catch(() => finish([]))
      }) as never
    )
    client.on('error', (err) => reject(err))
    client.connect(config)
  })
}

// forwardOut on the previous hop opens a channel to the next hop's host:port,
// which becomes the transport socket for the next SSH client — a jump chain.
function hopForward(prev: Client, target: SshHop): Promise<NodeJS.ReadableStream> {
  return new Promise((resolve, reject) => {
    prev.forwardOut('127.0.0.1', 0, target.host, target.port || 22, (err, stream) => {
      if (err) reject(err)
      else resolve(stream as unknown as NodeJS.ReadableStream)
    })
  })
}

// Walk the jump chain, each hop tunnelled through the previous, then connect
// to the target. Shared by the shell (sshConnect) and SFTP services.
export async function openChain(
  cfg: SshHop & { hops?: SshHop[]; vpnProfileId?: string; serverName?: string; serverId?: string },
  onHop?: (index: number, count: number) => void
): Promise<{ clients: Client[]; client: Client; close?: () => void }> {
  // A server behind a VPN is dialled through a loopback forward into the
  // tunnel. Only the first hop needs rewriting — everything after it is
  // reached through the hop before, so the chain is already inside.
  if (cfg.vpnProfileId) return openChainOverVpn(cfg, onHop)
  return openChainDirect(cfg, onHop)
}

async function openChainOverVpn(
  cfg: SshHop & { hops?: SshHop[]; vpnProfileId?: string; serverName?: string; serverId?: string },
  onHop?: (index: number, count: number) => void
): Promise<{ clients: Client[]; client: Client; close?: () => void }> {
  const { vpnOpenForward, vpnStart } = await import('./vpn/manager')
  const vpnId = cfg.vpnProfileId as string

  const started = await vpnStart(vpnId)
  if (!started.ok) {
    // The VPN's own message, not a connect timeout twenty seconds later.
    throw new Error(started.error ?? 'The VPN for this server could not be started.')
  }

  const first = cfg.hops?.[0] ?? cfg
  let fwd: { port: number; close: () => void } | null = null
  try {
    fwd = await vpnOpenForward(vpnId, first.host, first.port, {
      kind: 'server',
      id: cfg.serverId ?? first.host,
      name: cfg.serverName ?? first.host
    })
  } catch (err) {
    // System mode has a real route and no forward to open, so dial directly.
    if ((err as { code?: string }).code !== 'unsupported') throw err
  }

  if (!fwd) {
    const { registerVpnConsumer } = await import('./vpn/dependencies')
    const release = registerVpnConsumer(vpnId, {
      kind: 'server',
      id: cfg.serverId ?? first.host,
      name: cfg.serverName ?? first.host
    })
    const chain = await openChainDirect(cfg, onHop).catch((e) => {
      release()
      throw e
    })
    return { ...chain, close: release }
  }

  const local = fwd
  const rewritten: SshHop = { ...first, host: '127.0.0.1', port: local.port }
  const next = cfg.hops?.length
    ? { ...cfg, hops: [rewritten, ...cfg.hops.slice(1)] }
    : { ...cfg, ...rewritten }

  try {
    const chain = await openChainDirect(next, onHop)
    return { ...chain, close: () => local.close() }
  } catch (err) {
    local.close()
    throw err
  }
}

async function openChainDirect(
  cfg: SshHop & { hops?: SshHop[] },
  onHop?: (index: number, count: number) => void
): Promise<{ clients: Client[]; client: Client }> {
  const hops = cfg.hops ?? []
  const clients: Client[] = []
  let sock: NodeJS.ReadableStream | undefined
  for (let i = 0; i < hops.length; i++) {
    onHop?.(i, hops.length)
    const client = await connectClient(hops[i], sock)
    clients.push(client)
    sock = await hopForward(client, i + 1 < hops.length ? hops[i + 1] : cfg)
  }
  const client = await connectClient(cfg, sock)
  clients.push(client)
  return { clients, client }
}

// ---------------------------------------------------------------- pooling
//
// One authenticated connection per server, shared by every terminal session,
// SFTP browser and metrics sampler — the equivalent of OpenSSH's
// ControlMaster. Without it each new session re-runs authentication, which on
// a server with two-factor auth means another code prompt every time.

/**
 * A name for ONE authentication, minted once and never reused.
 *
 * `key` below identifies a ROUTE — `srv:abc` is the same string before and
 * after a reconnect, which is exactly what the pool wants and exactly what a
 * caller asking "did this command run over the connection that wrote the file"
 * must not be given. This counter answers that question instead: every id is
 * distinct, ids for pooled and unpooled connections come from the same
 * sequence, and an unpooled connection is never entered into the pool — so
 * `pooledConnectionIds()` cannot contain a `fresh#` id unless somebody has
 * changed what unpooled means, which is the thing worth catching.
 */
let connectionSeq = 0
function mintConnectionId(prefix: 'pooled' | 'fresh'): string {
  connectionSeq += 1
  return `${prefix}#${connectionSeq}`
}

export interface PooledConnection {
  key: string
  /** This authentication, not this route. See mintConnectionId. */
  id: string
  host: string
  username: string
  client: Client
  refs: number
  idle?: ReturnType<typeof setTimeout>
  // The hop this connection was opened through, held for as long as this
  // connection lives so a shared bastion is not torn down underneath it.
  parent?: PooledConnection
  // Closes the VPN forward this connection was dialled through, and releases
  // its live-dependent registration. Held here rather than by the caller
  // because the pool outlives any one acquire(): the socket must stay up until
  // the last session using it lets go.
  vpnRelease?: () => void
}

const pool = new Map<string, PooledConnection>()
const connecting = new Map<string, Promise<PooledConnection>>()

// Identity of a single hop. Includes the parent so the same host reached by a
// different route is not mistaken for the same connection.
function hopKey(
  hop: SshHop & { serverId?: string; vpnProfileId?: string; poolTag?: string },
  parentKey?: string
): string {
  const self = hop.serverId
    ? `srv:${hop.serverId}`
    : `${hop.username}@${hop.host}:${hop.port || 22}`
  // The transport is part of a connection's identity, not a detail of how it
  // was dialled.
  //
  // `vpnProfileId` stops a server whose profile changed from reusing a pooled
  // connection still riding the old tunnel — the UI would say one network while
  // the bytes went over another.
  //
  // `poolTag` covers the sharper case: a hop dialled through a VPN forward has
  // had its host and port rewritten to an ephemeral loopback port, but a hop
  // with a serverId keys on that id alone — so the next run would reuse a
  // connection pointing at a forward that has since been closed. The tag
  // carries the forward's identity into the key.
  const via = hop.vpnProfileId ? `|vpn:${hop.vpnProfileId}` : ''
  const tag = hop.poolTag ? `|${hop.poolTag}` : ''
  return parentKey ? `${parentKey}>${self}${via}${tag}` : `${self}${via}${tag}`
}

function destroy(conn: PooledConnection): void {
  try {
    conn.client.end()
  } catch {
    /* ignore */
  }
  // Let the bastion go once nothing is riding on it any more.
  if (conn.parent) release(conn.parent)
  // Same for the VPN forward underneath it. Doing this here rather than in
  // release() matters: release() is also the idle path, and a connection
  // sitting in the idle window still has a live socket through the forward.
  try {
    conn.vpnRelease?.()
  } catch {
    /* a forward that is already gone must not stop the rest of the teardown */
  }
  conn.vpnRelease = undefined
}

// Acquires one hop, reusing a live connection when there is one. `parent` must
// already be ref-held by the caller; ownership transfers to the returned
// connection, or is released when an existing one is reused instead.
async function acquireOne(
  hop: SshHop & { serverId?: string },
  parent: PooledConnection | null,
  allowPrompt = true
): Promise<PooledConnection> {
  const key = hopKey(hop, parent?.key)

  const existing = pool.get(key)
  if (existing) {
    existing.refs++
    if (existing.idle) clearTimeout(existing.idle)
    existing.idle = undefined
    if (parent) release(parent)
    return existing
  }

  // Collapse concurrent opens so a terminal and a metrics poll starting
  // together authenticate once, not twice.
  const inflight = connecting.get(key)
  if (inflight) {
    const conn = await inflight
    conn.refs++
    if (parent) release(parent)
    return conn
  }

  const promise = (async () => {
    // Reached through the bastion when there is one.
    const sock = parent ? await hopForward(parent.client, hop) : undefined
    const client = await connectClient(hop, sock, allowPrompt)
    const conn: PooledConnection = {
      key,
      id: mintConnectionId('pooled'),
      host: hop.host,
      username: hop.username,
      client,
      refs: 1,
      parent: parent ?? undefined
    }
    pool.set(key, conn)
    client.on('close', () => {
      if (pool.get(key) === conn) pool.delete(key)
      // Release the VPN forward here too, not only from destroy().
      //
      // destroy() runs on the idle path, and with `setPoolIdle(-1)` it never
      // runs at all — so a connection the network dropped kept its loopback
      // listener, its goroutines in netd, and its live-dependent registration
      // for the life of the app. That registration is what the stop
      // confirmation counts, so it went on naming sessions that no longer
      // existed. A dead client can never need its forward again.
      try {
        conn.vpnRelease?.()
      } catch {
        /* a forward already gone must not break the close path */
      }
      conn.vpnRelease = undefined
    })
    return conn
  })().finally(() => connecting.delete(key))

  connecting.set(key, promise)
  try {
    return await promise
  } catch (err) {
    if (parent) release(parent)
    throw err
  }
}

// Every hop is pooled in its own right, so several servers behind the same
// bastion share one authenticated bastion connection — the code is requested
// once, not once per destination.
export async function acquire(
  cfg: SshHop & { serverId?: string; hops?: SshHop[]; vpnProfileId?: string; serverName?: string },
  onHop?: (index: number, count: number) => void,
  // False for unattended callers. An unknown host is then refused rather than
  // raising a trust dialog nobody is present to reason about. Set in main only
  // — never taken from the renderer. See verifyHostKey.
  allowPrompt = true
): Promise<PooledConnection> {
  // Behind a VPN, the first hop is dialled through a loopback forward into the
  // tunnel. The forward is attached to the pooled connection rather than
  // released here, because the pool outlives this call — closing it now would
  // cut the connection the moment it was handed over.
  const dial = cfg.vpnProfileId ? await vpnDial(cfg) : null
  const effective = dial?.cfg ?? cfg

  const hops = effective.hops ?? []
  let parent: PooledConnection | null = null
  try {
    for (let i = 0; i < hops.length; i++) {
      onHop?.(i, hops.length)
      parent = await acquireOne(hops[i], parent, allowPrompt)
    }
    const conn = await acquireOne(effective, parent, allowPrompt)
    if (dial) {
      // Attach to whichever connection actually owns the socket. On a pool hit
      // the forward is redundant — the existing connection already has its own
      // — so release it immediately rather than leaking a listener per
      // acquire.
      if (conn.vpnRelease) dial.release()
      else conn.vpnRelease = dial.release
    }
    return conn
  } catch (err) {
    dial?.release()
    throw err
  }
}

// Bring the profile up and open a forward to the first hop, returning a config
// that dials the loopback end of it.
async function vpnDial(
  cfg: SshHop & { serverId?: string; hops?: SshHop[]; vpnProfileId?: string; serverName?: string }
): Promise<{ cfg: SshHop & { serverId?: string; hops?: SshHop[] }; release: () => void } | null> {
  const { vpnOpenForward, vpnStart } = await import('./vpn/manager')
  const vpnId = cfg.vpnProfileId as string

  const started = await vpnStart(vpnId)
  if (!started.ok) {
    throw new Error(started.error ?? 'The VPN for this server could not be started.')
  }

  const first = cfg.hops?.[0] ?? cfg
  const consumer = {
    kind: 'server' as const,
    id: cfg.serverId ?? first.host,
    name: cfg.serverName ?? first.host
  }

  let fwd: { port: number; close: () => void }
  try {
    fwd = await vpnOpenForward(vpnId, first.host, first.port || 22, consumer)
  } catch (err) {
    // System mode routes for real, so there is nothing to forward. Register as
    // a dependent anyway: stopping the VPN still disconnects this session.
    if ((err as { code?: string }).code !== 'unsupported') throw err
    const { registerVpnConsumer } = await import('./vpn/dependencies')
    return { cfg, release: registerVpnConsumer(vpnId, consumer) }
  }

  const rewritten = {
    ...first,
    host: '127.0.0.1',
    port: fwd.port,
    poolTag: `fwd:${vpnId}:${fwd.port}`
  } as SshHop
  return {
    cfg: cfg.hops?.length
      ? { ...cfg, hops: [rewritten, ...cfg.hops.slice(1)] }
      : { ...cfg, ...rewritten },
    release: () => fwd.close()
  }
}

// How long an authenticated connection is kept after its last session closes.
// This is what decides how often a two-factor code has to be re-entered:
// while the master is alive, new sessions reuse it and skip authentication.
// 0 closes immediately; Infinity keeps it until the app exits.
let idleMs = 15 * 60_000

export function setPoolIdle(minutes: number): void {
  idleMs = minutes < 0 ? Infinity : minutes * 60_000
}

export function release(conn: PooledConnection): void {
  conn.refs--
  if (conn.refs > 0) return
  if (idleMs === 0) {
    if (pool.get(conn.key) === conn) pool.delete(conn.key)
    destroy(conn)
    return
  }
  if (idleMs === Infinity) return
  conn.idle = setTimeout(() => {
    if (conn.refs > 0) return
    if (pool.get(conn.key) === conn) pool.delete(conn.key)
    destroy(conn)
  }, idleMs)
}

export interface PoolEntry {
  key: string
  host: string
  username: string
  sessions: number
}

export function poolList(): PoolEntry[] {
  return [...pool.values()].map((c) => ({
    key: c.key,
    host: c.host,
    username: c.username,
    sessions: c.refs
  }))
}

/**
 * Every authentication the pool is currently holding.
 *
 * Not `poolList()` with another column: this exists for callers that have to
 * PROVE something did not run over a shared connection, and handing them a
 * route key would let a reconnect satisfy the check by accident. See
 * `sshOpenFresh`.
 */
export function pooledConnectionIds(): string[] {
  return [...pool.values()].map((c) => c.id)
}

// Drops a shared connection now, forcing the next connect to authenticate.
export function poolClose(key: string): void {
  const conn = pool.get(key)
  if (!conn) return
  if (conn.idle) clearTimeout(conn.idle)
  pool.delete(key)
  destroy(conn)
}

export function poolDisposeAll(): void {
  for (const conn of [...pool.values()]) {
    if (conn.idle) clearTimeout(conn.idle)
    destroy(conn)
  }
  pool.clear()
}

export async function sshConnect(wc: WebContents, cfg: SshConnectConfig): Promise<void> {
  const { sessionId } = cfg
  sessions.set(sessionId, { conn: null, stream: null })

  try {
    status(wc, sessionId, 'connecting')
    const conn = await acquire(cfg, (i, count) =>
      status(wc, sessionId, 'hop', { hopIndex: i, hopCount: count })
    )
    const current = sessions.get(sessionId)
    if (!current) {
      // Closed while connecting.
      release(conn)
      return
    }
    current.conn = conn
    const target = conn.client

    status(wc, sessionId, 'authenticating', { hopCount: cfg.hops?.length ?? 0 })

    // A container shell is `exec` with a PTY rather than `shell`; everything
    // after this point — write, resize, close, the close reason — is identical,
    // which is the whole reason this is one code path and not a second
    // terminal.
    //
    // `initialCommand` is only ever produced by a validating builder in
    // shared/; see the field's own comment. Main does not re-derive it because
    // there is nothing to re-derive: it is a constant shape with one validated
    // identifier in it.
    const pty = { term: 'xterm-256color', cols: cfg.cols, rows: cfg.rows }
    type ShellCb = (err: Error | undefined, stream: ClientChannel) => void
    const open = (cb: ShellCb): void => {
      if (cfg.initialCommand) target.exec(cfg.initialCommand, { pty }, cb)
      else target.shell(pty, cb)
    }
    open((err, stream) => {
      if (err) {
        status(wc, sessionId, 'error', { message: err.message })
        cleanup(sessionId)
        return
      }
      const s = sessions.get(sessionId)
      if (!s) {
        stream.close()
        return
      }
      s.stream = stream
      status(wc, sessionId, 'ready')

      // Commands like `cat` on a large file arrive as hundreds of small
      // chunks. One IPC message each floods the renderer and stalls input, so
      // coalesce into at most one message per tick. A single keystroke echo
      // still goes out immediately — the timer only ever batches what arrives
      // within the same millisecond window.
      let pending: string[] = []
      let flushTimer: ReturnType<typeof setTimeout> | null = null
      const flush = (): void => {
        flushTimer = null
        if (pending.length === 0) return
        const payload = pending.length === 1 ? pending[0] : pending.join('')
        pending = []
        send(wc, `ssh:data:${sessionId}`, payload)
      }
      const push = (d: Buffer): void => {
        pending.push(d.toString('utf8'))
        if (!flushTimer) flushTimer = setTimeout(flush, 0)
      }

      stream.on('data', push)
      stream.stderr.on('data', push)

      // 'exit' carries why the shell ended and always arrives before 'close'.
      // Worth forwarding: "signal HUP" is a server-side idle timeout, while
      // "exit 0" is someone typing `exit` — the same closed tab, very
      // different causes.
      let exit: SshCloseInfo = {}
      stream.on('exit', (code: number | null, signal?: string) => {
        exit = { code: code ?? undefined, signal: signal || undefined }
      })

      stream.on('close', () => {
        if (flushTimer) clearTimeout(flushTimer)
        flush()
        send(wc, `ssh:close:${sessionId}`, exit)
        cleanup(sessionId)
      })
    })
  } catch (err) {
    status(wc, sessionId, 'error', { message: err instanceof Error ? err.message : String(err) })
    cleanup(sessionId)
  }
}

export function sshWrite(sessionId: string, data: string): void {
  sessions.get(sessionId)?.stream?.write(data)
}

export function sshResize(sessionId: string, cols: number, rows: number): void {
  sessions.get(sessionId)?.stream?.setWindow(rows, cols, 0, 0)
}

export function sshClose(sessionId: string): void {
  cleanup(sessionId)
}

export interface ExecResult {
  ok: boolean
  stdout: string
  stderr: string
  code: number | null
  signal: string | null
  error?: string
  truncated: boolean
  /**
   * Bytes dropped by EXEC_OUTPUT_CAP, across both streams.
   *
   * `truncated` says that something went; this says how much. A caller that
   * persists a result needs the number, not the flag: "the output was longer
   * than this" is not a fact anyone can act on a month later, while "2.8 MB
   * elided" is. Counting it costs one addition per dropped chunk.
   */
  elided: number
}

const EXEC_OUTPUT_CAP = 200_000 // bytes per stream, enough for inspection output without unbounded memory use

// Non-interactive command execution over the same pooled connection the
// interactive terminal uses (ssh2's exec channel rather than shell), for the
// MCP bridge's execute_command tool. A single command in, buffered result
// out — never a persistent shell.
// Rejects if `p` has not settled in time.
//
// Used to bring connection setup inside the caller's timeout. `unref` so a
// pending guard never holds the process open — the answer is already decided by
// the time it fires.
function withDeadline<T>(p: Promise<T>, ms: number, message: string): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined
  const guard = new Promise<never>((_resolve, reject) => {
    timer = setTimeout(() => reject(new Error(message)), ms)
    if (typeof timer.unref === 'function') timer.unref()
  })
  // race attaches handlers to `p`, so a late settle is not an unhandled
  // rejection.
  return Promise.race([p, guard]).finally(() => clearTimeout(timer))
}

export async function sshExec(
  cfg: SshHop & { serverId?: string; hops?: SshHop[] },
  command: string,
  timeoutMs = 30_000,
  // False for anything that fans out. See the note on sshExecStream: N unknown
  // hosts must not become N stacked trust dialogs.
  allowPrompt = true
): Promise<ExecResult> {
  let conn: PooledConnection | null = null
  try {
    // Inside the timeout, not before it. The timer used to be armed only after
    // this resolved, so TCP connect, every hop's forward, and an unknown-host
    // trust prompt were all outside the timeout the caller asked for — a
    // "30 second" exec could wait indefinitely on a host that accepted the
    // connection and then said nothing. The guarantee the signature offers is
    // now the one it gives.
    conn = await withDeadline(
      acquire(cfg, undefined, allowPrompt),
      timeoutMs,
      `Timed out after ${timeoutMs}ms connecting`
    )
    return await execOn(conn.client, command, timeoutMs)
  } catch (err) {
    return {
      ok: false,
      stdout: '',
      stderr: '',
      code: null,
      signal: null,
      truncated: false,
      elided: 0,
      error: err instanceof Error ? err.message : String(err)
    }
  } finally {
    if (conn) release(conn)
  }
}

/**
 * One buffered command over one client that is already open.
 *
 * Split out of `sshExec` so the unpooled path below runs the SAME channel
 * handling. The output cap, the elision count and the command timeout are
 * safety properties, and a second copy of them written for the verification
 * path would be a second thing to drift.
 */
function execOn(client: Client, command: string, timeoutMs: number): Promise<ExecResult> {
  return new Promise<ExecResult>((resolve) => {
    let settled = false
    const done = (result: ExecResult): void => {
      if (settled) return
      settled = true
      clearTimeout(timer)
      resolve(result)
    }
    const timer = setTimeout(() => {
      done({
        ok: false,
        stdout: '',
        stderr: '',
        code: null,
        signal: null,
        truncated: false,
        elided: 0,
        error: `Command timed out after ${timeoutMs}ms`
      })
    }, timeoutMs)

    // ssh2 THROWS `Not connected` synchronously rather than calling back with
    // an error when the client is already down, so a command run over a
    // connection that has closed rejected this promise instead of answering
    // it. Every caller here is written against "an ExecResult always comes
    // back", and the case that matters most is a confirmation whose session
    // died mid-check: it has to read as a failed verification rather than as
    // an exception on the way to deciding whether a key change is permanent.
    const start = (): void => {
      client.exec(command, (err, stream) => {
        if (err) {
          done({
            ok: false,
            stdout: '',
            stderr: '',
            code: null,
            signal: null,
            truncated: false,
            elided: 0,
            error: err.message
          })
          return
        }
        let stdout = ''
        let stderr = ''
        let truncated = false
        let elided = 0
        const append = (current: string, chunk: Buffer): string => {
          if (current.length >= EXEC_OUTPUT_CAP) {
            truncated = true
            // Counted rather than merely noted. A caller that writes this
            // result down has to be able to say how much went; see ExecResult.
            elided += chunk.length
            return current
          }
          return current + chunk.toString('utf8')
        }
        stream.on('data', (d: Buffer) => {
          stdout = append(stdout, d)
        })
        stream.stderr.on('data', (d: Buffer) => {
          stderr = append(stderr, d)
        })
        stream.on('close', (code: number | null, signal?: string) => {
          done({ ok: true, stdout, stderr, code: code ?? null, signal: signal ?? null, truncated, elided })
        })
      })
    }
    try {
      start()
    } catch (err) {
      done({
        ok: false,
        stdout: '',
        stderr: '',
        code: null,
        signal: null,
        truncated: false,
        elided: 0,
        error: err instanceof Error ? err.message : String(err)
      })
    }
  })
}

/**
 * A connection that is nobody else's — roadmap item 23, rule 2.
 *
 * WHAT THIS IS FOR. Item 23 stages an `authorized_keys` change behind a
 * watchdog the host arms on itself, and refuses to make it permanent until a
 * SECOND, INDEPENDENT session has proved the host still lets us in. Every other
 * caller in this file is the opposite of independent by design: `sshExec`,
 * `sshExecStream` and the terminal all go through `acquire()`, which is a
 * ControlMaster — the second command reuses the first command's authentication
 * and never speaks to sshd's auth layer at all. Running the confirmation over
 * one of those would prove only that the session which wrote the file can still
 * write files, which is not a claim about who can log in.
 *
 * BYPASSED, NOT DROPPED, and the choice is deliberate. `poolClose()` exists and
 * would also force a new authentication — by tearing down the connection every
 * open terminal pane and the metrics sampler are riding on, at the exact moment
 * the operator is watching a key change. Waiting for the pool to go idle is not
 * available either: `release()` only arms the idle timer at zero references,
 * and `setPoolIdle(-1)` makes it Infinity so it is never armed at all. So this
 * goes around the pool instead, through `openChain()` — a new TCP connection,
 * the full handshake, the key presented to sshd again — and leaves whatever the
 * pool is holding untouched. Two live connections for a few seconds is the
 * cost, and it buys a fact nothing else here can produce.
 *
 * WHAT IT REPORTS, and why the caller is given evidence rather than a boolean.
 * `authenticatedAt` is when THIS handshake completed, so a caller can require
 * that it happened after the write it is confirming; `pooledConnectionIds` is
 * what the pool held while this ran, so a caller can require that it is not
 * among them. Neither is checked here — a transport that graded its own
 * independence would be marking its own homework, and the rule belongs with the
 * protocol it protects. See src/main/services/access.ts.
 */
export interface FreshSession {
  /** This authentication. Never a pooled id; see mintConnectionId. */
  connectionId: string
  /** Every authentication the pool held while this one was opened. */
  pooledConnectionIds: string[]
  /** When this connection's handshake completed, as observed here. */
  authenticatedAt: number
  exec: (command: string, timeoutMs?: number) => Promise<ExecResult>
  /** Ends this connection. Must be called; nothing else is holding it. */
  close: () => void
}

export async function sshOpenFresh(
  cfg: SshHop & { serverId?: string; hops?: SshHop[]; vpnProfileId?: string; serverName?: string },
  timeoutMs = 30_000,
  now: () => number = Date.now
): Promise<FreshSession> {
  // Snapshotted on BOTH sides of the connect, and unioned. A pooled connection
  // opened while this one was being negotiated is still a connection this one
  // must not turn out to be, and taking only the "before" list would miss it.
  const before = pooledConnectionIds()
  const chain = await withDeadline(
    openChain(cfg),
    timeoutMs,
    `Timed out after ${timeoutMs}ms opening an independent session`
  )
  const authenticatedAt = now()
  const pooled = [...new Set([...before, ...pooledConnectionIds()])]
  let closed = false
  return {
    connectionId: mintConnectionId('fresh'),
    pooledConnectionIds: pooled,
    authenticatedAt,
    exec: (command, ms = timeoutMs) => execOn(chain.client, command, ms),
    close: () => {
      if (closed) return
      closed = true
      // Every client in the chain, not just the last: a bastion opened for this
      // one connection is this connection's to close, and leaving it up would
      // be an authenticated session nothing is tracking.
      for (const c of chain.clients) {
        try {
          c.end()
        } catch {
          /* already gone */
        }
      }
      try {
        chain.close?.()
      } catch {
        /* a VPN forward already closed must not break the teardown */
      }
    }
  }
}

/**
 * Run a command and stream its output until it is stopped.
 *
 * `sshExec` buffers and resolves; a following log never resolves, so this
 * hands back a stop function instead. The connection is acquired from the pool
 * like everything else, and released exactly once — a tail that leaks its
 * reference keeps an authenticated master alive for a pane the user closed,
 * which is invisible until an estate wonders why its sshd is busy.
 */
export async function sshExecStream(
  cfg: SshHop & { serverId?: string; hops?: SshHop[] },
  command: string,
  handlers: {
    onStdout: (chunk: string) => void
    onStderr: (chunk: string) => void
    onClose: (code: number | null) => void
    onError: (message: string) => void
  },
  // False for anything that fans out across several hosts at once.
  //
  // `metrics.ts` threads this through for the background sweep precisely so an
  // unattended sample cannot raise a trust-on-first-use dialog. Log tailing and
  // broadcast have the same problem for a different reason: the user IS present,
  // but a batch across fifteen hosts with unknown keys would raise fifteen
  // stacked modals, and a stack of identical dialogs is not a decision anyone
  // can reason about — it is the click-through this app's host verification
  // exists to avoid. An unknown host fails that host with a reason instead, and
  // the fix is to connect to it once directly.
  allowPrompt = true
): Promise<() => void> {
  const conn = await acquire(cfg, undefined, allowPrompt)
  let released = false
  const releaseOnce = (): void => {
    if (released) return
    released = true
    release(conn)
  }

  return await new Promise<() => void>((resolve, reject) => {
    conn.client.exec(command, (err, stream) => {
      if (err) {
        releaseOnce()
        reject(err)
        return
      }
      stream.on('data', (c: Buffer) => handlers.onStdout(c.toString('utf8')))
      stream.stderr.on('data', (c: Buffer) => handlers.onStderr(c.toString('utf8')))
      stream.on('close', (code: number | null) => {
        releaseOnce()
        handlers.onClose(code ?? null)
      })
      stream.on('error', (e: Error) => {
        releaseOnce()
        handlers.onError(e.message)
      })
      resolve(() => {
        // Signal first so the remote process actually dies rather than being
        // orphaned holding the file open; then close the channel regardless of
        // whether the server honoured the signal, and release either way.
        try {
          stream.signal('TERM')
        } catch {
          /* server may not support signals; close still ends the channel */
        }
        try {
          stream.close()
        } catch {
          /* already gone */
        }
        releaseOnce()
      })
    })
  })
}

export function sshDisposeAll(): void {
  for (const id of [...sessions.keys()]) cleanup(id)
  poolDisposeAll()
}

function cleanup(sessionId: string): void {
  const s = sessions.get(sessionId)
  if (!s) return
  sessions.delete(sessionId)
  try {
    s.stream?.close()
  } catch {
    /* ignore */
  }
  // The connection itself is shared, so hand it back rather than closing it.
  if (s.conn) release(s.conn)
}
