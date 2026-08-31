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

async function connectClient(hop: SshHop, sock?: NodeJS.ReadableStream): Promise<Client> {
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
        void verifyHostKey(hop.host, hop.port || 22, key).then(cb)
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

export interface PooledConnection {
  key: string
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
  parent: PooledConnection | null
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
    const client = await connectClient(hop, sock)
    const conn: PooledConnection = {
      key,
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
  onHop?: (index: number, count: number) => void
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
      parent = await acquireOne(hops[i], parent)
    }
    const conn = await acquireOne(effective, parent)
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

    target.shell({ term: 'xterm-256color', cols: cfg.cols, rows: cfg.rows }, (err, stream) => {
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
}

const EXEC_OUTPUT_CAP = 200_000 // bytes per stream, enough for inspection output without unbounded memory use

// Non-interactive command execution over the same pooled connection the
// interactive terminal uses (ssh2's exec channel rather than shell), for the
// MCP bridge's execute_command tool. A single command in, buffered result
// out — never a persistent shell.
export async function sshExec(
  cfg: SshHop & { serverId?: string; hops?: SshHop[] },
  command: string,
  timeoutMs = 30_000
): Promise<ExecResult> {
  let conn: PooledConnection | null = null
  try {
    conn = await acquire(cfg)
    const client = conn.client
    return await new Promise<ExecResult>((resolve) => {
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
          error: `Command timed out after ${timeoutMs}ms`
        })
      }, timeoutMs)

      client.exec(command, (err, stream) => {
        if (err) {
          done({ ok: false, stdout: '', stderr: '', code: null, signal: null, truncated: false, error: err.message })
          return
        }
        let stdout = ''
        let stderr = ''
        let truncated = false
        const append = (current: string, chunk: Buffer): string => {
          if (current.length >= EXEC_OUTPUT_CAP) {
            truncated = true
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
          done({ ok: true, stdout, stderr, code: code ?? null, signal: signal ?? null, truncated })
        })
      })
    })
  } catch (err) {
    return {
      ok: false,
      stdout: '',
      stderr: '',
      code: null,
      signal: null,
      truncated: false,
      error: err instanceof Error ? err.message : String(err)
    }
  } finally {
    if (conn) release(conn)
  }
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
