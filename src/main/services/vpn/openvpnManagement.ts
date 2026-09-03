import net from 'node:net'
import { Buffer } from 'node:buffer'
import { randomBytes } from 'node:crypto'
import { mkdirSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import type { VpnErrorCode, VpnPrompt, VpnState, VpnStats, VpnStatus } from '../../../shared/vpn'
import { VpnError, classifyEngineLine } from './errors'

// A typed client for the OpenVPN management interface.
//
// `--management-client` inverts the direction: openvpn dials us. That removes
// the window in which a listening management port sits unauthenticated, which
// is the whole reason this file listens instead of connecting. On POSIX the
// socket lives in a 0700 directory and filesystem permissions are the entire
// auth story. On Windows there are no unix sockets, so we bind 127.0.0.1:0,
// stop listening on the first accept, and refuse to trust a peer that does not
// open with the OpenVPN greeting.

export const MANAGEMENT_GREETING_PREFIX = '>INFO:OpenVPN Management Interface Version'

// A management line is a command or a status notification; neither is ever
// close to this long. Accumulating past it would let a wedged or hostile peer
// grow our heap without ever giving us something to parse, so it is treated as
// a protocol violation rather than as data still on its way.
export const MANAGEMENT_MAX_LINE_BYTES = 64 * 1024

// Sent in this order the moment the peer is trusted. `hold release` is last
// because the three before it decide what we are told about the connection
// that release starts.
const HANDSHAKE_COMMANDS = ['state on', 'bytecount 5', 'log on all', 'hold release']

// ------------------------------------------------------------------ escaping

const UNQUOTED_SAFE = /^[A-Za-z0-9_.@-]+$/

/** Backslash-escape `\` and `"` for a `"`-quoted management value.
 *
 *  Throws on a newline: the management protocol is line-oriented, so a `\n`
 *  inside a value is not something quoting can contain — it ends the command
 *  and starts another one the caller never wrote. A password containing `"` is
 *  the classic injection here and is handled; a password containing `\n` is
 *  refused. */
export function escapeManagementValue(value: string): string {
  if (/[\r\n\0]/.test(value)) {
    throw new VpnError('config-invalid', 'A credential contains a line break, which cannot be sent safely.')
  }
  return value.replace(/\\/g, '\\\\').replace(/"/g, '\\"')
}

/** The same value, wrapped in the quotes openvpn expects. */
export function quoteManagementValue(value: string): string {
  return `"${escapeManagementValue(value)}"`
}

// openvpn's own transcript writes a plain username and a quoted password. Both
// go through the escaper; a username that could not be mistaken for anything
// else is left bare so the wire matches what an operator would recognise.
function usernameArgument(value: string): string {
  return UNQUOTED_SAFE.test(value) ? escapeManagementValue(value) : quoteManagementValue(value)
}

// -------------------------------------------------------------------- parser

const STATE_MAP: Record<string, VpnState> = {
  CONNECTING: 'starting',
  WAIT: 'starting',
  RESOLVE: 'starting',
  TCP_CONNECT: 'starting',
  AUTH: 'authenticating',
  GET_CONFIG: 'authenticating',
  ASSIGN_IP: 'starting',
  ADD_ROUTES: 'starting',
  CONNECTED: 'connected',
  RECONNECTING: 'reconnecting',
  EXITING: 'stopped'
}

/** The `VpnState` an openvpn `>STATE:` name maps onto, or null for one we do
 *  not model. Null means "keep the state you already had" rather than a guess. */
export function mapOpenVpnState(name: string): VpnState | null {
  return STATE_MAP[name.trim().toUpperCase()] ?? null
}

export interface OpenVpnStateEvent {
  type: 'state'
  raw: string
  /** Epoch seconds as openvpn reported it; 0 when it was not a number. */
  time: number
  /** CONNECTING, AUTH, CONNECTED, RECONNECTING, … */
  name: string
  /** Field 3. On RECONNECTING this carries the reason: tls-error,
   *  ping-restart, auth-failure. On CONNECTED it is SUCCESS. */
  description: string
  /** Field 4: the local virtual IPv4 address. */
  localIp: string
  /** Fields 5 and 6. */
  remoteIp: string
  remotePort: string
  state: VpnState | null
}

export interface OpenVpnPasswordEvent {
  type: 'password'
  raw: string
  /** 'Auth', 'Private Key', … */
  realm: string
  /** True for `Verification Failed: 'Auth'`. */
  failed: boolean
  /** True when the line asks for a username as well as a password. */
  needsUsername: boolean
  /** Present when the line carried `SC:<echo-flag>,<challenge text>`. */
  challenge: { text: string; echo: boolean } | null
}

export type OpenVpnEvent =
  | { type: 'info'; raw: string; text: string }
  | { type: 'hold'; raw: string; text: string }
  | OpenVpnStateEvent
  | OpenVpnPasswordEvent
  | { type: 'bytecount'; raw: string; rxBytes: number; txBytes: number }
  | { type: 'log'; raw: string; time: number; flags: string; text: string }
  | { type: 'fatal'; raw: string; text: string; code: VpnErrorCode }
  | { type: 'need-ok'; raw: string; needType: string; text: string }
  | { type: 'reply'; raw: string; ok: boolean; text: string }
  | { type: 'other'; raw: string }

const NEED_RE = /^Need\s+'([^']*)'\s*(.*)$/
const FAILED_RE = /^Verification Failed:\s*'([^']*)'/
const SC_RE = /\bSC:([01]),([\s\S]*)$/

function toInt(s: string | undefined): number {
  const n = Number(s)
  return Number.isFinite(n) ? n : 0
}

function parsePasswordLine(raw: string, body: string): OpenVpnPasswordEvent {
  const failure = FAILED_RE.exec(body)
  if (failure) {
    return { type: 'password', raw, realm: failure[1], failed: true, needsUsername: false, challenge: null }
  }
  const need = NEED_RE.exec(body)
  const realm = need ? need[1] : ''
  const rest = need ? need[2] : body
  const sc = SC_RE.exec(rest)
  return {
    type: 'password',
    raw,
    realm,
    failed: false,
    // `Need 'Auth' username/password` wants both; `Need 'Private Key'
    // password` wants only the passphrase.
    needsUsername: /username/i.test(rest),
    challenge: sc ? { echo: sc[1] === '1', text: sc[2].trim() } : null
  }
}

/** OpenVPN reports an unusable clock and an expired certificate with almost
 *  the same words. `classifyEngineLine` folds both into `cert-expired`; a
 *  not-yet-valid certificate is nearly always a wrong clock, and telling the
 *  user to ask for a new certificate when their clock is wrong sends them to
 *  the wrong person. */
function classifyOpenVpnLine(text: string): VpnErrorCode | null {
  if (/not yet valid|is not valid until|certificate is not yet/i.test(text)) return 'clock-skew'
  return classifyEngineLine(text)
}

/** Pure: turn one management line into a typed event. Unknown lines become
 *  `other` rather than throwing — openvpn adds notifications between versions
 *  and an unrecognised one is not a reason to drop a working tunnel. */
export function parseManagementLine(line: string): OpenVpnEvent {
  const raw = line.replace(/\r$/, '')

  if (raw.startsWith('>INFO:')) return { type: 'info', raw, text: raw.slice(6) }
  if (raw.startsWith('>HOLD:')) return { type: 'hold', raw, text: raw.slice(6) }

  if (raw.startsWith('>STATE:')) {
    const f = raw.slice(7).split(',')
    const name = (f[1] ?? '').trim()
    return {
      type: 'state',
      raw,
      time: toInt(f[0]),
      name,
      description: (f[2] ?? '').trim(),
      localIp: (f[3] ?? '').trim(),
      remoteIp: (f[4] ?? '').trim(),
      remotePort: (f[5] ?? '').trim(),
      state: mapOpenVpnState(name)
    }
  }

  if (raw.startsWith('>PASSWORD:')) return parsePasswordLine(raw, raw.slice(10).trim())

  if (raw.startsWith('>BYTECOUNT:')) {
    const [rx, tx] = raw.slice(11).split(',')
    return { type: 'bytecount', raw, rxBytes: toInt(rx), txBytes: toInt(tx) }
  }

  if (raw.startsWith('>LOG:')) {
    const f = raw.slice(5).split(',')
    return { type: 'log', raw, time: toInt(f[0]), flags: f[1] ?? '', text: f.slice(2).join(',') }
  }

  if (raw.startsWith('>FATAL:')) {
    const text = raw.slice(7).trim()
    return { type: 'fatal', raw, text, code: classifyOpenVpnLine(text) ?? 'internal' }
  }

  if (raw.startsWith('>NEED-OK:')) {
    const body = raw.slice(9)
    const i = body.indexOf(':')
    return {
      type: 'need-ok',
      raw,
      needType: (i === -1 ? body : body.slice(0, i)).trim(),
      text: (i === -1 ? '' : body.slice(i + 1)).trim()
    }
  }

  if (raw.startsWith('SUCCESS:')) return { type: 'reply', raw, ok: true, text: raw.slice(8).trim() }
  if (raw.startsWith('ERROR:')) return { type: 'reply', raw, ok: false, text: raw.slice(6).trim() }

  return { type: 'other', raw }
}

// --------------------------------------------------------------------- class

/** Read fresh on every prompt rather than captured once, because with
 *  `--auth-nocache` a reconnect re-asks and the vault may have been relocked
 *  in between. */
export interface OpenVpnCredentials {
  username?: string
  password?: string
  keyPassphrase?: string
}

export interface OpenVpnManagementHooks {
  /** Same shape as `VpnDriverContext.emit`: a status patch the manager
   *  coalesces and change-detects before it reaches IPC. */
  emit(patch: Partial<VpnStatus>): void
  log(line: string, stream: 'ctl' | 'app'): void
  /** Resolves to null when the user cancels, which is a normal outcome. */
  askUser(p: Omit<VpnPrompt, 'id' | 'profileId' | 'profileName'>): Promise<string | null>
  credentials(): OpenVpnCredentials
  /** `>NEED-OK:` confirmations (token insertion, PKCS#11). Absent means we
   *  cannot show the question, so the answer is no. */
  confirm?(needType: string, text: string): Promise<boolean>
  /** Every parsed line, for logging and tests. */
  onEvent?(event: OpenVpnEvent): void
  /** The management channel went away: openvpn exited, or we closed it. */
  onClose?(): void
}

export interface OpenVpnManagementOptions {
  /** Defaults to `process.platform`. Injectable so the Windows branch is
   *  reachable from a test on any host. */
  platform?: NodeJS.Platform
  maxLineBytes?: number
}

export interface OpenVpnManagementEndpoint {
  /** Append verbatim to argv. The caller still owns `--management-client`,
   *  `--management-hold` and `--management-query-passwords`. */
  args: string[]
  socketPath?: string
  port?: number
}

export type OpenVpnSignal = 'SIGTERM' | 'SIGINT' | 'SIGHUP' | 'SIGUSR1' | 'SIGUSR2'

export class OpenVpnManagement {
  private readonly hooks: OpenVpnManagementHooks
  private readonly platform: NodeJS.Platform
  private readonly maxLineBytes: number

  private server: net.Server | null = null
  private socket: net.Socket | null = null
  private buffer: Buffer = Buffer.alloc(0)

  private mgmtDir: string | null = null
  private socketPathValue: string | null = null
  private portValue: number | null = null

  private greeted = false
  private closed = false

  // Prompts are serialised: openvpn can emit a second >PASSWORD: while we are
  // still showing the first, and two modal prompts racing produce answers
  // matched to the wrong question.
  private prompts: Promise<void> = Promise.resolve()

  private statsValue: VpnStats | null = null
  private assignedIp: string | undefined
  private remoteEndpoint: string | undefined

  // Set by `Verification Failed` or a `RECONNECTING,auth-failure`. Once these
  // credentials are known bad we never send them again: openvpn would keep
  // retrying and a retry storm locks the account (E28).
  private credentialsRejected = false

  private lastCode: VpnErrorCode | null = null

  private readonly ready: Promise<void>
  private readyResolve: (() => void) | null = null
  private readyReject: ((e: Error) => void) | null = null

  constructor(hooks: OpenVpnManagementHooks, options: OpenVpnManagementOptions) {
    this.hooks = hooks
    this.platform = options.platform ?? process.platform
    this.maxLineBytes = options.maxLineBytes ?? MANAGEMENT_MAX_LINE_BYTES
    this.ready = new Promise<void>((resolve, reject) => {
      this.readyResolve = resolve
      this.readyReject = reject
    })
    // Nobody is obliged to await whenConnected(); an unobserved rejection
    // must not take the app down.
    this.ready.catch(() => undefined)
  }

  get socketPath(): string | null {
    return this.socketPathValue
  }

  get port(): number | null {
    return this.portValue
  }

  /** The most recent `>BYTECOUNT:`, enriched with what CONNECTED told us. */
  stats(): VpnStats | null {
    return this.statsValue
  }

  /** The last error code seen in a `>FATAL:` or `>LOG:` line. The driver uses
   *  it when openvpn dies without saying why on the way out. */
  lastErrorCode(): VpnErrorCode | null {
    return this.lastCode
  }

  /** Bind the endpoint openvpn will dial back into and return the argv for it.
   *  Must be called before the process is spawned. */
  async listen(): Promise<OpenVpnManagementEndpoint> {
    if (this.server || this.socket) throw new VpnError('internal', 'The management endpoint is already listening.')

    const server = net.createServer()
    this.server = server
    server.on('error', (err: Error) => this.fail('internal', `The management endpoint failed: ${err.message}`))
    server.on('connection', (socket) => this.accept(socket))

    if (this.platform === 'win32') {
      const port = await bindTcp(server)
      this.portValue = port
      return { args: ['--management', '127.0.0.1', String(port)], port }
    }

    // NOT under the run directory, which is where this used to be and is why
    // OpenVPN could not start on macOS at all.
    //
    // sun_path is 104 bytes and the run directory alone is longer than that:
    // `~/Library/Application Support/ShellPilot/vpn-run/vpn-<uuid>-<8 hex>` is
    // 111 bytes for a seven-character username, so the socket came to 123 and
    // the length guard below rejected it before openvpn was ever launched. No
    // shorter username saves it — the floor is 117.
    //
    // The per-user temp directory is the shortest private location there is:
    // 48 bytes here, and macOS makes it 0700 and owned by the user, which is
    // the same protection the run directory gave. A random leaf keeps runs
    // apart, and `mkdirSync` WITHOUT `recursive` is deliberate — it throws on
    // an existing path, so a pre-created directory or symlink is refused
    // rather than adopted.
    const dir = join(tmpdir(), `sp-${randomBytes(8).toString('hex')}`)
    mkdirSync(dir, { mode: 0o700 })
    this.mgmtDir = dir
    const path = join(dir, 'm.sock')
    // Kept as a backstop, not as the mechanism: a host with an unusually long
    // temp directory would otherwise reach bind() and get only ENAMETOOLONG.
    const length = Buffer.byteLength(path)
    if (length > 100) {
      throw new VpnError('internal', `The management socket path is ${length} bytes, which is too long: ${path}`)
    }
    // A run directory left behind by a killed process (E48) still holds the
    // socket file, and bind() refuses to replace it.
    rmSync(path, { force: true })
    await bindUnix(server, path)
    this.socketPathValue = path
    return { args: ['--management', path, 'unix'], socketPath: path }
  }

  /** Resolves once openvpn has dialled in and, on Windows, identified itself. */
  whenConnected(timeoutMs?: number): Promise<void> {
    if (timeoutMs === undefined) return this.ready
    return new Promise<void>((resolve, reject) => {
      const timer = setTimeout(() => {
        reject(new VpnError('handshake-timeout', 'openvpn did not open its management channel.'))
      }, timeoutMs)
      this.ready.then(
        () => {
          clearTimeout(timer)
          resolve()
        },
        (e: Error) => {
          clearTimeout(timer)
          reject(e)
        }
      )
    })
  }

  /** Write one command. Rejects embedded newlines for the same reason
   *  `escapeManagementValue` does. */
  send(command: string): void {
    if (/[\r\n]/.test(command)) {
      throw new VpnError('internal', 'A management command contained a line break.')
    }
    this.write(command, command)
  }

  signal(name: OpenVpnSignal): void {
    this.send(`signal ${name}`)
  }

  /** Ask openvpn to exit. */
  sigterm(): void {
    this.signal('SIGTERM')
  }

  /** Soft restart: openvpn renegotiates without tearing the tunnel down. This
   *  is what a sleep/wake or an interface change wants (E20, E21) — a full
   *  restart would re-prompt for credentials it does not need to. */
  softRestart(): void {
    this.signal('SIGUSR1')
  }

  /** Stop listening, drop the connection and remove the socket. Idempotent. */
  close(): void {
    if (this.closed) return
    this.closed = true
    this.socket?.destroy()
    this.socket = null
    this.server?.close()
    this.server = null
    if (this.socketPathValue) rmSync(this.socketPathValue, { force: true })
    if (this.mgmtDir) rmSync(this.mgmtDir, { recursive: true, force: true })
    this.readyReject?.(new VpnError('internal', 'The management channel closed before openvpn connected.'))
    this.readyResolve = null
    this.readyReject = null
  }

  // ------------------------------------------------------------- connection

  private accept(socket: net.Socket): void {
    if (this.socket || this.closed) {
      socket.destroy()
      return
    }
    this.socket = socket
    // One connection is all openvpn makes, so stop listening immediately: on
    // Windows that shuts the 127.0.0.1 port before anything else can reach it.
    this.server?.close()
    this.server = null

    socket.setNoDelay(true)
    socket.on('data', (chunk: Buffer) => this.consume(chunk))
    socket.on('error', (err: Error) => this.hooks.log(`management socket error: ${err.message}`, 'app'))
    socket.on('close', () => {
      this.socket = null
      this.readyReject?.(new VpnError('internal', 'The management channel closed before openvpn connected.'))
      this.hooks.onClose?.()
    })

    // On POSIX the peer is authenticated by the 0700 directory it had to get
    // through, so the handshake goes out at once. On Windows nothing has
    // authenticated it yet and the greeting is the only evidence available.
    if (this.platform !== 'win32') {
      this.greeted = true
      this.handshake()
      this.markReady()
    }
  }

  private handshake(): void {
    for (const c of HANDSHAKE_COMMANDS) this.write(c, c)
  }

  private markReady(): void {
    this.readyResolve?.()
    this.readyResolve = null
    this.readyReject = null
  }

  private consume(chunk: Buffer): void {
    if (this.closed) return
    this.buffer = this.buffer.length === 0 ? chunk : Buffer.concat([this.buffer, chunk])
    for (;;) {
      const i = this.buffer.indexOf(0x0a)
      if (i === -1) {
        if (this.buffer.length > this.maxLineBytes) {
          this.buffer = Buffer.alloc(0)
          this.fail(
            'internal',
            `The management channel sent ${this.maxLineBytes} bytes with no line ending, which is not the management protocol.`
          )
        }
        return
      }
      const line = this.buffer.subarray(0, i).toString('utf8')
      this.buffer = this.buffer.subarray(i + 1)
      this.handleLine(line)
      if (this.closed) return
    }
  }

  private handleLine(line: string): void {
    if (!this.greeted) {
      // Windows only. A peer that does not open with the greeting is not
      // openvpn, and this is the only point at which we can tell.
      if (!line.startsWith(MANAGEMENT_GREETING_PREFIX)) {
        this.fail('internal', 'The management connection did not present the OpenVPN greeting, so it was refused.')
        return
      }
      this.greeted = true
      this.hooks.log(line, 'ctl')
      this.hooks.onEvent?.(parseManagementLine(line))
      this.handshake()
      this.markReady()
      return
    }

    const event = parseManagementLine(line)
    this.hooks.log(line, 'ctl')
    this.hooks.onEvent?.(event)

    switch (event.type) {
      case 'hold':
        // openvpn re-enters hold after a --management-hold restart, so this is
        // not only a start-up message.
        this.send('hold release')
        return
      case 'state':
        this.onState(event)
        return
      case 'password':
        this.onPassword(event)
        return
      case 'bytecount':
        this.statsValue = {
          rxBytes: event.rxBytes,
          txBytes: event.txBytes,
          assignedIp: this.assignedIp,
          remoteEndpoint: this.remoteEndpoint,
          sampledAt: Date.now()
        }
        this.hooks.emit({ stats: this.statsValue })
        return
      case 'log': {
        const code = classifyOpenVpnLine(event.text)
        if (code) this.lastCode = code
        return
      }
      case 'fatal':
        this.lastCode = event.code
        this.hooks.emit({ state: 'error', since: Date.now(), error: event.text, errorCode: event.code })
        return
      case 'need-ok':
        void this.onNeedOk(event.needType, event.text)
        return
      default:
        return
    }
  }

  private onState(event: OpenVpnStateEvent): void {
    if (event.name === 'CONNECTED') {
      this.assignedIp = event.localIp || undefined
      this.remoteEndpoint = event.remoteIp ? `${event.remoteIp}:${event.remotePort}` : undefined
      this.statsValue = {
        rxBytes: this.statsValue?.rxBytes ?? 0,
        txBytes: this.statsValue?.txBytes ?? 0,
        assignedIp: this.assignedIp,
        remoteEndpoint: this.remoteEndpoint,
        sampledAt: Date.now()
      }
      this.hooks.emit({ state: 'connected', since: Date.now(), stats: this.statsValue })
      return
    }

    if (event.name === 'RECONNECTING') {
      // The reason is the only useful part of this line. `auth-failure` means
      // openvpn is about to retry the credentials the server just refused, and
      // that loop is what locks accounts — so it ends here (E28).
      if (event.description === 'auth-failure') {
        this.rejectCredentials(`The server refused these credentials (${event.description}).`)
        return
      }
      this.hooks.emit({ state: 'reconnecting', since: Date.now() })
      this.hooks.log(`reconnecting: ${event.description || 'no reason given'}`, 'app')
      return
    }

    if (event.state) this.hooks.emit({ state: event.state, since: Date.now() })
  }

  private onPassword(event: OpenVpnPasswordEvent): void {
    if (event.failed) {
      this.rejectCredentials(`The server refused the ${event.realm || 'login'} credentials.`)
      return
    }
    if (this.credentialsRejected) {
      // openvpn asks again after a rejection. Answering with the same secret
      // is exactly the retry storm E28 is about.
      this.hooks.log('ignoring a repeated credential request: these credentials were already refused', 'app')
      return
    }

    // A re-prompt on RECONNECTING -> AUTH is expected with --auth-nocache
    // (E30). There is deliberately no timeout: if the user is away we sit in
    // `authenticating` until they come back rather than failing the tunnel.
    this.hooks.emit({ state: 'authenticating', since: Date.now() })
    this.prompts = this.prompts.then(() => this.answer(event)).catch((e: unknown) => {
      const message = e instanceof Error ? e.message : String(e)
      this.hooks.log(`credential exchange failed: ${message}`, 'app')
      this.stopWith('internal', message)
    })
  }

  private async answer(event: OpenVpnPasswordEvent): Promise<void> {
    if (this.closed || !this.socket) return
    const realm = event.realm || 'Auth'

    if (realm === 'Private Key') {
      const stored = this.hooks.credentials().keyPassphrase
      const passphrase =
        stored ?? (await this.hooks.askUser({ kind: 'passphrase', label: event.raw.slice(10).trim(), echo: false }))
      if (passphrase === null || passphrase === undefined) {
        this.cancel(null, 'The private key passphrase prompt was cancelled.')
        return
      }
      this.writePassword(realm, passphrase)
      return
    }

    let username = this.hooks.credentials().username
    if (event.needsUsername && !username) {
      const answer = await this.hooks.askUser({ kind: 'username', label: event.raw.slice(10).trim(), echo: true })
      if (answer === null) {
        this.cancel(null, 'The username prompt was cancelled.')
        return
      }
      username = answer
    }

    let password = this.hooks.credentials().password
    if (!password) {
      const answer = await this.hooks.askUser({ kind: 'password', label: event.raw.slice(10).trim(), echo: false })
      if (answer === null) {
        this.cancel(null, 'The password prompt was cancelled.')
        return
      }
      password = answer
    }

    if (event.challenge) {
      // A static challenge response is per-connection by definition, so it is
      // asked for every time and never cached (E29).
      const response = await this.hooks.askUser({
        kind: 'otp',
        // The engine's own wording: the server chose it and the user has
        // probably seen it in another client.
        label: event.raw.slice(10).trim(),
        echo: event.challenge.echo
      })
      if (response === null) {
        this.cancel('auth-otp-required', 'The one-time code prompt was cancelled.')
        return
      }
      if (username !== undefined) this.writeUsername(realm, username)
      this.writePassword(realm, `SCRV1:${b64(password)}:${b64(response)}`)
      return
    }

    if (username !== undefined) this.writeUsername(realm, username)
    this.writePassword(realm, password)
  }

  private async onNeedOk(needType: string, text: string): Promise<void> {
    // Auto-confirming a hardware-token prompt would answer a question the user
    // never saw, so without a way to ask, the answer is no.
    const ok = this.hooks.confirm ? await this.hooks.confirm(needType, text) : false
    if (!this.hooks.confirm) this.hooks.log(`declined a confirmation ShellPilot cannot show: ${needType} ${text}`, 'app')
    if (this.closed) return
    this.send(`needok ${needType} ${ok ? 'ok' : 'cancel'}`)
  }

  // ---------------------------------------------------------------- writing

  private writeUsername(realm: string, username: string): void {
    this.send(`username ${quoteManagementValue(realm)} ${usernameArgument(username)}`)
  }

  private writePassword(realm: string, password: string): void {
    const line = `password ${quoteManagementValue(realm)} ${quoteManagementValue(password)}`
    // The redacted form is what reaches the log. The driver's own redactor
    // only knows the literals it resolved from the vault, and a one-time code
    // is never one of them.
    this.write(line, `password ${quoteManagementValue(realm)} "***"`)
  }

  private write(line: string, logAs: string): void {
    if (this.closed || !this.socket) return
    this.socket.write(`${line}\n`)
    this.hooks.log(`> ${logAs}`, 'ctl')
  }

  // --------------------------------------------------------------- failures

  private rejectCredentials(detail: string): void {
    if (this.credentialsRejected) return
    this.credentialsRejected = true
    this.lastCode = 'auth-failed'
    this.stopWith('auth-failed', detail)
  }

  /** The user dismissed a prompt. That is a choice, not a fault: stop the
   *  engine cleanly. A cancelled one-time code still carries a code so the UI
   *  can offer "try again"; a cancelled password prompt just stops. */
  private cancel(code: VpnErrorCode | null, detail: string): void {
    this.hooks.log(detail, 'app')
    if (this.socket) this.sigterm()
    this.hooks.emit(
      code
        ? { state: 'stopped', since: Date.now(), error: detail, errorCode: code }
        : { state: 'stopped', since: Date.now() }
    )
  }

  /** Report, then ask openvpn to exit. Used where continuing would mean
   *  retrying something that already failed. */
  private stopWith(code: VpnErrorCode, detail: string): void {
    this.hooks.emit({ state: 'error', since: Date.now(), error: detail, errorCode: code })
    if (this.socket) this.sigterm()
  }

  /** Report and tear the channel down. Used where the channel itself is the
   *  problem, so there is nothing left to send a signal over. */
  private fail(code: VpnErrorCode, detail: string): void {
    this.hooks.log(detail, 'app')
    this.lastCode = code
    this.hooks.emit({ state: 'error', since: Date.now(), error: detail, errorCode: code })
    this.close()
  }
}

function b64(s: string): string {
  return Buffer.from(s, 'utf8').toString('base64')
}

function bindTcp(server: net.Server): Promise<number> {
  return new Promise((resolve, reject) => {
    const onError = (err: Error): void => {
      server.removeListener('error', onError)
      reject(err)
    }
    server.once('error', onError)
    // Port 0 and 127.0.0.1: the port is handed to openvpn on the command line
    // and nothing off this machine has any business reaching it.
    server.listen(0, '127.0.0.1', () => {
      server.removeListener('error', onError)
      const addr = server.address()
      resolve(typeof addr === 'object' && addr ? addr.port : 0)
    })
  })
}

function bindUnix(server: net.Server, path: string): Promise<void> {
  return new Promise((resolve, reject) => {
    const onError = (err: Error): void => {
      server.removeListener('error', onError)
      reject(err)
    }
    server.once('error', onError)
    server.listen(path, () => {
      server.removeListener('error', onError)
      resolve()
    })
  })
}
