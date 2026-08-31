import { describe, it, expect, afterEach } from 'vitest'
import net from 'node:net'
import { spawn, type ChildProcessWithoutNullStreams } from 'node:child_process'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { fileURLToPath } from 'node:url'

import type { VpnPrompt, VpnStatus } from '../src/shared/vpn'
import {
  MANAGEMENT_MAX_LINE_BYTES,
  OpenVpnManagement,
  escapeManagementValue,
  mapOpenVpnState,
  parseManagementLine,
  quoteManagementValue,
  type OpenVpnCredentials,
  type OpenVpnEvent
} from '../src/main/services/vpn/openvpnManagement'

const FAKE = fileURLToPath(new URL('./fixtures/fake-openvpn.mjs', import.meta.url))
const b64 = (s: string): string => Buffer.from(s, 'utf8').toString('base64')

// --------------------------------------------------------------- transcript

// The dialogue from the plan, verbatim. Feeding it through the parser is the
// cheap half of the coverage: it pins the wire format independently of whether
// a process ever runs.
const TRANSCRIPT = [
  ">INFO:OpenVPN Management Interface Version 5 -- type 'help' for more info",
  '>HOLD:Waiting for hold release',
  '>STATE:1756000000,CONNECTING,,,,,,',
  ">PASSWORD:Need 'Auth' username/password",
  ">PASSWORD:Need 'Auth' username/password SC:1,Enter your 6-digit code",
  ">PASSWORD:Need 'Private Key' password",
  ">PASSWORD:Verification Failed: 'Auth'",
  '>STATE:1756000001,AUTH,,,,,,',
  '>STATE:1756000002,GET_CONFIG,,,,,,',
  '>STATE:1756000003,ASSIGN_IP,,10.8.0.6,,,,',
  '>STATE:1756000004,CONNECTED,SUCCESS,10.8.0.6,203.0.113.1,1194,,',
  '>BYTECOUNT:184320,92160',
  '>STATE:1756000005,RECONNECTING,tls-error,,,,,',
  '>FATAL:Cannot resolve host address: vpn.example.com',
  'SUCCESS: real-time state notification set to ON',
  'ERROR: unknown command'
]

describe('OpenVPN management parser', () => {
  it('types every line of the recorded transcript', () => {
    const types = TRANSCRIPT.map((l) => parseManagementLine(l).type)
    expect(types).toEqual([
      'info',
      'hold',
      'state',
      'password',
      'password',
      'password',
      'password',
      'state',
      'state',
      'state',
      'state',
      'bytecount',
      'state',
      'fatal',
      'reply',
      'reply'
    ])
  })

  it('maps every state name the plan lists', () => {
    expect(mapOpenVpnState('CONNECTING')).toBe('starting')
    expect(mapOpenVpnState('WAIT')).toBe('starting')
    expect(mapOpenVpnState('RESOLVE')).toBe('starting')
    expect(mapOpenVpnState('TCP_CONNECT')).toBe('starting')
    expect(mapOpenVpnState('AUTH')).toBe('authenticating')
    expect(mapOpenVpnState('GET_CONFIG')).toBe('authenticating')
    expect(mapOpenVpnState('ASSIGN_IP')).toBe('starting')
    expect(mapOpenVpnState('ADD_ROUTES')).toBe('starting')
    expect(mapOpenVpnState('CONNECTED')).toBe('connected')
    expect(mapOpenVpnState('RECONNECTING')).toBe('reconnecting')
    expect(mapOpenVpnState('EXITING')).toBe('stopped')
    expect(mapOpenVpnState('SOMETHING_NEW')).toBeNull()
  })

  it('reads the CONNECTED fields as local VIP, remote ip and remote port', () => {
    const ev = parseManagementLine('>STATE:1756000004,CONNECTED,SUCCESS,10.8.0.6,203.0.113.1,1194,,')
    expect(ev).toMatchObject({
      type: 'state',
      name: 'CONNECTED',
      description: 'SUCCESS',
      localIp: '10.8.0.6',
      remoteIp: '203.0.113.1',
      remotePort: '1194',
      state: 'connected'
    })
  })

  it('reads the RECONNECTING reason out of field 3', () => {
    for (const reason of ['tls-error', 'ping-restart', 'auth-failure']) {
      const ev = parseManagementLine(`>STATE:1756000005,RECONNECTING,${reason},,,,,`)
      expect(ev).toMatchObject({ type: 'state', state: 'reconnecting', description: reason })
    }
  })

  it('separates a plain password request from a static challenge', () => {
    expect(parseManagementLine(">PASSWORD:Need 'Auth' username/password")).toMatchObject({
      realm: 'Auth',
      failed: false,
      needsUsername: true,
      challenge: null
    })
    expect(parseManagementLine(">PASSWORD:Need 'Auth' username/password SC:1,Enter your 6-digit code")).toMatchObject({
      realm: 'Auth',
      needsUsername: true,
      challenge: { echo: true, text: 'Enter your 6-digit code' }
    })
    expect(parseManagementLine(">PASSWORD:Need 'Auth' username/password SC:0,Response?")).toMatchObject({
      challenge: { echo: false, text: 'Response?' }
    })
    expect(parseManagementLine(">PASSWORD:Need 'Private Key' password")).toMatchObject({
      realm: 'Private Key',
      needsUsername: false,
      challenge: null
    })
    expect(parseManagementLine(">PASSWORD:Verification Failed: 'Auth'")).toMatchObject({
      realm: 'Auth',
      failed: true
    })
  })

  it('maps >FATAL: onto an error code', () => {
    expect(parseManagementLine('>FATAL:Cannot resolve host address: vpn.example.com')).toMatchObject({
      type: 'fatal',
      code: 'dns-failure'
    })
    expect(parseManagementLine('>FATAL:TLS key negotiation failed to occur within 60 seconds')).toMatchObject({
      code: 'tls-handshake-failed'
    })
    expect(parseManagementLine('>FATAL:Something nobody has a rule for')).toMatchObject({ code: 'internal' })
  })

  it('distinguishes an expired certificate from a wrong clock', () => {
    // E31 vs E32: telling a user with a skewed clock to ask for a new
    // certificate sends them to the wrong person.
    expect(parseManagementLine('>FATAL:VERIFY ERROR: certificate has expired')).toMatchObject({
      code: 'cert-expired'
    })
    expect(parseManagementLine('>FATAL:VERIFY ERROR: certificate is not yet valid')).toMatchObject({
      code: 'clock-skew'
    })
  })

  it('parses bytecount, log, need-ok and command replies', () => {
    expect(parseManagementLine('>BYTECOUNT:184320,92160')).toMatchObject({ rxBytes: 184320, txBytes: 92160 })
    expect(parseManagementLine('>LOG:1756000000,I,Initialization Sequence Completed')).toMatchObject({
      type: 'log',
      flags: 'I',
      text: 'Initialization Sequence Completed'
    })
    expect(parseManagementLine('>NEED-OK:token-insertion-request:Please insert your token')).toMatchObject({
      type: 'need-ok',
      needType: 'token-insertion-request',
      text: 'Please insert your token'
    })
    expect(parseManagementLine('SUCCESS: hold release succeeded')).toMatchObject({ type: 'reply', ok: true })
    expect(parseManagementLine('ERROR: unknown command')).toMatchObject({ type: 'reply', ok: false })
    expect(parseManagementLine('something else entirely')).toMatchObject({ type: 'other' })
  })
})

// ----------------------------------------------------------------- escaping

describe('management value escaping', () => {
  it('backslash-escapes quotes and backslashes', () => {
    expect(escapeManagementValue('plain')).toBe('plain')
    expect(escapeManagementValue('he said "hi"')).toBe('he said \\"hi\\"')
    expect(escapeManagementValue('back\\slash')).toBe('back\\\\slash')
    expect(escapeManagementValue('both "\\"')).toBe('both \\"\\\\\\"')
  })

  it('quotes the escaped value', () => {
    expect(quoteManagementValue('a"b')).toBe('"a\\"b"')
  })

  it('refuses a value carrying a line break, which quoting cannot contain', () => {
    // `password "Auth" "x\nsignal SIGTERM"` would be two commands, not one.
    expect(() => escapeManagementValue('x\nsignal SIGTERM')).toThrowError(/line break/)
    expect(() => escapeManagementValue('x\rsignal SIGTERM')).toThrowError(/line break/)
    expect(() => escapeManagementValue('x\0y')).toThrowError(/line break/)
  })
})

// ------------------------------------------------------------------ harness

interface Harness {
  mgmt: OpenVpnManagement
  patches: Partial<VpnStatus>[]
  logs: string[]
  events: OpenVpnEvent[]
  prompts: Omit<VpnPrompt, 'id' | 'profileId' | 'profileName'>[]
  stdout(): string
  child: ChildProcessWithoutNullStreams | null
}

const openDirs: string[] = []
const openMgmt: OpenVpnManagement[] = []
const openChildren: ChildProcessWithoutNullStreams[] = []
const openSockets: net.Socket[] = []

afterEach(() => {
  for (const c of openChildren.splice(0)) c.kill('SIGKILL')
  for (const s of openSockets.splice(0)) s.destroy()
  for (const m of openMgmt.splice(0)) m.close()
  for (const d of openDirs.splice(0)) rmSync(d, { recursive: true, force: true })
})

function makeRunDir(): string {
  const dir = mkdtempSync(`${tmpdir()}/ovpn-`)
  openDirs.push(dir)
  return dir
}

function makeManagement(opts: {
  credentials?: OpenVpnCredentials
  answer?: (p: Omit<VpnPrompt, 'id' | 'profileId' | 'profileName'>) => string | null
  platform?: NodeJS.Platform
  maxLineBytes?: number
}): Harness {
  const patches: Partial<VpnStatus>[] = []
  const logs: string[] = []
  const events: OpenVpnEvent[] = []
  const prompts: Omit<VpnPrompt, 'id' | 'profileId' | 'profileName'>[] = []
  const harness: Harness = {
    mgmt: new OpenVpnManagement(
      {
        emit: (p) => patches.push(p),
        log: (l) => logs.push(l),
        askUser: async (p) => {
          prompts.push(p)
          return opts.answer ? opts.answer(p) : null
        },
        credentials: () => opts.credentials ?? {},
        onEvent: (e) => events.push(e)
      },
      { runDir: makeRunDir(), platform: opts.platform, maxLineBytes: opts.maxLineBytes }
    ),
    patches,
    logs,
    events,
    prompts,
    stdout: () => '',
    child: null
  }
  openMgmt.push(harness.mgmt)
  return harness
}

/** Bind the endpoint, then run the fake binary against it exactly the way the
 *  driver will. */
async function runFake(h: Harness, extra: string[], config?: string): Promise<void> {
  const endpoint = await h.mgmt.listen()
  const args = [
    FAKE,
    ...endpoint.args,
    '--management-client',
    '--management-hold',
    '--script-security',
    '0',
    '--auth-nocache',
    '--verb',
    '3',
    ...extra
  ]
  if (config !== undefined) args.push('--config', '/dev/stdin')
  const child = spawn(process.execPath, args, { stdio: ['pipe', 'pipe', 'pipe'] })
  openChildren.push(child)
  h.child = child
  let out = ''
  child.stdout.setEncoding('utf8')
  child.stdout.on('data', (c: string) => (out += c))
  child.stderr.setEncoding('utf8')
  child.stderr.on('data', (c: string) => (out += c))
  h.stdout = () => out
  if (config !== undefined) {
    child.stdin.write(config)
    child.stdin.end()
  }
}

async function waitFor(check: () => boolean, what: string, ms = 8000): Promise<void> {
  const deadline = Date.now() + ms
  while (!check()) {
    if (Date.now() > deadline) throw new Error(`timed out waiting for ${what}`)
    await new Promise((r) => setTimeout(r, 10))
  }
}

const states = (h: Harness): (string | undefined)[] => h.patches.map((p) => p.state)
const lastWith = (h: Harness, key: keyof VpnStatus): Partial<VpnStatus> | undefined =>
  [...h.patches].reverse().find((p) => p[key] !== undefined)

// --------------------------------------------------------------- lifecycle

describe('OpenVpnManagement against the fake binary', () => {
  it('walks the full ladder to connected and reports the assigned addresses', async () => {
    const h = makeManagement({})
    await runFake(h, ['--tick-ms', '30'])
    await h.mgmt.whenConnected(8000)
    await waitFor(() => states(h).includes('connected'), 'connected')

    // The handshake goes out in the order the plan gives.
    const sent = h.logs.filter((l) => l.startsWith('> '))
    expect(sent.slice(0, 4)).toEqual(['> state on', '> bytecount 5', '> log on all', '> hold release'])

    expect(states(h)).toContain('starting')
    const connected = lastWith(h, 'state')
    expect(connected?.state).toBe('connected')
    expect(connected?.stats).toMatchObject({ assignedIp: '10.8.0.6', remoteEndpoint: '203.0.113.1:1194' })
  })

  it('counts bytes from >BYTECOUNT:', async () => {
    const h = makeManagement({})
    await runFake(h, ['--tick-ms', '20'])
    await waitFor(() => (h.mgmt.stats()?.rxBytes ?? 0) >= 368640, 'two bytecount ticks')
    const stats = h.mgmt.stats()
    expect(stats).toMatchObject({ rxBytes: 368640, txBytes: 184320, assignedIp: '10.8.0.6' })
    expect(stats?.sampledAt).toBeGreaterThan(0)
  })

  it('reports the config it was actually handed, read from stdin', async () => {
    const h = makeManagement({})
    const body = 'client\ndev tun\nremote vpn.example.com 1194 udp\n'
    await runFake(h, ['--tick-ms', '50'], body)
    await waitFor(() => states(h).includes('connected'), 'connected')
    const { createHash } = await import('node:crypto')
    const sha = createHash('sha256').update(body).digest('hex')
    expect(h.stdout()).toContain(`CONFIG_SHA256=${sha} CONFIG_BYTES=${Buffer.byteLength(body)}`)
  })

  it('maps >FATAL: onto a code and an error state', async () => {
    const h = makeManagement({})
    await runFake(h, ['--fail', 'fatal-dns'])
    await waitFor(() => states(h).includes('error'), 'the fatal error')
    expect(lastWith(h, 'errorCode')?.errorCode).toBe('dns-failure')
    expect(h.mgmt.lastErrorCode()).toBe('dns-failure')
  })
})

// -------------------------------------------------------------------- auth

describe('OpenVpnManagement credentials', () => {
  it('answers a plain username/password request', async () => {
    const h = makeManagement({ credentials: { username: 'alice', password: 's3cr3t' } })
    await runFake(h, ['--management-query-passwords', '--tick-ms', '50'])
    await waitFor(() => states(h).includes('connected'), 'connected')

    expect(states(h)).toContain('authenticating')
    expect(h.stdout()).toContain('RECV username "Auth" alice')
    expect(h.stdout()).toContain('AUTHPASS s3cr3t')
    // The password never reaches the log in the clear.
    expect(h.logs.join('\n')).toContain('> password "Auth" "***"')
    expect(h.logs.join('\n')).not.toContain('s3cr3t')
  })

  it('escapes a password containing quotes and backslashes end to end', async () => {
    const nasty = 'he said "hi" \\ bye'
    const h = makeManagement({ credentials: { username: 'alice', password: nasty } })
    await runFake(h, ['--management-query-passwords', '--tick-ms', '50'])
    await waitFor(() => h.stdout().includes('AUTHPASS'), 'the password')

    // On the wire it is escaped …
    expect(h.stdout()).toContain('RECV password "Auth" "he said \\"hi\\" \\\\ bye"')
    // … and openvpn's own tokenizer gets the original back, unsplit.
    expect(h.stdout()).toContain(`AUTHPASS ${nasty}\n`)
    await waitFor(() => states(h).includes('connected'), 'connected')
  })

  it('quotes a username that is not plainly safe', async () => {
    const h = makeManagement({ credentials: { username: 'ali ce"', password: 'p' } })
    await runFake(h, ['--management-query-passwords', '--tick-ms', '50'])
    await waitFor(() => h.stdout().includes('AUTHPASS'), 'the password')
    expect(h.stdout()).toContain('RECV username "Auth" "ali ce\\""')
  })

  it('answers a static challenge with the SCRV1 encoding and never caches it', async () => {
    const h = makeManagement({
      credentials: { username: 'alice', password: 's3cr3t' },
      answer: (p) => (p.kind === 'otp' ? '123456' : null)
    })
    await runFake(h, ['--fail', 'otp', '--management-query-passwords', '--tick-ms', '50'])
    await waitFor(() => states(h).includes('connected'), 'connected')

    expect(h.prompts).toHaveLength(1)
    expect(h.prompts[0]).toEqual({
      kind: 'otp',
      // The engine's own wording, verbatim.
      label: "Need 'Auth' username/password SC:1,Enter your 6-digit code",
      echo: true
    })
    expect(h.stdout()).toContain(`AUTHPASS SCRV1:${b64('s3cr3t')}:${b64('123456')}`)
  })

  it('asks for a private key passphrase and sends it under the Private Key realm', async () => {
    const h = makeManagement({ answer: (p) => (p.kind === 'passphrase' ? 'pk-pass' : null) })
    await runFake(h, ['--fail', 'keypass', '--tick-ms', '50'])
    await waitFor(() => states(h).includes('connected'), 'connected')

    expect(h.prompts[0]).toEqual({ kind: 'passphrase', label: "Need 'Private Key' password", echo: false })
    expect(h.stdout()).toContain('RECV password "Private Key" "pk-pass"')
    expect(h.stdout()).toContain('KEYPASS pk-pass')
  })

  it('takes a stored passphrase without prompting', async () => {
    const h = makeManagement({ credentials: { keyPassphrase: 'stored' } })
    await runFake(h, ['--fail', 'keypass', '--tick-ms', '50'])
    await waitFor(() => states(h).includes('connected'), 'connected')
    expect(h.prompts).toHaveLength(0)
    expect(h.stdout()).toContain('KEYPASS stored')
  })

  it('fails on Verification Failed and never retries the same credentials (E28)', async () => {
    const h = makeManagement({ credentials: { username: 'alice', password: 'wrong' } })
    await runFake(h, ['--fail', 'auth', '--management-query-passwords'])
    await waitFor(() => lastWith(h, 'errorCode')?.errorCode === 'auth-failed', 'the auth failure')

    // The engine exits after the SIGTERM, so `stopped` follows; the error
    // itself must have been reported before that.
    expect(h.patches.find((p) => p.errorCode === 'auth-failed')?.state).toBe('error')
    expect(h.mgmt.lastErrorCode()).toBe('auth-failed')
    expect(h.stdout()).toContain('RECV signal SIGTERM')

    // The fake re-asks after refusing. Give it room to be answered, then check
    // that it was not: a retry storm is what locks the account.
    await new Promise((r) => setTimeout(r, 250))
    const attempts = h.stdout().split('\n').filter((l) => l.startsWith('AUTHPASS'))
    expect(attempts).toHaveLength(1)
    expect(h.logs.join('\n')).toContain('already refused')
  })

  it('treats a RECONNECTING,auth-failure as a rejection rather than a retry loop', () => {
    const h = makeManagement({})
    // Drive the parser branch directly: openvpn reaches this state without a
    // >PASSWORD: line when it is retrying cached credentials.
    const ev = parseManagementLine('>STATE:1,RECONNECTING,auth-failure,,,,,')
    expect(ev).toMatchObject({ state: 'reconnecting', description: 'auth-failure' })
    expect(h.mgmt.lastErrorCode()).toBeNull()
  })

  it('stops cleanly with auth-otp-required when the user cancels the code prompt', async () => {
    const h = makeManagement({
      credentials: { username: 'alice', password: 's3cr3t' },
      answer: () => null
    })
    await runFake(h, ['--fail', 'otp', '--management-query-passwords'])
    await waitFor(() => lastWith(h, 'errorCode')?.errorCode === 'auth-otp-required', 'the cancellation')

    expect(lastWith(h, 'state')?.state).toBe('stopped')
    await waitFor(() => h.stdout().includes('RECV signal SIGTERM'), 'the SIGTERM')
    expect(h.stdout()).not.toContain('AUTHPASS')
  })

  it('re-prompts on reconnect without treating it as an error (E30)', async () => {
    let asked = 0
    const h = makeManagement({
      credentials: { username: 'alice' },
      answer: (p) => {
        if (p.kind !== 'password') return null
        asked++
        return 's3cr3t'
      }
    })
    await runFake(h, ['--fail', 'drop-after', '1', '--management-query-passwords', '--tick-ms', '30'])

    await waitFor(() => states(h).includes('connected'), 'the first connect')
    const firstConnect = states(h).lastIndexOf('connected')
    await waitFor(() => states(h).indexOf('reconnecting') > firstConnect, 'the drop')
    await waitFor(() => states(h).lastIndexOf('connected') > firstConnect, 'the reconnect')

    // Asked twice, because --auth-nocache means openvpn kept nothing.
    expect(asked).toBe(2)
    // Nothing about that sequence is an error.
    expect(states(h)).not.toContain('error')
    expect(h.patches.some((p) => p.errorCode !== undefined)).toBe(false)
    const order = states(h).filter((s) => s !== undefined)
    expect(order.indexOf('reconnecting')).toBeLessThan(order.lastIndexOf('authenticating'))
  })
})

// ------------------------------------------------------------------ signals

describe('OpenVpnManagement signals', () => {
  it('sends SIGUSR1 as a soft restart and comes back up (E20/E21)', async () => {
    const h = makeManagement({})
    await runFake(h, ['--tick-ms', '40'])
    await waitFor(() => states(h).includes('connected'), 'connected')
    const before = states(h).lastIndexOf('connected')

    h.mgmt.softRestart()
    await waitFor(() => h.stdout().includes('RECV signal SIGUSR1'), 'the signal')
    await waitFor(() => states(h).lastIndexOf('connected') > before, 'the reconnect')
    expect(states(h)).toContain('reconnecting')
  })

  it('sends SIGTERM on request', async () => {
    const h = makeManagement({})
    await runFake(h, ['--tick-ms', '40'])
    await waitFor(() => states(h).includes('connected'), 'connected')
    h.mgmt.sigterm()
    await waitFor(() => h.stdout().includes('RECV signal SIGTERM'), 'the signal')
  })

  it('refuses to smuggle a second command inside one', async () => {
    const h = makeManagement({})
    await runFake(h, ['--tick-ms', '40'])
    await h.mgmt.whenConnected(8000)
    expect(() => h.mgmt.send('status\nsignal SIGTERM')).toThrowError(/line break/)
  })
})

// ------------------------------------------------------------ wire hygiene

describe('OpenVpnManagement transport', () => {
  it('rejects a line longer than 64 KiB instead of buffering it', async () => {
    const h = makeManagement({})
    const endpoint = await h.mgmt.listen()
    expect(endpoint.socketPath).toBeTruthy()

    const peer = net.connect(endpoint.socketPath as string)
    openSockets.push(peer)
    let closed = false
    peer.on('close', () => (closed = true))
    peer.on('error', () => undefined)
    // A paused socket never reads, so it never sees the FIN either.
    peer.resume()
    await new Promise<void>((r) => peer.once('connect', () => r()))
    // No newline anywhere: a real management peer cannot produce this.
    peer.write('x'.repeat(MANAGEMENT_MAX_LINE_BYTES + 1))

    await waitFor(() => states(h).includes('error'), 'the protocol violation')
    expect(lastWith(h, 'error')?.error).toMatch(/no line ending/)
    await waitFor(() => closed, 'the socket teardown')
  })

  it('removes the socket and its 0700 directory on close', async () => {
    const h = makeManagement({})
    const endpoint = await h.mgmt.listen()
    const { existsSync, statSync } = await import('node:fs')
    expect(existsSync(endpoint.socketPath as string)).toBe(true)
    if (process.platform !== 'win32') {
      const dir = endpoint.socketPath!.replace(/\/[^/]+$/, '')
      expect(statSync(dir).mode & 0o777).toBe(0o700)
    }
    h.mgmt.close()
    expect(existsSync(endpoint.socketPath as string)).toBe(false)
  })

  it('declines a >NEED-OK: confirmation it has no way to show', async () => {
    const h = makeManagement({})
    const endpoint = await h.mgmt.listen()
    const peer = net.connect(endpoint.socketPath as string)
    openSockets.push(peer)
    let seen = ''
    peer.setEncoding('utf8')
    peer.on('data', (c: string) => (seen += c))
    await new Promise<void>((r) => peer.once('connect', () => r()))
    peer.write('>NEED-OK:token-insertion-request:Please insert your token\n')
    await waitFor(() => seen.includes('needok'), 'the reply')
    expect(seen).toContain('needok token-insertion-request cancel')
  })
})

// ------------------------------------------------------------------- win32

describe('OpenVpnManagement on Windows', () => {
  const real = process.platform

  function stubPlatform(value: NodeJS.Platform): void {
    Object.defineProperty(process, 'platform', { value, configurable: true })
  }

  afterEach(() => {
    Object.defineProperty(process, 'platform', { value: real, configurable: true })
  })

  it('binds 127.0.0.1:0 and hands openvpn the port', async () => {
    stubPlatform('win32')
    const h = makeManagement({})
    const endpoint = await h.mgmt.listen()
    expect(endpoint.socketPath).toBeUndefined()
    expect(endpoint.port).toBeGreaterThan(0)
    expect(endpoint.args).toEqual(['--management', '127.0.0.1', String(endpoint.port)])
  })

  it('refuses a peer that does not open with the OpenVPN greeting', async () => {
    stubPlatform('win32')
    const h = makeManagement({})
    const endpoint = await h.mgmt.listen()

    const peer = net.connect(endpoint.port as number, '127.0.0.1')
    openSockets.push(peer)
    let seen = ''
    peer.setEncoding('utf8')
    peer.on('data', (c: string) => (seen += c))
    await new Promise<void>((r) => peer.once('connect', () => r()))
    peer.write('hello, I am definitely openvpn\n')

    await waitFor(() => states(h).includes('error'), 'the refusal')
    expect(lastWith(h, 'error')?.error).toMatch(/greeting/)
    // Nothing was sent to an unidentified peer.
    expect(seen).toBe('')
    await expect(h.mgmt.whenConnected(200)).rejects.toThrow()
  })

  it('trusts a peer that opens with the greeting, then handshakes', async () => {
    stubPlatform('win32')
    const h = makeManagement({})
    const endpoint = await h.mgmt.listen()

    const peer = net.connect(endpoint.port as number, '127.0.0.1')
    openSockets.push(peer)
    let seen = ''
    peer.setEncoding('utf8')
    peer.on('data', (c: string) => (seen += c))
    await new Promise<void>((r) => peer.once('connect', () => r()))
    peer.write(">INFO:OpenVPN Management Interface Version 5 -- type 'help' for more info\n")

    await h.mgmt.whenConnected(4000)
    await waitFor(() => seen.includes('hold release'), 'the handshake')
    expect(seen.trim().split('\n')).toEqual(['state on', 'bytecount 5', 'log on all', 'hold release'])
  })

  it('runs the whole lifecycle over TCP, the way it will on Windows', async () => {
    const h = makeManagement({ platform: 'win32', credentials: { username: 'alice', password: 's3cr3t' } })
    await runFake(h, ['--management-query-passwords', '--tick-ms', '30'])
    await h.mgmt.whenConnected(8000)
    await waitFor(() => states(h).includes('connected'), 'connected')
    expect(h.mgmt.port).toBeGreaterThan(0)
    expect(lastWith(h, 'state')?.stats).toMatchObject({ assignedIp: '10.8.0.6' })
  })

  it('stops listening once the first peer is accepted, so nothing else can race in', async () => {
    stubPlatform('win32')
    const h = makeManagement({})
    const endpoint = await h.mgmt.listen()
    const port = endpoint.port as number

    const first = net.connect(port, '127.0.0.1')
    openSockets.push(first)
    await new Promise<void>((r) => first.once('connect', () => r()))
    await waitFor(() => true, 'accept', 200)
    await new Promise((r) => setTimeout(r, 50))

    const second = net.connect(port, '127.0.0.1')
    openSockets.push(second)
    await expect(
      new Promise<void>((resolve, reject) => {
        second.once('connect', () => reject(new Error('a second peer was accepted')))
        second.once('error', () => resolve())
      })
    ).resolves.toBeUndefined()
  })
})

// --------------------------------------------------------- the fake binary

describe('fake-openvpn', () => {
  it('prints a realistic version banner', async () => {
    const out = await new Promise<string>((resolve) => {
      const child = spawn(process.execPath, [FAKE, '--version'], { stdio: ['ignore', 'pipe', 'ignore'] })
      let s = ''
      child.stdout.setEncoding('utf8')
      child.stdout.on('data', (c: string) => (s += c))
      child.on('close', () => resolve(s))
    })
    expect(out).toMatch(/^OpenVPN 2\.6\.\d+ /)
    expect(out).toContain('library versions:')
  })

  it('exits 1 immediately with --fail crash', async () => {
    const code = await new Promise<number | null>((resolve) => {
      const child = spawn(process.execPath, [FAKE, '--fail', 'crash', '--management', '/nope.sock', 'unix'], {
        stdio: 'ignore'
      })
      child.on('close', (c) => resolve(c))
    })
    expect(code).toBe(1)
  })

  it('never becomes ready with --fail wedge', async () => {
    const h = makeManagement({})
    await runFake(h, ['--fail', 'wedge'])
    await h.mgmt.whenConnected(4000)
    await new Promise((r) => setTimeout(r, 300))
    expect(states(h)).toContain('starting')
    expect(states(h)).not.toContain('connected')
  })
})
