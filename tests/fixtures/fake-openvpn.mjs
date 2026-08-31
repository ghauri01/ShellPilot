#!/usr/bin/env node
// A stand-in for the openvpn binary, good enough that the whole OpenVPN
// lifecycle runs in CI without a real VPN, a TUN device or root.
//
// It speaks the management protocol the way openvpn does with
// --management-client: it DIALS the endpoint ShellPilot is already listening
// on, greets, honours --management-hold, walks the >STATE: ladder and emits
// >BYTECOUNT: on a timer. Failure modes are selected from argv so a test can
// ask for the exact thing it wants to assert about.
//
// Plain Node, cross-platform, no dependencies.
//
// argv:
//   --management <path> unix        connect to a unix socket
//   --management <host> <port>      connect to TCP (the Windows shape)
//   --management-client             accepted; this fake always dials
//   --management-hold               wait for `hold release` before starting
//   --management-query-passwords    ask for credentials over the channel
//   --config <path|/dev/stdin>      read the config, report its sha256
//   --tick-ms <n>                   >BYTECOUNT: interval (default: the
//                                   `bytecount N` seconds the client asked
//                                   for, else 1000)
//   --step-ms <n>                   delay between >STATE: steps (default 5)
//   --version                       print a banner and exit 0
//   --fail auth                     >PASSWORD:Verification Failed: 'Auth'
//   --fail otp                      the Auth prompt carries SC:1,<challenge>
//   --fail keypass                  ask for the private key passphrase first
//   --fail fatal-dns                >FATAL:Cannot resolve host address: ...
//   --fail drop-after <n>           RECONNECTING after n >BYTECOUNT: ticks
//   --fail crash                    exit 1 immediately, before connecting
//   --fail wedge                    stop at CONNECTING and never become ready
//   --fail slow <ms>                use <ms> as the per-step delay
//
// Everything it receives on the management channel is echoed to stdout as
// `RECV <line>` so a test can assert what was actually sent — including that a
// refused password was never sent twice. Credentials only ever reach this
// fake's stdout, never a real server.

import net from 'node:net'
import fs from 'node:fs'
import { createHash } from 'node:crypto'

const VERSION_BANNER = [
  'OpenVPN 2.6.12 x86_64-pc-linux-gnu [SSL (OpenSSL)] [LZO] [LZ4] [EPOLL] [PKCS11] [MH/PKTINFO] [AEAD] [DCO] built on Jul 17 2024',
  'library versions: OpenSSL 3.0.13 30 Jan 2024, LZO 2.10',
  'Originally developed by James Yonan',
  'Copyright (C) 2002-2024 OpenVPN Inc <sales@openvpn.net>'
].join('\n')

// ------------------------------------------------------------------- argv

function parseArgv(argv) {
  const opt = {
    socketPath: null,
    host: null,
    port: null,
    client: false,
    hold: false,
    queryPasswords: false,
    configPath: null,
    tickMs: null,
    stepMs: 5,
    fail: null,
    failArg: null,
    version: false
  }
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i]
    switch (a) {
      case '--version':
        opt.version = true
        break
      case '--management-client':
        opt.client = true
        break
      case '--management-hold':
        opt.hold = true
        break
      case '--management-query-passwords':
        opt.queryPasswords = true
        break
      case '--config':
        opt.configPath = argv[++i]
        break
      case '--tick-ms':
        opt.tickMs = Number(argv[++i])
        break
      case '--step-ms':
        opt.stepMs = Number(argv[++i])
        break
      case '--management': {
        const first = argv[++i]
        const second = argv[i + 1]
        if (second === 'unix') {
          opt.socketPath = first
          i++
        } else if (second !== undefined && /^\d+$/.test(second)) {
          opt.host = first
          opt.port = Number(second)
          i++
        } else {
          opt.socketPath = first
        }
        break
      }
      case '--fail': {
        opt.fail = argv[++i]
        const next = argv[i + 1]
        if (next !== undefined && !next.startsWith('--')) {
          opt.failArg = next
          i++
        }
        break
      }
      default:
        // Everything else (--verb, --auth-nocache, --pull-filter, …) is
        // accepted and ignored, the way an unrecognised-but-harmless flag
        // would be. A test asserting on argv reads the real argv, not this.
        break
    }
  }
  if (opt.fail === 'slow' && opt.failArg) opt.stepMs = Number(opt.failArg)
  return opt
}

const opt = parseArgv(process.argv.slice(2))

if (opt.version) {
  process.stdout.write(`${VERSION_BANNER}\n`)
  process.exit(0)
}

// E04/E55 material: a binary that dies before it ever opens the channel.
if (opt.fail === 'crash') {
  process.stderr.write('Options error: unable to start\n')
  process.exit(1)
}

// ----------------------------------------------------------------- config

// Read before connecting: with --config /dev/stdin the parent writes the body
// and closes, and reporting its checksum is how a test proves what was
// actually handed over rather than what it meant to hand over.
function readConfig(path) {
  if (!path) return null
  try {
    const body = path === '/dev/stdin' || path === '-' ? fs.readFileSync(0, 'utf8') : fs.readFileSync(path, 'utf8')
    return { bytes: Buffer.byteLength(body), sha256: createHash('sha256').update(body).digest('hex') }
  } catch (err) {
    process.stderr.write(`Options error: cannot read config ${path}: ${err.message}\n`)
    process.exit(1)
  }
}

const config = readConfig(opt.configPath)
if (config) {
  process.stdout.write(`CONFIG_SHA256=${config.sha256} CONFIG_BYTES=${config.bytes}\n`)
}

// ------------------------------------------------------------------- wire

const socket = opt.socketPath ? net.connect(opt.socketPath) : net.connect(opt.port, opt.host ?? '127.0.0.1')

socket.on('error', (err) => {
  process.stderr.write(`management: ${err.message}\n`)
  process.exit(1)
})

let bytecountSeconds = 0
let ticks = 0
let tickTimer = null
let rx = 0
let tx = 0
let released = !opt.hold
let exiting = false

const now = () => Math.floor(Date.now() / 1000)
const send = (line) => {
  if (!socket.destroyed) socket.write(`${line}\n`)
}
const state = (name, description = '', local = '', remote = '', port = '') =>
  send(`>STATE:${now()},${name},${description},${local},${remote},${port},,`)

const sleep = (ms) => new Promise((r) => setTimeout(r, ms))

function exit(code) {
  if (exiting) return
  exiting = true
  if (tickTimer) clearInterval(tickTimer)
  state('EXITING', code === 0 ? 'SIGTERM' : 'error')
  setTimeout(() => {
    socket.end()
    process.exit(code)
  }, 5)
}

// ---------------------------------------------------------------- commands

// openvpn's own parser handles "quoted args" with backslash escapes, and a
// password containing a quote is the whole point of the escaping test, so this
// has to unescape the same way rather than splitting on spaces.
function tokenize(line) {
  const out = []
  let cur = ''
  let quoted = false
  let started = false
  for (let i = 0; i < line.length; i++) {
    const c = line[i]
    if (c === '\\' && i + 1 < line.length) {
      cur += line[++i]
      started = true
    } else if (c === '"') {
      quoted = !quoted
      started = true
    } else if (!quoted && /\s/.test(c)) {
      if (started) out.push(cur)
      cur = ''
      started = false
    } else {
      cur += c
      started = true
    }
  }
  if (started) out.push(cur)
  return out
}

const received = []

function onCommand(line) {
  received.push(line)
  // Every command, verbatim, so a test can assert on the exact wire bytes.
  process.stdout.write(`RECV ${line}\n`)
  const tok = tokenize(line)
  switch (tok[0]) {
    case 'state':
      send('SUCCESS: real-time state notification set to ON')
      return
    case 'bytecount':
      bytecountSeconds = Number(tok[1]) || 0
      send('SUCCESS: bytecount interval changed')
      return
    case 'log':
      send('SUCCESS: real-time log notification set to ON')
      return
    case 'hold':
      if (tok[1] === 'release') {
        send('SUCCESS: hold release succeeded')
        if (!released) {
          released = true
          void run()
        }
      } else {
        send('ERROR: unknown hold command')
      }
      return
    case 'username':
      send('SUCCESS: username entered, but not yet verified')
      return
    case 'password':
      send('SUCCESS: password entered, but not yet verified')
      onPassword(tok[1], tok[2])
      return
    case 'needok':
      send('SUCCESS: needok command succeeded')
      return
    case 'signal':
      send('SUCCESS: signal sent')
      if (tok[1] === 'SIGUSR1') {
        // Soft restart: the tunnel comes back without a new process (E20/E21).
        void softRestart()
      } else {
        exit(0)
      }
      return
    default:
      send(`ERROR: unknown command '${tok[0] ?? ''}', enter 'help' for more options`)
  }
}

// -------------------------------------------------------------------- auth

let authAttempts = 0

function askAuth() {
  authAttempts++
  const challenge = opt.fail === 'otp' ? ' SC:1,Enter your 6-digit code' : ''
  send(`>PASSWORD:Need 'Auth' username/password${challenge}`)
}

function askKeyPass() {
  send(">PASSWORD:Need 'Private Key' password")
}

function onPassword(realm, value) {
  if (realm === 'Private Key') {
    process.stdout.write(`KEYPASS ${value}\n`)
    if (opt.queryPasswords) askAuth()
    else void connectLadder()
    return
  }
  process.stdout.write(`AUTHPASS ${value}\n`)

  if (opt.fail === 'auth') {
    // The client must not answer the next prompt with the same credentials.
    send(">PASSWORD:Verification Failed: 'Auth'")
    send(`>STATE:${now()},RECONNECTING,auth-failure,,,,,`)
    // Real openvpn asks again straight away. The point of the test is that the
    // client stays quiet rather than feeding the retry storm (E28), so the
    // re-ask goes out in the same write as the refusal.
    askAuth()
    setTimeout(() => exit(0), 1500)
    return
  }
  if (opt.fail === 'otp' && !String(value).startsWith('SCRV1:')) {
    send(">PASSWORD:Verification Failed: 'Auth'")
    setTimeout(() => exit(0), 20)
    return
  }
  void connectLadder()
}

// ------------------------------------------------------------------ ladder

async function run() {
  await sleep(opt.stepMs)
  state('CONNECTING')

  if (opt.fail === 'wedge') return // never becomes ready (E54)

  await sleep(opt.stepMs)
  if (opt.fail === 'fatal-dns') {
    send('>FATAL:Cannot resolve host address: vpn.example.com:1194 (Name or service not known)')
    setTimeout(() => {
      socket.end()
      process.exit(1)
    }, 10)
    return
  }

  state('WAIT')
  await sleep(opt.stepMs)
  state('RESOLVE')
  await sleep(opt.stepMs)
  state('TCP_CONNECT')
  await sleep(opt.stepMs)
  state('AUTH')

  if (opt.fail === 'keypass') {
    askKeyPass()
    return
  }
  if (opt.queryPasswords) {
    askAuth()
    return
  }
  void connectLadder()
}

async function connectLadder() {
  await sleep(opt.stepMs)
  state('GET_CONFIG')
  await sleep(opt.stepMs)
  state('ASSIGN_IP', '', '10.8.0.6')
  await sleep(opt.stepMs)
  state('ADD_ROUTES')
  await sleep(opt.stepMs)
  send(`>STATE:${now()},CONNECTED,SUCCESS,10.8.0.6,203.0.113.1,1194,,`)
  send(`>LOG:${now()},I,Initialization Sequence Completed`)
  startBytecount()
}

function startBytecount() {
  if (tickTimer) clearInterval(tickTimer)
  const interval = opt.tickMs ?? (bytecountSeconds > 0 ? bytecountSeconds * 1000 : 1000)
  tickTimer = setInterval(() => {
    ticks++
    rx += 184320
    tx += 92160
    send(`>BYTECOUNT:${rx},${tx}`)
    if (opt.fail === 'drop-after' && ticks >= Number(opt.failArg ?? 2)) {
      clearInterval(tickTimer)
      tickTimer = null
      void drop()
    }
  }, interval)
}

// Mid-session drop. With --auth-nocache openvpn re-asks on the way back up,
// which is expected behaviour and not an error (E30).
async function drop() {
  send(`>STATE:${now()},RECONNECTING,ping-restart,,,,,`)
  await sleep(opt.stepMs)
  state('WAIT')
  await sleep(opt.stepMs)
  state('AUTH')
  if (opt.queryPasswords) askAuth()
  else void connectLadder()
}

async function softRestart() {
  if (tickTimer) clearInterval(tickTimer)
  tickTimer = null
  send(`>STATE:${now()},RECONNECTING,SIGUSR1,,,,,`)
  await sleep(opt.stepMs)
  state('WAIT')
  await sleep(opt.stepMs)
  state('AUTH')
  if (opt.queryPasswords) askAuth()
  else void connectLadder()
}

// ------------------------------------------------------------------- start

let buffer = ''

socket.on('connect', () => {
  send(">INFO:OpenVPN Management Interface Version 5 -- type 'help' for more info")
  if (config) send(`>LOG:${now()},I,CONFIG_SHA256=${config.sha256} CONFIG_BYTES=${config.bytes}`)
  if (opt.hold) {
    send('>HOLD:Waiting for hold release')
  } else {
    void run()
  }
})

socket.on('data', (chunk) => {
  buffer += chunk.toString('utf8')
  for (;;) {
    const i = buffer.indexOf('\n')
    if (i === -1) return
    const line = buffer.slice(0, i).replace(/\r$/, '')
    buffer = buffer.slice(i + 1)
    if (line.length > 0) onCommand(line)
  }
})

socket.on('close', () => {
  if (!exiting) process.exit(0)
})

// Never outlive the test that started it.
const guard = setTimeout(() => process.exit(0), 30000)
guard.unref()

// A tally on the way out, for a test that would rather count than scan. Off by
// default so it cannot be mistaken for management output.
process.on('exit', () => {
  if (process.env.FAKE_OPENVPN_SUMMARY === '1') {
    process.stdout.write(`SUMMARY commands=${received.length} authPrompts=${authAttempts}\n`)
  }
})
