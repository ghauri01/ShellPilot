#!/usr/bin/env node
// A stand-in for frpc 0.71.0, good enough to exercise everything the real one
// is used for: it reads the generated TOML, expands `{{ .Envs.X }}` from its
// own environment exactly as frp's Go templating does, serves the admin API
// with HTTP Basic on 127.0.0.1, and logs in frpc's format so the supervisor's
// log-capture path is exercised rather than mocked.
//
// The behaviours below were checked against the real binary rather than the
// docs, and each one has a test that would pass against a laxer fake:
//   * `/healthz` takes no credentials; every `/api/*` route returns 401.
//   * `/api/status` answers `200 {}` until the client has logged in to frps,
//     and `/api/proxy/<name>/config` answers 404 over the same window.
//   * `/api/config` returns the config text with `{{ .Envs.X }}` unexpanded.
//   * Log lines go to STDOUT — warnings and errors included — wrapped in ANSI
//     colour, with the reset sequence at the start of the *next* line.
//
// Plain Node, no dependencies, no platform-specific calls.
//
//   fake-frpc.mjs -c <config.toml> [--fail <mode>]
//   fake-frpc.mjs -v | --version
//
// Failure modes, all scriptable from a test:
//   --fail auth              login fails with frps's authentication wording
//   --fail proxy-port        first proxy sits in `start error: port already used`
//   --fail version           login fails with a version-skew message
//   --fail wedge             /healthz never goes green, no proxy ever runs
//   --fail crash-after <ms>  serves normally, then exits 1 after <ms>

import http from 'node:http'
import { readFileSync, writeSync } from 'node:fs'

// ------------------------------------------------------------------ output
//
// Every line this fixture emits goes out with a *synchronous* write, and that
// is load-bearing rather than stylistic.
//
// `process.stdout.write` to a pipe — which is always the case here, because the
// supervisor captures it — is asynchronous. `process.exit()` discards whatever
// is still buffered, and so does the default action for a signal. This fixture
// writes a line and then exits in three places: the `--version` path, the
// `/api/stop` handler (ten milliseconds later), and the shutdown handler. Two
// of those three have tests asserting on the line written immediately before
// the exit, so the assertion is racing the flush and winning only because the
// gap is usually enough.
//
// This is not hypothetical. The same shape in `fake-openvpn.mjs` produced an
// intermittent failure that cost two agents most of a day to diagnose, and the
// obvious fix — a longer timeout — could not have worked, because the line is
// destroyed rather than delayed.
//
// A synchronous write cannot be lost: it has reached the pipe before the call
// returns. The cost is that a full pipe blocks this process, which for a
// fixture emitting a few dozen short lines is exactly the trade we want.
// EAGAIN is retried because a non-blocking pipe can refuse a write that would
// otherwise have succeeded.
function writeFd(fd, text) {
  const buf = Buffer.from(text, 'utf8')
  let off = 0
  while (off < buf.length) {
    try {
      off += writeSync(fd, buf, off, buf.length - off)
    } catch (err) {
      if (err.code === 'EAGAIN') continue
      if (err.code === 'EPIPE') return
      throw err
    }
  }
}
const out = (text) => writeFd(1, text)
const err = (text) => writeFd(2, text)

const VERSION = '0.71.0'

// ------------------------------------------------------------------ argv

function parseArgv(argv) {
  const out = { config: null, fail: null, crashAfterMs: 0, version: false }
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i]
    if (a === '-v' || a === '--version') out.version = true
    else if (a === '-c' || a === '--config') out.config = argv[++i] ?? null
    else if (a === '--fail') {
      out.fail = argv[++i] ?? null
      if (out.fail === 'crash-after') out.crashAfterMs = Number(argv[++i] ?? 0)
    }
  }
  return out
}

const args = parseArgv(process.argv.slice(2))

if (args.version) {
  // The real binary prints the bare version and nothing else.
  out(`${VERSION}\n`)
  process.exit(0)
}

// ------------------------------------------------------------------- log

const pad = (n, w = 2) => String(n).padStart(w, '0')

function stamp() {
  const d = new Date()
  return (
    `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ` +
    `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}.${pad(d.getMilliseconds(), 3)}`
  )
}

const RUN_ID = 'f4ke00000000c0de'

// frpc colours each line and emits the reset *after* the newline, so every
// line after the first arrives prefixed with an escape sequence. Reproduced
// exactly, because the client has to strip it before matching anything.
const COLOUR = { I: '\u001b[1;34m', W: '\u001b[1;33m', E: '\u001b[1;31m' }
const RESET = '\u001b[0m'
let firstLine = true

function log(level, where, message) {
  const prefix = firstLine ? '' : RESET
  firstLine = false
  out(`${prefix}${COLOUR[level]}${stamp()} [${level}] [${where}] ${message}\n`)
}
const info = (where, message) => log('I', where, message)
const warn = (where, message) => log('W', where, message)
const errorLog = (where, message) => log('E', where, message)

// ------------------------------------------------------------------ toml

// A deliberately small TOML reader: enough for the config ShellPilot
// generates, and nothing more. Anything it does not understand is ignored,
// which is the right failure mode for a fixture.
const ENV_TEMPLATE = /\{\{\s*\.Envs\.([A-Za-z_][A-Za-z0-9_]*)\s*\}\}/g

function expandEnv(text) {
  return text.replace(ENV_TEMPLATE, (_m, name) => process.env[name] ?? '')
}

function parseValue(raw) {
  const t = raw.trim()
  if (t.startsWith('"') && t.endsWith('"') && t.length >= 2) {
    return expandEnv(t.slice(1, -1))
  }
  if (t === 'true') return true
  if (t === 'false') return false
  if (t.startsWith('[') && t.endsWith(']')) {
    const inner = t.slice(1, -1).trim()
    if (!inner) return []
    return inner.split(',').map((p) => parseValue(p))
  }
  const n = Number(t)
  return Number.isNaN(n) ? t : n
}

function parseToml(text) {
  const root = {}
  const proxies = []
  const visitors = []
  let target = root

  const setDotted = (obj, key, value) => {
    const parts = key.split('.')
    let cur = obj
    for (let i = 0; i < parts.length - 1; i++) {
      if (typeof cur[parts[i]] !== 'object' || cur[parts[i]] === null) cur[parts[i]] = {}
      cur = cur[parts[i]]
    }
    cur[parts[parts.length - 1]] = value
  }

  for (const rawLine of text.split(/\r?\n/)) {
    const line = rawLine.trim()
    if (!line || line.startsWith('#')) continue
    if (line === '[[proxies]]') {
      target = {}
      proxies.push(target)
      continue
    }
    if (line === '[[visitors]]') {
      target = {}
      visitors.push(target)
      continue
    }
    if (line === '[proxies.plugin]') {
      const owner = proxies[proxies.length - 1]
      owner.plugin = {}
      target = owner.plugin
      continue
    }
    if (line.startsWith('[')) {
      // Unknown table: send its keys somewhere harmless.
      target = {}
      continue
    }
    const eq = line.indexOf('=')
    if (eq === -1) continue
    setDotted(target, line.slice(0, eq).trim(), parseValue(line.slice(eq + 1)))
  }

  return { root, proxies, visitors }
}

// ------------------------------------------------------------- proxy state

const WAIT_START = 'wait start'
const RUNNING = 'running'
const START_ERROR = 'start error'

// How long the client takes to reach frps, and then how long a proxy sits in
// `wait start` before it comes up. Both non-zero so a readiness poll actually
// has something to poll for, and so the pre-login `{}` window is observable.
const LOGIN_DELAY_MS = 60
const START_DELAY_MS = 120

let state = null
// Before frpc has logged in to frps there is no proxy table at all: the real
// binary answers `200 {}`. Nothing about that response distinguishes it from a
// healthy client with no proxies, which is exactly why readiness has to count
// against the configured names.
let loggedIn = false

function makeProxyState(p, index) {
  const failThis = args.fail === 'proxy-port' && index === 0
  return {
    name: String(p.name ?? `proxy-${index}`),
    type: String(p.type ?? 'tcp'),
    status: WAIT_START,
    err: '',
    localAddr: `${p.localIP ?? '127.0.0.1'}:${p.localPort ?? 0}`,
    remoteAddr: p.remotePort ? `:${p.remotePort}` : '',
    plugin: p.plugin?.type ?? '',
    fail: failThis
  }
}

function startProxies() {
  for (const p of state.proxies) {
    if (p.status !== WAIT_START) continue
    if (args.fail === 'wedge') continue
    if (p.fail) {
      p.status = START_ERROR
      p.err = `port already used, remote port ${p.remoteAddr.replace(':', '')}`
      warn('client/control.go:168', `[${RUN_ID}] [${p.name}] start error: ${p.err}`)
    } else {
      p.status = RUNNING
      p.err = ''
      info('client/control.go:168', `[${RUN_ID}] [${p.name}] start proxy success`)
    }
  }
}

function loadConfig(text) {
  const parsed = parseToml(text)
  const web = parsed.root.webServer ?? {}
  return {
    text,
    admin: {
      addr: String(web.addr ?? '127.0.0.1'),
      port: Number(web.port ?? 0),
      user: String(web.user ?? ''),
      password: String(web.password ?? '')
    },
    serverAddr: String(parsed.root.serverAddr ?? ''),
    serverPort: Number(parsed.root.serverPort ?? 0),
    proxies: parsed.proxies.map(makeProxyState),
    visitors: parsed.visitors
  }
}

// -------------------------------------------------------------- admin API

function unauthorized(res) {
  res.writeHead(401, {
    'www-authenticate': 'Basic realm="frp"',
    'content-type': 'text/plain'
  })
  res.end('unauthorized\n')
}

function authorised(req) {
  const header = req.headers.authorization
  if (typeof header !== 'string' || !header.startsWith('Basic ')) return false
  const decoded = Buffer.from(header.slice(6), 'base64').toString('utf8')
  const i = decoded.indexOf(':')
  if (i === -1) return false
  return decoded.slice(0, i) === state.admin.user && decoded.slice(i + 1) === state.admin.password
}

function statusPayload() {
  if (!loggedIn) return '{}'
  const grouped = {}
  for (const p of state.proxies) {
    ;(grouped[p.type] ??= []).push({
      name: p.name,
      type: p.type,
      status: p.status,
      err: p.err,
      local_addr: p.localAddr,
      remote_addr: p.remoteAddr,
      plugin: p.plugin
    })
  }
  return JSON.stringify(grouped)
}

function json(res, code, body) {
  res.writeHead(code, { 'content-type': 'application/json' })
  res.end(body)
}

function readBody(req, limit = 4 * 1024 * 1024) {
  return new Promise((resolve, reject) => {
    const chunks = []
    let total = 0
    req.on('data', (c) => {
      total += c.length
      if (total > limit) {
        req.destroy()
        reject(new Error('body too large'))
        return
      }
      chunks.push(c)
    })
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')))
    req.on('error', reject)
  })
}

let pendingConfig = null

const server = http.createServer((req, res) => {
  const url = new URL(req.url ?? '/', 'http://127.0.0.1')
  const path = url.pathname

  if (path === '/healthz' && req.method === 'GET') {
    // /healthz is unauthenticated in frp too, and the wedge mode is exactly
    // the "process is up but never becomes healthy" case the supervisor's
    // readiness timeout exists for.
    if (args.fail === 'wedge') {
      res.writeHead(503)
      res.end()
      return
    }
    res.writeHead(200)
    res.end()
    return
  }

  if (!authorised(req)) {
    unauthorized(res)
    return
  }

  if (path === '/api/status' && req.method === 'GET') {
    json(res, 200, statusPayload())
    return
  }

  if (path === '/api/config' && req.method === 'GET') {
    res.writeHead(200, { 'content-type': 'text/plain' })
    res.end(state.text)
    return
  }

  if (path === '/api/config' && req.method === 'PUT') {
    readBody(req).then(
      (body) => {
        pendingConfig = body
        info('client/admin_api.go:96', 'config file updated, waiting for reload')
        res.writeHead(200)
        res.end()
      },
      () => {
        res.writeHead(413)
        res.end()
      }
    )
    return
  }

  if (path === '/api/reload' && req.method === 'GET') {
    if (pendingConfig !== null) {
      const next = loadConfig(pendingConfig)
      pendingConfig = null
      // A reload keeps the control connection and the admin listener; only the
      // proxy set changes. Preserve the admin identity we are already serving.
      next.admin = state.admin
      state = next
      loggedIn = true
      info('client/service.go:391', 'success reload conf')
      setTimeout(startProxies, START_DELAY_MS)
    }
    res.writeHead(200)
    res.end()
    return
  }

  const proxyDetail = /^\/api\/proxy\/([^/]+)\/config$/.exec(path)
  if (proxyDetail && req.method === 'GET') {
    const name = decodeURIComponent(proxyDetail[1])
    const p = loggedIn ? state.proxies.find((x) => x.name === name) : undefined
    if (!p) {
      warn('http/handler.go:44', `http response [${path}]: error: proxy "${name}" not found`)
      json(res, 404, JSON.stringify({ error: 'proxy not found' }))
      return
    }
    json(res, 200, JSON.stringify({ name: p.name, type: p.type, localAddr: p.localAddr }))
    return
  }

  if (path === '/api/stop' && req.method === 'POST') {
    res.writeHead(200)
    res.end()
    info('client/service.go:225', 'received stop request, shutting down')
    setTimeout(() => process.exit(0), 10)
    return
  }

  res.writeHead(404, { 'content-type': 'text/plain' })
  res.end('not found\n')
})

// ------------------------------------------------------------------ main

if (!args.config) {
  err('flag needs an argument: -c\n')
  process.exit(1)
}

let configText
try {
  configText = readFileSync(args.config, 'utf8')
} catch (e) {
  err(`load config error: ${e.message}\n`)
  process.exit(1)
}

state = loadConfig(configText)
info('sub/root.go:142', `start frpc service for config file [${args.config}]`)
info('client/service.go:295', `try to connect to server...`)

// The two login failures happen before the admin listener would come up, which
// is what makes them look the way they do to the supervisor: a short-lived
// process, an actionable stderr line, and no control channel to ask.
if (args.fail === 'auth') {
  const line =
    "login to server failed: authentication failed: token in login doesn't match token from configuration"
  errorLog('client/service.go:340', line)
  err(`${line}\n`)
  process.exit(1)
}
if (args.fail === 'version') {
  const line = `login to server failed: version mismatch, frps version 0.60.0 is not compatible with frpc ${VERSION}`
  errorLog('client/service.go:340', line)
  err(`${line}\n`)
  process.exit(1)
}

server.listen(state.admin.port, state.admin.addr, () => {
  info('client/service.go:254', `admin server listen on ${state.admin.addr}:${server.address().port}`)
  setTimeout(() => {
    if (args.fail === 'wedge') return
    loggedIn = true
    info('client/service.go:287', `[${RUN_ID}] login to server success, get run id [${RUN_ID}]`)
    setTimeout(startProxies, START_DELAY_MS)
  }, LOGIN_DELAY_MS)
  if (args.fail === 'crash-after') {
    setTimeout(() => {
      errorLog('client/control.go:280', 'control connection closed unexpectedly')
      err('control connection closed unexpectedly\n')
      process.exit(1)
    }, args.crashAfterMs)
  }
})

server.on('error', (e) => {
  err(`admin server listen error: ${e.message}\n`)
  process.exit(1)
})

const shutdown = () => {
  info('client/service.go:225', 'shutting down')
  process.exit(0)
}
process.on('SIGTERM', shutdown)
process.on('SIGINT', shutdown)
