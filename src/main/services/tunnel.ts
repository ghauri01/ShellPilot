import net from 'node:net'
import type { Client } from 'ssh2'
import type { WebContents } from 'electron'
import { openChain } from './ssh'
import type { TunnelConfig, TunnelResult, TunnelSshConfig, TunnelState, TunnelStatus } from '../../shared/tunnel'

// Port forwarding over the SSH transport:
//   local  — listen here, forwardOut each connection to target via the server
//   remote — ask the server to listen, pipe its connections to a local target
//   socks  — listen here, speak SOCKS5, forwardOut to whatever each client asks

interface Active {
  cfg: TunnelConfig
  clients: Client[]
  server: net.Server | null
  sockets: Set<net.Socket>
  state: TunnelState
  error?: string
  connections: number
  listenPort?: number
  wc: WebContents
}

const tunnels = new Map<string, Active>()

function emit(t: Active): void {
  if (t.wc.isDestroyed()) return
  const status: TunnelStatus = {
    id: t.cfg.id,
    state: t.state,
    error: t.error,
    connections: t.connections,
    listenPort: t.listenPort
  }
  t.wc.send(`tunnel:status:${t.cfg.id}`, status)
}

function setState(t: Active, state: TunnelState, error?: string): void {
  t.state = state
  t.error = error
  emit(t)
}

// Wire a socket to an SSH channel, keeping the live connection count honest
// however the pair happens to tear down.
function bind(t: Active, socket: net.Socket, stream: NodeJS.ReadWriteStream): void {
  t.sockets.add(socket)
  t.connections++
  emit(t)
  let done = false
  const finish = (): void => {
    if (done) return
    done = true
    t.sockets.delete(socket)
    t.connections = Math.max(0, t.connections - 1)
    emit(t)
    socket.destroy()
    ;(stream as unknown as { end?: () => void }).end?.()
  }
  socket.on('error', finish)
  socket.on('close', finish)
  stream.on('error', finish)
  stream.on('close', finish)
  socket.pipe(stream).pipe(socket)
}

function forward(
  client: Client,
  srcHost: string,
  srcPort: number,
  dstHost: string,
  dstPort: number
): Promise<NodeJS.ReadWriteStream> {
  return new Promise((resolve, reject) => {
    client.forwardOut(srcHost, srcPort, dstHost, dstPort, (err, stream) =>
      err ? reject(err) : resolve(stream as unknown as NodeJS.ReadWriteStream)
    )
  })
}

function listen(server: net.Server, host: string, port: number): Promise<number> {
  return new Promise((resolve, reject) => {
    const onError = (err: NodeJS.ErrnoException): void => {
      server.removeListener('error', onError)
      reject(
        err.code === 'EADDRINUSE'
          ? new Error(`Port ${port} on ${host} is already in use.`)
          : err.code === 'EACCES'
            ? new Error(`Not allowed to bind port ${port} (ports below 1024 need elevated rights).`)
            : err
      )
    }
    server.once('error', onError)
    server.listen(port, host, () => {
      server.removeListener('error', onError)
      const addr = server.address()
      resolve(typeof addr === 'object' && addr ? addr.port : port)
    })
  })
}

// ------------------------------------------------------------------- SOCKS5

const SOCKS_VERSION = 0x05
const CMD_CONNECT = 0x01
const ATYP_IPV4 = 0x01
const ATYP_DOMAIN = 0x03
const ATYP_IPV6 = 0x04

// Read exactly `n` bytes, buffering across chunks.
function readBytes(socket: net.Socket, n: number): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = []
    let total = 0
    const onData = (chunk: Buffer): void => {
      chunks.push(chunk)
      total += chunk.length
      if (total < n) return
      const buf = Buffer.concat(chunks, total)
      cleanup()
      // Anything past the requested bytes belongs to the next stage.
      if (buf.length > n) socket.unshift(buf.subarray(n))
      resolve(buf.subarray(0, n))
    }
    const onErr = (e: Error): void => {
      cleanup()
      reject(e)
    }
    const onEnd = (): void => onErr(new Error('SOCKS client closed early'))
    const cleanup = (): void => {
      socket.removeListener('data', onData)
      socket.removeListener('error', onErr)
      socket.removeListener('end', onEnd)
    }
    socket.on('data', onData)
    socket.on('error', onErr)
    socket.on('end', onEnd)
  })
}

function socksReply(socket: net.Socket, code: number): void {
  // Reply address is unused by clients for CONNECT; report 0.0.0.0:0.
  socket.write(Buffer.from([SOCKS_VERSION, code, 0x00, ATYP_IPV4, 0, 0, 0, 0, 0, 0]))
}

async function handleSocks(t: Active, client: Client, socket: net.Socket): Promise<void> {
  // Greeting: version, method count, methods.
  const head = await readBytes(socket, 2)
  if (head[0] !== SOCKS_VERSION) throw new Error('Not a SOCKS5 client')
  await readBytes(socket, head[1])
  socket.write(Buffer.from([SOCKS_VERSION, 0x00])) // no authentication

  // Request: version, command, reserved, address type.
  const req = await readBytes(socket, 4)
  if (req[1] !== CMD_CONNECT) {
    socksReply(socket, 0x07) // command not supported
    socket.end()
    return
  }

  let host: string
  if (req[3] === ATYP_IPV4) {
    host = [...(await readBytes(socket, 4))].join('.')
  } else if (req[3] === ATYP_DOMAIN) {
    const len = (await readBytes(socket, 1))[0]
    host = (await readBytes(socket, len)).toString('utf8')
  } else if (req[3] === ATYP_IPV6) {
    const raw = await readBytes(socket, 16)
    const parts: string[] = []
    for (let i = 0; i < 16; i += 2) parts.push(raw.readUInt16BE(i).toString(16))
    host = parts.join(':')
  } else {
    socksReply(socket, 0x08) // address type not supported
    socket.end()
    return
  }
  const port = (await readBytes(socket, 2)).readUInt16BE(0)

  let stream: NodeJS.ReadWriteStream
  try {
    stream = await forward(client, socket.remoteAddress ?? '127.0.0.1', socket.remotePort ?? 0, host, port)
  } catch {
    socksReply(socket, 0x05) // connection refused
    socket.end()
    return
  }
  socksReply(socket, 0x00)
  bind(t, socket, stream)
}

// ---------------------------------------------------------------- lifecycle

export async function tunnelStart(
  wc: WebContents,
  cfg: TunnelConfig,
  ssh: TunnelSshConfig
): Promise<TunnelResult> {
  await tunnelStop(cfg.id)

  const t: Active = {
    cfg,
    clients: [],
    server: null,
    sockets: new Set(),
    state: 'starting',
    connections: 0,
    wc
  }
  tunnels.set(cfg.id, t)
  emit(t)

  try {
    const chain = await openChain(ssh)
    t.clients = chain.clients
    const client = chain.client

    // A dropped SSH connection must not leave a listener accepting traffic
    // that has nowhere to go.
    client.on('close', () => {
      if (tunnels.get(cfg.id) === t && t.state === 'active') {
        setState(t, 'error', 'SSH connection closed')
        void tunnelStop(cfg.id, true)
      }
    })
    client.on('error', (err: Error) => {
      if (tunnels.get(cfg.id) === t) setState(t, 'error', err.message)
    })

    if (cfg.kind === 'remote') {
      const port = await new Promise<number>((resolve, reject) => {
        client.forwardIn(cfg.listenHost, cfg.listenPort, (err, bound) =>
          err ? reject(err) : resolve(bound || cfg.listenPort)
        )
      })
      client.on('tcp connection', (info, accept) => {
        if (info.destPort !== port) return
        const stream = accept() as unknown as NodeJS.ReadWriteStream
        const socket = net.connect(cfg.targetPort, cfg.targetHost)
        socket.on('connect', () => bind(t, socket, stream))
        socket.on('error', () => (stream as unknown as { end: () => void }).end())
      })
      t.listenPort = port
      setState(t, 'active')
      return { ok: true, listenPort: port }
    }

    const server = net.createServer((socket) => {
      if (cfg.kind === 'socks') {
        handleSocks(t, client, socket).catch(() => socket.destroy())
        return
      }
      forward(client, socket.remoteAddress ?? '127.0.0.1', socket.remotePort ?? 0, cfg.targetHost, cfg.targetPort)
        .then((stream) => bind(t, socket, stream))
        .catch(() => socket.destroy())
    })
    t.server = server
    t.listenPort = await listen(server, cfg.listenHost, cfg.listenPort)
    setState(t, 'active')
    return { ok: true, listenPort: t.listenPort }
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err)
    setState(t, 'error', message)
    await tunnelStop(cfg.id, true)
    return { ok: false, error: message }
  }
}

export async function tunnelStop(id: string, keepError = false): Promise<void> {
  const t = tunnels.get(id)
  if (!t) return
  tunnels.delete(id)
  for (const s of t.sockets) {
    try {
      s.destroy()
    } catch {
      /* ignore */
    }
  }
  t.sockets.clear()
  if (t.server) await new Promise<void>((resolve) => t.server?.close(() => resolve()))
  for (const c of [...t.clients].reverse()) {
    try {
      c.end()
    } catch {
      /* ignore */
    }
  }
  t.connections = 0
  if (!keepError) setState(t, 'stopped')
  else emit(t)
}

export function tunnelStatus(id: string): TunnelStatus | null {
  const t = tunnels.get(id)
  if (!t) return null
  return { id, state: t.state, error: t.error, connections: t.connections, listenPort: t.listenPort }
}

export function tunnelList(): TunnelStatus[] {
  return [...tunnels.keys()].map((id) => tunnelStatus(id)).filter((s): s is TunnelStatus => s !== null)
}

export function tunnelDisposeAll(): void {
  for (const id of [...tunnels.keys()]) void tunnelStop(id, true)
}

// Opens a local forward on an ephemeral port and returns it. Used to reach a
// database that is only routable from the SSH server. Not registered as a
// user-visible tunnel — the caller owns its lifetime.
export async function openEphemeralForward(
  ssh: TunnelSshConfig,
  targetHost: string,
  targetPort: number
): Promise<{ port: number; close: () => void }> {
  const chain = await openChain(ssh)
  const client = chain.client
  const sockets = new Set<net.Socket>()

  const server = net.createServer((socket) => {
    sockets.add(socket)
    socket.on('close', () => sockets.delete(socket))
    forward(client, '127.0.0.1', 0, targetHost, targetPort)
      .then((stream) => {
        socket.pipe(stream).pipe(socket)
        const kill = (): void => {
          socket.destroy()
          ;(stream as unknown as { end?: () => void }).end?.()
        }
        socket.on('error', kill)
        stream.on('error', kill)
      })
      .catch(() => socket.destroy())
  })

  const port = await listen(server, '127.0.0.1', 0)

  return {
    port,
    close: () => {
      for (const s of sockets) s.destroy()
      sockets.clear()
      server.close()
      for (const c of [...chain.clients].reverse()) {
        try {
          c.end()
        } catch {
          /* ignore */
        }
      }
    }
  }
}
