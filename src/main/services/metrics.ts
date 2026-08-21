import type { Client } from 'ssh2'
import { acquire, release, type PooledConnection } from './ssh'
import type { HostMetrics, MetricsResult, SshConnectConfig } from '../../shared/ssh'

interface Conn {
  conn: PooledConnection
  client: Client
}

// One metrics connection per server id, opened lazily and reused for polling.
const conns = new Map<string, Conn>()

async function ensure(key: string, cfg: SshConnectConfig): Promise<Client> {
  const existing = conns.get(key)
  if (existing) return existing.client
  const conn = await acquire(cfg)
  const client = conn.client
  client.on('close', () => conns.delete(key))
  conns.set(key, { conn, client })
  return client
}

function exec(client: Client, cmd: string): Promise<string> {
  return new Promise((resolve, reject) => {
    client.exec(cmd, (err, stream) => {
      if (err) return reject(err)
      let out = ''
      stream.on('data', (d: Buffer) => (out += d.toString('utf8')))
      stream.stderr.on('data', () => {})
      stream.on('close', () => resolve(out))
    })
  })
}

// Single round-trip snippet. Sections are delimited by markers so parsing is
// resilient across distros.
//
// CPU is a delta of /proc/stat between two points in time. Taking both points
// inside one command means holding an exec channel open for the whole sleep,
// and that channel rides the same connection the interactive shell types over
// — so every poll stalled typing for as long as it slept. The delta is taken
// against the previous poll instead, which is both free and a more
// representative average. Only the first sample, which has no previous
// snapshot, pays for an in-command sleep.
const script = (withSleep: boolean): string => [
  'echo __CPU__',
  "grep '^cpu ' /proc/stat",
  ...(withSleep ? ['sleep 0.3', "grep '^cpu ' /proc/stat"] : []),
  'echo __MEM__',
  "grep -E '^(MemTotal|MemAvailable):' /proc/meminfo",
  'echo __DISK__',
  'df -kP / | tail -1',
  'echo __NET__',
  'cat /proc/net/dev',
  'echo __UP__',
  'head -1 /proc/uptime',
  'echo __HOST__',
  'uname -n',
  'echo __KERN__',
  'uname -r',
  'echo __CORES__',
  'nproc'
].join('; ')

const CMD = script(false)
const CMD_FIRST = script(true)

function section(text: string, name: string): string[] {
  const parts = text.split('__' + name + '__')
  if (parts.length < 2) return []
  const rest = parts[1]
  const end = rest.search(/__[A-Z]+__/)
  return (end === -1 ? rest : rest.slice(0, end)).trim().split('\n').filter(Boolean)
}

interface CpuSnap {
  total: number
  idle: number
}

function cpuTotals(line: string): CpuSnap {
  const n = line.trim().split(/\s+/).slice(1).map(Number)
  const total = n.reduce((a, b) => a + b, 0)
  const idle = (n[3] || 0) + (n[4] || 0) // idle + iowait
  return { total, idle }
}

function cpuPct(a: CpuSnap, b: CpuSnap): number {
  const dTotal = b.total - a.total
  const dIdle = b.idle - a.idle
  return dTotal > 0 ? Math.max(0, Math.min(100, (1 - dIdle / dTotal) * 100)) : 0
}

// `prev` is the snapshot from this key's previous poll; the returned `snap` is
// the one to diff the next poll against.
function parse(text: string, prev: CpuSnap | null): { data: HostMetrics; snap: CpuSnap | null } {
  const snaps = section(text, 'CPU').map(cpuTotals)
  const latest = snaps.length ? snaps[snaps.length - 1] : null
  const base = snaps.length >= 2 ? snaps[0] : prev
  const cpu = base && latest ? cpuPct(base, latest) : 0

  const mem = section(text, 'MEM')
  const kv: Record<string, number> = {}
  for (const l of mem) {
    const [k, v] = l.split(':')
    kv[k.trim()] = parseInt(v) * 1024
  }
  const memTotal = kv.MemTotal || 0
  const memUsed = Math.max(0, memTotal - (kv.MemAvailable || 0))

  const disk = section(text, 'DISK')[0]?.trim().split(/\s+/) ?? []
  const diskTotal = (parseInt(disk[1]) || 0) * 1024
  const diskUsed = (parseInt(disk[2]) || 0) * 1024

  let netRx = 0
  let netTx = 0
  for (const l of section(text, 'NET')) {
    const idx = l.indexOf(':')
    if (idx === -1) continue
    const iface = l.slice(0, idx).trim()
    if (iface === 'lo') continue
    const cols = l.slice(idx + 1).trim().split(/\s+/).map(Number)
    netRx += cols[0] || 0
    netTx += cols[8] || 0
  }

  const uptime = parseFloat(section(text, 'UP')[0] ?? '0') || 0
  const hostname = section(text, 'HOST')[0] ?? ''
  const kernel = section(text, 'KERN')[0] ?? ''
  const cores = parseInt(section(text, 'CORES')[0] ?? '1') || 1

  const data: HostMetrics = {
    cpu,
    memPct: memTotal ? (memUsed / memTotal) * 100 : 0,
    memUsed,
    memTotal,
    diskPct: diskTotal ? (diskUsed / diskTotal) * 100 : 0,
    diskUsed,
    diskTotal,
    netRx,
    netTx,
    uptime,
    hostname,
    kernel,
    cores
  }
  return { data, snap: latest }
}

// Last CPU snapshot per key, so the next poll has something to diff against.
const cpuState = new Map<string, CpuSnap>()
// In-flight sample per key, and the last successful result with its timestamp.
const inflight = new Map<string, Promise<MetricsResult>>()
const recent = new Map<string, { at: number; result: MetricsResult }>()

// A result younger than this is served from memory instead of opening another
// channel. Three panels can watch the same server at once (monitor strip,
// monitor tab, fleet card), each on its own timer, and every extra sample is
// extra traffic on the connection the terminal is typing over.
const MIN_AGE_MS = 1500

async function sample(key: string, cfg: SshConnectConfig): Promise<MetricsResult> {
  try {
    const client = await ensure(key, cfg)
    const prev = cpuState.get(key) ?? null
    const out = await exec(client, prev ? CMD : CMD_FIRST)
    const { data, snap } = parse(out, prev)
    if (snap) cpuState.set(key, snap)
    const result: MetricsResult = { ok: true, data }
    recent.set(key, { at: Date.now(), result })
    return result
  } catch (err) {
    return { ok: false, error: err instanceof Error ? err.message : String(err) }
  }
}

export function metricsSample(key: string, cfg: SshConnectConfig): Promise<MetricsResult> {
  const hit = recent.get(key)
  if (hit && Date.now() - hit.at < MIN_AGE_MS) return Promise.resolve(hit.result)
  const running = inflight.get(key)
  if (running) return running
  const p = sample(key, cfg).finally(() => inflight.delete(key))
  inflight.set(key, p)
  return p
}

export function metricsDisconnect(key: string): void {
  const entry = conns.get(key)
  if (!entry) return
  // Shared connection: hand it back instead of tearing it down.
  release(entry.conn)
  conns.delete(key)
  cpuState.delete(key)
  recent.delete(key)
}

export function metricsDisposeAll(): void {
  for (const k of [...conns.keys()]) metricsDisconnect(k)
}
