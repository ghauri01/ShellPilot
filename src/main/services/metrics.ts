import type { Client } from 'ssh2'
import { acquire, release, type PooledConnection } from './ssh'
import type { HostMetrics, MetricsResult, PortListener, ServiceUnit, SshConnectConfig } from '../../shared/ssh'

interface Conn {
  conn: PooledConnection
  client: Client
}

// One metrics connection per server id, opened lazily and reused for polling.
const conns = new Map<string, Conn>()

async function ensure(key: string, cfg: SshConnectConfig, allowPrompt = true): Promise<Client> {
  const existing = conns.get(key)
  if (existing) return existing.client
  const conn = await acquire(cfg, undefined, allowPrompt)
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
  // Which of those interfaces are real hardware.
  //
  // A packet arriving for a container is counted on the wire, again on the
  // bridge it crosses, and again on the veth into the namespace, so summing
  // every interface reports one packet three times. Measured on a host running
  // k3s and Docker: 69,462 bytes summed across all interfaces for 7,666 bytes
  // that actually crossed eth0 — nine times the truth, on exactly the kind of
  // host this app is for.
  //
  // A physical interface is the one with a backing device in sysfs. veth,
  // bridges, flannel, and both VPN tunnel types have none — and the tunnels
  // are right to be excluded too, since their traffic also leaves through the
  // wire encrypted and would otherwise be counted twice.
  'echo __PHYS__',
  'for i in /sys/class/net/*; do [ -e "$i/device" ] && basename "$i"; done 2>/dev/null',
  'echo __UP__',
  'head -1 /proc/uptime',
  'echo __HOST__',
  'uname -n',
  'echo __KERN__',
  'uname -r',
  'echo __CORES__',
  'nproc',
  // Both of these are absent on plenty of hosts — a container without systemd,
  // a box with neither ss nor netstat — so each is guarded and simply produces
  // an empty section rather than an error that would spoil the whole sample.
  // The marker line records which probe ran, because it changes how the output
  // parses and what the UI can honestly claim.
  'echo __SVC__',
  "command -v systemctl >/dev/null 2>&1 && systemctl list-units --type=service --state=running,failed --no-pager --no-legend --plain 2>/dev/null | head -" + String(MAX_SERVICES),
  'echo __PORTS__',
  // ss is preferred: it is present on anything modern, and netstat is
  // deprecated and absent by default on many distributions now.
  "if command -v ss >/dev/null 2>&1; then echo 'src:ss'; ss -lntupH 2>/dev/null | head -" + String(MAX_LISTENERS) +
    "; elif command -v netstat >/dev/null 2>&1; then echo 'src:netstat'; netstat -lntup 2>/dev/null | head -" + String(MAX_LISTENERS) + '; fi'
].join('; ')

// A busy host can run hundreds of units and listen on as many sockets. These
// are polled continuously, so the sample is capped rather than allowed to grow
// without limit — the UI says when it truncated.
const MAX_SERVICES = 80
const MAX_LISTENERS = 120

const CMD = script(false)
const CMD_FIRST = script(true)

function section(text: string, name: string): string[] {
  const parts = text.split('__' + name + '__')
  if (parts.length < 2) return []
  const rest = parts[1]
  const end = rest.search(/__[A-Z]+__/)
  return (end === -1 ? rest : rest.slice(0, end)).trim().split('\n').filter(Boolean)
}

// `systemctl list-units --plain --no-legend` gives:
//   nginx.service loaded active running A high performance web server
// Bullet-prefixed lines (● for failed) survive --plain on some versions, so
// the leading marker is stripped rather than assumed absent.
export function parseServices(lines: string[]): ServiceUnit[] {
  const out: ServiceUnit[] = []
  for (const raw of lines) {
    const line = raw.replace(/^[●*✓✗\s]+/, '').trim()
    if (!line) continue
    const parts = line.split(/\s+/)
    if (parts.length < 4) continue
    const [name, , active, sub, ...rest] = parts
    if (!name.endsWith('.service')) continue
    out.push({ name: name.replace(/\.service$/, ''), active, sub, description: rest.join(' ') })
  }
  return out
}

// Splits "0.0.0.0:22", "[::]:22" and "*:22" into address and port. Taking the
// last colon rather than the first is what makes IPv6 work.
export function splitEndpoint(text: string): { address: string; port: number } | null {
  const i = text.lastIndexOf(':')
  if (i === -1) return null
  const port = Number(text.slice(i + 1))
  if (!Number.isFinite(port) || port <= 0) return null
  const address = text.slice(0, i).replace(/^\[|\]$/g, '') || '*'
  // 0.0.0.0, :: and * all mean "every interface". Reported as one thing so a
  // dual-stack listener reads as the single service it is, rather than as two
  // rows that differ only in address family.
  return { address: address === '0.0.0.0' || address === '::' ? '*' : address, port }
}

// users:(("sshd",pid=1234,fd=3))  →  { process: 'sshd', pid: 1234 }
export function parseSsUsers(text: string): { process?: string; pid?: number } {
  const m = /users:\(\("([^"]+)",pid=(\d+)/.exec(text)
  return m ? { process: m[1], pid: Number(m[2]) } : {}
}

export function parseListeners(lines: string[]): { listeners: PortListener[]; source: 'ss' | 'netstat' | null } {
  const first = lines[0]?.trim()
  const source = first === 'src:ss' ? 'ss' : first === 'src:netstat' ? 'netstat' : null
  if (!source) return { listeners: [], source: null }

  const out: PortListener[] = []
  const seen = new Set<string>()
  for (const line of lines.slice(1)) {
    const parts = line.trim().split(/\s+/)
    if (parts.length < 4) continue

    let proto: string
    let endpoint: string
    let owner: { process?: string; pid?: number }

    if (source === 'ss') {
      // tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=1,fd=3))
      proto = parts[0]
      // udp rows have no LISTEN state, so the local address is found by
      // position from the end of the fixed columns rather than a fixed index.
      endpoint = parts[4] ?? ''
      owner = parseSsUsers(line)
    } else {
      // tcp 0 0 0.0.0.0:22 0.0.0.0:* LISTEN 1234/sshd
      proto = parts[0]
      endpoint = parts[3] ?? ''
      const prog = parts.find((p) => /^\d+\/\S+$/.test(p))
      const m = prog ? /^(\d+)\/(.+)$/.exec(prog) : null
      owner = m ? { pid: Number(m[1]), process: m[2] } : {}
      if (!/LISTEN/.test(line) && !proto.startsWith('udp')) continue
    }

    const split = splitEndpoint(endpoint)
    if (!split) continue
    // With wildcards normalised, the v4 and v6 rows of a dual-stack listener
    // collapse to one — which is what a reader wants to see.
    //
    // The key is built from the SAME proto that gets pushed. netstat prints
    // the families as `tcp` and `tcp6`, so keying on the raw value let both
    // rows through and then stored them as one identical `tcp` row twice:
    // an inflated port count, and two React children under one key in a list
    // that re-renders every couple of seconds.
    const normalised = proto.replace(/6$/, '')
    const dedupe = `${normalised}|${split.address}|${split.port}`
    if (seen.has(dedupe)) continue
    seen.add(dedupe)
    out.push({ proto: normalised, ...split, ...owner })
  }
  out.sort((a, b) => a.port - b.port || a.proto.localeCompare(b.proto))
  return { listeners: out, source }
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

/**
 * Cumulative bytes in and out across this host's own interfaces.
 *
 * `physLines` is what sysfs said has a backing device. When it names anything,
 * only those interfaces count. A packet destined for a container is counted on
 * the wire, again on the bridge, and again on the veth into the namespace, so
 * summing everything reports one packet several times over — measured at nine
 * times the truth on a host running k3s and Docker.
 *
 * When it names nothing, every non-loopback interface counts instead. That is
 * the case on a host whose sysfs we could not read, and on a container, where
 * there IS no physical interface and the veth genuinely is the wire.
 */
export function sumNetwork(
  netLines: string[],
  physLines: string[]
): { netRx: number; netTx: number } {
  const physical = new Set(physLines.map((l) => l.trim()).filter(Boolean))
  let netRx = 0
  let netTx = 0
  for (const l of netLines) {
    const idx = l.indexOf(':')
    if (idx === -1) continue
    const iface = l.slice(0, idx).trim()
    if (iface === 'lo') continue
    if (physical.size > 0 && !physical.has(iface)) continue
    // /proc/net/dev: eight receive columns, then eight transmit ones, so
    // transmitted bytes is index 8.
    const cols = l.slice(idx + 1).trim().split(/\s+/).map(Number)
    netRx += cols[0] || 0
    netTx += cols[8] || 0
  }
  return { netRx, netTx }
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

  const { netRx, netTx } = sumNetwork(section(text, 'NET'), section(text, 'PHYS'))

  const uptime = parseFloat(section(text, 'UP')[0] ?? '0') || 0
  const hostname = section(text, 'HOST')[0] ?? ''
  const kernel = section(text, 'KERN')[0] ?? ''
  const cores = parseInt(section(text, 'CORES')[0] ?? '1') || 1

  const svcLines = section(text, 'SVC')
  // The guard in the script means a host without systemd emits nothing here at
  // all, which is indistinguishable from systemd running no matching units —
  // so presence of the section header is not enough. A running host always has
  // at least one running unit, so an empty section on a systemd host is
  // vanishingly unlikely; treat lines-present as the signal and say so.
  const hasSystemd = svcLines.length > 0
  const { listeners, source: listenerSource } = parseListeners(section(text, 'PORTS'))

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
    cores,
    // An absent section means the tool is not on the host; an empty one means
    // it ran and found nothing. Only the former becomes null.
    services: svcLines.length > 0 ? parseServices(svcLines) : hasSystemd ? [] : null,
    listeners: listenerSource ? listeners : null,
    listenerSource
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

async function sample(key: string, cfg: SshConnectConfig, allowPrompt = true): Promise<MetricsResult> {
  try {
    const client = await ensure(key, cfg, allowPrompt)
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

export function metricsSample(
  key: string,
  cfg: SshConnectConfig,
  // False for the background fleet sweep. An unknown host is refused instead of
  // raising a trust-on-first-use dialog with nobody at the keyboard — see
  // verifyHostKey for why that dialog is only worth anything when the person
  // can connect it to something they just did.
  allowPrompt = true
): Promise<MetricsResult> {
  const hit = recent.get(key)
  if (hit && Date.now() - hit.at < MIN_AGE_MS) return Promise.resolve(hit.result)
  const running = inflight.get(key)
  if (running) return running
  const p = sample(key, cfg, allowPrompt).finally(() => inflight.delete(key))
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
