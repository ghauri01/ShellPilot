import { describe, it, expect, afterEach, beforeEach, vi } from 'vitest'
import { mkdtempSync, rmSync, symlinkSync, writeFileSync, readFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

const h = vi.hoisted(() => ({
  replies: new Map<string, { code?: number; stdout?: string; stderr?: string }>(),
  reads: [] as { cmd: string; args: string[] }[]
}))

vi.mock('node:child_process', () => ({
  execFile: (
    cmd: string,
    args: string[],
    _opts: unknown,
    cb: (e: unknown, stdout: string, stderr: string) => void
  ) => {
    h.reads.push({ cmd, args })
    const reply = h.replies.get(`${cmd} ${args.join(' ')}`) ?? {
      code: 1,
      stderr: `no fixture for ${cmd} ${args.join(' ')}`
    }
    const code = reply.code ?? 0
    setImmediate(() =>
      code === 0
        ? cb(null, reply.stdout ?? '', reply.stderr ?? '')
        : cb(Object.assign(new Error(`exit ${code}`), { code }), reply.stdout ?? '', reply.stderr ?? '')
    )
    return undefined
  },
  spawn: () => {
    throw new Error('spawn is not used by the DNS managers')
  }
}))

import { VpnError } from '../src/main/services/vpn/errors'
import type { NetApplyContext, PrivilegedResult } from '../src/main/services/vpn/netstate'
import { assertDnsSpec, dnsManagerFor, isDnsServer, runTag } from '../src/main/services/vpn/dns/index'
import type { DnsSpec } from '../src/main/services/vpn/dns/index'
import {
  buildApplyScript,
  buildRevertScript,
  parseScutilDns,
  parseServiceOrder,
  DarwinDnsManager
} from '../src/main/services/vpn/dns/darwin'
import {
  domainArgs,
  parseResolvConf,
  parseResolvectlStatus,
  renderResolvConf,
  LinuxDnsManager
} from '../src/main/services/vpn/dns/linux'
import {
  buildAddScript,
  buildQueryScript,
  buildRemoveScript,
  parseNrptJson,
  psQuote,
  Win32DnsManager
} from '../src/main/services/vpn/dns/win32'

function reply(key: string, stdout: string, code = 0): void {
  h.replies.set(key, { code, stdout })
}

interface Recorder {
  ctx: NetApplyContext
  calls: { cmd: string; args: string[]; stdin?: string }[]
  result: PrivilegedResult
}

function recorder(over: Partial<NetApplyContext> = {}): Recorder {
  const rec: Recorder = {
    calls: [],
    result: { code: 0, stdout: '', stderr: '' },
    ctx: {
      runId: 'run-1',
      runDir: tmpdir(),
      supportsStdin: true,
      runPrivileged: async (cmd, args, opts) => {
        rec.calls.push({ cmd, args, stdin: opts?.stdin })
        return rec.result
      },
      ...over
    }
  }
  return rec
}

const full: DnsSpec = { servers: ['10.8.0.1', '10.8.0.2'], searchDomains: ['corp.example'], interfaceName: 'utun4' }
const split: DnsSpec = {
  servers: ['10.8.0.1'],
  searchDomains: [],
  interfaceName: 'utun4',
  splitDomains: ['corp.example']
}

beforeEach(() => {
  h.replies.clear()
  h.reads.length = 0
})

// -------------------------------------------------------------------- shared

describe('DNS validation', () => {
  it('accepts real addresses and rejects anything that could become a command', () => {
    expect(isDnsServer('10.8.0.1')).toBe(true)
    expect(isDnsServer('fd00::1')).toBe(true)
    expect(isDnsServer('10.8.0.999')).toBe(false)
    expect(isDnsServer("10.8.0.1'; Remove-Item C:\\ -Recurse")).toBe(false)
    expect(() =>
      assertDnsSpec({ servers: ['$(rm -rf /)'], searchDomains: [], interfaceName: 'utun4' })
    ).toThrow(VpnError)
    expect(() =>
      assertDnsSpec({ servers: ['10.8.0.1'], searchDomains: ['a b'], interfaceName: 'utun4' })
    ).toThrow(VpnError)
    expect(() => assertDnsSpec(full)).not.toThrow()
  })

  it('tags every change with the run id so a sweep can be exact (E10)', () => {
    expect(runTag('run-1')).toBe('ShellPilot-run-1')
    expect(runTag('../evil')).toBe('ShellPilot-.._evil')
  })

  it('refuses a platform it has no implementation for', () => {
    expect(() => dnsManagerFor('freebsd')).toThrow(VpnError)
  })
})

// -------------------------------------------------------------------- darwin

const SCUTIL_DNS = `DNS configuration

resolver #1
  search domain[0] : lan
  nameserver[0] : 192.168.1.1
  nameserver[1] : 192.168.1.2
  if_index : 12 (en0)
  flags    : Request A records, Request AAAA records
  reach    : 0x00020002 (Reachable,Directly Reachable Address)

resolver #2
  domain   : corp.example
  nameserver[0] : 10.8.0.1
  if_index : 18 (utun4)
  flags    : Supplemental, Request A records
  reach    : 0x00000002 (Reachable)
  order    : 100
`

const SERVICE_ORDER = `An asterisk (*) denotes that a network service is disabled.
(1) Wi-Fi
(Hardware Port: Wi-Fi, Device: en0)

(2) Thunderbolt Ethernet
(Hardware Port: Thunderbolt Ethernet, Device: en4)
`

describe('darwin DNS', () => {
  const mgr = (): DarwinDnsManager => new DarwinDnsManager()

  it('parses scutil --dns into resolvers', () => {
    const resolvers = parseScutilDns(SCUTIL_DNS)
    expect(resolvers).toHaveLength(2)
    expect(resolvers[0]).toMatchObject({
      nameservers: ['192.168.1.1', '192.168.1.2'],
      searchDomains: ['lan'],
      interfaceIndex: 12,
      interfaceName: 'en0'
    })
    expect(resolvers[1]).toMatchObject({ domain: 'corp.example', nameservers: ['10.8.0.1'] })
  })

  it('pairs a network service with its BSD device', () => {
    expect(parseServiceOrder(SERVICE_ORDER)).toEqual({ en0: 'Wi-Fi', en4: 'Thunderbolt Ethernet' })
  })

  it('snapshots the unscoped resolver, which is the one a plain lookup uses', async () => {
    reply('scutil --dns', SCUTIL_DNS)
    reply('networksetup -listnetworkserviceorder', SERVICE_ORDER)
    const snap = await mgr().snapshot()
    expect(snap.platform).toBe('darwin')
    expect(snap.previous).toEqual(['192.168.1.1', '192.168.1.2'])
  })

  it('builds the exact scutil script for a full-tunnel resolver', () => {
    expect(buildApplyScript(full, 'ShellPilot-run-1')).toBe(
      [
        'd.init',
        'd.add ServerAddresses * 10.8.0.1 10.8.0.2',
        'd.add SearchDomains * corp.example',
        'd.add InterfaceName utun4',
        'set State:/Network/Service/ShellPilot-run-1/DNS',
        'd.init',
        'd.add InterfaceName utun4',
        'set State:/Network/Service/ShellPilot-run-1/IPv4',
        'quit',
        ''
      ].join('\n')
    )
  })

  it('uses SupplementalMatchDomains for split DNS (E12)', () => {
    const script = buildApplyScript(split, 'ShellPilot-run-1')
    expect(script).toContain('d.add SupplementalMatchDomains * corp.example')
    expect(script).toContain('d.add SupplementalMatchOrders * 100')
    expect(script).not.toContain('SearchDomains')
  })

  it('removes exactly the keys it created and nothing else', () => {
    expect(buildRevertScript('ShellPilot-run-1')).toBe(
      [
        'remove State:/Network/Service/ShellPilot-run-1/DNS',
        'remove State:/Network/Service/ShellPilot-run-1/IPv4',
        'quit',
        ''
      ].join('\n')
    )
  })

  it('sends the script on stdin, not on a command line', async () => {
    const rec = recorder()
    await mgr().apply(full, rec.ctx)
    expect(rec.calls).toHaveLength(1)
    expect(rec.calls[0].cmd).toBe('scutil')
    expect(rec.calls[0].args).toEqual([])
    expect(rec.calls[0].stdin).toBe(buildApplyScript(full, 'ShellPilot-run-1'))
  })

  it('refuses rather than pretending when the channel cannot carry stdin', async () => {
    const rec = recorder({ supportsStdin: false })
    await expect(mgr().apply(full, rec.ctx)).rejects.toMatchObject({ code: 'unsupported' })
    expect(rec.calls).toEqual([])
  })

  it('reverts idempotently even when the key has already gone', async () => {
    const rec = recorder()
    rec.result = { code: 1, stdout: '', stderr: 'No such key' }
    const snapshot = {
      platform: 'darwin' as const,
      capturedAt: 0,
      runId: 'run-1',
      interfaceName: 'utun4',
      previous: []
    }
    await expect(mgr().revert(snapshot, rec.ctx)).resolves.toBeUndefined()
    await expect(mgr().revert(snapshot, rec.ctx)).resolves.toBeUndefined()
    expect(rec.calls.map((c) => c.stdin)).toEqual([
      buildRevertScript('ShellPilot-run-1'),
      buildRevertScript('ShellPilot-run-1')
    ])
  })

  it('verify() confirms a change that took effect', async () => {
    reply('scutil --dns', SCUTIL_DNS)
    expect(await mgr().verify(split)).toMatchObject({ ok: true, actual: ['10.8.0.1'] })
  })

  it('verify() catches a change that silently did not apply', async () => {
    // The command exited 0 but mDNSResponder never picked the resolver up, so
    // every query is still going to the old server.
    reply('scutil --dns', SCUTIL_DNS)
    const result = await mgr().verify({ ...full, servers: ['10.9.9.9'] })
    expect(result.ok).toBe(false)
    expect(result.reason).toContain('did not take effect')
  })

  it('verify() reports a split rule that is not scoped to anything', async () => {
    reply('scutil --dns', SCUTIL_DNS)
    const result = await mgr().verify({ ...split, splitDomains: ['other.example'] })
    expect(result.ok).toBe(false)
    expect(result.reason).toContain('other.example')
  })
})

// --------------------------------------------------------------------- linux

const RESOLVECTL_LINK = `Link 5 (wg0)
    Current Scopes: DNS
         Protocols: +DefaultRoute -LLMNR -mDNS -DNSOverTLS DNSSEC=no/unsupported
Current DNS Server: 10.8.0.1
       DNS Servers: 10.8.0.1 10.8.0.2
        DNS Domain: ~corp.example
`

const RESOLVECTL_GLOBAL = `Global
       Protocols: -LLMNR -mDNS -DNSOverTLS DNSSEC=no/unsupported
resolv.conf mode: stub

Link 2 (eth0)
    Current Scopes: DNS
Current DNS Server: 192.168.1.1
       DNS Servers: 192.168.1.1
                    192.168.1.2
        DNS Domain: lan
`

describe('linux DNS', () => {
  let dir: string

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'shellpilot-dns-'))
  })
  afterEach(() => rmSync(dir, { recursive: true, force: true }))

  const at = (name = 'resolv.conf'): string => join(dir, name)

  it('parses resolvectl status, wrapped server lists included', () => {
    expect(parseResolvectlStatus(RESOLVECTL_LINK)).toEqual({
      servers: ['10.8.0.1', '10.8.0.2'],
      domains: ['~corp.example']
    })
    expect(parseResolvectlStatus(RESOLVECTL_GLOBAL).servers).toEqual([
      '192.168.1.1',
      '192.168.1.2'
    ])
  })

  it('parses a resolv.conf, comments and all', () => {
    expect(
      parseResolvConf('# generated\nsearch lan corp.example\nnameserver 192.168.1.1 # router\nnameserver 1.1.1.1\n')
    ).toEqual({ servers: ['192.168.1.1', '1.1.1.1'], searchDomains: ['lan', 'corp.example'] })
  })

  it('detects systemd-resolved by the symlink into /run/systemd/ (E11)', async () => {
    writeFileSync(at('stub'), 'nameserver 127.0.0.53\n')
    symlinkSync('/run/systemd/resolve/stub-resolv.conf', at())
    expect(await new LinuxDnsManager({ resolvConfPath: at() }).detectBackend()).toBe('resolv.conf')
    reply('resolvectl status', RESOLVECTL_GLOBAL)
    expect(await new LinuxDnsManager({ resolvConfPath: at() }).detectBackend()).toBe('resolvectl')
  })

  it('detects systemd-resolved behind a static stub resolv.conf too', async () => {
    writeFileSync(at(), 'nameserver 127.0.0.53\noptions edns0\n')
    reply('resolvectl status', RESOLVECTL_GLOBAL)
    expect(await new LinuxDnsManager({ resolvConfPath: at() }).detectBackend()).toBe('resolvectl')
  })

  it('falls back to the file when resolvectl does not answer', async () => {
    writeFileSync(at(), 'nameserver 192.168.1.1\n')
    expect(await new LinuxDnsManager({ resolvConfPath: at() }).detectBackend()).toBe('resolv.conf')
  })

  it('turns a split-DNS spec into routing-only domains and a full one into ~. (E12)', () => {
    expect(domainArgs(split)).toEqual(['~corp.example'])
    expect(domainArgs(full)).toEqual(['corp.example', '~.'])
    expect(domainArgs({ ...split, splitDomains: ['.corp.example'] })).toEqual(['~corp.example'])
  })

  it('produces the exact resolvectl argv', async () => {
    writeFileSync(at(), 'nameserver 127.0.0.53\n')
    reply('resolvectl status', RESOLVECTL_GLOBAL)
    const rec = recorder()
    await new LinuxDnsManager({ resolvConfPath: at() }).apply({ ...full, interfaceName: 'wg0' }, rec.ctx)
    expect(rec.calls.map((c) => [c.cmd, ...c.args])).toEqual([
      ['resolvectl', 'dns', 'wg0', '10.8.0.1', '10.8.0.2'],
      ['resolvectl', 'domain', 'wg0', 'corp.example', '~.']
    ])
  })

  it('reverts a resolvectl link with one idempotent command', async () => {
    const rec = recorder()
    const snapshot = {
      platform: 'linux' as const,
      capturedAt: 0,
      runId: 'run-1',
      interfaceName: 'wg0',
      previous: [],
      backend: 'resolvectl' as const
    }
    rec.result = { code: 1, stdout: '', stderr: "Failed to revert link: Link 'wg0' not known" }
    await expect(new LinuxDnsManager().revert(snapshot, rec.ctx)).resolves.toBeUndefined()
    await expect(new LinuxDnsManager().revert(snapshot, rec.ctx)).resolves.toBeUndefined()
    expect(rec.calls.map((c) => [c.cmd, ...c.args])).toEqual([
      ['resolvectl', 'revert', 'wg0'],
      ['resolvectl', 'revert', 'wg0']
    ])
  })

  it('stages the new resolv.conf in the run directory and installs it by path', async () => {
    writeFileSync(at(), 'nameserver 192.168.1.1\n')
    const rec = recorder({ runDir: dir })
    await new LinuxDnsManager({ resolvConfPath: at() }).apply({ ...full, interfaceName: 'wg0' }, rec.ctx)
    const staged = join(dir, 'resolv.conf')
    expect(rec.calls.map((c) => [c.cmd, ...c.args])).toEqual([
      ['install', '-m', '0644', staged, at()]
    ])
    // No shell, no stdin: only paths cross the privileged boundary.
    expect(rec.calls[0].stdin).toBeUndefined()
    const body = readFileSync(staged, 'utf8')
    expect(body).toContain('search corp.example')
    expect(body).toContain('nameserver 10.8.0.1')
    expect(body).toContain('nameserver 10.8.0.2')
  })

  it('renders a resolv.conf that says where the original went', () => {
    expect(renderResolvConf(full)).toContain('netstate.json')
  })

  it('puts a symlinked resolv.conf back as a symlink', async () => {
    const rec = recorder({ runDir: dir })
    await new LinuxDnsManager({ resolvConfPath: at() }).revert(
      {
        platform: 'linux',
        capturedAt: 0,
        runId: 'run-1',
        interfaceName: 'wg0',
        previous: [],
        backend: 'resolv.conf',
        resolvConf: { content: '', symlinkTarget: '/run/NetworkManager/resolv.conf' }
      },
      rec.ctx
    )
    expect(rec.calls.map((c) => [c.cmd, ...c.args])).toEqual([
      ['ln', '-sfn', '/run/NetworkManager/resolv.conf', at()]
    ])
  })

  it('puts a plain resolv.conf back byte for byte', async () => {
    const original = '# original\nnameserver 192.168.1.1\n'
    const rec = recorder({ runDir: dir })
    await new LinuxDnsManager({ resolvConfPath: at() }).revert(
      {
        platform: 'linux',
        capturedAt: 0,
        runId: 'run-1',
        interfaceName: 'wg0',
        previous: ['192.168.1.1'],
        backend: 'resolv.conf',
        resolvConf: { content: original, symlinkTarget: null }
      },
      rec.ctx
    )
    const staged = join(dir, 'resolv.conf.orig')
    expect(rec.calls.map((c) => [c.cmd, ...c.args])).toEqual([['install', '-m', '0644', staged, at()]])
    expect(readFileSync(staged, 'utf8')).toBe(original)
  })

  it('verify() catches a resolvectl change that did not apply', async () => {
    writeFileSync(at(), 'nameserver 127.0.0.53\n')
    reply('resolvectl status', RESOLVECTL_GLOBAL)
    reply('resolvectl status wg0', RESOLVECTL_LINK)
    const mgr = new LinuxDnsManager({ resolvConfPath: at() })
    expect(await mgr.verify({ ...full, interfaceName: 'wg0' })).toMatchObject({ ok: true })
    const bad = await mgr.verify({ ...full, servers: ['10.9.9.9'], interfaceName: 'wg0' })
    expect(bad.ok).toBe(false)
    expect(bad.reason).toContain('did not take effect')
  })

  it('verify() catches a split rule whose domain never got scoped', async () => {
    writeFileSync(at(), 'nameserver 127.0.0.53\n')
    reply('resolvectl status', RESOLVECTL_GLOBAL)
    reply('resolvectl status wg0', RESOLVECTL_LINK)
    const result = await new LinuxDnsManager({ resolvConfPath: at() }).verify({
      servers: ['10.8.0.1'],
      searchDomains: [],
      interfaceName: 'wg0',
      splitDomains: ['other.example']
    })
    expect(result.ok).toBe(false)
    expect(result.reason).toContain('~other.example')
  })

  it('verify() reads the file back on the resolv.conf branch', async () => {
    writeFileSync(at(), 'nameserver 10.8.0.1\nnameserver 10.8.0.2\n')
    const result = await new LinuxDnsManager({ resolvConfPath: at() }).verify({
      ...full,
      interfaceName: 'wg0'
    })
    expect(result).toMatchObject({ ok: true, actual: ['10.8.0.1', '10.8.0.2'] })
  })
})

// --------------------------------------------------------------------- win32

describe('win32 DNS', () => {
  const mgr = (): Win32DnsManager => new Win32DnsManager()
  const PS = ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-Command']

  it('quotes a PowerShell string by doubling the only metacharacter it has', () => {
    expect(psQuote("it's")).toBe("'it''s'")
  })

  it('tags every rule with the run id (E10)', () => {
    const script = buildAddScript(split, 'ShellPilot-run-1')
    expect(script).toBe(
      "$ErrorActionPreference='Stop'; Add-DnsClientNrptRule -Namespace '.corp.example' -NameServers @('10.8.0.1') -Comment 'ShellPilot-run-1' -DisplayName 'ShellPilot-run-1'"
    )
  })

  it('uses the whole tree for a full-tunnel profile and one rule per split domain', () => {
    expect(buildAddScript(full, 'ShellPilot-run-1')).toContain("-Namespace '.'")
    const many = buildAddScript(
      { ...split, splitDomains: ['corp.example', 'internal.example'] },
      'ShellPilot-run-1'
    )
    expect(many).toContain("-Namespace '.corp.example'")
    expect(many).toContain("-Namespace '.internal.example'")
  })

  it('sweeps by exact tag so a run id cannot match another by prefix', () => {
    const script = buildRemoveScript('ShellPilot-run-1')
    expect(script).toContain("$_.Comment -eq 'ShellPilot-run-1'")
    expect(script).not.toContain('-like')
    expect(script).toContain('Remove-DnsClientNrptRule -Name $_.Name -Force')
  })

  it('produces the exact argv for apply', async () => {
    const rec = recorder()
    await mgr().apply(split, rec.ctx)
    expect(rec.calls).toEqual([
      { cmd: 'powershell.exe', args: [...PS, buildAddScript(split, 'ShellPilot-run-1')], stdin: undefined }
    ])
  })

  it('produces the exact argv for revert and repeats harmlessly', async () => {
    const rec = recorder()
    const snapshot = {
      platform: 'win32' as const,
      capturedAt: 0,
      runId: 'run-1',
      interfaceName: 'ShellPilot Tunnel',
      previous: []
    }
    await mgr().revert(snapshot, rec.ctx)
    await mgr().revert(snapshot, rec.ctx)
    expect(rec.calls.map((c) => c.args)).toEqual([
      [...PS, buildRemoveScript('ShellPilot-run-1')],
      [...PS, buildRemoveScript('ShellPilot-run-1')]
    ])
  })

  it('parses every shape ConvertTo-Json produces', () => {
    expect(parseNrptJson('')).toEqual([])
    expect(parseNrptJson('{"Namespace":".corp.example","NameServers":["10.8.0.1"]}')).toEqual([
      { namespace: '.corp.example', nameServers: ['10.8.0.1'] }
    ])
    expect(
      parseNrptJson('[{"Namespace":[".a"],"NameServers":"10.8.0.1"},{"Namespace":".b","NameServers":null}]')
    ).toEqual([
      { namespace: '.a', nameServers: ['10.8.0.1'] },
      { namespace: '.b', nameServers: [] }
    ])
  })

  it('verify() confirms our own tagged rules rather than the machine resolvers', async () => {
    const rec = recorder()
    const m = mgr()
    await m.apply(split, rec.ctx)
    reply(
      `powershell.exe ${[...PS, buildQueryScript('ShellPilot-run-1')].join(' ')}`,
      '{"Namespace":".corp.example","NameServers":["10.8.0.1"]}'
    )
    expect(await m.verify(split)).toMatchObject({ ok: true, actual: ['10.8.0.1'] })
  })

  it('verify() catches a rule that was never created', async () => {
    const rec = recorder()
    const m = mgr()
    await m.apply(split, rec.ctx)
    reply(`powershell.exe ${[...PS, buildQueryScript('ShellPilot-run-1')].join(' ')}`, '')
    const result = await m.verify(split)
    expect(result.ok).toBe(false)
    expect(result.reason).toContain('ShellPilot-run-1')
  })

  it('verify() catches a rule that covers the wrong namespace', async () => {
    const rec = recorder()
    const m = mgr()
    await m.apply(split, rec.ctx)
    reply(
      `powershell.exe ${[...PS, buildQueryScript('ShellPilot-run-1')].join(' ')}`,
      '{"Namespace":".other.example","NameServers":["10.8.0.1"]}'
    )
    const result = await m.verify(split)
    expect(result.ok).toBe(false)
    expect(result.reason).toContain('.corp.example')
  })
})
