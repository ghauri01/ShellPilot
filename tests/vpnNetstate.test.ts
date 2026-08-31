import { describe, it, expect, afterEach, beforeEach, vi } from 'vitest'
import { existsSync, mkdirSync, mkdtempSync, rmSync, statSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

const h = vi.hoisted(() => ({
  replies: new Map<string, { code?: number; stdout?: string; stderr?: string }>()
}))

vi.mock('node:child_process', () => ({
  execFile: (
    cmd: string,
    args: string[],
    _opts: unknown,
    cb: (e: unknown, stdout: string, stderr: string) => void
  ) => {
    const reply = h.replies.get(`${cmd} ${args.join(' ')}`) ?? { code: 1, stderr: 'no fixture' }
    const code = reply.code ?? 0
    setImmediate(() =>
      code === 0
        ? cb(null, reply.stdout ?? '', reply.stderr ?? '')
        : cb(Object.assign(new Error(`exit ${code}`), { code }), reply.stdout ?? '', reply.stderr ?? '')
    )
    return undefined
  },
  spawn: () => {
    throw new Error('spawn is not used by netstate')
  }
}))

import {
  applyNetState,
  bootTime,
  clearNetState,
  netStatePath,
  parseNetState,
  readNetState,
  restoreOrphanedNetstate,
  revertNetState,
  writeNetState
} from '../src/main/services/vpn/netstate'
import type { NetApplyContext, NetStateFile, PrivilegedResult } from '../src/main/services/vpn/netstate'

let root: string
let runDir: string

interface Recorder {
  ctx: NetApplyContext
  calls: { cmd: string; args: string[]; snapshotOnDisk: boolean }[]
  result: PrivilegedResult
  fail?: boolean
}

function recorder(runId = 'run-1'): Recorder {
  const rec: Recorder = {
    calls: [],
    result: { code: 0, stdout: '', stderr: '' },
    ctx: {
      runId,
      runDir,
      supportsStdin: true,
      runPrivileged: async (cmd, args) => {
        // Recorded per call: the ordering guarantee is that no privileged
        // command ever runs before the snapshot is durable.
        rec.calls.push({ cmd, args, snapshotOnDisk: existsSync(netStatePath(runId, root)) })
        if (rec.fail) return { code: 1, stdout: '', stderr: 'nope' }
        return rec.result
      }
    }
  }
  return rec
}

function baseState(over: Partial<NetStateFile> = {}): NetStateFile {
  return {
    version: 1,
    runId: 'orphan-1',
    platform: 'linux',
    interfaceName: 'wg0',
    appliedAt: Date.now(),
    bootAt: bootTime(),
    ...over
  }
}

function seedOrphan(state: NetStateFile): void {
  mkdirSync(join(root, state.runId), { recursive: true })
  writeFileSync(join(root, state.runId, 'netstate.json'), JSON.stringify(state))
}

beforeEach(() => {
  h.replies.clear()
  root = mkdtempSync(join(tmpdir(), 'shellpilot-netstate-'))
  runDir = mkdtempSync(join(tmpdir(), 'shellpilot-rundir-'))
})
afterEach(() => {
  rmSync(root, { recursive: true, force: true })
  rmSync(runDir, { recursive: true, force: true })
})

describe('netstate file', () => {
  it('writes into the run directory, owner-only', async () => {
    const file = await writeNetState(baseState({ runId: 'run-1' }), root)
    expect(file).toBe(netStatePath('run-1', root))
    if (process.platform !== 'win32') {
      expect(statSync(file).mode & 0o777).toBe(0o600)
      expect(statSync(join(root, 'run-1')).mode & 0o777).toBe(0o700)
    }
    expect((await readNetState('run-1', root))?.interfaceName).toBe('wg0')
  })

  it('refuses a file it cannot trust rather than reverting against undefined', () => {
    expect(parseNetState('not json')).toBeNull()
    expect(parseNetState('{"version":2,"runId":"a"}')).toBeNull()
    expect(parseNetState('{"version":1}')).toBeNull()
    expect(parseNetState(JSON.stringify(baseState()))).not.toBeNull()
  })

  it('clears without complaint when there is nothing to clear', async () => {
    await expect(clearNetState('never-existed', root)).resolves.toBeUndefined()
  })
})

describe('apply ordering', () => {
  it('persists the snapshot before the first change reaches the system (E14)', async () => {
    const rec = recorder()
    const state = await applyNetState(
      {
        interfaceName: 'wg0',
        routes: [{ destination: '10.8.0.0/24', interfaceName: 'wg0' }],
        dns: { servers: ['10.8.0.1'], searchDomains: [], interfaceName: 'wg0' }
      },
      rec.ctx,
      { platform: 'linux', root }
    )
    expect(rec.calls.length).toBeGreaterThan(0)
    // Every one of them, not just the first: a later apply step still has to
    // be undoable if the process dies between two of them.
    expect(rec.calls.every((c) => c.snapshotOnDisk)).toBe(true)
    expect(state.routes?.planned).toEqual([{ destination: '10.8.0.0/24', interfaceName: 'wg0' }])
    expect(state.dns?.runId).toBe('run-1')
    expect(state.dns?.planned?.servers).toEqual(['10.8.0.1'])
    expect(await readNetState('run-1', root)).toEqual(JSON.parse(JSON.stringify(state)))
  })

  it('applies routes before DNS, and reverts DNS before routes', async () => {
    const rec = recorder()
    const state = await applyNetState(
      {
        interfaceName: 'wg0',
        routes: [{ destination: '10.8.0.0/24', interfaceName: 'wg0' }],
        dns: { servers: ['10.8.0.1'], searchDomains: [], interfaceName: 'wg0' }
      },
      rec.ctx,
      { platform: 'linux', root }
    )
    expect(rec.calls.map((c) => c.cmd)).toEqual(['ip', 'install'])
    rec.calls.length = 0
    await revertNetState(state, rec.ctx, { platform: 'linux', root })
    // Which command puts the resolver back depends on whether this host's
    // /etc/resolv.conf is a symlink; that it goes before the routes does not.
    expect(rec.calls).toHaveLength(2)
    expect(['install', 'ln']).toContain(rec.calls[0].cmd)
    expect(rec.calls[1].cmd).toBe('ip')
  })

  it('rolls back what it managed to apply when a later step fails', async () => {
    const rec = recorder()
    rec.fail = true
    await expect(
      applyNetState(
        { interfaceName: 'wg0', routes: [{ destination: '10.8.0.0/24', interfaceName: 'wg0' }] },
        rec.ctx,
        { platform: 'linux', root }
      )
    ).rejects.toMatchObject({ name: 'VpnError' })
    expect(rec.calls.map((c) => c.args.slice(0, 3))).toEqual([
      ['-4', 'route', 'replace'],
      ['-4', 'route', 'del']
    ])
    // The snapshot stays on disk: a rollback that itself failed is exactly
    // what the startup pass is for.
    expect(existsSync(netStatePath('run-1', root))).toBe(true)
  })

  it('reverts idempotently', async () => {
    const rec = recorder()
    const state = await applyNetState(
      { interfaceName: 'wg0', routes: [{ destination: '10.8.0.0/24', interfaceName: 'wg0' }] },
      rec.ctx,
      { platform: 'linux', root }
    )
    rec.calls.length = 0
    rec.fail = true
    await revertNetState(state, rec.ctx, { platform: 'linux', root })
    const first = rec.calls.map((c) => c.args)
    rec.calls.length = 0
    await expect(revertNetState(state, rec.ctx, { platform: 'linux', root })).resolves.toBeUndefined()
    expect(rec.calls.map((c) => c.args)).toEqual(first)
  })

  it('does nothing at all when the plan is empty', async () => {
    const rec = recorder()
    const state = await applyNetState({ interfaceName: 'wg0' }, rec.ctx, { platform: 'linux', root })
    expect(rec.calls).toEqual([])
    expect(state.routes).toBeUndefined()
    expect(state.dns).toBeUndefined()
  })
})

describe('restoreOrphanedNetstate', () => {
  const contextFor = (rec: Recorder) => (): NetApplyContext => rec.ctx

  it('leaves a live run completely alone', async () => {
    const rec = recorder()
    seedOrphan(
      baseState({
        routes: { platform: 'linux', capturedAt: 0, defaults: [], planned: [{ destination: '10.8.0.0/24', interfaceName: 'wg0' }] }
      })
    )
    const reports = await restoreOrphanedNetstate({
      liveRunIds: ['orphan-1'],
      createContext: contextFor(rec),
      platform: 'linux',
      root
    })
    expect(reports).toEqual([
      { runId: 'orphan-1', outcome: 'skipped', routes: 'none', dns: 'none', reason: 'run is still live' }
    ])
    expect(rec.calls).toEqual([])
    expect(existsSync(netStatePath('orphan-1', root))).toBe(true)
  })

  it('reverts a dead run and then forgets about it', async () => {
    const rec = recorder()
    seedOrphan(
      baseState({
        routes: {
          platform: 'linux',
          capturedAt: 0,
          defaults: [],
          planned: [{ destination: '10.8.0.0/24', interfaceName: 'wg0' }]
        }
      })
    )
    const reports = await restoreOrphanedNetstate({
      liveRunIds: [],
      createContext: contextFor(rec),
      platform: 'linux',
      root,
      interfaceExists: () => true
    })
    expect(reports).toEqual([{ runId: 'orphan-1', outcome: 'restored', routes: 'reverted', dns: 'none', reason: undefined }])
    expect(rec.calls.map((c) => c.args)).toEqual([['-4', 'route', 'del', '10.8.0.0/24', 'dev', 'wg0']])
    expect(existsSync(netStatePath('orphan-1', root))).toBe(false)
  })

  it('discards routes for an interface that no longer exists but still puts DNS back', async () => {
    // The kernel took the routes away with the device; the resolver is the
    // part that is still wrong, and it is the part a user would notice.
    const rec = recorder()
    seedOrphan(
      baseState({
        routes: {
          platform: 'linux',
          capturedAt: 0,
          defaults: [],
          planned: [{ destination: '10.8.0.0/24', interfaceName: 'wg0' }]
        },
        dns: {
          platform: 'linux',
          capturedAt: 0,
          runId: 'orphan-1',
          interfaceName: 'wg0',
          previous: ['192.168.1.1'],
          backend: 'resolvectl'
        }
      })
    )
    const reports = await restoreOrphanedNetstate({
      liveRunIds: [],
      createContext: contextFor(rec),
      platform: 'linux',
      root,
      interfaceExists: () => false
    })
    expect(reports[0]).toMatchObject({
      outcome: 'restored',
      routes: 'skipped-missing-interface',
      dns: 'reverted'
    })
    expect(reports[0].reason).toContain('wg0')
    expect(rec.calls.map((c) => [c.cmd, ...c.args])).toEqual([['resolvectl', 'revert', 'wg0']])
  })

  it('skips a vanished interface entirely when there is nothing else to undo', async () => {
    const rec = recorder()
    seedOrphan(
      baseState({
        routes: {
          platform: 'linux',
          capturedAt: 0,
          defaults: [],
          planned: [{ destination: '10.8.0.0/24', interfaceName: 'wg0' }]
        }
      })
    )
    const reports = await restoreOrphanedNetstate({
      liveRunIds: [],
      createContext: contextFor(rec),
      platform: 'linux',
      root,
      interfaceExists: () => false
    })
    expect(reports[0]).toMatchObject({ outcome: 'skipped', routes: 'skipped-missing-interface' })
    expect(rec.calls).toEqual([])
    expect(existsSync(netStatePath('orphan-1', root))).toBe(false)
  })

  it('discards routes from a previous boot but not the DNS they came with', async () => {
    const rec = recorder()
    seedOrphan(
      baseState({
        bootAt: bootTime() - 3_600_000,
        routes: {
          platform: 'linux',
          capturedAt: 0,
          defaults: [],
          planned: [{ destination: '10.8.0.0/24', interfaceName: 'wg0' }]
        },
        dns: {
          platform: 'linux',
          capturedAt: 0,
          runId: 'orphan-1',
          interfaceName: 'wg0',
          previous: [],
          backend: 'resolvectl'
        }
      })
    )
    const reports = await restoreOrphanedNetstate({
      liveRunIds: [],
      createContext: contextFor(rec),
      platform: 'linux',
      root,
      interfaceExists: () => true
    })
    expect(reports[0]).toMatchObject({ routes: 'skipped-stale-boot', dns: 'reverted' })
    expect(rec.calls.map((c) => c.cmd)).toEqual(['resolvectl'])
  })

  it('ignores a snapshot taken on another platform', async () => {
    const rec = recorder()
    seedOrphan(baseState({ platform: 'win32' }))
    const reports = await restoreOrphanedNetstate({
      liveRunIds: [],
      createContext: contextFor(rec),
      platform: 'linux',
      root
    })
    expect(reports[0]).toMatchObject({ outcome: 'skipped' })
    expect(reports[0].reason).toContain('win32')
    expect(existsSync(netStatePath('orphan-1', root))).toBe(true)
  })

  it('keeps the snapshot for next time when no privileged channel is available', async () => {
    seedOrphan(
      baseState({
        dns: {
          platform: 'linux',
          capturedAt: 0,
          runId: 'orphan-1',
          interfaceName: 'wg0',
          previous: [],
          backend: 'resolvectl'
        }
      })
    )
    const reports = await restoreOrphanedNetstate({
      liveRunIds: [],
      createContext: () => null,
      platform: 'linux',
      root
    })
    expect(reports[0]).toMatchObject({ outcome: 'skipped' })
    expect(reports[0].reason).toContain('privileged')
    expect(existsSync(netStatePath('orphan-1', root))).toBe(true)
  })

  it('keeps the snapshot when the revert itself failed', async () => {
    const rec = recorder()
    seedOrphan(
      baseState({
        platform: 'freebsd',
        dns: {
          platform: 'freebsd',
          capturedAt: 0,
          runId: 'orphan-1',
          interfaceName: 'tun0',
          previous: []
        }
      })
    )
    const reports = await restoreOrphanedNetstate({
      liveRunIds: [],
      createContext: contextFor(rec),
      platform: 'freebsd',
      root,
      interfaceExists: () => true
    })
    expect(reports[0]).toMatchObject({ outcome: 'failed', dns: 'failed' })
    expect(existsSync(netStatePath('orphan-1', root))).toBe(true)
  })

  it('handles several orphans and a run directory with no snapshot in it', async () => {
    const rec = recorder()
    mkdirSync(join(root, 'no-netstate'), { recursive: true })
    seedOrphan(baseState({ runId: 'orphan-1' }))
    seedOrphan(
      baseState({
        runId: 'orphan-2',
        dns: {
          platform: 'linux',
          capturedAt: 0,
          runId: 'orphan-2',
          interfaceName: 'wg1',
          previous: [],
          backend: 'resolvectl'
        }
      })
    )
    const reports = await restoreOrphanedNetstate({
      liveRunIds: [],
      createContext: contextFor(rec),
      platform: 'linux',
      root,
      interfaceExists: () => true
    })
    expect(reports.map((r) => r.runId).sort()).toEqual(['orphan-1', 'orphan-2'])
    expect(rec.calls.map((c) => [c.cmd, ...c.args])).toEqual([['resolvectl', 'revert', 'wg1']])
  })

  it('returns nothing when the run root has never been created', async () => {
    await expect(
      restoreOrphanedNetstate({
        liveRunIds: [],
        createContext: () => null,
        platform: 'linux',
        root: join(root, 'missing')
      })
    ).resolves.toEqual([])
  })
})
