// @vitest-environment jsdom
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { act, render, waitFor } from '@testing-library/react'
import { stubBridge } from './setup/renderer'
import { FleetWatcher } from '../src/renderer/src/components/monitor/FleetWatcher'
import { useApp } from '../src/renderer/src/store/app'
import { useAlerts, resetAlertsForTests } from '../src/renderer/src/store/alerts'
import type { JobProgress } from '../src/shared/jobs'
import type { StoredAlertEvent, StoredDbAlertRow } from '../src/shared/webhook'

// Roadmap item 19b: the producers.
//
// The store's side of the new kinds is proved in tests/stateAlerts.test.ts by
// calling checkStateAlert and noteAlertEvent directly. That says nothing about
// whether anything in the app ever calls them, which is precisely the gap this
// item exists to close for disk: a signal that is computed, ranked and rendered
// and then reaches nobody. These render the component that is mounted once at
// the app root and drive the real bridge events.

interface Bridge {
  sample: (e: Record<string, unknown>) => void
  progress: (p: JobProgress) => void
  posted: Record<string, unknown>[]
  shown: { title: string; body: string }[]
  recorded: StoredAlertEvent[]
}

let bridge: Bridge
let tunnelList: { id: string; state: string; connections: number }[]
let dbRows: StoredDbAlertRow[]

const T0 = new Date('2026-01-01T00:00:00Z').getTime()

function install(): void {
  const posted: Record<string, unknown>[] = []
  const shown: { title: string; body: string }[] = []
  const recorded: StoredAlertEvent[] = []
  let onSample: ((e: Record<string, unknown>) => void) | null = null
  let onProgress: ((p: JobProgress) => void) | null = null
  stubBridge({
    getVersion: () => Promise.resolve('9.9.9'),
    notify: {
      show: (title: string, body: string) => {
        shown.push({ title, body })
      }
    },
    webhook: {
      notify: (p: Record<string, unknown>) => {
        posted.push(p)
      },
      configure: () => Promise.resolve()
    },
    alerts: {
      record: (event: StoredAlertEvent) => {
        recorded.push(event)
        return Promise.resolve(true)
      },
      history: () => Promise.resolve([]),
      dbEvents: () => Promise.resolve(dbRows)
    },
    fleet: {
      configure: () => Promise.resolve(),
      onSample: (fn: (e: Record<string, unknown>) => void) => {
        onSample = fn
        return () => {
          onSample = null
        }
      }
    },
    jobs: {
      onProgress: (fn: (p: JobProgress) => void) => {
        onProgress = fn
        return () => {
          onProgress = null
        }
      }
    },
    tunnel: {
      list: () => Promise.resolve(tunnelList)
    }
  })
  bridge = {
    sample: (e) => onSample?.(e),
    progress: (p) => onProgress?.(p),
    posted,
    shown,
    recorded
  }
}

/** A host sample the sampler would emit. Everything healthy, so nothing but the
 *  kind under test can raise. */
function healthy(serverId: string): Record<string, unknown> {
  return {
    serverId,
    at: T0,
    host: {
      cpu: 1,
      memPct: 1,
      diskPct: 1,
      diskTotal: 100,
      inodePct: 1,
      load1: 0,
      cores: 4,
      services: []
    }
  }
}

/**
 * Mount the watcher and let hydration settle.
 *
 * The flush is not ceremony. FleetWatcher reads the durable alert log on mount
 * and the store says NOTHING out loud until that read comes back — a resolve
 * decided against an empty `announced` is a resolve for an alarm we cannot yet
 * know whether we hold. Every case below is about what is said after that, so
 * the wait is the same one the real app does.
 */
async function mount(): Promise<void> {
  render(<FleetWatcher />)
  await act(async () => {
    await Promise.resolve()
    await Promise.resolve()
  })
}

const raises = (): Record<string, unknown>[] => bridge.posted.filter((p) => p.event === 'raised')
const resolves = (): Record<string, unknown>[] => bridge.posted.filter((p) => p.event === 'resolved')
const chip = (k: string): unknown => useAlerts.getState().active[k]

beforeEach(() => {
  tunnelList = []
  dbRows = []
  install()
  resetAlertsForTests()
  vi.useFakeTimers({ shouldAdvanceTime: true })
  vi.setSystemTime(T0)
  const ws = useApp.getState().activeId()
  useApp.setState({
    servers: [
      {
        id: 'srv-1',
        workspaceId: ws,
        folderId: null,
        name: 'web-1',
        host: 'web1.example.internal',
        port: 22,
        username: 'ops',
        auth: 'key',
        route: [],
        demo: false
      }
    ] as never,
    tunnels: [
      { id: 'tun-1', workspaceId: ws, name: 'office-db', kind: 'local', status: 'active', serverId: 'srv-1', listen: '5432', target: '5432' }
    ] as never,
    databases: [
      { id: 'db-1', workspaceId: ws, name: 'orders-primary', kind: 'postgres', host: 'db', port: 5432, username: 'ops' }
    ] as never
  })
  useApp.getState().setSettings({ resourceAlertsEnabled: true, resourceAlertThreshold: 80 })
})

afterEach(() => {
  vi.useRealTimers()
})

describe('a host that stops answering', () => {
  it('raises when the sweep reports an error, and clears on the next sample', async () => {
    await mount()
    await act(async () => {
      bridge.sample({ serverId: 'srv-1', at: T0, error: 'connect ETIMEDOUT' })
    })
    expect(raises()).toHaveLength(1)
    expect(raises()[0].kind).toBe('host-unreachable')
    expect(raises()[0].summary).toBe('web-1 did not answer the last check')
    expect(chip('srv-1:host-unreachable')).toBeDefined()

    await act(async () => {
      bridge.sample(healthy('srv-1'))
    })
    expect(resolves()).toHaveLength(1)
    expect(resolves()[0].summary).toBe('web-1 is answering again')
    expect(chip('srv-1:host-unreachable')).toBeUndefined()
  })

  it('does not put the host error text on the wire', async () => {
    await mount()
    await act(async () => {
      bridge.sample({ serverId: 'srv-1', at: T0, error: 'ssh: handshake failed for root@10.0.0.9' })
    })
    expect(raises()).toHaveLength(1)
    const summary = raises()[0].summary as string
    expect(summary).toBe('web-1 did not answer the last check')
    expect(JSON.stringify(bridge.posted)).not.toContain('10.0.0.9')
    expect(JSON.stringify(bridge.posted)).not.toContain('handshake')
    // And not into the durable row either, which is what the inbox renders.
    // The webhook summary is built from our own words whatever is passed in, so
    // asserting on it alone would let the error text through to the one surface
    // that prints a detail verbatim.
    const row = bridge.recorded.find((r) => r.kind === 'host-unreachable')
    expect(row).toBeDefined()
    expect(row?.detail).toBeUndefined()
    expect(JSON.stringify(bridge.recorded)).not.toContain('10.0.0.9')
  })

  it('says nothing for a sweep that carried neither a host nor an error', async () => {
    await mount()
    await act(async () => {
      bridge.sample({ serverId: 'srv-1', at: T0 })
    })
    expect(bridge.posted).toHaveLength(0)
    expect(chip('srv-1:host-unreachable')).toBeUndefined()
  })

  it('uses the name its owner chose, not the id', async () => {
    await mount()
    await act(async () => {
      bridge.sample({ serverId: 'srv-1', at: T0, error: 'down' })
    })
    expect(raises()[0].server).toBe('web-1')
    expect(raises()[0].server).not.toBe('srv-1')
  })
})

describe('a job step that failed', () => {
  const hostEvent = (state: string): JobProgress =>
    ({
      jobId: 'job-1',
      host: { serverId: 'srv-1', serverName: 'web-1', state }
    }) as unknown as JobProgress

  it('raises on a failed host and names the job', async () => {
    await mount()
    await act(async () => {
      bridge.progress({ jobId: 'job-1', job: { title: 'nightly upgrade' } } as unknown as JobProgress)
      bridge.progress(hostEvent('failed'))
    })
    expect(raises()).toHaveLength(1)
    expect(raises()[0].kind).toBe('job-failed')
    expect(raises()[0].summary).toBe('web-1 failed a job step (nightly upgrade)')
  })

  it('clears when a later step on that host succeeds', async () => {
    await mount()
    await act(async () => {
      bridge.progress(hostEvent('failed'))
    })
    expect(raises()).toHaveLength(1)
    await act(async () => {
      bridge.progress(hostEvent('ok'))
    })
    expect(resolves()).toHaveLength(1)
  })

  it('treats every state that is not an answer as no news', async () => {
    await mount()
    await act(async () => {
      bridge.progress(hostEvent('failed'))
    })
    expect(raises()).toHaveLength(1)
    // `orphaned` is "nobody will ever know how this ended". It is terminal and
    // it is not a success, so it must not clear an alert.
    for (const state of ['pending', 'waiting', 'running', 'detached', 'rebooting', 'orphaned', 'skipped']) {
      await act(async () => {
        bridge.progress(hostEvent(state))
      })
    }
    expect(resolves()).toHaveLength(0)
    expect(chip('srv-1:job-failed')).toBeDefined()
  })
})

describe('a tunnel in error', () => {
  it('raises for an error state and clears when it goes active', async () => {
    tunnelList = [{ id: 'tun-1', state: 'error', connections: 0 }]
    await mount()
    await waitFor(() => expect(raises()).toHaveLength(1))
    expect(raises()[0].kind).toBe('tunnel-down')
    expect(raises()[0].summary).toBe('Tunnel office-db is in error')

    tunnelList = [{ id: 'tun-1', state: 'active', connections: 3 }]
    await act(async () => {
      await vi.advanceTimersByTimeAsync(10_000)
    })
    await waitFor(() => expect(resolves()).toHaveLength(1))
  })

  it('says nothing about a tunnel that is still starting', async () => {
    tunnelList = [{ id: 'tun-1', state: 'starting', connections: 0 }]
    await mount()
    await act(async () => {
      await vi.advanceTimersByTimeAsync(10_000)
    })
    expect(bridge.posted).toHaveLength(0)
    expect(chip('tun-1:tunnel-down')).toBeUndefined()
  })
})

describe('a database verdict item 18 already reached', () => {
  it('announces an alarm read back from the history store', async () => {
    dbRows = [{ kind: 'db-alarm', connectionId: 'db-1', question: 'replication', at: T0 }]
    await mount()
    await waitFor(() => expect(raises()).toHaveLength(1))
    expect(raises()[0].kind).toBe('db-alarm')
    expect(raises()[0].summary).toBe('orders-primary: replication is in alarm')
    // No chip: nothing in the store can ever say a database recovered.
    expect(chip('db-1:db-alarm')).toBeUndefined()
  })

  it('announces each row once, however many times it is polled', async () => {
    dbRows = [{ kind: 'db-alarm', connectionId: 'db-1', question: 'replication', at: T0 }]
    await mount()
    await waitFor(() => expect(raises()).toHaveLength(1))
    for (let i = 0; i < 3; i++) {
      await act(async () => {
        await vi.advanceTimersByTimeAsync(60_000)
      })
    }
    expect(raises()).toHaveLength(1)
  })

  it('reads the verdict rather than reaching one', async () => {
    // A watch and an alarm on the same question. The level is the kind the row
    // was written under; nothing here looks at a number to decide.
    dbRows = [
      { kind: 'db-alarm', connectionId: 'db-1', question: 'autovacuum', at: T0 + 1000 },
      { kind: 'db-watch', connectionId: 'db-1', question: 'autovacuum', at: T0 }
    ]
    await mount()
    await waitFor(() => expect(raises()).toHaveLength(2))
    // Oldest first: the flap counter has to see them in the order they happened.
    expect(raises().map((p) => p.summary)).toEqual([
      'orders-primary: autovacuum is worth watching',
      'orders-primary: autovacuum is in alarm'
    ])
  })
})
