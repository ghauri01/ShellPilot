// @vitest-environment jsdom
import { describe, expect, it, vi } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { stubBridge } from './setup/renderer'
import { ProcessesPanel } from '../src/renderer/src/components/processes/ProcessesPanel'
import type {
  ManagedProcessView,
  ProcessLogLine,
  ProcessStatus,
  ProcessesBridge
} from '../src/shared/processes'

// The panel half of roadmap item 1, rendered rather than read.
//
// What it asserts is what an OPERATOR sees, because two of the failures that
// matter here look like nothing at all on screen: a secret rendered as text
// looks like a helpful default, and a process that will not stay up looks
// identical to one somebody stopped.

const view = (over: Partial<ManagedProcessView> = {}): ManagedProcessView => ({
  id: 'p1',
  name: 'API server',
  command: '/usr/local/bin/node',
  args: ['server.js'],
  cwd: '/srv/api',
  env: [],
  restart: 'on-failure',
  readiness: { kind: 'spawned' },
  createdAt: '2026-01-01T00:00:00.000Z',
  ...over
})

const status = (over: Partial<ProcessStatus> = {}): ProcessStatus => ({
  id: 'p1',
  state: 'stopped',
  pid: 0,
  restarts: 0,
  ...over
})

function bridge(over: Partial<ProcessesBridge> = {}): {
  stub: ProcessesBridge
  calls: { start: string[]; stop: string[]; created: unknown[] }
} {
  const calls = { start: [] as string[], stop: [] as string[], created: [] as unknown[] }
  const stub: ProcessesBridge = {
    list: async () => [view()],
    status: async () => [status()],
    create: async (d) => {
      calls.created.push(d)
      return view()
    },
    remove: async () => true,
    start: async (id) => {
      calls.start.push(id)
      return status({ state: 'running', pid: 4242 })
    },
    stop: async (id) => {
      calls.stop.push(id)
      return status()
    },
    restart: async () => status({ state: 'running' }),
    logs: async () => [],
    ...over
  }
  stubBridge({ processes: stub })
  return { stub, calls }
}

describe('what the panel shows', () => {
  it('lists a process with its command and where it runs', async () => {
    bridge()
    render(<ProcessesPanel />)
    await screen.findByText('API server')
    expect(screen.getByText(/\/usr\/local\/bin\/node server\.js/)).toBeTruthy()
    expect(screen.getByText('/srv/api')).toBeTruthy()
  })

  it('says a process crash-looped rather than showing it as merely stopped', async () => {
    // The distinction is the whole message. "You stopped it" and "it would not
    // stay up" are the same absence of a running process and completely
    // different situations.
    bridge({
      status: async () => [
        status({
          state: 'crash-looped',
          error: 'It kept exiting, so it was stopped rather than restarted again.'
        })
      ]
    })
    render(<ProcessesPanel />)
    await screen.findByText('Crash-looped')
    expect(
      screen.getByText('It kept exiting, so it was stopped rather than restarted again.')
    ).toBeTruthy()
  })

  it('shows an environment KEY and where its value comes from, never a value', async () => {
    // Main does not send a value, and this asserts the panel has nothing that
    // could show one if a future change did.
    bridge({
      list: async () => [
        view({
          env: [
            { key: 'NODE_ENV', source: 'literal' },
            { key: 'DB_URL', source: 'vault', vaultEntryId: 'v-1', slot: 'password' }
          ]
        })
      ]
    })
    const { container } = render(<ProcessesPanel />)
    await screen.findByText(/NODE_ENV/)
    expect(screen.getByText(/DB_URL · from the vault/)).toBeTruthy()
    expect(container.textContent).not.toContain('v-1')
  })

  it('tells the user it cannot supervise anything when the bridge is absent', async () => {
    // Rather than rendering an Add button that does nothing.
    stubBridge({})
    render(<ProcessesPanel />)
    expect(
      screen.getByText('This build of ShellPilot cannot supervise local processes.')
    ).toBeTruthy()
  })
})

describe('the buttons', () => {
  it('starts a stopped process and cannot start a running one twice', async () => {
    const { calls } = bridge({ status: async () => [status({ state: 'stopped' })] })
    render(<ProcessesPanel />)
    const start = await screen.findByRole('button', { name: 'Start' })
    await userEvent.click(start)
    await waitFor(() => expect(calls.start).toEqual(['p1']))
  })

  it('disables Start while it is running, and Stop while it is not', async () => {
    bridge({ status: async () => [status({ state: 'running', pid: 4242 })] })
    render(<ProcessesPanel />)
    await screen.findByText('Running')
    expect(screen.getByRole('button', { name: 'Start' }).hasAttribute('disabled')).toBe(true)
    expect(screen.getByRole('button', { name: 'Stop' }).hasAttribute('disabled')).toBe(false)
  })

  it('adds a valid process, splitting the arguments without a shell', async () => {
    const { calls } = bridge({ list: async () => [] })
    render(<ProcessesPanel />)
    await userEvent.click(screen.getByRole('button', { name: /Add a process/ }))
    await userEvent.type(screen.getByPlaceholderText('API server'), 'Worker')
    await userEvent.type(screen.getByPlaceholderText('/usr/local/bin/node'), '/usr/bin/node')
    await userEvent.type(screen.getByPlaceholderText('server.js --port 3000'), 'worker.js --queue mail')
    await userEvent.type(screen.getByPlaceholderText('/srv/api'), '/srv/worker')
    await userEvent.click(screen.getByRole('button', { name: 'Add' }))

    await waitFor(() => expect(calls.created).toHaveLength(1))
    expect(calls.created[0]).toMatchObject({
      name: 'Worker',
      command: '/usr/bin/node',
      // Whitespace-split and passed straight through. No shell, so nothing was
      // expanded and nothing was quoted.
      args: ['worker.js', '--queue', 'mail'],
      cwd: '/srv/worker'
    })
  })

  it('refuses a secret-shaped literal in the form, and says where it should go', async () => {
    // Main refuses it too — the panel is not the boundary. What this asserts is
    // that the person is TOLD, with the alternative in the sentence, rather
    // than the create call failing somewhere they cannot see.
    const { calls } = bridge({ list: async () => [] })
    render(<ProcessesPanel />)
    await userEvent.click(screen.getByRole('button', { name: /Add a process/ }))
    await userEvent.type(screen.getByPlaceholderText('API server'), 'Worker')
    await userEvent.type(screen.getByPlaceholderText('/usr/local/bin/node'), '/usr/bin/node')
    await userEvent.type(screen.getByPlaceholderText('/srv/api'), '/srv/worker')
    await userEvent.click(screen.getByRole('button', { name: /Add a variable/ }))
    await userEvent.type(screen.getByLabelText('Variable 1 name'), 'STRIPE_API_KEY')
    await userEvent.type(screen.getByLabelText('Variable 1 value'), 'sk_live_abcdef')
    await userEvent.click(screen.getByRole('button', { name: 'Add' }))

    const alert = await screen.findByRole('alert')
    expect(alert.textContent).toContain('STRIPE_API_KEY')
    expect(alert.textContent).toContain('Add it to the vault and reference the entry instead')
    expect(calls.created).toEqual([])
  })

  it('accepts the same name once it comes from the vault instead', async () => {
    const { calls } = bridge({ list: async () => [] })
    render(<ProcessesPanel />)
    await userEvent.click(screen.getByRole('button', { name: /Add a process/ }))
    await userEvent.type(screen.getByPlaceholderText('API server'), 'Worker')
    await userEvent.type(screen.getByPlaceholderText('/usr/local/bin/node'), '/usr/bin/node')
    await userEvent.type(screen.getByPlaceholderText('/srv/api'), '/srv/worker')
    await userEvent.click(screen.getByRole('button', { name: /Add a variable/ }))
    await userEvent.type(screen.getByLabelText('Variable 1 name'), 'STRIPE_API_KEY')
    await userEvent.selectOptions(screen.getByLabelText('Variable 1 source'), 'vault')
    await userEvent.type(screen.getByLabelText('Variable 1 vault entry'), 'v-9')
    await userEvent.click(screen.getByRole('button', { name: 'Add' }))

    await waitFor(() => expect(calls.created).toHaveLength(1))
    expect(calls.created[0]).toMatchObject({
      env: [{ key: 'STRIPE_API_KEY', kind: 'vault', vaultEntryId: 'v-9', slot: 'password' }]
    })
  })

  it('says why a draft was refused instead of failing silently', async () => {
    const { calls } = bridge({ list: async () => [] })
    render(<ProcessesPanel />)
    await userEvent.click(screen.getByRole('button', { name: /Add a process/ }))
    await userEvent.type(screen.getByPlaceholderText('API server'), 'Worker')
    // No command.
    await userEvent.click(screen.getByRole('button', { name: 'Add' }))

    expect(await screen.findByRole('alert')).toHaveProperty(
      'textContent',
      'Give it a command to run.'
    )
    expect(calls.created).toEqual([])
  })
})

describe('the log drawer is bounded, and so is the poll', () => {
  it('asks for at most one capped page, and only for the row that is open', async () => {
    const asked: [string, number | undefined][] = []
    const lines: ProcessLogLine[] = Array.from({ length: 4_000 }, (_v, i) => ({
      at: i,
      stream: 'stdout' as const,
      text: `line ${i}`
    }))
    bridge({
      logs: async (id, limit) => {
        asked.push([id, limit])
        return lines.slice(-(limit ?? 500))
      }
    })
    render(<ProcessesPanel />)
    await screen.findByText('API server')

    // Closed: nothing is fetched at all.
    expect(asked).toEqual([])

    await userEvent.click(screen.getByRole('button', { name: 'Show output' }))
    await waitFor(() => expect(asked.length).toBeGreaterThan(0))
    // A crash-looping process is a log flood; the panel never asks for more
    // than one page of it however many lines exist.
    for (const [, limit] of asked) expect(limit).toBe(500)
  })

  it('does not poll while the window is in the background', async () => {
    // FleetMonitor keeps every panel mounted and hidden, so an unconditional
    // interval here is a poll per second for a tab nobody is looking at.
    vi.useFakeTimers({ shouldAdvanceTime: true })
    try {
      let listed = 0
      bridge({
        list: async () => {
          listed++
          return [view()]
        }
      })
      render(<ProcessesPanel />)
      await vi.waitFor(() => expect(listed).toBeGreaterThan(0))
      const afterMount = listed

      Object.defineProperty(document, 'visibilityState', {
        configurable: true,
        get: () => 'hidden'
      })
      await vi.advanceTimersByTimeAsync(10_000)
      expect(listed).toBe(afterMount)

      Object.defineProperty(document, 'visibilityState', {
        configurable: true,
        get: () => 'visible'
      })
      await vi.advanceTimersByTimeAsync(3_000)
      expect(listed).toBeGreaterThan(afterMount)
    } finally {
      vi.useRealTimers()
    }
  })
})
