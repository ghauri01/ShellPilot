// @vitest-environment jsdom
import { describe, expect, it, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { stubBridge } from './setup/renderer'
import { ServicesPanel } from '../src/renderer/src/components/monitor/ServicesPanel'
import type { Server } from '../src/renderer/src/types'

const server = (id: string, name: string): Server =>
  ({ id, name, host: 'h', port: 22, username: 'u' }) as unknown as Server

const reading = (over: Record<string, unknown> = {}) => ({
  status: 'ok',
  linger: 'lingering',
  units: [
    { name: 'api.service', load: 'loaded', active: 'active', sub: 'running', description: 'Demo API' }
  ],
  ...over
})

describe('the services panel', () => {
  it('does not claim anything is supervised before it has asked', async () => {
    // The list starts null, not empty. "Nothing is supervised" is a claim about
    // a server, and it must not be made about one nobody has spoken to.
    stubBridge({ services: { collect: async () => [] } } as never)
    render(<ServicesPanel servers={[server('a', 'web-1')]} />)

    expect(await screen.findByText(/Nothing read yet/)).toBeTruthy()
    expect(screen.queryByText(/No servers to ask/)).toBeNull()
  })

  it('leads with what will happen, not with the unit list', async () => {
    // A server whose units are running but whose account is not lingering.
    // Those units stop when the session ends, and the panel has to say so
    // ABOVE the list that shows them cheerfully running.
    stubBridge({
      services: {
        collect: async () => [
          { serverId: 'a', serverName: 'web-1', reading: reading({ linger: 'not-lingering' }) }
        ]
      }
    } as never)
    render(<ServicesPanel servers={[server('a', 'web-1')]} />)
    await userEvent.click(await screen.findByRole('button', { name: /Read services/ }))

    expect(await screen.findByText(/stop when your last session ends/)).toBeTruthy()
    expect(screen.getByText('api.service')).toBeTruthy()
  })

  it('does not raise that when the account is lingering', async () => {
    stubBridge({
      services: {
        collect: async () => [{ serverId: 'a', serverName: 'web-1', reading: reading() }]
      }
    } as never)
    render(<ServicesPanel servers={[server('a', 'web-1')]} />)
    await userEvent.click(await screen.findByRole('button', { name: /Read services/ }))

    expect(await screen.findByText(/supervised by the server/)).toBeTruthy()
    expect(screen.queryByText(/stop when your last session ends/)).toBeNull()
  })

  it('says the capability is missing rather than reporting no services', async () => {
    stubBridge({})
    render(<ServicesPanel servers={[server('a', 'web-1')]} />)
    await userEvent.click(await screen.findByRole('button', { name: /Read services/ }))

    expect(await screen.findByText(/does not expose server services/)).toBeTruthy()
  })

  it('offers nothing to press when the workspace has no servers', async () => {
    stubBridge({ services: { collect: vi.fn() } } as never)
    render(<ServicesPanel servers={[]} />)
    expect(
      ((await screen.findByRole('button', { name: /Read services/ })) as HTMLButtonElement).disabled
    ).toBe(true)
  })
})
